# AGENTS.md

Guidance for AI coding agents (and anyone else) working in this repository.

Repository orientation — architecture, the two FFI build modes, where generated
code comes from — lives in `CLAUDE.md`. This file covers the working practices
that sit on top of it: pre-push validation, CHANGELOG discipline, commit
conventions, and the handling of agent working documents.

## Project overview

`ZcashLightClientKit` is an iOS/macOS Swift Package that implements a Zcash lightwallet client. The Swift layer wraps a Rust core (in `rust/`) via an `libzcashlc` XCFramework. Most day-to-day SDK work happens in Swift only — SPM auto-downloads a pre-built XCFramework from GitHub Releases.

## Pre-push validation

Before opening a PR or pushing to an existing PR branch, run the checks CI runs.
On a cache miss CI builds the Rust FFI from source (30-minute timeout) before it
compiles a line of Swift, so a mistake that a local build would have caught in a
minute can cost most of an hour to surface.

Two workflows gate a PR:

| Workflow | Trigger | Local equivalent |
|---|---|---|
| `swift.yml` | any PR that is not docs-only | `swift build && swift test --filter OfflineTests` |
| `swiftlint.yml` | any PR touching `**/*.swift` | `swiftlint lint --strict` |

`codeql.yml` and `zizmor.yml` also run, and matter when you change workflow
files or add new Swift code paths.

Lint locally with `--strict`, which CI does not pass: it promotes warnings to
errors, so a clean `--strict` run is a superset of the CI job and cannot pass
here and fail there.

The package cannot build without an `libzcashlc` XCFramework. On a fresh
checkout `swift build` downloads the published binary named in `Package.swift`;
that binary is stale the moment your branch changes anything under `rust/`, so
build locally first:

```bash
./Scripts/init-local-ffi.sh --macos-only   # once per branch
./Scripts/rebuild-local-ffi.sh macos       # after each Rust edit
swift build
swift test --filter OfflineTests
```

### When to run which

| Change | Minimum |
|---|---|
| Doc or CHANGELOG only | nothing — `swift.yml` ignores those paths |
| Swift style or rename | `swiftlint lint --strict` |
| Swift logic or refactor | offline tests, then lint |
| Rust internals | local FFI rebuild, then offline tests |
| Any change to an FFI signature or a new FFI function | full `./Scripts/init-local-ffi.sh` (all five architectures) before PRing |

`--macos-only` and `rebuild-local-ffi.sh` cover one architecture. A mismatch
between the generated `zcashlc.h` and the Swift call site compiles cleanly on
both sides and fails at *runtime*, so a change to the Swift↔Rust boundary needs
a real build and the offline suite — never a lint pass alone.

### What cannot be run locally, or at all, in CI

- `DarksideTests` / `AliasDarksideTests` need a local `lightwalletd` in darkside
  mode (invocation in `CLAUDE.md`); they are not in CI.
- `NetworkTests` need an internet connection; `PerformanceTests` are not run in
  CI.
- The shared `ZcashLightClientKit.xctestplan` enables `OfflineTests` only.
  Enable the other targets by hand when you need them.
- Release artifacts come from the `Build FFI XCFramework` workflow
  (`workflow_dispatch`), never from a PR.

### Regenerate, never hand-edit

Generated output is checked in, so a hand edit shows up as a diff that the next
regeneration silently reverts:

- `Sources/ZcashLightClientKit/Error/Sourcery/generateErrorCode.sh` after
  editing `ZcashErrorCodeDefinition.swift`.
- `Tests/TestUtils/Sourcery/generateMocks.sh` after changing a mocked protocol
  (requires Sourcery **2.3.0** exactly; the script hard-checks the version).
- `Scripts/update-lightwallet-protocol.sh <ref>` for the lightwalletd protos —
  `nix develop` provides the `protoc` it needs.

## Build and test

Open the package or workspace in Xcode and build against an iOS or macOS target:

- `swift build` — build the package (macOS target).
- `swift test --filter OfflineTests` — run the offline unit tests. This is what CI runs (see `.github/workflows/swift.yml`).
- `xcodebuild ... -testPlan ZcashLightClientKit.xctestplan` — the shared test plan enables only `OfflineTests`; other test targets are disabled by default and must be enabled manually when needed.

Test targets are grouped by external dependencies:

| Target | Requires |
|---|---|
| `OfflineTests` | nothing |
| `NetworkTests` | internet connection |
| `DarksideTests` / `AliasDarksideTests` | a local `lightwalletd` (`Tests/lightwalletd/lightwalletd --no-tls-very-insecure --data-dir /tmp --darkside-very-insecure --log-file /dev/stdout`); optionally set `LIGHTWALLETD_ADDRESS` |
| `PerformanceTests` | network, not run in CI |

## Rust FFI development

The Rust code in `rust/` is compiled into the `libzcashlc` XCFramework. Two modes, switched automatically by `Package.swift` based on whether `LocalPackages/Package.swift` exists:

- **Binary release mode** (default): `.binaryTarget` in `Package.swift` pulls the XCFramework zip from the GitHub Release referenced there (URL + checksum).
- **Local FFI mode**: `LocalPackages/` acts as a path-dependency override. The workspace's `FFIBuilder` target auto-rebuilds on Xcode builds.

Scripts:

- `./Scripts/init-local-ffi.sh` — one-time setup; default builds all 5 architectures and creates `LocalPackages/`. **`--macos-only`** builds only the macOS slice from your `rust/` (good for `swift build` / `swift test` on the Mac). Use `--cached` only when your branch has no FFI changes relative to the release. Use --macos-only to rebuild for fast local development.
- `./Scripts/rebuild-local-ffi.sh [ios-sim|ios-device|macos]` — fast single-arch incremental rebuild after Rust edits. `ios-sim` is default.
- `./Scripts/reset-local-ffi.sh` — remove `LocalPackages/` and switch back to the release binary.

For FFI work, open `ZcashSDK.xcworkspace` (not `Package.swift`) so `FFIBuilder` auto-runs. After switching modes or if headers look stale, in Xcode: Cmd+Shift+K, then File > Packages > Reset Package Caches. When modifying the Rust/Swift FFI boundary, run the full `init-local-ffi.sh` before PRing — `rebuild-local-ffi.sh` only covers one arch.

See `docs/LOCAL_DEVELOPMENT.md` for the full reference.

## Release

- `./Scripts/release.sh <remote> <version>` — fully automated release (bumps the XCFramework URL+checksum in `Package.swift`, signs a tag, drafts GitHub Release).
- `./Scripts/prepare-release.sh <version>` — semi-automated alternative.
- The `Build FFI XCFramework` GitHub Action (`workflow_dispatch`) produces release artifacts.

## Architecture

### Two-layer wallet

1. **Rust core** (`rust/src/`) — key derivation, note scanning, transaction construction, block database migrations.
2. **Swift SDK** (`Sources/ZcashLightClientKit/`) — orchestration, networking, persistence, public API.

The Swift↔Rust bridge lives in `Sources/ZcashLightClientKit/Rust/`:
- `ZcashRustBackend` conforms to `ZcashRustBackendWelding` — the DB-bound surface.
- `ZcashKeyDerivationBackend` conforms to `ZcashKeyDerivationBackendWelding` — the stateless key-derivation surface.

Both are the only callers of the generated C header `libzcashlc`.

### Synchronizer is the public entry point

- `Synchronizer.swift` defines the public protocol.
- `SDKSynchronizer` (in `Synchronizer/SDKSynchronizer.swift`) is the concrete actor-based implementation. `ClosureSDKSynchronizer` and `CombineSDKSynchronizer` (plus the `ClosureSynchronizer`/`CombineSynchronizer` top-level files) are thin adapters over the `async/await` API. Prefer extending the async API and letting the adapters delegate.
- `Synchronizer/Dependencies.swift` is the DI composition root — it wires the entire object graph (repositories, services, rust backend, compact block processor, Tor client). Most "where does X come from?" questions are answered here.
- `Initializer.swift` is the user-facing entry point that validates paths, configures logging, and hands config to `Synchronizer`.

### Sync pipeline: CompactBlockProcessor + Actions

`Block/CompactBlockProcessor.swift` is a Swift actor that drives a state machine (`CBPState`) over an ordered list of `Block/Actions/*Action.swift` units: download → validate server → update chain tip → update subtree roots → process suggested scan ranges → scan → enhance → fetch UTXOs → clear cache → resubmit / migrate legacy / rewind. Each `Action` conforms to the protocol in `Block/Actions/Action.swift` and mutates a shared `ActionContext`.

The `CompactBlockProcessor` downloads compact blocks via `Block/Download/`, stores them on-disk via `Block/FilesystemStorage/` (NOT a sqlite `cacheDb` anymore — see MIGRATING.md), and invokes scanning/enhancement through the rust backend. Metadata lives in a sqlite `dataDb` accessed via `DAO/` and `Repository/`.

"Spend before Sync" (non-linear scan order) is the current sync algorithm — blocks may be scanned out-of-order so spendable notes are discovered early; tests and code refer to "scan ranges" and "suggested scan ranges" in this sense.

### Networking

- gRPC lightwalletd client: `Modules/Service/GRPC/`. The lightwalletd proto files are vendored from https://github.com/zcash/lightwallet-protocol as a git subtree under `lightwallet-protocol/`; update them with `Scripts/update-lightwallet-protocol.sh <ref>` (needs `protoc`, provided by `nix develop`), which also regenerates the checked-in `*.pb.swift`/`*.grpc.swift` sources (excluded from SwiftLint; regenerate, don't hand-edit). `ProtoBuf/proto/proposal.proto` is vendored from librustzcash, not the subtree.
- Tor: `Modules/Service/Tor/` and `Tor/TorClient.swift`. A Tor directory is provisioned in the Initializer config.
- `Modules/Service/LightWalletService.swift` is the service-level abstraction the rest of the SDK depends on.

### Generated code

Three kinds of generated code in this repo — do not edit by hand:

1. **Error types** — `Error/ZcashError.swift` and `Error/ZcashErrorCode.swift` are generated from `Error/ZcashErrorCodeDefinition.swift` via `Error/Sourcery/generateErrorCode.sh` (Sourcery). Add new errors by editing `ZcashErrorCodeDefinition.swift` and rerunning the script.
2. **Test mocks** — `Tests/TestUtils/Sourcery/GeneratedMocks/AutoMockable.generated.swift` via `Tests/TestUtils/Sourcery/generateMocks.sh`. Requires Sourcery **2.3.0** exactly (the script hard-checks the version).
3. **gRPC/protobuf** — see above.

Generated files and `Tests/` are excluded from the main `.swiftlint.yml` (tests have their own `.swiftlint_tests.yml`).

### Checkpoints

`Resources/checkpoints/{mainnet,testnet}/*.json` are bundled chain checkpoints, loaded by `Checkpoint/BundleCheckpointSource.swift`. They seed wallet birthday lookups.

## Worktree layout

Long-running feature work is kept in worktrees under `.worktrees/` (ignored) so
that a quick fix on a maintenance branch does not have to disturb it:

```bash
git worktree add .worktrees/fix-something -b fix/something maint/v2.8.x
```

Cut a new branch from the maintenance branch that owns the fix, not from the
feature branch you happen to be standing in — a fix belongs to the earliest line
it applies to and reaches the later ones by merging forward.

## CHANGELOG discipline

`CHANGELOG.md` exists for consumers of the published library, and nothing else.
`rust/CHANGELOG.md` is the same contract one layer down, for the C FFI surface
that `libzcashlc` exports.

- Update it for any **public API change, bug fix, or semantic change**. The entry
  **must** be part of the same commit that makes the change, not a follow-up.
- Entries carry **only** what a consumer needs in order to adapt: the public
  symbol by name, the precise shape of the change, what breaks at their call
  site, and the edit to make (or that none is needed).
- **Never** describe implementation details, or contracts that are not visible
  through the public API. In particular, do not narrate branch or release
  topology — which line merged into which, which release on another line carries
  the same change, which version numbers were skipped, why the ordering in the
  file looks the way it does. None of that is actionable for a consumer.
- Record **only completed changes since the last release**, never the
  interstitial states of an API that was changed several times since then. If a
  symbol was added and then renamed before release, the entry describes the final
  name only.
- **Never modify an entry under an already-published version heading** (a dated
  `# x.y.z - DATE` section whose tag exists). Those are the historical record of
  what that release shipped, and must not be altered even to clarify or correct.
  New information goes under `# Unreleased`.
- Do **not** add a separate "Breaking changes" section. `## Changed` already is
  the breaking-change section — everything under it is breaking, whether semver,
  dependency, or otherwise. Non-breaking additions go under `## Added`, fixes
  under `## Fixed`. Each `## Changed` entry should read as the consumer meets the
  break: "positional construction will not compile", "an exhaustive `switch`
  stops compiling until the new case is handled", "any conformer or test double
  must now provide this".
- Privacy, security, and cost properties are user-facing even when they are
  documented only in a doc comment. Wallet teams design confirmation UI from the
  changelog, so a feature that reveals data on-chain, costs a fee, or fails at
  runtime belongs here too.
- Breaking changes also get an entry in `MIGRATING.md`; the changelog says what
  changed, `MIGRATING.md` shows the before/after.

When preparing a release, audit the public surface by diffing the release range
rather than trusting the file to be complete. Behavior-only changes with no
signature change — altered equality semantics, stricter validation, a previously
fixed value becoming settable — are the ones most often missed.

## Commit and PR conventions

- Commit titles are `[#<issue_number>] <self-descriptive title>`; every PR
  references an issue. See `CONTRIBUTING.md`.
- PRs land as merge commits, never squashed, so every commit on the branch is
  part of the permanent history: keep them self-contained and buildable.
- `main` is development-stable — all merges build and pass tests — but consumers
  must depend on published tags, never on a branch.

## Working documents are not committed

Plans, design specs, and brainstorming documents are working artifacts of a
development session, not repository history. Never commit them.

- Write them to the `.plans/` directory at the repository root, which is listed
  in `.gitignore`.
- If `.plans/` does not exist yet, create it (and ensure `.plans/` appears in the
  checked-in `.gitignore`).
- After writing a plan or spec, report its full absolute path, untruncated, so it
  can be copy-pasted.

## Database access: views only, everything else through the FFI

`dataDb` is owned by Rust. `zcash_client_sqlite` defines both its tables and a
set of `v_*` views, and only the views are a supported interface. The tables
are an implementation detail that upstream reshapes freely, and a schema
migration that leaves a view's columns intact can still rename, split or drop
the tables underneath it.

**Swift may read `v_transactions` and `v_tx_outputs` directly. Every other
query goes through the FFI.** Never read a table from Swift, and never write
anything at all: writes belong to Rust, which owns invariants across tables
that no single statement can preserve.

Those two views are the client-facing read surface. `zcash_client_sqlite`
defines other `v_*` views, but they serve the scanning and note-commitment
machinery inside Rust and are not an interface for this SDK; treat them like
tables. The definitions live in `zcash_client_sqlite/src/wallet/db.rs` in
[librustzcash][lrz].

[lrz]: https://github.com/zcash/librustzcash

### Why those two, and when to ask for another

Everything the FFI returns is serialized and copied across the boundary, so a
query yielding many rows can cost more that way than reading it directly.
That is why `v_transactions` and `v_tx_outputs`, which back the transaction
history, are exempt at all.

Another query with the same bulk property may deserve the same treatment, but
that is not a call to make on your own. Do not add a direct read silently:
flag it to the user, say what the query returns and roughly how much data it
moves, and let them decide. If they agree, record it in the table below so the
next reader sees a sanctioned exception rather than a violation.

### Where direct access lives

All of it is under `Sources/ZcashLightClientKit/DAO/`. Adding a query anywhere
else is a mistake; adding one that names a table is a mistake wherever it is.

| File | Reads | Status |
|---|---|---|
| `TransactionDao.swift` | `v_transactions`, `v_tx_outputs` | views, fine |
| `BlockDao.swift` | `blocks` | **table, pre-existing exception** |

`PagedTransactionDao.swift` and `UnspentTransactionOutputDao.swift` name no
entities of their own.

The exception predates this rule and is being migrated to the FFI. Do not copy
it, and do not add to it: if you need something it exposes, add an FFI call
rather than a second table reader.

## Other notes

- SwiftLint is strict and its findings are blocking: no `print` / `debugPrint` /
  `NSLog` in SDK code (use the injected `Logger`), string interpolation rather
  than `+` concatenation, and `TODO: [#<issue_number>] ...` for TODOs. The only
  permitted `swiftlint:disable` exceptions are the ones listed in
  `SWIFTLINT.md`, always narrowly scoped.
- Prefer extending the `async`/`await` API on `SDKSynchronizer`; the
  `ClosureSDKSynchronizer` and `CombineSDKSynchronizer` adapters should stay thin
  delegations.

## Swift conventions and gotchas

- **Logging**: never call `print`, `debugPrint`, or `NSLog` in app/SDK code — SwiftLint enforces this. Use the injected `Logger` (see README "Integrating with logging tools"). The `Logger` protocol is provided to `Initializer` via `loggingPolicy`.
- **String building**: use interpolation, not `+` concatenation (SwiftLint `string_concatenation` is severity `error`).
- **TODOs**: format as `TODO: [#<issue_number>] ...` — bare `TODO:`/`FIXME:` warn.
- **SwiftLint disables**: only the exceptions listed in `SWIFTLINT.md` are permitted, always scoped with `// swiftlint:disable:next` / `disable:previous` / region blocks.
- **Main branch policy**: `main` is development-stable (all merges build + tests pass) but clients must depend on published tags, never on `main`.
- **Sync concurrency**: `CompactBlockProcessor` is a Swift actor. Callers without structured concurrency should hop to `@MainActor` contexts rather than blocking.

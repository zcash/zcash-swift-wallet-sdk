# AGENTS.md

Repository-specific guidance for coding agents lives in `CLAUDE.md`. The
conventions below apply to agent-generated working documents in this
repository.

## Plans and design documents are not committed

Plans, design specs, and brainstorming documents are working artifacts of a
development session, not repository history. Never commit them.

Standard handling:

- Write them to the `.plans/` directory at the repository root, which is
  listed in `.gitignore`.
- If `.plans/` does not exist yet, create it (and ensure `.plans/` appears in
  the checked-in `.gitignore`).
- After writing a plan or spec, report its full absolute path, untruncated,
  so it can be copy-pasted.

## Project overview

`ZcashLightClientKit` is an iOS/macOS Swift Package that implements a Zcash lightwallet client. The Swift layer wraps a Rust core (in `rust/`) via an `libzcashlc` XCFramework. Most day-to-day SDK work happens in Swift only — SPM auto-downloads a pre-built XCFramework from GitHub Releases.

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

- `./Scripts/init-local-ffi.sh` — one-time setup; default builds all 5 architectures and creates `LocalPackages/`. **`--macos-only`** builds only the macOS slice from your `rust/` (good for `swift build` / `swift test` on the Mac). Use `--cached` only when your branch has no FFI changes relative to the release.
- `./Scripts/rebuild-local-ffi.sh [ios-sim|ios-device|macos]` — fast single-arch incremental rebuild after Rust edits. `ios-sim` is default.
- `./Scripts/reset-local-ffi.sh` — remove `LocalPackages/` and switch back to the release binary.

For FFI work, open `ZcashSDK.xcworkspace` (not `Package.swift`) so `FFIBuilder` auto-runs. After switching modes or if headers look stale, in Xcode: Cmd+Shift+K, then File > Packages > Reset Package Caches. When modifying the Rust/Swift FFI boundary, run the full `init-local-ffi.sh` before PRing — `rebuild-local-ffi.sh` only covers one arch.

The `Makefile` wraps these (`make ffi-macos`, `make ffi-all`, `make init-ffi`, `make rebuild-ffi`, `make reset-ffi`, `make configure-local-ffi`); CI calls the targets, so prefer them over the scripts directly. `make help` lists everything.

See `docs/LOCAL_DEVELOPMENT.md` for the full reference.

## Release

A release runs in two phases, with a human reading a pull request in between.
`CONTRIBUTING.md` carries the full procedure; every command below accepts
`--dry-run`.

- `./Scripts/prepare-release.sh start --issue <N> <remote> <version>` — cut `release/X.Y.Z` from the previous release tag and `candidate/X.Y.Z` from the revision being released, promote the CHANGELOG, and open a draft pull request between them. Its diff is what users receive relative to the last release.
- `./Scripts/prepare-release.sh build <remote> <version>` — bump the recorded version, build the XCFramework and verify the SDK against it, upload it as a draft release, point `Package.swift` at it, and mark the pull request ready. Each step derives whether it has already run, so a failure resumes rather than restarting.
- `./Scripts/prepare-release.sh artifacts <version>` — the build and upload alone, touching no git or pull-request state. This is what the `Build FFI XCFramework` GitHub Action (`workflow_dispatch`) runs; it never builds a PR.
- `./Scripts/release.sh <remote> <version>` — after the pull request merges, run from `release/X.Y.Z`. Verifies the checksum against the uploaded asset, signs and pushes the tag, and publishes the release.

A version carrying a pre-release suffix, such as `2.8.0-rc.1`, is marked as a
pre-release on GitHub. The text transforms and predicates these scripts are
built from live in `Scripts/lib/release-lib.sh` and are covered by
`make test-scripts`, which `make check` includes.

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

- gRPC lightwalletd client: `Modules/Service/GRPC/`. The lightwalletd proto files are vendored from https://github.com/zcash/lightwallet-protocol as a git subtree under `lightwallet-protocol/`; update them with `Scripts/update-lightwallet-protocol.sh <ref>` (needs `protoc`, provided by `nix develop`), which also regenerates the checked-in `*.pb.swift`/`*.grpc.swift` sources (excluded from SwiftLint; regenerate, don't hand-edit). `ProtoBuf/proto/proposal.proto` is vendored from librustzcash, not the subtree; re-derive it with `Scripts/update-proposal-proto.sh` and never hand-edit it, because `proto-sync.yml` re-derives it from the pinned `zcash_client_backend` on every PR and fails if the committed copy differs.
- Tor: `Modules/Service/Tor/` and `Tor/TorClient.swift`. A Tor directory is provisioned in the Initializer config.
- `Modules/Service/LightWalletService.swift` is the service-level abstraction the rest of the SDK depends on.

### Generated code

Three kinds of generated code in this repo. The output is checked in, so a hand edit shows up as a diff that the next regeneration silently reverts — regenerate, never hand-edit:

1. **Error types** — `Error/ZcashError.swift` and `Error/ZcashErrorCode.swift` are generated from `Error/ZcashErrorCodeDefinition.swift` via `Error/Sourcery/generateErrorCode.sh` (Sourcery). Add new errors by editing `ZcashErrorCodeDefinition.swift` and rerunning the script.
2. **Test mocks** — `Tests/TestUtils/Sourcery/GeneratedMocks/AutoMockable.generated.swift` via `Tests/TestUtils/Sourcery/generateMocks.sh`. Requires Sourcery **2.3.0** exactly (the script hard-checks the version).
3. **gRPC/protobuf** — see above.

Generated files and `Tests/` are excluded from the main `.swiftlint.yml` (tests have their own `.swiftlint_tests.yml`).

### Checkpoints

`Resources/checkpoints/{mainnet,testnet}/*.json` are bundled chain checkpoints, loaded by `Checkpoint/BundleCheckpointSource.swift`. They seed wallet birthday lookups.

## Security-critical API rules

These rules exist because violations have shipped before. They are not stylistic.

### Semantic types for public APIs (MUST)

Every public API parameter that carries a domain value — key material, seeds, addresses, memos, account identifiers — MUST use its semantic wrapper type. Never accept or pass bare `String`, `[UInt8]`, or `Data` for these values. A primitive-typed parameter lets a typo or autocomplete slip a key into a memo field (this has happened) and lets invalid input travel all the way to the rust backend before failing.

- Existing semantic types to use: `UnifiedFullViewingKey`, `UnifiedSpendingKey`, `SaplingExtendedSpendingKey`, `SaplingExtendedFullViewingKey`, `TransparentAccountPrivKey`, `TransparentAddress`, `SaplingAddress`, `UnifiedAddress`, `TexAddress`, `Recipient` (`Model/WalletTypes.swift`), `Memo` (`Model/Memo.swift`), `Zip32AccountIndex`, `AccountUUID` (`Account/Account.swift`), `Zatoshi`, `TxId`, `BlockHeight`. Check for an existing type before inventing one.
- Raw input (user entry, QR scan, deep link) is converted into the semantic type **once, at the outermost app-facing layer**. Only semantic types flow inward. Unwrapping back to a raw encoding happens solely at the FFI boundary (`Rust/ZcashRustBackend.swift`, `Rust/ZcashKeyDerivationBackend.swift`).
- **All parsing and validation is librustzcash's job, surfaced through the FFI.** Semantic types validate on construction by calling the SDK's rust-backed validation — the way `UnifiedFullViewingKey`'s initializer validates via `DerivationTool` → `ZcashKeyDerivationBackend`. NEVER implement your own inline parser, regex, prefix check, or encoding check for key material or addresses in Swift. If the validation entry point you need does not exist, expose the librustzcash function through the welding layer (`ZcashRustBackendWelding` / `ZcashKeyDerivationBackendWelding`) and call that.
- New key-material types MUST adopt the `Undescribable` marker (`Model/WalletTypes.swift`) so secrets cannot be printed via reflection, and `StringEncoded` where a canonical string encoding exists.
- Known legacy counterexample — do not replicate its shape: `Synchronizer.importAccount(ufvk: String, ...)` (`Synchronizer.swift`) accepts the UFVK as a bare `String` and forwards it unvalidated through `SDKSynchronizer` to the FFI, bypassing the existing `UnifiedFullViewingKey` type. Any new or extended API takes the semantic type.

### Key material in errors and logs (MUST)

- NEVER interpolate key material, seeds, or raw caller input into error messages, `ZcashError` case definitions, or log lines.
- Rust FFI error strings (captured via `lastErrorMessage`) may echo the caller's input verbatim — e.g. an invalid UFVK string appears inside `"<input> is not a valid ufvk encoding"`. These strings are stored as the associated values of `ZcashError.rust*` cases (e.g. `rustImportAccountUfvk`). Treat every such associated value as sensitive.
- When logging errors, log `error.message` or `localizedDescription` (generic, code-prefixed, safe). NEVER log errors via `String(describing:)`, `"\(error)"`, or `dump(...)` — default reflection prints the associated values, and that output ends up in logs users mail to support.
- New error cases added to `Error/ZcashErrorCodeDefinition.swift` must keep raw input out of their `message` text; carry context via the error code, not the offending value.

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

## Pre-push validation

Before opening a PR or pushing to an existing PR branch, run the checks CI runs.
On a cache miss CI builds the Rust FFI from source (30-minute timeout) before it
compiles a line of Swift, so a mistake that a local build would have caught in a
minute can cost most of an hour to surface.

Four workflows gate a PR. `swift.yml` drives every build and test step through
the `Makefile`, so the local equivalent is the same target CI invokes, not a
hand-written `swift` command:

| Workflow | Trigger | Local equivalent |
|---|---|---|
| `swift.yml` | any PR outside its `paths-ignore` list | `make check` (`make build`, `make test-offline`, `make test-rust`) |
| `swiftlint.yml` | any PR touching `**/*.swift` or `.swiftlint.yml` | `make lint` |
| `proto-sync.yml` | any PR outside its `paths-ignore` list | `./Scripts/update-proposal-proto.sh --check` |
| `zizmor.yml` | every PR | matters when you change a workflow file |

`codeql.yml` does **not** run per PR — only on merges to `main` and weekly,
because its Swift matrix entry needs `build-mode: manual` and a full FFI build.

The `paths-ignore` list is specific: `README.md`, `CHANGELOG.md`,
`CONTRIBUTING.md`, `SWIFTLINT.md`, `LICENSE`, `responsible_disclosure.md`,
`docs/**`, and the issue and PR templates. This file is **not** on it, so a
change to `AGENTS.md` alone still triggers a full build.

`make lint` runs `swiftlint lint --quiet`. Adding `--strict` promotes warnings
to errors, so a clean `swiftlint lint --strict` is a superset of whatever CI
enforces and cannot pass locally and fail there.

The package cannot build without an `libzcashlc` XCFramework. On a fresh
checkout `swift build` downloads the published binary named in `Package.swift`;
that binary is stale the moment your branch changes anything under `rust/`.
`make ffi-macos` reproduces the CI "Build FFI for macOS" step exactly, and the
macOS slice alone is enough to build and test the Swift package:

```bash
make ffi-macos           # once per branch, and after each Rust edit
make configure-local-ffi # point Package.swift at the local build
make check               # build, the offline suite, then the Rust tests
```

`make test-rust` runs `cargo test`. The Rust unit tests sit below the Swift
package, so no `swift test` filter reaches them and `make test-offline` passing
says nothing about them; `swift.yml` runs both.

### When to run which

| Change | Minimum |
|---|---|
| A file on the `paths-ignore` list | nothing |
| Any other doc, including this one | `make check` — the build runs regardless |
| Swift style or rename | `make lint` |
| Swift logic or refactor | `make check`, then `make lint` |
| Rust internals | `make ffi-macos`, then `make check` (which runs `make test-rust`) |
| Any change to an FFI signature or a new FFI function | `make ffi-all` (all five architectures) before PRing |
| Bumping the pinned `zcash_client_backend` | `./Scripts/update-proposal-proto.sh --check` |

`make ffi-macos` and `make rebuild-ffi` cover one architecture. A mismatch
between the generated `zcashlc.h` and the Swift call site compiles cleanly on
both sides and fails at *runtime*, so a change to the Swift↔Rust boundary needs
a real build and the offline suite — never a lint pass alone.

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

## Conventions and gotchas

- **Logging**: never call `print`, `debugPrint`, or `NSLog` in app/SDK code — SwiftLint enforces this. Use the injected `Logger` (see README "Integrating with logging tools"). The `Logger` protocol is provided to `Initializer` via `loggingPolicy`.
- **String building**: use interpolation, not `+` concatenation (SwiftLint `string_concatenation` is severity `error`).
- **TODOs**: format as `TODO: [#<issue_number>] ...` — bare `TODO:`/`FIXME:` warn.
- **SwiftLint disables**: only the exceptions listed in `SWIFTLINT.md` are permitted, always scoped with `// swiftlint:disable:next` / `disable:previous` / region blocks. `SWIFTLINT.md` also documents the required Xcode setting for trimming trailing whitespace (including whitespace-only lines) — configure it before editing.
- **Comments**: properly punctuated prose sentences that explain *why*, not *what* (see `CONTRIBUTING.md`).
- **Commits and PRs**: every PR must reference an issue. Commit title format is `[#<issue_number>] <self-descriptive title>` (see `CONTRIBUTING.md`). PRs are always landed with a merge commit, never squash-merged; keep branch commits tidy and self-contained.
- **Test plan**: every PR needs a documented test plan, including how to manually verify the change on testnet where applicable (see `CODE_REVIEW_GUIDELINES.md`).
- **Docs location**: user-facing documentation belongs in `docs/`.
- **Design docs and plans**: write them to `.plans/` at the repository root, which is gitignored. Design notes, implementation plans, and handoff documents are conversation artifacts, not repository history — never commit them. Create `.plans/` (and add it to the checked-in `.gitignore`) if it is absent, and report the full, untruncated path of anything written there so it can be copy-pasted.
- **Rust formatting**: always run `cargo fmt` in `rust/` before committing changes to the Rust code. Consistent formatting keeps diffs minimal and avoids spurious conflicts when rebasing.
- **Main branch policy**: `main` is development-stable (all merges build + tests pass) but clients must depend on published tags, never on `main`.
- **Sync concurrency**: `CompactBlockProcessor` is a Swift actor. Callers without structured concurrency should hop to `@MainActor` contexts rather than blocking.

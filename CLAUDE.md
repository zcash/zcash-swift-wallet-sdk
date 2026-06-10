# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

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

- gRPC lightwalletd client: `Modules/Service/GRPC/` (proto files under `ProtoBuf/proto/` — generated `*.pb.swift`/`*.grpc.swift` files are checked in and excluded from SwiftLint; regenerate them, don't hand-edit).
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

## Conventions and gotchas

- **Logging**: never call `print`, `debugPrint`, or `NSLog` in app/SDK code — SwiftLint enforces this. Use the injected `Logger` (see README "Integrating with logging tools"). The `Logger` protocol is provided to `Initializer` via `loggingPolicy`.
- **String building**: use interpolation, not `+` concatenation (SwiftLint `string_concatenation` is severity `error`).
- **TODOs**: format as `TODO: [#<issue_number>] ...` — bare `TODO:`/`FIXME:` warn.
- **SwiftLint disables**: only the exceptions listed in `SWIFTLINT.md` are permitted, always scoped with `// swiftlint:disable:next` / `disable:previous` / region blocks.
- **Commits and PRs**: every PR must reference an issue. Commit title format is `[#<issue_number>] <self-descriptive title>` (see `CONTRIBUTING.md`). PRs are typically squash-merged.
- **Breaking API changes**: document them in `MIGRATING.md`, and add a `CHANGELOG.md` entry for every user-visible change.
- **Main branch policy**: `main` is development-stable (all merges build + tests pass) but clients must depend on published tags, never on `main`.
- **Sync concurrency**: `CompactBlockProcessor` is a Swift actor. Callers without structured concurrency should hop to `@MainActor` contexts rather than blocking.

## Slipstream (next-gen sync engine prototype)

Active multi-session project building a new Rust sync engine under `slipstream/` (branch `slipstream`).
For any Slipstream / sync-engine work: read `docs/slipstream/STATE.md` FIRST (current status + next task),
then `docs/slipstream/CONVENTIONS.md` (session protocol + always-green commands).
The old SDK sync path is frozen for this work — additive changes only.

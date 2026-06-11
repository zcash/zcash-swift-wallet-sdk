# Slipstream — Working Conventions

> Read once per session, after STATE.md. These keep code from N sessions looking like it came from one author.

## Session protocol (priority #1: survive interruptions)

1. **Bootstrap (every session):** read `STATE.md` → read the current phase plan in `plans/` → `git status && git log --oneline -5` on `slipstream` → run the always-green commands (below) to confirm baseline before writing anything.
2. **One task per session** by default. Never start a task you can't checkpoint. If a task turns out bigger than a session: finish a coherent sub-step, commit it green, and write exactly where you stopped (file, next step) into STATE.md session notes.
3. **Every commit contains:** the work + its tests green + the STATE.md update. A commit is the unit of resumability.
4. **Interrupted mid-task?** The rule is: repo must always be in a state where `git stash && always-green commands` pass. Uncommitted exploration goes to stash or is deleted; STATE.md says what was learned.
5. **Plan drift:** if reality contradicts the phase plan, do NOT improvise silently. Append a Decision Log entry (what changed, why), update the phase plan file, then continue.
6. **Detailed phase plans** are written by `T{N}.0` tasks in `docs/slipstream/plans/YYYY-MM-DD-phase-N-<name>.md` following the superpowers writing-plans format (bite-sized TDD steps, complete code, exact commands). Phase-plan step checkboxes are execution aids, not completion records — STATE.md task status is the single source of truth; never tick checkboxes after the fact.

## Always-green commands (must pass before AND after every commit)

```bash
cargo test -p slipstream-core -p slipstream-cli      # engine tests (fast)
swift test --filter OfflineTests                      # old SDK untouched (CI parity)
```

The cargo line runs before/after every commit. `swift test --filter OfflineTests` is required at every phase gate and whenever a commit touches anything outside `slipstream/` + `docs/` (Swift sources, Scripts/, root Cargo.toml, or modifications to existing Cargo.lock entries); pure slipstream-internal Rust commits (incl. additive Cargo.lock entries) may skip it.

Heavier checks, run when the touched area demands it:
```bash
./Scripts/init-local-ffi.sh --macos-only             # after any Cargo/workspace/FFI change
cargo test -p slipstream-core --features darkside -- --ignored --test-threads=1   # darkside integration; SERIAL ONLY (tests share the darkside server state); needs local lightwalletd, see below
```

**Single-slice landmine:** `./Scripts/rebuild-local-ffi.sh <arch>` REPLACES the whole local XCFramework with ONLY that slice (by design — fast iteration). After using it, other-platform builds/tests fail with "framework doesn't exist". Restore all 3 slices with `./Scripts/init-local-ffi.sh` (cargo-cached, mostly relink time). Slipstream work needs macOS (swift test) + ios-sim (Zodl simulator) + ios-device (device runs) — keep all three unless actively iterating on one.

**SPM staleness landmine:** after ANY local-FFI mode switch (`init-local-ffi.sh`/`reset-local-ffi.sh`), `swift test` may fail with "package at .../LocalPackages cannot be accessed" — Package.swift is byte-identical in both modes, so SPM's shared manifest cache replays the stale evaluation. Fix (verified 2026-06-10):
```bash
rm -rf ~/Library/Caches/org.swift.swiftpm/manifests && rm -rf .build
```

Darkside lightwalletd (for integration tests):
```bash
Tests/lightwalletd/lightwalletd --no-tls-very-insecure --data-dir /tmp --darkside-very-insecure --log-file /dev/stdout
```

## Git

- **LOCAL-ONLY (do not lift without explicit user instruction):** never `git push` any Slipstream work to ANY remote (this repo's fork or upstream, or the Zodl repo), never create remote issues/PRs. The prototype exists only on this machine.
- Branch: `slipstream` (this repo). Never commit to `main`.
- Commit format: `[#<tracking-issue>] slipstream: <imperative title>` (issue number lives in STATE.md).
- **Containment:** all work lives under `slipstream/` + `docs/slipstream/`. Permitted exceptions only: root `Cargo.toml` workspace lines, `CLAUDE.md` pointer, P4 FFI exports in `rust/src/lib.rs`, P4 Swift files in `Sources/ZcashLightClientKit/Slipstream/`. Background design documents (read-once reference, e.g. `docs/SLIPSTREAM_DESIGN.md`, `docs/SYNC_PERFORMANCE_PROPOSAL.md`) live at `docs/` top level — allowed.
- Old SDK files: additive changes only. Never modify `Block/`, `Synchronizer/SDKSynchronizer.swift`, or the action machine.
- **Zodl iOS repo** (P4+): `/Users/lukaskorba/Dev/Xcode/GitHub/LukasKorba/secant-ios-wallet` (remote `zodl-ios`). Read/write + git granted. Work on a `slipstream` branch cut from Zodl's **main** (the checkout may sit on unrelated feature branches — never base on those). Same one-task/commit/STATE.md discipline applies.

## Rust style (slipstream crates)

- Edition 2024, same toolchain as root (`rust-version = 1.90`).
- **No `unwrap`/`expect` outside tests.** Errors: one `thiserror` enum per module, flattened into `SlipstreamError` at the crate boundary.
- **No `println!`/`eprintln!`** in `slipstream-core` — `tracing` only (`info!/debug!/warn!` with structured fields). CLI may print.
- Async: tokio; CPU-bound work via `rayon` (global pool, already initialized by libzcashlc in-app; CLI initializes its own).
- Concurrency boundaries are **typed channels**; no shared mutable state across tasks except the documented snapshot atomics.
- Public items get doc comments; modules start with a 3–6 line "why this exists" header.
- TDD: write the failing test first for logic; integration tests live in `slipstream/core/tests/`; darkside-dependent tests are `#[ignore]` + feature-gated `darkside` so plain `cargo test` stays hermetic.
- Versions: reuse the workspace's existing crate versions (`zcash_client_backend 0.23`, `zcash_client_sqlite 0.21`, `tonic 0.14`, `prost 0.14`, `rayon 1.7`). New deps need a Decision Log entry.

## Swift style (P4+ only)

- Follow existing SDK conventions (SwiftLint rules apply; injected `Logger`, no `print`; `TODO: [#issue]` format).
- New files only: `Sources/ZcashLightClientKit/Slipstream/…`.

## Naming

- Crates: `slipstream-core`, `slipstream-cli` (dirs `slipstream/core`, `slipstream/cli`).
- FFI: `zcashlc_slipstream_*`. Swift: `SlipstreamSynchronizer`, `SlipstreamEngine` (FFI wrapper).
- Modules in core: `grpc`, `chunk`, `fetch`, `verify`, `block_source`, `wallet_session`, `scan`, `scheduler`, `enhance`, `transparent`, `events`, `engine`.

## Measurement discipline

- Every performance claim gets a row in STATE.md's truth table (machine, server, range, wall-clock, bound). No vibes.
- Benchmarks are CLI subcommands (reproducible by any session), not one-off scripts.

**STATE.md edit safety:** scripted/programmatic edits to STATE.md MUST assert their anchors exist before writing and verify the post-edit line count (append-only growth expected; any large deletion = abort and re-read). Recovery precedent: 2026-06-11 truncation, restored from git.

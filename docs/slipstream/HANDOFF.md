# Slipstream + Zodl macOS — team handoff

**2026-07-04.** Lukas is away; this is the operating manual. It assumes you are a Zodl
engineer with no prior slipstream context. Everything below is on public GitHub — nothing
lives only on Lukas's machine.

## 1 · The map

| Layer | Repo · branch | State |
|---|---|---|
| **Engine** (platform-neutral Rust) | [`LukasKorba/slipstream`](https://github.com/LukasKorba/slipstream) `main`, tag **v0.3.6** | The published snapshot. Development happens in the SDK repo's `slipstream/` directory and is re-extracted here per release. Start reading at `REVIEWING.md` (module map) and `HOSTING.md` (how a host drives it). |
| **SDK** (Swift, fork of zcash/zcash-swift-wallet-sdk) | [`LukasKorba/ZcashLightClientKit`](https://github.com/LukasKorba/ZcashLightClientKit) branch **`slipstream`**, tag **`zodl-beta4-rc1`** | Carries the engine (in `slipstream/`), the FFI additions (`rust/src/lib.rs`, `zcashlc_slipstream_*`), and `SlipstreamSynchronizer`. **Dual-engine**: the legacy `SDKSynchronizer` path is intact and frozen — same `Synchronizer` protocol, same `Initializer`, same `data.db`. |
| **App** | `LukasKorba/zodl-ios` branch **`slipstream-macos`**, tag **`beta4-rc1`** | The macOS product line (Beta 4 RC1 = the first slipstream-default build) + all shared fixes. Upstream `zodl-inc/zodl-ios` `main` is merged in (as of `33639517`). |

**Version scheme:** engine crates + public tags = `0.3.x` (0.3.6 current). Zodl macOS betas =
build numbers (Beta2=3, Beta3=4, Beta4=5) on marketing version 3.7.1.

## 2 · The one-switch safety story

`FeatureFlag.useSlipstreamSynchronizer` (Zodl `WalletConfig.swift`) chooses the engine at
startup. Defaults are **platform-split: macOS `true`, iOS `false`.**

**If slipstream misbehaves in the field and nobody can diagnose it: flip the default to
`false` and ship.** The legacy engine is fully functional, byte-compatible on the same
`data.db`, and receives upstream fixes (last merged: the Tor-retry hardening). That is the
emergency lever; it requires zero slipstream knowledge.

## 3 · Building

### Zodl (what you'll do most)
1. Clone **both repos side-by-side** (the app references the SDK by relative path
   `../ZcashLightClientKit`):
   ```
   ~/dev/ZcashLightClientKit   (branch: slipstream)
   ~/dev/zodl-ios              (branch: slipstream-macos)
   ```
2. The SDK needs the slipstream-era `libzcashlc` binary. Two ways:
   - **No Rust toolchain (recommended):** ensure the SDK checkout has **no `LocalPackages/`
     directory** — `Package.swift` then pulls the prebuilt XCFramework release from the fork
     (release `2.6.0-slipstream.1`; see §5 if `Package.swift` still points at an older zcash
     release — the pointer bump lands when the release publishes).
   - **With Rust (for engine/FFI work):** `./Scripts/init-local-ffi.sh` in the SDK repo
     (builds all 5 targets, ~20–40 min once, then incremental). ⚠ `rebuild-local-ffi.sh
     <arch>` REPLACES the whole xcframework with ONE slice — after using it, run the full
     init before building any other platform.
3. Open `secant.xcodeproj`. Schemes: **`zodlmac-internal`** (macOS) / `zodl-internal` (iOS).
   KeystoneSDK is vendored in-repo (`LocalPackages/keystone-sdk-ios`) — no extra setup.

### SDK / engine
- Swift gate (what CI runs): `swift test --filter OfflineTests` (515 tests).
- Engine gate: `cargo test -p slipstream-core -p slipstream-cli` (195 + 29 + 1) from the SDK
  repo root. Always-green rule: both gates pass on every commit of `slipstream`.
- Full reference: `docs/LOCAL_DEVELOPMENT.md`, `docs/slipstream/CONVENTIONS.md`.

## 4 · The documentation index (read in this order)

1. `docs/slipstream/STATE.md` — the living log; the TOP entry is always the current state
   and the next action. **Every work session updates it in the same commit as the work.**
2. `docs/slipstream/SCENARIO_MATRIX.md` — 42 lifecycle scenarios with per-row verdicts.
   **This is the release-gate tracking sheet**: flip 🟡→✅ with a date when a device test
   passes. Zero 🔴 remain.
3. `docs/slipstream/BETA4_RC1_GATE.md` — the six-gate go/no-go session for RC1 (run it on
   the installed build; ~90 min).
4. `docs/slipstream/INTEGRATION_GUIDE.md` — how an app integrates the SDK correctly (the
   render-verbatim rules: progress, balances, `isRecovering` are engine-guaranteed — do NOT
   re-derive them app-side).
5. Engine repo: `REVIEWING.md` (module map for protocol engineers), `HOSTING.md` (the crate
   contract for any host), `docs/book/` (20-chapter deep dive).
6. Zodl repo: `docs/macos/DESIGN_LANGUAGE.md` (+ `BETA4_PUNCHLIST.md` for the fix history,
   `docs/macos/MODALS.md`, `FOUNDATIONS_F1_VERDICTS.md`).

## 5 · Release procedures

- **FFI XCFramework (SDK binary):** GitHub Action `Build FFI XCFramework` on the fork
  (`workflow_dispatch`, pick branch `slipstream`, give a version like `2.6.0-slipstream.N`).
  It builds all targets and drafts a GitHub release. Then update `Package.swift`'s
  binaryTarget URL + checksum to the new release (the draft's notes carry the checksum;
  `Scripts/prepare-release.sh` / `release.sh` automate this) and publish the draft.
- **Engine release:** bump `slipstream/{core,cli}/Cargo.toml` versions in the SDK repo, then
  re-extract to the public repo: `rsync -a --delete` the four crate dirs, run the standalone
  cargo gate there, update `README.md`'s versioning map + `REVIEWING.md`, commit, tag
  `v0.3.x`, push.
- **Zodl macOS beta:** bump the macOS target's build number in the project, archive
  `zodlmac-internal`, notarize. Tag the commit (`beta4-rc1` pattern).

## 6 · Operating slipstream (what the logs mean)

- The engine logs under `slipstream_core::*`. A sync pass: `engine pass starting` → fetch
  `sub-chunk emitted` → `chunk scanned` → `sparse put_blocks` (the write-behind commit) →
  enhancement rounds → `SyncDone`.
- **`session stays alive — reviving after non-transient failure revivals=N backoff_secs=…`**
  — a pass failed and the engine is self-healing (15 s → 5 min capped backoff). One error
  dialog may show; sync resumes by itself. If revivals keep climbing forever, capture the
  `slipstream sync failed err=…` line above it — that's the root cause.
- **`scan queue: dropped orphaned historic ranges`** — normal after an account deletion; the
  engine pruning work that no remaining account needs.
- **`slipstream stop/start: drained in-flight wallet commit`** — normal; stop() waits for
  the wallet file to be quiescent (bounded ≤10 s) before account
  delete/import/rewind proceed.
- The app decides "Restoring vs syncing" from `SynchronizerState.isRecovering` — engine-
  computed and truthful from the first poll. Progress/balance/Activity during a restore are
  engine-guaranteed to never over-show. Render them verbatim; never re-derive.

## 7 · Known-open items (none block RC1)

> **2026-07-05 — v0.4 shipped to default.** Graft + batch-affine are DEFAULT ON
> (engine 0.4.0, `2026-07-05.v04-defaults-on`); kill switches
> `ZCASH_GRAFT_SUBTREE=0` / `ZCASH_BATCH_COMBINE=0`. Full gate record:
> `plans/2026-07-04-v04-graft-dont-grind-design.md` addendum. v0.5 opener
> approved: Plan C batched trial-decrypt (`plans/2026-07-05-plan-c-batched-decrypt-minispec.md`,
> C0 gate passed — DH = 92.4% of compact decrypt).

- The six-gate RC1 session (`BETA4_RC1_GATE.md`) — Lukas runs it on the installed build;
  remaining SCENARIO_MATRIX 🟡s green out during the soak.
- **Fork FFI release `2.6.0-slipstream.1` (team/CI-owned)** — a `Build FFI XCFramework` run
  is in flight on the fork ([run 28707492254](https://github.com/LukasKorba/ZcashLightClientKit/actions/runs/28707492254)).
  When it succeeds: publish the draft release it creates, then bump `Package.swift`'s
  binaryTarget URL + checksum to it (checksum is in the draft notes / `release.env`) and
  push. Until then, prebuilt-binary builds pull the official `2.6.0-alpha.6` zip, which has
  **no slipstream symbols** — building the SDK requires the Rust path
  (`./Scripts/init-local-ffi.sh`, §3). If the run failed, re-dispatch the workflow on
  branch `slipstream` with the same version (the upload-403 bug is already fixed,
  `04db2de1`).
- B4-18: Add-HW-wallet flow renders no "Restoring" state on first add (engine/SDK lane,
  punchlist).
- Transparent-funds trio (flagged v3 in `plans/2026-07-03-thin-sdk-sweep.md` §3).
- Upstreaming to `zcash/zcash-swift-wallet-sdk`: **DRAFT PR open —
  [zcash/zcash-swift-wallet-sdk#1800](https://github.com/zcash/zcash-swift-wallet-sdk/pull/1800)**.
  It stays draft until the `WalletInitMode` source-compat shim lands, internal docs are
  stripped, and the vendor-vs-crates.io question is settled with maintainers — the full
  sequence is in `docs/slipstream/2026-07-03-upstreaming-analysis.md`. Nothing operational
  depends on it.
- Zodl `slipstream-macos` → `zodl-inc main`: **PR open and ready for review —
  [zodl-inc/zodl-ios#1864](https://github.com/zodl-inc/zodl-ios/pull/1864)**. iOS behavior
  is preserved by the platform-split flag default; the PR description lists what reviewers
  should do (one iOS QA pass). The team owns the merge decision.

## 8 · Emergency contacts between the code and you

Every non-obvious decision in this codebase is written down next to the code it governs
(the comment style is deliberate: constraints and field evidence, with issue numbers).
When something looks wrong, `git log -p` the file and read the message of the commit that
introduced it — the messages carry the failure scenario that motivated each change.

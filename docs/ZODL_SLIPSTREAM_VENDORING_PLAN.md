# Vendor ZODL Slipstream as an opt-in variant of the Swift SDK

## Context

`zodl-slipstream` 0.1.1 (AGPL-3.0-only, dual-licensed commercially by Znewco/ZODL, licensing@zodl.com) is today an **unconditional** Cargo dependency of the in-tree `libzcashlc` staticlib, so the released `libzcashlc.xcframework` ships AGPL code to every SDK consumer — even those who never construct `SlipstreamSynchronizer`. Runtime opt-in is irrelevant to AGPL (distribution triggers it), and ZODL's `LICENSE-EXCEPTIONS.md` §2(b) explicitly withholds the AGPL §7 App Store permission from third parties — so third-party wallets shipping today's artifact to the App Store are outside the granted permissions unless they buy a commercial license.

Crucially, classic **Spend-before-Sync is not slipstream**: it's the pre-existing `suggestScanRanges` ordering in `SDKSynchronizer`/librustzcash and works without the AGPL engine. Opting out loses only the fast Rust engine.

**Goal**: restructure so the default product is MIT-clean (zero AGPL code in the binary) with classic SbS intact, and slipstream becomes an explicit opt-in product named **ZODL Slipstream** — per user decision and the crate's trademark/naming conditions (§4). Prior art: arthenica/ffmpeg-kit's dual `-gpl` artifacts (same API, checksum-pinned variants per release).

### Decisions (confirmed 2026-08-12)
- Default `ZcashLightClientKit` product/artifact: **MIT-clean**.
- Slipstream naming must reference **"ZODL Slipstream"**.
- In scope: AGPL notices/docs **and** CI cleanup (obsolete `authorize-slipstream` machinery — crate moved from private git to public crates.io in `edfd71b3`).
- Packaging shape (my recommendation, not explicitly picked by user — confirm at review): **single repo, two SwiftPM products, two xcframework artifacts per release**.

### Naming
| Thing | Name |
|---|---|
| Swift product + target + module | `ZODLSlipstream` (`Sources/ZODLSlipstream/`) |
| Cargo feature | `slipstream` |
| Rust module | `rust/src/slipstream_ffi.rs` |
| Clean artifact | `libzcashlc.xcframework.zip` (unchanged) |
| Slipstream artifact | `libzcashlc-zodl-slipstream.xcframework.zip` (inner xcframework/module stays `libzcashlc`) |
| Variant marker file | `.zodl-slipstream-variant` (repo root, gitignored; committed only by release automation) |
| Variant release tag | `X.Y.Z-zodl-slipstream` |
| cbindgen C define | `ZCASHLC_FEATURE_SLIPSTREAM` |

### Verified facts the design rests on
- `slipstream_core` is referenced **only** in `rust/src/lib.rs` ~4718–6856 (the FFI block: 11 `zcashlc_slipstream_*` fns + helpers + 2 test mods) and `rust/src/retained_marks.rs` (sole caller: `lib.rs:4983` inside `zcashlc_slipstream_open`). `ffi.rs`/`migration.rs` mention slipstream only in comments/SQL — no gating needed. Direct `tokio::` use is confined to that block (lib.rs:4997, 5009, 5450, 5649).
- Rust migration is engine-independent (`anchor_retention_interval` at lib.rs:152–202 stays ungated); clean-build migration keeps working.
- Only `Sources/ZcashLightClientKit/Slipstream/` (5 files, ~2.4k lines) calls `zcashlc_slipstream_*`. Other core references (Initializer hook, `TransactionDao` view read, ZRUST0093–0097, comments) are engine-independent and inert without the engine.
- `Initializer.slipstreamAnchorSource` (Initializer.swift:160) names `SlipstreamRestoreAnchor` (plain struct, SlipstreamEngine.swift:296) — must be extracted to core.
- `Package.swift` is tools-version 5.6, single product, existing filesystem-probe pattern for local FFI (lines 9–10, 24–38).

## Implementation (ordered; each phase leaves main green for the clean variant)

### Phase 1 — Rust feature gating
1. `Cargo.toml`:
   ```toml
   slipstream-core = { version = "0.1.1", package = "zodl-slipstream", optional = true }
   tokio = { version = "1", features = [...], optional = true }
   [features]
   default = []
   slipstream = ["dep:slipstream-core", "dep:tokio"]
   gpu = ["slipstream", "slipstream-core?/gpu"]
   ```
   Delete the stale commented `[patch.crates-io]` slipstream pin and rewrite the pre-crates.io dependency comment (~lines 114–126).
2. Extract lib.rs ~4718–6856 into `rust/src/slipstream_ffi.rs`; declare `#[cfg(feature = "slipstream")] mod slipstream_ffi;` and gate `mod retained_marks;` the same way (its call site moves into the new module). One cfg per `mod` line — the file boundary is the licensing audit boundary. `#[no_mangle]` symbol names unaffected. Expect a mechanical `pub(crate)` pass on private helpers the block uses (`catch_panic`, `unwrap_exc_or*`, `wallet_db`, `free_ptr_from_vec*`, …).
3. cbindgen — **one guarded header** (spike this first, ~10 min): in `rust/build.rs` add `.with_define("feature", "slipstream", "ZCASHLC_FEATURE_SLIPSTREAM")` so slipstream items in `zcashlc.h` are wrapped in `#if defined(ZCASHLC_FEATURE_SLIPSTREAM)`. Specialize at packaging time with `unifdef` (ships with macOS; `-x2` since it exits 1 on change): clean framework `-U`, slipstream framework `-D`. Rationale: accidental core references fail at *compile* time, not at consumer link time.

### Phase 2 — Artifacts & build scripts
- `BuildSupport/Makefile`: `SLIPSTREAM=0|1` → `--features slipstream`; separate output trees `products/` (clean, unchanged paths → CI cache keys survive) and `products-slipstream/`; apply unifdef in framework assembly. Shared cargo `target/` thrashes on feature flips (~2 min LTO relink/arch) — fine for CI (variant-keyed caches), document `CARGO_TARGET_DIR` for local dev.
- `Scripts/prepare-release.sh --slipstream`: builds superset, zips as `libzcashlc-zodl-slipstream.xcframework.zip`, uploads to the **same** draft release, appends `SLIPSTREAM_CHECKSUM`/`SLIPSTREAM_DOWNLOAD_URL` to `release.env`. Add the nm symbol gate (Verification) so a contaminated "clean" zip cannot ship.
- `Scripts/init-local-ffi.sh` / `rebuild-local-ffi.sh`: add `--slipstream` (existing `--gpu` now implies it); sets the feature and `touch .zodl-slipstream-variant`; plain init removes the marker. `LocalPackages/` layout unchanged (one xcframework, clean or superset).

### Phase 3 — SwiftPM graph (with Phase 4 in one PR; coupled by tools bump + marker)
Rejected honestly: two coexisting binaryTargets (duplicate `zcashlc_*` symbols under LTO), product-conditional binaryTargets (doesn't exist in SwiftPM), env-var probes (Xcode sandboxes dependency manifests), subdirectory manifests (URL resolution sees root only), SwiftPM traits (Swift 6.1; Xcode app projects can't enable traits yet — record as future simplification).

**Design**: bump to `// swift-tools-version:5.9`; keep exactly one binaryTarget named `libzcashlc` per graph and switch its URL/checksum on the marker file (same shape as the existing local-FFI probe):
- Marker absent (default): clean binaryTarget; only the `ZcashLightClientKit` product exists.
- Marker present: superset binaryTarget; **both** core and `ZODLSlipstream` target depend on it (superset is safe for core — every `zcashlc_*` symbol resolves); add `ZODLSlipstream` product + slipstream test targets inside the `if slipstreamVariant` branch.
- `Package.swift` release block carries **both** URL/checksum pairs (written by `release.sh` from `release.env`).

**Release choreography** (`Scripts/release.sh`): tag `2.9.0` on the release commit (marker absent). Then one extra commit adding only the marker on `release/2.9.0-zodl-slipstream`, tagged `2.9.0-zodl-slipstream`. SemVer pre-release suffix sorts below the release, so `from: "2.9.0"` can never auto-select the AGPL variant — opt-in is structurally guaranteed. Consumers use `.package(url:…, exact: "2.9.0-zodl-slipstream")` + `import ZODLSlipstream`; document "exact-only, no ranges" loudly.

### Phase 4 — Swift target split
- Move the 5 `Slipstream/` files to `Sources/ZODLSlipstream/`, adding `import ZcashLightClientKit`; **except** extract `SlipstreamRestoreAnchor` (plain struct) into core (`Sources/ZcashLightClientKit/Initializer+SlipstreamAnchor.swift`, `package` visibility) since `Initializer.slipstreamAnchorSource` names it. The FFI-calling resolver stays in the add-on.
- Access control: use the **`package`** modifier (hence 5.9 bump) — not `@_spi`, not `public`. Compiler-driven pass (~40–60 declarations): `Initializer` members (`container`, `rustBackend`, `transactionRepository`, `lightWalletService`, `blockDownloaderService`, `logger`, `initialize`, URLs, `slipstreamAnchorSource` setter, …), `DIContainer`, `TransactionRepository` (incl. `unreconciledTxids()`), `TransactionEncoder`, `ZcashRustBackendWelding`, `SDKFlags`, `InternalSyncStatus`, `OrchardMigrationHost`, `CheckpointSource`.
- Cross-cutting core code — **keep, name-only policy** (state it in the PR): `slipstreamAnchorSource` hook (nil-defaulting; installed only by the add-on), `TransactionDao.swift:119-128` view read (degrades to empty without the view), error codes ZRUST0093–0097 (inert; removing churns Sourcery output and breaks code stability), comments. Clean product may reference slipstream *by name* but has no code path reaching an engine symbol.

### Phase 5 — Tests
- Move the 3 slipstream OfflineTests files → `Tests/SlipstreamOfflineTests/`, `SlipstreamDarksideTests.swift` → `Tests/SlipstreamDarksideTests/`; declare both test targets only in the `slipstreamVariant` branch (they hit `zcashlc_slipstream_open`); imports gain `@testable import ZODLSlipstream`.
- Rust: `cargo test` (default) stays green with modules absent; CI adds `cargo test --features slipstream`. Root `Makefile`: `test-offline-slipstream`; update `ZcashLightClientKit.xctestplan` if it enumerates moved classes.

### Phase 6 — CI
- **Delete** `.github/actions/authorize-slipstream/` and its call sites (`build-ffi.yml:27`, `swift.yml:48`, `codeql.yml:125`) + stale private-repo cache commentary.
- `build-ffi.yml`: run `prepare-release.sh` then `prepare-release.sh --slipstream` (sequential reuses cargo cache; or a variant matrix with variant-keyed caches); both zips on one draft release; summary prints both checksum pairs.
- `swift.yml`: two jobs — *clean* (today's flow + nm symbol gate) and *slipstream* (`SLIPSTREAM=1`, touch marker, build + `SlipstreamOfflineTests`). Variant-keyed FFI caches.
- `codeql.yml`: build the slipstream variant (superset compiles every Swift source → whole tree scanned in one pass).

### Phase 7 — Docs & notices
- `Sources/ZODLSlipstream/NOTICE.md` (canonical): variant links `zodl-slipstream` (AGPL-3.0-only) → combined artifact distributed under AGPL terms; repo Swift sources remain MIT; commercial contact licensing@zodl.com; **App Store caveat** (no §7 permission for third parties; AGPL widely considered App-Store-incompatible — commercial license required); trademark/naming conditions per `LICENSE-EXCEPTIONS.md` ("ZODL Slipstream" product name satisfies the naming condition — cite it).
- `README.md` "Choosing a variant": default = MIT, zero AGPL, classic SbS via `SDKSynchronizer`; `ZODLSlipstream` = `exact:` variant tag, license consequences, NOTICE link.
- `MIGRATING.md` + `CHANGELOG.md`: existing `SlipstreamSynchronizer` users add the variant tag + `import ZODLSlipstream`; tools-version 5.9 floor. Root `LICENSE` stays MIT untouched.

### Versioning
Target **2.9.0**, not 2.8.0-final (tools-version bump, module moves, release-automation rewiring mid-rc). Ship 2.8.0 final as-is, land this immediately after, cut `2.9.0` + `2.9.0-zodl-slipstream` as the first dual release.

## Risks
1. cbindgen `defines`-through-`mod` behavior — the one unexecuted assumption; de-risk with the Phase 1.3 spike **first**.
2. `package`-modifier churn breadth (~40–60 decls) — mechanical; compiler is the checklist.
3. Variant-tag drift — mitigated: variant commit differs by exactly one file, created only by `release.sh`.
4. Consumers pinning ranges across variant tags — `exact:` only, documented loudly.
5. 2× LTO build time in `build-ffi.yml` — acceptable on a manual release workflow.

## Verification
Clean-artifact purity (also a hard gate in `prepare-release.sh`):
```bash
cargo tree --edges normal | grep -ic zodl                    # 0 (default features)
nm -gU target/aarch64-apple-darwin/release/libzcashlc.a | grep -c zcashlc_slipstream   # 0
strings …/libzcashlc.a | grep -ci slipstream                 # 0 (or triage)
grep -c ZCASHLC_FEATURE_SLIPSTREAM <clean framework Headers/zcashlc.h>  # 0 after unifdef
```
Superset completeness: `comm -13 <(nm clean|sort) <(nm slip|sort)` shows only slipstream additions incl. all 11 `_zcashlc_slipstream_*`.
Suites: `swift build && swift test --filter OfflineTests` (no marker, clean local FFI); `Scripts/init-local-ffi.sh --slipstream && swift test --filter SlipstreamOfflineTests`; `cargo test` and `cargo test --features slipstream`; Darkside per variant manually.

## Critical files
- `Package.swift` — dual-product/marker graph
- `Cargo.toml`, `rust/src/lib.rs` (→ new `rust/src/slipstream_ffi.rs`), `rust/build.rs`
- `BuildSupport/Makefile`, `Scripts/prepare-release.sh`, `Scripts/release.sh`, `Scripts/init-local-ffi.sh`, `Scripts/rebuild-local-ffi.sh`
- `Sources/ZcashLightClientKit/Slipstream/*` → `Sources/ZODLSlipstream/*` (+ `SlipstreamRestoreAnchor` extraction from `SlipstreamEngine.swift:296` into core)
- `.github/workflows/{build-ffi,swift,codeql}.yml`, delete `.github/actions/authorize-slipstream/`

# Upstreaming Slipstream into zcash/zcash-swift-wallet-sdk — what's actually needed

> **⚠ v0.5 ADDENDUM (2026-07-06) — §2's "zero [patch] sections" claim is now STALE.**
> v0.5 introduced vendored forks (`slipstream/vendor/orchard` 0.14.0 + `zcash_note_encryption`
> 0.4.1) wired via workspace members + `[patch.crates-io]` (SDK root Cargo.toml AND the
> published engine repo). The forks carry the `BatchDomain::batch_ka_agree_dec` seam and the
> GLV `endo.rs` ladder (default ON since 2026-07-06). Consequences for this plan:
> - **The "publish slipstream-core to crates.io" recommendation (§TL;DR-2) no longer works
>   as-is**: `[patch.crates-io]` does not propagate to crates.io consumers, so a published
>   slipstream-core would resolve the REAL orchard and fail to compile against the fork-only
>   `orchard::endo`/`batch_dh` APIs.
> - Three resolution paths, in preference order: **(a) upstream the seam** — PR the
>   `batch_ka_agree_dec` seam to zcash/librustzcash (zcash_note_encryption) and `endo.rs`
>   to zcash/orchard (the mini-spec §5b thread; both are small, additive, byte-identical,
>   KAT-gated — after which the forks die and §2 is true again); **(b) vendor in-tree in the
>   upstream SDK PR** (works today, +~14k lines of vendored fork, upstream carries the patch
>   sections); **(c) publish the forks under distinct names** (orchard-slipstream) — last resort.
> - Path (a) is also the strongest strategic move: the endo win (−24% DH core-time,
>   byte-identical) benefits every orchard consumer and builds upstream credibility ahead of
>   the SDK PR. Estimated PR size: endo.rs ~380 lines + 3 KATs; the seam ~40 lines.


**2026-07-03 · Analysis for Lukas.** Goal (his words): get slipstream into the upstream SDK
"off by default by flag — code there, not used, old SDK works", so the `slipstream` branch no
longer needs to be held on the SDK fork and the only long-lived branch left is Zodl's.

**TL;DR — it's a smaller lift than expected, with one real decision and one real fix:**

1. **No librustzcash PR is needed.** The engine and the FFI additions consume PUBLISHED
   crates.io librustzcash only — zero git dependencies, zero `[patch]` sections anywhere
   (verified across all five Cargo.toml files). The shardtree `SparseCachingShardStore`
   PR (#181, with Danny) is an independent nice-to-have; slipstream pins published shardtree
   and does not depend on that PR landing.
2. **The one real decision: vendor the engine in-tree vs publish `slipstream-core` to
   crates.io.** Recommendation: **publish to crates.io** — it shrinks the upstream diff by
   ~35k lines, keeps engine development in `github.com/LukasKorba/slipstream` (exactly the
   "only Zodl holds a branch" end-state), and it is publishable today (MIT, self-contained,
   published deps only).
3. **The one real fix: a compatibility shim for the `WalletInitMode` removal.** It is the
   only breaking public-API change on the branch. ~20 lines restores full source
   compatibility and makes the whole PR additive.

---

## 1. Current divergence (measured 2026-07-03)

- Fork: `LukasKorba/ZcashLightClientKit`, branch `slipstream`; upstream:
  `zcash/zcash-swift-wallet-sdk` (`upstream` remote).
- **199 commits ahead, 2 behind** (upstream moved twice since the last merge — trivial
  merge before PRing).
- **140 files changed: +40,872 / −274.** The +40k is dominated by NEW files:
  `slipstream/` engine crates (~34 files), `docs/slipstream/` (~52 files, internal),
  `Sources/…/Slipstream/` (Swift glue), tests. The **−274 in existing upstream files is
  the entire compatibility surface** — inventoried in §3.

## 2. The Rust story (the "which librustzcash" question)

- `libzcashlc` (rust/) and `slipstream-core` pin the SAME published crate set upstream
  already uses (`zcash_client_backend 0.23`, `zcash_client_sqlite 0.21`, `zcash_keys 0.14`,
  `zcash_protocol 0.9`, …). We track upstream's FFI line (currently `2.6.0-alpha.4` in-tree)
  and have merged their releases cleanly all along (e.g. 2.6.0-alpha.6 era, #1757).
- **No fork of librustzcash exists and none is needed.** No PR to zcash/librustzcash is a
  prerequisite.
- shardtree PR #181 (upstream zcash/incrementalmerkletree): independent performance
  contribution; the engine's 12× does NOT depend on it (the sparse-store win lives in
  slipstream's own `persist.rs` against published shardtree).
- `rust/src/lib.rs` additions are purely additive C symbols (`zcashlc_slipstream_*`:
  open/start/stop/snapshot/drain_events/notify_tx_change/wallet_summary/restore_anchor/free
  + two repr(C) structs). `rust/src/ffi.rs` gains four small crate-internal helpers on
  existing types (zero/from_spendable/uuid_bytes/…) — no public C ABI change to existing
  symbols, existing struct layouts untouched (all additions end-appended per the padding
  convention).

## 3. Public-API compatibility review (the −274 lines)

Modified upstream files fall into five classes:

**(a) BREAKING — needs the shim:**
- `Synchronizer.prepare(with:walletBirthday:for:name:keySource:)` →
  `prepare(with:walletBirthday:name:keySource:)` with `walletBirthday: BlockHeight?`;
  `WalletInitMode` enum deleted (the SDK now derives new/restore/existing from
  account-existence + birthday-presence). Breaks every client at compile time.
  **Fix: reintroduce `WalletInitMode` + a deprecated `prepare(…for:…)` overload as a
  protocol EXTENSION** mapping `.newWallet → walletBirthday: nil`, `.restoreWallet` /
  `.existingWallet → walletBirthday` as passed. Faithful to the old semantics (the
  derivation reproduces them), ~20 lines, makes the PR fully source-compatible; the
  removal itself becomes a proposal for upstream's next major.
- `Synchronizer.allTransactions()` was added as a protocol REQUIREMENT — source-breaking
  for third-party conformers (client-side mocks; Zashi has them). Move it to a protocol
  extension with a default implementation, or accept the break knowingly.

**(b) Additive public API (non-breaking):**
- `SynchronizerState.isRecovering: Bool` (defaulted in the public init).
- New public types: `SlipstreamSynchronizer` (actor, conforms to `Synchronizer`),
  `SlipstreamEngine`, `SlipstreamSnapshot`, `SlipstreamEngineEvent`.
- New `ZcashError` codes (generated via the existing Sourcery flow).
- `TransactionRepository.unreconciledTxids()` (+ DAO impl; defensive empty default).

**(c) Behavior changes to existing flows — disclose in the PR, likely wanted upstream:**
- Initializer seed↔account integrity guard (`ZINIT0006` `initializerSeedMismatch`):
  restoring a different seed over an existing wallet used to silently no-op (funds
  receivable but unspendable, sends fail ZRUST0002); now it throws. A correctness fix;
  imported-only wallets exempt.
- `Initializer.initialize` derives the init flow (was told via `WalletInitMode`); with the
  shim in (a), old callers keep compiling and get equivalent behavior.
- The slipstream anchor injection (`slipstreamAnchorSource`) is nil for `SDKSynchronizer` —
  the legacy fetch path is byte-for-byte intact (this was built deliberately for the
  old-path freeze; it is also exactly the "off by default" story upstream needs to see).

**(d) Behavior-identical refactors:** `ZcashRustBackend.getWalletSummary` now rides shared
`WalletSummary.fromFFI` + `withSpendableMasked()` helpers (same math, same `[#1591]` mask).

**(e) Ours-only noise to strip before PRing:** `CLAUDE.md` slipstream sections,
`docs/slipstream/` internal state/plans/audit (~52 files — replace with a curated set:
`INTEGRATION_GUIDE.md`, `ENGINE_API_V2.md`, the design doc), `SimpleConnectionProvider.swift`
WIP, local scripts that only serve our workflow. `CHANGELOG.md`/`MIGRATING.md` entries
already exist per upstream conventions and get reworded to match the final PR shape.

## 4. The vendoring decision (the only architectural question)

Two viable shapes for where the engine lives in upstream:

**Option A — publish `slipstream-core` to crates.io (RECOMMENDED).**
`rust/Cargo.toml` swaps `slipstream-core = { path = "slipstream/core" }` for
`slipstream-core = "0.3"`. The upstream diff drops to: `rust/src/lib.rs` FFI + the Swift
glue + tests (~5k lines instead of ~40k). Engine development, releases, and review stay in
`github.com/LukasKorba/slipstream` (v0.3.5 tagged today) — which is precisely the goal of
"keep only the Zodl branch": the SDK fork branch dissolves, the engine repo is the product.
Prereqs: `cargo publish` for `slipstream-core` (it is self-contained, MIT, publishable
today; `gpuhash` stays unpublished — the `gpu` feature is default-off and can be stripped
from the upstream feature graph or published later). One caveat to check at publish time:
crates.io requires all deps published (they are) and the `darkside` test feature's
generated proto stays behind a feature gate (it does).

**Option B — vendor `slipstream/` in-tree (what the branch does today).**
Works (CI proves it), but hands ECC a 35k-line engine to co-own in their repo, makes every
engine iteration an upstream PR, and re-couples you to their review latency — the opposite
of the stated goal. Only preferable if upstream explicitly wants to adopt the engine as
theirs.

## 5. CI / release mechanics (verified against the workflows in-tree)

- **Upstream CI builds the FFI from source** (`swift.yml`: builds the XCFramework into
  `BuildSupport/`, wires `LocalPackages/`, then `swift build` + OfflineTests). So a SINGLE
  PR carrying rust + Swift together is fully CI-testable — no two-step "release the FFI
  first" dance is required for review.
- The binary `Package.swift` flip happens only at THEIR release time (existing
  `Build FFI XCFramework` workflow) — the new `zcashlc_slipstream_*` symbols ride the next
  `libzcashlc` alpha automatically. `Package.swift` itself is untouched by our branch.
- Their gate is OfflineTests — ours pass 515/0 with slipstream included; the slipstream
  crate tests (187) would need a small workflow step if they want them in CI (worth
  offering in the PR).

## 6. Suggested sequence

1. **Now / cheap:** merge `upstream/main` (2 commits), strip §3(e) noise, add the
   `WalletInitMode` shim + `allTransactions()` extension-default. Result: a branch whose
   ONLY effect on existing clients is bug-fix (c) — old SDK works, slipstream dormant
   until a client instantiates `SlipstreamSynchronizer` (that IS the "flag": same
   `Initializer`, same protocol, same `data.db`; one class name decides the engine —
   document it in the PR as the opt-in).
2. **Publish `slipstream-core 0.3.x` to crates.io** and swap the path dep (Option A).
3. **Open an upstream ISSUE first, not a cold PR.** This is a second sync engine in their
   SDK — maintainer buy-in is the actual long pole, not the code. You have the contacts
   (Kris/nuttycom from the dedup thread, Daira; Danny already reviews the shardtree PR)
   and the killer artifact: measured **12× on-device** (25:11 → 2:05, A14 iPad, 269k-block
   restore) with the old path untouched. Propose: additive opt-in engine, evidence, the
   crates.io dependency shape, and the deprecation-not-removal of `WalletInitMode`.
4. **One PR** (rust FFI + Swift glue + tests + CHANGELOG), CI-green in their pipeline.
   Offer the darkside story honestly: the engine has its own crate tests + darkside
   feature + CLI harness; the SDK-level DarksideTests continue to cover the old path.
5. **After merge:** delete the fork's `slipstream` branch; engine work continues in
   `LukasKorba/slipstream` (crates.io releases), app work in Zodl's branch only. Zodl
   switches its SPM dependency back to upstream tags.

## 7. What this does NOT require

- No librustzcash fork or PR (published crates only — verified).
- No shardtree PR dependency (#181 is independent).
- No upstream release coordination before review (their CI builds FFI from source).
- No change to upstream's default behavior: `SDKSynchronizer` remains the default engine;
  nothing constructs slipstream unless a client does.

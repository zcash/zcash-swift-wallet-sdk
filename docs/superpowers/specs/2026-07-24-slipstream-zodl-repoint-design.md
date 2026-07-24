# Spec: Repoint slipstream-core to zodl-inc/slipstream @ michal/anchor-retention-interval-144

Approved 2026-07-24. Work branch: `michal/slipstream-zodl-repoint` (from `michal/slipstream-support` @ `dd6e4bef`). No Linear ticket for this work.

## Goal

The slipstream engine repo moved. Make the SDK consume `slipstream-core` from
`https://github.com/zodl-inc/slipstream.git` branch `michal/anchor-retention-interval-144`
(head `58aeac2b` at spec time), restore a working local-FFI dev setup in the Xcode
workspace, and land the change via a PR into `michal/slipstream-support`.

## Context established during brainstorming

- Committed state tracks `LukasKorba/slipstream.git` @ `michal/MOB-1455/MOB-1495-update-librustzcash-deps`,
  lock pinned to `187f639` for `slipstream-core 0.6.4` + `slipstream-gpuhash 0.0.1`.
- The zodl-inc repo is **private**; anonymous HTTPS fails, `gh` (account Chlup) and SSH work.
  Cargo uses `git-fetch-with-cli`, so git-CLI credentials govern cargo fetches.
- The new branch declares identical crates.io version reqs and pins the same librustzcash
  rev (`3a10e7f`) in its own (inert-as-dependency) patch table — the workspace's
  `[patch.crates-io]` keeps the crate graph a single family.
- Old-locked commit vs new head: 11 ahead / 4 behind; the 4 "behind" commits are the old
  PR #6 content, evidently squash-merged into the new repo's mainline (its anchor-144
  change is re-landed there; PR #6 does not exist in the new repo). The currently-locked
  commit already carries the 144-block anchor retention — no behavior change on that axis.
- Possible API drift from the 11 new commits (typed `sync_once` account / multi-account,
  `EngineConfig` probe-then-commit move, `report.rs` split). `rust/src/lib.rs` is the sole
  crate consumer (`ffi_handle`, `config::EngineConfig/Endpoint`, `session::*`, `anchor::*`,
  `wallet_session`, `scheduler`, `connector::TorConn`, `events::Progress`).
- Local FFI mode is active; `LocalPackages/libzcashlc.xcframework` has three arm64-only
  slices (ios-device, ios-sim, macos), built without `--gpu`.

## Approach (chosen among three)

**A — scoped re-resolve + incremental rebuild (chosen).** Edit the dependency line,
re-resolve only the two slipstream lock entries, let the compiler reveal drift, adapt,
rebuild the three slices incrementally.
**B — full `init-local-ffi.sh --arm-all`** — same end state, much slower; fallback only.
**C — pin `rev =` instead of `branch =`** — rejected; repo precedent is branch-tracking
with the lock pinning the exact commit.

## Changes

1. `Cargo.toml:120` — repoint URL + branch; rewrite the stale doc comment above it
   (references PR #6 and the old repo's lifecycle).
2. `Cargo.lock` — `cargo update -p slipstream-core -p slipstream-gpuhash`; both entries
   move to zodl-inc pinned at the branch head; no other lock churn; no duplicate crate
   families (new transitive deps required by the new commits are acceptable).
3. `rust/src/lib.rs` — adapt to compile drift. Authorized to extend/change the public
   Swift surface if the new engine API requires it, documented in MIGRATING.md +
   CHANGELOG.md ("adapt everything autonomously"). `cargo fmt` if Rust sources change.
4. LocalPackages rebuild — `rebuild-local-ffi.sh` for `ios-sim`, `ios-device`, `macos`
   (no `--gpu`), mirroring existing slices.

## Private-repo auth

Scope `credential.helper = !gh auth git-credential` to the cargo commands via
`GIT_CONFIG_*` environment variables — nothing written to machine git config. After the
lock pins the commit, cargo's git cache serves future builds offline. Final report notes
when a one-time `gh auth setup-git` is worth it.

## Verification (all must pass)

- `cargo check`/`cargo build` green; three slice rebuilds green.
- `swift build` green; `swift test --filter OfflineTests` green (CI parity).
- Lock inspection: both slipstream entries on zodl-inc @ same commit; single-family graph.

## Commits & PR

- Branch `michal/slipstream-zodl-repoint`; `[#1806]` commit convention; one atomic commit
  for Cargo.toml + Cargo.lock + compile-required adaptations; separate commits only for
  optional follow-ups. No CHANGELOG entry for the repoint itself (precedent `a849934f`)
  unless the Swift API moves.
- Push to origin (`zcash/zcash-swift-wallet-sdk`); PR base `michal/slipstream-support` ←
  head `michal/slipstream-zodl-repoint`, referencing issue #1806; no self-merge.

## Execution

Subagent-driven where sensible: mechanical resolve/build/test loops delegated to a
cheaper model (Sonnet); drift adaptation at high reasoning quality with TDD where a
testable seam exists. Stop only for real blockers; non-blocking findings go in the final
report (e.g. the FFI release GitHub Action needs credentials for the private repo).

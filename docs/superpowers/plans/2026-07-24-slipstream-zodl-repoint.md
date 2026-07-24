# Slipstream zodl-inc Repoint Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Repoint the `slipstream-core` git dependency from `LukasKorba/slipstream` to `zodl-inc/slipstream` @ `michal/anchor-retention-interval-144`, absorb any API drift in the FFI, rebuild the local XCFramework slices, verify, and PR into `michal/slipstream-support`.

**Architecture:** Single-crate consumer (`rust/src/lib.rs`) of a git dependency declared in the root `Cargo.toml`; local FFI mode active (`LocalPackages/libzcashlc.xcframework`, three arm64 slices). Scoped lock re-resolve, compiler-driven drift discovery, incremental slice rebuilds.

**Tech Stack:** Rust (cargo, git-fetch-with-cli), SwiftPM, `gh` CLI, `Scripts/rebuild-local-ffi.sh`.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-07-24-slipstream-zodl-repoint-design.md` (approved 2026-07-24).
- Work branch: `michal/slipstream-zodl-repoint`; PR base: `michal/slipstream-support`; remote `origin` = `zcash/zcash-swift-wallet-sdk`. No Linear ticket.
- Commit titles: `[#1806] <title>`; every commit must build. ONE atomic commit carries Cargo.toml + Cargo.lock + compile-required rust changes.
- Commit trailer (exact, last lines of every commit body):
  `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`
  `Claude-Session: https://claude.ai/code/session_01YCPiyz1m7VhxKyX1v37C4M`
- Private repo auth — export before ANY cargo command that may fetch:
  `export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0="credential.https://github.com.helper" GIT_CONFIG_VALUE_0='!gh auth git-credential'`
  Never write auth into machine git config; never change Cargo.toml URL to SSH.
- Target pin: branch `michal/anchor-retention-interval-144`, expected head `58aeac2b533747493dd077fc7b6b8fef9e5cd10f` (verify at resolve time; a moved head is acceptable — record the resolved rev).
- Swift style (if Swift is touched): no `;` statement separators; no `.init(...)` shorthand — spell the type name; prefer `OSAllocatedUnfairLock` over `NSLock` (import os); no `print`/`NSLog` (injected `Logger` only); string interpolation, not `+`; TODOs as `TODO: [#issue]`.
- Rust: run `cargo fmt` before committing any `rust/` source change.
- No `--gpu`, no `--universal` slice builds (mirror existing arm64-only slices).
- Existing OfflineTests are the regression net. This change adds no new behavior by design; new tests only if the Swift surface changes (then also MIGRATING.md + CHANGELOG.md entries).

---

### Task 1: Repoint Cargo.toml

**Files:**
- Modify: `Cargo.toml:112-120` (doc comment + dependency line)

**Interfaces:**
- Produces: `slipstream-core` declared from `https://github.com/zodl-inc/slipstream.git` branch `michal/anchor-retention-interval-144` — consumed by Task 2's re-resolve.

- [ ] **Step 1: Replace the comment + dependency line**

Replace lines 112–120 (`# Slipstream engine — …` through the `slipstream-core = …` line) with:

```toml
# Slipstream engine — the alternative sync engine the SlipstreamSynchronizer
# drives. Consumed as a remote crate from zodl-inc/slipstream, the engine's
# home since the personal-fork era (the old PR #6 adaptations are merged
# there). Tracks the anchor-retention branch (upstream-aligned 144-block
# anchor retention, typed multi-account sync_once, EngineConfig-owned
# endpoint probe-then-commit, report.rs presentation split); Cargo.lock pins
# the exact commit. Return to a release tag once one is cut with these
# aboard. The engine rides the same librustzcash rev as this package, so the
# graph stays a single family instance.
slipstream-core = { git = "https://github.com/zodl-inc/slipstream.git", branch = "michal/anchor-retention-interval-144" }
```

(The `tokio` line below and the `gpu = ["slipstream-core/gpu"]` feature stay untouched.)

- [ ] **Step 2: Verify the edit**

Run: `grep -n "slipstream" Cargo.toml`
Expected: the dependency line shows the zodl-inc URL + new branch; the `gpu` feature line unchanged; no other slipstream mentions changed. Do NOT commit yet (atomic commit lands in Task 4).

### Task 2: Re-resolve Cargo.lock (scoped)

**Files:**
- Modify: `Cargo.lock` (only `slipstream-core` / `slipstream-gpuhash` entries + any deps the new branch genuinely adds/drops)

**Interfaces:**
- Consumes: Task 1's Cargo.toml.
- Produces: lock entries `source = "git+https://github.com/zodl-inc/slipstream.git?branch=michal%2Fanchor-retention-interval-144#<rev>"` for BOTH slipstream packages at the SAME `<rev>` — consumed by every later build task.

- [ ] **Step 1: Re-resolve with scoped update**

```bash
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0="credential.https://github.com.helper" GIT_CONFIG_VALUE_0='!gh auth git-credential'
cargo update -p slipstream-core -p slipstream-gpuhash
```

Expected: output shows both packages moving to the zodl-inc source (rev `58aeac2b…` expected). Fallback if the package spec errors: `cargo update -p slipstream-core`, then re-run with `-p slipstream-gpuhash` only if it remains on the old source.

- [ ] **Step 2: Review the lock diff**

Run: `git diff --stat Cargo.lock && git diff Cargo.lock | grep -E "^[+-](name|source|version)" | sort | uniq -c | sort -rn | head -30`
Expected — ALL must hold:
1. Both slipstream entries on the zodl-inc source at one identical rev.
2. No version/source change to any shared crate (`orchard`, `zcash_*`, `sapling-crypto`, `shardtree`, `incrementalmerkletree` stay put).
3. No crate appears twice with two versions/sources that previously had one (single-family check): `for c in orchard zcash_client_backend zcash_primitives sapling-crypto; do echo "$c: $(grep -c "^name = \"$c\"" Cargo.lock)"; done` — counts identical to before the update (baseline: 1 each).
4. Added/removed transitive packages are acceptable ONLY if they correspond to dependency edits in the new slipstream commits; list them in the PR body.

If 2 or 3 fails: STOP the task and return the diff for main-session analysis (possible family fork — spec-level risk).

### Task 3: Probe compile (drift discovery)

**Files:** none modified.

**Interfaces:**
- Consumes: Task 2's lock.
- Produces: a drift report — either "clean" or the full `cargo check` error list — consumed by Task 4.

- [ ] **Step 1: cargo check**

```bash
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0="credential.https://github.com.helper" GIT_CONFIG_VALUE_0='!gh auth git-credential'
cargo check 2>&1 | tail -60
```

Expected: either `Finished` (no drift → skip Task 4 Steps 2–4, go straight to Task 4 Step 5 commit) or compile errors naming `slipstream_core` items.

- [ ] **Step 2: If errors — locate the new sources for signature reference**

Run: `ls ~/.cargo/git/checkouts/ | grep -i slipstream` and find the checkout dir matching rev `58aeac2b*`; the engine sources are under `<checkout>/core/src/`. Read `config.rs`, `session.rs`, `ffi_handle.rs`, `report.rs` there for exact current signatures. Record each compile error + the new signature it collides with.

### Task 4: Adapt FFI drift + atomic commit

**Files:**
- Modify: `rust/src/lib.rs` (sole `slipstream_core` consumer; hotspots: `EngineConfig::new` call ~line 5015, `SessionConfig { engine, account, tor }` ~5111, `SessionReporter` ~5112, `spawn_supervised`/`run_session` ~5122-5124, `anchor::*` ~5361-5406, `seed_progress_from_wallet` ~4808)
- Modify only if the C header must change: `rust/src/ffi.rs`, regenerated header, `Sources/ZcashLightClientKit/Rust/*`, `MIGRATING.md`, `CHANGELOG.md`

**Interfaces:**
- Consumes: Task 3's drift report + new-branch sources in the cargo checkout.
- Produces: `cargo check` green; the atomic repoint commit.

**Adaptation rules (binding):**
1. Preserve every exported `zcashlc_*` C symbol's name and shape; absorb drift inside the Rust layer.
2. Typed/multi-account `sync_once`: keep current single-account semantics — wrap the existing FFI account argument in the new typed form; do NOT surface multi-account upward unless compilation is impossible otherwise.
3. `EngineConfig` probe-then-commit fields: populate from existing FFI args where a 1:1 exists; otherwise use the engine's own defaults (`EngineConfig::new`'s defaults or `Default` impl — read the new `config.rs`).
4. `report.rs` split: if `SessionReporter`/event types moved modules or gained fields, re-import from the new path and map existing progress/event plumbing 1:1; drop no events.
5. Only if a C-header change is unavoidable: update the Swift bridge minimally, add MIGRATING.md + CHANGELOG.md entries, follow the Swift style constraints (Global Constraints).

- [ ] **Step 1: Apply minimal fixes per rule set**
- [ ] **Step 2: Re-run `cargo check` until green** (same env export; expected `Finished`)
- [ ] **Step 3: `cargo fmt`** (only if Rust sources changed), then `git diff --stat` to confirm the change surface matches the drift report
- [ ] **Step 4: If Swift changed: `swiftlint lint --quiet` clean on touched files; MIGRATING/CHANGELOG entries written**
- [ ] **Step 5: Atomic commit**

```bash
git add Cargo.toml Cargo.lock rust/src/ MIGRATING.md CHANGELOG.md Sources/ 2>/dev/null || git add Cargo.toml Cargo.lock
git commit -m "[#1806] Track slipstream-core via zodl-inc/slipstream

The slipstream engine repo moved to zodl-inc/slipstream; its
michal/anchor-retention-interval-144 branch carries the merged PR #6
adaptations plus upstream-aligned anchor retention. Repoint the git
dependency and re-pin the lock (slipstream-core + slipstream-gpuhash at
the same rev). <one line on drift adaptations, or 'No FFI drift — the
crate API our layer consumes is unchanged.'>

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01YCPiyz1m7VhxKyX1v37C4M"
```

Expected: exactly one commit; `git status --short` clean afterwards (LocalPackages is untracked by design).

### Task 5: Rebuild the three local FFI slices

**Files:** none tracked (writes `LocalPackages/libzcashlc.xcframework`, `target/`).

**Interfaces:**
- Consumes: Task 4's committed tree.
- Produces: three rebuilt arm64 slices — consumed by Task 6.

- [ ] **Step 1: ios-sim** — `./Scripts/rebuild-local-ffi.sh ios-sim` → expect exit 0, slice repackaged message
- [ ] **Step 2: ios-device** — `./Scripts/rebuild-local-ffi.sh ios-device` → expect exit 0
- [ ] **Step 3: macos** — `./Scripts/rebuild-local-ffi.sh macos` → expect exit 0
(Sequential — shared cargo target dir. Export the auth env first in each shell; fetches should hit the cargo git cache, auth is belt-and-braces.)

### Task 6: Swift verification

**Files:** none modified.

**Interfaces:**
- Consumes: Task 5's macos slice (swift build/test link it via LocalPackages).
- Produces: green `swift build` + OfflineTests — gate for Task 7.

- [ ] **Step 1: `swift build`** → expected `Build complete!`
- [ ] **Step 2: `swift test --filter OfflineTests`** → expected all tests pass (`Test Suite … passed`); CI parity per `.github/workflows/swift.yml`
Failures: fix if caused by this change (fold fix into a follow-up `[#1806]` commit, buildable); pre-existing unrelated failures are report material, verify by checking out `michal/slipstream-support` behavior only if ambiguity exists.

### Task 7: Push + PR

**Interfaces:**
- Consumes: all-green Tasks 4–6.
- Produces: open PR `michal/slipstream-support` ← `michal/slipstream-zodl-repoint`.

- [ ] **Step 1: Push** — `git push -u origin michal/slipstream-zodl-repoint` → expect new branch on origin
- [ ] **Step 2: PR**

```bash
gh pr create --base michal/slipstream-support --head michal/slipstream-zodl-repoint \
  --title "[#1806] Track slipstream-core via zodl-inc/slipstream" \
  --body "<summary of repoint; divergence analysis (11 ahead / 4 behind, squash-merged PR #6 content); resolved rev; lock-diff summary incl. any added/removed transitive deps; drift adaptations or 'none'; verification results (cargo check, 3 slices, swift build, OfflineTests); note: FFI release workflow needs credentials for the private repo. Refs #1806.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

https://claude.ai/code/session_01YCPiyz1m7VhxKyX1v37C4M>"
```

Expected: PR URL printed; no self-merge.

---

## Execution model

Subagent-driven (user's standing preference): Tasks 1–3 and 5–6 are mechanical → delegate to a cheaper model (Sonnet) with this plan verbatim; Task 4 severity-dependent — trivial signature updates stay with the Sonnet worker under the binding rules, semantic restructuring escalates to the main session. Task 2's STOP condition and any Swift-surface change always escalate. Task 7 runs from the main session after diff review.

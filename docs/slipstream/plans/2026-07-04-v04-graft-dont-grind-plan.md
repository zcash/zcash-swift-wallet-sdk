# v0.4 "Graft, don't grind" Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate most Sinsemilla combine work during restores by grafting server-provided
subtree roots for note-free shards (Plan A), cheapen the combines that remain via a
batch-affine builder (Plan B), with instruments (census, CLI bench, bench-ios) built first.

**Architecture:** Per-pool shard accumulator inside `sparse_put_blocks` buffers commitments
(restart-safe `slipstream_graft_buffer` table), eager-flushes to today's build path the
moment a shard shows an owned note, and at shard close either grafts the already-ingested
server root (root-only `Node::Leaf`-at-level-16 shard — the shape pruning already produces)
or builds. Semantic oracle (anchors/witnesses/balances/tx-set + darkside spend) gates the
not-byte-identical graft path; the byte oracle keeps gating everything else.

**Tech Stack:** Rust (slipstream-core, edition 2024), rusqlite, shardtree/incrementalmerkletree
public APIs, pasta_curves field math (Plan B), serde JSON (bench), XcodeGen + SwiftUI
(bench-ios, `ios-probe` pattern from the spike repo).

**Spec:** `docs/slipstream/plans/2026-07-04-v04-graft-dont-grind-design.md` (approved 2026-07-04).

## Global Constraints

- Branch: `slipstream-v04`. Never commit to `slipstream` or `main`. Pushing to origin is allowed (publish rule lifted 2026-06-17).
- Commit format: `[#1755] slipstream: <imperative title>` + trailer `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.
- Containment: engine work under `slipstream/` + `docs/slipstream/`; FFI additions only in `rust/src/lib.rs`; NO old-SDK-path changes.
- Rust style: no `unwrap`/`expect` outside tests; `tracing` only in slipstream-core (CLI may print); TDD; integration tests in `slipstream/core/tests/`; darkside tests `#[ignore]` + feature `darkside`.
- Always-green after every task: `cargo test -p slipstream-core` (currently 195/0), `cargo test -p slipstream-cli` (29/0), `cargo clippy -p slipstream-core -p slipstream-cli -- -D warnings`. When `rust/src/lib.rs` or Swift is touched: `swift build` + `swift test --filter OfflineTests` (515/0) after `./Scripts/rebuild-local-ffi.sh macos`.
- Bump `slipstream_core::engine::ENGINE_BUILD` in every perf-relevant engine commit (CONVENTIONS.md freshness rule) — Tasks 5, 7, 8, 12, 13.
- All new levers land default-OFF until Task 11 flips per the spec §2 policy (≥+10% device A/B + green gates → default-on).
- Device runs are Lukas's ([needs-user]); tasks that need them say so and are structured so autonomous work never blocks on them.

---

### Task 1: Shard census + bench JSON summary (P0 instruments, engine half)

**Files:**
- Create: `slipstream/core/src/census.rs`
- Modify: `slipstream/core/src/persist.rs` (census feed inside `sparse_put_blocks`, ~:543 transaction closure; census carried on `SparseTreeState`, struct at :302)
- Modify: `slipstream/core/src/config.rs` (add `bench_json_path: Option<std::path::PathBuf>`, default `None`, next to `gpu_subtree` at :85)
- Modify: `slipstream/core/src/session.rs` (emit summary at pass end where the `sync stage split` log line is produced)
- Test: census unit tests in `census.rs`; JSON emission test in `slipstream/core/tests/` next to existing integration tests

**Interfaces:**
- Produces: `pub struct ShardCensus { touched: BTreeSet<u64>, noted: BTreeSet<u64>, pub commitments: u64 }` with `pub fn feed(&mut self, start_position: u64, count: u64, note_positions: impl Iterator<Item = u64>)`, `pub fn shards(&self) -> u64`, `pub fn noted_shards(&self) -> u64`, `pub fn graftable_fraction(&self) -> f64` (= `1 − (noted + 1 tip) / touched`, clamped ≥ 0). Shard index = `position >> 16` (both pools use shard height 16).
- Produces: `pub struct BenchSummary` (serde `Serialize`): `engine_build: &'static str`, `total_s: f64`, per-stage ms mirrors of the existing stage-split fields, per-pool `{ shards, noted_shards, commitments, graftable_fraction }`. Written to `config.bench_json_path` when set.

- [ ] **Step 1: Write failing census unit tests** in `census.rs` `#[cfg(test)]`:

```rust
#[test]
fn census_counts_shards_and_notes() {
    let mut c = ShardCensus::default();
    // 3 commitments at the end of shard 0, 2 into shard 1; one note in shard 1.
    c.feed(65534, 5, [65537u64].into_iter());
    assert_eq!(c.shards(), 2);
    assert_eq!(c.noted_shards(), 1);
    assert_eq!(c.commitments, 5);
    // shard 1 is noted, shard 0 clean; tip discount makes graftable 0 of 2 here.
    assert!(c.graftable_fraction() <= 0.5);
}

#[test]
fn census_graftable_fraction_typical() {
    let mut c = ShardCensus::default();
    c.feed(0, 65536 * 10, [5u64].into_iter()); // 10 full shards, note in shard 0
    // 10 touched, 1 noted, 1 tip → 8/10 graftable
    assert!((c.graftable_fraction() - 0.8).abs() < 1e-9);
}
```

- [ ] **Step 2: Run to verify failure** — `cargo test -p slipstream-core census` → FAIL (module missing).
- [ ] **Step 3: Implement `census.rs`** (module header per conventions; `BTreeSet` walk in `feed`; `BenchSummary` struct + `pub fn write_json(&self, path: &Path) -> std::io::Result<()>` using `serde_json::to_writer_pretty`). Add `pub mod census;` to `lib.rs`. `serde`/`serde_json` are already workspace deps (verify in `slipstream/core/Cargo.toml`; add with `features=["derive"]` if absent).
- [ ] **Step 4: Wire the feed** — in `sparse_put_blocks`, after `note_positions` for the chunk is final, call `census.feed(start_position_u64, commitments_len, note_positions.iter().map(...))` per pool (two `ShardCensus` fields on `SparseTreeState`, skipped when `None`). Emit per-pool census fields on the existing `sparse {pool} tree split` info lines (persist.rs:946); assemble + write `BenchSummary` in `session.rs` at the stage-split site when `bench_json_path` is set.
- [ ] **Step 5: Integration assertion** — extend the cheapest existing persist integration test to set `bench_json_path` to a tempfile and assert the JSON parses and `commitments > 0`.
- [ ] **Step 6: Green + commit** — always-green commands; commit `[#1755] slipstream: v0.4 P0 — shard census + bench JSON summary`.

### Task 2: CLI `bench` subcommand (P0, Mac instrument)

**Files:**
- Modify: `slipstream/cli/src/main.rs` (new variant in the subcommand enum next to `Sync` at :36 / `Watch` at :95)
- Test: `slipstream/cli/tests/` (arg-parse + JSON-shape test; network-dependent run stays manual)

**Interfaces:**
- Consumes: `EngineConfig.bench_json_path`, `ShardCensus`/`BenchSummary` from Task 1.
- Produces: `slipstream bench --seed-file <path> --birthday <h> [--data-dir <tmp>] [--graft on|off] [--gpu on|off] [--json <out.json>] [--keep]` — fresh temp wallet dir per run (deleted unless `--keep`), drives the same restore path `Sync` uses, prints a human table + writes JSON.

- [ ] **Step 1: Failing arg-parse test** (clap try_parse of the full flag set asserting parsed values).
- [ ] **Step 2: Run** — `cargo test -p slipstream-cli bench` → FAIL.
- [ ] **Step 3: Implement** — reuse `Sync`'s setup verbatim (temp `tempfile::tempdir()` for `--data-dir` default; map `--graft`/`--gpu` onto `EngineConfig` fields — `graft_subtree` lands in Task 5, so until then the flag parses but is rejected with "graft not built yet" to keep the CLI honest); on completion read back the JSON (engine wrote it) and render the table.
- [ ] **Step 4: Green + commit** — `[#1755] slipstream: v0.4 P0 — slipstream-cli bench subcommand`.

### Task 3: bench-ios mini-app (P0, iPhone instrument)

**Files:**
- Create: `slipstream/bench-ios/probe/` (staticlib crate, workspace member — mirrors the spike's `crates/ios-probe`: `extern "C" fn slipstream_bench_run(seed_hex: *const c_char, birthday: u32, graft: bool, out_json: *mut c_char, cap: usize) -> i32` wrapping a tokio runtime + the same restore path the CLI uses, writing `BenchSummary` JSON into the buffer)
- Create: `slipstream/bench-ios/app/project.yml` (XcodeGen; links the probe xcframework + Metal-free), `slipstream/bench-ios/app/Sources/BenchApp.swift` (one screen: seed field prefilled from pasteboard, birthday field, Graft toggle, Run button, stage table from the JSON), `slipstream/bench-ios/setup.sh` (build xcframework for `aarch64-apple-ios` + `xcodegen generate` — copy the spike repo's `crates/ios-probe/setup.sh` shape)
- Test: `cargo test -p slipstream-bench-probe` (JSON-into-buffer unit test with a mocked summary; no device dependency), plus `xcodebuild -scheme BenchApp -destination 'generic/platform=iOS Simulator' build` must SUCCEED

**Interfaces:**
- Consumes: Task 1's `BenchSummary` (probe sets `bench_json_path` to an app-container temp file, reads it back, returns it).
- Produces: the on-device measuring instrument for P3/§2 gates. Zodl is explicitly NOT modified.

- [ ] **Step 1:** Failing probe unit test (buffer round-trip of a canned `BenchSummary`).
- [ ] **Step 2:** `cargo test -p slipstream-bench-probe` → FAIL (crate missing) → scaffold crate, add workspace member, implement, PASS.
- [ ] **Step 3:** App scaffold (project.yml + SwiftUI view + setup.sh), `xcodebuild` simulator build → SUCCEEDED. Generated `.xcodeproj`/`.xcframework` gitignored (spike pattern).
- [ ] **Step 4:** Green + commit `[#1755] slipstream: v0.4 P0 — bench-ios probe + app (ios-probe pattern)`.
- [ ] **Step 5 [needs-user]:** Lukas: `./slipstream/bench-ios/setup.sh`, set signing team, run on iPhone 16 Pro. Not blocking later tasks.

### Task 4: Baselines (P0 close-out — Mac now, iPhone when convenient)

**Files:**
- Modify: `docs/slipstream/plans/2026-07-04-v04-graft-dont-grind-design.md` (append `## Addendum — baselines`), `docs/slipstream/STATE.md`

- [ ] **Step 1:** Mac baseline ×3 (reference 269–273k restore): `cargo run -p slipstream-cli --release -- bench --seed-file <ref> --birthday <ref> --json /tmp/base{1,2,3}.json` — record median total + stage split + census (the census's `graftable_fraction` is the recorded PREDICTION for Plan A's ceiling; also run once against Lukas's real wallet for the bet denominator when he provides the seed on his machine — [needs-user]).
- [ ] **Step 2:** Append the baseline table + prediction to the spec addendum; STATE.md NEXT ACTION update; commit `[#1755] slipstream: v0.4 P0 — baselines + graft ceiling prediction`.

### Task 5: `graft_subtree` config + buffer table (P1 foundations)

**Files:**
- Create: `slipstream/core/src/graft.rs` (buffer schema + encode/decode + CRUD; module header explains the restart-safety contract)
- Modify: `slipstream/core/src/config.rs` (`pub graft_subtree: bool` default `false` + validation mirroring gpu's at :158: requires `sparse_persistence`), `rust/src/lib.rs` (`ZCASH_GRAFT_SUBTREE` env read, verbatim pattern of :4623-4632, NOT feature-gated — graft has no heavy deps), `slipstream/core/src/engine.rs` (log `graft_subtree` on the `engine pass starting` line)
- Test: `graft.rs` unit tests (rusqlite in-memory)

**Interfaces:**
- Produces (all take `&rusqlite::Transaction`, generic `H: HashSer`):
  - `pub fn ensure_buffer_table(tx) -> Result<(), SqliteClientError>` (lazy `CREATE TABLE IF NOT EXISTS slipstream_graft_buffer (pool INTEGER NOT NULL, shard_index INTEGER NOT NULL, position INTEGER NOT NULL, commitment BLOB NOT NULL, retention_kind INTEGER NOT NULL, checkpoint_height INTEGER, marking INTEGER, PRIMARY KEY (pool, shard_index, position)) WITHOUT ROWID` — called only on graft-ON paths so OFF stays byte-identical)
  - `pub fn append_rows<H>(tx, pool: ShieldedProtocol, rows: &[(u64 /*position*/, H, Retention<BlockHeight>)])`
  - `pub fn load_shard<H>(tx, pool, shard_index: u64) -> Result<Vec<(u64, H, Retention<BlockHeight>)>>` (ORDER BY position)
  - `pub fn delete_shard(tx, pool, shard_index) -> Result<()>`; `pub fn delete_above_height_positions(tx, pool, min_position: u64)` (rewind support, Task 9)
  - Retention encoding: kind 0=Ephemeral, 1=Marked, 2=Checkpoint (+`checkpoint_height`, `marking` 0=None/1=Marked/2=Reference), 3=Reference — with a `roundtrip` proptest-style loop over all variants.
- Produces: `EngineConfig.graft_subtree`, env `ZCASH_GRAFT_SUBTREE`.

- [ ] **Step 1:** Failing tests: table lazily created; append→load ordered round-trip incl. every Retention variant; delete_shard; load of missing shard = empty.
- [ ] **Step 2:** FAIL → implement → PASS.
- [ ] **Step 3:** Config + env + pass-starting log line; `cargo check` both `--features gpu` and default (the validation touchpoint sits next to gpu's).
- [ ] **Step 4:** Green (+ swift build + OfflineTests — `rust/src/lib.rs` touched, macOS slice rebuild) + ENGINE_BUILD bump + commit `[#1755] slipstream: v0.4 P1 — graft config + restart-safe buffer table`.

### Task 6: ShardAccumulator (P1 core logic, pure)

**Files:**
- Create: `slipstream/core/src/graft_accumulator.rs`
- Test: exhaustive unit tests in-module

**Interfaces:**
- Produces:

```rust
pub(crate) enum FeedAction<H> {
    /// Stream these straight to today's build path (passthrough shard or eager flush).
    Build(Vec<(u64, H, Retention<BlockHeight>)>),
    /// Shard closed note-free: ask the sink to graft `shard_index`; on `NoRoot`, the
    /// accumulator hands back the same rows as `Build`.
    CloseCleanShard { shard_index: u64, rows: Vec<(u64, H, Retention<BlockHeight>)> },
    /// Rows to persist into the buffer table this chunk (still-open, note-free shard).
    Buffer(Vec<(u64, H, Retention<BlockHeight>)>),
}
pub(crate) struct ShardAccumulator<H> { /* shard_height=16, open shard state, has_note, mode */ }
impl<H: Clone> ShardAccumulator<H> {
    /// `resume_rows`: buffered rows for the open shard loaded at seed time (restart / cross-range stitch).
    pub fn seed(start_position: u64, resume_rows: Vec<(u64, H, Retention<BlockHeight>)>) -> Self;
    /// Positions MUST be contiguous from the last feed (tree_size order) — debug_assert'd.
    pub fn feed(&mut self, start_position: u64, items: Vec<(H, Retention<BlockHeight>)>, note_positions: &[u64]) -> Vec<FeedAction<H>>;
    /// Range end / pass end: flush whatever is open as Build (tip shard never grafts).
    pub fn finish(&mut self) -> Option<FeedAction<H>>;
}
```

Rules (each is a test): (1) note position inside an open buffering shard ⇒ the whole
buffered prefix + the current items come back as ONE `Build` and the shard flips
passthrough for the rest of its span; (2) shard boundary crossing with zero notes ⇒
`CloseCleanShard` with the complete row set; (3) passthrough shards emit `Build`
immediately every feed; (4) a shard is passthrough at seed time iff `resume_rows` is
empty AND the store already holds internals for it (the caller decides via a
`store_has_internals: bool` seed arg — derivable state, nothing new persisted); (5)
`finish` never grafts; (6) mid-shard range end leaves rows in `Buffer` so the adjacent
range's `seed(resume_rows)` completes the shard later, whichever order ranges run.

- [ ] **Step 1:** Write the six rule tests + a straddle test (feed spanning 3 shards: clean, noted, open) — expect FAIL.
- [ ] **Step 2:** Implement (pure, no DB) → PASS → clippy.
- [ ] **Step 3:** Commit `[#1755] slipstream: v0.4 P1 — shard accumulator (eager-flush + close-verdict state machine)`.

### Task 7: Wire accumulator into `sparse_put_blocks`, verdict = always-build (P1 gate)

**Files:**
- Modify: `slipstream/core/src/persist.rs` (route per-pool commitments through the accumulator when `graft_subtree`; `SparseTreeState` gains two `Option<ShardAccumulator<…>>` + seed at :520-525 using Task 5's `load_shard`; `FeedAction::Build`/`CloseCleanShard(rows)` feed the EXISTING `build_orchard_subtrees`/`build_subtrees` + insert path unchanged; `Buffer` rows go to `append_rows` inside the same `transactionally` closure)
- Test: `slipstream/core/tests/` — graft-ON (verdict-build) vs graft-OFF full-range fixture

**Interfaces:**
- Consumes: Tasks 5+6 exactly as declared.
- Produces: the graft plumbing with zero behavior change — the P1 spec gate.

- [ ] **Step 1 (read-and-confirm, ~15 min):** re-read `sparse_put_blocks` :543-760 and confirm (a) `ensure_checkpoints` (:747-752) consumes stream-derived `cp_pos` maps only — no reads of open-shard internals; (b) frontier maintenance doesn't require the open shard's fragments mid-range. If either fails, the accumulator's `Buffer` action for the AFFECTED chunk degrades to `Build` (flag stays honest) and the finding is recorded in the spec addendum before proceeding.
- [ ] **Step 2:** Failing integration test: same darkside-free fixture the byte-oracle tests use, run once graft-OFF and once graft-ON(verdict-build); assert identical shard-store content (existing tree-dump helper) + empty buffer table at end + identical `sparse … tree split` totals fields present.
- [ ] **Step 3:** Implement the routing → PASS. Flag-OFF paths must not call `ensure_buffer_table` (assert: no `slipstream_graft_buffer` table after an OFF run).
- [ ] **Step 4:** Green + ENGINE_BUILD bump + commit `[#1755] slipstream: v0.4 P1 — accumulator wired, verdict=build (byte-equal gate)`.

### Task 8: Real graft — root lookup + root-only install + fallbacks (P2 heart)

**Files:**
- Modify: `slipstream/core/src/graft.rs` (root lookup + install), `slipstream/core/src/persist.rs` (verdict consult)
- Test: unit (install shape) + integration (mixed graft/build range)

**Interfaces:**
- Produces: `pub fn server_root<H: HashSer>(tx, pool, shard_index) -> Result<Option<H>>` — reads the shard root recorded by pass-start `put_subtree_roots` (engine.rs:180-181). **Step 1 confirms the physical source** (upstream `sapling_tree_shards`/`orchard_tree_shards` rows carry `root_hash` for completed shards; if the ingested roots live only as store shards, read via the store's `get_shard(shard_addr)` root annotation instead — whichever upstream actually persists).
- Produces: `pub fn graft_shard<H>(store, shard_index: u64, root: H) -> Result<()>` — installs `LocatedPrunableTree` at `Address::from_parts(Level::from(16), shard_index)` with `root: Tree::leaf((root, RetentionFlags::EPHEMERAL))` — the exact shape shardtree pruning produces for a collapsed subtree, so every reader already handles it. MUST tolerate replacing seeded/partial fragments for that shard (put_shard semantics — confirmed in Step 1).

- [ ] **Step 1 (read-and-confirm):** locate where `put_subtree_roots` persists roots + `put_shard` replace semantics in the vendored upstream; write the two findings as doc comments on the new functions.
- [ ] **Step 2:** Failing unit test: graft into an in-memory store → `get_shard` returns root-annotated leaf; root value round-trips; grafting over an existing partial shard replaces it.
- [ ] **Step 3:** Failing integration test: fixture wallet whose notes live in shard 1 of 3 completed shards + server roots pre-ingested → run graft-ON → assert shard 0,2 are root-only leaves, shard 1 fully built, buffer table empty, `census.graftable_fraction` matches, anchors equal to a graft-OFF run.
- [ ] **Step 4:** Implement verdict consult in persist.rs: `CloseCleanShard` → `server_root()?` — `Some(root)` ⇒ `graft_shard` + `delete_shard(buffer)`; `None` ⇒ build rows (fallback), `debug!` count. Log per-pass `grafted=N built=M fallback=K` on the tree-split lines.
- [ ] **Step 5:** Green + ENGINE_BUILD bump + commit `[#1755] slipstream: v0.4 P2 — graft note-free shards from server roots (fallback=build)`.

### Task 9: Lifecycle edges — rewind, import-requeue, restart (P2 safety)

**Files:**
- Modify: `slipstream/core/src/graft.rs` (rewind hook), the engine's `truncate_to_height` path (locate via `grep -rn "truncate_to_height" slipstream/core/src/`)
- Test: `slipstream/core/tests/` three scenarios

- [ ] **Step 1:** Failing tests: (a) restart-mid-shard — feed half a shard, drop state, re-seed from buffer, complete → grafts, content equal to uninterrupted run; (b) rewind — `truncate_to_height` below a grafted shard: buffer rows with positions above the truncation point deleted in the same transaction, subsequent rescan rebuilds/regrafts to equal content; (c) import-requeue — graft a shard, then rescan its range with a new account owning a note there → shard comes back BUILT with the witness present (put_shard replace path).
- [ ] **Step 2:** Implement the rewind buffer-trim + whatever (a)/(c) reveal (expected: nothing — they exercise Task 6/8 machinery) → PASS.
- [ ] **Step 3:** Green + commit `[#1755] slipstream: v0.4 P2 — graft lifecycle edges (restart/rewind/import) proven`.

### Task 10: Sampling verify + semantic oracle (P2 gate)

**Files:**
- Modify: `slipstream/core/src/graft.rs` + `config.rs` (`graft_verify_sample: u32`, default 16 — 1-in-16 graftable shards is ~6% of the old combine cost during soak; 0 = off)
- Create: `slipstream/core/tests/graft_semantic_oracle.rs` (feature `darkside`, `#[ignore]`, serial — join the existing 14-test darkside suite; reuse its harness helpers, located via `ls slipstream/core/tests/`)

**Interfaces:**
- Produces: sampling mode — for 1-in-N `CloseCleanShard`s, ALSO build, compare root to server root; mismatch ⇒ `error!` + install the BUILT shard (fallback wins) + `Progress` counter `graft_mismatches` (snapshot-visible so hosts can alert).
- Produces: the semantic-equality harness: run restore graft-OFF → snapshot `{anchor at each checkpoint depth, witness bytes for every owned note at a fixed checkpoint, balances (all pools/buckets), txids+nullifiers set}`; wipe; graft-ON → equal snapshots; then build + darkside-mine a spend using a grafted-tree witness → accepted.

- [ ] **Step 1:** Failing unit test for the sampling counter + mismatch-fallback (inject a wrong server root fixture).
- [ ] **Step 2:** Implement sampling → PASS.
- [ ] **Step 3:** Write the semantic oracle test (assert-by-assert per the Produces list — the spend proof is the last assert) → run against darkside → PASS. `cargo test -p slipstream-core --features darkside -- --ignored graft_semantic` documented in CONVENTIONS.md's darkside section.
- [ ] **Step 4:** Green + commit `[#1755] slipstream: v0.4 P2 — sampling verify + semantic oracle (darkside spend proof)`.

### Task 11: Device A/B + defaults decision (P3 — [needs-user] gates)

**Files:**
- Modify: `config.rs` (defaults flip iff gates pass), spec addendum, `STATE.md`, `docs/slipstream/SCENARIO_MATRIX.md` (S2/S21/S28/S15 re-run rows with graft on)

- [ ] **Step 1:** Mac A/B ×3 via `slipstream bench --graft off|on` (release build). Record: totals, combine ms delta, census prediction vs realized. **This is the aggregate + GPU-leg bet checkpoint** (`memory/v04-beer-bet.md` — GPU leg reads the banked `ZCASH_GPU_SUBTREE` on/off on the same build for the record).
- [ ] **Step 2 [needs-user]:** iPhone A/B via bench-ios; matrix spot rows on the Mac app build (restore, import-during-restore, rewind) with graft on.
- [ ] **Step 3:** Apply the §2 policy (≥+10% + green ⇒ `graft_subtree` default `true` on that device class — the default lives in `EngineConfig::default` + hosts override; record the decision), update docs, commit `[#1755] slipstream: v0.4 P3 — device A/B numbers + graft default decision`.

### Task 12: Level-synchronous fragment builder (P4 step 1 — byte-equal construction)

**Files:**
- Create: `slipstream/core/src/level_builder.rs`
- Modify: `slipstream/core/src/persist.rs` (`build_subtrees` routes to it behind `batch_combine: bool` config, default false — same routing shape as `build_orchard_subtrees` :987)
- Test: in-module equivalence proptest-style loop

**Interfaces:**
- Produces: `pub(crate) fn build_fragment<H: Hashable + Clone>(start: Position, items: Vec<(H, Retention<BlockHeight>)>) -> Option<(LocatedPrunableTree<H>, BTreeMap<BlockHeight, Position>)>` — bottom-up level-by-level build over `Tree::{parent,leaf,empty}` (construction pattern proven by `gpu_subtree.rs`'s rebuild), producing output EQUAL to `LocatedTree::from_iter` for the same input, including retention/annotation placement and recorded checkpoints. The level loop is the seam Task 13 batches: it sees ALL combines of a level as one slice.
- Config: `batch_combine` + env `ZCASH_BATCH_COMBINE` (same plumbing as Task 5's flag; one commit, both pools).

- [ ] **Step 1:** Failing equivalence test: 1,000 randomized fragments (sizes 1..=1024, random retentions incl. checkpoint marks, random start offsets) → `build_fragment` output `==` `from_iter` output (tree eq + checkpoints eq).
- [ ] **Step 2:** Implement → PASS (this is subtle — Nil-padding for non-power-of-two tails must match from_iter's; iterate until the 1,000-case loop is clean).
- [ ] **Step 3:** Route + integration byte-oracle rerun (the Task 7 fixture with `batch_combine on`, graft off) → identical stores.
- [ ] **Step 4:** Green + ENGINE_BUILD bump + commit `[#1755] slipstream: v0.4 P4 — level-synchronous builder (byte-equal to from_iter)`.

### Task 13: Batch-affine Sinsemilla combine (P4 step 2 — the SIMD leg)

**Files:**
- Create: `slipstream/core/src/batch_sinsemilla.rs`
- Modify: `slipstream/core/src/level_builder.rs` (per-level slice → batched combine when the level's width ≥ 32; scalar `H::combine` below that)
- Test: KAT vs `MerkleHashOrchard::combine` + the byte oracle

**Interfaces:**
- Produces: `pub(crate) fn combine_batch(level: Level, pairs: &[(MerkleHashOrchard, MerkleHashOrchard)]) -> Vec<MerkleHashOrchard>` — all N Sinsemilla chains advanced in lockstep (52 chunks × 2 incomplete additions), each step's N affine-addition λ-denominators inverted with ONE Montgomery batch inversion:

```rust
/// Batch-invert xs in place: product-tree forward pass, one field inversion, backward pass.
/// Standard Montgomery trick — 1 inversion + 3(N−1) muls for N inversions.
fn batch_invert(xs: &mut [Fp]) { /* prefix products; single .invert(); unwind */ }
```

  Affine incomplete add per element per step: `λ=(y2−y1)·inv(x2−x1); x3=λ²−x1−x2; y3=λ(x1−x3)−y1` (~3 muls + shared inversion vs ~11 projective muls). Generator table: reuse the resolved constants recipe from the spike's `SINSEMILLA-SPEC.md` + `sinsemilla-consts` (derive Q + S[0..1024] on first use, `OnceLock`). Message encoding (level‖left‖right → 52×10-bit chunks) copied from the spike's S4, KAT'd. Orchard-only (sapling combine is Pedersen — out of scope, scalar path remains).
- Fallback: any pair hitting the incomplete-addition degenerate case (x1==x2 — probability ~2⁻²⁵⁴, but MUST be handled) computes that ONE element via `MerkleHashOrchard::combine` scalar.

- [ ] **Step 1:** Failing KATs: `batch_invert` vs per-element `.invert()` (10k random); `combine_batch` vs `combine` (100k random `(level, left, right)`, byte equality) — expect FAIL.
- [ ] **Step 2:** Implement (spike-recipe port; no GPU, pure CPU) → PASS.
- [ ] **Step 3:** Wire into `level_builder` (width ≥ 32) → Task 12's equivalence loop + Task 7's byte-oracle fixture rerun with `batch_combine on` → identical.
- [ ] **Step 4:** Microbench (`#[ignore]` bench-style test printing ns/combine scalar vs batched at widths 32/256/4096) — record in spec addendum. If batched isn't ≥1.3× at width 4096, STOP and record honestly before proceeding to Step 5.
- [ ] **Step 5:** NEON pass, timeboxed to one session: `std::arch::aarch64` on the Fp mul inner loop ONLY if Step 4's profile shows the mul dominating; keep only on measured win (CONVENTIONS honesty rule). Skipping it is a valid outcome — record either way.
- [ ] **Step 6:** Green + ENGINE_BUILD bump + commit `[#1755] slipstream: v0.4 P4 — batch-affine Sinsemilla combine (+NEON iff it earned it)`. Mac A/B on the reference restore (`--graft on --batch-combine on|off`) → **SIMD-leg bet number recorded** in `memory/v04-beer-bet.md` + spec addendum.

### Task 14: Plan C go/no-go + release close-out (P5+P6)

**Files:**
- Modify: `STATE.md`, `CHANGELOG.md`, `docs/slipstream/HANDOFF.md` (§known-open-items), spec addendum; crate versions `slipstream/{core,cli}/Cargo.toml` → 0.4.0

- [ ] **Step 1:** Post-A/B profile review: if scan/decrypt now > 55% of wall on either device, write the Plan C mini-spec (`plans/` file, resurrecting parked L4a) and STOP for approval; else record "C deferred to v0.5" with the numbers.
- [ ] **Step 2:** Docs sweep (CHANGELOG user-visible entries; HANDOFF known-items updated; SCENARIO_MATRIX verdict flips dated; STATE NEXT ACTION → release marks).
- [ ] **Step 3:** crates 0.4.0 + full `./Scripts/init-local-ffi.sh` (all arches — iOS slices go stale during this work) + always-green suite + engine-repo re-extract + tag `v0.4.0` (the established release recipe from v0.3.5/0.3.6).
- [ ] **Step 4 [needs-user]:** Zodl flag-on victory-lap restore (unmeasured, agreed scope C) + **beer adjudication**: fill the settled legs in `memory/v04-beer-bet.md`.
- [ ] **Step 5:** Commit `[#1755] slipstream: v0.4 — release close-out (crates 0.4.0, docs, adjudication)`.

---

## Self-review (done at write time)

- **Spec coverage:** §3 P0→Tasks 1-4; §4 Plan A→Tasks 5-10; §2 gates+§8 P3→Task 11; §5 Plan B→Tasks 12-13; §6 testing→Tasks 1/7/9/10/12/13 gates; §7 fallbacks→Tasks 7 Step 1, 8 Step 4, 10, 13 Step 4 STOP rules; §8 P5/P6→Task 14. No uncovered spec section.
- **Honest unknowns are explicit read-and-confirm steps** (Task 7 Step 1, Task 8 Step 1), each with a defined degrade path — not placeholders.
- **Type consistency:** `FeedAction`/`ShardAccumulator` (Task 6) consumed by name in Task 7; `server_root`/`graft_shard` (Task 8) consumed in Tasks 9-10; `build_fragment` (Task 12) consumed in Task 13; config names `graft_subtree`/`graft_verify_sample`/`batch_combine` consistent across 5/7/10/12.

# v0.4 — "Graft, don't grind" (work-reduction release) — design spec

**Status: DRAFT — awaiting Lukas's review (2026-07-04).**
Branch: `slipstream-v04` (off `slipstream`, keeps PR #1800's head clean).
Companion game: `memory/v04-beer-bet.md` — every lever ships behind an on/off switch so
each bet leg is independently measurable.

## 1 · Why work reduction (the recorded history)

Three levers have been tried; the tree remembers all of them (STATE.md):

| Lever | Result | Where |
|---|---|---|
| GPU offload (Phase B0) | PARKED — ~1.1× iPhone/A14, **−25% M4**, A10 pathological | `gpu_subtree.rs`, feature `gpu`, `ZCASH_GPU_SUBTREE`, commit `9ac8fed8` |
| Persist-pipelining depth>1 | FALSIFIED — M4 ~26% *slower*; scan+persist share cores | `persist.rs` lane, `persist_depth` default 1 |
| Depth-1 write-behind, lane pool, sparse store | SHIPPED — these are v0.2's wins | persist.rs T6.8/T6.9 |

Strategic verdict on record: *modern devices are compute-bound; concurrency levers
conserve work and add contention. The only remaining lever is WORK REDUCTION — fewer
combines, or faster per-unit compute.*

The prize, measured (A10, 270k restore): **Σ orchard combine = 232.9 s = 46% of total
work** (+ ~30 s sapling combine). Park-time totals: M4 32.3 s, iPhone 16 Pro 89.7 s,
A14 125.5 s.

**The observation v0.4 is built on:** the engine already downloads every completed
subtree root from the server (`engine.rs:180` `get_subtree_roots` →
`put_subtree_roots`) — and then locally re-computes those same roots by hashing every
commitment of every scanned block, including for the (vast majority of) subtrees that
contain none of the wallet's notes. The wallet needs subtree *internals* only where it
owns notes (witnesses) and at the tip (frontier). Everywhere else the root alone
suffices — and the root is already on disk.

## 2 · Goals, non-goals, acceptance

**Goals**
1. **Plan A — graft:** skip building note-free completed shards; graft the
   server-provided root instead. Target: eliminate ~80–95% of combine work on typical
   restores.
2. **Plan B — batch-affine combine (+NEON):** make the combines that remain (note-bearing
   shards, tip shard) ~2× cheaper on CPU, byte-identical. This is the "SIMD" bet leg.
3. **Plan C — batched trial-decrypt:** post-A the profile shifts scan-ward; resurrect the
   parked L4a lever *if* Phase 0/post-A numbers justify it.
4. **Instruments:** `slipstream-cli bench` (machine-readable stage split + shard census),
   `bench-ios` mini-app (same harness on device), semantic oracle in the test suite.

**Non-goals**
- GPU work of any kind (stays banked, default-off; Plan A shrinks its target to nothing).
- Protocol/lightwalletd changes (v0.5 territory).
- Old-SDK sync path changes (frozen, as always).

**Reference workloads (pinned):** the standard ~269–273k-block test restore (cross-run
comparability with the park-time baselines) for engineering A/Bs; Lukas's real mainnet
wallet on his M4 Mac for the bet legs (`memory/v04-beer-bet.md` metric).

**Acceptance gates (per device: Lukas's M4 Mac + iPhone 16 Pro)**
- Semantic oracle green (§6) + full darkside suite green + scenario-matrix spot rows
  (restore, import-during-restore, rewind) green with graft on.
- Graft on/off A/B on the reference restore: wall-clock improvement ≥ +10% → lever ships
  default-ON on that device class; else default-OFF (still selectable).
- Aspirational headline (not a gate): iPhone 16 Pro reference restore **< 60 s**.
- No regression of the B4-16 lifecycle guarantees (stop/drain/revival untouched).

## 3 · Phase 0 — instruments first (settles the bets' denominators)

1. **Stage-split JSON:** the ground-truth logs already exist (`sync stage split`,
   `sparse orchard tree split` — persist.rs:946). Add a structured end-of-pass summary
   (serde JSON behind a `--bench` CLI flag / `bench` FFI query): totals, per-stage ms,
   per-pool build/insert/ensure, shard census.
2. **Shard census:** during a pass, count per pool: shards touched, shards note-bearing,
   commitments seen. `graftable_fraction = 1 − (note_shards + tip)/shards` — this
   *predicts* Plan A's ceiling per wallet before Plan A exists.
3. **CLI:** `slipstream-cli bench --seed-file … --birthday … [--graft on|off] [--json …]`
   — scripted restore into a temp wallet dir, prints the summary. (The CLI already does
   restores; this is a reporting + toggles wrapper.)
4. **bench-ios:** `slipstream/bench-ios/` — XcodeGen mini-app (the spike's `ios-probe`
   pattern) linking the local FFI slice; one screen: seed/birthday (prefilled from a
   file), Run, stage-split table, total. Toggles map to the same env/config switches.
   Zodl is NOT the instrument (one flag-on sanity run at the end, unmeasured — agreed
   scope option C).
5. **Baselines:** RC1-equivalent build, Mac + iPhone, reference wallet, ×3 each, recorded
   in this doc's addendum + STATE.md.

## 4 · Plan A — graft (the headline lever)

### Mechanism

Today (`persist.rs:489 sparse_put_blocks`, per scan-chunk): collect commitments →
`build_subtrees` (`:963`, rayon over 1024-position fragments → `LocatedTree::from_iter`,
**combines happen here**) → insert fragments into the sparse shard store (more combines
in stitching/`ensure`) → flush.

v0.4 (graft on): per pool, route commitments through a **shard accumulator** instead of
building immediately:

- **Accumulate:** append each chunk's commitments (+ retention marks + note positions —
  already collected at `:547`) to the open shard's buffer. Persist the buffer rows in the
  same per-chunk transaction (`graft_buffer(pool, shard_index, position, commitment,
  retention)`) so a kill/restart loses nothing — append-only, no hashing, ~2 MB/shard cap.
- **Eager flush on first owned note (witness-timing invariant):** the moment a buffered
  shard receives an owned-note position, flush its buffer through the build path *in that
  same `put_blocks` call* and mark the shard passthrough (subsequent chunks build
  fragments immediately, exactly today's path). A freshly-found note's witness data
  therefore exists at *identical* timing to v0.3.6 — buffering only ever delays internals
  no query can reference.
- **Verdict at shard close** (the accumulator sees position cross a 2^16 boundary; only
  reachable by shards still note-free):
  - shard contains **no owned note positions** AND the server root for that shard index
    is present (already ingested at pass start) → **graft**: install a root-only shard
    (`Tree::parent` with the known root annotation — the exact shape upstream stores for
    below-birthday shards today), drop the buffer. **Zero combines.**
  - shard **has owned notes** (or no server root yet — tip lag, server gap) → **build**:
    feed the buffered commitments through the existing `build_subtrees` + insert path,
    then drop the buffer. Byte-identical to today for this shard.
- **Tip shard / range end:** the final open shard never grafts — it builds from the
  buffer (the frontier and future appends need its internals). Checkpoint bookkeeping is
  unaffected: checkpoint positions are computed from the commitment stream, not from the
  built trees (persist.rs:1012).

### Switches (bet leg + safety)

Mirror the GPU pattern exactly (`SparseTreeState.gpu_subtree`, `persist.rs:526` +
`build_orchard_subtrees(gpu, …)` routing at `:987`): a `graft_subtree` flag on
`SparseTreeState`, `EngineConfig` field, `ZCASH_GRAFT_SUBTREE` env override, logged on
the `engine pass starting` line (the ENGINE_BUILD freshness discipline applies).
Default per §2 gates.

### Trust model (unchanged in kind, wider in coverage)

Grafted roots come from the same `GetSubtreeRoots` response the engine already writes
into the tree for below-birthday shards — v0.4 widens *usage* of an existing trust
surface, it does not create one. Failure mode of a wrong server root: invalid witness →
spend rejected by consensus — denial-of-service, never fund loss (same as today).
Mitigations:
1. **Sampling verify mode** (`graft_verify_sample=N`, default small &>0 during soak):
   for 1-in-N graftable shards, build *and* graft, compare roots, `error!` + fall back to
   built on mismatch. Catches server bugs at ~1/N of the old cost.
2. **Frontier cross-check** at pass end (tip frontier vs server treestate) — server
   self-consistency, cheap, already fetched.
3. Any graft anomaly (missing root, mismatch, buffer gap) → build path. Graft is an
   optimization of *representation*; every fallback is "do what v0.3 does".

### Edge cases (each becomes a test)

- **Restart mid-shard:** buffer rows are transactional with block metadata → reopen
  re-seeds the accumulator from `graft_buffer`. No rescan, no gap.
- **Rewind/reorg (`truncate_to_height`):** truncation below a grafted shard is upstream's
  existing shard-truncate (root-only shards truncate trivially); buffer rows above the
  truncation height are deleted with the same transaction (H1 serialization already stops
  the engine around rewinds).
- **`importAccount` mid-restore (B4-16 family):** the new account force-requeues
  [birthday, tip]; rescan of a range REPLACES grafted shards via the normal build path
  when the new account owns notes there (`put_shard` overwrites). Scenario-matrix rows
  S21/S28 re-run with graft on.
- **Spam-era shards:** dense shards are the biggest wins (most commitments, none ours).
- **Sapling + Orchard:** the accumulator is generic over pool (same as `build_subtrees`);
  both pools graft.
- **Multi-account wallets (Keystone):** note positions are per-wallet (all accounts) —
  a shard with ANY account's note builds. Correct by construction.

### Explicitly NOT byte-identical

data.db differs by design (root-only shards where full shards used to be). The oracle
therefore moves from byte-equality to semantic equality (§6). The shape produced —
root-annotated shard without internals — is a shape every reader already handles
(below-birthday shards look exactly like this today).

## 5 · Plan B — batch-affine combine + NEON (the "SIMD" leg)

The combines that remain after A (note-bearing shards, tip shard, A10-class devices where
they matter most) get cheaper, not fewer:

- Replace `LocatedTree::from_iter`'s one-at-a-time hashing with **our own level-synchronous
  fragment builder** (bottom-up; the public `Tree::{parent,leaf}` construction is proven by
  `gpu_subtree.rs`'s rebuild). At each level all combines are independent → run the
  Sinsemilla point-addition chains for the whole level in lockstep and use **Montgomery
  batch inversion** to share the one field inversion across N affine additions per step
  (~11 field muls/add projective → ~3 muls + 1/N inversion affine). Expected ~1.5–2.5× on
  combine compute, exact-same outputs (affine vs projective is representation, the math is
  identical) → **byte-identical, the strong oracle keeps applying**.
- NEON (`std::arch::aarch64`) on the hot field mul afterwards, measured, kept only if it
  beats scalar (Apple's MUL/UMULH pipeline is strong — honesty required).
- Switch: `batch_combine` flag, same plumbing pattern; default-on if byte-identical suite
  + ≥ +5% device A/B pass (it's zero-risk correctness-wise, so the bar is lower).

## 6 · Testing suite extension

1. **Semantic oracle (new, the A gate):** same seed, same block corpus (darkside for
   determinism + one mainnet soak), restore twice (graft off / on), assert equal:
   anchors at every checkpoint, witness path for every owned note, balances (all pools +
   spendability buckets), tx set + nullifiers, and a darkside **spend** built from a
   grafted-tree witness that validates. Lives next to the existing byte-identical oracle
   (`oracle.rs`); reused by CI where darkside runs today.
2. **Byte-identical oracle (existing):** still gates Plan B and every graft-OFF path.
3. **Unit tests:** accumulator (close/verdict/straddle/restart-from-buffer), graft
   fallback matrix (no-root, mismatch, rewind, import-requeue), census math.
4. **Bench artifacts:** Phase 0 JSON schemas asserted in CLI tests so the suite notices
   if the bench output drifts.

## 7 · Fallbacks & risk register

| Risk | Containment |
|---|---|
| Semantic oracle can't be made airtight in time | Ship graft default-OFF (switch stays); B still ships value; v0.4 becomes B+instruments |
| Grafted-witness spend fails in the field | Sampling-verify + fallback-to-build; flag off = exact v0.3.6 behavior (one-switch story, same as slipstream itself) |
| B's batch-affine misses byte-equality | It cannot ship — byte oracle is a hard gate; scalar path remains |
| Server root coverage gaps at tip | Expected + handled (build path); census quantifies how often |
| A's win smaller than predicted (census says wallet is note-dense) | The bets get interesting; B/C carry more weight; numbers are honest either way |

## 8 · Phasing (weekend-shaped, each gate = a commit)

- **P0** — instruments: census + stage-split JSON + CLI bench + baselines (Mac, iPhone).
  *Gate: baseline table in this doc; bets' denominators locked.*
- **P1** — accumulator + buffer table + build-at-close (graft **logic off** — verdict
  always "build"). *Gate: flag-OFF runs byte-identical (buffer table is created lazily on
  first flag-ON pass, so OFF paths write nothing new); flag-ON-verdict-build runs
  semantically identical + tree content byte-equal.*
- **P2** — graft verdict + root-only install + fallbacks + sampling verify.
  *Gate: semantic oracle green + darkside suite green.*
- **P3** — device A/B (CLI on Mac, bench-ios on iPhone), defaults decision, scenario-
  matrix spot rows. *Gate: §2 acceptance; GPU-leg + aggregate-leg bet numbers recorded.*
- **P4** — Plan B batch-affine (+NEON if it earns it). *Gate: byte oracle + A/B; SIMD-leg
  number recorded.*
- **P5** — Plan C go/no-go from the post-A profile; if go, its own mini-spec.
- **P6** — docs (STATE.md, CHANGELOG, HANDOFF §known-items), crates → 0.4.0, engine repo
  re-extract, Zodl flag-on sanity run (the victory lap), beer adjudication.

## Addendum — baselines (P0, 2026-07-04)

**Reference window (pinned):** test UFVK (canonical darkside seed, `stress_sparse_join.rs`
provenance), **birthday 2,740,000**, mainnet via `https://zec.rocks:443` → ~660,727 blocks
to the 2026-07-04 tip (~3,400,727). Bigger than the park-era 273k window — that's fine;
consistency of THIS window is what A/Bs compare against. M4 Max, release CLI,
`slipstream bench`, engine v0.3.6 (`ENGINE_BUILD 2026-06-17.torretry`).

| run | total_s | fetch_s | scan_s | enhance_s | persist_wait_s | persist_overlap_s |
|---|---|---|---|---|---|---|
| 1 | 39.0 | 14.4 | 38.4 | 0.16 | 18.5 | 10.6 |
| 2 | 35.4 | 11.7 | 34.9 | 0.14 | 18.5 | 10.4 |
| **3 (median total)** | **36.6** | 11.5 | 36.2 | 0.07 | 19.5 | 10.1 |

**Census (identical all 3 runs):** sapling 5 shards / 0 noted / **80% graftable**;
orchard **19 shards / 0 noted / 94.7% graftable** (foreign wallet — noted=0 as
predicted; Lukas's real wallet will show noted>0 and sets the bet denominator).

**Reading:** bound=scan every run, and `scan-compute ≈ scan_s − persist_wait ≈ 20 s` vs
`persist_busy ≈ 28.2 s` — **persist (combine-heavy) > scan-compute**, the park-time
thesis reproduced by the new instrument on this window. Plan A attacks the 28 s directly:
at ~95% orchard / 80% sapling shard-build elimination, predicted total ≈ low-20s ⇒
**~+55–75% on this reference wallet** (its graftable fraction is near-ideal; note-dense
wallets land lower — that's what the per-wallet census is for).

**Lukas's wallet baselines (2026-07-04, graft OFF, 5 runs — THE BET DENOMINATOR):**
totals 28.6 / 43.4 (network outlier) / 28.0 / 29.0 / 28.9 → **median 28.9 s**;
persist_wait 14.4–16.7 s; census stable: orchard 14 shards / 5 noted / **57% graftable**,
sapling 3 / 0 / 67%. Bet lines: Lukas +26% ⇒ v0.4 ≤ 22.9 s; Claude +42% ⇒ ≤ 20.4 s.

**First fair A/B (reference wallet, back-to-back, 2026-07-04, post-Task-8):**
graft ON total 30.4 s (fetch 15.9, persist_wait **8.2**) vs OFF 36.9 s (fetch 12.6,
persist_wait 18.2) ⇒ **+21% raw with ON drawing the worse fetch; ~+35% fetch-normalized**.
First-live-fire lesson banked: autocommit buffer appends = fsync/row (persist_wait 96.5 s!)
→ one txn per append (`24804da6`) → 8.2 s, BELOW the graft-off floor.

**[needs-user] rows to append:** Lukas's graft-ON runs (after Task 10 blesses
correctness); iPhone 16 Pro via bench-ios (Task 11/P3).

# Slipstream `put_blocks` — Upstream De-duplication & Ironwood Readiness

> **Status:** Analysis only — **no code moved.** Findings + a sequenced plan.
> **Audience:** the core `librustzcash` engineer (the DRY ask) **and** Slipstream maintainers.
> **Date:** 2026-06-19. **Trigger:** core-engineer call (transcript summary below).
> **Hard constraint:** **Ironwood lands in ~4 weeks regardless of Slipstream.**

---

## 0. TL;DR

The engineer's "~1000 lines of duplicated `put_blocks`" is **real, and Slipstream already documents it as a
deliberate, line-by-line mirror** of `zcash_client_backend ll/wallet.rs:235–550` (`persist.rs:483`). The mirror
exists for **one reason**: to swap the note-commitment-tree target from SQLite-backed to in-memory — which *is*
the speed win — but upstream exposes `put_blocks` as a **monolith calling four private helpers**, so the entire
surrounding body had to be copied to reach the one section that differs.

**The accounting (precise, line-cited in §3):**

| Bucket | ~Lines | Disposition |
|---|---|---|
| **Pure mirror** of *private* upstream helpers (`build_subtrees`, `ensure_checkpoints`, `Nullifiers::update_with`) | ~80 | **Delete** once upstream makes them `pub`. Zero behavior change. |
| **The prologue** (validation + per-block row loop + gap addresses + prune + `notify_scan_complete`) — already runs through the `LowLevelWalletWrite` *interface*, byte-for-byte upstream | ~230 | **Delete** once upstream extracts it as a `pub` function over `&mut impl LowLevelWalletWrite`. |
| **Near-mirror** (`stream_checkpoint_positions`) — a *pre-build* variant of private `checkpoint_positions` | ~15 | Collapses once upstream exposes `checkpoint_positions` (or accepts the stream form). |
| **The genuine 12× speed core** (in-memory `SparseShardStore` + seed/flush, `rayon::join` per-pool parallelism, T6.3b checkpoint-downgrade, T6.9 write-behind lane, GPU subtree) | ~250 | **Stays in Slipstream.** This *is* the divergence-from-upstream that makes it fast. |

**Net:** ~80 % of the duplication can be removed by **upstream changes that cost the standard path nothing**
(making 4 private items `pub` + extracting one prologue function + one bulk tree-flush trait method). The ~250-line
speed core is the irreducible value and stays. **Priority #1 (keep 12×) and Priority #2 (satisfy the maintainability
ask) do not conflict here** — the deduplication is a *behavior-preserving* lift of code that is already byte-identical
to upstream, gated by Slipstream's existing byte-identical-`data.db` oracle.

**Ironwood is the reason to do this now, not later.** Upstream's `put_blocks` is `#[cfg(feature = "orchard")]`-gated
section-by-section: Orchard was *added as cfg arms beside Sapling*, and **Ironwood is another such arm at every
Orchard site** (the engineer's exact words: *"just another section… like a duplicate of Orchard"*). The duplicated
code **is** the code Ironwood touches. So:

- **If we do nothing:** Ironwood gets implemented **twice** — once upstream, once in Slipstream's hand-copied mirror —
  and the two must be kept bit-identical by hand. Double the work, permanent divergence surface, on a 4-week clock.
- **If we dedup first:** upstream adds Ironwood **once** (it must anyway); Slipstream's thin override adds **only an
  in-memory Ironwood tree** mirroring how it already wraps Orchard (~40–60 lines of speed-core, not a 1000-line
  re-mirror), and the **GPU Sinsemilla subtree extends to Ironwood for free** (Ironwood is Sinsemilla/Pallas like
  Orchard).

---

## 1. The ask & the constraints

**From the call (core `librustzcash` engineer):**
1. *"Can we eliminate that duplication of `put_blocks`? What other duplication is there? Where are the differences?
   Are there reusable functions we can factor out in `zcash_client_backend`?"*
2. *"I'd really prefer it if Slipstream did not deal with `zcash_client_sqlite` directly — if it used the
   `zcash_client_backend` interfaces."*
3. *"That duplication is ~1000 lines of very similar logic, and it's stuff that's probably going to change with
   Ironwood. Even in the age of AI, I believe in don't-repeat-yourself."*
4. **Ironwood:** *"essentially identical to the handling of Orchard. In scanning it will just be another section that
   populates separate tables, populates a separate note-commitment tree… just like Orchard and Sapling are separated."*
   No Ironwood branch available yet (Nala Group's are under review with Dave).

**Constraints (from Lukas):**
- **Priority #1: keep the 12× speed.** Non-negotiable. We may shuffle code upstream↔Slipstream freely **as long as it
  does not slow Slipstream down.**
- **Priority #2: satisfy the maintainability ask** (dedup, use interfaces). Below #1, never traded for it.
- **Hard deadline: ~4 weeks** for the new pool to land. Ironwood happens whether Slipstream ships or not — so it's
  *either* Slipstream adopting Ironwood *or* the old SDK adopting it.
- **Ironwood = Orchard copy + 3 extra features** for security / ZEC-value-validity (response to the patched Orchard
  exploit; "fear in the air"). See §7 for where those features land relative to the scan/persist path.
- **This cycle: doc only. Move no code yet.**

---

## 2. How Slipstream persists today (ground truth)

**The interception is *already* interface-based.** Slipstream does **not** fork the scan engine — `scan_cached_blocks`
is upstream's, untouched (`persist.rs:3`). It intercepts persistence by implementing upstream's **`WalletWrite`
interface** with two facades:

- **`SparseFacade`** (`persist.rs:1145`) — implements `WalletRead`+`WalletWrite`, **delegates every method verbatim to
  the real `WalletDb`** *except* `put_blocks`, which it routes to `sparse_put_blocks` (`persist.rs:1202`, "THE
  INTERCEPT"). The whole substitution is one trait method.
- **`WriteBehindFacade`** (`persist.rs:1305`) — for the depth-1 write-behind pipeline: virtualizes the **exact 4-method
  read surface** `scan_cached_blocks` needs (`get_unified_full_viewing_keys`, `block_metadata(tip)`,
  `get_{sapling,orchard}_nullifiers(Unspent)`) so chunk N+1 can scan while chunk N's commit is deferred; `put_blocks`
  **stashes** instead of committing (`persist.rs:1443`). Every read/write *outside* that surface fails loudly
  (`unvirtualized`, `persist.rs:1261`) — so upstream read-surface drift can never become a silent stale read.

So **the wiring is clean and already goes through the interface.** The duplication is entirely *inside the body of
`put_blocks`*, which upstream offers only as a monolith.

**Anatomy of upstream `put_blocks` (`ll/wallet.rs:235`, `pub fn put_blocks<DbT, SE, TE>(wallet_db, …)` where
`DbT: PutBlocksDbT` bundles the row interface `LowLevelWalletWrite` *and* the tree interface
`WalletCommitmentTrees`):**

| # | Section | upstream lines | Goes through… | Slipstream |
|---|---|---|---|---|
| 1 | Validation (sequential-blocks) | 245–267 | pure logic | **copied** |
| 2 | Per-block loop: block meta, tx meta, mark spent, put shielded outputs, nullifier tracking, note positions | 278–417 | **`LowLevelWalletWrite`** ✅ | **copied** (identical calls) |
| 3 | Gap addresses for involved accounts | 440–457 | `LowLevelWalletWrite` | **copied** |
| 4 | Prune tracked nullifiers | 459–462 | `LowLevelWalletWrite` | **copied** |
| 5 | `build_subtrees` (rayon `par_chunks`) | 466–481 → priv `1146` | pure logic | **copied** |
| 6 | **`update_tree`** (insert_frontier + insert_tree loop + ensure_checkpoints) | 484–537 → priv `1228` | **`WalletCommitmentTrees`** | **THE substitution** ⬅ |
| 7 | `notify_scan_complete` | 539–547 | `LowLevelWalletWrite` | **copied** |

**Sections 1–5 and 7 are identical** and already pass through the `LowLevelWalletWrite` interface. **Only section 6
differs** — and `update_tree` is *already generic over the shard store* `S: ShardStore` (`ll/wallet.rs:1228`). Upstream
calls it with the SQLite-backed store; Slipstream wants it called with an in-memory `SparseShardStore`. That single
parameterization is the entire ~1000-line reason-to-copy.

---

## 3. The duplication, line-by-line (where which code lives)

Legend — **M** = pure mirror of a *private* upstream item (delete on `pub`); **P** = prologue/epilogue mirror (delete on
extract); **≈** = near-mirror with deliberate variance; **CORE** = genuine 12× speed core (stays).

| Slipstream `persist.rs` | What it is | Upstream origin | Cat. | Disposition |
|---|---|---|---|---|
| `build_subtrees` `963` | par_chunks subtree build | `ll/wallet.rs:1146` *(private)* | **M** | Upstream `pub` → **delete copy** |
| `ensure_checkpoints` `1106` | cross-pool checkpoint fill | `ll/wallet.rs:1184` *(private)* | **M** | Upstream `pub` → **delete copy** |
| `apply_nullifier_delta` `1252` | running unspent-NF view (write-behind) | `scanning.rs:435` `Nullifiers::update_with` *(private)* | **M** | Upstream `pub` → reuse |
| `sparse_put_blocks` §1 validation `496–516` | sequential-blocks guard | `put_blocks:245–267` | **P** | Upstream prologue fn → **delete** |
| `sparse_put_blocks` §2 row loop `550–688` | meta/tx/spend/output/NF rows | `put_blocks:278–417` | **P** | Upstream prologue fn (over `LowLevelWalletWrite`) → **delete** |
| `sparse_put_blocks` §3–4 gap+prune `691–703` | gap addrs, prune NFs | `put_blocks:440–462` | **P** | Upstream prologue fn → **delete** |
| `notify_scan_complete` call `923` | scan-complete epilogue | `put_blocks:539–547` | **P** | Stays in override (one call) |
| `stream_checkpoint_positions` `1019` | cp positions from the stream **pre-build** | `checkpoint_positions:1173` *(private, post-build)* | **≈** | Upstream `pub` + note equivalence → collapse |
| `SparseShardStore` / `SparseStoreError` `88–283` | **in-memory `ShardStore`** | — (Slipstream-original) | **CORE** | **Stays** |
| `SaplingSparseTree`/`OrchardSparseTree` `287` | in-mem `ShardTree` types | — | **CORE** | **Stays** |
| `seed_sapling`/`seed_orchard` `310/342` | preload DB tree → memory (per range) | — | **CORE** | **Stays** *(Ironwood: +`seed_ironwood`)* |
| `flush_sapling`/`flush_orchard` `375/432` | flush dirty tree delta once per chunk | — | **CORE** | **Stays**, but flush via a **bulk trait method** (see §4.3) *(Ironwood: +`flush_ironwood`)* |
| `rayon::join` per-pool block `758–906` | **parallel** sap/orch tree pipelines | — (upstream does this serially) | **CORE** | **Stays** *(Ironwood: 3rd arm)* |
| `doomed_checkpoint_cutoff` `1045` + `downgrade_doomed_checkpoints` `1087` | **T6.3b** skip ~9,900 cp create/destroy per 10k chunk | — (upstream creates+prunes them all) | **CORE** | **Stays** — *also an upstream-candidate, see §6* |
| `build_orchard_subtrees` `991` | **GPU** Sinsemilla subtree routing | — | **CORE** | **Stays** *(Ironwood: GPU-eligible, free)* |
| `SparseFacade` `1145` | `WalletWrite` intercept (the clean wiring) | — | **CORE** | **Stays** |
| `WriteBehindFacade` `1305` + `PendingPersist` `1240` | **T6.9** depth-1 write-behind read virtualization | — | **CORE** | **Stays** *(Ironwood: +`ironwood_nfs`)* |
| `PersistLane` / `lane_pool_policy` `1523+` | dedicated 2-thread persist lane (saturation-aware) | — | **CORE** | **Stays** |

**Reading of the table:** the **M + P + ≈** rows are the engineer's ~1000 lines. They are duplicated **not because
Slipstream wanted to diverge** but because upstream's seam is private/monolithic. The **CORE** rows are the genuine,
intentional divergence — the thing that turns persistence from the bottleneck into not-the-bottleneck.

---

## 4. What moves upstream (and why it costs the standard path nothing)

Three surgical, **backward-compatible** changes in `zcash_client_backend` — all in the engineer's own crate, consumable
by Slipstream via a **git-rev bump** (the dep is already a git pin: `~/.cargo/git/checkouts/librustzcash-…`, rev
`1600f94` — no crates.io release needed):

### 4.1 Make four private helpers `pub` (or `pub(crate)`→`pub`)
`build_subtrees`, `checkpoint_positions`, `ensure_checkpoints`, **`update_tree`**. The standard SQLite path keeps
calling them exactly as today — zero behavior change. Slipstream **deletes its hand-copies** and calls upstream's.
`update_tree` is the keystone: it is *already* `update_tree<S: ShardStore, …>(protocol, frontier, tree: &mut
ShardTree<S,…>, subtrees, missing_checkpoints)` — pool-agnostic and store-agnostic. Slipstream calls it with
`S = SparseShardStore`; upstream calls it with `S = SqliteShardStore`. Nothing else changes.

### 4.2 Extract the row-writing prologue as a `pub` function
Factor `put_blocks` §1–4 (validation + per-block row loop + gap addresses + prune) into e.g.
`pub fn put_blocks_rows(db: &mut impl LowLevelWalletWrite, …) -> RowsOutcome` returning the
`(sapling_commitments, orchard_commitments, note_positions, last_scanned_height, tx_refs)` it accumulates. Upstream's
own `put_blocks` becomes `put_blocks_rows(...)` → `build_subtrees(...)` → `update_tree(...)` → `notify_scan_complete`.
Slipstream's `sparse_put_blocks` becomes the **same three calls with its own in-memory `update_tree`** in the middle —
the ~230-line copy evaporates. This is the single biggest dedup and it's a pure refactor of upstream (oracle/tested by
upstream's existing suite).

### 4.3 Add a bulk tree-flush method to `WalletCommitmentTrees` (kills the direct `zcash_client_sqlite` coupling)
Today the **only** place Slipstream touches `zcash_client_sqlite` concretely is the flush: `flush_sapling`/`flush_orchard`
take `&mut zcash_client_sqlite::WalletDb<SqlTransaction…>` and reach into `with_*_tree_mut` + `store_mut().put_shard()`
(`persist.rs:376,433`). Add a trait method — e.g. `WalletCommitmentTrees::put_sapling_shards(&mut self, shards,
checkpoints_remove, checkpoints_add)` (and `_orchard`, `_ironwood`) — that performs a bulk dirty-delta flush. Slipstream
flushes **through the interface**; the `zcash_client_sqlite` import in `persist.rs` drops to just the error type. This
is the literal answer to *"I'd prefer Slipstream didn't deal with `zcash_client_sqlite` directly."*

**After 4.1–4.3:** `sparse_put_blocks` collapses from ~470 lines to **~150** — exactly the speed core: seed in-memory
trees → `put_blocks_rows` (upstream) → parallel per-pool { downgrade · `build_subtrees` (upstream / GPU) · in-memory
`update_tree` (upstream) } → bulk-flush (interface) → `notify_scan_complete` (upstream). Every deleted line is a line
that no longer has to track Ironwood by hand.

---

## 5. What MUST stay in Slipstream (the 12× core) — and why it can't move

Each of these is a deliberate divergence from upstream's behavior; moving it upstream would either change the standard
path's semantics or slow it down — so it stays:

- **In-memory `SparseShardStore` + `seed_*`/`flush_*`.** The whole point: upstream writes the shardtree to SQLite as it
  goes; Slipstream accumulates it in memory per scan range and flushes the **dirty delta once per chunk**. This is the
  largest single persistence win and is intrinsically a *different storage strategy*, not a shared helper.
- **`rayon::join` per-pool parallelism.** Upstream builds/updates Sapling then Orchard **serially**; Slipstream runs the
  two pool pipelines **concurrently**. (Upstream could adopt this — see §6 — but Slipstream can't depend on that landing.)
- **T6.3b checkpoint-downgrade.** Produces a **byte-identical `data.db`** while skipping ~9,900 checkpoint
  create/destroy cycles per 10k-block chunk that upstream's create-all-then-`prune_excess_checkpoints` performs. Pure
  Slipstream optimization (upstream-candidate, §6).
- **T6.9 write-behind lane** (`WriteBehindFacade` + `PendingPersist` + `PersistLane` + saturation-aware
  `lane_pool_policy`). Depth-1 pipeline overlapping chunk N's commit with chunk N+1's decrypt, on a dedicated 2-thread
  pool tuned against decrypt-pool contention. This is orchestration that lives *above* `put_blocks` and is Slipstream's
  alone.
- **GPU Sinsemilla subtree** (`build_orchard_subtrees` → `build_subtrees_gpu`). Off-CPU note-commitment combining.

> **Headroom note:** the engine is currently **scan-bound** (device: 276k-block restore in 77s, `enhance_s=0.53`,
> persistence *off* the critical path). The speed core's job is to *keep persist off the critical path*. So the dedup's
> real risk is narrow and measurable: **don't let persist regress back onto the critical path.** Slipstream's existing
> byte-identical-`data.db` oracle + per-pass timing logs (`rows_ms`/`tree_ms`/`flush_ms`/per-pool splits, already
> emitted at `persist.rs:936–956`) catch both correctness and timing regressions per step.

---

## 6. Upstream taking advantage of Slipstream's ideas (so everyone profits)

The user's framing — *"upstream taking advantage of Slipstream ideas if possible so all can profit"* — has three
concrete candidates. None are required for the dedup; all are gifts the standard ecosystem (zallet, zingo, mobile SDKs)
could take:

1. **The checkpoint-downgrade (T6.3b).** Upstream's `update_tree` creates every per-block checkpoint and lets
   `prune_excess_checkpoints` delete all but the newest ~100 — thousands of create/destroy cycles per chunk.
   Slipstream's `doomed_checkpoint_cutoff` computes the surviving window up front and never creates the doomed ones,
   **byte-identical result.** Upstreamed (even as an opt-in), it speeds the standard SQLite path too.
2. **In-memory accumulate + bulk-flush as an upstream `put_blocks` mode.** The §4.2 prologue extraction is the
   prerequisite; once the seam exists, upstream could offer a "batched tree" variant that any consumer opts into.
3. **GPU Sinsemilla subtree build** for Orchard **and** Ironwood (both Pallas/Sinsemilla). The hash-combining batch is
   pool-agnostic; a `zcash_client_backend` feature could expose it.

These are the "shuffle code from here to there and vice versa" wins — and they're the strongest argument that the
relationship is collaborative, not Slipstream-takes-from-upstream.

---

## 7. Ironwood readiness

**What it is:** a new shielded pool, **Orchard-shaped for scanning/persistence** (separate tables, separate
note-commitment tree, separate checkpoints), **plus 3 extra features** for security / ZEC-value-validity — the response
to the patched Orchard exploit.

**Where the extra features land (the key disambiguation):** the engineer was explicit that the **scan/persist** handling
is *"essentially identical to Orchard."* The 3 security/verification features are value-validity / proving concerns,
which live in the **consensus + transaction-construction/proving** layers — **not** in `put_blocks`, which only persists
*already-scanned* `ScannedBlock`s (commitments, nullifiers, decrypted notes). For our analysis, **Ironwood-in-`put_blocks`
== Orchard-in-`put_blocks`.**

> **One open question to confirm with the engineer** (flagged, not assumed): does any Ironwood validation run **during
> wallet scan** (per-note/per-block), or is it entirely consensus/proving? Either answer leaves Slipstream's *persist*
> override unaffected: Slipstream does **not** fork `scan_cached_blocks`, so any scan-side validation upstream adds is
> **inherited for free**. The only thing that would change is upstream's scan kernel, which Slipstream already consumes
> verbatim.

**How Ironwood lands in upstream `put_blocks`:** a `#[cfg(feature = "ironwood")]` arm beside every existing
`#[cfg(feature = "orchard")]` site — tree-size validation (`:256`), commitments vec (`:270`), `put_block_meta` args
(`:297` — **this widens `put_block_meta` and the `blocks` table → an upstream-owned DB migration**), per-tx
`ironwood_{spends,outputs}` + `mark_ironwood_note_spent` + `put_received_ironwood_note`, `track_block_ironwood_nullifiers`,
note positions, `build_subtrees`, `update_tree` (a third `ShardTree`), and the `WalletCommitmentTrees`
`with_ironwood_tree_mut`/`put_ironwood_subtree_roots` pair. Plus `ScannedBlock`/`ChainState` gain `ironwood()` /
`final_ironwood_tree()`.

**The two futures (the whole point of doing this now):**

- **Dedup NOT done first →** every one of those Ironwood arms must **also** be added to Slipstream's hand-copied mirror
  (a third `seed_/flush_/rayon` arm, a third checkpoint pipeline, etc.) **and kept byte-identical to upstream by hand.**
  Ironwood is implemented twice, on a 4-week clock, leaving a permanent divergence surface precisely on the
  newest/riskiest code.
- **Dedup done first →** upstream adds Ironwood **once** (unavoidable work it owns). Slipstream's override, now ~150
  lines of pure speed-core, adds **only**: `seed_ironwood`/`flush_ironwood` (mirroring Orchard), a **third `rayon::join`
  arm**, an `ironwood_nfs` running view in `WriteBehindFacade`, and **GPU-for-free** (Ironwood is Sinsemilla). The
  prologue/`build_subtrees`/`update_tree` Ironwood logic arrives from upstream automatically. **~40–60 speed-core lines,
  not a 1000-line re-mirror.** The DB migration is upstream's; Slipstream's `put_block_meta` call inherits it.

This is the engineer's DRY argument made concrete: **the duplicated code is exactly the code Ironwood changes**, so
removing the duplication converts an N=2 hand-synced Ironwood implementation into N=1.

---

## 8. Decision: refactor now vs. plan-then-ship (the call's two paths)

The engineer offered two paths and noted they're *"super challenged right now with so much in flight to review."* Given
the 4-week Ironwood deadline and review bandwidth, the leverage is asymmetric:

**The critical path is the small UPSTREAM seam PR (§4), and it's the engineer's own crate.** It is low-risk
(`pub`-ing private items + one pure refactor + one additive trait method), it is what unblocks **both** the dedup **and**
single-implementation Ironwood, and it is reviewable in isolation. Sequence:

1. **Upstream seam PR** (§4.1 + §4.2 + §4.3) — behavior-preserving; gated by upstream's own test suite. *(Engineer.)*
2. **Slipstream dedup** — bump the git rev, delete the **M/P/≈** copies, re-point `sparse_put_blocks` at the upstream
   prologue + `update_tree`, flush through the new trait method. **Every step oracle-gated** to the byte-identical
   `data.db` + the per-pass timing gate (§5). *(Slipstream / us.)*
3. **Ironwood lands once** — upstream adds the cfg arms + migration; Slipstream adds the ~40–60-line speed-core arm.

If the upstream PR can't be reviewed inside the window, the **fallback** preserves Priority #1: keep the mirror for this
Ironwood, but **freeze the per-pool sections behind small local helpers** in `persist.rs` (one `per_pool!`-style
seam per Orchard arm) so the Ironwood arm is a near-mechanical copy of the Orchard arm and the eventual upstream dedup
is a smaller diff. This is strictly worse than (1)→(3) but bounds the divergence if review slips.

**Honest cost/benefit:** the dedup buys maintainability and halves Ironwood, at the cost of one upstream PR + one
oracle-gated Slipstream refactor. It does **not** touch the speed core, so Priority #1 is structurally protected — the
only failure mode is a timing regression, which the existing gates catch before merge.

---

## 9. Risk register

- **Speed regression (Priority #1).** Mitigation: the byte-identical-`data.db` oracle + per-pass `rows/tree/flush`
  timing logs already exist; gate every dedup step on both. Persist is currently *off* the critical path (scan-bound),
  so there is headroom — but treat any move of persist onto the critical path as a hard stop.
- **The one genuine variance — `stream_checkpoint_positions` + the downgrade.** Slipstream computes checkpoint positions
  **pre-build** (from the commitment stream) so the T6.3b downgrade can run before `build_subtrees`; upstream's
  `checkpoint_positions` is **post-build**. These are *semantically equivalent* (`persist.rs:1012–1018` proves it) but
  **not textually identical** — so this is the one spot the dedup must preserve the order, not naively call the upstream
  post-build form. Keep the downgrade + the pre-build position map in Slipstream (or upstream the downgrade per §6).
- **Error-type coupling.** Both facades use `SqliteClientError` as `WalletWrite::Error` because the inner `Db` *is*
  `zcash_client_sqlite::WalletDb`. The §4.3 trait flush removes the *behavioral* `zcash_client_sqlite` coupling; the
  error *type* remains until/unless the facades go generic over `E`. Low priority — name it, don't block on it.
- **Ironwood scan-side validation (the §7 open question).** If Ironwood adds wallet-side per-note validation during
  scan, it lands in upstream's scan kernel, which Slipstream inherits — but confirm, so we're not surprised by a new
  read-surface method in `WriteBehindFacade` (which fails loudly by design — good, but worth pre-empting).
- **Rev-pin coordination.** The upstream seam PR and the Slipstream dedup must agree on a git rev; bump in lockstep.

---

## 10. Appendix — citation map

**Slipstream:** `slipstream/core/src/persist.rs` (2293 lines) — header `:1–5,482–488`; `sparse_put_blocks:489`;
`SparseShardStore:88`; `seed_*:310/342`; `flush_*:375/432`; `rayon::join:789`; `build_subtrees:963`;
`build_orchard_subtrees:991`; `stream_checkpoint_positions:1019`; `doomed_checkpoint_cutoff:1045`;
`downgrade_doomed_checkpoints:1087`; `ensure_checkpoints:1106`; `SparseFacade:1145`; `apply_nullifier_delta:1252`;
`WriteBehindFacade:1305`; `PersistLane/lane_pool_policy:1523+`.

**Upstream** (`~/.cargo/git/checkouts/librustzcash-c2c6180a1a11d4fa/1600f94/zcash_client_backend/src/`):
`put_blocks` `data_api/ll/wallet.rs:235` (`pub`, generic over `DbT: PutBlocksDbT`); **private** helpers
`build_subtrees:1146`, `checkpoint_positions:1173`, `ensure_checkpoints:1184`, `update_tree:1228` (generic over
`S: ShardStore`); `WalletCommitmentTrees` trait `data_api.rs:3313` (`with_{sapling,orchard}_tree_mut`,
`put_{sapling,orchard}_subtree_roots`); `Nullifiers::update_with` `scanning.rs:435`.

# Slipstream → upstream: a write-back overlay `ShardStore` for `incrementalmerkletree`

> **Status:** Analysis + plan only — **no code, no PR, no issue yet.** Captured to remember.
> **Date:** 2026-06-22. **Trigger:** core contact — *"consider upstreaming `SparseShardStore` into
> `incrementalmerkletree`; `MemoryShardStore` could use a full once-over; it's used directly by
> `zcash_client_memory`/WebZjs."*
> **Target crate:** `shardtree` (inside the `zcash/incrementalmerkletree` repo). **NOT**
> `zcash_client_backend` — that's the separate `put_blocks` dedup (see
> `2026-06-19-upstream-dedup-and-ironwood.md`). These are two distinct upstream tracks.

---

## 0. TL;DR

The "write-back overlay `ShardStore`" concept Slipstream's `SparseShardStore` embodies **already exists
upstream** as `shardtree::store::caching::CachingShardStore<S>` — but it's the **naive** version
(eager full-load, full-flush, terminal). **`SparseShardStore` is the optimized form of the same idea.**

So the upstreaming move is **not "add a new store"** — it's **"upgrade `CachingShardStore`"** with the
three deltas `SparseShardStore` already implements, plus fix `MemoryShardStore`'s dense-`Vec`
representation (which is also `CachingShardStore`'s cache, so it compounds).

- **Direct beneficiaries:** `zcash_client_memory` / **WebZjs** (WASM heap + per-flush write volume to
  IndexedDB), plus Slipstream (could delete its copy), zallet, zingo.
- **Mostly additive / lower-stakes** than the `put_blocks` seam: it's a self-contained data structure,
  no scan/consensus semantics, gated by `shardtree`'s own test suite.
- **No PR/issue exists** (checked `zcash/incrementalmerkletree` open PRs 2026-06-22). Only adjacent
  work: nuttycom's **#95** (explicit checkpoint retention).
- **One real design fork for nuttycom:** lazy-load-on-miss (needs `RefCell`) vs. explicit-preload
  (`SparseShardStore`'s choice).

---

## 1. Ground truth — where the code lives

**Upstream `shardtree-0.6.2`:**
- `src/store.rs` — the `ShardStore` trait (`:38`), `Checkpoint`/`TreeState` (`:257–320`), and a blanket
  `impl ShardStore for &mut S` (`:150`).
- `src/store/memory.rs` — `MemoryShardStore<H, C>` (`:15`); `Error = Infallible`.
- `src/store/caching.rs` — `CachingShardStore<S>` (`:22`), `load` (`:40`), `flush` (`:65`).

**Slipstream `slipstream/core/src/persist.rs`:**
- `SparseShardStore<H>` (`:101`), `SparseStoreError` (`:88`, incl. `NotPreloaded`), `impl ShardStore`
  (`:157`), `checkpoint_delta` (`:132`), `seed_{sapling,orchard}` (`:310/342`),
  `flush_{sapling,orchard}` (`:375/432`).

---

## 2. The gap — `CachingShardStore` (upstream) vs `SparseShardStore` (Slipstream)

`CachingShardStore` owns a `backend: S` and a `cache: MemoryShardStore` (`caching.rs:28–29`). It is the
right *shape* for an overlay, but every operation is whole-tree:

| Dimension | `CachingShardStore` (upstream, naive) | `SparseShardStore` (Slipstream, optimized) | Ideal upstream |
|---|---|---|---|
| **Seed** | eager full-load: copies **every** shard + checkpoint from backend (`caching.rs:43–55`) | sparse preload of just the scan range's working set | lazy-on-miss **or** sparse preload |
| **Flush granularity** | re-writes **every** shard (`:79–90`) + re-adds **every** checkpoint (`:94–112`) | `dirty_shards`/`cap_dirty` + `checkpoint_delta()` → writes only the delta | dirty delta |
| **Flush lifecycle** | `flush(self)` consumes self (`:65`) — terminal, one-shot | `&mut self`, per-chunk, reusable | incremental `flush_delta(&mut self)` + keep terminal `flush(self)` |
| **Backend handle** | **owns** `backend: S` (`:28`) → *could* lazy-fetch on miss | none (seeded externally) | owns backend (enables lazy) |
| **Read-miss policy** | n/a (cache holds everything) | loud `NotPreloaded` guard (`persist.rs:88,167`) | the fork ↓ |

**Why it matters for WebZjs:** `flush` re-serializing the entire tree on every call is the worst case
for a WASM→IndexedDB persistence layer. A dirty-delta flush turns each save from O(tree) into O(changes).

---

## 3. `MemoryShardStore` once-over (the contact's explicit ask)

1. **Dense `Vec` with empty back-fill → sparse `BTreeMap`.** `put_shard` back-fills empty shards from
   the last index up to the inserted index (`memory.rs:50–65`). A wallet synced from a **recent
   birthday** inserts a high-index shard first → allocates a long run of empty `LocatedTree`s,
   **O(max_index) memory + O(gap) work**, repeatedly. `BTreeMap<u64, LocatedPrunableTree>` (exactly
   `SparseShardStore`'s representation) is sparse and contract-compliant — `get_shard_roots` has **no
   contiguity requirement** (`store.rs:63`). Biggest single win; also fixes `CachingShardStore`'s cache.
   - **Verify-before-shipping:** nothing in the frontier/cap logic assumes contiguous shard roots.
     `SparseShardStore` in production says it's fine, but it deserves a dedicated test.
2. **Clone-heavy getters.** `get_shard`/`get_cap`/`get_checkpoint` clone on every read
   (`memory.rs:43/78/103`) because the trait returns owned values. An **additive** borrowing accessor
   (e.g. `with_shard(addr, |tree| …)`) lets in-memory stores skip the clone on hot reads. Non-breaking.
3. **`with_checkpoints` takes `&mut self`** (`store.rs:114`) but never mutates — same body as the
   `&self` `for_each_checkpoint`. Worth collapsing, but it's a **breaking** trait change → bundle with
   any other trait revision, don't do it alone.
4. **Doc nit:** `store.rs:142` "greater than to the given identifier."

---

## 4. The plan (sequenced, additive-first) — no code yet

1. **RFC issue to nuttycom** on `zcash/incrementalmerkletree`. Frame: *"`CachingShardStore` is the naive
   overlay; here are the 3 deltas `SparseShardStore` already proves + the `MemoryShardStore`
   representation fix + the lazy-vs-preload fork."* Reference **#95**. **(This is the only next action.)**
2. **`MemoryShardStore`: `Vec` → `BTreeMap`.** Smallest, self-contained, highest-value; add a
   non-contiguous-shard-roots test. Lands independently of everything else.
3. **`CachingShardStore`: dirty tracking.** Track dirty shards + cap + a checkpoint diff so `flush`
   writes only the delta; add an incremental `flush_delta(&mut self)`; keep `flush(self)` as the
   terminal convenience. Transparent to existing callers (same result, less I/O).
4. **Seed policy (the fork).** Implement nuttycom's choice: lazy-fetch-on-miss (needs `RefCell` because
   `get_shard` is `&self`, `store.rs:49`) **or** an explicit preload API mirroring `SparseShardStore`'s
   working-set + `NotPreloaded` guard.
5. **Slipstream adoption.** Once upstream has the enhanced store, evaluate deleting `SparseShardStore`
   in favour of it — **gated by the byte-identical `data.db` oracle + per-pass timing** (Priority #1
   unchanged). Keep `SparseShardStore` if the generic overlay can't match its per-chunk flush perf.

---

## 5. Open questions / forks

- **Lazy (`RefCell`) vs. explicit-preload.** `CachingShardStore` owns its backend so lazy is *possible*,
  but `get_shard(&self)` can't populate the cache without interior mutability. `SparseShardStore` chose
  explicit-preload precisely to dodge this. nuttycom's call.
- **Error type.** `CachingShardStore::Error` is `Infallible` (`caching.rs:126`); a lazy/sparse variant
  that can hit the backend on read (or a `NotPreloaded` guard) gains a *real* error. Don't silently
  break `Error = Infallible` consumers — likely a new store/variant rather than re-typing the existing.
- **BTreeMap contiguity.** Confirm the frontier/cap code never assumes dense shard roots (test it).
- **In-place vs. variant.** Can the dirty-set be added to `CachingShardStore` transparently (yes,
  result-preserving), while lazy-seed is opt-in / a sibling type? Lean: dirty-set in place; seed policy
  behind a constructor.

---

## 6. Status & relationship to the other upstream track

- **Status: PARKED as analysis.** No code, no PR, no issue.
- **Next step when picked up:** open the RFC issue to nuttycom (draft available on request).
- **Vs. the `put_blocks` dedup (`2026-06-19` doc):** *separate* upstream target (`shardtree`, not
  `zcash_client_backend`). Both are instances of *"upstream taking advantage of Slipstream's ideas so
  all profit"* (that doc's §6). This one is **more additive and lower-stakes** — a data structure, not a
  consensus-adjacent persistence seam — so it can proceed independently of the Ironwood clock.

## 7. Citation map

- **Upstream** `~/.cargo/registry/src/*/shardtree-0.6.2/src/`: `store.rs` (trait `:38`, `get_shard`
  `:49`, `get_shard_roots` `:63`, `with_checkpoints` `:112–116`, `Checkpoint` `:271`); `store/memory.rs`
  (`MemoryShardStore` `:15`, `put_shard` back-fill `:50–65`, clones `:43/78/103`); `store/caching.rs`
  (`CachingShardStore` `:22`, `backend` `:28`, `load` `:40–62`, `flush` `:65–115`).
- **Slipstream** `slipstream/core/src/persist.rs`: `SparseStoreError` `:88`, `SparseShardStore` `:101`,
  `checkpoint_delta` `:132`, `impl ShardStore` `:157`, `seed_*` `:310/342`, `flush_*` `:375/432`.

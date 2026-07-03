# GitHub issue draft — `zcash/incrementalmerkletree`

> **This is the paste-ready text for Point 1 (the design issue / RFC).** Post on
> `zcash/incrementalmerkletree`. No code yet — this is to get the maintainer's steer (esp. the §3
> fork) before PRs. Verified against `main` @ `8a79f09` (shardtree 0.6.2): the behaviours cited below
> are current. Analysis backing it: `docs/slipstream/2026-06-22-upstream-shardtree-overlay-store.md`.

---

**Title:** Scale the in-memory overlay path: sparse `MemoryShardStore` + dirty-delta `CachingShardStore`

## Summary

`CachingShardStore` is already the "write-back overlay" pattern — cache a tree in memory, flush to a
backend — but every operation is whole-tree:

- `load()` eagerly copies **every** shard and **every** checkpoint out of the backend.
- `flush()` re-writes **every** shard and re-adds **every** checkpoint regardless of what changed, and
  it consumes `self` (one-shot, can't flush-and-continue).

In the Zashi/Zodl wallet sync engine ("Slipstream") we built and shipped an optimized version of exactly
this overlay — **sparse seed + dirty-delta flush + incremental (reusable) flush** — as part of a ~12×
wallet-sync speedup, gated by a byte-identical `data.db` oracle. We'd like to fold those wins back
upstream so every consumer benefits — notably `zcash_client_memory`/WebZjs, where the per-flush cost and
in-memory footprint matter most.

This is **two largely independent improvements plus one design question** we'd like your steer on before
we open PRs. We have a working reference implementation for all of it and are offering to do the PRs.

## 1. `MemoryShardStore`: dense `Vec` → sparse `BTreeMap` (independent, small)

`MemoryShardStore` stores shards in a `Vec` indexed by shard index, and `put_shard` back-fills empty
shards from the last populated index up to the inserted one. Inserting a high-index shard — e.g. a wallet
synced from a **recent birthday**, whose first populated shard index is large — allocates a long run of
empty `LocatedTree`s: `O(max_index)` memory and `O(gap)` work, and it grows as the tree does.

A `BTreeMap<u64, LocatedPrunableTree<H>>` is sparse and (we believe) contract-compliant —
`ShardStore::get_shard_roots` is documented as "the addresses corresponding to the roots of subtrees
stored in this store", with no contiguity requirement. Direct heap win for `zcash_client_memory`/WebZjs,
and it also improves `CachingShardStore` (whose cache *is* a `MemoryShardStore`).

We'd add a test exercising **non-contiguous shard roots** to confirm nothing in the cap/frontier logic
assumes density. (Our production store uses exactly this `BTreeMap` representation, so we're fairly
confident — but it deserves an upstream test.)

## 2. `CachingShardStore`: dirty-delta + incremental flush

Today `flush()` writes the whole cached tree back. We propose:

- Track a **dirty set** (changed shards + a cap-dirty flag) and a **checkpoint diff** (added / removed /
  mutated since load), so `flush` writes only the delta.
- Add an incremental `flush_delta(&mut self)` that flushes the delta and **keeps the store usable** (for
  long syncs that flush per chunk), while keeping the existing terminal `flush(self)`.

For an async-persisted consumer like WebZjs (IndexedDB), this turns "re-serialize the entire tree on
every save" into "write only what changed" — typically `O(tree)` → `O(changes)` per checkpoint.

This is result-preserving: a delta flush leaves the backend in the same state a full flush would. We'd
add a test asserting exactly that.

## 3. The one design question: seed policy — explicit-preload vs lazy-on-miss

The sparse/delta overlay needs a seed policy, and there's a real fork we'd like your call on:

- **Explicit-preload (our recommendation).** The caller preloads the working set up front; reads then
  only ever hit the in-memory cache.
- **Lazy-on-miss.** `get_shard` fetches from the backend on a cache miss and caches the result.

We recommend **explicit-preload**, for four reasons:

1. `get_shard(&self)` is a read; lazy-on-miss must mutate the cache to stash the fetched shard → it needs
   interior mutability (`RefCell`), which is `!Sync` and adds a runtime-borrow panic surface.
   Explicit-preload keeps reads pure and `Sync`.
2. It's the only policy that composes with **async** backends: WebZjs/IndexedDB can't do blocking I/O
   inside a sync `get_shard`, so an async consumer must load up front regardless. Explicit-preload
   (async-load the working set → sync compute → async-flush the delta) fits; lazy-fetch-inside-a-sync-read
   can't exist there.
3. It's production-proven (our store, ~12× sync).
4. Predictable I/O — no surprise backend hit mid-tree-operation.

The cost — the caller must know its working set — is a solved pattern in our engine (computed from the
scan range). And the **dirty-delta flush (§2) is independent of this fork** and helps every consumer
regardless. Lazy could be added later as a convenience layer for sync backends.

> Sub-question: a sparse/strict store that can miss gains a real error type, whereas
> `CachingShardStore::Error` is currently `Infallible`. We'd likely express the strict variant as its own
> type / constructor rather than re-typing the existing `Error` (to avoid breaking `Error = Infallible`
> consumers) — but happy to follow your preference.

## Relationship to #95

The checkpoint-diff in §2 overlaps territory with #95 (explicit checkpoint retention). Happy to align so
they compose rather than collide.

## What we're offering

We have a working reference implementation of all of the above (Slipstream's `SparseShardStore`), so we're
offering to write the PRs:

- **PR 1** — `MemoryShardStore` `Vec` → `BTreeMap` (+ non-contiguous-roots test). Independent of the
  design question; can land first.
- **PR 2** — `CachingShardStore` dirty-delta + incremental flush + the chosen seed policy.

Before PR 2 we just need your steer on §3 (and a sanity check on §1's no-contiguity assumption). Happy to
share the reference `SparseShardStore` if useful.

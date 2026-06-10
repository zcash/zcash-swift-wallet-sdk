# Slipstream — a clean-sheet sync engine for mobile Zcash wallets

**Status:** design proposal (greenfield; no compatibility constraints assumed)
**Goal:** the fastest possible sync on iOS/Android, bounded only by physics: link bandwidth and aggregate core throughput.
**Date:** 2026-06-10. Companion analysis of the current SDK: `docs/SYNC_PERFORMANCE_PROPOSAL.md`.

---

## 0. The thesis

A light-client sync is not an RPC conversation with a server. It is a **bulk data-processing problem over static, public, immutable data** (the compact chain), plus a tiny mutable tail (the tip). Every fast engine that exists (warp sync, BlazeSync) is an approximation of the same ideal: *a saturated pipeline where bytes flow from the network through all CPU cores into a small set of conclusions, touching each byte exactly once.*

Slipstream designs that ideal directly, then adds the things the fast engines lack: verifiability, reorg correctness, resumability, multi-account support, and a mobile-grade operational envelope (memory, thermals, background slices).

### Design laws

1. **The chain is a static asset.** Distribute it like one (content-addressed chunks, parallel HTTP, CDN-able), don't stream it like a conversation.
2. **Wall-clock = max(stage times), not Σ.** Every stage runs concurrently with every other; every stage is internally parallel.
3. **Touch each byte once.** Blocks live in memory from socket to scanner; nothing is persisted except conclusions.
4. **Durability per chunk, not per step.** Crash-recovery replays at most one chunk (~seconds), so the hot loop never pays fsync.
5. **Spendability first, history second, memos last.** Perceived speed is a scheduling property, not a throughput property.
6. **The engine never sees spend authority.** Viewing keys only; spending stays in the wallet layer (PCZT-compatible).
7. **Engineer to measured floors.** Every target below is `max(download floor, compute floor)` — if an implementation misses it, that's a bug with a name.

### The floors (why there is no decrypt-less magic)

Trial decryption of a compact output requires `epk` (32 B), `cmu/cmx` (32 B), and the 52-byte ciphertext prefix — which is exactly what a `CompactSaplingOutput`/`CompactOrchardAction` contains. **The compact format is already detection-minimal.** No protocol-compatible shortcut exists that avoids downloading ~116–148 B/output or performing ~1 ECDH per (output × IVK); anyone claiming otherwise is trading away the privacy model (server-side detection) or correctness (skipping ranges). Therefore the design maximizes two things: *bytes/sec into the device* and *ECDH/sec across its cores*, and makes everything else free.

Reference floor numbers (1 account ≈ 2 IVKs/pool; measure on target hardware, these are estimates to be calibrated):

| Quantity | Estimate |
|---|---|
| Batched trial decrypt, per output, both attempts | ~20–30 µs/core (mobile big core) |
| 1M recent blocks ≈ 10–25M outputs+actions | ~2–4 min on 5 effective cores |
| Compact data, 1M recent blocks | ~1.5–3 GB |
| Download at 50 / 200 Mbps effective | ~5–8 min / ~1.5–2 min |
| Sparse tree work (50-tx wallet, see §3.3) | seconds |
| Result persistence | negligible (KB–MB) |

So a perfect engine syncs 1M blocks in **≈ max(download, decrypt) ≈ 2–6 minutes** on a modern phone with good bandwidth. Hours-long syncs are 100% orchestration failure, not crypto.

---

## 1. Shape of the system

One Rust core, three swappable layers, thin platform shells:

```
┌─────────────────────────────── SLIPSTREAM CORE (Rust) ───────────────────────────────┐
│                                                                                      │
│  TRANSPORT LAYER (pluggable providers, racing/failover)                              │
│   T0: lightwalletd gRPC ranges   T1: warp-packet CDN blobs   T2: zaino index APIs    │
│   (all optionally via Tor, circuit-isolated per fetch)                               │
│            │ N parallel fetchers, adaptive chunk sizing                              │
│            ▼                                                                         │
│  ┌──────────────────┐ bounded queues ┌──────────────────┐    found     ┌───────────┐ │
│  │ FETCH + VERIFY   │ ──────────────▶│ DETECT KERNEL    │── notes ────▶│ TREE      │ │
│  │ hash-chain check │   (in memory,  │ all-core batched │  (positions) │ sparse    │ │
│  │ position anchors │    zero disk)  │ trial decryption │              │ shards +  │ │
│  └──────────────────┘                │ CPU; GPU optional│              │ bridges   │ │
│            │                         └──────────────────┘              └───────────┘ │
│            │ height-ordered commit barrier                                  │        │
│            ▼                                                                ▼        │
│  ┌─────────────────────────────────────────────────────────────────────────────┐    │
│  │ COMMITTER (single writer): nullifier sweep → undo log → chunk checkpoint    │    │
│  └─────────────────────────────────────────────────────────────────────────────┘    │
│        │ txids                      │ events/progress (atomic snapshot)              │
│        ▼                            ▼                                                │
│  ┌────────────┐            ┌──────────────────┐      ┌─────────────────────────┐     │
│  │ ENHANCER   │── txs ────▶│ RESULTS STORE    │ ───▶ │ SQLITE PROJECTION       │     │
│  │ async pool │            │ append log +     │      │ (app-facing tx history, │     │
│  └────────────┘            │ snapshots        │      │  balances; write-behind)│     │
│  SCHEDULER: tip-first, backfill, QoS/thermal/background-slice aware                  │
└──────────────────────────────────────────────────────────────────────────────────────┘
        ▲ open(ufvks)/start(mode)/snapshot()/stop()          │ one event stream
   Swift shell (AsyncStream)                            Kotlin shell (Flow)
```

**Language:** Rust core (only credible option: shared across iOS/Android/desktop, the entire Zcash crypto ecosystem lives there, fearless parallelism, no GC pauses). Platform shells in Swift/Kotlin are *rendering code only* — UniFFI (or a hand C ABI) exposes ~6 functions and one event stream. There is no per-batch FFI: the boundary is crossed once at start and once per UI frame at most. Swift/Kotlin/C++ cores were considered and rejected: duplicated engineering per platform, slower field arithmetic, and no access to `sapling-crypto`/`orchard`/`shardtree`.

**Layering rule:** Transport, Detection, Tree, and Store interact only through typed channels and traits — each independently testable, replaceable, and upstreamable (e.g., the detect kernel can be adopted by the Android SDK without the store; zallet-style headless wallets can adopt transport+kernel with their own data model).

---

## 2. Transport: treat the chain as a CDN asset

### 2.1 Warp packets (T1 — the headline transport)

The unit of distribution is a **warp packet**: an immutable, content-addressed blob of ~10k blocks (~30–80 MB typical; output-count-bounded during spam ranges), generated once by an indexer (zaino plugin, or a standalone exporter against zebrad/lightwalletd) and served from dumb storage (S3/CDN/IPFS/mirror). Format:

```
header:
  start_height, end_height, prev_block_hash,
  start_tree_sizes  { sapling, orchard },          // absolute output positions
  start_frontiers   { sapling, orchard },          // commitment-tree frontiers at start
  per_block index   { offset, output/action counts },
  content_hash, generator_sig (advisory)
body:
  length-prefixed raw CompactBlock frames (wire protobuf, unmodified)
```

Why this is the unlock:

- **Parallel, resumable, full-link-speed download.** K fetchers pull K packets concurrently over HTTP/2/3 with range requests. No gRPC single-stream ceiling, no server CPU in the path, no stream rebuilds. CDNs and mirrors scale for free; the community can host packets anywhere because…
- **Packets are trustless.** The receiver verifies: internal hash-chain continuity, `prev_block_hash` linkage between packets, and `start_frontiers` against (a) the previous packet's computed end-frontier and (b) any server's subtree roots / treestate at spot-check heights. A malicious CDN can withhold, not forge.
- **Position anchors kill two RPCs and unlock out-of-order everything.** Because each packet self-describes its absolute tree positions and frontiers, *any packet is independently scannable with zero server round-trips* — no `GetTreeState` ever, and chunks can be detected in any order on any worker. (This is the generalization of what warp sync does in one process, turned into a verifiable data format.)
- **Spam-era variants.** A `lite` packet variant may omit ciphertexts (keeping `cmu`/nullifiers) for ranges the user opted to skip-detect (§6), halving spam-range bandwidth.

### 2.2 T0: stock lightwalletd (works today, no one's permission needed)

The same pipeline fed by 2–4 concurrent `GetBlockRange` streams over disjoint sub-ranges (lightwalletd allows this today), assembled into synthetic in-memory packets. Tree positions come from `ChainMetadata` (`sapling/orchardCommitmentTreeSize`, already in the CompactBlock proto), with one `GetTreeState` per scan-front as fallback for servers that omit it. T0 is the MVP transport: it already achieves `max(download, decrypt)`; T1 then raises the download ceiling.

### 2.3 T2: index accelerators (zaino-class extensions, optional)

- **Nullifier index** (`nullifier → (height, txid)`): turns "was my note spent?" into O(1) lookups; powers instant spent-status for restored notes ahead of the backfill front (DAGSync-lite walking of the wallet's own transaction graph).
- **Activity hints:** the existing transparent address index; optional ranged bloom digests of *txid prefixes* for watch-only restore flows.
- All T2 calls are advisory accelerators — the engine remains correct and complete with T0/T1 only.

### 2.4 Privacy posture

All transports run over Tor (arti) when enabled, with circuit isolation per packet / per txid-group. The fixed packet grid is itself a privacy feature: every restoring client fetches the *same* aligned blobs, so fetch patterns don't fingerprint birthdays beyond packet granularity (vs. today's bespoke ranges). Enhancement hides txid interest either by txid-isolated circuits (today's model) or by fetching the full block containing a hit. The detect kernel runs with viewing keys on-device only — nothing about detection ever leaves the device.

---

## 3. Compute: three engines, zero coupling

### 3.1 Detect kernel (the CPU burner)

A pure function: `(packet, scanning_key_set) → findings` — no database, no I/O, no shared mutable state.

- Outputs across all transactions in the packet are flattened into column-oriented arrays (epk[], cmu[], ct[]) per pool — data-oriented layout for cache-friendly batched ECDH (shared batch affine inversion, shared scalar recoding per IVK; NEON-vectorized field ops).
- Work-stealing across all cores (rayon), batch size tuned to L2 (~2–4k outputs). Multiple accounts share the batch overhead.
- Pool/epoch pruning: pre-NU5 packets skip Orchard entirely; key sets with no Sapling component skip Sapling.
- Emits per packet: found notes (with absolute positions, value, rseed), per-block hit map, and the packet's nullifier array handle for the committer sweep.
- **GPU afterburner (Tier 3, experimental):** the ECDH+ChaCha20+cmu-check inner loop is a textbook GPU workload (no divergence, fixed-size records). A Metal/Vulkan compute path could plausibly add 3–10× over CPU for spam-density ranges. Caveats are real: constant-time discipline on GPU, key material residency, per-vendor field-arithmetic kernels — prototype behind a flag, never default until reviewed. The architecture treats it as just another `DetectBackend` impl.

### 3.2 Why detection can be embarrassingly parallel safely

Detection is order-independent; *consequences* are not. The committer (single writer) applies packet results in height order: it merges found notes into the watched-nullifier set, then sweeps that packet's nullifier array — so a note received at height *h* and spent at *h+k* is caught regardless of which worker decrypted what, because the sweep happens at ordered-commit time, not at detect time. Out-of-order *scheduling* (tip before history) is bounded: the only disconnected scanned region is the tip window, whose nullifier arrays are tiny and retained until the backfill front connects (then dropped). Restored notes get instant spent-status via the T2 nullifier index when available, else on front-connection.

### 3.3 Sparse tree engine (witnesses without the tree)

The witness problem is where naïve engines drown. Slipstream does the minimum the math allows:

- **Teleport across empty space.** Server-provided subtree roots (existing lightwalletd API, verified against packet frontiers) advance the global frontier across any 2^16-leaf subtree containing none of our notes without hashing a single leaf.
- **Hash only owned shards.** When detection finds a note at position *p*, only the subtree containing *p* is materialized — its leaves are exactly the `cmu`s already in the packet(s) covering it; hashing 65k Pedersen/Sinsemilla nodes is ~0.1–0.3 s, parallelizable, and amortized across co-located notes.
- **Bridges, not per-note updates.** Per packet, compute one *bridge* (the combined ommer data needed to advance any witness across the packet's appends) as a parallel tree reduction; apply it to all tracked witnesses at once. Witness maintenance cost becomes O(packets × log n + owned notes), independent of total chain outputs.
- Packets retain `cmu` arrays only until their shard's fate is decided (no owned notes → dropped immediately), bounding memory.
- At the tip, the open shard's frontier updates incrementally per block — standard behavior, tiny.

This is the warp-sync insight, the shardtree/SBS asymptotics, and bridgetree's data structure, fused: same math, but in-memory, chunk-aligned, parallel, and write-behind.

### 3.4 Committer, results store, and the undo log

- Single writer applies ordered packet results: notes, spends, tx skeletons, witness bridges, frontier checkpoint, scan-coverage interval map. One atomic checkpoint per packet (law #4) — the *only* durability point in the hot path.
- The store is an **append-only log + periodic compact snapshot** (KBs–MBs total: keys' findings, not chain data). SQLite remains, but as a *projection*: the app-facing transaction history/balance views are rebuilt write-behind off the log, off the critical path, fully compatible with existing wallet data models (and with `zcash_client_sqlite` if an integrator wants to keep it as the projection target).
- Last R=100 blocks keep an **undo record** (effects + header hashes). Reorg = revert effects to fork point, invalidate coverage above it, rescan — same trust model as today, near-zero steady-state cost. Deeper-than-R reorgs degrade to range invalidation.

### 3.5 Enhancer

Found txids stream to an async pool (bounded fan-out, deduped, retried, Tor-isolated) fetching full transactions for amounts/outgoing-data/fee metadata. **Memos are lazy by default**: fetched in a trailing background pass or on first view (policy knob, §6). Enhancement never blocks the scan front; a wallet is spendable before its memos exist.

---

## 4. Scheduler: perceived speed is a policy

Priorities (preemptible, resumable):

1. **Tip verify + spendability window** (tip − ~10k → tip): wallet usable in seconds (this is Spend-before-Sync, kept).
2. **Activity-guided islands** (T2 hints, detected-spend walkbacks): the user's history materializes in likely-first order.
3. **Linear backfill** birthday → tip front (keeps the nullifier-retention bound tiny, §3.2).
4. **Memo/enhancement trailing pass.**

Operational envelope:

- **Modes:** `Sprint` (foreground restore: all cores, big buffers, ~300 MB budget), `Cruise` (foreground catch-up), `Drip` (background: E-cores only, small packets, ~60–80 MB, checkpoint-per-packet makes 30 s OS slices productive), `Plugged` (overnight: sprint while charging).
- Thermal/battery feedback throttles the detect pool, never the committer.
- Checkpoint+resume means *no work is ever lost* — kill -9 at any moment costs at most one packet.

---

## 5. Public surface (per platform, total)

```
SlipstreamEngine.open(dir, network, viewing_keys, policy) -> Engine
engine.start(mode)            // idempotent; returns immediately
engine.events()               // single stream: progress, found tx, spendable, reorg, completed
engine.snapshot()             // cheap atomic copy: heights, coverage map, balances, ETA
engine.stop() / .checkpoint() // graceful; resume-safe always
engine.rescan(from_height)    // coverage-map invalidation, not data deletion
```

ETA in `snapshot()` is honest: derived from measured live throughput per stage and remaining bytes/outputs — the engine knows whether it's download- or CPU-bound and says so (UI can render "downloading, 80 Mbps" vs "scanning, 210k outputs/s").

---

## 6. Policy knobs (explicit, default-safe)

| Knob | Default | Effect |
|---|---|---|
| `tor` | wallet-controlled | all transports via arti, circuit isolation |
| `memos` | lazy | trailing/on-demand memo fetch |
| `spam_heuristics` | **off** | opt-in: defer trial decryption of outputs in transactions matching dust-spam fingerprints (e.g., sandblasting-era shapes) to a background pass; documented, bounded risk of *delayed* (never lost) detection; big CPU win on spam ranges |
| `gpu_detect` | off | experimental afterburner (§3.1) |
| `bandwidth_cap` / `metered` | unlimited | fetcher concurrency + packet size |
| `background_budget` | OS default | Drip-mode sizing |

---

## 7. What it costs / what it buys (estimates to calibrate, not promises)

Assumptions: 1 account, modern phone (≥5 effective cores), recent-era chain density; "today" = current SDK measured behavior class.

| Scenario | Today (SDK) | Slipstream T0 (stock lwd) | + T1 (CDN packets) | Binding constraint |
|---|---|---|---|---|
| New wallet (birthday = tip) | ~min | < 10 s | < 10 s | a few RTTs |
| Catch-up, 1 week offline | minutes | < 15 s | < 15 s | RTT + tip window |
| **Restore, 1M blocks (recent era)** | **1.5–3 h** | **8–15 min** | **2–6 min** | download |
| Full restore crossing spam era (~2.7M blks) | 6–24 h+ | 45–90 min | 25–45 min | download; CPU on spam ranges |
| …with `spam_heuristics=on` | — | ~30–60 min | ~15–30 min | download |
| Battery per 1M blocks | high (hours of radio+CPU) | ~minutes of saturated CPU+radio | lower (radio-efficient bulk HTTP) | — |

Two orders of magnitude on the headline scenario, one order on the worst case — consistent with the floors in §0, which is the point: *the targets are the floors.*

---

## 8. Correctness & verification strategy

- **Differential testing:** every packet's findings replayed against `zcash_client_backend::scanning` as a golden oracle (CI, device farm).
- **Reorg fuzzing:** darkside-lightwalletd scenarios ported to packet form; undo-log invariants property-tested.
- **Determinism:** detect kernel is a pure function — record/replay of packet sets gives bit-stable regression tests and benchmarks.
- **Trust model unchanged** from today's light client: hash-chain + checkpoints + subtree-root cross-checks; optional multi-server quorum on roots/treestates (cheap: they're tiny); CDN is untrusted by construction.

## 9. Risks, honestly

| Risk | Exposure | Mitigation |
|---|---|---|
| Greenfield scanner correctness | funds-affecting | golden-oracle differential tests (§8); kernel can literally wrap upstream `scan_block` internals initially, swap optimized kernel later |
| Packet ecosystem bootstrap | T1 value depends on hosting | T0 is fully functional alone; exporter is a weekend project against zebrad; ECC/ZF/community mirrors + content addressing make hosting commodity |
| iOS/Android background semantics | resume bugs | checkpoint-per-packet is the *only* persistence path — exercised constantly, not a rare path |
| Memory under spam density | OOM kills | output-count-bounded packets; budget-aware queue sizing; Drip mode |
| GPU side channels | key extraction (theoretical) | off by default; per-app GPU isolation on modern mobile; external review before enabling |
| Divergence from upstream | maintenance | layers map cleanly onto librustzcash traits; upstream the packet format + kernel + bridge tree work (zallet and Android SDK want exactly these) |

## 10. Build order (each step ships value alone)

1. **Kernel + pipeline on T0** against stock lightwalletd, desktop CLI harness (zallet-adjacent dev tool): proves `max(download, decrypt)` end-to-end; this alone beats every current mobile wallet.
2. **Store + scheduler + mobile shells** (UniFFI, Drip/Sprint modes, resume): production engine, Zodl integration behind a flag.
3. **Warp-packet exporter + T1 fetchers** (+ mirrors): download ceiling raised to link speed; publish format spec for the ecosystem.
4. **T2 indexes (zaino PRs), spam policy, GPU prototype:** the long tail of multipliers.

Steps 1–2 ≈ the P0 engine from `SYNC_PERFORMANCE_PROPOSAL.md` built clean-sheet rather than retrofitted — the two documents converge: P0/P1 there are the brownfield ramp, Slipstream is the destination.

---

*Naming: "Slipstream" — the engine's entire job is keeping every stage in the draft of the one ahead of it. Alternative names considered: Meteor, Comet, ZipSync. Bikeshed freely; the channels don't care.*

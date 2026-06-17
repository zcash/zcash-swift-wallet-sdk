# Slipstream — Reviewer's Guide

> For Zcash protocol / cryptographic engineers. This is a **map** — where to look and why — not a
> tutorial. Prose deep-dives live in `docs/book/` (open `index.html`); build journals in `docs/plans/`.
> The engine consumes **published** librustzcash (crates.io, no forks). It adds *scheduling,
> persistence shape, and transport policy* — **not cryptography**.

## TL;DR
A mobile-first compact-block sync engine. Same wallet DB and note-commitment math as
`zcash_client_backend` / `zcash_client_sqlite` — the novelty is **how** it drives them: non-linear
Spend-before-Sync scheduling, concurrent density-adaptive fetch, an in-memory **sparse**
commitment-tree persistence path, depth-N in-order write-behind, a per-call Tor policy, and a
host-agnostic autonomous session. Every acceleration is **byte-identical** to upstream's `put_blocks`
and is oracle-gated. Note decryption, nullifier derivation, and tree hashing are **not** reimplemented.

## Start here (in order)
| # | Read | Why |
|---|------|-----|
| 1 | `core/src/engine.rs` → `sync_once` | One full pass, top to bottom — the spine. |
| 2 | `core/src/session.rs` → `run_session` | The autonomous lifecycle around passes (Tor bootstrap → resilient initial pass → follow + mempool). The single host entry point. |
| 3 | `core/src/scheduler.rs` → `run_to_completion` | Drives suggested scan-ranges → fetch/scan/persist/enhance per range. |
| 4 | `core/src/persist.rs` | The interesting persistence: sparse ShardTree + write-behind. The perf win **and** the byte-identity. |
| 5 | `cli/src/main.rs` → `cmd_sync`, `cmd_oracle` | Runnable harness + the correctness oracle. |

## Module map (`core/src/`)
| File | Responsibility |
|------|----------------|
| `engine.rs` | `sync_once` (one pass), `probe_tip`, `should_resync`, `SyncOutcome`, `ENGINE_BUILD`. |
| `session.rs` | `run_session` autonomous lifecycle; `SessionConfig` / `SessionReporter`; retry/jitter/backoff. |
| `scheduler.rs` | `run_to_completion`: Spend-before-Sync scan-range loop + per-range enhancement. |
| `scan.rs` | `scan_chunks`: batched `scan_cached_blocks`; treestate prefetch + bounded retry. |
| `fetch.rs` | Concurrent `GetBlockRange` (N streams); byte-budgeted sub-chunk splitting (sandblasting era); resume-on-cut. |
| `persist.rs` | Sparse in-memory `ShardTree` `put_blocks`; checkpoint-downgrade; `WriteBehindFacade` + persist lane (depth-N, **in-order, serial**). |
| `connector.rs` | Per-call Tor policy (`ConnPurpose` → circuit); `TorConn` bootstrap; bounded circuit-build + retry-on-fresh-circuit. |
| `grpc.rs` | lightwalletd tonic client; unary/stream helpers + deadlines; `retry_get_tree_state`. |
| `enhance.rs` | `run_enhancement`: `GetTransaction` / `TransactionsInvolvingAddress`, dedup. |
| `transparent.rs` | `refresh_utxos` — runs **before** the shielded scan (mirrors upstream `sync.rs`). |
| `mempool.rs` | `run_session`: `GetMempoolStream` → `decrypt_and_store_transaction` (0-conf); non-fatal. |
| `wallet_session.rs` | `WalletSession` — the `zcash_client_sqlite` `WalletDb` wrapper + account import. |
| `chunk.rs`, `block_source.rs` | In-memory chunk buffering / block-source plumbing feeding the scan kernel. |
| `events.rs` | `Progress` (poll atomics), `Event`, `Snapshot` — the host-facing progress surface. |
| `ffi_handle.rs` | `SlipstreamHandle` (runtime + state + event ring), `SyncState`, `FfiSlipstreamSnapshot/Event`, `spawn_supervised` (panic → `Error`). |
| `oracle.rs` | `semantic_diff` — row/byte-level `data.db` equivalence vs the upstream path. |
| `verify.rs` | Server / scan-continuity validation. |
| `config.rs` | `EngineConfig` (tunables, device-memory derate), `Endpoint`. |
| `error.rs` | `SlipstreamError` + `is_transient` (drives every retry decision). |

`gpuhash/` (crate `slipstream-gpuhash`, cargo feature `gpu`, **default-off**) — wgpu Orchard Sinsemilla
combine; byte-identical to `MerkleHashOrchard::combine` (KAT-gated). Released builds link zero wgpu.

## Sync data flow (one pass)
**Preflight** (`sync_once`): import account if the DB has none (UFVK + birthday treestate) →
`get_subtree_roots` / `put_subtree_roots` → chain tip → **transparent UTXO refresh** (before shielded)
→ `run_to_completion`:
- `suggest_scan_ranges` → **ChainTip priority, then Historic** (Spend-before-Sync; non-linear order, so
  spendable notes surface first).
- per range: **fetch** (≤ N concurrent streams; each plan-chunk split into ≤ `chunk_split_bytes`
  sub-chunks so the dense ~1.70–2.00M "sandblasting" era can't blow memory or the deadline; retries
  resume from the last emitted height) → **scan** (`scan_cached_blocks`, optionally time-sliced
  sub-batches) → **persist** (sparse: decrypt feeds an in-memory `ShardTree`, flushed once per chunk;
  **write-behind** runs chunk N's commit overlapped with N+1's decrypt, strictly in-order) →
  **interleaved enhancement** every few chunks.
- final `run_enhancement`, then the `sync stage split` log line (the perf ground truth:
  total / fetch / scan / enhance + persist_wait / persist_overlap + `bound`).

Then `run_session` **follows**: jittered tip poll (10–30 s, anti-fingerprint) gated by a held
`GetMempoolStream` (0-conf detection), keyless catch-up passes — all transient-tolerant.

## What to scrutinize (the claims, with file refs)
- **Sparse persistence** (`persist.rs`; book `07-sparse-persistence`): the magnitude win — an in-memory
  `ShardTree` + **checkpoint-downgrade** replaces upstream's per-block SQLite tree I/O. Claim:
  byte-identical `data.db`. Kill switch `EngineConfig.sparse_persistence=false`.
- **Write-behind** (`persist.rs` lane / `WriteBehindFacade`): persist overlaps scan but stays
  **in-order + serial** ⇒ identical bytes at any `persist_depth` (default 1 = legacy strict backpressure).
- **Tor policy** (`connector.rs`; book `15-privacy`): mirrors the old SDK `ServiceMode` —
  **bulk `GetBlockRange` is direct even with Tor on** (volume; per-user exposure is identical with or
  without Tor — documented threat model), wallet-identifying metadata over **isolated** circuits.
  Bounded circuit-build + retry-on-fresh-circuit (anti-stall). Bootstrap **never** silently falls to direct.
- **Autonomous session** (`session.rs`, `ffi_handle.rs::spawn_supervised`): the initial pass never
  surfaces a hard error on a transient/transport fault (retries with backoff, shows Disconnected); the
  follow loop never Errors; a panic becomes `SyncState::Error(2)` via the supervisor, not a silent hang.
- **GPU combine** (`gpuhash/`): optional offload, default-off, KAT + oracle byte-identical.

## Correctness contract
Acceleration paths are **proven byte-identical** to upstream's audited `put_blocks`:
- `oracle.rs::semantic_diff` + the `cli oracle` subcommand (run A = upstream path, run B =
  sparse / write-behind / gpu) ⇒ `VERDICT IDENTICAL` on mainnet + synthetic data.
- Hermetic + darkside integration tests in `core/tests/` (reorg, spendability, truncate; book
  `13-correctness-oracle`).
- The engine decides **order, batching, persistence shape, and transport** — never the crypto.

## Host / FFI boundary
Host-agnostic. One entry: `session::run_session(SessionConfig, SessionReporter)`. Hosts consume a
**poll model** — `ffi_handle::SlipstreamHandle::snapshot()` + a drained event ring — with **no FFI
callbacks** across the language boundary. The C ABI and the Swift layer live in the **SDK** repo
(`ZcashLightClientKit`), a thin veneer over this crate; a new host (e.g. an Android JNI shim) is the
same thin veneer. No key custody lives here beyond UFVK import (keys are `zcash_keys`).

## Build / run / verify
```sh
cargo test -p slipstream-core -p slipstream-cli                 # the always-green gate
cargo run  -p slipstream-cli -- sync   --server <lwd> --wallet-dir <dir> --ufvk <ufvk> --birthday <h>
cargo run  -p slipstream-cli -- oracle --server <lwd> --wallet-a <a> --wallet-b <b> \
           --ufvk <ufvk> --birthday <h> --sparse-b --write-behind-b   # byte-identity → VERDICT IDENTICAL
```
Architecture prose: `docs/book/index.html`.

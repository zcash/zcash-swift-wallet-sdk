# Slipstream Tor Integration — Implementation Plan

> **For agentic workers:** execute T0→T6 task-by-task. Steps use checkbox (`- [ ]`) syntax.
> **Execution model (per user):** build **all of T0–T6 in one continuous pass** — do NOT stop for
> approval between tasks. Commit at each green rung (work + tests green + STATE.md update, per
> CONVENTIONS). The **one** stop-and-reassess gate is **T0's GO/NO-GO**: T1–T6 assume the clean
> "engine awaits arti directly" outcome; if T0 is NO-GO, stop and surface the runtime-bridge
> finding before continuing (the connector interface still holds; only `TorConn`'s internals change).

**Goal:** Slipstream syncs with Tor ON using the *same per-call Tor policy as the old SDK* —
bulk block download stays direct, wallet-identifying calls go over isolated Tor circuits —
preserving full sync speed and a byte-identical `data.db`.

**Architecture:** The engine gains a `Connector` that yields the existing `LwdClient`
(`CompactTxStreamerClient<Channel>`) and routes by *purpose*: bulk fetch → direct (always);
metadata → Tor (when on). The FFI's existing `TorRuntime` (arti, behind `zcashlc_tor_*`) is
threaded into the engine; no second Tor bootstrap. Tor changes *transport only* → the byte-identity
golden oracle and darkside oracles remain the correctness gate throughout.

**Tech stack:** Rust (edition 2024, 1.90), `tonic`/`CompactTxStreamerClient<Channel>`,
`zcash_client_backend`'s `tor` feature (already enabled) + arti via `rust/src/tor.rs`,
Swift `SlipstreamSynchronizer` + `SDKFlags.ifTor` + `ServiceMode`.

**Conventions:** LOCAL-ONLY (no push); branch `slipstream`; commit `[#1755] slipstream: <imperative>`;
no `unwrap`/`expect` outside tests; `tracing` not `println`; always-green =
`cargo test -p slipstream-core -p slipstream-cli` (+ `init-local-ffi.sh` full 3-slice + `swift test
--filter OfflineTests` when the FFI signature / outside-slipstream code changes); darkside serial +
feature-gated. **No push until T5 (Tor + full speed + byte-identical) is green.**

---

## Privacy rationale (the decisions this plan encodes)

- **Mirror, don't reinvent.** The old SDK's Tor setup was authored/reviewed by the person who drove
  Tor into the SDK (and wrote zallet's sync). zallet itself has no Tor (it talks to a loopback
  validator), so the old SDK is the sole reference. We replicate its `ServiceMode` choices exactly.
- **Bulk download is `.direct` — by the old SDK's design** (`BlockDownloader.swift:139,187`). So the
  4 parallel 10k fetch streams stay direct = full speed. Consequence: the user's IP + birthday are
  exposed on bulk download **exactly as today** (parity, no regression). Tor protects the
  *identifying* calls (txids, addresses, submit, treestate@birthday) via isolated circuits.
- **The fetch *pattern* (4×10k vs 100-batch) is a software fingerprint, not a user fingerprint.**
  It identifies the engine/version (shared by all Slipstream users — an anonymity-set label), not the
  person. Per-user signals (IP, birthday) are identical to the old SDK; no client user-agent/version
  header is sent (verified). So this plan introduces no new per-user de-anonymization.

## Mirror mapping (the spec — every gRPC call → its old-SDK `ServiceMode`)

| Call (engine unless noted) | Old-SDK mode | `ConnPurpose` |
|---|---|---|
| bulk `blockStream` (4 streams, `fetch.rs`) | `.direct` | `BulkFetch` |
| `getTreeState` (chunk boundaries + birthday) | `.uniqueTor` | `MetadataUnique` |
| `getLatestBlock` (tip probe / follow loop) | `.uniqueTor` | `MetadataUnique` |
| `getInfo` (server validation / preflight) | `.defaultTor` | `MetadataDefault` |
| `fetchTransaction` (enhance, **Swift** aux) | `.torInGroup(txid)` | (Swift `ifTor`) |
| `latestBlockHeight` (**Swift** aux) | `.uniqueTor` | (Swift `ifTor`) |
| `submit` (**Swift**, SDKBroadcaster) | `.uniqueTor` | already covered |

---

## T0 — Runtime-boundary spike (GO/NO-GO gate)

**The make-or-break unknown:** `rust/src/tor.rs` creates arti's `PreferredRuntime` and the existing
FFI dials with `runtime.block_on(...)` (tor.rs:96). The Slipstream engine runs in its **own tokio
runtime** and must `.await` connections. Can the engine open an isolated arti Tor lightwalletd
connection from *its* tokio context, or does arti pin to the runtime it was created on?

**Files:**
- Investigate: `rust/src/tor.rs`, the `zcash_client_backend::tor` module under `~/.cargo/registry/src/*/zcash_client_backend-0.23.*/src/tor*`, arti `Client` runtime bounds.
- Spike test: `slipstream/core/tests/tor_runtime_spike.rs` (feature `tor-spike`, `#[ignore]`).

- [ ] **Step 1 — read arti's runtime model.** Determine: is `zcash_client_backend::tor::Client`
  `Send + Sync`? Is `connect_to_lightwalletd` awaitable from an arbitrary tokio runtime, or does it
  require the `PreferredRuntime` it was built on? Record the answer (this picks the GO vs NO-GO branch).
- [ ] **Step 2 — write the live spike** (ignored, network + Tor required):
  ```rust
  // tests/tor_runtime_spike.rs
  #[tokio::test(flavor = "multi_thread")]
  #[ignore = "needs network + Tor bootstrap; run manually for the T0 gate"]
  async fn engine_tokio_can_drive_an_isolated_tor_lwd_conn() {
      // Build (or import) an arti client the same way rust/src/tor.rs does, then — from THIS
      // tokio runtime, with NO block_on — open an isolated connection and make one getTreeState.
      let client = build_tor_client_for_spike().await; // mirrors TorRuntime::create
      let isolated = client.isolated_client();
      let mut conn = isolated
          .connect_to_lightwalletd("https://zec.rocks:443".parse().unwrap())
          .await
          .expect("connect_to_lightwalletd over Tor from engine tokio");
      let ts = conn.get_tree_state(/* a known height */).await.expect("getTreeState over Tor");
      assert!(!ts.sapling_tree.is_empty());
  }
  ```
- [ ] **Step 3 — run it:** `cargo test -p slipstream-core --features tor-spike --test tor_runtime_spike -- --ignored --nocapture`
  - **GO:** the connection + `getTreeState` succeed from the engine's tokio runtime → `TorConn`
    (T1) holds the arti client and connects inline. Proceed continuously T1→T6.
  - **NO-GO** (nested-runtime panic / Send bound fails): **STOP, surface the finding.** The fix is a
    bridge — the FFI's arti runtime owns a small connection-service task; the engine requests
    connections over a channel (oneshot per connect). `TorConn` becomes that channel handle; the
    `Connector` interface (T1) is unchanged. Re-plan T1's internals only, then continue.
- [ ] **Step 4 — record** the GO/NO-GO + the chosen `TorConn` mechanism in STATE.md. Commit
  `[#1755] slipstream: T-Tor.0 runtime-boundary spike (GO|NO-GO: <mechanism>)`.

---

## T1 — `Connector` abstraction (engine, behind the verified T0 mechanism)

**Files:**
- Create: `slipstream/core/src/connector.rs`
- Modify: `slipstream/core/src/lib.rs` (add `mod connector;`), `slipstream/core/src/grpc.rs` (keep `connect` as the direct primitive)

- [ ] **Step 1 — failing test** (`connector.rs` `#[cfg(test)]`): a direct-only `Connector` returns a
  client for every purpose; a Tor `Connector` (with a stub `TorConn`) returns the **direct** path for
  `BulkFetch` and the **Tor** path for `MetadataUnique`/`MetadataDefault`. (Use a stub `TorConn` that
  records which method was called — no live Tor in unit tests.)
- [ ] **Step 2 — implement:**
  ```rust
  //! connector.rs — yields LwdClient honoring the old SDK's per-call Tor policy.
  use crate::{config::Endpoint, error::SlipstreamError, grpc::{self, LwdClient}};

  /// Why a connection is opened — picks direct vs Tor, mirroring the old SDK's ServiceMode.
  #[derive(Clone, Copy, Debug, PartialEq, Eq)]
  pub enum ConnPurpose {
      /// Bulk compact-block download — ALWAYS direct (old SDK `blockStream` is `.direct`).
      BulkFetch,
      /// Wallet-identifying metadata (treestate, latest-block, tip) — isolated Tor (`.uniqueTor`).
      MetadataUnique,
      /// Server validation / getInfo — default Tor circuit (`.defaultTor`).
      MetadataDefault,
  }

  #[derive(Clone)]
  pub struct Connector {
      endpoint: Endpoint,
      tor: Option<TorConn>, // None => Tor off => all direct
  }

  impl Connector {
      pub fn direct(endpoint: Endpoint) -> Self { Self { endpoint, tor: None } }
      pub fn with_tor(endpoint: Endpoint, tor: TorConn) -> Self { Self { endpoint, tor: Some(tor) } }

      pub async fn connect(&self, purpose: ConnPurpose) -> Result<LwdClient, SlipstreamError> {
          match (&self.tor, purpose) {
              (None, _) | (Some(_), ConnPurpose::BulkFetch) => grpc::connect(&self.endpoint).await,
              (Some(t), ConnPurpose::MetadataUnique) => t.connect_isolated(&self.endpoint).await,
              (Some(t), ConnPurpose::MetadataDefault) => t.connect_default(&self.endpoint).await,
          }
      }
  }
  ```
  `TorConn` is the T0-resolved handle (GO: wraps the arti client, `connect_isolated` =
  `client.isolated_client().connect_to_lightwalletd(...).await`; NO-GO: a channel handle to the
  FFI's connection-service). Both expose `connect_isolated`/`connect_default -> Result<LwdClient, _>`.
- [ ] **Step 3 — verify:** `cargo test -p slipstream-core connector`
- [ ] **Step 4 — commit** `[#1755] slipstream: T-Tor.1 Connector abstraction (direct + Tor, purpose-routed)`.

---

## T2 — Route the metadata call sites through the `Connector`

**Files:** `slipstream/core/src/engine.rs` (probe_tip :112, run setup :171), `slipstream/core/src/scan.rs` (chunk-boundary treestate prefetch ~:323), any `getInfo` preflight. Thread a `Connector` (built at run start from `config.endpoint` + optional `TorConn`) to replace the bare `grpc::connect(&config.endpoint)` calls **at metadata sites only**. **Bulk fetch (`fetch.rs`) stays `grpc::connect` / `BulkFetch` — unchanged.**

- [ ] **Step 1 — failing test:** a run driven with a `Connector::with_tor(stub)` records that
  treestate + tip-probe used the Tor path while the bulk fetch used direct. (Inject the stub
  `TorConn` via the run entrypoint.)
- [ ] **Step 2 — implement:** replace metadata-site `grpc::connect(&config.endpoint)` with
  `connector.connect(ConnPurpose::MetadataUnique)` (treestate, tip) / `MetadataDefault` (getInfo);
  pass `connector` down the run/scan call chain. Leave fetch.rs on `BulkFetch`/direct.
- [ ] **Step 3 — verify byte-identity (Tor-off path unchanged):**
  `cargo test -p slipstream-core` + the hermetic oracle `cargo test -p slipstream-core oracle`.
- [ ] **Step 4 — commit** `[#1755] slipstream: T-Tor.2 route metadata calls via Connector (bulk stays direct)`.

---

## T3 — FFI wiring: hand the engine the Tor handle

**Files:** `rust/src/lib.rs` (`zcashlc_slipstream_open`/`zcashlc_slipstream_start`), `rust/src/ffi_handle.rs` (`SlipstreamHandle`), `rust/src/tor.rs` (expose an isolated-client/`TorConn` accessor), `slipstream/core/src/engine.rs` (run entrypoint accepts the optional `TorConn`), `Sources/.../Slipstream/SlipstreamEngine.swift`.

- [ ] **Step 1 — failing test** (Rust, FFI-level or handle-level): opening a handle with Tor enabled
  stores a `TorConn`; `start` builds a `Connector::with_tor`; Tor-disabled builds `Connector::direct`.
- [ ] **Step 2 — implement:** `zcashlc_slipstream_open` gains a `tor_runtime: *const tor::TorRuntime`
  (or a bool + the existing global Tor handle); store an isolated `TorConn` on `SlipstreamHandle` when
  non-null. `zcashlc_slipstream_start` builds the `Connector` accordingly and passes it into the
  engine run. Regenerate the header (cbindgen) — `make` / build.rs.
- [ ] **Step 3 — verify:** `cargo build -p libzcashlc` + header diff shows the new param; `cargo test`.
- [ ] **Step 4 — commit** `[#1755] slipstream: T-Tor.3 FFI passes the Tor handle into the engine`.

---

## T4 — Swift `SlipstreamSynchronizer`: honor Tor on aux calls + pass the flag

**Files:** `Sources/ZcashLightClientKit/Slipstream/SlipstreamSynchronizer.swift` (the `.direct` aux calls :609, :807, :824; engine open/start), `Sources/.../Slipstream/SlipstreamEngine.swift`.

- [ ] **Step 1 — failing test** (OfflineTests, mocked service): with `torEnabled = true`,
  `latestBlockHeight` is called with `.uniqueTor` and `fetchTransaction` with `ifTor(.txIdGroup(...))`
  (not `.direct`).
- [ ] **Step 2 — implement:** flip `mode: .direct` → `await sdkFlags.ifTor(.uniqueTor)` for
  `latestBlockHeight`; `fetchTransaction` → `await sdkFlags.ifTor(ServiceMode.txIdGroup(prefix:"fetch", txId:))`
  (mirror `SDKSynchronizer:1117`). Pass `torEnabled` (+ the Tor handle) into `engine.open/start`.
- [ ] **Step 3 — verify:** `swift test --filter OfflineTests`.
- [ ] **Step 4 — commit** `[#1755] slipstream: T-Tor.4 SlipstreamSynchronizer aux calls honor Tor`.

---

## T5 — Tor integration test + acceptance (the real gate)

**Files:** `slipstream/core/tests/tor_integration.rs` (feature-gated, `#[ignore]`), STATE.md.

- [ ] **Step 1 — integration test** (ignored; network + Tor): run a bounded sync with Tor ON and assert
  (a) the bulk stream connected **direct**, (b) treestate/tip used **Tor** (observable via a logging
  hook or a Tor-only endpoint), (c) the resulting `data.db` is **byte-identical** to a Tor-off run over
  the same range (reuse the `semantic_diff` oracle).
- [ ] **Step 2 — run the full gate ladder:** `cargo test -p slipstream-core -p slipstream-cli`;
  `cargo clippy` (default + `gpu`); darkside serial `--ignored --test-threads=1` (no-regression,
  transport-only); the mainnet tip−N oracle (`--sparse-b --write-behind-b`) VERDICT IDENTICAL; bump
  `ENGINE_BUILD` (engine.rs) → `2026-06-17.tor`; full `./Scripts/init-local-ffi.sh` (3 slices) +
  header freshness; `swift test --filter OfflineTests`.
- [ ] **Step 3 — device acceptance ([needs-user]):** Zodl with **Tor ON** → full-speed sync (the
  12×, not degraded), and the metadata calls visibly over Tor in the log; **Tor OFF** unchanged.
- [ ] **Step 4 — commit** `[#1755] slipstream: T-Tor.5 Tor integration test + acceptance (byte-identical, full speed)`.

---

## T6 — Docs

**Files:** `docs/slipstream/book/15-privacy.html` + `book/04-integration.html` (the Tor model: mirror
the old SDK, bulk-direct rationale, the per-call mapping, the parallelism-is-a-software-fingerprint
note), `docs/slipstream/STATE.md`, `CHANGELOG.md`/`MIGRATING.md` if the FFI signature changed.

- [ ] **Step 1** — write the privacy/integration doc updates (this plan's "Privacy rationale" +
  "Mirror mapping" are the source).
- [ ] **Step 2 — commit** `[#1755] slipstream: T-Tor.6 docs — Tor model + privacy parity`.

---

## Acceptance (the whole feature)

1. Tor OFF → byte-identical + full speed (unchanged). Tor ON → byte-identical + full speed; only the
   identifying calls traverse Tor (isolated circuits), bulk stays direct — **privacy parity with the
   old SDK**.
2. All gates green at T5 (cargo + clippy + darkside no-regression + mainnet oracle IDENTICAL +
   OfflineTests + 3-slice rebuild).
3. Device: Zodl Tor-ON syncs at Slipstream speed (the goal: fast *regardless* of Tor choice).
4. **Only then** is the no-push hold lifted.

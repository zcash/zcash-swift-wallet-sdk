# Orchestration Lift — make Slipstream a fully-autonomous sync engine (design)

> Brainstormed + approved 2026-06-17 (user chose **Approach A**: lift now, before publish, reuse the
> existing engine types as the reporting sink). Tracking issue **#1755**, branch `slipstream`, LOCAL-ONLY.
> Companion plan: `plans/2026-06-17-orchestration-lift-plan.md`.

## Goal

Move the sync **session orchestration** — resilient Tor bootstrap, the resilient initial pass, the
tip-following loop, mempool monitoring, the pass-retry ladder, and the jitter/backoff helpers —
out of the FFI crate (`rust/src/lib.rs`, `sync_body`) and the CLI (`slipstream/cli/src/main.rs`,
its own `--follow` loop) **into `slipstream-core`** as a single reusable entry point,
`session::run_session`. After this, **any** host (the iOS FFI, a future Android FFI, the CLI,
zingo, zallet) drives a complete, privacy-correct sync by calling **one function** instead of
re-implementing the loop.

**This is an internal relocation. Behaviour and on-disk bytes do not change.**

## Why (the stakes — recorded so the decision is legible later)

1. **The orchestration is privacy + resilience POLICY, not plumbing.** It encodes: jittered poll
   cadence (defeats a timing fingerprint), **never fall back to direct on Tor failure** (a direct
   fallback silently de-anonymises), isolated circuits for metadata + direct bulk, T8.7
   "never surface a transient error to a foreground wallet", the panic→Error supervisor, and
   mempool-failure-is-non-fatal. If every consumer re-implements the loop, **they can get these
   wrong** (an Android dev who falls back to direct de-anonymises users and never knows). Lifting
   puts those decisions in **one audited place**.
2. **Android is a first-class consumer (user: "Android is 100%").** It must be able to adopt the
   engine as easily as possible — a thin JNI veneer that calls `run_session` and polls a snapshot,
   re-implementing **none** of the orchestration.
3. **Credibility / pre-empts the obvious review feedback** ("why isn't it autonomous? Android has
   to redo the loop"). A reviewer wants the privacy-critical loop in the engine, not copy-pasted
   per host.
4. **Removes real duplication.** The CLI already has its own `--follow` loop — and it gets the
   resilience **wrong** (`std::process::exit(1)` on a follow-pass failure, main.rs:424; a real
   wallet must never die on a follow blip). It is a live example of the hazard in (1).

**Honest non-goal: this does NOT increase sync speed.** The orchestration is the session lifecycle
*around* the passes; it is not in the per-pass hot path. The 12× and the 90s/276k device run are
the pass algorithm (scan-bound, in `scheduler`/`scan`/`persist`), untouched here. The remaining
speed lever is the parked decrypt/work-reduction spike, unrelated to this change.

## Current state (verified 2026-06-17)

- **Already in `slipstream-core` (`ffi_handle.rs`):** `SlipstreamHandle` (runtime + the 3 Arcs +
  AbortHandle + endpoint/db/network/total_memory), `SyncState`, the `repr(C)` `FfiSlipstreamSnapshot`
  + `FfiSlipstreamEvent`, `spawn_supervised` (panic→Error supervisor + abort handle), `snapshot()`,
  `push_event`, `EVENT_RING_CAP`. **And `events.rs` `Progress`, `connector.rs` `TorConn` (the Tor
  mechanism), `engine.rs` `sync_once`/`probe_tip`/`should_resync`, `mempool.rs` `run_session`.**
- **In the FFI (`rust/src/lib.rs`) — the glue to be lifted:** `sync_body` (the async orchestration
  block), `run_pass_with_retry`, `push_ring_event`, `sync_retry_backoff`, `follow_poll_jitter`,
  `pass_retry_sleep`, `should_retry`, the constants (`FOLLOW_POLL_MIN_SECS`/`MAX_SECS`,
  `FOLLOW_FAILURE_CAP`, `MEMPOOL_FAILURE_CAP`, `PASS_RETRY_MAX`), and the `slipstream_retry_tests`
  module. **All host-agnostic Rust that merely consumes the engine types above.**
- **In the CLI:** a bespoke, simpler (and resilience-incorrect) `--follow` loop.

So "the orchestration lives at the SDK level" is really "~250 lines of host-agnostic loop logic sit
in the FFI crate, calling an engine that already owns every type the loop touches." The lift is
mostly **relocation into the crate that already owns the parts.**

## Target architecture

New module **`slipstream/core/src/session.rs`** (`pub mod session;` in `core/src/lib.rs`,
re-exported at the crate root). Public surface:

```rust
/// Per-session configuration: the per-pass engine config + optional account import + optional Tor.
#[derive(Clone, Debug)]
pub struct SessionConfig {
    pub engine: EngineConfig,
    /// Some((ufvk, birthday)) imports on the initial pass if the wallet has no account;
    /// None = already imported. Follow passes are always keyless regardless.
    pub account: Option<(String, u64)>,
    /// Some routes metadata over isolated Tor circuits (bulk stays direct); None = all direct.
    pub tor: Option<TorSessionConfig>,
}

/// Tor session policy. The HOST decides `dangerously_trust_everyone` (true on sandboxed app
/// dirs: iOS, Android) — keeps the engine host-agnostic (no `cfg!(target_os=...)` in core).
#[derive(Clone, Debug)]
pub struct TorSessionConfig {
    pub dir: std::path::PathBuf,
    pub dangerously_trust_everyone: bool,
}

/// The reporting sink: the host's shared progress/state/event handles — the EXACT types the FFI
/// handle already owns. Hosts read them via the existing poll-based snapshot()/drain model, the
/// easiest shape for iOS AND Android JNI (no FFI callbacks across the boundary).
#[derive(Clone)]
pub struct SessionReporter {
    pub progress: std::sync::Arc<crate::events::Progress>,
    pub state: std::sync::Arc<std::sync::Mutex<crate::ffi_handle::SyncState>>,
    pub events: std::sync::Arc<std::sync::Mutex<Vec<crate::ffi_handle::FfiSlipstreamEvent>>>,
}
impl SessionReporter {
    pub fn set_state(&self, s: SyncState);            // lock + write
    pub fn push_event(&self, e: FfiSlipstreamEvent);  // cap-then-push at EVENT_RING_CAP
}

/// Run a full sync session: resilient Tor bootstrap (never falls back to direct) → resilient
/// initial pass (T8.7) → tip-following loop with mempool monitoring, until the future is dropped
/// or aborted. Returns only if the initial pass hits a NON-transient error (after surfacing
/// Error to the reporter — exactly today's behaviour). On success it never returns (it follows).
pub async fn run_session(config: SessionConfig, reporter: SessionReporter);
```

Plus the lifted private items (`run_pass_with_retry`, `sync_retry_backoff`, `follow_poll_jitter`,
`pass_retry_sleep`, `should_retry`, the constants) and their unit tests — **moved verbatim** so
they keep passing. The follow loop's `rand::random::<f64>()` calls run in core (`rand` is already a
`slipstream-core` dep — no new dependency).

### Host wiring after the lift

- **iOS FFI (`rust/src/lib.rs`) — thin C-ABI veneer:** `zcashlc_slipstream_start` parses the C
  pointers, builds `EngineConfig` (with `scaled_for_device_memory` + the `gpu` env read), wraps it
  in `SessionConfig` (`tor: tor_dir.map(|dir| TorSessionConfig { dir, dangerously_trust_everyone:
  cfg!(target_os = "ios") })`), builds a `SessionReporter` from the handle's Arc clones, and
  `h.task = Some(spawn_supervised(&h.runtime, session::run_session(cfg, reporter), sup_state,
  sup_events))`. `open`/`stop`/`snapshot`/`drain_events`/`free`, the `SlipstreamHandle` newtype, and
  the `repr(C)` structs are **unchanged**.
- **CLI (`slipstream/cli/src/main.rs`):** one-shot `sync` (no `--follow`) keeps calling `sync_once`
  (it wants a single pass + the detailed report + exit). `sync --follow` calls `run_session`
  (with `tor: None`), **deleting the bespoke loop** — the CLI now demonstrates the engine's real,
  correct resilient behaviour. `cmd_oracle` is untouched (already uses `sync_once` directly).
- **A future Android FFI:** a JNI veneer that mirrors the iOS one — open a handle, call
  `run_session`, poll `snapshot()`, drain events. Re-implements only JNI marshalling.

## What is unchanged (the contract)

- **The C header `zcashlc.h`** — same six `zcashlc_slipstream_*` functions, same signatures →
  cbindgen output identical → **no Swift changes**.
- **The on-disk `data.db` bytes** — `run_session` drives the same `sync_once`; the pass logic
  (`scheduler`/`scan`/`persist`/`enhance`) is untouched. The mainnet/darkside/hermetic oracles stay
  **IDENTICAL by construction** (the orchestration never runs during an oracle sync — oracle =
  keyless `sync_once`, no handle/follow/mempool).
- **Observable FFI semantics** — state codes (0/1/2/3), event tags (1/3/4), snapshot fields, the
  supervisor's panic→Error(2), `stop()`/`free()` abort — all preserved (the logic moves verbatim;
  the abort seam stays because `spawn_supervised` is already engine-side).

## Risk register (honest)

| # | Risk | Severity | Mitigation |
|---|------|----------|------------|
| 1 | **Lifecycle regression** (abort/cancel, state transitions, supervisor interaction) — NOT caught by the byte oracle (bytes don't change) | High | Verbatim move; keep the `ffi_handle` supervisor tests; **`[needs-user]` device re-validation** is the real gate |
| 2 | CLI `--follow` output format changes (now ticker + engine tracing, not bespoke per-pass prints) | Low | Dev aid only ("for observing follow behaviour"); the engine's own stage-split log is richer |
| 3 | `tor_dangerously` must stay correct once host-parameterised | Low | FFI passes `cfg!(target_os = "ios")` (== today's `#[cfg]`); unit-trivial |
| 4 | `rand` in core | None | Already a `slipstream-core` dep (0.8); used in `persist`/`wallet_session` |

## Test strategy

- The lifted pure-fn tests (`sync_retry_backoff`, `follow_poll_jitter`, `should_retry`, the cap/
  constant sanity tests) move into `session.rs`'s test module — same assertions, keep passing.
- New hermetic unit tests for `SessionReporter::{set_state, push_event}` (state write; cap-then-push
  at `EVENT_RING_CAP`).
- Existing `ffi_handle` tests (supervisor panic→Error, cancel-ignored, ring cap, snapshot) stay.
- `swift test --filter OfflineTests` must stay green (the C ABI is unchanged but `rust/src/lib.rs`
  is touched → CI-parity gate).
- The follow loop itself is not hermetically unit-testable (it loops forever); covered by the pure
  helpers + the supervisor tests + the device re-validation.

## Gates (per CONVENTIONS)

- `cargo test -p slipstream-core -p slipstream-cli` before/after every rung.
- `clippy` clean — default **and** `--features gpu`.
- `rust/src/lib.rs` is outside `slipstream/` → `./Scripts/init-local-ffi.sh --macos-only` +
  `swift test --filter OfflineTests` at the FFI rung. **Then a full `./Scripts/init-local-ffi.sh`
  (all 3 slices) at the end** — `--macos-only` clobbers the iOS slices the device test needs.
- `ENGINE_BUILD` bump → `2026-06-17.session` (lets the device log prove the lifted build is running).
- STATE.md updated in the same commit as each rung (resumability).
- **`[needs-user]` device re-validation** (Tor-ON full-speed restore, log shows
  `engine_build=2026-06-17.session` + `slipstream Tor bootstrapped`) — the publish gate, unchanged.
- Mainnet/darkside oracles: IDENTICAL by construction; run if a machine/server is available, else
  noted as re-validation (not skipped-by-guess).

## Rung staircase (detail in the plan)

1. **R1** — `session.rs`: lifted private machinery (helpers + constants + `run_pass_with_retry`) +
   `SessionReporter` (+ its tests) + the moved pure-fn tests. `pub mod session;` + re-exports.
   (FFI/CLI still have their copies — transient, compiles, both green.)
2. **R2** — `run_session` + `SessionConfig`/`TorSessionConfig` in `session.rs` (the lifted loop).
3. **R3** — rewire the FFI `start` to `spawn_supervised(run_session(...))`; **delete** the FFI's
   `sync_body` + helpers + constants + `slipstream_retry_tests`; bump `ENGINE_BUILD`;
   `init-local-ffi.sh --macos-only` + OfflineTests.
4. **R4** — rewire CLI `--follow` to `run_session`; delete the bespoke loop.
5. **R5** — clippy (both features), full 3-slice `init-local-ffi.sh`, STATE.md + Decision Log final;
   hand off the `[needs-user]` device re-validation.

## Decision Log 2026-06-17-orchestration-lift

Approach A chosen over (B) publish-now-lift-later and (C) a new `SyncObserver` trait. Rationale:
the engine already owns the state/event/handle types, so reusing them as the reporting sink is the
**lowest-risk** lift **and** the **easiest** for both iOS and Android (polling beats FFI callbacks
across a language boundary). A `SyncObserver` trait (C) is a possible later polish but adds new
public surface for no near-term consumer. Held the publish until this lands + re-validates on device
(user: credibility + Android usability + avoiding hard review feedback justify waiting "a little
bit longer").

# Orchestration Lift — implementation plan

> Executes `plans/2026-06-17-orchestration-lift-design.md`. Issue **#1755**, branch `slipstream`,
> LOCAL-ONLY (no push). Each rung ends green (`cargo test -p slipstream-core -p slipstream-cli`) +
> a `[#1755] slipstream: <imperative>` commit that includes the STATE.md update.

**Always-green per rung:** `cargo test -p slipstream-core -p slipstream-cli`.
**FFI rung (R3) also:** `./Scripts/init-local-ffi.sh --macos-only` + `swift test --filter OfflineTests`.
**End (R5):** `cargo clippy` (default + `--features gpu`), full `./Scripts/init-local-ffi.sh` (3 slices).

---

## R1 — `session.rs` machinery + `SessionReporter` (no behaviour change anywhere)

**Files:** create `slipstream/core/src/session.rs`; modify `slipstream/core/src/lib.rs` (add
`pub mod session;` + re-exports).

- [ ] Create `session.rs` with a 4–6 line "why this exists" header.
- [ ] Move **verbatim** from `rust/src/lib.rs` into `session.rs` (as `pub(crate)`/private):
  constants `FOLLOW_POLL_MIN_SECS`, `FOLLOW_POLL_MAX_SECS`, `FOLLOW_FAILURE_CAP`,
  `MEMPOOL_FAILURE_CAP`, `PASS_RETRY_MAX`; fns `sync_retry_backoff`, `follow_poll_jitter`,
  `pass_retry_sleep`, `should_retry`, `run_pass_with_retry`. (Copy for now; deletion from lib.rs is R3.)
  - `run_pass_with_retry` keeps its signature: `(cfg: &EngineConfig, ufvk_ref: Option<(&str,u64)>,
    progress: &Arc<Progress>, tor: Option<&TorConn>) -> Result<SyncOutcome, SlipstreamError>`.
- [ ] Add `SessionReporter { progress, state, events }` (the 3 Arc types from `ffi_handle`/`events`)
  with `set_state(&self, SyncState)` (lock-and-write, poison-tolerant `unwrap_or_else(|p| p.into_inner())`)
  and `push_event(&self, FfiSlipstreamEvent)` (cap-then-push at `ffi_handle::EVENT_RING_CAP`,
  the exact `push_ring_event` logic).
- [ ] Move the pure-fn tests from `slipstream_retry_tests` (lib.rs) into `session.rs`'s `#[cfg(test)] mod tests`
  (verbatim: backoff grows+caps, jitter min/mid/near-max bounds, `should_retry` matrix, cap sanity).
  Add `reporter_push_event_caps_at_ring_cap` + `reporter_set_state_writes`.
- [ ] `core/src/lib.rs`: `pub mod session;` (after `pub mod scheduler;`) and
  `pub use session::{run_session, SessionConfig, SessionReporter, TorSessionConfig};`
  (run_session/SessionConfig land in R2 — add those two re-exports in R2 to keep R1 compiling; in R1
  re-export only `SessionReporter`).
- [ ] **Green** `cargo test -p slipstream-core -p slipstream-cli`; **commit**
  `[#1755] slipstream: lift session machinery into core (R1 — helpers + SessionReporter)`.

## R2 — `run_session` + `SessionConfig`/`TorSessionConfig`

**Files:** modify `slipstream/core/src/session.rs`, `slipstream/core/src/lib.rs`.

- [ ] Add `SessionConfig { engine: EngineConfig, account: Option<(String,u64)>, tor: Option<TorSessionConfig> }`
  (`#[derive(Clone, Debug)]`) and `TorSessionConfig { dir: PathBuf, dangerously_trust_everyone: bool }`.
- [ ] Add `pub async fn run_session(config: SessionConfig, reporter: SessionReporter)` — the lifted
  `sync_body`, translated 1:1:
  - SyncStarted: `reporter.push_event(FfiSlipstreamEvent { tag: 1, value: 0 })`.
  - Tor bootstrap: if `config.tor` is `Some(t)`, the resilient `loop { TorConn::bootstrap(&t.dir,
    t.dangerously_trust_everyone).await }` (on transient err: `reporter.set_state(Idle)` +
    `sync_retry_backoff` sleep + retry forever; never direct fallback); else `None`.
  - Initial pass: the T8.7 resilient `loop` around `run_pass_with_retry(&config.engine,
    account.as_ref().map(|(s,h)| (s.as_str(), *h)), &reporter.progress, tor.as_ref())` —
    transient → `set_state(Idle)` + backoff + retry; non-transient → `set_state(Error(1))` +
    `push_event(tag:4,value:1)` + **return**.
  - On `Ok(outcome)`: `set_state(Done)` + `push_event(tag:3, value: outcome.enhance.txs_stored)`,
    then the follow loop verbatim (mempool-or-jitter-sleep head → `probe_tip` → `should_resync` →
    keyless `run_pass_with_retry` catch-up; `set_state(Syncing)` during a real pass, back to `Done`;
    all the T8.7 never-Error-on-follow + T8.2 non-fatal-mempool semantics).
  - Replace every `state.lock()...=` with `reporter.set_state(...)`, every `push_ring_event(&events,
    e)` with `reporter.push_event(e)`, `progress` with `reporter.progress`.
- [ ] `core/src/lib.rs`: add `run_session, SessionConfig, TorSessionConfig` to the `pub use session::{…}`.
- [ ] **Green**; **commit** `[#1755] slipstream: add engine-owned run_session (R2 — the lifted session loop)`.

## R3 — rewire the FFI; delete the lifted glue; bump ENGINE_BUILD

**Files:** modify `rust/src/lib.rs`, `slipstream/core/src/engine.rs` (`ENGINE_BUILD`).

- [ ] `engine.rs`: `ENGINE_BUILD = "2026-06-17.session"`.
- [ ] `rust/src/lib.rs` `zcashlc_slipstream_start`: keep the C-pointer parsing (ufvk, tor_dir) +
  the `EngineConfig` build (`scaled_for_device_memory` + the `#[cfg(feature="gpu")]` env read).
  Then:
  ```rust
  let account = ufvk_str.map(|s| (s, birthday_height));
  let tor = tor_dir_opt.map(|dir| slipstream_core::session::TorSessionConfig {
      dir, dangerously_trust_everyone: cfg!(target_os = "ios"),
  });
  let cfg = slipstream_core::session::SessionConfig { engine: cfg, account, tor };
  let reporter = slipstream_core::session::SessionReporter {
      progress: std::sync::Arc::clone(&h.progress),
      state: std::sync::Arc::clone(&h.state),
      events: std::sync::Arc::clone(&h.events),
  };
  let sup_state = std::sync::Arc::clone(&h.state);
  let sup_events = std::sync::Arc::clone(&h.events);
  h.task = Some(slipstream_core::ffi_handle::spawn_supervised(
      &h.runtime, slipstream_core::session::run_session(cfg, reporter), sup_state, sup_events));
  Ok(true)
  ```
- [ ] **Delete** from `rust/src/lib.rs`: `sync_body` (the whole async block in `_start`),
  `run_pass_with_retry`, `push_ring_event`, `sync_retry_backoff`, `follow_poll_jitter`,
  `pass_retry_sleep`, `should_retry`, the 5 constants, and the entire `slipstream_retry_tests`
  module (all now in `session.rs`). Remove now-unused `use` (e.g. the `SlipstreamCoreEvent` alias
  if no longer referenced). Keep `SyncState` import if still used (it is — `_start`/`_stop` set it).
- [ ] Keep unchanged: `open`/`stop`/`snapshot`/`drain_events`/`free`, `SlipstreamHandle` newtype,
  `repr(C)` structs, `install_slipstream_panic_hook`.
- [ ] **Green** `cargo test -p slipstream-core -p slipstream-cli`; then `cargo build -p libzcashlc`
  (compiles the FFI); then `./Scripts/init-local-ffi.sh --macos-only` + `swift test --filter OfflineTests`.
- [ ] **Commit** `[#1755] slipstream: rewire FFI to engine-owned run_session; delete lifted glue (R3)`.

## R4 — rewire CLI `--follow` to `run_session`

**Files:** modify `slipstream/cli/src/main.rs`.

- [ ] In `cmd_sync`, the `if follow { … }` block (after the one-shot `sync_once` report): replace the
  bespoke initial-already-done + jittered probe/`sync_once` loop with a `run_session` call:
  build `SessionConfig { engine: cfg.clone(), account: None /* already imported by the one-shot */,
  tor: None }` and a `SessionReporter` whose `progress` is the CLI's existing ticker `Progress`
  (state/events = throwaway `Arc::new(Mutex::new(SyncState::Done))` / `Arc::new(Mutex::new(vec![]))`),
  then `slipstream_core::session::run_session(scfg, reporter).await` (runs until Ctrl-C; the ticker +
  the engine's `tracing` stage-split lines provide the observability the bespoke prints did).
  - Note: the one-shot pass already imported the account + printed the detailed report, so the
    follow phase is keyless — this avoids a double initial pass while keeping the nice one-shot report.
  - Delete the `FOLLOW_CLI_POLL_MIN/MAX` consts + the hand-rolled jitter/probe/exit(1) loop.
- [ ] One-shot `sync` (no `--follow`) and `cmd_oracle` unchanged.
- [ ] Keep the `sync_follow_flag_parses` test (parse-only, still valid).
- [ ] **Green** `cargo test -p slipstream-core -p slipstream-cli`; **commit**
  `[#1755] slipstream: CLI --follow uses engine run_session (R4 — drop the duplicate loop)`.

## R5 — final gates + handoff

- [ ] `cargo clippy -p slipstream-core -p slipstream-cli` (default) **and** `--features gpu` — zero warnings.
- [ ] `cargo clippy` on the FFI (`-p libzcashlc`) default + gpu — zero **new** warnings.
- [ ] Full `./Scripts/init-local-ffi.sh` (all 3 slices — restores the iOS slices `--macos-only`
  clobbered, so the device test has ios-device + ios-sim) → re-run `swift test --filter OfflineTests`.
- [ ] STATE.md: NEXT ACTION → "ORCHESTRATION LIFT COMPLETE; `[needs-user]` device re-validation
  (Tor ON, full speed, `engine_build=2026-06-17.session`) is the publish gate"; Decision Log entry;
  session-log rungs.
- [ ] **Commit** `[#1755] slipstream: orchestration lift complete (R5 — clippy + 3-slice + STATE)`.
- [ ] Report to the user: code-complete + green on all automated gates; the only remaining gate is
  the device re-validation, after which re-extract the standalone repo (now also has the lift) + push.

## Byte-identity argument (no oracle needed to believe it, but runnable)

`run_session` drives the same `sync_once`; the pass logic is untouched; the orchestration never
executes during an oracle run (oracle = keyless `sync_once`, no handle/follow/mempool). Therefore
`data.db` is byte-identical and the mainnet/darkside oracles stay IDENTICAL. Run them if a
server/machine is free; otherwise they are re-validation, not a blocker (documented, not skipped-by-guess).

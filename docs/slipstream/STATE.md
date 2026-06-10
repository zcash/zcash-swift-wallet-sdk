# Slipstream — Living State

> **THE first file every session reads. THE last file every session updates (in the same commit as the work).**
> Format rules: append, don't rewrite history. Keep "NEXT ACTION" accurate above all else.

## NEXT ACTION

➡️ **T0.4** — CLI scaffold. Detailed steps: docs/slipstream/plans/2026-06-10-phase-0-foundation.md, Task 0.4.

## Current phase: P0 — Foundation

| Task | Status | Session notes |
|---|---|---|
| T0.1 branch + issue + machinery | done | |
| T0.2 cargo workspace + FFI-scripts verify | done | `rebuild-local-ffi.sh` line 97 runs bare `cargo build --target ... --release` from repo root — with workspace this builds all members for the target, but slipstream crates are std-only so no issue; no script pinning needed. cargo test, cargo check, init-local-ffi --macos-only (~3 min incremental), OfflineTests (419/0 fail) all green. |
| T0.3 core domain types | done | |
| T0.4 CLI scaffold | todo | |
| T0.5 CLAUDE.md pointer + G0 gate | todo | |

## Gates & milestones

| Gate | Status | Evidence |
|---|---|---|
| G0 foundation green | ☐ | |
| G1 transport ≥2× single-stream | ☐ | |
| G2 scan core, ≥5× old SDK (CLI) | ☐ | |
| G3 engine-complete, differential parity | ☐ | |
| **M1 Zodl parity demo** | ☐ | |
| G5 ≤15 min / 1M on device | ☐ | |
| G6 kernel v2 (conditional) | ☐ | |
| M2 Android demo | ☐ | |

## Tracking issue

- GitHub issue: **#1755 — https://github.com/zcash/zcash-swift-wallet-sdk/issues/1755** (all commits use `[#1755] slipstream: <title>`)

## Decision log (append-only)

- 2026-06-10 — D1–D9 locked in ROADMAP.md (in-repo workspace; upstream-brain M1; unchanged data.db; additive Swift seam; CLI-first; keyless engine; engine-owned tokio runtime; poll-based FFI; branch/commit policy). Source: design sessions, `docs/SLIPSTREAM_DESIGN.md`, `docs/SYNC_PERFORMANCE_PROPOSAL.md`.
- 2026-06-10 — D9 amended per user: branch is **`slipstream`** (not `slipstream-proto`) in this repo; mirrored `slipstream` branch in Zodl iOS at P4. D1 amended: explicit containment rule (all work under `slipstream/` + `docs/slipstream/`; enumerated exceptions only).
- 2026-06-10 — Zodl iOS repo confirmed: `/Users/lukaskorba/Dev/Xcode/GitHub/LukasKorba/secant-ios-wallet` (remote `git@github.com:LukasKorba/zodl-ios.git`), read/write + git permission granted by user. Observed on feature branch `MOB-1125-implement-multi-currency-conversion-support`, clean tree — P4's `slipstream` branch must be cut from Zodl's main.

## Performance truth table

| Checkpoint | Machine/Device | Server | Range | Wall-clock | Bound | Date |
|---|---|---|---|---|---|---|
| (empty — first entry lands at T2.7 old-SDK baseline) | | | | | | |

## Blockers / needs-user

- (none) — Zodl repo access RESOLVED 2026-06-10: `…/secant-ios-wallet`, read/write + git granted.

## Session log (append one line per working session)

- 2026-06-10 — Planning session: ROADMAP, STATE, CONVENTIONS, Phase-0 plan created. No code yet.
- 2026-06-10 — Setup session: branch renamed to `slipstream`, Zodl repo path confirmed + permissions granted, containment rule made explicit. Ready to execute T0.1.
- 2026-06-10 — T0.1 done: branch `slipstream` created, tracking issue #1755, machinery committed.
- 2026-06-10 — T0.2 done: workspace conversion verified (cargo tests, cargo check, init-local-ffi --macos-only, OfflineTests all green).
- 2026-06-10 — T0.3 done: core domain types (config/error/events), 6 tests green.

# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- `zcashlc_get_transaction`, `zcashlc_free_transaction_data`, and `FfiTransactionData` expose the
  serialized bytes and expiry height available for any wallet-store transaction without depending
  on the transaction-history projection.
- Pool-migration (Orchard→Ironwood) FFI: 33 `zcashlc_migration_*` entry points with their
  `#[repr(C)]` return types and `zcashlc_free_migration_*` destructors, plus
  `zcashlc_ironwood_activation_height`. Each call takes the wallet-db path, a 16-byte account uuid
  and a network id, opens the wallet database and the account-keyed migration store, and reports
  failure through the thread-local last-error channel with `NULL` / `false` / `-1` sentinels. Two
  stable message prefixes name the actionable conditions: `MIGRATION_PLAN_STALE` and
  `MIGRATION_PROVING_UNAVAILABLE`.
  - State: `zcashlc_migration_advance_step` (drives upstream `advance_migration` and marshals its
    decision into `FfiMigrationAdvanceStep`, freed by
    `zcashlc_free_migration_advance_step`; `NULL` with no last error means no run is stored; the
    step discriminants are exported as `ZCASHLC_ADVANCE_STEP_*` constants; upstream `Reevaluate`
    and `Replan` map to the compatibility `_ATTEND` case; a `Prove` step's `kind_*` fields moved
    off the step itself onto `FfiProveTarget` rows — `prove_targets`/`prove_targets_len`, freed by
    the step's own destructor — one per transaction of the WHOLE provable batch upstream now
    serves in one call; `id` is `0` for `Prove`, the batch entries carrying their own; the step now
    also carries the engine's advisory OUTLOOK (upstream #2936, `Advance::next`) as
    `next_height`/`next_kind` — the earliest target height and kind of the migration's next
    serviceable work, assuming the served step is executed and recorded, `next_height = -1` when
    nothing is height-schedulable — with the kind exported as the `ZCASHLC_STEP_KIND_*` constants,
    a verbatim mirror of upstream `state::StepKind`), `_progress`,
    `_is_note_split_needed`, `_has_overdue_transfers`, and `_has_invalid_transfers` (true iff the
    NON-terminal stored run holds an engine-`Invalid` or expired-unmined transaction; a cancelled
    run answers `false`).
    `_advance_step` and `_has_overdue_transfers` take an
    `estimated_tip: i64` parameter (`-1` = disabled) evaluated under the upstream engine's
    `DuenessTargets` rule: the estimate may only ACCELERATE scheduled-height due-ness, expiry and
    boundary settledness stay on the SCANNED tip, and a broadcast whose expiry only the ESTIMATED
    target has passed is withheld (protective, reversible) without ever being treated as expired.
  - Sync scheduling: `zcashlc_migration_sync_wakeups` returns `FfiMigrationSyncWakeups` (freed by
    `zcashlc_free_migration_sync_wakeups`) — the stored run's minimal sync/proving wake-up schedule
    as of the scanned tip, jitter re-drawn on every call; `_block_rate_samples` returns
    `FfiBlockRateSamples` (freed by `zcashlc_free_migration_block_rate_samples`) — up to `window`
    most-recently-scanned `(height, header time)` rows, ascending, the raw input a wall-clock
    chain-tip estimator projects from (a missing wallet-database file, like a missing `blocks`
    table, is the benign empty answer, and a coerced read failure is logged rather than silent);
    both read-only/local-database-only. There is no repair entry point: every repair is the
    engine's, performed inside `advance_migration` — a funding note spent outside the migration is
    discovered by the satisfiability oracle from scanned wallet data, a recorded broadcast is
    promoted to mined, and a transaction this process submitted whose broadcast was never recorded
    (a crash, or a failed persist, between submitting and recording) is recognized by the id the
    engine derived when it BUILT it and promoted just the same.
  - Batching: `zcashlc_migration_batch_pczts_by_actions` (pure, no wallet database) splits an
    ORDERED array of transaction action-weights (16 per preparation, 3 per transfer) into signer
    sessions bounded by a caller-supplied action budget, returning `FfiMigrationBatchSizes` (freed by
    `zcashlc_free_migration_batch_sizes`) — the per-session transaction COUNTS, summing to the input
    length, for the caller to re-slice its own ordered PCZT array by.
  - Note split: `zcashlc_migration_prepare_note_split`, `_sign_note_split`. The latter's
    handback — the first note-split transaction, proved now and returned for immediate broadcast —
    goes through the same atomic broadcast seam as the delivery executor, so its artifact is
    likewise the finalized consensus transaction rather than a PCZT.
  - Proposal and commit: `zcashlc_migration_residual_after_migration`, `_propose_transfers`,
    `_sign_and_store_schedule`. Committing a plan is linear in the wallet's note count: the
    upstream `wallet::WalletMigration` adapter these calls run over snapshots its spendable-note
    selection per adapter (librustzcash #2946), and the FFI builds one adapter per call.
  - Proving: `zcashlc_migration_prove_transactions(ids, ids_len, max_proofs)` proves the
    transactions the caller NAMES — the batch a prior `_advance_step` returned as its PROVE step —
    and returns `FfiMigrationProveOutcome` (freed by `zcashlc_free_migration_prove_outcome`,
    `NULL` = error): `total_proved` plus `preparation_txids`/`preparation_txids_len`, a heap array
    of raw 32-byte txids naming THE PREPARATIONS IT PROVED and nothing else. A transfer's txid is
    never returned, because appearing in that array means "retrievable through
    `_take_preparation_by_txid`", and a transfer is delivered by the drive's BROADCAST instruction
    alone. Like the delivery executor it never cranks the
    engine: `advance_migration` is the top-level call, and there is no proving to do without an
    instruction saying what to prove. Per row, a transaction that is no longer `Signed` is a SKIP
    rather than an error (a stale instruction is safe — the engine re-offers un-recorded work on
    the next crank), as is one whose anchor is not yet scanned or retained; every successful proof
    persists through the store seam. `max_proofs <= 0` means unlimited, and a platform that
    serializes database access behind one actor can pass `1` and loop, chunking a sweep without
    re-cranking between chunks. Call it from the sync path.
  - Preparation retrieval: `zcashlc_migration_take_preparation_by_txid(txid_ptr)` serves the
    proved PREPARATION with that 32-byte raw txid, returning the same `FfiPreparedTransfer` the
    delivery executor does (freed by `zcashlc_free_migration_prepared_transfer`) — finalized
    consensus transaction bytes, the row's stored txid, and the ENGINE TRANSFER ID, so the caller
    closes the loop through the existing `_record_transfer_result` — the same `Proved -> Broadcast`
    mark the delivery executor's success path makes — with no identity of its own. A proved
    preparation is a complete PCZT and its submission is the platform's ORDINARY path, not the engine's delivery ceremony: preparations are ZIP 318-exempt, and the engine's
    contract is that a preparation is broadcast as soon as it is proved. The accessor IS the take
    seam, not a byte read — `txid -> row -> PoolMigrations::take_transaction_for_broadcast` in one
    database transaction, so the wallet's record binds AT RETRIEVAL and a crashed consumer
    re-retrieves the same bytes over the same record. It is PREPARATION-GATED: a transfer's txid
    is refused ("transfers are served by the drive's broadcast instruction alone"), bare, before
    the seam is reached, as an unknown txid is — both are questions about WHICH row was named, not
    about whether an artifact can be made servable, so neither carries
    `MIGRATION_PROVING_UNAVAILABLE`. The seam's own refusal of a non-`Proved` row remains the
    readiness gate. Retrieved-but-never-submitted is a bounded, engine-modelled state: the record
    is idempotent, the preparation carries a ZIP 203 expiry, and an unsubmitted row surfaces
    through the ordinary attention path once it expires. Submitted-but-never-marked is bounded
    too, and is the ACCIDENT rather than the ordinary path now that the caller marks: the engine
    promotes any in-flight transaction its scan sees mine, by the id it stored when it BUILT the
    transaction.
  - Delivery: `zcashlc_migration_take_broadcast_transaction` serves the transaction the caller
    NAMES — the instruction a prior `_advance_step` returned as its BROADCAST step. It never
    proves and never cranks the engine: `advance_migration` is the top-level call and every
    executor is subservient to it, so there is no broadcast to make without having first been
    instructed to make it, and the re-spread, the satisfiability verification and the dueness
    judgement all belong to that advance. Serving goes through the store's atomic broadcast seam
    (`PoolMigrations::take_transaction_for_broadcast`), which finalizes and extracts the
    transaction and records it in the wallet's own tables — raw bytes, sent outputs, input-spend
    marks, status-queue entry — in the same database transaction that hands the bytes back, so the
    wallet record binds at the broadcast attempt rather than after it. `FfiPreparedTransfer`'s
    `pczt`/`pczt_len` therefore carry the FINALIZED CONSENSUS TRANSACTION bytes, submittable as-is.
    The seam's own refusal of a row that is not `Proved` is the STALENESS GUARD — an instruction
    that went stale between the advance and the serve fails here rather than being acted on, and
    the caller discharges it by advancing again. `FfiPreparedTransfer` accordingly loses its
    `status` field and `FfiPreparedTransferStatus` is gone: an executor either serves or errors, so
    there is no "nothing due"/"awaiting proof" shape left to carry. WHETHER a missing proof is what
    blocks delivery is now reported on the advance step itself — each `FfiProveTarget` row gains a
    trailing `schedule_due` bool, true when the effective dueness target has already reached that
    transaction's scheduled height. Then `_record_transfer_result` (whose terminal tags — 2
    invalid, 3 expired — record `report_broadcast_failure` testimony stamped at the observed
    wallet tip; the next drive call adjudicates it through sqlite's satisfiability oracle, while
    unknown and already-mined rows remain no-ops), and `_record_immediate_run`, which records a
    send-max sweep built outside the engine.
  - Read-only reporting: the query that CANNOT drive the engine (it opens read-only connections
    and must not mutate) — `_has_overdue_transfers` — derives its answer from upstream's public
    per-row status view (`MigrationState::transaction_statuses`) instead of the exported
    broadcast/prove queue
    selectors. Only the DERIVATION moves; every answer is unchanged. The view agrees with the
    kernel's queues by construction and renders the doomed-broadcast withhold as neither ready nor
    actionable, so the protective withhold and the `Signed`/awaiting-signature exclusions hold
    exactly as before; and the engine's broadcast-before-prove precedence is preserved explicitly —
    the two-tier derivation takes the broadcast-ready `(scheduled_height, id)`-min first and reaches
    the still-unproved rows only when that tier is empty, exactly as upstream
    `MigrationState::next_step` consults its own two queues. What IS gone is the scratch-clone
    VIRTUAL PROVE behind `_has_overdue_transfers` (a
    `MigrationState` was cloned and every prove-ready row flipped `Proved` in memory, just to ask
    what would then be broadcastable): dependency readiness is keyed on `Mined`, never `Proved`, so
    proving can unblock nothing, and one pass per tier over the statuses gives the same answer the
    clone did. The ordering key within each tier is re-derived rather than read off the engine —
    the SDK's one accepted drift risk here, recorded on librustzcash #2938. It remains an
    ADVISORY display read: no store-oracle verification happens on it, so it never promises
    what the next delivery call will serve.
  - Recovery: `zcashlc_migration_restart_step`, and `_refresh_stale_transfers`, which rebuilds every
    expired transfer of the stored run and returns the full stored schedule, persisting
    all-or-nothing (NULL on any error).
  - External signer: `zcashlc_migration_create_unsigned_note_split_pczts`,
    `_store_signed_note_split_pczts`, `_create_unsigned_transfer_pczts`,
    `_store_signed_schedule_pczts`.
  - Residual locking: `zcashlc_migration_lock_residual` returns the total locked zatoshi (`0` is a
    valid "nothing was spendable"); `_unlock_residual` returns the cleared-output count.
  - Estimation: `zcashlc_migration_estimate_runs` returns `FfiMigrationRunEstimate` (a per-run
    `FfiRunEstimate` plus the final residual), freed by `zcashlc_free_migration_run_estimate`. A
    zero balance is the zero-run estimate, not an error. `FfiRunEstimate` gains trailing `actions`
    (the signing workload in Orchard-family actions: 16 per preparation transaction, 3 per transfer)
    and `keystone_rounds` (the Keystone-class signing-round count the optimal `MinRounds` packing
    computes for the run) fields.
  - Status: `zcashlc_migration_transaction_statuses` returns one row per committed migration
    transaction — stable id, kind, lifecycle state, scheduled/expiry/mined heights, the broadcast
    txid while in mempool, readiness, next action, blocking reason, the `depends_on` heap array of
    ids that must mine first, `anchor_boundary` (the bucketed boundary a TRANSFER's anchor was
    drawn against; `-1` always for a preparation), and a trailing compatibility `invalid_reason`.
    Upstream unsatisfiability marks and open broadcast-failure reports project to state `5` /
    blocker `6` without changing the Swift ABI — freed by
    `zcashlc_free_migration_transaction_statuses`. No stored run yields an empty container.
  - `FfiMigrationSchedule` gains a trailing `preparations`/`preparations_len` heap array of
    `FfiMigrationPreparationStep` (id, layer, index, broadcast height, and the whole preceding
    layer's ids as its `depends_on`) — the note-preparation transactions of the same plan, which the
    transfer rows alone do not surface.
- The echo parameters on the commit calls (`ids`, `amounts`, heights and duration on the schedule
  commits; `output_values` and `fee` on the note-split commit) are verified consent echoes, checked
  against the previewed plan or, once committed, the stored state. A mismatch surfaces
  `MIGRATION_PLAN_STALE`, so a stale or tampered display cannot sign values the user did not
  approve. Next-executable heights are compared only against the previewed plan; anchor heights are
  display-only.
- Every transfer amount the FFI reports is the value that CROSSES into Ironwood — one of the round
  `{1,2,5}×10ⁿ` denominations the run was planned in, and the amount the destination balance grows
  by — not the larger spend-side note value.
- Keystone batch-signing UR bridge:
  `zcashlc_migration_keystone_build_sign_batch_qr_parts` redacts each PCZT for the batch-signer role
  and returns animated `"zcash-sign-batch"` UR frames in `FfiKeystoneQrParts` (freed by
  `zcashlc_free_migration_keystone_qr_parts`), taking one ordered PCZT array with preparations first;
  `_keystone_reset_sign_batch_decoder` (void, infallible) and `_keystone_decode_sign_batch_part`
  (`FfiKeystoneBatchDecodeResult`, freed by
  `zcashlc_free_migration_keystone_batch_decode_result`) drive the multi-frame scan session and
  report the device's firmware version on completion, erroring on a request-id mismatch; and
  `_keystone_apply_batch_signatures` applies the response's signatures positionally to the caller's
  unsigned PCZTs, erroring if the counts disagree.
- `zcashlc_migration_create_unsigned_note_split_pczts` and `_create_unsigned_transfer_pczts` return
  PCZTs carrying the account's ZIP 32 spend derivation on every spend still awaiting a signature,
  across the Orchard and Ironwood bundles alike. Without it Keystone rejects the batch with "None of
  inputs belongs to the provided account". The migration engine stamps it during the build
  (`Committer::start` resolves the account derivation and both builders pass it to
  `build::finalize_pczt`), so these entry points marshal the engine's bytes through unmodified; an
  account whose ZIP 32 derivation the wallet does not know (a UFVK import made without one) yields
  unstamped PCZTs rather than an error from these calls.
- `Balance` (inside `FfiAccountBalance` / `FfiWalletSummary`) gains a trailing `locked_value` field,
  keeping "the sum of the fields is the account's total" true.
- `zcashlc_migration_propose_immediate_transfers` — briefly part of this unreleased cycle, never
  exposed through the Swift welding and removed again before release — is gone. The immediate
  (single-transaction) lane is built entirely on the general-purpose
  `zcashlc_propose_send_max_transfer` (called with `orchard_only: true`) instead, which the engine
  itself never touches.

### Changed
- The `zcashlc_voting_*` FFI is compiled again, against the Ironwood (NU6.3)
  dependency stack. It had been gated behind `#[cfg(zcash_voting)]` on the
  grounds that `zcash_voting` could not resolve against the Ironwood `orchard`
  release; that held for `zcash_voting 1.0.0`, which pins the pre-Ironwood
  librustzcash family, but not for `zcash_voting 2.0.0-rc.3`, which this crate
  now depends on directly from crates.io.

  Voting is compiled unconditionally rather than behind a Cargo feature. The
  Swift package cannot gate voting for its consumers, so a Rust-only feature
  would gate nothing reachable while leaving a bare `cargo build` producing a
  library the Swift layer could not link against.

  The FFI surface changed substantially, because `zcash_voting` absorbed
  orchestration this crate used to hand-roll and made the intermediate steps
  private:

  - Removed: `zcashlc_voting_build_vote_commitment`,
    `zcashlc_voting_sign_cast_vote`, `zcashlc_voting_build_share_payloads` and
    `zcashlc_voting_encrypt_shares`, all four superseded by the new
    `zcashlc_voting_commit_vote`; `zcashlc_voting_decompose_weight`, which has no
    upstream equivalent; `zcashlc_voting_get_delegation_submission` and
    `zcashlc_voting_get_delegation_submission_with_keystone_sig`, superseded by
    `zcashlc_voting_get_delegation_submission_with_signature`; and
    `zcashlc_voting_store_commitment_bundle`, superseded by
    `zcashlc_voting_record_vc_position`.
  - Added: `zcashlc_voting_commit_vote`,
    `zcashlc_voting_get_delegation_submission_with_signature`, and
    `zcashlc_voting_record_vc_position`.
  - Changed: `zcashlc_voting_db_open` takes a network id, fixing the voting
    network for the lifetime of the returned handle. A custom (regtest) network
    derives its voting identity from the registered base network, so a
    modified-mainnet chain votes with mainnet hotkeys and HRPs, and opening
    fails if that network was never configured. Because the handle carries it,
    `zcashlc_voting_init_round`, `zcashlc_voting_build_pczt`,
    `zcashlc_voting_commit_vote`, `zcashlc_voting_precompute_delegation_pir`
    and `zcashlc_voting_build_and_prove_delegation` no longer take a network
    id, and an unknown one is rejected once at open rather than by each call.
    `zcashlc_voting_init_round` still persists the round's network, so
    governance PCZT branch identifiers can be validated against it.
    `zcashlc_voting_generate_hotkey` drops its database and seed parameters and
    takes a network, because voting hotkeys are now app-owned random values
    rather than wallet-seed derivations; the caller must persist the returned
    stored secret. `zcashlc_voting_build_pczt` and
    `zcashlc_voting_build_and_prove_delegation` take a hotkey stored secret in
    place of a raw hotkey address, since delegation keys can only be
    constructed from a reconstructed hotkey. `zcashlc_voting_mark_vote_submitted`
    requires the cast-vote transaction hash.
    `zcashlc_voting_record_share_delegation` no longer accepts a nullifier,
    which the crate derives from the vote's recovery state so a caller cannot
    record one that disagrees with its share.
  - `FfiVotingHotkey` and `FfiBundleSetupResult` changed shape; the latter gained
    `dropped_count`, exposing notes the canonical bundling policy discarded.
- Migrated to `zcash_protocol 0.10.4`, `zcash_client_backend 0.24.0-rc.7`,
  `zcash_client_sqlite 0.22.0-rc.7`, `pczt 0.9.2`.
- The migration engine's wallet adapter is UPSTREAM's (`zcash_pool_migration::wallet::WalletMigration`
  plus `zcash_client_sqlite`'s account-scoped `PoolMigrations` store); the SDK's own fork of it is
  deleted. Three consequences reach behaviour rather than just code:
  - No migration type holds spend authority any more, and none can be given it. The adapter is
    built from the account's VIEWING key alone, and the engine's two signing entry points
    (`commit_preparation`, `rebuild_expired_transfer`) take an `orchard::keys::SpendingKey` per
    call — deriving its full viewing key and checking it against the account's stored one BEFORE
    building anything, refusing a foreign key with `CommitError::WrongSpendAuthority` /
    `RebuildError::WrongSpendAuthority` rather than silently signing nothing — so the FFI functions
    that sign pass the spending key they just decoded straight through and drop it with the call,
    instead of parking a `UnifiedSpendingKey` inside an adapter that mostly does not need one. The
    external-signer lanes are unchanged: they call the unsigned entry points, which take no
    authority at all.
  - The spendable-note snapshot that keeps a commit linear in the wallet's note count is
    upstream's own (librustzcash #2946) rather than an SDK mirror of it.
  - `PoolMigrationRead::mined_height` is answered by the adapter from the wallet's FULLY-SCANNED
    bound instead of being delegated to the store. The two agree on every value — the store
    applies the same rule at its own layer — so no answer changes; the store still answers
    directly on the paths that use it without an adapter.

  What remains SDK-side is the account's stored unified full viewing key: upstream's constructor
  takes the key from its CALLER (a wallet may hold several keys that view one account), and this
  SDK always supplies the one the account record holds, which is what lets an imported
  hardware-wallet account — whose spending key never exists on this device — plan, build and prove.
  A migration call against an account whose record holds no unified full viewing key now fails at
  the point the adapter is built rather than at the first key-dependent operation.
- `zcashlc_set_transaction_status` now returns `bool` (`true` on success) instead of `void`, so
  callers can detect a failed status write (previously any error — including an unknown chain
  height — was silently discarded). No `repr(C)` struct layout changes.
- `zcashlc_migration_state` is removed before any release exposed it, along with the state machine
  it served (`MigrationState`/`Complete`/`InProgress`/etc. never crossed the FFI as a stable shape).
  `zcashlc_migration_advance_step` replaces it: a verbatim, un-opinionated marshal of the upstream
  engine's own `next_step`, with no SDK-side derivation on top. `_progress` is otherwise unchanged
  in shape and keeps its own `is_immediate`-aware behavior: a mined immediate (send-max) run is
  consumed — it reports `is_present: false` and masks a stale engine `Complete`, so a host goes
  quiet once the sweep mines instead of reporting a per-run completion — while an unmined, unexpired
  immediate run still reports present with `is_immediate: true`. `FfiMigrationProgress` gains a
  trailing `is_immediate` boolean.
- The anchor bucket interval is selected per network: mainnet keeps the ZIP 318 144-block grid, while
  testnet and custom-parameter networks retain anchors every 12 blocks and compress the transfer and
  preparation delays by the same factor, so a migration crosses enough boundaries to be exercised in
  a test run. Nothing crosses the FFI for this — each wallet handle is opened with the interval its
  `network_id` selects — and a migration already in flight keeps the interval it was committed under.
- Note locks are owner-keyed: the residual lock is keyed to a deterministic per-account owner, which
  makes re-locking idempotent, and `zcashlc_migration_unlock_residual` still clears the account's
  locks wholesale.
- `zcashlc_migration_record_transfer_result`'s success tag no longer records the reported txid: the
  engine marks the broadcast under the id it derived when it built the transaction. The reported
  value is now CHECKED against that id, and a mismatch is an error — the two can differ only if the
  platform submitted something other than the artifact the engine handed it, which is worth naming
  rather than silently recording a broadcast of a transaction that was never sent.
- The migration store connection uses the same 15 s `busy_timeout` as the wallet handle, so a
  `zcashlc_migration_*` call racing an engine write waits for the lock instead of surfacing
  `database is locked` early.
- Terminal rejection evidence is reported to the upstream engine, whose satisfiability oracle
  returns `Reevaluate` or `Replan`; the FFI projects those onto its existing `Attend` case. The
  `ext_zcashlc_orchard_ironwood_migration_invalid_marks` extension table is retired: its schema
  migration is no longer registered. On the first migration call, surviving rejection rows are
  replayed at the current scanned height, funding-spent rows are left for the oracle to rediscover,
  and the table is dropped.
- The estimated-tip due-ness split is owned by the upstream engine (`DuenessTargets`) instead of
  hand-rolled SDK twins of the upstream predicates; behaviour additionally gains upstream's
  doomed-broadcast withhold (above).
- Which transaction each lane acts on is the engine's decision, not an SDK re-derivation, and it
  is made ONCE: `zcashlc_migration_advance_step` cranks `advance_migration`, and the two EXECUTORS
  — `_take_broadcast_transaction` and `_prove_transactions` — discharge the instruction it
  returned (see their entries above), so what they act on was verified against the store's
  satisfiability oracle before it was handed out. `_take_preparation_by_txid` is not a third
  executor but the retrieval half of the prove executor's own return: it acts only on a txid that
  return just named, and its gate refuses everything else. The READ-ONLY reporting query —
  `_has_overdue_transfers` — cannot drive,
  and reads the engine's public per-row status view instead; the SDK's hand-rolled twins of
  upstream's readiness predicates are gone, leaving only the `(scheduled_height, id)` ordering key
  that display read composes over the view. The note-split ceremony's immediate-broadcast pick
  reads the same view, so a resumed ceremony re-serves an already-proved, due preparation rather
  than proving another. The plan preview is likewise a READ of the engine's own
  `MigrationPlan::planned_transactions` enumeration — the same rows `commit_preparation` builds
  from — rather than a second derivation beside it: every preparation step's id, `layer`, `index`,
  `depends_on` and `broadcast_height`, and every transfer row's id and
  `next_executable_after_height`, come off that enumeration. A previewed row therefore describes
  exactly the transaction the commit will build, by construction rather than by two derivations
  agreeing; the values are unchanged (the enumeration's dependency and scheduling rules are the
  ones the preview used to reproduce by hand).
- Mined-transaction promotion is the upstream engine's: `advance_migration` sweeps every in-flight
  transaction and promotes the ones the wallet's scan has seen mine, so the drive path no longer
  reconciles first, and the read-only entry points reconcile through the engine's own
  `PoolMigrationRead::mined_height` rather than `WalletRead::get_tx_height`. That tightens the
  bound from the chain tip to the FULLY-SCANNED height — a promotion may not rest on a block
  outside the region a reorg truncation would roll back — and is the same bound the drive path
  promotes under, so a status read can no longer report `Mined` for a row `advance_migration`
  would refuse to promote.
- The five migration read entry points (`zcashlc_migration_transaction_statuses`,
  `zcashlc_migration_progress`, `zcashlc_migration_has_overdue_transfers`,
  `zcashlc_migration_has_invalid_transfers`,
  `zcashlc_migration_sync_wakeups`) now open the database read-only and report the persisted
  run without reconciling mined transactions first. Broadcast→Mined promotion is persisted by
  the write lanes (the advance-step engine sweep, the prove sweep, the delivery serves), which
  every live run drives at least once per open-lane pass, sync edge, and UI refresh; a read can
  therefore trail a just-mined broadcast by at most one such pass. Reads no longer contend with
  proving.

### Removed
- `zcashlc_migration_debug_reschedule_transfers` is removed. It was the only FFI entry point that
  wrote raw SQL directly against the engine-owned pool-migration tables, retro-compressing a
  committed schedule so its transfers become due in quick succession for manual broadcast testing.
  That testing purpose is now covered on the engine side by compressed test-network scheduling at
  commit time.
- `zcashlc_migration_pending_transfer_proposal` is removed, together with the standalone
  `zcashlc_free_migration_transfer_proposal` destructor that freed its answer. It was a
  KIND-FILTERED peek at the queue ("the next TRANSFER, specifically"), which the advance design
  makes a malformed question: any answer either masks imminent work of another kind or contradicts
  what the drive would serve. Its scheduling role belongs to `zcashlc_migration_advance_step`
  (whose outlook names the next serviceable work of ANY kind) and its display role to
  `zcashlc_migration_transaction_statuses` plus the schedule DTO. `FfiTransferProposal` itself
  stays — it is the row type of `FfiMigrationSchedule::transfers` — but is no longer handed out
  standalone.
- `zcashlc_migration_has_ready_broadcast` is removed. It had no consumer anywhere: the 2026-08-05
  D1 ruling deleted the sync gate's forward-looking clause, the only caller, and sync is now held
  only while a migration submission is in flight — never because a broadcast is expected in the
  future, and never for a fixed interval after one happened.
  `zcashlc_migration_has_overdue_transfers` — an honest "the delivery lane has actionable work"
  boolean, not a kind-filtered id peek — stays.
- `zcashlc_migration_extract_broadcast_tx` is removed. It had zero consumers, in the SDK or the
  app: every live flow receives already-finalized consensus transaction bytes from the store's
  atomic broadcast seam, never a PCZT that needs extracting. Its private helper,
  `migration_finalize::extract_tx`, goes with it — the FFI entry point was its only caller.

### Fixed
- `zcashlc_extract_and_store_from_pczt` now records the transaction's Ironwood
  outputs in the stored sent transaction. Every Ironwood output was previously
  omitted, so for a post-NU6.3 PCZT delivering its payment through the Ironwood
  pool the external recipient's address and the decrypted memo were never
  persisted (and are not otherwise recoverable), and wallet-internal Ironwood
  outputs were invisible to the wallet until the transaction was mined and
  scanned. Shielded sent outputs stored by this call are also now tagged with
  their note commitment tree, as the transaction-builder spend path already did.
- The migration prover's transient-vs-hard error classification (`ProveErrorClass::is_transient`,
  behind `zcashlc_migration_prove_transactions` / `_advance_step`): `UnknownSpentNote` (a
  late-mining dependency's note the wallet has not seen yet) and `Tree(ShardTreeError::Query(_))`
  (shard-tree query races during sync — this exact case crash-looped a prove batch on Android on
  2026-07-28) now correctly resolve as the transient "retry on a later sweep" outcome instead of a
  hard `MIGRATION_PROVING_UNAVAILABLE:` error; the non-query `Tree` variants (`Storage`/`Insert`)
  stay hard, since no amount of syncing repairs a failing persistence layer or a corrupt tree
  write, and every transient deferral is now logged with the row id (a stalled sweep was
  previously silent). `IronwoodTreeUnavailable` moves the other way, out of the transient set: the
  backend tracks no Ironwood commitment tree at all, which no amount of syncing ever produces, so
  treating it as transient could retry forever instead of surfacing the real condition.
- `zcashlc_get_memo` accepts the Ironwood output pool code (4); an Ironwood note id was rejected as
  an unrecognized shielded protocol.
- Due-ness and expiry are evaluated on the engine's target-height contract (`chain tip + 1`) in every
  read path, with the "never expires" case honoured. Transfers now become due and expire one block
  earlier, consistently, and a doomed transfer is no longer served for broadcast. This now includes
  the proving sweep — the one remaining raw-tip caller — so a preparation scheduled exactly at the
  target is offered for proving on the advance that sees it rather than one block late.
- An `estimated_tip` at or beyond `u32::MAX` saturates below the height ceiling instead of
  overflowing the `+ 1` target conversion.
- `FfiMigrationProgress.next_transfer_ready_at_height` reports the next transfer still awaiting
  broadcast rather than one already in the mempool.
- Transfer amounts are read from the engine's `crossing_values()` instead of being re-derived at
  three marshal sites. The values are identical by construction, so no reported number changes.

## 2.8.0-rc.2 - 2026-07-28

### Changed
- Migrated to `zcash_protocol 0.10.2`, `zcash_client_backend 0.24.0-rc.5`,
  `zcash_client_sqlite 0.22.0-rc.5`.
- `zcashlc_propose_transfer` and `zcashlc_propose_transfer_from_uri`: once NU6.3 is active, a single
  payment of a canonical ZIP 318 denomination crossing the Orchard turnstile is proposed as a
  canonical crossing — one fewer ZIP 317 marginal-fee action, and up to two anchor-bucket intervals of
  additional confirmations on its inputs beyond `confirmations_policy`. A payment that cannot be
  funded that way is proposed as an ordinary transaction.
- `zcashlc_init_data_database` applies new migrations that repair the data described under Fixed
  below. No rescan is required.

### Fixed
- Ironwood notes received on an account's internal address are classified as change, so
  `v_transactions.has_change` and `v_tx_outputs.is_change` no longer present an account's own change
  as a recipient of its transaction. Balances were unaffected.
- An address that had received only Ironwood notes is treated as used, so
  `zcashlc_get_next_available_address` no longer hands it out again and the receiving account is
  reported as involved in the transaction that paid it.
- The funding account recorded for a transparent output counts value spent from the Ironwood pool, so
  an output funded entirely from Ironwood is attributed to the funding account and one funded from
  several pools to its largest contributor.
- `zcashlc_transaction_data_requests` derives status requests from durable observation intent: a sent
  transaction is queried by txid when the wallet cannot observe one of its shielded spends or outputs,
  intent sleeps while a transaction is mined and revives after a rewind, and redundant requests for
  wallet-observable transactions are no longer produced.
- The Tor HTTP and gRPC transports bound each network operation, so `zcashlc_get_exchange_rate_usd`,
  `zcashlc_tor_http_get` / `_post` and the `zcashlc_tor_lwd_conn_*` calls fail with an error instead
  of hanging against a server that accepts a connection and then never responds. They also reject a
  URL whose scheme is neither `http` nor `https`, which was previously treated as plaintext HTTP.

## 2.7.0-rc.3 - 2026-07-28

### Changed
- Migrated to `zcash_protocol 0.10.2`, `zcash_client_backend 0.24.0-rc.5`,
  `zcash_client_sqlite 0.22.0-rc.5`.
- `zcashlc_propose_transfer` and `zcashlc_propose_transfer_from_uri`: once NU6.3 is active, a single
  payment of a canonical ZIP 318 denomination crossing the Orchard turnstile is proposed as a
  canonical crossing — one fewer ZIP 317 marginal-fee action, and up to two anchor-bucket intervals of
  additional confirmations on its inputs beyond `confirmations_policy`. A payment that cannot be
  funded that way is proposed as an ordinary transaction.
- `zcashlc_init_data_database` applies new migrations that repair the data described under Fixed
  below. No rescan is required.

### Fixed
- Ironwood notes received on an account's internal address are classified as change, so
  `v_transactions.has_change` and `v_tx_outputs.is_change` no longer present an account's own change
  as a recipient of its transaction. Balances were unaffected.
- An address that had received only Ironwood notes is treated as used, so
  `zcashlc_get_next_available_address` no longer hands it out again and the receiving account is
  reported as involved in the transaction that paid it.
- The funding account recorded for a transparent output counts value spent from the Ironwood pool, so
  an output funded entirely from Ironwood is attributed to the funding account and one funded from
  several pools to its largest contributor.
- `zcashlc_transaction_data_requests` derives status requests from durable observation intent: a sent
  transaction is queried by txid when the wallet cannot observe one of its shielded spends or outputs,
  intent sleeps while a transaction is mined and revives after a rewind, and redundant requests for
  wallet-observable transactions are no longer produced.
- The Tor HTTP and gRPC transports bound each network operation, so `zcashlc_get_exchange_rate_usd`,
  `zcashlc_tor_http_get` / `_post` and the `zcashlc_tor_lwd_conn_*` calls fail with an error instead
  of hanging against a server that accepts a connection and then never responds. They also reject a
  URL whose scheme is neither `http` nor `https`, which was previously treated as plaintext HTTP.

## 2.7.0-rc.2 - 2026-07-26

### Changed
- Migrated to `zcash_client_backend 0.24.0-rc.4`,
  `zcash_client_sqlite 0.22.0-rc.4`, `pczt 0.9.1`.
- `zcashlc_redact_pczt_for_signer` requests `zcash_client_backend`'s full
  (non-compacted) signer view rather than the compact one, and the PCZT it
  returns is serialized at the minimal encoding version capable of
  representing its content (v1 for a v5 transaction) rather than always v2.
  Deployed hardware signers do not provide the receiver capabilities the
  compact view and v2 encoding require. The full view also clears Ironwood
  spend witnesses and output metadata alongside the other bundles.
- `zcashlc_add_proofs_to_pczt` reuses a cached Orchard-family proving key
  across the Orchard and Ironwood proofs (both use the same PostNu6_3 circuit
  after NU6.3) instead of rebuilding it for each, and derives the Ironwood
  circuit version from the PCZT's consensus branch id rather than hardcoding
  it. The resulting proofs are unchanged.

### Fixed
- `zcashlc_propose_send_max_transfer` now spends from the Ironwood pool in
  addition to Sapling and Orchard, so a post-NU6.3 wallet's Ironwood funds are
  no longer silently excluded from a send-max. This affects only the general
  send-max proposal; the spend set used by
  `zcashlc_propose_orchard_to_ironwood_migration` is unchanged. There is no
  Swift API for the general send-max proposal; `zcashlc_propose_send_max_transfer`
  is reachable only through the C FFI.
- PCZTs created by `zcashlc_create_pczt_from_proposal` for post-NU6.3 (v6)
  transactions carry ZIP 32 derivation metadata on the wallet-controlled
  zero-value Orchard spends that pad them (via
  `zcash_client_backend 0.24.0-rc.4`), so external Signers can identify and
  sign them. Previously those actions were unsignable and extraction failed
  with a missing spend-auth signature.

## 2.7.0-rc.1 - 2026-07-25

### Added
- `zcashlc_put_ironwood_subtree_roots`: Store Ironwood subtree roots in the
  wallet database, mirroring the Sapling and Orchard entry points.
- `zcashlc_propose_orchard_to_ironwood_migration`: Propose migrating an
  account's entire Orchard balance into the Ironwood pool.
- The wallet-summary FFI structs gained `ironwood_balance` on the per-account
  balance and `next_ironwood_subtree_index` on the summary.

### Changed
- Migrated to the Ironwood (NU6.3) releases: `orchard` 0.14→0.15,
  `zcash_client_backend` 0.23→0.24.0-rc.2, `zcash_client_sqlite`
  0.21→0.22.0-rc.2, `zcash_primitives`/`zcash_proofs` 0.28→0.30,
  `zcash_protocol` 0.9→0.10, `zcash_address` 0.12→0.13, `zcash_transparent`
  0.8→0.10, `pczt` 0.7→0.8, `zcash_keys` 0.14→0.16; the `[patch.crates-io]`
  git overrides were dropped.
- `zcashlc_add_proofs_to_pczt` also proves Ironwood bundles.
- Once NU6.3 activates, a payment to an Orchard receiver is delivered through
  the Ironwood bundle of a version 6 transaction: proposals returned by
  `zcashlc_propose_transfer` report such payments and the change from Ironwood
  spends as Ironwood-pool outputs, and `zcashlc_create_proposed_transactions`
  and `zcashlc_create_pczt_from_proposal` build the version 6 transaction.
  Fee and change calculation derive the Orchard bundle version from the
  proposal's target height, charging one ZIP 317 action per Orchard spend or
  output at or beyond activation rather than `max(spends, outputs)`, with
  Ironwood spends, outputs and change charged against the Ironwood bundle.

### Removed
- The `zcashlc_voting_*` FFI is no longer compiled. `zcash_voting` cannot
  resolve against the Ironwood (NU6.3) `orchard` release, so the `voting`
  module is gated behind `#[cfg(zcash_voting)]` and the
  `zcash_voting`/`zcash_keys` dependencies are commented out in `Cargo.toml`.
  The module sources are retained so the surface can be reinstated once the
  voting crates support the Ironwood dependency stack.

### Fixed
- `zcashlc_delete_account` no longer fails with a rusqlite
  `InvalidParameterName(":address")` error when the account being deleted is
  recorded as the recipient of one of its own sent outputs. Wallets on the 2.6
  line received this fix in 2.6.0-alpha.6.

## 2.6.0-alpha.6 - 2026-06-26

### Fixed
- Updated `zcash_client_sqlite` to 0.21.1, fixing an `InvalidParameterName` error in `delete_account` when the account being deleted is referenced by a `sent_notes` row via its `to_account_id` column (i.e. an account involved in a cross-account transfer) ([librustzcash#2426](https://github.com/zcash/librustzcash/pull/2426)).

## 2.6.0-alpha.4 - 2026-06-04

### Changed
- Migrated to the released crates.io versions listed under 2.5.2 below,
  including `zcash_protocol` 0.9, which sets the NU6.2 activation heights
  (mainnet 3364600, testnet 4052000). The FFI surface is unchanged.

## 2.5.2 - 2026-06-03

### Changed
- Migrated to released crates.io versions of the Zcash crates: `orchard`
  0.13.1→0.14, `zcash_client_backend` 0.22→0.23, `zcash_client_sqlite`
  0.20.2→0.21, `zcash_keys` 0.13→0.14, `zcash_primitives`/`zcash_proofs`
  0.27→0.28, `zcash_protocol` 0.8→0.9, `zcash_address` 0.11→0.12,
  `zcash_transparent` 0.7→0.8, `pczt` 0.6→0.7. `zcash_protocol` 0.9 carries
  the NU6.2 activation heights (mainnet 3364600, testnet 4052000), so
  transactions targeting those heights and above are built against the NU6.2
  consensus branch id. The FFI surface is unchanged.

## 2.6.0-alpha.3 - 2026-05-27

### Changed
- Updated `zcash_voting` to 0.10.1, taken from the released crate rather than a
  git revision. No `zcashlc_voting_*` entry points were added or removed.

## 2.6.0-alpha.2 - 2026-05-18

### Changed
- Updated `zcash_voting` to 0.8.1 (from 0.6.0). No `zcashlc_voting_*` entry
  points were added or removed.

## 2.5.1 - 2026-05-15

### Changed
- Replaced the `[patch.crates-io]` git pin on the librustzcash crates with
  their published releases: `zcash_client_backend 0.22.0`,
  `zcash_client_sqlite 0.20.2`, `zcash_keys 0.13.0`, `pczt 0.6.0`,
  `zcash_primitives`/`zcash_proofs 0.27.1`, `zcash_protocol 0.8.0`,
  `zcash_address 0.11.0`, `zcash_transparent 0.7.0`.

### Fixed
- Proposing a transaction that shields more than 150 transparent P2PKH inputs
  no longer fails from an incorrect fee computation.

## 2.6.0-alpha.1 - 2026-05-12

### Added
- The `zcashlc_voting_*` surface grew from the 11 entry points added in 2.5.0
  to 59, covering the voting-database handle, round setup and state, vote
  commitment and share-payload construction, share encryption, delegation PIR
  precomputation, vote-tree sync, VAN and note witness generation, and the
  vote/delegation transaction-hash store. All of them were removed again in
  2.7.0-rc.1.

## 2.5.0 - 2026-05-11

### Added
- `zcashlc_voting_compute_share_nullifier`: Compute the 32-byte share-reveal
  nullifier from a vote commitment, primary blind, and share index. Returns
  the nullifier as a 64-character hex C-string; the caller must free the
  returned pointer via `zcashlc_string_free`. Returns `NULL` on error or
  panic. Pure-function FFI: no wallet DB, voting DB, network, randomness,
  or secret material involved.
- `zcashlc_voting_validate_pir_proof`: Validate a PIR-fetched IMT
  non-membership proof against an expected root.
- `zcashlc_voting_db_open`, `zcashlc_voting_db_free`, and
  `zcashlc_voting_set_wallet_id`: Manage the voting database handle used by
  stateful voting FFI calls.
- `zcashlc_voting_precompute_delegation_pir`: Precompute and cache delegation
  PIR IMT proofs for a voting bundle using the configured voting database and
  caller-supplied PIR endpoint.
- `zcashlc_voting_sync_vote_tree`: Sync the vote commitment tree for a round
  from a chain node URL, returning the latest synced block height (>= 0) on
  success, or -1 on error.
- `zcashlc_voting_generate_van_witness`: Generate a vote authority note Merkle witness for
  the second voting ZKP and return it as a JSON-encoded `VanWitness`
  (`auth_path`, `position`, `anchor_height`) in a `*mut FfiBoxedSlice`.
- `zcashlc_voting_reset_tree_client`: Drop the in-memory tree client for a
  round so the next `zcashlc_voting_sync_vote_tree` call creates a fresh one.
- `zcashlc_voting_warm_proving_caches`, `zcashlc_voting_decompose_weight`,
  `zcashlc_voting_generate_delegation_inputs`,
  `zcashlc_voting_generate_delegation_inputs_with_fvk`,
  `zcashlc_voting_extract_pczt_sighash`,
  `zcashlc_voting_extract_spend_auth_sig`,
  `zcashlc_voting_extract_nc_root`, and `zcashlc_voting_verify_witness`:
  Utility FFI for voting proof setup, PCZT/signature extraction,
  note-commitment root extraction, and witness verification.
- `FfiRoundState`, `FfiVotingHotkey`, `FfiBundleSetupResult`,
  `FfiRoundSummaries`, and `FfiVoteRecords`, plus their
  `zcashlc_voting_free_*` helpers, for C-compatible voting return values.
- `zcashlc_voting_generate_note_witnesses`: Generate Orchard Merkle inclusion
  witnesses for the notes in a voting bundle, anchored at the round's snapshot
  height.
- `VotingDatabaseHandle` now also carries a
  `zcash_voting::tree_sync::VoteTreeSync`, constructed in
  `zcashlc_voting_db_open` and consumed by the tree-sync FFI above.
- `zcashlc_voting_init_round`, `zcashlc_voting_get_round_state`,
  `zcashlc_voting_list_rounds`, `zcashlc_voting_get_votes`,
  `zcashlc_voting_clear_round`, `zcashlc_voting_delete_skipped_bundles`,
  recovery-state transaction/hash/signature helpers, and share-delegation
  tracking helpers for persisted voting round state.
- `zcashlc_voting_generate_hotkey`, `zcashlc_voting_setup_bundles`,
  `zcashlc_voting_get_bundle_count`, `zcashlc_voting_build_pczt`,
  `zcashlc_voting_store_tree_state`,
  `zcashlc_voting_build_and_prove_delegation`,
  `zcashlc_voting_get_delegation_submission`,
  `zcashlc_voting_get_delegation_submission_with_keystone_sig`, and
  `zcashlc_voting_store_van_position` for the delegation workflow FFI.
- `zcashlc_voting_encrypt_shares`, `zcashlc_voting_build_vote_commitment`,
  `zcashlc_voting_build_share_payloads`, `zcashlc_voting_mark_vote_submitted`,
  and `zcashlc_voting_sign_cast_vote` for the vote-casting FFI.
- `zcashlc_voting_get_wallet_notes`: Load unspent Orchard notes for a wallet
  account at a snapshot height and return them as JSON-encoded
  `Vec<NoteInfo>` in a `*mut FfiBoxedSlice`. `account_uuid` must be a non-null
  pointer to exactly 16 bytes (binary account UUID). Returns `NULL` on error
  or panic. Output is suitable as the `notes_json` input to
  `zcashlc_voting_precompute_delegation_pir`.
- `zcashlc_voting_extract_orchard_fvk_from_ufvk`: Decode a UFVK string and
  return the raw 96-byte Orchard full viewing key in a
  `*mut FfiBoxedSlice`. Returns `NULL` on missing Orchard component,
  malformed UFVK, or invalid `network_id`.
- Added `zcash_voting 0.5.7` (`default-features = false`, `client-pir`,
  `client-tree-sync`) as a Rust dependency.
- Added `zcash_keys 0.13` (`orchard` feature) as a Rust dependency, used by
  the new wallet-notes and key-utility FFI for voting to decode UFVKs and derive
  Orchard FVKs.
- Added `incrementalmerkletree 0.8` (`default-features = false`) as a direct
  Rust dependency, used by `zcashlc_voting_generate_note_witnesses` for
  `Position` and the `MerklePath` returned by the wallet DB.

### Changed
- Pinned `orchard` to `=0.13.1` and enabled its `unstable-voting-circuits`
  feature (required transitively by `zcash_voting`).
- Enabled the `client-tree-sync` feature on `zcash_voting`, required by the
  new tree-sync FFI symbols and by the `VoteTreeSync` field on
  `VotingDatabaseHandle`.

## 2.4.6 - 2026-03-12

### Changed
- This is the first release using Github artifact-based deployment. Users should 
  obtain releases from <TBD>

## 0.19.2 - 2026-03-02

### Fixed
- Updated to `shardtree 0.6.2, zcash_client_sqlite 0.19.4` to fix a note
  commitment tree corruption bug.

## 0.19.1 - 2025-11-26

### Added
- `ffi::ZecUsdExchange`
- `zcashlc_get_exchange_rate_usd_from`

### Changed
- Reduced the number of exchanges queried for ZEC/USD back to the number we had
  in 0.18 and earlier, to reduce power consumption.

## 0.19.0 - 2025-11-04

### Added
- `ffi::AddressCheckResult`
- `ffi::SingleUseTaddr`
- `zcashlc_get_single_use_taddr`
- `zcashlc_free_single_use_taddr`
- `zcashlc_tor_lwd_conn_check_single_use_taddr`
- `zcashlc_free_address_check_result`
- `zcashlc_propose_send_max_transfer`
- `zcashlc_tor_lwd_conn_update_transparent_address_transactions`
- `zcashlc_tor_lwd_conn_fetch_utxos_by_address`
- `zcashlc_delete_account`

### Changed
- MSRV is now 1.90.
- Migrated to `zcash_client_backend 0.21`, `zcash_client_sqlite 0.19`, `pczt-0.5`.

## 0.18.5 - 2025-10-23

### Changed
- Updated to `zcash_client_sqlite-0.18.9` to fix problems in transparent UTXO
  selection for shielding, including incorrect handling of outputs received at
  ephemeral addresses and selection of dust transparent outputs for shielding.

## 0.18.4 - 2025-10-16

### Changed
- Updated to `zcash_client_sqlite-0.18.7` to improve consistency of spentness
  determination, reliability of transaction status request generation,
  and fix removal of already-fulfilled transaction enhancement requests.

## 0.18.3 - 2025-10-08

### Fixed
- Updated to `zcash_client_sqlite-0.18.4` to fix a problem with balance calculation
  related to detection of spends of outputs received by the wallet's ephemeral
  addresses.

## 0.18.2 - 2025-10-01

### Fixed
- Updated to `zcash_client_sqlite-0.18.3` to fix a problem with display of
  zero-conf-shielded fully transparent transactions.

## 0.18.1 - 2025-09-29

### Fixed
- Updated to `zcash_client_sqlite-0.18.2` to fix a problem with zero-conf shielding.

## 0.18.0 - 2025-09-26

### Added

- `ConfirmationsPolicy`

### Changed

- Updated to `zcash_client_backend 0.20`, `zcash_client_sqlite 0.18`.
- functions now take `confirmations_policy: ConfirmationsPolicy` instead of `min_confirmations: u32`:

  * `zcashlc_get_wallet_summary`
  * `zcashlc_get_verified_transparent_balance`
  * `zcashlc_get_verified_transparent_balance_for_account`
  * `zcashlc_propose_transfer`
  * `zcashlc_propose_send_max_transfer`
  * `zcashlc_propose_transfer_from_uri`
  * `zcashlc_propose_shielding`

## 0.17.1 - 2025-08-29

### Changed
- Updated to `zcash_client_sqlite 0.17.3` (hotfix release).

### Fixed
- This release fixes a potential false-positive in the `expired_unmined` column
  of the `v_transactions` view.

## 0.17.0 - 2025-06-04

### Added
- `FfiHttpRequestHeader`
- `FfiHttpResponseBytes`
- `FfiHttpResponseHeader`
- `TorDormantMode`
- `zcashlc_free_http_response_bytes`
- `zcashlc_tor_http_get`
- `zcashlc_tor_http_post`
- `zcashlc_tor_set_dormant`

### Changed
- MSRV is now 1.87.
- Updated to `zcash_client_backend 0.19`, `zcash_client_sqlite 0.17`.

## 0.16.0 - 2025-05-13

### Added
- `OutputStatusFilter`
- `TransactionStatusFilter`

### Changed
- `zcashlc_get_next_available_address` now takes an additional `receiver_flags`
  argument that permits the caller to specify which receivers should be
  included in the generated unified address.
- `FfiTransactionDataRequest` variant `SpendsFromAddress` has been renamed to
  `TransactionsInvolvingAddress` and has new fields.

## 0.15.0 - 2025-04-24

### Added
- `zcashlc_tor_lwd_conn_get_info`
- `zcashlc_tor_lwd_conn_get_tree_state`
- `zcashlc_tor_lwd_conn_latest_block`

### Changed
- `FfiWalletSummary` has a new field `recovery_progress`.
- `FfiWalletSummary.scan_progress` now only tracks the progress of making
  existing wallet balance spendable. In some cases (depending on how long a
  wallet was offline since its last sync) it may also happen to include progress
  of discovering new notes, but in general `FfiWalletSummary.recovery_progress`
  now covers the discovery of historic wallet information.

### Fixed
- `zcashlc_tor_lwd_conn_fetch_transaction` now correctly returns `null` as the
  error sentinel instead of a "none" `FfiBoxedSlice`.

## 0.14.2 - 2025-04-02

### Fixed
- This fixes an error in the `transparent_gap_limit_handling` migration,
  whereby wallets having received transparent outputs at child indices below
  the index of the default address could cause the migration to fail.

## 0.14.1 - 2025-03-27

### Fixed
- This fixes an error in the `transparent_gap_limit_handling` migration,
  whereby wallets that received Orchard outputs at diversifier indices for
  which no Sapling receivers could exist would incorrectly attempt to
  derive UAs containing sapling receivers at those indices.

## 0.14.0 - 2025-03-21

### Added
- `zcashlc_fix_witnesses`

### Changed
- MSRV is now 1.85.
- Updated to `zcash_client_backend 0.18`, `zcash_client_sqlite 0.16`.
- Added support for gap-limit-based discovery of transparent wallet addresses.

## 0.13.0 - 2025-03-04

### Added
- `FfiAccountMetadataKey`
- `FfiSymmetricKeys`
- `zcashlc_account_metadata_key_from_parts`
- `zcashlc_derive_account_metadata_key`
- `zcashlc_derive_private_use_metadata_key`
- `zcashlc_free_account_metadata_key`
- `zcashlc_free_symmetric_keys`
- `zcashlc_free_tor_lwd_conn`
- `zcashlc_pczt_requires_sapling_proofs`
- `zcashlc_redact_pczt_for_signer`
- `zcashlc_tor_connect_to_lightwalletd`
- `zcashlc_tor_isolated_client`
- `zcashlc_tor_lwd_conn_fetch_transaction`
- `zcashlc_tor_lwd_conn_submit_transaction`

### Changed
- MSRV is now 1.84.
- `FfiAccount` now has a `ufvk` string field.

## 0.12.0 - 2024-12-16

### Added
- `FfiUuid`
- `zcashlc_free_ffi_uuid`
- `zcashlc_get_account`
- `zcashlc_free_account`
- `FfiAddress`
- `zcashlc_free_ffi_address`
- `zcashlc_derive_address_from_ufvk`
- `zcashlc_derive_address_from_uivk`
- `zcashlc_create_pczt_from_proposal`
- `zcashlc_add_proofs_to_pczt`
- `zcashlc_extract_and_store_from_pczt`

### Changed
- Updated dependencies:
  - `sapling-crypto 0.4`
  - `orchard 0.10.1`
  - `zcash_primitives 0.21`
  - `zcash_proofs 0.21`
  - `zcash_keys 0.6`
  - `zcash_client_backend 0.16`
  - `zcash_client_sqlite 0.14`
- `FfiAccounts` now contains `FfiUuid`s instead of `FfiAccount`s.
- `FfiAccount` has changed:
  - It must now be freed with `zcashlc_free_account`.
  - Added fields `uuid_bytes`, `account_name`, `key_source`.
  - Renamed `account_index` field to `hd_account_index`.
- The following structs now have an `account_uuid` field instead of an
  `account_id` field:
  - `FFIBinaryKey`
  - `FFIEncodedKey`
  - `FfiAccountBalance`
- The following functions now have additional arguments `account_name` (which
  must be set) and `key_source` (which may be null):
  - `zcashlc_create_account`
  - `zcashlc_import_account_ufvk`
- `zcashlc_import_account_ufvk` now has additional arguments `seed_fingerprint`
  and `hd_account_index_raw`, which must either both be set or both be "null"
  values.
- `zcashlc_import_account_ufvk` now returns `*mut FfiUuid` instead of `i32`.
- The following functions now take an `account_uuid_bytes` pointer to a byte
  array, instead of an `i32`:
  - `zcashlc_get_current_address`
  - `zcashlc_get_next_available_address`
  - `zcashlc_list_transparent_receivers`
  - `zcashlc_get_verified_transparent_balance_for_account`
  - `zcashlc_get_total_transparent_balance_for_account`
  - `zcashlc_propose_transfer`
  - `zcashlc_propose_transfer_from_uri`
  - `zcashlc_propose_shielding`
- `zcashlc_derive_spending_key` now returns `*mut FfiBoxedSlice` instead of
  `*mut FFIBinaryKey`.

### Removed
- `zcashlc_get_memo_as_utf8`

## 0.11.0 - 2024-11-15

### Added
- `zcashlc_derive_arbitrary_wallet_key`
- `zcashlc_derive_arbitrary_account_key`

### Changed
- Updated `librustzcash` dependencies:
  - `zcash_primitives 0.20`
  - `zcash_proofs 0.20`
  - `zcash_keys 0.5`
  - `zcash_client_backend 0.15`
  - `zcash_client_sqlite 0.13`
- Updated to `rusqlite` version `0.32`
- Updated to `tor-rtcompat` version `0.23`
- `zcashlc_propose_transfer`, `zcashlc_propose_transfer_from_uri` and
  `zcashlc_propose_shielding` no longer accpt a `use_zip317_fees` parameter;
  ZIP 317 standard fees are now always used and are not configurable.

## 0.10.2 - 2024-10-22

### Changed
- Updated to `zcash_client_sqlite` version `0.12.2`

### Fixed
- This release fixes an error in wallet rewind that could cause a crash in the
  wallet backend in certain circumstances.

### Changed
- Updated to `zcash_client_sqlite` version `0.12.1`

## 0.10.1 - 2024-10-10

### Changed
- Updated to `zcash_client_sqlite` version `0.12.1`

### Fixed
- This release fixes an error in scan progress computation that could, under
  certain circumstances, result in scan progress values greater than 100% being
  reported.

## 0.10.0 - 2024-10-04

### Changed
- `zcashlc_rewind_to_height` now returns an `i64` value instead of a boolean. The
  value `-1` indicates failure; any other height indicates the height to which the
  data store was actually truncated. Also, this procedure now takes an additional
  `safe_rewind_ret` parameter that, on failure to rewind, will be set to the
  minimum height for which the rewind would succeed, or to -1 if
  no such height can be determined.

### Removed
- `zcashlc_get_nearest_rewind_height` has been removed. The return value of
  `zcashlc_rewind_to_height`, or in the case of rewind failure the value of its
  `safe_rewind_ret` return parameter should be used instead.

### Fixed
- This release fixes a potential source of corruption in wallet note commitment
  trees related to incorrect handling of chain reorgs. It includes a database
  migration that will repair the corrupted database state of any wallet
  affected by this corner case.

## 0.9.1 - 2024-08-21

### Fixed
- A database migration misconfiguration that could results in problems with wallet
  initialization was fixed.

## 0.9.0 - 2024-08-20

### Added
- `zcashlc_create_tor_runtime`
- `zcashlc_free_tor_runtime`
- `zcashlc_get_exchange_rate_usd`
- `zcashlc_set_transaction_status`
- `zcashlc_transaction_data_requests`
- `zcashlc_free_transaction_data_requests`
- `FfiTransactionStatus_Tag`
- `FfiTransactionStatus`
- `FfiTransactionDataRequest_Tag`
- `SpendsFromAddress_Body`
- `FfiTransactionDataRequest`
- `FfiTransactionDataRequests`
- `Decimal`

### Changed
- MSRV is now 1.80.
- Migrated to `zcash_client_sqlite 0.11`.
- `zcashlc_init_on_load` now takes a log level filter as a UTF-8 C string, instead of
  a boolean.
- The following methods now support ZIP 320 (TEX) addresses:
  - `zcashlc_get_address_metadata`
  - `zcashlc_propose_transfer`
- `zcashlc_decrypt_and_store_transaction` now takes its `mined_height` argument
  as `int64_t`. This allows callers to pass the value of `mined_height` as
  returned by the zcashd `getrawtransaction` RPC method.

### Removed
- `zcashlc_is_valid_sapling_address`, `zcashlc_is_valid_transparent_address`,
  `zcashlc_is_valid_unified_address` (use `zcashlc_get_address_metadata` instead).

## 0.8.1 - 2024-06-14

### Fixed
- Further changes for compatibility with XCode 15.3 and above.

## 0.8.0 - 2024-04-17

### Added
- `zcashlc_is_valid_sapling_address`

### Changed
- Updates to `zcash_client_sqlite` version `0.10.3` to add migrations that ensure the
  wallet's default Unified address contains an Orchard receiver.
- `zcashlc_get_memo` now takes an additional `output_pool` parameter. This fixes a problem
  with the retrieval of Orchard memos.

### Removed
- `zcashlc_is_valid_shielded_address` - use `zcashlc_is_valid_sapling_address` instead.

## 0.7.4 - 2024-03-28

### Added
- `zcashlc_put_orchard_subtree_roots`

## 0.7.3 - 2024-03-27

- Updates to `zcash_client_backend 0.12.1` to fix a bug in note selection
  when sending to a transparent recipient.

## 0.7.2 - 2024-03-27

- Updates to `zcash_client_sqlite 0.10.2` to fix a bug in an SQL query
  that prevented shielding of transparent funds.

## 0.7.1 - 2024-03-25

- Updates to `zcash_client_sqlite` version 0.10.1 to fix an incorrect
  constraint on the `sent_notes` table. Databases built or upgraded
  using version 0.7.0 will need to be deleted and restored from seed.

## 0.7.0 - 2024-03-25

This version has been yanked due to a bug in zcash_client_sqlite version 0.10.0

## Notable Changes
- Adds Orchard support.

### Added
- Structs and functions for listing accounts in the wallet:
  - `zcashlc_list_accounts`
  - `zcashlc_free_accounts`
  - `FfiAccounts`
  - `FfiAccount`
- `zcashlc_is_seed_relevant_to_any_derived_account`

### Changed
- Update to zcash_client_backend version 0.12.0 and zcash_client_sqlite version
  0.10.0.
- `zcashlc_scan_blocks` now takes a `TreeState` protobuf object that provides
  the frontiers of the note commitment trees as of the end of the block prior to
  the range being scanned.

## 0.6.0 - 2024-03-07

### Added
- `zcashlc_create_proposed_transactions`

### Changed
- Migrated to `zcash_client_sqlite 0.9`.

- `zcashlc_propose_shielding` now raises an error if more than one transparent
  receiver has funds that require shielding, to avoid creating transactions that
  link these receivers on chain. It also now takes a `transparent_receiver`
  argument that can be used to select a specific receiver for which to shield
  funds.
- `zcashlc_propose_shielding` now returns a "none" `FfiBoxedSlice` (with its
  `ptr` field set to `null`) if there are no funds to shield, or if the funds
  are below `shielding_threshold`.

### Removed
- `zcashlc_create_proposed_transaction`
  (use `zcashlc_create_proposed_transactions` instead).

## 0.5.1 - 2024-01-30

Update to `librustzcash` tag `ecc_sdk-20240130a`.

### Fixes
This release fixes a problem in the serialization of transaction proposals having
empty transaction requests (shielding transactions are change-only and contain
no payments.)

## 0.5.0 - 2024-01-29

## Notable Changes

This release updates the `librustzcash` dependencies to the stable interim tag
`ecc_sdk-20240129`. This provides improvements to wallet query performance that
have not yet been released in a published version of the `zcash_client_sqlite`
crate, as well as numerous unreleased changes to the `zcash_client_backend` and
`zcash_primitives` crates.

### Added
- FFI data structures:
  - `FfiBalance`
  - `FfiAccountBalance`
  - `FfiWalletSummary`
  - `FfiScanSummary`
  - `FfiBoxedSlice`
- FFI methods:
  - `zcashlc_propose_transfer`
  - `zcashlc_propose_transfer_from_uri`
  - `zcashlc_propose_shielding`
  - `zcashlc_create_proposed_transaction`
  - `zcashlc_get_wallet_summary`
  - `zcashlc_free_wallet_summary`
  - `zcashlc_free_boxed_slice`
  - `zcashlc_free_scan_summary`

### Changed
- `zcashlc_scan_blocks` now returns a `FfiScanSummary` value.

### Removed
- `zcashlc_get_balance` (use `zcashlc_get_wallet_summary` instead)
- `zcashlc_get_scan_progress` (use `zcashlc_get_wallet_summary` instead)
- `zcashlc_get_verified_balance` (use `zcashlc_get_wallet_summary` instead)
- `zcashlc_create_to_address` (use `zcashlc_propose_transfer`  and
  `zcashlc_create_proposed_transaction` instead)
- `zcashlc_shield_funds` (use `zcashlc_propose_shielding`  and
  `zcashlc_create_proposed_transaction` instead)

## 0.4.1 - 2023-10-20

### Issues Resolved
- [#103] Update to `zcash_client_sqlite` with a fix for
  [incorrect note deduplication in `v_transactions`](https://github.com/zcash/librustzcash/pull/1020).

Updated dependencies:
  - `zcash_client_sqlite 0.8.1`

## 0.4.0 - 2023-09-25

### Notable Changes

This release overhauls the FFI library to provide support for allowing wallets to
spend funds without fully syncing the blockchain. This results in significant
changes to much of the API; it is recommended that users review the changes
from the previous release carefully.

### Changed
- `anyhow` is now used for error management

### Issues Resolved
- [#95] Update to `zcash_client_backend` and `zcash_client_sqlite` with fast sync support

Updated dependencies:
  - `zcash_address 0.3`
  - `zcash_client_backend 0.10.0`
  - `zcash_client_sqlite 0.8.0`
  - `zcash_primitives 0.13.0`
  - `zcash_proofs 0.13.0`

  - `orchard 0.6`
  - `ffi_helpers 0.3`
  - `secp256k1 0.26`

Added dependencies:
  - `anyhow 0.1`
  - `prost 0.12`
  - `cfg-if 1.0`
  - `rayon 1.7`
  - `log-panics 2.0`
  - `once_cell 1.0`
  - `sharded-slab 0.1`
  - `tracing 0.1`
  - `tracing-subscriber 0.3`

## 0.3.1
- [#88] unmined transaction shows note value spent instead of tx value

Fixes an issue where a sent transaction would show the whole note spent value
instead of the value of that the user meant to transfer until it was mined.

## 0.3.0

- [#87] Outbound transactions show the wrong amount on v_transactions

removes `v_tx_received` and `v_tx_sent`.

`v_transactions` now shows the `account_balance_delta` column where the clients can
query the effect of a given transaction in the account balance. If fee was paid from
the account that's being queried, the delta will include it. Transactions where funds
are received into the queried account, will show the amount that the acount is receiving
and won't include the transaction fee since it does not change the balance of the account.

Creates `v_tx_outputs` that allows clients to know the outputs involved in a transaction.

## 0.2.0

- [#34] Fix SwiftPackageManager deprecation Warning
We had to change the name of the package to make it match the name
of the github repository due to Swift Package Manager conventions.

please see README.md for more information on how to import this package
going forward.

### FsBlock Db implementation and removal of BlockBb cache.

Implements `zcashlc_init_block_metadata_db`, `zcashlc_write_block_metadata`,
`zcashlc_free_block_meta`, `zcashlc_free_blocks_meta`

Declare `repr(C)` structs for FFI:
 - `FFIBlockMeta`: a block metadata row
 - `FFIBlocksMeta`: a structure that holds an array of `FFIBlockMeta`


expose shielding threshold for `shield_funds`

- [#81] Adopt latest crate versions
Bumped dependencies to `zcash_primitives 0.10`, `zcash_client_backend 0.7`,
`zcash_proofs 0.10`, `zcash_client_sqlite 0.5.0`

this adds support for `min_confirmations` on `shield_funds` and `shielding_threshold`.
- [#78] removing cocoapods support

## 0.1.1

Updating:
````
 - zcash_client_backend v0.6.0 -> v0.6.1
 - zcash_client_sqlite v0.4.0 -> v0.4.2
 - zcash_primitives v0.9.0 -> v0.9.1
````
This fixes the following issue
- [#72] fixes get_transparent_balance() fails when no UTXOs

## 0.1.0

Unified spending keys are now used in all places where spending authority
is required, both for performing spends of shielded funds and for shielding
transparent funds. Unified spending keys are represented as opaque arrays
of bytes, and FFI methods are provided to permit derivation of viewing keys
from the binary unified spending key representation.

IMPORTANT NOTE: the binary representation of a unified spending key may be
cached, but may become invalid and require re-derivation from seed to use as
input to any of the relevant APIs in the future, in the case that the
representation of the spending key changes or new types of spending authority
are recognized.  Spending keys give irrevocable spend authority over
a specific account.  Clients that choose to store the binary representation
of unified spending keys locally on device, should handle them with the
same level of care and secure storage policies as the wallet seed itself.

### Added
- `zcashlc_create_account` provides new account creation functionality.
  This is now the preferred API for the creation of new spend authorities
  within the wallet; `zcashlc_init_accounts_table_with_keys` remains available
  but should only be used if it is necessary to add multiple accounts at once,
  such as when restoring a wallet from seed where multiple accounts had been
  previously derived.

Key derivation API:
- `zcashlc_derive_spending_key`
- `zcashlc_spending_key_to_full_viewing_key`

Address retrieval, derivation, and verification API:
- `zcashlc_get_current_address`
- `zcashlc_get_next_available_address`
- `zcashlc_get_sapling_receiver_for_unified_address`
- `zcashlc_get_transparent_receiver_for_unified_address`
- `zcashlc_is_valid_unified_address`
- `zcashlc_is_valid_unified_full_viewing_key`
- `zcashlc_list_transparent_receivers`
- `zcashlc_get_typecodes_for_unified_address_receivers`
- `zcashlc_free_typecodes`
- `zcashlc_get_address_metadata`
Balance API:
- `zcashlc_get_verified_transparent_balance_for_account`
- `zcashlc_get_total_transparent_balance_for_account`

New memo access API:
- `zcashlc_get_received_memo`
- `zcashlc_get_sent_memo`

### Changed
- `zcashlc_create_to_address` now has been changed as follows:
  - it no longer takes the string encoding of a Sapling extended spending key
    as spend authority; instead, it takes the binary encoded form of a unified
    spending key as returned by `zcashlc_create_account` or
    `zcashlc_derive_spending_key`. See the note above.
  - it now takes the minimum number of confirmations used to filter notes to
    spend as an argument.
  - the memo argument is now passed as a potentially-null pointer to an
    `[u8; 512]` instead of a C string.
- `zcashlc_shield_funds` has been changed as follows:
  - it no longer takes the transparent spending key for a single P2PKH address
    as spend authority; instead, it takes the binary encoded form of a unified
    spending key as returned by `zcashlc_create_account`
    or `zcashlc_derive_spending_key`. See the note above.
  - the memo argument is now passed as a potentially-null pointer to an
    `[u8; 512]` instead of a C string.
  - it no longer takes a destination address; instead, the internal shielding
    address is automatically derived from the account ID.
- Various changes have been made to correctly implement ZIP 316:
  - `FFIUnifiedViewingKey` now stores an account ID and the encoding of a
    ZIP 316 Unified Full Viewing Key.
  - `zcashlc_init_accounts_table_with_keys` now takes a slice of ZIP 316 UFVKs.
- `zcashlc_put_utxo` no longer has an `address_str` argument (the address is
  instead inferred from the script).
- `zcashlc_get_verified_balance` now takes the minimum number of confirmations
  used to filter received notes as an argument.
- `zcashlc_get_verified_transparent_balance` now takes the minimum number of
  confirmations used to filter received notes as an argument.
- `zcashlc_get_total_transparent_balance` now returns a balance that includes
  all UTXOs including those only in the mempool (i.e. those with 0
  confirmations).

### Removed

The following spending key derivation APIs have been removed and replaced by
`zcashlc_derive_spending_key`:
- `zcashlc_derive_extended_spending_key`
- `zcashlc_derive_transparent_private_key_from_seed`
- `zcashlc_derive_transparent_account_private_key_from_seed`

The following viewing key APIs have been removed and replaced by
`zcashlc_spending_key_to_full_viewing_key`:
- `zcashlc_derive_extended_full_viewing_key`
- `zcashlc_derive_shielded_address_from_viewing_key`
- `zcashlc_derive_unified_viewing_keys_from_seed`

The following address derivation APIs have been removed in favor of
`zcashlc_get_current_address` and `zcashlc_get_next_available_address`:
- `zcashlc_get_address`
- `zcashlc_derive_shielded_address_from_seed`
- `zcashlc_derive_transparent_address_from_secret_key`
- `zcashlc_derive_transparent_address_from_seed`
- `zcashlc_derive_transparent_address_from_public_key`

- `zcashlc_init_accounts_table` has been removed in favor of
  `zcashlc_create_account`

## 0.0.3
- [#13] Migrate to `zcash/librustzcash` revision with NU5 awareness (#20)
  This enables mobile wallets to send transactions after NU5 activation.

# Changelog
All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added
- Pool-migration (Orchard→Ironwood) FFI surface over the final engine
  (`zcash_pool_migration_backend` + the account-keyed store inside
  `zcash_client_sqlite::pool_migration`, both on librustzcash main; the family pin
  targets a plain main rev — boundary-anchor proving (#2710) and owner-keyed
  note locking (#2716) are both merged, nothing unmerged remains):
  21 of the 24 `zcashlc_migration_*` entry points (the residual-locking pair
  and the run-count estimate ride their own entries below) plus the
  `zcashlc_ironwood_activation_height` helper, with their `#[repr(C)]` return
  types and `zcashlc_free_migration_*` destructors. Each call opens the wallet database and
  the account-keyed migration store (a second connection into the same file) from
  the wallet-db path, 16-byte account uuid, and network id, and reports failures
  through the thread-local last-error channel (`NULL` / `false` / `-1` sentinels),
  with two stable prefixes (`MIGRATION_PLAN_STALE`, `MIGRATION_PROVING_UNAVAILABLE`)
  for the actionable conditions. The engine plans previews (`plan_migration`,
  carried propose→commit by an in-process plan cache), commits the note split and
  the transfer schedule atomically (pre-signing every transaction), defers anchors
  and witnesses to proving time (ZIP 374) — proving runs through the upstream
  prover (`engine::prove_transfer` / `engine::prove_preparation` driving
  `wallet::WalletMigrationProver`): transfers prove against the boundary anchor
  their schedule drew and persisted (ZIP 318 anchor cohorts; upstream retention,
  librustzcash #2700/#2710, keeps the matching 144-block boundary grid durably
  witnessable from NU6.3 activation), preparations against the wallet's natural
  anchor, and a boundary the wallet has not scanned or retained yet surfaces as
  the transient nothing-due, not an error — and leaves broadcasting,
  mined-reconciliation, rejection classification (the `sdk_invalid_marks` side
  table), and the platform's 5-state derivation to this layer (the v1 crate's
  `ReadyToPropose` state and `SyncRequiredBeforeNext` attention reason are gone
  entirely — the engine's atomic split+schedule commit means that intermediate
  moment cannot occur). `Complete` is
  per-run; sequential runs commit over a terminal predecessor. The external-signer
  note-split pair is plural (`zcashlc_migration_create_unsigned_note_split_pczts` /
  `zcashlc_migration_store_signed_note_split_pczts`): the engine builds N
  preparation transactions, not one split transaction. The schedule/note-split
  echo parameters (`ids`/`amounts`/heights/duration on the schedule-commit calls;
  `output_values`/`fee` on the note-split-commit call) are verified consent
  echoes, checked against the previewed plan (or, once committed, the stored
  state), with a mismatch surfacing `MIGRATION_PLAN_STALE`, so a stale or
  tampered display can never sign different values than the ones the user
  approved. Ids, amounts, expiry heights, and the estimated duration are
  always compared; next-executable heights are compared only against the
  previewed plan, never post-commit (the immediate lane's commit-time
  reschedule legitimately moves them away from an honest echo, with no way
  to converge by re-proposing); anchor heights are display-only, never
  compared. `include_residual` and `retryable` parameters, and the
  `is_sync_required` query, are removed — they never had a use.
  - State: `zcashlc_migration_state`, `zcashlc_migration_progress`,
    `zcashlc_migration_is_note_split_needed`,
    `zcashlc_migration_has_overdue_transfers`,
    `zcashlc_migration_has_invalid_transfers`,
    `zcashlc_migration_pending_transfer_proposal`.
  - Note split: `zcashlc_migration_prepare_note_split`,
    `zcashlc_migration_sign_note_split`.
  - Proposal/commit: `zcashlc_migration_residual_after_migration`,
    `zcashlc_migration_propose_transfers`,
    `zcashlc_migration_sign_and_store_schedule`.
  - Delivery: `zcashlc_migration_next_due_transfer`,
    `zcashlc_migration_extract_broadcast_tx`,
    `zcashlc_migration_record_transfer_result`,
    `zcashlc_migration_record_immediate_run` (records a broadcast
    immediate-migration sweep — an ordinary send-max transaction built
    outside the engine — so the migration state machine reports it).
  - Recovery: `zcashlc_migration_restart_step` (cancel and re-plan), and
    `zcashlc_migration_refresh_stale_transfers` — rebuilds every expired
    transfer of the stored run in place through the engine's
    rebuild-on-expiry (`rebuild_expired_transfer` /
    `rebuild_expired_transfer_unsigned`): the same funding note, recovered
    by nullifier identity from the expired PCZT, rescheduled from the tip
    with a fresh memoryless delay, a fresh canonical expiry, and a freshly
    drawn boundary anchor. The optional spending key selects the lane —
    with a usk the rebuilt transfer is signed anew in-process; a NULL usk
    (external signer) leaves it awaiting its signature for the unsigned
    PCZT ceremony to re-serve and complete. Returns the run's FULL
    transfer schedule as stored after the refresh (the same
    `FfiMigrationSchedule` the restart returns, here encoded from the
    persisted state) — the atomically-persisted truth the host
    re-displays and echoes, since a rebuilt transfer's fresh
    scheduled/expiry heights exist nowhere else; with nothing expired
    the current stored schedule comes back unchanged, and with no
    stored run or a terminal (completed or cancelled) stored run it is
    empty. Persisted all-or-nothing (on any rebuild error nothing
    persists and NULL is returned); a funding note spent outside the
    migration is a hard error naming the restart remedy.
  - External signer: `zcashlc_migration_create_unsigned_note_split_pczts`,
    `zcashlc_migration_store_signed_note_split_pczts`,
    `zcashlc_migration_create_unsigned_transfer_pczts`,
    `zcashlc_migration_store_signed_schedule_pczts`.
  - Helper: `zcashlc_ironwood_activation_height` (NU6.3 activation height for
    mainnet/testnet).
- Migration residual note locking: `zcashlc_migration_lock_residual` locks every
  currently-spendable, not-already-locked legacy-Orchard note of the account until
  explicit unlock (permanent lock expiry) and returns the total locked zatoshi
  (`0` is a legitimate "nothing was spendable" result; `-1` = error), and
  `zcashlc_migration_unlock_residual` clears ALL of the account's output locks —
  safe because this SDK never creates proposal-scoped locks — returning the
  cleared-output count (`-1` = error). `Balance` (inside
  `FfiAccountBalance`/`FfiWalletSummary`) gains a trailing `locked_value` field
  marshaled from the upstream balance, keeping the "sum of the fields is the
  account's total" contract true now that upstream totals include locked value.
- Migration run-count estimate: `zcashlc_migration_estimate_runs` marshals
  `zcash_pool_migration_backend::engine::estimate_migration_runs` — one
  `FfiRunEstimate` (migratable zatoshi, crossings, prep layers, prep
  transactions) per run inside an `FfiMigrationRunEstimate` (runs array +
  final residual), freed by `zcashlc_free_migration_run_estimate`. A zero (or
  fully sub-quantum) balance marshals as the zero-run estimate
  (`runs_len == 0`), not an error; NULL = error. Signer per-session capacity
  is deliberately NOT a parameter: the platform evaluates signing sessions
  from the per-run transaction counts.
- Keystone batch-signing UR bridge (`rust/src/migration_keystone.rs`, ported from
  `zcash-android-wallet-sdk`'s `backend-lib` at the same librustzcash pin — the engine/pczt APIs
  transferred directly): four new FFI functions plus the ZIP 32 spend-derivation annotation the
  two existing external-signer build calls now apply.
  - `zcashlc_migration_keystone_build_sign_batch_qr_parts` redacts every passed-in unsigned PCZT
    with `redact_pczt_for_batch_signer` (clearing the wire spend FVK and any pre-existing
    Orchard/Ironwood `spend_auth_sig` — the dummy padding spend `IoFinalizer` already self-signs,
    which the Keystone batch firmware otherwise rejects outright) before encoding a
    `pczt::roles::signer::batch::BatchSignRequest` into animated multi-part
    `"zcash-sign-batch"` UR QR frames (`FfiKeystoneQrParts`, this crate's first string-array FFI
    output type, freed by `zcashlc_free_migration_keystone_qr_parts`). Takes ONE ordered PCZT
    array (preparation PCZTs first, then transfer PCZTs) rather than the Android source's
    `(split, transfers)` pair — same wire order, flattened Rust-side shape, since the Swift
    caller already holds every unsigned PCZT as one collection. `ids` is deliberately not a
    parameter here; the build step has no use for them.
  - `zcashlc_migration_keystone_reset_sign_batch_decoder` (void, infallible) and
    `zcashlc_migration_keystone_decode_sign_batch_part` (returns
    `FfiKeystoneBatchDecodeResult`, freed by
    `zcashlc_free_migration_keystone_batch_decode_result`) drive the stateful multi-frame
    `"zcash-batch-sig-result"` scan session one QR frame at a time — `complete`/`progress` for
    the fountain-decoder state, and, once complete, the serialized `BatchSignResponse` bytes plus
    the signing device's own reported firmware version (the only place a batch-signed migration
    can learn it, since the response never echoes back PCZT bytes). Verifies the decoded
    response's request id against the caller-supplied `expected_request_id` and errors on
    mismatch rather than silently accepting a scan of an unrelated/stale response.
  - `zcashlc_migration_keystone_apply_batch_signatures` applies the decoded response's
    signatures back onto the SAME caller-held unsigned PCZTs, in the SAME order passed to the
    build call (signatures align by position, not by any id in the wire format), returning
    signed-but-unproven PCZT bytes through `FfiUnsignedTransferPczts` (now documented as a
    generic `(id, PCZT bytes)` pair set, not just an unsigned-PCZT container) with the input ids
    passed through positionally. Errors if the response's signature-set count doesn't match the
    PCZT count.
  - `zcashlc_migration_create_unsigned_note_split_pczts` and
    `zcashlc_migration_create_unsigned_transfer_pczts` now annotate every returned PCZT with the
    account's ZIP 32 seed fingerprint and account index (`spend_zip32_derivation`, on every not-
    yet-signed Orchard/Ironwood spend action) before returning it: the engine's builder never
    sets this, and combined with the batch redaction above clearing the spend FVK, an
    un-annotated migration PCZT gives Keystone no way to identify the account at all, failing
    on-device with "None of inputs belongs to the provided account". Applied as post-processing
    after `commit_or_resume` so both a freshly built AND a resumed (already-committed) run get
    annotated.

- Live per-transaction migration status read: `zcashlc_migration_transaction_statuses`
  marshals the engine's own `MigrationState::transaction_statuses(target)` verbatim —
  one row per committed migration transaction, keyed by its stable id (durable across
  reads and stale-transfer rebuilds), carrying kind, lifecycle state, scheduled/expiry
  heights, mined height, the broadcast txid while in-mempool, readiness, the next
  action, and the blocking reason. Mined-transaction reconciliation runs first, per the
  read-path convention, and a wallet with no stored run gets an empty container. Freed
  with `zcashlc_free_migration_transaction_statuses`. This is the engine-delegated
  equivalent of the platform-side "refresh a cached transfer's display state after a
  reschedule" reads other SDKs hand-roll over the store's SQL.

### Changed
- Immediate-migration state derivation (`zcashlc_migration_state` /
  `zcashlc_migration_progress`): a MINED immediate (send-max) run is now CONSUMED —
  it derives no migration state (the derivation falls through to `NotStarted`) and
  masks a stale engine `Complete` left by an earlier engine-tracked run, so the app
  goes fully quiet once the sweep mines instead of showing a per-run `Complete`. An
  UNMINED, unexpired immediate run still derives `InProgress` of one, and the
  expired-unmined re-offer is unchanged. To let the app keep the immediate
  aftermath quiet, `FfiMigrationProgress` gains a trailing `is_immediate` boolean —
  `true` for the immediate lane, `false` for engine-tracked runs (and for the
  absent sentinel). Part of the still-unreleased migration surface above.
- The librustzcash family pin advanced to current main, which now carries both
  the boundary-anchor proving of #2710 (on the 144-block retention grid) and
  the merged owner-keyed note locking of #2716 — nothing unmerged remains, so
  the pin targets a plain main rev and the former michal/* aggregation
  branches are retired. Note locks are owner-keyed at this rev: the residual
  lock placed by `zcashlc_migration_lock_residual` is keyed to a deterministic
  per-account owner (making re-locking idempotent), every selection path keeps
  excluding locked notes, and `zcashlc_migration_unlock_residual` still clears
  the account's locks wholesale.

### Fixed
- Migration due-ness and expiry are now evaluated on the engine's target-height
  contract (`chain tip + 1`, the height of the next block) everywhere, matching
  `zcash_pool_migration_backend`'s `MigrationState` queries. The read paths
  (`zcashlc_migration_state`/`_progress` state derivation,
  `zcashlc_migration_has_overdue_transfers`, `zcashlc_migration_has_invalid_transfers`,
  `zcashlc_migration_next_due_transfer`, `zcashlc_migration_pending_transfer_proposal`)
  previously passed the raw tip and two sites hand-rolled the expiry predicate as
  `tip > expiry_height` with no "never expires" (`expiry_height == 0`) guard — so at
  `tip == expiry_height` the SDK still reported a transfer in progress (and could
  serve its doomed broadcast, recording a spurious terminal `expired` mark) while
  the refresh lane, already on engine semantics, considered it expired and rebuilt
  it. The hand-rolled checks are replaced by the engine's own
  `expired_transactions(target)`; transfers now become due and expire exactly one
  block earlier, consistently across every read.
- Transfer amounts are now read from the engine's authoritative
  `NoteSplitPlan::crossing_values()` (on both the previewed plan and the stored
  state) instead of re-deriving them as `funding_notes()[i] − note_fee_buffer` at
  three marshal sites. The values are identical by construction at the pinned
  engine (`funding_notes()` is exactly `crossing_values()[i] + buffer`, 1:1 —
  the old comment's "post-reconciliation divergence" described a retired
  pre-finalization engine and no longer exists), so this removes the duplicated
  formula rather than changing any displayed number; a test pins the identity
  both ways.
- `FfiMigrationProgress.next_transfer_ready_at_height` no longer reports the
  height of a transfer that is already in the mempool: the minimum is taken over
  transfers still awaiting broadcast (`AwaitingSignature`/`Signed`/`Proved`)
  instead of merely "not yet mined", matching the field's documented contract
  ("the height at which the next transfer becomes broadcastable").

## 2.6.0-alpha.6 - 2026-06-26

### Fixed
- Updated `zcash_client_sqlite` to 0.21.1, fixing an `InvalidParameterName` error in `delete_account` when the account being deleted is referenced by a `sent_notes` row via its `to_account_id` column (i.e. an account involved in a cross-account transfer) ([librustzcash#2426](https://github.com/zcash/librustzcash/pull/2426)).

## 2.6.0-alpha.3 - 2026-05-27

### Added
- Added dependency `zcash_voting 0.10` & supporting FFI methods.

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

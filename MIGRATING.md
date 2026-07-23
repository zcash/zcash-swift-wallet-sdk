# Migrating from previous versions to _Unreleased_

## The pool-migration surface rides the final engine

The Orchard→Ironwood migration group (never in a released SDK) is rewired onto the final engine
crates (`zcash_pool_migration_backend` + `zcash_pool_migration_sqlite`). For integrators tracking
the unreleased surface:

- **The external-signer note-split pair went plural.** The engine builds N preparation
  transactions, not one split transaction, so
  `createUnsignedNoteSplitPCZT(accountUUID:) -> Data` is now
  `createUnsignedNoteSplitPCZTs(accountUUID:) -> [MigrationUnsignedTransferPczt]` (it also creates
  the run, persisted unsigned), and `storeSignedNoteSplitPCZT(accountUUID:_: Data)` is now
  `storeSignedNoteSplitPCZTs(accountUUID:_: [MigrationSignedTransferPczt])` (all-or-nothing; the
  returned `PreparedMigrationTransfer` is a storage receipt with a zeroed `txid` — the
  broadcastable value is served by the delivery lane). One signing ceremony still covers the whole
  migration together with `createUnsignedMigrationTransferPCZTs`.
- **`MigrationState.complete` is PER-RUN.** It means "the stored run is fully mined", never
  "nothing left to migrate": ask `proposeMigrationTransfers` whether anything remains (an empty
  schedule means no), and only then treat the account as done. Sequential runs are first-class — a
  new commit over a completed run starts the next one.
- **`MigrationState.readyToPropose` and `MigrationAttentionReason.syncRequiredBeforeNext` are
  removed** (not merely unreachable): the note split and the schedule commit atomically, so
  neither case ever had a real value to carry. This is source-breaking for an exhaustive `switch`
  over either enum — drop the corresponding `case`.
- **`includeResidual` is removed** from `proposeMigrationTransfers`, `restartCurrentMigrationStep`,
  and `refreshStaleMigrationTransfers`: the engine plans canonically and ZIP 318 keeps the residual
  in Orchard, so the parameter never had a real choice behind it. **`isSyncRequiredBeforeNextMigrationTransfer`
  is removed entirely** for the same reason: the note split and the schedule commit atomically, so
  a sync-required gate before the next transfer never had a use.
- **`refreshStaleMigrationTransfers(accountUUID:usk:)` really rebuilds expired transfers.** It
  rebuilds every EXPIRED transfer of the stored run in place: each rebuilt transfer re-spends the
  SAME funding note (recovered by nullifier identity, never an equal-value substitute) on a fresh
  schedule — a fresh memoryless delay from the current tip, a fresh canonical expiry, and a
  freshly drawn boundary anchor — and returns the run's full `MigrationSchedule` as stored AFTER
  the refresh (the current stored schedule when nothing had expired; empty when no run is stored
  or the run is terminal), persisted ALL-OR-NOTHING: a mid-refresh failure persists NONE of the
  batch's rebuilds, so a successful return's schedule is exactly what was atomically committed,
  never a partial batch. The rebuilt rows' fresh scheduled/expiry heights exist nowhere but in
  that returned schedule — re-display it and use it for every later consent echo; a pre-refresh
  copy fails the verified echo with `migrationPlanStale` from then on. `usk` is now
  `UnifiedSpendingKey?`: pass a spending key to sign each rebuilt transfer anew in-process, or
  `nil` for the external-signer (Keystone) lane, which leaves the rebuilt transfers awaiting their
  signature so the existing `createUnsignedMigrationTransferPCZTs` / `storeSignedMigrationSchedulePCZTs`
  ceremony re-serves and completes them. A `FundingNoteUnavailable`-class failure (the expired
  transfer's exact funding note was spent outside the migration) throws naming
  `restartCurrentMigrationStep` (cancel and re-plan the remaining balance) as the remedy.
- **Two new errors:** `migrationPlanStale` (ZRUST0128 — the schedule/note-split consent echo no
  longer matches what is about to be signed; the echo is VERIFIED, never inert display data.
  Recovery depends on when it fires: BEFORE a run is committed, the mismatch is against the
  previewed plan — propose again and re-display. AFTER a run is committed, the mismatch is
  against the stored run itself, and re-proposing cannot converge (proposals re-randomize and
  never touch the committed run) — instead re-read the current stored schedule, which
  `refreshStaleMigrationTransfers(accountUUID:usk:)` returns and the unsigned-transfer PCZT
  serve path works from, and re-display that) and `migrationProvingUnavailable` (ZRUST0127 —
  proving failed hard).
- **`MigrationTransferProposal.anchorHeight` is a reference height** (the proposal-time tip), not
  a commitment-tree anchor: ZIP 374 defers real anchors to proving time.

## The immediate migration lane leaves the engine

The immediate (single-transaction) Orchard→Ironwood migration is no longer proposed or tracked by
the migration engine's own schedule/commit machinery. It is now an ordinary send-max transfer that
the app executes through the normal transaction pipeline, with one new call to record the outcome:

- **`proposeImmediateMigration(accountUUID:) async throws -> MigrationSchedule` is now
  `proposeImmediateMigration(accountUUID:) async throws -> ImmediateMigrationProposal`.**
  `ImmediateMigrationProposal` carries an ordinary `Proposal` — feed it to
  `createProposedTransactions(proposal:spendingKey:)` (software accounts) or
  `createPCZTFromProposal(accountUUID:proposal:)` (Keystone accounts) exactly like any other
  transfer — plus the decoded `amount` (the net value crossing into Ironwood) and `fee`. There is
  no engine plan cache behind it: nothing about the returned proposal can go stale the way a
  `MigrationSchedule` preview can, and `signAndStoreMigrationSchedule` is not part of this lane (it
  remains for `proposeMigrationTransfers`'s gradual path).
- **New: `recordImmediateMigration(accountUUID:txid:) async throws`.** Call it after a successful
  broadcast (software or Keystone lane) so the platform migration state machine reports the sweep:
  `InProgress(0 of 1)` while unmined, then a quiet `NotStarted` once it mines. A MINED immediate
  sweep is CONSUMED — it is NOT surfaced as `Complete`, so there is nothing for the user to
  acknowledge and no per-run completion screen (the sweep zeroes the spendable Orchard balance, so
  the balance-gated "Migration Required" prompt does not re-offer unless new Orchard funds arrive
  later; an unmined sweep that expires likewise falls back to `NotStarted` so the prompt re-offers
  while funds remain). One row per account — a new record supersedes any previous one. Not
  broadcast-sensitive itself (no `migrationBroadcastDuringSync` guard): the actual broadcast already
  rides the guarded `createProposedTransactions`/`createTransactionFromPCZT` path.
- **`MigrationProgress` gains `isImmediate: Bool`** (additive — the public memberwise initializer
  defaults it to `false`, so existing `MigrationProgress(...)` construction sites keep compiling
  unchanged). It is `true` only while the immediate (send-max) lane's sweep is in progress and
  `false` for engine-tracked schedule runs, letting the app keep the immediate aftermath quiet (no
  per-transfer progress UI).
- **Removed** (internal welding surface, never reachable from outside the SDK):
  `ZcashRustBackendWelding.migrationProposeImmediateTransfers` and its FFI,
  `zcashlc_migration_propose_immediate_transfers`. Replaced by the general-purpose
  `proposeSendMaxTransfer(accountUUID:recipient:memo:orchardOnly:)` (called with `orchardOnly: true`
  and `recipient` set to the account's own address, `memo: nil`) — a plain "spend everything to one
  recipient" primitive the migration engine itself never touches.
- **`MigrationSchedule` itself is unaffected** and still backs `proposeMigrationTransfers` /
  `signAndStoreMigrationSchedule` (the gradual, privacy-path schedule).

## Residual locking and the run-count estimate join the migration group

The `Synchronizer` migration group gains three account-scoped requirements. Like the rest of the
group they come with protocol-extension defaults that throw an "unimplemented" `LocalizedError`, so
a custom `Synchronizer` conformer keeps compiling — but it must override them to offer the real
behavior (`SDKSynchronizer` does):

- **New: `lockMigrationResidual(accountUUID:) async throws -> Zatoshi`.** The "Lock balance" choice
  at migration `Complete`: locks every currently-spendable, not-already-locked legacy-Orchard note
  until explicit unlock and returns the total locked (`Zatoshi(0)` is legitimate — nothing was
  spendable). The lock never expires on its own; locked value leaves `PoolBalance.spendableValue`
  but stays in `PoolBalance.lockedValue` (and therefore in `total()`). Idempotent-additive:
  repeating the call locks (and reports) only notes that became spendable since. A concurrent-lock
  race throws (`rustMigrationLockResidual`, ZRUST0132) and may be retried.
- **New: `unlockMigrationResidual(accountUUID:) async throws -> Int`.** The release half: clears
  ALL of the account's output locks and returns the cleared count (safe — the SDK never creates
  proposal-scoped output locks). "Migrate anyway" over a locked residual composes as this call
  followed by `proposeImmediateMigration(accountUUID:)`; locked notes are excluded from note
  selection, so the unlock must come first.
- **New: `estimateMigrationRuns(accountUUID:) async throws -> MigrationRunEstimate`.** The rounds
  preview for the multi-round migration UI: how many migration RUNS ("rounds") migrating the whole
  spendable Orchard balance takes, per run both what it migrates and what preparing it costs, and
  the final residual that never migrates. External-signer session counts are a query on the result
  (`totalSigningSessions(maxTransactionsPerSession:)`), not a parameter. The zero-run estimate is a
  legitimate answer, not an error.

## The live per-transaction migration status read joins the migration group

The `Synchronizer` migration group gains one account-scoped requirement. Like the rest of the
group it comes with a protocol-extension default that throws an "unimplemented" `LocalizedError`,
so a custom `Synchronizer` conformer keeps compiling — but it must override it to offer the real
behavior (`SDKSynchronizer` does):

- **New: `migrationTransactionStatuses(accountUUID:) async throws -> [MigrationTransactionStatus]`.**
  The live per-transaction detail view behind `migrationProgress(accountUUID:)`'s aggregate
  summary: every committed migration transaction's kind (preparation layer/index or transfer
  crossing), lifecycle state (`broadcast`/`mined` fold the engine's txid/mined-height payload into
  the matching case, so illegal combinations are unrepresentable — a MINED row's txid is NOT
  carried by the engine's own state model), scheduled/expiry heights, readiness, and next
  action/blocker, keyed by a stable id. A verbatim marshal of the engine's own
  `MigrationState::transaction_statuses`, mined-reconciled at read like every sibling; an empty
  array means no stored run or no transactions, not an error. New error code
  `rustMigrationTransactionStatuses` (ZRUST0135).

## `prepare` now validates the seed against the existing wallet

If the wallet database already contains seed-derived account(s) and the seed passed to `prepare`
does not match them, `prepare` throws `ZcashError.initializerSeedMismatch` (`ZINIT0006`) instead of
silently opening the old wallet (which desynced the app's stored seed from the on-disk account).
Restoring a different wallet requires `wipe()` first. Wallets whose only accounts are imported
(hardware-wallet UFVKs) are exempt — there is no seed-derived account to compare.

PendingDb is no longer used. Wallet developers should take care about deleting
the database file since the SDK will no longer require it or any of the
information stored. 

Failed transactions will be treated as "Expired-Unmined" instead. The SDK won't 
track failures on its own. Wallet developers would have to account for those.

## Custom (regtest-style) networks and `NetworkType.regtest`

`NetworkType` gained a third case, `regtest`. **This is a source-breaking change for exhaustive
`switch` statements over `NetworkType`** — add a `.regtest` arm (or a `default`) when updating.

Custom networks let the SDK talk to a custom-parameter chain (for example a modified-mainnet
Ironwood testing backend) whose network upgrades activate at arbitrary heights:

- `ZcashNetworkBuilder.regtest(activationHeights:)` builds a regtest-identity network with the given
  `NetworkActivationHeights` (a `nil` height means "not activated"; the heights are not validated —
  mirror the `nuparams` of the node/`lightwalletd` you connect to).
- `ZcashNetworkBuilder.custom(base:activationHeights:)` combines a chosen base identity (address
  encoding + expected `chainName`, e.g. `.mainnet` for a modified-mainnet backend) with custom
  heights. On-disk databases still use the `regtest`-slot name prefix, so a custom network never
  collides with a real mainnet/testnet wallet in the same container.
- Server validation relaxes for custom networks: `ValidateServerAction` and
  `evaluateBestOf(endpoints:...)` skip the chain-name and consensus-branch-ID checks (the server of a
  modified chain may identify with its base chain's name and a nonstandard branch id). The
  Sapling-activation-height check still applies.

**Process-global registration and ordering.** The custom network's parameters are registered with
the Rust core **once per process** (the first `Initializer` created with a custom network does this).
Anything that resolves the custom network id before that registration — e.g. a
`DerivationTool(networkType: .regtest)` created before any `Initializer` — fails with
"custom network (id 2) used before it was configured", and key validators return `false`. Create the
`Initializer` first, or call `ZcashRustBackend.setCustomNetwork` yourself at startup. Registering a
**different** custom network later in the same process is a configuration bug: the newest values win
process-globally while earlier instances keep their own per-instance state (checkpoint sources,
constants), so the two desynchronize — the registration call reports this (and asserts in debug).

## Voting: submission contract and pre-1.0 database reset

The voting stack now rides upstream `zcash_voting` 1.0 (see the CHANGELOG for the full surface).
Two changes affect callers of the voting API directly:

- **`storeVoteTxHash` is what records submission.** Persisting the on-chain transaction hash now
  marks the vote submitted (submission state is derived from the stored hash and written atomically).
  Call `storeVoteTxHash` once the vote transaction is broadcast. `markVoteSubmitted` no longer stands
  alone — it re-applies that state idempotently (rejecting a conflicting hash) and throws if no hash
  has been stored yet. Any flow that previously called `markVoteSubmitted` as the submission mark must
  call `storeVoteTxHash` first.
- **Alpha-era voting databases are reset on open.** The voting database schema was rebuilt for 1.0;
  opening a voting database created by a 2.6.0-alpha build drops and recreates every voting table
  (rounds, votes, bundles, proofs, witnesses, share delegations, …). In-progress votes from an alpha
  build do not survive the upgrade and must be re-cast. This is the separate voting database only —
  wallet balances and the main wallet database are unaffected.

The voting hotkey contract also changed: `generateHotkey` takes `storedSecret:` (an app-owned
opaque secret) instead of `seed:`. Passing an empty array mints a fresh random hotkey; passing a
previously stored 64-byte secret deterministically reconstructs the same hotkey. Persisting that
secret is the only way to recover the same hotkey — the pre-1.0 seed-derived derivation is not
reproducible under 1.0.

## `Broadcaster` redesign (multi-server submission)

The `Broadcaster` API introduced in the 2.6.0-alpha tags has changed:

- Create APIs return `[CreatedTransaction]` (fields: `txId`, `raw` — non-optional, `expiryHeight`) instead of `[ZcashTransaction.Overview]`. The `.foundTransactions` event still emits overviews. A transaction created in a previous app session can be rebuilt for submission with `CreatedTransaction(overview:)`.
- `submit(_ rawTransaction: Data, to: LightWalletEndpoint)` is gone. Use:

```swift
let outcome = await synchronizer.broadcaster.submit(
    transaction: createdTransaction,
    to: endpoints           // [LightWalletEndpoint]; timing: defaults to SubmissionTiming.default
)
```

`submit` no longer throws — it returns a `TransactionSubmissionOutcome` (`accepted(by:)`, `rejected(code:message:)`, `unreachable`, `timedOut`, `notAttempted`, `cancelled`). Treat `timedOut` as pending: the transaction may still have been broadcast.

- Retry semantics: the endpoint list passed to `submit` is persisted as the transaction's retry plan. The SDK's background resubmission retries pending transactions through those endpoints (sequentially) instead of the synchronizer's default endpoint, and never auto-submits transactions created through `Broadcaster` that the app hasn't submitted yet. If the plan store cannot be read, background resubmission skips the affected transactions rather than falling back to the default endpoint. Plans are kept until the transaction expires (so a chain reorg cannot detach a transaction from its recorded endpoints), and `Synchronizer.wipe()` deletes the plan database file.
- The retry plan is recorded before any network attempt and stays recorded when `submit` returns `.cancelled` or `.timedOut`: background resubmission may still broadcast the transaction later. Treat those outcomes as "outcome unknown", not as "not sent".
- `LightWalletEndpoint` now conforms to `Equatable`. If your app declared that conformance retroactively, remove your declaration.

## `Initializer.InitializationResult` gained `.seedNotRelevant`

`Initializer.InitializationResult` (returned by `Initializer.initialize` and `Synchronizer.prepare`) gained a new case, `.seedNotRelevant`, returned when the rust layer reports that the provided seed does not match the accounts already present in the wallet database. Any exhaustive `switch` over `InitializationResult` must add a case for it. `prepare`/`initialize` can now return `.seedNotRelevant` in situations where they previously returned `.success` over a mismatched database — handle it the same way you already handle `.seedRequired`.

# Migrating from previous versions to 0.20.0-beta
The `SDKSynchronizer` no longer uses `NotificationCenter` to send notifications.
Notifications are replaced with `Combine` publishers.

`stateStream` publisher replaces notifications related to `SyncStatus` changes.
These notifications are replaced by `stateStream`:
- .synchronizerStarted
- .synchronizerProgressUpdated
- .synchronizerStatusWillUpdate
- .synchronizerSynced
- .synchronizerStopped
- .synchronizerDisconnected
- .synchronizerSyncing
- .synchronizerEnhancing
- .synchronizerFetching
- .synchronizerFailed

`eventStream` publisher replaces notifications related to transactions and other stuff.
These notifications are replaced by `eventStream`:
- .synchronizerMinedTransaction
- .synchronizerFoundTransactions
- .synchronizerStoredUTXOs
- .synchronizerConnectionStateChanged

`latestState` is also new property that can be used to get the latest SDK state in a synchronous way.
`SDKSynchronizer.status` is no longer public. To get `SyncStatus` either subscribe to `stateStream` 
or use `latestState`. 

# Migrating from previous versions to 0.18.x
Compact block cache no longer uses a sqlite database. The existing database
should be deleted. `Initializer` now takes an `fsBlockDbRootURL` which is a 
URL pointing to a RW directory in the filesystem that will be used to store
the cached blocks and the companion database managed internally by the SDK.

`Initializer` provides a convenience initializer that takes the an optional
URL to the `cacheDb` location to migrate the internal state of the 
`CompactBlockProcessor` and delete that database. 

````Swift
    convenience public init(
        cacheDbURL: URL?,
        fsBlockDbRoot: URL,
        dataDbURL: URL,
        pendingDbURL: URL,
        endpoint: LightWalletEndpoint,
        network: ZcashNetwork,
        spendParamsURL: URL,
        outputParamsURL: URL,
        viewingKeys: [UnifiedFullViewingKey],
        walletBirthday: BlockHeight,
        alias: String = "",
        loggerProxy: Logger? = nil
    )
````

We do not make any efforts to extract the cached blocks in the sqlite
`cacheDb` and storing them on disk. Although this might be the logical 
step to do, we think such migration as little to gain since a migration
function will be a "run once" function with many different scenarios to
consider and possibly very error prone. On the other hand, we rather delete
the `cacheDb` altogether and free up that space on the users' devices since
we have surveyed that the `cacheDb` as been growing exponentially taking up
many gigabyte of disk space. We forsee that many possible attempts to copy
information from one cache to another, would possibly fail 

Consuming block cache information for other purposes is discouraged. Users
must not make assumptions on its contents or rely on its contents in any way. 
Maintainers assume that this state is internal and won't consider further
uses other than the intended for the current development. If you consider
your application needs any other information than the ones available through
public APIs, please file the corresponding feature request.

# Migrating from 0.16.x-beta to 0.17.0-alpha.x

## Changes to Demo APP
The demo application now uses the SDKSynchronizer to create addresses and
shield funds.
`DerivationToolViewController` was removed. See `DerivationTool` unit tests
for sample code.
`GetAddressViewController` now derives transparent and sapling addresses
from Unified Address
`SendViewController` uses Unified Spending Key and type-safe `Memo`

## Changes To SDK
### `CompactBlockProcessor`
`public func getUnifiedAddress(accountIndex: Int) -> UnifiedAddress?`
`public func getSaplingAddress(accountIndex: Int) -> SaplingAddress?` derived from UA
`public func getTransparentAddress(accountIndex: Int) -> TransparentAddress?`
is derived from UA
`public func getTransparentBalance(accountIndex: Int) throws -> WalletBalance` now
fetches from account exclusively
`func refreshUTXOs(tAddress: TransparentAddress, startHeight: BlockHeight) async throws -> RefreshedUTXOs`
uses `TransparentAddress`

### Initializer
Migration of DataDB and CacheDB are delegated to `librustzcash`

removed `public func getAddress(index account: Int = 0) -> String`


### Wallet Types
`UnifiedSpendingKey` to represent Unified Spending Keys. This is a binary
encoded not meant to be stored or backed up. This only serves the purpose
of letting clients use the least privilege keys at all times for every
operation.

### Synchronizer
`sendToAddress` and `shieldFunds` now take a `UnifiedSpendingKey` instead
of the respective spending and transparent private keys.
`refreshUTXOs` uses `TransparentAddress`

### KeyDeriving protocol
Addresses should be obtained from the `Synchronizer` by using the `get_address` functions
Transparent and Sapling receivers should be obtained by extracting the receivers of a UA
````Swift
public extension UnifiedAddress {
    /// Extracts the sapling receiver from this UA if available
    /// - Returns: an `Optional<SaplingAddress>`
    func saplingReceiver() -> SaplingAddress? {
        try? DerivationTool.saplingReceiver(from: self)
    }

    /// Extracts the transparent receiver from this UA if available
    /// - Returns: an `Optional<TransparentAddress>`
    func transparentReceiver() -> TransparentAddress? {
        try? DerivationTool.transparentReceiver(from: self)
    }
````

**Removed**
`func deriveUnifiedFullViewingKeys(seed: [UInt8], numberOfAccounts: Int) throws -> [UnifiedFullViewingKey]`
`func deriveViewingKey(spendingKey: SaplingExtendedSpendingKey) throws -> SaplingExtendedFullViewingKey`
`func deriveSpendingKeys(seed: [UInt8], numberOfAccounts: Int) throws -> [SaplingExtendedSpendingKey]`
`func deriveUnifiedAddress(from ufvk: UnifiedFullViewingKey) throws -> UnifiedAddress`
`func deriveTransparentAddress(seed: [UInt8], account: Int, index: Int) throws -> TransparentAddress`
`func deriveTransparentAccountPrivateKey(seed: [UInt8], account: Int) throws -> TransparentAccountPrivKey`
`func deriveTransparentAddressFromAccountPrivateKey(_ xprv: TransparentAccountPrivKey, index: Int) throws -> TransparentAddress`

**Added**
`static func saplingReceiver(from unifiedAddress: UnifiedAddress) throws -> SaplingAddress?`
`static func transparentReceiver(from unifiedAddress: UnifiedAddress) throws -> TransparentAddress?`
`static func receiverTypecodesFromUnifiedAddress(_ address: UnifiedAddress) throws -> [UnifiedAddress.ReceiverTypecodes]`
`func deriveUnifiedSpendingKey(seed: [UInt8], accountIndex: Int) throws -> UnifiedSpendingKey`
`public func deriveUnifiedFullViewingKey(from spendingKey: UnifiedSpendingKey) throws -> UnifiedFullViewingKey`

## Notes on Structured Concurrency

`CompactBlockProcessor` is now an Swift Actor. This makes it more robust and have its own
async environment.

SDK Clients will likely be affected by some `async` methods on `SDKSynchronizer`.

We recommend clients that don't support structured concurrency features, to work around this by  surrounding the these function calls either in @MainActor contexts either by marking callers as @MainActor or launching tasks on that actor with `Task { @MainActor in ... }`

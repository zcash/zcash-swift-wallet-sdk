//
//  ZcashRustBackendWelding.swift
//  ZcashLightClientKit
//
//  Created by Francisco 'Pacu' Gindre on 2019-12-09.
//  Copyright © 2019 Electric Coin Company. All rights reserved.
//

import Foundation

typealias LCZip32Index = Int32

enum ZcashRustBackendWeldingConstants {
    static let validChain: Int32 = -1
}

/// Enumeration of potential return states for database initialization.
///
/// If `seedRequired` is returned, the caller must re-attempt initialization providing the seed.
public enum DbInitResult {
    case success
    case seedRequired
    case seedNotRelevant
}

/// Enumeration of potential return states for database rewind.
///
public enum RewindResult {
    /// The rewind succeeded. The associated block height indicates the maximum height of
    /// stored block data retained by the database; this may be less than the block height that
    /// was requested.
    case success(BlockHeight)
    /// The rewind did not succeed but the caller may re-attempt given the associated block height.
    case requestedHeightTooLow(BlockHeight)
}

protocol ZcashRustBackendWelding {
    /// Returns a list of the accounts in the wallet.
    func listAccounts() async throws -> [Account]

    /// Adds a new account to the wallet by importing the UFVK that will be used to detect incoming
    /// payments.
    ///
    /// Derivation metadata may optionally be included. To indicate that no derivation metadata is
    /// available, `seedFingerprint` and `zip32AccountIndex` should be set to `nil`. Derivation
    /// metadata will not be stored unless both the seed fingerprint and the HD account index are
    /// provided.
    ///
    /// - Returns: the globally unique identifier for the account.
    // swiftlint:disable:next function_parameter_count
    func importAccount(
        ufvk: String,
        seedFingerprint: [UInt8]?,
        zip32AccountIndex: Zip32AccountIndex?,
        treeState: TreeState,
        recoverUntil: UInt32?,
        purpose: AccountPurpose,
        name: String,
        keySource: String?
    ) async throws -> AccountUUID

    /// Adds the next available account-level spend authority, given the current set of [ZIP 316]
    /// account identifiers known, to the wallet database.
    ///
    /// Returns the newly created [ZIP 316] account identifier, along with the binary encoding of the
    /// [`UnifiedSpendingKey`] for the newly created account.  The caller should manage the memory of
    /// (and store) the returned spending keys in a secure fashion.
    ///
    /// If `seed` was imported from a backup and this method is being used to restore a
    /// previous wallet state, you should use this method to add all of the desired
    /// accounts before scanning the chain from the seed's birthday height.
    ///
    /// By convention, wallets should only allow a new account to be generated after funds
    /// have been received by the currently-available account (in order to enable
    /// automated account recovery).
    /// - parameter seed: byte array of the zip32 seed
    /// - parameter treeState: The TreeState Protobuf object for the height prior to the account birthday
    /// - parameter recoverUntil: the fully-scanned height up to which the account will be treated as "being recovered"
    /// - Returns: The `UnifiedSpendingKey` structs for the number of accounts created
    /// - Throws: `rustCreateAccount`.
    func createAccount(
        seed: [UInt8],
        treeState: TreeState,
        recoverUntil: UInt32?,
        name: String,
        keySource: String?
    ) async throws -> UnifiedSpendingKey

    /// Checks whether the given seed is relevant to any of the derived accounts in the wallet.
    ///
    /// - parameter seed: byte array of the seed
    func isSeedRelevantToAnyDerivedAccount(seed: [UInt8]) async throws -> Bool

    /// Scans a transaction for any information that can be decrypted by the accounts in the wallet, and saves it to the wallet.
    /// - parameter tx:     the transaction to decrypt
    /// - parameter minedHeight: height on which this transaction was mined. this is used to fetch the consensus branch ID.
    /// - Returns: The transaction's ID.
    /// - Throws: `rustDecryptAndStoreTransaction`.
    func decryptAndStoreTransaction(txBytes: [UInt8], minedHeight: UInt32?) async throws -> Data

    /// Returns the most-recently-generated unified payment address for the specified account.
    /// - parameter account: index of the given account
    /// - Throws:
    ///     - `rustGetCurrentAddress` if rust layer returns error.
    ///     - `rustGetCurrentAddressInvalidAddress` if generated unified address isn't valid.
    func getCurrentAddress(accountUUID: AccountUUID) async throws -> UnifiedAddress

    /// Returns a newly-generated unified payment address for the specified account, with the next available diversifier.
    /// - parameter account: index of the given account
    /// - parameter receiverFlags: bitflags specifying which receivers to include in the address.
    /// - Throws:
    ///     - `rustGetNextAvailableAddress` if rust layer returns error.
    ///     - `rustGetNextAvailableAddressInvalidAddress` if generated unified address isn't valid.
    func getNextAvailableAddress(accountUUID: AccountUUID, receiverFlags: UInt32) async throws -> UnifiedAddress

    /// Get memo from note.
    /// - parameter txId: ID of transaction containing the note
    /// - parameter outputPool: output pool identifier (2 = Sapling, 3 = Orchard)
    /// - parameter outputIndex: output index of note
    func getMemo(txId: Data, outputPool: UInt32, outputIndex: UInt16) async throws -> Memo?

    /// Get the verified cached transparent balance for the given address
    /// - parameter account; the account index to query
    /// - Throws:
    ///     - `rustGetTransparentBalanceNegativeAccount` if `account` is < 0.
    ///     - `rustGetTransparentBalance` if rust layer returns error.
    func getTransparentBalance(accountUUID: AccountUUID) async throws -> Int64

    /// Initializes the data db. This will performs any migrations needed on the sqlite file
    /// provided. Some migrations might need that callers provide the seed bytes.
    /// - Parameter seed: ZIP-32 compliant seed bytes for this wallet
    /// - Returns: `DbInitResult.success` if the dataDb was initialized successfully
    /// or `DbInitResult.seedRequired` if the operation requires the seed to be passed
    /// in order to be completed successfully.
    /// Throws `rustInitDataDb` if rust layer returns error.
    func initDataDb(seed: [UInt8]?) async throws -> DbInitResult

    /// Returns a list of the transparent receivers for the diversified unified addresses that have
    /// been allocated for the provided account.
    /// - parameter account: index of the given account
    /// - Throws:
    ///     - `rustListTransparentReceivers` if rust layer returns error.
    ///     - `rustListTransparentReceiversInvalidAddress` if transarent received generated by rust is invalid.
    func listTransparentReceivers(accountUUID: AccountUUID) async throws -> [TransparentAddress]

    /// Get the verified cached transparent balance for the given account
    /// - parameter account: account index to query the balance for.
    /// - Throws:
    ///     - `rustGetVerifiedTransparentBalanceNegativeAccount` if `account` is < 0.
    ///     - `rustGetVerifiedTransparentBalance` if rust layer returns error.
    func getVerifiedTransparentBalance(accountUUID: AccountUUID) async throws -> Int64

    /// Resets the state of the database to only contain block and transaction information up to the given height. clears up all derived data as well
    /// - parameter height: height to rewind to.
    /// - Throws: `rustRewindToHeight` if rust layer returns error.
    func rewindToHeight(height: BlockHeight) async throws -> RewindResult

    /// Truncates the data database to the specified chain state.
    ///
    /// In contrast to `rewindToHeight`, this method allows the caller to truncate the wallet database to a precise
    /// height by providing additional chain state information needed for note commitment tree maintenance after the
    /// truncation.
    /// - parameter chainState: the `TreeState` representing the chain state at the height to truncate to.
    /// - Throws: `rustTruncateToChainState` if rust layer returns error.
    func truncateToChainState(chainState: TreeState) async throws

    /// Resets the state of the FsBlock database to only contain block and transaction information up to the given height.
    /// - Note: this does not delete the files. Only rolls back the database.
    /// - parameter height: height to rewind to. This should be the height returned by a successful `rewindToHeight` call.
    /// - Throws: `rustRewindCacheToHeight` if rust layer returns error.
    func rewindCacheToHeight(height: Int32) async throws

    func putSaplingSubtreeRoots(startIndex: UInt64, roots: [SubtreeRoot]) async throws

    func putOrchardSubtreeRoots(startIndex: UInt64, roots: [SubtreeRoot]) async throws

    /// Adds a sequence of Ironwood (Orchard note-version V3 / NU6.3) subtree roots to the data store.
    func putIronwoodSubtreeRoots(startIndex: UInt64, roots: [SubtreeRoot]) async throws

    /// Updates the wallet's view of the blockchain.
    ///
    /// This method is used to provide the wallet with information about the state of the blockchain,
    /// and detect any previously scanned data that needs to be re-validated before proceeding with
    /// scanning. It should be called at wallet startup prior to calling `suggestScanRanges`
    /// in order to provide the wallet with the information it needs to correctly prioritize scanning
    /// operations.
    func updateChainTip(height: Int32) async throws

    /// Returns the height to which the wallet has been fully scanned.
    ///
    /// This is the height for which the wallet has fully trial-decrypted this and all
    /// preceding blocks beginning with the wallet's birthday height.
    func fullyScannedHeight() async throws -> BlockHeight?

    /// Returns the maximum height that the wallet has scanned.
    ///
    /// If the wallet is fully synced, this will be equivalent to `fullyScannedHeight`;
    /// otherwise the maximal scanned height is likely to be greater than the fully scanned
    /// height due to the fact that out-of-order scanning can leave gaps.
    func maxScannedHeight() async throws -> BlockHeight?

    /// Returns the account balances and sync status of the wallet.
    func getWalletSummary() async throws -> WalletSummary?

    /// Returns a list of suggested scan ranges based upon the current wallet state.
    ///
    /// This method should only be used in cases where the `CompactBlock` data that will be
    /// made available to `scanBlocks` for the requested block ranges includes note
    /// commitment tree size information for each block; or else the scan is likely to fail if
    /// notes belonging to the wallet are detected.
    func suggestScanRanges() async throws -> [ScanRange]

    /// Scans new blocks added to the cache for any transactions received by the tracked
    /// accounts, while checking that they form a valid chan.
    ///
    /// This function is built on the core assumption that the information provided in the
    /// block cache is more likely to be accurate than the previously-scanned information.
    /// This follows from the design (and trust) assumption that the `lightwalletd` server
    /// provides accurate block information as of the time it was requested.
    ///
    /// This function **assumes** that the caller is handling rollbacks.
    ///
    /// For brand-new light client databases, this function starts scanning from the Sapling
    /// activation height. This height can be fast-forwarded to a more recent block by calling
    /// [`initBlocksTable`] before this function.
    ///
    /// Scanned blocks are required to be height-sequential. If a block is missing from the
    /// cache, an error will be signalled.
    ///
    /// - parameter fromHeight: scan starting from the given height.
    /// - parameter fromState: The TreeState Protobuf object for the height prior to `fromHeight`
    /// - parameter limit: scan up to limit blocks.
    /// - Throws: `rustScanBlocks` if rust layer returns error.
    func scanBlocks(fromHeight: Int32, fromState: TreeState, limit: UInt32) async throws -> ScanSummary

    /// Upserts a UTXO into the data db database
    /// - parameter txid: the txid bytes for the UTXO
    /// - parameter index: the index of the UTXO
    /// - parameter script: the script of the UTXO
    /// - parameter value: the value of the UTXO
    /// - parameter height: the mined height for the UTXO
    /// - Throws: `rustPutUnspentTransparentOutput` if rust layer returns error.
    func putUnspentTransparentOutput(
        txid: [UInt8],
        index: Int,
        script: [UInt8],
        value: Int64,
        height: BlockHeight
    ) async throws

    /// Select transaction inputs, compute fees, and construct a proposal for a transaction
    /// that can then be authorized and made ready for submission to the network with
    /// `createProposedTransaction`.
    ///
    /// - parameter account: index of the given account
    /// - Parameter to: recipient address
    /// - Parameter value: transaction amount in Zatoshi
    /// - Parameter memo: the `MemoBytes` for this transaction. pass `nil` when sending to transparent receivers
    /// - Throws: `rustCreateToAddress`.
    func proposeTransfer(
        accountUUID: AccountUUID,
        to address: String,
        value: Int64,
        memo: MemoBytes?
    ) async throws -> FfiProposal

    /// Select transaction inputs, compute fees, and construct a proposal for a transaction
    /// that can then be authorized and made ready for submission to the network with
    /// `createProposedTransaction` from a valid [ZIP-321](https://zips.z.cash/zip-0321) Payment Request UR
    ///
    /// - parameter uri: the URI String that the proposal will be made from.
    /// - parameter account: index of the given account
    /// - Throws: `rustCreateToAddress`.
    func proposeTransferFromURI(
        _ uri: String,
        accountUUID: AccountUUID
    ) async throws -> FfiProposal

    /// Constructs a transaction proposal to shield all found UTXOs in data db for the given account,
    /// that can then be authorized and made ready for submission to the network with
    /// `createProposedTransaction`.
    ///
    /// Returns the proposal, or `nil` if the transparent balance that would be shielded
    /// is zero or below `shieldingThreshold`.
    ///
    /// - parameter account: index of the given account
    /// - Parameter memo: the `Memo` for this transaction
    /// - Parameter transparentReceiver: a specific transparent receiver within the account
    ///             that should be the source of transparent funds. Default is `nil` which
    ///             will select whichever of the account's transparent receivers has funds
    ///             to shield.
    /// - Throws: `rustShieldFunds` if rust layer returns error.
    func proposeShielding(
        accountUUID: AccountUUID,
        memo: MemoBytes?,
        shieldingThreshold: Zatoshi,
        transparentReceiver: String?
    ) async throws -> FfiProposal?

    /// Creates a transaction from the given proposal.
    /// - Parameter proposal: the transaction proposal.
    /// - Parameter usk: `UnifiedSpendingKey` for the account that controls the funds to be spent.
    /// - Throws: `rustCreateToAddress`.
    func createProposedTransactions(
        proposal: FfiProposal,
        usk: UnifiedSpendingKey
    ) async throws -> [Data]

    /// Creates a partially-created (unsigned without proofs) transaction from the given proposal.
    ///
    /// Do not call this multiple times in parallel, or you will generate PCZT instances that, if
    /// finalized, would double-spend the same notes.
    ///
    /// - Parameter accountUUID: The account for which the proposal was created.
    /// - Parameter proposal: The proposal for which to create the transaction.
    /// - Returns The partially created transaction in [Pczt] format.
    ///
    /// - Throws rustCreatePCZTFromProposal as a common indicator of the operation failure
    func createPCZTFromProposal(accountUUID: AccountUUID, proposal: FfiProposal) async throws -> Pczt

    /// Redacts information from the given PCZT that is unnecessary for the Signer role.
    ///
    /// - Parameter pczt: The partially created transaction in its serialized format.
    ///
    /// - Returns The updated PCZT in its serialized format.
    ///
    /// - Throws  rustRedactPCZTForSigner as a common indicator of the operation failure
    func redactPCZTForSigner(pczt: Pczt) async throws -> Pczt

    /// Checks whether the caller needs to have downloaded the Sapling parameters.
    ///
    /// - Parameter pczt: The partially created transaction in its serialized format.
    ///
    /// - Returns `true` if this PCZT requires Sapling proofs.
    func PCZTRequiresSaplingProofs(pczt: Pczt) async -> Bool

    /// Adds proofs to the given PCZT.
    ///
    /// - Parameter pczt: The partially created transaction in its serialized format.
    ///
    /// - Returns The updated PCZT in its serialized format.
    ///
    /// - Throws  rustAddProofsToPCZT as a common indicator of the operation failure
    func addProofsToPCZT(pczt: Pczt) async throws -> Pczt

    /// Takes a PCZT that has been separately proven and signed, finalizes it, and stores
    /// it in the wallet. Internally, this logic also submits and checks the newly stored and encoded transaction.
    ///
    /// - Parameter pcztWithProofs
    /// - Parameter pcztWithSigs
    ///
    /// - Returns The submission result of the completed transaction.
    ///
    /// - Throws  PcztException.ExtractAndStoreTxFromPcztException as a common indicator of the operation failure
    func extractAndStoreTxFromPCZT(pcztWithProofs: Pczt, pcztWithSigs: Pczt) async throws -> Data

    /// Gets the consensus branch id for the given height
    /// - Parameter height: the height you what to know the branch id for
    /// - Throws: `rustNoConsensusBranchId` if rust layer returns error.
    func consensusBranchIdFor(height: Int32) throws -> Int32

    /// Initializes Filesystem based block cache
    /// - Throws: `rustInitBlockMetadataDb` if rust layer returns error.
    func initBlockMetadataDb() async throws

    /// Write compact block metadata to a database known to the Rust layer
    /// - Parameter blocks: The `ZcashCompactBlock`s that are going to be marked as stored by the metadata Db.
    /// - Throws:
    ///     - `rustWriteBlocksMetadataAllocationProblem` if there problem with allocating memory on Swift side.
    ///     - `rustWriteBlocksMetadata` if there is problem with writing blocks metadata.
    func writeBlocksMetadata(blocks: [ZcashCompactBlock]) async throws

    /// Gets the latest block height stored in the filesystem based cache.
    /// -  Parameter fsBlockDbRoot: `URL` pointing to the filesystem root directory where the fsBlock cache is.
    /// this directory  is expected to contain a `/blocks` sub-directory with the blocks stored in the convened filename
    /// format `{height}-{hash}-block`. This directory has must be granted both write and read permissions.
    /// - Returns `BlockHeight` of the latest cached block or `.empty` if no blocks are stored.
    func latestCachedBlockHeight() async throws -> BlockHeight

    /// Returns an array of [`TransactionDataRequest`] values that describe information needed by
    /// the wallet to complete its view of transaction history.
    ///
    /// Requests for the same transaction data may be returned repeatedly by successive data
    /// requests. The caller of this method should consider the latest set of requests returned
    /// by this method to be authoritative and to subsume that returned by previous calls.
    func transactionDataRequests() async throws -> [TransactionDataRequest]

    /// Updates the wallet backend with respect to the status of a specific transaction, from the
    /// perspective of the main chain.
    ///
    /// Fully transparent transactions, and transactions that do not contain either shielded inputs
    /// or shielded outputs belonging to the wallet, may not be discovered by the process of chain
    /// scanning; as a consequence, the wallet must actively query to determine whether such
    /// transactions have been mined.
    func setTransactionStatus(txId: Data, status: TransactionStatus) async throws

    /// Fix witnesses - addressing note commitment tree bug.
    /// This function is supposed to be called occasionaly. It's handled by the SDK Synchronizer and called only once per version.
    func fixWitnesses() async

    /// Get an ephemeral single use transparent address
    func getSingleUseTransparentAddress(accountUUID: AccountUUID) async throws -> SingleUseTransparentAddress

    /// Attempts to delete an account defined by UUID
    func deleteAccount(_ accountUUID: AccountUUID) async throws

    // MARK: - Ironwood migration

    /// Current Orchard -> Ironwood migration state for `account`. This is also the reconciliation
    /// hub: call it on launch and after every migration-related operation.
    /// - Throws: `rustMigrationState` if the rust layer returns an error.
    func migrationState(for account: AccountUUID) async throws -> MigrationState

    /// Live migration progress, or `nil` when no migration is in progress.
    /// - Throws: `rustMigrationProgress` if the rust layer returns an error.
    func migrationProgress(for account: AccountUUID) async throws -> MigrationProgress?

    /// Whether the Orchard notes must be split before migration.
    ///
    /// - Throws: `rustMigrationIsNoteSplitNeeded` if the rust layer returns an error. In particular,
    ///   on a wallet that has never completed a sync (no chain tip known) this throws rather than
    ///   returning `false`.
    func migrationIsNoteSplitNeeded(for account: AccountUUID) async throws -> Bool

    /// Whether any scheduled transfer is past its send height but not yet broadcast.
    /// - Throws: `rustMigrationHasOverdueTransfers` if the rust layer returns an error.
    func migrationHasOverdueTransfers(for account: AccountUUID) async throws -> Bool

    /// Whether the migration is in an invalid state (spendable Orchard remains but no scheduled
    /// transfer covers it).
    /// - Throws: `rustMigrationHasInvalidTransfers` if the rust layer returns an error.
    func migrationHasInvalidTransfers(for account: AccountUUID) async throws -> Bool

    /// The optimal note split for the spendable Orchard balance.
    /// - Throws: `rustMigrationPrepareNoteSplit` if the rust layer returns an error.
    func migrationPrepareNoteSplit(for account: AccountUUID) async throws -> NoteSplitProposal

    /// Builds, signs, and persists the note-split transaction; returns the broadcastable prepared
    /// transfer. Only `proposal.proposalHandle` crosses to the native side — it identifies the
    /// exact cached plan the user was shown, and the native side refuses to sign any other plan,
    /// so a stale display cannot sign different values than the ones the user approved.
    /// - Throws: `migrationPlanStale` when the identified plan is missing (process restart
    ///   between propose and confirm) or superseded by a later propose/prepare call, and no
    ///   resumable run is stored — re-propose and re-display; `rustMigrationSignNoteSplit` for
    ///   other rust-layer errors.
    func migrationSignNoteSplit(
        proposal: NoteSplitProposal,
        usk: UnifiedSpendingKey,
        for account: AccountUUID
    ) async throws -> PreparedMigrationTransfer

    /// The leftover Orchard balance a migration would not cross, when it is large enough to be
    /// worth offering the user a choice about; `nil` when there is no such residual.
    ///
    /// - Throws: `rustMigrationResidualAfterMigration` if the rust layer returns an error. In
    ///   particular, on a wallet that has never completed a sync (no chain tip known) this throws
    ///   rather than returning `nil`.
    func migrationResidualAfterMigration(for account: AccountUUID) async throws -> Zatoshi?

    /// Locks EVERY currently-spendable, not-already-locked legacy-Orchard note of the account
    /// until explicit unlock and returns the total value locked (`Zatoshi(0)` when nothing was
    /// spendable — a legitimate result). Intended to be called at migration `Complete` to lock
    /// the sub-threshold residual that stays in Orchard (the "Lock balance" choice); the lock
    /// never expires on its own, so only `unlockMigrationResidual` releases it. Already-locked
    /// notes are excluded from selection, so repeating the call locks (and reports) only notes
    /// that became spendable since. Locked value leaves `PoolBalance.spendableValue` but stays
    /// in `PoolBalance.lockedValue` (and therefore in `total()`).
    /// - Throws: `rustMigrationLockResidual` if the rust layer returns an error (including a
    ///   concurrent-lock race, which the caller may retry).
    func lockMigrationResidual(accountUUID: AccountUUID) async throws -> Zatoshi

    /// Unlocks the account's locked outputs — the release half of `lockMigrationResidual` — and
    /// returns the number of outputs unlocked (`0` when nothing was locked). Clears ALL locks
    /// held for the account; that blanket clear is safe because the SDK never creates
    /// proposal-scoped output locks.
    /// - Throws: `rustMigrationUnlockResidual` if the rust layer returns an error.
    func unlockMigrationResidual(accountUUID: AccountUUID) async throws -> Int

    /// Estimates how the account migrates its whole spendable Orchard balance: the number of
    /// migration RUNS ("rounds") it takes, and for each run both what it migrates and what
    /// preparing it costs, so the platform can preview and compare the two — including external-
    /// signer session counts for any per-session capacity — before anything is planned or
    /// committed. A zero (or fully sub-quantum) balance yields the ZERO-RUN estimate
    /// (`runCount == 0`), a legitimate answer, not an error.
    /// - Throws: `rustMigrationEstimateRuns` if the rust layer returns an error.
    func estimateMigrationRuns(accountUUID: AccountUUID) async throws -> MigrationRunEstimate

    /// The full migration schedule for the spendable Orchard balance.
    /// - Throws: `rustMigrationProposeTransfers` if the rust layer returns an error.
    func migrationProposeTransfers(for account: AccountUUID) async throws -> MigrationSchedule

    /// Proposes a "send everything" transaction that sweeps the account's whole spendable balance
    /// (minus the ZIP-317 fee) to a single recipient, restricted to the given shielded-pool scope.
    /// Used by the Orchard -> Ironwood immediate migration lane (``OrchardMigration/proposeImmediateMigration()``,
    /// `orchardOnly: true`) to sweep the account's spendable Orchard notes to its own address,
    /// entirely outside the migration engine -- the returned proposal is an ORDINARY proposal, held
    /// by the caller like any other transfer.
    ///
    /// - Parameter accountUUID: index of the given account.
    /// - Parameter recipient: recipient address.
    /// - Parameter memo: the `MemoBytes` for this transaction. Pass `nil` when sending to transparent receivers.
    /// - Parameter orchardOnly: when `true`, restricts spendable notes to the Orchard pool alone (the
    ///   immediate migration sweep, which must not draw on Sapling funds); when `false`, spends from
    ///   both Sapling and Orchard (pre-existing behavior).
    /// - Throws: `rustProposeSendMaxTransfer` if the rust layer returns an error.
    func proposeSendMaxTransfer(
        accountUUID: AccountUUID,
        recipient: String,
        memo: MemoBytes?,
        orchardOnly: Bool
    ) async throws -> FfiProposal

    /// Pre-signs and persists every transfer in `schedule` (a no-op when a matching non-terminal
    /// run is already stored — the normal case, since the note-split submission commits the run).
    /// Only `schedule.proposalHandle` crosses to the native side — the schedule's display fields
    /// are never echoed back. A fresh commit signs exactly the cached plan the handle identifies;
    /// the resume/no-op case does not consult the handle (the stored run is durable, already
    /// handle-verified state).
    /// - Throws: `migrationPlanStale` when nothing is committed and the identified plan is
    ///   missing (process restart) or superseded by a later propose/prepare call — re-propose
    ///   and re-display the new schedule before retrying; `rustMigrationSignAndStoreSchedule`
    ///   for other rust-layer errors.
    func migrationSignAndStoreSchedule(
        _ schedule: MigrationSchedule,
        usk: UnifiedSpendingKey,
        for account: AccountUUID
    ) async throws

    /// The next height-due pre-signed transfer, or `nil` when nothing is currently due.
    /// - Throws: `rustMigrationNextDueTransfer` if the rust layer returns an error.
    func migrationNextDueTransfer(for account: AccountUUID) async throws -> PreparedMigrationTransfer?

    /// The next height-due scheduled transfer's full proposal (amount, anchor, timing) for the
    /// active run, or `nil` when nothing is currently pending (no active run, or only the note-split
    /// prep is pending). The proposal-level counterpart of `migrationNextDueTransfer`: it exposes the
    /// heights (notably `nextExecutableAfterHeight`) so a host can re-arm its own background window
    /// without parsing the signed PCZT.
    /// - Throws: `rustMigrationPendingTransferProposal` if the rust layer returns an error.
    func migrationPendingTransferProposal(for account: AccountUUID) async throws -> MigrationTransferProposal?

    /// Extracts the broadcast-ready consensus transaction bytes from a signed PCZT (the
    /// `PreparedMigrationTransfer.pczt` returned by `migrationNextDueTransfer` or
    /// `migrationSignNoteSplit`).
    /// - Throws: `rustMigrationExtractBroadcastTx` if the rust layer returns an error.
    func migrationExtractBroadcastTx(pczt: Data, for account: AccountUUID) async throws -> Data

    /// Records the platform's broadcast outcome for `transferId`, advancing the engine's state.
    /// - Throws: `rustMigrationRecordTransferResult` if the rust layer returns an error;
    ///           `migrationInvalidTxId` if `result` is `.success` and its `txId` does not decode
    ///           to a 32-byte transaction id.
    func migrationRecordTransferResult(
        transferId: String,
        result: MigrationTransferResult,
        for account: AccountUUID
    ) async throws

    /// Records a broadcast immediate-migration sweep (an ordinary send-max transaction proposed via
    /// ``proposeSendMaxTransfer(accountUUID:recipient:memo:orchardOnly:)`` with `orchardOnly: true`,
    /// built entirely outside the migration engine) so the platform's migration state machine
    /// reports it: `InProgress` (0 of 1) while unmined, `Complete` once mined, or a re-offer
    /// (`NotStarted`) if it expires unmined. One row per account: a new record supersedes any
    /// previous one.
    /// - Parameter txid: the swept transaction's id, in the SDK's raw/internal byte order (32 bytes).
    /// - Throws: `migrationRecordImmediateRunInvalidTxId` if `txid` is not exactly 32 bytes (checked
    ///   before any FFI call, since the C side reads it as a fixed 32-byte buffer). Otherwise
    ///   `rustMigrationRecordImmediateRun` if the rust layer returns an error (including "no chain
    ///   tip yet" on a wallet that has never completed a sync).
    func migrationRecordImmediateRun(txid: Data, for account: AccountUUID) async throws

    /// Cancels the stored run (its pre-signed transactions are abandoned; already-broadcast ones
    /// are unaffected on-chain), clears the invalid marks, and previews a fresh schedule against
    /// the live balance for the re-confirm lane.
    /// - Throws: `rustMigrationRestartStep` if the rust layer returns an error.
    func migrationRestartStep(for account: AccountUUID) async throws -> MigrationSchedule

    /// Rebuilds every EXPIRED transfer of the stored migration run in place through the engine:
    /// each rebuilt transfer re-spends the SAME funding note (recovered from the expired PCZT by
    /// nullifier identity, never an equal-value substitute) on a fresh schedule — a fresh
    /// memoryless delay from the current tip, a fresh canonical expiry, and a freshly drawn
    /// boundary anchor. Passing a spending key signs each rebuilt transfer anew in-process;
    /// passing `nil` (an external-signer account, whose spend authority never exists on this
    /// device) leaves it awaiting its signature, so the `migrationCreateUnsignedTransferPczts` /
    /// `migrationStoreSignedSchedulePczts` ceremony re-serves and completes it.
    ///
    /// Returns the run's FULL transfer schedule as stored AFTER the refresh — the same shape
    /// `migrationRestartStep` returns, here read from the persisted run (its `proposalHandle` is
    /// `0`: a stored run is durable, already handle-verified state that commit-shaped calls
    /// resume without consulting a handle). The rebuilt state persists all-or-nothing, and the
    /// returned schedule is that atomically-persisted truth for the host to re-display (a
    /// rebuilt transfer's fresh scheduled/expiry heights exist nowhere else). With nothing
    /// expired the current stored schedule comes back unchanged; with no stored run, or a
    /// terminal (completed or cancelled) one, the schedule is empty.
    /// - Throws: `rustMigrationRefreshStaleTransfers` if the rust layer returns an error —
    ///   notably when an expired transfer's funding note was spent outside the migration, where
    ///   the message names `restartCurrentMigrationStep` (cancel and re-plan) as the remedy. On
    ///   any throw nothing was persisted.
    func migrationRefreshStaleTransfers(
        usk: UnifiedSpendingKey?,
        for account: AccountUUID
    ) async throws -> MigrationSchedule

    /// Builds the whole previewed migration UNSIGNED for an external signer — the run is created
    /// by this call, with every transaction persisted awaiting its signature — and returns the
    /// preparation (note-split) subset of the PCZTs for the signing ceremony. The transfer subset
    /// of the same build is served by `migrationCreateUnsignedTransferPczts`. Resumes a stored
    /// non-terminal run; replaces a terminal one (the sequential-runs path). Only
    /// `schedule.proposalHandle` crosses to the native side: the run is built from exactly the
    /// cached plan the user-reviewed schedule identifies.
    /// - Throws: `migrationPlanStale` when the identified plan is missing (process restart) or
    ///   superseded by a later propose/prepare call — re-propose and re-display;
    ///   `rustMigrationCreateUnsignedNoteSplitPczt` for other rust-layer errors.
    func migrationCreateUnsignedNoteSplitPczts(
        for schedule: MigrationSchedule,
        for account: AccountUUID
    ) async throws -> [MigrationUnsignedTransferPczt]

    /// Applies the ceremony's signatures to the run's preparation (note-split) transactions,
    /// all-or-nothing: every element must match a stored transaction awaiting its signature or
    /// nothing is persisted. Returns a STORAGE RECEIPT for the first preparation transaction (its
    /// `txid` is zeroed — the broadcastable, proven value is served by the delivery lane).
    /// - Throws: `rustMigrationStoreSignedNoteSplitPczt` if the rust layer returns an error.
    func migrationStoreSignedNoteSplitPczts(
        _ signed: [MigrationSignedTransferPczt],
        for account: AccountUUID
    ) async throws -> PreparedMigrationTransfer

    /// Serves the TRANSFER subset of the unsigned build for the signing ceremony (see
    /// `migrationCreateUnsignedNoteSplitPczts` — the run and every unsigned transaction already
    /// exist, so the normal path here is the handle-free resume of the stored run;
    /// `schedule.proposalHandle` only gates the fresh-build case where this call is the one
    /// creating the run).
    /// - Throws: `migrationPlanStale` when nothing is committed and the identified plan is
    ///   missing or superseded — re-propose and re-display;
    ///   `rustMigrationCreateUnsignedTransferPczts` for other rust-layer errors.
    func migrationCreateUnsignedTransferPczts(
        for schedule: MigrationSchedule,
        for account: AccountUUID
    ) async throws -> [MigrationUnsignedTransferPczt]

    /// Accepts the full set of externally signed transfer PCZTs (all-or-nothing) and, if every
    /// staged transfer is matched exactly, persists the committed schedule.
    /// - Throws: `rustMigrationStoreSignedSchedulePczts` if the rust layer returns an error.
    func migrationStoreSignedSchedulePczts(_ signed: [MigrationSignedTransferPczt], for account: AccountUUID) async throws
}

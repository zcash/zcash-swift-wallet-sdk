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
    /// Closes and reopens the block database handle.
    /// This is needed after clearing the block cache to get a fresh connection.
    func reopenBlockDb() async throws

    /// Returns the type-safe wallet database handle for use in FFI calls.
    /// This is used internally for operations that need to pass the handle to other services.
    func resolveDbHandle() async throws -> WalletDbPtr

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

    /// Resets the state of the FsBlock database to only contain block and transaction information up to the given height.
    /// - Note: this does not delete the files. Only rolls back the database.
    /// - parameter height: height to rewind to. This should be the height returned by a successful `rewindToHeight` call.
    /// - Throws: `rustRewindCacheToHeight` if rust layer returns error.
    func rewindCacheToHeight(height: Int32) async throws

    func putSaplingSubtreeRoots(startIndex: UInt64, roots: [SubtreeRoot]) async throws

    func putOrchardSubtreeRoots(startIndex: UInt64, roots: [SubtreeRoot]) async throws

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
    func fixWitnesses() async throws

    /// Get an ephemeral single use transparent address
    func getSingleUseTransparentAddress(accountUUID: AccountUUID) async throws -> SingleUseTransparentAddress
    
    /// Attempts to delete an account defined by UUID
    func deleteAccount(_ accountUUID: AccountUUID) async throws
}

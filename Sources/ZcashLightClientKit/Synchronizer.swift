//
//  Synchronizer.swift
//  ZcashLightClientKit
//
//  Created by Francisco Gindre on 11/5/19.
//  Copyright © 2019 Electric Coin Company. All rights reserved.
//

import Combine
import Foundation

/// Represent the connection state to the lightwalletd server
public enum ConnectionState {
    /// not in use
    case idle

    /// there's a connection being attempted from a non error state
    case connecting

    /// connection is established, ready to use or in use
    case online

    /// the connection is being re-established after losing it temporarily
    case reconnecting

    /// the connection has been closed
    case shutdown
}

/// Reports the state of a synchronizer.
public struct SynchronizerState: Equatable {
    /// Unique Identifier for the current sync attempt
    /// - Note: Although on it's lifetime a synchronizer will attempt to sync between random fractions of a minute (when idle),
    /// each sync attempt will be considered a new sync session. This is to maintain a consistent UUID cadence
    /// given how application lifecycle varies between OS Versions, platforms, etc.
    /// SyncSessionIDs are provided to users
    public var syncSessionID: UUID
    /// account balance known to this synchronizer given the data that has processed locally
    public var accountsBalances: [AccountUUID: AccountBalance]
    /// status of the whole sync process
    var internalSyncStatus: InternalSyncStatus
    public var syncStatus: SyncStatus
    /// height of the latest block on the blockchain known to this synchronizer.
    public var latestBlockHeight: BlockHeight

    /// Represents a synchronizer that has made zero progress hasn't done a sync attempt
    public static var zero: SynchronizerState {
        SynchronizerState(
            syncSessionID: .nullID,
            accountsBalances: [:],
            internalSyncStatus: .unprepared,
            latestBlockHeight: .zero
        )
    }
    
    init(
        syncSessionID: UUID,
        accountsBalances: [AccountUUID: AccountBalance],
        internalSyncStatus: InternalSyncStatus,
        latestBlockHeight: BlockHeight
    ) {
        self.syncSessionID = syncSessionID
        self.accountsBalances = accountsBalances
        self.internalSyncStatus = internalSyncStatus
        self.latestBlockHeight = latestBlockHeight
        self.syncStatus = internalSyncStatus.mapToSyncStatus()
    }
}

public enum SynchronizerEvent {
    // Sent when the synchronizer finds a pendingTransaction that has been newly mined.
    case minedTransaction(ZcashTransaction.Overview)

    // Sent when the synchronizer finds a mined transaction
    case foundTransactions(_ transactions: [ZcashTransaction.Overview], _ inRange: CompactBlockRange?)
    // Sent when the synchronizer fetched utxos from lightwalletd attempted to store them.
    case storedUTXOs(_ inserted: [UnspentTransactionOutputEntity], _ skipped: [UnspentTransactionOutputEntity])
    // Connection state to LightwalletEndpoint changed.
    case connectionStateChanged(ConnectionState)
}

/// Primary interface for interacting with the SDK. Defines the contract that specific
/// implementations like SdkSynchronizer fulfill.
public protocol Synchronizer: AnyObject {
    /// Alias used for this instance.
    var alias: ZcashSynchronizerAlias { get }

    /// Latest state of the SDK which can be get in synchronous manner.
    var latestState: SynchronizerState { get }

    /// reflects current connection state to LightwalletEndpoint
    var connectionState: ConnectionState { get }

    /// This stream is backed by `CurrentValueSubject`. This is primary source of information about what is the SDK doing. New values are emitted when
    /// `InternalSyncStatus` is changed inside the SDK.
    ///
    /// Synchronization progress is part of the `InternalSyncStatus` so this stream emits lot of values. `throttle` can be used to control amout of values
    /// delivered. Values are delivered on random background thread.
    var stateStream: AnyPublisher<SynchronizerState, Never> { get }

    /// This stream is backed by `PassthroughSubject`. Check `SynchronizerEvent` to see which events may be emitted.
    var eventStream: AnyPublisher<SynchronizerEvent, Never> { get }

    /// This stream emits the latest known USD/ZEC exchange rate, paired with the time it was queried. See `FiatCurrencyResult`.
    var exchangeRateUSDStream: AnyPublisher<FiatCurrencyResult?, Never> { get }

    /// Initialize the wallet. The ZIP-32 seed bytes can optionally be passed to perform
    /// database migrations. most of the times the seed won't be needed. If they do and are
    /// not provided this will fail with `InitializationResult.seedRequired`. It could
    /// be the case that this method is invoked by a wallet that does not contain the seed phrase
    /// and is view-only, or by a wallet that does have the seed but the process does not have the
    /// consent of the OS to fetch the keys from the secure storage, like on background tasks.
    ///
    /// 'cache.db' and 'data.db' files are created by this function (if they
    /// do not already exist). These files can be given a prefix for scenarios where multiple wallets
    ///
    /// - Parameters:
    ///   - seed: ZIP-32 Seed bytes for the wallet that will be initialized
    ///   - walletBirthday: Birthday of wallet.
    ///   - for: [walletMode] Set `.newWallet` when preparing synchronizer for a brand new generated wallet,
    ///   `.restoreWallet` when wallet is about to be restored from a seed
    ///   and  `.existingWallet` for all other scenarios.
    ///   - name: name of the account.
    ///   - keySource: custom optional string for clients, used for example to help identify the type of the account.
    /// - Throws:
    ///     - `aliasAlreadyInUse` if the Alias used to create this instance is already used by other instance.
    ///     - `cantUpdateURLWithAlias` if the updating of paths in `Initilizer` according to alias fails. When this happens it means that
    ///                                some path passed to `Initializer` is invalid. The SDK can't recover from this and this instance
    ///                                won't do anything.
    ///     - Some other `ZcashError` thrown by lower layer of the SDK.
    func prepare(
        with seed: [UInt8]?,
        walletBirthday: BlockHeight,
        for walletMode: WalletInitMode,
        name: String,
        keySource: String?
    ) async throws -> Initializer.InitializationResult

    /// Starts this synchronizer within the given scope.
    ///
    /// Implementations should leverage structured concurrency and
    /// cancel all jobs when this scope completes.
    func start(retry: Bool) async throws

    /// Stop this synchronizer. Implementations should ensure that calling this method cancels all jobs that were created by this instance.
    /// It make some time before the SDK stops any activity. It doesn't have to be stopped when this function finishes.
    /// Observe `stateStream` or `latestState` to recognize that the SDK stopped any activity.
    func stop()

    /// Gets the sapling shielded address for the given account.
    /// - Parameter accountUUID: the  account whose address is of interest.
    /// - Returns the address or nil if account index is incorrect
    func getSaplingAddress(accountUUID: AccountUUID) async throws -> SaplingAddress

    /// Gets the default unified address for the given account.
    /// - Parameter accountUUID: the account whose address is of interest.
    /// - Returns the address or nil if account index is incorrect
    func getUnifiedAddress(accountUUID: AccountUUID) async throws -> UnifiedAddress

    /// Gets the transparent address for the given account.
    /// - Parameter accountUUID: the account whose address is of interest. By default, the first account is used.
    /// - Returns the address or nil if account index is incorrect
    func getTransparentAddress(accountUUID: AccountUUID) async throws -> TransparentAddress

    /// Obtains a fresh unified address for the given account with the specified receiver types.
    /// - Parameter accountUUID: the account whose address is of interest.
    /// - Parameter receivers: the receiver types to include in the address.
    /// - Returns the address or nil if account index is incorrect
    func getCustomUnifiedAddress(accountUUID: AccountUUID, receivers: Set<ReceiverType>) async throws -> UnifiedAddress

    /// Creates a proposal for transferring funds to the given recipient.
    ///
    /// - Parameter accountUUID: the account from which to transfer funds.
    /// - Parameter recipient: the recipient's address.
    /// - Parameter amount: the amount to send in Zatoshi.
    /// - Parameter memo: an optional memo to include as part of the proposal's transactions. Use `nil` when sending to transparent receivers otherwise the function will throw an error.
    ///
    /// If `prepare()` hasn't already been called since creation of the synchronizer instance or since the last wipe then this method throws
    /// `SynchronizerErrors.notPrepared`.
    func proposeTransfer(
        accountUUID: AccountUUID,
        recipient: Recipient,
        amount: Zatoshi,
        memo: Memo?
    ) async throws -> Proposal

    /// Creates a proposal for shielding any transparent funds received by the given account.
    ///
    /// - Parameter accountUUID: the account for which to shield funds.
    /// - Parameter shieldingThreshold: the minimum transparent balance required before a proposal will be created.
    /// - Parameter memo: an optional memo to include as part of the proposal's transactions.
    /// - Parameter transparentReceiver: a specific transparent receiver within the account
    ///             that should be the source of transparent funds. Default is `nil` which
    ///             will select whichever of the account's transparent receivers has funds
    ///             to shield.
    ///
    /// Returns the proposal, or `nil` if the transparent balance that would be shielded
    /// is zero or below `shieldingThreshold`.
    ///
    /// If `prepare()` hasn't already been called since creation of the synchronizer instance or since the last wipe then this method throws
    /// `SynchronizerErrors.notPrepared`.
    func proposeShielding(
        accountUUID: AccountUUID,
        shieldingThreshold: Zatoshi,
        memo: Memo,
        transparentReceiver: TransparentAddress?
    ) async throws -> Proposal?

    /// Creates the transactions in the given proposal.
    ///
    /// Returns a stream of objects for the transactions that were created as part of the
    /// proposal, indicating whether they were submitted to the network or if an error
    /// occurred.
    ///
    /// - Parameters:
    ///   - proposal: The proposal for which to create transactions. Attach a
    ///     `Proposal.PIRWitnessConfig` via `proposal.pirWitnessConfig` to enable PIR witness
    ///     fetching when the wallet is not fully synced.
    ///   - spendingKey: The `UnifiedSpendingKey` for the account that controls the funds.
    ///
    /// If `prepare()` hasn't already been called since creation of the synchronizer instance
    /// or since the last wipe then this method throws `SynchronizerErrors.notPrepared`.
    func createProposedTransactions(
        proposal: Proposal,
        spendingKey: UnifiedSpendingKey
    ) async throws -> AsyncThrowingStream<TransactionSubmitResult, Error>

    /// Attempts to propose fulfilling a [ZIP-321](https://zips.z.cash/zip-0321) payment URI by spending from the ZIP 32 account with the given index.
    ///  - Parameter uri: a valid ZIP-321 payment URI
    ///  - Parameter accountUUID: the account providing spend authority.
    ///
    /// - NOTE: If `prepare()` hasn't already been called since creating of synchronizer instance or since the last wipe then this method throws
    /// `SynchronizerErrors.notPrepared`.
    func proposefulfillingPaymentURI(
        _ uri: String,
        accountUUID: AccountUUID
    ) async throws -> Proposal

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
    func createPCZTFromProposal(accountUUID: AccountUUID, proposal: Proposal) async throws -> Pczt

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
    func createTransactionFromPCZT(pcztWithProofs: Pczt, pcztWithSigs: Pczt) async throws -> AsyncThrowingStream<TransactionSubmitResult, Error>

    /// all the transactions that are on the blockchain
    var transactions: [ZcashTransaction.Overview] { get async }

    /// All transactions that are related to sending funds
    var sentTransactions: [ZcashTransaction.Overview] { get async }

    /// all transactions related to receiving funds
    var receivedTransactions: [ZcashTransaction.Overview] { get async }

    /// A repository serving transactions in a paginated manner
    /// - Parameter kind: Transaction Kind expected from this PaginatedTransactionRepository
    func paginatedTransactions(of kind: TransactionKind) -> PaginatedTransactionRepository

    /// Get all memos for `transaction.rawID`.
    ///
    // sourcery: mockedName="getMemosForRawID"
    func getMemos(for rawID: Data) async throws -> [Memo]

    /// Get all memos for `transaction`.
    ///
    // sourcery: mockedName="getMemosForClearedTransaction"
    func getMemos(for transaction: ZcashTransaction.Overview) async throws -> [Memo]

    /// Attempt to get recipients from a Transaction Overview.
    /// - parameter transaction: A transaction overview
    /// - returns the recipients or an empty array if no recipients are found on this transaction because it's not an outgoing
    /// transaction
    ///
    // sourcery: mockedName="getRecipientsForClearedTransaction"
    func getRecipients(for transaction: ZcashTransaction.Overview) async -> [TransactionRecipient]

    /// Attempt to get outputs involved in a given Transaction.
    /// - parameter transaction: A transaction overview
    /// - returns the array of outputs involved in this transaction. Transparent outputs might not be tracked
    ///
    // sourcery: mockedName="getTransactionOutputsForTransaction"
    func getTransactionOutputs(for transaction: ZcashTransaction.Overview) async -> [ZcashTransaction.Output]

    /// Returns a list of confirmed transactions that preceed the given transaction with a limit count.
    /// - Parameters:
    ///     - from: the confirmed transaction from which the query should start from or nil to retrieve from the most recent transaction
    ///     - limit: the maximum amount of items this should return if available
    /// - Returns: an array with the given Transactions or an empty array
    func allTransactions(from transaction: ZcashTransaction.Overview, limit: Int) async throws -> [ZcashTransaction.Overview]

    /// Returns the latest block height from the provided Lightwallet endpoint
    func latestHeight() async throws -> BlockHeight

    /// Returns the latests UTXOs for the given address from the specified height on
    ///
    /// If `prepare()` hasn't already been called since creation of the synchronizer instance or since the last wipe then this method throws
    /// `SynchronizerErrors.notPrepared`.
    func refreshUTXOs(address: TransparentAddress, from height: BlockHeight) async throws -> RefreshedUTXOs

    /// Accounts balances
    /// - Returns: `[AccountUUID: AccountBalance]`, struct that holds Sapling and unshielded balances per account
    func getAccountsBalances() async throws -> [AccountUUID: AccountBalance]

    /// Fetches the latest ZEC-USD exchange rate and updates `exchangeRateUSDSubject`.
    func refreshExchangeRateUSD()

    /// Returns a list of the accounts in the wallet.
    func listAccounts() async throws -> [Account]

    /// Imports a new account with UnifiedFullViewingKey.
    /// - Parameters:
    ///   - ufvk: unified full viewing key
    ///   - purpose: of the account, either `spending` or `viewOnly`
    ///   - name: name of the account.
    ///   - keySource: custom optional string for clients, used for example to help identify the type of the account.
    // swiftlint:disable:next function_parameter_count
    func importAccount(
        ufvk: String,
        seedFingerprint: [UInt8]?,
        zip32AccountIndex: Zip32AccountIndex?,
        purpose: AccountPurpose,
        name: String,
        keySource: String?
    ) async throws -> AccountUUID

    func fetchTxidsWithMemoContaining(searchTerm: String) async throws -> [Data]

    /// Rescans the known blocks with the current keys.
    ///
    /// `rewind(policy:)` can be called anytime. If the sync process is in progress then it is stopped first. In this case, it make some significant
    /// time before rewind finishes. If `rewind(policy:)` is called don't call it again until publisher returned from first call finishes. Calling it
    /// again earlier results in undefined behavior.
    ///
    /// Returned publisher either completes or fails when the wipe is done. It doesn't emits any value.
    ///
    /// Possible errors:
    /// - Emits rewindErrorUnknownAnchorHeight when the rewind points to an invalid height.
    /// - Emits rewindError for other errors
    ///
    /// `rewind(policy:)` itself doesn't start the sync process when it's done and it doesn't trigger notifications as regorg would. After it is done
    /// you have start the sync process by calling `start()`
    ///
    /// If `prepare()` hasn't already been called since creation of the synchronizer instance or since the last wipe then returned publisher emits
    /// `SynchronizerErrors.notPrepared` error.
    ///
    /// - Parameter policy: the rewind policy
    func rewind(_ policy: RewindPolicy) -> AnyPublisher<Void, Error>

    /// Wipes out internal data structures of the SDK. After this call, everything is the same as before any sync. The state of the synchronizer is
    /// switched to `unprepared`. So before the next sync, it's required to call `prepare()`.
    ///
    /// `wipe()` can be called anytime. If the sync process is in progress then it is stopped first. In this case, it make some significant time
    /// before wipe finishes. If `wipe()` is called don't call it again until publisher returned from first call finishes. Calling it again earlier
    /// results in undefined behavior.
    ///
    /// Returned publisher either completes or fails when the wipe is done. It doesn't emits any value.
    ///
    /// Majority of wipe's work is to delete files. That is only operation that can throw error during wipe. This should succeed every time. If this
    /// fails then something is seriously wrong. If the wipe fails then the SDK may be in inconsistent state. It's suggested to call wipe again until
    /// it succeed.
    ///
    /// Returned publisher emits `initializerCantUpdateURLWithAlias` error if the Alias used to create this instance is already used by other
    /// instance.
    ///
    /// Returned publisher emits `initializerAliasAlreadyInUse` if the updating of paths in `Initilizer` according to alias fails. When
    /// this happens it means that some path passed to `Initializer` is invalid. The SDK can't recover from this and this instance won't do anything.
    ///
    func wipe() -> AnyPublisher<Void, Error>

    /// This API stops the synchronization and re-initalizes everything according to the new endpoint provided.
    /// It can be called anytime.
    /// - Throws: ZcashError when failures occur and related to `synchronizer.start(retry: Bool)`, it's the only throwing operation
    /// during the whole endpoint change.
    func switchTo(endpoint: LightWalletEndpoint) async throws

    /// Checks whether the given seed is relevant to any of the derived accounts in the wallet.
    ///
    /// - parameter seed: byte array of the seed
    func isSeedRelevantToAnyDerivedAccount(seed: [UInt8]) async throws -> Bool

    /// Takes the list of endpoints and runs it through a series of checks to evaluate its performance.
    /// - Parameters:
    ///    - endpoints: Array of endpoints to evaluate.
    ///    - fetchThresholdSeconds: The time to download `nBlocksToFetch` blocks from the stream must be below this threshold. The default is 60 seconds.
    ///    - nBlocksToFetch: The number of blocks expected to be downloaded from the stream, with the time compared to `fetchThresholdSeconds`. The default is 100.
    ///    - kServers: The required number of endpoints in the output. The default is 3.
    ///    - network: Mainnet or testnet. The default is mainnet.
    func evaluateBestOf(
        endpoints: [LightWalletEndpoint],
        fetchThresholdSeconds: Double,
        nBlocksToFetch: UInt64,
        kServers: Int,
        network: NetworkType
    ) async -> [LightWalletEndpoint]

    /// Takes a given date and finds out the closes checkpoint's height for it.
    /// Each checkpoint has a timestamp stored so it can be used for the calculations.
    func estimateBirthdayHeight(for date: Date) -> BlockHeight

    /// Takes a given height and finds out the closes checkpoint's timestamp for it.
    func estimateTimestamp(for height: BlockHeight) -> TimeInterval?

    /// Allows to setup the Tor opt-in/out runtime.
    /// - Parameters:
    ///    - enabled: When true, the SDK ensures `TorClient` is ready. This flag controls http and lwd service calls.
    /// - Throws: ZcashError when failures of the `TorClient` occur
    func tor(enabled: Bool) async throws

    /// Allows to setup exchange rate over Tor.
    /// - Parameters:
    ///    - enabled: When true, the SDK ensures `TorClient` is ready. This flag controls whether exchange rate feature is possible to use or not.
    /// - Throws: ZcashError when failures of the `TorClient` occur
    func exchangeRateOverTor(enabled: Bool) async throws

    /// Init of the SDK must always happen but initialization of `TorClient` can fail. This failure is designed to not block SDK initialization.
    /// Instead, a result of the initialization is stored in the `SDKFLags`
    /// - Returns: nil, the initialization hasn't been initiated, true/false = initialization succeeded/failed
    func isTorSuccessfullyInitialized() async -> Bool?

    /// Makes an HTTP request over Tor and delivers the `HTTPURLResponse`.
    ///
    /// This request is isolated (using separate circuits) from any other requests or
    /// Tor usage, but may still be correlatable by the server through request timing
    /// (if the caller does not mitigate timing attacks).
    ///
    /// The Swift's signature aligns with `URLSession.data(for request: URLRequest)`.
    ///
    /// - Parameters:
    ///    - for: URLRequest
    ///    - retryLimit: How many times the request will be retried in case of failure
    func httpRequestOverTor(for request: URLRequest, retryLimit: UInt8) async throws -> (data: Data, response: HTTPURLResponse)

    /// Performs an `sql` query on a database and returns some output as a string
    /// Use cautiously!
    /// The connection to the database is created in a read-only mode. it's a hard requirement.
    ///
    /// The following custom SQLite functions are provided:
    /// - `txid(Blob) -> String`: converts a transaction ID from its byte form to the user-facing
    ///   hex-encoded-reverse-bytes string.
    /// - `memo(Blob?) -> String?`: prints the given blob as a string if it is a text memo, and as
    ///   hex-encoded bytes otherwise.
    func debugDatabase(sql: String) -> String

    /// Get an ephemeral single use transparent address
    /// - Parameter accountUUID: The account for which the single use transparent address is going to be created.
    /// - Returns The struct with an ephemeral transparent address and gap limit info
    ///
    /// - Throws rustGetSingleUseTransparentAddress as a common indicator of the operation failure
    func getSingleUseTransparentAddress(accountUUID: AccountUUID) async throws -> SingleUseTransparentAddress

    /// Checks to find any single-use ephemeral addresses exposed in the past day that have not yet
    /// received funds, excluding any whose next check time is in the future. This will then choose the
    /// address that is most overdue for checking, retrieve any UTXOs for that address over Tor, and
    /// add them to the wallet database. If no such UTXOs are found, the check will be rescheduled
    /// following an expoential-backoff-with-jitter algorithm.
    /// - Parameter accountUUID: The account for which the single use transparent addresses are going to be checked.
    /// - Returns `.found(String)` an address found if UTXOs were added to the wallet, `.notFound` otherwise.
    ///
    /// - Throws rustCheckSingleUseTransparentAddresses as a common indicator of the operation failure
    func checkSingleUseTransparentAddresses(accountUUID: AccountUUID) async throws -> TransparentAddressCheckResult

    /// Finds all transactions associated with the given transparent address.
    /// - Parameter address: The address for which the transactions will be checked.
    /// - Returns `.found(String)` an address found if UTXOs were added to the wallet, `.notFound` otherwise.
    ///
    /// - Throws rustUpdateTransparentAddressTransactions as a common indicator of the operation failure
    func updateTransparentAddressTransactions(address: String) async throws -> TransparentAddressCheckResult

    /// Checks to find any UTXOs associated with the given transparent address. This check will cover the block range starting at the exposure height for that address,
    /// if known, or otherwise at the birthday height of the specified account.
    /// - Parameters:
    ///    - address: The address for which the transactions will be checked.
    ///    - accountUUID: The account for which the single use transparent addresses are going to be checked.
    /// - Returns `.found(String)` an address found if UTXOs were added to the wallet, `.notFound` otherwise.
    ///
    /// - Throws rustFetchUTXOsByAddress as a common indicator of the operation failure
    func fetchUTXOsBy(address: String, accountUUID: AccountUUID) async throws -> TransparentAddressCheckResult

    /// Calls `enhance` action for the provided txid.
    /// - Parameters:
    ///    - id: Transaction ID
    ///
    /// - Throws an error lwd related (fetching the transaction) or decryption related.
    func enhanceTransactionBy(txId: TxId) async throws -> Void
    
    /// Deletes the specified account, and all transactions that exclusively involve it, from the wallet database.
    /// - Parameter accountUUID: The account which is required to be deleted.
    ///
    /// - Throws rustDeleteAccount as a common indicator of the operation failure
    func deleteAccount(_ accountUUID: AccountUUID) async throws -> Void

    /// Check spendability of all unspent orchard notes in the wallet using a PIR server.
    /// Queries the wallet DB for unspent notes, checks each via PIR, and returns
    /// which are spent along with total spent value.
    ///
    /// - Parameters:
    ///   - pirServerUrl: Base URL of the spend-server.
    ///   - progress: Optional progress callback (0.0..1.0).
    func checkWalletSpendability(
        pirServerUrl: String,
        progress: SpendabilityProgressHandler?
    ) async throws -> SpendabilityResult

    /// Fetch note commitment witnesses from the PIR server for canonical Orchard
    /// notes the wallet wants to keep spendable during sync.
    ///
    /// Orchestrates: DB read (canonical notes) -> PIR server fetch -> DB write
    /// (store witnesses). Notes with witnesses bypass the shard-scanned gate in
    /// coin selection, making them spendable sooner.
    ///
    /// - Parameters:
    ///   - pirServerUrl: Base URL of the witness PIR server.
    ///   - progress: Optional progress callback (0.0..1.0).
    func fetchNoteWitnesses(
        pirServerUrl: String,
        progress: SpendabilityProgressHandler?
    ) async throws -> WitnessResult

}

public enum SyncStatus: Equatable {
    public static func == (lhs: SyncStatus, rhs: SyncStatus) -> Bool {
        switch (lhs, rhs) {
        case (.unprepared, .unprepared): return true
        case let (.syncing(lhsSyncProgress, lhsRecoveryPrgoress), .syncing(rhsSyncProgress, rhsRecoveryPrgoress)):
            return lhsSyncProgress == rhsSyncProgress && lhsRecoveryPrgoress == rhsRecoveryPrgoress
        case (.upToDate, .upToDate): return true
        case (.error, .error): return true
        default: return false
        }
    }
    
    /// Indicates that this Synchronizer is actively preparing to start,
    /// which usually involves setting up database tables, migrations or
    /// taking other maintenance steps that need to occur after an upgrade.
    case unprepared

    case syncing(_ syncProgress: Float, _ areFundsSpendable: Bool)

    /// Indicates that this Synchronizer is fully up to date and ready for all wallet functions.
    /// When set, a UI element may want to turn green.
    case upToDate

    /// Indicates that this Synchronizer was succesfully stopped via `stop()` method.
    case stopped
    
    case error(_ error: Error)
    
    public var isSyncing: Bool {
        if case .syncing = self {
            return true
        }
        
        return false
    }
    
    public var isSynced: Bool {
        if case .upToDate = self {
            return true
        }
        
        return false
    }

    public var isPrepared: Bool {
        if case .unprepared = self {
            return false
        }
        
        return true
    }

    public var briefDebugDescription: String {
        switch self {
        case .unprepared: return "unprepared"
        case .syncing: return "syncing"
        case .stopped: return "stopped"
        case .upToDate: return "up to date"
        case .error: return "error"
        }
    }
}

enum InternalSyncStatus: Equatable {
    /// Indicates that this Synchronizer is actively preparing to start,
    /// which usually involves setting up database tables, migrations or
    /// taking other maintenance steps that need to occur after an upgrade.
    case unprepared

    /// Indicates that this Synchronizer is actively processing new blocks (consists of fetch, scan and enhance operations)
    case syncing(Float, Bool)
    
    /// Indicates that this Synchronizer is fully up to date and ready for all wallet functions.
    /// When set, a UI element may want to turn green.
    case synced

    /// Indicates that [stop] has been called on this Synchronizer and it will no longer be used.
    case stopped

    /// Indicates that this Synchronizer is disconnected from its lightwalletd server.
    /// When set, a UI element may want to turn red.
    case disconnected

    case error(_ error: Error)
    
    public var isSyncing: Bool {
        if case .syncing = self {
            return true
        }
        
        return false
    }
    
    public var isSynced: Bool {
        if case .synced = self {
            return true
        }
        
        return false
    }

    public var isPrepared: Bool {
        if case .unprepared = self {
            return false
        }
        
        return true
    }

    public var briefDebugDescription: String {
        switch self {
        case .unprepared: return "unprepared"
        case .syncing: return "syncing"
        case .synced: return "synced"
        case .stopped: return "stopped"
        case .disconnected: return "disconnected"
        case .error: return "error"
        }
    }
}

/// Mode of the Synchronizer's initialization for the wallet.
public enum WalletInitMode: Equatable {
    /// For brand new wallet - typically when users creates a new wallet.
    case newWallet
    /// For a wallet that is about to be restored. Typically when a user wants to restore a wallet from a seed.
    case restoreWallet
    /// All other cases - typically when clients just start the process e.g. every regular app start for mobile apps.
    case existingWallet
}

/// Kind of transactions handled by a Synchronizer
public enum TransactionKind {
    case sent
    case received
    case all
}

/// Type of rewind available
///     -birthday: rewinds the local state to this wallet's birthday
///     -height: rewinds to the nearest blockheight to the one given as argument.
///     -transaction: rewinds to the nearest height based on the anchor of the provided transaction.
public enum RewindPolicy {
    case birthday
    case height(blockheight: BlockHeight)
    case transaction(_ transaction: ZcashTransaction.Overview)
    case quick
}

/// The result of submitting a transaction to the network.
///
/// - success: the transaction was successfully submitted to the mempool.
/// - grpcFailure: the transaction failed to reach the lightwalletd server.
/// - submitFailure: the transaction reached the lightwalletd server but failed to enter the mempool.
/// - notAttempted: the transaction was created and is in the local wallet, but was not submitted to the network.
public enum TransactionSubmitResult: Equatable {
    case success(txId: Data)
    case grpcFailure(txId: Data, error: LightWalletServiceError)
    case submitFailure(txId: Data, code: Int, description: String)
    case notAttempted(txId: Data)
}

extension InternalSyncStatus {
    public static func == (lhs: InternalSyncStatus, rhs: InternalSyncStatus) -> Bool {
        switch (lhs, rhs) {
        case (.unprepared, .unprepared): return true
        case let (.syncing(lhsSyncProgress, lhsRecoveryPrgoress), .syncing(rhsSyncProgress, rhsRecoveryPrgoress)):
            return lhsSyncProgress == rhsSyncProgress && lhsRecoveryPrgoress == rhsRecoveryPrgoress
        case (.synced, .synced): return true
        case (.stopped, .stopped): return true
        case (.disconnected, .disconnected): return true
        case (.error, .error): return true
        default: return false
        }
    }
}

extension InternalSyncStatus {
    init(_ syncProgress: Float, _ areFundsSpendable: Bool) {
        self = .syncing(syncProgress, areFundsSpendable)
    }
}

extension InternalSyncStatus {
    func mapToSyncStatus() -> SyncStatus {
        switch self {
        case .unprepared:
            return .unprepared
        case let .syncing(syncProgress, areFundsSpendable):
            return .syncing(syncProgress, areFundsSpendable)
        case .synced:
            return .upToDate
        case .stopped:
            return .stopped
        case .disconnected:
            return .error(ZcashError.synchronizerDisconnected)
        case .error(let error):
            return .error(error)
        }
    }
}

extension UUID {
    /// UUID  00000000-0000-0000-0000-000000000000
    static var nullID: UUID {
        UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    }
}

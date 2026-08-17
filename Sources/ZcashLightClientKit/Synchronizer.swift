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
    /// Height below which every block has been scanned contiguously from the wallet
    /// birthday. Unlike `latestBlockHeight` (chain tip) or `maxScannedHeight` (head-first
    /// scan progress), this is the only value that tells a caller "the wallet has
    /// authoritative note and nullifier state for this height." Callers that need a
    /// stable snapshot of balance at a specific height — e.g. voting power at a poll
    /// snapshot — must gate on this, not on `latestBlockHeight`.
    public var fullyScannedHeight: BlockHeight

    /// True while the wallet is in a deep recovery (a restore, or a new-account backfill) where the
    /// balance and transaction history are still provisional: during recent-first sync a note can
    /// appear unspent before the block that spends it has been scanned, transiently inflating both
    /// the balance and the Activity list. Clients should treat balance/Activity as not-yet-final
    /// (e.g. hold `0` and hold the Activity) until this is `false`. Derived from the wallet
    /// backend's `recovery_progress`; `false` for light catch-ups and once fully synced.
    public var isRecovering: Bool

    /// Represents a synchronizer that has made zero progress hasn't done a sync attempt
    public static var zero: SynchronizerState {
        SynchronizerState(
            syncSessionID: .nullID,
            accountsBalances: [:],
            internalSyncStatus: .unprepared,
            latestBlockHeight: .zero,
            fullyScannedHeight: .zero
        )
    }

    init(
        syncSessionID: UUID,
        accountsBalances: [AccountUUID: AccountBalance],
        internalSyncStatus: InternalSyncStatus,
        latestBlockHeight: BlockHeight,
        fullyScannedHeight: BlockHeight = .zero,
        isRecovering: Bool = false
    ) {
        self.syncSessionID = syncSessionID
        self.accountsBalances = accountsBalances
        self.internalSyncStatus = internalSyncStatus
        self.latestBlockHeight = latestBlockHeight
        self.fullyScannedHeight = fullyScannedHeight
        self.isRecovering = isRecovering
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
    /// `InitializationResult.seedNotRelevant` is returned when the provided seed does not match the accounts
    /// already present in the wallet database. The rust layer currently reports this during seed-requiring
    /// migrations; callers must treat it as "this database belongs to a different wallet" rather than proceed
    /// as if initialization succeeded.
    ///
    /// 'cache.db' and 'data.db' files are created by this function (if they
    /// do not already exist). These files can be given a prefix for scenarios where multiple wallets
    ///
    /// - Parameters:
    ///   - seed: ZIP-32 Seed bytes for the wallet that will be initialized
    ///   - walletBirthday: Birthday of the wallet to RESTORE from, or `nil` for a brand-new wallet (the
    ///   SDK then picks a reorg-safe recent height). Ignored when an account already exists.
    ///   - name: name of the account.
    ///   - keySource: custom optional string for clients, used for example to help identify the type of the account.
    /// - Note: The init flow (new / restore / existing) is DERIVED by the SDK — an existing account is
    ///   opened, a `nil` birthday creates a new wallet, a past birthday restores from it. A deliberate
    ///   re-scan/resync is the separate `rewind(_:)` action, not an init mode.
    /// - Throws:
    ///     - `aliasAlreadyInUse` if the Alias used to create this instance is already used by other instance.
    ///     - `cantUpdateURLWithAlias` if the updating of paths in `Initilizer` according to alias fails. When this happens it means that
    ///                                some path passed to `Initializer` is invalid. The SDK can't recover from this and this instance
    ///                                won't do anything.
    ///     - Some other `ZcashError` thrown by lower layer of the SDK.
    func prepare(
        with seed: [UInt8]?,
        walletBirthday: BlockHeight?,
        name: String,
        keySource: String?
    ) async throws -> Initializer.InitializationResult

    /// Starts this synchronizer within the given scope.
    ///
    /// Implementations should leverage structured concurrency and
    /// cancel all jobs when this scope completes.
    ///
    /// - Throws: ``ZcashError/migrationSyncBlocked`` when a migration submission is in flight for
    ///   any account in the wallet — a seconds-long hold, and the only one the migration gate
    ///   imposes. Wait until ``isMigrationSyncBlocked()`` is false, or observe
    ///   ``migrationSyncBlockedStream``, then retry.
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

    /// Creates a proposal that spends the maximum amount available in the given account to a single recipient.
    ///
    /// Unlike `proposeTransfer`, no `amount` is passed: the proposal is constructed to spend as much of the
    /// account's balance as `mode` allows, with the fee already accounted for by the proposal itself. The amount
    /// the recipient actually receives is `proposal.totalSpendValue() - proposal.totalFeeRequired()`.
    ///
    /// - Parameter accountUUID: the account from which to spend funds.
    /// - Parameter recipient: the recipient's address.
    /// - Parameter memo: an optional memo to include as part of the proposal's transactions. Use `nil` when sending to transparent receivers otherwise the function will throw an error.
    /// - Parameter mode: how much of the account's balance the proposal should target spending. See `MaxSpendMode`.
    ///
    /// If `prepare()` hasn't already been called since creation of the synchronizer instance or since the last wipe then this method throws
    /// `SynchronizerErrors.notPrepared`.
    func proposeSendMax(
        accountUUID: AccountUUID,
        recipient: Recipient,
        memo: Memo?,
        mode: MaxSpendMode
    ) async throws -> Proposal

    /// Creates a proposal that migrates the account's entire Orchard balance into the Ironwood pool.
    ///
    /// NU6.3 introduces the Orchard turnstile: value may leave the Orchard pool but never re-enter
    /// it, so Orchard funds must be moved across once and in full. This spends every Orchard note and
    /// sends the maximum to the account's own internal receiver, with the fee computed so no change
    /// returns to Orchard. Sapling and transparent funds are untouched. Fails unless NU6.3 is active
    /// at the chain tip.
    ///
    /// - Parameter accountUUID: the account whose Orchard balance is migrated.
    func proposeOrchardToIronwoodMigration(accountUUID: AccountUUID) async throws -> Proposal

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
    /// - Parameter proposal: the proposal for which to create transactions.
    /// - Parameter spendingKey: the `UnifiedSpendingKey` associated with the account for which the proposal was created.
    ///
    /// Returns a stream of objects for the transactions that were created as part of the
    /// proposal, indicating whether they were submitted to the network or if an error
    /// occurred.
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

    /// Returns all transactions, most recent first.
    func allTransactions() async throws -> [ZcashTransaction.Overview]

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
    ///   - birthday: custom optional BlochHeight representing birthday of the imported account.
    // swiftlint:disable:next function_parameter_count
    func importAccount(
        ufvk: String,
        seedFingerprint: [UInt8]?,
        zip32AccountIndex: Zip32AccountIndex?,
        purpose: AccountPurpose,
        name: String,
        keySource: String?,
        birthday: BlockHeight?
    ) async throws -> AccountUUID

    func fetchTxidsWithMemoContaining(searchTerm: String) async throws -> [Data]

    /// Rescans from the given `BlockHeight`.
    func rescanFrom(height: BlockHeight) async throws

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

    /// Fetch the commitment tree state at the given block height from lightwalletd,
    /// returned as protobuf-serialized bytes suitable for witness generation.
    ///
    /// Tor posture: when Tor is enabled on the Synchronizer, this uses a unique,
    /// one-shot Tor circuit per call (`.uniqueTor`), matching the policy of
    /// other public transport calls on this protocol (`fetchUTXOsBy`,
    /// `checkSingleUseTransparentAddresses`, `updateTransparentAddressTransactions`).
    /// A fresh circuit keeps each fetch unlinkable from other SDK traffic — in
    /// particular from later `.txIdGroup`-scoped submission of a transaction
    /// anchored at the same height. When Tor is disabled, this uses a direct
    /// gRPC connection.
    func getTreeState(height: UInt64) async throws -> Data

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

    /// Provides access to transaction creation and submission operations
    /// that are decoupled from the synchronizer's built-in submission flow.
    ///
    /// Use this to implement custom broadcast strategies such as submitting
    /// to multiple lightwalletd servers in parallel.
    var broadcaster: Broadcaster { get }

    // MARK: - Migration (Orchard -> Ironwood)
    //
    // Exposes the host's per-account `OrchardMigration` machinery and its wallet-scope sync gate
    // to the app: note-split preparation and submission, transfer scheduling, the advance drive
    // and its instruction executors, on-launch reconciliation/recovery, and external (PCZT)
    // signing. None of these methods require `prepare()` to have been called — a host may
    // broadcast a migration transfer from a background session without ever starting sync.
    //
    // The action surface is exactly three things: the conduit (`migrationAdvanceStep(accountUUID:)`),
    // the instruction executors (`proveMigrationTransactions`, `performMigrationBroadcast`,
    // `refreshStaleMigrationTransfers`), and reads. The app has no semantic goal except to advance
    // the migration and perform the advancement's dictates, and no member decides for itself what
    // the migration needs: `MigrationBroadcastInstruction` and `MigrationProveTarget` have no
    // public initializers, so the advance marshaling is their only producer and un-instructed
    // proving or broadcasting does not compile. This is a Swift-surface property, not a security
    // boundary — the Rust executors' per-row state gating remains the safety backstop.
    //
    // The ceremony/consent lane is deliberately untouched by this: `prepareNoteSplit` /
    // `submitNoteSplit` and the propose/sign/store family are pre-drive consent flows — a user
    // approving a plan that does not exist yet — so there is no instruction for them to carry.

    /// The migration engine's next step to advance `accountUUID`'s stored run, paired with its
    /// advisory outlook — a verbatim conduit of the engine's own `advance_migration`: the
    /// attention step, the broadcast-first ordering, and the prove batch's per-entry kinds are
    /// all the engine's own answer, marshaled field-for-field. Call it on launch and after every
    /// migration operation.
    ///
    /// `nil` means no run is stored — nothing to advance, nothing to poll. A non-`nil` answer is
    /// a ``MigrationAdvance``: `.step` is the step to perform now, judged with the engine's
    /// attend > broadcast > prove > rebuild priority under its dueness rule — the wall-clock
    /// chain-tip estimate, which this member always projects and passes, may only ACCELERATE
    /// scheduled-height due-ness, while expiry, boundary settledness, and every destructive
    /// determination evaluate on the SCANNED tip, and an estimator failure degrades to
    /// scanned-tip behavior rather than failing the call. The answer is memoryless about
    /// sessions: session policy (one broadcast per session, no sync in a broadcast session)
    /// stays with the caller and the sync gate. `.next` is the advisory outlook
    /// (``MigrationNextWork``) — what session to plan for once `.step` is executed, or `nil`
    /// when nothing is height-schedulable.
    ///
    /// This is the conduit: crank it, then switch over `.step` and perform that step's dictate.
    /// Every actionable arm hands the step's own payload straight to an executor:
    ///
    /// ```swift
    /// switch try await synchronizer.migrationAdvanceStep(accountUUID: account)?.step {
    /// case .prove(let instruction):
    ///     _ = try await synchronizer.proveMigrationTransactions(accountUUID: account, instruction, maxProofs: budget)
    /// case .broadcast(let instruction):
    ///     _ = try await synchronizer.performMigrationBroadcast(accountUUID: account, instruction, options: options)
    /// case .rebuild:
    ///     _ = try await synchronizer.refreshStaleMigrationTransfers(accountUUID: account, usk: usk)
    /// case .replan, .reevaluate, .waiting, .complete, nil:
    ///     break // nothing to perform; see the per-step notes below
    /// }
    /// ```
    ///
    /// Discharging each step (see ``MigrationAdvanceStep`` for the full contract):
    /// - `.reevaluate` — surfaced first, before any actionable step, while a broadcast-rejection
    ///   report is open → sync and call this again so the engine can adjudicate against the newly
    ///   scanned data; it keeps answering this until the scan reaches the rejecting node's tip.
    /// - `.replan` — the run's plan was undercut past the committed threshold and the verdict is
    ///   already persisted (no sync changes it) → surface the re-plan UX over the
    ///   ``MigrationTransactionStatus/State/invalid(reason:)`` row(s), then
    ///   ``restartCurrentMigrationStep(accountUUID:)``. Invalid rows are excluded from delivery
    ///   and from the sync gate.
    /// - `.broadcast` → ``performMigrationBroadcast(accountUUID:_:options:)`` with the step's own
    ///   ``MigrationBroadcastInstruction`` — submit and end the session (no sync).
    /// - `.prove` → ``proveMigrationTransactions(accountUUID:_:maxProofs:)`` at a sync wake-up.
    ///   Proving can unblock rows the batch did not name, so a host draining the run cranks again
    ///   afterwards and discharges the next instruction. Each entry's `kind` decides what follows
    ///   for that transaction: a `.preparation` entry may be proved and broadcast at the same
    ///   wake-up, while a `.transfer` entry's broadcast follows in its own later session.
    /// - `.rebuild` → ``refreshStaleMigrationTransfers(accountUUID:usk:)`` (needs spend
    ///   authority).
    /// - `.waiting` → register OS wake-ups from ``migrationSyncWakeups(accountUUID:)`` plus each
    ///   ``migrationTransactionStatuses(accountUUID:)`` row's `scheduledHeight`; the outlook's
    ///   `.next`, when present, sharpens which wake-up to arm first (a `.broadcast` outlook needs
    ///   no sync, a `.prove` one is sync-bound), but the wake-up schedule remains the authority —
    ///   the outlook is one call's lookahead, superseded by the next.
    /// - `.complete` is terminal for the stored run — including a cancelled one — and means
    ///   "stop polling" (its outlook is always `nil`). It is per-run, never "nothing left to
    ///   migrate": whether a migratable balance remains is answered by
    ///   ``proposeMigrationTransfers(accountUUID:)`` (an empty schedule means no).
    /// - Parameter accountUUID: the account whose next step is of interest.
    func migrationAdvanceStep(accountUUID: AccountUUID) async throws -> MigrationAdvance?

    /// Live migration progress for `accountUUID`, or `nil` when no snapshot is reportable:
    /// present only while an engine run is ACTIVE (not terminal) or a recorded immediate sweep is
    /// pending (unmined and unexpired); a terminal — complete or cancelled — run reports `nil`.
    /// - Parameter accountUUID: the account whose migration progress is of interest.
    func migrationProgress(accountUUID: AccountUUID) async throws -> MigrationProgress?

    /// The prove executor: proves up to `maxProofs` of the transactions `instruction` names,
    /// persisting each proof, and returns a ``MigrationProveOutcome`` — how many were proved (`0`
    /// is the ordinary "nothing in this batch is provable right now" answer) and the txids of the
    /// PREPARATIONS it proved.
    ///
    /// The txids are the handoff: a proved preparation is a complete transaction, ZIP 318-exempt
    /// and meant to be broadcast as soon as it is proved, so its submission is the app's ordinary
    /// path — for each returned txid call ``takeMigrationPreparation(accountUUID:byTxid:)``,
    /// submit the bytes it hands back through the app's ordinary raw-transaction machinery, and
    /// record the outcome the standard way. A transfer's txid is never returned — transfers are
    /// served by the drive's broadcast instruction alone.
    ///
    /// The instruction is a batch a ``migrationAdvanceStep(accountUUID:)`` crank handed out — the
    /// only way to hold one, since ``MigrationProveTarget`` has no public initializer. There is
    /// no loop here: proving can unblock rows the batch did not name, so a host draining the run
    /// cranks the conduit again and discharges the next instruction; a pass that proves `0` means
    /// the batch's remainder is transiently unprovable and a later wake-up will retry it.
    ///
    /// Run this at the sync wake-ups ``migrationSyncWakeups(accountUUID:)`` schedules — after the
    /// wake-up's sync has caught the wallet up — and never in a broadcast session. A transaction
    /// that cannot be proved yet (anchor not scanned/retained) is skipped and retried by a later
    /// call, as is one no longer awaiting its proof — so acting on a stale instruction is safe,
    /// and neither skip spends the budget.
    /// - Parameters:
    ///   - accountUUID: the account whose proofs should be produced.
    ///   - instruction: the prove batch the crank returned.
    ///   - maxProofs: this session's proof budget (at least `1`) — each proof is seconds of CPU,
    ///     so a background session bounds what it takes on and cranks again next time.
    /// - Throws: ``ZcashError/rustMigrationProveTransactions(_:)`` when `maxProofs` is below `1`
    ///   (a caller bug); ``ZcashError/migrationProvingUnavailable(_:)`` when proving fails for a
    ///   non-transient reason.
    func proveMigrationTransactions(
        accountUUID: AccountUUID,
        _ instruction: [MigrationProveTarget],
        maxProofs: Int
    ) async throws -> MigrationProveOutcome

    /// Serves the proved preparation with `txid` for submission — the retrieval half of the
    /// handoff ``proveMigrationTransactions(accountUUID:_:maxProofs:)`` opens by returning the
    /// preparations' txids.
    ///
    /// The accessor is the seam, not a byte read of a stored artifact: `txid -> row -> the
    /// store's atomic broadcast seam`, in one database transaction. The wallet's own record of
    /// the transaction binds at retrieval, so an app can never hold submittable bytes the wallet
    /// knows nothing about, and it is idempotent — a consumer that crashed between retrieving and
    /// submitting re-retrieves exactly the same bytes over the same record.
    ///
    /// Submit ``PreparedMigrationTransfer/pczt`` — a finalized consensus transaction, submittable
    /// as-is — through the app's ordinary raw-transaction machinery, then record the outcome the
    /// standard way: the returned ``PreparedMigrationTransfer/id`` is the engine transfer id that
    /// path keys on. Retrieved-but-never-submitted is a bounded state, not a leak: the
    /// preparation carries a ZIP 203 expiry, and an unsubmitted row surfaces through the
    /// ordinary attention path once it expires.
    ///
    /// Preparation-gated: a txid naming a transfer is refused. Transfers cross on the drive's own
    /// ZIP 318 schedule and are served by ``performMigrationBroadcast(accountUUID:_:options:)``
    /// alone. This call does not broadcast, so it carries no privacy options and is not guarded
    /// against sync.
    /// - Parameters:
    ///   - accountUUID: the account whose preparation is being retrieved.
    ///   - txid: a txid ``MigrationProveOutcome/preparationTxids`` named, in the SDK's
    ///     raw/internal byte order.
    /// - Throws: ``ZcashError/migrationProvingUnavailable(_:)`` when the stored artifact cannot be
    ///   turned into servable bytes; ``ZcashError/rustMigrationTakePreparation(_:)`` for a
    ///   transfer's txid, for a txid the stored run does not carry, and for the readiness refusal
    ///   of a preparation that is not proved — which an app discharges by proving again rather
    ///   than retrying this.
    func takeMigrationPreparation(accountUUID: AccountUUID, byTxid txid: Data) async throws -> PreparedMigrationTransfer

    /// Closes the seam: records the engine-side outcome of a preparation the app retrieved with
    /// ``takeMigrationPreparation(accountUUID:byTxid:)`` and submitted itself — the same per-row
    /// mark (`Proved -> Broadcast`) ``performMigrationBroadcast(accountUUID:_:options:)`` makes
    /// on its own success arm, made here by the app in place of the ceremony it deliberately
    /// skipped. It is the ordinary close of the loop, not a repair.
    ///
    /// Keyed on the retrieval result: it takes the ``PreparedMigrationTransfer`` the accessor
    /// returned, whose ``PreparedMigrationTransfer/id`` is already the engine transfer id the
    /// record path keys on. Preparation-gated in the same register as the accessor: an id naming
    /// a transfer is refused — the drive's own broadcast records transfer outcomes itself — as is
    /// an id the stored run does not carry.
    ///
    /// Report the submission's real outcome. An acceptance makes the mark; a permanent server
    /// rejection (`.invalidNote` / `.expired`) should be reported too — the engine dates the
    /// verdict against the observed tip and the next crank re-adjudicates, so a doomed row can
    /// raise attention instead of being re-served until expiry. A network-level non-acceptance
    /// needs no call — the engine's network-error outcome records nothing by design, so reporting
    /// one and reporting nothing leave the row equally re-servable. An app that crashed between
    /// submitting and marking still converges: the engine promotes any in-flight transaction its
    /// scan sees mine, and a later re-serve of the same bytes draws a duplicate rejection the SDK
    /// records as success.
    /// - Parameters:
    ///   - accountUUID: the account the preparation belongs to.
    ///   - prepared: the value ``takeMigrationPreparation(accountUUID:byTxid:)`` returned for this
    ///     submission.
    ///   - result: the submission's outcome, in the engine's own vocabulary.
    /// - Throws: ``ZcashError/rustMigrationRecordTransferResult(_:)`` when `prepared` names a
    ///   transfer or a transaction the stored run does not carry, and for rust-layer failures of
    ///   the record itself.
    func recordMigrationPreparationBroadcast(
        accountUUID: AccountUUID,
        _ prepared: PreparedMigrationTransfer,
        result: MigrationTransferResult
    ) async throws

    /// The stored run's minimal sync/proving wake-up schedule for `accountUUID`, as of the
    /// SCANNED chain tip: each row is a height at which to wake, sync, crank
    /// ``migrationAdvanceStep(accountUUID:)`` and discharge the prove instruction it returns, plus
    /// the transfer ids it covers.
    /// Register OS wake-ups from these heights (converted to wall clock via
    /// ``estimatedMigrationSecondsPerBlock()``) plus each status row's
    /// `scheduledHeight` for the broadcast windows. Jitter is re-drawn on every call — recompute
    /// (and re-register) after any state change rather than caching. Empty when there is nothing
    /// left to prove (including no stored or a terminal run).
    /// - Parameter accountUUID: the account whose wake-ups should be scheduled.
    /// - Throws: ``ZcashError/migrationWakeupInfeasible(_:)`` when a stored transfer admits no
    ///   valid wake-up height (an inconsistent stored schedule; rebuild or restart the run).
    func migrationSyncWakeups(accountUUID: AccountUUID) async throws -> [MigrationSyncWakeup]

    /// The drive's retained OUTLOOK for `accountUUID`: the most recent
    /// ``migrationAdvanceStep(accountUUID:)`` crank's advisory ``MigrationAdvance/next``, from ANY
    /// caller (the app's driver, or any other call for this account) — so a host can ask
    /// "when is the next migration wake, per the drive's own plan" without re-cranking the engine.
    ///
    /// Advisory and a floor: the height is the earliest the outlook's work becomes serviceable,
    /// never an appointment, and it holds only as of the crank that produced it — the very next
    /// crank's outlook (even to `nil`) supersedes it unconditionally. It complements, never
    /// replaces, ``migrationSyncWakeups(accountUUID:)``: this is one height, the schedule is
    /// many — a host arming OS wake-ups should min-fold this outlook's height in alongside the
    /// schedule's own heights, never treat it as a replacement source.
    ///
    /// `nil` means no crank has run this session, or the last step's own outcome (a chain
    /// condition or user/spend-authority action, not a height) decides what follows.
    /// - Parameter accountUUID: the account whose retained outlook is of interest.
    func nextMigrationWake(accountUUID: AccountUUID) async -> MigrationNextWork?

    /// The wall-clock ESTIMATED chain tip, projected from the most recently scanned blocks'
    /// header times (the measured-block-rate estimator behind `useEstimatedTip`). Falls back to
    /// the wallet's max SCANNED height when no samples exist. WALLET-scoped, like the batching
    /// group: the projection reads the shared blocks table, so it takes no account — one answer
    /// serves every account.
    /// - Throws: ``ZcashError/migrationChainTipUnavailable`` when the wallet has never scanned a
    ///   block, so no tip exists to estimate from.
    func estimatedMigrationChainTip() async throws -> BlockHeight

    /// The measured seconds-per-block over the most recently scanned blocks: the mean of the last
    /// up-to-100 consecutive header-time deltas, clamped to [5, 150] s, falling back to 75 s (the
    /// target spacing) when fewer than two samples exist. Use it to convert
    /// ``migrationSyncWakeups(accountUUID:)`` heights into wall-clock OS timers. WALLET-scoped
    /// like ``estimatedMigrationChainTip()`` — the measurement reads the shared blocks table, so
    /// it takes no account.
    func estimatedMigrationSecondsPerBlock() async throws -> Double

    /// The LIVE status of every committed migration transaction for `accountUUID`, keyed by its
    /// stable id — the per-transaction detail view behind ``migrationProgress(accountUUID:)``'s
    /// aggregate summary: what a wallet renders progress from and decides what to sign/prove/
    /// broadcast next.
    ///
    /// A verbatim marshal of the engine's own `MigrationState::transaction_statuses`: nothing
    /// here is derived independently of the engine's view. Each row's `id` is STABLE across reads
    /// and across a stale-transfer rebuild (a rebuilt transfer keeps its id; only its state and
    /// heights change), so a wallet may use it as a durable row key. Reconciles mined transactions
    /// first (the same read-path convention as ``migrationAdvanceStep(accountUUID:)``), so a transaction
    /// the wallet's own scan has since observed mined is reported `.mined` here even if the stored
    /// run still marks it broadcast. No stored run, or a stored run with no transactions, returns
    /// an EMPTY array — not an error.
    /// - Parameter accountUUID: the account whose migration transactions are of interest.
    func migrationTransactionStatuses(accountUUID: AccountUUID) async throws -> [MigrationTransactionStatus]

    /// Whether `accountUUID`'s Orchard notes must be split before migration.
    /// - Parameter accountUUID: the account to check.
    /// - Note: Requires at least one completed sync. On a wallet that has never completed a sync (no
    ///   chain tip known) this throws rather than returning `false`.
    func isNoteSplitNeeded(accountUUID: AccountUUID) async throws -> Bool

    /// The optimal note split for `accountUUID`'s spendable Orchard balance.
    ///
    /// Any subsequent propose/prepare call for the same account supersedes previously returned
    /// proposal handles — commit calls carrying an older handle throw `ZcashError.migrationPlanStale`.
    /// - Parameter accountUUID: the account to prepare a note split for.
    func prepareNoteSplit(accountUUID: AccountUUID) async throws -> NoteSplitProposal

    /// Signs, extracts, broadcasts, and records `accountUUID`'s note-split transaction, returning the
    /// broadcast outcome.
    ///
    /// - Parameters:
    ///   - accountUUID: the account whose note split is being submitted.
    ///   - proposal: the note-split proposal to sign and broadcast, from ``prepareNoteSplit(accountUUID:)``.
    ///   - usk: the account's unified spending key.
    ///   - options: network-privacy options (Tor, submission endpoint) for this broadcast.
    /// - Throws: ``ZcashError/migrationBroadcastDuringSync`` if the synchronizer is actively syncing —
    ///   sync and migration broadcasts must never share a session; this is enforced by the SDK on
    ///   this call, so stop sync first. Otherwise, a pre-broadcast failure throws untouched (nothing
    ///   was broadcast); a failure to record a broadcast that did land throws
    ///   ``ZcashError/migrationRecordFailedAfterBroadcast(_:)`` — the broadcast is real and a
    ///   later attempt self-heals.
    /// - Note: A completed submission leaves no timed hold behind — the migration gate blocks
    ///   ``isMigrationSyncBlocked()``/``start(retry:)`` only while this submission is in flight.
    ///   There is exactly one submission
    ///   endpoint per attempt, and no txid polling — confirmation comes from scanning. Calls for
    ///   different accounts are unserialized and safe to run concurrently; calls for the *same*
    ///   account are single-flight (a concurrent call waits for the in-flight one rather than
    ///   re-broadcasting). The sync-state check above is advisory, point-in-time enforcement, not a
    ///   hard mutual-exclusion lock: a sync started concurrently with an in-flight broadcast is not
    ///   torn down, so hosts should still sequence sync and migration-broadcast sessions themselves.
    func submitNoteSplit(
        accountUUID: AccountUUID,
        proposal: NoteSplitProposal,
        usk: UnifiedSpendingKey,
        options: MigrationNetworkPrivacyOptions
    ) async throws -> MigrationTransferResult

    /// The full migration schedule preview for `accountUUID`'s live spendable Orchard balance, in
    /// chronological broadcast order. Plans fresh (drawing new ZIP 318 schedule randomness) and
    /// caches the preview — a later commit signs exactly this plan, so always confirm the schedule
    /// the user actually saw. Any subsequent propose/prepare call for the same account supersedes
    /// previously returned proposal handles — commit calls carrying an older handle throw
    /// `ZcashError.migrationPlanStale`. An EMPTY schedule means there is nothing to migrate; after a
    /// completed run this is the "does anything remain" answer of the sequential-runs contract.
    /// - Parameter accountUUID: the account to propose a migration schedule for.
    func proposeMigrationTransfers(accountUUID: AccountUUID) async throws -> MigrationSchedule

    /// Proposes the immediate (single-transaction) migration: an ordinary send-max that spends ALL
    /// spendable Orchard notes of `accountUUID` and pays everything minus the ZIP-317 fee to the
    /// account's own unified address -- post-NU6.3 the payment lands in the Ironwood pool (the UA's
    /// Orchard receiver doubles as the Ironwood receiver). Deterministic for unchanged wallet state.
    ///
    /// Unlike ``proposeMigrationTransfers(accountUUID:)``, this is an ORDINARY
    /// proposal: it is not held by the migration engine, so there is no plan-cache staleness to
    /// invalidate it between this call and ``createProposedTransactions(proposal:spendingKey:)`` /
    /// ``createPCZTFromProposal(accountUUID:proposal:)``. Executing it is the caller's job exactly
    /// like any other transfer; call ``recordImmediateMigration(accountUUID:txid:)`` after a
    /// successful broadcast so the platform migration state machine reports it.
    /// - Parameter accountUUID: the account to propose the immediate migration for.
    /// - Throws: the rust layer's `InsufficientFunds` (mapped) when the fee would consume the whole
    ///   balance.
    func proposeImmediateMigration(accountUUID: AccountUUID) async throws -> ImmediateMigrationProposal

    /// Records a broadcast immediate-migration sweep in the SDK migration store so the platform
    /// migration state machine reports it: `InProgress` (0 of 1) while unmined, `Complete` once
    /// mined, or a re-offer (`NotStarted`) if it expires unmined. One row per account: a new record
    /// supersedes any previous one.
    ///
    /// Not broadcast-sensitive itself: the broadcast rides the already-guarded
    /// ``createProposedTransactions(proposal:spendingKey:)`` / ``createPCZTFromProposal(accountUUID:proposal:)``
    /// pipeline, so this call carries no ``ZcashError/migrationBroadcastDuringSync`` guard of its own.
    /// - Parameters:
    ///   - accountUUID: the account the immediate migration belongs to.
    ///   - txid: the broadcast transaction's id, in the SDK's raw/internal byte order (32 bytes;
    ///     matches `TxId.id`, not the reversed display-hex order produced by `Data.toHexStringTxId()`).
    func recordImmediateMigration(accountUUID: AccountUUID, txid: Data) async throws

    /// The leftover Orchard balance a migration of `accountUUID` would not cross, when large enough
    /// to be worth offering the user a choice about; `nil` when there is no such residual.
    /// - Parameter accountUUID: the account to check.
    /// - Note: Requires at least one completed sync. On a wallet that has never completed a sync (no
    ///   chain tip known) this throws rather than returning `nil`.
    func residualAfterMigration(accountUUID: AccountUUID) async throws -> Zatoshi?

    /// Locks every currently-spendable, not-already-locked legacy-Orchard note of `accountUUID`
    /// until explicit unlock and returns the total value locked — the "Lock balance" choice at
    /// migration `Complete`: the sub-threshold residual a migration would not cross stays in
    /// Orchard, out of spending, until ``unlockMigrationResidual(accountUUID:)`` releases it (the
    /// lock never expires on its own). Locked value leaves `PoolBalance.spendableValue` but stays
    /// in `PoolBalance.lockedValue`, and therefore in the account's total balance — locked funds
    /// never vanish from app-visible sums.
    /// - Parameter accountUUID: the account whose residual should be locked.
    /// - Note: `Zatoshi(0)` is a legitimate result (nothing was spendable, or everything spendable
    ///   was already locked). Idempotent-additive: already-locked notes are excluded from
    ///   selection, so repeating the call locks (and reports) only notes that became spendable
    ///   since.
    /// - Throws: ``ZcashError/rustMigrationLockResidual(_:)`` if the engine reports an error —
    ///   including a concurrent-lock race, which the caller may retry.
    func lockMigrationResidual(accountUUID: AccountUUID) async throws -> Zatoshi

    /// Clears ALL of `accountUUID`'s output locks — the release half of
    /// ``lockMigrationResidual(accountUUID:)`` — and returns the number of outputs unlocked (`0`
    /// when nothing was locked; the blanket clear is safe because the SDK never creates
    /// proposal-scoped output locks). "Migrate anyway" over a locked residual composes as this
    /// call followed by ``proposeImmediateMigration(accountUUID:)``: locked notes are excluded
    /// from note selection, so the unlock must come first.
    /// - Parameter accountUUID: the account whose output locks should be cleared.
    func unlockMigrationResidual(accountUUID: AccountUUID) async throws -> Int

    /// Estimates how `accountUUID` migrates its whole spendable Orchard balance — the rounds
    /// preview for the multi-round migration UI, answered before anything is planned or
    /// committed: the number of migration RUNS ("rounds") it takes, per run both what it migrates
    /// (the pool crossings) and what preparing it costs (the note-preparation layers,
    /// transactions, and signer ACTIONS), and the final residual that never migrates. External-
    /// signer effort is precomputed on the result in actions, not transaction counts:
    /// ``MigrationRunEstimate/totalActions`` is the signing workload and
    /// ``MigrationRunEstimate/totalKeystoneSigningSessions`` the signer-interaction count under
    /// the 96-action Keystone budget (see ``MigrationRunEstimate`` for why count-based session
    /// math undercounts).
    /// - Parameter accountUUID: the account to estimate for.
    /// - Note: The zero-run estimate (`runCount == 0`, a zero or fully sub-quantum balance) is a
    ///   legitimate answer, not an error.
    func estimateMigrationRuns(accountUUID: AccountUUID) async throws -> MigrationRunEstimate

    /// Pre-signs and persists every transfer in `schedule` in the migration engine for `accountUUID`
    /// (a no-op when a matching non-terminal run is already stored for the account — the normal
    /// case, since the note-split submission commits the run). Any subsequent propose/prepare call
    /// for the same account supersedes previously returned proposal handles — commit calls
    /// carrying an older handle throw `ZcashError.migrationPlanStale`.
    ///
    /// The SDK does not retain the proposal list: hosts that need to render the committed schedule
    /// later must persist it themselves at confirmation time.
    /// - Parameters:
    ///   - accountUUID: the account the schedule belongs to.
    ///   - schedule: the schedule to sign and store, from
    ///     ``proposeMigrationTransfers(accountUUID:)``. Only its `proposalHandle` crosses to the
    ///     native side -- the display fields (transfers, estimated duration) are never echoed back.
    ///     A fresh commit signs exactly the cached plan the handle identifies, so a stale or
    ///     tampered display can never sign different values than the ones the user approved; the
    ///     resume/no-op case above does not consult the handle at all. Not used by the immediate
    ///     lane: ``proposeImmediateMigration(accountUUID:)`` returns an ordinary
    ///     ``ImmediateMigrationProposal``, executed via ``createProposedTransactions(proposal:spendingKey:)``
    ///     / ``createPCZTFromProposal(accountUUID:proposal:)`` like any other transfer.
    ///   - usk: the account's unified spending key.
    /// - Throws: `ZcashError.migrationPlanStale` when nothing is committed and the identified plan
    ///   is missing (process restart between propose and confirm) or superseded by a later
    ///   propose/prepare call — re-propose and re-display; rust-layer errors otherwise.
    func signAndStoreMigrationSchedule(accountUUID: AccountUUID, _ schedule: MigrationSchedule, usk: UnifiedSpendingKey) async throws

    /// The broadcast executor: submits the already-proven migration transaction `instruction`
    /// names for `accountUUID`, records the outcome, and returns it.
    ///
    /// The instruction is the payload of a ``MigrationAdvanceStep/broadcast(_:)`` step that a
    /// ``migrationAdvanceStep(accountUUID:)`` crank handed out — and the only way to hold one,
    /// since ``MigrationBroadcastInstruction`` has no public initializer. This executor never
    /// advances the drive and never chooses a transaction: the ZIP 318 re-spread, the
    /// satisfiability verification, and the dueness judgement all happened in the crank that
    /// issued it, so there is no "nothing due" and no "awaiting proof" outcome to report. It
    /// never proves, either: a due row still awaiting its proof is never named by a `.broadcast`
    /// step; the crank reports it inside the `.prove` batch.
    ///
    /// It wraps exactly what an app cannot do for itself: serving the transaction's finalized
    /// bytes through the store's atomic broadcast seam, submitting them under the given privacy
    /// options — always over the dedicated migration Tor runtime when `options.useTor` is set,
    /// independent of the global `tor(enabled:)` toggle and fail-closed — bracketing the submit
    /// in the sync gate's in-flight marker, and recording the result.
    ///
    /// - Parameters:
    ///   - accountUUID: the account the instruction belongs to.
    ///   - instruction: the broadcast instruction the crank returned.
    ///   - options: network-privacy options (Tor, submission endpoint) for this broadcast.
    /// - Throws: ``ZcashError/migrationBroadcastDuringSync`` if the synchronizer is actively syncing —
    ///   sync and migration broadcasts must never share a session; this is enforced by the SDK on
    ///   this call, so stop sync first. Otherwise, a pre-broadcast failure throws untouched (nothing
    ///   was broadcast) — including
    ///   ``ZcashError/rustMigrationTakeBroadcastTransaction(_:)`` when the instruction has gone
    ///   STALE (its row is no longer proved-and-servable, typically because it was already
    ///   broadcast). Discharge a staleness throw by cranking
    ///   ``migrationAdvanceStep(accountUUID:)`` again, not by retrying the executor. A failure to
    ///   record a broadcast that did land throws
    ///   ``ZcashError/migrationRecordFailedAfterBroadcast(_:)`` — the broadcast is real and a
    ///   later attempt self-heals.
    /// - Note: A completed broadcast leaves NO timed hold behind: the gate is behavior-based, so
    ///   ``isMigrationSyncBlocked()``/``start(retry:)`` block only for the seconds this submission
    ///   is in flight, and a caller is free to sync the instant it is recorded. There is exactly
    ///   one submission
    ///   endpoint per attempt, and no txid polling — confirmation comes from scanning. Calls for
    ///   different accounts are unserialized and safe to run concurrently; calls for the *same*
    ///   account are single-flight (a concurrent call waits for the in-flight one rather than
    ///   re-broadcasting, and then meets the staleness refusal above). The sync-state check is
    ///   advisory, point-in-time enforcement, not a
    ///   hard mutual-exclusion lock: a sync started concurrently with an in-flight broadcast is not
    ///   torn down, so hosts should still sequence sync and migration-broadcast sessions themselves.
    func performMigrationBroadcast(
        accountUUID: AccountUUID,
        _ instruction: MigrationBroadcastInstruction,
        options: MigrationNetworkPrivacyOptions
    ) async throws -> MigrationTransferResult

    /// Whether ordinary wallet sync should currently be paused because a migration submission is
    /// in flight for any account in the wallet — including an account with no live activity this
    /// session (a gate file a crashed launch left a marker in still counts).
    ///
    /// The gate is behavior-based: the single present-tense condition is that a migration submit
    /// is between reaching the network and having its outcome recorded, which lasts seconds.
    /// Nothing else holds sync: there is no elapsed-time condition (a fixed post-broadcast delay
    /// is itself an identifiable pattern — a correlation signature rather than a defense against
    /// one; instead, a wake serves the drive's instruction without auto-appending a sync, so sync
    /// sessions start for a reason), no hold on user intent (a manual refresh or an attempt to
    /// create a transaction is never made to wait beyond an in-flight submit), and no
    /// work-pending query (a due row that still needs its proof needs MORE syncing, so
    /// ``hasOverdueMigrationTransfers(accountUUID:useEstimatedTip:)`` deliberately does not gate
    /// sync either).
    ///
    /// Non-throwing: degrades open (returns `false`, i.e. sync allowed) if the check itself fails
    /// rather than blocking sync on an internal error. ``start(retry:)`` consults this and throws
    /// ``ZcashError/migrationSyncBlocked`` while it is `true`.
    func isMigrationSyncBlocked() async -> Bool

    /// A stream of ``isMigrationSyncBlocked()`` at wallet scope: emits the current value on subscribe
    /// and re-evaluates reactively thereafter. The predicate is ``isMigrationSyncBlocked()``'s —
    /// an in-flight submission, and nothing else.
    ///
    /// - Important: The value delivered synchronously on subscribe is a conservative `false` seed; it
    ///   is corrected by the first asynchronous re-evaluation. A subscriber that must be correct from
    ///   its very first value should pair this stream with an initial ``isMigrationSyncBlocked()``
    ///   call.
    var migrationSyncBlockedStream: AnyPublisher<Bool, Never> { get }

    /// Whether `accountUUID` has any scheduled transfer that is past its send height but not yet
    /// broadcast — the "is there actionable work" query, counting an already-proved due
    /// transaction AND a due, dependency-satisfied `Signed` one that still needs its proof.
    /// Informational (re-arm background execution, launch
    /// reconciliation): it is deliberately NOT the sync-gate predicate — a due-but-unproved row
    /// needs MORE syncing and must never block sync, so ``isMigrationSyncBlocked()`` holds only
    /// while a submission is in flight. It is a READ,
    /// never a substitute for ``migrationAdvanceStep(accountUUID:)``: it says whether cranking is
    /// worth a wake-up, never what to do.
    /// - Parameters:
    ///   - accountUUID: the account to check.
    ///   - useEstimatedTip: opts the check into the wall-clock chain-tip estimate, which may only
    ///     ACCELERATE due-ness (expiry stays scanned-tip; estimator failure degrades to the
    ///     scanned-tip behavior) — the same rule ``migrationAdvanceStep(accountUUID:)`` always
    ///     applies. The protocol-extension overload without this parameter defaults it to `false`.
    func hasOverdueMigrationTransfers(accountUUID: AccountUUID, useEstimatedTip: Bool) async throws -> Bool

    /// Whether `accountUUID`'s migration is in an invalid state (spendable Orchard remains but no
    /// scheduled transfer covers it).
    /// - Parameter accountUUID: the account to check.
    func hasInvalidMigrationTransfers(accountUUID: AccountUUID) async throws -> Bool

    /// Re-evaluates `accountUUID`'s remaining spendable Orchard balance and returns a fresh schedule.
    ///
    /// The old plan is no longer valid: the engine discards it and derives a new one, which a
    /// follow-up ``signAndStoreMigrationSchedule(accountUUID:_:usk:)`` (or PCZT store) then signs and
    /// persists.
    /// - Parameter accountUUID: the account to restart.
    func restartCurrentMigrationStep(accountUUID: AccountUUID) async throws -> MigrationSchedule

    /// Rebuilds every EXPIRED transfer of `accountUUID`'s stored migration run in place through the
    /// engine and returns the run's FULL transfer schedule as stored AFTER the refresh.
    ///
    /// Each rebuilt transfer re-spends the SAME funding note (recovered from the expired transfer by
    /// nullifier identity, never an equal-value substitute) on a fresh schedule — a fresh
    /// memoryless delay from the current tip, a fresh canonical expiry, and a freshly drawn
    /// boundary anchor. The transfer ids are unchanged, but their schedule, expiry, and anchors are
    /// all fresh, and those fresh values exist nowhere but in the returned schedule: it is the
    /// atomically-persisted post-refresh truth, and the host MUST re-display it to the user. Once a
    /// run is stored (as it must be, to have anything to refresh), every subsequent commit-shaped
    /// call (``signAndStoreMigrationSchedule(accountUUID:_:usk:)``,
    /// ``createUnsignedNoteSplitPCZTs(accountUUID:for:)``,
    /// ``createUnsignedMigrationTransferPCZTs(accountUUID:for:)``) resumes it handle-free — the
    /// `schedule` argument identifies nothing at that point, so it is the stored run itself
    /// (already refreshed) that the external-signer ceremony converges on, not a comparison against
    /// whatever copy the host happens to pass. With nothing expired the current stored schedule
    /// comes back unchanged; with no stored run, or a terminal (completed or cancelled) one, the
    /// schedule is empty.
    /// - Parameters:
    ///   - accountUUID: the account to refresh.
    ///   - usk: the account's unified spending key, or `nil` for the external-signer (Keystone)
    ///     lane. Passing a key signs each rebuilt transfer anew in-process; passing `nil` (an
    ///     account whose spend authority never exists on this device) leaves the rebuilt transfers
    ///     awaiting their signature, so the existing
    ///     ``createUnsignedMigrationTransferPCZTs(accountUUID:for:)`` /
    ///     ``storeSignedMigrationSchedulePCZTs(accountUUID:_:)`` ceremony re-serves and completes
    ///     them.
    /// - Throws: notably, a `FundingNoteUnavailable`-class failure when an expired transfer's exact
    ///   funding note was spent outside the migration — the underlying message names
    ///   ``restartCurrentMigrationStep(accountUUID:)`` (cancel and re-plan the remaining balance) as
    ///   the remedy. Rebuilds are persisted ALL-OR-NOTHING: a mid-refresh throw (including this one)
    ///   persists NONE of the batch's rebuilds, so a non-throwing return's schedule is exactly what
    ///   was atomically persisted, never a partial batch.
    func refreshStaleMigrationTransfers(accountUUID: AccountUUID, usk: UnifiedSpendingKey?) async throws -> MigrationSchedule

    /// Builds `accountUUID`'s whole previewed migration UNSIGNED — the run is created by this
    /// call, with every transaction persisted awaiting its signature — and returns the preparation
    /// (note-split) subset of the PCZTs for the signing ceremony. The transfer subset of the same
    /// build is served by `createUnsignedMigrationTransferPCZTs(accountUUID:for:)`, so one
    /// ceremony signs everything (the final engine builds N preparation transactions, not one
    /// split transaction). Resumes a stored non-terminal run handle-free; replaces a terminal one.
    /// - Parameters:
    ///   - accountUUID: the account to build the PCZTs for.
    ///   - schedule: the schedule to build the run from, from
    ///     ``proposeMigrationTransfers(accountUUID:)``. Only its `proposalHandle` crosses to the
    ///     native side, and only when this call is the one creating the run (no stored run, or a
    ///     terminal one) — the display fields are never echoed back, and the ordinary resume case
    ///     does not consult the handle at all.
    /// - Throws: `ZcashError.migrationPlanStale` when this call is creating the run and the
    ///   identified plan is missing (process restart between propose and confirm) or superseded by
    ///   a later propose/prepare call — re-propose and re-display before retrying.
    func createUnsignedNoteSplitPCZTs(accountUUID: AccountUUID, for schedule: MigrationSchedule) async throws -> [MigrationUnsignedTransferPczt]

    /// Applies the ceremony's signatures to `accountUUID`'s preparation (note-split) transactions,
    /// all-or-nothing: every element must match a stored transaction awaiting its signature or
    /// nothing is persisted. Returns a STORAGE RECEIPT for the first preparation transaction (its
    /// `txid` is zeroed — the broadcastable, proven value is served by the delivery lane).
    /// - Parameters:
    ///   - accountUUID: the account the PCZTs belong to.
    ///   - signed: the externally signed preparation PCZTs, each paired with its engine id.
    func storeSignedNoteSplitPCZTs(accountUUID: AccountUUID, _ signed: [MigrationSignedTransferPczt]) async throws -> PreparedMigrationTransfer

    /// Builds one unsigned, proven PCZT per transfer of `schedule` for `accountUUID`, for an external
    /// signer. Serves the TRANSFER subset of the same unsigned build
    /// ``createUnsignedNoteSplitPCZTs(accountUUID:for:)`` serves the preparation subset of — the
    /// run and every unsigned transaction it needs normally already exist by the time this is
    /// called, so the usual path here is the handle-free resume of the stored run.
    /// - Parameters:
    ///   - accountUUID: the account the schedule belongs to.
    ///   - schedule: the schedule to build PCZTs for, from ``proposeMigrationTransfers(accountUUID:)``.
    ///     Only its `proposalHandle` crosses to the native side, and it only gates the fresh-build
    ///     case where this call is the one creating the run (no stored run, or a terminal one) —
    ///     the display fields are never echoed back, and the ordinary resume case does not consult
    ///     the handle at all.
    /// - Throws: `ZcashError.migrationPlanStale` when this call is creating the run and the
    ///   identified plan is missing (process restart) or superseded by a later propose/prepare
    ///   call — re-propose and re-display; rust-layer errors otherwise.
    func createUnsignedMigrationTransferPCZTs(accountUUID: AccountUUID, for schedule: MigrationSchedule) async throws -> [MigrationUnsignedTransferPczt]

    /// Accepts the full set of `accountUUID`'s externally signed transfer PCZTs (all-or-nothing),
    /// persisting them in the migration engine.
    ///
    /// The SDK does not retain the proposal list: hosts that need to render the committed schedule
    /// later must persist it themselves at confirmation time.
    /// - Parameters:
    ///   - accountUUID: the account the PCZTs belong to.
    ///   - signed: the full set of externally signed transfer PCZTs.
    func storeSignedMigrationSchedulePCZTs(accountUUID: AccountUUID, _ signed: [MigrationSignedTransferPczt]) async throws

    // MARK: - Migration Keystone batch-signing (external signer ceremony)
    //
    // A DB-free, account-free bridge for driving a Keystone hardware signer through the migration
    // ceremony's PCZTs over an animated multi-part QR UR: none of these calls take an
    // `accountUUID`, since they operate purely on caller-held PCZT bytes (from
    // `createUnsignedNoteSplitPCZTs(accountUUID:for:)` / `createUnsignedMigrationTransferPCZTs(accountUUID:for:)`)
    // and a scanned device response, never touching the wallet database or the migration engine.

    /// Splits an ORDERED unsigned-PCZT batch into signer sessions bounded by
    /// `maxActionsPerSession` actions, preserving order: each returned sub-array is one signing
    /// session, and their concatenation is exactly `pczts`. Run each session through the QR
    /// ceremony (``buildKeystoneSignBatchQRParts(requestId:pczts:maxFragmentLen:)`` ...) on its
    /// own.
    ///
    /// Action-weighted, not count-based: the split packs by each row's
    /// ``MigrationUnsignedTransferPczt/actions`` weight (16 preparation / 3 transfer) with an
    /// order-preserving greedy strategy — the CREATE/RE-SERVE order carries the ceremony's
    /// preparation-then-transfer contract, so reordering is not an option here (unlike the
    /// estimate's ``MigrationRunEstimate/Run/keystoneSigningSessions``, which packs optimally
    /// because nothing is dispatched yet). Account-free like the rest of this group: it weighs
    /// caller-held rows, never the wallet database.
    /// - Parameters:
    ///   - pczts: the unsigned PCZTs to split, in ceremony order (preparations first, then
    ///     transfers) — rows from the CREATE/RE-SERVE calls, whose `actions` weights are
    ///     populated.
    ///   - maxActionsPerSession: the signer's per-session action budget — e.g.
    ///     ``MigrationSigningBudget/keystone`` (96) — at least 16 (a single preparation
    ///     transaction, the minimum any signer must support).
    /// - Throws: `ZcashError.rustMigrationBatchPcztsByActions` when any row's weight is not
    ///   exactly 16 or 3 (e.g. rows returned by
    ///   ``applyKeystoneBatchSignatures(pczts:batchSignResponse:)``, which carry `0`), or when
    ///   `maxActionsPerSession` is below 16 — caller bugs, not signer conditions.
    func batchMigrationPcztsForSigning(
        _ pczts: [MigrationUnsignedTransferPczt],
        maxActionsPerSession: Int
    ) async throws -> [[MigrationUnsignedTransferPczt]]

    /// Builds the animated multi-part QR frames for a Keystone batch-signing request covering
    /// every PCZT in `pczts`, in the given order.
    ///
    /// `pczts` MUST be preparation (note-split) PCZTs first, then transfer PCZTs, in schedule
    /// order -- and the caller MUST pass this SAME array, in this SAME order, to
    /// ``applyKeystoneBatchSignatures(pczts:batchSignResponse:)`` once the device responds; the
    /// response's signatures are aligned by position, not by any id embedded in the wire format.
    ///
    /// Every PCZT is redacted for the batch-Signer role INSIDE this call before it reaches the
    /// wire (the signing firmware rejects a batch request carrying a pre-existing spend
    /// authorization signature). Callers must NOT pre-redact, and must retain their own
    /// unredacted `pczts` -- those unredacted bytes are what
    /// ``applyKeystoneBatchSignatures(pczts:batchSignResponse:)`` applies the device's signatures
    /// onto.
    /// - Parameters:
    ///   - requestId: an opaque correlation token (e.g. a UUID's bytes), round-tripped by the
    ///     device and checked in ``decodeKeystoneSignBatchPart(_:expectedRequestId:)`` to reject a
    ///     scan of an unrelated/stale response.
    ///   - pczts: the unsigned PCZTs to include, preparation-then-transfer, schedule order.
    ///   - maxFragmentLen: the maximum byte length of each animated QR frame's payload.
    /// - Returns: the QR frame strings, in wire fragment order -- display/scan them in that order.
    func buildKeystoneSignBatchQRParts(requestId: Data, pczts: [MigrationUnsignedTransferPczt], maxFragmentLen: Int) async throws -> [String]

    /// Discards any in-flight multi-part Keystone sign-batch-response scan session.
    ///
    /// Only one decode session exists at a time. Call this on scan-screen entry, on retry, and on
    /// exit, so a new attempt always starts from a clean slate regardless of how a previous
    /// attempt ended (cancel, back button, mid-stream error). Non-throwing and infallible.
    func resetKeystoneSignBatchDecoder() async

    /// Feeds one scanned QR frame into the active (or a freshly started) Keystone
    /// sign-batch-response decode session.
    ///
    /// `expectedRequestId` must match the decoded response's own request id once complete, or
    /// this throws (a scan of an unrelated/stale response) instead of silently accepting it.
    /// - Parameters:
    ///   - part: the scanned QR frame's raw string payload.
    ///   - expectedRequestId: the request id passed to
    ///     ``buildKeystoneSignBatchQRParts(requestId:pczts:maxFragmentLen:)`` for this ceremony.
    /// - Returns: a ``KeystoneBatchDecodeResult`` -- `complete == false` while more frames are
    ///   needed (`progress` reports 0-100 so far, `data`/`firmwareVersion` are `nil`);
    ///   `complete == true` once the full response has been decoded, with `data` holding the
    ///   batch-signature response and, when the device's response envelope carried it,
    ///   `firmwareVersion` set. The response is signatures-only -- no PCZT is echoed back by the
    ///   device -- and `firmwareVersion` is the ONLY way to learn the signing device's firmware
    ///   version in this batch flow.
    func decodeKeystoneSignBatchPart(_ part: String, expectedRequestId: Data) async throws -> KeystoneBatchDecodeResult

    /// Applies the ceremony's Keystone batch signatures to `pczts`, positionally.
    ///
    /// `pczts` MUST be the SAME array, in the SAME order, passed to
    /// ``buildKeystoneSignBatchQRParts(requestId:pczts:maxFragmentLen:)`` -- including the SAME
    /// unredacted bytes retained from that call, never the redacted wire copy.
    /// `batchSignResponse` is the `KeystoneBatchDecodeResult.data` a completed
    /// ``decodeKeystoneSignBatchPart(_:expectedRequestId:)`` returned.
    /// - Returns: one signed PCZT per element of `pczts`, in the same order, ready for the
    ///   existing note-split / schedule storage calls
    ///   (``storeSignedNoteSplitPCZTs(accountUUID:_:)`` /
    ///   ``storeSignedMigrationSchedulePCZTs(accountUUID:_:)``).
    func applyKeystoneBatchSignatures(pczts: [MigrationUnsignedTransferPczt], batchSignResponse: Data) async throws -> [MigrationSignedTransferPczt]
}

/// Error thrown by the default `Synchronizer.getTreeState(height:)` implementation
/// when a conformer without a lightwalletd source doesn't override it. Hoisted to
/// file scope because Swift forbids nesting concrete types with synthesized members
/// inside a generic function — protocol-extension methods carry an implicit `Self`
/// and so count as generic.
private struct GetTreeStateUnimplemented: LocalizedError {
    var errorDescription: String? {
        """
        Synchronizer.getTreeState(height:) has no default implementation. \
        Override this method in your Synchronizer conformer to provide a tree-state source.
        """
    }
}

/// Error thrown by the default `Synchronizer.broadcaster` implementation.
private struct BroadcasterUnimplemented: LocalizedError {
    var errorDescription: String? {
        """
        Synchronizer.broadcaster has no default implementation. \
        Override this property in your Synchronizer conformer to provide broadcast support.
        """
    }
}

/// Error thrown by the default implementations of the throwing members of the migration group (see
/// `public extension Synchronizer` below) when a conformer doesn't override them. One shared,
/// member-parameterized type rather than one hoisted struct per member (as
/// ``GetTreeStateUnimplemented``/``BroadcasterUnimplemented`` do): the migration group has over
/// thirty throwing requirements, and duplicating that two-struct precedent once per member would
/// be pure boilerplate for the same LocalizedError-conforming, "override this in your conformer"
/// pattern. Hoisted to file scope for the same reason as those two — protocol-extension methods
/// carry an implicit `Self` and so count as generic, and Swift forbids nesting concrete types with
/// synthesized members inside a generic function.
private struct MigrationUnimplemented: LocalizedError {
    /// The unimplemented member's signature, supplied by each default via `#function`.
    let member: String

    var errorDescription: String? {
        """
        Synchronizer.\(member) has no default implementation. \
        Override this member in your Synchronizer conformer to provide migration support.
        """
    }
}

/// Default broadcaster used by `Synchronizer` conformers that do not override
/// `broadcaster`.
private final class UnimplementedBroadcaster: Broadcaster {
    func createProposedTransactions(
        proposal: Proposal,
        spendingKey: UnifiedSpendingKey
    ) async throws -> [CreatedTransaction] {
        throw BroadcasterUnimplemented()
    }

    func createTransactionFromPCZT(
        pcztWithProofs: Pczt,
        pcztWithSigs: Pczt
    ) async throws -> [CreatedTransaction] {
        throw BroadcasterUnimplemented()
    }

    func submit(
        transaction: CreatedTransaction,
        to endpoints: [LightWalletEndpoint],
        timing: SubmissionTiming
    ) async -> TransactionSubmissionOutcome {
        // Non-throwing API: unavailability is reported as unreachable.
        .unreachable
    }

    func submit(
        transactions: [CreatedTransaction],
        to endpoints: [LightWalletEndpoint],
        timing: SubmissionTiming
    ) async -> [TransactionSubmissionReport] {
        transactions.enumerated().map { index, transaction in
            TransactionSubmissionReport(
                txId: transaction.txId,
                outcome: index == 0 ? .unreachable : .notAttempted
            )
        }
    }
}

public extension Synchronizer {
    /// Default implementation so adding `getTreeState(height:)` to the protocol is
    /// not a source-breaking change for downstream conformers. Conformers that have
    /// a lightwalletd connection (such as `SDKSynchronizer`) override this;
    /// conformers that don't — mocks, stubs, alternate transports — fall through to
    /// this default and report the feature as unavailable.
    func getTreeState(height: UInt64) async throws -> Data {
        throw GetTreeStateUnimplemented()
    }

    /// Default implementation so adding `broadcaster` to the protocol is not a
    /// source-breaking change for downstream conformers. Conformers with broadcast
    /// support override this; mocks, stubs, and alternate transports can fall
    /// through to this default and report the feature as unavailable.
    var broadcaster: Broadcaster {
        UnimplementedBroadcaster()
    }

    // MARK: - Migration (Orchard -> Ironwood) defaults
    //
    // Default implementations so adding the migration group to the protocol is not a
    // source-breaking change for downstream/stacked conformers (in particular the
    // `SlipstreamSynchronizer` stack, until it carries its own implementations). Conformers with
    // migration support (`SDKSynchronizer`) override every one of these; conformers that don't fall
    // through here. The throwing members all throw `MigrationUnimplemented`; the four non-throwing
    // members get inert defaults instead, documented below — conformers must override them to offer
    // real migration behavior.

    func migrationAdvanceStep(accountUUID: AccountUUID) async throws -> MigrationAdvance? {
        throw MigrationUnimplemented(member: #function)
    }

    func migrationProgress(accountUUID: AccountUUID) async throws -> MigrationProgress? {
        throw MigrationUnimplemented(member: #function)
    }

    func proveMigrationTransactions(
        accountUUID: AccountUUID,
        _ instruction: [MigrationProveTarget],
        maxProofs: Int
    ) async throws -> MigrationProveOutcome {
        throw MigrationUnimplemented(member: #function)
    }

    func takeMigrationPreparation(accountUUID: AccountUUID, byTxid txid: Data) async throws -> PreparedMigrationTransfer {
        throw MigrationUnimplemented(member: #function)
    }

    func recordMigrationPreparationBroadcast(
        accountUUID: AccountUUID,
        _ prepared: PreparedMigrationTransfer,
        result: MigrationTransferResult
    ) async throws {
        throw MigrationUnimplemented(member: #function)
    }

    func migrationSyncWakeups(accountUUID: AccountUUID) async throws -> [MigrationSyncWakeup] {
        throw MigrationUnimplemented(member: #function)
    }

    /// Inert default: conformers must override to provide the retained-outlook accessor. `nil` is
    /// the correct "no crank has run" answer either way, so this default needs no throwing variant.
    func nextMigrationWake(accountUUID: AccountUUID) async -> MigrationNextWork? {
        nil
    }

    func estimatedMigrationChainTip() async throws -> BlockHeight {
        throw MigrationUnimplemented(member: #function)
    }

    func estimatedMigrationSecondsPerBlock() async throws -> Double {
        throw MigrationUnimplemented(member: #function)
    }

    func migrationTransactionStatuses(accountUUID: AccountUUID) async throws -> [MigrationTransactionStatus] {
        throw MigrationUnimplemented(member: #function)
    }

    func isNoteSplitNeeded(accountUUID: AccountUUID) async throws -> Bool {
        throw MigrationUnimplemented(member: #function)
    }

    func prepareNoteSplit(accountUUID: AccountUUID) async throws -> NoteSplitProposal {
        throw MigrationUnimplemented(member: #function)
    }

    func submitNoteSplit(
        accountUUID: AccountUUID,
        proposal: NoteSplitProposal,
        usk: UnifiedSpendingKey,
        options: MigrationNetworkPrivacyOptions
    ) async throws -> MigrationTransferResult {
        throw MigrationUnimplemented(member: #function)
    }

    func proposeMigrationTransfers(accountUUID: AccountUUID) async throws -> MigrationSchedule {
        throw MigrationUnimplemented(member: #function)
    }

    func proposeImmediateMigration(accountUUID: AccountUUID) async throws -> ImmediateMigrationProposal {
        throw MigrationUnimplemented(member: #function)
    }

    func recordImmediateMigration(accountUUID: AccountUUID, txid: Data) async throws {
        throw MigrationUnimplemented(member: #function)
    }

    func residualAfterMigration(accountUUID: AccountUUID) async throws -> Zatoshi? {
        throw MigrationUnimplemented(member: #function)
    }

    func lockMigrationResidual(accountUUID: AccountUUID) async throws -> Zatoshi {
        throw MigrationUnimplemented(member: #function)
    }

    func unlockMigrationResidual(accountUUID: AccountUUID) async throws -> Int {
        throw MigrationUnimplemented(member: #function)
    }

    func estimateMigrationRuns(accountUUID: AccountUUID) async throws -> MigrationRunEstimate {
        throw MigrationUnimplemented(member: #function)
    }

    func signAndStoreMigrationSchedule(accountUUID: AccountUUID, _ schedule: MigrationSchedule, usk: UnifiedSpendingKey) async throws {
        throw MigrationUnimplemented(member: #function)
    }

    func performMigrationBroadcast(
        accountUUID: AccountUUID,
        _ instruction: MigrationBroadcastInstruction,
        options: MigrationNetworkPrivacyOptions
    ) async throws -> MigrationTransferResult {
        throw MigrationUnimplemented(member: #function)
    }

    /// Inert default: conformers must override to provide the wallet-scope migration privacy gate.
    func isMigrationSyncBlocked() async -> Bool {
        false
    }

    /// Inert default: conformers must override to provide the wallet-scope migration privacy gate.
    var migrationSyncBlockedStream: AnyPublisher<Bool, Never> {
        Just(false).eraseToAnyPublisher()
    }

    func hasOverdueMigrationTransfers(accountUUID: AccountUUID, useEstimatedTip: Bool) async throws -> Bool {
        throw MigrationUnimplemented(member: #function)
    }

    /// Convenience overload of the protocol requirement, defaulting `useEstimatedTip` to `false`
    /// (scanned-tip due-ness only) so one-argument call sites keep reading naturally.
    func hasOverdueMigrationTransfers(accountUUID: AccountUUID) async throws -> Bool {
        try await hasOverdueMigrationTransfers(accountUUID: accountUUID, useEstimatedTip: false)
    }

    func hasInvalidMigrationTransfers(accountUUID: AccountUUID) async throws -> Bool {
        throw MigrationUnimplemented(member: #function)
    }

    func restartCurrentMigrationStep(accountUUID: AccountUUID) async throws -> MigrationSchedule {
        throw MigrationUnimplemented(member: #function)
    }

    func refreshStaleMigrationTransfers(accountUUID: AccountUUID, usk: UnifiedSpendingKey?) async throws -> MigrationSchedule {
        throw MigrationUnimplemented(member: #function)
    }

    func createUnsignedNoteSplitPCZTs(accountUUID: AccountUUID, for schedule: MigrationSchedule) async throws -> [MigrationUnsignedTransferPczt] {
        throw MigrationUnimplemented(member: #function)
    }

    func storeSignedNoteSplitPCZTs(accountUUID: AccountUUID, _ signed: [MigrationSignedTransferPczt]) async throws -> PreparedMigrationTransfer {
        throw MigrationUnimplemented(member: #function)
    }

    func createUnsignedMigrationTransferPCZTs(accountUUID: AccountUUID, for schedule: MigrationSchedule) async throws -> [MigrationUnsignedTransferPczt] {
        throw MigrationUnimplemented(member: #function)
    }

    func storeSignedMigrationSchedulePCZTs(accountUUID: AccountUUID, _ signed: [MigrationSignedTransferPczt]) async throws {
        throw MigrationUnimplemented(member: #function)
    }

    func batchMigrationPcztsForSigning(
        _ pczts: [MigrationUnsignedTransferPczt],
        maxActionsPerSession: Int
    ) async throws -> [[MigrationUnsignedTransferPczt]] {
        throw MigrationUnimplemented(member: #function)
    }

    func buildKeystoneSignBatchQRParts(requestId: Data, pczts: [MigrationUnsignedTransferPczt], maxFragmentLen: Int) async throws -> [String] {
        throw MigrationUnimplemented(member: #function)
    }

    /// Inert default: conformers must override to provide real Keystone batch-signing decode
    /// session support. Mirrors `isMigrationSyncBlocked()`'s non-throwing inert-default
    /// treatment: this member is infallible by contract (see the protocol doc), so it cannot
    /// throw `MigrationUnimplemented` the way its throwing siblings do.
    func resetKeystoneSignBatchDecoder() async { }

    func decodeKeystoneSignBatchPart(_ part: String, expectedRequestId: Data) async throws -> KeystoneBatchDecodeResult {
        throw MigrationUnimplemented(member: #function)
    }

    func applyKeystoneBatchSignatures(pczts: [MigrationUnsignedTransferPczt], batchSignResponse: Data) async throws -> [MigrationSignedTransferPczt] {
        throw MigrationUnimplemented(member: #function)
    }
}

public extension ClosureSynchronizer {
    /// Default implementation so adding `broadcaster` to the protocol is not a
    /// source-breaking change for downstream conformers. Conformers with broadcast
    /// support override this; mocks, stubs, and alternate transports can fall
    /// through to this default and report the feature as unavailable.
    var broadcaster: Broadcaster {
        UnimplementedBroadcaster()
    }
}

public extension CombineSynchronizer {
    /// Default implementation so adding `broadcaster` to the protocol is not a
    /// source-breaking change for downstream conformers. Conformers with broadcast
    /// support override this; mocks, stubs, and alternate transports can fall
    /// through to this default and report the feature as unavailable.
    var broadcaster: Broadcaster {
        UnimplementedBroadcaster()
    }
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

//
//  ClosureSynchronizer.swift
//  
//
//  Created by Michal Fousek on 20.03.2023.
//

import Combine
import Foundation

/// This defines closure-based API for the SDK. It's expected that the implementation of this protocol is only a very thin layer that translates async
/// API defined in `Synchronizer` to closure-based API. And it doesn't do anything else. It's here so each client can choose the API that suits its
/// case the best.
///
/// If you are looking for documentation for a specific method or property look for it in the `Synchronizer` protocol.
public protocol ClosureSynchronizer {
    var alias: ZcashSynchronizerAlias { get }

    var latestState: SynchronizerState { get }
    var connectionState: ConnectionState { get }

    var stateStream: AnyPublisher<SynchronizerState, Never> { get }
    var eventStream: AnyPublisher<SynchronizerEvent, Never> { get }

    // swiftlint:disable:next function_parameter_count
    func prepare(
        with seed: [UInt8]?,
        walletBirthday: BlockHeight,
        for walletMode: WalletInitMode,
        name: String,
        keySource: String?,
        completion: @escaping (Result<Initializer.InitializationResult, Error>) -> Void
    )

    func start(retry: Bool, completion: @escaping (Error?) -> Void)
    func stop()

    func getSaplingAddress(accountUUID: AccountUUID, completion: @escaping (Result<SaplingAddress, Error>) -> Void)
    func getUnifiedAddress(accountUUID: AccountUUID, completion: @escaping (Result<UnifiedAddress, Error>) -> Void)
    func getTransparentAddress(accountUUID: AccountUUID, completion: @escaping (Result<TransparentAddress, Error>) -> Void)
    func getCustomUnifiedAddress(accountUUID: AccountUUID, receivers: Set<ReceiverType>, completion: @escaping (Result<UnifiedAddress, Error>) -> Void)

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
        memo: Memo?,
        completion: @escaping (Result<Proposal, Error>) -> Void
    )

    /// Creates a proposal for shielding any transparent funds received by the given account.
    ///
    /// - Parameter accountUUID: the account from which to shield funds.
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
        transparentReceiver: TransparentAddress?,
        completion: @escaping (Result<Proposal?, Error>) -> Void
    )

    /// Creates the transactions in the given proposal.
    ///
    /// - Parameter proposal: the proposal for which to create transactions.
    /// - Parameter spendingKey: the `UnifiedSpendingKey` associated with the account for which the proposal was created.
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
    ///   - completion: Completion handler.
    ///
    /// If `prepare()` hasn't already been called since creation of the synchronizer instance
    /// or since the last wipe then this method throws `SynchronizerErrors.notPrepared`.
    func createProposedTransactions(
        proposal: Proposal,
        spendingKey: UnifiedSpendingKey,
        completion: @escaping (Result<AsyncThrowingStream<TransactionSubmitResult, Error>, Error>) -> Void
    )

    func createPCZTFromProposal(
        accountUUID: AccountUUID,
        proposal: Proposal,
        completion: @escaping (Result<Pczt, Error>) -> Void
    )

    func redactPCZTForSigner(
        pczt: Pczt,
        completion: @escaping (Result<Pczt, Error>) -> Void
    )

    func PCZTRequiresSaplingProofs(
        pczt: Pczt,
        completion: @escaping (Bool) -> Void
    )

    func addProofsToPCZT(
        pczt: Pczt,
        completion: @escaping (Result<Pczt, Error>) -> Void
    )
    
    func createTransactionFromPCZT(
        pcztWithProofs: Pczt,
        pcztWithSigs: Pczt,
        completion: @escaping (Result<AsyncThrowingStream<TransactionSubmitResult, Error>, Error>) -> Void
    )

    func listAccounts(completion: @escaping (Result<[Account], Error>) -> Void)

    // swiftlint:disable:next function_parameter_count
    func importAccount(
        ufvk: String,
        seedFingerprint: [UInt8]?,
        zip32AccountIndex: Zip32AccountIndex?,
        purpose: AccountPurpose,
        name: String,
        keySource: String?,
        completion: @escaping (Result<AccountUUID, Error>) -> Void
    ) async throws

    func clearedTransactions(completion: @escaping ([ZcashTransaction.Overview]) -> Void)
    func sentTranscations(completion: @escaping ([ZcashTransaction.Overview]) -> Void)
    func receivedTransactions(completion: @escaping ([ZcashTransaction.Overview]) -> Void)
    func paginatedTransactions(of kind: TransactionKind) -> PaginatedTransactionRepository
    func getMemos(for transaction: ZcashTransaction.Overview, completion: @escaping (Result<[Memo], Error>) -> Void)
    func getRecipients(for transaction: ZcashTransaction.Overview, completion: @escaping ([TransactionRecipient]) -> Void)

    func allConfirmedTransactions(
        from transaction: ZcashTransaction.Overview,
        limit: Int,
        completion: @escaping (Result<[ZcashTransaction.Overview], Error>) -> Void
    )

    func latestHeight(completion: @escaping (Result<BlockHeight, Error>) -> Void)

    func refreshUTXOs(address: TransparentAddress, from height: BlockHeight, completion: @escaping (Result<RefreshedUTXOs, Error>) -> Void)

    func getAccountsBalances(_ completion: @escaping (Result<[AccountUUID: AccountBalance], Error>) -> Void)

    func refreshExchangeRateUSD()

    func estimateBirthdayHeight(for date: Date, completion: @escaping (BlockHeight) -> Void)

    func httpRequestOverTor(for request: URLRequest, retryLimit: UInt8, completion: @escaping (Result<(data: Data, response: HTTPURLResponse), Error>) -> Void)
    
    /*
     It can be missleading that these two methods are returning Publisher even this protocol is closure based. Reason is that Synchronizer doesn't
     provide different implementations for these two methods. So Combine it is even here.
     */
    func rewind(_ policy: RewindPolicy) -> CompletablePublisher<Error>
    func wipe() -> CompletablePublisher<Error>
}

//
//  CombineSynchronizer.swift
//  
//
//  Created by Michal Fousek on 16.03.2023.
//

import Combine
import Foundation

/// This defines a Combine-based API for the SDK. It's expected that the implementation of this protocol is only a very thin layer that translates
/// async API defined in `Synchronizer` to Combine-based API. And it doesn't do anything else. It's here so each client can choose the API that suits
/// its case the best.
///
/// If you are looking for documentation for a specific method or property look for it in the `Synchronizer` protocol.
public protocol CombineSynchronizer {
    var alias: ZcashSynchronizerAlias { get }

    var latestState: SynchronizerState { get }
    var connectionState: ConnectionState { get }

    var stateStream: AnyPublisher<SynchronizerState, Never> { get }
    var eventStream: AnyPublisher<SynchronizerEvent, Never> { get }

    func prepare(
        with seed: [UInt8]?,
        walletBirthday: BlockHeight,
        for walletMode: WalletInitMode,
        name: String,
        keySource: String?
    ) -> SinglePublisher<Initializer.InitializationResult, Error>

    func start(retry: Bool) -> CompletablePublisher<Error>
    func stop()

    func getSaplingAddress(accountUUID: AccountUUID) -> SinglePublisher<SaplingAddress, Error>
    func getUnifiedAddress(accountUUID: AccountUUID) -> SinglePublisher<UnifiedAddress, Error>
    func getTransparentAddress(accountUUID: AccountUUID) -> SinglePublisher<TransparentAddress, Error>
    func getCustomUnifiedAddress(accountUUID: AccountUUID, receivers: Set<ReceiverType>) -> SinglePublisher<UnifiedAddress, Error>

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
    ) -> SinglePublisher<Proposal, Error>

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
        transparentReceiver: TransparentAddress?
    ) -> SinglePublisher<Proposal?, Error>

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
    ///
    /// - Parameters:
    ///   - proposal: The proposal for which to create transactions. Attach a
    ///     `Proposal.PIRWitnessConfig` via `proposal.pirWitnessConfig` to enable PIR witness
    ///     fetching when the wallet is not fully synced.
    ///   - spendingKey: The `UnifiedSpendingKey` for the account that controls the funds.
    func createProposedTransactions(
        proposal: Proposal,
        spendingKey: UnifiedSpendingKey
    ) -> SinglePublisher<AsyncThrowingStream<TransactionSubmitResult, Error>, Error>

    func createPCZTFromProposal(
        accountUUID: AccountUUID,
        proposal: Proposal
    ) -> SinglePublisher<Pczt, Error>

    func redactPCZTForSigner(
        pczt: Pczt
    ) -> SinglePublisher<Pczt, Error>

    func PCZTRequiresSaplingProofs(
        pczt: Pczt
    ) -> SinglePublisher<Bool, Never>

    func addProofsToPCZT(
        pczt: Pczt
    ) -> SinglePublisher<Pczt, Error>

    func createTransactionFromPCZT(
        pcztWithProofs: Pczt,
        pcztWithSigs: Pczt
    ) -> SinglePublisher<AsyncThrowingStream<TransactionSubmitResult, Error>, Error>
    
    func proposefulfillingPaymentURI(
        _ uri: String,
        accountUUID: AccountUUID
    ) -> SinglePublisher<Proposal, Error>

    func listAccounts() -> SinglePublisher<[Account], Error>

    // swiftlint:disable:next function_parameter_count
    func importAccount(
        ufvk: String,
        seedFingerprint: [UInt8]?,
        zip32AccountIndex: Zip32AccountIndex?,
        purpose: AccountPurpose,
        name: String,
        keySource: String?
    ) async throws -> SinglePublisher<AccountUUID, Error>

    var allTransactions: SinglePublisher<[ZcashTransaction.Overview], Never> { get }
    var sentTransactions: SinglePublisher<[ZcashTransaction.Overview], Never> { get }
    var receivedTransactions: SinglePublisher<[ZcashTransaction.Overview], Never> { get }

    func paginatedTransactions(of kind: TransactionKind) -> PaginatedTransactionRepository

    func getMemos(for transaction: ZcashTransaction.Overview) -> SinglePublisher<[Memo], Error>

    func getRecipients(for transaction: ZcashTransaction.Overview) -> SinglePublisher<[TransactionRecipient], Never>

    func allTransactions(from transaction: ZcashTransaction.Overview, limit: Int) -> SinglePublisher<[ZcashTransaction.Overview], Error>

    func latestHeight() -> SinglePublisher<BlockHeight, Error>

    func refreshUTXOs(address: TransparentAddress, from height: BlockHeight) -> SinglePublisher<RefreshedUTXOs, Error>

    func refreshExchangeRateUSD()

    func estimateBirthdayHeight(for date: Date) -> SinglePublisher<BlockHeight, Error>

    func httpRequestOverTor(for request: URLRequest, retryLimit: UInt8) -> SinglePublisher<(data: Data, response: HTTPURLResponse), Error>
    
    func rewind(_ policy: RewindPolicy) -> CompletablePublisher<Error>
    func wipe() -> CompletablePublisher<Error>
}

//
//  ClosureSDKSynchronizer.swift
//  
//
//  Created by Michal Fousek on 20.03.2023.
//

import Combine
import Foundation

/// This is a super thin layer that implements the `ClosureSynchronizer` protocol and translates the async API defined in `Synchronizer` to
/// closure-based API. And it doesn't do anything else. It doesn't keep any state.  It's here so each client can choose the API that suits its case
/// the best. And usage of this can be combined with usage of `CombineSDKSynchronizer`. So devs can really choose the best SDK API for each part of the
/// client app.
///
/// If you are looking for documentation for a specific method or property look for it in the `Synchronizer` protocol.
public struct ClosureSDKSynchronizer {
    private let synchronizer: Synchronizer

    public init(synchronizer: Synchronizer) {
        self.synchronizer = synchronizer
    }
}

extension ClosureSDKSynchronizer: ClosureSynchronizer {
    public var alias: ZcashSynchronizerAlias { synchronizer.alias }

    public var latestState: SynchronizerState { synchronizer.latestState }
    public var connectionState: ConnectionState { synchronizer.connectionState }

    public var stateStream: AnyPublisher<SynchronizerState, Never> { synchronizer.stateStream }
    public var eventStream: AnyPublisher<SynchronizerEvent, Never> { synchronizer.eventStream }

    // swiftlint:disable:next function_parameter_count
    public func prepare(
        with seed: [UInt8]?,
        walletBirthday: BlockHeight,
        for walletMode: WalletInitMode,
        name: String,
        keySource: String?,
        completion: @escaping (Result<Initializer.InitializationResult, Error>) -> Void
    ) {
        AsyncToClosureGateway.executeThrowingAction(completion) {
            return try await self.synchronizer.prepare(
                with: seed,
                walletBirthday: walletBirthday,
                for: walletMode,
                name: name,
                keySource: keySource
            )
        }
    }

    public func start(retry: Bool, completion: @escaping (Error?) -> Void) {
        AsyncToClosureGateway.executeThrowingAction(completion) {
            try await self.synchronizer.start(retry: retry)
        }
    }

    public func stop() {
        synchronizer.stop()
    }

    public func getSaplingAddress(accountUUID: AccountUUID, completion: @escaping (Result<SaplingAddress, Error>) -> Void) {
        AsyncToClosureGateway.executeThrowingAction(completion) {
            try await self.synchronizer.getSaplingAddress(accountUUID: accountUUID)
        }
    }

    public func getUnifiedAddress(accountUUID: AccountUUID, completion: @escaping (Result<UnifiedAddress, Error>) -> Void) {
        AsyncToClosureGateway.executeThrowingAction(completion) {
            try await self.synchronizer.getUnifiedAddress(accountUUID: accountUUID)
        }
    }

    public func getTransparentAddress(accountUUID: AccountUUID, completion: @escaping (Result<TransparentAddress, Error>) -> Void) {
        AsyncToClosureGateway.executeThrowingAction(completion) {
            try await self.synchronizer.getTransparentAddress(accountUUID: accountUUID)
        }
    }

    public func getCustomUnifiedAddress(accountUUID: AccountUUID, receivers: Set<ReceiverType>, completion: @escaping (Result<UnifiedAddress, Error>) -> Void) {
        AsyncToClosureGateway.executeThrowingAction(completion) {
            try await self.synchronizer.getCustomUnifiedAddress(accountUUID: accountUUID, receivers: receivers)
        }
    }

    public func listAccounts(completion: @escaping (Result<[Account], Error>) -> Void) {
        AsyncToClosureGateway.executeThrowingAction(completion) {
            try await self.synchronizer.listAccounts()
        }
    }

    // swiftlint:disable:next function_parameter_count
    public func importAccount(
        ufvk: String,
        seedFingerprint: [UInt8]?,
        zip32AccountIndex: Zip32AccountIndex?,
        purpose: AccountPurpose,
        name: String,
        keySource: String?,
        completion: @escaping (Result<AccountUUID, Error>) -> Void
    ) async throws {
        AsyncToClosureGateway.executeThrowingAction(completion) {
            try await self.synchronizer.importAccount(
                ufvk: ufvk,
                seedFingerprint: seedFingerprint,
                zip32AccountIndex: zip32AccountIndex,
                purpose: purpose,
                name: name,
                keySource: keySource
            )
        }
    }

    public func proposeTransfer(
        accountUUID: AccountUUID,
        recipient: Recipient,
        amount: Zatoshi,
        memo: Memo?,
        completion: @escaping (Result<Proposal, Error>) -> Void
    ) {
        AsyncToClosureGateway.executeThrowingAction(completion) {
            try await self.synchronizer.proposeTransfer(accountUUID: accountUUID, recipient: recipient, amount: amount, memo: memo)
        }
    }

    public func proposeShielding(
        accountUUID: AccountUUID,
        shieldingThreshold: Zatoshi,
        memo: Memo,
        transparentReceiver: TransparentAddress? = nil,
        completion: @escaping (Result<Proposal?, Error>) -> Void
    ) {
        AsyncToClosureGateway.executeThrowingAction(completion) {
            try await self.synchronizer.proposeShielding(
                accountUUID: accountUUID,
                shieldingThreshold: shieldingThreshold,
                memo: memo,
                transparentReceiver: transparentReceiver
            )
        }
    }

    public func createProposedTransactions(
        proposal: Proposal,
        spendingKey: UnifiedSpendingKey,
        completion: @escaping (Result<AsyncThrowingStream<TransactionSubmitResult, Error>, Error>) -> Void
    ) {
        AsyncToClosureGateway.executeThrowingAction(completion) {
            try await self.synchronizer.createProposedTransactions(proposal: proposal, spendingKey: spendingKey)
        }
    }

    public func createPCZTFromProposal(
        accountUUID: AccountUUID,
        proposal: Proposal,
        completion: @escaping (Result<Pczt, Error>) -> Void
    ) {
        AsyncToClosureGateway.executeThrowingAction(completion) {
            try await self.synchronizer.createPCZTFromProposal(accountUUID: accountUUID, proposal: proposal)
        }
    }

    public func redactPCZTForSigner(
        pczt: Pczt,
        completion: @escaping (Result<Pczt, Error>) -> Void
    ) {
        AsyncToClosureGateway.executeThrowingAction(completion) {
            try await self.synchronizer.redactPCZTForSigner(pczt: pczt)
        }
    }

    public func PCZTRequiresSaplingProofs(
        pczt: Pczt,
        completion: @escaping (Bool) -> Void
    ) {
        AsyncToClosureGateway.executeAction(completion) {
            await self.synchronizer.PCZTRequiresSaplingProofs(pczt: pczt)
        }
    }

    public func addProofsToPCZT(
        pczt: Pczt,
        completion: @escaping (Result<Pczt, Error>) -> Void
    ) {
        AsyncToClosureGateway.executeThrowingAction(completion) {
            try await self.synchronizer.addProofsToPCZT(pczt: pczt)
        }
    }

    public func createTransactionFromPCZT(
        pcztWithProofs: Pczt,
        pcztWithSigs: Pczt,
        completion: @escaping (Result<AsyncThrowingStream<TransactionSubmitResult, Error>, Error>) -> Void
    ) {
        AsyncToClosureGateway.executeThrowingAction(completion) {
            try await self.synchronizer.createTransactionFromPCZT(pcztWithProofs: pcztWithProofs, pcztWithSigs: pcztWithSigs)
        }
    }

    public func clearedTransactions(completion: @escaping ([ZcashTransaction.Overview]) -> Void) {
        AsyncToClosureGateway.executeAction(completion) {
            await self.synchronizer.transactions
        }
    }

    public func sentTranscations(completion: @escaping ([ZcashTransaction.Overview]) -> Void) {
        AsyncToClosureGateway.executeAction(completion) {
            await self.synchronizer.sentTransactions
        }
    }

    public func receivedTransactions(completion: @escaping ([ZcashTransaction.Overview]) -> Void) {
        AsyncToClosureGateway.executeAction(completion) {
            await self.synchronizer.receivedTransactions
        }
    }
    
    public func paginatedTransactions(of kind: TransactionKind) -> PaginatedTransactionRepository { synchronizer.paginatedTransactions(of: kind) }

    public func getMemos(for transaction: ZcashTransaction.Overview, completion: @escaping (Result<[Memo], Error>) -> Void) {
        AsyncToClosureGateway.executeThrowingAction(completion) {
            try await self.synchronizer.getMemos(for: transaction)
        }
    }

    public func getRecipients(for transaction: ZcashTransaction.Overview, completion: @escaping ([TransactionRecipient]) -> Void) {
        AsyncToClosureGateway.executeAction(completion) {
            await self.synchronizer.getRecipients(for: transaction)
        }
    }

    public func allConfirmedTransactions(
        from transaction: ZcashTransaction.Overview,
        limit: Int,
        completion: @escaping (Result<[ZcashTransaction.Overview], Error>) -> Void
    ) {
        AsyncToClosureGateway.executeThrowingAction(completion) {
            try await self.synchronizer.allTransactions(from: transaction, limit: limit)
        }
    }

    public func latestHeight(completion: @escaping (Result<BlockHeight, Error>) -> Void) {
        AsyncToClosureGateway.executeThrowingAction(completion) {
            try await self.synchronizer.latestHeight()
        }
    }

    public func refreshUTXOs(address: TransparentAddress, from height: BlockHeight, completion: @escaping (Result<RefreshedUTXOs, Error>) -> Void) {
        AsyncToClosureGateway.executeThrowingAction(completion) {
            try await self.synchronizer.refreshUTXOs(address: address, from: height)
        }
    }

    public func getAccountsBalances(_ completion: @escaping (Result<[AccountUUID: AccountBalance], Error>) -> Void) {
        AsyncToClosureGateway.executeThrowingAction(completion) {
            try await self.synchronizer.getAccountsBalances()
        }
    }

    public func refreshExchangeRateUSD() {
        synchronizer.refreshExchangeRateUSD()
    }

    public func estimateBirthdayHeight(for date: Date, completion: @escaping (BlockHeight) -> Void) {
        let height = synchronizer.estimateBirthdayHeight(for: date)
        completion(height)
    }

    public func httpRequestOverTor(for request: URLRequest, retryLimit: UInt8, completion: @escaping (Result<(data: Data, response: HTTPURLResponse), Error>) -> Void) {
        AsyncToClosureGateway.executeThrowingAction(completion) {
            try await self.synchronizer.httpRequestOverTor(for: request, retryLimit: retryLimit)
        }
    }

    public var broadcaster: Broadcaster { synchronizer.broadcaster }

    /*
     It can be missleading that these two methods are returning Publisher even this protocol is closure based. Reason is that Synchronizer doesn't
     provide different implementations for these two methods. So Combine it is even here.
     */
    public func rewind(_ policy: RewindPolicy) -> CompletablePublisher<Error> { synchronizer.rewind(policy) }
    public func wipe() -> CompletablePublisher<Error> { synchronizer.wipe() }
}

//
//  CombineSDKSynchronizer.swift
//  
//
//  Created by Michal Fousek on 16.03.2023.
//

import Combine
import Foundation

/// This is a super thin layer that implements the `CombineSynchronizer` protocol and translates the async API defined in `Synchronizer` to
/// Combine-based API. And it doesn't do anything else. It doesn't keep any state. It's here so each client can choose the API that suits its case the
/// best. And usage of this can be combined with usage of `ClosureSDKSynchronizer`. So devs can really choose the best SDK API for each part of the
/// client app.
///
/// If you are looking for documentation for a specific method or property look for it in the `Synchronizer` protocol.
public struct CombineSDKSynchronizer {
    private let synchronizer: Synchronizer

    public init(synchronizer: Synchronizer) {
        self.synchronizer = synchronizer
    }
}

extension CombineSDKSynchronizer: CombineSynchronizer {
    public var alias: ZcashSynchronizerAlias { synchronizer.alias }

    public var latestState: SynchronizerState { synchronizer.latestState }
    public var connectionState: ConnectionState { synchronizer.connectionState }

    public var stateStream: AnyPublisher<SynchronizerState, Never> { synchronizer.stateStream }
    public var eventStream: AnyPublisher<SynchronizerEvent, Never> { synchronizer.eventStream }

    public func prepare(
        with seed: [UInt8]?,
        walletBirthday: BlockHeight,
        for walletMode: WalletInitMode,
        name: String,
        keySource: String?
    ) -> SinglePublisher<Initializer.InitializationResult, Error> {
        AsyncToCombineGateway.executeThrowingAction() {
            return try await self.synchronizer.prepare(
                with: seed,
                walletBirthday: walletBirthday,
                for: walletMode,
                name: name,
                keySource: keySource
            )
        }
    }

    public func start(retry: Bool) -> CompletablePublisher<Error> {
        AsyncToCombineGateway.executeThrowingAction() {
            try await self.synchronizer.start(retry: retry)
        }
    }

    public func stop() {
        synchronizer.stop()
    }

    public func getSaplingAddress(accountUUID: AccountUUID) -> SinglePublisher<SaplingAddress, Error> {
        AsyncToCombineGateway.executeThrowingAction() {
            try await self.synchronizer.getSaplingAddress(accountUUID: accountUUID)
        }
    }

    public func getUnifiedAddress(accountUUID: AccountUUID) -> SinglePublisher<UnifiedAddress, Error> {
        AsyncToCombineGateway.executeThrowingAction() {
            try await self.synchronizer.getUnifiedAddress(accountUUID: accountUUID)
        }
    }

    public func getTransparentAddress(accountUUID: AccountUUID) -> SinglePublisher<TransparentAddress, Error> {
        AsyncToCombineGateway.executeThrowingAction() {
            try await self.synchronizer.getTransparentAddress(accountUUID: accountUUID)
        }
    }

    public func getCustomUnifiedAddress(accountUUID: AccountUUID, receivers: Set<ReceiverType>) -> SinglePublisher<UnifiedAddress, Error> {
        AsyncToCombineGateway.executeThrowingAction() {
            try await self.synchronizer.getCustomUnifiedAddress(accountUUID: accountUUID, receivers: receivers)
        }
    }

    public func proposeTransfer(
        accountUUID: AccountUUID,
        recipient: Recipient,
        amount: Zatoshi,
        memo: Memo?
    ) -> SinglePublisher<Proposal, Error> {
        AsyncToCombineGateway.executeThrowingAction() {
            try await self.synchronizer.proposeTransfer(accountUUID: accountUUID, recipient: recipient, amount: amount, memo: memo)
        }
    }

    public func proposefulfillingPaymentURI(
        _ uri: String,
        accountUUID: AccountUUID
    ) -> SinglePublisher<Proposal, Error> {
        AsyncToCombineGateway.executeThrowingAction() {
            try await self.synchronizer.proposefulfillingPaymentURI(
                uri,
                accountUUID: accountUUID
            )
        }
    }

    public func proposeShielding(
        accountUUID: AccountUUID,
        shieldingThreshold: Zatoshi,
        memo: Memo,
        transparentReceiver: TransparentAddress? = nil
    ) -> SinglePublisher<Proposal?, Error> {
        AsyncToCombineGateway.executeThrowingAction() {
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
        spendingKey: UnifiedSpendingKey
    ) -> SinglePublisher<AsyncThrowingStream<TransactionSubmitResult, Error>, Error> {
        AsyncToCombineGateway.executeThrowingAction() {
            try await self.synchronizer.createProposedTransactions(proposal: proposal, spendingKey: spendingKey)
        }
    }

    public func createPCZTFromProposal(
        accountUUID: AccountUUID,
        proposal: Proposal
    ) -> SinglePublisher<Pczt, Error> {
        AsyncToCombineGateway.executeThrowingAction() {
            try await self.synchronizer.createPCZTFromProposal(accountUUID: accountUUID, proposal: proposal)
        }
    }

    public func redactPCZTForSigner(
        pczt: Pczt
    ) -> SinglePublisher<Pczt, Error> {
        AsyncToCombineGateway.executeThrowingAction() {
            try await self.synchronizer.redactPCZTForSigner(pczt: pczt)
        }
    }

    public func PCZTRequiresSaplingProofs(
        pczt: Pczt
    ) -> SinglePublisher<Bool, Never> {
        AsyncToCombineGateway.executeAction() {
            await self.synchronizer.PCZTRequiresSaplingProofs(pczt: pczt)
        }
    }

    public func addProofsToPCZT(
        pczt: Pczt
    ) -> SinglePublisher<Pczt, Error> {
        AsyncToCombineGateway.executeThrowingAction() {
            try await self.synchronizer.addProofsToPCZT(pczt: pczt)
        }
    }

    public func createTransactionFromPCZT(
        pcztWithProofs: Pczt,
        pcztWithSigs: Pczt
    ) -> SinglePublisher<AsyncThrowingStream<TransactionSubmitResult, Error>, Error> {
        AsyncToCombineGateway.executeThrowingAction() {
            try await self.synchronizer.createTransactionFromPCZT(pcztWithProofs: pcztWithProofs, pcztWithSigs: pcztWithSigs)
        }
    }

    public func listAccounts() -> SinglePublisher<[Account], Error> {
        AsyncToCombineGateway.executeThrowingAction() {
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
        keySource: String?
    ) async throws -> SinglePublisher<AccountUUID, Error> {
        AsyncToCombineGateway.executeThrowingAction() {
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

    public var allTransactions: SinglePublisher<[ZcashTransaction.Overview], Never> {
        AsyncToCombineGateway.executeAction() {
            await self.synchronizer.transactions
        }
    }

    public var sentTransactions: SinglePublisher<[ZcashTransaction.Overview], Never> {
        AsyncToCombineGateway.executeAction() {
            await self.synchronizer.sentTransactions
        }
    }

    public var receivedTransactions: SinglePublisher<[ZcashTransaction.Overview], Never> {
        AsyncToCombineGateway.executeAction() {
            await self.synchronizer.receivedTransactions
        }
    }
    
    public func paginatedTransactions(of kind: TransactionKind) -> PaginatedTransactionRepository { synchronizer.paginatedTransactions(of: kind) }

    public func getMemos(for transaction: ZcashTransaction.Overview) -> SinglePublisher<[Memo], Error> {
        AsyncToCombineGateway.executeThrowingAction() {
            try await self.synchronizer.getMemos(for: transaction)
        }
    }

    public func getRecipients(for transaction: ZcashTransaction.Overview) -> SinglePublisher<[TransactionRecipient], Never> {
        AsyncToCombineGateway.executeAction() {
            await self.synchronizer.getRecipients(for: transaction)
        }
    }

    public func allTransactions(from transaction: ZcashTransaction.Overview, limit: Int) -> SinglePublisher<[ZcashTransaction.Overview], Error> {
        AsyncToCombineGateway.executeThrowingAction() {
            try await self.synchronizer.allTransactions(from: transaction, limit: limit)
        }
    }

    public func latestHeight() -> SinglePublisher<BlockHeight, Error> {
        AsyncToCombineGateway.executeThrowingAction() {
            try await self.synchronizer.latestHeight()
        }
    }

    public func refreshUTXOs(address: TransparentAddress, from height: BlockHeight) -> SinglePublisher<RefreshedUTXOs, Error> {
        AsyncToCombineGateway.executeThrowingAction() {
            try await self.synchronizer.refreshUTXOs(address: address, from: height)
        }
    }

    public func getAccountsBalances() -> SinglePublisher<[AccountUUID: AccountBalance], Error> {
        AsyncToCombineGateway.executeThrowingAction() {
            try await self.synchronizer.getAccountsBalances()
        }
    }

    public func refreshExchangeRateUSD() {
        synchronizer.refreshExchangeRateUSD()
    }

    public func estimateBirthdayHeight(for date: Date) -> SinglePublisher<BlockHeight, Error> {
        let height = synchronizer.estimateBirthdayHeight(for: date)
        let subject = PassthroughSubject<BlockHeight, Error>()
        subject.send(height)
        subject.send(completion: .finished)
        return subject.eraseToAnyPublisher()
    }

    public func httpRequestOverTor(for request: URLRequest, retryLimit: UInt8) -> SinglePublisher<(data: Data, response: HTTPURLResponse), Error> {
        AsyncToCombineGateway.executeThrowingAction() {
            try await self.synchronizer.httpRequestOverTor(for: request, retryLimit: retryLimit)
        }
    }

    public var broadcaster: Broadcaster { synchronizer.broadcaster }

    public func rewind(_ policy: RewindPolicy) -> CompletablePublisher<Error> { synchronizer.rewind(policy) }
    public func wipe() -> CompletablePublisher<Error> { synchronizer.wipe() }
}

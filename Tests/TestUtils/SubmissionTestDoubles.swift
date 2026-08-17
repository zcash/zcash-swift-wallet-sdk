//
//  SubmissionTestDoubles.swift
//  TestUtils
//

import Foundation
import GRPC
import NIO
import NIOTransportServices
@testable import ZcashLightClientKit

final class RecordingCompactTxStreamerService: CompactTxStreamerProvider {
    var interceptors: CompactTxStreamerServerInterceptorFactoryProtocol? { nil }

    private(set) var endpoint: LightWalletEndpoint!

    private let sendResponse: SendResponse
    private let eventLoopGroup = NIOTSEventLoopGroup(loopCount: 1, defaultQoS: .default)
    private let queue = DispatchQueue(label: "RecordingCompactTxStreamerService.queue")
    private var submittedTransactions: [Data] = []
    private var server: Server?

    init(sendResponse: SendResponse) throws {
        self.sendResponse = sendResponse
        self.endpoint = LightWalletEndpoint(address: "127.0.0.1", port: 0, secure: false)

        let server = try Server.insecure(group: eventLoopGroup)
            .withServiceProviders([self])
            .bind(host: "127.0.0.1", port: 0)
            .wait()

        self.server = server
        self.endpoint = LightWalletEndpoint(
            address: "127.0.0.1",
            port: server.channel.localAddress?.port ?? 0,
            secure: false,
            singleCallTimeoutInMillis: 5_000,
            streamingCallTimeoutInMillis: 5_000
        )
    }

    func stop() throws {
        try server?.close().wait()
        try eventLoopGroup.syncShutdownGracefully()
    }

    func recordedTransactions() -> [Data] {
        queue.sync { submittedTransactions }
    }

    func getLatestBlock(request: ChainSpec, context: StatusOnlyCallContext) -> EventLoopFuture<BlockID> {
        unimplementedUnary(on: context.eventLoop)
    }

    func getBlock(request: BlockID, context: StatusOnlyCallContext) -> EventLoopFuture<CompactBlock> {
        unimplementedUnary(on: context.eventLoop)
    }

    func getBlockNullifiers(request: BlockID, context: StatusOnlyCallContext) -> EventLoopFuture<CompactBlock> {
        unimplementedUnary(on: context.eventLoop)
    }

    func getBlockRange(request: BlockRange, context: StreamingResponseCallContext<CompactBlock>) -> EventLoopFuture<GRPCStatus> {
        unimplementedStreaming(on: context.eventLoop)
    }

    func getBlockRangeNullifiers(request: BlockRange, context: StreamingResponseCallContext<CompactBlock>) -> EventLoopFuture<GRPCStatus> {
        unimplementedStreaming(on: context.eventLoop)
    }

    func getTransaction(request: TxFilter, context: StatusOnlyCallContext) -> EventLoopFuture<RawTransaction> {
        unimplementedUnary(on: context.eventLoop)
    }

    func sendTransaction(request: RawTransaction, context: StatusOnlyCallContext) -> EventLoopFuture<SendResponse> {
        queue.sync {
            submittedTransactions.append(request.data)
        }
        return context.eventLoop.makeSucceededFuture(sendResponse)
    }

    func getTaddressTxids(request: TransparentAddressBlockFilter, context: StreamingResponseCallContext<RawTransaction>) -> EventLoopFuture<GRPCStatus> {
        unimplementedStreaming(on: context.eventLoop)
    }

    func getTaddressTransactions(request: TransparentAddressBlockFilter, context: StreamingResponseCallContext<RawTransaction>) -> EventLoopFuture<GRPCStatus> {
        unimplementedStreaming(on: context.eventLoop)
    }

    func getTaddressBalance(request: AddressList, context: StatusOnlyCallContext) -> EventLoopFuture<Balance> {
        unimplementedUnary(on: context.eventLoop)
    }

    func getTaddressBalanceStream(context: UnaryResponseCallContext<Balance>) -> EventLoopFuture<(StreamEvent<Address>) -> Void> {
        unimplementedUnary(on: context.eventLoop)
    }

    func getMempoolTx(request: GetMempoolTxRequest, context: StreamingResponseCallContext<CompactTx>) -> EventLoopFuture<GRPCStatus> {
        unimplementedStreaming(on: context.eventLoop)
    }

    func getMempoolStream(request: ZcashLightClientKit.Empty, context: StreamingResponseCallContext<RawTransaction>) -> EventLoopFuture<GRPCStatus> {
        unimplementedStreaming(on: context.eventLoop)
    }

    func getTreeState(request: BlockID, context: StatusOnlyCallContext) -> EventLoopFuture<TreeState> {
        unimplementedUnary(on: context.eventLoop)
    }

    func getLatestTreeState(request: ZcashLightClientKit.Empty, context: StatusOnlyCallContext) -> EventLoopFuture<TreeState> {
        unimplementedUnary(on: context.eventLoop)
    }

    func getSubtreeRoots(request: GetSubtreeRootsArg, context: StreamingResponseCallContext<SubtreeRoot>) -> EventLoopFuture<GRPCStatus> {
        unimplementedStreaming(on: context.eventLoop)
    }

    func getAddressUtxos(request: GetAddressUtxosArg, context: StatusOnlyCallContext) -> EventLoopFuture<GetAddressUtxosReplyList> {
        unimplementedUnary(on: context.eventLoop)
    }

    func getAddressUtxosStream(request: GetAddressUtxosArg, context: StreamingResponseCallContext<GetAddressUtxosReply>) -> EventLoopFuture<GRPCStatus> {
        unimplementedStreaming(on: context.eventLoop)
    }

    func getLightdInfo(request: ZcashLightClientKit.Empty, context: StatusOnlyCallContext) -> EventLoopFuture<LightdInfo> {
        unimplementedUnary(on: context.eventLoop)
    }

    func ping(request: ZcashLightClientKit.Duration, context: StatusOnlyCallContext) -> EventLoopFuture<PingResponse> {
        unimplementedUnary(on: context.eventLoop)
    }

    private func unimplementedUnary<T>(on eventLoop: EventLoop) -> EventLoopFuture<T> {
        eventLoop.makeFailedFuture(GRPCStatus(code: .unimplemented, message: "Unused in test"))
    }

    private func unimplementedStreaming(on eventLoop: EventLoop) -> EventLoopFuture<GRPCStatus> {
        eventLoop.makeSucceededFuture(GRPCStatus(code: .unimplemented, message: "Unused in test"))
    }
}

final class EndpointSubmitterMock: EndpointSubmitter {
    enum Behavior {
        case succeed
        case succeedAfter(TimeInterval)
        case reject(code: Int, message: String)
        /// Rejects after the delay; an early cancellation shortens the delay
        /// but the rejection is still thrown (a response already in flight).
        case rejectAfter(TimeInterval, code: Int, message: String)
        case failTransport
        /// Sleeps ~10s; only ends via cancellation. Records the cancellation.
        case hang
        /// Ignores task cancellation for the given duration, then fails with a
        /// transport error — simulates work stuck in non-cancellable FFI.
        case hangUncancellable(TimeInterval)
    }

    struct MockTransportError: Error {}

    private let queue = DispatchQueue(label: "EndpointSubmitterMock")
    private var behaviors: [String: Behavior] = [:]
    private var submitted: [LightWalletEndpoint] = []
    private var cancelled: [LightWalletEndpoint] = []

    func set(behavior: Behavior, for endpoint: LightWalletEndpoint) {
        queue.sync { behaviors[Self.key(endpoint)] = behavior }
    }

    func recordedSubmissions() -> [LightWalletEndpoint] {
        queue.sync { submitted }
    }

    func recordedCancellations() -> [LightWalletEndpoint] {
        queue.sync { cancelled }
    }

    func submit(transaction: CreatedTransaction, to endpoint: LightWalletEndpoint) async throws {
        queue.sync { submitted.append(endpoint) }
        let behavior = queue.sync { behaviors[Self.key(endpoint)] } ?? Behavior.succeed

        switch behavior {
        case .succeed:
            return

        case .succeedAfter(let delay):
            do {
                try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            } catch is CancellationError {
                queue.sync { cancelled.append(endpoint) }
                throw CancellationError()
            }

        case let .reject(code, message):
            throw TransactionEncoderError.submitError(code: code, message: message)

        case let .rejectAfter(delay, code, message):
            try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            throw TransactionEncoderError.submitError(code: code, message: message)

        case .failTransport:
            throw MockTransportError()

        case .hangUncancellable(let duration):
            let deadline = Date().addingTimeInterval(duration)
            while Date() < deadline {
                try? await Task.sleep(nanoseconds: 50_000_000)
            }
            throw MockTransportError()

        case .hang:
            do {
                try await Task.sleep(nanoseconds: 10_000_000_000)
                throw MockTransportError()
            } catch is CancellationError {
                queue.sync { cancelled.append(endpoint) }
                throw CancellationError()
            }
        }
    }

    private static func key(_ endpoint: LightWalletEndpoint) -> String {
        "\(endpoint.host):\(endpoint.port)"
    }
}

final class StubTransactionEncoder: TransactionEncoder {
    private let createdTransactions: [CreatedTransaction]
    private let overviews: [ZcashTransaction.Overview]
    private(set) var receivedCreateArguments: (proposal: Proposal, spendingKey: UnifiedSpendingKey)?
    private(set) var receivedFetchTxIds: [Data]?
    private(set) var submittedTransactions: [EncodedTransaction] = []

    /// When set, `submit(transaction:)` records the transaction and then throws this error.
    var submitError: Error?
    /// `isTransactionKnownToServer(txId:)` returns `true` for txids in this set.
    var knownToServerTxIds: Set<Data> = []

    init(createdTransactions overviews: [ZcashTransaction.Overview]) {
        self.overviews = overviews
        self.createdTransactions = overviews.map { overview in
            guard let raw = overview.raw else {
                preconditionFailure("StubTransactionEncoder requires raw transaction bytes")
            }
            return CreatedTransaction(txId: overview.rawID, raw: raw, expiryHeight: overview.expiryHeight)
        }
    }

    func proposeTransfer(
        accountUUID: AccountUUID,
        recipient: String,
        amount: Zatoshi,
        memoBytes: MemoBytes?
    ) async throws -> Proposal {
        fatalError("Unused in test")
    }

    func proposeSendMax(
        accountUUID: AccountUUID,
        recipient: String,
        memo: MemoBytes?,
        mode: MaxSpendMode
    ) async throws -> Proposal {
        fatalError("Unused in test")
    }

    func proposeOrchardToIronwoodMigration(accountUUID: AccountUUID) async throws -> Proposal {
        fatalError("Unused in test")
    }

    func proposeShielding(
        accountUUID: AccountUUID,
        shieldingThreshold: Zatoshi,
        memoBytes: MemoBytes?,
        transparentReceiver: String?
    ) async throws -> Proposal? {
        fatalError("Unused in test")
    }

    func createProposedTransactions(
        proposal: Proposal,
        spendingKey: UnifiedSpendingKey
    ) async throws -> [CreatedTransaction] {
        receivedCreateArguments = (proposal, spendingKey)
        return createdTransactions
    }

    func createdTransactions(forTxIds txIds: [Data]) async throws -> [CreatedTransaction] {
        txIds.compactMap { txId in
            createdTransactions.first { $0.txId == txId }
        }
    }

    func proposeFulfillingPaymentFromURI(
        _ uri: String,
        accountUUID: AccountUUID
    ) async throws -> Proposal {
        fatalError("Unused in test")
    }

    func submit(transaction: EncodedTransaction) async throws {
        submittedTransactions.append(transaction)
        if let submitError {
            throw submitError
        }
    }

    func isTransactionKnownToServer(txId: Data) async -> Bool {
        knownToServerTxIds.contains(txId)
    }

    func fetchTransactionsForTxIds(_ txIds: [Data]) async throws -> [ZcashTransaction.Overview] {
        receivedFetchTxIds = txIds
        return txIds.compactMap { txId in
            overviews.first { $0.rawID == txId }
        }
    }

    func closeDBConnection() { }
}

final class SubmitPlanStoringMock: SubmitPlanStoring {
    var plans: [Data: StoredSubmitPlan] = [:]
    /// When true, lookups behave like a broken store: `plan(for:)` reports
    /// `.storeUnavailable` and `allPlannedTransactionIds()` is empty.
    var storeUnavailable = false
    private(set) var deletePlansReceivedTxIds: [[Data]] = []
    private(set) var clearCallsCount = 0
    private(set) var wipeCallsCount = 0

    func markAwaitingSubmission(txIds: [Data]) async {
        for txId in txIds where plans[txId] == nil {
            plans[txId] = StoredSubmitPlan.awaiting
        }
    }

    func recordPlan(txId: Data, endpoints: [LightWalletEndpoint]) async {
        guard !endpoints.isEmpty else { return }
        plans[txId] = StoredSubmitPlan.ready(endpoints)
    }

    func plan(for txId: Data) async -> StoredSubmitPlan? {
        guard !storeUnavailable else { return .storeUnavailable }
        return plans[txId]
    }

    func allPlannedTransactionIds() async -> [Data] {
        guard !storeUnavailable else { return [] }
        return Array(plans.keys)
    }

    func deletePlans(txIds: [Data]) async {
        deletePlansReceivedTxIds.append(txIds)
        for txId in txIds {
            plans[txId] = nil
        }
    }

    func clear() async {
        clearCallsCount += 1
        plans.removeAll()
    }

    func wipe() async {
        wipeCallsCount += 1
        plans.removeAll()
        storeUnavailable = false
    }
}

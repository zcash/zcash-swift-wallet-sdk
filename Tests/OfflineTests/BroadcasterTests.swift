//
//  BroadcasterTests.swift
//  ZcashLightClientKitTests
//

import Combine
import XCTest
import GRPC
import NIO
import NIOTransportServices
@testable import TestUtils
@testable import ZcashLightClientKit

final class BroadcasterTests: ZcashTestCase {
    private var cancellables: [AnyCancellable] = []

    override func setUp() async throws {
        try await super.setUp()
        cancellables = []
    }

    override func tearDown() async throws {
        cancellables = []
        try await super.tearDown()
    }

    // MARK: - createProposedTransactions

    func testCreateProposedTransactionsReturnsRawBytesAndEmitsEvent() async throws {
        let rawTransaction = Data([0x01, 0x02, 0x03, 0x04])
        let createdTransactions = [makeTransaction(raw: rawTransaction, rawID: Data(repeating: 0xAB, count: 32))]
        let transactionEncoder = StubTransactionEncoder(createdTransactions: createdTransactions)
        let synchronizer = try makeSynchronizer(transactionEncoder: transactionEncoder)

        let foundTransactionsExpectation = XCTestExpectation(description: "found transactions event")

        synchronizer.eventStream
            .sink { event in
                guard case let .foundTransactions(transactions, range) = event else { return }
                XCTAssertNil(range)
                XCTAssertEqual(transactions.map(\.rawID), createdTransactions.map(\.rawID))
                foundTransactionsExpectation.fulfill()
            }
            .store(in: &cancellables)

        await synchronizer.updateStatus(.stopped)

        let proposal = Proposal.testOnlyFakeProposal(totalFee: 10)
        let spendingKey = TestsData(networkType: .testnet).spendingKey

        let transactions = try await synchronizer.broadcaster.createProposedTransactions(
            proposal: proposal,
            spendingKey: spendingKey
        )

        XCTAssertEqual(transactionEncoder.receivedCreateArguments?.proposal, proposal)
        XCTAssertEqual(transactionEncoder.receivedCreateArguments?.spendingKey, spendingKey)
        XCTAssertEqual(transactions.map(\.rawID), createdTransactions.map(\.rawID))
        XCTAssertEqual(try transactions.map { try XCTUnwrap($0.raw) }, [rawTransaction])

        await fulfillment(of: [foundTransactionsExpectation], timeout: 1.0)
    }

    // MARK: - submit

    func testSubmitSendsRawBytesToProvidedEndpoint() async throws {
        let rawTransaction = Data([0x01, 0x02, 0x03, 0x04])
        let createdTransactions = [makeTransaction(raw: rawTransaction, rawID: Data(repeating: 0xAB, count: 32))]
        let transactionEncoder = StubTransactionEncoder(createdTransactions: createdTransactions)
        let service = try RecordingCompactTxStreamerService(sendResponse: makeSendResponse(errorCode: 0, errorMessage: ""))
        defer { try? service.stop() }
        let synchronizer = try makeSynchronizer(transactionEncoder: transactionEncoder)

        await synchronizer.updateStatus(.stopped)

        try await synchronizer.broadcaster.submit(rawTransaction, to: service.endpoint)

        XCTAssertEqual(service.recordedTransactions(), [rawTransaction])
    }

    func testSubmitThrowsWhenEndpointRejectsTransaction() async throws {
        try await assertSubmitThrows(errorCode: -25, errorMessage: "rejected")
    }

    // MARK: - Full round-trip: create then submit

    func testCreateThenSubmitRoundTrip() async throws {
        let rawTransaction = Data([0x01, 0x02, 0x03, 0x04])
        let createdTransactions = [makeTransaction(raw: rawTransaction, rawID: Data(repeating: 0xAB, count: 32))]
        let transactionEncoder = StubTransactionEncoder(createdTransactions: createdTransactions)
        let service = try RecordingCompactTxStreamerService(sendResponse: makeSendResponse(errorCode: 0, errorMessage: ""))
        defer { try? service.stop() }
        let synchronizer = try makeSynchronizer(transactionEncoder: transactionEncoder)

        await synchronizer.updateStatus(.stopped)

        let proposal = Proposal.testOnlyFakeProposal(totalFee: 10)
        let spendingKey = TestsData(networkType: .testnet).spendingKey

        // Step 1: Create without submitting
        let transactions = try await synchronizer.broadcaster.createProposedTransactions(
            proposal: proposal,
            spendingKey: spendingKey
        )

        XCTAssertEqual(service.recordedTransactions(), [], "No transactions should be submitted yet")

        // Step 2: Submit to the endpoint
        let raw = try XCTUnwrap(transactions.first?.raw)
        try await synchronizer.broadcaster.submit(raw, to: service.endpoint)

        XCTAssertEqual(service.recordedTransactions(), [rawTransaction])
    }

    func testBroadcasterThrowsWhenNotPrepared() async throws {
        let transactionEncoder = StubTransactionEncoder(createdTransactions: [])
        let synchronizer = try makeSynchronizer(transactionEncoder: transactionEncoder)

        // Status is .unprepared by default — broadcaster should throw

        let proposal = Proposal.testOnlyFakeProposal(totalFee: 10)
        let spendingKey = TestsData(networkType: .testnet).spendingKey

        do {
            _ = try await synchronizer.broadcaster.createProposedTransactions(
                proposal: proposal,
                spendingKey: spendingKey
            )
            XCTFail("Should throw when synchronizer is not prepared")
        } catch {
            XCTAssertTrue(error is ZcashError, "Expected ZcashError but got \(error)")
        }
    }

    // MARK: - Helpers

    private func makeSynchronizer(transactionEncoder: TransactionEncoder) throws -> SDKSynchronizer {
        let serviceMock = LightWalletServiceMock()
        let transactionRepository = TransactionRepositoryMock()

        mockContainer.mock(type: LightWalletService.self, isSingleton: true) { _ in serviceMock }
        mockContainer.mock(type: TransactionRepository.self, isSingleton: true) { _ in transactionRepository }

        let initializer = Initializer(
            container: mockContainer,
            cacheDbURL: nil,
            fsBlockDbRoot: testTempDirectory,
            generalStorageURL: testGeneralStorageDirectory,
            dataDbURL: try __dataDbURL(),
            torDirURL: try __torDirURL(),
            endpoint: LightWalletEndpointBuilder.default,
            network: ZcashNetworkBuilder.network(for: .testnet),
            spendParamsURL: try __spendParamsURL(),
            outputParamsURL: try __outputParamsURL(),
            saplingParamsSourceURL: SaplingParamsSourceURL.tests,
            isTorEnabled: false,
            isExchangeRateEnabled: false
        )

        let blockProcessor = CompactBlockProcessor(
            initializer: initializer,
            walletBirthdayProvider: { initializer.walletBirthday }
        )

        return SDKSynchronizer(
            status: .unprepared,
            initializer: initializer,
            transactionEncoder: transactionEncoder,
            transactionRepository: transactionRepository,
            blockProcessor: blockProcessor,
            syncSessionTicker: .live
        )
    }

    private func makeTransaction(raw: Data, rawID: Data) -> ZcashTransaction.Overview {
        ZcashTransaction.Overview(
            accountUUID: TestsData.mockedAccountUUID,
            blockTime: nil,
            expiryHeight: 123_456,
            fee: Zatoshi(10_000),
            index: 0,
            isShielding: false,
            hasChange: false,
            memoCount: 0,
            minedHeight: nil,
            raw: raw,
            rawID: rawID,
            receivedNoteCount: 0,
            sentNoteCount: 1,
            value: Zatoshi(-1_000),
            isExpiredUmined: false,
            totalSpent: nil,
            totalReceived: nil
        )
    }

    private func makeSendResponse(errorCode: Int32, errorMessage: String) -> SendResponse {
        var response = SendResponse()
        response.errorCode = errorCode
        response.errorMessage = errorMessage
        return response
    }

    private func assertSubmitThrows(errorCode: Int32, errorMessage: String) async throws {
        let rawTransaction = Data([0x0A, 0x0B, 0x0C])
        let transactionEncoder = StubTransactionEncoder(createdTransactions: [])
        let service = try RecordingCompactTxStreamerService(
            sendResponse: makeSendResponse(errorCode: errorCode, errorMessage: errorMessage)
        )
        defer { try? service.stop() }

        let synchronizer = try makeSynchronizer(transactionEncoder: transactionEncoder)

        await synchronizer.updateStatus(.stopped)

        do {
            try await synchronizer.broadcaster.submit(rawTransaction, to: service.endpoint)
            XCTFail("submit should throw when the server rejects the transaction.")
        } catch let error as TransactionEncoderError {
            guard case let .submitError(code, message) = error else {
                XCTFail("Expected submitError but got \(error)")
                return
            }
            XCTAssertEqual(code, Int(errorCode))
            XCTAssertEqual(message, errorMessage)
        } catch {
            XCTFail("Expected TransactionEncoderError.submitError but got \(error)")
        }

        XCTAssertEqual(service.recordedTransactions(), [rawTransaction])
    }
}

// MARK: - Test Doubles

private final class StubTransactionEncoder: TransactionEncoder {
    private let createdTransactions: [ZcashTransaction.Overview]
    private(set) var receivedCreateArguments: (proposal: Proposal, spendingKey: UnifiedSpendingKey)?

    init(createdTransactions: [ZcashTransaction.Overview]) {
        self.createdTransactions = createdTransactions
    }

    func proposeTransfer(
        accountUUID: AccountUUID,
        recipient: String,
        amount: Zatoshi,
        memoBytes: MemoBytes?
    ) async throws -> Proposal {
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
    ) async throws -> [ZcashTransaction.Overview] {
        receivedCreateArguments = (proposal, spendingKey)
        return createdTransactions
    }

    func proposeFulfillingPaymentFromURI(
        _ uri: String,
        accountUUID: AccountUUID
    ) async throws -> Proposal {
        fatalError("Unused in test")
    }

    func submit(transaction: EncodedTransaction) async throws {
        fatalError("Unused in test")
    }

    func fetchTransactionsForTxIds(_ txIds: [Data]) async throws -> [ZcashTransaction.Overview] {
        fatalError("Unused in test")
    }

    func closeDBConnection() { }
}

private final class RecordingCompactTxStreamerService: CompactTxStreamerProvider {
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

    func getTaddressBalance(request: AddressList, context: StatusOnlyCallContext) -> EventLoopFuture<Balance> {
        unimplementedUnary(on: context.eventLoop)
    }

    func getTaddressBalanceStream(context: UnaryResponseCallContext<Balance>) -> EventLoopFuture<(StreamEvent<Address>) -> Void> {
        unimplementedUnary(on: context.eventLoop)
    }

    func getMempoolTx(request: Exclude, context: StreamingResponseCallContext<CompactTx>) -> EventLoopFuture<GRPCStatus> {
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

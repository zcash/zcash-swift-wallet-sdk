// Generated using Sourcery 2.3.0 — https://github.com/krzysztofzablocki/Sourcery
// DO NOT EDIT
import Combine
@testable import ZcashLightClientKit
import Foundation



// MARK: - AutoMockable protocols
class ActionContextMock: ActionContext {


    init(
    ) {
    }
    var state: CBPState {
        get { return underlyingState }
    }
    var underlyingState: CBPState!
    var prevState: CBPState?
    var syncControlData: SyncControlData {
        get { return underlyingSyncControlData }
    }
    var underlyingSyncControlData: SyncControlData!
    var requestedRewindHeight: BlockHeight?
    var processedHeight: BlockHeight {
        get { return underlyingProcessedHeight }
    }
    var underlyingProcessedHeight: BlockHeight!
    var lastChainTipUpdateTime: TimeInterval {
        get { return underlyingLastChainTipUpdateTime }
    }
    var underlyingLastChainTipUpdateTime: TimeInterval!
    var lastScannedHeight: BlockHeight?
    var lastEnhancedHeight: BlockHeight?

    // MARK: - update

    var updateStateCallsCount = 0
    var updateStateCalled: Bool {
        return updateStateCallsCount > 0
    }
    var updateStateReceivedState: CBPState?
    var updateStateClosure: ((CBPState) async -> Void)?

    func update(state: CBPState) async {
        updateStateCallsCount += 1
        updateStateReceivedState = state
        await updateStateClosure!(state)
    }

    // MARK: - update

    var updateSyncControlDataCallsCount = 0
    var updateSyncControlDataCalled: Bool {
        return updateSyncControlDataCallsCount > 0
    }
    var updateSyncControlDataReceivedSyncControlData: SyncControlData?
    var updateSyncControlDataClosure: ((SyncControlData) async -> Void)?

    func update(syncControlData: SyncControlData) async {
        updateSyncControlDataCallsCount += 1
        updateSyncControlDataReceivedSyncControlData = syncControlData
        await updateSyncControlDataClosure!(syncControlData)
    }

    // MARK: - update

    var updateProcessedHeightCallsCount = 0
    var updateProcessedHeightCalled: Bool {
        return updateProcessedHeightCallsCount > 0
    }
    var updateProcessedHeightReceivedProcessedHeight: BlockHeight?
    var updateProcessedHeightClosure: ((BlockHeight) async -> Void)?

    func update(processedHeight: BlockHeight) async {
        updateProcessedHeightCallsCount += 1
        updateProcessedHeightReceivedProcessedHeight = processedHeight
        await updateProcessedHeightClosure!(processedHeight)
    }

    // MARK: - update

    var updateLastChainTipUpdateTimeCallsCount = 0
    var updateLastChainTipUpdateTimeCalled: Bool {
        return updateLastChainTipUpdateTimeCallsCount > 0
    }
    var updateLastChainTipUpdateTimeReceivedLastChainTipUpdateTime: TimeInterval?
    var updateLastChainTipUpdateTimeClosure: ((TimeInterval) async -> Void)?

    func update(lastChainTipUpdateTime: TimeInterval) async {
        updateLastChainTipUpdateTimeCallsCount += 1
        updateLastChainTipUpdateTimeReceivedLastChainTipUpdateTime = lastChainTipUpdateTime
        await updateLastChainTipUpdateTimeClosure!(lastChainTipUpdateTime)
    }

    // MARK: - update

    var updateLastScannedHeightCallsCount = 0
    var updateLastScannedHeightCalled: Bool {
        return updateLastScannedHeightCallsCount > 0
    }
    var updateLastScannedHeightReceivedLastScannedHeight: BlockHeight?
    var updateLastScannedHeightClosure: ((BlockHeight) async -> Void)?

    func update(lastScannedHeight: BlockHeight) async {
        updateLastScannedHeightCallsCount += 1
        updateLastScannedHeightReceivedLastScannedHeight = lastScannedHeight
        await updateLastScannedHeightClosure!(lastScannedHeight)
    }

    // MARK: - update

    var updateLastDownloadedHeightCallsCount = 0
    var updateLastDownloadedHeightCalled: Bool {
        return updateLastDownloadedHeightCallsCount > 0
    }
    var updateLastDownloadedHeightReceivedLastDownloadedHeight: BlockHeight?
    var updateLastDownloadedHeightClosure: ((BlockHeight) async -> Void)?

    func update(lastDownloadedHeight: BlockHeight) async {
        updateLastDownloadedHeightCallsCount += 1
        updateLastDownloadedHeightReceivedLastDownloadedHeight = lastDownloadedHeight
        await updateLastDownloadedHeightClosure!(lastDownloadedHeight)
    }

    // MARK: - update

    var updateLastEnhancedHeightCallsCount = 0
    var updateLastEnhancedHeightCalled: Bool {
        return updateLastEnhancedHeightCallsCount > 0
    }
    var updateLastEnhancedHeightReceivedLastEnhancedHeight: BlockHeight?
    var updateLastEnhancedHeightClosure: ((BlockHeight?) async -> Void)?

    func update(lastEnhancedHeight: BlockHeight?) async {
        updateLastEnhancedHeightCallsCount += 1
        updateLastEnhancedHeightReceivedLastEnhancedHeight = lastEnhancedHeight
        await updateLastEnhancedHeightClosure!(lastEnhancedHeight)
    }

    // MARK: - update

    var updateRequestedRewindHeightCallsCount = 0
    var updateRequestedRewindHeightCalled: Bool {
        return updateRequestedRewindHeightCallsCount > 0
    }
    var updateRequestedRewindHeightReceivedRequestedRewindHeight: BlockHeight?
    var updateRequestedRewindHeightClosure: ((BlockHeight) async -> Void)?

    func update(requestedRewindHeight: BlockHeight) async {
        updateRequestedRewindHeightCallsCount += 1
        updateRequestedRewindHeightReceivedRequestedRewindHeight = requestedRewindHeight
        await updateRequestedRewindHeightClosure!(requestedRewindHeight)
    }

}
class BlockDownloaderMock: BlockDownloader {


    init(
    ) {
    }

    // MARK: - setDownloadLimit

    var setDownloadLimitCallsCount = 0
    var setDownloadLimitCalled: Bool {
        return setDownloadLimitCallsCount > 0
    }
    var setDownloadLimitReceivedLimit: BlockHeight?
    var setDownloadLimitClosure: ((BlockHeight) async -> Void)?

    func setDownloadLimit(_ limit: BlockHeight) async {
        setDownloadLimitCallsCount += 1
        setDownloadLimitReceivedLimit = limit
        await setDownloadLimitClosure!(limit)
    }

    // MARK: - setSyncRange

    var setSyncRangeBatchSizeThrowableError: Error?
    var setSyncRangeBatchSizeCallsCount = 0
    var setSyncRangeBatchSizeCalled: Bool {
        return setSyncRangeBatchSizeCallsCount > 0
    }
    var setSyncRangeBatchSizeReceivedArguments: (range: CompactBlockRange, batchSize: Int)?
    var setSyncRangeBatchSizeClosure: ((CompactBlockRange, Int) async throws -> Void)?

    func setSyncRange(_ range: CompactBlockRange, batchSize: Int) async throws {
        if let error = setSyncRangeBatchSizeThrowableError {
            throw error
        }
        setSyncRangeBatchSizeCallsCount += 1
        setSyncRangeBatchSizeReceivedArguments = (range: range, batchSize: batchSize)
        try await setSyncRangeBatchSizeClosure!(range, batchSize)
    }

    // MARK: - startDownload

    var startDownloadMaxBlockBufferSizeCallsCount = 0
    var startDownloadMaxBlockBufferSizeCalled: Bool {
        return startDownloadMaxBlockBufferSizeCallsCount > 0
    }
    var startDownloadMaxBlockBufferSizeReceivedMaxBlockBufferSize: Int?
    var startDownloadMaxBlockBufferSizeClosure: ((Int) async -> Void)?

    func startDownload(maxBlockBufferSize: Int) async {
        startDownloadMaxBlockBufferSizeCallsCount += 1
        startDownloadMaxBlockBufferSizeReceivedMaxBlockBufferSize = maxBlockBufferSize
        await startDownloadMaxBlockBufferSizeClosure!(maxBlockBufferSize)
    }

    // MARK: - stopDownload

    var stopDownloadCallsCount = 0
    var stopDownloadCalled: Bool {
        return stopDownloadCallsCount > 0
    }
    var stopDownloadClosure: (() async -> Void)?

    func stopDownload() async {
        stopDownloadCallsCount += 1
        await stopDownloadClosure!()
    }

    // MARK: - waitUntilRequestedBlocksAreDownloaded

    var waitUntilRequestedBlocksAreDownloadedInThrowableError: Error?
    var waitUntilRequestedBlocksAreDownloadedInCallsCount = 0
    var waitUntilRequestedBlocksAreDownloadedInCalled: Bool {
        return waitUntilRequestedBlocksAreDownloadedInCallsCount > 0
    }
    var waitUntilRequestedBlocksAreDownloadedInReceivedRange: CompactBlockRange?
    var waitUntilRequestedBlocksAreDownloadedInClosure: ((CompactBlockRange) async throws -> Void)?

    func waitUntilRequestedBlocksAreDownloaded(in range: CompactBlockRange) async throws {
        if let error = waitUntilRequestedBlocksAreDownloadedInThrowableError {
            throw error
        }
        waitUntilRequestedBlocksAreDownloadedInCallsCount += 1
        waitUntilRequestedBlocksAreDownloadedInReceivedRange = range
        try await waitUntilRequestedBlocksAreDownloadedInClosure!(range)
    }

    // MARK: - update

    var updateLatestDownloadedBlockHeightForceCallsCount = 0
    var updateLatestDownloadedBlockHeightForceCalled: Bool {
        return updateLatestDownloadedBlockHeightForceCallsCount > 0
    }
    var updateLatestDownloadedBlockHeightForceReceivedArguments: (latestDownloadedBlockHeight: BlockHeight, force: Bool)?
    var updateLatestDownloadedBlockHeightForceClosure: ((BlockHeight, Bool) async -> Void)?

    func update(latestDownloadedBlockHeight: BlockHeight, force: Bool) async {
        updateLatestDownloadedBlockHeightForceCallsCount += 1
        updateLatestDownloadedBlockHeightForceReceivedArguments = (latestDownloadedBlockHeight: latestDownloadedBlockHeight, force: force)
        await updateLatestDownloadedBlockHeightForceClosure!(latestDownloadedBlockHeight, force)
    }

    // MARK: - latestDownloadedBlockHeight

    var latestDownloadedBlockHeightCallsCount = 0
    var latestDownloadedBlockHeightCalled: Bool {
        return latestDownloadedBlockHeightCallsCount > 0
    }
    var latestDownloadedBlockHeightReturnValue: BlockHeight!
    var latestDownloadedBlockHeightClosure: (() async -> BlockHeight)?

    func latestDownloadedBlockHeight() async -> BlockHeight {
        latestDownloadedBlockHeightCallsCount += 1
        if let closure = latestDownloadedBlockHeightClosure {
            return await closure()
        } else {
            return latestDownloadedBlockHeightReturnValue
        }
    }

    // MARK: - rewind

    var rewindLatestDownloadedBlockHeightCallsCount = 0
    var rewindLatestDownloadedBlockHeightCalled: Bool {
        return rewindLatestDownloadedBlockHeightCallsCount > 0
    }
    var rewindLatestDownloadedBlockHeightReceivedLatestDownloadedBlockHeight: BlockHeight?
    var rewindLatestDownloadedBlockHeightClosure: ((BlockHeight?) async -> Void)?

    func rewind(latestDownloadedBlockHeight: BlockHeight?) async {
        rewindLatestDownloadedBlockHeightCallsCount += 1
        rewindLatestDownloadedBlockHeightReceivedLatestDownloadedBlockHeight = latestDownloadedBlockHeight
        await rewindLatestDownloadedBlockHeightClosure!(latestDownloadedBlockHeight)
    }

}
class BlockDownloaderServiceMock: BlockDownloaderService {


    init(
    ) {
    }
    var storage: CompactBlockRepository {
        get { return underlyingStorage }
    }
    var underlyingStorage: CompactBlockRepository!

    // MARK: - downloadBlockRange

    var downloadBlockRangeModeThrowableError: Error?
    var downloadBlockRangeModeCallsCount = 0
    var downloadBlockRangeModeCalled: Bool {
        return downloadBlockRangeModeCallsCount > 0
    }
    var downloadBlockRangeModeReceivedArguments: (heightRange: CompactBlockRange, mode: ServiceMode)?
    var downloadBlockRangeModeClosure: ((CompactBlockRange, ServiceMode) async throws -> Void)?

    func downloadBlockRange(_ heightRange: CompactBlockRange, mode: ServiceMode) async throws {
        if let error = downloadBlockRangeModeThrowableError {
            throw error
        }
        downloadBlockRangeModeCallsCount += 1
        downloadBlockRangeModeReceivedArguments = (heightRange: heightRange, mode: mode)
        try await downloadBlockRangeModeClosure!(heightRange, mode)
    }

    // MARK: - rewind

    var rewindToThrowableError: Error?
    var rewindToCallsCount = 0
    var rewindToCalled: Bool {
        return rewindToCallsCount > 0
    }
    var rewindToReceivedHeight: BlockHeight?
    var rewindToClosure: ((BlockHeight) async throws -> Void)?

    func rewind(to height: BlockHeight) async throws {
        if let error = rewindToThrowableError {
            throw error
        }
        rewindToCallsCount += 1
        rewindToReceivedHeight = height
        try await rewindToClosure!(height)
    }

    // MARK: - lastDownloadedBlockHeight

    var lastDownloadedBlockHeightThrowableError: Error?
    var lastDownloadedBlockHeightCallsCount = 0
    var lastDownloadedBlockHeightCalled: Bool {
        return lastDownloadedBlockHeightCallsCount > 0
    }
    var lastDownloadedBlockHeightReturnValue: BlockHeight!
    var lastDownloadedBlockHeightClosure: (() async throws -> BlockHeight)?

    func lastDownloadedBlockHeight() async throws -> BlockHeight {
        if let error = lastDownloadedBlockHeightThrowableError {
            throw error
        }
        lastDownloadedBlockHeightCallsCount += 1
        if let closure = lastDownloadedBlockHeightClosure {
            return try await closure()
        } else {
            return lastDownloadedBlockHeightReturnValue
        }
    }

    // MARK: - latestBlockHeight

    var latestBlockHeightModeThrowableError: Error?
    var latestBlockHeightModeCallsCount = 0
    var latestBlockHeightModeCalled: Bool {
        return latestBlockHeightModeCallsCount > 0
    }
    var latestBlockHeightModeReceivedMode: ServiceMode?
    var latestBlockHeightModeReturnValue: BlockHeight!
    var latestBlockHeightModeClosure: ((ServiceMode) async throws -> BlockHeight)?

    func latestBlockHeight(mode: ServiceMode) async throws -> BlockHeight {
        if let error = latestBlockHeightModeThrowableError {
            throw error
        }
        latestBlockHeightModeCallsCount += 1
        latestBlockHeightModeReceivedMode = mode
        if let closure = latestBlockHeightModeClosure {
            return try await closure(mode)
        } else {
            return latestBlockHeightModeReturnValue
        }
    }

    // MARK: - fetchTransaction

    var fetchTransactionTxIdModeThrowableError: Error?
    var fetchTransactionTxIdModeCallsCount = 0
    var fetchTransactionTxIdModeCalled: Bool {
        return fetchTransactionTxIdModeCallsCount > 0
    }
    var fetchTransactionTxIdModeReceivedArguments: (txId: Data, mode: ServiceMode)?
    var fetchTransactionTxIdModeReturnValue: (tx: ZcashTransaction.Fetched?, status: TransactionStatus)!
    var fetchTransactionTxIdModeClosure: ((Data, ServiceMode) async throws -> (tx: ZcashTransaction.Fetched?, status: TransactionStatus))?

    func fetchTransaction(txId: Data, mode: ServiceMode) async throws -> (tx: ZcashTransaction.Fetched?, status: TransactionStatus) {
        if let error = fetchTransactionTxIdModeThrowableError {
            throw error
        }
        fetchTransactionTxIdModeCallsCount += 1
        fetchTransactionTxIdModeReceivedArguments = (txId: txId, mode: mode)
        if let closure = fetchTransactionTxIdModeClosure {
            return try await closure(txId, mode)
        } else {
            return fetchTransactionTxIdModeReturnValue
        }
    }

    // MARK: - fetchUnspentTransactionOutputs

    var fetchUnspentTransactionOutputsTAddressStartHeightModeThrowableError: Error?
    var fetchUnspentTransactionOutputsTAddressStartHeightModeCallsCount = 0
    var fetchUnspentTransactionOutputsTAddressStartHeightModeCalled: Bool {
        return fetchUnspentTransactionOutputsTAddressStartHeightModeCallsCount > 0
    }
    var fetchUnspentTransactionOutputsTAddressStartHeightModeReceivedArguments: (tAddress: String, startHeight: BlockHeight, mode: ServiceMode)?
    var fetchUnspentTransactionOutputsTAddressStartHeightModeReturnValue: AsyncThrowingStream<UnspentTransactionOutputEntity, Error>!
    var fetchUnspentTransactionOutputsTAddressStartHeightModeClosure: ((String, BlockHeight, ServiceMode) throws -> AsyncThrowingStream<UnspentTransactionOutputEntity, Error>)?

    func fetchUnspentTransactionOutputs(tAddress: String, startHeight: BlockHeight, mode: ServiceMode) throws -> AsyncThrowingStream<UnspentTransactionOutputEntity, Error> {
        if let error = fetchUnspentTransactionOutputsTAddressStartHeightModeThrowableError {
            throw error
        }
        fetchUnspentTransactionOutputsTAddressStartHeightModeCallsCount += 1
        fetchUnspentTransactionOutputsTAddressStartHeightModeReceivedArguments = (tAddress: tAddress, startHeight: startHeight, mode: mode)
        if let closure = fetchUnspentTransactionOutputsTAddressStartHeightModeClosure {
            return try closure(tAddress, startHeight, mode)
        } else {
            return fetchUnspentTransactionOutputsTAddressStartHeightModeReturnValue
        }
    }

    // MARK: - fetchUnspentTransactionOutputs

    var fetchUnspentTransactionOutputsTAddressesStartHeightModeThrowableError: Error?
    var fetchUnspentTransactionOutputsTAddressesStartHeightModeCallsCount = 0
    var fetchUnspentTransactionOutputsTAddressesStartHeightModeCalled: Bool {
        return fetchUnspentTransactionOutputsTAddressesStartHeightModeCallsCount > 0
    }
    var fetchUnspentTransactionOutputsTAddressesStartHeightModeReceivedArguments: (tAddresses: [String], startHeight: BlockHeight, mode: ServiceMode)?
    var fetchUnspentTransactionOutputsTAddressesStartHeightModeReturnValue: AsyncThrowingStream<UnspentTransactionOutputEntity, Error>!
    var fetchUnspentTransactionOutputsTAddressesStartHeightModeClosure: (([String], BlockHeight, ServiceMode) throws -> AsyncThrowingStream<UnspentTransactionOutputEntity, Error>)?

    func fetchUnspentTransactionOutputs(tAddresses: [String], startHeight: BlockHeight, mode: ServiceMode) throws -> AsyncThrowingStream<UnspentTransactionOutputEntity, Error> {
        if let error = fetchUnspentTransactionOutputsTAddressesStartHeightModeThrowableError {
            throw error
        }
        fetchUnspentTransactionOutputsTAddressesStartHeightModeCallsCount += 1
        fetchUnspentTransactionOutputsTAddressesStartHeightModeReceivedArguments = (tAddresses: tAddresses, startHeight: startHeight, mode: mode)
        if let closure = fetchUnspentTransactionOutputsTAddressesStartHeightModeClosure {
            return try closure(tAddresses, startHeight, mode)
        } else {
            return fetchUnspentTransactionOutputsTAddressesStartHeightModeReturnValue
        }
    }

    // MARK: - closeConnections

    var closeConnectionsCallsCount = 0
    var closeConnectionsCalled: Bool {
        return closeConnectionsCallsCount > 0
    }
    var closeConnectionsClosure: (() -> Void)?

    func closeConnections() {
        closeConnectionsCallsCount += 1
        closeConnectionsClosure!()
    }

}
class BlockEnhancerMock: BlockEnhancer {


    init(
    ) {
    }

    // MARK: - enhance

    var enhanceAtDidEnhanceThrowableError: Error?
    var enhanceAtDidEnhanceCallsCount = 0
    var enhanceAtDidEnhanceCalled: Bool {
        return enhanceAtDidEnhanceCallsCount > 0
    }
    var enhanceAtDidEnhanceReceivedArguments: (range: CompactBlockRange, didEnhance: (EnhancementProgress) async -> Void)?
    var enhanceAtDidEnhanceReturnValue: [ZcashTransaction.Overview]?
    var enhanceAtDidEnhanceClosure: ((CompactBlockRange, @escaping (EnhancementProgress) async -> Void) async throws -> [ZcashTransaction.Overview]?)?

    func enhance(at range: CompactBlockRange, didEnhance: @escaping (EnhancementProgress) async -> Void) async throws -> [ZcashTransaction.Overview]? {
        if let error = enhanceAtDidEnhanceThrowableError {
            throw error
        }
        enhanceAtDidEnhanceCallsCount += 1
        enhanceAtDidEnhanceReceivedArguments = (range: range, didEnhance: didEnhance)
        if let closure = enhanceAtDidEnhanceClosure {
            return try await closure(range, didEnhance)
        } else {
            return enhanceAtDidEnhanceReturnValue
        }
    }

}
class BlockScannerMock: BlockScanner {


    init(
    ) {
    }

    // MARK: - scanBlocks

    var scanBlocksAtDidScanThrowableError: Error?
    var scanBlocksAtDidScanCallsCount = 0
    var scanBlocksAtDidScanCalled: Bool {
        return scanBlocksAtDidScanCallsCount > 0
    }
    var scanBlocksAtDidScanReceivedArguments: (range: CompactBlockRange, didScan: (BlockHeight, UInt32) async throws -> Void)?
    var scanBlocksAtDidScanReturnValue: BlockHeight!
    var scanBlocksAtDidScanClosure: ((CompactBlockRange, @escaping (BlockHeight, UInt32) async throws -> Void) async throws -> BlockHeight)?

    func scanBlocks(at range: CompactBlockRange, didScan: @escaping (BlockHeight, UInt32) async throws -> Void) async throws -> BlockHeight {
        if let error = scanBlocksAtDidScanThrowableError {
            throw error
        }
        scanBlocksAtDidScanCallsCount += 1
        scanBlocksAtDidScanReceivedArguments = (range: range, didScan: didScan)
        if let closure = scanBlocksAtDidScanClosure {
            return try await closure(range, didScan)
        } else {
            return scanBlocksAtDidScanReturnValue
        }
    }

}
class BroadcasterMock: Broadcaster {


    init(
    ) {
    }

    // MARK: - createProposedTransactions

    var createProposedTransactionsProposalSpendingKeyThrowableError: Error?
    var createProposedTransactionsProposalSpendingKeyCallsCount = 0
    var createProposedTransactionsProposalSpendingKeyCalled: Bool {
        return createProposedTransactionsProposalSpendingKeyCallsCount > 0
    }
    var createProposedTransactionsProposalSpendingKeyReceivedArguments: (proposal: Proposal, spendingKey: UnifiedSpendingKey)?
    var createProposedTransactionsProposalSpendingKeyReturnValue: [CreatedTransaction]!
    var createProposedTransactionsProposalSpendingKeyClosure: ((Proposal, UnifiedSpendingKey) async throws -> [CreatedTransaction])?

    func createProposedTransactions(proposal: Proposal, spendingKey: UnifiedSpendingKey) async throws -> [CreatedTransaction] {
        if let error = createProposedTransactionsProposalSpendingKeyThrowableError {
            throw error
        }
        createProposedTransactionsProposalSpendingKeyCallsCount += 1
        createProposedTransactionsProposalSpendingKeyReceivedArguments = (proposal: proposal, spendingKey: spendingKey)
        if let closure = createProposedTransactionsProposalSpendingKeyClosure {
            return try await closure(proposal, spendingKey)
        } else {
            return createProposedTransactionsProposalSpendingKeyReturnValue
        }
    }

    // MARK: - createTransactionFromPCZT

    var createTransactionFromPCZTPcztWithProofsPcztWithSigsThrowableError: Error?
    var createTransactionFromPCZTPcztWithProofsPcztWithSigsCallsCount = 0
    var createTransactionFromPCZTPcztWithProofsPcztWithSigsCalled: Bool {
        return createTransactionFromPCZTPcztWithProofsPcztWithSigsCallsCount > 0
    }
    var createTransactionFromPCZTPcztWithProofsPcztWithSigsReceivedArguments: (pcztWithProofs: Pczt, pcztWithSigs: Pczt)?
    var createTransactionFromPCZTPcztWithProofsPcztWithSigsReturnValue: [CreatedTransaction]!
    var createTransactionFromPCZTPcztWithProofsPcztWithSigsClosure: ((Pczt, Pczt) async throws -> [CreatedTransaction])?

    func createTransactionFromPCZT(pcztWithProofs: Pczt, pcztWithSigs: Pczt) async throws -> [CreatedTransaction] {
        if let error = createTransactionFromPCZTPcztWithProofsPcztWithSigsThrowableError {
            throw error
        }
        createTransactionFromPCZTPcztWithProofsPcztWithSigsCallsCount += 1
        createTransactionFromPCZTPcztWithProofsPcztWithSigsReceivedArguments = (pcztWithProofs: pcztWithProofs, pcztWithSigs: pcztWithSigs)
        if let closure = createTransactionFromPCZTPcztWithProofsPcztWithSigsClosure {
            return try await closure(pcztWithProofs, pcztWithSigs)
        } else {
            return createTransactionFromPCZTPcztWithProofsPcztWithSigsReturnValue
        }
    }

    // MARK: - submit

    var submitTransactionToTimingCallsCount = 0
    var submitTransactionToTimingCalled: Bool {
        return submitTransactionToTimingCallsCount > 0
    }
    var submitTransactionToTimingReceivedArguments: (transaction: CreatedTransaction, endpoints: [LightWalletEndpoint], timing: SubmissionTiming)?
    var submitTransactionToTimingReturnValue: TransactionSubmissionOutcome!
    var submitTransactionToTimingClosure: ((CreatedTransaction, [LightWalletEndpoint], SubmissionTiming) async -> TransactionSubmissionOutcome)?

    func submit(transaction: CreatedTransaction, to endpoints: [LightWalletEndpoint], timing: SubmissionTiming) async -> TransactionSubmissionOutcome {
        submitTransactionToTimingCallsCount += 1
        submitTransactionToTimingReceivedArguments = (transaction: transaction, endpoints: endpoints, timing: timing)
        if let closure = submitTransactionToTimingClosure {
            return await closure(transaction, endpoints, timing)
        } else {
            return submitTransactionToTimingReturnValue
        }
    }

    // MARK: - submit

    var submitTransactionsToTimingCallsCount = 0
    var submitTransactionsToTimingCalled: Bool {
        return submitTransactionsToTimingCallsCount > 0
    }
    var submitTransactionsToTimingReceivedArguments: (transactions: [CreatedTransaction], endpoints: [LightWalletEndpoint], timing: SubmissionTiming)?
    var submitTransactionsToTimingReturnValue: [TransactionSubmissionReport]!
    var submitTransactionsToTimingClosure: (([CreatedTransaction], [LightWalletEndpoint], SubmissionTiming) async -> [TransactionSubmissionReport])?

    func submit(transactions: [CreatedTransaction], to endpoints: [LightWalletEndpoint], timing: SubmissionTiming) async -> [TransactionSubmissionReport] {
        submitTransactionsToTimingCallsCount += 1
        submitTransactionsToTimingReceivedArguments = (transactions: transactions, endpoints: endpoints, timing: timing)
        if let closure = submitTransactionsToTimingClosure {
            return await closure(transactions, endpoints, timing)
        } else {
            return submitTransactionsToTimingReturnValue
        }
    }

}
class CompactBlockRepositoryMock: CompactBlockRepository {


    init(
    ) {
    }

    // MARK: - create

    var createThrowableError: Error?
    var createCallsCount = 0
    var createCalled: Bool {
        return createCallsCount > 0
    }
    var createClosure: (() async throws -> Void)?

    func create() async throws {
        if let error = createThrowableError {
            throw error
        }
        createCallsCount += 1
        try await createClosure!()
    }

    // MARK: - latestHeight

    var latestHeightThrowableError: Error?
    var latestHeightCallsCount = 0
    var latestHeightCalled: Bool {
        return latestHeightCallsCount > 0
    }
    var latestHeightReturnValue: BlockHeight!
    var latestHeightClosure: (() async throws -> BlockHeight)?

    func latestHeight() async throws -> BlockHeight {
        if let error = latestHeightThrowableError {
            throw error
        }
        latestHeightCallsCount += 1
        if let closure = latestHeightClosure {
            return try await closure()
        } else {
            return latestHeightReturnValue
        }
    }

    // MARK: - write

    var writeBlocksThrowableError: Error?
    var writeBlocksCallsCount = 0
    var writeBlocksCalled: Bool {
        return writeBlocksCallsCount > 0
    }
    var writeBlocksReceivedBlocks: [ZcashCompactBlock]?
    var writeBlocksClosure: (([ZcashCompactBlock]) async throws -> Void)?

    func write(blocks: [ZcashCompactBlock]) async throws {
        if let error = writeBlocksThrowableError {
            throw error
        }
        writeBlocksCallsCount += 1
        writeBlocksReceivedBlocks = blocks
        try await writeBlocksClosure!(blocks)
    }

    // MARK: - rewind

    var rewindToThrowableError: Error?
    var rewindToCallsCount = 0
    var rewindToCalled: Bool {
        return rewindToCallsCount > 0
    }
    var rewindToReceivedHeight: BlockHeight?
    var rewindToClosure: ((BlockHeight) async throws -> Void)?

    func rewind(to height: BlockHeight) async throws {
        if let error = rewindToThrowableError {
            throw error
        }
        rewindToCallsCount += 1
        rewindToReceivedHeight = height
        try await rewindToClosure!(height)
    }

    // MARK: - clear

    var clearUpToThrowableError: Error?
    var clearUpToCallsCount = 0
    var clearUpToCalled: Bool {
        return clearUpToCallsCount > 0
    }
    var clearUpToReceivedHeight: BlockHeight?
    var clearUpToClosure: ((BlockHeight) async throws -> Void)?

    func clear(upTo height: BlockHeight) async throws {
        if let error = clearUpToThrowableError {
            throw error
        }
        clearUpToCallsCount += 1
        clearUpToReceivedHeight = height
        try await clearUpToClosure!(height)
    }

    // MARK: - clear

    var clearThrowableError: Error?
    var clearCallsCount = 0
    var clearCalled: Bool {
        return clearCallsCount > 0
    }
    var clearClosure: (() async throws -> Void)?

    func clear() async throws {
        if let error = clearThrowableError {
            throw error
        }
        clearCallsCount += 1
        try await clearClosure!()
    }

}
class LatestBlocksDataProviderMock: LatestBlocksDataProvider {


    init(
    ) {
    }
    var fullyScannedHeight: BlockHeight {
        get { return underlyingFullyScannedHeight }
    }
    var underlyingFullyScannedHeight: BlockHeight!
    var maxScannedHeight: BlockHeight {
        get { return underlyingMaxScannedHeight }
    }
    var underlyingMaxScannedHeight: BlockHeight!
    var latestBlockHeight: BlockHeight {
        get { return underlyingLatestBlockHeight }
    }
    var underlyingLatestBlockHeight: BlockHeight!
    var walletBirthday: BlockHeight {
        get { return underlyingWalletBirthday }
    }
    var underlyingWalletBirthday: BlockHeight!

    // MARK: - reset

    var resetCallsCount = 0
    var resetCalled: Bool {
        return resetCallsCount > 0
    }
    var resetClosure: (() async -> Void)?

    func reset() async {
        resetCallsCount += 1
        await resetClosure!()
    }

    // MARK: - updateScannedData

    var updateScannedDataCallsCount = 0
    var updateScannedDataCalled: Bool {
        return updateScannedDataCallsCount > 0
    }
    var updateScannedDataClosure: (() async -> Void)?

    func updateScannedData() async {
        updateScannedDataCallsCount += 1
        await updateScannedDataClosure!()
    }

    // MARK: - updateBlockData

    var updateBlockDataCallsCount = 0
    var updateBlockDataCalled: Bool {
        return updateBlockDataCallsCount > 0
    }
    var updateBlockDataClosure: (() async -> Void)?

    func updateBlockData() async {
        updateBlockDataCallsCount += 1
        await updateBlockDataClosure!()
    }

    // MARK: - updateWalletBirthday

    var updateWalletBirthdayCallsCount = 0
    var updateWalletBirthdayCalled: Bool {
        return updateWalletBirthdayCallsCount > 0
    }
    var updateWalletBirthdayReceivedWalletBirthday: BlockHeight?
    var updateWalletBirthdayClosure: ((BlockHeight) async -> Void)?

    func updateWalletBirthday(_ walletBirthday: BlockHeight) async {
        updateWalletBirthdayCallsCount += 1
        updateWalletBirthdayReceivedWalletBirthday = walletBirthday
        await updateWalletBirthdayClosure!(walletBirthday)
    }

    // MARK: - update

    var updateCallsCount = 0
    var updateCalled: Bool {
        return updateCallsCount > 0
    }
    var updateReceivedLatestBlockHeight: BlockHeight?
    var updateClosure: ((BlockHeight) async -> Void)?

    func update(_ latestBlockHeight: BlockHeight) async {
        updateCallsCount += 1
        updateReceivedLatestBlockHeight = latestBlockHeight
        await updateClosure!(latestBlockHeight)
    }

}
class LightWalletServiceMock: LightWalletService {


    init(
    ) {
    }
    var connectionStateChange: ((_ from: ConnectionState, _ to: ConnectionState) -> Void)?

    // MARK: - getInfo

    var getInfoModeThrowableError: Error?
    var getInfoModeCallsCount = 0
    var getInfoModeCalled: Bool {
        return getInfoModeCallsCount > 0
    }
    var getInfoModeReceivedMode: ServiceMode?
    var getInfoModeReturnValue: LightWalletdInfo!
    var getInfoModeClosure: ((ServiceMode) async throws -> LightWalletdInfo)?

    func getInfo(mode: ServiceMode) async throws -> LightWalletdInfo {
        if let error = getInfoModeThrowableError {
            throw error
        }
        getInfoModeCallsCount += 1
        getInfoModeReceivedMode = mode
        if let closure = getInfoModeClosure {
            return try await closure(mode)
        } else {
            return getInfoModeReturnValue
        }
    }

    // MARK: - latestBlock

    var latestBlockModeThrowableError: Error?
    var latestBlockModeCallsCount = 0
    var latestBlockModeCalled: Bool {
        return latestBlockModeCallsCount > 0
    }
    var latestBlockModeReceivedMode: ServiceMode?
    var latestBlockModeReturnValue: BlockID!
    var latestBlockModeClosure: ((ServiceMode) async throws -> BlockID)?

    func latestBlock(mode: ServiceMode) async throws -> BlockID {
        if let error = latestBlockModeThrowableError {
            throw error
        }
        latestBlockModeCallsCount += 1
        latestBlockModeReceivedMode = mode
        if let closure = latestBlockModeClosure {
            return try await closure(mode)
        } else {
            return latestBlockModeReturnValue
        }
    }

    // MARK: - latestBlockHeight

    var latestBlockHeightModeThrowableError: Error?
    var latestBlockHeightModeCallsCount = 0
    var latestBlockHeightModeCalled: Bool {
        return latestBlockHeightModeCallsCount > 0
    }
    var latestBlockHeightModeReceivedMode: ServiceMode?
    var latestBlockHeightModeReturnValue: BlockHeight!
    var latestBlockHeightModeClosure: ((ServiceMode) async throws -> BlockHeight)?

    func latestBlockHeight(mode: ServiceMode) async throws -> BlockHeight {
        if let error = latestBlockHeightModeThrowableError {
            throw error
        }
        latestBlockHeightModeCallsCount += 1
        latestBlockHeightModeReceivedMode = mode
        if let closure = latestBlockHeightModeClosure {
            return try await closure(mode)
        } else {
            return latestBlockHeightModeReturnValue
        }
    }

    // MARK: - blockRange

    var blockRangeModeThrowableError: Error?
    var blockRangeModeCallsCount = 0
    var blockRangeModeCalled: Bool {
        return blockRangeModeCallsCount > 0
    }
    var blockRangeModeReceivedArguments: (range: CompactBlockRange, mode: ServiceMode)?
    var blockRangeModeReturnValue: AsyncThrowingStream<ZcashCompactBlock, Error>!
    var blockRangeModeClosure: ((CompactBlockRange, ServiceMode) throws -> AsyncThrowingStream<ZcashCompactBlock, Error>)?

    func blockRange(_ range: CompactBlockRange, mode: ServiceMode) throws -> AsyncThrowingStream<ZcashCompactBlock, Error> {
        if let error = blockRangeModeThrowableError {
            throw error
        }
        blockRangeModeCallsCount += 1
        blockRangeModeReceivedArguments = (range: range, mode: mode)
        if let closure = blockRangeModeClosure {
            return try closure(range, mode)
        } else {
            return blockRangeModeReturnValue
        }
    }

    // MARK: - submit

    var submitSpendTransactionModeThrowableError: Error?
    var submitSpendTransactionModeCallsCount = 0
    var submitSpendTransactionModeCalled: Bool {
        return submitSpendTransactionModeCallsCount > 0
    }
    var submitSpendTransactionModeReceivedArguments: (spendTransaction: Data, mode: ServiceMode)?
    var submitSpendTransactionModeReturnValue: LightWalletServiceResponse!
    var submitSpendTransactionModeClosure: ((Data, ServiceMode) async throws -> LightWalletServiceResponse)?

    func submit(spendTransaction: Data, mode: ServiceMode) async throws -> LightWalletServiceResponse {
        if let error = submitSpendTransactionModeThrowableError {
            throw error
        }
        submitSpendTransactionModeCallsCount += 1
        submitSpendTransactionModeReceivedArguments = (spendTransaction: spendTransaction, mode: mode)
        if let closure = submitSpendTransactionModeClosure {
            return try await closure(spendTransaction, mode)
        } else {
            return submitSpendTransactionModeReturnValue
        }
    }

    // MARK: - fetchTransaction

    var fetchTransactionTxIdModeThrowableError: Error?
    var fetchTransactionTxIdModeCallsCount = 0
    var fetchTransactionTxIdModeCalled: Bool {
        return fetchTransactionTxIdModeCallsCount > 0
    }
    var fetchTransactionTxIdModeReceivedArguments: (txId: Data, mode: ServiceMode)?
    var fetchTransactionTxIdModeReturnValue: (tx: ZcashTransaction.Fetched?, status: TransactionStatus)!
    var fetchTransactionTxIdModeClosure: ((Data, ServiceMode) async throws -> (tx: ZcashTransaction.Fetched?, status: TransactionStatus))?

    func fetchTransaction(txId: Data, mode: ServiceMode) async throws -> (tx: ZcashTransaction.Fetched?, status: TransactionStatus) {
        if let error = fetchTransactionTxIdModeThrowableError {
            throw error
        }
        fetchTransactionTxIdModeCallsCount += 1
        fetchTransactionTxIdModeReceivedArguments = (txId: txId, mode: mode)
        if let closure = fetchTransactionTxIdModeClosure {
            return try await closure(txId, mode)
        } else {
            return fetchTransactionTxIdModeReturnValue
        }
    }

    // MARK: - fetchUTXOs

    var fetchUTXOsSingleThrowableError: Error?
    var fetchUTXOsSingleCallsCount = 0
    var fetchUTXOsSingleCalled: Bool {
        return fetchUTXOsSingleCallsCount > 0
    }
    var fetchUTXOsSingleReceivedArguments: (tAddress: String, height: BlockHeight, mode: ServiceMode)?
    var fetchUTXOsSingleReturnValue: AsyncThrowingStream<UnspentTransactionOutputEntity, Error>!
    var fetchUTXOsSingleClosure: ((String, BlockHeight, ServiceMode) throws -> AsyncThrowingStream<UnspentTransactionOutputEntity, Error>)?

    func fetchUTXOs(for tAddress: String, height: BlockHeight, mode: ServiceMode) throws -> AsyncThrowingStream<UnspentTransactionOutputEntity, Error> {
        if let error = fetchUTXOsSingleThrowableError {
            throw error
        }
        fetchUTXOsSingleCallsCount += 1
        fetchUTXOsSingleReceivedArguments = (tAddress: tAddress, height: height, mode: mode)
        if let closure = fetchUTXOsSingleClosure {
            return try closure(tAddress, height, mode)
        } else {
            return fetchUTXOsSingleReturnValue
        }
    }

    // MARK: - fetchUTXOs

    var fetchUTXOsForHeightModeThrowableError: Error?
    var fetchUTXOsForHeightModeCallsCount = 0
    var fetchUTXOsForHeightModeCalled: Bool {
        return fetchUTXOsForHeightModeCallsCount > 0
    }
    var fetchUTXOsForHeightModeReceivedArguments: (tAddresses: [String], height: BlockHeight, mode: ServiceMode)?
    var fetchUTXOsForHeightModeReturnValue: AsyncThrowingStream<UnspentTransactionOutputEntity, Error>!
    var fetchUTXOsForHeightModeClosure: (([String], BlockHeight, ServiceMode) throws -> AsyncThrowingStream<UnspentTransactionOutputEntity, Error>)?

    func fetchUTXOs(for tAddresses: [String], height: BlockHeight, mode: ServiceMode) throws -> AsyncThrowingStream<UnspentTransactionOutputEntity, Error> {
        if let error = fetchUTXOsForHeightModeThrowableError {
            throw error
        }
        fetchUTXOsForHeightModeCallsCount += 1
        fetchUTXOsForHeightModeReceivedArguments = (tAddresses: tAddresses, height: height, mode: mode)
        if let closure = fetchUTXOsForHeightModeClosure {
            return try closure(tAddresses, height, mode)
        } else {
            return fetchUTXOsForHeightModeReturnValue
        }
    }

    // MARK: - blockStream

    var blockStreamStartHeightEndHeightModeThrowableError: Error?
    var blockStreamStartHeightEndHeightModeCallsCount = 0
    var blockStreamStartHeightEndHeightModeCalled: Bool {
        return blockStreamStartHeightEndHeightModeCallsCount > 0
    }
    var blockStreamStartHeightEndHeightModeReceivedArguments: (startHeight: BlockHeight, endHeight: BlockHeight, mode: ServiceMode)?
    var blockStreamStartHeightEndHeightModeReturnValue: AsyncThrowingStream<ZcashCompactBlock, Error>!
    var blockStreamStartHeightEndHeightModeClosure: ((BlockHeight, BlockHeight, ServiceMode) throws -> AsyncThrowingStream<ZcashCompactBlock, Error>)?

    func blockStream(startHeight: BlockHeight, endHeight: BlockHeight, mode: ServiceMode) throws -> AsyncThrowingStream<ZcashCompactBlock, Error> {
        if let error = blockStreamStartHeightEndHeightModeThrowableError {
            throw error
        }
        blockStreamStartHeightEndHeightModeCallsCount += 1
        blockStreamStartHeightEndHeightModeReceivedArguments = (startHeight: startHeight, endHeight: endHeight, mode: mode)
        if let closure = blockStreamStartHeightEndHeightModeClosure {
            return try closure(startHeight, endHeight, mode)
        } else {
            return blockStreamStartHeightEndHeightModeReturnValue
        }
    }

    // MARK: - closeConnections

    var closeConnectionsCallsCount = 0
    var closeConnectionsCalled: Bool {
        return closeConnectionsCallsCount > 0
    }
    var closeConnectionsClosure: (() async -> Void)?

    func closeConnections() async {
        closeConnectionsCallsCount += 1
        await closeConnectionsClosure!()
    }

    // MARK: - getSubtreeRoots

    var getSubtreeRootsModeThrowableError: Error?
    var getSubtreeRootsModeCallsCount = 0
    var getSubtreeRootsModeCalled: Bool {
        return getSubtreeRootsModeCallsCount > 0
    }
    var getSubtreeRootsModeReceivedArguments: (request: GetSubtreeRootsArg, mode: ServiceMode)?
    var getSubtreeRootsModeReturnValue: AsyncThrowingStream<SubtreeRoot, Error>!
    var getSubtreeRootsModeClosure: ((GetSubtreeRootsArg, ServiceMode) throws -> AsyncThrowingStream<SubtreeRoot, Error>)?

    func getSubtreeRoots(_ request: GetSubtreeRootsArg, mode: ServiceMode) throws -> AsyncThrowingStream<SubtreeRoot, Error> {
        if let error = getSubtreeRootsModeThrowableError {
            throw error
        }
        getSubtreeRootsModeCallsCount += 1
        getSubtreeRootsModeReceivedArguments = (request: request, mode: mode)
        if let closure = getSubtreeRootsModeClosure {
            return try closure(request, mode)
        } else {
            return getSubtreeRootsModeReturnValue
        }
    }

    // MARK: - getTreeState

    var getTreeStateModeThrowableError: Error?
    var getTreeStateModeCallsCount = 0
    var getTreeStateModeCalled: Bool {
        return getTreeStateModeCallsCount > 0
    }
    var getTreeStateModeReceivedArguments: (id: BlockID, mode: ServiceMode)?
    var getTreeStateModeReturnValue: TreeState!
    var getTreeStateModeClosure: ((BlockID, ServiceMode) async throws -> TreeState)?

    func getTreeState(_ id: BlockID, mode: ServiceMode) async throws -> TreeState {
        if let error = getTreeStateModeThrowableError {
            throw error
        }
        getTreeStateModeCallsCount += 1
        getTreeStateModeReceivedArguments = (id: id, mode: mode)
        if let closure = getTreeStateModeClosure {
            return try await closure(id, mode)
        } else {
            return getTreeStateModeReturnValue
        }
    }

    // MARK: - getTaddressTransactions

    var getTaddressTransactionsModeThrowableError: Error?
    var getTaddressTransactionsModeCallsCount = 0
    var getTaddressTransactionsModeCalled: Bool {
        return getTaddressTransactionsModeCallsCount > 0
    }
    var getTaddressTransactionsModeReceivedArguments: (request: TransparentAddressBlockFilter, mode: ServiceMode)?
    var getTaddressTransactionsModeReturnValue: AsyncThrowingStream<RawTransaction, Error>!
    var getTaddressTransactionsModeClosure: ((TransparentAddressBlockFilter, ServiceMode) throws -> AsyncThrowingStream<RawTransaction, Error>)?

    func getTaddressTransactions(_ request: TransparentAddressBlockFilter, mode: ServiceMode) throws -> AsyncThrowingStream<RawTransaction, Error> {
        if let error = getTaddressTransactionsModeThrowableError {
            throw error
        }
        getTaddressTransactionsModeCallsCount += 1
        getTaddressTransactionsModeReceivedArguments = (request: request, mode: mode)
        if let closure = getTaddressTransactionsModeClosure {
            return try closure(request, mode)
        } else {
            return getTaddressTransactionsModeReturnValue
        }
    }

    // MARK: - getMempoolStream

    var getMempoolStreamThrowableError: Error?
    var getMempoolStreamCallsCount = 0
    var getMempoolStreamCalled: Bool {
        return getMempoolStreamCallsCount > 0
    }
    var getMempoolStreamReturnValue: AsyncThrowingStream<RawTransaction, Error>!
    var getMempoolStreamClosure: (() throws -> AsyncThrowingStream<RawTransaction, Error>)?

    func getMempoolStream() throws -> AsyncThrowingStream<RawTransaction, Error> {
        if let error = getMempoolStreamThrowableError {
            throw error
        }
        getMempoolStreamCallsCount += 1
        if let closure = getMempoolStreamClosure {
            return try closure()
        } else {
            return getMempoolStreamReturnValue
        }
    }

    // MARK: - checkSingleUseTransparentAddresses

    var checkSingleUseTransparentAddressesDbDataNetworkTypeAccountUUIDModeThrowableError: Error?
    var checkSingleUseTransparentAddressesDbDataNetworkTypeAccountUUIDModeCallsCount = 0
    var checkSingleUseTransparentAddressesDbDataNetworkTypeAccountUUIDModeCalled: Bool {
        return checkSingleUseTransparentAddressesDbDataNetworkTypeAccountUUIDModeCallsCount > 0
    }
    var checkSingleUseTransparentAddressesDbDataNetworkTypeAccountUUIDModeReceivedArguments: (dbData: (String, UInt), networkType: NetworkType, accountUUID: AccountUUID, mode: ServiceMode)?
    var checkSingleUseTransparentAddressesDbDataNetworkTypeAccountUUIDModeReturnValue: TransparentAddressCheckResult!
    var checkSingleUseTransparentAddressesDbDataNetworkTypeAccountUUIDModeClosure: (((String, UInt), NetworkType, AccountUUID, ServiceMode) async throws -> TransparentAddressCheckResult)?

    func checkSingleUseTransparentAddresses(dbData: (String, UInt), networkType: NetworkType, accountUUID: AccountUUID, mode: ServiceMode) async throws -> TransparentAddressCheckResult {
        if let error = checkSingleUseTransparentAddressesDbDataNetworkTypeAccountUUIDModeThrowableError {
            throw error
        }
        checkSingleUseTransparentAddressesDbDataNetworkTypeAccountUUIDModeCallsCount += 1
        checkSingleUseTransparentAddressesDbDataNetworkTypeAccountUUIDModeReceivedArguments = (dbData: dbData, networkType: networkType, accountUUID: accountUUID, mode: mode)
        if let closure = checkSingleUseTransparentAddressesDbDataNetworkTypeAccountUUIDModeClosure {
            return try await closure(dbData, networkType, accountUUID, mode)
        } else {
            return checkSingleUseTransparentAddressesDbDataNetworkTypeAccountUUIDModeReturnValue
        }
    }

    // MARK: - updateTransparentAddressTransactions

    var updateTransparentAddressTransactionsAddressStartEndDbDataNetworkTypeModeThrowableError: Error?
    var updateTransparentAddressTransactionsAddressStartEndDbDataNetworkTypeModeCallsCount = 0
    var updateTransparentAddressTransactionsAddressStartEndDbDataNetworkTypeModeCalled: Bool {
        return updateTransparentAddressTransactionsAddressStartEndDbDataNetworkTypeModeCallsCount > 0
    }
    var updateTransparentAddressTransactionsAddressStartEndDbDataNetworkTypeModeReceivedArguments: (address: String, start: BlockHeight, end: BlockHeight, dbData: (String, UInt), networkType: NetworkType, mode: ServiceMode)?
    var updateTransparentAddressTransactionsAddressStartEndDbDataNetworkTypeModeReturnValue: TransparentAddressCheckResult!
    var updateTransparentAddressTransactionsAddressStartEndDbDataNetworkTypeModeClosure: ((String, BlockHeight, BlockHeight, (String, UInt), NetworkType, ServiceMode) async throws -> TransparentAddressCheckResult)?

    func updateTransparentAddressTransactions(address: String, start: BlockHeight, end: BlockHeight, dbData: (String, UInt), networkType: NetworkType, mode: ServiceMode) async throws -> TransparentAddressCheckResult {
        if let error = updateTransparentAddressTransactionsAddressStartEndDbDataNetworkTypeModeThrowableError {
            throw error
        }
        updateTransparentAddressTransactionsAddressStartEndDbDataNetworkTypeModeCallsCount += 1
        updateTransparentAddressTransactionsAddressStartEndDbDataNetworkTypeModeReceivedArguments = (address: address, start: start, end: end, dbData: dbData, networkType: networkType, mode: mode)
        if let closure = updateTransparentAddressTransactionsAddressStartEndDbDataNetworkTypeModeClosure {
            return try await closure(address, start, end, dbData, networkType, mode)
        } else {
            return updateTransparentAddressTransactionsAddressStartEndDbDataNetworkTypeModeReturnValue
        }
    }

    // MARK: - fetchUTXOsByAddress

    var fetchUTXOsByAddressAddressDbDataNetworkTypeAccountUUIDModeThrowableError: Error?
    var fetchUTXOsByAddressAddressDbDataNetworkTypeAccountUUIDModeCallsCount = 0
    var fetchUTXOsByAddressAddressDbDataNetworkTypeAccountUUIDModeCalled: Bool {
        return fetchUTXOsByAddressAddressDbDataNetworkTypeAccountUUIDModeCallsCount > 0
    }
    var fetchUTXOsByAddressAddressDbDataNetworkTypeAccountUUIDModeReceivedArguments: (address: String, dbData: (String, UInt), networkType: NetworkType, accountUUID: AccountUUID, mode: ServiceMode)?
    var fetchUTXOsByAddressAddressDbDataNetworkTypeAccountUUIDModeReturnValue: TransparentAddressCheckResult!
    var fetchUTXOsByAddressAddressDbDataNetworkTypeAccountUUIDModeClosure: ((String, (String, UInt), NetworkType, AccountUUID, ServiceMode) async throws -> TransparentAddressCheckResult)?

    func fetchUTXOsByAddress(address: String, dbData: (String, UInt), networkType: NetworkType, accountUUID: AccountUUID, mode: ServiceMode) async throws -> TransparentAddressCheckResult {
        if let error = fetchUTXOsByAddressAddressDbDataNetworkTypeAccountUUIDModeThrowableError {
            throw error
        }
        fetchUTXOsByAddressAddressDbDataNetworkTypeAccountUUIDModeCallsCount += 1
        fetchUTXOsByAddressAddressDbDataNetworkTypeAccountUUIDModeReceivedArguments = (address: address, dbData: dbData, networkType: networkType, accountUUID: accountUUID, mode: mode)
        if let closure = fetchUTXOsByAddressAddressDbDataNetworkTypeAccountUUIDModeClosure {
            return try await closure(address, dbData, networkType, accountUUID, mode)
        } else {
            return fetchUTXOsByAddressAddressDbDataNetworkTypeAccountUUIDModeReturnValue
        }
    }

}
class LightWalletdInfoMock: LightWalletdInfo {


    init(
    ) {
    }
    var version: String {
        get { return underlyingVersion }
    }
    var underlyingVersion: String!
    var vendor: String {
        get { return underlyingVendor }
    }
    var underlyingVendor: String!
    var taddrSupport: Bool {
        get { return underlyingTaddrSupport }
    }
    var underlyingTaddrSupport: Bool!
    var chainName: String {
        get { return underlyingChainName }
    }
    var underlyingChainName: String!
    var saplingActivationHeight: UInt64 {
        get { return underlyingSaplingActivationHeight }
    }
    var underlyingSaplingActivationHeight: UInt64!
    var consensusBranchID: String {
        get { return underlyingConsensusBranchID }
    }
    var underlyingConsensusBranchID: String!
    var blockHeight: UInt64 {
        get { return underlyingBlockHeight }
    }
    var underlyingBlockHeight: UInt64!
    var gitCommit: String {
        get { return underlyingGitCommit }
    }
    var underlyingGitCommit: String!
    var branch: String {
        get { return underlyingBranch }
    }
    var underlyingBranch: String!
    var buildDate: String {
        get { return underlyingBuildDate }
    }
    var underlyingBuildDate: String!
    var buildUser: String {
        get { return underlyingBuildUser }
    }
    var underlyingBuildUser: String!
    var estimatedHeight: UInt64 {
        get { return underlyingEstimatedHeight }
    }
    var underlyingEstimatedHeight: UInt64!
    var zcashdBuild: String {
        get { return underlyingZcashdBuild }
    }
    var underlyingZcashdBuild: String!
    var zcashdSubversion: String {
        get { return underlyingZcashdSubversion }
    }
    var underlyingZcashdSubversion: String!

}
class LoggerMock: Logger {


    init(
    ) {
    }

    // MARK: - maxLogLevel

    var maxLogLevelCallsCount = 0
    var maxLogLevelCalled: Bool {
        return maxLogLevelCallsCount > 0
    }
    var maxLogLevelReturnValue: OSLogger.LogLevel?
    var maxLogLevelClosure: (() -> OSLogger.LogLevel?)?

    func maxLogLevel() -> OSLogger.LogLevel? {
        maxLogLevelCallsCount += 1
        if let closure = maxLogLevelClosure {
            return closure()
        } else {
            return maxLogLevelReturnValue
        }
    }

    // MARK: - debug

    var debugFileFunctionLineCallsCount = 0
    var debugFileFunctionLineCalled: Bool {
        return debugFileFunctionLineCallsCount > 0
    }
    var debugFileFunctionLineReceivedArguments: (message: String, file: StaticString, function: StaticString, line: Int)?
    var debugFileFunctionLineClosure: ((String, StaticString, StaticString, Int) -> Void)?

    func debug(_ message: String, file: StaticString, function: StaticString, line: Int) {
        debugFileFunctionLineCallsCount += 1
        debugFileFunctionLineReceivedArguments = (message: message, file: file, function: function, line: line)
        debugFileFunctionLineClosure!(message, file, function, line)
    }

    // MARK: - info

    var infoFileFunctionLineCallsCount = 0
    var infoFileFunctionLineCalled: Bool {
        return infoFileFunctionLineCallsCount > 0
    }
    var infoFileFunctionLineReceivedArguments: (message: String, file: StaticString, function: StaticString, line: Int)?
    var infoFileFunctionLineClosure: ((String, StaticString, StaticString, Int) -> Void)?

    func info(_ message: String, file: StaticString, function: StaticString, line: Int) {
        infoFileFunctionLineCallsCount += 1
        infoFileFunctionLineReceivedArguments = (message: message, file: file, function: function, line: line)
        infoFileFunctionLineClosure!(message, file, function, line)
    }

    // MARK: - event

    var eventFileFunctionLineCallsCount = 0
    var eventFileFunctionLineCalled: Bool {
        return eventFileFunctionLineCallsCount > 0
    }
    var eventFileFunctionLineReceivedArguments: (message: String, file: StaticString, function: StaticString, line: Int)?
    var eventFileFunctionLineClosure: ((String, StaticString, StaticString, Int) -> Void)?

    func event(_ message: String, file: StaticString, function: StaticString, line: Int) {
        eventFileFunctionLineCallsCount += 1
        eventFileFunctionLineReceivedArguments = (message: message, file: file, function: function, line: line)
        eventFileFunctionLineClosure!(message, file, function, line)
    }

    // MARK: - warn

    var warnFileFunctionLineCallsCount = 0
    var warnFileFunctionLineCalled: Bool {
        return warnFileFunctionLineCallsCount > 0
    }
    var warnFileFunctionLineReceivedArguments: (message: String, file: StaticString, function: StaticString, line: Int)?
    var warnFileFunctionLineClosure: ((String, StaticString, StaticString, Int) -> Void)?

    func warn(_ message: String, file: StaticString, function: StaticString, line: Int) {
        warnFileFunctionLineCallsCount += 1
        warnFileFunctionLineReceivedArguments = (message: message, file: file, function: function, line: line)
        warnFileFunctionLineClosure!(message, file, function, line)
    }

    // MARK: - error

    var errorFileFunctionLineCallsCount = 0
    var errorFileFunctionLineCalled: Bool {
        return errorFileFunctionLineCallsCount > 0
    }
    var errorFileFunctionLineReceivedArguments: (message: String, file: StaticString, function: StaticString, line: Int)?
    var errorFileFunctionLineClosure: ((String, StaticString, StaticString, Int) -> Void)?

    func error(_ message: String, file: StaticString, function: StaticString, line: Int) {
        errorFileFunctionLineCallsCount += 1
        errorFileFunctionLineReceivedArguments = (message: message, file: file, function: function, line: line)
        errorFileFunctionLineClosure!(message, file, function, line)
    }

    // MARK: - sync

    var syncFileFunctionLineCallsCount = 0
    var syncFileFunctionLineCalled: Bool {
        return syncFileFunctionLineCallsCount > 0
    }
    var syncFileFunctionLineReceivedArguments: (message: String, file: StaticString, function: StaticString, line: Int)?
    var syncFileFunctionLineClosure: ((String, StaticString, StaticString, Int) -> Void)?

    func sync(_ message: String, file: StaticString, function: StaticString, line: Int) {
        syncFileFunctionLineCallsCount += 1
        syncFileFunctionLineReceivedArguments = (message: message, file: file, function: function, line: line)
        syncFileFunctionLineClosure!(message, file, function, line)
    }

}
class SDKMetricsMock: SDKMetrics {


    init(
    ) {
    }

    // MARK: - cbpStart

    var cbpStartCallsCount = 0
    var cbpStartCalled: Bool {
        return cbpStartCallsCount > 0
    }
    var cbpStartClosure: (() -> Void)?

    func cbpStart() {
        cbpStartCallsCount += 1
        cbpStartClosure!()
    }

    // MARK: - actionStart

    var actionStartCallsCount = 0
    var actionStartCalled: Bool {
        return actionStartCallsCount > 0
    }
    var actionStartReceivedAction: CBPState?
    var actionStartClosure: ((CBPState) -> Void)?

    func actionStart(_ action: CBPState) {
        actionStartCallsCount += 1
        actionStartReceivedAction = action
        actionStartClosure!(action)
    }

    // MARK: - actionDetail

    var actionDetailForCallsCount = 0
    var actionDetailForCalled: Bool {
        return actionDetailForCallsCount > 0
    }
    var actionDetailForReceivedArguments: (detail: String, action: CBPState)?
    var actionDetailForClosure: ((String, CBPState) -> Void)?

    func actionDetail(_ detail: String, `for` action: CBPState) {
        actionDetailForCallsCount += 1
        actionDetailForReceivedArguments = (detail: detail, action: action)
        actionDetailForClosure!(detail, action)
    }

    // MARK: - actionStop

    var actionStopCallsCount = 0
    var actionStopCalled: Bool {
        return actionStopCallsCount > 0
    }
    var actionStopClosure: (() -> Void)?

    func actionStop() {
        actionStopCallsCount += 1
        actionStopClosure!()
    }

    // MARK: - logCBPOverviewReport

    var logCBPOverviewReportWalletSummaryCallsCount = 0
    var logCBPOverviewReportWalletSummaryCalled: Bool {
        return logCBPOverviewReportWalletSummaryCallsCount > 0
    }
    var logCBPOverviewReportWalletSummaryReceivedArguments: (logger: Logger, walletSummary: WalletSummary?)?
    var logCBPOverviewReportWalletSummaryClosure: ((Logger, WalletSummary?) async -> Void)?

    func logCBPOverviewReport(_ logger: Logger, walletSummary: WalletSummary?) async {
        logCBPOverviewReportWalletSummaryCallsCount += 1
        logCBPOverviewReportWalletSummaryReceivedArguments = (logger: logger, walletSummary: walletSummary)
        await logCBPOverviewReportWalletSummaryClosure!(logger, walletSummary)
    }

}
class SaplingParametersHandlerMock: SaplingParametersHandler {


    init(
    ) {
    }

    // MARK: - handleIfNeeded

    var handleIfNeededThrowableError: Error?
    var handleIfNeededCallsCount = 0
    var handleIfNeededCalled: Bool {
        return handleIfNeededCallsCount > 0
    }
    var handleIfNeededClosure: (() async throws -> Void)?

    func handleIfNeeded() async throws {
        if let error = handleIfNeededThrowableError {
            throw error
        }
        handleIfNeededCallsCount += 1
        try await handleIfNeededClosure!()
    }

}
class SynchronizerMock: Synchronizer {


    init(
    ) {
    }
    var alias: ZcashSynchronizerAlias {
        get { return underlyingAlias }
    }
    var underlyingAlias: ZcashSynchronizerAlias!
    var latestState: SynchronizerState {
        get { return underlyingLatestState }
    }
    var underlyingLatestState: SynchronizerState!
    var connectionState: ConnectionState {
        get { return underlyingConnectionState }
    }
    var underlyingConnectionState: ConnectionState!
    var stateStream: AnyPublisher<SynchronizerState, Never> {
        get { return underlyingStateStream }
    }
    var underlyingStateStream: AnyPublisher<SynchronizerState, Never>!
    var eventStream: AnyPublisher<SynchronizerEvent, Never> {
        get { return underlyingEventStream }
    }
    var underlyingEventStream: AnyPublisher<SynchronizerEvent, Never>!
    var exchangeRateUSDStream: AnyPublisher<FiatCurrencyResult?, Never> {
        get { return underlyingExchangeRateUSDStream }
    }
    var underlyingExchangeRateUSDStream: AnyPublisher<FiatCurrencyResult?, Never>!
    var transactions: [ZcashTransaction.Overview] {
        get async { return underlyingTransactions }
    }
    var underlyingTransactions: [ZcashTransaction.Overview] = []
    var sentTransactions: [ZcashTransaction.Overview] {
        get async { return underlyingSentTransactions }
    }
    var underlyingSentTransactions: [ZcashTransaction.Overview] = []
    var receivedTransactions: [ZcashTransaction.Overview] {
        get async { return underlyingReceivedTransactions }
    }
    var underlyingReceivedTransactions: [ZcashTransaction.Overview] = []
    var broadcaster: Broadcaster {
        get { return underlyingBroadcaster }
    }
    var underlyingBroadcaster: Broadcaster!
    var migrationSyncBlockedStream: AnyPublisher<Bool, Never> {
        get { return underlyingMigrationSyncBlockedStream }
    }
    var underlyingMigrationSyncBlockedStream: AnyPublisher<Bool, Never>!

    // MARK: - prepare

    var prepareWithWalletBirthdayNameKeySourceThrowableError: Error?
    var prepareWithWalletBirthdayNameKeySourceCallsCount = 0
    var prepareWithWalletBirthdayNameKeySourceCalled: Bool {
        return prepareWithWalletBirthdayNameKeySourceCallsCount > 0
    }
    var prepareWithWalletBirthdayNameKeySourceReceivedArguments: (seed: [UInt8]?, walletBirthday: BlockHeight?, name: String, keySource: String?)?
    var prepareWithWalletBirthdayNameKeySourceReturnValue: Initializer.InitializationResult!
    var prepareWithWalletBirthdayNameKeySourceClosure: (([UInt8]?, BlockHeight?, String, String?) async throws -> Initializer.InitializationResult)?

    func prepare(with seed: [UInt8]?, walletBirthday: BlockHeight?, name: String, keySource: String?) async throws -> Initializer.InitializationResult {
        if let error = prepareWithWalletBirthdayNameKeySourceThrowableError {
            throw error
        }
        prepareWithWalletBirthdayNameKeySourceCallsCount += 1
        prepareWithWalletBirthdayNameKeySourceReceivedArguments = (seed: seed, walletBirthday: walletBirthday, name: name, keySource: keySource)
        if let closure = prepareWithWalletBirthdayNameKeySourceClosure {
            return try await closure(seed, walletBirthday, name, keySource)
        } else {
            return prepareWithWalletBirthdayNameKeySourceReturnValue
        }
    }

    // MARK: - start

    var startRetryThrowableError: Error?
    var startRetryCallsCount = 0
    var startRetryCalled: Bool {
        return startRetryCallsCount > 0
    }
    var startRetryReceivedRetry: Bool?
    var startRetryClosure: ((Bool) async throws -> Void)?

    func start(retry: Bool) async throws {
        if let error = startRetryThrowableError {
            throw error
        }
        startRetryCallsCount += 1
        startRetryReceivedRetry = retry
        try await startRetryClosure!(retry)
    }

    // MARK: - stop

    var stopCallsCount = 0
    var stopCalled: Bool {
        return stopCallsCount > 0
    }
    var stopClosure: (() -> Void)?

    func stop() {
        stopCallsCount += 1
        stopClosure!()
    }

    // MARK: - getSaplingAddress

    var getSaplingAddressAccountUUIDThrowableError: Error?
    var getSaplingAddressAccountUUIDCallsCount = 0
    var getSaplingAddressAccountUUIDCalled: Bool {
        return getSaplingAddressAccountUUIDCallsCount > 0
    }
    var getSaplingAddressAccountUUIDReceivedAccountUUID: AccountUUID?
    var getSaplingAddressAccountUUIDReturnValue: SaplingAddress!
    var getSaplingAddressAccountUUIDClosure: ((AccountUUID) async throws -> SaplingAddress)?

    func getSaplingAddress(accountUUID: AccountUUID) async throws -> SaplingAddress {
        if let error = getSaplingAddressAccountUUIDThrowableError {
            throw error
        }
        getSaplingAddressAccountUUIDCallsCount += 1
        getSaplingAddressAccountUUIDReceivedAccountUUID = accountUUID
        if let closure = getSaplingAddressAccountUUIDClosure {
            return try await closure(accountUUID)
        } else {
            return getSaplingAddressAccountUUIDReturnValue
        }
    }

    // MARK: - getUnifiedAddress

    var getUnifiedAddressAccountUUIDThrowableError: Error?
    var getUnifiedAddressAccountUUIDCallsCount = 0
    var getUnifiedAddressAccountUUIDCalled: Bool {
        return getUnifiedAddressAccountUUIDCallsCount > 0
    }
    var getUnifiedAddressAccountUUIDReceivedAccountUUID: AccountUUID?
    var getUnifiedAddressAccountUUIDReturnValue: UnifiedAddress!
    var getUnifiedAddressAccountUUIDClosure: ((AccountUUID) async throws -> UnifiedAddress)?

    func getUnifiedAddress(accountUUID: AccountUUID) async throws -> UnifiedAddress {
        if let error = getUnifiedAddressAccountUUIDThrowableError {
            throw error
        }
        getUnifiedAddressAccountUUIDCallsCount += 1
        getUnifiedAddressAccountUUIDReceivedAccountUUID = accountUUID
        if let closure = getUnifiedAddressAccountUUIDClosure {
            return try await closure(accountUUID)
        } else {
            return getUnifiedAddressAccountUUIDReturnValue
        }
    }

    // MARK: - getTransparentAddress

    var getTransparentAddressAccountUUIDThrowableError: Error?
    var getTransparentAddressAccountUUIDCallsCount = 0
    var getTransparentAddressAccountUUIDCalled: Bool {
        return getTransparentAddressAccountUUIDCallsCount > 0
    }
    var getTransparentAddressAccountUUIDReceivedAccountUUID: AccountUUID?
    var getTransparentAddressAccountUUIDReturnValue: TransparentAddress!
    var getTransparentAddressAccountUUIDClosure: ((AccountUUID) async throws -> TransparentAddress)?

    func getTransparentAddress(accountUUID: AccountUUID) async throws -> TransparentAddress {
        if let error = getTransparentAddressAccountUUIDThrowableError {
            throw error
        }
        getTransparentAddressAccountUUIDCallsCount += 1
        getTransparentAddressAccountUUIDReceivedAccountUUID = accountUUID
        if let closure = getTransparentAddressAccountUUIDClosure {
            return try await closure(accountUUID)
        } else {
            return getTransparentAddressAccountUUIDReturnValue
        }
    }

    // MARK: - getCustomUnifiedAddress

    var getCustomUnifiedAddressAccountUUIDReceiversThrowableError: Error?
    var getCustomUnifiedAddressAccountUUIDReceiversCallsCount = 0
    var getCustomUnifiedAddressAccountUUIDReceiversCalled: Bool {
        return getCustomUnifiedAddressAccountUUIDReceiversCallsCount > 0
    }
    var getCustomUnifiedAddressAccountUUIDReceiversReceivedArguments: (accountUUID: AccountUUID, receivers: Set<ReceiverType>)?
    var getCustomUnifiedAddressAccountUUIDReceiversReturnValue: UnifiedAddress!
    var getCustomUnifiedAddressAccountUUIDReceiversClosure: ((AccountUUID, Set<ReceiverType>) async throws -> UnifiedAddress)?

    func getCustomUnifiedAddress(accountUUID: AccountUUID, receivers: Set<ReceiverType>) async throws -> UnifiedAddress {
        if let error = getCustomUnifiedAddressAccountUUIDReceiversThrowableError {
            throw error
        }
        getCustomUnifiedAddressAccountUUIDReceiversCallsCount += 1
        getCustomUnifiedAddressAccountUUIDReceiversReceivedArguments = (accountUUID: accountUUID, receivers: receivers)
        if let closure = getCustomUnifiedAddressAccountUUIDReceiversClosure {
            return try await closure(accountUUID, receivers)
        } else {
            return getCustomUnifiedAddressAccountUUIDReceiversReturnValue
        }
    }

    // MARK: - proposeTransfer

    var proposeTransferAccountUUIDRecipientAmountMemoThrowableError: Error?
    var proposeTransferAccountUUIDRecipientAmountMemoCallsCount = 0
    var proposeTransferAccountUUIDRecipientAmountMemoCalled: Bool {
        return proposeTransferAccountUUIDRecipientAmountMemoCallsCount > 0
    }
    var proposeTransferAccountUUIDRecipientAmountMemoReceivedArguments: (accountUUID: AccountUUID, recipient: Recipient, amount: Zatoshi, memo: Memo?)?
    var proposeTransferAccountUUIDRecipientAmountMemoReturnValue: Proposal!
    var proposeTransferAccountUUIDRecipientAmountMemoClosure: ((AccountUUID, Recipient, Zatoshi, Memo?) async throws -> Proposal)?

    func proposeTransfer(accountUUID: AccountUUID, recipient: Recipient, amount: Zatoshi, memo: Memo?) async throws -> Proposal {
        if let error = proposeTransferAccountUUIDRecipientAmountMemoThrowableError {
            throw error
        }
        proposeTransferAccountUUIDRecipientAmountMemoCallsCount += 1
        proposeTransferAccountUUIDRecipientAmountMemoReceivedArguments = (accountUUID: accountUUID, recipient: recipient, amount: amount, memo: memo)
        if let closure = proposeTransferAccountUUIDRecipientAmountMemoClosure {
            return try await closure(accountUUID, recipient, amount, memo)
        } else {
            return proposeTransferAccountUUIDRecipientAmountMemoReturnValue
        }
    }

    // MARK: - proposeSendMax

    var proposeSendMaxAccountUUIDRecipientMemoModeThrowableError: Error?
    var proposeSendMaxAccountUUIDRecipientMemoModeCallsCount = 0
    var proposeSendMaxAccountUUIDRecipientMemoModeCalled: Bool {
        return proposeSendMaxAccountUUIDRecipientMemoModeCallsCount > 0
    }
    var proposeSendMaxAccountUUIDRecipientMemoModeReceivedArguments: (accountUUID: AccountUUID, recipient: Recipient, memo: Memo?, mode: MaxSpendMode)?
    var proposeSendMaxAccountUUIDRecipientMemoModeReturnValue: Proposal!
    var proposeSendMaxAccountUUIDRecipientMemoModeClosure: ((AccountUUID, Recipient, Memo?, MaxSpendMode) async throws -> Proposal)?

    func proposeSendMax(accountUUID: AccountUUID, recipient: Recipient, memo: Memo?, mode: MaxSpendMode) async throws -> Proposal {
        if let error = proposeSendMaxAccountUUIDRecipientMemoModeThrowableError {
            throw error
        }
        proposeSendMaxAccountUUIDRecipientMemoModeCallsCount += 1
        proposeSendMaxAccountUUIDRecipientMemoModeReceivedArguments = (accountUUID: accountUUID, recipient: recipient, memo: memo, mode: mode)
        if let closure = proposeSendMaxAccountUUIDRecipientMemoModeClosure {
            return try await closure(accountUUID, recipient, memo, mode)
        } else {
            return proposeSendMaxAccountUUIDRecipientMemoModeReturnValue
        }
    }

    // MARK: - proposeOrchardToIronwoodMigration

    var proposeOrchardToIronwoodMigrationAccountUUIDThrowableError: Error?
    var proposeOrchardToIronwoodMigrationAccountUUIDCallsCount = 0
    var proposeOrchardToIronwoodMigrationAccountUUIDCalled: Bool {
        return proposeOrchardToIronwoodMigrationAccountUUIDCallsCount > 0
    }
    var proposeOrchardToIronwoodMigrationAccountUUIDReceivedAccountUUID: AccountUUID?
    var proposeOrchardToIronwoodMigrationAccountUUIDReturnValue: Proposal!
    var proposeOrchardToIronwoodMigrationAccountUUIDClosure: ((AccountUUID) async throws -> Proposal)?

    func proposeOrchardToIronwoodMigration(accountUUID: AccountUUID) async throws -> Proposal {
        if let error = proposeOrchardToIronwoodMigrationAccountUUIDThrowableError {
            throw error
        }
        proposeOrchardToIronwoodMigrationAccountUUIDCallsCount += 1
        proposeOrchardToIronwoodMigrationAccountUUIDReceivedAccountUUID = accountUUID
        if let closure = proposeOrchardToIronwoodMigrationAccountUUIDClosure {
            return try await closure(accountUUID)
        } else {
            return proposeOrchardToIronwoodMigrationAccountUUIDReturnValue
        }
    }

    // MARK: - proposeShielding

    var proposeShieldingAccountUUIDShieldingThresholdMemoTransparentReceiverThrowableError: Error?
    var proposeShieldingAccountUUIDShieldingThresholdMemoTransparentReceiverCallsCount = 0
    var proposeShieldingAccountUUIDShieldingThresholdMemoTransparentReceiverCalled: Bool {
        return proposeShieldingAccountUUIDShieldingThresholdMemoTransparentReceiverCallsCount > 0
    }
    var proposeShieldingAccountUUIDShieldingThresholdMemoTransparentReceiverReceivedArguments: (accountUUID: AccountUUID, shieldingThreshold: Zatoshi, memo: Memo, transparentReceiver: TransparentAddress?)?
    var proposeShieldingAccountUUIDShieldingThresholdMemoTransparentReceiverReturnValue: Proposal?
    var proposeShieldingAccountUUIDShieldingThresholdMemoTransparentReceiverClosure: ((AccountUUID, Zatoshi, Memo, TransparentAddress?) async throws -> Proposal?)?

    func proposeShielding(accountUUID: AccountUUID, shieldingThreshold: Zatoshi, memo: Memo, transparentReceiver: TransparentAddress?) async throws -> Proposal? {
        if let error = proposeShieldingAccountUUIDShieldingThresholdMemoTransparentReceiverThrowableError {
            throw error
        }
        proposeShieldingAccountUUIDShieldingThresholdMemoTransparentReceiverCallsCount += 1
        proposeShieldingAccountUUIDShieldingThresholdMemoTransparentReceiverReceivedArguments = (accountUUID: accountUUID, shieldingThreshold: shieldingThreshold, memo: memo, transparentReceiver: transparentReceiver)
        if let closure = proposeShieldingAccountUUIDShieldingThresholdMemoTransparentReceiverClosure {
            return try await closure(accountUUID, shieldingThreshold, memo, transparentReceiver)
        } else {
            return proposeShieldingAccountUUIDShieldingThresholdMemoTransparentReceiverReturnValue
        }
    }

    // MARK: - createProposedTransactions

    var createProposedTransactionsProposalSpendingKeyThrowableError: Error?
    var createProposedTransactionsProposalSpendingKeyCallsCount = 0
    var createProposedTransactionsProposalSpendingKeyCalled: Bool {
        return createProposedTransactionsProposalSpendingKeyCallsCount > 0
    }
    var createProposedTransactionsProposalSpendingKeyReceivedArguments: (proposal: Proposal, spendingKey: UnifiedSpendingKey)?
    var createProposedTransactionsProposalSpendingKeyReturnValue: AsyncThrowingStream<TransactionSubmitResult, Error>!
    var createProposedTransactionsProposalSpendingKeyClosure: ((Proposal, UnifiedSpendingKey) async throws -> AsyncThrowingStream<TransactionSubmitResult, Error>)?

    func createProposedTransactions(proposal: Proposal, spendingKey: UnifiedSpendingKey) async throws -> AsyncThrowingStream<TransactionSubmitResult, Error> {
        if let error = createProposedTransactionsProposalSpendingKeyThrowableError {
            throw error
        }
        createProposedTransactionsProposalSpendingKeyCallsCount += 1
        createProposedTransactionsProposalSpendingKeyReceivedArguments = (proposal: proposal, spendingKey: spendingKey)
        if let closure = createProposedTransactionsProposalSpendingKeyClosure {
            return try await closure(proposal, spendingKey)
        } else {
            return createProposedTransactionsProposalSpendingKeyReturnValue
        }
    }

    // MARK: - proposefulfillingPaymentURI

    var proposefulfillingPaymentURIAccountUUIDThrowableError: Error?
    var proposefulfillingPaymentURIAccountUUIDCallsCount = 0
    var proposefulfillingPaymentURIAccountUUIDCalled: Bool {
        return proposefulfillingPaymentURIAccountUUIDCallsCount > 0
    }
    var proposefulfillingPaymentURIAccountUUIDReceivedArguments: (uri: String, accountUUID: AccountUUID)?
    var proposefulfillingPaymentURIAccountUUIDReturnValue: Proposal!
    var proposefulfillingPaymentURIAccountUUIDClosure: ((String, AccountUUID) async throws -> Proposal)?

    func proposefulfillingPaymentURI(_ uri: String, accountUUID: AccountUUID) async throws -> Proposal {
        if let error = proposefulfillingPaymentURIAccountUUIDThrowableError {
            throw error
        }
        proposefulfillingPaymentURIAccountUUIDCallsCount += 1
        proposefulfillingPaymentURIAccountUUIDReceivedArguments = (uri: uri, accountUUID: accountUUID)
        if let closure = proposefulfillingPaymentURIAccountUUIDClosure {
            return try await closure(uri, accountUUID)
        } else {
            return proposefulfillingPaymentURIAccountUUIDReturnValue
        }
    }

    // MARK: - createPCZTFromProposal

    var createPCZTFromProposalAccountUUIDProposalThrowableError: Error?
    var createPCZTFromProposalAccountUUIDProposalCallsCount = 0
    var createPCZTFromProposalAccountUUIDProposalCalled: Bool {
        return createPCZTFromProposalAccountUUIDProposalCallsCount > 0
    }
    var createPCZTFromProposalAccountUUIDProposalReceivedArguments: (accountUUID: AccountUUID, proposal: Proposal)?
    var createPCZTFromProposalAccountUUIDProposalReturnValue: Pczt!
    var createPCZTFromProposalAccountUUIDProposalClosure: ((AccountUUID, Proposal) async throws -> Pczt)?

    func createPCZTFromProposal(accountUUID: AccountUUID, proposal: Proposal) async throws -> Pczt {
        if let error = createPCZTFromProposalAccountUUIDProposalThrowableError {
            throw error
        }
        createPCZTFromProposalAccountUUIDProposalCallsCount += 1
        createPCZTFromProposalAccountUUIDProposalReceivedArguments = (accountUUID: accountUUID, proposal: proposal)
        if let closure = createPCZTFromProposalAccountUUIDProposalClosure {
            return try await closure(accountUUID, proposal)
        } else {
            return createPCZTFromProposalAccountUUIDProposalReturnValue
        }
    }

    // MARK: - redactPCZTForSigner

    var redactPCZTForSignerPcztThrowableError: Error?
    var redactPCZTForSignerPcztCallsCount = 0
    var redactPCZTForSignerPcztCalled: Bool {
        return redactPCZTForSignerPcztCallsCount > 0
    }
    var redactPCZTForSignerPcztReceivedPczt: Pczt?
    var redactPCZTForSignerPcztReturnValue: Pczt!
    var redactPCZTForSignerPcztClosure: ((Pczt) async throws -> Pczt)?

    func redactPCZTForSigner(pczt: Pczt) async throws -> Pczt {
        if let error = redactPCZTForSignerPcztThrowableError {
            throw error
        }
        redactPCZTForSignerPcztCallsCount += 1
        redactPCZTForSignerPcztReceivedPczt = pczt
        if let closure = redactPCZTForSignerPcztClosure {
            return try await closure(pczt)
        } else {
            return redactPCZTForSignerPcztReturnValue
        }
    }

    // MARK: - PCZTRequiresSaplingProofs

    var pcztRequiresSaplingProofsPcztCallsCount = 0
    var pcztRequiresSaplingProofsPcztCalled: Bool {
        return pcztRequiresSaplingProofsPcztCallsCount > 0
    }
    var pcztRequiresSaplingProofsPcztReceivedPczt: Pczt?
    var pcztRequiresSaplingProofsPcztReturnValue: Bool!
    var pcztRequiresSaplingProofsPcztClosure: ((Pczt) async -> Bool)?

    func PCZTRequiresSaplingProofs(pczt: Pczt) async -> Bool {
        pcztRequiresSaplingProofsPcztCallsCount += 1
        pcztRequiresSaplingProofsPcztReceivedPczt = pczt
        if let closure = pcztRequiresSaplingProofsPcztClosure {
            return await closure(pczt)
        } else {
            return pcztRequiresSaplingProofsPcztReturnValue
        }
    }

    // MARK: - addProofsToPCZT

    var addProofsToPCZTPcztThrowableError: Error?
    var addProofsToPCZTPcztCallsCount = 0
    var addProofsToPCZTPcztCalled: Bool {
        return addProofsToPCZTPcztCallsCount > 0
    }
    var addProofsToPCZTPcztReceivedPczt: Pczt?
    var addProofsToPCZTPcztReturnValue: Pczt!
    var addProofsToPCZTPcztClosure: ((Pczt) async throws -> Pczt)?

    func addProofsToPCZT(pczt: Pczt) async throws -> Pczt {
        if let error = addProofsToPCZTPcztThrowableError {
            throw error
        }
        addProofsToPCZTPcztCallsCount += 1
        addProofsToPCZTPcztReceivedPczt = pczt
        if let closure = addProofsToPCZTPcztClosure {
            return try await closure(pczt)
        } else {
            return addProofsToPCZTPcztReturnValue
        }
    }

    // MARK: - createTransactionFromPCZT

    var createTransactionFromPCZTPcztWithProofsPcztWithSigsThrowableError: Error?
    var createTransactionFromPCZTPcztWithProofsPcztWithSigsCallsCount = 0
    var createTransactionFromPCZTPcztWithProofsPcztWithSigsCalled: Bool {
        return createTransactionFromPCZTPcztWithProofsPcztWithSigsCallsCount > 0
    }
    var createTransactionFromPCZTPcztWithProofsPcztWithSigsReceivedArguments: (pcztWithProofs: Pczt, pcztWithSigs: Pczt)?
    var createTransactionFromPCZTPcztWithProofsPcztWithSigsReturnValue: AsyncThrowingStream<TransactionSubmitResult, Error>!
    var createTransactionFromPCZTPcztWithProofsPcztWithSigsClosure: ((Pczt, Pczt) async throws -> AsyncThrowingStream<TransactionSubmitResult, Error>)?

    func createTransactionFromPCZT(pcztWithProofs: Pczt, pcztWithSigs: Pczt) async throws -> AsyncThrowingStream<TransactionSubmitResult, Error> {
        if let error = createTransactionFromPCZTPcztWithProofsPcztWithSigsThrowableError {
            throw error
        }
        createTransactionFromPCZTPcztWithProofsPcztWithSigsCallsCount += 1
        createTransactionFromPCZTPcztWithProofsPcztWithSigsReceivedArguments = (pcztWithProofs: pcztWithProofs, pcztWithSigs: pcztWithSigs)
        if let closure = createTransactionFromPCZTPcztWithProofsPcztWithSigsClosure {
            return try await closure(pcztWithProofs, pcztWithSigs)
        } else {
            return createTransactionFromPCZTPcztWithProofsPcztWithSigsReturnValue
        }
    }

    // MARK: - paginatedTransactions

    var paginatedTransactionsOfCallsCount = 0
    var paginatedTransactionsOfCalled: Bool {
        return paginatedTransactionsOfCallsCount > 0
    }
    var paginatedTransactionsOfReceivedKind: TransactionKind?
    var paginatedTransactionsOfReturnValue: PaginatedTransactionRepository!
    var paginatedTransactionsOfClosure: ((TransactionKind) -> PaginatedTransactionRepository)?

    func paginatedTransactions(of kind: TransactionKind) -> PaginatedTransactionRepository {
        paginatedTransactionsOfCallsCount += 1
        paginatedTransactionsOfReceivedKind = kind
        if let closure = paginatedTransactionsOfClosure {
            return closure(kind)
        } else {
            return paginatedTransactionsOfReturnValue
        }
    }

    // MARK: - getMemos

    var getMemosForRawIDThrowableError: Error?
    var getMemosForRawIDCallsCount = 0
    var getMemosForRawIDCalled: Bool {
        return getMemosForRawIDCallsCount > 0
    }
    var getMemosForRawIDReceivedRawID: Data?
    var getMemosForRawIDReturnValue: [Memo]!
    var getMemosForRawIDClosure: ((Data) async throws -> [Memo])?

    func getMemos(for rawID: Data) async throws -> [Memo] {
        if let error = getMemosForRawIDThrowableError {
            throw error
        }
        getMemosForRawIDCallsCount += 1
        getMemosForRawIDReceivedRawID = rawID
        if let closure = getMemosForRawIDClosure {
            return try await closure(rawID)
        } else {
            return getMemosForRawIDReturnValue
        }
    }

    // MARK: - getMemos

    var getMemosForClearedTransactionThrowableError: Error?
    var getMemosForClearedTransactionCallsCount = 0
    var getMemosForClearedTransactionCalled: Bool {
        return getMemosForClearedTransactionCallsCount > 0
    }
    var getMemosForClearedTransactionReceivedTransaction: ZcashTransaction.Overview?
    var getMemosForClearedTransactionReturnValue: [Memo]!
    var getMemosForClearedTransactionClosure: ((ZcashTransaction.Overview) async throws -> [Memo])?

    func getMemos(for transaction: ZcashTransaction.Overview) async throws -> [Memo] {
        if let error = getMemosForClearedTransactionThrowableError {
            throw error
        }
        getMemosForClearedTransactionCallsCount += 1
        getMemosForClearedTransactionReceivedTransaction = transaction
        if let closure = getMemosForClearedTransactionClosure {
            return try await closure(transaction)
        } else {
            return getMemosForClearedTransactionReturnValue
        }
    }

    // MARK: - getRecipients

    var getRecipientsForClearedTransactionCallsCount = 0
    var getRecipientsForClearedTransactionCalled: Bool {
        return getRecipientsForClearedTransactionCallsCount > 0
    }
    var getRecipientsForClearedTransactionReceivedTransaction: ZcashTransaction.Overview?
    var getRecipientsForClearedTransactionReturnValue: [TransactionRecipient]!
    var getRecipientsForClearedTransactionClosure: ((ZcashTransaction.Overview) async -> [TransactionRecipient])?

    func getRecipients(for transaction: ZcashTransaction.Overview) async -> [TransactionRecipient] {
        getRecipientsForClearedTransactionCallsCount += 1
        getRecipientsForClearedTransactionReceivedTransaction = transaction
        if let closure = getRecipientsForClearedTransactionClosure {
            return await closure(transaction)
        } else {
            return getRecipientsForClearedTransactionReturnValue
        }
    }

    // MARK: - getTransactionOutputs

    var getTransactionOutputsForTransactionCallsCount = 0
    var getTransactionOutputsForTransactionCalled: Bool {
        return getTransactionOutputsForTransactionCallsCount > 0
    }
    var getTransactionOutputsForTransactionReceivedTransaction: ZcashTransaction.Overview?
    var getTransactionOutputsForTransactionReturnValue: [ZcashTransaction.Output]!
    var getTransactionOutputsForTransactionClosure: ((ZcashTransaction.Overview) async -> [ZcashTransaction.Output])?

    func getTransactionOutputs(for transaction: ZcashTransaction.Overview) async -> [ZcashTransaction.Output] {
        getTransactionOutputsForTransactionCallsCount += 1
        getTransactionOutputsForTransactionReceivedTransaction = transaction
        if let closure = getTransactionOutputsForTransactionClosure {
            return await closure(transaction)
        } else {
            return getTransactionOutputsForTransactionReturnValue
        }
    }

    // MARK: - allTransactions

    var allTransactionsThrowableError: Error?
    var allTransactionsCallsCount = 0
    var allTransactionsCalled: Bool {
        return allTransactionsCallsCount > 0
    }
    var allTransactionsReturnValue: [ZcashTransaction.Overview]!
    var allTransactionsClosure: (() async throws -> [ZcashTransaction.Overview])?

    func allTransactions() async throws -> [ZcashTransaction.Overview] {
        if let error = allTransactionsThrowableError {
            throw error
        }
        allTransactionsCallsCount += 1
        if let closure = allTransactionsClosure {
            return try await closure()
        } else {
            return allTransactionsReturnValue
        }
    }

    // MARK: - allTransactions

    var allTransactionsFromLimitThrowableError: Error?
    var allTransactionsFromLimitCallsCount = 0
    var allTransactionsFromLimitCalled: Bool {
        return allTransactionsFromLimitCallsCount > 0
    }
    var allTransactionsFromLimitReceivedArguments: (transaction: ZcashTransaction.Overview, limit: Int)?
    var allTransactionsFromLimitReturnValue: [ZcashTransaction.Overview]!
    var allTransactionsFromLimitClosure: ((ZcashTransaction.Overview, Int) async throws -> [ZcashTransaction.Overview])?

    func allTransactions(from transaction: ZcashTransaction.Overview, limit: Int) async throws -> [ZcashTransaction.Overview] {
        if let error = allTransactionsFromLimitThrowableError {
            throw error
        }
        allTransactionsFromLimitCallsCount += 1
        allTransactionsFromLimitReceivedArguments = (transaction: transaction, limit: limit)
        if let closure = allTransactionsFromLimitClosure {
            return try await closure(transaction, limit)
        } else {
            return allTransactionsFromLimitReturnValue
        }
    }

    // MARK: - latestHeight

    var latestHeightThrowableError: Error?
    var latestHeightCallsCount = 0
    var latestHeightCalled: Bool {
        return latestHeightCallsCount > 0
    }
    var latestHeightReturnValue: BlockHeight!
    var latestHeightClosure: (() async throws -> BlockHeight)?

    func latestHeight() async throws -> BlockHeight {
        if let error = latestHeightThrowableError {
            throw error
        }
        latestHeightCallsCount += 1
        if let closure = latestHeightClosure {
            return try await closure()
        } else {
            return latestHeightReturnValue
        }
    }

    // MARK: - refreshUTXOs

    var refreshUTXOsAddressFromThrowableError: Error?
    var refreshUTXOsAddressFromCallsCount = 0
    var refreshUTXOsAddressFromCalled: Bool {
        return refreshUTXOsAddressFromCallsCount > 0
    }
    var refreshUTXOsAddressFromReceivedArguments: (address: TransparentAddress, height: BlockHeight)?
    var refreshUTXOsAddressFromReturnValue: RefreshedUTXOs!
    var refreshUTXOsAddressFromClosure: ((TransparentAddress, BlockHeight) async throws -> RefreshedUTXOs)?

    func refreshUTXOs(address: TransparentAddress, from height: BlockHeight) async throws -> RefreshedUTXOs {
        if let error = refreshUTXOsAddressFromThrowableError {
            throw error
        }
        refreshUTXOsAddressFromCallsCount += 1
        refreshUTXOsAddressFromReceivedArguments = (address: address, height: height)
        if let closure = refreshUTXOsAddressFromClosure {
            return try await closure(address, height)
        } else {
            return refreshUTXOsAddressFromReturnValue
        }
    }

    // MARK: - getAccountsBalances

    var getAccountsBalancesThrowableError: Error?
    var getAccountsBalancesCallsCount = 0
    var getAccountsBalancesCalled: Bool {
        return getAccountsBalancesCallsCount > 0
    }
    var getAccountsBalancesReturnValue: [AccountUUID: AccountBalance]!
    var getAccountsBalancesClosure: (() async throws -> [AccountUUID: AccountBalance])?

    func getAccountsBalances() async throws -> [AccountUUID: AccountBalance] {
        if let error = getAccountsBalancesThrowableError {
            throw error
        }
        getAccountsBalancesCallsCount += 1
        if let closure = getAccountsBalancesClosure {
            return try await closure()
        } else {
            return getAccountsBalancesReturnValue
        }
    }

    // MARK: - refreshExchangeRateUSD

    var refreshExchangeRateUSDCallsCount = 0
    var refreshExchangeRateUSDCalled: Bool {
        return refreshExchangeRateUSDCallsCount > 0
    }
    var refreshExchangeRateUSDClosure: (() -> Void)?

    func refreshExchangeRateUSD() {
        refreshExchangeRateUSDCallsCount += 1
        refreshExchangeRateUSDClosure!()
    }

    // MARK: - listAccounts

    var listAccountsThrowableError: Error?
    var listAccountsCallsCount = 0
    var listAccountsCalled: Bool {
        return listAccountsCallsCount > 0
    }
    var listAccountsReturnValue: [Account]!
    var listAccountsClosure: (() async throws -> [Account])?

    func listAccounts() async throws -> [Account] {
        if let error = listAccountsThrowableError {
            throw error
        }
        listAccountsCallsCount += 1
        if let closure = listAccountsClosure {
            return try await closure()
        } else {
            return listAccountsReturnValue
        }
    }

    // MARK: - importAccount

    var importAccountUfvkSeedFingerprintZip32AccountIndexPurposeNameKeySourceBirthdayThrowableError: Error?
    var importAccountUfvkSeedFingerprintZip32AccountIndexPurposeNameKeySourceBirthdayCallsCount = 0
    var importAccountUfvkSeedFingerprintZip32AccountIndexPurposeNameKeySourceBirthdayCalled: Bool {
        return importAccountUfvkSeedFingerprintZip32AccountIndexPurposeNameKeySourceBirthdayCallsCount > 0
    }
    var importAccountUfvkSeedFingerprintZip32AccountIndexPurposeNameKeySourceBirthdayReceivedArguments: (ufvk: String, seedFingerprint: [UInt8]?, zip32AccountIndex: Zip32AccountIndex?, purpose: AccountPurpose, name: String, keySource: String?, birthday: BlockHeight?)?
    var importAccountUfvkSeedFingerprintZip32AccountIndexPurposeNameKeySourceBirthdayReturnValue: AccountUUID!
    var importAccountUfvkSeedFingerprintZip32AccountIndexPurposeNameKeySourceBirthdayClosure: ((String, [UInt8]?, Zip32AccountIndex?, AccountPurpose, String, String?, BlockHeight?) async throws -> AccountUUID)?

    func importAccount(ufvk: String, seedFingerprint: [UInt8]?, zip32AccountIndex: Zip32AccountIndex?, purpose: AccountPurpose, name: String, keySource: String?, birthday: BlockHeight?) async throws -> AccountUUID {
        if let error = importAccountUfvkSeedFingerprintZip32AccountIndexPurposeNameKeySourceBirthdayThrowableError {
            throw error
        }
        importAccountUfvkSeedFingerprintZip32AccountIndexPurposeNameKeySourceBirthdayCallsCount += 1
        importAccountUfvkSeedFingerprintZip32AccountIndexPurposeNameKeySourceBirthdayReceivedArguments = (ufvk: ufvk, seedFingerprint: seedFingerprint, zip32AccountIndex: zip32AccountIndex, purpose: purpose, name: name, keySource: keySource, birthday: birthday)
        if let closure = importAccountUfvkSeedFingerprintZip32AccountIndexPurposeNameKeySourceBirthdayClosure {
            return try await closure(ufvk, seedFingerprint, zip32AccountIndex, purpose, name, keySource, birthday)
        } else {
            return importAccountUfvkSeedFingerprintZip32AccountIndexPurposeNameKeySourceBirthdayReturnValue
        }
    }

    // MARK: - fetchTxidsWithMemoContaining

    var fetchTxidsWithMemoContainingSearchTermThrowableError: Error?
    var fetchTxidsWithMemoContainingSearchTermCallsCount = 0
    var fetchTxidsWithMemoContainingSearchTermCalled: Bool {
        return fetchTxidsWithMemoContainingSearchTermCallsCount > 0
    }
    var fetchTxidsWithMemoContainingSearchTermReceivedSearchTerm: String?
    var fetchTxidsWithMemoContainingSearchTermReturnValue: [Data]!
    var fetchTxidsWithMemoContainingSearchTermClosure: ((String) async throws -> [Data])?

    func fetchTxidsWithMemoContaining(searchTerm: String) async throws -> [Data] {
        if let error = fetchTxidsWithMemoContainingSearchTermThrowableError {
            throw error
        }
        fetchTxidsWithMemoContainingSearchTermCallsCount += 1
        fetchTxidsWithMemoContainingSearchTermReceivedSearchTerm = searchTerm
        if let closure = fetchTxidsWithMemoContainingSearchTermClosure {
            return try await closure(searchTerm)
        } else {
            return fetchTxidsWithMemoContainingSearchTermReturnValue
        }
    }

    // MARK: - rescanFrom

    var rescanFromHeightThrowableError: Error?
    var rescanFromHeightCallsCount = 0
    var rescanFromHeightCalled: Bool {
        return rescanFromHeightCallsCount > 0
    }
    var rescanFromHeightReceivedHeight: BlockHeight?
    var rescanFromHeightClosure: ((BlockHeight) async throws -> Void)?

    func rescanFrom(height: BlockHeight) async throws {
        if let error = rescanFromHeightThrowableError {
            throw error
        }
        rescanFromHeightCallsCount += 1
        rescanFromHeightReceivedHeight = height
        try await rescanFromHeightClosure!(height)
    }

    // MARK: - rewind

    var rewindCallsCount = 0
    var rewindCalled: Bool {
        return rewindCallsCount > 0
    }
    var rewindReceivedPolicy: RewindPolicy?
    var rewindReturnValue: AnyPublisher<Void, Error>!
    var rewindClosure: ((RewindPolicy) -> AnyPublisher<Void, Error>)?

    func rewind(_ policy: RewindPolicy) -> AnyPublisher<Void, Error> {
        rewindCallsCount += 1
        rewindReceivedPolicy = policy
        if let closure = rewindClosure {
            return closure(policy)
        } else {
            return rewindReturnValue
        }
    }

    // MARK: - wipe

    var wipeCallsCount = 0
    var wipeCalled: Bool {
        return wipeCallsCount > 0
    }
    var wipeReturnValue: AnyPublisher<Void, Error>!
    var wipeClosure: (() -> AnyPublisher<Void, Error>)?

    func wipe() -> AnyPublisher<Void, Error> {
        wipeCallsCount += 1
        if let closure = wipeClosure {
            return closure()
        } else {
            return wipeReturnValue
        }
    }

    // MARK: - switchTo

    var switchToEndpointThrowableError: Error?
    var switchToEndpointCallsCount = 0
    var switchToEndpointCalled: Bool {
        return switchToEndpointCallsCount > 0
    }
    var switchToEndpointReceivedEndpoint: LightWalletEndpoint?
    var switchToEndpointClosure: ((LightWalletEndpoint) async throws -> Void)?

    func switchTo(endpoint: LightWalletEndpoint) async throws {
        if let error = switchToEndpointThrowableError {
            throw error
        }
        switchToEndpointCallsCount += 1
        switchToEndpointReceivedEndpoint = endpoint
        try await switchToEndpointClosure!(endpoint)
    }

    // MARK: - isSeedRelevantToAnyDerivedAccount

    var isSeedRelevantToAnyDerivedAccountSeedThrowableError: Error?
    var isSeedRelevantToAnyDerivedAccountSeedCallsCount = 0
    var isSeedRelevantToAnyDerivedAccountSeedCalled: Bool {
        return isSeedRelevantToAnyDerivedAccountSeedCallsCount > 0
    }
    var isSeedRelevantToAnyDerivedAccountSeedReceivedSeed: [UInt8]?
    var isSeedRelevantToAnyDerivedAccountSeedReturnValue: Bool!
    var isSeedRelevantToAnyDerivedAccountSeedClosure: (([UInt8]) async throws -> Bool)?

    func isSeedRelevantToAnyDerivedAccount(seed: [UInt8]) async throws -> Bool {
        if let error = isSeedRelevantToAnyDerivedAccountSeedThrowableError {
            throw error
        }
        isSeedRelevantToAnyDerivedAccountSeedCallsCount += 1
        isSeedRelevantToAnyDerivedAccountSeedReceivedSeed = seed
        if let closure = isSeedRelevantToAnyDerivedAccountSeedClosure {
            return try await closure(seed)
        } else {
            return isSeedRelevantToAnyDerivedAccountSeedReturnValue
        }
    }

    // MARK: - evaluateBestOf

    var evaluateBestOfEndpointsFetchThresholdSecondsNBlocksToFetchKServersNetworkCallsCount = 0
    var evaluateBestOfEndpointsFetchThresholdSecondsNBlocksToFetchKServersNetworkCalled: Bool {
        return evaluateBestOfEndpointsFetchThresholdSecondsNBlocksToFetchKServersNetworkCallsCount > 0
    }
    var evaluateBestOfEndpointsFetchThresholdSecondsNBlocksToFetchKServersNetworkReceivedArguments: (endpoints: [LightWalletEndpoint], fetchThresholdSeconds: Double, nBlocksToFetch: UInt64, kServers: Int, network: NetworkType)?
    var evaluateBestOfEndpointsFetchThresholdSecondsNBlocksToFetchKServersNetworkReturnValue: [LightWalletEndpoint]!
    var evaluateBestOfEndpointsFetchThresholdSecondsNBlocksToFetchKServersNetworkClosure: (([LightWalletEndpoint], Double, UInt64, Int, NetworkType) async -> [LightWalletEndpoint])?

    func evaluateBestOf(endpoints: [LightWalletEndpoint], fetchThresholdSeconds: Double, nBlocksToFetch: UInt64, kServers: Int, network: NetworkType) async -> [LightWalletEndpoint] {
        evaluateBestOfEndpointsFetchThresholdSecondsNBlocksToFetchKServersNetworkCallsCount += 1
        evaluateBestOfEndpointsFetchThresholdSecondsNBlocksToFetchKServersNetworkReceivedArguments = (endpoints: endpoints, fetchThresholdSeconds: fetchThresholdSeconds, nBlocksToFetch: nBlocksToFetch, kServers: kServers, network: network)
        if let closure = evaluateBestOfEndpointsFetchThresholdSecondsNBlocksToFetchKServersNetworkClosure {
            return await closure(endpoints, fetchThresholdSeconds, nBlocksToFetch, kServers, network)
        } else {
            return evaluateBestOfEndpointsFetchThresholdSecondsNBlocksToFetchKServersNetworkReturnValue
        }
    }

    // MARK: - estimateBirthdayHeight

    var estimateBirthdayHeightForCallsCount = 0
    var estimateBirthdayHeightForCalled: Bool {
        return estimateBirthdayHeightForCallsCount > 0
    }
    var estimateBirthdayHeightForReceivedDate: Date?
    var estimateBirthdayHeightForReturnValue: BlockHeight!
    var estimateBirthdayHeightForClosure: ((Date) -> BlockHeight)?

    func estimateBirthdayHeight(for date: Date) -> BlockHeight {
        estimateBirthdayHeightForCallsCount += 1
        estimateBirthdayHeightForReceivedDate = date
        if let closure = estimateBirthdayHeightForClosure {
            return closure(date)
        } else {
            return estimateBirthdayHeightForReturnValue
        }
    }

    // MARK: - estimateTimestamp

    var estimateTimestampForCallsCount = 0
    var estimateTimestampForCalled: Bool {
        return estimateTimestampForCallsCount > 0
    }
    var estimateTimestampForReceivedHeight: BlockHeight?
    var estimateTimestampForReturnValue: TimeInterval?
    var estimateTimestampForClosure: ((BlockHeight) -> TimeInterval?)?

    func estimateTimestamp(for height: BlockHeight) -> TimeInterval? {
        estimateTimestampForCallsCount += 1
        estimateTimestampForReceivedHeight = height
        if let closure = estimateTimestampForClosure {
            return closure(height)
        } else {
            return estimateTimestampForReturnValue
        }
    }

    // MARK: - tor

    var torEnabledThrowableError: Error?
    var torEnabledCallsCount = 0
    var torEnabledCalled: Bool {
        return torEnabledCallsCount > 0
    }
    var torEnabledReceivedEnabled: Bool?
    var torEnabledClosure: ((Bool) async throws -> Void)?

    func tor(enabled: Bool) async throws {
        if let error = torEnabledThrowableError {
            throw error
        }
        torEnabledCallsCount += 1
        torEnabledReceivedEnabled = enabled
        try await torEnabledClosure!(enabled)
    }

    // MARK: - exchangeRateOverTor

    var exchangeRateOverTorEnabledThrowableError: Error?
    var exchangeRateOverTorEnabledCallsCount = 0
    var exchangeRateOverTorEnabledCalled: Bool {
        return exchangeRateOverTorEnabledCallsCount > 0
    }
    var exchangeRateOverTorEnabledReceivedEnabled: Bool?
    var exchangeRateOverTorEnabledClosure: ((Bool) async throws -> Void)?

    func exchangeRateOverTor(enabled: Bool) async throws {
        if let error = exchangeRateOverTorEnabledThrowableError {
            throw error
        }
        exchangeRateOverTorEnabledCallsCount += 1
        exchangeRateOverTorEnabledReceivedEnabled = enabled
        try await exchangeRateOverTorEnabledClosure!(enabled)
    }

    // MARK: - isTorSuccessfullyInitialized

    var isTorSuccessfullyInitializedCallsCount = 0
    var isTorSuccessfullyInitializedCalled: Bool {
        return isTorSuccessfullyInitializedCallsCount > 0
    }
    var isTorSuccessfullyInitializedReturnValue: Bool?
    var isTorSuccessfullyInitializedClosure: (() async -> Bool?)?

    func isTorSuccessfullyInitialized() async -> Bool? {
        isTorSuccessfullyInitializedCallsCount += 1
        if let closure = isTorSuccessfullyInitializedClosure {
            return await closure()
        } else {
            return isTorSuccessfullyInitializedReturnValue
        }
    }

    // MARK: - httpRequestOverTor

    var httpRequestOverTorForRetryLimitThrowableError: Error?
    var httpRequestOverTorForRetryLimitCallsCount = 0
    var httpRequestOverTorForRetryLimitCalled: Bool {
        return httpRequestOverTorForRetryLimitCallsCount > 0
    }
    var httpRequestOverTorForRetryLimitReceivedArguments: (request: URLRequest, retryLimit: UInt8)?
    var httpRequestOverTorForRetryLimitReturnValue: (data: Data, response: HTTPURLResponse)!
    var httpRequestOverTorForRetryLimitClosure: ((URLRequest, UInt8) async throws -> (data: Data, response: HTTPURLResponse))?

    func httpRequestOverTor(for request: URLRequest, retryLimit: UInt8) async throws -> (data: Data, response: HTTPURLResponse) {
        if let error = httpRequestOverTorForRetryLimitThrowableError {
            throw error
        }
        httpRequestOverTorForRetryLimitCallsCount += 1
        httpRequestOverTorForRetryLimitReceivedArguments = (request: request, retryLimit: retryLimit)
        if let closure = httpRequestOverTorForRetryLimitClosure {
            return try await closure(request, retryLimit)
        } else {
            return httpRequestOverTorForRetryLimitReturnValue
        }
    }

    // MARK: - debugDatabase

    var debugDatabaseSqlCallsCount = 0
    var debugDatabaseSqlCalled: Bool {
        return debugDatabaseSqlCallsCount > 0
    }
    var debugDatabaseSqlReceivedSql: String?
    var debugDatabaseSqlReturnValue: String!
    var debugDatabaseSqlClosure: ((String) -> String)?

    func debugDatabase(sql: String) -> String {
        debugDatabaseSqlCallsCount += 1
        debugDatabaseSqlReceivedSql = sql
        if let closure = debugDatabaseSqlClosure {
            return closure(sql)
        } else {
            return debugDatabaseSqlReturnValue
        }
    }

    // MARK: - getTreeState

    var getTreeStateHeightThrowableError: Error?
    var getTreeStateHeightCallsCount = 0
    var getTreeStateHeightCalled: Bool {
        return getTreeStateHeightCallsCount > 0
    }
    var getTreeStateHeightReceivedHeight: UInt64?
    var getTreeStateHeightReturnValue: Data!
    var getTreeStateHeightClosure: ((UInt64) async throws -> Data)?

    func getTreeState(height: UInt64) async throws -> Data {
        if let error = getTreeStateHeightThrowableError {
            throw error
        }
        getTreeStateHeightCallsCount += 1
        getTreeStateHeightReceivedHeight = height
        if let closure = getTreeStateHeightClosure {
            return try await closure(height)
        } else {
            return getTreeStateHeightReturnValue
        }
    }

    // MARK: - getSingleUseTransparentAddress

    var getSingleUseTransparentAddressAccountUUIDThrowableError: Error?
    var getSingleUseTransparentAddressAccountUUIDCallsCount = 0
    var getSingleUseTransparentAddressAccountUUIDCalled: Bool {
        return getSingleUseTransparentAddressAccountUUIDCallsCount > 0
    }
    var getSingleUseTransparentAddressAccountUUIDReceivedAccountUUID: AccountUUID?
    var getSingleUseTransparentAddressAccountUUIDReturnValue: SingleUseTransparentAddress!
    var getSingleUseTransparentAddressAccountUUIDClosure: ((AccountUUID) async throws -> SingleUseTransparentAddress)?

    func getSingleUseTransparentAddress(accountUUID: AccountUUID) async throws -> SingleUseTransparentAddress {
        if let error = getSingleUseTransparentAddressAccountUUIDThrowableError {
            throw error
        }
        getSingleUseTransparentAddressAccountUUIDCallsCount += 1
        getSingleUseTransparentAddressAccountUUIDReceivedAccountUUID = accountUUID
        if let closure = getSingleUseTransparentAddressAccountUUIDClosure {
            return try await closure(accountUUID)
        } else {
            return getSingleUseTransparentAddressAccountUUIDReturnValue
        }
    }

    // MARK: - checkSingleUseTransparentAddresses

    var checkSingleUseTransparentAddressesAccountUUIDThrowableError: Error?
    var checkSingleUseTransparentAddressesAccountUUIDCallsCount = 0
    var checkSingleUseTransparentAddressesAccountUUIDCalled: Bool {
        return checkSingleUseTransparentAddressesAccountUUIDCallsCount > 0
    }
    var checkSingleUseTransparentAddressesAccountUUIDReceivedAccountUUID: AccountUUID?
    var checkSingleUseTransparentAddressesAccountUUIDReturnValue: TransparentAddressCheckResult!
    var checkSingleUseTransparentAddressesAccountUUIDClosure: ((AccountUUID) async throws -> TransparentAddressCheckResult)?

    func checkSingleUseTransparentAddresses(accountUUID: AccountUUID) async throws -> TransparentAddressCheckResult {
        if let error = checkSingleUseTransparentAddressesAccountUUIDThrowableError {
            throw error
        }
        checkSingleUseTransparentAddressesAccountUUIDCallsCount += 1
        checkSingleUseTransparentAddressesAccountUUIDReceivedAccountUUID = accountUUID
        if let closure = checkSingleUseTransparentAddressesAccountUUIDClosure {
            return try await closure(accountUUID)
        } else {
            return checkSingleUseTransparentAddressesAccountUUIDReturnValue
        }
    }

    // MARK: - updateTransparentAddressTransactions

    var updateTransparentAddressTransactionsAddressThrowableError: Error?
    var updateTransparentAddressTransactionsAddressCallsCount = 0
    var updateTransparentAddressTransactionsAddressCalled: Bool {
        return updateTransparentAddressTransactionsAddressCallsCount > 0
    }
    var updateTransparentAddressTransactionsAddressReceivedAddress: String?
    var updateTransparentAddressTransactionsAddressReturnValue: TransparentAddressCheckResult!
    var updateTransparentAddressTransactionsAddressClosure: ((String) async throws -> TransparentAddressCheckResult)?

    func updateTransparentAddressTransactions(address: String) async throws -> TransparentAddressCheckResult {
        if let error = updateTransparentAddressTransactionsAddressThrowableError {
            throw error
        }
        updateTransparentAddressTransactionsAddressCallsCount += 1
        updateTransparentAddressTransactionsAddressReceivedAddress = address
        if let closure = updateTransparentAddressTransactionsAddressClosure {
            return try await closure(address)
        } else {
            return updateTransparentAddressTransactionsAddressReturnValue
        }
    }

    // MARK: - fetchUTXOsBy

    var fetchUTXOsByAddressAccountUUIDThrowableError: Error?
    var fetchUTXOsByAddressAccountUUIDCallsCount = 0
    var fetchUTXOsByAddressAccountUUIDCalled: Bool {
        return fetchUTXOsByAddressAccountUUIDCallsCount > 0
    }
    var fetchUTXOsByAddressAccountUUIDReceivedArguments: (address: String, accountUUID: AccountUUID)?
    var fetchUTXOsByAddressAccountUUIDReturnValue: TransparentAddressCheckResult!
    var fetchUTXOsByAddressAccountUUIDClosure: ((String, AccountUUID) async throws -> TransparentAddressCheckResult)?

    func fetchUTXOsBy(address: String, accountUUID: AccountUUID) async throws -> TransparentAddressCheckResult {
        if let error = fetchUTXOsByAddressAccountUUIDThrowableError {
            throw error
        }
        fetchUTXOsByAddressAccountUUIDCallsCount += 1
        fetchUTXOsByAddressAccountUUIDReceivedArguments = (address: address, accountUUID: accountUUID)
        if let closure = fetchUTXOsByAddressAccountUUIDClosure {
            return try await closure(address, accountUUID)
        } else {
            return fetchUTXOsByAddressAccountUUIDReturnValue
        }
    }

    // MARK: - enhanceTransactionBy

    var enhanceTransactionByTxIdThrowableError: Error?
    var enhanceTransactionByTxIdCallsCount = 0
    var enhanceTransactionByTxIdCalled: Bool {
        return enhanceTransactionByTxIdCallsCount > 0
    }
    var enhanceTransactionByTxIdReceivedTxId: TxId?
    var enhanceTransactionByTxIdClosure: ((TxId) async throws -> Void)?

    func enhanceTransactionBy(txId: TxId) async throws {
        if let error = enhanceTransactionByTxIdThrowableError {
            throw error
        }
        enhanceTransactionByTxIdCallsCount += 1
        enhanceTransactionByTxIdReceivedTxId = txId
        try await enhanceTransactionByTxIdClosure!(txId)
    }

    // MARK: - deleteAccount

    var deleteAccountThrowableError: Error?
    var deleteAccountCallsCount = 0
    var deleteAccountCalled: Bool {
        return deleteAccountCallsCount > 0
    }
    var deleteAccountReceivedAccountUUID: AccountUUID?
    var deleteAccountClosure: ((AccountUUID) async throws -> Void)?

    func deleteAccount(_ accountUUID: AccountUUID) async throws {
        if let error = deleteAccountThrowableError {
            throw error
        }
        deleteAccountCallsCount += 1
        deleteAccountReceivedAccountUUID = accountUUID
        try await deleteAccountClosure!(accountUUID)
    }

    // MARK: - migrationAdvanceStep

    var migrationAdvanceStepAccountUUIDThrowableError: Error?
    var migrationAdvanceStepAccountUUIDCallsCount = 0
    var migrationAdvanceStepAccountUUIDCalled: Bool {
        return migrationAdvanceStepAccountUUIDCallsCount > 0
    }
    var migrationAdvanceStepAccountUUIDReceivedAccountUUID: AccountUUID?
    var migrationAdvanceStepAccountUUIDReturnValue: MigrationAdvance?
    var migrationAdvanceStepAccountUUIDClosure: ((AccountUUID) async throws -> MigrationAdvance?)?

    func migrationAdvanceStep(accountUUID: AccountUUID) async throws -> MigrationAdvance? {
        if let error = migrationAdvanceStepAccountUUIDThrowableError {
            throw error
        }
        migrationAdvanceStepAccountUUIDCallsCount += 1
        migrationAdvanceStepAccountUUIDReceivedAccountUUID = accountUUID
        if let closure = migrationAdvanceStepAccountUUIDClosure {
            return try await closure(accountUUID)
        } else {
            return migrationAdvanceStepAccountUUIDReturnValue
        }
    }

    // MARK: - migrationProgress

    var migrationProgressAccountUUIDThrowableError: Error?
    var migrationProgressAccountUUIDCallsCount = 0
    var migrationProgressAccountUUIDCalled: Bool {
        return migrationProgressAccountUUIDCallsCount > 0
    }
    var migrationProgressAccountUUIDReceivedAccountUUID: AccountUUID?
    var migrationProgressAccountUUIDReturnValue: MigrationProgress?
    var migrationProgressAccountUUIDClosure: ((AccountUUID) async throws -> MigrationProgress?)?

    func migrationProgress(accountUUID: AccountUUID) async throws -> MigrationProgress? {
        if let error = migrationProgressAccountUUIDThrowableError {
            throw error
        }
        migrationProgressAccountUUIDCallsCount += 1
        migrationProgressAccountUUIDReceivedAccountUUID = accountUUID
        if let closure = migrationProgressAccountUUIDClosure {
            return try await closure(accountUUID)
        } else {
            return migrationProgressAccountUUIDReturnValue
        }
    }

    // MARK: - proveMigrationTransactions

    var proveMigrationTransactionsAccountUUIDMaxProofsThrowableError: Error?
    var proveMigrationTransactionsAccountUUIDMaxProofsCallsCount = 0
    var proveMigrationTransactionsAccountUUIDMaxProofsCalled: Bool {
        return proveMigrationTransactionsAccountUUIDMaxProofsCallsCount > 0
    }
    var proveMigrationTransactionsAccountUUIDMaxProofsReceivedArguments: (accountUUID: AccountUUID, instruction: [MigrationProveTarget], maxProofs: Int)?
    var proveMigrationTransactionsAccountUUIDMaxProofsReturnValue: MigrationProveOutcome!
    var proveMigrationTransactionsAccountUUIDMaxProofsClosure: ((AccountUUID, [MigrationProveTarget], Int) async throws -> MigrationProveOutcome)?

    func proveMigrationTransactions(accountUUID: AccountUUID, _ instruction: [MigrationProveTarget], maxProofs: Int) async throws -> MigrationProveOutcome {
        if let error = proveMigrationTransactionsAccountUUIDMaxProofsThrowableError {
            throw error
        }
        proveMigrationTransactionsAccountUUIDMaxProofsCallsCount += 1
        proveMigrationTransactionsAccountUUIDMaxProofsReceivedArguments = (accountUUID: accountUUID, instruction: instruction, maxProofs: maxProofs)
        if let closure = proveMigrationTransactionsAccountUUIDMaxProofsClosure {
            return try await closure(accountUUID, instruction, maxProofs)
        } else {
            return proveMigrationTransactionsAccountUUIDMaxProofsReturnValue
        }
    }

    // MARK: - takeMigrationPreparation

    var takeMigrationPreparationAccountUUIDByTxidThrowableError: Error?
    var takeMigrationPreparationAccountUUIDByTxidCallsCount = 0
    var takeMigrationPreparationAccountUUIDByTxidCalled: Bool {
        return takeMigrationPreparationAccountUUIDByTxidCallsCount > 0
    }
    var takeMigrationPreparationAccountUUIDByTxidReceivedArguments: (accountUUID: AccountUUID, txid: Data)?
    var takeMigrationPreparationAccountUUIDByTxidReturnValue: PreparedMigrationTransfer!
    var takeMigrationPreparationAccountUUIDByTxidClosure: ((AccountUUID, Data) async throws -> PreparedMigrationTransfer)?

    func takeMigrationPreparation(accountUUID: AccountUUID, byTxid txid: Data) async throws -> PreparedMigrationTransfer {
        if let error = takeMigrationPreparationAccountUUIDByTxidThrowableError {
            throw error
        }
        takeMigrationPreparationAccountUUIDByTxidCallsCount += 1
        takeMigrationPreparationAccountUUIDByTxidReceivedArguments = (accountUUID: accountUUID, txid: txid)
        if let closure = takeMigrationPreparationAccountUUIDByTxidClosure {
            return try await closure(accountUUID, txid)
        } else {
            return takeMigrationPreparationAccountUUIDByTxidReturnValue
        }
    }

    // MARK: - recordMigrationPreparationBroadcast

    var recordMigrationPreparationBroadcastAccountUUIDResultThrowableError: Error?
    var recordMigrationPreparationBroadcastAccountUUIDResultCallsCount = 0
    var recordMigrationPreparationBroadcastAccountUUIDResultCalled: Bool {
        return recordMigrationPreparationBroadcastAccountUUIDResultCallsCount > 0
    }
    var recordMigrationPreparationBroadcastAccountUUIDResultReceivedArguments: (accountUUID: AccountUUID, prepared: PreparedMigrationTransfer, result: MigrationTransferResult)?
    var recordMigrationPreparationBroadcastAccountUUIDResultClosure: ((AccountUUID, PreparedMigrationTransfer, MigrationTransferResult) async throws -> Void)?

    func recordMigrationPreparationBroadcast(accountUUID: AccountUUID, _ prepared: PreparedMigrationTransfer, result: MigrationTransferResult) async throws {
        if let error = recordMigrationPreparationBroadcastAccountUUIDResultThrowableError {
            throw error
        }
        recordMigrationPreparationBroadcastAccountUUIDResultCallsCount += 1
        recordMigrationPreparationBroadcastAccountUUIDResultReceivedArguments = (accountUUID: accountUUID, prepared: prepared, result: result)
        try await recordMigrationPreparationBroadcastAccountUUIDResultClosure!(accountUUID, prepared, result)
    }

    // MARK: - migrationSyncWakeups

    var migrationSyncWakeupsAccountUUIDThrowableError: Error?
    var migrationSyncWakeupsAccountUUIDCallsCount = 0
    var migrationSyncWakeupsAccountUUIDCalled: Bool {
        return migrationSyncWakeupsAccountUUIDCallsCount > 0
    }
    var migrationSyncWakeupsAccountUUIDReceivedAccountUUID: AccountUUID?
    var migrationSyncWakeupsAccountUUIDReturnValue: [MigrationSyncWakeup]!
    var migrationSyncWakeupsAccountUUIDClosure: ((AccountUUID) async throws -> [MigrationSyncWakeup])?

    func migrationSyncWakeups(accountUUID: AccountUUID) async throws -> [MigrationSyncWakeup] {
        if let error = migrationSyncWakeupsAccountUUIDThrowableError {
            throw error
        }
        migrationSyncWakeupsAccountUUIDCallsCount += 1
        migrationSyncWakeupsAccountUUIDReceivedAccountUUID = accountUUID
        if let closure = migrationSyncWakeupsAccountUUIDClosure {
            return try await closure(accountUUID)
        } else {
            return migrationSyncWakeupsAccountUUIDReturnValue
        }
    }

    // MARK: - nextMigrationWake

    var nextMigrationWakeAccountUUIDCallsCount = 0
    var nextMigrationWakeAccountUUIDCalled: Bool {
        return nextMigrationWakeAccountUUIDCallsCount > 0
    }
    var nextMigrationWakeAccountUUIDReceivedAccountUUID: AccountUUID?
    var nextMigrationWakeAccountUUIDReturnValue: MigrationNextWork?
    var nextMigrationWakeAccountUUIDClosure: ((AccountUUID) async -> MigrationNextWork?)?

    func nextMigrationWake(accountUUID: AccountUUID) async -> MigrationNextWork? {
        nextMigrationWakeAccountUUIDCallsCount += 1
        nextMigrationWakeAccountUUIDReceivedAccountUUID = accountUUID
        if let closure = nextMigrationWakeAccountUUIDClosure {
            return await closure(accountUUID)
        } else {
            return nextMigrationWakeAccountUUIDReturnValue
        }
    }

    // MARK: - estimatedMigrationChainTip

    var estimatedMigrationChainTipThrowableError: Error?
    var estimatedMigrationChainTipCallsCount = 0
    var estimatedMigrationChainTipCalled: Bool {
        return estimatedMigrationChainTipCallsCount > 0
    }
    var estimatedMigrationChainTipReturnValue: BlockHeight!
    var estimatedMigrationChainTipClosure: (() async throws -> BlockHeight)?

    func estimatedMigrationChainTip() async throws -> BlockHeight {
        if let error = estimatedMigrationChainTipThrowableError {
            throw error
        }
        estimatedMigrationChainTipCallsCount += 1
        if let closure = estimatedMigrationChainTipClosure {
            return try await closure()
        } else {
            return estimatedMigrationChainTipReturnValue
        }
    }

    // MARK: - estimatedMigrationSecondsPerBlock

    var estimatedMigrationSecondsPerBlockThrowableError: Error?
    var estimatedMigrationSecondsPerBlockCallsCount = 0
    var estimatedMigrationSecondsPerBlockCalled: Bool {
        return estimatedMigrationSecondsPerBlockCallsCount > 0
    }
    var estimatedMigrationSecondsPerBlockReturnValue: Double!
    var estimatedMigrationSecondsPerBlockClosure: (() async throws -> Double)?

    func estimatedMigrationSecondsPerBlock() async throws -> Double {
        if let error = estimatedMigrationSecondsPerBlockThrowableError {
            throw error
        }
        estimatedMigrationSecondsPerBlockCallsCount += 1
        if let closure = estimatedMigrationSecondsPerBlockClosure {
            return try await closure()
        } else {
            return estimatedMigrationSecondsPerBlockReturnValue
        }
    }

    // MARK: - migrationTransactionStatuses

    var migrationTransactionStatusesAccountUUIDThrowableError: Error?
    var migrationTransactionStatusesAccountUUIDCallsCount = 0
    var migrationTransactionStatusesAccountUUIDCalled: Bool {
        return migrationTransactionStatusesAccountUUIDCallsCount > 0
    }
    var migrationTransactionStatusesAccountUUIDReceivedAccountUUID: AccountUUID?
    var migrationTransactionStatusesAccountUUIDReturnValue: [MigrationTransactionStatus]!
    var migrationTransactionStatusesAccountUUIDClosure: ((AccountUUID) async throws -> [MigrationTransactionStatus])?

    func migrationTransactionStatuses(accountUUID: AccountUUID) async throws -> [MigrationTransactionStatus] {
        if let error = migrationTransactionStatusesAccountUUIDThrowableError {
            throw error
        }
        migrationTransactionStatusesAccountUUIDCallsCount += 1
        migrationTransactionStatusesAccountUUIDReceivedAccountUUID = accountUUID
        if let closure = migrationTransactionStatusesAccountUUIDClosure {
            return try await closure(accountUUID)
        } else {
            return migrationTransactionStatusesAccountUUIDReturnValue
        }
    }

    // MARK: - isNoteSplitNeeded

    var isNoteSplitNeededAccountUUIDThrowableError: Error?
    var isNoteSplitNeededAccountUUIDCallsCount = 0
    var isNoteSplitNeededAccountUUIDCalled: Bool {
        return isNoteSplitNeededAccountUUIDCallsCount > 0
    }
    var isNoteSplitNeededAccountUUIDReceivedAccountUUID: AccountUUID?
    var isNoteSplitNeededAccountUUIDReturnValue: Bool!
    var isNoteSplitNeededAccountUUIDClosure: ((AccountUUID) async throws -> Bool)?

    func isNoteSplitNeeded(accountUUID: AccountUUID) async throws -> Bool {
        if let error = isNoteSplitNeededAccountUUIDThrowableError {
            throw error
        }
        isNoteSplitNeededAccountUUIDCallsCount += 1
        isNoteSplitNeededAccountUUIDReceivedAccountUUID = accountUUID
        if let closure = isNoteSplitNeededAccountUUIDClosure {
            return try await closure(accountUUID)
        } else {
            return isNoteSplitNeededAccountUUIDReturnValue
        }
    }

    // MARK: - prepareNoteSplit

    var prepareNoteSplitAccountUUIDThrowableError: Error?
    var prepareNoteSplitAccountUUIDCallsCount = 0
    var prepareNoteSplitAccountUUIDCalled: Bool {
        return prepareNoteSplitAccountUUIDCallsCount > 0
    }
    var prepareNoteSplitAccountUUIDReceivedAccountUUID: AccountUUID?
    var prepareNoteSplitAccountUUIDReturnValue: NoteSplitProposal!
    var prepareNoteSplitAccountUUIDClosure: ((AccountUUID) async throws -> NoteSplitProposal)?

    func prepareNoteSplit(accountUUID: AccountUUID) async throws -> NoteSplitProposal {
        if let error = prepareNoteSplitAccountUUIDThrowableError {
            throw error
        }
        prepareNoteSplitAccountUUIDCallsCount += 1
        prepareNoteSplitAccountUUIDReceivedAccountUUID = accountUUID
        if let closure = prepareNoteSplitAccountUUIDClosure {
            return try await closure(accountUUID)
        } else {
            return prepareNoteSplitAccountUUIDReturnValue
        }
    }

    // MARK: - submitNoteSplit

    var submitNoteSplitAccountUUIDProposalUskOptionsThrowableError: Error?
    var submitNoteSplitAccountUUIDProposalUskOptionsCallsCount = 0
    var submitNoteSplitAccountUUIDProposalUskOptionsCalled: Bool {
        return submitNoteSplitAccountUUIDProposalUskOptionsCallsCount > 0
    }
    var submitNoteSplitAccountUUIDProposalUskOptionsReceivedArguments: (accountUUID: AccountUUID, proposal: NoteSplitProposal, usk: UnifiedSpendingKey, options: MigrationNetworkPrivacyOptions)?
    var submitNoteSplitAccountUUIDProposalUskOptionsReturnValue: MigrationTransferResult!
    var submitNoteSplitAccountUUIDProposalUskOptionsClosure: ((AccountUUID, NoteSplitProposal, UnifiedSpendingKey, MigrationNetworkPrivacyOptions) async throws -> MigrationTransferResult)?

    func submitNoteSplit(accountUUID: AccountUUID, proposal: NoteSplitProposal, usk: UnifiedSpendingKey, options: MigrationNetworkPrivacyOptions) async throws -> MigrationTransferResult {
        if let error = submitNoteSplitAccountUUIDProposalUskOptionsThrowableError {
            throw error
        }
        submitNoteSplitAccountUUIDProposalUskOptionsCallsCount += 1
        submitNoteSplitAccountUUIDProposalUskOptionsReceivedArguments = (accountUUID: accountUUID, proposal: proposal, usk: usk, options: options)
        if let closure = submitNoteSplitAccountUUIDProposalUskOptionsClosure {
            return try await closure(accountUUID, proposal, usk, options)
        } else {
            return submitNoteSplitAccountUUIDProposalUskOptionsReturnValue
        }
    }

    // MARK: - proposeMigrationTransfers

    var proposeMigrationTransfersAccountUUIDThrowableError: Error?
    var proposeMigrationTransfersAccountUUIDCallsCount = 0
    var proposeMigrationTransfersAccountUUIDCalled: Bool {
        return proposeMigrationTransfersAccountUUIDCallsCount > 0
    }
    var proposeMigrationTransfersAccountUUIDReceivedAccountUUID: AccountUUID?
    var proposeMigrationTransfersAccountUUIDReturnValue: MigrationSchedule!
    var proposeMigrationTransfersAccountUUIDClosure: ((AccountUUID) async throws -> MigrationSchedule)?

    func proposeMigrationTransfers(accountUUID: AccountUUID) async throws -> MigrationSchedule {
        if let error = proposeMigrationTransfersAccountUUIDThrowableError {
            throw error
        }
        proposeMigrationTransfersAccountUUIDCallsCount += 1
        proposeMigrationTransfersAccountUUIDReceivedAccountUUID = accountUUID
        if let closure = proposeMigrationTransfersAccountUUIDClosure {
            return try await closure(accountUUID)
        } else {
            return proposeMigrationTransfersAccountUUIDReturnValue
        }
    }

    // MARK: - proposeImmediateMigration

    var proposeImmediateMigrationAccountUUIDThrowableError: Error?
    var proposeImmediateMigrationAccountUUIDCallsCount = 0
    var proposeImmediateMigrationAccountUUIDCalled: Bool {
        return proposeImmediateMigrationAccountUUIDCallsCount > 0
    }
    var proposeImmediateMigrationAccountUUIDReceivedAccountUUID: AccountUUID?
    var proposeImmediateMigrationAccountUUIDReturnValue: ImmediateMigrationProposal!
    var proposeImmediateMigrationAccountUUIDClosure: ((AccountUUID) async throws -> ImmediateMigrationProposal)?

    func proposeImmediateMigration(accountUUID: AccountUUID) async throws -> ImmediateMigrationProposal {
        if let error = proposeImmediateMigrationAccountUUIDThrowableError {
            throw error
        }
        proposeImmediateMigrationAccountUUIDCallsCount += 1
        proposeImmediateMigrationAccountUUIDReceivedAccountUUID = accountUUID
        if let closure = proposeImmediateMigrationAccountUUIDClosure {
            return try await closure(accountUUID)
        } else {
            return proposeImmediateMigrationAccountUUIDReturnValue
        }
    }

    // MARK: - recordImmediateMigration

    var recordImmediateMigrationAccountUUIDTxidThrowableError: Error?
    var recordImmediateMigrationAccountUUIDTxidCallsCount = 0
    var recordImmediateMigrationAccountUUIDTxidCalled: Bool {
        return recordImmediateMigrationAccountUUIDTxidCallsCount > 0
    }
    var recordImmediateMigrationAccountUUIDTxidReceivedArguments: (accountUUID: AccountUUID, txid: Data)?
    var recordImmediateMigrationAccountUUIDTxidClosure: ((AccountUUID, Data) async throws -> Void)?

    func recordImmediateMigration(accountUUID: AccountUUID, txid: Data) async throws {
        if let error = recordImmediateMigrationAccountUUIDTxidThrowableError {
            throw error
        }
        recordImmediateMigrationAccountUUIDTxidCallsCount += 1
        recordImmediateMigrationAccountUUIDTxidReceivedArguments = (accountUUID: accountUUID, txid: txid)
        try await recordImmediateMigrationAccountUUIDTxidClosure!(accountUUID, txid)
    }

    // MARK: - residualAfterMigration

    var residualAfterMigrationAccountUUIDThrowableError: Error?
    var residualAfterMigrationAccountUUIDCallsCount = 0
    var residualAfterMigrationAccountUUIDCalled: Bool {
        return residualAfterMigrationAccountUUIDCallsCount > 0
    }
    var residualAfterMigrationAccountUUIDReceivedAccountUUID: AccountUUID?
    var residualAfterMigrationAccountUUIDReturnValue: Zatoshi?
    var residualAfterMigrationAccountUUIDClosure: ((AccountUUID) async throws -> Zatoshi?)?

    func residualAfterMigration(accountUUID: AccountUUID) async throws -> Zatoshi? {
        if let error = residualAfterMigrationAccountUUIDThrowableError {
            throw error
        }
        residualAfterMigrationAccountUUIDCallsCount += 1
        residualAfterMigrationAccountUUIDReceivedAccountUUID = accountUUID
        if let closure = residualAfterMigrationAccountUUIDClosure {
            return try await closure(accountUUID)
        } else {
            return residualAfterMigrationAccountUUIDReturnValue
        }
    }

    // MARK: - lockMigrationResidual

    var lockMigrationResidualAccountUUIDThrowableError: Error?
    var lockMigrationResidualAccountUUIDCallsCount = 0
    var lockMigrationResidualAccountUUIDCalled: Bool {
        return lockMigrationResidualAccountUUIDCallsCount > 0
    }
    var lockMigrationResidualAccountUUIDReceivedAccountUUID: AccountUUID?
    var lockMigrationResidualAccountUUIDReturnValue: Zatoshi!
    var lockMigrationResidualAccountUUIDClosure: ((AccountUUID) async throws -> Zatoshi)?

    func lockMigrationResidual(accountUUID: AccountUUID) async throws -> Zatoshi {
        if let error = lockMigrationResidualAccountUUIDThrowableError {
            throw error
        }
        lockMigrationResidualAccountUUIDCallsCount += 1
        lockMigrationResidualAccountUUIDReceivedAccountUUID = accountUUID
        if let closure = lockMigrationResidualAccountUUIDClosure {
            return try await closure(accountUUID)
        } else {
            return lockMigrationResidualAccountUUIDReturnValue
        }
    }

    // MARK: - unlockMigrationResidual

    var unlockMigrationResidualAccountUUIDThrowableError: Error?
    var unlockMigrationResidualAccountUUIDCallsCount = 0
    var unlockMigrationResidualAccountUUIDCalled: Bool {
        return unlockMigrationResidualAccountUUIDCallsCount > 0
    }
    var unlockMigrationResidualAccountUUIDReceivedAccountUUID: AccountUUID?
    var unlockMigrationResidualAccountUUIDReturnValue: Int!
    var unlockMigrationResidualAccountUUIDClosure: ((AccountUUID) async throws -> Int)?

    func unlockMigrationResidual(accountUUID: AccountUUID) async throws -> Int {
        if let error = unlockMigrationResidualAccountUUIDThrowableError {
            throw error
        }
        unlockMigrationResidualAccountUUIDCallsCount += 1
        unlockMigrationResidualAccountUUIDReceivedAccountUUID = accountUUID
        if let closure = unlockMigrationResidualAccountUUIDClosure {
            return try await closure(accountUUID)
        } else {
            return unlockMigrationResidualAccountUUIDReturnValue
        }
    }

    // MARK: - estimateMigrationRuns

    var estimateMigrationRunsAccountUUIDThrowableError: Error?
    var estimateMigrationRunsAccountUUIDCallsCount = 0
    var estimateMigrationRunsAccountUUIDCalled: Bool {
        return estimateMigrationRunsAccountUUIDCallsCount > 0
    }
    var estimateMigrationRunsAccountUUIDReceivedAccountUUID: AccountUUID?
    var estimateMigrationRunsAccountUUIDReturnValue: MigrationRunEstimate!
    var estimateMigrationRunsAccountUUIDClosure: ((AccountUUID) async throws -> MigrationRunEstimate)?

    func estimateMigrationRuns(accountUUID: AccountUUID) async throws -> MigrationRunEstimate {
        if let error = estimateMigrationRunsAccountUUIDThrowableError {
            throw error
        }
        estimateMigrationRunsAccountUUIDCallsCount += 1
        estimateMigrationRunsAccountUUIDReceivedAccountUUID = accountUUID
        if let closure = estimateMigrationRunsAccountUUIDClosure {
            return try await closure(accountUUID)
        } else {
            return estimateMigrationRunsAccountUUIDReturnValue
        }
    }

    // MARK: - signAndStoreMigrationSchedule

    var signAndStoreMigrationScheduleAccountUUIDUskThrowableError: Error?
    var signAndStoreMigrationScheduleAccountUUIDUskCallsCount = 0
    var signAndStoreMigrationScheduleAccountUUIDUskCalled: Bool {
        return signAndStoreMigrationScheduleAccountUUIDUskCallsCount > 0
    }
    var signAndStoreMigrationScheduleAccountUUIDUskReceivedArguments: (accountUUID: AccountUUID, schedule: MigrationSchedule, usk: UnifiedSpendingKey)?
    var signAndStoreMigrationScheduleAccountUUIDUskClosure: ((AccountUUID, MigrationSchedule, UnifiedSpendingKey) async throws -> Void)?

    func signAndStoreMigrationSchedule(accountUUID: AccountUUID, _ schedule: MigrationSchedule, usk: UnifiedSpendingKey) async throws {
        if let error = signAndStoreMigrationScheduleAccountUUIDUskThrowableError {
            throw error
        }
        signAndStoreMigrationScheduleAccountUUIDUskCallsCount += 1
        signAndStoreMigrationScheduleAccountUUIDUskReceivedArguments = (accountUUID: accountUUID, schedule: schedule, usk: usk)
        try await signAndStoreMigrationScheduleAccountUUIDUskClosure!(accountUUID, schedule, usk)
    }

    // MARK: - performMigrationBroadcast

    var performMigrationBroadcastAccountUUIDOptionsThrowableError: Error?
    var performMigrationBroadcastAccountUUIDOptionsCallsCount = 0
    var performMigrationBroadcastAccountUUIDOptionsCalled: Bool {
        return performMigrationBroadcastAccountUUIDOptionsCallsCount > 0
    }
    var performMigrationBroadcastAccountUUIDOptionsReceivedArguments: (accountUUID: AccountUUID, instruction: MigrationBroadcastInstruction, options: MigrationNetworkPrivacyOptions)?
    var performMigrationBroadcastAccountUUIDOptionsReturnValue: MigrationTransferResult!
    var performMigrationBroadcastAccountUUIDOptionsClosure: ((AccountUUID, MigrationBroadcastInstruction, MigrationNetworkPrivacyOptions) async throws -> MigrationTransferResult)?

    func performMigrationBroadcast(accountUUID: AccountUUID, _ instruction: MigrationBroadcastInstruction, options: MigrationNetworkPrivacyOptions) async throws -> MigrationTransferResult {
        if let error = performMigrationBroadcastAccountUUIDOptionsThrowableError {
            throw error
        }
        performMigrationBroadcastAccountUUIDOptionsCallsCount += 1
        performMigrationBroadcastAccountUUIDOptionsReceivedArguments = (accountUUID: accountUUID, instruction: instruction, options: options)
        if let closure = performMigrationBroadcastAccountUUIDOptionsClosure {
            return try await closure(accountUUID, instruction, options)
        } else {
            return performMigrationBroadcastAccountUUIDOptionsReturnValue
        }
    }

    // MARK: - isMigrationSyncBlocked

    var isMigrationSyncBlockedCallsCount = 0
    var isMigrationSyncBlockedCalled: Bool {
        return isMigrationSyncBlockedCallsCount > 0
    }
    var isMigrationSyncBlockedReturnValue: Bool!
    var isMigrationSyncBlockedClosure: (() async -> Bool)?

    func isMigrationSyncBlocked() async -> Bool {
        isMigrationSyncBlockedCallsCount += 1
        if let closure = isMigrationSyncBlockedClosure {
            return await closure()
        } else {
            return isMigrationSyncBlockedReturnValue
        }
    }

    // MARK: - hasOverdueMigrationTransfers

    var hasOverdueMigrationTransfersAccountUUIDUseEstimatedTipThrowableError: Error?
    var hasOverdueMigrationTransfersAccountUUIDUseEstimatedTipCallsCount = 0
    var hasOverdueMigrationTransfersAccountUUIDUseEstimatedTipCalled: Bool {
        return hasOverdueMigrationTransfersAccountUUIDUseEstimatedTipCallsCount > 0
    }
    var hasOverdueMigrationTransfersAccountUUIDUseEstimatedTipReceivedArguments: (accountUUID: AccountUUID, useEstimatedTip: Bool)?
    var hasOverdueMigrationTransfersAccountUUIDUseEstimatedTipReturnValue: Bool!
    var hasOverdueMigrationTransfersAccountUUIDUseEstimatedTipClosure: ((AccountUUID, Bool) async throws -> Bool)?

    func hasOverdueMigrationTransfers(accountUUID: AccountUUID, useEstimatedTip: Bool) async throws -> Bool {
        if let error = hasOverdueMigrationTransfersAccountUUIDUseEstimatedTipThrowableError {
            throw error
        }
        hasOverdueMigrationTransfersAccountUUIDUseEstimatedTipCallsCount += 1
        hasOverdueMigrationTransfersAccountUUIDUseEstimatedTipReceivedArguments = (accountUUID: accountUUID, useEstimatedTip: useEstimatedTip)
        if let closure = hasOverdueMigrationTransfersAccountUUIDUseEstimatedTipClosure {
            return try await closure(accountUUID, useEstimatedTip)
        } else {
            return hasOverdueMigrationTransfersAccountUUIDUseEstimatedTipReturnValue
        }
    }

    // MARK: - hasInvalidMigrationTransfers

    var hasInvalidMigrationTransfersAccountUUIDThrowableError: Error?
    var hasInvalidMigrationTransfersAccountUUIDCallsCount = 0
    var hasInvalidMigrationTransfersAccountUUIDCalled: Bool {
        return hasInvalidMigrationTransfersAccountUUIDCallsCount > 0
    }
    var hasInvalidMigrationTransfersAccountUUIDReceivedAccountUUID: AccountUUID?
    var hasInvalidMigrationTransfersAccountUUIDReturnValue: Bool!
    var hasInvalidMigrationTransfersAccountUUIDClosure: ((AccountUUID) async throws -> Bool)?

    func hasInvalidMigrationTransfers(accountUUID: AccountUUID) async throws -> Bool {
        if let error = hasInvalidMigrationTransfersAccountUUIDThrowableError {
            throw error
        }
        hasInvalidMigrationTransfersAccountUUIDCallsCount += 1
        hasInvalidMigrationTransfersAccountUUIDReceivedAccountUUID = accountUUID
        if let closure = hasInvalidMigrationTransfersAccountUUIDClosure {
            return try await closure(accountUUID)
        } else {
            return hasInvalidMigrationTransfersAccountUUIDReturnValue
        }
    }

    // MARK: - restartCurrentMigrationStep

    var restartCurrentMigrationStepAccountUUIDThrowableError: Error?
    var restartCurrentMigrationStepAccountUUIDCallsCount = 0
    var restartCurrentMigrationStepAccountUUIDCalled: Bool {
        return restartCurrentMigrationStepAccountUUIDCallsCount > 0
    }
    var restartCurrentMigrationStepAccountUUIDReceivedAccountUUID: AccountUUID?
    var restartCurrentMigrationStepAccountUUIDReturnValue: MigrationSchedule!
    var restartCurrentMigrationStepAccountUUIDClosure: ((AccountUUID) async throws -> MigrationSchedule)?

    func restartCurrentMigrationStep(accountUUID: AccountUUID) async throws -> MigrationSchedule {
        if let error = restartCurrentMigrationStepAccountUUIDThrowableError {
            throw error
        }
        restartCurrentMigrationStepAccountUUIDCallsCount += 1
        restartCurrentMigrationStepAccountUUIDReceivedAccountUUID = accountUUID
        if let closure = restartCurrentMigrationStepAccountUUIDClosure {
            return try await closure(accountUUID)
        } else {
            return restartCurrentMigrationStepAccountUUIDReturnValue
        }
    }

    // MARK: - refreshStaleMigrationTransfers

    var refreshStaleMigrationTransfersAccountUUIDUskThrowableError: Error?
    var refreshStaleMigrationTransfersAccountUUIDUskCallsCount = 0
    var refreshStaleMigrationTransfersAccountUUIDUskCalled: Bool {
        return refreshStaleMigrationTransfersAccountUUIDUskCallsCount > 0
    }
    var refreshStaleMigrationTransfersAccountUUIDUskReceivedArguments: (accountUUID: AccountUUID, usk: UnifiedSpendingKey?)?
    var refreshStaleMigrationTransfersAccountUUIDUskReturnValue: MigrationSchedule!
    var refreshStaleMigrationTransfersAccountUUIDUskClosure: ((AccountUUID, UnifiedSpendingKey?) async throws -> MigrationSchedule)?

    func refreshStaleMigrationTransfers(accountUUID: AccountUUID, usk: UnifiedSpendingKey?) async throws -> MigrationSchedule {
        if let error = refreshStaleMigrationTransfersAccountUUIDUskThrowableError {
            throw error
        }
        refreshStaleMigrationTransfersAccountUUIDUskCallsCount += 1
        refreshStaleMigrationTransfersAccountUUIDUskReceivedArguments = (accountUUID: accountUUID, usk: usk)
        if let closure = refreshStaleMigrationTransfersAccountUUIDUskClosure {
            return try await closure(accountUUID, usk)
        } else {
            return refreshStaleMigrationTransfersAccountUUIDUskReturnValue
        }
    }

    // MARK: - createUnsignedNoteSplitPCZTs

    var createUnsignedNoteSplitPCZTsAccountUUIDForThrowableError: Error?
    var createUnsignedNoteSplitPCZTsAccountUUIDForCallsCount = 0
    var createUnsignedNoteSplitPCZTsAccountUUIDForCalled: Bool {
        return createUnsignedNoteSplitPCZTsAccountUUIDForCallsCount > 0
    }
    var createUnsignedNoteSplitPCZTsAccountUUIDForReceivedArguments: (accountUUID: AccountUUID, schedule: MigrationSchedule)?
    var createUnsignedNoteSplitPCZTsAccountUUIDForReturnValue: [MigrationUnsignedTransferPczt]!
    var createUnsignedNoteSplitPCZTsAccountUUIDForClosure: ((AccountUUID, MigrationSchedule) async throws -> [MigrationUnsignedTransferPczt])?

    func createUnsignedNoteSplitPCZTs(accountUUID: AccountUUID, for schedule: MigrationSchedule) async throws -> [MigrationUnsignedTransferPczt] {
        if let error = createUnsignedNoteSplitPCZTsAccountUUIDForThrowableError {
            throw error
        }
        createUnsignedNoteSplitPCZTsAccountUUIDForCallsCount += 1
        createUnsignedNoteSplitPCZTsAccountUUIDForReceivedArguments = (accountUUID: accountUUID, schedule: schedule)
        if let closure = createUnsignedNoteSplitPCZTsAccountUUIDForClosure {
            return try await closure(accountUUID, schedule)
        } else {
            return createUnsignedNoteSplitPCZTsAccountUUIDForReturnValue
        }
    }

    // MARK: - storeSignedNoteSplitPCZTs

    var storeSignedNoteSplitPCZTsAccountUUIDThrowableError: Error?
    var storeSignedNoteSplitPCZTsAccountUUIDCallsCount = 0
    var storeSignedNoteSplitPCZTsAccountUUIDCalled: Bool {
        return storeSignedNoteSplitPCZTsAccountUUIDCallsCount > 0
    }
    var storeSignedNoteSplitPCZTsAccountUUIDReceivedArguments: (accountUUID: AccountUUID, signed: [MigrationSignedTransferPczt])?
    var storeSignedNoteSplitPCZTsAccountUUIDReturnValue: PreparedMigrationTransfer!
    var storeSignedNoteSplitPCZTsAccountUUIDClosure: ((AccountUUID, [MigrationSignedTransferPczt]) async throws -> PreparedMigrationTransfer)?

    func storeSignedNoteSplitPCZTs(accountUUID: AccountUUID, _ signed: [MigrationSignedTransferPczt]) async throws -> PreparedMigrationTransfer {
        if let error = storeSignedNoteSplitPCZTsAccountUUIDThrowableError {
            throw error
        }
        storeSignedNoteSplitPCZTsAccountUUIDCallsCount += 1
        storeSignedNoteSplitPCZTsAccountUUIDReceivedArguments = (accountUUID: accountUUID, signed: signed)
        if let closure = storeSignedNoteSplitPCZTsAccountUUIDClosure {
            return try await closure(accountUUID, signed)
        } else {
            return storeSignedNoteSplitPCZTsAccountUUIDReturnValue
        }
    }

    // MARK: - createUnsignedMigrationTransferPCZTs

    var createUnsignedMigrationTransferPCZTsAccountUUIDForThrowableError: Error?
    var createUnsignedMigrationTransferPCZTsAccountUUIDForCallsCount = 0
    var createUnsignedMigrationTransferPCZTsAccountUUIDForCalled: Bool {
        return createUnsignedMigrationTransferPCZTsAccountUUIDForCallsCount > 0
    }
    var createUnsignedMigrationTransferPCZTsAccountUUIDForReceivedArguments: (accountUUID: AccountUUID, schedule: MigrationSchedule)?
    var createUnsignedMigrationTransferPCZTsAccountUUIDForReturnValue: [MigrationUnsignedTransferPczt]!
    var createUnsignedMigrationTransferPCZTsAccountUUIDForClosure: ((AccountUUID, MigrationSchedule) async throws -> [MigrationUnsignedTransferPczt])?

    func createUnsignedMigrationTransferPCZTs(accountUUID: AccountUUID, for schedule: MigrationSchedule) async throws -> [MigrationUnsignedTransferPczt] {
        if let error = createUnsignedMigrationTransferPCZTsAccountUUIDForThrowableError {
            throw error
        }
        createUnsignedMigrationTransferPCZTsAccountUUIDForCallsCount += 1
        createUnsignedMigrationTransferPCZTsAccountUUIDForReceivedArguments = (accountUUID: accountUUID, schedule: schedule)
        if let closure = createUnsignedMigrationTransferPCZTsAccountUUIDForClosure {
            return try await closure(accountUUID, schedule)
        } else {
            return createUnsignedMigrationTransferPCZTsAccountUUIDForReturnValue
        }
    }

    // MARK: - storeSignedMigrationSchedulePCZTs

    var storeSignedMigrationSchedulePCZTsAccountUUIDThrowableError: Error?
    var storeSignedMigrationSchedulePCZTsAccountUUIDCallsCount = 0
    var storeSignedMigrationSchedulePCZTsAccountUUIDCalled: Bool {
        return storeSignedMigrationSchedulePCZTsAccountUUIDCallsCount > 0
    }
    var storeSignedMigrationSchedulePCZTsAccountUUIDReceivedArguments: (accountUUID: AccountUUID, signed: [MigrationSignedTransferPczt])?
    var storeSignedMigrationSchedulePCZTsAccountUUIDClosure: ((AccountUUID, [MigrationSignedTransferPczt]) async throws -> Void)?

    func storeSignedMigrationSchedulePCZTs(accountUUID: AccountUUID, _ signed: [MigrationSignedTransferPczt]) async throws {
        if let error = storeSignedMigrationSchedulePCZTsAccountUUIDThrowableError {
            throw error
        }
        storeSignedMigrationSchedulePCZTsAccountUUIDCallsCount += 1
        storeSignedMigrationSchedulePCZTsAccountUUIDReceivedArguments = (accountUUID: accountUUID, signed: signed)
        try await storeSignedMigrationSchedulePCZTsAccountUUIDClosure!(accountUUID, signed)
    }

    // MARK: - batchMigrationPcztsForSigning

    var batchMigrationPcztsForSigningMaxActionsPerSessionThrowableError: Error?
    var batchMigrationPcztsForSigningMaxActionsPerSessionCallsCount = 0
    var batchMigrationPcztsForSigningMaxActionsPerSessionCalled: Bool {
        return batchMigrationPcztsForSigningMaxActionsPerSessionCallsCount > 0
    }
    var batchMigrationPcztsForSigningMaxActionsPerSessionReceivedArguments: (pczts: [MigrationUnsignedTransferPczt], maxActionsPerSession: Int)?
    var batchMigrationPcztsForSigningMaxActionsPerSessionReturnValue: [[MigrationUnsignedTransferPczt]]!
    var batchMigrationPcztsForSigningMaxActionsPerSessionClosure: (([MigrationUnsignedTransferPczt], Int) async throws -> [[MigrationUnsignedTransferPczt]])?

    func batchMigrationPcztsForSigning(_ pczts: [MigrationUnsignedTransferPczt], maxActionsPerSession: Int) async throws -> [[MigrationUnsignedTransferPczt]] {
        if let error = batchMigrationPcztsForSigningMaxActionsPerSessionThrowableError {
            throw error
        }
        batchMigrationPcztsForSigningMaxActionsPerSessionCallsCount += 1
        batchMigrationPcztsForSigningMaxActionsPerSessionReceivedArguments = (pczts: pczts, maxActionsPerSession: maxActionsPerSession)
        if let closure = batchMigrationPcztsForSigningMaxActionsPerSessionClosure {
            return try await closure(pczts, maxActionsPerSession)
        } else {
            return batchMigrationPcztsForSigningMaxActionsPerSessionReturnValue
        }
    }

    // MARK: - buildKeystoneSignBatchQRParts

    var buildKeystoneSignBatchQRPartsRequestIdPcztsMaxFragmentLenThrowableError: Error?
    var buildKeystoneSignBatchQRPartsRequestIdPcztsMaxFragmentLenCallsCount = 0
    var buildKeystoneSignBatchQRPartsRequestIdPcztsMaxFragmentLenCalled: Bool {
        return buildKeystoneSignBatchQRPartsRequestIdPcztsMaxFragmentLenCallsCount > 0
    }
    var buildKeystoneSignBatchQRPartsRequestIdPcztsMaxFragmentLenReceivedArguments: (requestId: Data, pczts: [MigrationUnsignedTransferPczt], maxFragmentLen: Int)?
    var buildKeystoneSignBatchQRPartsRequestIdPcztsMaxFragmentLenReturnValue: [String]!
    var buildKeystoneSignBatchQRPartsRequestIdPcztsMaxFragmentLenClosure: ((Data, [MigrationUnsignedTransferPczt], Int) async throws -> [String])?

    func buildKeystoneSignBatchQRParts(requestId: Data, pczts: [MigrationUnsignedTransferPczt], maxFragmentLen: Int) async throws -> [String] {
        if let error = buildKeystoneSignBatchQRPartsRequestIdPcztsMaxFragmentLenThrowableError {
            throw error
        }
        buildKeystoneSignBatchQRPartsRequestIdPcztsMaxFragmentLenCallsCount += 1
        buildKeystoneSignBatchQRPartsRequestIdPcztsMaxFragmentLenReceivedArguments = (requestId: requestId, pczts: pczts, maxFragmentLen: maxFragmentLen)
        if let closure = buildKeystoneSignBatchQRPartsRequestIdPcztsMaxFragmentLenClosure {
            return try await closure(requestId, pczts, maxFragmentLen)
        } else {
            return buildKeystoneSignBatchQRPartsRequestIdPcztsMaxFragmentLenReturnValue
        }
    }

    // MARK: - resetKeystoneSignBatchDecoder

    var resetKeystoneSignBatchDecoderCallsCount = 0
    var resetKeystoneSignBatchDecoderCalled: Bool {
        return resetKeystoneSignBatchDecoderCallsCount > 0
    }
    var resetKeystoneSignBatchDecoderClosure: (() async -> Void)?

    func resetKeystoneSignBatchDecoder() async {
        resetKeystoneSignBatchDecoderCallsCount += 1
        await resetKeystoneSignBatchDecoderClosure!()
    }

    // MARK: - decodeKeystoneSignBatchPart

    var decodeKeystoneSignBatchPartExpectedRequestIdThrowableError: Error?
    var decodeKeystoneSignBatchPartExpectedRequestIdCallsCount = 0
    var decodeKeystoneSignBatchPartExpectedRequestIdCalled: Bool {
        return decodeKeystoneSignBatchPartExpectedRequestIdCallsCount > 0
    }
    var decodeKeystoneSignBatchPartExpectedRequestIdReceivedArguments: (part: String, expectedRequestId: Data)?
    var decodeKeystoneSignBatchPartExpectedRequestIdReturnValue: KeystoneBatchDecodeResult!
    var decodeKeystoneSignBatchPartExpectedRequestIdClosure: ((String, Data) async throws -> KeystoneBatchDecodeResult)?

    func decodeKeystoneSignBatchPart(_ part: String, expectedRequestId: Data) async throws -> KeystoneBatchDecodeResult {
        if let error = decodeKeystoneSignBatchPartExpectedRequestIdThrowableError {
            throw error
        }
        decodeKeystoneSignBatchPartExpectedRequestIdCallsCount += 1
        decodeKeystoneSignBatchPartExpectedRequestIdReceivedArguments = (part: part, expectedRequestId: expectedRequestId)
        if let closure = decodeKeystoneSignBatchPartExpectedRequestIdClosure {
            return try await closure(part, expectedRequestId)
        } else {
            return decodeKeystoneSignBatchPartExpectedRequestIdReturnValue
        }
    }

    // MARK: - applyKeystoneBatchSignatures

    var applyKeystoneBatchSignaturesPcztsBatchSignResponseThrowableError: Error?
    var applyKeystoneBatchSignaturesPcztsBatchSignResponseCallsCount = 0
    var applyKeystoneBatchSignaturesPcztsBatchSignResponseCalled: Bool {
        return applyKeystoneBatchSignaturesPcztsBatchSignResponseCallsCount > 0
    }
    var applyKeystoneBatchSignaturesPcztsBatchSignResponseReceivedArguments: (pczts: [MigrationUnsignedTransferPczt], batchSignResponse: Data)?
    var applyKeystoneBatchSignaturesPcztsBatchSignResponseReturnValue: [MigrationSignedTransferPczt]!
    var applyKeystoneBatchSignaturesPcztsBatchSignResponseClosure: (([MigrationUnsignedTransferPczt], Data) async throws -> [MigrationSignedTransferPczt])?

    func applyKeystoneBatchSignatures(pczts: [MigrationUnsignedTransferPczt], batchSignResponse: Data) async throws -> [MigrationSignedTransferPczt] {
        if let error = applyKeystoneBatchSignaturesPcztsBatchSignResponseThrowableError {
            throw error
        }
        applyKeystoneBatchSignaturesPcztsBatchSignResponseCallsCount += 1
        applyKeystoneBatchSignaturesPcztsBatchSignResponseReceivedArguments = (pczts: pczts, batchSignResponse: batchSignResponse)
        if let closure = applyKeystoneBatchSignaturesPcztsBatchSignResponseClosure {
            return try await closure(pczts, batchSignResponse)
        } else {
            return applyKeystoneBatchSignaturesPcztsBatchSignResponseReturnValue
        }
    }

}
class TransactionRepositoryMock: TransactionRepository {


    init(
    ) {
    }

    // MARK: - closeDBConnection

    var closeDBConnectionCallsCount = 0
    var closeDBConnectionCalled: Bool {
        return closeDBConnectionCallsCount > 0
    }
    var closeDBConnectionClosure: (() -> Void)?

    func closeDBConnection() {
        closeDBConnectionCallsCount += 1
        closeDBConnectionClosure!()
    }

    // MARK: - countAll

    var countAllThrowableError: Error?
    var countAllCallsCount = 0
    var countAllCalled: Bool {
        return countAllCallsCount > 0
    }
    var countAllReturnValue: Int!
    var countAllClosure: (() async throws -> Int)?

    func countAll() async throws -> Int {
        if let error = countAllThrowableError {
            throw error
        }
        countAllCallsCount += 1
        if let closure = countAllClosure {
            return try await closure()
        } else {
            return countAllReturnValue
        }
    }

    // MARK: - countUnmined

    var countUnminedThrowableError: Error?
    var countUnminedCallsCount = 0
    var countUnminedCalled: Bool {
        return countUnminedCallsCount > 0
    }
    var countUnminedReturnValue: Int!
    var countUnminedClosure: (() async throws -> Int)?

    func countUnmined() async throws -> Int {
        if let error = countUnminedThrowableError {
            throw error
        }
        countUnminedCallsCount += 1
        if let closure = countUnminedClosure {
            return try await closure()
        } else {
            return countUnminedReturnValue
        }
    }

    // MARK: - isInitialized

    var isInitializedThrowableError: Error?
    var isInitializedCallsCount = 0
    var isInitializedCalled: Bool {
        return isInitializedCallsCount > 0
    }
    var isInitializedReturnValue: Bool!
    var isInitializedClosure: (() async throws -> Bool)?

    func isInitialized() async throws -> Bool {
        if let error = isInitializedThrowableError {
            throw error
        }
        isInitializedCallsCount += 1
        if let closure = isInitializedClosure {
            return try await closure()
        } else {
            return isInitializedReturnValue
        }
    }

    // MARK: - fetchTxidsWithMemoContaining

    var fetchTxidsWithMemoContainingSearchTermThrowableError: Error?
    var fetchTxidsWithMemoContainingSearchTermCallsCount = 0
    var fetchTxidsWithMemoContainingSearchTermCalled: Bool {
        return fetchTxidsWithMemoContainingSearchTermCallsCount > 0
    }
    var fetchTxidsWithMemoContainingSearchTermReceivedSearchTerm: String?
    var fetchTxidsWithMemoContainingSearchTermReturnValue: [Data]!
    var fetchTxidsWithMemoContainingSearchTermClosure: ((String) async throws -> [Data])?

    func fetchTxidsWithMemoContaining(searchTerm: String) async throws -> [Data] {
        if let error = fetchTxidsWithMemoContainingSearchTermThrowableError {
            throw error
        }
        fetchTxidsWithMemoContainingSearchTermCallsCount += 1
        fetchTxidsWithMemoContainingSearchTermReceivedSearchTerm = searchTerm
        if let closure = fetchTxidsWithMemoContainingSearchTermClosure {
            return try await closure(searchTerm)
        } else {
            return fetchTxidsWithMemoContainingSearchTermReturnValue
        }
    }

    // MARK: - find

    var findRawIDThrowableError: Error?
    var findRawIDCallsCount = 0
    var findRawIDCalled: Bool {
        return findRawIDCallsCount > 0
    }
    var findRawIDReceivedRawID: Data?
    var findRawIDReturnValue: ZcashTransaction.Overview!
    var findRawIDClosure: ((Data) async throws -> ZcashTransaction.Overview)?

    func find(rawID: Data) async throws -> ZcashTransaction.Overview {
        if let error = findRawIDThrowableError {
            throw error
        }
        findRawIDCallsCount += 1
        findRawIDReceivedRawID = rawID
        if let closure = findRawIDClosure {
            return try await closure(rawID)
        } else {
            return findRawIDReturnValue
        }
    }

    // MARK: - find

    var findOffsetLimitKindThrowableError: Error?
    var findOffsetLimitKindCallsCount = 0
    var findOffsetLimitKindCalled: Bool {
        return findOffsetLimitKindCallsCount > 0
    }
    var findOffsetLimitKindReceivedArguments: (offset: Int, limit: Int, kind: TransactionKind)?
    var findOffsetLimitKindReturnValue: [ZcashTransaction.Overview]!
    var findOffsetLimitKindClosure: ((Int, Int, TransactionKind) async throws -> [ZcashTransaction.Overview])?

    func find(offset: Int, limit: Int, kind: TransactionKind) async throws -> [ZcashTransaction.Overview] {
        if let error = findOffsetLimitKindThrowableError {
            throw error
        }
        findOffsetLimitKindCallsCount += 1
        findOffsetLimitKindReceivedArguments = (offset: offset, limit: limit, kind: kind)
        if let closure = findOffsetLimitKindClosure {
            return try await closure(offset, limit, kind)
        } else {
            return findOffsetLimitKindReturnValue
        }
    }

    // MARK: - find

    var findInLimitKindThrowableError: Error?
    var findInLimitKindCallsCount = 0
    var findInLimitKindCalled: Bool {
        return findInLimitKindCallsCount > 0
    }
    var findInLimitKindReceivedArguments: (range: CompactBlockRange, limit: Int, kind: TransactionKind)?
    var findInLimitKindReturnValue: [ZcashTransaction.Overview]!
    var findInLimitKindClosure: ((CompactBlockRange, Int, TransactionKind) async throws -> [ZcashTransaction.Overview])?

    func find(in range: CompactBlockRange, limit: Int, kind: TransactionKind) async throws -> [ZcashTransaction.Overview] {
        if let error = findInLimitKindThrowableError {
            throw error
        }
        findInLimitKindCallsCount += 1
        findInLimitKindReceivedArguments = (range: range, limit: limit, kind: kind)
        if let closure = findInLimitKindClosure {
            return try await closure(range, limit, kind)
        } else {
            return findInLimitKindReturnValue
        }
    }

    // MARK: - find

    var findFromLimitKindThrowableError: Error?
    var findFromLimitKindCallsCount = 0
    var findFromLimitKindCalled: Bool {
        return findFromLimitKindCallsCount > 0
    }
    var findFromLimitKindReceivedArguments: (from: ZcashTransaction.Overview, limit: Int, kind: TransactionKind)?
    var findFromLimitKindReturnValue: [ZcashTransaction.Overview]!
    var findFromLimitKindClosure: ((ZcashTransaction.Overview, Int, TransactionKind) async throws -> [ZcashTransaction.Overview])?

    func find(from: ZcashTransaction.Overview, limit: Int, kind: TransactionKind) async throws -> [ZcashTransaction.Overview] {
        if let error = findFromLimitKindThrowableError {
            throw error
        }
        findFromLimitKindCallsCount += 1
        findFromLimitKindReceivedArguments = (from: from, limit: limit, kind: kind)
        if let closure = findFromLimitKindClosure {
            return try await closure(from, limit, kind)
        } else {
            return findFromLimitKindReturnValue
        }
    }

    // MARK: - findPendingTransactions

    var findPendingTransactionsLatestHeightOffsetLimitThrowableError: Error?
    var findPendingTransactionsLatestHeightOffsetLimitCallsCount = 0
    var findPendingTransactionsLatestHeightOffsetLimitCalled: Bool {
        return findPendingTransactionsLatestHeightOffsetLimitCallsCount > 0
    }
    var findPendingTransactionsLatestHeightOffsetLimitReceivedArguments: (latestHeight: BlockHeight, offset: Int, limit: Int)?
    var findPendingTransactionsLatestHeightOffsetLimitReturnValue: [ZcashTransaction.Overview]!
    var findPendingTransactionsLatestHeightOffsetLimitClosure: ((BlockHeight, Int, Int) async throws -> [ZcashTransaction.Overview])?

    func findPendingTransactions(latestHeight: BlockHeight, offset: Int, limit: Int) async throws -> [ZcashTransaction.Overview] {
        if let error = findPendingTransactionsLatestHeightOffsetLimitThrowableError {
            throw error
        }
        findPendingTransactionsLatestHeightOffsetLimitCallsCount += 1
        findPendingTransactionsLatestHeightOffsetLimitReceivedArguments = (latestHeight: latestHeight, offset: offset, limit: limit)
        if let closure = findPendingTransactionsLatestHeightOffsetLimitClosure {
            return try await closure(latestHeight, offset, limit)
        } else {
            return findPendingTransactionsLatestHeightOffsetLimitReturnValue
        }
    }

    // MARK: - findReceived

    var findReceivedOffsetLimitThrowableError: Error?
    var findReceivedOffsetLimitCallsCount = 0
    var findReceivedOffsetLimitCalled: Bool {
        return findReceivedOffsetLimitCallsCount > 0
    }
    var findReceivedOffsetLimitReceivedArguments: (offset: Int, limit: Int)?
    var findReceivedOffsetLimitReturnValue: [ZcashTransaction.Overview]!
    var findReceivedOffsetLimitClosure: ((Int, Int) async throws -> [ZcashTransaction.Overview])?

    func findReceived(offset: Int, limit: Int) async throws -> [ZcashTransaction.Overview] {
        if let error = findReceivedOffsetLimitThrowableError {
            throw error
        }
        findReceivedOffsetLimitCallsCount += 1
        findReceivedOffsetLimitReceivedArguments = (offset: offset, limit: limit)
        if let closure = findReceivedOffsetLimitClosure {
            return try await closure(offset, limit)
        } else {
            return findReceivedOffsetLimitReturnValue
        }
    }

    // MARK: - findSent

    var findSentOffsetLimitThrowableError: Error?
    var findSentOffsetLimitCallsCount = 0
    var findSentOffsetLimitCalled: Bool {
        return findSentOffsetLimitCallsCount > 0
    }
    var findSentOffsetLimitReceivedArguments: (offset: Int, limit: Int)?
    var findSentOffsetLimitReturnValue: [ZcashTransaction.Overview]!
    var findSentOffsetLimitClosure: ((Int, Int) async throws -> [ZcashTransaction.Overview])?

    func findSent(offset: Int, limit: Int) async throws -> [ZcashTransaction.Overview] {
        if let error = findSentOffsetLimitThrowableError {
            throw error
        }
        findSentOffsetLimitCallsCount += 1
        findSentOffsetLimitReceivedArguments = (offset: offset, limit: limit)
        if let closure = findSentOffsetLimitClosure {
            return try await closure(offset, limit)
        } else {
            return findSentOffsetLimitReturnValue
        }
    }

    // MARK: - findForResubmission

    var findForResubmissionUpToThrowableError: Error?
    var findForResubmissionUpToCallsCount = 0
    var findForResubmissionUpToCalled: Bool {
        return findForResubmissionUpToCallsCount > 0
    }
    var findForResubmissionUpToReceivedUpTo: BlockHeight?
    var findForResubmissionUpToReturnValue: [ZcashTransaction.Overview]!
    var findForResubmissionUpToClosure: ((BlockHeight) async throws -> [ZcashTransaction.Overview])?

    func findForResubmission(upTo: BlockHeight) async throws -> [ZcashTransaction.Overview] {
        if let error = findForResubmissionUpToThrowableError {
            throw error
        }
        findForResubmissionUpToCallsCount += 1
        findForResubmissionUpToReceivedUpTo = upTo
        if let closure = findForResubmissionUpToClosure {
            return try await closure(upTo)
        } else {
            return findForResubmissionUpToReturnValue
        }
    }

    // MARK: - findMemos

    var findMemosForRawIDThrowableError: Error?
    var findMemosForRawIDCallsCount = 0
    var findMemosForRawIDCalled: Bool {
        return findMemosForRawIDCallsCount > 0
    }
    var findMemosForRawIDReceivedRawID: Data?
    var findMemosForRawIDReturnValue: [Memo]!
    var findMemosForRawIDClosure: ((Data) async throws -> [Memo])?

    func findMemos(for rawID: Data) async throws -> [Memo] {
        if let error = findMemosForRawIDThrowableError {
            throw error
        }
        findMemosForRawIDCallsCount += 1
        findMemosForRawIDReceivedRawID = rawID
        if let closure = findMemosForRawIDClosure {
            return try await closure(rawID)
        } else {
            return findMemosForRawIDReturnValue
        }
    }

    // MARK: - findMemos

    var findMemosForZcashTransactionThrowableError: Error?
    var findMemosForZcashTransactionCallsCount = 0
    var findMemosForZcashTransactionCalled: Bool {
        return findMemosForZcashTransactionCallsCount > 0
    }
    var findMemosForZcashTransactionReceivedTransaction: ZcashTransaction.Overview?
    var findMemosForZcashTransactionReturnValue: [Memo]!
    var findMemosForZcashTransactionClosure: ((ZcashTransaction.Overview) async throws -> [Memo])?

    func findMemos(for transaction: ZcashTransaction.Overview) async throws -> [Memo] {
        if let error = findMemosForZcashTransactionThrowableError {
            throw error
        }
        findMemosForZcashTransactionCallsCount += 1
        findMemosForZcashTransactionReceivedTransaction = transaction
        if let closure = findMemosForZcashTransactionClosure {
            return try await closure(transaction)
        } else {
            return findMemosForZcashTransactionReturnValue
        }
    }

    // MARK: - getRecipients

    var getRecipientsForThrowableError: Error?
    var getRecipientsForCallsCount = 0
    var getRecipientsForCalled: Bool {
        return getRecipientsForCallsCount > 0
    }
    var getRecipientsForReceivedRawID: Data?
    var getRecipientsForReturnValue: [TransactionRecipient]!
    var getRecipientsForClosure: ((Data) async throws -> [TransactionRecipient])?

    func getRecipients(for rawID: Data) async throws -> [TransactionRecipient] {
        if let error = getRecipientsForThrowableError {
            throw error
        }
        getRecipientsForCallsCount += 1
        getRecipientsForReceivedRawID = rawID
        if let closure = getRecipientsForClosure {
            return try await closure(rawID)
        } else {
            return getRecipientsForReturnValue
        }
    }

    // MARK: - getTransactionOutputs

    var getTransactionOutputsForThrowableError: Error?
    var getTransactionOutputsForCallsCount = 0
    var getTransactionOutputsForCalled: Bool {
        return getTransactionOutputsForCallsCount > 0
    }
    var getTransactionOutputsForReceivedRawID: Data?
    var getTransactionOutputsForReturnValue: [ZcashTransaction.Output]!
    var getTransactionOutputsForClosure: ((Data) async throws -> [ZcashTransaction.Output])?

    func getTransactionOutputs(for rawID: Data) async throws -> [ZcashTransaction.Output] {
        if let error = getTransactionOutputsForThrowableError {
            throw error
        }
        getTransactionOutputsForCallsCount += 1
        getTransactionOutputsForReceivedRawID = rawID
        if let closure = getTransactionOutputsForClosure {
            return try await closure(rawID)
        } else {
            return getTransactionOutputsForReturnValue
        }
    }

    // MARK: - debugDatabase

    var debugDatabaseSqlCallsCount = 0
    var debugDatabaseSqlCalled: Bool {
        return debugDatabaseSqlCallsCount > 0
    }
    var debugDatabaseSqlReceivedSql: String?
    var debugDatabaseSqlReturnValue: String!
    var debugDatabaseSqlClosure: ((String) -> String)?

    func debugDatabase(sql: String) -> String {
        debugDatabaseSqlCallsCount += 1
        debugDatabaseSqlReceivedSql = sql
        if let closure = debugDatabaseSqlClosure {
            return closure(sql)
        } else {
            return debugDatabaseSqlReturnValue
        }
    }

    // MARK: - unreconciledTxids

    var unreconciledTxidsThrowableError: Error?
    var unreconciledTxidsCallsCount = 0
    var unreconciledTxidsCalled: Bool {
        return unreconciledTxidsCallsCount > 0
    }
    var unreconciledTxidsReturnValue: Set<Data>!
    var unreconciledTxidsClosure: (() async throws -> Set<Data>)?

    func unreconciledTxids() async throws -> Set<Data> {
        if let error = unreconciledTxidsThrowableError {
            throw error
        }
        unreconciledTxidsCallsCount += 1
        if let closure = unreconciledTxidsClosure {
            return try await closure()
        } else {
            return unreconciledTxidsReturnValue
        }
    }

}
class UTXOFetcherMock: UTXOFetcher {


    init(
    ) {
    }

    // MARK: - fetch

    var fetchDidFetchThrowableError: Error?
    var fetchDidFetchCallsCount = 0
    var fetchDidFetchCalled: Bool {
        return fetchDidFetchCallsCount > 0
    }
    var fetchDidFetchReceivedDidFetch: ((Float) async -> Void)?
    var fetchDidFetchReturnValue: (inserted: [UnspentTransactionOutputEntity], skipped: [UnspentTransactionOutputEntity])!
    var fetchDidFetchClosure: ((@escaping (Float) async -> Void) async throws -> (inserted: [UnspentTransactionOutputEntity], skipped: [UnspentTransactionOutputEntity]))?

    func fetch(didFetch: @escaping (Float) async -> Void) async throws -> (inserted: [UnspentTransactionOutputEntity], skipped: [UnspentTransactionOutputEntity]) {
        if let error = fetchDidFetchThrowableError {
            throw error
        }
        fetchDidFetchCallsCount += 1
        fetchDidFetchReceivedDidFetch = didFetch
        if let closure = fetchDidFetchClosure {
            return try await closure(didFetch)
        } else {
            return fetchDidFetchReturnValue
        }
    }

}
class ZcashFileManagerMock: ZcashFileManager {


    init(
    ) {
    }

    // MARK: - isReadableFile

    var isReadableFileAtPathCallsCount = 0
    var isReadableFileAtPathCalled: Bool {
        return isReadableFileAtPathCallsCount > 0
    }
    var isReadableFileAtPathReceivedPath: String?
    var isReadableFileAtPathReturnValue: Bool!
    var isReadableFileAtPathClosure: ((String) -> Bool)?

    func isReadableFile(atPath path: String) -> Bool {
        isReadableFileAtPathCallsCount += 1
        isReadableFileAtPathReceivedPath = path
        if let closure = isReadableFileAtPathClosure {
            return closure(path)
        } else {
            return isReadableFileAtPathReturnValue
        }
    }

    // MARK: - removeItem

    var removeItemAtThrowableError: Error?
    var removeItemAtCallsCount = 0
    var removeItemAtCalled: Bool {
        return removeItemAtCallsCount > 0
    }
    var removeItemAtReceivedURL: URL?
    var removeItemAtClosure: ((URL) throws -> Void)?

    func removeItem(at URL: URL) throws {
        if let error = removeItemAtThrowableError {
            throw error
        }
        removeItemAtCallsCount += 1
        removeItemAtReceivedURL = URL
        try removeItemAtClosure!(URL)
    }

    // MARK: - isDeletableFile

    var isDeletableFileAtPathCallsCount = 0
    var isDeletableFileAtPathCalled: Bool {
        return isDeletableFileAtPathCallsCount > 0
    }
    var isDeletableFileAtPathReceivedPath: String?
    var isDeletableFileAtPathReturnValue: Bool!
    var isDeletableFileAtPathClosure: ((String) -> Bool)?

    func isDeletableFile(atPath path: String) -> Bool {
        isDeletableFileAtPathCallsCount += 1
        isDeletableFileAtPathReceivedPath = path
        if let closure = isDeletableFileAtPathClosure {
            return closure(path)
        } else {
            return isDeletableFileAtPathReturnValue
        }
    }

}
class ZcashRustBackendWeldingMock: ZcashRustBackendWelding {


    init(
    ) {
    }

    // MARK: - listAccounts

    var listAccountsThrowableError: Error?
    var listAccountsCallsCount = 0
    var listAccountsCalled: Bool {
        return listAccountsCallsCount > 0
    }
    var listAccountsReturnValue: [Account]!
    var listAccountsClosure: (() async throws -> [Account])?

    func listAccounts() async throws -> [Account] {
        if let error = listAccountsThrowableError {
            throw error
        }
        listAccountsCallsCount += 1
        if let closure = listAccountsClosure {
            return try await closure()
        } else {
            return listAccountsReturnValue
        }
    }

    // MARK: - importAccount

    var importAccountUfvkSeedFingerprintZip32AccountIndexTreeStateRecoverUntilPurposeNameKeySourceThrowableError: Error?
    var importAccountUfvkSeedFingerprintZip32AccountIndexTreeStateRecoverUntilPurposeNameKeySourceCallsCount = 0
    var importAccountUfvkSeedFingerprintZip32AccountIndexTreeStateRecoverUntilPurposeNameKeySourceCalled: Bool {
        return importAccountUfvkSeedFingerprintZip32AccountIndexTreeStateRecoverUntilPurposeNameKeySourceCallsCount > 0
    }
    var importAccountUfvkSeedFingerprintZip32AccountIndexTreeStateRecoverUntilPurposeNameKeySourceReceivedArguments: (ufvk: String, seedFingerprint: [UInt8]?, zip32AccountIndex: Zip32AccountIndex?, treeState: TreeState, recoverUntil: UInt32?, purpose: AccountPurpose, name: String, keySource: String?)?
    var importAccountUfvkSeedFingerprintZip32AccountIndexTreeStateRecoverUntilPurposeNameKeySourceReturnValue: AccountUUID!
    var importAccountUfvkSeedFingerprintZip32AccountIndexTreeStateRecoverUntilPurposeNameKeySourceClosure: ((String, [UInt8]?, Zip32AccountIndex?, TreeState, UInt32?, AccountPurpose, String, String?) async throws -> AccountUUID)?

    func importAccount(ufvk: String, seedFingerprint: [UInt8]?, zip32AccountIndex: Zip32AccountIndex?, treeState: TreeState, recoverUntil: UInt32?, purpose: AccountPurpose, name: String, keySource: String?) async throws -> AccountUUID {
        if let error = importAccountUfvkSeedFingerprintZip32AccountIndexTreeStateRecoverUntilPurposeNameKeySourceThrowableError {
            throw error
        }
        importAccountUfvkSeedFingerprintZip32AccountIndexTreeStateRecoverUntilPurposeNameKeySourceCallsCount += 1
        importAccountUfvkSeedFingerprintZip32AccountIndexTreeStateRecoverUntilPurposeNameKeySourceReceivedArguments = (ufvk: ufvk, seedFingerprint: seedFingerprint, zip32AccountIndex: zip32AccountIndex, treeState: treeState, recoverUntil: recoverUntil, purpose: purpose, name: name, keySource: keySource)
        if let closure = importAccountUfvkSeedFingerprintZip32AccountIndexTreeStateRecoverUntilPurposeNameKeySourceClosure {
            return try await closure(ufvk, seedFingerprint, zip32AccountIndex, treeState, recoverUntil, purpose, name, keySource)
        } else {
            return importAccountUfvkSeedFingerprintZip32AccountIndexTreeStateRecoverUntilPurposeNameKeySourceReturnValue
        }
    }

    // MARK: - createAccount

    var createAccountSeedTreeStateRecoverUntilNameKeySourceThrowableError: Error?
    var createAccountSeedTreeStateRecoverUntilNameKeySourceCallsCount = 0
    var createAccountSeedTreeStateRecoverUntilNameKeySourceCalled: Bool {
        return createAccountSeedTreeStateRecoverUntilNameKeySourceCallsCount > 0
    }
    var createAccountSeedTreeStateRecoverUntilNameKeySourceReceivedArguments: (seed: [UInt8], treeState: TreeState, recoverUntil: UInt32?, name: String, keySource: String?)?
    var createAccountSeedTreeStateRecoverUntilNameKeySourceReturnValue: UnifiedSpendingKey!
    var createAccountSeedTreeStateRecoverUntilNameKeySourceClosure: (([UInt8], TreeState, UInt32?, String, String?) async throws -> UnifiedSpendingKey)?

    func createAccount(seed: [UInt8], treeState: TreeState, recoverUntil: UInt32?, name: String, keySource: String?) async throws -> UnifiedSpendingKey {
        if let error = createAccountSeedTreeStateRecoverUntilNameKeySourceThrowableError {
            throw error
        }
        createAccountSeedTreeStateRecoverUntilNameKeySourceCallsCount += 1
        createAccountSeedTreeStateRecoverUntilNameKeySourceReceivedArguments = (seed: seed, treeState: treeState, recoverUntil: recoverUntil, name: name, keySource: keySource)
        if let closure = createAccountSeedTreeStateRecoverUntilNameKeySourceClosure {
            return try await closure(seed, treeState, recoverUntil, name, keySource)
        } else {
            return createAccountSeedTreeStateRecoverUntilNameKeySourceReturnValue
        }
    }

    // MARK: - isSeedRelevantToAnyDerivedAccount

    var isSeedRelevantToAnyDerivedAccountSeedThrowableError: Error?
    var isSeedRelevantToAnyDerivedAccountSeedCallsCount = 0
    var isSeedRelevantToAnyDerivedAccountSeedCalled: Bool {
        return isSeedRelevantToAnyDerivedAccountSeedCallsCount > 0
    }
    var isSeedRelevantToAnyDerivedAccountSeedReceivedSeed: [UInt8]?
    var isSeedRelevantToAnyDerivedAccountSeedReturnValue: Bool!
    var isSeedRelevantToAnyDerivedAccountSeedClosure: (([UInt8]) async throws -> Bool)?

    func isSeedRelevantToAnyDerivedAccount(seed: [UInt8]) async throws -> Bool {
        if let error = isSeedRelevantToAnyDerivedAccountSeedThrowableError {
            throw error
        }
        isSeedRelevantToAnyDerivedAccountSeedCallsCount += 1
        isSeedRelevantToAnyDerivedAccountSeedReceivedSeed = seed
        if let closure = isSeedRelevantToAnyDerivedAccountSeedClosure {
            return try await closure(seed)
        } else {
            return isSeedRelevantToAnyDerivedAccountSeedReturnValue
        }
    }

    // MARK: - decryptAndStoreTransaction

    var decryptAndStoreTransactionTxBytesMinedHeightThrowableError: Error?
    var decryptAndStoreTransactionTxBytesMinedHeightCallsCount = 0
    var decryptAndStoreTransactionTxBytesMinedHeightCalled: Bool {
        return decryptAndStoreTransactionTxBytesMinedHeightCallsCount > 0
    }
    var decryptAndStoreTransactionTxBytesMinedHeightReceivedArguments: (txBytes: [UInt8], minedHeight: UInt32?)?
    var decryptAndStoreTransactionTxBytesMinedHeightReturnValue: Data!
    var decryptAndStoreTransactionTxBytesMinedHeightClosure: (([UInt8], UInt32?) async throws -> Data)?

    func decryptAndStoreTransaction(txBytes: [UInt8], minedHeight: UInt32?) async throws -> Data {
        if let error = decryptAndStoreTransactionTxBytesMinedHeightThrowableError {
            throw error
        }
        decryptAndStoreTransactionTxBytesMinedHeightCallsCount += 1
        decryptAndStoreTransactionTxBytesMinedHeightReceivedArguments = (txBytes: txBytes, minedHeight: minedHeight)
        if let closure = decryptAndStoreTransactionTxBytesMinedHeightClosure {
            return try await closure(txBytes, minedHeight)
        } else {
            return decryptAndStoreTransactionTxBytesMinedHeightReturnValue
        }
    }

    // MARK: - getCurrentAddress

    var getCurrentAddressAccountUUIDThrowableError: Error?
    var getCurrentAddressAccountUUIDCallsCount = 0
    var getCurrentAddressAccountUUIDCalled: Bool {
        return getCurrentAddressAccountUUIDCallsCount > 0
    }
    var getCurrentAddressAccountUUIDReceivedAccountUUID: AccountUUID?
    var getCurrentAddressAccountUUIDReturnValue: UnifiedAddress!
    var getCurrentAddressAccountUUIDClosure: ((AccountUUID) async throws -> UnifiedAddress)?

    func getCurrentAddress(accountUUID: AccountUUID) async throws -> UnifiedAddress {
        if let error = getCurrentAddressAccountUUIDThrowableError {
            throw error
        }
        getCurrentAddressAccountUUIDCallsCount += 1
        getCurrentAddressAccountUUIDReceivedAccountUUID = accountUUID
        if let closure = getCurrentAddressAccountUUIDClosure {
            return try await closure(accountUUID)
        } else {
            return getCurrentAddressAccountUUIDReturnValue
        }
    }

    // MARK: - getNextAvailableAddress

    var getNextAvailableAddressAccountUUIDReceiverFlagsThrowableError: Error?
    var getNextAvailableAddressAccountUUIDReceiverFlagsCallsCount = 0
    var getNextAvailableAddressAccountUUIDReceiverFlagsCalled: Bool {
        return getNextAvailableAddressAccountUUIDReceiverFlagsCallsCount > 0
    }
    var getNextAvailableAddressAccountUUIDReceiverFlagsReceivedArguments: (accountUUID: AccountUUID, receiverFlags: UInt32)?
    var getNextAvailableAddressAccountUUIDReceiverFlagsReturnValue: UnifiedAddress!
    var getNextAvailableAddressAccountUUIDReceiverFlagsClosure: ((AccountUUID, UInt32) async throws -> UnifiedAddress)?

    func getNextAvailableAddress(accountUUID: AccountUUID, receiverFlags: UInt32) async throws -> UnifiedAddress {
        if let error = getNextAvailableAddressAccountUUIDReceiverFlagsThrowableError {
            throw error
        }
        getNextAvailableAddressAccountUUIDReceiverFlagsCallsCount += 1
        getNextAvailableAddressAccountUUIDReceiverFlagsReceivedArguments = (accountUUID: accountUUID, receiverFlags: receiverFlags)
        if let closure = getNextAvailableAddressAccountUUIDReceiverFlagsClosure {
            return try await closure(accountUUID, receiverFlags)
        } else {
            return getNextAvailableAddressAccountUUIDReceiverFlagsReturnValue
        }
    }

    // MARK: - getMemo

    var getMemoTxIdOutputPoolOutputIndexThrowableError: Error?
    var getMemoTxIdOutputPoolOutputIndexCallsCount = 0
    var getMemoTxIdOutputPoolOutputIndexCalled: Bool {
        return getMemoTxIdOutputPoolOutputIndexCallsCount > 0
    }
    var getMemoTxIdOutputPoolOutputIndexReceivedArguments: (txId: Data, outputPool: UInt32, outputIndex: UInt16)?
    var getMemoTxIdOutputPoolOutputIndexReturnValue: Memo?
    var getMemoTxIdOutputPoolOutputIndexClosure: ((Data, UInt32, UInt16) async throws -> Memo?)?

    func getMemo(txId: Data, outputPool: UInt32, outputIndex: UInt16) async throws -> Memo? {
        if let error = getMemoTxIdOutputPoolOutputIndexThrowableError {
            throw error
        }
        getMemoTxIdOutputPoolOutputIndexCallsCount += 1
        getMemoTxIdOutputPoolOutputIndexReceivedArguments = (txId: txId, outputPool: outputPool, outputIndex: outputIndex)
        if let closure = getMemoTxIdOutputPoolOutputIndexClosure {
            return try await closure(txId, outputPool, outputIndex)
        } else {
            return getMemoTxIdOutputPoolOutputIndexReturnValue
        }
    }

    // MARK: - getTransparentBalance

    var getTransparentBalanceAccountUUIDThrowableError: Error?
    var getTransparentBalanceAccountUUIDCallsCount = 0
    var getTransparentBalanceAccountUUIDCalled: Bool {
        return getTransparentBalanceAccountUUIDCallsCount > 0
    }
    var getTransparentBalanceAccountUUIDReceivedAccountUUID: AccountUUID?
    var getTransparentBalanceAccountUUIDReturnValue: Int64!
    var getTransparentBalanceAccountUUIDClosure: ((AccountUUID) async throws -> Int64)?

    func getTransparentBalance(accountUUID: AccountUUID) async throws -> Int64 {
        if let error = getTransparentBalanceAccountUUIDThrowableError {
            throw error
        }
        getTransparentBalanceAccountUUIDCallsCount += 1
        getTransparentBalanceAccountUUIDReceivedAccountUUID = accountUUID
        if let closure = getTransparentBalanceAccountUUIDClosure {
            return try await closure(accountUUID)
        } else {
            return getTransparentBalanceAccountUUIDReturnValue
        }
    }

    // MARK: - initDataDb

    var initDataDbSeedThrowableError: Error?
    var initDataDbSeedCallsCount = 0
    var initDataDbSeedCalled: Bool {
        return initDataDbSeedCallsCount > 0
    }
    var initDataDbSeedReceivedSeed: [UInt8]?
    var initDataDbSeedReturnValue: DbInitResult!
    var initDataDbSeedClosure: (([UInt8]?) async throws -> DbInitResult)?

    func initDataDb(seed: [UInt8]?) async throws -> DbInitResult {
        if let error = initDataDbSeedThrowableError {
            throw error
        }
        initDataDbSeedCallsCount += 1
        initDataDbSeedReceivedSeed = seed
        if let closure = initDataDbSeedClosure {
            return try await closure(seed)
        } else {
            return initDataDbSeedReturnValue
        }
    }

    // MARK: - listTransparentReceivers

    var listTransparentReceiversAccountUUIDThrowableError: Error?
    var listTransparentReceiversAccountUUIDCallsCount = 0
    var listTransparentReceiversAccountUUIDCalled: Bool {
        return listTransparentReceiversAccountUUIDCallsCount > 0
    }
    var listTransparentReceiversAccountUUIDReceivedAccountUUID: AccountUUID?
    var listTransparentReceiversAccountUUIDReturnValue: [TransparentAddress]!
    var listTransparentReceiversAccountUUIDClosure: ((AccountUUID) async throws -> [TransparentAddress])?

    func listTransparentReceivers(accountUUID: AccountUUID) async throws -> [TransparentAddress] {
        if let error = listTransparentReceiversAccountUUIDThrowableError {
            throw error
        }
        listTransparentReceiversAccountUUIDCallsCount += 1
        listTransparentReceiversAccountUUIDReceivedAccountUUID = accountUUID
        if let closure = listTransparentReceiversAccountUUIDClosure {
            return try await closure(accountUUID)
        } else {
            return listTransparentReceiversAccountUUIDReturnValue
        }
    }

    // MARK: - getVerifiedTransparentBalance

    var getVerifiedTransparentBalanceAccountUUIDThrowableError: Error?
    var getVerifiedTransparentBalanceAccountUUIDCallsCount = 0
    var getVerifiedTransparentBalanceAccountUUIDCalled: Bool {
        return getVerifiedTransparentBalanceAccountUUIDCallsCount > 0
    }
    var getVerifiedTransparentBalanceAccountUUIDReceivedAccountUUID: AccountUUID?
    var getVerifiedTransparentBalanceAccountUUIDReturnValue: Int64!
    var getVerifiedTransparentBalanceAccountUUIDClosure: ((AccountUUID) async throws -> Int64)?

    func getVerifiedTransparentBalance(accountUUID: AccountUUID) async throws -> Int64 {
        if let error = getVerifiedTransparentBalanceAccountUUIDThrowableError {
            throw error
        }
        getVerifiedTransparentBalanceAccountUUIDCallsCount += 1
        getVerifiedTransparentBalanceAccountUUIDReceivedAccountUUID = accountUUID
        if let closure = getVerifiedTransparentBalanceAccountUUIDClosure {
            return try await closure(accountUUID)
        } else {
            return getVerifiedTransparentBalanceAccountUUIDReturnValue
        }
    }

    // MARK: - rewindToHeight

    var rewindToHeightHeightThrowableError: Error?
    var rewindToHeightHeightCallsCount = 0
    var rewindToHeightHeightCalled: Bool {
        return rewindToHeightHeightCallsCount > 0
    }
    var rewindToHeightHeightReceivedHeight: BlockHeight?
    var rewindToHeightHeightReturnValue: RewindResult!
    var rewindToHeightHeightClosure: ((BlockHeight) async throws -> RewindResult)?

    func rewindToHeight(height: BlockHeight) async throws -> RewindResult {
        if let error = rewindToHeightHeightThrowableError {
            throw error
        }
        rewindToHeightHeightCallsCount += 1
        rewindToHeightHeightReceivedHeight = height
        if let closure = rewindToHeightHeightClosure {
            return try await closure(height)
        } else {
            return rewindToHeightHeightReturnValue
        }
    }

    // MARK: - truncateToChainState

    var truncateToChainStateChainStateThrowableError: Error?
    var truncateToChainStateChainStateCallsCount = 0
    var truncateToChainStateChainStateCalled: Bool {
        return truncateToChainStateChainStateCallsCount > 0
    }
    var truncateToChainStateChainStateReceivedChainState: TreeState?
    var truncateToChainStateChainStateClosure: ((TreeState) async throws -> Void)?

    func truncateToChainState(chainState: TreeState) async throws {
        if let error = truncateToChainStateChainStateThrowableError {
            throw error
        }
        truncateToChainStateChainStateCallsCount += 1
        truncateToChainStateChainStateReceivedChainState = chainState
        try await truncateToChainStateChainStateClosure!(chainState)
    }

    // MARK: - rewindCacheToHeight

    var rewindCacheToHeightHeightThrowableError: Error?
    var rewindCacheToHeightHeightCallsCount = 0
    var rewindCacheToHeightHeightCalled: Bool {
        return rewindCacheToHeightHeightCallsCount > 0
    }
    var rewindCacheToHeightHeightReceivedHeight: Int32?
    var rewindCacheToHeightHeightClosure: ((Int32) async throws -> Void)?

    func rewindCacheToHeight(height: Int32) async throws {
        if let error = rewindCacheToHeightHeightThrowableError {
            throw error
        }
        rewindCacheToHeightHeightCallsCount += 1
        rewindCacheToHeightHeightReceivedHeight = height
        try await rewindCacheToHeightHeightClosure!(height)
    }

    // MARK: - putSaplingSubtreeRoots

    var putSaplingSubtreeRootsStartIndexRootsThrowableError: Error?
    var putSaplingSubtreeRootsStartIndexRootsCallsCount = 0
    var putSaplingSubtreeRootsStartIndexRootsCalled: Bool {
        return putSaplingSubtreeRootsStartIndexRootsCallsCount > 0
    }
    var putSaplingSubtreeRootsStartIndexRootsReceivedArguments: (startIndex: UInt64, roots: [SubtreeRoot])?
    var putSaplingSubtreeRootsStartIndexRootsClosure: ((UInt64, [SubtreeRoot]) async throws -> Void)?

    func putSaplingSubtreeRoots(startIndex: UInt64, roots: [SubtreeRoot]) async throws {
        if let error = putSaplingSubtreeRootsStartIndexRootsThrowableError {
            throw error
        }
        putSaplingSubtreeRootsStartIndexRootsCallsCount += 1
        putSaplingSubtreeRootsStartIndexRootsReceivedArguments = (startIndex: startIndex, roots: roots)
        try await putSaplingSubtreeRootsStartIndexRootsClosure!(startIndex, roots)
    }

    // MARK: - putOrchardSubtreeRoots

    var putOrchardSubtreeRootsStartIndexRootsThrowableError: Error?
    var putOrchardSubtreeRootsStartIndexRootsCallsCount = 0
    var putOrchardSubtreeRootsStartIndexRootsCalled: Bool {
        return putOrchardSubtreeRootsStartIndexRootsCallsCount > 0
    }
    var putOrchardSubtreeRootsStartIndexRootsReceivedArguments: (startIndex: UInt64, roots: [SubtreeRoot])?
    var putOrchardSubtreeRootsStartIndexRootsClosure: ((UInt64, [SubtreeRoot]) async throws -> Void)?

    func putOrchardSubtreeRoots(startIndex: UInt64, roots: [SubtreeRoot]) async throws {
        if let error = putOrchardSubtreeRootsStartIndexRootsThrowableError {
            throw error
        }
        putOrchardSubtreeRootsStartIndexRootsCallsCount += 1
        putOrchardSubtreeRootsStartIndexRootsReceivedArguments = (startIndex: startIndex, roots: roots)
        try await putOrchardSubtreeRootsStartIndexRootsClosure!(startIndex, roots)
    }

    // MARK: - putIronwoodSubtreeRoots

    var putIronwoodSubtreeRootsStartIndexRootsThrowableError: Error?
    var putIronwoodSubtreeRootsStartIndexRootsCallsCount = 0
    var putIronwoodSubtreeRootsStartIndexRootsCalled: Bool {
        return putIronwoodSubtreeRootsStartIndexRootsCallsCount > 0
    }
    var putIronwoodSubtreeRootsStartIndexRootsReceivedArguments: (startIndex: UInt64, roots: [SubtreeRoot])?
    var putIronwoodSubtreeRootsStartIndexRootsClosure: ((UInt64, [SubtreeRoot]) async throws -> Void)?

    func putIronwoodSubtreeRoots(startIndex: UInt64, roots: [SubtreeRoot]) async throws {
        if let error = putIronwoodSubtreeRootsStartIndexRootsThrowableError {
            throw error
        }
        putIronwoodSubtreeRootsStartIndexRootsCallsCount += 1
        putIronwoodSubtreeRootsStartIndexRootsReceivedArguments = (startIndex: startIndex, roots: roots)
        try await putIronwoodSubtreeRootsStartIndexRootsClosure!(startIndex, roots)
    }

    // MARK: - updateChainTip

    var updateChainTipHeightThrowableError: Error?
    var updateChainTipHeightCallsCount = 0
    var updateChainTipHeightCalled: Bool {
        return updateChainTipHeightCallsCount > 0
    }
    var updateChainTipHeightReceivedHeight: Int32?
    var updateChainTipHeightClosure: ((Int32) async throws -> Void)?

    func updateChainTip(height: Int32) async throws {
        if let error = updateChainTipHeightThrowableError {
            throw error
        }
        updateChainTipHeightCallsCount += 1
        updateChainTipHeightReceivedHeight = height
        try await updateChainTipHeightClosure!(height)
    }

    // MARK: - fullyScannedHeight

    var fullyScannedHeightThrowableError: Error?
    var fullyScannedHeightCallsCount = 0
    var fullyScannedHeightCalled: Bool {
        return fullyScannedHeightCallsCount > 0
    }
    var fullyScannedHeightReturnValue: BlockHeight?
    var fullyScannedHeightClosure: (() async throws -> BlockHeight?)?

    func fullyScannedHeight() async throws -> BlockHeight? {
        if let error = fullyScannedHeightThrowableError {
            throw error
        }
        fullyScannedHeightCallsCount += 1
        if let closure = fullyScannedHeightClosure {
            return try await closure()
        } else {
            return fullyScannedHeightReturnValue
        }
    }

    // MARK: - maxScannedHeight

    var maxScannedHeightThrowableError: Error?
    var maxScannedHeightCallsCount = 0
    var maxScannedHeightCalled: Bool {
        return maxScannedHeightCallsCount > 0
    }
    var maxScannedHeightReturnValue: BlockHeight?
    var maxScannedHeightClosure: (() async throws -> BlockHeight?)?

    func maxScannedHeight() async throws -> BlockHeight? {
        if let error = maxScannedHeightThrowableError {
            throw error
        }
        maxScannedHeightCallsCount += 1
        if let closure = maxScannedHeightClosure {
            return try await closure()
        } else {
            return maxScannedHeightReturnValue
        }
    }

    // MARK: - getWalletSummary

    var getWalletSummaryThrowableError: Error?
    var getWalletSummaryCallsCount = 0
    var getWalletSummaryCalled: Bool {
        return getWalletSummaryCallsCount > 0
    }
    var getWalletSummaryReturnValue: WalletSummary?
    var getWalletSummaryClosure: (() async throws -> WalletSummary?)?

    func getWalletSummary() async throws -> WalletSummary? {
        if let error = getWalletSummaryThrowableError {
            throw error
        }
        getWalletSummaryCallsCount += 1
        if let closure = getWalletSummaryClosure {
            return try await closure()
        } else {
            return getWalletSummaryReturnValue
        }
    }

    // MARK: - suggestScanRanges

    var suggestScanRangesThrowableError: Error?
    var suggestScanRangesCallsCount = 0
    var suggestScanRangesCalled: Bool {
        return suggestScanRangesCallsCount > 0
    }
    var suggestScanRangesReturnValue: [ScanRange]!
    var suggestScanRangesClosure: (() async throws -> [ScanRange])?

    func suggestScanRanges() async throws -> [ScanRange] {
        if let error = suggestScanRangesThrowableError {
            throw error
        }
        suggestScanRangesCallsCount += 1
        if let closure = suggestScanRangesClosure {
            return try await closure()
        } else {
            return suggestScanRangesReturnValue
        }
    }

    // MARK: - scanBlocks

    var scanBlocksFromHeightFromStateLimitThrowableError: Error?
    var scanBlocksFromHeightFromStateLimitCallsCount = 0
    var scanBlocksFromHeightFromStateLimitCalled: Bool {
        return scanBlocksFromHeightFromStateLimitCallsCount > 0
    }
    var scanBlocksFromHeightFromStateLimitReceivedArguments: (fromHeight: Int32, fromState: TreeState, limit: UInt32)?
    var scanBlocksFromHeightFromStateLimitReturnValue: ScanSummary!
    var scanBlocksFromHeightFromStateLimitClosure: ((Int32, TreeState, UInt32) async throws -> ScanSummary)?

    func scanBlocks(fromHeight: Int32, fromState: TreeState, limit: UInt32) async throws -> ScanSummary {
        if let error = scanBlocksFromHeightFromStateLimitThrowableError {
            throw error
        }
        scanBlocksFromHeightFromStateLimitCallsCount += 1
        scanBlocksFromHeightFromStateLimitReceivedArguments = (fromHeight: fromHeight, fromState: fromState, limit: limit)
        if let closure = scanBlocksFromHeightFromStateLimitClosure {
            return try await closure(fromHeight, fromState, limit)
        } else {
            return scanBlocksFromHeightFromStateLimitReturnValue
        }
    }

    // MARK: - putUnspentTransparentOutput

    var putUnspentTransparentOutputTxidIndexScriptValueHeightThrowableError: Error?
    var putUnspentTransparentOutputTxidIndexScriptValueHeightCallsCount = 0
    var putUnspentTransparentOutputTxidIndexScriptValueHeightCalled: Bool {
        return putUnspentTransparentOutputTxidIndexScriptValueHeightCallsCount > 0
    }
    var putUnspentTransparentOutputTxidIndexScriptValueHeightReceivedArguments: (txid: [UInt8], index: Int, script: [UInt8], value: Int64, height: BlockHeight)?
    var putUnspentTransparentOutputTxidIndexScriptValueHeightClosure: (([UInt8], Int, [UInt8], Int64, BlockHeight) async throws -> Void)?

    func putUnspentTransparentOutput(txid: [UInt8], index: Int, script: [UInt8], value: Int64, height: BlockHeight) async throws {
        if let error = putUnspentTransparentOutputTxidIndexScriptValueHeightThrowableError {
            throw error
        }
        putUnspentTransparentOutputTxidIndexScriptValueHeightCallsCount += 1
        putUnspentTransparentOutputTxidIndexScriptValueHeightReceivedArguments = (txid: txid, index: index, script: script, value: value, height: height)
        try await putUnspentTransparentOutputTxidIndexScriptValueHeightClosure!(txid, index, script, value, height)
    }

    // MARK: - proposeTransfer

    var proposeTransferAccountUUIDToValueMemoThrowableError: Error?
    var proposeTransferAccountUUIDToValueMemoCallsCount = 0
    var proposeTransferAccountUUIDToValueMemoCalled: Bool {
        return proposeTransferAccountUUIDToValueMemoCallsCount > 0
    }
    var proposeTransferAccountUUIDToValueMemoReceivedArguments: (accountUUID: AccountUUID, address: String, value: Int64, memo: MemoBytes?)?
    var proposeTransferAccountUUIDToValueMemoReturnValue: FfiProposal!
    var proposeTransferAccountUUIDToValueMemoClosure: ((AccountUUID, String, Int64, MemoBytes?) async throws -> FfiProposal)?

    func proposeTransfer(accountUUID: AccountUUID, to address: String, value: Int64, memo: MemoBytes?) async throws -> FfiProposal {
        if let error = proposeTransferAccountUUIDToValueMemoThrowableError {
            throw error
        }
        proposeTransferAccountUUIDToValueMemoCallsCount += 1
        proposeTransferAccountUUIDToValueMemoReceivedArguments = (accountUUID: accountUUID, address: address, value: value, memo: memo)
        if let closure = proposeTransferAccountUUIDToValueMemoClosure {
            return try await closure(accountUUID, address, value, memo)
        } else {
            return proposeTransferAccountUUIDToValueMemoReturnValue
        }
    }

    // MARK: - proposeSendMaxTransfer

    var proposeSendMaxTransferAccountUUIDToMemoModeThrowableError: Error?
    var proposeSendMaxTransferAccountUUIDToMemoModeCallsCount = 0
    var proposeSendMaxTransferAccountUUIDToMemoModeCalled: Bool {
        return proposeSendMaxTransferAccountUUIDToMemoModeCallsCount > 0
    }
    var proposeSendMaxTransferAccountUUIDToMemoModeReceivedArguments: (accountUUID: AccountUUID, address: String, memo: MemoBytes?, mode: MaxSpendMode)?
    var proposeSendMaxTransferAccountUUIDToMemoModeReturnValue: FfiProposal!
    var proposeSendMaxTransferAccountUUIDToMemoModeClosure: ((AccountUUID, String, MemoBytes?, MaxSpendMode) async throws -> FfiProposal)?

    func proposeSendMaxTransfer(accountUUID: AccountUUID, to address: String, memo: MemoBytes?, mode: MaxSpendMode) async throws -> FfiProposal {
        if let error = proposeSendMaxTransferAccountUUIDToMemoModeThrowableError {
            throw error
        }
        proposeSendMaxTransferAccountUUIDToMemoModeCallsCount += 1
        proposeSendMaxTransferAccountUUIDToMemoModeReceivedArguments = (accountUUID: accountUUID, address: address, memo: memo, mode: mode)
        if let closure = proposeSendMaxTransferAccountUUIDToMemoModeClosure {
            return try await closure(accountUUID, address, memo, mode)
        } else {
            return proposeSendMaxTransferAccountUUIDToMemoModeReturnValue
        }
    }

    // MARK: - proposeOrchardToIronwoodMigration

    var proposeOrchardToIronwoodMigrationAccountUUIDThrowableError: Error?
    var proposeOrchardToIronwoodMigrationAccountUUIDCallsCount = 0
    var proposeOrchardToIronwoodMigrationAccountUUIDCalled: Bool {
        return proposeOrchardToIronwoodMigrationAccountUUIDCallsCount > 0
    }
    var proposeOrchardToIronwoodMigrationAccountUUIDReceivedAccountUUID: AccountUUID?
    var proposeOrchardToIronwoodMigrationAccountUUIDReturnValue: FfiProposal!
    var proposeOrchardToIronwoodMigrationAccountUUIDClosure: ((AccountUUID) async throws -> FfiProposal)?

    func proposeOrchardToIronwoodMigration(accountUUID: AccountUUID) async throws -> FfiProposal {
        if let error = proposeOrchardToIronwoodMigrationAccountUUIDThrowableError {
            throw error
        }
        proposeOrchardToIronwoodMigrationAccountUUIDCallsCount += 1
        proposeOrchardToIronwoodMigrationAccountUUIDReceivedAccountUUID = accountUUID
        if let closure = proposeOrchardToIronwoodMigrationAccountUUIDClosure {
            return try await closure(accountUUID)
        } else {
            return proposeOrchardToIronwoodMigrationAccountUUIDReturnValue
        }
    }

    // MARK: - proposeTransferFromURI

    var proposeTransferFromURIAccountUUIDThrowableError: Error?
    var proposeTransferFromURIAccountUUIDCallsCount = 0
    var proposeTransferFromURIAccountUUIDCalled: Bool {
        return proposeTransferFromURIAccountUUIDCallsCount > 0
    }
    var proposeTransferFromURIAccountUUIDReceivedArguments: (uri: String, accountUUID: AccountUUID)?
    var proposeTransferFromURIAccountUUIDReturnValue: FfiProposal!
    var proposeTransferFromURIAccountUUIDClosure: ((String, AccountUUID) async throws -> FfiProposal)?

    func proposeTransferFromURI(_ uri: String, accountUUID: AccountUUID) async throws -> FfiProposal {
        if let error = proposeTransferFromURIAccountUUIDThrowableError {
            throw error
        }
        proposeTransferFromURIAccountUUIDCallsCount += 1
        proposeTransferFromURIAccountUUIDReceivedArguments = (uri: uri, accountUUID: accountUUID)
        if let closure = proposeTransferFromURIAccountUUIDClosure {
            return try await closure(uri, accountUUID)
        } else {
            return proposeTransferFromURIAccountUUIDReturnValue
        }
    }

    // MARK: - proposeShielding

    var proposeShieldingAccountUUIDMemoShieldingThresholdTransparentReceiverThrowableError: Error?
    var proposeShieldingAccountUUIDMemoShieldingThresholdTransparentReceiverCallsCount = 0
    var proposeShieldingAccountUUIDMemoShieldingThresholdTransparentReceiverCalled: Bool {
        return proposeShieldingAccountUUIDMemoShieldingThresholdTransparentReceiverCallsCount > 0
    }
    var proposeShieldingAccountUUIDMemoShieldingThresholdTransparentReceiverReceivedArguments: (accountUUID: AccountUUID, memo: MemoBytes?, shieldingThreshold: Zatoshi, transparentReceiver: String?)?
    var proposeShieldingAccountUUIDMemoShieldingThresholdTransparentReceiverReturnValue: FfiProposal?
    var proposeShieldingAccountUUIDMemoShieldingThresholdTransparentReceiverClosure: ((AccountUUID, MemoBytes?, Zatoshi, String?) async throws -> FfiProposal?)?

    func proposeShielding(accountUUID: AccountUUID, memo: MemoBytes?, shieldingThreshold: Zatoshi, transparentReceiver: String?) async throws -> FfiProposal? {
        if let error = proposeShieldingAccountUUIDMemoShieldingThresholdTransparentReceiverThrowableError {
            throw error
        }
        proposeShieldingAccountUUIDMemoShieldingThresholdTransparentReceiverCallsCount += 1
        proposeShieldingAccountUUIDMemoShieldingThresholdTransparentReceiverReceivedArguments = (accountUUID: accountUUID, memo: memo, shieldingThreshold: shieldingThreshold, transparentReceiver: transparentReceiver)
        if let closure = proposeShieldingAccountUUIDMemoShieldingThresholdTransparentReceiverClosure {
            return try await closure(accountUUID, memo, shieldingThreshold, transparentReceiver)
        } else {
            return proposeShieldingAccountUUIDMemoShieldingThresholdTransparentReceiverReturnValue
        }
    }

    // MARK: - createProposedTransactions

    var createProposedTransactionsProposalUskThrowableError: Error?
    var createProposedTransactionsProposalUskCallsCount = 0
    var createProposedTransactionsProposalUskCalled: Bool {
        return createProposedTransactionsProposalUskCallsCount > 0
    }
    var createProposedTransactionsProposalUskReceivedArguments: (proposal: FfiProposal, usk: UnifiedSpendingKey)?
    var createProposedTransactionsProposalUskReturnValue: [Data]!
    var createProposedTransactionsProposalUskClosure: ((FfiProposal, UnifiedSpendingKey) async throws -> [Data])?

    func createProposedTransactions(proposal: FfiProposal, usk: UnifiedSpendingKey) async throws -> [Data] {
        if let error = createProposedTransactionsProposalUskThrowableError {
            throw error
        }
        createProposedTransactionsProposalUskCallsCount += 1
        createProposedTransactionsProposalUskReceivedArguments = (proposal: proposal, usk: usk)
        if let closure = createProposedTransactionsProposalUskClosure {
            return try await closure(proposal, usk)
        } else {
            return createProposedTransactionsProposalUskReturnValue
        }
    }

    // MARK: - getTransaction

    var getTransactionTxIdThrowableError: Error?
    var getTransactionTxIdCallsCount = 0
    var getTransactionTxIdCalled: Bool {
        return getTransactionTxIdCallsCount > 0
    }
    var getTransactionTxIdReceivedTxId: Data?
    var getTransactionTxIdReturnValue: TransactionData?
    var getTransactionTxIdClosure: ((Data) async throws -> TransactionData?)?

    func getTransaction(txId: Data) async throws -> TransactionData? {
        if let error = getTransactionTxIdThrowableError {
            throw error
        }
        getTransactionTxIdCallsCount += 1
        getTransactionTxIdReceivedTxId = txId
        if let closure = getTransactionTxIdClosure {
            return try await closure(txId)
        } else {
            return getTransactionTxIdReturnValue
        }
    }

    // MARK: - createPCZTFromProposal

    var createPCZTFromProposalAccountUUIDProposalThrowableError: Error?
    var createPCZTFromProposalAccountUUIDProposalCallsCount = 0
    var createPCZTFromProposalAccountUUIDProposalCalled: Bool {
        return createPCZTFromProposalAccountUUIDProposalCallsCount > 0
    }
    var createPCZTFromProposalAccountUUIDProposalReceivedArguments: (accountUUID: AccountUUID, proposal: FfiProposal)?
    var createPCZTFromProposalAccountUUIDProposalReturnValue: Pczt!
    var createPCZTFromProposalAccountUUIDProposalClosure: ((AccountUUID, FfiProposal) async throws -> Pczt)?

    func createPCZTFromProposal(accountUUID: AccountUUID, proposal: FfiProposal) async throws -> Pczt {
        if let error = createPCZTFromProposalAccountUUIDProposalThrowableError {
            throw error
        }
        createPCZTFromProposalAccountUUIDProposalCallsCount += 1
        createPCZTFromProposalAccountUUIDProposalReceivedArguments = (accountUUID: accountUUID, proposal: proposal)
        if let closure = createPCZTFromProposalAccountUUIDProposalClosure {
            return try await closure(accountUUID, proposal)
        } else {
            return createPCZTFromProposalAccountUUIDProposalReturnValue
        }
    }

    // MARK: - redactPCZTForSigner

    var redactPCZTForSignerPcztThrowableError: Error?
    var redactPCZTForSignerPcztCallsCount = 0
    var redactPCZTForSignerPcztCalled: Bool {
        return redactPCZTForSignerPcztCallsCount > 0
    }
    var redactPCZTForSignerPcztReceivedPczt: Pczt?
    var redactPCZTForSignerPcztReturnValue: Pczt!
    var redactPCZTForSignerPcztClosure: ((Pczt) async throws -> Pczt)?

    func redactPCZTForSigner(pczt: Pczt) async throws -> Pczt {
        if let error = redactPCZTForSignerPcztThrowableError {
            throw error
        }
        redactPCZTForSignerPcztCallsCount += 1
        redactPCZTForSignerPcztReceivedPczt = pczt
        if let closure = redactPCZTForSignerPcztClosure {
            return try await closure(pczt)
        } else {
            return redactPCZTForSignerPcztReturnValue
        }
    }

    // MARK: - PCZTRequiresSaplingProofs

    var pcztRequiresSaplingProofsPcztCallsCount = 0
    var pcztRequiresSaplingProofsPcztCalled: Bool {
        return pcztRequiresSaplingProofsPcztCallsCount > 0
    }
    var pcztRequiresSaplingProofsPcztReceivedPczt: Pczt?
    var pcztRequiresSaplingProofsPcztReturnValue: Bool!
    var pcztRequiresSaplingProofsPcztClosure: ((Pczt) async -> Bool)?

    func PCZTRequiresSaplingProofs(pczt: Pczt) async -> Bool {
        pcztRequiresSaplingProofsPcztCallsCount += 1
        pcztRequiresSaplingProofsPcztReceivedPczt = pczt
        if let closure = pcztRequiresSaplingProofsPcztClosure {
            return await closure(pczt)
        } else {
            return pcztRequiresSaplingProofsPcztReturnValue
        }
    }

    // MARK: - addProofsToPCZT

    var addProofsToPCZTPcztThrowableError: Error?
    var addProofsToPCZTPcztCallsCount = 0
    var addProofsToPCZTPcztCalled: Bool {
        return addProofsToPCZTPcztCallsCount > 0
    }
    var addProofsToPCZTPcztReceivedPczt: Pczt?
    var addProofsToPCZTPcztReturnValue: Pczt!
    var addProofsToPCZTPcztClosure: ((Pczt) async throws -> Pczt)?

    func addProofsToPCZT(pczt: Pczt) async throws -> Pczt {
        if let error = addProofsToPCZTPcztThrowableError {
            throw error
        }
        addProofsToPCZTPcztCallsCount += 1
        addProofsToPCZTPcztReceivedPczt = pczt
        if let closure = addProofsToPCZTPcztClosure {
            return try await closure(pczt)
        } else {
            return addProofsToPCZTPcztReturnValue
        }
    }

    // MARK: - extractAndStoreTxFromPCZT

    var extractAndStoreTxFromPCZTPcztWithProofsPcztWithSigsThrowableError: Error?
    var extractAndStoreTxFromPCZTPcztWithProofsPcztWithSigsCallsCount = 0
    var extractAndStoreTxFromPCZTPcztWithProofsPcztWithSigsCalled: Bool {
        return extractAndStoreTxFromPCZTPcztWithProofsPcztWithSigsCallsCount > 0
    }
    var extractAndStoreTxFromPCZTPcztWithProofsPcztWithSigsReceivedArguments: (pcztWithProofs: Pczt, pcztWithSigs: Pczt)?
    var extractAndStoreTxFromPCZTPcztWithProofsPcztWithSigsReturnValue: Data!
    var extractAndStoreTxFromPCZTPcztWithProofsPcztWithSigsClosure: ((Pczt, Pczt) async throws -> Data)?

    func extractAndStoreTxFromPCZT(pcztWithProofs: Pczt, pcztWithSigs: Pczt) async throws -> Data {
        if let error = extractAndStoreTxFromPCZTPcztWithProofsPcztWithSigsThrowableError {
            throw error
        }
        extractAndStoreTxFromPCZTPcztWithProofsPcztWithSigsCallsCount += 1
        extractAndStoreTxFromPCZTPcztWithProofsPcztWithSigsReceivedArguments = (pcztWithProofs: pcztWithProofs, pcztWithSigs: pcztWithSigs)
        if let closure = extractAndStoreTxFromPCZTPcztWithProofsPcztWithSigsClosure {
            return try await closure(pcztWithProofs, pcztWithSigs)
        } else {
            return extractAndStoreTxFromPCZTPcztWithProofsPcztWithSigsReturnValue
        }
    }

    // MARK: - consensusBranchIdFor

    var consensusBranchIdForHeightThrowableError: Error?
    var consensusBranchIdForHeightCallsCount = 0
    var consensusBranchIdForHeightCalled: Bool {
        return consensusBranchIdForHeightCallsCount > 0
    }
    var consensusBranchIdForHeightReceivedHeight: Int32?
    var consensusBranchIdForHeightReturnValue: Int32!
    var consensusBranchIdForHeightClosure: ((Int32) throws -> Int32)?

    func consensusBranchIdFor(height: Int32) throws -> Int32 {
        if let error = consensusBranchIdForHeightThrowableError {
            throw error
        }
        consensusBranchIdForHeightCallsCount += 1
        consensusBranchIdForHeightReceivedHeight = height
        if let closure = consensusBranchIdForHeightClosure {
            return try closure(height)
        } else {
            return consensusBranchIdForHeightReturnValue
        }
    }

    // MARK: - initBlockMetadataDb

    var initBlockMetadataDbThrowableError: Error?
    var initBlockMetadataDbCallsCount = 0
    var initBlockMetadataDbCalled: Bool {
        return initBlockMetadataDbCallsCount > 0
    }
    var initBlockMetadataDbClosure: (() async throws -> Void)?

    func initBlockMetadataDb() async throws {
        if let error = initBlockMetadataDbThrowableError {
            throw error
        }
        initBlockMetadataDbCallsCount += 1
        try await initBlockMetadataDbClosure!()
    }

    // MARK: - writeBlocksMetadata

    var writeBlocksMetadataBlocksThrowableError: Error?
    var writeBlocksMetadataBlocksCallsCount = 0
    var writeBlocksMetadataBlocksCalled: Bool {
        return writeBlocksMetadataBlocksCallsCount > 0
    }
    var writeBlocksMetadataBlocksReceivedBlocks: [ZcashCompactBlock]?
    var writeBlocksMetadataBlocksClosure: (([ZcashCompactBlock]) async throws -> Void)?

    func writeBlocksMetadata(blocks: [ZcashCompactBlock]) async throws {
        if let error = writeBlocksMetadataBlocksThrowableError {
            throw error
        }
        writeBlocksMetadataBlocksCallsCount += 1
        writeBlocksMetadataBlocksReceivedBlocks = blocks
        try await writeBlocksMetadataBlocksClosure!(blocks)
    }

    // MARK: - latestCachedBlockHeight

    var latestCachedBlockHeightThrowableError: Error?
    var latestCachedBlockHeightCallsCount = 0
    var latestCachedBlockHeightCalled: Bool {
        return latestCachedBlockHeightCallsCount > 0
    }
    var latestCachedBlockHeightReturnValue: BlockHeight!
    var latestCachedBlockHeightClosure: (() async throws -> BlockHeight)?

    func latestCachedBlockHeight() async throws -> BlockHeight {
        if let error = latestCachedBlockHeightThrowableError {
            throw error
        }
        latestCachedBlockHeightCallsCount += 1
        if let closure = latestCachedBlockHeightClosure {
            return try await closure()
        } else {
            return latestCachedBlockHeightReturnValue
        }
    }

    // MARK: - transactionDataRequests

    var transactionDataRequestsThrowableError: Error?
    var transactionDataRequestsCallsCount = 0
    var transactionDataRequestsCalled: Bool {
        return transactionDataRequestsCallsCount > 0
    }
    var transactionDataRequestsReturnValue: [TransactionDataRequest]!
    var transactionDataRequestsClosure: (() async throws -> [TransactionDataRequest])?

    func transactionDataRequests() async throws -> [TransactionDataRequest] {
        if let error = transactionDataRequestsThrowableError {
            throw error
        }
        transactionDataRequestsCallsCount += 1
        if let closure = transactionDataRequestsClosure {
            return try await closure()
        } else {
            return transactionDataRequestsReturnValue
        }
    }

    // MARK: - setTransactionStatus

    var setTransactionStatusTxIdStatusThrowableError: Error?
    var setTransactionStatusTxIdStatusCallsCount = 0
    var setTransactionStatusTxIdStatusCalled: Bool {
        return setTransactionStatusTxIdStatusCallsCount > 0
    }
    var setTransactionStatusTxIdStatusReceivedArguments: (txId: Data, status: TransactionStatus)?
    var setTransactionStatusTxIdStatusClosure: ((Data, TransactionStatus) async throws -> Void)?

    func setTransactionStatus(txId: Data, status: TransactionStatus) async throws {
        if let error = setTransactionStatusTxIdStatusThrowableError {
            throw error
        }
        setTransactionStatusTxIdStatusCallsCount += 1
        setTransactionStatusTxIdStatusReceivedArguments = (txId: txId, status: status)
        try await setTransactionStatusTxIdStatusClosure!(txId, status)
    }

    // MARK: - fixWitnesses

    var fixWitnessesCallsCount = 0
    var fixWitnessesCalled: Bool {
        return fixWitnessesCallsCount > 0
    }
    var fixWitnessesClosure: (() async -> Void)?

    func fixWitnesses() async {
        fixWitnessesCallsCount += 1
        await fixWitnessesClosure!()
    }

    // MARK: - getSingleUseTransparentAddress

    var getSingleUseTransparentAddressAccountUUIDThrowableError: Error?
    var getSingleUseTransparentAddressAccountUUIDCallsCount = 0
    var getSingleUseTransparentAddressAccountUUIDCalled: Bool {
        return getSingleUseTransparentAddressAccountUUIDCallsCount > 0
    }
    var getSingleUseTransparentAddressAccountUUIDReceivedAccountUUID: AccountUUID?
    var getSingleUseTransparentAddressAccountUUIDReturnValue: SingleUseTransparentAddress!
    var getSingleUseTransparentAddressAccountUUIDClosure: ((AccountUUID) async throws -> SingleUseTransparentAddress)?

    func getSingleUseTransparentAddress(accountUUID: AccountUUID) async throws -> SingleUseTransparentAddress {
        if let error = getSingleUseTransparentAddressAccountUUIDThrowableError {
            throw error
        }
        getSingleUseTransparentAddressAccountUUIDCallsCount += 1
        getSingleUseTransparentAddressAccountUUIDReceivedAccountUUID = accountUUID
        if let closure = getSingleUseTransparentAddressAccountUUIDClosure {
            return try await closure(accountUUID)
        } else {
            return getSingleUseTransparentAddressAccountUUIDReturnValue
        }
    }

    // MARK: - deleteAccount

    var deleteAccountThrowableError: Error?
    var deleteAccountCallsCount = 0
    var deleteAccountCalled: Bool {
        return deleteAccountCallsCount > 0
    }
    var deleteAccountReceivedAccountUUID: AccountUUID?
    var deleteAccountClosure: ((AccountUUID) async throws -> Void)?

    func deleteAccount(_ accountUUID: AccountUUID) async throws {
        if let error = deleteAccountThrowableError {
            throw error
        }
        deleteAccountCallsCount += 1
        deleteAccountReceivedAccountUUID = accountUUID
        try await deleteAccountClosure!(accountUUID)
    }

    // MARK: - migrationAdvanceStep

    var migrationAdvanceStepForThrowableError: Error?
    var migrationAdvanceStepForCallsCount = 0
    var migrationAdvanceStepForCalled: Bool {
        return migrationAdvanceStepForCallsCount > 0
    }
    var migrationAdvanceStepForReceivedAccount: AccountUUID?
    var migrationAdvanceStepForReturnValue: MigrationAdvance?
    var migrationAdvanceStepForClosure: ((AccountUUID) async throws -> MigrationAdvance?)?

    func migrationAdvanceStep(for account: AccountUUID) async throws -> MigrationAdvance? {
        if let error = migrationAdvanceStepForThrowableError {
            throw error
        }
        migrationAdvanceStepForCallsCount += 1
        migrationAdvanceStepForReceivedAccount = account
        if let closure = migrationAdvanceStepForClosure {
            return try await closure(account)
        } else {
            return migrationAdvanceStepForReturnValue
        }
    }

    // MARK: - migrationAdvanceStep

    var migrationAdvanceStepForEstimatedTipThrowableError: Error?
    var migrationAdvanceStepForEstimatedTipCallsCount = 0
    var migrationAdvanceStepForEstimatedTipCalled: Bool {
        return migrationAdvanceStepForEstimatedTipCallsCount > 0
    }
    var migrationAdvanceStepForEstimatedTipReceivedArguments: (account: AccountUUID, estimatedTip: BlockHeight?)?
    var migrationAdvanceStepForEstimatedTipReturnValue: MigrationAdvance?
    var migrationAdvanceStepForEstimatedTipClosure: ((AccountUUID, BlockHeight?) async throws -> MigrationAdvance?)?

    func migrationAdvanceStep(for account: AccountUUID, estimatedTip: BlockHeight?) async throws -> MigrationAdvance? {
        if let error = migrationAdvanceStepForEstimatedTipThrowableError {
            throw error
        }
        migrationAdvanceStepForEstimatedTipCallsCount += 1
        migrationAdvanceStepForEstimatedTipReceivedArguments = (account: account, estimatedTip: estimatedTip)
        if let closure = migrationAdvanceStepForEstimatedTipClosure {
            return try await closure(account, estimatedTip)
        } else {
            return migrationAdvanceStepForEstimatedTipReturnValue
        }
    }

    // MARK: - migrationProgress

    var migrationProgressForThrowableError: Error?
    var migrationProgressForCallsCount = 0
    var migrationProgressForCalled: Bool {
        return migrationProgressForCallsCount > 0
    }
    var migrationProgressForReceivedAccount: AccountUUID?
    var migrationProgressForReturnValue: MigrationProgress?
    var migrationProgressForClosure: ((AccountUUID) async throws -> MigrationProgress?)?

    func migrationProgress(for account: AccountUUID) async throws -> MigrationProgress? {
        if let error = migrationProgressForThrowableError {
            throw error
        }
        migrationProgressForCallsCount += 1
        migrationProgressForReceivedAccount = account
        if let closure = migrationProgressForClosure {
            return try await closure(account)
        } else {
            return migrationProgressForReturnValue
        }
    }

    // MARK: - migrationSyncWakeups

    var migrationSyncWakeupsForThrowableError: Error?
    var migrationSyncWakeupsForCallsCount = 0
    var migrationSyncWakeupsForCalled: Bool {
        return migrationSyncWakeupsForCallsCount > 0
    }
    var migrationSyncWakeupsForReceivedAccount: AccountUUID?
    var migrationSyncWakeupsForReturnValue: [MigrationSyncWakeup]!
    var migrationSyncWakeupsForClosure: ((AccountUUID) async throws -> [MigrationSyncWakeup])?

    func migrationSyncWakeups(for account: AccountUUID) async throws -> [MigrationSyncWakeup] {
        if let error = migrationSyncWakeupsForThrowableError {
            throw error
        }
        migrationSyncWakeupsForCallsCount += 1
        migrationSyncWakeupsForReceivedAccount = account
        if let closure = migrationSyncWakeupsForClosure {
            return try await closure(account)
        } else {
            return migrationSyncWakeupsForReturnValue
        }
    }

    // MARK: - migrationBlockRateSamples

    var migrationBlockRateSamplesWindowThrowableError: Error?
    var migrationBlockRateSamplesWindowCallsCount = 0
    var migrationBlockRateSamplesWindowCalled: Bool {
        return migrationBlockRateSamplesWindowCallsCount > 0
    }
    var migrationBlockRateSamplesWindowReceivedWindow: UInt32?
    var migrationBlockRateSamplesWindowReturnValue: [MigrationBlockRateSample]!
    var migrationBlockRateSamplesWindowClosure: ((UInt32) async throws -> [MigrationBlockRateSample])?

    func migrationBlockRateSamples(window: UInt32) async throws -> [MigrationBlockRateSample] {
        if let error = migrationBlockRateSamplesWindowThrowableError {
            throw error
        }
        migrationBlockRateSamplesWindowCallsCount += 1
        migrationBlockRateSamplesWindowReceivedWindow = window
        if let closure = migrationBlockRateSamplesWindowClosure {
            return try await closure(window)
        } else {
            return migrationBlockRateSamplesWindowReturnValue
        }
    }

    // MARK: - migrationBatchPcztsByActions

    var migrationBatchPcztsByActionsActionsMaxActionsPerSessionThrowableError: Error?
    var migrationBatchPcztsByActionsActionsMaxActionsPerSessionCallsCount = 0
    var migrationBatchPcztsByActionsActionsMaxActionsPerSessionCalled: Bool {
        return migrationBatchPcztsByActionsActionsMaxActionsPerSessionCallsCount > 0
    }
    var migrationBatchPcztsByActionsActionsMaxActionsPerSessionReceivedArguments: (actions: [UInt32], maxActionsPerSession: Int)?
    var migrationBatchPcztsByActionsActionsMaxActionsPerSessionReturnValue: [Int]!
    var migrationBatchPcztsByActionsActionsMaxActionsPerSessionClosure: (([UInt32], Int) async throws -> [Int])?

    func migrationBatchPcztsByActions(actions: [UInt32], maxActionsPerSession: Int) async throws -> [Int] {
        if let error = migrationBatchPcztsByActionsActionsMaxActionsPerSessionThrowableError {
            throw error
        }
        migrationBatchPcztsByActionsActionsMaxActionsPerSessionCallsCount += 1
        migrationBatchPcztsByActionsActionsMaxActionsPerSessionReceivedArguments = (actions: actions, maxActionsPerSession: maxActionsPerSession)
        if let closure = migrationBatchPcztsByActionsActionsMaxActionsPerSessionClosure {
            return try await closure(actions, maxActionsPerSession)
        } else {
            return migrationBatchPcztsByActionsActionsMaxActionsPerSessionReturnValue
        }
    }

    // MARK: - migrationTransactionStatuses

    var migrationTransactionStatusesForThrowableError: Error?
    var migrationTransactionStatusesForCallsCount = 0
    var migrationTransactionStatusesForCalled: Bool {
        return migrationTransactionStatusesForCallsCount > 0
    }
    var migrationTransactionStatusesForReceivedAccount: AccountUUID?
    var migrationTransactionStatusesForReturnValue: [MigrationTransactionStatus]!
    var migrationTransactionStatusesForClosure: ((AccountUUID) async throws -> [MigrationTransactionStatus])?

    func migrationTransactionStatuses(for account: AccountUUID) async throws -> [MigrationTransactionStatus] {
        if let error = migrationTransactionStatusesForThrowableError {
            throw error
        }
        migrationTransactionStatusesForCallsCount += 1
        migrationTransactionStatusesForReceivedAccount = account
        if let closure = migrationTransactionStatusesForClosure {
            return try await closure(account)
        } else {
            return migrationTransactionStatusesForReturnValue
        }
    }

    // MARK: - migrationIsNoteSplitNeeded

    var migrationIsNoteSplitNeededForThrowableError: Error?
    var migrationIsNoteSplitNeededForCallsCount = 0
    var migrationIsNoteSplitNeededForCalled: Bool {
        return migrationIsNoteSplitNeededForCallsCount > 0
    }
    var migrationIsNoteSplitNeededForReceivedAccount: AccountUUID?
    var migrationIsNoteSplitNeededForReturnValue: Bool!
    var migrationIsNoteSplitNeededForClosure: ((AccountUUID) async throws -> Bool)?

    func migrationIsNoteSplitNeeded(for account: AccountUUID) async throws -> Bool {
        if let error = migrationIsNoteSplitNeededForThrowableError {
            throw error
        }
        migrationIsNoteSplitNeededForCallsCount += 1
        migrationIsNoteSplitNeededForReceivedAccount = account
        if let closure = migrationIsNoteSplitNeededForClosure {
            return try await closure(account)
        } else {
            return migrationIsNoteSplitNeededForReturnValue
        }
    }

    // MARK: - migrationHasOverdueTransfers

    var migrationHasOverdueTransfersForEstimatedTipThrowableError: Error?
    var migrationHasOverdueTransfersForEstimatedTipCallsCount = 0
    var migrationHasOverdueTransfersForEstimatedTipCalled: Bool {
        return migrationHasOverdueTransfersForEstimatedTipCallsCount > 0
    }
    var migrationHasOverdueTransfersForEstimatedTipReceivedArguments: (account: AccountUUID, estimatedTip: BlockHeight?)?
    var migrationHasOverdueTransfersForEstimatedTipReturnValue: Bool!
    var migrationHasOverdueTransfersForEstimatedTipClosure: ((AccountUUID, BlockHeight?) async throws -> Bool)?

    func migrationHasOverdueTransfers(for account: AccountUUID, estimatedTip: BlockHeight?) async throws -> Bool {
        if let error = migrationHasOverdueTransfersForEstimatedTipThrowableError {
            throw error
        }
        migrationHasOverdueTransfersForEstimatedTipCallsCount += 1
        migrationHasOverdueTransfersForEstimatedTipReceivedArguments = (account: account, estimatedTip: estimatedTip)
        if let closure = migrationHasOverdueTransfersForEstimatedTipClosure {
            return try await closure(account, estimatedTip)
        } else {
            return migrationHasOverdueTransfersForEstimatedTipReturnValue
        }
    }

    // MARK: - migrationHasInvalidTransfers

    var migrationHasInvalidTransfersForThrowableError: Error?
    var migrationHasInvalidTransfersForCallsCount = 0
    var migrationHasInvalidTransfersForCalled: Bool {
        return migrationHasInvalidTransfersForCallsCount > 0
    }
    var migrationHasInvalidTransfersForReceivedAccount: AccountUUID?
    var migrationHasInvalidTransfersForReturnValue: Bool!
    var migrationHasInvalidTransfersForClosure: ((AccountUUID) async throws -> Bool)?

    func migrationHasInvalidTransfers(for account: AccountUUID) async throws -> Bool {
        if let error = migrationHasInvalidTransfersForThrowableError {
            throw error
        }
        migrationHasInvalidTransfersForCallsCount += 1
        migrationHasInvalidTransfersForReceivedAccount = account
        if let closure = migrationHasInvalidTransfersForClosure {
            return try await closure(account)
        } else {
            return migrationHasInvalidTransfersForReturnValue
        }
    }

    // MARK: - migrationPrepareNoteSplit

    var migrationPrepareNoteSplitForThrowableError: Error?
    var migrationPrepareNoteSplitForCallsCount = 0
    var migrationPrepareNoteSplitForCalled: Bool {
        return migrationPrepareNoteSplitForCallsCount > 0
    }
    var migrationPrepareNoteSplitForReceivedAccount: AccountUUID?
    var migrationPrepareNoteSplitForReturnValue: NoteSplitProposal!
    var migrationPrepareNoteSplitForClosure: ((AccountUUID) async throws -> NoteSplitProposal)?

    func migrationPrepareNoteSplit(for account: AccountUUID) async throws -> NoteSplitProposal {
        if let error = migrationPrepareNoteSplitForThrowableError {
            throw error
        }
        migrationPrepareNoteSplitForCallsCount += 1
        migrationPrepareNoteSplitForReceivedAccount = account
        if let closure = migrationPrepareNoteSplitForClosure {
            return try await closure(account)
        } else {
            return migrationPrepareNoteSplitForReturnValue
        }
    }

    // MARK: - migrationSignNoteSplit

    var migrationSignNoteSplitProposalUskForThrowableError: Error?
    var migrationSignNoteSplitProposalUskForCallsCount = 0
    var migrationSignNoteSplitProposalUskForCalled: Bool {
        return migrationSignNoteSplitProposalUskForCallsCount > 0
    }
    var migrationSignNoteSplitProposalUskForReceivedArguments: (proposal: NoteSplitProposal, usk: UnifiedSpendingKey, account: AccountUUID)?
    var migrationSignNoteSplitProposalUskForReturnValue: PreparedMigrationTransfer!
    var migrationSignNoteSplitProposalUskForClosure: ((NoteSplitProposal, UnifiedSpendingKey, AccountUUID) async throws -> PreparedMigrationTransfer)?

    func migrationSignNoteSplit(proposal: NoteSplitProposal, usk: UnifiedSpendingKey, for account: AccountUUID) async throws -> PreparedMigrationTransfer {
        if let error = migrationSignNoteSplitProposalUskForThrowableError {
            throw error
        }
        migrationSignNoteSplitProposalUskForCallsCount += 1
        migrationSignNoteSplitProposalUskForReceivedArguments = (proposal: proposal, usk: usk, account: account)
        if let closure = migrationSignNoteSplitProposalUskForClosure {
            return try await closure(proposal, usk, account)
        } else {
            return migrationSignNoteSplitProposalUskForReturnValue
        }
    }

    // MARK: - migrationResidualAfterMigration

    var migrationResidualAfterMigrationForThrowableError: Error?
    var migrationResidualAfterMigrationForCallsCount = 0
    var migrationResidualAfterMigrationForCalled: Bool {
        return migrationResidualAfterMigrationForCallsCount > 0
    }
    var migrationResidualAfterMigrationForReceivedAccount: AccountUUID?
    var migrationResidualAfterMigrationForReturnValue: Zatoshi?
    var migrationResidualAfterMigrationForClosure: ((AccountUUID) async throws -> Zatoshi?)?

    func migrationResidualAfterMigration(for account: AccountUUID) async throws -> Zatoshi? {
        if let error = migrationResidualAfterMigrationForThrowableError {
            throw error
        }
        migrationResidualAfterMigrationForCallsCount += 1
        migrationResidualAfterMigrationForReceivedAccount = account
        if let closure = migrationResidualAfterMigrationForClosure {
            return try await closure(account)
        } else {
            return migrationResidualAfterMigrationForReturnValue
        }
    }

    // MARK: - lockMigrationResidual

    var lockMigrationResidualAccountUUIDThrowableError: Error?
    var lockMigrationResidualAccountUUIDCallsCount = 0
    var lockMigrationResidualAccountUUIDCalled: Bool {
        return lockMigrationResidualAccountUUIDCallsCount > 0
    }
    var lockMigrationResidualAccountUUIDReceivedAccountUUID: AccountUUID?
    var lockMigrationResidualAccountUUIDReturnValue: Zatoshi!
    var lockMigrationResidualAccountUUIDClosure: ((AccountUUID) async throws -> Zatoshi)?

    func lockMigrationResidual(accountUUID: AccountUUID) async throws -> Zatoshi {
        if let error = lockMigrationResidualAccountUUIDThrowableError {
            throw error
        }
        lockMigrationResidualAccountUUIDCallsCount += 1
        lockMigrationResidualAccountUUIDReceivedAccountUUID = accountUUID
        if let closure = lockMigrationResidualAccountUUIDClosure {
            return try await closure(accountUUID)
        } else {
            return lockMigrationResidualAccountUUIDReturnValue
        }
    }

    // MARK: - unlockMigrationResidual

    var unlockMigrationResidualAccountUUIDThrowableError: Error?
    var unlockMigrationResidualAccountUUIDCallsCount = 0
    var unlockMigrationResidualAccountUUIDCalled: Bool {
        return unlockMigrationResidualAccountUUIDCallsCount > 0
    }
    var unlockMigrationResidualAccountUUIDReceivedAccountUUID: AccountUUID?
    var unlockMigrationResidualAccountUUIDReturnValue: Int!
    var unlockMigrationResidualAccountUUIDClosure: ((AccountUUID) async throws -> Int)?

    func unlockMigrationResidual(accountUUID: AccountUUID) async throws -> Int {
        if let error = unlockMigrationResidualAccountUUIDThrowableError {
            throw error
        }
        unlockMigrationResidualAccountUUIDCallsCount += 1
        unlockMigrationResidualAccountUUIDReceivedAccountUUID = accountUUID
        if let closure = unlockMigrationResidualAccountUUIDClosure {
            return try await closure(accountUUID)
        } else {
            return unlockMigrationResidualAccountUUIDReturnValue
        }
    }

    // MARK: - estimateMigrationRuns

    var estimateMigrationRunsAccountUUIDThrowableError: Error?
    var estimateMigrationRunsAccountUUIDCallsCount = 0
    var estimateMigrationRunsAccountUUIDCalled: Bool {
        return estimateMigrationRunsAccountUUIDCallsCount > 0
    }
    var estimateMigrationRunsAccountUUIDReceivedAccountUUID: AccountUUID?
    var estimateMigrationRunsAccountUUIDReturnValue: MigrationRunEstimate!
    var estimateMigrationRunsAccountUUIDClosure: ((AccountUUID) async throws -> MigrationRunEstimate)?

    func estimateMigrationRuns(accountUUID: AccountUUID) async throws -> MigrationRunEstimate {
        if let error = estimateMigrationRunsAccountUUIDThrowableError {
            throw error
        }
        estimateMigrationRunsAccountUUIDCallsCount += 1
        estimateMigrationRunsAccountUUIDReceivedAccountUUID = accountUUID
        if let closure = estimateMigrationRunsAccountUUIDClosure {
            return try await closure(accountUUID)
        } else {
            return estimateMigrationRunsAccountUUIDReturnValue
        }
    }

    // MARK: - migrationProposeTransfers

    var migrationProposeTransfersForThrowableError: Error?
    var migrationProposeTransfersForCallsCount = 0
    var migrationProposeTransfersForCalled: Bool {
        return migrationProposeTransfersForCallsCount > 0
    }
    var migrationProposeTransfersForReceivedAccount: AccountUUID?
    var migrationProposeTransfersForReturnValue: MigrationSchedule!
    var migrationProposeTransfersForClosure: ((AccountUUID) async throws -> MigrationSchedule)?

    func migrationProposeTransfers(for account: AccountUUID) async throws -> MigrationSchedule {
        if let error = migrationProposeTransfersForThrowableError {
            throw error
        }
        migrationProposeTransfersForCallsCount += 1
        migrationProposeTransfersForReceivedAccount = account
        if let closure = migrationProposeTransfersForClosure {
            return try await closure(account)
        } else {
            return migrationProposeTransfersForReturnValue
        }
    }

    // MARK: - proposeSendMaxTransfer

    var proposeSendMaxTransferAccountUUIDRecipientMemoOrchardOnlyThrowableError: Error?
    var proposeSendMaxTransferAccountUUIDRecipientMemoOrchardOnlyCallsCount = 0
    var proposeSendMaxTransferAccountUUIDRecipientMemoOrchardOnlyCalled: Bool {
        return proposeSendMaxTransferAccountUUIDRecipientMemoOrchardOnlyCallsCount > 0
    }
    var proposeSendMaxTransferAccountUUIDRecipientMemoOrchardOnlyReceivedArguments: (accountUUID: AccountUUID, recipient: String, memo: MemoBytes?, orchardOnly: Bool)?
    var proposeSendMaxTransferAccountUUIDRecipientMemoOrchardOnlyReturnValue: FfiProposal!
    var proposeSendMaxTransferAccountUUIDRecipientMemoOrchardOnlyClosure: ((AccountUUID, String, MemoBytes?, Bool) async throws -> FfiProposal)?

    func proposeSendMaxTransfer(accountUUID: AccountUUID, recipient: String, memo: MemoBytes?, orchardOnly: Bool) async throws -> FfiProposal {
        if let error = proposeSendMaxTransferAccountUUIDRecipientMemoOrchardOnlyThrowableError {
            throw error
        }
        proposeSendMaxTransferAccountUUIDRecipientMemoOrchardOnlyCallsCount += 1
        proposeSendMaxTransferAccountUUIDRecipientMemoOrchardOnlyReceivedArguments = (accountUUID: accountUUID, recipient: recipient, memo: memo, orchardOnly: orchardOnly)
        if let closure = proposeSendMaxTransferAccountUUIDRecipientMemoOrchardOnlyClosure {
            return try await closure(accountUUID, recipient, memo, orchardOnly)
        } else {
            return proposeSendMaxTransferAccountUUIDRecipientMemoOrchardOnlyReturnValue
        }
    }

    // MARK: - migrationSignAndStoreSchedule

    var migrationSignAndStoreScheduleUskForThrowableError: Error?
    var migrationSignAndStoreScheduleUskForCallsCount = 0
    var migrationSignAndStoreScheduleUskForCalled: Bool {
        return migrationSignAndStoreScheduleUskForCallsCount > 0
    }
    var migrationSignAndStoreScheduleUskForReceivedArguments: (schedule: MigrationSchedule, usk: UnifiedSpendingKey, account: AccountUUID)?
    var migrationSignAndStoreScheduleUskForClosure: ((MigrationSchedule, UnifiedSpendingKey, AccountUUID) async throws -> Void)?

    func migrationSignAndStoreSchedule(_ schedule: MigrationSchedule, usk: UnifiedSpendingKey, for account: AccountUUID) async throws {
        if let error = migrationSignAndStoreScheduleUskForThrowableError {
            throw error
        }
        migrationSignAndStoreScheduleUskForCallsCount += 1
        migrationSignAndStoreScheduleUskForReceivedArguments = (schedule: schedule, usk: usk, account: account)
        try await migrationSignAndStoreScheduleUskForClosure!(schedule, usk, account)
    }

    // MARK: - migrationProveTransactions

    var migrationProveTransactionsIdsMaxProofsForThrowableError: Error?
    var migrationProveTransactionsIdsMaxProofsForCallsCount = 0
    var migrationProveTransactionsIdsMaxProofsForCalled: Bool {
        return migrationProveTransactionsIdsMaxProofsForCallsCount > 0
    }
    var migrationProveTransactionsIdsMaxProofsForReceivedArguments: (ids: [UInt32], maxProofs: Int, account: AccountUUID)?
    var migrationProveTransactionsIdsMaxProofsForReturnValue: MigrationProveOutcome!
    var migrationProveTransactionsIdsMaxProofsForClosure: (([UInt32], Int, AccountUUID) async throws -> MigrationProveOutcome)?

    func migrationProveTransactions(ids: [UInt32], maxProofs: Int, for account: AccountUUID) async throws -> MigrationProveOutcome {
        if let error = migrationProveTransactionsIdsMaxProofsForThrowableError {
            throw error
        }
        migrationProveTransactionsIdsMaxProofsForCallsCount += 1
        migrationProveTransactionsIdsMaxProofsForReceivedArguments = (ids: ids, maxProofs: maxProofs, account: account)
        if let closure = migrationProveTransactionsIdsMaxProofsForClosure {
            return try await closure(ids, maxProofs, account)
        } else {
            return migrationProveTransactionsIdsMaxProofsForReturnValue
        }
    }

    // MARK: - migrationTakePreparation

    var migrationTakePreparationTxidForThrowableError: Error?
    var migrationTakePreparationTxidForCallsCount = 0
    var migrationTakePreparationTxidForCalled: Bool {
        return migrationTakePreparationTxidForCallsCount > 0
    }
    var migrationTakePreparationTxidForReceivedArguments: (txid: Data, account: AccountUUID)?
    var migrationTakePreparationTxidForReturnValue: PreparedMigrationTransfer!
    var migrationTakePreparationTxidForClosure: ((Data, AccountUUID) async throws -> PreparedMigrationTransfer)?

    func migrationTakePreparation(txid: Data, for account: AccountUUID) async throws -> PreparedMigrationTransfer {
        if let error = migrationTakePreparationTxidForThrowableError {
            throw error
        }
        migrationTakePreparationTxidForCallsCount += 1
        migrationTakePreparationTxidForReceivedArguments = (txid: txid, account: account)
        if let closure = migrationTakePreparationTxidForClosure {
            return try await closure(txid, account)
        } else {
            return migrationTakePreparationTxidForReturnValue
        }
    }

    // MARK: - migrationTakeBroadcastTransaction

    var migrationTakeBroadcastTransactionIdForThrowableError: Error?
    var migrationTakeBroadcastTransactionIdForCallsCount = 0
    var migrationTakeBroadcastTransactionIdForCalled: Bool {
        return migrationTakeBroadcastTransactionIdForCallsCount > 0
    }
    var migrationTakeBroadcastTransactionIdForReceivedArguments: (id: UInt32, account: AccountUUID)?
    var migrationTakeBroadcastTransactionIdForReturnValue: PreparedMigrationTransfer!
    var migrationTakeBroadcastTransactionIdForClosure: ((UInt32, AccountUUID) async throws -> PreparedMigrationTransfer)?

    func migrationTakeBroadcastTransaction(id: UInt32, for account: AccountUUID) async throws -> PreparedMigrationTransfer {
        if let error = migrationTakeBroadcastTransactionIdForThrowableError {
            throw error
        }
        migrationTakeBroadcastTransactionIdForCallsCount += 1
        migrationTakeBroadcastTransactionIdForReceivedArguments = (id: id, account: account)
        if let closure = migrationTakeBroadcastTransactionIdForClosure {
            return try await closure(id, account)
        } else {
            return migrationTakeBroadcastTransactionIdForReturnValue
        }
    }

    // MARK: - migrationRecordTransferResult

    var migrationRecordTransferResultTransferIdResultForThrowableError: Error?
    var migrationRecordTransferResultTransferIdResultForCallsCount = 0
    var migrationRecordTransferResultTransferIdResultForCalled: Bool {
        return migrationRecordTransferResultTransferIdResultForCallsCount > 0
    }
    var migrationRecordTransferResultTransferIdResultForReceivedArguments: (transferId: UInt32, result: MigrationTransferResult, account: AccountUUID)?
    var migrationRecordTransferResultTransferIdResultForClosure: ((UInt32, MigrationTransferResult, AccountUUID) async throws -> Void)?

    func migrationRecordTransferResult(transferId: UInt32, result: MigrationTransferResult, for account: AccountUUID) async throws {
        if let error = migrationRecordTransferResultTransferIdResultForThrowableError {
            throw error
        }
        migrationRecordTransferResultTransferIdResultForCallsCount += 1
        migrationRecordTransferResultTransferIdResultForReceivedArguments = (transferId: transferId, result: result, account: account)
        try await migrationRecordTransferResultTransferIdResultForClosure!(transferId, result, account)
    }

    // MARK: - migrationRecordImmediateRun

    var migrationRecordImmediateRunTxidForThrowableError: Error?
    var migrationRecordImmediateRunTxidForCallsCount = 0
    var migrationRecordImmediateRunTxidForCalled: Bool {
        return migrationRecordImmediateRunTxidForCallsCount > 0
    }
    var migrationRecordImmediateRunTxidForReceivedArguments: (txid: Data, account: AccountUUID)?
    var migrationRecordImmediateRunTxidForClosure: ((Data, AccountUUID) async throws -> Void)?

    func migrationRecordImmediateRun(txid: Data, for account: AccountUUID) async throws {
        if let error = migrationRecordImmediateRunTxidForThrowableError {
            throw error
        }
        migrationRecordImmediateRunTxidForCallsCount += 1
        migrationRecordImmediateRunTxidForReceivedArguments = (txid: txid, account: account)
        try await migrationRecordImmediateRunTxidForClosure!(txid, account)
    }

    // MARK: - migrationRestartStep

    var migrationRestartStepForThrowableError: Error?
    var migrationRestartStepForCallsCount = 0
    var migrationRestartStepForCalled: Bool {
        return migrationRestartStepForCallsCount > 0
    }
    var migrationRestartStepForReceivedAccount: AccountUUID?
    var migrationRestartStepForReturnValue: MigrationSchedule!
    var migrationRestartStepForClosure: ((AccountUUID) async throws -> MigrationSchedule)?

    func migrationRestartStep(for account: AccountUUID) async throws -> MigrationSchedule {
        if let error = migrationRestartStepForThrowableError {
            throw error
        }
        migrationRestartStepForCallsCount += 1
        migrationRestartStepForReceivedAccount = account
        if let closure = migrationRestartStepForClosure {
            return try await closure(account)
        } else {
            return migrationRestartStepForReturnValue
        }
    }

    // MARK: - migrationRefreshStaleTransfers

    var migrationRefreshStaleTransfersUskForThrowableError: Error?
    var migrationRefreshStaleTransfersUskForCallsCount = 0
    var migrationRefreshStaleTransfersUskForCalled: Bool {
        return migrationRefreshStaleTransfersUskForCallsCount > 0
    }
    var migrationRefreshStaleTransfersUskForReceivedArguments: (usk: UnifiedSpendingKey?, account: AccountUUID)?
    var migrationRefreshStaleTransfersUskForReturnValue: MigrationSchedule!
    var migrationRefreshStaleTransfersUskForClosure: ((UnifiedSpendingKey?, AccountUUID) async throws -> MigrationSchedule)?

    func migrationRefreshStaleTransfers(usk: UnifiedSpendingKey?, for account: AccountUUID) async throws -> MigrationSchedule {
        if let error = migrationRefreshStaleTransfersUskForThrowableError {
            throw error
        }
        migrationRefreshStaleTransfersUskForCallsCount += 1
        migrationRefreshStaleTransfersUskForReceivedArguments = (usk: usk, account: account)
        if let closure = migrationRefreshStaleTransfersUskForClosure {
            return try await closure(usk, account)
        } else {
            return migrationRefreshStaleTransfersUskForReturnValue
        }
    }

    // MARK: - migrationCreateUnsignedNoteSplitPczts

    var migrationCreateUnsignedNoteSplitPcztsForForThrowableError: Error?
    var migrationCreateUnsignedNoteSplitPcztsForForCallsCount = 0
    var migrationCreateUnsignedNoteSplitPcztsForForCalled: Bool {
        return migrationCreateUnsignedNoteSplitPcztsForForCallsCount > 0
    }
    var migrationCreateUnsignedNoteSplitPcztsForForReceivedArguments: (schedule: MigrationSchedule, account: AccountUUID)?
    var migrationCreateUnsignedNoteSplitPcztsForForReturnValue: [MigrationUnsignedTransferPczt]!
    var migrationCreateUnsignedNoteSplitPcztsForForClosure: ((MigrationSchedule, AccountUUID) async throws -> [MigrationUnsignedTransferPczt])?

    func migrationCreateUnsignedNoteSplitPczts(for schedule: MigrationSchedule, for account: AccountUUID) async throws -> [MigrationUnsignedTransferPczt] {
        if let error = migrationCreateUnsignedNoteSplitPcztsForForThrowableError {
            throw error
        }
        migrationCreateUnsignedNoteSplitPcztsForForCallsCount += 1
        migrationCreateUnsignedNoteSplitPcztsForForReceivedArguments = (schedule: schedule, account: account)
        if let closure = migrationCreateUnsignedNoteSplitPcztsForForClosure {
            return try await closure(schedule, account)
        } else {
            return migrationCreateUnsignedNoteSplitPcztsForForReturnValue
        }
    }

    // MARK: - migrationStoreSignedNoteSplitPczts

    var migrationStoreSignedNoteSplitPcztsForThrowableError: Error?
    var migrationStoreSignedNoteSplitPcztsForCallsCount = 0
    var migrationStoreSignedNoteSplitPcztsForCalled: Bool {
        return migrationStoreSignedNoteSplitPcztsForCallsCount > 0
    }
    var migrationStoreSignedNoteSplitPcztsForReceivedArguments: (signed: [MigrationSignedTransferPczt], account: AccountUUID)?
    var migrationStoreSignedNoteSplitPcztsForReturnValue: PreparedMigrationTransfer!
    var migrationStoreSignedNoteSplitPcztsForClosure: (([MigrationSignedTransferPczt], AccountUUID) async throws -> PreparedMigrationTransfer)?

    func migrationStoreSignedNoteSplitPczts(_ signed: [MigrationSignedTransferPczt], for account: AccountUUID) async throws -> PreparedMigrationTransfer {
        if let error = migrationStoreSignedNoteSplitPcztsForThrowableError {
            throw error
        }
        migrationStoreSignedNoteSplitPcztsForCallsCount += 1
        migrationStoreSignedNoteSplitPcztsForReceivedArguments = (signed: signed, account: account)
        if let closure = migrationStoreSignedNoteSplitPcztsForClosure {
            return try await closure(signed, account)
        } else {
            return migrationStoreSignedNoteSplitPcztsForReturnValue
        }
    }

    // MARK: - migrationCreateUnsignedTransferPczts

    var migrationCreateUnsignedTransferPcztsForForThrowableError: Error?
    var migrationCreateUnsignedTransferPcztsForForCallsCount = 0
    var migrationCreateUnsignedTransferPcztsForForCalled: Bool {
        return migrationCreateUnsignedTransferPcztsForForCallsCount > 0
    }
    var migrationCreateUnsignedTransferPcztsForForReceivedArguments: (schedule: MigrationSchedule, account: AccountUUID)?
    var migrationCreateUnsignedTransferPcztsForForReturnValue: [MigrationUnsignedTransferPczt]!
    var migrationCreateUnsignedTransferPcztsForForClosure: ((MigrationSchedule, AccountUUID) async throws -> [MigrationUnsignedTransferPczt])?

    func migrationCreateUnsignedTransferPczts(for schedule: MigrationSchedule, for account: AccountUUID) async throws -> [MigrationUnsignedTransferPczt] {
        if let error = migrationCreateUnsignedTransferPcztsForForThrowableError {
            throw error
        }
        migrationCreateUnsignedTransferPcztsForForCallsCount += 1
        migrationCreateUnsignedTransferPcztsForForReceivedArguments = (schedule: schedule, account: account)
        if let closure = migrationCreateUnsignedTransferPcztsForForClosure {
            return try await closure(schedule, account)
        } else {
            return migrationCreateUnsignedTransferPcztsForForReturnValue
        }
    }

    // MARK: - migrationStoreSignedSchedulePczts

    var migrationStoreSignedSchedulePcztsForThrowableError: Error?
    var migrationStoreSignedSchedulePcztsForCallsCount = 0
    var migrationStoreSignedSchedulePcztsForCalled: Bool {
        return migrationStoreSignedSchedulePcztsForCallsCount > 0
    }
    var migrationStoreSignedSchedulePcztsForReceivedArguments: (signed: [MigrationSignedTransferPczt], account: AccountUUID)?
    var migrationStoreSignedSchedulePcztsForClosure: (([MigrationSignedTransferPczt], AccountUUID) async throws -> Void)?

    func migrationStoreSignedSchedulePczts(_ signed: [MigrationSignedTransferPczt], for account: AccountUUID) async throws {
        if let error = migrationStoreSignedSchedulePcztsForThrowableError {
            throw error
        }
        migrationStoreSignedSchedulePcztsForCallsCount += 1
        migrationStoreSignedSchedulePcztsForReceivedArguments = (signed: signed, account: account)
        try await migrationStoreSignedSchedulePcztsForClosure!(signed, account)
    }

    // MARK: - migrationKeystoneBuildSignBatchQrParts

    var migrationKeystoneBuildSignBatchQrPartsRequestIdPcztsMaxFragmentLenThrowableError: Error?
    var migrationKeystoneBuildSignBatchQrPartsRequestIdPcztsMaxFragmentLenCallsCount = 0
    var migrationKeystoneBuildSignBatchQrPartsRequestIdPcztsMaxFragmentLenCalled: Bool {
        return migrationKeystoneBuildSignBatchQrPartsRequestIdPcztsMaxFragmentLenCallsCount > 0
    }
    var migrationKeystoneBuildSignBatchQrPartsRequestIdPcztsMaxFragmentLenReceivedArguments: (requestId: Data, pczts: [MigrationUnsignedTransferPczt], maxFragmentLen: Int)?
    var migrationKeystoneBuildSignBatchQrPartsRequestIdPcztsMaxFragmentLenReturnValue: [String]!
    var migrationKeystoneBuildSignBatchQrPartsRequestIdPcztsMaxFragmentLenClosure: ((Data, [MigrationUnsignedTransferPczt], Int) async throws -> [String])?

    func migrationKeystoneBuildSignBatchQrParts(requestId: Data, pczts: [MigrationUnsignedTransferPczt], maxFragmentLen: Int) async throws -> [String] {
        if let error = migrationKeystoneBuildSignBatchQrPartsRequestIdPcztsMaxFragmentLenThrowableError {
            throw error
        }
        migrationKeystoneBuildSignBatchQrPartsRequestIdPcztsMaxFragmentLenCallsCount += 1
        migrationKeystoneBuildSignBatchQrPartsRequestIdPcztsMaxFragmentLenReceivedArguments = (requestId: requestId, pczts: pczts, maxFragmentLen: maxFragmentLen)
        if let closure = migrationKeystoneBuildSignBatchQrPartsRequestIdPcztsMaxFragmentLenClosure {
            return try await closure(requestId, pczts, maxFragmentLen)
        } else {
            return migrationKeystoneBuildSignBatchQrPartsRequestIdPcztsMaxFragmentLenReturnValue
        }
    }

    // MARK: - migrationKeystoneResetSignBatchDecoder

    var migrationKeystoneResetSignBatchDecoderCallsCount = 0
    var migrationKeystoneResetSignBatchDecoderCalled: Bool {
        return migrationKeystoneResetSignBatchDecoderCallsCount > 0
    }
    var migrationKeystoneResetSignBatchDecoderClosure: (() async -> Void)?

    func migrationKeystoneResetSignBatchDecoder() async {
        migrationKeystoneResetSignBatchDecoderCallsCount += 1
        await migrationKeystoneResetSignBatchDecoderClosure!()
    }

    // MARK: - migrationKeystoneDecodeSignBatchPart

    var migrationKeystoneDecodeSignBatchPartExpectedRequestIdThrowableError: Error?
    var migrationKeystoneDecodeSignBatchPartExpectedRequestIdCallsCount = 0
    var migrationKeystoneDecodeSignBatchPartExpectedRequestIdCalled: Bool {
        return migrationKeystoneDecodeSignBatchPartExpectedRequestIdCallsCount > 0
    }
    var migrationKeystoneDecodeSignBatchPartExpectedRequestIdReceivedArguments: (part: String, expectedRequestId: Data)?
    var migrationKeystoneDecodeSignBatchPartExpectedRequestIdReturnValue: KeystoneBatchDecodeResult!
    var migrationKeystoneDecodeSignBatchPartExpectedRequestIdClosure: ((String, Data) async throws -> KeystoneBatchDecodeResult)?

    func migrationKeystoneDecodeSignBatchPart(_ part: String, expectedRequestId: Data) async throws -> KeystoneBatchDecodeResult {
        if let error = migrationKeystoneDecodeSignBatchPartExpectedRequestIdThrowableError {
            throw error
        }
        migrationKeystoneDecodeSignBatchPartExpectedRequestIdCallsCount += 1
        migrationKeystoneDecodeSignBatchPartExpectedRequestIdReceivedArguments = (part: part, expectedRequestId: expectedRequestId)
        if let closure = migrationKeystoneDecodeSignBatchPartExpectedRequestIdClosure {
            return try await closure(part, expectedRequestId)
        } else {
            return migrationKeystoneDecodeSignBatchPartExpectedRequestIdReturnValue
        }
    }

    // MARK: - migrationKeystoneApplyBatchSignatures

    var migrationKeystoneApplyBatchSignaturesPcztsBatchSignResponseThrowableError: Error?
    var migrationKeystoneApplyBatchSignaturesPcztsBatchSignResponseCallsCount = 0
    var migrationKeystoneApplyBatchSignaturesPcztsBatchSignResponseCalled: Bool {
        return migrationKeystoneApplyBatchSignaturesPcztsBatchSignResponseCallsCount > 0
    }
    var migrationKeystoneApplyBatchSignaturesPcztsBatchSignResponseReceivedArguments: (pczts: [MigrationUnsignedTransferPczt], batchSignResponse: Data)?
    var migrationKeystoneApplyBatchSignaturesPcztsBatchSignResponseReturnValue: [MigrationSignedTransferPczt]!
    var migrationKeystoneApplyBatchSignaturesPcztsBatchSignResponseClosure: (([MigrationUnsignedTransferPczt], Data) async throws -> [MigrationSignedTransferPczt])?

    func migrationKeystoneApplyBatchSignatures(pczts: [MigrationUnsignedTransferPczt], batchSignResponse: Data) async throws -> [MigrationSignedTransferPczt] {
        if let error = migrationKeystoneApplyBatchSignaturesPcztsBatchSignResponseThrowableError {
            throw error
        }
        migrationKeystoneApplyBatchSignaturesPcztsBatchSignResponseCallsCount += 1
        migrationKeystoneApplyBatchSignaturesPcztsBatchSignResponseReceivedArguments = (pczts: pczts, batchSignResponse: batchSignResponse)
        if let closure = migrationKeystoneApplyBatchSignaturesPcztsBatchSignResponseClosure {
            return try await closure(pczts, batchSignResponse)
        } else {
            return migrationKeystoneApplyBatchSignaturesPcztsBatchSignResponseReturnValue
        }
    }

}

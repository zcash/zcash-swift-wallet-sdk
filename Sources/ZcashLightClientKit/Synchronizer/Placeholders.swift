//
//  Placeholders.swift
//
//
//  Created for type-safe database handles.
//

import Foundation

/// Placeholder rust backend used before prepare() is called.
/// All methods throw synchronizerNotPrepared errors.
class PlaceholderRustBackend: ZcashRustBackendWelding {
    func reopenBlockDb() async throws {
        throw ZcashError.synchronizerNotPrepared
    }

    func resolveDbHandle() async throws -> WalletDbPtr {
        throw ZcashError.synchronizerNotPrepared
    }

    func listAccounts() async throws -> [Account] {
        throw ZcashError.synchronizerNotPrepared
    }

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
    ) async throws -> AccountUUID {
        throw ZcashError.synchronizerNotPrepared
    }

    func createAccount(
        seed: [UInt8],
        treeState: TreeState,
        recoverUntil: UInt32?,
        name: String,
        keySource: String?
    ) async throws -> UnifiedSpendingKey {
        throw ZcashError.synchronizerNotPrepared
    }

    func isSeedRelevantToAnyDerivedAccount(seed: [UInt8]) async throws -> Bool {
        throw ZcashError.synchronizerNotPrepared
    }

    func decryptAndStoreTransaction(txBytes: [UInt8], minedHeight: UInt32?) async throws -> Data {
        throw ZcashError.synchronizerNotPrepared
    }

    func getCurrentAddress(accountUUID: AccountUUID) async throws -> UnifiedAddress {
        throw ZcashError.synchronizerNotPrepared
    }

    func getNextAvailableAddress(accountUUID: AccountUUID, receiverFlags: UInt32) async throws -> UnifiedAddress {
        throw ZcashError.synchronizerNotPrepared
    }

    func getMemo(txId: Data, outputPool: UInt32, outputIndex: UInt16) async throws -> Memo? {
        throw ZcashError.synchronizerNotPrepared
    }

    func getTransparentBalance(accountUUID: AccountUUID) async throws -> Int64 {
        throw ZcashError.synchronizerNotPrepared
    }

    func initDataDb(seed: [UInt8]?) async throws -> DbInitResult {
        throw ZcashError.synchronizerNotPrepared
    }

    func listTransparentReceivers(accountUUID: AccountUUID) async throws -> [TransparentAddress] {
        throw ZcashError.synchronizerNotPrepared
    }

    func getVerifiedTransparentBalance(accountUUID: AccountUUID) async throws -> Int64 {
        throw ZcashError.synchronizerNotPrepared
    }

    func rewindToHeight(height: BlockHeight) async throws -> RewindResult {
        throw ZcashError.synchronizerNotPrepared
    }

    func rewindCacheToHeight(height: Int32) async throws {
        throw ZcashError.synchronizerNotPrepared
    }

    func putSaplingSubtreeRoots(startIndex: UInt64, roots: [SubtreeRoot]) async throws {
        throw ZcashError.synchronizerNotPrepared
    }

    func putOrchardSubtreeRoots(startIndex: UInt64, roots: [SubtreeRoot]) async throws {
        throw ZcashError.synchronizerNotPrepared
    }

    func updateChainTip(height: Int32) async throws {
        throw ZcashError.synchronizerNotPrepared
    }

    func fullyScannedHeight() async throws -> BlockHeight? {
        throw ZcashError.synchronizerNotPrepared
    }

    func maxScannedHeight() async throws -> BlockHeight? {
        throw ZcashError.synchronizerNotPrepared
    }

    func getWalletSummary() async throws -> WalletSummary? {
        throw ZcashError.synchronizerNotPrepared
    }

    func suggestScanRanges() async throws -> [ScanRange] {
        throw ZcashError.synchronizerNotPrepared
    }

    func scanBlocks(fromHeight: Int32, fromState: TreeState, limit: UInt32) async throws -> ScanSummary {
        throw ZcashError.synchronizerNotPrepared
    }

    func putUnspentTransparentOutput(txid: [UInt8], index: Int, script: [UInt8], value: Int64, height: BlockHeight) async throws {
        throw ZcashError.synchronizerNotPrepared
    }

    func proposeTransfer(accountUUID: AccountUUID, to address: String, value: Int64, memo: MemoBytes?) async throws -> FfiProposal {
        throw ZcashError.synchronizerNotPrepared
    }

    func proposeTransferFromURI(_ uri: String, accountUUID: AccountUUID) async throws -> FfiProposal {
        throw ZcashError.synchronizerNotPrepared
    }

    func proposeShielding(
        accountUUID: AccountUUID,
        memo: MemoBytes?,
        shieldingThreshold: Zatoshi,
        transparentReceiver: String?
    ) async throws -> FfiProposal? {
        throw ZcashError.synchronizerNotPrepared
    }

    func createProposedTransactions(proposal: FfiProposal, usk: UnifiedSpendingKey) async throws -> [Data] {
        throw ZcashError.synchronizerNotPrepared
    }

    func createPCZTFromProposal(accountUUID: AccountUUID, proposal: FfiProposal) async throws -> Pczt {
        throw ZcashError.synchronizerNotPrepared
    }

    func redactPCZTForSigner(pczt: Pczt) async throws -> Pczt {
        throw ZcashError.synchronizerNotPrepared
    }

    func PCZTRequiresSaplingProofs(pczt: Pczt) async -> Bool {
        return false
    }

    func addProofsToPCZT(pczt: Pczt) async throws -> Pczt {
        throw ZcashError.synchronizerNotPrepared
    }

    func extractAndStoreTxFromPCZT(pcztWithProofs: Pczt, pcztWithSigs: Pczt) async throws -> Data {
        throw ZcashError.synchronizerNotPrepared
    }

    func consensusBranchIdFor(height: Int32) throws -> Int32 {
        throw ZcashError.synchronizerNotPrepared
    }

    func initBlockMetadataDb() async throws {
        throw ZcashError.synchronizerNotPrepared
    }

    func writeBlocksMetadata(blocks: [ZcashCompactBlock]) async throws {
        throw ZcashError.synchronizerNotPrepared
    }

    func latestCachedBlockHeight() async throws -> BlockHeight {
        throw ZcashError.synchronizerNotPrepared
    }

    func transactionDataRequests() async throws -> [TransactionDataRequest] {
        throw ZcashError.synchronizerNotPrepared
    }

    func setTransactionStatus(txId: Data, status: TransactionStatus) async throws {
        throw ZcashError.synchronizerNotPrepared
    }

    func fixWitnesses() async throws {
        throw ZcashError.synchronizerNotPrepared
    }

    func getSingleUseTransparentAddress(accountUUID: AccountUUID) async throws -> SingleUseTransparentAddress {
        throw ZcashError.synchronizerNotPrepared
    }

    func deleteAccount(_ accountUUID: AccountUUID) async throws {
        throw ZcashError.synchronizerNotPrepared
    }
}

/// Placeholder transaction encoder used before prepare() is called.
class PlaceholderTransactionEncoder: TransactionEncoder {
    func proposeTransfer(
        accountUUID: AccountUUID,
        recipient: String,
        amount: Zatoshi,
        memoBytes: MemoBytes?
    ) async throws -> Proposal {
        throw ZcashError.synchronizerNotPrepared
    }

    func proposeShielding(
        accountUUID: AccountUUID,
        shieldingThreshold: Zatoshi,
        memoBytes: MemoBytes?,
        transparentReceiver: String?
    ) async throws -> Proposal? {
        throw ZcashError.synchronizerNotPrepared
    }

    func proposeFulfillingPaymentFromURI(
        _ uri: String,
        accountUUID: AccountUUID
    ) async throws -> Proposal {
        throw ZcashError.synchronizerNotPrepared
    }

    func createProposedTransactions(
        proposal: Proposal,
        spendingKey: UnifiedSpendingKey
    ) async throws -> [ZcashTransaction.Overview] {
        throw ZcashError.synchronizerNotPrepared
    }

    func submit(transaction: EncodedTransaction) async throws {
        throw ZcashError.synchronizerNotPrepared
    }

    func fetchTransactionsForTxIds(_ txIds: [Data]) async throws -> [ZcashTransaction.Overview] {
        throw ZcashError.synchronizerNotPrepared
    }

    func closeDBConnection() { }
}

extension LatestBlocksDataProviderImpl {
    /// Creates a placeholder instance for use before prepare() is called.
    static func placeholder() -> LatestBlocksDataProviderImpl {
        // Use a mock service and backend that won't be called
        let mockService = PlaceholderLightWalletService()
        let mockBackend = PlaceholderRustBackend()
        let sdkFlags = SDKFlags(torEnabled: false, exchangeRateEnabled: false)
        return LatestBlocksDataProviderImpl(service: mockService, rustBackend: mockBackend, sdkFlags: sdkFlags)
    }
}

/// Placeholder light wallet service for the placeholder LatestBlocksDataProvider.
private class PlaceholderLightWalletService: LightWalletService {
    var connectionStateChange: ((ConnectionState, ConnectionState) -> Void)?

    func getInfo(mode: ServiceMode) async throws -> LightWalletdInfo {
        throw ZcashError.synchronizerNotPrepared
    }

    func latestBlock(mode: ServiceMode) async throws -> BlockID {
        throw ZcashError.synchronizerNotPrepared
    }

    func latestBlockHeight(mode: ServiceMode) async throws -> BlockHeight {
        throw ZcashError.synchronizerNotPrepared
    }

    func blockRange(_ range: CompactBlockRange, mode: ServiceMode) throws -> AsyncThrowingStream<ZcashCompactBlock, Error> {
        AsyncThrowingStream { $0.finish(throwing: ZcashError.synchronizerNotPrepared) }
    }

    func submit(spendTransaction: Data, mode: ServiceMode) async throws -> LightWalletServiceResponse {
        throw ZcashError.synchronizerNotPrepared
    }

    func fetchTransaction(txId: Data, mode: ServiceMode) async throws -> (tx: ZcashTransaction.Fetched?, status: TransactionStatus) {
        throw ZcashError.synchronizerNotPrepared
    }

    func fetchUTXOs(for tAddress: String, height: BlockHeight, mode: ServiceMode) throws -> AsyncThrowingStream<UnspentTransactionOutputEntity, Error> {
        AsyncThrowingStream { $0.finish(throwing: ZcashError.synchronizerNotPrepared) }
    }

    func fetchUTXOs(for tAddresses: [String], height: BlockHeight, mode: ServiceMode) throws -> AsyncThrowingStream<UnspentTransactionOutputEntity, Error> {
        AsyncThrowingStream { $0.finish(throwing: ZcashError.synchronizerNotPrepared) }
    }

    func blockStream(startHeight: BlockHeight, endHeight: BlockHeight, mode: ServiceMode) throws -> AsyncThrowingStream<ZcashCompactBlock, Error> {
        AsyncThrowingStream { $0.finish(throwing: ZcashError.synchronizerNotPrepared) }
    }

    func closeConnections() async { }

    func getSubtreeRoots(_ request: GetSubtreeRootsArg, mode: ServiceMode) throws -> AsyncThrowingStream<SubtreeRoot, Error> {
        AsyncThrowingStream { $0.finish(throwing: ZcashError.synchronizerNotPrepared) }
    }

    func getTreeState(_ id: BlockID, mode: ServiceMode) async throws -> TreeState {
        throw ZcashError.synchronizerNotPrepared
    }

    func getTaddressTxids(_ request: TransparentAddressBlockFilter, mode: ServiceMode) throws -> AsyncThrowingStream<RawTransaction, Error> {
        AsyncThrowingStream { $0.finish(throwing: ZcashError.synchronizerNotPrepared) }
    }

    func getMempoolStream() throws -> AsyncThrowingStream<RawTransaction, Error> {
        AsyncThrowingStream { $0.finish(throwing: ZcashError.synchronizerNotPrepared) }
    }

    @DBActor
    func checkSingleUseTransparentAddresses(dbHandle: WalletDbPtr, accountUUID: AccountUUID, mode: ServiceMode) async throws -> TransparentAddressCheckResult {
        throw ZcashError.synchronizerNotPrepared
    }

    @DBActor
    func updateTransparentAddressTransactions(
        address: String,
        start: BlockHeight,
        end: BlockHeight,
        dbHandle: WalletDbPtr,
        mode: ServiceMode
    ) async throws -> TransparentAddressCheckResult {
        throw ZcashError.synchronizerNotPrepared
    }

    @DBActor
    func fetchUTXOsByAddress(
        address: String,
        dbHandle: WalletDbPtr,
        accountUUID: AccountUUID,
        mode: ServiceMode
    ) async throws -> TransparentAddressCheckResult {
        throw ZcashError.synchronizerNotPrepared
    }
}

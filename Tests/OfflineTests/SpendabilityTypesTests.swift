//
//  SpendabilityTypesTests.swift
//
//
//  Tests for spendability and witness PIR types used across the FFI boundary,
//  plus integration-level tests for the PIR witness retry and proactive
//  alignment logic in SDKSynchronizer.
//

import Foundation
@testable import TestUtils
import XCTest
@testable import ZcashLightClientKit

final class SpendabilityTypesTests: ZcashTestCase {
    let decoder = JSONDecoder()
    let encoder = JSONEncoder()

    // MARK: - PIRUnspentNote

    func testPIRUnspentNoteDecodesFromRustJSON() throws {
        let json = """
        {"id":42,"nf":[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31],"value":50000}
        """.data(using: .utf8)!

        let note = try decoder.decode(PIRUnspentNote.self, from: json)

        XCTAssertEqual(note.id, 42)
        XCTAssertEqual(note.nf, Array(0...31))
        XCTAssertEqual(note.value, 50_000)
    }

    func testPIRUnspentNoteArrayDecodesFromRustJSON() throws {
        let json = """
        [
          {"id":1,"nf":[170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170,170],"value":10000},
          {"id":2,"nf":[187,187,187,187,187,187,187,187,187,187,187,187,187,187,187,187,187,187,187,187,187,187,187,187,187,187,187,187,187,187,187,187],"value":20000}
        ]
        """.data(using: .utf8)!

        let notes = try decoder.decode([PIRUnspentNote].self, from: json)

        XCTAssertEqual(notes.count, 2)
        XCTAssertEqual(notes[0].id, 1)
        XCTAssertEqual(notes[0].nf, [UInt8](repeating: 0xAA, count: 32))
        XCTAssertEqual(notes[0].value, 10_000)
        XCTAssertEqual(notes[1].id, 2)
        XCTAssertEqual(notes[1].nf, [UInt8](repeating: 0xBB, count: 32))
        XCTAssertEqual(notes[1].value, 20_000)
    }

    func testPIRUnspentNoteRoundTrip() throws {
        let note = PIRUnspentNote(id: 7, nf: [UInt8](repeating: 0xFF, count: 32), value: 100_000)
        let data = try encoder.encode(note)
        let decoded = try decoder.decode(PIRUnspentNote.self, from: data)

        XCTAssertEqual(note, decoded)
    }

    func testPIRUnspentNoteEmptyArray() throws {
        let json = "[]".data(using: .utf8)!
        let notes = try decoder.decode([PIRUnspentNote].self, from: json)
        XCTAssertTrue(notes.isEmpty)
    }

    // MARK: - PIRSpendMetadata

    func testPIRSpendMetadataDecodesFromRustJSON() throws {
        let json = """
        {"spend_height":2800000,"first_output_position":12345678,"action_count":4}
        """.data(using: .utf8)!

        let meta = try decoder.decode(PIRSpendMetadata.self, from: json)

        XCTAssertEqual(meta.spendHeight, 2_800_000)
        XCTAssertEqual(meta.firstOutputPosition, 12_345_678)
        XCTAssertEqual(meta.actionCount, 4)
    }

    func testPIRSpendMetadataRoundTrip() throws {
        let meta = PIRSpendMetadata(spendHeight: 100, firstOutputPosition: 5000, actionCount: 3)
        let data = try encoder.encode(meta)
        let decoded = try decoder.decode(PIRSpendMetadata.self, from: data)

        XCTAssertEqual(meta, decoded)
    }

    func testPIRSpendMetadataEncodesSnakeCaseKeys() throws {
        let meta = PIRSpendMetadata(spendHeight: 100, firstOutputPosition: 5000, actionCount: 3)
        let data = try encoder.encode(meta)
        let jsonObject = try JSONSerialization.jsonObject(with: data) as! [String: Any]

        XCTAssertNotNil(jsonObject["spend_height"])
        XCTAssertNotNil(jsonObject["first_output_position"])
        XCTAssertNotNil(jsonObject["action_count"])
        XCTAssertNil(jsonObject["spendHeight"], "Should not use camelCase key")
    }

    // MARK: - PIRNullifierCheckResult

    func testPIRNullifierCheckResultDecodesFromRustJSON() throws {
        let json = """
        {"earliest_height":100,"latest_height":200,"spent":[{"spend_height":150,"first_output_position":5000,"action_count":3},null,{"spend_height":180,"first_output_position":8000,"action_count":1}]}
        """.data(using: .utf8)!

        let result = try decoder.decode(PIRNullifierCheckResult.self, from: json)

        XCTAssertEqual(result.earliestHeight, 100)
        XCTAssertEqual(result.latestHeight, 200)
        XCTAssertEqual(result.spent.count, 3)
        XCTAssertEqual(result.spent[0]?.spendHeight, 150)
        XCTAssertEqual(result.spent[0]?.firstOutputPosition, 5000)
        XCTAssertEqual(result.spent[0]?.actionCount, 3)
        XCTAssertNil(result.spent[1])
        XCTAssertEqual(result.spent[2]?.spendHeight, 180)
    }

    func testPIRNullifierCheckResultEmptySpent() throws {
        let json = """
        {"earliest_height":0,"latest_height":0,"spent":[]}
        """.data(using: .utf8)!

        let result = try decoder.decode(PIRNullifierCheckResult.self, from: json)

        XCTAssertEqual(result.earliestHeight, 0)
        XCTAssertEqual(result.latestHeight, 0)
        XCTAssertTrue(result.spent.isEmpty)
    }

    func testPIRNullifierCheckResultEncodesSnakeCaseKeys() throws {
        let meta = PIRSpendMetadata(spendHeight: 100, firstOutputPosition: 5000, actionCount: 3)
        let result = PIRNullifierCheckResult(earliestHeight: 500, latestHeight: 1000, spent: [nil, meta])
        let data = try encoder.encode(result)
        let jsonObject = try JSONSerialization.jsonObject(with: data) as! [String: Any]

        XCTAssertNotNil(jsonObject["earliest_height"], "Expected snake_case key 'earliest_height'")
        XCTAssertNotNil(jsonObject["latest_height"], "Expected snake_case key 'latest_height'")
        XCTAssertNotNil(jsonObject["spent"])
        XCTAssertNil(jsonObject["earliestHeight"], "Should not use camelCase key")
    }

    func testPIRNullifierCheckResultRoundTrip() throws {
        let meta1 = PIRSpendMetadata(spendHeight: 100, firstOutputPosition: 5000, actionCount: 2)
        let meta2 = PIRSpendMetadata(spendHeight: 200, firstOutputPosition: 9000, actionCount: 1)
        let result = PIRNullifierCheckResult(earliestHeight: 42, latestHeight: 99, spent: [meta1, meta2, nil])
        let data = try encoder.encode(result)
        let decoded = try decoder.decode(PIRNullifierCheckResult.self, from: data)

        XCTAssertEqual(result, decoded)
    }

    // MARK: - SpendabilityResult

    func testSpendabilityResultDecodesFromRustJSON() throws {
        let json = """
        {"earliest_height":100,"latest_height":200,"spent_note_ids":[1,3],"total_spent_value":50000}
        """.data(using: .utf8)!

        let result = try decoder.decode(SpendabilityResult.self, from: json)

        XCTAssertEqual(result.earliestHeight, 100)
        XCTAssertEqual(result.latestHeight, 200)
        XCTAssertEqual(result.spentNoteIds, [1, 3])
        XCTAssertEqual(result.totalSpentValue, 50_000)
    }

    func testSpendabilityResultEmpty() throws {
        let result = SpendabilityResult(earliestHeight: 0, latestHeight: 0, spentNoteIds: [], totalSpentValue: 0)
        let data = try encoder.encode(result)
        let decoded = try decoder.decode(SpendabilityResult.self, from: data)

        XCTAssertEqual(result, decoded)
        XCTAssertTrue(decoded.spentNoteIds.isEmpty)
        XCTAssertEqual(decoded.totalSpentValue, 0)
    }

    func testSpendabilityResultEncodesSnakeCaseKeys() throws {
        let result = SpendabilityResult(earliestHeight: 1, latestHeight: 2, spentNoteIds: [5], totalSpentValue: 999)
        let data = try encoder.encode(result)
        let jsonObject = try JSONSerialization.jsonObject(with: data) as! [String: Any]

        XCTAssertNotNil(jsonObject["earliest_height"])
        XCTAssertNotNil(jsonObject["latest_height"])
        XCTAssertNotNil(jsonObject["spent_note_ids"])
        XCTAssertNotNil(jsonObject["total_spent_value"])
    }

    // MARK: - Cross-type consistency: notes → check → result pipeline

    func testThreePhasePipelineTypes() throws {
        let meta1 = PIRSpendMetadata(spendHeight: 150, firstOutputPosition: 5000, actionCount: 3)
        let meta3 = PIRSpendMetadata(spendHeight: 180, firstOutputPosition: 8000, actionCount: 1)

        let notes = [
            PIRUnspentNote(id: 1, nf: [UInt8](repeating: 0xAA, count: 32), value: 10_000),
            PIRUnspentNote(id: 2, nf: [UInt8](repeating: 0xBB, count: 32), value: 20_000),
            PIRUnspentNote(id: 3, nf: [UInt8](repeating: 0xCC, count: 32), value: 30_000)
        ]

        let checkResult = PIRNullifierCheckResult(
            earliestHeight: 100,
            latestHeight: 200,
            spent: [meta1, nil, meta3]
        )

        XCTAssertEqual(notes.count, checkResult.spent.count, "Spent entries must be parallel to notes")

        let spentNotes = zip(notes, checkResult.spent).filter { $0.1 != nil }
        let spentNoteIds = spentNotes.map(\.0.id)
        let totalSpentValue = spentNotes.map(\.0.value).reduce(0, +)

        XCTAssertEqual(spentNoteIds, [1, 3])
        XCTAssertEqual(totalSpentValue, 40_000)

        let finalResult = SpendabilityResult(
            earliestHeight: checkResult.earliestHeight,
            latestHeight: checkResult.latestHeight,
            spentNoteIds: spentNoteIds,
            totalSpentValue: totalSpentValue
        )

        XCTAssertEqual(finalResult.earliestHeight, 100)
        XCTAssertEqual(finalResult.latestHeight, 200)
        XCTAssertEqual(finalResult.spentNoteIds, [1, 3])
        XCTAssertEqual(finalResult.totalSpentValue, 40_000)
    }

    func testThreePhasePipelineNoNotesSpent() throws {
        let notes = [
            PIRUnspentNote(id: 1, nf: [UInt8](repeating: 0xAA, count: 32), value: 10_000),
            PIRUnspentNote(id: 2, nf: [UInt8](repeating: 0xBB, count: 32), value: 20_000)
        ]

        let checkResult = PIRNullifierCheckResult(
            earliestHeight: 50,
            latestHeight: 150,
            spent: [nil, nil]
        )

        let spentNotes = zip(notes, checkResult.spent).filter { $0.1 != nil }
        XCTAssertTrue(spentNotes.isEmpty)
        XCTAssertEqual(spentNotes.map(\.0.value).reduce(0, +), 0)
    }

    func testThreePhasePipelineAllNotesSpent() throws {
        let meta1 = PIRSpendMetadata(spendHeight: 100, firstOutputPosition: 3000, actionCount: 2)
        let meta2 = PIRSpendMetadata(spendHeight: 120, firstOutputPosition: 4000, actionCount: 1)

        let notes = [
            PIRUnspentNote(id: 1, nf: [UInt8](repeating: 0xAA, count: 32), value: 10_000),
            PIRUnspentNote(id: 2, nf: [UInt8](repeating: 0xBB, count: 32), value: 20_000)
        ]

        let checkResult = PIRNullifierCheckResult(
            earliestHeight: 50,
            latestHeight: 150,
            spent: [meta1, meta2]
        )

        let spentNotes = zip(notes, checkResult.spent).filter { $0.1 != nil }
        XCTAssertEqual(spentNotes.count, 2)
        XCTAssertEqual(spentNotes.map(\.0.id), [1, 2])
        XCTAssertEqual(spentNotes.map(\.0.value).reduce(0, +), 30_000)
    }

    // MARK: - PIRNotePosition

    func testPIRNotePositionDecodesFromRustJSON() throws {
        let json = """
        {"id":42,"position":1000,"value":50000}
        """.data(using: .utf8)!

        let note = try decoder.decode(PIRNotePosition.self, from: json)

        XCTAssertEqual(note.id, 42)
        XCTAssertEqual(note.position, 1000)
        XCTAssertEqual(note.value, 50_000)
    }

    func testPIRNotePositionArrayDecodesFromRustJSON() throws {
        let json = """
        [
          {"id":1,"position":100,"value":10000},
          {"id":2,"position":200,"value":20000}
        ]
        """.data(using: .utf8)!

        let notes = try decoder.decode([PIRNotePosition].self, from: json)

        XCTAssertEqual(notes.count, 2)
        XCTAssertEqual(notes[0].id, 1)
        XCTAssertEqual(notes[0].position, 100)
        XCTAssertEqual(notes[0].value, 10_000)
        XCTAssertEqual(notes[1].id, 2)
        XCTAssertEqual(notes[1].position, 200)
        XCTAssertEqual(notes[1].value, 20_000)
    }

    func testPIRNotePositionRoundTrip() throws {
        let note = PIRNotePosition(id: 7, position: 999, value: 100_000)
        let data = try encoder.encode(note)
        let decoded = try decoder.decode(PIRNotePosition.self, from: data)

        XCTAssertEqual(note, decoded)
    }

    func testPIRNotePositionEmptyArray() throws {
        let json = "[]".data(using: .utf8)!
        let notes = try decoder.decode([PIRNotePosition].self, from: json)
        XCTAssertTrue(notes.isEmpty)
    }

    // MARK: - PIRWitnessEntry

    func testPIRWitnessEntryDecodesFromRustJSON() throws {
        let sibling = String(repeating: "aa", count: 32)
        let root = String(repeating: "bb", count: 32)
        let json = """
        {"note_id":42,"position":1000,"siblings":["\(sibling)"],"anchor_height":3200000,"anchor_root":"\(root)"}
        """.data(using: .utf8)!

        let entry = try decoder.decode(PIRWitnessEntry.self, from: json)

        XCTAssertEqual(entry.noteId, 42)
        XCTAssertEqual(entry.position, 1000)
        XCTAssertEqual(entry.siblings.count, 1)
        XCTAssertEqual(entry.siblings[0], sibling)
        XCTAssertEqual(entry.anchorHeight, 3_200_000)
        XCTAssertEqual(entry.anchorRoot, root)
    }

    func testPIRWitnessEntryEncodesSnakeCaseKeys() throws {
        let entry = PIRWitnessEntry(
            noteId: 1,
            position: 500,
            siblings: [String(repeating: "cc", count: 32)],
            anchorHeight: 100,
            anchorRoot: String(repeating: "dd", count: 32)
        )
        let data = try encoder.encode(entry)
        let jsonObject = try JSONSerialization.jsonObject(with: data) as! [String: Any]

        XCTAssertNotNil(jsonObject["note_id"], "Expected snake_case key 'note_id'")
        XCTAssertNotNil(jsonObject["anchor_height"], "Expected snake_case key 'anchor_height'")
        XCTAssertNotNil(jsonObject["anchor_root"], "Expected snake_case key 'anchor_root'")
        XCTAssertNil(jsonObject["noteId"], "Should not use camelCase key")
        XCTAssertNil(jsonObject["anchorHeight"], "Should not use camelCase key")
        XCTAssertNil(jsonObject["anchorRoot"], "Should not use camelCase key")
    }

    func testPIRWitnessEntryRoundTrip() throws {
        let siblings = (0..<32).map { _ in String(repeating: "ab", count: 32) }
        let entry = PIRWitnessEntry(
            noteId: 99,
            position: 12345,
            siblings: siblings,
            anchorHeight: 3_200_000,
            anchorRoot: String(repeating: "ff", count: 32)
        )
        let data = try encoder.encode(entry)
        let decoded = try decoder.decode(PIRWitnessEntry.self, from: data)

        XCTAssertEqual(entry, decoded)
    }

    // MARK: - PIRWitnessResult

    func testPIRWitnessResultDecodesFromRustJSON() throws {
        let sibling = String(repeating: "aa", count: 32)
        let root = String(repeating: "bb", count: 32)
        let json = """
        {"witnesses":[{"note_id":42,"position":1000,"siblings":["\(sibling)"],"anchor_height":3200000,"anchor_root":"\(root)"}]}
        """.data(using: .utf8)!

        let result = try decoder.decode(PIRWitnessResult.self, from: json)

        XCTAssertEqual(result.witnesses.count, 1)
        XCTAssertEqual(result.witnesses[0].noteId, 42)
        XCTAssertEqual(result.witnesses[0].anchorRoot, root)
    }

    func testPIRWitnessResultEmpty() throws {
        let json = """
        {"witnesses":[]}
        """.data(using: .utf8)!

        let result = try decoder.decode(PIRWitnessResult.self, from: json)
        XCTAssertTrue(result.witnesses.isEmpty)
    }

    func testPIRWitnessResultRoundTrip() throws {
        let result = PIRWitnessResult(witnesses: [
            PIRWitnessEntry(
                noteId: 1,
                position: 100,
                siblings: [String(repeating: "aa", count: 32)],
                anchorHeight: 500,
                anchorRoot: String(repeating: "bb", count: 32)
            )
        ])
        let data = try encoder.encode(result)
        let decoded = try decoder.decode(PIRWitnessResult.self, from: data)

        XCTAssertEqual(result, decoded)
    }

    // MARK: - WitnessResult (in-process only, not Codable)

    func testWitnessResultEquality() {
        let a = WitnessResult(witnessedNoteIds: [1, 2, 3], totalWitnessedValue: 30_000)
        let b = WitnessResult(witnessedNoteIds: [1, 2, 3], totalWitnessedValue: 30_000)
        let c = WitnessResult(witnessedNoteIds: [1, 2], totalWitnessedValue: 20_000)

        XCTAssertEqual(a, b)
        XCTAssertNotEqual(a, c)
    }

    func testWitnessResultEmpty() {
        let result = WitnessResult(witnessedNoteIds: [], totalWitnessedValue: 0)

        XCTAssertTrue(result.witnessedNoteIds.isEmpty)
        XCTAssertEqual(result.totalWitnessedValue, 0)
    }

    // MARK: - PIR witness retry

    private final class RetryTestTransactionEncoder: TransactionEncoder {
        enum StubbedResult {
            case success([ZcashTransaction.Overview])
            case failure(Error)
        }

        private(set) var createProposedTransactionsCallsCount = 0
        private(set) var usePIRWitnessesHistory: [Bool] = []
        var createResults: [StubbedResult] = []

        func createProposedTransactions(
            proposal: Proposal,
            spendingKey: UnifiedSpendingKey
        ) async throws -> [ZcashTransaction.Overview] {
            createProposedTransactionsCallsCount += 1
            usePIRWitnessesHistory.append(proposal.pirWitnessConfig?.usePIRWitnesses ?? false)
            let index = createProposedTransactionsCallsCount - 1
            guard createResults.indices.contains(index) else {
                XCTFail("Missing stubbed result for createProposedTransactions call \(index + 1)")
                return []
            }

            switch createResults[index] {
            case .success(let transactions):
                return transactions
            case .failure(let error):
                throw error
            }
        }

        func proposeTransfer(
            accountUUID: AccountUUID,
            recipient: String,
            amount: Zatoshi,
            memoBytes: MemoBytes?
        ) async throws -> Proposal {
            fatalError("Unused in PIR witness retry tests")
        }

        func proposeShielding(
            accountUUID: AccountUUID,
            shieldingThreshold: Zatoshi,
            memoBytes: MemoBytes?,
            transparentReceiver: String?
        ) async throws -> Proposal? {
            fatalError("Unused in PIR witness retry tests")
        }

        func proposeFulfillingPaymentFromURI(
            _ uri: String,
            accountUUID: AccountUUID
        ) async throws -> Proposal {
            fatalError("Unused in PIR witness retry tests")
        }

        func submit(transaction: EncodedTransaction) async throws {
            fatalError("Unused in PIR witness retry tests")
        }

        func fetchTransactionsForTxIds(_ txIds: [Data]) async throws -> [ZcashTransaction.Overview] {
            fatalError("Unused in PIR witness retry tests")
        }

        func closeDBConnection() {}
    }

    private func makeSpendingKey(network: ZcashNetwork) throws -> UnifiedSpendingKey {
        let derivationTool = DerivationTool(networkType: network.networkType)
        return try derivationTool.deriveUnifiedSpendingKey(
            seed: Environment.seedBytes,
            accountIndex: Zip32AccountIndex(0)
        )
    }

    private func makeProposal() -> Proposal {
        Proposal(inner: FfiProposal())
    }

    private func makeNotePosition() -> PIRNotePosition {
        PIRNotePosition(id: 1, position: 42, value: 60_000)
    }

    private func makeWitnessEntry() -> PIRWitnessEntry {
        PIRWitnessEntry(
            noteId: 1,
            position: 42,
            siblings: Array(repeating: String(repeating: "00", count: 32), count: 32),
            anchorHeight: 1_000,
            anchorRoot: String(repeating: "11", count: 32)
        )
    }

    private func makeSynchronizer(
        rustBackend: ZcashRustBackendWeldingMock,
        transactionEncoder: RetryTestTransactionEncoder,
        syncStatus: InternalSyncStatus = .synced,
        pirWitnessFetcher: @escaping SDKSynchronizer.PIRWitnessFetcher = { _, _, _ in
            preconditionFailure("Unexpected PIR witness fetch")
        }
    ) async throws -> SDKSynchronizer {
        let network = ZcashNetworkBuilder.network(for: .testnet)
        mockContainer.mock(type: ZcashRustBackendWelding.self, isSingleton: true) { _ in rustBackend }

        let initializer = Initializer(
            container: mockContainer,
            cacheDbURL: nil,
            fsBlockDbRoot: testTempDirectory,
            generalStorageURL: testGeneralStorageDirectory,
            dataDbURL: testTempDirectory.appendingPathComponent("data.db"),
            torDirURL: testTempDirectory.appendingPathComponent("tor"),
            endpoint: LightWalletEndpointBuilder.default,
            network: network,
            spendParamsURL: SaplingParamsSourceURL.tests.spendParamFileURL,
            outputParamsURL: SaplingParamsSourceURL.tests.outputParamFileURL,
            saplingParamsSourceURL: .tests,
            alias: .default,
            loggingPolicy: .noLogging,
            isTorEnabled: false,
            isExchangeRateEnabled: false
        )

        let blockProcessor = CompactBlockProcessor(
            initializer: initializer,
            walletBirthdayProvider: { 1 }
        )
        let synchronizer = SDKSynchronizer(
            status: .unprepared,
            initializer: initializer,
            transactionEncoder: transactionEncoder,
            transactionRepository: initializer.transactionRepository,
            blockProcessor: blockProcessor,
            syncSessionTicker: .live,
            pirWitnessFetcher: pirWitnessFetcher
        )
        await synchronizer.updateStatus(syncStatus, updateExternalStatus: false)

        return synchronizer
    }

    func testCreateProposedTransactionsRetriesOnceAfterPIRMismatch() async throws {
        let rustBackend = ZcashRustBackendWeldingMock()
        let transactionEncoder = RetryTestTransactionEncoder()
        transactionEncoder.createResults = [
            .failure(ZcashError.rustCreateToAddress("Selected Orchard inputs were backed by incompatible PIR witness anchors.")),
            .success([])
        ]
        let note = makeNotePosition()
        rustBackend.getPIRWitnessNotesReturnValue = [note]

        let witnessEntry = makeWitnessEntry()
        let synchronizer = try await makeSynchronizer(
            rustBackend: rustBackend,
            transactionEncoder: transactionEncoder,
            pirWitnessFetcher: { _, _, _ in
                return PIRWitnessResult(witnesses: [witnessEntry])
            }
        )

        var proposal = makeProposal()
        proposal.pirWitnessConfig = Proposal.PIRWitnessConfig(serverURL: "http://localhost:8080")
        let stream = try await synchronizer.createProposedTransactions(
            proposal: proposal,
            spendingKey: try makeSpendingKey(network: synchronizer.network)
        )

        var iterator = stream.makeAsyncIterator()
        let next = try await iterator.next()
        XCTAssertNil(next)
        XCTAssertEqual(transactionEncoder.createProposedTransactionsCallsCount, 2)
        XCTAssertEqual(transactionEncoder.usePIRWitnessesHistory, [false, true])
        XCTAssertEqual(rustBackend.getPIRWitnessNotesCallsCount, 1)
        XCTAssertEqual(rustBackend.insertPIRWitnessesCallsCount, 1)
        XCTAssertEqual(rustBackend.insertPIRWitnessesReceivedWitnesses, [witnessEntry])
    }

    func testCreateProposedTransactionsDoesNotRetryForNonPIRFailure() async throws {
        let rustBackend = ZcashRustBackendWeldingMock()
        let transactionEncoder = RetryTestTransactionEncoder()
        transactionEncoder.createResults = [
            .failure(ZcashError.rustCreateToAddress("proposal construction failed"))
        ]
        let synchronizer = try await makeSynchronizer(
            rustBackend: rustBackend,
            transactionEncoder: transactionEncoder
        )

        do {
            var proposal = makeProposal()
            proposal.pirWitnessConfig = Proposal.PIRWitnessConfig(serverURL: "http://localhost:8080")
            _ = try await synchronizer.createProposedTransactions(
                proposal: proposal,
                spendingKey: try makeSpendingKey(network: synchronizer.network)
            )
            XCTFail("Expected transaction creation to fail")
        } catch let ZcashError.rustCreateToAddress(message) {
            XCTAssertEqual(message, "proposal construction failed")
        } catch {
            XCTFail("Unexpected error: \(error)")
        }

        XCTAssertEqual(transactionEncoder.createProposedTransactionsCallsCount, 1)
        XCTAssertEqual(transactionEncoder.usePIRWitnessesHistory, [false])
        XCTAssertEqual(rustBackend.getPIRWitnessNotesCallsCount, 0)
        XCTAssertEqual(rustBackend.insertPIRWitnessesCallsCount, 0)
    }

    func testCreateProposedTransactionsDoesNotRetryWithoutWitnessServerURL() async throws {
        let rustBackend = ZcashRustBackendWeldingMock()
        let transactionEncoder = RetryTestTransactionEncoder()
        transactionEncoder.createResults = [
            .failure(ZcashError.rustCreateToAddress("Selected Orchard inputs were backed by incompatible PIR witness anchors."))
        ]
        let synchronizer = try await makeSynchronizer(
            rustBackend: rustBackend,
            transactionEncoder: transactionEncoder
        )

        do {
            _ = try await synchronizer.createProposedTransactions(
                proposal: makeProposal(),
                spendingKey: try makeSpendingKey(network: synchronizer.network)
            )
            XCTFail("Expected transaction creation to fail")
        } catch let ZcashError.rustCreateToAddress(message) {
            XCTAssertEqual(message, "Selected Orchard inputs were backed by incompatible PIR witness anchors.")
        } catch {
            XCTFail("Unexpected error: \(error)")
        }

        XCTAssertEqual(transactionEncoder.createProposedTransactionsCallsCount, 1)
        XCTAssertEqual(transactionEncoder.usePIRWitnessesHistory, [false])
        XCTAssertEqual(rustBackend.getPIRWitnessNotesCallsCount, 0)
        XCTAssertEqual(rustBackend.insertPIRWitnessesCallsCount, 0)
    }

    func testCreateProposedTransactionsDoesNotRetryWhenProposalHasNoPIRWitnessNotes() async throws {
        let rustBackend = ZcashRustBackendWeldingMock()
        let transactionEncoder = RetryTestTransactionEncoder()
        transactionEncoder.createResults = [
            .failure(ZcashError.rustCreateToAddress("All anchors must be equal"))
        ]
        rustBackend.getPIRWitnessNotesReturnValue = []

        let synchronizer = try await makeSynchronizer(
            rustBackend: rustBackend,
            transactionEncoder: transactionEncoder
        )

        do {
            var proposal = makeProposal()
            proposal.pirWitnessConfig = Proposal.PIRWitnessConfig(serverURL: "http://localhost:8080")
            _ = try await synchronizer.createProposedTransactions(
                proposal: proposal,
                spendingKey: try makeSpendingKey(network: synchronizer.network)
            )
            XCTFail("Expected transaction creation to fail")
        } catch let ZcashError.rustCreateToAddress(message) {
            XCTAssertEqual(message, "All anchors must be equal")
        } catch {
            XCTFail("Unexpected error: \(error)")
        }

        XCTAssertEqual(transactionEncoder.createProposedTransactionsCallsCount, 1)
        XCTAssertEqual(transactionEncoder.usePIRWitnessesHistory, [false])
        XCTAssertEqual(rustBackend.getPIRWitnessNotesCallsCount, 1)
        XCTAssertEqual(rustBackend.insertPIRWitnessesCallsCount, 0)
    }

    func testCreateProposedTransactionsDoesNotLoopAfterSecondFailure() async throws {
        let rustBackend = ZcashRustBackendWeldingMock()
        let transactionEncoder = RetryTestTransactionEncoder()
        let witnessEntry = makeWitnessEntry()
        transactionEncoder.createResults = [
            .failure(ZcashError.rustCreateToAddress("Selected Orchard inputs were backed by incompatible PIR witness anchors.")),
            .failure(ZcashError.rustCreateToAddress("All anchors must be equal"))
        ]
        rustBackend.getPIRWitnessNotesReturnValue = [makeNotePosition()]

        let synchronizer = try await makeSynchronizer(
            rustBackend: rustBackend,
            transactionEncoder: transactionEncoder,
            pirWitnessFetcher: { _, _, _ in
                PIRWitnessResult(witnesses: [witnessEntry])
            }
        )

        do {
            var proposal = makeProposal()
            proposal.pirWitnessConfig = Proposal.PIRWitnessConfig(serverURL: "http://localhost:8080")
            _ = try await synchronizer.createProposedTransactions(
                proposal: proposal,
                spendingKey: try makeSpendingKey(network: synchronizer.network)
            )
            XCTFail("Expected second transaction creation attempt to fail")
        } catch let ZcashError.rustCreateToAddress(message) {
            XCTAssertEqual(message, "All anchors must be equal")
        } catch {
            XCTFail("Unexpected error: \(error)")
        }

        XCTAssertEqual(transactionEncoder.createProposedTransactionsCallsCount, 2)
        XCTAssertEqual(transactionEncoder.usePIRWitnessesHistory, [false, true])
        XCTAssertEqual(rustBackend.getPIRWitnessNotesCallsCount, 1)
        XCTAssertEqual(rustBackend.insertPIRWitnessesCallsCount, 1)
    }

    // MARK: - Proactive alignment

    func testProactiveAlignmentFetchesWitnessesWhenSyncing() async throws {
        let rustBackend = ZcashRustBackendWeldingMock()
        let transactionEncoder = RetryTestTransactionEncoder()
        transactionEncoder.createResults = [.success([])]

        let note = makeNotePosition()
        rustBackend.getPIRWitnessNotesReturnValue = [note]

        let witnessEntry = makeWitnessEntry()
        var fetchCount = 0
        let synchronizer = try await makeSynchronizer(
            rustBackend: rustBackend,
            transactionEncoder: transactionEncoder,
            syncStatus: .syncing(0.5, false),
            pirWitnessFetcher: { _, _, _ in
                fetchCount += 1
                return PIRWitnessResult(witnesses: [witnessEntry])
            }
        )

        var proposal = makeProposal()
        proposal.pirWitnessConfig = Proposal.PIRWitnessConfig(serverURL: "http://localhost:8080")
        let stream = try await synchronizer.createProposedTransactions(
            proposal: proposal,
            spendingKey: try makeSpendingKey(network: synchronizer.network)
        )

        var iterator = stream.makeAsyncIterator()
        let next = try await iterator.next()
        XCTAssertNil(next)
        XCTAssertEqual(fetchCount, 1, "Proactive alignment should fetch witnesses once")
        XCTAssertEqual(transactionEncoder.createProposedTransactionsCallsCount, 1)
        XCTAssertEqual(transactionEncoder.usePIRWitnessesHistory, [true])
        XCTAssertEqual(rustBackend.insertPIRWitnessesCallsCount, 1)
    }

    func testProactiveAlignmentSkippedWhenSynced() async throws {
        let rustBackend = ZcashRustBackendWeldingMock()
        let transactionEncoder = RetryTestTransactionEncoder()
        transactionEncoder.createResults = [.success([])]
        rustBackend.getPIRWitnessNotesReturnValue = [makeNotePosition()]

        let synchronizer = try await makeSynchronizer(
            rustBackend: rustBackend,
            transactionEncoder: transactionEncoder,
            syncStatus: .synced
        )

        var proposal = makeProposal()
        proposal.pirWitnessConfig = Proposal.PIRWitnessConfig(serverURL: "http://localhost:8080")
        let stream = try await synchronizer.createProposedTransactions(
            proposal: proposal,
            spendingKey: try makeSpendingKey(network: synchronizer.network)
        )

        var iterator = stream.makeAsyncIterator()
        _ = try await iterator.next()
        XCTAssertEqual(transactionEncoder.usePIRWitnessesHistory, [false])
        XCTAssertEqual(rustBackend.getPIRWitnessNotesCallsCount, 0, "Should not query notes when synced")
        XCTAssertEqual(rustBackend.insertPIRWitnessesCallsCount, 0)
    }

    func testProactiveAlignmentSkippedWithoutWitnessServerURL() async throws {
        let rustBackend = ZcashRustBackendWeldingMock()
        let transactionEncoder = RetryTestTransactionEncoder()
        transactionEncoder.createResults = [.success([])]

        let synchronizer = try await makeSynchronizer(
            rustBackend: rustBackend,
            transactionEncoder: transactionEncoder,
            syncStatus: .syncing(0.3, false)
        )

        let stream = try await synchronizer.createProposedTransactions(
            proposal: makeProposal(),
            spendingKey: try makeSpendingKey(network: synchronizer.network)
        )

        var iterator = stream.makeAsyncIterator()
        _ = try await iterator.next()
        XCTAssertEqual(transactionEncoder.usePIRWitnessesHistory, [false], "Should not use PIR witnesses without witness URL")
        XCTAssertEqual(rustBackend.getPIRWitnessNotesCallsCount, 0, "Should not query notes without witness URL")
    }

    func testWitnessInsertionIgnoresNonCanonicalEntries() async throws {
        let rustBackend = ZcashRustBackendWeldingMock()
        let transactionEncoder = RetryTestTransactionEncoder()
        transactionEncoder.createResults = [.success([])]

        let canonicalNote = PIRNotePosition(id: 5, position: 100, value: 50_000)
        let nonCanonicalNote = PIRNotePosition(id: -3, position: 200, value: 30_000)
        rustBackend.getPIRWitnessNotesReturnValue = [canonicalNote, nonCanonicalNote]

        let canonicalWitness = PIRWitnessEntry(
            noteId: 5,
            position: 100,
            siblings: Array(repeating: String(repeating: "aa", count: 32), count: 32),
            anchorHeight: 2_000,
            anchorRoot: String(repeating: "bb", count: 32)
        )
        let nonCanonicalWitness = PIRWitnessEntry(
            noteId: -3,
            position: 200,
            siblings: Array(repeating: String(repeating: "cc", count: 32), count: 32),
            anchorHeight: 2_000,
            anchorRoot: String(repeating: "dd", count: 32)
        )

        let synchronizer = try await makeSynchronizer(
            rustBackend: rustBackend,
            transactionEncoder: transactionEncoder,
            syncStatus: .syncing(0.5, false),
            pirWitnessFetcher: { _, _, _ in
                PIRWitnessResult(witnesses: [canonicalWitness, nonCanonicalWitness])
            }
        )

        var proposal = makeProposal()
        proposal.pirWitnessConfig = Proposal.PIRWitnessConfig(serverURL: "http://localhost:8080")
        let stream = try await synchronizer.createProposedTransactions(
            proposal: proposal,
            spendingKey: try makeSpendingKey(network: synchronizer.network)
        )

        var iterator = stream.makeAsyncIterator()
        _ = try await iterator.next()

        XCTAssertEqual(rustBackend.insertPIRWitnessesCallsCount, 1, "Canonical witness should use insertPIRWitnesses")
        XCTAssertEqual(
            rustBackend.insertPIRWitnessesReceivedWitnesses,
            [canonicalWitness],
            "Only canonical (positive ID) witnesses should be inserted in the minimal design"
        )
    }
}

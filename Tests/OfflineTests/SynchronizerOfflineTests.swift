//
//  SynchronizerOfflineTests.swift
//  
//
//  Created by Michal Fousek on 23.03.2023.
//

import Combine
import Foundation
@testable import TestUtils
import XCTest
@testable import ZcashLightClientKit

class SynchronizerOfflineTests: ZcashTestCase {
    let data = TestsData(networkType: .testnet)
    var network: ZcashNetwork!
    var cancellables: [AnyCancellable] = []

    override func setUp() async throws {
        try await super.setUp()
        network = ZcashNetworkBuilder.network(for: .testnet)
        cancellables = []
    }

    override func tearDown() async throws {
        try await super.tearDown()
        network = nil
        cancellables = []
    }

    func _testCallPrepareWithAlreadyUsedAliasThrowsError() async throws {
        // Pick a testnet height for which both Sapling and Orchard are active.
        let walletBirthday = 1900000

        let firstTestCoordinator = try await TestCoordinator(
            alias: .custom("alias"),
            container: mockContainer,
            walletBirthday: walletBirthday,
            network: network,
            callPrepareInConstructor: false
        )

        let secondTestCoordinator = try await TestCoordinator(
            alias: .custom("alias"),
            container: mockContainer,
            walletBirthday: walletBirthday,
            network: network,
            callPrepareInConstructor: false
        )

        do {
            _ = try await firstTestCoordinator.prepare(seed: Environment.seedBytes)
        } catch {
            XCTFail("Unpected fail. Prepare should succeed. \(error)")
        }

        do {
            _ = try await secondTestCoordinator.prepare(seed: Environment.seedBytes)
            XCTFail("Prepare should fail.")
        } catch { }
    }

    func testWhenSynchronizerIsDeallocatedAliasIsntUsedAnymore() async throws {
        // Pick a testnet height for which both Sapling and Orchard are active.
        let walletBirthday = 1900000

        var testCoordinator: TestCoordinator! = try await TestCoordinator(
            alias: .default,
            container: mockContainer,
            walletBirthday: walletBirthday,
            network: network,
            callPrepareInConstructor: false
        )

        do {
            _ = try await testCoordinator.prepare(seed: Environment.seedBytes)
        } catch {
            XCTFail("Unpected fail. Prepare should succeed. \(error)")
        }

        testCoordinator = try await TestCoordinator(
            alias: .default,
            container: mockContainer,
            walletBirthday: walletBirthday,
            network: network,
            callPrepareInConstructor: false
        )

        do {
            _ = try await testCoordinator.prepare(seed: Environment.seedBytes)
        } catch {
            XCTFail("Unpected fail. Prepare should succeed. \(error)")
        }
    }

    func _testCallWipeWithAlreadyUsedAliasThrowsError() async throws {
        // Pick a testnet height for which both Sapling and Orchard are active.
        let walletBirthday = 1900000

        let firstTestCoordinator = try await TestCoordinator(
            alias: .default,
            container: mockContainer,
            walletBirthday: walletBirthday,
            network: network,
            callPrepareInConstructor: false
        )

        let secondTestCoordinator = try await TestCoordinator(
            alias: .default,
            container: mockContainer,
            walletBirthday: walletBirthday,
            network: network,
            callPrepareInConstructor: false
        )

        let firstWipeExpectation = XCTestExpectation(description: "First wipe expectation")

        firstTestCoordinator.synchronizer.wipe()
            .sink(
                receiveCompletion: { result in
                    switch result {
                    case .finished:
                        firstWipeExpectation.fulfill()
                    case let .failure(error):
                        XCTFail("Unexpected error when calling wipe \(error)")
                    }
                },
                receiveValue: { _ in }
            )
            .store(in: &cancellables)

        await fulfillment(of: [firstWipeExpectation], timeout: 1)

        let secondWipeExpectation = XCTestExpectation(description: "Second wipe expectation")

        secondTestCoordinator.synchronizer.wipe()
            .sink(
                receiveCompletion: { result in
                    switch result {
                    case .finished:
                        XCTFail("Second wipe should fail with error.")
                    case let .failure(error):
                        if let error = error as? ZcashError, case .initializerAliasAlreadyInUse = error {
                            secondWipeExpectation.fulfill()
                        } else {
                            XCTFail("Wipe failed with unexpected error: \(error)")
                        }
                    }
                },
                receiveValue: { _ in }
            )
            .store(in: &cancellables)

        await fulfillment(of: [secondWipeExpectation], timeout: 1)
    }

    func testPrepareCanBeCalledAfterWipeWithSameInstanceOfSDKSynchronizer() async throws {
        // Pick a testnet height for which both Sapling and Orchard are active.
        let walletBirthday = 1900000

        let testCoordinator = try await TestCoordinator(
            alias: .default,
            container: mockContainer,
            walletBirthday: walletBirthday,
            network: network,
            callPrepareInConstructor: false
        )

        let expectation = XCTestExpectation(description: "Wipe expectation")

        testCoordinator.synchronizer.wipe()
            .sink(
                receiveCompletion: { result in
                    switch result {
                    case .finished:
                        expectation.fulfill()
                    case let .failure(error):
                        XCTFail("Unexpected error when calling wipe \(error)")
                    }
                },
                receiveValue: { _ in }
            )
            .store(in: &cancellables)

        await fulfillment(of: [expectation], timeout: 1)

        do {
            _ = try await testCoordinator.prepare(seed: Environment.seedBytes)
        } catch {
            XCTFail("Prepare after wipe should succeed.")
        }
    }

    func testRefreshUTXOCalledWithoutPrepareThrowsError() async throws {
        // Pick a testnet height for which both Sapling and Orchard are active.
        let walletBirthday = 1900000

        let testCoordinator = try await TestCoordinator(
            alias: .default,
            container: mockContainer,
            walletBirthday: walletBirthday,
            network: network,
            callPrepareInConstructor: false
        )

        do {
            _ = try await testCoordinator.synchronizer.refreshUTXOs(address: data.transparentAddress, from: 1)
            XCTFail("Shield funds should fail.")
        } catch {
            if let error = error as? ZcashError, case .synchronizerNotPrepared = error {
            } else {
                XCTFail("Shield funds failed with unexpected error: \(error)")
            }
        }
    }

    func testRewindCalledWithoutPrepareThrowsError() async throws {
        // Pick a testnet height for which both Sapling and Orchard are active.
        let walletBirthday = 1900000

        let testCoordinator = try await TestCoordinator(
            alias: .default,
            container: mockContainer,
            walletBirthday: walletBirthday,
            network: network,
            callPrepareInConstructor: false
        )

        let expectation = XCTestExpectation()

        testCoordinator.synchronizer.rewind(.quick)
            .sink(
                receiveCompletion: { result in
                    switch result {
                    case .finished:
                        XCTFail("Rewind should fail with error.")
                    case let .failure(error):
                        if let error = error as? ZcashError, case .synchronizerNotPrepared = error {
                            expectation.fulfill()
                        } else {
                            XCTFail("Rewind failed with unexpected error: \(error)")
                        }
                    }
                },
                receiveValue: { _ in }
            )
            .store(in: &cancellables)

        await fulfillment(of: [expectation], timeout: 1)
    }

    func testURLsParsingFailsInInitializerPrepareThenThrowsError() async throws {
        let validFileURL = URL(fileURLWithPath: "/some/valid/path/to.file")
        let validDirectoryURL = URL(fileURLWithPath: "/some/valid/path/to/directory")
        let invalidPathURL = URL(string: "https://whatever")!

        let initializer = Initializer(
            cacheDbURL: nil,
            fsBlockDbRoot: validDirectoryURL,
            generalStorageURL: validDirectoryURL,
            dataDbURL: invalidPathURL,
            torDirURL: validDirectoryURL,
            endpoint: LightWalletEndpointBuilder.default,
            network: ZcashNetworkBuilder.network(for: .testnet),
            spendParamsURL: validFileURL,
            outputParamsURL: validFileURL,
            saplingParamsSourceURL: .default,
            alias: .default,
            loggingPolicy: .default(.debug),
            isTorEnabled: false,
            isExchangeRateEnabled: false
        )

        XCTAssertNotNil(initializer.urlsParsingError)

        let synchronizer = SDKSynchronizer(initializer: initializer)

        do {
            _ = try await synchronizer.prepare(with: Environment.seedBytes, walletBirthday: 123000, for: .newWallet, name: "", keySource: nil)
            XCTFail("Failure of prepare is expected.")
        } catch {
            if let error = error as? ZcashError, case let .initializerCantUpdateURLWithAlias(failedURL) = error {
                XCTAssertEqual(failedURL, invalidPathURL)
            } else {
                XCTFail("Failed with unexpected error: \(error)")
            }
        }
    }

    func testURLsParsingFailsInInitializerWipeThenThrowsError() async throws {
        let validFileURL = URL(fileURLWithPath: "/some/valid/path/to.file")
        let validDirectoryURL = URL(fileURLWithPath: "/some/valid/path/to/directory")
        let invalidPathURL = URL(string: "https://whatever")!

        let initializer = Initializer(
            cacheDbURL: nil,
            fsBlockDbRoot: validDirectoryURL,
            generalStorageURL: validDirectoryURL,
            dataDbURL: invalidPathURL,
            torDirURL: validDirectoryURL,
            endpoint: LightWalletEndpointBuilder.default,
            network: ZcashNetworkBuilder.network(for: .testnet),
            spendParamsURL: validFileURL,
            outputParamsURL: validFileURL,
            saplingParamsSourceURL: .default,
            alias: .default,
            loggingPolicy: .default(.debug),
            isTorEnabled: false,
            isExchangeRateEnabled: false
        )

        XCTAssertNotNil(initializer.urlsParsingError)

        let synchronizer = SDKSynchronizer(initializer: initializer)
        let expectation = XCTestExpectation()

        synchronizer.wipe()
            .sink(
                receiveCompletion: { result in
                    switch result {
                    case .finished:
                        XCTFail("Failure of wipe is expected.")
                    case let .failure(error):
                        if let error = error as? ZcashError, case let .initializerCantUpdateURLWithAlias(failedURL) = error {
                            XCTAssertEqual(failedURL, invalidPathURL)
                            expectation.fulfill()
                        } else {
                            XCTFail("Failed with unexpected error: \(error)")
                        }
                    }
                },
                receiveValue: { _ in }
            )
            .store(in: &cancellables)

        await fulfillment(of: [expectation], timeout: 1)
    }

    func testIsNewSessionOnUnpreparedToValidTransition() {
        XCTAssertTrue(SessionTicker.live.isNewSyncSession(.unprepared, .syncing(0, false)))
    }

    func testIsNotNewSessionOnUnpreparedToStateThatWontSync() {
        XCTAssertFalse(SessionTicker.live.isNewSyncSession(.unprepared, .disconnected))
        XCTAssertFalse(SessionTicker.live.isNewSyncSession(.unprepared, .unprepared))
    }

    func testIsNotNewSessionOnUnpreparedToInvalidOrUnexpectedTransitions() {
        XCTAssertFalse(SessionTicker.live.isNewSyncSession(.unprepared, .synced))
    }

    func testIsNotNewSyncSessionOnSameSession() {
        XCTAssertFalse(
            SessionTicker.live.isNewSyncSession(
                .syncing(0.5, false),
                .syncing(0.6, false)
            )
        )
    }

    func testIsNewSyncSessionWhenStartingFromSynced() {
        XCTAssertTrue(
            SessionTicker.live.isNewSyncSession(
                .synced,
                .syncing(0.6, false)
            )
        )
    }

    func testIsNewSyncSessionWhenStartingFromDisconnected() {
        XCTAssertTrue(
            SessionTicker.live.isNewSyncSession(
                .disconnected,
                .syncing(0.6, false)
            )
        )
    }

    func testIsNewSyncSessionWhenStartingFromStopped() {
        XCTAssertTrue(
            SessionTicker.live.isNewSyncSession(
                .stopped,
                .syncing(0.6, false)
            )
        )
    }

    func testInternalSyncStatusesDontDifferWhenOuterStatusIsTheSame() {
        XCTAssertFalse(InternalSyncStatus.disconnected.isDifferent(from: .disconnected))
        XCTAssertFalse(InternalSyncStatus.syncing(0, false).isDifferent(from: .syncing(0, false)))
        XCTAssertFalse(InternalSyncStatus.stopped.isDifferent(from: .stopped))
        XCTAssertFalse(InternalSyncStatus.synced.isDifferent(from: .synced))
        XCTAssertFalse(InternalSyncStatus.unprepared.isDifferent(from: .unprepared))
    }
    
    func testInternalSyncStatusMap_SyncingLowerBound() {
        let synchronizerState = synchronizerState(
            for:
                InternalSyncStatus.syncing(0, false)
        )

        if case let .syncing(data, false) = synchronizerState.syncStatus, data != nextafter(0.0, data) {
            XCTFail("Syncing is expected to be 0% (0.0) but received \(data).")
        }
    }

    func testInternalSyncStatusMap_SyncingInTheMiddle() {
        let synchronizerState = synchronizerState(
            for:
                InternalSyncStatus.syncing(0.45, false)
        )

        if case let .syncing(data, false) = synchronizerState.syncStatus, data != nextafter(0.45, data) {
            XCTFail("Syncing is expected to be 45% (0.45) but received \(data).")
        }
    }

    func testInternalSyncStatusMap_SyncingUpperBound() {
        let synchronizerState = synchronizerState(
            for:
                InternalSyncStatus.syncing(0.9, false)
        )

        if case let .syncing(data, false) = synchronizerState.syncStatus, data != nextafter(0.9, data) {
            XCTFail("Syncing is expected to be 90% (0.9) but received \(data).")
        }
    }
    
    func testInternalSyncStatusMap_FetchingUpperBound() {
        let synchronizerState = synchronizerState(for: InternalSyncStatus.syncing(1, false))

        if case let .syncing(data, false) = synchronizerState.syncStatus, data != nextafter(1.0, data) {
            XCTFail("Syncing is expected to be 100% (1.0) but received \(data).")
        }
    }

    func testSynchronizerStateZeroHasZeroFullyScannedHeight() {
        XCTAssertEqual(SynchronizerState.zero.fullyScannedHeight, .zero)
    }

    func testSynchronizerStateInitPreservesFullyScannedHeight() {
        let state = SynchronizerState(
            syncSessionID: .nullID,
            accountsBalances: [:],
            internalSyncStatus: .syncing(0, false),
            latestBlockHeight: 222_222,
            fullyScannedHeight: 100_000
        )

        XCTAssertEqual(state.fullyScannedHeight, 100_000)
    }

    // Regression guard: `fullyScannedHeight` is a *separate* dimension of `SynchronizerState`
    // from `latestBlockHeight`. Callers (e.g. shielded-vote snapshot gating) rely on receiving
    // a state-stream update whenever `fullyScannedHeight` advances, even if no other field
    // changes. If `Equatable` ever stops distinguishing this field — e.g. because someone
    // reorders the stored properties so the synthesised `==` excludes it — upstream
    // deduplication (`removeDuplicates`, `Publisher.removeDuplicates`, `CurrentValueSubject`
    // dedup) would silently swallow those updates.
    func testSynchronizerStateEquatableDistinguishesFullyScannedHeight() {
        let lhs = SynchronizerState(
            syncSessionID: .nullID,
            accountsBalances: [:],
            internalSyncStatus: .syncing(0.5, false),
            latestBlockHeight: 222_222,
            fullyScannedHeight: 100_000
        )
        let rhs = SynchronizerState(
            syncSessionID: .nullID,
            accountsBalances: [:],
            internalSyncStatus: .syncing(0.5, false),
            latestBlockHeight: 222_222,
            fullyScannedHeight: 120_000
        )

        XCTAssertNotEqual(lhs, rhs)
    }

    // The public `Synchronizer.getTreeState(height:)` accessor is the whole point
    // of exposing tree-state retrieval to app-layer code. These tests pin down the
    // shape of the protocol requirement by exercising the Sourcery-generated
    // `SynchronizerMock`: a regression in the requirement's signature, or in the
    // mock generator's handling of it, would break out-of-repo consumers that
    // mock the synchronizer in their own tests.
    func testSynchronizerGetTreeStatePassesHeightAndReturnsConfiguredData() async throws {
        let mock = SynchronizerMock()
        let expectedBytes = Data([0x01, 0x02, 0x03, 0x04])
        mock.getTreeStateHeightReturnValue = expectedBytes

        let result = try await mock.getTreeState(height: 2_400_000)

        XCTAssertEqual(result, expectedBytes)
        XCTAssertEqual(mock.getTreeStateHeightCallsCount, 1)
        XCTAssertEqual(mock.getTreeStateHeightReceivedHeight, 2_400_000)
    }

    func testSynchronizerGetTreeStatePropagatesError() async {
        struct BoomError: Error, Equatable {}
        let mock = SynchronizerMock()
        mock.getTreeStateHeightThrowableError = BoomError()

        do {
            _ = try await mock.getTreeState(height: 1_234_567)
            XCTFail("getTreeState was expected to throw")
        } catch let error as BoomError {
            XCTAssertEqual(error, BoomError())
        } catch {
            XCTFail("Unexpected error type \(error)")
        }
    }

    func synchronizerState(for internalSyncStatus: InternalSyncStatus) -> SynchronizerState {
        SynchronizerState(
            syncSessionID: .nullID,
            accountsBalances: [:],
            internalSyncStatus: internalSyncStatus,
            latestBlockHeight: .zero,
            fullyScannedHeight: .zero
        )
    }
}

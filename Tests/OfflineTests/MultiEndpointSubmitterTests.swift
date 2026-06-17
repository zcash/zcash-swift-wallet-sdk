//
//  MultiEndpointSubmitterTests.swift
//  ZcashLightClientKitTests
//

import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

final class MultiEndpointSubmitterTests: ZcashTestCase {
    private var mock: EndpointSubmitterMock!
    private var submitter: MultiEndpointSubmitter!

    override func setUp() async throws {
        try await super.setUp()
        mock = EndpointSubmitterMock()
        submitter = MultiEndpointSubmitter(endpointSubmitter: mock, logger: submissionLifecycleLogger())
    }

    private let fastTiming = SubmissionTiming(responseTimeout: 1.0, postAcceptanceGraceDelay: 0.3)

    private func endpoint(_ index: Int) -> LightWalletEndpoint {
        LightWalletEndpoint(address: "server\(index).example.com", port: 9067, secure: true)
    }

    private func makeTransaction() -> CreatedTransaction {
        CreatedTransaction(
            txId: Data(repeating: 0xAB, count: 32),
            raw: Data([0x01, 0x02, 0x03]),
            expiryHeight: 123_456
        )
    }

    func testEmptyEndpointListIsUnreachable() async {
        let outcome = await submitter.submit(transaction: makeTransaction(), to: [], timing: fastTiming)
        XCTAssertEqual(outcome, TransactionSubmissionOutcome.unreachable)
        XCTAssertTrue(mock.recordedSubmissions().isEmpty)
    }

    func testFirstSuccessWinsAndAllEndpointsAreAttempted() async {
        let endpoints = [endpoint(1), endpoint(2), endpoint(3)]
        mock.set(behavior: .succeed, for: endpoint(1))
        mock.set(behavior: .succeed, for: endpoint(2))
        mock.set(behavior: .succeed, for: endpoint(3))

        let outcome = await submitter.submit(transaction: makeTransaction(), to: endpoints, timing: fastTiming)

        guard case let .accepted(winner) = outcome else {
            XCTFail("Expected accepted, got \(outcome)")
            return
        }
        XCTAssertTrue(endpoints.contains(winner))
        XCTAssertEqual(mock.recordedSubmissions().count, 3)
    }

    func testAllRejectedReturnsFirstRejection() async {
        let endpoints = [endpoint(1), endpoint(2)]
        mock.set(behavior: .reject(code: -25, message: "first"), for: endpoint(1))
        mock.set(behavior: .reject(code: -26, message: "second"), for: endpoint(2))

        let outcome = await submitter.submit(transaction: makeTransaction(), to: endpoints, timing: fastTiming)

        guard case let .rejected(code, _) = outcome else {
            XCTFail("Expected rejected, got \(outcome)")
            return
        }
        // Either rejection can win the race to the actor; both are valid "first" rejections.
        XCTAssertTrue([-25, -26].contains(code))
    }

    func testAllTransportFailuresAreUnreachable() async {
        let endpoints = [endpoint(1), endpoint(2)]
        mock.set(behavior: .failTransport, for: endpoint(1))
        mock.set(behavior: .failTransport, for: endpoint(2))

        let outcome = await submitter.submit(transaction: makeTransaction(), to: endpoints, timing: fastTiming)

        XCTAssertEqual(outcome, TransactionSubmissionOutcome.unreachable)
    }

    func testMixedRejectionAndTransportFailureIsRejected() async {
        let endpoints = [endpoint(1), endpoint(2)]
        mock.set(behavior: .failTransport, for: endpoint(1))
        mock.set(behavior: .reject(code: -25, message: "bad tx"), for: endpoint(2))

        let outcome = await submitter.submit(transaction: makeTransaction(), to: endpoints, timing: fastTiming)

        XCTAssertEqual(outcome, TransactionSubmissionOutcome.rejected(code: -25, message: "bad tx"))
    }

    func testSuccessWithHangingEndpointResolvesImmediatelyAndCancelsAfterGrace() async {
        let endpoints = [endpoint(1), endpoint(2)]
        mock.set(behavior: .succeed, for: endpoint(1))
        mock.set(behavior: .hang, for: endpoint(2))
        // Generous margins: these asserts compare wall-clock times and must
        // survive multi-hundred-millisecond stalls on loaded CI machines.
        let timing = SubmissionTiming(responseTimeout: 5.0, postAcceptanceGraceDelay: 1.5)

        let start = Date()
        let outcome = await submitter.submit(transaction: makeTransaction(), to: endpoints, timing: timing)
        let elapsed = Date().timeIntervalSince(start)

        XCTAssertEqual(outcome, TransactionSubmissionOutcome.accepted(by: endpoint(1)))
        // Caller resumes at the first acceptance — well before the 5s timeout.
        XCTAssertLessThan(elapsed, 1.0)

        // Still inside the 1.5s grace window: the straggler must not be cancelled yet.
        try? await Task.sleep(nanoseconds: 200_000_000)
        XCTAssertTrue(mock.recordedCancellations().isEmpty, "Straggler must keep running through the grace window")

        // The hanging straggler gets cancelled once the grace window ends.
        try? await Task.sleep(nanoseconds: 2_300_000_000)
        XCTAssertEqual(mock.recordedCancellations().map(\.host), [endpoint(2).host])
    }

    func testStragglerSuccessDuringGraceIsAllowedToFinish() async {
        let endpoints = [endpoint(1), endpoint(2)]
        mock.set(behavior: .succeed, for: endpoint(1))
        mock.set(behavior: .succeedAfter(0.2), for: endpoint(2))
        // The straggler finishes at ~0.2s, far inside the 1.5s grace window
        // even with CI scheduling stalls.
        let timing = SubmissionTiming(responseTimeout: 5.0, postAcceptanceGraceDelay: 1.5)

        let outcome = await submitter.submit(transaction: makeTransaction(), to: endpoints, timing: timing)

        XCTAssertEqual(outcome, TransactionSubmissionOutcome.accepted(by: endpoint(1)))

        // Wait past the straggler's completion; it must not have been cancelled.
        try? await Task.sleep(nanoseconds: 700_000_000)
        XCTAssertTrue(mock.recordedCancellations().isEmpty)
    }

    func testTimeoutWithNoResponses() async {
        let endpoints = [endpoint(1), endpoint(2)]
        mock.set(behavior: .hang, for: endpoint(1))
        mock.set(behavior: .hang, for: endpoint(2))
        let timing = SubmissionTiming(responseTimeout: 0.2, postAcceptanceGraceDelay: 0.1)

        let outcome = await submitter.submit(transaction: makeTransaction(), to: endpoints, timing: timing)

        XCTAssertEqual(outcome, TransactionSubmissionOutcome.timedOut)
    }

    func testRejectionsThenHangTimesOut() async {
        // One endpoint rejects, the other never answers: not all endpoints
        // completed, so the timer decides — timeout, not rejection.
        let endpoints = [endpoint(1), endpoint(2)]
        mock.set(behavior: .reject(code: -25, message: "bad"), for: endpoint(1))
        mock.set(behavior: .hang, for: endpoint(2))
        let timing = SubmissionTiming(responseTimeout: 0.2, postAcceptanceGraceDelay: 0.1)

        let outcome = await submitter.submit(transaction: makeTransaction(), to: endpoints, timing: timing)

        XCTAssertEqual(outcome, TransactionSubmissionOutcome.timedOut)
    }

    func testCallerCancellationCancelsAllSubmissions() async {
        let endpoints = [endpoint(1), endpoint(2)]
        mock.set(behavior: .hang, for: endpoint(1))
        mock.set(behavior: .hang, for: endpoint(2))
        let transaction = makeTransaction()
        let timing = fastTiming
        let submitter = self.submitter!

        let task = Task { () -> TransactionSubmissionOutcome in
            await submitter.submit(transaction: transaction, to: endpoints, timing: timing)
        }

        // Give the race time to start both submissions, then cancel.
        try? await Task.sleep(nanoseconds: 100_000_000)
        task.cancel()
        let outcome = await task.value

        XCTAssertEqual(outcome, TransactionSubmissionOutcome.cancelled)

        try? await Task.sleep(nanoseconds: 200_000_000)
        XCTAssertEqual(mock.recordedCancellations().count, 2)
    }

    func testCallerCancellationReleasesCallerWhileChildIgnoresCancellation() async {
        // Simulates the Tor path: the child sits in blocking FFI that ignores
        // task cancellation. The caller must still be released at cancellation
        // time, not when the stuck child finally returns (3s) and not at the
        // response timeout (5s).
        mock.set(behavior: .hangUncancellable(3.0), for: endpoint(1))
        let transaction = makeTransaction()
        let timing = SubmissionTiming(responseTimeout: 5.0, postAcceptanceGraceDelay: 0.1)
        let submitter = self.submitter!

        let start = Date()
        let task = Task { () -> TransactionSubmissionOutcome in
            await submitter.submit(transaction: transaction, to: [endpoint(1)], timing: timing)
        }
        try? await Task.sleep(nanoseconds: 100_000_000)
        task.cancel()
        let outcome = await task.value
        let elapsed = Date().timeIntervalSince(start)

        XCTAssertEqual(outcome, TransactionSubmissionOutcome.cancelled)
        XCTAssertLessThan(elapsed, 1.5)
    }

    func testLateRejectionAfterCancellationStaysCancelled() async {
        // A rejection already in flight when the caller cancels must not
        // replace the `.cancelled` outcome, regardless of arrival order.
        let endpoints = [endpoint(1), endpoint(2)]
        mock.set(behavior: .rejectAfter(0.4, code: -25, message: "late"), for: endpoint(1))
        mock.set(behavior: .hangUncancellable(2.0), for: endpoint(2))
        let transaction = makeTransaction()
        let timing = SubmissionTiming(responseTimeout: 5.0, postAcceptanceGraceDelay: 0.1)
        let submitter = self.submitter!

        let task = Task { () -> TransactionSubmissionOutcome in
            await submitter.submit(transaction: transaction, to: endpoints, timing: timing)
        }
        try? await Task.sleep(nanoseconds: 100_000_000)
        task.cancel()
        let outcome = await task.value

        XCTAssertEqual(outcome, TransactionSubmissionOutcome.cancelled)
    }

    func testSingleEndpointAcceptanceFinishesWithoutLingeringGrace() async {
        mock.set(behavior: .succeed, for: endpoint(1))

        let outcome = await submitter.submit(transaction: makeTransaction(), to: [endpoint(1)], timing: fastTiming)

        XCTAssertEqual(outcome, TransactionSubmissionOutcome.accepted(by: endpoint(1)))

        // The lone success completes the race immediately; nothing is left to cancel.
        try? await Task.sleep(nanoseconds: 200_000_000)
        XCTAssertTrue(mock.recordedCancellations().isEmpty)
        XCTAssertEqual(mock.recordedSubmissions().count, 1)
    }

    func testSingleEndpointRejectionIsRejected() async {
        mock.set(behavior: .reject(code: -25, message: "bad tx"), for: endpoint(1))

        let outcome = await submitter.submit(transaction: makeTransaction(), to: [endpoint(1)], timing: fastTiming)

        XCTAssertEqual(outcome, TransactionSubmissionOutcome.rejected(code: -25, message: "bad tx"))
    }
}

//
//  EndpointSubmitterTests.swift
//  ZcashLightClientKitTests
//

import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

final class EndpointSubmitterTests: ZcashTestCase {
    private func makeSubmitter() throws -> GRPCEndpointSubmitter {
        GRPCEndpointSubmitter(
            torClient: TorClient(torDir: try __torDirURL()),
            sdkFlags: SDKFlags(torEnabled: false, exchangeRateEnabled: false),
            logger: submissionLifecycleLogger()
        )
    }

    private func makeTransaction() -> CreatedTransaction {
        CreatedTransaction(
            txId: Data(repeating: 0xAB, count: 32),
            raw: Data([0x01, 0x02, 0x03, 0x04]),
            expiryHeight: 123_456
        )
    }

    private func makeSendResponse(errorCode: Int32, errorMessage: String) -> SendResponse {
        var response = SendResponse()
        response.errorCode = errorCode
        response.errorMessage = errorMessage
        return response
    }

    func testSubmitDeliversRawBytesToEndpoint() async throws {
        let service = try RecordingCompactTxStreamerService(sendResponse: makeSendResponse(errorCode: 0, errorMessage: ""))
        defer { try? service.stop() }
        let submitter = try makeSubmitter()
        let transaction = makeTransaction()

        try await submitter.submit(transaction: transaction, to: service.endpoint)

        XCTAssertEqual(service.recordedTransactions(), [transaction.raw])
    }

    func testSubmitThrowsSubmitErrorOnServerRejection() async throws {
        let service = try RecordingCompactTxStreamerService(sendResponse: makeSendResponse(errorCode: -25, errorMessage: "rejected"))
        defer { try? service.stop() }
        let submitter = try makeSubmitter()

        do {
            try await submitter.submit(transaction: makeTransaction(), to: service.endpoint)
            XCTFail("Expected submitError")
        } catch let TransactionEncoderError.submitError(code, message) {
            XCTAssertEqual(code, -25)
            XCTAssertEqual(message, "rejected")
        }
    }

    func testSubmitThrowsTransportErrorForUnreachableEndpoint() async throws {
        let submitter = try makeSubmitter()
        // Nothing listens on this port; expect a transport-level failure.
        let endpoint = LightWalletEndpoint(
            address: "127.0.0.1",
            port: 1,
            secure: false,
            singleCallTimeoutInMillis: 2_000,
            streamingCallTimeoutInMillis: 2_000
        )

        do {
            try await submitter.submit(transaction: makeTransaction(), to: endpoint)
            XCTFail("Expected a transport error")
        } catch let TransactionEncoderError.submitError(code, message) {
            XCTFail("Expected a transport error, not a server rejection: \(code) \(message)")
        } catch {
            // Any non-submitError error is the expected transport failure.
        }
    }
}

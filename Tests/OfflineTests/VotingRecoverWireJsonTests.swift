//
//  VotingRecoverWireJsonTests.swift
//  ZcashLightClientKitTests
//

import XCTest
@testable import ZcashLightClientKit

private let recoverProposalId: UInt32 = 1
private let recoverShareIndex: UInt32 = 0
private let recoverConfirmedPosition: UInt64 = 999
private let recoverSubmitAt: UInt64 = 123

final class VotingRecoverWireJsonTests: XCTestCase {
    func test_recoverWireJson_malformedBundleJson_throwsRustError() {
        XCTAssertThrowsError(
            try VotingRustBackend.recoverWireJson(
                commitmentBundleJson: "not json",
                proposalId: recoverProposalId,
                shareIndex: recoverShareIndex,
                voteCommitmentTreePosition: recoverConfirmedPosition,
                submitAt: recoverSubmitAt
            )
        ) { error in
            guard case VotingRustBackendError.rustError(let message) = error else {
                XCTFail("expected .rustError, got \(error.localizedDescription)")
                return
            }
            XCTAssertTrue(
                message.contains("recover_wire_json failed"),
                "unexpected message: \(message)"
            )
        }
    }

    func test_recoverWireJson_emptyBundleJson_throwsRustError() {
        XCTAssertThrowsError(
            try VotingRustBackend.recoverWireJson(
                commitmentBundleJson: "",
                proposalId: recoverProposalId,
                shareIndex: recoverShareIndex,
                voteCommitmentTreePosition: recoverConfirmedPosition,
                submitAt: recoverSubmitAt
            )
        ) { error in
            guard case VotingRustBackendError.rustError(let message) = error else {
                XCTFail("expected .rustError, got \(error.localizedDescription)")
                return
            }
            XCTAssertTrue(
                message.contains("recover_wire_json failed"),
                "unexpected message: \(message)"
            )
        }
    }
}

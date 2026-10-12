//
//  VotingConfirmVoteSubmissionTests.swift
//  ZcashLightClientKitTests
//

import XCTest
@testable import ZcashLightClientKit

/// Builds a round identifier that satisfies the Rust round-parameter validation,
/// which requires 64 lowercase hex characters encoding a canonical Pallas field
/// element. `tag` occupies the low byte so each caller gets a distinct round.
private func hexRoundId(_ tag: UInt8) -> String {
    String(format: "%02x", tag) + String(repeating: "00", count: 31)
}

/// A well-formed round identifier that is never initialized, so the crate has no
/// vote row to confirm against.
private let confirmMissingRoundId = hexRoundId(0xfd)
private let confirmTxHash = "vote-tx-hash"
/// One well-formed `cast_vote` event, shaped exactly as
/// `Vec<zcash_voting::confirmation::TxEvent>` deserializes it. The FFI must hand
/// it to the crate unparsed — the SDK never splits `leaf_index` itself.
private let confirmEventsJson = """
[{"type":"cast_vote","attributes":[\
{"key":"vote_round_id","value":"\(confirmMissingRoundId)"},\
{"key":"leaf_index","value":"7,42"}]}]
"""

final class VotingConfirmVoteSubmissionTests: XCTestCase {
    func test_confirmVoteSubmission_beforeOpen_throwsDatabaseNotOpen() {
        let backend = VotingRustBackend()

        XCTAssertThrowsError(
            try backend.confirmVoteSubmission(
                roundId: confirmMissingRoundId,
                bundleIndex: 0,
                proposalId: 1,
                txHash: confirmTxHash,
                eventsJson: confirmEventsJson
            )
        ) { error in
            guard case VotingRustBackendError.databaseNotOpen = error else {
                XCTFail("expected .databaseNotOpen, got \(error.localizedDescription)")
                return
            }
        }
    }
}

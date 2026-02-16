//
//  Eip681Tests.swift
//  ZcashLightClientKit-Unit-Tests
//

import XCTest
@testable import ZcashLightClientKit

class Eip681Tests: XCTestCase {
    // MARK: - Native transfer parsing

    func testParseNativeTransfer() throws {
        let uri = "ethereum:0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359?value=2.014e18"
        let result = try ZcashEip681Backend.parseTransactionRequest(uri)

        guard case let .native(native) = result else {
            XCTFail("Expected .native, got \(result)")
            return
        }

        XCTAssertEqual(native.schemaPrefix, "ethereum")
        XCTAssertNil(native.chainId)
        XCTAssertEqual(native.recipientAddress, "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359")
        XCTAssertNotNil(native.valueHex)
        XCTAssertNil(native.gasLimitHex)
        XCTAssertNil(native.gasPriceHex)
    }

    func testParseNativeTransferWithChainId() throws {
        let uri = "ethereum:0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359@1?value=1e18"
        let result = try ZcashEip681Backend.parseTransactionRequest(uri)

        guard case let .native(native) = result else {
            XCTFail("Expected .native, got \(result)")
            return
        }

        XCTAssertEqual(native.chainId, 1)
    }

    func testParseNativeTransferWithoutValue() throws {
        let uri = "ethereum:0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
        let result = try ZcashEip681Backend.parseTransactionRequest(uri)

        guard case let .native(native) = result else {
            XCTFail("Expected .native, got \(result)")
            return
        }

        XCTAssertEqual(native.recipientAddress, "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359")
        XCTAssertNil(native.valueHex)
        XCTAssertNil(native.gasLimitHex)
        XCTAssertNil(native.gasPriceHex)
    }

    func testParseNativeTransferWithGasParams() throws {
        let uri = "ethereum:0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359?value=1e18&gasLimit=21000&gasPrice=20e9"
        let result = try ZcashEip681Backend.parseTransactionRequest(uri)

        guard case let .native(native) = result else {
            XCTFail("Expected .native, got \(result)")
            return
        }

        XCTAssertNotNil(native.valueHex)
        XCTAssertNotNil(native.gasLimitHex)
        XCTAssertNotNil(native.gasPriceHex)
    }

    // MARK: - ERC-20 transfer parsing

    func testParseErc20Transfer() throws {
        let uri = "ethereum:0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/transfer?address=0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359&uint256=1000000"
        let result = try ZcashEip681Backend.parseTransactionRequest(uri)

        guard case let .erc20(erc20) = result else {
            XCTFail("Expected .erc20, got \(result)")
            return
        }

        XCTAssertNil(erc20.chainId)
        XCTAssertEqual(erc20.tokenContractAddress, "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
        XCTAssertEqual(erc20.recipientAddress, "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359")
        XCTAssertNotNil(erc20.valueHex)
    }

    func testParseErc20TransferWithChainId() throws {
        let uri = "ethereum:0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48@1/transfer?address=0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359&uint256=1000000"
        let result = try ZcashEip681Backend.parseTransactionRequest(uri)

        guard case let .erc20(erc20) = result else {
            XCTFail("Expected .erc20, got \(result)")
            return
        }

        XCTAssertEqual(erc20.chainId, 1)
    }

    // MARK: - Error handling

    func testParseInvalidUri() {
        XCTAssertThrowsError(try ZcashEip681Backend.parseTransactionRequest("not-a-valid-uri")) { error in
            guard let zcashError = error as? ZcashError else {
                XCTFail("Expected ZcashError, got \(error)")
                return
            }
            XCTAssertEqual(zcashError.code, .rustEip681Parse)
        }
    }

    func testParseEmptyString() {
        XCTAssertThrowsError(try ZcashEip681Backend.parseTransactionRequest("")) { error in
            guard let zcashError = error as? ZcashError else {
                XCTFail("Expected ZcashError, got \(error)")
                return
            }
            XCTAssertEqual(zcashError.code, .rustEip681Parse)
        }
    }

    // MARK: - Serialization

    func testTransactionRequestToUri() throws {
        let input = "ethereum:0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359?value=2.014e18"
        let output = try ZcashEip681Backend.transactionRequestToUri(input)

        XCTAssertFalse(output.isEmpty)
        XCTAssertTrue(output.hasPrefix("ethereum:"))
        XCTAssertTrue(output.contains("0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"))
    }

    func testRoundTripNativeTransfer() throws {
        let input = "ethereum:0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359?value=2.014e18"
        let serialized = try ZcashEip681Backend.transactionRequestToUri(input)
        let firstParse = try ZcashEip681Backend.parseTransactionRequest(input)
        let secondParse = try ZcashEip681Backend.parseTransactionRequest(serialized)

        XCTAssertEqual(firstParse, secondParse)
    }

    func testRoundTripErc20Transfer() throws {
        let input = "ethereum:0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/transfer?address=0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359&uint256=1000000"
        let serialized = try ZcashEip681Backend.transactionRequestToUri(input)
        let firstParse = try ZcashEip681Backend.parseTransactionRequest(input)
        let secondParse = try ZcashEip681Backend.parseTransactionRequest(serialized)

        XCTAssertEqual(firstParse, secondParse)
    }
}

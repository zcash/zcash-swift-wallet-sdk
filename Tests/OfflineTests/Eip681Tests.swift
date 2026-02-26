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
        XCTAssertFalse(native.hasPay)
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

        XCTAssertEqual(erc20.schemaPrefix, "ethereum")
        XCTAssertFalse(erc20.hasPay)
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

    // MARK: - Construction from parts (native)

    func testCreateNativeTransactionRequestBasic() throws {
        let result = try ZcashEip681Backend.createNativeTransactionRequest(
            schemaPrefix: "ethereum",
            hasPay: false,
            chainId: nil,
            recipientAddress: "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            valueHex: "0xde0b6b3a7640000",
            gasLimitHex: nil,
            gasPriceHex: nil
        )

        guard case let .native(native) = result else {
            XCTFail("Expected .native, got \(result)")
            return
        }

        XCTAssertEqual(native.schemaPrefix, "ethereum")
        XCTAssertFalse(native.hasPay)
        XCTAssertNil(native.chainId)
        XCTAssertEqual(native.recipientAddress, "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359")
        XCTAssertEqual(native.valueHex, "0xde0b6b3a7640000")
    }

    func testCreateNativeTransactionRequestWithAllParams() throws {
        let result = try ZcashEip681Backend.createNativeTransactionRequest(
            schemaPrefix: "ethereum",
            hasPay: true,
            chainId: 1,
            recipientAddress: "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            valueHex: "0xde0b6b3a7640000",
            gasLimitHex: "0x5208",
            gasPriceHex: "0x4a817c800"
        )

        guard case let .native(native) = result else {
            XCTFail("Expected .native, got \(result)")
            return
        }

        XCTAssertEqual(native.schemaPrefix, "ethereum")
        XCTAssertTrue(native.hasPay)
        XCTAssertEqual(native.chainId, 1)
        XCTAssertEqual(native.recipientAddress, "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359")
        XCTAssertNotNil(native.valueHex)
        XCTAssertNotNil(native.gasLimitHex)
        XCTAssertNotNil(native.gasPriceHex)
    }

    func testCreateNativeTransactionRequestWithoutValue() throws {
        let result = try ZcashEip681Backend.createNativeTransactionRequest(
            schemaPrefix: "ethereum",
            hasPay: false,
            chainId: nil,
            recipientAddress: "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            valueHex: nil,
            gasLimitHex: nil,
            gasPriceHex: nil
        )

        guard case let .native(native) = result else {
            XCTFail("Expected .native, got \(result)")
            return
        }

        XCTAssertNil(native.valueHex)
        XCTAssertNil(native.gasLimitHex)
        XCTAssertNil(native.gasPriceHex)
    }

    // MARK: - Construction from parts (ERC-20)

    func testCreateErc20TransactionRequestBasic() throws {
        let result = try ZcashEip681Backend.createErc20TransactionRequest(
            schemaPrefix: "ethereum",
            hasPay: false,
            chainId: nil,
            tokenContractAddress: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            recipientAddress: "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            valueHex: "0xf4240"
        )

        guard case let .erc20(erc20) = result else {
            XCTFail("Expected .erc20, got \(result)")
            return
        }

        XCTAssertEqual(erc20.schemaPrefix, "ethereum")
        XCTAssertFalse(erc20.hasPay)
        XCTAssertNil(erc20.chainId)
        XCTAssertEqual(erc20.tokenContractAddress, "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
        XCTAssertEqual(erc20.recipientAddress, "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359")
        XCTAssertEqual(erc20.valueHex, "0xf4240")
    }

    func testCreateErc20TransactionRequestWithChainId() throws {
        let result = try ZcashEip681Backend.createErc20TransactionRequest(
            schemaPrefix: "ethereum",
            hasPay: false,
            chainId: 1,
            tokenContractAddress: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            recipientAddress: "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            valueHex: "0xf4240"
        )

        guard case let .erc20(erc20) = result else {
            XCTFail("Expected .erc20, got \(result)")
            return
        }

        XCTAssertEqual(erc20.chainId, 1)
    }

    // MARK: - Round-trip: construct from parts -> serialize -> parse

    func testRoundTripNativeFromParts() throws {
        let created = try ZcashEip681Backend.createNativeTransactionRequest(
            schemaPrefix: "ethereum",
            hasPay: false,
            chainId: 1,
            recipientAddress: "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            valueHex: "0xde0b6b3a7640000",
            gasLimitHex: "0x5208",
            gasPriceHex: nil
        )

        guard case let .native(native) = created else {
            XCTFail("Expected .native, got \(created)")
            return
        }

        // Serialize and re-parse to verify round-trip fidelity
        let uri = try ZcashEip681Backend.transactionRequestToUri(
            "ethereum:0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359@1?value=1000000000000000000&gasLimit=21000"
        )
        let parsed = try ZcashEip681Backend.parseTransactionRequest(uri)

        guard case let .native(parsedNative) = parsed else {
            XCTFail("Expected .native after round-trip, got \(parsed)")
            return
        }

        XCTAssertEqual(native.schemaPrefix, parsedNative.schemaPrefix)
        XCTAssertEqual(native.hasPay, parsedNative.hasPay)
        XCTAssertEqual(native.chainId, parsedNative.chainId)
        XCTAssertEqual(native.recipientAddress, parsedNative.recipientAddress)
    }

    func testRoundTripErc20FromParts() throws {
        let created = try ZcashEip681Backend.createErc20TransactionRequest(
            schemaPrefix: "ethereum",
            hasPay: false,
            chainId: nil,
            tokenContractAddress: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            recipientAddress: "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            valueHex: "0xf4240"
        )

        guard case let .erc20(erc20) = created else {
            XCTFail("Expected .erc20, got \(created)")
            return
        }

        // Parse the equivalent URI and compare
        let parsed = try ZcashEip681Backend.parseTransactionRequest(
            "ethereum:0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/transfer?address=0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359&uint256=1000000"
        )

        guard case let .erc20(parsedErc20) = parsed else {
            XCTFail("Expected .erc20 after parse, got \(parsed)")
            return
        }

        XCTAssertEqual(erc20.schemaPrefix, parsedErc20.schemaPrefix)
        XCTAssertEqual(erc20.hasPay, parsedErc20.hasPay)
        XCTAssertEqual(erc20.chainId, parsedErc20.chainId)
        XCTAssertEqual(erc20.tokenContractAddress, parsedErc20.tokenContractAddress)
        XCTAssertEqual(erc20.recipientAddress, parsedErc20.recipientAddress)
        XCTAssertEqual(erc20.valueHex, parsedErc20.valueHex)
    }

    // MARK: - Error handling for construction

    func testCreateNativeTransactionRequestInvalidAddress() {
        XCTAssertThrowsError(try ZcashEip681Backend.createNativeTransactionRequest(
            schemaPrefix: "ethereum",
            hasPay: false,
            chainId: nil,
            recipientAddress: "not-a-valid-address",
            valueHex: nil,
            gasLimitHex: nil,
            gasPriceHex: nil
        )) { error in
            guard let zcashError = error as? ZcashError else {
                XCTFail("Expected ZcashError, got \(error)")
                return
            }
            XCTAssertEqual(zcashError.code, .rustEip681Parse)
        }
    }
}

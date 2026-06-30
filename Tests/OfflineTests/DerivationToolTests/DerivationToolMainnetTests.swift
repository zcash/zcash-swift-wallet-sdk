//
//  DerivationToolTests.swift
//  ZcashLightClientKit-Unit-Tests
//
//  Created by Francisco Gindre on 10/9/20.
//

import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

class DerivationToolMainnetTests: XCTestCase {
    var seedPhrase = Environment.seedPhrase
    var seedData = Data(base64Encoded: "9VDVOZZZOWWHpZtq1Ebridp3Qeux5C+HwiRR0g7Oi7HgnMs8Gfln83+/Q1NnvClcaSwM4ADFL1uZHxypEWlWXg==")!

    let testRecipientAddress = UnifiedAddress(
        validatedEncoding: """
        u1l9f0l4348negsncgr9pxd9d3qaxagmqv3lnexcplmufpq7muffvfaue6ksevfvd7wrz7xrvn95rc5zjtn7ugkmgh5rnxswmcj30y0pw52pn0zjvy38rn2esfgve64rj5pcmazxgpyuj
        """,
        networkType: .mainnet
    )

    let expectedSpendingKey = UnifiedSpendingKey(
        network: .mainnet,
        bytes: Data(base64Encoded: """
        tNDWwgMg8Tkw4YrTsuDcwFRcaL4E6xllYD/72MAFAWl0ozX9q+ICqQOUcMGPAAAAgGofH2hCmQcNq7zShy1FFKYcENBO+X4tO3z8AlMahG6xOZQS96NqNozvVSf/ZffZxqWY0U8z2mwcJ\
        F04DKv/ZQRVzmOebCbHjT1q3PR40S8qy6jNFMmiKUUCprPLexpgB1ziepyEZ9FXROg3qYIwsmhZn3jFyDQ1/00oCXO3K65bln5489aKWhnXnmo/2qoFcmntX15GRdBtUw50Wj6+iAsAQB\
        gnnRntCLIa/wXB4KsvlPe21H9bTk24s27gb5/tIXOZNug65274BKRqcMVddG9ISBGT85GYg0BmOBVSIPt8ZvQ=
        """)!.bytes
    )

    let expectedViewingKey = UnifiedFullViewingKey(
        validatedEncoding: """
        uview17fme6ux853km45g9ep07djpfzeydxxgm22xpmr7arzxyutlusalgpqlx7suga4ahzywfuwz4jclm00u7g8u65qvvdt45kttnfunvschssg3h3g06txs9ja32vx3xa8dej3unnat\
        gzjvd0vumk37t8es3ludldrtse3q6226ws7eq4q0ywz78nudwpepgdn7jmxz8yvp7k6gxkeynkam0f8aqf9qpeaej55zhkw39x7epayhndul0j4xjttdxxlnwcd09nr8svyx8j0zng0w6\
        scx3m5unpkaqxcm3hslhlfg4caz7r8d4xy9wm7klkg79w7j0uyzec5s3yje20eg946r6rmkf532nfydu26s8q9ua7mwxw2j2ag7hfcuu652gw6uta03vlm05zju3a9rwc4h367kqzfqrc\
        z35pdwdk2a7yqnk850un3ujxcvve45ueajgvtr6dj4ufszgqwdy0aedgmkalx2p7qed2suarwkr35dl0c8dnqp3
        """
    )

    let expectedSaplingExtendedViewingKey = SaplingExtendedFullViewingKey(validatedEncoding: """
    zxviews1qw28psv0qqqqpqr2ru0kss5equx6h0xjsuk5299xrsgdqnhe0cknkl8uqff34prwkysswfhjk79n8l99f2grd26dqg6dy3jcmxsaypxfsu6ara6vsk3x8l544uaksstx9zre879md\
    g7s9a7zurrx6pf5qg2n323js2s3zlu8tn3848yyvlg4w38gx75cyv9jdpve77x9eq6rtl6d9qyh8det4edevlnc70tg5kse670x50764gzhy60dta0yv3wsd4fsuaz686lgszcq7kwxy
    """)

    let expectedSaplingAddress = SaplingAddress(validatedEncoding: "zs1vp7kvlqr4n9gpehztr76lcn6skkss9p8keqs3nv8avkdtjrcctrvmk9a7u494kluv756jeee5k0")

    let derivationTool = TestsData(networkType: .mainnet).derivationTools
    let expectedTransparentAddress = TransparentAddress(validatedEncoding: "t1dRJRY7GmyeykJnMH38mdQoaZtFhn1QmGz")

    func testDeriveViewingKeysFromSeed() throws {
        let seedBytes = [UInt8](seedData)

        let spendingKey = try derivationTool.deriveUnifiedSpendingKey(seed: seedBytes, accountIndex: Zip32AccountIndex(0))
        let viewingKey = try derivationTool.deriveUnifiedFullViewingKey(from: spendingKey)

        XCTAssertEqual(expectedViewingKey, viewingKey)
    }

    // TODO: [#1518] Fix the test, https://github.com/Electric-Coin-Company/zcash-swift-wallet-sdk/issues/1518
    func _testDeriveViewingKeyFromSpendingKeys() throws {
        let viewingKey = try derivationTool.deriveUnifiedFullViewingKey(from: expectedSpendingKey)
        XCTAssertEqual(expectedViewingKey, viewingKey)
    }

    // TODO: [#1518] Fix the test, https://github.com/Electric-Coin-Company/zcash-swift-wallet-sdk/issues/1518
    func _testDeriveSpendingKeysFromSeed() throws {
        let seedBytes = [UInt8](seedData)

        let spendingKey = try derivationTool.deriveUnifiedSpendingKey(seed: seedBytes, accountIndex: Zip32AccountIndex(0))

        XCTAssertEqual(expectedSpendingKey, spendingKey)
    }

    func testDeriveUnifiedSpendingKeyFromSeed() throws {
        let accountIndex = Zip32AccountIndex(0)
        let seedBytes = [UInt8](seedData)

        _ = try derivationTool.deriveUnifiedSpendingKey(seed: seedBytes, accountIndex: accountIndex)
    }

    func testGetTransparentAddressFromUA() throws {
        XCTAssertEqual(
            try DerivationTool(networkType: .mainnet).transparentReceiver(from: testRecipientAddress),
            expectedTransparentAddress
        )
    }

    func testIsValidViewingKey() {
        XCTAssertTrue(
            ZcashKeyDerivationBackend(networkType: .mainnet).isValidSaplingExtendedFullViewingKey(
                """
                zxviews1q0dm7hkzqqqqpqplzv3f50rl4vay8uy5zg9e92f62lqg6gzu63rljety32xy5tcyenzuu3n386ws772nm6tp4sads8n37gff6nxmyz8dn9keehmapk0spc6pzx5ux\
                epgu52xnwzxxnuja5tv465t9asppnj3eqncu3s7g3gzg5x8ss4ypkw08xwwyj7ky5skvnd9ldwj2u8fz2ry94s5q8p9lyp3j96yckudmp087d2jr2rnfuvjp7f56v78vpe658\
                vljjddj7s645q399jd7
                """
            )
        )

        XCTAssertFalse(
            ZcashKeyDerivationBackend(networkType: .mainnet).isValidSaplingExtendedFullViewingKey(
                "zxviews1q0dm7hkzky5skvnd9ldwj2u8fz2ry94s5q8p9lyp3j96yckudmp087d2jr2rnfuvjp7f56v78vpe658vljjddj7s645q399jd7"
            )
        )
    }

    func testDeriveQuiteALotOfUnifiedKeysFromSeed() throws {
        let numberOfAccounts: Int = 10
        var ufvks: [UnifiedFullViewingKey] = []
        for i in 0..<numberOfAccounts {
            let spendingKey = try derivationTool.deriveUnifiedSpendingKey(seed: [UInt8](seedData), accountIndex: Zip32AccountIndex(UInt32(i)))
            let viewingKey = try derivationTool.deriveUnifiedFullViewingKey(from: spendingKey)
            ufvks.append(viewingKey)
        }

        XCTAssertEqual(ufvks.count, numberOfAccounts)
        XCTAssertEqual(ufvks[0], expectedViewingKey)
    }

    func testShouldFailOnInvalidChecksumAddresses() {
        let testAddress = "t14oHp2v54vfmdgQ3v3SNuQga8JKHTNi2a1"
        XCTAssertFalse(DerivationTool(networkType: .mainnet).isValidTransparentAddress(testAddress))
    }

    func testSpendingKeyValidationFailsOnInvalidKey() throws {
        let wrongSpendingKey = """
        secret-extended-key-main1qw28psv0qqqqpqr2ru0kss5equx6h0xjsuk5299xrsgdqnhe0cknkl8uqff34prwkyuegyhh5d4rdr8025nl7e0hm8r2txx3fuea5mquy3wnsr9tlajs\
        g4wwvw0xcfk8357k4h850rgj72kt4rx3fjdz99zs9f4neda35cq8tn3848yyvlg4w38gx75cyv9jdpve77x9eq6rtl6d9qyh8det4edevlnc70tg5kse670x50764gzhy60dta0yv3wsd\
        4fsuaz686lgszc7nc9vvZzZzZz
        """

        XCTAssertFalse(DerivationTool(networkType: .mainnet).isValidSaplingExtendedSpendingKey(wrongSpendingKey))
    }
    // TODO: [#509] Address encoding does not catch this test https://github.com/zcash/ZcashLightClientKit/issues/509
//    func testSpendingKeyValidationThrowsWhenWrongNetwork() throws {
//        XCTAssertThrowsError(try derivationTool.isValidExtendedSpendingKey("secret-extended-key-test1qdxykmuaqqqqpqqg3x5c02p4rhw0rtszr8ln4xl7g6wg6qzsqgn445qsu3cq4vd6lk8xce3d4jw7s8ln5yjp6fqv2g0nzue2hc0kv5t004vklvlenncscq9flwh5vf5qnv0hnync72n7gjn70u47765v3kyrxytx50g730svvmhhlazn5rj8mshh470fkrmzg4xarhrqlygg8f486307ujhndwhsw2h7ddzf89k3534aeu0ypz2tjgrzlcqtat380vhe8awm03f58cqe49swv"))
//    }

    func testDeriveArbitraryWalletKeyTestVector() throws {
        // From https://github.com/zcash-hackworks/zcash-test-vectors/blob/master/zip_0032_arbitrary.py
        let contextString = [UInt8]("Zcash test vectors".utf8)
        let seed: [UInt8] = Array(Data(fromHexEncodedString: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")!)
        let expectedKey: [UInt8] = Array(Data(fromHexEncodedString: "e9da8806409dc3c3ebd1fc2a71c879c13dd7aa93ede803bf1a83414b9d3b158a")!)
        let key = try DerivationTool.deriveArbitraryWalletKey(contextString: contextString, seed: seed)
        XCTAssertEqual(key, expectedKey)
    }

    func testDeriveArbitraryAccountKeyTestVector() throws {
        // From https://github.com/zcash-hackworks/zcash-test-vectors/blob/master/zip_0032_arbitrary.py
        let contextString = [UInt8]("Zcash test vectors".utf8)
        let seed: [UInt8] = Array(Data(fromHexEncodedString: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")!)
        let expectedKey: [UInt8] = Array(Data(fromHexEncodedString: "bf60078362a09234fcbc6bf6c8a87bde9fc73776bf93f37adbcc439a85574a9a")!)
        let key = try DerivationTool(networkType: .mainnet).deriveArbitraryAccountKey(
            contextString: contextString,
            seed: seed,
            accountIndex: Zip32AccountIndex(0)
        )
        XCTAssertEqual(key, expectedKey)
    }
}

//
//  DerivatioToolTestnetTests.swift
//  ZcashLightClientKit-Unit-DerivationToolTests
//
//  Created by Francisco Gindre on 7/26/21.
//
// swift-format-ignore-file

import XCTest
@testable import TestUtils
@testable import ZcashLightClientKit

class DerivationToolTestnetTests: XCTestCase {
    var seedData = Data(base64Encoded: "9VDVOZZZOWWHpZtq1Ebridp3Qeux5C+HwiRR0g7Oi7HgnMs8Gfln83+/Q1NnvClcaSwM4ADFL1uZHxypEWlWXg==")!

    let testRecipientAddress = UnifiedAddress(
        validatedEncoding: """
        utest1uqmec4a2njqz2z2rwppchsd06qe7a0jh4jmsqr0yy99m9er9646zlxunf3v8qr0hncgv86e8a62vxy0qa32qzetmj8s57yudmyx9zav6f52nurclsqjkqtjtpz6vg679p6wkcz\
        pl2wu
        """,
        networkType: .testnet
    )

    let expectedSpendingKey = UnifiedSpendingKey(
        network: .testnet,
        bytes: Data(
            base64Encoded: """
            tNDWwgMg6xrWm9j+A47jcwGN5dh/XkFK6GKTy5TYam5Y8UF6o+kCqQNMS2+dAAAAgAiJqYeoNR3c8a4CGf86m/5GnI0AUAInWtAQ5HAKsbr9jmxmLayd6B/zoSQdJAxSHzFzKr4fZ\
            lFvfVlvs/mc8QwAqfuvRiaAmx95knjyp+RKfn8r72qMjYgzEWaj0ei+DGbvf/RToOR9wvevnpsPYkVN0dxg+RCDpqfUX+5K82uvByr+a0STltGka9zx5AiUuSBi/gC+rid7L5P123\
            xTQ+AAQAJO8vbUxpLCW2IvT1HEYhBOtKJDvC1Wp+wmBUmTmhG1aw/JybD+N5IY6PgiY2fiU43KI7tW9HZAlQTKitT+9m8=
            """
            )!.bytes
        )

    let expectedViewingKey = UnifiedFullViewingKey(
        validatedEncoding: """
        uviewtest12tkgzhaevmw78us4xj2cx6ehxjgpp5da2qwrjqvytztejqfjdmy3e6nryqggtwrjum5cefuuuky8rscuw5dynmjec2tx3kkupqexw4va879pf874kvp6r8kjeza26gysxll\
        aqwl67hm9u0jjke06zc93asrpw4wmy3g0lr9r5cy9pz49q2g7y7wm2pls5akmzhuvqr7khftk93aa2kpvwp7n3sjtmef28mxg3n2rpctsjlgsrhc29g6r23qc0u4tzd8rz8vqq4j7jxum\
        mdts8zx0jatzw4l2tl7r3egxhlw587rtkjx0y6dvw4hf4vjprn0qv3hs0sulmavk84ajeewn7argyerpr4essqvgfd0d24jpz6phxlasnd58qazh9d3yc6ad3hc5atp0pkvlq053zga65\
        gscp0pv2plhqj9y2tcmx43thw5g4v8z3unytkc2dhyttuhmnlh5dyz4rmhgfkc96tp8z8rpfe35whjvky0jagz5n7qx
        """
    )

    let expectedSaplingExtendedViewingKey = SaplingExtendedFullViewingKey(
        validatedEncoding: """
        zxviewtestsapling1qdxykmuaqqqqpqqg3x5c02p4rhw0rtszr8ln4xl7g6wg6qzsqgn445qsu3cq4vd6l5smlqrckkl2x5rnrauzc4gp665q3zyw0qf2sfdsx5wpp832htfavqk72uc\
        huuvq2dpmgk8jfaza5t5l56u66fpx0sr8ewp9s3wj2txavmhhlazn5rj8mshh470fkrmzg4xarhrqlygg8f486307ujhndwhsw2h7ddzf89k3534aeu0ypz2tjgrzlcqtat380vhe8awm\
        03f58cqgegsaj
        """
    )

    let expectedSaplingAddress = SaplingAddress(
        validatedEncoding: "ztestsapling1475xtm56czrzmleqzzlu4cxvjjfsy2p6rv78q07232cpsx5ee52k0mn5jyndq09mampkgvrxnwg"
    )

    let derivationTool = TestsData(networkType: .testnet).derivationTools
    let expectedTransparentAddress = TransparentAddress(validatedEncoding: "tmXuTnE11JojToagTqxXUn6KvdxDE3iLKbp")

    func testDeriveViewingKeysFromSeed() throws {
        let seedBytes = [UInt8](seedData)

        let spendingKey = try derivationTool.deriveUnifiedSpendingKey(seed: seedBytes, accountIndex: Zip32AccountIndex(0))
        let viewingKey = try derivationTool.deriveUnifiedFullViewingKey(from: spendingKey)

        XCTAssertEqual(expectedViewingKey, viewingKey)
    }

    // TODO: [#1518] Fix the test, https://github.com/Electric-Coin-Company/zcash-swift-wallet-sdk/issues/1518
    func _testDeriveViewingKeyFromSpendingKeys() throws {
        XCTAssertEqual(
            expectedViewingKey,
            try derivationTool.deriveUnifiedFullViewingKey(from: expectedSpendingKey)
        )
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
            try DerivationTool(networkType: .testnet).transparentReceiver(from: testRecipientAddress),
            expectedTransparentAddress
        )
    }

    func testIsValidTransparentAddressWrongNetwork() {
        XCTAssertFalse(
            derivationTool.isValidTransparentAddress(
                "t1dRJRY7GmyeykJnMH38mdQoaZtFhn1QmGz"
            )
        )
    }

    func testIsValidTransparentAddressFalse() {
        XCTAssertFalse(
            derivationTool.isValidTransparentAddress(
                "ztestsapling12k9m98wmpjts2m56wc60qzhgsfvlpxcwah268xk5yz4h942sd58jy3jamqyxjwums6hw7kfa4cc"
            )
        )
    }

    func testIsValidTransparentAddressTrue() {
        XCTAssertTrue(
            derivationTool.isValidTransparentAddress("tmSwpioc7reeoNrYB9SKpWkurJz3yEj3ee7")
        )
    }

    func testIsValidSaplingAddressTrue() {
        XCTAssertTrue(
            derivationTool.isValidSaplingAddress(
                "ztestsapling12k9m98wmpjts2m56wc60qzhgsfvlpxcwah268xk5yz4h942sd58jy3jamqyxjwums6hw7kfa4cc"
            )
        )
    }

    func testIsValidSaplingAddressWrongNetwork() {
        XCTAssertFalse(
            derivationTool.isValidSaplingAddress(
                "zs1vp7kvlqr4n9gpehztr76lcn6skkss9p8keqs3nv8avkdtjrcctrvmk9a7u494kluv756jeee5k0"
            )
        )
    }

    func testIsValidSaplingAddressFalse() {
        XCTAssertFalse(
            derivationTool.isValidSaplingAddress("tmSwpioc7reeoNrYB9SKpWkurJz3yEj3ee7")
        )
    }

    func testIsValidUnifiedAddressTrue() {
        XCTAssertTrue(
            derivationTool.isValidUnifiedAddress(testRecipientAddress.encoding)
        )
    }

    func testIsValidUnifiedAddressWrongNetwork() {
        XCTAssertFalse(
            derivationTool.isValidUnifiedAddress(
                """
                u1l9f0l4348negsncgr9pxd9d3qaxagmqv3lnexcplmufpq7muffvfaue6ksevfvd7wrz7xr\
                vn95rc5zjtn7ugkmgh5rnxswmcj30y0pw52pn0zjvy38rn2esfgve64rj5pcmazxgpyuj
                """
            )
        )
    }

    func testIsValidUnifiedAddressFalse() {
        XCTAssertFalse(
            derivationTool.isValidUnifiedAddress("tmSwpioc7reeoNrYB9SKpWkurJz3yEj3ee7")
        )
    }

    func testIsValidViewingKey() throws {
        XCTAssertTrue(
            ZcashKeyDerivationBackend(networkType: .testnet).isValidSaplingExtendedFullViewingKey(
                """
                zxviewtestsapling1qdxykmuaqqqqpqqg3x5c02p4rhw0rtszr8ln4xl7g6wg6qzsqgn445qsu3cq4vd6l5smlqrckkl2x5rnrauzc4gp665q3zyw0qf2sfdsx5wpp832htf\
                avqk72uchuuvq2dpmgk8jfaza5t5l56u66fpx0sr8ewp9s3wj2txavmhhlazn5rj8mshh470fkrmzg4xarhrqlygg8f486307ujhndwhsw2h7ddzf89k3534aeu0ypz2tjgrz\
                lcqtat380vhe8awm03f58cqgegsaj
                """
            )
        )

        XCTAssertFalse(
            ZcashKeyDerivationBackend(networkType: .testnet).isValidSaplingExtendedFullViewingKey(
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

    func testShouldFailOnInvalidChecksumAddresses() throws {
        let testAddress = "t14oHp2v54vfmdgQ3v3SNuQga8JKHTNi2a1"
        XCTAssertFalse(DerivationTool(networkType: .testnet).isValidTransparentAddress(testAddress))
    }

    func testSpendingKeyValidationFailsOnInvalidKey() {
        let wrongSpendingKey = """
        secret-extended-key-main1qw28psv0qqqqpqr2ru0kss5equx6h0xjsuk5299xrsgdqnhe0cknkl8uqff34prwkyuegyhh5d4rdr8025nl7e0hm8r2txx3fuea5mquy3wnsr9tlajs\
        g4wwvw0xcfk8357k4h850rgj72kt4rx3fjdz99zs9f4neda35cq8tn3848yyvlg4w38gx75cyv9jdpve77x9eq6rtl6d9qyh8det4edevlnc70tg5kse670x50764gzhy60dta0yv3wsd\
        4fsuaz686lgszc7nc9vvZzZzZz
        """

        XCTAssertFalse(DerivationTool(networkType: .testnet).isValidSaplingExtendedSpendingKey(wrongSpendingKey))
    }
    // TODO: [#509] Address encoding does not catch this test https://github.com/zcash/ZcashLightClientKit/issues/509
//    func testSpendingKeyValidationThrowsWhenWrongNetwork() throws {
//        XCTAssertThrowsError(try derivationTool.isValidExtendedSpendingKey("secret-extended-key-test1qdxykmuaqqqqpqqg3x5c02p4rhw0rtszr8ln4xl7g6wg6qzsqgn445qsu3cq4vd6lk8xce3d4jw7s8ln5yjp6fqv2g0nzue2hc0kv5t004vklvlenncscq9flwh5vf5qnv0hnync72n7gjn70u47765v3kyrxytx50g730svvmhhlazn5rj8mshh470fkrmzg4xarhrqlygg8f486307ujhndwhsw2h7ddzf89k3534aeu0ypz2tjgrzlcqtat380vhe8awm03f58cqe49swv"))
//    }
}

//
//  TestVector.swift
//
//
//  Created by Francisco Gindre on 9/26/22.
//

import Foundation
@testable import ZcashLightClientKit

/// Test vectors for unified addresses
/// Original file can be found here https://github.com/zcash-hackworks/zcash-test-vectors/blob/master/test-vectors/json/unified_address.json
/// Note: These vectors can't be used as-is since we are missing derivation functions that take a DiversifiedIndex
public struct TestVector {
    public enum Indices: Int, CaseIterable {
        case p2pkh_bytes = 0
        case p2sh_bytes
        case sapling_raw_addr
        case orchard_raw_addr
        case unknown_typecode
        case unknown_bytes
        case unified_addr
        case root_seed
        case account
        case diversifier_index
    }

    public var p2pkh_bytes: [UInt8]?
    public var p2sh_bytes: [UInt8]?
    public var sapling_raw_addr: [UInt8]?
    public var orchard_raw_addr: [UInt8]?
    public var unknown_typecode: UInt32?
    public var unknown_bytes: [UInt8]?
    public var unified_addr: String?
    public var root_seed: [UInt8]?
    public var account: UInt32 = 0
    public var diversifier_index: UInt32 = 0

    public static func optionalByteArrayKeyPath(from index: Indices) -> WritableKeyPath<TestVector, [UInt8]?>? {
        switch index {
        case .p2pkh_bytes:
            return \Self.p2pkh_bytes
        case .p2sh_bytes:
            return \Self.p2sh_bytes
        case .sapling_raw_addr:
            return \Self.sapling_raw_addr
        case .orchard_raw_addr:
            return \Self.orchard_raw_addr
        case .unknown_bytes:
            return \Self.unknown_bytes
        case .root_seed:
            return \Self.root_seed
        default:
            return nil
        }
    }

    static func stringKeyPath(from index: Indices) -> WritableKeyPath<TestVector, String?>? {
        switch index {
        case .unified_addr:
            return \Self.unified_addr
        default:
            return nil
        }
    }

    static func uintKeyPath(from index: Indices) -> WritableKeyPath<TestVector, UInt32>? {
        switch index {
        case .account:
            return \Self.account
        case .diversifier_index:
            return \Self.diversifier_index
        default:
            return nil
        }
    }

    public static var testVectors: [TestVector]? {
        var vectors: [TestVector] = []
        for rawVector in testVector.dropFirst(2) {
            guard let vector = TestVector(from: rawVector) else {
                return nil
            }
            vectors.append(vector)
        }

        return vectors
    }

    public init?(from rawVector: [Any?]) {
        guard rawVector.count == Indices.diversifier_index.rawValue + 1 else { return nil }

        for varIndex in Indices.allCases {
            switch varIndex {
            case .p2pkh_bytes, .p2sh_bytes, .sapling_raw_addr, .orchard_raw_addr, .unknown_bytes, .root_seed:
                guard let keyPath = Self.optionalByteArrayKeyPath(from: varIndex) else {
                    return nil
                }

                if rawVector[varIndex.rawValue] == nil {
                    self[keyPath: keyPath] = nil
                    break
                }

                guard
                    let hexString = rawVector[varIndex.rawValue] as? String,
                    let data = hexString.hexadecimal
                else { return nil }

                self[keyPath: keyPath] = data.bytes

            case .account, .diversifier_index:
                guard rawVector[varIndex.rawValue] != nil else { return nil }

                guard let keyPath = Self.uintKeyPath(from: varIndex) else { return nil }

                guard
                    let optionalValue = rawVector[varIndex.rawValue],
                    let intValue = optionalValue as? Int,
                    let uintValue = UInt32(exactly: intValue)
                else { return nil }

                self[keyPath: keyPath] = uintValue
            case .unified_addr:
                guard rawVector[varIndex.rawValue] != nil else { return nil }

                guard let keyPath = Self.stringKeyPath(from: varIndex) else { return nil }

                guard
                    let optionalValue = rawVector[varIndex.rawValue],
                    let stringValue = optionalValue as? String
                else { return nil }

                self[keyPath: keyPath] = stringValue

            case .unknown_typecode:
                self.unknown_typecode = rawVector[varIndex.rawValue] as? UInt32
            }
        }
    }
}

public extension String {
    /// Create `Data` from hexadecimal string representation
    ///
    /// This creates a `Data` object from hex string. Note, if the string has any spaces or non-hex characters (e.g. starts with '<' and with a '>'), those are ignored and only hex characters are processed.
    ///
    /// - returns: Data represented by this hexadecimal string.
    ///
    /// source: https://stackoverflow.com/questions/26501276/converting-hex-string-to-nsdata-in-swift
    var hexadecimal: Data? {
        var data = Data(capacity: count / 2)

        let regex = try! NSRegularExpression(pattern: "[0-9a-f]{1,2}", options: .caseInsensitive)
        regex.enumerateMatches(in: self, range: NSRange(startIndex..., in: self)) { match, _, _ in
            let byteString = (self as NSString).substring(with: match!.range)
            let num = UInt8(byteString, radix: 16)!
            data.append(num)
        }

        guard !data.isEmpty else { return nil }

        return data
    }
}

// swiftlint:disable line_length
public let testVector: [[Any?]] =
[
    ["From https://github.com/zcash-hackworks/zcash-test-vectors/blob/master/unified_address.py"],
    ["p2pkh_bytes, p2sh_bytes, sapling_raw_addr, orchard_raw_addr, unknown_typecode, unknown_bytes, unified_addr, root_seed, account, diversifier_index"],
    ["7bb83570b8fae146e03c5331a020b1e0892f631d", nil, "d8ef8293d26de832e7193f296ba1922d90f122c6135bc231eebd91efdb03b1a8606771cd4fd6480574d43e", nil, nil, nil, "u1m2p65qdnhexpfcmejjf6hjqd485xwfsrlf3cvc6wx5xhwrcq8myrdlqyhdpklz5d87ct0epfty0cr9d6q9fqtycx0j3vdhc2tzmkeejhtdqj3zrjqk3dd5ufpqkmueg89e6a6alvpaaxcx4fxsxqk4yj7g8dayn94d3afrsx66m3vq4rk03hc0ufmtkcm8wca7xja42f9kjau9708z7", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 0, 0],
    ["a7244a362f49f29644a955cf0039b88a61657861", nil, "435b0bbc95b5b7d52531a3944f2b85603ee22aaf850963bc156eb561edf2cbe7cf0e770e393ae5d7049026", nil, nil, nil, "u196qfugjlzacex3pnhj5hgkj7ppjxeg3egcwkn364rnt59nx7p2f4pp35h4v677hla3negz4w0quy9ul6an2azqv0lt7f5n4dz5pspk0uvhkqfft4ntarat6mf0zfc46s5rsvmrd63lvnp2y8kyyes2r0k439de6je9ugy85qkq9ldc7hkkvjav69gzyfl5sen8kfxk3gyhjpzn39xj0", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 0, 3],
    ["e256dcb03e05dde7c91212b47a7461311c415059", nil, "69a25a38699708e5f6e76e54e6a7a2ab84dcf288df0d1f2563670168d6c44ace0ef11155c60d5c225e9dec", nil, nil, nil, "u1vs0kanmdm4vtp2jy5lfsfspty0l7umph3ny6v9xwqpamvw2adshzsh24ukvc2hamwd8wky7sfalzv4szttsrss26m5yvxnh2r0h9u5vtksr0puhw89h7gm202h5qhn53cm2pt9uj7cwnymmgp26jxe9c0lt5z3egvl03hmdrg6r923t5xudetg2f6kzzn5h6xhaye8wmufnguaj8pws", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 0, 4],
    ["cad268758c5e71493066446b98e71df9d1d6a5ca", nil, "9f6e0bf90a18fc0b9b83ae9f23ad4358648638482b5def8975635b66fd8a708335f9235a3186ec0f033f84", "cecbe5e689a453a3fe10ccf7617e6c1fb382819d7fc9200a1f42092ac84a30378f8c1fb90dff71a6d5042d", nil, nil, "u1pg2aaph7jp8rpf6yhsza25722sg5fcn3vaca6ze27hqjw7jvvhhuxkpcg0ge9xh6drsgdkda8qjq5chpehkcpxf87rnjryjqwymdheptpvnljqqrjqzjwkc2ma6hcq666kgwfytxwac8eyex6ndgr6ezte66706e3vaqrd25dzvzkc69kw0jgywtd0cmq52q5lkw6uh7hyvzjse8ksx", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 1, 3],
    ["8d653347a0fd3cd0842a790a5eaf89d8e3854659", nil, "e1adf156a07d56bcac91bdb2f7bb3ea7c44569dcfee54273c09e8065807b6823faa94a77219554d0f6e017", "24f8a60cbd97e012618d56054ad39241411a28fdd50ee35efa91152f60d5fa21172e5d458ddbcb6b709896", nil, nil, "u19mzuf4l37ny393m59v4mxx4t3uyxkh7qpqjdfvlfk9f504cv9w4fpl7cql0kqvssz8jay8mgl8lnrtvg6yzh9pranjj963acc3h2z2qt7007du0lsmdf862dyy40c3wmt0kq35k5z836tfljgzsqtdsccchayfjpygqzkx24l77ga3ngfgskqddyepz8we7ny4ggmt7q48cgvgu57mz", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 1, 7],
    ["e511f439b5f96cf824cd5e0e6b2eb8ee1bc83cb7", nil, "60ba572f8e379312d86897025decdd64b4b95e2c4afa9d13726b8cc393edb4988c51b976028f890f108bd2", "1f24294ed1b405c7b3b1c3f13db5b9b27b5d0f2aca9d589a69e5be00eb978621e6776e87ea326d47a34c1a", nil, nil, "u1mtxw5nras5glkxz093282sv3n2h8qs7cpxcmmaxj96vtzjzl6rmdaxs4e9es7mxwmd0h3k5wz3ce4ll5g4jz2pn9su4pufq74pxhp4t235n6j7aed3hh8ss7pf3sekf7apsf6vtg84ue5zcq2k9q3xv5yth3q50fu4czdm8sn8q4de3m5k76g2vwwyjsf50hqfxgmwxqxu0rsy22ktw", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 1, 8],
    [nil, nil, "88533c398a49c2513dc85162bf220abaf47dc983f14e908ddaaa7322dba16531bc62efe750fe575c8d149b", "953f3c78d103c32b60559299462ebb27348964b892acad10482fe502c99f0d524959ba7be4f188e3a27138", nil, nil, "u1ay3aawlldjrmxqnjf5medr5ma6p3acnet464ht8lmwplq5cd3ugytcmlf96rrmtgwldc75x94qn4n8pgen36y8tywlq6yjk7lkf3fa8wzjrav8z2xpxqnrnmjxh8tmz6jhfh425t7f3vy6p4pd3zmqayq49efl2c4xydc0gszg660q9p", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 2, 0],
    [nil, nil, "616fe1a9d887148d6ca10f48ccd92d0dcad24f7c4c9d73ee8122b1766459b04dac4dc07e80edb9d229bbbc", "cc802699330bc4748e34dd598c7124e72299e6a6d5bcc32e90409c8024868b2705aadfab6068d458f69b0c", nil, nil, "u19a4vmx7ysmtavmnaz4d2dgl9pyshexw35rl5ezg5dkkxktg08p42lng7kf9hqtn2fhr63qzyhe8gtnvgtfl9yvne46x6zfzwgedx7c0chnrxty0k5r5qqph8k02zs8e3keul9vj8myju7rvqgjaysa9kt0fucxpzuky6kf0pjgy0a6hx", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 2, 5],
    [nil, nil, "9304f6e3c889829a0a48f2ebdc0803bbbd393ebf4264e45cb7db793e9376fa85ddf31f5024e0bf796672be", "3ed501c9c63abaf4d0136821f9647e764555a47033ad91d734df12d046c969751330bbf493a241ec4b88bc", nil, nil, "u13p2teem3xlvy4kwlke24hng5el2z6mn4ftj8xarwn8fy7dqt0flgcfpaxe6sk5cwawwh4tynzu7z2uschaf8tfa3tp2xgt8g4kx5lahhglcjm26jnvw7am6ld33708g0kv35pq83eg6gj82a0aau80enrhywpgr4v4m4vve7tg8vd4hz", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 2, 6],
    ["871a089d446268aa7ac03d2a6f60ae70808f3974", nil, nil, "31844683a07bf8e30057902b0d23e2b2ce9cad0b22190238ca4f329da92c7979052b00f735cb210671bdb0", nil, nil, "u1snf9yr883aj2hm8pksp9aymnqdwzy42rpzuffevj35hhxeckays5pcpeq7vy2mtgzlcuc4mnh9443qnuyje0yx6h59angywka4v2ap6kchh2j96ezf9w0c0auyz3wwts2lx5gmk2sk9", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 3, 0],
    ["7cb07c31b58040ac7cc12bfaaa138cfbefb38457", nil, nil, "05683c0303858388a785b4cf15d41ac69e1d435b0ad23838e18d62f7ec41c37fc86af71dffd94dfff6b207", nil, nil, "u1szwcx2zdxalyp7cfqwrptv95rnpyajejs6jmwacz4cgm2g3vzdxl5perhpg3nyhnuplvptdr4g63gupdfj5zal9v35s3e6adqsckv68hyrclan3gxaj6mz8aejzsnhqjyn32jcpnpra", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 3, 1],
    ["3e02e08b5965fce9c20ce6de6f9407674d01ba02", nil, nil, "551a16fb00d5482a2ab25182560661cfd74a60fe77a0f1c9347f16ba5249889f3ae346ed6938c30abfaf80", nil, nil, "u1glq6lzrxc7n7r4c922qht20zmpxyl0asfuldrjcaddagfspxpc3040fdfwdf5crw4j6j6wkx4r038s0w24w7enpyfmmdfu9t9p2amxazgvasms8l03l3j5yhrrfqy6xzue5uggef4p8", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 3, 2],
    [nil, nil, "6493348e8aee112a87f5fa65e1c57065aad369401e05d0daa96e0bcd89e67bf19beb3ac74d599d94585a68", "165082de84f2ad7204426ffafd6b6c7de9cab6d25c13846a1786715268c415948db788f4a5e0daa03d699e", nil, nil, "u1tqhg04ppjt6vlf2uvkygt07sqzgpclxdpn7j7ydkcr0e8ym68wn592z7uqudktrwn4u3q57flp8hw3d0wd9t0rm0e6m8eys27evfawh6zhha6eulzj86uz89swu7gtk0vcknd3dauhc96twhx20xxsp93dxahqlt7z5p04ldgy2y2lp0", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 4, 0],
    [nil, nil, "65b6b03f7b27189cc0ed54bcf6bd938e39bfd1bf66b8a038c0a967fbc50e48c18da3de20d671858b8f7fbf", "c906109b51e2b37bf8b67761bfa917dc5059c357b7dc8107672b66189a0d15bc496d84ef9114c68c99c911", nil, nil, "u1zm98xj3ncc79sx8jxhcscptxav0p4wam8mlkf4lp69rhramz7v6fsndwxcd4qtmzkefwcwn5rgd8uztvdrvfqv32jk3xx6wlt7gae9fhs7xh48d3kn9fe92xtcff8hu0zgegmgr95qtxayjylfdct96eg2f2r06drf6sj800mcsns3n0", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 4, 1],
    [nil, nil, "e987a4f50c94ba88e048638ecec706ef8a162674c9bef8caedfdf4b2131b451559090488ffe29ec02abac1", "7cd065b0ab297fb7fd701291d03589031fe3aadf1177902e5bcb65b5ba0aa2a0b73f09734f0b867b29763d", nil, nil, "u1hfgf2s4pghqteculnmq2rcnvyesml74zqfp5yfhxhwewx62q75qhgmwreg5qht7c5vu3fxefunjrarrfhmcuw2z4ndx0qx7u74gkw2n7v0ypvd4mxgzlenvs7lkurdj09zuhz6pmtuzs4m42sx92axuuru4dmgu46a920x5kuye6gxvs", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 4, 2],
    ["40c44030e468b7091e9bb33ba0abdc63986f3c36", nil, nil, "ea9df83fbee07d6f7895ebb2ea41ec7c4ba682b863e069b4a438e31c9571c83126c305d75456412aeaef1b", nil, nil, "u17cfcut587e3kszg8vud0z5a8lj9gyypyvtt5xn4hfc4p3kv4e0jfr2pzzxhywlkhsjldtmkvupwr7mkjvruz8gnxk7a64x777p4l3u7vpm6zsdsx88ef90x5q5sqx57fq8vtj5vk3hx", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 5, 0],
    ["937e71f9b2b6440a05ee1475bcc487e08a4f5801", nil, nil, "fd3e7eccdb1a91f2c4498bb7eb61cba83eca499cfde9c5ce3e3241873bad2e423abe91dece0a6930e8901d", nil, nil, "u1z6qgxh0wyw0ptgwwgsr5uv05n3xm3z8yrdr06k7q6fj9ypyjcj2hxwfmktv4a7ejaqphcgkddhsvrs93skzl3frm8e48at6huayg7k67e3c50ykpdnhva2jfh5dfcvy6nvttqwgz5a7", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 5, 1],
    ["b34866819053983231c48fd8a2706cecff29ba99", nil, nil, "5ef3c8b2bf2a8b0e60a6254f312229b4124d4787e7dada5d81e16b51211707871bede32811a35f4094ae8b", nil, nil, "u1g6jcyfwqd9yx8pdg4yvf0nsr5j7k5gmx83shh8v0v3w256umheen026x66f4608w2vydyasphgp80j9avq9h56dx73gg2559l5lj707v4458a0ucyhfxcjcccfx9z9upmcf3c6hg9k8", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 5, 2],
    ["06974d8bcd8ba8ef89ce36a653d93868251c2e3d", nil, nil, "3c40246912b6efefab9a55244ac2c174e1a9f8c0bc0fd526933963c6ecb9b84ec8b0f6b40dc858fa23c72b", 65532, "d56a1d62f5a8d7551db5fd9313e8c7203d996af7d477083756d59af80d06a745f44ab023752cb5b406ed8985e18130ab33362697b0e4e4c763ccb8f676495c222f7fba1e31defa3d5a57efc2e1e9b01a035587d5fb1a38e01d94903d3c3e0ad3360c1d3710acd20b183e31d49f25c9a138f49b1a537edcf04be34a9851a7af9db6990ed83dd64af3597c04323ea51b0052ad8084a8b9da948d320dadd64f5431e61ddf658d24ae67c22c8d13", "u1en8ysypun4gdkdnu8zqqg6k73ankr9ffwfzg08wtzg9z939w0wupewemfrc8a630e8gc4uqucym0l4v44fszy3et4veyypt3jsyp0whfpfsn2lw30kj8nepe6wvvasf00wklh85u9v8glqndupmamk9z2ja9sanf70pp4yxvkt3dmyzxa0kkhv2c9pxmkghrxqk0590azvya3nzrtevj449nu3laskrhf7c7nj9cyw7ty38mccg4znrr876guu6pzndx7ngwzhmlsn8d89saf5araaacrhr9958xr6z23mj4qtzzn98whdpu8u7n8fhf5d2vypljda62q73du44sf0e0kxmq3gvgkta0qqgq9w6r403gc5jz2any02etmwlttkv84hgh95czhdf2jugk3u36ke0kchcthg240", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 6, 0],
    ["cdd4b2be1b57f24c85fc1e43c77bb2da2d2646f1", nil, nil, "fc235122892d611e52ee5b447a77ec5a296213948fb56d721f66f264e32e7d0ce5473005fc4c0bcf421e8f", 65532, "09131fc00fe7f235734276d38d47f1e191e00c7a1d48af046827591e9733a97fa6b679f3dc601d008285edcbdae69ce8fc1be4aac00ff2711ebd931de518856878f73476f21a482ec9378365c8f7393c94e2885315eb4671098b79535e790fe53e29fef2b3766697ac32b4f473f468a008e72389fc03880d780cb07fcfaabe3f1a84b27db59a4a153d882d2b2103596555ed9494c6ac893c49723833ec8926c1039586a7afcf4a0d9c731e98", "u1a7gz63aey4tnj4klwauth00vnkmltwafwzk9nld2ys7yz3yjzjcdp47crc37zc4g9aq4athg9zh8r792e44kd6g2f4drhsl5ph4ja8pe4gcc9yjyf3rn7pej808hcy6xh0x6y8khmzljehjlwqq4h2czp35vu3l7aa7rpw5vcng9gswwlaqn5ptes592wejx7f49rxsvmzeqjekjtyfevehanvyksa8gtkpk75yrqnam26hzuxrtm6agaluy4hv0ha4sg6h22394m0x5th6r8uj7svzlklaja852vv9ud5gznu2sqyrsqveqjmfk9rcs59sprjj8nrt2nke862xlhvjq9y9zswen27eqj5slg52q2zch59uzwaeat8jw6z6092uu8yqqnnj7h0yguhypgd8y2wu9ftgg38ym3", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 6, 1],
    ["9f98c3116cb2f4e6f4c814148c81e379a538ced3", nil, nil, "2526ec6552f3e0175c922f019077146b5193e880461c3e1daca4778cde010ed5875f16b743ef86ac648b3d", 65532, "5d99589c8bb838e8aaf745533ed9e8ae3a1cd074a51a20da8aba18d1dbebbc862ded42435e92476930d069896cff30eb414f727b89e001afa2fb8dc3436d75a4a6f26572504b192232ecb9f0c02411e52596bc5e90457e745939ffedbd12863ce71a02af117d417adb3d15cc54dcb1fce467500c6b8fb86b12b56da9c382857deecc40a98d5f2935395ee4762dd21afdbb5d47fa9a6dd984d567db2857b927b7fae2db587105415d4642789d", "u1ln90fvpdtyjapnsqpa2xjsarmhu3k2qvdr6uc6upurnuvzh382jzmfyw40yu8avd2lj7arvq57n0qmryy0flp7tm0fw05h366587mzzwwrls85da6l2sr7tuazmv5s02avxaxrl4j7pau0u9xyp470y9hkca5m9g4735208w6957p82lxajzq4l2pqkam86y6jfx8cd8ecw2e05qnh0qq95dr09sgz9hqmflzac7hsxj47yvjd69ej06ewdg97wsu2x9wg3ahfh6s4nvk65elwcu5wl092ta38028p4lc2d6l7ea63s6uh4ek0ry9lg50acxuw2sdv02jh90tzh783d59gneu8ue3wqefjmtndyquwq9kkxaedhtqh2yyjew93ua38vp8uchug0q7kg7qvp4l65t9yqaz2w2p", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 6, 2],
    [nil, nil, "da2672c010f7364df6fad49dd39be0e4d4be73c45e239448fcc385cc68094bf36ddbc4ec0219b567955556", nil, 65533, "d17d19f3355bcf73cecb8cb8a5da01307152f13936a270572670dc82d39026c6cb4cd4b0f7f5aa2a4f5a5341ec5dd715406f2fdd2afa733f5f641c8c21862a1bafce2609d9eecfa158cfb5cd79f88008e315dc7d8388e76c1782fd2795d18a763624c25fa959cc97489ce75745824b77868c53239cfbdf73ca", "u1sem2gcey0emntrvxyjv8hyhq0w5fr4sxaj3cppgrfqgg6laydh8m78gy2cw2p54zzak3alnnsx4xjuhazpkrfcd90wl0c7ldj6y095hh5j6j2evry9vg5jqp4dyqpwqeryu7pes4sxyyyqwn6egs5daxk4473v9xpgzrwv5n0tvs93nlj4xpphq4vs2w8um9ph7zkte08t7fa509mnrt9apuhr22xq34mp2svjnq6rvfn0hg6lkehxtlj39vgjxjlkjfhx8rw2f02ckq8k5szcxsnhkgr2cqlmf2udl2gqdqr5t6", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 7, 1],
    [nil, nil, "9b728ad6f50371e961236630b3c8cdd8149ca22cdb87a62cc0ba3e3cfd2b0adcc82930e447f8dcf54b450b", nil, 65533, "ec65604037314faaceb56218c6bd30f8374ac13386793f21a9fb80ad03bc0cda4a44946c00e1b1a1df0e5b87b5bece477a709649e950060591394812951e1fe3895b8cc3d14d2cf6556df6ed4b4ddd3d9a69f53357d7767f4f5ccbdbc596631277f8fecd08cb056b95e3025b9792fff7f244fc716269b926d6", "u10j2s9sy4dmuakf57z58jc5t8yuswega82jpd2hk3q62l6fsphwyjxvmvfwy8skvvvea6dnkl8l9zpjf3m27qsav9y9nlj59hagmjf5xh0xxyqr8lymnmtjn6gzgrn04dr5s0k9k9wuxc2udzjh4llv47zm6jn6ff0j65s54h3m6p0n9ajswrqzpvy8eh4d5pvypyc6rp5m07uwmjp4sr0upca5hl7gr4pxg45m7vlnx5r7va4n6mfyr98twvjrhcyalwhddelnnjrkhcj0wcp5eyas2c2kcadrxyzw28vvv47q74", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 7, 5],
    [nil, nil, "9dd77ff5af4c80c25114e83758cbe1b535cfe9413017994163a12b0de522cdd1b5d4be299c0788ccb1541e", nil, 65533, "2e9596fa825c6bf21aff9e68625a192440ea06828123d97884806f15fa08da52754a1095e3ff1abd5ce4fddfccfc3a6128aef784a64610a89d1a7099216d0814d3a2d452431c32d411ac1cce82ad0229407bbc48985675e3f874a4533f1d63a84dfa3e0f460fe2f57e34fbc75423c3737f5b2a0615f5722db0", "u1mtnedjgkz5ln6zzs7nrcyt8mertjundexqdxx52n2x4ww3v52s0akf3qy6sqlze3nexcjsxtcajglxcdwg47dsrrva6g5t4nf8u3sjchhkmsqghelysrn0cl52c2m8uuv3nyfdv258jjqnvd4lgqtugc8aqvpmt05c49qv2yqlhxvnq9phdamm4xv89cc7tzvzgmwltxxdsvme44dgzt8prkcwcsma8cdr76m8n0xwj02tpr9086a237xakkdf8fumsj8u4r6qlf0d59x0mw83ar36vrcr94zsherapa0566vd22", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 7, 10],
    ["65704e3ab767ca578e5b092fb47604f659475bae", nil, nil, "5f09a9807a56323b263b05df368dc28391b21a64a0e1b40f9a6803b7e68f3905923f35cb01f119b223f493", nil, nil, "u1n9znrl4zyuvds24rcapzglzapqdlax4r8rgkvek0y0xlzfjfvn7zexelrafkchea24w030cr9jqsel7t8lvveaq7m7w4z0khmrlzc6748w9ldlccy02scd5xngtcv2yy4ctnyu9zn5m", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 8, 0],
    ["ef85a6553d89f153b37afcab928eb2bb5fb337db", nil, nil, "21006cfbb3db4f4bb63111ef63f7f80056f31b344d06aca5b7fa0740c660c8b2dc3bd234f4c18ae9eaf811", nil, nil, "u19f2knszheph2dt8lrnwqeeq9krnw39pgz8syqv028ghtg7kjz6xvu23suv5hmdmj7e6fjuu6060y34fdw8ccjlp8gsqp0usyhrgw3reqfveet7hh2pqcjafysqqv2l3felj7sl7a7ym", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 8, 1],
    ["f96a00ef8b2233236967a6a43f07ec6074f7fdc5", nil, nil, "04915d2bebce11111ce195226cde8440263c50204b2272ac8a96b38dbd70db8969ec9b6c87cd15d9d76512", nil, nil, "u160suxvjkgt22zcp7f9xw5f0axdu7rxdt5ktyexpn4cq70w4at2f74390mns7uksfenrdmcjjzqalyfky6tq05jv8mnamrkyxn9dcxe35z4x6m35cczmjcj55g0fc6a2thz03sjfywxa", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 8, 2],
    [nil, nil, nil, "e340636542ece1c81285ed4eab448adbb5a8c0f4d386eeff337e88e6915f6c3ec1b6ea835a88d56612d2bd", nil, nil, "u1ddnjsdcpm36r6aq79n3s68shjweksnmwtdltrh046s8m6xcws9ygyawalxx8n6hg6vegk0wh8zjnafxgh6msppjsljvyt0ynece3lvm0", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 9, 0],
    [nil, nil, nil, "3fadf8edb20a3301e8260aa311f4cbd54d7d6a76baac88c244b0b121c6dc22a8bcce15898e267829fc1e01", nil, nil, "u1nztelxna9h7w0vtpd2xjhxt4lpu8s9cmdl8n8vcr7actf2ny45nd07cy8cyuhuvw3axcp545y0ktq9cezuzx84jyhex8dk4tdvwhu4dl", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 9, 1],
    [nil, nil, nil, "987fd74a2256c596a66f83eaff7bb026286e972be56d3b50e3459747dfba53ffa0f24732b4aa6cd437a317", nil, nil, "u1trxzh330wl8wkh92uwv508z0qfx270ruuar8fxeng7arry5d73q9ve6gfud36s9nc4qj3uvn082l9srrfayjhnf20mmunywtvqzgc90c", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 9, 2],
    [nil, nil, "99ae333db1074fca1a6a94bed3ea548c1db2512dfbe75af9e84c162260b4813bb6bdb4443969daa5713ff1", "cdf7fed0d0822fd849cffb20a4d5ee701ad8141e66d81ddfabf87875117c05092240603c546b8dc187cd8c", 65532, "657b43ee8da645443814cc7329f3e9b4e54c236c29af3923101756d9fa4bd0f7d2ddaacb6b0f86a2658e0a07a05ac5b950051cd24c47a88d13d659ba2a46ca1830816d09cd7646f76f716abec5de", "u1xdrenc94696j8clxa2xnkdg8xd5t3y8s24urctyxu87vggv0u46qr4lkpnh7gqqdev9wwugt6xkv8c8du8ufhfl8nfjnzusf6cw20wpm85hlshmnmj2lkyhka9rua7qw7kr0xeajk7y2rlsuwl6z6l5l3wq3v6rrqt9e8zy7sc7pww45jznrj4xy6h9rp4kjy5xtl5upr30u4cyk58kv3t80k3p8w97k3e345h7avmjylxakx6sgyk5ss8th5kqay50ewav62eeep7tghzejaflsdstpwz55haex398jqpq27007me2", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 10, 0],
    [nil, nil, "52d58f91376aa980f2b9a6283ff357e84246d6942352184886449ffea8fad7e7ca5b490d090a96e0323392", "e4e01051b99c08506834971f80dadec44a4da13ecdcba617f77fc48d25324f57cb1d4d7424705d573cd682", 65532, "07fe9b523410806ea6f288f8736c23357c85f45791e1708029d9824d90704607f387a03e49bf9836574431345a7877efaa8a08e73081ef8d62cb780ab6883a50a0d470190dfba10a857f82842d38", "u1y647tzm2ms4stj8skfswfljmvatmhwqzjzl2uq5v3a78ys2mls2g9thdap4yfmr9tw6y5h9gnehzhpddyl43enmhd6xv2udcttqmas35l62jt2yar33jwr5eulchzxg3d8upf2raqcx3jup8s3dep6an5n5xh9ngdjfp4hjv8fwfhh34kvglsug57zf0duypq6ugmysw0mnhdg5fz9sndputdc7pdssg6k3ks76wrrnuu5najqxj8xchp5xv5ahfh3f2szrfl5cm6mslq2f69ja9r54plen209xwpdpwsvm6zep4gwl", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 10, 2],
    [nil, nil, "7a53f581d15985d0aafe134adb9540ffd19d965a43977ed4cb552cac5740a907ea24a9152b52268fe8cc3f", "b5a053ec1ab0623ce04f350cbb26031338dea9074551433adeb1bf3cb67c1e93982f42de822ebe4299692a", 65532, "25b3d6da0573d316eb160dc0b716c48fbd467f75b780149ae8808f4e68f50c0536acddf6f1aeab016b6bc1ec144b4e553acfd670f77e755fc88e0677e31ba459b44e307768958fe3789d41c2b1ff", "u1m5jvynaxyrtk27mt23q0j4r8uf5dzzhlwf6qd4s7pfdclqnmgkaf82kqrch0p44kd97f9pmwnk6q3rnjnzvlwv2ll289ahzlee4zcnual03ntelg2q2wxlqc6ueav935j4j2rzv2gxcdh6lk67quzxnxt5ay9xh0qjc9575dptfs9luhhr0m9wms2taq2vnrryjdj3ht5cktwathcerl9kw25y89f3hffyr65rnfw0jk2ka7703m8wym0c04u6r0xgagpn7xzfaxttrwgftmztzln6y2qcdglk3u28dgrswywqne28g", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 10, 4],
    ["294dbb37edd92ce046e266e22b0ed530a44b79c7", nil, nil, "24fd59f32b2d39dde66e46c39206a31bc04fa5c6847976ea6bbd3163ee14f58f584acc131479ea558d3f84", 65531, "2fe806b94569cd4059f396bf29b99d0a40e5e1711ca944f72d436a102fca4b97693da0b086fe9d2e7162470d02e0f05d4bec9512bfb3f38327296efaa74328b118c27402c70c3a90b49ad4bbc68e37c0aa7d9b3fe17799d73b841e751713a02943905aae0803fd69442eb7681ec2a05600054e92eed555028f21b6a155268a2dd6640a69301a52a38d4d9f9f957ae35af7167118141ce4c9be0a6a492fe79f1581a155fa3a2b9dafd82e650b386ad3a08cb6b83131ac300b0846354a7eef9c410e4b62c47c5426907dfc6685c5c99b7141ac626ab4761fd3f41e728e1a28f89db89f", "u1tqx832p4wsfe9pd67ggm3qsmfuvdhqvw2259y7uwug7y0lpeu87fmgpqh3zmamex3fzs0d4ct4hhsg2csj5z0q5f3f7n656ap8e4nlng9c4440rz9s7ekxanfw6g84f7vu82fumtmlz3vstl2a9ufa0970k4knsz2wpsjt2xycqeay76pt4fx3ak9y7mps2q6qe2n2h7wkakxr7xu6vd36zhhzgln7ttmrzc0f9ye3jmyu2pp8l8rect87lfxj2fgckcwz3svdx70a947fz04kgu7e907enzrk676zdkdmuyw2kyrclkmj62kmyy2rjetpus7knmxfuu7z0m63uwfhdynhuu3yrjqu5y089v8zwnh60mw5ngc0kszdjmc339fk9mjn396m5ekv7h7td7fa0u9097xph3y5vth9af4sw6ykxdms84wr544mxxqtmgj027d9e8rnlrazge0kwyydyhder3chwhmaqjk9skuxgxzternw4xx962qed", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 11, 0],
    ["6462c9a3003e4d0e0ab764860d8b71f8a36a23ff", nil, nil, "933bf1eb8fc99c38251bd42bb2e7e4afe526352a9b024f8d671b4d337277194b52338a91ce472503a48a00", 65531, "fdeca364dd2f0f0739f0534556483199c71f189341ac9b78a269164206a0ea1ce73bfb2a942e7370b247c046f8e75ef8e3f8bd821cf577491864e20e6d08fd2e32b555c92c661f19588b72a89599710a88061253ca285b6304b37da2b5294f5cb354a894322848ccbdc7c2545b7da568afac87ffa005c312241c2d57f4b45d6419f0d2e2c5af33ae243785b325cdab95404fc7aed70525cddb41872cfcc214b13232edc78609753dbff930eb0dc156612b9cb434bc4b693392deb87c530435312edcedc6a961133338d786c4a3e103f60110a16b1337129704bf4754ff6ba9fbe659", "u1adph5ua2pv8ghr7utshst0fm0ad7tj32y09t2nhxn2ccwm6hengck3w2vy34tvhqay7rlw8vcfh63f85lh7lz63l0c5vja49tu8vcxvx30re085n8jt5hcqh4g4ec77czl4c8nspqps2ac2g5kxhl4j5g6mz3vsvxrg74e8p9s8hhqu8u3gldhxvrxg2htykqc7ceh930f3edxsg49nctv2e36cne6qpkvxzfymh2el2eguw6kg7zvdu620rgk4cwyvt9hz7zpjk9wskjdpk6p3cpyx3yuf5lk46nx2fyqjca3vtz8d9df3tpmg74d90uv7pp09apfa5ep374clznmh2ne5suxtzk22cp7mvu9gtswpvx9wfst63s73yjwqu9cjenwntdsep0uqz2hgnh4xpq0rlllwgv8z70ke6z5zkwnjmlrzt6nsvhac4zz245rp3rkj9lmj8tvpfmd0zawy08dv3hqxxf8cr06x90amtgkh2ura0yyfwucu", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 11, 1],
    ["d5bca9e4e50be0c16bdfed7e5aca20ad43a23f20", nil, nil, "5ef2817381571b0e85215959f1fad87bf99bfb0799d81b2824fe4cc10f07776bbe7305e7c4c3933be4270f", 65531, "51e610620f71cda8fc877625f2c5bb04cbe1228b1e886f4050afd8fe94e97d2e9e85c6bb748c0042d3249abb1342bb0eebf62058bf3de080d94611a3750915b5dc6c0b3899d41222bace760ee9c8818ded599e34c56d7372af1eb86852f2a732104bdb750739de6c2c6e0f9eb7cb17f1942bfc9f4fd6ebb6b4cdd4da2bca26fac4578e9f543405acc7d86ff59158bd0cba3aef6f4a8472d144d99f8b8d1dedaa9077d4f01d4bb27bbe31d88fbefac3dcd4797563a26b1d61fcd9a464ab21ed550fe6fa09695ba0b2f10eea6468cc6e20a66f826e3d14c5006f0563887f5e1289be1b", "u12acx92vw49jek4lwwnjtzm0cssn2wxfneu7ryj4amd8kvnhahdrq0htsnrwhqvl92yg92yut5jvgygk0rqfs4lgthtycsewc4t57jyjn9p2g6ffxek9rdg48xe5kr37hxxh86zxh2ef0u2lu22n25xaf3a45as6mtxxlqe37r75mndzu9z2fe4h77m35c5mrzf4uqru3fjs39ednvw9ay8nf9r8g9jx8rgj50mj098exdyq803hmqsek3dwlnz4g5whc88mkvvjnfmjldjs9hm8rx89ctn5wxcc2e05rcz7m955zc7trfm07gr7ankf96jxwwfcqppmdefj8gc6508gep8ndrml34rdpk9tpvwzgdcv7lk2d70uh5jqacrpk6zsety33qcc554r3cls4ajktg03d9fye6exk8gnve562yadzsfmfh9d7v6ctl5ufm9ewpr6se25c47huk4fh2hakkwerkdd2yy3093snsgree5lt6smejfvse8v", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 11, 2],
    [nil, nil, nil, "6ed96d65379d5ece656901f5cb20cf554ce18600d4a1edcf6812f4459d7ff73cf2b88cd8476b75e8c08d28", 65535, "34d6e84bf59c1e04619a7c23a996941d889e4622a9b9b1d59d5e319094318cd405ba27b7e2c084762d31453ec4549a4d97729d033460fcf89d6494f2ffd789e98082ea5ce9534b3acd60fe49e37e4f666931677319ed89f85588741b3128901a93bd78e4be0225a9e2692c77c969ed0176bdf9555948cbd5a332d045de6ba6bf4490adfe7444cd467a09075417fcc0062e49f008c51ad4227439c1b4476ccd8e97862dab7be1e8d399c05ef27c6e22ee273e15786e394c8f1be31682a30147963ac8da8d41d804258426a3f70289b8ad19d8de13be4eebe3bd4c8a6f55d6e0c373", "u1uehkuaq6rpfgt4ed5zpvhczg9apgpmyk5eq9qg23j8w7jxkhdnqzacte6gu8zgzfzgxy48ryzus3wnkhfxrxmlhs34xde3f34uxcnv3y6dsgj288vu56xs9f6ghvqsgkhuwtz4kkfxj8pa27v5p3ttlst340zvwx9nj6s0zw8p3wwk3zh37dwc7znqz52gj2fpaapzxzyagah0aeyxwa9fxxvyyj6w989v96ymsgf7s8s6ej9346p60fcjzzynvf9rmxevumdvt8l9mvhdfz4u5j4h7e0zjr2sde7fu7z9s02447qg6qzllm22egnx6ej6qczkkk2ygvpy08un9ggp853sddp6vskrlar6sygxec5f6c2t2eu9zmc728esy4sj9z853gxuplr6hw7lpcwzk20d85vuflnhlfv8nr3020r0v9z83ryudsyjv66rttxq2cscqlrdxakrmpjptzcf", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 12, 0],
    [nil, nil, nil, "b6f481042a780462ffa96f81e1288978e5f05c791587de7e957729bcac6eb95892532b0fe13e9c7eef6a24", 65535, "d456851879f5fbc282db9e134806bff71e11bc33ab75dd6ca067fb73a043b646a7cf39cab4928386786d2f24141ee120fdc34d6764eafc66880ee0204f53cc1167ed20b43a52dea3ca7cff8ef35cd8e6d7c111a68ef44bcd0c1513ad47ca61c659cc5d325b440f6b9f59aff66879bb6688fd2859362b182f207b3175961f6411a493bffd048e7d0d87d82fe6f990a2b0a25f5aa0111a6e68f37bf6f3ac2d26b84686e569d58d99c1383597fad81193c4c1b16e6a90e2d507cdfe6fbdaa86163e9cf5de3100fbca7e8da047b090db9f37952fbfee76af61668190bd52ed490e677b", "u1m76hh3wch9vwctg92h0jjt8zu6dry4zl97q9q94huutng5sxyhlzgfj64jqnvla2vqrqe0ndt67td2kejv6zlcw9zeurexxs67l7y67p7mww2j2uvfsp6uynct2apcr0m9xrmswtktmgs3x2glvndrqazy0gyrp30j328h4m5gkju9rl3pfrtjn9tm8v0rzr6t8gkklqfxgwk976dvv4kh7hl5utp9gjryu8wwu80h733ss5cjwpeewdgd3l8h46c0c7hxz4c6daws3vurq2fj9h0hpjnycup9tu8nfahvqjxewyhyuzynnjxa7jrvw2ekdytqs7sn02gqx4vxtkjzfrcy67lkmr6p5kalj0g8apazeyzqw3ywppy9482wj8k4tm06573nr3h78ecq9n260g7c0hm5jm3ffa4g2vk0edpdsnemksdegxgt9s7h8v8pjmcp23rnahmzf8pxdtdt", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 12, 1],
    [nil, nil, nil, "a8e557a58a1908eb8a1bb078b77a95c032fe0a0069ce8c89d3e7705a48d2c08f7b604e5af0218d8cc9c8b8", 65535, "515d014384af07219c7c0ee7fc7bfc79f325644e4df4c0d7db08e9f0bd024943c705abff8994bfa605cfbc7ed746a7d3f7c37d9e8bdc433b7d79e08a12f738a8f0dbddfef2f2657ef3e47d1b0fd11e6a13311fb799c79c641d9da43b33e7ad012e28255398789262275f1175be8462c01491c4d842406d0ec4282c9526174a09878fe8fdde33a29604e5e5e7b2a025d6650b97dbb52befb59b1d30a57433b0a351474444099daa371046613260cf3354cfcdada663ece824ffd7e44393886a86165ddddf2b4c41773554c86995269408b11e6737a4c447586f69173446d8e48bf8", "u1c2tpmmdl49pdcfntc2e2gjaxmj2a0ackydlj9aeuqlet4erjdn2edwvtx6vd8nrkxjnvgckn4j3nx48p2gep5x23akrl2cv7u2un4vmjed9hav39taqgzyp602m3tpcv3uzdsjdyl8wxrjycx5aus8ypq2xja8yw0cf045n0zvwt3ajtgs2xyzjl6cq2245avkm26qjv72ta65h04etlp4ntdq87eu9efjx5v6gjsfvwrdt99m4lpu9j52t0h8yvpnzukuzdt89e3pg9cmderzh7tnahmw0rfyc37aqmd6dh24fnxmxagsj4mtz8jv3c3ch20xu4k6whwfsaf2sra4ktgdej9p6kqz05ae3vl3f93xsfx05xpaf884h56epcetx627jttgx2499vc0uzxl83hcdt92z4hy5la40ervrpha4kn3kxxwrngdj76u6mrfcmt4737czn08vd60k5gj", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 12, 2],
    [nil, nil, nil, "5178924f7067eac261044ca27ba3cf52f798486973af0795e61587aa1b1ecad333dc520497edc61df88980", nil, nil, "u1dqavtnjvu42hlsjw6sc2mxajqlyt03zg8l4luykz9fnchunq74nqxhfp58h5n5xfpyqhheax8thta8lfkjgp8wqwsavc0g4mgu4du02c", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 13, 0],
    [nil, nil, nil, "907639193311a847366c1a43ebaadd935a53180fd3e1219c07c8205f45077bc1768abdcf2425a4a13c4aba", nil, nil, "u1q8g29qhrktunc24lud3fgk007u7ya8q5g8vy9awadxtl7wu5vjllr4mmdfwk0zdh8zqxgl93sthzumeanzzkdqmqdft6ryhwtvqyqt3e", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 13, 1],
    [nil, nil, nil, "2809ddfc7db70c660a6c3fc7560c7add1c7889d9b277cb92d14cb40d2de00aae31670b753a42bdcdc3c220", nil, nil, "u13j3q8q8f9hx2nx0w9l52dqksy4png7fgm0lqjh8ahn9enyvz5z9xnwzdcdjmpf756s2y88rnyr9px4f4k9w03sl6fr4vwsqcvg8ggfjx", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 13, 2],
    ["e8225b817cdcfd01307c66ca35188e9b1ac238ca", nil, nil, "b208c9235c8d40e49b76100b2d010f3783f12c66e7d3beb117b2c96321b7f6562adb4efc144e39d909e728", nil, nil, "u1ukslldhknrzmvpdmn03u03edgfy976w3muurfs9asvh3n9uh9h6sgle6m7yjgf3wafxtvke08u735v4nd3kjqnyulw7cvxh6ke357knyjudgqtes6kcw7y28e6kewr03pjah5mh26na", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 14, 0],
    ["3869048bd22a3c3e6bc884333b0a71b05f7f4125", nil, nil, "332f451dc6f7da17fe5ff4077d3d5db79a036e712df558853d4a854ac4f6e51474cf75f38fa97c22b4cf09", nil, nil, "u1a0dnfvgdp4khm5yk79ltkkvp8jjmjykjy38cdue8ktl8askwenl4lzfyu0p7end0guyu6up57wylzns0tpr99wz5z8edh5u0m4yzuusysr3d2xczwkp82atq3vfw45u2yvtau852lnw", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 14, 1],
    ["59e919ce60110f97707c5c232b7d4db19e32c3ed", nil, nil, "3b68c29b4a138b289fea8b6795e64759a7cd7c0aaf4bb98ed3079959b0bba9b761704b6cfc1465ad74bb05", nil, nil, "u1a84vn0qes8q3jhk7zxs2whd2p922far8kztqdapergs5ej8rarn53v5ddnd6t7e3l5efhaefrhkptatnzq565nrpvf7kn2787gdvervmk08azp4qgehaew2zplkxkkyu36l3v7drg2v", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 14, 2],
    [nil, nil, "eee19641bc6b802f353eb793f728b17a277ef0358696a24a7122bc56537b229647f3810d27ce45227c6f39", nil, nil, nil, "u187vrwl4ampyxd5m6aj38n4ndkmj8v6gs97hkt23aps3sn5k89a0gk2smluexgdprcrtm56ezc5c7tjwlrnnl79tjtrxmqd42c5mpyz7g", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 15, 0],
    [nil, nil, "50ca46f825f7f423007aa4147169b529f07f1c8ed634fafc8145a4813177dd1257ee8d8fc5f44e9b564f6a", nil, nil, nil, "u1xd83nhheggwe78x3lvcygdl8cmwz3gfxnr02sytkxvfpwdep9dzl7vte48zhkx39s705yqp20rw4l835fhg3ylkde44l7glt3cyps5wk", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 15, 2],
    [nil, nil, "c412c8ff78f28d9b3391f4ab15d06acf46ac052821ee096a51524813f2adf9a4065cc6c45feba2c052df9e", nil, nil, nil, "u1w7x9ttwvk30grems6ae3rhgs6xytrrueaklyc5t509fpux7043fzla70jehhxyn4mg9d3ym095s3wghl9trvvdmu56yn74ajqy38ufjg", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 15, 3],
    ["f441228ee26a3a7d0d00e4d65ba49e3aa4877eb8", nil, nil, "2598d84dffb34f5908b90732490f3881399150d4c694fce9bf30d1560b2c56f09829fe123b9add20e5d71c", nil, nil, "u1smpx6drvevct3dyrer7esjlct99lf4nxdeltdetyxjdrmtqag7q7mkrd8rxlvj9e5vy0qy24fhvvvrj7agfdgxapefxe72xl8vuu9ds5yfq0p86r3y0jw4suurzjz5s6lzrxkfft4am", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 16, 0],
    ["9f1f8526792b04efdda3b38981867397ac11e3c0", nil, nil, "c1150ae8529e667015c462f91fb26e9124095aebd6e72fca95a2fe17ae53e8cb101eda84d9fb4d336ee103", nil, nil, "u1ymxkv9nks7tuzjt265fg8vctdq5nxqw4l0q2xj2ya5dkt660rrzkg032v5duhgeqae6cnh9tzxry4dspv8yvtq5lem9gujysaz64034mavd8p0ejqhnvp2jg34nt24y2c2whclxxk94", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 16, 1],
    ["6149d0373c63fddd4fca3b9f5407ad22abda0df2", nil, nil, "e961944a708a15c9c62734c34510bb5e2cd740abdeb488e4142b5d402b0295bec67922f1e71ab7fbd0a2ae", nil, nil, "u14j8rtl62a70skh0nhzv7tasxsa69axm0vlac37ye3mcgfpjk6k9ury7hlmet0grhvhedtfj27xmsygp06pcm932f8sc33u5uwps57d89667kyhwmj8pucp5r8cel2lhuaxmx5ftm2nt", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 16, 2],
    ["0eb9651c003776ab5d1e93c2779d10a0bdc3bb77", nil, "d3a803803feee7a032a24adfaa8f6a94cecb9671c1333d0d5d1a3d79d82bc310727c665364d71022559c50", "7c98b8f613f9ff02746bea2a167cfd1bd3a1862af9631bf61d9d604e0824e2cb8467a1e549db87a76e7a8a", nil, nil, "u1xjkw3lwwf9crx8cz050gdwfejufzhcusc37ged99w8fyj7tyx3e7hgmauyuv538dak2sepq6wjv4tyyjnhcef02dr682y5dsuzuftsx83lrvfc6dxd0kk260m4p3c9ka96vf3z9u6axvsj47mfd6kszy39e5gma28yg88yp92kxjt8ah0x329j4gxjdfyn0n2wp3urwrxxz6z0ynx82", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 17, 0],
    ["69f48a4974e80758ed435592a1dd4e4b38826cbc", nil, "25c25d58c50533dfb55d29f9a8864f58f02ea4fed44369352c43538cdf9545b905bb2ef0961bd2daf25883", "8a1bff2a9d921e1153b3cb264bc05185a9811de911d53467935434d6537d306752d02054fe5a170464259d", nil, nil, "u1p4c4u3uz2vtkedv78d4phjav86exankz0x9wmrmz8q4mxqaf43gwd0qt486jk5jvpvyccc6lyy2vaq3ht8ngnw4vusryxd9erhhl2uy5x6x4huyfdymwxj7dkyyeut8ld36kxwu3v5wjg7jwp9kr8ul7u3xdakfunvmwq0rkv6y4k0ngm2n24x763uurfmrr685welsefyys2xwp8ug", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 17, 1],
    ["f1bc3d7261bf77fe808e2b7178981c7cfe5570fd", nil, "54b7fc0c85d378f375be48218a85424bb9e7a304830e9eb7255a12a09c961cca1f629b867e13242ed90d92", "14adca6f616abcbe5bc850cc617dcf999517a9a790292fec6bc0761eaa790333e7d06d016de05bca7c6712", nil, nil, "u1ap7zakdnuefrgdglr334cw62hnqjkhr65t7tketyym0amkhdvyedpucuyxwu9z2te5vp0jf75jgsm36d7r09h6z3qe5rkgd8y28er6fz8z5rckspevxnx4y9wfk49njpcujh5gle7mfan90m9tt9a2gltyh8hx27cwt7h6u8ndmzhtk8qrq8hjytnakjqm0n658llh4z0277cyl2rcu", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 17, 2],
    ["407158fc804361fcb965dfa4882f0f1df5a49f47", nil, nil, "a80405d5568ab8ab8f8546163d951ab297fd5e6f43e7fcebcb664feacfab5afd80aaf7f354c07a9901788c", nil, nil, "u1udmzarqn6y9026whk083lm5vs8pv282egeln6xg0n2a3w4klkpn6208h68ntuus7gp54d937u4f724v2xgdx6qeu74j45vxfn822xty2yyx6u0ecakj8r9uu3r2jqafj64w7updkhtq", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 18, 0],
    ["f597980d65ca2ecd0fab5354e66ba9d4cd50f463", nil, nil, "33112cb923b3197a38c7a6eb50a837b0a44952fe31e528a1512994fcfa2b5f87b9c86ed9234426d3bbb526", nil, nil, "u1fyvdgdehrx3gvjx5f2ez2lkcm0lcrfxg8hksdmg3g8zujfz8xk2kyhu4dafs99y96sq2t5c3d3zsxhhnlfmj6trmttg5awtwczz8g8xjr7u30hxc4nkyfyefyl4xt3dxdjevsnrkqdg", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 18, 1],
    ["3e7f16836d93b5417445ad0fc9f7ba023617e2b3", nil, nil, "0dacf7b768abb04a02b2e30bf31440300b64275f3677d02e52ba0f4ce779cafee8ceea69acf2e1f0fee926", nil, nil, "u1kfzux4hf9favh8jmssqa2h04k87advldqz5ze7a8t4un3nkegklhz3ewzk6lmqg0uy7matdway9vn2q8q9rxp0fjwuewpcjtwrwavxjdsfxdvsk5nkx4q35atp0tfepfdsapqkk4en5", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 18, 2],
    ["29b06b228eb6b70fda051ff9e01bcb271b51c683", nil, "8660070e3757ff6507060791fd694f6a631b8495a2b74ffa39236cf653caea5575b86af3200b010e513bab", nil, nil, nil, "u1hrwrtyl3m8m2c6vkhu8wng43j5yvwweg37n2qstsqwc9dfw4vhs69m09064522758p44pfz42gu6hydjxua0wt0ge907sgrxkc9mft4gyfjevkhsyl4d8lnzgyd90arhx4t6v20zlfz", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 19, 5],
    ["29099a651d5561f800e58f3e33c27f078a98581f", nil, "6d75a1a948a4e730db3b4b816dbc7d80b4eb1bc68de9ac87b0cd1f1b3e6068e677888e105ac727c0d14b49", nil, nil, nil, "u1rf4n5f682jspygln8r5pjwh6fmta7xz6n9x868f5wgc9prxsqkrh8jkpmn7wfnag56ml7czw68dv96299ft6s98p05u4jvdx3elyr83jqnzr603vw8yarptpg5pj73zlea0sksuje3r", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 19, 11],
    ["475494432c3437d50ef23623cb67670fef27d8f5", nil, "38b14b44ed6f4a3ae8c5c3923e5770b786f9b41d46c65a149b13910f4a0a64e83bb9bc98e80d9576fbf76e", nil, nil, nil, "u1l6exm3zmfsr74sqvlwgc0zf7mydwf6z5r79amka84kfwzwef3wxs0yupl2lwhws85vdmqet3rtz795gpnm4h0jjfv4hanwqta0ezlxqe4p578a4aq09s93xhhtf3xhtrlh575qrsf5g", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 19, 15]
]

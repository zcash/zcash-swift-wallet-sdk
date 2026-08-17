// swift-tools-version:5.6
import PackageDescription

let targets: [Target] = [
    .binaryTarget(
        name: "libzcashlc",
        url: "https://github.com/zcash/zcash-swift-wallet-sdk/releases/download/2.7.0-rc.3/libzcashlc.xcframework.zip",
        checksum: "0000000000000000000000000000000000000000000000000000000000000000"
    )
]

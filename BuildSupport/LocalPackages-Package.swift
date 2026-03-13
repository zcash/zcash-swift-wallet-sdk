// swift-tools-version:5.6
import PackageDescription

let package = Package(
    name: "libzcashlc",
    products: [
        .library(name: "libzcashlc", targets: ["libzcashlc"])
    ],
    targets: [
        .binaryTarget(
            name: "libzcashlc",
            path: "libzcashlc.xcframework"
        )
    ]
)

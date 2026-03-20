// swift-tools-version:5.6
import PackageDescription
import Foundation

// Automatically detect local FFI development mode.
// When LocalPackages/Package.swift exists (created by Scripts/init-local-ffi.sh),
// the SDK builds against the locally-built FFI instead of the pre-built binary
// from GitHub Releases. Run `rm -rf LocalPackages` to switch back.
let packageDir = URL(fileURLWithPath: #filePath).deletingLastPathComponent().path
let useLocalFFI = FileManager.default.fileExists(atPath: packageDir + "/LocalPackages/Package.swift")

var dependencies: [Package.Dependency] = [
    .package(url: "https://github.com/grpc/grpc-swift.git", from: "1.24.2"),
    .package(url: "https://github.com/stephencelis/SQLite.swift.git", from: "0.15.3")
]

var sdkDependencies: [Target.Dependency] = [
    .product(name: "SQLite", package: "SQLite.swift"),
    .product(name: "GRPC", package: "grpc-swift"),
]

var targets: [Target] = []

if useLocalFFI {
    dependencies.append(.package(name: "libzcashlc", path: "LocalPackages"))
    sdkDependencies.append(.product(name: "libzcashlc", package: "libzcashlc"))
} else {
    // Binary target for the Rust FFI library
    // Updated by Scripts/release.sh during the release process
    targets.append(
        .binaryTarget(
            name: "libzcashlc",
            url: "https://github.com/valargroup/zcash-swift-wallet-sdk/releases/download/0.0.25-voting/libzcashlc.xcframework.zip",
            checksum: "4ad1b94b5155df8f8d8ebc553cfd9387e2349593254d596badfef91496eaa1a2"
        )
    )
    sdkDependencies.append("libzcashlc")
}

targets.append(contentsOf: [
    .target(
        name: "ZcashLightClientKit",
        dependencies: sdkDependencies,
        exclude: [
            "Modules/Service/GRPC/ProtoBuf/proto/compact_formats.proto",
            "Modules/Service/GRPC/ProtoBuf/proto/proposal.proto",
            "Modules/Service/GRPC/ProtoBuf/proto/service.proto",
            "Error/Sourcery/"
        ],
        resources: [
            .copy("Resources/checkpoints")
        ],
        linkerSettings: [
            .linkedFramework("SystemConfiguration", .when(platforms: [.macOS]))
        ]
    ),
    .target(
        name: "TestUtils",
        dependencies: ["ZcashLightClientKit"],
        path: "Tests/TestUtils",
        exclude: [
            "proto/darkside.proto",
            "Sourcery/AutoMockable.stencil",
            "Sourcery/generateMocks.sh"
        ],
        resources: [
            .copy("Resources/test_data.db"),
            .copy("Resources/cache.db"),
            .copy("Resources/darkside_caches.db"),
            .copy("Resources/darkside_data.db"),
            .copy("Resources/sandblasted_mainnet_block.json"),
            .copy("Resources/txBase64String.txt"),
            .copy("Resources/txFromAndroidSDK.txt"),
            .copy("Resources/integerOverflowJSON.json"),
            .copy("Resources/sapling-spend.params"),
            .copy("Resources/sapling-output.params")
        ]
    ),
    .testTarget(
        name: "OfflineTests",
        dependencies: ["ZcashLightClientKit", "TestUtils"]
    ),
    .testTarget(
        name: "NetworkTests",
        dependencies: ["ZcashLightClientKit", "TestUtils"]
    ),
    .testTarget(
        name: "DarksideTests",
        dependencies: ["ZcashLightClientKit", "TestUtils"]
    ),
    .testTarget(
        name: "AliasDarksideTests",
        dependencies: ["ZcashLightClientKit", "TestUtils"],
        exclude: [
            "scripts/"
        ]
    ),
    .testTarget(
        name: "PerformanceTests",
        dependencies: ["ZcashLightClientKit", "TestUtils"]
    )
])

let package = Package(
    name: "ZcashLightClientKit",
    platforms: [
        .iOS(.v13),
        .macOS(.v12)
    ],
    products: [
        .library(
            name: "ZcashLightClientKit",
            targets: ["ZcashLightClientKit"]
        )
    ],
    dependencies: dependencies,
    targets: targets
)

// swift-tools-version:5.9
import PackageDescription
import Foundation

let packageDir = URL(fileURLWithPath: #filePath).deletingLastPathComponent().path

// Automatically detect local FFI development mode.
// When LocalPackages/Package.swift exists (created by Scripts/init-local-ffi.sh),
// the SDK builds against the locally-built FFI instead of the pre-built binary
// from GitHub Releases. Run `rm -rf LocalPackages` to switch back.
let useLocalFFI = FileManager.default.fileExists(atPath: packageDir + "/LocalPackages/Package.swift")

// ZODL Slipstream variant (AGPL-3.0-only engine; see Sources/ZODLSlipstream/NOTICE.md).
// Two switches, one meaning:
// - `zodlSlipstreamVariantPinned` is flipped to `true` by Scripts/release.sh on
//   `X.Y.Z-zodl-slipstream` release tags. The flag must live in the manifest BYTES
//   (not only in a filesystem probe): SwiftPM's shared manifest cache is keyed on
//   manifest content, so byte-identical manifests across the two variant tags would
//   conflate their target graphs.
// - The `.zodl-slipstream-variant` marker file serves local development; it is
//   created by `Scripts/init-local-ffi.sh --zodl-slipstream` (which must also purge
//   the SwiftPM manifest cache when flipping, for the same reason).
// Plain `X.Y.Z` tags can never resolve to the ZODL Slipstream variant, and SemVer
// orders the `-zodl-slipstream` pre-release suffix BELOW `X.Y.Z`, so `from:` ranges
// never auto-select it — consumers opt in with `exact: "X.Y.Z-zodl-slipstream"`.
let zodlSlipstreamVariantPinned = false
let zodlSlipstreamVariant = zodlSlipstreamVariantPinned
    || FileManager.default.fileExists(atPath: packageDir + "/.zodl-slipstream-variant")

// Binary artifact pins. Updated by Scripts/release.sh during the release process.
let cleanFFIURL = "https://github.com/zcash/zcash-swift-wallet-sdk/releases/download/2.8.0-rc.2/libzcashlc.xcframework.zip"
let cleanFFIChecksum = "7d0b196c53a70ae5eed453709cc231318cc1b90077f3157c33704fed32acf02f"
// No released ZODL Slipstream artifact exists yet; the first dual release
// (planned 2.9.0 / 2.9.0-zodl-slipstream) fills these in.
let zodlSlipstreamFFIURL = ""
let zodlSlipstreamFFIChecksum = ""

var dependencies: [Package.Dependency] = [
    .package(url: "https://github.com/grpc/grpc-swift.git", from: "1.24.2"),
    .package(url: "https://github.com/stephencelis/SQLite.swift.git", from: "0.15.3")
]

var sdkDependencies: [Target.Dependency] = [
    .product(name: "SQLite", package: "SQLite.swift"),
    .product(name: "GRPC", package: "grpc-swift"),
]

var targets: [Target] = []

// Exactly ONE binaryTarget named `libzcashlc` exists per resolved graph, so a
// consuming app can never link two copies of the Rust staticlib. The ZODL
// Slipstream variant swaps in a strict SUPERSET artifact (all of libzcashlc plus
// the engine FFI), which is safe for the core target — every `zcashlc_*` symbol
// resolves.
let ffiDependency: Target.Dependency
if useLocalFFI {
    dependencies.append(.package(name: "libzcashlc", path: "LocalPackages"))
    ffiDependency = .product(name: "libzcashlc", package: "libzcashlc")
} else {
    if zodlSlipstreamVariant && zodlSlipstreamFFIChecksum.isEmpty {
        fatalError("""
        The ZODL Slipstream variant has no released binary artifact yet. Build the FFI \
        locally with Scripts/init-local-ffi.sh --zodl-slipstream, or pin a released \
        X.Y.Z-zodl-slipstream tag once one exists.
        """)
    }
    targets.append(
        .binaryTarget(
            name: "libzcashlc",
            url: zodlSlipstreamVariant ? zodlSlipstreamFFIURL : cleanFFIURL,
            checksum: zodlSlipstreamVariant ? zodlSlipstreamFFIChecksum : cleanFFIChecksum
        )
    )
    ffiDependency = "libzcashlc"
}
sdkDependencies.append(ffiDependency)

targets.append(contentsOf: [
    .target(
        name: "ZcashLightClientKit",
        dependencies: sdkDependencies,
        exclude: [
            "Modules/Service/GRPC/ProtoBuf/proto/proposal.proto",
            "Error/Sourcery/"
        ],
        resources: [
            .copy("Resources/checkpoints")
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

var products: [Product] = [
    .library(
        name: "ZcashLightClientKit",
        targets: ["ZcashLightClientKit"]
    )
]

if zodlSlipstreamVariant {
    targets.append(contentsOf: [
        .target(
            name: "ZODLSlipstream",
            dependencies: ["ZcashLightClientKit", ffiDependency],
            path: "Sources/ZODLSlipstream",
            exclude: [
                "NOTICE.md"
            ]
        ),
        .testTarget(
            name: "ZODLSlipstreamOfflineTests",
            dependencies: ["ZODLSlipstream", "ZcashLightClientKit", "TestUtils"],
            path: "Tests/ZODLSlipstreamOfflineTests"
        ),
        .testTarget(
            name: "ZODLSlipstreamDarksideTests",
            dependencies: ["ZODLSlipstream", "ZcashLightClientKit", "TestUtils"],
            path: "Tests/ZODLSlipstreamDarksideTests"
        )
    ])
    products.append(
        .library(
            name: "ZODLSlipstream",
            targets: ["ZODLSlipstream"]
        )
    )
}

let package = Package(
    name: "ZcashLightClientKit",
    platforms: [
        .iOS(.v13),
        .macOS(.v12)
    ],
    products: products,
    dependencies: dependencies,
    targets: targets
)

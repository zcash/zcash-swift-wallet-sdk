#!/bin/bash
# Initialize local FFI development environment
# Usage: ./Scripts/init-local-ffi.sh [--cached]
#   --cached   Download pre-built release instead of building from source
#
# This creates LocalPackages/ with a locally-built xcframework.
# Package.swift automatically detects LocalPackages/ and switches
# from the release binary to the local build.
#
# To switch back to the release binary: rm -rf LocalPackages/

set -e
cd "$(dirname "$0")/.."

# Ensure cargo/rustup are on PATH (needed when invoked from Xcode)
if [[ -f "$HOME/.cargo/env" ]]; then
    source "$HOME/.cargo/env"
fi

USE_CACHED=false
if [[ "$1" == "--cached" ]]; then
    USE_CACHED=true
fi

XCFRAMEWORK_DIR="LocalPackages/libzcashlc.xcframework"

if [[ "$USE_CACHED" == "true" ]]; then
    echo "Downloading pre-built xcframework..."
    # Extract the version from the download URL in Package.swift
    SDK_VERSION=$(grep -oE 'releases/download/[0-9]+\.[0-9]+\.[0-9]+' Package.swift | head -1 | sed 's|releases/download/||')
    if [[ -z "$SDK_VERSION" ]]; then
        echo "Error: Could not determine SDK version from Package.swift"
        exit 1
    fi
    DOWNLOAD_URL="https://github.com/zcash/zcash-swift-wallet-sdk/releases/download/${SDK_VERSION}/libzcashlc.xcframework.zip"

    mkdir -p LocalPackages
    curl -L "$DOWNLOAD_URL" -o LocalPackages/libzcashlc.xcframework.zip
    unzip -o LocalPackages/libzcashlc.xcframework.zip -d LocalPackages/
    rm LocalPackages/libzcashlc.xcframework.zip
    echo ""
    echo "Note: Downloaded pre-built xcframework may not match your local source."
    echo "      Run './Scripts/rebuild-local-ffi.sh' to rebuild for your target platform."
else
    echo "Building full xcframework from source (this takes a while)..."
    cd BuildSupport
    make xcframework
    cd ..
    mkdir -p LocalPackages
    cp -R BuildSupport/products/libzcashlc.xcframework "$XCFRAMEWORK_DIR"
fi

# Create local SPM package wrapper
cat > LocalPackages/Package.swift << 'EOF'
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
EOF

echo ""
echo "Local FFI initialized at LocalPackages/"
echo "Package.swift will automatically use the local build."
echo ""
echo "Next steps:"
echo "  1. Open ZcashSDK.xcworkspace in Xcode (or run: swift build)"
echo "  2. The workspace scheme rebuilds FFI automatically on each build."
echo "     If opening Package.swift directly, run ./Scripts/rebuild-local-ffi.sh after Rust changes."
echo ""
echo "To switch back to the release binary: rm -rf LocalPackages/"

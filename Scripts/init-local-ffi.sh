#!/bin/bash
# Initialize local FFI development environment
# Usage: ./Scripts/init-local-ffi.sh [--cached|--macos-only]
#   --cached      Download pre-built release instead of building from source
#   --macos-only  Build only the macOS slice from your rust/ (fast; swift build / swift test on Mac)
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
MACOS_ONLY=false
if [[ "${1:-}" == "--cached" ]]; then
    USE_CACHED=true
elif [[ "${1:-}" == "--macos-only" ]]; then
    MACOS_ONLY=true
fi

XCFRAMEWORK_DIR="LocalPackages/libzcashlc.xcframework"

if [[ "$MACOS_ONLY" == "true" ]]; then
    echo "Initializing local FFI for macOS only (single-arch from your rust/)..."
    mkdir -p LocalPackages
    # rebuild-local-ffi.sh requires this directory to exist; it replaces contents entirely.
    mkdir -p "$XCFRAMEWORK_DIR"
    ./Scripts/rebuild-local-ffi.sh macos
elif [[ "$USE_CACHED" == "true" ]]; then
    echo "Downloading pre-built xcframework..."
    REPO="zcash/zcash-swift-wallet-sdk"

    # Extract the version from the download URL in Package.swift
    SDK_VERSION=$(grep -oE 'releases/download/[0-9]+\.[0-9]+\.[0-9]+' Package.swift | head -1 | sed 's|releases/download/||')
    if [[ -z "$SDK_VERSION" ]]; then
        echo "Error: Could not determine SDK version from Package.swift"
        exit 1
    fi

    # Extract the expected checksum from Package.swift
    EXPECTED_CHECKSUM=$(grep -A1 'libzcashlc.xcframework.zip' Package.swift | grep 'checksum:' | sed -E 's/.*checksum: "([a-f0-9]+)".*/\1/')
    if [[ -z "$EXPECTED_CHECKSUM" ]]; then
        echo "Error: Could not extract checksum from Package.swift"
        exit 1
    fi

    mkdir -p LocalPackages
    # Use gh CLI to download release assets (works for both draft and published releases)
    gh release download "$SDK_VERSION" \
        --repo "$REPO" \
        --pattern "libzcashlc.xcframework.zip" \
        --dir LocalPackages

    # Verify checksum
    ACTUAL_CHECKSUM=$(shasum -a 256 LocalPackages/libzcashlc.xcframework.zip | awk '{print $1}')
    if [[ "$ACTUAL_CHECKSUM" != "$EXPECTED_CHECKSUM" ]]; then
        echo "Error: Checksum mismatch!"
        echo "  Expected: $EXPECTED_CHECKSUM"
        echo "  Actual:   $ACTUAL_CHECKSUM"
        rm -f LocalPackages/libzcashlc.xcframework.zip
        exit 1
    fi
    echo "Checksum verified."

    # Remove any existing framework first: extracting/copying onto an existing
    # directory leaves stale files (or, for cp -R, nests the new framework inside
    # the old one), so installs must always start from a clean target.
    rm -rf "$XCFRAMEWORK_DIR"
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
    # cp -R into an EXISTING directory copies the source INSIDE it (nested
    # libzcashlc.xcframework/libzcashlc.xcframework with stale slices at the top
    # level — device builds silently run old code). Always replace, never merge.
    rm -rf "$XCFRAMEWORK_DIR"
    cp -R BuildSupport/products/libzcashlc.xcframework "$XCFRAMEWORK_DIR"
fi

# Create local SPM package wrapper
cp BuildSupport/LocalPackages-Package.swift LocalPackages/Package.swift

echo ""
echo "Local FFI initialized at LocalPackages/"
echo "Package.swift will automatically use the local build."
echo ""
echo "Next steps:"
echo "  1. Open ZcashSDK.xcworkspace in Xcode (or run: swift build)"
echo "  2. The workspace scheme rebuilds FFI automatically on each build."
echo "     If opening Package.swift directly, run ./Scripts/rebuild-local-ffi.sh after Rust changes."
if [[ "$MACOS_ONLY" == "true" ]]; then
    echo ""
    echo "Note: --macos-only produced a single-slice XCFramework. For iOS Simulator or device,"
    echo "      run ./Scripts/rebuild-local-ffi.sh ios-sim or ios-device, or full ./Scripts/init-local-ffi.sh for every arch."
fi
echo ""
echo "To switch back to the release binary: rm -rf LocalPackages/"

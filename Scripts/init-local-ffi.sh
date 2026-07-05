#!/bin/bash
# Initialize local FFI development environment
# Usage: ./Scripts/init-local-ffi.sh [option]
#
# Options:
#   (no option)   Build the full XCFramework (all 5 architectures) from your rust/.
#   --arm-macos   Build only the arm64 macOS slice (aarch64-apple-darwin).
#   --arm-ios     Build only the arm64 iOS slices: simulator (aarch64-apple-ios-sim)
#                 and device (aarch64-apple-ios).
#   --arm-all     Build all arm64 slices: iOS simulator + device + macOS.
#   --cached      Download the pre-built release XCFramework instead of building.
#
# The --arm-* options skip the x86_64 simulator/Mac slices, which you cannot run on
# Apple Silicon anyway, so local iteration is faster. They always build the aarch64
# targets regardless of host architecture.
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

XCFRAMEWORK_DIR="LocalPackages/libzcashlc.xcframework"

usage() {
    if [[ -n "${1:-}" ]]; then
        echo "Error: $1" >&2
        echo "" >&2
    fi
    cat >&2 << 'USAGEEOF'
Usage: ./Scripts/init-local-ffi.sh [option]

Options:
  (no option)   Build the full XCFramework (all 5 architectures) from your rust/.
  --arm-macos   Build only the arm64 macOS slice (aarch64-apple-darwin).
  --arm-ios     Build only the arm64 iOS slices: simulator + device.
  --arm-all     Build all arm64 slices: iOS simulator + device + macOS.
  --cached      Download the pre-built release XCFramework instead of building.

Creates LocalPackages/ with a locally-built xcframework. Package.swift detects
LocalPackages/ and uses it instead of the released binary.
USAGEEOF
    exit 1
}

# Build an arm64-only xcframework containing exactly the requested slices, then
# atomically swap it into place. Each argument is one of: ios-sim, ios-device, macos.
#
# The slices reuse the same LibraryIdentifiers as the full build (e.g.
# macos-arm64_x86_64) but declare only arm64 in SupportedArchitectures, matching
# what rebuild-local-ffi.sh produces, so the two tools stay interchangeable.
build_arm_xcframework() {
    local targets=("$@")

    local temp_dir temp_xcfw
    temp_dir=$(mktemp -d)
    temp_xcfw="$temp_dir/libzcashlc.xcframework"
    mkdir -p "$temp_xcfw"

    # One JSON object per slice, accumulated for the xcframework Info.plist.
    local libraries_json=""

    local target
    for target in "${targets[@]}"; do
        local rust_target slice platform variant
        case "$target" in
            ios-sim)
                rust_target="aarch64-apple-ios-sim"
                slice="ios-arm64_x86_64-simulator"
                platform="ios"
                variant="simulator"
                ;;
            ios-device)
                rust_target="aarch64-apple-ios"
                slice="ios-arm64"
                platform="ios"
                variant=""
                ;;
            macos)
                rust_target="aarch64-apple-darwin"
                slice="macos-arm64_x86_64"
                platform="macos"
                variant=""
                ;;
            *)
                echo "Internal error: unknown arm target '$target'" >&2
                exit 1
                ;;
        esac

        echo "Building $rust_target -> $slice ..."

        # Ensure the Rust target is available (idempotent), then build it.
        # cargo is incremental, so repeat builds after small edits are fast.
        rustup target add "$rust_target"
        cargo build --target "$rust_target" --release

        # Populate the framework for this slice.
        local framework="$temp_xcfw/$slice/libzcashlc.framework"
        mkdir -p "$framework/Modules" "$framework/Headers"
        cp "target/$rust_target/release/libzcashlc.a" "$framework/libzcashlc"
        cp BuildSupport/module.modulemap "$framework/Modules/"
        cp BuildSupport/platform-Info.plist "$framework/Info.plist"
        if [[ -d "target/Headers" ]]; then
            cp -R target/Headers/* "$framework/Headers/"
        fi

        # Assemble this slice's AvailableLibraries entry as JSON (arm64 only).
        local variant_json=""
        if [[ -n "$variant" ]]; then
            variant_json=", \"SupportedPlatformVariant\": \"$variant\""
        fi
        local entry="{\"LibraryIdentifier\": \"$slice\", \"LibraryPath\": \"libzcashlc.framework\", \"SupportedArchitectures\": [\"arm64\"], \"SupportedPlatform\": \"$platform\"$variant_json}"
        if [[ -n "$libraries_json" ]]; then
            libraries_json="$libraries_json, $entry"
        else
            libraries_json="$entry"
        fi
    done

    # Generate the xcframework Info.plist from JSON; plutil emits canonical XML
    # and validates it in one step, so we avoid hand-writing plist whitespace.
    printf '{"AvailableLibraries": [%s], "CFBundlePackageType": "XFWK", "XCFrameworkFormatVersion": "1.0"}' "$libraries_json" \
        | plutil -convert xml1 -o "$temp_xcfw/Info.plist" -

    # Atomically swap the freshly built xcframework into place.
    mkdir -p LocalPackages
    rm -rf "$XCFRAMEWORK_DIR"
    mv "$temp_xcfw" "$XCFRAMEWORK_DIR"
    rm -rf "$temp_dir"

    # The slices above are assembled shallow (iOS layout). macOS embedded
    # frameworks require the VERSIONED bundle layout, else the app build fails
    # ("expected Versions/Current/Resources/Info.plist"). Same fix as the full
    # make path below and rebuild-local-ffi.sh; guarded for iOS-only subsets.
    if [[ -d "$XCFRAMEWORK_DIR/macos-arm64_x86_64/libzcashlc.framework" ]]; then
        ./Scripts/version-macos-framework.sh "$XCFRAMEWORK_DIR/macos-arm64_x86_64/libzcashlc.framework"
    fi
}

# Parse the single optional flag.
if [[ $# -gt 1 ]]; then
    usage "Too many arguments; pass at most one option."
fi

BUILD_MODE="full"
ARM_TARGETS=()
case "${1:-}" in
    "")
        BUILD_MODE="full"
        ;;
    --cached)
        BUILD_MODE="cached"
        ;;
    --arm-macos)
        BUILD_MODE="arm"
        ARM_TARGETS=(macos)
        ;;
    --arm-ios)
        BUILD_MODE="arm"
        ARM_TARGETS=(ios-sim ios-device)
        ;;
    --arm-all)
        BUILD_MODE="arm"
        ARM_TARGETS=(ios-sim ios-device macos)
        ;;
    *)
        usage "Unknown option: $1"
        ;;
esac

if [[ "$BUILD_MODE" == "arm" ]]; then
    echo "Initializing local FFI for arm64 (${ARM_TARGETS[*]})..."
    build_arm_xcframework "${ARM_TARGETS[@]}"
elif [[ "$BUILD_MODE" == "cached" ]]; then
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
    # The Makefile assembles every slice shallow (iOS layout). macOS embedded
    # frameworks require the versioned bundle layout, else Xcode rejects the app
    # ("expected Versions/Current/Resources/Info.plist"). Fix the macOS slice.
    ./Scripts/version-macos-framework.sh "$XCFRAMEWORK_DIR/macos-arm64_x86_64/libzcashlc.framework"
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
if [[ "$BUILD_MODE" == "arm" ]]; then
    echo ""
    echo "Note: this produced an arm64-only XCFramework (${ARM_TARGETS[*]})."
    echo "      Building for an x86_64 simulator/Mac or a slice you didn't include will fail"
    echo "      until you build it. Run ./Scripts/rebuild-local-ffi.sh <target> for a single"
    echo "      arch, or ./Scripts/init-local-ffi.sh (no flags) for the full 5-architecture build."
fi
echo ""
echo "To switch back to the release binary: rm -rf LocalPackages/"

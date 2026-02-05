#!/bin/bash
# Fast incremental FFI rebuild for local development
# Usage: ./Scripts/rebuild-local-ffi.sh [target]
#
# Targets:
#   ios-sim     iOS Simulator (default, detects arm64 vs x86_64)
#   ios-device  iOS Device (arm64)
#   macos       macOS (detects arm64 vs x86_64)
#
# Examples:
#   ./Scripts/rebuild-local-ffi.sh              # iOS Simulator (auto-detect arch)
#   ./Scripts/rebuild-local-ffi.sh ios-device   # iOS Device
#   ./Scripts/rebuild-local-ffi.sh macos        # macOS

set -e
cd "$(dirname "$0")/.."

TARGET="${1:-ios-sim}"
XCFRAMEWORK_DIR="LocalPackages/libzcashlc.xcframework"

# Check if initialized
if [[ ! -d "$XCFRAMEWORK_DIR" ]]; then
    echo "Error: Local FFI not initialized. Run ./Scripts/init-local-ffi.sh first"
    exit 1
fi

# Detect host architecture
HOST_ARCH=$(uname -m)
if [[ "$HOST_ARCH" == "arm64" ]]; then
    IS_APPLE_SILICON=true
else
    IS_APPLE_SILICON=false
fi

# Map target to Rust triple and xcframework slice
case "$TARGET" in
    ios-sim|ios-simulator)
        if [[ "$IS_APPLE_SILICON" == "true" ]]; then
            RUST_TARGET="aarch64-apple-ios-sim"
            XCFRAMEWORK_SLICE="ios-arm64_x86_64-simulator"
        else
            RUST_TARGET="x86_64-apple-ios"
            XCFRAMEWORK_SLICE="ios-arm64_x86_64-simulator"
        fi
        ;;
    ios-device|ios)
        RUST_TARGET="aarch64-apple-ios"
        XCFRAMEWORK_SLICE="ios-arm64"
        ;;
    macos|mac)
        if [[ "$IS_APPLE_SILICON" == "true" ]]; then
            RUST_TARGET="aarch64-apple-darwin"
        else
            RUST_TARGET="x86_64-apple-darwin"
        fi
        XCFRAMEWORK_SLICE="macos-arm64_x86_64"
        ;;
    *)
        echo "Unknown target: $TARGET"
        echo "Valid targets: ios-sim, ios-device, macos"
        exit 1
        ;;
esac

echo "Building for $TARGET ($RUST_TARGET)..."
echo ""

# Ensure Rust target is installed
rustup target add "$RUST_TARGET" 2>/dev/null || true

# Incremental cargo build (fast for small changes!)
# Cargo.toml is at the repo root, so we run cargo from there
cargo build --target "$RUST_TARGET" --release

# Path to built static library (target/ is at repo root)
BUILT_LIB="target/$RUST_TARGET/release/libzcashlc.a"

# Path to framework binary within xcframework
FRAMEWORK_DIR="$XCFRAMEWORK_DIR/$XCFRAMEWORK_SLICE/libzcashlc.framework"
FRAMEWORK_BINARY="$FRAMEWORK_DIR/libzcashlc"

echo "Copying built library to xcframework..."

# Copy the static library to the framework
# Note: For universal slices, we replace with single-arch (fine for local dev)
cp "$BUILT_LIB" "$FRAMEWORK_BINARY"

# Regenerate headers if build.rs produced new ones
if [[ -d "target/Headers" ]]; then
    cp -R "target/Headers" "$FRAMEWORK_DIR/"
fi

echo ""
echo "Rebuilt $TARGET in $XCFRAMEWORK_DIR"
echo ""
echo "Note: This is a single-architecture build for local development only."
echo "      The xcframework now contains only $RUST_TARGET for the $XCFRAMEWORK_SLICE slice."
echo "      Run 'init-local-ffi.sh' to rebuild all architectures."
echo ""
echo "Xcode should automatically pick up the changes. If not, clean build folder (Cmd+Shift+K)."

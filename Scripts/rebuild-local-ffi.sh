#!/bin/bash
# Fast incremental FFI rebuild for local development
# Usage: ./Scripts/rebuild-local-ffi.sh [target]
#
# Targets:
#   ios-sim     iOS Simulator (default, detects arm64 vs x86_64)
#   ios-device  iOS Device (arm64)
#   ios-all     iOS Device + iOS Simulator (both arm64)
#   macos       macOS (detects arm64 vs x86_64)
#
# Examples:
#   ./Scripts/rebuild-local-ffi.sh              # iOS Simulator (auto-detect arch)
#   ./Scripts/rebuild-local-ffi.sh ios-device   # iOS Device
#   ./Scripts/rebuild-local-ffi.sh ios-all      # iOS Device + Simulator
#   ./Scripts/rebuild-local-ffi.sh macos        # macOS

set -e
cd "$(dirname "$0")/.."

# Ensure cargo/rustup are on PATH (needed when invoked from Xcode)
if [[ -f "$HOME/.cargo/env" ]]; then
    source "$HOME/.cargo/env"
fi

TARGET="${1:-ios-sim}"
XCFRAMEWORK_DIR="LocalPackages/libzcashlc.xcframework"

# Check if initialized
if [[ ! -d "$XCFRAMEWORK_DIR" ]]; then
    echo "Error: Local FFI not initialized. Run ./Scripts/init-local-ffi.sh first"
    exit 1
fi

ensure_rust_target() {
    local rust_target="$1"
    if ! rustup target list --installed | grep -q "^${rust_target}$"; then
        echo "Rust target '$rust_target' is not installed."
        read -p "Install it now? [Y/n] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Nn]$ ]]; then
            echo "Cannot build without the target. Exiting."
            exit 1
        fi
        rustup target add "$rust_target"
    fi
}

copy_framework_slice() {
    local rust_target="$1"
    local framework_dir="$2"
    mkdir -p "$framework_dir/Modules" "$framework_dir/Headers"
    cp "target/$rust_target/release/libzcashlc.a" "$framework_dir/libzcashlc"
    cp BuildSupport/module.modulemap "$framework_dir/Modules/"
    cp BuildSupport/platform-Info.plist "$framework_dir/Info.plist"
    if [[ -d "target/Headers" ]]; then
        cp -R target/Headers/* "$framework_dir/Headers/"
    fi
}

if [[ "$TARGET" == "ios-all" ]]; then
    echo "Building ios-all (device arm64 + simulator arm64)..."
    echo ""
    for RUST_TARGET in aarch64-apple-ios aarch64-apple-ios-sim; do
        ensure_rust_target "$RUST_TARGET"
        echo "Building $RUST_TARGET..."
        cargo build --target "$RUST_TARGET" --release
    done

    TEMP_DIR=$(mktemp -d)
    TEMP_XCFW="$TEMP_DIR/libzcashlc.xcframework"
    copy_framework_slice "aarch64-apple-ios"     "$TEMP_XCFW/ios-arm64/libzcashlc.framework"
    copy_framework_slice "aarch64-apple-ios-sim" "$TEMP_XCFW/ios-arm64-simulator/libzcashlc.framework"

    cat > "$TEMP_XCFW/Info.plist" << 'PLISTEOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>AvailableLibraries</key>
	<array>
		<dict>
			<key>LibraryIdentifier</key>
			<string>ios-arm64</string>
			<key>LibraryPath</key>
			<string>libzcashlc.framework</string>
			<key>SupportedArchitectures</key>
			<array>
				<string>arm64</string>
			</array>
			<key>SupportedPlatform</key>
			<string>ios</string>
		</dict>
		<dict>
			<key>LibraryIdentifier</key>
			<string>ios-arm64-simulator</string>
			<key>LibraryPath</key>
			<string>libzcashlc.framework</string>
			<key>SupportedArchitectures</key>
			<array>
				<string>arm64</string>
			</array>
			<key>SupportedPlatform</key>
			<string>ios</string>
			<key>SupportedPlatformVariant</key>
			<string>simulator</string>
		</dict>
	</array>
	<key>CFBundlePackageType</key>
	<string>XFWK</string>
	<key>XCFrameworkFormatVersion</key>
	<string>1.0</string>
</dict>
</plist>
PLISTEOF

    rm -rf "$XCFRAMEWORK_DIR"
    mv "$TEMP_XCFW" "$XCFRAMEWORK_DIR"
    rm -rf "$TEMP_DIR"

    echo ""
    echo "Rebuilt ios-all (device arm64 + simulator arm64) in $XCFRAMEWORK_DIR"
    echo ""
    echo "Xcode should automatically pick up the changes. If not, clean build folder (Cmd+Shift+K)."
    exit 0
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
    ios-sim)
        if [[ "$IS_APPLE_SILICON" == "true" ]]; then
            RUST_TARGET="aarch64-apple-ios-sim"
            ARCH="arm64"
        else
            RUST_TARGET="x86_64-apple-ios"
            ARCH="x86_64"
        fi
        XCFRAMEWORK_SLICE="ios-arm64_x86_64-simulator"
        PLATFORM="ios"
        PLATFORM_VARIANT="simulator"
        ;;
    ios-device)
        RUST_TARGET="aarch64-apple-ios"
        XCFRAMEWORK_SLICE="ios-arm64"
        ARCH="arm64"
        PLATFORM="ios"
        PLATFORM_VARIANT=""
        ;;
    macos)
        if [[ "$IS_APPLE_SILICON" == "true" ]]; then
            RUST_TARGET="aarch64-apple-darwin"
            ARCH="arm64"
        else
            RUST_TARGET="x86_64-apple-darwin"
            ARCH="x86_64"
        fi
        XCFRAMEWORK_SLICE="macos-arm64_x86_64"
        PLATFORM="macos"
        PLATFORM_VARIANT=""
        ;;
    *)
        echo "Unknown target: $TARGET"
        echo "Valid targets: ios-sim, ios-device, ios-all, macos"
        exit 1
        ;;
esac

echo "Building for $TARGET ($RUST_TARGET)..."
echo ""

ensure_rust_target "$RUST_TARGET"

# Incremental cargo build (fast for small changes!)
# Cargo.toml is at the repo root, so we run cargo from there
cargo build --target "$RUST_TARGET" --release

# Path to built static library (target/ is at repo root)
BUILT_LIB="target/$RUST_TARGET/release/libzcashlc.a"

# Atomically rebuild the xcframework with only this single slice.
# This prevents stale binaries from remaining for other targets,
# which could silently use outdated code if Xcode switches platforms.
TEMP_DIR=$(mktemp -d)
TEMP_XCFW="$TEMP_DIR/libzcashlc.xcframework"
TEMP_FRAMEWORK="$TEMP_XCFW/$XCFRAMEWORK_SLICE/libzcashlc.framework"

mkdir -p "$TEMP_FRAMEWORK/Modules"
mkdir -p "$TEMP_FRAMEWORK/Headers"

# Copy built library, headers, and module map
cp "$BUILT_LIB" "$TEMP_FRAMEWORK/libzcashlc"
cp BuildSupport/module.modulemap "$TEMP_FRAMEWORK/Modules/"
cp BuildSupport/platform-Info.plist "$TEMP_FRAMEWORK/Info.plist"

if [[ -d "target/Headers" ]]; then
    cp -R target/Headers/* "$TEMP_FRAMEWORK/Headers/"
fi

# Generate xcframework Info.plist describing only this slice
VARIANT_ENTRY=""
if [[ -n "$PLATFORM_VARIANT" ]]; then
    VARIANT_ENTRY="			<key>SupportedPlatformVariant</key>
			<string>${PLATFORM_VARIANT}</string>"
fi

cat > "$TEMP_XCFW/Info.plist" << PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>AvailableLibraries</key>
	<array>
		<dict>
			<key>LibraryIdentifier</key>
			<string>${XCFRAMEWORK_SLICE}</string>
			<key>LibraryPath</key>
			<string>libzcashlc.framework</string>
			<key>SupportedArchitectures</key>
			<array>
				<string>${ARCH}</string>
			</array>
			<key>SupportedPlatform</key>
			<string>${PLATFORM}</string>
${VARIANT_ENTRY}
		</dict>
	</array>
	<key>CFBundlePackageType</key>
	<string>XFWK</string>
	<key>XCFrameworkFormatVersion</key>
	<string>1.0</string>
</dict>
</plist>
PLISTEOF

# Atomic swap
rm -rf "$XCFRAMEWORK_DIR"
mv "$TEMP_XCFW" "$XCFRAMEWORK_DIR"
rm -rf "$TEMP_DIR"

echo ""
echo "Rebuilt $TARGET ($ARCH) in $XCFRAMEWORK_DIR"
echo ""
echo "The xcframework now contains ONLY $RUST_TARGET."
echo "Building for a different platform will fail until you rebuild for that target."
echo "Run 'init-local-ffi.sh' to rebuild all architectures."
echo ""
echo "Xcode should automatically pick up the changes. If not, clean build folder (Cmd+Shift+K)."

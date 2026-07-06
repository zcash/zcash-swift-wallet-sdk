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

# Ensure cargo/rustup are on PATH (needed when invoked from Xcode)
if [[ -f "$HOME/.cargo/env" ]]; then
    source "$HOME/.cargo/env"
fi

# Parse a target (ios-sim|ios-device|macos) + optional --gpu (v0.3 GPU Orchard offload
# build; links wgpu via the libzcashlc `gpu` feature). Runtime opt-in: ZCASH_GPU_SUBTREE.
TARGET="ios-sim"
CARGO_FEATURES=""
for arg in "$@"; do
    case "$arg" in
        --gpu) CARGO_FEATURES="--features gpu" ;;
        ios-sim|ios-device|macos) TARGET="$arg" ;;
        *) echo "Unknown arg: $arg"; echo "Usage: rebuild-local-ffi.sh [ios-sim|ios-device|macos] [--gpu]"; exit 1 ;;
    esac
done
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
        echo "Valid targets: ios-sim, ios-device, macos"
        exit 1
        ;;
esac

echo "Building for $TARGET ($RUST_TARGET)...${CARGO_FEATURES:+ [v0.3 GPU: $CARGO_FEATURES]}"
echo ""

# Check if Rust target is installed
if ! rustup target list --installed | grep -q "^${RUST_TARGET}$"; then
    echo "Rust target '$RUST_TARGET' is not installed."
    read -p "Install it now? [Y/n] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        echo "Cannot build without the target. Exiting."
        exit 1
    fi
    rustup target add "$RUST_TARGET"
fi

# Incremental cargo build (fast for small changes!)
# Cargo.toml is at the repo root, so we run cargo from there.
# $CARGO_FEATURES is intentionally unquoted (empty = no extra args; "--features gpu" splits).
cargo build --target "$RUST_TARGET" --release $CARGO_FEATURES

# Path to built static library (target/ is at repo root)
BUILT_LIB="target/$RUST_TARGET/release/libzcashlc.a"

# Atomically rebuild the xcframework, PRESERVING the other platforms' slices.
# (This script used to keep only the rebuilt slice to avoid staleness — but
# that silently destroyed the other platforms' builds, breaking e.g. Zodl iOS
# after a macOS-only rebuild, three times. The ENGINE_BUILD log tag is the
# definitive per-slice freshness check; preserved slices get a loud warning.)
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

# Carry over every OTHER slice from the existing xcframework, with a loud
# staleness reminder (they contain whatever Rust they were last built with).
if [[ -d "$XCFRAMEWORK_DIR" ]]; then
    for slice_path in "$XCFRAMEWORK_DIR"/*/; do
        [[ -d "$slice_path" ]] || continue
        slice_name="$(basename "$slice_path")"
        if [[ "$slice_name" != "$XCFRAMEWORK_SLICE" ]]; then
            # -P: keep symlinks as symlinks (the versioned macOS framework
            # layout relies on Versions/Current links).
            cp -RP "$slice_path" "$TEMP_XCFW/$slice_name"
            echo "⚠️  preserved existing slice '$slice_name' — it is NOT rebuilt by this run;"
            echo "    check its ENGINE_BUILD tag before trusting it on that platform."
        fi
    done
fi

# Generate the xcframework Info.plist from the slices ACTUALLY PRESENT in
# the assembled bundle (deterministic slice-name → platform mapping).
{
    cat << 'PLISTHEAD'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>AvailableLibraries</key>
	<array>
PLISTHEAD
    for slice_path in "$TEMP_XCFW"/*/; do
        [[ -d "$slice_path" ]] || continue
        slice_name="$(basename "$slice_path")"
        entry_variant=""
        case "$slice_name" in
            ios-arm64)
                entry_platform="ios"
                entry_archs="<string>arm64</string>" ;;
            ios-arm64_x86_64-simulator)
                entry_platform="ios"
                entry_archs="<string>arm64</string><string>x86_64</string>"
                entry_variant="			<key>SupportedPlatformVariant</key>
			<string>simulator</string>" ;;
            ios-arm64-simulator)
                entry_platform="ios"
                entry_archs="<string>arm64</string>"
                entry_variant="			<key>SupportedPlatformVariant</key>
			<string>simulator</string>" ;;
            macos-arm64_x86_64)
                entry_platform="macos"
                entry_archs="<string>arm64</string><string>x86_64</string>" ;;
            macos-arm64)
                entry_platform="macos"
                entry_archs="<string>arm64</string>" ;;
            *)
                echo "warning: unknown slice '$slice_name' — no plist entry emitted" >&2
                continue ;;
        esac
        cat << ENTRYEOF
		<dict>
			<key>LibraryIdentifier</key>
			<string>${slice_name}</string>
			<key>LibraryPath</key>
			<string>libzcashlc.framework</string>
			<key>SupportedArchitectures</key>
			<array>
				${entry_archs}
			</array>
			<key>SupportedPlatform</key>
			<string>${entry_platform}</string>
${entry_variant}
		</dict>
ENTRYEOF
    done
    cat << 'PLISTTAIL'
	</array>
	<key>CFBundlePackageType</key>
	<string>XFWK</string>
	<key>XCFrameworkFormatVersion</key>
	<string>1.0</string>
</dict>
</plist>
PLISTTAIL
} > "$TEMP_XCFW/Info.plist"

# Atomic swap
rm -rf "$XCFRAMEWORK_DIR"
mv "$TEMP_XCFW" "$XCFRAMEWORK_DIR"
rm -rf "$TEMP_DIR"

# macOS embedded frameworks need the versioned bundle layout (the slice is built
# shallow like iOS); without this Xcode rejects the embedded framework.
if [[ "$TARGET" == "macos" ]]; then
    ./Scripts/version-macos-framework.sh "$XCFRAMEWORK_DIR/$XCFRAMEWORK_SLICE/libzcashlc.framework"
fi

echo ""
echo "Rebuilt $TARGET ($ARCH) in $XCFRAMEWORK_DIR"
echo ""
echo "The xcframework now contains ONLY $RUST_TARGET."
echo "Building for a different platform will fail until you rebuild for that target."
echo "Run 'init-local-ffi.sh' to rebuild all architectures."
echo ""
echo "Xcode should automatically pick up the changes. If not, clean build folder (Cmd+Shift+K)."

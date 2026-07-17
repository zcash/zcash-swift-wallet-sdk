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
# --universal (macos, ios-sim): build BOTH archs of the slice and lipo them — REQUIRED
# before an Xcode ARCHIVE (Release links arm64+x86_64; a host-arch-only macOS slice
# fails with hundreds of undefined _zcashlc_* symbols — bit the Beta5 archive
# 2026-07-07) and before any `generic/platform=iOS Simulator` build (links both sim
# archs; an arm64-only sim slice fails the x86_64 link — bit Zodl iOS 2026-07-08).
TARGET="ios-sim"
CARGO_FEATURES=""
UNIVERSAL=false
for arg in "$@"; do
    case "$arg" in
        --gpu) CARGO_FEATURES="--features gpu" ;;
        --universal) UNIVERSAL=true ;;
        ios-sim|ios-device|macos) TARGET="$arg" ;;
        *) echo "Unknown arg: $arg"; echo "Usage: rebuild-local-ffi.sh [ios-sim|ios-device|macos] [--gpu] [--universal]"; exit 1 ;;
    esac
done
if [[ "$UNIVERSAL" == "true" && "$TARGET" != "macos" && "$TARGET" != "ios-sim" ]]; then
    echo "--universal is only meaningful for the macos and ios-sim targets"; exit 1
fi
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
if [[ "$TARGET" == "macos" && "$UNIVERSAL" == "true" ]]; then
    echo "Universal macOS build (arm64 + x86_64)..."
    for t in aarch64-apple-darwin x86_64-apple-darwin; do
        if ! rustup target list --installed | grep -q "^${t}$"; then
            rustup target add "$t"
        fi
        cargo build --target "$t" --release $CARGO_FEATURES
    done
    BUILT_LIB="target/libzcashlc-macos-universal.a"
    lipo -create \
        target/aarch64-apple-darwin/release/libzcashlc.a \
        target/x86_64-apple-darwin/release/libzcashlc.a \
        -output "$BUILT_LIB"
elif [[ "$TARGET" == "ios-sim" && "$UNIVERSAL" == "true" ]]; then
    echo "Universal iOS Simulator build (arm64 + x86_64)..."
    for t in aarch64-apple-ios-sim x86_64-apple-ios; do
        if ! rustup target list --installed | grep -q "^${t}$"; then
            rustup target add "$t"
        fi
        cargo build --target "$t" --release $CARGO_FEATURES
    done
    BUILT_LIB="target/libzcashlc-ios-sim-universal.a"
    lipo -create \
        target/aarch64-apple-ios-sim/release/libzcashlc.a \
        target/x86_64-apple-ios/release/libzcashlc.a \
        -output "$BUILT_LIB"
else
    cargo build --target "$RUST_TARGET" --release $CARGO_FEATURES
    # Path to built static library (target/ is at repo root)
    BUILT_LIB="target/$RUST_TARGET/release/libzcashlc.a"
fi

# Downgrade guard: replacing a previously-universal slice with a host-arch-only binary
# silently breaks builds that link both archs (macOS: Xcode ARCHIVE; iOS Simulator:
# any `generic/platform=iOS Simulator` destination).
if [[ ( "$TARGET" == "macos" || "$TARGET" == "ios-sim" ) && "$UNIVERSAL" != "true" ]]; then
    OLD_BIN="$XCFRAMEWORK_DIR/$XCFRAMEWORK_SLICE/libzcashlc.framework/libzcashlc"
    if [[ -e "$OLD_BIN" ]] && lipo -archs "$OLD_BIN" 2>/dev/null | grep -q "x86_64"; then
        echo "⚠️  DOWNGRADE: the existing $TARGET slice was universal (arm64+x86_64); this"
        echo "    rebuild replaces it with ${ARCH}-only. Builds that link both archs"
        echo "    (macOS ARCHIVE / generic iOS-Simulator destinations) will fail with"
        echo "    undefined _zcashlc_* symbols. To restore:"
        echo "      ./Scripts/rebuild-local-ffi.sh $TARGET --universal"
    fi
fi

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
        # Honesty pass: claim ONLY the archs actually inside the slice binary.
        # (The name-derived defaults above lie after a host-arch-only macos rebuild
        # of a formerly-universal slice — Xcode then selects the slice for x86_64
        # and dies at link with undefined symbols instead of failing early.)
        slice_bin="$slice_path/libzcashlc.framework/libzcashlc"
        if actual_archs=$(lipo -archs "$slice_bin" 2>/dev/null) && [[ -n "$actual_archs" ]]; then
            entry_archs=""
            for a in $actual_archs; do
                entry_archs+="<string>${a}</string>"
            done
        fi
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
echo "Other platforms' slices were preserved as-is (NOT rebuilt) — check their"
echo "ENGINE_BUILD log tag before trusting them after Rust changes."
echo "Run 'init-local-ffi.sh --arm-all' to rebuild every slice fresh."
echo ""
echo "Xcode should automatically pick up the changes. If not, clean build folder (Cmd+Shift+K)."

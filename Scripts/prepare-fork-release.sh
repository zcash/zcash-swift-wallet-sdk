#!/bin/bash
# Build and upload xcframework to the valargroup fork
#
# This is a lightweight version of prepare-release.sh for the fork.
# It builds only iOS device + iOS simulator (arm64 only, no x86_64/macOS)
# to keep build times short during development.
#
# NOTE: Before upstreaming, all scripts and Package.swift changes need to be
# reviewed against the upstream contributing guidelines and the full
# prepare-release.sh / release.sh workflow restored.
#
# Usage: ./Scripts/prepare-fork-release.sh <version>
# Example: ./Scripts/prepare-fork-release.sh 0.1.0-voting

set -e
cd "$(dirname "$0")/.."

if [[ -f "$HOME/.cargo/env" ]]; then
    source "$HOME/.cargo/env"
fi

if [[ -z "$1" ]]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 0.1.0-voting"
    exit 1
fi

VERSION="$1"
REPO="valargroup/zcash-swift-wallet-sdk"
PRODUCTS_DIR="BuildSupport/products"
ZIP_FILE="libzcashlc.xcframework.zip"

echo "=== Fork release ${VERSION} (iOS only, arm64) ==="
echo ""

# --- Build ---

TARGETS="aarch64-apple-ios aarch64-apple-ios-sim"
for TARGET in $TARGETS; do
    if ! rustup target list --installed | grep -q "^${TARGET}$"; then
        echo "Installing Rust target ${TARGET}..."
        rustup target add "$TARGET"
    fi
    echo "Building ${TARGET} (release)..."
    cargo build --target "$TARGET" --release
done

# --- Assemble xcframework ---

echo ""
echo "Assembling xcframework..."

XCFW="$PRODUCTS_DIR/libzcashlc.xcframework"
rm -rf "$XCFW"

# iOS device slice (arm64)
DEVICE_FW="$XCFW/ios-arm64/libzcashlc.framework"
mkdir -p "$DEVICE_FW/Modules" "$DEVICE_FW/Headers"
cp target/aarch64-apple-ios/release/libzcashlc.a "$DEVICE_FW/libzcashlc"
cp -R target/Headers/* "$DEVICE_FW/Headers/"
cp BuildSupport/module.modulemap "$DEVICE_FW/Modules/"
cp BuildSupport/platform-Info.plist "$DEVICE_FW/Info.plist"

# iOS simulator slice (arm64 only — sufficient for Apple Silicon dev)
SIM_FW="$XCFW/ios-arm64-simulator/libzcashlc.framework"
mkdir -p "$SIM_FW/Modules" "$SIM_FW/Headers"
cp target/aarch64-apple-ios-sim/release/libzcashlc.a "$SIM_FW/libzcashlc"
cp -R target/Headers/* "$SIM_FW/Headers/"
cp BuildSupport/module.modulemap "$SIM_FW/Modules/"
cp BuildSupport/platform-Info.plist "$SIM_FW/Info.plist"

# xcframework Info.plist (iOS device + arm64 simulator only)
cat > "$XCFW/Info.plist" << 'PLISTEOF'
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

# --- Zip and checksum ---

echo ""
echo "Creating archive..."

cd "$PRODUCTS_DIR"
rm -f "$ZIP_FILE"
zip -r "$ZIP_FILE" libzcashlc.xcframework
CHECKSUM=$(shasum -a 256 "$ZIP_FILE" | awk '{print $1}')
cd ../..

DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ZIP_FILE}"

# --- Upload to GitHub ---

echo ""
echo "Uploading to GitHub..."

if gh release view "$VERSION" --repo "$REPO" &>/dev/null; then
    echo "Release $VERSION exists, updating assets..."
    gh release upload "$VERSION" \
        "$PRODUCTS_DIR/$ZIP_FILE" \
        --repo "$REPO" \
        --clobber
else
    gh release create "$VERSION" \
        "$PRODUCTS_DIR/$ZIP_FILE" \
        --repo "$REPO" \
        --title "$VERSION" \
        --notes "Development build for voting FFI integration" \
        --prerelease
fi

echo ""
echo "=========================================="
echo "  Release uploaded: ${DOWNLOAD_URL}"
echo "=========================================="
echo ""
echo "Update Package.swift binaryTarget:"
echo ""
echo "    url: \"${DOWNLOAD_URL}\","
echo "    checksum: \"${CHECKSUM}\""
echo ""

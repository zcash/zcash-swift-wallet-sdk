#!/usr/bin/env bash
#
# version-macos-framework.sh — convert a SHALLOW libzcashlc.framework into the
# VERSIONED bundle layout that macOS requires for an embedded framework.
#
# Why: BuildSupport/Makefile assembles every platform's framework identically —
# a flat `libzcashlc.framework/{libzcashlc,Headers,Modules,Info.plist}` with the
# shared `platform-Info.plist` (which is the iOS-simulator one: CFBundlePackageType
# BNDL, CFBundleSupportedPlatforms [iphonesimulator]). That is fine for iOS (shallow
# bundles), but macOS embedding fails with:
#   "... contains Info.plist, expected Versions/Current/Resources/Info.plist
#    since the platform does not use shallow bundles".
# This rewrites the macOS slice into Versions/A/... with the proper symlinks and a
# correct macOS Info.plist (FMWK / MacOSX / LSMinimumSystemVersion). Idempotent.
#
# Usage:
#   ./Scripts/version-macos-framework.sh <path/to/libzcashlc.framework>
# Default (no arg): the macOS slice inside the local-FFI xcframework.

set -euo pipefail

NAME="libzcashlc"
DEFAULT_FW="LocalPackages/libzcashlc.xcframework/macos-arm64_x86_64/${NAME}.framework"
FW="${1:-$DEFAULT_FW}"

if [[ ! -d "$FW" ]]; then
    echo "error: framework not found: $FW" >&2
    exit 1
fi

# Already versioned? Nothing to do.
if [[ -d "$FW/Versions/A" ]]; then
    echo "version-macos-framework: $FW already versioned — skipping"
    exit 0
fi

echo "version-macos-framework: converting $FW to versioned layout"

mkdir -p "$FW/Versions/A/Resources"

# Move the real payload under Versions/A.
[[ -f "$FW/$NAME" ]]   && mv "$FW/$NAME"   "$FW/Versions/A/$NAME"
[[ -d "$FW/Headers" ]] && mv "$FW/Headers" "$FW/Versions/A/Headers"
[[ -d "$FW/Modules" ]] && mv "$FW/Modules" "$FW/Versions/A/Modules"

# Drop the shallow (iOS) Info.plist and write the correct macOS one into Resources.
rm -f "$FW/Info.plist"
cat > "$FW/Versions/A/Resources/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleExecutable</key>
	<string>libzcashlc</string>
	<key>CFBundleIdentifier</key>
	<string>libzcashlc</string>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>CFBundleName</key>
	<string>libzcashlc</string>
	<key>CFBundlePackageType</key>
	<string>FMWK</string>
	<key>CFBundleVersion</key>
	<string>0.8.1</string>
	<key>CFBundleShortVersionString</key>
	<string>0.8.1</string>
	<key>CFBundleSupportedPlatforms</key>
	<array>
		<string>MacOSX</string>
	</array>
	<key>LSMinimumSystemVersion</key>
	<string>12.0</string>
</dict>
</plist>
PLIST

# Symlinks: Versions/Current -> A, then the top-level entries -> Versions/Current/*.
ln -sfn A "$FW/Versions/Current"
ln -sfn "Versions/Current/$NAME" "$FW/$NAME"
ln -sfn Versions/Current/Headers "$FW/Headers"
ln -sfn Versions/Current/Modules "$FW/Modules"
ln -sfn Versions/Current/Resources "$FW/Resources"

echo "version-macos-framework: done"

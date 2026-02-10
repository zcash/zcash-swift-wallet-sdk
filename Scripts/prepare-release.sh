#!/bin/bash
# Prepare FFI artifacts for an SDK release
# Usage: ./Scripts/prepare-release.sh [--force-overwrite-existing-release] <version>
#
# This script:
#   1. Builds the full xcframework (all architectures)
#   2. Creates a zip archive with checksum
#   3. Uploads to GitHub as a DRAFT release
#   4. Outputs the values needed for Package.swift
#
# After running this script:
#   1. Update Package.swift with the URL and checksum
#   2. Commit the Package.swift change
#   3. Create a signed tag for the SDK release
#   4. Publish the draft release on GitHub
#
# Options:
#   --force-overwrite-existing-release  Allow overwriting an existing release
#
# Prerequisites:
#   - gh CLI installed and authenticated (https://cli.github.com/)
#   - Rust toolchain with all Apple targets
#   - GPG key configured for signing tags

set -e
cd "$(dirname "$0")/.."

FORCE_OVERWRITE=false
if [[ "$1" == "--force-overwrite-existing-release" ]]; then
    FORCE_OVERWRITE=true
    shift
fi

if [[ -z "$1" ]]; then
    echo "Usage: $0 [--force-overwrite-existing-release] <version>"
    echo "Example: $0 2.5.0"
    exit 1
fi

VERSION="$1"
REPO="zcash/zcash-swift-wallet-sdk"
PRODUCTS_DIR="BuildSupport/products"
ZIP_FILE="libzcashlc.xcframework.zip"

echo "=== Preparing release ${VERSION} ==="
echo ""

# Check for uncommitted changes
if [[ -n $(git status --porcelain) ]]; then
    echo "Warning: You have uncommitted changes."
    read -p "Continue anyway? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Build full xcframework
echo "=== Building xcframework (this takes a while) ==="
cd BuildSupport
make clean
make xcframework
cd ..

# Create release archive
echo ""
echo "=== Creating release archive ==="
cd "$PRODUCTS_DIR"
rm -f "$ZIP_FILE" checksum.txt
zip -r "$ZIP_FILE" libzcashlc.xcframework
CHECKSUM=$(shasum -a 256 "$ZIP_FILE" | awk '{print $1}')
echo "$CHECKSUM  $ZIP_FILE" > checksum.txt
cd ../..

# Upload to GitHub as draft release
echo ""
echo "=== Uploading to GitHub (draft release) ==="

if gh release view "$VERSION" --repo "$REPO" &>/dev/null; then
    if [[ "$FORCE_OVERWRITE" != "true" ]]; then
        echo "Error: Release $VERSION already exists."
        echo "Use --force-overwrite-existing-release to update an existing release."
        exit 1
    fi
    echo "Release $VERSION already exists. Updating assets (--force-overwrite-existing-release)..."
    gh release upload "$VERSION" \
        "$PRODUCTS_DIR/$ZIP_FILE" \
        "$PRODUCTS_DIR/checksum.txt" \
        --repo "$REPO" \
        --clobber
else
    gh release create "$VERSION" \
        "$PRODUCTS_DIR/$ZIP_FILE" \
        "$PRODUCTS_DIR/checksum.txt" \
        --repo "$REPO" \
        --title "$VERSION" \
        --notes "Zcash Light Client SDK ${VERSION}" \
        --draft
fi

RELEASE_URL="https://github.com/${REPO}/releases/tag/${VERSION}"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ZIP_FILE}"

echo ""
echo "=========================================="
echo "  Draft release created: ${RELEASE_URL}"
echo "=========================================="
echo ""
echo "Next steps:"
echo ""
echo "1. Update Package.swift with:"
echo ""
echo "   .binaryTarget("
echo "       name: \"libzcashlc\","
echo "       url: \"${DOWNLOAD_URL}\","
echo "       checksum: \"${CHECKSUM}\""
echo "   ),"
echo ""
echo "2. Commit the change:"
echo "   git add Package.swift"
echo "   git commit -m \"Prepare release ${VERSION}\""
echo ""
echo "3. Create signed tag:"
echo "   git tag -s ${VERSION} -m \"Release ${VERSION}\""
echo ""
echo "4. Push:"
echo "   git push origin main ${VERSION}"
echo ""
echo "5. Publish the draft release:"
echo "   ${RELEASE_URL}"
echo ""

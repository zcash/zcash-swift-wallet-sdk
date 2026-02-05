#!/bin/bash
# Full SDK release workflow
# Usage: ./Scripts/release.sh <version>
#
# This script performs the COMPLETE release process:
#   1. Verifies clean working directory
#   2. Builds the full xcframework
#   3. Uploads artifacts to GitHub (draft release)
#   4. Updates Package.swift with URL and checksum
#   5. Commits the Package.swift change
#   6. Creates a signed tag
#   7. Pushes to origin
#   8. Publishes the GitHub release
#
# Prerequisites:
#   - gh CLI installed and authenticated
#   - Rust toolchain with all Apple targets
#   - GPG key configured for signing tags
#   - Clean working directory (no uncommitted changes)
#
# For security releases where you need more control over timing,
# use prepare-release.sh instead and perform steps manually.

set -e
cd "$(dirname "$0")/.."

if [[ -z "$1" ]]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 2.5.0"
    exit 1
fi

VERSION="$1"
REPO="zcash/zcash-swift-wallet-sdk"
PRODUCTS_DIR="BuildSupport/products"
ZIP_FILE="libzcashlc.xcframework.zip"

echo "=== SDK Release ${VERSION} ==="
echo ""

# Verify clean working directory
if [[ -n $(git status --porcelain) ]]; then
    echo "Error: Working directory is not clean."
    echo "Please commit or stash your changes before releasing."
    git status --short
    exit 1
fi

# Verify we're on main branch
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [[ "$CURRENT_BRANCH" != "main" ]]; then
    echo "Warning: You are on branch '$CURRENT_BRANCH', not 'main'."
    read -p "Continue anyway? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check if tag already exists
if git rev-parse "$VERSION" >/dev/null 2>&1; then
    echo "Error: Tag $VERSION already exists."
    exit 1
fi

# Verify GPG signing is configured
if ! git config --get user.signingkey >/dev/null 2>&1; then
    echo "Error: No GPG signing key configured."
    echo "Run: git config --global user.signingkey <your-key-id>"
    exit 1
fi

echo "=== Step 1/8: Building xcframework ==="
cd BuildSupport
make clean
make xcframework
cd ..

echo ""
echo "=== Step 2/8: Creating release archive ==="
cd "$PRODUCTS_DIR"
rm -f "$ZIP_FILE" checksum.txt
zip -r "$ZIP_FILE" libzcashlc.xcframework
CHECKSUM=$(shasum -a 256 "$ZIP_FILE" | awk '{print $1}')
echo "$CHECKSUM  $ZIP_FILE" > checksum.txt
cd ../..

echo ""
echo "=== Step 3/8: Uploading to GitHub (draft) ==="
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ZIP_FILE}"

gh release create "$VERSION" \
    "$PRODUCTS_DIR/$ZIP_FILE" \
    "$PRODUCTS_DIR/checksum.txt" \
    --repo "$REPO" \
    --title "$VERSION" \
    --notes "Zcash Light Client SDK ${VERSION}" \
    --draft

echo ""
echo "=== Step 4/8: Updating Package.swift ==="

# Update the binaryTarget URL and checksum in Package.swift
# This uses sed to find and replace the url and checksum lines
sed -i.bak -E \
    -e "s|(url: \"https://github.com/${REPO}/releases/download/)[^\"]+(/libzcashlc.xcframework.zip\")|\1${VERSION}\2|" \
    -e "s|(checksum: \")[^\"]+(\")|\1${CHECKSUM}\2|" \
    Package.swift
rm -f Package.swift.bak

# Verify the update worked
if ! grep -q "download/${VERSION}/libzcashlc.xcframework.zip" Package.swift; then
    echo "Error: Failed to update Package.swift URL"
    git checkout Package.swift
    exit 1
fi

if ! grep -q "checksum: \"${CHECKSUM}\"" Package.swift; then
    echo "Error: Failed to update Package.swift checksum"
    git checkout Package.swift
    exit 1
fi

echo "Package.swift updated with:"
echo "  URL: ${DOWNLOAD_URL}"
echo "  Checksum: ${CHECKSUM}"

echo ""
echo "=== Step 5/8: Committing Package.swift ==="
git add Package.swift
git commit -m "Prepare release ${VERSION}"

echo ""
echo "=== Step 6/8: Creating signed tag ==="
git tag -s "$VERSION" -m "Release ${VERSION}"

echo ""
echo "=== Step 7/8: Pushing to origin ==="
git push origin "$CURRENT_BRANCH" "$VERSION"

echo ""
echo "=== Step 8/8: Publishing release ==="
gh release edit "$VERSION" --repo "$REPO" --draft=false

echo ""
echo "=========================================="
echo "  Release ${VERSION} complete!"
echo "=========================================="
echo ""
echo "  GitHub Release: https://github.com/${REPO}/releases/tag/${VERSION}"
echo "  Package.swift updated and pushed"
echo "  Signed tag ${VERSION} created and pushed"
echo ""

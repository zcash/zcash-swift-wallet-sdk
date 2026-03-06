#!/bin/bash
# Full SDK release workflow
# Usage: ./Scripts/release.sh <remote> <version>
#
# This script performs the COMPLETE release process:
#   1. Pre-flight checks (clean dir, branch, GPG)
#   2. Builds xcframework and uploads draft release (via prepare-release.sh)
#   3. Updates Package.swift with URL and checksum
#   4. Commits the Package.swift change
#   5. Pauses for manual verification of the draft release
#   6. Creates a signed tag
#   7. Pushes to the specified remote
#   8. Publishes the GitHub release
#
# Arguments:
#   <remote>   The git remote pointing to zcash/zcash-swift-wallet-sdk
#              (e.g., 'origin' or 'upstream')
#   <version>  The version to release (e.g., '2.5.0')
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

if [[ -z "$1" ]] || [[ -z "$2" ]]; then
    echo "Usage: $0 <remote> <version>"
    echo "Example: $0 upstream 2.5.0"
    echo ""
    echo "Available remotes:"
    git remote -v
    exit 1
fi

UPSTREAM_REMOTE="$1"
VERSION="$2"

# Verify the remote exists
if ! git remote get-url "$UPSTREAM_REMOTE" &>/dev/null; then
    echo "Error: Remote '$UPSTREAM_REMOTE' does not exist."
    echo ""
    echo "Available remotes:"
    git remote -v
    exit 1
fi
REPO="zcash/zcash-swift-wallet-sdk"
PRODUCTS_DIR="BuildSupport/products"

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

# === Step 1: Build and upload draft release ===
echo "=== Step 1/6: Build and upload draft release ==="
./Scripts/prepare-release.sh "$VERSION"

# Read release info written by prepare-release.sh
source "$PRODUCTS_DIR/release.env"

echo ""
echo "=== Step 2/6: Updating Package.swift ==="

# Update the binaryTarget URL and checksum in Package.swift
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
echo "=== Step 3/6: Committing Package.swift ==="
git add Package.swift
git commit -m "Prepare release ${VERSION}"

# === Confirmation step ===
echo ""
echo "=========================================="
echo "  Draft release uploaded and Package.swift committed."
echo "  Please verify the draft release before continuing:"
echo ""
echo "  https://github.com/${REPO}/releases/tag/${VERSION}"
echo "=========================================="
echo ""
read -p "Proceed with tagging, pushing, and publishing? [y/N] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "Release paused. To resume manually:"
    echo "  git tag -s ${VERSION} -m \"Release ${VERSION}\""
    echo "  git push ${UPSTREAM_REMOTE} ${CURRENT_BRANCH} ${VERSION}"
    echo "  gh release edit ${VERSION} --repo ${REPO} --draft=false"
    exit 0
fi

echo ""
echo "=== Step 4/6: Creating signed tag ==="
git tag -s "$VERSION" -m "Release ${VERSION}"

echo ""
echo "=== Step 5/6: Pushing to $UPSTREAM_REMOTE ==="
git push "$UPSTREAM_REMOTE" "$CURRENT_BRANCH" "$VERSION"

echo ""
echo "=== Step 6/6: Publishing release ==="
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

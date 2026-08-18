#!/bin/bash
# Full SDK release workflow
# Usage: ./Scripts/release.sh <remote> <version>
#
# This script performs the COMPLETE release process:
#   1. Pre-flight checks (clean dir, branch, GPG)
#   2. Builds BOTH xcframework variants and uploads them to one draft release
#      (via prepare-release.sh --zodl-slipstream; the clean build runs the AGPL
#      purity gate)
#   3. Updates all four artifact pins in Package.swift
#   4. Commits the Package.swift change
#   5. Pauses for manual verification of the draft release
#   6. Creates two signed tags: X.Y.Z (clean) and X.Y.Z-zodl-slipstream (a
#      one-commit variant flipping zodlSlipstreamVariantPinned)
#   7. Pushes branch and both tags to the specified remote
#   8. Publishes the GitHub release
#
# Arguments:
#   <remote>   The git remote pointing to zcash/zcash-swift-wallet-sdk
#              (e.g., 'origin' or 'upstream')
#   <version>  The version to release (e.g., '2.5.0')
#
# Versions with a SemVer pre-release suffix (e.g. 2.6.0-alpha.1, 2.7.0-rc.2)
# are detected automatically and the GitHub release is marked as a pre-release.
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

# Ensure Rust toolchain is on PATH (needed when invoked from Xcode build phases)
if [[ -f "$HOME/.cargo/env" ]]; then
    source "$HOME/.cargo/env"
fi

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

# SemVer: a hyphen in the version (e.g. 2.6.0-alpha.1) marks a pre-release
PRERELEASE_FLAG=()
if [[ "$VERSION" == *-* ]]; then
    PRERELEASE_FLAG=(--prerelease)
fi

echo "=== SDK Release ${VERSION} ==="
if [[ ${#PRERELEASE_FLAG[@]} -gt 0 ]]; then
    echo "Pre-release suffix detected. The GitHub release will be marked as a pre-release."
fi
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

# Check if tags already exist (the release cuts BOTH variant tags)
ZODL_SLIPSTREAM_TAG="${VERSION}-zodl-slipstream"
for tag in "$VERSION" "$ZODL_SLIPSTREAM_TAG"; do
    if git rev-parse "$tag" >/dev/null 2>&1; then
        echo "Error: Tag $tag already exists."
        exit 1
    fi
done

# Verify GPG signing is configured
if ! git config --get user.signingkey >/dev/null 2>&1; then
    echo "Error: No GPG signing key configured."
    echo "Run: git config --global user.signingkey <your-key-id>"
    exit 1
fi

# === Step 1: Build and upload draft release (both artifact variants) ===
echo "=== Step 1/6: Build and upload draft release ==="
./Scripts/prepare-release.sh --zodl-slipstream "$VERSION"

# Read release info written by prepare-release.sh
source "$PRODUCTS_DIR/release.env"

if [[ -z "${ZODL_SLIPSTREAM_CHECKSUM:-}" ]] || [[ -z "${ZODL_SLIPSTREAM_DOWNLOAD_URL:-}" ]]; then
    echo "Error: release.env is missing the ZODL Slipstream artifact info."
    exit 1
fi

echo ""
echo "=== Step 2/6: Updating Package.swift ==="

# Update the four binary-artifact pins in Package.swift. Both pairs live on
# every release commit; which pair the manifest uses is decided by the
# zodlSlipstreamVariantPinned constant (flipped only on the variant tag below).
sed -i.bak -E \
    -e "s|(let cleanFFIURL = \")[^\"]*(\")|\1${DOWNLOAD_URL}\2|" \
    -e "s|(let cleanFFIChecksum = \")[^\"]*(\")|\1${CHECKSUM}\2|" \
    -e "s|(let zodlSlipstreamFFIURL = \")[^\"]*(\")|\1${ZODL_SLIPSTREAM_DOWNLOAD_URL}\2|" \
    -e "s|(let zodlSlipstreamFFIChecksum = \")[^\"]*(\")|\1${ZODL_SLIPSTREAM_CHECKSUM}\2|" \
    Package.swift
rm -f Package.swift.bak

# Verify the update worked
for expected in \
    "let cleanFFIURL = \"${DOWNLOAD_URL}\"" \
    "let cleanFFIChecksum = \"${CHECKSUM}\"" \
    "let zodlSlipstreamFFIURL = \"${ZODL_SLIPSTREAM_DOWNLOAD_URL}\"" \
    "let zodlSlipstreamFFIChecksum = \"${ZODL_SLIPSTREAM_CHECKSUM}\""
do
    if ! grep -qF "$expected" Package.swift; then
        echo "Error: Failed to update Package.swift (missing: $expected)"
        git checkout Package.swift
        exit 1
    fi
done

echo "Package.swift updated with:"
echo "  Clean URL: ${DOWNLOAD_URL}"
echo "  Clean checksum: ${CHECKSUM}"
echo "  ZODL Slipstream URL: ${ZODL_SLIPSTREAM_DOWNLOAD_URL}"
echo "  ZODL Slipstream checksum: ${ZODL_SLIPSTREAM_CHECKSUM}"

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
    echo "  # variant tag: flip zodlSlipstreamVariantPinned to true in Package.swift,"
    echo "  # commit, tag ${ZODL_SLIPSTREAM_TAG}, then git reset --hard HEAD~1"
    echo "  git push ${UPSTREAM_REMOTE} ${CURRENT_BRANCH} ${VERSION} ${ZODL_SLIPSTREAM_TAG}"
    echo "  gh release edit ${VERSION} --repo ${REPO} --draft=false${PRERELEASE_FLAG:+ ${PRERELEASE_FLAG[*]}}"
    exit 0
fi

echo ""
echo "=== Step 4/6: Creating signed tags (clean + ZODL Slipstream variant) ==="
git tag -s "$VERSION" -m "Release ${VERSION}"

# The variant tag is ONE commit on top of the release commit, flipping the
# zodlSlipstreamVariantPinned constant so the manifest selects the AGPL superset
# artifact and grows the ZODLSlipstream product. The flag must change the
# manifest BYTES (not just a marker file): SwiftPM's shared manifest cache is
# keyed on manifest content, and byte-identical manifests across the two tags
# would conflate their target graphs. SemVer sorts the -zodl-slipstream
# pre-release suffix below ${VERSION}, so version ranges never resolve to it;
# consumers opt in with exact: only.
sed -i.bak 's|let zodlSlipstreamVariantPinned = false|let zodlSlipstreamVariantPinned = true|' Package.swift
rm -f Package.swift.bak
if ! grep -q "let zodlSlipstreamVariantPinned = true" Package.swift; then
    echo "Error: Failed to flip zodlSlipstreamVariantPinned for the variant tag"
    git checkout Package.swift
    exit 1
fi
git add Package.swift
git commit -m "Select the ZODL Slipstream (AGPL) variant for ${ZODL_SLIPSTREAM_TAG}"
git tag -s "$ZODL_SLIPSTREAM_TAG" -m "Release ${ZODL_SLIPSTREAM_TAG} (ZODL Slipstream variant, AGPL-3.0-only engine)"
# Return the branch to the clean release commit; the variant lives on via its tag.
git reset --hard HEAD~1

echo ""
echo "=== Step 5/6: Pushing to $UPSTREAM_REMOTE ==="
git push "$UPSTREAM_REMOTE" "$CURRENT_BRANCH" "$VERSION" "$ZODL_SLIPSTREAM_TAG"

echo ""
echo "=== Step 6/6: Publishing release ==="
gh release edit "$VERSION" --repo "$REPO" --draft=false "${PRERELEASE_FLAG[@]}"

echo ""
echo "=========================================="
if [[ ${#PRERELEASE_FLAG[@]} -gt 0 ]]; then
    echo "  Pre-release ${VERSION} complete!"
else
    echo "  Release ${VERSION} complete!"
fi
echo "=========================================="
echo ""
echo "  GitHub Release: https://github.com/${REPO}/releases/tag/${VERSION}"
echo "  Package.swift updated and pushed"
echo "  Signed tag ${VERSION} created and pushed"
echo ""

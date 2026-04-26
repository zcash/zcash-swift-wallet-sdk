#!/bin/bash
# Build xcframework, upload to GitHub release, and update Package.swift
# to point at the new release. Designed for feature-branch PR workflows
# where reviewers pull and build with zero Rust setup.
#
# Usage: ./Scripts/publish-fork-release.sh <version>
# Example: ./Scripts/publish-fork-release.sh 0.6.0-voting-2.4.10-rc1

set -e
cd "$(dirname "$0")/.."

if [[ -z "$1" ]]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 0.6.0-voting-2.4.10-rc1"
    exit 1
fi

VERSION="$1"
REPO="valargroup/zcash-swift-wallet-sdk"
ZIP_FILE="libzcashlc.xcframework.zip"
ZIP_PATH="BuildSupport/products/$ZIP_FILE"

# Refuse to run if Package.swift is wired local (skip-worktree set) — in that
# state it holds local path overrides, not the binaryTarget we need to patch.
if git ls-files -v -- Package.swift | grep -q '^S'; then
    echo "Error: Package.swift has skip-worktree set (wired local)."
    echo "Unwire from the workspace before publishing a release."
    exit 1
fi

./Scripts/prepare-fork-release.sh "$VERSION"

CHECKSUM=$(shasum -a 256 "$ZIP_PATH" | awk '{print $1}')
URL="https://github.com/${REPO}/releases/download/${VERSION}/${ZIP_FILE}"

echo ""
echo "Updating Package.swift binaryTarget..."

sed -i.bak -E "s|url: \"https://github.com/${REPO}/releases/download/[^\"]+/libzcashlc.xcframework.zip\"|url: \"${URL}\"|" Package.swift
sed -i.bak -E "s|checksum: \"[a-f0-9]+\"|checksum: \"${CHECKSUM}\"|" Package.swift
rm -f Package.swift.bak

if ! grep -q "url: \"${URL}\"" Package.swift; then
    echo "Error: Failed to update url in Package.swift"
    exit 1
fi
if ! grep -q "checksum: \"${CHECKSUM}\"" Package.swift; then
    echo "Error: Failed to update checksum in Package.swift"
    exit 1
fi

echo ""
echo "=========================================="
echo "  Published ${VERSION}"
echo "=========================================="
echo ""
echo "Package.swift updated. Review and commit:"
echo ""
echo "    git diff Package.swift"
echo "    git add Package.swift"
echo "    git commit -m \"Point Package.swift at ${VERSION}\""

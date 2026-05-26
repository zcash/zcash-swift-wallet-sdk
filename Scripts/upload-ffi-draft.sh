#!/bin/bash
# Package an already-built libzcashlc XCFramework and upload it as a draft
# GitHub release. Versions with an -alpha.N / -beta.N suffix are marked as
# GitHub pre-releases.
#
# Assumes BuildSupport/products/libzcashlc.xcframework already exists
# (build it with: make -C BuildSupport xcframework).
#
# Writes BuildSupport/products/release.env with CHECKSUM / DOWNLOAD_URL / VERSION.
#
# Usage: ./Scripts/upload-ffi-draft.sh [--force-overwrite-existing-release] <version>
#
# Prerequisites: gh CLI installed and authenticated.

set -e
cd "$(dirname "$0")/.."

FORCE_OVERWRITE=false
if [[ "$1" == "--force-overwrite-existing-release" ]]; then
    FORCE_OVERWRITE=true
    shift
fi

VERSION="$1"
if [[ -z "$VERSION" ]]; then
    echo "Usage: $0 [--force-overwrite-existing-release] <version>" >&2
    exit 1
fi

REPO="zcash/zcash-swift-wallet-sdk"
PRODUCTS_DIR="BuildSupport/products"
ZIP_FILE="libzcashlc.xcframework.zip"

if [[ ! -d "$PRODUCTS_DIR/libzcashlc.xcframework" ]]; then
    echo "Error: $PRODUCTS_DIR/libzcashlc.xcframework not found." >&2
    echo "Build it first with: make -C BuildSupport xcframework" >&2
    exit 1
fi

# Create the release archive and checksum.
echo "=== Creating release archive ==="
(
    cd "$PRODUCTS_DIR"
    rm -f "$ZIP_FILE"
    zip -r "$ZIP_FILE" libzcashlc.xcframework
)
CHECKSUM=$(shasum -a 256 "$PRODUCTS_DIR/$ZIP_FILE" | awk '{print $1}')
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ZIP_FILE}"

# alpha/beta versions are GitHub pre-releases.
PRERELEASE_FLAG=""
if [[ "$VERSION" == *-alpha.* || "$VERSION" == *-beta.* ]]; then
    PRERELEASE_FLAG="--prerelease"
fi

echo ""
echo "=== Uploading to GitHub (draft release) ==="
if gh release view "$VERSION" --repo "$REPO" &>/dev/null; then
    if [[ "$FORCE_OVERWRITE" != "true" ]]; then
        echo "Error: release $VERSION already exists." >&2
        echo "Use --force-overwrite-existing-release to update an existing release." >&2
        exit 1
    fi
    # Refuse to overwrite the assets of a release that has already been
    # published. The force flag is intended for retrying a draft, not for
    # silently replacing a binary that downstream consumers may already
    # have downloaded.
    EXISTING_IS_DRAFT=$(gh release view "$VERSION" --repo "$REPO" --json isDraft --jq '.isDraft')
    if [[ "$EXISTING_IS_DRAFT" != "true" ]]; then
        echo "Error: release $VERSION is already published; refusing to clobber its assets." >&2
        echo "If you really need to replace published artifacts, do it manually via gh." >&2
        exit 1
    fi
    echo "Release $VERSION already exists as a draft. Updating assets..."
    gh release upload "$VERSION" \
        "$PRODUCTS_DIR/$ZIP_FILE" \
        --repo "$REPO" \
        --clobber
else
    gh release create "$VERSION" \
        "$PRODUCTS_DIR/$ZIP_FILE" \
        --repo "$REPO" \
        --title "$VERSION" \
        --notes "Zcash Light Client SDK ${VERSION}" \
        --draft $PRERELEASE_FLAG
fi

# Write release info only after a successful upload, so a failed upload
# does not leave a release.env claiming the artifact was published.
cat > "$PRODUCTS_DIR/release.env" << EOF
CHECKSUM=${CHECKSUM}
DOWNLOAD_URL=${DOWNLOAD_URL}
VERSION=${VERSION}
EOF

echo ""
echo "Draft release ready: https://github.com/${REPO}/releases/tag/${VERSION}"
echo "  URL:      ${DOWNLOAD_URL}"
echo "  Checksum: ${CHECKSUM}"

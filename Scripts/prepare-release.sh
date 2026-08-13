#!/bin/bash
# Prepare FFI artifacts for an SDK release
# Usage: ./Scripts/prepare-release.sh [--force-overwrite-existing-release] [--slipstream] <version>
#
# This is the CANONICAL build+upload path for releases. It:
#   1. Builds the full xcframework (all architectures)
#   2. Creates a zip archive with checksum
#   3. Uploads to GitHub as a DRAFT release
#   4. Writes release info to BuildSupport/products/release.env
#   5. Outputs the values needed for Package.swift
#
# Versions with a SemVer pre-release suffix (e.g. 2.6.0-alpha.1, 2.7.0-rc.2)
# are detected automatically and the GitHub release is marked as a pre-release.
#
# After running this script:
#   1. Update Package.swift with the URL and checksum
#   2. Commit the Package.swift change
#   3. Create a signed tag for the SDK release
#   4. Publish the draft release on GitHub
#
# Or use ./Scripts/release.sh to automate all of the above.
#
# Options:
#   --force-overwrite-existing-release  Allow overwriting an existing release
#   --slipstream                        Also build and upload the ZODL Slipstream
#                                        (AGPL-3.0-only) variant as a second asset
#                                        on the SAME draft release. The default
#                                        artifact (libzcashlc.xcframework.zip) is
#                                        always built and is always the MIT-clean
#                                        product; this flag only adds the opt-in
#                                        libzcashlc-zodl-slipstream.xcframework.zip
#                                        alongside it.
#
# Prerequisites:
#   - gh CLI installed and authenticated (https://cli.github.com/)
#   - Rust toolchain with all Apple targets

set -e
cd "$(dirname "$0")/.."

# Ensure cargo/rustup are on PATH (needed when invoked from CI or Xcode)
if [[ -f "$HOME/.cargo/env" ]]; then
    source "$HOME/.cargo/env"
fi

FORCE_OVERWRITE=false
SLIPSTREAM=false
while [[ "$1" == --* ]]; do
    case "$1" in
        --force-overwrite-existing-release)
            FORCE_OVERWRITE=true
            ;;
        --slipstream)
            SLIPSTREAM=true
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--force-overwrite-existing-release] [--slipstream] <version>"
            exit 1
            ;;
    esac
    shift
done

if [[ -z "$1" ]]; then
    echo "Usage: $0 [--force-overwrite-existing-release] [--slipstream] <version>"
    echo "Example: $0 2.5.0"
    echo "         $0 --slipstream 2.9.0"
    exit 1
fi

VERSION="$1"
# Release onto the repo the workflow runs in (GITHUB_REPOSITORY in Actions), so forks can
# publish their own FFI releases — the hardcoded upstream 403s under a fork's CI token.
REPO="${GITHUB_REPOSITORY:-zcash/zcash-swift-wallet-sdk}"
PRODUCTS_DIR="BuildSupport/products"
ZIP_FILE="libzcashlc.xcframework.zip"
SLIPSTREAM_PRODUCTS_DIR="BuildSupport/products-slipstream"
SLIPSTREAM_ZIP_FILE="libzcashlc-zodl-slipstream.xcframework.zip"

# SemVer: a hyphen in the version (e.g. 2.6.0-alpha.1) marks a pre-release
PRERELEASE_FLAG=()
if [[ "$VERSION" == *-* ]]; then
    PRERELEASE_FLAG=(--prerelease)
fi

echo "=== Preparing release ${VERSION} ==="
if [[ ${#PRERELEASE_FLAG[@]} -gt 0 ]]; then
    echo "Pre-release suffix detected. The GitHub release will be marked as a pre-release."
fi
if [[ "$SLIPSTREAM" == "true" ]]; then
    echo "Also building the ZODL Slipstream (AGPL-3.0-only) variant for this release."
fi
echo ""

# Check for uncommitted changes (skip in non-interactive mode, e.g. CI)
if [[ -t 0 ]] && [[ -n $(git status --porcelain) ]]; then
    echo "Warning: You have uncommitted changes."
    read -p "Continue anyway? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

git checkout -b "release/ffi-${VERSION}"

# Build full xcframework
echo "=== Building xcframework (this takes a while) ==="
cd BuildSupport
make clean
make xcframework
cd ..

# Hard purity gate: the default artifact must ship zero AGPL zodl-slipstream code,
# regardless of whether --slipstream was passed. This is what stands between an
# accidental Cargo.toml/feature regression and an AGPL-contaminated "clean" release.
echo ""
echo "=== Verifying clean artifact purity (no AGPL zodl-slipstream code) ==="
CLEAN_CONTAMINATED=false
while IFS= read -r slice; do
    SLICE_COUNT=$(nm -gU "$slice" 2>/dev/null | grep -c zcashlc_slipstream || true)
    if [[ "$SLICE_COUNT" -ne 0 ]]; then
        echo "FATAL: $slice exports $SLICE_COUNT zcashlc_slipstream symbol(s) — the clean artifact must ship zero."
        CLEAN_CONTAMINATED=true
    fi
done < <(find "$PRODUCTS_DIR" -name "libzcashlc.a")
while IFS= read -r header; do
    if grep -q "ZCASHLC_FEATURE_SLIPSTREAM" "$header"; then
        echo "FATAL: $header still references ZCASHLC_FEATURE_SLIPSTREAM — unifdef should have stripped it."
        CLEAN_CONTAMINATED=true
    fi
done < <(find "$PRODUCTS_DIR/libzcashlc.xcframework" -name "zcashlc.h")
if [[ "$CLEAN_CONTAMINATED" == "true" ]]; then
    echo ""
    echo "Aborting: the default libzcashlc.xcframework artifact must be MIT-clean (zero AGPL code)."
    exit 1
fi
echo "Clean: no zcashlc_slipstream symbols in any staticlib slice, no ZCASHLC_FEATURE_SLIPSTREAM in the header."

# Create release archive
echo ""
echo "=== Creating release archive ==="
cd "$PRODUCTS_DIR"
rm -f "$ZIP_FILE"
zip -r "$ZIP_FILE" libzcashlc.xcframework
CHECKSUM=$(shasum -a 256 "$ZIP_FILE" | awk '{print $1}')
cd ../..

DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ZIP_FILE}"

SLIPSTREAM_CHECKSUM=""
SLIPSTREAM_DOWNLOAD_URL=""
if [[ "$SLIPSTREAM" == "true" ]]; then
    # Build the superset xcframework (inner name stays libzcashlc.xcframework;
    # only the outer zip and the products-slipstream/ tree are variant-named).
    echo ""
    echo "=== Building ZODL Slipstream (AGPL) xcframework variant ==="
    cd BuildSupport
    make clean SLIPSTREAM=1
    make xcframework SLIPSTREAM=1
    cd ..

    # Inverse of the clean-artifact gate above: every slice must actually carry
    # the engine, or the "slipstream" artifact would silently be the clean one.
    echo ""
    echo "=== Verifying slipstream artifact completeness (AGPL engine present) ==="
    SLIPSTREAM_INCOMPLETE=false
    while IFS= read -r slice; do
        SLICE_COUNT=$(nm -gU "$slice" 2>/dev/null | grep -c zcashlc_slipstream || true)
        if [[ "$SLICE_COUNT" -eq 0 ]]; then
            echo "FATAL: $slice exports zero zcashlc_slipstream symbols — the slipstream artifact must carry the engine."
            SLIPSTREAM_INCOMPLETE=true
        fi
    done < <(find "$SLIPSTREAM_PRODUCTS_DIR" -name "libzcashlc.a")
    if [[ "$SLIPSTREAM_INCOMPLETE" == "true" ]]; then
        echo ""
        echo "Aborting: the ZODL Slipstream artifact must carry the full slipstream engine in every slice."
        exit 1
    fi
    echo "Slipstream engine present in every staticlib slice."

    echo ""
    echo "=== Creating ZODL Slipstream release archive ==="
    cd "$SLIPSTREAM_PRODUCTS_DIR"
    rm -f "$SLIPSTREAM_ZIP_FILE"
    zip -r "$SLIPSTREAM_ZIP_FILE" libzcashlc.xcframework
    SLIPSTREAM_CHECKSUM=$(shasum -a 256 "$SLIPSTREAM_ZIP_FILE" | awk '{print $1}')
    cd ../..

    SLIPSTREAM_DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${SLIPSTREAM_ZIP_FILE}"
fi

# Write release info for consumption by other scripts (release.sh, CI)
{
    echo "CHECKSUM=${CHECKSUM}"
    echo "DOWNLOAD_URL=${DOWNLOAD_URL}"
    echo "VERSION=${VERSION}"
    if [[ "$SLIPSTREAM" == "true" ]]; then
        echo "SLIPSTREAM_CHECKSUM=${SLIPSTREAM_CHECKSUM}"
        echo "SLIPSTREAM_DOWNLOAD_URL=${SLIPSTREAM_DOWNLOAD_URL}"
    fi
} > "$PRODUCTS_DIR/release.env"

# Upload to GitHub as draft release
echo ""
echo "=== Uploading to GitHub (draft release) ==="

UPLOAD_FILES=("$PRODUCTS_DIR/$ZIP_FILE")
if [[ "$SLIPSTREAM" == "true" ]]; then
    UPLOAD_FILES+=("$SLIPSTREAM_PRODUCTS_DIR/$SLIPSTREAM_ZIP_FILE")
fi

if gh release view "$VERSION" --repo "$REPO" &>/dev/null; then
    if [[ "$FORCE_OVERWRITE" != "true" ]]; then
        echo "Error: Release $VERSION already exists."
        echo "Use --force-overwrite-existing-release to update an existing release."
        exit 1
    fi
    echo "Release $VERSION already exists. Updating assets (--force-overwrite-existing-release)..."
    gh release upload "$VERSION" \
        "${UPLOAD_FILES[@]}" \
        --repo "$REPO" \
        --clobber
    # gh release upload can only replace assets, not release properties, so an
    # existing release (e.g. one created before pre-release detection existed)
    # needs an explicit edit to gain the pre-release bit.
    if [[ ${#PRERELEASE_FLAG[@]} -gt 0 ]]; then
        echo "Marking existing release ${VERSION} as a pre-release."
        gh release edit "$VERSION" --repo "$REPO" "${PRERELEASE_FLAG[@]}"
    fi
else
    gh release create "$VERSION" \
        "${UPLOAD_FILES[@]}" \
        --repo "$REPO" \
        --title "$VERSION" \
        --notes "Zcash Light Client SDK ${VERSION}" \
        --draft \
        "${PRERELEASE_FLAG[@]}"
fi

RELEASE_URL="https://github.com/${REPO}/releases/tag/${VERSION}"

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
if [[ "$SLIPSTREAM" == "true" ]]; then
    echo ""
    echo "   ...and the ZODL Slipstream variant's binaryTarget with:"
    echo ""
    echo "   .binaryTarget("
    echo "       name: \"libzcashlc\","
    echo "       url: \"${SLIPSTREAM_DOWNLOAD_URL}\","
    echo "       checksum: \"${SLIPSTREAM_CHECKSUM}\""
    echo "   ),"
fi
echo ""
echo "2. Commit the change:"
echo "   git add Package.swift"
echo "   git commit -m \"Prepare ffi release for sdk version ${VERSION}\""
echo ""
echo "3. Push:"
echo "   git push -u upstream release/ffi-${VERSION}"
echo ""
echo "4. Once release/ffi-${VERSION} has merged to the SDK release branch, create the signed tag:"
echo "   git tag -s ${VERSION} -m \"Release ${VERSION}\""
echo ""
echo "5. Publish the draft release:"
echo "   ${RELEASE_URL}"
echo ""

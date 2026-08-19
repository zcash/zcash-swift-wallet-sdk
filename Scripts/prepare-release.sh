#!/bin/bash
# Prepare FFI artifacts for an SDK release
# Usage: ./Scripts/prepare-release.sh [--force-overwrite-existing-release] [--zodl-slipstream] <version>
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
#   --zodl-slipstream                   Also build and upload the ZODL Slipstream
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
ZODL_SLIPSTREAM=false
while [[ "$1" == --* ]]; do
    case "$1" in
        --force-overwrite-existing-release)
            FORCE_OVERWRITE=true
            ;;
        --zodl-slipstream)
            ZODL_SLIPSTREAM=true
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--force-overwrite-existing-release] [--zodl-slipstream] <version>"
            exit 1
            ;;
    esac
    shift
done

if [[ -z "$1" ]]; then
    echo "Usage: $0 [--force-overwrite-existing-release] [--zodl-slipstream] <version>"
    echo "Example: $0 2.5.0"
    echo "         $0 --zodl-slipstream 2.9.0"
    exit 1
fi

VERSION="$1"
# Release onto the repo the workflow runs in (GITHUB_REPOSITORY in Actions), so forks can
# publish their own FFI releases — the hardcoded upstream 403s under a fork's CI token.
REPO="${GITHUB_REPOSITORY:-zcash/zcash-swift-wallet-sdk}"
PRODUCTS_DIR="BuildSupport/products"
ZIP_FILE="libzcashlc.xcframework.zip"
ZODL_SLIPSTREAM_PRODUCTS_DIR="BuildSupport/products-zodl-slipstream"
ZODL_SLIPSTREAM_ZIP_FILE="libzcashlc-zodl-slipstream.xcframework.zip"

# SemVer: a hyphen in the version (e.g. 2.6.0-alpha.1) marks a pre-release
PRERELEASE_FLAG=()
if [[ "$VERSION" == *-* ]]; then
    PRERELEASE_FLAG=(--prerelease)
fi

echo "=== Preparing release ${VERSION} ==="
if [[ ${#PRERELEASE_FLAG[@]} -gt 0 ]]; then
    echo "Pre-release suffix detected. The GitHub release will be marked as a pre-release."
fi
if [[ "$ZODL_SLIPSTREAM" == "true" ]]; then
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
# regardless of whether --zodl-slipstream was passed. This is what stands between an
# accidental Cargo.toml/feature regression and an AGPL-contaminated "clean" release.
echo ""
echo "=== Verifying clean artifact purity (no AGPL zodl-slipstream code) ==="
CLEAN_CONTAMINATED=false
while IFS= read -r slice; do
    # (a) Our FFI entry points. Their absence proves the engine is unreachable...
    SLICE_COUNT=$(nm -gU "$slice" 2>/dev/null | grep -c zcashlc_slipstream || true)
    if [[ "$SLICE_COUNT" -ne 0 ]]; then
        echo "FATAL: $slice exports $SLICE_COUNT zcashlc_slipstream symbol(s) — the clean artifact must ship zero."
        CLEAN_CONTAMINATED=true
    fi
    # (b) ...but NOT that no AGPL code was linked, which is the licensing question.
    # The engine crate leaves its own identifiers in the binary (type names, panic
    # locations, module paths); a clean build has zero, an engine build has dozens.
    # This is the check that actually says "no AGPL code here", so it stands even
    # if (a) is ever satisfied by a build that still links the engine.
    ENGINE_STRINGS=$(strings "$slice" 2>/dev/null | grep -ci 'zodl.slipstream' || true)
    if [[ "$ENGINE_STRINGS" -ne 0 ]]; then
        echo "FATAL: $slice contains $ENGINE_STRINGS ZODL Slipstream identifier(s) — AGPL code is linked into the clean artifact."
        CLEAN_CONTAMINATED=true
    fi
done < <(find "$PRODUCTS_DIR" -name "libzcashlc.a")
while IFS= read -r header; do
    if grep -q "ZCASHLC_ZODL_SLIPSTREAM" "$header"; then
        echo "FATAL: $header still references ZCASHLC_ZODL_SLIPSTREAM — unifdef should have stripped it."
        CLEAN_CONTAMINATED=true
    fi
done < <(find "$PRODUCTS_DIR/libzcashlc.xcframework" -name "zcashlc.h")
if [[ "$CLEAN_CONTAMINATED" == "true" ]]; then
    echo ""
    echo "Aborting: the default libzcashlc.xcframework artifact must be MIT-clean (zero AGPL code)."
    exit 1
fi
# The artifact must also SAY what it is: once unzipped the two xcframeworks are
# structurally identical, so a missing or disagreeing stamp would let a
# mislabelled artifact ship under the right filename.
CLEAN_STAMP=$(plutil -extract ZCASHLCVariant raw -o - "$PRODUCTS_DIR/libzcashlc.xcframework/Info.plist" 2>/dev/null || echo "<unstamped>")
if [[ "$CLEAN_STAMP" != "clean" ]]; then
    echo "FATAL: the default artifact is stamped '$CLEAN_STAMP', expected 'clean'."
    exit 1
fi
echo "Clean: no ZODL Slipstream entry points, no AGPL engine code, no ZCASHLC_ZODL_SLIPSTREAM in the header, stamped 'clean'."

# Create release archive
echo ""
echo "=== Creating release archive ==="
cd "$PRODUCTS_DIR"
rm -f "$ZIP_FILE"
zip -r "$ZIP_FILE" libzcashlc.xcframework
CHECKSUM=$(shasum -a 256 "$ZIP_FILE" | awk '{print $1}')
cd ../..

DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ZIP_FILE}"

ZODL_SLIPSTREAM_CHECKSUM=""
ZODL_SLIPSTREAM_DOWNLOAD_URL=""
if [[ "$ZODL_SLIPSTREAM" == "true" ]]; then
    # Build the superset xcframework (inner name stays libzcashlc.xcframework;
    # only the outer zip and the products-zodl-slipstream/ tree are variant-named).
    echo ""
    echo "=== Building ZODL Slipstream (AGPL) xcframework variant ==="
    cd BuildSupport
    make clean ZODL_SLIPSTREAM=1
    make xcframework ZODL_SLIPSTREAM=1
    cd ..

    # Inverse of the clean-artifact gate above: every slice must actually carry
    # the engine, or the ZODL Slipstream artifact would silently be the clean one.
    echo ""
    echo "=== Verifying ZODL Slipstream artifact completeness (AGPL engine present) ==="
    ZODL_SLIPSTREAM_INCOMPLETE=false
    while IFS= read -r slice; do
        SLICE_COUNT=$(nm -gU "$slice" 2>/dev/null | grep -c zcashlc_slipstream || true)
        if [[ "$SLICE_COUNT" -eq 0 ]]; then
            echo "FATAL: $slice exports zero zcashlc_slipstream symbols — the ZODL Slipstream artifact must carry the engine."
            ZODL_SLIPSTREAM_INCOMPLETE=true
        fi
    done < <(find "$ZODL_SLIPSTREAM_PRODUCTS_DIR" -name "libzcashlc.a")
    if [[ "$ZODL_SLIPSTREAM_INCOMPLETE" == "true" ]]; then
        echo ""
        echo "Aborting: the ZODL Slipstream artifact must carry the full zodl-slipstream engine in every slice."
        exit 1
    fi
    # It must also SAY what it is, or the two structurally-identical artifacts
    # could be swapped and still pass every other check.
    ZODL_SLIPSTREAM_STAMP=$(plutil -extract ZCASHLCVariant raw -o - "$ZODL_SLIPSTREAM_PRODUCTS_DIR/libzcashlc.xcframework/Info.plist" 2>/dev/null || echo "<unstamped>")
    if [[ "$ZODL_SLIPSTREAM_STAMP" != "zodl-slipstream" ]]; then
        echo "FATAL: the ZODL Slipstream artifact is stamped '$ZODL_SLIPSTREAM_STAMP', expected 'zodl-slipstream'."
        exit 1
    fi
    echo "ZODL Slipstream engine present in every staticlib slice, stamped 'zodl-slipstream'."

    echo ""
    echo "=== Creating ZODL Slipstream release archive ==="
    cd "$ZODL_SLIPSTREAM_PRODUCTS_DIR"
    rm -f "$ZODL_SLIPSTREAM_ZIP_FILE"
    zip -r "$ZODL_SLIPSTREAM_ZIP_FILE" libzcashlc.xcframework
    ZODL_SLIPSTREAM_CHECKSUM=$(shasum -a 256 "$ZODL_SLIPSTREAM_ZIP_FILE" | awk '{print $1}')
    cd ../..

    ZODL_SLIPSTREAM_DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ZODL_SLIPSTREAM_ZIP_FILE}"
fi

# Write release info for consumption by other scripts (release.sh, CI)
{
    echo "CHECKSUM=${CHECKSUM}"
    echo "DOWNLOAD_URL=${DOWNLOAD_URL}"
    echo "VERSION=${VERSION}"
    if [[ "$ZODL_SLIPSTREAM" == "true" ]]; then
        echo "ZODL_SLIPSTREAM_CHECKSUM=${ZODL_SLIPSTREAM_CHECKSUM}"
        echo "ZODL_SLIPSTREAM_DOWNLOAD_URL=${ZODL_SLIPSTREAM_DOWNLOAD_URL}"
    fi
} > "$PRODUCTS_DIR/release.env"

# Upload to GitHub as draft release
echo ""
echo "=== Uploading to GitHub (draft release) ==="

UPLOAD_FILES=("$PRODUCTS_DIR/$ZIP_FILE")
if [[ "$ZODL_SLIPSTREAM" == "true" ]]; then
    UPLOAD_FILES+=("$ZODL_SLIPSTREAM_PRODUCTS_DIR/$ZODL_SLIPSTREAM_ZIP_FILE")
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
if [[ "$ZODL_SLIPSTREAM" == "true" ]]; then
    echo ""
    echo "   ...and the ZODL Slipstream variant's binaryTarget with:"
    echo ""
    echo "   .binaryTarget("
    echo "       name: \"libzcashlc\","
    echo "       url: \"${ZODL_SLIPSTREAM_DOWNLOAD_URL}\","
    echo "       checksum: \"${ZODL_SLIPSTREAM_CHECKSUM}\""
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

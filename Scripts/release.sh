#!/bin/bash
# Full SDK release workflow
# Usage: ./Scripts/release.sh <remote> <version>
#
# This script performs the COMPLETE release process:
#   1. Pre-flight checks (clean dir, branch, GPG)
#   2. Builds the XCFramework and uploads a draft release
#      (via prepare-release.sh → upload-ffi-draft.sh).
#   3. Updates Package.swift and CHANGELOG (via update-package-swift.sh
#      and stamp-changelog.sh) and commits the result.
#   4. Pushes the release branch to the specified remote.
#   5. Tags HEAD with a signed tag and publishes the draft pre-release
#      (via finalize-release.sh, which prompts before tagging).
#
# Arguments:
#   <remote>   The git remote pointing to zcash/zcash-swift-wallet-sdk
#              (e.g., 'origin' or 'upstream')
#   <version>  The version to release (e.g., '2.6.0-alpha.2')
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
    echo "Example: $0 upstream 2.6.0-alpha.2"
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

# Check if tag already exists (locally or on the remote). Catching a
# remote-only tag here saves the maintainer from a 45-minute build that
# would only fail at finalize-release.sh's pre-flight.
if git rev-parse "$VERSION" >/dev/null 2>&1; then
    echo "Error: Tag $VERSION already exists locally."
    exit 1
fi
if [[ -n $(git ls-remote --tags "$UPSTREAM_REMOTE" "refs/tags/$VERSION" 2>/dev/null) ]]; then
    echo "Error: Tag $VERSION already exists on $UPSTREAM_REMOTE."
    exit 1
fi

# Verify GPG signing is configured
if ! git config --get user.signingkey >/dev/null 2>&1; then
    echo "Error: No GPG signing key configured."
    echo "Run: git config --global user.signingkey <your-key-id>"
    exit 1
fi

# === Step 1: Build and upload draft release ===
echo "=== Step 1/5: Build and upload draft release ==="
# --force-overwrite-existing-release lets a retry of a partially-failed
# release re-upload the artifact. upload-ffi-draft.sh's isDraft guard
# refuses to clobber a release that has already been published.
./Scripts/prepare-release.sh --force-overwrite-existing-release "$VERSION"

# Read release info written by prepare-release.sh
source "$PRODUCTS_DIR/release.env"

echo ""
echo "=== Step 2/5: Updating Package.swift and CHANGELOG ==="

if ! ./Scripts/update-package-swift.sh "$VERSION" "$CHECKSUM"; then
    git checkout Package.swift
    exit 1
fi

if ! ./Scripts/stamp-changelog.sh "$VERSION"; then
    # Defensive: stamp-changelog.sh checks its preconditions before
    # mutating CHANGELOG.md, but restore both files anyway so a retry
    # starts from a clean working tree.
    git checkout Package.swift CHANGELOG.md
    exit 1
fi

echo ""
echo "=== Step 3/5: Committing Package.swift and CHANGELOG ==="
git add Package.swift CHANGELOG.md
git commit -m "Prepare release ${VERSION}"

echo ""
echo "=== Step 4/5: Pushing release branch to ${UPSTREAM_REMOTE} ==="
RELEASE_BRANCH=$(git rev-parse --abbrev-ref HEAD)
RELEASE_SHA=$(git rev-parse HEAD)
git push "$UPSTREAM_REMOTE" "$RELEASE_BRANCH"

echo ""
echo "=== Step 5/5: Tagging and publishing ==="
# finalize-release.sh validates state, prompts for confirmation, creates the
# signed tag, pushes it, and publishes the draft release. If you abort at its
# prompt, re-run:
#   ./Scripts/finalize-release.sh <remote> <version> <release-sha>
./Scripts/finalize-release.sh "$UPSTREAM_REMOTE" "$VERSION" "$RELEASE_SHA"

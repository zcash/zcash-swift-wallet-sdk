#!/bin/bash
# Tag and publish a pre-release whose FFI artifacts and Package.swift /
# CHANGELOG update were already produced by the "Build FFI XCFramework"
# CI workflow.
#
# Run this AFTER approving the CI-opened `release/ffi-<version>` PR but
# BEFORE merging it: the release branch must still exist on the remote so
# its tip can be fetched and tagged. The tag must point to the commit CI
# produced — passed explicitly as <release-sha> so the script can verify
# HEAD matches and refuse to tag a merge or post-merge commit.
#
# It:
#   1. Verifies HEAD equals <release-sha> and that SHA is the tip of
#      <remote>/release/ffi-<version>, and that the draft release exists.
#   2. Creates a GPG-signed tag <version> on HEAD.
#   3. Pushes the tag to <remote>.
#   4. Publishes the draft pre-release.
#
# Usage: ./Scripts/finalize-release.sh <remote> <version> <release-sha>
#
# The release commit SHA is printed in the body of the CI-opened release
# PR (and in the workflow run's Summary).
#
# Prerequisites:
#   - gh CLI installed and authenticated
#   - GPG signing key configured for the repo
#   - The release/ffi-<version> PR approved (but not yet merged) and the
#     release commit checked out, e.g.:
#       git fetch <remote> <release-sha>
#       git checkout <release-sha>

set -e
cd "$(dirname "$0")/.."

REMOTE="$1"
VERSION="$2"
RELEASE_SHA="$3"
REPO="zcash/zcash-swift-wallet-sdk"

if [[ -z "$REMOTE" || -z "$VERSION" || -z "$RELEASE_SHA" ]]; then
    echo "Usage: $0 <remote> <version> <release-sha>" >&2
    echo "Example: $0 upstream 2.6.0-alpha.2 4838fa913fea1234..." >&2
    exit 1
fi

# RELEASE_SHA must be a full 40-character SHA (not a prefix). Abbreviated
# SHAs would still work for git commands but fail the equality checks below.
if [[ ! "$RELEASE_SHA" =~ ^[0-9a-f]{40}$ ]]; then
    echo "Error: <release-sha> must be a full 40-character commit SHA." >&2
    exit 1
fi

# 1. Version must look like a semver release (stable or pre-release).
#    The alpha/beta-only constraint applies to the CI release workflow
#    and is enforced there; this script also runs from release.sh for
#    stable releases, so we just shape-check here.
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
    echo "Error: VERSION '$VERSION' must be a semver release (e.g. 2.6.0 or 2.6.0-alpha.2)." >&2
    exit 1
fi

# 2. The git remote must exist.
if ! git remote get-url "$REMOTE" &>/dev/null; then
    echo "Error: git remote '$REMOTE' does not exist." >&2
    git remote -v >&2
    exit 1
fi

# 3. Working directory must be clean.
if [[ -n $(git status --porcelain) ]]; then
    echo "Error: working directory is not clean." >&2
    git status --short >&2
    exit 1
fi

# 4. A GPG signing key must be configured.
if ! git config --get user.signingkey >/dev/null 2>&1; then
    echo "Error: no GPG signing key configured (git config user.signingkey)." >&2
    exit 1
fi

# 5. Tag state — distinguish four cases:
#    a) Tag absent: normal path, will be created below.
#    b) Tag local-only (prior run created it but failed to push): error.
#    c) Tag local+remote and on HEAD: a prior run got past tag+push but
#       failed before publishing the draft. Skip re-creating; just publish.
#    d) Tag exists on a different commit: error, point at cleanup.
TAG_NEEDS_CREATE=true
if git rev-parse --verify "refs/tags/${VERSION}" >/dev/null 2>&1; then
    TAG_LOCAL_SHA=$(git rev-parse "refs/tags/${VERSION}^{commit}")
    HEAD_SHA=$(git rev-parse HEAD)
    TAG_REMOTE_SHA=$(git ls-remote --tags "$REMOTE" "refs/tags/${VERSION}" 2>/dev/null | awk '{print $1}')

    if [[ "$TAG_LOCAL_SHA" != "$HEAD_SHA" ]]; then
        echo "Error: existing tag ${VERSION} points to ${TAG_LOCAL_SHA}, but HEAD is ${HEAD_SHA}." >&2
        echo "Delete the misplaced tag before re-running:" >&2
        echo "  git tag -d ${VERSION}" >&2
        if [[ -n "$TAG_REMOTE_SHA" ]]; then
            echo "  git push ${REMOTE} :refs/tags/${VERSION}" >&2
        fi
        exit 1
    fi
    if [[ -z "$TAG_REMOTE_SHA" ]]; then
        echo "Error: tag ${VERSION} exists locally but was not pushed to ${REMOTE}." >&2
        echo "A previous finalize run likely created the tag and then failed to push." >&2
        echo "To recover, run:" >&2
        echo "  git push ${REMOTE} ${VERSION}" >&2
        echo "  gh release edit ${VERSION} --repo ${REPO} --draft=false" >&2
        exit 1
    fi
    # Tag is on HEAD and pushed — resume from the publish step.
    TAG_NEEDS_CREATE=false
    echo "Note: tag ${VERSION} is already present on ${REMOTE} at HEAD; resuming finalize."
fi

# 6. HEAD must equal the supplied release SHA, and that SHA must be the
#    tip of the remote release branch. The SHA is the authoritative
#    reference: the maintainer copies it from the CI-opened PR body, so
#    we're verifying the same commit CI built and verified.
HEAD_SHA=$(git rev-parse HEAD)
if [[ "$HEAD_SHA" != "$RELEASE_SHA" ]]; then
    echo "Error: HEAD is ${HEAD_SHA} but expected release SHA is ${RELEASE_SHA}." >&2
    echo "Check out the release commit:" >&2
    echo "  git fetch ${REMOTE} ${RELEASE_SHA}" >&2
    echo "  git checkout ${RELEASE_SHA}" >&2
    exit 1
fi
RELEASE_BRANCH="release/ffi-${VERSION}"
REMOTE_BRANCH_SHA=$(git ls-remote --heads "$REMOTE" "refs/heads/${RELEASE_BRANCH}" 2>/dev/null | awk '{print $1}')
if [[ -z "$REMOTE_BRANCH_SHA" ]]; then
    echo "Error: ${RELEASE_BRANCH} not found on ${REMOTE}." >&2
    echo "If the PR was already merged, the branch has been auto-deleted." >&2
    echo "Re-run the release workflow to recreate it." >&2
    exit 1
fi
if [[ "$REMOTE_BRANCH_SHA" != "$RELEASE_SHA" ]]; then
    echo "Error: ${REMOTE}/${RELEASE_BRANCH} tip (${REMOTE_BRANCH_SHA}) does not match the supplied release SHA (${RELEASE_SHA})." >&2
    echo "Either you have the wrong SHA, or a newer workflow run has superseded this release." >&2
    exit 1
fi

# Belt-and-braces: confirm HEAD's content matches what CI produced.
if ! grep -q "releases/download/${VERSION}/libzcashlc.xcframework.zip" Package.swift; then
    echo "Error: Package.swift does not reference the ${VERSION} FFI release." >&2
    exit 1
fi
if ! grep -qE "^# ${VERSION} " CHANGELOG.md; then
    echo "Error: CHANGELOG.md has no '# ${VERSION}' release header." >&2
    exit 1
fi

# 7. The draft release must exist and still be a draft.
if ! gh release view "$VERSION" --repo "$REPO" &>/dev/null; then
    echo "Error: GitHub release $VERSION not found. Run the release workflow first." >&2
    exit 1
fi
IS_DRAFT=$(gh release view "$VERSION" --repo "$REPO" --json isDraft --jq '.isDraft')
if [[ "$IS_DRAFT" != "true" ]]; then
    echo "Error: release $VERSION is already published." >&2
    exit 1
fi

# Confirmation (interactive sessions only).
echo ""
if [[ "$TAG_NEEDS_CREATE" == "true" ]]; then
    echo "About to tag and publish pre-release ${VERSION}:"
else
    echo "About to publish pre-release ${VERSION} (tag already exists at HEAD):"
fi
echo "  commit: $(git rev-parse --short HEAD)"
echo "  remote: ${REMOTE}"
echo ""
if [[ -t 0 ]]; then
    read -p "Proceed? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborted. Re-run this script to resume."
        exit 0
    fi
fi

if [[ "$TAG_NEEDS_CREATE" == "true" ]]; then
    echo ""
    echo "=== Creating signed tag ${VERSION} ==="
    git tag -s "$VERSION" -m "Release ${VERSION}"

    echo "=== Pushing tag to ${REMOTE} ==="
    git push "$REMOTE" "$VERSION"
fi

echo ""
echo "=== Publishing draft release ==="
gh release edit "$VERSION" --repo "$REPO" --draft=false

echo ""
echo "=========================================="
echo "  Pre-release ${VERSION} published!"
echo "  https://github.com/${REPO}/releases/tag/${VERSION}"
echo "=========================================="

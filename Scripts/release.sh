#!/usr/bin/env bash
#
# release.sh: tag and publish a release whose pull request has merged.
#
# This is the last step. Scripts/prepare-release.sh has already cut the
# branches, opened and readied the pull request, built the XCFramework, and
# pointed Package.swift at it; someone has merged that pull request into
# release/X.Y.Z. What is left is to sign the tag, push it, and take the GitHub
# release out of draft.
#
# Usage:
#   ./Scripts/release.sh [--dry-run] <remote> <version>
#
#   <remote>   git remote for the repository being released, e.g. upstream
#   <version>  the version to release, e.g. 2.7.1
#
# Prerequisites:
#   - run from release/X.Y.Z, with the pull request merged
#   - gh installed and authenticated
#   - a tag signing key configured
#
# Afterwards, merge release/X.Y.Z back into its maint/ branch and forward along
# the chain, as described in CONTRIBUTING.md.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
# shellcheck source=lib/release-lib.sh
. "Scripts/lib/release-lib.sh"

usage() {
    cat <<'EOF'
Usage: ./Scripts/release.sh [--dry-run] <remote> <version>

Tag and publish a release whose pull request has already merged into
release/X.Y.Z. Run it from that branch.

Options:
  --dry-run  print what would happen and change nothing
EOF
}

main() {
    local remote version release_branch declared_version declared_checksum
    local asset_checksum dir is_draft prerelease
    local local_sha remote_sha ahead behind

    while [ $# -gt 0 ]; do
        case "$1" in
            --dry-run) DRY_RUN=true; shift ;;
            -h|--help) usage; return 0 ;;
            --*)       usage >&2; die "unknown option '$1'" ;;
            *)         break ;;
        esac
    done

    if [ $# -lt 2 ]; then
        usage >&2
        die "release.sh needs a remote and a version."
    fi
    remote="$1"
    version="${2#v}"
    release_branch="release/${version}"
    # Every `gh release edit` below carries this, including the ones quoted in
    # the recovery instructions, so a hand-finished release ends up with the
    # same pre-release bit an automated one would have had.
    prerelease="$(prerelease_flag "$version")"

    step "Checking preconditions"
    require_clean_tree
    require_remote "$remote"
    # Fatal even under --dry-run: the verification below downloads the release
    # asset, so a dry run without a token cannot do the one thing it exists for.
    require_gh_auth

    if is_prerelease "$version"; then
        echo "  ${version} carries a pre-release suffix; it will be published as a pre-release"
    fi

    GH_REPO="$(repo_for_remote "$remote")"
    export GH_REPO
    echo "  repository: ${GH_REPO}"

    # The old script checked for `main`, which contradicts the branch model in
    # CONTRIBUTING.md: release/X.Y.Z is what gets tagged.
    if [ "$(git rev-parse --abbrev-ref HEAD)" != "$release_branch" ]; then
        die "release.sh must run from ${release_branch}." \
            "You are on $(git rev-parse --abbrev-ref HEAD)." \
            "Merge the release pull request, then check out ${release_branch}."
    fi

    echo "  fetching ${remote} ..."
    if ! git fetch --tags "$remote" >/dev/null 2>&1; then
        die "git fetch ${remote} failed." \
            "The already-tagged and up-to-date checks below would otherwise run" \
            "on stale refs, and would report agreement that does not exist."
    fi

    # A local tag with no remote counterpart is the signature of a previous run
    # that died between tagging and pushing, so say which case this is rather
    # than reporting the bare fact and leaving the operator to investigate.
    if git rev-parse -q --verify "refs/tags/${version}" >/dev/null; then
        if git ls-remote --tags --exit-code "$remote" "refs/tags/${version}" >/dev/null 2>&1; then
            die "${version} is already tagged on ${remote}; this release is out." \
                "If it still shows as a draft, publish it with:" \
                "  gh release edit ${version} --repo ${GH_REPO} --draft=false ${prerelease}"
        fi
        die "${version} is tagged locally but not on ${remote}." \
            "A previous run probably stopped between tagging and pushing." \
            "Resume with:" \
            "  git push ${remote} refs/tags/${version}" \
            "  gh release edit ${version} --repo ${GH_REPO} --draft=false ${prerelease}" \
            "Or discard the local tag and start over: git tag -d ${version}"
    fi

    # The tag is cut from this checkout, but what was reviewed and merged is
    # what sits on the remote. Requiring the two to be identical is what makes
    # the tag trustworthy -- and, once they are, there is nothing left to push
    # but the tag itself, so the release branch is never written to from here.
    if ! git rev-parse -q --verify "refs/remotes/${remote}/${release_branch}" >/dev/null; then
        die "${remote}/${release_branch} was not found." \
            "The release pull request merges into ${release_branch} on ${remote}." \
            "Either it was never pushed there, or '${remote}' is not the remote" \
            "the release was prepared against."
    fi
    local_sha="$(git rev-parse "refs/heads/${release_branch}")"
    remote_sha="$(git rev-parse "refs/remotes/${remote}/${release_branch}")"
    if [ "$local_sha" != "$remote_sha" ]; then
        ahead="$(git rev-list --count "${remote}/${release_branch}..${release_branch}")"
        behind="$(git rev-list --count "${release_branch}..${remote}/${release_branch}")"
        die "${release_branch} does not match ${remote}/${release_branch}." \
            "  local:  ${local_sha} (${ahead} commit(s) ${remote} does not have)" \
            "  remote: ${remote_sha} (${behind} commit(s) missing from this checkout)" \
            "Only what has merged on ${remote} may be tagged; a pushed tag cannot" \
            "be recalled. If this checkout is merely behind:" \
            "  git pull --ff-only ${remote} ${release_branch}" \
            "Commits that exist only here do not belong in a release. Land them" \
            "through a pull request first."
    fi
    echo "  ${release_branch} matches ${remote}/${release_branch} at $(git rev-parse --short "$local_sha")"

    # Advisory under --dry-run: nothing else in the dry run needs a signing key,
    # so reporting its absence beats refusing to show the rest of the plan.
    if ! git config --get user.signingkey >/dev/null 2>&1; then
        die_unless_dry_run "no tag signing key is configured." \
            "Run: git config --global user.signingkey <your-key-id>"
    fi

    step "Verifying Package.swift against the uploaded artifact"

    declared_version="$(package_swift_url_version Package.swift)"
    if [ "$declared_version" != "$version" ]; then
        die "Package.swift points at ${declared_version}, not ${version}." \
            "The release pull request may not have merged into this branch."
    fi

    if ! gh release view "$version" --repo "$GH_REPO" >/dev/null 2>&1; then
        die "there is no ${version} release on ${GH_REPO}." \
            "Run 'prepare-release.sh build' first."
    fi

    is_draft="$(gh release view "$version" --repo "$GH_REPO" --json isDraft --jq .isDraft)"
    if [ "$is_draft" != "true" ]; then
        die "release ${version} on ${GH_REPO} is already published."
    fi

    # SwiftPM validates this checksum when it fetches the binary target, so a
    # mismatch does not fail here -- it fails in every consumer's build, after
    # the release is public. Verify against the asset itself, not release.env.
    declared_checksum="$(package_swift_checksum Package.swift)"
    dir="$(mktemp -d)"
    if ! gh release download "$version" --repo "$GH_REPO" \
            --pattern "$ZIP_FILE" --dir "$dir" >/dev/null; then
        rm -rf "$dir"
        die "could not download ${ZIP_FILE} from the ${version} release." \
            "The release exists but may carry no asset. Check" \
            "https://github.com/${GH_REPO}/releases/tag/${version}, or re-run" \
            "'prepare-release.sh build --rebuild' to rebuild and re-upload it."
    fi
    asset_checksum="$(shasum -a 256 "${dir}/${ZIP_FILE}" | awk '{print $1}')"
    rm -rf "$dir"

    if [ "$declared_checksum" != "$asset_checksum" ]; then
        die "checksum mismatch between Package.swift and the uploaded asset." \
            "Package.swift declares: ${declared_checksum}" \
            "${ZIP_FILE} hashes to:  ${asset_checksum}" \
            "Re-run 'prepare-release.sh build --rebuild' to reconcile them."
    fi
    echo "  checksum matches: ${asset_checksum}"

    # From here on the actions are effectively permanent: a pushed tag and a
    # published release are not things to retract quietly. Each step therefore
    # reports what has already happened if the next one fails, rather than
    # letting `set -e` abort with only the underlying tool's message.
    step "Creating the signed tag ${version}"
    run git tag -s "$version" -m "Release ${version}"

    # Only the tag. ${release_branch} was verified identical to its remote
    # counterpart above, so pushing it could contribute nothing except, on a
    # checkout that had drifted, commits the pull request never carried.
    step "Pushing the tag ${version} to ${remote}"
    if ! run git push "$remote" "refs/tags/${version}"; then
        cat >&2 <<EOF

error: the push failed. The signed tag ${version} EXISTS LOCALLY but may not
have reached ${remote}, and the release is still a draft.

Check with:
  git ls-remote --tags ${remote} refs/tags/${version}

Then either retry:
  git push ${remote} refs/tags/${version}
  gh release edit ${version} --repo ${GH_REPO} --draft=false ${prerelease}

or discard the local tag and start over:
  git tag -d ${version}
EOF
        exit 1
    fi

    step "Publishing the release"
    if ! run gh release edit "$version" --repo "$GH_REPO" --draft=false "$prerelease"; then
        cat >&2 <<EOF

error: the release could not be published.

The signed tag ${version} IS already on ${remote} and is public -- do not
delete it. Only the draft release remains. Publish it by hand with:

  gh release edit ${version} --repo ${GH_REPO} --draft=false ${prerelease}

or from https://github.com/${GH_REPO}/releases/tag/${version}
EOF
        exit 1
    fi

    # Under --dry-run none of the three steps above ran, so the summary must
    # not claim the release is out.
    if [ "$DRY_RUN" = "true" ]; then
        cat <<EOF

Dry run: nothing was tagged, pushed or published. ${version} is not released.

A real run would sign and push the tag ${version}, publish
https://github.com/${GH_REPO}/releases/tag/${version}, and then need
${release_branch} merged back into its maint/ branch.
EOF
    else
        cat <<EOF

Release ${version} is out.

  https://github.com/${GH_REPO}/releases/tag/${version}

Now merge ${release_branch} back into its maint/ branch, then forward along the
chain to newer maint/ branches and finally to main, as described in
CONTRIBUTING.md. Skipping a forward merge is how a fix silently regresses.
EOF
    fi
}

main "$@"

#!/usr/bin/env bash
#
# prepare-release.sh: cut a release for review, then build and attach its
# artifacts.
#
# A release happens in two phases, with a human reading the pull request in
# between.
#
#   start      Cut release/X.Y.Z from the previous release tag and
#              candidate/X.Y.Z from the revision being released, promote the
#              CHANGELOG, and open a DRAFT pull request from candidate into
#              release. That PR's diff is exactly what users receive relative
#              to the previous release, with none of the intervening history.
#
#   build      After that PR has been reviewed: bump the version everywhere it
#              is recorded, build and upload the XCFramework, point
#              Package.swift at it, extend candidate/X.Y.Z with the result, and
#              mark the PR ready for review.
#
#   artifacts  Build, zip and upload the XCFramework alone. Touches no git or
#              pull-request state; this is what .github/workflows/build-ffi.yml
#              runs, and what `build --artifacts local` uses underneath.
#
# Once the pull request has merged, Scripts/release.sh tags and publishes.
#
# Run `./Scripts/prepare-release.sh <subcommand> --help` for the options of
# each phase.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
# shellcheck source=lib/release-lib.sh
. "Scripts/lib/release-lib.sh"

# Ensure cargo/rustup are on PATH (needed when invoked from CI or Xcode).
if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck source=/dev/null
    . "$HOME/.cargo/env"
fi

usage() {
    cat <<'EOF'
Usage: ./Scripts/prepare-release.sh <subcommand> [options]

Subcommands:
  start      Cut the release branches and open the draft pull request.
  build      Bump versions, build and upload the artifacts, ready the PR.
  artifacts  Build and upload the XCFramework alone; no git, no PR.

Run `./Scripts/prepare-release.sh <subcommand> --help` for details.
EOF
}

usage_start() {
    cat <<'EOF'
Usage: ./Scripts/prepare-release.sh start --issue <N> [options] <remote> <version> [<revision>]

Phase one of a release. Creates release/X.Y.Z from the previous release tag and
pushes it; creates candidate/X.Y.Z from the revision being released; promotes
the CHANGELOG's Unreleased section; and opens a DRAFT pull request from the
candidate branch into the release branch.

Basing the release branch on the previous release tag is what makes the pull
request worth reviewing: its diff is exactly what users receive relative to the
last release, rather than the intervening development history.

It deliberately does not build anything. The binary target's URL and checksum
cannot exist until the XCFramework has been built and uploaded, which is what
`prepare-release.sh build` does after this PR has been reviewed.

Arguments:
  <remote>    git remote for the repository being released, e.g. upstream
  <version>   version being released, e.g. 2.7.1
  <revision>  commit or branch holding the changes to release
              (default: current HEAD, which should be a maint/ branch)

Options:
  --issue <N>       release tracking issue; the PR body gets `Closes #N`.
                    Required: every pull request must reference an issue.
  --previous <tag>  base the release branch on this tag rather than the
                    detected one. Use when the newest tag reachable from
                    <revision> is not the release you are following.
  --dry-run         print what would happen and change nothing.
EOF
}

usage_build() {
    cat <<'EOF'
Usage: ./Scripts/prepare-release.sh build [options] <remote> <version>

Phase two of a release, run after the draft pull request from
`prepare-release.sh start` has been reviewed. In order:

  A. Bump the recorded version in Cargo.toml, Cargo.lock and
     BuildSupport/platform-Info.plist; commit and push.
  B. Build the XCFramework and upload it as a draft GitHub release.
  C. Point Package.swift at that release; commit and push.
  D. Comment on the pull request and mark it ready for review.

Every step checks whether it has already run and skips if so, so re-running
after a failure resumes rather than starting over. The five-architecture build
is slow enough that this matters.

Options:
  --artifacts local  build the XCFramework on this machine (default)
  --artifacts ci     dispatch .github/workflows/build-ffi.yml on the candidate
                     branch, wait for it, and take the checksum from the asset
                     it uploads. Step A is pushed first, so CI builds the
                     bumped version. The runner performs the same verification
                     before it uploads; --skip-verify here does not reach it.
  --rebuild          rebuild and re-upload even if the draft release already
                     carries the XCFramework
  --skip-verify      do not build and test the SDK against the new XCFramework
                     before uploading it (local builds only)
  --dry-run          print what would happen and change nothing
EOF
}

usage_artifacts() {
    cat <<'EOF'
Usage: ./Scripts/prepare-release.sh artifacts [options] <version>

Build the XCFramework for all five Apple architectures, zip it, and upload it
to GitHub as a DRAFT release. Writes BuildSupport/products/release.env with the
checksum and download URL. A version carrying a pre-release suffix, such as
2.8.0-rc.1, is marked as a pre-release on GitHub.

This touches no git state and no pull request, which is what lets
.github/workflows/build-ffi.yml run it with only `contents: write`. It is also
what `prepare-release.sh build --artifacts local` uses underneath; you rarely
need to run it directly.

It refuses unless Cargo.toml already declares <version>. A dispatched CI build
takes its version from the workflow input but its sources from the branch; were
the two allowed to disagree, the upload would carry the right name and the
wrong library.

Before uploading, it points Package.swift at the framework it just built via
LocalPackages, builds the Swift package, and runs the OfflineTests suite. A
mismatch across the FFI boundary compiles on both sides and fails only at link
or run time, so this is the last point at which one can be caught cheaply.

Options:
  --force-overwrite-existing-release  replace the assets of an existing DRAFT
                                      release. A published release is refused:
                                      Package.swift pins its asset's checksum,
                                      so replacing it breaks every consumer
                                      that has already resolved the version.
  --skip-verify                       do not build and test the SDK against the
                                      new XCFramework before uploading it
  --dry-run                           print what would happen and change nothing
EOF
}

# --------------------------------------------------------------------- start

# The body of the draft pull request. It has to carry enough context that a
# reviewer arriving cold knows both what they are looking at and that it is
# deliberately incomplete.
start_pr_body() {
    local version="$1" prev_tag="$2" issue="$3"
    cat <<EOF
Closes #${issue}

Release \`${version}\`, following \`${prev_tag}\`.

The base of this pull request is \`release/${version}\`, which starts out
identical to \`${prev_tag}\`. Its diff is therefore exactly what users receive
relative to the last release, rather than the intervening development history.

## This is a draft: the artifact phase has not run

Reviewing this diff is the first of two phases. Once it looks right, a
maintainer runs

    ./Scripts/prepare-release.sh build <remote> ${version}

which extends this branch with:

- the version bump, across \`Cargo.toml\`, \`Cargo.lock\` and
  \`BuildSupport/platform-Info.plist\`;
- the \`libzcashlc\` XCFramework, built for all five Apple architectures and
  uploaded as a draft GitHub release;
- \`Package.swift\`, rewritten so its binary target points at that release and
  carries its checksum.

When that has happened a comment will be added here and this pull request will
be marked ready for review. **Do not merge before then.** Merging early tags a
release whose \`Package.swift\` still points at the previous version's
XCFramework.

After merging, \`./Scripts/release.sh <remote> ${version}\` verifies the
checksum against the uploaded asset, signs and pushes the tag, and publishes
the release.
EOF
}

cmd_start() {
    local previous="" issue="" remote version revision rev_sha prev_tag
    local release_branch candidate_branch b today pr_body_file

    local -a positional=()

    while [ $# -gt 0 ]; do
        case "$1" in
            --issue)    issue="${2:?--issue needs an issue number}"; shift 2 ;;
            --previous) previous="${2:?--previous needs a tag}"; shift 2 ;;
            --dry-run)  DRY_RUN=true; shift ;;
            -h|--help)  usage_start; return 0 ;;
            --*)        usage_start >&2; die "unknown option '$1'" ;;
            *)          positional+=("$1"); shift ;;
        esac
    done
    # Options may appear anywhere, including after the positionals.
    set -- ${positional[@]+"${positional[@]}"}

    if [ $# -lt 2 ]; then
        usage_start >&2
        die "start needs a remote and a version."
    fi
    remote="$1"
    version="${2#v}"
    revision="${3:-HEAD}"

    if [ -z "$issue" ]; then
        die "--issue <N> is required." \
            "Every pull request must reference an issue (see CONTRIBUTING.md)." \
            "Open a release tracking issue first, then pass its number."
    fi

    step "Checking preconditions"
    require_clean_tree
    require_remote "$remote"
    # Advisory under --dry-run: this is the one subcommand whose dry run reaches
    # GitHub nowhere, so an unauthenticated rehearsal can still show the whole
    # plan. `build` and `artifacts` read release and pull-request state even
    # under --dry-run, and keep the check fatal.
    require_gh_auth die_unless_dry_run

    GH_REPO="$(repo_for_remote "$remote")"
    export GH_REPO
    echo "  repository: ${GH_REPO}"

    echo "  fetching ${remote} ..."
    if ! git fetch --tags "$remote" >/dev/null 2>&1; then
        die "git fetch ${remote} failed." \
            "Every check below compares against ${remote}; running them on" \
            "stale refs would report agreement that does not exist."
    fi

    rev_sha="$(git rev-parse --verify "${revision}^{commit}")"
    echo "  releasing the content of ${revision} ($(git rev-parse --short "$rev_sha"))"

    if git rev-parse -q --verify "refs/tags/${version}" >/dev/null; then
        die "${version} is already tagged; pick a new version."
    fi

    step "Determining the release base"
    if [ -n "$previous" ]; then
        prev_tag="$previous"
        if ! git rev-parse -q --verify "refs/tags/${prev_tag}" >/dev/null; then
            die "no such tag '${prev_tag}'."
        fi
        echo "  using --previous ${prev_tag}"
    else
        # Only tags reachable from the revision are candidates: a tag on a
        # newer line is not something this release can succeed. The glob keeps
        # non-version tags (e.g. rustwelding-*) out of the running.
        prev_tag="$(git tag --list --merged "$rev_sha" '[0-9]*' | version_sort | tail -1)"
        if [ -z "$prev_tag" ]; then
            die "no release tags are reachable from ${revision}." \
                "Pass --previous <tag> to say which release this follows."
        fi
        echo "  newest release reachable from ${revision}: ${prev_tag}"
    fi

    if version_le "$version" "$prev_tag"; then
        die "${version} does not come after ${prev_tag}."
    fi

    release_branch="release/${version}"
    candidate_branch="candidate/${version}"
    for b in "$release_branch" "$candidate_branch"; do
        if git rev-parse -q --verify "refs/heads/${b}" >/dev/null; then
            die "branch ${b} already exists locally." \
                "This usually means a previous 'start' for ${version} got partway through." \
                "Delete ${release_branch} and ${candidate_branch} locally and re-run, or, if" \
                "both are already pushed to ${remote} and only the pull request is missing," \
                "open it by hand with gh pr create (see start_pr_body for the body text)."
        fi
    done

    echo
    echo "  ${release_branch}    <- ${prev_tag}  (PR base, pushed to ${remote})"
    echo "  ${candidate_branch}  <- ${revision}  (release prep goes here)"

    step "Creating ${release_branch} from ${prev_tag}"
    run git branch "$release_branch" "refs/tags/${prev_tag}"
    run git push "$remote" "${release_branch}:${release_branch}"

    step "Creating ${candidate_branch} from ${revision}"
    run git switch -c "$candidate_branch" "$rev_sha"

    step "Promoting the CHANGELOG"
    if ! changelog_unreleased_nonempty CHANGELOG.md; then
        die "the Unreleased section of CHANGELOG.md is empty." \
            "Every user-visible change needs an entry before release."
    fi
    today="$(date +%Y-%m-%d)"
    if [ "$DRY_RUN" = "true" ]; then
        echo "  would insert '# ${version} - ${today}' below '# Unreleased'"
    else
        if ! promote_changelog CHANGELOG.md "$version" "$today"; then
            die "CHANGELOG.md has no '# Unreleased' heading to promote."
        fi
        echo "  # ${version} - ${today}"
    fi

    step "Committing"
    run git add CHANGELOG.md
    run git commit -m "Prepare SDK release ${version}"

    step "Pushing ${candidate_branch}"
    run git push -u "$remote" "$candidate_branch"

    step "Opening the draft pull request"
    if [ "$DRY_RUN" = "true" ]; then
        echo "  would open a draft PR ${candidate_branch} -> ${release_branch} on ${GH_REPO}"
        echo "  body would close issue #${issue}"
    elif ! start_pr_body "$version" "$prev_tag" "$issue" |
        gh pr create --repo "$GH_REPO" --draft \
            --base "$release_branch" --head "$candidate_branch" \
            --title "Release zcash-swift-wallet-sdk ${version}" \
            --body-file -; then
        # gh pr create is the last of five steps; both branches are already on
        # the remote by this point. Detect the failure explicitly (rather than
        # letting set -e abort with only gh's own output) so the operator
        # knows not to re-push, and can open the PR by hand.
        pr_body_file="$(mktemp)"
        start_pr_body "$version" "$prev_tag" "$issue" > "$pr_body_file"
        die "gh pr create failed." \
            "${release_branch} and ${candidate_branch} are already pushed to ${remote} --" \
            "they do not need re-pushing. Open the pull request by hand:" \
            "" \
            "  gh pr create --repo ${GH_REPO} --draft \\" \
            "      --base ${release_branch} --head ${candidate_branch} \\" \
            "      --title \"Release zcash-swift-wallet-sdk ${version}\" \\" \
            "      --body-file ${pr_body_file}" \
            "" \
            "(the PR body is already written out at ${pr_body_file})"
    fi

    if [ "$DRY_RUN" = "true" ]; then
        cat <<EOF

Dry run: nothing was changed. ${release_branch} and ${candidate_branch} were
not created, nothing was pushed to ${remote}, and no pull request was opened.
The working tree is untouched -- ${candidate_branch} is not checked out.

A real run would leave a draft pull request open whose diff is exactly what
users get over ${prev_tag}. Once that PR looked right, the next step would be

  ./Scripts/prepare-release.sh build ${remote} ${version}

which bumps the recorded version, builds and uploads the XCFramework, points
Package.swift at it, and marks the PR ready for review.
EOF
    else
        cat <<EOF

Done. ${release_branch} and ${candidate_branch} are on ${remote}, and the draft
pull request is open. ${candidate_branch} is checked out here.

Review the PR diff: it is exactly what users get over ${prev_tag}. Then run

  ./Scripts/prepare-release.sh build ${remote} ${version}

which bumps the recorded version, builds and uploads the XCFramework, points
Package.swift at it, and marks the PR ready for review.
EOF
    fi
}

# ----------------------------------------------------------------- artifacts

# Build the Swift package and run the offline tests against the XCFramework
# that was just built, by pointing Package.swift at it through LocalPackages.
#
# This is the first time anything links the new framework. A mismatch across
# the FFI boundary -- a changed signature, a dropped symbol -- compiles on both
# sides and surfaces only at link or run time, so without this the first
# consumer to find out is a user who has already upgraded.
verify_against_local_ffi() {
    local had_local_packages=false

    if [ -d LocalPackages ]; then
        had_local_packages=true
        echo "  LocalPackages/ already exists and will be replaced"
    fi

    step "Verifying the SDK against the freshly built XCFramework"
    run make configure-local-ffi
    run make build
    run make test-offline

    # Leave the tree as we found it. LocalPackages/ is gitignored, but its mere
    # presence switches Package.swift from the released binary target to the
    # local one, so leaving it behind would silently change what the operator's
    # next build links against.
    if [ "$had_local_packages" = "false" ]; then
        run rm -rf LocalPackages
    else
        echo "  leaving LocalPackages/ in place; it predates this run"
        echo "  re-run ./Scripts/init-local-ffi.sh if you need it rebuilt"
    fi
}

# Build, archive and upload. Returns with $PRODUCTS_DIR/release.env written.
# Callers set GH_REPO; it falls back to the repository the workflow runs in
# (GITHUB_REPOSITORY under Actions) and then to the canonical repository, so a
# CI dispatch needs no argument and a fork publishes its own releases instead of
# failing with 403 against upstream.
produce_artifacts() {
    local version="$1" force="$2" verify="$3"
    local manifest_version checksum download_url exists

    : "${GH_REPO:=${GITHUB_REPOSITORY:-$DEFAULT_REPO}}"
    export GH_REPO

    require_gh_auth

    manifest_version="$(cargo_package_version Cargo.toml)"
    if [ "$manifest_version" != "$version" ]; then
        die "Cargo.toml declares version ${manifest_version}, not ${version}." \
            "Run 'prepare-release.sh build' to bump it, or dispatch this build" \
            "from a branch where the bump has already landed."
    fi

    if is_prerelease "$version"; then
        echo "  ${version} carries a pre-release suffix; the release will be marked as a pre-release"
    fi

    # Check before the ten-minute build, not after: nothing below depends on
    # the build or the checksum, so a doomed run should fail in a second, the
    # same reasoning that puts the version guard above ahead of the build.
    exists=false
    if gh release view "$version" --repo "$GH_REPO" >/dev/null 2>&1; then
        if [ "$force" != "true" ]; then
            die "release ${version} already exists." \
                "Use --force-overwrite-existing-release to replace its assets."
        fi
        # Only a draft may be overwritten. Package.swift pins the checksum of
        # whatever asset a published release carries, and SwiftPM checks it at
        # fetch time, so replacing the bytes behind that URL breaks the build of
        # everyone who has already resolved ${version} -- and keeps breaking it,
        # because a published tag is immutable. The remedy is a new version.
        if [ "$(gh release view "$version" --repo "$GH_REPO" \
                --json isDraft --jq .isDraft)" != "true" ]; then
            die "release ${version} is published; its assets will not be replaced." \
                "Package.swift pins the checksum of the asset attached to it, and" \
                "SwiftPM verifies that checksum on every fetch. Replacing the asset" \
                "would break the build of every consumer that has resolved ${version}." \
                "Release a new version instead."
        fi
        echo "  draft release ${version} exists; replacing its assets"
        exists=true
    fi

    step "Building the XCFramework for ${version} (this takes a while)"
    run make clean-ffi
    run make ffi-all

    # Between the build and the upload, deliberately: this is the last point at
    # which a broken FFI boundary can be caught before the artifact is public.
    if [ "$verify" = "true" ]; then
        verify_against_local_ffi
    else
        echo "  skipping the build-and-test verification (--skip-verify)"
    fi

    step "Creating the release archive"
    if [ "$DRY_RUN" = "true" ]; then
        echo "  would zip ${PRODUCTS_DIR}/${ZIP_FILE} and checksum it"
        echo "  would upload it to ${GH_REPO} as a draft release"
        return 0
    fi

    ( cd "$PRODUCTS_DIR" && rm -f "$ZIP_FILE" && zip -qr "$ZIP_FILE" libzcashlc.xcframework )
    checksum="$(shasum -a 256 "${PRODUCTS_DIR}/${ZIP_FILE}" | awk '{print $1}')"
    download_url="https://github.com/${GH_REPO}/releases/download/${version}/${ZIP_FILE}"
    echo "  ${ZIP_FILE}: ${checksum}"

    step "Uploading to ${GH_REPO} as a draft release"
    if [ "$exists" = "true" ]; then
        gh release upload "$version" "${PRODUCTS_DIR}/${ZIP_FILE}" \
            --repo "$GH_REPO" --clobber
        # `gh release upload` replaces assets, never release properties, so the
        # pre-release bit has to be set on its own. A draft cut before this
        # handling existed carries whatever it was created with.
        gh release edit "$version" --repo "$GH_REPO" "$(prerelease_flag "$version")"
    else
        gh release create "$version" "${PRODUCTS_DIR}/${ZIP_FILE}" \
            --repo "$GH_REPO" --title "$version" \
            --notes "Zcash Light Client SDK ${version}" --draft \
            "$(prerelease_flag "$version")"
    fi

    # Only write this once the upload has actually succeeded: everything it
    # records was already known beforehand, so this is a pure reordering, but
    # a caller trusting this file must never see a DOWNLOAD_URL that 404s.
    cat > "${PRODUCTS_DIR}/release.env" <<EOF
CHECKSUM=${checksum}
DOWNLOAD_URL=${download_url}
VERSION=${version}
EOF

    echo "  draft release: https://github.com/${GH_REPO}/releases/tag/${version}"
}

cmd_artifacts() {
    local force=false verify=true version

    local -a positional=()

    while [ $# -gt 0 ]; do
        case "$1" in
            --force-overwrite-existing-release) force=true; shift ;;
            --skip-verify) verify=false; shift ;;
            --dry-run) DRY_RUN=true; shift ;;
            -h|--help) usage_artifacts; return 0 ;;
            --*)       usage_artifacts >&2; die "unknown option '$1'" ;;
            *)         positional+=("$1"); shift ;;
        esac
    done
    # Options may appear anywhere, including after the positionals.
    set -- ${positional[@]+"${positional[@]}"}

    if [ $# -lt 1 ]; then
        usage_artifacts >&2
        die "artifacts needs a version."
    fi
    version="${1#v}"

    produce_artifacts "$version" "$force" "$verify"
}

# --------------------------------------------------------------------- build

# Marks this script's own PR comment so a re-run recognises it.
READY_MARKER="<!-- prepare-release: ready -->"

# True when every recorded version already reads <version>. The working tree is
# known clean by preflight, so reading it is the same as reading HEAD's tree.
versions_already_bumped() {
    local version="$1" short
    short="$(strip_prerelease "$version")"
    [ "$(cargo_package_version Cargo.toml)" = "$version" ] &&
        [ "$(cargo_lock_package_version Cargo.lock libzcashlc)" = "$version" ] &&
        [ "$(plist_value "$PLIST" CFBundleShortVersionString)" = "$short" ] &&
        [ "$(plist_value "$PLIST" CFBundleVersion)" = "$short" ]
}

package_swift_current() {
    [ "$(package_swift_url_version Package.swift)" = "$1" ] &&
        [ "$(package_swift_checksum Package.swift)" = "$2" ]
}

release_has_asset() {
    gh release view "$1" --repo "$GH_REPO" --json assets --jq '.assets[].name' \
        2>/dev/null | grep -qx "$ZIP_FILE"
}

# The checksum of the asset actually attached to the release. Deliberately not
# read from release.env: that lives under the gitignored BuildSupport/products/
# and is absent in a fresh clone, so trusting it would make a resumed run
# depend on which machine started it.
checksum_of_release_asset() {
    local version="$1" dir sum
    dir="$(mktemp -d)"
    if ! gh release download "$version" --repo "$GH_REPO" \
        --pattern "$ZIP_FILE" --dir "$dir" >/dev/null; then
        rm -rf "$dir"
        return 1
    fi
    sum="$(shasum -a 256 "${dir}/${ZIP_FILE}" | awk '{print $1}')"
    rm -rf "$dir"
    printf '%s\n' "$sum"
}

latest_ffi_run_id() {
    gh run list --repo "$GH_REPO" --workflow=build-ffi.yml --branch "$1" \
        --limit 1 --json databaseId --jq '.[0].databaseId' 2>/dev/null
}

# Dispatch the workflow and block until it finishes. Everything informational
# goes to stderr so stdout carries only the checksum. $rebuild forwards as the
# workflow's `force` input, so CI's produce_artifacts call overwrites an
# existing draft release the same way the local --rebuild path does.
build_artifacts_in_ci() {
    local version="$1" branch="$2" rebuild="$3" before after run_id waited
    before="$(latest_ffi_run_id "$branch")"
    echo "  dispatching build-ffi.yml on ${branch}" >&2
    if [ "$rebuild" = "true" ]; then
        gh workflow run build-ffi.yml --repo "$GH_REPO" --ref "$branch" \
            -f version="$version" -f force=true >&2
    else
        gh workflow run build-ffi.yml --repo "$GH_REPO" --ref "$branch" \
            -f version="$version" >&2
    fi

    # `gh workflow run` does not report the run it created, so wait for a run
    # id that differs from the one that was newest beforehand.
    waited=0
    while :; do
        after="$(latest_ffi_run_id "$branch")"
        if [ -n "$after" ] && [ "$after" != "${before}" ]; then
            run_id="$after"
            break
        fi
        if [ "$waited" -ge 180 ]; then
            echo "error: the dispatched run did not appear within 180s." >&2
            return 1
        fi
        sleep 5
        waited=$((waited + 5))
    done

    echo "  watching run ${run_id}" >&2
    gh run watch "$run_id" --repo "$GH_REPO" --exit-status >&2
    checksum_of_release_asset "$version"
}

pr_has_ready_comment() {
    gh pr view "$1" --repo "$GH_REPO" --json comments --jq '.comments[].body' \
        2>/dev/null | grep -qF "$READY_MARKER"
}

build_ready_comment() {
    local version="$1" checksum="$2"
    cat <<EOF
${READY_MARKER}
The artifact phase has completed; this branch is ready to be merged and tagged.

- Draft release: https://github.com/${GH_REPO}/releases/tag/${version}
- \`libzcashlc.xcframework.zip\` checksum: \`${checksum}\`

\`Package.swift\` now points at that release. After merging, run

    ./Scripts/release.sh <remote> ${version}

from \`release/${version}\`. It re-verifies the checksum against the uploaded
asset, signs and pushes the tag, and publishes the release.
EOF
}

# Push only when the branch is ahead, so a resumed run is quiet rather than
# noisily re-pushing.
push_if_ahead() {
    local remote="$1" branch="$2" ahead
    ahead="$(git rev-list --count "${remote}/${branch}..${branch}" 2>/dev/null || echo unknown)"
    if [ "$ahead" = "0" ]; then
        echo "  ${branch} is already up to date on ${remote}"
    else
        run git push "$remote" "$branch"
    fi
}

cmd_build() {
    local artifacts="local" rebuild=false verify=true remote version
    local candidate_branch pr_number checksum is_draft behind current_branch

    local -a positional=()

    while [ $# -gt 0 ]; do
        case "$1" in
            --artifacts) artifacts="${2:?--artifacts needs local or ci}"; shift 2 ;;
            --rebuild)   rebuild=true; shift ;;
            --skip-verify) verify=false; shift ;;
            --dry-run)   DRY_RUN=true; shift ;;
            -h|--help)   usage_build; return 0 ;;
            --*)         usage_build >&2; die "unknown option '$1'" ;;
            *)           positional+=("$1"); shift ;;
        esac
    done
    # Options may appear anywhere, including after the positionals.
    set -- ${positional[@]+"${positional[@]}"}

    case "$artifacts" in
        local|ci) ;;
        *) die "--artifacts must be 'local' or 'ci', not '${artifacts}'." ;;
    esac

    if [ $# -lt 2 ]; then
        usage_build >&2
        die "build needs a remote and a version."
    fi
    remote="$1"
    version="${2#v}"
    candidate_branch="candidate/${version}"

    step "Checking preconditions"
    require_clean_tree
    require_remote "$remote"
    require_gh_auth

    GH_REPO="$(repo_for_remote "$remote")"
    export GH_REPO
    echo "  repository: ${GH_REPO}"

    echo "  fetching ${remote} ..."
    # A failed fetch that leaves a stale remote-tracking ref resolvable would
    # let the behind-check below pass on out-of-date information -- the very
    # thing it exists to prevent.
    if ! git fetch "$remote" >/dev/null 2>&1; then
        die "git fetch ${remote} failed." \
            "The behind-check below would otherwise run on stale refs."
    fi

    if ! git rev-parse -q --verify "refs/heads/${candidate_branch}" >/dev/null; then
        die "branch ${candidate_branch} does not exist locally." \
            "Run 'prepare-release.sh start' first, or check out the branch."
    fi
    current_branch="$(git rev-parse --abbrev-ref HEAD)"
    if [ "$current_branch" != "$candidate_branch" ]; then
        run git switch "$candidate_branch"
    fi

    # Under --dry-run, `run` above only printed what it would do -- it did not
    # switch. Everything below still reads the live working tree unconditionally
    # (versions_already_bumped, package_swift_current), so without this note a
    # dry run silently reports Step A's and Step C's state for whatever branch
    # happened to be checked out, not for ${candidate_branch}.
    if [ "$DRY_RUN" = "true" ] && [ "$current_branch" != "$candidate_branch" ]; then
        cat <<EOF

*** DRY RUN NOTE: still on ${current_branch} ***
--dry-run does not switch branches, so this checkout was not moved to
${candidate_branch}. The Step A and Step C findings below describe the state
of ${current_branch}, not ${candidate_branch}. A real run would switch first
and its findings would reflect ${candidate_branch} truthfully.
EOF
    fi

    # Review comments land as pushes to this branch. Building from a checkout
    # that is behind would ship an XCFramework compiled from sources nobody
    # reviewed, under a Package.swift that claims otherwise. A ref that fails
    # to resolve must not be treated as "definitely not behind" -- that would
    # silently defeat the check it is guarding.
    if ! git rev-parse -q --verify "refs/remotes/${remote}/${candidate_branch}" >/dev/null; then
        die "${remote}/${candidate_branch} was not found." \
            "Either ${candidate_branch} has not been pushed to ${remote} yet, or '${remote}'" \
            "differs from the remote 'start' pushed it to. Try: git fetch ${remote}"
    fi
    behind="$(git rev-list --count "${candidate_branch}..${remote}/${candidate_branch}")"
    if [ "$behind" != "0" ]; then
        die "${candidate_branch} is ${behind} commit(s) behind ${remote}/${candidate_branch}." \
            "Pull them first: git pull --ff-only ${remote} ${candidate_branch}"
    fi

    pr_number="$(gh pr list --repo "$GH_REPO" --head "$candidate_branch" \
        --state open --json number --jq '.[0].number')"
    if [ -z "$pr_number" ]; then
        die "no open pull request has head ${candidate_branch} on ${GH_REPO}." \
            "Phase one opens it; run 'prepare-release.sh start' first."
    fi
    echo "  pull request #${pr_number}"

    # --- A -----------------------------------------------------------------
    step "A. Recording version ${version}"
    if versions_already_bumped "$version"; then
        echo "  Cargo.toml, Cargo.lock and ${PLIST} already read ${version}"
    else
        if [ "$DRY_RUN" = "true" ]; then
            echo "  would set the version in Cargo.toml, Cargo.lock and ${PLIST}"
        else
            # Any failure partway through leaves Cargo.toml, Cargo.lock and
            # ${PLIST} restored to their committed state, the same way Step C
            # restores Package.swift on failure -- so a resumed run starts
            # from a clean tree instead of dying at require_clean_tree.
            if ! bump_cargo_version Cargo.toml "$version"; then
                git checkout -- Cargo.toml Cargo.lock "$PLIST"
                die "Cargo.toml has no version key in its [package] table."
            fi
            if ! cargo update --workspace --quiet; then
                git checkout -- Cargo.toml Cargo.lock "$PLIST"
                die "cargo update --workspace failed after bumping Cargo.toml."
            fi
            if ! set_plist_version "$PLIST" "$version"; then
                git checkout -- Cargo.toml Cargo.lock "$PLIST"
                die "failed to set the version in ${PLIST}."
            fi
            echo "  Cargo.toml, Cargo.lock: ${version}"
            echo "  ${PLIST}: $(strip_prerelease "$version")"
        fi
        run git add Cargo.toml Cargo.lock "$PLIST"
        run git commit -m "Bump libzcashlc version to ${version}"
    fi
    push_if_ahead "$remote" "$candidate_branch"

    # --- B -----------------------------------------------------------------
    step "B. Producing the release artifacts"
    if [ "$DRY_RUN" = "true" ]; then
        echo "  would produce the XCFramework via the '${artifacts}' path"
        checksum="<checksum not yet known>"
    elif [ "$rebuild" != "true" ] && release_has_asset "$version"; then
        echo "  draft release ${version} already carries ${ZIP_FILE}; reusing it"
        checksum="$(checksum_of_release_asset "$version")"
    elif [ "$artifacts" = "ci" ]; then
        checksum="$(build_artifacts_in_ci "$version" "$candidate_branch" "$rebuild")"
    else
        produce_artifacts "$version" "$rebuild" "$verify"
        checksum="$(checksum_of_release_asset "$version")"
    fi
    echo "  checksum: ${checksum}"

    # --- C -----------------------------------------------------------------
    step "C. Pointing Package.swift at the release"
    if [ "$DRY_RUN" != "true" ] && package_swift_current "$version" "$checksum"; then
        echo "  Package.swift already names this release"
    else
        if [ "$DRY_RUN" = "true" ]; then
            echo "  would rewrite the binary target url and checksum"
        else
            if ! rewrite_package_swift Package.swift "$GH_REPO" "$version" "$checksum"; then
                git checkout -- Package.swift
                die "failed to rewrite the binary target in Package.swift."
            fi
        fi
        run git add Package.swift
        run git commit -m "Update Package.swift for release ${version}"
    fi
    push_if_ahead "$remote" "$candidate_branch"

    # --- D -----------------------------------------------------------------
    step "D. Marking pull request #${pr_number} ready"
    if [ "$DRY_RUN" != "true" ] && pr_has_ready_comment "$pr_number"; then
        echo "  the ready-to-merge comment is already present"
    elif [ "$DRY_RUN" = "true" ]; then
        echo "  would comment on #${pr_number} and mark it ready for review"
    else
        build_ready_comment "$version" "$checksum" |
            gh pr comment "$pr_number" --repo "$GH_REPO" --body-file -
    fi

    if [ "$DRY_RUN" != "true" ]; then
        is_draft="$(gh pr view "$pr_number" --repo "$GH_REPO" --json isDraft --jq .isDraft)"
        if [ "$is_draft" = "true" ]; then
            gh pr ready "$pr_number" --repo "$GH_REPO"
        else
            echo "  #${pr_number} is already ready for review"
        fi
    fi

    cat <<EOF

Done. https://github.com/${GH_REPO}/pull/${pr_number} is ready for review.

Once it has merged, from release/${version}:

  ./Scripts/release.sh ${remote} ${version}

which verifies the checksum against the uploaded asset, signs and pushes the
tag ${version}, and publishes the draft release. Afterwards merge the release
branch back into its maint/ branch and forward along the chain, as described in
CONTRIBUTING.md.
EOF
}

# ------------------------------------------------------------------ dispatch

main() {
    if [ $# -lt 1 ]; then
        usage >&2
        exit 1
    fi
    case "$1" in
        start)     shift; cmd_start "$@" ;;
        build)     shift; cmd_build "$@" ;;
        artifacts) shift; cmd_artifacts "$@" ;;
        -h|--help) usage ;;
        *)         usage >&2; die "unknown subcommand '$1'" ;;
    esac
}

main "$@"

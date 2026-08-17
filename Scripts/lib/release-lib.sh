# Shared helpers for the release scripts. Source this; do not execute it.
#
#   . "$(dirname "$0")/lib/release-lib.sh"
#
# Everything here is either a pure text transform or a preflight predicate, so
# that Scripts/tests/run-tests.sh can exercise it without a network, a git
# remote, or a GitHub token.
#
# Written for bash 3.2, which is what macOS ships.

# Paths, relative to the repository root.
PLIST="BuildSupport/platform-Info.plist"
PRODUCTS_DIR="BuildSupport/products"
ZIP_FILE="libzcashlc.xcframework.zip"
DEFAULT_REPO="zcash/zcash-swift-wallet-sdk"

# Set by each subcommand's argument parsing.
DRY_RUN="${DRY_RUN:-false}"

# ------------------------------------------------------------------ output

step() { echo; echo "==> $*"; }

die() {
    echo "error: $1" >&2
    shift
    while [ $# -gt 0 ]; do echo "       $1" >&2; shift; done
    exit 1
}

warn() {
    echo "warning: $1" >&2
    shift
    while [ $# -gt 0 ]; do echo "         $1" >&2; shift; done
}

# A precondition that only a real run has to satisfy: fatal normally, advisory
# under --dry-run. Reserved for checks nothing in the dry run itself depends on,
# so that a rehearsal still reports the problem rather than refusing to start.
# A check the dry run does depend on must stay fatal: silencing it there only
# relocates the failure to a message that blames the wrong thing.
die_unless_dry_run() {
    if [ "$DRY_RUN" = "true" ]; then
        warn "$@"
    else
        die "$@"
    fi
}

# Run a command, or describe it under --dry-run. Only state-changing commands
# go through this: preflight reads run unconditionally, so a dry run still
# reports what it found rather than what it assumed.
run() {
    if [ "$DRY_RUN" = "true" ]; then
        echo "  would run: $*"
    else
        "$@"
    fi
}

# ----------------------------------------------------------------- versions

# Semver ordering as a filter. GNU `sort -V` ranks 2.7.0-rc.1 *above* 2.7.0,
# which is backwards: a pre-release precedes its release. Mapping '-' to '~'
# fixes it, because sort -V treats '~' as lower than the empty string.
version_sort() { sed 's/-/~/' | sort -V | sed 's/~/-/'; }

# True when $1 <= $2 under that ordering.
version_le() {
    [ "$(printf '%s\n%s\n' "$1" "$2" | version_sort | head -1)" = "$1" ]
}

# 2.7.0-rc.3 -> 2.7.0. Apple rejects a CFBundleShortVersionString that is not a
# dotted numeric string, so the pre-release suffix cannot go into the plist.
strip_prerelease() { printf '%s\n' "${1%%-*}"; }

# SemVer: the hyphen introduces the pre-release identifiers, so 2.8.0-rc.1 is a
# pre-release and 2.8.0 is not.
is_prerelease() {
    case "$1" in
        *-*) return 0 ;;
        *)   return 1 ;;
    esac
}

# The `gh release` argument that makes a release's pre-release bit agree with
# its version. GitHub keeps that bit separately from the tag, and it is what
# stops a release candidate from being served as `latest` to everyone who asks
# the API for the newest release.
#
# Stated in both directions rather than only when set, because `gh release
# upload` replaces assets but not release properties: a draft created before
# the version gained or shed its suffix would otherwise keep the stale bit.
prerelease_flag() {
    if is_prerelease "$1"; then
        printf '%s\n' "--prerelease=true"
    else
        printf '%s\n' "--prerelease=false"
    fi
}

# What to call a version in prose. The closing summary is the last line an
# operator reads, and the two outcomes differ in what the API will serve as
# `latest`, so a run that published a release candidate must not sign off in
# the words of one that shipped to everybody.
release_noun() {
    if is_prerelease "$1"; then
        printf '%s\n' "Pre-release"
    else
        printf '%s\n' "Release"
    fi
}

# owner/repo from any form of GitHub remote URL: scp-style ssh, ssh://, or
# https, with or without a .git suffix.
repo_slug_from_url() {
    printf '%s\n' "$1" | sed -E \
        -e 's|\.git$||' \
        -e 's|^[a-z+]+://||' \
        -e 's|^[^/@]+@||' \
        -e 's|^[^/:]+[:/]||'
}

# ------------------------------------------------------------------- Cargo

# The version declared in a manifest's [package] table. `version` also appears
# in the dependency tables, so the search is scoped to [package] and stops at
# the next table heading.
cargo_package_version() {
    awk '
        /^\[/ { in_pkg = ($0 == "[package]") }
        in_pkg && /^version[[:space:]]*=/ {
            sub(/^version[[:space:]]*=[[:space:]]*"/, "")
            sub(/"[[:space:]]*$/, "")
            print
            exit
        }
    ' "$1"
}

# The version recorded for a named package in a lockfile.
cargo_lock_package_version() {
    awk -v pkg="$2" '
        /^name = / {
            name = $0
            sub(/^name = "/, "", name)
            sub(/"$/, "", name)
            next
        }
        /^version = / && name == pkg {
            sub(/^version = "/, "")
            sub(/"$/, "")
            print
            exit
        }
    ' "$1"
}

# Set the [package] version. Non-zero if the manifest has none, rather than
# writing a file that silently lost the key.
bump_cargo_version() {
    local file="$1" version="$2" tmp
    tmp="$(mktemp)"
    if ! awk -v ver="$version" '
        /^\[/ { in_pkg = ($0 == "[package]") }
        in_pkg && !changed && /^version[[:space:]]*=/ {
            print "version = \"" ver "\""
            changed = 1
            next
        }
        { print }
        END { if (!changed) exit 1 }
    ' "$file" > "$tmp"; then
        rm -f "$tmp"
        return 1
    fi
    mv "$tmp" "$file"
}

# -------------------------------------------------------------------- plist

plist_value() { plutil -extract "$2" raw -o - "$1"; }

# CFBundleVersion and CFBundleShortVersionString must both be dotted numeric
# strings, so the pre-release suffix is dropped. PlistBuddy rather than sed:
# the value is addressed by key, not by its position in the file.
set_plist_version() {
    local file="$1" short
    short="$(strip_prerelease "$2")"
    /usr/libexec/PlistBuddy -c "Set :CFBundleVersion ${short}" "$file" >/dev/null
    /usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString ${short}" "$file" >/dev/null
    [ "$(plist_value "$file" CFBundleShortVersionString)" = "$short" ] &&
        [ "$(plist_value "$file" CFBundleVersion)" = "$short" ]
}

# ---------------------------------------------------------------- CHANGELOG

# True when the Unreleased section has at least one non-blank line before the
# next heading. Entries are written as part of the commit that makes each
# change, so an empty section means they were forgotten -- far more likely than
# a genuinely invisible release.
changelog_unreleased_nonempty() {
    awk '
        /^# Unreleased/ { f = 1; next }
        f && /^# / { exit }
        f && NF { found = 1 }
        END { exit !found }
    ' "$1"
}

# Insert a dated release heading below `# Unreleased`, leaving the entries
# where they are. Never generates text.
promote_changelog() {
    local file="$1" version="$2" date="$3" tmp
    tmp="$(mktemp)"
    if ! awk -v ver="$version" -v date="$date" '
        !changed && /^# Unreleased/ {
            print
            print ""
            print "# " ver " - " date
            changed = 1
            next
        }
        { print }
        END { if (!changed) exit 1 }
    ' "$file" > "$tmp"; then
        rm -f "$tmp"
        return 1
    fi
    mv "$tmp" "$file"
}

# ------------------------------------------------------------ Package.swift

package_swift_url_version() {
    sed -n -E 's|.*/releases/download/([^/"]+)/libzcashlc\.xcframework\.zip".*|\1|p' "$1" | head -1
}

package_swift_checksum() {
    sed -n -E 's|.*checksum: "([0-9a-fA-F]+)".*|\1|p' "$1" | head -1
}

# Point the binary target at a release. The whole URL is replaced, owner
# included, so a run against a fork does not leave Package.swift pointing at
# the canonical repository. Verified before returning: a silent no-match here
# would ship the previous release's framework under the new tag.
rewrite_package_swift() {
    local file="$1" repo="$2" version="$3" checksum="$4"
    local url="https://github.com/${repo}/releases/download/${version}/${ZIP_FILE}"
    # Escape dots in ZIP_FILE for use as a sed regex pattern
    local zip_pattern="${ZIP_FILE//./\.}"
    sed -i.bak -E \
        -e "s|url: \"https://github\.com/[^\"]*/releases/download/[^\"]*/$(printf '%s\n' "$zip_pattern")\"|url: \"${url}\"|" \
        -e "s|checksum: \"[0-9a-fA-F]*\"|checksum: \"${checksum}\"|" \
        "$file"
    rm -f "${file}.bak"
    grep -qF "$url" "$file" && grep -qF "checksum: \"${checksum}\"" "$file"
}

# ----------------------------------------------------------------- preflight

require_clean_tree() {
    if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
        die "the working tree has uncommitted changes." \
            "Commit or stash them before releasing."
    fi
}

require_remote() {
    if ! git remote get-url "$1" >/dev/null 2>&1; then
        die "no such remote '$1'." "Available remotes: $(git remote | tr '\n' ' ')"
    fi
}

# $1 names how to report a failure, defaulting to `die`. Callers whose
# --dry-run path makes no authenticated call pass `die_unless_dry_run`, so a
# rehearsal reports the problem instead of refusing to run. Callers whose dry
# run does reach GitHub keep the default: without a token those reads fail
# anyway, and further along, with a message that misdiagnoses the cause.
require_gh_auth() {
    local report="${1:-die}"
    if ! command -v gh >/dev/null 2>&1; then
        "$report" "the GitHub CLI (gh) is not installed." \
            "See https://cli.github.com/"
        return
    fi
    if ! gh auth status >/dev/null 2>&1; then
        "$report" "gh is not authenticated." "Run: gh auth login"
    fi
}

# The repository a remote points at. Everything reaching GitHub goes through
# this rather than a hardcoded slug, so a rehearsal against a fork stays inside
# the fork instead of reaching the canonical repository.
repo_for_remote() { repo_slug_from_url "$(git remote get-url "$1")"; }

# Tests for prepare-release.sh's CI artifact path, with `gh` stubbed out.
#
# `build --artifacts ci` reads the checksum through `checksum="$(...)"`, where
# bash drops errexit. A failed CI run must still fail the call rather than fall
# through to the checksum of an older asset left on the draft release.

# Runs build_artifacts_in_ci in a subshell with a `gh` stub. $1 is the exit
# status the stubbed `gh run watch` returns. The stub always has an asset to
# download, standing in for one left on the draft by an earlier build.
_ci_build_with_watch_status() {
    PREPARE_RELEASE_NO_MAIN=1 WATCH_STATUS="$1" bash -c '
        set -euo pipefail
        . "$0"
        GH_REPO="example/repo"
        # `latest_ffi_run_id` runs in a command substitution, so the count of
        # `run list` calls has to live in a file to survive between them.
        runs_file="$(mktemp)"
        echo 0 > "$runs_file"
        sleep() { :; }
        gh() {
            case "$1 $2" in
                "run list")
                    runs=$(($(cat "$runs_file") + 1))
                    echo "$runs" > "$runs_file"
                    [ "$runs" -gt 1 ] && echo 2 || echo 1 ;;
                "workflow run") return 0 ;;
                "run watch") return "$WATCH_STATUS" ;;
                "release download")
                    local dir=""
                    while [ $# -gt 0 ]; do
                        [ "$1" = "--dir" ] && dir="$2"
                        shift
                    done
                    echo stale > "$dir/$ZIP_FILE" ;;
                *) return 1 ;;
            esac
        }
        # Called the way cmd_build calls it: inside a command substitution,
        # where errexit does not apply to the function body.
        checksum="$(build_artifacts_in_ci 9.9.9 candidate/9.9.9 true 2>/dev/null)"
        printf "%s\n" "$checksum"
    ' "$REPO_ROOT/Scripts/prepare-release.sh"
}

test_ci_build_fails_when_the_run_fails() {
    assert_fails "a failed CI run fails build_artifacts_in_ci" _ci_build_with_watch_status 1
}

test_ci_build_returns_a_checksum_when_the_run_succeeds() {
    local out
    out="$(_ci_build_with_watch_status 0)"
    assert_eq "$(printf 'stale\n' | shasum -a 256 | awk '{print $1}')" "$out" \
        "a successful CI run returns the asset's checksum"
}

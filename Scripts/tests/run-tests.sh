#!/usr/bin/env bash
#
# Test runner for the release-support shell library.
#
# Sources Scripts/lib/release-lib.sh, then every Scripts/tests/test-*.sh, and
# runs each function whose name begins with `test_`. There is no external
# dependency: adding bats to this repository is not worth it for a handful of
# text transforms.
#
# Usage: ./Scripts/tests/run-tests.sh [name-filter]

set -uo pipefail

TESTS_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$TESTS_DIR/../.." && pwd)"
FILTER="${1:-}"

# shellcheck source=../lib/release-lib.sh
. "$REPO_ROOT/Scripts/lib/release-lib.sh"

_assertions=0
_failures=0
_current=""

_fail() {
    _failures=$((_failures + 1))
    printf '  FAIL %s: %s\n' "$_current" "$1"
    shift
    while [ $# -gt 0 ]; do printf '         %s\n' "$1"; shift; done
}

assert_eq() {
    _assertions=$((_assertions + 1))
    [ "$1" = "$2" ] && return 0
    _fail "$3" "expected: [$1]" "actual:   [$2]"
}

assert_succeeds() {
    _assertions=$((_assertions + 1))
    local label="$1"; shift
    "$@" >/dev/null 2>&1 && return 0
    _fail "$label" "expected success, got exit $?: $*"
}

assert_fails() {
    _assertions=$((_assertions + 1))
    local label="$1"; shift
    "$@" >/dev/null 2>&1 || return 0
    _fail "$label" "expected failure, got success: $*"
}

assert_file_contains() {
    _assertions=$((_assertions + 1))
    grep -qF "$2" "$1" && return 0
    _fail "$3" "file $1 does not contain: $2"
}

assert_file_lacks() {
    _assertions=$((_assertions + 1))
    grep -qF "$2" "$1" || return 0
    _fail "$3" "file $1 unexpectedly contains: $2"
}

SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

# A writable copy of a fixture. Each call gets its own copy, so a test that
# rewrites a file in place cannot disturb another test.
_fixture_seq=0
fixture() {
    _fixture_seq=$((_fixture_seq + 1))
    local dest="$SCRATCH/${_fixture_seq}-$1"
    cp "$TESTS_DIR/fixtures/$1" "$dest"
    printf '%s\n' "$dest"
}

for f in "$TESTS_DIR"/test-*.sh; do
    [ -e "$f" ] || continue
    # shellcheck source=/dev/null
    . "$f"
done

for t in $(declare -F | awk '{print $3}' | grep '^test_' | sort); do
    case "$t" in
        *"$FILTER"*) ;;
        *) continue ;;
    esac
    _current="$t"
    "$t"
done

printf '\n%d assertions, %d failed\n' "$_assertions" "$_failures"
[ "$_failures" -eq 0 ]

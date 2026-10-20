# Offline argument-validation tests for prepare-release.sh.
#
# These must not reach the network. Each asserts a failure that argument
# parsing detects on its own, which is only true if validation runs before
# preflight -- so they double as a guard on that ordering.

_prepare() { "$REPO_ROOT/Scripts/prepare-release.sh" "$@"; }

test_prepare_release_is_executable() {
    assert_succeeds "prepare-release.sh is executable" \
        test -x "$REPO_ROOT/Scripts/prepare-release.sh"
}

test_no_subcommand_fails() {
    assert_fails "no subcommand" _prepare
}

test_unknown_subcommand_fails() {
    assert_fails "unknown subcommand" _prepare frobnicate
}

test_help_succeeds() {
    assert_succeeds "--help" _prepare --help
}

test_start_help_succeeds() {
    assert_succeeds "start --help" _prepare start --help
}

test_start_without_issue_fails() {
    assert_fails "start without --issue" _prepare start upstream 2.7.1
}

test_start_without_version_fails() {
    assert_fails "start without a version" _prepare start --issue 1 upstream
}

test_start_unknown_option_fails() {
    assert_fails "start with an unknown option" \
        _prepare start --issue 1 --frobnicate upstream 2.7.1
}

test_start_help_mentions_the_draft_pr() {
    assert_succeeds "start --help mentions the draft PR" \
        sh -c "'$REPO_ROOT/Scripts/prepare-release.sh' start --help | grep -qi draft"
}

test_artifacts_help_succeeds() {
    assert_succeeds "artifacts --help" _prepare artifacts --help
}

test_artifacts_without_version_fails() {
    assert_fails "artifacts without a version" _prepare artifacts
}

test_artifacts_unknown_option_fails() {
    assert_fails "artifacts with an unknown option" _prepare artifacts --frobnicate 2.7.1
}

test_build_help_succeeds() {
    assert_succeeds "build --help" _prepare build --help
}

test_build_without_version_fails() {
    assert_fails "build without a version" _prepare build upstream
}

test_build_unknown_option_fails() {
    assert_fails "build with an unknown option" _prepare build --frobnicate upstream 2.7.1
}

# --artifacts is validated during parsing, before any network call.
test_build_rejects_unknown_artifacts_path() {
    assert_fails "build --artifacts frobnicate" \
        _prepare build --artifacts frobnicate upstream 2.7.1
}

_release() { "$REPO_ROOT/Scripts/release.sh" "$@"; }

test_release_is_executable() {
    assert_succeeds "release.sh is executable" test -x "$REPO_ROOT/Scripts/release.sh"
}

test_release_help_succeeds() {
    assert_succeeds "release.sh --help" _release --help
}

test_release_without_version_fails() {
    assert_fails "release.sh without a version" _release upstream
}

test_release_unknown_option_fails() {
    assert_fails "release.sh with an unknown option" _release --frobnicate upstream 2.7.1
}

test_artifacts_documents_skip_verify() {
    assert_succeeds "artifacts --help documents --skip-verify" \
        sh -c "'$REPO_ROOT/Scripts/prepare-release.sh' artifacts --help | grep -q -- --skip-verify"
}

test_build_documents_skip_verify() {
    assert_succeeds "build --help documents --skip-verify" \
        sh -c "'$REPO_ROOT/Scripts/prepare-release.sh' build --help | grep -q -- --skip-verify"
}

# The overwrite path is restricted to drafts, and the help text has to say so:
# an operator reaching for the flag is by definition about to replace an
# artifact, and needs to know which ones are off limits before they try.
test_artifacts_help_restricts_overwrite_to_drafts() {
    assert_succeeds "artifacts --help says the overwrite is draft-only" \
        sh -c "'$REPO_ROOT/Scripts/prepare-release.sh' artifacts --help |
               grep -A1 -- --force-overwrite-existing-release | grep -q DRAFT"
}

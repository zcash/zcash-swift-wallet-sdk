# Tests for the version and URL helpers in Scripts/lib/release-lib.sh.

test_version_sort_orders_releases() {
    local got
    got="$(printf '2.7.1\n2.10.0\n2.7.0\n' | version_sort | tr '\n' ' ')"
    assert_eq "2.7.0 2.7.1 2.10.0 " "$got" "version_sort orders numerically, not lexically"
}

# GNU sort -V ranks 2.7.0-rc.1 above 2.7.0, which is backwards: a pre-release
# precedes its release. This is the bug version_sort exists to correct.
test_version_sort_ranks_prerelease_below_release() {
    local got
    got="$(printf '2.7.0\n2.7.0-rc.1\n' | version_sort | tr '\n' ' ')"
    assert_eq "2.7.0-rc.1 2.7.0 " "$got" "version_sort puts a pre-release below its release"
}

test_version_le_true_when_less() {
    assert_succeeds "version_le 2.7.0 2.7.1" version_le 2.7.0 2.7.1
}

test_version_le_true_when_equal() {
    assert_succeeds "version_le 2.7.0 2.7.0" version_le 2.7.0 2.7.0
}

test_version_le_false_when_greater() {
    assert_fails "version_le 2.7.1 2.7.0" version_le 2.7.1 2.7.0
}

test_version_le_false_for_release_over_its_prerelease() {
    assert_fails "version_le 2.7.0 2.7.0-rc.3" version_le 2.7.0 2.7.0-rc.3
}

test_strip_prerelease_removes_suffix() {
    assert_eq "2.7.0" "$(strip_prerelease 2.7.0-rc.3)" "strip_prerelease 2.7.0-rc.3"
}

test_strip_prerelease_leaves_plain_version() {
    assert_eq "2.7.0" "$(strip_prerelease 2.7.0)" "strip_prerelease 2.7.0"
}

test_strip_prerelease_handles_alpha() {
    assert_eq "2.6.0" "$(strip_prerelease 2.6.0-alpha.6)" "strip_prerelease 2.6.0-alpha.6"
}

test_is_prerelease_true_for_rc() {
    assert_succeeds "is_prerelease 2.8.0-rc.1" is_prerelease 2.8.0-rc.1
}

test_is_prerelease_true_for_alpha() {
    assert_succeeds "is_prerelease 2.6.0-alpha.6" is_prerelease 2.6.0-alpha.6
}

test_is_prerelease_false_for_release() {
    assert_fails "is_prerelease 2.8.0" is_prerelease 2.8.0
}

# The pre-release bit is stated in both directions. Only asserting the positive
# case would let `prerelease_flag` emit nothing for a release and still pass,
# which is exactly the state a re-uploaded draft must be able to leave behind.
test_prerelease_flag_marks_a_prerelease() {
    assert_eq "--prerelease=true" "$(prerelease_flag 2.8.0-rc.1)" \
        "prerelease_flag 2.8.0-rc.1"
}

test_prerelease_flag_unmarks_a_release() {
    assert_eq "--prerelease=false" "$(prerelease_flag 2.8.0)" \
        "prerelease_flag 2.8.0"
}

test_repo_slug_from_ssh_url() {
    assert_eq "zcash/zcash-swift-wallet-sdk" \
        "$(repo_slug_from_url 'git@github.com:zcash/zcash-swift-wallet-sdk.git')" \
        "repo_slug_from_url scp-style ssh"
}

test_repo_slug_from_https_url() {
    assert_eq "zcash/zcash-swift-wallet-sdk" \
        "$(repo_slug_from_url 'https://github.com/zcash/zcash-swift-wallet-sdk.git')" \
        "repo_slug_from_url https with .git"
}

test_repo_slug_from_https_url_without_suffix() {
    assert_eq "zcash/zcash-swift-wallet-sdk" \
        "$(repo_slug_from_url 'https://github.com/zcash/zcash-swift-wallet-sdk')" \
        "repo_slug_from_url https without .git"
}

test_repo_slug_from_ssh_protocol_url() {
    assert_eq "zcash/zcash-swift-wallet-sdk" \
        "$(repo_slug_from_url 'ssh://git@github.com/zcash/zcash-swift-wallet-sdk.git')" \
        "repo_slug_from_url ssh:// scheme"
}

# The fork rehearsal in the design depends on this: a fork remote must yield the
# fork's slug, never the canonical one.
test_repo_slug_from_fork_url() {
    assert_eq "nuttycom/zcash-swift-wallet-sdk" \
        "$(repo_slug_from_url 'git@github.com:nuttycom/zcash-swift-wallet-sdk.git')" \
        "repo_slug_from_url a fork"
}

# Tests for the file-reading and file-rewriting helpers.

test_cargo_package_version_reads_package_table() {
    assert_eq "2.7.0-rc.3" "$(cargo_package_version "$(fixture Cargo.toml)")" \
        "cargo_package_version reads [package].version"
}

test_cargo_lock_package_version_reads_named_package() {
    assert_eq "2.7.0-rc.3" \
        "$(cargo_lock_package_version "$(fixture Cargo.lock)" libzcashlc)" \
        "cargo_lock_package_version finds libzcashlc"
}

test_cargo_lock_package_version_does_not_confuse_packages() {
    assert_eq "0.15.0" \
        "$(cargo_lock_package_version "$(fixture Cargo.lock)" orchard)" \
        "cargo_lock_package_version finds orchard"
}

test_bump_cargo_version_rewrites_package_table() {
    local f; f="$(fixture Cargo.toml)"
    bump_cargo_version "$f" 2.7.1
    assert_eq "2.7.1" "$(cargo_package_version "$f")" "bump_cargo_version sets [package].version"
}

# `version` appears in inline dependency forms like `orchard = { version = "..." }`
# and bare dependency-name forms like `version_check = "..."`. The column-0
# anchor alone excludes these, so this test passes even without table scoping.
test_bump_cargo_version_leaves_dependencies_alone() {
    local f; f="$(fixture Cargo.toml)"
    bump_cargo_version "$f" 2.7.1
    assert_file_contains "$f" 'orchard = { version = "0.15" }' \
        "bump_cargo_version leaves dependency versions untouched"
    assert_file_contains "$f" 'version_check = "0.9"' \
        "bump_cargo_version leaves build-dependencies untouched"
}

# The scoping in bump_cargo_version only changes behaviour when a bare
# `version =` at column 0 precedes [package] -- the [dependencies.X] sub-table
# form. Without the fixture below, deleting `in_pkg &&` from the awk leaves
# every other test in this file passing, because the column-0 anchor alone
# already excludes `orchard = { version = "0.15" }`.
test_bump_cargo_version_scopes_to_package_when_not_first_table() {
    local f; f="$(fixture Cargo-package-not-first.toml)"
    bump_cargo_version "$f" 2.7.1
    assert_eq "2.7.1" "$(cargo_package_version "$f")" \
        "bump_cargo_version finds [package] when it is not the first table"
    assert_file_contains "$f" 'version = "0.15"' \
        "bump_cargo_version leaves a preceding sub-table's version alone"
}

test_bump_cargo_version_fails_without_package_version() {
    local f; f="$SCRATCH/no-package-version.toml"
    printf '[dependencies]\nversion = "1.0"\n' > "$f"
    assert_fails "bump_cargo_version with no [package] table" \
        bump_cargo_version "$f" 2.7.1
}

test_plist_value_reads_key() {
    assert_eq "0.8.1" "$(plist_value "$(fixture platform-Info.plist)" CFBundleShortVersionString)" \
        "plist_value reads CFBundleShortVersionString"
}

test_set_plist_version_strips_prerelease() {
    local f; f="$(fixture platform-Info.plist)"
    set_plist_version "$f" 2.7.0-rc.3
    assert_eq "2.7.0" "$(plist_value "$f" CFBundleShortVersionString)" \
        "set_plist_version writes a numeric short version"
    assert_eq "2.7.0" "$(plist_value "$f" CFBundleVersion)" \
        "set_plist_version writes CFBundleVersion"
}

test_set_plist_version_leaves_other_keys() {
    local f; f="$(fixture platform-Info.plist)"
    set_plist_version "$f" 2.7.1
    assert_eq "100.0" "$(plist_value "$f" MinimumOSVersion)" \
        "set_plist_version does not disturb MinimumOSVersion"
}

test_changelog_unreleased_nonempty_true_with_entries() {
    assert_succeeds "changelog_unreleased_nonempty with entries" \
        changelog_unreleased_nonempty "$(fixture CHANGELOG.md)"
}

test_changelog_unreleased_nonempty_false_when_empty() {
    assert_fails "changelog_unreleased_nonempty with an empty section" \
        changelog_unreleased_nonempty "$(fixture CHANGELOG-empty-unreleased.md)"
}

test_promote_changelog_inserts_heading() {
    local f; f="$(fixture CHANGELOG.md)"
    promote_changelog "$f" 2.7.1 2026-07-30
    assert_file_contains "$f" "# 2.7.1 - 2026-07-30" "promote_changelog inserts the heading"
    assert_file_contains "$f" "# Unreleased" "promote_changelog keeps the Unreleased heading"
    assert_file_contains "$f" "A thing that was added." "promote_changelog keeps the entries"
}

test_promote_changelog_inserts_only_once() {
    local f count; f="$(fixture CHANGELOG.md)"
    promote_changelog "$f" 2.7.1 2026-07-30
    count="$(grep -c '^# 2.7.1 - 2026-07-30$' "$f")"
    assert_eq "1" "$count" "promote_changelog inserts exactly one heading"
}

test_promote_changelog_fails_without_unreleased() {
    local f; f="$SCRATCH/no-unreleased.md"
    printf '# 2.7.0 - 2026-05-01\n\n- old\n' > "$f"
    assert_fails "promote_changelog with no Unreleased heading" \
        promote_changelog "$f" 2.7.1 2026-07-30
}

test_package_swift_url_version_reads_version() {
    assert_eq "2.7.0-rc.3" "$(package_swift_url_version "$(fixture Package.swift)")" \
        "package_swift_url_version reads the URL version"
}

test_package_swift_checksum_reads_checksum() {
    assert_eq "0000000000000000000000000000000000000000000000000000000000000000" \
        "$(package_swift_checksum "$(fixture Package.swift)")" \
        "package_swift_checksum reads the checksum"
}

test_rewrite_package_swift_sets_url_and_checksum() {
    local f sum; f="$(fixture Package.swift)"
    sum="1111111111111111111111111111111111111111111111111111111111111111"
    rewrite_package_swift "$f" zcash/zcash-swift-wallet-sdk 2.7.1 "$sum"
    assert_eq "2.7.1" "$(package_swift_url_version "$f")" "rewrite_package_swift sets the URL version"
    assert_eq "$sum" "$(package_swift_checksum "$f")" "rewrite_package_swift sets the checksum"
}

# The fork rehearsal depends on the owner being rewritten too, not just the
# version: otherwise a fork run would point Package.swift at the canonical repo.
test_rewrite_package_swift_sets_owner() {
    local f sum; f="$(fixture Package.swift)"
    sum="1111111111111111111111111111111111111111111111111111111111111111"
    rewrite_package_swift "$f" nuttycom/zcash-swift-wallet-sdk 2.7.1 "$sum"
    assert_file_contains "$f" \
        "https://github.com/nuttycom/zcash-swift-wallet-sdk/releases/download/2.7.1/libzcashlc.xcframework.zip" \
        "rewrite_package_swift rewrites the repository owner"
    assert_file_lacks "$f" "zcash/zcash-swift-wallet-sdk/releases" \
        "rewrite_package_swift leaves no stale owner"
}

test_rewrite_package_swift_fails_without_binary_target() {
    local f; f="$SCRATCH/no-target.swift"
    printf 'let package = Package(name: "X")\n' > "$f"
    assert_fails "rewrite_package_swift with no binary target" \
        rewrite_package_swift "$f" zcash/zcash-swift-wallet-sdk 2.7.1 \
        1111111111111111111111111111111111111111111111111111111111111111
}

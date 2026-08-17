# Offline, text-only checks on .github/workflows/build-ffi.yml.
#
# These never invoke gh or dispatch anything; they just read the checked-in
# YAML. They exist to pin two properties from Finding 1's fix:
#
#   - the workflow accepts a `force` input and reads it into the build step
#     via `env:`, so `prepare-release.sh build --artifacts ci --rebuild` has
#     something to forward to;
#   - no `${{ }}` expression is interpolated directly into a `run:` script.
#     Template injection into `run:` is exactly what this repository's
#     zizmor lint flags; every workflow input must instead flow in through
#     `env:` and be read back as a shell variable.

_workflow_file() { printf '%s\n' "$REPO_ROOT/.github/workflows/build-ffi.yml"; }

test_build_ffi_workflow_declares_force_input() {
    assert_succeeds "build-ffi.yml declares a force input" \
        grep -q '^      force:' "$(_workflow_file)"
}

test_build_ffi_workflow_reads_force_via_env() {
    assert_succeeds "build-ffi.yml's build step reads FORCE from env, not inline" \
        grep -qF 'FORCE: ${{ github.event.inputs.force }}' "$(_workflow_file)"
}

test_build_ffi_workflow_branches_on_force_in_shell() {
    assert_succeeds "build-ffi.yml's run script branches on \$FORCE" \
        grep -qF '[ "$FORCE" = "true" ]' "$(_workflow_file)"
}

test_build_ffi_workflow_force_path_passes_force_overwrite_flag() {
    assert_succeeds "the \$FORCE=true branch passes --force-overwrite-existing-release" \
        grep -qF -- '--force-overwrite-existing-release "$VERSION"' "$(_workflow_file)"
}

# Every `${{ }}` in the file must be a single `KEY: ${{ ... }}` line inside an
# `env:` block -- never text spliced into a `run:` script. This is a
# regression guard: it would fail if a future change went back to writing
# `run: ./foo ${{ github.event.inputs.x }}`.
test_build_ffi_workflow_interpolations_are_env_assignments_only() {
    local offending
    offending="$(grep -n '\${{' "$(_workflow_file)" |
        grep -vE '^[0-9]+: *[A-Za-z_]+: \$\{\{ [^}]+ \}\}$')"
    assert_eq "" "$offending" \
        "every \${{ }} in build-ffi.yml is an env: key assignment, none inside run:"
}

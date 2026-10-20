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

# No `${{ }}` may appear on a `run:` line or anywhere in its block scalar. That
# is the injection GitHub evaluates before the shell ever sees the script, so
# workflow inputs reach it through `env:` and are read back as shell variables.
# Expressions elsewhere -- an action's `with:` inputs, a cache key -- are
# evaluated as YAML values and cannot reach a shell, so they are unrestricted.
# This is a regression guard: it would fail if a future change went back to
# writing `run: ./foo ${{ github.event.inputs.x }}`.
test_build_ffi_workflow_no_interpolation_reaches_a_run_script() {
    local offending
    offending="$(awk '
        {
            here = match($0, /[^ \t]/)
            indent = here ? here - 1 : length($0)
            if ($0 ~ /^[ \t]*-?[ \t]*run:/) {
                in_run = 1
                run_indent = indent
            } else if (in_run && $0 ~ /[^ \t]/ && indent <= run_indent) {
                in_run = 0
            }
            if (in_run && index($0, "${{")) print NR ": " $0
        }
    ' "$(_workflow_file)")"
    assert_eq "" "$offending" \
        "no \${{ }} in build-ffi.yml is spliced into a run: script"
}

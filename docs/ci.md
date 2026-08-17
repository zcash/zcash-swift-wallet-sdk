# Continuous Integration

The project uses GitHub Actions for CI. Workflows are defined in `.github/workflows/`.

## PR Checks

When a PR is opened, the following checks run automatically:

- **SwiftLint** (`swiftlint.yml`) — checks Swift code style
- **Build and Run Offline Tests** (`swift.yml`) — builds the FFI from source (with caching), builds the Swift package, and runs the `OfflineTests` suite

## FFI Build Workflow

The **Build FFI XCFramework** workflow (`build-ffi.yml`) is triggered manually
via `workflow_dispatch`. It runs `./Scripts/prepare-release.sh artifacts`, which
builds the full XCFramework for every platform, verifies that the Swift package
builds and passes `OfflineTests` when linked against it, then zips it with its
checksum and uploads it as a draft GitHub Release.

That verification runs before the upload, not after: a mismatch across the FFI
boundary compiles on both sides and fails only at link or run time, so it is
the last point at which one can be caught before the artifact is public.

It touches no git or pull-request state, which is why it needs only
`contents: write`. To consume its output, run
`./Scripts/prepare-release.sh build --artifacts ci <remote> <version>` from a
checkout on the candidate branch: that dispatches the workflow, waits for it,
and writes the resulting URL and checksum into `Package.swift`.

## Manual Deployment

Prerequisites:
- Write permissions on the repo
- `gh` CLI installed and authenticated
- Rust toolchain with all Apple platform targets
- A tag signing key configured

A release is three commands, described in full under "Cutting a release" in
`CONTRIBUTING.md`:

- `./Scripts/prepare-release.sh start --issue <N> <remote> <version>` — cut the
  branches, promote the CHANGELOG, open the draft PR
- `./Scripts/prepare-release.sh build <remote> <version>` — bump versions, build
  and verify the artifacts, upload them, ready the PR
- `./Scripts/release.sh <remote> <version>` — tag and publish, after the PR
  merges. It refuses unless the local release branch matches the remote, and
  pushes nothing but the tag.

A version with a pre-release suffix, such as `2.8.0-rc.1`, is marked as a
pre-release on GitHub at every point it is created, re-uploaded or published.

Pass `--dry-run` to any of them first. See each subcommand's `--help` for
options.

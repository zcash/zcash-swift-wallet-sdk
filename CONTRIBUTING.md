# Contributing Guidelines

This document contains information and guidelines about contributing to this project.
Please read it before you start participating.

**Topics**

* [Asking Questions](#asking-questions)
* [Reporting Security Issues](#reporting-security-issues)
* [Reporting Non Security Issues](#reporting-other-issues)
* [Release and Maintenance Branches](#release-and-maintenance-branches)
* [Commit Messages](#commit-messages)
* [Developers Certificate of Origin](#developers-certificate-of-origin)

## Asking Questions

Questions are welcome! We encourage you to ask questions through GitHub issues.
Before doing so, please check that the project issues database doesn't already
include an answer to your question. Then open a new Issue and use the "Question"
label.

## Reporting Security Issues

If you have discovered an issue with this code that could present a security hazard or wish to discuss a sensitive issue with our security team, please contact security@z.cash [security.asc](https://z.cash/gpg-pubkeys/security.asc). Key fingerprint = AF85 0445 546C 18B7 86F9 2C62 88FB 8B86 D8B5 A68C

## Reporting Non Security Issues

A great way to contribute to the project
is to send a detailed issue when you encounter a problem.
We always appreciate a well-written, thorough bug report.

Check that the project issues database
doesn't already include that problem or suggestion before submitting an issue.
If you find a match, add a quick "+1" or "I have this problem too."
Doing this helps prioritize the most common problems and requests.

When reporting issues, please include the following:

* The iOS version you're using
* The device you're targeting
* The full output of any stack trace or compiler error
* A code snippet that reproduces the described behavior, if applicable
* Any other details that would be useful in understanding the problem

This information will help us review and fix your issue faster.

## Pull Requests

We **love** pull requests!

All contributions _will_ be licensed under the MIT license.

Code/comments should adhere to the following rules:

* Every Pull request must have an Issue associated to it. PRs with not
associated with an Issue will be closed
* Code build and Code Lint must pass.
* Names should be descriptive and concise.
* Although they are not mandatory, PRs that include significant testing will be
prioritized.
* All enhancements and bug fixes need to be documented in the CHANGELOG.
* When writing comments, use properly constructed sentences, including
  punctuation.
* When documenting APIs and/or source code, don't make assumptions or make
  implications about race, gender, religion, political orientation or anything
  else that isn't relevant to the project.
* Remember that source code usually gets written once and read often: ensure
  the reader doesn't have to make guesses. Make sure that the purpose and inner
  logic are either obvious to a reasonably skilled professional, or add a
  comment that explains it.

## Release and Maintenance Branches

`main` is the development trunk. Released versions are maintained on long-lived
`maint/` branches, one per minor release line, so that a fix can reach users
already running an older version without shipping them unrelated trunk work.

| Branch | Lifetime | Purpose |
| --- | --- | --- |
| `main` | permanent | Development trunk. New feature work lands here. |
| `maint/vX.Y.x` | permanent | One per supported release line. Fixes to released versions land here. |
| `release/X.Y.Z` | one release | Cut from the previous release tag. The base of the release PR, and what gets tagged. |
| `candidate/X.Y.Z` | one release | Cut from the revision being released. Carries the release preparation commits, and is the head of the release PR. |

### Basing a bug fix

**The rule is: merge forward, cherry-pick back.**

Branch bug fixes from the oldest currently-supported maintenance branch — at the
time of writing that is `maint/v2.7.x`. From there the fix travels to every newer
line by merging forward, keeping one commit identity and leaving later merges
between those branches clean. This is the normal path and the one the diagram
below shows; expect nearly every fix to take it.

Cherry-picking back is the exception, for a fix that has already landed on a
newer line and turns out to be needed on an older one too. Never merge backward:
that would drag everything else on the newer line into the older release.

```
                    fix/1234
                   ●────●
                  /       \
maint/v2.7.x  ───●─────────●─────────────────────────────▶   base bug fixes here
                            \
                             \  merge forward
                              ▼
maint/v2.8.x  ───●────────────●──────────────────────────▶
                               \
                                \  merge forward
                                 ▼
main          ───●───────────────●───────────────────────▶
```

### Cutting a release

A release happens in two phases, with a human reading the pull request in
between. Both are driven by `./Scripts/prepare-release.sh`; pass `--dry-run` to
either to see what it will do without changing anything.

**Phase one** — `./Scripts/prepare-release.sh start --issue <N> <remote> <version>`:

1. Create `release/X.Y.Z` **from the previous release tag** and push it to
   upstream. It starts out identical to the last release.
2. Create `candidate/X.Y.Z` from the maintenance branch that contains all of
   the changes to be released.
3. Promote the CHANGELOG's `Unreleased` section to `X.Y.Z`.
4. Open a **draft** pull request **on the public repository** from
   `candidate/X.Y.Z` into `release/X.Y.Z`.

Review that pull request. Its diff is exactly what users receive relative to
the last release, rather than the intervening development history — which is
the whole reason the release branch is based on the previous release tag.

**Phase two** — `./Scripts/prepare-release.sh build <remote> <version>`:

5. Bump the recorded version in `Cargo.toml`, `Cargo.lock` and
   `BuildSupport/platform-Info.plist`.
6. Build the XCFramework; verify the SDK builds and passes `OfflineTests`
   against it; then upload it as a draft GitHub release. `--artifacts ci` does
   all of that on a runner instead of locally; `--skip-verify` skips the
   build-and-test check.
7. Rewrite `Package.swift`'s binary target to point at that release.
8. Extend `candidate/X.Y.Z` with both commits, comment on the pull request, and
   mark it ready for review.

Each step of phase two checks whether it has already run, so re-running it
after a failure resumes rather than starting over.

9. Merge the pull request, then run `./Scripts/release.sh <remote> X.Y.Z` from
   `release/X.Y.Z`. It requires that branch to be identical to its counterpart
   on `<remote>` — only what merged there may be tagged, and a pushed tag
   cannot be recalled — then verifies the checksum in `Package.swift` against
   the uploaded asset, signs the tag `X.Y.Z`, pushes it, and publishes the
   release. The tag is the only thing pushed.

A version carrying a pre-release suffix, such as `2.8.0-rc.1`, is marked as a
pre-release on GitHub, both on the draft created in step 6 and on the published
release in step 9. That bit is what keeps a release candidate from being served
as `latest` to everyone who asks the API for the newest release.

The artifact build alone is available as
`./Scripts/prepare-release.sh artifacts <version>`. It touches no git or
pull-request state, which is what lets `.github/workflows/build-ffi.yml` run it
with only `contents: write`. Its
`--force-overwrite-existing-release` replaces the assets of a *draft* release
only: `Package.swift` pins the checksum of whatever a published release
carries, and SwiftPM checks it on every fetch, so replacing that asset breaks
the build of every consumer that has already resolved the version.

```
tag X.Y.W  (previous release)
      │
      └──▶  release/X.Y.Z  ●──────────────────────────────●  tag X.Y.Z
                                                          ▲
                                                          │  PR: candidate ──▶ release
                                                          │
     candidate/X.Y.Z   ●────●────●────────────────────────┘
                       ▲     CHANGELOG, version bump, XCFramework
                       │
                       │  branch from maint
maint/vX.Y.x ──●────●──┴────────────────────────▶
               └─ changes to be released ─┘
```

### After the release

Three merges, in order:

1. Merge `release/X.Y.Z` back into `maint/vX.Y.x`, so the maintenance branch
   carries the tagged release and its preparation commits.
2. Merge each maintenance branch forward into the next newer one. With
   `maint/v2.7.x` and `maint/v2.8.x` both active, a release on the 2.7 line goes
   `maint/v2.7.x` → `maint/v2.8.x`. Repeat along the chain for every newer line.
3. Merge the newest maintenance branch into `main`.

```
release/X.Y.Z   ●  tag X.Y.Z
                 \
                  \  1. merge back
                   ▼
maint/vX.Y.x  ──────●────────────────────────────────────▶
                     \
                      \  2. merge forward
                       ▼
maint/vX.Y+1.x  ────────●────────────────────────────────▶
                         \
                          \  3. merge back to trunk
                           ▼
main          ──────────────●────────────────────────────▶
```

Do not treat step 3 as release-time-only work: merge `maint/` branches back to
`main` regularly. Trunk then never drifts far from what is shipping, and each
merge stays small enough to resolve confidently.

Skipping a forward merge is how a fix silently regresses — a user upgrading from
2.7.1 to 2.8.0 would lose it. If a forward merge conflicts, resolve it in favour
of keeping both changes rather than dropping either, and verify the result builds
before pushing.

## Commit Messages

Commit history is an important part of the project's documentation.
Besides its obvious testimonial value, commits represent a point in time
in the project's lifetime in a given context. A good record of the changes that
occurred during the project's life helps to guarantee that it can outlive its
stakeholders no matter how foundational or crucial these individuals (or
groups) were. As any reading material, it is best appreciated and comprehended
when there's a visible structure that readers can follow and reason about.

For that we've defined a structure for commit messages that all contributors must
follow to maintain coherence on the project's commit log. The proposed format
has been inspired by [this great article](https://cbea.ms/git-commit/)


### Preparing to contribute to the project
The first thing you should look for is an existing issue. It is possible
that the contribution you are planning to work on was already discussed
by other users and/or contributors in the past. If not present, file an
issue following the criteria described in the preceding sections.

Every contribution must reference an existing Issue. This issue is important
since it will be directly referenced in the title of your commit.

We prefer small PR's, and PRs are always landed with a _merge commit_ —
never squash-merged or rebased — so the branch's commits enter history
exactly as reviewed. Because of this, we encourage contributors to squash
their own work into a tidy series of self-contained commits before review.

When squashing commits, use your best judgement. In some situations, a refactoring may
be done before actual behavior changes are implemented. It is reasonable to keep such
a refactoring as a separate commit as it both makes review easier and allows for
these refactoring commit SHAs to be added to `.git-blame-ignore-revs`.

### Structuring a PR Commit

#### Commit Title
The first line of your commit message constitutes its _title_. Maintainers will
use commit titles to create release notes. Your contribution will be featured
in a public release of the project. Think of it as a newspaper headline. It
should be descriptive and provide the reader a broad idea of what the commit is
about. You can use a related github issue if it matches this criterion.

**Preferred title format**

`[#{issue_number}] {self_descriptive_title}`

Example

`[#258] - User can take the backup test successfully more than once`

optionally you can append the PR # between parenthesis.

#### Commit message's body

Use the body of the commit to bring more context to the change. Usually the bulk
of the problem might be explained in the GitHub Issue. It's a good long term strategy
not to rely on such elements. If the project were to change its hosting, much of the
associated "Issues" and "pull requests" will be lost, yet the commit history will
probably be preserved and the context will also be.

If there are followup issues for this commit, consider referencing those as well.

**Use the tools on your favor!**

When opening a Pull Request, GitHub will take the title of your commit as the PR's
title and the body of your PR its description. Having a proper structure on your
commit will make your day shorter.


### Example:

````
commit [some_hash]
Author: You <you@somedomain.io>
Date:   some date

    [#258] User can take the backup test successfully more than once (#282)
    
    Closes #258
    
    this checks that when the user taps the finished button on the phrase displayed it has definitely not passed the test before going to the recovery flow.
    
    Note: this should actually go to the next or previous screen according to the context that takes the user to the phrase display screen from that context.
    
    Add //TODO comment with the permanent fix for the problem
````

When you open a PR with a commit like this one the first line will land on the GUI's title field,
and the body will be added as the description of the PR.

Adding the text `Closes #{issue_number}` will tell GitHub to close the issue when the PR is merged.

Let the machines do their work.



## Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

- (a) The contribution was created in whole or in part by me and I
      have the right to submit it under the open source license
      indicated in the file; or

- (b) The contribution is based upon previous work that, to the best
      of my knowledge, is covered under an appropriate open source
      license and I have the right under that license to submit that
      work with modifications, whether created in whole or in part
      by me, under the same open source license (unless I am
      permitted to submit under a different license), as indicated
      in the file; or

- (c) The contribution was provided directly to me by some other
      person who certified (a), (b) or (c) and I have not modified
      it.

- (d) I understand and agree that this project and the contribution
      are public and that a record of the contribution (including all
      personal information I submit with it, including my sign-off) is
      maintained indefinitely and may be redistributed consistent with
      this project or the open source license(s) involved.



This contribution guide is inspired on great projects like [AlamoFire](https://github.com/Alamofire/Foundation/blob/master/CONTRIBUTING.md) and [CocoaPods](https://github.com/CocoaPods/CocoaPods/blob/master/CONTRIBUTING.md)

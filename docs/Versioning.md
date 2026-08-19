# Versioning and SwiftPM Resolution

This project follows [Semantic Versioning 2.0.0](https://semver.org/). Release
tags come in two families:

| Tag | Contents | How consumers select it |
| :-- | :-- | :-- |
| `X.Y.Z` | Default variant: MIT-only, no AGPL code | Normal version ranges (`from:`, `.upToNextMajor`) or `exact:` |
| `X.Y.Z-alphaN` / `-betaN` / `-rcN` | Pre-releases of the default variant | `exact:` (or a pre-release lower bound, see caveats) |
| `X.Y.Z-zodl-slipstream` | ZODL Slipstream variant: adds the AGPL-3.0-only engine and the `ZODLSlipstream` product | `exact:` **only** |

The `-zodl-slipstream` suffix is a SemVer *pre-release identifier*. That is a
deliberate design choice, not a labeling convenience: SemVer orders
`X.Y.Z-anything` **below** `X.Y.Z`, and SwiftPM's resolver categorically
excludes pre-release versions from ordinary ranges. Together these make the
AGPL variant impossible to adopt by accident. The rest of this document
records exactly how SwiftPM behaves, with the resolver source as the
reference, and the caveats worth knowing.

## How SwiftPM resolves these tags

The behaviors below were verified against the SwiftPM resolver sources
([`TSCUtility/Version.swift`](https://github.com/apple/swift-tools-support-core/blob/main/Sources/TSCUtility/Version.swift),
[`PackageGraph/VersionSetSpecifier.swift`](https://github.com/swiftlang/swift-package-manager/blob/main/Sources/PackageGraph/VersionSetSpecifier.swift)),
not inferred from documentation.

### Tag validity

`2.9.0-zodl-slipstream` is a valid SemVer version and a valid SwiftPM release
tag. Pre-release identifiers may contain letters, digits, and hyphens;
`zodl-slipstream` is a single such identifier. (SemVer's "no leading zeros"
rule applies only to purely numeric identifiers.)

### Version ranges never resolve to a pre-release tag

`Range<Version>.contains(version:)` begins with a hard rule: **if the
candidate version carries pre-release identifiers and neither range bound
does, it is rejected.** A consumer using

```swift
.package(url: "…", from: "2.9.0")
```

can therefore never resolve `2.9.0-zodl-slipstream` — and not future variant
tags like `2.10.0-zodl-slipstream` either, even though their core version lies
inside the range. This is structural resolver behavior, not an artifact of
version ordering, and it is the guarantee the dual-variant scheme leans on.

### `exact:` is the opt-in path

```swift
.package(url: "…", exact: "2.9.0-zodl-slipstream")
```

`exact:` resolves by direct version equality and bypasses the pre-release gate
entirely. It is the **only** supported way to consume a `-zodl-slipstream`
tag. Do not attempt to construct ranges across variant tags; besides being
unsupported, ranges cannot reach them at all (above).

## Toolchain floor

The manifest declares `swift-tools-version:5.9`, which the ZODLSlipstream split
requires: the two targets share internals through the `package` access modifier,
introduced in Swift 5.9.

This raises nothing in practice. The resolved dependency graph already contains
manifests at tools-version **6.2** (swift-protobuf, swift-collections,
swift-async-algorithms, reached through grpc-swift), and SwiftPM requires a
toolchain at least as new as the highest tools-version in the graph — so
consumers already needed Swift 6.2+ before this package declared 5.9. The
previous `5.6` declaration was also already inaccurate: the sources use the
Swift 5.7 `if let x {` shorthand in dozens of places and cannot compile on a 5.6
compiler.

## Caveats

### 1. Pre-release lower bounds open the whole range to pre-releases

If a consumer uses a pre-release *lower bound* — e.g. `from: "2.9.0-rc1"`
while testing a release candidate — SwiftPM admits pre-release versions across
the **entire** resulting range (`2.9.0-rc1 ..< 3.0.0`), not just pre-releases
of `2.9.0`. In that configuration a future `2.15.3-zodl-slipstream` tag is
in-range.

In practice such a consumer still cannot land on the variant, because the
resolver picks the *highest* version in range and every variant tag's clean
twin (`2.15.3 > 2.15.3-zodl-slipstream`) exists and outranks it. That
protection rests on a release invariant:

> **Release invariant:** a `X.Y.Z-zodl-slipstream` tag must never exist
> without its `X.Y.Z` twin. `Scripts/release.sh` creates both tags in one run
> and pushes them in a single `git push`; keep it that way, and never delete a
> clean tag while its variant tag remains.

Consumers who want to avoid this class of surprise entirely should pin
pre-releases with `exact:` rather than using pre-release lower bounds.

### 2. Pin the ZODL Slipstream variant in `Package.swift`, not Xcode's version field

Xcode's Package Dependencies UI runs its own version-string validation,
separate from SwiftPM's parser, and it has a documented history of mishandling
pre-release strings in the "Exact Version" field (reverting or mutating the
entered value; see Apple Developer Forums threads
[775538](https://developer.apple.com/forums/thread/775538) and
[730959](https://developer.apple.com/forums/thread/730959)). The
`zodl-slipstream` identifier avoids the specific known failure shapes, but the
field's round-trip behavior is not something to rely on.

Recommendation: declare the dependency in a `Package.swift` manifest with
`exact:`, or if the app must use an Xcode project dependency, verify after
entering the pin that `Package.resolved` records the intended
`X.Y.Z-zodl-slipstream` version.

### 3. Tag listing order

For the same core version, pre-release identifiers compare lexically:
`2.9.0-rc1 < 2.9.0-zodl-slipstream < 2.9.0`. This has no effect on resolution
(ranges exclude both; `exact:` matches literally), but in sorted tag listings
the variant appears *after* the release candidates and *before* the release.

### 4. Both variants share one release

The two tags of a release point at almost-identical commits: the variant tag
is exactly one commit ahead, flipping the `zodlSlipstreamVariantPinned` constant
in `Package.swift`. The flag lives in the manifest bytes (rather than only in
a marker file) because SwiftPM's shared manifest cache is keyed on manifest
*content* — byte-identical manifests across the two tags would let one
variant's cached target graph serve the other. Local development uses the
`.zodl-slipstream-variant` marker file instead (see
`Scripts/init-local-ffi.sh`), which is why the local-FFI scripts purge the
SwiftPM manifest cache whenever the marker flips.

## Build-type table (app-facing version codes)

The pre-release build types used by the default variant, in order of
stability:

| Type  | Purpose | Stability | Audience | Identifier | Example Version |
| :---- | :--------- | :---------- | :-------- | :------- | :--- |
| **alpha** | **Sandbox.** For developers to verify behavior and try features. Things seen here might never go to production. Most bugs here can be ignored.| Unstable: Expect bugs | Internal developers | 0XX | 1.2.3-alpha04 (10203004) |
| **beta** | **Hand-off.** For developers to present finished features. Bugs found here should be reported and immediately addressed, if they relate to recent changes. | Unstable: Report bugs | Internal stakeholders | 2XX | 1.2.3-beta04 (10203204) |
| **release candidate** | **Hardening.** Final testing for an app release that we believe is ready to go live. The focus here is regression testing to ensure that new changes have not introduced instability in areas that were previously working.  | Stable: Hunt for bugs | External testers | 4XX | 1.2.3-rc04 (10203404) |
| **production** | **Delivery.** Deliver new features to end users. Any bugs found here need to be prioritized. Some will require immediate attention but most can be worked into a future release. | Stable: Prioritize bugs | Public | 8XX | 1.2.3 (10203800) |

`-zodl-slipstream` tags are not a build type in this ladder; they are the
same code as their `X.Y.Z` twin plus the engine flip, and inherit that
release's stability.

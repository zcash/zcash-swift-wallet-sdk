# ZODL Slipstream — Licensing Notice

The `ZODLSlipstream` product of this package, and the
`libzcashlc-zodl-slipstream.xcframework` binary artifact it links, incorporate
the **ZODL Slipstream** sync engine (the [`zodl-slipstream`
crate](https://crates.io/crates/zodl-slipstream), published by Znewco, Inc.
d/b/a Zcash Open Development Lab), which is licensed under the **GNU Affero
General Public License, version 3.0 only (AGPL-3.0-only)**.

This notice does not apply to the default `ZcashLightClientKit` product and its
`libzcashlc.xcframework` artifact, which contain **no** ZODL Slipstream code
and are distributed, together with all Swift sources in this repository, under
the MIT license (see the repository's `LICENSE` file).

## What using the ZODL Slipstream variant means for your app

- The combined binary your app links is a work incorporating AGPL-3.0-only
  code. Distributing it means your distribution must comply with the AGPL —
  including the obligation to offer the complete corresponding source of the
  work under the AGPL — unless you hold a commercial license from Znewco, Inc.
- **Apple App Store:** Znewco's
  [`LICENSE-EXCEPTIONS.md`](https://github.com/zodl-inc/slipstream/blob/main/LICENSE-EXCEPTIONS.md)
  grants an AGPL §7 additional permission for App Store distribution **to
  Znewco only**, and states that *no* such permission is granted to any other
  party. AGPL obligations are widely considered incompatible with App Store
  distribution terms. In practice, a third-party app shipping this variant
  through the App Store needs a **commercial license**.
- **Commercial licensing:** contact **licensing@zodl.com** (see
  [`COMMERCIAL-LICENSE.md`](https://github.com/zodl-inc/slipstream/blob/main/COMMERCIAL-LICENSE.md)).
- **Trademarks/naming:** redistribution is subject to the naming and trademark
  conditions in `LICENSE-EXCEPTIONS.md`. The product name "ZODL Slipstream"
  used by this package follows those attribution-naming conditions.

## How to stay AGPL-free

Depend on a plain `X.Y.Z` release tag (the default) and use the
`ZcashLightClientKit` product with `SDKSynchronizer`. Classic Spend-before-Sync
scan ordering is part of the default product; only the accelerated Rust engine
(`SlipstreamSynchronizer`) is AGPL-licensed. The ZODL Slipstream variant is only
ever selected by explicitly pinning an `X.Y.Z-zodl-slipstream` tag.

The full AGPL-3.0 text is available at
<https://www.gnu.org/licenses/agpl-3.0.txt> and in the
[`LICENSE`](https://github.com/zodl-inc/slipstream/blob/main/LICENSE) file of
the `zodl-slipstream` crate.

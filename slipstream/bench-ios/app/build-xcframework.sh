#!/bin/sh
# Build the bench probe staticlib for device + simulator and bundle an
# XCFramework (the libzcashlc shape). Same recipe as the spike's ios-probe.
set -eu
cd "$(dirname "$0")"
ROOT="$(cd ../../.. && pwd)"
MANIFEST="$ROOT/Cargo.toml"

echo "→ building slipstream-bench-probe for device (arm64) + simulator (arm64)…"
cargo build --manifest-path "$MANIFEST" -p slipstream-bench-probe --release --target aarch64-apple-ios
cargo build --manifest-path "$MANIFEST" -p slipstream-bench-probe --release --target aarch64-apple-ios-sim

echo "→ assembling SlipstreamBench.xcframework…"
rm -rf SlipstreamBench.xcframework
xcodebuild -create-xcframework \
  -library "$ROOT/target/aarch64-apple-ios/release/libslipstream_bench_probe.a"     -headers ../probe/include \
  -library "$ROOT/target/aarch64-apple-ios-sim/release/libslipstream_bench_probe.a" -headers ../probe/include \
  -output SlipstreamBench.xcframework

echo "✓ SlipstreamBench.xcframework"

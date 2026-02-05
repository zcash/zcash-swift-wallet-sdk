# Local FFI Development

This guide explains how to work on the Rust FFI code alongside the Swift SDK.

## Overview

The SDK uses a pre-built XCFramework (`libzcashlc`) for the Rust FFI layer. For most SDK development, you don't need to rebuild the FFI - SPM automatically downloads the pre-built binary from GitHub Releases.

However, if you need to modify the Rust code in `rust/`, you'll need to set up local FFI development.

## Prerequisites

1. **Rust toolchain** - Install via [rustup](https://rustup.rs/):
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. **Apple platform targets** - Install the required Rust targets:
   ```bash
   rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
   rustup target add aarch64-apple-darwin x86_64-apple-darwin
   ```

## Quick Start

### One-Time Setup

```bash
# Clone the repository
git clone https://github.com/zcash/zcash-swift-wallet-sdk
cd zcash-swift-wallet-sdk

# Initialize local FFI (builds from source)
./Scripts/init-local-ffi.sh

# Or use --cached to download pre-built release (faster, but may not match local source)
./Scripts/init-local-ffi.sh --cached
```

Then add the local package to Xcode:
1. Open your Xcode project/workspace
2. File → Add Package Dependencies → Add Local...
3. Select the `LocalPackages` directory

Xcode will automatically prefer the local package over the remote binary target.

### Development Loop

```bash
# 1. Edit Rust code
vim rust/src/lib.rs

# 2. Fast incremental rebuild (seconds, not minutes!)
./Scripts/rebuild-local-ffi.sh              # iOS Simulator (default)
./Scripts/rebuild-local-ffi.sh ios-device   # iOS Device
./Scripts/rebuild-local-ffi.sh macos        # macOS

# 3. Build/test in Xcode (changes picked up automatically)
#    Or clean build folder if needed: Cmd+Shift+K
```

## Scripts Reference

### `init-local-ffi.sh`

One-time setup that creates the local development environment.

```bash
./Scripts/init-local-ffi.sh          # Build from source (recommended)
./Scripts/init-local-ffi.sh --cached # Download pre-built release
```

This script:
- Builds the full XCFramework (all 5 architectures) or downloads a pre-built one
- Creates `LocalPackages/` with an SPM wrapper package
- The local package shadows the binary target in Package.swift

### `rebuild-local-ffi.sh`

Fast incremental rebuild for the current development target.

```bash
./Scripts/rebuild-local-ffi.sh [target]
```

Targets:
- `ios-sim` (default) - iOS Simulator, auto-detects arm64 vs x86_64
- `ios-device` - iOS Device (arm64)
- `macos` - macOS, auto-detects arm64 vs x86_64

**Why it's fast:** Only builds ONE architecture, and Cargo's incremental compilation means small changes rebuild in seconds.

**Note:** This creates a single-architecture build. Run `init-local-ffi.sh` before submitting PRs to verify all architectures compile.

## Architecture Details

### XCFramework Structure

The XCFramework contains three platform slices:
- `ios-arm64` - iOS devices
- `ios-arm64_x86_64-simulator` - iOS Simulator (universal)
- `macos-arm64_x86_64` - macOS (universal)

### Build Targets

| Development Target | Rust Target | XCFramework Slice |
|-------------------|-------------|-------------------|
| iOS Simulator (Apple Silicon) | `aarch64-apple-ios-sim` | `ios-arm64_x86_64-simulator` |
| iOS Simulator (Intel) | `x86_64-apple-ios` | `ios-arm64_x86_64-simulator` |
| iOS Device | `aarch64-apple-ios` | `ios-arm64` |
| macOS (Apple Silicon) | `aarch64-apple-darwin` | `macos-arm64_x86_64` |
| macOS (Intel) | `x86_64-apple-darwin` | `macos-arm64_x86_64` |

### Local Package Override

When you add `LocalPackages` as a local package in Xcode, it provides a package named `libzcashlc` with the same product name as the binary target in Package.swift. SPM automatically prefers local packages over remote dependencies, so your local build is used instead of the GitHub Releases binary.

## Troubleshooting

### Xcode doesn't pick up FFI changes

1. Clean the build folder: Cmd+Shift+K
2. If that doesn't work, close Xcode and delete DerivedData:
   ```bash
   rm -rf ~/Library/Developer/Xcode/DerivedData
   ```

### Build fails with missing target

Ensure all Rust targets are installed:
```bash
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
rustup target add aarch64-apple-darwin x86_64-apple-darwin
```

### Header changes not reflected

The headers are regenerated during cargo build. If you see stale headers:
```bash
rm -rf target/Headers
./Scripts/rebuild-local-ffi.sh
```

## Full Rebuild

Before submitting a PR that modifies Rust code:

```bash
# Full rebuild to verify all architectures compile
./Scripts/init-local-ffi.sh

# Run tests
swift test
```

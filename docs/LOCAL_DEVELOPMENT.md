# Local FFI Development

This guide explains how to work on the Rust FFI code alongside the Swift SDK.

## Overview

The SDK uses a pre-built XCFramework (`libzcashlc`) for the Rust FFI layer. For most SDK development, you don't need to rebuild the FFI — SPM automatically downloads the pre-built binary from GitHub Releases.

However, if you need to modify the Rust code in `rust/`, you'll need to set up local FFI development.

## How It Works

`Package.swift` automatically detects the presence of `LocalPackages/Package.swift` (created by the init script). When it exists, the SDK builds against your locally-built FFI instead of downloading the release binary. When it doesn't exist, the release binary is used as usual.

This means switching modes is as simple as:
- **Enable local FFI:** `./Scripts/init-local-ffi.sh`
- **Disable local FFI:** `rm -rf LocalPackages/` (or `./Scripts/reset-local-ffi.sh`)

No manual `Package.swift` edits are needed.

## Prerequisites

1. **Rust toolchain** — Install via [rustup](https://rustup.rs/):
   ```bash
   curl --proto '=https' --tlsv1.3 -sSf https://sh.rustup.rs | sh
   ```

2. **Apple platform targets** — Install the required Rust targets:
   ```bash
   rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
   rustup target add aarch64-apple-darwin x86_64-apple-darwin
   ```

## Quick Start

### One-Time Setup

You **must** run `init-local-ffi.sh` before opening the project in Xcode. Without it, SPM will attempt to download the release binary, which may not exist for development branches.

```bash
# Clone the repository
git clone https://github.com/zcash/zcash-swift-wallet-sdk
cd zcash-swift-wallet-sdk

# Initialize local FFI (builds from source)
./Scripts/init-local-ffi.sh
```

The `--cached` flag downloads a pre-built release instead of building from source. This only works when `Package.swift` points to a published release:

```bash
./Scripts/init-local-ffi.sh --cached
```

### Opening in Xcode

You can open the project two ways:

- **Workspace** (recommended for FFI development) — includes the FFIBuilder target that automatically rebuilds the FFI when you build in Xcode:
  ```bash
  open ZcashSDK.xcworkspace
  ```
- **Package directly** — simpler, but you'll need to run `rebuild-local-ffi.sh` manually after Rust changes:
  ```bash
  open Package.swift
  ```

If Xcode was already open before you ran `init-local-ffi.sh`, reset package caches: File > Packages > Reset Package Caches.

### Development Loop

```bash
# 1. Edit Rust code
vim rust/src/lib.rs

# 2. Fast incremental rebuild (seconds, not minutes!)
./Scripts/rebuild-local-ffi.sh              # iOS Simulator (default)
./Scripts/rebuild-local-ffi.sh ios-device   # iOS Device
./Scripts/rebuild-local-ffi.sh macos        # macOS

# 3. Build/test in Xcode
#    Clean build folder if Xcode doesn't pick up changes: Cmd+Shift+K
```

### Switching Back to Release Binary

```bash
./Scripts/reset-local-ffi.sh
```

If using Xcode, you may also need to reset package caches: File > Packages > Reset Package Caches.

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
- `Package.swift` automatically detects `LocalPackages/` and switches to local mode

### `rebuild-local-ffi.sh`

Fast incremental rebuild for the current development target. Requires `init-local-ffi.sh` to have been run first.

```bash
./Scripts/rebuild-local-ffi.sh [target]
```

Targets:
- `ios-sim` (default) — iOS Simulator, auto-detects arm64 vs x86_64
- `ios-device` — iOS Device (arm64)
- `macos` — macOS, auto-detects arm64 vs x86_64

**Why it's fast:** Only builds ONE architecture, and Cargo's incremental compilation means small changes rebuild in seconds.

**Note:** This creates a single-architecture build. Run `init-local-ffi.sh` before submitting PRs to verify all architectures compile.

### `reset-local-ffi.sh`

Removes `LocalPackages/` and switches back to the release binary.

```bash
./Scripts/reset-local-ffi.sh
```

## Architecture Details

### XCFramework Structure

The XCFramework contains three platform slices:
- `ios-arm64` — iOS devices
- `ios-arm64_x86_64-simulator` — iOS Simulator (universal)
- `macos-arm64_x86_64` — macOS (universal)

### Build Targets

| Development Target | Rust Target | XCFramework Slice |
|-------------------|-------------|-------------------|
| iOS Simulator (Apple Silicon) | `aarch64-apple-ios-sim` | `ios-arm64_x86_64-simulator` |
| iOS Simulator (Intel) | `x86_64-apple-ios` | `ios-arm64_x86_64-simulator` |
| iOS Device | `aarch64-apple-ios` | `ios-arm64` |
| macOS (Apple Silicon) | `aarch64-apple-darwin` | `macos-arm64_x86_64` |
| macOS (Intel) | `x86_64-apple-darwin` | `macos-arm64_x86_64` |

### Local Package Override

The `LocalPackages` directory contains a Swift package named `libzcashlc` with the same product name as the binary target in `Package.swift`. When `Package.swift` detects that `LocalPackages/Package.swift` exists, it adds `LocalPackages` as a path dependency and uses it instead of the `.binaryTarget` declaration. This switching is automatic — no manual edits to `Package.swift` are needed.

## Automatic FFI Rebuilds

The shared `ZcashLightClientKit` scheme in `ZcashSDK.xcworkspace` includes `FFIBuilder` as a build dependency. FFIBuilder runs `rebuild-local-ffi.sh` with the appropriate platform based on your selected destination, so Rust code is automatically recompiled when you build in Xcode.

**Note:** The FFIBuilder target requires `init-local-ffi.sh` to have been run first — it calls `rebuild-local-ffi.sh`, which expects `LocalPackages/` to exist.

| Approach | Best for |
|----------|----------|
| Manual script (`rebuild-local-ffi.sh`) | Occasional FFI changes, simple setup |
| FFIBuilder target in workspace | Frequent FFI changes, prefer staying in Xcode |

## Troubleshooting

### Xcode can't resolve packages / shows 404 error

This means `LocalPackages/` doesn't exist and SPM is trying to download the release binary. Run `./Scripts/init-local-ffi.sh` to set up local development, then reset package caches in Xcode: File > Packages > Reset Package Caches.

### Xcode doesn't pick up FFI changes

1. Clean the build folder: Cmd+Shift+K
2. If that doesn't work, reset package caches: File > Packages > Reset Package Caches
3. If that doesn't work, close Xcode and delete DerivedData:
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

### Xcode uses wrong FFI after switching modes

After running `init-local-ffi.sh` or `reset-local-ffi.sh`, Xcode may need to re-resolve packages:
1. File > Packages > Reset Package Caches
2. If that doesn't help, close and reopen the workspace

### `rustup: command not found` in Xcode build

The scripts source `~/.cargo/env` to find the Rust toolchain. If you installed Rust via a non-standard method (e.g., Homebrew, Nix), you may need to ensure `cargo` and `rustup` are on the default PATH or add the appropriate source/export to `~/.zprofile`.

## Full Rebuild

Before submitting a PR that modifies Rust code:

```bash
# Full rebuild to verify all architectures compile
./Scripts/init-local-ffi.sh

# Run tests
swift test
```

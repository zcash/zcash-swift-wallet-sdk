# Zcash Swift Wallet SDK Consolidation Plan

## Executive Summary

This document outlines a plan to merge the `zcash-light-client-ffi` repository into `zcash-swift-wallet-sdk`, addressing the current pain points while maintaining developer productivity.

### Current State

**zcash-swift-wallet-sdk:**
- Swift Package Manager project for iOS/macOS Zcash wallet
- Depends on `zcash-light-client-ffi` via SPM git reference (exact version 0.19.1)
- Uses FFI through direct C function calls via `import libzcashlc`

**zcash-light-client-ffi/canon:**
- Rust crate producing a static library with C bindings (cbindgen)
- Builds XCFramework for 5 architectures across 3 Apple platforms
- **Problem:** Commits large (~50-100MB) XCFramework binaries to git repository
- Build time: significant (5-10 minutes per architecture)

### Goals

1. **Consolidate repositories** - Move FFI source code into SDK repository
2. **Preserve developer experience** - Normal Swift development should not require FFI rebuilds
3. **Remove binaries from git** - Store release artifacts externally (GitHub Releases)
4. **Enable local development** - SDK developers can rebuild FFI when needed

---

## Proposed Architecture

### Repository Structure (Post-Merge)

```
zcash-swift-wallet-sdk/
├── Package.swift                     # SDK package (consumers reference this)
├── Package.resolved
├── Cargo.toml                        # Rust crate manifest (at root, parallel to Package.swift)
├── Cargo.lock
├── ZcashSDK.xcworkspace              # ← Developers open this for FFI work
│
├── Sources/
│   └── ZcashLightClientKit/          # Existing SDK source
│
├── Tests/                            # Existing tests
│
├── Example/                          # Existing example app
│
├── rust/                             # ← MIGRATED from zcash-light-client-ffi
│   ├── build.rs
│   ├── src/
│   │   ├── lib.rs
│   │   ├── ffi.rs
│   │   ├── derivation.rs
│   │   ├── tor.rs
│   │   └── ...
│   └── wrapper.h, wrapper.c
│
├── Scripts/
│   ├── build-xcframework.sh          # Full xcframework build
│   ├── prepare-release.sh            # Build FFI & upload draft release
│   ├── release.sh                    # Full automated release workflow
│   ├── init-local-ffi.sh             # One-time local dev setup
│   └── rebuild-local-ffi.sh          # Fast incremental rebuild (single arch)
│
├── BuildSupport/                     # All build-related files
│   ├── Makefile                      # Orchestrates FFI build
│   ├── module.modulemap              # Clang module definition
│   ├── Info.plist                    # Framework Info.plist template
│   ├── platform-Info.plist           # Platform-specific plist
│   └── FFIBuilder.xcodeproj          # Xcode project with Run Script build phase
│
├── .github/
│   └── workflows/
│       ├── swift.yml                 # Existing: SDK tests (uses pre-built FFI)
│       ├── build-ffi.yml             # NEW: Build & release xcframework
│       └── swiftlint.yml             # Existing
│
└── LocalPackages/                    # For local FFI development (gitignored)
    └── .gitkeep
```

### Key Design Decision: Binary Target with Local Override

The primary challenge is that Swift Package Manager requires either:
- A binary target (pre-built xcframework), OR
- Source compilation

We cannot have SPM conditionally choose between them at resolve time. The solution:
- **Production/Consumers:** Package.swift uses a binary target pointing to GitHub Releases
- **Local Development:** Developers add a local package override that shadows the binary target

---

## Implementation Strategy

### Prerequisites: Source Code Migration (Manual)

Before implementing this plan, the FFI source code must be migrated into the SDK repository. This will be done manually using `git filter-repo` and rebasing to preserve commit history.

**Source migration (performed manually, not part of this plan):**
1. Use `git filter-repo` to extract FFI history into SDK repo
2. Rebase to integrate histories cleanly
3. Result: `rust/` directory containing FFI source with full history

**Post-migration path mapping:**
| Original Location | New Location |
|-------------------|--------------|
| `zcash-light-client-ffi/canon/rust/Cargo.toml` | `zcash-swift-wallet-sdk/Cargo.toml` (root) |
| `zcash-light-client-ffi/canon/rust/Cargo.lock` | `zcash-swift-wallet-sdk/Cargo.lock` (root) |
| `zcash-light-client-ffi/canon/rust/` (other files) | `zcash-swift-wallet-sdk/rust/` |
| `zcash-light-client-ffi/canon/support/` | `zcash-swift-wallet-sdk/BuildSupport/` |
| `zcash-light-client-ffi/canon/Makefile` | `zcash-swift-wallet-sdk/BuildSupport/Makefile` |

### Phase 1: Update Build Configuration

After source migration, update paths in build files:

1. **Update Makefile paths** in `BuildSupport/Makefile`:
   - Reference `../Cargo.toml` for the manifest (now at root)
   - Reference `../rust/` for source files
2. **Update Cargo.toml** to point to source in `rust/` directory:
   - Set `build = "rust/build.rs"`
   - Ensure `[lib]` path points to `rust/src/lib.rs`
3. **Update build.rs** if it has any path dependencies (now at `rust/build.rs`)
4. **Remove the release copy step** from Makefile - it currently copies the final xcframework to `releases/XCFramework/` for committing to git. This is no longer needed since we're storing binaries in GitHub Releases instead. The Makefile should output to `BuildSupport/products/` and stop there.
5. **Verify build** - Ensure `make xcframework` outputs to `BuildSupport/products/`

**Artifact flow after migration:**
```
Makefile builds to:     BuildSupport/products/libzcashlc.xcframework
                                    │
            ┌───────────────────────┼───────────────────────┐
            │                       │                       │
            ▼                       ▼                       ▼
    CI uploads to           init-local-ffi.sh         rebuild-local-ffi.sh
    GitHub Releases         copies to                 (bypasses Makefile,
                            LocalPackages/            copies directly from
                                                      target/)
```

Note: Since `Cargo.toml` is at the repo root, the `target/` directory is also at the repo root.

### Phase 2: Configure GitHub Releases for Binary Distribution

**How it works:**
- CI builds xcframework on tagged releases
- Uploads xcframework.zip to GitHub Release assets
- Package.swift references the release URL with checksum

**Package.swift configuration:**
```swift
// Package.swift
import PackageDescription

let package = Package(
    name: "ZcashLightClientKit",
    platforms: [.iOS(.v13), .macOS(.v12)],
    products: [
        .library(name: "ZcashLightClientKit", targets: ["ZcashLightClientKit"])
    ],
    dependencies: [
        .package(url: "https://github.com/grpc/grpc-swift.git", exact: "1.24.2"),
        .package(url: "https://github.com/stephencelis/SQLite.swift.git", exact: "0.15.3"),
    ],
    targets: [
        // Binary target pointing to GitHub Release
        .binaryTarget(
            name: "libzcashlc",
            url: "https://github.com/zcash/zcash-swift-wallet-sdk/releases/download/2.5.0/libzcashlc.xcframework.zip",
            checksum: "abc123..." // SHA256 of the zip file
        ),
        .target(
            name: "ZcashLightClientKit",
            dependencies: [
                "libzcashlc",
                .product(name: "GRPC", package: "grpc-swift"),
                .product(name: "SQLite", package: "SQLite.swift"),
            ],
            path: "Sources/ZcashLightClientKit",
            // ... rest of configuration
        ),
        // ... test targets
    ]
)
```

**Advantages:**
- Standard SPM workflow for consumers
- No binary artifacts in git
- Automatic download on first build
- Checksum verification for security

**Disadvantages:**
- Must update Package.swift checksum for each FFI release
- Requires GitHub Release creation workflow

### Phase 3: CI/CD for FFI Builds

Create `.github/workflows/build-ffi.yml`:

```yaml
name: Build FFI XCFramework

on:
  # Manual trigger for preparing releases
  workflow_dispatch:
    inputs:
      version:
        description: 'SDK version (e.g., 2.5.0)'
        required: true

env:
  RUST_TOOLCHAIN: stable

jobs:
  build-xcframework:
    runs-on: macos-15
    steps:
      - uses: actions/checkout@v4

      - name: Select Xcode
        run: sudo xcode-select -s /Applications/Xcode_16.0.app

      - name: Setup Rust
        uses: dtolnay/rust-action@stable
        with:
          targets: |
            aarch64-apple-ios
            x86_64-apple-ios
            aarch64-apple-ios-sim
            x86_64-apple-darwin
            aarch64-apple-darwin

      - name: Cache Cargo
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/registry
            ~/.cargo/git
            target
          key: ${{ runner.os }}-cargo-${{ hashFiles('Cargo.lock') }}

      - name: Build XCFramework
        run: |
          cd BuildSupport
          make clean
          make xcframework

      - name: Create Release Archive
        run: |
          cd BuildSupport/products
          zip -r libzcashlc.xcframework.zip libzcashlc.xcframework
          shasum -a 256 libzcashlc.xcframework.zip > checksum.txt
          echo "CHECKSUM=$(cat checksum.txt | awk '{print $1}')" >> $GITHUB_ENV

      - name: Create Draft Release
        uses: softprops/action-gh-release@v1
        with:
          tag_name: ${{ github.event.inputs.version }}
          name: ${{ github.event.inputs.version }}
          draft: true
          files: |
            BuildSupport/products/libzcashlc.xcframework.zip
            BuildSupport/products/checksum.txt
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Output Package.swift Update
        run: |
          echo ""
          echo "========================================"
          echo "Update Package.swift with:"
          echo "========================================"
          echo ""
          echo "url: \"https://github.com/zcash/zcash-swift-wallet-sdk/releases/download/${{ github.event.inputs.version }}/libzcashlc.xcframework.zip\","
          echo "checksum: \"${{ env.CHECKSUM }}\""
          echo ""
          echo "Then commit, tag ${{ github.event.inputs.version }}, and publish the draft release."
```

**Note:** This workflow creates a **draft** release. The release must be published manually after updating Package.swift and tagging the SDK. This ensures the tag and Package.swift are consistent before the release goes live.

### Phase 4: Local Development Workflow

For SDK developers who need to modify the Rust FFI, we provide two scripts:
1. **`init-local-ffi.sh`** - One-time setup (builds full xcframework from source, or use `--cached` to download pre-built)
2. **`rebuild-local-ffi.sh`** - Fast incremental rebuild (single architecture only)

The key optimization: **during development, you only need to build for the architecture you're testing on**. Cargo's incremental compilation means small Rust changes rebuild in seconds, not minutes.

#### Architecture Selection for Local Development

| Development Target | Architecture | Cargo Target |
|-------------------|--------------|--------------|
| iOS Simulator (Apple Silicon Mac) | arm64 | `aarch64-apple-ios-sim` |
| iOS Simulator (Intel Mac) | x86_64 | `x86_64-apple-ios` |
| iOS Device | arm64 | `aarch64-apple-ios` |
| macOS (Apple Silicon) | arm64 | `aarch64-apple-darwin` |
| macOS (Intel) | x86_64 | `x86_64-apple-darwin` |

#### Script: `Scripts/init-local-ffi.sh`

One-time setup that creates the xcframework structure. By default, builds from source to ensure the xcframework matches your local code. Use `--cached` to download a pre-built release as a starting point (faster initial setup, but may not match local source).

```bash
#!/bin/bash
# Initialize local FFI development environment
# Usage: ./Scripts/init-local-ffi.sh [--cached]
#   --cached   Download pre-built release instead of building from source

set -e
cd "$(dirname "$0")/.."

USE_CACHED=false
if [[ "$1" == "--cached" ]]; then
    USE_CACHED=true
fi

XCFRAMEWORK_DIR="LocalPackages/libzcashlc.xcframework"

if [[ "$USE_CACHED" == "true" ]]; then
    echo "Downloading pre-built xcframework..."
    # Extract the version from the download URL in Package.swift
    SDK_VERSION=$(grep -oE 'releases/download/[0-9]+\.[0-9]+\.[0-9]+' Package.swift | head -1 | sed 's|releases/download/||')
    if [[ -z "$SDK_VERSION" ]]; then
        echo "Error: Could not determine SDK version from Package.swift"
        exit 1
    fi
    DOWNLOAD_URL="https://github.com/zcash/zcash-swift-wallet-sdk/releases/download/${SDK_VERSION}/libzcashlc.xcframework.zip"

    mkdir -p LocalPackages
    curl -L "$DOWNLOAD_URL" -o LocalPackages/libzcashlc.xcframework.zip
    unzip -o LocalPackages/libzcashlc.xcframework.zip -d LocalPackages/
    rm LocalPackages/libzcashlc.xcframework.zip
    echo ""
    echo "Note: Downloaded pre-built xcframework may not match your local source."
    echo "      Run './Scripts/rebuild-local-ffi.sh' to rebuild for your target platform."
else
    echo "Building full xcframework from source (this takes a while)..."
    cd BuildSupport
    make xcframework
    cd ..
    mkdir -p LocalPackages
    cp -R BuildSupport/products/libzcashlc.xcframework "$XCFRAMEWORK_DIR"
fi

# Create local SPM package wrapper
cat > LocalPackages/Package.swift << 'EOF'
// swift-tools-version:5.6
import PackageDescription

let package = Package(
    name: "libzcashlc",
    products: [
        .library(name: "libzcashlc", targets: ["libzcashlc"])
    ],
    targets: [
        .binaryTarget(
            name: "libzcashlc",
            path: "libzcashlc.xcframework"
        )
    ]
)
EOF

echo ""
echo "Local FFI initialized at LocalPackages/"
echo ""
echo "Next steps:"
echo "  1. In Xcode: File → Add Package Dependencies → Add Local..."
echo "     Select: $(pwd)/LocalPackages"
echo "  2. After making Rust changes, run: ./Scripts/rebuild-local-ffi.sh"
```

#### Script: `Scripts/rebuild-local-ffi.sh`

Fast incremental rebuild for the current development target. Only builds ONE architecture.

```bash
#!/bin/bash
# Fast incremental FFI rebuild for local development
# Usage: ./Scripts/rebuild-local-ffi.sh [target]
#
# Targets:
#   ios-sim     iOS Simulator (default, detects arm64 vs x86_64)
#   ios-device  iOS Device (arm64)
#   macos       macOS (detects arm64 vs x86_64)
#
# Examples:
#   ./Scripts/rebuild-local-ffi.sh              # iOS Simulator (auto-detect arch)
#   ./Scripts/rebuild-local-ffi.sh ios-device   # iOS Device
#   ./Scripts/rebuild-local-ffi.sh macos        # macOS

set -e
cd "$(dirname "$0")/.."

TARGET="${1:-ios-sim}"
XCFRAMEWORK_DIR="LocalPackages/libzcashlc.xcframework"

# Check if initialized
if [[ ! -d "$XCFRAMEWORK_DIR" ]]; then
    echo "Error: Local FFI not initialized. Run ./Scripts/init-local-ffi.sh first"
    exit 1
fi

# Detect host architecture
HOST_ARCH=$(uname -m)
if [[ "$HOST_ARCH" == "arm64" ]]; then
    IS_APPLE_SILICON=true
else
    IS_APPLE_SILICON=false
fi

# Map target to Rust triple and xcframework slice
case "$TARGET" in
    ios-sim|ios-simulator)
        if [[ "$IS_APPLE_SILICON" == "true" ]]; then
            RUST_TARGET="aarch64-apple-ios-sim"
            XCFRAMEWORK_SLICE="ios-arm64_x86_64-simulator"
        else
            RUST_TARGET="x86_64-apple-ios"
            XCFRAMEWORK_SLICE="ios-arm64_x86_64-simulator"
        fi
        ;;
    ios-device|ios)
        RUST_TARGET="aarch64-apple-ios"
        XCFRAMEWORK_SLICE="ios-arm64"
        ;;
    macos|mac)
        if [[ "$IS_APPLE_SILICON" == "true" ]]; then
            RUST_TARGET="aarch64-apple-darwin"
        else
            RUST_TARGET="x86_64-apple-darwin"
        fi
        XCFRAMEWORK_SLICE="macos-arm64_x86_64"
        ;;
    *)
        echo "Unknown target: $TARGET"
        echo "Valid targets: ios-sim, ios-device, macos"
        exit 1
        ;;
esac

echo "Building for $TARGET ($RUST_TARGET)..."
echo ""

# Ensure Rust target is installed
rustup target add "$RUST_TARGET" 2>/dev/null || true

# Incremental cargo build (fast for small changes!)
# Cargo.toml is at the repo root, so we run cargo from there
cargo build --target "$RUST_TARGET" --release

# Path to built static library (target/ is at repo root)
BUILT_LIB="target/$RUST_TARGET/release/libzcashlc.a"

# Path to framework binary within xcframework
FRAMEWORK_DIR="$XCFRAMEWORK_DIR/$XCFRAMEWORK_SLICE/libzcashlc.framework"
FRAMEWORK_BINARY="$FRAMEWORK_DIR/libzcashlc"

echo "Copying built library to xcframework..."

# Copy the static library to the framework
# Note: For universal slices, we replace with single-arch (fine for local dev)
cp "$BUILT_LIB" "$FRAMEWORK_BINARY"

# Regenerate headers if build.rs produced new ones
if [[ -f "target/Headers/zcashlc.h" ]]; then
    cp "target/Headers/zcashlc.h" "$FRAMEWORK_DIR/Headers/"
fi

echo ""
echo "✓ Rebuilt $TARGET in $XCFRAMEWORK_DIR"
echo ""
echo "Note: This is a single-architecture build for local development only."
echo "      The xcframework now contains only $RUST_TARGET for the $XCFRAMEWORK_SLICE slice."
echo "      Run 'init-local-ffi.sh' to rebuild all architectures."
echo ""
echo "Xcode should automatically pick up the changes. If not, clean build folder (Cmd+Shift+K)."
```

#### Understanding the Fast Rebuild

The `rebuild-local-ffi.sh` script is fast because:

1. **Single architecture**: Instead of 5 targets, we build only 1
2. **Incremental compilation**: Cargo only recompiles changed code
3. **No lipo step**: We skip creating universal binaries
4. **Direct copy**: We copy the `.a` file directly into the existing xcframework

**Typical rebuild times:**
- Full xcframework (5 architectures): 25-50 minutes
- Single architecture (first build): 5-10 minutes
- Single architecture (incremental): 5-30 seconds

#### Xcode Integration

**Local Package Override**

1. Run `./Scripts/init-local-ffi.sh` once
2. In Xcode: File → Add Package Dependencies → Add Local...
3. Select the `LocalPackages` directory
4. Xcode will prefer the local package over the remote binary target

**Why this works:** When you add a local package that provides the same product name (`libzcashlc`) as a remote dependency, Xcode/SPM automatically uses the local version. This is a built-in SPM feature for development workflows.

#### Triggering FFI Rebuilds

The `rebuild-local-ffi.sh` script is the common foundation for all rebuild approaches. Developers choose their preferred trigger:

**Option 1: Manual (Simplest)**
```bash
# After editing rust/src/*.rs
./Scripts/rebuild-local-ffi.sh
# Xcode picks up changes automatically (or Cmd+Shift+K to clean)
```

**Option 2: File Watcher (Automatic, Terminal-Based)**
```bash
# Install once: cargo install cargo-watch
# Run from repo root in a terminal, leave it running during development:
cargo watch -w rust -s './Scripts/rebuild-local-ffi.sh'
```

**Option 3: Development Workspace (Automatic, Xcode-Integrated)**

For developers who want Xcode to automatically rebuild the FFI, we provide a development workspace:

```
zcash-swift-wallet-sdk/
├── Package.swift                    # SDK package (consumers use this)
├── ZcashSDK.xcworkspace             # ← Developers open this
├── BuildSupport/
│   └── FFIBuilder.xcodeproj         # Has Run Script build phase
├── rust/
├── Sources/
└── ...
```

The workspace includes:
- The SDK package (for editing Swift code)
- `FFIBuilder.xcodeproj` with a target whose build phase runs `rebuild-local-ffi.sh`

**Important:** Opening the root folder or `Package.swift` directly opens the package without build phases. Developers must explicitly open `ZcashSDK.xcworkspace` to get automatic FFI rebuilds.

All three options invoke the same `rebuild-local-ffi.sh` script - they're just different triggers. Choose based on preference:

| Approach | Best for |
|----------|----------|
| Manual script | Occasional FFI changes, simple setup |
| cargo-watch | Focused FFI development sessions |
| Development workspace | Developers who prefer staying in Xcode |

#### Development Workflow Summary

```
┌─────────────────────────────────────────────────────────────────┐
│                    FFI Development Workflow                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ONE TIME:                                                       │
│    ./Scripts/init-local-ffi.sh                                  │
│    Add LocalPackages to Xcode as local package                  │
│                                                                  │
│  EDIT-BUILD-TEST LOOP:                                          │
│    1. Edit rust/src/*.rs                                        │
│    2. ./Scripts/rebuild-local-ffi.sh      ← Fast! (seconds)    │
│    3. Build/test in Xcode                                       │
│    4. Repeat                                                    │
│                                                                  │
│  BEFORE PR:                                                      │
│    ./Scripts/init-local-ffi.sh            ← Full rebuild       │
│    Run tests on all platforms                                   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Phase 5: Package.swift Configuration

The SDK's `Package.swift` should use a straightforward binary target pointing to GitHub Releases:

```swift
// Package.swift
import PackageDescription

let package = Package(
    name: "ZcashLightClientKit",
    platforms: [.iOS(.v13), .macOS(.v12)],
    products: [
        .library(name: "ZcashLightClientKit", targets: ["ZcashLightClientKit"])
    ],
    dependencies: [
        .package(url: "https://github.com/grpc/grpc-swift.git", exact: "1.24.2"),
        .package(url: "https://github.com/stephencelis/SQLite.swift.git", exact: "0.15.3"),
    ],
    targets: [
        .binaryTarget(
            name: "libzcashlc",
            url: "https://github.com/zcash/zcash-swift-wallet-sdk/releases/download/2.5.0/libzcashlc.xcframework.zip",
            checksum: "abc123def456..." // SHA256 of zip file
        ),
        .target(
            name: "ZcashLightClientKit",
            dependencies: [
                "libzcashlc",
                .product(name: "GRPC", package: "grpc-swift"),
                .product(name: "SQLite", package: "SQLite.swift"),
            ],
            path: "Sources/ZcashLightClientKit"
        ),
        // ... test targets
    ]
)
```

**Local development override:** Developers use Xcode's local package feature (described in Phase 4) rather than modifying Package.swift. This keeps the manifest clean and avoids accidental commits of local paths.

**Why not environment variables?** SPM evaluates `Package.swift` at resolution time, before any build-time environment is set. Environment-based conditionals in Package.swift don't work reliably with Xcode, though they can work for pure command-line `swift build` workflows.

---

## Developer Workflows

### Workflow 1: App Developer (Consumer)

**Goal:** Use the SDK without building FFI

```bash
# In your app's Package.swift or Xcode project:
dependencies: [
    .package(url: "https://github.com/zcash/zcash-swift-wallet-sdk",
             from: "2.5.0")
]

# SPM automatically downloads the pre-built xcframework from GitHub Releases
# No Rust toolchain required
```

### Workflow 2: SDK Developer (No FFI Changes)

**Goal:** Work on Swift SDK code without rebuilding FFI

```bash
git clone https://github.com/zcash/zcash-swift-wallet-sdk
cd zcash-swift-wallet-sdk

# SPM will fetch pre-built FFI from GitHub Releases
# Open in Xcode and develop normally
open Package.swift
```

### Workflow 3: SDK Developer (With FFI Changes)

**Goal:** Modify Rust FFI and test with SDK

```bash
git clone https://github.com/zcash/zcash-swift-wallet-sdk
cd zcash-swift-wallet-sdk

# Install Rust (if not present)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# ONE-TIME: Initialize local FFI (builds from source, or use --cached to download)
./Scripts/init-local-ffi.sh

# Add LocalPackages to Xcode as a local package dependency
# (File → Add Package Dependencies → Add Local → select LocalPackages/)

# --- Development Loop ---

# 1. Make changes to rust/src/*.rs
vim rust/src/lib.rs

# 2. Fast incremental rebuild (seconds, not minutes!)
./Scripts/rebuild-local-ffi.sh           # iOS Simulator (default)
./Scripts/rebuild-local-ffi.sh ios-device  # For device testing
./Scripts/rebuild-local-ffi.sh macos       # For macOS testing

# 3. Build/test in Xcode (changes picked up automatically)
#    Or: swift test

# 4. Repeat steps 1-3

# --- Before Submitting PR ---

# Full rebuild to verify all architectures compile
./Scripts/init-local-ffi.sh

# Run full test suite
swift test
```

### Workflow 4: Releasing a New SDK Version

**Prerequisites:**
- GPG key configured for signing tags (`git config --global user.signingkey <key-id>`)
- `gh` CLI installed and authenticated
- Clean working directory on `main` branch

**Automated release (normal case):**
```bash
# Single command does everything
./Scripts/release.sh 2.5.0
```

**Manual release (security fixes or more control):**
```bash
# 1. Ensure all changes are committed and tested
git status  # Should be clean
swift test  # All tests pass

# 2. Build FFI and upload artifacts (creates draft GitHub release)
./Scripts/prepare-release.sh 2.5.0

# 3. Script outputs the checksum - update Package.swift:
#    url: ".../releases/download/2.5.0/libzcashlc.xcframework.zip"
#    checksum: "<checksum-from-script>"

# 4. Commit the Package.swift update
git add Package.swift
git commit -m "Prepare release 2.5.0"

# 5. Create signed tag
git tag -s 2.5.0 -m "Release 2.5.0"

# 6. Push commit and tag
git push origin main 2.5.0

# 7. Publish the draft release on GitHub
#    (Script outputs the URL to the draft release)
```

#### Script: `Scripts/prepare-release.sh`

Builds FFI artifacts and uploads them as a draft GitHub release.

```bash
#!/bin/bash
# Prepare FFI artifacts for an SDK release
# Usage: ./Scripts/prepare-release.sh <version>
#
# This script:
#   1. Builds the full xcframework (all architectures)
#   2. Creates a zip archive with checksum
#   3. Uploads to GitHub as a DRAFT release
#   4. Outputs the values needed for Package.swift
#
# After running this script:
#   1. Update Package.swift with the URL and checksum
#   2. Commit the Package.swift change
#   3. Create a signed tag for the SDK release
#   4. Publish the draft release on GitHub
#
# Prerequisites:
#   - gh CLI installed and authenticated (https://cli.github.com/)
#   - Rust toolchain with all Apple targets
#   - GPG key configured for signing tags

set -e
cd "$(dirname "$0")/.."

if [[ -z "$1" ]]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 2.5.0"
    exit 1
fi

VERSION="$1"
REPO="zcash/zcash-swift-wallet-sdk"
PRODUCTS_DIR="BuildSupport/products"
ZIP_FILE="libzcashlc.xcframework.zip"

echo "=== Preparing release ${VERSION} ==="
echo ""

# Check for uncommitted changes
if [[ -n $(git status --porcelain) ]]; then
    echo "Warning: You have uncommitted changes."
    read -p "Continue anyway? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Build full xcframework
echo "=== Building xcframework (this takes a while) ==="
cd BuildSupport
make clean
make xcframework
cd ..

# Create release archive
echo ""
echo "=== Creating release archive ==="
cd "$PRODUCTS_DIR"
rm -f "$ZIP_FILE" checksum.txt
zip -r "$ZIP_FILE" libzcashlc.xcframework
CHECKSUM=$(shasum -a 256 "$ZIP_FILE" | awk '{print $1}')
echo "$CHECKSUM  $ZIP_FILE" > checksum.txt
cd ../..

# Upload to GitHub as draft release
echo ""
echo "=== Uploading to GitHub (draft release) ==="

if gh release view "$VERSION" --repo "$REPO" &>/dev/null; then
    echo "Release $VERSION already exists. Updating assets..."
    gh release upload "$VERSION" \
        "$PRODUCTS_DIR/$ZIP_FILE" \
        "$PRODUCTS_DIR/checksum.txt" \
        --repo "$REPO" \
        --clobber
else
    gh release create "$VERSION" \
        "$PRODUCTS_DIR/$ZIP_FILE" \
        "$PRODUCTS_DIR/checksum.txt" \
        --repo "$REPO" \
        --title "$VERSION" \
        --notes "Zcash Light Client SDK ${VERSION}" \
        --draft
fi

RELEASE_URL="https://github.com/${REPO}/releases/tag/${VERSION}"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ZIP_FILE}"

echo ""
echo "=========================================="
echo "  Draft release created: ${RELEASE_URL}"
echo "=========================================="
echo ""
echo "Next steps:"
echo ""
echo "1. Update Package.swift with:"
echo ""
echo "   .binaryTarget("
echo "       name: \"libzcashlc\","
echo "       url: \"${DOWNLOAD_URL}\","
echo "       checksum: \"${CHECKSUM}\""
echo "   ),"
echo ""
echo "2. Commit the change:"
echo "   git add Package.swift"
echo "   git commit -m \"Prepare release ${VERSION}\""
echo ""
echo "3. Create signed tag:"
echo "   git tag -s ${VERSION} -m \"Release ${VERSION}\""
echo ""
echo "4. Push:"
echo "   git push origin main ${VERSION}"
echo ""
echo "5. Publish the draft release:"
echo "   ${RELEASE_URL}"
echo ""
```

#### Script: `Scripts/release.sh`

Performs the full automated release workflow: builds FFI, updates Package.swift, commits, tags, pushes, and publishes.

```bash
#!/bin/bash
# Full SDK release workflow
# Usage: ./Scripts/release.sh <version>
#
# This script performs the COMPLETE release process:
#   1. Verifies clean working directory
#   2. Builds the full xcframework
#   3. Uploads artifacts to GitHub (draft release)
#   4. Updates Package.swift with URL and checksum
#   5. Commits the Package.swift change
#   6. Creates a signed tag
#   7. Pushes to origin
#   8. Publishes the GitHub release
#
# Prerequisites:
#   - gh CLI installed and authenticated
#   - Rust toolchain with all Apple targets
#   - GPG key configured for signing tags
#   - Clean working directory (no uncommitted changes)
#
# For security releases where you need more control over timing,
# use prepare-release.sh instead and perform steps manually.

set -e
cd "$(dirname "$0")/.."

if [[ -z "$1" ]]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 2.5.0"
    exit 1
fi

VERSION="$1"
REPO="zcash/zcash-swift-wallet-sdk"
PRODUCTS_DIR="BuildSupport/products"
ZIP_FILE="libzcashlc.xcframework.zip"

echo "=== SDK Release ${VERSION} ==="
echo ""

# Verify clean working directory
if [[ -n $(git status --porcelain) ]]; then
    echo "Error: Working directory is not clean."
    echo "Please commit or stash your changes before releasing."
    git status --short
    exit 1
fi

# Verify we're on main branch
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [[ "$CURRENT_BRANCH" != "main" ]]; then
    echo "Warning: You are on branch '$CURRENT_BRANCH', not 'main'."
    read -p "Continue anyway? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check if tag already exists
if git rev-parse "$VERSION" >/dev/null 2>&1; then
    echo "Error: Tag $VERSION already exists."
    exit 1
fi

# Verify GPG signing is configured
if ! git config --get user.signingkey >/dev/null 2>&1; then
    echo "Error: No GPG signing key configured."
    echo "Run: git config --global user.signingkey <your-key-id>"
    exit 1
fi

echo "=== Step 1/8: Building xcframework ==="
cd BuildSupport
make clean
make xcframework
cd ..

echo ""
echo "=== Step 2/8: Creating release archive ==="
cd "$PRODUCTS_DIR"
rm -f "$ZIP_FILE" checksum.txt
zip -r "$ZIP_FILE" libzcashlc.xcframework
CHECKSUM=$(shasum -a 256 "$ZIP_FILE" | awk '{print $1}')
echo "$CHECKSUM  $ZIP_FILE" > checksum.txt
cd ../..

echo ""
echo "=== Step 3/8: Uploading to GitHub (draft) ==="
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ZIP_FILE}"

gh release create "$VERSION" \
    "$PRODUCTS_DIR/$ZIP_FILE" \
    "$PRODUCTS_DIR/checksum.txt" \
    --repo "$REPO" \
    --title "$VERSION" \
    --notes "Zcash Light Client SDK ${VERSION}" \
    --draft

echo ""
echo "=== Step 4/8: Updating Package.swift ==="

# Update the binaryTarget URL and checksum in Package.swift
# This uses sed to find and replace the url and checksum lines
sed -i.bak -E \
    -e "s|(url: \"https://github.com/${REPO}/releases/download/)[^\"]+(/libzcashlc.xcframework.zip\")|\1${VERSION}\2|" \
    -e "s|(checksum: \")[^\"]+(\")|\1${CHECKSUM}\2|" \
    Package.swift
rm -f Package.swift.bak

# Verify the update worked
if ! grep -q "download/${VERSION}/libzcashlc.xcframework.zip" Package.swift; then
    echo "Error: Failed to update Package.swift URL"
    git checkout Package.swift
    exit 1
fi

if ! grep -q "checksum: \"${CHECKSUM}\"" Package.swift; then
    echo "Error: Failed to update Package.swift checksum"
    git checkout Package.swift
    exit 1
fi

echo "Package.swift updated with:"
echo "  URL: ${DOWNLOAD_URL}"
echo "  Checksum: ${CHECKSUM}"

echo ""
echo "=== Step 5/8: Committing Package.swift ==="
git add Package.swift
git commit -m "Prepare release ${VERSION}"

echo ""
echo "=== Step 6/8: Creating signed tag ==="
git tag -s "$VERSION" -m "Release ${VERSION}"

echo ""
echo "=== Step 7/8: Pushing to origin ==="
git push origin "$CURRENT_BRANCH" "$VERSION"

echo ""
echo "=== Step 8/8: Publishing release ==="
gh release edit "$VERSION" --repo "$REPO" --draft=false

echo ""
echo "=========================================="
echo "  Release ${VERSION} complete!"
echo "=========================================="
echo ""
echo "  GitHub Release: https://github.com/${REPO}/releases/tag/${VERSION}"
echo "  Package.swift updated and pushed"
echo "  Signed tag ${VERSION} created and pushed"
echo ""
```

**When to use which script:**

| Script | Use case |
|--------|----------|
| `release.sh` | Normal releases - fully automated |
| `prepare-release.sh` | Security releases - manual control over when source is pushed |

---

## Migration Checklist

### Pre-Migration

- [ ] Ensure all pending PRs to zcash-light-client-ffi are merged
- [ ] Document current FFI version and its compatibility with SDK
- [ ] Notify SDK consumers of upcoming changes

### Migration Steps

- [ ] **Prerequisites: Source Migration (Manual)**
  - [ ] Use `git filter-repo` to migrate FFI source with history
  - [ ] Rebase to integrate histories
  - [ ] Verify `Cargo.toml` and `Cargo.lock` are at repository root
  - [ ] Verify `rust/` and `BuildSupport/` directories are in place

- [ ] **Phase 1: Update Build Configuration**
  - [ ] Update `BuildSupport/Makefile` to use `--manifest-path ../Cargo.toml`
  - [ ] Update `Cargo.toml` paths for new layout (build script, lib path)
  - [ ] Remove the `releases/XCFramework/` copy step from Makefile
  - [ ] Update `rust/build.rs` if needed
  - [ ] Verify `make xcframework` outputs to `BuildSupport/products/`

- [ ] **Phase 2: CI/CD Setup**
  - [ ] Create `build-ffi.yml` workflow
  - [ ] Test workflow with manual dispatch
  - [ ] Create initial release (e.g., `2.5.0`) with xcframework artifacts
  - [ ] Verify xcframework downloads correctly

- [ ] **Phase 3: Package.swift Update**
  - [ ] Update to use binary target with GitHub Release URL
  - [ ] Add checksum
  - [ ] Remove dependency on external FFI repository
  - [ ] Test SPM resolution

- [ ] **Phase 4: Developer Tooling**
  - [ ] Create `Scripts/init-local-ffi.sh` (one-time setup)
  - [ ] Create `Scripts/rebuild-local-ffi.sh` (fast incremental rebuild)
  - [ ] Create `Scripts/build-xcframework.sh` (full build, used by other scripts)
  - [ ] Create `Scripts/prepare-release.sh` (build + upload draft release)
  - [ ] Create `Scripts/release.sh` (full automated release workflow)
  - [ ] Create `BuildSupport/FFIBuilder.xcodeproj` (Run Script build phase)
  - [ ] Create `ZcashSDK.xcworkspace` (references package + FFIBuilder)
  - [ ] Write `docs/LOCAL_DEVELOPMENT.md`
  - [ ] Update README with new workflows

- [ ] **Phase 5: Cleanup**
  - [ ] Archive zcash-light-client-ffi repository
  - [ ] Update any documentation references
  - [ ] Announce migration to SDK consumers

---

## Versioning Strategy

### Unified SDK + FFI Versioning

SDK and FFI releases share the same version number:
- SDK release `2.5.0` uses FFI artifacts at `releases/download/2.5.0/libzcashlc.xcframework.zip`
- Single version to track, simpler for consumers

**Critical ordering requirement:** FFI artifacts must exist BEFORE the SDK tag is created, because `Package.swift` at that tag must reference a valid download URL.

```
┌─────────────────────────────────────────────────────────────────┐
│                     SDK Release Process                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. Build FFI artifacts                                         │
│     └─→ ./Scripts/prepare-release.sh 2.5.0                      │
│                                                                  │
│  2. Artifacts uploaded to GitHub (draft release)                │
│     └─→ releases/download/2.5.0/libzcashlc.xcframework.zip     │
│                                                                  │
│  3. Update Package.swift with URL + checksum                    │
│     └─→ Script outputs the values to use                        │
│                                                                  │
│  4. Commit Package.swift update                                 │
│     └─→ git commit -m "Prepare release 2.5.0"                   │
│                                                                  │
│  5. Create signed tag and push                                  │
│     └─→ git tag -s 2.5.0 -m "Release 2.5.0"                    │
│     └─→ git push origin main 2.5.0                              │
│                                                                  │
│  6. Publish the GitHub release (removes draft status)           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Security Release Workflow

For security-sensitive releases where you need to ship before revealing source:

1. **Fix vulnerability** in `rust/src/` (don't push yet)
2. **Build & upload FFI** - `./Scripts/prepare-release.sh 2.5.1`
3. **Update Package.swift** with new URL and checksum
4. **Commit locally** - `git commit -m "Prepare release 2.5.1"`
5. **Create signed tag** - `git tag -s 2.5.1 -m "Release 2.5.1"`
6. **Publish GitHub release** (binary now available to users)
7. **Push source changes** - `git push origin main 2.5.1`

Users can update to the fixed binary immediately. The source diff becomes visible only when you push in step 7.

---

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| GitHub Release asset download limits | High traffic could hit rate limits | Consider CDN mirror or GitHub LFS |
| Build time for FFI in CI | ~30-40 min per release | Aggressive caching, sccache |
| Breaking changes in Package.swift | Consumers must update | Semantic versioning, clear changelog |
| Checksum management | Manual process error-prone | CI outputs checksum, consider automation |
| Local dev setup complexity | Developer friction | Clear docs, helper scripts, fast incremental rebuilds |

---

## Future Considerations

### Swift Package Plugins (Swift 5.9+)

Once SPM build plugins mature, consider:
- Build plugin that compiles Rust source on-demand
- Would eliminate need for pre-built binaries
- Currently limited by sandbox restrictions

### GitHub Packages

Alternative to GitHub Releases:
- Better suited for package distribution
- Requires authentication for private repos
- Consider if release assets become problematic

### Binary Cache Service

For teams with heavy FFI development:
- Self-hosted cache (e.g., S3 + CloudFront)
- Faster downloads, no GitHub rate limits
- More operational overhead

---

## Questions for Stakeholder Review

1. **Release Automation:** How automated should the checksum update process be? Options:
   - Manual update after each FFI build (current plan)
   - Bot PR with updated checksum
   - CI fails if checksum mismatch, prompts update

2. **Local Development Priority:** How often do SDK developers modify FFI code? This affects how polished the local workflow needs to be.

3. **Archive Timeline:** When should zcash-light-client-ffi be archived? Immediately after migration, or keep for historical reference?

4. **Consumer Communication:** What's the communication plan for notifying current SDK users of the migration?

---

## Appendix: Current FFI Dependencies in SDK

Files that import `libzcashlc`:
- `Sources/ZcashLightClientKit/Rust/ZcashRustBackend.swift`
- `Sources/ZcashLightClientKit/Rust/ZcashKeyDerivationBackend.swift`
- `Sources/ZcashLightClientKit/Account/AccountMetadataKey.swift`
- `Sources/ZcashLightClientKit/Tor/TorClient.swift`

These files use 69 FFI functions for:
- Account management
- Address generation
- Balance queries
- Blockchain scanning
- Transaction building
- Tor integration
- Key derivation

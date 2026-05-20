#!/bin/bash
# Update the libzcashlc binaryTarget URL and checksum in Package.swift.
#
# Usage: ./Scripts/update-package-swift.sh <version> <checksum>

set -e
cd "$(dirname "$0")/.."

VERSION="$1"
CHECKSUM="$2"

if [[ -z "$VERSION" || -z "$CHECKSUM" ]]; then
    echo "Usage: $0 <version> <checksum>" >&2
    exit 1
fi

REPO="zcash/zcash-swift-wallet-sdk"

sed -i.bak -E \
    -e "s|(url: \"https://github.com/${REPO}/releases/download/)[^\"]+(/libzcashlc.xcframework.zip\")|\1${VERSION}\2|" \
    -e "s|(checksum: \")[^\"]+(\")|\1${CHECKSUM}\2|" \
    Package.swift
rm -f Package.swift.bak

if ! grep -q "download/${VERSION}/libzcashlc.xcframework.zip" Package.swift; then
    echo "Error: failed to update Package.swift URL" >&2
    exit 1
fi

if ! grep -q "checksum: \"${CHECKSUM}\"" Package.swift; then
    echo "Error: failed to update Package.swift checksum" >&2
    exit 1
fi

echo "Package.swift updated: ${VERSION} / ${CHECKSUM}"

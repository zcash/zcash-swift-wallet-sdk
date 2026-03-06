#!/bin/bash
# Remove local FFI development environment and switch back to release binary
# Usage: ./Scripts/reset-local-ffi.sh

set -e
cd "$(dirname "$0")/.."

if [[ ! -d "LocalPackages" ]]; then
    echo "LocalPackages/ does not exist. Already using the release binary."
    exit 0
fi

rm -rf LocalPackages/
echo "Removed LocalPackages/. Package.swift will now use the release binary."
echo ""
echo "If using Xcode, you may need to: File > Packages > Reset Package Caches"

#!/bin/bash
# Remove local FFI development environment and switch back to release binary
# Usage: ./Scripts/reset-local-ffi.sh

set -e
cd "$(dirname "$0")/.."

if [[ ! -d "LocalPackages" ]] && [[ ! -f .zodl-slipstream-variant ]]; then
    echo "LocalPackages/ does not exist. Already using the release binary."
    exit 0
fi

rm -rf LocalPackages/

# Clearing the marker is part of resetting, not an extra: it selects the TARGET
# GRAPH, so leaving it behind would make "switch back to the release binary" pick
# the ZODL Slipstream (AGPL) release rather than the clean one — the opposite of
# what this script promises.
if [[ -f .zodl-slipstream-variant ]]; then
    rm -f .zodl-slipstream-variant
    echo "Cleared .zodl-slipstream-variant: back to the MIT-clean target graph."
fi

# The marker is read while the manifest is evaluated, so both SwiftPM's
# content-keyed manifest cache and .build's already-resolved graph have to go;
# purge-cache alone leaves the previous variant's graph in place.
swift package purge-cache > /dev/null 2>&1 || true
swift package reset > /dev/null 2>&1 || true

echo "Removed LocalPackages/. Package.swift will now use the release binary."
echo ""
echo "If using Xcode, you must also: File > Packages > Reset Package Caches"
echo "(Xcode resolves packages into DerivedData, which SwiftPM's caches do not cover.)"

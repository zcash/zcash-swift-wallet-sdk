#!/bin/sh
# One command to a ready-to-open bench app (v0.4 P0, spec §3.4).
set -eu
cd "$(dirname "$0")/app"
./build-xcframework.sh
xcodegen generate
echo
echo "✓ ready:  open slipstream/bench-ios/app/SlipstreamBench.xcodeproj"
echo "  then: set your Team under Signing & Capabilities, pick the iPhone as the"
echo "  destination, Run, paste the reference UFVK + birthday, tap Run bench."

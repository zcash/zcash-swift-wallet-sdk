#!/bin/bash
# Update the vendored lightwallet-protocol subtree and regenerate the Swift
# protobuf/gRPC sources derived from it.
#
# Usage: ./Scripts/update-lightwallet-protocol.sh <ref>
#
#   <ref>  A tag (e.g. v0.5.0) or branch of https://github.com/zcash/lightwallet-protocol
#
# The proto definitions live in lightwallet-protocol/ as a git subtree; this
# script pulls the requested ref with `git subtree pull --squash` (recording
# the exact command in the merge commit message) and then regenerates
# Sources/ZcashLightClientKit/Modules/Service/GRPC/ProtoBuf/*.swift.
#
# Regeneration requires `protoc` on the PATH (provided by the nix dev shell:
# `nix develop`). The protoc-gen-swift and protoc-gen-grpc-swift plugins are
# built from the exact swift-protobuf / grpc-swift versions pinned in
# Package.resolved, so the generated code always matches the runtime
# libraries the SDK links against.
#
# The regenerated sources are left uncommitted for review; commit them
# (along with any SDK changes the new protocol version requires) as a
# follow-up to the subtree merge commit.

set -euo pipefail
cd "$(dirname "$0")/.."

REPO_URL="https://github.com/zcash/lightwallet-protocol.git"
PREFIX="lightwallet-protocol"
PROTO_DIR="$PREFIX/walletrpc"
OUT_DIR="Sources/ZcashLightClientKit/Modules/Service/GRPC/ProtoBuf"
PLUGIN_SCRATCH=".build/protoc-plugins"

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <ref>" >&2
    exit 1
fi
REF="$1"

if ! command -v protoc > /dev/null; then
    echo "Error: protoc not found on PATH. Run this script inside the nix dev shell (nix develop)." >&2
    exit 1
fi

if ! git diff-index --quiet HEAD; then
    echo "Error: the working tree has uncommitted changes; git subtree requires a clean tree." >&2
    exit 1
fi

SUBTREE_CMD="git subtree pull --prefix=$PREFIX $REPO_URL $REF --squash"
echo "==> $SUBTREE_CMD"
$SUBTREE_CMD -m "$(cat <<EOF
Update lightwallet-protocol subtree to $REF

This subtree merge was performed with:

    $SUBTREE_CMD
EOF
)"

echo "==> Building protoc plugins from the versions pinned in Package.resolved"
swift package resolve
swift build --package-path .build/checkouts/swift-protobuf --product protoc-gen-swift \
    -c release --scratch-path "$PLUGIN_SCRATCH/swift-protobuf"
swift build --package-path .build/checkouts/grpc-swift --product protoc-gen-grpc-swift \
    -c release --scratch-path "$PLUGIN_SCRATCH/grpc-swift"
PROTOC_GEN_SWIFT="$PLUGIN_SCRATCH/swift-protobuf/release/protoc-gen-swift"
PROTOC_GEN_GRPC_SWIFT="$PLUGIN_SCRATCH/grpc-swift/release/protoc-gen-grpc-swift"

echo "==> Regenerating Swift sources in $OUT_DIR"
# Visibility=Package: the ZODLSlipstream target (a separate module in this
# package) reaches generated types like TreeState and FfiProposal through
# `package`-visible SDK seams, so the generated declarations must be at least
# `package` themselves. No generated type is part of the SDK's public API.
protoc -I "$PROTO_DIR" \
    --plugin=protoc-gen-swift="$PROTOC_GEN_SWIFT" \
    --swift_out="$OUT_DIR" \
    --swift_opt=Visibility=Package \
    compact_formats.proto service.proto
protoc -I "$PROTO_DIR" \
    --plugin=protoc-gen-grpc-swift="$PROTOC_GEN_GRPC_SWIFT" \
    --grpc-swift_out="$OUT_DIR" \
    --grpc-swift_opt=Visibility=Package \
    service.proto

# proposal.proto is vendored from librustzcash (zcash_client_backend), not
# from lightwallet-protocol; regenerate it too so all generated sources come
# from the same plugin versions.
protoc -I "$OUT_DIR/proto" \
    --plugin=protoc-gen-swift="$PROTOC_GEN_SWIFT" \
    --swift_out="$OUT_DIR" \
    --swift_opt=Visibility=Package \
    proposal.proto

echo
echo "Done. Review the regenerated sources and commit them:"
git status --short "$OUT_DIR"

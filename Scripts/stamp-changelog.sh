#!/bin/bash
# Stamp the CHANGELOG: insert a dated, versioned release header just below
# the existing "# Unreleased" header. The Unreleased section is preserved
# (empty) so the next release can stamp from a known starting state.
#
# Usage: ./Scripts/stamp-changelog.sh <version>

set -e
cd "$(dirname "$0")/.."

VERSION="$1"

if [[ -z "$VERSION" ]]; then
    echo "Usage: $0 <version>" >&2
    exit 1
fi

if ! grep -q "^# Unreleased\$" CHANGELOG.md; then
    echo "Error: CHANGELOG.md has no '# Unreleased' header to stamp." >&2
    exit 1
fi

DATE=$(date -u +%Y-%m-%d)

# awk for portability — BSD/GNU sed disagree on how to insert literal
# newlines in a replacement; awk's print is consistent everywhere.
awk -v ver="$VERSION" -v date="$DATE" '
    /^# Unreleased$/ && !stamped {
        print
        print ""
        print "# " ver " - " date
        stamped = 1
        next
    }
    { print }
' CHANGELOG.md > CHANGELOG.md.tmp
mv CHANGELOG.md.tmp CHANGELOG.md

echo "CHANGELOG.md stamped: # ${VERSION} - ${DATE}"

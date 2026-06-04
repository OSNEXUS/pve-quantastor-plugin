#!/bin/bash
# Build the pve-storage-quantastor .deb package.
# Run from the repository root.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Ensure debhelper is available
if ! command -v dh >/dev/null 2>&1; then
    echo "ERROR: debhelper not installed. Run: apt install debhelper" >&2
    exit 1
fi

# Make maintainer scripts executable (debhelper requires this)
chmod 0755 debian/postinst debian/prerm

echo "Building package..."
dpkg-buildpackage -us -uc -b

echo ""
echo "Built packages:"
ls -1 ../*.deb 2>/dev/null || echo "(no .deb found in parent directory)"

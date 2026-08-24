#!/bin/bash
# tests/smoke/run-all.sh — runner for all smoke tests
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Pre-flight prereq detection.
# Smoke tests need a prepared rootfs at /var/cache/noid-smoke/rootfs-f44.
# Without it, every test exits 77 (skipped) and CI/local results look
# falsely successful. Detect missing prereqs upfront and tell the user
# how to fix it.
ROOTFS_DIR="${NOID_SMOKE_ROOTFS:-/var/cache/noid-smoke/rootfs-f44}"
ROOTFS_MANIFEST="${ROOTFS_DIR}/.noid-smoke-rootfs-manifest"
ROOTFS_RELEASEVER="${NOID_SMOKE_RELEASEVER:-44}"
PREP_SCRIPT="$SCRIPT_DIR/prep-rootfs.sh"

if [ ! -f "$ROOTFS_MANIFEST" ]; then
    echo "WARN: smoke-test rootfs not found at ${ROOTFS_DIR}" >&2
    echo "      All tests will SKIP (exit 77). To enable smoke testing, run:" >&2
    echo "        sudo bash ${PREP_SCRIPT}" >&2
    echo "      (~2-5 min, ~500 MB download for first run)" >&2
    echo "" >&2
else
    expected_definition="$(sha256sum "$PREP_SCRIPT" | awk '{print $1}')"
    manifest_version="$(sed -n 's/^manifest-version=//p' "$ROOTFS_MANIFEST" 2>/dev/null || true)"
    manifest_definition="$(sed -n 's/^definition-sha256=//p' "$ROOTFS_MANIFEST" 2>/dev/null || true)"
    manifest_release="$(sed -n 's/^releasever=//p' "$ROOTFS_MANIFEST" 2>/dev/null || true)"
    if [ "$manifest_version" != 2 ] \
       || [ "$manifest_definition" != "$expected_definition" ] \
       || [ "$manifest_release" != "$ROOTFS_RELEASEVER" ]; then
        echo "ERR: smoke-test rootfs is stale or unverified at ${ROOTFS_DIR}" >&2
        echo "     Rebuild it from the current signed-package definition:" >&2
        echo "       sudo bash ${PREP_SCRIPT}" >&2
        exit 1
    fi
fi

total=0
pass=0
fail=0
skipped=0

for t in M*-smoke.sh; do
    [ -f "$t" ] || continue
    total=$((total + 1))
    rc=0
    bash "./$t" >/dev/null 2>&1 || rc=$?
    case $rc in
        0)
            pass=$((pass + 1))
            printf 'PASS  smoke/%s\n' "${t%-smoke.sh}"
            ;;
        77)
            skipped=$((skipped + 1))
            printf 'SKIP  smoke/%s  (prerequisites missing)\n' "${t%-smoke.sh}"
            ;;
        *)
            fail=$((fail + 1))
            printf 'FAIL  smoke/%s  (exit %d — re-run with verbose to debug)\n' "${t%-smoke.sh}" "$rc"
            ;;
    esac
done

echo
echo '--------------------------------------------------------------------'
if [ "$total" -eq 0 ]; then
    echo 'ERR: no smoke tests discovered' >&2
    exit 2
elif [ "$fail" -ne 0 ]; then
    echo "Smoke FAILED: ${pass}/${total} passed, ${fail} failed, ${skipped} skipped"
    exit 1
elif [ "$skipped" -eq "$total" ] && [ "$total" -gt 0 ]; then
    # All tests skipped = nothing actually verified, exit 77
    # (LSB "test was skipped"). Better than a false-positive exit 0.
    echo "Smoke: 0 actually run — all ${total} skipped due to missing prerequisites."
    echo "  Run 'sudo bash ${PREP_SCRIPT}' to enable smoke tests."
    exit 77
elif [ "$skipped" -eq 0 ]; then
    echo "All smoke tests passed: ${pass}/${total}"
    exit 0
else
    echo "Smoke: ${pass}/${total} passed, ${skipped} skipped (prereqs)"
    exit 0
fi

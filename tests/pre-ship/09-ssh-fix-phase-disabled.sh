#!/bin/bash
# 09-ssh-fix-phase-disabled — pre-ship-tag gate (NOT in run-all.sh)
#
# Asserts that the SSH fix-phase is REVERTED before tagging a release.
# During the build/test cycle, the fix-phase RE-ENABLES openssh-server in the
# image so VM-based audits can SSH in. This is operationally necessary AND a
# release-blocker — the fix-phase MUST be reverted before every public tag.
#
# Run this manually as the final pre-tag check:
#   bash tests/pre-ship/09-ssh-fix-phase-disabled.sh
#   echo "exit code: $?"
#
# Or wire into a release-only CI job (NOT the regular tests/run-all.sh).
#
# SSH fix-phase kept disabled until 100% (release-blocker).

set -euo pipefail

KS_FILE="$(cd "$(dirname "$0")/../.." && pwd)/kickstart/snippets/09-ssh.ks"

if [ ! -f "$KS_FILE" ]; then
    echo "FAIL  09-ssh-fix-phase-disabled  ($KS_FILE not found)"
    exit 1
fi

# Check 1: openssh-server exclusion is ACTIVE (uncommented `-openssh-server` line)
if ! grep -qE '^-openssh-server[[:space:]]*$' "$KS_FILE"; then
    echo "FAIL  09-ssh-fix-phase-disabled"
    echo "  expected: '^-openssh-server' (uncommented exclusion in %packages block)"
    echo "  actual:   exclusion is commented out OR missing"
    echo ""
    echo "  Fix-phase still active. Revert before tagging:"
    echo "  - Restore the active '-openssh-server' exclusion in kickstart/snippets/09-ssh.ks"
    echo "  - Edit kickstart/snippets/09-ssh.ks Test 3.1 logic: present=FAIL, absent=OK"
    echo "  - Edit kickstart/snippets/26-package-set.ks MUST_ABSENT: uncomment 'openssh-server'"
    echo "  - Edit kickstart/snippets/17-gnome-hardening.ks: remove fix-phase Gap 1d block"
    exit 1
fi

# Check 2: fix-phase comment block is REMOVED (status change marker)
if grep -qE 'rc\.[0-9]+ fix-phase RE-ENABLED' "$KS_FILE"; then
    echo "FAIL  09-ssh-fix-phase-disabled"
    echo "  expected: no active 'rc.X fix-phase RE-ENABLED' comment block"
    echo "  actual:   fix-phase status comment still present in $KS_FILE"
    echo ""
    echo "  Remove the obsolete block; do not retain release-history markers in source."
    exit 1
fi

# Check 3: Test 3.1 logic is reverted (present should be FAIL, not [OK] with warn)
if grep -qE 'RE-DISABLE BEFORE rc' "$KS_FILE"; then
    echo "FAIL  09-ssh-fix-phase-disabled"
    echo "  expected: Test 3.1 inverted back — 'present = FAIL, absent = OK'"
    echo "  actual:   'RE-DISABLE BEFORE rc' marker still in Test 3.1 logic"
    exit 1
fi

echo "PASS  09-ssh-fix-phase-disabled  (fix-phase reverted, ship-ready)"
exit 0

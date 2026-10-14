#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail
. "$(dirname "$0")/lib.sh"
PROJECT_ROOT=$(find_project_root)
test_start "00-compose-metalinks"
assert_file_executable "$PROJECT_ROOT/scripts/prepare-compose-metalinks.py" \
    "current-metadata preparation helper is executable"
assert_cmd_success "native Metalink and offline Kickstart trust-boundary fixtures" \
    python3 "$PROJECT_ROOT/tests/00-compose-metalinks.py"
assert_grep_fixed '"$FLAT_KS" "$COMPOSE_METALINK_DIR"' \
    "$PROJECT_ROOT/scripts/build-iso.sh" "canonical builder prepares current Fedora metadata"
assert_grep_fixed 'updates-upstream.xml updates-current.xml compose-metalinks.json' \
    "$PROJECT_ROOT/scripts/build-iso.sh" "original and constrained metadata evidence is retained"
assert_grep_fixed 'python3 "$METALINK_HELPER" "$TMPDIR/metadata"' \
    "$PROJECT_ROOT/tests/pre-ship/25-installed-package-freshness.sh" \
    "installed freshness query shares the validated current-metadata selector"
assert_grep_fixed '--setopt=fedora.skip_if_unavailable=False --setopt=updates.skip_if_unavailable=False' \
    "$PROJECT_ROOT/tests/pre-ship/25-installed-package-freshness.sh" \
    "neither required Fedora repository can be silently skipped"
test_finish

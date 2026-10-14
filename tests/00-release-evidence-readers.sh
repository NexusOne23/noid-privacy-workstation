#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Counterexamples for the candidate gates; no candidate or host mutation.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
ROOT=$(find_project_root)
test_start "00-release-evidence-readers"
assert_cmd_success "candidate readers reject query failures and preserve failed recovery backups" \
    python3 "$ROOT/tests/fixtures/release_gate_readers.py" "$ROOT"
test_finish

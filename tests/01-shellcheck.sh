#!/bin/bash
# 01-shellcheck — run ShellCheck over standalone test scripts under tests/
#
# ShellCheck is optional (not always installed). If missing, skip gracefully.
# When run, ShellCheck finds style/logic issues bash -n doesn't (e.g.
# unquoted vars, [ vs [[, missing shebang, subshell traps).
#
# "ShellCheck" capitalized in the doc
# comments above. ShellCheck parses `# shellcheck …` (lowercase, leading
# space) as a directive comment, so a plain English description that began
# `# shellcheck is optional …` was reported as SC1073/SC1072. Capitalised
# wording sidesteps the directive parser.
#
# Substantive coverage of `.ks` heredoc bodies lives in
# `tests/02-shellcheck-heredocs.sh`. This test is a
# BLOCKING gate on standalone shell scripts (tests/ + tests/pre-ship/ +
# tests/smoke/ + scripts/ + scripts/anaconda-patch/ + branding/icons/): a shellcheck
# finding outside the documented --exclude set FAILS the test by
# intent, "build/orchestration logic must not regress quietly". The looser
# advisory standard applies only to 02's heredoc-extracted scripts (which
# carry intentional word-splitting and so additionally exclude SC2086 etc.).
set -uo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"

test_start "01-shellcheck"

if ! command -v shellcheck >/dev/null 2>&1; then
    _fail "shellcheck unavailable — standalone lint gate did not run"
    test_finish
    exit 1
fi

shopt -s nullglob

# Kickstart files contain non-shell directives (like %packages, %post),
# which the linter cannot parse. Instead, we extract embedded shell scripts
# (things inside heredocs that contain shebangs or bash code) for analysis;
# that path lives in 02-shellcheck-heredocs.sh.
#
# For now, check only the standalone shell scripts under tests/ —
# the kickstart %post blocks are indirectly covered by bash -n + E2E.
# (post-install/ mirror was removed to avoid drift; kickstart heredocs
# are the single source of truth.)

errors=0
# Scope was previously tests/*.sh
# only. Extended to scripts/*.sh + scripts/lib/*.sh +
# scripts/anaconda-patch/*.sh + branding/icons/*.sh + tests/smoke/*.sh +
# tests/pre-ship/*.sh —
# those paths carry release-relevant build/orchestration logic that must
# not regress quietly.
for dir in tests tests/pre-ship tests/smoke scripts scripts/lib scripts/anaconda-patch branding/icons; do
    target_dir="$PROJECT_ROOT/$dir"
    [ -d "$target_dir" ] || continue
    for f in "$target_dir"/*.sh; do
        [ -f "$f" ] || continue
        rel="${f#"$PROJECT_ROOT"/}"
        # SC1091 (not following sourced files) — lib.sh and the build
        # libraries are sourced by runtime-resolved paths.
        # SC2016 (single-quote no-expand) is intentional in lib.sh assert
        # description strings (default-message scaffolds).
        # SC2012 (use find instead of ls) — predictable filename patterns
        # in branding/icons/ + similar; intentional ls usage.
        # SC2015 (A && B || C) — idiomatic test pattern (`&& _pass || _fail`)
        # where both helpers return 0 deterministically.
        if shellcheck --shell=bash \
                --exclude=SC1091,SC2016,SC2012,SC2015 \
                "$f" >/dev/null 2>&1; then
            _pass "shellcheck: $rel"
        else
            errors=$((errors + 1))
            _fail "shellcheck: $rel"
        fi
    done
done

# Gating is via _fail above (→ TEST_FAILS → test_finish exits non-zero): a
# ShellCheck finding on a standalone script FAILS this test. The counter is
# kept only for this summary diagnostic (capitalised per the note
# above — a comment line beginning `# shellcheck` is parsed as a directive).
[ "$errors" -eq 0 ] || echo "  $errors standalone script(s) failed shellcheck (blocking — fix, or add a justified code to --exclude)"

test_finish

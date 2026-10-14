#!/bin/bash
# 01-shellcheck — run ShellCheck over standalone test scripts under tests/
#
# ShellCheck is a full-suite prerequisite (run-all.sh preflights it); a
# missing binary fails this gate closed. ShellCheck finds style/logic issues
# bash -n doesn't (e.g. unquoted vars, [ vs [[, missing shebang, subshell traps).
#
# Keep comment lines from starting with lowercase `# shellcheck`: ShellCheck
# parses that as directive syntax (SC1073/SC1072 on plain English text).
#
# Substantive coverage of `.ks` heredoc bodies lives in
# `tests/02-shellcheck-heredocs.sh`. This test is a
# BLOCKING gate on standalone shell scripts (tests/ + tests/pre-ship/ +
# tests/smoke/ + scripts/ + scripts/lib/ + scripts/anaconda-patch/ +
# branding/icons/): a shellcheck
# finding outside the documented --exclude set FAILS the test by
# intent, "build/orchestration logic must not regress quietly". 02's
# heredoc-extracted scripts are equally blocking at error/warning severity;
# only their style/info findings are advisory, and SC1091 (a source path
# that exists only on the installed image) is their single exclusion.
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

# Kickstart files are not shell; their heredoc bodies are linted by
# tests/02-shellcheck-heredocs.sh. This gate lints every standalone *.sh in
# the directories listed below, which carry release-relevant test, build and
# orchestration logic that must not regress quietly.

errors=0
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

#!/bin/bash
# 00-syntax-sweep — bash -n on every .ks file
#
# Purpose: fast sanity check. Would NOT have caught M22 sed bug (sed
# passed bash -n), but catches typos/missing fi/missing quotes.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"

test_start "00-syntax-sweep"

shopt -s nullglob

files=()
for f in "$PROJECT_ROOT"/kickstart/master.ks "$PROJECT_ROOT"/kickstart/snippets/*.ks; do
    [ -f "$f" ] || continue
    files+=("$f")
done

for f in "${files[@]}"; do
    rel="${f#"$PROJECT_ROOT"/}"
    if bash -n "$f" 2>/dev/null; then
        _pass "bash -n: $rel"
    else
        _fail "bash -n: $rel"
    fi
done

# The shared fixture logger must keep deliberately provoked failures
# distinguishable from production incidents, including in child Bash scripts.
logger_capture=$(NOID_TEST_LOGGER_BACKEND=/usr/bin/echo \
    logger -t noid-fixture -- "FAIL: expected path")
assert_eq '-t noid-fixture-test -- FAIL: expected path' "$logger_capture" \
    "test logger suffixes a short-form production tag"
logger_capture=$(NOID_TEST_LOGGER_BACKEND=/usr/bin/echo \
    bash -c 'logger --tag=noid-child "FAIL: expected child path"')
assert_eq '--tag=noid-child-test FAIL: expected child path' "$logger_capture" \
    "exported test logger suffixes a child-script tag"
logger_capture=$(NOID_TEST_LOGGER_BACKEND=/usr/bin/echo \
    logger "fixture without explicit tag")
assert_eq '-t noid-test fixture without explicit tag' "$logger_capture" \
    "test logger supplies an explicit generic test tag"

assert_cmd_failure "negative grep assertion rejects a missing target" \
    bash -c '. "$1"; test_start fixture; assert_not_grep x "$2"; test_finish' \
        _ "$(dirname "$0")/lib.sh" "$PROJECT_ROOT/.missing-negative-target"
assert_cmd_failure "extended negative grep assertion rejects a missing target" \
    bash -c '. "$1"; test_start fixture; assert_not_grep_extended x "$2"; test_finish' \
        _ "$(dirname "$0")/lib.sh" "$PROJECT_ROOT/.missing-negative-target"

test_finish

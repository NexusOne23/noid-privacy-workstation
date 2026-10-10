#!/bin/bash
# 00-syntax-sweep — bash -n on every .ks file, plus tests/lib.sh self-tests
#
# Purpose: fast sanity check. bash -n catches typos, missing fi and unbalanced
# quotes, not wrong program logic such as an incorrect sed expression. The
# same file proves the shared test library's own failure semantics.
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
assert_cmd_failure "fixed-string negative grep assertion rejects a missing target" \
    bash -c '. "$1"; test_start fixture; assert_not_grep_fixed x "$2"; test_finish' \
        _ "$(dirname "$0")/lib.sh" "$PROJECT_ROOT/.missing-negative-target"

# A negative command assertion must not pass merely because the command under
# test is missing or cannot be executed; exact-status assertions compare codes.
LIB_SELF="$(dirname "$0")/lib.sh"
assert_cmd_failure "negative command assertion rejects a missing command" \
    bash -c '. "$1"; test_start fixture; assert_cmd_failure x /nonexistent/validator; test_finish' \
        _ "$LIB_SELF"
assert_cmd_failure "negative command assertion rejects a command-not-found status" \
    bash -c '. "$1"; test_start fixture; assert_cmd_failure x bash -c "exit 127"; test_finish' \
        _ "$LIB_SELF"
assert_cmd_success "negative command assertion accepts an ordinary rejection" \
    bash -c '. "$1"; test_start fixture; assert_cmd_failure x bash -c "exit 2"; test_finish' \
        _ "$LIB_SELF"
assert_cmd_success "exact-status assertion accepts the documented code" \
    bash -c '. "$1"; test_start fixture; assert_cmd_status 2 x bash -c "exit 2"; test_finish' \
        _ "$LIB_SELF"
assert_cmd_failure "exact-status assertion rejects a different failure code" \
    bash -c '. "$1"; test_start fixture; assert_cmd_status 2 x bash -c "exit 1"; test_finish' \
        _ "$LIB_SELF"

# A test file that neither checks nor skips anything must not report PASS.
assert_cmd_failure "a test file without any check fails" \
    bash -c '. "$1"; test_start fixture; test_finish' _ "$LIB_SELF"
assert_cmd_success "a test file whose only result is an explicit skip passes" \
    bash -c '. "$1"; test_start fixture; _skip capability; test_finish' _ "$LIB_SELF"

# Heredoc extraction returns exactly one closed block.
HEREDOC_FIXTURE_DIR=$(mktemp -d)
trap 'rm -rf -- "$HEREDOC_FIXTURE_DIR"' EXIT
printf '%s\n' "cat > /a <<'DOC_EOF'" A DOC_EOF "cat > /b <<'DOC_EOF'" B DOC_EOF \
    > "$HEREDOC_FIXTURE_DIR/twice.ks"
printf '%s\n' "cat > /a <<'DOC_EOF'" line1 line2 > "$HEREDOC_FIXTURE_DIR/unterminated.ks"
if extract_heredoc "$HEREDOC_FIXTURE_DIR/twice.ks" DOC_EOF "$HEREDOC_FIXTURE_DIR/first"; then
    assert_eq A "$(cat "$HEREDOC_FIXTURE_DIR/first")" \
        "heredoc extraction returns only the first same-marker block"
else
    _fail "heredoc extraction returns only the first same-marker block"
fi
if extract_heredoc "$HEREDOC_FIXTURE_DIR/twice.ks" DOC_EOF "$HEREDOC_FIXTURE_DIR/second" 2; then
    assert_eq B "$(cat "$HEREDOC_FIXTURE_DIR/second")" \
        "heredoc extraction selects an explicit later occurrence"
else
    _fail "heredoc extraction selects an explicit later occurrence"
fi
assert_cmd_failure "heredoc extraction rejects a missing occurrence" \
    extract_heredoc "$HEREDOC_FIXTURE_DIR/twice.ks" DOC_EOF "$HEREDOC_FIXTURE_DIR/third" 3
assert_cmd_failure "heredoc extraction rejects an unterminated block" \
    extract_heredoc "$HEREDOC_FIXTURE_DIR/unterminated.ks" DOC_EOF "$HEREDOC_FIXTURE_DIR/open"

# Executable scratch lives outside the checkout and fails clearly when its
# parent cannot be used.
if exec_scratch=$(make_exec_tmpdir syntax-sweep); then
    printf '#!/bin/sh\nexit 0\n' > "$exec_scratch/probe"
    chmod 0700 "$exec_scratch/probe"
    assert_cmd_success "exec scratch directory runs fixture programs" "$exec_scratch/probe"
    case "$exec_scratch/" in
        "$PROJECT_ROOT"/*) _fail "exec scratch directory is outside the checkout" ;;
        *) _pass "exec scratch directory is outside the checkout" ;;
    esac
    rm -rf -- "$exec_scratch"
else
    _fail "exec scratch directory can be created"
fi
assert_cmd_failure "exec scratch creation rejects an unusable parent" \
    env NOID_TEST_EXEC_TMPDIR="$HEREDOC_FIXTURE_DIR/missing-parent" \
        bash -c '. "$1"; make_exec_tmpdir probe' _ "$LIB_SELF"
unset exec_scratch

# The suite runner's own log and status handling, exercised on a copy of the
# real run-all.sh with synthetic test scripts only.
assert_cmd_success "test runner distinguishes test failures from lost logs" \
    python3 "$PROJECT_ROOT/tests/fixtures/test_runner.py" \
        "$PROJECT_ROOT/tests/run-all.sh"

test_finish

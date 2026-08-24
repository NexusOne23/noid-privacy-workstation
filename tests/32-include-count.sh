#!/bin/bash
# 32-include-count — guards against orphaned/missing snippets
#
# Covers: master.ks %include directives match actual snippet files.
# Would catch: a new snippet file added without being wired in, or a
# %include referencing a missing snippet.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
MASTER="$PROJECT_ROOT/kickstart/master.ks"
SNIPPETS_DIR="$PROJECT_ROOT/kickstart/snippets"
INDEX_FILE="$PROJECT_ROOT/INDEX.md"

test_start "32-include-count"

assert_file_exists "$MASTER"
assert_file_exists "$INDEX_FILE"

# Extract all %include snippets/... lines from master.ks
includes=$(grep -oE '%include[[:space:]]+snippets/[0-9a-zA-Z_.-]+\.ks' "$MASTER" | awk '{print $2}' | sort -u)
include_count=$(echo "$includes" | grep -c . || true); include_count=${include_count:-0}

# Every %include must point to an existing file
missing=0
for inc in $includes; do
    if [ ! -f "$PROJECT_ROOT/kickstart/$inc" ]; then
        _fail "%include references missing snippet: $inc"
        missing=$((missing + 1))
    fi
done
if [ "$missing" -eq 0 ]; then
    _pass "all $include_count %include references resolve"
fi

# Every snippet file must be referenced by exactly one %include
orphan=0
for f in "$SNIPPETS_DIR"/*.ks; do
    rel="snippets/$(basename "$f")"
    if ! echo "$includes" | grep -qFx "$rel"; then
        _fail "orphan snippet (not %include'd): $rel"
        orphan=$((orphan + 1))
    fi
done
if [ "$orphan" -eq 0 ]; then
    snippet_count=$(find "$SNIPPETS_DIR" -maxdepth 1 -name '*.ks' -type f | wc -l)
    _pass "all $snippet_count snippet files are %include'd"
fi

# Include count must equal the snippet-file count (every snippet wired in, none orphaned)
snippet_count=$(find "$SNIPPETS_DIR" -maxdepth 1 -name '*.ks' -type f | wc -l)
if [ "$include_count" -eq "$snippet_count" ]; then
    _pass "include count ($include_count) matches snippet count ($snippet_count)"
else
    _fail "include count ($include_count) != snippet count ($snippet_count)"
fi

# The human repository map must enumerate every included module exactly once
# and preserve cross-module ownership boundaries used during review.
for inc in $includes; do
    base=$(basename "$inc")
    index_refs=$(grep -oF "(kickstart/$inc)" "$INDEX_FILE" | wc -l || true)
    assert_eq 1 "$index_refs" "INDEX has exactly one module row for $base"
done
assert_grep_fixed 'Owns strict-default global + physical Quad9 DoT' \
    "$INDEX_FILE" "INDEX assigns global DNS/resolved ownership to M05"
assert_grep_fixed 'Owns chrony NTS time synchronization only' \
    "$INDEX_FILE" "INDEX limits M11 ownership to time synchronization"
assert_grep_fixed 'DNS/resolved policy belongs to M05' "$INDEX_FILE" \
    "INDEX carries the M11 cross-module DNS boundary"
assert_not_grep '11-dns-ntp.ks.*Quad9 system DNS-over-TLS' "$INDEX_FILE" \
    "INDEX does not assign Quad9 configuration to M11"

build_line=$(grep -nF 'scripts/build-iso.sh' "$INDEX_FILE" | head -1 | cut -d: -f1 || true)
installed_line=$(grep -nF '# Only after the unsigned candidate exists:' "$INDEX_FILE" | \
    head -1 | cut -d: -f1 || true)
if [ -n "$build_line" ] && [ -n "$installed_line" ] && \
   [ "$build_line" -lt "$installed_line" ]; then
    _pass "INDEX orders candidate build before installed-candidate gates"
else
    _fail "INDEX orders candidate build before installed-candidate gates"
fi
assert_grep_fixed 'never against the build host' "$INDEX_FILE" \
    "INDEX separates installed-candidate tests from host checks"
assert_grep_fixed 'canonical pre-ship block of tests/README.md' "$INDEX_FILE" \
    "INDEX delegates the complete installed-candidate ledger to one canonical source"

test_finish

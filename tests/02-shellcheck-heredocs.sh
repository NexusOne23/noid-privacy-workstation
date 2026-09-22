#!/bin/bash
# 02-shellcheck-heredocs — extract shebang-prefixed heredocs from .ks files
#                          and verify bash -n + ShellCheck warnings (REQUIRED)
#
# The sibling 01-shellcheck covers standalone scripts under tests (including
# pre-ship and smoke), scripts and branding/icons. Real user-facing scripts
# also live inside .ks heredocs; this test covers that separate surface:
#
#   1. Iterate every kickstart/master.ks + kickstart/snippets/*.ks
#   2. Extract every heredoc body whose first line is a shebang (#!/...)
#   3. bash -n REQUIRED on each extracted script (syntax errors = test fail)
#   4. ShellCheck error/warning severity REQUIRED on each extracted script;
#      info/style findings remain visible as an advisory count
#
# Heredoc patterns matched:
#   cat > foo.sh <<'MARKER'      (single-quoted, no expansion)
#   cat > foo.sh <<"MARKER"      (double-quoted)
#   cat > foo.sh <<MARKER        (unquoted)
# Marker must match: [A-Za-z_][A-Za-z0-9_]+
#
# Skip rules:
#   - heredocs without shebang are not user-facing scripts (probably config
#     files, RPM repo definitions, .desktop files, etc.) — skipped silently.
#   - shellcheck advisory excludes are documented inline below.

set -uo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"

test_start "02-shellcheck-heredocs"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

# ---------------------------------------------------------------------
# Extract every shebang-prefixed heredoc from all .ks files.
# ---------------------------------------------------------------------
extract_shebang_heredocs() {
    local source=$1
    local outdir=$2
    local base=$3

    awk -v base="$base" -v outdir="$outdir" '
        # Match heredoc start: <<MARKER, <<'\''MARKER'\'', <<"MARKER".
        # Marker = [A-Za-z_][A-Za-z0-9_]+ ; trailing whitespace + EOL allowed.
        /<<[ \t]*[\47"]?[A-Za-z_][A-Za-z0-9_]+[\47"]?[ \t]*$/ && !in_hd {
            line = $0
            sub(/.*<<[ \t]*[\47"]?/, "", line)
            sub(/[\47"]?[ \t]*$/, "", line)
            marker = line
            in_hd = 1
            opener_line = NR
            buffer = ""
            next
        }
        in_hd {
            # End of heredoc: line that is exactly the marker (with optional
            # leading/trailing whitespace per heredoc <<- semantics).
            end_re = "^[ \t]*" marker "[ \t]*$"
            if ($0 ~ end_re) {
                # Only emit if body starts with shebang
                if (substr(buffer, 1, 3) == "#!/") {
                    # A delimiter name is reusable within one Kickstart file.
                    # Include its opener line so a later block can never
                    # overwrite an earlier script before linting sees it.
                    outfile = outdir "/" base "__L" opener_line "__" marker ".sh"
                    print buffer > outfile
                    close(outfile)
                }
                in_hd = 0
                buffer = ""
                marker = ""
                next
            }
            buffer = buffer (length(buffer) ? "\n" : "") $0
        }
    ' "$source"
}

# Mutation control: two script heredocs may legitimately reuse a delimiter.
# Both must survive extraction as distinct files or the lint corpus is lossy.
collision_dir="$WORKDIR/collision-control"
mkdir -p "$collision_dir"
cat > "$WORKDIR/collision-control.ks" <<'COLLISION_FIXTURE_EOF'
cat > /tmp/first <<'REUSED_EOF'
#!/bin/bash
echo first-collision-sentinel
REUSED_EOF
cat > /tmp/second <<'REUSED_EOF'
#!/bin/bash
echo second-collision-sentinel
REUSED_EOF
COLLISION_FIXTURE_EOF
extract_shebang_heredocs \
    "$WORKDIR/collision-control.ks" "$collision_dir" collision-control
collision_files=("$collision_dir"/*.sh)
if [ "${#collision_files[@]}" -ne 2 ] \
   || ! grep -qF first-collision-sentinel "${collision_files[@]}" \
   || ! grep -qF second-collision-sentinel "${collision_files[@]}"; then
    _fail "reused heredoc delimiter overwrote or hid an extracted script"
else
    _pass "reused heredoc delimiters retain both scripts in the lint corpus"
fi

extract_count=0
shopt -s nullglob
for ks in "$PROJECT_ROOT"/kickstart/master.ks "$PROJECT_ROOT"/kickstart/snippets/*.ks; do
    [ -f "$ks" ] || continue
    base=$(basename "$ks" .ks)
    extract_shebang_heredocs "$ks" "$WORKDIR" "$base"
done

# Count extracted scripts
shopt -s nullglob
extract_count=0
for sh_file in "$WORKDIR"/*.sh; do
    [ -f "$sh_file" ] || continue
    extract_count=$((extract_count + 1))
done

if [ "$extract_count" -eq 0 ]; then
    _fail "extraction yielded 0 shebang-prefixed heredocs (regex bug?)"
    test_finish
    exit 1
fi

_pass "extracted $extract_count shebang-prefixed heredoc script(s)"

# ---------------------------------------------------------------------
# Classify by shebang so we only run bash -n / shellcheck on bash/sh scripts.
# Non-bash interpreters (Python, nftables, awk, etc.) get silently skipped —
# they have their own static-checks elsewhere (Module 13 Python via
# `python3 -m py_compile` in tests/13-welcome-script.sh, nft via
# `nft -c -f` at runtime, etc.).
# ---------------------------------------------------------------------
bash_count=0
non_bash_count=0
for sh_file in "$WORKDIR"/*.sh; do
    [ -f "$sh_file" ] || continue
    shebang=$(head -1 "$sh_file")
    case "$shebang" in
        \#!/bin/bash*|\#!/usr/bin/bash*|\#!/usr/bin/env\ bash*|\#!/bin/sh*|\#!/usr/bin/sh*|\#!/usr/bin/env\ sh*)
            bash_count=$((bash_count + 1))
            ;;
        *)
            # Move out of the way so the loops below don't pick it up
            mv "$sh_file" "${sh_file%.sh}.skip"
            non_bash_count=$((non_bash_count + 1))
            ;;
    esac
done

_pass "shebang classification: $bash_count bash/sh scripts, $non_bash_count other (skipped)"

# ---------------------------------------------------------------------
# bash -n REQUIRED — syntax errors fail the test
# ---------------------------------------------------------------------
bash_n_fails=0
for sh_file in "$WORKDIR"/*.sh; do
    [ -f "$sh_file" ] || continue
    rel=$(basename "$sh_file")
    if bash -n "$sh_file" 2>/dev/null; then
        : # silent on success — too noisy with 50+ scripts
    else
        bash_n_fails=$((bash_n_fails + 1))
        _fail "bash -n: $rel (syntax error)"
        # Show the actual error for diagnosis
        bash -n "$sh_file" 2>&1 | head -5 | sed 's/^/      /' || true
    fi
done

if [ "$bash_n_fails" -eq 0 ]; then
    _pass "bash -n clean on all $bash_count bash/sh heredoc scripts"
fi

# ---------------------------------------------------------------------
# ShellCheck REQUIRED at warning severity; style/info remains advisory
# (capital S to avoid SC1073/SC1072 directive misparse)
# ---------------------------------------------------------------------
# Excludes (intentional patterns or noise):
#   SC1091 — non-constant source (sourced files at install path, OK)
#   SC2034 — unused var (often used in heredocs that are read by other code)
#   SC2086 — word splitting (intentional for route/IP CIDR expansion in NM
#            dispatcher and similar; quoting would break the expansion)
#   SC2155 — declare-and-assign masks return code (style preference; readable)
#   SC2064 — already audited + fixed in Module 40 (SC2064 trap-quoting)
if command -v shellcheck >/dev/null 2>&1; then
    sc_blocking=0
    sc_style=0
    shellcheck_files=("$WORKDIR"/*.sh)
    sc_pids=()
    sc_outputs=()
    sc_errors=()
    chunk_size=32
    start=0
    chunk_id=0
    # One style-level JSON analysis contains every severity. Four independent
    # chunks run concurrently; we classify ERROR/WARNING as blocking and
    # INFO/STYLE as advisory from those same results, avoiding a redundant
    # second parse of the complete corpus.
    while [ "$start" -lt "${#shellcheck_files[@]}" ]; do
        chunk=("${shellcheck_files[@]:start:chunk_size}")
        sc_out="$WORKDIR/shellcheck-$chunk_id.json"
        sc_err="$WORKDIR/shellcheck-$chunk_id.err"
        shellcheck --shell=bash --severity=style --format=json \
            --exclude=SC1091,SC2034,SC2086,SC2155,SC2064 \
            "${chunk[@]}" >"$sc_out" 2>"$sc_err" &
        sc_pids+=("$!")
        sc_outputs+=("$sc_out")
        sc_errors+=("$sc_err")
        start=$((start + chunk_size))
        chunk_id=$((chunk_id + 1))
    done
    for index in "${!sc_pids[@]}"; do
        sc_rc=0
        wait "${sc_pids[$index]}" || sc_rc=$?
        if [ "$sc_rc" -gt 1 ]; then
            sc_blocking=1
            _fail "ShellCheck execution failed for heredoc chunk $index (rc=$sc_rc)"
            sed 's/^/      /' "${sc_errors[$index]}"
            continue
        fi
        if grep -qE '"level"[[:space:]]*:[[:space:]]*"(error|warning)"' \
                "${sc_outputs[$index]}"; then
            sc_blocking=1
            _fail "ShellCheck warning/error in extracted heredoc chunk $index"
            sed 's/^/      /' "${sc_outputs[$index]}"
        fi
        if grep -qE '"level"[[:space:]]*:[[:space:]]*"(info|style)"' \
                "${sc_outputs[$index]}"; then
            sc_style=1
        fi
    done
    if [ "$sc_blocking" -eq 0 ]; then
        _pass "ShellCheck warning/error gate clean on all $bash_count bash/sh heredocs"
    fi
    _pass "ShellCheck style/info advisory present: $sc_style (non-blocking corpus result)"
else
    _fail "shellcheck unavailable — required heredoc lint gate did not run"
fi

test_finish

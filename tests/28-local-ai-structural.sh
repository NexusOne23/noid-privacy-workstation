#!/bin/bash
# 28-local-ai-structural — verify M28 structural invariants
#
# Invariants (guards against regression of the rewrite):
#   1. RamaLama is Option A (first, recommended)
#   2. Ollama is Option B
#   3. LM Studio is Option C
#   4. llama.cpp is Option D
#   5. "Which option?" decision table present
#   6. Ollama's package/advisory/artifact/authentication boundaries are explicit
#   7. llama-vscode and the WebUI preserve the owner-authorized agent workflow
#   8. Loopback, runtime verification and generator parity stay enforced

set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/28-local-ai-docs.ks"
STAMP_PATTERN_DOC="$PROJECT_ROOT/docs/engineering-health-stamp-pattern.md"

test_start "28-local-ai-structural"

if [ ! -f "$KS_FILE" ]; then
    _fail "M28 snippet missing: $KS_FILE"
    test_finish
    exit 1
fi

TMPDIR="$(mktemp -d)"
EXEC_TMPDIR="$(mktemp -d /var/tmp/noid-m28-test.XXXXXX)"
trap 'rm -rf "$TMPDIR" "$EXEC_TMPDIR"' EXIT

DOC="$TMPDIR/28-local-ai.md"
extract_heredoc "$KS_FILE" "AI_DOC_EOF" "$DOC" || true

assert_file_min_size "$DOC" 8192 "doc extracted >8KB"

# Every fenced command example is an independently copyable unit. Angle-bracket
# placeholders in command position are invalid Bash; parse the bytes exactly as
# shipped rather than normalizing documentation tokens in the test.
MARKDOWN_BASH_DIR="$TMPDIR/markdown-bash"
MARKDOWN_JSON_DIR="$TMPDIR/markdown-json"
mkdir -p "$MARKDOWN_BASH_DIR" "$MARKDOWN_JSON_DIR"
awk -v out="$MARKDOWN_BASH_DIR" '
    /^```bash[[:space:]]*$/ {
        in_block = 1
        count++
        file = sprintf("%s/block-%02d.sh", out, count)
        next
    }
    in_block && /^```[[:space:]]*$/ {
        in_block = 0
        close(file)
        next
    }
    in_block { print > file }
' "$DOC"
awk -v out="$MARKDOWN_JSON_DIR" '
    /^```json[[:space:]]*$/ {
        in_block = 1
        count++
        file = sprintf("%s/block-%02d.json", out, count)
        next
    }
    in_block && /^```[[:space:]]*$/ {
        in_block = 0
        close(file)
        next
    }
    in_block { print > file }
' "$DOC"

shopt -s nullglob
markdown_bash_blocks=("$MARKDOWN_BASH_DIR"/*.sh)
markdown_bash_fails=0
artifact_consuming_blocks=0
strict_artifact_consuming_blocks=0
for markdown_block in "${markdown_bash_blocks[@]}"; do
    bash -n "$markdown_block" || markdown_bash_fails=$((markdown_bash_fails + 1))
    if grep -qE -- 'ollama_expected=|llama_cpp_expected=|llama_vscode_expected=|^model_id=ornith$' \
            "$markdown_block"; then
        artifact_consuming_blocks=$((artifact_consuming_blocks + 1))
        if [ "$(sed -n '1p' "$markdown_block")" = '(' ] \
           && [ "$(sed -n '2p' "$markdown_block")" = 'set -euo pipefail' ] \
           && [ "$(tail -n 1 "$markdown_block")" = ')' ]; then
            strict_artifact_consuming_blocks=$((strict_artifact_consuming_blocks + 1))
        fi
    fi
done
if [ "${#markdown_bash_blocks[@]}" -gt 0 ] && [ "$markdown_bash_fails" -eq 0 ]; then
    _pass "every fenced Bash example parses verbatim"
else
    _fail "every fenced Bash example parses verbatim"
fi
assert_eq 4 "$artifact_consuming_blocks" \
    "all four artifact-consuming examples are present"
assert_eq "$artifact_consuming_blocks" "$strict_artifact_consuming_blocks" \
    "every artifact-consuming example is confined to a strict fail-closed subshell"

markdown_json_blocks=("$MARKDOWN_JSON_DIR"/*.json)
markdown_json_fails=0
for markdown_block in "${markdown_json_blocks[@]}"; do
    jq -e . "$markdown_block" >/dev/null \
        || markdown_json_fails=$((markdown_json_fails + 1))
done
if [ "${#markdown_json_blocks[@]}" -gt 0 ] && [ "$markdown_json_fails" -eq 0 ]; then
    _pass "every fenced JSON example parses verbatim"
else
    _fail "every fenced JSON example parses verbatim"
fi

# Artifact examples use persistent /var/tmp because the payloads are large and
# executable. Execute their exact cleanup functions: success must remove only
# the mktemp-owned prefix, while an unexpected path or a same-prefix symlink
# must fail without touching its target.
assert_eq 3 \
    "$(grep -Ec '^cleanup_(ollama|llama_cpp|llama_vscode)_stage\(\) \{$' "$DOC")" \
    "all three persistent artifact stages define exact cleanup functions"
assert_eq 3 \
    "$(grep -Ec '^trap cleanup_(ollama|llama_cpp|llama_vscode)_stage EXIT$' "$DOC")" \
    "all three artifact stages clean up on every shell exit"
assert_eq 3 "$(grep -c "^trap 'exit 1' HUP INT TERM$" "$DOC")" \
    "all three artifact subshells route terminating signals through EXIT cleanup"
assert_eq 3 "$(grep -c '^trap - EXIT HUP INT TERM$' "$DOC")" \
    "all three successful artifact paths retire their cleanup traps"

cleanup_specs=(
    'cleanup_ollama_stage|ollama_stage|noid-ollama'
    'cleanup_llama_cpp_stage|llama_cpp_stage|noid-llama-cpp'
    'cleanup_llama_vscode_stage|llama_vscode_stage|noid-llama-vscode'
)
for cleanup_spec in "${cleanup_specs[@]}"; do
    IFS='|' read -r cleanup_fn cleanup_var cleanup_prefix <<< "$cleanup_spec"
    cleanup_fragment="$TMPDIR/$cleanup_fn.sh"
    awk -v header="$cleanup_fn() {" '
        $0 == header { in_function = 1 }
        in_function { print }
        in_function && $0 == "}" { exit }
    ' "$DOC" > "$cleanup_fragment"
    if [ -s "$cleanup_fragment" ] && bash -n "$cleanup_fragment"; then
        _pass "$cleanup_fn is extractable and parses verbatim"
    else
        _fail "$cleanup_fn is extractable and parses verbatim"
    fi

    cleanup_live=$(mktemp -d "/var/tmp/$cleanup_prefix.cleanup-test.XXXXXXXX")
    mkdir "$cleanup_live/nested"
    printf '%s\n' payload > "$cleanup_live/nested/payload"
    if (
        # shellcheck disable=SC1090
        . "$cleanup_fragment"
        printf -v "$cleanup_var" '%s' "$cleanup_live"
        "$cleanup_fn"
    ); then
        _pass "$cleanup_fn removes its exact mktemp-owned tree"
    else
        _fail "$cleanup_fn removes its exact mktemp-owned tree"
    fi
    if [ ! -e "$cleanup_live" ] && [ ! -L "$cleanup_live" ]; then
        _pass "$cleanup_fn leaves no persistent artifact stage"
    else
        _fail "$cleanup_fn leaves no persistent artifact stage"
        find "$cleanup_live" -depth -delete 2>/dev/null || true
    fi

    cleanup_unexpected="$EXEC_TMPDIR/$cleanup_prefix-unexpected"
    mkdir "$cleanup_unexpected"
    printf '%s\n' must-survive > "$cleanup_unexpected/sentinel"
    if (
        # shellcheck disable=SC1090
        . "$cleanup_fragment"
        printf -v "$cleanup_var" '%s' "$cleanup_unexpected"
        "$cleanup_fn"
    ) 2>/dev/null; then
        _fail "$cleanup_fn rejects a path outside its exact /var/tmp prefix"
    else
        _pass "$cleanup_fn rejects a path outside its exact /var/tmp prefix"
    fi
    assert_grep_fixed must-survive "$cleanup_unexpected/sentinel" \
        "$cleanup_fn preserves an unexpected target"

    cleanup_protected="$EXEC_TMPDIR/$cleanup_prefix-protected"
    mkdir "$cleanup_protected"
    printf '%s\n' must-survive > "$cleanup_protected/sentinel"
    cleanup_link=$(mktemp -d "/var/tmp/$cleanup_prefix.cleanup-link.XXXXXXXX")
    rmdir "$cleanup_link"
    ln -s "$cleanup_protected" "$cleanup_link"
    if (
        # shellcheck disable=SC1090
        . "$cleanup_fragment"
        printf -v "$cleanup_var" '%s' "$cleanup_link"
        "$cleanup_fn"
    ) 2>/dev/null; then
        _fail "$cleanup_fn rejects a same-prefix symlink"
    else
        _pass "$cleanup_fn rejects a same-prefix symlink"
    fi
    assert_grep_fixed must-survive "$cleanup_protected/sentinel" \
        "$cleanup_fn never traverses the symlink target"
    unlink "$cleanup_link"
done

assert_grep_fixed 'set -euo pipefail' "$KS_FILE" \
    "M28 enforces the repository strict-variable baseline"
assert_not_grep '^set -e$' "$KS_FILE" \
    "M28 cannot silently lose nounset protection"
assert_grep_fixed 'restorecon -F -- "$STAMP"' "$KS_FILE" \
    "M28 labels its health stamp through the exact fail-closed path"
assert_grep_fixed 'restorecon -F -- "$DOC_DIR"' "$KS_FILE" \
    "M28 labels the installed-document directory"
assert_grep_fixed 'matchpathcon -V "$DOC_DIR"' "$KS_FILE" \
    "M28 verifies the installed-document directory label"
assert_grep_fixed 'sync -- "$DOC_TMP"' "$KS_FILE" \
    "M28 syncs the complete guide before atomic publication"
assert_grep_fixed 'restorecon -F -- "$AI_DOC"' "$KS_FILE" \
    "M28 labels the installed guide before verifying success"
assert_grep_fixed 'matchpathcon -V "$AI_DOC"' "$KS_FILE" \
    "M28 verifies the installed guide label"
assert_grep_fixed 'sync -- "$AI_DOC"' "$KS_FILE" \
    "M28 syncs the published guide data"
assert_grep_fixed '|| die "restorecon is required for fail-closed SELinux labeling"' "$KS_FILE" \
    "missing SELinux labeling support is fatal"
assert_not_grep_extended 'restorecon .*(2>/dev/null|\|\| true)' "$KS_FILE" \
    "M28 cannot report installed output after SELinux labeling failed"
assert_not_grep 'eval "$1"' "$KS_FILE" \
    "verification executes argument vectors rather than shell-evaluated strings"
assert_grep_fixed 'DOC_TMP=$(mktemp "$DOC_DIR/.28-local-ai.md.XXXXXXXX")' "$KS_FILE" \
    "guide publication starts from a private same-filesystem temporary file"
assert_grep_fixed '# Shipped Markdown target: /usr/share/doc/noid-privacy/28-local-ai.md' "$KS_FILE" \
    "atomic guide target remains visible to the repository document inventory"
assert_grep_fixed '# Shipped Markdown heredoc: AI_DOC_EOF' "$KS_FILE" \
    "atomic guide body remains visible to cross-module Markdown classifiers"
assert_grep_fixed 'mv -fT "$DOC_TMP" "$AI_DOC"' "$KS_FILE" \
    "guide publication atomically replaces the exact target"
assert_grep_fixed "ai_doc_meta=\$(stat -c '%u:%g:%a:%h'" "$KS_FILE" \
    "guide ownership, mode and hard-link count are verified"
assert_grep_fixed 'STAMP_TMP=$(mktemp "$STAMP_DIR/.stamp-28-local-ai-docs.ok.XXXXXXXX")' "$KS_FILE" \
    "health stamp publication starts from a private same-filesystem temporary file"
assert_grep_fixed 'mv -fT -- "$STAMP_TMP" "$STAMP"' "$KS_FILE" \
    "health stamp publication atomically replaces the exact target"
assert_grep_fixed "stat -Lc '%u:%g:%a:%h' -- \"\$path\"" "$KS_FILE" \
    "health stamp ownership, mode and hard-link count are verified"
assert_grep_fixed 'prior Module 28 health stamp is absent' "$KS_FILE" \
    "old M28 success evidence is retired before guide publication"
assert_grep_fixed 'verify_m28_health_stamp()' "$KS_FILE" \
    "staged and final M28 evidence share one exact validator"
assert_grep_fixed 'STAMP_PUBLICATION_ACTIVE=1' "$KS_FILE" \
    "published M28 evidence remains removable through every final gate"
assert_grep_fixed 'matchpathcon -V "$STAMP_TMP"' "$KS_FILE" \
    "M28 validates the staged stamp SELinux context"
assert_grep_fixed 'matchpathcon -V "$STAMP"' "$KS_FILE" \
    "M28 validates the final stamp SELinux context"
assert_grep_fixed 'Merely placing a direct write after the verification guard is' \
    "$STAMP_PATTERN_DOC" \
    "engineering guidance rejects stale success from a direct tail write"
assert_grep_fixed 'never normalize an existing' "$STAMP_PATTERN_DOC" \
    "engineering guidance preserves drift evidence at the shared boundary"
assert_grep_fixed 'an `EXIT` cleanup must' "$STAMP_PATTERN_DOC" \
    "engineering guidance requires cleanup through every final publication gate"
assert_grep_fixed 'tests/28-local-ai-structural.sh' "$STAMP_PATTERN_DOC" \
    "engineering guidance names the executed failure-path reference"

m28_invalidate_line=$(grep -nF \
    '# M28_HEALTH_INVALIDATION_BEGIN' "$KS_FILE" | cut -d: -f1)
m28_first_payload_line=$(grep -nF \
    'install -d -m 0755 -o root -g root "$DOC_DIR"' \
    "$KS_FILE" | cut -d: -f1)
m28_publish_line=$(grep -nF \
    'exact Module 28 health stamp published atomically' \
    "$KS_FILE" | cut -d: -f1)
m28_complete_line=$(grep -nF \
    'log "=== Module 28 Local AI Stack Documentation complete ==="' \
    "$KS_FILE" | cut -d: -f1)
if [ -n "$m28_invalidate_line" ] && [ -n "$m28_first_payload_line" ] \
   && [ -n "$m28_publish_line" ] && [ -n "$m28_complete_line" ] \
   && [ "$m28_invalidate_line" -lt "$m28_first_payload_line" ] \
   && [ "$m28_publish_line" -lt "$m28_complete_line" ]; then
    _pass "M28 retires old health before mutation and completes after publication"
else
    _fail "M28 retires old health before mutation and completes after publication"
fi

# Execute the exact production invalidation/publication blocks in a disposable,
# disk-backed tree. A stale success, shared-directory drift, candidate/final
# labeling failure or rename failure must never leave plausible green evidence.
m28_stamp_root="$EXEC_TMPDIR/health-stamp"
m28_stamp_state="$m28_stamp_root/state"
m28_stamp_bin="$m28_stamp_root/bin"
m28_stamp_invalidate="$m28_stamp_root/invalidate.sh"
m28_stamp_publish="$m28_stamp_root/publish.sh"
m28_stamp_uid=$(id -u)
m28_stamp_gid=$(id -g)
mkdir -p "$m28_stamp_bin"

cat > "$m28_stamp_bin/restorecon" <<'M28_STAMP_RESTORECON_EOF'
#!/usr/bin/env bash
set -euo pipefail
target="${!#}"
case "${FAKE_RESTORECON_FAIL:-}" in
    all) exit 1 ;;
    final)
        case "$target" in
            */stamp-28-local-ai-docs.ok) exit 1 ;;
        esac
        ;;
esac
exit 0
M28_STAMP_RESTORECON_EOF
cat > "$m28_stamp_bin/matchpathcon" <<'M28_STAMP_MATCHPATHCON_EOF'
#!/usr/bin/env bash
exit 0
M28_STAMP_MATCHPATHCON_EOF
cat > "$m28_stamp_bin/mv" <<'M28_STAMP_MV_EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "${FAKE_MV_FAIL:-0}" -eq 1 ]; then
    exit 1
fi
exec /usr/bin/mv "$@"
M28_STAMP_MV_EOF
chmod 0700 "$m28_stamp_bin/restorecon" \
    "$m28_stamp_bin/matchpathcon" "$m28_stamp_bin/mv"

{
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
        'PHASE=test' 'log() { :; }' \
        'die() { exit 1; }' \
        "STAMP_DIR=$m28_stamp_state" \
        'STAMP="$STAMP_DIR/stamp-28-local-ai-docs.ok"'
    sed -n \
        '/^# M28_HEALTH_INVALIDATION_BEGIN$/,/^# M28_HEALTH_INVALIDATION_END$/p' \
        "$KS_FILE" |
        sed -e "s|/var/lib/noid-privacy|$m28_stamp_state|g" \
            -e "s/-o root -g root/-o $m28_stamp_uid -g $m28_stamp_gid/" \
            -e "s/0:0:755/$m28_stamp_uid:$m28_stamp_gid:755/"
} > "$m28_stamp_invalidate"
{
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
        'PHASE=test' 'log() { :; }' \
        'die() { exit 1; }' \
        "STAMP_DIR=$m28_stamp_state" \
        'STAMP="$STAMP_DIR/stamp-28-local-ai-docs.ok"' \
        'DOC_TMP=' 'STAMP_TMP=' 'STAMP_PUBLICATION_ACTIVE=0' \
        'checks=23' 'fails=0'
    sed -n '/^cleanup() {$/,/^}$/p' "$KS_FILE"
    printf '%s\n' 'trap cleanup EXIT'
    sed -n \
        '/^# M28_HEALTH_PUBLICATION_BEGIN$/,/^# M28_HEALTH_PUBLICATION_END$/p' \
        "$KS_FILE" |
        sed -e "s/chown root:root/chown $m28_stamp_uid:$m28_stamp_gid/" \
            -e "s/0:0:755/$m28_stamp_uid:$m28_stamp_gid:755/" \
            -e "s/0:0:644:1/$m28_stamp_uid:$m28_stamp_gid:644:1/"
} > "$m28_stamp_publish"
chmod 0700 "$m28_stamp_invalidate" "$m28_stamp_publish"

mkdir -m 0755 "$m28_stamp_state"
printf '%s\n' 'module=28' 'name=local-ai-docs' 'status=ok' \
    > "$m28_stamp_state/stamp-28-local-ai-docs.ok"
assert_cmd_success "M28 rerun invalidates its prior build-success stamp" \
    env PATH="$m28_stamp_bin:$PATH" "$m28_stamp_invalidate"
if [ ! -e "$m28_stamp_state/stamp-28-local-ai-docs.ok" ]; then
    _pass "M28 old success evidence is absent before guide publication"
else
    _fail "M28 old success evidence is absent before guide publication"
fi

chmod 0777 "$m28_stamp_state"
printf '%s\n' 'must-survive' \
    > "$m28_stamp_state/stamp-28-local-ai-docs.ok"
assert_cmd_failure "M28 rejects shared state-directory metadata drift" \
    env PATH="$m28_stamp_bin:$PATH" "$m28_stamp_invalidate"
assert_eq "$m28_stamp_uid:$m28_stamp_gid:777" \
    "$(stat -c '%u:%g:%a' "$m28_stamp_state")" \
    "M28 does not normalize drifted shared-directory metadata"
assert_grep_fixed 'must-survive' \
    "$m28_stamp_state/stamp-28-local-ai-docs.ok" \
    "M28 does not traverse a drifted shared state boundary"
rm "$m28_stamp_state/stamp-28-local-ai-docs.ok"
chmod 0755 "$m28_stamp_state"

assert_cmd_failure "M28 rejects a health-stamp candidate label failure" \
    env PATH="$m28_stamp_bin:$PATH" FAKE_RESTORECON_FAIL=all \
        "$m28_stamp_publish"
if [ ! -e "$m28_stamp_state/stamp-28-local-ai-docs.ok" ] \
   && [ -z "$(find "$m28_stamp_state" -maxdepth 1 \
        -name '.stamp-28-local-ai-docs.ok.*' -print -quit)" ]; then
    _pass "M28 candidate-label failure leaves no plausible health evidence"
else
    _fail "M28 candidate-label failure leaves no plausible health evidence"
fi

assert_cmd_failure "M28 retires a stamp after final-label failure" \
    env PATH="$m28_stamp_bin:$PATH" FAKE_RESTORECON_FAIL=final \
        "$m28_stamp_publish"
if [ ! -e "$m28_stamp_state/stamp-28-local-ai-docs.ok" ]; then
    _pass "M28 final-label failure removes the published success stamp"
else
    _fail "M28 final-label failure removes the published success stamp"
fi

assert_cmd_failure "M28 rejects an atomic health-stamp rename failure" \
    env PATH="$m28_stamp_bin:$PATH" FAKE_MV_FAIL=1 "$m28_stamp_publish"
if [ ! -e "$m28_stamp_state/stamp-28-local-ai-docs.ok" ] \
   && [ -z "$(find "$m28_stamp_state" -maxdepth 1 \
        -name '.stamp-28-local-ai-docs.ok.*' -print -quit)" ]; then
    _pass "M28 rename failure leaves no stamp or staged candidate"
else
    _fail "M28 rename failure leaves no stamp or staged candidate"
fi

assert_cmd_success "M28 publishes exact health evidence after all gates" \
    env PATH="$m28_stamp_bin:$PATH" "$m28_stamp_publish"
assert_grep_fixed 'module=28' \
    "$m28_stamp_state/stamp-28-local-ai-docs.ok"
assert_grep_fixed 'name=local-ai-docs' \
    "$m28_stamp_state/stamp-28-local-ai-docs.ok"
assert_grep_fixed 'checks_passed=23' \
    "$m28_stamp_state/stamp-28-local-ai-docs.ok"
assert_grep_fixed 'checks_total=23' \
    "$m28_stamp_state/stamp-28-local-ai-docs.ok"
assert_eq 10 \
    "$(wc -l < "$m28_stamp_state/stamp-28-local-ai-docs.ok")" \
    "M28 published health stamp has the exact ten-line schema"

# --- 1. Option ordering ----------------------------------------------------

# Extract the Option headers and their line numbers
option_a_line=$(grep -m1 -n '^## Option A' "$DOC" | cut -d: -f1 || true)
option_b_line=$(grep -m1 -n '^## Option B' "$DOC" | cut -d: -f1 || true)
option_c_line=$(grep -m1 -n '^## Option C' "$DOC" | cut -d: -f1 || true)
option_d_line=$(grep -m1 -n '^## Option D' "$DOC" | cut -d: -f1 || true)

# All four options exist
[ -n "$option_a_line" ] && _pass "Option A header found" || _fail "Option A header missing"
[ -n "$option_b_line" ] && _pass "Option B header found" || _fail "Option B header missing"
[ -n "$option_c_line" ] && _pass "Option C header found" || _fail "Option C header missing"
[ -n "$option_d_line" ] && _pass "Option D header found" || _fail "Option D header missing"

# Order is sequential
if [ -n "$option_a_line" ] && [ -n "$option_b_line" ] && [ -n "$option_c_line" ] && [ -n "$option_d_line" ]; then
    if [ "$option_a_line" -lt "$option_b_line" ] \
       && [ "$option_b_line" -lt "$option_c_line" ] \
       && [ "$option_c_line" -lt "$option_d_line" ]; then
        _pass "Options appear in order A → B → C → D"
    else
        _fail "Options are out of order (A=$option_a_line B=$option_b_line C=$option_c_line D=$option_d_line)"
    fi
fi

# --- 2. Option → tool assignment (invariant) -----

assert_grep_extended "^## Option A.*RamaLama"   "$DOC" "Option A = RamaLama"
assert_grep_fixed 'if ! option_a_line=$(grep -m1 -n' "$KS_FILE" \
    "missing Option A reaches the verification failure branch under strict mode"
assert_grep_fixed 'if ! option_b_line=$(grep -m1 -n' "$KS_FILE" \
    "missing Option B reaches the verification failure branch under strict mode"
assert_not_grep "option_a_line=\$(grep -n.*head -1" "$KS_FILE" \
    "strict pipefail cannot abort before the intended structure diagnostic"
assert_grep_fixed 'grep -qF -- "$keyword" "$AI_DOC"' "$KS_FILE" \
    "keyword verification safely accepts needles beginning with a dash"
assert_grep_extended "^## Option B.*Ollama"     "$DOC" "Option B = Ollama"
assert_grep_extended "^## Option C.*LM Studio"  "$DOC" "Option C = LM Studio"
assert_grep_extended "^## Option D.*llama.cpp"  "$DOC" "Option D = llama.cpp"

# --- 3. "Which option?" decision matrix present -----------------------------

assert_grep_fixed "Which option should you pick"   "$DOC" "'Which option?' section header present"
assert_grep_fixed "RamaLama" "$DOC" "RamaLama appears in doc"

# --- 4. RamaLama philosophical framing present ------------------------------

assert_grep_fixed "dnf install ramalama"           "$DOC" "RamaLama install uses dnf"
assert_grep_fixed "rootless-container path"        "$DOC" "RamaLama rootless container boundary mentioned"
assert_grep_fixed "network=none"                   "$DOC" "RamaLama --network=none isolation mentioned"
assert_grep_fixed "selinux=true"                   "$DOC" "RamaLama keeps SELinux labels explicitly"
assert_grep_fixed "device=none"                    "$DOC" "RamaLama CPU baseline does not leak accelerator devices"
assert_grep_fixed "pull=never"                     "$DOC" "RamaLama reviewed artifacts are not silently refreshed"
assert_grep_fixed "--webui on"                     "$DOC" "RamaLama browser UI mode is explicit"
assert_grep_fixed "--webui off"                    "$DOC" "RamaLama editor/headless mode is explicit"
assert_grep_fixed "can also select a host backend" "$DOC" \
    "RamaLama container use is verified rather than inferred"
assert_grep_fixed 'Hosted API transports such as `openai://`' "$DOC" \
    "RamaLama remote-provider transport is an explicit egress boundary"
assert_grep_fixed 'audited `serve` default was the' "$DOC" \
    "RamaLama wildcard default justifies the explicit loopback bind"
assert_grep_fixed 'must not contain' "$DOC" \
    "RamaLama dry-run rejects SELinux label disablement"

# --- 5. Ollama security section preserved (not silently dropped) -----------

assert_grep_fixed "CVE-2025-63389"                 "$DOC" "Ollama CVE-2025-63389 warning preserved"
assert_grep_fixed "CVE-2026-7482"                  "$DOC" "affected Fedora Ollama candidate is rejected"
assert_grep_fixed "CVE-2026-5757"                  "$DOC" "unresolved Ollama model-processing advisory is tracked"
assert_grep_fixed "CVE-2026-15685"                 "$DOC" "Ollama downloadBlob advisory is reviewed"
assert_grep_fixed "9239a254e054"                   "$DOC" "Ollama empty-digest guard is traced to upstream"
assert_grep_fixed "CVE-2026-65315"                 "$DOC" "Ollama GGUF allocation advisory is reviewed"
assert_grep_fixed "67b6a1c2d453"                   "$DOC" "Ollama GGUF repair is traced to upstream"
assert_grep_fixed "issue 17041"                    "$DOC" "open Ollama tensor-redirect SSRF is tracked"
assert_grep_fixed 'without rejecting loopback, private or' "$DOC" \
    "reviewed Ollama redirect path remains explicitly unresolved"
assert_grep_fixed 'routes the digest through `manifest.BlobsPath` before any' "$DOC" \
    "reviewed Ollama source validates digests before array slicing"
assert_grep_fixed 'caps strings, arrays and tensor dimensions' "$DOC" \
    "reviewed Ollama source retains GGUF allocation bounds"
assert_grep_fixed "ollama-0.12.11-4.fc44"          "$DOC" "audited Fedora 44 candidate is named exactly"
assert_grep_fixed "ollama_version=v0.32.15"        "$DOC" "current reviewed Ollama release is pinned exactly"
assert_grep_fixed "50539c5fe9bf85887733355098dcdb266b433cb8c73fa180713417e9ed6e42bb" "$DOC" \
    "current reviewed Ollama artifact is pinned independently"
assert_grep_fixed 'version probe reported'$'\n''0.32.15' "$DOC" \
    "executed Ollama version probe matches the current reviewed release"
assert_grep_fixed 'github.com/ollama/ollama/releases/download/$ollama_version' "$DOC" \
    "Ollama evaluation pins one exact upstream release"
assert_grep_fixed 'sha256sum --check selected.sha256' "$DOC" \
    "Ollama release payload uses the vendor checksum manifest"
assert_grep_fixed 'test "$(wc -l < "$ollama_stage/selected.sha256")" -eq 1' "$DOC" \
    "Ollama checksum selection must resolve exactly one artifact"
assert_grep_fixed 'cut -d'\'' '\'' -f1 < "$ollama_stage/selected.sha256")" = "$ollama_expected"' "$DOC" \
    "Ollama vendor checksum is compared with the retained review pin"
assert_grep_fixed 'tar --zstd -tf' "$DOC" \
    "Ollama archive is inspected before extraction"
assert_grep_fixed '[[ ! $ollama_version =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]' "$DOC" \
    "Ollama version input is a complete semantic release token"
assert_not_grep_extended 'sudo[[:space:]]+sh[[:space:]]+.*/ollama-install\.sh' "$DOC" \
    "documentation never executes the mutable Ollama installer as root"
assert_grep_fixed "OLLAMA_NO_CLOUD=1"              "$DOC" "Ollama cloud features are disabled explicitly"
assert_grep_fixed 'was executed offline in a network-unshared sandbox' "$DOC" \
    "current Ollama client receives an offline runtime compatibility probe"
assert_grep_fixed 'absolute/traversal paths or special device entries' "$DOC" \
    "current Ollama archive shape was inspected before the pin moved"
assert_grep_fixed "OLLAMA_VULKAN=1"                "$DOC" "current Ollama Vulkan opt-in is documented"
assert_grep_fixed "GGML_VK_VISIBLE_DEVICES"        "$DOC" "current Ollama Vulkan device selection is documented"
assert_grep_fixed 'stale `OLLAMA_VULKAN=0`'        "$DOC" "obsolete Ollama Vulkan recipe is rejected"
assert_not_grep '^export OLLAMA_VULKAN=0'           "$DOC" \
    "obsolete Ollama Vulkan disable variable is not an active recipe"
assert_not_grep   '^Environment="OLLAMA_LLM_LIBRARY=vulkan"' "$DOC" \
    "obsolete Ollama Vulkan variable is not an active recipe"
assert_grep_fixed 'OLLAMA_HOST=127.0.0.1:11434'     "$DOC" "Ollama service is loopback-bound"
assert_grep_fixed 'requires no authentication'      "$DOC" "current Ollama local API authentication boundary is explicit"

# --- 5b. Reviewed current llama.cpp boundary --------------------------------

assert_grep_fixed 'llama_cpp_build=b10605' "$DOC" \
    "current reviewed llama.cpp build is pinned exactly"
assert_grep_fixed 'llama-b10605-bin-ubuntu-vulkan-x64.tar.gz' "$DOC" \
    "reviewed Linux Vulkan artifact is named exactly"
assert_grep_fixed 'e19d439953b4ccc8ce8fb17963d2882658573cbbce7a753543e0791ffbeff350' "$DOC" \
    "reviewed llama.cpp artifact is pinned to the GitHub digest"
assert_grep_fixed '32,911,942-byte archive' "$DOC" \
    "reviewed llama.cpp artifact byte count is pinned exactly"
assert_grep_fixed 'release build 10605 at commit `a130532ae`' "$DOC" \
    "executed llama.cpp identity matches the reviewed release"
assert_grep_fixed 'github.com/ggml-org/llama.cpp/releases/download/$llama_cpp_build' "$DOC" \
    "llama.cpp release download is version-specific"
assert_grep_fixed 'executed offline in a network-unshared' "$DOC" \
    "current llama.cpp binary receives an offline runtime compatibility probe"
assert_grep_fixed 'does not repeat the model/performance record' "$DOC" \
    "current CLI verification is not overstated as a repeated benchmark"
assert_grep_fixed 'tar --no-same-owner --no-same-permissions --strip-components=1' "$DOC" \
    "reviewed llama.cpp archive is extracted without owner/permission trust"
assert_grep_fixed 'tensor overrides' "$DOC" \
    "automatic-fit conflict with CPU-MoE tensor overrides is explicit"
assert_grep_fixed 'Never claim a target reserve from the command line alone' "$DOC" \
    "VRAM reserve requires observed evidence"

# --- 6. Maintained editor + full owner-agent boundaries ---------------------

# llama-vscode is pinned to the audited behavior, and NoID Privacy's owner profile
# receives local file/terminal tools without accidentally enabling
# remote/default installer paths.
assert_grep_extended "^## VSCodium integration" "$DOC" "editor-integration section present"
assert_grep_fixed "llama-vscode"       "$DOC" "llama-vscode editor option documented"
assert_grep_fixed "Cline"              "$DOC" "Cline documented (agentic alternative)"
assert_grep_fixed "Do not infer privacy from the VSCodium core" "$DOC" \
    "agent extension privacy boundary is explicit"
assert_grep_fixed "/infill"            "$DOC" "FIM /infill architecture documented"
assert_grep_fixed 'curl -LsSf https://llama.app/install.sh | sh' "$DOC" \
    "llama-vscode mutable installer action is disclosed but not used"
assert_grep_fixed 'llama_vscode_version=0.0.63' "$DOC" \
    "llama-vscode package version is pinned to the reviewed Open VSX release"
assert_grep_fixed '7fe75977590fe7f21ba72567bf1a99129b9fe5413f740eec4c50165afce89e65' "$DOC" \
    "llama-vscode package bytes are pinned to the reviewed digest"
assert_grep_fixed 'registry.sha256' "$DOC" \
    "llama-vscode registry checksum is compared with the retained review pin"
assert_grep_fixed '.publisher == "ggml-org"' "$DOC" \
    "llama-vscode package identity is inspected before installation"
assert_grep_fixed '.engines.vscode == "^1.109.0"' "$DOC" \
    "llama-vscode package compatibility floor is inspected before installation"
assert_grep_fixed 'provides `llama-server` but no `llama` command' "$DOC" \
    "Fedora/runtime detection mismatch is explicit"
assert_grep_fixed 'select remote OpenRouter endpoints' "$DOC" \
    "llama-vscode remote provider and agent-tool paths are explicit"
assert_grep_fixed '"llama-vscode.ask_install_llamacpp": false' "$DOC" \
    "llama-vscode cannot offer its mutable runtime installer"
assert_grep_fixed '"llama-vscode.env_start_last_used": false' "$DOC" \
    "llama-vscode cannot autostart an unreviewed environment"
assert_grep_fixed '"llama-vscode.ai_model": ""' "$DOC" \
    "llama-vscode remote-looking default model name is cleared"
assert_grep_fixed '"llama-vscode.agent_rules": "AGENTS.md"' "$DOC" \
    "llama-vscode receives the repository policy as agent context"
assert_grep_fixed '"llama-vscode.scripts_folder": "/var/empty"' "$DOC" \
    "llama-vscode cannot discover repository-owned DSL scripts by default"
assert_grep_fixed '"llama-vscode.only_one_local_model": false' "$DOC" \
    "independent completion/chat/tool profiles remain available"
assert_grep_fixed 'selected DSL script can run' "$DOC" \
    "llama-vscode script-command authority is disclosed"
assert_grep_fixed '"llama-vscode.endpoint": ""' "$DOC" \
    "unconfigured FIM endpoint cannot generate background errors"
assert_grep_fixed '"llama-vscode.auto": false' "$DOC" \
    "automatic FIM stays off until a reviewed FIM model exists"
assert_grep_fixed '"llama-vscode.lm_max_input_tokens": 0' "$DOC" \
    "llama-vscode discovers local runtime input limits"
assert_grep_fixed '"llama-vscode.lm_max_output_tokens": 0' "$DOC" \
    "llama-vscode discovers local runtime output limits"
assert_grep_fixed '"llama-vscode.rag_enabled": false' "$DOC" \
    "unsafe llama-vscode incremental RAG path stays disabled"
assert_grep_fixed 'without either ignore check or a workspace-boundary check' "$DOC" \
    "llama-vscode 0.0.63 incremental RAG defect is explicit"
assert_grep_fixed 'File search/read tools remain' "$DOC" \
    "RAG mitigation does not remove owner file context"
assert_grep_fixed '"llama-vscode.auto_memory_enabled": true' "$DOC" \
    "owner profile receives cross-session local memory"
assert_grep_fixed '"llama-vscode.tool_multi_edit_file_enabled": true' "$DOC" \
    "owner profile includes the reviewed multi-file edit tool"
assert_grep_fixed '"llama-vscode.reminder_edit_file_frequency": 5' "$DOC" \
    "edit-tool reminder cadence is explicit"
assert_grep_fixed '"llama-vscode.tool_permit_some_terminal_commands": true' "$DOC" \
    "owner profile removes avoidable terminal confirmations"
assert_grep_fixed '"llama-vscode.tool_permit_file_changes": true' "$DOC" \
    "owner profile permits unconfirmed file edits"
assert_grep_fixed '"llama-vscode.tool_permit_file_delete": true' "$DOC" \
    "owner profile deliberately permits workspace-root file deletion"
assert_grep_fixed 'external `vscode://ggml-org.llama-vscode/' "$DOC" \
    "llama-vscode external URI-handler boundary is explicit"
assert_grep_fixed 'commands classified as' "$DOC" \
    "llama-vscode's unavoidable modifying-command prompt is disclosed"
assert_grep_fixed '--tools all --ui --no-ui-mcp-proxy' "$DOC" \
    "browser owner profile gets all local built-in tools without MCP proxy"
assert_grep_fixed '**Always allow**' "$DOC" \
    "browser owner profile removes per-tool confirmation"
assert_grep_fixed '60 seconds and 16 KiB' "$DOC" \
    "llama.cpp built-in shell limits are not hidden"
assert_grep_fixed '4096 tokens are usually too small' "$DOC" \
    "full agent tool-schema context cannot silently remain at 4K"
assert_grep_fixed '--reasoning on|off' "$DOC" \
    "current reasoning-mode control is documented"
assert_grep_fixed 'deprecated `--chat-template-kwargs' "$DOC" \
    "deprecated reasoning configuration is rejected"
assert_grep_fixed 'full owner mode and optional isolation' "$DOC" \
    "sandbox is optional rather than imposed on the owner workflow"
assert_grep_fixed 'LoadCredential=api-key:' "$DOC" \
    "optional service supplies its API key as a systemd credential"
assert_grep_fixed '${CREDENTIALS_DIRECTORY}/api-key' "$DOC" \
    "optional service consumes the credential from its protected runtime path"

# --- 7. Removal/update boundary ---------------------------------------------

assert_grep_fixed "sudo dnf remove ramalama"       "$DOC" "RamaLama removal command"
assert_grep_fixed "Uninstalling a runtime does not automatically" "$DOC" \
    "runtime removal does not overclaim data cleanup"

# --- 8. Hardware and socket verification -----------------------------------

assert_grep_fixed "Hardware check"                 "$DOC"
assert_grep_fixed "nvidia-smi"                     "$DOC"
assert_grep_fixed "CPU-only"                       "$DOC" "CPU-only baseline remains explicit"
assert_grep_fixed "Intel Arc"                      "$DOC" "Intel Arc path remains explicitly scoped"
assert_grep_fixed "ss -ltnp"                       "$DOC" "listener verification documented"
assert_grep_fixed '`0.0.0.0:8080` or `[::]:8080` listener' "$DOC" \
    "non-loopback bind is rejected"

# --- 8b. MoE expert-offload + agent-tool sandbox sections -------------------
# Expert-offload claims are explicitly build/backend scoped, and tool-enabled
# servers have a systemd sandbox plus an effect-verification command.

assert_grep_fixed "n-cpu-moe"       "$DOC" "MoE expert-offload (--n-cpu-moe) documented"
assert_grep_fixed "override-tensor" "$DOC" "MoE -ot/--override-tensor documented"
assert_grep_fixed "not available or" "$DOC" "MoE flags are not claimed universal"
assert_grep_fixed '96c11c22b1128c3c8c655b21557b409f307c557f' "$DOC" \
    "Gemma reference model is tied to an immutable publisher revision"
assert_grep_fixed '295121f61edeedaa8604bcaf3171831981c546c3a10a210cea87dc992eb429ae' "$DOC" \
    "Gemma reference GGUF bytes are pinned"
assert_grep_fixed '383064f72a1ef3087b779f268d3ca117eb989aac' "$DOC" \
    "Ornith reference model is tied to an immutable publisher revision"
assert_grep_fixed 'ff25291b2599fb927a835e624d2b3540106af61761c3fa57ac4264046dbec002' "$DOC" \
    "Ornith reference GGUF bytes are pinned"
assert_grep_fixed '85bf2b98cdcbad4291cb4f46943526cc089f75a0' "$DOC" \
    "Ornith 1.5 9B candidate is tied to an immutable publisher revision"
assert_grep_fixed '7d791afcb31812acc88cd5aafc675391df28c6fc3d8eae002bb4e6cc3d8cfd8d' "$DOC" \
    "Ornith 1.5 9B candidate bytes are pinned"
assert_grep_fixed 'fbbaed45c2f0e200276ffa51701a24d45dc7f57e' "$DOC" \
    "Ornith 1.5 35B candidate is tied to an immutable publisher revision"
assert_grep_fixed 'ca6ea26329c88b78ffd90a85163be2e746c2fafd1024f56db47e499f117f9a7f' "$DOC" \
    "Ornith 1.5 35B candidate bytes are pinned"
assert_grep_fixed 'publisher claims, not reproduced NoID Privacy' "$DOC" \
    "new Ornith capabilities are not overstated as local validation"
assert_grep_fixed 'Llama 4 Scout and' "$DOC" \
    "current official Llama family is acknowledged without an invented local pin"
assert_grep_fixed '--ctx-size 32768 --parallel 1 --jinja' "$DOC" \
    "measured reference agent slot has a useful 32K context"
assert_grep_fixed 'gpu_layers=27' "$DOC" \
    "Gemma 4-GiB reference placement is explicit"
assert_grep_fixed 'gpu_layers=41' "$DOC" \
    "Ornith 4-GiB reference placement is explicit"
assert_grep_fixed '--fit off --load-mode mmap' "$DOC" \
    "reference placement uses the actually measured load/fit mode"
assert_grep_fixed '20 generated tokens/s was therefore **not** achieved' "$DOC" \
    "reference-host throughput is reported without a false 20 tok/s claim"
assert_grep_fixed "NoNewPrivileges" "$DOC" "agent-tool systemd sandbox documented"
assert_grep_fixed "CapabilityBoundingSet=" "$DOC" "agent service has an empty capability bounding set"
assert_grep_fixed "StateDirectory=noid-agent-scratch" "$DOC" \
    "agent scratch uses systemd-managed writable state"
assert_grep_fixed "systemd-analyze security" "$DOC" "sandbox verification documented"

# --- 9. heredoc <-> docs/28-local-ai.md twin in sync ------------------------
# docs/28-local-ai.md is the canonical source for the M28 AI_DOC_EOF heredoc.
# Assert byte identity and the dedicated generator's check mode.
DOCS_TWIN="$PROJECT_ROOT/docs/28-local-ai.md"
if [ -f "$DOCS_TWIN" ]; then
    if diff -q "$DOC" "$DOCS_TWIN" >/dev/null 2>&1; then
        _pass "docs/28-local-ai.md byte-identical to M28 AI_DOC_EOF heredoc"
    else
        _fail "docs/28-local-ai.md DRIFTED from M28 heredoc (re-sync the docs copy with the shipped heredoc)"
    fi
else
    _fail "docs/28-local-ai.md twin missing"
fi
assert_cmd_success "regen-local-ai-doc.sh --check" \
    "$PROJECT_ROOT/scripts/regen-local-ai-doc.sh" --check
assert_eq 4 "$(grep -c '^set -euo pipefail$' "$TMPDIR/28-local-ai.md")" \
    "all four artifact-consuming blocks fail closed on digest or identity drift"

test_finish

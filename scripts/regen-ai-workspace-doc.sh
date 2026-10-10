#!/usr/bin/env bash
# Sync the installed M08 AI-workspace heredoc from docs/ai-workspace.md.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LIB="$REPO_ROOT/scripts/lib/source-generator.sh"
# shellcheck source=scripts/lib/source-generator.sh
. "$LIB"
SRC=${NOID_AI_WORKSPACE_SRC:-$REPO_ROOT/docs/ai-workspace.md}
TARGET=${NOID_AI_WORKSPACE_M08:-$REPO_ROOT/kickstart/snippets/08-service-minimization.ks}
OPENING="<<'AI_WORKSPACE_DOC_EOF'"
CLOSING=AI_WORKSPACE_DOC_EOF

log() { echo "[regen-ai-workspace-doc] $*"; }
usage() { echo "Usage: scripts/regen-ai-workspace-doc.sh [--check]"; }
noid_generator_parse_cli "$@" || { usage >&2; exit 2; }
[ "$NOID_GENERATOR_MODE" != help ] || { usage; exit 0; }
noid_generator_require_tools bash cat head || exit 2
noid_generator_require_source "$SRC" "$CLOSING" || exit 2
noid_generator_marker_pair "$TARGET" "$OPENING" "$CLOSING" || exit 3
start=$NOID_GENERATOR_START
end=$NOID_GENERATOR_END

if noid_generator_block_matches "$TARGET" "$SRC" "$OPENING" "$CLOSING"; then
    log "IN SYNC: M08 heredoc matches docs/ai-workspace.md"
    exit 0
fi
[ "$NOID_GENERATOR_MODE" != check ] \
    || { log "DRIFT DETECTED: run scripts/regen-ai-workspace-doc.sh"; exit 1; }

noid_generator_install_traps
noid_generator_new_candidate "$TARGET" || exit 4
tmp=$NOID_GENERATOR_PATH
head -n "$start" "$TARGET" > "$tmp"
cat "$SRC" >> "$tmp"
tail -n +"$end" "$TARGET" >> "$tmp"
bash -n "$tmp" || { log "ERROR: generated candidate is invalid Bash"; exit 4; }
noid_generator_block_matches "$tmp" "$SRC" "$OPENING" "$CLOSING" \
    || { log "ERROR: generated candidate failed byte parity"; exit 4; }
noid_generator_publish "$tmp" "$TARGET" || exit 4
log "OK: M08 heredoc validated and published atomically"

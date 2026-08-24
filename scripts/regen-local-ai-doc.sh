#!/usr/bin/env bash
# Sync the M28 installed-document heredoc from docs/28-local-ai.md.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LIB="$REPO_ROOT/scripts/lib/source-generator.sh"
# shellcheck source=scripts/lib/source-generator.sh
. "$LIB"
SRC=${NOID_LOCAL_AI_SRC:-$REPO_ROOT/docs/28-local-ai.md}
TARGET=${NOID_LOCAL_AI_M28:-$REPO_ROOT/kickstart/snippets/28-local-ai-docs.ks}
OPENING="<<'AI_DOC_EOF'"
CLOSING=AI_DOC_EOF

log() { echo "[regen-local-ai-doc] $*"; }
usage() { echo "Usage: scripts/regen-local-ai-doc.sh [--check]"; }
noid_generator_parse_cli "$@" || { usage >&2; exit 2; }
[ "$NOID_GENERATOR_MODE" != help ] || { usage; exit 0; }
noid_generator_require_tools bash cat cut diff grep head mktemp mv od readlink \
    sed stat tail tr || exit 2
noid_generator_require_source "$SRC" "$CLOSING" || exit 2
noid_generator_marker_pair "$TARGET" "$OPENING" "$CLOSING" || exit 3
start=$NOID_GENERATOR_START
end=$NOID_GENERATOR_END

if noid_generator_block_matches "$TARGET" "$SRC" "$OPENING" "$CLOSING"; then
    log "IN SYNC: M28 heredoc matches docs/28-local-ai.md"
    exit 0
fi
[ "$NOID_GENERATOR_MODE" != check ] \
    || { log "DRIFT DETECTED: run scripts/regen-local-ai-doc.sh"; exit 1; }

tmp=$(noid_generator_temp_for "$TARGET") || exit 4
trap 'rm -f -- "$tmp"' EXIT HUP INT TERM
head -n "$start" "$TARGET" > "$tmp"
cat "$SRC" >> "$tmp"
tail -n +"$end" "$TARGET" >> "$tmp"
bash -n "$tmp" || { log "ERROR: generated candidate is invalid Bash"; exit 4; }
noid_generator_block_matches "$tmp" "$SRC" "$OPENING" "$CLOSING" \
    || { log "ERROR: generated candidate failed byte parity"; exit 4; }
noid_generator_publish "$tmp" "$TARGET" || exit 4
trap - EXIT HUP INT TERM
log "OK: M28 heredoc regenerated and validated before atomic publication"

#!/usr/bin/env bash
# Sync the M06 installed-document heredoc from docs/wan-egress-strict.md.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LIB="$REPO_ROOT/scripts/lib/source-generator.sh"
# shellcheck source=scripts/lib/source-generator.sh
. "$LIB"
SRC=${NOID_WAN_STRICT_DOC_SRC:-$REPO_ROOT/docs/wan-egress-strict.md}
TARGET=${NOID_WAN_STRICT_M06:-$REPO_ROOT/kickstart/snippets/06-vpn-killswitch.ks}
OPENING="<<'DOC_EOF'"
CLOSING=DOC_EOF

log() { echo "[regen-wan-strict-doc] $*"; }
usage() { echo "Usage: scripts/regen-wan-strict-doc.sh [--check]"; }
noid_generator_parse_cli "$@" || { usage >&2; exit 2; }
[ "$NOID_GENERATOR_MODE" != help ] || { usage; exit 0; }
noid_generator_require_tools bash cat cut diff grep head mktemp mv od readlink \
    sed stat tail tr || exit 2
noid_generator_require_source "$SRC" "$CLOSING" || exit 2
noid_generator_marker_pair "$TARGET" "$OPENING" "$CLOSING" || exit 3
start=$NOID_GENERATOR_START
end=$NOID_GENERATOR_END

if noid_generator_block_matches "$TARGET" "$SRC" "$OPENING" "$CLOSING"; then
    log "IN SYNC: M06 heredoc matches docs/wan-egress-strict.md"
    exit 0
fi
[ "$NOID_GENERATOR_MODE" != check ] \
    || { log "DRIFT DETECTED: run scripts/regen-wan-strict-doc.sh"; exit 1; }

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
log "OK: M06 heredoc regenerated and validated before atomic publication"

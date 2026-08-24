#!/usr/bin/env bash
# Regenerate the deterministic gzip+base64 Thunderbird hardening embed in M35.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LIB="$REPO_ROOT/scripts/lib/source-generator.sh"
# shellcheck source=scripts/lib/source-generator.sh
. "$LIB"
SRC=${NOID_THUNDERBIRD_EMBED_SRC:-$REPO_ROOT/thunderbird/noid-thunderbird-hardening.js}
TARGET=${NOID_THUNDERBIRD_EMBED_M35:-$REPO_ROOT/kickstart/snippets/35-thunderbird.ks}
OPENING="base64 -d <<'TB_HARDENING_GZ_B64_EOF' | gunzip > \"\$USERJS_CANDIDATE\""
CLOSING=TB_HARDENING_GZ_B64_EOF

log() { echo "[regen-thunderbird-embed] $*"; }
usage() { echo "Usage: scripts/regen-thunderbird-embed.sh [--check]"; }
noid_generator_parse_cli "$@" || { usage >&2; exit 2; }
[ "$NOID_GENERATOR_MODE" != help ] || { usage; exit 0; }
noid_generator_require_tools base64 bash cat cmp cut diff grep gzip head mktemp \
    mv od readlink sed stat tail tr wc || exit 2
noid_generator_require_source "$SRC" "$CLOSING" || exit 2
noid_generator_marker_pair "$TARGET" "$OPENING" "$CLOSING" || exit 3
start=$NOID_GENERATOR_START
end=$NOID_GENERATOR_END

fresh=$(mktemp "${TARGET}.fresh.XXXXXX")
tmp=''
trap 'rm -f -- "$fresh" "$tmp"' EXIT HUP INT TERM
gzip -n -c -- "$SRC" | base64 -w 76 > "$fresh"
if noid_generator_block_matches "$TARGET" "$fresh" "$OPENING" "$CLOSING"; then
    log "IN SYNC: M35 embed matches the Thunderbird source"
    exit 0
fi
[ "$NOID_GENERATOR_MODE" != check ] \
    || { log "DRIFT DETECTED: run scripts/regen-thunderbird-embed.sh"; exit 1; }

tmp=$(noid_generator_temp_for "$TARGET") || exit 4
head -n "$start" "$TARGET" > "$tmp"
cat "$fresh" >> "$tmp"
tail -n +"$end" "$TARGET" >> "$tmp"
bash -n "$tmp" || { log "ERROR: generated candidate is invalid Bash"; exit 4; }
noid_generator_block_matches "$tmp" "$fresh" "$OPENING" "$CLOSING" \
    || { log "ERROR: candidate embed differs from deterministic payload"; exit 4; }
sed -n "$((start + 1)),$((start + $(wc -l < "$fresh")))p" "$tmp" \
    | base64 -d | gzip -dc | cmp -s - "$SRC" \
    || { log "ERROR: candidate embed does not decode to the source bytes"; exit 4; }
noid_generator_publish "$tmp" "$TARGET" || exit 4
tmp=''
trap - EXIT HUP INT TERM
rm -f -- "$fresh"
log "OK: M35 embed validated and published atomically"

#!/usr/bin/env bash
# Sync M35's Thunderbird AutoConfig heredoc from thunderbird/mozilla.cfg.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LIB="$REPO_ROOT/scripts/lib/source-generator.sh"
# shellcheck source=scripts/lib/source-generator.sh
. "$LIB"
SRC=${NOID_THUNDERBIRD_CFG_SRC:-$REPO_ROOT/thunderbird/mozilla.cfg}
TARGET=${NOID_THUNDERBIRD_CFG_M35:-$REPO_ROOT/kickstart/snippets/35-thunderbird.ks}
OPENING="cat > \"\$MOZILLA_CFG_CANDIDATE\" <<'MOZILLA_CFG_EOF'"
CLOSING=MOZILLA_CFG_EOF

log() { echo "[regen-thunderbird-mozilla-cfg] $*"; }
usage() { echo "Usage: scripts/regen-thunderbird-mozilla-cfg.sh [--check]"; }
noid_generator_parse_cli "$@" || { usage >&2; exit 2; }
[ "$NOID_GENERATOR_MODE" != help ] || { usage; exit 0; }
noid_generator_require_tools bash cat cut diff grep head mktemp mv od readlink \
    sed stat tail tr || exit 2
noid_generator_require_source "$SRC" "$CLOSING" || exit 2
noid_generator_marker_pair "$TARGET" "$OPENING" "$CLOSING" || exit 3
start=$NOID_GENERATOR_START
end=$NOID_GENERATOR_END

if noid_generator_block_matches "$TARGET" "$SRC" "$OPENING" "$CLOSING"; then
    log "IN SYNC: M35 AutoConfig matches thunderbird/mozilla.cfg"
    exit 0
fi
[ "$NOID_GENERATOR_MODE" != check ] \
    || { log "DRIFT DETECTED: run scripts/regen-thunderbird-mozilla-cfg.sh"; exit 1; }

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
log "OK: M35 AutoConfig validated and published atomically"

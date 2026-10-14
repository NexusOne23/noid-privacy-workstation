#!/usr/bin/env bash
# Keep M17's user-side complete-quit helper identical to repo source.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LIB="$REPO_ROOT/scripts/lib/source-generator.sh"
# shellcheck source=scripts/lib/source-generator.sh
. "$LIB"

TARGET=${NOID_GS_QUIT_M17:-$REPO_ROOT/kickstart/snippets/17-gnome-hardening.ks}
SOURCE=${NOID_GS_QUIT_SOURCE:-$REPO_ROOT/scripts/noid-gnome-software-quit.sh}
OPENING="cat > /usr/local/bin/noid-gnome-software-quit <<'NOID_GS_QUIT_EOF'"
CLOSING=NOID_GS_QUIT_EOF

log() { echo "[regen-gnome-software-quit-embed] $*"; }
usage() { echo "Usage: scripts/regen-gnome-software-quit-embed.sh [--check]"; }
noid_generator_parse_cli "$@" || { usage >&2; exit 2; }
[[ $NOID_GENERATOR_MODE != help ]] || { usage; exit 0; }
noid_generator_require_tools bash cat head || exit 2
noid_generator_require_source "$SOURCE" "$CLOSING" || exit 2
noid_generator_marker_pair "$TARGET" "$OPENING" "$CLOSING" || exit 3

if noid_generator_block_matches "$TARGET" "$SOURCE" "$OPENING" "$CLOSING"; then
    log "IN SYNC: M17 GNOME Software complete-quit helper matches canonical source"
    exit 0
fi
[[ $NOID_GENERATOR_MODE != check ]] || {
    log "DRIFT DETECTED: run scripts/regen-gnome-software-quit-embed.sh"
    exit 1
}

noid_generator_install_traps
noid_generator_new_candidate "$TARGET" || exit 4
candidate=$NOID_GENERATOR_PATH
start=$NOID_GENERATOR_START
end=$NOID_GENERATOR_END
{
    head -n "$start" "$TARGET"
    cat "$SOURCE"
    tail -n +"$end" "$TARGET"
} > "$candidate"
chmod --reference="$TARGET" "$candidate"
bash -n "$candidate" || { log "ERROR: generated M17 candidate is invalid Bash"; exit 4; }
noid_generator_block_matches "$candidate" "$SOURCE" "$OPENING" "$CLOSING" \
    || { log "ERROR: generated helper block differs from canonical source"; exit 4; }
noid_generator_publish "$candidate" "$TARGET" || exit 4
log "OK: M17 GNOME Software complete-quit helper published atomically"

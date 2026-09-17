#!/usr/bin/env bash
# Keep M17's Live-installer WebUI lifecycle helper identical to its source.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LIB="$REPO_ROOT/scripts/lib/source-generator.sh"
# shellcheck source=scripts/lib/source-generator.sh
. "$LIB"

TARGET=${NOID_LIVEINST_LIFECYCLE_M17:-$REPO_ROOT/kickstart/snippets/17-gnome-hardening.ks}
SOURCE=${NOID_LIVEINST_LIFECYCLE_SOURCE:-$REPO_ROOT/scripts/noid-liveinst-webui-lifecycle.py}
OPENING="cat > /usr/local/libexec/noid-liveinst-webui-lifecycle <<'NOID_LIVEINST_WEBUI_LIFECYCLE_EOF'"
CLOSING=NOID_LIVEINST_WEBUI_LIFECYCLE_EOF

log() { echo "[regen-liveinst-webui-lifecycle-embed] $*"; }
usage() { echo "Usage: scripts/regen-liveinst-webui-lifecycle-embed.sh [--check]"; }
noid_generator_parse_cli "$@" || { usage >&2; exit 2; }
[ "$NOID_GENERATOR_MODE" != help ] || { usage; exit 0; }
noid_generator_require_tools bash cat chmod diff grep head mktemp mv od \
    readlink sed stat tail tr wc || exit 2
noid_generator_require_source "$SOURCE" "$CLOSING" || exit 2
noid_generator_marker_pair "$TARGET" "$OPENING" "$CLOSING" || exit 3

if noid_generator_block_matches "$TARGET" "$SOURCE" "$OPENING" "$CLOSING"; then
    log "IN SYNC: M17 Live-installer lifecycle helper matches canonical source"
    exit 0
fi
[ "$NOID_GENERATOR_MODE" != check ] || {
    log "DRIFT DETECTED: run scripts/regen-liveinst-webui-lifecycle-embed.sh"
    exit 1
}

candidate=$(noid_generator_temp_for "$TARGET") || exit 4
trap 'rm -f -- "$candidate"' EXIT HUP INT TERM
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
candidate=''
trap - EXIT HUP INT TERM
log "OK: M17 Live-installer lifecycle helper published atomically"

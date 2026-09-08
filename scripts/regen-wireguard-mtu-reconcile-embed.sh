#!/usr/bin/env bash
# Keep M06's installed live-only WireGuard MTU reconciler byte-identical to source.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LIB="$REPO_ROOT/scripts/lib/source-generator.sh"
# shellcheck source=scripts/lib/source-generator.sh
. "$LIB"

TARGET=${NOID_WG_MTU_M06:-$REPO_ROOT/kickstart/snippets/06-vpn-killswitch.ks}
SOURCE=${NOID_WG_MTU_SOURCE:-$REPO_ROOT/scripts/noid-wireguard-mtu-reconcile.sh}
OPENING="cat > /usr/local/sbin/noid-wireguard-mtu-reconcile <<'NOID_WG_MTU_EOF'"
CLOSING=NOID_WG_MTU_EOF

log() { echo "[regen-wireguard-mtu-reconcile-embed] $*"; }
usage() { echo "Usage: scripts/regen-wireguard-mtu-reconcile-embed.sh [--check]"; }
noid_generator_parse_cli "$@" || { usage >&2; exit 2; }
[ "$NOID_GENERATOR_MODE" != help ] || { usage; exit 0; }
noid_generator_require_tools bash cat chmod diff grep head mktemp mv od \
    readlink sed stat tail tr wc || exit 2
noid_generator_require_source "$SOURCE" "$CLOSING" || exit 2
noid_generator_marker_pair "$TARGET" "$OPENING" "$CLOSING" || exit 3

if noid_generator_block_matches "$TARGET" "$SOURCE" "$OPENING" "$CLOSING"; then
    log "IN SYNC: M06 WireGuard MTU reconciler matches canonical source"
    exit 0
fi
[ "$NOID_GENERATOR_MODE" != check ] || {
    log "DRIFT DETECTED: run scripts/regen-wireguard-mtu-reconcile-embed.sh"
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
bash -n "$candidate" || { log "ERROR: generated M06 candidate is invalid Bash"; exit 4; }
noid_generator_block_matches "$candidate" "$SOURCE" "$OPENING" "$CLOSING" \
    || { log "ERROR: generated reconciler differs from canonical source"; exit 4; }
noid_generator_publish "$candidate" "$TARGET" || exit 4
candidate=''
trap - EXIT HUP INT TERM
log "OK: M06 WireGuard MTU reconciler published atomically"

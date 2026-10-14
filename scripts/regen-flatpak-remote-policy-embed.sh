#!/usr/bin/env bash
# Keep M18's installed Flatpak policy controller byte-identical to source.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LIB="$REPO_ROOT/scripts/lib/source-generator.sh"
# shellcheck source=scripts/lib/source-generator.sh
. "$LIB"

TARGET=${NOID_FLATPAK_POLICY_M18:-$REPO_ROOT/kickstart/snippets/18-flatpak-sandboxing.ks}
SOURCE=${NOID_FLATPAK_POLICY_SOURCE:-$REPO_ROOT/scripts/noid-flatpak-remote-policy.sh}
OPENING="cat > /usr/local/libexec/noid-flatpak-remote-policy <<'NOID_FLATPAK_POLICY_EOF'"
CLOSING=NOID_FLATPAK_POLICY_EOF

log() { echo "[regen-flatpak-remote-policy-embed] $*"; }
usage() { echo "Usage: scripts/regen-flatpak-remote-policy-embed.sh [--check]"; }
noid_generator_parse_cli "$@" || { usage >&2; exit 2; }
[ "$NOID_GENERATOR_MODE" != help ] || { usage; exit 0; }
noid_generator_require_tools bash cat head || exit 2
noid_generator_require_source "$SOURCE" "$CLOSING" || exit 2
noid_generator_marker_pair "$TARGET" "$OPENING" "$CLOSING" || exit 3

if noid_generator_block_matches "$TARGET" "$SOURCE" "$OPENING" "$CLOSING"; then
    log "IN SYNC: M18 Flatpak controller matches canonical source"
    exit 0
fi
[ "$NOID_GENERATOR_MODE" != check ] || {
    log "DRIFT DETECTED: run scripts/regen-flatpak-remote-policy-embed.sh"
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
bash -n "$candidate" || { log "ERROR: generated M18 candidate is invalid Bash"; exit 4; }
noid_generator_block_matches "$candidate" "$SOURCE" "$OPENING" "$CLOSING" \
    || { log "ERROR: generated controller block differs from canonical source"; exit 4; }
noid_generator_publish "$candidate" "$TARGET" || exit 4
log "OK: M18 Flatpak controller published atomically"

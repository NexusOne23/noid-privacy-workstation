#!/usr/bin/env bash
# Keep M17's Anaconda Live required-space derivative identical to its source.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LIB="$REPO_ROOT/scripts/lib/source-generator.sh"
# shellcheck source=scripts/lib/source-generator.sh
. "$LIB"

TARGET=${NOID_LIVEINST_REQUIRED_SPACE_M17:-$REPO_ROOT/kickstart/snippets/17-gnome-hardening.ks}
SOURCE=${NOID_LIVEINST_REQUIRED_SPACE_SOURCE:-$REPO_ROOT/overrides/anaconda/live-os-initialization.py}
OPENING="cat > \"\$liveinst_update_source\" <<'NOID_LIVEINST_REQUIRED_SPACE_EOF'"
CLOSING=NOID_LIVEINST_REQUIRED_SPACE_EOF
HASH_VARIABLE=LIVEINST_UPDATE_SOURCE_SHA256

log() { echo "[regen-liveinst-required-space-embed] $*"; }
usage() { echo "Usage: scripts/regen-liveinst-required-space-embed.sh [--check]"; }
noid_generator_parse_cli "$@" || { usage >&2; exit 2; }
[ "$NOID_GENERATOR_MODE" != help ] || { usage; exit 0; }
noid_generator_require_tools bash cat chmod cut diff grep head mktemp mv od \
    readlink sed sha256sum stat tail tr wc || exit 2
noid_generator_require_source "$SOURCE" "$CLOSING" || exit 2
noid_generator_marker_pair "$TARGET" "$OPENING" "$CLOSING" || exit 3

source_sha256=$(sha256sum -- "$SOURCE")
source_sha256=${source_sha256%% *}
expected_hash_line="${HASH_VARIABLE}=\"${source_sha256}\""
mapfile -t hash_lines < <(
    grep -nE "^${HASH_VARIABLE}=\"[0-9a-f]{64}\"$" "$TARGET" | cut -d: -f1
)
if [ "${#hash_lines[@]}" -ne 1 ]; then
    log "ERROR: M17 must contain exactly one well-formed ${HASH_VARIABLE} assignment"
    exit 3
fi

if noid_generator_block_matches "$TARGET" "$SOURCE" "$OPENING" "$CLOSING" \
   && [ "$(grep -Fxc "$expected_hash_line" "$TARGET")" -eq 1 ]; then
    log "IN SYNC: M17 Live required-space derivative and runtime hash match canonical source"
    exit 0
fi
[ "$NOID_GENERATOR_MODE" != check ] || {
    log "DRIFT DETECTED: M17 derivative block or runtime hash differs; run scripts/regen-liveinst-required-space-embed.sh"
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
sed -i -E \
    "s|^${HASH_VARIABLE}=\"[0-9a-f]{64}\"$|${expected_hash_line}|" \
    "$candidate"
chmod --reference="$TARGET" "$candidate"
bash -n "$candidate" || { log "ERROR: generated M17 candidate is invalid Bash"; exit 4; }
noid_generator_block_matches "$candidate" "$SOURCE" "$OPENING" "$CLOSING" \
    || { log "ERROR: generated derivative block differs from canonical source"; exit 4; }
[ "$(grep -Fxc "$expected_hash_line" "$candidate")" -eq 1 ] \
    || { log "ERROR: generated runtime hash differs from canonical source"; exit 4; }
noid_generator_publish "$candidate" "$TARGET" || exit 4
candidate=''
trap - EXIT HUP INT TERM
log "OK: M17 Live required-space derivative and runtime hash published atomically"

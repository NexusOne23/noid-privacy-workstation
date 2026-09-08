#!/usr/bin/env bash
# Synchronize M03's BPF object/controller payload and its named digest field.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LIB="$REPO_ROOT/scripts/lib/source-generator.sh"
# shellcheck source=scripts/lib/source-generator.sh
. "$LIB"
TARGET=${NOID_LAN_XDP_M03:-$REPO_ROOT/kickstart/snippets/03-firewalld.ks}
CONTROLLER=${NOID_LAN_XDP_CONTROLLER:-$REPO_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.sh}
OBJECT_B64=${NOID_LAN_XDP_OBJECT_B64:-$REPO_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.o.b64}
OBJECT_OPENING="<<'NOID_LAN_XDP_OBJECT_B64_EOF'"
OBJECT_CLOSING=NOID_LAN_XDP_OBJECT_B64_EOF
CONTROLLER_OPENING="<<'NOID_LAN_XDP_CONTROLLER_EOF'"
CONTROLLER_CLOSING=NOID_LAN_XDP_CONTROLLER_EOF
HASH_FIELD=NOID_LAN_XDP_OBJECT_SHA256

log() { echo "[regen-lan-xdp-embed] $*"; }
usage() { echo "Usage: scripts/regen-lan-xdp-embed.sh [--check]"; }
noid_generator_parse_cli "$@" || { usage >&2; exit 2; }
[ "$NOID_GENERATOR_MODE" != help ] || { usage; exit 0; }
noid_generator_require_tools awk base64 bash cat cut diff grep head mktemp mv \
    od readlink sed sha256sum stat tail tr || exit 2
noid_generator_require_source "$OBJECT_B64" "$OBJECT_CLOSING" || exit 2
noid_generator_require_source "$CONTROLLER" "$CONTROLLER_CLOSING" || exit 2
noid_generator_marker_pair "$TARGET" "$OBJECT_OPENING" "$OBJECT_CLOSING" || exit 3
noid_generator_marker_pair "$TARGET" "$CONTROLLER_OPENING" "$CONTROLLER_CLOSING" || exit 3

decoded=$(mktemp "${TARGET}.decoded.XXXXXX")
tmp1=''
tmp2=''
candidate=''
trap 'rm -f -- "$decoded" "$tmp1" "$tmp2" "$candidate"' EXIT HUP INT TERM
base64 -d -- "$OBJECT_B64" > "$decoded" \
    || { log "ERROR: pinned object payload is not valid base64"; exit 3; }
object_hash=$(sha256sum -- "$decoded" | awk '{print $1}')
mapfile -t controller_hashes < <(
    sed -n 's/^OBJECT_SHA256=\([0-9a-f]\{64\}\)$/\1/p' "$CONTROLLER"
)
[ "${#controller_hashes[@]}" -eq 1 ] \
    && [ "${controller_hashes[0]}" = "$object_hash" ] \
    || { log "ERROR: controller has no unique matching object digest"; exit 3; }
mapfile -t target_hashes < <(
    sed -n "s/^${HASH_FIELD}=\([0-9a-f]\{64\}\)$/\1/p" "$TARGET"
)
[ "${#target_hashes[@]}" -eq 1 ] \
    || { log "ERROR: M03 has no unique named object-digest field"; exit 3; }

object_ok=0
controller_ok=0
noid_generator_block_matches "$TARGET" "$OBJECT_B64" \
    "$OBJECT_OPENING" "$OBJECT_CLOSING" && object_ok=1 || true
noid_generator_block_matches "$TARGET" "$CONTROLLER" \
    "$CONTROLLER_OPENING" "$CONTROLLER_CLOSING" && controller_ok=1 || true
if [ "$object_ok" -eq 1 ] && [ "$controller_ok" -eq 1 ] \
        && [ "${target_hashes[0]}" = "$object_hash" ]; then
    log "IN SYNC: M03 object, controller and named SHA-256 field"
    exit 0
fi
[ "$NOID_GENERATOR_MODE" != check ] \
    || { log "DRIFT DETECTED: run scripts/regen-lan-xdp-embed.sh"; exit 1; }

# Build all three replacements in sibling temporary files. Only the fully
# validated final candidate can replace M03.
noid_generator_marker_pair "$TARGET" "$OBJECT_OPENING" "$OBJECT_CLOSING"
start=$NOID_GENERATOR_START
end=$NOID_GENERATOR_END
tmp1=$(noid_generator_temp_for "$TARGET") || exit 4
head -n "$start" "$TARGET" > "$tmp1"
cat "$OBJECT_B64" >> "$tmp1"
tail -n +"$end" "$TARGET" >> "$tmp1"

noid_generator_marker_pair "$tmp1" "$CONTROLLER_OPENING" "$CONTROLLER_CLOSING"
start=$NOID_GENERATOR_START
end=$NOID_GENERATOR_END
tmp2=$(noid_generator_temp_for "$TARGET") || exit 4
head -n "$start" "$tmp1" > "$tmp2"
cat "$CONTROLLER" >> "$tmp2"
tail -n +"$end" "$tmp1" >> "$tmp2"

candidate=$(noid_generator_temp_for "$TARGET") || exit 4
sed "s/^${HASH_FIELD}=[0-9a-f]\{64\}$/${HASH_FIELD}=${object_hash}/" \
    "$tmp2" > "$candidate"
bash -n "$candidate" || { log "ERROR: candidate is invalid Bash"; exit 4; }
[ "$(grep -Fxc "${HASH_FIELD}=${object_hash}" "$candidate" || true)" -eq 1 ] \
    || { log "ERROR: candidate digest field is not exact"; exit 4; }
noid_generator_block_matches "$candidate" "$OBJECT_B64" \
    "$OBJECT_OPENING" "$OBJECT_CLOSING" \
    || { log "ERROR: candidate object block failed parity"; exit 4; }
noid_generator_block_matches "$candidate" "$CONTROLLER" \
    "$CONTROLLER_OPENING" "$CONTROLLER_CLOSING" \
    || { log "ERROR: candidate controller block failed parity"; exit 4; }
noid_generator_publish "$candidate" "$TARGET" || exit 4
candidate=''
trap - EXIT HUP INT TERM
rm -f -- "$decoded" "$tmp1" "$tmp2"
log "OK: M03 LAN-XDP payload validated and published atomically"

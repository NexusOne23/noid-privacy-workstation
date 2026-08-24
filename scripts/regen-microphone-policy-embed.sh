#!/usr/bin/env bash
# Keep the three M17 microphone-policy heredocs byte-identical to repo sources.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LIB="$REPO_ROOT/scripts/lib/source-generator.sh"
# shellcheck source=scripts/lib/source-generator.sh
. "$LIB"

TARGET=${NOID_MIC_POLICY_M17:-$REPO_ROOT/kickstart/snippets/17-gnome-hardening.ks}
SOURCES=(
    "${NOID_MIC_POLICY_CONF:-$REPO_ROOT/scripts/noid-microphone-privacy.conf}"
    "${NOID_MIC_POLICY_LUA:-$REPO_ROOT/scripts/noid-microphone-privacy.lua}"
    "${NOID_MIC_POLICY_TOGGLE:-$REPO_ROOT/scripts/noid-toggle-microphone.sh}"
)
OPENINGS=(
    "cat > /etc/wireplumber/wireplumber.conf.d/90-noid-microphone-privacy.conf <<'NOID_MIC_WP_CONF_EOF'"
    "cat > /usr/local/share/wireplumber/scripts/noid-microphone-privacy.lua <<'NOID_MIC_WP_LUA_EOF'"
    "cat > /usr/local/bin/noid-toggle-microphone <<'NOID_MIC_TOGGLE_EOF'"
)
CLOSINGS=(
    NOID_MIC_WP_CONF_EOF
    NOID_MIC_WP_LUA_EOF
    NOID_MIC_TOGGLE_EOF
)

log() { echo "[regen-microphone-policy-embed] $*"; }
usage() { echo "Usage: scripts/regen-microphone-policy-embed.sh [--check]"; }
noid_generator_parse_cli "$@" || { usage >&2; exit 2; }
[ "$NOID_GENERATOR_MODE" != help ] || { usage; exit 0; }
noid_generator_require_tools bash cat chmod cmp diff grep head mktemp mv od \
    readlink sed stat tail tr wc || exit 2

for i in "${!SOURCES[@]}"; do
    noid_generator_require_source "${SOURCES[$i]}" "${CLOSINGS[$i]}" || exit 2
    noid_generator_marker_pair "$TARGET" "${OPENINGS[$i]}" "${CLOSINGS[$i]}" || exit 3
done

in_sync=1
for i in "${!SOURCES[@]}"; do
    noid_generator_block_matches "$TARGET" "${SOURCES[$i]}" \
        "${OPENINGS[$i]}" "${CLOSINGS[$i]}" || in_sync=0
done
if [ "$in_sync" -eq 1 ]; then
    log "IN SYNC: all M17 microphone-policy embeds match their sources"
    exit 0
fi
[ "$NOID_GENERATOR_MODE" != check ] || {
    log "DRIFT DETECTED: run scripts/regen-microphone-policy-embed.sh"
    exit 1
}

candidate=$(noid_generator_temp_for "$TARGET") || exit 4
scratch=''
trap 'rm -f -- "$candidate" "$scratch"' EXIT HUP INT TERM
cp -- "$TARGET" "$candidate"
chmod --reference="$TARGET" "$candidate"

for i in "${!SOURCES[@]}"; do
    noid_generator_marker_pair "$candidate" "${OPENINGS[$i]}" "${CLOSINGS[$i]}" || exit 4
    start=$NOID_GENERATOR_START
    end=$NOID_GENERATOR_END
    scratch=$(noid_generator_temp_for "$candidate") || exit 4
    head -n "$start" "$candidate" > "$scratch"
    cat "${SOURCES[$i]}" >> "$scratch"
    tail -n +"$end" "$candidate" >> "$scratch"
    mv -T -- "$scratch" "$candidate"
    scratch=''
done

bash -n "$candidate" || { log "ERROR: generated M17 candidate is invalid Bash"; exit 4; }
for i in "${!SOURCES[@]}"; do
    noid_generator_block_matches "$candidate" "${SOURCES[$i]}" \
        "${OPENINGS[$i]}" "${CLOSINGS[$i]}" \
        || { log "ERROR: generated block differs from ${SOURCES[$i]}"; exit 4; }
done
noid_generator_publish "$candidate" "$TARGET" || exit 4
candidate=''
trap - EXIT HUP INT TERM
log "OK: all M17 microphone-policy embeds published atomically"

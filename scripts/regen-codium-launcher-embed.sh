#!/usr/bin/env bash
# Keep M08's VSCodium launch and desktop-sync helpers byte-identical to source.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LIB="$REPO_ROOT/scripts/lib/source-generator.sh"
# shellcheck source=scripts/lib/source-generator.sh
. "$LIB"

TARGET=${NOID_CODIUM_LAUNCHER_M08:-$REPO_ROOT/kickstart/snippets/08-service-minimization.ks}
SOURCES=(
    "${NOID_CODIUM_LAUNCH_SOURCE:-$REPO_ROOT/scripts/noid-codium-launch.sh}"
    "${NOID_CODIUM_SYNC_SOURCE:-$REPO_ROOT/scripts/noid-codium-launcher-sync.sh}"
)
OPENINGS=(
    "cat > /usr/libexec/noid-codium-launch <<'NOID_CODIUM_LAUNCH_EOF'"
    "cat > /usr/local/sbin/noid-codium-launcher-sync <<'NOID_CODIUM_SYNC_EOF'"
)
CLOSINGS=(
    NOID_CODIUM_LAUNCH_EOF
    NOID_CODIUM_SYNC_EOF
)

log() { echo "[regen-codium-launcher-embed] $*"; }
usage() { echo "Usage: scripts/regen-codium-launcher-embed.sh [--check]"; }
noid_generator_parse_cli "$@" || { usage >&2; exit 2; }
[[ $NOID_GENERATOR_MODE != help ]] || { usage; exit 0; }
noid_generator_require_tools bash cat chmod cut diff grep head mktemp mv od \
    readlink sed stat tail tr || exit 2

starts=()
ends=()
previous_end=0
for index in "${!SOURCES[@]}"; do
    noid_generator_require_source "${SOURCES[$index]}" "${CLOSINGS[$index]}" \
        || exit 2
    noid_generator_marker_pair "$TARGET" "${OPENINGS[$index]}" \
        "${CLOSINGS[$index]}" || exit 3
    [[ $NOID_GENERATOR_START -gt $previous_end ]] || {
        log "ERROR: target blocks overlap or are out of order"
        exit 3
    }
    starts+=("$NOID_GENERATOR_START")
    ends+=("$NOID_GENERATOR_END")
    previous_end=$NOID_GENERATOR_END
done

drift=0
for index in "${!SOURCES[@]}"; do
    if ! noid_generator_block_matches "$TARGET" "${SOURCES[$index]}" \
            "${OPENINGS[$index]}" "${CLOSINGS[$index]}"; then
        drift=1
    fi
done
if [[ $drift -eq 0 ]]; then
    log "IN SYNC: M08 VSCodium launcher helpers match their sources"
    exit 0
fi
[[ $NOID_GENERATOR_MODE != check ]] || {
    log "DRIFT DETECTED: run scripts/regen-codium-launcher-embed.sh"
    exit 1
}

candidate=$(noid_generator_temp_for "$TARGET") || exit 4
trap 'rm -f -- "$candidate"' EXIT HUP INT TERM
cursor=1
{
    for index in "${!SOURCES[@]}"; do
        sed -n "${cursor},${starts[$index]}p" "$TARGET"
        cat "${SOURCES[$index]}"
        cursor=${ends[$index]}
    done
    tail -n +"$cursor" "$TARGET"
} > "$candidate"
chmod --reference="$TARGET" "$candidate"
bash -n "$candidate" || {
    log "ERROR: generated M08 candidate is invalid Bash"
    exit 4
}
for index in "${!SOURCES[@]}"; do
    noid_generator_block_matches "$candidate" "${SOURCES[$index]}" \
        "${OPENINGS[$index]}" "${CLOSINGS[$index]}" || {
        log "ERROR: generated block differs from source: ${SOURCES[$index]}"
        exit 4
    }
done
noid_generator_publish "$candidate" "$TARGET" || exit 4
candidate=
trap - EXIT HUP INT TERM
log "OK: M08 VSCodium launcher helpers published atomically"

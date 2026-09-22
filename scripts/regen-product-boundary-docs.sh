#!/usr/bin/env bash
# Keep M31's installed product-boundary docs byte-identical to their sources.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LIB="$REPO_ROOT/scripts/lib/source-generator.sh"
# shellcheck source=scripts/lib/source-generator.sh
. "$LIB"

TARGET=${NOID_PRODUCT_BOUNDARY_M31:-$REPO_ROOT/kickstart/snippets/31-user-docs-tier-c.ks}
THREAT_SOURCE=${NOID_THREAT_MODEL_SRC:-$REPO_ROOT/docs/threat-model.md}
SCOPE_SOURCE=${NOID_SCOPE_SRC:-$REPO_ROOT/docs/scope.md}
PQ_SOURCE=${NOID_PQ_SRC:-$REPO_ROOT/docs/post-quantum-readiness.md}
PERFORMANCE_SOURCE=${NOID_PERFORMANCE_PROFILE_SRC:-$REPO_ROOT/docs/performance-profile.md}
LICENSING_SOURCE=${NOID_LICENSING_SRC:-$REPO_ROOT/LICENSING.md}

SOURCES=(
    "$THREAT_SOURCE"
    "$SCOPE_SOURCE"
    "$PQ_SOURCE"
    "$PERFORMANCE_SOURCE"
    "$LICENSING_SOURCE"
)
OPENINGS=(
    "cat > \"\$DOC_TMP\" <<'NOID_THREAT_MODEL_DOC_EOF'"
    "cat > \"\$DOC_TMP\" <<'NOID_SCOPE_DOC_EOF'"
    "cat > \"\$DOC_TMP\" <<'NOID_PQ_DOC_EOF'"
    "cat > \"\$DOC_TMP\" <<'NOID_PERFORMANCE_PROFILE_DOC_EOF'"
    "cat > \"\$DOC_TMP\" <<'NOID_LICENSING_DOC_EOF'"
)
CLOSINGS=(
    NOID_THREAT_MODEL_DOC_EOF
    NOID_SCOPE_DOC_EOF
    NOID_PQ_DOC_EOF
    NOID_PERFORMANCE_PROFILE_DOC_EOF
    NOID_LICENSING_DOC_EOF
)

log() { echo "[regen-product-boundary-docs] $*"; }
usage() { echo "Usage: scripts/regen-product-boundary-docs.sh [--check]"; }
noid_generator_parse_cli "$@" || { usage >&2; exit 2; }
[ "$NOID_GENERATOR_MODE" != help ] || { usage; exit 0; }
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
    [ "$NOID_GENERATOR_START" -gt "$previous_end" ] || {
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
if [ "$drift" -eq 0 ]; then
    log "IN SYNC: all M31 product-boundary docs match their sources"
    exit 0
fi
[ "$NOID_GENERATOR_MODE" != check ] || {
    log "DRIFT DETECTED: run scripts/regen-product-boundary-docs.sh"
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
    log "ERROR: generated M31 candidate is invalid Bash"
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
candidate=''
trap - EXIT HUP INT TERM
log "OK: all M31 product-boundary docs published atomically"

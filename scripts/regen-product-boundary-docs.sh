#!/usr/bin/env bash
# Keep M31's installed product-boundary docs, license texts and the XDP object's
# corresponding source byte-identical to their sources, together with the named
# SHA-256 fields of every non-documentation block.
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
GPL3_SOURCE=${NOID_GPL3_LICENSE_SRC:-$REPO_ROOT/COPYING}
GPL2_SOURCE=${NOID_GPL2_LICENSE_SRC:-$REPO_ROOT/licenses/GPL-2.0.txt}
XDP_SOURCE=${NOID_LAN_XDP_SOURCE_SRC:-$REPO_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.c}
XDP_BUILD_SOURCE=${NOID_LAN_XDP_BUILD_SRC:-$REPO_ROOT/scripts/build-lan-xdp-object.sh}

SOURCES=(
    "$THREAT_SOURCE"
    "$SCOPE_SOURCE"
    "$PQ_SOURCE"
    "$PERFORMANCE_SOURCE"
    "$LICENSING_SOURCE"
    "$GPL3_SOURCE"
    "$GPL2_SOURCE"
    "$XDP_SOURCE"
    "$XDP_BUILD_SOURCE"
)
OPENINGS=(
    "cat > \"\$DOC_TMP\" <<'NOID_THREAT_MODEL_DOC_EOF'"
    "cat > \"\$DOC_TMP\" <<'NOID_SCOPE_DOC_EOF'"
    "cat > \"\$DOC_TMP\" <<'NOID_PQ_DOC_EOF'"
    "cat > \"\$DOC_TMP\" <<'NOID_PERFORMANCE_PROFILE_DOC_EOF'"
    "cat > \"\$DOC_TMP\" <<'NOID_LICENSING_DOC_EOF'"
    "cat > \"\$DOC_TMP\" <<'NOID_GPL3_LICENSE_EOF'"
    "cat > \"\$DOC_TMP\" <<'NOID_GPL2_LICENSE_EOF'"
    "cat > \"\$DOC_TMP\" <<'NOID_LAN_XDP_SOURCE_EOF'"
    "cat > \"\$DOC_TMP\" <<'NOID_LAN_XDP_BUILD_SCRIPT_EOF'"
)
CLOSINGS=(
    NOID_THREAT_MODEL_DOC_EOF
    NOID_SCOPE_DOC_EOF
    NOID_PQ_DOC_EOF
    NOID_PERFORMANCE_PROFILE_DOC_EOF
    NOID_LICENSING_DOC_EOF
    NOID_GPL3_LICENSE_EOF
    NOID_GPL2_LICENSE_EOF
    NOID_LAN_XDP_SOURCE_EOF
    NOID_LAN_XDP_BUILD_SCRIPT_EOF
)
# Named SHA-256 field that M31 checks before and after publication; empty for
# documentation blocks.
HASH_FIELDS=(
    ''
    ''
    ''
    ''
    ''
    NOID_GPL3_LICENSE_SHA256
    NOID_GPL2_LICENSE_SHA256
    NOID_LAN_XDP_SOURCE_SHA256
    NOID_LAN_XDP_BUILD_SCRIPT_SHA256
)

log() { echo "[regen-product-boundary-docs] $*"; }
usage() { echo "Usage: scripts/regen-product-boundary-docs.sh [--check]"; }
noid_generator_parse_cli "$@" || { usage >&2; exit 2; }
[ "$NOID_GENERATOR_MODE" != help ] || { usage; exit 0; }
noid_generator_require_tools awk bash cat sha256sum || exit 2

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

declare -A source_hashes=()
for index in "${!SOURCES[@]}"; do
    field=${HASH_FIELDS[$index]}
    [ -n "$field" ] || continue
    source_hashes[$field]=$(sha256sum -- "${SOURCES[$index]}" | awk '{print $1}')
    [ "$(grep -Ec "^${field}=[0-9a-f]{64}\$" "$TARGET" || true)" -eq 1 ] || {
        log "ERROR: M31 has no unique named digest field: $field"
        exit 3
    }
done

drift=0
for index in "${!SOURCES[@]}"; do
    if ! noid_generator_block_matches "$TARGET" "${SOURCES[$index]}" \
            "${OPENINGS[$index]}" "${CLOSINGS[$index]}"; then
        drift=1
    fi
    field=${HASH_FIELDS[$index]}
    if [ -n "$field" ] \
            && ! grep -qxF "${field}=${source_hashes[$field]}" "$TARGET"; then
        drift=1
    fi
done
if [ "$drift" -eq 0 ]; then
    log "IN SYNC: all M31 product-boundary docs, license texts and XDP source match their sources"
    exit 0
fi
[ "$NOID_GENERATOR_MODE" != check ] || {
    log "DRIFT DETECTED: run scripts/regen-product-boundary-docs.sh"
    exit 1
}

noid_generator_install_traps
noid_generator_new_candidate "$TARGET" || exit 4
candidate=$NOID_GENERATOR_PATH
noid_generator_new_scratch || exit 4
spliced=$NOID_GENERATOR_PATH
cursor=1
{
    for index in "${!SOURCES[@]}"; do
        sed -n "${cursor},${starts[$index]}p" "$TARGET"
        cat "${SOURCES[$index]}"
        cursor=${ends[$index]}
    done
    tail -n +"$cursor" "$TARGET"
} > "$spliced"
sed_program=()
for field in "${!source_hashes[@]}"; do
    sed_program+=(-e "s/^${field}=[0-9a-f]\{64\}\$/${field}=${source_hashes[$field]}/")
done
sed "${sed_program[@]}" "$spliced" > "$candidate"
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
for field in "${!source_hashes[@]}"; do
    [ "$(grep -Fxc "${field}=${source_hashes[$field]}" "$candidate" || true)" -eq 1 ] || {
        log "ERROR: generated digest field is not exact: $field"
        exit 4
    }
done
noid_generator_publish "$candidate" "$TARGET" || exit 4
log "OK: all M31 product-boundary docs, license texts and XDP source published atomically"

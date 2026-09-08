#!/usr/bin/env bash
# Sync M35's installed smartcard guide from docs/35-thunderbird-smartcard.md.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LIB="$REPO_ROOT/scripts/lib/source-generator.sh"
# shellcheck source=scripts/lib/source-generator.sh
. "$LIB"

TARGET=${NOID_TB_SMARTCARD_M35:-$REPO_ROOT/kickstart/snippets/35-thunderbird.ks}
SOURCE=${NOID_TB_SMARTCARD_SRC:-$REPO_ROOT/docs/35-thunderbird-smartcard.md}
OPENING="cat > \"\$SMARTCARD_DOC_CANDIDATE\" <<'NOID_TB_SMARTCARD_DOC_EOF'"
CLOSING=NOID_TB_SMARTCARD_DOC_EOF

log() { echo "[regen-thunderbird-smartcard-doc] $*"; }
usage() { echo "Usage: scripts/regen-thunderbird-smartcard-doc.sh [--check]"; }
noid_generator_parse_cli "$@" || { usage >&2; exit 2; }
[ "$NOID_GENERATOR_MODE" != help ] || { usage; exit 0; }
noid_generator_require_tools bash cat chmod cut diff grep head mktemp mv od \
    readlink sed stat tail tr || exit 2
noid_generator_require_source "$SOURCE" "$CLOSING" || exit 2
noid_generator_marker_pair "$TARGET" "$OPENING" "$CLOSING" || exit 3

if noid_generator_block_matches "$TARGET" "$SOURCE" "$OPENING" "$CLOSING"; then
    log "IN SYNC: M35 smartcard guide matches its canonical source"
    exit 0
fi
[ "$NOID_GENERATOR_MODE" != check ] || {
    log "DRIFT DETECTED: run scripts/regen-thunderbird-smartcard-doc.sh"
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
bash -n "$candidate" || {
    log "ERROR: generated M35 candidate is invalid Bash"
    exit 4
}
noid_generator_block_matches "$candidate" "$SOURCE" "$OPENING" "$CLOSING" \
    || {
        log "ERROR: generated smartcard guide differs from source"
        exit 4
    }
noid_generator_publish "$candidate" "$TARGET" || exit 4
candidate=''
trap - EXIT HUP INT TERM
log "OK: M35 smartcard guide published atomically"

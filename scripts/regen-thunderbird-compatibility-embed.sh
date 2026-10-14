#!/usr/bin/env bash
# Keep the native compatibility worker and reviewed seed metadata in M35.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LIB="$REPO_ROOT/scripts/lib/source-generator.sh"
# shellcheck source=scripts/lib/source-generator.sh
. "$LIB"
TARGET=${NOID_TB_COMPAT_M35:-$REPO_ROOT/kickstart/snippets/35-thunderbird.ks}
WORKER=${NOID_TB_COMPAT_WORKER:-$REPO_ROOT/scripts/noid-thunderbird-compatibility.py}
SEED=${NOID_TB_COMPAT_SEED:-$REPO_ROOT/thunderbird/dkim-compatibility.json}
PAIRS=(
    "$WORKER:TB_NATIVE_COMPAT_EOF"
    "$SEED:TB_SEED_COMPAT_EOF"
)

log() { echo "[regen-thunderbird-compatibility-embed] $*"; }
usage() { echo "Usage: scripts/regen-thunderbird-compatibility-embed.sh [--check]"; }
noid_generator_parse_cli "$@" || { usage >&2; exit 2; }
[ "$NOID_GENERATOR_MODE" != help ] || { usage; exit 0; }
noid_generator_require_tools bash cp python3 wc || exit 2

opening_for() {
    local file=$1 closing=$2 matches
    matches=$(grep -F "<<'$closing'" "$file") || return 1
    [ "$(printf '%s\n' "$matches" | wc -l)" -eq 1 ] || return 1
    printf '%s\n' "$matches"
}

all_blocks_match() {
    local candidate=$1 pair source closing opening
    for pair in "${PAIRS[@]}"; do
        source=${pair%:*}
        closing=${pair##*:}
        opening=$(opening_for "$candidate" "$closing") || return 1
        noid_generator_block_matches "$candidate" "$source" "$opening" "$closing" \
            || return 1
    done
}

for pair in "${PAIRS[@]}"; do
    source=${pair%:*}
    closing=${pair##*:}
    noid_generator_require_source "$source" "$closing" || exit 2
    opening=$(opening_for "$TARGET" "$closing") \
        || { log "ERROR: exactly one opening marker is required: $closing"; exit 3; }
    noid_generator_marker_pair "$TARGET" "$opening" "$closing" || exit 3
done
python3 - "$WORKER" "$SEED" <<'PY' || { log "ERROR: a compatibility source is invalid"; exit 2; }
from pathlib import Path
import json, sys
worker, seed = map(Path, sys.argv[1:])
compile(worker.read_text(), str(worker), 'exec')
json.loads(seed.read_text())
PY

if all_blocks_match "$TARGET"; then
    log "IN SYNC: M35 compatibility worker and seed match their sources"
    exit 0
fi
[ "$NOID_GENERATOR_MODE" != check ] \
    || { log "DRIFT DETECTED: run scripts/regen-thunderbird-compatibility-embed.sh"; exit 1; }

noid_generator_install_traps
noid_generator_new_candidate "$TARGET" || exit 4
candidate=$NOID_GENERATOR_PATH
cp -- "$TARGET" "$candidate"
for pair in "${PAIRS[@]}"; do
    source=${pair%:*}
    closing=${pair##*:}
    opening=$(opening_for "$candidate" "$closing") || exit 3
    python3 - "$candidate" "$source" "$opening" "$closing" <<'PY'
from pathlib import Path
import sys
target, source, opening, closing = sys.argv[1:]
p = Path(target)
before, rest = p.read_text().split(opening + "\n", 1)
_, after = rest.split("\n" + closing + "\n", 1)
p.write_text(before + opening + "\n" + Path(source).read_text() + closing + "\n" + after)
PY
done
chmod --reference="$TARGET" "$candidate"
bash -n "$candidate" || { log "ERROR: generated M35 candidate is invalid Bash"; exit 4; }
all_blocks_match "$candidate" \
    || { log "ERROR: generated candidate failed byte parity"; exit 4; }
noid_generator_publish "$candidate" "$TARGET" || exit 4
log "OK: M35 compatibility worker and seed published atomically"

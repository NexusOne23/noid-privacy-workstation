#!/usr/bin/env bash
# Keep the native compatibility worker and reviewed seed metadata in M35.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$REPO_ROOT/scripts/lib/source-generator.sh"
noid_generator_parse_cli "$@" || exit 2
if [ "$NOID_GENERATOR_MODE" = help ]; then
    echo 'Usage: regen-thunderbird-compatibility-embed.sh [--check]'
    exit 0
fi
noid_generator_require_tools python3 bash cat head tail
target="$REPO_ROOT/kickstart/snippets/35-thunderbird.ks"
candidate=$(noid_generator_temp_for "$target")
trap 'rm -f -- "$candidate"' EXIT
cp -- "$target" "$candidate"
for pair in \
    'scripts/noid-thunderbird-compatibility.py:TB_NATIVE_COMPAT_EOF' \
    'thunderbird/dkim-compatibility.json:TB_SEED_COMPAT_EOF'; do
    source="$REPO_ROOT/${pair%:*}"
    closing=${pair##*:}
    opening=$(grep -F "<<'$closing'" "$target")
    noid_generator_require_source "$source" "$closing"
    noid_generator_marker_pair "$target" "$opening" "$closing"
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
bash -n "$candidate"
python3 - "$REPO_ROOT" <<'PY'
from pathlib import Path
import json, sys
root = Path(sys.argv[1])
p = root / 'scripts/noid-thunderbird-compatibility.py'
compile(p.read_text(), str(p), 'exec')
json.loads((root / 'thunderbird/dkim-compatibility.json').read_text())
PY
if cmp -s "$candidate" "$target"; then
    echo 'Thunderbird compatibility sources are in sync'
elif [ "$NOID_GENERATOR_MODE" = check ]; then
    echo 'Thunderbird compatibility embed drift' >&2
    exit 1
else
    noid_generator_publish "$candidate" "$target"
    echo 'Published Thunderbird compatibility sources'
fi

#!/bin/bash
# 29-installed-package-freshness — networked installed-VM release gate
#
# Run only in the freshly installed candidate VM, after its controlled WAN is
# available. This is intentionally outside tests/run-all.sh: source tests and
# a mounted ISO cannot prove what current Fedora repositories offer to the
# installed NEVRA set at release time.
set -euo pipefail

TEST_NAME=29-installed-package-freshness
TMPDIR=$(mktemp -d /var/tmp/noid-package-freshness.XXXXXX)
trap 'rm -rf "$TMPDIR"' EXIT

if [ "$(id -u)" -eq 0 ]; then
    DNF=(dnf)
elif sudo -n true >/dev/null 2>&1; then
    DNF=(sudo -n dnf)
else
    echo "FAIL  $TEST_NAME: run as root or establish sudo credentials first" >&2
    exit 2
fi

for repo in fedora updates; do
    if ! repo_listing=$("${DNF[@]}" --no-plugins repo list --enabled "$repo"); then
        echo "FAIL  $TEST_NAME: cannot query required Fedora repository: $repo" >&2
        exit 2
    fi
    if ! awk -v expected="$repo" \
            'NR > 1 && $1 == expected { found++ } END { exit !(found == 1) }' \
            <<< "$repo_listing"; then
        echo "FAIL  $TEST_NAME: required Fedora repository is unavailable: $repo" >&2
        exit 2
    fi
done

# Restrict the query to Fedora base + stable updates. Third-party repositories
# are separately audited and must neither prompt for a new key nor make this
# Fedora security-baseline result dependent on their availability.
DNF_SCOPE=("--repo=fedora,updates" --no-plugins --assumeno)
"${DNF[@]}" --refresh "${DNF_SCOPE[@]}" updateinfo list \
    --updates --security --json > "$TMPDIR/security.json"
upgrade_query_rc=0
"${DNF[@]}" "${DNF_SCOPE[@]}" check-upgrade --json \
    > "$TMPDIR/upgrades.json" || upgrade_query_rc=$?
case "$upgrade_query_rc" in
    0|100) ;;
    *)
        echo "FAIL  $TEST_NAME: DNF check-upgrade query failed (rc=$upgrade_query_rc)" >&2
        exit 2
        ;;
esac
"${DNF[@]}" "${DNF_SCOPE[@]}" repo info fedora updates \
    > "$TMPDIR/repositories.txt"

gate_rc=0
python3 - "$TMPDIR/security.json" "$TMPDIR/upgrades.json" <<'PY' || gate_rc=$?
import json
import sys

security_path, upgrades_path = sys.argv[1:]
try:
    with open(security_path, encoding="utf-8") as stream:
        advisories = json.load(stream)
    with open(upgrades_path, encoding="utf-8") as stream:
        upgrade_document = json.load(stream)
except (OSError, UnicodeError, json.JSONDecodeError) as exc:
    print(f"invalid DNF JSON evidence: {exc}", file=sys.stderr)
    raise SystemExit(2)

if not isinstance(advisories, list) or not isinstance(upgrade_document, dict):
    print("unexpected DNF JSON document shape", file=sys.stderr)
    raise SystemExit(2)

# DNF5 emits an empty object when no upgrades exist and an explicit
# {"upgrades": [...]} object when they do. Accept only those two documented
# states: treating an unknown schema as "zero" would make this release gate
# fail open after a CLI/schema change.
if upgrade_document == {}:
    upgrades = []
elif set(upgrade_document) == {"upgrades"} and isinstance(
        upgrade_document["upgrades"], list):
    upgrades = upgrade_document["upgrades"]
else:
    print("unexpected DNF check-upgrade JSON schema", file=sys.stderr)
    raise SystemExit(2)

blocking_severities = {"critical", "important", "moderate"}
required_advisory_keys = {"name", "nevra", "severity"}
for index, item in enumerate(advisories):
    if (not isinstance(item, dict)
            or not required_advisory_keys.issubset(item)
            or not isinstance(item["severity"], str)):
        print(
            f"unexpected DNF advisory JSON schema at item {index}",
            file=sys.stderr,
        )
        raise SystemExit(2)
blocking = [
    item for item in advisories
    if item["severity"].lower() in blocking_severities
]

if blocking:
    print("blocking Fedora security advisories:", file=sys.stderr)
    for item in sorted(blocking, key=lambda entry: (
        str(entry.get("severity", "")),
        str(entry.get("name", "")),
        str(entry.get("nevra", "")),
    )):
        print(
            f"  {item.get('severity', '?'):9} "
            f"{item.get('name', '?')} {item.get('nevra', '?')}",
            file=sys.stderr,
        )

if upgrades:
    print(f"{len(upgrades)} Fedora package upgrade(s) available:", file=sys.stderr)
    for item in sorted(upgrades, key=lambda entry: (
        str(entry.get("name", "")), str(entry.get("arch", ""))
    )):
        print(
            f"  {item.get('name', '?')}.{item.get('arch', '?')} "
            f"{item.get('evr', '?')} [{item.get('repository', '?')}]",
            file=sys.stderr,
        )

if blocking or upgrades:
    raise SystemExit(1)
PY

echo "Repository evidence ($(date -u +%Y-%m-%dT%H:%M:%SZ)):"
awk '
    /^(Repo ID|Metadata expire)[[:space:]]*:/ ||
    /^[[:space:]]+(Available packages|Revision|Updated)[[:space:]]*:/ {
        print "  " $0
    }
' "$TMPDIR/repositories.txt"
if [ "$gate_rc" -ne 0 ]; then
    echo "FAIL  $TEST_NAME: rebuild from refreshed Fedora Metalink payloads" >&2
    exit "$gate_rc"
fi

echo "PASS  $TEST_NAME: zero Fedora upgrades; zero Critical/Important/Moderate advisories"

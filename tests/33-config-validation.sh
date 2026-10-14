#!/bin/bash
# 33-config-validation — JSON/XML/systemd unit structural validation
#
# Covers: every cat > *.json heredoc in kickstart produces valid JSON.
# Every systemd unit heredoc [Unit] has required sections.
# Would catch: malformed JSON snippet, systemd unit missing [Service].
set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
M32_FILE="$PROJECT_ROOT/kickstart/snippets/32-branding.ks"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

test_start "33-config-validation"

# --- complete Fedora 44 kickstart validation -------------------------------
# master.ks contains %include directives, so validating it unflattened does
# not parse the actual multi-MiB build input. Mirror CI locally: flatten every
# snippet into one file and validate against the F44 grammar.
if command -v ksflatten >/dev/null 2>&1 && command -v ksvalidator >/dev/null 2>&1; then
    FLAT_KS="$TMPDIR/master-flat.ks"
    if ksflatten -c "$PROJECT_ROOT/kickstart/master.ks" -o "$FLAT_KS" >/dev/null 2>&1 && \
       ksvalidator -v F44 "$FLAT_KS" >/dev/null 2>&1; then
        _pass "flattened master.ks passes Fedora 44 pykickstart validation"
    else
        _fail "flattened master.ks fails Fedora 44 pykickstart validation"
    fi
else
    # Mirror tests/00-compose-sources.sh: a missing grammar gate is a visible
    # failure, never a counted green PASS (the F44 grammar check did not run).
    _fail "pykickstart unavailable — F44 grammar gate did not run (install pykickstart)"
fi

# --- JSON heredocs ---------------------------------------------------------
# Validate every `cat > *.json <<MARKER` template and every template whose
# marker ends in JSON_EOF (used when an atomic writer targets a temporary
# variable rather than a literal *.json path). Parse the heredoc boundaries
# directly (no pipeline subshell can hide an error count) and substitute shell
# scalar placeholders with JSON number 0 before json.loads().
if json_result=$(python3 - "$PROJECT_ROOT/kickstart/snippets" <<'PY'
import json
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
start_re = re.compile(
    r'''\bcat\s*>\s*(.*?)\s*<<-?\s*['"]?'''
    r'''([A-Za-z_][A-Za-z0-9_]*)['"]?\s*$'''
)
scalar_re = re.compile(
    r'''\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*'''
)
errors = []
count = 0

for path in sorted(root.glob("*.ks")):
    lines = path.read_text(encoding="utf-8").splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        match = None if line.lstrip().startswith("#") else start_re.search(line)
        if not match:
            index += 1
            continue
        target = match.group(1)
        marker = match.group(2)
        if ".json" not in target and not marker.endswith("JSON_EOF"):
            index += 1
            continue
        start_line = index + 2
        index += 1
        body = []
        while index < len(lines) and lines[index].strip() != marker:
            body.append(lines[index])
            index += 1
        if index == len(lines):
            errors.append(f"{path.name}:{start_line}: unterminated {marker}")
            break
        count += 1
        rendered = scalar_re.sub("0", "\n".join(body) + "\n")
        try:
            json.loads(rendered)
        except json.JSONDecodeError as exc:
            errors.append(f"{path.name}:{start_line}: {marker}: {exc}")
        index += 1

if count == 0:
    errors.append("extractor found zero JSON heredocs")
if errors:
    print("\n".join(errors))
    raise SystemExit(1)
print(count)
PY
); then
    _pass "all $json_result JSON heredoc templates parse after shell-scalar substitution"
else
    _fail "JSON heredoc template validation failed"
    printf '%s\n' "$json_result" | sed 's/^/      /'
fi

# --- systemd unit heredocs -------------------------------------------------
# Every heredoc body that declares [Unit] must carry its own implementation
# section unless it is a *.d/*.conf drop-in. The drop-in target is taken from
# the heredoc's own writer: the opener line, the line before it (multi-line
# publisher calls) or the publish command right after the terminator (atomic
# writers staging a temporary file), never a later heredoc's opener. Checking
# each body separately prevents a drop-in's [Service] section from masking a
# unit that lost its own.
cat > "$TMPDIR/unit-sections.py" <<'PY'
from pathlib import Path
import re
import sys

heredoc_re = re.compile(r"""(?<!<)<<-?\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\1\s*$""")
impl_re = re.compile(
    r"^\[(Service|Timer|Socket|Path|Mount|Automount|Swap|Slice|Scope)\]$"
)
dropin_re = re.compile(r"/systemd/(?:system|user)/[^\s\"']+\.d/[^\s\"']+\.conf")
errors = []
units = 0
for name in sys.argv[1:]:
    path = Path(name)
    lines = path.read_text(encoding="utf-8").splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        match = None if line.lstrip().startswith("#") else heredoc_re.search(line)
        if not match:
            index += 1
            continue
        marker = match.group(2)
        opener = index
        index += 1
        body = []
        while index < len(lines) and lines[index] != marker:
            body.append(lines[index].strip())
            index += 1
        if index == len(lines):
            errors.append(f"{path.name}:{opener + 1}: unterminated {marker}")
            break
        if "[Unit]" in body:
            units += 1
            if not any(impl_re.match(entry) for entry in body):
                context = lines[max(0, opener - 1):opener + 1]
                for entry in lines[index + 1:index + 5]:
                    if heredoc_re.search(entry):
                        break
                    context.append(entry)
                if not any(dropin_re.search(entry) for entry in context):
                    errors.append(
                        f"{path.name}:{opener + 1}: {marker}: [Unit] without an "
                        "implementation section outside a *.d/*.conf drop-in"
                    )
        index += 1
if errors:
    print("\n".join(errors))
    raise SystemExit(1)
print(units)
PY
if unit_result=$(python3 "$TMPDIR/unit-sections.py" \
        "$PROJECT_ROOT"/kickstart/snippets/*.ks); then
    _pass "all $unit_result systemd unit heredocs carry their own implementation section or are drop-ins"
else
    _fail "systemd unit heredoc without its own implementation section"
    printf '%s\n' "$unit_result" | sed 's/^/      /'
fi
# Negative control: a [Service]-only drop-in in the same file must not mask a
# unit whose implementation section is missing.
cat > "$TMPDIR/unit-sections-fixture.ks" <<'UNIT_FIXTURE_EOF'
cat > /etc/systemd/system/broken.service <<'BROKEN_UNIT_EOF'
[Unit]
Description=unit without an implementation section
[Install]
WantedBy=multi-user.target
BROKEN_UNIT_EOF
cat > /etc/systemd/system/other.service.d/override.conf <<'DROPIN_EOF'
[Service]
Environment=FIXTURE=1
DROPIN_EOF
UNIT_FIXTURE_EOF
assert_cmd_failure "unit check rejects a unit masked by a drop-in in the same file" \
    python3 "$TMPDIR/unit-sections.py" "$TMPDIR/unit-sections-fixture.ks"
cat > "$TMPDIR/unit-sections-dropin.ks" <<'UNIT_DROPIN_FIXTURE_EOF'
cat > /etc/systemd/system/gdm.service.d/40-fixture.conf <<'GATE_EOF'
[Unit]
Requires=fixture.service
GATE_EOF
UNIT_DROPIN_FIXTURE_EOF
assert_cmd_success "unit check accepts a [Unit]-only drop-in" \
    python3 "$TMPDIR/unit-sections.py" "$TMPDIR/unit-sections-dropin.ks"

# Every local Markdown Documentation= target must actually be generated by a
# kickstart snippet. Direct writers are discovered from their literal target;
# atomic writers declare the same closed inventory through the reviewed
# `# Shipped Markdown target:` marker.
if doc_result=$(python3 - "$PROJECT_ROOT/kickstart/snippets" <<'PY'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
ref_re = re.compile(
    r'Documentation=file:///usr/share/doc/noid-privacy/([A-Za-z0-9._-]+\.md)'
)
create_re = re.compile(
    r'^\s*cat\s*>\s*["\x27]?/usr/share/doc/noid-privacy/'
    r'([A-Za-z0-9._-]+\.md)["\x27]?\s*<<'
)
marker_re = re.compile(
    r'^# Shipped Markdown target: /usr/share/doc/noid-privacy/'
    r'([A-Za-z0-9._-]+\.md)$'
)
references = set()
created = set()
for path in sorted(root.glob('*.ks')):
    for line in path.read_text(encoding='utf-8').splitlines():
        marker = marker_re.fullmatch(line)
        if marker:
            created.add(marker.group(1))
            continue
        if line.lstrip().startswith('#'):
            continue
        references.update(ref_re.findall(line))
        match = create_re.search(line)
        if match:
            created.add(match.group(1))

missing = sorted(references - created)
if missing:
    print('\n'.join(missing))
    raise SystemExit(1)
print(f'{len(references)} local Markdown Documentation= targets')
PY
); then
    _pass "$doc_result are generated by the kickstart"
else
    _fail "dangling local systemd Documentation= target(s)"
    printf '%s\n' "$doc_result" | sed 's/^/      /'
fi

# --- NM conf.d INI format --------------------------------------------------
# Validate each deployed conf.d heredoc body, not unrelated shell assignments
# and systemd sections elsewhere in its containing snippet.
if nm_result=$(python3 - "$PROJECT_ROOT/kickstart/snippets" <<'PY'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
opener_re = re.compile(
    r'''\bcat\s*>\s*(.*?)\s*<<-?\s*['"]?'''
    r'''([A-Za-z_][A-Za-z0-9_]*)['"]?\s*$'''
)
section_re = re.compile(r"^\[[A-Za-z0-9._-]+\]$")
assignment_re = re.compile(r"^[A-Za-z][A-Za-z0-9._-]*=")
errors = []
count = 0

for path in sorted(root.glob("*.ks")):
    lines = path.read_text(encoding="utf-8").splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        match = None if line.lstrip().startswith("#") else opener_re.search(line)
        if not match:
            index += 1
            continue
        target, marker = match.groups()
        if "/etc/NetworkManager/conf.d/" not in target or ".conf" not in target:
            index += 1
            continue
        start_line = index + 2
        index += 1
        body = []
        while index < len(lines) and lines[index].strip() != marker:
            body.append(lines[index])
            index += 1
        if index == len(lines):
            errors.append(f"{path.name}:{start_line}: unterminated {marker}")
            break
        count += 1
        stripped = [entry.strip() for entry in body]
        sections = sum(bool(section_re.fullmatch(entry)) for entry in stripped)
        assignments = sum(bool(assignment_re.match(entry)) for entry in stripped)
        meaningful = [entry for entry in stripped if entry]
        if target.endswith("/03-vpn-zone.conf"):
            comment_only = meaningful and all(
                entry.startswith("#") for entry in meaningful
            )
            rationale = any(
                "intentionally a no-op placeholder" in entry for entry in meaningful
            ) and any("Module 06" in entry for entry in meaningful)
            if not comment_only or not rationale:
                errors.append(
                    f"{path.name}:{start_line}: {marker}: reviewed VPN-zone "
                    "placeholder is not comment-only with its Module 06 rationale"
                )
        elif sections < 1 or assignments < 1:
            errors.append(
                f"{path.name}:{start_line}: {marker}: "
                f"sections={sections} assignments={assignments}"
            )
        index += 1

if count != 5:
    errors.append(f"expected 5 deployed NM conf.d heredocs, found {count}")
if errors:
    print("\n".join(errors))
    raise SystemExit(1)
print(count)
PY
); then
    _pass "$nm_result NM conf.d bodies are active INI or the reviewed comment-only placeholder"
else
    _fail "NM conf.d heredoc-body validation failed"
    printf '%s\n' "$nm_result" | sed 's/^/      /'
fi

# --- .desktop files --------------------------------------------------------
# Discover literal .desktop targets plus the established DESKTOP_EOF and
# AUTOSTART_EOF marker families used by staged/atomic target variables.
if desktop_result=$(python3 - "$PROJECT_ROOT/kickstart/snippets" <<'PY'
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
opener_re = re.compile(
    r'''<<-?\s*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?\s*$'''
)
errors = []
count = 0

for path in sorted(root.glob("*.ks")):
    lines = path.read_text(encoding="utf-8").splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        match = None if line.lstrip().startswith("#") else opener_re.search(line)
        if not match:
            index += 1
            continue
        marker = match.group(1)
        prefix = line[:match.start()]
        is_desktop = (
            ".desktop" in prefix
            or marker.endswith("DESKTOP_EOF")
            or marker == "AUTOSTART_EOF"
        )
        if not is_desktop:
            index += 1
            continue
        start_line = index + 2
        index += 1
        body = []
        while index < len(lines) and lines[index].strip() != marker:
            body.append(lines[index])
            index += 1
        if index == len(lines):
            errors.append(f"{path.name}:{start_line}: unterminated {marker}")
            break
        count += 1
        meaningful = [
            entry.strip() for entry in body
            if entry.strip() and not entry.lstrip().startswith("#")
        ]
        if not meaningful or meaningful[0] != "[Desktop Entry]":
            actual = meaningful[0] if meaningful else "<empty>"
            errors.append(
                f"{path.name}:{start_line}: {marker}: "
                f"first content line is {actual!r}"
            )
        index += 1

if count != 11:
    errors.append(f"expected 11 desktop-entry heredoc templates, found {count}")
if errors:
    print("\n".join(errors))
    raise SystemExit(1)
print(count)
PY
); then
    _pass "all $desktop_result desktop-entry heredocs start with [Desktop Entry]"
else
    _fail "desktop-entry heredoc-body validation failed"
    printf '%s\n' "$desktop_result" | sed 's/^/      /'
fi

# --- systemd ReadWritePaths existence (226/NAMESPACE guard) ------------------
# A ReadWritePaths/ReadOnlyPaths/BindPaths token that is neither '-'-prefixed
# (optional) nor guaranteed to exist makes mount-namespace setup hard-fail
# (status=226/NAMESPACE) BEFORE ExecStart — the service dies before its script
# runs. Recurrences: /var/lib/rpm, dnf5daemon-server, /var/cache/dnf. Each token
# under a package-owned /var tree must be '-'-prefixed OR in GUARANTEED below.
rwp_errors=0
# Core trees and their project-managed subpaths are covered by package/tmpfiles
# ordering. A per-user /home subpath is not: it must carry a same-unit path
# condition and be reviewed explicitly below.
rwp_safe='^/(usr|etc|boot|run|root|tmp|dev)(/|$)|^/home$|^/var/tmp(/|$)|^/var/lib/noid-privacy(/|$)'
# package-owned /var subdirs that ARE guaranteed (shipping pkg in comment):
#   /var/log filesystem · journal systemd(persistent) · aide aide · audit audit
#   · dnf+libdnf5 libdnf5 · AccountsService accountsservice
#   · NetworkManager NM · rsyslog (drop-in: applies only if rsyslog installed)
rwp_guaranteed=" /var/log /var/log/journal /var/log/aide /var/log/audit /var/lib/dnf /var/cache/libdnf5 /var/lib/aide /var/lib/AccountsService /var/lib/NetworkManager /var/lib/rsyslog "
rwp_conditionally_present=" /home/liveuser "
extract_heredoc "$M32_FILE" AVATAR_BACKFILL_EOF \
    "$TMPDIR/noid-skel-avatar-backfill.service" \
    || _fail "M32 conditional live-avatar unit extraction"
assert_grep_fixed 'ConditionPathExists=/home/liveuser' \
    "$TMPDIR/noid-skel-avatar-backfill.service" \
    "liveuser write scope has a same-unit path-existence condition"
assert_grep_fixed 'ReadWritePaths=/home/liveuser /var/lib/AccountsService' \
    "$TMPDIR/noid-skel-avatar-backfill.service" \
    "reviewed conditional write scope remains bound to the live-avatar unit"
while IFS= read -r line; do
    for tok in ${line#*=}; do
        case "$tok" in -*) continue ;; esac
        if [[ "$tok" =~ $rwp_safe ]]; then continue; fi
        case "$rwp_guaranteed" in *" $tok "*) continue ;; esac
        case "$rwp_conditionally_present" in *" $tok "*) continue ;; esac
        _fail "RWP non-'-'-prefixed, non-guaranteed: '$tok' (226/NAMESPACE risk — '-'-prefix it or justify in GUARANTEED)"
        rwp_errors=$((rwp_errors + 1))
    done
done < <(
    # A systemd directive shown as a USER EXAMPLE inside a shipped *.md doc
    # heredoc is not a service deployed by NoID Privacy — exclude *.md heredoc bodies
    # before the RWP scan so doc examples don't trip the 226/NAMESPACE guard.
    # Atomic writers target a temporary variable rather than a literal *.md
    # path, so they declare their marker with `# Shipped Markdown heredoc:`.
    for ksf in "$PROJECT_ROOT"/kickstart/snippets/*.ks "$PROJECT_ROOT"/kickstart/master.ks; do
        awk '
            /^# Shipped Markdown heredoc: [A-Za-z0-9_]+$/ {
                declared[$5] = 1
                next
            }
            !indoc && match($0, /[A-Za-z0-9_]+EOF/) {
                marker = substr($0, RSTART, RLENGTH)
                if ($0 ~ /cat[[:space:]]*>[[:space:]]*[^ ]*\.md[[:space:]]*<</ \
                        || marker in declared) {
                    md = marker
                    indoc = 1
                }
                next
            }
            indoc && $0 == md { indoc = 0; next }
            !indoc
        ' "$ksf"
    done | grep -hE '^[[:space:]]*(ReadWritePaths|ReadOnlyPaths|BindPaths|BindReadOnlyPaths)=' 2>/dev/null
)
if [ "$rwp_errors" -eq 0 ]; then
    _pass "all path-namespace tokens are optional, guaranteed, or condition-guarded"
fi

test_finish

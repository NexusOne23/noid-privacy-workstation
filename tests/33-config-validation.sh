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
# not parse the actual 2.4-MiB build input. Mirror CI locally: flatten every
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
# variable rather than a literal *.json path). The former awk/while
# implementation read a newline-delimited stream with `read -d ''` and changed
# its error counter inside a pipeline subshell; malformed JSON could therefore
# be reported as success. Parse the boundaries directly and substitute shell
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
# Scan for [Unit] blocks and check basic structural integrity.

systemd_errors=0
for ks in "$PROJECT_ROOT"/kickstart/snippets/*.ks; do
    rel=$(basename "$ks")
    # Count [Unit] and [Service] or [Timer] appearances in heredoc bodies
    unit_count=$(grep -c '^\[Unit\]' "$ks" 2>/dev/null || true)
    unit_count=${unit_count:-0}
    service_count=$(grep -c '^\[Service\]\|^\[Timer\]\|^\[Socket\]\|^\[Path\]\|^\[Mount\]\|^\[Automount\]' "$ks" 2>/dev/null || true)
    service_count=${service_count:-0}
    # A .service.d/*.conf drop-in may validly contain only [Unit] dependency
    # directives. Count only literal direct, guarded-atomic or durable-staged
    # systemd drop-in targets as exceptions; ordinary units still require an
    # implementation section.
    direct_unit_dropin_count=$(grep -cE '^cat > /etc/systemd/system/[^[:space:]]+\.service\.d/[^[:space:]]+\.conf <<' \
        "$ks" 2>/dev/null || true)
    atomic_unit_dropin_count=$(grep -cE '^publish_root_file "\$[A-Za-z_][A-Za-z0-9_]*" /etc/systemd/system/[^[:space:]]+\.service\.d/[^[:space:]]+\.conf 0?644$' \
        "$ks" 2>/dev/null || true)
    staged_unit_dropin_count=$(python3 - "$ks" <<'PY'
from pathlib import Path
import re
import sys

text = Path(sys.argv[1]).read_text(encoding="utf-8")
pattern = re.compile(
    r"(?m)^stage_root_file[ \t]+(?:\\[ \t]*\n[ \t]*)?"
    r"/etc/systemd/system/[^ \t\n]+\.service\.d/[^ \t\n]+\.conf"
    r"[ \t]+(?:\\[ \t]*\n[ \t]*)?0?644[ \t]+<<"
)
print(len(pattern.findall(text)))
PY
)
    staged_unit_dropin_count=${staged_unit_dropin_count:-0}
    unit_dropin_count=$((direct_unit_dropin_count + atomic_unit_dropin_count + staged_unit_dropin_count))
    unit_dropin_count=${unit_dropin_count:-0}
    covered_count=$((service_count + unit_dropin_count))
    if [ "$unit_count" -gt 0 ] && [ "$covered_count" -lt "$unit_count" ]; then
        _fail "$rel: $unit_count [Unit] blocks but only $service_count impl + $unit_dropin_count valid drop-in sections"
        systemd_errors=$((systemd_errors + 1))
    fi
done

if [ "$systemd_errors" -eq 0 ]; then
    _pass "systemd unit heredocs have matching implementation sections"
fi

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

if count != 12:
    errors.append(f"expected 12 desktop-entry heredoc templates, found {count}")
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

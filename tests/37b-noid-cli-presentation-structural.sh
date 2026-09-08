#!/bin/bash
# 37b-noid-cli-presentation-structural — complete Tools CLI presentation gate
#
# Every NoID Privacy-owned command exposed by the Tools app must use the shared
# terminal presentation or an already-equivalent purpose-built orchestrator.
# noid-audit is deliberately excluded because it is sourced from its own repo.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
M13="$PROJECT_ROOT/kickstart/snippets/13-aide-welcome.ks"
M37="$PROJECT_ROOT/kickstart/snippets/37-noid-tools-app.ks"

test_start "37b-noid-cli-presentation-structural"

assert_grep_fixed 'fmt_tty_banner() { # TITLE [SUBTITLE]' "$M13" \
    "shared formatter provides the interactive-only banner"
assert_grep_fixed '[ -t 1 ] || return 0' "$M13" \
    "redirected and machine-consumed output receives no automatic banner"
assert_grep_fixed 'if [ -n "${NOID_FMT_AUTO_TITLE:-}" ]; then' "$M13" \
    "shared formatter supports declarative CLI titles"

TMP_APP="$(mktemp --suffix=.py)"
trap 'rm -f "$TMP_APP"' EXIT
extract_heredoc "$M37" "NOID_TOOLS_PY_EOF" "$TMP_APP"

if presentation_result=$(python3 - "$TMP_APP" "$PROJECT_ROOT" 2>&1 <<'PY'
import ast
import pathlib
import re
import sys

app_path = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
tree = ast.parse(app_path.read_text(encoding='utf-8'))


def literal(name):
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == name
                for target in node.targets):
            return ast.literal_eval(node.value)
    raise SystemExit(f'{name} literal not found')


catalog = literal('CATALOG')
catalog_paths = {
    entry[3]
    for _title, _description, entries in catalog
    for entry in entries
    if entry[3] != '/usr/local/bin/noid-audit'
}

# path: (producer module, distinctive presentation marker)
contracts = {
    '/usr/local/bin/noid-network-audit':
        ('36-noid-network-app.ks', 'fmt_banner "WAN-egress-strict audit"'),
    '/usr/local/sbin/noid-lan-xdp':
        ('03-firewalld.ks', 'NOID_FMT_AUTO_TITLE="NoID Privacy — LAN XDP Boundary"'),
    '/usr/local/bin/noid-autostart-netwait':
        ('13-aide-welcome.ks', 'NOID_FMT_AUTO_TITLE="NoID Privacy — Network Gate"'),
    '/usr/local/sbin/noid-aide-check.sh':
        ('13-aide-welcome.ks', 'NOID_FMT_AUTO_TITLE="NoID Privacy — AIDE Check"'),
    '/usr/local/bin/noid-status':
        ('13-aide-welcome.ks', 'fmt_banner "NoID Privacy — System Status"'),
    '/usr/local/bin/noid-help':
        ('30-user-docs-tier-b.ks', 'NOID_FMT_AUTO_TITLE="NoID Privacy — Help"'),
    '/usr/local/bin/noid-integrity-check':
        ('33-operational-hygiene.ks', 'NOID_FMT_AUTO_TITLE="NoID Privacy — Integrity"'),
    '/usr/local/bin/noid-dns-diagnose':
        ('11b-dns-health.ks', 'NOID_FMT_AUTO_TITLE="NoID Privacy — DNS Diagnosis"'),
    '/usr/local/bin/noid-pending-reboot-check.sh':
        ('25-update-process.ks', 'fmt_banner "NoID Privacy — Pending Reboot"'),
    '/usr/local/sbin/noid-aide-baseline-review':
        ('13-aide-welcome.ks', 'NOID_FMT_AUTO_TITLE="NoID Privacy — AIDE Baseline"'),
    '/usr/local/sbin/noid-toggle-aide':
        ('13-aide-welcome.ks', 'NOID_FMT_AUTO_TITLE="NoID Privacy — AIDE"'),
    '/usr/local/bin/noid-toggle-aide-popup':
        ('13-aide-welcome.ks', 'NOID_FMT_AUTO_TITLE="NoID Privacy — AIDE Popup"'),
    '/usr/local/sbin/noid-toggle-audit-notify':
        ('12-selinux-auditd.ks', 'NOID_FMT_AUTO_TITLE="NoID Privacy — Audit Alerts"'),
    '/usr/local/sbin/noid-toggle-wan-strict':
        ('06-vpn-killswitch.ks', 'NOID_FMT_AUTO_SUBTITLE="Physical-WAN egress policy"'),
    '/usr/local/sbin/noid-dns-mode':
        ('05-lan-isolation.ks', "_tty_banner('NoID Privacy — DNS over TLS',"),
    '/usr/local/sbin/noid-toggle-printing':
        ('05-lan-isolation.ks', 'NOID_FMT_AUTO_TITLE="NoID Privacy — Printing"'),
    '/usr/local/sbin/noid-wan-strict':
        ('06-vpn-killswitch.ks', 'NOID_FMT_AUTO_SUBTITLE="Runtime status and operations"'),
    '/usr/local/bin/noid-lan-allow':
        ('05-lan-isolation.ks', 'NOID_FMT_AUTO_TITLE="NoID Privacy — LAN Exceptions"'),
    '/usr/local/sbin/noid-arp-hardening.sh':
        ('04-arp-hardening.ks', 'NOID_FMT_AUTO_TITLE="NoID Privacy — Gateway ARP Pin"'),
    '/usr/local/sbin/noid-toggle-bluetooth':
        ('08-service-minimization.ks', 'NOID_FMT_AUTO_TITLE="NoID Privacy — Bluetooth"'),
    '/usr/local/sbin/noid-toggle-location':
        ('08-service-minimization.ks', 'NOID_FMT_AUTO_TITLE="NoID Privacy — Location"'),
    '/usr/local/bin/noid-toggle-microphone':
        ('17-gnome-hardening.ks', 'NOID_FMT_AUTO_TITLE="NoID Privacy — Microphone"'),
    '/usr/local/bin/noid-toggle-bash-history':
        ('10-pam-login.ks', 'NOID_FMT_AUTO_TITLE="NoID Privacy — Bash History"'),
    '/usr/local/sbin/noid-toggle-gaming':
        ('08-service-minimization.ks', 'fmt_banner "NoID Privacy Gaming Mode"'),
    '/usr/local/bin/noid-toggle-gsk-gl':
        ('19-nvidia-mok-docs.ks', 'NOID_FMT_AUTO_TITLE="NoID Privacy — GTK Renderer"'),
    '/usr/local/bin/noid-toggle-lid-action':
        ('17-gnome-hardening.ks', 'NOID_FMT_AUTO_TITLE="NoID Privacy — Lid Close"'),
    '/usr/local/bin/noid-usbguard-devices':
        ('14-usbguard.ks', '"NoID Privacy — USBGuard Devices",'),
    '/usr/local/bin/noid-luks-backup.sh':
        ('22-luks-partitioning.ks', 'fmt_banner "NoID Privacy LUKS Header Backup"'),
    '/usr/local/bin/noid-snap-pre':
        ('20-snapper.ks', 'NOID_FMT_AUTO_TITLE="NoID Privacy — Snapshot"'),
    '/usr/local/sbin/noid-time-recovery':
        ('11-dns-ntp.ks', 'NOID_FMT_AUTO_TITLE="NoID Privacy — Time Recovery"'),
    '/usr/local/sbin/noid-grub-password':
        ('01-bootloader.ks', 'NOID_FMT_AUTO_TITLE="NoID Privacy — GRUB Password"'),
    '/usr/local/bin/noid-mei-lockdown':
        ('15-intel-me-mitigation.ks', 'NOID_FMT_AUTO_SUBTITLE="Experimental core lockdown"'),
    '/usr/local/bin/noid-mei-restore-submodules':
        ('15-intel-me-mitigation.ks', 'NOID_FMT_AUTO_SUBTITLE="Submodule policy"'),
    '/usr/local/bin/noid-firefox-relax-fpp':
        ('16-firefox.ks', 'NOID_FMT_AUTO_TITLE="NoID Privacy — Firefox FPP"'),
    '/usr/local/bin/noid-firefox-relax-webrtc':
        ('16-firefox.ks', 'NOID_FMT_AUTO_TITLE="NoID Privacy — Firefox WebRTC"'),
    '/usr/local/bin/noid-firefox-drm':
        ('16-firefox.ks', 'fmt_banner "NoID Privacy — Firefox DRM"'),
    '/usr/local/bin/noid-firefox-create-isolated-profile':
        ('33-operational-hygiene.ks', 'NOID_FMT_AUTO_TITLE="NoID Privacy — Firefox Profile"'),
    '/usr/local/bin/noid-firefox-harden-profile':
        ('16-firefox.ks', 'NOID_FMT_AUTO_TITLE="NoID Privacy — Firefox Hardening"'),
    '/usr/local/bin/noid-thunderbird-harden-profile':
        ('35-thunderbird.ks', 'NOID_FMT_AUTO_TITLE="NoID Privacy — Thunderbird"'),
    '/usr/local/bin/noid-toggle-thirdparty-repos':
        ('08-service-minimization.ks', 'NOID_FMT_AUTO_TITLE="NoID Privacy — Repositories"'),
    '/usr/local/sbin/noid-toggle-fedora-flatpaks':
        ('18-flatpak-sandboxing.ks', 'NOID_FMT_AUTO_TITLE="NoID Privacy — Fedora Flatpaks"'),
    '/usr/local/bin/noid-install-displaylink':
        ('14-usbguard.ks', 'NOID_FMT_AUTO_TITLE="NoID Privacy — DisplayLink"'),
    '/usr/local/bin/noid-claude-install':
        ('13-aide-welcome.ks', 'fmt_banner "NoID Privacy — Claude Code'),
    '/usr/local/bin/noid-codex-install':
        ('13-aide-welcome.ks', 'fmt_banner "NoID Privacy — OpenAI Codex'),
    '/usr/local/bin/noid-protonvpn-install':
        ('13-aide-welcome.ks', 'fmt_banner "Proton VPN — Official GUI"'),
    '/usr/local/bin/noid-mullvad-install':
        ('13-aide-welcome.ks', 'fmt_banner "Mullvad VPN — Official App"'),
    '/usr/local/bin/noid-nvidia-install.sh':
        ('19-nvidia-mok-docs.ks', 'fmt_banner "NoID Privacy NVIDIA Setup"'),
    '/usr/local/bin/noid-complete-setup.sh':
        ('08-service-minimization.ks', 'fmt_banner "NoID Privacy Media Codec Setup"'),
    '/usr/local/bin/noid-update-all.sh':
        ('25-update-process.ks', 'NoID Privacy — System Update Orchestrator'),
}

if set(contracts) != catalog_paths:
    missing = sorted(catalog_paths - set(contracts))
    stale = sorted(set(contracts) - catalog_paths)
    raise SystemExit(
        f'presentation inventory drift; missing={missing!r}, stale={stale!r}')

def heredocs(text):
    """Return shell heredoc bodies with their source opener and line."""
    lines = text.splitlines()
    found = []
    for index, opener in enumerate(lines):
        match = re.search(
            r"<<-?['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?", opener)
        if not match:
            continue
        delimiter = match.group(1)
        end = index + 1
        while end < len(lines) and lines[end].strip() != delimiter:
            end += 1
        # Snippets also embed documentation and program source that can show
        # a heredoc opener as inert payload text. Only complete shell-level
        # candidates can bind a producer contract here.
        if end == len(lines):
            continue
        found.append((index + 1, opener, '\n'.join(lines[index + 1:end])))
    return found

def matching_helper_heredocs(text, command, marker):
    basename = pathlib.PurePosixPath(command).name
    matches = []
    for line_number, opener, body in heredocs(text):
        # Direct writers name the command in the opener. Staged writers name
        # it in the payload header/preamble. This also binds the Flatpak GUI
        # alias to its shared policy-controller payload.
        preamble = '\n'.join(body.splitlines()[:14])
        if (marker in body
                and (basename in opener or basename in preamble)):
            matches.append((line_number, opener, body))
    return matches

# These three public commands deliberately render an equivalent native frame:
# one is Python, one mirrors the Python presentation without loading privileged
# code from an ad-hoc path, and one is the established nine-step orchestrator.
equivalent_renderers = {
    '/usr/local/sbin/noid-dns-mode': (
        'def _tty_banner(',
        "_tty_banner('NoID Privacy — DNS over TLS',",
    ),
    '/usr/local/bin/noid-usbguard-devices': (
        'def fmt_tty_banner(',
        'if not _FMT_TTY:',
        '"NoID Privacy — USBGuard Devices",',
        'fmt_section("Blocked USB devices")',
        'fmt_section("Persistent block/reject rules")',
    ),
    '/usr/local/bin/noid-update-all.sh': (
        'NoID Privacy — System Update Orchestrator',
        'Update Summary',
    ),
}

for command, (module, marker) in contracts.items():
    source = root / 'kickstart' / 'snippets' / module
    text = source.read_text(encoding='utf-8')
    matches = matching_helper_heredocs(text, command, marker)
    if len(matches) != 1:
        locations = [(line, opener) for line, opener, _body in matches]
        raise SystemExit(
            f'{command}: expected marker in exactly one matching helper '
            f'heredoc in {module}, found {locations!r}: {marker!r}')
    helper_body = matches[0][2]

    if command in equivalent_renderers:
        missing_equivalent = [
            required for required in equivalent_renderers[command]
            if required not in helper_body
        ]
        if missing_equivalent:
            raise SystemExit(
                f'{command}: equivalent presentation contract is incomplete: '
                f'{missing_equivalent!r}')
    else:
        if '/usr/local/lib/noid-privacy/agent-install-format.sh' not in helper_body:
            raise SystemExit(
                f'{command}: public CLI does not load the shared formatter')
        if 'NOID_FMT_AUTO_TITLE=' not in helper_body and 'fmt_banner ' not in helper_body:
            raise SystemExit(
                f'{command}: public CLI loads the formatter but presents no banner')

    # Mutation control: the same marker elsewhere in the module must not make
    # the helper contract pass once it is absent from the payload heredoc.
    outside_only = text.replace(marker, '') + f'\n# {marker}\n'
    if matching_helper_heredocs(outside_only, command, marker):
        raise SystemExit(
            f'{command}: whole-module marker injection bypassed heredoc binding')

print(f'presentation contracts complete: {len(contracts)}/{len(catalog_paths)}')
PY
); then
    _pass "every in-repo Tools CLI has a reviewed presentation marker"
else
    printf '%s\n' "$presentation_result" | sed 's/^/      /' >&2
    _fail "in-repo Tools CLI presentation inventory drifted"
fi

test_finish

#!/bin/bash
# 05-lan-isolation-structural — verify Module 05 LAN isolation (L5-L7)
#
# Checks:
#   - resolved.conf.d drop-in has Quad9 DNS + DoT + DNSSEC + LLMNR/mDNS off
#   - NetworkManager conf.d has [main] hostname-mode=none + [connectivity] enabled=false
#     (per-connection properties moved to Module 23 dispatcher 40-noid-connection-defaults
#     after NM 1.54+ rejected them as conf.d defaults — tested in 23-networkmanager-structural)
#   - maintained GVfs WSDD/DNS-SD GSettings disabled via dconf defaults/locks
#   - no RPM-owned /usr/share/gvfs rewrite or tmpfiles overwrite
#   - Package exclusions: optional Avahi integrations, nss-mdns, samba server,
#     cups-browsed
#   - Service masks: avahi, wsdd, cups triple
#   - noid-lan-allow escape-hatch script
#   - noid-dns-mode global + physical DoT selector with VPN isolation

set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/05-lan-isolation.ks"
PAM_KS="$PROJECT_ROOT/kickstart/snippets/10-pam-login.ks"
DOT_RUNTIME="$PROJECT_ROOT/tests/pre-ship/05-resolved-dot-runtime.sh"
TEST_LEDGER="$PROJECT_ROOT/tests/README.md"

test_start "05-lan-isolation-structural"

assert_file_exists "$KS_FILE"
assert_file_executable "$DOT_RUNTIME" \
    "global DoT/per-link VPN runtime gate is executable"
assert_cmd_success "DoT runtime gate parses" bash -n "$DOT_RUNTIME"
assert_grep_fixed 'fresh-install:quad9-query|live:vpn-query|live:vpn-dot-query|fresh-install:vpn-query|fresh-install:vpn-dot-query|reboot:vpn-query|reboot:vpn-dot-query' \
    "$DOT_RUNTIME" "controlled direct and in-tunnel transport probes are explicit"
assert_grep_fixed 'global_row.get("dnsOverTLS") != expected_mode' \
    "$DOT_RUNTIME" "runtime gate binds global DoT to the selected mode"
assert_grep_fixed 'generic unset-profile DNS transport is not opportunistic' \
    "$DOT_RUNTIME" "runtime gate pins the merged generic NetworkManager default"
assert_grep_fixed 'profile_mode.stdout.strip() not in {' \
    "$DOT_RUNTIME" "VPN probe requires an actually unset per-profile transport"
assert_grep_fixed 'row.get("dnsOverTLS") == "opportunistic"' \
    "$DOT_RUNTIME" "VPN probe requires the inherited opportunistic runtime mode"
assert_grep_fixed 'vpn-dot-query requires an exclusively Quad9 tunnel DNS' \
    "$DOT_RUNTIME" "DoT positive control rejects mixed provider resolver scopes"
assert_grep_fixed 'use a disposable test profile' "$DOT_RUNTIME" \
    "DoT positive control keeps provider-owned runtime state outside the fixture"
assert_grep_fixed 'connection-noid-ethernet-dns' \
    "$DOT_RUNTIME" "link-down gate verifies the native physical Strict DoT default"
assert_grep_fixed 'physical_runtime"] != "none"' \
    "$DOT_RUNTIME" "profile-default allowance is restricted to no active physical link"
assert_grep_fixed '--json=short proto.on.quad9.net.' \
    "$DOT_RUNTIME" "Quad9 protocol proof uses systemd-resolved structured output"
assert_grep_fixed 'record.get("items") != ["dot"]' \
    "$DOT_RUNTIME" "Quad9 protocol proof requires its exact documented DoT token"
assert_not_grep '"dot\."' "$DOT_RUNTIME" \
    "runtime gate does not confuse dig presentation with the TXT payload"
assert_cmd_success \
    "VPN probes preserve strict global/physical policy and include the DoT positive control" \
    awk '
        /fresh-install quad9-query/ { quad9 = NR }
        /sudo bash tests\/pre-ship\/05-resolved-dot-runtime\.sh fresh-install vpn-query/ {
            vpn = NR
        }
        /fresh-install vpn-dot-query/ { vpn_dot = NR }
        /reboot config/ { reboot = NR }
        END { exit !(quad9 && quad9 < vpn && vpn < vpn_dot && vpn_dot < reboot) }
    ' "$TEST_LEDGER"
assert_not_grep 'sudo noid-dns-mode opportunistic' "$TEST_LEDGER" \
    "VPN runtime proof never weakens the global or physical selector"

TMPDIR="$(mktemp -d)"
FIXTURE_UID=$(command id -u)
FIXTURE_GID=$(command id -g)
TOPOLOGY_FIXTURE=""
trap 'rm -rf "$TMPDIR"; [ -z "$TOPOLOGY_FIXTURE" ] || rm -f "$TOPOLOGY_FIXTURE"' EXIT

extract_heredoc "$KS_FILE" "RESOLVED_EOF"   "$TMPDIR/resolved.conf" || _fail "resolved extraction"
extract_heredoc "$KS_FILE" "NM_EOF"         "$TMPDIR/nm.conf" || _fail "NM conf extraction"
extract_heredoc "$KS_FILE" "DCONF_GVFS_EOF" "$TMPDIR/gvfs.dconf" || _fail "GVfs dconf extraction"
extract_heredoc "$KS_FILE" "DCONF_GVFS_LOCKS_EOF" "$TMPDIR/gvfs.locks" \
    || _fail "GVfs dconf locks extraction"
extract_heredoc "$KS_FILE" "RUNTIME_TMPFILES_EOF" "$TMPDIR/noid-runtime.conf" \
    || _fail "shared runtime tmpfiles extraction"
extract_heredoc "$KS_FILE" "DNS_MODE_EOF" "$TMPDIR/noid-dns-mode" \
    || _fail "global DNS transport selector extraction"
extract_heredoc "$KS_FILE" "LAN_ALLOW_EOF"  "$TMPDIR/noid-lan-allow" || _fail "noid-lan-allow extraction"
extract_heredoc "$KS_FILE" "LAN_EXPIRY_SERVICE_EOF" "$TMPDIR/lan-expiry.service" \
    || _fail "LAN expiry service extraction"
extract_heredoc "$KS_FILE" "LAN_EXPIRY_TIMER_EOF" "$TMPDIR/lan-expiry.timer" \
    || _fail "LAN expiry timer extraction"
extract_heredoc "$KS_FILE" "LAN_EXPIRY_GENERATOR_EOF" "$TMPDIR/lan-expiry-generator" \
    || _fail "LAN expiry generator extraction"
extract_heredoc "$KS_FILE" "LAN_EXPIRY_FAILURE_EOF" "$TMPDIR/lan-expiry-failure.service" \
    || _fail "LAN expiry failure service extraction"
extract_heredoc "$KS_FILE" "LAN_EXPIRY_NM_EOF" "$TMPDIR/lan-expiry-nm.conf" \
    || _fail "LAN expiry NetworkManager dependency extraction"
extract_heredoc "$PAM_KS" "SUDO_EOF" "$TMPDIR/noid-sudoers.conf" \
    || _fail "NoID Privacy sudo environment policy extraction"
# Execute the exact merged-policy AWK program shipped in the Kickstart.
# A syntax-only grep missed a real compose failure when a comparison operand
# was placed on the line after `==`; this fixture exercises both acceptance
# and the intended lexically-later-override rejection.
assert_cmd_success "merged resolved verifier extraction" \
    python3 - "$KS_FILE" "$TMPDIR/resolved-policy.awk" <<'PY'
import sys
from pathlib import Path

source = Path(sys.argv[1]).read_text(encoding='utf-8').splitlines()
starts = [
    index for index, line in enumerate(source)
    if 'M05_RESOLVED_MERGE_AWK_BEGIN' in line
]
ends = [
    index for index, line in enumerate(source)
    if 'M05_RESOLVED_MERGE_AWK_END' in line
]
assert len(starts) == 1 and len(ends) == 1 and starts[0] < ends[0]
program = '\n'.join(source[starts[0] + 1:ends[0]]) + '\n'
Path(sys.argv[2]).write_text(program, encoding='utf-8')
PY
assert_cmd_success "merged resolved verifier accepts the canonical Quad9 policy" \
    awk \
        -v expected_dns='9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net 2620:fe::fe#dns.quad9.net 2620:fe::9#dns.quad9.net' \
        -v expected_fallback='9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net' \
        -f "$TMPDIR/resolved-policy.awk" "$TMPDIR/resolved.conf"
cp "$TMPDIR/resolved.conf" "$TMPDIR/resolved-overridden.conf"
printf '%s\n' \
    '# /etc/systemd/resolved.conf.d/zzzz-foreign.conf' \
    '[Resolve]' \
    'DNSOverTLS=no' >> "$TMPDIR/resolved-overridden.conf"
assert_cmd_failure "merged resolved verifier rejects a later override" \
    awk \
        -v expected_dns='9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net 2620:fe::fe#dns.quad9.net 2620:fe::9#dns.quad9.net' \
        -v expected_fallback='9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net' \
        -f "$TMPDIR/resolved-policy.awk" "$TMPDIR/resolved-overridden.conf"

assert_cmd_success "noid-lan-allow is valid bash" bash -n "$TMPDIR/noid-lan-allow"
assert_grep_fixed 'The NOID_* defaults below are fixture seams' \
    "$TMPDIR/noid-lan-allow" \
    "LAN helper documents its privileged environment trust boundary"
assert_grep_fixed 'Defaults env_reset' "$TMPDIR/noid-sudoers.conf" \
    "sudo strips ambient variables before privileged LAN operations"
assert_not_grep_extended '^Defaults[[:space:]]+env_keep.*NOID_' \
    "$TMPDIR/noid-sudoers.conf" \
    "sudo preserves no LAN fixture override"
assert_not_grep_extended '^(Environment|PassEnvironment)=.*NOID_' \
    "$TMPDIR/lan-expiry.service" \
    "automatic LAN expiry reconciliation receives no fixture override"
lan_allow_compose_verify="$TMPDIR/lan-allow-compose-verify.sh"
lan_allow_verify_extract_rc=0
awk '
        /# M05_LAN_ALLOW_COMPOSE_VERIFY_BEGIN/ {
            if (seen++) exit 2
            copy=1
            next
        }
        /# M05_LAN_ALLOW_COMPOSE_VERIFY_END/ {
            if (!copy || closed++) exit 3
            copy=0
            next
        }
        copy { print }
        END { if (seen != 1 || closed != 1 || copy) exit 4 }
    ' "$KS_FILE" > "$lan_allow_compose_verify" \
    || lan_allow_verify_extract_rc=$?
assert_eq 0 "$lan_allow_verify_extract_rc" \
    "LAN helper compose verifier extracts from its unique markers"
chmod 0755 "$TMPDIR/noid-lan-allow"
assert_cmd_success \
    "exact compose verifier accepts the exact published LAN helper" \
    bash -c '. "$1"; verify_lan_allow_contract "$2" "$3" "$4"' \
    _ "$lan_allow_compose_verify" "$TMPDIR/noid-lan-allow" \
    "$FIXTURE_UID" "$FIXTURE_GID"
sed 's/raw ARP and kernel neighbour identity disagree/raw ARP and kernel peer mismatch/' \
    "$TMPDIR/noid-lan-allow" > "$TMPDIR/noid-lan-allow-drifted"
chmod 0755 "$TMPDIR/noid-lan-allow-drifted"
assert_cmd_failure \
    "exact compose verifier rejects LAN-helper contract drift" \
    bash -c '. "$1"; verify_lan_allow_contract "$2" "$3" "$4"' \
    _ "$lan_allow_compose_verify" "$TMPDIR/noid-lan-allow-drifted" \
    "$FIXTURE_UID" "$FIXTURE_GID"
assert_cmd_success "noid-dns-mode is valid Python" \
    python3 -c 'import ast,sys; ast.parse(open(sys.argv[1], encoding="utf-8").read())' \
    "$TMPDIR/noid-dns-mode"
assert_cmd_success "noid-dns-mode help is non-privileged and self-contained" \
    python3 "$TMPDIR/noid-dns-mode" --help
assert_cmd_success \
    "noid-lan-allow pins one C locale before localized metadata comparisons" \
    awk '
        $0 == "LC_ALL=C" { pin_count++; pin_line=NR }
        $0 == "export LC_ALL" { export_count++; export_line=NR }
        /stat -c .*%F/ && first_type_stat == 0 { first_type_stat=NR }
        END {
            exit !(pin_count == 1 && export_count == 1 &&
                   pin_line < export_line && export_line < first_type_stat)
        }
    ' "$TMPDIR/noid-lan-allow"

# --- resolved.conf.d: Quad9 DoT + DNSSEC + no LLMNR/mDNS --------------------
assert_grep_fixed '9.9.9.9#dns.quad9.net'     "$TMPDIR/resolved.conf"
assert_grep_fixed '149.112.112.112'           "$TMPDIR/resolved.conf"
assert_grep_extended '^DNSSEC=allow-downgrade$'  "$TMPDIR/resolved.conf"
assert_grep_extended '^DNSOverTLS=yes$'   "$TMPDIR/resolved.conf"
assert_grep_extended '^LLMNR=no$'                "$TMPDIR/resolved.conf"
assert_grep_extended '^MulticastDNS=no$'         "$TMPDIR/resolved.conf"
assert_grep_fixed 'install -d -m 0755 -o root -g root /etc/systemd/resolved.conf.d' \
    "$KS_FILE" "resolved drop-in directory mode is independent of the compose umask"
assert_grep_fixed "stat -c '%u:%g:%a:%F'" "$KS_FILE" \
    "compose verification pins resolved drop-in directory ownership and mode"
assert_grep_fixed 'strict certificate authentication' "$TMPDIR/resolved.conf" \
    "Quad9 entries carry the intended DoT certificate name/SNI"
assert_grep_fixed 'authenticated TLS and resolution fails closed' \
    "$TMPDIR/resolved.conf" "global Quad9 DoT is strict by image default"
assert_grep_fixed 'generic dns-over-tls=1 fallback' \
    "$TMPDIR/resolved.conf" "best-effort tunnel DoT stays isolated from physical strict DoT"
assert_not_grep 'generic dns-over-tls=0 fallback' "$KS_FILE" \
    "the retired forced-plaintext tunnel default cannot return"
assert_grep_fixed 'force validation off' "$TMPDIR/resolved.conf" \
    "allow-downgrade names its active DNSSEC downgrade boundary"
assert_grep_fixed 'proven insecure (unsigned) delegation' "$TMPDIR/resolved.conf" \
    "strict DNSSEC is not confused with requiring every domain to be signed"
assert_not_grep 'SNI verification\|~46%\|Proton DNS' "$KS_FILE" \
    "M05 contains no authentication hype, unsourced percentage or fixed VPN-provider premise"

# Exercise the exact merged-policy AWK program embedded in M05. GNU awk does
# not continue a statement merely because a line ends after `==`; this fixture
# prevents a syntactically valid Bash/Kickstart file from hiding that runtime
# parser failure again.
resolved_merge_awk="$TMPDIR/resolved-merge.awk"
resolved_merge_extract_rc=0
awk '
        /# M05_RESOLVED_MERGE_AWK_BEGIN/ {
            if (seen++) exit 2
            copy=1
            next
        }
        /# M05_RESOLVED_MERGE_AWK_END/ {
            if (!copy || closed++) exit 3
            copy=0
            next
        }
        copy { print }
        END { if (seen != 1 || closed != 1 || copy) exit 4 }
    ' "$KS_FILE" > "$resolved_merge_awk" || resolved_merge_extract_rc=$?
assert_eq 0 "$resolved_merge_extract_rc" \
    "merged resolved verifier extracts from its unique markers"
m05_expected_dns=$(sed -n "s/^resolved_expected_dns='\\(.*\\)'$/\\1/p" "$KS_FILE")
m05_expected_fallback=$(sed -n "s/^resolved_expected_fallback='\\(.*\\)'$/\\1/p" "$KS_FILE")
assert_eq "$(sed -n 's/^DNS=//p' "$TMPDIR/resolved.conf")" \
    "$m05_expected_dns" "merged verifier pins the exact configured DNS set"
assert_eq "$(sed -n 's/^FallbackDNS=//p' "$TMPDIR/resolved.conf")" \
    "$m05_expected_fallback" \
    "merged verifier pins the exact configured fallback set"
assert_cmd_success "merged resolved verifier accepts the exact M05 policy" \
    awk -v expected_dns="$m05_expected_dns" \
        -v expected_fallback="$m05_expected_fallback" \
        -f "$resolved_merge_awk" "$TMPDIR/resolved.conf"
cp "$TMPDIR/resolved.conf" "$TMPDIR/resolved-overridden.conf"
printf '%s\n' '[Resolve]' 'DNSOverTLS=no' \
    >> "$TMPDIR/resolved-overridden.conf"
assert_cmd_failure "merged resolved verifier rejects a later transport override" \
    awk -v expected_dns="$m05_expected_dns" \
        -v expected_fallback="$m05_expected_fallback" \
        -f "$resolved_merge_awk" "$TMPDIR/resolved-overridden.conf"

# --- native global DNS transport selector ----------------------------------
assert_grep_fixed "MODE_VALUE = {" "$TMPDIR/noid-dns-mode"
for contract in \
        "'off': 'no'" \
        "'opportunistic': 'opportunistic'" \
        "'strict': 'yes'"; do
    assert_grep_fixed "$contract" "$TMPDIR/noid-dns-mode" \
        "DNS selector maps the closed CLI mode: $contract"
done
assert_grep_fixed "MODE_CONF = CONF_DIR / 'zzzz-noid-dns-mode.conf'" \
    "$TMPDIR/noid-dns-mode" \
    "DNS selector owns one lexically late resolved drop-in"
assert_grep_fixed "'NOID-DNS-MODE-V2'" "$TMPDIR/noid-dns-mode" \
    "DNS selector publishes a versioned machine-status schema"
assert_grep_fixed "'selection', 'configured', 'runtime_global'," \
    "$TMPDIR/noid-dns-mode" \
    "DNS machine status starts with desired, merged and runtime truth"
assert_grep_fixed "'physical_configured', 'physical_runtime', 'scope', 'link_mode'" \
    "$TMPDIR/noid-dns-mode" \
    "DNS machine status also exposes physical and routing truth"
assert_grep_fixed "domain.get('name') == '.'" "$TMPDIR/noid-dns-mode" \
    "DNS selector detects a provider/private catch-all link"
assert_grep_fixed "domain.get('routeOnly') is True" "$TMPDIR/noid-dns-mode" \
    "DNS selector distinguishes the native ~. routing scope"
assert_grep_fixed "global_servers_named" "$TMPDIR/noid-dns-mode" \
    "strict mode requires certificate-named global resolvers"
assert_grep_fixed "MODE_CONF.unlink()" "$TMPDIR/noid-dns-mode" \
    "reset removes only the selector-owned drop-in"
assert_grep_fixed "os.replace(temp, MODE_CONF)" "$TMPDIR/noid-dns-mode" \
    "DNS selector publishes atomically without following the destination"
assert_grep_fixed "_trusted_regular_file(MODE_CONF, 0o644)" \
    "$TMPDIR/noid-dns-mode" \
    "published DNS selector bytes retain the exact metadata contract"
assert_grep_fixed "[MATCHPATHCON, '-V', str(MODE_CONF)]" \
    "$TMPDIR/noid-dns-mode" \
    "published DNS selector bytes receive the expected SELinux label"
assert_grep_fixed "os.O_NOFOLLOW" "$TMPDIR/noid-dns-mode" \
    "DNS selector lock rejects symlink traversal"
assert_grep_fixed "_restore(old_selection)" "$TMPDIR/noid-dns-mode" \
    "failed convergence restores the previous DNS selection"
assert_grep_fixed "[SYSTEMCTL, 'reload', 'systemd-resolved.service']" \
    "$TMPDIR/noid-dns-mode" \
    "DNS selector uses the native notify-reload path without destroying link state"
assert_cmd_failure \
    "DNS selector never tears down resolve1 link objects for a config change" \
    grep -qF -- "[SYSTEMCTL, 'restart', 'systemd-resolved.service']" \
        "$TMPDIR/noid-dns-mode"
assert_grep_fixed "VPN/private per-link profiles were not rewritten" \
    "$TMPDIR/noid-dns-mode" \
    "CLI names the exact physical/profile mutation boundary"
assert_grep_fixed "NoID Privacy's generic \`opportunistic\` connection" \
    "$TMPDIR/noid-dns-mode" \
    "CLI attributes an unset tunnel transport to the image connection default"
assert_not_grep 'provider-supplied transport policy\|provider/tunnel link policy' \
    "$TMPDIR/noid-dns-mode" \
    "CLI does not misattribute an inherited tunnel transport to the provider"
assert_not_grep 'VPN/private per-link DNS is unchanged' \
    "$TMPDIR/noid-dns-mode" \
    "generated resolver policy does not confuse profile mutation with effective DNS"
assert_grep_fixed "PHYSICAL_TYPES = {" "$TMPDIR/noid-dns-mode" \
    "physical mutation is closed to native Ethernet and Wi-Fi types"
assert_grep_fixed "_strict_physical_defaults_are_effective()" \
    "$TMPDIR/noid-dns-mode" \
    "an inherited profile mode is trusted only after effective M23 default validation"
assert_grep_fixed "values == {'default', 'yes'}" "$TMPDIR/noid-dns-mode" \
    "only the strict explicit/inherited combination may converge semantically"
assert_grep_fixed "[NMCLI, 'connection', 'modify', profile['uuid']," \
    "$TMPDIR/noid-dns-mode" \
    "installed physical profiles use NetworkManager's native mutation API"
assert_grep_fixed "[NMCLI, 'device', 'modify', profile['device']," \
    "$TMPDIR/noid-dns-mode" \
    "Live physical profiles use NetworkManager's runtime mutation API"
assert_grep_fixed "_restore_physical(" "$TMPDIR/noid-dns-mode" \
    "global rollback restores the exact physical pre-state"
assert_grep_fixed "args == ['--physical-value']" "$TMPDIR/noid-dns-mode" \
    "M23 consumes one closed selected physical-mode value"
assert_not_grep "resolvectl.*query\|RESOLVECTL, 'query'" "$TMPDIR/noid-dns-mode" \
    "changing DNS mode does not generate an unrelated test query"
assert_grep_fixed 'chmod 0755 /usr/local/sbin/noid-dns-mode' "$KS_FILE" \
    "global DNS selector installs as an executable"
assert_grep_fixed \
    "stat -c '%u:%g:%a:%h:%F' \\" "$KS_FILE" \
    "compose verification checks exact owned-file metadata"
# `sudo -l` exit 0 only means "permitted by the security policy", which
# %wheel ALL=(ALL) ALL grants every wheel member, so it is no evidence of a
# passwordless route. Only the verbose listing's `!authenticate` tag is.
assert_grep_fixed "'-n', '-l', '-l', '--'" \
    "$TMPDIR/noid-dns-mode" \
    "direct DNS CLI asks for the matching sudoers entry, not just permission"
assert_grep_fixed "'!authenticate' in listing" \
    "$TMPDIR/noid-dns-mode" \
    "direct DNS CLI requires an explicit passwordless tag before choosing sudo"
assert_grep_fixed "listing.count('Matched:') == 1" \
    "$TMPDIR/noid-dns-mode" \
    "direct DNS CLI requires one unambiguous matching sudoers entry"
assert_grep_fixed "LC_ALL=C.UTF-8" \
    "$TMPDIR/noid-dns-mode" \
    "the translated sudo listing is read under a pinned locale"
assert_grep_fixed \
    "'/usr/bin/sudo', ['/usr/bin/sudo', '-n', '--'] + argv" \
    "$TMPDIR/noid-dns-mode" \
    "authorized direct DNS CLI route remains noninteractive"
assert_grep_fixed \
    "os.execv('/usr/bin/pkexec', ['/usr/bin/pkexec'] + argv)" \
    "$TMPDIR/noid-dns-mode" \
    "direct DNS CLI retains the exact-program polkit fallback"
assert_cmd_success "DNS selector privilege route is closed over root, Live, sudo, and polkit" \
    python3 - "$TMPDIR/noid-dns-mode" <<'PY'
import ast
import sys
from types import SimpleNamespace

tree = ast.parse(open(sys.argv[1], encoding='utf-8').read())
wanted_functions = {
    '_noninteractive_sudo_authorizes',
    '_become_root',
}
body = [
    node for node in tree.body
    if ((isinstance(node, ast.FunctionDef)
         and node.name in wanted_functions)
        or (isinstance(node, ast.ClassDef) and node.name == 'ModeError'))
]
assert {
    node.name for node in body if isinstance(node, ast.FunctionDef)
} == wanted_functions
module = ast.Module(body=body, type_ignores=[])
ast.fix_missing_locations(module)

class ExecCalled(Exception):
    pass

class FakeOS:
    euid = 1000
    calls = []

    @classmethod
    def geteuid(cls):
        return cls.euid

    @classmethod
    def execv(cls, path, argv):
        cls.calls.append((path, argv))
        raise ExecCalled

state = {'live': False, 'sudo_rc': 1, 'sudo_out': '', 'policy_calls': []}
def run(argv, timeout):
    state['policy_calls'].append((argv, timeout))
    return SimpleNamespace(returncode=state['sudo_rc'],
                           stdout=state['sudo_out'])

namespace = {
    'SELF': '/usr/local/sbin/noid-dns-mode',
    '_is_live_session': lambda: state['live'],
    '_run': run,
    'os': FakeOS,
}
exec(compile(module, '<noid-dns-mode-privilege>', 'exec'), namespace)
become_root = namespace['_become_root']
backend = ['/usr/local/sbin/noid-dns-mode', 'strict']

try:
    become_root('strict')
except ExecCalled:
    pass
assert FakeOS.calls[-1] == \
       ('/usr/bin/pkexec', ['/usr/bin/pkexec'] + backend)
assert state['policy_calls'][-1] == \
       (['/usr/bin/env', 'LC_ALL=C.UTF-8', 'LANG=C.UTF-8',
         '/usr/bin/sudo', '-n', '-l', '-l', '--'] + backend, 3)

# "Permitted by the security policy" is not "passwordless": a PASSWD-tagged
# %wheel match must still route through polkit, or `sudo -n` fails with
# "a password is required" and the selector never runs.
state['sudo_rc'] = 0
state['sudo_out'] = ('Sudoers entry: /etc/sudoers.d/10-wheel\n'
                     '    Options: setenv\n'
                     '    Matched: /usr/local/sbin/noid-dns-mode strict\n')
try:
    become_root('strict')
except ExecCalled:
    pass
assert FakeOS.calls[-1] == \
       ('/usr/bin/pkexec', ['/usr/bin/pkexec'] + backend)

state['sudo_out'] = ('Sudoers entry: /etc/sudoers.d/90-owner\n'
                     '    Options: !authenticate\n'
                     '    Matched: /usr/local/sbin/noid-dns-mode strict\n')
try:
    become_root('strict')
except ExecCalled:
    pass
assert FakeOS.calls[-1] == \
       ('/usr/bin/sudo', ['/usr/bin/sudo', '-n', '--'] + backend)

state['sudo_out'] = ('Sudoers entry: /etc/sudoers.d/90-owner\n'
                     '    Options: !authenticate\n'
                     '    Matched: /usr/local/sbin/noid-dns-mode strict\n'
                     'Sudoers entry: /etc/sudoers.d/10-wheel\n'
                     '    Options: setenv\n'
                     '    Matched: /usr/local/sbin/noid-dns-mode strict\n')
try:
    become_root('strict')
except ExecCalled:
    pass
assert FakeOS.calls[-1] == \
       ('/usr/bin/pkexec', ['/usr/bin/pkexec'] + backend)

state['live'] = True
policy_count = len(state['policy_calls'])
try:
    become_root('strict')
except ExecCalled:
    pass
assert FakeOS.calls[-1] == \
       ('/usr/bin/sudo', ['/usr/bin/sudo', '-n', '--'] + backend)
assert len(state['policy_calls']) == policy_count

FakeOS.euid = 0
exec_count = len(FakeOS.calls)
assert become_root('strict') is None
assert len(FakeOS.calls) == exec_count
PY
assert_cmd_success "DNS selector parser and rollback state machine fixtures" \
    python3 - "$TMPDIR/noid-dns-mode" <<'PY'
import contextlib
import io
import json
import os
import runpy
import sys
from types import SimpleNamespace

loaded = runpy.run_path(sys.argv[1], run_name='noid_dns_mode_fixture')
# runpy returns a result mapping, while function objects retain the executed
# module's own globals dictionary. Patch that authoritative dictionary.
ns = loaded['_runtime_state'].__globals__

global_row = {
    'dnsOverTLS': 'opportunistic',
    'servers': [
        {'addressString': '9.9.9.9', 'name': 'dns.quad9.net'},
        {'addressString': '149.112.112.112', 'name': 'dns.quad9.net'},
    ],
}
vpn_row = {
    'ifname': 'vpn-test0',
    'dnsOverTLS': 'no',
    'servers': [{'addressString': '10.0.0.1'}],
    'searchDomains': [{'name': '.', 'routeOnly': True}],
}

def completed(stdout, rc=0):
    return SimpleNamespace(returncode=rc, stdout=stdout, stderr='')

ns['_run'] = lambda argv, timeout=10: completed(
    json.dumps([global_row, vpn_row]))
state = ns['_runtime_state']([])
assert state == {
    'runtime_global': 'opportunistic',
    'scope': 'link',
    'link_mode': 'no',
    'physical_runtime': 'none',
    'global_servers_named': True,
    'physical_servers_named': True,
    'physical_runtime_by_ifname': {},
}

ns['_run'] = lambda argv, timeout=10: completed(json.dumps([global_row]))
state = ns['_runtime_state']([])
assert state['scope'] == 'global'
assert state['link_mode'] == 'none'
assert state['global_servers_named'] is True

unnamed = dict(global_row)
unnamed['servers'] = [{'addressString': '192.0.2.53'}]
ns['_run'] = lambda argv, timeout=10: completed(json.dumps([unnamed]))
assert ns['_runtime_state']([])['global_servers_named'] is False

ns['_run'] = lambda argv, timeout=10: completed('{not-json')
assert ns['_runtime_state']([])['runtime_global'] == 'unknown'

physical = [{
    'uuid': '11111111-1111-4111-8111-111111111111',
    'type': '802-11-wireless',
    'device': 'wlan0',
    'configured': 'yes',
}]
physical_row = {
    'ifname': 'wlan0',
    'dnsOverTLS': 'yes',
    'servers': [
        {'addressString': '9.9.9.9', 'name': 'dns.quad9.net'},
    ],
    'searchDomains': [{'name': '.', 'routeOnly': True}],
}
ns['_run'] = lambda argv, timeout=10: completed(
    json.dumps([global_row, physical_row]))
state = ns['_runtime_state'](physical)
assert state['scope'] == 'physical'
assert state['physical_runtime'] == 'yes'
assert state['physical_servers_named'] is True
assert state['physical_runtime_by_ifname'] == {'wlan0': 'yes'}

merged = '''
[Resolve]
DNSOverTLS=no
# /etc/systemd/resolved.conf.d/99-privacy.conf
[Resolve]
DNSOverTLS=opportunistic
# /etc/systemd/resolved.conf.d/zzzz-noid-dns-mode.conf
[Resolve]
DNSOverTLS=yes
'''
ns['_run'] = lambda argv, timeout=10: completed(merged)
assert ns['_configured_mode']() == 'yes'

ModeError = ns['ModeError']

def fixture_change(action, *, publish_error=False, named=True):
    events = []
    lock_fd = os.open('/dev/null', os.O_RDONLY)
    ns['_become_root'] = lambda selected: events.append(('root', selected))
    ns['_trusted_directory'] = lambda path, mode: events.append(
        ('dir', str(path), mode))
    ns['_trusted_regular_file'] = lambda path, mode: events.append(
        ('file', str(path), mode))
    ns['_selection'] = lambda: 'default'
    ns['_lock'] = lambda: lock_fd
    profiles = [{
        'uuid': '11111111-1111-4111-8111-111111111111',
        'type': '802-11-wireless',
        'device': 'wlan0',
        'configured': 'yes',
    }]
    ns['_managed_physical_profiles'] = lambda: profiles
    ns['_runtime_state'] = lambda profiles=None: {
        'global_servers_named': named,
        'physical_servers_named': named,
        'runtime_global': 'yes',
        'physical_runtime': 'yes',
        'physical_runtime_by_ifname': {'wlan0': 'yes'},
        'scope': 'global',
        'link_mode': 'none',
    }
    def publish(mode):
        events.append(('publish', mode))
        if publish_error:
            raise ModeError('fixture publication failed')
    ns['_publish'] = publish
    ns['_remove'] = lambda: events.append(('remove',))
    ns['_configured_mode'] = lambda: (
        'yes' if action == 'reset'
        else ns['MODE_VALUE'][action])
    ns['_reload_and_wait'] = lambda expected: events.append(
        ('reload', expected))
    ns['_restore'] = lambda previous: events.append(('restore', previous))
    ns['_set_physical'] = lambda current, expected: events.append(
        ('physical', expected))
    ns['_restore_physical'] = lambda current, runtime: events.append(
        ('physical-restore', tuple(sorted(runtime.items()))))
    ns['_state'] = lambda: {
        'selection': action if action != 'reset' else 'default',
        'configured': (
            'yes' if action == 'reset'
            else ns['MODE_VALUE'][action]),
        'runtime_global': (
            'yes' if action == 'reset'
            else ns['MODE_VALUE'][action]),
        'physical_configured': (
            'yes' if action == 'reset' else ns['MODE_VALUE'][action]),
        'physical_runtime': (
            'yes' if action == 'reset' else ns['MODE_VALUE'][action]),
        'scope': 'global',
        'link_mode': 'none',
    }
    ns['_human_status'] = lambda state: events.append(('status',))
    with contextlib.redirect_stdout(io.StringIO()):
        try:
            ns['_change'](action)
        except ModeError as exc:
            return events, str(exc)
    return events, None

events, error = fixture_change('strict')
assert error is None
assert ('publish', 'strict') in events
assert ('reload', 'yes') in events
assert ('physical', 'yes') in events
assert not any(event[0] == 'restore' for event in events)

events, error = fixture_change('strict', publish_error=True)
assert error and 'previous DNS mode restored' in error
assert events.index(('publish', 'strict')) < events.index(('restore', 'default'))
assert ('reload', 'yes') in events
assert any(event[0] == 'physical-restore' for event in events)

events, error = fixture_change('strict', named=False)
assert error and 'certificate name/SNI' in error
assert not any(event[0] in {'publish', 'restore', 'reload', 'physical'}
               for event in events)

events, error = fixture_change('reset')
assert error is None
assert ('remove',) in events
assert ('reload', 'yes') in events
assert ('physical', 'yes') in events
PY

assert_cmd_success "DNS selector physical ownership and native mutation fixtures" \
    python3 - "$TMPDIR/noid-dns-mode" <<'PY'
import runpy
import sys
from types import SimpleNamespace

loaded = runpy.run_path(sys.argv[1], run_name='noid_dns_physical_fixture')
ns = loaded['_managed_physical_profiles'].__globals__
calls = []

def completed(stdout='', rc=0, stderr=''):
    return SimpleNamespace(
        returncode=rc, stdout=stdout, stderr=stderr)

physical_uuid = '11111111-1111-4111-8111-111111111111'
inactive_uuid = '33333333-3333-4333-8333-333333333333'
vpn_uuid = '22222222-2222-4222-8222-222222222222'

def enumerate_run(argv, timeout=10):
    calls.append(tuple(argv))
    if argv[-3:] == ['connection', 'show', '--active']:
        return completed(
            f'{physical_uuid}:wlan0\n'
            f'{vpn_uuid}:wg0\n')
    if argv[-2:] == ['connection', 'show']:
        return completed(
            f'{physical_uuid}:802-11-wireless\n'
            f'{inactive_uuid}:802-3-ethernet\n'
            f'{vpn_uuid}:wireguard\n')
    if argv[-3:] == ['connection', 'show', physical_uuid]:
        return completed('2\n')
    if argv[-3:] == ['connection', 'show', inactive_uuid]:
        return completed('2\n')
    raise AssertionError(argv)

ns['_run'] = enumerate_run
ns['_is_live_boot'] = lambda: False
profiles = ns['_managed_physical_profiles']()
assert profiles == [
    {
        'uuid': inactive_uuid,
        'type': '802-3-ethernet',
        'device': '',
        'configured': 'yes',
    },
    {
        'uuid': physical_uuid,
        'type': '802-11-wireless',
        'device': 'wlan0',
        'configured': 'yes',
    },
]
assert not any(vpn_uuid in part for call in calls for part in call[1:])

def physical_defaults_run(argv, timeout=10):
    assert argv == [ns['NETWORKMANAGER'], '--print-config']
    return completed('''
[connection-noid-ethernet-dns]
match-device=type:ethernet
connection.dns-over-tls=2
[connection-noid-wifi-dns]
match-device=type:wifi
connection.dns-over-tls=2
''')

ns['_run'] = physical_defaults_run
assert ns['_strict_physical_defaults_are_effective']()

mixed_profiles = [
    {
        'uuid': inactive_uuid,
        'type': '802-3-ethernet',
        'device': '',
        'configured': 'default',
    },
    {
        'uuid': physical_uuid,
        'type': '802-11-wireless',
        'device': 'wlan0',
        'configured': 'yes',
    },
]
runtime = {
    'runtime_global': 'yes',
    'scope': 'global',
    'link_mode': 'none',
    'physical_runtime': 'yes',
    'global_servers_named': True,
    'physical_servers_named': True,
    'physical_runtime_by_ifname': {'wlan0': 'yes'},
}
ns['_managed_physical_profiles'] = lambda: mixed_profiles
ns['_runtime_state'] = lambda profiles=None: runtime
ns['_selection'] = lambda: 'default'
ns['_configured_mode'] = lambda: 'yes'
ns['_is_live_boot'] = lambda: False
ns['_strict_physical_defaults_are_effective'] = lambda: True
assert ns['_state']()['physical_configured'] == 'yes'
ns['_strict_physical_defaults_are_effective'] = lambda: False
assert ns['_state']()['physical_configured'] == 'mixed'
ns['_strict_physical_defaults_are_effective'] = lambda: True
mixed_profiles[0]['configured'] = 'no'
assert ns['_state']()['physical_configured'] == 'mixed'
mixed_profiles[0]['configured'] = 'default'
mixed_profiles[1]['configured'] = 'default'
assert ns['_state']()['physical_configured'] == 'default'

mutation_calls = []
def installed_mutation(argv, timeout=10):
    mutation_calls.append(tuple(argv))
    if argv[-3:] == ['connection', 'show', physical_uuid]:
        return completed('1\n')
    if argv[-3:] == ['connection', 'show', inactive_uuid]:
        return completed('1\n')
    return completed()
ns['_run'] = installed_mutation
ns['_is_live_boot'] = lambda: False
active = next(profile for profile in profiles if profile['device'])
inactive = next(profile for profile in profiles if not profile['device'])
ns['_apply_physical_value'](active, 'opportunistic')
assert mutation_calls == [
    (ns['NMCLI'], 'connection', 'modify', physical_uuid,
     'connection.dns-over-tls', 'opportunistic'),
    (ns['NMCLI'], 'device', 'reapply', 'wlan0'),
    (ns['NMCLI'], '-e', 'no', '-g', 'connection.dns-over-tls',
     'connection', 'show', physical_uuid),
]
mutation_calls.clear()
ns['_apply_physical_value'](inactive, 'opportunistic')
assert mutation_calls == [
    (ns['NMCLI'], 'connection', 'modify', inactive_uuid,
     'connection.dns-over-tls', 'opportunistic'),
    (ns['NMCLI'], '-e', 'no', '-g', 'connection.dns-over-tls',
     'connection', 'show', inactive_uuid),
]

mutation_calls.clear()
ns['_is_live_boot'] = lambda: True
ns['_run'] = lambda argv, timeout=10: (
    mutation_calls.append(tuple(argv)) or completed())
ns['_apply_physical_value'](active, 'yes')
assert mutation_calls == [
    (ns['NMCLI'], 'device', 'modify', 'wlan0',
     'connection.dns-over-tls', 'yes'),
    (ns['RESOLVECTL'], 'dnsovertls', 'wlan0', 'yes'),
]
PY

# --- NM conf 99-privacy.conf: only [main] hostname-mode + [connectivity] -----
# All per-connection properties (ignore-auto-dns/routes, lldp, dhcp-send-hostname,
# ip6-privacy, addr-gen-mode, mdns/llmnr) were rejected by NM 1.54+ as
# connection-defaults and migrated to the Module 23 dispatcher
# (/etc/NetworkManager/dispatcher.d/40-noid-connection-defaults). They are
# tested by tests/23-networkmanager-structural.sh — not here.
assert_grep_extended '^hostname-mode=none$'  "$TMPDIR/nm.conf" "[main] hostname-mode=none"
assert_grep_extended '^enabled=false$'       "$TMPDIR/nm.conf" "[connectivity] enabled=false"

# --- native GVfs discovery policy -------------------------------------------
assert_grep_fixed '[org/gnome/system/wsdd]' "$TMPDIR/gvfs.dconf"
assert_grep_fixed "display-mode='disabled'" "$TMPDIR/gvfs.dconf"
assert_grep_fixed '[org/gnome/system/dns-sd]' "$TMPDIR/gvfs.dconf"
assert_grep_fixed "display-local='disabled'" "$TMPDIR/gvfs.dconf"
assert_grep_fixed '/org/gnome/system/wsdd/display-mode' "$TMPDIR/gvfs.locks"
assert_grep_fixed '/org/gnome/system/dns-sd/display-local' "$TMPDIR/gvfs.locks"
assert_not_grep 'cat > /usr/share/gvfs/mounts\|noid-gvfs-silence.conf\|AutoMount=false' \
    "$KS_FILE" "M05 never rewrites or re-overwrites RPM-owned GVfs mount files"
mkdir -p "$TMPDIR/dconf.d/locks"
cp "$TMPDIR/gvfs.dconf" "$TMPDIR/dconf.d/04-noid-lan-discovery"
cp "$TMPDIR/gvfs.locks" "$TMPDIR/dconf.d/locks/04-noid-lan-discovery"
assert_cmd_success "native GVfs dconf source compiles" \
    dconf compile "$TMPDIR/dconf.db" "$TMPDIR/dconf.d"
assert_cmd_success "installed GVfs WSDD schema exposes disabled enum" \
    bash -c "gsettings range org.gnome.system.wsdd display-mode | grep -qw disabled"
assert_cmd_success "installed GVfs DNS-SD schema exposes disabled enum" \
    bash -c "gsettings range org.gnome.system.dns_sd display-local | grep -qw disabled"
assert_grep_fixed 'rpm -V gvfs' "$KS_FILE" \
    "compose verification rejects GVfs package drift"
assert_not_grep "stat -Lc '%u:%g:%a:%h:%F' /usr/local/bin/noid-lan-allow" \
    "$KS_FILE" "installed helper verification does not follow a symlink"
assert_not_grep 'no DHCP Option 12 hostname leak\|Prevent NM from sending hostname' \
    "$KS_FILE" "hostname-mode is not mislabeled as DHCP send suppression"
assert_eq 9 \
    "$(grep -Evc '^[[:space:]]*(#|$)' "$TMPDIR/noid-runtime.conf")" \
    "shared runtime tmpfiles contract owns its directory, six locks and two explicit SELinux relabel entries"
# M12's audit-notify.service runs ProtectSystem=strict with
# ReadWritePaths=/run/noid-privacy, so its toggle lock has to live under the
# shared directory this file boot-creates rather than directly in /run.
assert_grep_fixed 'f /run/noid-privacy/audit-notify-toggle.lock 0600 root root -' \
    "$TMPDIR/noid-runtime.conf" \
    "shared runtime directory boot-creates the audit-notify toggle lock"
assert_grep_fixed 'd /run/noid-privacy 0755 root root -' \
    "$TMPDIR/noid-runtime.conf" \
    "shared NoID Privacy runtime directory has one boot-wide tmpfiles owner"
assert_grep_fixed 'f /run/noid-privacy/lan-exceptions.lock 0600 root root -' \
    "$TMPDIR/noid-runtime.conf" \
    "M05 transaction lock exists root-private before the boot gate"
assert_grep_fixed 'f /run/noid-privacy/lan-topology-refresh.lock 0600 root root -' \
    "$TMPDIR/noid-runtime.conf" \
    "M03 topology lock exists root-private before the boot gate"
assert_grep_fixed 'f /run/noid-privacy/dns-mode.lock 0600 root root -' \
    "$TMPDIR/noid-runtime.conf" \
    "global DNS transport changes serialize on a root-private lock"
assert_grep_fixed 'f /run/noid-privacy/usbguard-add-user.lock 0600 root root -' \
    "$TMPDIR/noid-runtime.conf" \
    "USBGuard reconciliation lock exists before the Live boot gate"
assert_grep_fixed 'z /run/noid-privacy/usbguard-add-user.lock 0600 root root -' \
    "$TMPDIR/noid-runtime.conf" \
    "USBGuard reconciliation lock is restored to its defined SELinux context"
assert_grep_fixed 'f /run/noid-privacy/displaylink.lock 0600 root root -' \
    "$TMPDIR/noid-runtime.conf" \
    "DisplayLink transaction lock is pre-created in the labelled runtime namespace"
assert_grep_fixed 'z /run/noid-privacy/displaylink.lock 0600 root root -' \
    "$TMPDIR/noid-runtime.conf" \
    "DisplayLink transaction lock is restored to its defined SELinux context"
assert_grep_fixed 'No consumer may claim the shared path through RuntimeDirectory=' \
    "$KS_FILE" "shared runtime lifetime cannot regress to per-service ownership"

# --- Package exclusions in KS source ----------------------------------------
# Note: avahi (main pkg) and samba-common are INTENTIONALLY not excluded —
# F44 GNOME 50 stack hard-deps on libavahi-core.so.7 (avahi) and libsmbclient
# (samba-common). The service-bearing avahi package is kept and its native
# daemon activation is masked in %post; samba-common has no daemon executable.
PACKAGES_FILE="$TMPDIR/packages.list"
packages_extract_rc=0
awk '
    /^%packages([[:space:]]|$)/ { if (seen++) exit 2; packages=1; next }
    packages && /^%end[[:space:]]*$/ { packages=0; closed++; next }
    packages { print }
    END { if (seen != 1 || closed != 1 || packages) exit 3 }
' "$KS_FILE" > "$PACKAGES_FILE" || packages_extract_rc=$?
assert_eq 0 "$packages_extract_rc" \
    "M05 has one closed package block for exact exclusion checks"
for pkg in -avahi-autoipd -avahi-tools -avahi-ui -avahi-ui-tools -nss-mdns \
           -samba -samba-client -cups-browsed -cups-pdf; do
    assert_cmd_success "%packages exclusion: ${pkg#-}" \
        grep -qxF -- "$pkg" "$PACKAGES_FILE"
done
assert_not_grep 'avahi package is excluded' "$KS_FILE" \
    "retained avahi main package is not falsely documented as excluded"
assert_not_grep 'Library-only presence is intentional' "$KS_FILE" \
    "service-bearing avahi is not mislabeled library-only"
assert_grep_fixed 'systemd-backed D-Bus activation alias' "$KS_FILE" \
    "avahi mask rationale covers its packaged D-Bus activation route"
assert_grep_fixed 'service/socket activation masked' "$KS_FILE" \
    "avahi compose log describes the exact retained/masked state"
assert_grep_fixed 'samba-common: installed packaging companion; no daemon executable' \
    "$KS_FILE" "samba-common compose log does not inherit Avahi's mask claim"

# --- Service masks in KS source ---------------------------------------------
for unit in avahi-daemon.service avahi-daemon.socket wsdd.service wsdd2.service \
            cups.path cups.service cups.socket cups-browsed.service; do
    assert_grep_fixed "systemctl mask $unit" "$KS_FILE" "mask: $unit"
done

# --- noid-lan-allow escape-hatch --------------------------------------------
assert_grep_fixed 'block-lan-out' "$TMPDIR/noid-lan-allow"
assert_grep_fixed 'firewall-cmd --permanent' "$TMPDIR/noid-lan-allow"
assert_grep_fixed 'noid-snap-pre' "$TMPDIR/noid-lan-allow"

# --- per-IP exception API -------------------------------
# Per-IP exception API + temp-timer + revert + list — drop-in replacement
# for prior global-only on/off CLI. Legacy on/off paths preserved for
# back-compat.
assert_grep_fixed 'sudo noid-lan-allow --add <IP> --direction outbound [--temp MIN]' \
    "$TMPDIR/noid-lan-allow" "explicit outbound per-IP API"
assert_grep_fixed 'sudo noid-lan-allow --add <IP> --direction inbound --protocol tcp|udp --ports PORT|START-END [--temp MIN]' \
    "$TMPDIR/noid-lan-allow" "port-scoped inbound per-IP API"
assert_grep_fixed 'sudo noid-lan-allow --add <IP> --direction both --protocol tcp|udp --ports PORT|START-END [--temp MIN]' \
    "$TMPDIR/noid-lan-allow" "port-scoped bidirectional per-IP API"
assert_grep_fixed '--temp'       "$TMPDIR/noid-lan-allow" "bounded temporary grant argument"
assert_grep_fixed '--revert'     "$TMPDIR/noid-lan-allow" "--revert <IP> arg"
assert_grep_fixed '--list'       "$TMPDIR/noid-lan-allow" "--list arg"
assert_grep_fixed 'ACCEPT_PRIORITY="-100"' "$TMPDIR/noid-lan-allow" "priority='-100' rich-rule"
assert_grep_fixed 'add_ip_exception'      "$TMPDIR/noid-lan-allow" "per-IP add helper"
assert_grep_fixed 'revert_ip_exception'   "$TMPDIR/noid-lan-allow" "per-IP revert helper"
assert_grep_fixed 'add_temp_ip_exception' "$TMPDIR/noid-lan-allow" "per-IP temp helper"
assert_not_grep 'systemd-run --on-active=' "$TMPDIR/noid-lan-allow" \
    "temporary grants never depend on a reboot-volatile transient timer"
assert_grep_fixed 'CREATED_EPOCH=' "$TMPDIR/noid-lan-allow" \
    "temporary grants persist an absolute creation time"
assert_grep_fixed 'EXPIRES_EPOCH=' "$TMPDIR/noid-lan-allow" \
    "temporary grants persist an absolute deadline"
assert_grep_fixed 'CREATED_BOOTTIME=' "$TMPDIR/noid-lan-allow" \
    "same-boot expiry also uses a monotonic source"
assert_grep_fixed 'Any wall-clock rollback before creation is unsafe' \
    "$TMPDIR/noid-lan-allow" "clock rollback revokes instead of extending access"
assert_grep_fixed 'missing or invalid' "$TMPDIR/noid-lan-allow" \
    "missing/invalid exception metadata is revoked"
assert_grep_fixed 'flock --exclusive 8' "$TMPDIR/noid-lan-allow" \
    "add/revert/reconcile transitions share one lock"
assert_grep_fixed 'exec 8<>"$LAN_EXCEPTION_LOCK"' "$TMPDIR/noid-lan-allow" \
    "locking never truncates an existing transaction object"
assert_grep_fixed "LAN_EXCEPTION_LOCK=\"\${NOID_LAN_EXCEPTION_LOCK:-/run/noid-privacy/lan-exceptions.lock}\"" \
    "$TMPDIR/noid-lan-allow" \
    "exception lock stays inside the shared root runtime boundary"
assert_grep_fixed "LAN_STATE_GID=\"\${NOID_LAN_STATE_GID:-0}\"" \
    "$TMPDIR/noid-lan-allow" \
    "closed LAN state metadata validates both UID and GID"
assert_grep_fixed 'Before=NetworkManager.service network-pre.target' \
    "$TMPDIR/lan-expiry.service" "boot expiry reconciliation precedes networking"
assert_grep_fixed 'ExecStart=/usr/local/bin/noid-lan-allow --reconcile-expired' \
    "$TMPDIR/lan-expiry.service" "installed service runs the closed reconciler"
assert_grep_fixed 'Documentation=file:///usr/share/doc/noid-privacy/05-lan-isolation.md' \
    "$TMPDIR/lan-expiry.service" "expiry service uses one canonical file URI"
assert_grep_fixed 'UMask=0077' "$TMPDIR/lan-expiry.service" \
    "expiry service keeps root-private creation defaults"
assert_grep_fixed \
    'ReadWritePaths=/var/lib/noid-privacy /run/noid-privacy -/sys/fs/bpf' \
    "$TMPDIR/lan-expiry.service" \
    "expiry service cannot write unrelated runtime state"
assert_grep_fixed 'OnUnitInactiveSec=5s' "$TMPDIR/lan-expiry.timer" \
    "installed timer retains a closed fallback deadline"
assert_grep_fixed 'AccuracySec=1us' "$TMPDIR/lan-expiry.timer" \
    "deadline timer does not add a scheduling window"
assert_cmd_success "deadline generator parses" bash -n "$TMPDIR/lan-expiry-generator"
assert_grep_fixed "'OnActiveSec='" "$TMPDIR/lan-expiry-generator" \
    "generated schedule resets the fallback poll expression"
assert_grep_fixed '"OnActiveSec=${delay}s"' "$TMPDIR/lan-expiry-generator" \
    "generated schedule carries a monotonic deadline"
assert_grep_fixed '"OnCalendar=@${epoch}"' "$TMPDIR/lan-expiry-generator" \
    "generated schedule carries an absolute realtime deadline"
assert_grep_fixed 'chmod 0644 "$dropin"' "$TMPDIR/lan-expiry-generator" \
    "generated systemd configuration is warning-free public unit metadata"
assert_grep_fixed 'unsafe or malformed schedule; reconciling immediately' \
    "$TMPDIR/lan-expiry-generator" \
    "invalid generated deadline state fails closed immediately"
assert_grep_fixed 'OnFailure=noid-lan-expiry-failure.service' \
    "$TMPDIR/lan-expiry.service" "pre-exec/service failures trigger fail-closed handling"
assert_not_grep 'RefuseManualStop=yes' "$TMPDIR/lan-expiry.timer" \
    "the helper can stop the timer after the final temporary exception"
assert_not_grep 'OnBootSec=' "$TMPDIR/lan-expiry.timer" \
    "boot does not start unconditional five-second polling"
assert_grep_fixed 'next_temporary_schedule()' "$TMPDIR/noid-lan-allow" \
    "timer activation is derived from both durable deadline clocks"
assert_grep_fixed 'publish_expiry_schedule()' "$TMPDIR/noid-lan-allow" \
    "deadline publication is a closed root-owned transaction"
assert_grep_fixed 'sync_expiry_timer()' "$TMPDIR/noid-lan-allow" \
    "every mutation can reconcile timer lifecycle"
assert_grep_fixed 'ExecStart=/usr/bin/systemctl --no-block stop NetworkManager.service' \
    "$TMPDIR/lan-expiry-failure.service" \
    "systemd-level expiry failure stops networking"
# A guard that stays failed must not let its dependents republish the failure
# without bound. Each re-queue reprints the guard's [FAILED] plus this unit's
# [DEPEND] and re-triggers OnFailure=, which floods console, journal and audit
# backlog while nothing is actually retried.
assert_grep_fixed 'StartLimitIntervalSec=60s' "$TMPDIR/lan-expiry.service" \
    "expiry reconciliation shares the topology guard's start-rate window"
assert_grep_fixed 'StartLimitBurst=3' "$TMPDIR/lan-expiry.service" \
    "expiry reconciliation stops re-queueing after the third attempt"
assert_grep_fixed 'StartLimitIntervalSec=60s' "$TMPDIR/lan-expiry-failure.service" \
    "the fail-closed notifier cannot outrun its own trigger"
assert_grep_fixed 'StartLimitBurst=3' "$TMPDIR/lan-expiry-failure.service" \
    "the fail-closed notifier is bounded per window"
# Stopping an already-inactive NetworkManager changes nothing about the posture
# but still enqueues a job against a unit that hard-requires the failed guard.
assert_grep_fixed \
    'ExecCondition=/usr/bin/systemctl is-active --quiet NetworkManager.service' \
    "$TMPDIR/lan-expiry-failure.service" \
    "the fail-closed stop is skipped when networking is already down"
assert_grep_fixed 'NoNewPrivileges=yes' "$TMPDIR/lan-expiry-failure.service" \
    "failure path cannot gain privileges"
assert_grep_fixed 'CapabilityBoundingSet=' "$TMPDIR/lan-expiry-failure.service" \
    "failure path retains no ambient capability surface"
assert_grep_fixed 'ProtectSystem=strict' "$TMPDIR/lan-expiry-failure.service" \
    "failure path has a read-only system view"
assert_grep_fixed 'Requires=noid-lan-expiry-reconcile.service' \
    "$TMPDIR/lan-expiry-nm.conf" "NetworkManager requires a successful boot reconciliation"
assert_grep_fixed \
    'Requires=firewalld.service noid-lan-topology-guard.service noid-arp-state-guard.service' \
    "$TMPDIR/lan-expiry.service" \
    "expiry reconciliation requires every authoritative pre-network boundary"
assert_grep_fixed 'systemctl enable noid-lan-expiry-reconcile.service' \
    "$KS_FILE" "expiry boot gate is enabled"
assert_not_grep 'systemctl enable .*noid-lan-expiry-reconcile.timer' \
    "$KS_FILE" "expiry timer is not globally enabled"
assert_grep_fixed 'validate_ip_family'    "$TMPDIR/noid-lan-allow" "Python ipaddress validation"
assert_grep_fixed 'peer in ipaddress.ip_interface(x).network' "$TMPDIR/noid-lan-allow" \
    "IPv4 exception is restricted to a directly attached prefix"
assert_grep_fixed \
    '# shellcheck disable=SC2086 # one reviewed argv per whitespace-free CIDR.' \
    "$TMPDIR/noid-lan-allow" \
    "intentional CIDR argv splitting is locally documented"
assert_grep_fixed 'IPv6 per-IP LAN exceptions are unsupported' \
    "$TMPDIR/noid-lan-allow" \
    "IPv6 is rejected until XDP/NDP peer return-flow support exists"
assert_not_grep 'validate_ipv6_peer' "$TMPDIR/noid-lan-allow" \
    "no dead IP-only IPv6 allow path remains"
assert_grep_fixed 'arping -c 3 -w 5 -I "$iface" "$ip"' "$TMPDIR/noid-lan-allow" \
    "IPv4 peer MAC uses bounded explicit TOFU learning"
assert_grep_fixed 'nud permanent' "$TMPDIR/noid-lan-allow" \
    "learned IPv4 peer is pinned as a permanent neighbour"
assert_grep_fixed 'raw ARP and kernel neighbour identity disagree' \
    "$TMPDIR/noid-lan-allow" \
    "raw peer learning must agree with the device-scoped kernel cache"
assert_grep_fixed '[ "$neighbor_count" -le 1 ]' "$TMPDIR/noid-lan-allow" \
    "peer learning rejects ambiguous kernel-neighbour state"
assert_grep_fixed 'time-separated raw ARP observations disagree' \
    "$TMPDIR/noid-lan-allow" \
    "empty neighbour cache requires two matching bounded observations"
assert_grep_fixed 'sleep 1' "$TMPDIR/noid-lan-allow" \
    "empty-cache peer observations are time-separated"
assert_grep_fixed 'observed=$(exact_permanent_neighbour_mac "$ip" "$iface"' \
    "$TMPDIR/noid-lan-allow" \
    "peer learning proves one exact permanent postcondition"
assert_grep_fixed '^[a-zA-Z0-9_.-]{1,15}$' "$TMPDIR/noid-lan-allow" \
    "durable interface identities respect Linux IFNAMSIZ"
assert_grep_fixed 'LAN_PEER_STATE_DIR="${NOID_LAN_PEER_STATE_DIR:-/var/lib/noid-privacy/lan-peer-bindings}"' "$TMPDIR/noid-lan-allow" \
    "IPv4 IP/MAC/interface binding has persistent root-owned state"
assert_grep_fixed 'ARP_HARDENING_STATE="${NOID_ARP_HARDENING_STATE:-/var/lib/noid-privacy/arp-hardening.state}"' \
    "$TMPDIR/noid-lan-allow" \
    "peer cleanup reads the independent protected-gateway state"
assert_grep_fixed '[ -x "$ARP_STATE_GUARD" ] && "$ARP_STATE_GUARD" || return 1' \
    "$TMPDIR/noid-lan-allow" \
    "production gateway-pin decisions require M04's complete state guard"
assert_grep_fixed 'ip neigh replace "$ip" lladdr "$PROTECTED_GATEWAY_MAC"' \
    "$TMPDIR/noid-lan-allow" \
    "revoking a gateway peer restores the independent permanent gateway pin"
assert_grep_fixed '[ "$PROTECTED_GATEWAY_ENABLED" = 1 ]' \
    "$TMPDIR/noid-lan-allow" \
    "gateway pin is restored only when M04's kernel-pin state is enabled"
assert_grep_fixed '[[ "$PROTECTED_GATEWAY_ENABLED" =~ ^[01]$ ]]' \
    "$TMPDIR/noid-lan-allow" \
    "M05 accepts M04's retained disabled identity without treating it as corrupt"
assert_grep_fixed '[ "$observed" = "$PROTECTED_GATEWAY_MAC" ] || return 1' \
    "$TMPDIR/noid-lan-allow" \
    "gateway-pin restoration has an exact postcondition"
assert_grep_fixed '[ "$observed" = "$mac" ]' \
    "$TMPDIR/noid-lan-allow" \
    "non-gateway cleanup deletes only its exact managed permanent neighbour"
assert_grep_fixed 'ip neigh del "$ip" dev "$iface" || return 1' \
    "$TMPDIR/noid-lan-allow" \
    "managed-neighbour deletion failures are never reported as cleanup success"
assert_grep_fixed '[ "$observed" != "$mac" ] || return 1' \
    "$TMPDIR/noid-lan-allow" \
    "managed-neighbour deletion has an exact absence postcondition"
assert_not_grep 'learn-open\|learn-close\|lan_learning_v4' "$TMPDIR/noid-lan-allow" \
    "explicit peer learning uses standard ARP without dynamic admission state"
assert_not_grep 'arp_hardening\|lan_peer_bindings\|lan_peer_ips' \
    "$TMPDIR/noid-lan-allow" \
    "LAN peer verification has no hookless M04 shadow-table dependency"

# Exercise the production IPv4 trust-establishment function with a real-shape
# directly attached route. This catches state/neighbor/nft transaction bugs
# that string assertions cannot.
awk '/^# === ACTION DISPATCH ===/ {exit} {print}' \
    "$TMPDIR/noid-lan-allow" > "$TMPDIR/noid-lan-functions.sh"
mkdir -p "$TMPDIR/mock-sys/test0/device" "$TMPDIR/peer-state"
chmod 0700 "$TMPDIR/peer-state"
MOCK_IP_LOG="$TMPDIR/peer-ip.log"
MOCK_ARPING_COUNT="$TMPDIR/peer-arping.count"
MOCK_ARPING_LOG="$TMPDIR/peer-arping.log"
: > "$MOCK_IP_LOG"
: > "$MOCK_ARPING_COUNT"
: > "$MOCK_ARPING_LOG"
# These command doubles are exported and invoked indirectly by the extracted
# production helper sourced in the subshell below.
# shellcheck disable=SC2317,SC2329
ip() {
    printf '%s\n' "$*" >> "$MOCK_IP_LOG"
    case "$*" in
        '-4 route get 198.19.7.20')
            printf '%s\n' '198.19.7.20 dev test0 src 198.19.7.10'
            ;;
        '-o -4 addr show dev test0 scope global')
            printf '%s\n' '2: test0 inet 198.19.7.10/24 scope global test0'
            ;;
        '-4 neigh show to 198.19.7.20 dev test0')
            if [ "${MOCK_NEIGH_MODE:-present}" = empty ] \
                    && ! grep -q '^neigh replace 198.19.7.20 ' \
                        "$MOCK_IP_LOG"; then
                return 0
            fi
            printf '%s\n' \
                "198.19.7.20 lladdr ${MOCK_NEIGH_MAC:-52:54:00:aa:bb:cc} PERMANENT"
            ;;
        'neigh replace 198.19.7.20 lladdr 52:54:00:aa:bb:cc dev test0 nud permanent')
            ;;
        *) return 1 ;;
    esac
}
# shellcheck disable=SC2317,SC2329
arping() {
    local count=0 mac=52:54:00:aa:bb:cc
    [ ! -s "$MOCK_ARPING_COUNT" ] || read -r count < "$MOCK_ARPING_COUNT"
    count=$((count + 1))
    printf '%s\n' "$count" > "$MOCK_ARPING_COUNT"
    if [ "${MOCK_ARPING_MODE:-stable}" = alternate ] \
            && [ $((count % 2)) -eq 0 ]; then
        mac=02:00:00:00:00:33
    fi
    printf 'call=%s mac=%s\n' "$count" "$mac" >> "$MOCK_ARPING_LOG"
    printf 'Unicast reply from 198.19.7.20 [%s] 0.500ms\n' "$mac"
}
# shellcheck disable=SC2317,SC2329
sleep() {
    printf 'sleep %s\n' "$*" >> "$MOCK_ARPING_LOG"
}
# shellcheck disable=SC2317,SC2329
chown() { return 0; }
# shellcheck disable=SC2317,SC2329
function firewall-cmd() { return 0; }
export MOCK_IP_LOG MOCK_ARPING_COUNT MOCK_ARPING_LOG
export -f ip arping sleep chown
export -f -- firewall-cmd
set +e
(
    # Each assignment intentionally belongs only to this isolated production
    # helper invocation; the following fixture supplies a different identity.
    # shellcheck disable=SC2030
    export NOID_SYS_CLASS_NET="$TMPDIR/mock-sys"
    # shellcheck disable=SC2030
    export NOID_LAN_PEER_STATE_DIR="$TMPDIR/peer-state"
    # shellcheck disable=SC2030
    export NOID_LAN_STATE_UID NOID_LAN_STATE_GID
    # shellcheck disable=SC2030
    NOID_LAN_STATE_UID=$FIXTURE_UID
    # shellcheck disable=SC2030
    NOID_LAN_STATE_GID=$FIXTURE_GID
    # shellcheck disable=SC2030
    export NOID_LAN_XDP_CONTROLLER=/bin/true
    # shellcheck disable=SC1090
    . "$TMPDIR/noid-lan-functions.sh"
    learn_ipv4_peer 198.19.7.20 outbound none 0 0
)
peer_rc=$?
set -e
assert_eq "0" "$peer_rc" "directly attached IPv4 peer learning succeeds"
assert_grep_fixed 'neigh replace 198.19.7.20 lladdr 52:54:00:aa:bb:cc dev test0 nud permanent' \
    "$MOCK_IP_LOG" "learned peer becomes a permanent neighbor"
assert_grep_fixed 'IP=198.19.7.20' "$TMPDIR/peer-state/198_19_7_20.state" \
    "peer state records canonical IPv4"
assert_grep_fixed 'VERSION=2' "$TMPDIR/peer-state/198_19_7_20.state" \
    "peer state uses the closed direction-aware schema"
assert_grep_fixed 'DIRECTION=outbound' "$TMPDIR/peer-state/198_19_7_20.state" \
    "peer state records outbound-only direction"
assert_grep_fixed 'PROTOCOL=none' "$TMPDIR/peer-state/198_19_7_20.state" \
    "outbound peer state has no unsolicited-ingress protocol"
assert_grep_fixed 'PORT_START=0' "$TMPDIR/peer-state/198_19_7_20.state" \
    "outbound peer state has no unsolicited-ingress port"
assert_grep_fixed 'PORT_END=0' "$TMPDIR/peer-state/198_19_7_20.state" \
    "outbound peer state has no unsolicited-ingress range"
assert_grep_fixed 'MAC=52:54:00:aa:bb:cc' "$TMPDIR/peer-state/198_19_7_20.state" \
    "peer state records learned MAC"
assert_eq "600" "$(stat -c '%a' "$TMPDIR/peer-state/198_19_7_20.state")" \
    "peer binding state is root-private"
assert_eq "$FIXTURE_UID:$FIXTURE_GID" \
    "$(stat -c '%u:%g' "$TMPDIR/peer-state/198_19_7_20.state")" \
    "fixture peer state preserves the production UID/GID contract"

rm -f "$TMPDIR/peer-state/198_19_7_20.state"
: > "$MOCK_IP_LOG"
: > "$MOCK_ARPING_COUNT"
: > "$MOCK_ARPING_LOG"
set +e
# Each fixture case deliberately owns an isolated environment.
# shellcheck disable=SC2030,SC2031
(
    export NOID_SYS_CLASS_NET="$TMPDIR/mock-sys"
    export NOID_LAN_PEER_STATE_DIR="$TMPDIR/peer-state"
    export NOID_LAN_STATE_UID="$FIXTURE_UID"
    export NOID_LAN_STATE_GID="$FIXTURE_GID"
    export NOID_LAN_XDP_CONTROLLER=/bin/true
    export MOCK_NEIGH_MODE=empty
    # shellcheck disable=SC1090
    . "$TMPDIR/noid-lan-functions.sh"
    learn_ipv4_peer 198.19.7.20 outbound none 0 0
)
peer_empty_rc=$?
set -e
assert_eq 0 "$peer_empty_rc" \
    "empty-cache IPv4 peer learning succeeds with two raw observations"
assert_eq 2 "$(cat "$MOCK_ARPING_COUNT")" \
    "empty-cache peer learning performs exactly two bounded observations"
assert_grep_fixed 'sleep 1' "$MOCK_ARPING_LOG" \
    "empty-cache peer observations are time-separated"

rm -f "$TMPDIR/peer-state/198_19_7_20.state"
: > "$MOCK_IP_LOG"
: > "$MOCK_ARPING_COUNT"
: > "$MOCK_ARPING_LOG"
peer_alternate_rc=0
# Each fixture case deliberately owns an isolated environment.
# shellcheck disable=SC2030,SC2031
(
    export NOID_SYS_CLASS_NET="$TMPDIR/mock-sys"
    export NOID_LAN_PEER_STATE_DIR="$TMPDIR/peer-state"
    export NOID_LAN_STATE_UID="$FIXTURE_UID"
    export NOID_LAN_STATE_GID="$FIXTURE_GID"
    export NOID_LAN_XDP_CONTROLLER=/bin/true
    export MOCK_NEIGH_MODE=empty
    export MOCK_ARPING_MODE=alternate
    # shellcheck disable=SC1090
    . "$TMPDIR/noid-lan-functions.sh"
    learn_ipv4_peer 198.19.7.20 outbound none 0 0
) >"$TMPDIR/peer-alternate.out" 2>&1 || peer_alternate_rc=$?
assert_eq 1 "$peer_alternate_rc" \
    "different empty-cache raw observations fail closed"
assert_cmd_success "raw disagreement publishes no peer state" \
    test ! -e "$TMPDIR/peer-state/198_19_7_20.state"
assert_not_grep 'neigh replace 198.19.7.20' "$MOCK_IP_LOG" \
    "raw disagreement fails before permanent-neighbour mutation"

rm -f "$TMPDIR/peer-state/198_19_7_20.state"
: > "$MOCK_IP_LOG"
: > "$MOCK_ARPING_COUNT"
peer_mismatch_rc=0
(
    # These overrides deliberately replace the prior subshell's isolated
    # values for the disagreement fixture.
    # shellcheck disable=SC2031
    export NOID_SYS_CLASS_NET="$TMPDIR/mock-sys"
    # shellcheck disable=SC2031
    export NOID_LAN_PEER_STATE_DIR="$TMPDIR/peer-state"
    # shellcheck disable=SC2030,SC2031
    export NOID_LAN_STATE_UID="$FIXTURE_UID"
    # shellcheck disable=SC2030,SC2031
    export NOID_LAN_STATE_GID="$FIXTURE_GID"
    # shellcheck disable=SC2031
    export NOID_LAN_XDP_CONTROLLER=/bin/true
    export MOCK_NEIGH_MAC=02:00:00:00:00:22
    # shellcheck disable=SC1090
    . "$TMPDIR/noid-lan-functions.sh"
    learn_ipv4_peer 198.19.7.20 outbound none 0 0
) >"$TMPDIR/peer-mismatch.out" 2>&1 || peer_mismatch_rc=$?
assert_eq 1 "$peer_mismatch_rc" \
    "raw/kernel peer identity disagreement fails closed"
assert_not_grep 'neigh replace 198.19.7.20' "$MOCK_IP_LOG" \
    "identity disagreement fails before permanent-neighbour mutation"
assert_cmd_success "identity disagreement publishes no peer state" \
    test ! -e "$TMPDIR/peer-state/198_19_7_20.state"
unset -f ip arping sleep chown firewall-cmd

# The production lock must preserve existing bytes and reject alternate
# path identities before opening them read/write.
mkdir -p "$TMPDIR/lock-contract"
chmod 0755 "$TMPDIR/lock-contract"
printf '%s\n' sentinel > "$TMPDIR/lock-contract/regular.lock"
chmod 0600 "$TMPDIR/lock-contract/regular.lock"
assert_cmd_success "regular lock is acquired without truncation" \
    bash -c '
        firewall-cmd() { return 0; }
        export -f -- firewall-cmd
        export NOID_LAN_EXCEPTION_LOCK=$1
        export NOID_LAN_STATE_UID=$2 NOID_LAN_STATE_GID=$3
        . "$4"
        acquire_exception_lock
    ' _ "$TMPDIR/lock-contract/regular.lock" "$FIXTURE_UID" "$FIXTURE_GID" \
        "$TMPDIR/noid-lan-functions.sh"
assert_eq sentinel "$(cat "$TMPDIR/lock-contract/regular.lock")" \
    "lock acquisition preserves pre-existing bytes"

printf '%s\n' protected > "$TMPDIR/lock-contract/symlink-target"
chmod 0600 "$TMPDIR/lock-contract/symlink-target"
ln -s symlink-target "$TMPDIR/lock-contract/symlink.lock"
assert_cmd_failure "symlink lock is rejected before it can be followed" \
    bash -c '
        firewall-cmd() { return 0; }
        export -f -- firewall-cmd
        export NOID_LAN_EXCEPTION_LOCK=$1
        export NOID_LAN_STATE_UID=$2 NOID_LAN_STATE_GID=$3
        . "$4"
        acquire_exception_lock
    ' _ "$TMPDIR/lock-contract/symlink.lock" "$FIXTURE_UID" "$FIXTURE_GID" \
        "$TMPDIR/noid-lan-functions.sh"
assert_eq protected "$(cat "$TMPDIR/lock-contract/symlink-target")" \
    "rejected symlink lock never truncates its target"

: > "$TMPDIR/lock-contract/hardlink-target"
chmod 0600 "$TMPDIR/lock-contract/hardlink-target"
ln "$TMPDIR/lock-contract/hardlink-target" \
    "$TMPDIR/lock-contract/hardlink.lock"
assert_cmd_failure "multiply linked lock identity is rejected" \
    bash -c '
        firewall-cmd() { return 0; }
        export -f -- firewall-cmd
        export NOID_LAN_EXCEPTION_LOCK=$1
        export NOID_LAN_STATE_UID=$2 NOID_LAN_STATE_GID=$3
        . "$4"
        acquire_exception_lock
    ' _ "$TMPDIR/lock-contract/hardlink.lock" "$FIXTURE_UID" "$FIXTURE_GID" \
        "$TMPDIR/noid-lan-functions.sh"

assert_grep_fixed 'canonicalize_ip' "$TMPDIR/noid-lan-allow" \
    "managed and legacy-revoke IP input is canonicalized"
assert_grep_fixed '--revert requires exactly one <IP> argument' \
    "$TMPDIR/noid-lan-allow" \
    "revert rejects ignored trailing arguments"
assert_grep_fixed '--reconcile-expired takes no arguments' \
    "$TMPDIR/noid-lan-allow" \
    "reconciliation rejects ignored trailing arguments"
assert_grep_fixed '--global-state takes no arguments' \
    "$TMPDIR/noid-lan-allow" \
    "machine-state reads reject ignored trailing arguments"
assert_grep_fixed 'rollback_ip_exception_fail_closed' "$TMPDIR/noid-lan-allow" \
    "every partial per-IP add has one verified fail-closed rollback"
assert_grep_fixed 'LAN exception rolled back because its durable state could not be reloaded' \
    "$TMPDIR/noid-lan-allow" \
    "post-topology state reload failure enters the same fail-closed rollback"
assert_grep_fixed 'Machine state: BLOCKED/ALLOWED/INCONSISTENT' \
    "$TMPDIR/noid-lan-allow" "help documents every machine-state verdict"
assert_grep_fixed 'Show all active per-IP exceptions (no root required)' \
    "$TMPDIR/noid-lan-allow" "help accurately marks read-only listing unprivileged"
assert_grep_fixed 'verify_ip_exception_absent "$ip" "$family" || rollback_failed=1' \
    "$TMPDIR/noid-lan-allow" "rollback proves every exception layer absent"
assert_grep_fixed 'refresh_topology_guard --invalidate-peer-flows "$ip" --require-xdp' \
    "$TMPDIR/noid-lan-allow" \
    "new peer publication selects a fresh correlation generation before widening"
assert_eq 5 \
    "$(grep -Fc -- '--invalidate-peer-flows "$ip" --require-xdp' \
        "$TMPDIR/noid-lan-allow")" \
    "every peer add, edit, revoke and rollback invalidates reusable tuples"
assert_cmd_success "every XDP-first peer exclusion also invalidates old tuples" \
    awk '
        /--exclude-peer "\$ip"/ {
            if ($0 ~ /--invalidate-peer-flows "\$ip"/) {
                covered++
            } else {
                getline
                if ($0 ~ /--invalidate-peer-flows "\$ip"/) covered++
            }
            exclusions++
        }
        END { exit !(exclusions == 4 && covered == exclusions) }
    ' "$TMPDIR/noid-lan-allow"
assert_grep_fixed 'rules=$(firewall-cmd "${args[@]}" --policy="$POLICY"' \
    "$TMPDIR/noid-lan-allow" \
    "firewalld policy queries preserve query-error status"
assert_grep_fixed 'outbound_rule_absent "$ip" permanent || return 1' \
    "$TMPDIR/noid-lan-allow" \
    "absence postconditions distinguish missing rules from query failure"
assert_grep_fixed 'any_inbound_rule_for_ip_absent "$ip" runtime || return 1' \
    "$TMPDIR/noid-lan-allow" \
    "inbound absence postconditions distinguish missing rules from query failure"
assert_grep_fixed 'firewall_contract_exists "$ip" runtime || return 1' \
    "$TMPDIR/noid-lan-allow" \
    "runtime postcondition checks the exact direction-aware firewalld contract"
assert_grep_fixed 'ip=$(canonicalize_ip "$ip" || true)' "$TMPDIR/noid-lan-allow" \
    "temporary timer identity is derived from canonical IP input"
unguarded_reload_count=$(awk '
    /firewall-cmd --reload/ && $0 !~ /if !/ && $0 !~ /\|\|/ {count++}
    END {print count+0}
' "$TMPDIR/noid-lan-allow")
assert_eq "0" "$unguarded_reload_count" \
    "per-IP firewalld reloads are never unguarded under errexit"
assert_grep_fixed 'LAN exception rolled back because topology sync failed' \
    "$TMPDIR/noid-lan-allow" "failed two-layer add is rolled back"
assert_grep_fixed 'LAN topology guard helper is missing' "$TMPDIR/noid-lan-allow" \
    "missing dynamic guard is a failure, not an empty success"
assert_grep_fixed 'topology preflight failed; refusing global LAN allow' \
    "$TMPDIR/noid-lan-allow" "global weakening requires a valid protected pre-state"
assert_grep_fixed 'global LAN allow rolled back because topology sync failed' \
    "$TMPDIR/noid-lan-allow" "failed global detach is rolled back"
assert_grep_fixed 'GLOBAL_ALLOW_MARKER="${NOID_LAN_GLOBAL_ALLOW_MARKER:-/var/lib/noid-privacy/lan-global-allow.enabled}"' \
    "$TMPDIR/noid-lan-allow" "global opt-in has a durable explicit source of truth"
assert_grep_fixed 'GLOBAL_RUNTIME_STATE="${NOID_LAN_GLOBAL_RUNTIME_STATE:-/run/noid-privacy/lan-global-state}"' \
    "$TMPDIR/noid-lan-allow" "global status uses a root-published runtime contract"
assert_grep_fixed 'state=$(read_global_runtime_state)' "$TMPDIR/noid-lan-allow" \
    "unprivileged global-state validates the root-published contract without Polkit"
assert_grep_fixed 'valid_global_allow_marker()' "$TMPDIR/noid-lan-allow" \
    "global allow cannot be authorized by a mere pathname"
assert_grep_fixed 'firewalld, durable marker and runtime topology/WAN-strict state disagree' \
    "$TMPDIR/noid-lan-allow" "split enforcement state is reported as inconsistent"
assert_grep_fixed 'global_state' "$TMPDIR/noid-lan-allow" \
    "global on/off verifies its complete cross-layer postcondition"
assert_grep_fixed 'restore_global_block_state' "$TMPDIR/noid-lan-allow" \
    "failed global activation restores the complete default state"
assert_grep_fixed 'stopping NetworkManager fail-closed' "$TMPDIR/noid-lan-allow" \
    "failed protection restore cannot leave a public-prefix LAN gap"
assert_not_grep 'noid-snap-pre.*LAN egress allow.*[|][|][[:space:]]*true' \
    "$TMPDIR/noid-lan-allow" "snapshot failure cannot precede a weakening action"
assert_grep_fixed 'LAN exception revoked because the expiry-timer postcondition failed' \
    "$TMPDIR/noid-lan-allow" \
    "failed timer postcondition revokes the newly published exception"
assert_grep_fixed 'Duration must be 1..1440 minutes' "$TMPDIR/noid-lan-allow" \
    "temporary LAN exposure is bounded to 24 hours"
assert_grep_fixed 'durable exception was revoked, but final topology refresh failed' \
    "$TMPDIR/noid-lan-allow" "revoke reports partial runtime failure honestly"

# Full global on/off transaction with deterministic firewalld + topology state.
# This proves the CLI reports ALLOWED only after both durable sources and the
# root-published runtime contract agree, then restores all three on `off`.
printf '%s\n' HOST > "$TMPDIR/global-firewalld.state"
GLOBAL_FW_STATE="$TMPDIR/global-firewalld.state"
mkdir -p "$TMPDIR/global-state-root" "$TMPDIR/runtime-state-root" \
    "$TMPDIR/lock-root"
chmod 0755 "$TMPDIR/global-state-root" "$TMPDIR/runtime-state-root" \
    "$TMPDIR/lock-root"
GLOBAL_MARKER="$TMPDIR/global-state-root/global-allow.marker"
GLOBAL_RUNTIME="$TMPDIR/runtime-state-root/global-runtime.state"
GLOBAL_LOCK="$TMPDIR/lock-root/global.lock"
XDP_HEALTH="$TMPDIR/xdp-health.state"
MOCK_SYSTEMCTL_LOG="$TMPDIR/mock-systemctl.calls"
printf '%s\n' 'STATE=ACTIVE' > "$XDP_HEALTH"
export GLOBAL_FW_STATE GLOBAL_MARKER GLOBAL_RUNTIME XDP_HEALTH MOCK_SYSTEMCTL_LOG
# The production-helper subshells above intentionally used fixture-local
# copies; this export establishes the independent full-CLI fixture contract.
# shellcheck disable=SC2031
export NOID_LAN_STATE_UID NOID_LAN_STATE_GID
NOID_LAN_STATE_UID=$FIXTURE_UID
NOID_LAN_STATE_GID=$FIXTURE_GID
# shellcheck disable=SC2317,SC2329 # exported; invoked by the extracted production CLI.
function firewall-cmd() {
    case "$*" in
        '--info-policy=block-lan-out') return 0 ;;
        '--permanent --policy=block-lan-out --list-ingress-zones')
            [ "$(cat "$GLOBAL_FW_STATE")" != HOST ] || printf '%s\n' HOST
            ;;
        '--permanent --policy=block-lan-out --remove-ingress-zone=HOST')
            printf '%s\n' NONE > "$GLOBAL_FW_STATE" ;;
        '--permanent --policy=block-lan-out --add-ingress-zone=HOST')
            printf '%s\n' HOST > "$GLOBAL_FW_STATE" ;;
        '--reload') ;;
        *) return 1 ;;
    esac
}
# shellcheck disable=SC2317,SC2329 # exported; invoked by the extracted production CLI.
id() {
    [ "${1:-}" != -u ] || { printf '%s\n' 0; return 0; }
    command id "$@"
}
# shellcheck disable=SC2317,SC2329 # exported; invoked by the extracted production CLI.
systemctl() {
    printf '%s\n' "$*" >> "$MOCK_SYSTEMCTL_LOG"
    return 0
}
export -f -- firewall-cmd
export -f id systemctl
TOPOLOGY_FIXTURE=$(mktemp "$PROJECT_ROOT/.test-topology-refresh.XXXXXX")
cat > "$TOPOLOGY_FIXTURE" <<'MOCK_TOPOLOGY_EOF'
#!/bin/bash
set -eu
host=0
[ "$(cat "$GLOBAL_FW_STATE")" != HOST ] || host=1
marker=0
[ ! -e "$GLOBAL_MARKER" ] || marker=1
if [ "$host:$marker" = 1:0 ]; then
    printf '%s\n' BLOCKED > "$GLOBAL_RUNTIME"
elif [ "$host:$marker" = 0:1 ]; then
    printf '%s\n' ALLOWED > "$GLOBAL_RUNTIME"
else
    printf '%s\n' INCONSISTENT > "$GLOBAL_RUNTIME"
    chmod 0644 "$GLOBAL_RUNTIME"
    exit 1
fi
chmod 0644 "$GLOBAL_RUNTIME"
MOCK_TOPOLOGY_EOF
chmod 0755 "$TOPOLOGY_FIXTURE"
global_on_rc=0
printf '%s\n' y | env PATH=/usr/bin:/bin \
    NOID_LAN_EXCEPTION_LOCK="$GLOBAL_LOCK" \
    NOID_LAN_GLOBAL_ALLOW_MARKER="$GLOBAL_MARKER" \
    NOID_LAN_GLOBAL_RUNTIME_STATE="$GLOBAL_RUNTIME" \
    NOID_LAN_TOPOLOGY_REFRESH="$TOPOLOGY_FIXTURE" \
    NOID_LAN_XDP_HEALTH_FILE="$XDP_HEALTH" \
    NOID_LAN_XDP_CONTROLLER=/bin/true \
    bash "$TMPDIR/noid-lan-allow" on \
    > "$TMPDIR/global-on.out" 2>&1 || global_on_rc=$?
if [ "$global_on_rc" -ne 0 ]; then
    sed 's/^/    /' "$TMPDIR/global-on.out" >&2
fi
assert_eq 0 "$global_on_rc" "global allow transaction completes"
assert_eq NONE "$(cat "$GLOBAL_FW_STATE")" "global allow detaches firewalld HOST"
assert_file_exists "$GLOBAL_MARKER" "global allow commits its durable marker"
assert_eq "$FIXTURE_UID:$FIXTURE_GID:600:1:0" \
    "$(stat -c '%u:%g:%a:%h:%s' "$GLOBAL_MARKER")" \
    "global allow marker is one exact empty root-state record"
assert_eq ALLOWED "$(cat "$GLOBAL_RUNTIME")" \
    "global allow publishes ALLOWED after topology synchronization"
assert_grep_fixed 'Global LAN egress allow active across firewalld, topology and WAN-strict' \
    "$TMPDIR/global-on.out" "global allow success text names every synchronized layer"
assert_grep_fixed 'Standard ARP and permanent neighbour pins are unchanged' \
    "$TMPDIR/global-on.out" "global IP opt-in states its orthogonal ARP boundary"
idempotent_on_rc=0
env PATH=/usr/bin:/bin \
    NOID_LAN_EXCEPTION_LOCK="$GLOBAL_LOCK" \
    NOID_LAN_GLOBAL_ALLOW_MARKER="$GLOBAL_MARKER" \
    NOID_LAN_GLOBAL_RUNTIME_STATE="$GLOBAL_RUNTIME" \
    NOID_LAN_TOPOLOGY_REFRESH="$TOPOLOGY_FIXTURE" \
    NOID_LAN_XDP_HEALTH_FILE="$XDP_HEALTH" \
    NOID_LAN_XDP_CONTROLLER=/bin/true \
    bash "$TMPDIR/noid-lan-allow" on \
    > "$TMPDIR/global-on-idempotent.out" 2>&1 || idempotent_on_rc=$?
assert_eq 0 "$idempotent_on_rc" "already-active global allow is noninteractive and idempotent"
assert_grep_fixed 'already active and synchronized' "$TMPDIR/global-on-idempotent.out" \
    "idempotent global allow reports its verified state"

global_off_rc=0
env PATH=/usr/bin:/bin \
    NOID_LAN_EXCEPTION_LOCK="$GLOBAL_LOCK" \
    NOID_LAN_GLOBAL_ALLOW_MARKER="$GLOBAL_MARKER" \
    NOID_LAN_GLOBAL_RUNTIME_STATE="$GLOBAL_RUNTIME" \
    NOID_LAN_TOPOLOGY_REFRESH="$TOPOLOGY_FIXTURE" \
    NOID_LAN_XDP_HEALTH_FILE="$XDP_HEALTH" \
    NOID_LAN_XDP_CONTROLLER=/bin/true \
    bash "$TMPDIR/noid-lan-allow" off \
    > "$TMPDIR/global-off.out" 2>&1 || global_off_rc=$?
if [ "$global_off_rc" -ne 0 ]; then
    sed 's/^/    /' "$TMPDIR/global-off.out" >&2
fi
assert_eq 0 "$global_off_rc" "global block restore transaction completes"
assert_eq HOST "$(cat "$GLOBAL_FW_STATE")" "global block restore reattaches HOST"
if [ ! -e "$GLOBAL_MARKER" ]; then
    _pass "global block restore removes the durable allow marker"
else
    _fail "global block restore left the durable allow marker"
fi
assert_eq BLOCKED "$(cat "$GLOBAL_RUNTIME")" \
    "global block restore publishes BLOCKED after topology synchronization"
idempotent_off_rc=0
env PATH=/usr/bin:/bin \
    NOID_LAN_EXCEPTION_LOCK="$GLOBAL_LOCK" \
    NOID_LAN_GLOBAL_ALLOW_MARKER="$GLOBAL_MARKER" \
    NOID_LAN_GLOBAL_RUNTIME_STATE="$GLOBAL_RUNTIME" \
    NOID_LAN_TOPOLOGY_REFRESH="$TOPOLOGY_FIXTURE" \
    NOID_LAN_XDP_HEALTH_FILE="$XDP_HEALTH" \
    NOID_LAN_XDP_CONTROLLER=/bin/true \
    bash "$TMPDIR/noid-lan-allow" off \
    > "$TMPDIR/global-off-idempotent.out" 2>&1 || idempotent_off_rc=$?
assert_eq 0 "$idempotent_off_rc" "already-blocked global state is idempotent"
assert_grep_fixed 'already in the default synchronized BLOCKED state' \
    "$TMPDIR/global-off-idempotent.out" \
    "idempotent block restore does not create an unnecessary snapshot"
unset -f firewall-cmd id systemctl

test_finish

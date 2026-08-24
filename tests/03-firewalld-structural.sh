#!/bin/bash
# 03-firewalld-structural — verify Module 03 firewalld snippet structural invariants
#
# Checks:
#   - firewalld.conf has DefaultZone=drop + LogDenied=off +
#     StrictForwardPorts=yes
#   - block-lan-out.xml has 38 host-stack rules + HOST ingress + drop egress:
#     37 LAN drops and one host-only DHCPv4 source-port continuation whose
#     exact root-owned UDP 68->67 selector is enforced by the earlier M03 hook
#     (the former 8 AMT-port rules were removed because firmware OOB traffic
#     bypasses the host firewall; retaining them implied false protection)
#     The reviewed 37-rule policy includes the RFC-reserved ranges and
#     LAN-discovery ports from the source-internal consistency seal: CGN
#     100.64.0.0/10, link-local 169.254.0.0/16, loopback 127.0.0.0/8,
#     0.0.0.0/8, testing 192.0.2.0/24 + 198.51.100.0/24 + 203.0.113.0/24,
#     benchmark 198.18.0.0/15, IPv6 loopback ::1/128, unspec ::/128,
#     documentation 2001:db8::/32 — the reviewed local/special-use baseline)
#     The .ks file as a whole has one additional literal policy rule for that
#     DHCP continuation; this test counts the block-lan-out heredoc only.
#     (libvirt ingress is in derived block-lan-out-vms.xml, generated at runtime
#     via cp+sed when libvirt zone exists — F44 firewalld validator rejects
#     mixed HOST+libvirt in <ingress-zone>; split)
#   - allow-host-ipv6.xml has exactly 6 icmp-types (4xMLD + 2xNDP)
#   - No router-advertisement + no redirect in allow-host-ipv6
#   - 03-vpn-zone.conf is no-op placeholder (NM 1.54+ rejected connection.zone
#     as connection-default; actual VPN zone enforcement is in Module 06
#     dispatcher /etc/NetworkManager/dispatcher.d/50-vpn-zone-enforce —
#     tested by 06-vpn-killswitch-structural.sh)
#   - zone-enforce script has runtime verification

set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/03-firewalld.ks"

test_start "03-firewalld-structural"

assert_file_exists "$KS_FILE"
assert_file_exists "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.c"
assert_file_exists "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.o.b64"
assert_file_exists "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.sh"
assert_file_executable "$PROJECT_ROOT/scripts/build-lan-xdp-object.sh" \
    "LAN XDP object builder is executable"
assert_grep_fixed 'export PATH=/usr/sbin:/usr/bin' \
    "$PROJECT_ROOT/scripts/build-lan-xdp-object.sh" \
    "LAN XDP object builder resolves only Fedora system tools"
assert_grep_fixed 'SOURCE_DIR="${SOURCE%/*}"' \
    "$PROJECT_ROOT/scripts/build-lan-xdp-object.sh" \
    "BTF path normalization starts at the XDP source directory"
assert_grep_fixed \
    '-fdebug-prefix-map="$SOURCE_DIR=/usr/src/noid-privacy-fedora"' \
    "$PROJECT_ROOT/scripts/build-lan-xdp-object.sh" \
    "object rebuild reproduces the pinned source path"
assert_not_grep 'kickstart/snippets/99-finalize.ks\|"$M99"' \
    "$PROJECT_ROOT/scripts/build-lan-xdp-object.sh" \
    "object builder has no silent M99 hash-replacement target"
assert_grep_fixed 'mapfile -t controller_hashes' \
    "$PROJECT_ROOT/scripts/build-lan-xdp-object.sh" \
    "object builder requires one unique controller hash before mutation"
assert_grep_fixed 'repairing an interrupted object/controller publication' \
    "$PROJECT_ROOT/scripts/build-lan-xdp-object.sh" \
    "build mode can recover its own interrupted two-file publication"
builder_before=$(sha256sum \
    "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.o.b64" \
    "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.sh" \
    "$KS_FILE")
assert_cmd_failure "object builder rejects unknown arguments before mutation" \
    "$PROJECT_ROOT/scripts/build-lan-xdp-object.sh" --write-typo
builder_after=$(sha256sum \
    "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.o.b64" \
    "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.sh" \
    "$KS_FILE")
assert_eq "$builder_before" "$builder_after" \
    "object-builder argument rejection preserves every owned payload"

XDP_REPAIR_REPO=$(mktemp -d /var/tmp/noid-xdp-repair.XXXXXX)
mkdir -p "$XDP_REPAIR_REPO/scripts/lib" \
    "$XDP_REPAIR_REPO/overrides/noid-lan-xdp" \
    "$XDP_REPAIR_REPO/kickstart/snippets"
cp "$PROJECT_ROOT/scripts/build-lan-xdp-object.sh" \
    "$PROJECT_ROOT/scripts/regen-lan-xdp-embed.sh" \
    "$XDP_REPAIR_REPO/scripts/"
cp "$PROJECT_ROOT/scripts/lib/source-generator.sh" \
    "$XDP_REPAIR_REPO/scripts/lib/"
cp "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.c" \
    "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.o.b64" \
    "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.sh" \
    "$XDP_REPAIR_REPO/overrides/noid-lan-xdp/"
cp "$KS_FILE" "$XDP_REPAIR_REPO/kickstart/snippets/03-firewalld.ks"
sed -i 's/^OBJECT_SHA256=[0-9a-f]\{64\}$/OBJECT_SHA256=0000000000000000000000000000000000000000000000000000000000000000/' \
    "$XDP_REPAIR_REPO/overrides/noid-lan-xdp/noid-lan-xdp.sh"
assert_cmd_success "object builder repairs an interrupted controller publication" \
    "$XDP_REPAIR_REPO/scripts/build-lan-xdp-object.sh"
assert_cmd_success "repaired XDP payload passes strict check mode" \
    "$XDP_REPAIR_REPO/scripts/build-lan-xdp-object.sh" --check
assert_cmd_success "repaired object bytes match the canonical payload" \
    cmp -s "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.o.b64" \
        "$XDP_REPAIR_REPO/overrides/noid-lan-xdp/noid-lan-xdp.bpf.o.b64"
assert_cmd_success "repaired controller bytes match the canonical payload" \
    cmp -s "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.sh" \
        "$XDP_REPAIR_REPO/overrides/noid-lan-xdp/noid-lan-xdp.sh"
assert_cmd_success "repair also restores the embedded M03 payload" \
    cmp -s "$KS_FILE" "$XDP_REPAIR_REPO/kickstart/snippets/03-firewalld.ks"
rm -rf -- "$XDP_REPAIR_REPO"

assert_file_executable "$PROJECT_ROOT/tests/03b-lan-xdp-controller-state.sh" \
    "LAN XDP state/identity/rollback fixture is executable"
assert_file_executable "$PROJECT_ROOT/tests/03c-firewalld-firstboot-runtime.sh" \
    "all-physical firstboot firewalld fixture is executable"
assert_file_executable "$PROJECT_ROOT/tests/pre-ship/03-lan-xdp-packet-fixtures.py" \
    "crafted XDP packet-fixture generator is executable"
assert_file_executable "$PROJECT_ROOT/tests/pre-ship/03-lan-direction-nft-runtime.sh" \
    "direction-aware nftables netns gate is executable"
assert_file_exists "$PROJECT_ROOT/docs/hardware-network-compatibility.md"
assert_grep_fixed 'cause unverified' "$PROJECT_ROOT/docs/known-failures.md" \
    "historical M03 namespace failure keeps its root cause unverified"
assert_grep_fixed 'did not create a previously absent boot order' \
    "$PROJECT_ROOT/docs/known-failures.md" \
    "redundant tmpfiles ordering is not presented as a proven repair"
assert_not_grep 'fast physical coldplug could start' \
    "$PROJECT_ROOT/docs/known-failures.md" \
    "known-failure guide contains no precluded coldplug-order claim"
assert_grep_fixed 'is not a coldplug-race fix' \
    "$PROJECT_ROOT/docs/hardware-network-compatibility.md" \
    "hardware guide distinguishes explicit ownership from default boot order"
for pkg in firewalld libnftnl nftables bpftool iproute iproute-tc util-linux-core python3; do
    assert_grep_extended "^${pkg}$" "$KS_FILE" \
        "Module 03 explicitly owns runtime package $pkg"
done
assert_cmd_success "LAN XDP payload generator reports no drift" \
    "$PROJECT_ROOT/scripts/regen-lan-xdp-embed.sh" --check

TMPDIR="$(mktemp -d /var/tmp/noid-test-03.XXXXXX)"
NOID_LAN_STATE_UID=$(id -u)
NOID_LAN_STATE_GID=$(id -g)
export NOID_LAN_STATE_UID NOID_LAN_STATE_GID
trap 'rm -rf "$TMPDIR"' EXIT

# --- extract files ----------------------------------------------------------
extract_heredoc "$KS_FILE" "FW_CONF_EOF"  "$TMPDIR/firewalld.conf" || _fail "firewalld.conf extraction"
extract_heredoc "$KS_FILE" "POLICY_EOF"   "$TMPDIR/block-lan-out.xml" || _fail "block-lan-out.xml extraction"
extract_heredoc "$KS_FILE" "HOSTV6_EOF"   "$TMPDIR/allow-host-ipv6.xml" || _fail "allow-host-ipv6.xml extraction"
extract_heredoc "$KS_FILE" "NOID_VPN_ZONE_EOF" "$TMPDIR/noid-vpn.xml" || _fail "noid-vpn.xml extraction"
extract_heredoc "$KS_FILE" "NM_VPN_EOF"   "$TMPDIR/03-vpn-zone.conf" || _fail "03-vpn-zone.conf extraction"
extract_heredoc "$KS_FILE" "ENFORCE_EOF"  "$TMPDIR/noid-firewalld-zone-enforce.sh" || _fail "enforce.sh extraction"
extract_heredoc "$KS_FILE" "LAN_TOPOLOGY_NFT_EOF" "$TMPDIR/noid-lan-topology.nft" || _fail "LAN topology nft extraction"
extract_heredoc "$KS_FILE" "LAN_TOPOLOGY_REFRESH_EOF" "$TMPDIR/noid-lan-topology-refresh.sh" || _fail "LAN topology refresh extraction"
extract_heredoc "$KS_FILE" "LAN_TOPOLOGY_BOOT_REFRESH_EOF" "$TMPDIR/noid-lan-topology-boot-refresh.sh" || _fail "LAN topology boot refresh extraction"
extract_heredoc "$KS_FILE" "LAN_TOPOLOGY_DISPATCHER_EOF" "$TMPDIR/noid-lan-topology-dispatcher.sh" || _fail "LAN topology dispatcher extraction"
extract_heredoc "$KS_FILE" "LAN_TOPOLOGY_SERVICE_EOF" "$TMPDIR/noid-lan-topology-guard.service" || _fail "LAN topology service extraction"
extract_heredoc "$KS_FILE" "LAN_TOPOLOGY_HOTPLUG_SERVICE_EOF" "$TMPDIR/noid-lan-topology-hotplug@.service" || _fail "LAN topology hotplug service extraction"
extract_heredoc "$KS_FILE" "LAN_TOPOLOGY_HOTPLUG_UDEV_EOF" "$TMPDIR/70-noid-lan-topology-hotplug.rules" || _fail "LAN topology hotplug udev extraction"
extract_heredoc "$KS_FILE" "NOID_LAN_XDP_NOTIFY_EOF" "$TMPDIR/noid-lan-xdp-notify" || _fail "LAN XDP notifier extraction"
extract_heredoc "$KS_FILE" "NOID_LAN_XDP_OBJECT_B64_EOF" "$TMPDIR/noid-lan-xdp.bpf.o.b64" || _fail "LAN XDP object extraction"
extract_heredoc "$KS_FILE" "NOID_LAN_XDP_CONTROLLER_EOF" "$TMPDIR/noid-lan-xdp" || _fail "LAN XDP controller extraction"
chmod 0755 "$TMPDIR/noid-lan-topology-boot-refresh.sh" "$TMPDIR/noid-lan-xdp-notify"

# --- firewalld.conf baseline ------------------------------------------------
assert_grep_extended '^DefaultZone=drop$' "$TMPDIR/firewalld.conf"
assert_grep_fixed "flowtable fast path off" "$TMPDIR/firewalld.conf" \
    "flowtable comment describes both software fastpath and derived offload"
assert_not_grep 'flowtable HW offload' "$TMPDIR/firewalld.conf" \
    "flowtable setting is not mislabeled as hardware-only"
assert_grep_fixed '`nft -a list table inet firewalld`' "$TMPDIR/firewalld.conf" \
    "counter diagnostic uses valid nft table-list syntax"
assert_not_grep 'nft list counters table' "$TMPDIR/firewalld.conf" \
    "counter diagnostic contains no invalid nft object-list command"
assert_grep_fixed 'That auditor reference is not installed in the image.' \
    "$TMPDIR/firewalld.conf" \
    "repository-only denial-log reference is identified as source-only"
assert_grep_fixed 'section 5.3.1' "$TMPDIR/firewalld.conf" \
    "6to4 filtering rationale points to the governing RFC section"
assert_not_grep 'CVE-2021-24122' "$TMPDIR/firewalld.conf" \
    "6to4 filtering does not cite an unrelated Bluetooth CVE"
assert_grep_extended '^LogDenied=off$'    "$TMPDIR/firewalld.conf"
assert_grep_extended '^FirewallBackend=nftables$' "$TMPDIR/firewalld.conf"
assert_grep_extended '^RFC3964_IPv4=yes$' "$TMPDIR/firewalld.conf"
assert_grep_extended '^IPv6_rpfilter=loose$' "$TMPDIR/firewalld.conf" \
    "asymmetric VPN paths retain loose IPv6 reverse-path filtering"
assert_grep_fixed "Deliberate deviation from firewalld's \`strict\` default" \
    "$TMPDIR/firewalld.conf" \
    "IPv6 reverse-path policy discloses its weaker-than-vendor posture"
assert_grep_fixed 'cost of strict per-interface IPv6 source anti-spoofing' \
    "$TMPDIR/firewalld.conf" \
    "IPv6 reverse-path policy records the concrete security trade-off"
assert_grep_extended '^NftablesCounters=yes$' "$TMPDIR/firewalld.conf"
assert_grep_extended '^StrictForwardPorts=yes$' "$TMPDIR/firewalld.conf" \
    "external DNAT cannot bypass explicit firewalld forward-port authorization"
assert_not_grep 'firewall-cmd --info-policy.*counter' "$TMPDIR/firewalld.conf" \
    "counter documentation does not claim firewall-cmd exposes packet counters"

# --- block-lan-out.xml: 37 drops + one host-only DHCP continuation ----------
rule_count=$(grep -c '<rule ' "$TMPDIR/block-lan-out.xml" 2>/dev/null || true)
rule_count=${rule_count:-0}
assert_eq "38" "$rule_count" \
    "block-lan-out.xml has 37 drops plus one host DHCP continuation"
DHCP_HOST_RULE='  <rule family="ipv4" priority="-32768"><source-port port="68" protocol="udp"/><accept/></rule>'
assert_eq 1 "$(grep -cFx "$DHCP_HOST_RULE" "$TMPDIR/block-lan-out.xml" || true)" \
    "host policy has one highest-precedence DHCP client source-port continuation"
assert_grep_fixed 'firewalld rich language permits one port element per rule' \
    "$TMPDIR/block-lan-out.xml" \
    "coarse firewalld selector records why M03 must enforce the exact tuple"
assert_grep_fixed \
    'meta skuid 0' "$TMPDIR/noid-lan-topology.nft" \
    "topology DHCP pass is restricted to a root-owned socket"
assert_grep_fixed \
    'udp sport 68 udp dport 67 counter name dhcp_client_v4 accept' \
    "$TMPDIR/noid-lan-topology.nft" \
    "topology DHCP pass requires the exact IPv4 client/server port tuple"
assert_grep_fixed \
    'counter name blocked_dhcp_client_misuse_v4 drop' \
    "$TMPDIR/noid-lan-topology.nft" \
    "topology guard drops every remaining unapproved IPv4 UDP source-68 packet"
assert_grep_fixed \
    'oifname @lan_guard_ifaces meta nfproto ipv4 udp sport 68' \
    "$TMPDIR/noid-lan-topology.nft" \
    "reserved-port fallback is scoped to interfaces enforcing BLOCKED mode"
dhcp_pass_line=$(grep -nF 'udp sport 68 udp dport 67 counter name dhcp_client_v4 accept' \
    "$TMPDIR/noid-lan-topology.nft" | cut -d: -f1)
inbound_reply_line=$(grep -nF 'oifname @physical_ifaces ct state established,related' \
    "$TMPDIR/noid-lan-topology.nft" | head -1 | cut -d: -f1)
allowed_v4_line=$(grep -nF 'oifname @physical_ifaces ip daddr @allowed_v4 accept' \
    "$TMPDIR/noid-lan-topology.nft" | head -1 | cut -d: -f1)
allowed_v6_line=$(grep -nF 'oifname @physical_ifaces ip6 daddr @allowed_v6 accept' \
    "$TMPDIR/noid-lan-topology.nft" | head -1 | cut -d: -f1)
dhcp_misuse_line=$(grep -nF 'counter name blocked_dhcp_client_misuse_v4 drop' \
    "$TMPDIR/noid-lan-topology.nft" | cut -d: -f1)
connected_drop_line=$(grep -nF 'oifname @physical_ifaces ip daddr @connected_v4' \
    "$TMPDIR/noid-lan-topology.nft" | head -1 | cut -d: -f1)
if [ "$dhcp_pass_line" -lt "$inbound_reply_line" ] \
        && [ "$inbound_reply_line" -lt "$allowed_v4_line" ] \
        && [ "$allowed_v4_line" -lt "$allowed_v6_line" ] \
        && [ "$allowed_v6_line" -lt "$dhcp_misuse_line" ] \
        && [ "$dhcp_misuse_line" -lt "$connected_drop_line" ]; then
    _pass "DHCP, explicit peer grants and reserved-port fallback have the fail-closed order"
else
    _fail "DHCP/peer selector order could widen or shadow an explicit grant"
fi
assert_grep_fixed \
    "sed -i '\\|^  <rule family=\"ipv4\" priority=\"-32768\"><source-port port=\"68\" protocol=\"udp\"/><accept/></rule>\$|d'" \
    "$KS_FILE" \
    "derived VM policy deletes the host-only DHCP continuation exactly"
forward_body=$(awk '
    /^    chain forward \{/ { inside = 1 }
    inside { print }
    inside && /^    \}$/ { exit }
' "$TMPDIR/noid-lan-topology.nft")
if grep -qE 'sport 68|dport 67|dhcp_client' <<<"$forward_body"; then
    _fail "forward chain inherited the host DHCP-client exception"
else
    _pass "forward chain has no DHCP-client exception"
fi
unset DHCP_HOST_RULE dhcp_pass_line inbound_reply_line allowed_v4_line \
    allowed_v6_line dhcp_misuse_line connected_drop_line forward_body
assert_not_grep '16992\|16993\|16994\|16995' "$TMPDIR/block-lan-out.xml" \
    "host firewall does not misrepresent AMT out-of-band filtering"

# Dedicated VPN zone: unlike firewalld `trusted`, target DROP does not expose
# listening host services to unsolicited tunnel-side traffic.
assert_grep_fixed '<zone target="DROP">' "$TMPDIR/noid-vpn.xml"
assert_not_grep '<service ' "$TMPDIR/noid-vpn.xml" "noid-vpn zone opens no services"
assert_grep_fixed 'change-interface=noid-vpn' "$TMPDIR/03-vpn-zone.conf"

# Topology-aware layer closes the static-address-list gap for directly
# connected networks using unusual/public prefixes. Explicit per-IP allows
# are mirrored ahead of the drop and set replacement is one atomic nft batch.
assert_grep_fixed 'table inet noid_lan_topology' "$TMPDIR/noid-lan-topology.nft"
assert_grep_fixed 'set lan_guard_ifaces {' "$TMPDIR/noid-lan-topology.nft" \
    "topology table has a dedicated default-boundary interface set"
assert_grep_fixed 'Physical interfaces enforcing the default LAN boundary' \
    "$TMPDIR/noid-lan-topology.nft" \
    "dedicated interface set documents its BLOCKED-state ownership"
assert_grep_fixed 'oifname @physical_ifaces ip daddr @connected_v4' "$TMPDIR/noid-lan-topology.nft"
assert_grep_fixed 'oifname @physical_ifaces ip6 daddr @connected_v6' "$TMPDIR/noid-lan-topology.nft"
assert_grep_fixed 'type filter hook forward priority -4; policy accept;' \
    "$TMPDIR/noid-lan-topology.nft" \
    "VM/container forwarded traffic receives the topology boundary"
assert_grep_fixed 'ip daddr @allowed_v4 accept' "$TMPDIR/noid-lan-topology.nft"
assert_grep_fixed 'ip6 daddr @allowed_v6 accept' "$TMPDIR/noid-lan-topology.nft"
assert_grep_fixed "printf 'flush set %s lan_guard_ifaces" \
    "$TMPDIR/noid-lan-topology-refresh.sh" \
    "every atomic topology refresh clears the prior guard-interface state"
assert_grep_fixed "printf 'add element %s lan_guard_ifaces" \
    "$TMPDIR/noid-lan-topology-refresh.sh" \
    "BLOCKED refreshes repopulate the guard-interface set"
# Every plain-address interval set needs auto-merge. Without it nft refuses an
# element already covered by another ("conflicting intervals specified"), and
# the producer performs only exact-string de-duplication -- so a host whose
# links yield nested prefixes fails the whole atomic refresh, which on a pre-up
# event aborts NetworkManager's activation of that link. Verified in a netns
# that merging changes no semantics: `nft get element` still answers for every
# member, and deleting a single /32 splits the range correctly.
for topology_interval_set in connected_v4 connected_v6 allowed_v4 allowed_v6 \
                             outbound_peers_v4 inbound_peers_v4; do
    set_body=$(awk -v s="set $topology_interval_set {" '
        index($0, s) { inside = 1 }
        inside { print }
        inside && /^\s*\}/ { exit }
    ' "$TMPDIR/noid-lan-topology.nft")
    printf '%s' "$set_body" | grep -q 'flags interval' \
        && printf '%s' "$set_body" | grep -q 'auto-merge' \
        && _pass "interval set $topology_interval_set tolerates a covered prefix" \
        || _fail "interval set $topology_interval_set lacks auto-merge"
done
unset topology_interval_set set_body
# The concatenated selector sets deliberately do NOT carry it: the kernel
# rejects an overlapping concatenated element with "File exists" whether or not
# auto-merge is declared, so declaring it there would only look like protection.
for topology_concat_set in inbound_tcp_v4 inbound_udp_v4; do
    set_body=$(awk -v s="set $topology_concat_set {" '
        index($0, s) { inside = 1 }
        inside { print }
        inside && /^\s*\}/ { exit }
    ' "$TMPDIR/noid-lan-topology.nft")
    printf '%s' "$set_body" | grep -q 'auto-merge' \
        && _fail "concatenated set $topology_concat_set claims a merge nft cannot do" \
        || _pass "concatenated set $topology_concat_set claims no false merge tolerance"
done
unset topology_concat_set set_body
assert_grep_fixed 'table netdev noid_l2_guard' "$TMPDIR/noid-lan-topology-refresh.sh" \
    "physical interfaces receive a Layer-2 guard"
assert_grep_fixed 'hook ingress device' "$TMPDIR/noid-lan-topology-refresh.sh"
assert_grep_fixed 'hook egress device' "$TMPDIR/noid-lan-topology-refresh.sh"
assert_grep_fixed 'ether type { ip, ip6, arp, 0x888e } accept' \
    "$TMPDIR/noid-lan-topology-refresh.sh" \
    "only IP, standard ARP, and required EAPOL EtherTypes pass Layer 2"
assert_cmd_success "LAN topology refresh is valid bash" bash -n "$TMPDIR/noid-lan-topology-refresh.sh"
assert_cmd_success "LAN topology boot refresh is valid bash" bash -n "$TMPDIR/noid-lan-topology-boot-refresh.sh"
assert_cmd_success "LAN topology dispatcher is valid bash" bash -n "$TMPDIR/noid-lan-topology-dispatcher.sh"
assert_grep_fixed 'ExecStart=/usr/local/sbin/noid-lan-topology-boot-refresh.sh' \
    "$TMPDIR/noid-lan-topology-guard.service" \
    "initial boot retries the complete topology transaction from fresh state"
assert_grep_fixed \
    'After=firewalld.service systemd-tmpfiles-setup.service' \
    "$TMPDIR/noid-lan-topology-guard.service" \
    "initial topology guard names its shared runtime directory owner explicitly"
assert_grep_fixed \
    'Requires=firewalld.service systemd-tmpfiles-setup.service' \
    "$TMPDIR/noid-lan-topology-guard.service" \
    "initial topology guard propagates firewalld/runtime-owner failure explicitly"
assert_grep_fixed \
    'After=firewalld.service noid-lan-topology-guard.service systemd-tmpfiles-setup.service' \
    "$TMPDIR/noid-lan-topology-hotplug@.service" \
    "hotplug refresh names the baseline and runtime owner explicitly"
assert_grep_fixed \
    'Requires=firewalld.service systemd-tmpfiles-setup.service' \
    "$TMPDIR/noid-lan-topology-hotplug@.service" \
    "hotplug refresh propagates runtime-owner failure explicitly"
assert_grep_fixed 'StartLimitIntervalSec=60s' "$TMPDIR/noid-lan-topology-guard.service" \
    "repeated external boot-guard activation has an explicit bounded interval"
assert_grep_fixed 'StartLimitBurst=3' "$TMPDIR/noid-lan-topology-guard.service" \
    "repeated external boot-guard activation cannot flood the console indefinitely"
assert_grep_fixed 'NOID_LAN_XDP_SYNC_ATTEMPTS=1' \
    "$TMPDIR/noid-lan-topology-boot-refresh.sh" \
    "boot retry invokes the complete refresh with one inner controller attempt"
assert_grep_fixed 'NOID_LAN_RETRY_DEGRADED_XDP=1 "$REFRESH"; then' \
    "$TMPDIR/noid-lan-topology-boot-refresh.sh" \
    "boot retry observes a committed but transient XDP degradation"
assert_grep_fixed 'logger -t "$LOG_TAG" "$*" || true' \
    "$TMPDIR/noid-lan-topology-boot-refresh.sh" \
    "boot diagnostics cannot replace the refresh result when logger fails"
assert_not_grep_extended '^[[:space:]]*nft[[:space:]]' \
    "$TMPDIR/noid-lan-topology-boot-refresh.sh" \
    "boot retry cannot repeat only the final nft mutation"
assert_grep_fixed 'inspect journalctl -b -t noid-lan-topology' \
    "$TMPDIR/noid-lan-topology-boot-refresh.sh" \
    "systemd status points to the exact detailed topology journal"

cat > "$TMPDIR/topology-refresh-fixture" <<'TOPOLOGY_REFRESH_FIXTURE_EOF'
#!/bin/bash
set -eu
[ "${NOID_LAN_XDP_SYNC_ATTEMPTS:-}" = 1 ] || exit 97
count=0
[ ! -f "$BOOT_RETRY_COUNT" ] || count=$(cat "$BOOT_RETRY_COUNT")
count=$((count + 1))
printf '%s\n' "$count" > "$BOOT_RETRY_COUNT"
[ "$count" -ge "${BOOT_RETRY_SUCCEED_ON:-999}" ]
TOPOLOGY_REFRESH_FIXTURE_EOF
chmod 0755 "$TMPDIR/topology-refresh-fixture"
assert_cmd_success "boot topology transaction retries then converges" \
    env \
        BOOT_RETRY_COUNT="$TMPDIR/topology-boot-retry-success.count" \
        BOOT_RETRY_SUCCEED_ON=3 \
        NOID_LAN_TOPOLOGY_REFRESH="$TMPDIR/topology-refresh-fixture" \
        NOID_LAN_TOPOLOGY_BOOT_ATTEMPTS=4 \
        NOID_LAN_TOPOLOGY_BOOT_BACKOFF=0 \
        "$TMPDIR/noid-lan-topology-boot-refresh.sh"
assert_eq 3 "$(cat "$TMPDIR/topology-boot-retry-success.count")" \
    "boot topology transaction re-runs exactly through first success"
boot_retry_rc=0
env \
    BOOT_RETRY_COUNT="$TMPDIR/topology-boot-retry-fail.count" \
    BOOT_RETRY_SUCCEED_ON=9 \
    NOID_LAN_TOPOLOGY_REFRESH="$TMPDIR/topology-refresh-fixture" \
    NOID_LAN_TOPOLOGY_BOOT_ATTEMPTS=3 \
    NOID_LAN_TOPOLOGY_BOOT_BACKOFF=0 \
    "$TMPDIR/noid-lan-topology-boot-refresh.sh" >/dev/null 2>&1 \
    || boot_retry_rc=$?
assert_eq 1 "$boot_retry_rc" \
    "boot topology transaction remains fail-closed after bounded exhaustion"
assert_eq 3 "$(cat "$TMPDIR/topology-boot-retry-fail.count")" \
    "boot topology transaction stops at its exact attempt bound"

cat > "$TMPDIR/topology-xdp-degraded-fixture" <<'TOPOLOGY_XDP_DEGRADED_FIXTURE_EOF'
#!/bin/bash
set -eu
[ "${NOID_LAN_XDP_SYNC_ATTEMPTS:-}" = 1 ] || exit 97
[ "${NOID_LAN_RETRY_DEGRADED_XDP:-}" = 1 ] || exit 98
count=0
[ ! -f "$BOOT_RETRY_COUNT" ] || count=$(cat "$BOOT_RETRY_COUNT")
count=$((count + 1))
printf '%s\n' "$count" > "$BOOT_RETRY_COUNT"
[ "$count" -ge "${BOOT_RETRY_SUCCEED_ON:-999}" ] && exit 0
exit 75
TOPOLOGY_XDP_DEGRADED_FIXTURE_EOF
chmod 0755 "$TMPDIR/topology-xdp-degraded-fixture"
assert_cmd_success "boot retries a committed transient XDP degradation" \
    env \
        BOOT_RETRY_COUNT="$TMPDIR/topology-xdp-degraded-success.count" \
        BOOT_RETRY_SUCCEED_ON=3 \
        NOID_LAN_TOPOLOGY_REFRESH="$TMPDIR/topology-xdp-degraded-fixture" \
        NOID_LAN_TOPOLOGY_BOOT_ATTEMPTS=4 \
        NOID_LAN_TOPOLOGY_BOOT_BACKOFF=0 \
        "$TMPDIR/noid-lan-topology-boot-refresh.sh"
assert_eq 3 "$(cat "$TMPDIR/topology-xdp-degraded-success.count")" \
    "boot spends the outer budget until the XDP postcheck converges"
xdp_degraded_exhausted_rc=0
env \
    BOOT_RETRY_COUNT="$TMPDIR/topology-xdp-degraded-exhausted.count" \
    BOOT_RETRY_SUCCEED_ON=9 \
    NOID_LAN_TOPOLOGY_REFRESH="$TMPDIR/topology-xdp-degraded-fixture" \
    NOID_LAN_TOPOLOGY_BOOT_ATTEMPTS=3 \
    NOID_LAN_TOPOLOGY_BOOT_BACKOFF=0 \
    "$TMPDIR/noid-lan-topology-boot-refresh.sh" \
    >"$TMPDIR/topology-xdp-degraded-exhausted.log" 2>&1 \
    || xdp_degraded_exhausted_rc=$?
assert_eq 0 "$xdp_degraded_exhausted_rc" \
    "bounded XDP exhaustion preserves the documented firewall fallback"
assert_eq 3 "$(cat "$TMPDIR/topology-xdp-degraded-exhausted.count")" \
    "boot bounds an enduring XDP degradation exactly"
assert_grep_fixed \
    'XDP postcheck remained degraded after 3 complete transaction attempt(s); lower nft/firewall layers are committed' \
    "$TMPDIR/topology-xdp-degraded-exhausted.log" \
    "bounded XDP exhaustion remains explicit without blocking WAN repair"

mkdir -p "$TMPDIR/boot-logger-fail-bin"
cat > "$TMPDIR/boot-logger-fail-bin/logger" <<'BOOT_LOGGER_FAIL_EOF'
#!/bin/bash
exit 69
BOOT_LOGGER_FAIL_EOF
chmod 0755 "$TMPDIR/boot-logger-fail-bin/logger"
assert_cmd_success "logger failure cannot abort a converging boot retry" \
    env \
        PATH="$TMPDIR/boot-logger-fail-bin:/usr/bin:/bin" \
        BOOT_RETRY_COUNT="$TMPDIR/topology-boot-logger-fail.count" \
        BOOT_RETRY_SUCCEED_ON=2 \
        NOID_LAN_TOPOLOGY_REFRESH="$TMPDIR/topology-refresh-fixture" \
        NOID_LAN_TOPOLOGY_BOOT_ATTEMPTS=3 \
        NOID_LAN_TOPOLOGY_BOOT_BACKOFF=0 \
        "$TMPDIR/noid-lan-topology-boot-refresh.sh"
assert_eq 2 "$(cat "$TMPDIR/topology-boot-logger-fail.count")" \
    "logger failure preserves the exact refresh retry result"
if command -v udevadm >/dev/null 2>&1; then
    assert_cmd_success "LAN topology hotplug rule passes udev verification" \
        udevadm verify --no-summary "$TMPDIR/70-noid-lan-topology-hotplug.rules"
fi
assert_cmd_success "LAN XDP controller is valid bash" bash -n "$TMPDIR/noid-lan-xdp"
assert_grep_fixed 'NOID_FMT_AUTO_TITLE="NoID Privacy — LAN XDP Boundary"' \
    "$TMPDIR/noid-lan-xdp" \
    "interactive status uses the shared NoID Privacy CLI frame"
assert_grep_fixed 'fmt_section "Live attachment identity"' \
    "$TMPDIR/noid-lan-xdp" "interactive status labels its native identity rows"
formatter_line=$(grep -nF \
    'NOID_FMT_AUTO_TITLE="NoID Privacy — LAN XDP Boundary"' \
    "$TMPDIR/noid-lan-xdp" | cut -d: -f1)
lock_reexec_line=$(grep -nF \
    'exec flock --close --exclusive "$LOCK_FILE"' \
    "$TMPDIR/noid-lan-xdp" | cut -d: -f1)
if [ "$formatter_line" -gt "$lock_reexec_line" ]; then
    _pass "TTY formatter loads only in the final lock-owning process"
else
    _fail "TTY formatter loads only in the final lock-owning process"
fi
assert_grep_fixed 'require_ethernet_link "$iface"' "$TMPDIR/noid-lan-xdp" \
    "controller refuses non-Ethernet links before ACTIVE status"
assert_not_grep 'map_flow_delete_remote_ip\|bpf_map_get_next_key' \
    "$TMPDIR/noid-lan-xdp" \
    "peer transition has no racy userspace scan/delete of a shared flow map"
assert_grep_fixed 'if [ -z "$fresh_flow_peer" ]; then' \
    "$TMPDIR/noid-lan-xdp" \
    "ordinary refreshes retain the established reply-correlation map"
assert_grep_fixed '--invalidate-peer-flows)' \
    "$TMPDIR/noid-lan-topology-refresh.sh" \
    "topology transaction accepts one explicit peer-flow invalidation"
assert_grep_fixed \
    'xdp_args+=(--fresh-flow-map-for-peer "$INVALIDATE_FLOW_PEER")' \
    "$TMPDIR/noid-lan-topology-refresh.sh" \
    "peer invalidation selects a fresh flow generation before publication"
assert_grep_fixed 'xdp_ifaces+=("$iface")' "$TMPDIR/noid-lan-topology-refresh.sh" \
    "refresh separates Ethernet XDP links from the complete physical L3 set"
assert_grep_fixed 'for item in "${xdp_ifaces[@]}"; do' \
    "$TMPDIR/noid-lan-topology-refresh.sh" \
    "XDP arguments and netdev hooks use only qualified Ethernet links"
assert_grep_fixed 'does not satisfy the Ethernet XDP contract' \
    "$TMPDIR/noid-lan-topology-refresh.sh" \
    "LAN peers cannot bind to a partially enforced non-Ethernet path"
assert_cmd_success "LAN XDP controller embed matches its audited source" \
    cmp -s "$TMPDIR/noid-lan-xdp" "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.sh"
assert_cmd_success "LAN XDP object embed matches its pinned payload" \
    cmp -s "$TMPDIR/noid-lan-xdp.bpf.o.b64" \
        "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.o.b64"
assert_grep_fixed 'noid_xdp_flows_v4' \
    "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.c" \
    "XDP ingress is coupled to observed egress flow state"
assert_grep_fixed 'noid_xdp_dhcp_v4' \
    "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.c" \
    "DHCP bootstrap is coupled to an egress-observed transaction map"
assert_grep_fixed 'struct noid_dhcp4' \
    "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.c" \
    "DHCP transaction state has a dedicated exact-match key"
assert_grep_fixed '__u32 ifindex;' \
    "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.c" \
    "DHCP transaction state is bound to one physical interface"
assert_grep_fixed '__be32 xid;' \
    "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.c" \
    "DHCP transaction state includes the BOOTP transaction ID"
assert_grep_fixed '__builtin_memcpy(key.mac.addr, chaddr, ETH_ALEN);' \
    "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.c" \
    "DHCP reply lookup includes the BOOTP client hardware address"
assert_grep_fixed '#define NOID_DHCP_FLOW_NS (90ULL * 1000000000)' \
    "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.c" \
    "DHCP bootstrap admission expires after a bounded 90 seconds"
assert_grep_fixed 'udp->source == bpf_htons(68) && udp->dest == bpf_htons(67)' \
    "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.c" \
    "TC egress observes only client-to-server DHCP traffic"
assert_grep_fixed 'dhcp->op != 1' \
    "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.c" \
    "TC egress records only BOOTP request messages"
assert_grep_fixed 'noid_dhcp4_is_live(ctx->ingress_ifindex, dhcp->xid,' \
    "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.c" \
    "XDP admits a DHCP reply only for the exact live request"
assert_grep_fixed 'noid_record_local_source_mac(ctx->ifindex, eth->h_source);' \
    "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.c" \
    "TC egress registers the locally emitted MAC after NetworkManager rotation"
assert_grep_fixed 'bpf_map_update_elem(&noid_xdp_local_macs, &key, &allowed, BPF_ANY);' \
    "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.c" \
    "rotated local MAC publication updates only the interface-bound local map"
assert_grep_fixed 'object-pinned "$pin/progs/noid_lan_egress"' \
    "$PROJECT_ROOT/tests/pre-ship/03-lan-xdp-runtime.sh" \
    "runtime gate attaches the exact TC program sharing the XDP maps"
assert_grep_fixed 'unshare --net /usr/bin/sleep 300' \
    "$PROJECT_ROOT/tests/pre-ship/03-lan-xdp-runtime.sh" \
    "runtime gate owns process-bound network namespaces"
assert_grep_fixed 'nsenter --target "$target_pid" --net -- "$@"' \
    "$PROJECT_ROOT/tests/pre-ship/03-lan-xdp-runtime.sh" \
    "runtime gate enters only each isolated network namespace"
assert_grep_fixed '[[ -z ${namespace_ids[$observed]+present} ]]' \
    "$PROJECT_ROOT/tests/pre-ship/03-lan-xdp-runtime.sh" \
    "runtime gate requires four distinct namespace identities"
assert_not_grep_extended 'ip netns (add|exec)|ip -n' \
    "$PROJECT_ROOT/tests/pre-ship/03-lan-xdp-runtime.sh" \
    "runtime gate cannot regress to persistent named-namespace entry"
assert_grep_fixed 'XDP_DROP_DEFAULT' \
    "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.c" \
    "XDP boundary has an explicit default-drop verdict"
assert_grep_fixed 'if ((void *)(eth + 1) > data_end)' \
    "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.c" \
    "XDP rejects a frame shorter than the Ethernet header before any field read"
assert_grep_fixed '#define NOID_IPV4_MAX_LEN 1500' \
    "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.c" \
    "IPv4 checksum work and admitted physical-link datagrams have a fixed bound"
assert_grep_fixed 'iterations = bpf_loop((length + 1) / 2, noid_checksum_step, &state, 0);' \
    "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.c" \
    "checksum validation uses the verifier-bounded loop helper"
assert_grep_fixed '!noid_checksum_valid(ip, ihl, data_end, 0)' \
    "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.c" \
    "every admitted IPv4 path validates the complete header checksum"
assert_grep_fixed 'udp->check == 0 ||' \
    "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.c" \
    "UDP paths require an explicit checksum instead of accepting IPv4 omission"
assert_grep_fixed 'NOID_XDP_DROP_FRAGMENT' \
    "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.c" \
    "unreassembled IPv4 fragments have a dedicated fail-closed verdict"
assert_not_grep 'noid_xdp_fragments_v4' \
    "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.c" \
    "no stale fragment-admission map remains in the object"
assert_not_grep 'noid_xdp_fragments_v4' "$TMPDIR/noid-lan-xdp" \
    "controller cannot reuse the retired fragment-admission map"
assert_grep_fixed '!noid_mac_equal(eth->h_source, arp->sender_mac)' \
    "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.c" \
    "ARP sender identity is correlated with the Ethernet source"
assert_grep_fixed '!noid_mac_equal(eth->h_dest, arp->target_mac)' \
    "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.c" \
    "unicast ARP reply target identity is correlated with Ethernet destination"
assert_grep_fixed 'operation == NOID_ARPOP_REQUEST' \
    "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.c" \
    "standard ARP requests reach native IPv4 ACD"
assert_grep_fixed 'NOID_XDP_PASS_ARP_STANDARD' \
    "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.c" \
    "standard ARP has an explicit observable XDP verdict"
assert_not_grep 'noid_xdp_learning_v4\|NOID_XDP_PASS_ARP_LEARNING' \
    "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.c" \
    "BPF object has no obsolete dynamic ARP admission map"
assert_grep_fixed 'static-address namespace received DHCP without a tracked request' \
    "$PROJECT_ROOT/tests/pre-ship/03-lan-xdp-runtime.sh" \
    "runtime gate rejects an unsolicited exact DHCP reply on direct static addressing"
assert_grep_fixed 'static-address unsolicited DHCP drop+7 baseline valid' \
    "$PROJECT_ROOT/tests/pre-ship/03-lan-xdp-runtime.sh" \
    "runtime gate reports the complete reachable crafted-packet matrix"
assert_cmd_success "crafted XDP packet fixture source parses" \
    python3 -c 'import ast,pathlib,sys; ast.parse(pathlib.Path(sys.argv[1]).read_text())' \
        "$PROJECT_ROOT/tests/pre-ship/03-lan-xdp-packet-fixtures.py"
assert_grep_fixed 'struct noid_link_mac' \
    "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.c" \
    "gateway and local MAC authorization includes a physical-link key"
assert_grep_fixed '.ifindex = ctx->ingress_ifindex' \
    "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.c" \
    "ingress peers and reverse flows bind to the receiving NIC"
assert_grep_fixed 'flow.ifindex = ctx->ifindex' \
    "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.c" \
    "TC egress state records the transmitting NIC"
assert_grep_fixed '--peer "${peer_ifaces_v4[$i]},${peer_ips_v4[$i]},${peer_macs_v4[$i]},${peer_directions_v4[$i]},${peer_protocols_v4[$i]},${peer_port_starts_v4[$i]},${peer_port_ends_v4[$i]}"' \
    "$TMPDIR/noid-lan-topology-refresh.sh" \
    "peer authorization publishes binding, direction, protocol and ports atomically"
assert_grep_fixed 'xdp_args=(sync "$global_allow")' \
    "$TMPDIR/noid-lan-topology-refresh.sh" \
    "topology refresh publishes its validated global state to XDP"
assert_grep_fixed $'if "$XDP_CONTROLLER" "${xdp_args[@]}" >/dev/null \\' \
    "$TMPDIR/noid-lan-topology-refresh.sh" \
    "internal XDP convergence suppresses stdout while retaining stderr diagnostics"
assert_grep_fixed 'CapabilityBoundingSet=CAP_NET_ADMIN CAP_BPF CAP_PERFMON' \
    "$KS_FILE" "topology services carry only the BPF/network capabilities they require"
assert_grep_fixed 'SystemCallFilter=@system-service bpf' "$KS_FILE" \
    "topology service syscall policy explicitly admits BPF loading"
assert_grep_fixed 'ProtectKernelTunables=no' "$KS_FILE" \
    "bpffs is not accidentally remounted read-only by the service sandbox"
assert_grep_fixed '"$XDP_CONTROLLER" status >/dev/null' \
    "$TMPDIR/noid-lan-topology-refresh.sh" \
    "every topology refresh verifies live XDP/TC postconditions"
assert_grep_fixed 'publish_xdp_health DEGRADED sync-or-postcheck-failed' \
    "$TMPDIR/noid-lan-topology-refresh.sh" \
    "XDP-only failure publishes an explicit degraded state"
assert_grep_fixed 'retire_runtime_status "$GLOBAL_RUNTIME_STATE" || true' \
    "$TMPDIR/noid-lan-topology-refresh.sh" \
    "failed global-state publication retires prior runtime evidence"
assert_grep_fixed 'retire_runtime_status "$XDP_HEALTH_FILE" || true' \
    "$TMPDIR/noid-lan-topology-refresh.sh" \
    "failed XDP-health publication retires prior runtime evidence"
assert_not_grep 'publish_global_state INCONSISTENT || true' \
    "$TMPDIR/noid-lan-topology-refresh.sh" \
    "inconsistent-state publication is not silently swallowed without diagnostics"
assert_grep_fixed '/usr/local/bin/noid-lan-xdp-notify' "$KS_FILE" \
    "graphical sessions warn about a degraded raw-packet boundary"
assert_grep_fixed 'select the previous Fedora kernel under GRUB Advanced options' \
    "$TMPDIR/noid-lan-xdp-notify" \
    "transaction failure notification includes the kernel rollback"
assert_eq 1 \
    "$(grep -cF 'select the previous Fedora kernel under GRUB Advanced options' \
        "$TMPDIR/noid-lan-xdp-notify")" \
    "kernel rollback appears in exactly one reason-specific remedy"

NOTIFY_BIN="$TMPDIR/notify-bin"
NOTIFY_HEALTH_DIR="$TMPDIR/notify-health"
NOTIFY_HEALTH="$NOTIFY_HEALTH_DIR/health"
NOTIFY_CAPTURE="$TMPDIR/notify.capture"
mkdir -m 0755 "$NOTIFY_BIN" "$NOTIFY_HEALTH_DIR"
cat > "$NOTIFY_BIN/notify-send" <<'NOTIFY_SEND_FIXTURE_EOF'
#!/bin/bash
printf '%s\n' "$@" > "$NOID_NOTIFY_CAPTURE"
NOTIFY_SEND_FIXTURE_EOF
chmod 0755 "$NOTIFY_BIN/notify-send"
notify_uid=$(id -u)
notify_gid=$(id -g)
for notify_case in \
    'sync-or-postcheck-failed|previous Fedora kernel' \
    'controller-missing|installed LAN XDP controller is missing' \
    'unsupported-link-type|link type is not Ethernet-framed' \
    'no-ethernet-link|No Ethernet-framed physical link is present' \
    'physical-ipv6-unsupported|Physical-link IPv6 is enabled'; do
    notify_detail=${notify_case%%|*}
    notify_remedy=${notify_case#*|}
    printf 'STATE=DEGRADED\nDETAIL=%s\n' "$notify_detail" > "$NOTIFY_HEALTH"
    chmod 0644 "$NOTIFY_HEALTH"
    rm -f -- "$NOTIFY_CAPTURE"
    assert_cmd_success "notifier accepts degradation reason: $notify_detail" \
        env PATH="$NOTIFY_BIN:/usr/bin:/bin" \
            NOID_NOTIFY_CAPTURE="$NOTIFY_CAPTURE" \
            NOID_LAN_XDP_HEALTH_FILE="$NOTIFY_HEALTH" \
            NOID_LAN_XDP_STATE_UID="$notify_uid" \
            NOID_LAN_XDP_STATE_GID="$notify_gid" \
            "$TMPDIR/noid-lan-xdp-notify"
    assert_grep_fixed "$notify_remedy" "$NOTIFY_CAPTURE" \
        "notifier selects remedy for: $notify_detail"
    if [ "$notify_detail" != sync-or-postcheck-failed ]; then
        assert_not_grep 'previous Fedora kernel' "$NOTIFY_CAPTURE" \
            "non-kernel degradation avoids rollback advice: $notify_detail"
    fi
done
printf 'STATE=DEGRADED\nDETAIL=unsupported-link-type\nEXTRA=unsafe\n' \
    > "$NOTIFY_HEALTH"
rm -f -- "$NOTIFY_CAPTURE"
assert_cmd_success "malformed health evidence is ignored at login" \
    env PATH="$NOTIFY_BIN:/usr/bin:/bin" \
        NOID_NOTIFY_CAPTURE="$NOTIFY_CAPTURE" \
        NOID_LAN_XDP_HEALTH_FILE="$NOTIFY_HEALTH" \
        NOID_LAN_XDP_STATE_UID="$notify_uid" \
        NOID_LAN_XDP_STATE_GID="$notify_gid" \
        "$TMPDIR/noid-lan-xdp-notify"
if [ -e "$NOTIFY_CAPTURE" ]; then
    _fail "malformed health evidence triggered a login notification"
else
    _pass "malformed health evidence cannot choose a misleading remedy"
fi
assert_grep_fixed 'xdpgeneric) expected_mode=generic' "$TMPDIR/noid-lan-xdp" \
    "status maps the recorded generic-XDP mode to bpftool's exact mode name"
assert_grep_fixed 'bpftool -j net show dev "$iface"' "$TMPDIR/noid-lan-xdp" \
    "status inspects both physical attachments without an ifconfig_t transition"
assert_not_grep 'ip -json -details\|tc -json -details' "$TMPDIR/noid-lan-xdp" \
    "status cannot trigger cross-domain BPF expansion through iproute2"
assert_grep_fixed '[ -r "$OBJECT" ] || die "BPF object missing or unreadable: $OBJECT"' \
    "$TMPDIR/noid-lan-xdp" \
    "sync and status diagnose an unreadable pinned object before hashing"
assert_grep_fixed '|| die "cannot hash BPF object: $OBJECT"' \
    "$TMPDIR/noid-lan-xdp" \
    "sync and status preserve an explicit object-hash failure diagnostic"
assert_grep_fixed '[ "$expected" = "$OBJECT_SHA256" ] || die "BPF object hash mismatch"' \
    "$TMPDIR/noid-lan-xdp" \
    "sync and status reject an object digest mismatch explicitly"
assert_grep_fixed 'die "cannot read local MAC for $iface"' \
    "$TMPDIR/noid-lan-xdp" \
    "interface identity reads have a defined fail-closed diagnostic"
assert_not_grep '^bootstrap()' "$TMPDIR/noid-lan-xdp" \
    "controller does not expose an incomplete policy bootstrap entry point"
assert_not_grep 'bootstrap|sync 0|1' "$TMPDIR/noid-lan-xdp" \
    "controller usage advertises only complete policy transactions"
assert_grep_fixed 'STATE_SCHEMA=2' "$TMPDIR/noid-lan-xdp" \
    "controller publishes and requires the closed state schema"
assert_grep_fixed 'MAP_SCHEMA=4' "$TMPDIR/noid-lan-xdp" \
    "controller versions reusable map layouts independently"
assert_grep_fixed "metadata=\$(stat -c '%u:%a' -- \"\$STATE_FILE\"" \
    "$TMPDIR/noid-lan-xdp" \
    "controller verifies root ownership and private mode before parsing state"
assert_grep_fixed '*) die "unknown state key"' "$TMPDIR/noid-lan-xdp" \
    "state grammar rejects undeclared fields"
assert_grep_fixed 'load_gateway_identity' "$TMPDIR/noid-lan-xdp" \
    "controller parses M04 identity through one closed loader"
assert_grep_fixed '$EXPECTED_ARP_STATE_UID:$EXPECTED_ARP_STATE_GID:644:1' \
    "$TMPDIR/noid-lan-xdp" \
    "gateway identity is ownership/mode/link-count bound"
assert_grep_fixed '$EXPECTED_ARP_STATE_UID:$EXPECTED_ARP_STATE_GID:755' \
    "$TMPDIR/noid-lan-xdp" \
    "gateway identity parent is ownership/mode bound"
assert_grep_fixed 'case "$value" in 0|1) ;;' \
    "$TMPDIR/noid-lan-xdp" \
    "kernel-pin opt-out remains a valid XDP gateway identity"
assert_grep_fixed 'gateway_state_present=1' "$TMPDIR/noid-lan-xdp" \
    "present gateway state is validated before BPF generation"
assert_grep_fixed 'if [ "$gateway_state_present" -eq 1 ]; then' \
    "$TMPDIR/noid-lan-xdp" \
    "only a validated identity seeds the gateway map"
assert_grep_fixed '[ "${#entries[@]}" -gt 0 ] || die "state contains no interface attachments"' \
    "$TMPDIR/noid-lan-xdp" \
    "an empty attachment set cannot claim an active boundary"
assert_grep_fixed '[ "${canonical_generation%/*}" = "$canonical_root" ]' \
    "$TMPDIR/noid-lan-xdp" \
    "state generation is confined to a direct canonical BPF-root child"
assert_grep_fixed 'generation=$(mktemp -d "$canonical_root/generation_XXXXXXXX")' \
    "$TMPDIR/noid-lan-xdp" \
    "fresh BPF generation names are atomically reserved"
assert_not_grep 'generation_${$}_${RANDOM}' "$TMPDIR/noid-lan-xdp" \
    "controller has no collision-prone PID/RANDOM generation allocation"
assert_grep_fixed 'PENDING_GENERATION=$generation' "$TMPDIR/noid-lan-xdp" \
    "cleanup owns a generation only after atomic creation succeeds"
assert_grep_fixed '/run/noid-privacy/lan-xdp.lock' "$TMPDIR/noid-lan-xdp" \
    "controller lock stays inside the NoID Privacy root runtime boundary"
assert_grep_fixed 'umask 077' "$TMPDIR/noid-lan-xdp" \
    "controller creates its lock and state with root-private defaults"
assert_grep_fixed '"flags": 0,' "$TMPDIR/noid-lan-xdp" \
    "map reuse checks flags as well as type, sizes and capacity"
assert_grep_fixed 'generation_program_identities "$old_generation"' \
    "$TMPDIR/noid-lan-xdp" \
    "rollback source includes validated pinned XDP and TC programs"
assert_grep_fixed 'pinned "$generation/progs/noid_lan_xdp"' "$TMPDIR/noid-lan-xdp" \
    "the XDP program identity is resolved through its exact pin path"
assert_grep_fixed 'pinned "$generation/progs/noid_lan_egress"' "$TMPDIR/noid-lan-xdp" \
    "the TC program identity is resolved through its exact pin path"
assert_grep_fixed 'not re.fullmatch(r"[0-9a-f]{16}", tag)' "$TMPDIR/noid-lan-xdp" \
    "a resolved pin must still present a well-formed program tag"
assert_grep_fixed 'restore_old_generation "$old_generation" "${old_entries[@]}"' \
    "$TMPDIR/noid-lan-xdp" \
    "rollback selects modes from validated old state rather than new attaches"
assert_grep_fixed 'row.get("kind") == "clsact/egress"' "$TMPDIR/noid-lan-xdp" \
    "status binds the pinned tracker to the exact TC egress hook"
assert_grep_fixed 'row.get("id") == tc_id' "$TMPDIR/noid-lan-xdp" \
    "status binds the live TC hook to the pinned program identity"
assert_grep_fixed 'len(xdp_matches) != 1 or len(tc_matches) != 1' \
    "$TMPDIR/noid-lan-xdp" \
    "status requires one exact XDP and TC attachment match"
assert_grep_fixed 'returns TC_ACT_OK on every exit' "$TMPDIR/noid-lan-xdp" \
    "status rationale scopes the load-bearing TC postcondition"
assert_not_grep 'type, name, ID and tag\|type, name, tag and program ID' \
    "$PROJECT_ROOT/overrides/noid-lan-xdp/README.md" \
    "XDP documentation does not claim an unbound program tag"
assert_grep_fixed 'or an outbound-approved exact LAN peer binding' \
    "$PROJECT_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.c" \
    "BPF contract documents the peer-authorized correlated-reply path"
assert_grep_fixed "A peer cannot initiate an ICMP echo request;" \
    "$PROJECT_ROOT/overrides/noid-lan-xdp/README.md" \
    "XDP documentation scopes peer-initiated traffic to expressible selectors"
assert_grep_fixed 'generic XDP' \
    "$PROJECT_ROOT/docs/hardware-network-compatibility.md" \
    "hardware documentation covers the driver-independent fallback"
assert_grep_fixed 'Not release-qualified' \
    "$PROJECT_ROOT/docs/hardware-network-compatibility.md" \
    "stacked and non-default paths are not overclaimed"
assert_not_grep 'LEARNING_WINDOW_NS\|noid_xdp_learning_v4\|learn-open\|learn-close' \
    "$TMPDIR/noid-lan-xdp" "controller contains no obsolete dynamic ARP admission"
assert_grep_fixed 'for net_path in "$SYS_CLASS_NET"/*' "$TMPDIR/noid-lan-topology-refresh.sh" \
    "topology refresh enumerates every kernel-backed physical NIC"
assert_grep_fixed '[ -d "$net_path/device" ] || continue' "$TMPDIR/noid-lan-topology-refresh.sh" \
    "topology refresh excludes virtual/tunnel interfaces"
assert_not_grep 'device status 2>/dev/null || true' "$TMPDIR/noid-lan-topology-refresh.sh" \
    "NetworkManager failure cannot empty the topology sets"
assert_not_grep '--list-ingress-zones 2>/dev/null || true' "$TMPDIR/noid-lan-topology-refresh.sh" \
    "firewalld query failure cannot imitate the explicit global opt-out"
assert_grep_fixed 'for net_path in "$SYS_CLASS_NET"/*' \
    "$TMPDIR/noid-firewalld-zone-enforce.sh" \
    "firstboot enumerates every kernel-backed network interface"
assert_grep_fixed 'PHYSICAL_IFACES+=("$iface")' \
    "$TMPDIR/noid-firewalld-zone-enforce.sh" \
    "firstboot retains every hardware-backed physical interface"
assert_grep_fixed 'firewall-cmd --permanent --zone=drop --change-interface="$iface"' \
    "$TMPDIR/noid-firewalld-zone-enforce.sh" \
    "firstboot stages every physical interface in the permanent drop zone"
assert_grep_fixed 'firewall-cmd --zone=drop --change-interface="$iface"' \
    "$TMPDIR/noid-firewalld-zone-enforce.sh" \
    "firstboot repairs a conflicting runtime profile assignment"
assert_not_grep_extended 'proton\*|tun\*|tap\*|wg\*' \
    "$TMPDIR/noid-firewalld-zone-enforce.sh" \
    "hardware-backed detection is provider-neutral"
reload_count=$(grep -c '^firewall-cmd --reload$' \
    "$TMPDIR/noid-firewalld-zone-enforce.sh" || true)
assert_eq 1 "$reload_count" \
    "firstboot batches SSH, policy and NIC mutations behind one reload"
assert_not_grep '--remove-interface=.*|| true' \
    "$TMPDIR/noid-firewalld-zone-enforce.sh" \
    "zone transition failure is not swallowed"
assert_not_grep 'firewall-cmd --reload 2>/dev/null || true' \
    "$TMPDIR/noid-firewalld-zone-enforce.sh" \
    "firstboot firewall reload failure is visible"
assert_grep_fixed 'CRITICAL: ssh service remains allowed in drop zone' \
    "$TMPDIR/noid-firewalld-zone-enforce.sh" \
    "firstboot verifies the SSH deny postcondition"
assert_grep_fixed 'CRITICAL: ssh service remains allowed in libvirt NAT zone' \
    "$TMPDIR/noid-firewalld-zone-enforce.sh" \
    "firstboot verifies the NAT guest-to-host SSH deny postcondition"
ssh_strip_line=$(grep -n 'remove-service=ssh' "$TMPDIR/noid-firewalld-zone-enforce.sh" | head -1 | cut -d: -f1)
physical_scan_line=$(grep -n '^declare -a PHYSICAL_IFACES=()$' \
    "$TMPDIR/noid-firewalld-zone-enforce.sh" | head -1 | cut -d: -f1 || true)
if [ -n "$ssh_strip_line" ] && [ -n "$physical_scan_line" ] \
        && [ "$ssh_strip_line" -lt "$physical_scan_line" ]; then
    _pass "SSH is stripped before NIC discovery (no-NIC installs stay closed)"
else
    _fail "SSH strip must run before NIC discovery"
fi
no_nic_line=$(grep -n 'no physical interface present' \
    "$TMPDIR/noid-firewalld-zone-enforce.sh" | head -1 | cut -d: -f1 || true)
if [ -n "$no_nic_line" ] && [ -n "$ssh_strip_line" ] \
        && [ "$ssh_strip_line" -lt "$no_nic_line" ]; then
    _pass "no-NIC branch cannot bypass the SSH deny transaction"
else
    _fail "no-NIC branch cannot bypass the SSH deny transaction"
fi
assert_grep_fixed 'firewall-offline-cmd --zone=drop --remove-service-from-zone=ssh' \
    "$KS_FILE" "offline zone edit uses the non-lokkit F44 option"
assert_grep_fixed 'firewall-offline-cmd --zone=libvirt --remove-service-from-zone=ssh' \
    "$KS_FILE" "offline Libvirt NAT zone edit closes guest-to-host SSH"
assert_grep_fixed 'firewall-offline-cmd --policy=libvirt-to-host --remove-service-from-policy=ssh' \
    "$KS_FILE" "offline policy edit uses the non-lokkit F44 option"
assert_not_grep 'firewall-offline-cmd --zone=drop --remove-service=ssh' \
    "$KS_FILE" "offline zone edit does not mix the legacy lokkit option"
assert_not_grep 'firewall-offline-cmd --zone=libvirt --remove-service=ssh' \
    "$KS_FILE" "offline Libvirt zone edit does not mix the legacy lokkit option"
assert_not_grep 'firewall-offline-cmd --policy=libvirt-to-host --remove-service=ssh' \
    "$KS_FILE" "offline policy edit does not mix the legacy lokkit option"
if command -v firewall-offline-cmd >/dev/null 2>&1; then
    offline_help=$(firewall-offline-cmd --help 2>&1)
    if grep -q -- '--remove-service-from-zone=<service>' <<<"$offline_help" \
        && grep -q -- '--remove-service-from-policy=<service>' <<<"$offline_help"; then
        _pass "installed firewall-offline-cmd documents both selected removal options"
    else
        _fail "installed firewall-offline-cmd lacks a selected removal option"
    fi
fi
assert_grep_fixed 'declare -a EXPECTED_HOSTV6_RULES=(' \
    "$TMPDIR/noid-firewalld-zone-enforce.sh" \
    "firstboot defines the exact six-rule IPv6 contract"
assert_grep_fixed 'for scope in runtime permanent; do' \
    "$TMPDIR/noid-firewalld-zone-enforce.sh" \
    "firstboot verifies both loaded and permanent IPv6 rule sets"
assert_grep_fixed 'rule count is $rule_count, expected 6' \
    "$TMPDIR/noid-firewalld-zone-enforce.sh" \
    "firstboot rejects extra or missing IPv6 rules"
assert_grep_fixed 'require_policy_value -15000 priority' \
    "$TMPDIR/noid-firewalld-zone-enforce.sh" \
    "firstboot verifies the exact IPv6 policy priority"
assert_grep_fixed 'firewall-offline-cmd --check-config' "$KS_FILE" \
    "compose gate validates the complete permanent firewalld configuration"
assert_grep_fixed 'StrictForwardPorts=yes' "$KS_FILE" \
    "compose gate pins strict external-DNAT handling"
assert_grep_fixed 'verify_fail()' "$KS_FILE" \
    "compose verification has a single fail-closed error path"
assert_grep_fixed 'matchpathcon -V "$script"' "$KS_FILE" \
    "compose gate verifies executable SELinux labels"
assert_grep_fixed 'installed LAN-XDP object digest drift' "$KS_FILE" \
    "compose gate verifies the exact deployed BPF bytes"
assert_not_grep '⚠ v2 artifact' "$KS_FILE" \
    "retired security artifacts fail the compose instead of warning"
assert_grep_fixed 'nft -c -f "$batch"' "$TMPDIR/noid-lan-topology-refresh.sh" \
    "topology refresh validates the complete atomic batch"
# The helper compares `stat -c %F` against the English literal `directory`, and
# systemd hands services the installation's LANG. Without an exported C locale
# the same check that passes in the en_US.UTF-8 compose fail-closes in
# milliseconds on every localized installation, before firewalld or nft is
# reached — the guard is a hard NetworkManager requirement, so that removes the
# network entirely. Keep both halves: the assignment and the export.
assert_grep_fixed 'LC_ALL=C.UTF-8' "$TMPDIR/noid-lan-topology-refresh.sh" \
    "topology refresh pins the parse locale for localized installations"
assert_grep_fixed 'export LC_ALL' "$TMPDIR/noid-lan-topology-refresh.sh" \
    "the pinned locale reaches the stat/nft child processes"
# systemd's console message names `systemctl status`, which only shows this
# unit's own stdout/stderr. A logger-only diagnostic leaves that command empty.
assert_grep_fixed 'printf '"'"'%s: %s\n'"'"' "$LOG_TAG" "$*" >&2' \
    "$TMPDIR/noid-lan-topology-refresh.sh" \
    "every fatal topology diagnostic also reaches the unit journal"
assert_not_grep 'logger -t "\$LOG_TAG" "FAILED:' \
    "$TMPDIR/noid-lan-topology-refresh.sh" \
    "no fatal path logs to the syslog identifier alone"
assert_grep_fixed 'fail "FAILED: $xdp_message"' \
    "$TMPDIR/noid-lan-topology-refresh.sh" \
    "required XDP degradation reaches both diagnostic sinks"
assert_eq 3 \
    "$(grep -Fc 'fail "FAILED: $xdp_message"' \
        "$TMPDIR/noid-lan-topology-refresh.sh")" \
    "all three required-XDP degradation exits use the dual-sink reporter"
assert_grep_fixed 'base topology table rejected in check mode' \
    "$TMPDIR/noid-lan-topology-refresh.sh" \
    "the base-table load reports nft's own rejection instead of a bare set -e exit"
assert_grep_fixed 'pre-up|up|down|dhcp4-change|dhcp6-change|reapply' \
    "$TMPDIR/noid-lan-topology-dispatcher.sh"
assert_grep_fixed 'SYS_CLASS_NET="${NOID_SYS_CLASS_NET:-/sys/class/net}"' \
    "$TMPDIR/noid-lan-topology-dispatcher.sh" \
    "topology dispatcher classifies the event against kernel-backed devices"
assert_grep_fixed '[ ! -d "$SYS_CLASS_NET/$IFACE/device" ]' \
    "$TMPDIR/noid-lan-topology-dispatcher.sh" \
    "virtual VPN, tunnel and dummy interface events take the cheap path"
assert_grep_fixed 'get element inet noid_lan_topology physical_ifaces' \
    "$TMPDIR/noid-lan-topology-dispatcher.sh" \
    "down events retain a disappearing physical interface from committed policy"
assert_not_grep '--xdp-unchanged' "$TMPDIR/noid-lan-topology-dispatcher.sh" \
    "every retained physical event still performs the full XDP postchecked refresh"

# Functional event classifier. NetworkManager serializes ordinary dispatcher
# scripts, so a virtual-interface false positive would multiply the full BPF
# generation cost across every VPN connection cycle.
dispatch_root="$TMPDIR/topology-dispatch"
mkdir -p "$dispatch_root/sys/physical0/device" \
    "$dispatch_root/sys/virtual0" "$dispatch_root/sys/stale0" \
    "$dispatch_root/bin"
cat > "$dispatch_root/bin/refresh" <<'DISPATCH_REFRESH_FIXTURE_EOF'
#!/bin/bash
set -euo pipefail
printf 'called\n' >> "${NOID_TEST_CALLS:?}"
DISPATCH_REFRESH_FIXTURE_EOF
cat > "$dispatch_root/bin/nft" <<'DISPATCH_NFT_FIXTURE_EOF'
#!/bin/bash
set -euo pipefail
case "${NOID_TEST_NFT_MODE:-missing}" in
    missing)
        exit 1
        ;;
    member)
        case "${1:-}" in list|get) exit 0 ;; *) exit 2 ;; esac
        ;;
    nonmember)
        case "${1:-}" in list) exit 0 ;; get) exit 1 ;; *) exit 2 ;; esac
        ;;
    *) exit 2 ;;
esac
DISPATCH_NFT_FIXTURE_EOF
chmod 0755 "$dispatch_root/bin/refresh" "$dispatch_root/bin/nft"
: > "$dispatch_root/calls"

assert_cmd_success "hardware-backed up event performs a full topology refresh" \
    env NOID_LAN_TOPOLOGY_REFRESH="$dispatch_root/bin/refresh" \
    NOID_SYS_CLASS_NET="$dispatch_root/sys" NOID_NFT_BIN="$dispatch_root/bin/nft" \
    NOID_TEST_CALLS="$dispatch_root/calls" NOID_TEST_NFT_MODE=missing \
    bash "$TMPDIR/noid-lan-topology-dispatcher.sh" physical0 up
assert_eq "1" "$(wc -l < "$dispatch_root/calls")" \
    "physical event invokes exactly one topology transaction"

assert_cmd_success "virtual up event exits without a topology refresh" \
    env NOID_LAN_TOPOLOGY_REFRESH="$dispatch_root/bin/refresh" \
    NOID_SYS_CLASS_NET="$dispatch_root/sys" NOID_NFT_BIN="$dispatch_root/bin/nft" \
    NOID_TEST_CALLS="$dispatch_root/calls" NOID_TEST_NFT_MODE=missing \
    bash "$TMPDIR/noid-lan-topology-dispatcher.sh" virtual0 up
assert_eq "1" "$(wc -l < "$dispatch_root/calls")" \
    "virtual activation cannot regenerate the physical XDP boundary"

assert_cmd_success "nonmember virtual down event exits without refresh" \
    env NOID_LAN_TOPOLOGY_REFRESH="$dispatch_root/bin/refresh" \
    NOID_SYS_CLASS_NET="$dispatch_root/sys" NOID_NFT_BIN="$dispatch_root/bin/nft" \
    NOID_TEST_CALLS="$dispatch_root/calls" NOID_TEST_NFT_MODE=nonmember \
    bash "$TMPDIR/noid-lan-topology-dispatcher.sh" virtual0 down
assert_eq "1" "$(wc -l < "$dispatch_root/calls")" \
    "ordinary virtual teardown cannot regenerate the physical XDP boundary"

assert_cmd_success "disappearing committed physical down event refreshes" \
    env NOID_LAN_TOPOLOGY_REFRESH="$dispatch_root/bin/refresh" \
    NOID_SYS_CLASS_NET="$dispatch_root/sys" NOID_NFT_BIN="$dispatch_root/bin/nft" \
    NOID_TEST_CALLS="$dispatch_root/calls" NOID_TEST_NFT_MODE=member \
    bash "$TMPDIR/noid-lan-topology-dispatcher.sh" stale0 down
assert_eq "2" "$(wc -l < "$dispatch_root/calls")" \
    "committed physical teardown cannot leave stale topology state"

assert_cmd_success "missing topology table triggers conservative down recovery" \
    env NOID_LAN_TOPOLOGY_REFRESH="$dispatch_root/bin/refresh" \
    NOID_SYS_CLASS_NET="$dispatch_root/sys" NOID_NFT_BIN="$dispatch_root/bin/nft" \
    NOID_TEST_CALLS="$dispatch_root/calls" NOID_TEST_NFT_MODE=missing \
    bash "$TMPDIR/noid-lan-topology-dispatcher.sh" virtual0 down
assert_eq "3" "$(wc -l < "$dispatch_root/calls")" \
    "missing committed topology state is repaired rather than silently skipped"

assert_cmd_failure "unsafe interface name is rejected" \
    env NOID_LAN_TOPOLOGY_REFRESH="$dispatch_root/bin/refresh" \
    NOID_SYS_CLASS_NET="$dispatch_root/sys" NOID_NFT_BIN="$dispatch_root/bin/nft" \
    NOID_TEST_CALLS="$dispatch_root/calls" NOID_TEST_NFT_MODE=missing \
    bash "$TMPDIR/noid-lan-topology-dispatcher.sh" ../escape up
assert_eq "3" "$(wc -l < "$dispatch_root/calls")" \
    "unsafe interface input cannot select a sysfs path or invoke refresh"
assert_grep_fixed 'flock --close --exclusive "$LOCK_FILE"' \
    "$TMPDIR/noid-lan-topology-refresh.sh" \
    "concurrent refreshes serialize without leaking the lock descriptor"
assert_grep_fixed '/run/noid-privacy/lan-topology-refresh.lock' \
    "$TMPDIR/noid-lan-topology-refresh.sh" \
    "topology lock stays inside the NoID Privacy root runtime boundary"
assert_grep_fixed 'umask 077' "$TMPDIR/noid-lan-topology-refresh.sh" \
    "topology refresh creates its transaction lock root-private"
assert_grep_fixed 'NOID_LAN_TOPOLOGY_LOCK_HELD=1 /bin/bash "$0" "$@"' \
    "$TMPDIR/noid-lan-topology-refresh.sh" \
    "topology transaction re-executes once under the parent-held lock"
assert_grep_fixed 'valid_global_allow_marker()' \
    "$TMPDIR/noid-lan-topology-refresh.sh" \
    "global widening requires one closed empty marker identity"
assert_grep_fixed 'validate_global_runtime_state "$state"' \
    "$TMPDIR/noid-lan-topology-refresh.sh" \
    "published global state is byte- and metadata-postchecked"
assert_grep_fixed 'exact_permanent_neighbour_mac()' \
    "$TMPDIR/noid-lan-topology-refresh.sh" \
    "restored M05 peer pins use one exact kernel postcondition"
assert_grep_fixed 'restored LAN peer binding failed its exact kernel postcondition' \
    "$TMPDIR/noid-lan-topology-refresh.sh" \
    "peer-pin postcheck failure is an explicit topology failure"
assert_grep_fixed '^[a-zA-Z0-9_.-]{1,15}$' \
    "$TMPDIR/noid-lan-topology-refresh.sh" \
    "topology identities respect Linux IFNAMSIZ"
assert_not_grep 'ReadWritePaths=.* /run$' "$KS_FILE" \
    "topology units no longer expose all of /run as writable"
assert_not_grep 'exec 9>"$LOCK_FILE"\|flock 9' \
    "$TMPDIR/noid-lan-topology-refresh.sh" \
    "nft/ip children cannot inherit the historical fd 9 lock"
assert_grep_fixed '/etc/systemd/system/noid-lan-topology-hotplug@.service' "$KS_FILE" \
    "late net-device hotplug has a dedicated refresh oneshot"
assert_grep_fixed '/etc/udev/rules.d/70-noid-lan-topology-hotplug.rules' "$KS_FILE" \
    "late net-device hotplug is wired through udev"
assert_grep_fixed 'ENV{SYSTEMD_WANTS}+="noid-lan-topology-hotplug@%k.service"' "$KS_FILE" \
    "udev schedules a per-event refresh without a long-running RUN command"
assert_grep_fixed 'TEST=="device"' "$KS_FILE" \
    "udev excludes virtual interfaces before scheduling a physical refresh"
assert_grep_fixed 'ExecCondition=/usr/bin/test -d /sys/class/net/%I/device' "$KS_FILE" \
    "hotplug service rechecks that its instance is hardware-backed"
assert_grep_fixed 'pre-up.d/30-noid-lan-topology-guard' "$KS_FILE" \
    "topology guard is registered in NetworkManager pre-up.d"
assert_grep_fixed 'no-wait.d/30-noid-lan-topology-guard' "$KS_FILE" \
    "ordinary topology refresh uses NetworkManager's parallel no-wait path"
assert_grep_fixed 'ln -sfnT no-wait.d/30-noid-lan-topology-guard' "$KS_FILE" \
    "normal topology entry points exactly at its no-wait copy"
assert_grep_fixed 'cmp -s' "$KS_FILE" \
    "awaited and no-wait topology copies have a byte-parity postcondition"
assert_grep_fixed 'Requires=firewalld.service' "$KS_FILE" \
    "topology service cannot run against failed firewalld state"
assert_grep_fixed 'Requires=noid-lan-topology-guard.service' "$KS_FILE" \
    "NetworkManager activation is blocked if the initial topology guard fails"
# --- block-lan-out.xml zones ------------------------------------------------
# F44 firewalld validator rejects mixed HOST+libvirt ingress.
# This heredoc carries HOST only; the libvirt counterpart is generated at runtime
# via cp+sed (block-lan-out-vms.xml). Verify the heredoc has HOST + that the
# %post block contains the cp+sed split logic + that the source ks references
# block-lan-out-vms.xml as the runtime-derived target.
assert_grep_fixed '<ingress-zone name="HOST"/>'    "$TMPDIR/block-lan-out.xml"
assert_grep_fixed '<egress-zone name="drop"/>'     "$TMPDIR/block-lan-out.xml"
assert_not_grep   '<ingress-zone name="libvirt"/>' "$TMPDIR/block-lan-out.xml" "libvirt ingress NOT in HOST policy heredoc (split per F44 validator)"
assert_grep_fixed 'block-lan-out-vms.xml' "$KS_FILE" "block-lan-out-vms.xml referenced (runtime derive when libvirt zone exists)"
assert_grep_extended 'cp /etc/firewalld/policies/block-lan-out\.xml' "$KS_FILE" "cp source for split"

# --- block-lan-out LAN-discovery ports --------------------------------------
for port in 137 138 139 445 1900 3702 5353 5355 5357; do
    assert_grep_extended "port=\"${port}\"" "$TMPDIR/block-lan-out.xml" "LAN-discovery port ${port}"
done

# --- block-lan-out RFC1918 destinations -------------------------------------
assert_grep_fixed 'address="10.0.0.0/8"'      "$TMPDIR/block-lan-out.xml"
assert_grep_fixed 'address="172.16.0.0/12"'   "$TMPDIR/block-lan-out.xml"
assert_grep_fixed 'address="192.168.0.0/16"'  "$TMPDIR/block-lan-out.xml"
assert_grep_fixed 'address="fe80::/10"'       "$TMPDIR/block-lan-out.xml"
assert_grep_fixed 'address="ff00::/8"'        "$TMPDIR/block-lan-out.xml"
assert_grep_fixed 'address="fc00::/7"'        "$TMPDIR/block-lan-out.xml"

# --- allow-host-ipv6 hardened override: exactly 6 icmp-types ---------------
icmp_count=$(grep -c '<icmp-type ' "$TMPDIR/allow-host-ipv6.xml" 2>/dev/null || true)
icmp_count=${icmp_count:-0}
assert_eq "6" "$icmp_count" "allow-host-ipv6.xml has 6 icmp-types (4xMLD + 2xNDP)"

# --- allow-host-ipv6: RA + redirect ABSENT (defense-in-depth) ---------------
assert_not_grep 'icmp-type name="router-advertisement"' "$TMPDIR/allow-host-ipv6.xml"
assert_not_grep 'icmp-type name="redirect"'             "$TMPDIR/allow-host-ipv6.xml"

# --- 03-vpn-zone.conf is a no-op placeholder (NM 1.54+ rejection) -
# Actual VPN-zone enforcement lives in Module 06 dispatcher 50-vpn-zone-enforce.
# Just verify the placeholder is shipped and references the dispatcher migration
# so anyone grepping NetworkManager config lands on the migration note.
assert_grep_fixed 'dispatcher.d/50-vpn-zone-enforce' "$TMPDIR/03-vpn-zone.conf" \
    "placeholder references Module 06 dispatcher (NM 1.54+ migration note)"

# --- runtime verification present in enforce.sh ----------------------------
assert_grep_fixed '--info-policy=allow-host-ipv6' \
    "$TMPDIR/noid-firewalld-zone-enforce.sh"
assert_grep_fixed '--policy=allow-host-ipv6 --list-rich-rules' \
    "$TMPDIR/noid-firewalld-zone-enforce.sh" \
    "firstboot policy verification uses the firewalld rich-rule CLI"
assert_not_grep 'firewall-cmd.*--list-rules' "$TMPDIR/noid-firewalld-zone-enforce.sh" \
    "firstboot policy verification never calls the nonexistent generic rule CLI"

# --- topology refresh functional test with deterministic command doubles ----
# Exercise the extracted production script end-to-end without touching the
# host firewall. Two addresses in each family deliberately share one prefix;
# duplicate durable exceptions must also collapse to one nft element.
mkdir -p "$TMPDIR/mock-bin" "$TMPDIR/mock-sys/test0/device" \
    "$TMPDIR/mock-sys/raw0/device"
printf '%s\n' 1 > "$TMPDIR/mock-sys/test0/type"
printf '%s\n' 65534 > "$TMPDIR/mock-sys/raw0/type"

cat > "$TMPDIR/mock-bin/nmcli" <<'MOCK_NMCLI_EOF'
#!/bin/bash
set -eu
case "$*" in
    *'device status'*) printf '%s\n' 'test0:ethernet:connected' ;;
    *) exit 1 ;;
esac
MOCK_NMCLI_EOF

cat > "$TMPDIR/mock-bin/ip" <<'MOCK_IP_EOF'
#!/bin/bash
set -eu
printf '%s\n' "$*" >> "$IP_CALLS"
case "$*" in
    '-o -4 addr show dev test0 scope global')
        printf '%s\n' \
            '2: test0 inet 198.19.7.10/24 scope global test0' \
            '2: test0 inet 198.19.7.11/24 scope global secondary test0'
        ;;
    '-o -6 addr show dev test0 scope global')
        if [ "${MOCK_NO_IPV6:-0}" != 1 ]; then
            printf '%s\n' \
                '2: test0 inet6 2001:db8:7::10/64 scope global' \
                '2: test0 inet6 2001:db8:7::11/64 scope global secondary'
        fi
        ;;
    '-o -4 addr show dev raw0 scope global'|\
    '-o -6 addr show dev raw0 scope global')
        exit 0
        ;;
    'neigh replace 198.19.7.20 lladdr 02:00:00:00:00:01 dev test0 nud permanent'|\
    'neigh replace 198.19.7.21 lladdr 02:00:00:00:00:02 dev test0 nud permanent'|\
    'neigh replace 198.19.7.22 lladdr 02:00:00:00:00:03 dev test0 nud permanent')
        exit 0
        ;;
    '-4 neigh show to 198.19.7.20 dev test0')
        peer_mac=02:00:00:00:00:01
        [ "${MOCK_NEIGH_MISMATCH:-0}" != 1 ] \
            || peer_mac=02:00:00:00:00:22
        printf '%s\n' \
            "198.19.7.20 dev test0 lladdr $peer_mac PERMANENT"
        ;;
    '-4 neigh show to 198.19.7.21 dev test0')
        printf '%s\n' \
            '198.19.7.21 dev test0 lladdr 02:00:00:00:00:02 PERMANENT'
        ;;
    '-4 neigh show to 198.19.7.22 dev test0')
        printf '%s\n' \
            '198.19.7.22 dev test0 lladdr 02:00:00:00:00:03 PERMANENT'
        ;;
    *) exit 1 ;;
esac
MOCK_IP_EOF

cat > "$TMPDIR/mock-bin/firewall-cmd" <<'MOCK_FIREWALL_EOF'
#!/bin/bash
set -eu
case "$*" in
    *'--list-ingress-zones'*)
        [ "${MOCK_GLOBAL_ALLOW:-0}" = 1 ] || printf '%s\n' 'HOST'
        ;;
    *) exit 1 ;;
esac
MOCK_FIREWALL_EOF

cat > "$TMPDIR/policy-exporter" <<'MOCK_POLICY_EOF'
#!/bin/bash
set -eu
[ "${1:-}" = --export-policy ] || exit 2
[ "${MOCK_POLICY_EMPTY:-0}" != 1 ] || exit 0
exclude=''
if [ "${2:-}" = --exclude ]; then
    [ "$#" -eq 3 ] || exit 2
    exclude=$3
elif [ "$#" -ne 1 ]; then
    exit 2
fi
[ "$exclude" = 198.19.7.20 ] || printf 'test0\t198.19.7.20\t02:00:00:00:00:01\toutbound\tnone\t0\t0\n'
[ "$exclude" = 198.19.7.21 ] || printf 'test0\t198.19.7.21\t02:00:00:00:00:02\tinbound\ttcp\t8443\t8443\n'
[ "$exclude" = 198.19.7.22 ] || printf 'test0\t198.19.7.22\t02:00:00:00:00:03\tboth\tudp\t5300\t5301\n'
[ "${MOCK_POLICY_RAW:-0}" != 1 ] \
    || printf 'raw0\t198.19.7.23\t02:00:00:00:00:03\toutbound\tnone\t0\t0\n'
MOCK_POLICY_EOF

cat > "$TMPDIR/xdp-controller" <<'MOCK_XDP_EOF'
#!/bin/bash
set -eu
printf 'xdp %s\n' "$*" >> "$XDP_CALLS"
printf 'xdp %s\n' "$*" >> "$EVENT_CALLS"
exit "${MOCK_XDP_RC:-0}"
MOCK_XDP_EOF

cat > "$TMPDIR/mock-bin/nft" <<'MOCK_NFT_EOF'
#!/bin/bash
set -eu
printf '%s\n' "$*" >> "$NFT_CALLS"
printf 'nft %s\n' "$*" >> "$EVENT_CALLS"
case "${1:-}" in
    list) exit 0 ;;
    -c) [ "${2:-}" = '-f' ] && [ -r "${3:-}" ] ;;
    -f) cp -- "${2:-}" "$NFT_CAPTURE" ;;
    *) exit 1 ;;
esac
MOCK_NFT_EOF

cat > "$TMPDIR/mock-bin/logger" <<'MOCK_LOGGER_EOF'
#!/bin/bash
exit 0
MOCK_LOGGER_EOF
chmod 0755 "$TMPDIR/mock-bin/"*
chmod 0755 "$TMPDIR/policy-exporter" "$TMPDIR/xdp-controller"

# This host intentionally mounts /tmp noexec. Export shell-function wrappers
# so the production script can invoke the command doubles through bash while
# still exercising its normal command names and command -v checks.
MOCK_BIN="$TMPDIR/mock-bin"
# shellcheck disable=SC2317,SC2329  # exported; invoked in the child production shell
nmcli() { bash "$MOCK_BIN/nmcli" "$@"; }
# shellcheck disable=SC2317,SC2329  # exported; invoked in the child production shell
ip() { bash "$MOCK_BIN/ip" "$@"; }
# shellcheck disable=SC2317,SC2329  # exported; invoked in the child production shell
nft() { bash "$MOCK_BIN/nft" "$@"; }
# shellcheck disable=SC2317,SC2329  # exported; invoked in the child production shell
logger() { bash "$MOCK_BIN/logger" "$@"; }
# shellcheck disable=SC2317,SC2329  # exported; selectively injects publication failure.
mv() {
    local target="${*: -1}"
    if [ -n "${MOCK_FAIL_MV_TARGET:-}" ] \
       && [ "$target" = "$MOCK_FAIL_MV_TARGET" ]; then
        return 70
    fi
    command mv "$@"
}
# shellcheck disable=SC2317,SC2329  # exported; invoked in the child production shell
function firewall-cmd() { bash "$MOCK_BIN/firewall-cmd" "$@"; }
export MOCK_BIN
export -f nmcli ip nft logger mv
export -f -- firewall-cmd

refresh_rc=0
env PATH="/usr/bin:/bin" \
    NOID_SYS_CLASS_NET="$TMPDIR/mock-sys" \
    NOID_LAN_TOPOLOGY_NFT_FILE="$TMPDIR/noid-lan-topology.nft" \
    NOID_LAN_TOPOLOGY_LOCK_FILE="$TMPDIR/topology-refresh.lock" \
    NOID_LAN_POLICY_EXPORTER="$TMPDIR/policy-exporter" \
    NOID_LAN_GLOBAL_ALLOW_MARKER="$TMPDIR/global-allow.marker" \
    NOID_LAN_GLOBAL_RUNTIME_STATE="$TMPDIR/global-runtime.state" \
    NOID_LAN_XDP_CONTROLLER="$TMPDIR/xdp-controller" \
    NOID_LAN_XDP_HEALTH_FILE="$TMPDIR/xdp-health.state" \
    NFT_CAPTURE="$TMPDIR/captured.nft" NFT_CALLS="$TMPDIR/nft.calls" \
    XDP_CALLS="$TMPDIR/xdp.calls" EVENT_CALLS="$TMPDIR/event.calls" \
    IP_CALLS="$TMPDIR/ip.calls" \
    bash -x "$TMPDIR/noid-lan-topology-refresh.sh" \
    >"$TMPDIR/refresh.log" 2>&1 || refresh_rc=$?
if [ "$refresh_rc" -eq 0 ]; then
    _pass "topology refresh builds a complete atomic batch"
else
    sed 's/^/    /' "$TMPDIR/refresh.log" >&2
    _fail "topology refresh builds a complete atomic batch (rc=$refresh_rc)"
fi
assert_eq "1" "$(grep -Fc 'connected_v4 { 198.19.7.0/24 }' "$TMPDIR/captured.nft")" \
    "duplicate IPv4 addresses produce one connected prefix"
assert_eq "1" "$(grep -Fc 'connected_v6 { 2001:db8:7::/64 }' "$TMPDIR/captured.nft")" \
    "duplicate IPv6 addresses produce one connected prefix"
assert_eq "1" "$(grep -Fc 'allowed_v4 { 198.19.7.20 }' "$TMPDIR/captured.nft")" \
    "outbound-only peer is admitted to guest-originated LAN flows"
assert_eq "1" "$(grep -Fc 'allowed_v4 { 198.19.7.22 }' "$TMPDIR/captured.nft")" \
    "both-direction peer includes guest-originated LAN flows"
assert_not_grep 'allowed_v4 { 198.19.7.21 }' "$TMPDIR/captured.nft" \
    "inbound-only peer cannot authorize guest-originated LAN flows"
assert_not_grep 'add element inet noid_lan_topology allowed_v6' \
    "$TMPDIR/captured.nft" "IPv6 per-peer admission remains unsupported"
assert_grep_fixed 'outbound_peers_v4 { 198.19.7.20 }' "$TMPDIR/captured.nft" \
    "outbound-only peer can return only correlated flows"
assert_grep_fixed 'outbound_peers_v4 { 198.19.7.22 }' "$TMPDIR/captured.nft" \
    "both-direction peer includes correlated return flows"
assert_grep_fixed 'inbound_peers_v4 { 198.19.7.21 }' "$TMPDIR/captured.nft" \
    "inbound-only peer is published separately"
assert_grep_fixed 'inbound_peers_v4 { 198.19.7.22 }' "$TMPDIR/captured.nft" \
    "both-direction peer is published to inbound enforcement"
assert_grep_fixed 'inbound_tcp_v4 { "test0" . 198.19.7.21 . 8443 }' \
    "$TMPDIR/captured.nft" "single TCP port remains an exact inbound selector"
assert_grep_fixed 'inbound_udp_v4 { "test0" . 198.19.7.22 . 5300-5301 }' \
    "$TMPDIR/captured.nft" "UDP range remains an exact inbound selector"
assert_eq "1" "$(grep -Fc 'hook ingress device "test0"' "$TMPDIR/captured.nft")" \
    "one physical ingress Layer-2 hook is generated"
assert_eq "1" "$(grep -Fc 'hook egress device "test0"' "$TMPDIR/captured.nft")" \
    "one physical egress Layer-2 hook is generated"
assert_not_grep 'hook ingress device "raw0"' "$TMPDIR/captured.nft" \
    "Raw-IP physical link receives no Ethernet ingress hook"
assert_not_grep 'hook egress device "raw0"' "$TMPDIR/captured.nft" \
    "Raw-IP physical link receives no Ethernet egress hook"
assert_grep_fixed 'physical_ifaces { "raw0" }' "$TMPDIR/captured.nft" \
    "Raw-IP physical link remains covered by L3 topology and WAN-strict"
assert_grep_fixed 'lan_guard_ifaces { "test0" }' "$TMPDIR/captured.nft" \
    "default BLOCKED mode protects the Ethernet interface from source-port misuse"
assert_grep_fixed 'lan_guard_ifaces { "raw0" }' "$TMPDIR/captured.nft" \
    "default BLOCKED mode protects the Raw-IP L3 interface too"
assert_not_grep '--iface raw0' "$TMPDIR/xdp.calls" \
    "Raw-IP physical link cannot abort the qualified Ethernet XDP generation"
assert_grep_fixed 'STATE=DEGRADED' "$TMPDIR/xdp-health.state" \
    "mixed Ethernet/Raw-IP topology is visibly degraded"
assert_grep_fixed 'DETAIL=unsupported-link-type' "$TMPDIR/xdp-health.state" \
    "mixed topology health records the exact unsupported-link reason"
assert_grep_fixed '-c -f ' "$TMPDIR/nft.calls" \
    "generated nft batch is syntax-checked before application"
assert_grep_fixed 'flush set inet noid_wan_strict physical_ifaces' \
    "$TMPDIR/captured.nft" "hotplug refresh synchronizes WAN hardware set"
assert_grep_fixed 'flush set inet noid_wan_strict lan_exceptions_v4' \
    "$TMPDIR/captured.nft" "hotplug refresh synchronizes WAN IPv4 LAN exceptions"
assert_grep_fixed 'flush set inet noid_wan_strict lan_exceptions_v6' \
    "$TMPDIR/captured.nft" "hotplug refresh synchronizes WAN IPv6 LAN exceptions"
assert_grep_fixed 'flush set inet noid_wan_strict lan_inbound_peers_v4' \
    "$TMPDIR/captured.nft" "hotplug refresh synchronizes inbound reply peers"
assert_grep_fixed 'lan_inbound_peers_v4 { 198.19.7.21 }' \
    "$TMPDIR/captured.nft" "WAN strict admits replies to an inbound-only peer"
assert_not_grep_extended 'arp_hardening|lan_peer_bindings|lan_peer_ips' \
    "$TMPDIR/captured.nft" \
    "topology refresh emits no non-enforcing ARP shadow-table transaction"
assert_grep_fixed 'neigh replace 198.19.7.20 lladdr 02:00:00:00:00:01 dev test0 nud permanent' "$TMPDIR/ip.calls" \
    "topology refresh restores permanent approved neighbors"
assert_grep_fixed '--peer test0,198.19.7.20,02:00:00:00:00:01,outbound,none,0,0' \
    "$TMPDIR/xdp.calls" "XDP receives the closed outbound-only selector"
assert_grep_fixed '--peer test0,198.19.7.21,02:00:00:00:00:02,inbound,tcp,8443,8443' \
    "$TMPDIR/xdp.calls" "XDP receives the exact inbound TCP selector"
assert_grep_fixed '--peer test0,198.19.7.22,02:00:00:00:00:03,both,udp,5300,5301' \
    "$TMPDIR/xdp.calls" "XDP receives the exact both-direction UDP selector"

flow_refresh_rc=0
env PATH="/usr/bin:/bin" \
    NOID_SYS_CLASS_NET="$TMPDIR/mock-sys" \
    NOID_LAN_TOPOLOGY_NFT_FILE="$TMPDIR/noid-lan-topology.nft" \
    NOID_LAN_TOPOLOGY_LOCK_FILE="$TMPDIR/topology-refresh-flow-reset.lock" \
    NOID_LAN_POLICY_EXPORTER="$TMPDIR/policy-exporter" \
    NOID_LAN_GLOBAL_ALLOW_MARKER="$TMPDIR/global-allow.marker" \
    NOID_LAN_GLOBAL_RUNTIME_STATE="$TMPDIR/flow-reset-global.state" \
    NOID_LAN_XDP_CONTROLLER="$TMPDIR/xdp-controller" \
    NOID_LAN_XDP_HEALTH_FILE="$TMPDIR/flow-reset-xdp-health.state" \
    NFT_CAPTURE="$TMPDIR/flow-reset.captured.nft" \
    NFT_CALLS="$TMPDIR/flow-reset.nft.calls" \
    XDP_CALLS="$TMPDIR/flow-reset.xdp.calls" \
    EVENT_CALLS="$TMPDIR/flow-reset.event.calls" \
    IP_CALLS="$TMPDIR/flow-reset.ip.calls" \
    bash "$TMPDIR/noid-lan-topology-refresh.sh" \
        --invalidate-peer-flows 198.19.7.22 --require-xdp \
    >"$TMPDIR/flow-reset-refresh.log" 2>&1 || flow_refresh_rc=$?
assert_eq 0 "$flow_refresh_rc" \
    "peer-flow invalidation completes inside the topology transaction"
assert_grep_fixed '--fresh-flow-map-for-peer 198.19.7.22' \
    "$TMPDIR/flow-reset.xdp.calls" \
    "topology runtime binds the fresh flow generation to the exact peer transition"
assert_cmd_success "XDP generation is replaced before the mutating nft transaction" \
    awk '
        /^xdp sync 0/ && xdp_line == 0 { xdp_line=NR }
        /^nft -f / && nft_apply_line == 0 { nft_apply_line=NR }
        END { exit !(xdp_line > 0 && nft_apply_line > xdp_line) }
    ' "$TMPDIR/event.calls"
assert_eq "BLOCKED" "$(cat "$TMPDIR/global-runtime.state")" \
    "default refresh publishes a cross-layer BLOCKED state"
assert_eq 600 "$(stat -c '%a' "$TMPDIR/topology-refresh.lock")" \
    "topology transaction lock is not acquirable by an unprivileged user"

# A durable peer cannot enter XDP/nft merely because `ip neigh replace`
# returned success: the exact device-scoped PERMANENT identity must be
# observable afterwards.
peer_postcheck_rc=0
env PATH="/usr/bin:/bin" MOCK_NEIGH_MISMATCH=1 \
    NOID_SYS_CLASS_NET="$TMPDIR/mock-sys" \
    NOID_LAN_TOPOLOGY_NFT_FILE="$TMPDIR/noid-lan-topology.nft" \
    NOID_LAN_TOPOLOGY_LOCK_FILE="$TMPDIR/topology-refresh-peer-mismatch.lock" \
    NOID_LAN_POLICY_EXPORTER="$TMPDIR/policy-exporter" \
    NOID_LAN_GLOBAL_ALLOW_MARKER="$TMPDIR/peer-mismatch-marker" \
    NOID_LAN_GLOBAL_RUNTIME_STATE="$TMPDIR/peer-mismatch-global.state" \
    NOID_LAN_XDP_CONTROLLER="$TMPDIR/xdp-controller" \
    NOID_LAN_XDP_HEALTH_FILE="$TMPDIR/peer-mismatch-health.state" \
    NFT_CAPTURE="$TMPDIR/peer-mismatch.captured.nft" \
    NFT_CALLS="$TMPDIR/peer-mismatch.nft.calls" \
    XDP_CALLS="$TMPDIR/peer-mismatch.xdp.calls" \
    EVENT_CALLS="$TMPDIR/peer-mismatch.event.calls" \
    IP_CALLS="$TMPDIR/peer-mismatch.ip.calls" \
    bash "$TMPDIR/noid-lan-topology-refresh.sh" \
    >"$TMPDIR/peer-mismatch.log" 2>&1 || peer_postcheck_rc=$?
assert_eq 1 "$peer_postcheck_rc" \
    "mismatched permanent peer postcondition fails closed"
if [ ! -e "$TMPDIR/peer-mismatch.xdp.calls" ]; then
    _pass "peer postcondition fails before XDP publication"
else
    _fail "peer postcondition fails before XDP publication"
fi
if [ ! -e "$TMPDIR/peer-mismatch.captured.nft" ]; then
    _pass "peer postcondition fails before nft publication"
else
    _fail "peer postcondition fails before nft publication"
fi

# A pathname, symlink, non-empty file or weakly permissioned file is never
# sufficient evidence for the explicit global opt-in.
: > "$TMPDIR/invalid-global-allow.marker"
chmod 0644 "$TMPDIR/invalid-global-allow.marker"
invalid_marker_rc=0
env PATH="/usr/bin:/bin" MOCK_GLOBAL_ALLOW=1 MOCK_POLICY_EMPTY=1 \
    NOID_SYS_CLASS_NET="$TMPDIR/mock-sys-etheronly" \
    NOID_LAN_TOPOLOGY_NFT_FILE="$TMPDIR/noid-lan-topology.nft" \
    NOID_LAN_TOPOLOGY_LOCK_FILE="$TMPDIR/topology-refresh-invalid-marker.lock" \
    NOID_LAN_POLICY_EXPORTER="$TMPDIR/policy-exporter" \
    NOID_LAN_GLOBAL_ALLOW_MARKER="$TMPDIR/invalid-global-allow.marker" \
    NOID_LAN_GLOBAL_RUNTIME_STATE="$TMPDIR/invalid-marker-global.state" \
    NOID_LAN_XDP_CONTROLLER="$TMPDIR/xdp-controller" \
    NOID_LAN_XDP_HEALTH_FILE="$TMPDIR/invalid-marker-health.state" \
    NFT_CAPTURE="$TMPDIR/invalid-marker.captured.nft" \
    NFT_CALLS="$TMPDIR/invalid-marker.nft.calls" \
    XDP_CALLS="$TMPDIR/invalid-marker.xdp.calls" \
    EVENT_CALLS="$TMPDIR/invalid-marker.event.calls" \
    IP_CALLS="$TMPDIR/invalid-marker.ip.calls" \
    bash "$TMPDIR/noid-lan-topology-refresh.sh" \
    >"$TMPDIR/invalid-marker.log" 2>&1 || invalid_marker_rc=$?
assert_eq 1 "$invalid_marker_rc" \
    "weak global-allow marker cannot authorize widening"
assert_eq INCONSISTENT "$(cat "$TMPDIR/invalid-marker-global.state")" \
    "invalid global marker publishes a visible inconsistent state"
if [ ! -e "$TMPDIR/invalid-marker.captured.nft" ]; then
    _pass "invalid global marker fails before nft widening"
else
    _fail "invalid global marker fails before nft widening"
fi

# A qualified Ethernet link with global IPv6 cannot claim the complete raw
# packet contract because the current XDP parser is IPv4-only. Conversely,
# an IPv4-only link must not be degraded merely because it has IPv4.
mkdir -p "$TMPDIR/mock-sys-etheronly/test0/device"
printf '%s\n' 1 > "$TMPDIR/mock-sys-etheronly/test0/type"
ipv6_ether_rc=0
env PATH="/usr/bin:/bin" MOCK_POLICY_EMPTY=1 \
    NOID_SYS_CLASS_NET="$TMPDIR/mock-sys-etheronly" \
    NOID_LAN_TOPOLOGY_NFT_FILE="$TMPDIR/noid-lan-topology.nft" \
    NOID_LAN_TOPOLOGY_LOCK_FILE="$TMPDIR/topology-refresh-ipv6-ether.lock" \
    NOID_LAN_POLICY_EXPORTER="$TMPDIR/policy-exporter" \
    NOID_LAN_GLOBAL_ALLOW_MARKER="$TMPDIR/global-allow.marker" \
    NOID_LAN_GLOBAL_RUNTIME_STATE="$TMPDIR/ipv6-ether-global.state" \
    NOID_LAN_XDP_CONTROLLER=/bin/true \
    NOID_LAN_XDP_HEALTH_FILE="$TMPDIR/ipv6-ether-xdp-health.state" \
    NFT_CAPTURE="$TMPDIR/ipv6-ether.captured.nft" NFT_CALLS="$TMPDIR/ipv6-ether.nft.calls" \
    XDP_CALLS="$TMPDIR/ipv6-ether.xdp.calls" EVENT_CALLS="$TMPDIR/ipv6-ether.event.calls" \
    IP_CALLS="$TMPDIR/ipv6-ether.ip.calls" \
    bash "$TMPDIR/noid-lan-topology-refresh.sh" \
    >"$TMPDIR/ipv6-ether-refresh.log" 2>&1 || ipv6_ether_rc=$?
assert_eq "0" "$ipv6_ether_rc" \
    "global physical IPv6 retains the independently enforced L3 baseline"
assert_grep_fixed 'STATE=DEGRADED' "$TMPDIR/ipv6-ether-xdp-health.state" \
    "global physical IPv6 cannot claim the complete XDP contract"
assert_grep_fixed 'DETAIL=physical-ipv6-unsupported' \
    "$TMPDIR/ipv6-ether-xdp-health.state" \
    "global physical IPv6 records its exact degraded reason"

ipv4_only_rc=0
env PATH="/usr/bin:/bin" MOCK_POLICY_EMPTY=1 MOCK_NO_IPV6=1 \
    NOID_SYS_CLASS_NET="$TMPDIR/mock-sys-etheronly" \
    NOID_LAN_TOPOLOGY_NFT_FILE="$TMPDIR/noid-lan-topology.nft" \
    NOID_LAN_TOPOLOGY_LOCK_FILE="$TMPDIR/topology-refresh-ipv4-only.lock" \
    NOID_LAN_POLICY_EXPORTER="$TMPDIR/policy-exporter" \
    NOID_LAN_GLOBAL_ALLOW_MARKER="$TMPDIR/global-allow.marker" \
    NOID_LAN_GLOBAL_RUNTIME_STATE="$TMPDIR/ipv4-only-global.state" \
    NOID_LAN_XDP_CONTROLLER=/bin/true \
    NOID_LAN_XDP_HEALTH_FILE="$TMPDIR/ipv4-only-xdp-health.state" \
    NFT_CAPTURE="$TMPDIR/ipv4-only.captured.nft" NFT_CALLS="$TMPDIR/ipv4-only.nft.calls" \
    XDP_CALLS="$TMPDIR/ipv4-only.xdp.calls" EVENT_CALLS="$TMPDIR/ipv4-only.event.calls" \
    IP_CALLS="$TMPDIR/ipv4-only.ip.calls" \
    bash "$TMPDIR/noid-lan-topology-refresh.sh" \
    >"$TMPDIR/ipv4-only-refresh.log" 2>&1 || ipv4_only_rc=$?
assert_eq "0" "$ipv4_only_rc" \
    "IPv4-only Ethernet topology completes normally"
assert_grep_fixed 'STATE=ACTIVE' "$TMPDIR/ipv4-only-xdp-health.state" \
    "IPv4-only Ethernet retains active XDP health"
assert_grep_fixed 'DETAIL=verified' "$TMPDIR/ipv4-only-xdp-health.state" \
    "IPv4 cannot trigger the physical-IPv6 warning"

# A hardware-backed Raw-IP link stays in every L3/WAN-strict set but cannot
# receive Ethernet XDP/TC or netdev EtherType hooks. It must not disable the
# qualified Ethernet generation, while a durable peer targeting that link is
# rejected before any boundary mutation.
raw_peer_rc=0
env PATH="/usr/bin:/bin" MOCK_POLICY_RAW=1 \
    NOID_SYS_CLASS_NET="$TMPDIR/mock-sys" \
    NOID_LAN_TOPOLOGY_NFT_FILE="$TMPDIR/noid-lan-topology.nft" \
    NOID_LAN_TOPOLOGY_LOCK_FILE="$TMPDIR/topology-refresh-raw-peer.lock" \
    NOID_LAN_POLICY_EXPORTER="$TMPDIR/policy-exporter" \
    NOID_LAN_GLOBAL_ALLOW_MARKER="$TMPDIR/global-allow.marker" \
    NOID_LAN_GLOBAL_RUNTIME_STATE="$TMPDIR/raw-peer-global.state" \
    NOID_LAN_XDP_CONTROLLER="$TMPDIR/xdp-controller" \
    NOID_LAN_XDP_HEALTH_FILE="$TMPDIR/raw-peer-xdp-health.state" \
    NFT_CAPTURE="$TMPDIR/raw-peer.captured.nft" NFT_CALLS="$TMPDIR/raw-peer.nft.calls" \
    XDP_CALLS="$TMPDIR/raw-peer.xdp.calls" EVENT_CALLS="$TMPDIR/raw-peer.event.calls" \
    IP_CALLS="$TMPDIR/raw-peer.ip.calls" \
    bash "$TMPDIR/noid-lan-topology-refresh.sh" \
    >"$TMPDIR/raw-peer-refresh.log" 2>&1 || raw_peer_rc=$?
assert_eq "1" "$raw_peer_rc" \
    "LAN peer on a non-Ethernet physical link fails closed"
if [ ! -e "$TMPDIR/raw-peer.xdp.calls" ]; then
    _pass "unsupported LAN peer is rejected before XDP mutation"
else
    _fail "unsupported LAN peer is rejected before XDP mutation"
fi

# A Raw-IP-only machine keeps the independently enforceable L3 baseline and
# publishes the unsupported boundary without invoking the Ethernet controller.
mkdir -p "$TMPDIR/mock-sys-rawonly/raw0/device"
printf '%s\n' 65534 > "$TMPDIR/mock-sys-rawonly/raw0/type"
raw_only_rc=0
env PATH="/usr/bin:/bin" MOCK_POLICY_EMPTY=1 \
    NOID_SYS_CLASS_NET="$TMPDIR/mock-sys-rawonly" \
    NOID_LAN_TOPOLOGY_NFT_FILE="$TMPDIR/noid-lan-topology.nft" \
    NOID_LAN_TOPOLOGY_LOCK_FILE="$TMPDIR/topology-refresh-raw-only.lock" \
    NOID_LAN_POLICY_EXPORTER="$TMPDIR/policy-exporter" \
    NOID_LAN_GLOBAL_ALLOW_MARKER="$TMPDIR/global-allow.marker" \
    NOID_LAN_GLOBAL_RUNTIME_STATE="$TMPDIR/raw-only-global.state" \
    NOID_LAN_XDP_CONTROLLER=/bin/false \
    NOID_LAN_XDP_HEALTH_FILE="$TMPDIR/raw-only-xdp-health.state" \
    NFT_CAPTURE="$TMPDIR/raw-only.captured.nft" NFT_CALLS="$TMPDIR/raw-only.nft.calls" \
    XDP_CALLS="$TMPDIR/raw-only.xdp.calls" EVENT_CALLS="$TMPDIR/raw-only.event.calls" \
    IP_CALLS="$TMPDIR/raw-only.ip.calls" \
    bash "$TMPDIR/noid-lan-topology-refresh.sh" \
    >"$TMPDIR/raw-only-refresh.log" 2>&1 || raw_only_rc=$?
assert_eq "0" "$raw_only_rc" \
    "Raw-IP-only topology retains WAN recovery behind L3/firewalld"
assert_grep_fixed 'STATE=DEGRADED' "$TMPDIR/raw-only-xdp-health.state" \
    "Raw-IP-only topology cannot claim an active Ethernet boundary"
assert_grep_fixed 'DETAIL=no-ethernet-link' "$TMPDIR/raw-only-xdp-health.state" \
    "Raw-IP-only topology records the exact missing-contract reason"
assert_grep_fixed 'physical_ifaces { "raw0" }' "$TMPDIR/raw-only.captured.nft" \
    "Raw-IP-only link remains in the L3 physical set"
assert_grep_fixed 'lan_guard_ifaces { "raw0" }' "$TMPDIR/raw-only.captured.nft" \
    "Raw-IP-only BLOCKED mode retains the reserved-port fallback"
assert_not_grep 'hook ingress device "raw0"' "$TMPDIR/raw-only.captured.nft" \
    "Raw-IP-only link receives no invalid Ethernet ingress hook"
assert_not_grep 'hook egress device "raw0"' "$TMPDIR/raw-only.captured.nft" \
    "Raw-IP-only link receives no invalid Ethernet egress hook"

# Global opt-in keeps physical interfaces in WAN-strict, permits only the
# connected prefixes there and empties topology drops. Standard ARP is already
# independent of this IP policy. This catches historical split-brain status and the tempting
# but unsafe workaround of emptying WAN-strict's physical interface set.
: > "$TMPDIR/global-allow.marker"
chmod 0600 "$TMPDIR/global-allow.marker"
global_rc=0
env PATH="/usr/bin:/bin" MOCK_GLOBAL_ALLOW=1 \
    NOID_SYS_CLASS_NET="$TMPDIR/mock-sys" \
    NOID_LAN_TOPOLOGY_NFT_FILE="$TMPDIR/noid-lan-topology.nft" \
    NOID_LAN_TOPOLOGY_LOCK_FILE="$TMPDIR/topology-refresh-global.lock" \
    NOID_LAN_POLICY_EXPORTER="$TMPDIR/policy-exporter" \
    NOID_LAN_GLOBAL_ALLOW_MARKER="$TMPDIR/global-allow.marker" \
    NOID_LAN_GLOBAL_RUNTIME_STATE="$TMPDIR/global-runtime.state" \
    NOID_LAN_XDP_CONTROLLER=/bin/true \
    NOID_LAN_XDP_HEALTH_FILE="$TMPDIR/xdp-health.state" \
    NFT_CAPTURE="$TMPDIR/global.captured.nft" NFT_CALLS="$TMPDIR/global.nft.calls" \
    XDP_CALLS="$TMPDIR/global.xdp.calls" EVENT_CALLS="$TMPDIR/global.event.calls" \
    IP_CALLS="$TMPDIR/global.ip.calls" \
    bash "$TMPDIR/noid-lan-topology-refresh.sh" \
    >"$TMPDIR/global-refresh.log" 2>&1 || global_rc=$?
if [ "$global_rc" -eq 0 ]; then
    _pass "global LAN opt-in builds a complete cross-layer batch"
else
    sed 's/^/    /' "$TMPDIR/global-refresh.log" >&2
    _fail "global LAN opt-in builds a complete cross-layer batch (rc=$global_rc)"
fi
assert_not_grep 'add element inet noid_lan_topology connected_v4' \
    "$TMPDIR/global.captured.nft" \
    "global opt-in empties the connected-prefix topology drop set"
assert_not_grep 'add element inet noid_lan_topology lan_guard_ifaces' \
    "$TMPDIR/global.captured.nft" \
    "global opt-in atomically disables the default-only reserved-port fallback"
assert_grep_fixed 'add element inet noid_wan_strict physical_ifaces { "test0" }' \
    "$TMPDIR/global.captured.nft" \
    "global opt-in preserves WAN-strict physical-interface coverage"
assert_grep_fixed 'add element inet noid_wan_strict lan_exceptions_v4 { 198.19.7.0/24 }' \
    "$TMPDIR/global.captured.nft" \
    "global opt-in admits only the connected IPv4 prefix through WAN-strict"
assert_not_grep 'global_lan_ifaces' "$TMPDIR/global.captured.nft" \
    "global IP opt-in has no obsolete ARP packet-filter state"
assert_eq "ALLOWED" "$(cat "$TMPDIR/global-runtime.state")" \
    "global refresh publishes ALLOWED only after complete application"

# A global widening on a qualified Ethernet link must not claim ALLOWED or
# apply any nft batch when the earliest XDP layer cannot switch.
global_xdp_fail_rc=0
env PATH="/usr/bin:/bin" MOCK_GLOBAL_ALLOW=1 MOCK_POLICY_EMPTY=1 \
    NOID_SYS_CLASS_NET="$TMPDIR/mock-sys-etheronly" \
    NOID_LAN_TOPOLOGY_NFT_FILE="$TMPDIR/noid-lan-topology.nft" \
    NOID_LAN_TOPOLOGY_LOCK_FILE="$TMPDIR/topology-refresh-global-xdp-fail.lock" \
    NOID_LAN_POLICY_EXPORTER="$TMPDIR/policy-exporter" \
    NOID_LAN_GLOBAL_ALLOW_MARKER="$TMPDIR/global-allow.marker" \
    NOID_LAN_GLOBAL_RUNTIME_STATE="$TMPDIR/global-xdp-fail-runtime.state" \
    NOID_LAN_XDP_CONTROLLER=/bin/false \
    NOID_LAN_XDP_HEALTH_FILE="$TMPDIR/global-xdp-fail-health.state" \
    NOID_LAN_XDP_SYNC_ATTEMPTS=1 NOID_LAN_XDP_SYNC_BACKOFF=0 \
    NFT_CAPTURE="$TMPDIR/global-xdp-fail.captured.nft" \
    NFT_CALLS="$TMPDIR/global-xdp-fail.nft.calls" \
    XDP_CALLS="$TMPDIR/global-xdp-fail.xdp.calls" \
    EVENT_CALLS="$TMPDIR/global-xdp-fail.event.calls" \
    IP_CALLS="$TMPDIR/global-xdp-fail.ip.calls" \
    bash "$TMPDIR/noid-lan-topology-refresh.sh" \
    >"$TMPDIR/global-xdp-fail.log" 2>&1 || global_xdp_fail_rc=$?
assert_eq 1 "$global_xdp_fail_rc" \
    "global Ethernet widening fails closed when XDP cannot switch"
assert_eq INCONSISTENT "$(cat "$TMPDIR/global-xdp-fail-runtime.state")" \
    "failed global XDP switch cannot publish a false ALLOWED state"
if [ ! -e "$TMPDIR/global-xdp-fail.captured.nft" ]; then
    _pass "failed global XDP switch aborts before the nft widening"
else
    _fail "failed global XDP switch aborts before the nft widening"
fi

# Even the independent status publication can fail after a valid earlier run.
# Neither a stale global ALLOWED state nor stale ACTIVE XDP health may survive
# the failed atomic replacement and mislead unprivileged readers.
stale_global_state="$TMPDIR/stale-global-runtime.state"
stale_global_marker="$TMPDIR/stale-global-allow.marker"
printf '%s\n' ALLOWED > "$stale_global_state"
: > "$stale_global_marker"
chmod 0644 "$stale_global_marker"
stale_global_rc=0
env PATH="/usr/bin:/bin" MOCK_GLOBAL_ALLOW=1 MOCK_POLICY_EMPTY=1 \
    MOCK_FAIL_MV_TARGET="$stale_global_state" \
    NOID_SYS_CLASS_NET="$TMPDIR/mock-sys-etheronly" \
    NOID_LAN_TOPOLOGY_NFT_FILE="$TMPDIR/noid-lan-topology.nft" \
    NOID_LAN_TOPOLOGY_LOCK_FILE="$TMPDIR/topology-refresh-stale-global.lock" \
    NOID_LAN_POLICY_EXPORTER="$TMPDIR/policy-exporter" \
    NOID_LAN_GLOBAL_ALLOW_MARKER="$stale_global_marker" \
    NOID_LAN_GLOBAL_RUNTIME_STATE="$stale_global_state" \
    NOID_LAN_XDP_CONTROLLER=/bin/true \
    NOID_LAN_XDP_HEALTH_FILE="$TMPDIR/stale-global-xdp-health.state" \
    NFT_CAPTURE="$TMPDIR/stale-global.captured.nft" \
    NFT_CALLS="$TMPDIR/stale-global.nft.calls" \
    XDP_CALLS="$TMPDIR/stale-global.xdp.calls" \
    EVENT_CALLS="$TMPDIR/stale-global.event.calls" \
    IP_CALLS="$TMPDIR/stale-global.ip.calls" \
    bash "$TMPDIR/noid-lan-topology-refresh.sh" \
    >"$TMPDIR/stale-global.log" 2>&1 || stale_global_rc=$?
assert_eq 1 "$stale_global_rc" \
    "invalid global marker still preserves the original failure"
if [ ! -e "$stale_global_state" ] && [ ! -L "$stale_global_state" ]; then
    _pass "failed INCONSISTENT publication retires stale ALLOWED evidence"
else
    _fail "failed INCONSISTENT publication retires stale ALLOWED evidence"
fi

stale_xdp_health="$TMPDIR/stale-xdp-health.state"
printf 'STATE=ACTIVE\nDETAIL=verified\n' > "$stale_xdp_health"
stale_xdp_rc=0
env PATH="/usr/bin:/bin" MOCK_GLOBAL_ALLOW=0 MOCK_POLICY_EMPTY=1 \
    MOCK_FAIL_MV_TARGET="$stale_xdp_health" \
    NOID_SYS_CLASS_NET="$TMPDIR/mock-sys-etheronly" \
    NOID_LAN_TOPOLOGY_NFT_FILE="$TMPDIR/noid-lan-topology.nft" \
    NOID_LAN_TOPOLOGY_LOCK_FILE="$TMPDIR/topology-refresh-stale-xdp.lock" \
    NOID_LAN_POLICY_EXPORTER="$TMPDIR/policy-exporter" \
    NOID_LAN_GLOBAL_ALLOW_MARKER="$TMPDIR/stale-xdp-global-allow.marker" \
    NOID_LAN_GLOBAL_RUNTIME_STATE="$TMPDIR/stale-xdp-global.state" \
    NOID_LAN_XDP_CONTROLLER=/bin/false \
    NOID_LAN_XDP_HEALTH_FILE="$stale_xdp_health" \
    NOID_LAN_XDP_SYNC_ATTEMPTS=1 NOID_LAN_XDP_SYNC_BACKOFF=0 \
    NFT_CAPTURE="$TMPDIR/stale-xdp.captured.nft" \
    NFT_CALLS="$TMPDIR/stale-xdp.nft.calls" \
    XDP_CALLS="$TMPDIR/stale-xdp.xdp.calls" \
    EVENT_CALLS="$TMPDIR/stale-xdp.event.calls" \
    IP_CALLS="$TMPDIR/stale-xdp.ip.calls" \
    bash "$TMPDIR/noid-lan-topology-refresh.sh" \
    >"$TMPDIR/stale-xdp.log" 2>&1 || stale_xdp_rc=$?
assert_eq 1 "$stale_xdp_rc" \
    "failed XDP-health publication makes the refresh fail visibly"
if [ ! -e "$stale_xdp_health" ] && [ ! -L "$stale_xdp_health" ]; then
    _pass "failed DEGRADED publication retires stale ACTIVE evidence"
else
    _fail "failed DEGRADED publication retires stale ACTIVE evidence"
fi

# XDP-only rejection is a deliberately degraded recovery path, not a silent
# success and not a total WAN lockout. The independently committed topology
# policy must remain BLOCKED while the health contract says DEGRADED.
rm -f "$TMPDIR/global-allow.marker"
degraded_rc=0
env PATH="/usr/bin:/bin" MOCK_GLOBAL_ALLOW=0 \
    MOCK_POLICY_EMPTY=1 \
    NOID_SYS_CLASS_NET="$TMPDIR/mock-sys" \
    NOID_LAN_TOPOLOGY_NFT_FILE="$TMPDIR/noid-lan-topology.nft" \
    NOID_LAN_TOPOLOGY_LOCK_FILE="$TMPDIR/topology-refresh-degraded.lock" \
    NOID_LAN_POLICY_EXPORTER="$TMPDIR/policy-exporter" \
    NOID_LAN_GLOBAL_ALLOW_MARKER="$TMPDIR/global-allow.marker" \
    NOID_LAN_GLOBAL_RUNTIME_STATE="$TMPDIR/degraded-global.state" \
    NOID_LAN_XDP_CONTROLLER=/bin/false \
    NOID_LAN_XDP_HEALTH_FILE="$TMPDIR/degraded-xdp-health.state" \
    NFT_CAPTURE="$TMPDIR/degraded.captured.nft" NFT_CALLS="$TMPDIR/degraded.nft.calls" \
    XDP_CALLS="$TMPDIR/degraded.xdp.calls" EVENT_CALLS="$TMPDIR/degraded.event.calls" \
    IP_CALLS="$TMPDIR/degraded.ip.calls" \
    bash "$TMPDIR/noid-lan-topology-refresh.sh" \
    >"$TMPDIR/degraded-refresh.log" 2>&1 || degraded_rc=$?
assert_eq "0" "$degraded_rc" \
    "XDP-only incompatibility preserves the WAN recovery baseline"
assert_grep_fixed 'STATE=DEGRADED' "$TMPDIR/degraded-xdp-health.state" \
    "XDP-only incompatibility is explicitly degraded"
assert_eq "BLOCKED" "$(cat "$TMPDIR/degraded-global.state")" \
    "degraded raw-packet state keeps the default LAN topology block"

# The boot wrapper's opt-in status is emitted only after the same complete
# lower-layer transaction. This closes the gap where the wrapper's advertised
# outer budget stopped after the first fail-soft XDP result.
retryable_degraded_rc=0
env PATH="/usr/bin:/bin" MOCK_GLOBAL_ALLOW=0 \
    MOCK_POLICY_EMPTY=1 \
    NOID_SYS_CLASS_NET="$TMPDIR/mock-sys" \
    NOID_LAN_TOPOLOGY_NFT_FILE="$TMPDIR/noid-lan-topology.nft" \
    NOID_LAN_TOPOLOGY_LOCK_FILE="$TMPDIR/topology-refresh-retryable-degraded.lock" \
    NOID_LAN_POLICY_EXPORTER="$TMPDIR/policy-exporter" \
    NOID_LAN_GLOBAL_ALLOW_MARKER="$TMPDIR/global-allow.marker" \
    NOID_LAN_GLOBAL_RUNTIME_STATE="$TMPDIR/retryable-degraded-global.state" \
    NOID_LAN_XDP_CONTROLLER=/bin/false \
    NOID_LAN_XDP_HEALTH_FILE="$TMPDIR/retryable-degraded-xdp-health.state" \
    NOID_LAN_XDP_SYNC_ATTEMPTS=1 NOID_LAN_XDP_SYNC_BACKOFF=0 \
    NOID_LAN_RETRY_DEGRADED_XDP=1 \
    NFT_CAPTURE="$TMPDIR/retryable-degraded.captured.nft" \
    NFT_CALLS="$TMPDIR/retryable-degraded.nft.calls" \
    XDP_CALLS="$TMPDIR/retryable-degraded.xdp.calls" \
    EVENT_CALLS="$TMPDIR/retryable-degraded.event.calls" \
    IP_CALLS="$TMPDIR/retryable-degraded.ip.calls" \
    bash "$TMPDIR/noid-lan-topology-refresh.sh" \
    >"$TMPDIR/retryable-degraded-refresh.log" 2>&1 \
    || retryable_degraded_rc=$?
assert_eq 75 "$retryable_degraded_rc" \
    "boot opt-in receives the reserved retryable XDP status"
assert_eq "BLOCKED" "$(cat "$TMPDIR/retryable-degraded-global.state")" \
    "retryable XDP status is emitted only after the blocked baseline commits"
assert_grep_fixed 'table netdev noid_l2_guard' \
    "$TMPDIR/retryable-degraded.captured.nft" \
    "retryable XDP status retains the committed Layer-2 guard"
unset -f nmcli ip nft logger firewall-cmd

test_finish

#!/bin/bash
# 23-networkmanager-structural — M23 regression test
#
# Covers: MAC randomization conf.d file, IPv6 conf.d file, connection
# defaults conf.d file including native MPTCP/rp_filter ownership, expected
# drop-in paths.
# Would catch: missing drop-in, wrong priority prefix, conflicting setting.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/23-networkmanager.ks"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

test_start "23-networkmanager-structural"

assert_file_exists "$KS_FILE"
assert_cmd_success "bash -n $KS_FILE" bash -n "$KS_FILE"

# Three conf.d drop-ins, in priority order (00-/01-/02-)
assert_grep_fixed "/etc/NetworkManager/conf.d/00-noid-mac-randomization.conf" "$KS_FILE"
assert_grep_fixed "/etc/NetworkManager/conf.d/01-noid-ipv6.conf" "$KS_FILE"
assert_grep_fixed "/etc/NetworkManager/conf.d/02-noid-connection-defaults.conf" "$KS_FILE"

# Heredoc markers
assert_grep_fixed 'MAC_EOF' "$KS_FILE"
assert_grep_fixed 'IPV6_EOF' "$KS_FILE"
assert_grep_fixed 'DEFAULTS_EOF' "$KS_FILE"
extract_heredoc "$KS_FILE" "MAC_EOF" "$TMPDIR/mac-randomization.conf" \
    || _fail "MAC/WoL defaults extraction"
extract_heredoc "$KS_FILE" "IPV6_EOF" "$TMPDIR/ipv6.conf" \
    || _fail "IPv6 defaults extraction"
extract_heredoc "$KS_FILE" "DEFAULTS_EOF" "$TMPDIR/connection-defaults.conf" \
    || _fail "connection-wide defaults extraction"
extract_heredoc "$KS_FILE" "DISPATCHER_EOF" "$TMPDIR/connection-defaults.sh" \
    || _fail "connection-defaults dispatcher extraction"
extract_heredoc "$KS_FILE" "SYSCTL_REAPPLY_EOF" "$TMPDIR/sysctl-reapply.sh" \
    || _fail "sysctl reapply dispatcher extraction"
extract_heredoc "$KS_FILE" "NM_SCOPE_EOF" "$TMPDIR/nm-scope.sh" \
    || _fail "account-completion profile scoper extraction"
extract_heredoc "$KS_FILE" "NM_SCOPE_SERVICE_EOF" "$TMPDIR/nm-scope.service" \
    || _fail "account-completion profile scoper service extraction"
extract_heredoc "$KS_FILE" "NM_SCOPE_TIMER_EOF" "$TMPDIR/nm-scope.timer" \
    || _fail "account-completion profile scoper timer extraction"
assert_cmd_success "connection-defaults dispatcher is valid bash" \
    bash -n "$TMPDIR/connection-defaults.sh"
assert_cmd_success "sysctl reapply dispatcher is valid bash" \
    bash -n "$TMPDIR/sysctl-reapply.sh"
assert_cmd_success "account-completion profile scoper is valid bash" \
    bash -n "$TMPDIR/nm-scope.sh"

# NetworkManager.conf requires numeric enum/flag values. 32768 is the `ignore`
# ownership boundary, not the control that disables WoL; M27 owns the native
# device default.
assert_grep_fixed 'ethernet.wake-on-lan=32768' "$TMPDIR/mac-randomization.conf" \
    "numeric NetworkManager ignore flag leaves M27's Wake-on-LAN state unchanged"
assert_not_grep '^ethernet\.wake-on-lan=ignore$' \
    "$TMPDIR/mac-randomization.conf" \
    "NM.conf does not use nmcli's wake-on-lan enum nick"
assert_grep_fixed 'does not itself disable WoL' "$KS_FILE" \
    "M23 documents the maintained NetworkManager ignore semantics"
assert_grep_fixed 'systemd.link `WakeOnLan=off`' "$KS_FILE" \
    "M23 names M27 as the actual Wake-on-LAN disable owner"
assert_not_grep 'explicitly disabled at NM layer' "$KS_FILE" \
    "M23 no longer attributes the disable action to NetworkManager ignore"
assert_grep_fixed "connection's stable ID" "$TMPDIR/mac-randomization.conf" \
    "Ethernet stable-MAC provenance names NetworkManager's maintained input"
assert_grep_fixed 'host-specific secret' "$TMPDIR/mac-randomization.conf" \
    "Ethernet stable-MAC provenance names the per-host secret"
assert_not_grep 'connection UUID + host machine-id\|host machine-id.*device hint' \
    "$TMPDIR/mac-randomization.conf" \
    "M23 does not invent machine-id/device-hint inputs for NetworkManager stable MACs"
assert_grep_fixed 'Reduces pre-association probe linkability' \
    "$TMPDIR/mac-randomization.conf" \
    "WiFi scan randomization claim stays within its real privacy effect"
assert_not_grep 'Prevents tracking via probe requests' "$KS_FILE" \
    "WiFi scan randomization is not presented as complete anti-tracking"

# Scan probes use a fresh locally administered identity, association follows
# Fedora's per-SSID stable pseudonym, and wired profiles use NetworkManager's
# per-profile stable identity. Do not preserve the hardware OUI through a
# generate-mac-address-mask: the maintained empty-mask default scrambles it.
assert_grep_fixed 'wifi.scan-rand-mac-address=yes' \
    "$TMPDIR/mac-randomization.conf" \
    "WiFi scan probes use NetworkManager randomization"
assert_grep_fixed 'wifi.cloned-mac-address=stable-ssid' "$KS_FILE" \
    "WiFi association retains Fedora's per-SSID pseudonym"
assert_grep_fixed 'ethernet.cloned-mac-address=stable' \
    "$TMPDIR/mac-randomization.conf" \
    "Ethernet uses a stable per-profile pseudonym"
assert_not_grep 'generate-mac-address-mask[[:space:]]*=' \
    "$TMPDIR/mac-randomization.conf" \
    "NoID Privacy does not retain the hardware vendor OUI"

# IPv6 policy: physical profiles are changed to method=disabled on first up.
# Native non-physical types stay outside the dispatcher mutation boundary so
# the reviewed VPN/provider configuration remains authoritative.
assert_grep_fixed 'ipv6.method=disabled' "$KS_FILE"
assert_not_grep 'ipv6.method=ignore' "$KS_FILE" \
    "M23 does not claim or apply a nonexistent VPN-profile mutation"
assert_grep_fixed 'Non-physical profiles (including wireguard, VPN, dummy and bridge types)' \
    "$KS_FILE" "M23 documents the non-physical ownership boundary"
assert_grep_fixed 'Setting only ipv6.method=auto is not' "$TMPDIR/ipv6.conf" \
    "physical IPv6 address defaults reject a partial re-enable recipe"
assert_grep_fixed 'physical XDP peer/flow contract must' "$TMPDIR/ipv6.conf" \
    "physical IPv6 wording names the all-layer custom-fork boundary"
assert_eq "2" "$(grep -c '^ipv6\.addr-gen-mode=1$' "$TMPDIR/ipv6.conf")" \
    "both physical sections use NM.conf's numeric stable-privacy enum"
assert_not_grep '^ipv6\.addr-gen-mode=stable-privacy$' "$TMPDIR/ipv6.conf" \
    "NM.conf does not use nmcli's addr-gen-mode enum nick"
assert_not_grep 'privacy-safe re-enable defaults\|re-enable templates' "$KS_FILE" \
    "M23 no longer advertises a nonfunctional partial IPv6 re-enable"
assert_grep_fixed 'ipv4.link-local=2' "$TMPDIR/connection-defaults.conf" \
    "global connection default disables IPv4LL fallback with the numeric config value"
assert_grep_fixed 'ipv4.dad-timeout=200' "$TMPDIR/connection-defaults.conf" \
    "global connection default explicitly preserves native IPv4 DAD"
assert_not_grep '^ipv4\.dad-timeout=0$' "$TMPDIR/connection-defaults.conf" \
    "NoID Privacy never disables NetworkManager duplicate-address detection"
assert_eq "1" "$(grep -c '^ipv4\.dad-timeout=200$' "$TMPDIR/connection-defaults.conf")" \
    "IPv4 DAD default has one exact effective assignment"
assert_eq "1" "$(grep -c '^ipv4\.dhcp-send-hostname=0$' "$TMPDIR/connection-defaults.conf")" \
    "global IPv4 DHCP hostname suppression uses the current ternary value"
assert_eq "1" "$(grep -c '^ipv6\.dhcp-send-hostname=0$' "$TMPDIR/connection-defaults.conf")" \
    "global IPv6 DHCP hostname suppression uses the current ternary value"
assert_eq "1" "$(grep -c '^connection\.dns-over-tls=1$' "$TMPDIR/connection-defaults.conf")" \
    "non-physical per-link DNS scopes inherit best-effort opportunistic DoT"
assert_eq "1" "$(grep -c '^connection\.mptcp-flags=1$' "$TMPDIR/connection-defaults.conf")" \
    "unset profiles disable NetworkManager MPTCP handling before activation"
assert_grep_fixed 'loosens strict rp_filter=1 to mode 2.' \
    "$TMPDIR/connection-defaults.conf" \
    "MPTCP default documents the native activation-time rp_filter conflict"
assert_eq "2" "$(grep -c '^connection\.dns-over-tls=2$' "$TMPDIR/connection-defaults.conf")" \
    "Ethernet and Wi-Fi each have one fail-closed first-activation DoT default"
assert_grep_fixed '[connection-noid-ethernet-dns]' "$TMPDIR/connection-defaults.conf" \
    "Ethernet first activation has a dedicated NetworkManager default section"
assert_grep_fixed 'match-device=type:ethernet' "$TMPDIR/connection-defaults.conf" \
    "Ethernet Strict DoT default uses NetworkManager native device matching"
assert_grep_fixed '[connection-noid-wifi-dns]' "$TMPDIR/connection-defaults.conf" \
    "Wi-Fi first activation has a dedicated NetworkManager default section"
assert_grep_fixed 'match-device=type:wifi' "$TMPDIR/connection-defaults.conf" \
    "Wi-Fi Strict DoT default uses NetworkManager native device matching"
assert_grep_fixed 'LLDP receive listener off' "$TMPDIR/connection-defaults.conf" \
    "M23 describes NetworkManager's receive-side LLDP control"
assert_grep_fixed 'not transmission of' "$TMPDIR/connection-defaults.conf" \
    "M23 does not misattribute LLDP transmit suppression to NetworkManager"
assert_not_grep 'no IEEE 802.1AB broadcasts' "$KS_FILE" \
    "receive-only LLDP policy is not advertised as an outbound packet block"
assert_not_grep 'prevents NM from sending the OS hostname\|no DHCP hostname leak\|best-effort canonical 2026\|dhcp-send-hostname=false belt-and-suspenders' \
    "$KS_FILE" "hostname-mode and DHCP-send controls are not conflated or hyped"
assert_grep_fixed 'not a unique device or user identifier' \
    "$TMPDIR/connection-defaults.conf" \
    "generic DHCP hostname disclosure is described precisely"
assert_not_grep 'does NOT identify the device or user' "$KS_FILE" \
    "generic hostname wording avoids an absolute non-identification claim"
cp "$TMPDIR/connection-defaults.conf" "$TMPDIR/connection-defaults.mutated.conf"
sed -i 's/^ipv4\.dad-timeout=200$/ipv4.dad-timeout=0/' \
    "$TMPDIR/connection-defaults.mutated.conf"
dad_config_valid() {
    [ "$(grep -c '^ipv4\.dad-timeout=200$' "$1")" -eq 1 ] \
        && ! grep -qx 'ipv4.dad-timeout=0' "$1"
}
if dad_config_valid "$TMPDIR/connection-defaults.mutated.conf"; then
    _fail "DAD-off mutation is rejected by the effective-value assertion"
else
    _pass "DAD-off mutation is rejected by the effective-value assertion"
fi

cp "$TMPDIR/connection-defaults.conf" "$TMPDIR/dns-default.mutated.conf"
sed -i '0,/^connection\.dns-over-tls=1$/s//connection.dns-over-tls=0/' \
    "$TMPDIR/dns-default.mutated.conf"
dns_default_valid() {
    [ "$(grep -c '^connection\.dns-over-tls=1$' "$1")" -eq 1 ] \
        && [ "$(grep -c '^connection\.dns-over-tls=2$' "$1")" -eq 2 ] \
        && ! grep -qx 'connection.dns-over-tls=0' "$1"
}
if dns_default_valid "$TMPDIR/dns-default.mutated.conf"; then
    _fail "forced-plaintext generic DNS mutation is rejected"
else
    _pass "forced-plaintext generic DNS mutation is rejected"
fi

cp "$TMPDIR/connection-defaults.conf" "$TMPDIR/mptcp-default.mutated.conf"
sed -i 's/^connection\.mptcp-flags=1$/connection.mptcp-flags=0/' \
    "$TMPDIR/mptcp-default.mutated.conf"
mptcp_default_valid() {
    [ "$(grep -c '^connection\.mptcp-flags=1$' "$1")" -eq 1 ] \
        && ! grep -qx 'connection.mptcp-flags=0' "$1"
}
if mptcp_default_valid "$TMPDIR/mptcp-default.mutated.conf"; then
    _fail "MPTCP default mutation is rejected"
else
    _pass "MPTCP default mutation is rejected"
fi

if command -v NetworkManager >/dev/null 2>&1; then
    mkdir -p "$TMPDIR/nm-conf.d" "$TMPDIR/nm-system-conf.d"
    cp "$TMPDIR/mac-randomization.conf" "$TMPDIR/nm-conf.d/00-noid.conf"
    cp "$TMPDIR/ipv6.conf" "$TMPDIR/nm-conf.d/01-noid.conf"
    cp "$TMPDIR/connection-defaults.conf" "$TMPDIR/nm-conf.d/02-noid.conf"
    printf '[main]\n' > "$TMPDIR/NetworkManager.conf"
    printf '[main]\n' > "$TMPDIR/NetworkManager-intern.conf"
    printf '[main]\nNetworkingEnabled=true\n' > "$TMPDIR/NetworkManager.state"
    if NetworkManager --print-config \
        --config="$TMPDIR/NetworkManager.conf" \
        --config-dir="$TMPDIR/nm-conf.d" \
        --system-config-dir="$TMPDIR/nm-system-conf.d" \
        --intern-config="$TMPDIR/NetworkManager-intern.conf" \
        --state-file="$TMPDIR/NetworkManager.state" \
        > "$TMPDIR/nm-effective.conf" 2> "$TMPDIR/nm-parser.stderr" \
       && grep -qx 'ipv4.dad-timeout=200' "$TMPDIR/nm-effective.conf" \
       && grep -qx 'ipv4.dhcp-send-hostname=0' "$TMPDIR/nm-effective.conf" \
       && grep -qx 'ipv6.dhcp-send-hostname=0' "$TMPDIR/nm-effective.conf" \
       && grep -qx 'ethernet.wake-on-lan=32768' "$TMPDIR/nm-effective.conf" \
       && [ "$(grep -cFx 'ipv6.addr-gen-mode=1' \
            "$TMPDIR/nm-effective.conf")" -eq 2 ] \
       && grep -qx 'connection.dns-over-tls=1' "$TMPDIR/nm-effective.conf" \
       && grep -qx 'connection.mptcp-flags=1' "$TMPDIR/nm-effective.conf" \
       && [ "$(grep -cFx 'connection.dns-over-tls=2' \
            "$TMPDIR/nm-effective.conf")" -eq 2 ] \
       && grep -qx '\[connection-noid-ethernet-dns\]' \
            "$TMPDIR/nm-effective.conf" \
       && grep -qx 'match-device=type:ethernet' "$TMPDIR/nm-effective.conf" \
       && grep -qx '\[connection-noid-wifi-dns\]' \
            "$TMPDIR/nm-effective.conf" \
       && grep -qx 'match-device=type:wifi' "$TMPDIR/nm-effective.conf" \
       && [ ! -s "$TMPDIR/nm-parser.stderr" ]; then
        _pass "installed NetworkManager parser accepts numeric enums, MPTCP-off and physical-first DoT defaults"
    else
        _fail "installed NetworkManager parser accepts numeric enums, MPTCP-off and physical-first DoT defaults"
    fi
fi

if command -v nmcli >/dev/null 2>&1; then
    nmcli --offline connection add type ethernet con-name noid-dhcp-hostname-test \
        ifname test0 ipv4.dhcp-send-hostname no ipv6.dhcp-send-hostname no \
        > "$TMPDIR/nmcli-dhcp-hostname.nmconnection"
    assert_eq "2" "$(grep -c '^dhcp-send-hostname=0$' \
        "$TMPDIR/nmcli-dhcp-hostname.nmconnection")" \
        "installed nmcli serializes both current DHCP hostname properties as ternary zero"
fi

# File permissions are set (644 for all conf.d drop-ins)
assert_grep_extended 'chmod 644 /etc/NetworkManager/conf.d/' "$KS_FILE"

# SELinux relabel post-write: every owned target is exact and failure remains
# compose-fatal; recursive relabeling could touch foreign dispatcher payloads.
assert_eq "6" "$(grep -c '^[[:space:]]*restorecon -F' "$KS_FILE")" \
    "all six M23 relabel groups are exact"
assert_not_grep 'restorecon -R' "$KS_FILE" \
    "M23 never recursively relabels foreign NetworkManager payloads"
assert_not_grep 'restorecon.*[|][|][[:space:]]*true' "$KS_FILE" \
    "M23 does not swallow SELinux relabel failures"
assert_grep_fixed '/etc/NetworkManager/dispatcher.d/pre-up.d/40-noid-connection-defaults' \
    "$KS_FILE" "physical dispatcher symlink is explicitly relabeled"
assert_grep_fixed '/etc/NetworkManager/dispatcher.d/pre-up.d/99-noid-sysctl-reapply' \
    "$KS_FILE" "ingress-policy dispatcher symlink is explicitly relabeled"

# Every physical profile is forced into firewalld target-DROP at runtime and
# persisted. This closes saved/imported connection.zone=home/public bypasses.
assert_grep_fixed 'firewall-cmd --zone=drop --change-interface="$INTERFACE"' \
    "$TMPDIR/connection-defaults.sh"
assert_grep_fixed 'nmcli connection modify "$UUID" connection.zone drop' \
    "$TMPDIR/connection-defaults.sh"
assert_grep_fixed 'export LC_ALL=C' "$TMPDIR/connection-defaults.sh" \
    "nmcli dispatcher parsing is locale-independent"
assert_grep_fixed "only NetworkManager's native connection.type selects the physical" \
    "$TMPDIR/connection-defaults.sh" \
    "physical policy documents its native type authority"
assert_not_grep_extended 'wg\*|tun\*|tap\*|ppp\*|virbr\*|veth\*|docker\*|br-\*' \
    "$TMPDIR/connection-defaults.sh" \
    "mutable interface-name prefixes cannot bypass physical-link policy"
assert_grep_fixed 'pre-up.d/40-noid-connection-defaults' "$KS_FILE" \
    "physical zone hook is registered in NetworkManager pre-up.d"
assert_grep_fixed 'chmod 700 /etc/NetworkManager/dispatcher.d/40-noid-connection-defaults' \
    "$KS_FILE" "physical hardening dispatcher is root-only"
assert_grep_fixed 'exit 1' "$TMPDIR/connection-defaults.sh" \
    "physical zone enforcement fails loudly"
assert_not_grep 'sysctl -w.*disable_ipv6=1.*[|][|][[:space:]]*true' \
    "$TMPDIR/connection-defaults.sh" \
    "live IPv6 hardening cannot fail silently"
assert_grep_fixed '9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net' \
    "$TMPDIR/connection-defaults.sh" \
    "live per-link DNS preserves the intended Quad9 TLS server name"
assert_grep_fixed 'resolvectl dnsovertls "$INTERFACE" "$DNS_DOT_MODE"' \
    "$TMPDIR/connection-defaults.sh" \
    "live per-link Quad9 uses the exact M05-selected DoT transport"
assert_grep_fixed '/usr/local/sbin/noid-dns-mode --physical-value' \
    "$TMPDIR/connection-defaults.sh" \
    "physical dispatcher consumes one closed M05 transport value"
assert_grep_fixed '^(no|opportunistic|yes)$' \
    "$TMPDIR/connection-defaults.sh" \
    "physical dispatcher rejects an open-ended DNS mode"
assert_eq "3" "$(grep -cF 'connection.dns-over-tls "$DNS_DOT_MODE"' \
    "$TMPDIR/connection-defaults.sh")" \
    "both Live and persistent physical branches override the VPN-compatible default"
assert_grep_fixed 'live runtime profile mirror failed' "$TMPDIR/connection-defaults.sh"
assert_eq "3" "$(grep -c '^[[:space:]]*ipv4\.dhcp-send-hostname false$' \
    "$TMPDIR/connection-defaults.sh")" \
    "every live/persistent physical-profile mutation disables IPv4 DHCP hostname sending"
assert_eq "3" "$(grep -c '^[[:space:]]*ipv6\.dhcp-send-hostname false$' \
    "$TMPDIR/connection-defaults.sh")" \
    "every live/persistent physical-profile mutation disables IPv6 DHCP hostname sending"
assert_grep_fixed 'FAIL: targeted ingress-policy repair failed' \
    "$TMPDIR/sysctl-reapply.sh" \
    "post-activation ingress-policy enforcement is fail-visible"
assert_grep_fixed 'pre-up|up|vpn-pre-up|vpn-up|dhcp4-change|reapply)' \
    "$TMPDIR/sysctl-reapply.sh" \
    "awaited activation plus IPv4 renewal/reapply events restore ingress policy"
assert_not_grep_extended 'connectivity-change|dhcp6-change' \
    "$TMPDIR/sysctl-reapply.sh" \
    "unrelated connectivity and IPv6-only events do not trigger sysctl work"
assert_not_grep 'sysctl --system' "$TMPDIR/sysctl-reapply.sh" \
    "NetworkManager events never reload unrelated sysctl drop-ins"
assert_grep_fixed 'IPV4_CONF_ROOT=/proc/sys/net/ipv4/conf' "$TMPDIR/sysctl-reapply.sh" \
    "production rp_filter writes use the fixed procfs hierarchy"
assert_grep_fixed 'IPV6_CONF_ROOT=/proc/sys/net/ipv6/conf' "$TMPDIR/sysctl-reapply.sh" \
    "production IPv6 frame-filter writes use the fixed procfs hierarchy"
assert_grep_fixed 'NOID_TEST_MODE' "$TMPDIR/sysctl-reapply.sh" \
    "the functional-test root override is explicitly test-gated"
assert_grep_fixed 'repair_one "$IPV4_CONF_ROOT/all/rp_filter" 0' \
    "$TMPDIR/sysctl-reapply.sh" "the load-bearing global rp_filter node is required"
assert_grep_fixed 'repair_one "$IPV4_CONF_ROOT/$INTERFACE/rp_filter" 1' \
    "$TMPDIR/sysctl-reapply.sh" "a concurrently removed event interface is tolerated"
assert_grep_fixed 'repair_one "$IPV4_CONF_ROOT/$INTERFACE/drop_gratuitous_arp" 1' \
    "$TMPDIR/sysctl-reapply.sh" "gratuitous-ARP filtering is restored after WLAN association"
assert_grep_fixed 'repair_one "$IPV4_CONF_ROOT/$INTERFACE/drop_unicast_in_l2_multicast" 1' \
    "$TMPDIR/sysctl-reapply.sh" "IPv4 GTK unicast-in-multicast filtering is restored after WLAN association"
assert_grep_fixed 'repair_one "$IPV6_CONF_ROOT/$INTERFACE/drop_unicast_in_l2_multicast" 1' \
    "$TMPDIR/sysctl-reapply.sh" "IPv6 GTK unicast-in-multicast filtering is restored after WLAN association"
assert_not_grep_extended 'run/initramfs/live|run/livesys' "$TMPDIR/sysctl-reapply.sh" \
    "targeted ingress repair is not skipped on the live system"
assert_grep_fixed 'pre-up.d/99-noid-sysctl-reapply' "$KS_FILE" \
    "ingress policy is restored before NetworkManager exposes a fully active interface"
assert_grep_fixed 'source-capable drift path' "$TMPDIR/sysctl-reapply.sh" \
    "dispatcher rationale distinguishes reviewed source capability"
assert_grep_fixed 'live full-policy verification additionally observed the IPv6 WLAN node at 0' \
    "$TMPDIR/sysctl-reapply.sh" \
    "dispatcher rationale records the reproduced runtime drift without overstating writer attribution"
assert_not_grep 'wpa_supplicant also clears two M02 frame-filter nodes on disassociation' \
    "$KS_FILE" "unqualified live root-cause wording cannot return"

# Journal evidence must identify the failed policy phase without persisting
# connection UUIDs, interface names, foreign usernames or DHCP route contents.
if awk '
    /logger -t/ { remaining = 2 }
    remaining > 0 {
        if ($0 ~ /\$(UUID|INTERFACE|current_perm|current|route|uuid|active_device|user_name)/)
            sensitive = 1
        remaining--
    }
    END { exit sensitive ? 0 : 1 }
' "$TMPDIR/connection-defaults.sh" "$TMPDIR/nm-scope.sh" \
        "$TMPDIR/sysctl-reapply.sh"; then
    _fail "M23 journal messages contain persistent network/account identifiers"
else
    _pass "M23 journal messages omit persistent network/account identifiers"
fi
assert_not_grep 'err=$modify_err' "$TMPDIR/connection-defaults.sh" \
    "raw nmcli error text cannot copy profile identifiers into the journal"

# Functional contract: the dispatcher changes only the global rp_filter and
# four concrete interface policy nodes, validates interface names, ignores
# IPv6-only events, tolerates a concurrently removed interface, and fails if
# the global kernel policy node is unexpectedly absent.
rp_root="$TMPDIR/rp-filter"
ipv6_root="$TMPDIR/ipv6-conf"
mkdir -p "$rp_root/all" "$rp_root/test0" "$rp_root/unrelated"
mkdir -p "$ipv6_root/test0" "$ipv6_root/unrelated"
printf '2\n' > "$rp_root/all/rp_filter"
printf '2\n' > "$rp_root/test0/rp_filter"
printf '0\n' > "$rp_root/test0/drop_gratuitous_arp"
printf '0\n' > "$rp_root/test0/drop_unicast_in_l2_multicast"
printf '0\n' > "$ipv6_root/test0/drop_unicast_in_l2_multicast"
printf '7\n' > "$rp_root/unrelated/value"
printf '8\n' > "$ipv6_root/unrelated/value"
assert_cmd_success "targeted ingress-policy fixture repair succeeds" \
    env NOID_TEST_MODE=1 NOID_TEST_IPV4_CONF_ROOT="$rp_root" \
    NOID_TEST_IPV6_CONF_ROOT="$ipv6_root" \
    bash "$TMPDIR/sysctl-reapply.sh" test0 reapply
assert_eq "1" "$(<"$rp_root/all/rp_filter")" \
    "targeted repair restores the global strict rp_filter policy"
assert_eq "1" "$(<"$rp_root/test0/rp_filter")" \
    "targeted repair restores the event interface strict rp_filter policy"
assert_eq "1" "$(<"$rp_root/test0/drop_gratuitous_arp")" \
    "targeted repair restores the event interface gratuitous-ARP filter"
assert_eq "1" "$(<"$rp_root/test0/drop_unicast_in_l2_multicast")" \
    "targeted repair restores the event interface IPv4 GTK frame filter"
assert_eq "1" "$(<"$ipv6_root/test0/drop_unicast_in_l2_multicast")" \
    "targeted repair restores the event interface IPv6 GTK frame filter"
assert_eq "7" "$(<"$rp_root/unrelated/value")" \
    "targeted repair leaves unrelated runtime kernel policy untouched"
assert_eq "8" "$(<"$ipv6_root/unrelated/value")" \
    "targeted repair leaves unrelated IPv6 runtime policy untouched"

printf '2\n' > "$rp_root/all/rp_filter"
printf '2\n' > "$rp_root/test0/rp_filter"
printf '0\n' > "$rp_root/test0/drop_gratuitous_arp"
printf '0\n' > "$rp_root/test0/drop_unicast_in_l2_multicast"
printf '0\n' > "$ipv6_root/test0/drop_unicast_in_l2_multicast"
assert_cmd_success "awaited pre-up ingress-policy repair succeeds" \
    env NOID_TEST_MODE=1 NOID_TEST_IPV4_CONF_ROOT="$rp_root" \
    NOID_TEST_IPV6_CONF_ROOT="$ipv6_root" \
    bash "$TMPDIR/sysctl-reapply.sh" test0 pre-up
assert_eq "1:1:1:1:1" \
    "$(<"$rp_root/all/rp_filter"):$(<"$rp_root/test0/rp_filter"):$(<"$rp_root/test0/drop_gratuitous_arp"):$(<"$rp_root/test0/drop_unicast_in_l2_multicast"):$(<"$ipv6_root/test0/drop_unicast_in_l2_multicast")" \
    "pre-up closes all five targeted policy nodes before full activation"

printf '2\n' > "$rp_root/all/rp_filter"
printf '2\n' > "$rp_root/test0/rp_filter"
printf '0\n' > "$rp_root/test0/drop_gratuitous_arp"
printf '0\n' > "$rp_root/test0/drop_unicast_in_l2_multicast"
printf '0\n' > "$ipv6_root/test0/drop_unicast_in_l2_multicast"
assert_cmd_success "IPv6-only event is ignored" \
    env NOID_TEST_MODE=1 NOID_TEST_IPV4_CONF_ROOT="$rp_root" \
    NOID_TEST_IPV6_CONF_ROOT="$ipv6_root" \
    bash "$TMPDIR/sysctl-reapply.sh" test0 dhcp6-change
assert_eq "2" "$(<"$rp_root/all/rp_filter")" \
    "IPv6-only event does not rewrite global rp_filter"
assert_eq "2" "$(<"$rp_root/test0/rp_filter")" \
    "IPv6-only event does not rewrite interface rp_filter"
assert_eq "0" "$(<"$rp_root/test0/drop_gratuitous_arp")" \
    "IPv6-only event does not rewrite the IPv4 gratuitous-ARP filter"
assert_eq "0" "$(<"$rp_root/test0/drop_unicast_in_l2_multicast")" \
    "IPv6-only event does not rewrite the IPv4 GTK frame filter"
assert_eq "0" "$(<"$ipv6_root/test0/drop_unicast_in_l2_multicast")" \
    "IPv6-only event alone does not rewrite the IPv6 GTK frame filter"

assert_cmd_failure "invalid interface name fails closed before procfs access" \
    env NOID_TEST_MODE=1 NOID_TEST_IPV4_CONF_ROOT="$rp_root" \
    NOID_TEST_IPV6_CONF_ROOT="$ipv6_root" \
    bash "$TMPDIR/sysctl-reapply.sh" ../escape up
assert_eq "2" "$(<"$rp_root/all/rp_filter")" \
    "invalid interface input cannot select a procfs path"
assert_cmd_failure "dot-dot interface cannot traverse the procfs policy root" \
    env NOID_TEST_MODE=1 NOID_TEST_IPV4_CONF_ROOT="$rp_root" \
    NOID_TEST_IPV6_CONF_ROOT="$ipv6_root" \
    bash "$TMPDIR/sysctl-reapply.sh" .. up

mkdir -p "$rp_root/v4only"
printf '2\n' > "$rp_root/v4only/rp_filter"
printf '0\n' > "$rp_root/v4only/drop_gratuitous_arp"
printf '0\n' > "$rp_root/v4only/drop_unicast_in_l2_multicast"
assert_cmd_success "an interface without an IPv6 procfs node is tolerated" \
    env NOID_TEST_MODE=1 NOID_TEST_IPV4_CONF_ROOT="$rp_root" \
    NOID_TEST_IPV6_CONF_ROOT="$ipv6_root" \
    bash "$TMPDIR/sysctl-reapply.sh" v4only up
assert_eq "1:1:1" \
    "$(<"$rp_root/v4only/rp_filter"):$(<"$rp_root/v4only/drop_gratuitous_arp"):$(<"$rp_root/v4only/drop_unicast_in_l2_multicast")" \
    "IPv4 policy is repaired even when the interface has no IPv6 node"

printf '2\n' > "$rp_root/all/rp_filter"
assert_cmd_success "removed interface is tolerated after global repair" \
    env NOID_TEST_MODE=1 NOID_TEST_IPV4_CONF_ROOT="$rp_root" \
    NOID_TEST_IPV6_CONF_ROOT="$ipv6_root" \
    bash "$TMPDIR/sysctl-reapply.sh" gone0 up
assert_eq "1" "$(<"$rp_root/all/rp_filter")" \
    "global policy is repaired even when the event interface disappeared"

missing_root="$TMPDIR/rp-filter-missing-global"
mkdir -p "$missing_root/test0"
printf '2\n' > "$missing_root/test0/rp_filter"
assert_cmd_failure "missing global rp_filter policy fails visibly" \
    env NOID_TEST_MODE=1 NOID_TEST_IPV4_CONF_ROOT="$missing_root" \
    NOID_TEST_IPV6_CONF_ROOT="$ipv6_root" \
    bash "$TMPDIR/sysctl-reapply.sh" test0 up
assert_cmd_failure "test mode rejects an incomplete dual-stack root override" \
    env NOID_TEST_MODE=1 NOID_TEST_IPV4_CONF_ROOT="$rp_root" \
    bash "$TMPDIR/sysctl-reapply.sh" test0 up
assert_grep_fixed 'pre-up|up|dhcp4-change|reapply' \
    "$TMPDIR/connection-defaults.sh" \
    "DHCP renewals and profile reapplication trigger route-policy enforcement"
assert_grep_fixed 'dhcp4-change|reapply)' "$TMPDIR/connection-defaults.sh" \
    "native renewal/reapply events share the route-policy path"
assert_grep_fixed 'DHCP route policy re-enforced' \
    "$TMPDIR/connection-defaults.sh"
assert_not_grep_extended '^[[:space:]]*sleep[[:space:]]' \
    "$TMPDIR/connection-defaults.sh" \
    "DHCP route enforcement contains no fixed-delay synchronization guess"
assert_grep_fixed 'nmcli device reapply "$INTERFACE"' "$TMPDIR/connection-defaults.sh" \
    "persistent settings are applied synchronously"
assert_not_grep 'nmcli connection up.*[&]' "$TMPDIR/connection-defaults.sh" \
    "no success marker races a background reconnect"
assert_not_grep 'ip -4 route del.*[|][|][[:space:]]*true' "$TMPDIR/connection-defaults.sh" \
    "DHCP route deletion failure is not swallowed"
assert_grep_fixed 'read -r -a route_args <<< "$route"' \
    "$TMPDIR/connection-defaults.sh" \
    "DHCP route text is converted to an argv array without eval"
assert_grep_fixed 'ip -4 route del "${delete_args[@]}"' \
    "$TMPDIR/connection-defaults.sh" \
    "DHCP route deletion uses the filtered, quoted argv"
assert_grep_fixed 'delete_args+=(dev "$INTERFACE")' \
    "$TMPDIR/connection-defaults.sh" \
    "DHCP route deletion remains bound to the enumerated interface"
assert_grep_fixed '[ "$token" = linkdown ] || [ "$token" = dead ]' \
    "$TMPDIR/connection-defaults.sh" \
    "display-only nexthop state is removed before route deletion"
assert_not_grep 'ip -4 route del $route' "$TMPDIR/connection-defaults.sh" \
    "DHCP-provided route text is never expanded as an unquoted shell word"
assert_grep_fixed 'FAIL: cannot enumerate physical-link DHCP routes' \
    "$TMPDIR/connection-defaults.sh" \
    "DHCP route enumeration has a visible failure path"
assert_grep_fixed 'block-lan-out covers RFC1918' "$TMPDIR/connection-defaults.sh" \
    "TunnelVision layering names the static LAN egress control"
assert_not_grep 'next-hops' "$TMPDIR/connection-defaults.sh" \
    "destination filtering is not mislabeled as next-hop filtering"
assert_grep_fixed 'IPV4_METHOD" != "link-local"' "$TMPDIR/connection-defaults.sh" \
    "link-local profiles bypass invalid DNS/DHCP mutations"
assert_grep_fixed 'NOID_NM_DEFAULTS_STATE_DIR:-/var/lib/NetworkManager/noid-defaults' \
    "$TMPDIR/connection-defaults.sh" \
    "dispatcher state location is isolated for functional tests"
assert_grep_fixed 'flock --exclusive 9' "$TMPDIR/connection-defaults.sh" \
    "concurrent events for one UUID are serialized"
assert_grep_fixed 'if ! PROFILE_UUIDS=$(nmcli -t -e no -f UUID connection show' \
    "$TMPDIR/connection-defaults.sh" \
    "stale-event classification requires a successful full profile enumeration"
assert_grep_fixed 'grep -Fqx -- "$UUID" <<< "$PROFILE_UUIDS"' \
    "$TMPDIR/connection-defaults.sh" \
    "stale-event classification compares the complete UUID exactly"
assert_grep_fixed '^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$' \
    "$TMPDIR/connection-defaults.sh" \
    "dispatcher state and lock names require NetworkManager's canonical UUID format"
assert_grep_fixed 'FAIL: cannot determine type for an existing connection' \
    "$TMPDIR/connection-defaults.sh" \
    "a present profile with an unreadable type remains fail-closed"
assert_grep_fixed 'publish_state || exit 1' "$TMPDIR/connection-defaults.sh" \
    "state publication failure cannot be logged as success"
assert_eq "1" \
    "$(grep -cF 'publish_state || exit 1' "$TMPDIR/connection-defaults.sh")" \
    "only the persistent profile branch publishes one-shot completion"
assert_grep_fixed 'if [ "$LIVE_MODE" != 1 ] && [ -f "$STATE_FILE" ]; then' \
    "$TMPDIR/connection-defaults.sh" \
    "Live runtime state cannot be skipped by a persistent completion marker"
assert_grep_fixed \
    'Live DHCP renewal: reasserting complete runtime physical-link policy' \
    "$TMPDIR/connection-defaults.sh" \
    "Live DHCP renewal explicitly continues into complete DNS/profile hardening"
assert_grep_fixed \
    'Live-Mode runtime hardening reasserted on a physical connection' \
    "$TMPDIR/connection-defaults.sh" \
    "Live completion evidence describes repeatable runtime enforcement"
assert_grep_fixed \
    'Live DHCP security policy restored without recursive profile mutation' \
    "$TMPDIR/connection-defaults.sh" \
    "Live DHCP restores enforcement without recursively restarting DHCP"
assert_grep_fixed 'if [ "$ACTION" = up ]; then' \
    "$TMPDIR/connection-defaults.sh" \
    "only the final Live activation event mirrors policy into the NM profile"
assert_grep_fixed 'nmcli connection modify --temporary uuid "$UUID"' \
    "$TMPDIR/connection-defaults.sh" \
    "Live profile mirroring uses NetworkManager's native runtime-only form"
assert_grep_fixed 'nmcli device modify "$INTERFACE"' \
    "$TMPDIR/connection-defaults.sh" \
    "Live active IPv6 reconciliation uses NetworkManager's native runtime-only form"
assert_grep_fixed 'ipv6.method disabled >/dev/null 2>&1' \
    "$TMPDIR/connection-defaults.sh" \
    "Live active reconciliation is limited to the stale IPv6 method"
assert_grep_fixed 'if [ "$LIVE_PROFILE_IPV6_METHOD" != disabled ]' \
    "$TMPDIR/connection-defaults.sh" \
    "an already-disabled Live profile does not trigger a redundant reapply event"
assert_eq "1" "$(grep -cF 'nmcli device reapply "$INTERFACE"' \
    "$TMPDIR/connection-defaults.sh")" \
    "only the installed persistent profile path uses the maintained reapply operation"
assert_not_grep 'FAIL: live runtime profile reapply failed' \
    "$TMPDIR/connection-defaults.sh" \
    "Live profile mirroring has no DHCP-restarting reapply path"
assert_not_grep 'touch "$STATE_FILE"' "$TMPDIR/connection-defaults.sh" \
    "one-shot completion is not published by an unchecked touch"
assert_grep_fixed 'persist_profile_metadata || exit 1' "$TMPDIR/connection-defaults.sh" \
    "non-reapplicable metadata is persisted only in its checked final phase"
assert_grep_fixed 'queue_account_scope_reconciliation || exit 1' \
    "$TMPDIR/connection-defaults.sh" \
    "later first-up profiles queue active/saved permission reconciliation"
assert_grep_fixed 'nm-physical-profiles-scope-pending.flag' \
    "$TMPDIR/connection-defaults.sh" \
    "dispatcher publishes an explicit account-scope pending generation"
assert_grep_fixed 'flock --exclusive 8' "$TMPDIR/connection-defaults.sh" \
    "dispatcher serializes pending publication with scoper finalization"
assert_grep_fixed '"$systemctl_bin" --no-block restart' \
    "$TMPDIR/connection-defaults.sh" \
    "permission reconciliation does not wait for helper completion"
assert_grep_fixed 'noid-nm-scope-physical-profiles.timer' \
    "$TMPDIR/connection-defaults.sh" \
    "dispatcher reuses the bounded account-scoper timer"
assert_grep_fixed 'rm -f -- "$scope_flag"' "$TMPDIR/connection-defaults.sh" \
    "new profile reconciliation invalidates stale all-profile evidence"
assert_grep_fixed 'NOID_TEST_NM_SCOPE_FLAG' "$TMPDIR/connection-defaults.sh" \
    "account-scope test path cannot mutate the production completion flag"
assert_grep_fixed 'NOID_TEST_CMDLINE_FILE' "$TMPDIR/connection-defaults.sh" \
    "dispatcher fixture cannot inherit the host kernel command line"
assert_grep_fixed 'if ! KERNEL_CMDLINE=$(<"$CMDLINE_FILE") || [ -z "$KERNEL_CMDLINE" ]; then' \
    "$TMPDIR/connection-defaults.sh" \
    "dispatcher fails visibly when the kernel command line is unreadable or empty"
assert_grep_fixed 'case " $KERNEL_CMDLINE " in' \
    "$TMPDIR/connection-defaults.sh" \
    "Live-image detection compares complete kernel-command-line tokens"
assert_grep_fixed '*" rd.live.image "*) LIVE_MODE=1 ;;' \
    "$TMPDIR/connection-defaults.sh" \
    "only the exact rd.live.image token selects the Live path"
assert_not_grep "grep -q 'rd\\\\.live\\\\.image'" \
    "$TMPDIR/connection-defaults.sh" \
    "a lookalike kernel argument cannot select the Live path"
assert_grep_fixed 'if ! passwd_db=$(getent passwd 2>/dev/null); then' \
    "$TMPDIR/connection-defaults.sh" \
    "NSS enumeration failure cannot be mistaken for a pending local user"
assert_grep_fixed 'while IFS=: read -r name _ uid _ _ home shell; do' \
    "$TMPDIR/connection-defaults.sh" \
    "dispatcher selects the completed account with the scoper's native fields"
assert_grep_fixed "marker_stat=\$(stat -c '%u:%Y:%F' -- \"\$marker\"" \
    "$TMPDIR/connection-defaults.sh" \
    "dispatcher uses the same single-snapshot GIS evidence as the scoper"
assert_not_grep '\$3 == 1000' "$TMPDIR/connection-defaults.sh" \
    "dispatcher does not hard-code a UID that can disagree with the scoper"
assert_grep_fixed "grep -q '^liveuser:' <<< \"\$passwd_db\"" \
    "$TMPDIR/connection-defaults.sh" \
    "dispatcher reuses its complete NSS snapshot for stale-liveuser trust"
assert_not_grep 'getent passwd liveuser' "$TMPDIR/connection-defaults.sh" \
    "dispatcher has no second fallible NSS decision"
assert_grep_fixed 'gnome-initial-setup-done' "$TMPDIR/nm-scope.sh" \
    "account-completion retry waits for the installed user workflow"
assert_grep_fixed 'export LC_ALL=C' "$TMPDIR/nm-scope.sh" \
    "account-scoper parsing is locale-independent"
assert_grep_fixed "marker_stat=\$(stat -c '%u:%Y:%F' -- \"\$marker\"" \
    "$TMPDIR/nm-scope.sh" \
    "account completion uses one checked marker metadata snapshot"
assert_not_grep 'stat -c %u "$marker"\|stat -c %Y "$marker"' \
    "$TMPDIR/nm-scope.sh" \
    "account completion has no split owner/mtime race window"
assert_grep_fixed '[[ "$marker_mtime" =~ ^[0-9]+$ ]] || continue' \
    "$TMPDIR/nm-scope.sh" \
    "account completion rejects a malformed marker timestamp"
assert_grep_fixed '"$NMCLI" -e no -g connection.permissions' "$TMPDIR/nm-scope.sh" \
    "profile scoper disables nmcli colon escaping before its postcondition"
assert_grep_fixed 'FAIL: cannot read physical-profile permissions' \
    "$TMPDIR/nm-scope.sh" "profile scoper logs initial permission-read failure"
assert_grep_fixed 'FAIL: cannot persist physical-profile permissions' \
    "$TMPDIR/nm-scope.sh" "profile scoper logs permission-write failure"
assert_grep_fixed 'FAIL: cannot verify physical-profile permissions' \
    "$TMPDIR/nm-scope.sh" "profile scoper logs permission-postread failure"
assert_not_grep 'current=\$(nmcli -g connection.permissions' "$TMPDIR/nm-scope.sh" \
    "profile scoper has no escaped-value read path"
assert_grep_fixed 'if ! profile_list=$("$NMCLI" -t -f UUID,TYPE connection show)' \
    "$TMPDIR/nm-scope.sh" "profile enumeration failure is not hidden by process substitution"
assert_grep_fixed 'if ! active_profiles=$("$NMCLI" -t -f UUID,DEVICE connection show --active)' \
    "$TMPDIR/nm-scope.sh" "active-profile enumeration failure is explicit"
assert_grep_fixed '"$NMCLI" connection up uuid "$uuid" ifname "$active_device"' \
    "$TMPDIR/nm-scope.sh" "permission mismatch triggers controlled active-profile reconciliation"
assert_grep_fixed '"$NMCLI" device reapply "$active_device"' \
    "$TMPDIR/nm-scope.sh" "active-profile reconciliation has a checked reapply postcondition"
assert_grep_fixed 'OnUnitActiveSec=2min' "$TMPDIR/nm-scope.timer" \
    "account-completion race remains retryable"
assert_grep_fixed '"$SYSTEMCTL" stop noid-nm-scope-physical-profiles.timer' \
    "$TMPDIR/nm-scope.sh" \
    "successful account scoping stops the already-active retry timer"
assert_grep_fixed 'if [ -e "$PENDING" ]' "$TMPDIR/nm-scope.sh" \
    "account scoper checks pending evidence at both lifecycle gates"
assert_grep_fixed 'a physical profile changed during account scoping' \
    "$TMPDIR/nm-scope.sh" \
    "stale scoper enumeration cannot publish all-profile completion"
assert_grep_fixed 'FAIL: cannot publish account-scope completion flag' \
    "$TMPDIR/nm-scope.sh" \
    "account scoper cannot hide atomic completion-publication failure"
assert_grep_fixed 'ConditionPathExists=!/var/lib/noid-privacy/nm-physical-profiles-scoped.flag' \
    "$TMPDIR/nm-scope.service" \
    "completed account scoping is one-shot"
assert_grep_fixed 'ConditionKernelCommandLine=!rd.live.image' \
    "$TMPDIR/nm-scope.service" \
    "direct account-scoper activation is condition-skipped on Live media"
assert_grep_fixed 'ConditionKernelCommandLine=!rd.live.image' \
    "$TMPDIR/nm-scope.timer" \
    "account-scoper retry scheduling is condition-skipped on Live media"
assert_eq "2" "$(cat "$TMPDIR/nm-scope.service" "$TMPDIR/nm-scope.timer" \
    | grep -cFx 'ConditionKernelCommandLine=!rd.live.image')" \
    "both account-scoper units carry exactly one native Live guard"
assert_grep_fixed 'systemctl enable noid-nm-scope-physical-profiles.timer' "$KS_FILE" \
    "account-completion retry timer is enabled"
assert_grep_fixed 'verify_owned_regular()' "$KS_FILE" \
    "M23 verification has an exact root-owned regular-file primitive"
assert_grep_fixed 'has_exact_once()' "$KS_FILE" \
    "M23 verification has a single-assignment primitive"
for exact_default in \
    '[main]' \
    'hostname-mode=none' \
    '[connection-noid-ethernet-dns]' \
    'match-device=type:ethernet' \
    '[connection-noid-wifi-dns]' \
    'match-device=type:wifi' \
    '[connection]' \
    'connection.lldp=0' \
    'connection.mptcp-flags=1' \
    'connection.dns-over-tls=1' \
    'ipv4.dhcp-send-hostname=0' \
    'ipv4.dad-timeout=200' \
    'ipv4.link-local=2' \
    'ipv6.dhcp-send-hostname=0'; do
    assert_grep_fixed "has_exact_once '$exact_default'" "$KS_FILE" \
        "compose verification requires one exact $exact_default assignment"
done
assert_grep_fixed \
    "[ \"\$(grep -cFx 'connection.dns-over-tls=2'" "$KS_FILE" \
    "compose verification requires exactly two physical Strict DoT defaults"
assert_grep_fixed 'verify_owned_regular /usr/local/sbin/noid-nm-scope-physical-profiles 755' \
    "$KS_FILE" "account-completion helper metadata is verified"
assert_grep_fixed "grep -qFx 'ExecStart=/usr/local/sbin/noid-nm-scope-physical-profiles'" \
    "$KS_FILE" "account-completion service entrypoint is verified"
assert_eq "2" "$(grep -cF \
    "grep -qFx 'ConditionKernelCommandLine=!rd.live.image'" "$KS_FILE")" \
    "compose verification pins the Live guard on both account-scoper units"
assert_grep_fixed 'systemctl is-enabled --quiet noid-nm-scope-physical-profiles.timer' \
    "$KS_FILE" "account-completion retry timer enablement is verified"
assert_grep_fixed 'account-completion scoper units pass systemd parser verification' \
    "$KS_FILE" "compose verification runs the real systemd unit parser"
assert_grep_fixed 'systemd-analyze verify --recursive-errors=no' "$KS_FILE" \
    "M23 parser result is scoped to M23-owned unit errors"
assert_not_grep '/etc/NetworkManager/system-connections' "$TMPDIR/nm-scope.service" \
    "profile writes stay behind NetworkManager D-Bus instead of a direct /etc write grant"
assert_grep_fixed '../40-noid-connection-defaults' "$KS_FILE" \
    "physical pre-up registration has an exact relative-target postcondition"
assert_grep_fixed '../99-noid-sysctl-reapply' "$KS_FILE" \
    "ingress-policy pre-up registration has an exact relative-target postcondition"

# A physical connection remains physical even when an administrator gives its
# kernel interface a VPN-looking prefix. Native connection.type, not the
# mutable interface name, must select the drop-zone policy.
physical_name_calls="$TMPDIR/physical-name.calls"
physical_name_cmdline="$TMPDIR/physical-name.cmdline"
printf '%s\n' 'root=UUID=fixture quiet' > "$physical_name_cmdline"
: > "$physical_name_calls"
# shellcheck disable=SC2317,SC2329 # exported; invoked by the extracted dispatcher.
nmcli() {
    case "$*" in
        '-e no -g connection.type connection show 11111111-1111-4111-8111-111111111111')
            printf '%s\n' "$NOID_TEST_CONNECTION_TYPE" ;;
        '-g ipv4.method connection show 11111111-1111-4111-8111-111111111111')
            printf '%s\n' auto ;;
        *) return 1 ;;
    esac
}
# shellcheck disable=SC2317,SC2329 # exported; invoked by the extracted dispatcher.
function firewall-cmd() {
    printf '%s\n' "$*" >> "$NOID_TEST_PHYSICAL_NAME_CALLS"
}
# shellcheck disable=SC2317,SC2329 # exported; invoked by the extracted dispatcher.
logger() { return 0; }
export -f nmcli logger
export -f -- firewall-cmd
assert_cmd_success "VPN-looking physical interface reaches native type policy" \
    env CONNECTION_UUID=11111111-1111-4111-8111-111111111111 \
        NOID_TEST_MODE=1 \
        NOID_TEST_CMDLINE_FILE="$physical_name_cmdline" \
        NOID_NM_DEFAULTS_LOCK_DIR="$TMPDIR/physical-name-lock" \
        NOID_TEST_CONNECTION_TYPE=802-3-ethernet \
        NOID_TEST_PHYSICAL_NAME_CALLS="$physical_name_calls" \
        bash "$TMPDIR/connection-defaults.sh" wgphysical0 pre-up
assert_grep_fixed '--zone=drop --change-interface=wgphysical0' \
    "$physical_name_calls" \
    "VPN-looking physical interface is placed in the runtime drop zone"
: > "$physical_name_calls"
assert_cmd_success "physical-looking WireGuard profile remains outside physical policy" \
    env CONNECTION_UUID=11111111-1111-4111-8111-111111111111 \
        NOID_TEST_MODE=1 \
        NOID_TEST_CMDLINE_FILE="$physical_name_cmdline" \
        NOID_NM_DEFAULTS_LOCK_DIR="$TMPDIR/physical-name-lock" \
        NOID_TEST_CONNECTION_TYPE=wireguard \
        NOID_TEST_PHYSICAL_NAME_CALLS="$physical_name_calls" \
        bash "$TMPDIR/connection-defaults.sh" ethernet0 pre-up
assert_eq "0" "$(wc -l < "$physical_name_calls")" \
    "native WireGuard type is never placed in the physical drop zone"
unset -f nmcli logger firewall-cmd

# Simulate the marker disappearing at the exact old split-stat window. The
# new single lstat snapshot must treat it as pending and never enumerate or
# mutate NetworkManager profiles.
race_scope_home="$TMPDIR/race-scope-home"
race_scope_state="$TMPDIR/race-scope-state"
race_marker="$race_scope_home/.config/gnome-initial-setup-done"
race_nm_calls="$TMPDIR/race-scope-nm.calls"
mkdir -p "$race_scope_home/.config" "$race_scope_state"
: > "$race_marker"
: > "$race_nm_calls"
# shellcheck disable=SC2317,SC2329 # exported; invoked by the extracted helper.
getent() {
    printf '%s\n' "fixture:x:1000:1000::${NOID_TEST_RACE_HOME}:/bin/bash"
}
# shellcheck disable=SC2317,SC2329 # exported; invoked by the extracted helper.
stat() {
    case "$*" in
        "-c %u $NOID_TEST_RACE_MARKER")
            mv -- "$NOID_TEST_RACE_MARKER" \
                "$NOID_TEST_RACE_MARKER.disappeared"
            printf '%s\n' 1000
            ;;
        "-c %Y $NOID_TEST_RACE_MARKER")
            return 1
            ;;
        "-c %u:%Y:%F -- $NOID_TEST_RACE_MARKER")
            mv -- "$NOID_TEST_RACE_MARKER" \
                "$NOID_TEST_RACE_MARKER.disappeared"
            return 1
            ;;
        *)
            command stat "$@"
            ;;
    esac
}
# shellcheck disable=SC2317,SC2329 # exported; invoked by the extracted helper.
nmcli() {
    printf '%s\n' "$*" >> "$NOID_TEST_RACE_NM_CALLS"
    return 1
}
# shellcheck disable=SC2317,SC2329 # exported; invoked by the extracted helper.
logger() { return 0; }
export -f getent stat nmcli logger
assert_cmd_success "disappearing account marker remains pending evidence" \
    env NOID_NMCLI_BIN=nmcli \
        NOID_NM_SCOPE_STATE_DIR="$race_scope_state" \
        NOID_NM_SCOPE_LOCK="$TMPDIR/race-scope.lock" \
        NOID_TEST_RACE_HOME="$race_scope_home" \
        NOID_TEST_RACE_MARKER="$race_marker" \
        NOID_TEST_RACE_NM_CALLS="$race_nm_calls" \
        bash "$TMPDIR/nm-scope.sh"
assert_cmd_failure "disappearing account marker cannot seal completion" \
    test -e "$race_scope_state/nm-physical-profiles-scoped.flag"
assert_eq "0" "$(wc -l < "$race_nm_calls")" \
    "disappearing account marker cannot reach NetworkManager mutation"
unset -f getent stat nmcli logger

# Execute the full account-completion helper with an nmcli double that emits
# the same escaped-colon representation that exposed the live-VM regression
# unless `-e no` is supplied. A successful run must persist the one-shot flag.
scope_home="$TMPDIR/scope-home"
scope_state="$TMPDIR/scope-state"
scope_nm_state="$TMPDIR/scope-nm-state"
scope_nm_active_state="$TMPDIR/scope-nm-active-state"
scope_nm_calls="$TMPDIR/scope-nm-calls"
mkdir -p "$scope_home/.config" "$scope_state"
touch -d '2 minutes ago' "$scope_home/.config/gnome-initial-setup-done"
# Exported functions work even when the host's hardened /tmp is noexec.
# shellcheck disable=SC2317,SC2329 # exported; invoked by the extracted helper.
getent() {
    printf '%s\n' "fixture:x:1000:1000::${NOID_TEST_SCOPE_HOME}:/bin/bash"
}
# shellcheck disable=SC2317,SC2329 # exported; invoked by the extracted helper.
logger() { return 0; }
# shellcheck disable=SC2317,SC2329 # exported; invoked by the extracted helper.
systemctl() {
    printf '%s\n' "$*" >> "$NOID_TEST_SYSTEMCTL_CALLS"
}
# shellcheck disable=SC2317,SC2329 # exported; invoked by the extracted helper.
nmcli() {
printf '%s\n' "$*" >> "$NOID_TEST_NM_CALLS"
case "$*" in
    '-t -f UUID,TYPE connection show')
        printf '%s\n' 'fixture-uuid:802-3-ethernet' ;;
    '-t -f UUID,DEVICE connection show --active')
        printf '%s\n' 'fixture-uuid:test0' ;;
    '-e no -g connection.permissions connection show fixture-uuid')
        if [ -f "$NOID_TEST_NM_STATE" ]; then
            cat "$NOID_TEST_NM_STATE"
        else
            printf '%s\n' "${NOID_TEST_INITIAL_PERMISSION:-}"
        fi ;;
    'connection modify fixture-uuid connection.permissions user:fixture')
        printf '%s\n' 'user:fixture' > "$NOID_TEST_NM_STATE"
        if [ "${NOID_TEST_INJECT_SCOPE_PENDING:-0}" = 1 ]; then
            : > "$NOID_TEST_SCOPE_PENDING"
        fi
        ;;
    'device reapply test0')
        [ -f "$NOID_TEST_NM_ACTIVE_STATE" ] ;;
    'connection up uuid fixture-uuid ifname test0')
        : > "$NOID_TEST_NM_ACTIVE_STATE" ;;
    *) return 1 ;;
esac
}
export -f getent logger nmcli systemctl
assert_cmd_success "account scoper accepts canonical unescaped NM permission" \
    env NOID_NMCLI_BIN=nmcli \
        NOID_NM_SCOPE_STATE_DIR="$scope_state" \
        NOID_NM_SCOPE_LOCK="$TMPDIR/scope.lock" \
        NOID_SYSTEMCTL_BIN=systemctl \
        NOID_TEST_SCOPE_HOME="$scope_home" \
        NOID_TEST_NM_STATE="$scope_nm_state" \
        NOID_TEST_NM_ACTIVE_STATE="$scope_nm_active_state" \
        NOID_TEST_NM_CALLS="$scope_nm_calls" \
        NOID_TEST_SYSTEMCTL_CALLS="$TMPDIR/systemctl.calls" \
        bash "$TMPDIR/nm-scope.sh"
assert_file_exists "$scope_state/nm-physical-profiles-scoped.flag" \
    "successful scoping publishes its atomic one-shot flag"
assert_eq "755" "$(stat -c '%a' "$scope_state")" \
    "profile scoper preserves unprivileged access to shared status files"
assert_eq "600" "$(stat -c '%a' "$scope_state/nm-physical-profiles-scoped.flag")" \
    "profile scoper keeps its own one-shot flag private"
assert_grep_fixed '-e no -g connection.permissions connection show fixture-uuid' \
    "$scope_nm_calls" "functional scoper requests unescaped permission values"
assert_eq "2" "$(grep -c '^device reapply test0$' "$scope_nm_calls")" \
    "account scoper verifies reapply before and after reconciliation"
assert_grep_fixed 'connection up uuid fixture-uuid ifname test0' \
    "$scope_nm_calls" "account scoper reactivates the mismatched active profile"
assert_grep_fixed 'stop noid-nm-scope-physical-profiles.timer' \
    "$TMPDIR/systemctl.calls" "functional scoper stops its retry timer"

# A physical profile queued after this scoper's enumeration began makes the
# pass stale. The pending generation must survive, the all-profile flag must
# remain absent and the retry timer must stay armed.
rm -f "$scope_state/nm-physical-profiles-scoped.flag" \
    "$scope_state/nm-physical-profiles-scope-pending.flag" \
    "$scope_nm_state" "$scope_nm_active_state"
: > "$scope_nm_calls"
: > "$TMPDIR/systemctl.calls"
assert_cmd_success "concurrent profile queue keeps scoper pass pending" \
    env NOID_NMCLI_BIN=nmcli \
        NOID_NM_SCOPE_STATE_DIR="$scope_state" \
        NOID_NM_SCOPE_LOCK="$TMPDIR/scope.lock" \
        NOID_SYSTEMCTL_BIN=systemctl \
        NOID_TEST_INJECT_SCOPE_PENDING=1 \
        NOID_TEST_SCOPE_PENDING="$scope_state/nm-physical-profiles-scope-pending.flag" \
        NOID_TEST_SCOPE_HOME="$scope_home" \
        NOID_TEST_NM_STATE="$scope_nm_state" \
        NOID_TEST_NM_ACTIVE_STATE="$scope_nm_active_state" \
        NOID_TEST_NM_CALLS="$scope_nm_calls" \
        NOID_TEST_SYSTEMCTL_CALLS="$TMPDIR/systemctl.calls" \
        bash "$TMPDIR/nm-scope.sh"
assert_file_exists "$scope_state/nm-physical-profiles-scope-pending.flag" \
    "concurrent dispatcher generation survives stale scoper pass"
assert_cmd_failure "stale scoper pass cannot publish completion" \
    test -e "$scope_state/nm-physical-profiles-scoped.flag"
assert_not_grep 'stop noid-nm-scope-physical-profiles.timer' \
    "$TMPDIR/systemctl.calls" \
    "stale scoper pass leaves its retry timer armed"

# A failure in the atomic completion rename happens after the timer stop. It
# must leave no false completion evidence and explicitly re-arm the timer.
rm -f "$scope_state/nm-physical-profiles-scoped.flag" \
    "$scope_state/nm-physical-profiles-scope-pending.flag" \
    "$scope_nm_state" "$scope_nm_active_state"
: > "$scope_nm_calls"
: > "$TMPDIR/systemctl.calls"
# shellcheck disable=SC2317,SC2329 # exported; invoked by the extracted helper.
mv() {
    local target="${*: -1}"
    [ "$target" != "$NOID_TEST_FAIL_PUBLISH_TARGET" ] || return 1
    command mv "$@"
}
export -f mv
publish_failure_rc=0
env NOID_NMCLI_BIN=nmcli \
    NOID_NM_SCOPE_STATE_DIR="$scope_state" \
    NOID_NM_SCOPE_LOCK="$TMPDIR/scope.lock" \
    NOID_SYSTEMCTL_BIN=systemctl \
    NOID_TEST_FAIL_PUBLISH_TARGET="$scope_state/nm-physical-profiles-scoped.flag" \
    NOID_TEST_SCOPE_HOME="$scope_home" \
    NOID_TEST_NM_STATE="$scope_nm_state" \
    NOID_TEST_NM_ACTIVE_STATE="$scope_nm_active_state" \
    NOID_TEST_NM_CALLS="$scope_nm_calls" \
    NOID_TEST_SYSTEMCTL_CALLS="$TMPDIR/systemctl.calls" \
    bash "$TMPDIR/nm-scope.sh" || publish_failure_rc=$?
if [ "$publish_failure_rc" -ne 0 ] \
   && [ ! -e "$scope_state/nm-physical-profiles-scoped.flag" ]; then
    _pass "completion publish failure remains fail-visible without false evidence"
else
    _fail "completion publish failure was hidden or falsely sealed"
fi
assert_grep_fixed 'stop noid-nm-scope-physical-profiles.timer' \
    "$TMPDIR/systemctl.calls" \
    "completion publication follows a checked timer stop"
assert_grep_fixed 'start noid-nm-scope-physical-profiles.timer' \
    "$TMPDIR/systemctl.calls" \
    "completion publish failure explicitly re-arms the retry timer"
unset -f mv

# A profile copied from the Live image is the one reviewed nonempty legacy
# scope that may be adopted, and only after the liveuser account is absent.
rm -f "$scope_state/nm-physical-profiles-scoped.flag" "$scope_nm_state" \
    "$scope_nm_active_state"
: > "$scope_nm_calls"
assert_cmd_success "account scoper adopts the exact stale liveuser permission" \
    env NOID_NMCLI_BIN=nmcli \
        NOID_NM_SCOPE_STATE_DIR="$scope_state" \
        NOID_NM_SCOPE_LOCK="$TMPDIR/scope.lock" \
        NOID_SYSTEMCTL_BIN=systemctl \
        NOID_TEST_SCOPE_HOME="$scope_home" \
        NOID_TEST_INITIAL_PERMISSION=user:liveuser \
        NOID_TEST_NM_STATE="$scope_nm_state" \
        NOID_TEST_NM_ACTIVE_STATE="$scope_nm_active_state" \
        NOID_TEST_NM_CALLS="$scope_nm_calls" \
        NOID_TEST_SYSTEMCTL_CALLS="$TMPDIR/systemctl.calls" \
        bash "$TMPDIR/nm-scope.sh"
assert_eq user:fixture "$(cat "$scope_nm_state")" \
    "stale liveuser permission is replaced with the completed account"

rm -f "$scope_state/nm-physical-profiles-scoped.flag" "$scope_nm_state" \
    "$scope_nm_active_state"
: > "$scope_nm_calls"
foreign_rc=0
env NOID_NMCLI_BIN=nmcli \
    NOID_NM_SCOPE_STATE_DIR="$scope_state" \
    NOID_NM_SCOPE_LOCK="$TMPDIR/scope.lock" \
    NOID_SYSTEMCTL_BIN=systemctl \
    NOID_TEST_SCOPE_HOME="$scope_home" \
    NOID_TEST_INITIAL_PERMISSION=user:someone-else \
    NOID_TEST_NM_STATE="$scope_nm_state" \
    NOID_TEST_NM_ACTIVE_STATE="$scope_nm_active_state" \
    NOID_TEST_NM_CALLS="$scope_nm_calls" \
    NOID_TEST_SYSTEMCTL_CALLS="$TMPDIR/systemctl.calls" \
    bash "$TMPDIR/nm-scope.sh" || foreign_rc=$?
if [ "$foreign_rc" -ne 0 ] \
   && [ ! -e "$scope_state/nm-physical-profiles-scoped.flag" ] \
   && ! grep -q '^connection modify fixture-uuid connection.permissions' \
        "$scope_nm_calls"; then
    _pass "foreign NetworkManager permissions are preserved and fail visible"
else
    _fail "foreign NetworkManager permission was overwritten or falsely sealed"
fi
unset -f getent logger nmcli systemctl

# NetworkManager documents that every already-queued dispatcher event runs
# even if a later event made it obsolete. Exercise the exact three-way trust
# boundary: proven-removed UUID succeeds, failed enumeration fails, and a
# still-present UUID with an unreadable type also fails.
stale_log="$TMPDIR/stale-event.log"
stale_cmdline="$TMPDIR/stale.cmdline"
printf '%s\n' 'root=UUID=fixture quiet' > "$stale_cmdline"
# shellcheck disable=SC2317,SC2329 # exported; invoked by the extracted dispatcher.
logger() {
    printf '%s\n' "$*" >> "$NOID_TEST_STALE_LOG"
}
# shellcheck disable=SC2317,SC2329 # exported; invoked by the extracted dispatcher.
nmcli() {
    case "$*" in
        '-e no -g connection.type connection show 22222222-2222-4222-8222-222222222222')
            return 10 ;;
        '-t -e no -f UUID connection show')
            case "${NOID_TEST_STALE_MODE:-}" in
                removed) printf '%s\n' other-profile ;;
                present) printf '%s\n' 22222222-2222-4222-8222-222222222222 ;;
                broken) return 10 ;;
                *) return 11 ;;
            esac
            ;;
        *) return 12 ;;
    esac
}
export -f logger nmcli
: > "$stale_log"
: > "$TMPDIR/empty.cmdline"
assert_cmd_failure "empty kernel command line fails closed before profile mutation" \
    env CONNECTION_UUID=22222222-2222-4222-8222-222222222222 \
        NOID_TEST_MODE=1 \
        NOID_TEST_CMDLINE_FILE="$TMPDIR/empty.cmdline" \
        NOID_NM_DEFAULTS_STATE_DIR="$TMPDIR/stale-state" \
        NOID_NM_DEFAULTS_LOCK_DIR="$TMPDIR/stale-lock" \
        NOID_TEST_STALE_LOG="$stale_log" \
        NOID_TEST_STALE_MODE=removed \
        bash "$TMPDIR/connection-defaults.sh" transient0 up
assert_cmd_failure "dot-dot connection UUID is rejected before path use" \
    env CONNECTION_UUID=.. \
        NOID_TEST_MODE=1 \
        NOID_TEST_CMDLINE_FILE="$stale_cmdline" \
        NOID_NM_DEFAULTS_STATE_DIR="$TMPDIR/stale-state" \
        NOID_NM_DEFAULTS_LOCK_DIR="$TMPDIR/stale-lock" \
        NOID_TEST_STALE_LOG="$stale_log" \
        NOID_TEST_STALE_MODE=removed \
        bash "$TMPDIR/connection-defaults.sh" transient0 up
assert_cmd_failure "noncanonical connection UUID is rejected before nmcli lookup" \
    env CONNECTION_UUID=fixture \
        NOID_TEST_MODE=1 \
        NOID_TEST_CMDLINE_FILE="$stale_cmdline" \
        NOID_NM_DEFAULTS_STATE_DIR="$TMPDIR/stale-state" \
        NOID_NM_DEFAULTS_LOCK_DIR="$TMPDIR/stale-lock" \
        NOID_TEST_STALE_LOG="$stale_log" \
        NOID_TEST_STALE_MODE=removed \
        bash "$TMPDIR/connection-defaults.sh" transient0 up
assert_cmd_success "proven-removed queued connection event is ignored" \
    env CONNECTION_UUID=22222222-2222-4222-8222-222222222222 \
        NOID_TEST_MODE=1 \
        NOID_TEST_CMDLINE_FILE="$stale_cmdline" \
        NOID_NM_DEFAULTS_STATE_DIR="$TMPDIR/stale-state" \
        NOID_NM_DEFAULTS_LOCK_DIR="$TMPDIR/stale-lock" \
        NOID_TEST_STALE_LOG="$stale_log" \
        NOID_TEST_STALE_MODE=removed \
        bash "$TMPDIR/connection-defaults.sh" transient0 up
assert_grep_fixed 'stale: skipping obsolete queued up event for a removed connection' \
    "$stale_log" "proven-obsolete event leaves explicit local evidence"
assert_cmd_failure "profile enumeration failure remains fail-closed" \
    env CONNECTION_UUID=22222222-2222-4222-8222-222222222222 \
        NOID_TEST_MODE=1 \
        NOID_TEST_CMDLINE_FILE="$stale_cmdline" \
        NOID_NM_DEFAULTS_STATE_DIR="$TMPDIR/stale-state" \
        NOID_NM_DEFAULTS_LOCK_DIR="$TMPDIR/stale-lock" \
        NOID_TEST_STALE_LOG="$stale_log" \
        NOID_TEST_STALE_MODE=broken \
        bash "$TMPDIR/connection-defaults.sh" transient0 up
assert_cmd_failure "existing profile with unreadable type remains fail-closed" \
    env CONNECTION_UUID=22222222-2222-4222-8222-222222222222 \
        NOID_TEST_MODE=1 \
        NOID_TEST_CMDLINE_FILE="$stale_cmdline" \
        NOID_NM_DEFAULTS_STATE_DIR="$TMPDIR/stale-state" \
        NOID_NM_DEFAULTS_LOCK_DIR="$TMPDIR/stale-lock" \
        NOID_TEST_STALE_LOG="$stale_log" \
        NOID_TEST_STALE_MODE=present \
        bash "$TMPDIR/connection-defaults.sh" transient0 up
unset -f logger nmcli

# A profile reapply is a native NetworkManager event, not a timer surrogate.
# Prove it bypasses the existing one-shot marker, preserves the DHCP default
# route, removes a non-default Option-121 route and performs no profile rewrite.
ROUTE_CALLS="$TMPDIR/reapply-route.calls"
NM_REAPPLY_CALLS="$TMPDIR/reapply-nmcli.calls"
REAPPLY_STATE="$TMPDIR/reapply-state"
export ROUTE_CALLS NM_REAPPLY_CALLS
mkdir -p "$REAPPLY_STATE"
: > "$REAPPLY_STATE/11111111-1111-4111-8111-111111111111"
: > "$ROUTE_CALLS"
: > "$NM_REAPPLY_CALLS"
# shellcheck disable=SC2317,SC2329 # exported; invoked by the extracted dispatcher.
nmcli() {
    printf '%s\n' "$*" >> "$NM_REAPPLY_CALLS"
    case "$*" in
        '-e no -g connection.type connection show 11111111-1111-4111-8111-111111111111')
            printf '%s\n' '802-3-ethernet' ;;
        '-g ipv4.method connection show 11111111-1111-4111-8111-111111111111')
            printf '%s\n' 'auto' ;;
        *) return 1 ;;
    esac
}
# shellcheck disable=SC2317,SC2329 # exported; invoked by the extracted dispatcher.
function firewall-cmd() { return 0; }
# shellcheck disable=SC2317,SC2329 # exported; invoked by the extracted dispatcher.
ip() {
    case "$*" in
        '-4 route show dev test0 proto dhcp')
            printf '%s\n' \
                'default via 192.0.2.1 proto dhcp metric 100 linkdown' \
                '198.51.100.0/24 via 192.0.2.1 proto dhcp metric 100 linkdown' \
                '203.0.113.0/24 via 192.0.2.1 proto dhcp metric 101 dead'
            ;;
        '-4 route del 198.51.100.0/24 via 192.0.2.1 proto dhcp metric 100 dev test0'|\
        '-4 route del 203.0.113.0/24 via 192.0.2.1 proto dhcp metric 101 dev test0')
            printf '%s\n' "$*" >> "$ROUTE_CALLS"
            ;;
        *) return 1 ;;
    esac
}
# shellcheck disable=SC2317,SC2329 # exported; invoked by the extracted dispatcher.
logger() { return 0; }
export -f nmcli ip logger
export -f -- firewall-cmd
assert_cmd_success "reapply event enforces DHCP routes despite one-shot marker" \
    env CONNECTION_UUID=11111111-1111-4111-8111-111111111111 \
        NOID_TEST_MODE=1 \
        NOID_TEST_CMDLINE_FILE="$stale_cmdline" \
        NOID_NM_DEFAULTS_STATE_DIR="$REAPPLY_STATE" \
        NOID_NM_DEFAULTS_LOCK_DIR="$TMPDIR/reapply-lock" \
        bash "$TMPDIR/connection-defaults.sh" test0 reapply
assert_eq "2" "$(wc -l < "$ROUTE_CALLS")" \
    "reapply removes both non-default DHCP routes with display-only state"
assert_grep_fixed \
    '-4 route del 198.51.100.0/24 via 192.0.2.1 proto dhcp metric 100 dev test0' \
    "$ROUTE_CALLS" "reapply strips linkdown and restores the interface binding"
assert_grep_fixed \
    '-4 route del 203.0.113.0/24 via 192.0.2.1 proto dhcp metric 101 dev test0' \
    "$ROUTE_CALLS" "reapply strips dead and restores the interface binding"
assert_not_grep 'route del default' "$ROUTE_CALLS" \
    "reapply preserves the DHCP default route"
assert_not_grep 'linkdown\|dead' "$ROUTE_CALLS" \
    "display-only route flags are never replayed into ip route del"
assert_not_grep 'connection modify\|device reapply' "$NM_REAPPLY_CALLS" \
    "event-driven route cleanup does not recursively mutate the profile"
assert_file_exists "$REAPPLY_STATE/11111111-1111-4111-8111-111111111111" \
    "event-driven route cleanup leaves the existing one-shot marker intact"
unset -f nmcli ip logger firewall-cmd

# Live-media mutations are D-Bus/runtime-only. Prove that an existing marker
# cannot suppress either a DHCP-renewal reassertion or the next connection-up
# reassertion, while reapply remains outside this complete mutation path.
LIVE_CALLS="$TMPDIR/live-reassert.calls"
LIVE_LOG="$TMPDIR/live-reassert.log"
LIVE_STATE="$TMPDIR/live-reassert-state"
LIVE_ROUTE_REMOVED="$TMPDIR/live-route-removed"
LIVE_UUID=33333333-3333-4333-8333-333333333333
export LIVE_CALLS LIVE_LOG LIVE_ROUTE_REMOVED LIVE_UUID
mkdir -p "$LIVE_STATE"
: > "$LIVE_STATE/$LIVE_UUID"
: > "$LIVE_CALLS"
: > "$LIVE_LOG"
printf '%s\n' 'root=live:LABEL=NOID rd.live.image quiet' \
    > "$TMPDIR/live.cmdline"
# shellcheck disable=SC2317,SC2329 # exported; invoked by the extracted dispatcher.
nmcli() {
    printf 'nmcli %s\n' "$*" >> "$LIVE_CALLS"
    case "$*" in
        "-e no -g connection.type connection show $LIVE_UUID")
            printf '%s\n' '802-3-ethernet' ;;
        "-g ipv4.method connection show $LIVE_UUID")
            printf '%s\n' 'auto' ;;
        "-g ipv6.method connection show $LIVE_UUID")
            printf '%s\n' "${NOID_TEST_LIVE_IPV6_METHOD:-auto}" ;;
        "connection modify --temporary uuid $LIVE_UUID "*) ;;
        "device modify test0 ipv6.method disabled")
            [ "${NOID_TEST_LIVE_DEVICE_MODIFY_FAIL:-0}" != 1 ] ;;
        *) return 1 ;;
    esac
}
# shellcheck disable=SC2317,SC2329 # exported; invoked by the extracted dispatcher.
function firewall-cmd() {
    printf 'firewall-cmd %s\n' "$*" >> "$LIVE_CALLS"
}
# shellcheck disable=SC2317,SC2329 # exported; invoked by the extracted dispatcher.
resolvectl() {
    printf 'resolvectl %s\n' "$*" >> "$LIVE_CALLS"
}
# shellcheck disable=SC2317,SC2329 # exported; invoked by the extracted dispatcher.
sysctl() {
    printf 'sysctl %s\n' "$*" >> "$LIVE_CALLS"
}
# shellcheck disable=SC2317,SC2329 # exported; invoked by the extracted dispatcher.
ip() {
    case "$*" in
        '-4 route show dev test0 proto dhcp')
            printf '%s\n' \
                'default via 192.0.2.1 dev test0 proto dhcp metric 100'
            if [ ! -e "$LIVE_ROUTE_REMOVED" ]; then
                printf '%s\n' \
                    '198.51.100.0/24 via 192.0.2.1 dev test0 proto dhcp metric 100'
            fi
            ;;
        '-4 route del 198.51.100.0/24 via 192.0.2.1 dev test0 proto dhcp metric 100')
            : > "$LIVE_ROUTE_REMOVED"
            printf 'ip %s\n' "$*" >> "$LIVE_CALLS"
            ;;
        '-6 addr flush dev test0'|'-6 route flush dev test0')
            printf 'ip %s\n' "$*" >> "$LIVE_CALLS"
            ;;
        *) return 1 ;;
    esac
}
# shellcheck disable=SC2317,SC2329 # exported; invoked by the extracted dispatcher.
logger() {
    printf '%s\n' "$*" >> "$LIVE_LOG"
}
export -f nmcli ip logger resolvectl sysctl
export -f -- firewall-cmd
for live_action in dhcp4-change up; do
    assert_cmd_success "Live $live_action reasserts runtime policy despite marker" \
        env CONNECTION_UUID="$LIVE_UUID" \
            NOID_TEST_MODE=1 \
            NOID_TEST_CMDLINE_FILE="$TMPDIR/live.cmdline" \
            NOID_NM_DEFAULTS_STATE_DIR="$LIVE_STATE" \
            NOID_NM_DEFAULTS_LOCK_DIR="$TMPDIR/live-reassert-lock" \
            bash "$TMPDIR/connection-defaults.sh" test0 "$live_action"
done
assert_eq "2" "$(grep -c '^resolvectl dns test0 ' "$LIVE_CALLS")" \
    "Live DHCP and reconnect both restore named Quad9 link servers"
assert_eq "2" "$(grep -c '^resolvectl dnsovertls test0 yes$' "$LIVE_CALLS")" \
    "Live DHCP and reconnect both restore selected strict DoT"
assert_eq "1" \
    "$(grep -c "^nmcli connection modify --temporary uuid $LIVE_UUID " \
        "$LIVE_CALLS")" \
    "only final Live up mirrors policy into NetworkManager's temporary profile"
assert_eq "1" \
    "$(grep -c '^nmcli device modify test0 ipv6.method disabled$' \
        "$LIVE_CALLS")" \
    "only final Live up reconciles the one stale active IPv6 method"
assert_not_grep '^nmcli device reapply test0$' "$LIVE_CALLS" \
    "Live profile mirroring does not restart the acquired DHCP transaction"
live_device_modify_count=$(
    grep -c '^nmcli device modify test0 ipv6.method disabled$' "$LIVE_CALLS"
)
assert_cmd_success "an already-disabled Live activation stays on the no-reapply path" \
    env CONNECTION_UUID="$LIVE_UUID" \
        NOID_TEST_MODE=1 \
        NOID_TEST_CMDLINE_FILE="$TMPDIR/live.cmdline" \
        NOID_TEST_NM_SCOPE_FLAG="$TMPDIR/live-nm-scope.flag" \
        NOID_TEST_NM_SCOPE_PENDING="$TMPDIR/live-nm-scope-pending.flag" \
        NOID_TEST_NM_SCOPE_LOCK="$TMPDIR/live-nm-scope.lock" \
        NOID_TEST_SYSTEMCTL_BIN=/bin/true \
        NOID_TEST_LIVE_IPV6_METHOD=disabled \
        NOID_NM_DEFAULTS_STATE_DIR="$LIVE_STATE" \
        NOID_NM_DEFAULTS_LOCK_DIR="$TMPDIR/live-reassert-lock" \
        bash "$TMPDIR/connection-defaults.sh" test0 up
assert_eq "$live_device_modify_count" \
    "$(grep -c '^nmcli device modify test0 ipv6.method disabled$' \
        "$LIVE_CALLS")" \
    "an already-disabled Live profile emits no redundant device reapply"
assert_cmd_failure "a required Live active IPv6 reconciliation fails closed" \
    env CONNECTION_UUID="$LIVE_UUID" \
        NOID_TEST_MODE=1 \
        NOID_TEST_CMDLINE_FILE="$TMPDIR/live.cmdline" \
        NOID_TEST_NM_SCOPE_FLAG="$TMPDIR/live-nm-scope.flag" \
        NOID_TEST_NM_SCOPE_PENDING="$TMPDIR/live-nm-scope-pending.flag" \
        NOID_TEST_NM_SCOPE_LOCK="$TMPDIR/live-nm-scope.lock" \
        NOID_TEST_SYSTEMCTL_BIN=/bin/true \
        NOID_TEST_LIVE_IPV6_METHOD=auto \
        NOID_TEST_LIVE_DEVICE_MODIFY_FAIL=1 \
        NOID_NM_DEFAULTS_STATE_DIR="$LIVE_STATE" \
        NOID_NM_DEFAULTS_LOCK_DIR="$TMPDIR/live-reassert-lock" \
        bash "$TMPDIR/connection-defaults.sh" test0 up
assert_grep_fixed 'FAIL: live active IPv6 method reconciliation failed' \
    "$LIVE_LOG" "a failed active-method transition is journal-visible"
assert_eq "1" "$(grep -c '^ip -4 route del ' "$LIVE_CALLS")" \
    "Live renewal deletes the injected Option-121 route once"
assert_file_exists "$LIVE_STATE/$LIVE_UUID" \
    "Live reassertion neither consumes nor rewrites a persistent marker"
assert_grep_fixed \
    'Live DHCP renewal: reasserting complete runtime physical-link policy' \
    "$LIVE_LOG" "Live renewal records why complete policy is reapplied"
assert_grep_fixed \
    'Live DHCP security policy restored without recursive profile mutation' \
    "$LIVE_LOG" "Live DHCP records the non-recursive enforcement path"
unset -f nmcli ip logger resolvectl sysctl firewall-cmd

# Execute the persistent link-local path with deterministic command doubles.
# The production mutation must atomically convert a link-local-only profile to
# DHCP plus ipv4.link-local=disabled. This keeps WAN recovery possible without
# emitting RFC3927 DAD/announcement frames.
NM_CALLS="$TMPDIR/nmcli.calls"
NM_DISPATCH_PERMISSION="$TMPDIR/nm-dispatch.permission"
NM_SCOPE_RECONCILE_FLAG="$TMPDIR/nm-scope-reconcile.flag"
NM_SCOPE_RECONCILE_PENDING="$TMPDIR/nm-scope-reconcile-pending.flag"
NM_SCOPE_RECONCILE_LOCK="$TMPDIR/nm-scope-reconcile.lock"
NM_SCOPE_RECONCILE_CALLS="$TMPDIR/nm-scope-reconcile.calls"
NOID_TEST_DISPATCH_HOME="$TMPDIR/nm-dispatch-home"
NOID_TEST_DISPATCH_UID=1001
NOID_TEST_DISPATCH_MTIME=$(($(date +%s) - 120))
export NM_CALLS NM_DISPATCH_PERMISSION NM_SCOPE_RECONCILE_CALLS
export NOID_TEST_DISPATCH_HOME NOID_TEST_DISPATCH_UID NOID_TEST_DISPATCH_MTIME
mkdir -p "$NOID_TEST_DISPATCH_HOME/.config"
: > "$NOID_TEST_DISPATCH_HOME/.config/gnome-initial-setup-done"
: > "$NM_SCOPE_RECONCILE_FLAG"
rm -f "$NM_SCOPE_RECONCILE_PENDING"
: > "$NM_SCOPE_RECONCILE_CALLS"
printf '%s\n' 'root=UUID=fixture noid.lookalike=rd.live.image quiet' \
    > "$TMPDIR/installed.cmdline"
# shellcheck disable=SC2317,SC2329 # exported; invoked by the extracted dispatcher.
nmcli() {
    printf '%s\n' "$*" >> "$NM_CALLS"
    case "$*" in
        '-e no -g connection.type connection show 11111111-1111-4111-8111-111111111111')
            printf '%s\n' '802-3-ethernet' ;;
        '-g ipv4.method connection show 11111111-1111-4111-8111-111111111111')
            printf '%s\n' 'link-local' ;;
        '-g connection.zone connection show 11111111-1111-4111-8111-111111111111')
            printf '%s\n' 'drop' ;;
        '-e no -g connection.permissions connection show 11111111-1111-4111-8111-111111111111')
            [ -f "$NM_DISPATCH_PERMISSION" ] \
                && cat "$NM_DISPATCH_PERMISSION" || printf '\n' ;;
        'connection modify 11111111-1111-4111-8111-111111111111 connection.permissions user:fixture')
            printf '%s\n' 'user:fixture' > "$NM_DISPATCH_PERMISSION" ;;
        'connection modify 11111111-1111-4111-8111-111111111111 '*) ;;
        'device reapply test0') ;;
        *) return 1 ;;
    esac
}
# shellcheck disable=SC2317,SC2329 # exported; invoked by the extracted dispatcher.
function firewall-cmd() { return 0; }
# shellcheck disable=SC2317,SC2329 # exported; invoked by the extracted dispatcher.
getent() {
    [ "$1" = passwd ] || return 1
    [ "${NOID_TEST_GETENT_FAIL:-0}" != 1 ] || return 2
    printf '%s\n' \
        "fixture:x:${NOID_TEST_DISPATCH_UID}:${NOID_TEST_DISPATCH_UID}::${NOID_TEST_DISPATCH_HOME}:/bin/bash"
}
# shellcheck disable=SC2317,SC2329 # exported; invoked by the extracted dispatcher.
stat() {
    case "$*" in
        "-c %u:%Y:%F -- $NOID_TEST_DISPATCH_HOME/.config/gnome-initial-setup-done")
            printf '%s:%s:%s\n' "$NOID_TEST_DISPATCH_UID" \
                "$NOID_TEST_DISPATCH_MTIME" 'regular empty file'
            ;;
        *)
            command stat "$@"
            ;;
    esac
}
# shellcheck disable=SC2317,SC2329 # exported; invoked by the extracted dispatcher.
ip() {
    [ "$*" = '-4 route show dev test0 proto dhcp' ]
}
# shellcheck disable=SC2317,SC2329 # exported; invoked by the extracted dispatcher.
logger() { return 0; }
# shellcheck disable=SC2317,SC2329 # exported; invoked by the extracted dispatcher.
systemctl() {
    printf '%s\n' "$*" >> "$NM_SCOPE_RECONCILE_CALLS"
    [ "${NOID_TEST_SYSTEMCTL_FAIL:-0}" != 1 ]
}
export -f nmcli ip logger getent stat systemctl
export -f -- firewall-cmd
dispatcher_rc=0
CONNECTION_UUID=11111111-1111-4111-8111-111111111111 \
NOID_TEST_MODE=1 \
NOID_TEST_CMDLINE_FILE="$TMPDIR/installed.cmdline" \
NOID_NM_DEFAULTS_STATE_DIR="$TMPDIR/nm-state" \
NOID_NM_DEFAULTS_LOCK_DIR="$TMPDIR/nm-lock" \
NOID_TEST_NM_SCOPE_FLAG="$NM_SCOPE_RECONCILE_FLAG" \
NOID_TEST_NM_SCOPE_PENDING="$NM_SCOPE_RECONCILE_PENDING" \
NOID_TEST_NM_SCOPE_LOCK="$NM_SCOPE_RECONCILE_LOCK" \
NOID_TEST_SYSTEMCTL_BIN=systemctl \
    bash "$TMPDIR/connection-defaults.sh" test0 up || dispatcher_rc=$?
if [ "$dispatcher_rc" -eq 0 ]; then
    _pass "link-local dispatcher path completes without invalid mutation"
else
    _fail "link-local dispatcher path failed (rc=$dispatcher_rc)"
fi
assert_grep_fixed 'connection modify 11111111-1111-4111-8111-111111111111 ' \
    "$NM_CALLS" \
    "kernel-argument lookalike stays on the persistent profile path"
assert_cmd_failure "newly scoped profile invalidates old all-profile evidence" \
    test -e "$NM_SCOPE_RECONCILE_FLAG"
assert_file_exists "$NM_SCOPE_RECONCILE_PENDING" \
    "newly scoped profile publishes pending reconciliation evidence"
assert_eq "600" "$(stat -c '%a' "$NM_SCOPE_RECONCILE_PENDING")" \
    "pending reconciliation evidence is private"
assert_grep_fixed \
    '--no-block restart noid-nm-scope-physical-profiles.timer' \
    "$NM_SCOPE_RECONCILE_CALLS" \
    "newly scoped profile queues asynchronous active-state reconciliation"
assert_grep_fixed \
    'connection modify 11111111-1111-4111-8111-111111111111 connection.permissions user:fixture' \
    "$NM_CALLS" \
    "completed non-1000 account receives immediate physical-profile scope"

rm -f "$TMPDIR/nm-state/11111111-1111-4111-8111-111111111111"
nss_failure_rc=0
CONNECTION_UUID=11111111-1111-4111-8111-111111111111 \
NOID_TEST_MODE=1 \
NOID_TEST_CMDLINE_FILE="$TMPDIR/installed.cmdline" \
NOID_NM_DEFAULTS_STATE_DIR="$TMPDIR/nm-state" \
NOID_NM_DEFAULTS_LOCK_DIR="$TMPDIR/nm-lock" \
NOID_TEST_GETENT_FAIL=1 \
    bash "$TMPDIR/connection-defaults.sh" test0 up || nss_failure_rc=$?
if [ "$nss_failure_rc" -ne 0 ] \
   && [ ! -e "$TMPDIR/nm-state/11111111-1111-4111-8111-111111111111" ]; then
    _pass "NSS enumeration failure cannot publish a connection marker"
else
    _fail "NSS enumeration failure was hidden or falsely sealed"
fi

# An interruption after the saved permission changed but before reconciliation
# leaves the expected permission already present and no UUID marker. A retry
# must still invalidate old all-profile evidence and queue the scoper.
: > "$NM_SCOPE_RECONCILE_FLAG"
rm -f "$NM_SCOPE_RECONCILE_PENDING"
: > "$NM_SCOPE_RECONCILE_CALLS"
scope_queue_failure_rc=0
env CONNECTION_UUID=11111111-1111-4111-8111-111111111111 \
    NOID_TEST_MODE=1 \
    NOID_TEST_CMDLINE_FILE="$TMPDIR/installed.cmdline" \
    NOID_NM_DEFAULTS_STATE_DIR="$TMPDIR/nm-state" \
    NOID_NM_DEFAULTS_LOCK_DIR="$TMPDIR/nm-lock" \
    NOID_TEST_NM_SCOPE_FLAG="$NM_SCOPE_RECONCILE_FLAG" \
    NOID_TEST_NM_SCOPE_PENDING="$NM_SCOPE_RECONCILE_PENDING" \
    NOID_TEST_NM_SCOPE_LOCK="$NM_SCOPE_RECONCILE_LOCK" \
    NOID_TEST_SYSTEMCTL_BIN=systemctl \
    NOID_TEST_SYSTEMCTL_FAIL=1 \
    bash "$TMPDIR/connection-defaults.sh" test0 up || scope_queue_failure_rc=$?
if [ "$scope_queue_failure_rc" -ne 0 ] \
   && [ ! -e "$TMPDIR/nm-state/11111111-1111-4111-8111-111111111111" ]; then
    _pass "failed reconciliation scheduling cannot publish a UUID marker"
else
    _fail "failed reconciliation scheduling was hidden or falsely sealed"
fi

: > "$NM_SCOPE_RECONCILE_FLAG"
rm -f "$NM_SCOPE_RECONCILE_PENDING"
: > "$NM_SCOPE_RECONCILE_CALLS"
assert_cmd_success "already-saved user scope still queues interrupted reconciliation" \
    env CONNECTION_UUID=11111111-1111-4111-8111-111111111111 \
        NOID_TEST_MODE=1 \
        NOID_TEST_CMDLINE_FILE="$TMPDIR/installed.cmdline" \
        NOID_NM_DEFAULTS_STATE_DIR="$TMPDIR/nm-state" \
        NOID_NM_DEFAULTS_LOCK_DIR="$TMPDIR/nm-lock" \
        NOID_TEST_NM_SCOPE_FLAG="$NM_SCOPE_RECONCILE_FLAG" \
        NOID_TEST_NM_SCOPE_PENDING="$NM_SCOPE_RECONCILE_PENDING" \
        NOID_TEST_NM_SCOPE_LOCK="$NM_SCOPE_RECONCILE_LOCK" \
        NOID_TEST_SYSTEMCTL_BIN=systemctl \
        bash "$TMPDIR/connection-defaults.sh" test0 up
assert_cmd_failure "interrupted retry invalidates stale all-profile evidence" \
    test -e "$NM_SCOPE_RECONCILE_FLAG"
assert_eq "1" "$(grep -c \
    '^--no-block restart noid-nm-scope-physical-profiles.timer$' \
    "$NM_SCOPE_RECONCILE_CALLS")" \
    "interrupted retry queues exactly one asynchronous scoper run"
unset -f nmcli ip logger getent stat systemctl firewall-cmd
grep 'connection modify 11111111-1111-4111-8111-111111111111 ' \
    "$NM_CALLS" > "$TMPDIR/link-local-modify.call" || true
assert_grep_fixed 'ipv6.method disabled' "$TMPDIR/link-local-modify.call" \
    "link-local mutation retains IPv6 disablement"
assert_grep_fixed 'connection.mdns 0' "$TMPDIR/link-local-modify.call" \
    "link-local mutation retains discovery suppression"
assert_grep_fixed 'ipv4.method auto' "$TMPDIR/link-local-modify.call" \
    "link-local profile is converted to ordinary WAN DHCP"
assert_grep_fixed 'ipv4.link-local disabled' "$TMPDIR/link-local-modify.call" \
    "converted profile cannot emit RFC3927 fallback frames"
assert_grep_fixed 'ipv4.dhcp-client-id mac' "$TMPDIR/link-local-modify.call" \
    "converted DHCP identity remains aligned with the randomized MAC"
assert_grep_fixed 'ipv4.dhcp-send-hostname false' "$TMPDIR/link-local-modify.call" \
    "converted profile suppresses IPv4 DHCP hostname transmission"
assert_grep_fixed 'ipv6.dhcp-send-hostname false' "$TMPDIR/link-local-modify.call" \
    "converted profile suppresses IPv6 DHCP hostname transmission"
reapply_line=$(grep -n '^device reapply test0$' "$NM_CALLS" | head -1 | cut -d: -f1)
permission_line=$(grep -n \
    '^connection modify 11111111-1111-4111-8111-111111111111 connection.permissions user:fixture$' \
    "$NM_CALLS" | head -1 | cut -d: -f1)
if [ -n "$reapply_line" ] && [ -n "$permission_line" ] \
        && [ "$reapply_line" -lt "$permission_line" ]; then
    _pass "non-reapplicable permissions are persisted after active reapply"
else
    _fail "connection.permissions must not precede nmcli device reapply"
fi
if command -v nmcli >/dev/null 2>&1; then
    assert_cmd_success "NetworkManager accepts the final auto + IPv4LL-disabled combination" \
        nmcli --offline connection add type ethernet con-name noid-test \
            ifname test0 ipv4.method auto ipv4.link-local disabled
fi

test_finish

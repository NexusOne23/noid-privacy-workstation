#!/bin/bash
# 06-vpn-killswitch-structural — M06 regression test
#
# Covers the complete M06 surface: VPN-zone dispatch, WAN-strict nft policy,
# boot guard/bootstrap, hardened units, libnm endpoint reconciliation, CLI,
# toggle behaviour and installed-surface verification.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/06-vpn-killswitch.ks"
DOC_REGEN="$PROJECT_ROOT/scripts/regen-wan-strict-doc.sh"
MTU_REGEN="$PROJECT_ROOT/scripts/regen-wireguard-mtu-reconcile-embed.sh"
MTU_SOURCE="$PROJECT_ROOT/scripts/noid-wireguard-mtu-reconcile.sh"
TMPDIR="$(mktemp -d)"
EXEC_TMPDIR="$(mktemp -d -p /var/tmp noid-vpn-zone-test.XXXXXX)"
trap 'rm -rf "$TMPDIR" "$EXEC_TMPDIR"' EXIT

test_start "06-vpn-killswitch-structural"

assert_file_exists "$KS_FILE"
assert_grep_fixed '%packages --exclude-weakdeps' "$KS_FILE" \
    "M06 package solve follows the repository weak-dependency policy"
assert_cmd_success "bash -n $KS_FILE" bash -n "$KS_FILE"
assert_file_exists "$DOC_REGEN"
assert_cmd_success "WAN-strict installed documentation is in sync" \
    "$DOC_REGEN" --check
assert_file_exists "$MTU_REGEN"
assert_file_exists "$MTU_SOURCE"
assert_cmd_success "WireGuard MTU reconciler embed is in sync" \
    "$MTU_REGEN" --check
M06_HEADER="$TMPDIR/m06-header"
sed -n '1,55p' "$KS_FILE" > "$M06_HEADER"
assert_grep_fixed 'noid-wan-strict-endpoint-expiry.service/.timer' "$M06_HEADER" \
    "M06 architecture ledger includes recurring endpoint expiry"
assert_grep_fixed '/etc/tmpfiles.d/noid-wan-strict.conf' "$M06_HEADER" \
    "M06 architecture ledger includes lock/evidence pre-creation"
assert_grep_fixed '/usr/local/sbin/noid-wan-strict-publish-status' "$M06_HEADER" \
    "M06 architecture ledger includes its status publisher"
assert_grep_fixed '/usr/local/sbin/noid-wireguard-mtu-reconcile' "$M06_HEADER" \
    "M06 architecture ledger includes the live-only MTU owner"

extract_heredoc "$KS_FILE" "NOID_WG_MTU_EOF" \
    "$TMPDIR/noid-wireguard-mtu-reconcile" \
    || _fail "WireGuard MTU reconciler extraction"
extract_heredoc "$KS_FILE" "WG_MTU_DISPATCHER_EOF" \
    "$TMPDIR/45-noid-wireguard-mtu" \
    || _fail "WireGuard MTU dispatcher extraction"
assert_cmd_success "WireGuard MTU reconciler syntax" \
    bash -n "$TMPDIR/noid-wireguard-mtu-reconcile"
assert_cmd_success "WireGuard MTU dispatcher syntax" \
    bash -n "$TMPDIR/45-noid-wireguard-mtu"
assert_cmd_success "WireGuard MTU canonical source matches its embed" \
    cmp -s "$MTU_SOURCE" "$TMPDIR/noid-wireguard-mtu-reconcile"
assert_grep_fixed '"$IP" link set dev "$iface" mtu "$worst_safe"' \
    "$TMPDIR/noid-wireguard-mtu-reconcile" \
    "reconciler changes only the computed live link MTU"
assert_not_grep_extended 'nmcli.*(modify|down|up)|connection (modify|down|up)' \
    "$TMPDIR/noid-wireguard-mtu-reconcile" \
    "reconciler never persists or reactivates an owner profile"
assert_grep_fixed 'pre-up|vpn-pre-up)' "$TMPDIR/45-noid-wireguard-mtu" \
    "tunnel pre-up attempts the lower-only MTU correction before activation completes"
assert_grep_fixed 'dhcp4-change|dhcp6-change|reapply|connectivity-change)' \
    "$TMPDIR/45-noid-wireguard-mtu" \
    "physical path changes re-evaluate active WireGuard links"
assert_grep_fixed 'ln -sfnT no-wait.d/45-noid-wireguard-mtu' "$KS_FILE" \
    "ordinary MTU reconciliation uses NetworkManager's no-wait path"

# Single dispatcher file, canonical path
assert_grep_fixed "/etc/NetworkManager/dispatcher.d/50-vpn-zone-enforce" "$KS_FILE"

# Permissions are set explicitly (dispatcher requires root:root + exec bit)
# All NoID Privacy NetworkManager dispatchers/pre-up/no-wait helpers use 700 and
# root:root ownership.
assert_grep_extended 'chmod 700 /etc/NetworkManager/dispatcher.d/50-vpn-zone-enforce' "$KS_FILE"
assert_grep_extended 'chown root:root /etc/NetworkManager/dispatcher.d/50-vpn-zone-enforce' "$KS_FILE"

# Dispatcher uses firewalld for live membership and only a temporary
# NetworkManager profile update; provider-created volatile profiles must never
# become persistent autoconnect files.
assert_grep_fixed "firewall-cmd" "$KS_FILE"
assert_grep_fixed 'con mod --temporary "$UUID" connection.zone noid-vpn' "$KS_FILE"

# Hardened noid-vpn zone is the destination; stock trusted (target ACCEPT)
# must not reappear.
extract_heredoc "$KS_FILE" "DISPATCHER_EOF" "$TMPDIR/vpn-zone-dispatcher.sh" \
    || _fail "VPN zone dispatcher extraction"
assert_cmd_success "VPN zone dispatcher is valid bash" \
    bash -n "$TMPDIR/vpn-zone-dispatcher.sh"
assert_grep_fixed 'IFACE="${1:-}"' "$TMPDIR/vpn-zone-dispatcher.sh" \
    "VPN zone dispatcher treats missing interface context as empty"
assert_grep_fixed 'ACTION="${2:-}"' "$TMPDIR/vpn-zone-dispatcher.sh" \
    "VPN zone dispatcher treats missing action context as empty"
assert_cmd_success "manual context-free VPN zone invocation exits cleanly" \
    bash "$TMPDIR/vpn-zone-dispatcher.sh"
assert_grep_fixed '--zone=noid-vpn --change-interface="$IFACE"' \
    "$TMPDIR/vpn-zone-dispatcher.sh"
assert_grep_fixed 'con mod --temporary "$UUID" connection.zone noid-vpn' \
    "$TMPDIR/vpn-zone-dispatcher.sh"
assert_not_grep 'con mod "$UUID" connection.zone noid-vpn' \
    "$TMPDIR/vpn-zone-dispatcher.sh" \
    "dispatcher never persists a provider-created volatile tunnel profile"
# Updating the profile NetworkManager invents for an assumed external tunnel
# makes it release the device (unmanaged-external-down) and take the creator's
# address with it, which killed every wg-quick and provider-daemon tunnel about
# a second after it appeared. The gate must test ownership, not storage
# location: NetworkManager keeps its own WireGuard and VPN-plugin profiles
# under /run as well, so a path test would skip the mirror for every tunnel.
assert_grep_fixed '"${CONNECTION_EXTERNAL:-0}" = 1' \
    "$TMPDIR/vpn-zone-dispatcher.sh" \
    "zone mirror is gated on NetworkManager's own external-ownership flag"
assert_grep_fixed 'externally created tunnel, NetworkManager mirror skipped' \
    "$TMPDIR/vpn-zone-dispatcher.sh" \
    "skipping the mirror for an externally created tunnel is reported, not silent"
assert_not_grep 'CONNECTION_FILENAME' "$TMPDIR/vpn-zone-dispatcher.sh" \
    "profile ownership is never inferred from the profile's path"
assert_not_grep 'zone=trusted\|connection.zone trusted' \
    "$TMPDIR/vpn-zone-dispatcher.sh" "dispatcher never assigns target-ACCEPT trusted zone"
assert_grep_fixed 'vpn|wireguard|tun|ip-tunnel' "$TMPDIR/vpn-zone-dispatcher.sh" \
    "only explicit NM VPN/tunnel connection types are promoted"
assert_grep_fixed 'it does not add a WAN-strict endpoint schema' \
    "$TMPDIR/vpn-zone-dispatcher.sh" \
    "generic VPN zoning is not misrepresented as WAN-strict protocol support"
assert_grep_fixed 'pre-up|up|vpn-pre-up|vpn-up' "$TMPDIR/vpn-zone-dispatcher.sh" \
    "normal and VPN-plugin events are handled before and after activation"
assert_grep_fixed 'RUNTIME_ZONE=$(firewall-cmd --get-zone-of-interface="$IFACE"' \
    "$TMPDIR/vpn-zone-dispatcher.sh" "fast path verifies live firewalld state"
assert_grep_fixed 'pre-up.d/50-vpn-zone-enforce' "$KS_FILE" \
    "VPN zone hook is registered in NetworkManager pre-up.d"
assert_grep_fixed '[ -e "/sys/class/net/$IFACE/master" ]' \
    "$TMPDIR/vpn-zone-dispatcher.sh" \
    "kernel controller ports cannot enter the VPN zone"
assert_grep_fixed 'connection.port-type' "$TMPDIR/vpn-zone-dispatcher.sh" \
    "NetworkManager port metadata is checked"
assert_grep_fixed 'connection.controller' "$TMPDIR/vpn-zone-dispatcher.sh" \
    "NetworkManager controller metadata is checked"

# A Libvirt TAP is represented by NetworkManager as connection.type=tun, so a
# type allow-list alone is insufficient. Execute the extracted dispatcher with
# native-shaped profile metadata and prove that controller ports are rejected
# before either runtime or temporary zone mutation. Then prove that a standalone
# TUN profile still follows the normal enforcement path.
MOCK_BIN="$EXEC_TMPDIR/mocks"
MOCK_LOG="$EXEC_TMPDIR/mocks.log"
mkdir -p "$MOCK_BIN"
cat > "$MOCK_BIN/nmcli" <<'MOCK_NMCLI_EOF'
#!/bin/bash
printf 'nmcli %s\n' "$*" >> "$NOID_TEST_LOG"
case "$*" in
    "-g connection.port-type con show fixture-uuid")
        printf '%s\n' "${NOID_TEST_PORT_TYPE:-}"
        ;;
    "-g connection.controller con show fixture-uuid")
        printf '%s\n' "${NOID_TEST_CONTROLLER:-}"
        ;;
    "-g connection.type con show fixture-uuid")
        printf '%s\n' "${NOID_TEST_CONNECTION_TYPE:-tun}"
        ;;
    "-g connection.zone con show fixture-uuid")
        printf '%s\n' "${NOID_TEST_CONNECTION_ZONE:-}"
        ;;
    "con mod --temporary fixture-uuid connection.zone noid-vpn")
        ;;
    *)
        exit 2
        ;;
esac
MOCK_NMCLI_EOF
cat > "$MOCK_BIN/firewall-cmd" <<'MOCK_FIREWALL_EOF'
#!/bin/bash
printf 'firewall-cmd %s\n' "$*" >> "$NOID_TEST_LOG"
case "$*" in
    "--get-zone-of-interface=fixture0")
        printf '%s\n' "${NOID_TEST_RUNTIME_ZONE:-drop}"
        ;;
    "--zone=noid-vpn --change-interface=fixture0")
        ;;
    *)
        exit 2
        ;;
esac
MOCK_FIREWALL_EOF
cat > "$MOCK_BIN/logger" <<'MOCK_LOGGER_EOF'
#!/bin/bash
printf 'logger %s\n' "$*" >> "$NOID_TEST_LOG"
MOCK_LOGGER_EOF
chmod 700 "$MOCK_BIN/nmcli" "$MOCK_BIN/firewall-cmd" "$MOCK_BIN/logger"

: > "$MOCK_LOG"
assert_cmd_success "controller-backed TUN profile is rejected" \
    env PATH="$MOCK_BIN:/usr/bin:/bin" NOID_TEST_LOG="$MOCK_LOG" \
        NOID_TEST_LOGGER_BACKEND="$MOCK_BIN/logger" \
        NOID_TEST_PORT_TYPE=bridge NOID_TEST_CONTROLLER=fixture-controller \
        NOID_TEST_CONNECTION_TYPE=tun CONNECTION_UUID=fixture-uuid \
        bash "$TMPDIR/vpn-zone-dispatcher.sh" fixture0 up
assert_grep_fixed 'logger -t noid-vpn-zone-test refused controller port fixture0' \
    "$MOCK_LOG" "controller-port refusal is explicit"
assert_not_grep '^firewall-cmd ' "$MOCK_LOG" \
    "controller port never reaches runtime zone mutation"
assert_not_grep '^nmcli con mod ' "$MOCK_LOG" \
    "controller port never reaches profile zone mutation"

: > "$MOCK_LOG"
assert_cmd_success "standalone TUN profile remains supported" \
    env PATH="$MOCK_BIN:/usr/bin:/bin" NOID_TEST_LOG="$MOCK_LOG" \
        NOID_TEST_LOGGER_BACKEND="$MOCK_BIN/logger" \
        NOID_TEST_PORT_TYPE= NOID_TEST_CONTROLLER= \
        NOID_TEST_CONNECTION_TYPE=tun CONNECTION_UUID=fixture-uuid \
        bash "$TMPDIR/vpn-zone-dispatcher.sh" fixture0 up
assert_grep_fixed 'firewall-cmd --zone=noid-vpn --change-interface=fixture0' \
    "$MOCK_LOG" "standalone TUN reaches runtime zone enforcement"
assert_grep_fixed 'nmcli con mod --temporary fixture-uuid connection.zone noid-vpn' \
    "$MOCK_LOG" "standalone TUN reaches non-persistent zone enforcement"

# NetworkManager stores its own WireGuard and VPN-plugin profiles under /run as
# well -- a Proton-style volatile profile is still NetworkManager's own. It
# must keep the mirror, or a path-based gate would silently disable the
# bookkeeping for every tunnel on the system.
: > "$MOCK_LOG"
assert_cmd_success "NetworkManager's own volatile profile keeps the zone mirror" \
    env PATH="$MOCK_BIN:/usr/bin:/bin" NOID_TEST_LOG="$MOCK_LOG" \
        NOID_TEST_LOGGER_BACKEND="$MOCK_BIN/logger" \
        NOID_TEST_PORT_TYPE= NOID_TEST_CONTROLLER= \
        NOID_TEST_CONNECTION_TYPE=wireguard CONNECTION_UUID=fixture-uuid \
        CONNECTION_FILENAME=/run/NetworkManager/system-connections/proton.nmconnection \
        bash "$TMPDIR/vpn-zone-dispatcher.sh" fixture0 up
assert_grep_fixed 'nmcli con mod --temporary fixture-uuid connection.zone noid-vpn' \
    "$MOCK_LOG" "a volatile NetworkManager-owned profile is still mirrored"

# An externally created kernel tunnel (wg-quick, a provider daemon) is assumed
# by NetworkManager. Mirroring the zone into the profile it invents makes it
# release the device and drop the address its creator installed, so the tunnel
# dies about a second after it appeared. The firewalld enforcement must still
# run; only the mirror is skipped.
: > "$MOCK_LOG"
assert_cmd_success "externally created tunnel is zoned without touching its profile" \
    env PATH="$MOCK_BIN:/usr/bin:/bin" NOID_TEST_LOG="$MOCK_LOG" \
        NOID_TEST_LOGGER_BACKEND="$MOCK_BIN/logger" \
        NOID_TEST_PORT_TYPE= NOID_TEST_CONTROLLER= \
        NOID_TEST_CONNECTION_TYPE=wireguard CONNECTION_UUID=fixture-uuid \
        CONNECTION_EXTERNAL=1 \
        bash "$TMPDIR/vpn-zone-dispatcher.sh" fixture0 up
assert_grep_fixed 'firewall-cmd --zone=noid-vpn --change-interface=fixture0' \
    "$MOCK_LOG" "externally created tunnel still reaches runtime zone enforcement"
assert_not_grep '^nmcli con mod ' "$MOCK_LOG" \
    "externally created tunnel profile is never modified"
assert_grep_fixed 'externally created tunnel, NetworkManager mirror skipped' \
    "$MOCK_LOG" "skipping the mirror is reported rather than silent"

# Ownership, not location: an external tunnel whose profile happens to sit on a
# persistent path must still be left alone. This is the case a /etc allow-list
# would have got wrong.
: > "$MOCK_LOG"
assert_cmd_success "external ownership outranks a persistent-looking path" \
    env PATH="$MOCK_BIN:/usr/bin:/bin" NOID_TEST_LOG="$MOCK_LOG" \
        NOID_TEST_LOGGER_BACKEND="$MOCK_BIN/logger" \
        NOID_TEST_PORT_TYPE= NOID_TEST_CONTROLLER= \
        NOID_TEST_CONNECTION_TYPE=wireguard CONNECTION_UUID=fixture-uuid \
        CONNECTION_EXTERNAL=1 \
        CONNECTION_FILENAME=/etc/NetworkManager/system-connections/fixture0.nmconnection \
        bash "$TMPDIR/vpn-zone-dispatcher.sh" fixture0 up
assert_not_grep '^nmcli con mod ' "$MOCK_LOG" \
    "a persistent path never overrides external ownership"

# WAN-strict must restrict only hardware-backed interfaces. The former final
# catch-all drop merely exempted a hard-coded list of tunnel names and broke
# provider neutrality for an arbitrary legitimate tunnel name.
extract_heredoc "$KS_FILE" "NFT_EOF" "$TMPDIR/noid-wan-strict.nft" \
    || _fail "WAN-strict nft extraction"
chmod 0644 "$TMPDIR/noid-wan-strict.nft"
assert_grep_fixed 'set physical_ifaces {' "$TMPDIR/noid-wan-strict.nft"
assert_grep_fixed 'set lan_exceptions_v4 {' "$TMPDIR/noid-wan-strict.nft" \
    "WAN-strict has exact IPv4 LAN exception state"
assert_grep_fixed 'set lan_exceptions_v6 {' "$TMPDIR/noid-wan-strict.nft" \
    "WAN-strict has exact IPv6 LAN exception state"
assert_grep_fixed 'set lan_inbound_peers_v4 {' "$TMPDIR/noid-wan-strict.nft" \
    "WAN-strict has a separate IPv4 reply set for inbound-capable LAN peers"
# Same requirement as the topology table: lan_exceptions_* holds approved peers
# AND connected prefixes, so one can cover the other. Without auto-merge nft
# refuses the covered element with "conflicting intervals specified" and the
# whole WAN-strict batch fails.
for wan_interval_set in bypass_grace_v4 lan_exceptions_v4 lan_exceptions_v6 \
                        lan_inbound_peers_v4; do
    set_body=$(awk -v s="set $wan_interval_set {" '
        index($0, s) { inside = 1 }
        inside { print }
        inside && /^\s*\}/ { exit }
    ' "$TMPDIR/noid-wan-strict.nft")
    printf '%s' "$set_body" | grep -q 'flags interval' \
        && printf '%s' "$set_body" | grep -q 'auto-merge' \
        && _pass "interval set $wan_interval_set tolerates a covered prefix" \
        || _fail "interval set $wan_interval_set lacks auto-merge"
done
unset wan_interval_set set_body
assert_grep_fixed 'oifname @physical_ifaces ct state established,related' \
    "$TMPDIR/noid-wan-strict.nft" \
    "inbound LAN replies are limited to hardware interfaces and conntrack state"
assert_grep_fixed 'ip daddr @lan_inbound_peers_v4 accept' \
    "$TMPDIR/noid-wan-strict.nft" \
    "inbound LAN sessions can send only state-correlated replies on hardware links"
assert_grep_fixed 'ip daddr @lan_exceptions_v4 accept' "$TMPDIR/noid-wan-strict.nft" \
    "exact IPv4 LAN opt-ins precede WAN physical drop"
assert_grep_fixed 'ip6 daddr @lan_exceptions_v6 accept' "$TMPDIR/noid-wan-strict.nft" \
    "exact IPv6 LAN opt-ins precede WAN physical drop"
assert_grep_fixed 'type filter hook forward priority -5; policy accept;' \
    "$TMPDIR/noid-wan-strict.nft" \
    "VM/container forwarded traffic cannot bypass WAN strict"
assert_grep_fixed 'oifname @physical_ifaces meta nfproto ipv4' \
    "$TMPDIR/noid-wan-strict.nft" "IPv4 final drop is hardware-scoped"
assert_grep_fixed 'oifname @physical_ifaces meta nfproto ipv6' \
    "$TMPDIR/noid-wan-strict.nft" "IPv6 final drop is hardware-scoped"
assert_not_grep 'oifname "proton0"\|oifname "wg0"\|oifname "tun0"' \
    "$TMPDIR/noid-wan-strict.nft" "WAN strict does not trust tunnel names"
assert_not_grep ' log prefix ' "$TMPDIR/noid-wan-strict.nft" \
    "blocked destinations are counted without journal metadata"
assert_grep_fixed '"NOID_SYS_CLASS_NET", "/sys/class/net"' \
    "$KS_FILE" \
    "atomic boot transaction discovers every hardware-backed interface"

extract_heredoc "$KS_FILE" "BOOTSTRAP_EOF" "$TMPDIR/wan-bootstrap.sh" \
    || _fail "WAN bootstrap extraction"
extract_heredoc "$KS_FILE" "WAN_STRICT_SERVICE_EOF" "$TMPDIR/wan-strict.service" \
    || _fail "WAN-strict service extraction"
extract_heredoc "$KS_FILE" "WAN_STATUS_SERVICE_EOF" \
    "$TMPDIR/wan-strict-status-publish.service" \
    || _fail "WAN-strict status publisher service extraction"
extract_heredoc "$KS_FILE" "WAN_TMPFILES_EOF" "$TMPDIR/wan-strict.tmpfiles" \
    || _fail "WAN-strict tmpfiles extraction"
extract_heredoc "$KS_FILE" "SERVICE_EOF" "$TMPDIR/profile-scan.service" \
    || _fail "profile scanner service extraction"
extract_heredoc "$KS_FILE" "ENDPOINT_EXPIRY_SERVICE_EOF" \
    "$TMPDIR/endpoint-expiry.service" \
    || _fail "endpoint expiry service extraction"
assert_grep_fixed 'f /run/lock/noid-wan-strict.lock 0600 root root -' \
    "$TMPDIR/wan-strict.tmpfiles" \
    "WAN controller lock exists before sandbox construction"
assert_grep_fixed 'f /run/lock/noid-wireguard-mtu.lock 0600 root root -' \
    "$TMPDIR/wan-strict.tmpfiles" \
    "WireGuard MTU reconciliation lock is pre-created root-private"
assert_grep_fixed \
    'd /run/noid-privacy/wan-strict-active 0700 root root -' \
    "$TMPDIR/wan-strict.tmpfiles" \
    "volatile authenticated-tunnel evidence is root-private at boot"
assert_grep_fixed 'Requires=systemd-tmpfiles-setup.service' \
    "$TMPDIR/wan-strict.service" \
    "early-boot service requires the shared runtime directory owner"
assert_grep_fixed 'After=local-fs.target nftables.service firewalld.service systemd-tmpfiles-setup.service' \
    "$TMPDIR/wan-strict.service" \
    "WAN bootstrap waits for shared runtime directory creation"
assert_grep_fixed \
    'ConditionPathExists=!/var/lib/noid-privacy/wan-strict-disabled.flag' \
    "$TMPDIR/wan-strict.service" \
    "explicit opt-out suppresses the boot bootstrap even if enablement drifts"
assert_not_grep '^RuntimeDirectory=noid-privacy$' "$TMPDIR/wan-strict.service" \
    "stopping WAN strict cannot delete unrelated shared runtime state"
assert_grep_fixed \
    'ReadWritePaths=/var/lib/noid-privacy /run/noid-privacy /run/lock/noid-wan-strict.lock' \
    "$TMPDIR/wan-strict.service" \
    "service namespace exposes only persistent, volatile and lock state"
assert_grep_fixed \
    'ExecStart=/usr/local/sbin/noid-wan-strict-publish-status' \
    "$TMPDIR/wan-strict-status-publish.service" \
    "boot-complete oneshot delegates to the closed status publisher"
assert_grep_fixed \
    'After=local-fs.target systemd-tmpfiles-setup.service noid-wan-strict.service' \
    "$TMPDIR/wan-strict-status-publish.service" \
    "status publication waits for either active-policy bootstrap or exact opt-out"
assert_grep_fixed 'Before=multi-user.target graphical.target' \
    "$TMPDIR/wan-strict-status-publish.service" \
    "status exists before an interactive Network GUI can consume it"
assert_grep_fixed \
    'ReadWritePaths=/run/noid-privacy /run/lock/noid-wan-strict.lock' \
    "$TMPDIR/wan-strict-status-publish.service" \
    "publisher can mutate only reboot-volatile status and lock state"
assert_grep_fixed 'CapabilityBoundingSet=CAP_NET_ADMIN' \
    "$TMPDIR/wan-strict-status-publish.service" \
    "publisher can inspect the nft postcondition without broader capabilities"
assert_grep_fixed 'ProtectSystem=strict' \
    "$TMPDIR/wan-strict-status-publish.service" \
    "status publisher has a read-only root filesystem"
assert_grep_fixed 'UMask=0077' \
    "$TMPDIR/wan-strict-status-publish.service" \
    "status publisher defaults new files private"
assert_grep_fixed 'PrivateDevices=yes' \
    "$TMPDIR/wan-strict-status-publish.service" \
    "status publisher has no host device access"
assert_grep_fixed 'systemctl enable noid-wan-strict-status-publish.service' \
    "$KS_FILE" \
    "status publisher remains enabled when WAN enforcement is disabled"
assert_not_grep \
    'ConditionPathExists=!/var/lib/noid-privacy/wan-strict-disabled.flag' \
    "$TMPDIR/wan-strict-status-publish.service" \
    "opt-out cannot suppress publication of its own DISABLED contract"
for unit_file in "$TMPDIR/wan-strict.service" \
                 "$TMPDIR/profile-scan.service" \
                 "$TMPDIR/endpoint-expiry.service"; do
    assert_grep_fixed 'ProtectSystem=strict' "$unit_file" \
        "M06 controller unit has a read-only root filesystem: $(basename "$unit_file")"
    assert_grep_fixed \
        'ReadWritePaths=/var/lib/noid-privacy /run/noid-privacy /run/lock/noid-wan-strict.lock' \
        "$unit_file" \
        "M06 controller unit narrows writable state: $(basename "$unit_file")"
    assert_grep_fixed 'UMask=0077' "$unit_file" \
        "M06 controller unit defaults new files private: $(basename "$unit_file")"
    assert_grep_fixed 'CapabilityBoundingSet=CAP_NET_ADMIN' "$unit_file" \
        "M06 controller unit retains only nft administration capability: $(basename "$unit_file")"
    assert_grep_fixed 'PrivateDevices=yes' "$unit_file" \
        "M06 controller unit has no host device access: $(basename "$unit_file")"
done
extract_heredoc "$KS_FILE" "PIN_EOF" "$TMPDIR/endpoint-pin.sh" \
    || _fail "endpoint dispatcher extraction"
extract_heredoc "$KS_FILE" "TUNNEL_DOWN_EOF" \
    "$TMPDIR/tunnel-down.sh" \
    || _fail "tunnel-down dispatcher extraction"
extract_heredoc "$KS_FILE" "ENDPOINT_ENGINE_EOF" "$TMPDIR/endpoint-engine.py" \
    || _fail "libnm endpoint controller extraction"
extract_heredoc "$KS_FILE" "SCAN_PROFILES_EOF" "$TMPDIR/profile-scan.sh" \
    || _fail "profile scanner extraction"
extract_heredoc "$KS_FILE" "SCAN_UP_EOF" "$TMPDIR/scan-on-network-up.sh" \
    || _fail "physical-up scanner dispatcher extraction"
extract_heredoc "$KS_FILE" "TUNNEL_SCAN_SERVICE_EOF" \
    "$TMPDIR/tunnel-scan.service" \
    || _fail "unmanaged tunnel scan unit extraction"
extract_heredoc "$KS_FILE" "TOGGLE_WAN_STRICT_EOF" "$TMPDIR/toggle-wan-strict.sh" \
    || _fail "WAN-strict toggle extraction"
extract_heredoc "$KS_FILE" "CLI_EOF" "$TMPDIR/wan-strict-cli.sh" \
    || _fail "WAN-strict CLI extraction"
extract_heredoc "$KS_FILE" "WAN_STATUS_EOF" "$TMPDIR/wan-status-publisher.sh" \
    || _fail "WAN-strict status publisher extraction"
extract_heredoc "$KS_FILE" "WAN_BOOT_GUARD_EOF" "$TMPDIR/wan-boot-guard.sh" \
    || _fail "WAN-strict boot guard extraction"
assert_cmd_success "WAN bootstrap is valid bash" bash -n "$TMPDIR/wan-bootstrap.sh"
assert_cmd_success "endpoint dispatcher is valid bash" bash -n "$TMPDIR/endpoint-pin.sh"
assert_cmd_success "tunnel-down dispatcher is valid bash" \
    bash -n "$TMPDIR/tunnel-down.sh"
assert_cmd_success "libnm endpoint controller compiles" \
    python3 -c 'import pathlib,sys; p=pathlib.Path(sys.argv[1]); compile(p.read_text(), str(p), "exec")' \
    "$TMPDIR/endpoint-engine.py"

# NetworkManager-openvpn stores redundant gateways in one `remote` item and its
# Gateway tooltip documents both the space delimiter and the host:port:proto
# form. Rejecting either aborted the whole reconciliation, so mark_armed() was
# never reached and bypass_grace_v4 stayed at 0.0.0.0/0 -- one malformed-looking
# but perfectly valid profile made the kill switch fail open for every tunnel.
assert_cmd_success "OpenVPN gateway forms NetworkManager documents are accepted" \
    python3 - "$TMPDIR/endpoint-engine.py" <<'PY'
import ast
import ipaddress
import re
import sys

tree = ast.parse(open(sys.argv[1], encoding='utf-8').read())
wanted = {'split_endpoint', 'fail'}
nodes = [node for node in tree.body
         if isinstance(node, (ast.FunctionDef, ast.ClassDef))
         and node.name in wanted | {'EndpointError'}]
module = ast.Module(body=nodes, type_ignores=[])
ast.fix_missing_locations(module)
namespace = {'re': re, 'ipaddress': ipaddress}
exec(compile(module, '<endpoint-fixture>', 'exec'), namespace)
split_endpoint = namespace['split_endpoint']
EndpointError = namespace['EndpointError']

# Documented transport suffix, IPv4 and hostname.
assert split_endpoint('ovpn.corp.com:1234:tcp', 1194) == ('ovpn.corp.com', 1234, 'tcp')
assert split_endpoint('ovpn.corp.com:1234:udp6', 1194) == ('ovpn.corp.com', 1234, 'udp')
assert split_endpoint('ovpn.corp.com:tcp4', 1194) == ('ovpn.corp.com', 1194, 'tcp')
assert split_endpoint('198.51.100.7:1234:tcp', 1194) == ('198.51.100.7', 1234, 'tcp')
# Bracketed IPv6 with and without the suffix.
assert split_endpoint('[2001:db8::1]:1194:udp', 1194) == ('2001:db8::1', 1194, 'udp')
assert split_endpoint('[2001:db8::1]:1194', 1194) == ('2001:db8::1', 1194, None)
# A bare IPv6 literal must survive untouched: t, p and u are not hex digits,
# so no valid address can be mistaken for a transport suffix.
assert split_endpoint('2001:db8::1', 1194) == ('2001:db8::1', 1194, None)
assert split_endpoint('2001:db8::c', 1194) == ('2001:db8::c', 1194, None)
# Still closed against genuine garbage.
for bad in ('', ' ', 'ovpn.corp.com:0:tcp', ':tcp', 'ovpn.corp.com:99999'):
    try:
        split_endpoint(bad, None)
    except EndpointError:
        continue
    raise AssertionError(f'accepted invalid endpoint: {bad!r}')

# The delimiter class the reconciler splits on must cover whitespace.
source = open(sys.argv[1], encoding='utf-8').read()
assert 're.split(r"[\\s,;]+", remote_text)' in source, \
    'remote gateways are not split on whitespace'
assert re.split(r"[\s,;]+", 'a.example:1194 b.example:1194') == \
    ['a.example:1194', 'b.example:1194']
PY
assert_grep_fixed 'effective_proto = endpoint_proto or proto' \
    "$TMPDIR/endpoint-engine.py" \
    "per-gateway OpenVPN transport overrides the connection-wide default"

assert_grep_fixed 'cannot execute the WireGuard runtime query' \
    "$TMPDIR/endpoint-engine.py" \
    "a missing optional wg binary cannot escape as an unhandled traceback"
assert_grep_fixed 'item.kind == "wireguard" and _is_hostname(item.host)' \
    "$TMPDIR/endpoint-engine.py" \
    "literal-IP WireGuard peers arm without needing the wg runtime query"
assert_grep_fixed 'skipping unparsable VPN profile' "$TMPDIR/endpoint-engine.py" \
    "one unparsable profile cannot disarm the whole kill switch"

assert_cmd_success "profile scanner is valid bash" bash -n "$TMPDIR/profile-scan.sh"
assert_cmd_success "physical-up scanner dispatcher is valid bash" bash -n "$TMPDIR/scan-on-network-up.sh"
assert_cmd_success "WAN-strict toggle is valid bash" bash -n "$TMPDIR/toggle-wan-strict.sh"
assert_cmd_success "WAN-strict CLI is valid bash" bash -n "$TMPDIR/wan-strict-cli.sh"
assert_grep_fixed '# bounded recovery path during connect' \
    "$TMPDIR/wan-strict-cli.sh" \
    "WAN help names the explicit timed pause as a bounded recovery path"
assert_not_grep '# workaround during connect' "$TMPDIR/wan-strict-cli.sh" \
    "WAN help does not present the bounded recovery path as a workaround"
assert_cmd_success "WAN status publisher is valid bash" bash -n "$TMPDIR/wan-status-publisher.sh"
assert_cmd_success "WAN persisted-strict boot guard is valid bash" bash -n "$TMPDIR/wan-boot-guard.sh"

# The three internal wrappers are exact, argumentless entry points. Exercise
# their real parsing order against redirected dependencies so a regression
# cannot hide behind an early root check, current opt-out flag or host state.
arg_contract_root="$EXEC_TMPDIR/argument-contract"
arg_contract_bin="$arg_contract_root/bin"
arg_contract_state="$arg_contract_root/state"
arg_contract_marker="$arg_contract_root/dependency-called"
mkdir -p "$arg_contract_bin" "$arg_contract_state"
cat > "$arg_contract_bin/dependency" <<'ARG_DEPENDENCY_EOF'
#!/bin/bash
printf 'called\n' >> "$NOID_TEST_ARG_MARKER"
exit 97
ARG_DEPENDENCY_EOF
chmod 0755 "$arg_contract_bin/dependency"

sed \
    -e "s|exec /usr/local/libexec/noid-wan-strict-endpoints publish-status|exec $arg_contract_bin/dependency publish-status|" \
    "$TMPDIR/wan-status-publisher.sh" > "$arg_contract_root/publish-status"
sed \
    -e "s|STATUS_DIR=\"/run/noid-privacy\"|STATUS_DIR=\"$arg_contract_state\"|" \
    -e "s|STATUS_PUBLISHER=\"/usr/local/sbin/noid-wan-strict-publish-status\"|STATUS_PUBLISHER=\"$arg_contract_bin/dependency\"|" \
    -e "s|/usr/local/libexec/noid-wan-strict-endpoints bootstrap|$arg_contract_bin/dependency bootstrap|" \
    -e "s|-o root -g root|-o $(id -un) -g $(id -gn)|g" \
    "$TMPDIR/wan-bootstrap.sh" > "$arg_contract_root/bootstrap"
sed \
    -e "s|/var/lib/noid-privacy/wan-strict-disabled.flag|$arg_contract_root/disabled.flag|" \
    -e "s|ENGINE=/usr/local/libexec/noid-wan-strict-endpoints|ENGINE=$arg_contract_bin/dependency|" \
    "$TMPDIR/profile-scan.sh" > "$arg_contract_root/profile-scan"
chmod 0755 "$arg_contract_root/publish-status" "$arg_contract_root/bootstrap" \
    "$arg_contract_root/profile-scan"

assert_zero_arg_wrapper_rejects() {
    local name=$1 script=$2 expected_error=$3
    local vector_label rc out err
    shift 3
    vector_label=$1
    shift
    out="$arg_contract_root/${name}-${vector_label}.out"
    err="$arg_contract_root/${name}-${vector_label}.err"
    rm -f -- "$arg_contract_marker"
    set +e
    env -i NOID_TEST_ARG_MARKER="$arg_contract_marker" \
        PATH="$arg_contract_bin" /bin/bash "$script" "$@" >"$out" 2>"$err"
    rc=$?
    set -e
    assert_eq "2" "$rc" "$name rejects $vector_label before its dependency"
    assert_eq "" "$(cat "$out")" "$name keeps stdout empty for $vector_label"
    assert_eq "$expected_error" "$(cat "$err")" \
        "$name emits one constant diagnostic for $vector_label"
    if [ ! -e "$arg_contract_marker" ] && [ ! -L "$arg_contract_marker" ]; then
        _pass "$name leaves dependencies unreachable for $vector_label"
    else
        _fail "$name leaves dependencies unreachable for $vector_label"
    fi
}

for wrapper_spec in \
    "publish-status|$arg_contract_root/publish-status|noid-wan-strict-publish-status: no arguments accepted" \
    "bootstrap|$arg_contract_root/bootstrap|noid-wan-strict-bootstrap.sh: no arguments accepted" \
    "profile-scan|$arg_contract_root/profile-scan|noid-wan-strict-scan-profiles.sh: no arguments accepted"; do
    IFS='|' read -r wrapper_name wrapper_path wrapper_error <<< "$wrapper_spec"
    assert_zero_arg_wrapper_rejects "$wrapper_name" "$wrapper_path" \
        "$wrapper_error" unknown unknown
    assert_zero_arg_wrapper_rejects "$wrapper_name" "$wrapper_path" \
        "$wrapper_error" empty ''
    assert_zero_arg_wrapper_rejects "$wrapper_name" "$wrapper_path" \
        "$wrapper_error" surplus one two
    assert_zero_arg_wrapper_rejects "$wrapper_name" "$wrapper_path" \
        "$wrapper_error" newline $'line\nbreak'
    assert_zero_arg_wrapper_rejects "$wrapper_name" "$wrapper_path" \
        "$wrapper_error" ansi $'\033[31mred'
done
for zero_arg_wrapper in "$TMPDIR/wan-status-publisher.sh" \
                        "$TMPDIR/wan-bootstrap.sh" \
                        "$TMPDIR/profile-scan.sh"; do
    assert_grep_fixed 'PATH=/usr/sbin:/usr/bin:/sbin:/bin' "$zero_arg_wrapper" \
        "argumentless WAN wrapper closes command resolution: $(basename "$zero_arg_wrapper")"
    assert_grep_fixed 'if [ "$#" -ne 0 ]; then' "$zero_arg_wrapper" \
        "argumentless WAN wrapper has an explicit count gate: $(basename "$zero_arg_wrapper")"
done

assert_cmd_success "WAN-strict CLI is ShellCheck-clean including info findings" \
    shellcheck -S info "$TMPDIR/wan-strict-cli.sh"
assert_cmd_success "WAN-strict toggle is ShellCheck-clean including info findings" \
    shellcheck -S info "$TMPDIR/toggle-wan-strict.sh"
for mode in DISABLED GRACE_PAUSED GRACE_BOOTSTRAP STRICT STRICT_EMPTY ERROR; do
    assert_grep_fixed "\"$mode\"" "$TMPDIR/endpoint-engine.py" \
        "machine status supports $mode"
done
assert_grep_fixed 'stream.write(f"MODE={mode}\n")' "$TMPDIR/endpoint-engine.py" \
    "status contract is a single machine-readable key"
assert_grep_fixed 'STATUS.unlink(missing_ok=True)' "$TMPDIR/endpoint-engine.py" \
    "failed publication removes stale status instead of preserving a false mode"
assert_grep_fixed '"NOID_WAN_STATUS_FILE", "/run/noid-privacy/wan-strict-status"' \
    "$TMPDIR/endpoint-engine.py" \
    "runtime status cannot survive a failed reboot bootstrap as stale state"
assert_grep_fixed 'wan-strict-bootstrap.failed' "$TMPDIR/endpoint-engine.py" \
    "failed bootstrap publishes a durable runtime ERROR contract"
assert_grep_fixed 'exec /usr/local/libexec/noid-wan-strict-endpoints publish-status' \
    "$TMPDIR/wan-status-publisher.sh" \
    "compatibility status publisher delegates to the locked controller"
assert_grep_fixed '[ -e "$ARMED_FLAG" ]' "$TMPDIR/wan-boot-guard.sh" \
    "pre-up guard uses durable ever-armed state rather than non-empty data"
assert_grep_fixed \
    'valid_marker "$DISABLED_FLAG" NOID_WAN_STRICT_DISABLED_V1' \
    "$TMPDIR/wan-boot-guard.sh" \
    "boot bypass requires the exact disabled marker"
assert_grep_fixed \
    'valid_marker "$ARMED_FLAG" NOID_WAN_STRICT_ARMED_V1' \
    "$TMPDIR/wan-boot-guard.sh" \
    "boot strict path requires the exact armed marker"
assert_grep_fixed 'disabled marker is untrusted or malformed' \
    "$TMPDIR/wan-boot-guard.sh" \
    "malformed opt-out evidence blocks physical pre-up"
assert_grep_fixed 'line=$(read_exact_line "$STATUS_FILE")' \
    "$TMPDIR/wan-boot-guard.sh" \
    "armed boot path requires an exact one-line strict status contract"
assert_grep_fixed 'MODE=GRACE_PAUSED) printf' \
    "$TMPDIR/wan-boot-guard.sh" \
    "bounded user pause survives physical-link reactivation"
assert_grep_fixed 'recovery networking remains available' "$TMPDIR/wan-boot-guard.sh" \
    "never-enabled bootstrap failure retains a documented recovery route"
assert_grep_fixed '/usr/local/sbin/noid-wan-strict-publish-status' "$TMPDIR/wan-bootstrap.sh" \
    "bootstrap publishes actual postcondition"
assert_grep_fixed 'rm -f -- "$STATUS_FILE"' "$TMPDIR/wan-bootstrap.sh" \
    "failed bootstrap retires stale machine status before recomputation"
assert_not_grep '"$STATUS_PUBLISHER" || true' "$TMPDIR/wan-bootstrap.sh" \
    "bootstrap status-publication failure is never swallowed"
assert_grep_fixed 'publish_status()' "$TMPDIR/endpoint-engine.py" \
    "endpoint transitions publish their committed postcondition under lock"
assert_grep_fixed 'def nft_json(*arguments: str) -> list[object]:' \
    "$TMPDIR/endpoint-engine.py" \
    "runtime evidence uses nftables machine-readable output"
assert_grep_fixed 'def explicit_pause_active() -> bool:' \
    "$TMPDIR/endpoint-engine.py" \
    "bounded pause reconciliation has one closed authority"
assert_grep_fixed 'not autoresume_timer_active() or not nft_table_present()' \
    "$TMPDIR/endpoint-engine.py" \
    "neither a stale timer nor an absent table can authorize pause grace"
assert_grep_fixed 'return nft_set_nonempty("bypass_grace_v4")' \
    "$TMPDIR/endpoint-engine.py" \
    "pause preservation also requires the already-committed nft grace set"
assert_grep_fixed 'grace = reconciliation_grace()' \
    "$TMPDIR/endpoint-engine.py" \
    "profile and expiry reconciliation preserve an exact bounded pause"
assert_grep_fixed 'except EndpointError:' "$TMPDIR/endpoint-engine.py" \
    "runtime evidence failures publish ERROR rather than optimistic protection"
assert_grep_fixed 'ARMED_CONTENT = b"NOID_WAN_STRICT_ARMED_V1\n"' \
    "$TMPDIR/endpoint-engine.py" \
    "armed state has an exact versioned content contract"
assert_grep_fixed 'DISABLED_CONTENT = b"NOID_WAN_STRICT_DISABLED_V1\n"' \
    "$TMPDIR/endpoint-engine.py" \
    "disabled state has an exact versioned content contract"
assert_grep_fixed 'STATUS_PUBLISHER=/usr/local/sbin/noid-wan-strict-publish-status' \
    "$TMPDIR/toggle-wan-strict.sh" "feature toggle publishes actual postcondition"
assert_grep_fixed '"$ENDPOINT_ENGINE" publish-status' "$TMPDIR/wan-strict-cli.sh" \
    "root diagnostic refreshes and consumes the committed status snapshot"
assert_grep_fixed 'Published mode: $runtime_mode' "$TMPDIR/wan-strict-cli.sh" \
    "root diagnostic displays the exact published runtime mode"
assert_grep_fixed '"$STATE_FILE" 2>/dev/null) || v4=""' \
    "$TMPDIR/wan-strict-cli.sh" \
    "IPv4 diagnostics treat a not-yet-created endpoint file as an empty set"
assert_grep_fixed '"$STATE_FILE" 2>/dev/null) || v6=""' \
    "$TMPDIR/wan-strict-cli.sh" \
    "IPv6 diagnostics treat a not-yet-created endpoint file as an empty set"
assert_grep_fixed 'read_runtime_mode()' "$TMPDIR/toggle-wan-strict.sh" \
    "feature toggle consumes the published runtime contract"
assert_grep_fixed 'runtime mode:             $runtime_mode' \
    "$TMPDIR/toggle-wan-strict.sh" \
    "unprivileged toggle status displays the published runtime mode"
assert_not_grep '-> ENABLED\|FULLY DISABLED' "$TMPDIR/toggle-wan-strict.sh" \
    "toggle status never substitutes inferred enabled/full labels for runtime mode"

# --- unit-state helpers: a failed unit must not wedge the disable path ------
# systemd keeps a failed unit at ActiveState=failed until `reset-failed`; a
# successful `systemctl stop` does not clear it (verified on an installed
# host). Treating `failed` as still-active made every stop postcondition
# unsatisfiable, so one transient failure broke `noid-toggle-wan-strict off`
# permanently. Exercise the real helpers against a state machine rather than
# grepping for the pattern.
UNIT_STATE_HELPERS="$TMPDIR/unit-state-helpers.sh"
sed -n '/^unit_is_not_running() {/,/^}/p;/^stop_unit_if_running() {/,/^}/p' \
    "$TMPDIR/toggle-wan-strict.sh" > "$UNIT_STATE_HELPERS"
assert_cmd_success "unit-state helpers extract as valid bash" \
    bash -n "$UNIT_STATE_HELPERS"
assert_eq 2 "$(grep -c '^[a-z_]*() {' "$UNIT_STATE_HELPERS")" \
    "both unit-state helpers were extracted"

# Drives the extracted helpers with a systemctl state machine: prints the
# current ActiveState, lets `stop` succeed or fail on demand, and models that
# only reset-failed clears a latched failure.
# The mock state MUST NOT be called `state`: unit_is_not_running declares
# `local state`, and bash's dynamic scoping would let that empty local shadow
# the mock's variable. Every case would then take the `[ -z "$state" ]` branch
# and pass without ever exercising a real ActiveState.
run_unit_state_case() {
    bash -c '
        set -uo pipefail
        MOCK_STATE=$1; MOCK_STOP_RC=$2; MOCK_LOG=$3
        systemctl() {
            case "$1" in
                show) printf "%s\n" "$MOCK_STATE" ;;
                stop) printf "stop\n" >> "$MOCK_LOG"
                      [ "$MOCK_STOP_RC" -eq 0 ] || return "$MOCK_STOP_RC"
                      # Faithful to systemd: a successful stop does NOT clear
                      # a latched failure. Modelling it as cleared would let
                      # this fixture pass against the very defect it guards.
                      [ "$MOCK_STATE" = failed ] || MOCK_STATE=inactive ;;
                reset-failed) printf "reset-failed\n" >> "$MOCK_LOG"
                      [ "$MOCK_STATE" != failed ] || MOCK_STATE=inactive ;;
                *) return 0 ;;
            esac
        }
        . "$4"
        stop_unit_if_running probe.service
        rc=$?
        printf "rc=%s final=%s\n" "$rc" "$MOCK_STATE"
    ' _ "$1" "$2" "$3" "$UNIT_STATE_HELPERS"
}

UNIT_STATE_LOG="$TMPDIR/unit-state.log"

: > "$UNIT_STATE_LOG"
assert_eq "rc=0 final=inactive" "$(run_unit_state_case failed 0 "$UNIT_STATE_LOG")" \
    "a failed unit counts as stopped and is left genuinely inactive"
assert_grep_fixed 'reset-failed' "$UNIT_STATE_LOG" \
    "a latched failure is retired instead of blocking the disable path"
assert_not_grep '^stop$' "$UNIT_STATE_LOG" \
    "an already-failed unit is not stopped a second time"

: > "$UNIT_STATE_LOG"
assert_eq "rc=0 final=inactive" "$(run_unit_state_case active 0 "$UNIT_STATE_LOG")" \
    "a running unit is stopped and its postcondition holds"
assert_grep_fixed 'stop' "$UNIT_STATE_LOG" "a running unit is actually stopped"

: > "$UNIT_STATE_LOG"
assert_eq "rc=1 final=active" "$(run_unit_state_case active 1 "$UNIT_STATE_LOG")" \
    "a refused stop still fails closed instead of reporting success"

: > "$UNIT_STATE_LOG"
assert_eq "rc=0 final=inactive" "$(run_unit_state_case inactive 0 "$UNIT_STATE_LOG")" \
    "an already-inactive unit needs no transition"
assert_not_grep '^stop$' "$UNIT_STATE_LOG" \
    "an inactive unit is not stopped needlessly"
assert_grep_fixed '/usr/local/libexec/noid-wan-strict-endpoints bootstrap' \
    "$TMPDIR/wan-bootstrap.sh" "bootstrap delegates closed state parsing/publication"
for signal_trap in "trap 'exit 129' HUP" "trap 'exit 130' INT" \
                   "trap 'exit 143' TERM"; do
    assert_grep_fixed "$signal_trap" "$TMPDIR/wan-bootstrap.sh" \
        "bootstrap signal exit reaches failure publication: $signal_trap"
done
assert_grep_fixed 'destroy table inet noid_wan_strict\n' \
    "$TMPDIR/endpoint-engine.py" \
    "bootstrap uses idempotent destruction inside the replacement transaction"
assert_grep_fixed 'batch += nft_batch(records, set(), grace, now)' \
    "$TMPDIR/endpoint-engine.py" \
    "table, interfaces, endpoints and grace share one bootstrap transaction"
assert_not_grep 'nft delete table inet noid_wan_strict' "$TMPDIR/wan-bootstrap.sh" \
    "bootstrap has no delete-then-load policy gap"

# If both the endpoint transaction and ERROR-status recomputation fail, the
# service must remain failed and no stale prior MODE=STRICT evidence may
# survive. Keep the executable fixture off the hardened host's noexec /tmp.
bootstrap_fixture_root="$EXEC_TMPDIR/bootstrap-failure"
bootstrap_fixture_bin="$bootstrap_fixture_root/bin"
bootstrap_fixture_status="$bootstrap_fixture_root/run/noid-privacy"
mkdir -p "$bootstrap_fixture_bin" "$bootstrap_fixture_status"
printf 'MODE=STRICT\n' >"$bootstrap_fixture_status/wan-strict-status"
cat >"$bootstrap_fixture_bin/endpoints" <<'WAN_BOOTSTRAP_ENGINE_FAIL_EOF'
#!/bin/bash
exit 69
WAN_BOOTSTRAP_ENGINE_FAIL_EOF
cat >"$bootstrap_fixture_bin/publish-status" <<'WAN_BOOTSTRAP_STATUS_FAIL_EOF'
#!/bin/bash
exit 70
WAN_BOOTSTRAP_STATUS_FAIL_EOF
chmod 0755 "$bootstrap_fixture_bin/endpoints" \
    "$bootstrap_fixture_bin/publish-status"
bootstrap_fixture="$EXEC_TMPDIR/wan-bootstrap-failure.fixture"
sed \
    -e "s|STATUS_DIR=\"/run/noid-privacy\"|STATUS_DIR=\"$bootstrap_fixture_status\"|" \
    -e "s|STATUS_PUBLISHER=\"/usr/local/sbin/noid-wan-strict-publish-status\"|STATUS_PUBLISHER=\"$bootstrap_fixture_bin/publish-status\"|" \
    -e "s|/usr/local/libexec/noid-wan-strict-endpoints bootstrap|$bootstrap_fixture_bin/endpoints bootstrap|" \
    -e "s|-o root -g root|-o $(id -un) -g $(id -gn)|g" \
    "$TMPDIR/wan-bootstrap.sh" >"$bootstrap_fixture"
chmod 0755 "$bootstrap_fixture"
if "$bootstrap_fixture" >"$TMPDIR/bootstrap-failure.out" 2>&1; then
    _fail "failed WAN bootstrap preserves the original non-zero service result"
else
    _pass "failed WAN bootstrap preserves the original non-zero service result"
fi
if [ ! -e "$bootstrap_fixture_status/wan-strict-status" ] \
   && [ ! -L "$bootstrap_fixture_status/wan-strict-status" ]; then
    _pass "failed WAN status recomputation leaves no stale machine mode"
else
    _fail "failed WAN status recomputation leaves no stale machine mode"
fi
assert_file_exists "$bootstrap_fixture_status/wan-strict-bootstrap.failed" \
    "failed WAN bootstrap retains its explicit failure marker"
assert_grep_fixed 'WAN-strict ERROR status publication failed' \
    "$TMPDIR/bootstrap-failure.out" \
    "failed WAN status publication is visible"

assert_grep_fixed 'counter wan_passed_v6 { }' "$TMPDIR/noid-wan-strict.nft" \
    "IPv6 endpoint observability counter is declared"
assert_grep_fixed 'counter name wan_passed_v6 accept' "$TMPDIR/noid-wan-strict.nft" \
    "IPv6 endpoint accepts increment their named counter"
assert_grep_fixed 'exit 5' "$TMPDIR/wan-bootstrap.sh" \
    "corrupt endpoint controller state fails boot closed"
assert_grep_fixed 'wireguard:up|vpn:vpn-up' "$TMPDIR/endpoint-pin.sh" \
    "only supported activated tunnel events can request durable promotion"
# An externally created tunnel reaches this dispatcher too: NetworkManager
# assumes it behind a profile it invents and emits up for it. commit-active
# can never succeed on that profile -- it names the peer key with no endpoint
# -- so without this gate every wg-quick or provider-daemon connect logged a
# warning about an endpoint that "was not durably committed", for a supported
# configuration. Kernel discovery owns those tunnels.
#
# The gate is also what makes "Discovery pins, it does not arm" structural.
# commit_active() calls mark_armed() unconditionally once past its endpoint
# gates, so the contract otherwise rests on NetworkManager happening not to
# copy the kernel peer's endpoint into the profile it invents.
assert_grep_fixed '"${CONNECTION_EXTERNAL:-0}" = 1' "$TMPDIR/endpoint-pin.sh" \
    "an externally created tunnel never reaches the durable commit path"
assert_grep_fixed 'endpoint pinning is owned by kernel discovery' \
    "$TMPDIR/endpoint-pin.sh" \
    "the skip is reported at ordinary priority instead of as a warning"
assert_not_grep 'CONNECTION_FILENAME' "$TMPDIR/endpoint-pin.sh" \
    "profile ownership is never inferred from the profile's path"
# Order matters: the gate has to precede the engine call, or the warning it
# exists to prevent is emitted before it is reached.
assert_cmd_success "the ownership gate precedes the commit-active call" \
    env AWK_IN="$TMPDIR/endpoint-pin.sh" awk '
        /CONNECTION_EXTERNAL/ { gate = NR }
        /commit-active --interface/ && !engine { engine = NR }
        END { exit !(gate && engine && gate < engine) }' "$TMPDIR/endpoint-pin.sh"
assert_grep_fixed 'record-disconnect' "$TMPDIR/tunnel-down.sh" \
    "ordinary down delegates volatile-proof cleanup to the controller"
assert_grep_fixed 'down|vpn-down' "$TMPDIR/tunnel-down.sh" \
    "only tunnel-down actions can retire volatile active proof"
assert_grep_fixed 'connection.type connection show "$UUID"' \
    "$TMPDIR/tunnel-down.sh" \
    "tunnel-down dispatcher classifies the NetworkManager profile"
assert_grep_fixed 'wireguard:down|vpn:vpn-down|:down|:vpn-down' \
    "$TMPDIR/tunnel-down.sh" \
    "schema-matched or previously classified tunnel-down events reach the controller"
assert_not_grep 'pre-down|vpn-pre-down' "$TMPDIR/tunnel-down.sh" \
    "tunnel teardown has no pre-down policy-relaxation phase"
assert_grep_fixed \
    'rm -f /etc/NetworkManager/dispatcher.d/58-wan-strict-clean-disconnect' \
    "$KS_FILE" "retired automatic-relaxation dispatcher is removed"
assert_grep_fixed \
    '/etc/NetworkManager/dispatcher.d/pre-down.d/58-wan-strict-clean-disconnect' \
    "$KS_FILE" "retired pre-down relaxation link is removed"
assert_not_grep 'prepare-clean-disconnect\|finish-disconnect\|CLEAN_RESET' \
    "$TMPDIR/endpoint-engine.py" \
    "endpoint controller has no automatic direct-WAN reset path"
assert_grep_fixed 'print("DOWN_STRICT")' "$TMPDIR/endpoint-engine.py" \
    "every accepted tunnel-down publishes the fail-closed result"
assert_grep_fixed 'print("IGNORED_UNSUPPORTED")' "$TMPDIR/endpoint-engine.py" \
    "unsupported virtual down events are explicitly ignored"
assert_grep_fixed 'stat.S_IMODE(info.st_mode) != 0o600' \
    "$TMPDIR/endpoint-engine.py" \
    "active runtime proof is root-private"
assert_grep_fixed 'info.st_gid != expected_gid' \
    "$TMPDIR/endpoint-engine.py" \
    "runtime and persistent evidence validate the owning group"
assert_grep_fixed 'or mode & 0o022' "$TMPDIR/endpoint-engine.py" \
    "state parents reject group/world-writable replacement boundaries"
assert_not_grep 'if records:' \
    "$TMPDIR/endpoint-engine.py" \
    "saved endpoint records never arm strict mode without tunnel activation"
assert_grep_fixed 'mark_armed()' "$TMPDIR/endpoint-engine.py" \
    "supported tunnel activation retains the durable boot guard"
assert_grep_fixed 'NM.Client.new(None)' "$TMPDIR/endpoint-engine.py" \
    "production profiles come from NetworkManager's loaded libnm model"
assert_grep_fixed 'NM.keyfile_read(' "$TMPDIR/endpoint-engine.py" \
    "isolated fixtures use libnm's section-aware keyfile reader"
assert_grep_fixed 'fixture profile override is disabled in production' \
    "$TMPDIR/endpoint-engine.py" "raw fixture directories are test-gated"
assert_not_grep 'getent\|awk -F=.*endpoint\|/\^endpoint=' \
    "$TMPDIR/endpoint-pin.sh" "active endpoint path has no DNS/file-text trust path"
assert_not_grep 'getent\|awk -F=.*endpoint\|/\^endpoint=' \
    "$TMPDIR/profile-scan.sh" "profile reconciliation wrapper has no additive parser"
assert_grep_fixed 'fcntl.LOCK_EX | fcntl.LOCK_NB' \
    "$TMPDIR/endpoint-engine.py" \
    "every endpoint transition uses a deadline-bounded shared lock"
assert_grep_fixed 'raise LockTimeout("endpoint transaction lock timed out")' \
    "$TMPDIR/endpoint-engine.py" "lock deadline has a distinct retryable verdict"
assert_grep_fixed 'raise SystemExit(75)' "$TMPDIR/endpoint-engine.py" \
    "lock contention exposes the retryable temporary-failure exit code"
assert_grep_fixed 'RestartPreventExitStatus=1' "$TMPDIR/endpoint-pin.sh" \
    "VPN-up lock contention queues a retry without looping permanent failures"
assert_grep_fixed 'raise fail("WAN strict is explicitly disabled")' \
    "$TMPDIR/endpoint-engine.py" \
    "queued dispatcher work rechecks opt-out only after taking the controller lock"
assert_grep_fixed 'getattr(os, "O_NOFOLLOW", 0)' "$TMPDIR/endpoint-engine.py" \
    "transaction lock rejects symlink traversal"
assert_grep_fixed 'stat.S_IMODE(info.st_mode) != 0o600' "$TMPDIR/endpoint-engine.py" \
    "transaction lock has a closed root-private metadata contract"
assert_grep_fixed 'info.st_gid != expected_gid' "$TMPDIR/endpoint-engine.py" \
    "transaction lock and state evidence validate the owning group"
assert_grep_fixed 'NFT = command_path("NOID_NFT_BIN", "/usr/bin/nft")' \
    "$TMPDIR/endpoint-engine.py" "production nft execution uses the absolute Fedora path"
assert_grep_fixed 'WG = command_path("NOID_WG_BIN", "/usr/bin/wg")' \
    "$TMPDIR/endpoint-engine.py" "production WireGuard query uses an absolute path"
assert_grep_fixed 'SYSTEMCTL = command_path("NOID_SYSTEMCTL_BIN", "/usr/bin/systemctl")' \
    "$TMPDIR/endpoint-engine.py" "production timer query uses an absolute path"
assert_grep_fixed 'if TEST_MODE:' "$TMPDIR/endpoint-engine.py" \
    "command overrides remain test-mode-only"
assert_grep_fixed 'read_owned_regular_text(' "$TMPDIR/endpoint-engine.py" \
    "root nft policy input uses the closed owner/mode/no-follow reader"
assert_grep_fixed 'table_headers != [("inet", "noid_wan_strict")]' \
    "$TMPDIR/endpoint-engine.py" "bootstrap accepts exactly one intended nft table"
assert_grep_fixed 'if canonical != value:' "$TMPDIR/endpoint-engine.py" \
    "state parsing rejects rather than normalizes non-canonical endpoint IPs"
assert_grep_fixed 'os.chmod(path, create_mode, follow_symlinks=False)' \
    "$TMPDIR/endpoint-engine.py" \
    "new trusted directories receive their exact mode despite the service umask"
assert_grep_fixed 'type ipv4_addr . inet_proto . inet_service' "$TMPDIR/noid-wan-strict.nft" \
    "IPv4 endpoint permissions are exact address+transport+port tuples"
assert_grep_fixed 'type ipv6_addr . inet_proto . inet_service' "$TMPDIR/noid-wan-strict.nft" \
    "IPv6 endpoint permissions are exact address+transport+port tuples"
assert_grep_fixed 'ip daddr . meta l4proto . th dport @vpn_endpoints_v4' "$TMPDIR/noid-wan-strict.nft" \
    "IPv4 allow rule requires the full endpoint tuple"
assert_grep_fixed 'ip6 daddr . meta l4proto . th dport @vpn_endpoints_v6' "$TMPDIR/noid-wan-strict.nft" \
    "IPv6 allow rule requires the full endpoint tuple"
assert_grep_fixed 'HEADER = "NOID-WAN-ENDPOINTS-V2"' "$TMPDIR/endpoint-engine.py" \
    "persistent endpoint state has a versioned closed contract"
assert_grep_fixed 'if len(fields) != 7' "$TMPDIR/endpoint-engine.py" \
    "controller validates every provenance-state field"
assert_grep_fixed 'source not in {"literal", "authenticated", "retained"}' \
    "$TMPDIR/endpoint-engine.py" "state provenance is closed"
assert_grep_fixed 'if (source == "literal") != (expires == 0):' \
    "$TMPDIR/endpoint-engine.py" \
    "only a re-derived literal record may omit a deadline"
assert_grep_fixed 'persistent-profile override is disabled in production' \
    "$TMPDIR/endpoint-engine.py" \
    "saved-profile lookup cannot be redirected outside test mode"

# Unmanaged kernel tunnels have no NetworkManager profile and produce no
# dispatcher event, so udev is the only trigger that fires in time.
assert_grep_fixed \
    'SUBSYSTEM=="net", ACTION=="add", ENV{DEVTYPE}=="wireguard", TAG+="systemd", ENV{SYSTEMD_WANTS}+="noid-wan-strict-tunnel-scan.service"' \
    "$KS_FILE" "unmanaged tunnel discovery is triggered by the kernel net event"
assert_grep_fixed 'cat > /etc/udev/rules.d/71-noid-wan-strict-tunnel-hotplug.rules' \
    "$KS_FILE" "the hotplug rule has an exact installed path"
assert_grep_fixed 'cat > /etc/systemd/system/noid-wan-strict-tunnel-scan.service' \
    "$KS_FILE" "the hotplug rule starts an installed unit"
for hardening in 'ProtectSystem=strict' 'NoNewPrivileges=yes' \
                 'CapabilityBoundingSet=CAP_NET_ADMIN' \
                 'ExecStart=/usr/local/sbin/noid-wan-strict-scan-profiles.sh'; do
    assert_grep_fixed "$hardening" "$TMPDIR/tunnel-scan.service" \
        "unmanaged tunnel scan keeps the profile scanner's contract: $hardening"
done
assert_not_grep 'nmcli connection reload' "$TMPDIR/tunnel-scan.service" \
    "a kernel tunnel event does not re-read every NetworkManager keyfile"
assert_grep_fixed 'listing = _wg_query("all", field)' "$TMPDIR/endpoint-engine.py" \
    "discovery reads the whole kernel view in one query"
assert_grep_fixed 'CAP_NET_ADMIN' "$TMPDIR/endpoint-engine.py" \
    "the controller states why the kernel view is a trusted source"
assert_grep_fixed 'os.replace(staged, STATE)' "$TMPDIR/endpoint-engine.py" \
    "state publication is atomic"
assert_grep_fixed 'prior strict state restored' "$TMPDIR/endpoint-engine.py" \
    "partial explicit reset rolls grace back to prior strict state"
assert_grep_fixed '[*NFT, "-f", "-"]' "$TMPDIR/endpoint-engine.py" \
    "all endpoint-set replacements use one nft transaction"
assert_grep_fixed 'vpn_candidates_v4' "$TMPDIR/noid-wan-strict.nft" \
    "IPv4 DNS candidates have a separate nft set"
assert_grep_fixed 'vpn_candidates_v6' "$TMPDIR/noid-wan-strict.nft" \
    "IPv6 DNS candidates have a separate nft set"
assert_grep_fixed 'timeout 2m' "$TMPDIR/noid-wan-strict.nft" \
    "candidate sets have a kernel-enforced default timeout"
assert_grep_fixed 'set vpn_bootstrap_routes_v4 {' "$TMPDIR/noid-wan-strict.nft" \
    "dynamic-client IPv4 bootstrap routes have a separate set"
assert_grep_fixed 'set vpn_bootstrap_routes_v6 {' "$TMPDIR/noid-wan-strict.nft" \
    "dynamic-client IPv6 bootstrap routes have a separate set"
awk '
    /^[[:space:]]*set vpn_bootstrap_routes_v4 \{/ { inside=1 }
    inside { print }
    inside && /^[[:space:]]*\}/ { exit }
' "$TMPDIR/noid-wan-strict.nft" > "$TMPDIR/bootstrap-routes-v4.nft"
assert_grep_extended '^[[:space:]]*type ipv4_addr \. inet_proto[[:space:]]*$' \
    "$TMPDIR/bootstrap-routes-v4.nft" \
    "bootstrap route allowance is address and transport scoped"
assert_grep_fixed 'timeout 1m' "$TMPDIR/noid-wan-strict.nft" \
    "bootstrap route sets have a kernel-enforced one-minute lifetime"
assert_grep_fixed 'ip daddr . meta l4proto @vpn_bootstrap_routes_v4' \
    "$TMPDIR/noid-wan-strict.nft" \
    "local IPv4 output can use only a current bootstrap address/transport"
sed -n '/chain forward {/,/^    }/p' "$TMPDIR/noid-wan-strict.nft" \
    > "$TMPDIR/nft-forward-chain"
assert_not_grep 'vpn_bootstrap_routes_v4' "$TMPDIR/nft-forward-chain" \
    "transient bootstrap routes never permit forwarded traffic"
assert_grep_fixed 'meta skuid "systemd-resolve"' "$TMPDIR/noid-wan-strict.nft" \
    "pre-tunnel DNS egress is resolver-process scoped"
assert_grep_fixed 'noid-wan-strict-endpoint-expiry.timer' "$KS_FILE" \
    "authenticated endpoint records have an installed expiry timer"
assert_not_grep '^Persistent=true$' "$KS_FILE" \
    "monotonic expiry timer writes no meaningless persistent calendar stamp"
assert_grep_fixed 'ExecStart=/usr/local/libexec/noid-wan-strict-endpoints expire' \
    "$KS_FILE" "expiry service prunes profiles without refreshing DNS candidates"
assert_grep_fixed 'resolve_candidates=False' "$TMPDIR/endpoint-engine.py" \
    "expiry/profile prune cannot prolong unauthenticated candidates"
assert_grep_fixed 'changed = records != existing' "$TMPDIR/endpoint-engine.py" \
    "unchanged expiry pass avoids endpoint-state and nft churn"
assert_grep_fixed 'ExecStartPre=/usr/bin/nmcli connection reload' "$KS_FILE" \
    "profile-path events synchronize NetworkManager before reconciliation"
assert_grep_fixed 'systemctl enable noid-wan-strict-endpoint-expiry.timer' \
    "$KS_FILE" "authenticated endpoint expiry is enabled"
assert_grep_fixed 'NOID_MEI_KT_CHECK_ONLY=1' "$PROJECT_ROOT/kickstart/snippets/15-intel-me-mitigation.ks" \
    "cross-module Intel KT check remains non-mutating in status detector"
assert_grep_fixed 'IPv4 bootstrap-grace mode' "$PROJECT_ROOT/docs/wan-egress-strict.md" \
    "fresh-install direct-WAN exception is explicit"
assert_not_grep 'Strict mode becomes permanent' "$PROJECT_ROOT/docs/wan-egress-strict.md" \
    "documentation does not describe a user-controllable state as permanent"
assert_grep_fixed 'This table describes endpoint extraction only' \
    "$PROJECT_ROOT/docs/wan-egress-strict.md" \
    "provider rows do not overclaim whole-client qualification"
assert_grep_fixed 'IVPN desktop client' "$PROJECT_ROOT/docs/wan-egress-strict.md" \
    "IVPN standard-transport boundary is stated explicitly"
assert_grep_fixed 'IPsec/IKEv2 is not a recognized M06 profile path' \
    "$PROJECT_ROOT/docs/wan-egress-strict.md" \
    "IVPN naming cannot be mistaken for IPsec support"
assert_grep_fixed 'mullvad/mullvadvpn-app/blob/main/docs/security.md' \
    "$PROJECT_ROOT/docs/wan-egress-strict.md" \
    "Mullvad firewall qualification boundary cites current primary source"
assert_grep_fixed 'ivpn/desktop-app/blob/development/readme.md' \
    "$PROJECT_ROOT/docs/wan-egress-strict.md" \
    "IVPN protocol statement cites current primary source"

# Heredoc marker
assert_grep_fixed "DISPATCHER_EOF" "$KS_FILE"

# Verification step is present (bash -n of the dispatcher itself + content check)
assert_grep_fixed 'bash -n /etc/NetworkManager/dispatcher.d/50-vpn-zone-enforce' "$KS_FILE"
assert_grep_fixed 'verify_owned_regular()' "$KS_FILE" \
    "STEP 8 has one closed owner/mode/link-count verifier"
STEP8_BLOCK="$TMPDIR/step8-verification.sh"
STEP8_NORMALIZED="$TMPDIR/step8-verification-normalized.sh"
awk '/^# STEP 8: Verification/,/^%end$/' "$KS_FILE" > "$STEP8_BLOCK"
awk '{
    if (sub(/[[:space:]]*\\$/, "")) {
        printf "%s ", $0
    } else {
        print
    }
}' "$STEP8_BLOCK" | sed -E 's/[[:space:]]+/ /g' > "$STEP8_NORMALIZED"

# Every directly installed M06 file is a closed regular-file contract. Symlink
# registrations are checked separately against their exact relative targets.
while IFS='|' read -r verified_path expected_mode; do
    [ -n "$verified_path" ] || continue
    count=$(grep -Fc \
        "verify_owned_regular $verified_path $expected_mode" \
        "$STEP8_NORMALIZED" || true)
    if [ "$count" -eq 1 ]; then
        _pass "STEP 8 verifies installed surface: $verified_path ($expected_mode)"
    else
        _fail "STEP 8 verifies installed surface exactly once: $verified_path ($expected_mode)"
    fi
done <<'VERIFIED_SURFACES_EOF'
/etc/NetworkManager/dispatcher.d/50-vpn-zone-enforce|700
/usr/local/sbin/noid-wireguard-mtu-reconcile|755
/etc/NetworkManager/dispatcher.d/pre-up.d/45-noid-wireguard-mtu|700
/etc/NetworkManager/dispatcher.d/no-wait.d/45-noid-wireguard-mtu|700
/etc/nftables.d/noid-wan-strict.nft|644
/etc/tmpfiles.d/noid-wan-strict.conf|644
/usr/local/sbin/noid-wan-strict-publish-status|755
/usr/local/libexec/noid-wan-strict-endpoints|755
/usr/local/sbin/noid-wan-strict-bootstrap.sh|700
/etc/systemd/system/noid-wan-strict.service|644
/etc/systemd/system/noid-wan-strict-status-publish.service|644
/etc/NetworkManager/dispatcher.d/pre-up.d/20-noid-wan-strict-boot-guard|700
/etc/NetworkManager/dispatcher.d/58-wan-strict-tunnel-down|700
/etc/NetworkManager/dispatcher.d/60-vpn-endpoint-pin|700
/usr/local/sbin/noid-wan-strict|755
/usr/local/sbin/noid-wan-strict-scan-profiles.sh|700
/etc/NetworkManager/dispatcher.d/no-wait.d/55-wan-strict-scan-on-network-up|700
/etc/systemd/system/noid-wan-strict-scan-profiles.path|644
/etc/systemd/system/noid-wan-strict-scan-profiles.service|644
/etc/systemd/system/noid-wan-strict-endpoint-expiry.service|644
/etc/systemd/system/noid-wan-strict-endpoint-expiry.timer|644
/usr/local/sbin/noid-toggle-wan-strict|755
/usr/share/doc/noid-privacy/wan-egress-strict.md|644
VERIFIED_SURFACES_EOF
assert_grep_fixed \
    'ExecStart=/usr/local/sbin/noid-wan-strict-bootstrap.sh' \
    "$STEP8_BLOCK" "STEP 8 verifies the main killswitch ExecStart"
assert_not_grep 'noid-wan-strict-bootstrap.service' "$KS_FILE" \
    "WAN strict comments name the installed noid-wan-strict.service unit"
assert_grep_fixed \
    'PathChanged=/etc/NetworkManager/system-connections' \
    "$STEP8_BLOCK" "STEP 8 verifies the profile watcher contract"
assert_grep_fixed 'Unit=noid-wan-strict-endpoint-expiry.service' \
    "$STEP8_BLOCK" "STEP 8 verifies the expiry timer target"
assert_grep_fixed \
    'readlink /etc/NetworkManager/dispatcher.d/pre-up.d/50-vpn-zone-enforce' \
    "$STEP8_BLOCK" "STEP 8 verifies the VPN pre-up registration"
assert_grep_fixed \
    'readlink /etc/NetworkManager/dispatcher.d/55-wan-strict-scan-on-network-up' \
    "$STEP8_BLOCK" "STEP 8 verifies the no-wait dispatcher registration"
assert_grep_fixed \
    'readlink /etc/NetworkManager/dispatcher.d/45-noid-wireguard-mtu' \
    "$STEP8_BLOCK" "STEP 8 verifies the MTU no-wait dispatcher registration"
assert_grep_fixed \
    '[ ! -e /etc/NetworkManager/dispatcher.d/pre-down.d/58-wan-strict-clean-disconnect ]' \
    "$STEP8_BLOCK" "STEP 8 rejects the retired pre-down relaxation registration"
assert_not_grep_extended 'log "STEP.*#[0-9]+' "$KS_FILE" \
    "installation log contains no stale numbered history marker"

# --- noid-toggle-wan-strict CLI + state-file 0644 ---
assert_grep_fixed 'TOGGLE_WAN_STRICT_EOF' "$KS_FILE" "toggle-wan-strict heredoc marker"
assert_grep_fixed '/usr/local/sbin/noid-toggle-wan-strict' "$KS_FILE" "toggle binary path"
assert_grep_fixed 'STEP 6b' "$KS_FILE" "STEP 6b deployment label"
assert_grep_fixed 'wan-strict-disabled.flag' "$KS_FILE" "flag-file path"
# State-file mode 0644 remains GUI-readable but is owned by one atomic writer.
assert_grep_fixed 'os.fchmod(stream.fileno(), 0o644)' "$TMPDIR/endpoint-engine.py" \
    "controller publishes exact state-file mode 0644"

# --- dispatcher early-exit guard + current loaded-profile reconciliation ---
# Both opt-out-aware dispatchers exit on the exact durable flag before doing
# any profile or endpoint work.
assert_grep_fixed \
    '[ -e /var/lib/noid-privacy/wan-strict-disabled.flag ] && exit 0' \
    "$TMPDIR/endpoint-pin.sh" "endpoint dispatcher has the opt-out early-exit guard"
assert_grep_fixed \
    '[ ! -e "$DISABLED_FLAG" ] || exit 0' \
    "$TMPDIR/scan-on-network-up.sh" "network-up scanner has the opt-out early-exit guard"
assert_not_grep '/sys/class/net/proton\*\|/sys/class/net/mullvad-' \
    "$TMPDIR/wan-bootstrap.sh" "bootstrap no longer guesses active VPNs by interface name"
assert_grep_fixed '"$SCANNER"' "$TMPDIR/toggle-wan-strict.sh" \
    "toggle-on reconciles NetworkManager-loaded profiles"
# Toggle script: the chmod-toggle mechanism was REMOVED (the dispatcher
# stays 0700 always; the flag-file is the single source of truth). The
# documenting lock-history block was consolidated away and the chmod-toggle
# lines no longer exist in source, so a direct absence-assert is unambiguous.
assert_not_grep 'chmod 0[67]00 "$DISPATCHER"' "$KS_FILE" \
    "chmod-toggle anti-pattern absent (flag-file is single source of truth)"
assert_grep_fixed 'rollback_failed_enable()' "$TMPDIR/toggle-wan-strict.sh" \
    "failed enable has an explicit rollback"
assert_grep_fixed 'systemctl is-active --quiet "$SERVICE"' "$TMPDIR/toggle-wan-strict.sh" \
    "toggle verifies the service is active before reporting success"
assert_grep_fixed '! nft_table_present || ! dispatcher_executable' "$TMPDIR/toggle-wan-strict.sh" \
    "toggle verifies nft table and dispatcher before reporting success"
assert_not_grep 'systemctl enable --now "$SERVICE".*|| true' "$TMPDIR/toggle-wan-strict.sh" \
    "WAN-strict enable failure is not swallowed"
assert_not_grep 'systemctl unmask "$SERVICE".*|| true' "$TMPDIR/toggle-wan-strict.sh" \
    "WAN-strict unmask failure is not swallowed"
assert_grep_fixed 'set -euo pipefail' "$TMPDIR/wan-strict-cli.sh" \
    "WAN control CLI cannot continue after a load-bearing failure"
assert_grep_fixed 'NFT_FAMILY=inet' "$TMPDIR/wan-strict-cli.sh" \
    "WAN CLI keeps nft family separate from the table name"
assert_grep_fixed 'nft list table "$NFT_FAMILY" "$NFT_TABLE"' \
    "$TMPDIR/wan-strict-cli.sh" \
    "WAN CLI passes fixed nft selectors as quoted arguments"
assert_grep_fixed 'NFT_FAMILY=inet' "$TMPDIR/toggle-wan-strict.sh" \
    "WAN toggle keeps nft family separate from the table name"
assert_grep_fixed 'nft list table "$NFT_FAMILY" "$NFT_TABLE"' \
    "$TMPDIR/toggle-wan-strict.sh" \
    "WAN toggle passes fixed nft selectors as quoted arguments"
assert_grep_fixed '"$ENDPOINT_ENGINE" pause' "$TMPDIR/wan-strict-cli.sh" \
    "pause uses the shared locked controller"
assert_grep_fixed '"$ENDPOINT_ENGINE" resume' "$TMPDIR/wan-strict-cli.sh" \
    "resume uses the shared locked controller"
assert_grep_fixed '"$ENDPOINT_ENGINE" arm-empty' "$TMPDIR/wan-strict-cli.sh" \
    "no-VPN fail-closed selection uses the shared locked controller"
assert_grep_fixed '--timer-property=AccuracySec=1s' \
    "$TMPDIR/wan-strict-cli.sh" \
    "bounded pause has an explicit one-second timer accuracy"
assert_not_grep 'nft .*add element.*bypass_grace_v4\|nft flush set.*bypass_grace_v4' \
    "$TMPDIR/wan-strict-cli.sh" \
    "pause/resume never mutate grace outside the controller lock"
assert_grep_fixed '"$ENDPOINT_ENGINE" disable' "$TMPDIR/toggle-wan-strict.sh" \
    "feature disable removes the table under the shared controller lock"
assert_grep_fixed '"$ENDPOINT_ENGINE" enable' "$TMPDIR/toggle-wan-strict.sh" \
    "feature enable installs the table under the shared controller lock"
assert_grep_fixed 'PROFILE_PATH=noid-wan-strict-scan-profiles.path' \
    "$TMPDIR/toggle-wan-strict.sh" \
    "feature toggle owns the profile watcher lifecycle"
assert_grep_fixed 'EXPIRY_TIMER=noid-wan-strict-endpoint-expiry.timer' \
    "$TMPDIR/toggle-wan-strict.sh" \
    "feature toggle owns the endpoint-expiry timer lifecycle"
assert_grep_fixed \
    'quiesce_auxiliary_units' \
    "$TMPDIR/toggle-wan-strict.sh" \
    "feature opt-out stops persistent M06 background activation"
assert_grep_fixed 'PROFILE_SERVICE=noid-wan-strict-scan-profiles.service' \
    "$TMPDIR/toggle-wan-strict.sh" \
    "feature opt-out drains an already-triggered profile scan"
assert_grep_fixed 'EXPIRY_SERVICE=noid-wan-strict-endpoint-expiry.service' \
    "$TMPDIR/toggle-wan-strict.sh" \
    "feature opt-out drains an already-triggered expiry pass"
assert_grep_fixed 'AUTORESUME_SERVICE=noid-wan-strict-autoresume.service' \
    "$TMPDIR/toggle-wan-strict.sh" \
    "feature opt-out drains a queued transient auto-resume"
assert_grep_fixed 'policy remains enforced' "$TMPDIR/toggle-wan-strict.sh" \
    "failed background drain aborts before policy removal"
assert_grep_fixed \
    'systemctl enable --now "$PROFILE_PATH" "$EXPIRY_TIMER"' \
    "$TMPDIR/toggle-wan-strict.sh" \
    "feature opt-in restores required M06 background reconciliation"
assert_grep_fixed 'auxiliary_units_are_off' "$TMPDIR/toggle-wan-strict.sh" \
    "disabled postcondition verifies silent watcher/timer state"
assert_grep_fixed 'auxiliary_units_are_on' "$TMPDIR/toggle-wan-strict.sh" \
    "active postcondition verifies watcher/timer availability"
assert_not_grep 'touch "$FLAG"\|rm -f "$FLAG"' "$TMPDIR/toggle-wan-strict.sh" \
    "toggle never mutates the shared disabled flag outside the controller lock"

# --- scan-profiles helper + path-unit + service ---
# Compatibility helper invokes exact libnm reconciliation.
assert_grep_fixed '/usr/local/sbin/noid-wan-strict-scan-profiles.sh' "$KS_FILE" "scan-profiles helper path"
assert_grep_fixed 'SCAN_PROFILES_EOF' "$KS_FILE" "scan-profiles helper heredoc marker"
# Path-unit watches NM connection-profiles directory
assert_grep_fixed '/etc/systemd/system/noid-wan-strict-scan-profiles.path' "$KS_FILE" "path-unit"
assert_grep_fixed 'PathChanged=/etc/NetworkManager/system-connections' "$KS_FILE" "PathChanged target"
# Service-unit triggered by path-unit
assert_grep_fixed '/etc/systemd/system/noid-wan-strict-scan-profiles.service' "$KS_FILE" "service-unit"
# `After=NetworkManager.service` is satisfied by an NM job that failed on one of
# its own dependencies, so this unit can be released with no daemon listening.
# Both the reload and the libnm scanner need it. Without the gate the
# unconditional ExecStartPre turns every NM-less boot into a second red unit,
# and the path unit re-arms the same failure on each profile change — including
# the archival that M41 performs on the very first installed boot.
assert_grep_fixed \
    'ExecCondition=/usr/bin/systemctl is-active --quiet NetworkManager.service' \
    "$TMPDIR/profile-scan.service" \
    "endpoint scan is skipped, not failed, while NetworkManager is down"
assert_grep_fixed 'does not replay a consumed event' "$KS_FILE" \
    "path-unit comment credits the real reconciliation re-entry paths"
# CLI subcommand `scan-profiles`
assert_grep_fixed 'scan-profiles)' "$TMPDIR/wan-strict-cli.sh" \
    "CLI scan-profiles subcommand"
assert_cmd_success "WAN help works without root or a loaded nft table" \
    bash "$TMPDIR/wan-strict-cli.sh" help
assert_grep_fixed 'arm-empty [--yes]' "$TMPDIR/wan-strict-cli.sh" \
    "WAN help exposes the confirmed no-VPN fail-closed transition"
assert_not_grep 'Toggle wan-strict off' "$TMPDIR/wan-strict-cli.sh" \
    "help does not promise a hostname re-pin without a fresh activation event"
assert_not_grep 'block ALL physical WAN' "$TMPDIR/wan-strict-cli.sh" \
    "WAN CLI does not overstate STRICT_EMPTY as blocking its resolver bootstrap"
assert_grep_fixed \
    'Only the documented systemd-resolved bootstrap exception remains' \
    "$TMPDIR/wan-strict-cli.sh" \
    "WAN CLI names the retained process-scoped resolver bootstrap"
assert_grep_fixed \
    '(unavailable — nft table is absent in $runtime_mode mode)' \
    "$TMPDIR/wan-strict-cli.sh" \
    "root status remains usable for the explicit disabled mode"
wan_status_extra_output=
if wan_status_extra_output=$(bash "$TMPDIR/wan-strict-cli.sh" status extra 2>&1); then
    wan_status_extra_rc=0
else
    wan_status_extra_rc=$?
fi
assert_eq 2 "$wan_status_extra_rc" \
    "WAN status rejects extra arguments with its parser exit code"
assert_eq 'ERROR: status accepts no arguments' "$wan_status_extra_output" \
    "WAN status reports the exact extra-argument contract"
assert_cmd_failure "WAN toggle status rejects ignored extra arguments" \
    bash "$TMPDIR/toggle-wan-strict.sh" status extra
assert_grep_fixed '"$ENGINE" reconcile' "$TMPDIR/profile-scan.sh" \
    "scan-profiles compatibility command replaces rather than appends desired state"
# Physical-link `up` retries hostname resolution after DNS is usable.
assert_grep_fixed '/etc/NetworkManager/dispatcher.d/55-wan-strict-scan-on-network-up' "$KS_FILE" "physical-up scanner dispatcher path"
assert_grep_fixed 'dns-change)' "$TMPDIR/scan-on-network-up.sh" \
    "DNS changes trigger candidate reconciliation"
assert_grep_fixed 'reapply)' "$TMPDIR/scan-on-network-up.sh" \
    "physical Reapply triggers current bootstrap-route reconciliation"
assert_grep_fixed 'reconcile-bootstrap --interface "$IFACE" --uuid "$UUID"' \
    "$TMPDIR/scan-on-network-up.sh" \
    "Reapply delegates to the locked libnm controller"
assert_grep_fixed '[ -d "/sys/class/net/$IFACE/device" ]' "$TMPDIR/scan-on-network-up.sh" "scanner retry is physical-link scoped"
assert_grep_extended 'chmod 700 /etc/NetworkManager/dispatcher.d/no-wait.d/55-wan-strict-scan-on-network-up' "$KS_FILE" "physical-up/reapply target mode 700"
assert_grep_fixed 'ln -sfn no-wait.d/55-wan-strict-scan-on-network-up' "$KS_FILE" \
    "official no-wait dispatcher placement closes the pre-profile race"
assert_grep_fixed 'get_applied_connection_async' "$TMPDIR/endpoint-engine.py" \
    "controller reads NetworkManager's current applied connection natively"
assert_grep_fixed 'for family, address, next_hop in _host_routes(runtime):' \
    "$TMPDIR/endpoint-engine.py" \
    "candidates come from the applied connection, the authority on live routing"
assert_not_grep '_host_routes(runtime) - _host_routes(persistent)\|- saved' \
    "$TMPDIR/endpoint-engine.py" \
    "keyfile-flush timing may not decide whether a probe route is admitted"
assert_grep_fixed 'persistent = _persistent_profile(profile_uuid)' \
    "$TMPDIR/endpoint-engine.py" \
    "persistent profile is still read as the root-ownership gate"
assert_grep_fixed 'if persistent is None:' "$TMPDIR/endpoint-engine.py" \
    "absent or untrusted physical profile yields no bootstrap window at all"
assert_grep_fixed 'candidate.get_connection_type() != "dummy"' \
    "$TMPDIR/endpoint-engine.py" \
    "bootstrap route requires a software dummy default-route owner"
assert_grep_fixed 'if len(addresses) > 8' "$TMPDIR/endpoint-engine.py" \
    "bootstrap route fanout has a closed upper bound"
assert_not_grep 'systemctl enable noid-wan-strict-scan-profiles.path.*|| true' "$KS_FILE" \
    "path-unit enable failure is not swallowed"
# CLI help text fix: false "No action needed" claim REMOVED
assert_not_grep 'No action needed — dispatcher pins new endpoint' "$KS_FILE"

# --- no universal WireGuard keepalive mutation ------------------------------
assert_not_grep 'KEEPALIVE_EOF\|wg set.*persistent-keepalive' "$KS_FILE" \
    "runtime off is never rewritten as an assumed missing keepalive"
assert_grep_fixed 'rm -f /etc/NetworkManager/dispatcher.d/80-vpn-keepalive' \
    "$KS_FILE" "rerun removes the obsolete universal mutator"
assert_grep_fixed 'obsolete universal WireGuard keepalive mutator present' \
    "$KS_FILE" "compose verification rejects the retired hook"
assert_grep_fixed '# PersistentKeepalive = 25' \
    "$PROJECT_ROOT/kickstart/snippets/29-user-docs.ks" \
    "generic WireGuard keepalive is an explicit commented opt-in"
assert_grep_fixed 'NoID Privacy does not infer user' \
    "$PROJECT_ROOT/kickstart/snippets/29-user-docs.ks" \
    "documentation states the unobservable-intent boundary"

# --- no provider-owned Proton profile mutation ------------------------------
assert_grep_fixed \
    'rm -f /etc/NetworkManager/dispatcher.d/70-pvpn-killswitch-dns-fix' \
    "$KS_FILE" "rerun removes the obsolete Proton profile mutator"
assert_grep_fixed 'Provider-owned kill-switch profiles' "$KS_FILE" \
    "M06 keeps provider profile and sentinel lifecycle outside its authority"
assert_not_grep \
    'KS_FIX_EOF\|Clearing invalid DNS placeholder\|nmcli con down "\$UUID"' \
    "$KS_FILE" "M06 never rewrites or reactivates a provider kill-switch profile"
assert_grep_fixed 'obsolete Proton kill-switch profile mutator present' \
    "$PROJECT_ROOT/kickstart/snippets/99-finalize.ks" \
    "compose verification rejects the retired provider mutator"

# --- exact no-hype threat/onboarding boundary -------------------------------
assert_not_grep 'ships an always-active\|BitTorrent bind / malware' "$KS_FILE" \
    "M06 source makes no universal always-active or malware-proof claim"
for boundary in 'deliberately has no automatic wall-clock expiry' \
                'not described as malware-proof' AF_PACKET CAP_NET_RAW \
                CAP_NET_ADMIN CAP_SYS_ADMIN 'initial host network stack'; do
    assert_grep_fixed "$boundary" "$PROJECT_ROOT/docs/wan-egress-strict.md" \
        "WAN documentation names exact boundary: $boundary"
done
assert_grep_fixed 'Required onboarding/no-VPN decision' \
    "$PROJECT_ROOT/kickstart/snippets/29-user-docs.ks" \
    "installed setup guide requires an explicit onboarding/no-VPN decision"
assert_file_executable \
    "$PROJECT_ROOT/tests/pre-ship/21-wan-threat-boundary-runtime.sh"
assert_cmd_success "WAN threat-boundary runtime gate parses" \
    bash -n "$PROJECT_ROOT/tests/pre-ship/21-wan-threat-boundary-runtime.sh"

# --- Functional libnm/reconciliation fixture; no host network mutation -----
profiles="$TMPDIR/profiles"
# Stand-in for /etc/NetworkManager/system-connections. Whether a profile is
# saved here decides whether its observed-active tuples earn a bounded
# `retained` lease, so this directory must be an explicit fixture: without the
# override the controller would read the host's real profile directory, where
# an unreadable root-only keyfile would answer "saved" by accident and every
# retention check below would pass without exercising anything.
persistent="$TMPDIR/persistent"
state_dir="$TMPDIR/state"
mkdir -p "$profiles" "$persistent" "$state_dir"
chmod 0755 "$state_dir"
printf 'NOID_GATEWAY_XDP_READY_V1\n' > "$state_dir/network-ready"
chmod 0644 "$state_dir/network-ready"
cat > "$profiles/wg-literal.nmconnection" <<'WG_LITERAL_PROFILE'
[connection]
id=literal
uuid=11111111-1111-4111-8111-111111111111
type=wireguard

[wireguard]
private-key-flags=2

[wireguard-peer.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=]
endpoint=198.51.100.10:51820
allowed-ips=0.0.0.0/0;
WG_LITERAL_PROFILE
cat > "$profiles/wg-hostname.nmconnection" <<'WG_HOSTNAME_PROFILE'
[connection]
id=hostname
uuid=22222222-2222-4222-8222-222222222222
type=wireguard

[wireguard]
private-key-flags=2

[wireguard-peer.AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=]
endpoint=vpn.example:51821
allowed-ips=0.0.0.0/0;

[ipv4]
method=disabled
endpoint=192.0.2.250:9999
WG_HOSTNAME_PROFILE
cat > "$profiles/openvpn.nmconnection" <<'VPN_PROFILE'
[connection]
id=openvpn
uuid=33333333-3333-4333-8333-333333333333
type=vpn

[vpn]
service-type=org.freedesktop.NetworkManager.openvpn
remote=192.0.2.200
remote=ovpn.example
proto=tcp
port=443
ca=/etc/pki/noid-test-ca.pem
remote-cert-tls=server

[ipv4]
method=auto
remote=192.0.2.251
VPN_PROFILE
# Every profile above stands for an ordinary saved profile, so it exists on
# "disk" too and earns no retention lease. Deleting one must keep revoking its
# pin in the same reconciliation, which the assertions further down rely on.
cp "$profiles"/*.nmconnection "$persistent/"
cat > "$TMPDIR/dns.map" <<'DNS_MAP'
vpn.example 203.0.113.10
vpn.example 203.0.113.11
ovpn.example 192.0.2.44
DNS_MAP
cat > "$TMPDIR/nft-mock" <<'NFT_MOCK'
#!/bin/bash
set -euo pipefail
printf '%s\n' "--- $*" >> "$NOID_NFT_LOG"
if [ "$*" = "-j list tables" ]; then
    printf '%s\n' \
        '{"nftables":[{"table":{"family":"inet","name":"noid_wan_strict"}}]}'
    exit 0
fi
if [ "${1:-}" = -j ] && [ "${2:-}" = list ] && [ "${3:-}" = set ] \
        && [ "${4:-}" = inet ] && [ "${5:-}" = noid_wan_strict ]; then
    set_name=${6:-}
    elements=
    case " ${NOID_NFT_NONEMPTY_SETS:-} " in
        *" $set_name "*) elements=',"elem":[{"fixture":"present"}]' ;;
    esac
    printf '{"nftables":[{"set":{"family":"inet","name":"%s","table":"noid_wan_strict"%s}}]}\n' \
        "$set_name" "$elements"
    exit 0
fi
if [ "${1:-}" = "-f" ]; then
    if [ -n "${NOID_NFT_STARTED_FILE:-}" ]; then
        : > "$NOID_NFT_STARTED_FILE"
    fi
    if [ -n "${NOID_NFT_SLEEP:-}" ]; then
        sleep "$NOID_NFT_SLEEP"
    fi
    cat >> "$NOID_NFT_LOG"
fi
printf '%s\n' "--- END $*" >> "$NOID_NFT_LOG"
[ "${NOID_NFT_FAIL:-0}" != 1 ]
NFT_MOCK
cat > "$TMPDIR/wg-mock" <<'WG_MOCK'
#!/bin/bash
set -euo pipefail
key=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
# `wg show all <field>` prefixes every row with its interface, which is the
# shape the unmanaged-tunnel discovery parses. It answers empty unless a
# scenario file supplies rows, so the profile-driven cases above stay unchanged
# and every discovery assertion has to set up its own kernel view.
if [ "${2:-}" = all ]; then
    case "${3:-}" in
        latest-handshakes)
            [ -z "${NOID_TEST_WG_ALL_HANDSHAKES:-}" ] \
                || cat "$NOID_TEST_WG_ALL_HANDSHAKES" ;;
        endpoints)
            [ -z "${NOID_TEST_WG_ALL_ENDPOINTS:-}" ] \
                || cat "$NOID_TEST_WG_ALL_ENDPOINTS" ;;
        *) exit 1 ;;
    esac
    exit 0
fi
case "${3:-}" in
    latest-handshakes) printf '%s\t%s\n' "$key" "$(date +%s)" ;;
    endpoints) printf '%s\t%s\n' "$key" '203.0.113.10:51821' ;;
    *) exit 1 ;;
esac
WG_MOCK
cat > "$TMPDIR/systemctl-mock" <<'SYSTEMCTL_MOCK'
#!/bin/bash
if [ "$*" = "is-active --quiet noid-wan-strict-autoresume.timer" ]; then
    exit "${NOID_TIMER_RC:-4}"
fi
exit 2
SYSTEMCTL_MOCK
chmod 0755 "$TMPDIR/nft-mock" "$TMPDIR/wg-mock" \
    "$TMPDIR/systemctl-mock" "$TMPDIR/endpoint-engine.py"
: > "$TMPDIR/nft.log"
mkdir -p "$TMPDIR/sys-class/testeth0/device"

engine_env=(
    NOID_WAN_STRICT_TEST_MODE=1
    NOID_NM_PROFILE_DIRS="$profiles"
    NOID_NM_PERSISTENT_DIR="$persistent"
    NOID_WAN_STRICT_STATE_FILE="$state_dir/endpoints"
    NOID_WAN_STRICT_ARMED_FILE="$state_dir/armed"
    NOID_WAN_ACTIVE_DIR="$state_dir/active"
    NOID_WAN_DISABLED_FILE="$state_dir/disabled"
    NOID_WAN_FAILED_FILE="$state_dir/failed"
    NOID_WAN_STRICT_LOCK_FILE="$state_dir/lock"
    NOID_TEST_DNS_MAP="$TMPDIR/dns.map"
    NOID_NFT_BIN="bash $TMPDIR/nft-mock"
    NOID_WG_BIN="bash $TMPDIR/wg-mock"
    NOID_SYSTEMCTL_BIN="bash $TMPDIR/systemctl-mock"
    NOID_NFT_LOG="$TMPDIR/nft.log"
    NOID_TEST_SKIP_STATUS=1
    NOID_WAN_POLICY_FILE="$TMPDIR/noid-wan-strict.nft"
    NOID_SYS_CLASS_NET="$TMPDIR/sys-class"
    NOID_NETWORK_READY_FILE="$state_dir/network-ready"
    NOID_TEST_WG_ALL_ENDPOINTS="$TMPDIR/wg-all-endpoints"
    NOID_TEST_WG_ALL_HANDSHAKES="$TMPDIR/wg-all-handshakes"
)
: > "$TMPDIR/wg-all-endpoints"
: > "$TMPDIR/wg-all-handshakes"

# Runtime-mode publication must distinguish an empty set from an unreadable
# set and reject mixed flag/table/armed states. The mock emits the current
# libnftables JSON object shape without exposing or changing host firewall
# state.
STATUS_MOCK_BIN="$EXEC_TMPDIR/status-mocks"
mkdir -p "$STATUS_MOCK_BIN"
cat > "$STATUS_MOCK_BIN/nft" <<'STATUS_NFT_MOCK'
#!/bin/bash
set -euo pipefail
if [ "$*" = "-j list tables" ]; then
    if [ "${NOID_NFT_QUERY_FAIL:-0}" = 1 ]; then
        exit 1
    fi
    if [ "${NOID_NFT_TABLE_PRESENT:-1}" = 1 ]; then
        printf '%s\n' \
            '{"nftables":[{"metainfo":{"version":"fixture","release_name":"fixture","json_schema_version":1}},{"table":{"family":"inet","name":"noid_wan_strict","handle":1}}]}'
    else
        printf '%s\n' \
            '{"nftables":[{"metainfo":{"version":"fixture","release_name":"fixture","json_schema_version":1}}]}'
    fi
    exit 0
fi
if [ "${1:-}" = -j ] && [ "${2:-}" = list ] && [ "${3:-}" = set ] \
        && [ "${4:-}" = inet ] && [ "${5:-}" = noid_wan_strict ]; then
    set_name=${6:-}
    [ -n "$set_name" ] || exit 2
    if [ "${NOID_NFT_FAIL_SET:-}" = "$set_name" ]; then
        exit 1
    fi
    elements=
    case " ${NOID_NFT_NONEMPTY_SETS:-} " in
        *" $set_name "*) elements=',"elem":[{"fixture":"present"}]' ;;
    esac
    printf '{"nftables":[{"metainfo":{"version":"fixture","release_name":"fixture","json_schema_version":1}},{"set":{"family":"inet","name":"%s","table":"noid_wan_strict","type":"fixture"%s}}]}\n' \
        "$set_name" "$elements"
    exit 0
fi
exit 2
STATUS_NFT_MOCK
cat > "$STATUS_MOCK_BIN/systemctl" <<'STATUS_SYSTEMCTL_MOCK'
#!/bin/bash
if [ "$*" = "is-active --quiet noid-wan-strict-autoresume.timer" ]; then
    exit "${NOID_TIMER_RC:-4}"
fi
exit 2
STATUS_SYSTEMCTL_MOCK
chmod 0755 "$STATUS_MOCK_BIN/nft" "$STATUS_MOCK_BIN/systemctl"
status_env=(
    "${engine_env[@]}"
    PATH="$STATUS_MOCK_BIN:/usr/bin:/bin"
    NOID_NFT_BIN="$STATUS_MOCK_BIN/nft"
    NOID_SYSTEMCTL_BIN="$STATUS_MOCK_BIN/systemctl"
    NOID_TEST_SKIP_STATUS=0
    NOID_WAN_STATUS_FILE="$state_dir/status"
)

rm -f "$state_dir/armed" "$state_dir/disabled" "$state_dir/failed" \
    "$state_dir/endpoints" "$state_dir/status"
assert_cmd_success "nft set query failure publishes ERROR" \
    env "${status_env[@]}" NOID_NFT_FAIL_SET=vpn_endpoints_v4 \
        python3 "$TMPDIR/endpoint-engine.py" publish-status
assert_eq "MODE=ERROR" "$(cat "$state_dir/status")" \
    "unreadable endpoint set cannot be mislabeled strict-empty"

rm -f "$state_dir/status"
assert_cmd_success "unarmed table without grace publishes ERROR" \
    env "${status_env[@]}" python3 "$TMPDIR/endpoint-engine.py" publish-status
assert_eq "MODE=ERROR" "$(cat "$state_dir/status")" \
    "unarmed no-grace table cannot be mislabeled strict"

printf '%s\n' NOID_WAN_STRICT_ARMED_V1 > "$state_dir/armed"
chmod 0644 "$state_dir/armed"
rm -f "$state_dir/status"
assert_cmd_success "armed grace without a timer publishes ERROR" \
    env "${status_env[@]}" NOID_NFT_NONEMPTY_SETS=bypass_grace_v4 \
        python3 "$TMPDIR/endpoint-engine.py" publish-status
assert_eq "MODE=ERROR" "$(cat "$state_dir/status")" \
    "armed grace cannot look like bootstrap onboarding"

rm -f "$state_dir/status"
assert_cmd_success "armed grace with active timer publishes GRACE_PAUSED" \
    env "${status_env[@]}" NOID_NFT_NONEMPTY_SETS=bypass_grace_v4 \
        NOID_TIMER_RC=0 python3 "$TMPDIR/endpoint-engine.py" publish-status
assert_eq "MODE=GRACE_PAUSED" "$(cat "$state_dir/status")" \
    "bounded pause remains a valid explicit armed state"

printf '%s\n' \
    'NOID-WAN-ENDPOINTS-V2' \
    '11111111-1111-4111-8111-111111111111 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa literal udp 198.51.100.10 51820 0' \
    > "$state_dir/endpoints"
chmod 0644 "$state_dir/endpoints"
rm -f "$state_dir/status"
assert_cmd_success "armed durable tuple publishes STRICT" \
    env "${status_env[@]}" NOID_NFT_NONEMPTY_SETS=vpn_endpoints_v4 \
        python3 "$TMPDIR/endpoint-engine.py" publish-status
assert_eq "MODE=STRICT" "$(cat "$state_dir/status")" \
    "exact armed state and durable tuple publish strict"

printf '%s\n' NOID_WAN_STRICT_DISABLED_V1 > "$state_dir/disabled"
chmod 0644 "$state_dir/disabled"
rm -f "$state_dir/status"
assert_cmd_success "disabled flag with absent table publishes DISABLED" \
    env "${status_env[@]}" NOID_NFT_TABLE_PRESENT=0 \
        python3 "$TMPDIR/endpoint-engine.py" publish-status
assert_eq "MODE=DISABLED" "$(cat "$state_dir/status")" \
    "exact disabled flag and absent table form the opt-out postcondition"

install -m 0644 /dev/null "$state_dir/failed"
rm -f "$state_dir/status"
assert_cmd_success "explicit disabled mode supersedes stale boot-failure mode" \
    env "${status_env[@]}" NOID_NFT_TABLE_PRESENT=0 \
        python3 "$TMPDIR/endpoint-engine.py" publish-status
assert_eq "MODE=DISABLED" "$(cat "$state_dir/status")" \
    "stale volatile failure evidence cannot hide an exact user opt-out"
rm -f "$state_dir/failed"

rm -f "$state_dir/status"
assert_cmd_success "disabled flag with present table publishes ERROR" \
    env "${status_env[@]}" python3 "$TMPDIR/endpoint-engine.py" publish-status
assert_eq "MODE=ERROR" "$(cat "$state_dir/status")" \
    "mixed disabled flag and live table cannot look exact"

printf '%s\n' MALFORMED > "$state_dir/disabled"
rm -f "$state_dir/status"
assert_cmd_success "malformed disabled marker publishes ERROR" \
    env "${status_env[@]}" NOID_NFT_TABLE_PRESENT=0 \
        python3 "$TMPDIR/endpoint-engine.py" publish-status
assert_eq "MODE=ERROR" "$(cat "$state_dir/status")" \
    "marker existence alone cannot authorize disabled mode"

rm -f "$state_dir/armed" "$state_dir/disabled" "$state_dir/failed" \
    "$state_dir/endpoints" "$state_dir/status"

cat > "$TMPDIR/physical-persistent.nmconnection" <<'PHYSICAL_PERSISTENT'
[connection]
id=physical-persistent
uuid=44444444-4444-4444-8444-444444444444
type=ethernet

[ethernet]

[ipv4]
method=auto

[ipv6]
method=auto
PHYSICAL_PERSISTENT
cat > "$TMPDIR/physical-applied.nmconnection" <<'PHYSICAL_APPLIED'
[connection]
id=physical-applied
uuid=44444444-4444-4444-8444-444444444444
type=ethernet

[ethernet]

[ipv4]
method=auto
route1=93.184.216.34/32,192.168.50.1
route2=93.184.216.0/24,192.168.50.1

[ipv6]
method=auto
PHYSICAL_APPLIED
bootstrap_env=(
    "${engine_env[@]}"
    NOID_TEST_RUNTIME_PROFILE="$TMPDIR/physical-applied.nmconnection"
    NOID_TEST_PERSISTENT_PROFILE="$TMPDIR/physical-persistent.nmconnection"
    NOID_TEST_SOFTWARE_DEFAULT_FAMILIES=4
    NOID_TEST_GATEWAY4=192.168.50.1
)
: > "$TMPDIR/nft.log"
assert_cmd_success "dynamic client admits only its current applied host-route delta" \
    env "${bootstrap_env[@]}" python3 "$TMPDIR/endpoint-engine.py" \
        reconcile-bootstrap --interface testeth0 \
        --uuid 44444444-4444-4444-8444-444444444444
assert_grep_fixed '93.184.216.34 . tcp timeout 60s' "$TMPDIR/nft.log" \
    "bootstrap delta admits the exact public host for TCP"
assert_grep_fixed '93.184.216.34 . udp timeout 60s' "$TMPDIR/nft.log" \
    "bootstrap delta admits the exact public host for UDP"
assert_not_grep '93.184.216.0' "$TMPDIR/nft.log" \
    "bootstrap delta rejects prefixes broader than one host"
assert_eq "2" "$(grep -o 'timeout 60s' "$TMPDIR/nft.log" | wc -l)" \
    "one host creates exactly two bounded transport tuples"

: > "$TMPDIR/nft.log"
assert_cmd_success "host-route delta without a software default stays closed" \
    env "${bootstrap_env[@]}" NOID_TEST_SOFTWARE_DEFAULT_FAMILIES= \
        python3 "$TMPDIR/endpoint-engine.py" reconcile-bootstrap \
        --interface testeth0 --uuid 44444444-4444-4444-8444-444444444444
assert_not_grep 'add element inet noid_wan_strict vpn_bootstrap_routes_' \
    "$TMPDIR/nft.log" "ordinary physical Reapply cannot create an exception"

: > "$TMPDIR/nft.log"
assert_cmd_success "host route through a non-current gateway stays closed" \
    env "${bootstrap_env[@]}" NOID_TEST_GATEWAY4=192.168.50.2 \
        python3 "$TMPDIR/endpoint-engine.py" reconcile-bootstrap \
        --interface testeth0 --uuid 44444444-4444-4444-8444-444444444444
assert_not_grep 'add element inet noid_wan_strict vpn_bootstrap_routes_' \
    "$TMPDIR/nft.log" "wrong-next-hop route cannot create an exception"

cat > "$TMPDIR/physical-applied.nmconnection" <<'PHYSICAL_APPLIED_EMPTY'
[connection]
id=physical-applied
uuid=44444444-4444-4444-8444-444444444444
type=ethernet

[ethernet]

[ipv4]
method=auto

[ipv6]
method=auto
PHYSICAL_APPLIED_EMPTY
: > "$TMPDIR/nft.log"
assert_cmd_success "stale Reapply event re-reads and flushes current empty delta" \
    env "${bootstrap_env[@]}" python3 "$TMPDIR/endpoint-engine.py" \
        reconcile-bootstrap --interface testeth0 \
        --uuid 44444444-4444-4444-8444-444444444444
assert_grep_fixed 'flush set inet noid_wan_strict vpn_bootstrap_routes_v4' \
    "$TMPDIR/nft.log" "stale event revokes prior IPv4 bootstrap routes"
assert_not_grep 'add element inet noid_wan_strict vpn_bootstrap_routes_' \
    "$TMPDIR/nft.log" "stale event cannot replay a removed applied route"

cat > "$TMPDIR/physical-applied.nmconnection" <<'PHYSICAL_APPLIED_SAVED'
[connection]
id=physical-applied
uuid=44444444-4444-4444-8444-444444444444
type=ethernet

[ethernet]

[ipv4]
method=auto
route1=93.184.216.34/32,192.168.50.1

[ipv6]
method=auto
PHYSICAL_APPLIED_SAVED
cp "$TMPDIR/physical-applied.nmconnection" "$TMPDIR/physical-persistent.nmconnection"
: > "$TMPDIR/nft.log"
# A client may add its probe route with Update()+Reapply rather than Reapply
# alone, which makes the applied and persistent views identical (Proton VPN
# GTK 4.16.5 does; its NM audit trail shows op="connection-update"
# args="ipv4.routes" followed by op="device-reapply"). Admission must depend on
# the bounded event and the policy conditions, never on that difference --
# otherwise only the first connection after a state reset can ever probe.
assert_cmd_success "already-saved client probe route still opens its window" \
    env "${bootstrap_env[@]}" python3 "$TMPDIR/endpoint-engine.py" \
        reconcile-bootstrap --interface testeth0 \
        --uuid 44444444-4444-4444-8444-444444444444
assert_grep_fixed '93.184.216.34 . tcp timeout 60s' "$TMPDIR/nft.log" \
    "persisted probe route is admitted for TCP like a Reapply-only one"
assert_grep_fixed '93.184.216.34 . udp timeout 60s' "$TMPDIR/nft.log" \
    "persisted probe route is admitted for UDP like a Reapply-only one"
assert_eq "2" "$(grep -o 'timeout 60s' "$TMPDIR/nft.log" | wc -l)" \
    "a persisted host route stays bounded to exactly two transport tuples"

: > "$TMPDIR/nft.log"
assert_cmd_success "saved host route without a software default stays closed" \
    env "${bootstrap_env[@]}" NOID_TEST_SOFTWARE_DEFAULT_FAMILIES= \
        python3 "$TMPDIR/endpoint-engine.py" reconcile-bootstrap \
        --interface testeth0 --uuid 44444444-4444-4444-8444-444444444444
assert_not_grep 'add element inet noid_wan_strict vpn_bootstrap_routes_' \
    "$TMPDIR/nft.log" \
    "saved route cannot open a window without a kill-switch dummy default"

: > "$TMPDIR/nft.log"
assert_cmd_success "saved host route through a foreign gateway stays closed" \
    env "${bootstrap_env[@]}" NOID_TEST_GATEWAY4=192.168.50.2 \
        python3 "$TMPDIR/endpoint-engine.py" reconcile-bootstrap \
        --interface testeth0 --uuid 44444444-4444-4444-8444-444444444444
assert_not_grep 'add element inet noid_wan_strict vpn_bootstrap_routes_' \
    "$TMPDIR/nft.log" \
    "saved route via a non-current gateway cannot open a window"

if env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" reconcile \
        >"$TMPDIR/engine.stdout" 2>"$TMPDIR/engine.stderr"; then
    _pass "libnm controller reconciles literal profiles and bounded DNS candidates"
else
    sed 's/^/    controller: /' "$TMPDIR/engine.stderr" >&2
    _fail "libnm controller reconciles literal profiles and bounded DNS candidates"
fi
assert_grep_fixed 'NOID-WAN-ENDPOINTS-V2' "$state_dir/endpoints" \
    "state publishes the exact v2 header"
assert_grep_fixed 'literal udp 198.51.100.10 51820 0' "$state_dir/endpoints" \
    "literal WireGuard endpoint is durable with profile provenance"
assert_not_grep '203.0.113.10\|203.0.113.11\|192.0.2.44' "$state_dir/endpoints" \
    "unauthenticated hostname answers are never durable"
grep 'add element inet noid_wan_strict vpn_candidates_v4' "$TMPDIR/nft.log" \
    > "$TMPDIR/candidate.batch" || true
for candidate in \
    '192.0.2.44 . tcp . 443 timeout 120s' \
    '203.0.113.10 . udp . 51821 timeout 120s' \
    '203.0.113.11 . udp . 51821 timeout 120s'; do
    assert_grep_fixed "$candidate" "$TMPDIR/candidate.batch" \
        "current DNS answer is an exact timeout-bounded candidate: $candidate"
done
assert_eq "3" "$(grep -o 'timeout 120s' "$TMPDIR/candidate.batch" | wc -l)" \
    "initial candidate transaction has no extra address"
assert_not_grep '192.0.2.200\|192.0.2.250\|192.0.2.251' "$TMPDIR/nft.log" \
    "wrong-section and shadowed duplicate keys are ignored by libnm's effective model"
assert_eq "644" "$(stat -c '%a' "$state_dir/endpoints")" \
    "controller state metadata is exact"
if [ ! -e "$state_dir/armed" ]; then
    _pass "saved endpoint profiles alone do not arm strict mode"
else
    _fail "saved endpoint profiles alone do not arm strict mode"
fi
assert_grep_fixed 'add element inet noid_wan_strict bypass_grace_v4 { 0.0.0.0/0 }' \
    "$TMPDIR/nft.log" \
    "unactivated saved profiles preserve explicit direct/bootstrap grace"

# Hostname endpoint resolution is not allowed to race the physical boundary:
# literal endpoint policy remains available, while DNS is deferred until M04
# republishes its exact gateway/XDP readiness marker.
rm -f "$state_dir/network-ready"
: > "$TMPDIR/nft.log"
assert_cmd_success "missing gateway/XDP readiness defers hostname resolution" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" reconcile
assert_grep_fixed 'literal udp 198.51.100.10 51820 0' "$state_dir/endpoints" \
    "literal endpoint remains durable before resolver readiness"
assert_not_grep 'add element inet noid_wan_strict vpn_candidates_' \
    "$TMPDIR/nft.log" \
    "no hostname DNS candidate is published before gateway/XDP readiness"
printf 'NOID_GATEWAY_XDP_READY_V1\n' > "$state_dir/network-ready"
chmod 0644 "$state_dir/network-ready"

: > "$TMPDIR/nft.log"
assert_cmd_success "bootstrap replaces the complete WAN policy in one nft invocation" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" bootstrap
assert_eq "1" "$(grep -c '^--- -f -$' "$TMPDIR/nft.log")" \
    "bootstrap submits exactly one nft transaction"
assert_grep_fixed 'destroy table inet noid_wan_strict' "$TMPDIR/nft.log" \
    "atomic bootstrap transaction begins with idempotent old-table destruction"
assert_grep_fixed 'table inet noid_wan_strict {' "$TMPDIR/nft.log" \
    "atomic bootstrap transaction contains the complete replacement table"
assert_grep_fixed 'physical_ifaces { "testeth0" }' "$TMPDIR/nft.log" \
    "physical-interface membership is committed with the replacement table"
assert_grep_fixed 'set lan_inbound_peers_v4 {' "$TMPDIR/nft.log" \
    "atomic WAN bootstrap retains the inbound-peer reply contract"
assert_grep_fixed 'oifname @physical_ifaces ct state established,related' \
    "$TMPDIR/nft.log" \
    "atomic WAN bootstrap retains hardware-scoped conntrack replies"
assert_grep_fixed 'ip daddr @lan_inbound_peers_v4 accept' \
    "$TMPDIR/nft.log" \
    "atomic WAN bootstrap retains state-correlated inbound replies"
assert_grep_fixed '198.51.100.10 . udp . 51820' "$TMPDIR/nft.log" \
    "durable endpoints are committed in the same table transaction"

# The nft policy is root-executed input. Exercise the exact metadata,
# no-follow and single-table gates rather than relying only on source strings.
chmod 0664 "$TMPDIR/noid-wan-strict.nft"
assert_cmd_failure "bootstrap rejects a writable nft policy" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" bootstrap
chmod 0644 "$TMPDIR/noid-wan-strict.nft"
mv "$TMPDIR/noid-wan-strict.nft" "$TMPDIR/noid-wan-strict.nft.real"
ln -s noid-wan-strict.nft.real "$TMPDIR/noid-wan-strict.nft"
assert_cmd_failure "bootstrap rejects a symlinked nft policy" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" bootstrap
rm "$TMPDIR/noid-wan-strict.nft"
mv "$TMPDIR/noid-wan-strict.nft.real" "$TMPDIR/noid-wan-strict.nft"
cp "$TMPDIR/noid-wan-strict.nft" "$TMPDIR/unsafe-second-table.nft"
printf '\ntable inet unexpected_fixture { }\n' >> "$TMPDIR/unsafe-second-table.nft"
chmod 0644 "$TMPDIR/unsafe-second-table.nft"
assert_cmd_failure "bootstrap rejects an appended second nft table" \
    env "${engine_env[@]}" \
        NOID_WAN_POLICY_FILE="$TMPDIR/unsafe-second-table.nft" \
        python3 "$TMPDIR/endpoint-engine.py" bootstrap

cp "$state_dir/endpoints" "$state_dir/endpoints.canonical"
printf '%s\n' \
    '33333333-3333-4333-8333-333333333333 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb literal udp 2001:0DB8::1 51820 0' \
    >> "$state_dir/endpoints"
assert_cmd_failure "state parser rejects a non-canonical endpoint address" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" reconcile
mv "$state_dir/endpoints.canonical" "$state_dir/endpoints"
chmod 0644 "$state_dir/endpoints"

created_status_dir="$TMPDIR/umask-created-status"
assert_cmd_success "status publisher creates its exact directory under umask 077" \
    bash -c '
        umask 077
        exec env "$@"
    ' _ "${status_env[@]}" \
        NOID_WAN_STATUS_FILE="$created_status_dir/status" \
        python3 "$TMPDIR/endpoint-engine.py" publish-status
assert_eq 755 "$(stat -c '%a' "$created_status_dir")" \
    "trusted-directory creation is not weakened by the caller umask"

# Hold the real fixture lock and prove the controller returns its distinct
# retryable code inside the configured test deadline.
lock_ready="$TMPDIR/lock-held.ready"
python3 - "$state_dir/lock" "$lock_ready" <<'PY' &
import fcntl
import pathlib
import sys
import time

with open(sys.argv[1], "a+", encoding="ascii") as stream:
    fcntl.flock(stream, fcntl.LOCK_EX)
    pathlib.Path(sys.argv[2]).write_text("ready\n", encoding="ascii")
    time.sleep(2)
PY
lock_holder_pid=$!
for _ in $(seq 1 100); do
    [ -e "$lock_ready" ] && break
    sleep 0.01
done
if [ ! -e "$lock_ready" ]; then
    _fail "bounded-lock fixture acquired the controller lock"
    kill "$lock_holder_pid" 2>/dev/null || true
else
    _pass "bounded-lock fixture acquired the controller lock"
fi
lock_timeout_rc=0
env "${engine_env[@]}" NOID_TEST_LOCK_TIMEOUT=0.1 \
    python3 "$TMPDIR/endpoint-engine.py" reconcile \
    > "$TMPDIR/lock-timeout.out" 2> "$TMPDIR/lock-timeout.err" \
    || lock_timeout_rc=$?
assert_eq 75 "$lock_timeout_rc" \
    "controller lock deadline yields the retryable temporary-failure code"
assert_grep_fixed 'endpoint transaction lock timed out' "$TMPDIR/lock-timeout.err" \
    "lock timeout is explicit rather than an unexplained dispatcher stall"
wait "$lock_holder_pid"

: > "$TMPDIR/nft.log"
rm -f "$TMPDIR/nft.started"
env "${engine_env[@]}" NOID_NFT_SLEEP=1 \
    NOID_NFT_STARTED_FILE="$TMPDIR/nft.started" \
    python3 "$TMPDIR/endpoint-engine.py" reconcile \
    >"$TMPDIR/concurrent-reconcile.out" 2>"$TMPDIR/concurrent-reconcile.err" &
reconcile_pid=$!
for _ in $(seq 1 100); do
    [ -e "$TMPDIR/nft.started" ] && break
    sleep 0.01
done
if [ ! -e "$TMPDIR/nft.started" ]; then
    _fail "concurrency fixture observes first locked transaction"
    kill "$reconcile_pid" 2>/dev/null || true
    wait "$reconcile_pid" 2>/dev/null || true
else
    _pass "concurrency fixture observes first locked transaction"
fi
env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" reset \
    >"$TMPDIR/concurrent-reset.out" 2>"$TMPDIR/concurrent-reset.err" &
reset_pid=$!
serialization_violation=0
for _ in $(seq 1 50); do
    nft_entry_count=$(grep -c '^--- -f -$' "$TMPDIR/nft.log" || true)
    if [ "$nft_entry_count" -ne 1 ]; then
        serialization_violation=1
        break
    fi
    sleep 0.01
done
assert_eq 0 "$serialization_violation" \
    "concurrent reset stays outside nft throughout the locked observation window"
if wait "$reconcile_pid" && wait "$reset_pid"; then
    _pass "serialized reconcile/reset transactions both complete"
else
    sed 's/^/    reconcile: /' "$TMPDIR/concurrent-reconcile.err" >&2
    sed 's/^/    reset: /' "$TMPDIR/concurrent-reset.err" >&2
    _fail "serialized reconcile/reset transactions both complete"
fi
assert_eq "2" "$(grep -c '^--- -f -$' "$TMPDIR/nft.log")" \
    "serialized reconcile/reset produce exactly two complete nft transactions"
assert_eq "2" "$(grep -c '^--- END -f -$' "$TMPDIR/nft.log")" \
    "each concurrent nft transaction completes before lock handoff"
assert_eq "1" "$(wc -l < "$state_dir/endpoints")" \
    "later locked reset deterministically owns the final empty state"
if [ ! -e "$state_dir/armed" ]; then
    _pass "later locked reset deterministically owns the final grace marker state"
else
    _fail "later locked reset deterministically owns the final grace marker state"
fi
assert_cmd_success "post-concurrency reconciliation restores the fixture desired state" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" reconcile

: > "$TMPDIR/nft.log"
assert_cmd_success "locked disable publishes its exact flag and table transition" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" disable
assert_eq "NOID_WAN_STRICT_DISABLED_V1" "$(cat "$state_dir/disabled")" \
    "disabled flag has a versioned exact contract"
assert_eq "644" "$(stat -c '%a' "$state_dir/disabled")" \
    "disabled flag has exact metadata"
assert_grep_fixed 'destroy table inet noid_wan_strict' "$TMPDIR/nft.log" \
    "locked disable removes the policy inside its controller transaction"
: > "$TMPDIR/nft.log"
if env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" reconcile \
        >"$TMPDIR/disabled-reconcile.stdout" \
        2>"$TMPDIR/disabled-reconcile.stderr"; then
    _fail "queued reconciliation is rejected after locked opt-out"
else
    _pass "queued reconciliation is rejected after locked opt-out"
fi
assert_grep_fixed 'WAN strict is explicitly disabled' \
    "$TMPDIR/disabled-reconcile.stderr" \
    "post-lock opt-out rejection is explicit"
assert_eq "0" "$(grep -c '^--- -f -$' "$TMPDIR/nft.log" || true)" \
    "post-opt-out queued work cannot recreate the nft table"
install -m 0644 /dev/null "$state_dir/failed"
assert_cmd_success "locked enable removes the flag and atomically installs policy" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" enable
if [ ! -e "$state_dir/disabled" ]; then
    _pass "locked enable removes the disabled marker"
else
    _fail "locked enable removes the disabled marker"
fi
if [ ! -e "$state_dir/failed" ]; then
    _pass "locked enable consumes superseded volatile boot-failure evidence"
else
    _fail "locked enable consumes superseded volatile boot-failure evidence"
fi
assert_eq "1" "$(grep -c '^--- -f -$' "$TMPDIR/nft.log")" \
    "locked enable commits one complete table transaction"

: > "$TMPDIR/nft.log"
if env "${engine_env[@]}" NOID_TEST_SKIP_STATUS=0 \
        NOID_WAN_STATUS_FILE=/proc/noid-wan-status \
        NOID_WAN_FAILED_FILE="$state_dir/no-failure" \
        NOID_WAN_DISABLED_FILE="$state_dir/no-disable" \
        python3 "$TMPDIR/endpoint-engine.py" pause >/dev/null 2>&1; then
    _fail "status-publication failure after pause is rejected"
else
    _pass "status-publication failure after pause is rejected"
fi
assert_eq "2" "$(grep -c '^--- -f -$' "$TMPDIR/nft.log")" \
    "failed pause performs one relaxation and one prior-state rollback transaction"
assert_eq "2" "$(grep -c 'add element inet noid_wan_strict bypass_grace_v4' \
    "$TMPDIR/nft.log")" \
    "failed unarmed pause restores the exact prior grace state"

: > "$TMPDIR/nft.log"
assert_cmd_success "resume while unarmed preserves direct/bootstrap grace" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" resume
assert_grep_fixed 'add element inet noid_wan_strict bypass_grace_v4 { 0.0.0.0/0 }' \
    "$TMPDIR/nft.log" "unarmed resume cannot invent undocumented strict mode"

: > "$TMPDIR/nft.log"
assert_cmd_success "explicit no-VPN arm-empty enters fail-closed state" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" arm-empty
assert_file_exists "$state_dir/armed" \
    "arm-empty publishes the durable armed marker"
assert_eq "NOID-WAN-ENDPOINTS-V2" "$(cat "$state_dir/endpoints")" \
    "arm-empty publishes an exact empty endpoint state"
assert_not_grep 'add element inet noid_wan_strict bypass_grace_v4' \
    "$TMPDIR/nft.log" "arm-empty removes direct-WAN grace"
rm -f "$state_dir/status"
assert_cmd_success "armed empty runtime publishes STRICT_EMPTY" \
    env "${status_env[@]}" python3 "$TMPDIR/endpoint-engine.py" publish-status
assert_eq "MODE=STRICT_EMPTY" "$(cat "$state_dir/status")" \
    "arm-empty has the exact machine-readable postcondition"
assert_cmd_success "fixture returns from arm-empty to bootstrap grace" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" reset
assert_cmd_success "fixture desired profiles are restored after arm-empty" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" reconcile

: > "$TMPDIR/nft.log"
if env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" commit-active \
        --interface wgtest0 --event up --uuid 22222222-2222-4222-8222-222222222222 \
        >"$TMPDIR/commit.stdout" 2>"$TMPDIR/commit.stderr"; then
    _pass "recent WireGuard peer-key handshake promotes only its observed address"
else
    sed 's/^/    controller: /' "$TMPDIR/commit.stderr" >&2
    _fail "recent WireGuard peer-key handshake promotes only its observed address"
fi
assert_grep_fixed '22222222-2222-4222-8222-222222222222' "$state_dir/endpoints" \
    "authenticated record retains profile UUID provenance"
assert_grep_fixed 'authenticated udp 203.0.113.10 51821' "$state_dir/endpoints" \
    "WireGuard authenticated runtime endpoint is durable and bounded"
assert_file_exists "$state_dir/armed" \
    "first committed strict state creates the never-silent-reopen marker"
assert_not_grep 'add element inet noid_wan_strict bypass_grace_v4' \
    "$TMPDIR/nft.log" \
    "activation strict-gate removes grace before later reconciliation work"
assert_eq "NOID_WAN_TUNNEL_ACTIVE_V1 22222222-2222-4222-8222-222222222222" \
    "$(cat "$state_dir/active/22222222-2222-4222-8222-222222222222.state")" \
    "confirmed WireGuard activation publishes exact volatile proof"
assert_eq "600" \
    "$(stat -c '%a' "$state_dir/active/22222222-2222-4222-8222-222222222222.state")" \
    "active-tunnel proof is root-private"
assert_grep_fixed 'flush set inet noid_wan_strict vpn_bootstrap_routes_v4' \
    "$TMPDIR/nft.log" "confirmed activation revokes transient bootstrap routes"

# A scheduled pause is an explicit bounded user decision. NetworkManager emits
# profile, DNS and Reapply events during exactly the captive-portal/VPN setup
# window for which pause exists; those reconciliations must not collapse grace
# seconds after the CLI reported a multi-minute interval. Both authorities are
# required, so a stale timer with an already-closed nft set cannot reopen it.
: > "$TMPDIR/nft.log"
assert_cmd_success "profile reconciliation preserves an exact active pause" \
    env "${engine_env[@]}" NOID_TIMER_RC=0 \
        NOID_NFT_NONEMPTY_SETS=bypass_grace_v4 \
        python3 "$TMPDIR/endpoint-engine.py" reconcile
assert_grep_fixed \
    'add element inet noid_wan_strict bypass_grace_v4 { 0.0.0.0/0 }' \
    "$TMPDIR/nft.log" \
    "profile/DNS reconciliation cannot silently end the bounded pause"

: > "$TMPDIR/nft.log"
assert_cmd_success "authenticated activation honors an exact active pause" \
    env "${engine_env[@]}" NOID_TIMER_RC=0 \
        NOID_NFT_NONEMPTY_SETS=bypass_grace_v4 \
        python3 "$TMPDIR/endpoint-engine.py" commit-active \
        --interface wgtest0 --event up \
        --uuid 22222222-2222-4222-8222-222222222222
assert_grep_fixed \
    'add element inet noid_wan_strict bypass_grace_v4 { 0.0.0.0/0 }' \
    "$TMPDIR/nft.log" \
    "supported tunnel activation does not override the user's live pause"

: > "$TMPDIR/nft.log"
assert_cmd_success "timer alone cannot reopen manually resumed strict mode" \
    env "${engine_env[@]}" NOID_TIMER_RC=0 NOID_NFT_NONEMPTY_SETS= \
        python3 "$TMPDIR/endpoint-engine.py" reconcile
assert_not_grep 'add element inet noid_wan_strict bypass_grace_v4' \
    "$TMPDIR/nft.log" \
    "stale timer without committed nft grace remains strict"

: > "$TMPDIR/nft.log"
if env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" expire \
        >"$TMPDIR/expiry-noop.stdout" 2>"$TMPDIR/expiry-noop.stderr"; then
    _pass "unchanged expiry pass is successful"
else
    sed 's/^/    controller: /' "$TMPDIR/expiry-noop.stderr" >&2
    _fail "unchanged expiry pass is successful"
fi
assert_eq "0" "$(grep -c '^--- -f -$' "$TMPDIR/nft.log" || true)" \
    "unchanged expiry pass performs no nft transaction"
assert_eq "0" "$(wc -c < "$TMPDIR/expiry-noop.stdout")" \
    "unchanged periodic expiry pass is silent"

: > "$TMPDIR/nft.log"
assert_cmd_failure "pre-down cannot be used as a WAN-strict relaxation action" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" \
        record-disconnect --interface wgtest0 --event pre-down \
        --uuid 22222222-2222-4222-8222-222222222222
assert_file_exists "$state_dir/armed" \
    "rejected pre-down leaves the durable armed marker intact"
assert_cmd_success "clean native WireGuard down remains fail-closed" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" \
        record-disconnect --interface wgtest0 --event down \
        --uuid 22222222-2222-4222-8222-222222222222
assert_file_exists "$state_dir/armed" \
    "native WireGuard down preserves durable armed state"
if [ ! -e "$state_dir/active/22222222-2222-4222-8222-222222222222.state" ]; then
    _pass "native WireGuard down removes volatile active proof"
else
    _fail "native WireGuard down removes volatile active proof"
fi
assert_not_grep 'add element inet noid_wan_strict bypass_grace_v4' \
    "$TMPDIR/nft.log" \
    "native WireGuard down cannot restore direct-WAN grace"

: > "$TMPDIR/nft.log"
assert_cmd_success "WireGuard fixture republishes active proof after reconnect" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" commit-active \
        --interface wgtest0 --event up \
        --uuid 22222222-2222-4222-8222-222222222222

cat > "$TMPDIR/dns.map" <<'ROTATED_DNS_MAP'
vpn.example 203.0.113.99
ovpn.example 192.0.2.44
ROTATED_DNS_MAP
: > "$TMPDIR/nft.log"
assert_cmd_success "DNS rotation replaces candidate desired state without durable promotion" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" reconcile
grep 'add element inet noid_wan_strict vpn_candidates_v4' "$TMPDIR/nft.log" \
    > "$TMPDIR/rotated-candidate.batch" || true
assert_grep_fixed '192.0.2.44 . tcp . 443 timeout 120s' \
    "$TMPDIR/rotated-candidate.batch" "OpenVPN candidate remains current"
assert_grep_fixed '203.0.113.99 . udp . 51821 timeout 120s' \
    "$TMPDIR/rotated-candidate.batch" "rotated WireGuard answer replaces candidates"
assert_not_grep '203.0.113.10\|203.0.113.11' "$TMPDIR/rotated-candidate.batch" \
    "candidate transaction removes prior DNS answers"
assert_eq "2" "$(grep -o 'timeout 120s' "$TMPDIR/rotated-candidate.batch" | wc -l)" \
    "rotated candidate transaction has no extra address"
assert_not_grep 'authenticated udp 203.0.113.99' "$state_dir/endpoints" \
    "forged/rotated DNS cannot enter durable authenticated state"

: > "$TMPDIR/dns.map"
: > "$TMPDIR/nft.log"
assert_cmd_success "offline DNS produces no candidate and preserves only prior authenticated state" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" reconcile
assert_grep_fixed 'flush set inet noid_wan_strict vpn_candidates_v4' \
    "$TMPDIR/nft.log" "offline DNS still revokes the previous candidate set"
assert_not_grep 'add element inet noid_wan_strict vpn_candidates_' \
    "$TMPDIR/nft.log" "offline DNS cannot manufacture an endpoint candidate"
assert_grep_fixed 'authenticated udp 203.0.113.10 51821' "$state_dir/endpoints" \
    "DNS failure does not rewrite prior handshake evidence as a new answer"

cat > "$TMPDIR/dns.map" <<'RESTORED_DNS_MAP'
vpn.example 203.0.113.99
ovpn.example 192.0.2.44
RESTORED_DNS_MAP

rm "$profiles/wg-hostname.nmconnection"
: > "$TMPDIR/nft.log"
assert_cmd_success "deleted profile revokes its authenticated record" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" reconcile
assert_not_grep '22222222-2222-4222-8222-222222222222\|203.0.113.10' \
    "$state_dir/endpoints" "profile deletion removes old UUID/address provenance"

: > "$TMPDIR/nft.log"
if env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" \
        record-disconnect --interface wgtest0 --event down \
        --uuid 22222222-2222-4222-8222-222222222222 \
        >"$TMPDIR/classified-down.out"; then
    _pass "queued previously classified tunnel down is accepted and stays armed"
else
    _fail "queued previously classified tunnel down is accepted and stays armed"
fi
assert_eq "DOWN_STRICT" "$(cat "$TMPDIR/classified-down.out")" \
    "trusted active proof survives profile removal long enough for cleanup"
assert_file_exists "$state_dir/armed" \
    "accepted queued down preserves the durable boot guard"
if [ ! -e "$state_dir/active/22222222-2222-4222-8222-222222222222.state" ]; then
    _pass "accepted queued down removes volatile active proof"
else
    _fail "accepted queued down removes volatile active proof"
fi
assert_not_grep 'add element inet noid_wan_strict bypass_grace_v4' \
    "$TMPDIR/nft.log" "unexpected down cannot restore direct WAN"

if env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" \
        record-disconnect --interface vnet2 --event down \
        --uuid 55555555-5555-4555-8555-555555555555 \
        >"$TMPDIR/unsupported-down.out"; then
    _pass "unrelated virtual down event is ignored"
else
    _fail "unrelated virtual down event is ignored"
fi
assert_eq "IGNORED_UNSUPPORTED" "$(cat "$TMPDIR/unsupported-down.out")" \
    "unsupported profile cannot create a false tunnel-down event"

assert_cmd_success "activated identity-verifying OpenVPN profile promotes observed gateway" \
    env "${engine_env[@]}" VPN_IP4_GATEWAY=192.0.2.44 \
        python3 "$TMPDIR/endpoint-engine.py" commit-active --interface tun0 --event vpn-up \
        --uuid 33333333-3333-4333-8333-333333333333
assert_grep_fixed 'authenticated tcp 192.0.2.44 443' "$state_dir/endpoints" \
    "OpenVPN promotion binds activated gateway to identity-bearing profile"

# NetworkManager exports the unspecified address for "this family has no
# gateway", which every IPv4-only VPN hits on VPN_IP6_GATEWAY. Rejecting it as
# a hostile address class aborted the whole vpn-up reconciliation and left the
# dispatcher failing on every single OpenVPN activation.
assert_cmd_success "unspecified gateway family does not abort the promotion" \
    env "${engine_env[@]}" VPN_IP4_GATEWAY=192.0.2.44 VPN_IP6_GATEWAY=0.0.0.0 \
        python3 "$TMPDIR/endpoint-engine.py" commit-active --interface tun0 --event vpn-up \
        --uuid 33333333-3333-4333-8333-333333333333
assert_grep_fixed 'authenticated tcp 192.0.2.44 443' "$state_dir/endpoints" \
    "promotion survives the unspecified-gateway export NetworkManager always makes"
assert_cmd_failure "a malformed gateway export still fails closed" \
    env "${engine_env[@]}" VPN_IP4_GATEWAY=not-an-address \
        python3 "$TMPDIR/endpoint-engine.py" commit-active --interface tun0 --event vpn-up \
        --uuid 33333333-3333-4333-8333-333333333333

# Measured against NetworkManager-openvpn 1.12.5 the gateway variables never
# carry the outer peer: they hold the tunnel gateway once the server pushes
# routes, and the unspecified address when it pushes none. The host route
# NetworkManager installs on the physical link does name it.
assert_cmd_success "outer-peer host route alone promotes the OpenVPN profile" \
    env "${engine_env[@]}" NOID_TEST_HOST_ROUTES="192.0.2.44 192.0.2.77" \
        python3 "$TMPDIR/endpoint-engine.py" commit-active --interface tun0 --event vpn-up \
        --uuid 33333333-3333-4333-8333-333333333333
assert_grep_fixed 'authenticated tcp 192.0.2.44 443' "$state_dir/endpoints" \
    "host-route promotion binds exactly the profile's own resolved endpoint"
assert_not_grep_fixed '192.0.2.77' "$state_dir/endpoints" \
    "an unrelated host route cannot widen the pin beyond that endpoint"
assert_cmd_failure "promotion fails closed when no source names the outer peer" \
    env "${engine_env[@]}" VPN_IP4_GATEWAY=203.0.113.7 \
        NOID_TEST_HOST_ROUTES="192.0.2.77" \
        python3 "$TMPDIR/endpoint-engine.py" commit-active --interface tun0 --event vpn-up \
        --uuid 33333333-3333-4333-8333-333333333333

sed -i -E '/ authenticated / s/[0-9]+$/1/' "$state_dir/endpoints"
if env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" expire \
        >"$TMPDIR/expiry-change.stdout" 2>"$TMPDIR/expiry-change.stderr"; then
    _pass "expiry transaction prunes authenticated leases without refreshing DNS"
else
    sed 's/^/    controller: /' "$TMPDIR/expiry-change.stderr" >&2
    _fail "expiry transaction prunes authenticated leases without refreshing DNS"
fi
assert_grep_fixed 'endpoint expiry state changed; retained ' \
    "$TMPDIR/expiry-change.stdout" \
    "changed expiry pass records one meaningful state transition"
assert_not_grep ' authenticated ' "$state_dir/endpoints" \
    "expired authenticated records leave durable state"

rm "$profiles/openvpn.nmconnection" "$profiles/wg-literal.nmconnection"
: > "$TMPDIR/nft.log"
assert_cmd_success "armed empty desired state remains strict instead of reopening grace" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" reconcile
assert_not_grep 'add element inet noid_wan_strict bypass_grace_v4' "$TMPDIR/nft.log" \
    "profile deletion cannot silently restore full-WAN bootstrap grace"

assert_cmd_success "explicit reset remains a supported transition to direct-WAN grace" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" reset
if [ ! -e "$state_dir/armed" ]; then
    _pass "explicit reset removes armed marker"
else
    _fail "explicit reset removes armed marker"
fi
assert_grep_fixed 'add element inet noid_wan_strict bypass_grace_v4 { 0.0.0.0/0 }' \
    "$TMPDIR/nft.log" "explicit reset deliberately restores bootstrap grace"
if ! find "$state_dir/active" -type f -print -quit \
        2>/dev/null | grep -q .; then
    _pass "explicit reset clears all volatile tunnel activation proof"
else
    _fail "explicit reset clears all volatile tunnel activation proof"
fi

cat > "$profiles/openvpn.nmconnection" <<'CLEAN_VPN_PROFILE'
[connection]
id=openvpn-tunnel-down
uuid=33333333-3333-4333-8333-333333333333
type=vpn

[vpn]
service-type=org.freedesktop.NetworkManager.openvpn
remote=192.0.2.200
remote=ovpn.example
proto=tcp
port=443
ca=/etc/pki/noid-test-ca.pem
remote-cert-tls=server

[ipv4]
method=auto
CLEAN_VPN_PROFILE
cat > "$TMPDIR/dns.map" <<'CLEAN_DNS_MAP'
ovpn.example 192.0.2.44
CLEAN_DNS_MAP
: > "$TMPDIR/nft.log"
assert_cmd_success "saving a supported profile does not arm strict mode" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" reconcile
if [ ! -e "$state_dir/armed" ]; then
    _pass "saved profile remains unarmed until authenticated activation"
else
    _fail "saved profile remains unarmed until authenticated activation"
fi
assert_grep_fixed 'add element inet noid_wan_strict bypass_grace_v4 { 0.0.0.0/0 }' \
    "$TMPDIR/nft.log" "saved profile preserves disclosed direct-WAN grace"

: > "$TMPDIR/nft.log"
assert_cmd_success "authenticated OpenVPN activation arms tunnel-down fixture" \
    env "${engine_env[@]}" VPN_IP4_GATEWAY=192.0.2.44 \
        python3 "$TMPDIR/endpoint-engine.py" commit-active \
        --interface tun0 --event vpn-up \
        --uuid 33333333-3333-4333-8333-333333333333
assert_file_exists "$state_dir/armed" \
    "authenticated OpenVPN activation creates durable armed state"
assert_file_exists \
    "$state_dir/active/33333333-3333-4333-8333-333333333333.state" \
    "authenticated OpenVPN activation creates volatile active proof"

: > "$TMPDIR/nft.log"
assert_cmd_success "clean OpenVPN down remains fail-closed" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" \
        record-disconnect --interface tun0 --event vpn-down \
        --uuid 33333333-3333-4333-8333-333333333333
assert_file_exists "$state_dir/armed" \
    "clean OpenVPN down preserves durable armed state"
if [ ! -e "$state_dir/active/33333333-3333-4333-8333-333333333333.state" ]; then
    _pass "clean OpenVPN down consumes volatile active proof"
else
    _fail "clean OpenVPN down consumes volatile active proof"
fi
assert_not_grep 'add element inet noid_wan_strict bypass_grace_v4' \
    "$TMPDIR/nft.log" "clean OpenVPN down cannot restore direct WAN"

rm "$profiles/openvpn.nmconnection"
assert_cmd_success "dynamic client profile removal converges strict-empty first" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" reconcile
: > "$TMPDIR/nft.log"
assert_cmd_success "duplicate queued VPN down remains fail-closed" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" \
        record-disconnect --interface tun0 --event vpn-down \
        --uuid 33333333-3333-4333-8333-333333333333
assert_file_exists "$state_dir/armed" \
    "queued VPN down preserves durable strict-empty state"
assert_not_grep 'add element inet noid_wan_strict bypass_grace_v4' \
    "$TMPDIR/nft.log" "queued VPN down cannot restore direct-WAN grace"
assert_eq "NOID-WAN-ENDPOINTS-V2" "$(cat "$state_dir/endpoints")" \
    "profile reconciliation, not tunnel-down, owns empty endpoint state"

# --- Volatile-profile retention -------------------------------------------
# A client that never saves its VPN profile takes it away again on disconnect.
# Re-deriving desired state from loaded profiles alone therefore unpins the
# exact address the client is about to dial for its reconnect, and its first
# packets are dropped by the layer that exists to let them through. The pin is
# kept alive by the same activation evidence and the same bounded lifetime that
# already back a hostname promotion -- and only for this volatile class.
runtime_uuid=44444444-4444-4444-8444-444444444444
saved_uuid=55555555-5555-4555-8555-555555555555
cat > "$profiles/runtime-only.nmconnection" <<'RUNTIME_ONLY_PROFILE'
[connection]
id=runtime-only
uuid=44444444-4444-4444-8444-444444444444
type=wireguard

[wireguard]
private-key-flags=2

[wireguard-peer.AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=]
endpoint=198.51.100.77:51820
allowed-ips=0.0.0.0/0;
RUNTIME_ONLY_PROFILE
: > "$TMPDIR/nft.log"
assert_cmd_success "volatile profile reconciles as an ordinary literal endpoint" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" reconcile
assert_grep_fixed 'literal udp 198.51.100.77 51820 0' "$state_dir/endpoints" \
    "loaded volatile profile is durable desired state like any other"
assert_not_grep ' retained ' "$state_dir/endpoints" \
    "a saved-profile reconciliation alone never creates a retention lease"

: > "$TMPDIR/nft.log"
assert_cmd_success "observed activation of a volatile profile creates a bounded lease" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" commit-active \
        --interface wgtest1 --event up --uuid "$runtime_uuid"
assert_grep_fixed "$runtime_uuid" "$state_dir/endpoints" \
    "retention lease keeps its profile provenance"
assert_eq "1" \
    "$(grep -c " retained udp 198.51.100.77 51820 [0-9]" "$state_dir/endpoints")" \
    "activation adds exactly one retention lease for the observed tuple"
assert_grep_fixed 'literal udp 198.51.100.77 51820 0' "$state_dir/endpoints" \
    "the loaded profile keeps contributing its own re-derived record"
assert_grep_fixed \
    'add element inet noid_wan_strict vpn_endpoints_v4 { 198.51.100.77 . udp . 51820 }' \
    "$TMPDIR/nft.log" \
    "two records describing one tuple collapse to the permanent element"
assert_not_grep '198.51.100.77 . udp . 51820 timeout' "$TMPDIR/nft.log" \
    "a lease cannot downgrade the loaded profile's element to a timeout"

# nft silently keeps the LAST occurrence of a repeated key inside one add
# element, so a duplicate is not a loud failure but a quiet wrong answer.
: > "$TMPDIR/nft.log"
sleep 1
assert_cmd_success "repeated activation refreshes rather than accumulates" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" commit-active \
        --interface wgtest1 --event up --uuid "$runtime_uuid"
assert_eq "1" \
    "$(grep -c " retained udp 198.51.100.77 51820 [0-9]" "$state_dir/endpoints")" \
    "reconnecting does not grow durable state by one record per connect"
assert_eq "0" \
    "$(grep 'add element inet noid_wan_strict vpn_endpoints_v4' "$TMPDIR/nft.log" \
        | grep -c '198\.51\.100\.77 \. udp \. 51820.*198\.51\.100\.77 \. udp \. 51820' \
        || true)" \
    "one tuple is never committed twice inside one transaction"

# The client disconnects: NetworkManager drops the volatile profile entirely.
mv "$profiles/runtime-only.nmconnection" "$TMPDIR/runtime-only.fixture"
: > "$TMPDIR/nft.log"
assert_cmd_success "volatile profile removal keeps the observed tuple pinned" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" reconcile
assert_not_grep 'literal udp 198.51.100.77' "$state_dir/endpoints" \
    "the re-derived record disappears with the profile it came from"
assert_grep_fixed " retained udp 198.51.100.77 51820 " "$state_dir/endpoints" \
    "activation evidence survives the client's normal disconnected state"
assert_grep_fixed '198.51.100.77 . udp . 51820 timeout' "$TMPDIR/nft.log" \
    "the surviving pin is committed with its remaining lifetime, not permanently"

: > "$TMPDIR/nft.log"
assert_cmd_success "retention lease is re-armed across a reboot" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" bootstrap
assert_grep_fixed '198.51.100.77 . udp . 51820 timeout' "$TMPDIR/nft.log" \
    "boot transaction and first reconciliation no longer contradict each other"

# A saved profile is the deliberate counter-case: activating it must not create
# a lease, so deleting it still revokes its pin in the same reconciliation.
cat > "$profiles/saved-literal.nmconnection" <<'SAVED_LITERAL_PROFILE'
[connection]
id=saved-literal
uuid=55555555-5555-4555-8555-555555555555
type=wireguard

[wireguard]
private-key-flags=2

[wireguard-peer.AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=]
endpoint=198.51.100.88:51820
allowed-ips=0.0.0.0/0;
SAVED_LITERAL_PROFILE
cp "$profiles/saved-literal.nmconnection" "$persistent/"
assert_cmd_success "saved profile activation is accepted" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" commit-active \
        --interface wgtest2 --event up --uuid "$saved_uuid"
assert_not_grep "$saved_uuid .* retained " "$state_dir/endpoints" \
    "a profile that survives on disk earns no retention lease"
rm "$profiles/saved-literal.nmconnection"
assert_cmd_success "saved profile deletion reconciles" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" reconcile
assert_not_grep '198.51.100.88' "$state_dir/endpoints" \
    "deleting a saved profile still revokes its pin in the same pass"

# Both bounded exits stay available: the lease expires on its own, and the
# documented reset revokes it at once.
sed -i -E '/ retained / s/[0-9]+$/1/' "$state_dir/endpoints"
assert_cmd_success "expiry pass prunes an elapsed retention lease" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" expire
assert_not_grep '198.51.100.77' "$state_dir/endpoints" \
    "an elapsed retention lease leaves durable state like any other lease"

assert_cmd_failure "activation without any loaded profile is refused" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" commit-active \
        --interface wgtest2 --event up --uuid "$saved_uuid"
cp "$TMPDIR/runtime-only.fixture" "$profiles/runtime-only.nmconnection"
assert_cmd_success "fixture restores a live retention lease for the reset check" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" commit-active \
        --interface wgtest1 --event up --uuid "$runtime_uuid"
assert_grep_fixed " retained udp 198.51.100.77 51820 " "$state_dir/endpoints" \
    "a live lease exists before the reset check"
assert_cmd_success "explicit reset revokes a live retention lease immediately" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" reset
assert_eq "NOID-WAN-ENDPOINTS-V2" "$(cat "$state_dir/endpoints")" \
    "reset remains the immediate revocation path for every lease"
printf '%s\n' NOID_WAN_STRICT_ARMED_V1 > "$state_dir/armed"
chmod 0644 "$state_dir/armed"

# A retention lease is state, not a licence: the parser still refuses one
# without a deadline, exactly as it refuses a literal record that carries one.
cp "$state_dir/endpoints" "$state_dir/endpoints.clean"
printf '%s\n' \
    "$runtime_uuid cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc retained udp 198.51.100.77 51820 0" \
    >> "$state_dir/endpoints"
assert_cmd_failure "a retention lease without a deadline is rejected" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" reconcile
mv "$state_dir/endpoints.clean" "$state_dir/endpoints"
chmod 0644 "$state_dir/endpoints"

# --- Unmanaged kernel tunnels ---------------------------------------------
# wg-quick, Mullvad's own daemon and systemd-networkd configure kernel
# WireGuard directly. NetworkManager leaves those devices unmanaged and emits no
# dispatcher event, so with strict mode armed such a tunnel could not handshake
# at all. Discovery reads the kernel instead -- and must never arm by itself.
rm -f "$profiles/runtime-only.nmconnection"
wgq_peer='BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgY='
covered_peer='BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc='
printf '%s\t%s\t%s\n' wgq0 "$wgq_peer" '198.51.100.55:51820' \
    > "$TMPDIR/wg-all-endpoints"
printf '%s\t%s\t%s\n' wgq0 "$wgq_peer" '0' > "$TMPDIR/wg-all-handshakes"

# Positive control for the fixture itself: without it every "not pinned"
# assertion below could pass because the mock answers nothing at all.
assert_eq "$wgq_peer 198.51.100.55:51820" \
    "$(env "${engine_env[@]}" bash "$TMPDIR/wg-mock" show all endpoints \
        | awk -F'\t' '{print $2, $3}')" \
    "the kernel-view fixture actually answers"

: > "$TMPDIR/nft.log"
assert_cmd_success "unmanaged kernel tunnel is discovered and pinned" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" reconcile
assert_grep_fixed 'literal udp 198.51.100.55 51820 0' "$state_dir/endpoints" \
    "a tunnel no profile describes still becomes durable desired state"
assert_grep_fixed '198.51.100.55 . udp . 51820' "$TMPDIR/nft.log" \
    "the discovered tuple is committed to the physical boundary"
assert_not_grep ' retained ' "$state_dir/endpoints" \
    "discovery without a handshake earns no lease"

# The kernel's completed handshake is the same evidence the profile-backed
# WireGuard path already accepts, so it earns the same bounded lease.
#
# It must not depend on the event that discovered the tunnel. Measured in a VM
# against a real wg-quick tunnel: udev fires when the interface appears, seconds
# BEFORE the first handshake completes, and on a host whose only tunnel is
# unmanaged nothing else reconciles afterwards -- so the lease was never created
# and the next connect paid the full handshake retry again. The periodic expiry
# pass is the second, sanctioned entry point that closes that window, and it is
# tested here first precisely because it is the one that carries that case.
printf '%s\t%s\t%s\n' wgq0 "$wgq_peer" "$(date +%s)" \
    > "$TMPDIR/wg-all-handshakes"
assert_cmd_success "the periodic expiry pass records a handshake that arrived later" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" expire
assert_eq "1" \
    "$(grep -c ' retained udp 198.51.100.55 51820 [0-9]' "$state_dir/endpoints")" \
    "kernel handshake evidence creates exactly one bounded lease"

# Without a ceiling on re-issuing, every pass would rewrite durable state with a
# fresh deadline and turn a five-minute timer into a five-minute write loop.
# The wall clock has to advance between the passes: a re-issued lease inside the
# same second is byte-identical to the old one, so without the sleep this check
# would pass with the ceiling removed and prove nothing.
lease_state=$(sha256sum "$state_dir/endpoints" | awk '{print $1}')
sleep 1
assert_cmd_success "a further pass over a fresh lease changes nothing" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" expire
sleep 1
assert_cmd_success "an ordinary reconciliation over a fresh lease changes nothing" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" reconcile
assert_eq "$lease_state" "$(sha256sum "$state_dir/endpoints" | awk '{print $1}')" \
    "a lease with most of its lifetime left is not re-issued on every pass"

# wg-quick down removes the interface outright: the lease is the only thing
# that keeps the address reachable for the next attempt.
: > "$TMPDIR/wg-all-endpoints"
: > "$TMPDIR/wg-all-handshakes"
: > "$TMPDIR/nft.log"
assert_cmd_success "tunnel teardown reconciles" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" reconcile
assert_not_grep 'literal udp 198.51.100.55' "$state_dir/endpoints" \
    "the kernel-derived record disappears with the interface"
assert_grep_fixed ' retained udp 198.51.100.55 51820 ' "$state_dir/endpoints" \
    "the proven endpoint stays pinned across teardown"
assert_grep_fixed '198.51.100.55 . udp . 51820 timeout' "$TMPDIR/nft.log" \
    "the surviving discovered pin carries its remaining lifetime"

# Arming narrows connectivity. An unrelated kernel WireGuard interface -- a
# container mesh, a test tunnel -- must never be able to cut a machine off.
printf '%s\t%s\t%s\n' wgq0 "$wgq_peer" '198.51.100.55:51820' \
    > "$TMPDIR/wg-all-endpoints"
printf '%s\t%s\t%s\n' wgq0 "$wgq_peer" "$(date +%s)" \
    > "$TMPDIR/wg-all-handshakes"
rm -f "$state_dir/armed"
: > "$TMPDIR/nft.log"
assert_cmd_success "discovery runs while unarmed" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" reconcile
if [ ! -e "$state_dir/armed" ]; then
    _pass "kernel tunnel discovery never arms the boundary by itself"
else
    _fail "kernel tunnel discovery never arms the boundary by itself"
fi
assert_grep_fixed 'add element inet noid_wan_strict bypass_grace_v4 { 0.0.0.0/0 }' \
    "$TMPDIR/nft.log" \
    "an unarmed host keeps its disclosed grace despite a live tunnel"
printf '%s\n' NOID_WAN_STRICT_ARMED_V1 > "$state_dir/armed"
chmod 0644 "$state_dir/armed"

# A peer a loaded profile already describes keeps that profile's identity, so
# one tunnel can never produce two competing records.
cat > "$profiles/covered.nmconnection" <<'COVERED_PROFILE'
[connection]
id=covered
uuid=66666666-6666-4666-8666-666666666666
type=wireguard

[wireguard]
private-key-flags=2

[wireguard-peer.BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=]
endpoint=198.51.100.99:51820
allowed-ips=0.0.0.0/0;
COVERED_PROFILE
cp "$profiles/covered.nmconnection" "$persistent/"
printf '%s\t%s\t%s\n%s\t%s\t%s\n' \
    wgq0 "$wgq_peer" '198.51.100.55:51820' \
    wgq1 "$covered_peer" '198.51.100.44:51820' > "$TMPDIR/wg-all-endpoints"
assert_cmd_success "mixed profile-backed and unmanaged view reconciles" \
    env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" reconcile
assert_grep_fixed 'literal udp 198.51.100.99 51820 0' "$state_dir/endpoints" \
    "the loaded profile remains the authority for its own peer"
assert_not_grep '198.51.100.44' "$state_dir/endpoints" \
    "a peer a profile already covers is not pinned a second time from the kernel"

# Module 26 ships wireguard-tools, but a host can still lack it -- an image
# predating that include, or an administrator who removed it. Then there is no
# kernel tooling to ask, which is a missing source and not a policy failure.
: > "$TMPDIR/nft.log"
assert_cmd_success "a missing wg binary degrades to profile-only discovery" \
    env "${engine_env[@]}" NOID_WG_BIN=/nonexistent/noid-wg \
        python3 "$TMPDIR/endpoint-engine.py" reconcile
assert_grep_fixed 'literal udp 198.51.100.99 51820 0' "$state_dir/endpoints" \
    "profile-derived state survives an absent WireGuard toolchain"
assert_not_grep '198.51.100.55 51820 0' "$state_dir/endpoints" \
    "no kernel-derived record is invented without the tool that reports it"

# Anything that does not match the measured three-field shape is reported.
printf '%s\t%s\n%s\t%s\t%s\n%s\t%s\t%s\n%s\t%s\t%s\n' \
    wgq0 'two-field-line' \
    wgq0 'not-a-peer-key' '198.51.100.60:51820' \
    wgq0 "$wgq_peer" '127.0.0.1:51820' \
    wgq2 "$wgq_peer" '198.51.100.55:51820' > "$TMPDIR/wg-all-endpoints"
if env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" reconcile \
        >/dev/null 2>"$TMPDIR/runtime-skip.err"; then
    _pass "malformed kernel rows are skipped instead of aborting reconciliation"
else
    sed 's/^/    controller: /' "$TMPDIR/runtime-skip.err" >&2
    _fail "malformed kernel rows are skipped instead of aborting reconciliation"
fi
assert_grep_fixed 'unmanaged WireGuard peer(s) skipped' "$TMPDIR/runtime-skip.err" \
    "what discovery ignored is named, never silently dropped"
assert_not_grep '127.0.0.1\|198.51.100.60' "$state_dir/endpoints" \
    "an unsafe address class or invalid peer key never enters durable state"

# Enumeration is bounded, and the bound is reported rather than silent.
python3 - "$TMPDIR/wg-all-endpoints" <<'PY'
import base64, sys, pathlib
rows = [
    "wgq0\t%s\t198.51.100.%d:51820" % (
        base64.b64encode(bytes([index]) * 32).decode(), 100 + index)
    for index in range(1, 10)
]
pathlib.Path(sys.argv[1]).write_text("\n".join(rows) + "\n")
PY
if env "${engine_env[@]}" NOID_WAN_WG_MAX_PEERS=2 \
        python3 "$TMPDIR/endpoint-engine.py" reconcile \
        >/dev/null 2>"$TMPDIR/runtime-cap.err"; then
    _pass "the per-interface peer ceiling is enforced without failing"
else
    sed 's/^/    controller: /' "$TMPDIR/runtime-cap.err" >&2
    _fail "the per-interface peer ceiling is enforced without failing"
fi
assert_eq "2" \
    "$(grep -c ' literal udp 198.51.100.10[0-9] 51820 0' "$state_dir/endpoints")" \
    "exactly the ceiling many kernel peers are pinned"
assert_grep_fixed 'unmanaged WireGuard peer(s) skipped' "$TMPDIR/runtime-cap.err" \
    "the enforced ceiling is disclosed"

# Clients that never save their profile create a new UUID per server, so the
# number of simultaneously live leases needs its own ceiling.
: > "$TMPDIR/wg-all-endpoints"
: > "$TMPDIR/wg-all-handshakes"
rm -f "$profiles/covered.nmconnection"
python3 - "$state_dir/endpoints" <<'PY'
import sys, time, pathlib
now = int(time.time())
lines = ["NOID-WAN-ENDPOINTS-V2"]
for index in range(1, 10):
    lines.append("%08d-0000-4000-8000-000000000000 %s retained udp 198.51.100.%d 51820 %d"
                 % (index, "%064d" % index, 200 + index, now + 3600 * index))
pathlib.Path(sys.argv[1]).write_text("\n".join(lines) + "\n")
PY
chmod 0644 "$state_dir/endpoints"
if env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" reconcile \
        >/dev/null 2>"$TMPDIR/retain-cap.err"; then
    _pass "the retention ceiling is enforced without failing"
else
    sed 's/^/    controller: /' "$TMPDIR/retain-cap.err" >&2
    _fail "the retention ceiling is enforced without failing"
fi
assert_eq "8" "$(grep -c ' retained ' "$state_dir/endpoints")" \
    "at most the ceiling many retention leases stay live"
assert_not_grep '198.51.100.201 ' "$state_dir/endpoints" \
    "the oldest activation is the one that loses its lease"
assert_grep_fixed 'retention lease(s) pruned at the ceiling' "$TMPDIR/retain-cap.err" \
    "pruning at the ceiling is disclosed"
printf '%s\n' 'NOID-WAN-ENDPOINTS-V2' > "$state_dir/endpoints"
chmod 0644 "$state_dir/endpoints"

chmod 0666 "$state_dir/endpoints"
if env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" bootstrap >/dev/null 2>&1; then
    _fail "weakened endpoint state metadata is rejected"
else
    _pass "weakened endpoint state metadata is rejected"
fi
chmod 0644 "$state_dir/endpoints"

state_before=$(sha256sum "$state_dir/endpoints" | awk '{print $1}')
export NOID_NFT_FAIL=1
if env "${engine_env[@]}" python3 "$TMPDIR/endpoint-engine.py" reconcile >/dev/null 2>&1; then
    _fail "failed nft transaction cannot publish endpoint state"
else
    _pass "failed nft transaction cannot publish endpoint state"
fi
unset NOID_NFT_FAIL
assert_eq "$state_before" "$(sha256sum "$state_dir/endpoints" | awk '{print $1}')" \
    "failed nft transaction preserves prior state bytes"
test_finish

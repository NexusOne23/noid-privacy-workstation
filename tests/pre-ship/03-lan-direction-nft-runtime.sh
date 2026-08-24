#!/bin/bash
# Validate direction-aware peer schemas and the cross-layer host DHCPv4
# control-plane selector in a disposable network namespace.
set -euo pipefail

TEST_NAME=03-lan-direction-nft-runtime
PROJECT_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
M03="$PROJECT_ROOT/kickstart/snippets/03-firewalld.ks"
M06="$PROJECT_ROOT/kickstart/snippets/06-vpn-killswitch.ks"

if [ "$(id -u)" -ne 0 ]; then
    if sudo -n true >/dev/null 2>&1; then
        exec sudo -n "$0"
    fi
    echo "FAIL  $TEST_NAME: run as root or establish sudo credentials first" >&2
    exit 2
fi
for command in nft unshare awk ip python3 setpriv sysctl; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "FAIL  $TEST_NAME: missing command: $command" >&2
        exit 2
    }
done

fixture=$(mktemp -d /var/tmp/noid-nft-direction.XXXXXX)
cleanup() { find "$fixture" -depth -delete; }
trap cleanup EXIT HUP INT TERM

extract_heredoc() {
    local source=$1 marker=$2 output=$3
    awk -v marker="$marker" '
        !inside && $0 ~ "<<-?[[:space:]]*[\047\"]?" marker "[\047\"]?([[:space:]]|$)" {
            inside=1
            next
        }
        inside && ($0 == marker || $0 ~ "^[\\t]+" marker "$") {
            found=1
            exit
        }
        inside { print }
        END { exit !(inside && found) }
    ' "$source" > "$output"
}

extract_heredoc "$M03" LAN_TOPOLOGY_NFT_EOF "$fixture/topology.nft"
extract_heredoc "$M03" POLICY_EOF "$fixture/block-lan-out.xml"
extract_heredoc "$M06" NFT_EOF "$fixture/wan.nft"

DHCP_HOST_RULE='  <rule family="ipv4" priority="-32768"><source-port port="68" protocol="udp"/><accept/></rule>'
[ "$(grep -cFx "$DHCP_HOST_RULE" "$fixture/block-lan-out.xml" || true)" = 1 ] || {
    echo "FAIL  $TEST_NAME: host policy lacks the exact DHCP continuation" >&2
    exit 1
}

unshare -n -- bash -euo pipefail -c '
    topology=$1
    wan=$2
    nft -f "$topology"
    nft -f "$wan"

    nft add element inet noid_lan_topology outbound_peers_v4 \
        "{ 198.19.7.20 }"
    nft add element inet noid_lan_topology inbound_peers_v4 \
        "{ 198.19.7.21, 198.19.7.22 }"
    nft add element inet noid_lan_topology inbound_tcp_v4 \
        "{ \"lo\" . 198.19.7.21 . 8443 }"
    nft add element inet noid_lan_topology inbound_udp_v4 \
        "{ \"lo\" . 198.19.7.22 . 5300-5301 }"
    nft add element inet noid_wan_strict lan_inbound_peers_v4 \
        "{ 198.19.7.21, 198.19.7.22 }"

    nft get element inet noid_lan_topology outbound_peers_v4 \
        "{ 198.19.7.20 }" >/dev/null
    nft get element inet noid_lan_topology inbound_tcp_v4 \
        "{ \"lo\" . 198.19.7.21 . 8443 }" >/dev/null
    nft get element inet noid_lan_topology inbound_udp_v4 \
        "{ \"lo\" . 198.19.7.22 . 5300 }" >/dev/null
    nft get element inet noid_lan_topology inbound_udp_v4 \
        "{ \"lo\" . 198.19.7.22 . 5301 }" >/dev/null
    if nft get element inet noid_lan_topology inbound_udp_v4 \
            "{ \"lo\" . 198.19.7.22 . 5299 }" >/dev/null 2>&1; then
        echo "adjacent UDP port entered the interval" >&2
        exit 1
    fi
    nft get element inet noid_wan_strict lan_inbound_peers_v4 \
        "{ 198.19.7.21 }" >/dev/null

    # Model firewalld 2.4s documented compilation of the extracted negative-
    # priority Rich_SourcePort accept: it runs in the policy pre chain before
    # the static destination denies. M03 at priority -4 remains the exact
    # selector in front of firewalld (+10), while a later observation hook
    # stands in for TC egress. This proves packets must survive both L3 layers
    # before the existing BPF transaction tracker can observe them.
    ip link set lo up
    ip link add noiddhcp0 type dummy
    ip addr add 198.19.7.10/24 dev noiddhcp0
    ip link set noiddhcp0 up
    ip route add default dev noiddhcp0
    sysctl -q -w net.ipv4.ip_unprivileged_port_start=0
    nft add element inet noid_lan_topology physical_ifaces \
        "{ \"noiddhcp0\" }"
    nft add element inet noid_lan_topology lan_guard_ifaces \
        "{ \"noiddhcp0\" }"
    nft add element inet noid_lan_topology connected_v4 \
        "{ 198.19.7.0/24 }"
    nft add element inet noid_lan_topology allowed_v4 \
        "{ 198.19.7.20 }"
    nft -f - <<"DHCP_NFT_EOF"
table inet noid_dhcp_firewalld_fixture {
    chain output {
        type filter hook output priority 10; policy accept;
        jump pre
        jump deny
    }
    chain pre {
        meta nfproto ipv4 udp sport 68 accept
        ip daddr 198.19.7.20 accept
    }
    chain deny {
        ip daddr { 10.0.0.0/8, 198.19.7.0/24, 255.255.255.255 } drop
    }
}
table inet noid_dhcp_observe_fixture {
    counter seen { }
    chain output {
        type filter hook output priority 20; policy accept;
        counter name seen
    }
}
DHCP_NFT_EOF

    send_udp() {
        owner=$4
        runner=()
        if [ "$owner" = unprivileged ]; then
            runner=(setpriv --reuid=65534 --regid=65534 --clear-groups)
        fi
        "${runner[@]}" python3 - "$1" "$2" "$3" <<"PYTHON_EOF"
import socket
import sys

sport = int(sys.argv[1])
destination = sys.argv[2]
dport = int(sys.argv[3])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
if destination == "255.255.255.255":
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
sock.bind(("198.19.7.10", sport))
try:
    sock.sendto(b"noid-dhcp-path-probe", (destination, dport))
except PermissionError:
    # nftables returns EPERM to the local sender for a terminal output drop.
    pass
sock.close()
PYTHON_EOF
    }
    observed_packets() {
        nft -j list counter inet noid_dhcp_observe_fixture seen \
            | python3 -c "import json,sys; print(json.load(sys.stdin)[\"nftables\"][1][\"counter\"][\"packets\"])"
    }
    check_udp_path() {
        label=$1 expected=$2 sport=$3 destination=$4 dport=$5
        owner=${6:-root}
        nft reset counter inet noid_dhcp_observe_fixture seen >/dev/null
        send_udp "$sport" "$destination" "$dport" "$owner"
        actual=$(observed_packets)
        [ "$actual" = "$expected" ] || {
            echo "FAIL  $label: expected late-hook packets=$expected, got $actual" >&2
            exit 1
        }
    }

    # Positive DHCP phases: connected-server renewal, limited broadcast and a
    # routed server/relay all retain only the root-owned UDP 68->67 contract.
    # The dummy address above is configured directly rather than by DHCP, so
    # this same run also proves topology enforcement is address-source agnostic.
    check_udp_path dhcp-unicast 1 68 198.19.7.30 67
    check_udp_path dhcp-broadcast 1 68 255.255.255.255 67
    check_udp_path dhcp-routed-private 1 68 10.0.0.20 67

    # An explicit outbound peer grant must remain complete even for the
    # reserved local source port. Production still requires privilege to bind
    # that port; the lowered namespace sysctl makes the non-root case testable.
    check_udp_path explicit-peer-ordinary 1 40000 198.19.7.20 443
    check_udp_path explicit-peer-source68 1 68 198.19.7.20 443
    check_udp_path explicit-peer-unprivileged-source68 1 68 198.19.7.20 443 unprivileged

    # Negative matrix: outside an explicit peer grant, neither half of the
    # cross-layer selector may authorize a neighboring port, arbitrary
    # source-68 data, a forged client source port, broadcast misuse or ordinary
    # LAN traffic. The WAN positive control prevents a blanket drop false green.
    check_udp_path wrong-client-port 0 1068 198.19.7.30 67
    check_udp_path unprivileged-dhcp-client 0 68 198.19.7.30 67 unprivileged
    check_udp_path reserved-port-misuse-lan 0 68 198.19.7.30 443
    check_udp_path reserved-port-misuse-wan 0 68 8.8.8.8 443
    check_udp_path wrong-broadcast-client 0 1068 255.255.255.255 67
    check_udp_path wrong-broadcast-service 0 68 255.255.255.255 1067
    check_udp_path ordinary-lan-application 0 40000 198.19.7.30 443
    check_udp_path ordinary-wan-application 1 40000 8.8.8.8 443

    # Model the committed global-allow transaction: firewalld detaches the HOST
    # policy and the same atomic topology refresh empties every default-only
    # drop set. Source port 68 must not survive as an accidental hidden block.
    nft delete table inet noid_dhcp_firewalld_fixture
    nft flush set inet noid_lan_topology allowed_v4
    nft flush set inet noid_lan_topology connected_v4
    nft flush set inet noid_lan_topology lan_guard_ifaces
    check_udp_path global-allow-ordinary 1 40000 198.19.7.30 443
    check_udp_path global-allow-source68 1 68 198.19.7.30 443

    nft list ruleset >/dev/null
' _ "$fixture/topology.nft" "$fixture/wan.nft"

echo "PASS  $TEST_NAME: exact DHCPv4 plus peer/global grants; unapproved LAN and reserved-port misuse remain blocked"

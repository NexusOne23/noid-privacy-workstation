#!/usr/bin/env bash
# Candidate-only M04/M23 IPv4 Address Conflict Detection gate. Run after the
# isolated test NIC is active in every lifecycle pass:
#   sudo bash tests/pre-ship/04-ipv4-acd-runtime.sh live
#   sudo bash tests/pre-ship/04-ipv4-acd-runtime.sh fresh-install
#   sudo bash tests/pre-ship/04-ipv4-acd-runtime.sh reboot
set -euo pipefail
export LC_ALL=C.UTF-8 LANG=C.UTF-8

TEST_NAME=04-ipv4-acd-runtime
PASS_ID=${1:-invalid}
fail() { echo "FAIL  $TEST_NAME [$PASS_ID]: $*" >&2; exit 1; }
note() { echo "  [$PASS_ID] $*"; }

[ "$#" -eq 1 ] || {
    echo "usage: $0 {live|fresh-install|reboot}" >&2
    exit 2
}
case "$PASS_ID" in live|fresh-install|reboot) ;; *) exit 2 ;; esac

if [ "$(id -u)" -ne 0 ]; then
    if sudo -n true >/dev/null 2>&1; then
        exec sudo -n "$0" "$PASS_ID"
    fi
    fail "run as root or establish sudo credentials first"
fi
grep -q '^ID=noid-privacy-workstation$' /etc/os-release 2>/dev/null || \
    fail "not running inside the NoID Privacy candidate"
for tool in arping awk grep ip NetworkManager nmcli nsenter python3 \
            readlink stat systemctl unshare; do
    command -v "$tool" >/dev/null 2>&1 || fail "missing command: $tool"
done

NM_DEFAULTS=/etc/NetworkManager/conf.d/02-noid-connection-defaults.conf
STATE=/var/lib/noid-privacy/arp-hardening.state
DISABLED=/var/lib/noid-privacy/arp-hardening.disabled
STATE_GUARD=/usr/local/sbin/noid-arp-state-guard.sh
DISPATCHER=/etc/NetworkManager/dispatcher.d/90-arp-hardening
PREUP=/etc/NetworkManager/dispatcher.d/pre-up.d/90-arp-hardening
NOWAIT=/etc/NetworkManager/dispatcher.d/no-wait.d/90-arp-hardening
XDP_CONTROLLER=/usr/local/sbin/noid-lan-xdp
XDP_HEALTH=/run/noid-privacy/lan-xdp-health
for path in "$NM_DEFAULTS" "$STATE"; do
    [ -f "$path" ] && [ ! -L "$path" ] && [ -s "$path" ] || \
        fail "missing, empty, non-regular or symlinked: $path"
done
[ -x "$STATE_GUARD" ] || fail "installed gateway state guard is missing"
"$STATE_GUARD" || fail "installed gateway identity contract failed validation"
systemctl is-active --quiet noid-arp-state-guard.service || \
    fail "pre-network gateway state guard is not active"
[ "$(stat -Lc '%u:%g:%a:%h' "$STATE")" = '0:0:644:1' ] || \
    fail "gateway state metadata is unsafe"
[ -d /var/lib/noid-privacy ] && [ ! -L /var/lib/noid-privacy ] \
    && [ "$(stat -Lc '%u:%g:%a' /var/lib/noid-privacy)" = '0:0:755' ] \
    || fail "gateway state parent metadata is unsafe"
[ ! -e "$DISABLED" ] && [ ! -L "$DISABLED" ] || \
    fail "candidate is unexpectedly in the explicit kernel-pin opt-out state"
[ -L "$DISPATCHER" ] \
    && [ "$(readlink "$DISPATCHER")" = no-wait.d/90-arp-hardening ] \
    || fail "generated gateway dispatcher has no exact no-wait root symlink"
for copy in "$PREUP" "$NOWAIT"; do
    [ -f "$copy" ] && [ ! -L "$copy" ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' "$copy")" = '0:0:700:1' ] \
        || fail "generated gateway dispatcher copy metadata is unsafe: $copy"
done
cmp -s "$PREUP" "$NOWAIT" || \
    fail "awaited and no-wait generated dispatcher copies differ"
[ -x "$XDP_CONTROLLER" ] || fail "installed XDP controller is missing/non-executable"
grep -qx 'STATE=ACTIVE' "$XDP_HEALTH" 2>/dev/null || \
    fail "physical-link XDP health is not ACTIVE"
"$XDP_CONTROLLER" status >/dev/null || \
    fail "physical-link XDP/TC attachment identity failed"
note "exact installed XDP/TC generation and gateway-state contract are active"

# Retired hookless shadow state must not survive an upgrade. Native RFC 5227
# probes, announcements, conflict packets and replies remain owned by the
# kernel/NetworkManager; the exact neighbour and M03 XDP gate are authoritative.
for retired in \
    /usr/share/noid-privacy/arp-hardening/arp-bootstrap.nft \
    /usr/share/noid-privacy/arp-hardening/arp-hardening.nft.template \
    /usr/share/noid-privacy/arp-hardening/arp-hardening-firewalld-reload.conf.template \
    /etc/nftables/arp-hardening.nft \
    /etc/systemd/system/firewalld.service.d/arp-hardening-firewalld-reload.conf \
    /usr/local/sbin/noid-arp-bootstrap.sh \
    /etc/systemd/system/noid-arp-bootstrap.service \
    /etc/systemd/system/NetworkManager.service.d/21-noid-arp-bootstrap.conf \
    /etc/NetworkManager/dispatcher.d/25-noid-arp-bootstrap-learn \
    /etc/NetworkManager/dispatcher.d/pre-up.d/25-noid-arp-bootstrap-learn; do
    [ ! -e "$retired" ] && [ ! -L "$retired" ] || \
        fail "retired non-enforcing ARP artifact remains: $retired"
done
note "native ARP/ACD path has no M04 nft/firewalld shadow machinery"

# Closed-schema state parse without sourcing root-controlled data as shell.
mapfile -t state_lines < "$STATE"
[ "${#state_lines[@]}" -eq 5 ] || fail "ARP state does not contain exactly five records"
declare -A state=()
for line in "${state_lines[@]}"; do
    [[ $line == *=* ]] || fail "malformed ARP state record"
    key=${line%%=*}; value=${line#*=}
    [[ -z ${state[$key]+present} ]] || fail "duplicate ARP state key: $key"
    case "$key" in ENABLED|WAN_IFACE|GATEWAY_IP|GATEWAY_MAC|LEARNED_AT) ;; \
        *) fail "unknown ARP state key: $key" ;; esac
    state["$key"]=$value
done
[ "${state[ENABLED]:-}" = 1 ] || fail "ARP state is not enabled"
[[ ${state[WAN_IFACE]:-} =~ ^[a-zA-Z0-9_.-]{1,15}$ ]] || fail "invalid WAN interface"
gateway_ip=$(python3 -c \
    'import ipaddress,sys; print(ipaddress.IPv4Address(sys.argv[1]))' \
    "${state[GATEWAY_IP]:-}" 2>/dev/null) || fail "invalid gateway IPv4 address"
[ "$gateway_ip" = "${state[GATEWAY_IP]}" ] || fail "non-canonical gateway IPv4 address"
gateway_mac=${state[GATEWAY_MAC]:-}
[[ $gateway_mac =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]] || fail "invalid gateway MAC"
[[ ${state[LEARNED_AT]:-} =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] \
    || fail "invalid gateway learning timestamp"
neighbour=$(ip -4 neigh show to "$gateway_ip" dev "${state[WAN_IFACE]}") || \
    fail "cannot query exact gateway neighbour"
[ "$(grep -c . <<<"$neighbour")" -eq 1 ] || fail "gateway neighbour is absent or ambiguous"
observed_pin=$(awk -v ip="$gateway_ip" '
    NR == 1 && $1 == ip {
        mac=""
        for (i=1; i<=NF; i++) if ($i == "lladdr") mac=tolower($(i+1))
        if (mac != "" && tolower($NF) == "permanent") print mac
    }
' <<<"$neighbour")
[ "$observed_pin" = "$gateway_mac" ] || \
    fail "exact-device gateway neighbour is not the recorded permanent pin"
note "gateway $gateway_ip is permanently pinned on ${state[WAN_IFACE]}"

# The installed global default must be effective in NetworkManager's own
# parser, while no active physical profile may explicitly override DAD off.
grep -qx 'ipv4.dad-timeout=200' "$NM_DEFAULTS" || \
    fail "installed NetworkManager default does not explicitly enable IPv4 DAD"
effective_nm=$(NetworkManager --print-config 2>/dev/null) || \
    fail "NetworkManager cannot print effective configuration"
grep -qx 'ipv4.dad-timeout=200' <<<"$effective_nm" || \
    fail "effective NetworkManager configuration lost ipv4.dad-timeout=200"
physical_profiles=0
active_profiles=$(nmcli -t -f UUID,TYPE connection show --active) || \
    fail "cannot enumerate active NetworkManager profiles"
while IFS=: read -r uuid type; do
    case "$type" in 802-3-ethernet|802-11-wireless) ;; *) continue ;; esac
    [[ $uuid =~ ^[0-9a-fA-F-]{36}$ ]] || fail "active physical profile has an invalid UUID"
    physical_profiles=$((physical_profiles + 1))
    dad=$(nmcli -g ipv4.dad-timeout connection show uuid "$uuid" 2>/dev/null) || \
        fail "cannot read ipv4.dad-timeout for active physical profile $uuid"
    case "$dad" in 0|off) fail "active physical profile $uuid disables IPv4 DAD" ;; esac
done <<< "$active_profiles"
[ "$physical_profiles" -gt 0 ] || fail "no active physical NetworkManager profile"
note "NetworkManager effective/default and active-profile DAD settings are enabled"

# Observe both outcomes on a private veth pair. A process-bound namespace
# avoids ip-netns' bind-mount setup, which SELinux correctly rejects against a
# Live ISO's tmpfs-labeled overlay root. The peer owns the candidate address for
# the first run and must cause DAD failure; after removal the same probe must
# succeed. No packet leaves the disposable namespace pair.
suffix=$$
host_if="nah$suffix"
peer_if="nap$suffix"
namespace_pid=
peer_namespace=
output=$(mktemp)
cleanup() {
    trap - EXIT HUP INT TERM
    ip link del "$host_if" >/dev/null 2>&1 || true
    if [[ -n ${namespace_pid:-} ]]; then
        kill "$namespace_pid" >/dev/null 2>&1 || true
        wait "$namespace_pid" 2>/dev/null || true
    fi
    rm -f "$output"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
host_namespace=$(readlink /proc/self/ns/net) || \
    fail "cannot identify the host network namespace"
unshare --net /usr/bin/sleep 60 &
namespace_pid=$!
for _ in {1..50}; do
    peer_namespace=$(readlink "/proc/$namespace_pid/ns/net" 2>/dev/null || true)
    [[ -n $peer_namespace && $peer_namespace != "$host_namespace" ]] && break
    kill -0 "$namespace_pid" 2>/dev/null || \
        fail "process-bound network namespace exited during setup"
    sleep 0.02
done
[[ -n $peer_namespace && $peer_namespace != "$host_namespace" ]] || \
    fail "unshare did not create an isolated network namespace"
ip link add "$host_if" type veth peer name "$peer_if"
ip link set "$peer_if" netns "$namespace_pid"
ip link set "$host_if" up
nsenter --target "$namespace_pid" --net ip link set lo up
nsenter --target "$namespace_pid" --net ip link set "$peer_if" up
nsenter --target "$namespace_pid" --net \
    ip addr add 198.18.0.77/24 dev "$peer_if"

duplicate_rc=0
arping -D -c 2 -w 3 -I "$host_if" 198.18.0.77 > "$output" 2>&1 \
    || duplicate_rc=$?
[ "$duplicate_rc" -ne 0 ] || fail "DAD accepted an address owned by the isolated peer"
grep -qi 'reply from' "$output" || fail "DAD failure lacked an observed conflicting ARP reply"

nsenter --target "$namespace_pid" --net \
    ip addr del 198.18.0.77/24 dev "$peer_if"
if ! arping -D -c 2 -w 3 -I "$host_if" 198.18.0.77 > "$output" 2>&1; then
    fail "DAD rejected the now-unused isolated address"
fi
if grep -qi 'reply from' "$output"; then
    fail "unused-address DAD unexpectedly observed a conflict"
fi
note "isolated DAD rejects a duplicate and accepts the same address once unused"

echo "PASS  $TEST_NAME [$PASS_ID]: native ACD + validated exact gateway pin/XDP identity"

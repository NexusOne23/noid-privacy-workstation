# ============================================================================
# Module 06 — VPN + Killswitch + WAN-egress-strict (defense-in-depth)
# Status: LOCKED 2026-08-15 (v71) — disable pathname expansion in WireGuard interface enumeration.
#
# Decision: the image is provider-neutral and enables a physical-interface
# L3 egress backstop by default. Its actual runtime mode is authoritative:
# a never-armed install deliberately remains in GRACE_BOOTSTRAP until the user
# configures a supported VPN path or explicitly chooses no VPN/disable. In
# STRICT/STRICT_EMPTY, the nft inet output/forward hooks block host-network-
# namespace IPv4/IPv6 public egress on discovered physical interfaces outside
# reconciled durable VPN tuples and bounded handshake candidates. This covers
# ordinary applications that bind a physical NIC directly (SO_BINDTODEVICE /
# curl --interface) instead of following a provider's default route.
#
# This is not a universal malware or host-compromise boundary. CAP_NET_RAW
# link-layer injection, CAP_NET_ADMIN/CAP_SYS_ADMIN control of networking,
# separately controlled network namespaces/devices, non-IP link protocols and
# firmware out-of-band paths are outside M06. LAN IP traffic falls through to
# M03's separate topology policy.
# Threat model, edge-cases and
# CLI usage are documented in the deployed user-doc (STEP 7).
#
# Architecture (5 dispatchers + 1 pre-up boot-guard + 1 nft-table +
#               4 services + 1 path-unit + 1 timer + 2 CLIs +
#               controller/wrappers + 1 user-doc + state):
#   - pre-up.d/20-noid-wan-strict-boot-guard : fails boot networking CLOSED
#                                        (downs the physical link) when armed
#                                        strict state is missing/invalid
#   - 45-noid-wireguard-mtu          : lower-only live MTU reconciliation from
#                                      each active peer's real outer path
#   - 50-vpn-zone-enforce              : firewalld zone=noid-vpn on VPN-up
#   - 55-wan-strict-scan-on-network-up : reconcile loaded profiles, bounded
#                                        hostname candidates and the applied
#                                        connection's bootstrap host routes
#   - 58-wan-strict-tunnel-down        : retire volatile active proof after
#                                        tunnel teardown; strict stays armed
#   - 60-vpn-endpoint-pin              : commit an observed active endpoint
#                                        only after tunnel activation/handshake
#   - /etc/nftables.d/noid-wan-strict.nft   : the table + sets + counters
#   - noid-wan-strict.service               : boot-time bootstrap
#   - noid-wan-strict-status-publish.service : republishes the verified
#                                               runtime contract after every
#                                               boot, including explicit OFF
#   - noid-wan-strict-scan-profiles.path    : watches the NM profile dir
#   - noid-wan-strict-scan-profiles.service : oneshot trigger of the helper
#   - noid-wan-strict-endpoint-expiry.service/.timer : bounded authenticated
#                                                       lease pruning
#   - /etc/tmpfiles.d/noid-wan-strict.conf   : pre-created lock/evidence paths
#   - /usr/local/sbin/noid-wan-strict-publish-status : closed status publisher
#   - /usr/local/sbin/noid-wireguard-mtu-reconcile    : live-only WG MTU owner
#   - /usr/local/sbin/noid-wan-strict-bootstrap.sh     : boot-time setup
#   - /usr/local/libexec/noid-wan-strict-endpoints     : libnm controller
#   - /usr/local/sbin/noid-wan-strict-scan-profiles.sh : compatibility wrapper
#   - /usr/local/sbin/noid-wan-strict       : CLI status/pause/resume/reset/
#                                             scan-profiles
#   - /usr/local/sbin/noid-toggle-wan-strict : on/off toggle (GUI-paired)
#   - /usr/share/doc/noid-privacy/wan-egress-strict.md : user-doc
#   - /var/lib/noid-privacy/wan-strict-endpoints.txt   : v2 state (0644,
#     GUI-readable; profile/fingerprint/provenance/expiry + exact tuple)
#   - /var/lib/noid-privacy/wan-strict-armed.flag      : strict was committed;
#                                                        empty state stays closed
#   - /var/lib/noid-privacy/wan-strict-disabled.flag   : disable-flag
#   - /run/noid-privacy/wan-strict-active/              : activated-tunnel proof
#
# Design constraints (decided + incident-verified; keep when editing):
#   - The 50- dispatcher is the SOLE VPN-zone enforcement: NM 1.54+ rejects
#     connection.zone as a connection-default, the M03 conf file is a no-op
#     placeholder. Without the dispatcher, VPN ifaces land in the drop zone
#     and block-lan-out kills VPN-internal 10.x traffic.
#   - Disabled-state mechanism is the FLAG-FILE, never dispatcher chmod:
#     dispatchers stay mode 0700 always with an early-exit guard. Toggling
#     the exec-bit instead produces "Cannot execute" NM journal-spam on
#     every NM event.
#   - Loaded profiles come from libnm, not section-blind file greps. Literal
#     endpoints form durable desired state. DNS answers enter only separate
#     120-second candidate sets; successful WireGuard handshakes or qualifying
#     OpenVPN activation may promote the actually observed address with a
#     bounded authenticated lease. Profile deletion/change and lease expiry
#     atomically revoke stale tuples.
#   - A client whose profile NetworkManager only ever holds in volatile /run
#     state takes that profile away again on disconnect. Its observed-active
#     tuples therefore also get a bounded `retained` lease, so the address is
#     still pinned while the client reconnects to it. Saved profiles get no
#     such lease: deleting one still revokes its pin in the same pass.
#   - Kernel WireGuard tunnels that NO NetworkManager profile describes
#     (wg-quick, Mullvad's own daemon, systemd-networkd) are read from the
#     kernel itself. NetworkManager does reflect such a device: it assumes it
#     behind a profile it invents and emits up/down with CONNECTION_EXTERNAL=1,
#     measured on the installed image. That reflection is not a management
#     contract though -- it can be released again at any time -- so the udev
#     net/add rule with DEVTYPE=wireguard stays the trigger, and nothing may
#     write to the profile NetworkManager invented for it. The endpoint is
#     readable before the first handshake, so it can be pinned in time.
#     Discovery pins but never arms: arming narrows connectivity and stays an
#     explicit or NM-confirmed decision.
#   - Dynamic clients that create their VPN profile only after probing an
#     endpoint may temporarily Reapply a single-host route to the physical
#     connection. The no-wait reapply hook admits only the current applied-vs-
#     persistent /32 or /128 delta, only while a software dummy default route
#     is active, only for local TCP/UDP, and for at most 60 seconds. It never
#     opens grace, persists data or permits forwarded traffic.
#   - The path-unit must NOT carry After/Wants=NetworkManager.service —
#     that creates a basic.target ordering cycle via paths.target; inotify
#     works without network. The triggered SERVICE keeps the NM ordering.
#   - bypass_grace_v4 holds 0.0.0.0/0 only before the first committed strict
#     state or after explicit pause/reset. The armed flag prevents an empty or
#     expired endpoint set, clean disconnect, crash, carrier loss or reboot from
#     silently reopening grace after strict activation.
#   - Saved profile data never arms the boundary by itself. Only the supported
#     tunnel-up runtime path creates the durable armed marker plus a volatile
#     active-tunnel proof. Tunnel-down removes only that volatile proof; only an
#     explicit pause/reset/disable operation can relax the durable boundary.
#   - Provider-owned kill-switch profiles, sentinel DNS and lifecycle remain
#     provider-owned. In particular, Proton's current backend deliberately
#     creates dummy sink profiles with 0.0.0.0/::1 DNS. A NetworkManager
#     dispatcher must not rewrite or down/up those profiles: normal dispatcher
#     scripts are serialized and queued events can already be stale, so
#     self-mutation races the provider and stalls unrelated network events.
#   - WireGuard MTU correction therefore never writes, saves, reactivates or
#     otherwise persists a provider/user profile. The awaited tunnel pre-up
#     path and parallel physical-change path derive a ceiling from every
#     current peer route, lower only the live kernel link, retain an already
#     safer value, reject incomplete evidence and preserve IPv6's 1280-byte
#     floor. A provider reconnect naturally reruns the same event calculation.
#   - M06 deliberately has NO health stamp — it uses the
#     multi-component STEP 8 verify-block instead; M99 EXPECTED_STAMPS
#     excludes M06.
#   - nft -c inside the Anaconda %post chroot ALWAYS false-negatives (no
#     netfilter namespace) — verify-blocks must probe `nft list tables`
#     first and INFO-skip in the chroot.
#
# Cross-reference:
#   - Module 02: rp_filter=1 + src_valid_mark=1 sysctl pair (fwmark-tunneled
#     traffic exempt from strict reverse-path validation)
#   - Module 03: block-lan-out (LAN egress) — this module covers WAN egress
#   - Module 04: dispatcher mode 700 baseline consistency
#
# References: ProtonVPN GitHub issue #130 (interface-bind bypass, no
# upstream fix) · ProtonVPN python-proton-vpn-api-core kill-switch backend ·
# NetworkManager-dispatcher(8) · WireGuard FAQ "rp_filter and fwmark" ·
# Privacy Guides community (Linux killswitch + IP leakage).
# ============================================================================

%packages --exclude-weakdeps
# Explicit runtime dependencies of the libnm endpoint controller. Both are
# Fedora-main packages; the controller never installs or downloads code.
NetworkManager-libnm
python3-gobject
%end

%post --erroronfail --log=/var/log/ks-06-vpn-killswitch.log
set -euo pipefail
umask 077

log() { echo "[noid-06-vpn]" "$@"; }
log "=== Module 06 post-install: VPN zone-enforce + WAN-egress-strict dispatchers + toggle CLI + scan-profiles ==="

# ====================================================================
# STEP 1: Install NM dispatcher — enforce zone=noid-vpn for VPN ifaces
# ====================================================================
# Triggered at every interface-up event. Filters:
#   - skip physical (they stay in drop zone)
#   - skip controller ports (for example Libvirt TAPs enslaved to virbr0)
#   - skip lo, virbr*, docker*, veth*, br*, pvpnks* (non-VPN virtuals)
#   - require an NM VPN/tunnel connection type; do not trust arbitrary virtual
#     interfaces merely because they lack a physical `/sys/.../device`
#
# Double action for robustness without taking ownership of a provider profile:
#   (a) firewall-cmd --change-interface = runtime effect, takes effect now
#   (b) nmcli con mod --temporary = mirror the zone in NetworkManager without
#       changing an unsaved/volatile profile into an on-disk autoconnect file.
# The dispatcher runs for every activation, so persistent user-owned profiles
# also receive the runtime zone without NoID Privacy rewriting durable intent.
mkdir -p /etc/NetworkManager/dispatcher.d/pre-up.d
cat > /etc/NetworkManager/dispatcher.d/50-vpn-zone-enforce << 'DISPATCHER_EOF'
#!/bin/bash
#
# NoID Privacy — enforce connection.zone=noid-vpn for VPN interfaces
# Module 06 — see the design-constraints block in the module header.
#
# Problem: VPN clients (Proton, Mullvad, etc.) create NM profiles via D-Bus
# without setting connection.zone, OR with explicit connection.zone=drop /
# vendor-specific value. Module 03 has no NM default to fall back on
# (NM 1.54+ rejects connection.zone in connection-defaults sections;
# M03 acknowledged this — see /etc/NetworkManager/conf.d/03-vpn-zone.conf
# placeholder). Without enforcement here, VPN interfaces would land in the
# default 'drop' zone (firewalld DefaultZone=drop), and block-lan-out policy
# would drop VPN-internal traffic (Proton DNS 10.2.0.1, Mullvad DNS 10.64.x.x,
# native WireGuard endpoints) → broken VPN.
#
# Solution: on every interface-up event, if the active NM connection is a
# VPN/tunnel type and its zone is not already `noid-vpn`, enforce it via
# firewall-cmd (runtime) and an explicitly temporary NM profile update.
#
# Filters out:
#   - physical interfaces (have /sys/class/net/<iface>/device symlink)
#   - controller ports (have a kernel master or NM controller/port metadata)
#   - lo, virbr*, docker*, veth*, br*, pvpnks* (non-VPN virtual interfaces)
#
# Accepted NM connection types: vpn, wireguard, tun and ip-tunnel.
#

IFACE="${1:-}"
ACTION="${2:-}"

# Process normal tunnel links and VPN-plugin events.
case "$ACTION" in
    pre-up|up|vpn-pre-up|vpn-up) ;;
    *) exit 0 ;;
esac

# Skip physical interfaces - they stay in drop zone
[ -d "/sys/class/net/$IFACE/device" ] && exit 0

# A controller port carries its controller's traffic; it is not a standalone
# tunnel. This rejects externally created Libvirt TAPs even though
# NetworkManager represents a TAP with connection.type=tun.
if [ -e "/sys/class/net/$IFACE/master" ]; then
    logger -t noid-vpn-zone "refused controller port $IFACE"
    exit 0
fi

# Skip known non-VPN virtual interfaces
# Skip-list extended for bond/vlan/macsec
# false-positive prevention. NoID Privacy image target users rarely run
# enterprise link-aggregation (bond) or VLAN tagging, but if they do,
# auto-zoning to `noid-vpn` would be wrong (those carry physical traffic).
# Never trust or reject an `ipsec*` name by itself. The stock image does not
# support IPsec/IKEv2 and M21 denies its ESP transforms, but an owner may
# deliberately replace that policy and install another NetworkManager plugin.
# Such an interface must still pass the explicit NM-type gate below. That only
# grants the inbound-DROP VPN zone; it does not add a WAN-strict endpoint schema
# or turn the owner-modified path into a NoID Privacy-tested VPN protocol.
# vlan-tag pattern eth0.100/wlan0.42 matched via shell glob *.[0-9]*
case "$IFACE" in
    lo|virbr*|docker*|veth*|br*|pvpnks*) exit 0 ;;
    bond*|vlan*|macsec*) exit 0 ;;
    *.[0-9]|*.[0-9][0-9]|*.[0-9][0-9][0-9]|*.[0-9][0-9][0-9][0-9]) exit 0 ;;
esac

# Look up NM connection UUID for this active device
UUID="${CONNECTION_UUID:-}"
if [ -z "$UUID" ]; then
    UUID=$(nmcli -t -f UUID,DEVICE con show --active 2>/dev/null \
        | awk -F: -v d="$IFACE" '$2==d {print $1; exit}')
fi
[ -n "$UUID" ] || exit 0

# NetworkManager may learn an externally created controller port before the
# kernel master symlink is visible to this event. Reject its durable profile
# metadata as an independent fail-closed check.
PORT_TYPE=$(nmcli -g connection.port-type con show "$UUID" 2>/dev/null)
CONTROLLER=$(nmcli -g connection.controller con show "$UUID" 2>/dev/null)
if [ -n "$PORT_TYPE" ] || [ -n "$CONTROLLER" ]; then
    logger -t noid-vpn-zone "refused controller port $IFACE"
    exit 0
fi

# A virtual interface is not automatically trustworthy. Require an explicit
# NetworkManager VPN/tunnel type so bridges, containers and future virtual
# device kinds cannot be promoted to the VPN zone by a naming gap.
CONNECTION_TYPE=$(nmcli -g connection.type con show "$UUID" 2>/dev/null)
case "$CONNECTION_TYPE" in
    vpn|wireguard|tun|ip-tunnel) ;;
    *)
        logger -t noid-vpn-zone "refused non-VPN connection type ${CONNECTION_TYPE:-unknown} on $IFACE"
        exit 0
        ;;
esac

# Check current zone
CURRENT_ZONE=$(nmcli -g connection.zone con show "$UUID" 2>/dev/null)
RUNTIME_ZONE=$(firewall-cmd --get-zone-of-interface="$IFACE" 2>/dev/null || true)

# Fast path only when both NetworkManager's profile view and live firewalld
# state agree. Trusting the profile alone could leave an interface in a stale
# permissive runtime zone.
if [ "$CURRENT_ZONE" = "noid-vpn" ] && [ "$RUNTIME_ZONE" = "noid-vpn" ]; then
    exit 0
fi

# Apply immediately to the live interface. `--permanent` alone would not
# change runtime state and would leave the current tunnel in the wrong zone.
if ! firewall-cmd --zone=noid-vpn --change-interface="$IFACE" >/dev/null 2>&1; then
    logger -t noid-vpn-zone "FAILED runtime zone=noid-vpn on $IFACE"
    exit 1
fi

# NetworkManager also assumes a tunnel created outside itself — wg-quick, or a
# provider daemon that builds its own kernel device — and represents it with a
# profile it invented. Updating that profile makes NetworkManager release the
# device: it drops from activated to unmanaged-external-down and takes the
# address its creator installed with it. Measured on the installed image, the
# device is released 1.6 ms after the update and about a second after the
# tunnel appeared, so the handshake completes and nothing carries traffic
# afterwards.
#
# NetworkManager-dispatcher(8) states the ownership directly: CONNECTION_EXTERNAL
# is "1" when the connection describes a network configuration created outside
# of NetworkManager. Gate on that, not on where the profile happens to sit --
# NetworkManager keeps its own WireGuard and VPN-plugin profiles under /run
# too, so a path test would skip the mirror for every tunnel and silently drop
# the bookkeeping it exists to do. The firewalld change above is the actual
# enforcement and holds either way.
if [ "${CONNECTION_EXTERNAL:-0}" = 1 ]; then
    logger -t noid-vpn-zone \
        "enforced zone=noid-vpn on $IFACE (was: ${CURRENT_ZONE:-unset}); externally created tunnel, NetworkManager mirror skipped"
    exit 0
fi

# Mirror the zone only in NetworkManager's runtime copy. An unqualified
# `connection modify` persists profiles by default and turns provider-created
# save_to_disk=False tunnels into stale autoconnect files under /etc.
if ! nmcli con mod --temporary "$UUID" connection.zone noid-vpn 2>/dev/null; then
    logger -t noid-vpn-zone "FAILED temporary zone=noid-vpn for $IFACE"
    exit 1
fi

logger -t noid-vpn-zone "enforced zone=noid-vpn on $IFACE (was: ${CURRENT_ZONE:-unset})"
DISPATCHER_EOF

# Mode 700 root:root — uniform baseline across all NoID Privacy NM
# dispatchers (M04 convention; simplifies audit reasoning).
chmod 700 /etc/NetworkManager/dispatcher.d/50-vpn-zone-enforce
chown root:root /etc/NetworkManager/dispatcher.d/50-vpn-zone-enforce
# NetworkManager only runs pre-up/vpn-pre-up hooks from pre-up.d. Keep the
# normal root entry for up/vpn-up and symlink the same audited script here.
ln -sfn ../50-vpn-zone-enforce \
    /etc/NetworkManager/dispatcher.d/pre-up.d/50-vpn-zone-enforce
log "STEP 1: /etc/NetworkManager/dispatcher.d/50-vpn-zone-enforce installed"

# ====================================================================
# STEP 2: Install nft-table /etc/nftables.d/noid-wan-strict.nft
# ====================================================================
# Defines table inet noid_wan_strict with sets vpn_endpoints_v4 / _v6 +
# bypass_grace_v4. Loaded at boot by noid-wan-strict.service (STEP 4) and
# populated by 60-vpn-endpoint-pin dispatcher (STEP 5) on VPN-up events.
# Priority -5 = runs BEFORE firewalld at +10, so noid_wan_strict drops
# public-IP-egress on physical NICs before firewalld block-lan-out gets
# the packet.
mkdir -p /etc/nftables.d
cat > /etc/nftables.d/noid-wan-strict.nft <<'NFT_EOF'
#!/usr/sbin/nft -f
#
# NoID Privacy — WAN egress strict (Module 06)
# Covers the host-L3 SO_BINDTODEVICE / --interface route-bypass class beyond
# a provider default-route killswitch. Applications using ordinary IPv4/IPv6
# sockets can select a physical NIC and skip that default route. In STRICT
# modes this table drops such egress on physical NICs outside:
#   - local-address ranges passed onward to the independent LAN deny layer
#   - reconciled durable VPN endpoints and bounded handshake candidates
#   - non-physical interfaces (not matched by @physical_ifaces; no fragile
#     tunnel-name allowlist)
# It does not claim AF_PACKET/link-layer, privileged network-control,
# separately controlled namespace/device or firmware coverage.
#
# State management:
#   - sets vpn_endpoints_v4 / vpn_endpoints_v6 contain reconciled durable state
#   - sets vpn_candidates_v4 / vpn_candidates_v6 contain timeout-bounded DNS
#     answers for the handshake only; they are never persisted
#   - sets vpn_bootstrap_routes_v4 / vpn_bootstrap_routes_v6 contain only
#     transient single-host routes applied by a VPN client while a software
#     default-route killswitch is active; they expire in the kernel
#   - bootstrap service noid-wan-strict.service re-populates from
#     /var/lib/noid-privacy/wan-strict-endpoints.txt at boot
#   - bypass_grace_v4 holds 0.0.0.0/0 only before first explicit arming/reset;
#     the armed marker prevents deletion/expiry from silently reopening it
#
# Reference:
#   - ProtonVPN issue #130 (long-known, no upstream fix)
#   - netfilter nftables hook semantics; Linux packet(7)/capabilities(7)
#
# Priority: filter - 5 = -5 (BEFORE firewalld at +10), so this drops first.

table inet noid_wan_strict {
    set physical_ifaces {
        type ifname
        comment "Physical network interfaces; populated before NetworkManager"
    }

    set vpn_endpoints_v4 {
        type ipv4_addr . inet_proto . inet_service
        flags timeout
        comment "Reconciled VPN endpoint IPv4 + transport + port"
    }

    set vpn_endpoints_v6 {
        type ipv6_addr . inet_proto . inet_service
        flags timeout
        comment "Reconciled VPN endpoint IPv6 + transport + port"
    }

    set vpn_candidates_v4 {
        type ipv4_addr . inet_proto . inet_service
        flags timeout
        timeout 2m
        comment "Unauthenticated DNS handshake candidates; never persistent"
    }

    set vpn_candidates_v6 {
        type ipv6_addr . inet_proto . inet_service
        flags timeout
        timeout 2m
        comment "Unauthenticated DNS handshake candidates; never persistent"
    }

    set vpn_bootstrap_routes_v4 {
        type ipv4_addr . inet_proto
        flags timeout
        timeout 1m
        comment "Transient VPN bootstrap host routes; local TCP/UDP only"
    }

    set vpn_bootstrap_routes_v6 {
        type ipv6_addr . inet_proto
        flags timeout
        timeout 1m
        comment "Transient VPN bootstrap host routes; local TCP/UDP only"
    }

    set bypass_grace_v4 {
        type ipv4_addr
        flags interval
        auto-merge
        comment "Bootstrap-grace: only before first arming or explicit reset"
    }

    set lan_exceptions_v4 {
        type ipv4_addr
        flags interval
        auto-merge
        comment "Exact approved peers or connected prefixes in explicit global LAN mode"
    }

    set lan_exceptions_v6 {
        type ipv6_addr
        flags interval
        auto-merge
        comment "Exact approved peers or connected prefixes in explicit global LAN mode"
    }

    set lan_inbound_peers_v4 {
        type ipv4_addr
        flags interval
        auto-merge
        comment "Inbound-only/both peers; only conntrack-correlated host replies pass onward"
    }

    counter wan_blocked_v4 { }
    counter wan_blocked_v6 { }
    counter wan_passed_v4 { }
    counter wan_passed_v6 { }

    chain output {
        type filter hook output priority -5; policy accept;

        # Every restriction below is scoped to a dynamically populated set of
        # real hardware-backed network interfaces. Arbitrarily named genuine
        # tunnels and other virtual links therefore remain provider-neutral.

        # Bootstrap-grace passthrough (set holds 0.0.0.0/0 only during initial
        # fresh-install setup; removed on first committed strict state)
        oifname @physical_ifaces ip daddr @bypass_grace_v4 accept

        # Per-IP LAN opt-ins are mirrored transactionally from M05/M03. This
        # must precede the physical-WAN drops so unusual/public on-link IPv4
        # and global IPv6 peers can reach the later topology/firewalld gates.
        oifname @physical_ifaces ct state established,related \
            ip daddr @lan_inbound_peers_v4 accept
        oifname @physical_ifaces ip daddr @lan_exceptions_v4 accept
        oifname @physical_ifaces ip6 daddr @lan_exceptions_v6 accept

        # Local-address ranges continue to M03's later LAN deny hooks. These
        # accepts do not create a final LAN application-data exception.
        oifname @physical_ifaces ip daddr 192.168.0.0/16 accept
        oifname @physical_ifaces ip daddr 10.0.0.0/8 accept
        oifname @physical_ifaces ip daddr 172.16.0.0/12 accept
        oifname @physical_ifaces ip daddr 169.254.0.0/16 accept
        oifname @physical_ifaces ip daddr 100.64.0.0/10 accept
        oifname @physical_ifaces ip daddr 255.255.255.255 accept
        oifname @physical_ifaces ip daddr 224.0.0.0/4 accept

        # IPv6 link-local + ULA + multicast + loopback
        oifname @physical_ifaces ip6 daddr fe80::/10 accept
        oifname @physical_ifaces ip6 daddr fc00::/7 accept
        oifname @physical_ifaces ip6 daddr ff00::/8 accept

        # Resolver egress is process-scoped rather than a general DNS tuple
        # exception. This lets systemd-resolved obtain bounded hostname
        # candidates while other processes remain unable to use direct DNS.
        oifname @physical_ifaces meta skuid "systemd-resolve" \
            meta l4proto { tcp, udp } th dport 53 accept
        oifname @physical_ifaces meta skuid "systemd-resolve" \
            meta l4proto tcp th dport 853 accept

        # Reconciled exact VPN tuples and short-lived hostname handshake
        # candidates. Address alone is never a general WAN exception.
        oifname @physical_ifaces \
            ip daddr . meta l4proto . th dport @vpn_endpoints_v4 \
            counter name wan_passed_v4 accept
        oifname @physical_ifaces \
            ip6 daddr . meta l4proto . th dport @vpn_endpoints_v6 \
            counter name wan_passed_v6 accept
        oifname @physical_ifaces \
            ip daddr . meta l4proto . th dport @vpn_candidates_v4 \
            counter name wan_passed_v4 accept
        oifname @physical_ifaces \
            ip6 daddr . meta l4proto . th dport @vpn_candidates_v6 \
            counter name wan_passed_v6 accept

        # Some dynamic clients first install a non-persistent single-host
        # route through the physical gateway while their own software default
        # killswitch is active, then probe the server before creating the VPN
        # profile. The controller admits only that runtime-vs-disk delta for
        # one minute. This exception is local-output-only and address+transport
        # scoped; it never opens grace or forwarded traffic.
        oifname @physical_ifaces \
            ip daddr . meta l4proto @vpn_bootstrap_routes_v4 \
            counter name wan_passed_v4 accept
        oifname @physical_ifaces \
            ip6 daddr . meta l4proto @vpn_bootstrap_routes_v6 \
            counter name wan_passed_v6 accept

        # Drop everything else egressing on real hardware. Counters retain
        # diagnostics without writing destination metadata into the journal.
        oifname @physical_ifaces meta nfproto ipv4 \
            counter name wan_blocked_v4 drop
        oifname @physical_ifaces meta nfproto ipv6 \
            counter name wan_blocked_v6 drop
    }

    # VM and privileged-container bridges traverse forward rather than output.
    # Give them the identical physical-WAN boundary so a bridge/NAT path cannot
    # bypass strict mode. Traffic routed through a virtual VPN interface does
    # not match @physical_ifaces and remains provider-neutral.
    chain forward {
        type filter hook forward priority -5; policy accept;

        oifname @physical_ifaces ip daddr @bypass_grace_v4 accept
        oifname @physical_ifaces ip daddr @lan_exceptions_v4 accept
        oifname @physical_ifaces ip6 daddr @lan_exceptions_v6 accept

        # M03's later topology/firewalld hooks enforce the actual LAN block.
        oifname @physical_ifaces ip daddr 192.168.0.0/16 accept
        oifname @physical_ifaces ip daddr 10.0.0.0/8 accept
        oifname @physical_ifaces ip daddr 172.16.0.0/12 accept
        oifname @physical_ifaces ip daddr 169.254.0.0/16 accept
        oifname @physical_ifaces ip daddr 100.64.0.0/10 accept
        oifname @physical_ifaces ip daddr 255.255.255.255 accept
        oifname @physical_ifaces ip daddr 224.0.0.0/4 accept
        oifname @physical_ifaces ip6 daddr fe80::/10 accept
        oifname @physical_ifaces ip6 daddr fc00::/7 accept
        oifname @physical_ifaces ip6 daddr ff00::/8 accept

        oifname @physical_ifaces \
            ip daddr . meta l4proto . th dport @vpn_endpoints_v4 \
            counter name wan_passed_v4 accept
        oifname @physical_ifaces \
            ip6 daddr . meta l4proto . th dport @vpn_endpoints_v6 \
            counter name wan_passed_v6 accept
        oifname @physical_ifaces \
            ip daddr . meta l4proto . th dport @vpn_candidates_v4 \
            counter name wan_passed_v4 accept
        oifname @physical_ifaces \
            ip6 daddr . meta l4proto . th dport @vpn_candidates_v6 \
            counter name wan_passed_v6 accept

        oifname @physical_ifaces meta nfproto ipv4 \
            counter name wan_blocked_v4 drop
        oifname @physical_ifaces meta nfproto ipv6 \
            counter name wan_blocked_v6 drop
    }
}
NFT_EOF
chmod 644 /etc/nftables.d/noid-wan-strict.nft
chown root:root /etc/nftables.d/noid-wan-strict.nft
log "STEP 2: /etc/nftables.d/noid-wan-strict.nft installed"

# The controller serializes every transition on a no-follow root-private lock.
# Pre-create that file before systemd constructs its read-only service
# namespace; also create the exact root-private directory for volatile
# authenticated-tunnel evidence.
mkdir -p /etc/tmpfiles.d
cat > /etc/tmpfiles.d/noid-wan-strict.conf <<'WAN_TMPFILES_EOF'
# NoID Privacy — M06 private runtime transaction/evidence paths
f /run/lock/noid-wan-strict.lock 0600 root root -
f /run/lock/noid-wireguard-mtu.lock 0600 root root -
d /run/noid-privacy/wan-strict-active 0700 root root -
WAN_TMPFILES_EOF
chmod 0644 /etc/tmpfiles.d/noid-wan-strict.conf
chown root:root /etc/tmpfiles.d/noid-wan-strict.conf
systemd-tmpfiles --create /etc/tmpfiles.d/noid-wan-strict.conf
log "STEP 2a: M06 runtime lock/evidence paths installed"

# Single machine-readable runtime status contract for CLIs and the unprivileged
# Network GUI. Root recomputes it from the actual nft table, pause timer,
# endpoint state and explicit disable flag after every supported transition.
cat > /usr/local/sbin/noid-wan-strict-publish-status <<'WAN_STATUS_EOF'
#!/bin/bash
# Compatibility wrapper. The libnm controller takes the shared no-follow lock,
# derives mode from committed nft/flag/failure state, and atomically publishes.
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
if [ "$#" -ne 0 ]; then
    echo "noid-wan-strict-publish-status: no arguments accepted" >&2
    exit 2
fi
[ "$(id -u)" -eq 0 ] || { echo "status publisher requires root" >&2; exit 1; }
exec /usr/local/libexec/noid-wan-strict-endpoints publish-status
WAN_STATUS_EOF
chmod 0755 /usr/local/sbin/noid-wan-strict-publish-status
chown root:root /usr/local/sbin/noid-wan-strict-publish-status
log "STEP 2b: machine-readable WAN status publisher installed"

# One maintained profile/runtime authority for every WAN endpoint transition.
# Production reads NetworkManager's already-loaded profiles through libnm;
# fixture directories are accepted only through an explicit test override and
# are parsed by libnm's own keyfile reader, never by section-blind text greps.
mkdir -p /usr/local/libexec
cat > /usr/local/libexec/noid-wan-strict-endpoints <<'ENDPOINT_ENGINE_EOF'
#!/usr/bin/python3
"""Reconcile WAN-strict VPN endpoints from libnm and authenticated runtime state."""

from __future__ import annotations

import argparse
import dataclasses
import fcntl
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import shlex
import socket
import stat
import subprocess
import sys
import tempfile
import time
import uuid as uuidlib

import gi

gi.require_version("NM", "1.0")
from gi.repository import Gio, GLib, NM  # noqa: E402

HEADER = "NOID-WAN-ENDPOINTS-V2"
TABLE = "inet noid_wan_strict"
ARMED_CONTENT = b"NOID_WAN_STRICT_ARMED_V1\n"
DISABLED_CONTENT = b"NOID_WAN_STRICT_DISABLED_V1\n"
FAILED_CONTENT = b""
READY_CONTENT = b"NOID_GATEWAY_XDP_READY_V1\n"
STATE = pathlib.Path(os.environ.get(
    "NOID_WAN_STRICT_STATE_FILE",
    "/var/lib/noid-privacy/wan-strict-endpoints.txt",
))
ARMED = pathlib.Path(os.environ.get(
    "NOID_WAN_STRICT_ARMED_FILE",
    "/var/lib/noid-privacy/wan-strict-armed.flag",
))
DISABLED = pathlib.Path(os.environ.get(
    "NOID_WAN_DISABLED_FILE", "/var/lib/noid-privacy/wan-strict-disabled.flag"
))
FAILED = pathlib.Path(os.environ.get(
    "NOID_WAN_FAILED_FILE", "/run/noid-privacy/wan-strict-bootstrap.failed"
))
STATUS = pathlib.Path(os.environ.get(
    "NOID_WAN_STATUS_FILE", "/run/noid-privacy/wan-strict-status"
))
NETWORK_READY = pathlib.Path(os.environ.get(
    "NOID_NETWORK_READY_FILE", "/run/noid-privacy/gateway-xdp.ready"
))
POLICY = pathlib.Path(os.environ.get(
    "NOID_WAN_POLICY_FILE", "/etc/nftables.d/noid-wan-strict.nft"
))
LOCK = pathlib.Path(os.environ.get(
    "NOID_WAN_STRICT_LOCK_FILE",
    "/run/lock/noid-wan-strict.lock",
))
ACTIVE_DIR = pathlib.Path(os.environ.get(
    "NOID_WAN_ACTIVE_DIR", "/run/noid-privacy/wan-strict-active"
))
TEST_MODE = os.environ.get("NOID_WAN_STRICT_TEST_MODE") == "1"


def command_path(test_name: str, production_path: str) -> list[str]:
    if TEST_MODE:
        return shlex.split(os.environ.get(test_name, production_path))
    return [production_path]


NFT = command_path("NOID_NFT_BIN", "/usr/bin/nft")
WG = command_path("NOID_WG_BIN", "/usr/bin/wg")
SYSTEMCTL = command_path("NOID_SYSTEMCTL_BIN", "/usr/bin/systemctl")
CANDIDATE_TTL = int(os.environ.get("NOID_WAN_CANDIDATE_TTL", "120"))
BOOTSTRAP_TTL = int(os.environ.get("NOID_WAN_BOOTSTRAP_TTL", "60"))
AUTH_TTL = int(os.environ.get("NOID_WAN_AUTH_TTL", "86400"))
# Upper bound on simultaneously live retention leases. Clients that keep their
# profile only in runtime state create a NEW profile with a NEW UUID per server,
# so without a cap a day of server hopping would leave one open tuple per server
# visited. The newest leases win; the same bound of eight already limits
# transient bootstrap routes and unmanaged tunnel enumeration.
RETAIN_MAX = int(os.environ.get("NOID_WAN_RETAIN_MAX", "8"))
# Kernel WireGuard tunnels that no NetworkManager profile describes.
WG_MAX_INTERFACES = int(os.environ.get("NOID_WAN_WG_MAX_INTERFACES", "8"))
WG_MAX_PEERS = int(os.environ.get("NOID_WAN_WG_MAX_PEERS", "8"))
WG_HANDSHAKE_MAX_AGE = 180
# A tunnel NetworkManager does not manage has no profile UUID, but durable
# state is keyed by one, so it gets a deterministic UUIDv5 of its peer public
# key. The key is the identity, not the interface name: wg-quick takes the name
# from a file name and other clients rename their interface between versions,
# while the peer key is the server's cryptographic identity and is exactly what
# the kernel enforces.
RUNTIME_NAMESPACE = uuidlib.uuid5(
    uuidlib.NAMESPACE_DNS, "runtime-tunnel.wan-strict.noid-privacy.invalid"
)
PEER_KEY = re.compile(r"[A-Za-z0-9+/]{43}=")
LOCK_TIMEOUT = (
    float(os.environ.get("NOID_TEST_LOCK_TIMEOUT", "30"))
    if TEST_MODE else 30.0
)
SKIP_STATUS = TEST_MODE and os.environ.get("NOID_TEST_SKIP_STATUS") == "1"


class EndpointError(RuntimeError):
    """Closed-contract validation or publication failure."""


class LockTimeout(EndpointError):
    """The bounded endpoint transaction-lock deadline expired."""


@dataclasses.dataclass(frozen=True, order=True)
class Endpoint:
    profile_uuid: str
    fingerprint: str
    kind: str
    host: str
    proto: str
    port: int
    peer_key: str = "-"
    identity_ok: bool = False


@dataclasses.dataclass(frozen=True, order=True)
class Record:
    profile_uuid: str
    fingerprint: str
    source: str
    proto: str
    address: str
    port: int
    expires: int


def fail(message: str) -> EndpointError:
    return EndpointError(message)


def expected_identity() -> tuple[int, int]:
    if TEST_MODE:
        return os.geteuid(), os.getegid()
    return 0, 0


def trusted_directory(path: pathlib.Path, label: str, *,
                      create_mode: int | None = None,
                      exact_mode: int | None = None) -> os.stat_result:
    if create_mode is not None:
        created = False
        try:
            path.mkdir(mode=create_mode, parents=True, exist_ok=False)
            created = True
        except FileExistsError:
            pass
        except OSError as exc:
            raise fail(f"cannot create {label} directory") from exc
        if created:
            try:
                os.chmod(path, create_mode, follow_symlinks=False)
            except OSError as exc:
                raise fail(f"cannot set {label} directory mode") from exc
    try:
        info = path.lstat()
    except OSError as exc:
        raise fail(f"cannot inspect {label} directory") from exc
    expected_uid, expected_gid = expected_identity()
    mode = stat.S_IMODE(info.st_mode)
    if (not stat.S_ISDIR(info.st_mode)
            or info.st_uid != expected_uid or info.st_gid != expected_gid
            or mode & 0o022
            or (exact_mode is not None and mode != exact_mode)):
        raise fail(f"{label} directory metadata mismatch")
    return info


def exact_file_present(path: pathlib.Path, label: str, mode: int,
                       content: bytes) -> bool:
    try:
        path_info = path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise fail(f"cannot inspect {label}") from exc
    expected_uid, expected_gid = expected_identity()
    if (not stat.S_ISREG(path_info.st_mode) or path_info.st_nlink != 1
            or path_info.st_uid != expected_uid
            or path_info.st_gid != expected_gid
            or stat.S_IMODE(path_info.st_mode) != mode):
        raise fail(f"{label} metadata mismatch")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (path_info.st_dev, path_info.st_ino):
            raise fail(f"{label} identity changed while opening")
        data = os.read(fd, len(content) + 1)
    except OSError as exc:
        raise fail(f"cannot read {label}") from exc
    finally:
        if "fd" in locals():
            os.close(fd)
    if data != content:
        raise fail(f"{label} content mismatch")
    return True


def read_owned_regular_text(path: pathlib.Path, label: str, mode: int) -> str:
    trusted_directory(path.parent, f"{label} parent")
    try:
        path_info = path.lstat()
    except OSError as exc:
        raise fail(f"cannot inspect {label}") from exc
    expected_uid, expected_gid = expected_identity()
    if (not stat.S_ISREG(path_info.st_mode) or path_info.st_nlink != 1
            or path_info.st_uid != expected_uid
            or path_info.st_gid != expected_gid
            or stat.S_IMODE(path_info.st_mode) != mode):
        raise fail(f"{label} metadata mismatch")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    fd = -1
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "r", encoding="utf-8", newline="") as stream:
            fd = -1
            opened = os.fstat(stream.fileno())
            if ((opened.st_dev, opened.st_ino) !=
                    (path_info.st_dev, path_info.st_ino)):
                raise fail(f"{label} identity changed while opening")
            if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                    or opened.st_uid != expected_uid
                    or opened.st_gid != expected_gid
                    or stat.S_IMODE(opened.st_mode) != mode):
                raise fail(f"opened {label} metadata mismatch")
            return stream.read()
    except (OSError, UnicodeError) as exc:
        raise fail(f"cannot read {label}") from exc
    finally:
        if fd >= 0:
            os.close(fd)


def canonical_uuid(value: str) -> str:
    try:
        parsed = str(uuidlib.UUID(value))
    except (ValueError, AttributeError) as exc:
        raise fail("invalid profile UUID") from exc
    if parsed != value.lower():
        raise fail("non-canonical profile UUID")
    return parsed


def canonical_ip(value: str) -> str:
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as exc:
        raise fail("invalid endpoint address") from exc
    if parsed.is_unspecified or parsed.is_multicast or parsed.is_loopback:
        raise fail("unsafe endpoint address class")
    canonical = str(parsed)
    if canonical != value:
        raise fail("non-canonical endpoint address")
    return canonical


def split_endpoint(raw: str, default_port: int | None) -> tuple[str, int, str | None]:
    value = raw.strip().strip('"')
    if not value or any(ch.isspace() for ch in value):
        raise fail("empty or whitespace-bearing endpoint")
    # NetworkManager-openvpn documents an optional transport suffix in the
    # Gateway field: its tooltip reads "Remote gateway(s), with optional port
    # and protocol (e.g. ovpn.corp.com:1234:tcp)". Strip it before the
    # host/port split, which otherwise rejects the whole profile. The token is
    # unambiguous against a bare IPv6 literal because t, p and u are not hex
    # digits, so no valid address can end in :tcp or :udp.
    transport_proto = None
    transport = re.search(r":(?:tcp|udp)[46]?$", value, re.IGNORECASE)
    if transport:
        transport_proto = transport.group(0)[1:4].lower()
        value = value[:transport.start()]
        if not value:
            raise fail("endpoint carries a transport but no host")
    host = value
    port = default_port
    match = re.fullmatch(r"\[([^]]+)](?::([0-9]+))?", value)
    if match:
        host = match.group(1)
        port = int(match.group(2)) if match.group(2) else default_port
    else:
        try:
            host = str(ipaddress.ip_address(value))
        except ValueError:
            match = re.fullmatch(r"([^:]+):([0-9]+)", value)
            if match:
                host, port = match.group(1), int(match.group(2))
    if port is None or not 1 <= int(port) <= 65535:
        raise fail("endpoint has no valid destination port")
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        try:
            host = host.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise fail("invalid endpoint hostname") from exc
        if not host or len(host) > 253 or not re.fullmatch(
            r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host
        ):
            raise fail("invalid endpoint hostname")
    return host, int(port), transport_proto


def endpoint_fingerprint(*parts: str) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part.encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


def vpn_value(setting: NM.SettingVpn, name: str) -> str:
    return (setting.get_data_item(name) or "").strip()


def endpoint_from_connection(connection: NM.Connection) -> list[Endpoint]:
    profile_uuid = canonical_uuid(connection.get_uuid())
    connection_type = connection.get_connection_type()
    result: list[Endpoint] = []
    if connection_type == "wireguard":
        setting = connection.get_setting_by_name(NM.SETTING_WIREGUARD_SETTING_NAME)
        if setting is None:
            return result
        for index in range(setting.get_peers_len()):
            peer = setting.get_peer(index)
            raw = peer.get_endpoint() or ""
            if not raw:
                continue
            host, port, transport_proto = split_endpoint(raw, None)
            if transport_proto is not None:
                raise fail("WireGuard endpoint carries an OpenVPN transport suffix")
            peer_key = peer.get_public_key() or ""
            if not peer_key:
                raise fail("WireGuard endpoint has no peer public key")
            fingerprint = endpoint_fingerprint(
                profile_uuid, "wireguard", peer_key, host, "udp", str(port)
            )
            result.append(Endpoint(
                profile_uuid, fingerprint, "wireguard", host, "udp", port,
                peer_key, True,
            ))
        return result
    if connection_type != "vpn":
        return result
    setting = connection.get_setting_vpn()
    if setting is None:
        return result
    service_type = setting.get_service_type() or ""
    if not service_type.endswith(".openvpn"):
        return result
    proto_value = (vpn_value(setting, "proto")
                   or vpn_value(setting, "protocol")).lower()
    if vpn_value(setting, "proto-tcp").lower() in {"yes", "true", "1"}:
        proto_value = "tcp"
    if vpn_value(setting, "proto-udp").lower() in {"yes", "true", "1"}:
        proto_value = "udp"
    proto = "tcp" if "tcp" in proto_value else "udp"
    port_text = vpn_value(setting, "port") or vpn_value(setting, "remote-port")
    if port_text and not port_text.isdigit():
        raise fail("OpenVPN destination port is not numeric")
    default_port = int(port_text) if port_text else 1194
    if not 1 <= default_port <= 65535:
        raise fail("OpenVPN destination port out of range")
    remote_text = vpn_value(setting, "remote") or vpn_value(setting, "gateway")
    if not remote_text:
        return result
    ca = vpn_value(setting, "ca")
    identity_option = (
        vpn_value(setting, "remote-cert-tls").lower() == "server"
        or bool(vpn_value(setting, "verify-x509-name"))
        or bool(vpn_value(setting, "tls-remote"))
    )
    identity_ok = bool(ca and identity_option)
    # NetworkManager stores redundant gateways in one `remote` data item and
    # its editor documents "use commas or spaces as delimiters", so whitespace
    # is a first-class separator here, not stray formatting. Splitting on
    # [,;] alone sent a space-separated value straight into split_endpoint's
    # whitespace guard and aborted the entire reconciliation.
    for raw in filter(None, re.split(r"[\s,;]+", remote_text)):
        host, port, endpoint_proto = split_endpoint(raw.strip(), default_port)
        effective_proto = endpoint_proto or proto
        fingerprint = endpoint_fingerprint(
            profile_uuid, service_type, host, effective_proto, str(port), ca,
            vpn_value(setting, "remote-cert-tls"),
            vpn_value(setting, "verify-x509-name"),
            vpn_value(setting, "tls-remote"),
        )
        result.append(Endpoint(
            profile_uuid, fingerprint, "openvpn", host, effective_proto, port, "-",
            identity_ok,
        ))
    return result


def read_keyfile_connection(path: pathlib.Path) -> NM.Connection:
    try:
        keyfile = GLib.KeyFile()
        keyfile.load_from_file(str(path), GLib.KeyFileFlags.NONE)
        connection = NM.keyfile_read(
            keyfile, str(path.parent), NM.KeyfileHandlerFlags.NONE,
            None, None,
        )
    except GLib.Error as exc:
        raise fail("libnm could not read keyfile profile") from exc
    if connection is None:
        raise fail("libnm rejected keyfile profile")
    return connection


def load_connections() -> list[NM.Connection]:
    fixture_dirs = os.environ.get("NOID_NM_PROFILE_DIRS", "").split()
    if fixture_dirs:
        if not TEST_MODE:
            raise fail("fixture profile override is disabled in production")
        connections: list[NM.Connection] = []
        for directory in fixture_dirs:
            for path in sorted(pathlib.Path(directory).glob("*.nmconnection")):
                connections.append(read_keyfile_connection(path))
        return connections
    client = NM.Client.new(None)
    return list(client.get_connections())


def _wg_query(*arguments: str) -> str | None:
    """One `wg show` query. None means there is nothing to enumerate.

    Module 26 ships wireguard-tools, so on a stock image this query answers.
    A host can still lack it -- an image predating that include, or an
    administrator who removed it -- and then there is no kernel WireGuard
    tooling to ask. That is a missing discovery source, not a policy failure,
    so unlike a malformed profile it must never abort the reconciliation
    around it.
    """
    try:
        result = subprocess.run(
            [*WG, "show", *arguments], text=True, capture_output=True,
            timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return result.stdout


def _wg_all_rows(field: str) -> tuple[list[tuple[str, str, str]], int] | None:
    """Parse `wg show all <field>` into (interface, peer key, value) rows.

    Measured against wireguard-tools 1.0.x: exactly three tab-separated fields
    per line, one line per peer, IPv6 endpoints bracketed. Returns the rows plus
    the number of lines that did not match that shape, so a caller can report
    what it ignored instead of silently narrowing its own view.
    """
    listing = _wg_query("all", field)
    if listing is None:
        return None
    rows: list[tuple[str, str, str]] = []
    skipped = 0
    for line in listing.splitlines():
        fields = line.split("\t")
        if len(fields) != 3:
            skipped += 1
            continue
        interface, peer_key, value = fields
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", interface) \
                or not PEER_KEY.fullmatch(peer_key):
            skipped += 1
            continue
        rows.append((interface, peer_key, value))
    return rows, skipped


def runtime_tunnel_endpoints(covered_keys: set[str]) -> list[Endpoint]:
    """Endpoints of kernel WireGuard tunnels that no loaded profile describes.

    wg-quick, Mullvad's own daemon and systemd-networkd configure the kernel
    directly. NetworkManager does notice the device: it assumes it behind a
    profile it invents and emits dispatcher events for it. That profile is not
    a usable source, though -- measured on the installed image it carries the
    peer's public key with `endpoint=None`, and endpoint_from_connection()
    skips a peer with no endpoint -- so nothing in the profile-driven path ever
    learns where the tunnel actually goes. With strict mode armed such a tunnel
    could not complete a handshake at all.

    The endpoint is in the kernel as soon as the interface is configured:
    measured on 2026-08-02, `wg show all endpoints` answers while
    `latest-handshakes` is still 0. It is therefore pinnable before the first
    handshake needs it, which is what makes this a discovery problem rather than
    a chicken-and-egg one.

    The same read covers userspace implementations: `wg` enumerates them through
    their /run/wireguard/<interface>.sock UAPI before falling back to netlink, so
    wireguard-go and boringtun -- the implementations wg-quick itself uses --
    appear in the same listing with the same fields. Verified against a UAPI stub
    speaking the documented protocol.

    Creating or configuring a WireGuard interface requires CAP_NET_ADMIN, and the
    UAPI socket is root-private, so this source is exactly as trustworthy as a
    root-owned NetworkManager profile. Peers a loaded profile already covers are
    skipped, so one tunnel never produces two competing identities.
    """
    parsed = _wg_all_rows("endpoints")
    if parsed is None:
        return []
    rows, skipped = parsed
    discovered: dict[tuple[str, str], Endpoint] = {}
    peers: dict[str, int] = {}
    for interface, peer_key, value in rows:
        if interface not in peers:
            if len(peers) >= WG_MAX_INTERFACES:
                skipped += 1
                continue
            peers[interface] = 0
        if value == "(none)" or peer_key in covered_keys:
            continue
        if peers[interface] >= WG_MAX_PEERS:
            skipped += 1
            continue
        peers[interface] += 1
        try:
            host, port, transport = split_endpoint(value, None)
            if transport is not None:
                raise fail("unmanaged tunnel endpoint carries a transport suffix")
            address = canonical_ip(host)
        except EndpointError:
            skipped += 1
            continue
        profile_uuid = str(uuidlib.uuid5(RUNTIME_NAMESPACE, peer_key))
        fingerprint = endpoint_fingerprint(
            profile_uuid, "wireguard-runtime", peer_key, address, "udp",
            str(port),
        )
        discovered[(profile_uuid, fingerprint)] = Endpoint(
            profile_uuid, fingerprint, "wireguard-runtime", address, "udp",
            port, peer_key, True,
        )
    if skipped:
        print(
            f"noid-wan-strict-endpoints: {skipped} unmanaged WireGuard peer(s) "
            "skipped; their endpoints are NOT pinned and cannot pass WAN-strict",
            file=sys.stderr,
        )
    return sorted(discovered.values())


def runtime_tunnel_leases(endpoints: list[Endpoint], now: int,
                          existing: list[Record]) -> list[Record]:
    """Bounded leases for unmanaged tunnels the kernel says really work.

    An unmanaged tunnel leaves the kernel the moment it is taken down, so
    re-deriving from live state alone unpins its endpoint exactly while the user
    reconnects -- the same gap a volatile NetworkManager profile has, for the
    same reason. A completed handshake is the kernel's own proof that this peer
    answered, which is the identical evidence the profile-backed WireGuard path
    already accepts, so it earns the identical bounded lease.

    The proof arrives after the event that discovered the tunnel: udev fires when
    the interface appears, seconds before its first handshake completes. Measured
    in a VM against a real wg-quick tunnel, the reconciliation triggered by that
    event therefore always saw `latest-handshakes` at 0 and the lease was never
    created, because nothing else reconciles on a host whose only tunnel is
    unmanaged. The periodic expiry pass is the second, sanctioned entry point and
    closes that window.

    A lease is only issued while none exists with more than half its lifetime
    left. Without that guard every reconciliation would rewrite durable state
    with a fresh deadline, turning a five-minute timer into a five-minute write
    loop for as long as the tunnel is up.
    """
    runtime = [item for item in endpoints if item.kind == "wireguard-runtime"]
    if not runtime:
        return []
    fresh = {
        (item.profile_uuid, item.fingerprint) for item in existing
        if item.source == "retained" and item.expires - now > AUTH_TTL // 2
    }
    runtime = [item for item in runtime
               if (item.profile_uuid, item.fingerprint) not in fresh]
    if not runtime:
        return []
    parsed = _wg_all_rows("latest-handshakes")
    if parsed is None:
        return []
    rows, _ = parsed
    handshakes: dict[str, int] = {}
    for _interface, peer_key, value in rows:
        if not value.isdigit():
            continue
        handshakes[peer_key] = max(handshakes.get(peer_key, 0), int(value))
    leases: list[Record] = []
    for endpoint in runtime:
        stamp = handshakes.get(endpoint.peer_key, 0)
        if stamp <= 0 or stamp > now + 30 \
                or now - stamp > WG_HANDSHAKE_MAX_AGE:
            continue
        leases.append(Record(
            endpoint.profile_uuid, endpoint.fingerprint, "retained", "udp",
            endpoint.host, endpoint.port, now + AUTH_TTL,
        ))
    return leases


def collect_endpoints() -> list[Endpoint]:
    endpoints: list[Endpoint] = []
    skipped = 0
    for connection in load_connections():
        try:
            endpoints.extend(endpoint_from_connection(connection))
        except EndpointError as exc:
            # Isolate the profile rather than aborting the whole reconciliation.
            # One unparsable gateway string used to abort every caller --
            # reconcile, expire, record-disconnect and commit-active alike --
            # so mark_armed() was never reached and bypass_grace_v4 stayed at
            # 0.0.0.0/0. A single malformed profile therefore turned the kill
            # switch fail-OPEN for every unrelated tunnel. Skipping is the
            # closed direction: the skipped profile simply gets no pinned
            # endpoint and cannot pass WAN-strict, and commit_active() still
            # refuses outright ("active profile has no supported endpoint
            # contract") if the skipped profile is the one coming up.
            # The reason is actionable on its own; no profile identifier is
            # logged, so nothing machine-identifying reaches the journal.
            print(
                f"noid-wan-strict-endpoints: skipping unparsable VPN profile: {exc}",
                file=sys.stderr,
            )
            skipped += 1
    if skipped:
        print(
            f"noid-wan-strict-endpoints: {skipped} VPN profile(s) skipped; their "
            "endpoints are NOT pinned and cannot pass WAN-strict",
            file=sys.stderr,
        )
    # Peers a loaded profile already describes keep that profile's identity; the
    # kernel view only adds tunnels NetworkManager does not manage at all.
    endpoints.extend(runtime_tunnel_endpoints(
        {item.peer_key for item in endpoints if item.peer_key != "-"}
    ))
    if len(set(endpoints)) != len(endpoints):
        raise fail("duplicate canonical endpoint definition")
    return sorted(endpoints)


def _host_routes(connection: NM.Connection) -> set[tuple[int, str, str]]:
    result: set[tuple[int, str, str]] = set()
    for family, setting, exact_prefix in (
        (4, connection.get_setting_ip4_config(), 32),
        (6, connection.get_setting_ip6_config(), 128),
    ):
        if setting is None:
            continue
        for index in range(setting.get_num_routes()):
            route = setting.get_route(index)
            if route.get_prefix() != exact_prefix:
                continue
            try:
                address = ipaddress.ip_address(route.get_dest())
                next_hop = ipaddress.ip_address(route.get_next_hop() or "")
            except ValueError:
                continue
            if address.version != family or next_hop.version != family:
                continue
            if not address.is_global:
                continue
            result.add((family, str(address), str(next_hop)))
    return result


def _fixture_bootstrap_context(
        profile_uuid: str,
        ) -> tuple[NM.Connection, NM.Connection, set[int], dict[int, str]]:
    runtime_path = os.environ.get("NOID_TEST_RUNTIME_PROFILE", "")
    persistent_path = os.environ.get("NOID_TEST_PERSISTENT_PROFILE", "")
    if not runtime_path or not persistent_path:
        raise fail("bootstrap-route fixture profiles are missing")
    runtime = read_keyfile_connection(pathlib.Path(runtime_path))
    persistent = read_keyfile_connection(pathlib.Path(persistent_path))
    if canonical_uuid(runtime.get_uuid()) != profile_uuid \
            or canonical_uuid(persistent.get_uuid()) != profile_uuid:
        raise fail("bootstrap-route fixture UUID mismatch")
    try:
        families = {
            int(item) for item in os.environ.get(
                "NOID_TEST_SOFTWARE_DEFAULT_FAMILIES", ""
            ).split()
        }
    except ValueError as exc:
        raise fail("invalid bootstrap-route fixture family") from exc
    if not families <= {4, 6}:
        raise fail("invalid bootstrap-route fixture family")
    gateways: dict[int, str] = {}
    for family, variable in (
        (4, "NOID_TEST_GATEWAY4"), (6, "NOID_TEST_GATEWAY6")
    ):
        value = os.environ.get(variable, "")
        if value:
            address = canonical_ip(value)
            if ipaddress.ip_address(address).version != family:
                raise fail("bootstrap-route fixture gateway family mismatch")
            gateways[family] = address
    return runtime, persistent, families, gateways


def _persistent_profile(profile_uuid: str) -> NM.Connection | None:
    root = pathlib.Path("/etc/NetworkManager/system-connections")
    try:
        paths = sorted(root.glob("*.nmconnection"))
    except OSError as exc:
        raise fail("cannot enumerate persistent NetworkManager profiles") from exc
    for path in paths:
        try:
            info = path.lstat()
        except OSError as exc:
            raise fail("cannot inspect persistent NetworkManager profile") from exc
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o077):
            continue
        try:
            connection = read_keyfile_connection(path)
        except EndpointError:
            continue
        if connection.get_uuid() and canonical_uuid(connection.get_uuid()) == profile_uuid:
            return connection
    return None


def _profile_is_runtime_only(profile_uuid: str) -> bool:
    """True when no saved keyfile on disk claims this profile UUID.

    NetworkManager keeps a profile either in /etc/NetworkManager/system-
    connections or, for a profile a client added without asking for it to be
    saved, only in volatile /run state. Both are ordinary loaded profiles while
    they exist; the difference is what happens when the client disconnects. A
    saved profile stays and is re-read on the next reconciliation. A volatile
    one is taken away with the tunnel, so the endpoint the client is about to
    reconnect to is unpinned exactly while it needs to be reachable. ProtonVPN's
    Linux app is the documented case: its WireGuard profile is created under
    /run on connect and never reaches /etc, while its own kill-switch dummy
    profile is saved normally.

    Only that volatile class earns a retention record, because only there is
    profile absence the client's normal disconnected state rather than a user
    deletion. Anything unreadable or unparsable counts as saved, which is the
    answer that grants nothing.
    """
    override = os.environ.get("NOID_NM_PERSISTENT_DIR", "")
    if override and not TEST_MODE:
        raise fail("persistent-profile override is disabled in production")
    root = pathlib.Path(
        override if override and TEST_MODE
        else "/etc/NetworkManager/system-connections"
    )
    try:
        paths = sorted(root.glob("*.nmconnection"))
    except OSError:
        return False
    for path in paths:
        try:
            info = path.lstat()
        except OSError:
            return False
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            continue
        try:
            connection = read_keyfile_connection(path)
        except EndpointError:
            return False
        if (connection.get_uuid() or "").lower() == profile_uuid:
            return False
    return True


def _applied_connection(device: NM.Device) -> NM.Connection:
    """Fetch NetworkManager's effective device state without a sync D-Bus call."""
    loop = GLib.MainLoop()
    cancellable = Gio.Cancellable()
    outcome: dict[str, object] = {}

    def complete(source: NM.Device, result: Gio.AsyncResult, _data: object) -> None:
        if "error" in outcome:
            return
        try:
            connection, _version = source.get_applied_connection_finish(result)
            outcome["connection"] = connection
        except GLib.Error as exc:
            outcome["error"] = exc
        finally:
            loop.quit()

    def timed_out() -> bool:
        outcome["error"] = TimeoutError(
            "NetworkManager applied-connection query timed out"
        )
        cancellable.cancel()
        loop.quit()
        return GLib.SOURCE_REMOVE

    device.get_applied_connection_async(0, cancellable, complete, None)
    timeout_source = GLib.timeout_add(2000, timed_out)
    loop.run()
    if "error" not in outcome:
        GLib.source_remove(timeout_source)
    if "connection" not in outcome:
        raise fail("cannot read applied physical NetworkManager connection") \
            from outcome.get("error")
    return outcome["connection"]  # type: ignore[return-value]


def _live_bootstrap_context(
        interface: str, profile_uuid: str,
        ) -> tuple[NM.Connection, NM.Connection, set[int], dict[int, str]] | None:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", interface):
        raise fail("invalid physical interface name")
    if not (pathlib.Path("/sys/class/net") / interface / "device").is_dir():
        raise fail("bootstrap-route event is not hardware-backed")
    client = NM.Client.new(None)
    device = next(
        (item for item in client.get_devices() if item.get_iface() == interface),
        None,
    )
    if device is None or device.get_active_connection() is None:
        raise fail("physical device has no active connection")
    active = device.get_active_connection()
    if canonical_uuid(active.get_uuid()) != profile_uuid:
        raise fail("physical reapply UUID does not match active connection")
    # The applied connection is the authority for what the kernel is actually
    # routing right now. The persistent profile is still read, but only as an
    # ownership gate: a physical profile that is absent or not root-owned with
    # tight modes yields no bootstrap window at all (see _persistent_profile).
    # It is deliberately NOT used as an is-this-route-new oracle any more --
    # see collect_bootstrap_routes() for why that comparison was unsound.
    runtime = _applied_connection(device)
    persistent = _persistent_profile(profile_uuid)
    if persistent is None:
        return None
    software_defaults: set[int] = set()
    for candidate in client.get_active_connections():
        if candidate.get_uuid() == profile_uuid \
                or candidate.get_connection_type() != "dummy":
            continue
        devices = list(candidate.get_devices())
        if any((pathlib.Path("/sys/class/net") / item.get_iface() / "device").is_dir()
               for item in devices):
            continue
        if candidate.get_default():
            software_defaults.add(4)
        if candidate.get_default6():
            software_defaults.add(6)
    gateways: dict[int, str] = {}
    for family, config in (
        (4, device.get_ip4_config()), (6, device.get_ip6_config())
    ):
        if config is None or not config.get_gateway():
            continue
        gateway = canonical_ip(config.get_gateway())
        if ipaddress.ip_address(gateway).version == family:
            gateways[family] = gateway
    return runtime, persistent, software_defaults, gateways


def collect_bootstrap_routes(
        interface: str, profile_uuid: str,
        ) -> set[tuple[str, str]]:
    profile_uuid = canonical_uuid(profile_uuid)
    if TEST_MODE and os.environ.get("NOID_TEST_RUNTIME_PROFILE"):
        context = _fixture_bootstrap_context(profile_uuid)
    else:
        context = _live_bootstrap_context(interface, profile_uuid)
    if context is None:
        return set()
    runtime, _persistent, software_defaults, gateways = context
    # Route novelty is NOT decided by "applied minus persistent" any more.
    # That comparison assumed a client adds its probe route with Reapply only.
    # NetworkManager also exposes Update()/Update2(to-disk), and a client that
    # calls both -- Proton VPN GTK 4.16.5 does, its NM audit trail shows
    # op="connection-update" args="ipv4.routes" immediately followed by
    # op="device-reapply" -- makes the two sides identical. The difference then
    # measured only whether the keyfile had already been flushed when the
    # dispatcher read it, i.e. a race, not a property of the route: the very
    # first connection won it and every later one lost it, permanently.
    # It also never separated a client probe route from a saved user route,
    # only Update+Reapply clients from Reapply-only ones.
    # The real bound is the event itself: this runs on a physical Reapply, the
    # exception is local-output-only TCP/UDP, expires in BOOTSTRAP_TTL seconds
    # and is re-derived from scratch on every later event. The conditions below
    # (software dummy default-route owner, current physical gateway as next
    # hop, exact host prefix, global destination, at most eight addresses)
    # carry the actual policy.
    addresses: set[str] = set()
    for family, address, next_hop in _host_routes(runtime):
        if family not in software_defaults or gateways.get(family) != next_hop:
            continue
        addresses.add(address)
    if len(addresses) > 8:
        raise fail("too many transient VPN bootstrap host routes")
    return {
        (address, protocol)
        for address in addresses
        for protocol in ("tcp", "udp")
    }


def _runtime_dir(directory: pathlib.Path) -> None:
    trusted_directory(directory.parent, "tunnel runtime parent")
    trusted_directory(
        directory, "tunnel runtime state",
        create_mode=0o700, exact_mode=0o700,
    )


def _marker_path(directory: pathlib.Path, profile_uuid: str) -> pathlib.Path:
    return directory / f"{canonical_uuid(profile_uuid)}.state"


def _marker_metadata(path: pathlib.Path) -> os.stat_result | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise fail("cannot inspect tunnel runtime marker") from exc
    expected_uid, expected_gid = expected_identity()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != expected_uid or info.st_gid != expected_gid
            or stat.S_IMODE(info.st_mode) != 0o600):
        raise fail("tunnel runtime marker metadata mismatch")
    return info


def _write_marker(path: pathlib.Path, payload: str) -> None:
    _runtime_dir(path.parent)
    prior = _marker_metadata(path)
    flags = (os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC
             | getattr(os, "O_NOFOLLOW", 0))
    try:
        fd = os.open(path, flags, 0o600)
        opened = os.fstat(fd)
        expected_uid, expected_gid = expected_identity()
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or opened.st_uid != expected_uid
                or opened.st_gid != expected_gid):
            raise OSError("opened tunnel marker metadata mismatch")
        if prior is not None and (opened.st_dev, opened.st_ino) != (
                prior.st_dev, prior.st_ino):
            raise OSError("tunnel marker identity changed while opening")
        data = payload.encode("ascii")
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written <= 0:
                raise OSError("short tunnel marker write")
            offset += written
        os.fsync(fd)
        os.fchmod(fd, 0o600)
        if not TEST_MODE:
            os.fchown(fd, 0, 0)
    except (OSError, UnicodeError) as exc:
        raise fail("cannot publish tunnel runtime marker") from exc
    finally:
        if "fd" in locals():
            os.close(fd)
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _read_marker(path: pathlib.Path) -> str | None:
    if _marker_metadata(path) is None:
        return None
    try:
        return path.read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise fail("cannot read tunnel runtime marker") from exc


def _remove_marker(path: pathlib.Path) -> bool:
    if _marker_metadata(path) is None:
        return False
    try:
        path.unlink()
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as exc:
        raise fail("cannot remove tunnel runtime marker") from exc
    return True


def _clear_marker_dir(directory: pathlib.Path) -> None:
    try:
        info = directory.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise fail("cannot inspect tunnel runtime state directory") from exc
    _runtime_dir(directory)
    for path in sorted(directory.iterdir()):
        match = re.fullmatch(
            r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.state",
            path.name,
        )
        if match is None:
            raise fail("unexpected tunnel runtime marker name")
        canonical_uuid(match.group(1))
        _remove_marker(path)


def _active_marker(profile_uuid: str) -> pathlib.Path:
    return _marker_path(ACTIVE_DIR, profile_uuid)


def mark_tunnel_active(profile_uuid: str) -> None:
    profile_uuid = canonical_uuid(profile_uuid)
    _write_marker(
        _active_marker(profile_uuid),
        f"NOID_WAN_TUNNEL_ACTIVE_V1 {profile_uuid}\n",
    )


def active_marker_present(profile_uuid: str) -> bool:
    profile_uuid = canonical_uuid(profile_uuid)
    value = _read_marker(_active_marker(profile_uuid))
    if value is None:
        return False
    if value != f"NOID_WAN_TUNNEL_ACTIVE_V1 {profile_uuid}\n":
        raise fail("invalid active-tunnel marker content")
    return True


def any_active_marker() -> bool:
    try:
        ACTIVE_DIR.lstat()
    except FileNotFoundError:
        return False
    _runtime_dir(ACTIVE_DIR)
    found = False
    for path in sorted(ACTIVE_DIR.iterdir()):
        match = re.fullmatch(
            r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.state",
            path.name,
        )
        if match is None or not active_marker_present(match.group(1)):
            raise fail("invalid active-tunnel marker set")
        found = True
    return found


def state_metadata_ok(path: pathlib.Path) -> None:
    trusted_directory(path.parent, "WAN strict persistent state")
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise fail("endpoint state is not one regular file")
    expected_uid, expected_gid = expected_identity()
    if (info.st_uid != expected_uid or info.st_gid != expected_gid
            or stat.S_IMODE(info.st_mode) != 0o644):
        raise fail("endpoint state owner/mode mismatch")


def load_state() -> list[Record]:
    state_metadata_ok(STATE)
    try:
        lines = STATE.read_text(encoding="ascii").splitlines()
    except FileNotFoundError:
        return []
    except (OSError, UnicodeError) as exc:
        raise fail("cannot read endpoint state") from exc
    if not lines:
        return []
    if lines[0] != HEADER:
        raise fail("legacy or unknown endpoint state format")
    records: list[Record] = []
    for line in lines[1:]:
        fields = line.split(" ")
        if len(fields) != 7 or any(not field for field in fields):
            raise fail("invalid endpoint state field count")
        profile_uuid, fingerprint, source, proto, address, port_s, expires_s = fields
        profile_uuid = canonical_uuid(profile_uuid)
        if not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
            raise fail("invalid endpoint fingerprint")
        if source not in {"literal", "authenticated", "retained"}:
            raise fail("invalid endpoint provenance")
        if proto not in {"tcp", "udp"}:
            raise fail("invalid endpoint transport")
        address = canonical_ip(address)
        if not port_s.isdigit() or not 1 <= int(port_s) <= 65535:
            raise fail("invalid endpoint port")
        if not expires_s.isdigit():
            raise fail("invalid endpoint expiry")
        expires = int(expires_s)
        # A literal record is re-derived from a loaded profile on every pass and
        # therefore carries no deadline; every other provenance is evidence with
        # a bounded lifetime and must carry one. The field layout is unchanged,
        # so the v2 header still describes this file exactly.
        if (source == "literal") != (expires == 0):
            raise fail("endpoint provenance/expiry mismatch")
        records.append(Record(
            profile_uuid, fingerprint, source, proto, address, int(port_s),
            expires,
        ))
    if len(set(records)) != len(records):
        raise fail("duplicate endpoint state record")
    return sorted(records)


def stage_state(records: list[Record]) -> pathlib.Path:
    trusted_directory(
        STATE.parent, "WAN strict persistent state", create_mode=0o755
    )
    fd, name = tempfile.mkstemp(prefix=".wan-endpoints.", dir=STATE.parent)
    path = pathlib.Path(name)
    try:
        with os.fdopen(fd, "w", encoding="ascii", newline="\n") as stream:
            stream.write(HEADER + "\n")
            for record in sorted(records):
                stream.write("{} {} {} {} {} {} {}\n".format(*dataclasses.astuple(record)))
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o644)
            if not TEST_MODE:
                os.fchown(stream.fileno(), 0, 0)
        return path
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def mark_armed() -> None:
    if flag_present(ARMED, "WAN strict armed", ARMED_CONTENT):
        return
    write_flag(ARMED, "WAN strict armed", ARMED_CONTENT)


def flag_present(path: pathlib.Path, label: str, content: bytes) -> bool:
    trusted_directory(path.parent, f"{label} parent")
    return exact_file_present(path, f"{label} flag", 0o644, content)


def write_flag(path: pathlib.Path, label: str, content: bytes) -> None:
    trusted_directory(path.parent, f"{label} parent", create_mode=0o755)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    staged = pathlib.Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o644)
            if not TEST_MODE:
                os.fchown(stream.fileno(), 0, 0)
        os.replace(staged, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        if not exact_file_present(path, f"{label} flag", 0o644, content):
            raise fail(f"{label} flag publication disappeared")
    except BaseException:
        staged.unlink(missing_ok=True)
        raise


def write_disabled_flag() -> None:
    write_flag(DISABLED, "WAN strict disabled", DISABLED_CONTENT)


def remove_flag(path: pathlib.Path, label: str, content: bytes) -> None:
    if not flag_present(path, label, content):
        return
    path.unlink()
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def remove_disabled_flag() -> None:
    remove_flag(DISABLED, "WAN strict disabled", DISABLED_CONTENT)


def remove_failed_flag() -> None:
    remove_flag(FAILED, "WAN strict bootstrap failure", FAILED_CONTENT)


def remove_armed_flag() -> None:
    remove_flag(ARMED, "WAN strict armed", ARMED_CONTENT)


def resolve(endpoint: Endpoint) -> list[str]:
    try:
        return [canonical_ip(endpoint.host)]
    except EndpointError:
        pass
    trusted_directory(
        NETWORK_READY.parent, "gateway/XDP readiness parent", exact_mode=0o755
    )
    if not exact_file_present(
            NETWORK_READY, "gateway/XDP readiness marker", 0o644, READY_CONTENT):
        return []
    fixture_map = os.environ.get("NOID_TEST_DNS_MAP", "")
    if fixture_map:
        if not TEST_MODE:
            raise fail("DNS fixture override is disabled in production")
        result: set[str] = set()
        for line in pathlib.Path(fixture_map).read_text(encoding="ascii").splitlines():
            fields = line.split(" ")
            if len(fields) != 2 or any(not field for field in fields):
                raise fail("invalid DNS fixture record")
            if fields[0] == endpoint.host:
                result.add(canonical_ip(fields[1]))
        return sorted(result)
    socktype = socket.SOCK_STREAM if endpoint.proto == "tcp" else socket.SOCK_DGRAM
    try:
        answers = socket.getaddrinfo(
            endpoint.host, endpoint.port, socket.AF_UNSPEC, socktype
        )
    except socket.gaierror:
        return []
    result: set[str] = set()
    for answer in answers:
        try:
            result.add(canonical_ip(answer[4][0]))
        except EndpointError:
            continue
    return sorted(result, key=lambda item: (ipaddress.ip_address(item).version, item))


def nft_batch(records: list[Record], candidates: set[tuple[str, str, int]] | None,
              grace: bool | None, now: int) -> str:
    commands = [
        f"flush set {TABLE} vpn_endpoints_v4",
        f"flush set {TABLE} vpn_endpoints_v6",
    ]
    # Several records can describe one exact tuple at once: a loaded profile and
    # the bounded proof that the same tunnel was observed active. nft does not
    # reject a repeated key inside one `add element`; measured against nft 1.1.x
    # in a throwaway network namespace, the LAST occurrence silently wins, so a
    # string sort would let an arbitrary timeout override a permanent element.
    # Collapse to one element per tuple here instead: a record without a
    # deadline outranks every timed one, and among timed ones the longest
    # remaining lifetime wins. Neither direction adds a tuple.
    durable: dict[int, dict[tuple[str, str, int], int | None]] = {4: {}, 6: {}}
    for record in records:
        key = (record.address, record.proto, record.port)
        family = ipaddress.ip_address(record.address).version
        timeout = None if record.expires == 0 else max(1, record.expires - now)
        if key in durable[family]:
            previous = durable[family][key]
            if previous is None or (timeout is not None and timeout <= previous):
                continue
        durable[family][key] = timeout
    for family, set_name in ((4, "vpn_endpoints_v4"), (6, "vpn_endpoints_v6")):
        elements = []
        for (address, proto, port), timeout in durable[family].items():
            element = f"{address} . {proto} . {port}"
            if timeout is not None:
                element += f" timeout {timeout}s"
            elements.append(element)
        if elements:
            commands.append(
                f"add element {TABLE} {set_name} {{ {', '.join(sorted(elements))} }}"
            )
    if candidates is not None:
        commands.extend([
            f"flush set {TABLE} vpn_candidates_v4",
            f"flush set {TABLE} vpn_candidates_v6",
        ])
        by_family: dict[int, list[str]] = {4: [], 6: []}
        for address, proto, port in candidates:
            family = ipaddress.ip_address(address).version
            by_family[family].append(
                f"{address} . {proto} . {port} timeout {CANDIDATE_TTL}s"
            )
        for family, set_name in ((4, "vpn_candidates_v4"), (6, "vpn_candidates_v6")):
            if by_family[family]:
                commands.append(
                    f"add element {TABLE} {set_name} {{ {', '.join(sorted(set(by_family[family])))} }}"
                )
    if grace is not None:
        commands.append(f"flush set {TABLE} bypass_grace_v4")
        if grace:
            commands.append(
                f"add element {TABLE} bypass_grace_v4 {{ 0.0.0.0/0 }}"
            )
    return "\n".join(commands) + "\n"


def apply_nft(records: list[Record], candidates: set[tuple[str, str, int]] | None,
              grace: bool | None, now: int) -> None:
    apply_raw_nft(nft_batch(records, candidates, grace, now))


def apply_raw_nft(batch: str) -> None:
    result = subprocess.run(
        [*NFT, "-f", "-"], input=batch,
        text=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise fail("atomic nft endpoint reconciliation failed")


def reconcile_bootstrap(interface: str, profile_uuid: str) -> int:
    # A late no-wait Reapply event must not recreate its pre-profile window
    # after the tunnel-up path has already published active runtime proof.
    candidates = set() if any_active_marker() else collect_bootstrap_routes(
        interface, profile_uuid
    )
    commands = [
        f"flush set {TABLE} vpn_bootstrap_routes_v4",
        f"flush set {TABLE} vpn_bootstrap_routes_v6",
    ]
    by_family: dict[int, list[str]] = {4: [], 6: []}
    for address, protocol in candidates:
        family = ipaddress.ip_address(address).version
        by_family[family].append(
            f"{address} . {protocol} timeout {BOOTSTRAP_TTL}s"
        )
    for family, set_name in (
        (4, "vpn_bootstrap_routes_v4"),
        (6, "vpn_bootstrap_routes_v6"),
    ):
        if by_family[family]:
            commands.append(
                f"add element {TABLE} {set_name} "
                f"{{ {', '.join(sorted(by_family[family]))} }}"
            )
    apply_raw_nft("\n".join(commands) + "\n")
    print(f"reconciled {len(candidates)} transient bootstrap route tuple(s)")
    return 0


def clear_bootstrap_routes() -> None:
    apply_raw_nft(
        f"flush set {TABLE} vpn_bootstrap_routes_v4\n"
        f"flush set {TABLE} vpn_bootstrap_routes_v6\n"
    )


def nft_json(*arguments: str) -> list[object]:
    try:
        result = subprocess.run(
            [*NFT, "-j", *arguments], text=True, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise fail("cannot query nft runtime state") from exc
    if result.returncode != 0:
        raise fail("nft runtime query failed")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise fail("nft runtime query returned invalid JSON") from exc
    objects = payload.get("nftables") if isinstance(payload, dict) else None
    if not isinstance(objects, list):
        raise fail("nft runtime query returned an invalid schema")
    return objects


def nft_table_present() -> bool:
    matches = []
    for item in nft_json("list", "tables"):
        table = item.get("table") if isinstance(item, dict) else None
        if isinstance(table, dict) \
                and table.get("family") == "inet" \
                and table.get("name") == "noid_wan_strict":
            matches.append(table)
    if len(matches) > 1:
        raise fail("duplicate WAN-strict nft table identity")
    return bool(matches)


def nft_set_nonempty(name: str) -> bool:
    matches = []
    for item in nft_json(
            "list", "set", "inet", "noid_wan_strict", name):
        nft_set = item.get("set") if isinstance(item, dict) else None
        if isinstance(nft_set, dict) \
                and nft_set.get("family") == "inet" \
                and nft_set.get("table") == "noid_wan_strict" \
                and nft_set.get("name") == name:
            matches.append(nft_set)
    if len(matches) != 1:
        raise fail(f"WAN-strict nft set identity mismatch: {name}")
    elements = matches[0].get("elem", [])
    if not isinstance(elements, list):
        raise fail(f"WAN-strict nft set elements have invalid schema: {name}")
    return bool(elements)


def autoresume_timer_active() -> bool:
    try:
        result = subprocess.run(
            [*SYSTEMCTL, "is-active", "--quiet",
             "noid-wan-strict-autoresume.timer"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=3, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise fail("cannot query WAN-strict auto-resume timer") from exc
    if result.returncode == 0:
        return True
    if result.returncode in {3, 4}:
        return False
    raise fail("WAN-strict auto-resume timer query failed")


def explicit_pause_active() -> bool:
    """Return true only for an already-committed, still-bounded pause.

    The transient timer alone is not authority to reopen grace: a manual
    resume closes the nft set before the CLI stops the timer, and another
    controller action may run in that narrow interval. Conversely, the nft
    grace set alone is not bounded evidence. Requiring both preserves an
    explicit pause across profile/DNS/expiry reconciliation without allowing a
    stale timer or stale set to weaken strict mode.
    """
    if not autoresume_timer_active() or not nft_table_present():
        return False
    return nft_set_nonempty("bypass_grace_v4")


def reconciliation_grace() -> bool:
    if not flag_present(ARMED, "WAN strict armed", ARMED_CONTENT):
        return True
    return explicit_pause_active()


def derive_runtime_mode() -> str:
    disabled = flag_present(
        DISABLED, "WAN strict disabled", DISABLED_CONTENT
    )
    failed = flag_present(
        FAILED, "WAN strict bootstrap failure", FAILED_CONTENT
    )
    armed = flag_present(ARMED, "WAN strict armed", ARMED_CONTENT)
    table_present = nft_table_present()
    if disabled:
        return "DISABLED" if not table_present else "ERROR"
    if failed:
        return "ERROR"
    records = load_state()
    if not table_present:
        return "ERROR"
    grace = nft_set_nonempty("bypass_grace_v4")
    endpoints_v4 = nft_set_nonempty("vpn_endpoints_v4")
    endpoints_v6 = nft_set_nonempty("vpn_endpoints_v6")
    endpoints = endpoints_v4 or endpoints_v6
    if endpoints and not records:
        return "ERROR"
    if grace:
        if autoresume_timer_active():
            return "GRACE_PAUSED"
        return "ERROR" if armed else "GRACE_BOOTSTRAP"
    if not armed:
        return "ERROR"
    return "STRICT" if endpoints else "STRICT_EMPTY"


def publish_status() -> None:
    if SKIP_STATUS:
        return
    if os.geteuid() != 0 and not TEST_MODE:
        raise fail("status publication requires root")
    trusted_directory(
        STATUS.parent, "WAN strict runtime status",
        create_mode=0o755, exact_mode=0o755,
    )
    try:
        mode = derive_runtime_mode()
    except EndpointError:
        mode = "ERROR"
    fd, name = tempfile.mkstemp(prefix=".wan-strict-status.", dir=STATUS.parent)
    staged = pathlib.Path(name)
    try:
        with os.fdopen(fd, "w", encoding="ascii", newline="\n") as stream:
            stream.write(f"MODE={mode}\n")
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o644)
            if not TEST_MODE:
                os.fchown(stream.fileno(), 0, 0)
        os.replace(staged, STATUS)
        directory_fd = os.open(STATUS.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        if not exact_file_present(
                STATUS, "WAN strict runtime status", 0o644,
                f"MODE={mode}\n".encode("ascii")):
            raise fail("WAN runtime status postcondition disappeared")
    except Exception as exc:
        staged.unlink(missing_ok=True)
        try:
            STATUS.unlink(missing_ok=True)
        except OSError:
            pass
        raise fail("atomic WAN status publication failed") from exc


def publish(records: list[Record], candidates: set[tuple[str, str, int]] | None,
            grace: bool | None, now: int) -> None:
    old_records = load_state()
    old_grace = reconciliation_grace()
    staged = stage_state(records)
    try:
        apply_nft(records, candidates, grace, now)
        try:
            os.replace(staged, STATE)
            directory_fd = os.open(STATE.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError as exc:
            apply_nft(old_records, set(), old_grace, now)
            raise fail("endpoint state publication failed; nft rolled back") from exc
    finally:
        staged.unlink(missing_ok=True)


def desired(existing: list[Record], endpoints: list[Endpoint], now: int,
            additions: list[Record] | None = None,
            resolve_candidates: bool = True,
            ) -> tuple[list[Record], set[tuple[str, str, int]]]:
    by_fingerprint = {(item.profile_uuid, item.fingerprint): item for item in endpoints}
    records: set[Record] = set()
    candidates: set[tuple[str, str, int]] = set()
    for endpoint in endpoints:
        try:
            address = canonical_ip(endpoint.host)
        except EndpointError:
            if resolve_candidates:
                for address in resolve(endpoint):
                    candidates.add((address, endpoint.proto, endpoint.port))
        else:
            records.add(Record(
                endpoint.profile_uuid, endpoint.fingerprint, "literal",
                endpoint.proto, address, endpoint.port, 0,
            ))
    # Evidence records outlive a single pass, so they are carried over rather
    # than re-derived. `authenticated` still requires its profile to be loaded:
    # deleting a saved profile revokes its promoted address in the very same
    # reconciliation, which is the whole point of that check. `retained` is the
    # provenance for a profile that NetworkManager only ever held in volatile
    # runtime state (see _profile_is_runtime_only), where profile absence is the
    # client's normal disconnected condition and not a deletion, so it survives
    # until its own deadline. Repeated activations of the same tunnel produce
    # one record per pass with a fresh deadline; keeping the longest-lived one
    # per provenance stops durable state from growing on every reconnect.
    survivors: dict[tuple[str, str, str, str, str, int], Record] = {}
    for record in [*existing, *(additions or [])]:
        if record.source == "literal" or record.expires <= now:
            continue
        endpoint = by_fingerprint.get((record.profile_uuid, record.fingerprint))
        if endpoint is None:
            if record.source != "retained":
                continue
        elif record.proto != endpoint.proto or record.port != endpoint.port:
            continue
        key = (record.profile_uuid, record.fingerprint, record.source,
               record.proto, record.address, record.port)
        previous = survivors.get(key)
        if previous is None or record.expires > previous.expires:
            survivors[key] = record
    kept = list(survivors.values())
    leases = [item for item in kept if item.source == "retained"]
    if len(leases) > RETAIN_MAX:
        # Newest activation first, then the record itself, so the survivors are
        # decided by evidence age and never by dictionary insertion order.
        leases.sort(key=lambda item: (-item.expires, item))
        pruned = set(leases[RETAIN_MAX:])
        print(
            f"noid-wan-strict-endpoints: {len(pruned)} oldest retention "
            "lease(s) pruned at the ceiling; those endpoints are no longer "
            "pinned",
            file=sys.stderr,
        )
        kept = [item for item in kept if item not in pruned]
    records.update(kept)
    return sorted(records), candidates


def reconcile(additions: list[Record] | None = None) -> int:
    now = int(time.time())
    endpoints = collect_endpoints()
    existing = load_state()
    records, candidates = desired(
        existing, endpoints, now,
        [*(additions or []), *runtime_tunnel_leases(endpoints, now, existing)],
    )
    # Saved profile data is desired endpoint material, not proof that a tunnel
    # was active. Only commit_active() may create the durable armed marker.
    grace = reconciliation_grace()
    publish(records, candidates, grace, now)
    publish_status()
    print(f"reconciled {len(records)} durable record(s), {len(candidates)} candidate tuple(s)")
    return 0


def bootstrap() -> int:
    now = int(time.time())
    records = [
        item for item in load_state()
        if item.source == "literal" or item.expires > now
    ]
    grace = reconciliation_grace()
    policy = read_owned_regular_text(
        POLICY, "WAN-strict nft policy", 0o644
    )
    table_headers = re.findall(
        r"(?m)^[ \t]*table[ \t]+([A-Za-z0-9_-]+)[ \t]+"
        r"([A-Za-z0-9_.-]+)[ \t]*\{",
        policy,
    )
    if table_headers != [("inet", "noid_wan_strict")] \
            or re.search(r"(?m)^[ \t]*(?:include|flush[ \t]+ruleset)\b", policy):
        raise fail("WAN-strict nft policy has an unsafe table contract")
    physical: list[str] = []
    sys_class_net = pathlib.Path(os.environ.get(
        "NOID_SYS_CLASS_NET", "/sys/class/net"
    ))
    for path in sorted(sys_class_net.iterdir()):
        if not (path / "device").is_dir():
            continue
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", path.name):
            raise fail("unsafe physical interface name")
        physical.append(path.name)
    batch = "destroy table inet noid_wan_strict\n" + policy.rstrip() + "\n"
    batch += nft_batch(records, set(), grace, now)
    if physical:
        quoted = ", ".join(f'"{name}"' for name in physical)
        batch += (
            "add element inet noid_wan_strict physical_ifaces "
            f"{{ {quoted} }}\n"
        )
    apply_raw_nft(batch)
    publish_status()
    print(f"bootstrapped {len(records)} durable endpoint record(s)")
    return 0


def expire() -> int:
    now = int(time.time())
    endpoints = collect_endpoints()
    existing = load_state()
    records, _ = desired(
        existing, endpoints, now,
        runtime_tunnel_leases(endpoints, now, existing),
        resolve_candidates=False,
    )
    changed = records != existing
    if changed:
        grace = reconciliation_grace()
        publish(records, None, grace, now)
    publish_status()
    if changed:
        print(
            "endpoint expiry state changed; "
            f"retained {len(records)} current record(s)"
        )
    return 0


def wg_runtime(interface: str) -> tuple[dict[str, int], dict[str, tuple[str, int]]]:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", interface):
        raise fail("invalid WireGuard interface name")
    handshakes: dict[str, int] = {}
    endpoints: dict[str, tuple[str, int]] = {}
    for field, target in (("latest-handshakes", handshakes), ("endpoints", endpoints)):
        try:
            result = subprocess.run(
                [*WG, "show", interface, field], text=True, capture_output=True,
                timeout=10, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise fail("timeout reading WireGuard runtime peer state") from exc
        except OSError as exc:
            # subprocess.run raises FileNotFoundError -- an OSError -- when the
            # executable is absent. Module 26 ships wireguard-tools, but a host
            # can still lack it, and NetworkManager's native kernel WireGuard
            # support creates working type=wireguard profiles either way, so
            # this path stays reachable. Uncaught, that escaped main()'s
            # `except EndpointError` as a
            # raw traceback before mark_armed() ran, leaving bypass_grace_v4 at
            # 0.0.0.0/0 with one journal warning as the only signal. The
            # sibling call sites already narrow OSError this way (nft_json,
            # autoresume_timer_active), so this is consistency, not new policy.
            raise fail("cannot execute the WireGuard runtime query") from exc
        if result.returncode != 0:
            raise fail("cannot read WireGuard runtime peer state")
        for line in result.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) != 2:
                raise fail("invalid WireGuard runtime output")
            if field == "latest-handshakes":
                if not parts[1].isdigit():
                    raise fail("invalid WireGuard handshake time")
                handshakes[parts[0]] = int(parts[1])
            elif parts[1] != "(none)":
                host, port, transport_proto = split_endpoint(parts[1], None)
                if transport_proto is not None:
                    raise fail("WireGuard runtime endpoint has a transport suffix")
                endpoints[parts[0]] = (canonical_ip(host), port)
    return handshakes, endpoints


def commit_active(interface: str, action: str, profile_uuid: str) -> int:
    now = int(time.time())
    profile_uuid = canonical_uuid(profile_uuid)
    endpoints = [item for item in collect_endpoints() if item.profile_uuid == profile_uuid]
    if not endpoints:
        raise fail("active profile has no supported endpoint contract")
    additions: list[Record] = []
    # Only a hostname-based peer can contribute here: the loop below appends a
    # record exactly when canonical_ip(endpoint.host) raises, which is what
    # _is_hostname() tests. A profile whose WireGuard peers all carry literal
    # IPs gained nothing from the runtime query but still died with it when the
    # optional wg binary was missing, so it never armed at all.
    if any(item.kind == "wireguard" and _is_hostname(item.host)
           for item in endpoints):
        handshakes, runtime = wg_runtime(interface)
        for endpoint in endpoints:
            if endpoint.kind != "wireguard" or endpoint.peer_key not in runtime:
                continue
            stamp = handshakes.get(endpoint.peer_key, 0)
            if stamp <= 0 or stamp > now + 30 or now - stamp > 180:
                continue
            address, port = runtime[endpoint.peer_key]
            if port != endpoint.port:
                continue
            if address not in resolve(endpoint):
                continue
            try:
                canonical_ip(endpoint.host)
            except EndpointError:
                additions.append(Record(
                    endpoint.profile_uuid, endpoint.fingerprint,
                    "authenticated", "udp", address, port, now + AUTH_TTL,
                ))
    elif action == "vpn-up":
        observed = outer_peer_addresses()
        for endpoint in endpoints:
            if endpoint.kind != "openvpn" or not endpoint.identity_ok:
                continue
            resolved = set(resolve(endpoint))
            for address in sorted(observed & resolved):
                try:
                    canonical_ip(endpoint.host)
                except EndpointError:
                    additions.append(Record(
                        endpoint.profile_uuid, endpoint.fingerprint,
                        "authenticated", endpoint.proto, address,
                        endpoint.port, now + AUTH_TTL,
                    ))
    if not additions and all(
        _is_hostname(item.host) for item in endpoints
    ):
        raise fail("no recently authenticated hostname endpoint was observed")
    # This dispatcher event is proof that this profile's tunnel really came up.
    # For a profile NetworkManager holds only in volatile runtime state that is
    # the sole lasting evidence it will ever leave behind, because the profile
    # itself disappears on disconnect and the next reconciliation then unpins
    # the address the client is about to dial again. Without this the client's
    # first packets after every boot and every reconnect are dropped by the
    # layer that exists to let exactly those through -- the reconnect still
    # succeeds on a retry, so the cost is silent latency, not a visible error.
    # Same evidence class and same bounded lifetime as a hostname promotion, and
    # still one exact address/transport/port tuple. A saved profile deliberately
    # gets nothing: deleting it must keep revoking its pin at once.
    if _profile_is_runtime_only(profile_uuid):
        proven = [
            (item.fingerprint, item.proto, item.address, item.port)
            for item in additions
        ]
        for endpoint in endpoints:
            if _is_hostname(endpoint.host):
                continue
            proven.append((
                endpoint.fingerprint, endpoint.proto,
                canonical_ip(endpoint.host), endpoint.port,
            ))
        additions.extend(
            Record(profile_uuid, fingerprint, "retained", proto, address, port,
                   now + AUTH_TTL)
            for fingerprint, proto, address, port in proven
        )
    # The active-tunnel dispatcher is the sole automatic arming authority.
    # Preserve only an already-committed explicit pause (both its live nft set
    # and its bounded timer must agree); otherwise remove onboarding grace in a
    # narrow transaction before any second profile/DNS read or state
    # publication can fail. If this gate cannot reach nft, the durable boot
    # guard still blocks a falsely unarmed reboot. Volatile active proof is
    # published only after every live state transaction succeeds.
    pause_grace = explicit_pause_active()
    mark_armed()
    apply_nft(load_state(), None, pause_grace, now)
    result = reconcile(additions)
    clear_bootstrap_routes()
    mark_tunnel_active(profile_uuid)
    return result


def _is_hostname(host: str) -> bool:
    try:
        canonical_ip(host)
    except EndpointError:
        return True
    return False


def physical_host_routes() -> set[str]:
    """Single-address routes NetworkManager holds on active non-VPN links.

    When a VPN activates, NetworkManager installs a host route towards the
    address the outer connection was established to, on the connection that
    carries it, so the tunnel cannot route through itself. Measured on this
    image that route is present with and without a server-pushed default
    route, and it names the outer peer -- which no dispatcher variable does.

    Everything else that happens to be a host route here (the DHCP gateway,
    for one) is returned as well and is harmless: every caller narrows this
    set by intersecting it with one profile's own resolved endpoints, so an
    unrelated entry can never widen that profile's pin.
    """
    if os.environ.get("NOID_NM_PROFILE_DIRS", "").split():
        # Profiles already come from a fixture, so the live daemon must not be
        # consulted for routes either: a test would otherwise read the routing
        # state of whatever machine it happens to run on.
        if not TEST_MODE:
            raise fail("fixture profile override is disabled in production")
        return {
            canonical_ip(item)
            for item in os.environ.get("NOID_TEST_HOST_ROUTES", "").split()
        }
    # The client must outlive the traversal. NMActiveConnection and NMIPConfig
    # are live D-Bus proxies owned by the client, so iterating over a temporary
    # `NM.Client.new(None).get_active_connections()` hands back objects whose
    # owner is already finalized: every route list then reads back empty, and
    # the promotion silently finds nothing to intersect. Verified on the live
    # image -- temporary client returns no routes, held client returns both.
    client = NM.Client.new(None)
    routes: set[str] = set()
    for active in client.get_active_connections():
        if active.get_vpn():
            continue
        for config, host_prefix in ((active.get_ip4_config(), 32),
                                    (active.get_ip6_config(), 128)):
            if config is None:
                continue
            for route in config.get_routes():
                if route.get_prefix() != host_prefix:
                    continue
                try:
                    routes.add(canonical_ip(route.get_dest()))
                except EndpointError:
                    continue
    return routes


def outer_peer_addresses() -> set[str]:
    """Addresses this host actually opened an outer VPN connection to.

    Two sources, unioned. NetworkManager's dispatcher gateway variables are
    the documented one, but they do not carry the outer peer for OpenVPN:
    measured against NetworkManager-openvpn 1.12.5 they hold the *tunnel*
    gateway once the server pushes routes, and the unspecified address when it
    pushes none -- never the address the client dialled. They are still read so
    that a plugin or version which does report the outer peer keeps working.

    An unspecified address means "this family has no gateway", which every
    IPv4-only profile hits on VPN_IP6_GATEWAY. Treating it as a hostile address
    aborted the entire reconciliation and left OpenVPN endpoints unpinnable, so
    it is skipped rather than rejected. A syntactically invalid value is still
    a contract violation and still fails closed.
    """
    observed: set[str] = set()
    for name in ("VPN_IP4_GATEWAY", "VPN_IP6_GATEWAY"):
        value = os.environ.get(name, "").strip()
        if not value:
            continue
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError as exc:
            raise fail("invalid VPN gateway address") from exc
        if parsed.is_unspecified:
            continue
        observed.add(canonical_ip(value))
    observed.update(physical_host_routes())
    return observed


def record_disconnect(interface: str, action: str, profile_uuid: str) -> int:
    profile_uuid = canonical_uuid(profile_uuid)
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", interface):
        raise fail("invalid tunnel-down interface")
    if action not in {"down", "vpn-down"}:
        raise fail("invalid tunnel-down event")
    active_path = _active_marker(profile_uuid)
    was_active = active_marker_present(profile_uuid)
    if not was_active and not any(
            endpoint.profile_uuid == profile_uuid
            for endpoint in collect_endpoints()):
        print("IGNORED_UNSUPPORTED")
        return 0
    if was_active:
        _remove_marker(active_path)
    # The durable armed marker and endpoint state are intentionally untouched.
    # A clean user disconnect has the same fail-closed result as forced loss.
    print("DOWN_STRICT")
    return 0


def arm_empty() -> int:
    now = int(time.time())
    old_records = load_state()
    was_armed = flag_present(ARMED, "WAN strict armed", ARMED_CONTENT)
    try:
        # Close nft first, then publish the durable armed marker. Until the
        # marker exists a crash can only leave an unexpectedly closed live
        # table; it cannot leave a falsely armed reboot contract.
        publish([], set(), False, now)
        mark_armed()
        publish_status()
        if not SKIP_STATUS and derive_runtime_mode() != "STRICT_EMPTY":
            raise fail("arm-empty postcondition is not STRICT_EMPTY")
    except BaseException as exc:
        try:
            if not was_armed:
                remove_armed_flag()
            publish(old_records, set(), not was_armed, now)
            publish_status()
        except BaseException:
            pass
        raise fail("arm-empty failed; prior WAN state restoration attempted") from exc
    _clear_marker_dir(ACTIVE_DIR)
    return 0


def reset() -> int:
    now = int(time.time())
    old_records = load_state()
    was_armed = flag_present(ARMED, "WAN strict armed", ARMED_CONTENT)
    _clear_marker_dir(ACTIVE_DIR)
    publish([], set(), True, now)
    try:
        ARMED.unlink(missing_ok=True)
        publish_status()
    except Exception as exc:
        # Reset is an explicit privacy trade-off, but partial reset is not an
        # accepted state: restore the prior strict/strict-empty transaction.
        publish(old_records, set(), not was_armed, now)
        if was_armed:
            mark_armed()
        publish_status()
        raise fail("armed flag removal failed; prior strict state restored") from exc
    return 0


def pause() -> int:
    now = int(time.time())
    records = load_state()
    prior_grace = reconciliation_grace()
    try:
        apply_nft(records, None, True, now)
        publish_status()
    except BaseException as exc:
        apply_nft(records, None, prior_grace, now)
        try:
            publish_status()
        except BaseException:
            pass
        raise fail("pause failed; prior mode restored") from exc
    return 0


def resume() -> int:
    grace = not flag_present(ARMED, "WAN strict armed", ARMED_CONTENT)
    apply_nft(load_state(), None, grace, int(time.time()))
    publish_status()
    return 0


def disable_policy() -> int:
    was_disabled = flag_present(
        DISABLED, "WAN strict disabled", DISABLED_CONTENT
    )
    if not was_disabled:
        write_disabled_flag()
    try:
        apply_raw_nft("destroy table inet noid_wan_strict\n")
        publish_status()
        return 0
    except BaseException as exc:
        if not was_disabled:
            # A failed disable is not allowed to leave a half-transitioned
            # flag/table pair. Restore the maintained strict policy from its
            # durable desired state; this may discard transient counters and
            # DNS candidates, but it fails closed.
            remove_disabled_flag()
            try:
                bootstrap()
            except BaseException:
                pass
        raise fail("disable failed; prior enforced state restoration attempted") from exc


def enable_policy() -> int:
    was_disabled = flag_present(
        DISABLED, "WAN strict disabled", DISABLED_CONTENT
    )
    if was_disabled:
        remove_disabled_flag()
    try:
        # A prior boot failure is retained until an explicit recovery
        # transition. This new locked enable attempt supersedes that volatile
        # evidence before publishing its own actual postcondition.
        remove_failed_flag()
        return bootstrap()
    except BaseException as exc:
        if was_disabled:
            # The pre-transition state was deliberately disabled. Restore its
            # exact flag/table contract if enforcement cannot be committed.
            write_disabled_flag()
            try:
                apply_raw_nft("destroy table inet noid_wan_strict\n")
                publish_status()
            except BaseException:
                pass
        raise fail("enable failed; prior disabled state restoration attempted") from exc


def open_lock():
    trusted_directory(
        LOCK.parent, "WAN strict transaction lock", create_mode=0o755
    )
    flags = (os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
             | getattr(os, "O_NOFOLLOW", 0))
    try:
        fd = os.open(LOCK, flags, 0o600)
    except OSError as exc:
        raise fail("cannot open endpoint transaction lock") from exc
    info = os.fstat(fd)
    expected_uid, expected_gid = expected_identity()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != expected_uid or info.st_gid != expected_gid
            or stat.S_IMODE(info.st_mode) != 0o600):
        os.close(fd)
        raise fail("endpoint transaction lock metadata mismatch")
    return os.fdopen(fd, "r+", encoding="ascii")


def acquire_lock(lock_stream) -> None:
    deadline = time.monotonic() + LOCK_TIMEOUT
    while True:
        try:
            fcntl.flock(lock_stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise LockTimeout("endpoint transaction lock timed out")
            time.sleep(min(0.1, remaining))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=(
        "bootstrap", "reconcile", "expire", "commit-active", "arm-empty", "reset",
        "pause", "resume", "disable", "enable", "publish-status",
        "reconcile-bootstrap", "record-disconnect",
    ))
    parser.add_argument("--interface", default="")
    parser.add_argument("--event", default="")
    parser.add_argument("--uuid", default="")
    args = parser.parse_args()
    with open_lock() as lock_stream:
        acquire_lock(lock_stream)
        if args.action not in {"disable", "enable", "publish-status"} \
                and flag_present(
                    DISABLED, "WAN strict disabled", DISABLED_CONTENT):
            raise fail("WAN strict is explicitly disabled")
        if args.action == "bootstrap":
            return bootstrap()
        if args.action == "reconcile":
            return reconcile()
        if args.action == "expire":
            return expire()
        if args.action == "arm-empty":
            return arm_empty()
        if args.action == "reset":
            return reset()
        if args.action == "pause":
            return pause()
        if args.action == "resume":
            return resume()
        if args.action == "disable":
            return disable_policy()
        if args.action == "enable":
            return enable_policy()
        if args.action == "publish-status":
            publish_status()
            return 0
        if args.action == "reconcile-bootstrap":
            if not args.interface or not args.uuid:
                raise fail("reconcile-bootstrap requires interface and profile UUID")
            return reconcile_bootstrap(args.interface, args.uuid)
        if args.action == "record-disconnect":
            if not args.interface or not args.uuid or not args.event:
                raise fail("tunnel-down recording requires event context")
            return record_disconnect(args.interface, args.event, args.uuid)
        if not args.interface or not args.uuid:
            raise fail("commit-active requires interface and profile UUID")
        return commit_active(args.interface, args.event, args.uuid)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except LockTimeout as exc:
        print(f"noid-wan-strict-endpoints: {exc}", file=sys.stderr)
        raise SystemExit(75)
    except EndpointError as exc:
        print(f"noid-wan-strict-endpoints: {exc}", file=sys.stderr)
        raise SystemExit(1)
ENDPOINT_ENGINE_EOF
chmod 0755 /usr/local/libexec/noid-wan-strict-endpoints
chown root:root /usr/local/libexec/noid-wan-strict-endpoints
python3 -c 'p="/usr/local/libexec/noid-wan-strict-endpoints"; compile(open(p, encoding="utf-8").read(), p, "exec")'
log "STEP 2c: libnm endpoint controller installed + compiled"

# ====================================================================
# STEP 3: Install bootstrap-script
# ====================================================================
# Atomically replaces + populates the nft table at boot and every service start.
mkdir -p /usr/local/sbin
cat > /usr/local/sbin/noid-wan-strict-bootstrap.sh <<'BOOTSTRAP_EOF'
#!/bin/bash
#
# NoID Privacy — WAN egress strict bootstrap
#
# Loads /etc/nftables.d/noid-wan-strict.nft (defines table inet noid_wan_strict)
# and asks the controller to validate/prune/populate closed v2 endpoint state
# from /var/lib/noid-privacy/wan-strict-endpoints.txt.
#
# State semantics:
#   - armed marker + unexpired v2 records → strict durable endpoint set
#   - armed marker + no records           → STRICT_EMPTY, never grace
#   - no armed marker (records or empty)  → explicit direct/bootstrap grace
#   - only an explicit reset removes armed state and restores bootstrap grace
#
# Re-run-safe: one idempotent `destroy table` + complete replacement batch.
#

set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
if [ "$#" -ne 0 ]; then
    echo "noid-wan-strict-bootstrap.sh: no arguments accepted" >&2
    exit 2
fi

LOG_TAG="noid-wan-strict"
STATUS_DIR="/run/noid-privacy"
FAILED_FLAG="$STATUS_DIR/wan-strict-bootstrap.failed"
STATUS_FILE="$STATUS_DIR/wan-strict-status"
STATUS_PUBLISHER="/usr/local/sbin/noid-wan-strict-publish-status"

log() {
    if ! logger -t "$LOG_TAG" "$@"; then
        echo "[$LOG_TAG] WARN: journal logging failed" >&2
    fi
    echo "[$LOG_TAG] $*"
}

# The controller validates state and submits one nft transaction containing
# `destroy table`, the complete replacement policy, physical interfaces,
# durable/candidate sets and grace. The old table remains active until commit.
install -d -m 0755 -o root -g root "$STATUS_DIR"
rm -f "$FAILED_FLAG"
# Invoked indirectly by the EXIT trap below.
# shellcheck disable=SC2329
bootstrap_exit() {
    local rc=$?
    trap - EXIT
    if [ "$rc" -ne 0 ]; then
        if ! rm -f -- "$STATUS_FILE"; then
            log "ERROR: stale WAN-strict runtime status could not be removed"
        fi
        if install -m 0644 -o root -g root /dev/null "$FAILED_FLAG"; then
            if ! "$STATUS_PUBLISHER"; then
                rm -f -- "$STATUS_FILE" \
                    || log "ERROR: failed WAN-strict status could not be removed"
                log "ERROR: WAN-strict ERROR status publication failed"
            fi
        else
            log "ERROR: WAN-strict bootstrap failure marker publication failed"
            rm -f -- "$STATUS_FILE" \
                || log "ERROR: stale WAN-strict runtime status remains"
        fi
    fi
    exit "$rc"
}
trap bootstrap_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if ! /usr/local/libexec/noid-wan-strict-endpoints bootstrap; then
    log "ERROR: atomic WAN-strict policy/state bootstrap failed"
    exit 5
fi

rm -f "$FAILED_FLAG"
trap - EXIT

exit 0
BOOTSTRAP_EOF
chmod 700 /usr/local/sbin/noid-wan-strict-bootstrap.sh
chown root:root /usr/local/sbin/noid-wan-strict-bootstrap.sh

# Ensure state-file directory exists (Module 99 also creates this; idempotent)
mkdir -p /var/lib/noid-privacy
chmod 755 /var/lib/noid-privacy
chown root:root /var/lib/noid-privacy
log "STEP 3: /usr/local/sbin/noid-wan-strict-bootstrap.sh installed"

# ====================================================================
# STEP 4: Install systemd-service noid-wan-strict.service
# ====================================================================
# Oneshot service that runs the bootstrap-script at boot (after firewalld,
# before NetworkManager). Defense-in-depth hardening matches NoID Privacy baseline.
cat > /etc/systemd/system/noid-wan-strict.service <<'WAN_STRICT_SERVICE_EOF'
[Unit]
Description=NoID Privacy — WAN egress strict bootstrap (Module 06)
Documentation=man:nft(8)
DefaultDependencies=no
Requires=systemd-tmpfiles-setup.service
After=local-fs.target nftables.service firewalld.service systemd-tmpfiles-setup.service
Before=NetworkManager.service network.target
Wants=local-fs.target
ConditionPathExists=!/var/lib/noid-privacy/wan-strict-disabled.flag

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/noid-wan-strict-bootstrap.sh
RemainAfterExit=yes
StandardOutput=journal
StandardError=journal
UMask=0077

# Security hardening (idempotent, no network beyond local nft)
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_ADMIN
ProtectSystem=strict
ProtectHome=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
PrivateTmp=yes
# /run/noid-privacy is shared by independent NoID Privacy services and therefore has
# the system-wide lifetime defined by /etc/tmpfiles.d/noid-runtime.conf. A
# consumer unit must not bind that shared directory to its own stop lifecycle.
ReadWritePaths=/var/lib/noid-privacy /run/noid-privacy /run/lock/noid-wan-strict.lock
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
RestrictAddressFamilies=AF_NETLINK AF_INET AF_INET6 AF_UNIX
IPAddressDeny=any

[Install]
WantedBy=multi-user.target
WAN_STRICT_SERVICE_EOF
chmod 644 /etc/systemd/system/noid-wan-strict.service
chown root:root /etc/systemd/system/noid-wan-strict.service
systemctl enable noid-wan-strict.service >/dev/null
log "STEP 4: noid-wan-strict.service installed + enabled"

# The primary service is deliberately disabled when the user opts out, while
# /run is reboot-volatile. Without an independently enabled publisher, an exact
# persistent DISABLED state loses only its readable runtime contract at reboot;
# the Network GUI then correctly refuses to infer and locks itself in UNKNOWN.
# This oneshot changes no policy. It runs after the optional bootstrap and asks
# the same closed controller to derive the postcondition from flag, nft, timer
# and failure state. Before=graphical.target closes the first-login race.
cat > /etc/systemd/system/noid-wan-strict-status-publish.service <<'WAN_STATUS_SERVICE_EOF'
[Unit]
Description=NoID Privacy — publish WAN-egress-strict runtime state
Documentation=file:///usr/share/doc/noid-privacy/wan-egress-strict.md
Wants=systemd-tmpfiles-setup.service
After=local-fs.target systemd-tmpfiles-setup.service noid-wan-strict.service
Before=multi-user.target graphical.target
ConditionFileIsExecutable=/usr/local/sbin/noid-wan-strict-publish-status

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/noid-wan-strict-publish-status
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_ADMIN
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
RestrictAddressFamilies=AF_UNIX AF_NETLINK
IPAddressDeny=any
ReadWritePaths=/run/noid-privacy /run/lock/noid-wan-strict.lock

[Install]
WantedBy=multi-user.target
WAN_STATUS_SERVICE_EOF
chmod 0644 /etc/systemd/system/noid-wan-strict-status-publish.service
chown root:root /etc/systemd/system/noid-wan-strict-status-publish.service
systemctl enable noid-wan-strict-status-publish.service >/dev/null
log "STEP 4b: boot-complete WAN runtime-status publisher installed + enabled"

# Persisted strict mode is load-bearing: if its boot transaction fails, a
# physical connection must not come up without the promised WAN backstop.
# Fresh/never-enabled systems have no endpoint state and retain a bounded
# recovery route (bootstrap grace or explicit `noid-toggle-wan-strict off`).
mkdir -p /etc/NetworkManager/dispatcher.d/pre-up.d
cat > /etc/NetworkManager/dispatcher.d/pre-up.d/20-noid-wan-strict-boot-guard <<'WAN_BOOT_GUARD_EOF'
#!/bin/bash
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset BASH_ENV CDPATH ENV GLOBIGNORE PYTHONPATH PYTHONHOME

IFACE="${1:-}"
ACTION="${2:-}"
ARMED_FLAG=/var/lib/noid-privacy/wan-strict-armed.flag
DISABLED_FLAG=/var/lib/noid-privacy/wan-strict-disabled.flag
STATUS_FILE=/run/noid-privacy/wan-strict-status
LC_ALL=C
export LC_ALL

read_exact_line() {
    local path=$1 parent metadata line bytes lines
    parent=${path%/*}
    [ -d "$parent" ] && [ ! -L "$parent" ] || return 1
    [ "$(stat -c '%u:%g:%a' "$parent" 2>/dev/null)" = 0:0:755 ] \
        || return 1
    [ -f "$path" ] && [ ! -L "$path" ] || return 1
    metadata=$(stat -c '%u:%g:%a:%h' "$path" 2>/dev/null) || return 1
    [ "$metadata" = 0:0:644:1 ] || return 1
    IFS= read -r line < "$path" || return 1
    bytes=$(wc -c < "$path") || return 1
    lines=$(wc -l < "$path") || return 1
    [ "$lines" -eq 1 ] && [ "$bytes" -eq $((${#line} + 1)) ] || return 1
    printf '%s\n' "$line"
}

valid_marker() {
    local line
    line=$(read_exact_line "$1") || return 1
    [ "$line" = "$2" ]
}

read_status_mode() {
    local line
    line=$(read_exact_line "$STATUS_FILE") || return 1
    case "$line" in
        MODE=STRICT) printf '%s\n' STRICT ;;
        MODE=STRICT_EMPTY) printf '%s\n' STRICT_EMPTY ;;
        MODE=GRACE_PAUSED) printf '%s\n' GRACE_PAUSED ;;
        *) return 1 ;;
    esac
}

block_physical_pre_up() {
    logger -p user.crit -t noid-wan-strict "$1"
    ip link set dev "$IFACE" down 2>/dev/null || true
    exit 1
}

[ "$ACTION" = pre-up ] || exit 0
[ -n "$IFACE" ] || exit 0
[ -d "/sys/class/net/$IFACE/device" ] || exit 0

if [ -e "$DISABLED_FLAG" ] || [ -L "$DISABLED_FLAG" ]; then
    if valid_marker "$DISABLED_FLAG" NOID_WAN_STRICT_DISABLED_V1; then
        exit 0
    fi
    block_physical_pre_up \
        "blocked physical pre-up: disabled marker is untrusted or malformed"
fi

if [ -e "$ARMED_FLAG" ] || [ -L "$ARMED_FLAG" ]; then
    valid_marker "$ARMED_FLAG" NOID_WAN_STRICT_ARMED_V1 || \
        block_physical_pre_up \
            "blocked physical pre-up: armed marker is untrusted or malformed"
    if ! mode=$(read_status_mode); then
        block_physical_pre_up \
            "blocked physical pre-up: armed strict state lacks exact strict status"
    fi
elif grep -qx 'MODE=ERROR' "$STATUS_FILE" 2>/dev/null; then
    logger -p user.warning -t noid-wan-strict \
        "bootstrap failed before first strict activation; recovery networking remains available"
fi
WAN_BOOT_GUARD_EOF
chmod 0700 /etc/NetworkManager/dispatcher.d/pre-up.d/20-noid-wan-strict-boot-guard
chown root:root /etc/NetworkManager/dispatcher.d/pre-up.d/20-noid-wan-strict-boot-guard
restorecon -F /etc/NetworkManager/dispatcher.d/pre-up.d/20-noid-wan-strict-boot-guard \
    2>/dev/null || true
log "STEP 4: persisted-strict pre-up failure guard installed"

# Tunnel teardown retires only volatile active proof. The durable armed marker
# and exact endpoint state remain fail-closed until an explicit pause, reset or
# feature-disable operation. Remove the retired pre-down relaxation surface
# before installing the ordinary down-event handler.
rm -f /etc/NetworkManager/dispatcher.d/58-wan-strict-clean-disconnect \
    /etc/NetworkManager/dispatcher.d/pre-down.d/58-wan-strict-clean-disconnect
cat > /etc/NetworkManager/dispatcher.d/58-wan-strict-tunnel-down <<'TUNNEL_DOWN_EOF'
#!/bin/bash
# Clean, forced and queued tunnel-down events all preserve durable strict mode.
set -euo pipefail

IFACE="${1:-}"
ACTION="${2:-}"
UUID="${CONNECTION_UUID:-}"
ENGINE=/usr/local/libexec/noid-wan-strict-endpoints
DISABLED_FLAG=/var/lib/noid-privacy/wan-strict-disabled.flag

[ ! -e "$DISABLED_FLAG" ] || exit 0
[ -n "$IFACE" ] && [ -n "$UUID" ] || exit 0
[ ! -d "/sys/class/net/$IFACE/device" ] || exit 0
[ -x "$ENGINE" ] || {
    logger -p user.warning -t noid-wan-strict-down \
        "endpoint controller missing during tunnel teardown"
    exit 1
}

case "$ACTION" in
    down|vpn-down) ;;
    *) exit 0 ;;
esac

CONNECTION_TYPE=$(nmcli -g connection.type connection show "$UUID" 2>/dev/null) \
    || CONNECTION_TYPE=
case "$CONNECTION_TYPE:$ACTION" in
    wireguard:down|vpn:vpn-down|:down|:vpn-down)
        if ! outcome=$("$ENGINE" record-disconnect \
                --interface "$IFACE" --event "$ACTION" --uuid "$UUID"); then
            logger -p user.warning -t noid-wan-strict-down \
                "tunnel-down proof cleanup failed; durable strict mode retained"
            exit 1
        fi
        if [ "$outcome" = DOWN_STRICT ]; then
            logger -t noid-wan-strict-down \
                "tunnel down recorded; WAN-strict remains armed"
        fi
        ;;
    *) exit 0 ;;
esac
TUNNEL_DOWN_EOF
chmod 700 /etc/NetworkManager/dispatcher.d/58-wan-strict-tunnel-down
chown root:root /etc/NetworkManager/dispatcher.d/58-wan-strict-tunnel-down
restorecon -F /etc/NetworkManager/dispatcher.d/58-wan-strict-tunnel-down \
    2>/dev/null || true
log "STEP 4: fail-closed tunnel-down proof cleanup installed"

# ====================================================================
# STEP 5: Install dispatcher 60-vpn-endpoint-pin
# ====================================================================
# On tunnel activation, asks the libnm controller to commit only the actually
# observed endpoint: a recent WireGuard peer-key handshake, or NetworkManager's
# activated external gateway for an identity-verifying OpenVPN profile.
cat > /etc/NetworkManager/dispatcher.d/60-vpn-endpoint-pin <<'PIN_EOF'
#!/bin/bash
# Commit only the endpoint actually observed after tunnel activation. Profile
# interpretation and durable-state reconciliation are owned by libnm controller.
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset BASH_ENV CDPATH ENV GLOBIGNORE PYTHONPATH PYTHONHOME

IFACE="${1:-}"
ACTION="${2:-}"
ENGINE=/usr/local/libexec/noid-wan-strict-endpoints

[ -e /var/lib/noid-privacy/wan-strict-disabled.flag ] && exit 0
[ -n "$IFACE" ] || exit 0
[ -d "/sys/class/net/$IFACE/device" ] && exit 0

UUID="${CONNECTION_UUID:-}"
[ -n "$UUID" ] || exit 0
CONNECTION_TYPE=$(nmcli -g connection.type connection show "$UUID" 2>/dev/null) \
    || exit 0
case "$CONNECTION_TYPE:$ACTION" in
    wireguard:up|vpn:vpn-up) ;;
    *) exit 0 ;;
esac

# A tunnel created outside NetworkManager -- wg-quick, or a provider daemon
# that builds its own kernel device -- also arrives here, because
# NetworkManager assumes it behind a profile it invents and emits up for it.
# That profile is not a source this dispatcher can use: measured on the
# installed image it names the peer's public key with no endpoint, so
# commit-active finds no endpoint contract and exits non-zero. The user then
# gets a warning on every single connect saying the endpoint "was not durably
# committed", for a configuration that is supported and working.
#
# Those tunnels are pinned by kernel discovery instead: udev fires on
# net/add with DEVTYPE=wireguard and the reconciliation reads the endpoint
# straight from `wg show`. Measured from an unarmed host, that path produced
# the runtime identity and its bounded handshake lease while the mode
# correctly stayed GRACE_BOOTSTRAP.
#
# Gating here also makes the documented contract structural rather than
# incidental. "Discovery pins, it does not arm" currently holds only because
# NetworkManager happens not to copy the kernel peer's endpoint into the
# profile it invents; commit_active() calls mark_armed() unconditionally once
# past its endpoint gates. If a future NetworkManager populated that endpoint,
# an externally created tunnel would silently arm the boundary. It must not.
if [ "${CONNECTION_EXTERNAL:-0}" = 1 ]; then
    logger -t noid-vpn-endpoint-pin \
        "externally created tunnel on $IFACE; endpoint pinning is owned by kernel discovery"
    exit 0
fi

if "$ENGINE" commit-active --interface "$IFACE" --event "$ACTION" \
        --uuid "$UUID"; then
    logger -t noid-vpn-endpoint-pin \
        "active tunnel endpoint reconciled from authenticated runtime evidence"
    exit 0
else
    engine_rc=$?
fi

if [ "$engine_rc" -eq 75 ]; then
    retry_id=$(printf '%s\n' "$IFACE:$ACTION:$UUID" \
        | /usr/bin/sha256sum | awk '{print substr($1,1,16)}')
    retry_unit="noid-wan-strict-endpoint-pin-retry-$retry_id"
    if /usr/bin/systemd-run --quiet --collect --unit="$retry_unit" \
            --property=Type=exec --property=Restart=on-failure \
            --property=RestartPreventExitStatus=1 --property=RestartSec=5s \
            "$ENGINE" commit-active --interface "$IFACE" --event "$ACTION" \
            --uuid "$UUID" \
       || /usr/bin/systemctl is-active --quiet "$retry_unit.service"; then
        logger -p user.warning -t noid-vpn-endpoint-pin \
            "endpoint transaction was busy; authenticated commit queued for retry"
        exit 0
    fi
fi

if [ "$engine_rc" -ne 0 ]; then
    logger -p user.warning -t noid-vpn-endpoint-pin \
        "active tunnel endpoint was not durably committed; only bounded candidate state remains"
    exit 1
fi
PIN_EOF
chmod 700 /etc/NetworkManager/dispatcher.d/60-vpn-endpoint-pin
chown root:root /etc/NetworkManager/dispatcher.d/60-vpn-endpoint-pin
log "STEP 5: /etc/NetworkManager/dispatcher.d/60-vpn-endpoint-pin installed"

# ====================================================================
# STEP 5b: Retire the obsolete Proton profile mutator
# ====================================================================
# Proton's current backend intentionally creates its dummy kill-switch profiles
# with sink DNS and owns their add/remove lifecycle. The retired dispatcher
# rewrote and synchronously reactivated those profiles from their own `up`
# event, racing Proton and blocking NetworkManager's serialized event queue.
# NoID Privacy's provider-neutral WAN-strict controller does not need that mutation.
rm -f /etc/NetworkManager/dispatcher.d/70-pvpn-killswitch-dns-fix
log "STEP 5b: obsolete Proton kill-switch profile mutator absent"

# ====================================================================
# STEP 5c: remove the obsolete universal WireGuard keepalive mutator
# ====================================================================
# Runtime `off` cannot distinguish an omitted default from an explicit zero.
# Automatically changing every kernel-WireGuard peer therefore overrode
# unobservable user/provider intent and added periodic traffic. Keepalive is
# now configured only in the profile by an explicit user/provider choice.
rm -f /etc/NetworkManager/dispatcher.d/80-vpn-keepalive
log "STEP 5c: obsolete universal WireGuard keepalive dispatcher absent"

# ====================================================================
# STEP 5d: live-only WireGuard MTU reconciliation
# ====================================================================
# NetworkManager documents that wireguard.mtu=0 does not account for current
# routes at activation. A reduced outer link can therefore leave the default
# tunnel MTU locally fragmenting. Do not persist provider-created runtime
# profiles: derive the ceiling from the actual peer route and lower only the
# live kernel interface. The tunnel pre-up copy is awaited so the unsafe MTU
# is closed before NetworkManager reports activation; later physical-link
# changes use the maintained no-wait path and never hold the serial queue.
cat > /usr/local/sbin/noid-wireguard-mtu-reconcile <<'NOID_WG_MTU_EOF'
#!/bin/bash
# NoID Privacy -- reconcile an active WireGuard link with its real outer MTU.
# This changes only the live kernel link. It never edits or persists an owning
# NetworkManager, provider, wg-quick, Mullvad, Proton, or OpenVPN profile.

set -euo pipefail
set -f
PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL
unset BASH_ENV CDPATH ENV GLOBIGNORE PYTHONPATH PYTHONHOME
umask 077

IP=/usr/bin/ip
WG=/usr/bin/wg
FLOCK=/usr/bin/flock
LOGGER=/usr/bin/logger
CAT=/usr/bin/cat
AWK=/usr/bin/awk
GREP=/usr/bin/grep
HEAD=/usr/bin/head
LOCK=/run/lock/noid-wireguard-mtu.lock
SYS_CLASS_NET=/sys/class/net
WG_PAD=16
WG_TRAILER=32

log_info() {
    "$LOGGER" -t noid-wireguard-mtu -- "$*"
}

log_warn() {
    "$LOGGER" -p user.warning -t noid-wireguard-mtu -- "$*"
}

valid_uint() {
    case "${1:-}" in
        ''|*[!0-9]*) return 1 ;;
        *) return 0 ;;
    esac
}

valid_iface() {
    case "${1:-}" in
        ''|-*|*[!A-Za-z0-9_.:-]*) return 1 ;;
    esac
    [ "${#1}" -le 15 ] && [ -e "$SYS_CLASS_NET/$1" ]
}

wireguard_iface() {
    local iface=$1 item
    for item in $("$WG" show interfaces 2>/dev/null); do
        [ "$item" != "$iface" ] || return 0
    done
    return 1
}

read_link_mtu() {
    local value
    value=$("$CAT" "$SYS_CLASS_NET/$1/mtu" 2>/dev/null) || return 1
    valid_uint "$value" || return 1
    [ "$value" -gt 0 ] || return 1
    printf '%s' "$value"
}

endpoint_family() {
    case "$1" in
        \[*\]:*|*:*:*) printf 'inet6' ;;
        *)             printf 'inet' ;;
    esac
}

endpoint_host() {
    local endpoint=$1
    case "$endpoint" in
        \[*\]:*) endpoint=${endpoint#[}; printf '%s' "${endpoint%%]*}" ;;
        *)       printf '%s' "${endpoint%:*}" ;;
    esac
}

wireguard_fwmark() {
    local mark
    mark=$("$WG" show "$1" fwmark 2>/dev/null) || return 1
    case "$mark" in
        ''|off|none) return 1 ;;
        *) printf '%s' "$mark" ;;
    esac
}

# Emit "<outer-interface> <route-mtu-or-zero>". Return 2 if an unmarked
# full-tunnel lookup loops back into the tunnel instead of revealing its outer
# path. A route-scoped/PMTU-cached MTU is stricter than the device MTU.
route_lookup() {
    local host=$1 mark=$2 tunnel=$3 output first flattened
    local dev='' route_mtu=0 i j
    local -a fields

    if [ -n "$mark" ]; then
        output=$("$IP" route get "$host" mark "$mark" 2>/dev/null) || return 1
    else
        output=$("$IP" route get "$host" 2>/dev/null) || return 1
    fi
    [ -n "$output" ] || return 1
    first=$(printf '%s\n' "$output" | "$HEAD" -1)
    read -ra fields <<<"$first"
    for ((i = 0; i < ${#fields[@]}; i++)); do
        [ "${fields[i]}" = dev ] || continue
        [ $((i + 1)) -lt ${#fields[@]} ] || return 1
        dev=${fields[i + 1]}
        break
    done
    [ -n "$dev" ] || return 1
    [ "$dev" != "$tunnel" ] || return 2

    flattened=${output//$'\n'/ }
    read -ra fields <<<"$flattened"
    for ((i = 0; i < ${#fields[@]}; i++)); do
        [ "${fields[i]}" = mtu ] || continue
        j=$((i + 1))
        [ "$j" -lt ${#fields[@]} ] || continue
        if [ "${fields[j]}" = lock ]; then
            j=$((j + 1))
            [ "$j" -lt ${#fields[@]} ] || continue
        fi
        valid_uint "${fields[j]}" || continue
        route_mtu=${fields[j]}
        break
    done
    printf '%s %s' "$dev" "$route_mtu"
}

safe_inner_mtu() {
    local outer=$1 family=$2 overhead usable
    case "$family" in
        inet6) overhead=$((40 + 8 + WG_TRAILER)) ;;
        inet)  overhead=$((20 + 8 + WG_TRAILER)) ;;
        *) return 1 ;;
    esac
    usable=$((outer - overhead))
    [ "$usable" -ge "$WG_PAD" ] || return 1
    printf '%s' $((usable / WG_PAD * WG_PAD))
}

# Return success when the tunnel carries, or is configured to carry, usable
# IPv6. Link-local-only state is not treated as user IPv6 traffic, matching the
# read-only NoID Privacy MTU audit.
tunnel_has_usable_ipv6() {
    local addresses allowed
    addresses=$("$IP" -6 addr show dev "$1" 2>/dev/null) || return 2
    if printf '%s\n' "$addresses" | "$GREP" -qE 'inet6 .* scope global'; then
        return 0
    fi
    allowed=$("$WG" show "$1" allowed-ips 2>/dev/null) || return 2
    if printf '%s\n' "$allowed" | "$GREP" -q ':'; then
        return 0
    fi
    return 1
}

reconcile_one() {
    local iface=$1 current endpoints endpoint family host mark lookup lookup_rc
    local outer_dev route_mtu outer_mtu candidate worst_safe='' worst_detail=''
    local peers=0 unresolved=0 ipv6_rc applied

    valid_iface "$iface" || {
        log_warn "refused invalid or absent interface name"
        return 1
    }
    wireguard_iface "$iface" || return 0
    current=$(read_link_mtu "$iface") || {
        log_warn "$iface has an unreadable live MTU; left unchanged"
        return 1
    }
    endpoints=$("$WG" show "$iface" endpoints 2>/dev/null | "$AWK" '{print $2}') || {
        log_warn "$iface peer endpoints are unreadable; live MTU $current retained"
        return 1
    }
    [ -n "$endpoints" ] || {
        log_warn "$iface has no peer endpoints; live MTU $current retained"
        return 1
    }
    mark=$(wireguard_fwmark "$iface") || mark=''

    while IFS= read -r endpoint; do
        [ -n "$endpoint" ] || continue
        peers=$((peers + 1))
        if [ "$endpoint" = '(none)' ]; then
            unresolved=$((unresolved + 1))
            continue
        fi
        family=$(endpoint_family "$endpoint")
        host=$(endpoint_host "$endpoint")
        if lookup=$(route_lookup "$host" "$mark" "$iface"); then
            lookup_rc=0
        else
            lookup_rc=$?
        fi
        if [ "$lookup_rc" -ne 0 ]; then
            unresolved=$((unresolved + 1))
            continue
        fi
        outer_dev=${lookup%% *}
        route_mtu=${lookup##* }
        valid_iface "$outer_dev" || {
            unresolved=$((unresolved + 1))
            continue
        }
        outer_mtu=$(read_link_mtu "$outer_dev") || {
            unresolved=$((unresolved + 1))
            continue
        }
        if [ "$route_mtu" -gt 0 ] && [ "$route_mtu" -lt "$outer_mtu" ]; then
            outer_mtu=$route_mtu
        fi
        candidate=$(safe_inner_mtu "$outer_mtu" "$family") || {
            unresolved=$((unresolved + 1))
            continue
        }
        if [ -z "$worst_safe" ] || [ "$candidate" -lt "$worst_safe" ]; then
            worst_safe=$candidate
            worst_detail="$outer_dev/$outer_mtu/$family"
        fi
    done <<<"$endpoints"

    if [ "$peers" -eq 0 ] || [ "$unresolved" -ne 0 ] || [ -z "$worst_safe" ]; then
        log_warn "$iface outer route incomplete ($unresolved/$peers peers); live MTU $current retained"
        return 1
    fi
    [ "$current" -gt "$worst_safe" ] || return 0

    if [ "$worst_safe" -lt 1280 ]; then
        if tunnel_has_usable_ipv6 "$iface"; then
            ipv6_rc=0
        else
            ipv6_rc=$?
        fi
        case "$ipv6_rc" in
            0)
                log_warn "$iface needs MTU $worst_safe below the IPv6 minimum; live MTU $current retained"
                return 1
                ;;
            1) ;;
            *)
                log_warn "$iface IPv6 state is unreadable; live MTU $current retained"
                return 1
                ;;
        esac
    fi

    if ! "$IP" link set dev "$iface" mtu "$worst_safe"; then
        log_warn "$iface MTU correction $current->$worst_safe failed; profile was not modified"
        return 1
    fi
    applied=$(read_link_mtu "$iface") || applied='unreadable'
    if [ "$applied" != "$worst_safe" ]; then
        log_warn "$iface MTU postcondition failed (expected $worst_safe, got $applied)"
        return 1
    fi
    log_info "lowered $iface live MTU $current->$worst_safe for outer $worst_detail; owning profile unchanged"
    printf '%s\n' "$iface: live MTU $current -> $worst_safe (outer $worst_detail)"
}

reconcile_all() {
    local interfaces iface failures=0
    interfaces=$("$WG" show interfaces 2>/dev/null) || return 1
    [ -n "$interfaces" ] || return 0
    for iface in $interfaces; do
        reconcile_one "$iface" || failures=$((failures + 1))
    done
    [ "$failures" -eq 0 ]
}

[ "$EUID" -eq 0 ] || {
    echo "noid-wireguard-mtu-reconcile: root required" >&2
    exit 1
}
[ "$#" -eq 1 ] || {
    echo "Usage: noid-wireguard-mtu-reconcile --all|INTERFACE" >&2
    exit 2
}

lock_state=$(stat -Lc '%u:%g:%a:%h' "$LOCK" 2>/dev/null || true)
[ -f "$LOCK" ] && [ ! -L "$LOCK" ] && [ "$lock_state" = '0:0:600:1' ] || {
    log_warn "lock file is absent or untrusted; no MTU was changed"
    exit 1
}
exec 9<>"$LOCK"
"$FLOCK" -w 3 9 || {
    log_warn "another MTU reconciliation is still active; this event was skipped"
    exit 1
}

case "$1" in
    --all) reconcile_all ;;
    --*)
        echo "Usage: noid-wireguard-mtu-reconcile --all|INTERFACE" >&2
        exit 2
        ;;
    *) reconcile_one "$1" ;;
esac
NOID_WG_MTU_EOF
chmod 0755 /usr/local/sbin/noid-wireguard-mtu-reconcile
chown root:root /usr/local/sbin/noid-wireguard-mtu-reconcile

mkdir -p /etc/NetworkManager/dispatcher.d/pre-up.d \
    /etc/NetworkManager/dispatcher.d/no-wait.d
cat > /etc/NetworkManager/dispatcher.d/no-wait.d/45-noid-wireguard-mtu <<'WG_MTU_DISPATCHER_EOF'
#!/bin/bash
# NetworkManager bridge for live-only WireGuard MTU reconciliation.
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL
unset BASH_ENV CDPATH ENV GLOBIGNORE PYTHONPATH PYTHONHOME

IFACE=${1:-}
ACTION=${2:-}
HELPER=/usr/local/sbin/noid-wireguard-mtu-reconcile

[ -x "$HELPER" ] || {
    /usr/bin/logger -p user.warning -t noid-wireguard-mtu -- \
        "runtime helper is missing; dispatcher event $ACTION was skipped"
    exit 0
}

target=''
case "$ACTION" in
    pre-up|vpn-pre-up)
        target=$IFACE
        ;;
    up|vpn-up)
        if [ -n "$IFACE" ] && /usr/bin/wg show "$IFACE" >/dev/null 2>&1; then
            target=$IFACE
        else
            target=--all
        fi
        ;;
    dhcp4-change|dhcp6-change|reapply|connectivity-change)
        target=--all
        ;;
    *) exit 0 ;;
esac

[ -n "$target" ] || exit 0
if ! "$HELPER" "$target" >/dev/null; then
    /usr/bin/logger -p user.warning -t noid-wireguard-mtu -- \
        "event $ACTION could not prove a safe live MTU; link/profile state was retained"
fi
exit 0
WG_MTU_DISPATCHER_EOF
chmod 0700 /etc/NetworkManager/dispatcher.d/no-wait.d/45-noid-wireguard-mtu
chown root:root /etc/NetworkManager/dispatcher.d/no-wait.d/45-noid-wireguard-mtu
install -o root -g root -m 0700 \
    /etc/NetworkManager/dispatcher.d/no-wait.d/45-noid-wireguard-mtu \
    /etc/NetworkManager/dispatcher.d/pre-up.d/45-noid-wireguard-mtu
ln -sfnT no-wait.d/45-noid-wireguard-mtu \
    /etc/NetworkManager/dispatcher.d/45-noid-wireguard-mtu
restorecon -F /usr/local/sbin/noid-wireguard-mtu-reconcile \
    /etc/NetworkManager/dispatcher.d/pre-up.d/45-noid-wireguard-mtu \
    /etc/NetworkManager/dispatcher.d/no-wait.d/45-noid-wireguard-mtu \
    /etc/NetworkManager/dispatcher.d/45-noid-wireguard-mtu 2>/dev/null || true
log "STEP 5d: lower-only live WireGuard MTU reconciliation installed"

# ====================================================================
# STEP 6: Install CLI control tool /usr/local/sbin/noid-wan-strict
# ====================================================================
# User-facing CLI for pause/resume/status/reset of WAN-egress-strict.
# Use-cases: Captive Portal login (pause), VPN-provider switch (reset),
# diagnostic (status), troubleshooting.
cat > /usr/local/sbin/noid-wan-strict <<'CLI_EOF'
#!/bin/bash
#
# NoID Privacy — WAN-egress-strict CLI tool (Module 06)
#
# User-facing control for the WAN-egress-strict policy. Allows pausing
# (e.g. for Captive Portal login), resuming, status inspection, full
# reset (e.g. when switching VPN provider), and manual scan-profiles
# reconciliation (= refresh literal desired state and bounded candidates).
#
# Default pause duration: 5 minutes (auto-resume via systemd-run timer).
#

set -euo pipefail

# shellcheck source=/dev/null
[ ! -r /usr/local/lib/noid-privacy/agent-install-format.sh ] || \
    NOID_FMT_AUTO_TITLE="NoID Privacy — WAN Strict" \
    NOID_FMT_AUTO_SUBTITLE="Runtime status and operations" \
    . /usr/local/lib/noid-privacy/agent-install-format.sh

NFT_FAMILY=inet
NFT_TABLE=noid_wan_strict
STATE_FILE="/var/lib/noid-privacy/wan-strict-endpoints.txt"
ARMED_FLAG="/var/lib/noid-privacy/wan-strict-armed.flag"
STATUS_FILE="/run/noid-privacy/wan-strict-status"
ENDPOINT_ENGINE="/usr/local/libexec/noid-wan-strict-endpoints"
LOG_TAG="noid-wan-strict"

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "ERROR: this command requires root (run with sudo)" >&2
        exit 1
    fi
}

require_loaded_table() {
    if ! nft list table "$NFT_FAMILY" "$NFT_TABLE" >/dev/null 2>&1; then
        echo "ERROR: WAN-strict nft table is not loaded" >&2
        exit 2
    fi
}

cmd_status() {
    "$ENDPOINT_ENGINE" publish-status
    local status_line runtime_mode
    status_line=$(cat "$STATUS_FILE" 2>/dev/null) || {
        echo "ERROR: committed WAN runtime status is unavailable" >&2
        exit 1
    }
    if [[ ! "$status_line" =~ ^MODE=(DISABLED|GRACE_BOOTSTRAP|GRACE_PAUSED|STRICT|STRICT_EMPTY|ERROR)$ ]]; then
        echo "ERROR: committed WAN runtime status has an invalid contract" >&2
        exit 1
    fi
    runtime_mode=${BASH_REMATCH[1]}

    echo "==================================================================="
    echo "  NoID Privacy WAN-egress-strict status"
    echo "==================================================================="
    echo "  Published mode: $runtime_mode"
    case "$runtime_mode" in
        STRICT)
            echo "        Host-L3 physical WAN restricted to exact durable/candidate tuples"
            ;;
        STRICT_EMPTY)
            echo "        Armed fail-closed state; no durable VPN endpoint is available"
            ;;
        GRACE_BOOTSTRAP)
            echo "        Onboarding/no-VPN decision pending; direct IPv4 WAN is available"
            ;;
        GRACE_PAUSED)
            echo "        User-requested bounded pause; direct IPv4 WAN is available"
            ;;
        DISABLED)
            echo "        User opt-out; this physical-WAN L3 layer is not enforced"
            ;;
        ERROR)
            echo "        Postcondition is unverifiable; do not infer protection"
            ;;
    esac
    echo ""

    echo "  Pinned VPN endpoint tuples (IPv4):"
    local v4
    v4=$(awk 'NR > 1 && $5 !~ /:/ && ($4 == "tcp" || $4 == "udp") \
        {printf "%s %s:%s  source=%s profile=%.8s expiry=%s\n", $4, $5, $6, $3, $1, $7}' \
        "$STATE_FILE" 2>/dev/null) || v4=""
    if [[ -z "$v4" ]]; then
        echo "    (none)"
    else
        printf '    %s\n' "${v4//$'\n'/$'\n    '}"
    fi
    echo ""

    echo "  Pinned VPN endpoint tuples (IPv6):"
    local v6
    v6=$(awk 'NR > 1 && $5 ~ /:/ && ($4 == "tcp" || $4 == "udp") \
        {printf "%s [%s]:%s  source=%s profile=%.8s expiry=%s\n", $4, $5, $6, $3, $1, $7}' \
        "$STATE_FILE" 2>/dev/null) || v6=""
    if [[ -z "$v6" ]]; then
        echo "    (none)"
    else
        printf '    %s\n' "${v6//$'\n'/$'\n    '}"
    fi
    echo ""

    echo "  Counters:"
    local counters
    if counters=$(nft list counters table "$NFT_FAMILY" "$NFT_TABLE" 2>/dev/null); then
        printf '%s\n' "$counters" \
            | grep -E '^\s+(counter|packets)' | sed 's/^/    /' || true
    else
        echo "    (unavailable — nft table is absent in $runtime_mode mode)"
    fi
    echo ""

    echo "  Persistent state-file: $STATE_FILE"
    local state_lines
    state_lines=$(awk 'END {print NR+0}' "$STATE_FILE" 2>/dev/null) || state_lines=0
    if [[ "$state_lines" -gt 1 ]]; then
        echo "    Closed v2 records (UUID fingerprint provenance tuple expiry):"
        sed 's/^/      /' "$STATE_FILE"
    else
        if [[ -e "$ARMED_FLAG" ]]; then
            echo "    (empty — armed strict mode remains fail-closed across reboot)"
        else
            echo "    (empty — unarmed direct/bootstrap grace is available)"
        fi
    fi
    echo ""
}

cmd_pause() {
    local duration="${1:-5}"

    if ! [[ "$duration" =~ ^[0-9]+$ ]] || \
       [[ "$duration" -lt 1 ]] || [[ "$duration" -gt 1440 ]]; then
        echo "ERROR: duration must be 1..1440 minutes" >&2
        exit 1
    fi

    local sec=$((duration * 60))
    # Arm fail-safe auto-resume before relaxing the nft rule. If scheduling
    # fails, strict mode has never been left.
    systemctl stop noid-wan-strict-autoresume.timer 2>/dev/null || true
    if ! systemd-run --on-active="${sec}" --unit="noid-wan-strict-autoresume" \
        --timer-property=AccuracySec=1s \
        --description="NoID Privacy auto-resume WAN-egress-strict" \
        /usr/local/sbin/noid-wan-strict resume >/dev/null 2>&1; then
        echo "ERROR: auto-resume could not be scheduled; strict mode unchanged" >&2
        exit 1
    fi
    if ! "$ENDPOINT_ENGINE" pause; then
        systemctl stop noid-wan-strict-autoresume.timer 2>/dev/null || true
        echo "ERROR: failed to enter and publish grace; strict mode restored" >&2
        exit 1
    fi

    logger -t "$LOG_TAG" "WARN: PAUSED for ${duration}min — passthrough active, privacy reduced"

    echo "WARN: WAN-egress-strict PAUSED for ${duration} minute(s)"
    echo "      Privacy reduced — direct WLAN traffic now possible."
    echo "      Auto-resume scheduled via systemd-run."
    echo ""
    echo "      Resume earlier: sudo noid-wan-strict resume"

}

cmd_resume() {
    if ! "$ENDPOINT_ENGINE" resume; then
        echo "ERROR: failed to restore strict mode" >&2
        exit 1
    fi
    systemctl stop noid-wan-strict-autoresume.timer 2>/dev/null || true

    logger -t "$LOG_TAG" "RESUMED — strict mode active"
    echo "OK: WAN-egress-strict RESUMED — strict mode active"
    local v4_set v6_set
    v4_set=$(nft list set "$NFT_FAMILY" "$NFT_TABLE" \
        vpn_endpoints_v4 2>/dev/null) || v4_set=""
    v6_set=$(nft list set "$NFT_FAMILY" "$NFT_TABLE" \
        vpn_endpoints_v6 2>/dev/null) || v6_set=""
    if [[ "$v4_set$v6_set" == *"elements = {"* ]]; then
        echo "    Exact endpoint tuples are active (see status for details)."
    else
        echo "    WARN: no endpoints pinned — connect VPN to re-pin"
    fi
}

cmd_arm_empty() {
    local confirmation_mode="${1:-interactive}"
    if [[ "$confirmation_mode" != "interactive" && "$confirmation_mode" != "--yes" ]]; then
        echo "ERROR: arm-empty accepts only the optional --yes confirmation flag" >&2
        exit 2
    fi
    echo "WARN: This will block ordinary application and forwarded physical WAN."
    echo "      Only the documented systemd-resolved bootstrap exception remains"
    echo "      until a supported VPN endpoint is available."
    echo "      The WAN-strict policy remains enabled and enters STRICT_EMPTY."
    echo ""
    if [[ "$confirmation_mode" != "--yes" ]]; then
        read -rp "Continue? (type 'yes' to confirm) " confirm
        [[ "$confirm" == "yes" ]] || { echo "Aborted."; exit 0; }
    fi

    systemctl stop noid-wan-strict-autoresume.timer 2>/dev/null || true
    if ! "$ENDPOINT_ENGINE" arm-empty; then
        echo "ERROR: transactional arm-empty transition failed" >&2
        exit 1
    fi
    logger -t "$LOG_TAG" \
        "ARM_EMPTY — ordinary physical WAN blocked; resolver bootstrap retained"
    echo "OK: STRICT_EMPTY active. Ordinary physical WAN is blocked."
    echo "    The service-UID-scoped systemd-resolved bootstrap exception remains."
    echo "    Connect a supported VPN or explicitly reset to bootstrap grace."
}

cmd_reset() {
    local confirmation_mode="${1:-interactive}"
    if [[ "$confirmation_mode" != "interactive" && "$confirmation_mode" != "--yes" ]]; then
        echo "ERROR: reset accepts only the optional --yes confirmation flag" >&2
        exit 2
    fi
    echo "WARN: This will CLEAR ALL pinned VPN endpoint tuples + reset to bootstrap-grace."
    echo "      At next VPN-up, endpoint will be re-pinned automatically."
    echo ""
    if [[ "$confirmation_mode" != "--yes" ]]; then
        read -rp "Continue? (type 'yes' to confirm) " confirm
        [[ "$confirm" == "yes" ]] || { echo "Aborted."; exit 0; }
    fi

    systemctl stop noid-wan-strict-autoresume.timer 2>/dev/null || true
    if ! "$ENDPOINT_ENGINE" reset; then
        echo "ERROR: transactional endpoint reset failed" >&2
        exit 1
    fi
    logger -t "$LOG_TAG" "RESET — endpoints cleared, grace mode active"
    echo "OK: Reset complete. Bootstrap-grace mode active."
    echo "    Connect VPN to re-pin endpoint."
}

cmd_scan_profiles() {
    # Compatibility name: this is an exact reconciliation, not additive trust.
    local helper=/usr/local/sbin/noid-wan-strict-scan-profiles.sh
    if [ ! -x "$helper" ]; then
        echo "ERROR: $helper missing or not executable" >&2
        exit 1
    fi
    "$helper"
}

cmd_help() {
    cat <<'HELP_EOF'
NoID Privacy WAN-egress-strict CLI

USAGE:
  sudo noid-wan-strict status                Show mode + endpoint tuples + counters
  sudo noid-wan-strict pause [MINUTES]       Temporarily passthrough (default 5min)
  sudo noid-wan-strict resume                Re-enable strict mode immediately
  sudo noid-wan-strict arm-empty [--yes]      Block ordinary WAN; retain resolver bootstrap
  sudo noid-wan-strict reset [--yes]          Restore onboarding/bootstrap grace
  sudo noid-wan-strict scan-profiles         Reconcile libnm profiles and bounded candidates
  sudo noid-wan-strict help                  Show this help

EDGE-CASES:
  Captive Portal (Hotel/Cafe-WLAN with HTTP-redirect login):
      sudo noid-wan-strict pause 10
      # complete portal login in browser
      # VPN reconnects automatically afterward
      # auto-resume kicks in after 10min OR run 'resume' manually

  Switching VPN provider (e.g. ProtonVPN -> Mullvad):
      sudo noid-wan-strict reset
      # confirm with 'yes'
      # connect a supported profile -> literal/reconciled or authenticated state

  VPN server change (e.g. one saved endpoint to another):
      Literal-IP profiles reconcile durably. Hostname profiles receive only a
      120-second exact handshake candidate; durable promotion requires a recent
      WireGuard key handshake or a qualifying activated OpenVPN identity.

      If switching to a BRAND-NEW server (never connected before), one of:
      (a) sudo noid-wan-strict scan-profiles    # after profile created
      (b) sudo noid-wan-strict pause 5          # bounded recovery path during connect

  Force reconciliation of NetworkManager-loaded VPN profiles:
      sudo noid-wan-strict scan-profiles

  Diagnose connection issues:
      sudo noid-wan-strict status
      sudo journalctl -t noid-wan-strict -t noid-wan-strict-scan -t noid-vpn-endpoint-pin
      sudo nft list table inet noid_wan_strict

DOCUMENTATION:
  /usr/share/doc/noid-privacy/wan-egress-strict.md
HELP_EOF
}

case "${1:-help}" in
    status)
        [[ "$#" -eq 1 ]] || { echo "ERROR: status accepts no arguments" >&2; exit 2; }
        require_root
        cmd_status
        ;;
    pause)
        [[ "$#" -le 2 ]] || { echo "ERROR: pause accepts one optional duration" >&2; exit 2; }
        require_root
        require_loaded_table
        cmd_pause "${2:-5}"
        ;;
    resume)
        [[ "$#" -eq 1 ]] || { echo "ERROR: resume accepts no arguments" >&2; exit 2; }
        require_root
        require_loaded_table
        cmd_resume
        ;;
    arm-empty)
        [[ "$#" -le 2 ]] || { echo "ERROR: arm-empty accepts only optional --yes" >&2; exit 2; }
        require_root
        require_loaded_table
        cmd_arm_empty "${2:-interactive}"
        ;;
    reset)
        [[ "$#" -le 2 ]] || { echo "ERROR: reset accepts only optional --yes" >&2; exit 2; }
        require_root
        require_loaded_table
        cmd_reset "${2:-interactive}"
        ;;
    scan-profiles)
        [[ "$#" -eq 1 ]] || { echo "ERROR: scan-profiles accepts no arguments" >&2; exit 2; }
        require_root
        require_loaded_table
        cmd_scan_profiles
        ;;
    help|-h|--help)
        [[ "$#" -le 1 ]] || { echo "ERROR: help accepts no arguments" >&2; exit 2; }
        cmd_help
        ;;
    *)
        echo "Unknown command: $1" >&2
        cmd_help
        exit 2
        ;;
esac
CLI_EOF
chmod 755 /usr/local/sbin/noid-wan-strict
chown root:root /usr/local/sbin/noid-wan-strict
log "STEP 6: /usr/local/sbin/noid-wan-strict CLI installed"

# ====================================================================
# STEP 6c: libnm reconciliation wrapper + path/service triggers
# ====================================================================
# Literal addresses become durable desired state. Hostnames receive only
# timeout-bounded handshake candidates; the VPN-up dispatcher separately owns
# authenticated promotion. Re-running replaces, rather than grows, state.
mkdir -p /usr/local/sbin
cat > /usr/local/sbin/noid-wan-strict-scan-profiles.sh <<'SCAN_PROFILES_EOF'
#!/bin/bash
# Compatibility entry point. The controller reads NetworkManager's loaded
# profiles through libnm, atomically replaces the durable literal/authenticated
# desired set, and refreshes only timeout-bounded DNS handshake candidates.
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
if [ "$#" -ne 0 ]; then
    echo "noid-wan-strict-scan-profiles.sh: no arguments accepted" >&2
    exit 2
fi

[ -e /var/lib/noid-privacy/wan-strict-disabled.flag ] && exit 0
ENGINE=/usr/local/libexec/noid-wan-strict-endpoints

"$ENGINE" reconcile
logger -t noid-wan-strict-scan \
    "loaded-profile endpoint state and bounded candidates reconciled"
exit 0
SCAN_PROFILES_EOF
chmod 700 /usr/local/sbin/noid-wan-strict-scan-profiles.sh
chown root:root /usr/local/sbin/noid-wan-strict-scan-profiles.sh
log "STEP 6c: /usr/local/sbin/noid-wan-strict-scan-profiles.sh installed"

# Reconcile after physical activation and on NetworkManager's DNS-change event.
# A dynamic VPN client can also Reapply a transient endpoint host route before
# it creates a tunnel profile. NetworkManager's documented no-wait directory
# starts that narrow reconciliation immediately; the controller re-reads the
# current applied state under its own lock so an obsolete queued event cannot
# replay an old route. Hostname resolution remains a post-up operation.
mkdir -p /etc/NetworkManager/dispatcher.d/no-wait.d
cat > /etc/NetworkManager/dispatcher.d/no-wait.d/55-wan-strict-scan-on-network-up <<'SCAN_UP_EOF'
#!/bin/bash
# Reconcile saved endpoints and transient VPN bootstrap host routes.
set -euo pipefail

IFACE="${1:-}"
ACTION="${2:-}"
SCANNER=/usr/local/sbin/noid-wan-strict-scan-profiles.sh
ENGINE=/usr/local/libexec/noid-wan-strict-endpoints
DISABLED_FLAG=/var/lib/noid-privacy/wan-strict-disabled.flag

[ ! -e "$DISABLED_FLAG" ] || exit 0

case "$ACTION" in
    up)
        [ -n "$IFACE" ] || exit 0
        [ -d "/sys/class/net/$IFACE/device" ] || exit 0
        ;;
    reapply)
        [ -n "$IFACE" ] || exit 0
        [ -d "/sys/class/net/$IFACE/device" ] || exit 0
        UUID="${CONNECTION_UUID:-}"
        [ -n "$UUID" ] || exit 0
        [ -x "$ENGINE" ] || {
            logger -t noid-wan-strict-scan \
                "ERROR: endpoint controller missing during physical reapply"
            exit 1
        }
        if ! "$ENGINE" reconcile-bootstrap --interface "$IFACE" --uuid "$UUID"; then
            logger -t noid-wan-strict-scan \
                "ERROR: transient VPN bootstrap-route reconciliation failed"
            exit 1
        fi
        logger -t noid-wan-strict-scan \
            "transient VPN bootstrap routes reconciled"
        exit 0
        ;;
    dns-change) ;;
    *) exit 0 ;;
esac
[ -x "$SCANNER" ] || {
    logger -t noid-wan-strict-scan "ERROR: endpoint scanner missing"
    exit 1
}

if ! "$SCANNER"; then
    logger -t noid-wan-strict-scan "ERROR: physical-up endpoint scan failed"
    exit 1
fi
SCAN_UP_EOF
chmod 700 /etc/NetworkManager/dispatcher.d/no-wait.d/55-wan-strict-scan-on-network-up
chown root:root /etc/NetworkManager/dispatcher.d/no-wait.d/55-wan-strict-scan-on-network-up
ln -sfn no-wait.d/55-wan-strict-scan-on-network-up \
    /etc/NetworkManager/dispatcher.d/55-wan-strict-scan-on-network-up
restorecon -F /etc/NetworkManager/dispatcher.d/no-wait.d/55-wan-strict-scan-on-network-up \
    /etc/NetworkManager/dispatcher.d/55-wan-strict-scan-on-network-up 2>/dev/null || true
log "STEP 6c: no-wait physical-up/reapply endpoint reconciliation installed"

# Path-unit: watches NM system-connections for profile changes (auto-fires
# on file create/modify/delete from ProtonVPN-app, nmcli, etc.)
cat > /etc/systemd/system/noid-wan-strict-scan-profiles.path <<'PATH_EOF'
[Unit]
Description=NoID Privacy — Watch NM connection-profiles for changes, trigger wan-strict re-scan
Documentation=man:nft(8)
# After/Wants NetworkManager.service REMOVED — caused
# ordering-cycle (basic.target → paths.target → this path → NetworkManager
# → network-pre → firewalld → basic.target). Path units use inotify
# (kernel-level) and work regardless of network state. The triggered
# service (.service) keeps After=NetworkManager.service so the actual
# nft work happens after NM is ready.

[Path]
# Watch system-wide profile directory (where ProtonVPN-app/nmcli writes new
# connection profiles). PathChanged fires on any file create/modify/delete.
# Triggers exact libnm reconciliation after create/modify/delete.
PathChanged=/etc/NetworkManager/system-connections

[Install]
WantedBy=multi-user.target
PATH_EOF
chmod 644 /etc/systemd/system/noid-wan-strict-scan-profiles.path
chown root:root /etc/systemd/system/noid-wan-strict-scan-profiles.path
log "STEP 6c: /etc/systemd/system/noid-wan-strict-scan-profiles.path installed"

# Service-unit: oneshot that runs helper. Triggered by path-unit only.
# Hardening: minimal (needs read /etc/NetworkManager + write /var/lib/noid-
# privacy + invoke nft). No PrivateNetwork because we use nft.
cat > /etc/systemd/system/noid-wan-strict-scan-profiles.service <<'SERVICE_EOF'
[Unit]
Description=NoID Privacy — reconcile loaded VPN endpoint profiles
Documentation=man:nft(8)
After=noid-wan-strict.service NetworkManager.service
# Only meaningful when wan-strict is active. If service inactive, the
# controller's nft transaction fails visibly if the table is unavailable.

[Service]
Type=oneshot
# `After=` alone is satisfied by a NetworkManager job that failed on one of its
# own dependencies, so this unit can be released while no daemon is listening.
# Both the reload and the libnm-based scanner need that daemon: without the
# gate, the unconditional ExecStartPre turns every NM-less boot into a second
# red unit, and the path unit re-arms the same failure on each profile change.
# ExecCondition= ends the run as cleanly skipped instead of failed. PathChanged=
# does not replay a consumed event merely because NetworkManager returns; M04's
# gateway/XDP readiness publication and the boot bootstrap are the independent
# reconciliation re-entry points.
ExecCondition=/usr/bin/systemctl is-active --quiet NetworkManager.service
ExecStartPre=/usr/bin/nmcli connection reload
ExecStart=/usr/local/sbin/noid-wan-strict-scan-profiles.sh
# Hardening — the controller needs libnm/DNS reads, nft netlink and only its
# shared NoID Privacy state plus the pre-created transaction lock writable.
UMask=0077
ProtectSystem=strict
ReadWritePaths=/var/lib/noid-privacy /run/noid-privacy /run/lock/noid-wan-strict.lock
ProtectHome=yes
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_ADMIN
PrivateTmp=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
SystemCallArchitectures=native
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectClock=yes
ProtectHostname=yes
ProtectControlGroups=yes
RestrictNamespaces=yes

[Install]
# Not WantedBy anything — triggered by the .path unit only.
SERVICE_EOF
chmod 644 /etc/systemd/system/noid-wan-strict-scan-profiles.service
chown root:root /etc/systemd/system/noid-wan-strict-scan-profiles.service
log "STEP 6c: /etc/systemd/system/noid-wan-strict-scan-profiles.service installed"

# ====================================================================
# STEP 6d: unmanaged-tunnel hotplug reconciliation
# ====================================================================
# wg-quick, Mullvad's own daemon and systemd-networkd configure kernel
# WireGuard directly. NetworkManager does emit dispatcher events for the
# profile it invents for such a device, but that profile names no peer
# endpoint, so the endpoint dispatcher has nothing to commit from it; and the
# profile path-unit watches keyfiles that never appear. Neither existing
# trigger therefore yields the endpoint. udev does: the kernel
# emits `add` on the net subsystem with DEVTYPE=wireguard and the device is
# already tagged for systemd. Verified on the reference host 2026-08-02.
#
# The reconciliation is global and idempotent, so this is deliberately NOT a
# templated per-interface unit: systemd merges concurrent start requests for
# one oneshot, and the controller reads every interface at the moment it runs.
# Two interfaces appearing within the same run are therefore covered by the
# merged job unless the second appears after that read, in which case the
# ordinary profile, DNS and expiry re-entry points pick it up.
cat > /etc/systemd/system/noid-wan-strict-tunnel-scan.service <<'TUNNEL_SCAN_SERVICE_EOF'
[Unit]
Description=NoID Privacy — reconcile endpoints of unmanaged kernel tunnels
Documentation=man:wg(8)
After=noid-wan-strict.service NetworkManager.service

[Service]
Type=oneshot
# The controller reads NetworkManager's loaded model through libnm on the same
# pass, so it needs that daemon exactly as the profile scanner does. Without
# the gate a tunnel brought up before NetworkManager is ready would leave a red
# unit instead of a cleanly skipped one; the boot bootstrap and the ordinary
# reconciliation entry points remain the independent re-entry.
ExecCondition=/usr/bin/systemctl is-active --quiet NetworkManager.service
ExecStart=/usr/local/sbin/noid-wan-strict-scan-profiles.sh
# Identical hardening to the profile scanner: same binary, same state, same
# netlink need. No nmcli reload -- no keyfile changed.
UMask=0077
ProtectSystem=strict
ReadWritePaths=/var/lib/noid-privacy /run/noid-privacy /run/lock/noid-wan-strict.lock
ProtectHome=yes
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_ADMIN
PrivateTmp=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
SystemCallArchitectures=native
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectClock=yes
ProtectHostname=yes
ProtectControlGroups=yes
RestrictNamespaces=yes

[Install]
# Not WantedBy anything — triggered by the udev rule only.
TUNNEL_SCAN_SERVICE_EOF
chmod 644 /etc/systemd/system/noid-wan-strict-tunnel-scan.service
chown root:root /etc/systemd/system/noid-wan-strict-tunnel-scan.service
log "STEP 6d: /etc/systemd/system/noid-wan-strict-tunnel-scan.service installed"

mkdir -p /etc/udev/rules.d
cat > /etc/udev/rules.d/71-noid-wan-strict-tunnel-hotplug.rules <<'TUNNEL_HOTPLUG_UDEV_EOF'
# Pin the endpoint of a kernel WireGuard tunnel that no NetworkManager profile
# describes, before its first handshake needs to pass the physical boundary.
SUBSYSTEM=="net", ACTION=="add", ENV{DEVTYPE}=="wireguard", TAG+="systemd", ENV{SYSTEMD_WANTS}+="noid-wan-strict-tunnel-scan.service"
TUNNEL_HOTPLUG_UDEV_EOF
chmod 0644 /etc/udev/rules.d/71-noid-wan-strict-tunnel-hotplug.rules
chown root:root /etc/udev/rules.d/71-noid-wan-strict-tunnel-hotplug.rules
log "STEP 6d: unmanaged-tunnel udev hotplug rule installed"

# Authenticated hostname records carry a hard expiry. nft enforces their
# per-element timeout immediately; this timer also prunes the readable state
# file and republishes the exact durable set without refreshing DNS candidates.
cat > /etc/systemd/system/noid-wan-strict-endpoint-expiry.service <<'ENDPOINT_EXPIRY_SERVICE_EOF'
[Unit]
Description=NoID Privacy — prune expired authenticated WAN endpoints
After=noid-wan-strict.service NetworkManager.service
ConditionPathExists=!/var/lib/noid-privacy/wan-strict-disabled.flag

[Service]
Type=oneshot
ExecStart=/usr/local/libexec/noid-wan-strict-endpoints expire
UMask=0077
ProtectSystem=strict
ReadWritePaths=/var/lib/noid-privacy /run/noid-privacy /run/lock/noid-wan-strict.lock
ProtectHome=yes
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_ADMIN
PrivateTmp=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
SystemCallArchitectures=native
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectClock=yes
ProtectHostname=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
ENDPOINT_EXPIRY_SERVICE_EOF

cat > /etc/systemd/system/noid-wan-strict-endpoint-expiry.timer <<'ENDPOINT_EXPIRY_TIMER_EOF'
[Unit]
Description=NoID Privacy — periodic authenticated WAN-endpoint expiry

[Timer]
OnBootSec=5min
OnUnitActiveSec=5min
AccuracySec=30s
Unit=noid-wan-strict-endpoint-expiry.service

[Install]
WantedBy=timers.target
ENDPOINT_EXPIRY_TIMER_EOF
chmod 0644 /etc/systemd/system/noid-wan-strict-endpoint-expiry.service \
    /etc/systemd/system/noid-wan-strict-endpoint-expiry.timer
chown root:root /etc/systemd/system/noid-wan-strict-endpoint-expiry.service \
    /etc/systemd/system/noid-wan-strict-endpoint-expiry.timer
log "STEP 6c: authenticated endpoint expiry service/timer installed"

# Enable path and expiry triggers. Both services remain static.
systemctl daemon-reload
systemctl enable noid-wan-strict-scan-profiles.path
systemctl enable noid-wan-strict-endpoint-expiry.timer
log "STEP 6c: noid-wan-strict-scan-profiles.path enabled (auto-fires on profile changes)"

# ====================================================================
# STEP 6b: /usr/local/sbin/noid-toggle-wan-strict
# ====================================================================
# User-facing on/off toggle (pattern, paired with the M36 GUI app).
# off → service disabled + nft table deleted + flag-file created (the
# flag is the single source of truth; dispatchers stay 0700 — see the
# header Design constraints). on → flag removed FIRST, then enable+start
# (bootstrap re-arms the table; loaded profiles reconcile after NM events).
# The deployed toggle script below owns the complete transition details.

cat > /usr/local/sbin/noid-toggle-wan-strict <<'TOGGLE_WAN_STRICT_EOF'
#!/bin/bash
# noid-toggle-wan-strict — enable or disable the WAN-egress-strict policy.
#
# Disabled state (user opt-in, removes privacy protection):
#   - noid-wan-strict.service disabled + stopped (mask not used because
#     the unit file lives in /etc/systemd/system/ — mask would conflict
#     with the regular file; disable equivalently prevents boot-start)
#   - profile watcher and endpoint-expiry timer disabled + stopped, so opt-out
#     has no periodic or profile-change background activation
#   - noid-wan-strict-autoresume.timer stopped (if active from prior 'pause')
#   - nft table 'inet noid_wan_strict' deleted
#   - flag-file /var/lib/noid-privacy/wan-strict-disabled.flag created —
#     this is the single source of truth; dispatcher 60-vpn-endpoint-pin
#     has an early-exit guard that checks this file and exits 0 silently
#     when present (replaces an earlier chmod 0600 mechanism which
#     caused 5+ "Cannot execute" NM-dispatcher journal-spam per boot)
#
# Enabled state (NoID Privacy default):
#   - noid-wan-strict.service unmasked (safety, in case of prior manual mask)
#     + enabled + started — bootstrap restores validated unexpired state, then
#     the libnm reconciler processes currently loaded profiles
#   - profile watcher and endpoint-expiry timer enabled + started
#   - flag-file removed
#
# Note: dispatcher /etc/NetworkManager/dispatcher.d/60-vpn-endpoint-pin
# remains mode 0700 in BOTH states. The flag-file early-exit
# inside the dispatcher is the disable-mechanism, not chmod.
#
# Usage:
#   sudo noid-toggle-wan-strict on     # enable (NoID Privacy default)
#   sudo noid-toggle-wan-strict off    # disable (user opt-in, confirms first)
#   noid-toggle-wan-strict             # show status (no root required)

set -euo pipefail

# shellcheck source=/dev/null
[ ! -r /usr/local/lib/noid-privacy/agent-install-format.sh ] || \
    NOID_FMT_AUTO_TITLE="NoID Privacy — WAN Strict" \
    NOID_FMT_AUTO_SUBTITLE="Physical-WAN egress policy" \
    . /usr/local/lib/noid-privacy/agent-install-format.sh

FLAG=/var/lib/noid-privacy/wan-strict-disabled.flag
SERVICE=noid-wan-strict.service
PROFILE_PATH=noid-wan-strict-scan-profiles.path
PROFILE_SERVICE=noid-wan-strict-scan-profiles.service
EXPIRY_TIMER=noid-wan-strict-endpoint-expiry.timer
EXPIRY_SERVICE=noid-wan-strict-endpoint-expiry.service
AUTORESUME_TIMER=noid-wan-strict-autoresume.timer
AUTORESUME_SERVICE=noid-wan-strict-autoresume.service
DISPATCHER=/etc/NetworkManager/dispatcher.d/60-vpn-endpoint-pin
NFT_FAMILY=inet
NFT_TABLE=noid_wan_strict
STATUS_PUBLISHER=/usr/local/sbin/noid-wan-strict-publish-status
STATUS_FILE=/run/noid-privacy/wan-strict-status
SCANNER=/usr/local/sbin/noid-wan-strict-scan-profiles.sh
ENDPOINT_ENGINE=/usr/local/libexec/noid-wan-strict-endpoints

ACTION="${1:-status}"
CONFIRMATION_MODE="${2:-interactive}"

require_root() {
    [ "$(id -u)" -eq 0 ] || {
        echo "ERROR: '$ACTION' requires root (use sudo or pkexec)." >&2
        exit 1
    }
}

service_state() {
    systemctl is-enabled "$SERVICE" 2>/dev/null || true
}

service_is_off() {
    local s
    s="$(service_state)"
    [ "$s" = "disabled" ] || [ "$s" = "masked" ]
}

# A failed unit is not running, and systemd keeps it in ActiveState=failed
# until `reset-failed` -- a successful `systemctl stop` does NOT clear it.
# Verified on an installed host: a oneshot that exits non-zero reports
# `failed`, still reports `failed` after `systemctl stop`, and only reaches
# `inactive` after `reset-failed`. Treating `failed` as still-active therefore
# made every stop postcondition below permanently unsatisfiable, so a single
# transient unit failure left `noid-toggle-wan-strict off` broken for good.
# The name says not-running rather than inactive because that is what the
# callers actually need to know.
unit_is_not_running() {
    local state
    state=$(systemctl show --property=ActiveState --value "$1" 2>/dev/null || true)
    [ -z "$state" ] || [ "$state" = "inactive" ] || [ "$state" = "failed" ]
}

stop_unit_if_running() {
    # Retire a residual failure so the unit ends in a genuine `inactive` state:
    # otherwise `systemctl is-failed` would keep reporting a fault for a unit
    # this toggle deliberately turned off. The journal keeps the failure
    # record; only the latched state is cleared. reset-failed is a no-op on a
    # healthy unit and must not turn an unknown unit name into a hard error.
    if unit_is_not_running "$1"; then
        systemctl reset-failed "$1" 2>/dev/null || true
        return 0
    fi
    systemctl stop "$1" || return 1
    systemctl reset-failed "$1" 2>/dev/null || true
    unit_is_not_running "$1"
}

main_service_is_off() {
    service_is_off && unit_is_not_running "$SERVICE"
}

unit_is_off() {
    local state
    state=$(systemctl is-enabled "$1" 2>/dev/null || true)
    [ "$state" = "disabled" ] || [ "$state" = "masked" ]
}

auxiliary_units_are_off() {
    unit_is_off "$PROFILE_PATH" && unit_is_off "$EXPIRY_TIMER" \
        && unit_is_not_running "$PROFILE_PATH" \
        && unit_is_not_running "$PROFILE_SERVICE" \
        && unit_is_not_running "$EXPIRY_TIMER" \
        && unit_is_not_running "$EXPIRY_SERVICE" \
        && unit_is_not_running "$AUTORESUME_TIMER" \
        && unit_is_not_running "$AUTORESUME_SERVICE"
}

auxiliary_units_are_on() {
    systemctl is-enabled --quiet "$PROFILE_PATH" \
        && systemctl is-enabled --quiet "$EXPIRY_TIMER" \
        && systemctl is-active --quiet "$PROFILE_PATH" \
        && systemctl is-active --quiet "$EXPIRY_TIMER"
}

quiesce_auxiliary_units() {
    local unit failed=0
    # Stop activators first so no new one-shot job can be queued while the
    # already-triggered services are drained.
    for unit in "$PROFILE_PATH" "$EXPIRY_TIMER" "$AUTORESUME_TIMER" \
                "$PROFILE_SERVICE" "$EXPIRY_SERVICE" "$AUTORESUME_SERVICE"; do
        if ! stop_unit_if_running "$unit"; then
            echo "WARN: could not quiesce $unit" >&2
            failed=1
        fi
    done
    if ! systemctl disable "$PROFILE_PATH" "$EXPIRY_TIMER"; then
        echo "WARN: could not disable M06 persistent activators" >&2
        failed=1
    fi
    auxiliary_units_are_off || failed=1
    return "$failed"
}

nft_table_present() {
    nft list table "$NFT_FAMILY" "$NFT_TABLE" >/dev/null 2>&1
}

dispatcher_executable() {
    [ -x "$DISPATCHER" ]
}

read_runtime_mode() {
    local parent_metadata metadata line bytes lines mode
    parent_metadata=$(stat -c '%u:%g:%a' "${STATUS_FILE%/*}" 2>/dev/null) || {
        echo ERROR
        return
    }
    [ "$parent_metadata" = "0:0:755" ] \
        && [ ! -L "${STATUS_FILE%/*}" ] || {
        echo ERROR
        return
    }
    if [ ! -f "$STATUS_FILE" ] || [ -L "$STATUS_FILE" ]; then
        echo UNKNOWN
        return
    fi
    metadata=$(stat -c '%u:%g:%a:%h' "$STATUS_FILE" 2>/dev/null) || {
        echo ERROR
        return
    }
    [ "$metadata" = "0:0:644:1" ] || {
        echo ERROR
        return
    }
    IFS= read -r line < "$STATUS_FILE" || {
        echo ERROR
        return
    }
    bytes=$(wc -c < "$STATUS_FILE") || {
        echo ERROR
        return
    }
    lines=$(wc -l < "$STATUS_FILE") || {
        echo ERROR
        return
    }
    [ "$lines" -eq 1 ] && [ "$bytes" -eq $((${#line} + 1)) ] || {
        echo ERROR
        return
    }
    case "$line" in
        MODE=DISABLED|MODE=GRACE_BOOTSTRAP|MODE=GRACE_PAUSED|MODE=STRICT|MODE=STRICT_EMPTY|MODE=ERROR)
            mode=${line#MODE=}
            echo "$mode"
            ;;
        *) echo ERROR ;;
    esac
}

runtime_mode_detail() {
    case "$1" in
        DISABLED) echo "user opt-out; M06 host-L3 physical-WAN policy absent" ;;
        GRACE_BOOTSTRAP) echo "onboarding/no-VPN decision pending; direct IPv4 WAN available" ;;
        GRACE_PAUSED) echo "bounded user pause; direct IPv4 WAN available" ;;
        STRICT) echo "durable VPN tuples active; bounded DNS candidates possible" ;;
        STRICT_EMPTY) echo "armed fail-closed state with no durable endpoint" ;;
        ERROR) echo "published postcondition reports failure; do not infer protection" ;;
        UNKNOWN) echo "no valid postcondition is available; do not infer protection" ;;
    esac
}

rollback_failed_enable() {
    if ! quiesce_auxiliary_units; then
        echo "WARN: rollback could not quiesce M06 background units; policy remains enforced" >&2
        return 1
    fi
    if ! stop_unit_if_running "$SERVICE"; then
        echo "WARN: rollback could not stop $SERVICE; policy remains enforced" >&2
        return 1
    fi
    if ! systemctl disable "$SERVICE"; then
        echo "WARN: rollback could not disable $SERVICE; policy remains enforced" >&2
        return 1
    fi
    if ! main_service_is_off; then
        echo "WARN: rollback did not quiesce $SERVICE; policy remains enforced" >&2
        return 1
    fi
    if ! "$ENDPOINT_ENGINE" disable; then
        echo "WARN: rollback could not restore the locked disabled state" >&2
        return 1
    fi
    if [ -x "$STATUS_PUBLISHER" ] && ! "$STATUS_PUBLISHER"; then
        echo "WARN: rollback status publication failed" >&2
        return 1
    fi
    return 0
}

case "$ACTION" in
    on|enable)
        [ "$#" -eq 1 ] || {
            echo "ERROR: '$ACTION' accepts no additional arguments" >&2
            exit 2
        }
        require_root
        if ! systemctl unmask "$SERVICE"; then
            echo "ERROR: could not unmask $SERVICE; WAN strict remains disabled." >&2
            exit 1
        fi
        # The controller removes the flag and installs the complete nft policy
        # under its shared lock before systemd starts the persistent service.
        # No dispatcher chmod fiddling: the dispatcher stays mode 0700 always;
        # the flag-file is the single source of truth for disabled/enabled
        # state.
        if ! "$ENDPOINT_ENGINE" enable; then
            echo "ERROR: could not commit enabled WAN-strict state." >&2
            if ! rollback_failed_enable; then
                echo "ERROR: rollback was incomplete; inspect systemctl/nft state." >&2
            fi
            exit 1
        fi
        # enable+start restores the closed persisted state. The explicit libnm
        # reconciliation below covers profiles already loaded by NetworkManager.
        if ! systemctl enable --now "$SERVICE"; then
            echo "ERROR: could not enable/start $SERVICE; rolling back." >&2
            if ! rollback_failed_enable; then
                echo "ERROR: rollback was incomplete; inspect systemctl/nft state." >&2
            fi
            exit 1
        fi
        if ! systemctl enable --now "$PROFILE_PATH" "$EXPIRY_TIMER"; then
            echo "ERROR: could not enable/start M06 background units; rolling back." >&2
            if ! rollback_failed_enable; then
                echo "ERROR: rollback was incomplete; inspect systemctl/nft state." >&2
            fi
            exit 1
        fi
        if ! systemctl is-enabled --quiet "$SERVICE" || \
           ! systemctl is-active --quiet "$SERVICE" || \
           ! auxiliary_units_are_on || \
           ! nft_table_present || ! dispatcher_executable; then
            echo "ERROR: WAN-strict post-enable verification failed; rolling back." >&2
            if ! rollback_failed_enable; then
                echo "ERROR: rollback was incomplete; inspect systemctl/nft state." >&2
            fi
            exit 1
        fi
        if ! "$SCANNER"; then
            echo "ERROR: WAN-strict profile reconciliation failed; rolling back." >&2
            if ! rollback_failed_enable; then
                echo "ERROR: rollback was incomplete; inspect systemctl/nft state." >&2
            fi
            exit 1
        fi
        "$STATUS_PUBLISHER"
        echo "[OK] WAN-egress-strict ENABLED (NoID Privacy default restored)."
        echo "      Loaded profiles reconciled; hostname candidates remain bounded."
        echo "      Authenticated endpoint promotion occurs on tunnel activation."
        echo "      Disable again: sudo noid-toggle-wan-strict off"
        ;;
    off|disable)
        [ "$#" -le 2 ] || {
            echo "ERROR: '$ACTION' accepts only the optional --yes confirmation flag" >&2
            exit 2
        }
        require_root
        if [ "$CONFIRMATION_MODE" != "interactive" ] && \
           [ "$CONFIRMATION_MODE" != "--yes" ]; then
            echo "ERROR: '$ACTION' accepts only the optional --yes confirmation flag" >&2
            exit 2
        fi
        echo "WARN: Disabling WAN-egress-strict removes critical privacy protection."
        echo "      Direct physical-WAN traffic + SO_BINDTODEVICE bypass become possible."
        if [ "$CONFIRMATION_MODE" != "--yes" ]; then
            read -rp "Continue? (type 'yes' to confirm) " confirm
            [ "$confirm" = "yes" ] || { echo "Aborted."; exit 0; }
        fi

        # Flag-file is single source of truth — dispatcher
        # has early-exit guard checking this file. No more chmod 0600 on
        # the dispatcher (the earlier chmod 0600 design caused 5+ "Cannot execute" errors per
        # boot in journal via NM-dispatcher polling on every NM event).
        if ! quiesce_auxiliary_units; then
            echo "ERROR: M06 background work could not be quiesced; policy remains enforced." >&2
            exit 1
        fi
        if ! stop_unit_if_running "$SERVICE"; then
            echo "ERROR: could not stop $SERVICE" >&2
            exit 1
        fi
        if ! systemctl disable "$SERVICE"; then
            echo "ERROR: could not disable $SERVICE" >&2
            exit 1
        fi
        if ! main_service_is_off; then
            echo "ERROR: $SERVICE did not reach the exact disabled/inactive state" >&2
            exit 1
        fi
        if ! "$ENDPOINT_ENGINE" disable; then
            echo "ERROR: could not commit the locked disabled state" >&2
            exit 1
        fi
        "$STATUS_PUBLISHER"
        echo "[OK] WAN-egress-strict DISABLED."
        echo "      Enable again: sudo noid-toggle-wan-strict on"
        ;;
    status|"")
        [ "$#" -le 1 ] || {
            echo "ERROR: status accepts no additional arguments" >&2
            exit 2
        }
        svc_state="$(service_state)"
        [ -z "$svc_state" ] && svc_state="unknown"
        flag_state="absent"
        [ -f "$FLAG" ] && flag_state="present"
        runtime_mode=$(read_runtime_mode)
        runtime_detail=$(runtime_mode_detail "$runtime_mode")

        if [ "$(id -u)" -ne 0 ]; then
            # The root publisher already validated nft/flag/failure state.
            # Non-root output consumes that contract and never infers an
            # optimistic mode from flag absence.
            echo "WAN-egress-strict state (published runtime contract):"
            echo "  noid-wan-strict.service: $svc_state"
            echo "  runtime mode:             $runtime_mode"
            echo
            echo "-> $runtime_mode — $runtime_detail"
            exit 0
        fi

        nft_state="absent"
        nft_table_present && nft_state="present"
        disp_state="non-executable"
        dispatcher_executable && disp_state="executable"

        echo "WAN-egress-strict state (system-level):"
        echo "  noid-wan-strict.service: $svc_state"
        echo "  nft table:               $nft_state"
        echo "  dispatcher exec-bit:     $disp_state  (expected: executable)"
        echo "  flag-file:               $flag_state"
        echo "  published runtime mode:  $runtime_mode"
        echo
        echo "-> $runtime_mode — $runtime_detail"
        case "$runtime_mode" in
            DISABLED)
                if main_service_is_off && [ "$nft_state" = "absent" ] && \
                   [ "$flag_state" = "present" ] && auxiliary_units_are_off; then
                    echo "   Layer consistency: exact disabled postcondition"
                else
                    echo "   Layer consistency: MIXED; inspect before normalizing"
                fi
                ;;
            GRACE_BOOTSTRAP|GRACE_PAUSED|STRICT|STRICT_EMPTY)
                if [ "$svc_state" = "enabled" ] && [ "$nft_state" = "present" ] && \
                   [ "$flag_state" = "absent" ] && auxiliary_units_are_on; then
                    echo "   Layer consistency: exact active-policy postcondition"
                else
                    echo "   Layer consistency: MIXED; inspect before normalizing"
                fi
                ;;
            ERROR|UNKNOWN)
                echo "   Layer consistency: unverifiable; inspect service and nft state"
                ;;
        esac
        ;;
    *)
        echo "Usage: noid-toggle-wan-strict [on|off|status]" >&2
        exit 1
        ;;
esac
TOGGLE_WAN_STRICT_EOF
chmod 0755 /usr/local/sbin/noid-toggle-wan-strict
chown root:root /usr/local/sbin/noid-toggle-wan-strict
log "STEP 6b: /usr/local/sbin/noid-toggle-wan-strict CLI installed"

# ====================================================================
# STEP 7: Install user-facing documentation
# ====================================================================
# /usr/share/doc/noid-privacy/wan-egress-strict.md — explains why this
# layer exists, how endpoint trust/reconciliation works, edge-cases and CLI.
# User-facing because mandatory reading for Captive-Portal scenarios.
mkdir -p /usr/share/doc/noid-privacy
cat > /usr/share/doc/noid-privacy/wan-egress-strict.md <<'DOC_EOF'
# WAN-Egress-Strict — physical-interface egress boundary

NoID Privacy enables an nftables policy that blocks public-IP egress on hardware-backed
interfaces unless a packet matches a narrowly defined exception. This closes a
class of default-route bypasses such as `SO_BINDTODEVICE` or
`curl --interface <physical-iface>`. It is an independent backstop, not proof
that a VPN client, DNS resolver, LAN, firmware or application is leak-free.

Local-address traffic continues to Module 03, which owns the separate LAN
destination boundary. A never-armed installation starts in the disclosed
IPv4 bootstrap-grace mode so a user can obtain and configure a VPN. This is an
onboarding state, not active strict enforcement. Once strict mode has been
armed, an empty endpoint set stays fail-closed across reboot and every tunnel
disconnect, including a deliberate user disconnect. Direct-WAN grace then
requires a separate explicit pause, reset or feature-disable operation.

## Onboarding and no-VPN decision

`GRACE_BOOTSTRAP` deliberately has no automatic wall-clock expiry. An expiry
could strand a new installation before the user has network access to obtain a
profile, and NoID Privacy explicitly supports operation without a VPN. The trade-off is
conspicuous direct IPv4 WAN until the user makes one of these choices:

- configure a supported literal/runtime-confirmed endpoint and verify
  `STRICT`;
- choose an armed fail-closed posture with
  `sudo noid-wan-strict arm-empty` (`STRICT_EMPTY`) while no endpoint is
  available; or
- explicitly choose no VPN with `sudo noid-toggle-wan-strict off`, which
  publishes `DISABLED` instead of pretending grace is strict protection.

`GRACE_BOOTSTRAP` therefore means “decision pending”, regardless of service
enablement or flag absence. The Network app, both CLIs and the runtime status
file display this mode directly. No component may relabel it as merely
“enabled” or infer protection from file existence.

## What the policy permits

The `inet noid_wan_strict` output and forward chains run before firewalld. They
apply only when the egress interface belongs to the boot-populated
`physical_ifaces` set.

In strict mode, physical egress is limited to:

- link/bootstrap traffic and local-address ranges that must reach later policy;
- explicit LAN exceptions synchronized by Modules 03 and 05;
- durable exact VPN `address . TCP/UDP . destination-port` tuples;
- 120-second exact hostname handshake candidates;
- 60-second local-output-only `address . TCP/UDP` bootstrap routes derived
  from a VPN client's current applied physical host routes under the documented
  software-default, gateway and profile-ownership gates; and
- DNS on TCP/UDP 53 or TCP 853 only from the `systemd-resolve` service UID.

Everything else to public IPv4/IPv6 destinations through a physical interface
is dropped and counted without destination logging. Forwarded VM/container
traffic has the same hardware-interface boundary.

The process-scoped resolver exception is necessary because pre-tunnel hostname
resolution otherwise deadlocks behind strict mode. It is not a general direct
DNS exception for applications. A process with root-equivalent control can
still bypass host policy and is outside this layer's protection claim.

## Exact threat boundary

The `inet` output hook sees IPv4/IPv6 packets sent by local processes through
the initial host network stack; the forward hook sees packets routed through
that stack. M06 filters those packets when their selected egress device is in
its boot-discovered physical-interface set. This includes ordinary
unprivileged TCP/UDP applications using route selection, socket binding or
`SO_BINDTODEVICE`.

M06 is not described as malware-proof. In particular, it does not claim to
control:

- Ethernet frames injected through an `AF_PACKET` socket by a process with
  `CAP_NET_RAW`; those operate at the device/link layer rather than proving
  traversal of the nft `inet` output hook;
- a process with `CAP_NET_ADMIN` that can change firewall, routes, interfaces
  or other network controls;
- `CAP_SYS_ADMIN`/root-equivalent control able to create or join a separately
  controlled network namespace or rearrange its devices/control plane;
- non-IP link protocols, radio/driver behavior below the host IP stack, or
  firmware out-of-band networking such as Intel AMT; or
- compromise of the kernel, nftables authority or boot trust chain.

Network namespaces have their own network devices, IP stacks, routes and
firewall rules. Traffic that is ultimately forwarded through a physical
interface still meets the host forward boundary when that path traverses this
namespace, but M06 does not promise coverage after privileged control has
moved or replaced that path. Module 03's netdev/XDP receive controls are a
separate ingress boundary and do not turn M06 into an egress link-layer filter.

## Endpoint trust states

M06 deliberately separates six different facts.

### 1. Literal profile endpoint

An endpoint already expressed as a canonical numeric IP in a NetworkManager
profile can enter durable desired state. It is bound to:

- the NetworkManager profile UUID;
- a SHA-256 fingerprint of the relevant profile endpoint/identity fields;
- transport, canonical address and destination port; and
- provenance `literal` with expiry `0`.

The profile is read from NetworkManager's loaded libnm model. M06 does not scan
keyfiles with section-blind regular expressions. NetworkManager therefore owns
keyfile parsing, accepted sections and its root-ownership/non-writable checks.

### 2. Hostname handshake candidate

For a hostname, current resolver answers enter only
`vpn_candidates_v4`/`vpn_candidates_v6`. Each exact tuple has a kernel-enforced
120-second timeout and is never written to restart state. A DNS-change event or
profile reconciliation flushes the candidate sets and replaces them with the
current desired answers.

This is intentionally labeled unauthenticated. Opportunistic DNS can be
downgraded or forged. During the short candidate window, another local process
could address the same IP, transport and port; nftables cannot prove which
application originated a WireGuard packet. The bounded window enables the
cryptographic tunnel handshake but is not equivalent to trusting the VPN
provider or server.

Users who cannot accept that residual window must use a reviewed literal-IP
profile or keep WAN-strict fail-closed and perform no hostname candidate scan.

### 3. Runtime-confirmed hostname endpoint

A hostname answer becomes durable only when the active-tunnel dispatcher can
bind the actually observed address to stronger runtime evidence:

- **WireGuard:** the peer public key is the one in the loaded profile, the
  kernel reports the same runtime address/port, and its latest authenticated
  handshake is no more than 180 seconds old.
- **OpenVPN:** NetworkManager has emitted `vpn-up`, the observed external
  gateway matches a current endpoint answer, and the loaded OpenVPN profile
  contains a CA plus `remote-cert-tls=server`, `verify-x509-name`, or
  `tls-remote` identity policy.

Other VPN plugins and hidden proprietary endpoint schemas are not guessed.
They may require a literal endpoint, a deliberate bounded pause, or disabling
this optional layer. Universal provider compatibility is not claimed.

Runtime-confirmed records use provenance `authenticated` and expire after 24
hours. nftables applies the remaining lifetime to the element itself; a
five-minute timer also prunes expired file records without refreshing DNS
candidates. A long-running hostname-based tunnel may therefore need to
reconnect before the lease expires. This availability trade-off bounds stale
direct-WAN permission.

### 4. Volatile-profile retention lease

NetworkManager keeps a profile either saved under
`/etc/NetworkManager/system-connections` or, for a profile a client added without
asking for it to be saved, only in volatile `/run` state. Both are ordinary
loaded profiles while they exist. The difference appears on disconnect: a saved
profile stays and is re-read on the next reconciliation, while a volatile one is
taken away together with the tunnel.

Re-deriving desired state from loaded profiles alone therefore unpins exactly the
address such a client is about to dial for its next attempt, and its first
packets are dropped by the layer that exists to let them through. The attempt
still succeeds on a retry, so the cost is silent latency rather than a visible
error — and it recurs at every boot and every reconnect. ProtonVPN's Linux app is
the documented case: its WireGuard profile is created under `/run` on connect and
never reaches `/etc`, while its own kill-switch dummy profile is saved normally.

When the active-tunnel dispatcher confirms an activation for a profile that is
not saved on disk, its observed tuples therefore also receive provenance
`retained`, with the same 24-hour lifetime as an authenticated lease. A
`retained` record survives the absence of its profile; no other provenance does.

The trade-off is stated plainly: for up to 24 hours after the last confirmed
activation, one exact address/transport/port tuple per observed endpoint stays
permitted on physical interfaces although no loaded profile currently names it.
That is the same permission a saved profile grants continuously, so this makes
the boundary provider-independent rather than wider. It is bounded three ways:
the lease expires on its own, the five-minute expiry timer prunes it, and
`sudo noid-wan-strict reset` revokes every record at once.

A saved profile deliberately receives no lease. Deleting one still revokes its
pin in the same reconciliation.

Such clients create a **new** profile with a **new** UUID for every server, so
without a bound a week of server hopping would leave one open tuple per server
visited. At most eight leases are live at once; when more exist the oldest
activations are pruned and the pruning is reported. A user who always reconnects
to the same server therefore holds exactly one lease, refreshed on every connect.

### 5. Unmanaged kernel tunnel

`wg-quick`, Mullvad's own daemon and `systemd-networkd` configure kernel
WireGuard directly. NetworkManager does notice the device: it assumes it behind
a profile it invents and emits `up`/`down` with `CONNECTION_EXTERNAL=1`. That
reflection is not ownership, and it is not durable — NetworkManager releases
such a device again as soon as anything writes to that invented profile, taking
the address its real creator installed with it. So nothing may write there, and
the profile-driven path cannot be relied on to learn of the tunnel; with strict
mode armed it could not complete a handshake at all.

The endpoint is in the kernel as soon as the interface is configured, before any
handshake: `wg show all endpoints` answers while `latest-handshakes` is still
`0`. Pinning it in time is therefore a discovery problem, not a chicken-and-egg
one. The trigger is a udev rule on `SUBSYSTEM=="net", ACTION=="add",
ENV{DEVTYPE}=="wireguard"`, which the kernel emits with the device already
tagged for systemd — no polling and no background daemon.

Creating or configuring a WireGuard interface requires `CAP_NET_ADMIN`, so this
source is exactly as trustworthy as a root-owned NetworkManager profile. The
identity is the peer's public key, not the interface name: `wg-quick` takes the
name from a file name and other clients rename their interface between versions,
while the peer key is the server's cryptographic identity and is what the kernel
enforces. A peer that a loaded profile already describes keeps that profile's
identity, so one tunnel never produces two competing records.

A completed handshake — the kernel's own proof that the peer answered, the same
evidence the profile-backed WireGuard path already accepts — earns the same
bounded `retained` lease, because an unmanaged tunnel leaves the kernel entirely
when it is taken down.

That proof arrives *after* the event that discovered the tunnel: udev fires when
the interface appears, seconds before the first handshake completes. Measured in
a VM against a real `wg-quick` tunnel, the reconciliation triggered by that event
therefore always saw `latest-handshakes` at `0`, and on a host whose only tunnel
is unmanaged nothing else reconciles afterwards — so the lease was never issued
and the next connect paid the full handshake retry again. The five-minute expiry
pass is the second entry point and closes that window. A lease is only issued
while none exists with more than half its lifetime left, so a periodic pass
cannot turn into a periodic write loop.

At most eight interfaces and eight peers per interface are enumerated; anything
beyond that, and any line that does not match the measured three-field output
shape, is reported rather than silently dropped.

### 6. Dynamic-client bootstrap host route

Some clients install their own software default-route killswitch, then use
NetworkManager `Reapply` to add a temporary public `/32` or `/128` route through
the physical gateway before they create the tunnel profile. Waiting for a
profile-directory event is too late for that first probe.

The physical `reapply` dispatcher therefore reads NetworkManager's current
applied connection. A route is admitted only when all of these conditions hold:

- it is an exact host route (`/32` or `/128`) in the applied connection;
- its next hop is the physical connection's current gateway;
- a non-hardware NetworkManager `dummy` connection currently owns the default
  route for the same address family;
- no more than eight destination addresses are present; and
- the exception is limited to local TCP/UDP output and expires in 60 seconds.

Whether the client also saved that route to its keyfile is deliberately not a
criterion. NetworkManager offers `Update()`/`Update2(to-disk)` next to
`Reapply`, and a client that calls both makes the applied and persistent views
identical; Proton VPN GTK 4.16.5 does exactly that. Treating that difference as
"newly added" measured only whether the keyfile flush had won the race against
the dispatcher read, so the first connection succeeded and every later one
failed permanently. It also never distinguished a client probe route from a
saved user route -- only `Update`+`Reapply` clients from `Reapply`-only ones.
The bound that carries the policy is the event plus the conditions above: the
window is re-derived from scratch on each physical `reapply`, never persisted,
and always expires. A saved user host route toward the current physical gateway
therefore does obtain the same bounded window while a software kill switch owns
the default route; only root can write such a route, and root can already pause
or disable this layer outright. The persistent profile is still read, but only
as an ownership gate: an absent profile, or one that is not root-owned with
tight modes, yields no bootstrap window at all.

Prefixes broader than one host, non-global destinations, routes
through another gateway and forwarded traffic are never admitted. The route is
not authentication evidence, is not persisted and does not arm strict mode.
Like hostname candidates, another local process could use the same short-lived
destination/transport allowance. This bounded compatibility path is narrower
than reopening bootstrap grace, but it is still an explicit residual window.

## Exact reconciliation

`/usr/local/libexec/noid-wan-strict-endpoints` is the single state authority.
All bootstrap, profile, DNS, tunnel-up/down, expiry, reset and manual
transitions use one lock. The controller computes the complete desired set,
sends one nft batch, and atomically publishes the v2 state file. If nft
publication fails, the old state bytes remain. If the later file replacement
fails, the old nft set is restored.

Bootstrap/restart does not delete the live table and load a replacement in two
steps. One nft transaction contains idempotent `destroy table`, the complete
replacement policy, physical-interface membership, endpoint/candidate sets and
grace state. The old table therefore remains active until the kernel accepts the
entire replacement. Pause, resume, reset, feature-enable and feature-disable use
the same controller lock; the disabled marker is fsynced and versioned rather
than touched outside the transaction. Runtime status is derived from exact
marker contents and nftables' machine-readable JSON state, not from
human-formatted substring matches. A missing or unreadable set, malformed JSON
or mixed flag/table/armed state publishes `ERROR` instead of an optimistic
mode. The status file is published atomically under the same lock. If status
publication after a pause fails, grace is rolled back to strict; stale status
is removed on any publication failure rather than being presented as current
evidence.

An explicit bounded pause is also part of that locked reconciliation contract.
Profile changes, DNS changes, endpoint expiry and a service bootstrap preserve
`GRACE_PAUSED` only while both the current nft grace set and its transient
auto-resume timer agree. A stale timer cannot reopen a manually resumed strict
state, and an unbounded/stale grace set cannot survive the next reconciliation.
A supported tunnel activation likewise honors the still-active user-requested
pause; the timer or an explicit `resume` closes it.

The state header and record shape are closed:

```text
NOID-WAN-ENDPOINTS-V2
PROFILE_UUID FINGERPRINT literal|authenticated|retained tcp|udp IP PORT EXPIRY_EPOCH
```

Unknown versions, extra/missing fields, non-canonical UUID/IP values, invalid
ports, duplicate records, wrong provenance/expiry combinations, symlinks,
multiple hard links, wrong owner or a mode other than `0644` fail closed.
The armed and disabled markers likewise have exact versioned one-line contents,
root:root ownership, one link and mode `0644`; the transaction lock and active
tunnel evidence are pre-created root-private through tmpfiles.

Every profile create/change/delete and DNS-change rebuilds the desired set:

- deleted profiles revoke their records;
- a changed endpoint/peer/identity fingerprint invalidates old records;
- DNS rotation replaces candidates rather than accumulating answers;
- authenticated and retained records disappear at expiry;
- literal records remain only while the matching loaded profile exists; and
- retained records are the sole exception and outlive their profile's absence,
  because for a volatile profile that absence is the client's normal
  disconnected state rather than a deletion.

Only a `literal` record may carry expiry `0`; every other provenance is bounded
evidence and must carry a deadline. Several records can describe one tuple at
once — a loaded profile and the bounded proof that the same tunnel was observed
active. They are collapsed into a single nftables element per tuple, where a
record without a deadline outranks every timed one and the longest remaining
lifetime wins among timed ones. Neither direction can add a tuple.

Physical `reapply` events independently replace both transient bootstrap-route
sets from the current applied host routes that satisfy the software-default,
current-gateway and root-owned-profile gates. The dispatcher uses
NetworkManager's `no-wait.d` mechanism for the pre-profile race, while the
controller re-reads current state under the shared lock; a queued stale event
therefore cannot replay an address that is no longer applied.

`/var/lib/noid-privacy/wan-strict-armed.flag` records either that a supported
tunnel-up runtime path committed strict mode or that the user explicitly chose
`arm-empty`. Merely saving or scanning a profile never arms the boundary.
Profile deletion, expiry, crash, carrier loss and a supported down event can
therefore produce `STRICT_EMPTY`, but cannot silently reopen `0.0.0.0/0`
grace. The marker is removed only by an explicit `noid-wan-strict reset`.

## Tunnel disconnect remains fail-closed

On supported tunnel activation, the authenticated endpoint dispatcher commits
strict state and writes a root-private active marker under
`/run/noid-privacy/wan-strict-active/`. NetworkManager's later `down` or
`vpn-down` event removes only that volatile proof. The dispatcher first
requires the matching NetworkManager tunnel event; the controller then
requires either an existing authenticated active marker or a currently
supported profile schema. Unrelated virtual-interface events are ignored. A
qualifying event does not clear the armed marker, endpoint state or nft policy.

Clean user disconnect, client quit, crash, carrier loss, suspend/shutdown and a
queued stale down event therefore all retain `STRICT` or `STRICT_EMPTY`.
NetworkManager documents that dispatcher events are queued and can run after a
newer state transition, so a teardown event is not an authorization token for a
policy downgrade.

This behavior matches the persistent or “lockdown” kill-switch model: after
arming, connecting without a VPN requires a separately visible user action.
Use a bounded `pause` for captive-portal or compatibility work, `reset` to
return to onboarding grace, or turn the optional feature off. No VPN provider is
assumed, and provider-owned kill-switch behavior remains an independent layer.

## Runtime modes

| Mode | Meaning |
|---|---|
| `GRACE_BOOTSTRAP` | Unarmed after initial setup or explicit reset; direct IPv4 WAN deliberately available |
| `GRACE_PAUSED` | User requested a bounded direct-WAN pause |
| `STRICT` | At least one durable exact endpoint record is active |
| `STRICT_EMPTY` | Armed and fail-closed, but no durable endpoint remains |
| `DISABLED` | User explicitly disabled the layer |
| `ERROR` | Bootstrap/postcondition failed; do not infer protection |

### Endpoint-discovery coverage, stated plainly

Durable endpoint pinning has two sources: NetworkManager profiles through libnm,
and the kernel's own WireGuard state for tunnels no profile describes. The honest
summary is below. This table describes endpoint extraction only; it is not a
release qualification of a provider's routes, DNS, privileged daemon or separate
kill-switch firewall.

| Tunnel as configured | Pinned durably | Consequence when it is not |
|---|---|---|
| NetworkManager WireGuard profile | yes | — |
| NetworkManager OpenVPN profile | yes | — |
| Provider client that creates its profile on connect (Proton VPN) | yes, plus a bounded lease across disconnect | — |
| `wg-quick` / `systemd-networkd` WireGuard | yes, from the kernel | does not arm the boundary by itself |
| Mullvad native WireGuard over its standard kernel/UAPI path | yes, from the kernel | as above; obfuscated/private transports are separate rows below |
| IVPN desktop client | conditional on the exposed standard WireGuard UAPI or a recognized NetworkManager OpenVPN profile | no dedicated NoID Privacy client qualification; provider firewall/daemon remain separate |
| Userspace WireGuard exposing the standard UAPI (`wireguard-go`, `boringtun`) | yes, same path as the kernel | — |
| WireGuard-derived clients with a private control channel | no | not reachable through `wg`; the bounded bootstrap route is the only path out |
| OpenVPN outside NetworkManager | no | as above |
| WireGuard over TCP, obfuscation or "stealth" transports | no | the UDP-only pin does not describe the real tuple |

The current Mullvad source documents an independently managed Linux nftables
firewall, applied atomically by its privileged daemon, and lists several
WireGuard obfuscation transports. The current IVPN desktop source documents a
privileged daemon, its own kill switch, and WireGuard/OpenVPN as the advertised
protocols. NoID Privacy neither rewrites nor treats either provider firewall as proof of
M06 compatibility. A release-specific runtime test must still verify first-hop
reachability, tunnel-down behavior, DNS and the combined nftables ruleset.
IPsec/IKEv2 is not a recognized M06 profile path and is not implied by the name
"IVPN".

Discovery is a read of `wg show all endpoints`, so it needs `wireguard-tools`
present. Module 26 ships that package, so a stock image can enumerate. A host
that lacks it — an image predating that include, or an administrator who
removed it — simply has no WireGuard tooling to enumerate, and the
reconciliation continues on its profile source alone rather than failing.

"Does not arm the boundary by itself" is measured, not assumed: on an
unarmed host a `wg-quick` tunnel produced its kernel-derived identity and a
bounded handshake lease while the mode stayed `GRACE_BOOTSTRAP`, and the same
detector recorded `STRICT` when a NetworkManager WireGuard profile came up
instead. NetworkManager does assume such a device behind a profile it invents
and does emit dispatcher events for it, but that profile names the peer's
public key with no endpoint, so the endpoint dispatcher finds no endpoint
contract to commit and the arming path is never reached.

That single read covers more than the kernel: `wg` enumerates userspace
implementations through their `/run/wireguard/<interface>.sock` UAPI before it
falls back to netlink, so `wireguard-go` and `boringtun` — the implementations
`wg-quick` itself uses via `WG_QUICK_USERSPACE_IMPLEMENTATION` — appear in the
same listing with the same fields. Verified against a UAPI stub speaking the
documented protocol: the interface is discovered, receives its own peer-key
identity and its endpoint is committed to the boundary exactly like a kernel
tunnel. A client that keeps a private control channel instead of that socket is
not reachable this way and stays outside the coverage.

**Discovery pins, it does not arm.** A tunnel found in the kernel makes its
endpoint reachable inside an already-armed boundary; it never creates the armed
marker. Arming narrows connectivity, and an unrelated kernel WireGuard interface
— a container mesh, a test tunnel — must not be able to cut a machine off its
network. Users whose only tunnel is unmanaged therefore still arm deliberately:
bring the tunnel up, then `sudo noid-wan-strict arm-empty`. The next
reconciliation re-derives the tunnel's endpoint, so the result is `STRICT` with
that tuple pinned, not `STRICT_EMPTY`.

`STRICT_EMPTY` is a correct, fail-closed state, not a fault: the layer stays
armed and never reopens `0.0.0.0/0` merely because it lost sight of an endpoint.
For the rows that remain unpinned, a first connect depends on the bounded
bootstrap host route, so plan for that rather than being surprised by it.

Separately, none of this governs *when* a client starts. An application
launched from XDG autostart can probe its server before any physical link
exists, which fails with the boundary completely uninvolved and
`wan_blocked_v4` at zero. The App Autostart switch in `noid-welcome`
(`/usr/local/bin/noid-autostart-netwait`) addresses that case and is
provider-neutral; see the Proton VPN guide's Step 3 for the reasoning.

`DISABLED` also stops and disables the profile watcher and five-minute endpoint
expiry timer, drains already-triggered scan/expiry jobs, and stops both halves
of a transient auto-resume job. Policy removal aborts while enforcement is
still present if that background work cannot be quiesced. Re-enabling the
feature restores both persistent activators before reporting an exact
active-policy postcondition. Every queued controller action also rechecks the
exact disabled marker after acquiring the shared lock, so a dispatcher event
that began before opt-out cannot recreate the table afterward. Opt-out
therefore does not leave periodic or profile-change M06 work running in the
background.

Use the root-published runtime status, not file existence alone:

```bash
sudo noid-wan-strict status
noid-toggle-wan-strict status
sudo nft list table inet noid_wan_strict
```

## Normal and edge-case behavior

| Scenario | Behavior |
|---|---|
| Normal traffic routed over an arbitrary tunnel interface | Does not match the physical-interface set |
| Public destination via `curl --interface <physical-iface>` | Dropped unless it exactly matches an endpoint/candidate tuple |
| Same endpoint IP on another port/protocol | Dropped |
| Literal saved endpoint | Reconciled durably from libnm |
| New hostname endpoint | Bounded candidate, then runtime-confirmed promotion where supported |
| Dynamic client probes before creating its profile | Current exact applied-only host route receives a 60-second local TCP/UDP window when a software dummy default route is active |
| Forged/rotated DNS answer | Candidate only; cannot directly become durable state |
| Profile changed or deleted | Old fingerprint/UUID records revoked on reconciliation |
| Clean user/client disconnect after confirmed activation | Armed strict/strict-empty remains; unrestricted WAN is not restored |
| Crash, forced loss, reboot or profile disappearance | Armed strict/strict-empty remains; unrestricted WAN is not restored |
| Captive portal | Requires a deliberate bounded pause |
| Unsupported provider schema | Fails closed or requires an explicit user-chosen compatibility path |

### Captive portal

```bash
sudo noid-wan-strict pause 10
# complete portal authentication
sudo noid-wan-strict resume
```

The pause permits direct IPv4 WAN for the requested interval, not just portal
traffic. Auto-resume is armed before grace is added. Routine profile, DNS,
expiry and service reconciliation preserves the bounded pause; it cannot be
ended silently by a normal NetworkManager event. Reboot restores persisted
strict/strict-empty state when the armed marker exists.

### New or changed VPN profile

NetworkManager normally triggers the path/DNS reconciliation automatically.
The legacy-compatible command name performs the same exact replacement:

```bash
sudo noid-wan-strict scan-profiles
```

It does not certify or permanently trust DNS answers. If a client hides its
endpoint or uses an unsupported plugin schema, use a reviewed literal endpoint
or deliberately choose a pause/disable trade-off.

### Reset

```bash
sudo noid-wan-strict reset
```

Reset clears durable/candidate sets, removes the armed marker and deliberately
returns to full IPv4 bootstrap grace. It is not routine garbage collection;
normal reconciliation already removes stale profile state.

### No-VPN fail-closed

```bash
sudo noid-wan-strict arm-empty
```

This confirmed transition clears all endpoint records, writes the durable armed
marker, removes grace and verifies `STRICT_EMPTY`. Ordinary application and
forwarded physical WAN remain blocked until a supported VPN endpoint is
committed or the user explicitly chooses a reset, pause or feature disable.
The service-UID-scoped resolver bootstrap exception described above remains.

## Components

| Component | Path | Role |
|---|---|---|
| nft policy | `/etc/nftables.d/noid-wan-strict.nft` | Durable/candidate sets, resolver exception and physical drops |
| boot loader | `/usr/local/sbin/noid-wan-strict-bootstrap.sh` | Loads table/interface set and validated unexpired v2 state |
| boot status publisher | `noid-wan-strict-status-publish.service` | Republishes the closed runtime contract before login even when explicit opt-out keeps the policy service disabled |
| controller | `/usr/local/libexec/noid-wan-strict-endpoints` | libnm parsing, resolution, authentication, expiry and atomic reconciliation |
| profile wrapper | `/usr/local/sbin/noid-wan-strict-scan-profiles.sh` | Compatibility/manual reconcile entry point |
| boot guard | `/etc/NetworkManager/dispatcher.d/pre-up.d/20-noid-wan-strict-boot-guard` | Fails boot networking closed (downs the physical link) when armed strict state is missing or invalid |
| WireGuard MTU reconciler | `/usr/local/sbin/noid-wireguard-mtu-reconcile` + `pre-up.d/no-wait.d/45-noid-wireguard-mtu` | Lower-only live-interface correction from every resolved peer's real outer route; never edits or reconnects an owning profile |
| physical/DNS/reapply dispatcher | `/etc/NetworkManager/dispatcher.d/55-wan-strict-scan-on-network-up` → `no-wait.d/…` | Refreshes profile/candidate state and current transient bootstrap routes |
| tunnel-down dispatcher | `/etc/NetworkManager/dispatcher.d/58-wan-strict-tunnel-down` | Removes volatile active proof while preserving durable strict state |
| tunnel dispatcher | `/etc/NetworkManager/dispatcher.d/60-vpn-endpoint-pin` | Requests runtime-confirmed promotion and publishes active proof |
| profile path/service | `noid-wan-strict-scan-profiles.path/.service` | Reconciles create/change/delete events |
| expiry timer/service | `noid-wan-strict-endpoint-expiry.timer/.service` | Prunes bounded authenticated leases |
| tunnel hotplug | `/etc/udev/rules.d/71-noid-wan-strict-tunnel-hotplug.rules` + `noid-wan-strict-tunnel-scan.service` | Reconciles when a kernel WireGuard device appears that NetworkManager does not manage |
| state | `/var/lib/noid-privacy/wan-strict-endpoints.txt` | Closed v2 durable records |
| armed marker | `/var/lib/noid-privacy/wan-strict-armed.flag` | Prevents silent grace reopening |
| active runtime markers | `/run/noid-privacy/wan-strict-active/` | Root-private, reboot-volatile evidence of authenticated tunnel activation |
| CLI | `/usr/local/sbin/noid-wan-strict` | Status, pause, resume, arm-empty, reset, reconcile |
| feature toggle | `/usr/local/sbin/noid-toggle-wan-strict` | Explicit system-level on/off choice |

## Diagnostics without destination logging

```bash
sudo nft list counters table inet noid_wan_strict
sudo journalctl -b \
  -u noid-wan-strict.service \
  -u noid-wan-strict-scan-profiles.service \
  -u noid-wan-strict-endpoint-expiry.service \
  -t noid-vpn-endpoint-pin \
  -t noid-wan-strict-down
sudo noid-wan-strict status
```

Counters are aggregate. Endpoint state necessarily contains exact destination
addresses and profile UUIDs locally, so treat the state/status output as
network metadata when sharing diagnostics.

## References

- [NetworkManager dispatcher contract](https://networkmanager.dev/docs/api/latest/NetworkManager-dispatcher.html)
- [NetworkManager keyfile format and safety checks](https://networkmanager.dev/docs/api/latest/nm-settings-keyfile.html)
- [NetworkManager VPN settings](https://networkmanager.dev/docs/api/latest/settings-vpn.html)
- [NetworkManager active-connection state and reason](https://networkmanager.dev/docs/libnm/latest/NMActiveConnection.html)
- [Mullvad Lockdown mode](https://mullvad.net/en/help/using-mullvad-vpn-app#lockdown-mode)
- [Mullvad app security model](https://github.com/mullvad/mullvadvpn-app/blob/main/docs/security.md)
- [Mullvad current transport matrix](https://github.com/mullvad/mullvadvpn-app/blob/main/README.md)
- [IVPN desktop app source and protocol statement](https://github.com/ivpn/desktop-app/blob/development/readme.md)
- [Proton VPN Advanced kill switch](https://protonvpn.com/support/advanced-kill-switch)
- [WireGuard protocol and runtime model](https://www.wireguard.com/protocol/)
- [ProtonVPN issue #130 — interface-bind bypass report](https://github.com/ProtonVPN/proton-vpn-gtk-app/issues/130)
- [nftables hook semantics](https://netfilter.org/projects/nftables/manpage.html)
- [Linux `packet(7)` / `AF_PACKET`](https://man7.org/linux/man-pages/man7/packet.7.html)
- [Linux capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [Linux network namespaces](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
DOC_EOF
chmod 644 /usr/share/doc/noid-privacy/wan-egress-strict.md
chown root:root /usr/share/doc/noid-privacy/wan-egress-strict.md
log "STEP 7: /usr/share/doc/noid-privacy/wan-egress-strict.md installed"

# ====================================================================
# STEP 8: Verification (logged to /var/log/ks-06-vpn-killswitch.log)
# ====================================================================
log "STEP 8: verification ==="
verify_fail=0

verify_owned_regular() {
    local path="$1" expected_mode="$2" metadata
    [ -f "$path" ] && [ ! -L "$path" ] || return 1
    metadata=$(stat -c '%u:%g:%a:%h' "$path" 2>/dev/null) || return 1
    [ "$metadata" = "0:0:${expected_mode}:1" ]
}

# Runtime lock/evidence paths must exist before the sandboxed boot controller.
if verify_owned_regular /etc/tmpfiles.d/noid-wan-strict.conf 644 &&
   grep -qxF 'f /run/lock/noid-wan-strict.lock 0600 root root -' \
        /etc/tmpfiles.d/noid-wan-strict.conf &&
   grep -qxF 'f /run/lock/noid-wireguard-mtu.lock 0600 root root -' \
        /etc/tmpfiles.d/noid-wan-strict.conf &&
   grep -qxF 'd /run/noid-privacy/wan-strict-active 0700 root root -' \
        /etc/tmpfiles.d/noid-wan-strict.conf; then
    log "  ✓ M06 tmpfiles lock/evidence contract present + valid"
else
    log "  ✗ M06 tmpfiles lock/evidence contract missing or invalid"
    verify_fail=$((verify_fail + 1))
fi

# The MTU gate changes only an already-created WireGuard kernel link. The
# tunnel pre-up copy is awaited; normal/physical events point at an exact
# no-wait copy so no remote catalog or later VPN activation queues behind it.
if verify_owned_regular /usr/local/sbin/noid-wireguard-mtu-reconcile 755 &&
   bash -n /usr/local/sbin/noid-wireguard-mtu-reconcile &&
   grep -qF '"$IP" link set dev "$iface" mtu "$worst_safe"' \
        /usr/local/sbin/noid-wireguard-mtu-reconcile &&
   ! grep -qE 'nmcli.*(modify|down|up)|connection (modify|down|up)' \
        /usr/local/sbin/noid-wireguard-mtu-reconcile &&
   verify_owned_regular \
        /etc/NetworkManager/dispatcher.d/pre-up.d/45-noid-wireguard-mtu 700 &&
   verify_owned_regular \
        /etc/NetworkManager/dispatcher.d/no-wait.d/45-noid-wireguard-mtu 700 &&
   cmp -s /etc/NetworkManager/dispatcher.d/pre-up.d/45-noid-wireguard-mtu \
        /etc/NetworkManager/dispatcher.d/no-wait.d/45-noid-wireguard-mtu &&
   [ "$(readlink /etc/NetworkManager/dispatcher.d/45-noid-wireguard-mtu 2>/dev/null)" = \
        no-wait.d/45-noid-wireguard-mtu ] &&
   bash -n /etc/NetworkManager/dispatcher.d/pre-up.d/45-noid-wireguard-mtu; then
    log "  ✓ lower-only WireGuard MTU helper + awaited/no-wait dispatch pair valid"
else
    log "  ✗ WireGuard MTU helper or dispatcher publication invalid"
    verify_fail=$((verify_fail + 1))
fi

# The armed-state boot guard is the earliest fail-closed NetworkManager gate.
# It is a direct root-owned file, not a symlink to another dispatcher mode.
if verify_owned_regular \
        /etc/NetworkManager/dispatcher.d/pre-up.d/20-noid-wan-strict-boot-guard \
        700 &&
   [ -x /etc/NetworkManager/dispatcher.d/pre-up.d/20-noid-wan-strict-boot-guard ] &&
   bash -n \
        /etc/NetworkManager/dispatcher.d/pre-up.d/20-noid-wan-strict-boot-guard &&
   grep -qF 'ip link set dev "$IFACE" down' \
        /etc/NetworkManager/dispatcher.d/pre-up.d/20-noid-wan-strict-boot-guard; then
    log "  ✓ persisted-strict pre-up boot guard present + valid"
else
    log "  ✗ persisted-strict pre-up boot guard missing or invalid"
    verify_fail=$((verify_fail + 1))
fi

# 50-vpn-zone-enforce dispatcher (v2+v3)
if verify_owned_regular /etc/NetworkManager/dispatcher.d/50-vpn-zone-enforce 700 &&
   [ -x /etc/NetworkManager/dispatcher.d/50-vpn-zone-enforce ] &&
   [ "$(readlink /etc/NetworkManager/dispatcher.d/pre-up.d/50-vpn-zone-enforce 2>/dev/null)" = \
        ../50-vpn-zone-enforce ] &&
   bash -n /etc/NetworkManager/dispatcher.d/50-vpn-zone-enforce &&
   grep -qF -- '--zone=noid-vpn --change-interface="$IFACE"' \
        /etc/NetworkManager/dispatcher.d/50-vpn-zone-enforce &&
   grep -qF 'con mod --temporary "$UUID" connection.zone noid-vpn' \
        /etc/NetworkManager/dispatcher.d/50-vpn-zone-enforce; then
    log "  ✓ 50-vpn-zone-enforce regular/owned + pre-up link + policy valid"
else
    log "  ✗ 50-vpn-zone-enforce ownership, link or policy invalid"
    verify_fail=$((verify_fail + 1))
fi

# 55-wan-strict-scan-on-network-up dispatcher
if verify_owned_regular \
        /etc/NetworkManager/dispatcher.d/no-wait.d/55-wan-strict-scan-on-network-up \
        700 &&
   [ "$(readlink /etc/NetworkManager/dispatcher.d/55-wan-strict-scan-on-network-up 2>/dev/null)" = \
        no-wait.d/55-wan-strict-scan-on-network-up ] &&
   [ -x /etc/NetworkManager/dispatcher.d/no-wait.d/55-wan-strict-scan-on-network-up ] &&
   bash -n /etc/NetworkManager/dispatcher.d/no-wait.d/55-wan-strict-scan-on-network-up &&
   grep -qF 'reconcile-bootstrap' \
        /etc/NetworkManager/dispatcher.d/no-wait.d/55-wan-strict-scan-on-network-up; then
    log "  ✓ 55-wan-strict no-wait physical-up/reapply reconciliation present + valid"
else
    log "  ✗ 55-wan-strict no-wait physical-up/reapply reconciliation missing or invalid"
    verify_fail=$((verify_fail + 1))
fi

# 58-wan-strict-tunnel-down dispatcher
if verify_owned_regular \
        /etc/NetworkManager/dispatcher.d/58-wan-strict-tunnel-down 700 &&
   [ -x /etc/NetworkManager/dispatcher.d/58-wan-strict-tunnel-down ] &&
   bash -n /etc/NetworkManager/dispatcher.d/58-wan-strict-tunnel-down &&
   grep -qF 'record-disconnect' \
        /etc/NetworkManager/dispatcher.d/58-wan-strict-tunnel-down &&
   [ ! -e /etc/NetworkManager/dispatcher.d/58-wan-strict-clean-disconnect ] &&
   [ ! -e /etc/NetworkManager/dispatcher.d/pre-down.d/58-wan-strict-clean-disconnect ]; then
    log "  ✓ 58-wan-strict tunnel-down cleanup present; relaxation hook absent"
else
    log "  ✗ 58-wan-strict tunnel-down cleanup/retired-hook contract invalid"
    verify_fail=$((verify_fail + 1))
fi

# 60-vpn-endpoint-pin dispatcher
if verify_owned_regular /etc/NetworkManager/dispatcher.d/60-vpn-endpoint-pin 700 &&
   [ -x /etc/NetworkManager/dispatcher.d/60-vpn-endpoint-pin ] &&
   bash -n /etc/NetworkManager/dispatcher.d/60-vpn-endpoint-pin &&
   grep -qF '/usr/local/libexec/noid-wan-strict-endpoints' \
        /etc/NetworkManager/dispatcher.d/60-vpn-endpoint-pin && \
   grep -qF 'commit-active' /etc/NetworkManager/dispatcher.d/60-vpn-endpoint-pin; then
    log "  ✓ 60-vpn-endpoint-pin regular/owned + authenticated delegation valid"
else
    log "  ✗ 60-vpn-endpoint-pin ownership or authenticated delegation invalid"
    verify_fail=$((verify_fail + 1))
fi

# The former 80-vpn-keepalive hook is forbidden: runtime `off` does not
# reveal whether zero was an explicit profile decision.
if [ -e /etc/NetworkManager/dispatcher.d/80-vpn-keepalive ]; then
    log "  ✗ obsolete universal WireGuard keepalive mutator present"
    verify_fail=$((verify_fail + 1))
else
    log "  ✓ no universal WireGuard keepalive mutation"
fi

# nft-table file. Anaconda %post runs in a chroot without netfilter-
# namespace access → nft -c -f always false-negatives there regardless of
# file validity. Probe the namespace first via `nft list tables`: real
# syntax check post-install, INFO-skip in the chroot.
if verify_owned_regular /etc/nftables.d/noid-wan-strict.nft 644; then
    log "  ✓ /etc/nftables.d/noid-wan-strict.nft regular + owned"
    if nft list tables >/dev/null 2>&1; then
        if nft -c -f /etc/nftables.d/noid-wan-strict.nft 2>/dev/null; then
            log "  ✓ nft-table syntax valid"
        else
            log "  ✗ nft-table syntax ERROR"
            verify_fail=$((verify_fail + 1))
        fi
    else
        log "  [INFO] nft-table syntax check skipped (no netfilter-NS in Anaconda chroot — file IS valid, verified post-install)"
    fi
else
    log "  ✗ /etc/nftables.d/noid-wan-strict.nft ownership or type invalid"
    verify_fail=$((verify_fail + 1))
fi
if grep -qF 'type ipv4_addr . inet_proto . inet_service' /etc/nftables.d/noid-wan-strict.nft 2>/dev/null &&
   grep -qF 'ip daddr . meta l4proto . th dport @vpn_endpoints_v4' /etc/nftables.d/noid-wan-strict.nft 2>/dev/null &&
   grep -qF 'ip daddr . meta l4proto @vpn_bootstrap_routes_v4' /etc/nftables.d/noid-wan-strict.nft 2>/dev/null; then
    log "  ✓ endpoint and bounded bootstrap-route allowances have exact scopes"
else
    log "  ✗ endpoint/bootstrap-route allowances are not exact scopes"
    verify_fail=$((verify_fail + 1))
fi

# bootstrap-script
if verify_owned_regular /usr/local/sbin/noid-wan-strict-bootstrap.sh 700 &&
   [ -x /usr/local/sbin/noid-wan-strict-bootstrap.sh ] &&
   bash -n /usr/local/sbin/noid-wan-strict-bootstrap.sh &&
   grep -qFx \
        'if ! /usr/local/libexec/noid-wan-strict-endpoints bootstrap; then' \
        /usr/local/sbin/noid-wan-strict-bootstrap.sh; then
    log "  ✓ bootstrap-script regular/owned + controller delegation valid"
else
    log "  ✗ bootstrap-script ownership or controller delegation invalid"
    verify_fail=$((verify_fail + 1))
fi

# systemd-service
if verify_owned_regular /etc/systemd/system/noid-wan-strict.service 644 &&
   grep -qFx 'ExecStart=/usr/local/sbin/noid-wan-strict-bootstrap.sh' \
        /etc/systemd/system/noid-wan-strict.service &&
   grep -qFx 'Before=NetworkManager.service network.target' \
        /etc/systemd/system/noid-wan-strict.service &&
   grep -qFx \
        'ReadWritePaths=/var/lib/noid-privacy /run/noid-privacy /run/lock/noid-wan-strict.lock' \
        /etc/systemd/system/noid-wan-strict.service &&
   grep -qFx 'CapabilityBoundingSet=CAP_NET_ADMIN' \
        /etc/systemd/system/noid-wan-strict.service &&
   grep -qFx 'UMask=0077' \
        /etc/systemd/system/noid-wan-strict.service; then
    log "  ✓ noid-wan-strict.service regular/owned + boot contract valid"
    if systemctl is-enabled --quiet noid-wan-strict.service 2>/dev/null; then
        log "  ✓ noid-wan-strict.service enabled"
    else
        log "  ✗ noid-wan-strict.service NOT enabled"
        verify_fail=$((verify_fail + 1))
    fi
else
    log "  ✗ noid-wan-strict.service ownership or boot contract invalid"
    verify_fail=$((verify_fail + 1))
fi

# The opt-out disables the policy service, so its reboot-volatile status must
# be republished by a separately enabled, policy-neutral oneshot before login.
if verify_owned_regular \
        /etc/systemd/system/noid-wan-strict-status-publish.service 644 &&
   grep -qFx \
        'ExecStart=/usr/local/sbin/noid-wan-strict-publish-status' \
        /etc/systemd/system/noid-wan-strict-status-publish.service &&
   grep -qFx \
        'After=local-fs.target systemd-tmpfiles-setup.service noid-wan-strict.service' \
        /etc/systemd/system/noid-wan-strict-status-publish.service &&
   grep -qFx 'Before=multi-user.target graphical.target' \
        /etc/systemd/system/noid-wan-strict-status-publish.service &&
   grep -qFx 'CapabilityBoundingSet=CAP_NET_ADMIN' \
        /etc/systemd/system/noid-wan-strict-status-publish.service &&
   grep -qFx \
        'ReadWritePaths=/run/noid-privacy /run/lock/noid-wan-strict.lock' \
        /etc/systemd/system/noid-wan-strict-status-publish.service &&
   systemctl is-enabled --quiet \
        noid-wan-strict-status-publish.service 2>/dev/null; then
    log "  ✓ WAN runtime status is republished before login in ON and OFF states"
else
    log "  ✗ WAN runtime status boot publisher missing, unsafe or disabled"
    verify_fail=$((verify_fail + 1))
fi

if verify_owned_regular /usr/local/sbin/noid-wan-strict-scan-profiles.sh 700 &&
   [ -x /usr/local/sbin/noid-wan-strict-scan-profiles.sh ] &&
   bash -n /usr/local/sbin/noid-wan-strict-scan-profiles.sh &&
   grep -qFx '"$ENGINE" reconcile' \
        /usr/local/sbin/noid-wan-strict-scan-profiles.sh; then
    log "  ✓ endpoint reconciliation wrapper regular/owned + valid"
else
    log "  ✗ endpoint reconciliation wrapper missing or invalid"
    verify_fail=$((verify_fail + 1))
fi
if verify_owned_regular /usr/local/libexec/noid-wan-strict-endpoints 755 &&
   [ -x /usr/local/libexec/noid-wan-strict-endpoints ] &&
   python3 -c 'p="/usr/local/libexec/noid-wan-strict-endpoints"; compile(open(p, encoding="utf-8").read(), p, "exec")' &&
   grep -qF 'NM.Client.new(None)' /usr/local/libexec/noid-wan-strict-endpoints &&
   grep -qF 'def bootstrap() -> int:' /usr/local/libexec/noid-wan-strict-endpoints &&
   grep -qF 'def nft_json(*arguments: str) -> list[object]:' \
        /usr/local/libexec/noid-wan-strict-endpoints &&
   grep -qF 'def derive_runtime_mode() -> str:' \
        /usr/local/libexec/noid-wan-strict-endpoints &&
   grep -qF 'raise fail("WAN strict is explicitly disabled")' \
        /usr/local/libexec/noid-wan-strict-endpoints &&
   grep -qF 'def main() -> int:' /usr/local/libexec/noid-wan-strict-endpoints; then
    log "  ✓ libnm endpoint controller regular/owned + syntax valid"
else
    log "  ✗ libnm endpoint controller missing or invalid"
    verify_fail=$((verify_fail + 1))
fi
if verify_owned_regular \
        /etc/systemd/system/noid-wan-strict-scan-profiles.path 644 &&
   grep -qFx 'PathChanged=/etc/NetworkManager/system-connections' \
        /etc/systemd/system/noid-wan-strict-scan-profiles.path &&
   systemctl is-enabled --quiet noid-wan-strict-scan-profiles.path 2>/dev/null; then
    log "  ✓ endpoint profile path trigger enabled"
else
    log "  ✗ endpoint profile path trigger ownership, contract or enablement invalid"
    verify_fail=$((verify_fail + 1))
fi
if verify_owned_regular \
        /etc/systemd/system/noid-wan-strict-scan-profiles.service 644 &&
   grep -qFx \
        'ExecStart=/usr/local/sbin/noid-wan-strict-scan-profiles.sh' \
        /etc/systemd/system/noid-wan-strict-scan-profiles.service &&
   grep -qFx 'ProtectSystem=strict' \
        /etc/systemd/system/noid-wan-strict-scan-profiles.service &&
   grep -qFx \
        'ReadWritePaths=/var/lib/noid-privacy /run/noid-privacy /run/lock/noid-wan-strict.lock' \
        /etc/systemd/system/noid-wan-strict-scan-profiles.service; then
    log "  ✓ endpoint profile reconciliation service present + valid"
else
    log "  ✗ endpoint profile reconciliation service missing or invalid"
    verify_fail=$((verify_fail + 1))
fi
if verify_owned_regular \
        /etc/systemd/system/noid-wan-strict-tunnel-scan.service 644 &&
   grep -qFx \
        'ExecStart=/usr/local/sbin/noid-wan-strict-scan-profiles.sh' \
        /etc/systemd/system/noid-wan-strict-tunnel-scan.service &&
   grep -qFx 'ProtectSystem=strict' \
        /etc/systemd/system/noid-wan-strict-tunnel-scan.service &&
   verify_owned_regular \
        /etc/udev/rules.d/71-noid-wan-strict-tunnel-hotplug.rules 644 &&
   grep -qF 'ENV{DEVTYPE}=="wireguard"' \
        /etc/udev/rules.d/71-noid-wan-strict-tunnel-hotplug.rules &&
   grep -qF 'noid-wan-strict-tunnel-scan.service' \
        /etc/udev/rules.d/71-noid-wan-strict-tunnel-hotplug.rules; then
    log "  ✓ unmanaged-tunnel hotplug reconciliation present + valid"
else
    log "  ✗ unmanaged-tunnel hotplug reconciliation missing or invalid"
    verify_fail=$((verify_fail + 1))
fi
if verify_owned_regular \
        /etc/systemd/system/noid-wan-strict-endpoint-expiry.timer 644 &&
   grep -qFx 'OnUnitActiveSec=5min' \
        /etc/systemd/system/noid-wan-strict-endpoint-expiry.timer &&
   grep -qFx 'Unit=noid-wan-strict-endpoint-expiry.service' \
        /etc/systemd/system/noid-wan-strict-endpoint-expiry.timer &&
   systemctl is-enabled --quiet noid-wan-strict-endpoint-expiry.timer 2>/dev/null; then
    log "  ✓ authenticated endpoint expiry timer regular/owned + enabled"
else
    log "  ✗ authenticated endpoint expiry timer ownership, contract or enablement invalid"
    verify_fail=$((verify_fail + 1))
fi
if verify_owned_regular \
        /etc/systemd/system/noid-wan-strict-endpoint-expiry.service 644 &&
   grep -qFx \
        'ExecStart=/usr/local/libexec/noid-wan-strict-endpoints expire' \
        /etc/systemd/system/noid-wan-strict-endpoint-expiry.service &&
   grep -qFx 'ProtectSystem=strict' \
        /etc/systemd/system/noid-wan-strict-endpoint-expiry.service &&
   grep -qFx \
        'ReadWritePaths=/var/lib/noid-privacy /run/noid-privacy /run/lock/noid-wan-strict.lock' \
        /etc/systemd/system/noid-wan-strict-endpoint-expiry.service; then
    log "  ✓ authenticated endpoint expiry service present + valid"
else
    log "  ✗ authenticated endpoint expiry service missing or invalid"
    verify_fail=$((verify_fail + 1))
fi

# CLI control tool
if verify_owned_regular /usr/local/sbin/noid-wan-strict 755 &&
   [ -x /usr/local/sbin/noid-wan-strict ] &&
   bash -n /usr/local/sbin/noid-wan-strict &&
   grep -q 'cmd_status\|cmd_pause\|cmd_resume\|cmd_reset' \
        /usr/local/sbin/noid-wan-strict; then
    log "  ✓ noid-wan-strict CLI regular/owned + valid"
else
    log "  ✗ noid-wan-strict CLI ownership, syntax or subcommands invalid"
    verify_fail=$((verify_fail + 1))
fi
if verify_owned_regular /usr/local/sbin/noid-toggle-wan-strict 755 &&
   [ -x /usr/local/sbin/noid-toggle-wan-strict ] &&
   bash -n /usr/local/sbin/noid-toggle-wan-strict &&
   grep -qF 'ENDPOINT_ENGINE=/usr/local/libexec/noid-wan-strict-endpoints' \
        /usr/local/sbin/noid-toggle-wan-strict &&
   grep -qF 'PROFILE_PATH=noid-wan-strict-scan-profiles.path' \
        /usr/local/sbin/noid-toggle-wan-strict &&
   grep -qF 'EXPIRY_TIMER=noid-wan-strict-endpoint-expiry.timer' \
        /usr/local/sbin/noid-toggle-wan-strict; then
    log "  ✓ WAN-strict feature toggle present + valid"
else
    log "  ✗ WAN-strict feature toggle missing or invalid"
    verify_fail=$((verify_fail + 1))
fi
if verify_owned_regular /usr/local/sbin/noid-wan-strict-publish-status 755 &&
   [ -x /usr/local/sbin/noid-wan-strict-publish-status ] &&
   bash -n /usr/local/sbin/noid-wan-strict-publish-status &&
   grep -qFx \
        'exec /usr/local/libexec/noid-wan-strict-endpoints publish-status' \
        /usr/local/sbin/noid-wan-strict-publish-status; then
    log "  ✓ machine-readable WAN status publisher present + valid"
else
    log "  ✗ machine-readable WAN status publisher missing or invalid"
    verify_fail=$((verify_fail + 1))
fi

# User-doc verify (full content embedded via the STEP 7 heredoc)
if verify_owned_regular /usr/share/doc/noid-privacy/wan-egress-strict.md 644 &&
   grep -qFx '# WAN-Egress-Strict — physical-interface egress boundary' \
        /usr/share/doc/noid-privacy/wan-egress-strict.md; then
    log "  ✓ /usr/share/doc/noid-privacy/wan-egress-strict.md regular/owned + valid"
else
    log "  ✗ /usr/share/doc/noid-privacy/wan-egress-strict.md ownership or content invalid"
    verify_fail=$((verify_fail + 1))
fi

if [ "$verify_fail" -ne 0 ]; then
    log "=== Module 06 FAILED: $verify_fail verification error(s) ==="
    exit 1
fi
log "=== Module 06 complete ==="
%end

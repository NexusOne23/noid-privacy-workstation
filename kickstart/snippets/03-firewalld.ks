# ============================================================================
# Module 03 — Firewalld
# Status: LOCKED 2026-08-21 (v5.45) — preserve explicit peer/global LAN grants around the exact DHCPv4 path.
#
# Covers:
#   - Hardened /etc/firewalld/firewalld.conf (DefaultZone=drop)
#   - block-lan-out policy ALWAYS ACTIVE (no mode toggle): 37 port +
#     destination drop rules, IPv4 + IPv6 symmetric, plus one host-only
#     DHCPv4 source-port continuation whose exact selector is enforced by
#     the earlier topology hook
#   - Dual-policy split: block-lan-out (HOST ingress) + derived
#     block-lan-out-vms (libvirt ingress) — the F44 firewalld validator
#     rejects HOST mixed with regular zones in one <ingress-zone>
#   - allow-host-ipv6 hardened override: 6 ICMPv6 types kept (4x MLD +
#     2x NDP), router-advertisement + redirect dropped (Rogue-RA /
#     ICMPv6-redirect attack classes)
#   - VPN connections land in a dedicated target=DROP `noid-vpn` zone
#     (enforced by the M06 dispatcher) so private tunnel destinations work
#     without exposing host services to new tunnel-side connections
#   - First-boot safety net: every physical interface → drop zone +
#     post-Anaconda/Libvirt SSH re-strip (STEP 4)
#
# Design rationale (permanent, no Mode A/B toggle):
#   - block-lan-out drops HOST → drop-zone egress for LAN discovery ports
#     (NetBIOS/SMB/SSDP/WSD/mDNS/LLMNR), RFC1918 + CGN + link-local +
#     test-net destinations, multicast/broadcast, and IPv6 equivalents.
#     It deliberately does not claim to filter Intel AMT/CSME out-of-band
#     traffic: that path operates independently of the host OS firewall.
#   - VMs on virbr0 (libvirt ingress) get the same 37 LAN-drop rules, but
#     never the host DHCP-client continuation. Inter-VM traffic and VM→host
#     services (192.168.122.1 dnsmasq) are unaffected — their egress zone is
#     libvirt/HOST, not drop.
#   - Failure mode is LOUD: if VPN zone assignment fails, the VPN breaks
#     visibly instead of silently leaking to LAN.
#
# ssh-strip architecture (3 layers, all retained):
#   - master.ks `firewall --enabled --remove-service=ssh` — declarative;
#     F44 Anaconda does not honor it at runtime, kept for forward-compat.
#   - STEP 3b %post strip via firewall-offline-cmd — durable for the
#     normal NAT `libvirt` zone and routed `libvirt-to-host` policy (both
#     shipped by Libvirt independently of the kickstart directive);
#     best-effort for drop.xml, which Anaconda's post-%post Network-Task
#     rewrites with ssh re-added.
#   - Firstboot re-strip in noid-firewalld-zone-enforce.sh — the canonical
#     path; runs AFTER the Network-Task and wins.
# ============================================================================

# ---------------------------------------------------------------------------
# Packages
# ---------------------------------------------------------------------------
%packages --exclude-weakdeps
firewalld
libnftnl
nftables
# Loads and attaches the prebuilt, source-auditable XDP/TC LAN boundary.
bpftool
# Controller/runtime closure: `ip` + `tc`, and `flock` + `mountpoint`.
iproute
iproute-tc
util-linux-core
# Controller closure for canonical IP/CIDR validation and JSON inspection.
python3
# iptables-nft not explicitly listed: firewalld 2.3+ uses the nftables backend
# directly (FirewallBackend=nftables in firewalld.conf) and does not need it.
# Fedora's current solver nonetheless selects it to satisfy the generic
# `iptables` capability required by libvirt-daemon-driver-nwfilter from
# @virtualization. It runs only as a compatibility provider here; firewalld and
# libvirt's own nftables tables (libvirt_network) are the active path.
%end

# ---------------------------------------------------------------------------
# %post — firewalld config + always-active block-lan-out policy
# ---------------------------------------------------------------------------
%post --erroronfail --log=/var/log/ks-03-firewalld.log
set -euo pipefail

log() { echo "[noid-03-firewalld]" "$@"; }
log "=== Module 03 post-install: firewalld (always-drop-lan) ==="

# ====================================================================
# STEP 1: /etc/firewalld/firewalld.conf — main config (14 params)
# ====================================================================
# DefaultZone=drop: physical interfaces auto-land in the drop zone (or are
# corrected by the STEP 4 safety net). block-lan-out (STEP 2) applies when
# HOST sends traffic out of any drop-zone interface.
cat > /etc/firewalld/firewalld.conf << 'FW_CONF_EOF'
# NoID Privacy — firewalld main config

# Default zone: drop (blocks incoming, allows outgoing, conntrack ESTABLISHED OK)
DefaultZone=drop

# Resource management
CleanupOnExit=yes
CleanupModulesOnExit=no

# Deliberate deviation from firewalld's `strict` default: `loose` accepts a
# return route through any interface, preserving asymmetric VPN and multihomed
# paths at the cost of strict per-interface IPv6 source anti-spoofing.
IPv6_rpfilter=loose

# Performance: batch nftables transactions. Keep firewalld's nftables
# flowtable fast path off; this disables the software fast path and any
# hardware offload built on it.
IndividualCalls=no
NftablesFlowtable=off

# Per-rule counters for kernel-ruleset diagnostics.
# Deviation from firewalld default (`NftablesCounters=no` per firewalld.conf(5)
# 2026): NoID Privacy enables them for bounded diagnostics via
# `nft -a list table inet firewalld`; `firewall-cmd --info-policy` reports
# policy configuration, not packet/byte counters. Performance cost is marginal
# on single-host workstation throughput. Documented deviation.
NftablesCounters=yes

# Keep firewalld's LogDenied=off default explicit. Privacy rationale: every
# LAN scan, NAT probe and
# stray broadcast from neighbors lands in journal with src/dst IPs +
# ports. On a hostile-LAN profile that's continuous IP-tracking data
# in logs (which then end up in journal/audit). Defense-Evidence
# tradeoff: when we DO want the log volume (debugging a denial),
# `firewall-cmd --set-log-denied=all` toggles it without rebuild.
# Source auditors: see docs/fp-database.md ("Firewall denial logging") in the
# project repository. That auditor reference is not installed in the image.
LogDenied=off

# Backend + modern table flags
FirewallBackend=nftables
NftablesTableOwner=yes

# Reload behavior: full flush, DROP everything during reload window
# (established connections survive via conntrack)
FlushAllOnReload=yes
ReloadPolicy=INPUT:DROP,FORWARD:DROP,OUTPUT:DROP

# Filter non-global embedded IPv4 destinations in 6to4 traffic (RFC 3964,
# section 5.3.1).
RFC3964_IPv4=yes

# Never let an external DNAT manager implicitly authorize forwarded ports.
# Containers/VMs that publish a port require an explicit firewalld allowance.
StrictForwardPorts=yes
FW_CONF_EOF

chmod 600 /etc/firewalld/firewalld.conf
chown root:root /etc/firewalld/firewalld.conf
log "STEP 1: /etc/firewalld/firewalld.conf written (14 params)"

# ====================================================================
# STEP 2: block-lan-out policy — ALWAYS ACTIVE + libvirt ingress
# ====================================================================
# Written directly to /etc/firewalld/policies/ — loaded unconditionally at
# firewalld startup. Port rules + destination rules are deliberately
# redundant: a rogue app could aim LAN-discovery traffic at a public IP
# (port rules catch it) or any protocol at a private IP (dest rules catch
# it). egress-zone="drop" applies to ANY interface in the drop zone — VPN
# interfaces must NOT be there (STEP 3 / M06 put them in `noid-vpn`), or
# private tunnel endpoints and per-link DNS could break.
# The derived -vms variant (libvirt ingress) gives VMs the same semantics;
# inter-VM + VM→host flows have egress libvirt/HOST and are unaffected
# (flow summary: see the header Design rationale). The one host DHCP-client
# continuation is removed from that copy: forwarded guests never inherit it.
# Dependency: the 'libvirt' firewalld zone ships in
# libvirt-daemon-config-network (@virtualization); without it only the
# HOST policy is installed.
mkdir -p /etc/firewalld/policies
cat > /etc/firewalld/policies/block-lan-out.xml << 'POLICY_EOF'
<?xml version="1.0" encoding="utf-8"?>
<!-- NoID Privacy — block LAN egress (ALWAYS ACTIVE per design directive)
     Drops HOST traffic (ingress) -> drop zone traffic (egress): all LAN
     discovery protocols (by port) AND all RFC1918/broadcast/multicast
     destinations (by address). IPv4 + IPv6 symmetric drop coverage.
     Activated: at boot, automatically, no user intervention.
     VPN-safe: VPN interfaces are in the dedicated `noid-vpn` zone,
     so provider-defined private tunnel endpoints and DNS remain reachable.
     VM-coverage: a derived libvirt copy gets the same 37 drop rules but not
     the host-only DHCPv4 client continuation. -->
<policy priority="100" target="CONTINUE">
  <short>NoID Privacy block LAN egress (HOST)</short>
  <description>Always-active: drops HOST egress to RFC1918/broadcast/multicast + LAN discovery ports (v4+v6). Root-owned DHCPv4 client traffic is continued only after M03 enforces the exact UDP 68-to-67 selector. The derived VM policy retains the 37 drop rules and removes that host-only exception.</description>

  <!-- firewalld rich language permits one port element per rule, so it cannot
       express both UDP source 68 and destination 67 here. This negative-
       priority source-port continuation is safe only as the second half of
       M03's earlier physical-output contract: that hook accepts root-owned
       IPv4 UDP 68->67, preserves explicitly approved peer traffic, and drops
       every other unapproved physical IPv4 UDP source-68 packet before
       firewalld while the default LAN boundary is active. Keep this rule
       HOST-only. -->
  <rule family="ipv4" priority="-32768"><source-port port="68" protocol="udp"/><accept/></rule>

  <!-- ===== IPv4 LAN discovery ports ===== -->
  <!-- NetBIOS Name Service -->
  <rule family="ipv4"><port port="137" protocol="udp"/><drop/></rule>
  <!-- NetBIOS Datagram -->
  <rule family="ipv4"><port port="138" protocol="udp"/><drop/></rule>
  <!-- NetBIOS Session -->
  <rule family="ipv4"><port port="139" protocol="tcp"/><drop/></rule>
  <!-- SMB direct -->
  <rule family="ipv4"><port port="445" protocol="tcp"/><drop/></rule>
  <!-- SSDP / UPnP discovery -->
  <rule family="ipv4"><port port="1900" protocol="udp"/><drop/></rule>
  <!-- WS-Discovery (Windows SSDP-like) -->
  <rule family="ipv4"><port port="3702" protocol="udp"/><drop/></rule>
  <!-- mDNS / Bonjour -->
  <rule family="ipv4"><port port="5353" protocol="udp"/><drop/></rule>
  <!-- LLMNR -->
  <rule family="ipv4"><port port="5355" protocol="udp"/><drop/></rule>
  <!-- WSD HTTP (device management) -->
  <rule family="ipv4"><port port="5357" protocol="tcp"/><drop/></rule>

  <!-- ===== IPv4 LAN destinations — reviewed private/special-use baseline ===== -->
  <!-- Private, link-local, loopback, multicast and limited broadcast -->
  <rule family="ipv4"><destination address="10.0.0.0/8"/><drop/></rule>           <!-- RFC1918 private A -->
  <rule family="ipv4"><destination address="172.16.0.0/12"/><drop/></rule>        <!-- RFC1918 private B -->
  <rule family="ipv4"><destination address="192.168.0.0/16"/><drop/></rule>       <!-- RFC1918 private C -->
  <rule family="ipv4"><destination address="100.64.0.0/10"/><drop/></rule>        <!-- RFC6598 CGN -->
  <rule family="ipv4"><destination address="169.254.0.0/16"/><drop/></rule>       <!-- RFC3927 link-local APIPA -->
  <rule family="ipv4"><destination address="127.0.0.0/8"/><drop/></rule>          <!-- RFC1122 loopback (defense in depth — kernel rejects already) -->
  <rule family="ipv4"><destination address="0.0.0.0/8"/><drop/></rule>            <!-- RFC1122 "this network" -->
  <rule family="ipv4"><destination address="224.0.0.0/4"/><drop/></rule>          <!-- RFC5771 multicast -->
  <rule family="ipv4"><destination address="255.255.255.255/32"/><drop/></rule>   <!-- broadcast -->
  <!-- Documentation and benchmarking ranges -->
  <rule family="ipv4"><destination address="192.0.2.0/24"/><drop/></rule>         <!-- RFC5737 TEST-NET-1 -->
  <rule family="ipv4"><destination address="198.51.100.0/24"/><drop/></rule>      <!-- RFC5737 TEST-NET-2 -->
  <rule family="ipv4"><destination address="203.0.113.0/24"/><drop/></rule>       <!-- RFC5737 TEST-NET-3 -->
  <rule family="ipv4"><destination address="198.18.0.0/15"/><drop/></rule>        <!-- RFC2544 benchmark -->

  <!-- ===== IPv6 LAN discovery ports (defense in depth) ===== -->
  <rule family="ipv6"><port port="137" protocol="udp"/><drop/></rule>
  <rule family="ipv6"><port port="138" protocol="udp"/><drop/></rule>
  <rule family="ipv6"><port port="139" protocol="tcp"/><drop/></rule>
  <rule family="ipv6"><port port="445" protocol="tcp"/><drop/></rule>
  <rule family="ipv6"><port port="1900" protocol="udp"/><drop/></rule>
  <rule family="ipv6"><port port="3702" protocol="udp"/><drop/></rule>
  <rule family="ipv6"><port port="5353" protocol="udp"/><drop/></rule>
  <rule family="ipv6"><port port="5355" protocol="udp"/><drop/></rule>
  <rule family="ipv6"><port port="5357" protocol="tcp"/><drop/></rule>

  <!-- ===== IPv6 LAN destinations — reviewed local/special-use baseline ===== -->
  <!-- Link-local, ULA, multicast, loopback and unspecified -->
  <rule family="ipv6"><destination address="fe80::/10"/><drop/></rule>            <!-- RFC4291 link-local -->
  <rule family="ipv6"><destination address="fc00::/7"/><drop/></rule>             <!-- RFC4193 ULA -->
  <rule family="ipv6"><destination address="ff00::/8"/><drop/></rule>             <!-- RFC4291 multicast -->
  <rule family="ipv6"><destination address="::1/128"/><drop/></rule>              <!-- loopback (defense in depth) -->
  <rule family="ipv6"><destination address="::/128"/><drop/></rule>               <!-- unspecified address -->
  <!-- Documentation -->
  <rule family="ipv6"><destination address="2001:db8::/32"/><drop/></rule>        <!-- RFC3849 documentation -->

  <ingress-zone name="HOST"/>
  <egress-zone name="drop"/>
</policy>
POLICY_EOF
chmod 644 /etc/firewalld/policies/block-lan-out.xml
chown root:root /etc/firewalld/policies/block-lan-out.xml

# F44 firewalld rejects mixing HOST + regular zones in <ingress-zone>
# ("may only contain one of: many regular zones, ANY, or HOST") — when the
# libvirt zone exists, derive the -vms policy as a copy with libvirt
# ingress. The 37 drop rules stay identical; the host-only DHCP-client
# continuation is removed before the VM policy is published.
if [ -f /usr/lib/firewalld/zones/libvirt.xml ] || \
   [ -f /etc/firewalld/zones/libvirt.xml ]; then
    cp /etc/firewalld/policies/block-lan-out.xml \
       /etc/firewalld/policies/block-lan-out-vms.xml
    sed -i 's|<ingress-zone name="HOST"/>|<ingress-zone name="libvirt"/>|' \
        /etc/firewalld/policies/block-lan-out-vms.xml
    sed -i 's|<short>NoID Privacy block LAN egress (HOST)</short>|<short>NoID Privacy block LAN egress (libvirt VMs)</short>|' \
        /etc/firewalld/policies/block-lan-out-vms.xml
    sed -i '\|^  <rule family="ipv4" priority="-32768"><source-port port="68" protocol="udp"/><accept/></rule>$|d' \
        /etc/firewalld/policies/block-lan-out-vms.xml
    sed -i 's|Always-active: drops HOST egress|Always-active: drops libvirt VM egress|' \
        /etc/firewalld/policies/block-lan-out-vms.xml
    sed -i 's|Root-owned DHCPv4 client traffic is continued only after M03 enforces the exact UDP 68-to-67 selector. The derived VM policy retains the 37 drop rules and removes that host-only exception.|This VM policy contains only the 37 LAN-drop rules; it has no host DHCP-client exception.|' \
        /etc/firewalld/policies/block-lan-out-vms.xml
    chmod 644 /etc/firewalld/policies/block-lan-out-vms.xml
    chown root:root /etc/firewalld/policies/block-lan-out-vms.xml
    log "STEP 2: host policy installed with exact-cross-layer DHCP continuation; VM policy installed with 37 drop rules only"
else
    log "STEP 2: /etc/firewalld/policies/block-lan-out.xml installed (HOST ingress only, libvirt zone absent)"
fi

# ====================================================================
# STEP 2b: allow-host-ipv6 hardened override
# ====================================================================
# Fedora's stock allow-host-ipv6 policy accepts 8 ICMPv6 types into HOST;
# two of them are attack vectors: router-advertisement (Rogue-RA, RFC 6104
# — attacker on the local link becomes default route) and redirect
# (ICMPv6-redirect gateway MITM). The hardened override keeps only the 6
# required types (4x MLD for multicast membership + 2x NDP for neighbour
# resolution — loopback + VPN-tunnel IPv6 keep working). M02 sysctls
# already reject RA/redirects; the firewall layer is independent
# defense-in-depth that survives NM/sysctl misconfig (e.g. a user
# switching an interface to ipv6.method=auto).
# Override method: same filename under /etc/firewalld/policies/ — /etc
# takes precedence over /usr/lib at load time; stock-matching priority
# (-15000), ingress ANY, egress HOST keep rule ordering.
# User recovery (legitimate RA use-case):
#   sudo rm /etc/firewalld/policies/allow-host-ipv6.xml
#   sudo firewall-cmd --reload
cat > /etc/firewalld/policies/allow-host-ipv6.xml << 'HOSTV6_EOF'
<?xml version="1.0" encoding="utf-8"?>
<!-- NoID Privacy — hardened allow-host-ipv6 override
     Replaces stock 8-type /usr/lib/firewalld/policies/allow-host-ipv6.xml.
     Kept: 4×MLD + 2×NDP (required for loopback ::1 + VPN tunnel IPv6).
     Dropped: router-advertisement (Rogue-RA/RFC6104) + redirect (ICMP-redirect).
     See Module 03 STEP 2b rationale for full defense-in-depth context. -->
<policy target="CONTINUE" priority="-15000">
  <short>Allow host IPv6 (NoID Privacy hardened)</short>
  <description>MLD + NDP only. router-advertisement + redirect dropped to block Rogue-RA + ICMPv6-redirect attacks. Required for loopback and VPN tunnel IPv6.</description>
  <ingress-zone name="ANY" />
  <egress-zone name="HOST" />
  <rule family="ipv6">
    <icmp-type name="neighbour-advertisement" />
    <accept />
  </rule>
  <rule family="ipv6">
    <icmp-type name="neighbour-solicitation" />
    <accept />
  </rule>
  <rule family="ipv6">
    <icmp-type name="mld-listener-done" />
    <accept />
  </rule>
  <rule family="ipv6">
    <icmp-type name="mld-listener-query" />
    <accept />
  </rule>
  <rule family="ipv6">
    <icmp-type name="mld-listener-report" />
    <accept />
  </rule>
  <rule family="ipv6">
    <icmp-type name="mld2-listener-report" />
    <accept />
  </rule>
</policy>
HOSTV6_EOF
chmod 644 /etc/firewalld/policies/allow-host-ipv6.xml
chown root:root /etc/firewalld/policies/allow-host-ipv6.xml
log "STEP 2b: /etc/firewalld/policies/allow-host-ipv6.xml override installed (6 types, RA+redirect dropped)"

# ====================================================================
# STEP 2c: dedicated VPN zone — private tunnel egress, no new inbound
# ====================================================================
# The stock `trusted` zone has target ACCEPT and exposes listening host
# services to unsolicited traffic routed through the tunnel. `noid-vpn`
# remains separate from the physical `drop` zone (so VPN-private DNS works),
# but target=DROP rejects new inbound tunnel-side connections. Established
# replies continue to pass through conntrack.
mkdir -p /etc/firewalld/zones
cat > /etc/firewalld/zones/noid-vpn.xml <<'NOID_VPN_ZONE_EOF'
<?xml version="1.0" encoding="utf-8"?>
<zone target="DROP">
  <short>NoID Privacy VPN tunnel</short>
  <description>VPN interfaces: outbound traffic and established replies work; unsolicited inbound traffic to host services is dropped.</description>
</zone>
NOID_VPN_ZONE_EOF
chmod 0644 /etc/firewalld/zones/noid-vpn.xml
chown root:root /etc/firewalld/zones/noid-vpn.xml
log "STEP 2c: /etc/firewalld/zones/noid-vpn.xml installed (target DROP)"

# ====================================================================
# STEP 2d: topology-aware LAN egress guard
# ====================================================================
# Static RFC1918/ULA rules cannot identify a directly attached network that
# uses public or otherwise unusual addressing. This nft table adds the active
# Ethernet/Wi-Fi prefixes themselves to an atomic interval set. Per-IP accepts
# created by noid-lan-allow are mirrored into an earlier allow set. Priority -4
# runs after M06 WAN-strict (-5) and before firewalld (+10); a drop verdict is
# final, while an allow continues into the normal firewalld policy.
# DHCPv4 therefore needs both halves of one fail-closed contract: this hook
# proves physical interface + IPv4 + root socket + UDP 68->67. Explicitly
# approved peer traffic is evaluated next; while the default LAN boundary is
# BLOCKED, a dedicated interface set then drops every remaining physical IPv4
# UDP source-68 packet. The later host-only firewalld rich rule can consequently
# continue source port 68 ahead of its static destination drops without
# shadowing an explicit peer grant. Global LAN allow atomically empties that
# dedicated set while detaching the host policy. The VM/forward hook receives
# no DHCP allowance.
# The XDP program is compiled from the audited source under
# overrides/noid-lan-xdp/ with Fedora 44 clang, stripped of DWARF while
# retaining BTF, and hash-pinned here. The source/object/controller embedding
# is checked by scripts/regen-lan-xdp-embed.sh.
install -d -m 0755 /usr/lib/noid-privacy /usr/local/sbin
base64 -d > /usr/lib/noid-privacy/noid-lan-xdp.bpf.o <<'NOID_LAN_XDP_OBJECT_B64_EOF'
f0VMRgIBAQAAAAAAAAAAAAEA9wABAAAAAAAAAAAAAAAAAAAAAAAAALCaAAAAAAAAAAAAAEAAAAAA
AEAAEQAQAGNK9P8AAAAAezro/wAAAAB7GuD/AAAAALcBAAABAAAAexr4/wAAAAC0BgAAAAAAAGMq
8P8AAAAAFgIZAAAAAAAmAhgA3AUAAAQCAAABAAAAdAIAAAEAAAC/owAAAAAAAAcDAADg////vCEA
AAAAAAAYAgAAsAEAAAAAAAAAAAAAtwQAAAAAAACFAAAAtQAAAMUADgAAAAAAcaH4/wAAAAAWAQwA
AAAAAGGh9P8AAAAAvBIAAAAAAAB0AgAAEAAAAFQBAAD//wAADCEAAAAAAAC8EgAAAAAAAHQCAAAQ
AAAADCEAAAAAAABUAQAA//8AALQGAAABAAAAFgEBAP//AAC0BgAAAAAAALxgAAAAAAAAlQAAAAAA
AAC/RQAAAAAAAL8wAAAAAAAA3AAAABAAAABpFAwAAAAAAAwEAAAAAAAAaRAOAAAAAAAMBAAAAAAA
AGkQEAAAAAAADAQAAAAAAABpEBIAAAAAAAwEAAAAAAAAcREJAAAAAABkAQAACAAAAAwUAAAAAAAA
vyEAAAAAAAC8MgAAAAAAAL9TAAAAAAAAhRAAAMv///+VAAAAAAAAALcAAAABAAAAJgEcAO0CAABk
AQAAAQAAAGEkEAAAAAAAPkEZAAAAAAB5IwAAAAAAAA8TAAAAAAAAeSUIAAAAAAC/NgAAAAAAAAcG
AAABAAAAvVYDAAAAAAC0AQAAAAAAAHMSGAAAAAAABQAQAAAAAABEAQAAAQAAAD5BBAAAAAAAvzEA
AAAAAAAHAQAAAgAAAL1RAwAAAAAABQD3/wAAAABxMQAAAAAAAAUABAAAAAAAcTQAAAAAAABxMQEA
AAAAAGQBAAAIAAAATEEAAAAAAABhIxQAAAAAAAwTAAAAAAAAYzIUAAAAAAC3AAAAAAAAAJUAAAAA
AAAAvxYAAAAAAABhaAQAAAAAAGFpAAAAAAAAtAEAAAAAAABjGuz/AAAAAL+XAAAAAAAABwcAAA4A
AAC9hwkAAAAAALQBAAAIAAAAYxrY/wAAAAC/ogAAAAAAAAcCAADY////GAEAAAAAAAAAAAAAAAAA
AIUAAAABAAAAFQD1BAAAAAAFAPEEAAAAAL+iAAAAAAAABwIAAOz///8YAQAAAAAAAAAAAAAAAAAA
hQAAAAEAAAAVAAsAAAAAAHEBAAAAAAAAFgEJAAAAAAC0AQAAAAAAAGMa2P8AAAAAv6IAAAAAAAAH
AgAA2P///xgBAAAAAAAAAAAAAAAAAACFAAAAAQAAABUA+gQAAAAABQD2BAAAAABhYQwAAAAAALQC
AAAAAAAAayri/wAAAABjGtj/AAAAAHGRCwAAAAAAZAEAAAgAAABxkgoAAAAAAEwhAAAAAAAAaxrg
/wAAAABxkQcAAAAAAGQBAAAIAAAAcZIGAAAAAABMIQAAAAAAAHGSCAAAAAAAZAIAABAAAABxkwkA
AAAAAGQDAAAYAAAATCMAAAAAAABMEwAAAAAAAGM63P8AAAAAv6IAAAAAAAAHAgAA2P///xgBAAAA
AAAAAAAAAAAAAACFAAAAAQAAAHGRDQAAAAAAZAEAAAgAAABxkgwAAAAAAEwhAAAAAAAAFgEBAIio
AABWARkAgQAAAL+XAAAAAAAABwcAABIAAAC9hwkAAAAAALQBAAAIAAAAYxrY/wAAAAC/ogAAAAAA
AAcCAADY////GAEAAAAAAAAAAAAAAAAAAIUAAAABAAAAFQC5BAAAAAAFALUEAAAAAHGSEAAAAAAA
cZERAAAAAABkAQAACAAAAEwhAAAAAAAAFgEBAIioAABWAQcAgQAAAL+XAAAAAAAABwcAABYAAAAt
h+7/AAAAAHGSFAAAAAAAcZEVAAAAAABkAQAACAAAAEwhAAAAAAAAFgEBAIEAAABWAQkAiKgAALQB
AAAIAAAAYxrY/wAAAAC/ogAAAAAAAAcCAADY////GAEAAAAAAAAAAAAAAAAAAIUAAAABAAAAFQCh
BAAAAAAFAJ0EAAAAAL+TAAAAAAAABwMAAAYAAAAWAVcACAAAABYBSgAIBgAAVgHYA4iOAAC/dAAA
AAAAAAcEAAAEAAAALYQ9AAAAAABxMQAAAAAAALwSAAAAAAAAVAIAAAEAAABWAjkAAAAAAHGSCAAA
AAAAcZMHAAAAAABMIwAAAAAAAHGSCQAAAAAATCMAAAAAAABxkgoAAAAAAEwjAAAAAAAAcZILAAAA
AABMIwAAAAAAAEwTAAAAAAAAVAMAAP8AAAAWAy0AAAAAAHGRAAAAAAAAVgEKAAEAAABxkQEAAAAA
AFYBCACAAAAAcZECAAAAAABWAQYAwgAAAHGRAwAAAAAAVgEEAAAAAABxkQQAAAAAAFYBAgAAAAAA
cZEFAAAAAAAWARwAAwAAAGFhDAAAAAAAtAIAAAAAAABrKuL/AAAAAGMa2P8AAAAAcZEFAAAAAABk
AQAACAAAAHGSBAAAAAAATCEAAAAAAABrGuD/AAAAAHGRAQAAAAAAZAEAAAgAAABxkgAAAAAAAEwh
AAAAAAAAcZICAAAAAABkAgAAEAAAAHGTAwAAAAAAZAMAABgAAABMIwAAAAAAAEwTAAAAAAAAYzrc
/wAAAAC/ogAAAAAAAAcCAADY////GAEAAAAAAAAAAAAAAAAAAL9GAAAAAAAAhQAAAAEAAAC/ZAAA
AAAAABUABQAAAAAAcXEAAAAAAAAWAQMAAAAAACYBAgADAAAAcXEBAAAAAACmARkBBQAAALQBAAAI
AAAAYxrY/wAAAAC/ogAAAAAAAAcCAADY////GAEAAAAAAAAAAAAAAAAAAIUAAAABAAAAFQBTBAAA
AAAFAE8EAAAAAL9xAAAAAAAABwEAABwAAAC9gRoAAAAAALQBAAAIAAAAYxrY/wAAAAC/ogAAAAAA
AAcCAADY////GAEAAAAAAAAAAAAAAAAAAIUAAAABAAAAFQBHBAAAAAAFAEMEAAAAALQBAAAAAAAA
Yxro/wAAAAC3AQAAAAAAAHsa4P8AAAAAexrY/wAAAAC/cQAAAAAAAAcBAAAUAAAAvYEgAAAAAAC0
AQAACAAAAGMa8P8AAAAAv6IAAAAAAAAHAgAA8P///xgBAAAAAAAAAAAAAAAAAACFAAAAAQAAABUA
NgQAAAAABQAyBAAAAABxcQAAAAAAAHFyAQAAAAAAZAIAAAgAAABMEgAAAAAAAFYCCQAAAQAAcXEC
AAAAAABxcgMAAAAAAGQCAAAIAAAATBIAAAAAAABWAgQACAAAAHFxBAAAAAAAVgECAAYAAABxcQUA
AAAAABYBVgAEAAAAtAEAAAgAAABjGtj/AAAAAL+iAAAAAAAABwIAANj///8YAQAAAAAAAAAAAAAA
AAAAhQAAAAEAAAAVAB8EAAAAAAUAGwQAAAAAcXIAAAAAAAC8IQAAAAAAAFQBAADwAAAAFgEJAEAA
AAC0AQAACAAAAGMa8P8AAAAAv6IAAAAAAAAHAgAA8P///xgBAAAAAAAAAAAAAAAAAACFAAAAAQAA
ABUAEgQAAAAABQAOBAAAAABkAgAAAgAAAFQCAAD8AAAApgIDABQAAAC/dQAAAAAAAA8lAAAAAAAA
vYUJAAAAAAC0AQAACAAAAGMa8P8AAAAAv6IAAAAAAAAHAgAA8P///xgBAAAAAAAAAAAAAAAAAACF
AAAAAQAAABUAAwQAAAAABQD/AwAAAAB7Osj/AAAAAHsKwP8AAAAAaXECAAAAAADcAQAAEAAAAHsa
0P8AAAAAriEiAAAAAAB5odD/AAAAACYBIADcBQAAeaHQ/wAAAAC8FAAAAAAAAL9xAAAAAAAAD0EA
AAAAAAAtgRsAAAAAAHFxCAAAAAAAFgEZAAAAAAB5ocj/AAAAAHERAAAAAAAAvBMAAAAAAABUAwAA
AQAAAFYDFAAAAAAAe0q4/wAAAABxlAgAAAAAAHGTBwAAAAAATEMAAAAAAABxlAkAAAAAAExDAAAA
AAAAcZQKAAAAAABMQwAAAAAAAHGUCwAAAAAATEMAAAAAAABMEwAAAAAAAFQDAAD/AAAAFgMHAAAA
AAC/cQAAAAAAAL+DAAAAAAAAeyqw/wAAAAC0BAAAAAAAAHtaqP8AAAAAhRAAAP////9WALEAAAAA
ALQBAAAIAAAAYxrw/wAAAAC/ogAAAAAAAAcCAADw////GAEAAAAAAAAAAAAAAAAAAIUAAAABAAAA
FQDSAwAAAAAFAM4DAAAAAHEzAAAAAAAAvDEAAAAAAABUAQAAAQAAAFYBggAAAAAAcZAHAAAAAAC8
AQAAAAAAAEwxAAAAAAAAcZUIAAAAAAC8UgAAAAAAAEwSAAAAAAAAcZQJAAAAAAC8QQAAAAAAAEwh
AAAAAAAAcZIKAAAAAAC8KAAAAAAAAEwYAAAAAAAAcZELAAAAAABjGtD/AAAAAEyBAAAAAAAAFgFy
AAAAAABxcQgAAAAAAF4TcAAAAAAAcXEJAAAAAABeEG4AAAAAAHFxCgAAAAAAXhVsAAAAAABxcQsA
AAAAAF4UagAAAAAAcXEMAAAAAABeEmgAAAAAAHFxDQAAAAAAYaLQ/wAAAABeEmUAAAAAAHFyBgAA
AAAAcXEHAAAAAABkAQAACAAAAEwhAAAAAAAA3AEAABAAAAAWAWwBAQAAABYBAQACAAAABQCZAQAA
AABhYQwAAAAAALQCAAAAAAAAayri/wAAAABjGtj/AAAAAHFxFwAAAAAAZAEAAAgAAABxchYAAAAA
AEwhAAAAAAAAaxrg/wAAAABxcRMAAAAAAGQBAAAIAAAAcXISAAAAAABMIQAAAAAAAHFyFAAAAAAA
ZAIAABAAAABxcxUAAAAAAGQDAAAYAAAATCMAAAAAAABMEwAAAAAAAGM63P8AAAAAv6IAAAAAAAAH
AgAA2P///xgBAAAAAAAAAAAAAAAAAACFAAAAAQAAABUAxQEAAAAAcZEAAAAAAAAWAQEA/wAAAAUA
CgAAAAAAcZIBAAAAAABWAggA/wAAAHGSAgAAAAAAVgIGAP8AAABxkgMAAAAAAFYCBAD/AAAAcZIE
AAAAAABWAgIA/wAAAHGSBQAAAAAAFgLfAv8AAAC/cgAAAAAAAAcCAAASAAAAcSIAAAAAAABeISkA
AAAAAHFxEwAAAAAAcZIBAAAAAABeEiYAAAAAAHFxFAAAAAAAcZICAAAAAABeEiMAAAAAAHFxFQAA
AAAAcZIDAAAAAABeEiAAAAAAAHFxFgAAAAAAcZIEAAAAAABeEh0AAAAAAHFxFwAAAAAAcZIFAAAA
AABeEhoAAAAAAGFhDAAAAAAAtAIAAAAAAABrKuL/AAAAAGMa2P8AAAAAcZEFAAAAAABkAQAACAAA
AHGSBAAAAAAATCEAAAAAAABrGuD/AAAAAHGRAQAAAAAAZAEAAAgAAABxkgAAAAAAAEwhAAAAAAAA
cZICAAAAAABkAgAAEAAAAHGTAwAAAAAAZAMAABgAAABMIwAAAAAAAEwTAAAAAAAAYzrc/wAAAAC/
ogAAAAAAAAcCAADY////GAEAAAAAAAAAAAAAAAAAAIUAAAABAAAAVQCyAgAAAAC0AQAACAAAAGMa
2P8AAAAAv6IAAAAAAAAHAgAA2P///xgBAAAAAAAAAAAAAAAAAACFAAAAAQAAABUATAMAAAAABQBI
AwAAAAC0AQAACAAAAGMa2P8AAAAAv6IAAAAAAAAHAgAA2P///xgBAAAAAAAAAAAAAAAAAACFAAAA
AQAAABUAQwMAAAAABQA/AwAAAABxcQIAAAAAAHFyAwAAAAAAZAIAAAgAAABMEgAAAAAAANwCAAAQ
AAAADyQAAAAAAAC9hAkAAAAAALQBAAAIAAAAYxrY/wAAAAC/ogAAAAAAAAcCAADY////GAEAAAAA
AAAAAAAAAAAAAIUAAAABAAAAFQAzAwAAAAAFAC8DAAAAALQBAAACAAAAYxrY/wAAAAC/ogAAAAAA
AAcCAADY////GAEAAAAAAAAAAAAAAAAAAIUAAAABAAAAFQBAAwAAAAAFADwDAAAAAHmh0P8AAAAA
aXEGAAAAAABUAQAAv/8AABYBCQAAAAAAtAEAAAcAAABjGvD/AAAAAL+iAAAAAAAABwIAAPD///8Y
AQAAAAAAAAAAAAAAAAAAhQAAAAEAAAAVAB0DAAAAAAUAGQMAAAAAYWEMAAAAAABhcgwAAAAAAGMq
9P8AAAAAYxrw/wAAAAC0AgAAAAAAALQBAAAAAAAAYxqQ/wAAAABrKv7/AAAAAHmjyP8AAAAAcTEF
AAAAAABkAQAACAAAAHEyBAAAAAAATCEAAAAAAABrGvz/AAAAAHExAQAAAAAAZAEAAAgAAABxMgAA
AAAAAEwhAAAAAAAAcTICAAAAAABkAgAAEAAAAHEzAwAAAAAAZAMAABgAAABMIwAAAAAAAEwTAAAA
AAAAYzr4/wAAAAC/ogAAAAAAAAcCAADw////GAEAAAAAAAAAAAAAAAAAAIUAAAABAAAAtAEAAAAA
AABjGmj/AAAAAGMacP8AAAAAYxqA/wAAAABjGoj/AAAAAGMaeP8AAAAAewrI/wAAAAAVAA4AAAAA
AHmiyP8AAAAAaSEEAAAAAABjGmj/AAAAAGkhAgAAAAAAYxpw/wAAAABxIQEAAAAAAGMagP8AAAAA
cSIAAAAAAAC8IQAAAAAAAFQBAAABAAAAYxp4/wAAAABUAgAAAgAAAHQCAAABAAAAYyqI/wAAAABh
YQwAAAAAAGMa8P8AAAAAtAEAAAAAAABrGvr/AAAAAHGRBQAAAAAAZAEAAAgAAABxkgQAAAAAAEwh
AAAAAAAAaxr4/wAAAAC0AQAAAQAAAGMaoP8AAAAAYxqY/wAAAAB5ocj/AAAAABUBAgAAAAAAtAEA
AAAAAABjGpj/AAAAAHmhwP8AAAAAVQECAAAAAAC0AQAAAAAAAGMaoP8AAAAAcZEBAAAAAABkAQAA
CAAAAHGSAAAAAAAATCEAAAAAAABxkgIAAAAAAGQCAAAQAAAAcZMDAAAAAABkAwAAGAAAAEwjAAAA
AAAATBMAAAAAAABjOvT/AAAAAL+iAAAAAAAABwIAAPD///8YAQAAAAAAAAAAAAAAAAAAhQAAAAEA
AAAVAAwAAAAAALQBAAABAAAAYxqQ/wAAAAB5ocj/AAAAAFUBAgAAAAAAtAEAAAAAAABjGpD/AAAA
AHmhyP8AAAAAVQEEAAAAAAB5ocD/AAAAABUBAgAAAAAAtAEAAAEAAABjGpD/AAAAAHmhsP8AAAAA
eaLQ/wAAAAAcEgAAAAAAAHsq0P8AAAAAYaGg/wAAAABhopj/AAAAAFwhAAAAAAAAYxqg/wAAAABx
cQkAAAAAAGMayP8AAAAAFgErAAEAAABhocj/AAAAABYBFgAGAAAAYaHI/wAAAABWAZ0CEQAAAHmh
0P8AAAAAVAEAAP//AACmAQgACAAAAHmhqP8AAAAABwEAAAgAAAB7Gpj/AAAAAC2BBAAAAAAAeaGw
/wAAAAAHAQAACAAAAHmiuP8AAAAAvSGXAAAAAAC0AQAACAAAAGMa8P8AAAAAv6IAAAAAAAAHAgAA
8P///xgBAAAAAAAAAAAAAAAAAACFAAAAAQAAABUAlQIAAAAABQCRAgAAAAB5odD/AAAAAFQBAAD/
/wAApgEHABQAAAB5oaj/AAAAAAcBAAAUAAAALYEEAAAAAAB5obD/AAAAAAcBAAAUAAAAeaK4/wAA
AAC9ISoAAAAAALQBAAAIAAAAYxrw/wAAAAC/ogAAAAAAAAcCAADw////GAEAAAAAAAAAAAAAAAAA
AIUAAAABAAAAFQCCAgAAAAAFAH4CAAAAAHmh0P8AAAAAVAEAAP//AACmARUACAAAAHmpqP8AAAAA
BwkAAAgAAAAtiRIAAAAAAHmisP8AAAAABwIAAAgAAAC0AQAAAQAAAHmjuP8AAAAALTIBAAAAAAC0
AQAAAAAAAGGikP8AAAAApAIAAP////9MIQAAAAAAAFQBAAABAAAAVgEHAAAAAAB5otD/AAAAAFQC
AAD//wAAeaGo/wAAAAC/gwAAAAAAALQEAAAAAAAAhRAAAP////9WAMEAAAAAALQBAAAIAAAAYxrw
/wAAAAC/ogAAAAAAAAcCAADw////GAEAAAAAAAAAAAAAAAAAAIUAAAABAAAAFQBhAgAAAAAFAF0C
AAAAAHmhqP8AAAAAaREMAAAAAAC8EgAAAAAAAHQCAAACAAAAVAIAADwAAACmAhMAFAAAAHmj0P8A
AAAAVAMAAP//AAAuMhAAAAAAAFQBAAAOAAAAtAIAAAEAAABWAQEAAAAAALQCAAAAAAAAYaGQ/wAA
AACkAQAA/////0whAAAAAAAAVAEAAAEAAABWAQcAAAAAAHmj0P8AAAAAVAMAAP//AAC/cQAAAAAA
AHmiqP8AAAAAv4QAAAAAAACFEAAAIgAAAFYAhwAAAAAAtAEAAAgAAABjGvD/AAAAAL+iAAAAAAAA
BwIAAPD///8YAQAAAAAAAAAAAAAAAAAAhQAAAAEAAAAVAD8CAAAAAAUAOwIAAAAAcZEAAAAAAABW
AQoA/wAAAHGRAQAAAAAAVgEIAP8AAABxkQIAAAAAAFYBBgD/AAAAcZEDAAAAAABWAQQA/wAAAHGR
BAAAAAAAVgECAP8AAABxkQUAAAAAABYBRgD/AAAAYWEMAAAAAAC0AgAAAAAAAGsq4v8AAAAAYxrY
/wAAAABxkQUAAAAAAGQBAAAIAAAAcZIEAAAAAABMIQAAAAAAAGsa4P8AAAAAcZEBAAAAAABkAQAA
CAAAAHGSAAAAAAAATCEAAAAAAABxkgIAAAAAAGQCAAAQAAAAcZMDAAAAAABkAwAAGAAAAEwjAAAA
AAAATBMAAAAAAABjOtz/AAAAAL+iAAAAAAAABwIAANj///8YAQAAAAAAAAAAAAAAAAAAhQAAAAEA
AABVACwAAAAAALQBAAAIAAAAYxrY/wAAAAC/ogAAAAAAAAcCAADY////GAEAAAAAAAAAAAAAAAAA
AIUAAAABAAAAFQAQAgAAAAAFAAwCAAAAALQBAAAIAAAAYxrY/wAAAAC/ogAAAAAAAAcCAADY////
GAEAAAAAAAAAAAAAAAAAAIUAAAABAAAAFQAHAgAAAAAFAAMCAAAAALQBAAAAAAAAYxrA/wAAAAB5
oaj/AAAAAGkRAAAAAAAAVgEHAABDAAB5oaj/AAAAAGkRAgAAAAAAtAIAAAEAAABjKsD/AAAAABYB
AgAARAAAtAEAAAAAAABjGsD/AAAAAGGhkP8AAAAAYaLA/wAAAABMIQAAAAAAAFQBAAABAAAAVgES
AAAAAAC0AQAACAAAAGMa8P8AAAAAv6IAAAAAAAAHAgAA8P///xgBAAAAAAAAAAAAAAAAAACFAAAA
AQAAABUA7QEAAAAABQDpAQAAAAC0AQAABAAAAGMa2P8AAAAAv6IAAAAAAAAHAgAA2P///xgBAAAA
AAAAAAAAAAAAAACFAAAAAQAAABUA+gEAAAAABQD2AQAAAAB5oaj/AAAAAGkRBAAAAAAA3AEAABAA
AACmAQ0ACAAAAHmi0P8AAAAAVAIAAP//AABeIQoAAAAAAHmhqP8AAAAAaREGAAAAAAAWAQcAAAAA
AHmj0P8AAAAAVAMAAP//AAC/cQAAAAAAAHmiqP8AAAAAv4QAAAAAAACFEAAAIgAAAFYAaAAAAAAA
tAEAAAgAAABjGvD/AAAAAL+iAAAAAAAABwIAAPD///8YAQAAAAAAAAAAAAAAAAAAhQAAAAEAAAAV
AMoBAAAAAAUAxgEAAAAAtAEAAAgAAABjGtj/AAAAAL+iAAAAAAAABwIAANj///8YAQAAAAAAAAAA
AAAAAAAAhQAAAAEAAAAVAMEBAAAAAAUAvQEAAAAAtAEAAAEAAABhooD/AAAAABYCAQAGAAAAtAEA
AAAAAABhooj/AAAAAFwSAAAAAAAAeaGo/wAAAABpEQIAAAAAAFYC1QABAAAAvxIAAAAAAADcAgAA
EAAAAGGjcP8AAAAALiPRAAAAAABho2j/AAAAAK4jzwAAAAAAtAEAAAEAAABjGvD/AAAAAL+iAAAA
AAAABwIAAPD///8YAQAAAAAAAAAAAAAAAAAAhQAAAAEAAAAVAL8BAAAAAAUAuwEAAAAAeaGo/wAA
AABxEQAAAAAAABYBDgALAAAAFgENAAMAAABWAaAAAAAAAHmhqP8AAAAAcREBAAAAAAAWAeYAAAAA
ALQBAAAIAAAAYxrw/wAAAAC/ogAAAAAAAAcCAADw////GAEAAAAAAAAAAAAAAAAAAIUAAAABAAAA
FQCYAQAAAAAFAJQBAAAAAHmiqP8AAAAABwIAABwAAAAtgukAAAAAAHmisP8AAAAABwIAABwAAAB5
o7j/AAAAAC0y5QAAAAAAcZcAAAAAAAC8cgAAAAAAAFQCAADwAAAAVgLhAEAAAAAWAd0ACwAAAFYB
AwADAAAAeaGo/wAAAABxEQEAAAAAACYB3AAPAAAAZAcAAAIAAABUBwAA/AAAAKYHEQAUAAAAeaGw
/wAAAAAPcQAAAAAAAAcBAAAQAAAAeaK4/wAAAAAtIQwAAAAAALxxAAAAAAAABAEAAAgAAAB5oqj/
AAAAAGkiCgAAAAAA3AIAABAAAAAuIQYAAAAAAL+RAAAAAAAAvHIAAAAAAAC/gwAAAAAAALQEAAAA
AAAAhRAAAP////9WANoAAAAAALQBAAAIAAAAYxrw/wAAAAC/ogAAAAAAAAcCAADw////GAEAAAAA
AAAAAAAAAAAAAIUAAAABAAAAFQBrAQAAAAAFAGcBAAAAAGGhwP8AAAAAVAEAAAEAAAAWAW0AAAAA
AHmhqP8AAAAABwEAAPgAAAAtgVgAAAAAAHmhsP8AAAAABwEAAPgAAAB5orj/AAAAAC0hVAAAAAAA
eaGY/wAAAABxEQAAAAAAAFYBUQACAAAAeaGo/wAAAABxEQkAAAAAAFYBTgABAAAAeaGo/wAAAABx
EQoAAAAAAFYBSwAGAAAAeaOo/wAAAABxMfUAAAAAAGQBAAAIAAAAcTL0AAAAAABMIQAAAAAAAHEy
9gAAAAAAZAIAABAAAABxM/cAAAAAAGQDAAAYAAAATCMAAAAAAABMEwAAAAAAAFYDPwBjglNjYWEM
AAAAAAC0AgAAAAAAAGsq+v8AAAAAYxrw/wAAAAB5o6j/AAAAAHExKQAAAAAAZAEAAAgAAABxMigA
AAAAAEwhAAAAAAAAaxr4/wAAAABxMSUAAAAAAGQBAAAIAAAAcTIkAAAAAABMIQAAAAAAAHEyJgAA
AAAAZAIAABAAAABxMycAAAAAAGQDAAAYAAAATCMAAAAAAABMEwAAAAAAAGM69P8AAAAAv6IAAAAA
AAAHAgAA8P///xgBAAAAAAAAAAAAAAAAAACFAAAAAQAAABUAJAAAAAAAeaGo/wAAAAAHAQAAJAAA
AHGSAAAAAAAAVgIKAP8AAABxkwEAAAAAAFYDCAD/AAAAcZMCAAAAAABWAwYA/wAAAHGTAwAAAAAA
VgMEAP8AAABxkwQAAAAAAFYDAgD/AAAAcZMFAAAAAAAWA+AA/wAAAHETAAAAAAAAXjIUAAAAAAB5
oqj/AAAAAHEiJQAAAAAAcZMBAAAAAABeIxAAAAAAAHmiqP8AAAAAcSImAAAAAABxkwIAAAAAAF4j
DAAAAAAAeaKo/wAAAABxIicAAAAAAHGTAwAAAAAAXiMIAAAAAAB5oqj/AAAAAHEiKAAAAAAAcZME
AAAAAABeIwQAAAAAAHmiqP8AAAAAcSIpAAAAAABxkwUAAAAAAB4jygAAAAAAtAEAAAgAAABjGvD/
AAAAAL+iAAAAAAAABwIAAPD///8YAQAAAAAAAAAAAAAAAAAAhQAAAAEAAAAVAAQBAAAAAAUAAAEA
AAAAtAEAAAgAAABjGvD/AAAAAL+iAAAAAAAABwIAAPD///8YAQAAAAAAAAAAAAAAAAAAhQAAAAEA
AAAVAPsAAAAAAAUA9wAAAAAAtAEAAAEAAABhooD/AAAAABYCAQARAAAAtAEAAAAAAABhooj/AAAA
AFwSAAAAAAAAeaGo/wAAAABpEQIAAAAAAFYCDwABAAAAvxIAAAAAAADcAgAAEAAAAGGjcP8AAAAA
LiMLAAAAAABho2j/AAAAAK4jCQAAAAAAtAEAAAEAAABjGvD/AAAAAL+iAAAAAAAABwIAAPD///8Y
AQAAAAAAAAAAAAAAAAAAhQAAAAEAAAAVAPkAAAAAAAUA9QAAAAAAYWIMAAAAAABjKtj/AAAAAGFy
DAAAAAAAYyrc/wAAAABhchAAAAAAAGMq4P8AAAAAeaKo/wAAAABpIgAAAAAAAGsa5v8AAAAAayrk
/wAAAABhocj/AAAAAHMa6P8AAAAAYaF4/wAAAABhoqD/AAAAAEwSAAAAAAAAVAIAAAEAAAAWAg4A
AAAAAL+iAAAAAAAABwIAANj///8YAQAAAAAAAAAAAAAAAAAAhQAAAAEAAAAVAAgAAAAAAHkGAAAA
AAAAhQAAAAUAAAAtBtMAAAAAAL+iAAAAAAAABwIAANj///8YAQAAAAAAAAAAAAAAAAAAhQAAAAMA
AAC0AQAACAAAAGMa2P8AAAAAv6IAAAAAAAAHAgAA2P///xgBAAAAAAAAAAAAAAAAAACFAAAAAQAA
ABUAuwAAAAAABQC3AAAAAABhYQwAAAAAAGMa2P8AAAAAYXEMAAAAAABjGtz/AAAAAGFxEAAAAAAA
Yxrg/wAAAAB5oqj/AAAAAHEhBAAAAAAAcSIFAAAAAABkAgAACAAAAEwSAAAAAAAABQDV/wAAAAB5
oaj/AAAAAHERAQAAAAAApgEk/wIAAAC0AQAACAAAAGMa8P8AAAAAv6IAAAAAAAAHAgAA8P///xgB
AAAAAAAAAAAAAAAAAACFAAAAAQAAABUAowAAAAAABQCfAAAAAAC0AQAABAAAAGMa2P8AAAAAv6IA
AAAAAAAHAgAA2P///xgBAAAAAAAAAAAAAAAAAACFAAAAAQAAABUAsAAAAAAABQCsAAAAAAB5oaj/
AAAAAGkRDgAAAAAAVAEAAJ//AAAWAQkAAAAAALQBAAAIAAAAYxrw/wAAAAC/ogAAAAAAAAcCAADw
////GAEAAAAAAAAAAAAAAAAAAIUAAAABAAAAFQCNAAAAAAAFAIkAAAAAAGFhDAAAAAAAYxrY/wAA
AAB5oqj/AAAAAGEhGAAAAAAAYxrc/wAAAABhIRQAAAAAAGMa4P8AAAAAcSERAAAAAABzGuj/AAAA
ABYBAQARAAAAVgENAAYAAAAPeQAAAAAAAL+RAAAAAAAABwEAAAQAAAC9gRIAAAAAALQBAAAIAAAA
Yxrw/wAAAAC/ogAAAAAAAAcCAADw////GAEAAAAAAAAAAAAAAAAAAIUAAAABAAAAFQB1AAAAAAAF
AHEAAAAAALQBAAAIAAAAYxrw/wAAAAC/ogAAAAAAAAcCAADw////GAEAAAAAAAAAAAAAAAAAAIUA
AAABAAAAFQBsAAAAAAAFAGgAAAAAAGmRAAAAAAAAaxrm/wAAAABpkQIAAAAAAGsa5P8AAAAAYaF4
/wAAAABhoqD/AAAAAEwSAAAAAAAAVAIAAAEAAAAWAg4AAAAAAL+iAAAAAAAABwIAANj///8YAQAA
AAAAAAAAAAAAAAAAhQAAAAEAAAAVAAgAAAAAAHkGAAAAAAAAhQAAAAUAAAAtBg4AAAAAAL+iAAAA
AAAABwIAANj///8YAQAAAAAAAAAAAAAAAAAAhQAAAAMAAAC0AQAACAAAAGMa8P8AAAAAv6IAAAAA
AAAHAgAA8P///xgBAAAAAAAAAAAAAAAAAACFAAAAAQAAABUATAAAAAAABQBIAAAAAAC0AQAABgAA
AGMa8P8AAAAAv6IAAAAAAAAHAgAA8P///xgBAAAAAAAAAAAAAAAAAACFAAAAAQAAABUAWQAAAAAA
BQBVAAAAAAB5paj/AAAAAHFSDwAAAAAAcVMOAAAAAABxVAwAAAAAAHFVDQAAAAAAYWAMAAAAAAC0
BgAAAAAAAGtq/v8AAAAAYwrw/wAAAABkBQAACAAAAExFAAAAAAAAZAMAABAAAABkAgAAGAAAAEwy
AAAAAAAATFIAAAAAAABjKvT/AAAAAHESBQAAAAAAZAIAAAgAAABxEwQAAAAAAEwyAAAAAAAAayr8
/wAAAABxEgEAAAAAAGQCAAAIAAAAcRMAAAAAAABMMgAAAAAAAHETAgAAAAAAZAMAABAAAABxEQMA
AAAAAGQBAAAYAAAATDEAAAAAAABMIQAAAAAAAGMa+P8AAAAAv6IAAAAAAAAHAgAA8P///xgBAAAA
AAAAAAAAAAAAAACFAAAAAQAAABUACAAAAAAAeQYAAAAAAACFAAAABQAAAC0GGwAAAAAAv6IAAAAA
AAAHAgAA8P///xgBAAAAAAAAAAAAAAAAAACFAAAAAwAAALQBAAAIAAAAYxrw/wAAAAC/ogAAAAAA
AAcCAADw////GAEAAAAAAAAAAAAAAAAAAIUAAAABAAAAFQAMAAAAAAAFAAgAAAAAALQBAAAIAAAA
Yxrw/wAAAAC/ogAAAAAAAAcCAADw////GAEAAAAAAAAAAAAAAAAAAIUAAAABAAAAFQADAAAAAAB5
AQAAAAAAAAcBAAABAAAAexAAAAAAAAC0AAAAAQAAAJUAAAAAAAAAtAEAAAMAAABjGvD/AAAAAL+i
AAAAAAAABwIAAPD///8YAQAAAAAAAAAAAAAAAAAAhQAAAAEAAAAVAAwAAAAAAAUACAAAAAAAtAEA
AAUAAABjGvD/AAAAAL+iAAAAAAAABwIAAPD///8YAQAAAAAAAAAAAAAAAAAAhQAAAAEAAAAVAAMA
AAAAAHkBAAAAAAAABwEAAAEAAAB7EAAAAAAAALQAAAACAAAABQDp/wAAAABhFlAAAAAAAGEYTAAA
AAAAtwIAAAAAAABjKvz/AAAAAGMq+P8AAAAAv4cAAAAAAAAHBwAADgAAAC1n2AAAAAAAYRIoAAAA
AAC0AwAAAAAAAGM64P8AAAAAYyrY/wAAAAC0AgAAAQAAAHMq0P8AAAAAcYIGAAAAAAC8IwAAAAAA
AFQDAAABAAAAVgMtAAAAAABxgwgAAAAAAHGEBwAAAAAATDQAAAAAAABxgwkAAAAAAEw0AAAAAAAA
cYMKAAAAAABMNAAAAAAAAHGDCwAAAAAATDQAAAAAAABMJAAAAAAAAFQEAAD/AAAAFgQhAAAAAAC/
ogAAAAAAAAcCAADc////v4MAAAAAAAAHAwAABgAAAHE0BQAAAAAAc0IFAAAAAABxNAQAAAAAAHNC
BAAAAAAAcTQDAAAAAABzQgMAAAAAAHE0AgAAAAAAc0ICAAAAAABxNAEAAAAAAHNCAQAAAAAAcTMA
AAAAAABzMgAAAAAAAL+iAAAAAAAABwIAANj///+/GQAAAAAAABgBAAAAAAAAAAAAAAAAAACFAAAA
AQAAAL+RAAAAAAAAVQAJAAAAAAC/ogAAAAAAAAcCAADY////v6MAAAAAAAAHAwAA0P///xgBAAAA
AAAAAAAAAAAAAAC3BAAAAAAAAIUAAAACAAAAv5EAAAAAAABxgwwAAAAAAHGCDQAAAAAAZAIAAAgA
AABMMgAAAAAAABYCAQCIqAAAVgIQAIEAAAC/hwAAAAAAAAcHAAASAAAALWeYAAAAAABxgxAAAAAA
AHGCEQAAAAAAZAIAAAgAAABMMgAAAAAAABYCAQCIqAAAVgIHAIEAAAC/hwAAAAAAAAcHAAAWAAAA
LWePAAAAAABxgxQAAAAAAHGCFQAAAAAAZAIAAAgAAABMMgAAAAAAAFYCigAIAAAAv3IAAAAAAAAH
AgAAFAAAAC1ihwAAAAAAcXIAAAAAAAC8IwAAAAAAAFQDAADwAAAAVgODAEAAAABkAgAAAgAAALwj
AAAAAAAAVAMAAPwAAACmA38AFAAAAFcCAAD/AAAAv3gAAAAAAAAPKAAAAAAAAC1oewAAAAAAaXIG
AAAAAABUAgAAH/8AAFYCeAAAAAAAYREoAAAAAABjGuz/AAAAAGFyEAAAAAAAYyrw/wAAAABhcgwA
AAAAAGMq9P8AAAAAcXIJAAAAAABzKvz/AAAAABYCWAABAAAAFgILABEAAABWAm0ABgAAAL+BAAAA
AAAABwEAABQAAAAtYWoAAAAAAGmBAgAAAAAAaxr4/wAAAABpgQAAAAAAAGsa+v8AAAAAGAYAAABA
cWEAAAAAjAYAAAUAWAAAAAAAv4cAAAAAAAAHBwAACAAAAC1nYAAAAAAAaYIAAAAAAABWAkEAAEQA
ALQCAAAARAAAaYMCAAAAAABWAz4AAEMAALQCAAAAAAAAYyrk/wAAAABjGtj/AAAAAIUAAAAFAAAA
GAEAAAAEa/QAAAAAFAAAAA8QAAAAAAAAewrQ/wAAAAC/gQAAAAAAAAcBAAD4AAAALWFQAAAAAABx
cQAAAAAAAFYBTgABAAAAcYEJAAAAAABWAUwAAQAAAHGBCgAAAAAAVgFKAAYAAABxgfUAAAAAAGQB
AAAIAAAAcYL0AAAAAABMIQAAAAAAAHGC9gAAAAAAZAIAABAAAABxg/cAAAAAAGQDAAAYAAAATCMA
AAAAAABMEwAAAAAAAFYDPwBjglNjv6EAAAAAAAAHAQAA4P///3GCDQAAAAAAZAIAAAgAAABxgwwA
AAAAAEwyAAAAAAAAcYMOAAAAAABkAwAAEAAAAHGEDwAAAAAAZAQAABgAAABMNAAAAAAAAEwkAAAA
AAAAY0rc/wAAAABxgikAAAAAAHMhBQAAAAAAcYIoAAAAAABzIQQAAAAAAHGCJwAAAAAAcyEDAAAA
AABxgiYAAAAAAHMhAgAAAAAAcYIlAAAAAABzIQEAAAAAAHGCJAAAAAAAcyEAAAAAAAC/ogAAAAAA
AAcCAADY////v6MAAAAAAAAHAwAA0P///xgBAAAAAAAAAAAAAAAAAAC3BAAAAAAAAIUAAAACAAAA
aYIAAAAAAABpgQIAAAAAAGsq+v8AAAAAaxr4/wAAAAAYBgAAALhk2QAAAABFAAAABQAMAAAAAAC/
gQAAAAAAAAcBAAAIAAAALWEUAAAAAABxgQAAAAAAAFYBEgAIAAAAcYEEAAAAAABxggUAAAAAAGQC
AAAIAAAATBIAAAAAAABrKvj/AAAAABgGAAAAWEf4AAAAAA0AAACFAAAABQAAAA9gAAAAAAAAewrY
/wAAAAC/ogAAAAAAAAcCAADs////v6MAAAAAAAAHAwAA2P///xgBAAAAAAAAAAAAAAAAAAC3BAAA
AAAAAIUAAAACAAAAtAAAAAAAAACVAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAR1BMAJ/rAQAYAAAAAAAAADgLAAA4CwAAkQQAAAAAAAAA
AAACAwAAAAEAAAAAAAABBAAAACAAAAEAAAAAAAAAAwAAAAACAAAABAAAAAIAAAAFAAAAAAAAAQQA
AAAgAAAAAAAAAAAAAAIGAAAAAAAAAAAAAAMAAAAAAgAAAAQAAAABAAAAAAAAAAAAAAIIAAAAGQAA
AAAAAAgJAAAAHwAAAAAAAAEEAAAAIAAAAAAAAAAAAAACCwAAACwAAAAAAAAIDAAAADEAAAAAAAAB
AQAAAAgAAAAAAAAABAAABCAAAAA/AAAAAQAAAAAAAABEAAAABQAAAEAAAABQAAAABwAAAIAAAABU
AAAACgAAAMAAAABaAAAAAAAADg0AAAABAAAAAAAAAAAAAAIQAAAAAAAAAAAAAAMAAAAAAgAAAAQA
AAAAAQAAAAAAAAAAAAISAAAAcAAAAAMAAAQMAAAAfgAAAAgAAAAAAAAAhgAAABMAAAAgAAAAigAA
ABUAAABQAAAAjgAAAAEAAAQGAAAAlwAAABQAAAAAAAAAAAAAAAAAAAMAAAAACwAAAAQAAAAGAAAA
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
CAAAAEACAADsAQAACAAAAGACAADxAQAACAAAAIACAACqAwAACAAAAKACAACyAwAACAAAAMACAAC5
AwAACAAAAOACAADEAwAACAAAAAADAADOAwAATgAAACADAADZAwAATgAAAKADAAA7AQAACAAAACAE
AABHAQAACAAAAEAEAAD6AQAACAAAAGAEAAAAAAAATwAAAIAEAADjAwAAIwAAAMAEAADqAwAACAAA
AAAFAADzAwAACAAAACAFAAAAAAAAUQAAAEAFAAD8AwAACAAAAIAFAAAFBAAACwAAAKAFAAARBAAA
IwAAAMAFAAAAAAAAAAAAAwAAAAAIAAAABAAAAAUAAAAAAAAAAAAAAwAAAAAIAAAABAAAAAQAAAAA
AAAAAQAABQgAAAAaBAAAUAAAAAAAAAAAAAAAAAAAAl0AAAAAAAAAAQAABQgAAAAkBAAAUgAAAAAA
AAAAAAAAAAAAAl4AAAAAAAAAAQAADQIAAAAyAgAASwAAACcEAAABAAAMUwAAAAAAAAACAAANVgAA
ADoEAAAIAAAAQAQAAEAAAABHBAAAAAAAAQgAAABAAAABTAQAAAAAAAxVAAAAXwQAAAAAAAEBAAAA
CAAAAQAAAAAAAAADAAAAAFgAAAAEAAAABAAAAGQEAAAAAAAOWQAAAAEAAABsBAAABwAADwAAAAAO
AAAAAAAAACAAAAAXAAAAAAAAACAAAAAbAAAAAAAAACAAAAAmAAAAAAAAACAAAAAwAAAAAAAAACAA
AAA2AAAAAAAAACAAAAA7AAAAAAAAACAAAAByBAAAAQAADwAAAABaAAAAAAAAAAQAAAB6BAAAAAAA
BwAAAACIBAAAAAAABwAAAAAAaW50AF9fQVJSQVlfU0laRV9UWVBFX18AX191MzIAdW5zaWduZWQg
aW50AF9fdTgAdW5zaWduZWQgY2hhcgB0eXBlAG1heF9lbnRyaWVzAGtleQB2YWx1ZQBub2lkX3hk
cF9nbG9iYWxfYWxsb3cAbm9pZF9saW5rX21hYwBpZmluZGV4AG1hYwBwYWQAbm9pZF9tYWMAYWRk
cgBub2lkX3hkcF9nYXRld2F5X21hY3MAbm9pZF94ZHBfbG9jYWxfbWFjcwBub2lkX2RoY3A0AHhp
ZABfX2JlMzIAbm9pZF9leHBpcnkAZXhwaXJlc19ucwBfX3U2NAB1bnNpZ25lZCBsb25nIGxvbmcA
bm9pZF94ZHBfZGhjcF92NABub2lkX2Zsb3c0AHJlbW90ZV9pcABsb2NhbF9pcAByZW1vdGVfcG9y
dABsb2NhbF9wb3J0AHByb3RvY29sAF9fYmUxNgBfX3UxNgB1bnNpZ25lZCBzaG9ydABub2lkX3hk
cF9mbG93c192NABub2lkX3BlZXI0AGlwAG5vaWRfcGVlcjRfcG9saWN5AGRpcmVjdGlvbgBwb3J0
X3N0YXJ0AHBvcnRfZW5kAG5vaWRfeGRwX3BlZXI0AG5vaWRfeGRwX3N0YXRzAHhkcF9tZABkYXRh
AGRhdGFfZW5kAGRhdGFfbWV0YQBpbmdyZXNzX2lmaW5kZXgAcnhfcXVldWVfaW5kZXgAZWdyZXNz
X2lmaW5kZXgAY3R4AG5vaWRfbGFuX3hkcAB4ZHAAL3Vzci9zcmMvbm9pZC1wcml2YWN5LWZlZG9y
YS9ub2lkLWxhbi14ZHAuYnBmLmMAc3RhcnQAbGVuZ3RoAHBhY2tldF9lbmQAc2VlZABub2lkX2No
ZWNrc3VtX3ZhbGlkAC50ZXh0AGlwaGRyAGlobAB2ZXJzaW9uAHRvcwB0b3RfbGVuAGlkAGZyYWdf
b2ZmAHR0bABjaGVjawBfX3N1bTE2AGFkZHJzAHNhZGRyAGRhZGRyAHRyYW5zcG9ydAB0cmFuc3Bv
cnRfbGVuZ3RoAG5vaWRfaXB2NF90cmFuc3BvcnRfY2hlY2tzdW1fdmFsaWQAX19za19idWZmAGxl
bgBwa3RfdHlwZQBtYXJrAHF1ZXVlX21hcHBpbmcAdmxhbl9wcmVzZW50AHZsYW5fdGNpAHZsYW5f
cHJvdG8AcHJpb3JpdHkAdGNfaW5kZXgAY2IAaGFzaAB0Y19jbGFzc2lkAG5hcGlfaWQAZmFtaWx5
AHJlbW90ZV9pcDQAbG9jYWxfaXA0AHJlbW90ZV9pcDYAbG9jYWxfaXA2AHRzdGFtcAB3aXJlX2xl
bgBnc29fc2VncwBnc29fc2l6ZQB0c3RhbXBfdHlwZQBod3RzdGFtcABmbG93X2tleXMAc2sAbm9p
ZF9sYW5fZWdyZXNzAHRjAGluZGV4AG9wYXF1ZQBsb25nAG5vaWRfY2hlY2tzdW1fc3RlcABjaGFy
AExJQ0VOU0UALm1hcHMAbGljZW5zZQBicGZfZmxvd19rZXlzAGJwZl9zb2NrAAAAAJ/rAQAgAAAA
AAAAAEQAAABEAAAATCcAAJAnAAAAAAAACAAAAEMCAAABAAAAAAAAAD8AAACoAgAAAwAAAAAAAABC
AAAAGAEAAEoAAACwAQAAVwAAADcEAAABAAAAAAAAAFQAAAAQAAAAQwIAAOMBAAAAAAAARwIAAAAA
AAAAhAYACAAAAEcCAAAAAAAAKZAGABAAAABHAgAAAAAAACWMBgAgAAAARwIAAAAAAAALoAYAKAAA
AEcCAAAAAAAAFrAGADgAAABHAgAAAAAAABuwBgBgAAAARwIAAAAAAAAWcAMAeAAAAEcCAAAAAAAA
CXgDAJgAAABHAgAAAAAAAA68BgCwAAAARwIAAAAAAAAQwAYAuAAAAEcCAAAAAAAAE8AGAMAAAABH
AgAAAAAAABDABgDoAAAARwIAAAAAAAAWcAMAAAEAAEcCAAAAAAAACXgDAAgBAABHAgAAAAAAABJ8
AwAQAQAARwIAAAAAAAAt0AYAIAEAAEcCAAAAAAAAIJgDACgBAABHAgAAAAAAACCYAwAwAQAARwIA
AAAAAAAFoAMAwAEAAEcCAAAAAAAACaQDAPgBAABHAgAAAAAAADD8BgAIAgAARwIAAAAAAAAbDAcA
GAIAAEcCAAAAAAAAIAwHAEACAABHAgAAAAAAABZwAwBYAgAARwIAAAAAAAAJeAMAiAIAAEcCAAAA
AAAAMPwGAJgCAABHAgAAAAAAABsMBwCoAgAARwIAAAAAAAAgDAcA0AIAAEcCAAAAAAAALCgHAAAD
AABHAgAAAAAAABZwAwAYAwAARwIAAAAAAAAJeAMAOAMAAEcCAAAAAAAAEjgHAFADAABHAgAAAAAA
ABxIBwBgAwAARwIAAAAAAAAsSAcAaAMAAEcCAAAAAAAACRwEAHADAABHAgAAAAAAABEcBACAAwAA
RwIAAAAAAAARHAQAiAMAAEcCAAAAAAAAFCwEAJgDAABHAgAAAAAAABEsBACgAwAARwIAAAAAAAAU
LAQAqAMAAEcCAAAAAAAAESwEALADAABHAgAAAAAAABQsBAC4AwAARwIAAAAAAAARLAQAwAMAAEcC
AAAAAAAAFCwEAMgDAABHAgAAAAAAABEsBADgAwAARwIAAAAAAAA4TAcA6AMAAEcCAAAAAAAADcwD
APADAABHAgAAAAAAABXMAwD4AwAARwIAAAAAAAANzAMAAAQAAEcCAAAAAAAAFcwDAAgEAABHAgAA
AAAAAA3MAwAQBAAARwIAAAAAAAAVzAMAGAQAAEcCAAAAAAAADcwDACAEAABHAgAAAAAAABXMAwAo
BAAARwIAAAAAAAANzAMAMAQAAEcCAAAAAAAAFcwDADgEAABHAgAAAAAAAA3MAwBABAAARwIAAAAA
AAAVzAMASAQAAEcCAAAAAAAAKFgHAFgEAABHAgAAAAAAACCYAwBgBAAARwIAAAAAAAAgmAMAaAQA
AEcCAAAAAAAABaADAPgEAABHAgAAAAAAAAmkAwAgBQAARwIAAAAAAABHWAcAKAUAAEcCAAAAAAAA
FFwHADAFAABHAgAAAAAAACBcBwBABQAARwIAAAAAAABAXAcASAUAAEcCAAAAAAAANlwHAHAFAABH
AgAAAAAAABZwAwCIBQAARwIAAAAAAAAJeAMAmAUAAEcCAAAAAAAAGowHAKgFAABHAgAAAAAAAB+M
BwDQBQAARwIAAAAAAAAWcAMA6AUAAEcCAAAAAAAACXgDAAAGAABHAgAAAAAAABtsCAAgBgAARwIA
AAAAAAAYdAgAMAYAAEcCAAAAAAAAL3QIAFgGAABHAgAAAAAAABZwAwBwBgAARwIAAAAAAAAJeAMA
gAYAAEcCAAAAAAAAGZQHAKAGAABHAgAAAAAAAEeUBwCoBgAARwIAAAAAAAAZmAcAyAYAAEcCAAAA
AAAAPpgHANAGAABHAgAAAAAAABmcBwDYBgAARwIAAAAAAAAynAcA4AYAAEcCAAAAAAAAGaAHAOgG
AABHAgAAAAAAADKcBwAQBwAARwIAAAAAAAAWcAMAKAcAAEcCAAAAAAAACXgDADgHAABHAgAAAAAA
ABF8CABABwAARwIAAAAAAAAZfAgAUAcAAEcCAAAAAAAAGXwIAHgHAABHAgAAAAAAABZwAwCQBwAA
RwIAAAAAAAAJeAMAoAcAAEcCAAAAAAAAF4QIALAHAABHAgAAAAAAACiICAC4BwAARwIAAAAAAAAY
jAgAyAcAAEcCAAAAAAAANIgIAPAHAABHAgAAAAAAABZwAwAICAAARwIAAAAAAAAJeAMAKAgAAEcC
AAAAAAAAGJQIAEAIAABHAgAAAAAAACCYCABYCAAARwIAAAAAAAAYnAgAeAgAAEcCAAAAAAAAMpwI
AIAIAABHAgAAAAAAADmcCACICAAARwIAAAAAAABCnAgAkAgAAEcCAAAAAAAACRwEAKAIAABHAgAA
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
AAAAABsQDQBYBgAARwIAAAAAAAArEA0AYAYAAEcCAAAAAAAAExQNAGgGAABHAgAAAAAAACsQDQBw
BgAARwIAAAAAAAAiHA0AkAYAAEcCAAAAAAAAGhwNAOAGAABHAgAAAAAAAAU0DQAABwAARwIAAAAA
AAABPA0AERkGExQVGBcaFhIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAAEAAAAA
AAAAAAAAAAAAAAAAAAAAAAADAAMAAAAAAAAAAAAAAAAAAAAAAAEAAAACAAEAAAAAAAAAAAAYAQAA
AAAAABUAAAACAAEAGAEAAAAAAACYAAAAAAAAADgAAAACAAEAsAEAAAAAAAD4AAAAAAAAAAAAAAAD
AAUAAAAAAAAAAAAAAAAAAAAAAEsAAAASAAMAAAAAAAAAAADoKAAAAAAAAFgAAAARAAcAwAAAAAAA
AAAgAAAAAAAAAGcAAAARAAcAAAAAAAAAAAAgAAAAAAAAAH0AAAARAAcAIAAAAAAAAAAgAAAAAAAA
AJMAAAARAAcAQAAAAAAAAAAgAAAAAAAAAKcAAAARAAcAoAAAAAAAAAAgAAAAAAAAALYAAAARAAcA
gAAAAAAAAAAgAAAAAAAAAMgAAAARAAcAYAAAAAAAAAAgAAAAAAAAANkAAAASAAUAAAAAAAAAAAAQ
BwAAAAAAAOkAAAARAAgAAAAAAAAAAAAEAAAAAAAAAABub2lkX2NoZWNrc3VtX3ZhbGlkAG5vaWRf
aXB2NF90cmFuc3BvcnRfY2hlY2tzdW1fdmFsaWQAbm9pZF9jaGVja3N1bV9zdGVwAG5vaWRfbGFu
X3hkcABub2lkX3hkcF9zdGF0cwBub2lkX3hkcF9nbG9iYWxfYWxsb3cAbm9pZF94ZHBfZ2F0ZXdh
eV9tYWNzAG5vaWRfeGRwX2xvY2FsX21hY3MAbm9pZF94ZHBfcGVlcjQAbm9pZF94ZHBfZmxvd3Nf
djQAbm9pZF94ZHBfZGhjcF92NABub2lkX2xhbl9lZ3Jlc3MATElDRU5TRQAAAAAAAAAAcAAAAAAA
AAABAAAAAQAAAGAAAAAAAAAAAQAAAAgAAACYAAAAAAAAAAEAAAAJAAAA6AAAAAAAAAABAAAACAAA
AMABAAAAAAAAAQAAAAoAAABAAgAAAAAAAAEAAAAIAAAAAAMAAAAAAAABAAAACAAAAPgEAAAAAAAA
AQAAAAsAAABwBQAAAAAAAAEAAAAIAAAA0AUAAAAAAAABAAAACAAAAFgGAAAAAAAAAQAAAAgAAAAQ
BwAAAAAAAAEAAAAIAAAAeAcAAAAAAAABAAAACAAAAPAHAAAAAAAAAQAAAAgAAABICQAAAAAAAAoA
AAABAAAAeAkAAAAAAAABAAAACAAAAJgLAAAAAAAAAQAAAAsAAABoDQAAAAAAAAEAAAALAAAAqA0A
AAAAAAABAAAACAAAAPANAAAAAAAAAQAAAAgAAABwDgAAAAAAAAEAAAAIAAAAuA4AAAAAAAABAAAA
CAAAACAPAAAAAAAAAQAAAAgAAAAgEAAAAAAAAAEAAAAMAAAA8BEAAAAAAAABAAAACwAAAGATAAAA
AAAAAQAAAAgAAAD4EwAAAAAAAAEAAAAIAAAA0BQAAAAAAAAKAAAAAQAAAAAVAAAAAAAAAQAAAAgA
AADgFQAAAAAAAAoAAAABAAAAEBYAAAAAAAABAAAACAAAAEgXAAAAAAAAAQAAAAsAAACIFwAAAAAA
AAEAAAAIAAAA0BcAAAAAAAABAAAACAAAAKAYAAAAAAAAAQAAAAgAAADoGAAAAAAAAAEAAAAIAAAA
iBkAAAAAAAAKAAAAAQAAALgZAAAAAAAAAQAAAAgAAAAAGgAAAAAAAAEAAAAIAAAAwBoAAAAAAAAB
AAAACAAAAEgbAAAAAAAAAQAAAAgAAACAHAAAAAAAAAoAAAABAAAAsBwAAAAAAAABAAAACAAAAIge
AAAAAAAAAQAAAAsAAADoHwAAAAAAAAEAAAAIAAAAMCAAAAAAAAABAAAACAAAAPAgAAAAAAAAAQAA
AAgAAACwIQAAAAAAAAEAAAANAAAA+CEAAAAAAAABAAAADQAAADAiAAAAAAAAAQAAAAgAAADwIgAA
AAAAAAEAAAAIAAAAOCMAAAAAAAABAAAACAAAAKAjAAAAAAAAAQAAAAgAAABgJAAAAAAAAAEAAAAI
AAAAqCQAAAAAAAABAAAACAAAACglAAAAAAAAAQAAAA0AAABwJQAAAAAAAAEAAAANAAAAqCUAAAAA
AAABAAAACAAAAPAlAAAAAAAAAQAAAAgAAAAoJwAAAAAAAAEAAAAOAAAAcCcAAAAAAAABAAAADgAA
AKgnAAAAAAAAAQAAAAgAAADwJwAAAAAAAAEAAAAIAAAAWCgAAAAAAAABAAAACAAAAKAoAAAAAAAA
AQAAAAgAAACIAQAAAAAAAAEAAAALAAAA0AEAAAAAAAABAAAACwAAAPAFAAAAAAAAAQAAAA4AAADg
BgAAAAAAAAEAAAANAAAA0AoAAAAAAAAEAAAACQAAANwKAAAAAAAABAAAAAoAAADoCgAAAAAAAAQA
AAALAAAA9AoAAAAAAAAEAAAADgAAAAALAAAAAAAABAAAAA0AAAAMCwAAAAAAAAQAAAAMAAAAGAsA
AAAAAAAEAAAACAAAADALAAAAAAAABAAAABAAAAAsAAAAAAAAAAQAAAACAAAAPAAAAAAAAAAEAAAA
AQAAAEQAAAAAAAAABAAAAAEAAABMAAAAAAAAAAQAAAABAAAAXAAAAAAAAAAEAAAABgAAAHAAAAAA
AAAABAAAAAIAAACAAAAAAAAAAAQAAAACAAAAkAAAAAAAAAAEAAAAAgAAAKAAAAAAAAAABAAAAAIA
AACwAAAAAAAAAAQAAAACAAAAwAAAAAAAAAAEAAAAAgAAANAAAAAAAAAABAAAAAIAAADgAAAAAAAA
AAQAAAACAAAA8AAAAAAAAAAEAAAAAgAAAAABAAAAAAAABAAAAAIAAAAQAQAAAAAAAAQAAAACAAAA
IAEAAAAAAAAEAAAAAgAAADABAAAAAAAABAAAAAIAAABAAQAAAAAAAAQAAAACAAAAUAEAAAAAAAAE
AAAAAgAAAGABAAAAAAAABAAAAAIAAABwAQAAAAAAAAQAAAACAAAAgAEAAAAAAAAEAAAAAgAAAJAB
AAAAAAAABAAAAAIAAACgAQAAAAAAAAQAAAACAAAAsAEAAAAAAAAEAAAAAgAAAMABAAAAAAAABAAA
AAIAAADQAQAAAAAAAAQAAAACAAAA4AEAAAAAAAAEAAAAAgAAAPABAAAAAAAABAAAAAIAAAAAAgAA
AAAAAAQAAAACAAAAEAIAAAAAAAAEAAAAAgAAACACAAAAAAAABAAAAAIAAAAwAgAAAAAAAAQAAAAC
AAAAQAIAAAAAAAAEAAAAAgAAAFACAAAAAAAABAAAAAIAAABgAgAAAAAAAAQAAAACAAAAcAIAAAAA
AAAEAAAAAgAAAIACAAAAAAAABAAAAAIAAACQAgAAAAAAAAQAAAACAAAAoAIAAAAAAAAEAAAAAgAA
ALACAAAAAAAABAAAAAIAAADAAgAAAAAAAAQAAAACAAAA0AIAAAAAAAAEAAAAAgAAAOACAAAAAAAA
BAAAAAIAAADwAgAAAAAAAAQAAAACAAAAAAMAAAAAAAAEAAAAAgAAABADAAAAAAAABAAAAAIAAAAg
AwAAAAAAAAQAAAACAAAAMAMAAAAAAAAEAAAAAgAAAEADAAAAAAAABAAAAAIAAABQAwAAAAAAAAQA
AAACAAAAYAMAAAAAAAAEAAAAAgAAAHADAAAAAAAABAAAAAIAAACAAwAAAAAAAAQAAAACAAAAkAMA
AAAAAAAEAAAAAgAAAKADAAAAAAAABAAAAAIAAACwAwAAAAAAAAQAAAACAAAAwAMAAAAAAAAEAAAA
AgAAANADAAAAAAAABAAAAAIAAADgAwAAAAAAAAQAAAACAAAA8AMAAAAAAAAEAAAAAgAAAAAEAAAA
AAAABAAAAAIAAAAQBAAAAAAAAAQAAAACAAAAIAQAAAAAAAAEAAAAAgAAADAEAAAAAAAABAAAAAIA
AABABAAAAAAAAAQAAAACAAAAUAQAAAAAAAAEAAAAAgAAAGAEAAAAAAAABAAAAAIAAABwBAAAAAAA
AAQAAAACAAAAgAQAAAAAAAAEAAAAAgAAAJAEAAAAAAAABAAAAAIAAACgBAAAAAAAAAQAAAACAAAA
sAQAAAAAAAAEAAAAAgAAAMAEAAAAAAAABAAAAAIAAADQBAAAAAAAAAQAAAACAAAA4AQAAAAAAAAE
AAAAAgAAAPAEAAAAAAAABAAAAAIAAAAABQAAAAAAAAQAAAACAAAAEAUAAAAAAAAEAAAAAgAAACAF
AAAAAAAABAAAAAIAAAAwBQAAAAAAAAQAAAACAAAAQAUAAAAAAAAEAAAAAgAAAFAFAAAAAAAABAAA
AAIAAABgBQAAAAAAAAQAAAACAAAAcAUAAAAAAAAEAAAAAgAAAIAFAAAAAAAABAAAAAIAAACQBQAA
AAAAAAQAAAACAAAAoAUAAAAAAAAEAAAAAgAAALAFAAAAAAAABAAAAAIAAADABQAAAAAAAAQAAAAC
AAAA0AUAAAAAAAAEAAAAAgAAAOAFAAAAAAAABAAAAAIAAADwBQAAAAAAAAQAAAACAAAAAAYAAAAA
AAAEAAAAAgAAABAGAAAAAAAABAAAAAIAAAAgBgAAAAAAAAQAAAACAAAAMAYAAAAAAAAEAAAAAgAA
AEAGAAAAAAAABAAAAAIAAABQBgAAAAAAAAQAAAACAAAAYAYAAAAAAAAEAAAAAgAAAHAGAAAAAAAA
BAAAAAIAAACABgAAAAAAAAQAAAACAAAAkAYAAAAAAAAEAAAAAgAAAKAGAAAAAAAABAAAAAIAAACw
BgAAAAAAAAQAAAACAAAAwAYAAAAAAAAEAAAAAgAAANAGAAAAAAAABAAAAAIAAADgBgAAAAAAAAQA
AAACAAAA8AYAAAAAAAAEAAAAAgAAAAAHAAAAAAAABAAAAAIAAAAQBwAAAAAAAAQAAAACAAAAIAcA
AAAAAAAEAAAAAgAAADAHAAAAAAAABAAAAAIAAABABwAAAAAAAAQAAAACAAAAUAcAAAAAAAAEAAAA
AgAAAGAHAAAAAAAABAAAAAIAAABwBwAAAAAAAAQAAAACAAAAgAcAAAAAAAAEAAAAAgAAAJAHAAAA
AAAABAAAAAIAAACgBwAAAAAAAAQAAAACAAAAsAcAAAAAAAAEAAAAAgAAAMAHAAAAAAAABAAAAAIA
AADQBwAAAAAAAAQAAAACAAAA4AcAAAAAAAAEAAAAAgAAAPAHAAAAAAAABAAAAAIAAAAACAAAAAAA
AAQAAAACAAAAEAgAAAAAAAAEAAAAAgAAACAIAAAAAAAABAAAAAIAAAAwCAAAAAAAAAQAAAACAAAA
QAgAAAAAAAAEAAAAAgAAAFAIAAAAAAAABAAAAAIAAABgCAAAAAAAAAQAAAACAAAAcAgAAAAAAAAE
AAAAAgAAAIAIAAAAAAAABAAAAAIAAACQCAAAAAAAAAQAAAACAAAAoAgAAAAAAAAEAAAAAgAAALAI
AAAAAAAABAAAAAIAAADACAAAAAAAAAQAAAACAAAA0AgAAAAAAAAEAAAAAgAAAOAIAAAAAAAABAAA
AAIAAADwCAAAAAAAAAQAAAACAAAAAAkAAAAAAAAEAAAAAgAAABAJAAAAAAAABAAAAAIAAAAgCQAA
AAAAAAQAAAACAAAAMAkAAAAAAAAEAAAAAgAAAEAJAAAAAAAABAAAAAIAAABQCQAAAAAAAAQAAAAC
AAAAYAkAAAAAAAAEAAAAAgAAAHAJAAAAAAAABAAAAAIAAACACQAAAAAAAAQAAAACAAAAkAkAAAAA
AAAEAAAAAgAAAKAJAAAAAAAABAAAAAIAAACwCQAAAAAAAAQAAAACAAAAwAkAAAAAAAAEAAAAAgAA
ANAJAAAAAAAABAAAAAIAAADgCQAAAAAAAAQAAAACAAAA8AkAAAAAAAAEAAAAAgAAAAAKAAAAAAAA
BAAAAAIAAAAQCgAAAAAAAAQAAAACAAAAIAoAAAAAAAAEAAAAAgAAADAKAAAAAAAABAAAAAIAAABA
CgAAAAAAAAQAAAACAAAAUAoAAAAAAAAEAAAAAgAAAGAKAAAAAAAABAAAAAIAAABwCgAAAAAAAAQA
AAACAAAAgAoAAAAAAAAEAAAAAgAAAJAKAAAAAAAABAAAAAIAAACgCgAAAAAAAAQAAAACAAAAsAoA
AAAAAAAEAAAAAgAAAMAKAAAAAAAABAAAAAIAAADQCgAAAAAAAAQAAAACAAAA4AoAAAAAAAAEAAAA
AgAAAPAKAAAAAAAABAAAAAIAAAAACwAAAAAAAAQAAAACAAAAEAsAAAAAAAAEAAAAAgAAACALAAAA
AAAABAAAAAIAAAAwCwAAAAAAAAQAAAACAAAAQAsAAAAAAAAEAAAAAgAAAFALAAAAAAAABAAAAAIA
AABgCwAAAAAAAAQAAAACAAAAcAsAAAAAAAAEAAAAAgAAAIALAAAAAAAABAAAAAIAAACQCwAAAAAA
AAQAAAACAAAAoAsAAAAAAAAEAAAAAgAAALALAAAAAAAABAAAAAIAAADACwAAAAAAAAQAAAACAAAA
0AsAAAAAAAAEAAAAAgAAAOALAAAAAAAABAAAAAIAAADwCwAAAAAAAAQAAAACAAAAAAwAAAAAAAAE
AAAAAgAAABAMAAAAAAAABAAAAAIAAAAgDAAAAAAAAAQAAAACAAAAMAwAAAAAAAAEAAAAAgAAAEAM
AAAAAAAABAAAAAIAAABQDAAAAAAAAAQAAAACAAAAYAwAAAAAAAAEAAAAAgAAAHAMAAAAAAAABAAA
AAIAAACADAAAAAAAAAQAAAACAAAAkAwAAAAAAAAEAAAAAgAAAKAMAAAAAAAABAAAAAIAAACwDAAA
AAAAAAQAAAACAAAAwAwAAAAAAAAEAAAAAgAAANAMAAAAAAAABAAAAAIAAADgDAAAAAAAAAQAAAAC
AAAA8AwAAAAAAAAEAAAAAgAAAAANAAAAAAAABAAAAAIAAAAQDQAAAAAAAAQAAAACAAAAIA0AAAAA
AAAEAAAAAgAAADANAAAAAAAABAAAAAIAAABADQAAAAAAAAQAAAACAAAAUA0AAAAAAAAEAAAAAgAA
AGANAAAAAAAABAAAAAIAAABwDQAAAAAAAAQAAAACAAAAgA0AAAAAAAAEAAAAAgAAAJANAAAAAAAA
BAAAAAIAAACgDQAAAAAAAAQAAAACAAAAsA0AAAAAAAAEAAAAAgAAAMANAAAAAAAABAAAAAIAAADQ
DQAAAAAAAAQAAAACAAAA4A0AAAAAAAAEAAAAAgAAAPANAAAAAAAABAAAAAIAAAAADgAAAAAAAAQA
AAACAAAAEA4AAAAAAAAEAAAAAgAAACAOAAAAAAAABAAAAAIAAAAwDgAAAAAAAAQAAAACAAAAQA4A
AAAAAAAEAAAAAgAAAFAOAAAAAAAABAAAAAIAAABgDgAAAAAAAAQAAAACAAAAcA4AAAAAAAAEAAAA
AgAAAIAOAAAAAAAABAAAAAIAAACQDgAAAAAAAAQAAAACAAAAoA4AAAAAAAAEAAAAAgAAALAOAAAA
AAAABAAAAAIAAADADgAAAAAAAAQAAAACAAAA0A4AAAAAAAAEAAAAAgAAAOAOAAAAAAAABAAAAAIA
AADwDgAAAAAAAAQAAAACAAAAAA8AAAAAAAAEAAAAAgAAABAPAAAAAAAABAAAAAIAAAAgDwAAAAAA
AAQAAAACAAAAMA8AAAAAAAAEAAAAAgAAAEAPAAAAAAAABAAAAAIAAABQDwAAAAAAAAQAAAACAAAA
YA8AAAAAAAAEAAAAAgAAAHAPAAAAAAAABAAAAAIAAACADwAAAAAAAAQAAAACAAAAkA8AAAAAAAAE
AAAAAgAAAKAPAAAAAAAABAAAAAIAAACwDwAAAAAAAAQAAAACAAAAwA8AAAAAAAAEAAAAAgAAANAP
AAAAAAAABAAAAAIAAADgDwAAAAAAAAQAAAACAAAA8A8AAAAAAAAEAAAAAgAAAAAQAAAAAAAABAAA
AAIAAAAQEAAAAAAAAAQAAAACAAAAIBAAAAAAAAAEAAAAAgAAADAQAAAAAAAABAAAAAIAAABAEAAA
AAAAAAQAAAACAAAAUBAAAAAAAAAEAAAAAgAAAGAQAAAAAAAABAAAAAIAAABwEAAAAAAAAAQAAAAC
AAAAgBAAAAAAAAAEAAAAAgAAAJAQAAAAAAAABAAAAAIAAACgEAAAAAAAAAQAAAACAAAAsBAAAAAA
AAAEAAAAAgAAAMAQAAAAAAAABAAAAAIAAADQEAAAAAAAAAQAAAACAAAA4BAAAAAAAAAEAAAAAgAA
APAQAAAAAAAABAAAAAIAAAAAEQAAAAAAAAQAAAACAAAAEBEAAAAAAAAEAAAAAgAAACARAAAAAAAA
BAAAAAIAAAAwEQAAAAAAAAQAAAACAAAAQBEAAAAAAAAEAAAAAgAAAFARAAAAAAAABAAAAAIAAABg
EQAAAAAAAAQAAAACAAAAcBEAAAAAAAAEAAAAAgAAAIARAAAAAAAABAAAAAIAAACQEQAAAAAAAAQA
AAACAAAAoBEAAAAAAAAEAAAAAgAAALARAAAAAAAABAAAAAIAAADAEQAAAAAAAAQAAAACAAAA0BEA
AAAAAAAEAAAAAgAAAOARAAAAAAAABAAAAAIAAADwEQAAAAAAAAQAAAACAAAAABIAAAAAAAAEAAAA
AgAAABASAAAAAAAABAAAAAIAAAAgEgAAAAAAAAQAAAACAAAAMBIAAAAAAAAEAAAAAgAAAEASAAAA
AAAABAAAAAIAAABQEgAAAAAAAAQAAAACAAAAYBIAAAAAAAAEAAAAAgAAAHASAAAAAAAABAAAAAIA
AACAEgAAAAAAAAQAAAACAAAAkBIAAAAAAAAEAAAAAgAAAKASAAAAAAAABAAAAAIAAACwEgAAAAAA
AAQAAAACAAAAwBIAAAAAAAAEAAAAAgAAANASAAAAAAAABAAAAAIAAADgEgAAAAAAAAQAAAACAAAA
8BIAAAAAAAAEAAAAAgAAAAATAAAAAAAABAAAAAIAAAAQEwAAAAAAAAQAAAACAAAAIBMAAAAAAAAE
AAAAAgAAADATAAAAAAAABAAAAAIAAABAEwAAAAAAAAQAAAACAAAAUBMAAAAAAAAEAAAAAgAAAGAT
AAAAAAAABAAAAAIAAABwEwAAAAAAAAQAAAACAAAAgBMAAAAAAAAEAAAAAgAAAJATAAAAAAAABAAA
AAIAAACgEwAAAAAAAAQAAAACAAAAsBMAAAAAAAAEAAAAAgAAAMATAAAAAAAABAAAAAIAAADQEwAA
AAAAAAQAAAACAAAA4BMAAAAAAAAEAAAAAgAAAPATAAAAAAAABAAAAAIAAAAAFAAAAAAAAAQAAAAC
AAAAEBQAAAAAAAAEAAAAAgAAACAUAAAAAAAABAAAAAIAAAAwFAAAAAAAAAQAAAACAAAAQBQAAAAA
AAAEAAAAAgAAAFAUAAAAAAAABAAAAAIAAABgFAAAAAAAAAQAAAACAAAAcBQAAAAAAAAEAAAAAgAA
AIAUAAAAAAAABAAAAAIAAACQFAAAAAAAAAQAAAACAAAAoBQAAAAAAAAEAAAAAgAAALAUAAAAAAAA
BAAAAAIAAADAFAAAAAAAAAQAAAACAAAA0BQAAAAAAAAEAAAAAgAAAOAUAAAAAAAABAAAAAIAAADw
FAAAAAAAAAQAAAACAAAAABUAAAAAAAAEAAAAAgAAABAVAAAAAAAABAAAAAIAAAAgFQAAAAAAAAQA
AAACAAAAMBUAAAAAAAAEAAAAAgAAAEAVAAAAAAAABAAAAAIAAABQFQAAAAAAAAQAAAACAAAAYBUA
AAAAAAAEAAAAAgAAAHAVAAAAAAAABAAAAAIAAACAFQAAAAAAAAQAAAACAAAAkBUAAAAAAAAEAAAA
AgAAAKAVAAAAAAAABAAAAAIAAACwFQAAAAAAAAQAAAACAAAAwBUAAAAAAAAEAAAAAgAAANAVAAAA
AAAABAAAAAIAAADgFQAAAAAAAAQAAAACAAAA8BUAAAAAAAAEAAAAAgAAAAAWAAAAAAAABAAAAAIA
AAAQFgAAAAAAAAQAAAACAAAAIBYAAAAAAAAEAAAAAgAAADAWAAAAAAAABAAAAAIAAABAFgAAAAAA
AAQAAAACAAAAUBYAAAAAAAAEAAAAAgAAAGAWAAAAAAAABAAAAAIAAABwFgAAAAAAAAQAAAACAAAA
gBYAAAAAAAAEAAAAAgAAAJAWAAAAAAAABAAAAAIAAACgFgAAAAAAAAQAAAACAAAAsBYAAAAAAAAE
AAAAAgAAAMAWAAAAAAAABAAAAAIAAADQFgAAAAAAAAQAAAACAAAA4BYAAAAAAAAEAAAAAgAAAPAW
AAAAAAAABAAAAAIAAAAAFwAAAAAAAAQAAAACAAAAEBcAAAAAAAAEAAAAAgAAACAXAAAAAAAABAAA
AAIAAAAwFwAAAAAAAAQAAAACAAAAQBcAAAAAAAAEAAAAAgAAAFAXAAAAAAAABAAAAAIAAABgFwAA
AAAAAAQAAAACAAAAcBcAAAAAAAAEAAAAAgAAAIAXAAAAAAAABAAAAAIAAACQFwAAAAAAAAQAAAAC
AAAAoBcAAAAAAAAEAAAAAgAAALAXAAAAAAAABAAAAAIAAADAFwAAAAAAAAQAAAACAAAA0BcAAAAA
AAAEAAAAAgAAAOAXAAAAAAAABAAAAAIAAADwFwAAAAAAAAQAAAACAAAAABgAAAAAAAAEAAAAAgAA
ABAYAAAAAAAABAAAAAIAAAAgGAAAAAAAAAQAAAACAAAAMBgAAAAAAAAEAAAAAgAAAEAYAAAAAAAA
BAAAAAIAAABQGAAAAAAAAAQAAAACAAAAYBgAAAAAAAAEAAAAAgAAAHAYAAAAAAAABAAAAAIAAACA
GAAAAAAAAAQAAAACAAAAkBgAAAAAAAAEAAAAAgAAAKAYAAAAAAAABAAAAAIAAACwGAAAAAAAAAQA
AAACAAAAwBgAAAAAAAAEAAAAAgAAANAYAAAAAAAABAAAAAIAAADgGAAAAAAAAAQAAAACAAAA8BgA
AAAAAAAEAAAAAgAAAAAZAAAAAAAABAAAAAIAAAAQGQAAAAAAAAQAAAACAAAAIBkAAAAAAAAEAAAA
AgAAADAZAAAAAAAABAAAAAIAAABAGQAAAAAAAAQAAAACAAAAUBkAAAAAAAAEAAAAAgAAAGAZAAAA
AAAABAAAAAIAAABwGQAAAAAAAAQAAAACAAAAgBkAAAAAAAAEAAAAAgAAAJAZAAAAAAAABAAAAAIA
AACgGQAAAAAAAAQAAAACAAAAsBkAAAAAAAAEAAAAAgAAAMAZAAAAAAAABAAAAAIAAADQGQAAAAAA
AAQAAAACAAAA4BkAAAAAAAAEAAAAAgAAAPAZAAAAAAAABAAAAAIAAAAAGgAAAAAAAAQAAAACAAAA
EBoAAAAAAAAEAAAAAgAAACAaAAAAAAAABAAAAAIAAAAwGgAAAAAAAAQAAAACAAAAQBoAAAAAAAAE
AAAAAgAAAFAaAAAAAAAABAAAAAIAAABgGgAAAAAAAAQAAAACAAAAcBoAAAAAAAAEAAAAAgAAAIAa
AAAAAAAABAAAAAIAAACQGgAAAAAAAAQAAAACAAAAoBoAAAAAAAAEAAAAAgAAALAaAAAAAAAABAAA
AAIAAADAGgAAAAAAAAQAAAACAAAA0BoAAAAAAAAEAAAAAgAAAOAaAAAAAAAABAAAAAIAAADwGgAA
AAAAAAQAAAACAAAAABsAAAAAAAAEAAAAAgAAABAbAAAAAAAABAAAAAIAAAAgGwAAAAAAAAQAAAAC
AAAAMBsAAAAAAAAEAAAAAgAAAEAbAAAAAAAABAAAAAIAAABQGwAAAAAAAAQAAAACAAAAYBsAAAAA
AAAEAAAAAgAAAHAbAAAAAAAABAAAAAIAAACAGwAAAAAAAAQAAAACAAAAkBsAAAAAAAAEAAAAAgAA
AKAbAAAAAAAABAAAAAIAAACwGwAAAAAAAAQAAAACAAAAwBsAAAAAAAAEAAAAAgAAANAbAAAAAAAA
BAAAAAIAAADgGwAAAAAAAAQAAAACAAAA8BsAAAAAAAAEAAAAAgAAAAAcAAAAAAAABAAAAAIAAAAQ
HAAAAAAAAAQAAAACAAAAIBwAAAAAAAAEAAAAAgAAADAcAAAAAAAABAAAAAIAAABAHAAAAAAAAAQA
AAACAAAAUBwAAAAAAAAEAAAAAgAAAGAcAAAAAAAABAAAAAIAAABwHAAAAAAAAAQAAAACAAAAgBwA
AAAAAAAEAAAAAgAAAJAcAAAAAAAABAAAAAIAAACgHAAAAAAAAAQAAAACAAAAsBwAAAAAAAAEAAAA
AgAAAMAcAAAAAAAABAAAAAIAAADQHAAAAAAAAAQAAAACAAAA4BwAAAAAAAAEAAAAAgAAAPAcAAAA
AAAABAAAAAIAAAAAHQAAAAAAAAQAAAACAAAAEB0AAAAAAAAEAAAAAgAAACAdAAAAAAAABAAAAAIA
AAAwHQAAAAAAAAQAAAACAAAAQB0AAAAAAAAEAAAAAgAAAFAdAAAAAAAABAAAAAIAAABgHQAAAAAA
AAQAAAACAAAAcB0AAAAAAAAEAAAAAgAAAIAdAAAAAAAABAAAAAIAAACQHQAAAAAAAAQAAAACAAAA
oB0AAAAAAAAEAAAAAgAAALAdAAAAAAAABAAAAAIAAADAHQAAAAAAAAQAAAACAAAA0B0AAAAAAAAE
AAAAAgAAAOAdAAAAAAAABAAAAAIAAADwHQAAAAAAAAQAAAACAAAAAB4AAAAAAAAEAAAAAgAAABAe
AAAAAAAABAAAAAIAAAAgHgAAAAAAAAQAAAACAAAAMB4AAAAAAAAEAAAAAgAAAEAeAAAAAAAABAAA
AAIAAABQHgAAAAAAAAQAAAACAAAAYB4AAAAAAAAEAAAAAgAAAHAeAAAAAAAABAAAAAIAAACAHgAA
AAAAAAQAAAACAAAAkB4AAAAAAAAEAAAAAgAAAKgeAAAAAAAABAAAAAEAAAC4HgAAAAAAAAQAAAAB
AAAAyB4AAAAAAAAEAAAAAQAAANgeAAAAAAAABAAAAAEAAADoHgAAAAAAAAQAAAABAAAA+B4AAAAA
AAAEAAAAAQAAAAgfAAAAAAAABAAAAAEAAAAYHwAAAAAAAAQAAAABAAAAKB8AAAAAAAAEAAAAAQAA
ADgfAAAAAAAABAAAAAEAAABIHwAAAAAAAAQAAAABAAAAWB8AAAAAAAAEAAAAAQAAAGgfAAAAAAAA
BAAAAAEAAAB4HwAAAAAAAAQAAAABAAAAiB8AAAAAAAAEAAAAAQAAAJgfAAAAAAAABAAAAAEAAACo
HwAAAAAAAAQAAAABAAAAuB8AAAAAAAAEAAAAAQAAAMgfAAAAAAAABAAAAAEAAADYHwAAAAAAAAQA
AAABAAAA6B8AAAAAAAAEAAAAAQAAAPgfAAAAAAAABAAAAAEAAAAIIAAAAAAAAAQAAAABAAAAGCAA
AAAAAAAEAAAAAQAAACggAAAAAAAABAAAAAEAAAA4IAAAAAAAAAQAAAABAAAASCAAAAAAAAAEAAAA
AQAAAFggAAAAAAAABAAAAAEAAABoIAAAAAAAAAQAAAABAAAAeCAAAAAAAAAEAAAAAQAAAIggAAAA
AAAABAAAAAEAAACYIAAAAAAAAAQAAAABAAAAqCAAAAAAAAAEAAAAAQAAALggAAAAAAAABAAAAAEA
AADIIAAAAAAAAAQAAAABAAAA2CAAAAAAAAAEAAAAAQAAAOggAAAAAAAABAAAAAEAAAD4IAAAAAAA
AAQAAAABAAAACCEAAAAAAAAEAAAAAQAAABghAAAAAAAABAAAAAEAAAAoIQAAAAAAAAQAAAABAAAA
OCEAAAAAAAAEAAAAAQAAAEghAAAAAAAABAAAAAEAAABYIQAAAAAAAAQAAAABAAAAaCEAAAAAAAAE
AAAAAQAAAHghAAAAAAAABAAAAAEAAACIIQAAAAAAAAQAAAABAAAAmCEAAAAAAAAEAAAAAQAAAKgh
AAAAAAAABAAAAAEAAADAIQAAAAAAAAQAAAAGAAAA0CEAAAAAAAAEAAAABgAAAOAhAAAAAAAABAAA
AAYAAADwIQAAAAAAAAQAAAAGAAAAACIAAAAAAAAEAAAABgAAABAiAAAAAAAABAAAAAYAAAAgIgAA
AAAAAAQAAAAGAAAAMCIAAAAAAAAEAAAABgAAAEAiAAAAAAAABAAAAAYAAABQIgAAAAAAAAQAAAAG
AAAAYCIAAAAAAAAEAAAABgAAAHAiAAAAAAAABAAAAAYAAACAIgAAAAAAAAQAAAAGAAAAkCIAAAAA
AAAEAAAABgAAAKAiAAAAAAAABAAAAAYAAACwIgAAAAAAAAQAAAAGAAAAwCIAAAAAAAAEAAAABgAA
ANAiAAAAAAAABAAAAAYAAADgIgAAAAAAAAQAAAAGAAAA8CIAAAAAAAAEAAAABgAAAAAjAAAAAAAA
BAAAAAYAAAAQIwAAAAAAAAQAAAAGAAAAICMAAAAAAAAEAAAABgAAADAjAAAAAAAABAAAAAYAAABA
IwAAAAAAAAQAAAAGAAAAUCMAAAAAAAAEAAAABgAAAGAjAAAAAAAABAAAAAYAAABwIwAAAAAAAAQA
AAAGAAAAgCMAAAAAAAAEAAAABgAAAJAjAAAAAAAABAAAAAYAAACgIwAAAAAAAAQAAAAGAAAAsCMA
AAAAAAAEAAAABgAAAMAjAAAAAAAABAAAAAYAAADQIwAAAAAAAAQAAAAGAAAA4CMAAAAAAAAEAAAA
BgAAAPAjAAAAAAAABAAAAAYAAAAAJAAAAAAAAAQAAAAGAAAAECQAAAAAAAAEAAAABgAAACAkAAAA
AAAABAAAAAYAAAAwJAAAAAAAAAQAAAAGAAAAQCQAAAAAAAAEAAAABgAAAFAkAAAAAAAABAAAAAYA
AABgJAAAAAAAAAQAAAAGAAAAcCQAAAAAAAAEAAAABgAAAIAkAAAAAAAABAAAAAYAAACQJAAAAAAA
AAQAAAAGAAAAoCQAAAAAAAAEAAAABgAAALAkAAAAAAAABAAAAAYAAADAJAAAAAAAAAQAAAAGAAAA
0CQAAAAAAAAEAAAABgAAAOAkAAAAAAAABAAAAAYAAADwJAAAAAAAAAQAAAAGAAAAACUAAAAAAAAE
AAAABgAAABAlAAAAAAAABAAAAAYAAAAgJQAAAAAAAAQAAAAGAAAAMCUAAAAAAAAEAAAABgAAAEAl
AAAAAAAABAAAAAYAAABQJQAAAAAAAAQAAAAGAAAAYCUAAAAAAAAEAAAABgAAAHAlAAAAAAAABAAA
AAYAAACAJQAAAAAAAAQAAAAGAAAAkCUAAAAAAAAEAAAABgAAAKAlAAAAAAAABAAAAAYAAACwJQAA
AAAAAAQAAAAGAAAAwCUAAAAAAAAEAAAABgAAANAlAAAAAAAABAAAAAYAAADgJQAAAAAAAAQAAAAG
AAAA8CUAAAAAAAAEAAAABgAAAAAmAAAAAAAABAAAAAYAAAAQJgAAAAAAAAQAAAAGAAAAICYAAAAA
AAAEAAAABgAAADAmAAAAAAAABAAAAAYAAABAJgAAAAAAAAQAAAAGAAAAUCYAAAAAAAAEAAAABgAA
AGAmAAAAAAAABAAAAAYAAABwJgAAAAAAAAQAAAAGAAAAgCYAAAAAAAAEAAAABgAAAJAmAAAAAAAA
BAAAAAYAAACgJgAAAAAAAAQAAAAGAAAAsCYAAAAAAAAEAAAABgAAAMAmAAAAAAAABAAAAAYAAADQ
JgAAAAAAAAQAAAAGAAAA4CYAAAAAAAAEAAAABgAAAPAmAAAAAAAABAAAAAYAAAAAJwAAAAAAAAQA
AAAGAAAAECcAAAAAAAAEAAAABgAAACAnAAAAAAAABAAAAAYAAAAwJwAAAAAAAAQAAAAGAAAAQCcA
AAAAAAAEAAAABgAAAFAnAAAAAAAABAAAAAYAAABgJwAAAAAAAAQAAAAGAAAAcCcAAAAAAAAEAAAA
BgAAAIAnAAAAAAAABAAAAAYAAACQJwAAAAAAAAQAAAAGAAAAoCcAAAAAAAAEAAAABgAAAAAuc3lt
dGFiAC5zdHJ0YWIALnNoc3RydGFiAC5yZWwudGV4dAAucmVseGRwAC5yZWx0YwAubWFwcwBsaWNl
bnNlAC5yZWwuQlRGAC5yZWwuQlRGLmV4dAAubGx2bV9hZGRyc2lnAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB8AAAABAAAA
BgAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAqAIAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAb
AAAACQAAAEAAAAAAAAAAAAAAAAAAAAD4bQAAAAAAABAAAAAAAAAADgAAAAEAAAAIAAAAAAAAABAA
AAAAAAAAKQAAAAEAAAAGAAAAAAAAAAAAAAAAAAAA6AIAAAAAAADoKAAAAAAAAAAAAAAAAAAACAAA
AAAAAAAAAAAAAAAAACUAAAAJAAAAQAAAAAAAAAAAAAAAAAAAAAhuAAAAAAAAAAQAAAAAAAAOAAAA
AwAAAAgAAAAAAAAAEAAAAAAAAAAxAAAAAQAAAAYAAAAAAAAAAAAAAAAAAADQKwAAAAAAABAHAAAA
AAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAALQAAAAkAAABAAAAAAAAAAAAAAAAAAAAACHIAAAAA
AABAAAAAAAAAAA4AAAAFAAAACAAAAAAAAAAQAAAAAAAAADQAAAABAAAAAwAAAAAAAAAAAAAAAAAA
AOAyAAAAAAAA4AAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAA6AAAAAQAAAAMAAAAAAAAA
AAAAAAAAAADAMwAAAAAAAAQAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAARgAAAAEAAAAA
AAAAAAAAAAAAAAAAAAAAxDMAAAAAAADhDwAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAEIA
AAAJAAAAQAAAAAAAAAAAAAAAAAAAAEhyAAAAAAAAgAAAAAAAAAAOAAAACQAAAAgAAAAAAAAAEAAA
AAAAAABPAAAAAQAAAAAAAAAAAAAAAAAAAAAAAACoQwAAAAAAALAnAAAAAAAAAAAAAAAAAAAEAAAA
AAAAAAAAAAAAAAAASwAAAAkAAABAAAAAAAAAAAAAAAAAAAAAyHIAAAAAAACAJwAAAAAAAA4AAAAL
AAAACAAAAAAAAAAQAAAAAAAAAFgAAAADTP9vAAAAgAAAAAAAAAAAAAAAAFhrAAAAAAAACwAAAAAA
AAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAgAAAAAAAAAAAAAAAAAAAAAAAABoawAAAAAA
AJgBAAAAAAAADwAAAAcAAAAIAAAAAAAAABgAAAAAAAAACQAAAAMAAAAAAAAAAAAAAAAAAAAAAAAA
AG0AAAAAAADxAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAABEAAAADAAAAAAAAAAAAAAAA
AAAAAAAAAEiaAAAAAAAAZgAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAA=
NOID_LAN_XDP_OBJECT_B64_EOF
NOID_LAN_XDP_OBJECT_SHA256=9f244286de91021ed53fab3f1bf03cdfc248aa9e0090061a91beafe39f96849a
printf '%s  %s\n' \
    "$NOID_LAN_XDP_OBJECT_SHA256" \
    /usr/lib/noid-privacy/noid-lan-xdp.bpf.o | sha256sum -c -
chmod 0644 /usr/lib/noid-privacy/noid-lan-xdp.bpf.o
chown root:root /usr/lib/noid-privacy/noid-lan-xdp.bpf.o

cat > /usr/local/sbin/noid-lan-xdp <<'NOID_LAN_XDP_CONTROLLER_EOF'
#!/bin/bash
# NoID Privacy physical-link XDP/TC controller. Configuration swaps use fresh pinned
# maps and overwrite each XDP link atomically; active flow maps are reused so a
# topology refresh does not break established WAN traffic.
set -euo pipefail
umask 077
LC_ALL=C
export LC_ALL

OBJECT=${NOID_LAN_XDP_OBJECT:-/usr/lib/noid-privacy/noid-lan-xdp.bpf.o}
OBJECT_SHA256=9f244286de91021ed53fab3f1bf03cdfc248aa9e0090061a91beafe39f96849a
BPF_ROOT=${NOID_LAN_XDP_BPF_ROOT:-/sys/fs/bpf/noid-lan-xdp}
STATE_FILE=${NOID_LAN_XDP_STATE_FILE:-/run/noid-privacy/lan-xdp.state}
LOCK_FILE=${NOID_LAN_XDP_LOCK_FILE:-/run/noid-privacy/lan-xdp.lock}
# Sidecar, deliberately NOT a state-file key: the state grammar is closed and
# audited, and a schema bump would fail-closed on every already-running host.
# A missing, stale or unreadable sidecar only ever costs a full rebuild.
POLICY_DIGEST_FILE=${NOID_LAN_XDP_POLICY_DIGEST_FILE:-/run/noid-privacy/lan-xdp.policy-digest}
SYS_CLASS_NET=${NOID_SYS_CLASS_NET:-/sys/class/net}
ARP_STATE=${NOID_ARP_STATE_FILE:-/var/lib/noid-privacy/arp-hardening.state}
EXPECTED_ARP_STATE_UID=0
EXPECTED_ARP_STATE_GID=0
EXPECTED_DIGEST_UID=0
EXPECTED_DIGEST_GID=0
STATE_SCHEMA=2
MAP_SCHEMA=4
PENDING_GENERATION=''
STATE_GENERATION=''
STATE_OBJECT_SHA256=''
STATE_REUSE_MAPS=0
GATEWAY_IFACE=''
GATEWAY_IP=''
GATEWAY_MAC=''
declare -a STATE_ENTRIES=()

cleanup() {
    local rc=$?
    trap - EXIT
    [ -z "$PENDING_GENERATION" ] || rm -rf "$PENDING_GENERATION"
    exit "$rc"
}
trap cleanup EXIT

die() { echo "noid-lan-xdp: ERROR: $*" >&2; exit 1; }
valid_iface() { [[ $1 =~ ^[a-zA-Z0-9_.-]{1,15}$ ]]; }
valid_mac() { [[ $1 =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]]; }
# True when the gateway IPv4 lies inside a directly-connected subnet of $iface.
# Binds the pinned gateway MAC to every on-link physical interface (multi-homed
# WAN return) without ever accepting it on an unrelated subnet.
iface_onlink_ipv4() {
    local iface=$1 gw=$2 cidrs
    [ -n "$gw" ] || return 1
    cidrs=$(ip -o -4 addr show dev "$iface" scope global 2>/dev/null \
        | awk '{print $4}')
    [ -n "$cidrs" ] || return 1
    # shellcheck disable=SC2086 # intentional word-split of the CIDR list.
    python3 - "$gw" $cidrs <<'ONLINK_PY'
import ipaddress, sys
try:
    gw = ipaddress.ip_address(sys.argv[1])
except ValueError:
    sys.exit(1)
for cidr in sys.argv[2:]:
    try:
        if gw in ipaddress.ip_interface(cidr).network:
            sys.exit(0)
    except ValueError:
        continue
sys.exit(1)
ONLINK_PY
}
mac_hex() { printf '%s' "$1" | tr ':' ' '; }
u32_hex() {
    python3 -c 'import sys; n=int(sys.argv[1]); print(" ".join(f"{b:02x}" for b in n.to_bytes(4,sys.byteorder)))' "$1"
}
ipv4_hex() {
    python3 -c 'import ipaddress,sys; print(" ".join(f"{b:02x}" for b in ipaddress.IPv4Address(sys.argv[1]).packed))' "$1"
}
peer_policy_hex() {
    python3 -c '
import sys
direction = {"outbound": 1, "inbound": 2, "both": 3}[sys.argv[1]]
protocol = {"none": 0, "tcp": 6, "udp": 17}[sys.argv[2]]
start, end = int(sys.argv[3]), int(sys.argv[4])
value = bytes((direction, protocol))
value += start.to_bytes(2, sys.byteorder)
value += end.to_bytes(2, sys.byteorder)
value += bytes(2)
print(" ".join(f"{byte:02x}" for byte in value))
' "$1" "$2" "$3" "$4"
}

read_ifindex() {
    local iface=$1 value
    value=$(cat "$SYS_CLASS_NET/$iface/ifindex" 2>/dev/null) \
        || die "cannot read interface index for $iface"
    [[ $value =~ ^[1-9][0-9]*$ ]] || die "invalid interface index for $iface"
    printf '%s\n' "$value"
}
require_ethernet_link() {
    local iface=$1 link_type
    link_type=$(cat "$SYS_CLASS_NET/$iface/type" 2>/dev/null) \
        || die "cannot read link-layer type for $iface"
    [ "$link_type" = 1 ] \
        || die "unsupported non-Ethernet link-layer type $link_type on $iface"
}
require_root() {
    [ "$(id -u)" -eq 0 ] || die "must run as root"
}

load_gateway_identity() {
    local line key value canonical metadata parent count=0
    local seen_enabled=0 seen_iface=0 seen_ip=0 seen_mac=0 seen_learned=0
    GATEWAY_IFACE=''
    GATEWAY_IP=''
    GATEWAY_MAC=''
    parent=${ARP_STATE%/*}
    [ -d "$parent" ] && [ ! -L "$parent" ] \
        || die "gateway identity parent is not a non-symlink directory"
    metadata=$(stat -Lc '%u:%g:%a' -- "$parent") \
        || die "cannot inspect gateway identity parent"
    [ "$metadata" = \
      "$EXPECTED_ARP_STATE_UID:$EXPECTED_ARP_STATE_GID:755" ] \
        || die "gateway identity parent has unsafe metadata"
    [ -f "$ARP_STATE" ] && [ ! -L "$ARP_STATE" ] \
        || die "gateway identity is not a regular non-symlink file"
    metadata=$(stat -Lc '%u:%g:%a:%h' -- "$ARP_STATE") \
        || die "cannot inspect gateway identity metadata"
    [ "$metadata" = \
      "$EXPECTED_ARP_STATE_UID:$EXPECTED_ARP_STATE_GID:644:1" ] \
        || die "gateway identity has unsafe metadata"
    while IFS= read -r line || [ -n "$line" ]; do
        [[ "$line" == *=* ]] || die "malformed gateway identity line"
        key=${line%%=*}
        value=${line#*=}
        [ -n "$value" ] || die "empty gateway identity value"
        case "$key" in
            ENABLED)
                [ "$seen_enabled" -eq 0 ] || die "duplicate gateway ENABLED"
                seen_enabled=1
                case "$value" in 0|1) ;;
                    *) die "invalid gateway ENABLED value" ;;
                esac
                ;;
            WAN_IFACE)
                [ "$seen_iface" -eq 0 ] || die "duplicate gateway WAN_IFACE"
                seen_iface=1
                valid_iface "$value" || die "invalid gateway interface"
                GATEWAY_IFACE=$value
                ;;
            GATEWAY_IP)
                [ "$seen_ip" -eq 0 ] || die "duplicate gateway IPv4"
                seen_ip=1
                canonical=$(python3 -c \
                    'import ipaddress,sys; print(ipaddress.IPv4Address(sys.argv[1]))' \
                    "$value" 2>/dev/null) || die "invalid gateway IPv4"
                [ "$canonical" = "$value" ] || die "non-canonical gateway IPv4"
                GATEWAY_IP=$value
                ;;
            GATEWAY_MAC)
                [ "$seen_mac" -eq 0 ] || die "duplicate gateway MAC"
                seen_mac=1
                valid_mac "$value" || die "invalid gateway MAC"
                GATEWAY_MAC=$value
                ;;
            LEARNED_AT)
                [ "$seen_learned" -eq 0 ] || die "duplicate gateway timestamp"
                seen_learned=1
                [[ "$value" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] \
                    || die "invalid gateway timestamp"
                ;;
            *) die "unknown gateway identity key" ;;
        esac
        count=$((count + 1))
    done < "$ARP_STATE"
    [ "$count" -eq 5 ] \
        && [ "$seen_enabled$seen_iface$seen_ip$seen_mac$seen_learned" = 11111 ] \
        || die "gateway identity is incomplete"
}

load_state() {
    local line key value state_schema='' map_schema='' state_object=''
    local generation='' canonical_root canonical_generation iface mode metadata
    local schema_count=0 map_count=0 object_count=0 generation_count=0
    declare -a entries=()
    declare -A seen_ifaces=()

    STATE_GENERATION=''
    STATE_OBJECT_SHA256=''
    STATE_REUSE_MAPS=0
    STATE_ENTRIES=()
    [ -r "$STATE_FILE" ] || return 1
    [ -f "$STATE_FILE" ] && [ ! -L "$STATE_FILE" ] \
        || die "state is not a regular non-symlink file"
    metadata=$(stat -c '%u:%a' -- "$STATE_FILE" 2>/dev/null) \
        || die "cannot inspect state ownership and mode"
    [ "$metadata" = 0:600 ] \
        || die "state must be root-owned with mode 0600"
    while IFS= read -r line || [ -n "$line" ]; do
        [[ $line == *=* ]] || die "malformed state line"
        key=${line%%=*}
        value=${line#*=}
        [ -n "$value" ] || die "empty state value"
        case "$key" in
            STATE_SCHEMA)
                schema_count=$((schema_count + 1)); state_schema=$value ;;
            MAP_SCHEMA)
                map_count=$((map_count + 1)); map_schema=$value ;;
            OBJECT_SHA256)
                object_count=$((object_count + 1)); state_object=$value ;;
            GEN)
                generation_count=$((generation_count + 1)); generation=$value ;;
            IFACE)
                iface=${value%%:*}; mode=${value#*:}
                if [ "$iface" = "$value" ] || ! valid_iface "$iface"; then
                    die "invalid state interface"
                fi
                case "$mode" in xdpdrv|xdpgeneric) ;; *) die "invalid state XDP mode" ;; esac
                [[ -z ${seen_ifaces[$iface]+x} ]] || die "duplicate state interface"
                seen_ifaces[$iface]=1
                entries+=("$iface:$mode")
                ;;
            *) die "unknown state key" ;;
        esac
    done < "$STATE_FILE"
    [ "$generation_count" -eq 1 ] || die "state must contain exactly one generation"
    [ "${#entries[@]}" -gt 0 ] || die "state contains no interface attachments"

    # A legacy state written by the immediately preceding controller has only
    # GEN/IFACE rows. It may be detached/rolled back after full path validation,
    # but its maps are never reused. Any partially versioned mixture is invalid.
    if [ "$schema_count" -eq 0 ] && [ "$map_count" -eq 0 ] \
            && [ "$object_count" -eq 0 ]; then
        STATE_REUSE_MAPS=0
    else
        [ "$schema_count" -eq 1 ] && [ "$state_schema" = "$STATE_SCHEMA" ] \
            || die "unsupported state schema"
        [ "$map_count" -eq 1 ] || die "state must contain exactly one map schema"
        [ "$object_count" -eq 1 ] \
            && [[ $state_object =~ ^[0-9a-f]{64}$ ]] \
            || die "invalid state object digest"
        case "$map_schema" in
            "$MAP_SCHEMA") STATE_REUSE_MAPS=1 ;;
            2|3)
                # One-way migration from either preceding map set. Validate
                # its attachment for rollback, but reuse none of its maps:
                # map-v4 replaces the broad peer byte with a direction and
                # protocol/port selector value.
                STATE_REUSE_MAPS=0
                ;;
            *) die "unsupported map schema" ;;
        esac
        STATE_OBJECT_SHA256=$state_object
    fi

    [ -d "$BPF_ROOT" ] && [ ! -L "$BPF_ROOT" ] \
        || die "BPF root is not a non-symlink directory"
    [ -d "$generation" ] && [ ! -L "$generation" ] \
        || die "state generation is not a non-symlink directory"
    canonical_root=$(readlink -e -- "$BPF_ROOT") \
        || die "cannot canonicalize BPF root"
    canonical_generation=$(readlink -e -- "$generation") \
        || die "cannot canonicalize state generation"
    [ "${canonical_generation%/*}" = "$canonical_root" ] \
        || die "state generation is outside the BPF root"
    [[ ${canonical_generation##*/} =~ ^generation_([0-9]+_[0-9]+|[A-Za-z0-9]{8})$ ]] \
        || die "invalid state generation name"

    STATE_GENERATION=$canonical_generation
    STATE_ENTRIES=("${entries[@]}")
}

map_mac_update() {
    local map=$1 iface=$2 mac=$3 ifindex
    ifindex=$(read_ifindex "$iface")
    # shellcheck disable=SC2046 # bpftool requires one argv per hex byte.
    bpftool map update pinned "$map" key hex $(u32_hex "$ifindex") \
        $(mac_hex "$mac") 00 00 value hex 01
}

map_peer_update() {
    local map=$1 iface=$2 ip=$3 mac=$4 direction=$5 protocol=$6
    local port_start=$7 port_end=$8 ifindex
    ifindex=$(read_ifindex "$iface")
    # shellcheck disable=SC2046 # bpftool requires one argv per hex byte.
    bpftool map update pinned "$map" key hex $(u32_hex "$ifindex") \
        $(ipv4_hex "$ip") $(mac_hex "$mac") 00 00 value hex \
        $(peer_policy_hex "$direction" "$protocol" "$port_start" "$port_end")
}

map_is_compatible() {
    local map=$1 map_type=$2 key_size=$3 value_size=$4 max_entries=$5
    bpftool -j map show pinned "$map" 2>/dev/null \
        | python3 -c '
import json, sys

expected_type, key_size, value_size, max_entries = sys.argv[1:]
document = json.load(sys.stdin)
if isinstance(document, list):
    if len(document) != 1:
        raise SystemExit(1)
    document = document[0]
expected = {
    "type": expected_type,
    "bytes_key": int(key_size),
    "bytes_value": int(value_size),
    "max_entries": int(max_entries),
    "flags": 0,
}
if not isinstance(document, dict) or any(document.get(k) != v for k, v in expected.items()):
    raise SystemExit(1)
' "$map_type" "$key_size" "$value_size" "$max_entries"
}

# Identify both pinned programs of one generation. Prints "<xdp_id> <tc_id>";
# any deviation exits non-zero and prints nothing, so every caller fails closed.
#
# Each program is resolved through its own pin path. The earlier form took one
# `bpftool --bpffs prog show` snapshot and searched it for the pin path, which
# needs BPF_PROG_GET_NEXT_ID — a call the kernel gates on CAP_SYS_ADMIN, not on
# CAP_BPF. Every unit that drives this controller deliberately carries only
# CAP_NET_ADMIN, CAP_BPF and CAP_PERFMON, so the enumeration returned EPERM
# there and identifying an already-existing generation could never succeed:
# fail-soft callers absorbed that as one DEGRADED line per boot, while the
# fail-closed revoke path in module 05 turned it into a NetworkManager-stop
# loop that left the machine without a login and without a rescue shell.
#
# The binding is not weakened. Resolving the pin path through the kernel is at
# least as tight as searching a system-wide list for a self-reported path, and
# a wrong program behind the expected path still fails the id/type/name/tag
# checks below.
#
# Cost: two bpftool executions per call instead of one, measured on this image
# at ~190 ms each against ~210 ms for the snapshot. Correctness outranks that
# difference, and the same measurement shows `--bpffs` was never the expensive
# part — bpftool's fixed startup is.
generation_program_identities() {
    local generation=$1 xdp_row tc_row
    xdp_row=$(bpftool -j prog show \
        pinned "$generation/progs/noid_lan_xdp" 2>/dev/null) || return 1
    tc_row=$(bpftool -j prog show \
        pinned "$generation/progs/noid_lan_egress" 2>/dev/null) || return 1
    python3 -c '
import json, re, sys


def identify(document, program_name, program_type):
    try:
        row = json.loads(document)
    except ValueError:
        raise SystemExit(1)
    if not isinstance(row, dict):
        raise SystemExit(1)
    program_id = row.get("id")
    tag = row.get("tag")
    if (row.get("type") != program_type or row.get("name") != program_name
            or not isinstance(program_id, int) or program_id <= 0
            or not isinstance(tag, str) or not re.fullmatch(r"[0-9a-f]{16}", tag)):
        raise SystemExit(1)
    return program_id


print(identify(sys.argv[1], "noid_lan_xdp", "xdp"),
      identify(sys.argv[2], "noid_lan_egress", "sched_cls"))
' "$xdp_row" "$tc_row"
}

attach_generation() {
    local generation=$1 iface=$2 mode
    if bpftool net attach xdpdrv pinned \
        "$generation/progs/noid_lan_xdp" dev "$iface" overwrite 2>/dev/null; then
        mode=xdpdrv
    elif bpftool net attach xdpgeneric pinned \
        "$generation/progs/noid_lan_xdp" dev "$iface" overwrite; then
        mode=xdpgeneric
    else
        return 1
    fi
    if ! tc qdisc replace dev "$iface" clsact \
       || ! tc filter replace dev "$iface" egress pref 10 handle 1 \
            bpf direct-action pinned \
            "$generation/progs/noid_lan_egress"; then
        # The XDP overwrite has already changed this interface. Report that
        # partial attachment to the caller and keep its fail-closed XDP program
        # live until the transaction restores the old XDP/TC pair (or detaches
        # this first-generation attempt). Detaching here would make the outer
        # rollback unaware that this interface also needs restoration.
        printf '%s:%s\n' "$iface" "$mode"
        return 1
    fi
    printf '%s:%s\n' "$iface" "$mode"
}

restore_old_generation() {
    local old_generation=$1 entry iface mode phase=old failed=0
    declare -A old_modes=()
    shift
    for entry in "$@"; do
        if [ "$entry" = -- ]; then
            phase=attached
            continue
        fi
        iface=${entry%%:*}
        mode=${entry#*:}
        valid_iface "$iface" || { failed=1; continue; }
        if [ "$phase" = old ]; then
            old_modes[$iface]=$mode
            continue
        fi
        if [[ -n ${old_modes[$iface]+x} ]]; then
            mode=${old_modes[$iface]}
            bpftool net attach "$mode" pinned \
                "$old_generation/progs/noid_lan_xdp" dev "$iface" overwrite \
                >/dev/null 2>&1 || failed=1
            tc qdisc replace dev "$iface" clsact >/dev/null 2>&1 \
                || failed=1
            tc filter replace dev "$iface" egress pref 10 handle 1 \
                bpf direct-action pinned \
                "$old_generation/progs/noid_lan_egress" >/dev/null 2>&1 \
                || failed=1
        else
            bpftool net detach "$mode" dev "$iface" >/dev/null 2>&1 || true
            tc filter delete dev "$iface" egress pref 10 >/dev/null 2>&1 || true
        fi
    done
    [ "$failed" -eq 0 ]
}

# Read the sidecar digest that describes the currently committed generation.
# Every rejection path returns non-zero, which only ever selects a full
# rebuild. The recorded generation must equal the one the authoritative state
# file names, so a sidecar left over from an older generation is never trusted.
read_policy_digest() {
    local expected_generation=$1 line key value metadata
    local generation='' digest='' generation_count=0 digest_count=0
    [ -f "$POLICY_DIGEST_FILE" ] && [ ! -L "$POLICY_DIGEST_FILE" ] || return 1
    metadata=$(stat -c '%u:%g:%a:%h' -- "$POLICY_DIGEST_FILE" 2>/dev/null) \
        || return 1
    [ "$metadata" = "$EXPECTED_DIGEST_UID:$EXPECTED_DIGEST_GID:600:1" ] || return 1
    while IFS= read -r line || [ -n "$line" ]; do
        [[ $line == *=* ]] || return 1
        key=${line%%=*}
        value=${line#*=}
        [ -n "$value" ] || return 1
        case "$key" in
            GEN) generation_count=$((generation_count + 1)); generation=$value ;;
            DIGEST) digest_count=$((digest_count + 1)); digest=$value ;;
            *) return 1 ;;
        esac
    done < "$POLICY_DIGEST_FILE"
    [ "$generation_count" -eq 1 ] && [ "$digest_count" -eq 1 ] || return 1
    [[ $digest =~ ^[0-9a-f]{64}$ ]] || return 1
    [ "$generation" = "$expected_generation" ] || return 1
    printf '%s\n' "$digest"
}

# Publish the sidecar only after the authoritative state file has committed.
# A failure here is not fatal: it merely forfeits the next fast path.
write_policy_digest() {
    local generation=$1 digest=$2 dir tmp
    dir=${POLICY_DIGEST_FILE%/*}
    install -d -m 0755 "$dir" || return 1
    tmp=$(mktemp "$dir/.lan-xdp-policy-digest.XXXXXX") || return 1
    if ! { printf 'GEN=%s\n' "$generation"
           printf 'DIGEST=%s\n' "$digest"; } > "$tmp" \
       || ! chmod 0600 "$tmp" \
       || ! chown "$EXPECTED_DIGEST_UID:$EXPECTED_DIGEST_GID" "$tmp" \
       || ! mv -fT "$tmp" "$POLICY_DIGEST_FILE"; then
        rm -f -- "$tmp"
        return 1
    fi
}

sync_policy() {
    local global_allow=$1
    shift
    local -a ifaces=() peers=() old_entries=() attached=() reuse=()
    local arg iface pair ip mac direction protocol port_start port_end
    local fresh_flow_peer=''
    local old_generation='' generation state_dir tmp
    local canonical_root
    local expected gwif gateway_state_present=0
    local desired_digest=''
    local -a fields=()
    declare -A seen_ifaces=() seen_peers=()

    case "$global_allow" in 0|1) ;; *) die "sync requires global mode 0 or 1" ;; esac
    while [ "$#" -gt 0 ]; do
        arg=$1
        shift
        case "$arg" in
            --iface)
                [ "$#" -gt 0 ] || die "--iface requires a value"
                iface=$1; shift
                valid_iface "$iface" || die "unsafe interface name"
                [ -d "$SYS_CLASS_NET/$iface/device" ] || die "not a physical interface: $iface"
                require_ethernet_link "$iface"
                if [[ -z ${seen_ifaces[$iface]+x} ]]; then
                    ifaces+=("$iface"); seen_ifaces[$iface]=1
                fi
                ;;
            --peer)
                [ "$#" -gt 0 ] \
                    || die "--peer requires IFACE,IPv4,MAC,DIRECTION,PROTOCOL,PORT_START,PORT_END"
                pair=$1; shift
                IFS=, read -r -a fields <<< "$pair"
                [ "${#fields[@]}" -eq 7 ] || die "invalid peer policy field count"
                iface=${fields[0]}; ip=${fields[1]}; mac=${fields[2],,}
                direction=${fields[3]}; protocol=${fields[4]}
                port_start=${fields[5]}; port_end=${fields[6]}
                valid_iface "$iface" || die "unsafe peer interface name"
                [[ -n ${seen_ifaces[$iface]+x} ]] \
                    || die "peer interface is not in the physical interface set"
                ip=$(python3 -c 'import ipaddress,sys; print(ipaddress.IPv4Address(sys.argv[1]))' "$ip") \
                    || die "invalid peer IPv4"
                valid_mac "$mac" || die "invalid peer MAC"
                case "$direction" in outbound|inbound|both) ;;
                    *) die "invalid peer direction" ;;
                esac
                case "$direction:$protocol:$port_start:$port_end" in
                    outbound:none:0:0) ;;
                    inbound:tcp:*:*|inbound:udp:*:*|both:tcp:*:*|both:udp:*:*)
                        [[ $port_start =~ ^[1-9][0-9]{0,4}$ ]] \
                            && [[ $port_end =~ ^[1-9][0-9]{0,4}$ ]] \
                            && [ "$port_start" -le "$port_end" ] \
                            && [ "$port_end" -le 65535 ] \
                            || die "invalid peer port selector"
                        ;;
                    *) die "peer direction and selector disagree" ;;
                esac
                [[ -z ${seen_peers[$ip]+x} ]] \
                    || die "duplicate peer IPv4 policy"
                peers+=("$iface,$ip,$mac,$direction,$protocol,$port_start,$port_end")
                seen_peers[$ip]=1
                ;;
            --fresh-flow-map-for-peer)
                [ "$#" -gt 0 ] && [ -z "$fresh_flow_peer" ] \
                    || die "--fresh-flow-map-for-peer requires one unique IPv4"
                fresh_flow_peer=$(python3 -c \
                    'import ipaddress,sys; print(ipaddress.IPv4Address(sys.argv[1]))' \
                    "$1" 2>/dev/null) || die "invalid flow-reset IPv4"
                [ "$fresh_flow_peer" = "$1" ] \
                    || die "non-canonical flow-reset IPv4"
                shift
                ;;
            *) die "unknown sync argument: $arg" ;;
        esac
    done
    [ "${#ifaces[@]}" -gt 0 ] || die "sync requires at least one physical interface"

    # Validate optional M04 identity before creating a BPF generation or
    # touching an attachment. A present malformed object is never equivalent
    # to "identity not learned yet".
    if [ -e "$ARP_STATE" ] || [ -L "$ARP_STATE" ]; then
        load_gateway_identity
        gateway_state_present=1
    fi

    [ -r "$OBJECT" ] || die "BPF object missing or unreadable: $OBJECT"
    expected=$(sha256sum "$OBJECT" 2>/dev/null | awk '{print $1}') \
        || die "cannot hash BPF object: $OBJECT"
    [ "$expected" = "$OBJECT_SHA256" ] || die "BPF object hash mismatch"
    mountpoint -q /sys/fs/bpf || die "bpffs is not mounted"
    [ ! -L "$BPF_ROOT" ] || die "BPF root must not be a symlink"
    install -d -m 0700 "$BPF_ROOT"
    canonical_root=$(readlink -e -- "$BPF_ROOT") \
        || die "cannot canonicalize BPF root"
    if [ -e "$STATE_FILE" ] || [ -L "$STATE_FILE" ]; then
        load_state || die "cannot load existing XDP state"
        old_generation=$STATE_GENERATION
        old_entries=("${STATE_ENTRIES[@]}")
        generation_program_identities "$old_generation" >/dev/null \
            || die "existing state has no valid pinned XDP and TC programs"
    fi

    # Canonical digest of EVERY input that decides the enforced boundary. An
    # omission here would let a real policy change be skipped, so this list is
    # the security-critical half of the fast path below:
    #   - schema/object identity: a controller or BPF object change must rebuild
    #   - global_allow: the LAN widening switch itself
    #   - gateway identity: seeded into noid_xdp_gateway_macs
    #   - per interface name, ifindex AND local MAC: both are map key/value
    #     material, and MAC randomization changes the MAC on reconnect
    #   - the complete peer policy tuples
    # Sorted so that pure enumeration order can never look like a change.
    desired_digest=$( {
        printf 'NOID-LAN-XDP-POLICY-V1\n'
        printf 'state_schema=%s\nmap_schema=%s\nobject=%s\n' \
            "$STATE_SCHEMA" "$MAP_SCHEMA" "$OBJECT_SHA256"
        printf 'global_allow=%s\n' "$global_allow"
        printf 'gateway=%s|%s|%s|%s\n' "$gateway_state_present" \
            "$GATEWAY_IFACE" "$GATEWAY_IP" "$GATEWAY_MAC"
        for iface in "${ifaces[@]}"; do
            printf 'iface=%s|%s|%s\n' "$iface" \
                "$(cat "$SYS_CLASS_NET/$iface/ifindex")" \
                "$(tr 'A-F' 'a-f' < "$SYS_CLASS_NET/$iface/address")"
        done | LC_ALL=C sort
        if [ "${#peers[@]}" -gt 0 ]; then
            printf 'peer=%s\n' "${peers[@]}" | LC_ALL=C sort
        fi
    } | sha256sum) || die "cannot compute the policy digest"
    desired_digest=${desired_digest%% *}
    [[ $desired_digest =~ ^[0-9a-f]{64}$ ]] || die "invalid policy digest"

    # Fast path. NetworkManager serializes dispatcher scripts and an awaited
    # pre-up blocks the activation it reports to applications, so one queued
    # link event burst previously rebuilt an identical BPF generation once per
    # event and starved every unrelated profile activation for seconds. Skip
    # the rebuild only when the complete input set is byte-identical AND the
    # live attachment still binds the pinned program identities on every
    # recorded interface. `status` is the existing, audited postcondition and is
    # reused verbatim in a subshell rather than reimplemented; its `die` paths
    # end that subshell only. Any doubt whatsoever falls through to the full
    # transaction, so the unconditional self-healing property is preserved.
    if [ -n "$old_generation" ] \
       && [ -z "$fresh_flow_peer" ] \
       && [ "$STATE_REUSE_MAPS" -eq 1 ] \
       && [ "$STATE_OBJECT_SHA256" = "$OBJECT_SHA256" ] \
       && [ "$(read_policy_digest "$old_generation" || true)" = "$desired_digest" ] \
       && ( status ) >/dev/null 2>&1; then
        return 0
    fi
    # Past this point the committed generation is about to be replaced. Retire
    # the sidecar first so an interrupted transaction can never leave a digest
    # that authorizes skipping a rebuild the machine did not actually perform.
    # Removal failure is not fatal: the sidecar is bound to the generation
    # named by the state file, and that generation is about to be replaced,
    # so a leftover can never authorize a skip afterwards.
    rm -f -- "$POLICY_DIGEST_FILE" 2>/dev/null || true

    # bpffs rejects dots in object/directory names on current Fedora kernels.
    # Let mktemp atomically reserve a fresh name: a PID/RANDOM collision must
    # never make cleanup remove a pre-existing active generation.
    generation=$(mktemp -d "$canonical_root/generation_XXXXXXXX") \
        || die "cannot create a fresh BPF generation"
    PENDING_GENERATION=$generation
    mkdir -m 0700 "$generation/progs" "$generation/maps"
    if [ -n "$old_generation" ] && [ "$STATE_REUSE_MAPS" -eq 1 ]; then
        map_is_compatible "$old_generation/maps/noid_xdp_flows_v4" \
            lru_hash 20 8 65536 || die "incompatible reusable flow map"
        map_is_compatible "$old_generation/maps/noid_xdp_dhcp_v4" \
            lru_hash 16 8 256 || die "incompatible reusable DHCP map"
        map_is_compatible "$old_generation/maps/noid_xdp_stats" \
            percpu_array 4 8 9 || die "incompatible reusable stats map"
        # A peer policy transition must never share its reply-correlation map
        # with the still-attached old TC program: that program can insert a new
        # tuple concurrently after any userspace scan/delete has completed.
        # Give the pending generation a fresh flow map instead. The old map and
        # attachments remain untouched for rollback until every new attachment
        # and the authoritative state file commit.
        if [ -z "$fresh_flow_peer" ]; then
            reuse+=(map name noid_xdp_flows_v4 pinned \
                "$old_generation/maps/noid_xdp_flows_v4")
        fi
        reuse+=(map name noid_xdp_dhcp_v4 pinned \
            "$old_generation/maps/noid_xdp_dhcp_v4")
        reuse+=(map name noid_xdp_stats pinned \
            "$old_generation/maps/noid_xdp_stats")
    fi
    if ! bpftool prog loadall "$OBJECT" "$generation/progs" \
        "${reuse[@]}" pinmaps "$generation/maps"; then
        rm -rf "$generation"
        die "kernel rejected BPF object"
    fi
    if [ -n "$fresh_flow_peer" ]; then
        printf 'FLOW_RESET peer_ip=%s scope=all\n' "$fresh_flow_peer"
    fi

    for iface in "${ifaces[@]}"; do
        mac=$(tr 'A-F' 'a-f' < "$SYS_CLASS_NET/$iface/address") || {
            rm -rf "$generation"
            die "cannot read local MAC for $iface"
        }
        valid_mac "$mac" || { rm -rf "$generation"; die "invalid local MAC"; }
        map_mac_update "$generation/maps/noid_xdp_local_macs" "$iface" "$mac"
    done
    if [ "$gateway_state_present" -eq 1 ]; then
        # Seed the validated gateway MAC for EVERY physical interface whose
        # directly-connected IPv4 subnet contains the gateway IP, not only the
        # recorded WAN_IFACE. ENABLED=0 disables only M04's kernel neighbour
        # pin; retaining this identity is deliberate so the M03 default-drop
        # return gate cannot open during that explicit opt-out.
        for gwif in "${ifaces[@]}"; do
            if [ "$gwif" = "$GATEWAY_IFACE" ] \
               || iface_onlink_ipv4 "$gwif" "$GATEWAY_IP"; then
                map_mac_update \
                    "$generation/maps/noid_xdp_gateway_macs" \
                    "$gwif" "$GATEWAY_MAC"
            fi
        done
    fi
    for pair in "${peers[@]}"; do
        IFS=, read -r iface ip mac direction protocol port_start port_end <<< "$pair"
        map_peer_update "$generation/maps/noid_xdp_peer4" \
            "$iface" "$ip" "$mac" "$direction" "$protocol" \
            "$port_start" "$port_end"
    done
    bpftool map update pinned "$generation/maps/noid_xdp_global_allow" \
        key hex 00 00 00 00 value hex "0$global_allow"

    for iface in "${ifaces[@]}"; do
        entry=''
        if ! entry=$(attach_generation "$generation" "$iface"); then
            [ -z "$entry" ] || attached+=("$entry")
            restore_old_generation "$old_generation" "${old_entries[@]}" \
                -- "${attached[@]}" \
                || echo "noid-lan-xdp: CRITICAL: rollback was incomplete" >&2
            rm -rf "$generation"
            die "cannot attach XDP/TC to $iface"
        fi
        attached+=("$entry")
    done

    state_dir=${STATE_FILE%/*}
    if ! install -d -m 0755 "$state_dir" \
       || ! tmp=$(mktemp "$state_dir/.lan-xdp-state.XXXXXX") \
       || ! {
            printf 'STATE_SCHEMA=%s\n' "$STATE_SCHEMA"
            printf 'MAP_SCHEMA=%s\n' "$MAP_SCHEMA"
            printf 'OBJECT_SHA256=%s\n' "$OBJECT_SHA256"
            printf 'GEN=%s\n' "$generation"
            for entry in "${attached[@]}"; do printf 'IFACE=%s\n' "$entry"; done
          } > "$tmp" \
       || ! chmod 0600 "$tmp" \
       || ! mv -fT "$tmp" "$STATE_FILE"; then
        rm -f "${tmp:-}"
        restore_old_generation "$old_generation" "${old_entries[@]}" \
            -- "${attached[@]}" \
            || echo "noid-lan-xdp: CRITICAL: rollback was incomplete" >&2
        die "cannot publish XDP generation state"
    fi
    PENDING_GENERATION=''

    # Sidecar last: the state file stays the single authority, and a failure to
    # publish the digest only forfeits the next fast path. It is never fatal and
    # never precedes the commit it describes.
    write_policy_digest "$generation" "$desired_digest" \
        || logger -t noid-lan-xdp \
            "policy digest not published; the next refresh rebuilds in full" \
            || true

    # Detach disappeared physical interfaces only after every desired link and
    # the authoritative state file have committed. Entries are root-produced.
    for entry in "${old_entries[@]}"; do
        iface=${entry%%:*}; mode=${entry#*:}
        valid_iface "$iface" || continue
        [[ -z ${seen_ifaces[$iface]+x} ]] || continue
        bpftool net detach "$mode" dev "$iface" >/dev/null 2>&1 || true
        tc filter delete dev "$iface" egress pref 10 >/dev/null 2>&1 || true
    done
    if [ -n "$old_generation" ] && [ "$old_generation" != "$generation" ]; then
        rm -rf "$old_generation"
    fi
}

status() {
    local generation entry iface mode expected_mode expected_ifindex expected
    local xdp_program_id tc_program_id
    [ -r "$OBJECT" ] || die "BPF object missing or unreadable: $OBJECT"
    expected=$(sha256sum "$OBJECT" 2>/dev/null | awk '{print $1}') \
        || die "cannot hash BPF object: $OBJECT"
    [ "$expected" = "$OBJECT_SHA256" ] || die "BPF object hash mismatch"
    load_state || die "not loaded"
    [ "$STATE_REUSE_MAPS" -eq 1 ] || die "state requires a map-schema migration sync"
    [ "$STATE_OBJECT_SHA256" = "$OBJECT_SHA256" ] \
        || die "state object digest does not match the selected object"
    generation=$STATE_GENERATION
    [ -r "$generation/progs/noid_lan_xdp" ] || die "missing pinned XDP program"
    [ -r "$generation/progs/noid_lan_egress" ] || die "missing pinned TC program"
    read -r xdp_program_id tc_program_id \
        < <(generation_program_identities "$generation") \
        || die "cannot identify the pinned XDP and TC programs"
    # The helper prints nothing on any rejection, so an empty or malformed read
    # must not reach the per-interface comparison as a wildcard.
    [[ $xdp_program_id =~ ^[1-9][0-9]*$ && $tc_program_id =~ ^[1-9][0-9]*$ ]] \
        || die "cannot identify the pinned XDP and TC programs"
    if [ -t 1 ] && declare -F fmt_section >/dev/null; then
        fmt_section "Live attachment identity"
    fi
    for entry in "${STATE_ENTRIES[@]}"; do
        iface=${entry%%:*}
        mode=${entry#*:}
        [ -d "$SYS_CLASS_NET/$iface/device" ] \
            || die "state interface is no longer physical"
        require_ethernet_link "$iface"
        # Keep inspection in the caller's already-authorized service domain.
        # Executing ip/tc transitions to Fedora's ifconfig_t; asking either
        # tool to expand a program loaded by NetworkManager's dispatcher then
        # requests cross-domain bpf:prog_run and emits a denied AVC. bpftool's
        # device-scoped JSON binds the same kernel attachments without that
        # transition. Its unrelated netfilter enumeration can be EPERM in the
        # capability-limited service and is deliberately ignored; the xdp/tc
        # arrays remain complete and were verified on the target sandbox.
        #
        # The pinned lookups above bind type, name and program ID. This
        # query additionally binds that ID to the exact interface, XDP mode
        # and clsact egress hook. The TC program is a side-effect-only flow
        # tracker and returns TC_ACT_OK on every exit, so its live hook/program
        # identity is the load-bearing postcondition; the attach path still
        # owns the stable pref/handle/direct-action configuration.
        case "$mode" in
            xdpdrv) expected_mode=driver ;;
            xdpgeneric) expected_mode=generic ;;
            *) die "invalid XDP mode in state" ;;
        esac
        expected_ifindex=$(read_ifindex "$iface")
        bpftool -j net show dev "$iface" 2>/dev/null \
            | python3 -c '
import json, sys
document = json.load(sys.stdin)
if (not isinstance(document, list) or len(document) != 1
        or not isinstance(document[0], dict)):
    raise SystemExit(1)
document = document[0]
iface, ifindex, mode = sys.argv[1], int(sys.argv[2]), sys.argv[3]
xdp_id, tc_id = int(sys.argv[4]), int(sys.argv[5])
xdp = document.get("xdp")
tc = document.get("tc")
if not isinstance(xdp, list) or not isinstance(tc, list):
    raise SystemExit(1)
xdp_matches = [row for row in xdp if isinstance(row, dict)
               and row.get("devname") == iface
               and row.get("ifindex") == ifindex
               and row.get("mode") == mode
               and row.get("id") == xdp_id]
tc_matches = [row for row in tc if isinstance(row, dict)
              and row.get("devname") == iface
              and row.get("ifindex") == ifindex
              and row.get("kind") == "clsact/egress"
              and row.get("id") == tc_id]
if len(xdp_matches) != 1 or len(tc_matches) != 1:
    raise SystemExit(1)
' "$iface" "$expected_ifindex" "$expected_mode" \
                "$xdp_program_id" "$tc_program_id" \
            || die "live XDP/TC attachment identity mismatch on $iface"
        echo "ACTIVE interface=$iface mode=$mode"
    done
    echo "ACTIVE boundary=verified"
}

require_root
if [ "${NOID_LAN_XDP_LOCK_HELD:-0}" != 1 ]; then
    [[ "$LOCK_FILE" == /* && "$LOCK_FILE" != */ ]] \
        || die "lock path must be an absolute file path"
    install -d -m 0755 "${LOCK_FILE%/*}"
    exec flock --close --exclusive "$LOCK_FILE" env NOID_LAN_XDP_LOCK_HELD=1 \
        /bin/bash "$0" "$@"
fi
unset NOID_LAN_XDP_LOCK_HELD

# Human invocations receive the same TTY-only presentation as the other public
# NoID Privacy CLIs. Load it only after the lock-owning re-exec, otherwise both
# process images render the banner. Service, dispatcher and command-substitution
# callers retain the byte-stable machine output because stdout is redirected.
# shellcheck source=/dev/null
[ ! -r /usr/local/lib/noid-privacy/agent-install-format.sh ] || \
    NOID_FMT_AUTO_TITLE="NoID Privacy — LAN XDP Boundary" \
    NOID_FMT_AUTO_SUBTITLE="Live XDP and TC attachment identity" \
    . /usr/local/lib/noid-privacy/agent-install-format.sh

case "${1:-}" in
    sync) shift; [ "$#" -gt 0 ] || die "sync requires mode"; sync_policy "$@" ;;
    status) [ "$#" -eq 1 ] || die "status takes no arguments"; status ;;
    *) die "usage: $0 {sync 0|1 [--iface IFACE] [--peer IFACE,IPv4,MAC,DIRECTION,PROTOCOL,PORT_START,PORT_END] [--fresh-flow-map-for-peer IPv4]|status}" ;;
esac
NOID_LAN_XDP_CONTROLLER_EOF
chmod 0755 /usr/local/sbin/noid-lan-xdp
chown root:root /usr/local/sbin/noid-lan-xdp

mkdir -p /etc/nftables.d /usr/local/sbin \
    /etc/NetworkManager/dispatcher.d/pre-up.d \
    /etc/NetworkManager/dispatcher.d/no-wait.d
cat > /etc/nftables.d/noid-lan-topology.nft <<'LAN_TOPOLOGY_NFT_EOF'
#!/usr/sbin/nft -f
table inet noid_lan_topology {
    set physical_ifaces {
        type ifname
        comment "Active physical Ethernet/Wi-Fi interfaces"
    }
    set lan_guard_ifaces {
        type ifname
        comment "Physical interfaces enforcing the default LAN boundary"
    }
    # auto-merge on every plain-address interval set below. nft(8): without it
    # "1.2.3.2 can not be added" to a set that already covers it, and the
    # producer emits one element per collected prefix with only exact-string
    # de-duplication -- no containment reduction. A docked laptop with Ethernet
    # on 10.20.5.0/24 and Wi-Fi on 10.20.0.0/16, or one NIC carrying a DHCP
    # address plus a manual host address, therefore made `nft -c -f` fail with
    # "conflicting intervals specified", which aborts the whole atomic refresh
    # and, on a pre-up event, NetworkManager's activation of that link.
    #
    # Verified in a network namespace that this changes no semantics: merged
    # ranges still answer `nft get element` for every member address, deleting
    # a single /32 out of a merged range works and splits it correctly, and a
    # nested prefix collapses into the covering one it was already inside.
    #
    # Deliberately NOT on inbound_tcp_v4/inbound_udp_v4: those are concatenated
    # types, where the kernel rejects an overlapping element with "File exists"
    # whether or not auto-merge is set, so declaring it there would only look
    # like protection.
    set connected_v4 {
        type ipv4_addr
        flags interval
        auto-merge
        comment "Directly connected physical IPv4 prefixes"
    }
    set connected_v6 {
        type ipv6_addr
        flags interval
        auto-merge
        comment "Directly connected physical IPv6 prefixes"
    }
    set allowed_v4 {
        type ipv4_addr
        flags interval
        auto-merge
        comment "Explicit noid-lan-allow IPv4 destinations"
    }
    set allowed_v6 {
        type ipv6_addr
        flags interval
        auto-merge
        comment "Explicit noid-lan-allow IPv6 destinations"
    }
    set outbound_peers_v4 {
        type ipv4_addr
        flags interval
        auto-merge
        comment "Peers whose guest-originated flows may receive correlated replies"
    }
    set inbound_peers_v4 {
        type ipv4_addr
        flags interval
        auto-merge
        comment "Peers with one explicit inbound TCP/UDP selector"
    }
    set inbound_tcp_v4 {
        type ifname . ipv4_addr . inet_service
        flags interval
        comment "Exact interface, peer and inbound TCP destination port selector"
    }
    set inbound_udp_v4 {
        type ifname . ipv4_addr . inet_service
        flags interval
        comment "Exact interface, peer and inbound UDP destination port selector"
    }
    counter dhcp_client_v4 { }
    counter blocked_dhcp_client_misuse_v4 { }
    counter blocked_v4 { }
    counter blocked_v6 { }

    chain output {
        type filter hook output priority -4; policy accept;

        oifname @physical_ifaces meta nfproto ipv4 meta skuid 0 \
            udp sport 68 udp dport 67 counter name dhcp_client_v4 accept
        oifname @physical_ifaces ct state established,related \
            ip daddr @inbound_peers_v4 accept
        oifname @physical_ifaces ip daddr @allowed_v4 accept
        oifname @physical_ifaces ip6 daddr @allowed_v6 accept
        oifname @lan_guard_ifaces meta nfproto ipv4 udp sport 68 \
            counter name blocked_dhcp_client_misuse_v4 drop
        oifname @physical_ifaces ip daddr @connected_v4 \
            counter name blocked_v4 drop
        oifname @physical_ifaces ip6 daddr @connected_v6 \
            counter name blocked_v6 drop
    }

    chain input {
        type filter hook input priority -4; policy accept;

        iifname @physical_ifaces ct state established,related \
            ip saddr @outbound_peers_v4 accept
        iifname . ip saddr . tcp dport @inbound_tcp_v4 accept
        iifname . ip saddr . udp dport @inbound_udp_v4 accept
        ip saddr @inbound_peers_v4 drop
    }

    # Forwarded traffic from VM/privileged-container bridges does not traverse
    # the host output hook. Apply the same physical on-link boundary here;
    # firewalld remains responsible for the VM-specific exception policy.
    chain forward {
        type filter hook forward priority -4; policy accept;

        oifname @physical_ifaces ip daddr @allowed_v4 accept
        oifname @physical_ifaces ip6 daddr @allowed_v6 accept
        oifname @physical_ifaces ip daddr @connected_v4 \
            counter name blocked_v4 drop
        oifname @physical_ifaces ip6 daddr @connected_v6 \
            counter name blocked_v6 drop
    }
}
LAN_TOPOLOGY_NFT_EOF
chmod 0644 /etc/nftables.d/noid-lan-topology.nft
chown root:root /etc/nftables.d/noid-lan-topology.nft

cat > /usr/local/sbin/noid-lan-topology-refresh.sh <<'LAN_TOPOLOGY_REFRESH_EOF'
#!/bin/bash
# Refresh directly connected physical-link prefixes and explicit per-IP allows.
# One nft batch flushes/repopulates all sets and rebuilds per-device netdev
# hooks atomically: no partial-policy gap.
set -euo pipefail
umask 077
# Every state-contract check below compares `stat -c %F` against the literal
# `directory`, and that field is translated. systemd exports /etc/locale.conf's
# LANG to services, so on a localized installation the same check that passes in
# the en_US.UTF-8 compose returns e.g. `Verzeichnis` and the guard fail-closes
# within milliseconds, before it reaches firewalld or nft. The image ships
# twelve langpacks, so that is the norm outside English, not an edge case.
# Pin the parse locale for the whole helper; sibling M03/M05 controllers already
# do the same. Diagnostics stay English, which is what the journal expects.
LC_ALL=C.UTF-8
export LC_ALL

NFT_FILE="${NOID_LAN_TOPOLOGY_NFT_FILE:-/etc/nftables.d/noid-lan-topology.nft}"
TABLE='inet noid_lan_topology'
POLICY=block-lan-out
LOG_TAG=noid-lan-topology
# Every fatal path must reach both sinks. `logger` records under the syslog
# identifier, which `journalctl -t noid-lan-topology` reads but
# `systemctl status noid-lan-topology-guard.service` does not: the unit's own
# journal only carries this process's stdout/stderr. systemd's console message
# tells the operator to run exactly that status command, so a logger-only
# diagnostic leaves a fail-closed boot with no reachable reason at all. Mirror
# to stderr so the advertised command answers the question it promises.
fail() {
    logger -t "$LOG_TAG" "$*" || true
    printf '%s: %s\n' "$LOG_TAG" "$*" >&2
}
SYS_CLASS_NET="${NOID_SYS_CLASS_NET:-/sys/class/net}"
LOCK_FILE="${NOID_LAN_TOPOLOGY_LOCK_FILE:-/run/noid-privacy/lan-topology-refresh.lock}"
POLICY_EXPORTER="${NOID_LAN_POLICY_EXPORTER:-/usr/local/bin/noid-lan-allow}"
GLOBAL_ALLOW_MARKER="${NOID_LAN_GLOBAL_ALLOW_MARKER:-/var/lib/noid-privacy/lan-global-allow.enabled}"
GLOBAL_RUNTIME_STATE="${NOID_LAN_GLOBAL_RUNTIME_STATE:-/run/noid-privacy/lan-global-state}"
XDP_CONTROLLER="${NOID_LAN_XDP_CONTROLLER:-/usr/local/sbin/noid-lan-xdp}"
XDP_HEALTH_FILE="${NOID_LAN_XDP_HEALTH_FILE:-/run/noid-privacy/lan-xdp-health}"
STATE_UID="${NOID_LAN_STATE_UID:-0}"
STATE_GID="${NOID_LAN_STATE_GID:-0}"
# Boot ordering runs this guard Before=NetworkManager, so the first XDP attach
# can race a physical link (e.g. Wi-Fi firmware) that is still registering its
# netdev. Retry the whole all-or-nothing sync a bounded number of times; a
# steady-state boot succeeds on the first try, so the retry never fires.
# Overridable for tests (zero backoff) and per-host tuning.
XDP_SYNC_ATTEMPTS="${NOID_LAN_XDP_SYNC_ATTEMPTS:-4}"
XDP_SYNC_BACKOFF="${NOID_LAN_XDP_SYNC_BACKOFF:-1}"
RETRY_DEGRADED_XDP="${NOID_LAN_RETRY_DEGRADED_XDP:-0}"
XDP_RETRY_RC=75
EXCLUDE_PEER=''
INVALIDATE_FLOW_PEER=''
REQUIRE_XDP=0
xdp_retryable_degraded=0

case "$RETRY_DEGRADED_XDP" in
    0|1) ;;
    *) echo "invalid degraded-XDP retry selector" >&2; exit 2 ;;
esac

[[ "$STATE_UID" =~ ^(0|[1-9][0-9]{0,9})$ ]] \
    && [[ "$STATE_GID" =~ ^(0|[1-9][0-9]{0,9})$ ]] || {
    echo "invalid LAN state owner contract" >&2
    exit 1
}

trusted_state_directory() {
    local path="$1" expected_mode="${2:-}" metadata uid gid mode type
    [[ "$path" == /* && "$path" != / && "$path" != */ ]] || return 1
    [ -d "$path" ] && [ ! -L "$path" ] || return 1
    metadata=$(stat -c '%u:%g:%a:%F' "$path") || return 1
    IFS=: read -r uid gid mode type <<< "$metadata"
    [ "$uid" = "$STATE_UID" ] && [ "$gid" = "$STATE_GID" ] \
        && [ "$type" = directory ] || return 1
    if [ -n "$expected_mode" ]; then
        [ "$mode" = "$expected_mode" ]
    else
        [[ "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
        (( (8#$mode & 0022) == 0 ))
    fi
}

ensure_state_directory() {
    local path="$1" mode="$2" parent
    parent=${path%/*}
    if [ -e "$path" ] || [ -L "$path" ]; then
        trusted_state_directory "$path" || return 1
        chmod "$mode" "$path" || return 1
        chown "$STATE_UID:$STATE_GID" "$path" || return 1
    else
        trusted_state_directory "$parent" || return 1
        install -d -m "$mode" "$path" || return 1
        chown "$STATE_UID:$STATE_GID" "$path" || return 1
    fi
    trusted_state_directory "$path" "$mode"
}

valid_global_allow_marker() {
    local dir metadata
    dir=${GLOBAL_ALLOW_MARKER%/*}
    trusted_state_directory "$dir" || return 2
    if [ ! -e "$GLOBAL_ALLOW_MARKER" ] && [ ! -L "$GLOBAL_ALLOW_MARKER" ]; then
        return 1
    fi
    [ -f "$GLOBAL_ALLOW_MARKER" ] && [ ! -L "$GLOBAL_ALLOW_MARKER" ] \
        || return 2
    metadata=$(stat -c '%u:%g:%a:%h:%s' "$GLOBAL_ALLOW_MARKER") \
        || return 2
    [ "$metadata" = "$STATE_UID:$STATE_GID:600:1:0" ] || return 2
}

validate_global_runtime_state() {
    local expected="$1" metadata expected_size
    [ -f "$GLOBAL_RUNTIME_STATE" ] && [ ! -L "$GLOBAL_RUNTIME_STATE" ] \
        || return 1
    metadata=$(stat -c '%u:%g:%a:%h' "$GLOBAL_RUNTIME_STATE") || return 1
    [ "$metadata" = "$STATE_UID:$STATE_GID:644:1" ] || return 1
    expected_size=$((${#expected} + 1))
    [ "$(stat -c '%s' "$GLOBAL_RUNTIME_STATE")" -eq "$expected_size" ] \
        && [ "$(cat "$GLOBAL_RUNTIME_STATE")" = "$expected" ]
}

retire_runtime_status() {
    local path="$1" state_dir
    state_dir=${path%/*}
    trusted_state_directory "$state_dir" 755 || return 1
    rm -f -- "$path" || return 1
    [ ! -e "$path" ] && [ ! -L "$path" ]
}

publish_global_state() {
    local state="$1" state_dir tmp
    case "$state" in BLOCKED|ALLOWED|INCONSISTENT) ;; *) return 1 ;; esac
    state_dir=${GLOBAL_RUNTIME_STATE%/*}
    ensure_state_directory "$state_dir" 755 || return 1
    if ! tmp=$(mktemp "$state_dir/.lan-global-state.XXXXXX"); then
        retire_runtime_status "$GLOBAL_RUNTIME_STATE" || true
        return 1
    fi
    if ! printf '%s\n' "$state" > "$tmp" \
       || ! chmod 0644 "$tmp" \
       || ! chown "$STATE_UID:$STATE_GID" "$tmp" \
       || [ "$(stat -c '%u:%g:%a:%h' "$tmp" 2>/dev/null || true)" != \
            "$STATE_UID:$STATE_GID:644:1" ] \
       || ! mv -fT "$tmp" "$GLOBAL_RUNTIME_STATE" \
       || ! validate_global_runtime_state "$state"; then
        rm -f -- "$tmp"
        retire_runtime_status "$GLOBAL_RUNTIME_STATE" || true
        return 1
    fi
}

mark_global_inconsistent() {
    if publish_global_state INCONSISTENT; then
        return 0
    fi
    fail "FAILED: global LAN runtime-state publication failed; prior status retired or untrusted"
    return 1
}

validate_xdp_health() {
    local expected_state="$1" expected_detail="$2" metadata expected_size
    local -a lines=()
    [ -f "$XDP_HEALTH_FILE" ] && [ ! -L "$XDP_HEALTH_FILE" ] \
        || return 1
    metadata=$(stat -c '%u:%g:%a:%h:%F' "$XDP_HEALTH_FILE") || return 1
    [ "$metadata" = \
        "$STATE_UID:$STATE_GID:644:1:regular file" ] || return 1
    expected_size=$((15 + ${#expected_state} + ${#expected_detail}))
    [ "$(stat -c '%s' "$XDP_HEALTH_FILE")" -eq "$expected_size" ] || return 1
    mapfile -t lines < "$XDP_HEALTH_FILE" || return 1
    [ "${#lines[@]}" -eq 2 ] \
        && [ "${lines[0]}" = "STATE=$expected_state" ] \
        && [ "${lines[1]}" = "DETAIL=$expected_detail" ]
}

publish_xdp_health() {
    local state="$1" detail="$2" state_dir tmp
    case "$state" in ACTIVE|DEGRADED) ;; *) return 1 ;; esac
    case "$detail" in
        verified|controller-missing|sync-or-postcheck-failed|\
        unsupported-link-type|no-ethernet-link|physical-ipv6-unsupported) ;;
        *) return 1 ;;
    esac
    state_dir=${XDP_HEALTH_FILE%/*}
    ensure_state_directory "$state_dir" 755 || return 1
    if ! tmp=$(mktemp "$state_dir/.lan-xdp-health.XXXXXX"); then
        retire_runtime_status "$XDP_HEALTH_FILE" || true
        return 1
    fi
    if ! printf 'STATE=%s\nDETAIL=%s\n' "$state" "$detail" > "$tmp" \
       || ! chmod 0644 "$tmp" \
       || ! chown "$STATE_UID:$STATE_GID" "$tmp" \
       || [ "$(stat -c '%u:%g:%a:%h' "$tmp" 2>/dev/null || true)" != \
            "$STATE_UID:$STATE_GID:644:1" ] \
       || ! mv -fT "$tmp" "$XDP_HEALTH_FILE" \
       || ! validate_xdp_health "$state" "$detail"; then
        rm -f -- "$tmp"
        retire_runtime_status "$XDP_HEALTH_FILE" || true
        return 1
    fi
}

# Boot-monotonic centiseconds. CLOCK_REALTIME is unusable for the coalescing
# comparison below: chrony is configured with `makestep 1.0 3` and steps the
# wall clock during exactly the early-boot window in which NetworkManager emits
# most topology events. A backward step makes a scan that started BEFORE an
# event carry the LARGER stamp, so coalescing would discard an event no scan
# ever saw and a freshly appeared interface could stay outside the enforced
# topology sets until the next non-skipped refresh. /proc/uptime is immune to
# that step. Prints nothing and fails when unreadable, so every caller falls
# through to a full rebuild instead of trusting an unusable stamp.
boot_monotonic_cs() {
    local up _rest
    read -r up _rest < /proc/uptime 2>/dev/null || return 1
    [[ $up =~ ^([0-9]+)\.([0-9]{2})$ ]] || return 1
    printf '%s%s' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
}

# Stamp the moment this event arrived, BEFORE blocking on the lock, and carry
# it across the re-exec through the inherited environment. The coalescing test
# further down must compare against arrival time, not lock-acquisition time.
export NOID_LAN_TOPOLOGY_QUEUED_AT="${NOID_LAN_TOPOLOGY_QUEUED_AT:-$(boot_monotonic_cs || true)}"

# Boot, NetworkManager and udev-hotplug triggers may overlap. A parent flock
# process retains the lock while --close guarantees the protected script and
# its nft/ip children do not inherit the lock descriptor across SELinux domain
# transitions. Re-exec once under that parent to cover the whole transaction.
if [ "${NOID_LAN_TOPOLOGY_LOCK_HELD:-0}" != "1" ]; then
    lock_dir=${LOCK_FILE%/*}
    [[ "$LOCK_FILE" == /* && "$LOCK_FILE" != */ ]] \
        || { echo "lock path must be an absolute file path" >&2; exit 1; }
    trusted_state_directory "$lock_dir" || {
        echo "lock parent is not a trusted state directory" >&2
        exit 1
    }
    if [ ! -e "$LOCK_FILE" ] && [ ! -L "$LOCK_FILE" ]; then
        install -m 0600 /dev/null "$LOCK_FILE"
        chown "$STATE_UID:$STATE_GID" "$LOCK_FILE"
    fi
    [ -f "$LOCK_FILE" ] && [ ! -L "$LOCK_FILE" ] \
        && [ "$(stat -c '%u:%g:%a:%h' "$LOCK_FILE")" = \
            "$STATE_UID:$STATE_GID:600:1" ] || {
        echo "lock file is not one closed root-private identity" >&2
        exit 1
    }
    exec flock --close --exclusive "$LOCK_FILE" \
        env NOID_LAN_TOPOLOGY_LOCK_HELD=1 /bin/bash "$0" "$@"
fi
unset NOID_LAN_TOPOLOGY_LOCK_HELD

while [ "$#" -gt 0 ]; do
    case "$1" in
        --exclude-peer)
            [ -z "$EXCLUDE_PEER" ] && [ "$#" -ge 2 ] \
                || { echo "invalid duplicate/missing --exclude-peer" >&2; exit 2; }
            EXCLUDE_PEER=$2
            shift 2
            ;;
        --invalidate-peer-flows)
            [ -z "$INVALIDATE_FLOW_PEER" ] && [ "$#" -ge 2 ] \
                || { echo "invalid duplicate/missing --invalidate-peer-flows" >&2; exit 2; }
            INVALIDATE_FLOW_PEER=$2
            shift 2
            ;;
        --require-xdp)
            [ "$REQUIRE_XDP" -eq 0 ] \
                || { echo "duplicate --require-xdp" >&2; exit 2; }
            REQUIRE_XDP=1
            shift
            ;;
        *) echo "unknown topology-refresh argument: $1" >&2; exit 2 ;;
    esac
done

# Coalescing, NOT debouncing. NetworkManager queues one dispatcher invocation
# per event and runs them one at a time while an awaited pre-up blocks the
# activation it reports to applications, so a link burst previously serialized
# N identical full transactions and starved unrelated profile activations.
#
# This never delays anything and never drops the last word: a queued run exits
# only when a LATER-STARTED run already completed successfully. That run
# enumerated live kernel state after this event arrived, so it provably covers
# it. Comparing against the completion time instead would be wrong -- a run
# that started before the event can finish after it while never having seen it.
#
# Explicitly targeted invocations always execute: they carry an intent that a
# generic rescan does not reproduce.
#
# Both stamps are boot-monotonic centiseconds and the file carries an explicit
# format tag. The tag is load-bearing, not decoration: a pre-monotonic stamp
# holds CLOCK_REALTIME nanoseconds, a number that outranks every plausible
# boot-monotonic value. Without the tag, replacing this helper in a running
# system would let one stale realtime number coalesce away EVERY subsequent
# generic refresh until the next reboot, because no run could ever publish a
# larger value. An untagged, foreign or malformed line fails this parse, costs
# exactly one full rebuild and is then replaced by a tagged stamp.
SCAN_STAMP="${NOID_LAN_TOPOLOGY_SCAN_STAMP:-/run/noid-privacy/lan-topology-refresh.scan}"
SCAN_STAMP_TAG=MONOTONIC_CS
SCAN_STARTED_AT=$(boot_monotonic_cs || true)
if [ -z "$EXCLUDE_PEER" ] && [ -z "$INVALIDATE_FLOW_PEER" ] \
   && [ "$REQUIRE_XDP" -eq 0 ] \
   && [ -n "${NOID_LAN_TOPOLOGY_QUEUED_AT:-}" ] \
   && [[ "${NOID_LAN_TOPOLOGY_QUEUED_AT}" =~ ^[0-9]+$ ]] \
   && [ -f "$SCAN_STAMP" ] && [ ! -L "$SCAN_STAMP" ] \
   && [ "$(stat -c '%u:%g:%a' "$SCAN_STAMP" 2>/dev/null || true)" \
        = "$STATE_UID:$STATE_GID:600" ]; then
    last_scan=$(cat "$SCAN_STAMP" 2>/dev/null || true)
    if [[ "$last_scan" =~ ^${SCAN_STAMP_TAG}=([0-9]+)$ ]] \
       && [ "${BASH_REMATCH[1]}" -gt "$NOID_LAN_TOPOLOGY_QUEUED_AT" ]; then
        logger -t "$LOG_TAG" \
            "coalesced: a later scan already covered this event" || true
        exit 0
    fi
fi

if [ ! -r "$NFT_FILE" ]; then
    fail "FAILED: missing $NFT_FILE"
    exit 1
fi
# These two were the only fail-closed exits in this helper that produced no
# record at all: bare commands under `set -e` abort with nft's status and
# nothing else. That is exactly the early, sub-second failure window, so a
# boot-time rejection here left `systemctl status` empty and the eight-attempt
# boot wrapper repeating an invisible cause. Capture nft's own diagnostic.
if ! nft list table inet noid_lan_topology >/dev/null 2>&1; then
    if ! nft_error=$(nft -c -f "$NFT_FILE" 2>&1); then
        fail "FAILED: base topology table rejected in check mode: $nft_error"
        exit 1
    fi
    if ! nft_error=$(nft -f "$NFT_FILE" 2>&1); then
        fail "FAILED: base topology table could not be loaded: $nft_error"
        exit 1
    fi
fi

declare -a ifaces=() xdp_ifaces=() unsupported_ifaces=()
declare -a prefixes_v4=() prefixes_v6=() allows_v4=()
declare -a peer_ips_v4=() peer_ifaces_v4=() peer_macs_v4=()
declare -a peer_directions_v4=() peer_protocols_v4=() peer_port_starts_v4=()
declare -a peer_port_ends_v4=() outbound_peer_ips_v4=() inbound_peer_ips_v4=()
declare -a inbound_tcp_v4=() inbound_udp_v4=()
declare -A seen_ifaces=() seen_xdp_ifaces=() seen_v4=() seen_v6=() seen_peer_v4=()
physical_ipv6_on_xdp=0

# The global opt-in is valid only when its durable marker and firewalld agree.
# Never infer an allow from one missing attachment: a partial or manually
# edited state remains visibly inconsistent and the previous nft policy stays.
guard_enabled=1
global_allow=0
if ! command -v firewall-cmd >/dev/null 2>&1 \
   || ! ingress=$(firewall-cmd --permanent --policy="$POLICY" \
        --list-ingress-zones 2>/dev/null); then
    mark_global_inconsistent || true
    fail "FAILED: cannot read permanent $POLICY ingress zones"
    exit 1
fi
host_attached=0
if printf '%s\n' "$ingress" | tr ' ' '\n' | grep -qxF HOST; then
    host_attached=1
fi
marker_present=0
if valid_global_allow_marker; then
    marker_present=1
else
    marker_status=$?
    if [ "$marker_status" -ne 1 ]; then
        mark_global_inconsistent || true
        fail "FAILED: invalid global LAN allow marker contract"
        exit 1
    fi
fi
if [ "$marker_present" -eq 0 ] && [ "$host_attached" -eq 1 ]; then
    guard_enabled=1
elif [ "$marker_present" -eq 1 ] && [ "$host_attached" -eq 0 ]; then
    guard_enabled=0
    global_allow=1
else
    mark_global_inconsistent || true
    fail "FAILED: global LAN marker/firewalld state disagree"
    exit 1
fi

canonical_network() {
    python3 -c 'import ipaddress,sys; print(ipaddress.ip_interface(sys.argv[1]).network)' "$1"
}

canonical_ip() {
    python3 -c 'import ipaddress,sys; print(ipaddress.ip_address(sys.argv[1]))' "$1"
}

if [ -n "$INVALIDATE_FLOW_PEER" ]; then
    canonical=$(canonical_ip "$INVALIDATE_FLOW_PEER" 2>/dev/null) || {
        fail "FAILED: invalid peer flow-invalidation address"
        exit 1
    }
    [ "$canonical" = "$INVALIDATE_FLOW_PEER" ] \
        && [[ "$INVALIDATE_FLOW_PEER" != *:* ]] || {
        fail "FAILED: non-canonical peer flow-invalidation IPv4"
        exit 1
    }
fi

# Enumerate every kernel-backed physical interface for the L3 topology and
# WAN-strict sets. XDP/TC and netdev EtherType hooks have a narrower contract:
# only ARPHRD_ETHER (type 1) exposes an Ethernet header to the current parser.
# Keep unsupported links in the L3 sets, but never let one Raw-IP/WWAN device
# tear down valid XDP generations on the supported Ethernet/Wi-Fi links.
# Global LAN opt-in may empty topology drop sets, but it must never empty
# WAN-strict's physical-interface truth and create an unrelated WAN bypass.
for net_path in "$SYS_CLASS_NET"/*; do
    [ -e "$net_path" ] || continue
    iface=${net_path##*/}
    [[ "$iface" =~ ^[a-zA-Z0-9_.-]{1,15}$ ]] || {
        fail "FAILED: unsafe physical interface name"
        exit 1
    }
    [ -d "$net_path/device" ] || continue
    if [[ -z ${seen_ifaces[$iface]+present} ]]; then
        ifaces+=("$iface")
        seen_ifaces["$iface"]=1
    fi
    if ! link_type=$(cat "$net_path/type" 2>/dev/null); then
        fail "FAILED: cannot read link-layer type for $iface"
        exit 1
    fi
    if [ "$link_type" = 1 ]; then
        xdp_ifaces+=("$iface")
        seen_xdp_ifaces["$iface"]=1
    elif [[ "$link_type" =~ ^[0-9]+$ ]]; then
        unsupported_ifaces+=("$iface:$link_type")
    else
        fail "FAILED: invalid link-layer type for $iface"
        exit 1
    fi

    if ! addr_v4=$(ip -o -4 addr show dev "$iface" scope global 2>/dev/null); then
        fail "FAILED: cannot read IPv4 addresses for $iface"
        exit 1
    fi
    while IFS= read -r cidr; do
        [ -n "$cidr" ] || continue
        network=$(canonical_network "$cidr")
        if [[ -z ${seen_v4[$network]+present} ]]; then
            prefixes_v4+=("$network")
            seen_v4["$network"]=1
        fi
    done < <(printf '%s\n' "$addr_v4" | awk '{print $4}')

    if ! addr_v6=$(ip -o -6 addr show dev "$iface" scope global 2>/dev/null); then
        fail "FAILED: cannot read IPv6 addresses for $iface"
        exit 1
    fi
    while IFS= read -r cidr; do
        [ -n "$cidr" ] || continue
        [[ -z ${seen_xdp_ifaces[$iface]+present} ]] \
            || physical_ipv6_on_xdp=1
        network=$(canonical_network "$cidr")
        if [[ -z ${seen_v6[$network]+present} ]]; then
            prefixes_v6+=("$network")
            seen_v6["$network"]=1
        fi
    done < <(printf '%s\n' "$addr_v6" | awk '{print $4}')
done

# Consume the helper's closed v2 export. The helper is the only parser of the
# durable expiry/direction/selector schema; this layer accepts exactly seven
# tab-separated, already-canonical fields and rejects any disagreement.
if [ "$guard_enabled" -eq 1 ]; then
    [ -x "$POLICY_EXPORTER" ] || {
        fail "FAILED: LAN policy exporter is missing"
        exit 1
    }
    export_args=(--export-policy)
    if [ -n "$EXCLUDE_PEER" ]; then
        EXCLUDE_PEER=$(canonical_ip "$EXCLUDE_PEER" 2>/dev/null) || {
            fail "FAILED: invalid excluded peer"
            exit 1
        }
        case "$EXCLUDE_PEER" in *:*) exit 2 ;; esac
        export_args+=(--exclude "$EXCLUDE_PEER")
    fi
    policy_export=$("$POLICY_EXPORTER" "${export_args[@]}") || {
        fail "FAILED: durable LAN policy export was rejected"
        exit 1
    }
    while IFS=$'\t' read -r peer_iface peer_ip peer_mac direction protocol \
            port_start port_end extra; do
        [ -n "$peer_iface$peer_ip$peer_mac$direction$protocol$port_start$port_end" ] \
            || continue
        [ -z "$extra" ] || { fail "FAILED: extra policy export field"; exit 1; }
        canonical=$(canonical_ip "$peer_ip" 2>/dev/null) \
            || { fail "FAILED: invalid exported peer IPv4"; exit 1; }
        [ "$canonical" = "$peer_ip" ] && [[ "$peer_ip" != *:* ]] \
            || { fail "FAILED: non-canonical exported peer"; exit 1; }
        [[ "$peer_iface" =~ ^[a-zA-Z0-9_.-]{1,15}$ ]] \
            && [[ -n ${seen_ifaces[$peer_iface]+present} ]] \
            || { fail "FAILED: exported peer interface is not physical"; exit 1; }
        [[ -n ${seen_xdp_ifaces[$peer_iface]+present} ]] || {
            fail "FAILED: exported peer interface does not satisfy the Ethernet XDP contract"
            exit 1
        }
        [[ "$peer_mac" =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]] \
            || { fail "FAILED: invalid exported peer MAC"; exit 1; }
        case "$direction:$protocol:$port_start:$port_end" in
            outbound:none:0:0) ;;
            inbound:tcp:*:*|inbound:udp:*:*|both:tcp:*:*|both:udp:*:*)
                [[ "$port_start" =~ ^[1-9][0-9]{0,4}$ ]] \
                    && [[ "$port_end" =~ ^[1-9][0-9]{0,4}$ ]] \
                    && [ "$port_start" -le "$port_end" ] \
                    && [ "$port_end" -le 65535 ] \
                    || { fail "FAILED: invalid exported port selector"; exit 1; }
                ;;
            *) fail "FAILED: invalid exported direction selector"; exit 1 ;;
        esac
        [[ -z ${seen_peer_v4[$peer_ip]+present} ]] \
            || { fail "FAILED: duplicate exported peer"; exit 1; }
        seen_peer_v4["$peer_ip"]=1
        peer_ips_v4+=("$peer_ip")
        peer_ifaces_v4+=("$peer_iface")
        peer_macs_v4+=("$peer_mac")
        peer_directions_v4+=("$direction")
        peer_protocols_v4+=("$protocol")
        peer_port_starts_v4+=("$port_start")
        peer_port_ends_v4+=("$port_end")
        case "$direction" in
            outbound|both)
                allows_v4+=("$peer_ip")
                outbound_peer_ips_v4+=("$peer_ip")
                ;;
        esac
        case "$direction" in
            inbound|both)
                inbound_peer_ips_v4+=("$peer_ip")
                port_selector=$port_start
                [ "$port_start" = "$port_end" ] \
                    || port_selector="$port_start-$port_end"
                if [ "$protocol" = tcp ]; then
                    inbound_tcp_v4+=("\"$peer_iface\" . $peer_ip . $port_selector")
                else
                    inbound_udp_v4+=("\"$peer_iface\" . $peer_ip . $port_selector")
                fi
                ;;
        esac
    done <<< "$policy_export"
fi

# M06's WAN-strict table uses the same hardware-interface truth to catch
# SO_BINDTODEVICE on every physical link without hard-coded tunnel names.
# At boot M06 populates its own set; this conditional cross-sync covers
# Ethernet/Wi-Fi hotplug and connection changes atomically with the LAN sets.
sync_wan_strict=0
if nft list set inet noid_wan_strict physical_ifaces >/dev/null 2>&1 \
   && nft list set inet noid_wan_strict lan_inbound_peers_v4 >/dev/null 2>&1; then
    sync_wan_strict=1
fi
# Restore the exact neighbour pins before enabling any selector that uses the
# binding. A failure leaves every later policy layer unchanged.
exact_permanent_neighbour_mac() {
    local ip="$1" iface="$2" records
    records=$(ip -4 neigh show to "$ip" dev "$iface" 2>/dev/null) || return 1
    [ "$(grep -c . <<< "$records")" -eq 1 ] || return 1
    awk -v ip="$ip" '
        NR == 1 && $1 == ip {
            mac=""
            for (i=1; i<=NF; i++) {
                if ($i == "lladdr") mac=tolower($(i+1))
            }
            if (mac != "" && tolower($NF) == "permanent") print mac
        }
    ' <<< "$records"
}

for i in "${!peer_ips_v4[@]}"; do
    if ! ip neigh replace "${peer_ips_v4[$i]}" lladdr "${peer_macs_v4[$i]}" \
        dev "${peer_ifaces_v4[$i]}" nud permanent; then
        fail "FAILED: cannot restore an approved LAN peer binding"
        exit 1
    fi
    if [ "$(exact_permanent_neighbour_mac "${peer_ips_v4[$i]}" \
            "${peer_ifaces_v4[$i]}" || true)" != "${peer_macs_v4[$i]}" ]; then
        fail "FAILED: restored LAN peer binding failed its exact kernel postcondition"
        exit 1
    fi
done

# Replace the earliest pre-AF_PACKET generation first. For widening, later
# nft/firewalld layers still block until commit. For narrowing/revoke, the raw
# packet boundary closes before a stale later permit is touched.
xdp_args=(sync "$global_allow")
for item in "${xdp_ifaces[@]}"; do
    xdp_args+=(--iface "$item")
done
if [ -n "$INVALIDATE_FLOW_PEER" ]; then
    xdp_args+=(--fresh-flow-map-for-peer "$INVALIDATE_FLOW_PEER")
fi
for i in "${!peer_ips_v4[@]}"; do
    xdp_args+=(--peer "${peer_ifaces_v4[$i]},${peer_ips_v4[$i]},${peer_macs_v4[$i]},${peer_directions_v4[$i]},${peer_protocols_v4[$i]},${peer_port_starts_v4[$i]},${peer_port_ends_v4[$i]}")
done
xdp_required=$REQUIRE_XDP
[ "${#peer_ips_v4[@]}" -eq 0 ] || xdp_required=1
[ -z "$INVALIDATE_FLOW_PEER" ] || xdp_required=1
# A global LAN widening on an Ethernet path is truthful only when the earliest
# raw-packet layer switched too. Raw-IP-only links retain their documented L3
# fallback because the current XDP parser cannot attach there.
if [ "$global_allow" -eq 1 ] && [ "${#xdp_ifaces[@]}" -gt 0 ]; then
    xdp_required=1
fi
if [ "${#xdp_ifaces[@]}" -eq 0 ]; then
    publish_xdp_health DEGRADED no-ethernet-link
    xdp_message="no physical interface satisfies the Ethernet XDP contract; L3/firewalld/WAN-strict remain active"
    if [ "$xdp_required" -ne 0 ]; then
        fail "FAILED: $xdp_message"
        mark_global_inconsistent || true
        exit 1
    fi
    logger -t "$LOG_TAG" "DEGRADED: $xdp_message" || true
elif [ ! -x "$XDP_CONTROLLER" ]; then
    publish_xdp_health DEGRADED controller-missing
    xdp_message="installed LAN XDP controller is missing or not executable: $XDP_CONTROLLER"
    if [ "$xdp_required" -ne 0 ]; then
        fail "FAILED: $xdp_message"
        mark_global_inconsistent || true
        exit 1
    fi
    logger -t "$LOG_TAG" "DEGRADED: $xdp_message" || true
else
    # Each attempt is a full controller sync + strict status postcheck, so the
    # all-or-nothing attach and fail-closed semantics are unchanged; the bounded
    # retry only re-runs the whole transaction to absorb the boot-time netdev
    # race. Exhausting the retries keeps the exact prior fail-soft behaviour:
    # nft L2 + firewalld still enforce, a later dispatcher/hotplug refresh
    # re-attaches, and the health file drives the login notice.
    xdp_sync_ok=0
    xdp_attempt=0
    while [ "$xdp_attempt" -lt "$XDP_SYNC_ATTEMPTS" ]; do
        xdp_attempt=$((xdp_attempt + 1))
        if "$XDP_CONTROLLER" "${xdp_args[@]}" >/dev/null \
           && "$XDP_CONTROLLER" status >/dev/null; then
            xdp_sync_ok=1
            break
        fi
        [ "$xdp_attempt" -lt "$XDP_SYNC_ATTEMPTS" ] && sleep "$XDP_SYNC_BACKOFF"
    done
    if [ "$xdp_sync_ok" -eq 1 ]; then
        if [ "$physical_ipv6_on_xdp" -eq 1 ]; then
            logger -t "$LOG_TAG" \
                "DEGRADED: a physical Ethernet link has global IPv6 while the current XDP parser supports IPv4 only; physical IPv6 will not pass" \
                || true
        fi
        if [ "${#unsupported_ifaces[@]}" -gt 0 ]; then
            publish_xdp_health DEGRADED unsupported-link-type
            logger -t "$LOG_TAG" \
                "DEGRADED: unsupported physical link-layer path(s): ${unsupported_ifaces[*]}; qualified Ethernet XDP links remain active" \
                || true
        elif [ "$physical_ipv6_on_xdp" -eq 1 ]; then
            publish_xdp_health DEGRADED physical-ipv6-unsupported
        else
            publish_xdp_health ACTIVE verified
        fi
    else
        publish_xdp_health DEGRADED sync-or-postcheck-failed
        xdp_message="physical-link XDP generation refresh/postcheck failed after ${xdp_attempt} attempt(s)"
        if [ "$xdp_required" -ne 0 ]; then
            fail "FAILED: $xdp_message"
            mark_global_inconsistent || true
            exit 1
        fi
        logger -t "$LOG_TAG" "DEGRADED: $xdp_message" || true
        # The lower layers still commit below. The boot wrapper requests this
        # reserved status only after that complete transaction so it can spend
        # its bounded outer retry budget on a transient early-boot attach race.
        # Ordinary callers retain the documented fail-soft exit status.
        xdp_retryable_degraded=1
    fi
fi

batch=$(mktemp)
trap 'rm -f "$batch"' EXIT
publish_global_state INCONSISTENT
{
    printf 'flush set %s physical_ifaces\n' "$TABLE"
    printf 'flush set %s lan_guard_ifaces\n' "$TABLE"
    printf 'flush set %s connected_v4\n' "$TABLE"
    printf 'flush set %s connected_v6\n' "$TABLE"
    printf 'flush set %s allowed_v4\n' "$TABLE"
    printf 'flush set %s allowed_v6\n' "$TABLE"
    printf 'flush set %s outbound_peers_v4\n' "$TABLE"
    printf 'flush set %s inbound_peers_v4\n' "$TABLE"
    printf 'flush set %s inbound_tcp_v4\n' "$TABLE"
    printf 'flush set %s inbound_udp_v4\n' "$TABLE"
    if [ "$sync_wan_strict" -eq 1 ]; then
        printf 'flush set inet noid_wan_strict physical_ifaces\n'
        printf 'flush set inet noid_wan_strict lan_exceptions_v4\n'
        printf 'flush set inet noid_wan_strict lan_exceptions_v6\n'
        printf 'flush set inet noid_wan_strict lan_inbound_peers_v4\n'
    fi
    for item in "${ifaces[@]}"; do
        printf 'add element %s physical_ifaces { "%s" }\n' "$TABLE" "$item"
        if [ "$guard_enabled" -eq 1 ]; then
            printf 'add element %s lan_guard_ifaces { "%s" }\n' "$TABLE" "$item"
        fi
        if [ "$sync_wan_strict" -eq 1 ]; then
            printf 'add element inet noid_wan_strict physical_ifaces { "%s" }\n' "$item"
        fi
    done
    for item in "${prefixes_v4[@]}"; do
        if [ "$guard_enabled" -eq 1 ]; then
            printf 'add element %s connected_v4 { %s }\n' "$TABLE" "$item"
        elif [ "$sync_wan_strict" -eq 1 ]; then
            printf 'add element inet noid_wan_strict lan_exceptions_v4 { %s }\n' "$item"
        fi
    done
    for item in "${prefixes_v6[@]}"; do
        if [ "$guard_enabled" -eq 1 ]; then
            printf 'add element %s connected_v6 { %s }\n' "$TABLE" "$item"
        elif [ "$sync_wan_strict" -eq 1 ]; then
            printf 'add element inet noid_wan_strict lan_exceptions_v6 { %s }\n' "$item"
        fi
    done
    for item in "${allows_v4[@]}"; do
        printf 'add element %s allowed_v4 { %s }\n' "$TABLE" "$item"
        if [ "$sync_wan_strict" -eq 1 ]; then
            printf 'add element inet noid_wan_strict lan_exceptions_v4 { %s }\n' "$item"
        fi
    done
    for item in "${outbound_peer_ips_v4[@]}"; do
        printf 'add element %s outbound_peers_v4 { %s }\n' "$TABLE" "$item"
    done
    for item in "${inbound_peer_ips_v4[@]}"; do
        printf 'add element %s inbound_peers_v4 { %s }\n' "$TABLE" "$item"
        if [ "$sync_wan_strict" -eq 1 ]; then
            printf 'add element inet noid_wan_strict lan_inbound_peers_v4 { %s }\n' "$item"
        fi
    done
    for item in "${inbound_tcp_v4[@]}"; do
        printf 'add element %s inbound_tcp_v4 { %s }\n' "$TABLE" "$item"
    done
    for item in "${inbound_udp_v4[@]}"; do
        printf 'add element %s inbound_udp_v4 { %s }\n' "$TABLE" "$item"
    done
    # Layer-2 guard for Ethernet-framed physical devices. IP proceeds to the
    # inet/firewalld layers, standard ARP proceeds to native RFC 5227/kernel
    # handling with M04's permanent neighbour pins, and EAPOL (0x888e) is
    # required for WPA-Enterprise/802.1X link authentication. Every other
    # EtherType is rejected before a raw listener or sender can use it.
    # Non-Ethernet physical links remain in the L3/WAN-strict sets above but
    # cannot receive an `ether type` hook or the current Ethernet XDP parser.
    printf 'table netdev noid_l2_guard\n'
    printf 'delete table netdev noid_l2_guard\n'
    printf 'table netdev noid_l2_guard {\n'
    printf 'counter blocked_ingress { }\n'
    printf 'counter blocked_egress { }\n'
    chain_index=0
    for item in "${xdp_ifaces[@]}"; do
        printf 'chain ingress_%d { type filter hook ingress device "%s" priority -500; policy drop; ether type { ip, ip6, arp, 0x888e } accept; counter name blocked_ingress drop; }\n' \
            "$chain_index" "$item"
        printf 'chain egress_%d { type filter hook egress device "%s" priority -500; policy drop; ether type { ip, ip6, arp, 0x888e } accept; counter name blocked_egress drop; }\n' \
            "$chain_index" "$item"
        chain_index=$((chain_index + 1))
    done
    printf '}\n'
} > "$batch"

if ! nft_error=$(nft -c -f "$batch" 2>&1) || ! nft_error=$(nft -f "$batch" 2>&1); then
    fail "FAILED: atomic topology-set refresh rejected: $nft_error"
    exit 1
fi

if [ "$global_allow" -eq 1 ]; then
    publish_global_state ALLOWED
else
    publish_global_state BLOCKED
fi
# Publish the scan-start moment only after the transaction committed. A failed
# or aborted run must never let a queued successor skip itself. Failure to
# publish only forfeits coalescing, so it is deliberately non-fatal. An
# unreadable monotonic clock publishes nothing at all: an untagged or empty
# stamp must never become the value a successor compares itself against.
if [[ "$SCAN_STARTED_AT" =~ ^[0-9]+$ ]] \
   && scan_tmp=$(mktemp "${SCAN_STAMP%/*}/.lan-topology-scan.XXXXXX" 2>/dev/null); then
    if printf '%s=%s\n' "$SCAN_STAMP_TAG" "$SCAN_STARTED_AT" > "$scan_tmp" \
       && chmod 0600 "$scan_tmp" \
       && chown "$STATE_UID:$STATE_GID" "$scan_tmp"; then
        mv -fT "$scan_tmp" "$SCAN_STAMP" || rm -f -- "$scan_tmp"
    else
        rm -f -- "$scan_tmp"
    fi
fi
logger -t "$LOG_TAG" "refreshed: ${#ifaces[@]} physical L3 interfaces, ${#xdp_ifaces[@]} Ethernet XDP/L2 links, ${#unsupported_ifaces[@]} unsupported link types, ${#prefixes_v4[@]} IPv4 + ${#prefixes_v6[@]} IPv6 prefixes, ${#allows_v4[@]} IPv4 allows; IPv6 peer allows unsupported; XDP health recorded separately" || true
if [ "$xdp_retryable_degraded" -eq 1 ] \
   && [ "$RETRY_DEGRADED_XDP" -eq 1 ]; then
    exit "$XDP_RETRY_RC"
fi
LAN_TOPOLOGY_REFRESH_EOF
chmod 0755 /usr/local/sbin/noid-lan-topology-refresh.sh
chown root:root /usr/local/sbin/noid-lan-topology-refresh.sh

cat > /usr/local/sbin/noid-lan-topology-boot-refresh.sh <<'LAN_TOPOLOGY_BOOT_REFRESH_EOF'
#!/bin/bash
# During physical coldplug, a netdev can be renamed or briefly disappear after
# /sys enumeration but before nft validates its netdev hook. Retry the complete
# topology transaction from fresh kernel state, never only its final nft step.
set -euo pipefail
umask 077

REFRESH="${NOID_LAN_TOPOLOGY_REFRESH:-/usr/local/sbin/noid-lan-topology-refresh.sh}"
ATTEMPTS="${NOID_LAN_TOPOLOGY_BOOT_ATTEMPTS:-8}"
BACKOFF="${NOID_LAN_TOPOLOGY_BOOT_BACKOFF:-1}"
LOG_TAG=noid-lan-topology-boot
XDP_RETRY_RC=75

journal_log() {
    logger -t "$LOG_TAG" "$*" || true
}

[ "$#" -eq 0 ] || {
    echo "boot topology refresh accepts no arguments" >&2
    exit 2
}
[[ "$ATTEMPTS" =~ ^[1-9][0-9]?$ ]] || {
    echo "invalid boot topology attempt count" >&2
    exit 2
}
[[ "$BACKOFF" =~ ^(0|[1-9][0-9]?)$ ]] || {
    echo "invalid boot topology backoff" >&2
    exit 2
}
[ -x "$REFRESH" ] || {
    echo "topology refresh helper is not executable: $REFRESH" >&2
    exit 1
}

attempt=0
last_rc=1
while [ "$attempt" -lt "$ATTEMPTS" ]; do
    attempt=$((attempt + 1))
    # The boot wrapper owns the complete-transaction retry budget. Disable the
    # refresh helper's inner controller retry so coldplug cannot multiply the
    # default eight outer attempts by four inner attempts.
    if NOID_LAN_XDP_SYNC_ATTEMPTS=1 \
       NOID_LAN_RETRY_DEGRADED_XDP=1 "$REFRESH"; then
        if [ "$attempt" -gt 1 ]; then
            journal_log "complete topology transaction converged on attempt $attempt"
        fi
        exit 0
    else
        last_rc=$?
    fi
    if [ "$last_rc" -eq "$XDP_RETRY_RC" ]; then
        journal_log \
            "retryable XDP postcheck degradation on complete topology transaction attempt $attempt/$ATTEMPTS"
        printf '%s\n' \
            "noid-lan-topology-boot: XDP postcheck degraded on complete transaction attempt $attempt/$ATTEMPTS; lower nft/firewall layers committed; retrying from fresh state" \
            >&2
    else
        journal_log \
            "complete topology transaction attempt $attempt/$ATTEMPTS failed (rc=$last_rc)"
        printf '%s\n' \
            "noid-lan-topology-boot: complete transaction attempt $attempt/$ATTEMPTS failed (rc=$last_rc); inspect journalctl -b -t noid-lan-topology" \
            >&2
    fi
    if [ "$attempt" -lt "$ATTEMPTS" ] && [ "$BACKOFF" -gt 0 ]; then
        sleep "$BACKOFF"
    fi
done

if [ "$last_rc" -eq "$XDP_RETRY_RC" ]; then
    journal_log \
        "DEGRADED: XDP postcheck remained unavailable after $ATTEMPTS complete transaction attempt(s); lower nft/firewall layers are committed"
    printf '%s\n' \
        "noid-lan-topology-boot: XDP postcheck remained degraded after $ATTEMPTS complete transaction attempt(s); lower nft/firewall layers are committed; inspect journalctl -b -t noid-lan-topology" \
        >&2
    exit 0
fi
journal_log \
    "FAILED: complete topology transaction rejected after $ATTEMPTS attempt(s) (last rc=$last_rc)"
exit "$last_rc"
LAN_TOPOLOGY_BOOT_REFRESH_EOF
chmod 0755 /usr/local/sbin/noid-lan-topology-boot-refresh.sh
chown root:root /usr/local/sbin/noid-lan-topology-boot-refresh.sh

cat > /etc/NetworkManager/dispatcher.d/no-wait.d/30-noid-lan-topology-guard <<'LAN_TOPOLOGY_DISPATCHER_EOF'
#!/bin/bash
# Refresh before/after physical address or route changes. A pre-up failure is
# fail-closed: NetworkManager may abort activation rather than expose a LAN gap.
# NetworkManager runs normal dispatcher scripts one at a time, so never queue
# the expensive full XDP/nft transaction for VPN, tunnel or dummy interfaces.
# Ref: networkmanager.dev/docs/api/latest/NetworkManager-dispatcher.html
set -euo pipefail

IFACE="${1:-}"
ACTION="${2:-}"
REFRESH="${NOID_LAN_TOPOLOGY_REFRESH:-/usr/local/sbin/noid-lan-topology-refresh.sh}"
SYS_CLASS_NET="${NOID_SYS_CLASS_NET:-/sys/class/net}"
NFT="${NOID_NFT_BIN:-nft}"

case "$ACTION" in
    pre-up|up|down|dhcp4-change|dhcp6-change|reapply) ;;
    *) exit 0 ;;
esac
[[ "$IFACE" =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || exit 1

# VPN/tunnel/dummy events do not change physical-link topology. A disappearing
# physical device may already be absent from sysfs at `down`, so retain it as a
# physical event when the currently committed nft set still identifies it. If
# that table is unavailable, refresh conservatively so this path can restore it.
if [ ! -d "$SYS_CLASS_NET/$IFACE/device" ]; then
    [ "$ACTION" = down ] || exit 0
    if "$NFT" list table inet noid_lan_topology >/dev/null 2>&1; then
        "$NFT" get element inet noid_lan_topology physical_ifaces \
            "{ \"$IFACE\" }" >/dev/null 2>&1 || exit 0
    fi
fi

exec "$REFRESH"
LAN_TOPOLOGY_DISPATCHER_EOF
chmod 0700 /etc/NetworkManager/dispatcher.d/no-wait.d/30-noid-lan-topology-guard
chown root:root /etc/NetworkManager/dispatcher.d/no-wait.d/30-noid-lan-topology-guard
# `pre-up` is a load-bearing fail-closed gate and stays awaited. Ordinary
# address/route events can take several seconds for a complete XDP/nft
# transaction; NetworkManager otherwise serializes them ahead of unrelated
# tunnel `pre-up` actions. Keep one source payload, install an exact awaited
# copy, and point the normal dispatcher entry into the documented no-wait path.
install -m 0700 -o root -g root \
    /etc/NetworkManager/dispatcher.d/no-wait.d/30-noid-lan-topology-guard \
    /etc/NetworkManager/dispatcher.d/pre-up.d/30-noid-lan-topology-guard
ln -sfnT no-wait.d/30-noid-lan-topology-guard \
    /etc/NetworkManager/dispatcher.d/30-noid-lan-topology-guard

cat > /etc/systemd/system/noid-lan-topology-guard.service <<'LAN_TOPOLOGY_SERVICE_EOF'
[Unit]
Description=NoID Privacy topology-aware physical LAN egress guard
Documentation=man:nft(8)
After=firewalld.service systemd-tmpfiles-setup.service
Before=NetworkManager.service network-pre.target
Requires=firewalld.service systemd-tmpfiles-setup.service
StartLimitIntervalSec=60s
StartLimitBurst=3

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/noid-lan-topology-boot-refresh.sh
RemainAfterExit=yes
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
# XDP program/map pins live in bpffs below /sys. ProtectKernelTunables=yes
# remounts that path read-only even with ReadWritePaths and would make this
# fail-closed boot gate stop NetworkManager. Capabilities + syscall filtering
# retain the narrower mutation boundary.
ProtectKernelTunables=no
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_NETLINK AF_UNIX
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service bpf
CapabilityBoundingSet=CAP_NET_ADMIN CAP_BPF CAP_PERFMON
ReadWritePaths=-/sys/fs/bpf /run/noid-privacy

[Install]
WantedBy=multi-user.target
LAN_TOPOLOGY_SERVICE_EOF
chmod 0644 /etc/systemd/system/noid-lan-topology-guard.service
chown root:root /etc/systemd/system/noid-lan-topology-guard.service

# A boot scan plus NetworkManager dispatchers do not cover a hardware adapter
# that appears later and is configured outside NetworkManager. A udev-triggered
# oneshot closes that hotplug discovery gap. Both udev and the unit recheck the
# same `/sys/class/net/<iface>/device` predicate used by the refresh helper, so
# transient veth/tunnel creation cannot trigger a physical-boundary rebuild.
cat > /etc/systemd/system/noid-lan-topology-hotplug@.service <<'LAN_TOPOLOGY_HOTPLUG_SERVICE_EOF'
[Unit]
Description=Refresh NoID Privacy physical-network guards after net-device hotplug (%I)
After=firewalld.service noid-lan-topology-guard.service systemd-tmpfiles-setup.service
Requires=firewalld.service systemd-tmpfiles-setup.service

[Service]
Type=oneshot
ExecCondition=/usr/bin/test -d /sys/class/net/%I/device
ExecStart=/usr/local/sbin/noid-lan-topology-refresh.sh
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
# Required for bpffs generation replacement; see the primary service above.
ProtectKernelTunables=no
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_NETLINK AF_UNIX
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service bpf
CapabilityBoundingSet=CAP_NET_ADMIN CAP_BPF CAP_PERFMON
ReadWritePaths=-/sys/fs/bpf /run/noid-privacy
LAN_TOPOLOGY_HOTPLUG_SERVICE_EOF
chmod 0644 /etc/systemd/system/noid-lan-topology-hotplug@.service
chown root:root /etc/systemd/system/noid-lan-topology-hotplug@.service

cat > /etc/udev/rules.d/70-noid-lan-topology-hotplug.rules <<'LAN_TOPOLOGY_HOTPLUG_UDEV_EOF'
# Refresh both LAN/topology and WAN-strict hardware sets for late adapters.
SUBSYSTEM=="net", ACTION=="add", KERNEL!="lo", TEST=="device", TAG+="systemd", ENV{SYSTEMD_WANTS}+="noid-lan-topology-hotplug@%k.service"
LAN_TOPOLOGY_HOTPLUG_UDEV_EOF
chmod 0644 /etc/udev/rules.d/70-noid-lan-topology-hotplug.rules
chown root:root /etc/udev/rules.d/70-noid-lan-topology-hotplug.rules

# XDP-only incompatibility intentionally preserves the lower firewall/nft
# layers and WAN repair access. Make that reduced raw-packet boundary visible
# at every graphical login until a successful refresh replaces the health file.
mkdir -p /etc/xdg/autostart
cat > /usr/local/bin/noid-lan-xdp-notify <<'NOID_LAN_XDP_NOTIFY_EOF'
#!/bin/bash
set -euo pipefail
HEALTH_FILE=${NOID_LAN_XDP_HEALTH_FILE:-/run/noid-privacy/lan-xdp-health}
EXPECTED_UID=${NOID_LAN_XDP_STATE_UID:-0}
EXPECTED_GID=${NOID_LAN_XDP_STATE_GID:-0}

read_health() {
    local directory metadata
    local -a lines=()
    directory=${HEALTH_FILE%/*}
    [ -d "$directory" ] && [ ! -L "$directory" ] \
        && [ -f "$HEALTH_FILE" ] && [ ! -L "$HEALTH_FILE" ] \
        && [ -r "$HEALTH_FILE" ] || return 1
    metadata=$(stat -c '%u:%g:%a' "$directory") || return 1
    [ "$metadata" = "$EXPECTED_UID:$EXPECTED_GID:755" ] || return 1
    metadata=$(stat -c '%u:%g:%a:%h' "$HEALTH_FILE") || return 1
    [ "$metadata" = "$EXPECTED_UID:$EXPECTED_GID:644:1" ] || return 1
    mapfile -t lines < "$HEALTH_FILE" || return 1
    [ "${#lines[@]}" -eq 2 ] || return 1
    STATE=${lines[0]#STATE=}
    DETAIL=${lines[1]#DETAIL=}
    [ "${lines[0]}" = "STATE=$STATE" ] \
        && [ "${lines[1]}" = "DETAIL=$DETAIL" ] || return 1
    case "$STATE:$DETAIL" in
        ACTIVE:verified|DEGRADED:controller-missing|\
        DEGRADED:sync-or-postcheck-failed|DEGRADED:unsupported-link-type|\
        DEGRADED:no-ethernet-link|DEGRADED:physical-ipv6-unsupported) ;;
        *) return 1 ;;
    esac
}

STATE=unknown
DETAIL=unavailable
health_valid=0
if read_health; then
    health_valid=1
fi
case "$#" in
    0) [ "$health_valid" -eq 1 ] && [ "$STATE" = DEGRADED ] || exit 0 ;;
    1) [ "$1" = --force ] || exit 2 ;;
    *) exit 2 ;;
esac
command -v notify-send >/dev/null 2>&1 || exit 0

case "$DETAIL" in
    sync-or-postcheck-failed)
        message='The running kernel rejected the XDP/TC transaction or its post-check. WAN repair access remains available behind nft/firewall fallback layers. Reboot and select the previous Fedora kernel under GRUB Advanced options, then run noid-status.'
        ;;
    controller-missing)
        message='The installed LAN XDP controller is missing. WAN repair access remains available behind nft/firewall fallback layers. Repair or reinstall the NoID Privacy payload, then run noid-status; an older kernel does not restore a missing controller.'
        ;;
    unsupported-link-type)
        message='A physical link type is not Ethernet-framed and cannot receive the Ethernet XDP boundary. WAN repair access remains available behind nft/firewall fallback layers. Use a supported Ethernet/Wi-Fi path or review the hardware compatibility guide.'
        ;;
    no-ethernet-link)
        message='No Ethernet-framed physical link is present for the XDP boundary. WAN repair access remains available behind nft/firewall fallback layers. Connect a supported Ethernet/Wi-Fi path, then run noid-status.'
        ;;
    physical-ipv6-unsupported)
        message='Physical-link IPv6 is enabled, but this raw-packet XDP parser is IPv4-only. WAN repair access remains available behind nft/firewall fallback layers. Return physical IPv6 to the documented default-off policy or retain this visibly reduced boundary.'
        ;;
    *)
        message='The LAN XDP health detail is missing or unsafe. WAN repair access remains available behind nft/firewall fallback layers. Run noid-status and inspect the health file before choosing a recovery action.'
        ;;
esac
exec notify-send --urgency=critical --icon=network-error \
    --app-name='NoID Privacy' \
    'LAN raw-packet protection is degraded' \
    "$message"
NOID_LAN_XDP_NOTIFY_EOF
chmod 0755 /usr/local/bin/noid-lan-xdp-notify
chown root:root /usr/local/bin/noid-lan-xdp-notify

cat > /etc/xdg/autostart/noid-lan-xdp-health.desktop <<'NOID_LAN_XDP_NOTIFY_DESKTOP_EOF'
[Desktop Entry]
Type=Application
Name=NoID Privacy LAN Boundary Health
Comment=Warn when physical-link raw-packet protection is degraded
Exec=/usr/local/bin/noid-lan-xdp-notify
OnlyShowIn=GNOME;
NoDisplay=true
X-GNOME-Autostart-enabled=true
NOID_LAN_XDP_NOTIFY_DESKTOP_EOF
chmod 0644 /etc/xdg/autostart/noid-lan-xdp-health.desktop
chown root:root /etc/xdg/autostart/noid-lan-xdp-health.desktop

# NetworkManager must not activate physical links after a failed initial guard
# load. `Before=` alone orders jobs but does not propagate failure; this hard
# requirement closes that fail-open boot path.
mkdir -p /etc/systemd/system/NetworkManager.service.d
cat > /etc/systemd/system/NetworkManager.service.d/20-noid-lan-topology-guard.conf <<'LAN_TOPOLOGY_NM_REQUIRE_EOF'
[Unit]
Requires=noid-lan-topology-guard.service
After=noid-lan-topology-guard.service
LAN_TOPOLOGY_NM_REQUIRE_EOF
chmod 0644 /etc/systemd/system/NetworkManager.service.d/20-noid-lan-topology-guard.conf
chown root:root /etc/systemd/system/NetworkManager.service.d/20-noid-lan-topology-guard.conf
log "STEP 2d: topology-aware LAN guard + serialized hotplug refresh installed"

# ====================================================================
# STEP 3: NetworkManager VPN-zone rationale placeholder
# ====================================================================
# VPN interfaces must land in `noid-vpn`, not physical `drop`, or
# block-lan-out would drop their internal 10.x traffic. The deployed file
# below is a deliberate no-op placeholder — NM 1.54+ rejects
# connection.zone as a connection-default; the actual enforcement is the
# M06 dispatcher (50-vpn-zone-enforce). The placeholder keeps the expected
# NM config-path discoverable (rationale inside the file).
mkdir -p /etc/NetworkManager/conf.d
cat > /etc/NetworkManager/conf.d/03-vpn-zone.conf << 'NM_VPN_EOF'
# NoID Privacy — VPN connections in the dedicated noid-vpn firewalld zone
#
# Prevents block-lan-out policy from affecting VPN-internal 10.x/16.x/192.x.
# The noid-vpn zone has target DROP: outbound traffic and established replies
# work, while unsolicited tunnel-side connections to host services do not.
#
# NM 1.54+ rejects connection.zone as a connection-default value
# in NM.conf [connection-*] sections (warnings logged, settings NOT applied).
# Actual VPN zone enforcement is now handled exclusively by the NM dispatcher
# script in Module 06 (/etc/NetworkManager/dispatcher.d/50-vpn-zone-enforce),
# which uses firewall-cmd --change-interface=noid-vpn on every VPN connection
# up event. The dispatcher mechanism is more robust because it also catches
# VPN clients that explicitly set connection.zone=drop — which a NM.conf
# default could never override.
#
# This file is intentionally a no-op placeholder, kept so anyone grep-ing
# /etc/NetworkManager for "vpn-zone" lands here and reads the note above.
# Decision: defensive discoverability via
# expected NM config-path > moving archaeology to /usr/share/doc/. A future
# auditor inspecting NM VPN routing will check /etc/NetworkManager first.
NM_VPN_EOF
chmod 644 /etc/NetworkManager/conf.d/03-vpn-zone.conf
chown root:root /etc/NetworkManager/conf.d/03-vpn-zone.conf
log "STEP 3: VPN-zone rationale placeholder installed; Module 06 dispatcher performs enforcement"

# ====================================================================
# STEP 3b: Strip stock-default ssh allowance
# ====================================================================
# pykickstart's `firewall --enabled` adds ssh to the default zone (= drop
# on this image), while Libvirt ships ssh allowances in both its normal
# NAT `libvirt` zone and routed `libvirt-to-host` policy. All three are
# wrong-by-default here (no sshd installed; on manual reinstall the user
# adds ssh back explicitly, see the M09 opt-in playbook). 3-layer strip
# architecture: see the module header.
# firewall-offline-cmd writes the permanent config directly — the
# documented client for the Anaconda %post chroot, where no firewalld
# daemon serves D-Bus; offline changes load when firewalld starts. The
# drop-zone strip is best-effort (Anaconda's post-%post Network-Task
# rewrites drop.xml with ssh re-added — the firstboot re-strip in
# noid-firewalld-zone-enforce.sh is the canonical path); the
# Libvirt zone/policy strips are durable `/etc/firewalld` overrides from
# install-time on. Idempotent.
if firewall-offline-cmd --zone=drop --query-service=ssh >/dev/null 2>&1; then
    # firewall-offline-cmd reserves --remove-service for its legacy lokkit
    # compatibility mode. Combining that spelling with --zone/--policy is a
    # fatal "Can't use lokkit options with other options" error on F44.
    firewall-offline-cmd --zone=drop --remove-service-from-zone=ssh
fi
if firewall-offline-cmd --zone=libvirt --query-service=ssh >/dev/null 2>&1; then
    firewall-offline-cmd --zone=libvirt --remove-service-from-zone=ssh
fi
if firewall-offline-cmd --policy=libvirt-to-host --query-service=ssh >/dev/null 2>&1; then
    firewall-offline-cmd --policy=libvirt-to-host --remove-service-from-policy=ssh
fi
log "STEP 3b: stripped stock-default ssh from drop + Libvirt NAT/routed boundaries (defense-in-depth)"

# ====================================================================
# STEP 4: First-boot safety net — every physical interface → drop zone
# ====================================================================
# Safety net for profiles Anaconda preconfigured with a zone other than drop.
# The one-shot covers every kernel-backed physical interface present at first
# boot; Module 23 remains the steady-state pre-up/up enforcement for later
# profiles and hotplug. The stamp is written only after every postcondition.
cat > /etc/systemd/system/noid-firewalld-zone-enforce.service << 'SVC_EOF'
[Unit]
Description=NoID Privacy: enforce drop zone for all physical interfaces
After=NetworkManager.service firewalld.service
Requires=firewalld.service
ConditionPathExists=!/var/lib/noid-privacy/.firewalld-zone-enforced
ConditionKernelCommandLine=!rd.live.image

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/noid-firewalld-zone-enforce.sh
RemainAfterExit=yes
UMask=0077

# Full 2026-baseline sandbox. Service
# calls firewall-cmd (D-Bus AF_UNIX → firewalld) + writes /var/lib/noid-
# privacy flag file. AF_NETLINK whitelisted because firewalld may use it
# internally even though firewall-cmd is D-Bus only — defensive.
NoNewPrivileges=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
ProtectKernelLogs=yes
ProtectHostname=yes
ProtectClock=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/etc/firewalld /run/firewalld /var/lib/noid-privacy
PrivateTmp=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK
RestrictNamespaces=yes
MemoryDenyWriteExecute=yes
IPAddressDeny=any
IPAddressAllow=localhost
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources

[Install]
WantedBy=multi-user.target
SVC_EOF

cat > /usr/local/sbin/noid-firewalld-zone-enforce.sh << 'ENFORCE_EOF'
#!/bin/bash
#
# NoID Privacy — First-boot safety net: every physical interface → drop zone.
# DefaultZone=drop should handle this automatically, but Anaconda may have
# preconfigured a NetworkManager profile with a different zone. Module 23
# enforces future pre-up/up events; this one-shot closes the initial state.
#
set -euo pipefail
umask 077

log() { logger -t noid-firewalld-zone "$*"; }
SYS_CLASS_NET=${NOID_SYS_CLASS_NET:-/sys/class/net}
STAMP_FILE=${NOID_FIREWALLD_ZONE_STAMP:-/var/lib/noid-privacy/.firewalld-zone-enforced}
log "=== first-boot zone enforcement ==="

# Anaconda's Network-Task may add SSH to drop.xml after the compose-time
# offline edit. Strip that latent listener exposure independently of NICs: an
# offline/no-NIC installation needs the same deny postcondition as a connected
# installation. Batch every permanent mutation before one reload.
if firewall-cmd --permanent --zone=drop --query-service=ssh >/dev/null 2>&1; then
    firewall-cmd --permanent --zone=drop --remove-service=ssh
fi
if firewall-cmd --permanent --zone=libvirt --query-service=ssh >/dev/null 2>&1; then
    firewall-cmd --permanent --zone=libvirt --remove-service=ssh
fi
if firewall-cmd --permanent --policy=libvirt-to-host --query-service=ssh >/dev/null 2>&1; then
    firewall-cmd --permanent --policy=libvirt-to-host --remove-service=ssh
fi

declare -a PHYSICAL_IFACES=()
for net_path in "$SYS_CLASS_NET"/*; do
    [ -e "$net_path" ] || continue
    iface=${net_path##*/}
    [ "$iface" != lo ] || continue
    [[ "$iface" =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || {
        log "CRITICAL: unsafe physical interface name"
        exit 1
    }
    [ -d "$net_path/device" ] || continue
    [ -r "$net_path/address" ] || {
        log "CRITICAL: cannot read hardware address for $iface"
        exit 1
    }
    PHYSICAL_IFACES+=("$iface")
done

for iface in "${PHYSICAL_IFACES[@]}"; do
    firewall-cmd --permanent --zone=drop --change-interface="$iface"
    log "permanent drop-zone binding staged for physical interface $iface"
done

# Exactly one reload commits SSH removal, policy overrides and all permanent
# interface bindings together. Then repair any runtime assignment retained by
# an explicitly zoned NetworkManager profile; Module 23 persists that profile.
firewall-cmd --reload
for iface in "${PHYSICAL_IFACES[@]}"; do
    if [ "$(firewall-cmd --get-zone-of-interface="$iface" 2>/dev/null || true)" != drop ]; then
        firewall-cmd --zone=drop --change-interface="$iface"
    fi
    [ "$(firewall-cmd --get-zone-of-interface="$iface")" = drop ] || {
        log "CRITICAL: $iface did not enter drop zone"
        exit 1
    }
    log "$iface verified in drop zone"
done

[ "$(firewall-cmd --permanent --zone=drop --query-service=ssh 2>&1 || true)" = "no" ] || {
    log "CRITICAL: ssh service remains allowed in drop zone"
    exit 1
}
if firewall-cmd --permanent --get-zones | tr ' ' '\n' | grep -qx libvirt; then
    [ "$(firewall-cmd --permanent --zone=libvirt --query-service=ssh 2>&1 || true)" = "no" ] || {
        log "CRITICAL: ssh service remains allowed in libvirt NAT zone"
        exit 1
    }
fi
if firewall-cmd --permanent --get-policies | tr ' ' '\n' \
        | grep -qx libvirt-to-host; then
    [ "$(firewall-cmd --permanent --policy=libvirt-to-host --query-service=ssh 2>&1 || true)" = "no" ] || {
        log "CRITICAL: ssh service remains allowed in libvirt-to-host policy"
        exit 1
    }
fi
log "ssh stripped from drop + Libvirt NAT/routed boundaries at firstboot"

if [ "${#PHYSICAL_IFACES[@]}" -eq 0 ]; then
    log "no physical interface present; deny defaults and SSH postconditions verified"
else
    log "${#PHYSICAL_IFACES[@]} physical interface(s) verified in drop zone"
fi

# End-to-end proof that firewalld loaded exactly the hardened policy contract.
require_policy_value() {
    local expected=$1 field=$2 actual
    shift 2
    actual=$("$@") || {
        log "CRITICAL: cannot read allow-host-ipv6 permanent $field"
        exit 1
    }
    [ "$actual" = "$expected" ] || {
        log "CRITICAL: allow-host-ipv6 permanent $field is $actual, expected $expected"
        exit 1
    }
}
require_policy_value -15000 priority firewall-cmd --permanent \
    --policy=allow-host-ipv6 --get-priority
require_policy_value CONTINUE target firewall-cmd --permanent \
    --policy=allow-host-ipv6 --get-target
require_policy_value ANY ingress-zones firewall-cmd --permanent \
    --policy=allow-host-ipv6 --list-ingress-zones
require_policy_value HOST egress-zones firewall-cmd --permanent \
    --policy=allow-host-ipv6 --list-egress-zones

declare -a EXPECTED_HOSTV6_RULES=(
    'rule family="ipv6" icmp-type name="mld-listener-done" accept'
    'rule family="ipv6" icmp-type name="mld-listener-query" accept'
    'rule family="ipv6" icmp-type name="mld-listener-report" accept'
    'rule family="ipv6" icmp-type name="mld2-listener-report" accept'
    'rule family="ipv6" icmp-type name="neighbour-advertisement" accept'
    'rule family="ipv6" icmp-type name="neighbour-solicitation" accept'
)
for scope in runtime permanent; do
    scope_args=()
    [ "$scope" = runtime ] || scope_args+=(--permanent)
    policy_info=$(firewall-cmd "${scope_args[@]}" \
        --info-policy=allow-host-ipv6) || {
        log "CRITICAL: cannot inspect allow-host-ipv6 $scope policy"
        exit 1
    }
    for metadata in \
        '  disable: no' \
        '  priority: -15000' \
        '  target: CONTINUE' \
        '  ingress-zones: ANY' \
        '  egress-zones: HOST' \
        '  services: ' \
        '  ports: ' \
        '  protocols: ' \
        '  masquerade: no' \
        '  forward-ports: ' \
        '  source-ports: ' \
        '  icmp-blocks: '; do
        printf '%s\n' "$policy_info" | grep -qxF "$metadata" || {
            log "CRITICAL: allow-host-ipv6 $scope metadata mismatch: $metadata"
            exit 1
        }
    done
    rules_output=$(firewall-cmd "${scope_args[@]}" \
        --policy=allow-host-ipv6 --list-rich-rules)
    rule_count=$(printf '%s\n' "$rules_output" | grep -c '^rule ' || true)
    [ "$rule_count" = 6 ] || {
        log "CRITICAL: allow-host-ipv6 $scope rule count is $rule_count, expected 6"
        exit 1
    }
    for expected_rule in "${EXPECTED_HOSTV6_RULES[@]}"; do
        printf '%s\n' "$rules_output" | grep -qxF "$expected_rule" || {
            log "CRITICAL: allow-host-ipv6 $scope rule missing: $expected_rule"
            exit 1
        }
    done
done
log "allow-host-ipv6 exact metadata + six-rule runtime/permanent contract verified"

install -d -m 0755 "${STAMP_FILE%/*}"
install -m 0600 /dev/null "$STAMP_FILE"

# Note: an early M17 livesys-session-extra hook once added SSH to the drop/
# FedoraWorkstation zones for Live-mode VM-audit access; it was reverted
# (see M17 source). The NoID Privacy default image ships no SSH server. The
# ssh-strip above is the canonical path — no M17 Live-hook competes with it.

log "=== done ==="
ENFORCE_EOF

chmod 755 /usr/local/sbin/noid-firewalld-zone-enforce.sh
chown root:root /usr/local/sbin/noid-firewalld-zone-enforce.sh
log "STEP 4: noid-firewalld-zone-enforce service + script installed"

# ====================================================================
# STEP 5: Enable services
# ====================================================================
systemctl enable firewalld.service
systemctl enable noid-firewalld-zone-enforce.service
systemctl enable noid-lan-topology-guard.service
log "STEP 5: firewalld + zone-enforce + LAN-topology-guard services enabled"

# Normalize and verify project-owned SELinux labels now; Module 99 repeats the
# full-image relabel gate, but Module 03 must not hand it mislabeled executables.
restorecon -RF \
    /etc/firewalld \
    /etc/NetworkManager/conf.d/03-vpn-zone.conf \
    /etc/NetworkManager/dispatcher.d \
    /etc/nftables.d/noid-lan-topology.nft \
    /etc/systemd/system/noid-firewalld-zone-enforce.service \
    /etc/systemd/system/noid-lan-topology-guard.service \
    /etc/systemd/system/noid-lan-topology-hotplug@.service \
    /etc/systemd/system/NetworkManager.service.d/20-noid-lan-topology-guard.conf \
    /etc/udev/rules.d/70-noid-lan-topology-hotplug.rules \
    /etc/xdg/autostart/noid-lan-xdp-health.desktop \
    /usr/lib/noid-privacy/noid-lan-xdp.bpf.o \
    /usr/local/bin/noid-lan-xdp-notify \
    /usr/local/sbin/noid-firewalld-zone-enforce.sh \
    /usr/local/sbin/noid-lan-topology-boot-refresh.sh \
    /usr/local/sbin/noid-lan-topology-refresh.sh \
    /usr/local/sbin/noid-lan-xdp

# ====================================================================
# STEP 6: Verification (logged to /var/log/ks-03-firewalld.log)
# ====================================================================
log "STEP 6: verification ==="

verify_fail() {
    log "  ✗ $*"
    exit 1
}
require_mode() {
    local expected=$1 path=$2 actual
    [ -e "$path" ] || verify_fail "required artifact missing: $path"
    actual=$(stat -Lc '%u:%g:%a' "$path") \
        || verify_fail "cannot inspect $path"
    [ "$actual" = "0:0:$expected" ] \
        || verify_fail "$path metadata is $actual, expected 0:0:$expected"
}
require_exact_line() {
    local path=$1 expected=$2 count
    count=$(grep -cFx -- "$expected" "$path" || true)
    [ "$count" = 1 ] \
        || verify_fail "$path must contain exactly once: $expected"
}

require_mode 600 /etc/firewalld/firewalld.conf
config_count=$(grep -Ec '^[A-Za-z][A-Za-z0-9_]*=' \
    /etc/firewalld/firewalld.conf || true)
[ "$config_count" = 14 ] \
    || verify_fail "firewalld.conf has $config_count settings, expected 14"
for setting in \
    DefaultZone=drop \
    CleanupOnExit=yes \
    CleanupModulesOnExit=no \
    IPv6_rpfilter=loose \
    IndividualCalls=no \
    NftablesFlowtable=off \
    NftablesCounters=yes \
    LogDenied=off \
    FirewallBackend=nftables \
    NftablesTableOwner=yes \
    FlushAllOnReload=yes \
    ReloadPolicy=INPUT:DROP,FORWARD:DROP,OUTPUT:DROP \
    RFC3964_IPv4=yes \
    StrictForwardPorts=yes; do
    require_exact_line /etc/firewalld/firewalld.conf "$setting"
done

HOST_POLICY=/etc/firewalld/policies/block-lan-out.xml
require_mode 644 "$HOST_POLICY"
DHCP_HOST_RULE='  <rule family="ipv4" priority="-32768"><source-port port="68" protocol="udp"/><accept/></rule>'
require_exact_line "$HOST_POLICY" "$DHCP_HOST_RULE"
rule_count=$(grep -c '<rule ' "$HOST_POLICY" || true)
[ "$rule_count" = 38 ] \
    || verify_fail "block-lan-out has $rule_count rules, expected 38 (37 drops + host DHCP continuation)"
[ "$(grep -c '<ingress-zone name="HOST"/>' "$HOST_POLICY" || true)" = 1 ] \
    || verify_fail "block-lan-out must have exactly one HOST ingress"
[ "$(grep -c '<egress-zone name="drop"/>' "$HOST_POLICY" || true)" = 1 ] \
    || verify_fail "block-lan-out must have exactly one drop egress"
! grep -q '<ingress-zone name="libvirt"/>' "$HOST_POLICY" \
    || verify_fail "HOST policy illegally mixes libvirt ingress"

if [ -f /usr/lib/firewalld/zones/libvirt.xml ] \
        || [ -f /etc/firewalld/zones/libvirt.xml ]; then
    VM_POLICY=/etc/firewalld/policies/block-lan-out-vms.xml
    require_mode 644 "$VM_POLICY"
    vms_rule_count=$(grep -c '<rule ' "$VM_POLICY" || true)
    [ "$vms_rule_count" = 37 ] \
        || verify_fail "block-lan-out-vms has $vms_rule_count rules, expected 37"
    [ "$(grep -c '<ingress-zone name="libvirt"/>' "$VM_POLICY" || true)" = 1 ] \
        || verify_fail "VM policy must have exactly one libvirt ingress"
    ! grep -q '<ingress-zone name="HOST"/>' "$VM_POLICY" \
        || verify_fail "VM policy illegally retains HOST ingress"
    [ "$(grep -c '<egress-zone name="drop"/>' "$VM_POLICY" || true)" = 1 ] \
        || verify_fail "VM policy must have exactly one drop egress"
    [ "$(grep -cF "$DHCP_HOST_RULE" "$VM_POLICY" || true)" = 0 ] \
        || verify_fail "VM policy inherited the host-only DHCP continuation"
    cmp <(grep '<rule ' "$HOST_POLICY" | grep -Fvx "$DHCP_HOST_RULE") \
        <(grep '<rule ' "$VM_POLICY") \
        || verify_fail "HOST and VM 37-rule LAN-drop bodies differ"
fi

HOSTV6_POLICY=/etc/firewalld/policies/allow-host-ipv6.xml
require_mode 644 "$HOSTV6_POLICY"
require_exact_line "$HOSTV6_POLICY" '<policy target="CONTINUE" priority="-15000">'
require_exact_line "$HOSTV6_POLICY" '  <ingress-zone name="ANY" />'
require_exact_line "$HOSTV6_POLICY" '  <egress-zone name="HOST" />'
v6_count=$(grep -c '<icmp-type name=' "$HOSTV6_POLICY" || true)
[ "$v6_count" = 6 ] \
    || verify_fail "allow-host-ipv6 has $v6_count ICMP types, expected 6"
for icmp_type in \
    mld-listener-done \
    mld-listener-query \
    mld-listener-report \
    mld2-listener-report \
    neighbour-advertisement \
    neighbour-solicitation; do
    [ "$(grep -cF "<icmp-type name=\"$icmp_type\" />" "$HOSTV6_POLICY" || true)" = 1 ] \
        || verify_fail "allow-host-ipv6 exact rule missing/duplicated: $icmp_type"
done

VPN_ZONE=/etc/firewalld/zones/noid-vpn.xml
require_mode 644 "$VPN_ZONE"
require_exact_line "$VPN_ZONE" '<zone target="DROP">'
[ "$(grep -c '<service ' "$VPN_ZONE" || true)" = 0 ] \
    || verify_fail "noid-vpn zone opens a service"

require_mode 644 /etc/NetworkManager/conf.d/03-vpn-zone.conf
grep -qF 'dispatcher.d/50-vpn-zone-enforce' \
    /etc/NetworkManager/conf.d/03-vpn-zone.conf \
    || verify_fail "VPN placeholder does not identify its Module 06 enforcer"
! grep -qE '^[[:space:]]*connection\.zone=' \
    /etc/NetworkManager/conf.d/03-vpn-zone.conf \
    || verify_fail "invalid NetworkManager connection.zone default returned"

require_mode 644 /etc/nftables.d/noid-lan-topology.nft
require_exact_line /etc/nftables.d/noid-lan-topology.nft \
    '        oifname @physical_ifaces meta nfproto ipv4 meta skuid 0 \'
require_exact_line /etc/nftables.d/noid-lan-topology.nft \
    '            udp sport 68 udp dport 67 counter name dhcp_client_v4 accept'
require_exact_line /etc/nftables.d/noid-lan-topology.nft \
    '        oifname @lan_guard_ifaces meta nfproto ipv4 udp sport 68 \'
require_exact_line /etc/nftables.d/noid-lan-topology.nft \
    '            counter name blocked_dhcp_client_misuse_v4 drop'
require_mode 755 /usr/local/sbin/noid-lan-topology-boot-refresh.sh
require_mode 755 /usr/local/sbin/noid-lan-topology-refresh.sh
require_mode 700 /etc/NetworkManager/dispatcher.d/pre-up.d/30-noid-lan-topology-guard
require_mode 700 /etc/NetworkManager/dispatcher.d/no-wait.d/30-noid-lan-topology-guard
[ "$(readlink /etc/NetworkManager/dispatcher.d/30-noid-lan-topology-guard)" \
    = no-wait.d/30-noid-lan-topology-guard ] \
    || verify_fail "NetworkManager no-wait topology link is missing or wrong"
cmp -s \
    /etc/NetworkManager/dispatcher.d/pre-up.d/30-noid-lan-topology-guard \
    /etc/NetworkManager/dispatcher.d/no-wait.d/30-noid-lan-topology-guard \
    || verify_fail "awaited and no-wait topology dispatcher copies differ"
require_mode 644 /etc/systemd/system/noid-lan-topology-guard.service
require_mode 644 /etc/systemd/system/noid-lan-topology-hotplug@.service
require_mode 644 /etc/systemd/system/NetworkManager.service.d/20-noid-lan-topology-guard.conf
require_mode 644 /etc/udev/rules.d/70-noid-lan-topology-hotplug.rules
require_mode 755 /usr/local/sbin/noid-firewalld-zone-enforce.sh
require_mode 644 /etc/systemd/system/noid-firewalld-zone-enforce.service
require_mode 755 /usr/local/bin/noid-lan-xdp-notify
require_mode 644 /etc/xdg/autostart/noid-lan-xdp-health.desktop

require_mode 644 /usr/lib/noid-privacy/noid-lan-xdp.bpf.o
echo '9f244286de91021ed53fab3f1bf03cdfc248aa9e0090061a91beafe39f96849a  /usr/lib/noid-privacy/noid-lan-xdp.bpf.o' \
    | sha256sum -c - >/dev/null \
    || verify_fail "installed LAN-XDP object digest drift"
require_mode 755 /usr/local/sbin/noid-lan-xdp
for script in \
    /usr/local/sbin/noid-lan-xdp \
    /usr/local/sbin/noid-lan-topology-boot-refresh.sh \
    /usr/local/sbin/noid-lan-topology-refresh.sh \
    /usr/local/sbin/noid-firewalld-zone-enforce.sh \
    /etc/NetworkManager/dispatcher.d/pre-up.d/30-noid-lan-topology-guard \
    /etc/NetworkManager/dispatcher.d/no-wait.d/30-noid-lan-topology-guard \
    /usr/local/bin/noid-lan-xdp-notify; do
    bash -n "$script" || verify_fail "Bash syntax invalid: $script"
    matchpathcon -V "$script" >/dev/null 2>&1 \
        || verify_fail "SELinux label mismatch: $script"
done

firewall-offline-cmd --check-config >/dev/null \
    || verify_fail "firewalld rejected the complete permanent configuration"
for unit in \
    firewalld.service \
    noid-firewalld-zone-enforce.service \
    noid-lan-topology-guard.service; do
    systemctl is-enabled --quiet "$unit" \
        || verify_fail "required service is not enabled: $unit"
done

[ ! -e /usr/local/sbin/noid-privacy-mode.sh ] \
    || verify_fail "retired noid-privacy-mode.sh remains installed"
[ ! -e /usr/share/noid-privacy/firewalld-modes ] \
    || verify_fail "retired firewalld mode templates remain installed"

log "=== Module 03 complete ==="
%end

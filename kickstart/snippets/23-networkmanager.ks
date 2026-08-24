# ============================================================================
# Module 23 — NetworkManager Privacy Hardening
# Status: LOCKED 2026-08-11 (v49) — keep strict rp_filter native across activation.
#
# Covers:
#   - 00-noid-mac-randomization.conf (MAC_EOF): ethernet
#     cloned-mac-address=stable + ethernet.wake-on-lan=32768 (ignore) +
#     wifi.scan-rand-mac-address=yes
#   - 01-noid-ipv6.conf (IPV6_EOF): ethernet+wifi ip6-privacy=2 +
#     addr-gen-mode=1 (stable-privacy) latent custom-fork safeguards
#     (RFC 8981/7217), not a standalone physical-IPv6 re-enable recipe
#   - 02-noid-connection-defaults.conf (DEFAULTS_EOF): [main]
#     hostname-mode=none + [connection] connection.lldp=0 + unset-profile
#     MPTCP endpoint handling disabled + non-physical dns-over-tls=1 + physical
#     activation dns-over-tls=2 + ipv4/ipv6.dhcp-send-hostname=0 + IPv4 DAD
#     enabled
#   - dispatcher.d/40-noid-connection-defaults (DISPATCHER_EOF): Layer 1 =
#     always-runs physical-zone enforcement (firewalld `drop` for every
#     wifi/ethernet connection); Layer 2 = STATE_FILE-guarded first-up
#     hardening (user-scope after runtime reapply, dhcp-client-id=mac,
#     ipv6 method/ignore-auto-*, mdns/llmnr/lldp off, TunnelVision
#     route-cleanup) with a Live-Mode runtime-only dual path; DHCP-route
#     cleanup is also event-driven on every DHCPv4 renewal/reapply
#   - noid-nm-scope-physical-profiles: on installed systems after GIS account
#     completion, and when a later first-up profile requests reconciliation,
#     scope saved physical profiles and reconcile every active profile via
#     reapply or controlled reactivation + a checked final reapply; Live media
#     are condition-skipped because liveuser has no persistent pre-login scope
#   - dispatcher.d/99-noid-sysctl-reapply (SYSCTL_REAPPLY_EOF): targeted
#     strict rp_filter + WLAN frame-filter repair on awaited pre-up and
#     IPv4-capable up/vpn-up/dhcp4/reapply events
#   - STEP 3 verification (3.1-3.9, dynamic accumulator)
#
# NOT covered (other modules own these):
#   - Connectivity check and global resolved/Quad9 policy (M05
#     99-privacy.conf) · VPN noid-vpn zone (M03 03-vpn-zone.conf) · VPN
#     killswitch dispatchers (M06 20-/50-/55-/58-/60-; retired 70- absent) ·
#     ARP dispatcher (M04 90-) ·
#     NM service-unit hardening (M08) · sysctl IPv6 safety net (M02) ·
#     gai.conf IPv4 precedence + WAN IPv6 firstboot (M07)
#
# Deliberate deviations (do NOT re-litigate):
#   - WiFi connection MAC: Fedora vendor default (stable-ssid via
#     22-wifi-mac-addr.conf) is NOT overridden — verify 3.5 depends on it.
#   - wake-on-lan=32768 is NM.conf's numeric form of `ignore`: NetworkManager
#     does not manage device WoL.
#     M27's earlier systemd.link `WakeOnLan=off` is the disabling control;
#     an explicit per-connection NM value is the administrator opt-in.
#   - ipv4.ignore-auto-routes=false + post-DHCP route-cleanup — NOT =true
#     (=true also dropped the DHCP default route → no internet pre-VPN,
#     blocking VPN setup). Cleanup deletes every proto-dhcp route except
#     default; connected-subnet routes are proto=kernel and survive.
#     Defense layering: L1 block-lan-out (M03) / L2 drop zone (M03) /
#     L3 this route-cleanup / L4 VPN-client killswitch.
#   - Connection permissions: user-scope ONLY for wifi/ethernet; VPN +
#     killswitch profiles (wireguard/dummy and other non-physical native
#     connection types) intentionally stay system-wide.
#   - hostname-mode=none controls NetworkManager's management of the local
#     transient hostname; it is not a DHCP-send control. The separate current
#     ipv4/ipv6.dhcp-send-hostname ternary is pinned to 0 globally and applied
#     to physical profiles. The generic master.ks hostname remains a separate
#     data-minimization fallback, not evidence that suppression succeeded.
#   - NetworkManager MPTCP endpoint handling is disabled only as the default
#     for profiles whose connection.mptcp-flags remain unset/default. An
#     explicit per-profile value remains the administrator opt-in, but enabling
#     IPv4 MPTCP handling conflicts with this image's strict rp_filter policy.
#
# Constraint notes (keep when editing):
#   - NM 1.54+ REJECTS ipv6.method, ipv4/ipv6.ignore-auto-dns/routes and
#     connection.zone as [connection-*] defaults in NM.conf (logged as
#     unknown key, silently ignored) — the 40- dispatcher applies them through
#     this module's maintained per-profile nmcli path.
#   - `connection.dns-over-tls` is a maintained [connection-*] default in NM
#     1.56. The generic fallback is deliberately 1: VPN/private and other
#     non-physical scopes try DoT but may fall back to DNS/53 when the selected
#     resolver has no DoT endpoint. This is best-effort encryption, not strict
#     authentication or downgrade resistance. Device-matched Ethernet/Wi-Fi
#     sections default to strict (numeric 2), closing the first activation
#     before the physical-only dispatcher replaces DHCP DNS with named Quad9
#     and applies M05's current selection. An explicit profile value always
#     wins over these defaults.
#   - `connection.mptcp-flags` is a maintained [connection] default. With an
#     unset profile NetworkManager otherwise enables MPTCP endpoint handling
#     when the kernel MPTCP sysctl permits it, and deliberately loosens strict
#     IPv4 rp_filter=1 to loose mode 2. Numeric 1 is the NM.conf form of
#     `disabled`; pinning it prevents that activation-time policy conflict.
#     The targeted 99- dispatcher remains defense in depth for explicit
#     profile overrides and other runtime drift.
#   - Live-Mode: Anaconda's connection lives in /run/NetworkManager/... .
#     A persistent `nmcli connection modify` attempts migration into the
#     read-only image overlay and fails. The runtime path uses resolvectl +
#     sysctl for active enforcement, `connection modify --temporary` for
#     NetworkManager's in-memory/runtime-backed profile view, and the narrowly
#     scoped `device modify ... ipv6.method disabled` only when the profile
#     activated with another method. A complete `device reapply` restarts DHCP.
#   - nmcli permissions CLI format is "user:NAME" WITHOUT trailing colon
#     (the "user:NAME:;" form is .nmconnection file list-format).
#   - NetworkManager always runs an already-queued dispatcher event even when
#     a later event made it obsolete. A missing event UUID is ignored only
#     after a successful full profile enumeration proves it no longer exists;
#     enumeration/type failures for a still-present UUID remain fail-closed.
#   - Interface names are administrator-controlled and never establish device
#     type. The physical-policy dispatcher classifies only NetworkManager's
#     native connection.type; name prefixes cannot bypass the physical policy.
#   - NM may set per-interface rp_filter=2 at connection activation,
#     overriding the M02 wildcard *.rp_filter=1 (wildcard only applies to
#     interfaces existing at systemd-sysctl time; effective =
#     MAX(all, interface)). Fedora 44's CONFIG_HS20-enabled wpa_supplicant 2.11
#     contains an unconditional disassociation call with frame-filter flags=0;
#     its nl80211 backend maps that to zero for drop_gratuitous_arp and
#     drop_unicast_in_l2_multicast, while an ordinary non-HS20 association does
#     not repopulate those flags. This is a source-proven drift capability, not
#     a claim that one observed reference-host roam attributed the live writer.
#     The 99- dispatcher repairs only the global/interface rp_filter nodes and
#     those two exact interface frame-filter nodes after awaited pre-up and
#     IPv4-capable activation/renewal/reapply events. It never reloads unrelated
#     sysctl drop-ins. This also applies in Live-Mode because sysctl state is
#     runtime state. It must sort AFTER the M06 dispatchers
#     (20-/50-/55-/58-/60-). The retired 70-pvpn-killswitch-dns-fix name is
#     deliberately absent and asserted absent by M99.
#   - tests/23 pins the three conf.d paths + heredoc tags and the physical
#     `ipv6.method=disabled` contract. It also proves native non-physical
#     connection types are not rewritten by this module.
#
# Cross-reference:
#   - M02 (sysctl wildcards + IPv6 safety net), M03 (zones), M04 (ARP),
#     M05 (NM privacy conf), M06 (dispatcher chain), M07 (gai.conf +
#     WAN IPv6 firstboot), M08 (NM unit hardening).
# ============================================================================

# ---------------------------------------------------------------------------
# %post — Module 23 MAC randomization
# ---------------------------------------------------------------------------
%post --erroronfail --log=/var/log/ks-23-networkmanager.log
set -euo pipefail

log() { echo "[noid-23-nm] $*"; }
log "=== Module 23 post-install: NetworkManager privacy ==="

# ====================================================================
# STEP 1: Ethernet MAC randomization
# ====================================================================
# Rationale lives in the deployed MAC_EOF heredoc. 00-noid-* prefix loads
# BEFORE other drop-ins (NM reads conf.d alphabetically, last-wins per key);
# the WiFi connection MAC stays on the Fedora vendor default
# (wifi.cloned-mac-address=stable-ssid via 22-wifi-mac-addr.conf).

log "STEP 1: writing /etc/NetworkManager/conf.d/00-noid-mac-randomization.conf"

mkdir -p /etc/NetworkManager/conf.d
cat > /etc/NetworkManager/conf.d/00-noid-mac-randomization.conf <<'MAC_EOF'
# NoID Privacy — Ethernet MAC randomization + WoL ownership (Module 23)
#
# MAC randomization: stable persistent randomized MAC for new ethernet
# connections. NetworkManager derives this hash from the connection's stable ID
# (whose default includes the connection UUID) and a host-specific secret.
# Persistent across reboots, DHCP leases work, hardware vendor OUI is hidden.
#
# Wake-on-LAN: NetworkManager.conf requires the numeric magic value 32768 for
# the `ignore` flag (nmcli accepts the nick). It disables NM management; it
# does not itself disable WoL. Module 27's systemd.link
# `WakeOnLan=off` sets the device-wide default before NetworkManager starts.
# Users who need WoL can explicitly override it per connection:
#   sudo nmcli connection modify "<name>" 802-3-ethernet.wake-on-lan magic
#
# WiFi connection MAC: Fedora vendor default (stable-ssid) is NOT overridden:
#   /usr/lib/NetworkManager/conf.d/22-wifi-mac-addr.conf
# WiFi scan MAC: explicitly randomized below (NM 1.46+ already defaults to
# yes; the explicit value keeps the image policy auditable).

# Randomize MAC during WiFi scans (before connecting to any network).
# Reduces pre-association probe linkability to the hardware MAC; it is one
# privacy layer, not a claim that all WiFi scanning becomes untrackable.
[device]
wifi.scan-rand-mac-address=yes

[connection.noid-ethernet-mac]
match-device=type:ethernet
ethernet.cloned-mac-address=stable
# Preserve M27's device policy unless a connection explicitly opts in.
# 32768 = NM_SETTING_WIRED_WAKE_ON_LAN_IGNORE in NM.conf.
ethernet.wake-on-lan=32768
MAC_EOF

chmod 644 /etc/NetworkManager/conf.d/00-noid-mac-randomization.conf
chown root:root /etc/NetworkManager/conf.d/00-noid-mac-randomization.conf

if command -v restorecon >/dev/null 2>&1; then
    restorecon -F /etc/NetworkManager/conf.d/00-noid-mac-randomization.conf
fi

log "  [OK] MAC randomization + NetworkManager WoL ownership config written"

# ====================================================================
# STEP 2: IPv6 per-connection defaults
# ====================================================================
# IPv6 method policy (applied via the 40- dispatcher — NM 1.54+ rejects it
# as a conf.d connection-default):
#   Physical interfaces (ethernet + wifi): ipv6.method=disabled — NM keeps
#   physical-profile IPv6 configuration disabled. Modules 02 and 07 supply
#   independent kernel layers; address ordering and DNS behavior are separate.
#   Non-physical profiles (including wireguard, VPN, dummy and bridge types)
#   are deliberately not mutated by this dispatcher. Their reviewed provider
#   or administrator configuration owns tunnel/address policy.
# The conf file below carries only latent ip6-privacy + addr-gen-mode
# safeguards for a reviewed all-layer custom IPv6 fork. They are not a
# supported re-enable recipe: changing only ipv6.method cannot satisfy the
# M02/M03/M07/M23/XDP physical-link contract. Loads after 00-
# (alphabetical); orthogonal to M03's 03-vpn-zone.conf (connection.zone).

log "STEP 2: writing /etc/NetworkManager/conf.d/01-noid-ipv6.conf"

cat > /etc/NetworkManager/conf.d/01-noid-ipv6.conf <<'IPV6_EOF'
# NoID Privacy — IPv6 per-connection defaults (Module 23)
#
# Physical interfaces: latent ip6-privacy + addr-gen-mode safeguards for a
# reviewed all-layer custom IPv6 fork. Setting only ipv6.method=auto is not
# supported: Modules 02/03/07/23 and the physical XDP peer/flow contract must
# be changed and tested together. If that complete fork enables IPv6, these
# settings avoid a MAC-derived stable interface identifier.
#
#   ip6-privacy=2      RFC 4941/8981 — generate AND prefer temporary addresses
#   addr-gen-mode=1   RFC 7217 stable-privacy — opaque interface ID per-network,
#                     not MAC-derived, different per SSID/LAN. NM.conf requires
#                     the numeric enum value; nmcli also accepts the nick.
#
# Physical-link IPv6 is disabled at two independent configuration layers:
#   1. sysctl 99-wan-ipv6-off.conf (Module 07 — kernel level)
#   2. NM dispatcher 40-noid-connection-defaults (Module 23 — first-up of
#      each new ethernet/wifi connection sets ipv6.method=disabled)
# WireGuard/VPN address policy is separately owned by its tunnel configuration;
# M23 makes no NM-layer change to those non-physical profiles.
#
# Why ipv6.method= is NOT here anymore:
# NetworkManager 1.54+ rejects ipv6.method as a connection-default value in
# NM.conf [connection-*] sections. The setting was logged as "unknown key"
# and silently ignored — TunnelVision-style protection (CVE-2024-3661) was
# missing because ipv4.ignore-auto-routes also failed to apply. The fix:
# applied per-connection via NM dispatcher (40-noid-connection-defaults)
# which uses nmcli — that mechanism IS accepted by NM 1.54+.

[connection-ethernet-ipv6]
match-device=type:ethernet
ipv6.ip6-privacy=2
ipv6.addr-gen-mode=1

[connection-wifi-ipv6]
match-device=type:wifi
ipv6.ip6-privacy=2
ipv6.addr-gen-mode=1
IPV6_EOF

chmod 644 /etc/NetworkManager/conf.d/01-noid-ipv6.conf
chown root:root /etc/NetworkManager/conf.d/01-noid-ipv6.conf

if command -v restorecon >/dev/null 2>&1; then
    restorecon -F /etc/NetworkManager/conf.d/01-noid-ipv6.conf
fi

log "  [OK] IPv6 per-connection defaults written (ethernet+wifi latent address safeguards; non-physical profiles untouched)"

# ====================================================================
# STEP 2b: connection-wide defaults (LLDP, per-link DNS transport, hostname)
# ====================================================================
# Rationale lives in the deployed DEFAULTS_EOF heredoc (LLDP belt+
# suspenders, NM 1.54+ full connection.lldp property name, hostname-mode
# + dhcp-send-hostname). Loads after 00- + 01- (alphabetical).

log "STEP 2b: writing /etc/NetworkManager/conf.d/02-noid-connection-defaults.conf"

cat > /etc/NetworkManager/conf.d/02-noid-connection-defaults.conf <<'DEFAULTS_EOF'
# NoID Privacy — connection-wide defaults (Module 23)
#
# LLDP receive listener off: NetworkManager's current property controls
# reception and publication of learned neighbor data, not transmission of
# local IEEE 802.1AB advertisements. The global default is already disabled;
# pinning it minimizes passive topology collection and listener attack surface
# and survives future upstream default changes. Other LLDP-capable daemons are
# outside this property and must be governed by their own service policy.
#
# NM 1.54+ requires the full "connection.lldp" property name in
# [connection] section — the bare "lldp" was silently rejected with a
# warning and not applied. Now uses connection.lldp=0.
#
# `hostname-mode=none` prevents NetworkManager from replacing the local
# transient hostname from DHCP/reverse-DNS input. It does not govern outgoing
# DHCP option 12 or DHCPv6 option 39. Those are separate maintained settings:
# the current ternary ipv4/ipv6.dhcp-send-hostname values are pinned to 0
# below, and the dispatcher writes the same properties to physical profiles.
#
# VPN/private and other non-physical per-link DNS with an unset
# `connection.dns-over-tls` property defaults to `opportunistic`: DoT is tried
# first, while an unavailable or interfered TLS path may fall back to DNS/53.
# systemd-resolved cannot authenticate a resolver in opportunistic mode, so
# this is best-effort transport encryption rather than a strict or MITM-
# resistant boundary. An explicit profile value wins. Ethernet/Wi-Fi instead
# use NetworkManager's maintained device-matched connection defaults to start
# at strict DoT before any DHCP-provided resolver can be queried in plaintext.
# M05's selector and this dispatcher's physical-only branch then replace DHCP
# DNS with named Quad9 and apply the selected strict/opportunistic/off mode.
# The global and physical image default remains strict.
#
# NetworkManager otherwise enables MPTCP endpoint handling for an unset
# profile when the kernel MPTCP sysctl permits it. For IPv4 it then deliberately
# loosens strict rp_filter=1 to mode 2. Numeric 1 is the maintained NM.conf form
# of `disabled`; explicit per-profile MPTCP flags remain an administrator opt-in
# whose routing requirements conflict with this image's strict rp_filter policy.
#
# NoID Privacy DEFAULT install already mitigated: master.ks sets
# `network --hostname=noid-privacy` — already a generic, non-personally-
# identifying hostname. The residual disclosure is the shared product label
# ("noid-privacy" requesting DHCP), not a unique device or user identifier.
#
# Custom-hostname users (e.g., `hostnamectl set-hostname my-laptop`)
# should consider reverting to generic via `sudo hostnamectl set-hostname noid-host`
# OR explicitly set their preferred privacy-safe alternative.

[main]
hostname-mode=none

[connection-noid-ethernet-dns]
match-device=type:ethernet
connection.dns-over-tls=2

[connection-noid-wifi-dns]
match-device=type:wifi
connection.dns-over-tls=2

[connection]
connection.lldp=0
connection.mptcp-flags=1
# Generic fallback only. NetworkManager searches matching connection-* sections
# before [connection], so the two physical-device sections above win during
# first activation while unset non-physical/VPN/private profiles inherit
# downgrade-capable best-effort DoT. Numeric 1 = opportunistic in NM.conf.
connection.dns-over-tls=1
ipv4.dhcp-send-hostname=0
# NetworkManager 1.56's maintained fallback is 200 ms. Keep the same native
# value explicit so no profile with an unset property silently disables IPv4
# duplicate-address detection. M04 deliberately installs no ARP packet hook,
# allowing the corresponding RFC 5227 probes/conflict packets to pass.
ipv4.dad-timeout=200
# Numeric 2 is required in NetworkManager.conf (nmcli's "disabled" alias is
# not accepted here). Prevent only RFC 3927 IPv4-link-local fallback and its
# probes/announcements when DHCP is absent; ordinary IPv4 DAD above remains
# enabled, and WAN DHCP remains enabled by ipv4.method=auto profiles.
ipv4.link-local=2
ipv6.dhcp-send-hostname=0
DEFAULTS_EOF

chmod 644 /etc/NetworkManager/conf.d/02-noid-connection-defaults.conf
chown root:root /etc/NetworkManager/conf.d/02-noid-connection-defaults.conf

if command -v restorecon >/dev/null 2>&1; then
    restorecon -F /etc/NetworkManager/conf.d/02-noid-connection-defaults.conf
fi

log "  [OK] strict-rp_filter-compatible MPTCP and scoped DoT defaults written"

# ====================================================================
# STEP 2c: NM dispatcher — apply NoID Privacy hardening per-connection
# ====================================================================
# NM 1.54+ rejects ipv4/ipv6.ignore-auto-dns/routes, ipv6.method and
# connection.zone as [connection-*] conf.d defaults (logged + silently
# ignored) — this dispatcher applies them through the maintained per-profile
# nmcli path at first up (state-file-gated, idempotent).
#
# TunnelVision (CVE-2024-3661) strategy: ipv4.ignore-auto-routes=false +
# post-DHCP route-cleanup. =true would also drop the DHCP default route —
# no internet pre-VPN, blocking VPN setup. The cleanup keeps default +
# connected-subnet (proto=kernel) and deletes every other proto-dhcp route,
# covering non-RFC1918 Option-121 targets. NetworkManager's awaited activation
# and native DHCPv4-renewal/reapply dispatcher events replace timing guesses:
# cleanup runs immediately after a synchronous mutation and again for the
# resulting event. An unavoidable event-handling interval remains covered by
# L1 block-lan-out (M03), L2 drop zone (M03), L3 this cleanup and, when one is
# active, the VPN client's own killswitch.

log "STEP 2c: writing NM dispatcher /etc/NetworkManager/dispatcher.d/40-noid-connection-defaults"

mkdir -p /etc/NetworkManager/dispatcher.d/pre-up.d
cat > /etc/NetworkManager/dispatcher.d/40-noid-connection-defaults <<'DISPATCHER_EOF'
#!/bin/bash
# NoID Privacy Workstation 44 — NM dispatcher
# Apply NoID Privacy hardening defaults to ethernet/wifi connections.
# NM 1.54+ rejects these in NM.conf [connection-*] — must be set per-conn.
#
# Two enforcement layers:
#   Layer 1: physical firewalld-zone enforcement (always-runs, idempotent)
#   Layer 2: First-up profile hardening (STATE_FILE-guarded per installed
#     connection; Live runtime-only state is reasserted after every up/DHCP)
#     ipv4.dhcp-client-id=mac, ipv6.method=disabled, ignore-auto-dns,
#     ipv6.privacy=2, mdns/llmnr/lldp off, then user scope after the checked
#     runtime reapply. GNOME/nmcli-created physical profiles may otherwise
#     default to system-wide permissions and expose a pre-login attack
#     surface. Specific DHCP-route cleanup also runs on every dhcp4-change
#     and reapply event; it is never one-shot.

set -u
export LC_ALL=C
INTERFACE="${1:-}"
ACTION="${2:-}"
CMDLINE_FILE=/proc/cmdline
if [ "${NOID_TEST_MODE:-0}" = 1 ]; then
    CMDLINE_FILE=${NOID_TEST_CMDLINE_FILE:?NOID_TEST_CMDLINE_FILE is required in test mode}
fi

case "$ACTION" in
    pre-up|up|dhcp4-change|reapply) ;;
    *) exit 0 ;;
esac

if [[ ! "$INTERFACE" =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || \
   [ "$INTERFACE" = . ] || [ "$INTERFACE" = .. ]; then
    logger -t noid-nm-defaults \
        "FAIL: invalid interface supplied for dispatcher action $ACTION"
    exit 1
fi

# Live-mode dual-path hardening.
# The previous implementation unconditionally skipped Live Mode → the Live VM had ZERO
# NM hardening (DNS DHCP-pushed instead of Quad9, ipv6.method not disabled).
# That's not acceptable for Live-User-Test phase.
#
# Root: F44 Anaconda's auto-generated connection lives in /run/NetworkManager/
# system-connections/ (ephemeral, tmpfs). nmcli connection modify tries to
# migrate-to-persist into /etc/.../<uuid>.nmconnection which fails with
# "Read-only file system" (NM internal error for /run-anchored profiles).
#
# Fix: detect Live-Mode and use RUNTIME-only hardening path:
#   - resolvectl dns/dnsovertls <iface> <Quad9...> (M05-selected per-link
#     transport; default `yes` is strict DoT, while explicit opportunistic/no
#     modes retain their documented downgrade/fallback behavior)
#   - resolvectl domain <iface> ~.          (catchall for all queries)
#   - sysctl net.ipv6.conf.<iface>.disable_ipv6=1  (IPv6 off, kernel-level)
# That fits the Live-Mode tmpfs constraint AND gives us a hardened test env.
# Persistent system gets the standard nmcli connection modify path. Match the
# complete kernel-command-line token; a value merely containing that text is
# not evidence that this is a Live image.
LIVE_MODE=0
if ! KERNEL_CMDLINE=$(<"$CMDLINE_FILE") || [ -z "$KERNEL_CMDLINE" ]; then
    logger -t noid-nm-defaults "FAIL: cannot read kernel command line"
    exit 1
fi
case " $KERNEL_CMDLINE " in
    *" rd.live.image "*) LIVE_MODE=1 ;;
esac

UUID="${CONNECTION_UUID:-}"
if [[ ! "$UUID" =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ ]]; then
    logger -t noid-nm-defaults \
        "FAIL: missing or malformed connection UUID for dispatcher action $ACTION"
    exit 1
fi

LOCK_DIR="${NOID_NM_DEFAULTS_LOCK_DIR:-/run/lock/noid-nm-defaults}"
if ! install -d -m 0700 "$LOCK_DIR"; then
    logger -t noid-nm-defaults "FAIL: cannot create dispatcher lock directory"
    exit 1
fi
exec 9>"$LOCK_DIR/$UUID.lock"
if ! flock --exclusive 9; then
    logger -t noid-nm-defaults "FAIL: cannot serialize connection event"
    exit 1
fi

# Detect connection type (used by both Layer 1 + Layer 2). Interface names are
# mutable administrator input, so prefixes such as wg/tun/veth are never type
# authority: only NetworkManager's native connection.type selects the physical
# policy. NetworkManager's dispatcher contract guarantees that an event already
# queued will run even when a later event made it obsolete. VPN clients can
# therefore remove a short-lived profile before its queued `up` event reaches
# this script.
#
# Treat that race as stale only when a successful full enumeration proves the
# event UUID is gone. A failed enumeration or a still-present UUID with a
# failed type lookup remains a hard failure; otherwise a real NetworkManager
# outage could silently bypass physical-link policy.
TYPE=""
if ! TYPE=$(nmcli -e no -g connection.type connection show "$UUID" \
        2>/dev/null) || [ -z "$TYPE" ]; then
    if ! PROFILE_UUIDS=$(nmcli -t -e no -f UUID connection show 2>/dev/null); then
        logger -t noid-nm-defaults \
            "FAIL: cannot enumerate profiles after connection-type lookup failed"
        exit 1
    fi
    if ! grep -Fqx -- "$UUID" <<< "$PROFILE_UUIDS"; then
        logger -t noid-nm-defaults \
            "stale: skipping obsolete queued $ACTION event for a removed connection"
        exit 0
    fi
    logger -t noid-nm-defaults \
        "FAIL: cannot determine type for an existing connection"
    exit 1
fi

# Link-local is a valid NetworkManager fallback when a physical segment has no
# DHCP server. DNS, DHCP client-ID and automatic-route properties are not valid
# or meaningful for that method, so discover it before constructing a mutation.
IPV4_METHOD=""
case "$TYPE" in
    802-3-ethernet|802-11-wireless|ethernet|wifi)
        if ! IPV4_METHOD=$(nmcli -g ipv4.method connection show "$UUID" \
                2>/dev/null) || [ -z "$IPV4_METHOD" ]; then
            logger -t noid-nm-defaults \
                "FAIL: cannot determine physical connection IPv4 method"
            exit 1
        fi
        if [ "${NOID_TEST_MODE:-0}" = 1 ]; then
            DNS_DOT_MODE="${NOID_TEST_DNS_DOT_MODE:-yes}"
        elif ! DNS_DOT_MODE=$(
                /usr/local/sbin/noid-dns-mode --physical-value 2>/dev/null
            ); then
            DNS_DOT_MODE=""
        fi
        if [[ ! "$DNS_DOT_MODE" =~ ^(no|opportunistic|yes)$ ]]; then
            logger -t noid-nm-defaults \
                "FAIL: cannot determine the selected physical DNS transport"
            exit 1
        fi
        ;;
esac

remove_specific_dhcp_routes() {
    local routes route token previous route_has_interface
    local -a route_args delete_args
    if ! routes=$(ip -4 route show dev "$INTERFACE" proto dhcp 2>/dev/null); then
        logger -t noid-nm-defaults \
            "FAIL: cannot enumerate physical-link DHCP routes"
        return 1
    fi
    while IFS= read -r route; do
        [ -n "$route" ] || continue
        case "$route" in
            default*) continue ;;
        esac
        # `ip route show` emits an argv-like route specification, but may omit
        # the interface used as its filter and add display-only nexthop state
        # such as `linkdown` or `dead`. Those state words are rejected by
        # `ip route del`. Rebuild a quoted argv without the display-only words
        # and bind the deletion to the interface that was enumerated. Preserve
        # either word when it is the value following `dev` (interface names are
        # administrator-controlled).
        read -r -a route_args <<< "$route"
        delete_args=()
        previous=""
        route_has_interface=0
        for token in "${route_args[@]}"; do
            if { [ "$token" = linkdown ] || [ "$token" = dead ]; } && \
               [ "$previous" != dev ]; then
                continue
            fi
            delete_args+=("$token")
            if [ "$previous" = dev ] && [ "$token" = "$INTERFACE" ]; then
                route_has_interface=1
            fi
            previous="$token"
        done
        if [ "$route_has_interface" != 1 ]; then
            delete_args+=(dev "$INTERFACE")
        fi
        if ! ip -4 route del "${delete_args[@]}"; then
            logger -t noid-nm-defaults \
                "FAIL: could not delete a non-default DHCP route"
            return 1
        fi
    done <<< "$routes"
}

# ============================================================================
# Layer 1: active firewalld enforcement — always-runs, idempotent
# ============================================================================
# This layer is only the always-on runtime firewalld boundary. User scoping is
# non-reapplicable profile metadata and is therefore written later, after the
# active profile's reapply postcondition; the account-completion helper covers
# profiles first activated before the installed user exists.
case "$TYPE" in
    802-3-ethernet|802-11-wireless|ethernet|wifi)
        # Every physical profile must remain in the inbound-DROP zone. Relying
        # only on DefaultZone or a one-shot firstboot assignment is insufficient:
        # a saved/imported profile can carry connection.zone=home/public and
        # re-open host services on a later reconnect.
        if ! firewall-cmd --zone=drop --change-interface="$INTERFACE" \
            >/dev/null 2>&1; then
            logger -t noid-nm-defaults \
                "FAIL: runtime firewalld drop-zone enforcement failed"
            exit 1
        fi
        ;;
esac

# DHCP renewals or profile reapplication can reintroduce Option-121 routes long
# after the first-up marker exists. Strip every non-default proto-dhcp route on
# each native event. The separate block-lan-out covers RFC1918 destinations
# even while this route-specific TunnelVision boundary is reconciling. A Live
# dhcp4-change continues into the complete runtime hardening path because DHCP
# can also replace its ephemeral per-link DNS state. Reapply exits here to
# avoid recursively causing another reapply.
case "$ACTION" in
dhcp4-change|reapply)
    case "$TYPE" in
        802-3-ethernet|802-11-wireless|ethernet|wifi)
            remove_specific_dhcp_routes || exit 1
            logger -t noid-nm-defaults \
                "DHCP route policy re-enforced for a physical connection event"
            ;;
    esac
    if [ "$LIVE_MODE" != 1 ] || [ "$ACTION" = reapply ]; then
        exit 0
    fi
    logger -t noid-nm-defaults \
        "Live DHCP renewal: reasserting complete runtime physical-link policy"
    ;;
esac

# Pre-up is intentionally limited to the always-on runtime zone layer.
# Installed profile rewrites run only after activation. Live runtime hardening
# additionally runs after DHCP renewal, when DHCP-supplied link DNS may have
# replaced the prior D-Bus-only values.
if [ "$ACTION" != up ] \
   && { [ "$LIVE_MODE" != 1 ] || [ "$ACTION" != dhcp4-change ]; }; then
    exit 0
fi

# ============================================================================
# Layer 2: First-up hardening — STATE_FILE-guarded one-shot per connection
# ============================================================================
STATE_DIR="${NOID_NM_DEFAULTS_STATE_DIR:-/var/lib/NetworkManager/noid-defaults}"
STATE_FILE="$STATE_DIR/$UUID"
# A Live profile and all its mutations live only in /run/D-Bus state. A
# persistent marker would outlive that state across reconnect and falsely skip
# the next hardening pass. Installed profiles retain the one-shot optimization
# because their successful mutation is durable.
if [ "$LIVE_MODE" != 1 ] && [ -f "$STATE_FILE" ]; then
    exit 0
fi

if ! install -d -m 0700 "$STATE_DIR"; then
    logger -t noid-nm-defaults \
        "FAIL: cannot create private dispatcher state directory"
    exit 1
fi

publish_state() {
    local tmp
    if ! tmp=$(mktemp "$STATE_DIR/.${UUID}.XXXXXX"); then
        logger -t noid-nm-defaults \
            "FAIL: cannot create dispatcher state tempfile"
        return 1
    fi
    if ! chmod 0600 "$tmp" || ! mv -Tf "$tmp" "$STATE_FILE"; then
        rm -f "$tmp"
        logger -t noid-nm-defaults \
            "FAIL: cannot publish dispatcher state marker"
        return 1
    fi
}

persist_profile_metadata() {
    local current_zone current_perm expected_perm passwd_db user_name
    local name uid home shell marker now marker_stat
    local marker_uid marker_mtime marker_type marker_extra marker_age

    if ! current_zone=$(nmcli -g connection.zone connection show "$UUID" \
            2>/dev/null); then
        logger -t noid-nm-defaults "FAIL: cannot read physical connection zone"
        return 1
    fi
    if [ "$current_zone" != "drop" ] && \
       ! nmcli connection modify "$UUID" connection.zone drop >/dev/null 2>&1; then
        logger -t noid-nm-defaults "FAIL: could not persist physical drop zone"
        return 1
    fi

    # Scope only after runtime reapply and only to the same completed account
    # selected by the dedicated scoper. Enumerate first so an NSS failure cannot
    # be mistaken for "user pending" and sealed by the one-shot marker.
    if ! passwd_db=$(getent passwd 2>/dev/null); then
        logger -t noid-nm-defaults "FAIL: cannot enumerate local accounts"
        return 1
    fi
    if ! now=$(date +%s) || [[ ! "$now" =~ ^[0-9]+$ ]]; then
        logger -t noid-nm-defaults \
            "FAIL: cannot obtain a valid account-completion time"
        return 1
    fi
    user_name=""
    while IFS=: read -r name _ uid _ _ home shell; do
        [ "$uid" -ge 1000 ] 2>/dev/null || continue
        [ "$uid" -lt 60000 ] || continue
        case "$shell" in */false|*/nologin) continue ;; esac
        marker="$home/.config/gnome-initial-setup-done"
        if ! marker_stat=$(stat -c '%u:%Y:%F' -- "$marker" 2>/dev/null); then
            continue
        fi
        IFS=: read -r marker_uid marker_mtime marker_type marker_extra \
            <<< "$marker_stat"
        [ -z "$marker_extra" ] || continue
        case "$marker_type" in
            "regular file"|"regular empty file") ;;
            *) continue ;;
        esac
        [[ "$marker_uid" =~ ^[0-9]+$ ]] && \
            [[ "$marker_mtime" =~ ^[0-9]+$ ]] || continue
        [ "$marker_uid" = "$uid" ] || continue
        [ "$now" -ge "$marker_mtime" ] || continue
        marker_age=$((now - marker_mtime))
        [ "$marker_age" -ge 60 ] || continue
        user_name="$name"
        break
    done <<< "$passwd_db"
    if [ -z "$user_name" ]; then
        logger -t noid-nm-defaults \
            "pending: completed local account not ready; account-completion timer will scope physical profiles"
        return 0
    fi
    if ! current_perm=$(nmcli -e no -g connection.permissions connection show "$UUID" \
            2>/dev/null); then
        logger -t noid-nm-defaults \
            "FAIL: cannot read physical connection permissions"
        return 1
    fi
    expected_perm="user:$user_name"
    case "$current_perm" in
        "")
            ;;
        "$expected_perm")
            return 0
            ;;
        user:liveuser)
            if grep -q '^liveuser:' <<< "$passwd_db"; then
                logger -t noid-nm-defaults \
                    "FAIL: liveuser still exists; preserving its explicit physical-profile permission"
                return 1
            fi
            logger -t noid-nm-defaults \
                "permissions: adopting stale removed-liveuser physical-profile scope"
            ;;
        *)
            logger -t noid-nm-defaults \
                "FAIL: refusing to replace foreign physical-profile permissions"
            return 1
            ;;
    esac
    if [ "$current_perm" != "$expected_perm" ]; then
        if ! nmcli connection modify "$UUID" connection.permissions \
                "$expected_perm" >/dev/null 2>&1; then
            logger -t noid-nm-defaults \
                "FAIL: physical-profile permissions rewrite failed"
            return 1
        fi
        logger -t noid-nm-defaults \
            "permissions: scoped a physical profile to the local user"
    fi
    if ! current_perm=$(nmcli -e no -g connection.permissions connection show "$UUID" \
            2>/dev/null) || [ "$current_perm" != "$expected_perm" ]; then
        logger -t noid-nm-defaults \
            "FAIL: exact physical-profile permission postcondition failed"
        return 1
    fi
}

queue_account_scope_reconciliation() {
    local scope_flag=/var/lib/noid-privacy/nm-physical-profiles-scoped.flag
    local scope_pending=/var/lib/noid-privacy/nm-physical-profiles-scope-pending.flag
    local scope_lock=/run/lock/noid-nm-scope-physical-profiles.lock
    local systemctl_bin=systemctl
    local pending_tmp=""
    local queue_rc=0

    if [ "${NOID_TEST_MODE:-0}" = 1 ]; then
        scope_flag=${NOID_TEST_NM_SCOPE_FLAG:?NOID_TEST_NM_SCOPE_FLAG is required for account-scope tests}
        scope_pending=${NOID_TEST_NM_SCOPE_PENDING:?NOID_TEST_NM_SCOPE_PENDING is required for account-scope tests}
        scope_lock=${NOID_TEST_NM_SCOPE_LOCK:?NOID_TEST_NM_SCOPE_LOCK is required for account-scope tests}
        systemctl_bin=${NOID_TEST_SYSTEMCTL_BIN:?NOID_TEST_SYSTEMCTL_BIN is required for account-scope tests}
    fi

    # connection.permissions cannot be reapplied to an already-active profile.
    # Serialize the pending marker, completion invalidation and timer restart
    # with the helper's short start/finalization sections. The helper never
    # holds this lock across NetworkManager mutations, so an awaited dispatcher
    # event cannot deadlock its controlled reactivation. A pending marker also
    # tells an already-running helper that its enumeration became stale and
    # forbids it from publishing obsolete all-profile evidence.
    if ! install -d -m 0755 "${scope_flag%/*}" \
       || ! exec 8>"$scope_lock" \
       || ! flock --exclusive 8; then
        logger -t noid-nm-defaults \
            "FAIL: cannot enter account-scope reconciliation queue"
        return 1
    fi
    if ! pending_tmp=$(mktemp "${scope_pending}.XXXXXX") \
       || ! chmod 0600 "$pending_tmp" \
       || ! mv -Tf "$pending_tmp" "$scope_pending"; then
        rm -f -- "$pending_tmp"
        logger -t noid-nm-defaults \
            "FAIL: cannot publish account-scope pending evidence"
        queue_rc=1
    elif ! rm -f -- "$scope_flag"; then
        logger -t noid-nm-defaults \
            "FAIL: cannot invalidate account-scope completion evidence"
        queue_rc=1
    elif ! "$systemctl_bin" --no-block restart \
            noid-nm-scope-physical-profiles.timer; then
        logger -t noid-nm-defaults \
            "FAIL: cannot queue active-profile permission reconciliation"
        queue_rc=1
    fi
    if ! flock --unlock 8; then
        logger -t noid-nm-defaults \
            "FAIL: cannot release account-scope reconciliation queue"
        queue_rc=1
    fi
    exec 8>&-
    [ "$queue_rc" -eq 0 ] || return 1
    logger -t noid-nm-defaults \
        "pending: queued active-profile permission reconciliation"
}

case "$TYPE" in
    802-3-ethernet|802-11-wireless|ethernet|wifi)
        if [ "$LIVE_MODE" = "1" ]; then
            # ----- Live-Mode runtime-only path -----
            # Handle Anaconda's connection in
            # /run/NetworkManager/system-connections/. A normal persistent
            # `connection modify` tries to migrate it into the read-only image
            # overlay. NetworkManager's maintained `--temporary` form instead
            # updates its in-memory profile and runtime backing only. Active
            # enforcement remains the resolver/kernel operations below.
            #
            # 1. DNS via resolvectl. #server-name supplies the intended TLS
            # identity/SNI. The exact M05 selection above is applied to this
            # physical link; VPN/private connection types never enter this
            # branch.
            if ! resolvectl dns "$INTERFACE" \
                9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net \
                2620:fe::fe#dns.quad9.net 2620:fe::9#dns.quad9.net \
                >/dev/null; then
                logger -t noid-nm-defaults \
                    "WARN: live per-link DNS update failed; global Quad9 policy remains"
            fi
            if ! resolvectl domain "$INTERFACE" '~.' >/dev/null; then
                logger -t noid-nm-defaults \
                    "WARN: live per-link routing-domain update failed"
            fi
            if ! resolvectl dnsovertls "$INTERFACE" "$DNS_DOT_MODE" >/dev/null; then
                logger -t noid-nm-defaults \
                    "WARN: live per-link DoT update failed; global Quad9 policy remains"
            fi
            # 2. IPv6 off via sysctl (kernel-level, no NM-API needed)
            if ! sysctl -w "net.ipv6.conf.${INTERFACE}.disable_ipv6=1" >/dev/null; then
                logger -t noid-nm-defaults "FAIL: live IPv6 disable failed"
                exit 1
            fi
            # 3. Flush ipv6 routes/addrs that may have been pushed by DHCPv6/RA
            if ! ip -6 addr flush dev "$INTERFACE" || \
               ! ip -6 route flush dev "$INTERFACE"; then
                logger -t noid-nm-defaults "FAIL: live IPv6 state flush failed"
                exit 1
            fi
            # 4. Mirror the enforced policy into NetworkManager's temporary
            # profile view only after final activation. The active boundary is
            # already enforced above through resolvectl, sysctl and exact
            # address/route cleanup. Do not reapply this complete profile:
            # Fedora 44 NetworkManager reproduced canceling and restarting the
            # just-acquired DHCP transaction after `device reapply`, which
            # queued another dhcp4-change, gateway/XDP refresh and chrony
            # offline/online cycle. The temporary profile is consumed on the
            # next native activation without writing Live-media state to disk.
            #
            # The first activation is already using its pre-mutation applied
            # connection. With the kernel IPv6 gate closed above, leaving that
            # applied method at `auto` makes NetworkManager retry IPv6LL every
            # two seconds and grow the journal indefinitely. Read the profile
            # method before changing its temporary backing. If it was not
            # already disabled, use NetworkManager's maintained `device modify`
            # operation for this one property only. Live Fedora 44 runtime
            # verification showed that this exact reapply leaves the acquired
            # DHCP lease/default route intact; reapplying the complete changed
            # profile remains forbidden.
            if [ "$ACTION" = up ]; then
                if ! LIVE_PROFILE_IPV6_METHOD=$(
                        nmcli -g ipv6.method connection show "$UUID" 2>/dev/null
                    ) || [ -z "$LIVE_PROFILE_IPV6_METHOD" ]; then
                    logger -t noid-nm-defaults \
                        "FAIL: cannot read the Live physical-profile IPv6 method"
                    exit 1
                fi
                if [ "$IPV4_METHOD" = "link-local" ]; then
                    modify_args=(
                        ipv4.method auto
                        ipv4.link-local disabled
                        ipv4.ignore-auto-dns yes
                        ipv4.ignore-auto-routes no
                        ipv4.dns "9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net"
                        ipv6.method disabled
                        ipv6.ignore-auto-dns yes
                        ipv6.ignore-auto-routes yes
                        connection.mdns 0
                        connection.llmnr 0
                        connection.dns-over-tls "$DNS_DOT_MODE"
                        connection.lldp disable
                        ipv4.dhcp-send-hostname false
                        ipv6.dhcp-send-hostname false
                    )
                else
                    modify_args=(
                        ipv4.link-local disabled
                        ipv4.ignore-auto-dns yes
                        ipv4.ignore-auto-routes no
                        ipv4.dns "9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net"
                        ipv6.method disabled
                        ipv6.ignore-auto-dns yes
                        ipv6.ignore-auto-routes yes
                        connection.mdns 0
                        connection.llmnr 0
                        connection.dns-over-tls "$DNS_DOT_MODE"
                        connection.lldp disable
                        ipv4.dhcp-send-hostname false
                        ipv6.dhcp-send-hostname false
                    )
                fi
                if ! nmcli connection modify --temporary uuid "$UUID" \
                        "${modify_args[@]}"; then
                    logger -t noid-nm-defaults \
                        "FAIL: live runtime profile mirror failed"
                    exit 1
                fi
                if [ "$LIVE_PROFILE_IPV6_METHOD" != disabled ] \
                   && ! nmcli device modify "$INTERFACE" \
                        ipv6.method disabled >/dev/null 2>&1; then
                    logger -t noid-nm-defaults \
                        "FAIL: live active IPv6 method reconciliation failed"
                    exit 1
                fi

                # Postcheck the current active route state after the final up
                # event. Native later reapply/dhcp4-change events also recheck
                # this boundary without a fixed-delay assumption.
                remove_specific_dhcp_routes || exit 1
            else
                logger -t noid-nm-defaults \
                    "Live DHCP security policy restored without recursive profile mutation"
            fi
            logger -t noid-nm-defaults \
                "Live-Mode runtime hardening reasserted on a physical connection"
        else
            # ----- Persistent system path: nmcli connection modify -----
            # ipv4.dhcp-client-id=mac aligns with the active cloned MAC:
            # same identity space, no independent machine-id-derived DHCP
            # identifier, and MAC-based lease binding remains functional.
            # NetworkManager 1.56's internal DHCP client already falls back to
            # `mac` when this is unset; pin it in the profile so the contract is
            # explicit and does not depend on plugin/default drift.
            modify_args=(
                ipv6.ignore-auto-dns yes
                ipv6.ignore-auto-routes yes
                ipv6.method disabled
                ipv6.ip6-privacy 2
                ipv6.addr-gen-mode stable-privacy
                connection.lldp disable
                connection.mdns 0
                connection.llmnr 0
                connection.dns-over-tls "$DNS_DOT_MODE"
                ipv4.dhcp-send-hostname false
                ipv6.dhcp-send-hostname false
            )
            if [ "$IPV4_METHOD" != "link-local" ]; then
                modify_args=(
                    ipv4.link-local disabled
                    ipv4.ignore-auto-dns yes
                    ipv4.ignore-auto-routes no
                    ipv4.dhcp-client-id mac
                    "${modify_args[@]}"
                )
            else
                # A literal link-local method cannot be combined with disabled
                # IPv4LL. Convert it to ordinary DHCP with IPv4LL disabled in
                # the same atomic profile mutation: WAN can recover if a DHCP
                # server appears, but no 169.254/16 fallback is announced.
                modify_args=(
                    ipv4.method auto
                    ipv4.link-local disabled
                    ipv4.ignore-auto-dns yes
                    ipv4.ignore-auto-routes no
                    ipv4.dhcp-client-id mac
                    "${modify_args[@]}"
                )
            fi
            if ! nmcli connection modify "$UUID" \
                    "${modify_args[@]}" >/dev/null 2>&1; then
                logger -t noid-nm-defaults \
                    "FAIL: persistent physical-profile mutation failed"
                exit 1
            fi

            if ! nmcli device reapply "$INTERFACE" >/dev/null 2>&1; then
                logger -t noid-nm-defaults \
                    "FAIL: could not reapply hardened physical-profile properties"
                exit 1
            fi

            # Same post-DHCP route-cleanup as the live path. `device reapply`
            # returns after NetworkManager's D-Bus operation, so inspect its
            # current result immediately. NetworkManager also queues a native
            # `reapply` event; that and every later `dhcp4-change` recheck the
            # policy independently of timer assumptions.
            remove_specific_dhcp_routes || exit 1

            # Metadata that NM cannot reapply to an already active connection
            # is deliberately persisted only after the runtime postconditions.
            # The asynchronous scoper reconciles any saved/active permission
            # mismatch independently; this dispatcher never waits for helper
            # completion while holding its per-UUID lock.
            persist_profile_metadata || exit 1
            queue_account_scope_reconciliation || exit 1
            publish_state || exit 1
            logger -t noid-nm-defaults \
                "Persistent hardening applied to a physical connection"
        fi
        ;;
esac

exit 0
DISPATCHER_EOF

chmod 700 /etc/NetworkManager/dispatcher.d/40-noid-connection-defaults
chown root:root /etc/NetworkManager/dispatcher.d/40-noid-connection-defaults
ln -sfn ../40-noid-connection-defaults \
    /etc/NetworkManager/dispatcher.d/pre-up.d/40-noid-connection-defaults

if command -v restorecon >/dev/null 2>&1; then
    restorecon -F \
        /etc/NetworkManager/dispatcher.d/40-noid-connection-defaults \
        /etc/NetworkManager/dispatcher.d/pre-up.d \
        /etc/NetworkManager/dispatcher.d/pre-up.d/40-noid-connection-defaults
fi

log "  [OK] NM dispatcher 40-noid-connection-defaults installed"

# ====================================================================
# STEP 2d: account-completion physical-profile scoper
# ====================================================================
# On an installed system, retry the one-time account-scoping step after
# Anaconda/GNOME Initial Setup.
# The network boundary is already active before this point; this helper removes
# system-wide/pre-login ownership and reconciles saved versus active profile
# state when that non-reapplicable metadata changed. Live media have no later
# persistent pre-login account/profile ownership to reconcile, so both units
# use systemd's native kernel-command-line condition and never trigger the
# otherwise necessary active-profile reactivation there.
log "STEP 2d: writing the account-completion physical-profile scoper"

cat > /usr/local/sbin/noid-nm-scope-physical-profiles <<'NM_SCOPE_EOF'
#!/bin/bash
set -euo pipefail
export LC_ALL=C

STATE_DIR="${NOID_NM_SCOPE_STATE_DIR:-/var/lib/noid-privacy}"
FLAG="${NOID_NM_SCOPE_FLAG:-$STATE_DIR/nm-physical-profiles-scoped.flag}"
PENDING="${NOID_NM_SCOPE_PENDING:-$STATE_DIR/nm-physical-profiles-scope-pending.flag}"
LOCK="${NOID_NM_SCOPE_LOCK:-/run/lock/noid-nm-scope-physical-profiles.lock}"
NMCLI="${NOID_NMCLI_BIN:-nmcli}"
SYSTEMCTL="${NOID_SYSTEMCTL_BIN:-systemctl}"

exec 9>"$LOCK"
flock --exclusive 9
# A queued dispatcher publishes PENDING before invalidating FLAG. Therefore
# PENDING wins after an interruption that left both files present. Consume it
# at the start of this enumeration; any later dispatcher recreates it and the
# finalization gate below rejects this now-stale pass.
if [ -e "$PENDING" ]; then
    if ! rm -f -- "$PENDING" "$FLAG"; then
        logger -t noid-nm-scope \
            "FAIL: cannot consume account-scope pending evidence"
        exit 1
    fi
elif [ -e "$FLAG" ]; then
    exit 0
fi
if ! flock --unlock 9; then
    logger -t noid-nm-scope "FAIL: cannot release account-scope start gate"
    exit 1
fi

user_name=""
if ! passwd_db=$(getent passwd); then
    logger -t noid-nm-scope "FAIL: cannot enumerate local accounts"
    exit 1
fi
if ! now=$(date +%s) || [[ ! "$now" =~ ^[0-9]+$ ]]; then
    logger -t noid-nm-scope "FAIL: cannot obtain a valid account-completion time"
    exit 1
fi
while IFS=: read -r name _ uid _ _ home shell; do
    [ "$uid" -ge 1000 ] 2>/dev/null || continue
    [ "$uid" -lt 60000 ] || continue
    case "$shell" in */false|*/nologin) continue ;; esac
    marker="$home/.config/gnome-initial-setup-done"
    # Capture owner, mtime and inode type in one checked lstat snapshot. A
    # disappearing or concurrently replaced marker is pending evidence, never
    # an empty timestamp that arithmetic could misread as an ancient marker.
    if ! marker_stat=$(stat -c '%u:%Y:%F' -- "$marker" 2>/dev/null); then
        continue
    fi
    IFS=: read -r marker_uid marker_mtime marker_type marker_extra \
        <<< "$marker_stat"
    [ -z "$marker_extra" ] || continue
    case "$marker_type" in
        "regular file"|"regular empty file") ;;
        *) continue ;;
    esac
    [[ "$marker_uid" =~ ^[0-9]+$ ]] && \
        [[ "$marker_mtime" =~ ^[0-9]+$ ]] || continue
    [ "$marker_uid" = "$uid" ] || continue
    [ "$now" -ge "$marker_mtime" ] || continue
    marker_age=$((now - marker_mtime))
    [ "$marker_age" -ge 60 ] || continue
    user_name="$name"
    break
done <<< "$passwd_db"

if [ -z "$user_name" ]; then
    logger -t noid-nm-scope "pending: completed local account not ready"
    exit 0
fi

if ! profile_list=$("$NMCLI" -t -f UUID,TYPE connection show); then
    logger -t noid-nm-scope "FAIL: cannot enumerate NetworkManager profiles"
    exit 1
fi
if ! active_profiles=$("$NMCLI" -t -f UUID,DEVICE connection show --active); then
    logger -t noid-nm-scope "FAIL: cannot enumerate active NetworkManager profiles"
    exit 1
fi
while IFS=: read -r uuid type; do
    [ -n "$uuid" ] || continue
    case "$type" in
        802-3-ethernet|802-11-wireless|ethernet|wifi) ;;
        *) continue ;;
    esac
    # nmcli's default output escaping turns `user:NAME` into `user\:NAME`.
    # Disable escaping so the postcondition below compares the real value.
    if ! current=$("$NMCLI" -e no -g connection.permissions \
            connection show "$uuid"); then
        logger -t noid-nm-scope \
            "FAIL: cannot read physical-profile permissions"
        exit 1
    fi
    expected="user:$user_name"
    case "$current" in
        "") ;;
        "$expected") ;;
        user:liveuser)
            if grep -q '^liveuser:' <<< "$passwd_db"; then
                logger -t noid-nm-scope \
                    "FAIL: liveuser still exists; preserving its explicit physical-profile permission"
                exit 1
            fi
            logger -t noid-nm-scope \
                "adopting a stale removed-liveuser physical-profile permission"
            ;;
        *)
            logger -t noid-nm-scope \
                "FAIL: refusing to replace foreign physical-profile permissions"
            exit 1
            ;;
    esac
    if [ "$current" != "$expected" ]; then
        if ! "$NMCLI" connection modify "$uuid" connection.permissions \
                "$expected" >/dev/null; then
            logger -t noid-nm-scope \
                "FAIL: cannot persist physical-profile permissions"
            exit 1
        fi
    fi
    if ! current=$("$NMCLI" -e no -g connection.permissions \
            connection show "$uuid"); then
        logger -t noid-nm-scope \
            "FAIL: cannot verify physical-profile permissions"
        exit 1
    fi
    if [ "$current" != "$expected" ]; then
        logger -t noid-nm-scope \
            "FAIL: a physical profile is not exactly user-scoped"
        exit 1
    fi

    # connection.permissions is persisted metadata and NetworkManager refuses
    # to reapply it to an already-active connection. Leaving the saved and
    # active settings divergent makes every later `nmcli device reapply`
    # (including GUI-driven edits) fail until the next reboot. First try the
    # cheap postcondition. If NM reports the known metadata mismatch, activate
    # the same UUID on the same device and require a final successful reapply.
    # This is idempotent and also repairs a prior run interrupted after the
    # profile write but before active-state reconciliation.
    active_device=$(awk -F: -v wanted="$uuid" \
        '$1 == wanted && $2 != "" { print $2; exit }' <<< "$active_profiles")
    if [ -n "$active_device" ] && \
       ! "$NMCLI" device reapply "$active_device" >/dev/null 2>&1; then
        if ! "$NMCLI" connection up uuid "$uuid" ifname "$active_device" \
                >/dev/null 2>&1; then
            logger -t noid-nm-scope \
                "FAIL: cannot reactivate a scoped physical profile"
            exit 1
        fi
        if ! "$NMCLI" device reapply "$active_device" >/dev/null 2>&1; then
            logger -t noid-nm-scope \
                "FAIL: a scoped active physical profile remains non-reapplicable"
            exit 1
        fi
        logger -t noid-nm-scope \
            "reactivated a scoped physical profile"
    fi
done <<< "$profile_list"

# Re-enter the short queue/finalization gate only after every NetworkManager
# mutation and controlled reactivation is complete. If a dispatcher queued
# work during this pass, its PENDING marker proves our enumeration is stale:
# leave the timer armed and refuse to publish completion. A dispatcher that is
# waiting for this lock will invalidate any completion we publish before it
# restarts the timer, closing the inverse ordering as well.
if ! flock --exclusive 9; then
    logger -t noid-nm-scope "FAIL: cannot enter account-scope finalization gate"
    exit 1
fi
if [ -e "$PENDING" ]; then
    logger -t noid-nm-scope \
        "pending: a physical profile changed during account scoping"
    exit 0
fi

# /var/lib/noid-privacy is the shared status/stamp directory. Several
# deliberately non-secret 0644 files below it are read by unprivileged status
# tools (notably noid-network). Keep the directory searchable/readable while
# protecting this helper's own one-shot flag with mode 0600 below. Fully
# prepare its temporary inode before stopping the retry timer, so an allocation
# or permission failure leaves the existing retry path untouched.
if ! install -d -m 0755 "$STATE_DIR"; then
    logger -t noid-nm-scope "FAIL: cannot create account-scope state directory"
    exit 1
fi
if ! tmp=$(mktemp "$STATE_DIR/.nm-scoped.XXXXXX"); then
    logger -t noid-nm-scope "FAIL: cannot create account-scope state tempfile"
    exit 1
fi
if ! chmod 0600 "$tmp"; then
    rm -f -- "$tmp"
    logger -t noid-nm-scope "FAIL: cannot protect account-scope state tempfile"
    exit 1
fi

# ConditionPathExists= on the timer is evaluated when the timer starts, not
# before each later elapse. Stop the already-active retry timer while holding
# the finalization gate and immediately before the atomic completion publish;
# otherwise it wakes every two minutes for the rest of this boot merely to
# condition-skip the service and pollute the journal. Any stop/publish failure
# leaves FLAG absent and explicitly re-arms the timer.
if ! "$SYSTEMCTL" stop noid-nm-scope-physical-profiles.timer; then
    rm -f -- "$tmp"
    "$SYSTEMCTL" start noid-nm-scope-physical-profiles.timer >/dev/null 2>&1 \
        || logger -t noid-nm-scope \
            "FAIL: cannot re-arm account-scope retry timer after stop failure"
    logger -t noid-nm-scope "FAIL: cannot stop completed account-scope retry timer"
    exit 1
fi
if ! mv -Tf "$tmp" "$FLAG"; then
    rm -f -- "$tmp"
    "$SYSTEMCTL" start noid-nm-scope-physical-profiles.timer >/dev/null 2>&1 \
        || logger -t noid-nm-scope \
            "FAIL: cannot re-arm account-scope retry timer after publish failure"
    logger -t noid-nm-scope "FAIL: cannot publish account-scope completion flag"
    exit 1
fi
logger -t noid-nm-scope "physical profiles scoped after account completion"
NM_SCOPE_EOF
chmod 0755 /usr/local/sbin/noid-nm-scope-physical-profiles
chown root:root /usr/local/sbin/noid-nm-scope-physical-profiles

cat > /etc/systemd/system/noid-nm-scope-physical-profiles.service <<'NM_SCOPE_SERVICE_EOF'
[Unit]
Description=Scope physical NetworkManager profiles after local account completion
After=NetworkManager.service
Requires=NetworkManager.service
ConditionPathExists=!/var/lib/noid-privacy/nm-physical-profiles-scoped.flag
ConditionKernelCommandLine=!rd.live.image

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/noid-nm-scope-physical-profiles
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/noid-privacy /run/lock
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes

# No [Install] section: this unit is triggered exclusively by the paired
# .timer (Unit= reference); only the timer is systemctl-enabled.
NM_SCOPE_SERVICE_EOF

cat > /etc/systemd/system/noid-nm-scope-physical-profiles.timer <<'NM_SCOPE_TIMER_EOF'
[Unit]
Description=Retry physical NetworkManager profile scoping until account completion
ConditionPathExists=!/var/lib/noid-privacy/nm-physical-profiles-scoped.flag
ConditionKernelCommandLine=!rd.live.image

[Timer]
OnBootSec=2min
OnUnitActiveSec=2min
AccuracySec=15s
Unit=noid-nm-scope-physical-profiles.service

[Install]
WantedBy=timers.target
NM_SCOPE_TIMER_EOF

chmod 0644 /etc/systemd/system/noid-nm-scope-physical-profiles.service \
    /etc/systemd/system/noid-nm-scope-physical-profiles.timer
chown root:root /etc/systemd/system/noid-nm-scope-physical-profiles.service \
    /etc/systemd/system/noid-nm-scope-physical-profiles.timer
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F /usr/local/sbin/noid-nm-scope-physical-profiles \
        /etc/systemd/system/noid-nm-scope-physical-profiles.service \
        /etc/systemd/system/noid-nm-scope-physical-profiles.timer
fi
systemctl enable noid-nm-scope-physical-profiles.timer

# ====================================================================
# STEP 2e: NM connection-event targeted ingress-policy repair dispatcher
# ====================================================================
# NM may set per-interface rp_filter=2 (LOOSE) at connection activation,
# overriding the M02 wildcard *.rp_filter=1 after systemd-sysctl has applied
# the boot policy. systemd also replays matching wildcard rules as interfaces
# appear, but later NetworkManager/wpa_supplicant writes can still drift.
# Fedora's wpa_supplicant contains a source-proven disassociation path that can
# clear both the IPv4 and IPv6 drop_unicast_in_l2_multicast nodes plus the IPv4
# drop_gratuitous_arp node; live M02 verification observed the IPv6 WLAN node
# at 0 while its source contract requires 1.
# Repair only those four exact interface procfs knobs plus the load-bearing
# global rp_filter node. A full `sysctl --system` here would repeatedly
# overwrite unrelated runtime subsystem state and serialize later dispatcher
# work. Full rationale + refs live in the deployed SYSCTL_REAPPLY_EOF heredoc.
log "STEP 2e: writing /etc/NetworkManager/dispatcher.d/99-noid-sysctl-reapply"

cat > /etc/NetworkManager/dispatcher.d/99-noid-sysctl-reapply <<'SYSCTL_REAPPLY_EOF'
#!/bin/bash
# NoID Privacy — targeted ingress-policy repair on NM events (Module 23)
#
# NetworkManager auto-sets per-interface
# net.ipv4.conf.<iface>.rp_filter=2 (LOOSE) at connection activation,
# overriding NoID Privacy's wildcard *.rp_filter=1 from /etc/sysctl.d/99-hardening.conf
# after the boot policy is applied. Per kernel-doc:
# effective = MAX(all, interface) → MAX(1, 2) = 2 LOOSE.
#
# Fedora 44's CONFIG_HS20-enabled wpa_supplicant 2.11 calls its frame-filter
# backend with flags=0 from wpa_supplicant_mark_disassoc(). The nl80211 backend
# maps zero to IPv4 drop_gratuitous_arp and both IPv4/IPv6
# drop_unicast_in_l2_multicast nodes, while an ordinary non-HS20 association
# does not set those flags again. This is the exact source-capable drift path;
# live full-policy verification additionally observed the IPv6 WLAN node at 0.
# NetworkManager emits an awaited pre-up before exposing a fully activated
# interface and a dhcp4-change after a WiFi-roam DHCP restart.
#
# Fix: repair only the load-bearing global rp_filter node and those four exact
# per-interface nodes after events that can create, renew or reapply an
# IPv4-capable interface. Re-reading every sysctl drop-in on each network event
# is unrelated work, can overwrite runtime subsystem state, and serializes
# later NetworkManager dispatcher actions.
#
# Refs: docs.kernel.org/networking/ip-sysctl.html,
# networkmanager.dev NetworkManager-dispatcher(8), and Fedora 44
# wpa_supplicant-2.11-9.fc44 src/drivers/driver_nl80211.c +
# wpa_supplicant/events.c.

set -euo pipefail

INTERFACE="${1:-}"
ACTION="${2:-}"
IPV4_CONF_ROOT=/proc/sys/net/ipv4/conf
IPV6_CONF_ROOT=/proc/sys/net/ipv6/conf
if [ "${NOID_TEST_MODE:-0}" = 1 ]; then
    [ -n "${NOID_TEST_IPV4_CONF_ROOT:-}" ] \
        && [ -n "${NOID_TEST_IPV6_CONF_ROOT:-}" ] || exit 2
    IPV4_CONF_ROOT=$NOID_TEST_IPV4_CONF_ROOT
    IPV6_CONF_ROOT=$NOID_TEST_IPV6_CONF_ROOT
fi

repair_one() {
    local path="$1" allow_missing="$2"
    if [ ! -e "$path" ]; then
        [ "$allow_missing" -eq 1 ]
        return
    fi
    [ "$(<"$path")" = 1 ] || printf '1\n' > "$path"
    [ "$(<"$path")" = 1 ] || return 1
}

case "$ACTION" in
    pre-up|up|vpn-pre-up|vpn-up|dhcp4-change|reapply)
        if [[ ! "$INTERFACE" =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || \
           [ "$INTERFACE" = . ] || [ "$INTERFACE" = .. ]; then
            logger -t noid-sysctl-reapply \
                "FAIL: invalid interface supplied for ingress-policy repair"
            exit 1
        fi
        if ! repair_one "$IPV4_CONF_ROOT/all/rp_filter" 0 \
           || ! repair_one "$IPV4_CONF_ROOT/$INTERFACE/rp_filter" 1 \
           || ! repair_one "$IPV4_CONF_ROOT/$INTERFACE/drop_gratuitous_arp" 1 \
           || ! repair_one "$IPV4_CONF_ROOT/$INTERFACE/drop_unicast_in_l2_multicast" 1 \
           || ! repair_one "$IPV6_CONF_ROOT/$INTERFACE/drop_unicast_in_l2_multicast" 1; then
            logger -t noid-sysctl-reapply \
                "FAIL: targeted ingress-policy repair failed after $ACTION"
            exit 1
        fi
        ;;
esac

exit 0
SYSCTL_REAPPLY_EOF

chmod 700 /etc/NetworkManager/dispatcher.d/99-noid-sysctl-reapply
chown root:root /etc/NetworkManager/dispatcher.d/99-noid-sysctl-reapply
ln -sfn ../99-noid-sysctl-reapply \
    /etc/NetworkManager/dispatcher.d/pre-up.d/99-noid-sysctl-reapply

if command -v restorecon >/dev/null 2>&1; then
    restorecon -F \
        /etc/NetworkManager/dispatcher.d/99-noid-sysctl-reapply \
        /etc/NetworkManager/dispatcher.d/pre-up.d \
        /etc/NetworkManager/dispatcher.d/pre-up.d/99-noid-sysctl-reapply
fi

log "  [OK] NM dispatcher 99-noid-sysctl-reapply installed"

# ====================================================================
# STEP 3: Verification
# ====================================================================
log "STEP 3: verification"

verify_ok=0
verify_fail=0

verify_owned_regular() {
    local path="$1" expected_mode="$2"
    [ -f "$path" ] && [ ! -L "$path" ] && \
        [ "$(stat -Lc '%u:%g:%a:%h' "$path" 2>/dev/null)" = \
            "0:0:${expected_mode}:1" ]
}

has_exact_once() {
    local needle="$1" path="$2" count
    count=$(grep -Fxc -- "$needle" "$path" 2>/dev/null || true)
    [ "$count" = 1 ]
}

# 3.1 — MAC randomization config has exact file metadata
if verify_owned_regular \
        /etc/NetworkManager/conf.d/00-noid-mac-randomization.conf 644; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] MAC randomization config metadata verified"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] MAC randomization config missing or metadata unsafe"
fi

# 3.2 — Key MAC content present (ethernet MAC + WiFi scan MAC + numeric NM
# WoL-ignore flag; NM.conf does not accept nmcli's enum nick here)
if grep -qFx 'ethernet.cloned-mac-address=stable' \
        /etc/NetworkManager/conf.d/00-noid-mac-randomization.conf 2>/dev/null && \
   grep -qFx 'wifi.scan-rand-mac-address=yes' \
        /etc/NetworkManager/conf.d/00-noid-mac-randomization.conf 2>/dev/null && \
   grep -qFx 'ethernet.wake-on-lan=32768' \
        /etc/NetworkManager/conf.d/00-noid-mac-randomization.conf 2>/dev/null; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] cloned-mac-address=stable + scan-rand-mac + NM WoL=32768 (ignore) present"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] MAC/WoL config incomplete in 00-noid-mac-randomization.conf"
fi

# 3.2b — exact connection-wide defaults. NM 1.54+ requires the full
# `connection.lldp` prefix; every load-bearing assignment must occur once.
if verify_owned_regular \
        /etc/NetworkManager/conf.d/02-noid-connection-defaults.conf 644 && \
   has_exact_once '[main]' \
        /etc/NetworkManager/conf.d/02-noid-connection-defaults.conf && \
   has_exact_once 'hostname-mode=none' \
        /etc/NetworkManager/conf.d/02-noid-connection-defaults.conf && \
   has_exact_once '[connection]' \
        /etc/NetworkManager/conf.d/02-noid-connection-defaults.conf && \
   has_exact_once '[connection-noid-ethernet-dns]' \
        /etc/NetworkManager/conf.d/02-noid-connection-defaults.conf && \
   has_exact_once 'match-device=type:ethernet' \
        /etc/NetworkManager/conf.d/02-noid-connection-defaults.conf && \
   has_exact_once '[connection-noid-wifi-dns]' \
        /etc/NetworkManager/conf.d/02-noid-connection-defaults.conf && \
   has_exact_once 'match-device=type:wifi' \
        /etc/NetworkManager/conf.d/02-noid-connection-defaults.conf && \
   [ "$(grep -cFx 'connection.dns-over-tls=2' \
        /etc/NetworkManager/conf.d/02-noid-connection-defaults.conf)" -eq 2 ] && \
   has_exact_once 'connection.lldp=0' \
        /etc/NetworkManager/conf.d/02-noid-connection-defaults.conf && \
   has_exact_once 'connection.mptcp-flags=1' \
        /etc/NetworkManager/conf.d/02-noid-connection-defaults.conf && \
   has_exact_once 'connection.dns-over-tls=1' \
        /etc/NetworkManager/conf.d/02-noid-connection-defaults.conf && \
   has_exact_once 'ipv4.dhcp-send-hostname=0' \
        /etc/NetworkManager/conf.d/02-noid-connection-defaults.conf && \
   has_exact_once 'ipv4.dad-timeout=200' \
        /etc/NetworkManager/conf.d/02-noid-connection-defaults.conf && \
   has_exact_once 'ipv4.link-local=2' \
        /etc/NetworkManager/conf.d/02-noid-connection-defaults.conf && \
   has_exact_once 'ipv6.dhcp-send-hostname=0' \
        /etc/NetworkManager/conf.d/02-noid-connection-defaults.conf; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] MPTCP-off, physical Strict DoT and generic opportunistic defaults are exact"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] 02-noid-connection-defaults.conf metadata or scoped defaults are wrong"
fi

# 3.3 — IPv6 per-connection defaults have exact file metadata
if verify_owned_regular /etc/NetworkManager/conf.d/01-noid-ipv6.conf 644; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] IPv6 per-connection defaults metadata verified"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] 01-noid-ipv6.conf missing or metadata unsafe"
fi

# 3.4 — IPv6 sections correct (NM 1.54+ rejects ipv6.method= as a
# connection-default; only ethernet+wifi sections remain in 01-noid-ipv6.conf
# for ip6-privacy + addr-gen-mode defense-in-depth defaults. Non-physical
# profiles stay outside this module's mutation boundary).
if grep -qE '^\[connection-ethernet-ipv6\]' /etc/NetworkManager/conf.d/01-noid-ipv6.conf 2>/dev/null && \
   grep -qE '^\[connection-wifi-ipv6\]' /etc/NetworkManager/conf.d/01-noid-ipv6.conf 2>/dev/null; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] 2 physical connection-type sections present; non-physical types untouched"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] 01-noid-ipv6.conf missing connection-ethernet-ipv6 or connection-wifi-ipv6 section"
fi

# 3.4c — NM dispatcher 40-noid-connection-defaults present + executable
# (handles ipv4.ignore-auto-routes/dns + ipv6.ignore-auto-routes/dns +
#  ipv6.method=disabled + connection.lldp/mdns/llmnr per-connection at first up.
#  NM 1.54+ rejects these as defaults in NM.conf — the dispatcher is M23's
#  maintained per-profile path.)
if verify_owned_regular \
        /etc/NetworkManager/dispatcher.d/40-noid-connection-defaults 700 && \
   bash -n /etc/NetworkManager/dispatcher.d/40-noid-connection-defaults; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] NM dispatcher 40 metadata + syntax verified"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] NM dispatcher 40 missing, unsafe or syntactically invalid"
fi

# 3.4d — awaited pre-up registration is the exact relative symlink
if [ -L /etc/NetworkManager/dispatcher.d/pre-up.d/40-noid-connection-defaults ] && \
   [ "$(readlink /etc/NetworkManager/dispatcher.d/pre-up.d/40-noid-connection-defaults)" = \
        ../40-noid-connection-defaults ]; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] NM dispatcher 40 pre-up registration is exact"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] NM dispatcher 40 pre-up registration missing or redirected"
fi

# 3.4e — account-completion profile scoper payload
if verify_owned_regular /usr/local/sbin/noid-nm-scope-physical-profiles 755 && \
   bash -n /usr/local/sbin/noid-nm-scope-physical-profiles && \
   grep -qF 'connection.permissions' \
        /usr/local/sbin/noid-nm-scope-physical-profiles && \
   grep -qF 'nm-physical-profiles-scoped.flag' \
        /usr/local/sbin/noid-nm-scope-physical-profiles; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] account-completion physical-profile scoper verified"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] account-completion physical-profile scoper missing or malformed"
fi

# 3.4f — paired static service carries the exact helper entrypoint
if verify_owned_regular \
        /etc/systemd/system/noid-nm-scope-physical-profiles.service 644 && \
   grep -qFx 'ExecStart=/usr/local/sbin/noid-nm-scope-physical-profiles' \
        /etc/systemd/system/noid-nm-scope-physical-profiles.service && \
   grep -qFx 'ConditionPathExists=!/var/lib/noid-privacy/nm-physical-profiles-scoped.flag' \
        /etc/systemd/system/noid-nm-scope-physical-profiles.service && \
   grep -qFx 'ConditionKernelCommandLine=!rd.live.image' \
        /etc/systemd/system/noid-nm-scope-physical-profiles.service; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] account-completion physical-profile service verified"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] account-completion physical-profile service missing or malformed"
fi

# 3.4g — retry timer exists, targets the exact service and is enabled
if verify_owned_regular \
        /etc/systemd/system/noid-nm-scope-physical-profiles.timer 644 && \
   grep -qFx 'Unit=noid-nm-scope-physical-profiles.service' \
        /etc/systemd/system/noid-nm-scope-physical-profiles.timer && \
   grep -qFx 'ConditionKernelCommandLine=!rd.live.image' \
        /etc/systemd/system/noid-nm-scope-physical-profiles.timer && \
   systemctl is-enabled --quiet noid-nm-scope-physical-profiles.timer; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] account-completion physical-profile retry timer verified + enabled"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] account-completion physical-profile retry timer missing, malformed or disabled"
fi

# 3.4h — systemd parses the paired scoper units as installed. Limit the exit
# status to errors in the two specified M23 units: recursively loaded Fedora
# dependency units are outside this module's ownership and may be deliberately
# absent from the minimal compose smoke root. ExecStart validation remains part
# of each specified service's parser result.
if systemd-analyze verify --recursive-errors=no \
        /etc/systemd/system/noid-nm-scope-physical-profiles.service \
        /etc/systemd/system/noid-nm-scope-physical-profiles.timer \
        >/dev/null 2>&1; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] account-completion scoper units pass systemd parser verification"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] account-completion scoper unit parser verification failed"
fi

# 3.4b — Defense-in-depth ip6-privacy + addr-gen-mode defaults
if grep -qFx 'ipv6.ip6-privacy=2' /etc/NetworkManager/conf.d/01-noid-ipv6.conf 2>/dev/null && \
   grep -qFx 'ipv6.addr-gen-mode=1' /etc/NetworkManager/conf.d/01-noid-ipv6.conf 2>/dev/null; then
    # ensure both appear at least twice (once for ethernet + once for wifi)
    # `2>/dev/null || true` avoids the `|| echo 0` capture trap: grep -c on
    # a missing file exits 1 AND prints "0", so `|| echo 0` yields "0\n0"
    # and breaks the arithmetic below.
    priv_count=$(grep -cE '^ipv6.ip6-privacy=2' /etc/NetworkManager/conf.d/01-noid-ipv6.conf 2>/dev/null || true)
    agm_count=$(grep -cFx 'ipv6.addr-gen-mode=1' /etc/NetworkManager/conf.d/01-noid-ipv6.conf 2>/dev/null || true)
    priv_count=${priv_count:-0}
    agm_count=${agm_count:-0}
    if [ "$priv_count" -ge 2 ] && [ "$agm_count" -ge 2 ]; then
        verify_ok=$((verify_ok + 1))
        log "  [OK] ip6-privacy=2 + addr-gen-mode=1 (stable-privacy) on ethernet+wifi"
    else
        verify_fail=$((verify_fail + 1))
        log "  [FAIL] ip6-privacy/addr-gen-mode not set on both ethernet+wifi (priv=${priv_count} agm=${agm_count})"
    fi
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] ip6-privacy=2 or addr-gen-mode=1 (stable-privacy) missing"
fi

# 3.5 — Fedora WiFi vendor default exists with the exact dependency value
if [ -f /usr/lib/NetworkManager/conf.d/22-wifi-mac-addr.conf ] && \
   [ ! -L /usr/lib/NetworkManager/conf.d/22-wifi-mac-addr.conf ] && \
   grep -qFx 'wifi.cloned-mac-address=stable-ssid' \
        /usr/lib/NetworkManager/conf.d/22-wifi-mac-addr.conf; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] Fedora WiFi stable-SSID MAC default verified"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] Fedora WiFi stable-SSID MAC default missing or changed"
fi

# 3.6 — Cross-check: Module 05 privacy config still present
if [ -f /etc/NetworkManager/conf.d/99-privacy.conf ]; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] Module 05 NM privacy config present"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] Module 05 NM privacy config missing"
fi

# 3.7 — Cross-check: Module 03 VPN zone config still present
if [ -f /etc/NetworkManager/conf.d/03-vpn-zone.conf ]; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] Module 03 VPN zone config present"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] Module 03 VPN zone config missing"
fi

# 3.8 — Cross-check: Module 07 gai.conf present (getaddrinfo destination order)
if [ -f /etc/gai.conf ] && \
   grep -qFx 'precedence ::ffff:0:0/96 100' /etc/gai.conf 2>/dev/null; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] Module 07 gai.conf deliberate IPv4 destination precedence present"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] Module 07 gai.conf missing or precedence wrong"
fi

# 3.9 — dispatcher 99-noid-sysctl-reapply deployed (targeted ingress policy)
if verify_owned_regular \
        /etc/NetworkManager/dispatcher.d/99-noid-sysctl-reapply 700 && \
   bash -n /etc/NetworkManager/dispatcher.d/99-noid-sysctl-reapply && \
   grep -qF 'IPV4_CONF_ROOT=/proc/sys/net/ipv4/conf' /etc/NetworkManager/dispatcher.d/99-noid-sysctl-reapply 2>/dev/null && \
   grep -qF 'IPV6_CONF_ROOT=/proc/sys/net/ipv6/conf' /etc/NetworkManager/dispatcher.d/99-noid-sysctl-reapply 2>/dev/null && \
   grep -qF 'drop_gratuitous_arp' /etc/NetworkManager/dispatcher.d/99-noid-sysctl-reapply 2>/dev/null && \
   grep -qF 'repair_one "$IPV6_CONF_ROOT/$INTERFACE/drop_unicast_in_l2_multicast" 1' /etc/NetworkManager/dispatcher.d/99-noid-sysctl-reapply 2>/dev/null && \
   ! grep -qF 'sysctl --system' /etc/NetworkManager/dispatcher.d/99-noid-sysctl-reapply 2>/dev/null && \
   grep -qE '^case "\$ACTION"' /etc/NetworkManager/dispatcher.d/99-noid-sysctl-reapply 2>/dev/null; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] dispatcher 99-noid-sysctl-reapply executable + targeted ingress repair present"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] 99-noid-sysctl-reapply missing or malformed (targeted ingress repair)"
fi

# 3.9b — awaited pre-up registration for the ingress-policy repair
if [ -L /etc/NetworkManager/dispatcher.d/pre-up.d/99-noid-sysctl-reapply ] && \
   [ "$(readlink /etc/NetworkManager/dispatcher.d/pre-up.d/99-noid-sysctl-reapply)" = \
        ../99-noid-sysctl-reapply ]; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] dispatcher 99 pre-up registration is exact"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] dispatcher 99 pre-up registration missing or redirected"
fi

log "  Verification: ${verify_ok} OK, ${verify_fail} FAIL"
if [ "$verify_fail" -gt 0 ]; then
    log "=== Module 23 FAILED (${verify_fail} verification failures) ==="
    exit 1
fi

log "=== Module 23 complete ==="
%end

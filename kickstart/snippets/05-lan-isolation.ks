# ============================================================================
# Module 05 — LAN Isolation (Layer 5-7)
# Status: LOCKED 2026-08-15 (v6.48) — bind privileged LAN test overrides to stripped production environments.
#
# Covers:
#   - systemd-resolved hardening (Quad9 global DNS + DoT + DNSSEC + LLMNR/mDNS off)
#   - NetworkManager hardening (hostname-mode=none + connectivity probe off;
#     per-connection mdns/llmnr/ignore-auto-dns live in the Module 23
#     dispatcher — NM 1.54+ rejects them as [connection-defaults])
#   - gvfs wsdd/dns-sd discovery disabled through the maintained GVfs
#     GSettings enums and system dconf locks (no RPM-owned file rewrite)
#   - Package exclusion: precise per package (NOT all-samba, NOT all-avahi)
#       * avahi (daemon+libavahi-core) → KEPT  (spice-webdavd + hplip-libs +
#         libsane-hpaio hard-dep; daemon masked)
#       * avahi-autoipd|tools|ui|ui-tools → EXCLUDED
#       * nss-mdns                     → EXCLUDED
#       * samba (server)               → EXCLUDED
#       * samba-client (CLI)           → EXCLUDED
#       * samba-common (config/data; no daemon) → KEPT  (libsmbclient →
#         gnome-control-center hard-pin chain; orphan configs removed)
#       * cups-browsed | cups-pdf      → EXCLUDED
#       * cups (libs)                  → KEPT  (GTK Save-as-PDF works
#         without the daemon; daemon triple-masked)
#   - Service masking: avahi-daemon + wsdd + cups (triple: path/service/socket)
#   - Escape-hatch CLI: noid-lan-allow (per-IP exceptions recommended,
#     global toggle legacy)
#
# Decisions:
#   [Q1] DNSSEC=allow-downgrade remains the private-zone/VPN compatibility
#        mode. Global and physical Quad9 use strict authenticated DoT by
#        default; NetworkManager's generic non-physical fallback is
#        opportunistic so VPN/private resolvers can try DoT without being
#        forced onto port 853. DNS/53 fallback and active downgrade remain
#        possible, and an explicit profile value wins. Physical Ethernet/Wi-Fi
#        instead starts strict. The global/physical opportunistic selector is
#        a separate explicit compatibility choice.
#   [Q2] Native GVfs GSettings `disabled` values suppress network:/// WSDD
#        and DNS-SD enumeration; distro dconf defaults/locks survive upgrades
#        without modifying `/usr/share/gvfs/mounts` package files.
#   [Q3] NM per-connection overrides live in the Module 23 dispatcher
#        (NM 1.54+ rejects mdns/llmnr keys as connection-defaults)
#   [Q4] Both maintained discovery schemas are disabled and locked.
#   [Q5] Package exclusion precise per package (see Covers)
#   [Q6] cups daemon masked (triple), libs kept
#   [Q7] Drop-in under /etc/systemd/resolved.conf.d/ (not main-file patch)
#   [Q8] FallbackDNS=Quad9-only (NOT mixed-provider) — privacy >
#        reliability; a Cloudflare entry would be the leak path in exactly
#        the regression case FallbackDNS exists for
#
# Design directive: the hardened state is the baseline — no Mode A/B
# toggle, LAN drop-all always active. noid-lan-allow is a single-purpose
# escape-hatch (one directly attached IPv4 peer such as a printer/NAS), NOT
# a mode toggle: service discovery (mDNS/SMB/WSD) stays excluded + masked
# either way.
#
# Constraint note (keep when editing): noid-lan-allow manages HOST ingress
# on block-lan-out ONLY — libvirt lives permanently in the companion
# block-lan-out-vms policy; adding libvirt to block-lan-out trips the F44
# validator (HOST + regular zones cannot mix in one ingress list).
#
# Cross-reference: M02 IGMP sysctls · M03 block-lan-out always-active ·
# M06 VPN per-link ~. DNS catchall · M23 per-connection dispatcher ·
# M26 package-set consolidation.
# ============================================================================

# ============================================================================
# %packages — exclusions
# ============================================================================
# dnf resolver will honor these excludes unless a strong hard dep pulls them
# back in. wsdd cannot be excluded here because gvfs requires /usr/bin/wsdd
# at file level. The maintained GVfs discovery schemas below disable WSDD
# enumeration; service masks remain an independent defense-in-depth layer.
%packages --exclude-weakdeps
# avahi (main package = daemon binary + libavahi-core.so.7). Direct hard-deps:
#   - spice-webdavd → avahi (package-level, for VM-clipboard daemon)
#   - hplip-libs + libsane-hpaio → libavahi-core.so.7 (HP printer/scanner)
# Cannot exclude without dropping HP support + spice-webdavd (4 packages).
# avahi-libs (separate package, libavahi-client.so.3 + libavahi-common.so.3)
# is the actual GNOME 50 dep chain — pulled by gvfs/cups/pipewire/geoclue2/
# tinysparql/pipewire-pulseaudio. That stays regardless of `avahi` decision.
# Daemon neutralized via systemctl mask in STEP 4 (no listener, no traffic).
-avahi-autoipd
-avahi-tools
-avahi-ui
-avahi-ui-tools
-nss-mdns
# samba: gnome-shell → gnome-control-center (50.1) hard-deps on libsmbclient.so.0
# at runtime (used by /usr/libexec/gnome-control-center-print-renderer +
# -search-provider executables). libsmbclient version-pin-requires samba-common
# = 2:4.24.1-1.fc44 → both forced into image. Exclude server-side (-samba) and
# CLI client (-samba-client). samba-common is config-only (no libs, no daemon,
# no service, no listener); orphan config files removed in STEP 5a.
-samba
-samba-client
-cups-browsed
-cups-pdf
%end

# ============================================================================
# %post — configuration, tmpfiles, service masking
# ============================================================================
%post --erroronfail --log=/var/log/ks-05-lan-isolation.log
set -euo pipefail

log() { echo "[noid-05-lan]" "$@"; }
log "=== Module 05 post-install: LAN isolation (L5-L7) ==="

# ====================================================================
# STEP 1: systemd-resolved drop-in — Quad9 global + DoT + DNSSEC
# ====================================================================
# Drop-in under /etc/systemd/resolved.conf.d/ survives package updates.
# DNS= global primary: Quad9 IPv4+IPv6. The #dns.quad9.net suffix supplies the
#   intended TLS server name/SNI for strict certificate authentication.
# FallbackDNS= safety net: per systemd-resolved(8) it activates only when
#   resolved knows of NO DNS at all (no global DNS= and no per-link server
#   on a default-route link) — NOT when configured servers are unreachable.
#   With DNS= set above it stays inert; pinning it to Quad9 replaces the
#   compiled-in Quad9+Cloudflare+Google list so even a config regression
#   that drops DNS= cannot leak queries to a third party.
# DNSOverTLS=yes: global Quad9 queries use authenticated DoT (:853) and fail
#   closed instead of falling back to DNS/53. Every global server carries the
#   Quad9 certificate name. M23 gives unset provider/private and other
#   non-physical links a best-effort opportunistic default, but gives physical
#   Ethernet/Wi-Fi a strict activation default before explicitly applying this
#   selected NoID Privacy mode. Users who need a VPN or
#   captive-portal compatibility path can deliberately select opportunistic
#   mode in Setup, Network, Tools or noid-dns-mode; that mode is downgrade-
#   capable and permits DNS/53 fallback.
# DNSSEC=allow-downgrade: attempts validation, but a synthesized capability
#   response can force DNSSEC validation off. Properly proven insecure
#   (unsigned) delegations are valid even under strict DNSSEC; unsigned does
#   not itself justify allow-downgrade.
# LLMNR=no + MulticastDNS=no: explicit, global + per-link.
install -d -m 0755 -o root -g root /etc/systemd/resolved.conf.d
cat > /etc/systemd/resolved.conf.d/99-privacy.conf <<'RESOLVED_EOF'
# NoID Privacy — systemd-resolved hardening (Module 05)

[Resolve]
# Primary DNS: Quad9 IPv4 + IPv6. #hostname supplies the intended TLS server
# name/SNI for strict certificate authentication below.
# These are used when no per-link DNS is available (= no VPN active, or
# VPN push-DNS not set). With NetworkManager ignore-auto-dns=true, DHCP
# ISP DNS never becomes per-link, so Quad9 is always the effective DNS
# unless a VPN sets per-link DNS with Domains=~. catchall.
DNS=9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net 2620:fe::fe#dns.quad9.net 2620:fe::9#dns.quad9.net

# Fallback: same Quad9. Per systemd-resolved(8), FallbackDNS activates only
# when NO DNS is configured at all (no global DNS= and no per-link server) —
# not when configured servers are unreachable. With DNS= set above this
# stays inert; it replaces the compiled-in Quad9+Cloudflare+Google fallback
# list so even a config regression that drops DNS= cannot leak queries to a
# third party.
# Same-provider kept despite mixed-provider 2026 best-
# practice. Privacy>reliability for our threat model — a Cloudflare entry
# here would be the leak path in exactly that regression case. During a
# multi-hour Quad9 outage the user switches manually via `resolvectl dns`.
FallbackDNS=9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net

# DNSSEC compatibility mode: attempt validation, but permit the selected DNS
# server to be treated as DNSSEC-incapable. An active attacker can synthesize
# that condition and force validation off. Strict DNSSEC still accepts a
# cryptographically proven insecure (unsigned) delegation; the compatibility
# risk here is broken/non-supporting resolvers and private zones without the
# required trust anchors, not the mere existence of unsigned domains.
DNSSEC=allow-downgrade

# Strict transport for the global Quad9 scope: every upstream connection uses
# authenticated TLS and resolution fails closed when TCP/853 or certificate
# validation fails. NetworkManager's M23 generic dns-over-tls=1 fallback lets
# unset non-physical/VPN/private scopes try DoT with DNS/53 fallback; it is not
# authenticated or downgrade-resistant. Device-matched Ethernet/Wi-Fi starts
# at strict DoT before its physical-profile dispatcher installs named Quad9
# and applies the selected mode.
DNSOverTLS=yes

# No multicast LAN discovery protocols
LLMNR=no
MulticastDNS=no

# Cache=yes is the systemd-resolved default. Explicit setting is drift-proof
# against future-default-changes. Cache lifetime per upstream TTL.
Cache=yes
RESOLVED_EOF
chmod 644 /etc/systemd/resolved.conf.d/99-privacy.conf
chown root:root /etc/systemd/resolved.conf.d/99-privacy.conf
log "STEP 1: /etc/systemd/resolved.conf.d/99-privacy.conf written (Quad9 + strict authenticated DoT)"

# ====================================================================
# STEP 1b: native global + physical-link DNS transport selector
# ====================================================================
# The base policy above remains package/image-owned. This helper publishes one
# lexically later, narrowly scoped drop-in for the global DNSOverTLS= value:
#   opportunistic — encrypted where available, DNS/53 compatibility fallback
#   strict        — DNSOverTLS=yes, authenticated and fail-closed
#   off           — explicit plaintext DNS recovery/compatibility choice
#   reset         — remove the selector and return to the image policy
#
# Active physical Ethernet/Wi-Fi profiles are converged transactionally with
# the global value. Per-link VPN/private DNS is intentionally untouched.
cat > /usr/local/sbin/noid-dns-mode <<'DNS_MODE_EOF'
#!/usr/bin/python3
"""Select NoID Privacy's global and physical-link DNS-over-TLS mode.

Usage:
  noid-dns-mode status
  noid-dns-mode opportunistic
  noid-dns-mode strict
  noid-dns-mode off
  noid-dns-mode reset

The selector changes global DNSOverTLS= and managed physical Ethernet/Wi-Fi
profiles hardened by NoID Privacy. It does not rewrite VPN, tunnel, bridge or
private per-link profiles. If `connection.dns-over-tls` remains at its default
(-1), NetworkManager applies NoID Privacy's generic `opportunistic` connection
default; an explicit profile value takes precedence. Opportunistic transport
may fall back to unauthenticated DNS/53 and is not MITM-resistant.
"""

import fcntl
import json
import os
import pwd
import re
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path


os.environ['LC_ALL'] = 'C'
CONF_DIR = Path('/etc/systemd/resolved.conf.d')
BASE_CONF = CONF_DIR / '99-privacy.conf'
MODE_CONF = CONF_DIR / 'zzzz-noid-dns-mode.conf'
RUNTIME_DIR = Path('/run/noid-privacy')
LOCK_FILE = RUNTIME_DIR / 'dns-mode.lock'
SELF = '/usr/local/sbin/noid-dns-mode'
PHYSICAL_TYPES = {
    '802-3-ethernet', '802-11-wireless', 'ethernet', 'wifi',
}
UUID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-'
    r'[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
IFNAME_RE = re.compile(r'^[a-zA-Z0-9_.-]{1,15}$')

SYSTEMCTL = '/usr/bin/systemctl'
SYSTEMD_ANALYZE = '/usr/bin/systemd-analyze'
NETWORKMANAGER = '/usr/bin/NetworkManager'
RESOLVECTL = '/usr/bin/resolvectl'
NMCLI = '/usr/bin/nmcli'
RESTORECON = '/usr/sbin/restorecon'
MATCHPATHCON = '/usr/sbin/matchpathcon'

DEFAULT_MODE = 'strict'
MODE_VALUE = {
    'off': 'no',
    'opportunistic': 'opportunistic',
    'strict': 'yes',
}
MODE_BYTES = {
    mode: (
        '# NoID Privacy - user-selected global and physical DNS transport\n'
        '# Managed by noid-dns-mode; VPN/private profiles are not rewritten.\n'
        '\n'
        '[Resolve]\n'
        f'DNSOverTLS={value}\n'
    ).encode('ascii')
    for mode, value in MODE_VALUE.items()
}


class ModeError(RuntimeError):
    """Expected closed-contract failure."""


def _tty_banner(title, subtitle):
    """Render the shared 52-column CLI frame for human terminal output."""
    if not sys.stdout.isatty():
        return
    color = not os.environ.get('NO_COLOR') and os.environ.get('TERM', 'dumb') != 'dumb'
    blue = '\033[38;5;39m' if color else ''
    bold = '\033[1m' if color else ''
    grey = '\033[38;5;245m' if color else ''
    reset = '\033[0m' if color else ''
    bar = '─' * 52
    print(f'{blue}╭{bar}╮{reset}')
    print(f'{blue}│{reset} {bold}{title}{reset}'
          f'{" " * max(0, 50 - len(title))} {blue}│{reset}')
    print(f'{blue}│{reset} {grey}{subtitle}{reset}'
          f'{" " * max(0, 50 - len(subtitle))} {blue}│{reset}')
    print(f'{blue}╰{bar}╯{reset}')


def _run(argv, timeout=10):
    try:
        return subprocess.run(
            argv, check=False, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ModeError(f'cannot run {argv[0]}: {exc}') from exc


def _trusted_directory(path, mode):
    try:
        info = path.lstat()
    except OSError as exc:
        raise ModeError(f'cannot inspect {path}: {exc}') from exc
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
            or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != mode):
        raise ModeError(
            f'untrusted directory contract for {path}; expected root:root '
            f'{mode:04o} directory')


def _trusted_regular_file(path, mode):
    try:
        info = path.lstat()
    except OSError as exc:
        raise ModeError(f'cannot inspect {path}: {exc}') from exc
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_gid != 0 or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != mode):
        raise ModeError(
            f'untrusted file contract for {path}; expected root:root '
            f'{mode:04o} single-link regular file')


def _selection():
    try:
        info = MODE_CONF.lstat()
    except FileNotFoundError:
        return 'default'
    except OSError:
        return 'invalid'
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_gid != 0 or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o644):
        return 'invalid'
    try:
        payload = MODE_CONF.read_bytes()
    except OSError:
        return 'invalid'
    return next(
        (mode for mode, expected in MODE_BYTES.items() if payload == expected),
        'invalid')


def _configured_mode():
    result = _run(
        [SYSTEMD_ANALYZE, 'cat-config', 'systemd/resolved.conf'], timeout=5)
    if result.returncode != 0:
        return 'unknown'
    in_resolve = False
    value = 'unknown'
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if line == '[Resolve]':
            in_resolve = True
            continue
        if line.startswith('['):
            in_resolve = False
            continue
        if in_resolve and line.startswith('DNSOverTLS='):
            candidate = line.split('=', 1)[1].strip()
            value = candidate if candidate in {'no', 'opportunistic', 'yes'} \
                else 'unknown'
    return value


def _normalize_profile_value(raw_value):
    return {
        '-1': 'default',
        '0': 'no',
        '1': 'opportunistic',
        '2': 'yes',
        'default': 'default',
        'no': 'no',
        'opportunistic': 'opportunistic',
        'yes': 'yes',
    }.get(raw_value.strip())


def _managed_physical_profiles():
    """Return closed metadata for NoID Privacy-managed Ethernet/Wi-Fi profiles."""
    active_result = _run(
        [NMCLI, '-t', '-e', 'no', '-f', 'UUID,DEVICE',
         'connection', 'show', '--active'], timeout=5)
    if active_result.returncode != 0:
        raise ModeError(
            'cannot enumerate active NetworkManager profiles: '
            f'{active_result.stderr.strip() or active_result.returncode}')
    active_devices = {}
    for line in active_result.stdout.splitlines():
        if not line:
            continue
        fields = line.split(':')
        if len(fields) != 2:
            raise ModeError('malformed active-profile enumeration')
        uuid, device = fields
        if (not UUID_RE.fullmatch(uuid) or not IFNAME_RE.fullmatch(device)
                or uuid in active_devices):
            raise ModeError('unsafe or duplicate active profile identity')
        active_devices[uuid] = device

    result = _run(
        [NMCLI, '-t', '-e', 'no', '-f', 'UUID,TYPE',
         'connection', 'show'], timeout=5)
    if result.returncode != 0:
        raise ModeError(
            'cannot enumerate saved NetworkManager profiles: '
            f'{result.stderr.strip() or result.returncode}')
    profiles = []
    seen = set()
    for line in result.stdout.splitlines():
        if not line:
            continue
        fields = line.split(':')
        if len(fields) != 2:
            raise ModeError('malformed saved-profile enumeration')
        uuid, type_ = fields
        if type_ not in PHYSICAL_TYPES:
            continue
        device = active_devices.get(uuid, '')
        if not UUID_RE.fullmatch(uuid) or uuid in seen:
            raise ModeError('unsafe or duplicate physical profile')
        # Live media owns only applied D-Bus state. An inactive /run-backed
        # profile has no durable target and is converged when activated.
        if _is_live_boot() and not device:
            continue
        value_result = _run(
            [NMCLI, '-e', 'no', '-g', 'connection.dns-over-tls',
             'connection', 'show', uuid], timeout=5)
        if value_result.returncode != 0:
            raise ModeError(
                f'cannot read physical-profile DNS mode for {device}')
        configured = _normalize_profile_value(value_result.stdout)
        if configured is None:
            raise ModeError(
                f'unknown physical-profile DNS mode for {device}')
        seen.add(uuid)
        profiles.append({
            'uuid': uuid,
            'type': type_,
            'device': device,
            'configured': configured,
        })
    return sorted(profiles, key=lambda item: (item['device'], item['uuid']))


def _aggregate_modes(values, empty='none'):
    values = set(values)
    if not values:
        return empty
    return next(iter(values)) if len(values) == 1 else 'mixed'


def _strict_physical_defaults_are_effective():
    """Prove that an unset physical profile inherits M23's Strict DoT."""
    result = _run([NETWORKMANAGER, '--print-config'], timeout=5)
    if result.returncode != 0:
        return False
    sections = {}
    current = None
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if line.startswith('[') and line.endswith(']'):
            current = line[1:-1]
            sections.setdefault(current, {})
        elif current and line and not line.startswith('#') and '=' in line:
            key, value = line.split('=', 1)
            sections[current][key] = value
    expected = {
        'connection-noid-ethernet-dns': 'type:ethernet',
        'connection-noid-wifi-dns': 'type:wifi',
    }
    return all(
        sections.get(section, {}).get('match-device') == device_match
        and sections[section].get('connection.dns-over-tls') == '2'
        for section, device_match in expected.items()
    )


def _aggregate_physical_configured(profiles):
    values = {profile['configured'] for profile in profiles}
    # A newly saved, still-inactive physical profile legitimately remains at
    # NetworkManager's `default` sentinel until its first M23 dispatcher run.
    # Treat that sentinel as equivalent to an explicit strict profile only
    # when NetworkManager's effective merged config proves both native M23
    # device-matched Strict DoT defaults. Any other mixture remains visible.
    if values == {'default', 'yes'} \
            and _strict_physical_defaults_are_effective():
        return 'yes'
    return _aggregate_modes(values)


def _runtime_state(profiles=None):
    profiles = _managed_physical_profiles() if profiles is None else profiles
    physical_ifnames = {
        profile['device'] for profile in profiles if profile['device']}
    result = _run(
        [RESOLVECTL, 'status', '--json=short'], timeout=5)
    if result.returncode != 0:
        return {
            'runtime_global': 'unknown',
            'scope': 'unknown',
            'link_mode': 'unknown',
            'physical_runtime': 'unknown',
            'global_servers_named': False,
            'physical_servers_named': False,
            'physical_runtime_by_ifname': {},
        }
    try:
        rows = json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError):
        rows = None
    if not isinstance(rows, list):
        return {
            'runtime_global': 'unknown',
            'scope': 'unknown',
            'link_mode': 'unknown',
            'physical_runtime': 'unknown',
            'global_servers_named': False,
            'physical_servers_named': False,
            'physical_runtime_by_ifname': {},
        }
    globals_ = [
        row for row in rows
        if isinstance(row, dict) and 'ifname' not in row
    ]
    if len(globals_) != 1:
        return {
            'runtime_global': 'unknown',
            'scope': 'unknown',
            'link_mode': 'unknown',
            'physical_runtime': 'unknown',
            'global_servers_named': False,
            'physical_servers_named': False,
            'physical_runtime_by_ifname': {},
        }
    global_row = globals_[0]
    runtime = global_row.get('dnsOverTLS')
    if runtime not in {'no', 'opportunistic', 'yes'}:
        runtime = 'unknown'
    servers = global_row.get('servers')
    named = (
        isinstance(servers, list)
        and bool(servers)
        and all(isinstance(server, dict) and bool(server.get('name'))
                for server in servers)
    )
    routed_physical = []
    routed_other = []
    physical_modes = {}
    physical_servers_named = True
    for row in rows:
        if not isinstance(row, dict) or 'ifname' not in row:
            continue
        ifname = row.get('ifname')
        if ifname in physical_ifnames:
            mode = row.get('dnsOverTLS')
            physical_modes[ifname] = (
                mode if mode in {'no', 'opportunistic', 'yes'}
                else 'unknown')
            link_servers = row.get('servers')
            if isinstance(link_servers, list) and link_servers:
                physical_servers_named = (
                    physical_servers_named
                    and all(isinstance(server, dict)
                            and bool(server.get('name'))
                            for server in link_servers))
        domains = row.get('searchDomains')
        root_route = isinstance(domains, list) and any(
            isinstance(domain, dict)
            and domain.get('name') == '.'
            and domain.get('routeOnly') is True
            for domain in domains
        )
        link_servers = row.get('servers')
        if root_route and isinstance(link_servers, list) and link_servers:
            if ifname in physical_ifnames:
                routed_physical.append(row)
            else:
                routed_other.append(row)
    routed_links = routed_physical + routed_other
    if routed_physical and routed_other:
        scope = 'mixed'
    elif routed_other:
        scope = 'link'
    elif routed_physical:
        scope = 'physical'
    else:
        scope = 'global'
        link_mode = 'none'
    if routed_links:
        modes = {
            row.get('dnsOverTLS')
            if row.get('dnsOverTLS') in {'no', 'opportunistic', 'yes'}
            else 'unknown'
            for row in routed_links
        }
        link_mode = next(iter(modes)) if len(modes) == 1 else 'mixed'
    return {
        'runtime_global': runtime,
        'scope': scope,
        'link_mode': link_mode,
        'physical_runtime': _aggregate_modes(
            physical_modes.values(), empty='none'),
        'global_servers_named': named,
        'physical_servers_named': physical_servers_named,
        'physical_runtime_by_ifname': physical_modes,
    }


def _state():
    profiles = _managed_physical_profiles()
    runtime = _runtime_state(profiles)
    physical_configured = _aggregate_physical_configured(profiles)
    # Live media cannot persist Anaconda's /run-backed profile. Its applied
    # D-Bus state is therefore the authoritative configured state.
    if _is_live_boot() and physical_configured != 'none':
        physical_configured = runtime['physical_runtime']
    state = {
        'selection': _selection(),
        'configured': _configured_mode(),
        'physical_configured': physical_configured,
    }
    state.update(runtime)
    return state


def _machine_status(state):
    print('NOID-DNS-MODE-V2')
    for key in (
            'selection', 'configured', 'runtime_global',
            'physical_configured', 'physical_runtime', 'scope', 'link_mode'):
        print(f'{key}={state[key]}')


def _human_status(state):
    selection_labels = {
        'default': 'image default (strict)',
        'off': 'off (plaintext DNS)',
        'opportunistic': 'opportunistic',
        'strict': 'strict (authenticated, fail-closed)',
        'invalid': 'ERROR — selector file is unsafe or malformed',
    }
    value_labels = {
        'no': 'off (plaintext DNS)',
        'opportunistic': 'opportunistic (DNS/53 fallback allowed)',
        'yes': 'strict (authenticated DoT, fail-closed)',
        'unknown': 'UNKNOWN',
    }
    link_labels = {
        'no': 'DoT=no (effective per-link setting)',
        'opportunistic': 'opportunistic DoT',
        'yes': 'strict DoT',
        'mixed': 'mixed per-link modes',
        'unknown': 'UNKNOWN',
    }
    physical_labels = {
        'none': 'no managed physical profile',
        'default': 'profile default (not explicitly converged)',
        **link_labels,
    }
    print('NoID Privacy — DNS transport')
    print(f"  Selection      : {selection_labels[state['selection']]}")
    print(f"  Merged config  : {value_labels[state['configured']]}")
    print(f"  Runtime global : {value_labels[state['runtime_global']]}")
    print('  Physical config: '
          f"{physical_labels.get(state['physical_configured'], state['physical_configured'])}")
    print('  Physical live  : '
          f"{physical_labels.get(state['physical_runtime'], state['physical_runtime'])}")
    if state['scope'] == 'link':
        print(
            '  Active DNS path: VPN/private ~. link '
            f"({link_labels.get(state['link_mode'], state['link_mode'])})")
        print('  Note           : the selected global mode is currently dormant; '
              'the active link profile is not rewritten by this selector. '
              'Inspect its profile and the NoID Privacy connection default '
              'separately.')
    elif state['scope'] == 'physical':
        print('  Active DNS path: NoID Privacy-managed physical link')
    elif state['scope'] == 'mixed':
        print('  Active DNS path: mixed physical and VPN/private ~. links')
    elif state['scope'] == 'global':
        print('  Active DNS path: global resolver scope')
    else:
        print('  Active DNS path: UNKNOWN')


def _lock():
    _trusted_directory(RUNTIME_DIR, 0o755)
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(LOCK_FILE, flags, 0o600)
    except OSError as exc:
        raise ModeError(f'cannot open DNS-mode lock: {exc}') from exc
    info = os.fstat(fd)
    path_info = LOCK_FILE.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_gid != 0 or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or (info.st_dev, info.st_ino) != (path_info.st_dev, path_info.st_ino)):
        os.close(fd)
        raise ModeError('unsafe DNS-mode lock metadata')
    fcntl.flock(fd, fcntl.LOCK_EX)
    return fd


def _sync_conf_dir():
    flags = os.O_RDONLY
    if hasattr(os, 'O_DIRECTORY'):
        flags |= os.O_DIRECTORY
    fd = os.open(CONF_DIR, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _publish(mode):
    payload = MODE_BYTES[mode]
    fd, temp_name = tempfile.mkstemp(
        prefix=f'.{MODE_CONF.name}.', dir=CONF_DIR)
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, 'wb', closefd=True) as stream:
            stream.write(payload)
            stream.flush()
            os.fchmod(stream.fileno(), 0o644)
            os.fchown(stream.fileno(), 0, 0)
            os.fsync(stream.fileno())
        result = _run([RESTORECON, '-F', str(temp)], timeout=5)
        if result.returncode != 0:
            raise ModeError(
                f'cannot label DNS-mode drop-in: {result.stderr.strip()}')
        info = temp.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or info.st_gid != 0 or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o644
                or temp.read_bytes() != payload):
            raise ModeError('temporary DNS-mode payload failed verification')
        os.replace(temp, MODE_CONF)
        result = _run([RESTORECON, '-F', str(MODE_CONF)], timeout=5)
        if result.returncode != 0:
            raise ModeError(
                f'cannot label published DNS-mode drop-in: '
                f'{result.stderr.strip()}')
        _trusted_regular_file(MODE_CONF, 0o644)
        if MODE_CONF.read_bytes() != payload:
            raise ModeError('published DNS-mode payload differs from input')
        result = _run([MATCHPATHCON, '-V', str(MODE_CONF)], timeout=5)
        if result.returncode != 0:
            raise ModeError(
                f'DNS-mode SELinux context mismatch: '
                f'{result.stdout.strip() or result.stderr.strip()}')
        _sync_conf_dir()
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def _remove():
    selection = _selection()
    if selection == 'invalid':
        raise ModeError('refusing to remove an unsafe or foreign selector file')
    if selection != 'default':
        MODE_CONF.unlink()
        _sync_conf_dir()


def _restore(selection):
    if selection == 'default':
        _remove()
    else:
        _publish(selection)


def _reload_and_wait(expected):
    # systemd-resolved is Type=notify-reload on Fedora 44/systemd 259. SIGHUP
    # reloads its configuration and flushes caches/open TCP connections without
    # destroying the resolve1 D-Bus link objects NetworkManager is updating.
    result = _run([SYSTEMCTL, 'reload', 'systemd-resolved.service'], timeout=20)
    if result.returncode != 0:
        detail = result.stderr.strip() or f'exit {result.returncode}'
        raise ModeError(f'systemd-resolved reload failed: {detail}')
    for _attempt in range(30):
        runtime = _runtime_state()['runtime_global']
        if runtime == expected:
            return
        time.sleep(0.1)
    raise ModeError(
        f'resolver runtime did not converge to DNSOverTLS={expected}')


def _is_live_boot():
    try:
        cmdline = Path('/proc/cmdline').read_text(
            encoding='ascii', errors='strict').split()
        return (
            any(token == 'rd.live.image'
                or token.startswith('rd.live.image=') for token in cmdline)
            and Path('/run/initramfs/livedev').exists())
    except (OSError, UnicodeError):
        return False


def _profile_alias(value):
    aliases = {
        'default': 'default',
        'no': 'no',
        'opportunistic': 'opportunistic',
        'yes': 'yes',
    }
    try:
        return aliases[value]
    except KeyError as exc:
        raise ModeError(f'unsupported physical DNS mode: {value}') from exc


def _apply_physical_value(profile, value):
    alias = _profile_alias(value)
    if _is_live_boot():
        result = _run(
            [NMCLI, 'device', 'modify', profile['device'],
             'connection.dns-over-tls', alias], timeout=20)
        if result.returncode == 0:
            result = _run(
                [RESOLVECTL, 'dnsovertls', profile['device'], alias],
                timeout=10)
    else:
        result = _run(
            [NMCLI, 'connection', 'modify', profile['uuid'],
             'connection.dns-over-tls', alias], timeout=20)
        if result.returncode == 0 and profile['device']:
            result = _run(
                [NMCLI, 'device', 'reapply', profile['device']], timeout=20)
    if result.returncode != 0:
        raise ModeError(
            f'physical DNS mode update failed for {profile["device"]}: '
            f'{result.stderr.strip() or result.returncode}')
    if not _is_live_boot():
        result = _run(
            [NMCLI, '-e', 'no', '-g', 'connection.dns-over-tls',
             'connection', 'show', profile['uuid']], timeout=5)
        actual = (
            _normalize_profile_value(result.stdout)
            if result.returncode == 0 else None)
        if actual != value:
            raise ModeError(
                f'physical DNS profile postcondition failed for '
                f'{profile["uuid"]}')


def _wait_physical(expected_by_ifname, profiles):
    for _attempt in range(30):
        runtime = _runtime_state(profiles)['physical_runtime_by_ifname']
        if all(runtime.get(ifname) == expected
               for ifname, expected in expected_by_ifname.items()):
            return
        time.sleep(0.1)
    raise ModeError('physical-link DNS runtime did not converge')


def _set_physical(profiles, expected):
    for profile in profiles:
        _apply_physical_value(profile, expected)
    _wait_physical(
        {profile['device']: expected for profile in profiles
         if profile['device']}, profiles)


def _restore_physical(profiles, runtime_by_ifname):
    expected = {}
    for profile in profiles:
        value = (
            runtime_by_ifname.get(profile['device'], 'unknown')
            if _is_live_boot() else profile['configured'])
        if value not in {'default', 'no', 'opportunistic', 'yes'}:
            raise ModeError(
                f'cannot restore unknown physical DNS mode for '
                f'{profile["device"]}')
        _apply_physical_value(profile, value)
        # A restored installed-profile default inherits the restored global
        # mode; Live runtime snapshots are always explicit.
        if profile['device']:
            expected[profile['device']] = (
                _configured_mode() if value == 'default' else value)
    _wait_physical(expected, profiles)


def _is_live_session():
    try:
        username = pwd.getpwuid(os.getuid()).pw_name
        cmdline = Path('/proc/cmdline').read_text(
            encoding='ascii', errors='strict').split()
        live_boot = any(
            token == 'rd.live.image' or token.startswith('rd.live.image=')
            for token in cmdline)
        return (
            username == 'liveuser' and live_boot
            and Path('/run/initramfs/livedev').exists())
    except (KeyError, OSError, UnicodeError):
        return False


def _noninteractive_sudo_authorizes(argv):
    """True only when sudo policy runs this exact argv without a password.

    A plain `sudo -l <cmd>` exit status only proves the command is "permitted
    by the security policy" (sudo(8)), which `%wheel ALL=(ALL) ALL` satisfies
    for every wheel member, and sudoers(5) `listpw` defaults to `any`, which
    the image's unrelated NOPASSWD drop-ins already satisfy. The probe thus
    succeeded for selectors that have no sudoers rule at all, the sudo route
    was chosen, and `sudo -n --` then failed with "a password is required"
    instead of using the provisioned polkit AUTH_ADMIN route. The verbose
    listing prints the matching entry only and tags a passwordless rule as
    `Options: !authenticate`; it is translated, so pin the locale.
    """
    try:
        result = _run(
            ['/usr/bin/env', 'LC_ALL=C.UTF-8', 'LANG=C.UTF-8',
             '/usr/bin/sudo', '-n', '-l', '-l', '--'] + argv,
            timeout=3)
    except ModeError:
        return False
    if result.returncode != 0:
        return False
    listing = result.stdout or ''
    return ('!authenticate' in listing
            and listing.count('Matched:') == 1)


def _become_root(action):
    if os.geteuid() == 0:
        return
    argv = [SELF, action]
    if (_is_live_session() or _noninteractive_sudo_authorizes(argv)):
        os.execv(
            '/usr/bin/sudo', ['/usr/bin/sudo', '-n', '--'] + argv)
    os.execv('/usr/bin/pkexec', ['/usr/bin/pkexec'] + argv)


def _change(action):
    _become_root(action)
    _trusted_directory(CONF_DIR, 0o755)
    _trusted_regular_file(BASE_CONF, 0o644)
    if _selection() == 'invalid':
        raise ModeError('selector file is unsafe or not owned by noid-dns-mode')
    lock_fd = _lock()
    try:
        old_selection = _selection()
        if old_selection == 'invalid':
            raise ModeError(
                'selector file changed to an unsafe or foreign payload')
        profiles = _managed_physical_profiles()
        old_runtime = _runtime_state(profiles)
        if action == 'strict':
            if (not old_runtime['global_servers_named']
                    or not old_runtime['physical_servers_named']):
                raise ModeError(
                    'strict mode requires every global and physical-link '
                    'resolver to carry a certificate name/SNI')
        try:
            if action == 'reset':
                _remove()
                expected = MODE_VALUE[DEFAULT_MODE]
            else:
                _publish(action)
                expected = MODE_VALUE[action]
            configured = _configured_mode()
            if configured != expected:
                raise ModeError(
                    f'a later/foreign drop-in overrides DNSOverTLS={expected} '
                    f'(merged value: {configured})')
            _reload_and_wait(expected)
            _set_physical(profiles, expected)
        except ModeError as exc:
            try:
                _restore(old_selection)
                restored = (
                    MODE_VALUE[DEFAULT_MODE] if old_selection == 'default'
                    else MODE_VALUE[old_selection])
                _reload_and_wait(restored)
                _restore_physical(
                    profiles, old_runtime['physical_runtime_by_ifname'])
            except ModeError as rollback_exc:
                raise ModeError(
                    f'{exc}; ROLLBACK ALSO FAILED: {rollback_exc}') from exc
            raise ModeError(f'{exc}; previous DNS mode restored') from exc
    finally:
        os.close(lock_fd)
    state = _state()
    _human_status(state)
    print('OK: global and managed physical DNS transport changed; '
          'VPN/private per-link profiles were not rewritten.')


def main():
    args = sys.argv[1:]
    if args == ['--status-machine']:
        _machine_status(_state())
        return 0
    if args == ['--physical-value']:
        selection = _selection()
        if selection == 'invalid':
            raise ModeError('selector file is unsafe or malformed')
        selected = DEFAULT_MODE if selection == 'default' else selection
        print(MODE_VALUE[selected])
        return 0
    _tty_banner('NoID Privacy — DNS over TLS',
                'Global + physical transport')
    if args in (['--help'], ['-h']):
        print(__doc__ or '')
        return 0
    if not args:
        args = ['status']
    if args == ['status']:
        _human_status(_state())
        return 0
    if len(args) == 1 and args[0] in {
            'off', 'opportunistic', 'strict', 'reset'}:
        _change(args[0])
        return 0
    print(__doc__ or '', file=sys.stderr)
    return 2


if __name__ == '__main__':
    try:
        sys.exit(main())
    except ModeError as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        sys.exit(1)
DNS_MODE_EOF
chmod 0755 /usr/local/sbin/noid-dns-mode
chown root:root /usr/local/sbin/noid-dns-mode
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F /usr/local/sbin/noid-dns-mode
fi
log "STEP 1b: /usr/local/sbin/noid-dns-mode installed (global + physical DoT selector)"

# ====================================================================
# STEP 2: NetworkManager process defaults — hostname ownership + probe off
# ====================================================================
# M05 owns only the process-level keys below. M23 owns per-profile DNS
# transport compatibility, mDNS/LLMNR and DHCP identity. `hostname-mode=none` only prevents
# NetworkManager from changing the transient local hostname; it does not
# suppress DHCP hostname options. M23's current ternary
# ipv4/ipv6.dhcp-send-hostname=0 settings own that separate control.
# connectivity.enabled=false: disables NM fedoraproject.org/static/hotspot.txt
#   probe (predictable HTTP fingerprint + unnecessary metadata leak).
mkdir -p /etc/NetworkManager/conf.d
cat > /etc/NetworkManager/conf.d/99-privacy.conf <<'NM_EOF'
# NoID Privacy — NetworkManager hardening (Module 05)
#
# NetworkManager 1.54+ rejects most per-connection
# properties as defaults in [connection-defaults] — they were silently
# dropped with warnings. Critical settings now applied via dispatcher script:
# /etc/NetworkManager/dispatcher.d/40-noid-connection-defaults (Module 23).
#
# Properties moved to dispatcher (per-connection via nmcli):
#   ipv4.ignore-auto-dns/routes  (TunnelVision CVE-2024-3661 mitigation)
#   ipv6.ignore-auto-dns/routes
#   ipv6.method=disabled
#   ipv6.ip6-privacy=2 + addr-gen-mode=stable-privacy
#   connection.mdns/llmnr/lldp = 0
#   ipv4/ipv6.dhcp-send-hostname=0
#
# Properties that ARE accepted as NM.conf defaults (kept here):
#   [main] hostname-mode=none
#   [connectivity] enabled=false

# Keep the configured local hostname stable. This key controls only whether
# NetworkManager adopts a transient hostname from DHCP/reverse DNS; it is not
# a DHCP send-hostname control.
[main]
hostname-mode=none

# Disable NM connectivity check (HTTP probe to fedoraproject.org)
[connectivity]
enabled=false
NM_EOF
chmod 644 /etc/NetworkManager/conf.d/99-privacy.conf
chown root:root /etc/NetworkManager/conf.d/99-privacy.conf
log "STEP 2: /etc/NetworkManager/conf.d/99-privacy.conf written (transient-hostname management + connectivity probe off)"

# ====================================================================
# STEP 3: native GVfs discovery policy — maintained GSettings + dconf
# ====================================================================
# GVfs 1.60's `network:///` backend reads these public schemas and skips the
# corresponding URI enumeration/monitor entirely at enum value `disabled`.
# Keep Fedora's package-owned AutoMount definitions untouched: direct package
# verification and future vendor updates remain meaningful.
mkdir -p /etc/dconf/db/distro.d/locks
cat > /etc/dconf/db/distro.d/04-noid-lan-discovery <<'DCONF_GVFS_EOF'
[org/gnome/system/wsdd]
display-mode='disabled'

[org/gnome/system/dns-sd]
display-local='disabled'
extra-domains=''
DCONF_GVFS_EOF

cat > /etc/dconf/db/distro.d/locks/04-noid-lan-discovery <<'DCONF_GVFS_LOCKS_EOF'
/org/gnome/system/wsdd/display-mode
/org/gnome/system/dns-sd/display-local
/org/gnome/system/dns-sd/extra-domains
DCONF_GVFS_LOCKS_EOF

chmod 0644 /etc/dconf/db/distro.d/04-noid-lan-discovery \
    /etc/dconf/db/distro.d/locks/04-noid-lan-discovery
chown root:root /etc/dconf/db/distro.d/04-noid-lan-discovery \
    /etc/dconf/db/distro.d/locks/04-noid-lan-discovery
dconf update
log "STEP 3: native GVfs WSDD/DNS-SD GSettings disabled + locked"

# ====================================================================
# STEP 4: Service masking — avahi, wsdd, cups
# ====================================================================
# These masks are defense-in-depth. The service-bearing avahi main package is
# retained for the dependency chain documented above. Masking its service and
# socket also blocks the systemd-backed D-Bus activation alias.
# wsdd service masking is cosmetic (wsdd is not spawned by systemd anyway —
# gvfs spawns it as user subprocess), but matches host state.
# cups triple-masking (.path .service .socket) kills all cups autostart
# vectors. Save-as-PDF via GTK print dialog works without the daemon.

# avahi — full double-mask (service + socket) mirroring host
systemctl mask avahi-daemon.service
systemctl mask avahi-daemon.socket

# wsdd — mask both variants (defense-in-depth; the native GVfs GSettings
# policy above owns user-session discovery suppression)
systemctl mask wsdd.service
systemctl mask wsdd2.service

# cups — triple mask (path + service + socket)
systemctl mask cups.path
systemctl mask cups.service
systemctl mask cups.socket

# cups-browsed — should already be absent via %packages exclude, but mask
# defensively in case transitive dep pulls it in
systemctl mask cups-browsed.service

log "STEP 4: services masked (avahi + wsdd + cups triple + cups-browsed)"

# ====================================================================
# STEP 4b: noid-toggle-printing — reviewed opt-in for the masked print stack
# ====================================================================
# STEP 4 masks the print daemon because LAN isolation is a product decision,
# not an accident: no listener, no browsing, no discovery. That decision stays
# the default, but it must remain a decision the owner can take back without
# reconstructing four systemctl invocations from documentation. Without this
# CLI the only published path was `systemctl unmask` by hand, which is exactly
# the "undocumented recovery" class this image otherwise refuses to ship.
#
# Scope boundaries, deliberately narrow:
#   - cups-browsed stays masked and uninstalled in BOTH states. It is the
#     network-printer auto-discovery daemon and the actual privacy cost; a
#     printer added by address needs none of it.
#   - avahi/wsdd stay masked in both states for the same reason, so enabling
#     printing never re-opens mDNS/WSD discovery.
#   - No firewall change. A network printer additionally needs an explicit
#     outbound LAN exception via `noid-lan-allow`; printing is client-initiated
#     TCP to the printer (IPP 631 / JetDirect 9100), so outbound is sufficient
#     and no inbound port is opened.
#   - cups.service is left socket/path-activated rather than enabled outright,
#     so cupsd runs only once something actually talks to it.
cat > /usr/local/sbin/noid-toggle-printing <<'NOID_TOGGLE_PRINTING_EOF'
#!/bin/bash
# noid-toggle-printing — enable or disable the local print stack (CUPS).
#
# Default state (NoID Privacy): cups.path + cups.service + cups.socket masked,
# cups-browsed masked and not installed. GTK "Save as PDF" works in this state;
# it needs no daemon.
#
# Enabled state (owner opt-in): the three cups units unmasked, cups.socket and
# cups.path enabled and started. cupsd is activated on demand.
#
# What this never does: it does not unmask cups-browsed, avahi or wsdd, and it
# does not touch the firewall. Network-printer discovery stays off and a
# network printer still needs its own outbound LAN exception.
#
# Usage:
#   sudo noid-toggle-printing on      # enable the local print stack
#   sudo noid-toggle-printing off     # restore the NoID Privacy default
#   noid-toggle-printing              # show status (no root required)

set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset BASH_ENV CDPATH ENV GLOBIGNORE PYTHONPATH PYTHONHOME
# `systemctl is-enabled` and the mask probe below compare against literal
# English states; systemd hands services the installation's LANG.
LC_ALL=C.UTF-8
export LC_ALL

# shellcheck source=/dev/null
[ ! -r /usr/local/lib/noid-privacy/agent-install-format.sh ] || \
    NOID_FMT_AUTO_TITLE="NoID Privacy — Printing" \
    NOID_FMT_AUTO_SUBTITLE="Local print stack (CUPS)" \
    . /usr/local/lib/noid-privacy/agent-install-format.sh

CUPS_UNITS="cups.path cups.service cups.socket"
# Activation entry points only. cups.service stays socket/path-activated so a
# host that never prints never runs cupsd.
CUPS_ACTIVATION="cups.socket cups.path"
# Discovery daemons that must remain masked in BOTH states — they are the
# privacy cost this image removed, not a printing prerequisite.
DISCOVERY_UNITS="cups-browsed.service avahi-daemon.service avahi-daemon.socket wsdd.service wsdd2.service"

ACTION="${1:-status}"

require_root() {
    [ "$(id -u)" -eq 0 ] || {
        echo "ERROR: '$ACTION' requires root (use sudo or pkexec)." >&2
        exit 1
    }
}

is_masked() {
    [ "$(systemctl is-enabled "$1" 2>/dev/null || true)" = masked ]
}

all_cups_masked() {
    local unit
    for unit in $CUPS_UNITS; do
        is_masked "$unit" || return 1
    done
    return 0
}

no_cups_masked() {
    local unit
    for unit in $CUPS_UNITS; do
        ! is_masked "$unit" || return 1
    done
    return 0
}

# A discovery daemon that lost its mask is reported but never silently
# re-masked by the `on` path: that would hide an unexpected system change.
discovery_intact() {
    local unit
    for unit in $DISCOVERY_UNITS; do
        # An absent unit cannot run and counts as intact; cups-browsed and wsdd
        # are excluded from %packages on a stock image.
        if systemctl cat "$unit" >/dev/null 2>&1 && ! is_masked "$unit"; then
            return 1
        fi
    done
    return 0
}

report_discovery_drift() {
    local unit
    for unit in $DISCOVERY_UNITS; do
        if systemctl cat "$unit" >/dev/null 2>&1 && ! is_masked "$unit"; then
            echo "  WARNING: $unit is no longer masked — network-printer" >&2
            echo "           discovery may be reachable. Re-mask it with:" >&2
            echo "           sudo systemctl mask $unit" >&2
        fi
    done
}

case "$ACTION" in
    on|enable)
        require_root
        # shellcheck disable=SC2086  # deliberate word splitting of the unit list
        if ! systemctl unmask $CUPS_UNITS; then
            echo "ERROR: failed to unmask the CUPS units" >&2
            exit 1
        fi
        # shellcheck disable=SC2086
        if ! systemctl enable --now $CUPS_ACTIVATION; then
            echo "ERROR: failed to activate $CUPS_ACTIVATION; restoring the" >&2
            echo "       masked default" >&2
            # shellcheck disable=SC2086
            systemctl disable --now $CUPS_ACTIVATION >/dev/null 2>&1 || true
            # shellcheck disable=SC2086
            systemctl mask $CUPS_UNITS >/dev/null 2>&1 || true
            exit 1
        fi
        if ! systemctl is-active --quiet cups.socket; then
            echo "ERROR: cups.socket did not come up; restoring the masked" >&2
            echo "       default" >&2
            # shellcheck disable=SC2086
            systemctl disable --now $CUPS_ACTIVATION >/dev/null 2>&1 || true
            # shellcheck disable=SC2086
            systemctl mask $CUPS_UNITS >/dev/null 2>&1 || true
            exit 1
        fi
        report_discovery_drift
        echo "[OK] Printing ENABLED (cups.socket + cups.path active)."
        echo "      USB printer:     plug it in and allow it in the USBGuard"
        echo "                       prompt, then add it in GNOME Settings."
        echo "      Network printer: allow its address first —"
        echo "                       sudo noid-lan-allow --add <IPv4> --direction outbound"
        echo "                       then add it by address (ipp://<IPv4>:631/ipp/print)."
        echo "      Auto-discovery stays off by design (cups-browsed, avahi and"
        echo "      wsdd remain masked)."
        echo "      Disable again: sudo noid-toggle-printing off"
        echo "      Unmasking removes the /etc/systemd/system mask symlinks,"
        echo "      which an active AIDE baseline reports as expected drift."
        ;;
    off|disable)
        require_root
        # shellcheck disable=SC2086
        systemctl disable --now $CUPS_ACTIVATION >/dev/null 2>&1 || true
        systemctl stop cups.service >/dev/null 2>&1 || true
        # shellcheck disable=SC2086
        if ! systemctl mask $CUPS_UNITS; then
            echo "ERROR: failed to mask the CUPS units" >&2
            exit 1
        fi
        if ! all_cups_masked; then
            echo "ERROR: printing disable postcondition failed" >&2
            exit 1
        fi
        echo "[OK] Printing DISABLED (NoID Privacy default restored)."
        echo "      GTK 'Save as PDF' keeps working — it needs no daemon."
        echo "      Enable again: sudo noid-toggle-printing on"
        ;;
    status|"")
        mask_state=mixed
        if all_cups_masked; then
            mask_state=masked
        elif no_cups_masked; then
            mask_state=unmasked
        fi
        socket_state=inactive
        systemctl is-active --quiet cups.socket && socket_state=active
        daemon_state=inactive
        systemctl is-active --quiet cups.service && daemon_state=active
        discovery_state=masked
        discovery_intact || discovery_state=EXPOSED

        echo "Printing state (system-level):"
        echo "  cups units:        $mask_state"
        echo "  cups.socket:       $socket_state"
        echo "  cupsd:             $daemon_state"
        echo "  discovery daemons: $discovery_state"
        echo
        if [ "$mask_state" = masked ]; then
            echo "-> DISABLED (NoID Privacy default) — 'Save as PDF' still works"
        elif [ "$mask_state" = unmasked ] && [ "$socket_state" = active ]; then
            echo "-> ENABLED — cupsd is activated on demand"
        else
            echo "-> MIXED — run 'on' or 'off' to normalize"
        fi
        [ "$discovery_state" = masked ] || report_discovery_drift
        ;;
    *)
        echo "Usage: noid-toggle-printing [on|off|status]" >&2
        exit 1
        ;;
esac
NOID_TOGGLE_PRINTING_EOF
chmod 0755 /usr/local/sbin/noid-toggle-printing
chown root:root /usr/local/sbin/noid-toggle-printing
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F /usr/local/sbin/noid-toggle-printing 2>/dev/null || true
fi
if ! bash -n /usr/local/sbin/noid-toggle-printing; then
    echo "  [FAIL] noid-toggle-printing failed its syntax check"
    exit 1
fi
log "STEP 4b: noid-toggle-printing installed (reviewed print-stack opt-in)"

# ====================================================================
# STEP 5: samba-common orphan config cleanup (5 files + upgrade-resistance)
# ====================================================================
# samba-common is a hard-pinned transitive dep:
#   gnome-shell → gnome-control-center → libsmbclient = samba-common
# The package ships config files for daemons we don't install (no smbd/
# nmbd/winbindd). All 5 files below are pure orphans — no daemon, no
# service, no listener uses them. Removing keeps the image clean without
# touching libsmbclient.so.0 (used by gnome-control-center print/search).
# STEP 5b adds tmpfiles.d 'r' upgrade-resistance for absent daemon configs.
for orphan in /etc/samba/smb.conf /etc/samba/smb.conf.example \
              /etc/samba/lmhosts /etc/sysconfig/samba \
              /etc/logrotate.d/samba; do
    if [ -f "$orphan" ]; then
        rm -f "$orphan"
        log "STEP 5a: orphan removed: $orphan"
    fi
done
if [ -d /etc/samba ] && [ -z "$(ls -A /etc/samba 2>/dev/null)" ]; then
    rmdir /etc/samba
    log "STEP 5a: /etc/samba/ empty dir removed"
fi

# STEP 5b: tmpfiles.d 'r' rule for upgrade-resistance. If dnf upgrades samba-
# common in future, orphan config files come back; this rule ensures they
# get auto-removed at next boot via systemd-tmpfiles-setup.service. Mirrors
# Type 'r' = remove file if exists, no error
# if absent.
cat > /etc/tmpfiles.d/noid-samba-cleanup.conf <<'SAMBA_TMPFILES_EOF'
# NoID Privacy — samba-common orphan config cleanup (Module 05)
#
# samba-common is hard-pinned via gnome-shell→gnome-control-center→libsmbclient
# chain. Its orphan config files (no daemon uses them) re-appear on package
# upgrade. This rule auto-removes them on every boot before user session.
#
# Format: type path mode uid gid age argument
# Type 'r' = remove file if it exists (does not error if absent)

r /etc/samba/smb.conf
r /etc/samba/smb.conf.example
r /etc/samba/lmhosts
r /etc/sysconfig/samba
r /etc/logrotate.d/samba
SAMBA_TMPFILES_EOF
chmod 644 /etc/tmpfiles.d/noid-samba-cleanup.conf
chown root:root /etc/tmpfiles.d/noid-samba-cleanup.conf
log "STEP 5b: /etc/tmpfiles.d/noid-samba-cleanup.conf written (upgrade-resistance)"

# STEP 5c: guarantee the shared /run/noid-privacy runtime state dir exists
# at every boot BEFORE any consumer service starts. /run is tmpfs (wiped each
# boot); several services consume ReadWritePaths=/run/noid-privacy under
# ProtectSystem=strict (M06 vpn-killswitch, M07 ipv6-privacy, M12 auditd,
# M21 dracut-hostonly). ReadWritePaths= requires the path to pre-exist or the
# unit hard-fails at namespace setup with status=226/NAMESPACE. Creating it via
# systemd-tmpfiles-setup.service gives the directory one boot-wide owner and
# lifetime. No consumer may claim the shared path through RuntimeDirectory=:
# systemd removes an owned runtime directory when that individual unit stops,
# including unrelated services' live state below the same path.
cat > /etc/tmpfiles.d/noid-runtime.conf <<'RUNTIME_TMPFILES_EOF'
# NoID Privacy — shared runtime state directory (created early each boot)
#
# /run is tmpfs and wiped on every boot. Consumers declaring
# ReadWritePaths=/run/noid-privacy under ProtectSystem=strict need it to exist
# before they start, or systemd aborts them with status=226/NAMESPACE.
#
# Format: type path mode uid gid age argument
d /run/noid-privacy 0755 root root -
f /run/noid-privacy/lan-topology-refresh.lock 0600 root root -
f /run/noid-privacy/lan-exceptions.lock 0600 root root -
f /run/noid-privacy/dns-mode.lock 0600 root root -
f /run/noid-privacy/usbguard-add-user.lock 0600 root root -
z /run/noid-privacy/usbguard-add-user.lock 0600 root root -
f /run/noid-privacy/displaylink.lock 0600 root root -
z /run/noid-privacy/displaylink.lock 0600 root root -
f /run/noid-privacy/audit-notify-toggle.lock 0600 root root -
RUNTIME_TMPFILES_EOF
chmod 644 /etc/tmpfiles.d/noid-runtime.conf
chown root:root /etc/tmpfiles.d/noid-runtime.conf
log "STEP 5c: /etc/tmpfiles.d/noid-runtime.conf written (/run/noid-privacy boot-create)"

# ====================================================================
# STEP 6: Verification block (logged to /var/log/ks-05-lan-isolation.log)
# ====================================================================
log "STEP 6: verification ==="
verify_failed=0
verify_fail() {
    log "  ✗ $*"
    verify_failed=1
}

# Verify both owned bytes/metadata and the merged systemd-resolved view. The
# latter catches a lexically later drop-in that would silently override M05.
if [ "$(LC_ALL=C stat -c '%u:%g:%a:%h:%F' \
        /etc/systemd/resolved.conf.d/99-privacy.conf 2>/dev/null || true)" \
        = '0:0:644:1:regular file' ]; then
    log "  ✓ resolved drop-in: closed root-owned file"
else
    verify_fail "resolved drop-in metadata contract failed"
fi
if [ "$(LC_ALL=C stat -c '%u:%g:%a:%F' \
        /etc/systemd/resolved.conf.d 2>/dev/null || true)" \
        = '0:0:755:directory' ]; then
    log "  ✓ resolved drop-in directory: closed root-owned directory"
else
    verify_fail "resolved drop-in directory metadata contract failed"
fi
resolved_expected_dns='9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net 2620:fe::fe#dns.quad9.net 2620:fe::9#dns.quad9.net'
resolved_expected_fallback='9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net'
if resolved_merged=$(systemd-analyze cat-config systemd/resolved.conf 2>/dev/null) \
   && printf '%s\n' "$resolved_merged" | awk \
         -v expected_dns="$resolved_expected_dns" \
         -v expected_fallback="$resolved_expected_fallback" '
         # M05_RESOLVED_MERGE_AWK_BEGIN
        /^\[Resolve\]$/ { section="Resolve"; next }
        /^\[/ { section="" }
        section == "Resolve" && /^[A-Za-z][A-Za-z0-9]*=/ {
            key=$0; sub(/=.*/, "", key)
            value=$0; sub(/^[^=]*=/, "", value)
            setting[key]=value
        }
        END {
            ok = (setting["DNS"] == expected_dns)
            ok = ok && (setting["FallbackDNS"] == expected_fallback)
            ok = ok && (setting["DNSSEC"] == "allow-downgrade")
            ok = ok && (setting["DNSOverTLS"] == "yes")
            ok = ok && (setting["LLMNR"] == "no")
            ok = ok && (setting["MulticastDNS"] == "no")
            ok = ok && (setting["Cache"] == "yes")
            exit !ok
        }
        # M05_RESOLVED_MERGE_AWK_END
    '; then
    log "  ✓ merged resolved policy: exact M05 transport/discovery contract"
else
    verify_fail "merged resolved policy is missing or overridden"
fi
if [ "$(LC_ALL=C stat -c '%u:%g:%a:%h:%F' \
        /usr/local/sbin/noid-dns-mode 2>/dev/null || true)" \
        = '0:0:755:1:regular file' ] \
   && python3 -c \
        "import ast; ast.parse(open('/usr/local/sbin/noid-dns-mode', encoding='utf-8').read())" \
        2>/dev/null; then
    log "  ✓ noid-dns-mode: closed root-owned executable with valid syntax"
else
    verify_fail "noid-dns-mode deployment/syntax contract failed"
fi

# Verify NM drop-in. STEP 2 only writes [main] hostname-mode +
# [connectivity] enabled — all per-connection properties migrated to the
# Module 23 dispatcher (NM 1.54+ rejects them as connection-defaults);
# per-property checks are owned by tests/23-networkmanager-structural.sh.
if [ "$(LC_ALL=C stat -c '%u:%g:%a:%h:%F' \
        /etc/NetworkManager/conf.d/99-privacy.conf 2>/dev/null || true)" \
        = '0:0:644:1:regular file' ]; then
    log "  ✓ NM drop-in: closed root-owned file"
else
    verify_fail "NM drop-in metadata contract failed"
fi
if nm_merged=$(NetworkManager --print-config 2>/dev/null) \
   && printf '%s\n' "$nm_merged" | awk '
        /^\[main\]$/ { section="main"; next }
        /^\[connectivity\]$/ { section="connectivity"; next }
        /^\[/ { section="" }
        section == "main" && $0 == "hostname-mode=none" { hostname=1 }
        section == "connectivity" && $0 == "enabled=false" { probe=1 }
        END { exit !(hostname == 1 && probe == 1) }
    '; then
    log "  ✓ merged NM policy: hostname ownership + connectivity probe disabled"
else
    verify_fail "merged NM policy is missing or overridden"
fi
# Cross-ref Module 23: per-connection hardening dispatcher must exist.
# Without it, ipv4.ignore-auto-routes (TunnelVision CVE-2024-3661 mitigation) etc.
# never get applied. This is the authoritative source for those settings since
# NM 1.54+ rejected them as conf.d defaults.
#
# Module 05 runs BEFORE Module 23 in the %include chain — the dispatcher
# won't exist yet when this verify-block runs; demoted from FAIL to
# "deferred to 99-finalize" so the M05 log shows no misleading red-cross.
if [ -x /etc/NetworkManager/dispatcher.d/40-noid-connection-defaults ]; then
    log "  ✓ Module 23 dispatcher present (per-connection hardening: TunnelVision + lldp + ip6-privacy + mdns/llmnr)"
else
    log "  · Module 23 dispatcher not yet deployed (Module 05 runs before Module 23 — full check in 99-finalize)"
fi

# Verify maintained GVfs schema policy and prove package bytes stayed pristine.
if grep -qx "display-mode='disabled'" \
        /etc/dconf/db/distro.d/04-noid-lan-discovery \
   && grep -qx "display-local='disabled'" \
        /etc/dconf/db/distro.d/04-noid-lan-discovery \
   && gsettings range org.gnome.system.wsdd display-mode | grep -qw disabled \
   && gsettings range org.gnome.system.dns_sd display-local | grep -qw disabled; then
    log "  ✓ native GVfs WSDD/DNS-SD disabled enum policy present"
else
    verify_fail "native GVfs discovery schema/policy mismatch"
fi
if gvfs_verify=$(rpm -V gvfs 2>&1); then
    log "  ✓ gvfs RPM-owned files remain byte/metadata pristine"
else
    verify_fail "gvfs package drift detected: $gvfs_verify"
fi

# Verify package excludes. avahi + samba-common stay installed
# intentionally (hard-deps documented in the %packages section above);
# they are checked separately below to avoid misleading FAIL log entries.
for pkg in avahi-autoipd avahi-tools avahi-ui avahi-ui-tools nss-mdns samba samba-client cups-browsed cups-pdf; do
    if rpm -q "$pkg" >/dev/null 2>&1; then
        verify_fail "$pkg: INSTALLED (expected: absent)"
    else
        rpm_rc=$?
        if [ "$rpm_rc" -eq 1 ]; then
            log "  ✓ $pkg: absent"
        else
            verify_fail "$pkg: RPM query failed (rc=$rpm_rc)"
        fi
    fi
done

for unit in avahi-daemon.service avahi-daemon.socket wsdd.service wsdd2.service \
            cups.path cups.service cups.socket cups-browsed.service; do
    unit_state=$(systemctl is-enabled "$unit" 2>/dev/null || true)
    if [ "$unit_state" = masked ]; then
        log "  ✓ $unit: masked"
    else
        verify_fail "$unit: expected masked, observed ${unit_state:-unavailable}"
    fi
done
# avahi + samba-common: BY DESIGN INSTALLED (GNOME 50 hard-deps). avahi is a
# service-bearing package whose daemon activation is masked in Step 4;
# samba-common carries configuration/data/runtime-directory payload but no
# daemon executable.
for pkg_kept in avahi samba-common; do
    if rpm -q "$pkg_kept" >/dev/null 2>&1; then
        if [ "$pkg_kept" = avahi ]; then
            log "  · avahi: installed for dependencies; service/socket activation masked"
        else
            log "  · samba-common: installed packaging companion; no daemon executable"
        fi
    else
        log "  · $pkg_kept: absent (uncommon — likely no GNOME pulled them)"
    fi
done

if [ "$verify_failed" -ne 0 ]; then
    log "STEP 6 FAILED: refusing to publish an incompletely verified M05 payload"
    exit 1
fi

# ----------------------------------------------------------------------------
# Install /usr/local/bin/noid-lan-allow escape-hatch
# ----------------------------------------------------------------------------
# LAN isolation (block-lan-out + gvfs silence + mDNS/SMB/WSD packages excluded)
# breaks some legitimate home-network workflows: network printers, NAS shares,
# Chromecast, IP cameras. This script offers a minimal, documented opt-in
# that re-enables LAN egress WITHOUT re-introducing the Layer-2/7 protocols
# we explicitly disabled.
#
# The approach: bind one canonical, directly attached IPv4 address to the
# observed interface/MAC and publish only its requested direction/port
# selectors across XDP/TC, nftables and firewalld. The legacy global switch is
# a separate explicit opt-in. Neither path installs avahi/samba/cups-browsed,
# so service discovery stays off.

log "Installing /usr/local/bin/noid-lan-allow (escape-hatch)"

cat > /usr/local/bin/noid-lan-allow <<'LAN_ALLOW_EOF'
#!/bin/bash
# noid-lan-allow — selectively allow outbound LAN traffic
#
# Default state: block-lan-out drops reserved/private destinations and the
# topology-aware nft layer drops every directly connected physical prefix,
# including LANs that use unusual/public address space.
#
# Two mechanisms (per-IP recommended, global toggle legacy):
#
#   1. Per-IP exception (recommended): adds an accept rich-rule with
#      priority="-100" so it fires BEFORE the policy's drop rules. Temporary
#      grants carry root-owned absolute + same-boot monotonic expiry state and
#      are reconciled by an installed boot gate/timer.
#
#   2. Legacy global toggle: commits an explicit durable marker and updates
#      firewalld, topology and WAN-strict as one verified IP-policy transaction.
#      Standard ARP and existing permanent neighbour pins are orthogonal.
#      Allows every directly connected/local destination while keeping the
#      physical inbound IP DROP policy — used only when many peers need access.
#
# Preferred usage:
#   sudo noid-lan-allow --add <IP> --direction outbound [--temp MIN]
#   sudo noid-lan-allow --add <IP> --direction inbound --protocol tcp|udp \
#     --ports PORT|START-END [--temp MIN]
#   sudo noid-lan-allow --add <IP> --direction both --protocol tcp|udp \
#     --ports PORT|START-END [--temp MIN]
#   sudo noid-lan-allow --revert <IP>         Remove per-IP exception + expiry state
#   noid-lan-allow --list                     Show all active per-IP exceptions (no root required)
#   sudo noid-lan-allow on                    Legacy global allow (prefer per-IP)
#   sudo noid-lan-allow off                   Legacy global revert to hardened default
#   noid-lan-allow status                     Show global + per-IP state
#   noid-lan-allow help                       Show this help
#
# Bare <IP> and legacy --temp <IP> [MIN] remain outbound-only compatibility
# forms; new documentation and automation must use the explicit API above.

set -euo pipefail
umask 077

# shellcheck source=/dev/null
[ ! -r /usr/local/lib/noid-privacy/agent-install-format.sh ] || \
    NOID_FMT_AUTO_TITLE="NoID Privacy — LAN Exceptions" \
    NOID_FMT_AUTO_SUBTITLE="Explicit peer access" \
    . /usr/local/lib/noid-privacy/agent-install-format.sh

# Pin the tool locale: metadata gates compare localized stat/coreutils output
# (e.g. '%F' file-type strings) against canonical English forms.
LC_ALL=C
export LC_ALL

POLICY=block-lan-out
INBOUND_ZONE=drop
ACCEPT_PRIORITY="-100"
# The NOID_* defaults below are fixture seams, not a privileged override API.
# Production safety depends on M10 sudo env_reset preserving no NOID_* names
# and on system units passing no NOID_* environment. Keep those cross-module
# contracts synchronized before adding another privileged caller.
LAN_PEER_STATE_DIR="${NOID_LAN_PEER_STATE_DIR:-/var/lib/noid-privacy/lan-peer-bindings}"
LAN_EXCEPTION_STATE_DIR="${NOID_LAN_EXCEPTION_STATE_DIR:-/var/lib/noid-privacy/lan-exceptions}"
LAN_EXCEPTION_LOCK="${NOID_LAN_EXCEPTION_LOCK:-/run/noid-privacy/lan-exceptions.lock}"
LAN_EXCEPTION_TIMER="${NOID_LAN_EXCEPTION_TIMER:-noid-lan-expiry-reconcile.timer}"
LAN_EXCEPTION_SCHEDULE_FILE="${NOID_LAN_EXCEPTION_SCHEDULE_FILE:-/run/noid-privacy/lan-expiry-schedule}"
LAN_STATE_UID="${NOID_LAN_STATE_UID:-0}"
LAN_STATE_GID="${NOID_LAN_STATE_GID:-0}"
SYS_CLASS_NET="${NOID_SYS_CLASS_NET:-/sys/class/net}"
GLOBAL_ALLOW_MARKER="${NOID_LAN_GLOBAL_ALLOW_MARKER:-/var/lib/noid-privacy/lan-global-allow.enabled}"
GLOBAL_RUNTIME_STATE="${NOID_LAN_GLOBAL_RUNTIME_STATE:-/run/noid-privacy/lan-global-state}"
TOPOLOGY_REFRESH="${NOID_LAN_TOPOLOGY_REFRESH:-/usr/local/sbin/noid-lan-topology-refresh.sh}"
XDP_CONTROLLER="${NOID_LAN_XDP_CONTROLLER:-/usr/local/sbin/noid-lan-xdp}"
XDP_HEALTH_FILE="${NOID_LAN_XDP_HEALTH_FILE:-/run/noid-privacy/lan-xdp-health}"
ARP_HARDENING_STATE="${NOID_ARP_HARDENING_STATE:-/var/lib/noid-privacy/arp-hardening.state}"
ARP_STATE_GUARD=/usr/local/sbin/noid-arp-state-guard.sh

[[ "$LAN_STATE_UID" =~ ^(0|[1-9][0-9]{0,9})$ ]] \
    && [[ "$LAN_STATE_GID" =~ ^(0|[1-9][0-9]{0,9})$ ]] || {
    echo "Error: invalid LAN state owner contract." >&2
    exit 1
}

if ! command -v firewall-cmd >/dev/null 2>&1; then
    echo "Error: firewall-cmd not available." >&2
    exit 1
fi

# Validate IP (v4 or v6) and return family ("ipv4"|"ipv6"). Empty on invalid.
# Always exits 0 (empty output signals invalid) to avoid set -e interaction.
validate_ip_family() {
    python3 -c "
import ipaddress, sys
try:
    ip = ipaddress.ip_address(sys.argv[1])
    print('ipv4' if isinstance(ip, ipaddress.IPv4Address) else 'ipv6')
except ValueError:
    sys.exit(0)
" "$1" 2>/dev/null
}

canonicalize_ip() {
    python3 -c 'import ipaddress,sys; print(ipaddress.ip_address(sys.argv[1]))' \
        "$1" 2>/dev/null
}

require_root() {
    [ "$(id -u)" -eq 0 ] || {
        echo "ERROR: This action requires root (use sudo)." >&2
        exit 1
    }
}

trusted_state_directory() {
    local path="$1" expected_mode="${2:-}" metadata uid gid mode type
    [[ "$path" == /* && "$path" != / && "$path" != */ ]] || return 1
    [ -d "$path" ] && [ ! -L "$path" ] || return 1
    metadata=$(stat -c '%u:%g:%a:%F' "$path") || return 1
    IFS=: read -r uid gid mode type <<< "$metadata"
    [ "$uid" = "$LAN_STATE_UID" ] && [ "$gid" = "$LAN_STATE_GID" ] \
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
    trusted_state_directory "$parent" || {
        echo "ERROR: untrusted parent for LAN state directory: $path" >&2
        return 1
    }
    if [ -e "$path" ] || [ -L "$path" ]; then
        trusted_state_directory "$path" "$mode" || {
            echo "ERROR: invalid LAN state directory contract: $path" >&2
            return 1
        }
        return 0
    fi
    install -d -m "$mode" "$path" || return 1
    chown "$LAN_STATE_UID:$LAN_STATE_GID" "$path" || return 1
    trusted_state_directory "$path" "$mode"
}

acquire_exception_lock() {
    local lock_dir metadata path_identity fd_identity
    [[ "$LAN_EXCEPTION_LOCK" == /* && "$LAN_EXCEPTION_LOCK" != */ ]] || {
        echo "ERROR: invalid LAN exception lock path." >&2
        return 1
    }
    lock_dir=${LAN_EXCEPTION_LOCK%/*}
    ensure_state_directory "$lock_dir" 755 || return 1
    if [ ! -e "$LAN_EXCEPTION_LOCK" ] && [ ! -L "$LAN_EXCEPTION_LOCK" ]; then
        install -m 0600 /dev/null "$LAN_EXCEPTION_LOCK" || return 1
        chown "$LAN_STATE_UID:$LAN_STATE_GID" "$LAN_EXCEPTION_LOCK" || return 1
    fi
    [ -f "$LAN_EXCEPTION_LOCK" ] && [ ! -L "$LAN_EXCEPTION_LOCK" ] \
        || return 1
    metadata=$(stat -c '%u:%g:%a:%h' "$LAN_EXCEPTION_LOCK" 2>/dev/null) \
        || return 1
    [ "$metadata" = "$LAN_STATE_UID:$LAN_STATE_GID:600:1" ] \
        || {
            echo "ERROR: invalid LAN exception lock metadata: $metadata" >&2
            return 1
        }
    exec 8<>"$LAN_EXCEPTION_LOCK"
    metadata=$(stat -Lc '%u:%g:%a:%h' /proc/self/fd/8 2>/dev/null) \
        || return 1
    [ "$metadata" = "$LAN_STATE_UID:$LAN_STATE_GID:600:1" ] \
        || return 1
    path_identity=$(stat -Lc '%d:%i' "$LAN_EXCEPTION_LOCK") || return 1
    fd_identity=$(stat -Lc '%d:%i' /proc/self/fd/8) || return 1
    [ "$path_identity" = "$fd_identity" ] || return 1
    flock --exclusive 8 || return 1
    [ "$(stat -Lc '%d:%i' "$LAN_EXCEPTION_LOCK")" = "$fd_identity" ]
}

exception_state_file() {
    local ip="$1" family digest
    [ "$(canonicalize_ip "$ip" || true)" = "$ip" ] \
        || return 1
    family=$(validate_ip_family "$ip")
    case "$family" in ipv4|ipv6) ;; *) return 1 ;; esac
    digest=$(printf '%s' "$ip" | sha256sum | awk '{print $1}') || return 1
    printf '%s/%s.state\n' "$LAN_EXCEPTION_STATE_DIR" "$digest"
}

now_epoch() {
    if [ -n "${NOID_TEST_NOW_EPOCH:-}" ]; then
        printf '%s\n' "$NOID_TEST_NOW_EPOCH"
    else
        date +%s
    fi
}

current_boot_id() {
    if [ -n "${NOID_TEST_BOOT_ID:-}" ]; then
        printf '%s\n' "$NOID_TEST_BOOT_ID"
    else
        cat /proc/sys/kernel/random/boot_id
    fi
}

current_boottime() {
    if [ -n "${NOID_TEST_BOOTTIME:-}" ]; then
        printf '%s\n' "$NOID_TEST_BOOTTIME"
    else
        awk '{sub(/\..*/, "", $1); print $1}' /proc/uptime
    fi
}

is_uint() {
    [[ "$1" =~ ^(0|[1-9][0-9]{0,17})$ ]]
}

ensure_exception_state_dir() {
    ensure_state_directory "$LAN_EXCEPTION_STATE_DIR" 755
}

validate_direction_selector() {
    local direction="$1" protocol="$2" port_start="$3" port_end="$4"
    case "$direction:$protocol:$port_start:$port_end" in
        outbound:none:0:0) return 0 ;;
        inbound:tcp:*:*|inbound:udp:*:*|both:tcp:*:*|both:udp:*:*)
            [[ "$port_start" =~ ^[1-9][0-9]{0,4}$ ]] \
                && [[ "$port_end" =~ ^[1-9][0-9]{0,4}$ ]] \
                && [ "$port_start" -le "$port_end" ] \
                && [ "$port_end" -le 65535 ]
            ;;
        *) return 1 ;;
    esac
}

write_exception_state() {
    local ip="$1" family="$2" kind="$3" duration="$4"
    local direction="$5" protocol="$6" port_start="$7" port_end="$8"
    local created expires boot_id boottime state tmp
    created=$(now_epoch)
    boot_id=$(current_boot_id)
    boottime=$(current_boottime)
    is_uint "$created" && is_uint "$boottime" || return 1
    [[ "$boot_id" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] \
        || return 1
    case "$kind" in
        permanent)
            [ "$duration" = 0 ] || return 1
            expires=0
            ;;
        temporary)
            is_uint "$duration" \
                && [ "$duration" -ge 60 ] && [ "$duration" -le 86400 ] || return 1
            expires=$((created + duration))
            ;;
        *) return 1 ;;
    esac
    [ "$family" = ipv4 ] || return 1
    [ "$(canonicalize_ip "$ip" || true)" = "$ip" ] \
        && [ "$(validate_ip_family "$ip")" = ipv4 ] || return 1
    validate_direction_selector "$direction" "$protocol" "$port_start" "$port_end" \
        || return 1
    ensure_exception_state_dir || return 1
    state=$(exception_state_file "$ip")
    tmp=$(mktemp "$LAN_EXCEPTION_STATE_DIR/.exception.XXXXXX") || return 1
    if ! printf '%s\n' \
        'VERSION=2' \
        "IP=$ip" \
        "FAMILY=$family" \
        "DIRECTION=$direction" \
        "PROTOCOL=$protocol" \
        "PORT_START=$port_start" \
        "PORT_END=$port_end" \
        "KIND=$kind" \
        "CREATED_EPOCH=$created" \
        "EXPIRES_EPOCH=$expires" \
        "BOOT_ID=${boot_id,,}" \
        "CREATED_BOOTTIME=$boottime" \
        "DURATION_SEC=$duration" > "$tmp"; then
        rm -f -- "$tmp"
        return 1
    fi
    chmod 0644 "$tmp" || { rm -f -- "$tmp"; return 1; }
    chown "$LAN_STATE_UID:$LAN_STATE_GID" "$tmp" \
        || { rm -f -- "$tmp"; return 1; }
    [ "$(stat -c '%u:%g:%a:%h:%F' "$tmp")" = \
        "$LAN_STATE_UID:$LAN_STATE_GID:644:1:regular file" ] || {
        rm -f -- "$tmp"
        return 1
    }
    mv -fT "$tmp" "$state" || { rm -f -- "$tmp"; return 1; }
    [ "$(stat -c '%u:%g:%a:%h:%F' "$state")" = \
        "$LAN_STATE_UID:$LAN_STATE_GID:644:1:regular file" ] \
        && load_exception_state "$ip" \
        && [ "$EX_STATE_FAMILY" = "$family" ] \
        && [ "$EX_STATE_KIND" = "$kind" ] \
        && [ "$EX_STATE_DURATION" = "$duration" ] \
        && [ "$EX_STATE_CREATED" = "$created" ] \
        && [ "$EX_STATE_EXPIRES" = "$expires" ] \
        && [ "$EX_STATE_BOOT_ID" = "${boot_id,,}" ] \
        && [ "$EX_STATE_BOOTTIME" = "$boottime" ] \
        && [ "$EX_STATE_DIRECTION" = "$direction" ] \
        && [ "$EX_STATE_PROTOCOL" = "$protocol" ] \
        && [ "$EX_STATE_PORT_START" = "$port_start" ] \
        && [ "$EX_STATE_PORT_END" = "$port_end" ]
}

load_exception_state() {
    local requested_ip="$1" state line key value count=0
    local seen_version=0 seen_ip=0 seen_family=0 seen_direction=0 seen_protocol=0
    local seen_port_start=0 seen_port_end=0 seen_kind=0 seen_created=0
    local seen_expires=0 seen_boot=0 seen_boottime=0 seen_duration=0
    local metadata canonical delta
    trusted_state_directory "$LAN_EXCEPTION_STATE_DIR" 755 || return 1
    state=$(exception_state_file "$requested_ip")
    [ -f "$state" ] && [ ! -L "$state" ] || return 1
    metadata=$(stat -c '%u:%g:%a:%h:%F' "$state") || return 1
    [ "$metadata" = "$LAN_STATE_UID:$LAN_STATE_GID:644:1:regular file" ] \
        || return 1
    EX_STATE_VERSION="" EX_STATE_IP="" EX_STATE_FAMILY=""
    EX_STATE_DIRECTION="" EX_STATE_PROTOCOL="" EX_STATE_PORT_START=""
    EX_STATE_PORT_END="" EX_STATE_KIND=""
    EX_STATE_CREATED="" EX_STATE_EXPIRES="" EX_STATE_BOOT_ID=""
    EX_STATE_BOOTTIME="" EX_STATE_DURATION=""
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in *=*) ;; *) return 1 ;; esac
        key=${line%%=*}; value=${line#*=}
        case "$key" in
            VERSION) [ "$seen_version" -eq 0 ] || return 1; seen_version=1; EX_STATE_VERSION=$value ;;
            IP) [ "$seen_ip" -eq 0 ] || return 1; seen_ip=1; EX_STATE_IP=$value ;;
            FAMILY) [ "$seen_family" -eq 0 ] || return 1; seen_family=1; EX_STATE_FAMILY=$value ;;
            DIRECTION) [ "$seen_direction" -eq 0 ] || return 1; seen_direction=1; EX_STATE_DIRECTION=$value ;;
            PROTOCOL) [ "$seen_protocol" -eq 0 ] || return 1; seen_protocol=1; EX_STATE_PROTOCOL=$value ;;
            PORT_START) [ "$seen_port_start" -eq 0 ] || return 1; seen_port_start=1; EX_STATE_PORT_START=$value ;;
            PORT_END) [ "$seen_port_end" -eq 0 ] || return 1; seen_port_end=1; EX_STATE_PORT_END=$value ;;
            KIND) [ "$seen_kind" -eq 0 ] || return 1; seen_kind=1; EX_STATE_KIND=$value ;;
            CREATED_EPOCH) [ "$seen_created" -eq 0 ] || return 1; seen_created=1; EX_STATE_CREATED=$value ;;
            EXPIRES_EPOCH) [ "$seen_expires" -eq 0 ] || return 1; seen_expires=1; EX_STATE_EXPIRES=$value ;;
            BOOT_ID) [ "$seen_boot" -eq 0 ] || return 1; seen_boot=1; EX_STATE_BOOT_ID=$value ;;
            CREATED_BOOTTIME) [ "$seen_boottime" -eq 0 ] || return 1; seen_boottime=1; EX_STATE_BOOTTIME=$value ;;
            DURATION_SEC) [ "$seen_duration" -eq 0 ] || return 1; seen_duration=1; EX_STATE_DURATION=$value ;;
            *) return 1 ;;
        esac
        count=$((count + 1))
    done < "$state"
    [ "$count" -eq 13 ] && [ "$EX_STATE_VERSION" = 2 ] || return 1
    canonical=$(canonicalize_ip "$EX_STATE_IP" || true)
    [ "$canonical" = "$requested_ip" ] || return 1
    [ "$(validate_ip_family "$EX_STATE_IP")" = "$EX_STATE_FAMILY" ] || return 1
    [ "$EX_STATE_FAMILY" = ipv4 ] || return 1
    validate_direction_selector "$EX_STATE_DIRECTION" "$EX_STATE_PROTOCOL" \
        "$EX_STATE_PORT_START" "$EX_STATE_PORT_END" || return 1
    is_uint "$EX_STATE_CREATED" && is_uint "$EX_STATE_EXPIRES" \
        && is_uint "$EX_STATE_BOOTTIME" && is_uint "$EX_STATE_DURATION" || return 1
    [[ "$EX_STATE_BOOT_ID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] \
        || return 1
    case "$EX_STATE_KIND" in
        permanent)
            [ "$EX_STATE_EXPIRES" -eq 0 ] && [ "$EX_STATE_DURATION" -eq 0 ] || return 1
            ;;
        temporary)
            [ "$EX_STATE_DURATION" -ge 60 ] && [ "$EX_STATE_DURATION" -le 86400 ] || return 1
            delta=$((EX_STATE_EXPIRES - EX_STATE_CREATED))
            [ "$delta" -eq "$EX_STATE_DURATION" ] || return 1
            ;;
        *) return 1 ;;
    esac
}

remove_exception_state() {
    if [ ! -e "$LAN_EXCEPTION_STATE_DIR" ] \
       && [ ! -L "$LAN_EXCEPTION_STATE_DIR" ]; then
        return 0
    fi
    trusted_state_directory "$LAN_EXCEPTION_STATE_DIR" 755 || return 1
    rm -f -- "$(exception_state_file "$1")"
}

exception_is_expired() {
    local now boot_id boottime
    [ "$EX_STATE_KIND" = temporary ] || return 1
    now=$(now_epoch); boot_id=$(current_boot_id); boottime=$(current_boottime)
    is_uint "$now" && is_uint "$boottime" || return 0
    # Any wall-clock rollback before creation is unsafe: revoke rather than
    # silently extending the grant. A forward jump expires in the usual way.
    [ "$now" -ge "$EX_STATE_CREATED" ] || return 0
    [ "$now" -lt "$EX_STATE_EXPIRES" ] || return 0
    if [ "${boot_id,,}" = "$EX_STATE_BOOT_ID" ]; then
        [ "$boottime" -ge "$EX_STATE_BOOTTIME" ] || return 0
        [ $((boottime - EX_STATE_BOOTTIME)) -lt "$EX_STATE_DURATION" ] || return 0
    fi
    return 1
}

refresh_topology_guard() {
    if [ ! -x "$TOPOLOGY_REFRESH" ]; then
        echo "ERROR: LAN topology guard helper is missing." >&2
        return 1
    fi
    if ! /bin/bash "$TOPOLOGY_REFRESH" "$@"; then
        echo "ERROR: LAN topology guard refresh failed." >&2
        return 1
    fi
    if ! grep -qx 'STATE=ACTIVE' "$XDP_HEALTH_FILE" 2>/dev/null \
       || [ ! -x "$XDP_CONTROLLER" ] \
       || ! "$XDP_CONTROLLER" status >/dev/null 2>&1; then
        echo "ERROR: LAN policy change refused because the XDP/TC boundary is degraded." >&2
        return 1
    fi
}

peer_state_file() {
    local ip="$1"
    [ "$(canonicalize_ip "$ip" || true)" = "$ip" ] \
        && [ "$(validate_ip_family "$ip")" = ipv4 ] || return 1
    printf '%s/%s.state\n' "$LAN_PEER_STATE_DIR" \
        "$(printf '%s' "$ip" | tr ':.' '__')"
}

load_ipv4_peer_state() {
    local requested_ip="$1" state line key value count=0 metadata canonical
    local seen_version=0 seen_ip=0 seen_iface=0 seen_mac=0 seen_direction=0
    local seen_protocol=0 seen_port_start=0 seen_port_end=0
    trusted_state_directory "$LAN_PEER_STATE_DIR" 700 || return 1
    state=$(peer_state_file "$requested_ip")
    [ -f "$state" ] && [ ! -L "$state" ] || return 1
    metadata=$(stat -c '%u:%g:%a:%h:%F' "$state") || return 1
    [ "$metadata" = "$LAN_STATE_UID:$LAN_STATE_GID:600:1:regular file" ] \
        || return 1
    PEER_STATE_VERSION="" PEER_STATE_IP="" PEER_STATE_IFACE=""
    PEER_STATE_MAC="" PEER_STATE_DIRECTION="" PEER_STATE_PROTOCOL=""
    PEER_STATE_PORT_START="" PEER_STATE_PORT_END=""
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in *=*) ;; *) return 1 ;; esac
        key=${line%%=*}; value=${line#*=}
        case "$key" in
            VERSION) [ "$seen_version" -eq 0 ] || return 1; seen_version=1; PEER_STATE_VERSION=$value ;;
            IP) [ "$seen_ip" -eq 0 ] || return 1; seen_ip=1; PEER_STATE_IP=$value ;;
            IFACE) [ "$seen_iface" -eq 0 ] || return 1; seen_iface=1; PEER_STATE_IFACE=$value ;;
            MAC) [ "$seen_mac" -eq 0 ] || return 1; seen_mac=1; PEER_STATE_MAC=${value,,} ;;
            DIRECTION) [ "$seen_direction" -eq 0 ] || return 1; seen_direction=1; PEER_STATE_DIRECTION=$value ;;
            PROTOCOL) [ "$seen_protocol" -eq 0 ] || return 1; seen_protocol=1; PEER_STATE_PROTOCOL=$value ;;
            PORT_START) [ "$seen_port_start" -eq 0 ] || return 1; seen_port_start=1; PEER_STATE_PORT_START=$value ;;
            PORT_END) [ "$seen_port_end" -eq 0 ] || return 1; seen_port_end=1; PEER_STATE_PORT_END=$value ;;
            *) return 1 ;;
        esac
        count=$((count + 1))
    done < "$state"
    [ "$count" -eq 8 ] && [ "$PEER_STATE_VERSION" = 2 ] || return 1
    canonical=$(canonicalize_ip "$PEER_STATE_IP" || true)
    [ "$canonical" = "$requested_ip" ] || return 1
    [[ "$PEER_STATE_IFACE" =~ ^[a-zA-Z0-9_.-]{1,15}$ ]] || return 1
    [[ "$PEER_STATE_MAC" =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]] || return 1
    validate_direction_selector "$PEER_STATE_DIRECTION" "$PEER_STATE_PROTOCOL" \
        "$PEER_STATE_PORT_START" "$PEER_STATE_PORT_END"
}

write_ipv4_peer_state() {
    local ip="$1" iface="$2" mac="${3,,}" direction="$4" protocol="$5"
    local port_start="$6" port_end="$7" state tmp
    [ "$(canonicalize_ip "$ip" || true)" = "$ip" ] \
        && [ "$(validate_ip_family "$ip")" = ipv4 ] || return 1
    [[ "$iface" =~ ^[a-zA-Z0-9_.-]{1,15}$ ]] || return 1
    [[ "$mac" =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]] || return 1
    validate_direction_selector "$direction" "$protocol" "$port_start" "$port_end" \
        || return 1
    ensure_state_directory "$LAN_PEER_STATE_DIR" 700 || return 1
    state=$(peer_state_file "$ip")
    tmp=$(mktemp "$LAN_PEER_STATE_DIR/.peer.XXXXXX") || return 1
    if ! printf '%s\n' \
        'VERSION=2' \
        "IP=$ip" \
        "IFACE=$iface" \
        "MAC=$mac" \
        "DIRECTION=$direction" \
        "PROTOCOL=$protocol" \
        "PORT_START=$port_start" \
        "PORT_END=$port_end" > "$tmp"; then
        rm -f -- "$tmp"
        return 1
    fi
    chmod 0600 "$tmp" || { rm -f -- "$tmp"; return 1; }
    chown "$LAN_STATE_UID:$LAN_STATE_GID" "$tmp" \
        || { rm -f -- "$tmp"; return 1; }
    [ "$(stat -c '%u:%g:%a:%h:%F' "$tmp")" = \
        "$LAN_STATE_UID:$LAN_STATE_GID:600:1:regular file" ] || {
        rm -f -- "$tmp"
        return 1
    }
    mv -fT "$tmp" "$state" || { rm -f -- "$tmp"; return 1; }
    [ "$(stat -c '%u:%g:%a:%h:%F' "$state")" = \
        "$LAN_STATE_UID:$LAN_STATE_GID:600:1:regular file" ] \
        && load_ipv4_peer_state "$ip" \
        && [ "$PEER_STATE_IFACE" = "$iface" ] \
        && [ "$PEER_STATE_MAC" = "$mac" ] \
        && [ "$PEER_STATE_DIRECTION" = "$direction" ] \
        && [ "$PEER_STATE_PROTOCOL" = "$protocol" ] \
        && [ "$PEER_STATE_PORT_START" = "$port_start" ] \
        && [ "$PEER_STATE_PORT_END" = "$port_end" ]
}

load_protected_gateway_state() {
    local line key value count=0 metadata canonical
    local seen_enabled=0 seen_iface=0 seen_ip=0 seen_mac=0 seen_learned=0
    # The production path is a multi-file M04 contract, not an isolated data
    # file. Test fixtures use a private state path and validate the parser
    # directly; the installed path must first pass the authoritative guard.
    if [ "$ARP_HARDENING_STATE" = \
         /var/lib/noid-privacy/arp-hardening.state ]; then
        [ -x "$ARP_STATE_GUARD" ] && "$ARP_STATE_GUARD" || return 1
    fi
    [ -f "$ARP_HARDENING_STATE" ] && [ ! -L "$ARP_HARDENING_STATE" ] \
        || return 1
    metadata=$(stat -c '%u:%g:%a:%h:%F' "$ARP_HARDENING_STATE") || return 1
    [ "$metadata" = "$LAN_STATE_UID:$LAN_STATE_GID:644:1:regular file" ] \
        || return 1
    PROTECTED_GATEWAY_ENABLED="" PROTECTED_GATEWAY_IFACE=""
    PROTECTED_GATEWAY_IP="" PROTECTED_GATEWAY_MAC=""
    PROTECTED_GATEWAY_LEARNED_AT=""
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in *=*) ;; *) return 1 ;; esac
        key=${line%%=*}; value=${line#*=}
        case "$key" in
            ENABLED)
                [ "$seen_enabled" -eq 0 ] || return 1
                seen_enabled=1; PROTECTED_GATEWAY_ENABLED=$value
                ;;
            WAN_IFACE)
                [ "$seen_iface" -eq 0 ] || return 1
                seen_iface=1; PROTECTED_GATEWAY_IFACE=$value
                ;;
            GATEWAY_IP)
                [ "$seen_ip" -eq 0 ] || return 1
                seen_ip=1; PROTECTED_GATEWAY_IP=$value
                ;;
            GATEWAY_MAC)
                [ "$seen_mac" -eq 0 ] || return 1
                seen_mac=1; PROTECTED_GATEWAY_MAC=${value,,}
                ;;
            LEARNED_AT)
                [ "$seen_learned" -eq 0 ] || return 1
                seen_learned=1; PROTECTED_GATEWAY_LEARNED_AT=$value
                ;;
            *) return 1 ;;
        esac
        count=$((count + 1))
    done < "$ARP_HARDENING_STATE"
    [ "$count" -eq 5 ] \
        && [[ "$PROTECTED_GATEWAY_ENABLED" =~ ^[01]$ ]] || return 1
    [[ "$PROTECTED_GATEWAY_IFACE" =~ ^[a-zA-Z0-9_.-]{1,15}$ ]] || return 1
    canonical=$(canonicalize_ip "$PROTECTED_GATEWAY_IP" || true)
    [ "$canonical" = "$PROTECTED_GATEWAY_IP" ] \
        && [ "$(validate_ip_family "$PROTECTED_GATEWAY_IP")" = ipv4 ] || return 1
    [[ "$PROTECTED_GATEWAY_MAC" =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]] || return 1
    [[ "$PROTECTED_GATEWAY_LEARNED_AT" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] \
        || return 1
}

exact_permanent_neighbour_mac() {
    local ip="$1" iface="$2" records record_count
    records=$(ip -4 neigh show to "$ip" dev "$iface" 2>/dev/null) || return 1
    record_count=$(awk 'NF { count++ } END { print count + 0 }' <<< "$records") \
        || return 1
    case "$record_count" in
        0) return 0 ;;
        1) ;;
        *) return 1 ;;
    esac
    awk -v ip="$ip" '
        NR == 1 && $1 == ip {
            mac=""
            for (i=1; i<=NF; i++) if ($i == "lladdr") mac=tolower($(i+1))
            if (mac != "" && tolower($NF) == "permanent") print mac
        }
    ' <<< "$records"
}

remove_ipv4_peer_state() {
    local ip="$1" state iface mac observed
    if [ ! -e "$LAN_PEER_STATE_DIR" ] && [ ! -L "$LAN_PEER_STATE_DIR" ]; then
        return 0
    fi
    trusted_state_directory "$LAN_PEER_STATE_DIR" 700 || return 1
    state=$(peer_state_file "$ip")
    iface="" mac=""
    if load_ipv4_peer_state "$ip"; then
        iface=$PEER_STATE_IFACE
        mac=$PEER_STATE_MAC
    fi
    if [[ "$iface" =~ ^[a-zA-Z0-9_.-]{1,15}$ ]] \
       && [[ "$mac" =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]]; then
        if load_protected_gateway_state; then
            if [ "$PROTECTED_GATEWAY_ENABLED" = 1 ] \
               && [ "$ip" = "$PROTECTED_GATEWAY_IP" ] \
               && [ "$iface" = "$PROTECTED_GATEWAY_IFACE" ]; then
                ip neigh replace "$ip" lladdr "$PROTECTED_GATEWAY_MAC" \
                    dev "$iface" nud permanent || return 1
                observed=$(exact_permanent_neighbour_mac "$ip" "$iface") \
                    || return 1
                [ "$observed" = "$PROTECTED_GATEWAY_MAC" ] || return 1
            else
                observed=$(exact_permanent_neighbour_mac "$ip" "$iface") \
                    || return 1
                if [ "$observed" = "$mac" ]; then
                    ip neigh del "$ip" dev "$iface" || return 1
                    observed=$(exact_permanent_neighbour_mac "$ip" "$iface") \
                        || return 1
                    [ "$observed" != "$mac" ] || return 1
                fi
            fi
        elif [ -e "$ARP_HARDENING_STATE" ] || [ -L "$ARP_HARDENING_STATE" ]; then
            echo "ERROR: protected gateway state is invalid; preserving the kernel neighbour and peer evidence after LAN policy revoke." >&2
            return 1
        else
            observed=$(exact_permanent_neighbour_mac "$ip" "$iface") \
                || return 1
            if [ "$observed" = "$mac" ]; then
                ip neigh del "$ip" dev "$iface" || return 1
                observed=$(exact_permanent_neighbour_mac "$ip" "$iface") \
                    || return 1
                [ "$observed" != "$mac" ] || return 1
            fi
        fi
    fi
    rm -f -- "$state" || return 1
    [ ! -e "$state" ] && [ ! -L "$state" ]
}

verify_ip_exception_runtime() {
    local ip="$1" family="$2" topo_set wan_set state iface mac neigh selector_set
    if [ "$family" = "ipv4" ]; then
        topo_set=allowed_v4
        wan_set=lan_exceptions_v4
    else
        topo_set=allowed_v6
        wan_set=lan_exceptions_v6
    fi
    ip_exception_exists "$ip" || return 1
    load_exception_state "$ip" || return 1
    [ "$EX_STATE_FAMILY" = "$family" ] || return 1
    firewall_contract_exists "$ip" permanent || return 1
    firewall_contract_exists "$ip" runtime || return 1
    case "$EX_STATE_DIRECTION" in
        outbound|both)
            outbound_rule_exists "$ip" runtime || return 1
            nft get element inet noid_lan_topology "$topo_set" "{ $ip }" \
                >/dev/null || return 1
            if nft list table inet noid_wan_strict >/dev/null 2>&1; then
                nft get element inet noid_wan_strict "$wan_set" "{ $ip }" \
                    >/dev/null || return 1
            fi
            ;;
        inbound)
            outbound_rule_absent "$ip" runtime || return 1
            ! nft get element inet noid_lan_topology "$topo_set" "{ $ip }" \
                >/dev/null 2>&1 || return 1
            ;;
    esac
    if [ "$family" = "ipv4" ]; then
        load_ipv4_peer_state "$ip" || return 1
        iface=$PEER_STATE_IFACE
        mac=$PEER_STATE_MAC
        [ "$PEER_STATE_DIRECTION" = "$EX_STATE_DIRECTION" ] || return 1
        [ "$PEER_STATE_PROTOCOL" = "$EX_STATE_PROTOCOL" ] || return 1
        [ "$PEER_STATE_PORT_START" = "$EX_STATE_PORT_START" ] || return 1
        [ "$PEER_STATE_PORT_END" = "$EX_STATE_PORT_END" ] || return 1
        neigh=$(exact_permanent_neighbour_mac "$ip" "$iface") || return 1
        [ "$neigh" = "$mac" ] || return 1
        case "$EX_STATE_DIRECTION" in
            inbound|both)
                inbound_rule_exists "$ip" "$EX_STATE_PROTOCOL" \
                    "$EX_STATE_PORT_START" "$EX_STATE_PORT_END" runtime || return 1
                nft get element inet noid_lan_topology inbound_peers_v4 \
                    "{ $ip }" >/dev/null || return 1
                selector_set="inbound_${EX_STATE_PROTOCOL}_v4"
                nft get element inet noid_lan_topology "$selector_set" \
                    "{ \"$iface\" . $ip . $EX_STATE_PORT_START }" >/dev/null \
                    || return 1
                nft get element inet noid_lan_topology "$selector_set" \
                    "{ \"$iface\" . $ip . $EX_STATE_PORT_END }" >/dev/null \
                    || return 1
                if nft list table inet noid_wan_strict >/dev/null 2>&1; then
                    nft get element inet noid_wan_strict lan_inbound_peers_v4 \
                        "{ $ip }" >/dev/null || return 1
                fi
                ;;
            outbound)
                any_inbound_rule_for_ip_absent "$ip" runtime || return 1
                ! nft get element inet noid_lan_topology inbound_peers_v4 \
                    "{ $ip }" >/dev/null 2>&1 || return 1
                ;;
        esac
    fi
    if [ "$EX_STATE_KIND" = temporary ] && exception_is_expired; then
        return 1
    fi
    return 0
}

verify_ip_exception_absent() {
    local ip="$1" family="$2" topo_set wan_set
    if [ "$family" = "ipv4" ]; then
        topo_set=allowed_v4
        wan_set=lan_exceptions_v4
    else
        topo_set=allowed_v6
        wan_set=lan_exceptions_v6
    fi
    ip_exception_absent "$ip" || return 1
    outbound_rule_absent "$ip" permanent || return 1
    outbound_rule_absent "$ip" runtime || return 1
    any_inbound_rule_for_ip_absent "$ip" permanent || return 1
    any_inbound_rule_for_ip_absent "$ip" runtime || return 1
    ! nft get element inet noid_lan_topology "$topo_set" "{ $ip }" >/dev/null 2>&1 \
        || return 1
    if nft list table inet noid_wan_strict >/dev/null 2>&1; then
        ! nft get element inet noid_wan_strict "$wan_set" "{ $ip }" >/dev/null 2>&1 \
            || return 1
        ! nft get element inet noid_wan_strict lan_inbound_peers_v4 \
            "{ $ip }" >/dev/null 2>&1 || return 1
    fi
    if [ "$family" = "ipv4" ]; then
        [ ! -e "$(peer_state_file "$ip")" ] \
            && [ ! -L "$(peer_state_file "$ip")" ] || return 1
        ! nft get element inet noid_lan_topology inbound_peers_v4 \
            "{ $ip }" >/dev/null 2>&1 || return 1
    fi
    [ ! -e "$(exception_state_file "$ip")" ] \
        && [ ! -L "$(exception_state_file "$ip")" ] || return 1
    return 0
}

learn_ipv4_peer() {
    local ip="$1" direction="$2" protocol="$3" port_start="$4" port_end="$5"
    local route_line iface cidrs first_output second_output mac_count
    local neighbor_output neighbor_count
    local observed cleanup_failed=0
    local -a first_macs=() second_macs=() neighbor_macs=()

    route_line=$(ip -4 route get "$ip" 2>/dev/null | head -1) || true
    iface=$(printf '%s\n' "$route_line" | awk '
        {for (i=1; i<=NF; i++) if ($i=="dev") {print $(i+1); exit}}')
    [[ "$iface" =~ ^[a-zA-Z0-9_.-]{1,15}$ ]] || {
        echo "ERROR: no route/interface for IPv4 peer $ip" >&2
        return 1
    }
    [ -d "$SYS_CLASS_NET/$iface/device" ] || {
        echo "ERROR: $ip is not routed over a hardware-backed interface" >&2
        return 1
    }
    cidrs=$(ip -o -4 addr show dev "$iface" scope global 2>/dev/null \
        | awk '{print $4}')
    # shellcheck disable=SC2086 # one reviewed argv per whitespace-free CIDR.
    if ! python3 - "$ip" $cidrs <<'ONLINK_PY'
import ipaddress, sys
peer = ipaddress.ip_address(sys.argv[1])
sys.exit(0 if any(peer in ipaddress.ip_interface(x).network for x in sys.argv[2:]) else 1)
ONLINK_PY
    then
        echo "ERROR: $ip is not directly attached; refusing a LAN exception to a routed/WAN address" >&2
        return 1
    fi
    if ! command -v arping >/dev/null 2>&1; then
        echo "ERROR: arping is required for explicit LAN peer trust establishment" >&2
        return 1
    fi
    # Snapshot any independent kernel neighbour before the AF_PACKET probe.
    # Fedora arping does not populate an empty cache, so emptiness is a normal
    # first-contact state rather than an error.
    neighbor_output=$(ip -4 neigh show to "$ip" dev "$iface" 2>/dev/null) \
        || return 1
    neighbor_count=$(grep -c . <<< "$neighbor_output" || true)
    [ "$neighbor_count" -le 1 ] || {
        echo "ERROR: expected at most one device-scoped kernel neighbour for $ip" >&2
        return 1
    }
    mapfile -t neighbor_macs < <(awk -v ip="$ip" '
        NR == 1 && $1 == ip {
            for (i=1; i<=NF; i++) {
                if ($i == "lladdr") mac=tolower($(i+1))
            }
            if (mac != "") print mac
        }
    ' <<< "$neighbor_output" | sort -u)
    if [ "$neighbor_count" -eq 1 ] \
            && [ "${#neighbor_macs[@]}" -ne 1 ]; then
        echo "ERROR: kernel neighbour identity is incomplete for $ip" >&2
        return 1
    fi

    first_output=""
    if ! first_output=$(arping -c 3 -w 5 -I "$iface" "$ip" 2>&1); then
        echo "ERROR: no ARP response from explicitly selected peer $ip" >&2
        return 1
    fi

    mapfile -t first_macs < <(printf '%s\n' "$first_output" \
        | grep -Eio '([0-9a-f]{2}:){5}[0-9a-f]{2}' | tr '[:upper:]' '[:lower:]' | sort -u)
    mac_count=${#first_macs[@]}
    if [ "$mac_count" -ne 1 ]; then
        echo "ERROR: expected exactly one peer MAC for $ip, observed $mac_count" >&2
        return 1
    fi

    if [ "$neighbor_count" -eq 1 ]; then
        [ "${neighbor_macs[0]}" = "${first_macs[0]}" ] || {
            echo "ERROR: raw ARP and kernel neighbour identity disagree for $ip" >&2
            return 1
        }
    else
        # An empty cache requires a second, time-separated bounded observation.
        # Never synthesize the kernel cross-check from the first raw reply.
        sleep 1
        second_output=""
        if ! second_output=$(arping -c 3 -w 5 -I "$iface" "$ip" 2>&1); then
            echo "ERROR: no second ARP response from explicitly selected peer $ip" >&2
            return 1
        fi
        mapfile -t second_macs < <(printf '%s\n' "$second_output" \
            | grep -Eio '([0-9a-f]{2}:){5}[0-9a-f]{2}' \
            | tr '[:upper:]' '[:lower:]' | sort -u)
        [ "${#second_macs[@]}" -eq 1 ] \
            && [ "${second_macs[0]}" = "${first_macs[0]}" ] || {
            echo "ERROR: time-separated raw ARP observations disagree for $ip" >&2
            return 1
        }
    fi

    # Publish the closed identity record first. It is not admitted by M03
    # until the matching exception record exists, so this ordering permits
    # complete cleanup if the kernel replacement or postcheck fails.
    write_ipv4_peer_state "$ip" "$iface" "${first_macs[0]}" \
        "$direction" "$protocol" "$port_start" "$port_end" || return 1
    if ! ip neigh replace "$ip" lladdr "${first_macs[0]}" \
            dev "$iface" nud permanent; then
        remove_ipv4_peer_state "$ip" || cleanup_failed=1
        [ "$cleanup_failed" -eq 0 ] || {
            echo "CRITICAL: failed peer pin left identity state behind" >&2
        }
        return 1
    fi
    observed=$(exact_permanent_neighbour_mac "$ip" "$iface" || true)
    if [ "$observed" != "${first_macs[0]}" ]; then
        remove_ipv4_peer_state "$ip" || cleanup_failed=1
        [ "$cleanup_failed" -eq 0 ] || {
            echo "CRITICAL: failed peer postcheck could not clean identity state" >&2
        }
        return 1
    fi
}

policy_has_ingress() {
    local zone="$1"
    firewall-cmd --permanent --policy="$POLICY" --list-ingress-zones 2>/dev/null \
        | tr ' ' '\n' | grep -qxF "$zone"
}

valid_global_allow_marker() {
    local dir metadata
    dir=${GLOBAL_ALLOW_MARKER%/*}
    trusted_state_directory "$dir" 755 || return 2
    if [ ! -e "$GLOBAL_ALLOW_MARKER" ] && [ ! -L "$GLOBAL_ALLOW_MARKER" ]; then
        return 1
    fi
    [ -f "$GLOBAL_ALLOW_MARKER" ] && [ ! -L "$GLOBAL_ALLOW_MARKER" ] \
        || return 2
    metadata=$(stat -c '%u:%g:%a:%h:%s' "$GLOBAL_ALLOW_MARKER") \
        || return 2
    [ "$metadata" = \
        "$LAN_STATE_UID:$LAN_STATE_GID:600:1:0" ] || return 2
}

read_global_runtime_state() {
    local dir metadata state expected_size
    dir=${GLOBAL_RUNTIME_STATE%/*}
    trusted_state_directory "$dir" 755 || return 1
    [ -f "$GLOBAL_RUNTIME_STATE" ] && [ ! -L "$GLOBAL_RUNTIME_STATE" ] \
        || return 1
    metadata=$(stat -c '%u:%g:%a:%h:%F' "$GLOBAL_RUNTIME_STATE") \
        || return 1
    [ "$metadata" = \
        "$LAN_STATE_UID:$LAN_STATE_GID:644:1:regular file" ] || return 1
    state=$(cat "$GLOBAL_RUNTIME_STATE") || return 1
    case "$state" in BLOCKED|ALLOWED|INCONSISTENT) ;; *) return 1 ;; esac
    expected_size=$((${#state} + 1))
    [ "$(stat -c '%s' "$GLOBAL_RUNTIME_STATE")" -eq "$expected_size" ] \
        || return 1
    printf '%s\n' "$state"
}

global_state() {
    local ingress runtime marker_status marker_present=0 host_attached=0
    if ! ingress=$(firewall-cmd --permanent --policy="$POLICY" \
            --list-ingress-zones 2>/dev/null); then
        printf '%s\n' INCONSISTENT
        return 1
    fi
    if printf '%s\n' "$ingress" | tr ' ' '\n' | grep -qxF HOST; then
        host_attached=1
    fi
    if valid_global_allow_marker; then
        marker_present=1
    else
        marker_status=$?
        [ "$marker_status" -eq 1 ] || {
            printf '%s\n' INCONSISTENT
            return 1
        }
    fi
    if ! runtime=$(read_global_runtime_state); then
        runtime=INCONSISTENT
    fi

    if [ "$marker_present" -eq 0 ] && [ "$host_attached" -eq 1 ] \
       && [ "$runtime" = BLOCKED ]; then
        printf '%s\n' BLOCKED
        return 0
    fi
    if [ "$marker_present" -eq 1 ] && [ "$host_attached" -eq 0 ] \
       && [ "$runtime" = ALLOWED ]; then
        printf '%s\n' ALLOWED
        return 0
    fi
    printf '%s\n' INCONSISTENT
    return 1
}

set_global_allow_marker() {
    local dir tmp
    dir=${GLOBAL_ALLOW_MARKER%/*}
    ensure_state_directory "$dir" 755 || return 1
    tmp=$(mktemp "$dir/.lan-global-allow.XXXXXX") || return 1
    chmod 0600 "$tmp" || { rm -f -- "$tmp"; return 1; }
    chown "$LAN_STATE_UID:$LAN_STATE_GID" "$tmp" \
        || { rm -f -- "$tmp"; return 1; }
    [ "$(stat -c '%u:%g:%a:%h:%s' "$tmp")" = \
        "$LAN_STATE_UID:$LAN_STATE_GID:600:1:0" ] || {
        rm -f -- "$tmp"
        return 1
    }
    mv -fT "$tmp" "$GLOBAL_ALLOW_MARKER" \
        || { rm -f -- "$tmp"; return 1; }
    valid_global_allow_marker
}

clear_global_allow_marker() {
    trusted_state_directory "${GLOBAL_ALLOW_MARKER%/*}" 755 || return 1
    rm -f -- "$GLOBAL_ALLOW_MARKER"
    [ ! -e "$GLOBAL_ALLOW_MARKER" ] && [ ! -L "$GLOBAL_ALLOW_MARKER" ]
}

restore_global_block_state() {
    if ! policy_has_ingress HOST; then
        firewall-cmd --permanent --policy="$POLICY" --add-ingress-zone=HOST \
            >/dev/null || return 1
    fi
    firewall-cmd --reload >/dev/null || return 1
    clear_global_allow_marker || return 1
    refresh_topology_guard
}

port_selector_text() {
    if [ "$1" = "$2" ]; then printf '%s\n' "$1"; else printf '%s-%s\n' "$1" "$2"; fi
}

outbound_rule_text() {
    local ip="$1" family
    family=$(validate_ip_family "$ip")
    case "$family" in ipv4|ipv6) ;; *) return 1 ;; esac
    printf 'rule priority="%s" family="%s" destination address="%s" accept\n' \
        "$ACCEPT_PRIORITY" "$family" "$ip"
}

inbound_rule_text() {
    local ports
    ports=$(port_selector_text "$3" "$4")
    printf 'rule priority="%s" family="ipv4" source address="%s" port port="%s" protocol="%s" accept\n' \
        "$ACCEPT_PRIORITY" "$1" "$ports" "$2"
}

outbound_rule_exists() {
    local ip="$1" scope="${2:-permanent}" rules
    local -a args=()
    [ "$scope" != permanent ] || args+=(--permanent)
    rules=$(firewall-cmd "${args[@]}" --policy="$POLICY" \
        --list-rich-rules 2>/dev/null) || return 2
    printf '%s\n' "$rules" \
        | grep -F "priority=\"${ACCEPT_PRIORITY}\"" \
        | grep -F "destination address=\"${ip}\"" \
        | grep -qE 'accept[[:space:]]*$'
}

outbound_rule_absent() {
    local rc
    if outbound_rule_exists "$@"; then
        return 1
    else
        rc=$?
        [ "$rc" -eq 1 ]
    fi
}

inbound_rule_exists() {
    local ip="$1" protocol="$2" port_start="$3" port_end="$4"
    local scope="${5:-permanent}" ports rules
    local -a args=()
    [ "$scope" != permanent ] || args+=(--permanent)
    ports=$(port_selector_text "$port_start" "$port_end")
    rules=$(firewall-cmd "${args[@]}" --zone="$INBOUND_ZONE" \
        --list-rich-rules 2>/dev/null) || return 2
    printf '%s\n' "$rules" \
        | grep -F "priority=\"${ACCEPT_PRIORITY}\"" \
        | grep -F "source address=\"${ip}\"" \
        | grep -F "port port=\"${ports}\" protocol=\"${protocol}\"" \
        | grep -qE 'accept[[:space:]]*$'
}

ip_exception_exists() {
    local ip="$1" rc
    if outbound_rule_exists "$ip" permanent; then
        return 0
    else
        rc=$?
        [ "$rc" -eq 1 ] || return 2
    fi
    if load_exception_state "$ip"; then
        case "$EX_STATE_DIRECTION" in
            inbound|both)
                inbound_rule_exists "$ip" "$EX_STATE_PROTOCOL" \
                    "$EX_STATE_PORT_START" "$EX_STATE_PORT_END" permanent
                return
                ;;
        esac
    fi
    return 1
}

ip_exception_absent() {
    local rc
    if ip_exception_exists "$@"; then
        return 1
    else
        rc=$?
        [ "$rc" -eq 1 ]
    fi
}

any_inbound_rule_for_ip_exists() {
    local ip="$1" scope="${2:-permanent}"
    local rules
    local -a args=()
    [ "$scope" != permanent ] || args+=(--permanent)
    rules=$(firewall-cmd "${args[@]}" --zone="$INBOUND_ZONE" \
        --list-rich-rules 2>/dev/null) || return 2
    printf '%s\n' "$rules" \
        | grep -F "priority=\"${ACCEPT_PRIORITY}\"" \
        | grep -F "source address=\"${ip}\"" \
        | grep -qE 'port port="[0-9]+(-[0-9]+)?" protocol="(tcp|udp)" accept[[:space:]]*$'
}

any_inbound_rule_for_ip_absent() {
    local rc
    if any_inbound_rule_for_ip_exists "$@"; then
        return 1
    else
        rc=$?
        [ "$rc" -eq 1 ]
    fi
}

managed_firewall_rule_exists() {
    local ip="$1" scope="${2:-permanent}" rc
    if outbound_rule_exists "$ip" "$scope"; then
        return 0
    else
        rc=$?
        [ "$rc" -eq 1 ] || return 2
    fi
    any_inbound_rule_for_ip_exists "$ip" "$scope"
}

managed_inbound_rule_count() {
    local ip="$1" scope="${2:-permanent}" rules rule count=0
    local escaped_ip=${ip//./\\.}
    local rule_re="^rule priority=\"${ACCEPT_PRIORITY}\" family=\"ipv4\" source address=\"${escaped_ip}\" port port=\"[0-9]+(-[0-9]+)?\" protocol=\"(tcp|udp)\" accept$"
    local -a args=()
    [ "$scope" != permanent ] || args+=(--permanent)
    rules=$(firewall-cmd "${args[@]}" --zone="$INBOUND_ZONE" \
        --list-rich-rules 2>/dev/null) || return 1
    while IFS= read -r rule; do
        [[ "$rule" =~ $rule_re ]] || continue
        count=$((count + 1))
    done <<< "$rules"
    printf '%s\n' "$count"
}

firewall_contract_exists() {
    local ip="$1" scope="${2:-permanent}" inbound_count
    inbound_count=$(managed_inbound_rule_count "$ip" "$scope") || return 1
    case "$EX_STATE_DIRECTION" in
        outbound)
            outbound_rule_exists "$ip" "$scope" && [ "$inbound_count" -eq 0 ]
            ;;
        inbound)
            outbound_rule_absent "$ip" "$scope" \
                && inbound_rule_exists "$ip" "$EX_STATE_PROTOCOL" \
                    "$EX_STATE_PORT_START" "$EX_STATE_PORT_END" "$scope" \
                && [ "$inbound_count" -eq 1 ]
            ;;
        both)
            outbound_rule_exists "$ip" "$scope" \
                && inbound_rule_exists "$ip" "$EX_STATE_PROTOCOL" \
                    "$EX_STATE_PORT_START" "$EX_STATE_PORT_END" "$scope" \
                && [ "$inbound_count" -eq 1 ]
            ;;
        *) return 1 ;;
    esac
}

list_managed_firewall_ips() {
    local scope rules rule ip canonical rule_family
    local outbound_re="^rule priority=\"${ACCEPT_PRIORITY}\" family=\"(ipv4|ipv6)\" destination address=\"([0-9A-Fa-f:.]+)\" accept$"
    local inbound_re="^rule priority=\"${ACCEPT_PRIORITY}\" family=\"ipv4\" source address=\"([0-9.]+)\" port port=\"[0-9]+(-[0-9]+)?\" protocol=\"(tcp|udp)\" accept$"
    local -a args=()
    for scope in permanent runtime; do
        args=()
        [ "$scope" != permanent ] || args+=(--permanent)
        rules=$(firewall-cmd "${args[@]}" --policy="$POLICY" \
            --list-rich-rules 2>/dev/null) || return 1
        while IFS= read -r rule; do
            [[ "$rule" =~ $outbound_re ]] || continue
            rule_family=${BASH_REMATCH[1]}
            ip=${BASH_REMATCH[2]}
            canonical=$(canonicalize_ip "$ip" || true)
            [ "$canonical" = "$ip" ] \
                && [ "$(validate_ip_family "$ip")" = "$rule_family" ] || return 1
            printf '%s\n' "$ip"
        done <<< "$rules"
        rules=$(firewall-cmd "${args[@]}" --zone="$INBOUND_ZONE" \
            --list-rich-rules 2>/dev/null) || return 1
        while IFS= read -r rule; do
            [[ "$rule" =~ $inbound_re ]] || continue
            ip=${BASH_REMATCH[1]}
            canonical=$(canonicalize_ip "$ip" || true)
            [ "$canonical" = "$ip" ] || return 1
            printf '%s\n' "$ip"
        done <<< "$rules"
    done | sort -u
}

remove_all_managed_firewall_rules_for_ip() {
    local ip="$1" scope rules rule failed=0 escaped_ip
    local outbound_rule inbound_re
    local -a args=()
    escaped_ip=${ip//./\\.}
    outbound_rule=$(outbound_rule_text "$ip")
    inbound_re="^rule priority=\"${ACCEPT_PRIORITY}\" family=\"ipv4\" source address=\"${escaped_ip}\" port port=\"[0-9]+(-[0-9]+)?\" protocol=\"(tcp|udp)\" accept$"
    for scope in permanent runtime; do
        args=()
        [ "$scope" != permanent ] || args+=(--permanent)
        rules=$(firewall-cmd "${args[@]}" --policy="$POLICY" \
            --list-rich-rules 2>/dev/null) || { failed=1; continue; }
        if printf '%s\n' "$rules" | grep -Fxq -- "$outbound_rule"; then
            firewall-cmd "${args[@]}" --policy="$POLICY" \
                --remove-rich-rule="$outbound_rule" >/dev/null || failed=1
        fi
        rules=$(firewall-cmd "${args[@]}" --zone="$INBOUND_ZONE" \
            --list-rich-rules 2>/dev/null) || { failed=1; continue; }
        while IFS= read -r rule; do
            [[ "$rule" =~ $inbound_re ]] || continue
            firewall-cmd "${args[@]}" --zone="$INBOUND_ZONE" \
                --remove-rich-rule="$rule" >/dev/null || failed=1
        done <<< "$rules"
    done
    [ "$failed" -eq 0 ]
}

remove_loaded_firewall_rules() {
    local ip="$1" failed=0 rule query_rc
    case "$EX_STATE_DIRECTION" in
        outbound|both)
            rule=$(outbound_rule_text "$ip") || return 1
            if outbound_rule_exists "$ip" permanent; then
                firewall-cmd --permanent --policy="$POLICY" \
                    --remove-rich-rule="$rule" >/dev/null || failed=1
            else
                query_rc=$?
                [ "$query_rc" -eq 1 ] || failed=1
            fi
            if outbound_rule_exists "$ip" runtime; then
                firewall-cmd --policy="$POLICY" --remove-rich-rule="$rule" \
                    >/dev/null || failed=1
            else
                query_rc=$?
                [ "$query_rc" -eq 1 ] || failed=1
            fi
            ;;
    esac
    case "$EX_STATE_DIRECTION" in
        inbound|both)
            rule=$(inbound_rule_text "$ip" "$EX_STATE_PROTOCOL" \
                "$EX_STATE_PORT_START" "$EX_STATE_PORT_END")
            if inbound_rule_exists "$ip" "$EX_STATE_PROTOCOL" \
                    "$EX_STATE_PORT_START" "$EX_STATE_PORT_END" permanent; then
                firewall-cmd --permanent --zone="$INBOUND_ZONE" \
                    --remove-rich-rule="$rule" >/dev/null || failed=1
            else
                query_rc=$?
                [ "$query_rc" -eq 1 ] || failed=1
            fi
            if inbound_rule_exists "$ip" "$EX_STATE_PROTOCOL" \
                    "$EX_STATE_PORT_START" "$EX_STATE_PORT_END" runtime; then
                firewall-cmd --zone="$INBOUND_ZONE" --remove-rich-rule="$rule" \
                    >/dev/null || failed=1
            else
                query_rc=$?
                [ "$query_rc" -eq 1 ] || failed=1
            fi
            ;;
    esac
    [ "$failed" -eq 0 ]
}

add_loaded_firewall_rules() {
    local ip="$1" rule
    case "$EX_STATE_DIRECTION" in
        outbound|both)
            rule=$(outbound_rule_text "$ip")
            firewall-cmd --permanent --policy="$POLICY" \
                --add-rich-rule="$rule" >/dev/null || return 1
            ;;
    esac
    case "$EX_STATE_DIRECTION" in
        inbound|both)
            rule=$(inbound_rule_text "$ip" "$EX_STATE_PROTOCOL" \
                "$EX_STATE_PORT_START" "$EX_STATE_PORT_END")
            firewall-cmd --permanent --zone="$INBOUND_ZONE" \
                --add-rich-rule="$rule" >/dev/null || return 1
            ;;
    esac
    firewall-cmd --reload >/dev/null || return 1
}

rollback_ip_exception_fail_closed() {
    local ip="$1" family="$2" rollback_failed=0
    # Close the earliest raw-packet permission before touching any later
    # firewalld/state layer. Continue narrowing even if this pre-step fails,
    # but retain the failure so the caller stops networking conservatively.
    refresh_topology_guard --exclude-peer "$ip" \
        --invalidate-peer-flows "$ip" --require-xdp \
        || rollback_failed=1
    if load_exception_state "$ip"; then
        remove_loaded_firewall_rules "$ip" || rollback_failed=1
    else
        remove_all_managed_firewall_rules_for_ip "$ip" || rollback_failed=1
    fi
    firewall-cmd --reload >/dev/null || rollback_failed=1
    if [ "$family" = "ipv4" ]; then
        remove_ipv4_peer_state "$ip" || rollback_failed=1
    fi
    remove_exception_state "$ip" || rollback_failed=1
    refresh_topology_guard --require-xdp || rollback_failed=1
    verify_ip_exception_absent "$ip" "$family" || rollback_failed=1
    [ "$rollback_failed" -eq 0 ]
}

# Print all closed v2 per-IP exception records (one canonical IP per line).
list_per_ip_raw() {
    local exclude="${1:-}" state_file candidate canonical
    if [ ! -e "$LAN_EXCEPTION_STATE_DIR" ] \
       && [ ! -L "$LAN_EXCEPTION_STATE_DIR" ]; then
        return 0
    fi
    trusted_state_directory "$LAN_EXCEPTION_STATE_DIR" 755 || return 1
    for state_file in "$LAN_EXCEPTION_STATE_DIR"/*.state; do
        [ -e "$state_file" ] || [ -L "$state_file" ] || continue
        [ -f "$state_file" ] && [ ! -L "$state_file" ] || return 1
        candidate=$(awk -F= '$1=="IP" {print $2}' "$state_file" 2>/dev/null) \
            || return 1
        canonical=$(canonicalize_ip "$candidate" || true)
        [ -n "$canonical" ] \
            && [ "$(exception_state_file "$canonical")" = "$state_file" ] || return 1
        [ "$canonical" != "$exclude" ] || continue
        load_exception_state "$canonical" || return 1
        printf '%s\n' "$canonical"
    done | sort -u
}

next_temporary_schedule() {
    local exceptions ip now boot_id boottime wall_remaining mono_remaining
    local next_epoch=0 next_delay=0
    now=$(now_epoch)
    boot_id=$(current_boot_id)
    boottime=$(current_boottime)
    is_uint "$now" && is_uint "$boottime" \
        && [[ "$boot_id" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] \
        || return 1
    boot_id=${boot_id,,}
    exceptions=$(list_per_ip_raw) || return 1
    while IFS= read -r ip; do
        [ -n "$ip" ] || continue
        load_exception_state "$ip" || return 1
        [ "$EX_STATE_KIND" = temporary ] || continue

        # The caller must revoke an already-expired record before publishing
        # another deadline. Refusing it here prevents a stale grant from being
        # silently converted into a later timer.
        [ "$now" -ge "$EX_STATE_CREATED" ] \
            && [ "$now" -lt "$EX_STATE_EXPIRES" ] || return 1
        wall_remaining=$((EX_STATE_EXPIRES - now))
        mono_remaining=$wall_remaining
        if [ "$boot_id" = "$EX_STATE_BOOT_ID" ]; then
            [ "$boottime" -ge "$EX_STATE_BOOTTIME" ] || return 1
            mono_remaining=$((EX_STATE_DURATION - (boottime - EX_STATE_BOOTTIME)))
            [ "$mono_remaining" -gt 0 ] || return 1
            [ "$mono_remaining" -le "$wall_remaining" ] \
                || mono_remaining=$wall_remaining
        fi
        if [ "$next_epoch" -eq 0 ] \
           || [ "$EX_STATE_EXPIRES" -lt "$next_epoch" ]; then
            next_epoch=$EX_STATE_EXPIRES
        fi
        if [ "$next_delay" -eq 0 ] \
           || [ "$mono_remaining" -lt "$next_delay" ]; then
            next_delay=$mono_remaining
        fi
    done <<< "$exceptions"
    if [ "$next_epoch" -gt 0 ]; then
        printf '%s\t%s\n' "$next_epoch" "$next_delay"
    fi
}

publish_expiry_schedule() {
    local epoch="$1" delay="$2" dir tmp metadata
    is_uint "$epoch" && is_uint "$delay" \
        && [ "$epoch" -gt 0 ] && [ "$delay" -gt 0 ] || return 1
    dir=${LAN_EXCEPTION_SCHEDULE_FILE%/*}
    ensure_state_directory "$dir" 755 || return 1
    tmp=$(mktemp "$dir/.lan-expiry-schedule.XXXXXX") || return 1
    if ! printf '%s\n' \
        'VERSION=1' \
        "EPOCH=$epoch" \
        "MONOTONIC_DELAY_SEC=$delay" > "$tmp"; then
        rm -f -- "$tmp"
        return 1
    fi
    chmod 0600 "$tmp" || { rm -f -- "$tmp"; return 1; }
    chown "$LAN_STATE_UID:$LAN_STATE_GID" "$tmp" \
        || { rm -f -- "$tmp"; return 1; }
    metadata=$(stat -c '%u:%g:%a:%h:%F' "$tmp") || {
        rm -f -- "$tmp"
        return 1
    }
    [ "$metadata" = \
        "$LAN_STATE_UID:$LAN_STATE_GID:600:1:regular file" ] || {
        rm -f -- "$tmp"
        return 1
    }
    mv -fT "$tmp" "$LAN_EXCEPTION_SCHEDULE_FILE" \
        || { rm -f -- "$tmp"; return 1; }
    [ "$(stat -c '%u:%g:%a:%h:%F' "$LAN_EXCEPTION_SCHEDULE_FILE")" = \
        "$LAN_STATE_UID:$LAN_STATE_GID:600:1:regular file" ]
}

clear_expiry_schedule() {
    local dir
    dir=${LAN_EXCEPTION_SCHEDULE_FILE%/*}
    if [ ! -e "$dir" ] && [ ! -L "$dir" ]; then
        return 0
    fi
    trusted_state_directory "$dir" 755 || return 1
    if [ -L "$LAN_EXCEPTION_SCHEDULE_FILE" ]; then
        return 1
    fi
    rm -f -- "$LAN_EXCEPTION_SCHEDULE_FILE"
    [ ! -e "$LAN_EXCEPTION_SCHEDULE_FILE" ] \
        && [ ! -L "$LAN_EXCEPTION_SCHEDULE_FILE" ]
}

sync_expiry_timer() {
    local schedule epoch delay
    schedule=$(next_temporary_schedule) || return 1
    systemctl stop "$LAN_EXCEPTION_TIMER" || return 1
    if [ -z "$schedule" ]; then
        clear_expiry_schedule || return 1
        systemctl daemon-reload
        return
    fi
    IFS=$'\t' read -r epoch delay <<< "$schedule"
    publish_expiry_schedule "$epoch" "$delay" || return 1
    systemctl daemon-reload || return 1
    systemctl start "$LAN_EXCEPTION_TIMER" \
        && systemctl is-active "$LAN_EXCEPTION_TIMER" >/dev/null 2>&1
}

add_ip_exception() {
    local ip="$1" kind="${2:-permanent}" duration="${3:-0}"
    local direction="${4:-outbound}" protocol="${5:-none}"
    local port_start="${6:-0}" port_end="${7:-0}"
    local family state
    case "$kind" in permanent|temporary) ;; *) return 1 ;; esac
    if ! state=$(global_state) || [ "$state" != BLOCKED ]; then
        echo "ERROR: per-IP exceptions require the verified default BLOCKED mode; turn global allow off first." >&2
        exit 1
    fi
    ip=$(canonicalize_ip "$ip" || true)
    family=$(validate_ip_family "$ip")
    [ -n "$family" ] || { echo "ERROR: Invalid IP address: $ip" >&2; exit 1; }
    if [ "$family" != ipv4 ]; then
        echo "ERROR: IPv6 per-IP LAN exceptions are unsupported: the mandatory XDP boundary has no authenticated IPv6/NDP peer return-flow contract. No rule was added." >&2
        return 1
    fi
    if ! validate_direction_selector "$direction" "$protocol" \
            "$port_start" "$port_end"; then
        echo "ERROR: invalid LAN direction/protocol/port selector" >&2
        return 1
    fi

    if [ -e "$(exception_state_file "$ip")" ] \
       || [ -L "$(exception_state_file "$ip")" ]; then
        load_exception_state "$ip" || {
            echo "ERROR: existing LAN exception metadata is invalid; refusing an unsafe edit" >&2
            return 1
        }
        # Remove the peer from the earliest XDP generation and later nft/WAN
        # sets before touching its old final firewalld permits. This temporary
        # state is deliberately fail-closed and makes edit a narrowing-first
        # transaction rather than a stale-broad-allow window.
        if ! refresh_topology_guard --exclude-peer "$ip" \
                --invalidate-peer-flows "$ip" --require-xdp; then
            echo "ERROR: existing LAN exception could not be quiesced; edit aborted" >&2
            return 1
        fi
        if ! remove_loaded_firewall_rules "$ip" \
           || ! firewall-cmd --reload >/dev/null; then
            echo "CRITICAL: old LAN exception could not be removed after XDP quiesce; stopping NetworkManager." >&2
            systemctl stop NetworkManager.service
            return 1
        fi
    fi

    # Every exception is restricted to a directly attached, exact IPv4/MAC/
    # interface identity. Re-learning on edit prevents a stale identity from
    # being silently carried into a newly widened selector.
    if ! learn_ipv4_peer "$ip" "$direction" "$protocol" "$port_start" "$port_end"; then
        rollback_ip_exception_fail_closed "$ip" "$family" \
            || systemctl stop NetworkManager.service
        return 1
    fi

    if ! write_exception_state "$ip" "$family" "$kind" "$duration" \
            "$direction" "$protocol" "$port_start" "$port_end"; then
        rollback_ip_exception_fail_closed "$ip" "$family" \
            || systemctl stop NetworkManager.service
        echo "ERROR: LAN exception metadata could not be published" >&2
        return 1
    fi

    # Publish the exact XDP map first, then the nft/WAN selector mirrors. The final
    # firewalld accepts are installed only after those earlier layers pass.
    if ! refresh_topology_guard --invalidate-peer-flows "$ip" --require-xdp; then
        if ! rollback_ip_exception_fail_closed "$ip" "$family"; then
            echo "CRITICAL: rollback could not be proven after topology failure; stopping NetworkManager." >&2
            systemctl stop NetworkManager.service
        fi
        echo "ERROR: LAN exception rolled back because topology sync failed." >&2
        return 1
    fi
    if ! load_exception_state "$ip"; then
        if ! rollback_ip_exception_fail_closed "$ip" "$family"; then
            echo "CRITICAL: rollback could not be proven after exception-state reload failure; stopping NetworkManager." >&2
            systemctl stop NetworkManager.service
        fi
        echo "ERROR: LAN exception rolled back because its durable state could not be reloaded." >&2
        return 1
    fi
    if ! add_loaded_firewall_rules "$ip"; then
        echo "ERROR: final firewalld publication failed; rolling the exception back." >&2
        rollback_ip_exception_fail_closed "$ip" "$family" \
            || systemctl stop NetworkManager.service
        return 1
    fi
    if ! verify_ip_exception_runtime "$ip" "$family"; then
        if ! rollback_ip_exception_fail_closed "$ip" "$family"; then
            echo "CRITICAL: failed exception postcondition and rollback reconciliation; stopping NetworkManager." >&2
            systemctl stop NetworkManager.service
        fi
        echo "ERROR: LAN exception rolled back because its complete runtime postcondition failed." >&2
        exit 1
    fi
    if ! sync_expiry_timer; then
        rollback_ip_exception_fail_closed "$ip" "$family" \
            || systemctl stop NetworkManager.service
        echo "ERROR: LAN exception revoked because the expiry-timer postcondition failed" >&2
        return 1
    fi
    echo "[OK] LAN exception committed: $ip ($direction, $protocol, $port_start-$port_end, $kind)."
}

revert_ip_exception() {
    local ip="$1"
    local sync_timer="${2:-yes}" family removed=0 query_rc
    ip=$(canonicalize_ip "$ip" || true)
    family=$(validate_ip_family "$ip")
    [ -n "$family" ] || { echo "ERROR: Invalid IP address: $ip" >&2; exit 1; }

    if [ -e "$(exception_state_file "$ip")" ] \
       || [ -L "$(exception_state_file "$ip")" ]; then
        load_exception_state "$ip" || {
            echo "WARN: exception metadata is invalid; applying the closed orphan-permit revoke." >&2
            revoke_invalid_ip_exception "$ip" "$family" || return 1
            removed=1
            if [ "$sync_timer" = yes ] && ! sync_expiry_timer; then
                echo "ERROR: exception is revoked, but expiry-timer state could not be reconciled" >&2
                return 1
            fi
            echo "[OK] Invalid LAN exception revoked: $ip"
            return 0
        }
        # Revoke the earliest raw-packet permission first. The helper also
        # removes later nft/WAN mirrors while the durable record is retained
        # solely as rollback evidence.
        if ! refresh_topology_guard --exclude-peer "$ip" \
                --invalidate-peer-flows "$ip" --require-xdp; then
            echo "CRITICAL: XDP-first revoke failed; stopping NetworkManager." >&2
            systemctl stop NetworkManager.service
            return 1
        fi
        if ! remove_loaded_firewall_rules "$ip" \
           || ! firewall-cmd --reload >/dev/null; then
            echo "CRITICAL: firewalld revoke failed after XDP quiesce; stopping NetworkManager." >&2
            systemctl stop NetworkManager.service
            return 1
        fi
        if [ "$family" = ipv4 ]; then
            remove_ipv4_peer_state "$ip" || return 1
        fi
        remove_exception_state "$ip" || return 1
        if ! refresh_topology_guard --require-xdp; then
            echo "ERROR: durable exception was revoked, but final topology refresh failed; networking remains stopped." >&2
            systemctl stop NetworkManager.service
            return 1
        fi
        verify_ip_exception_absent "$ip" "$family" || {
            echo "CRITICAL: durable exception was revoked but runtime allow state remains; stopping NetworkManager." >&2
            systemctl stop NetworkManager.service
            return 1
        }
        removed=1
    else
        if managed_firewall_rule_exists "$ip" permanent; then
            echo "WARN: orphan firewalld LAN permit has no valid durable selector; applying closed revoke." >&2
            revoke_invalid_ip_exception "$ip" "$family" || return 1
            removed=1
        else
            query_rc=$?
            if [ "$query_rc" -ne 1 ]; then
                echo "ERROR: cannot query firewalld while checking for an orphan LAN permit." >&2
                return 1
            fi
        fi
    fi

    if [ "$removed" -eq 1 ]; then
        echo "[OK] LAN exception reverted: $ip"
    else
        echo "[INFO] No exception found for $ip. Nothing to revert."
    fi
    if [ "$sync_timer" = yes ] && ! sync_expiry_timer; then
        echo "ERROR: exception is revoked, but expiry-timer state could not be reconciled" >&2
        return 1
    fi
}

add_temp_ip_exception() {
    local ip="$1"
    local minutes="${2:-60}"
    local direction="${3:-outbound}" protocol="${4:-none}"
    local port_start="${5:-0}" port_end="${6:-0}"
    local family

    if ! [[ "$minutes" =~ ^[0-9]+$ ]] || \
       [ "$minutes" -lt 1 ] || [ "$minutes" -gt 1440 ]; then
        echo "ERROR: Duration must be 1..1440 minutes." >&2
        exit 1
    fi

    ip=$(canonicalize_ip "$ip" || true)
    family=$(validate_ip_family "$ip")
    [ -n "$family" ] || { echo "ERROR: Invalid IP address: $ip" >&2; exit 1; }
    # add_ip_exception publishes the deadline first, then starts the installed
    # timer and rolls the grant back if the active-timer postcondition fails.
    add_ip_exception "$ip" temporary "$((minutes * 60))" \
        "$direction" "$protocol" "$port_start" "$port_end"
    load_exception_state "$ip" || {
        rollback_ip_exception_fail_closed "$ip" "$family" || systemctl stop NetworkManager.service
        echo "ERROR: temporary exception has no valid durable expiry state" >&2
        exit 1
    }
    echo "[OK] Durable auto-revert deadline: epoch $EX_STATE_EXPIRES (${minutes}min): $ip"
    echo "      Cancel earlier: sudo noid-lan-allow --revert $ip"
}

show_per_ip_exceptions() {
    local exceptions
    if ! exceptions=$(list_per_ip_raw); then
        echo "ERROR: LAN exception state is invalid; no partial list is shown." >&2
        return 1
    fi
    if [ -z "$exceptions" ]; then
        echo "  (none)"
        return 0
    fi

    while IFS= read -r ip; do
        [ -n "$ip" ] || continue
        local timer_state="INVALID metadata — fail-closed reconciliation required"
        local selector="unavailable — invalid metadata" now remaining
        if load_exception_state "$ip"; then
            if [ "$EX_STATE_KIND" = permanent ]; then
                timer_state=permanent
            elif exception_is_expired; then
                timer_state="temporary (expired; revocation pending/failing)"
            else
                now=$(now_epoch)
                remaining=$((EX_STATE_EXPIRES - now))
                timer_state="temporary (${remaining}s maximum wall-clock remaining; epoch $EX_STATE_EXPIRES)"
            fi
            if [ "$EX_STATE_DIRECTION" = outbound ]; then
                selector="outbound only"
            else
                selector="$EX_STATE_DIRECTION $EX_STATE_PROTOCOL ports ${EX_STATE_PORT_START}-${EX_STATE_PORT_END}"
            fi
        fi
        printf "  %-15s %-42s %s\n" "$ip" "$selector" "$timer_state"
    done <<< "$exceptions"
}

list_machine() {
    local exceptions ip expires rows
    exceptions=$(list_per_ip_raw) || return 1
    rows=$(
        while IFS= read -r ip; do
            [ -n "$ip" ] || continue
            load_exception_state "$ip" || exit 1
            expires=$EX_STATE_EXPIRES
            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                "$ip" "$EX_STATE_DIRECTION" "$EX_STATE_PROTOCOL" \
                "$EX_STATE_PORT_START" "$EX_STATE_PORT_END" \
                "$EX_STATE_KIND" "$EX_STATE_DURATION" "$expires"
        done <<< "$exceptions"
    ) || return 1
    echo 'NOID-LAN-EXCEPTIONS-V2'
    [ -z "$rows" ] || printf '%s\n' "$rows"
}

list_reconcile_candidates() {
    local state_file candidate canonical
    {
        list_managed_firewall_ips || return 1
        if [ -e "$LAN_EXCEPTION_STATE_DIR" ] \
           || [ -L "$LAN_EXCEPTION_STATE_DIR" ]; then
            trusted_state_directory "$LAN_EXCEPTION_STATE_DIR" 755 || return 1
            for state_file in "$LAN_EXCEPTION_STATE_DIR"/*.state; do
                [ -e "$state_file" ] || [ -L "$state_file" ] || continue
                [ -f "$state_file" ] && [ ! -L "$state_file" ] || return 1
                candidate=$(awk -F= '$1=="IP" {print $2}' "$state_file" 2>/dev/null) \
                    || return 1
                canonical=$(canonicalize_ip "$candidate" || true)
                [ -n "$canonical" ] \
                    && [ "$(exception_state_file "$canonical")" = "$state_file" ] \
                    || return 1
                printf '%s\n' "$canonical"
            done
        fi
    } | sort -u
}

revoke_invalid_ip_exception() {
    local ip="$1" family="$2"
    if ! refresh_topology_guard --exclude-peer "$ip" \
            --invalidate-peer-flows "$ip" --require-xdp; then
        echo "CRITICAL: invalid exception could not be quiesced in XDP/nft; stopping NetworkManager." >&2
        systemctl stop NetworkManager.service
        return 1
    fi
    if ! remove_all_managed_firewall_rules_for_ip "$ip" \
       || ! firewall-cmd --reload >/dev/null; then
        echo "CRITICAL: invalid exception firewalld permits could not be removed; stopping NetworkManager." >&2
        systemctl stop NetworkManager.service
        return 1
    fi
    if [ "$family" = ipv4 ]; then
        remove_ipv4_peer_state "$ip" || return 1
    fi
    remove_exception_state "$ip" || return 1
    if ! refresh_topology_guard --require-xdp \
       || ! verify_ip_exception_absent "$ip" "$family"; then
        echo "CRITICAL: invalid exception revoke postcondition failed; stopping NetworkManager." >&2
        systemctl stop NetworkManager.service
        return 1
    fi
}

export_policy() {
    local exclude="${1:-}" exceptions ip
    if [ -n "$exclude" ]; then
        exclude=$(canonicalize_ip "$exclude" || true)
        [ "$(validate_ip_family "$exclude")" = ipv4 ] || return 1
    fi
    exceptions=$(list_per_ip_raw "$exclude") || return 1
    while IFS= read -r ip; do
        [ -n "$ip" ] || continue
        [ "$ip" != "$exclude" ] || continue
        load_exception_state "$ip" || return 1
        if [ "$EX_STATE_KIND" = temporary ] && exception_is_expired; then
            continue
        fi
        load_ipv4_peer_state "$ip" || return 1
        [ "$PEER_STATE_DIRECTION" = "$EX_STATE_DIRECTION" ] \
            && [ "$PEER_STATE_PROTOCOL" = "$EX_STATE_PROTOCOL" ] \
            && [ "$PEER_STATE_PORT_START" = "$EX_STATE_PORT_START" ] \
            && [ "$PEER_STATE_PORT_END" = "$EX_STATE_PORT_END" ] || return 1
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$PEER_STATE_IFACE" "$ip" "$PEER_STATE_MAC" \
            "$EX_STATE_DIRECTION" "$EX_STATE_PROTOCOL" \
            "$EX_STATE_PORT_START" "$EX_STATE_PORT_END"
    done <<< "$exceptions"
}

reconcile_fail_closed() {
    echo "CRITICAL: LAN expiry reconciliation failed: $*" >&2
    systemctl --no-block stop NetworkManager.service >/dev/null 2>&1 || true
    return 1
}

reconcile_expired_exceptions() {
    local exceptions ip canonical family
    if ! exceptions=$(list_reconcile_candidates); then
        reconcile_fail_closed "cannot enumerate durable exception rules and state"
        return 1
    fi
    while IFS= read -r ip; do
        [ -n "$ip" ] || continue
        canonical=$(canonicalize_ip "$ip" || true)
        family=$(validate_ip_family "$canonical")
        if [ -z "$family" ] || [ "$canonical" != "$ip" ]; then
            reconcile_fail_closed "invalid destination in a managed firewalld rule"
            return 1
        fi
        if ! load_exception_state "$ip"; then
            echo "WARN: revoking $ip because its durable metadata is missing or invalid." >&2
            if ! revoke_invalid_ip_exception "$ip" "$family"; then
                reconcile_fail_closed "could not revoke invalid exception $ip"
                return 1
            fi
        elif ! firewall_contract_exists "$ip" permanent; then
            echo "WARN: revoking $ip because firewalld and durable selector state disagree." >&2
            if ! revoke_invalid_ip_exception "$ip" "$family"; then
                reconcile_fail_closed "could not revoke inconsistent exception $ip"
                return 1
            fi
        elif [ "$EX_STATE_KIND" = temporary ] && exception_is_expired; then
            echo "INFO: revoking expired LAN exception $ip." >&2
            if ! revert_ip_exception "$ip" no-sync; then
                reconcile_fail_closed "could not revoke expired exception $ip"
                return 1
            fi
        fi
    done <<< "$exceptions"

    if ! sync_expiry_timer; then
        reconcile_fail_closed "could not synchronize the temporary-exception timer"
        return 1
    fi
    echo "[OK] LAN exception expiry reconciliation complete."
}

action_status() {
    if firewall-cmd --info-policy="$POLICY" >/dev/null 2>&1; then
        local ingress state
        if ! ingress=$(firewall-cmd --permanent --policy="$POLICY" --list-ingress-zones); then
            echo "ERROR: cannot query block-lan-out ingress state." >&2
            return 1
        fi
        local ingress_trim
        ingress_trim=$(echo "$ingress" | tr -s ' ' | sed 's/^ *//;s/ *$//')

        echo "Global block-lan-out policy:"
        echo "  ingress-zones: ${ingress_trim:-<none>}"
        if state=$(global_state); then
            case "$state" in
                BLOCKED) echo "  state:         BLOCKED (default hardened)" ;;
                ALLOWED) echo "  state:         ALLOWED (all enforcement layers synchronized)" ;;
            esac
        else
            echo "  state:         INCONSISTENT — do not assume LAN access or isolation"
            echo "ERROR: firewalld, durable marker and runtime topology/WAN-strict state disagree." >&2
            return 1
        fi
        echo
        echo "Per-IP exceptions:"
        show_per_ip_exceptions
    else
        echo "ERROR: block-lan-out policy not found; LAN isolation is not verifiable." >&2
        return 1
    fi
}

action_help() {
    cat <<'HELP_EOF'
NoID Privacy LAN-allow CLI — selectively allow outbound LAN traffic

PER-IP EXCEPTIONS (recommended):
  sudo noid-lan-allow --add <IP> --direction outbound [--temp MIN]
  sudo noid-lan-allow --add <IP> --direction inbound --protocol tcp|udp --ports PORT|START-END [--temp MIN]
  sudo noid-lan-allow --add <IP> --direction both --protocol tcp|udp --ports PORT|START-END [--temp MIN]
  sudo noid-lan-allow --revert <IP>         Remove exception + durable expiry state
  noid-lan-allow --list                     Show all active per-IP exceptions (no root required)

GLOBAL TOGGLE (legacy — synchronizes every outbound LAN enforcement layer):
  sudo noid-lan-allow on                    Allow all directly connected/local destinations
  sudo noid-lan-allow off                   Restore hardened default

STATUS:
  noid-lan-allow status                     Show global + per-IP state
  noid-lan-allow --global-state             Machine state: BLOCKED/ALLOWED/INCONSISTENT
  noid-lan-allow help                       Show this help

EXAMPLES:
  sudo noid-lan-allow --add 192.168.1.50 --direction outbound
  sudo noid-lan-allow --add 192.168.1.60 --direction inbound --protocol tcp --ports 443
  sudo noid-lan-allow --add 192.168.1.70 --direction both --protocol udp --ports 5000-5010 --temp 30
  sudo noid-lan-allow --revert 192.168.1.50     # remove printer
  noid-lan-allow --list                     # show all exceptions (no root required)
HELP_EOF
}

parse_port_selector() {
    local raw="$1"
    case "$raw" in
        *-*)
            PORT_START=${raw%%-*}
            PORT_END=${raw#*-}
            [ "$PORT_END" != "$raw" ] && [[ "$PORT_END" != *-* ]] || return 1
            ;;
        *) PORT_START=$raw; PORT_END=$raw ;;
    esac
    [[ "$PORT_START" =~ ^[1-9][0-9]{0,4}$ ]] \
        && [[ "$PORT_END" =~ ^[1-9][0-9]{0,4}$ ]] \
        && [ "$PORT_START" -le "$PORT_END" ] \
        && [ "$PORT_END" -le 65535 ]
}

action_add() {
    local ip="${1:-}"; shift || true
    local direction="" protocol="" ports="" minutes=""
    [ -n "$ip" ] || { echo "ERROR: --add requires <IP>." >&2; exit 2; }
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --direction)
                [ -z "$direction" ] && [ "$#" -ge 2 ] \
                    || { echo "ERROR: duplicate/missing --direction value" >&2; exit 2; }
                direction=$2; shift 2 ;;
            --protocol)
                [ -z "$protocol" ] && [ "$#" -ge 2 ] \
                    || { echo "ERROR: duplicate/missing --protocol value" >&2; exit 2; }
                protocol=$2; shift 2 ;;
            --ports)
                [ -z "$ports" ] && [ "$#" -ge 2 ] \
                    || { echo "ERROR: duplicate/missing --ports value" >&2; exit 2; }
                ports=$2; shift 2 ;;
            --temp)
                [ -z "$minutes" ] && [ "$#" -ge 2 ] \
                    || { echo "ERROR: duplicate/missing --temp value" >&2; exit 2; }
                minutes=$2; shift 2 ;;
            *) echo "ERROR: unknown --add argument: $1" >&2; exit 2 ;;
        esac
    done
    case "$direction" in
        outbound)
            [ -z "$protocol$ports" ] \
                || { echo "ERROR: outbound-only uses correlated replies and accepts no inbound selector" >&2; exit 2; }
            protocol=none; PORT_START=0; PORT_END=0
            ;;
        inbound|both)
            case "$protocol" in tcp|udp) ;;
                *) echo "ERROR: inbound-capable rules require --protocol tcp|udp" >&2; exit 2 ;;
            esac
            [ -n "$ports" ] && parse_port_selector "$ports" \
                || { echo "ERROR: inbound-capable rules require --ports 1..65535 or START-END" >&2; exit 2; }
            ;;
        *) echo "ERROR: --direction must be outbound, inbound or both" >&2; exit 2 ;;
    esac
    if [ -n "$minutes" ]; then
        add_temp_ip_exception "$ip" "$minutes" "$direction" "$protocol" \
            "$PORT_START" "$PORT_END"
    else
        add_ip_exception "$ip" permanent 0 "$direction" "$protocol" \
            "$PORT_START" "$PORT_END"
    fi
}

# === ACTION DISPATCH ===

ACTION="${1:-status}"

case "$ACTION" in
    --add)
        require_root
        acquire_exception_lock
        shift
        action_add "$@"
        ;;
    --temp)
        [ "$#" -le 3 ] || { echo "ERROR: legacy --temp accepts only <IP> [MIN]." >&2; exit 2; }
        [ -n "${2:-}" ] || { echo "ERROR: --temp requires <IP> argument." >&2; exit 1; }
        require_root
        acquire_exception_lock
        add_temp_ip_exception "$2" "${3:-60}" outbound none 0 0
        ;;
    --revert)
        [ "$#" -eq 2 ] \
            || { echo "ERROR: --revert requires exactly one <IP> argument." >&2; exit 2; }
        require_root
        acquire_exception_lock
        revert_ip_exception "$2"
        ;;
    --reconcile-expired)
        [ "$#" -eq 1 ] \
            || { echo "ERROR: --reconcile-expired takes no arguments." >&2; exit 2; }
        require_root
        acquire_exception_lock
        reconcile_expired_exceptions
        ;;
    --list)
        [ "$#" -eq 1 ] \
            || { echo "ERROR: --list takes no arguments." >&2; exit 2; }
        echo "Per-IP LAN exceptions:"
        show_per_ip_exceptions
        ;;
    --list-machine)
        [ "$#" -eq 1 ] || { echo "ERROR: --list-machine takes no arguments" >&2; exit 2; }
        list_machine
        ;;
    --export-policy)
        require_root
        case "$#" in
            1) export_policy ;;
            3)
                [ "$2" = --exclude ] \
                    || { echo "ERROR: --export-policy accepts only --exclude <IPv4>" >&2; exit 2; }
                export_policy "$3"
                ;;
            *) echo "ERROR: --export-policy accepts only optional --exclude <IPv4>" >&2; exit 2 ;;
        esac
        ;;
    --global-state)
        [ "$#" -eq 1 ] \
            || { echo "ERROR: --global-state takes no arguments." >&2; exit 2; }
        if [ "$(id -u)" -ne 0 ]; then
            if state=$(read_global_runtime_state) \
               && [ "$state" != INCONSISTENT ]; then
                printf '%s\n' "$state"
            else
                printf '%s\n' INCONSISTENT
                exit 1
            fi
        elif state=$(global_state); then
            printf '%s\n' "$state"
        else
            printf '%s\n' INCONSISTENT
            exit 1
        fi
        ;;
    on|enable|allow)
        [ "$#" -le 2 ] \
            || { echo "ERROR: '$ACTION' accepts at most one confirmation flag." >&2; exit 2; }
        require_root
        acquire_exception_lock
        confirmation_mode="${2:-interactive}"
        if [ "$confirmation_mode" != "interactive" ] && \
           [ "$confirmation_mode" != "--yes" ]; then
            echo "ERROR: '$ACTION' accepts only the optional --yes confirmation flag" >&2
            exit 2
        fi
        # Prove the dynamic layer is present and internally consistent before
        # weakening anything. An already-active verified state is idempotent.
        if ! refresh_topology_guard; then
            echo "ERROR: topology preflight failed; refusing global LAN allow." >&2
            exit 1
        fi
        if pre_state=$(global_state) && [ "$pre_state" = ALLOWED ]; then
            echo "[OK] Global LAN egress allow is already active and synchronized."
            exit 0
        fi
        if [ "${pre_state:-INCONSISTENT}" != BLOCKED ]; then
            echo "ERROR: default LAN boundary is inconsistent; refusing to weaken it." >&2
            exit 1
        fi

        echo "⚠ Disabling block-lan-out entirely. The host can reach ALL directly"
        echo "  connected LAN destinations. Physical inbound DROP and disabled"
        echo "  service discovery remain in place."
        echo "  Tip: For one peer, prefer 'sudo noid-lan-allow --add <IP> --direction outbound'."
        if [ "$confirmation_mode" != "--yes" ]; then
            read -rp "Continue? [y/N] " CONFIRM
            [[ "$CONFIRM" =~ ^[yY]([eE][sS])?$ ]] || { echo "Aborted."; exit 0; }
        fi

        if command -v noid-snap-pre >/dev/null 2>&1; then
            if ! noid-snap-pre "LAN egress allow (global)"; then
                echo "ERROR: snapshot failed; refusing to weaken LAN isolation." >&2
                exit 1
            fi
        fi

        if firewall-cmd --info-policy="$POLICY" >/dev/null 2>&1; then
            if policy_has_ingress HOST; then
                if ! firewall-cmd --permanent --policy="$POLICY" \
                        --remove-ingress-zone=HOST >/dev/null; then
                    echo "ERROR: could not detach the firewalld LAN boundary." >&2
                    exit 1
                fi
            fi
            if ! firewall-cmd --reload >/dev/null; then
                if ! restore_global_block_state; then
                    echo "CRITICAL: firewalld reload and rollback failed; stopping NetworkManager." >&2
                    systemctl stop NetworkManager.service
                fi
                echo "ERROR: firewalld reload failed; global LAN allow was not activated." >&2
                exit 1
            fi
            marker_ok=1
            set_global_allow_marker || marker_ok=0
            if [ "$marker_ok" -ne 1 ] || ! refresh_topology_guard; then
                # The topology layer remains blocking until its final atomic
                # refresh. Restore every source of truth if activation fails.
                if ! restore_global_block_state; then
                    echo "CRITICAL: global allow rollback failed; stopping NetworkManager." >&2
                    systemctl stop NetworkManager.service
                fi
                echo "ERROR: global LAN allow rolled back because topology sync failed." >&2
                exit 1
            fi
            if ! state=$(global_state) || [ "$state" != ALLOWED ]; then
                if ! restore_global_block_state; then
                    echo "CRITICAL: global allow postcondition rollback failed; stopping NetworkManager." >&2
                    systemctl stop NetworkManager.service
                fi
                echo "ERROR: global LAN allow failed its complete postcondition and was rolled back." >&2
                exit 1
            fi
            echo "[OK] Global LAN egress allow active across firewalld, topology and WAN-strict. Standard ARP and permanent neighbour pins are unchanged; physical inbound IP DROP remains active."
        else
            echo "ERROR: block-lan-out policy not found; refusing unverifiable global allow." >&2
            exit 1
        fi
        ;;
    off|disable|block)
        [ "$#" -eq 1 ] \
            || { echo "ERROR: '$ACTION' takes no arguments." >&2; exit 2; }
        require_root
        acquire_exception_lock
        if state=$(global_state) && [ "$state" = BLOCKED ]; then
            echo "[OK] LAN boundary is already in the default synchronized BLOCKED state."
            exit 0
        fi
        if command -v noid-snap-pre >/dev/null 2>&1; then
            if ! noid-snap-pre "LAN egress restore to block"; then
                echo "WARN: snapshot failed; continuing because this action restores protection." >&2
            fi
        fi

        if firewall-cmd --info-policy="$POLICY" >/dev/null 2>&1; then
            if ! restore_global_block_state; then
                echo "CRITICAL: static LAN blocks were restored but the topology layer failed; stopping NetworkManager fail-closed." >&2
                systemctl stop NetworkManager.service
                exit 1
            fi
            if ! state=$(global_state) || [ "$state" != BLOCKED ]; then
                echo "CRITICAL: restored LAN boundary failed its complete postcondition; stopping NetworkManager." >&2
                systemctl stop NetworkManager.service
                exit 1
            fi
            echo "[OK] block-lan-out re-attached (HOST ingress restored). Default hardened state."
        else
            echo "ERROR: block-lan-out policy not found; cannot restore the default boundary." >&2
            exit 1
        fi
        ;;
    status|"")
        [ "$#" -le 1 ] \
            || { echo "ERROR: status takes no arguments." >&2; exit 2; }
        action_status
        ;;
    help|-h|--help)
        [ "$#" -eq 1 ] \
            || { echo "ERROR: help takes no arguments." >&2; exit 2; }
        action_help
        ;;
    -*)
        echo "ERROR: Unknown option: $ACTION" >&2
        action_help
        exit 1
        ;;
    *)
        # Backward-compatible bare IP: now explicitly outbound-only.
        [ "$#" -eq 1 ] || { echo "ERROR: bare-IP form accepts no extra arguments" >&2; exit 2; }
        require_root
        acquire_exception_lock
        add_ip_exception "$ACTION" permanent 0 outbound none 0 0
        ;;
esac
LAN_ALLOW_EOF

chmod 755 /usr/local/bin/noid-lan-allow
chown root:root /usr/local/bin/noid-lan-allow
# M05_LAN_ALLOW_COMPOSE_VERIFY_BEGIN
verify_lan_allow_contract() {
    local helper_path="$1" expected_uid="${2:-0}" expected_gid="${3:-0}"
    [ "$(LC_ALL=C stat -c '%u:%g:%a:%h:%F' "$helper_path" \
            2>/dev/null || true)" \
        = "$expected_uid:$expected_gid:755:1:regular file" ] \
        && bash -n "$helper_path" \
        && grep -qF \
        'ARP_HARDENING_STATE="${NOID_ARP_HARDENING_STATE:-/var/lib/noid-privacy/arp-hardening.state}"' \
        "$helper_path" \
        && grep -qF \
        'ip neigh replace "$ip" lladdr "$PROTECTED_GATEWAY_MAC"' \
        "$helper_path" \
        && grep -qF \
        '[ "$observed" = "$PROTECTED_GATEWAY_MAC" ] || return 1' \
        "$helper_path" \
        && grep -qF \
        '[ "$PROTECTED_GATEWAY_ENABLED" = 1 ]' \
        "$helper_path" \
        && grep -qF \
        '[ -x "$ARP_STATE_GUARD" ] && "$ARP_STATE_GUARD" || return 1' \
        "$helper_path" \
        && grep -qF \
        'valid_global_allow_marker()' \
        "$helper_path" \
        && grep -qF \
        'read_global_runtime_state()' \
        "$helper_path" \
        && grep -qF \
        'next_temporary_schedule()' \
        "$helper_path" \
        && grep -qF \
        'publish_expiry_schedule()' \
        "$helper_path" \
        && grep -qF \
        'path_identity=$(stat -Lc' \
        "$helper_path" \
        && grep -qF \
        'raw ARP and kernel neighbour identity disagree' \
        "$helper_path"
}
# M05_LAN_ALLOW_COMPOSE_VERIFY_END
if ! verify_lan_allow_contract /usr/local/bin/noid-lan-allow 0 0; then
    log "  ERROR: noid-lan-allow closed state/identity contract failed verification"
    exit 1
fi
log "  Installed /usr/local/bin/noid-lan-allow (755)"

# A temporary exception's deadline is durable data, not a transient timer.
# The boot service runs after the authoritative topology and M04 state guards
# but before NetworkManager may expose a link. A systemd generator converts the
# root-owned runtime schedule into combined realtime and monotonic triggers, so
# the expensive full reconciliation runs at the earliest actual deadline rather
# than every five seconds. The static five-second expression is only a closed
# fallback if the timer is ever started without generated deadline state.
cat > /etc/systemd/system/noid-lan-expiry-reconcile.service <<'LAN_EXPIRY_SERVICE_EOF'
[Unit]
Description=NoID Privacy fail-closed LAN exception expiry reconciliation
Documentation=file:///usr/share/doc/noid-privacy/05-lan-isolation.md
After=firewalld.service noid-lan-topology-guard.service noid-arp-state-guard.service
Before=NetworkManager.service network-pre.target
Requires=firewalld.service noid-lan-topology-guard.service noid-arp-state-guard.service
Wants=network-pre.target
OnFailure=noid-lan-expiry-failure.service
RefuseManualStop=yes
# The topology guard already rate-limits its own execution. Without the same
# bound here, a guard that stays failed lets every requester re-queue this unit
# indefinitely: each attempt republishes the guard's [FAILED] plus this unit's
# [DEPEND] line and re-triggers OnFailure=, which floods console, journal and
# audit backlog while nothing is retried in userspace. Three attempts per minute
# keep the fail-closed state visible exactly once per window and then quiet.
StartLimitIntervalSec=60s
StartLimitBurst=3

[Service]
Type=oneshot
ExecStart=/usr/local/bin/noid-lan-allow --reconcile-expired
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
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
ReadWritePaths=/var/lib/noid-privacy /run/noid-privacy -/sys/fs/bpf

[Install]
WantedBy=network-pre.target
LAN_EXPIRY_SERVICE_EOF

cat > /etc/systemd/system/noid-lan-expiry-reconcile.timer <<'LAN_EXPIRY_TIMER_EOF'
[Unit]
Description=Deadline-driven NoID Privacy LAN exception expiry check
OnFailure=noid-lan-expiry-failure.service

[Timer]
OnUnitInactiveSec=5s
AccuracySec=1us
Unit=noid-lan-expiry-reconcile.service

[Install]
WantedBy=timers.target
LAN_EXPIRY_TIMER_EOF

install -d -m 0755 /usr/lib/systemd/system-generators
cat > /usr/lib/systemd/system-generators/noid-lan-expiry-generator <<'LAN_EXPIRY_GENERATOR_EOF'
#!/bin/bash
# Convert the helper's validated runtime schedule into native systemd timer
# expressions. Invalid schedule metadata triggers immediate fail-closed
# reconciliation instead of being ignored as though no exception existed.
set -euo pipefail
umask 077
LC_ALL=C
export LC_ALL

output_dir="${1:?missing normal generator output directory}"
schedule=/run/noid-privacy/lan-expiry-schedule
dropin_dir="$output_dir/noid-lan-expiry-reconcile.timer.d"
dropin="$dropin_dir/50-noid-deadline.conf"

emit_immediate() {
    install -d -m 0755 "$dropin_dir"
    printf '%s\n' \
        '[Timer]' \
        'OnActiveSec=' \
        'OnActiveSec=1us' \
        > "$dropin"
    chmod 0644 "$dropin"
}

invalid_schedule() {
    echo "noid-lan-expiry-generator: unsafe or malformed schedule; reconciling immediately" >&2
    emit_immediate
    exit 0
}

runtime_dir=${schedule%/*}
if [ ! -e "$runtime_dir" ] && [ ! -L "$runtime_dir" ]; then
    exit 0
fi
[ -d "$runtime_dir" ] && [ ! -L "$runtime_dir" ] \
    || invalid_schedule
[ "$(stat -c '%u:%g:%a:%F' "$runtime_dir" 2>/dev/null || true)" = \
    '0:0:755:directory' ] || invalid_schedule
if [ ! -e "$schedule" ] && [ ! -L "$schedule" ]; then
    exit 0
fi
[ -f "$schedule" ] && [ ! -L "$schedule" ] \
    || invalid_schedule
[ "$(stat -c '%u:%g:%a:%h:%F' "$schedule" 2>/dev/null || true)" = \
    '0:0:600:1:regular file' ] || invalid_schedule

version="" epoch="" delay="" count=0
seen_version=0 seen_epoch=0 seen_delay=0
while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in *=*) ;; *) invalid_schedule ;; esac
    key=${line%%=*}
    value=${line#*=}
    case "$key" in
        VERSION)
            [ "$seen_version" -eq 0 ] || invalid_schedule
            seen_version=1
            version=$value
            ;;
        EPOCH)
            [ "$seen_epoch" -eq 0 ] || invalid_schedule
            seen_epoch=1
            epoch=$value
            ;;
        MONOTONIC_DELAY_SEC)
            [ "$seen_delay" -eq 0 ] || invalid_schedule
            seen_delay=1
            delay=$value
            ;;
        *) invalid_schedule ;;
    esac
    count=$((count + 1))
done < "$schedule"

[ "$count" -eq 3 ] && [ "$version" = 1 ] \
    && [[ "$epoch" =~ ^[1-9][0-9]{0,17}$ ]] \
    && [[ "$delay" =~ ^[1-9][0-9]{0,17}$ ]] \
    || invalid_schedule

install -d -m 0755 "$dropin_dir"
printf '%s\n' \
    '[Timer]' \
    'OnActiveSec=' \
    "OnActiveSec=${delay}s" \
    "OnCalendar=@${epoch}" \
    > "$dropin"
chmod 0644 "$dropin"
LAN_EXPIRY_GENERATOR_EOF
chmod 0755 /usr/lib/systemd/system-generators/noid-lan-expiry-generator
chown root:root /usr/lib/systemd/system-generators/noid-lan-expiry-generator
if [ "$(LC_ALL=C stat -c '%u:%g:%a:%h:%F' \
        /usr/lib/systemd/system-generators/noid-lan-expiry-generator \
        2>/dev/null || true)" != '0:0:755:1:regular file' ] \
   || ! bash -n /usr/lib/systemd/system-generators/noid-lan-expiry-generator \
   || ! grep -qF '"OnActiveSec=${delay}s"' \
        /usr/lib/systemd/system-generators/noid-lan-expiry-generator \
   || ! grep -qF '"OnCalendar=@${epoch}"' \
        /usr/lib/systemd/system-generators/noid-lan-expiry-generator; then
    log "  ERROR: LAN expiry deadline generator failed verification"
    exit 1
fi

cat > /etc/systemd/system/noid-lan-expiry-failure.service <<'LAN_EXPIRY_FAILURE_EOF'
[Unit]
Description=NoID Privacy LAN expiry fail-closed network stop
# Bound to the same window as its trigger. A reconciliation that keeps failing
# must not turn this notifier into the motor of its own repetition.
StartLimitIntervalSec=60s
StartLimitBurst=3

[Service]
Type=oneshot
# Stopping an already-inactive NetworkManager changes nothing about the
# fail-closed posture but still enqueues a job against a unit that hard-requires
# the failed topology guard, which re-publishes the whole failure block. Skip
# cleanly in that case: the network is already down, which is the intended end
# state. ExecCondition= reports this as skipped, not as a fourth red unit.
ExecCondition=/usr/bin/systemctl is-active --quiet NetworkManager.service
ExecStart=/usr/bin/systemctl --no-block stop NetworkManager.service
UMask=0077
NoNewPrivileges=yes
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
RestrictAddressFamilies=AF_UNIX
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
CapabilityBoundingSet=
LAN_EXPIRY_FAILURE_EOF

mkdir -p /etc/systemd/system/NetworkManager.service.d
cat > /etc/systemd/system/NetworkManager.service.d/22-noid-lan-expiry.conf <<'LAN_EXPIRY_NM_EOF'
[Unit]
Requires=noid-lan-expiry-reconcile.service
After=noid-lan-expiry-reconcile.service
LAN_EXPIRY_NM_EOF

chmod 0644 /etc/systemd/system/noid-lan-expiry-reconcile.service \
    /etc/systemd/system/noid-lan-expiry-reconcile.timer \
    /etc/systemd/system/noid-lan-expiry-failure.service \
    /etc/systemd/system/NetworkManager.service.d/22-noid-lan-expiry.conf
chown root:root /etc/systemd/system/noid-lan-expiry-reconcile.service \
    /etc/systemd/system/noid-lan-expiry-reconcile.timer \
    /etc/systemd/system/noid-lan-expiry-failure.service \
    /etc/systemd/system/NetworkManager.service.d/22-noid-lan-expiry.conf
systemctl daemon-reload
systemctl enable noid-lan-expiry-reconcile.service

log "=== Module 05 complete ==="
%end

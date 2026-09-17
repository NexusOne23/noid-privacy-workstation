# ============================================================================
# Module 11 — NTP (chrony NTS-only)
# Status: LOCKED 2026-08-23 (v39) — retry bounded resolver/NTS-KE failure without crossing readiness.
#
# Covers:
#   - /etc/chrony.conf full replacement: NTS-only, 6 operator-supported
#     public/production servers (DE×2 PTB / SE×2 Netnod / NL×2 SIDN-TimeNL),
#     minsources 3 minimum-selectable-source threshold,
#     cmdport 0 + Unix-socket command interface
#   - systemd-timesyncd explicit mask (defense-in-depth — survives a later
#     chrony removal and blocks later timedated/preset selection of plain NTP)
#   - Fedora-owned chronyd-restricted.service: starts unprivileged in
#     chronyd_restricted_t with only CAP_SYS_TIME + the vendor sandbox
#   - Fedora-owned /etc/sysconfig/chronyd OPTIONS="-F 2" retained; no brittle
#     library-syscall allowlist override; chronyd -p syntax pre-validation
#
# Server-set dependency policy (revalidate for every release candidate):
#   - EU-only, institution-operated set: PTB national metrology, Netnod and
#     SIDN Labs; no US endpoint, commercial CDN or individual-run endpoint in
#     the configured list.
#   - `manifests/chrony-nts-sources-v1.tsv` records the dated primary operator
#     page and its exact service classification for every configured name.
#     Public DNS, certificates and backend routing are mutable dependencies;
#     the candidate runtime gate must prove them instead of trusting history.
#   - Netnod slots are UNICAST site-endpoints only (lul1/mmo1).
#     The anycast KE endpoint negotiates ANY site's -ts backend; a backend
#     already registered by another source makes chronyd refuse the
#     duplicate and the slot stays at reach 0. The release gate therefore
#     proves distinct negotiated timestamp backends; site names alone are not
#     called collision-free.
#   - SIDN explicitly designates ntppool1/2 for production. Its GNSS-free
#     UTC(VSL) ntppool3/4 endpoints are explicitly pre-production and are not
#     base-image dependencies, even when DNS, TLS and NTS happen to work.
#   - Six hostnames are not six independent trust roots. Operator correlation
#     is retained in the manifest; no one operator owns a majority of the
#     configured slots, and `minsources` is not described as a voting quorum.
#
# Design constraints (keep when editing):
#   - maxpoll is valid ONLY as a per-server option — a global `maxpoll N`
#     line makes chronyd refuse to start ("Invalid directive").
#   - cmdport 0 is REQUIRED to close UDP:323 — bindcmdaddress 127.0.0.1
#     alone leaves the IPv6 socket open (per-family sockets).
#   - No `pool`/include expansion (closed manifest-bound source set), no
#     `sourcedir /run/chrony-dhcp` (DHCP NTP injection), keyfile /dev/null
#     (symmetric-key sources fail closed), maxupdateskew 100.0. `maxchange`
#     deliberately skips the first three updates so every certificate-valid RTC
#     bootstrap can complete, then rejects a newly accepted >1000-second offset.
#     The local-VT recovery remains for clocks outside TLS certificate validity.
#   - Chrony measurement-file logging stays DISABLED by design: Fedora's
#     stanza inherits global weekly rotation with four archives (about 35 days),
#     beyond M42's scoped 30-day boundary; tracking lines also carry source-IP +
#     oscillator-drift fingerprints. Live debug =
#     `sudo chronyc tracking` / `sources -v` / `ntpdata` (current daemon
#     state, on-demand through the group-restricted Unix command socket).
#   - Keep Fedora's `-F 2` chronyd filter. `-F 1` is a library-sensitive
#     syscall allowlist which upstream recommends only for a qualified exact
#     matrix; Fedora already had to repair it for a glibc transition in
#     chrony-4.8-3. The native restricted unit compensates with a stronger
#     privilege/SELinux/systemd boundary and remains package-maintained.
#   - ipv4 + offline keywords on all servers (image ships v6 off on WAN per
#     M02/M07; M04 publishes the gateway/XDP readiness event that runs
#     `chronyc online`).
#   - Fedora's two chrony NetworkManager dispatchers are kept pristine in
#     /usr but shadowed with root-owned no-ops in /etc. Otherwise the vendor
#     `chronyc onoffline` path can bring sources online before M04 publishes
#     readiness, and the DHCP path is redundant with the closed configuration
#     which deliberately has no `sourcedir /run/chrony-dhcp`.
#
# Cross-reference:
#   - Module 05: systemd-resolved drop-in (Quad9 DoT) — untouched here.
#   - Module 08: deliberately carries no competing chronyd drop-in; Fedora's
#     restricted client unit is the single sandbox owner.
#   - Module 30: user-doc mirrors the chrony.conf server table — keep in
#     sync on any server-set change (plus manifests/chrony-nts-sources-v1.tsv,
#     tests/11, tests/30, tests/README and M99).
# ============================================================================

# No %packages block — chrony is base Fedora @core dep.
# No -systemd-timesyncd package exclusion: Fedora 44 ships the daemon and unit
# in the essential systemd-udev package. The service is masked instead.

%post --erroronfail --log=/var/log/ks-11-dns-ntp.log

set -euo pipefail
echo "=============================================================="
echo "[Module 11] NTP (chrony NTS-only)"
echo "=============================================================="

rpm_payload_file_pristine() {
    local package=$1 path=$2 expected actual
    [ "$(rpm -q --qf '%{FILEDIGESTALGO}' "$package" 2>/dev/null || true)" = 8 ] \
        || return 1
    expected=$(rpm -q --qf '[%{FILENAMES}\t%{FILEDIGESTS}\n]' "$package" \
        2>/dev/null | awk -F '\t' -v target="$path" '
            $1 == target { count++; digest=$2 }
            END { if (count != 1 || digest == "") exit 1; print digest }
        ') || return 1
    actual=$(sha256sum -- "$path" 2>/dev/null) || return 1
    actual=${actual%% *}
    [ "$actual" = "$expected" ]
}

# ----------------------------------------------------------------------------
# Step 1: /etc/chrony.conf — NTS-only configuration (complete replacement)
# ----------------------------------------------------------------------------
#
# Replaces Fedora default chrony.conf (pool 2.fedora.pool.ntp.org iburst).
# Our version has:
#   - 6 NTS servers across DE×2 PTB / SE×2 Netnod / NL×2 SIDN-TimeNL
#     + minsources 3 minimum-selectable-source threshold
#   - ipv4 keyword on all (image has IPv6 off on WAN)
#   - cmdport 0 + bindcmdaddress unix-socket (no UDP:323 listener)
#   - no pool/include expansion (closed manifest-bound source set)
#   - no sourcedir /run/chrony-dhcp (blocks DHCP NTP injection)
#
echo ""
echo "[Step 1] Writing /etc/chrony.conf (NTS-only, hardened)"

cat > /etc/chrony.conf <<'CHRONY_EOF'
# NoID Privacy — chrony NTS-only configuration
# Design rationale: captured inline below.
# This file replaces the Fedora default chrony.conf completely.

# ----------------------------------------------------------------------------
# NTS-authenticated NTP servers (Network Time Security, RFC 8915)
# ----------------------------------------------------------------------------
# NTP timestamps are authenticated with keys exchanged over TLS (NTS-KE on
# TCP port 4460). There is no unauthenticated fallback. NTS prevents timestamp
# modification/forgery, but it does not prevent packet dropping or bounded
# delay attacks.
#
# 6 servers for chrony's source-selection algorithm with explicit `minsources 3`
# threshold below. Multiple site/server endpoints provide redundancy within
# each operator; three independent operators in three countries reduce
# common-mode operator and jurisdiction failures:
#   - ptbtime1.ptb.de         PTB (DE)        national-metrology endpoint #1
#   - ptbtime4.ptb.de         PTB (DE)        separate-location endpoint
#   - lul1.nts.netnod.se      Netnod (SE)     Luleå NTS-KE site
#   - mmo1.nts.netnod.se      Netnod (SE)     Malmö NTS-KE site
#   - ntppool1.time.nl        SIDN Labs (NL)  TimeNL production endpoint #1
#   - ntppool2.time.nl        SIDN Labs (NL)  TimeNL production endpoint #2
#
# Server-set rationale (current state):
#   - All slots are UNICAST site-endpoints. The Netnod anycast KE endpoint
#     (nts.netnod.se) may negotiate ANY site's -ts backend; if that backend is
#     already registered by another configured source, chronyd refuses the
#     duplicate and the slot stays at reach 0. The release gate proves that
#     all negotiated timestamp addresses are distinct; configuration shape
#     alone is not treated as proof.
#   - SIDN's maintained page designates only ntppool1/2 for production.
#     ntppool3/4 are pre-production and intentionally absent from this default.
#   - Posture: 6 servers / 3 institutional operators / 3 EU countries (DE×2
#     PTB / SE×2 Netnod / NL×2 SIDN-TimeNL), with no US, commercial-CDN or
#     individual-run endpoint in the configured list. Operator-published
#     status, IPv4 DNS, NTS-KE certificate/hostname, distinct negotiated
#     backends, reachability and source selection are candidate gates.
#
# 'ipv4' keyword: image has IPv6 disabled on WAN interface
# (net.ipv6.conf.default.disable_ipv6=1 via Module 02 sysctl, plus per-WAN
# explicit disable via Module 07). Forcing IPv4 avoids unnecessary v6
# resolution attempts and timeouts during first boot.
server ptbtime1.ptb.de iburst nts ipv4 maxpoll 11 offline
server ptbtime4.ptb.de iburst nts ipv4 maxpoll 11 offline
server lul1.nts.netnod.se iburst nts ipv4 maxpoll 11 offline
server mmo1.nts.netnod.se iburst nts ipv4 maxpoll 11 offline
server ntppool1.time.nl iburst nts ipv4 maxpoll 11 offline
server ntppool2.time.nl iburst nts ipv4 maxpoll 11 offline

# Reliability threshold: require at least 3 of 6 sources to be considered
# selectable before chrony adjusts the local clock. Chrony's separate source-
# selection algorithm determines agreement and falsetickers. `minsources 3`
# is not a quorum or 3-of-6 vote and does not itself establish majority
# consensus or operator diversity.
minsources 3

# maxpoll is set PER-SERVER on each `server ... maxpoll 11` line above
# (chrony.conf(5) does NOT support maxpoll as a global directive — only as a
# server option). Rationale: battery + privacy + traffic-reduction.

# Strict frequency-skew rejection. Default 1000
# accepts frequency estimates whose error bounds have not settled. The
# maintained Chrony 4.8 guidance names 100 ppm as typical for wireless NTP
# sources; it is a reliability bound, not a separate MITM defense.
maxupdateskew 100.0

# Symmetric-key fail-closed boundary. `keyfile` does not select an
# authentication mode by itself: source `key` options do. Pointing it at the
# empty /dev/null ensures an accidentally added symmetric-key source cannot
# authenticate. The exact manifest-generated `server ... nts` lines below
# remain the actual NTS-only source boundary.
keyfile /dev/null

# ----------------------------------------------------------------------------
# Clock frequency + RTC management
# ----------------------------------------------------------------------------

# Drift file — stores frequency compensation for the system clock's
# oscillator so chrony does not need to relearn it on every boot.
driftfile /var/lib/chrony/drift

# Step (not slew) the system clock if offset > 1.0 seconds, but only during the
# first 3 updates after chronyd start. `maxchange` deliberately starts checking
# only after the same three-update bootstrap window: a certificate-valid
# firmware RTC containing local civil time, or any other large initial offset,
# remains automatically recoverable. A later accepted offset above 1000 seconds
# terminates chronyd instead of moving the clock; ignore=0 permits no post-
# bootstrap exception. This `maxchange` limit is not authentication.
# A clock outside TLS certificate validity still has no
# authenticated measurement and follows the recovery boundary below.
# `chronyc makestep` cannot repair a clock which is outside the NTS-KE TLS
# certificate-validity window: no authenticated measurement exists to step
# from. Use the local-VT `/usr/local/sbin/noid-time-recovery` workflow below.
makestep 1.0 3
maxchange 1000 3 0

# Periodically sync the hardware RTC to the disciplined system clock.
# Ensures RTC accuracy survives reboots.
rtcsync

# ----------------------------------------------------------------------------
# NTS cookie persistence
# ----------------------------------------------------------------------------
# chrony stores NTS-KE session cookies and authentication keys in this
# directory (one file per server IP, typically 8 cookies each). These
# allow NTS-KE handshake skip on chronyd restart, avoiding TLS handshake
# overhead and reducing load on NTS providers.
ntsdumpdir /var/lib/chrony

# ----------------------------------------------------------------------------
# Leap second handling
# ----------------------------------------------------------------------------
# Reads leap-seconds.list from tzdata package (base Fedora dep).
# Without this, chronyd would rely on NTP server leap announcements only.
leapseclist /usr/share/zoneinfo/leap-seconds.list

# ----------------------------------------------------------------------------
# Measurement-file logging — disabled by design
# ----------------------------------------------------------------------------
# Chrony's `log`, `logdir` and `logbanner` directives are intentionally OMITTED.
# Fedora's /etc/logrotate.d/chrony sets no per-file schedule or retention cap,
# so it inherits the global weekly schedule and four archives: an event can
# remain for about 35 days, beyond the scoped 30-day M42 boundary, because
# /var/log/chrony is not covered by noid-misc-logs-prune. Per-measurement
# tracking.log lines also contain the disciplined NTP source IP, system-clock
# oscillator frequency and timestamps, exposing an online-time profile plus a
# potentially identifying drift signal.
#
# Live debug remains fully available via the runtime chronyc interface:
#   sudo chronyc tracking     — current sync state, offset, freq, skew
#   sudo chronyc sources -v   — per-source state with offset/drift columns
#   sudo chronyc ntpdata      — per-source last NTP packet timing
# All three read the running daemon's current state on demand; this module
# creates no persistent Chrony measurement log. Chronyd can still emit
# informational, warning and error events through syslog/journald.

# ----------------------------------------------------------------------------
# Command interface hardening (Unix socket only)
# ----------------------------------------------------------------------------
# cmdport 0 closes the UDP command port completely (default 323).
# Without this, chronyd listens on IPv4 + IPv6 UDP:323 for control
# messages from chronyc. Even with 'cmdallow' restrictions, the port
# remains visible on network scans and represents attack surface.
#
# bindcmdaddress /var/run/chrony/chronyd.sock directs chronyc to use an
# AF_UNIX socket inside the chrony:chrony 0750 runtime directory. Directory
# traversal is the access boundary even when the socket node itself has broader
# mode bits; normal image users therefore use `sudo chronyc`. This is the only
# configured chronyc control path after `cmdport 0`; NTP/NTS client traffic is
# separate.
#
# Note: bindcmdaddress 127.0.0.1 alone is INSUFFICIENT — chrony opens
# separate sockets per protocol family, so IPv6 UDP:323 would remain
# open. Only cmdport 0 fully closes it. (Auto-memory gotcha documented.)
bindcmdaddress /var/run/chrony/chronyd.sock
cmdport 0
CHRONY_EOF

chmod 644 /etc/chrony.conf
chown root:root /etc/chrony.conf
restorecon -F /etc/chrony.conf
matchpathcon -V /etc/chrony.conf
echo "  [OK] /etc/chrony.conf written"

# Dated machine-readable operator review. This is evidence for the frozen
# source candidate, not a promise that external service status cannot change.
mkdir -p /usr/share/doc/noid-privacy
cat > /usr/share/doc/noid-privacy/11-nts-sources.tsv <<'NTS_SOURCE_MANIFEST_EOF'
hostname	operator	country	operator_status	operator_source	reviewed_on
ptbtime1.ptb.de	PTB	DE	public-service	https://www.ptb.de/cms/en/ptb/fachabteilungen/abt9/gruppe-95/ref-952/time-synchronization-of-computers-using-the-network-time-protocol-ntp.html	2026-08-14
ptbtime4.ptb.de	PTB	DE	public-service	https://www.ptb.de/cms/en/ptb/fachabteilungen/abt9/gruppe-95/ref-952/time-synchronization-of-computers-using-the-network-time-protocol-ntp.html	2026-08-14
lul1.nts.netnod.se	Netnod	SE	public-service	https://tech.netnod.se/en/time-services/NTS	2026-08-14
mmo1.nts.netnod.se	Netnod	SE	public-service	https://tech.netnod.se/en/time-services/NTS	2026-08-14
ntppool1.time.nl	SIDN-Labs	NL	production	https://nts.time.nl/	2026-08-14
ntppool2.time.nl	SIDN-Labs	NL	production	https://nts.time.nl/	2026-08-14
NTS_SOURCE_MANIFEST_EOF
chmod 0644 /usr/share/doc/noid-privacy/11-nts-sources.tsv
chown root:root /usr/share/doc/noid-privacy/11-nts-sources.tsv
restorecon -F /usr/share/doc/noid-privacy/11-nts-sources.tsv
matchpathcon -V /usr/share/doc/noid-privacy/11-nts-sources.tsv
echo "  [OK] dated NTS operator-status manifest written"

# ----------------------------------------------------------------------------
# Step 2: Mask systemd-timesyncd.service (defense-in-depth)
# ----------------------------------------------------------------------------
#
# Fedora 44's essential systemd-udev package owns systemd-timesyncd. When
# chrony is present, timesyncd is blocked by the unit-level Conflicts=
# relationship. If chrony is later removed, that conflict disappears and
# timedated, a preset or an explicit enablement could select unauthenticated
# plain NTP (timesyncd has no NTS support).
#
# Explicit mask symlink (/etc/systemd/system/systemd-timesyncd.service ->
# /dev/null) persists even if chrony is removed later.
echo ""
echo "[Step 2] Masking systemd-timesyncd.service"
systemctl mask systemd-timesyncd.service
if [ -L /etc/systemd/system/systemd-timesyncd.service ] && \
   [ "$(readlink /etc/systemd/system/systemd-timesyncd.service)" = "/dev/null" ]; then
    echo "  [OK] systemd-timesyncd.service masked"
else
    echo "  [WARN] mask failed (symlink not found — check systemctl output)"
fi

# ----------------------------------------------------------------------------
# Step 3: Verify chrony state directories
# ----------------------------------------------------------------------------
# The chrony package declares /var/lib/chrony (NTS cookies + drift) and
# /var/log/chrony (tracking log) as %ghost: it owns the paths + their intended
# chrony:chrony 0750 but does not materialize them at install, so they are
# absent in the %post chroot. Create them with that intended ownership/mode.
echo ""
echo "[Step 3] Verifying chrony state directories"

for d in /var/lib/chrony /var/log/chrony; do
    if [ -e "$d" ] && [ ! -d "$d" ]; then
        echo "  [FAIL] $d exists but is not a directory"
        exit 1
    fi
    install -d -o chrony -g chrony -m 0750 "$d"
    restorecon -F "$d"
    matchpathcon -V "$d"
    owner=$(stat -c "%U:%G" "$d")
    mode=$(stat -c "%a" "$d")
    if [ "$owner" != "chrony:chrony" ] || [ "$mode" != "750" ]; then
        echo "  [FAIL] $d owner/mode postcondition failed: $owner $mode"
        exit 1
    fi
    echo "  [OK] $d enforced (owner: $owner, mode: $mode)"
done

# ----------------------------------------------------------------------------
# Step 3b: Fedora-native restricted client + maintained seccomp level
# ----------------------------------------------------------------------------
# Fedora's restricted unit is specifically intended for minimal NTP/NTS client
# configurations. It starts chronyd as the chrony user (not as a privileged
# process which drops later), selects chronyd_restricted_t, bounds capabilities
# to CAP_SYS_TIME, and layers NNP/private devices/strict filesystem/systemd
# syscall filtering. Keep the package-owned -F 2 filter: it blocks fork/exec
# without the known cross-library fragility of the -F 1 syscall allowlist.
#
# `/etc/systemd/ntp-units.d/50-chronyd.list` overrides Fedora's provider list
# through systemd-timedated's documented native mechanism, so a later
# `timedatectl set-ntp true` selects the restricted service rather than silently
# re-enabling the ordinary unit.

echo ""
echo "[Step 3b] Verifying Fedora restricted chronyd client contract"

restricted_unit=/usr/lib/systemd/system/chronyd-restricted.service
if [ "$(rpm -qf --qf '%{NAME}\n' "$restricted_unit" 2>/dev/null || true)" != chrony ] \
   || [ "$(stat -c '%U:%G:%a' "$restricted_unit" 2>/dev/null || true)" != \
      root:root:644 ] \
   || ! rpm_payload_file_pristine chrony "$restricted_unit"; then
    echo "  [FAIL] Fedora chronyd-restricted.service ownership/package invalid"
    exit 1
fi
for native_line in \
    'ExecStart=/usr/sbin/chronyd -n -U $OPTIONS' \
    'SELinuxContext=system_u:system_r:chronyd_restricted_t:s0' \
    'AmbientCapabilities=CAP_SYS_TIME' \
    'CapabilityBoundingSet=CAP_SYS_TIME' \
    'NoNewPrivileges=yes' \
    'PrivateDevices=yes' \
    'ProtectSystem=strict' \
    'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX'; do
    if ! grep -qxF "$native_line" "$restricted_unit"; then
        echo "  [FAIL] Fedora restricted-unit contract missing: $native_line"
        exit 1
    fi
done
unset native_line

if [ "$(rpm -qf --qf '%{NAME}\n' /etc/sysconfig/chronyd 2>/dev/null || true)" != chrony ] \
   || [ "$(stat -c '%U:%G:%a' /etc/sysconfig/chronyd 2>/dev/null || true)" != \
      root:root:644 ] \
   || ! rpm_payload_file_pristine chrony /etc/sysconfig/chronyd \
   || [ "$(grep -cE '^[[:space:]]*OPTIONS=' /etc/sysconfig/chronyd 2>/dev/null || true)" != 1 ] \
   || ! grep -qxF 'OPTIONS="-F 2"' /etc/sysconfig/chronyd; then
    echo "  [FAIL] Fedora-owned chronyd OPTIONS=-F 2 contract invalid"
    exit 1
fi
if [ -e /etc/systemd/system/chronyd.service.d/99-noid-hardening.conf ] \
   || [ -L /etc/systemd/system/chronyd.service.d/99-noid-hardening.conf ] \
   || [ -e /etc/systemd/system/chronyd-restricted.service.d/99-noid-hardening.conf ] \
   || [ -L /etc/systemd/system/chronyd-restricted.service.d/99-noid-hardening.conf ]; then
    echo "  [FAIL] competing NoID Privacy chronyd sandbox drop-in present"
    exit 1
fi

install -d -o root -g root -m 0755 /etc/systemd/ntp-units.d
cat > /etc/systemd/ntp-units.d/50-chronyd.list <<'NTP_PROVIDER_EOF'
# NoID Privacy — keep systemd-timedated on Fedora's restricted NTS client.
chronyd-restricted.service
NTP_PROVIDER_EOF
chmod 0644 /etc/systemd/ntp-units.d/50-chronyd.list
chown root:root /etc/systemd/ntp-units.d/50-chronyd.list
restorecon -F /etc/systemd/ntp-units.d/50-chronyd.list
matchpathcon -V /etc/systemd/ntp-units.d/50-chronyd.list

# Anaconda's target package transaction can run systemctl preset after the
# compose-time enable/disable calls below. Own that native decision with an
# early system preset, so package installation cannot re-enable the ordinary
# privileged service while replacing the restricted client.
install -d -o root -g root -m 0755 /etc/systemd/system-preset
cat > /etc/systemd/system-preset/05-noid-chrony.preset <<'CHRONY_PRESET_EOF'
disable chronyd.service
enable chronyd-restricted.service
CHRONY_PRESET_EOF
chmod 0644 /etc/systemd/system-preset/05-noid-chrony.preset
chown root:root /etc/systemd/system-preset/05-noid-chrony.preset
restorecon -F /etc/systemd/system-preset/05-noid-chrony.preset
matchpathcon -V /etc/systemd/system-preset/05-noid-chrony.preset
echo "  [OK] Fedora restricted unit + OPTIONS=-F 2 + timedated provider verified"

# NetworkManager gives /etc dispatchers precedence over same-named /usr
# dispatchers. Keep Fedora's package payload pristine and use that native
# override tier to close two competing chrony control paths:
#   - 20-chrony-onoffline calls `chronyc onoffline` on ordinary link events,
#     which can make sources online before the gateway/XDP readiness marker.
#   - 20-chrony-dhcp writes DHCP-supplied NTP sources. The closed NTS policy
#     intentionally has no sourcedir for them, so executing it is redundant
#     and would become an unauthenticated source-injection path if that policy
#     ever drifted.
chrony_vendor_dispatcher_dir=/usr/lib/NetworkManager/dispatcher.d
chrony_admin_dispatcher_dir=/etc/NetworkManager/dispatcher.d
for chrony_dispatcher_name in 20-chrony-dhcp 20-chrony-onoffline; do
    chrony_vendor_dispatcher=$chrony_vendor_dispatcher_dir/$chrony_dispatcher_name
    if [ "$(rpm -qf --qf '%{NAME}\n' "$chrony_vendor_dispatcher" \
            2>/dev/null || true)" != chrony ] \
       || [ "$(stat -c '%U:%G:%a:%h' "$chrony_vendor_dispatcher" \
            2>/dev/null || true)" != root:root:755:1 ] \
       || ! rpm_payload_file_pristine chrony "$chrony_vendor_dispatcher"; then
        echo "  [FAIL] Fedora chrony dispatcher contract invalid: $chrony_dispatcher_name"
        exit 1
    fi
done
unset chrony_dispatcher_name chrony_vendor_dispatcher

install -d -o root -g root -m 0755 "$chrony_admin_dispatcher_dir"
cat > "$chrony_admin_dispatcher_dir/20-chrony-onoffline" \
    <<'CHRONY_ONOFFLINE_SHADOW_EOF'
#!/usr/bin/sh
# NoID Privacy — NetworkManager vendor-dispatcher shadow.
# Gateway/XDP readiness is the sole authority for chrony source transitions.
exit 0
CHRONY_ONOFFLINE_SHADOW_EOF
cat > "$chrony_admin_dispatcher_dir/20-chrony-dhcp" \
    <<'CHRONY_DHCP_SHADOW_EOF'
#!/usr/bin/sh
# NoID Privacy — NetworkManager vendor-dispatcher shadow.
# The closed NTS source manifest intentionally rejects DHCP time sources.
exit 0
CHRONY_DHCP_SHADOW_EOF
chmod 0755 \
    "$chrony_admin_dispatcher_dir/20-chrony-onoffline" \
    "$chrony_admin_dispatcher_dir/20-chrony-dhcp"
chown root:root \
    "$chrony_admin_dispatcher_dir/20-chrony-onoffline" \
    "$chrony_admin_dispatcher_dir/20-chrony-dhcp"
restorecon -F \
    "$chrony_admin_dispatcher_dir/20-chrony-onoffline" \
    "$chrony_admin_dispatcher_dir/20-chrony-dhcp"
matchpathcon -V \
    "$chrony_admin_dispatcher_dir/20-chrony-onoffline" \
    "$chrony_admin_dispatcher_dir/20-chrony-dhcp"
echo "  [OK] Fedora chrony dispatcher payloads pristine; readiness-only shadows installed"
unset chrony_vendor_dispatcher_dir chrony_admin_dispatcher_dir

# M04 retires readiness before every gateway transition and publishes it only
# after DHCP gateway learning, permanent-neighbor publication, XDP/TC topology
# rebuild and the complete boundary postcheck. Chronyd itself remains Fedora's
# unchanged restricted unit. Two separate chrony-owned one-shots move its
# declaratively offline sources across that boundary without executing
# chronyc in either the NoNewPrivileges first-boot domain or NetworkManager's
# dispatcher domain.
cat > /etc/systemd/system/noid-chrony-network-offline.service \
    <<'CHRONY_NETWORK_OFFLINE_SERVICE_EOF'
[Unit]
Description=NoID Privacy: hold NTS sources offline during gateway/XDP transition
Requires=chronyd-restricted.service
After=chronyd-restricted.service
Before=noid-chrony-network-online.service

[Service]
Type=oneshot
User=chrony
Group=chrony
ExecStart=/usr/local/libexec/noid-network-readiness offline-consumer
# Do not set NoNewPrivileges here: Fedora SELinux intentionally transitions
# chronyc_exec_t into chronyc_t. The caller domains cannot receive replies
# from chronyd_restricted_t directly. The chrony UID, empty capability set,
# SUID/SGID ban, AF_UNIX-only boundary and remaining sandbox constrain this
# synchronous transition one-shot.
PrivateDevices=yes
PrivateTmp=yes
ProtectSystem=strict
# ProtectSystem=strict makes /run read-only, and this one-shot needs to write
# under /run/chrony twice: the transition lock it takes to serialise against
# its sibling, and the reply socket chronyc itself creates next to
# chronyd.sock. Without this the unit dies before running chronyc at all --
# verified on a live host, where the sandbox reports both "Read-only file
# system" for the lock and "Could not create /run/chrony/chronyc.<pid>".
# Every NTS source ships `offline`, so a dead online-consumer means the clock
# never synchronises. Not RuntimeDirectory=: that would delete /run/chrony,
# including chronyd's own socket, when this one-shot stops.
ReadWritePaths=/run/chrony
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
CapabilityBoundingSet=
CHRONY_NETWORK_OFFLINE_SERVICE_EOF

cat > /etc/systemd/system/noid-chrony-network-online.service \
    <<'CHRONY_NETWORK_ONLINE_SERVICE_EOF'
[Unit]
Description=NoID Privacy: bring NTS sources online after gateway/XDP readiness
Requires=chronyd-restricted.service
After=chronyd-restricted.service
ConditionPathExists=/run/noid-privacy/gateway-xdp.ready

[Service]
Type=oneshot
User=chrony
Group=chrony
ExecStartPre=!/usr/local/libexec/noid-network-readiness consumer-precheck
ExecStart=/usr/local/libexec/noid-network-readiness online-consumer
# DNS and NTS-KE can remain unavailable after the physical gateway/XDP
# boundary is already valid. The consumer deliberately returns every source
# offline when its bounded resolver window expires; retry that closed state
# instead of leaving time synchronisation dormant until another link event.
# Back off to one attempt per 15 minutes during a prolonged upstream outage.
# A retired or invalid READY marker makes the existing precheck/consumer exit
# successfully, which terminates this retry chain without bringing a source
# online across an unverified boundary.
Restart=on-failure
RestartSec=30s
RestartSteps=4
RestartMaxDelaySec=15min
# Do not set NoNewPrivileges here: Fedora SELinux intentionally transitions
# chronyc_exec_t into chronyc_t. NNP blocks that transition, leaves the client
# in unconfined_service_t and makes chronyd_restricted_t unable to reply to its
# Unix datagram socket. The chrony UID, empty capability set, SUID/SGID ban,
# AF_UNIX-only boundary and remaining sandbox still constrain this one-shot.
PrivateDevices=yes
PrivateTmp=yes
ProtectSystem=strict
# ProtectSystem=strict makes /run read-only, and this one-shot needs to write
# under /run/chrony twice: the transition lock it takes to serialise against
# its sibling, and the reply socket chronyc itself creates next to
# chronyd.sock. Without this the unit dies before running chronyc at all --
# verified on a live host, where the sandbox reports both "Read-only file
# system" for the lock and "Could not create /run/chrony/chronyc.<pid>".
# Every NTS source ships `offline`, so a dead online-consumer means the clock
# never synchronises. Not RuntimeDirectory=: that would delete /run/chrony,
# including chronyd's own socket, when this one-shot stops.
ReadWritePaths=/run/chrony
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
CapabilityBoundingSet=

[Install]
WantedBy=chronyd-restricted.service
CHRONY_NETWORK_ONLINE_SERVICE_EOF
chmod 0644 \
    /etc/systemd/system/noid-chrony-network-offline.service \
    /etc/systemd/system/noid-chrony-network-online.service
chown root:root \
    /etc/systemd/system/noid-chrony-network-offline.service \
    /etc/systemd/system/noid-chrony-network-online.service
restorecon -F \
    /etc/systemd/system/noid-chrony-network-offline.service \
    /etc/systemd/system/noid-chrony-network-online.service
matchpathcon -V \
    /etc/systemd/system/noid-chrony-network-offline.service \
    /etc/systemd/system/noid-chrony-network-online.service

# Retire the earlier path-watch prototype. M04 starts the consumer directly
# when it atomically publishes readiness. Enabling the same oneshot as a
# chronyd-restricted.service want also re-applies `chronyc online` after a
# legitimate daemon restart while an already verified marker still exists.
systemctl disable noid-chrony-network-online.path >/dev/null 2>&1 || true
rm -f /etc/systemd/system/noid-chrony-network-online.path \
    /etc/systemd/system/multi-user.target.wants/noid-chrony-network-online.path

# ----------------------------------------------------------------------------
# Step 3c: deliberate local-console recovery for a dead/wildly wrong RTC
# ----------------------------------------------------------------------------
# NTS-KE authenticates with TLS. If the wall clock predates a certificate's
# notBefore or exceeds its notAfter, `chronyc makestep` has no authenticated
# measurement to apply. Do not solve that dependency cycle with plaintext NTP
# or chrony's security-sensitive `nocerttimecheck` escape hatch. This manual
# helper instead seeds a separately verified UTC value at a physical Linux VT,
# then restarts the unchanged NTS-only source policy.

echo ""
echo "[Step 3c] Installing authenticated bad-clock recovery workflow"

cat > /usr/local/sbin/noid-time-recovery <<'TIME_RECOVERY_EOF'
#!/bin/bash
# Deliberately seed a plausibly current wall clock from a UTC value which the
# local operator verified independently, then restart NoID Privacy's unchanged
# NTS-only chronyd policy. This helper never fetches time and never weakens
# NTS checks.
set -euo pipefail

PATH=/usr/sbin:/usr/bin
LC_ALL=C
export PATH LC_ALL
umask 077

# shellcheck source=/dev/null
[ ! -r /usr/local/lib/noid-privacy/agent-install-format.sh ] || \
    NOID_FMT_AUTO_TITLE="NoID Privacy — Time Recovery" \
    NOID_FMT_AUTO_SUBTITLE="Offline NTS clock recovery" \
    . /usr/local/lib/noid-privacy/agent-install-format.sh

# A second, image-relative plausibility bound catches a confirmed year typo
# without trusting the currently broken clock. Five leap-years is deliberately
# generous for recovery; an older image needs a maintained replacement rather
# than an ever-wider bootstrap window.
MAX_RECOVERY_HORIZON_SECONDS=158112000

usage() {
    cat <<'USAGE_EOF'
Usage:
  sudo noid-time-recovery set YYYY-MM-DDTHH:MM:SSZ

Run this only from a physical Linux text console (for example Ctrl+Alt+F3).
Obtain the exact UTC value from an independently verified clock. The helper
does not contact any time server and does not disable NTS certificate checks.
USAGE_EOF
}

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

require_root() {
    (( EUID == 0 )) || die "root is required (use sudo from the local VT)"
}

require_local_vt() {
    local tty_path
    [[ -t 0 && -t 1 && -t 2 ]] || \
        die "stdin, stdout and stderr must all be the physical console TTY"
    [[ -z "${SSH_CONNECTION:-}${SSH_CLIENT:-}${SSH_TTY:-}" ]] || \
        die "remote sessions are not accepted for clock recovery"
    tty_path=$(/usr/bin/tty) || die "cannot identify the controlling TTY"
    [[ "$tty_path" =~ ^/dev/tty([1-9]|[1-5][0-9]|6[0-3])$ ]] || \
        die "use a physical Linux VT such as /dev/tty3, not $tty_path"
}

canonical_timestamp() {
    local value=$1 canonical
    [[ "$value" =~ ^[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$ ]] \
        || return 1
    canonical=$(/usr/bin/date --utc --date="$value" '+%Y-%m-%dT%H:%M:%SZ') \
        || return 1
    [[ "$canonical" == "$value" ]] || return 1
    printf '%s\n' "$canonical"
}

timestamp_epoch() {
    /usr/bin/date --utc --date="$1" +%s
}

load_build_floor() {
    local path=$1 expected_uid=$2 expected_gid=$3 expected_mode=$4
    local metadata line_count value
    [[ -f "$path" && ! -L "$path" ]] || return 1
    metadata=$(/usr/bin/stat -c '%u:%g:%a:%h' -- "$path") || return 1
    [[ "$metadata" == "${expected_uid}:${expected_gid}:${expected_mode}:1" ]] \
        || return 1
    line_count=$(/usr/bin/grep -c '^NOID_BUILD_TIMESTAMP=' "$path" || true)
    [[ "$line_count" == 1 ]] || return 1
    value=$(/usr/bin/sed -nE 's/^NOID_BUILD_TIMESTAMP="([^"]+)"$/\1/p' "$path")
    canonical_timestamp "$value"
}

current_utc() {
    /usr/bin/date --utc '+%Y-%m-%dT%H:%M:%SZ'
}

confirm_candidate() {
    local expected=$1 entered
    IFS= read -r entered
    [[ "$entered" == "$expected" ]]
}

stop_chronyd() { /usr/bin/systemctl stop chronyd-restricted.service; }
start_chronyd() { /usr/bin/systemctl start chronyd-restricted.service; }
chronyd_active() { /usr/bin/systemctl is-active --quiet chronyd-restricted.service; }
set_system_clock() { /usr/bin/date --utc --set="@$1" >/dev/null; }
rtc_exists() { [[ -e /dev/rtc || -e /dev/rtc0 ]]; }
sync_rtc() { /usr/sbin/hwclock --systohc --utc; }
audit_event() { /usr/bin/logger -p authpriv.notice -t noid-time-recovery -- "$1"; }

restore_needed=0
recovery_cleanup() {
    local rc=$?
    trap - EXIT HUP INT TERM
    if (( restore_needed )); then
        if ! start_chronyd; then
            printf '%s\n' \
                'ERROR: failed to restore chronyd-restricted.service after recovery failure' >&2
            rc=1
        fi
    fi
    exit "$rc"
}

main() {
    local candidate build_floor candidate_epoch build_epoch max_epoch current expected
    local rtc_failed=0

    case "${1:-}" in
        -h|--help)
            [[ $# -eq 1 ]] || { usage >&2; exit 2; }
            usage
            exit 0
            ;;
    esac
    [[ $# -eq 2 && "$1" == set ]] || { usage >&2; exit 2; }

    require_root
    require_local_vt

    candidate=$(canonical_timestamp "$2") || \
        die "timestamp must be a real, exact UTC value: YYYY-MM-DDTHH:MM:SSZ"
    build_floor=$(load_build_floor /etc/noid-build-info 0 0 644) || \
        die "/etc/noid-build-info is missing, aliased, misowned or malformed"
    candidate_epoch=$(timestamp_epoch "$candidate") || die "cannot parse candidate UTC"
    build_epoch=$(timestamp_epoch "$build_floor") || die "cannot parse build timestamp"
    (( candidate_epoch >= build_epoch )) || \
        die "candidate UTC predates the immutable image timestamp $build_floor"
    max_epoch=$((build_epoch + MAX_RECOVERY_HORIZON_SECONDS))
    (( candidate_epoch <= max_epoch )) || \
        die "candidate UTC exceeds the image-relative five-year recovery horizon"
    current=$(current_utc) || die "cannot read current UTC"

    printf '%s\n' \
        "Current system UTC:  $current" \
        "Candidate source UTC: $candidate" \
        "Image time floor:     $build_floor" \
        "" \
        "The candidate must come from an independently verified clock and be" \
        "close enough to current UTC for NTS TLS validation. This operation may move" \
        "the clock backwards and affect timestamps, timers and running programs."
    expected="SET VERIFIED UTC $candidate"
    printf 'Type exactly [%s]: ' "$expected"
    confirm_candidate "$expected" || die "confirmation did not match; no state changed"

    restore_needed=1
    trap recovery_cleanup EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM

    audit_event "operator confirmed local-VT manual clock recovery" || true
    stop_chronyd || die "could not stop chronyd-restricted.service; clock was not changed"
    set_system_clock "$candidate_epoch" || die "system clock update failed"

    if rtc_exists; then
        if ! sync_rtc; then
            rtc_failed=1
            printf '%s\n' \
                'WARNING: system time changed, but writing the hardware RTC failed.' >&2
        fi
    else
        printf '%s\n' \
            'WARNING: no hardware RTC was found; the manual seed may not survive reboot.' >&2
    fi

    start_chronyd || die "clock changed, but chronyd-restricted.service could not be started"
    chronyd_active || die "clock changed, but chronyd-restricted.service is not active"
    restore_needed=0
    trap - EXIT HUP INT TERM
    audit_event "manual clock seed applied; NTS-only chronyd restarted" || true

    printf '%s\n' \
        "[OK] Manual UTC seed applied: $candidate" \
        '[OK] NTS-only chronyd-restricted.service is active.' \
        'Verify authentication/synchronization with:' \
        '  sudo chronyc -N authdata' \
        '  sudo chronyc tracking' \
        '  sudo chronyc sources -v'
    if (( rtc_failed )); then
        die "chronyd was restored, but the hardware RTC write failed; repair the RTC/battery"
    fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
TIME_RECOVERY_EOF

chmod 0755 /usr/local/sbin/noid-time-recovery
chown root:root /usr/local/sbin/noid-time-recovery

mkdir -p /usr/share/doc/noid-privacy
cat > /usr/share/doc/noid-privacy/11-time-recovery.md <<'TIME_RECOVERY_DOC_EOF'
# NoID Privacy authenticated time recovery

## When this is needed

NTS exchanges keys over TLS. A large initial offset which is still inside the
NTS certificates' validity window is corrected automatically after NTS
authentication and Chrony's source selection. This includes the common firmware
case where an RTC containing local civil time is interpreted as UTC. The early
`makestep` policy applies the correction and `rtcsync` subsequently disciplines
the hardware RTC; no manual recovery is needed.

If a dead RTC instead leaves the wall clock before an NTS certificate's
activation time or after its expiration, certificate validation correctly fails
and `chronyc makestep` has no authenticated measurement to use. The recovery
boundary seeds only an approximate wall clock; chronyd still performs the precise
authenticated correction afterward.

NoID Privacy does **not** enable plaintext NTP, `nocerttimecheck`, timesyncd or a remote
time-fetching bootstrap for this case.

## Deliberate local-VT procedure

1. Obtain current UTC from an independently verified clock. Prefer comparison
   of two independent devices/sources. Do not derive it from an unauthenticated
   response fetched by the affected workstation.
2. On the workstation, press `Ctrl+Alt+F3`, log in at that physical text
   console, and run (substitute the verified value):

       sudo noid-time-recovery set 2026-07-13T18:42:00Z

3. Review the current time, requested time and root-owned image-time floor.
   Type the displayed timestamp-bound confirmation exactly. Piped input,
   graphical pseudo-terminals, serial/SSH sessions, invalid calendar values,
   timestamps predating the image, values more than five years beyond the image
   timestamp, aliased metadata, wrong ownership/mode and malformed build
   metadata are rejected before the service or clock changes.
4. Return to the graphical session with `Ctrl+Alt+F2` after verification.

The helper stops chronyd only after confirmation, sets the system clock, writes
the hardware RTC when one exists, and starts the same NTS-only configuration.
An error after the stop triggers a best-effort chronyd restart. It does not
modify `/etc/chrony.conf`, the NTS cookie store or certificate validation.

## Verify the authenticated result

    systemctl is-active chronyd-restricted.service
    sudo chronyc -N authdata
    sudo chronyc tracking
    sudo chronyc sources -v
    journalctl -u chronyd-restricted.service -b --no-pager

In `authdata`, established NTS sources have non-zero key/type/length fields and
cookies. `tracking` should eventually report a normal leap status. If NTS-KE
still cannot validate the server certificates, verify a better UTC value and
repeat the local-VT procedure. Do not relax NTS certificate validation.

If the RTC write fails, the helper still restores chronyd but exits non-zero.
Repair the RTC/battery; otherwise the manual procedure may be needed again
after power loss. File deletion or clock correction does not rewrite earlier
journal, audit, snapshot or backup timestamps.
TIME_RECOVERY_DOC_EOF

chmod 0644 /usr/share/doc/noid-privacy/11-time-recovery.md
chown root:root /usr/share/doc/noid-privacy/11-time-recovery.md
restorecon -F /usr/local/sbin/noid-time-recovery \
    /usr/share/doc/noid-privacy/11-time-recovery.md
matchpathcon -V /usr/local/sbin/noid-time-recovery
matchpathcon -V /usr/share/doc/noid-privacy/11-time-recovery.md
echo "  [OK] local-VT time-recovery helper + guide installed"

# ----------------------------------------------------------------------------
# Step 4: chrony.conf syntax pre-validation + enable restricted service
# ----------------------------------------------------------------------------
# Pre-validate chrony.conf via `chronyd -p`
# (print configuration and exit) before enabling. Analog to visudo -cf in
# Module 10 — broken config would otherwise mean silent time-sync failure
# at next boot (timesyncd masked = no fallback). Use -f to point at our
# config explicitly; -p exits 0 on syntax-OK, non-zero on error.
echo ""
echo "[Step 4] Validating /etc/chrony.conf + enabling chronyd-restricted.service"

if ! chronyd -p -f /etc/chrony.conf >/var/log/ks-11-chronyd-validate.log 2>&1; then
    echo "  [FAIL] /etc/chrony.conf invalid syntax — see /var/log/ks-11-chronyd-validate.log"
    cat /var/log/ks-11-chronyd-validate.log || true
    exit 1
fi
echo "  [OK] /etc/chrony.conf syntax validated (chronyd -p -f)"

systemctl disable chronyd.service
systemctl enable chronyd-restricted.service noid-chrony-network-online.service
echo "  [OK] ordinary chronyd.service disabled; restricted client + readiness consumer enabled"

# ----------------------------------------------------------------------------
# Step 5: Verification
# ----------------------------------------------------------------------------

echo ""
echo "[Step 5] Verification"

fail=0

# 5.1 — generated artifacts are regular, singly linked, owned and labeled.
if [ -f /etc/chrony.conf ] && [ ! -L /etc/chrony.conf ] \
   && [ "$(stat -c '%U:%G:%a:%h' /etc/chrony.conf 2>/dev/null || true)" = \
        root:root:644:1 ] \
   && matchpathcon -V /etc/chrony.conf >/dev/null 2>&1; then
    echo "  [OK] chrony.conf type, metadata and SELinux label"
else
    echo "  [FAIL] chrony.conf type, metadata or SELinux label invalid"
    fail=$((fail + 1))
fi

# 5.2 — chrony.conf contains exactly 6 manifest-bound offline NTS IPv4 servers
# grep -c returns "0" + exit 1 on zero matches; use `|| true` + default-zero
# to avoid the bash $(...) || echo 0 multi-line capture bug.
nts_count=$(grep -c "^server .* iburst nts ipv4 maxpoll 11 offline$" /etc/chrony.conf 2>/dev/null || true)
nts_count=${nts_count:-0}
if [ "$nts_count" -eq 6 ]; then
    echo "  [OK] 6 NTS servers start offline with ipv4 keyword"
else
    echo "  [FAIL] expected 6 offline NTS servers with ipv4, found $nts_count"
    fail=$((fail + 1))
fi

nts_manifest=/usr/share/doc/noid-privacy/11-nts-sources.tsv
if [ -f "$nts_manifest" ] && [ ! -L "$nts_manifest" ] \
   && [ "$(stat -c '%U:%G:%a:%h' "$nts_manifest" 2>/dev/null || true)" = \
        root:root:644:1 ] \
   && matchpathcon -V "$nts_manifest" >/dev/null 2>&1 \
   && awk -F '\t' '
        NR == 1 {
            if ($0 != "hostname\toperator\tcountry\toperator_status\toperator_source\treviewed_on") exit 1
            next
        }
        NR == 2 { review_date=$6 }
        NF != 6 || $1 !~ /^[a-z0-9.-]+$/ || $2 !~ /^[A-Za-z-]+$/ ||
        $3 !~ /^(DE|SE|NL)$/ || $4 !~ /^(public-service|production)$/ ||
        $5 !~ /^https:\/\// || $6 !~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/ ||
        $6 != review_date || seen[$1]++ { bad=1 }
        END { exit !(NR == 7 && review_date != "" && bad == 0) }
    ' "$nts_manifest" \
   && cmp -s \
        <(
            awk -F '\t' \
                'NR > 1 {print "server " $1 " iburst nts ipv4 maxpoll 11 offline"}' \
                "$nts_manifest"
            cat <<'EXPECTED_CHRONY_ACTIVE_EOF'
minsources 3
maxupdateskew 100.0
keyfile /dev/null
driftfile /var/lib/chrony/drift
makestep 1.0 3
maxchange 1000 3 0
rtcsync
ntsdumpdir /var/lib/chrony
leapseclist /usr/share/zoneinfo/leap-seconds.list
bindcmdaddress /var/run/chrony/chronyd.sock
cmdport 0
EXPECTED_CHRONY_ACTIVE_EOF
        ) \
        <(awk '!/^[[:space:]]*(#|$)/ {print}' /etc/chrony.conf); then
    echo "  [OK] active Chrony config exactly matches the closed dated manifest"
else
    echo "  [FAIL] NTS manifest, active-config or artifact contract invalid"
    fail=$((fail + 1))
fi

# 5.3 — minimum selectable-source threshold
if grep -qE "^minsources[[:space:]]+3$" /etc/chrony.conf; then
    echo "  [OK] minsources 3 minimum-selectable-source threshold"
else
    echo "  [FAIL] minsources 3 missing"
    fail=$((fail + 1))
fi

# 5.4 — cmdport 0 + unix-socket bindcmdaddress
if grep -q "^cmdport 0$" /etc/chrony.conf && \
   grep -q "^bindcmdaddress /var/run/chrony/chronyd.sock$" /etc/chrony.conf; then
    echo "  [OK] cmdport 0 + unix-socket bindcmdaddress"
else
    echo "  [FAIL] chrony command interface not hardened"
    fail=$((fail + 1))
fi

# 5.5 — measurement-file logging directives MUST be absent
# Fedora's chrony stanza inherits about 35 days of global weekly retention,
# beyond M42's scoped 30-day boundary; measurement logs also expose the source
# and oscillator-drift signal. Live debug via chronyc remains available.
if grep -qE '^[[:space:]]*(log([[:space:]]|$)|logdir([[:space:]]|$)|logbanner([[:space:]]|$))' \
        /etc/chrony.conf; then
    echo "  [FAIL] Chrony measurement-file logging directive present"
    fail=$((fail + 1))
else
    echo "  [OK] Chrony measurement-file logging disabled"
fi

# 5.6 — every configured server line uses NTS. The exact active-config check
# above independently excludes pools and all other dynamic/additional sources.
ntp_fallback_found=0
srv_total=$(grep -c "^server " /etc/chrony.conf 2>/dev/null || true)
srv_nts=$(grep -c "^server .* nts " /etc/chrony.conf 2>/dev/null || true)
srv_total=${srv_total:-0}
srv_nts=${srv_nts:-0}
if [ "$srv_total" -ne "$srv_nts" ]; then
    echo "  [FAIL] $srv_total server lines but only $srv_nts have 'nts' keyword"
    ntp_fallback_found=1
fi
if [ "$ntp_fallback_found" -eq 0 ]; then
    echo "  [OK] no unauthenticated NTP fallback (all $srv_total servers NTS)"
else
    fail=$((fail + 1))
fi

# 5.7 — systemd-timesyncd remains Fedora-owned and masked.
if [ "$(rpm -qf --qf '%{NAME}\n' \
        /usr/lib/systemd/system/systemd-timesyncd.service \
        2>/dev/null || true)" = systemd-udev ] \
   && [ -L /etc/systemd/system/systemd-timesyncd.service ] && \
   [ "$(readlink /etc/systemd/system/systemd-timesyncd.service)" = "/dev/null" ]; then
    echo "  [OK] Fedora systemd-udev timesyncd service masked"
else
    echo "  [FAIL] systemd-timesyncd ownership/mask contract invalid"
    fail=$((fail + 1))
fi

# 5.8 — restricted client persistently enabled; ordinary service disabled
restricted_state=$(systemctl is-enabled chronyd-restricted.service \
    2>/dev/null || true)
ordinary_state=$(systemctl is-enabled chronyd.service 2>/dev/null || true)
readiness_service_state=$(systemctl is-enabled noid-chrony-network-online.service \
    2>/dev/null || true)
if [ "$restricted_state" = enabled ] && [ "$ordinary_state" = disabled ] \
   && [ "$readiness_service_state" = enabled ]; then
    echo "  [OK] restricted chronyd client + readiness consumer enabled exclusively"
else
    echo "  [FAIL] restricted/ordinary/readiness states: $restricted_state/$ordinary_state/$readiness_service_state"
    fail=$((fail + 1))
fi
unset restricted_state ordinary_state readiness_service_state

# 5.9 — Module 05 resolved drop-in present (cross-reference check)
if [ -f /etc/systemd/resolved.conf.d/99-privacy.conf ]; then
    echo "  [OK] Module 05 resolved drop-in present (cross-ref)"
else
    echo "  [WARN] Module 05 resolved drop-in missing — check Module 05 kickstart"
fi

# 5.10 — native sandbox/provider is the sole chronyd policy owner. Repeat the
# package contract here after every later module has run, rather than relying
# only on the pre-enable Step 3b observation.
native_chronyd_fail=0
restricted_unit=/usr/lib/systemd/system/chronyd-restricted.service
provider_file=/etc/systemd/ntp-units.d/50-chronyd.list
preset_file=/etc/systemd/system-preset/05-noid-chrony.preset
if [ "$(rpm -qf --qf '%{NAME}\n' "$restricted_unit" 2>/dev/null || true)" != chrony ] \
   || [ "$(stat -c '%U:%G:%a' "$restricted_unit" 2>/dev/null || true)" != \
      root:root:644 ] \
   || ! rpm_payload_file_pristine chrony "$restricted_unit"; then
    native_chronyd_fail=1
fi
for native_line in \
    'ExecStart=/usr/sbin/chronyd -n -U $OPTIONS' \
    'SELinuxContext=system_u:system_r:chronyd_restricted_t:s0' \
    'AmbientCapabilities=CAP_SYS_TIME' \
    'CapabilityBoundingSet=CAP_SYS_TIME' \
    'NoNewPrivileges=yes' \
    'PrivateDevices=yes' \
    'ProtectSystem=strict' \
    'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX'; do
    grep -qxF "$native_line" "$restricted_unit" 2>/dev/null || \
        native_chronyd_fail=1
done
unset native_line
if [ "$(rpm -qf --qf '%{NAME}\n' /etc/sysconfig/chronyd 2>/dev/null || true)" != chrony ] \
   || [ "$(stat -c '%U:%G:%a' /etc/sysconfig/chronyd 2>/dev/null || true)" != \
      root:root:644 ] \
   || ! rpm_payload_file_pristine chrony /etc/sysconfig/chronyd \
   || [ "$(grep -cE '^[[:space:]]*OPTIONS=' /etc/sysconfig/chronyd 2>/dev/null || true)" != 1 ] \
   || ! grep -qxF 'OPTIONS="-F 2"' /etc/sysconfig/chronyd; then
    native_chronyd_fail=1
fi
if [ "$(stat -c '%U:%G:%a' /etc/systemd/ntp-units.d 2>/dev/null || true)" != \
     root:root:755 ] \
   || [ ! -f "$provider_file" ] || [ -L "$provider_file" ] \
   || [ "$(stat -c '%U:%G:%a:%h' "$provider_file" 2>/dev/null || true)" != \
      root:root:644:1 ] \
   || ! matchpathcon -V "$provider_file" >/dev/null 2>&1 \
   || [ "$(grep -cEv '^[[:space:]]*(#|$)' "$provider_file" 2>/dev/null || true)" != 1 ] \
   || [ "$(grep -cFx 'chronyd-restricted.service' "$provider_file" 2>/dev/null || true)" != 1 ]; then
    native_chronyd_fail=1
fi
if [ ! -f "$preset_file" ] || [ -L "$preset_file" ] \
   || [ "$(stat -c '%U:%G:%a:%h' "$preset_file" 2>/dev/null || true)" != \
      root:root:644:1 ] \
   || ! matchpathcon -V "$preset_file" >/dev/null 2>&1 \
   || [ "$(cat "$preset_file" 2>/dev/null || true)" != \
      $'disable chronyd.service\nenable chronyd-restricted.service' ]; then
    native_chronyd_fail=1
fi
if [ -e /etc/systemd/system/chronyd.service.d/99-noid-hardening.conf ] \
   || [ -L /etc/systemd/system/chronyd.service.d/99-noid-hardening.conf ] \
   || [ -e /etc/systemd/system/chronyd-restricted.service.d/99-noid-hardening.conf ] \
   || [ -L /etc/systemd/system/chronyd-restricted.service.d/99-noid-hardening.conf ]; then
    native_chronyd_fail=1
fi
if [ "$native_chronyd_fail" -eq 0 ]; then
    echo "  [OK] Fedora restricted unit/provider/-F 2 contract is exclusive"
else
    echo "  [FAIL] native restricted chronyd unit/provider/-F 2 contract invalid"
    fail=$((fail + 1))
fi

# 5.11 — tzdata provides leap-seconds.list (required for leapseclist directive)
if [ -f /usr/share/zoneinfo/leap-seconds.list ]; then
    echo "  [OK] leap-seconds.list present (tzdata)"
else
    echo "  [FAIL] /usr/share/zoneinfo/leap-seconds.list missing — tzdata?"
    fail=$((fail + 1))
fi

# 5.12 — deliberate bad-clock recovery artifacts and unchanged auth boundary
if [ -f /usr/local/sbin/noid-time-recovery ] \
   && [ ! -L /usr/local/sbin/noid-time-recovery ] \
   && [ "$(stat -c '%U:%G:%a:%h' /usr/local/sbin/noid-time-recovery \
        2>/dev/null || true)" = root:root:755:1 ] \
   && [ -f /usr/share/doc/noid-privacy/11-time-recovery.md ] \
   && [ ! -L /usr/share/doc/noid-privacy/11-time-recovery.md ] \
   && [ "$(stat -c '%U:%G:%a:%h' \
        /usr/share/doc/noid-privacy/11-time-recovery.md \
        2>/dev/null || true)" = root:root:644:1 ] \
   && matchpathcon -V /usr/local/sbin/noid-time-recovery >/dev/null 2>&1 \
   && matchpathcon -V /usr/share/doc/noid-privacy/11-time-recovery.md \
        >/dev/null 2>&1 \
   && bash -n /usr/local/sbin/noid-time-recovery \
   && ! grep -qE '^[[:space:]]*nocerttimecheck([[:space:]]|$)' /etc/chrony.conf; then
    echo "  [OK] local-VT recovery installed without an NTS certificate-time bypass"
else
    echo "  [FAIL] local-VT recovery artifact/authentication boundary invalid"
    fail=$((fail + 1))
fi

# 5.13 — event-driven source gating leaves Fedora's restricted unit intact.
offline_readiness_unit=/etc/systemd/system/noid-chrony-network-offline.service
online_readiness_unit=/etc/systemd/system/noid-chrony-network-online.service
if [ -f "$offline_readiness_unit" ] && [ ! -L "$offline_readiness_unit" ] \
   && [ "$(stat -c '%U:%G:%a:%h' "$offline_readiness_unit")" = root:root:644:1 ] \
   && [ -f "$online_readiness_unit" ] && [ ! -L "$online_readiness_unit" ] \
   && [ "$(stat -c '%U:%G:%a:%h' "$online_readiness_unit")" = root:root:644:1 ] \
   && [ ! -e /etc/systemd/system/noid-chrony-network-online.path ] \
   && [ ! -L /etc/systemd/system/noid-chrony-network-online.path ] \
   && grep -qxF \
        'ExecStart=/usr/local/libexec/noid-network-readiness offline-consumer' \
        "$offline_readiness_unit" \
   && grep -qxF 'User=chrony' "$offline_readiness_unit" \
   && ! grep -qxF 'NoNewPrivileges=yes' "$offline_readiness_unit" \
   && grep -qxF \
        'ExecStart=/usr/local/libexec/noid-network-readiness online-consumer' \
        "$online_readiness_unit" \
   && grep -qxF 'Restart=on-failure' "$online_readiness_unit" \
   && grep -qxF 'RestartSec=30s' "$online_readiness_unit" \
   && grep -qxF 'RestartSteps=4' "$online_readiness_unit" \
   && grep -qxF 'RestartMaxDelaySec=15min' "$online_readiness_unit" \
   && grep -qxF 'WantedBy=chronyd-restricted.service' \
        "$online_readiness_unit" \
   && ! grep -qxF 'NoNewPrivileges=yes' "$online_readiness_unit" \
   && systemd-analyze verify \
        "$offline_readiness_unit" "$online_readiness_unit"; then
    echo "  [OK] readiness gates NTS sources through SELinux-compatible one-shots with bounded retry backoff"
else
    echo "  [FAIL] chrony network-readiness unit contracts invalid"
    fail=$((fail + 1))
fi
unset offline_readiness_unit online_readiness_unit

# 5.14 — no vendor dispatcher can bypass the readiness or closed-source gates.
chrony_vendor_dispatcher_dir=/usr/lib/NetworkManager/dispatcher.d
chrony_admin_dispatcher_dir=/etc/NetworkManager/dispatcher.d
chrony_dispatcher_fail=0
for chrony_dispatcher_name in 20-chrony-dhcp 20-chrony-onoffline; do
    chrony_vendor_dispatcher=$chrony_vendor_dispatcher_dir/$chrony_dispatcher_name
    chrony_admin_dispatcher=$chrony_admin_dispatcher_dir/$chrony_dispatcher_name
    if [ "$(rpm -qf --qf '%{NAME}\n' "$chrony_vendor_dispatcher" \
            2>/dev/null || true)" != chrony ] \
       || [ "$(stat -c '%U:%G:%a:%h' "$chrony_vendor_dispatcher" \
            2>/dev/null || true)" != root:root:755:1 ] \
       || ! rpm_payload_file_pristine chrony "$chrony_vendor_dispatcher" \
       || [ ! -f "$chrony_admin_dispatcher" ] \
       || [ -L "$chrony_admin_dispatcher" ] \
       || [ "$(stat -c '%U:%G:%a:%h' "$chrony_admin_dispatcher" \
            2>/dev/null || true)" != root:root:755:1 ] \
       || ! matchpathcon -V "$chrony_admin_dispatcher" >/dev/null 2>&1 \
       || [ "$(awk '!/^[[:space:]]*(#|$)/ {print}' \
            "$chrony_admin_dispatcher" 2>/dev/null || true)" != 'exit 0' ]; then
        chrony_dispatcher_fail=1
    fi
done
if [ "$chrony_dispatcher_fail" -eq 0 ]; then
    echo "  [OK] readiness is the sole chrony network-state authority"
else
    echo "  [FAIL] a Fedora chrony dispatcher is unshadowed or modified"
    fail=$((fail + 1))
fi
unset chrony_vendor_dispatcher_dir chrony_admin_dispatcher_dir
unset chrony_dispatcher_name chrony_vendor_dispatcher chrony_admin_dispatcher
unset chrony_dispatcher_fail

if [ $fail -gt 0 ]; then
    echo ""
    echo "[Module 11] FAILED ($fail checks)"
    exit 1
fi

echo ""
echo "=============================================================="
echo "[Module 11] Done — all checks passed"
echo "=============================================================="

%end

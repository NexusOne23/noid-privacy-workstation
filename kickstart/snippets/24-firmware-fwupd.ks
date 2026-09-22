# ============================================================================
# Module 24 — Firmware / fwupd Hardening
# Status: LOCKED 2026-08-02 (v24) — keep fwupd history state private.
#
# Covers:
#   - /etc/fwupd/remotes.d/lvfs.conf (LVFS_EOF): LVFS stable ENABLED
#     (firmware updates are security-critical), AutomaticReports +
#     AutomaticSecurityReports=false, no active ReportURI key
#   - /etc/fwupd/remotes.d/lvfs-testing.conf (LVFSTEST_EOF): disabled,
#     AutomaticReports + AutomaticSecurityReports=false, no active ReportURI
#   - /etc/fwupd/remotes.d/lvfs-embargo.conf (LVFSEMBARGO_EOF): disabled,
#     automatic reports off, no active ReportURI
#   - vendor-directory remains enabled and byte-for-byte RPM-pristine: its
#     MetadataURI is the Fedora-owned local file:/// source, not a network remote
#   - /etc/fwupd/fwupd.conf (FWUPDCONF_EOF): P2pPolicy=nothing,
#     DisabledPlugins=redfish;android_boot, OnlyTrusted=true, UpdateMotd=false (AIDE
#     noise — /etc/motd.d/fwupd mutations), ShowDevicePrivate=false,
#     IdleTimeout=300, IdleInhibitStartupThreshold=0 (bounded on-demand daemon)
#   - masks: passim.service + fwupd-refresh.timer + fwupd-refresh.service
#   - user doc 24-firmware-updates.md (DOC_EOF): privacy settings, HSI,
#     update procedure, proxy, troubleshooting
#   - STEP 5b: retire the legacy keep-warm drop-in/boot enablement; retain
#     upstream's static D-Bus on-demand service
#   - fwupd >= 2.1.7 required: OnlyTrusted then gates both firmware payload and
#     metadata trust, and D-Bus clients cannot request a forced install
#   - exact stale /var/lib/fwupd/remotes.d overrides removed for all four
#     retained remotes; any other mutable or /etc remote definition fails closed
#   - /var/lib/fwupd remains root-only 0700 before and after daemon activation;
#     a native systemd StateDirectoryMode drop-in prevents the vendor unit's
#     implicit 0755 default from exposing firmware and HSI history metadata
#   - STEP 6: exact content/metadata/lifecycle verification (abort on any fail)
#
# Deliberate deviations (do NOT re-litigate):
#   - LVFS stable stays ENABLED: firmware updates patch UEFI/ME/SSD CVEs;
#     only automatic reporting and the configured success-report endpoint are
#     stripped. Explicit upload commands remain explicit user actions.
#   - fwupd-refresh timer AND service are BOTH masked: the timer fires
#     hourly HTTPS fetches to the LVFS CDN before any VPN exists (SNI +
#     timing fingerprint to the ISP). Re-enable requires unmasking BOTH —
#     timer alone silently fails (it triggers the masked service). The
#     deployed doc carries the exact re-enable command.
#   - passim is masked IN ADDITION to P2pPolicy=nothing as a prophylactic
#     Silent Machine boundary if the optional service is installed later.
#     Historical fwupd#8254 did activate passim despite the policy, but
#     upstream fixed that bug in PR #8286 on 2025-01-08.
#   - fwupd.conf mode is 0640 (the fwupd-2.x RPM default) — a chmod 644
#     gets reset by RPM config-noreplace post-trans and only produces a
#     transient rpm -V mode flag.
#   - Fedora packages /var/lib/fwupd as 0700, but fwupd.service declares
#     StateDirectory=fwupd without a StateDirectoryMode. systemd's maintained
#     default is 0755 and adjusts an existing directory to that mode at service
#     start. M24 sets only StateDirectoryMode=0700 and leaves the vendor-owned
#     StateDirectory path/lifecycle intact.
#   - fwupd.service stays upstream-static and D-Bus-activated: no firmware
#     daemon runs merely because the machine booted. IdleTimeout=300 retains
#     fwupd's maintained default, and IdleInhibitStartupThreshold=0 prevents a
#     slow hardware probe alone from turning the daemon lifetime unlimited.
#     Hardware plugins such as Thunderbolt may intentionally inhibit automatic
#     idle shutdown; M25 therefore asks the daemon to quit after its synchronous
#     user-started firmware workflow. Upstream defines that request to wait for
#     any firmware update in progress. No plugin is disabled for dormancy.
#
# Constraint notes (keep when editing):
#   - fwupd 2.1.7 is the minimum accepted daemon. Fedora 44 publishes it through
#     the normal signed package lifecycle; M24 never substitutes an upstream
#     binary or enables updates-testing. A compose before it reaches the build's
#     enabled repositories fails rather than overstating OnlyTrusted.
#   - fwupd 2.x merged the plugin sub-packages into the main RPM; fwupd-efi
#     is still Recommends-only → the explicit %packages add is load-bearing
#     (--exclude-weakdeps would drop it → UEFI capsule updates fail with
#     "fwupdx64.efi.signed cannot be found").
#   - tests/24 pins the conf keys (P2pPolicy=nothing, UpdateMotd=false) —
#     they live inside the deployed heredocs.
#   - Verify 6.5 requires the proactive passim.service mask even when the
#     optional package is not currently installed.
#
# Cross-reference:
#   - M01: fwupd + efibootmgr packages. M08: fwupd.service sandbox drop-in +
#     live-skip. This module owns the UpdateMotd/AIDE-noise rationale. M15: MEI/BootGuard for
#     HSI. M25: fwupdmgr refresh/update path with user confirm.
# ============================================================================

# ---------------------------------------------------------------------------
# %packages — explicit fwupd-efi
# ---------------------------------------------------------------------------
# fwupd Recommends fwupd-efi (fwupd 2.x merged the plugin sub-packages into
# the main RPM; the UEFI capsule plugin is built-in) — with the master.ks
# --exclude-weakdeps the explicit listing is load-bearing: without fwupd-efi,
# /usr/libexec/fwupd/efi/fwupdx64.efi.signed is missing and UEFI capsule
# firmware updates fail.
%packages --exclude-weakdeps
fwupd-efi
%end

# ---------------------------------------------------------------------------
# %post — Module 24 fwupd automatic-report lockdown + documentation
# ---------------------------------------------------------------------------
%post --erroronfail --log=/var/log/ks-24-firmware-fwupd.log
set -euo pipefail

log() { echo "[noid-24-fwupd] $*"; }
log "=== Module 24 post-install: fwupd hardening ==="

# fwupd 2.1.6 checked only the firmware-payload trust flag when
# OnlyTrusted=true and still accepted the D-Bus force-install flag. Upstream
# 2.1.7 makes trusted metadata load-bearing too and removes that force flag
# from the D-Bus allowlist. Refuse an older compose payload; use the signed
# Fedora package lifecycle rather than replacing it with an upstream binary.
FWUPD_MIN_VERSION=2.1.7
if ! FWUPD_VERSION=$(rpm -q --qf '%{VERSION}' fwupd 2>/dev/null); then
    log "  [FAIL] fwupd package is missing"
    exit 1
fi
if ! FWUPD_VERSION_CANDIDATE="$FWUPD_VERSION" \
    FWUPD_MIN_VERSION_CANDIDATE="$FWUPD_MIN_VERSION" rpm --eval \
    '%{lua:if rpm.vercmp(os.getenv("FWUPD_VERSION_CANDIDATE"), os.getenv("FWUPD_MIN_VERSION_CANDIDATE")) < 0 then error("below minimum") end}' \
    >/dev/null 2>&1; then
    log "  [FAIL] fwupd ${FWUPD_VERSION} is below required ${FWUPD_MIN_VERSION}"
    exit 1
fi
log "  [OK] fwupd ${FWUPD_VERSION} satisfies trust floor ${FWUPD_MIN_VERSION}"

verify_safe_root_dir() {
    local path="$1" metadata uid gid mode
    [ -d "$path" ] && [ ! -L "$path" ] || return 1
    metadata=$(stat -Lc '%u:%g:%a' -- "$path" 2>/dev/null) || return 1
    IFS=: read -r uid gid mode <<< "$metadata"
    [ "$uid:$gid" = "0:0" ] || return 1
    (( (8#$mode & 8#022) == 0 ))
}

# ====================================================================
# STEP 1: LVFS stable remote — explicit no automatic reporting
# ====================================================================
# Fedora default is already AutomaticReports=false, but we set it
# explicitly to survive future default changes. fwupd reads these files
# at startup. In both 2.1.6 and 2.1.7 its search order is mutable /var/lib,
# then /etc, then /usr/share; the first same-ID file wins. Remove the four
# retained IDs from that higher-priority mutable tier before writing /etc.
# Any other mutable definition or unexpected /etc remote fails verification.
#
# We keep LVFS enabled because firmware updates are security-critical
# (e.g., Intel ME patches, SSD firmware, UEFI security fixes).

log "STEP 1: writing /etc/fwupd/remotes.d/lvfs.conf"

for config_dir in /etc/fwupd /etc/fwupd/remotes.d; do
    if ! verify_safe_root_dir "$config_dir"; then
        log "  [FAIL] unsafe fwupd configuration directory: ${config_dir}"
        exit 1
    fi
done
for mutable_dir in /var/lib/fwupd /var/lib/fwupd/remotes.d; do
    if { [ -e "$mutable_dir" ] || [ -L "$mutable_dir" ]; } && \
       ! verify_safe_root_dir "$mutable_dir"; then
        log "  [FAIL] unsafe fwupd mutable directory: ${mutable_dir}"
        exit 1
    fi
done

# Fedora packages this state directory as 0700, but the vendor service's
# StateDirectory=fwupd has no explicit mode and systemd therefore adjusts it
# to the 0755 default on activation. pending.db contains firmware history and
# HSI history; keep that host metadata behind a root-only directory on every
# daemon start. StateDirectoryMode is the native systemd ownership mechanism,
# not a wrapper around fwupd.
install -d -m 0700 -o root -g root -- /var/lib/fwupd
if [ "$(stat -Lc '%u:%g:%a' -- /var/lib/fwupd 2>/dev/null)" != "0:0:700" ]; then
    log "  [FAIL] fwupd state directory is not root-only 0700"
    exit 1
fi
for unit_dir in /etc/systemd/system /etc/systemd/system/fwupd.service.d; do
    if ! verify_safe_root_dir "$unit_dir"; then
        log "  [FAIL] unsafe fwupd systemd directory: ${unit_dir}"
        exit 1
    fi
done
FWUPD_STATE_DROPIN=/etc/systemd/system/fwupd.service.d/97-noid-state-privacy.conf
rm -f -- "$FWUPD_STATE_DROPIN"
cat > "$FWUPD_STATE_DROPIN" <<'FWUPD_STATE_EOF'
# NoID Privacy — keep local firmware and HSI history root-only
[Service]
StateDirectoryMode=0700
FWUPD_STATE_EOF
chmod 644 "$FWUPD_STATE_DROPIN"
chown root:root "$FWUPD_STATE_DROPIN"
log "  [OK] fwupd state directory pinned root-only across daemon activation"

rm -f -- \
    /var/lib/fwupd/remotes.d/lvfs.conf \
    /var/lib/fwupd/remotes.d/lvfs-testing.conf \
    /var/lib/fwupd/remotes.d/lvfs-embargo.conf \
    /var/lib/fwupd/remotes.d/vendor-directory.conf
rm -f -- /etc/fwupd/remotes.d/lvfs.conf
cat > /etc/fwupd/remotes.d/lvfs.conf <<'LVFS_EOF'
[fwupd Remote]
# NoID Privacy — LVFS stable remote (Module 24)
# Firmware updates enabled, automatic report uploads disabled.
Enabled=true
Title=Linux Vendor Firmware Service
MetadataURI=https://cdn.fwupd.org/downloads/firmware.xml.zst
FirmwareBaseURI=https://fwupd.org/downloads

# Privacy: no automatic reporting of firmware versions or HSI scores
AutomaticReports=false
AutomaticSecurityReports=false

# ReportURI intentionally omitted — this remote has no success-report endpoint.
# This is belt+suspenders with AutomaticReports=false; explicitly running a
# different upload-oriented fwupdmgr command remains a separate user action.

# The public stable channel has passed the vendor/LVFS release workflow; NoID Privacy
# does not require an additional local per-checksum allowlist.
ApprovalRequired=false
LVFS_EOF

chmod 644 /etc/fwupd/remotes.d/lvfs.conf
chown root:root /etc/fwupd/remotes.d/lvfs.conf
log "  [OK] lvfs.conf written (automatic reports off)"

# ====================================================================
# STEP 2: LVFS testing remote — explicitly disabled
# ====================================================================
log "STEP 2: writing /etc/fwupd/remotes.d/lvfs-testing.conf"

rm -f -- /etc/fwupd/remotes.d/lvfs-testing.conf
cat > /etc/fwupd/remotes.d/lvfs-testing.conf <<'LVFSTEST_EOF'
[fwupd Remote]
# NoID Privacy — LVFS testing remote (Module 24)
# Explicitly disabled. This public pre-release channel is not a NoID Privacy default.
Enabled=false
Title=Linux Vendor Firmware Service (testing)
MetadataURI=https://cdn.fwupd.org/downloads/firmware-testing.xml.zst
FirmwareBaseURI=https://fwupd.org/downloads
AutomaticReports=false
AutomaticSecurityReports=false
ApprovalRequired=false
LVFSTEST_EOF

chmod 644 /etc/fwupd/remotes.d/lvfs-testing.conf
chown root:root /etc/fwupd/remotes.d/lvfs-testing.conf
log "  [OK] lvfs-testing.conf written (disabled)"

# ====================================================================
# STEP 2b: LVFS embargo remote — explicitly disabled + no reporting
# ====================================================================
# The package remote is disabled today, but an untouched %config(noreplace)
# file can be replaced by a later RPM default. Own the network/privacy
# properties explicitly, as for stable/testing. The vendor-directory remote
# remains vendor-owned because it is an enabled local file:/// source only.
log "STEP 2b: writing /etc/fwupd/remotes.d/lvfs-embargo.conf"

rm -f -- /etc/fwupd/remotes.d/lvfs-embargo.conf
cat > /etc/fwupd/remotes.d/lvfs-embargo.conf <<'LVFSEMBARGO_EOF'
[fwupd Remote]
# NoID Privacy — LVFS embargo remote (Module 24)
# Explicitly disabled. This authenticated vendor pre-release channel is not
# part of the workstation update contract.
Enabled=false
Title=Linux Vendor Firmware Service (embargo)
MetadataURI=https://cdn.fwupd.org/downloads/firmware-embargo.xml.zst
PrivacyURI=https://lvfs.readthedocs.io/en/latest/privacy.html
FirmwareBaseURI=https://fwupd.org/downloads
OrderBefore=lvfs,lvfs-testing
RequiresAuth=true
AutomaticReports=false
AutomaticSecurityReports=false
ApprovalRequired=false

# ReportURI intentionally omitted, so a deliberate later enablement cannot
# silently add automatic firmware or HSI reporting.
# Credentials belong in ~/.config/fwupd/remotes.d/lvfs-embargo.conf.
#Username=
#Password=
LVFSEMBARGO_EOF

chmod 644 /etc/fwupd/remotes.d/lvfs-embargo.conf
chown root:root /etc/fwupd/remotes.d/lvfs-embargo.conf
log "  [OK] lvfs-embargo.conf written (disabled, reporting endpoint absent)"

# ====================================================================
# STEP 3: fwupd.conf — P2P and inapplicable server/Android plugins disabled
# ====================================================================
# passim is a P2P daemon (port 27500) that publishes cached fwupd metadata
# and uses local discovery so LAN peers can fetch it. That visibility and
# traffic conflict with the silent-machine and LAN-isolation posture.
#
# Redfish is a server/BMC firmware management protocol. No desktop use case.
# Disabling it removes unnecessary SMBIOS Type 42 probing + network discovery.
#
# Android Boot flashes in-device Android A/B firmware partitions and opens
# candidate block partitions read/write during discovery. This x86_64
# workstation is not an Android A/B firmware target; Android Studio, ADB and
# the emulator are unrelated and remain available.

log "STEP 3: writing /etc/fwupd/fwupd.conf (P2P off + inapplicable plugins disabled)"

rm -f -- /etc/fwupd/fwupd.conf
cat > /etc/fwupd/fwupd.conf <<'FWUPDCONF_EOF'
# NoID Privacy — fwupd daemon config (Module 24)

[fwupd]
# Disable P2P firmware metadata sharing via passim.
# passim listens on 0.0.0.0:27500 and advertises data to LAN peers.
# With this set, explicit NoID Privacy firmware workflows use the configured remote
# instead of LAN peers.
P2pPolicy=nothing

# Disable Redfish plugin (server/BMC protocol, no desktop use case).
# Prevents unnecessary SMBIOS Type 42 probing at startup.
# Disable Android Boot's write-capable raw-partition discovery on this
# x86_64 workstation; this does not affect Android Studio, ADB or emulators.
# fwupd string-list values use semicolons, not commas.
DisabledPlugins=redfish;android_boot

# Require trusted firmware payload and metadata signatures. The compose-time
# fwupd >= 2.1.7 floor above makes both halves of this statement enforceable.
OnlyTrusted=true

# Do NOT write "firmware updates available" to /etc/motd.d/fwupd on each
# refresh. Fedora default is true, which causes /etc/motd.d mutations during
# each user-started noid-update-all.sh firmware check and creates avoidable
# AIDE drift. The interactive workflow already surfaces updates.
UpdateMotd=false

# Do NOT expose fields marked private (for example device serials) to
# unprivileged D-Bus clients. Keep false explicit so a package-default change
# cannot widen this privacy boundary.
ShowDevicePrivate=false

# Use fwupd's maintained five-minute idle default. Some hardware plugins,
# notably Thunderbolt, can intentionally inhibit automatic idle shutdown;
# the explicit NoID Privacy update workflow asks the daemon to quit after it has
# safely finished any firmware update in progress.
IdleTimeout=300

# Never turn a slow hardware probe alone into an unlimited daemon lifetime.
IdleInhibitStartupThreshold=0
FWUPDCONF_EOF

# 0640 = the fwupd RPM-default mode: a chmod 644 here gets reset by the
# RPM config-noreplace post-trans logic anyway and only produces a transient
# rpm -V mode flag during install.
chmod 640 /etc/fwupd/fwupd.conf
chown root:root /etc/fwupd/fwupd.conf
log "  [OK] fwupd.conf written (P2P=nothing, Redfish/Android Boot disabled, UpdateMotd off, ShowDevicePrivate off, bounded on-demand lifetime, perms 0640 RPM-default)"

# Mask passim.service — belt+suspenders with P2pPolicy=nothing.
# Historical fwupd#8254 allowed an unnecessary D-Bus connection even with
# P2pPolicy=nothing; upstream PR #8286 fixed that on 2025-01-08. Keep the mask
# as a proactive Silent Machine boundary if passim is installed later, not as
# a claim that the fixed fwupd 2.x path still activates it.
if [ -d /etc/systemd/system ]; then
    systemctl mask passim.service
    log "  [OK] passim.service masked"
fi

# Mask fwupd-refresh.timer — ships enabled by default and fires hourly HTTPS
# fetches to the LVFS CDN; on a generic image that leaks "hardened client
# queries LVFS" metadata to the ISP before any VPN exists. Refresh happens
# only via an explicit `fwupdmgr refresh` (user or M25). Re-enable command
# (BOTH units) is in the deployed doc.
if [ -d /etc/systemd/system ]; then
    systemctl mask fwupd-refresh.timer
    log "  [OK] fwupd-refresh.timer masked"
fi

# Mask fwupd-refresh.service too (belt+suspenders): with only the timer
# masked, a manual `systemctl start` or a user-modified different timer
# could still trigger the service.
if [ -d /etc/systemd/system ]; then
    systemctl mask fwupd-refresh.service
    log "  [OK] fwupd-refresh.service masked (belt+suspenders with timer mask)"
fi

# ====================================================================
# STEP 4: User documentation
# ====================================================================
log "STEP 4: writing /usr/share/doc/noid-privacy/24-firmware-updates.md"

if ! verify_safe_root_dir /usr/share/doc; then
    log "  [FAIL] unsafe documentation parent directory: /usr/share/doc"
    exit 1
fi
if [ -e /usr/share/doc/noid-privacy ] || \
   [ -L /usr/share/doc/noid-privacy ]; then
    if ! verify_safe_root_dir /usr/share/doc/noid-privacy; then
        log "  [FAIL] unsafe documentation directory: /usr/share/doc/noid-privacy"
        exit 1
    fi
else
    mkdir /usr/share/doc/noid-privacy
    chmod 755 /usr/share/doc/noid-privacy
    chown root:root /usr/share/doc/noid-privacy
fi

rm -f -- /usr/share/doc/noid-privacy/24-firmware-updates.md
cat > /usr/share/doc/noid-privacy/24-firmware-updates.md <<'DOC_EOF'
# Firmware Updates — NoID Privacy

## Overview

NoID Privacy uses the **fwupd** client/daemon with the Linux Vendor Firmware
Service (LVFS) for firmware updates. Firmware updates are security-critical —
they patch vulnerabilities in UEFI, SSD controllers, Intel ME, network
adapters, and more.

## Privacy Settings

NoID Privacy disables automatic report uploads for all three NoID Privacy-owned LVFS
remotes:

- **AutomaticReports**: OFF — prevents fwupd from sending your firmware
  update results automatically
- **AutomaticSecurityReports**: OFF — prevents fwupd from sending your
  HSI (Host Security ID) assessment automatically
- **ReportURI**: ABSENT — the remotes have no configured success-report
  endpoint

Metadata and firmware downloads still create ordinary HTTPS request metadata
at the CDN or proxy, including timing and the connecting IP address. Commands
whose stated purpose is an explicit upload, such as `fwupdmgr report-devices`,
remain user-triggered capabilities; the supported NoID Privacy update workflow
does not call them.

Additionally:

- **P2P sharing (passim)**: DISABLED — prevents publishing and advertising
  cached firmware metadata to your local network on port 27500
- **Redfish plugin**: DISABLED — server/BMC protocol, no desktop use
- **Android Boot plugin**: DISABLED — this x86_64 workstation is not an
  in-device Android A/B firmware target. This fwupd plugin requires raw
  partition read/write access; it is unrelated to Android Studio, ADB and the
  Android emulator, which remain available.
- **fwupd-refresh.timer**: MASKED — no background HTTPS fetches to LVFS.
  Metadata is refreshed only through an explicit fwupd client action,
  including the user-started `noid-update-all.sh` workflow. This ensures LVFS
  traffic happens only as part of a deliberate firmware workflow.
- **fwupd-refresh.service**: MASKED — belt-and-suspenders alongside the
  timer mask. The timer invokes this service, and masking both also closes
  direct service starts. An explicit `fwupdmgr refresh` remains available.

  To deliberately opt into scheduled refresh, accept its background network
  traffic and unmask BOTH units (timer alone silently fails because its
  service remains masked). If you require VPN-only egress, first ensure the
  routing policy fails closed independently of VPN client state:
  `sudo systemctl unmask fwupd-refresh.timer fwupd-refresh.service && sudo systemctl enable --now fwupd-refresh.timer`
- **fwupd.service**: ON DEMAND — the upstream static D-Bus service is not
  enabled at boot. A fwupd D-Bus client command starts it when needed.
  The daemon uses its maintained five-minute idle timeout. Some hardware
  plugins may intentionally inhibit automatic idle shutdown, so the supported
  NoID Privacy update workflow asks it to quit only after the firmware command
  has completed; fwupd itself defers that request while an update is in
  progress.
- **Package trust floor**: fwupd 2.1.7 or newer is required. Together with
  `OnlyTrusted=true`, this requires trusted metadata as well as a trusted
  firmware payload and rejects a D-Bus request to force an install. NoID Privacy
  follows Fedora's signed package lifecycle and does not replace fwupd with an
  ad-hoc upstream binary.

## Checking for Updates

The user-started NoID Privacy Update workflow (`noid-update-all.sh`) refreshes
metadata, checks for firmware updates, and asks for confirmation before
installing:

```bash
# Manual check:
fwupdmgr refresh --force
fwupdmgr get-updates

# Install available updates:
fwupdmgr update

# Safely request daemon shutdown after any in-progress update finishes:
fwupdmgr quit
```

Run the user-facing client as your desktop user. It downloads and parses
network content without root privileges, while PolicyKit authorizes the
privileged daemon action when required. Do not prefix the network-facing
`refresh` or `update` client with `sudo`.

Connect AC power where available, save your work, follow device-specific
prompts, and never power off or suspend the machine while firmware is being
written. Some updates are staged as UEFI capsules and require a reboot.

## HSI — Host Security ID

fwupd includes a security assessment called HSI (Host Security ID) that
evaluates your hardware's security posture:

```bash
# Check your HSI score:
fwupdmgr security
```

### HSI Levels

| Level | Meaning |
|-------|---------|
| HSI:0 | Insecure or limited detected firmware protection |
| HSI:1 | Critical baseline: essential protections pass |
| HSI:2 | Risky: remaining issues are theoretical, difficult, or impractical to exploit |
| HSI:3 | Protected: only minor issues remain; may include out-of-band recovery |
| HSI:4 | Secure: robust firmware protections |
| HSI:5 | Secure Proven: out-of-band attestation; no tests currently implement this level |

The HSI specification is under active development, and HSI:5 cannot currently
be obtained. Interpret the individual attributes produced by the installed
fwupd version, not just the aggregate label.

The `!` suffix (e.g., HSI:2!) indicates one or more runtime HSI findings,
such as a tainted kernel or a suspend-state concern. It is not automatically
cosmetic: inspect the individual `fwupdmgr security` attributes and decide
whether each finding matters for the machine's threat model.

### What NoID Privacy Achieves

Keeping Intel MEI modules available (Module 15) lets fwupd inspect supported
platform attributes such as BootGuard state, ME version, and manufacturing
mode. Availability varies by hardware and plugin. AMD PSP is a different
firmware architecture; the host `ccp` driver is not an equivalent universal
attestation channel (see `15-amd-psp-hardware-layer.md`).

The achieved HSI **level varies by hardware, firmware, configuration, runtime
state, and fwupd version** and is not fixed. fwupd 2.1.6 moved the previously
combined early-boot UEFI memory result into separate HSI-3 `MemoryProtection`
and `NxCompat` attributes. The minimum-supported 2.1.7 release also adds MTD
lock and TCG disk-encryption security attributes. A scoring-model change or new
attribute can alter the aggregate result without a firmware or shim change; it
does not make other failing attributes cosmetic. Keep the system updated, then
review the individual attributes rather than treating the aggregate number as
a NoID Privacy guarantee.

## LVFS Remotes

| Remote | Status | Purpose |
|--------|--------|---------|
| lvfs (stable) | Enabled | Public production firmware channel |
| lvfs-testing | Disabled | Public opt-in pre-release channel |
| lvfs-embargo | Disabled | Authenticated vendor pre-release channel |
| vendor-directory | Enabled | Local `file:///` metadata shipped by Fedora |

To temporarily enable testing firmware (not recommended):

```bash
fwupdmgr enable-remote lvfs-testing
# ... install firmware ...
fwupdmgr disable-remote lvfs-testing
```

## Network Configuration

NoID Privacy ships the provider-neutral host-L3 WAN-egress backstop in Module
06; the VPN client itself (ProtonVPN, Mullvad, plain WireGuard/OpenVPN, ...) is
set up by you — see the getting-started guide. fwupd receives no special VPN
route: it follows the host's ordinary routing and proxy configuration. If a VPN
installs the default route, LVFS HTTPS normally follows that route; an active
split-tunnel or excluded route can differ, so VPN activity alone is not proof
that a particular fwupd transfer uses the tunnel.

When Module 06 reports `STRICT` or `STRICT_EMPTY`, its kernel nftables hooks
block public-IP fallback through discovered physical interfaces outside the
bounded VPN-handshake allowances. In those modes, fwupd cannot silently fall
back to direct physical-WAN HTTPS while the tunnel is unavailable. The
`GRACE_BOOTSTRAP`, `GRACE_PAUSED`, and `DISABLED` modes deliberately permit
direct WAN and are not fail-closed. With neither a VPN route nor an explicit
proxy, LVFS uses the ordinary direct network route.

### Explicit Proxy (advanced)

fwupdmgr's libcurl download path honors lower-case proxy environment variables.
For a one-shot manual workflow, pass them only to the unprivileged client
commands that transfer data:

```bash
proxy_url='http://proxy.example.com:8080'
env http_proxy="$proxy_url" https_proxy="$proxy_url" \
  /usr/bin/fwupdmgr refresh --force
env http_proxy="$proxy_url" https_proxy="$proxy_url" \
  /usr/bin/fwupdmgr update
```

This does not create a persistent global proxy for unrelated services. Do not
put proxy credentials in command arguments or shell history; use your
administrator's managed secret mechanism if the proxy requires authentication.
The Module 25 wrapper does not invent or persist proxy settings.

### What goes over the network

- **Metadata refresh**: Manual only (`fwupdmgr refresh` or via Module 25
  `noid-update-all.sh`) — no background hourly fetches (timer + service
  both masked, see Privacy Settings above)
- **Firmware downloads**: Triggered by an explicit install/update operation —
  the owned LVFS remotes use `https://fwupd.org/downloads/`
- **Automatic uploads**: Disabled for the owned LVFS remotes
- **Explicit uploads**: Possible only when you deliberately invoke a reporting
  command; the NoID Privacy update workflow does not do so

## Troubleshooting

### fwupdmgr hangs or times out

fwupd downloads metadata via HTTPS. If your VPN blocks LVFS:

```bash
# Makes one direct request using the host's current routing/proxy policy:
curl --fail --show-error --silent --head --max-time 20 \
  https://cdn.fwupd.org/downloads/firmware.xml.zst
```

### No devices found

Some devices require specific kernel modules. Check:

```bash
fwupdmgr --show-all get-devices
```

### UEFI capsule update failed

Ensure `/boot/efi` is mounted and writable:

```bash
findmnt --mountpoint /boot/efi --output SOURCE,FSTYPE,OPTIONS --noheadings
# Expected: one vfat mount with rw among its options.
```
DOC_EOF

chmod 644 /usr/share/doc/noid-privacy/24-firmware-updates.md
chown root:root /usr/share/doc/noid-privacy/24-firmware-updates.md
log "  [OK] documentation written"

# ====================================================================
# STEP 5: SELinux context restore
# ====================================================================
log "STEP 5: SELinux context restore"
if ! command -v restorecon >/dev/null 2>&1; then
    log "  [FAIL] restorecon is unavailable"
    exit 1
fi
FWUPD_RELABEL_PATHS=(
    /etc/fwupd/fwupd.conf
    /etc/fwupd/remotes.d/lvfs.conf
    /etc/fwupd/remotes.d/lvfs-testing.conf
    /etc/fwupd/remotes.d/lvfs-embargo.conf
    /etc/systemd/system/fwupd.service.d/97-noid-state-privacy.conf
    /var/lib/fwupd
    /usr/share/doc/noid-privacy/24-firmware-updates.md
)
if ! restorecon -F "${FWUPD_RELABEL_PATHS[@]}"; then
    log "  [FAIL] restorecon failed for fwupd configuration/documentation"
    exit 1
fi
log "  [OK] restorecon complete"

# ====================================================================
# STEP 5b: restore upstream-static, on-demand fwupd lifecycle
# ====================================================================
# `systemctl disable` is the native inverse of the retired NoID Privacy [Install]
# extension. Run it before removing that extension so an upgrade from an older
# image removes the exact generated WantedBy link. The vendor unit then returns
# to its maintained [Install]-less `static` state and remains D-Bus activatable.
log "STEP 5b: disabling legacy fwupd boot start"
systemctl disable fwupd.service
rm -f -- /etc/systemd/system/fwupd.service.d/99-noid-keep-warm.conf
systemctl daemon-reload
log "  [OK] fwupd.service restored to static on-demand activation"

# ====================================================================
# STEP 6: Verification
# ====================================================================
log "STEP 6: verification"

verify_ok=0
verify_fail=0

verify_owned_regular() {
    local path="$1" expected_mode="$2"
    [ -f "$path" ] && [ ! -L "$path" ] && \
        [ "$(stat -Lc '%u:%g:%a:%h' -- "$path" 2>/dev/null)" = \
            "0:0:${expected_mode}:1" ]
}

verify_rpm_regular() {
    local path="$1" package="$2" expected_mode="$3"
    local record dump_path dump_size dump_mtime dump_sha dump_mode
    local dump_owner dump_group dump_config dump_doc dump_rdev dump_symlink dump_extra

    verify_owned_regular "$path" "$expected_mode" || return 1
    [ "$(rpm -qf --qf '%{NAME}\n' "$path" 2>/dev/null)" = "$package" ] || return 1
    record=$(
        rpm -q --dump "$package" 2>/dev/null |
            awk -v wanted="$path" \
                '$1 == wanted { print; found=1 } END { exit !found }'
    ) || return 1
    read -r dump_path dump_size dump_mtime dump_sha dump_mode \
        dump_owner dump_group dump_config dump_doc dump_rdev dump_symlink \
        dump_extra <<< "$record"
    [ "$dump_path" = "$path" ] &&
        [ "$dump_mode" = "0100${expected_mode}" ] &&
        # rpm --dump column 11 is the symlink target (X for regular files),
        # not a file-capability field.
        [ "${dump_config}:${dump_doc}:${dump_rdev}:${dump_symlink}" = "1:0:0:X" ] &&
        [ -z "${dump_extra:-}" ] &&
        [ "$(stat -Lc '%s:%Y:%U:%G:%a' -- "$path" 2>/dev/null)" = \
            "${dump_size}:${dump_mtime}:${dump_owner}:${dump_group}:${expected_mode}" ] &&
        [ "$(sha256sum "$path" | awk '{ print $1 }')" = "$dump_sha" ]
}

# 6.1 — LVFS stable exists as the exact owned file with automatic reports off
if verify_owned_regular /etc/fwupd/remotes.d/lvfs.conf 644; then
    if grep -qFx '[fwupd Remote]' /etc/fwupd/remotes.d/lvfs.conf && \
       grep -qFx 'AutomaticReports=false' \
            /etc/fwupd/remotes.d/lvfs.conf && \
       grep -qFx 'AutomaticSecurityReports=false' \
            /etc/fwupd/remotes.d/lvfs.conf; then
        verify_ok=$((verify_ok + 1))
        log "  [OK] lvfs.conf: exact metadata + automatic reports off"
    else
        verify_fail=$((verify_fail + 1))
        log "  [FAIL] lvfs.conf: remote section/report settings incorrect"
    fi
    if grep -qFx 'Enabled=true' /etc/fwupd/remotes.d/lvfs.conf; then
        verify_ok=$((verify_ok + 1))
        log "  [OK] lvfs.conf: LVFS enabled"
    else
        verify_fail=$((verify_fail + 1))
        log "  [FAIL] lvfs.conf: LVFS not enabled"
    fi
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] lvfs.conf missing or not root:root 0644 regular single-link"
fi

# 6.2 — LVFS testing disabled with both automatic-report paths off
if verify_owned_regular /etc/fwupd/remotes.d/lvfs-testing.conf 644; then
    if grep -qFx '[fwupd Remote]' \
            /etc/fwupd/remotes.d/lvfs-testing.conf && \
       grep -qFx 'Enabled=false' \
            /etc/fwupd/remotes.d/lvfs-testing.conf && \
       grep -qFx 'AutomaticReports=false' \
            /etc/fwupd/remotes.d/lvfs-testing.conf && \
       grep -qFx 'AutomaticSecurityReports=false' \
            /etc/fwupd/remotes.d/lvfs-testing.conf; then
        verify_ok=$((verify_ok + 1))
        log "  [OK] lvfs-testing.conf: disabled + automatic reports off"
    else
        verify_fail=$((verify_fail + 1))
        log "  [FAIL] lvfs-testing.conf: enabled or report settings incomplete"
    fi
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] lvfs-testing.conf missing or metadata incorrect"
fi

# 6.2b — LVFS embargo disabled with both automatic-report paths off and no endpoint
if verify_owned_regular /etc/fwupd/remotes.d/lvfs-embargo.conf 644 && \
   grep -qFx '[fwupd Remote]' /etc/fwupd/remotes.d/lvfs-embargo.conf && \
   grep -qFx 'Enabled=false' /etc/fwupd/remotes.d/lvfs-embargo.conf && \
   grep -qFx 'AutomaticReports=false' /etc/fwupd/remotes.d/lvfs-embargo.conf && \
   grep -qFx 'AutomaticSecurityReports=false' \
        /etc/fwupd/remotes.d/lvfs-embargo.conf && \
   ! grep -Eq '^[[:space:]]*ReportURI[[:space:]]*=' \
        /etc/fwupd/remotes.d/lvfs-embargo.conf; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] lvfs-embargo.conf: exact metadata + disabled reporting"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] lvfs-embargo.conf: metadata/privacy boundary incomplete"
fi

# 6.2c — vendor-directory is the exact Fedora-owned local directory remote
VENDOR_REMOTE=/etc/fwupd/remotes.d/vendor-directory.conf
if verify_rpm_regular "$VENDOR_REMOTE" fwupd 644 && \
   grep -qFx '[fwupd Remote]' "$VENDOR_REMOTE" && \
   grep -qFx 'Enabled=true' "$VENDOR_REMOTE" && \
   grep -qFx \
       'MetadataURI=file:///usr/share/fwupd/remotes.d/vendor/firmware' \
       "$VENDOR_REMOTE" && \
   ! grep -Eq '^[[:space:]]*ReportURI[[:space:]]*=' "$VENDOR_REMOTE"; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] vendor-directory: RPM-pristine enabled local file source"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] vendor-directory: package bytes or local-only contract differs"
fi

# 6.2d — the higher-priority mutable tier must contain no remote definitions
mutable_remote=
if [ -d /var/lib/fwupd/remotes.d ]; then
    mutable_remote=$(
        find -P /var/lib/fwupd/remotes.d -mindepth 1 -maxdepth 1 \
            -name '*.conf' -print -quit
    )
fi
if [ -z "$mutable_remote" ]; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] no higher-priority mutable remote definitions"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] unexpected mutable remote definition: ${mutable_remote}"
fi

# 6.2e — fail closed if Fedora adds or the image inherits another remote
EXPECTED_REMOTE_FILES=$(
    printf '%s\n' lvfs-embargo.conf lvfs-testing.conf lvfs.conf \
        vendor-directory.conf |
        LC_ALL=C sort
)
ACTUAL_REMOTE_FILES=$(
    find -P /etc/fwupd/remotes.d -mindepth 1 -maxdepth 1 \
        -name '*.conf' -printf '%f\n' |
        LC_ALL=C sort
)
if [ "$ACTUAL_REMOTE_FILES" = "$EXPECTED_REMOTE_FILES" ]; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] effective remote source-file inventory is closed"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] effective remote source-file inventory differs"
fi

# 6.3 — Documentation exists with exact metadata
if verify_owned_regular /usr/share/doc/noid-privacy/24-firmware-updates.md 644; then
    doc_size=$(stat -c %s /usr/share/doc/noid-privacy/24-firmware-updates.md 2>/dev/null || echo 0)
    doc_size=${doc_size:-0}
    if [ "$doc_size" -gt 1024 ]; then
        verify_ok=$((verify_ok + 1))
        log "  [OK] documentation ${doc_size} bytes"
    else
        verify_fail=$((verify_fail + 1))
        log "  [FAIL] documentation too small (${doc_size} bytes)"
    fi
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] documentation missing or metadata incorrect"
fi

# 6.4 — fwupd.conf exists with all hardening keys
if verify_owned_regular /etc/fwupd/fwupd.conf 640; then
    if grep -qFx '[fwupd]' /etc/fwupd/fwupd.conf && \
       grep -qFx 'P2pPolicy=nothing' /etc/fwupd/fwupd.conf && \
       grep -qFx 'DisabledPlugins=redfish;android_boot' \
            /etc/fwupd/fwupd.conf && \
       grep -qFx 'OnlyTrusted=true' /etc/fwupd/fwupd.conf && \
       grep -qFx 'UpdateMotd=false' /etc/fwupd/fwupd.conf && \
       grep -qFx 'ShowDevicePrivate=false' /etc/fwupd/fwupd.conf && \
       grep -qFx 'IdleTimeout=300' /etc/fwupd/fwupd.conf && \
       grep -qFx 'IdleInhibitStartupThreshold=0' \
            /etc/fwupd/fwupd.conf; then
        verify_ok=$((verify_ok + 1))
        log "  [OK] fwupd.conf: exact metadata + complete hardening policy"
    else
        verify_fail=$((verify_fail + 1))
        log "  [FAIL] fwupd.conf: hardening/lifecycle key missing"
    fi
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] fwupd.conf missing or not root:root 0640 regular single-link"
fi

# 6.4b — firmware/HSI history remains private after every systemd activation
if verify_owned_regular "$FWUPD_STATE_DROPIN" 644 && \
   [ "$(grep -cxF '[Service]' "$FWUPD_STATE_DROPIN" 2>/dev/null)" = 1 ] && \
   [ "$(grep -cxF 'StateDirectoryMode=0700' "$FWUPD_STATE_DROPIN" 2>/dev/null)" = 1 ] && \
   [ "$(stat -Lc '%u:%g:%a' -- /var/lib/fwupd 2>/dev/null)" = "0:0:700" ]; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] fwupd firmware/HSI state remains root-only 0700"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] fwupd firmware/HSI state privacy boundary is incomplete"
fi

# 6.5 — passim.service must retain the proactive mask whether or not the
# optional package is currently installed.
if [ -L /etc/systemd/system/passim.service ] && \
   [ "$(readlink /etc/systemd/system/passim.service 2>/dev/null || true)" = "/dev/null" ]; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] passim.service proactively masked"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] proactive passim.service mask missing or incorrect"
fi

# 6.5b — fwupd-refresh.timer must be masked (privacy — no background LVFS fetch)
if [ -L /etc/systemd/system/fwupd-refresh.timer ]; then
    refresh_target=$(readlink /etc/systemd/system/fwupd-refresh.timer 2>/dev/null || true)
    if [ "$refresh_target" = "/dev/null" ]; then
        verify_ok=$((verify_ok + 1))
        log "  [OK] fwupd-refresh.timer masked"
    else
        verify_fail=$((verify_fail + 1))
        log "  [FAIL] fwupd-refresh.timer mask target is incorrect"
    fi
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] fwupd-refresh.timer mask symlink missing"
fi

# 6.5c — fwupd-refresh.service must be masked (belt+suspenders with timer mask)
if [ -L /etc/systemd/system/fwupd-refresh.service ]; then
    refresh_svc_target=$(readlink /etc/systemd/system/fwupd-refresh.service 2>/dev/null || true)
    if [ "$refresh_svc_target" = "/dev/null" ]; then
        verify_ok=$((verify_ok + 1))
        log "  [OK] fwupd-refresh.service masked"
    else
        verify_fail=$((verify_fail + 1))
        log "  [FAIL] fwupd-refresh.service mask target is incorrect"
    fi
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] fwupd-refresh.service mask symlink missing"
fi

# 6.6 — no owned network remote may have a reporting endpoint
report_uri_present=0
for remote_name in lvfs lvfs-testing lvfs-embargo; do
    if grep -Eq '^[[:space:]]*ReportURI[[:space:]]*=' \
        "/etc/fwupd/remotes.d/${remote_name}.conf" 2>/dev/null; then
        report_uri_present=1
    fi
done
if [ "$report_uri_present" -ne 0 ]; then
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] an owned LVFS remote has a ReportURI"
else
    verify_ok=$((verify_ok + 1))
    log "  [OK] owned LVFS remotes have no ReportURI"
fi

# 6.7 — Cross-check: fwupd package installed (Module 01 responsibility)
if rpm -q fwupd >/dev/null 2>&1; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] fwupd package installed"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] fwupd package missing (Module 01 dependency)"
fi

# 6.7b — M24's explicit weak dependency and its UEFI capsule payload
FWUPD_EFI_PAYLOAD=/usr/libexec/fwupd/efi/fwupdx64.efi.signed
if rpm -q fwupd-efi >/dev/null 2>&1 && \
   verify_owned_regular "$FWUPD_EFI_PAYLOAD" 600 && \
   [ -s "$FWUPD_EFI_PAYLOAD" ] && \
   [ "$(rpm -qf --qf '%{NAME}' "$FWUPD_EFI_PAYLOAD" 2>/dev/null)" = \
        fwupd-efi ]; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] fwupd-efi package + exact owned UEFI capsule payload present"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] fwupd-efi package/payload ownership or metadata incorrect"
fi

# 6.8 — maintained idle timeout plus no unlimited slow-start inhibition
if grep -q '^IdleTimeout=300$' /etc/fwupd/fwupd.conf 2>/dev/null && \
   grep -q '^IdleInhibitStartupThreshold=0$' \
        /etc/fwupd/fwupd.conf 2>/dev/null; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] fwupd.conf: bounded on-demand idle policy"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] fwupd.conf: bounded on-demand idle policy missing"
fi

# 6.9 — retired NoID Privacy keep-warm extension is absent
if [ ! -e /etc/systemd/system/fwupd.service.d/99-noid-keep-warm.conf ] && \
   [ ! -L /etc/systemd/system/fwupd.service.d/99-noid-keep-warm.conf ]; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] legacy fwupd keep-warm drop-in absent"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] legacy fwupd keep-warm drop-in remains"
fi

# 6.10 — vendor service is static and has no multi-user boot link
fwupd_enable_state=$(systemctl is-enabled fwupd.service 2>/dev/null || true)
if [ "$fwupd_enable_state" = static ] && \
   [ ! -e /etc/systemd/system/multi-user.target.wants/fwupd.service ] && \
   [ ! -L /etc/systemd/system/multi-user.target.wants/fwupd.service ]; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] fwupd.service static and absent from the boot target"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] fwupd.service is not purely static/on-demand (state=$fwupd_enable_state)"
fi

log "  Verification: ${verify_ok} OK, ${verify_fail} FAIL"

# Abort the build on any verify failure (silent regression here could ship
# automatic reporting or an ineffective configuration).
if [ "$verify_fail" -gt 0 ]; then
    log "=== Module 24 FAILED (${verify_fail} verification failures) ==="
    exit 1
fi

log "=== Module 24 complete ==="
%end

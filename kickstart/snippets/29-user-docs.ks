# ============================================================================
# Module 29 — User Documentation (Tier A: README + Getting Started + VPN)
# Status: LOCKED 2026-08-22 (v62) — name the v1.7 physical IPv6 support boundary.
#
# Scope: ship 4 user-facing docs forming the onboarding path:
#   - 00-README.md                   master index + task-based navigation
#   - 01-getting-started.md          first-day checklist (CRITICAL ->
#                                    IMPORTANT -> RECOMMENDED triage)
#   - 06-vpn-setup.md                ProtonVPN / Mullvad / generic WireGuard /
#                                    OpenVPN import + killswitch verification
#   - gnome-extensions-autostart.md  pre-installed extensions + autostart
#                                    best-practice
#
# Doc-accuracy constraints (verified; keep on future edits):
#   - noid-update-all.sh is documented WITHOUT sudo (the script root-guards
#     and refuses sudo invocation). M25 owns its side-effect-free `--help` and
#     strict no-operational-options contract.
#   - wireguard-tools IS an M26 baseline package (M06 still installs no
#     packages of its own). Docs keep the rpm -q || dnf install line purely as
#     a recovery path for a host where it was removed — never as a claim that
#     the image ships without it.
#   - NetworkManager-openvpn + its GNOME authentication dialog ARE explicit
#     M26 baseline packages: provider-neutral OpenVPN import works without a
#     preliminary install, while no provider/profile/credential is configured.
#   - block-lan-out has NO gateway exception (DHCP works via NM's raw L2
#     socket); WAN-egress-strict is the `noid_wan_strict` nftables table,
#     NOT a firewalld zone; LAN exceptions go via `noid-lan-allow`.
#   - TunnelVision mitigation = IPv6 ignore-auto-routes + IPv4 DHCP-route
#     cleanup; IPv4 ignore-auto-routes stays OFF by design (enabling it
#     dropped the pre-VPN default route).
#   - THREE opt-in sudo wrapper scripts; noid-complete-setup.sh installs
#     ffmpeg + GPU HW-decode swap ONLY (RAR/7z extraction is covered by
#     pre-installed unar + 7zip).
#   - IPsec/IKEv2/L2TP are documented as not supported (M21 blacklists
#     those module families).
#   - 00-README "Architecture in 30 seconds" carries the functional-section
#     count (= master.ks %includes minus 99-finalize) — treadmill:
#     sync that README number in the SAME commit whenever the master.ks
#     %include count changes.
# Shipped Markdown target: /usr/share/doc/noid-privacy/00-README.md
# Shipped Markdown heredoc: README_EOF
# Shipped Markdown target: /usr/share/doc/noid-privacy/01-getting-started.md
# Shipped Markdown heredoc: GETSTART_EOF
# Shipped Markdown target: /usr/share/doc/noid-privacy/06-vpn-setup.md
# Shipped Markdown heredoc: VPN_EOF
# Shipped Markdown target: /usr/share/doc/noid-privacy/gnome-extensions-autostart.md
# Shipped Markdown heredoc: GNOME_EXT_EOF
#
# Verify-block doctrine (Lesson #30): doc keyword checks use case-
# insensitive grep -qi DIRECTLY on the deployed file — never via an
# echo-bash-variable pipeline. Both failure classes (strict-case grep and
# the variable pipeline) produced false FAILs that occur ONLY inside the
# Anaconda %post bash environment.
#
# Cross-references: every doc linked from the Tier-A docs MUST be shipped by
# an owning module — before adding a link, verify a literal writer or
# `# Shipped Markdown target:` declaration exists under kickstart/. Philosophy:
# task-based navigation
# (00-README), priority triage (01-getting-started), the VPN doc fills the
# provider-neutral-image gap.
#
# Dependencies: none at build. Runtime: yelp + xdg-open + zenity (M26).
# Package modifications: NONE. Doc-only module.
# ============================================================================

%packages --exclude-weakdeps
# No packages. Documentation-only module.
%end

%post --log=/var/log/ks-29-user-docs.log --erroronfail
set -euo pipefail

PHASE=""
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [M29] ${PHASE}: $*"; }
die() { log "FAIL: $*"; exit 1; }
DOC_TMP=""
STAMP_TMP=""
STAMP_PUBLICATION_ACTIVE=0
STAMP_DIR=/var/lib/noid-privacy
STAMP="$STAMP_DIR/stamp-29-user-docs.ok"
cleanup() {
    if [ -n "${DOC_TMP:-}" ]; then
        rm -f -- "$DOC_TMP" || true
    fi
    if [ -n "${STAMP_TMP:-}" ]; then
        rm -f -- "$STAMP_TMP" || true
    fi
    if [ "${STAMP_PUBLICATION_ACTIVE:-0}" -eq 1 ]; then
        if ! rm -f -- "$STAMP"; then
            log "FAIL: could not retire incomplete Module 29 health stamp"
        fi
        sync -- "$STAMP_DIR" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

publish_doc() {
    local target=$1
    [ -n "$DOC_TMP" ] || die "internal error: no document temporary file"
    chmod 0644 "$DOC_TMP"
    chown root:root "$DOC_TMP"
    sync -- "$DOC_TMP" \
        || die "cannot sync staged user documentation: $target"
    mv -fT "$DOC_TMP" "$target"
    DOC_TMP=""
    restorecon -F "$target" \
        || die "restorecon failed for user documentation: $target"
    matchpathcon -V "$target" >/dev/null \
        || die "SELinux context differs for user documentation: $target"
    sync -- "$target" "$DOC_DIR" \
        || die "cannot sync published user documentation: $target"
}

log "=== Module 29 User Documentation start ==="
command -v restorecon >/dev/null 2>&1 \
    || die "restorecon is required for fail-closed SELinux labeling"
command -v matchpathcon >/dev/null 2>&1 \
    || die "matchpathcon is required for fail-closed SELinux verification"

# M29_HEALTH_INVALIDATION_BEGIN
# The stamp describes one complete four-document publication. Validate the
# shared state boundary without normalizing drift, then retire any earlier
# success before the first owned documentation mutation.
PHASE="P0-health-invalidation"
if { [ -e "$STAMP_DIR" ] || [ -L "$STAMP_DIR" ]; } \
   && { [ ! -d "$STAMP_DIR" ] || [ -L "$STAMP_DIR" ]; }; then
    die "$STAMP_DIR exists but is not a real directory"
fi
if [ ! -e "$STAMP_DIR" ]; then
    install -d -m 0755 -o root -g root "$STAMP_DIR"
fi
if [ "$(stat -Lc '%u:%g:%a' -- "$STAMP_DIR" 2>/dev/null || true)" != \
        0:0:755 ]; then
    die "$STAMP_DIR metadata is not root:root 0755"
fi
if ! restorecon -F -- "$STAMP_DIR" \
   || ! matchpathcon -V "$STAMP_DIR" >/dev/null; then
    die "$STAMP_DIR SELinux context is not canonical"
fi
if [ -e "$STAMP" ] || [ -L "$STAMP" ]; then
    if [ ! -f "$STAMP" ] && [ ! -L "$STAMP" ]; then
        die "health-stamp target is not a file or symlink: $STAMP"
    fi
    rm -f -- "$STAMP" \
        || die "cannot invalidate stale Module 29 health stamp"
    sync -- "$STAMP_DIR"
fi
log "  [OK] prior Module 29 health stamp is absent"
# M29_HEALTH_INVALIDATION_END

# ------------------------------------------------------------------------------
# Phase 1 — Ensure doc directory
# ------------------------------------------------------------------------------
PHASE="P1-setup"
DOC_DIR=/usr/share/doc/noid-privacy
log "Preparing $DOC_DIR"
if { [ -e "$DOC_DIR" ] || [ -L "$DOC_DIR" ]; } \
   && { [ ! -d "$DOC_DIR" ] || [ -L "$DOC_DIR" ]; }; then
    die "$DOC_DIR exists but is not a real directory"
fi
install -d -m 0755 -o root -g root "$DOC_DIR"
[ "$(stat -c '%u:%g:%a' "$DOC_DIR")" = "0:0:755" ] \
    || die "$DOC_DIR metadata is not root:root 0755"
restorecon -F "$DOC_DIR" \
    || die "restorecon failed for documentation directory"
matchpathcon -V "$DOC_DIR" >/dev/null \
    || die "$DOC_DIR SELinux context differs"

# ------------------------------------------------------------------------------
# Phase 2 — Write 00-README.md (master index)
# ------------------------------------------------------------------------------
PHASE="P2-readme"
log "Writing 00-README.md"

README_DOC="$DOC_DIR/00-README.md"
DOC_TMP=$(mktemp "$DOC_DIR/.00-README.md.XXXXXXXX")
cat > "$DOC_TMP" <<'README_EOF'
# NoID Privacy Workstation — Documentation Index

Welcome. This directory contains all documentation for the hardening
layers shipped with this image. If you are new to NoID Privacy, start
with the three links under **New here? Start here** below.

> **Quick commands**
> - `noid-status` — one-screen diagnostic overview of all hardening
> - `noid-help` — list + open user-doc topics (this directory)
> - `noid-help search <keyword>` — grep across all docs
> - `noid-welcome.sh --again` — re-run the first-boot welcome dialog
> - `less /usr/share/doc/noid-privacy/<file>.md` — read any doc in-terminal
> - `xdg-open /usr/share/doc/noid-privacy/<file>.md` — open in GUI editor

## New here? Start here

1. **[01-getting-started.md](01-getting-started.md)** — first-day
   checklist. Do this FIRST (15-30 min).
2. **[06-vpn-setup.md](06-vpn-setup.md)** — import your VPN config.
   The image ships provider-neutral; you plug in your own.
3. **[22-disk-encryption.md](22-disk-encryption.md)** — LUKS header
   backup + recovery strategy. Do this WITHIN 24 HOURS.

## Task-based reference

"I want to …" → read this:

| Task | Document | Section |
|------|----------|---------|
| Back up my LUKS header | 22-disk-encryption.md | Backup Strategy |
| Import a WireGuard VPN config | 06-vpn-setup.md | Option 1-3 |
| Configure the AIDE baseline, schedule and notifications | notifications.md | whole file |
| Inspect, allow or revoke a USB device | 14-usbguard.md | Device overview and management |
| Switch to NVIDIA proprietary driver | 19-nvidia-drivers.md | Installation |
| Diagnose a GTK4 hybrid-GPU launch stall | 19-nvidia-drivers.md | GTK4 launch stall |
| Enroll a MOK key for Secure Boot | 19-secure-boot-mok.md | Enrollment |
| Install optional packages (printing, Bluetooth, etc.) | 26-optional-packages.md | Install Commands |
| Select or measure a performance/power profile | 27-performance.md | whole file |
| Understand the product threat model and limits | threat-model.md | whole file |
| Review repository/component licensing | licensing.md | whole file |
| Roll back after a bad update | 20-rollback-recovery.md | Recovery Paths |
| Re-enable a masked service | 08-masked-services.md | whole file |
| Install a local AI coding assistant | 28-local-ai.md | full guide |
| Understand cloud-agent privacy and policy | ai-workspace.md | full guide |
| Update my system safely | 01-getting-started.md | Prefer the guided update process |
| Tighten Firefox fingerprint protection | 16-firefox-hardening.md | Fingerprint |
| Allow a single LAN device through the isolation firewall | 05-lan-isolation.md | whole file |
| Manage GNOME extensions + autostart applications | gnome-extensions-autostart.md | whole file |

## All documentation by category

### Getting started
- [00-README.md](00-README.md) — this file
- [00-architecture.md](00-architecture.md) — module/layer map and trust boundaries
- [00-cheatsheet.md](00-cheatsheet.md) — one-screen quick reference of all `noid-*` commands + diagnostics
- [01-getting-started.md](01-getting-started.md) — first-day checklist
- [01-grub-password.md](01-grub-password.md) — optional GRUB authentication and recovery impact
- [threat-model.md](threat-model.md) — attacker classes, coverage and residual risks
- [scope.md](scope.md) — target audience, anti-targets and explicit out-of-scope uses
- [post-quantum-readiness.md](post-quantum-readiness.md) — current PQ capability and protocol gaps
- [performance-profile.md](performance-profile.md) — source-level performance rationale and trade-offs
- [licensing.md](licensing.md) — exact multi-license repository and component inventory
- [notifications.md](notifications.md) — what the desktop notifications mean
- [ecosystem-and-support.md](ecosystem-and-support.md) — project website, the Android/Windows siblings, how to support development

### System security
- [02-system-security.md](02-system-security.md) — sysctl + SELinux + auditd + kernel lockdown
- [03-firewall-zones.md](03-firewall-zones.md) — firewalld zones + block-lan-out + how to allow
- [05-lan-isolation.md](05-lan-isolation.md) — Layer 5-7 isolation (mDNS/SMB/WSD/NetBIOS off)
- [08-masked-services.md](08-masked-services.md) — masked-service policy + how to unmask
- [08-fss-verify.md](08-fss-verify.md) — journal forward-secure-sealing verification
- [10-bash-history.md](10-bash-history.md) — shell-history privacy behavior

### Networking & VPN
- [06-vpn-setup.md](06-vpn-setup.md) — VPN import + killswitch verification
- [07-physical-ipv6-boundary.md](07-physical-ipv6-boundary.md) — physical IPv6 is not a release-qualified v1.7 mode
- [11-dns-custom.md](11-dns-custom.md) — change DNS provider, NTP troubleshooting
- [11-time-recovery.md](11-time-recovery.md) — local-VT recovery for a badly wrong RTC
- [11b-dns-diagnostics.md](11b-dns-diagnostics.md) — manual DNS evidence collection and explicit probes
- [wan-egress-strict.md](wan-egress-strict.md) — exact VPN-endpoint egress mode

### Storage & recovery
- [20-rollback-recovery.md](20-rollback-recovery.md) — snapshot rollback
- [22-disk-encryption.md](22-disk-encryption.md) — LUKS + btrfs + backup

### Applications & browser
- [16-firefox-hardening.md](16-firefox-hardening.md) — local NoID Privacy Firefox derivative + uBlock
- [17-gnome-hardening.md](17-gnome-hardening.md) — GNOME privacy locks and session helpers
- [18-flatpak-trust-model.md](18-flatpak-trust-model.md) — Flatpak trust, Fedora-RPM one-shot browsing and manual AppImage exceptions
- [35-thunderbird-smartcard.md](35-thunderbird-smartcard.md) — experimental Thunderbird/RNP smartcard boundary
- [gnome-extensions-autostart.md](gnome-extensions-autostart.md) — pre-installed extensions, opt-in alternatives, autostart best-practice 2026

### Hardware
- [14-usbguard.md](14-usbguard.md) — USB device whitelisting
- [15-intel-me-hardware-layer.md](15-intel-me-hardware-layer.md) — Intel ME mitigation (Intel hosts)
- [15-amd-psp-hardware-layer.md](15-amd-psp-hardware-layer.md) — AMD PSP / ASP awareness (AMD hosts)
- [19-nvidia-drivers.md](19-nvidia-drivers.md) — NVIDIA proprietary driver (opt-in)
- [19-secure-boot-mok.md](19-secure-boot-mok.md) — MOK enrollment for kernel modules
- [21-kernel-module-blacklist.md](21-kernel-module-blacklist.md) — which modules are blacklisted
- [27-performance.md](27-performance.md) — Fedora-owned defaults, GNOME/tuned opt-ins and honest measurement
- [docking-stations.md](docking-stations.md) — Thunderbolt dock guidance

### System
- [24-firmware-updates.md](24-firmware-updates.md) — fwupd + LVFS posture
- [26-optional-packages.md](26-optional-packages.md) — what was excluded + how to install
- [32-branding.md](32-branding.md) — local-only branding maintenance units
- [trademark-notice.md](trademark-notice.md) — product identity and upstream attribution

### Advanced
- [ai-workspace.md](ai-workspace.md) — Claude/Codex/Gemini/Cursor policy adapters, privacy defaults, and cloud trust boundaries
- [28-local-ai.md](28-local-ai.md) — local LLM coding assistant (offline AI)
- [ssh-client-hardening.md](ssh-client-hardening.md) — SSH client crypto + HashKnownHosts migration
- [ssh-server-opt-in.md](ssh-server-opt-in.md) — enable SSH server (opt-in)
- [33-oauth-audit-checklist.md](33-oauth-audit-checklist.md) — user-invoked OAuth grant review
- [33-firefox-profile-isolation.md](33-firefox-profile-isolation.md) — separate-browser-profile workflow
- [33-integrity-check-guide.md](33-integrity-check-guide.md) — user-invoked integrity scan guide
- [aide-notify-dropin.conf](aide-notify-dropin.conf) — template for AIDE notifications
- [aide-schedule-override.conf](aide-schedule-override.conf) — template for AIDE timer

## Architecture in 30 seconds

This image is a **Fedora 44 Workstation** with 41 functional sections
(Modules) applied during the Anaconda install:

- **Layered ownership**: each functional section has an owning Module and
  explicit cross-Module contracts in a fixed compose order. Rerun support is
  Module-specific, not a universal idempotency promise.
- **Defense-in-depth**: load-bearing controls such as VPN-zone/WAN-strict
  safety, the physical IPv6 boundary and kernel lockdown combine
  owner-specific enforcement with postcondition checks
- **Silent-machine baseline**: no project telemetry or LAN discovery;
  documented DHCP/ARP and NTS control traffic remains, DNS diagnostics send
  a query only after an explicit `probe TARGET`, and user-installed
  applications can add traffic
- **Provider-neutral**: ships no configured VPN provider, mail account, cloud
  account or credentials. Thunderbird is installed but has no account until
  you configure one.
- **Scoped recovery**: many controls have documented opt-outs, but recovery is
  not universally one-click. Storage layout, encryption, firmware and some
  image-policy changes can require a reviewed migration or reinstall; every
  opt-out names its security/privacy cost.

The section documents record relevant rationale, upstream sources and
trade-offs. Treat references as starting points and re-check moving upstream
behavior against the installed version.

## CLI tools shipped

User-facing helpers are in `/usr/local/bin/` and `/usr/local/sbin/` (both are
on the normal NoID Privacy command path). This table highlights common entry
points; `noid-help commands` prints the complete installed inventory:

| Command | Purpose | Doc |
|---------|---------|-----|
| `noid-status` | Hardening state diagnostic (one screen) | (built-in help: `noid-status --help`) |
| `noid-help` | List / open / search user-doc topics | 00-cheatsheet.md |
| `noid-welcome.sh --again` | Re-open first-boot welcome (priority-layout menu, includes mic/cam toggles) | This file |
| `noid-network-audit <wan\|firewall\|nft\|mtu>` | Read-only formatted WAN-strict, firewalld, in-kernel nftables and WireGuard tunnel-MTU postcondition audits | wan-egress-strict.md / 03-firewall-zones.md |
| `noid-dns-mode status\|opportunistic\|strict\|off\|reset` | Select and verify global + active physical Quad9 DoT without changing VPN/private DNS | 11-dns-custom.md |
| `noid-luks-backup.sh` | LUKS header backup wrapper (--verify, --list-existing) | 22-disk-encryption.md |
| `noid-complete-setup.sh` | Install optional full codecs + vendor-specific GPU decode drivers; `unar`/`7zip` are already installed | 26-optional-packages.md |
| `noid-nvidia-install.sh` | NVIDIA proprietary install Stage 1 (GPU-gen-detect + MOK) | 19-nvidia-drivers.md |
| `noid-toggle-gsk-gl auto/on/off/status` | Reversible GTK4 renderer policy; automatic only on portable NVIDIA-offload hybrids | 19-nvidia-drivers.md |
| `noid-snap-pre <description>` | Manual snapshot before a change | 20-rollback-recovery.md |
| `noid-update-all.sh` | Guided system update (snapshot + DNF + Flatpak + firmware) | 01-getting-started.md |
| `noid-toggle-aide-popup` | Enable/disable AIDE desktop notifications | notifications.md |
| `noid-usbguard-devices` | Inspect runtime/persistent USB state; allow or revoke exact devices | 14-usbguard.md |
| `noid-firefox-relax-fpp` | Temporarily relax Firefox FPP canvas for sites | 16-firefox-hardening.md |
| `noid-mei-restore-submodules` | Unblacklist MEI submodules (fwupd BootGuard) | 15-intel-me-hardware-layer.md |
| `noid-mei-lockdown` | Re-apply MEI submodule lockdown | 15-intel-me-hardware-layer.md |

## Where to get help

### In-system

- Run `noid-status` for a one-screen diagnostic.
- Read any doc in this directory: `less /usr/share/doc/noid-privacy/<file>.md`
- Re-open the first-boot welcome: `noid-welcome.sh --again`

### System logs

- Live notifications (AIDE, etc.) in the GNOME notification drawer.
- Journal: `journalctl -b -p warning` shows warnings since last boot.
- Firewall log: `journalctl -u firewalld` (drops visible with `grep -i drop`).
- Audit log: `sudo ausearch -ts today` (requires privileges).

### External

- Project website (all NoID Privacy platforms): <https://noid-privacy.com>
- Source + issue tracker: <https://github.com/NexusOne23/noid-privacy-workstation>
- Upstream Fedora docs: <https://docs.fedoraproject.org/>
- CIS Benchmark RHEL 9: <https://www.cisecurity.org/benchmark/red_hat_linux>
- Historical Firefox hardening reference snapshot:
  <https://github.com/arkenfox/user.js>

## License & source

- Fedora base package set: every package retains its own upstream license
- NoID Privacy documentation: CC-BY-SA-4.0
- NoID Privacy code and machine-readable policy: GPL-3.0-or-later except the
  file-level and embedded-source exceptions inventoried in
  [licensing.md](licensing.md)

NoID Privacy's image-owned hardening components do not send project telemetry.
This does not cover Fedora/upstream applications, software you install, cloud
services you invoke, or the explicitly initiated network probes documented
above.

README_EOF

publish_doc "$README_DOC"
log "  [OK] 00-README.md written"

# ------------------------------------------------------------------------------
# Phase 3 — Write 01-getting-started.md (first-day checklist)
# ------------------------------------------------------------------------------
PHASE="P3-getting-started"
log "Writing 01-getting-started.md"

GETSTART_DOC="$DOC_DIR/01-getting-started.md"
DOC_TMP=$(mktemp "$DOC_DIR/.01-getting-started.md.XXXXXXXX")
cat > "$DOC_TMP" <<'GETSTART_EOF'
# Getting Started — First-Day Checklist

Welcome to NoID Privacy Workstation. This page walks you through the tasks
you should do in your first day of using the system, before relying on
it for anything serious.

All installed user guides live together in
`/usr/share/doc/noid-privacy/`. List them with `noid-help list`, open one with
`noid-help <topic>`, or search all of them with
`noid-help search <keyword>`. The terminal reader does not turn Markdown
references into clickable links, so this guide uses those runnable commands.

Tasks are grouped by **priority**:

- **⚠ CRITICAL** — without these, you can lose data irreversibly
- **⏱ IMPORTANT** — do within the first 24 hours
- **✓ RECOMMENDED** — do within the first week

Total time if you do everything: ~60-90 min including reading.
Minimum viable (CRITICAL only): ~15 min.

---

## ⚠ CRITICAL — Do FIRST (~15 minutes)

### 1. Back up your LUKS header

If you selected disk encryption, LUKS2 metadata and keyslots unlock the
encrypted volume. Damage to both metadata areas or required keyslots can make
the volume inaccessible. An offline, tested header backup adds a recovery path;
it does not replace a data backup.

#### Easy path — opt-in helper (recommended)

Use an external target that supports enforceable per-file POSIX ownership and
modes, such as ext4, XFS or Btrfs directly or inside a LUKS container. Typical
FAT32/exFAT desktop sticks are rejected because they cannot enforce the
helper's private `root:root` mode-0700 staging contract. Reformatting erases a
device, so copy its existing data elsewhere first. After a suitable target is
mounted by GNOME, run:

```bash
noid-luks-backup.sh
```

The helper auto-detects your LUKS partition(s), selects only mounted removable
media whose topology and permissions satisfy its backup contract, and wraps
`cryptsetup luksHeaderBackup` with a sensible default filename, structural
verification, SHA-256 evidence and durable synchronization. Also available as
"Back up LUKS header" in the first-boot welcome menu
(`noid-welcome.sh --again`).

#### Manual walkthrough

```bash
(
set -euo pipefail

# 1. Inspect every LUKS device and the mounted external target.
lsblk -o NAME,PATH,FSTYPE,TYPE,MOUNTPOINTS

# 2. Export the exact values you verified. These examples are inert comments:
# export LUKS_DEVICE=/dev/nvme0n1p3
# export LUKS_BACKUP_DIR=/run/media/"$USER"/USB_LABEL
luks_device=${LUKS_DEVICE:?export LUKS_DEVICE with the exact LUKS block device}
backup_dir=${LUKS_BACKUP_DIR:?export LUKS_BACKUP_DIR with the mounted external directory}
test -b "$luks_device"
test -d "$backup_dir"
sudo cryptsetup luksDump "$luks_device" >/dev/null

# 3. Back up to the EXTERNAL target — never to the encrypted source drive.
backup="$backup_dir/luks-header-$(date -u +%Y%m%dT%H%M%SZ).bin"
sudo cryptsetup luksHeaderBackup "$luks_device" \
    --header-backup-file "$backup"
sudo chown "$(id -u):$(id -g)" "$backup"
chmod 0600 "$backup"
cryptsetup luksDump "$backup" >/dev/null
sha256sum "$backup"
sync "$backup" "$backup_dir"
)
```

Then copy the `.bin` file to a **second** USB stick stored in a
different physical location (friend's house, bank safe, parents'
place). Two copies, two places.

A header backup plus any passphrase valid when that backup was created can
decrypt the data even after that passphrase is removed from the live header.
Protect every copy and securely retire obsolete copies; prefer encrypted
external media.

If you have additional encrypted drives (data disks, backup disks),
repeat for each one.

Full details + `borg` backup setup: `noid-help 22-disk-encryption`.

### 2. Write down your passphrase and recovery key

Every active LUKS keyslot credential can unlock the volume: that may include
your passphrase, a recovery key, or another deliberately enrolled credential.
If every usable credential is lost, neither the header backup nor NoID Privacy
can recover the plaintext.

- **Write the passphrase** on paper. Store the paper separately from
  the laptop (different room, different building, safe).
- If you generated a recovery key with `systemd-cryptenroll
  --recovery-key` during install, write that down too (64 characters).
- A copy stored only in a password manager on this same encrypted disk is
  unavailable when you need it to unlock or recover that disk. Keep at least
  one protected recovery copy physically separate from the workstation.

### 3. Set up your VPN

The image ships **no** VPN provider. You import your own config. Without a VPN,
your ISP can observe destination and traffic metadata and may also see DNS
queries when authenticated DNS is unavailable and the documented DNS/53
fallback is used. A VPN moves that visibility and trust to the VPN provider; it
does not make browsing anonymous by itself.

→ Run `noid-help 06-vpn-setup` for:
- **ProtonVPN** (WireGuard) — manual config or official opt-in client
- **Mullvad** (WireGuard) — numbered account without an email address
- **Generic WireGuard** — self-hosted or other providers
- **OpenVPN** — maintained compatibility path for providers and deployments

After setup, verify with `curl https://am.i.mullvad.net/json` — the
`ip` field should be the VPN server IP, not your home IP. This is an explicit
request to Mullvad, which necessarily exposes that connection's source IP and
request metadata to the service.

### Optional: sudo-level setup (any time later)

The image ships three opt-in wrapper scripts for tasks that need
`sudo` privilege or careful user interaction. All are **completely
optional** — the supported base image does not require them. They
exist as convenience wrappers around documented manual steps, with
the same unified "return to welcome menu" flow at the end.

All three are also available as clickable options in the first-boot
welcome dialog (`noid-welcome.sh --again`).

```bash
# 1. LUKS header backup (CRITICAL — do this first-day, see above)
#    Auto-detects LUKS partition + mounted removable media, wraps
#    cryptsetup luksHeaderBackup with SHA256 verification.
noid-luks-backup.sh

# 2. Media-codec completion (transaction size varies with installed state)
#    Installs full ffmpeg + GStreamer H.265 coverage, the Fedora/Cisco
#    OpenH264 bridges, and the applicable GPU HW-decode codec-driver swap
#    (Intel intel-media-driver / AMD mesa-va-drivers-freeworld).
#    Opt in when the Fedora-free baseline lacks a format or acceleration path
#    you actually need.
#
#    NOTE: RAR + 7-Zip archive extraction
#    are HANDLED BY PRE-INSTALLED FOSS alternatives — unar (RARv5 + multi-
#    volume via Fedora main) + 7zip (Fedora main, replaces legacy p7zip).
#    No opt-in setup needed. M08's minimalist package set dropped unrar
#    + p7zip-plugins from noid-complete-setup.sh because Fedora-main FOSS
#    alternatives cover the use-case without RPM Fusion nonfree license.
noid-complete-setup.sh

# 3. NVIDIA proprietary driver install (Stage 1 of 3)
#    GPU-generation-detection + branch selection (mainline vs 580xx LTS).
#    Shows trade-off matrix with explicit "SKIP recommended for most users".
#    If user opts in: installs akmod-nvidia + xorg-x11-drv-nvidia-cuda,
#    triggers akmods build, generates MOK, imports to MOK queue.
#    Refuses install on Kepler/Fermi (EOL drivers with unpatched CVEs).
#    Non-NVIDIA systems see "No NVIDIA GPU detected" and exit harmlessly.
#    After running: reboot, navigate 7-step MokManager blue screen,
#    reboot again, then run #2 (noid-complete-setup.sh) for HW-decode.
noid-nvidia-install.sh
```

All scripts refuse to run as root and invoke `sudo` internally for privileged
operations. Capabilities differ by tool: the NVIDIA helper supports `--dry-run`
and `--rollback`; the LUKS helper provides `--verify` and `--list-existing`.
Check each tool's `--help` instead of assuming a shared option set.

Full documentation:

- `noid-luks-backup.sh` — `noid-help 22-disk-encryption`
  (section "LUKS Header Backup — Easy path")
- `noid-complete-setup.sh` — `noid-help 26-optional-packages`
  (section "RPM Fusion codec stack")
- `noid-nvidia-install.sh` — `noid-help 19-nvidia-drivers`
  (section "Quick setup — Stage 1") + `noid-help 19-secure-boot-mok`
  (for the 7-step MokManager blue screen walkthrough)

---

## ⏱ IMPORTANT — Do within 24 hours (~30 minutes)

### 4. Run `noid-status` and verify everything is green

```bash
noid-status
```

This shows a curated diagnostic overview including kernel lockdown, SELinux,
firewall, VPN, AIDE, USBGuard, LUKS, Secure Boot and HSI. It is not proof that
every control or hardware path works. Read each section. If anything looks
wrong (red/FAIL marker),
check the corresponding doc in this directory.

### 5. Decide whether to establish and schedule AIDE checks

The image deliberately creates no trusted AIDE database and leaves
`aide-check.timer` disabled. If you want file-integrity monitoring, prepare a
candidate, review its complete report, and commit only the exact SHA-256 you
personally accept:

```bash
sudo noid-aide-baseline-review prepare
sudo noid-aide-baseline-review status
# After reviewing the complete report:
sudo noid-aide-baseline-review commit SHA256
sudo systemctl enable --now aide-check.timer
```

After that explicit trust decision, the default timer runs between 07:00 and
08:00 and compares configured paths with the accepted database. Optional
desktop notification setup is documented by `noid-help notifications`.

- **No differences**: only means the configured comparison matched the
  accepted database; it is not a general claim that the system is clean.
- **Differences after an update**: review the exact paths and package evidence;
  the updater does not absorb them automatically.
- **Unexpected differences**: investigate and preserve the report.
  Start with `sudo journalctl -u aide-check.service` to see what
  changed. Never commit a candidate merely to silence an alert.

Details: `noid-help notifications`.

To disable the popup (log-only mode):
```bash
sudo noid-toggle-aide-popup off
```

### 6. Prefer the guided update process

This image ships `noid-update-all.sh`, a guided update workflow that:

1. Takes a **pre-update snapshot** (so you can roll back if an update
   breaks the system)
2. Runs `dnf upgrade` with a consistent umask and logging
3. Runs `flatpak update`
4. Offers firmware updates via `fwupdmgr` (opt-in per run)
5. Checks against an existing user-owned AIDE baseline and preserves drift
6. Creates a **post-update snapshot** for comparison

```bash
noid-update-all.sh
```

Run it as your **normal user** — the script refuses to start via
sudo and invokes sudo internally only where needed.

If a reboot is required, the script tells you. There is no grub-btrfs
integration and GRUB does not list Snapper snapshots. While the system still
boots, inspect and select the correct snapshot explicitly:

```bash
(
set -euo pipefail
sudo snapper -c root list
snapshot_id=${NOID_SNAPSHOT_ID:?export NOID_SNAPSHOT_ID with the reviewed numeric ID}
sudo noid-snap-rollback "$snapshot_id"
sudo reboot
)
```

If the desktop no longer starts, boot to the text console instead: press `e`
at the GRUB menu, append ` systemd.unit=multi-user.target`, unlock LUKS, log
in with your user account and run the same reviewed rollback command
(rescue/emergency targets provide no maintenance shell on this image — run
`noid-help 99-troubleshooting` and read "Boot-level problems").
`/home` and `/boot` are outside the root-snapshot boundary. See
`noid-help 20-rollback-recovery` before relying on recovery.

**Plain `dnf upgrade` works too**, but you lose the guided snapshot,
post-update AIDE check and Flatpak/firmware steps. Use the guided script when
you can; neither path accepts AIDE drift automatically.

### 7. Plug in your trusted USB devices once

USBGuard blocks unknown USB devices by default. The **first** time you
plug in each device (keyboard, mouse, printer, yubikey, external
drive), USBGuard will deny it and show a notification. Allow it via:

```bash
sudo noid-usbguard-devices allow
```

Or click "Allow" in the notification for a temporary authorization of the
current device instance. For a durable rule with rollback evidence, use the
helper above. Run `noid-help 14-usbguard` for the full workflow and
USBGuard's native privilege-granularity limitation.

---

## ✓ RECOMMENDED — Within the first week

### 8. Review Firefox hardening

Firefox ships with:
- NoID Privacy Firefox Hardening (locally maintained derivative of the reviewed
  arkenfox v144.0 snapshot; no automatic upstream import)
- uBlock Origin with extra blocklists (phishing + LAN intrusion)
- System/VPN DNS by default; direct WAN uses strict authenticated global +
  physical Quad9 DoT, while unset VPN/private profiles use best-effort
  opportunistic DoT (both opportunistic paths permit DNS/53 fallback)
- Total Cookie Protection (TCP)
- Fingerprint Protection (FPP) with canvas randomization

Some sites may break (for example captchas, banks or streaming services).
Diagnose the responsible layer before changing it: uBlock can be relaxed per
site, while the supported FPP and WebRTC compatibility helpers are
profile-scoped and affect every site in the selected profile. Use a separate
compatibility profile when a narrow exception matters. See
`noid-help 16-firefox-hardening`.

### 9. If you have an NVIDIA GPU → choose the driver path for your workload

The image ships with the open-source **Nouveau** kernel driver and Mesa's
**NVK** Vulkan driver. GPU coverage and conformance evolve with Mesa; consult
the [current NVK status](https://docs.mesa3d.org/drivers/nvk.html) and inspect
the installed version with `rpm -q mesa-vulkan-drivers`. This path covers
common desktop, browser, video-playback, office and indie-gaming workloads.
Install the proprietary driver only if you need: **CUDA** (ML/AI), **DLSS**,
**AAA gaming at max settings**, or **NVENC** (streaming).

#### Easy path — opt-in helper (recommended)

```bash
noid-nvidia-install.sh
```

The helper:

- Shows an explicit **trade-off matrix** ("Recommended: SKIP — nouveau+NVK
  is enough for most users") before asking for consent
- **Detects your GPU generation** (Blackwell/Ada/Ampere/Turing →
  mainline; Volta/Pascal/Maxwell → 580xx LTS; Kepler/Fermi → REFUSE)
- **Warns on mixed-generation multi-NVIDIA** setups (one branch can't
  support both)
- Installs correct packages for F44 Wayland-only (`akmod-nvidia` +
  `xorg-x11-drv-nvidia-cuda` — NOT the X11 session driver)
- Triggers akmods build, generates MOK key, imports to queue
- Prints **full 7-step MokManager blue screen walkthrough**
- Offers `--rollback` for recovery if anything breaks

Also available as "Install NVIDIA Driver" in the welcome
dialog (`noid-welcome.sh --again`).

#### Manual walkthrough

If you prefer explicit control over every step, run
`noid-help 19-nvidia-drivers` (section "Manual walkthrough") +
`noid-help 19-secure-boot-mok` (for
the 7-step MOK enrollment blue screen flow).

### 10. Optional packages you may want

The image excludes software that most users don't need (printing,
calendar apps, etc.) to reduce attack surface and
ISO size. If you need any of them, install on demand:

- **Printing**: `sudo dnf install cups gutenprint-cups hplip`
- **Bluetooth**: stack and GNOME controls are installed but radio/service ship
  off; opt in with `sudo noid-toggle-bluetooth on`. Install `bluez-obexd` only
  if Bluetooth file transfer is specifically needed.
- **Calendar/Contacts**: `sudo dnf install gnome-calendar gnome-contacts`
- **Office**: LibreOffice is already installed.
- **Development**: VSCodium and selected CLI tools are already installed.
  Install only the Fedora-signed tools you need; keep Python dependencies in
  virtual environments and language/build ecosystems in rootless containers.

Full list + commands: `noid-help 26-optional-packages`.

### 11. Local AI coding assistant (optional)

If you want local AI inference for code completion or chat, this image supports
CPU and several GPU backends. Model acquisition, editor extensions, and their
update/telemetry behavior are separate network boundaries.
Run `noid-help 28-local-ai` for the full guide including
the reviewed `llama-vscode` owner profile and loopback llama.cpp WebUI.

---

## 🧭 Background services and schedules

This table distinguishes always-active components, opt-in schedules and manual
workflows:

| Component | Schedule | Purpose |
|-----------|----------|---------|
| `firewalld` | always | Default-deny firewall + LAN isolation |
| VPN kill switch | while the configured VPN policy is active | Enforces that policy if its tunnel goes down |
| SELinux | always | MAC enforcement + targeted policy |
| `auditd` | always | Kernel audit log (`/var/log/audit/`) |
| AIDE check | disabled until reviewed baseline + explicit enable | Optional daily 07:00-08:00 integrity scan; popup is separately controllable |
| fwupd refresh | automatic timer masked | Firmware metadata refresh is manual |
| Flatpak updates | manual (via update-all) | User apps |
| DNF updates | manual (via update-all) | System packages |
| NTP sync (NTS-only) | continuous | Secure clock sync |
| DNS (resolved; strict global + physical Quad9 DoT) | continuous | VPN/private `~.` link DNS takes precedence; unset profiles inherit best-effort opportunistic DoT with DNS/53 fallback; Firefox follows that system path |

---

## 📖 Where to next

- **Full index**: `noid-help 00-README` — browse by category
- **Diagnostics**: `noid-status`
- **Re-run this welcome**: `noid-welcome.sh --again`
- **Detailed section docs**: `noid-help list` or
  `ls /usr/share/doc/noid-privacy/`

For a first diagnostic pass:

```bash
noid-status         # see what the system thinks
journalctl -b -p 4  # warnings and errors since last boot
```

Welcome aboard.

GETSTART_EOF

publish_doc "$GETSTART_DOC"
log "  [OK] 01-getting-started.md written"

# ------------------------------------------------------------------------------
# Phase 4 — Write 06-vpn-setup.md (ProtonVPN + Mullvad + generic WireGuard)
# ------------------------------------------------------------------------------
PHASE="P4-vpn-setup"
log "Writing 06-vpn-setup.md"

VPN_DOC="$DOC_DIR/06-vpn-setup.md"
DOC_TMP=$(mktemp "$DOC_DIR/.06-vpn-setup.md.XXXXXXXX")
cat > "$DOC_TMP" <<'VPN_EOF'
# VPN Setup

This image ships **no** VPN provider. You import your own config, via
NetworkManager. The image supplies a hardened firewall-zone safety layer;
a route/DNS killswitch is provider- or profile-specific and must be tested.

## Why neutral?

Many VPN providers ship a client with an optional killswitch, but behavior
differs and must not be assumed. Bundling one in the base image means we'd pick a winner,
carry its dependencies, and fight its auto-update cycle. Instead, we
ship provider-neutral inbound/LAN controls plus optional WAN-strict. The
dispatcher recognizes maintained NetworkManager profile/interface schemas; it
is not proof that every provider client is classified. You pick the provider
you trust and verify its live profile.

Before treating VPN protection as active, complete and test one setup below.
Choosing no VPN is also supported, but direct-WAN destination and traffic
metadata remain visible to the access network/ISP.

Every public-IP, DNS or browser leak-test site below is a third-party
observation, not a local proof. Invoking one necessarily discloses the tested
connection's source IP and request/browser metadata to that operator.

## What's already done for you (inbound/LAN layers, not a killswitch)

Regardless of VPN provider, the default posture includes the following layers.
Their live status and explicit user toggles remain authoritative; no item below
is evidence that a separate VPN route/DNS killswitch is active:

1. **Default firewalld zone is `drop`** (Module 03) — zero unsolicited
   inbound connections are accepted on your physical interface. Firewalld
   zone `drop` is not a blanket outbound-WAN block.
2. **Block-lan-out policy** — outbound traffic to the local LAN is
   dropped (the gateway included; DHCP still works via NM's raw L2 socket).
3. **NM dispatcher** (Module 06) — whenever a VPN-style interface
   (`wg0`, `proton0`, `tun0`, `mullvad-*`, etc.) comes up, it's
   forced into firewalld's inbound-DROP `noid-vpn` zone,
   regardless of what zone the VPN client set.
4. **IPv6 disabled per WAN** (Module 07) — the IPv6 attack surface
   is reduced; VPN-internal IPv6 (your VPN provider's DNS)
   still works when routed over the tunnel.
5. **System/VPN DNS in Firefox** (Modules 05/16/23) — an active VPN/private
   `~.` resolver wins; direct WAN uses strict authenticated global + physical
   Quad9 DoT. Unset VPN/private profiles inherit best-effort opportunistic DoT;
   both that link mode and explicit pre-VPN compatibility can fall back to
   DNS/53. This is not a route killswitch.
6. **TunnelVision mitigation** (CVE-2024-3661, Module 23) — a NM
   dispatcher neutralizes DHCP Option-121 classless-static-routes that
   would bypass the VPN tunnel: IPv6 uses `ipv6.ignore-auto-routes=yes`,
   and for IPv4 the dispatcher strips any DHCP-pushed Option-121 routes
   after each lease (IPv4 `ignore-auto-routes` is intentionally left OFF
   — enabling it dropped the pre-VPN default route). Upstream NetworkManager also documents
   a **policy-routing** alternative (add VPN routes to a custom table,
   set rule priority higher than main) which is sometimes better when
   you also need legitimate DHCP-option-121 routes; the NoID Privacy approach
   trades that flexibility for simplicity on the "always-VPN" threat
   model.
7. **Optional WAN-egress-strict** (Module 06) — literal loaded-profile
   endpoints and runtime-confirmed hostname endpoints form reconciled exact
   tuples; unauthenticated DNS answers are only 120-second handshake
   candidates. Mode `STRICT` blocks other public egress on physical
   interfaces. Before first arming, `GRACE_BOOTSTRAP`/
   `GRACE_PAUSED` deliberately retains recovery WAN. `noid-wan-strict status`
   is the authority; `STRICT_EMPTY` stays closed after deletion/expiry and
   strict mode must never be inferred merely from file presence.

### Required onboarding/no-VPN decision

`GRACE_BOOTSTRAP` has no automatic timer: expiring it could strand a fresh
installation before a profile can be obtained, and NoID Privacy supports operation
without a VPN. It is nevertheless direct IPv4 WAN, not strict protection.
Choose and verify one explicit outcome:

- configure a supported VPN endpoint until `sudo noid-wan-strict status`
  reports `STRICT`;
- deliberately keep an armed `STRICT_EMPTY` fail-closed posture; or
- choose no VPN with `sudo noid-toggle-wan-strict off`, then verify the
  published mode is `DISABLED`.

The Network app and `noid-toggle-wan-strict status` must show the same
root-published runtime mode. Flag absence or service enablement alone is not a
protection signal.

### Advanced: policy routing alternative (TunnelVision power-user setup)

NoID Privacy's default TunnelVision mitigation is designed for "always-VPN"
profiles. If you need legitimate DHCP-option-121 routes (e.g. a corporate
network with split-tunnel resources at non-RFC-1918 IPs), policy routing is
the alternative recommended by upstream NetworkManager. It places VPN routes
in a separate routing table with a higher-priority rule, so malicious
option-121 routes injected into the main table are bypassed for VPN-bound
traffic:

```bash
(
set -euo pipefail
# 1. Find your VPN connection name
nmcli connection show
vpn_profile=${VPN_PROFILE:?export VPN_PROFILE with the exact VPN connection name}
nmcli --get-values GENERAL.STATE --escape no \
    connection show "$vpn_profile" >/dev/null

# 2. Apply policy routing. Table 75 is a table identifier; rule priority
#    32000 is evaluated before the main lookup rule at 32766.
sudo nmcli connection modify "$vpn_profile" \
    ipv4.route-table 75 \
    ipv4.routing-rules "priority 32000 from all table 75" \
    ipv6.route-table 75 \
    ipv6.routing-rules "priority 32000 from all table 75"

# 3. Restart the VPN to apply
sudo nmcli connection down "$vpn_profile"
sudo nmcli connection up "$vpn_profile"
)
```

**Side effects to know about**:
- If you are using full-tunnel (`AllowedIPs = 0.0.0.0/0, ::/0` —
  the NoID Privacy default for Proton/Mullvad), this configuration routes
  all matching IP traffic through the VPN, including LAN destinations.
  Required link control/gateway traffic is separate. Local-network printers /
  NAS / services will become unreachable unless explicitly excepted.
- Captive portals (hotel / coffee-shop WiFi login pages) won't work
  while this is active — disable temporarily or use a separate
  WiFi-only profile without VPN routing-rules.
- Bug-fix note: NetworkManager fixed partially ignored VPN routing rules in
  development release 1.51.6 and stable releases 1.50.2 / 1.48.16. The
  Fedora 44 package used by this image includes the fix; on other releases,
  check the distribution changelog for a backport.

When NOT to use policy routing: if your VPN already covers 0.0.0.0/0
and you don't need DHCP-option-121 routes for legitimate cases, the
NoID Privacy default (IPv6 ignore-auto-routes + IPv4 route-cleanup) is simpler,
but the two designs have different routing/failure behavior and must not be
called universally equivalent. Reference: [NetworkManager blog — Protect your VPN from
TunnelVision attacks](https://networkmanager.dev/blog/protect-your-vpn-from-tunnelvision-attacks/).

Important: the `noid-vpn` zone and block-lan-out policy do not prevent direct
public WAN fallback. A tunnel-down block exists only when an independently
verified provider kill switch is in its blocking state or NoID Privacy WAN-strict
reports `STRICT`. Test the exact selected mode; do not merge these layers into
one generic “safety net”.

---

## Option 1: ProtonVPN (WireGuard)

### Step 1 — Generate a WireGuard config

1. Log into <https://account.protonvpn.com/>
2. Navigate to **Downloads → WireGuard configuration**
3. Keep the downloaded `.conf` basename under 15 characters, following
   Proton's current conservative guidance. Dashes are valid WireGuard
   interface-name characters and work with NetworkManager; Proton's own
   maintained example is `proton-238.conf`.
4. Select only generator features you understand. The available NAT,
   NetShield, accelerator, port-forwarding and IPv6 choices depend on the
   current Proton plan and generator; do not copy a historical preset blindly.
5. Pick a server (e.g. `US#1`) → **Create**
6. Download the resulting `.conf` file to `~/Downloads/`.

### Step 2 — Import into NetworkManager

```bash
(
set -euo pipefail
# wireguard-tools ships with the image; this confirms it and recovers a host where it was removed
rpm -q wireguard-tools || sudo dnf install wireguard-tools

# Export the exact downloaded file first. Its basename becomes both the
# WireGuard interface and initial NetworkManager connection name.
# export PROTON_WG_CONFIG="$HOME/Downloads/proton-238.conf"
proton_config=${PROTON_WG_CONFIG:?export PROTON_WG_CONFIG with the exact downloaded .conf}
test -f "$proton_config"
test ! -L "$proton_config"
config_name=${proton_config##*/}
[[ "$config_name" =~ ^[A-Za-z0-9_.-]+\.conf$ ]]
initial_profile=${config_name%.conf}
test "${#initial_profile}" -le 15
chmod 0600 "$proton_config"
if nmcli --terse --escape no --fields NAME connection show \
    | grep -qxF -- "$initial_profile"; then
  printf 'Connection already exists: %s\n' "$initial_profile" >&2
  false
fi

# Import the exact file and verify its derived initial profile.
sudo nmcli connection import type wireguard file "$proton_config"
nmcli --get-values GENERAL.NAME --escape no connection show "$initial_profile" \
    | grep -qxF -- "$initial_profile"

# Record this value for the following steps, changing it only if you rename
# the connection yourself:
printf 'export PROTON_PROFILE=%q\n' "$initial_profile"
)
```

### Step 3 — Set preferences

```bash
(
set -euo pipefail
proton_profile=${PROTON_PROFILE:?export PROTON_PROFILE with the exact imported connection name}
nmcli --get-values GENERAL.NAME --escape no connection show "$proton_profile" \
    | grep -qxF -- "$proton_profile"

# Auto-connect at boot (makes it the default route as soon as network is up)
sudo nmcli connection modify "$proton_profile" connection.autoconnect yes

# Confirm the NM dispatcher will use the inbound-DROP VPN zone
# (this is automatic on first `up`, but you can preset for clarity):
sudo nmcli connection modify "$proton_profile" connection.zone noid-vpn

# DNS leak protection: negative priority makes Proton's DNS exclusive
# when the VPN is up (other interfaces' DNS is ignored).
sudo nmcli connection modify "$proton_profile" ipv4.dns-priority -1
sudo nmcli connection modify "$proton_profile" ipv6.dns-priority -1
)
```

### Step 4 — Bring it up and verify

```bash
(
set -euo pipefail
proton_profile=${PROTON_PROFILE:?export PROTON_PROFILE with the exact imported connection name}
nmcli --get-values GENERAL.NAME --escape no connection show "$proton_profile" \
    | grep -qxF -- "$proton_profile"

# Activate
sudo nmcli connection up "$proton_profile"

# Check your external IP — should be the ProtonVPN server IP.
curl --fail --silent --show-error https://am.i.mullvad.net/json \
    | jq -r '.ip, .country, .city'

# Alternative leak-test sites (use at least two — each has blind spots):
#   https://ipleak.net/               (IP + DNS + WebRTC, AirVPN)
#   https://browserleaks.com/ip       (comprehensive browser-side checks)
#   https://mullvad.net/en/check      (Mullvad's own)

# Resolve the effective interface instead of assuming a historical name.
vpn_if=$(nmcli --get-values GENERAL.DEVICES --escape no \
    connection show "$proton_profile" | head -n1)
test -n "$vpn_if" && test "$vpn_if" != "--"
resolvectl status "$vpn_if"
)
```

Matching public-IP and resolver observations show only those two properties;
they do not prove the tunnel's failure behavior. Also inspect routes, the
effective interface/zone and the selected provider kill switch or NoID Privacy
WAN-strict mode, then perform the tunnel-down test below.

### Step 5 — Optional: ProtonVPN's official CLI or GUI + kill switch

This is an alternative client path with its own enforcement state, not an
extra label for the NoID Privacy inbound/LAN layers. Before installing the third-party
RPM, review Proton's current Fedora support page, release notes, provenance,
privacy terms and current vulnerability history. The release-RPM filename and
Fedora-specific signing fingerprint can rotate, so copy them from the live
official page and verify the displayed fingerprint there instead of trusting a
stale value embedded in this image:

```bash
# Open and review the maintained instructions first:
xdg-open https://protonvpn.com/support/official-linux-vpn-fedora
xdg-open https://protonvpn.com/support/linux-cli

# After following the current official release-repository step and verifying
# its Fedora-specific signing-key prompt, install the client you chose:
sudo dnf install proton-vpn-cli
# GUI alternative:
# sudo dnf install proton-vpn-gnome-desktop
```

Both clients may be installed, but Proton documents that CLI and GUI cannot run
at the same time. Pick one active client and stop the other before switching.

#### Tray icon for the GUI app

If the installed `proton-vpn-gnome-desktop` version publishes an AppIndicator,
NoID Privacy already supplies the **AppIndicator + KStatusNotifierItem Support**
GNOME Shell extension (M26 baseline), enabled by default through M17. No
additional shell extension is needed for that protocol; whether the vendor app
publishes an item remains version-dependent.

Background: GNOME Shell removed native tray-icon support years ago.
NoID Privacy baked in the AppIndicator extension because many apps still
expect tray icons (Thunderbird unread-indicator, KeePassXC
minimize-to-tray, Element/Signal notification badges, etc.) — broader
UX regression without it. Full rationale + opt-in alternatives
(Vitals, Privacy Quick Settings) + GNOME 50 autostart best-practice
2026 in [gnome-extensions-autostart.md](gnome-extensions-autostart.md).

#### GUI reconnect while the desktop session is locked

Tested with Proton VPN GTK 4.16.5: if its local-agent channel drops while
logind reports the GNOME session as locked, the app keeps scheduling retries
but defers the actual VPN reconnect until the session unlocks. The unlock
signal then schedules a new attempt. This is explicit provider behavior in the
tagged 4.16.5
[reconnector](https://github.com/ProtonVPN/proton-vpn-gtk-app/blob/v4.16.5/proton/vpn/app/gtk/services/reconnector/reconnector.py)
and
[logind session service](https://github.com/ProtonVPN/proton-vpn-gtk-app/blob/v4.16.5/proton/vpn/app/gtk/services/reconnector/login_session_service.py),
not a NoID Privacy firewall or sleep-policy decision.

Autostart, connect-at-app-start and Advanced kill switch therefore do not by
themselves promise unattended availability while the desktop remains locked.
When Proton's kill switch or NoID Privacy WAN-strict is enforcing, the safe
expected failure mode is blocked traffic until Proton reconnects. NoID Privacy
does not patch vendor Python, spoof logind's lock state, or mutate Proton-owned
NetworkManager profiles to bypass this boundary. Re-check the current
[Proton Linux release notes](https://protonvpn.com/support/release-notes-linux)
when upgrading because provider behavior can change.

#### Log in + basic usage (CLI)

The CLI binary is `protonvpn` (no hyphens), shipped by the
`proton-vpn-cli` package:

```bash
# Log in (prompts for password)
proton_account=${PROTON_ACCOUNT:?export PROTON_ACCOUNT with your Proton username}
protonvpn signin "$proton_account"

# Connect to the fastest available server
protonvpn connect

# Connect to a specific country / city / server
protonvpn connect --country US
protonvpn connect --city chicago
protonvpn connect US#1

# Disconnect
protonvpn disconnect
```

#### Enable the CLI standard kill switch

```bash
# Blocks accidental tunnel loss; see the boundary below.
protonvpn config set kill-switch standard

# Disable later (if needed)
protonvpn config set kill-switch off
```

Proton documents that `standard` blocks traffic after an accidental tunnel
loss but does **not** block when you deliberately disconnect. Do not use
`protonvpn disconnect` as proof of standard-mode protection. The GUI's
Advanced kill switch has persistent/manual-disconnect semantics; configure it
in the GUI and verify it separately. NoID Privacy WAN-strict `STRICT` is an independent
physical-egress layer with its own endpoint/profile limitations.

#### Provider-owned profile recovery

```bash
# Read-only diagnosis: record active provider profiles and service state.
nmcli connection show --active | grep -E 'pvpn-'
systemctl --no-pager --type=service --all | grep -i proton
```

If traffic remains blocked after a client change, do not guess profile names or
delete `pvpn-*` connections from a dated recipe. Reinstall/start the same
client version if necessary, disable its kill switch through its supported
UI/CLI, capture its logs, and follow the current Proton recovery/support path.
NoID Privacy does not own those profiles.

#### Uninstall

```bash
(
set -euo pipefail
# Export exactly one client package: proton-vpn-cli or
# proton-vpn-gnome-desktop.
# export PROTON_CLIENT_PACKAGE=proton-vpn-cli
proton_client=${PROTON_CLIENT_PACKAGE:?export one exact Proton client package}
case "$proton_client" in
  proton-vpn-cli|proton-vpn-gnome-desktop) ;;
  *) printf 'Unsupported package selection: %s\n' "$proton_client" >&2; false ;;
esac
sudo dnf remove "$proton_client"

# Remove the vendor repository package only after both clients are absent.
if ! rpm -q proton-vpn-cli >/dev/null 2>&1 \
   && ! rpm -q proton-vpn-gnome-desktop >/dev/null 2>&1; then
  sudo dnf remove protonvpn-stable-release
fi
)
```

References:
- Install guide: <https://protonvpn.com/support/official-linux-vpn-fedora>
- CLI usage: <https://protonvpn.com/support/linux-cli>
- Release notes: <https://protonvpn.com/support/release-notes-linux-cli>

---

## Option 2: Mullvad (WireGuard)

### Prerequisites

NoID Privacy includes both `unzip` and `wireguard-tools`; the checks below
only confirm them and recover a host where one was removed.
This documented `nmcli` import lets NetworkManager and systemd-resolved own
tunnel DNS; do not add `openresolv` here. Mullvad documents that package in its separate
[Debian `wg-quick` command-line path](https://mullvad.net/en/help/wireguard-and-mullvad-vpn),
not for a NetworkManager import.

```bash
rpm -q unzip
rpm -q wireguard-tools || sudo dnf install wireguard-tools
```

### Step 1 — Generate a WireGuard config

1. Log into <https://mullvad.net/en/account/wireguard-config>
2. Generate a keypair for this device (Mullvad gives you the public
   key to save in your account). **Generate a separate key per device**
   — Mullvad warns that reuse across devices is likely to cause connectivity
   problems.
3. The generator can add a kill switch, but Mullvad implements that option as
   wg-quick `PostUp`/`PreDown` firewall commands. A NetworkManager native
   WireGuard import has no corresponding hook setting, so do **not** count a
   successful `nmcli` import as proof that those commands were retained or
   executed. For this NetworkManager path, separately test a provider
   route/DNS kill switch or arm and verify NoID Privacy WAN-strict `STRICT`.
   If you intentionally want Mullvad's generated hook recipe, follow its
   maintained wg-quick guide as a separate path and test its resolver/firewall
   behavior.
4. Select the countries / cities you want
5. Download the ZIP of `.conf` files

Mullvad's default filename format (for example `se-mma-wg-001.conf`) contains
dashes, which are valid. Keep the interface basename within WireGuard's
15-character limit; do not remove valid dashes as generic troubleshooting.

### Step 2 — Import into NetworkManager

```bash
(
set -euo pipefail
# Export the exact downloaded ZIP and one exact member basename first.
# export MULLVAD_ZIP="$HOME/Downloads/mullvad-wireguard-configs.zip"
# export MULLVAD_CONFIG_BASENAME=se-mma-wg-001.conf
mullvad_zip=${MULLVAD_ZIP:?export MULLVAD_ZIP with the downloaded archive}
config_name=${MULLVAD_CONFIG_BASENAME:?export one exact .conf member basename}
test -f "$mullvad_zip"
test ! -L "$mullvad_zip"
[[ "$config_name" =~ ^[A-Za-z0-9_.-]+\.conf$ ]]
test "$(unzip -Z1 "$mullvad_zip" | grep -cFx -- "$config_name")" -eq 1

umask 077
config_dir="$HOME/mullvad-configs"
config_file="$config_dir/$config_name"
install -d -m 0700 "$config_dir"
test ! -e "$config_file"
test ! -L "$config_file"
candidate=$(mktemp "$config_dir/.mullvad-config.XXXXXXXX")
trap 'rm -f -- "$candidate"' EXIT
unzip -p "$mullvad_zip" "$config_name" > "$candidate"
test -s "$candidate"
chmod 0600 "$candidate"
mv -T -- "$candidate" "$config_file"
trap - EXIT

# Import only the newly extracted exact member. NetworkManager derives the
# initial connection ID from its basename.
mullvad_profile=${config_name%.conf}
if nmcli --terse --escape no --fields NAME connection show \
    | grep -qxF -- "$mullvad_profile"; then
  printf 'Connection already exists: %s\n' "$mullvad_profile" >&2
  false
fi
sudo nmcli connection import type wireguard file "$config_file"
nmcli --get-values GENERAL.NAME --escape no connection show "$mullvad_profile" \
    | grep -qxF -- "$mullvad_profile"
printf 'export MULLVAD_PROFILE=%q\n' "$mullvad_profile"
)
```

### Step 3 — DNS leak hardening (Mullvad-specific best practice)

Mullvad recommends setting a negative DNS priority so the VPN's DNS
server is used **exclusively** when the tunnel is up — preventing
system DNS queries from leaking to your LAN/ISP even momentarily:

```bash
(
set -euo pipefail
mullvad_profile=${MULLVAD_PROFILE:?export MULLVAD_PROFILE with the exact imported connection name}
nmcli --get-values GENERAL.NAME --escape no connection show "$mullvad_profile" \
    | grep -qxF -- "$mullvad_profile"
sudo nmcli connection modify "$mullvad_profile" ipv4.dns-priority -1
sudo nmcli connection modify "$mullvad_profile" ipv6.dns-priority -1

# Auto-connect
sudo nmcli connection modify "$mullvad_profile" connection.autoconnect yes

# Bring it up
sudo nmcli connection up "$mullvad_profile"
)
```

The same `connection.zone noid-vpn` command as Proton Step 3 also
applies (the NoID Privacy dispatcher enforces it automatically at up-time,
but setting explicitly is cleaner).

### Step 4 — Verify

Same as Proton Step 4 — check `curl am.i.mullvad.net/json`, `ipleak.net`,
and `browserleaks.com/ip`. Mullvad's own check page
(<https://mullvad.net/en/check>) is one provider observation; combine it with
the local route, DNS, zone and tunnel-down checks. `resolvectl status` should
show the DNS server supplied on the active Mullvad link.

### Step 5 — Mullvad's own app (alternative)

Mullvad ships an RPM for its desktop app:
<https://mullvad.net/en/download/vpn/linux>

Mullvad documents an always-on built-in kill switch plus an optional lockdown
mode in its app; verify the installed app version and the selected mode with a
tunnel-down test. If you use the app, do not activate a manual NetworkManager
tunnel at the same time — keep one routing mechanism active.

---

## Option 3: Generic WireGuard (self-hosted or a provider supplying standard configs)

Any `.conf` file following the standard WireGuard format works:

```ini
[Interface]
PrivateKey = <your private key>
Address = 10.x.x.x/32
DNS = 10.x.x.x

[Peer]
PublicKey = <server public key>
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = vpn.example.com:51820
# Optional only after an explicit NAT-idle requirement:
# PersistentKeepalive = 25
```

Save it to a private file, then supply both that exact file and the connection
name you expect NetworkManager to create:

```bash
(
set -euo pipefail
wireguard_config=${WIREGUARD_CONFIG:?export WIREGUARD_CONFIG with the exact .conf file}
wireguard_profile=${WIREGUARD_PROFILE:?export WIREGUARD_PROFILE with its expected connection name}
test -f "$wireguard_config"
test ! -L "$wireguard_config"
chmod 0600 "$wireguard_config"
if nmcli --terse --escape no --fields NAME connection show \
    | grep -qxF -- "$wireguard_profile"; then
  printf 'Connection already exists: %s\n' "$wireguard_profile" >&2
  false
fi
sudo nmcli connection import type wireguard file "$wireguard_config"
nmcli --get-values GENERAL.NAME --escape no connection show "$wireguard_profile" \
    | grep -qxF -- "$wireguard_profile"
sudo nmcli connection modify "$wireguard_profile" connection.autoconnect yes
sudo nmcli connection up "$wireguard_profile"
)
```

WireGuard's default keepalive is off. Leave it off for peers that do not need
to keep an inbound NAT mapping alive. An explicit nonzero value adds periodic
traffic, power use and an observable timing pattern; NoID Privacy does not infer user
intent from runtime `off` and does not rewrite this profile automatically.

### Important: `AllowedIPs` for full tunnel

For an all-traffic tunnel, `AllowedIPs = 0.0.0.0/0, ::/0`. If you
see split-tunnel configs (`10.0.0.0/8` only), you are NOT getting
VPN routing for public traffic — only private/internal routing. Make
sure you know which behavior you want.

---

## Option 4: OpenVPN

Some maintained providers and existing deployments use OpenVPN `.ovpn` files.
The Fedora-signed NetworkManager OpenVPN plugin and its GNOME authentication
dialog are part of the explicit M26 base contract. They remain passive until a
profile is selected and configure no provider, server or credentials by
themselves. Verify that image-owned prerequisite before importing:

> **Note**: Mullvad ended OpenVPN support on **2026-01-15** — all
> Mullvad OpenVPN servers were shut down. If you previously used
> a Mullvad `.ovpn` file, switch to **Option 2 (Mullvad WireGuard)**
> above. Reference: [Mullvad — Removing OpenVPN 15th January 2026](https://mullvad.net/en/blog/removing-openvpn-15th-january-2026).

> **Import `.ovpn` files from a terminal, not from GNOME Settings.**
> Most providers ship the certificate and key inside the `.ovpn` file. On
> import, NetworkManager writes those blocks out as separate files under the
> importing user's data directory — `~/.local/share/networkmanagement/` for a
> desktop import, `/root/.local/share/…` under `sudo`. NoID Privacy runs
> NetworkManager with `ProtectHome=yes`, so home directories do not exist
> inside its sandbox and its OpenVPN child cannot open those files. The
> connection then fails with *"Connection activation failed: Unknown reason"*,
> and only the journal names the cause:
> `--ca fails with '…': No such file or directory (errno=2)`.
>
> The block below avoids this by pointing the import at `/etc/openvpn`, which
> is outside the sandbox restriction, root-owned and already carries the
> SELinux type OpenVPN expects. Measured on this image: the same profile fails
> to activate on the default path and connects with traffic on this one. The
> GNOME Settings import has no equivalent setting, so use the terminal for
> `.ovpn` files with embedded certificates. Profiles that reference their
> certificates as separate paths outside a home directory import either way.


```bash
(
set -euo pipefail
# Native NetworkManager/OpenVPN service and GNOME authentication dialog:
rpm -q NetworkManager-openvpn NetworkManager-openvpn-gnome
openvpn_config=${OPENVPN_CONFIG:?export OPENVPN_CONFIG with the exact .ovpn file}
openvpn_profile=${OPENVPN_PROFILE:?export OPENVPN_PROFILE with its expected connection name}
test -f "$openvpn_config"
test ! -L "$openvpn_config"
chmod 0600 "$openvpn_config"
if nmcli --terse --escape no --fields NAME connection show \
    | grep -qxF -- "$openvpn_profile"; then
  printf 'Connection already exists: %s\n' "$openvpn_profile" >&2
  false
fi
# Extract embedded certificates to /etc/openvpn instead of a home directory,
# which NetworkManager's ProtectHome=yes sandbox cannot see. See the note above.
sudo install -d -m 0700 /etc/openvpn/noid-imported
sudo env XDG_DATA_HOME=/etc/openvpn/noid-imported \
    nmcli connection import type openvpn file "$openvpn_config"
sudo restorecon -RF /etc/openvpn/noid-imported
nmcli --get-values GENERAL.NAME --escape no connection show "$openvpn_profile" \
    | grep -qxF -- "$openvpn_profile"
sudo nmcli connection modify "$openvpn_profile" connection.zone noid-vpn
sudo nmcli connection modify "$openvpn_profile" connection.autoconnect yes
sudo nmcli connection up "$openvpn_profile"
)
```

OpenVPN and WireGuard have different protocol, compatibility and operational
properties. Prefer a currently maintained provider path that you can verify on
this host; do not infer actual throughput without measuring it.

---

## Stock support scope: WireGuard and OpenVPN

For NoID Privacy, “supported” means more than NetworkManager being able to
load a plugin: the profile must be covered by the documented import, DNS,
inbound-DROP zone, tunnel-down and optional WAN-strict endpoint-validation
paths. The stock image verifies that complete contract for native **WireGuard**
profiles and for OpenVPN through the included NetworkManager plugin. No OpenVPN
provider, profile, account, server or credential is preconfigured.
NetworkManager itself supports more VPN plugins, but its
[upstream inventory](https://networkmanager.dev/docs/vpn/) does not make those
paths NoID Privacy-tested.

### Not supported by the stock image: IPsec / IKEv2 / L2TP

This is not a blanket claim that modern IKEv2/IPsec is insecure. IKEv2
authenticates peers and negotiates IPsec ESP/AH security associations; the
IETF specification describes the confidentiality, integrity and
authentication properties in [RFC 7296](https://www.rfc-editor.org/rfc/rfc7296).
Do not conflate that with IKEv1: the IETF deprecated IKEv1 and its obsolete
algorithm ecosystem in
[RFC 9395](https://www.rfc-editor.org/rfc/rfc9395). Bare L2TP does not define
tunnel protection; the standards-track security profile uses IPsec, as
documented in [RFC 3193](https://www.rfc-editor.org/rfc/rfc3193).

NoID Privacy does not ship the IPsec/IKEv2 or L2TP daemon/plugin stack. Module
21 denies the loadable ESP-transform and L2TP modules because no stock workflow
needs that additional kernel and userspace surface. An owner can deliberately
replace those defaults, but that becomes an owner-maintained configuration:
the project has not verified its plugin lifecycle, DNS behavior, tunnel-down
semantics or WAN-strict endpoint schema. Unknown WAN-strict schemas fail
closed instead of being guessed.

---

## Verifying the selected tunnel-down behavior

First record which enforcement mode should decide the result:

```bash
sudo noid-wan-strict status
# For Proton CLI, also record:
protonvpn config list
```

Expected public-WAN behavior after the tunnel is down:

| Enforcing state | Deliberate disconnect | Unexpected tunnel loss |
|---|---:|---:|
| Only NoID Privacy inbound `drop` + block-lan-out | direct WAN allowed | direct WAN allowed |
| Proton CLI `standard` | direct WAN allowed by design | blocked |
| Proton GUI Advanced | blocked | blocked |
| NoID Privacy WAN-strict `STRICT` | blocked except exact VPN endpoint tuples | blocked except exact VPN endpoint tuples |

For a manual WireGuard profile, the following distinguishes the base boundary
from NoID Privacy WAN-strict. Use a controlled test destination and expect the result
shown by the table, not an unconditional failure:

```bash
(
set -euo pipefail
# Inspect first, then export the exact physical NIC and active VPN profile.
ip -br link
nmcli connection show --active
# export PHYSICAL_INTERFACE=wlp0s20f3
# export VPN_PROFILE='Proton US1'
phys=${PHYSICAL_INTERFACE:?export the exact physical interface}
vpn_profile=${VPN_PROFILE:?export the exact active VPN profile}
test -d "/sys/class/net/$phys"
nmcli --get-values GENERAL.STATE --escape no connection show "$vpn_profile" \
    | grep -q '^activated$'

restore_needed=0
restore_vpn() {
  if [ "$restore_needed" -eq 1 ]; then
    sudo nmcli connection up "$vpn_profile"
  fi
}
trap restore_vpn EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

sudo nmcli connection down "$vpn_profile"
restore_needed=1

# A route alone is not proof; bind an actual connection to the physical NIC
# and retain its exit status for comparison with the selected policy.
curl_rc=0
curl --interface "$phys" --connect-timeout 5 --max-time 10 \
    https://example.com/ -o /dev/null || curl_rc=$?
sudo nft list counters table inet noid_wan_strict
printf 'physical-interface curl exit: %s\n' "$curl_rc"

restore_vpn
restore_needed=0
trap - EXIT INT TERM
)
```

In base/grace mode, successful direct `curl` is the expected demonstration that
the inbound/LAN layers are not a killswitch. In `STRICT`, it must fail and the
WAN-block counter must increase. A failed ping alone is never sufficient proof:
the destination or ICMP path may be unavailable for unrelated reasons.

### Test 2 — DNS only via VPN

With VPN up:

```bash
(
set -euo pipefail
# Resolve the effective device for the selected active profile.
vpn_profile=${VPN_PROFILE:?export the exact active VPN profile}
vpn_if=$(nmcli --get-values GENERAL.DEVICES --escape no \
    connection show "$vpn_profile" | sed -n '1p')
test -n "$vpn_if" && test "$vpn_if" != "--"
resolvectl status "$vpn_if"
)
```

The link should show the resolver scope and DNS servers supplied for the
selected tunnel. Compare those values with the provider's current profile
rather than a historical hard-coded address.

### Test 3 — No IP leak in browser

Open Firefox, go to <https://browserleaks.com/ip>. The reported IP
must match the VPN server, not your ISP. Check also:
- WebRTC IP: should be VPN IP or nothing
- DNS server: should be VPN DNS
- IPv6: should be either VPN IPv6 or none (not your ISP's IPv6)

---

## Troubleshooting

### The VPN connects but `curl am.i.mullvad.net` shows my home IP

The interface came up but isn't the default route.

```bash
# Check the default route
ip route show default

# Should show something like: "default dev proton0 ..." or "dev wg0 ..."
# If it shows your physical interface, the VPN config is split-tunnel.
# Check the AllowedIPs in the .conf — must be 0.0.0.0/0 for full tunnel.
```

### VPN comes up but I can't reach anything

The dispatcher may not have run, or the interface isn't in the
inbound-DROP `noid-vpn` zone.

```bash
(
set -euo pipefail
# Resolve the actual active device; do not assume proton0/wg0/tun0.
vpn_profile=${VPN_PROFILE:?export the exact active VPN profile}
vpn_if=$(nmcli --get-values GENERAL.DEVICES --escape no \
    connection show "$vpn_profile" | sed -n '1p')
test -n "$vpn_if" && test "$vpn_if" != "--"

# Check firewalld zone of the VPN interface
sudo firewall-cmd --get-zone-of-interface="$vpn_if"
# Should print: noid-vpn

# If not, force it now:
sudo firewall-cmd --zone=noid-vpn --change-interface="$vpn_if"

# And persist in the NM profile:
sudo nmcli connection modify "$vpn_profile" connection.zone noid-vpn
)
```

Also check the dispatcher ran:

```bash
sudo journalctl -t noid-vpn-zone -n 20
```

### DNS works but browsing doesn't

The VPN tunnel is up, DNS goes through, but TCP connections do not. One
possible cause is block-lan-out classifying the interface as a physical/LAN
path instead of a VPN interface.

```bash
# Verify dispatcher hardened-zone enforcement
sudo grep "zone=noid-vpn" /etc/NetworkManager/dispatcher.d/50-vpn-zone-enforce

# Read the exact active skip lists for bridge/container, bond/VLAN/MACsec and
# VLAN-tagged interfaces instead of relying on a copied pattern inventory.
sudo sed -n '/^case "$IFACE" in/,/^esac/p' \
    /etc/NetworkManager/dispatcher.d/50-vpn-zone-enforce
ip -o link show | awk -F': ' '{print $2}'
```

If a native WireGuard profile was given a reserved-looking interface name such
as `br-vpn0`, rename it through NetworkManager instead of editing the
root-owned dispatcher or adding an invalid `Name=` key to `[Interface]`:

```bash
sudo nmcli connection modify "My VPN" connection.interface-name wg-vpn0
sudo nmcli connection down "My VPN"
sudo nmcli connection up "My VPN"
```

For provider-managed VPN types whose interface name is generated internally,
use the provider's supported setting or report the classification problem; do
not weaken the global skip rules around bridge/container devices.

### LAN isolation blocks local devices (block-lan-out)

The block-lan-out policy drops outbound traffic to the entire LAN (the
gateway included). To reach a specific LAN device (NAS, printer, local
server), add a per-IP exception with `noid-lan-allow`:

```bash
# Permanent exception for one device:
sudo noid-lan-allow --add 192.168.1.50 --direction outbound
# or temporary (durable deadline survives reboot):
sudo noid-lan-allow --add 192.168.1.50 --direction outbound --temp 30
sudo noid-lan-allow --list                # show active exceptions
```

See [05-lan-isolation.md](05-lan-isolation.md) for the exact exception,
expiry and revoke workflow.

### I need to switch servers frequently

Each ProtonVPN server is a separate `.conf` file. You can import
multiple and switch via:

```bash
nmcli connection show                    # list all profiles
sudo nmcli connection up "Proton NL1"     # switch to a different one
```

At every `pre-up`/`up` event, the NoID Privacy dispatcher assigns recognized
NetworkManager VPN/tunnel profiles to the hardened inbound-DROP `noid-vpn`
zone and persists that zone in the profile. It never promotes them to
firewalld's target-ACCEPT `trusted` zone.

---

## References

- **WireGuard specification**: <https://www.wireguard.com/protocol/>
- **NetworkManager dispatcher**: `man 8 NetworkManager-dispatcher`
- **ProtonVPN WireGuard docs**: <https://protonvpn.com/support/wireguard-configurations/>
- **Mullvad help center**: <https://mullvad.net/en/help>
- **TunnelVision CVE-2024-3661**: the mitigation (DHCP Option 121
  neutralized — IPv6 `ignore-auto-routes` + an IPv4 DHCP-route cleanup
  in the NM dispatcher) is already in effect — see Module 23's NetworkManager
  connection-default enforcement.

VPN_EOF

publish_doc "$VPN_DOC"
log "  [OK] 06-vpn-setup.md written"

# ------------------------------------------------------------------------------
# Phase 5 — Write gnome-extensions-autostart.md
# ------------------------------------------------------------------------------
PHASE="P5-gnome-extensions-autostart"
log "Writing gnome-extensions-autostart.md"

GNOME_EXT_DOC="$DOC_DIR/gnome-extensions-autostart.md"
DOC_TMP=$(mktemp "$DOC_DIR/.gnome-extensions-autostart.md.XXXXXXXX")
cat > "$DOC_TMP" <<'GNOME_EXT_EOF'
# GNOME 50 extensions and app autostart

NoID Privacy Workstation 44 ships GNOME 50 on Fedora 44. This guide
covers two related desktop-administration topics:

- **GNOME Shell extensions** — why NoID Privacy baked in 2, deliberately excludes
  others, and how to opt-in to more
- **App autostart** — the included NoID Privacy Welcome picker, GNOME Tweaks,
  manual XDG entries, and systemd user services

---

## Part 1 — Extensions

### Why minimal extensions on a privacy image?

GNOME Shell extensions execute JavaScript in the GNOME Shell session
context and can affect shell UI and state. Every extension you enable adds:

- **Attack surface** — additional code in a security-sensitive shell context
- **Compatibility work** — shell API changes can require extension updates
- **Runtime cost** — extension work shares the interactive shell session

NoID Privacy limits this surface to two functional extensions whose
first-install sources/packages were reviewed for the documented role. A
runtime update changes those exact bytes: signature/identity/archive checks
are supply-chain gates, not a substitute for renewed source review.

### Pre-installed: Just-Perfection (events-button hide)

- **UUID**: `just-perfection-desktop@just-perfection`
- **Version**: first-install repository pin `36`; a user-initiated M25 Update
  All run checks EGO for the running GNOME major and may transactionally
  advance a non-RPM system extension to a newer compatible version after
  identity, archive-safety, no-downgrade and post-publication checks. EGO
  supplies no artifact signature; the updater's recorded SHA-256 is local
  identity evidence, not an upstream signature or source review
- **Upstream**: <https://gitlab.gnome.org/jrahmatzadeh/just-perfection>
- **License**: GPL-3.0-only
- **Audit**: the exact pinned v36 source contained no network or telemetry
  sender; do not project that finding onto a later M25-updated version
- **Install method**: SHA-pinned first-install zip from extensions.gnome.org
  (M17 Step 2b); explicit later EGO updates are owned by M25
- **Locked dconf key**: `events-button=false` (other features stay
  user-toggleable via `dconf-editor`)
- **Unsolicited donation reminder**: disabled by the NoID Privacy dconf
  default, but not locked; opening a donation URL still requires a user action

**Why baked in**: M17 unmasked `evolution-source-registry` +
`evolution-calendar-factory` to fix gnome-shell-calendar-server cascade
log-spam. With these services running but NO calendar sources registered
(NoID Privacy default = no GOA, no local calendar, no CalDAV), the clock-menu
events widget shows "No events today" — visual clutter. Just-Perfection
hides that section while keeping the backend D-Bus chain healthy.

### Pre-installed: AppIndicator + KStatusNotifierItem Support (tray icons)

- **UUID**: `appindicatorsupport@rgcjonas.gmail.com`
- **Version**: the Fedora compose-selected RPM (updated only in a
  user-initiated `dnf`/M25 workflow)
- **Upstream**: <https://github.com/ubuntu/gnome-shell-extension-appindicator>
- **License**: GPL-2.0-only
- **Provenance**: Fedora-signed RPM
- **Install method**: RPM (M26 baseline)

**Why baked in**: some applications expose status through the
StatusNotifier/AppIndicator protocol. This extension provides the local
D-Bus/UI bridge GNOME Shell needs to display those items. Re-audit the
packaged version when its source changes.

### Deliberately excluded

#### gnome-tweaks

**Excluded from the base image because**: NoID Privacy Welcome already provides the
required app-autostart picker, while Tweaks adds a broader optional
customization surface. This is package/scope minimization, not a security
boundary.

GNOME's dconf model is explicit: a system lock takes precedence over the
user database. Tweaks can change unlocked preferences, but it **cannot bypass
a dconf lock** by writing `~/.config/dconf/user`.

**Supported opt-in**: `sudo dnf install gnome-tweaks`. GNOME Help documents
**Tweaks → Startup Applications** as a supported autostart GUI. The trade-off
is one additional package and a broader preferences UI, not loss of NoID Privacy's
locked settings.

#### gnome-extensions-app

**Excluded from the base image because** the two curated extensions work
without a separate manager. M17 locks `allow-extension-installation=false`,
so an unprivileged user cannot use the app to install new extension payloads.
The app can still manage already-installed extensions and their unlocked
preferences; `enabled-extensions` is deliberately not locked.

**Install if you want it**: `sudo dnf install gnome-extensions-app`.

### Opt-in for power users

#### Vitals (CPU/RAM/Temperature in top-bar)

- **Tradeoff**: Polls local `/proc/` and `/sys/` data frequently and adds
  always-on code to the shell process; review the exact packaged source for
  any behavior beyond that intended role
- **Better alternative on NoID Privacy**: `btop` CLI (already pre-installed) —
  runs on demand outside GNOME Shell instead of adding an always-on extension

No supported RPM command is embedded here because package availability and
GNOME Shell compatibility change independently. Check the enabled Fedora
repositories without installing anything:

```bash
dnf --cacheonly search vitals
```

This checks already downloaded Fedora metadata without creating network
traffic. A plain `dnf search vitals` may explicitly refresh configured
repositories. If no reviewed, GNOME-50-compatible Fedora package is available,
keep the on-demand `btop` path. Do not weaken the system extension-install lock
solely to follow an obsolete package recipe.

#### Privacy Quick Settings Menu

- **Tradeoff**: Its controls may overlap the GNOME Privacy panel while adding
  another extension to the shell context; compare the exact version's feature
  set before deciding
- **Better alternative on NoID Privacy**: bind a keyboard shortcut to open
  Privacy panel directly (e.g. Super+P → `gnome-control-center privacy`)

**If you want it anyway**: it is not part of NoID Privacy's Fedora-RPM baseline.
Keep the system extension-install lock in place. Prefer a reviewed,
GNOME-50-compatible Fedora package when one exists; otherwise an administrator
must review the exact source/version and choose a supported system-wide
installation method. This guide deliberately does not turn off
`/org/gnome/shell/allow-extension-installation` merely to permit a one-off
extensions.gnome.org install.

---

## Part 2 — App Autostart

GNOME Settings on this image does not expose an application-autostart control.
NoID Privacy includes its own picker in Welcome. Upstream GNOME Help also documents
**Tweaks → Startup Applications** when the optional `gnome-tweaks` package is
installed; this guide does not invent a historical GNOME version boundary.

Choose the mechanism that matches the workload and ownership:

### Method 1 — NoID Privacy Welcome → App Autostart (included GUI)

The NoID Privacy Welcome dialog ships a built-in **App Autostart** section
that handles the file-copy for you with a searchable app picker. It is the
included NoID Privacy path and requires no additional package.

```bash
# Open the dialog
noid-welcome.sh --again
```

Then in the dialog:
1. Scroll to the **App Autostart** section (between **Gaming Mode (Steam /
   Proton)** and **Security Notifications**)
2. Click "**+ Add app to autostart**"
3. Search and select your app (e.g. "Proton VPN", "KeePassXC")
4. App appears in the autostart list immediately
5. At the next eligible graphical login, the desktop entry starts unless its
   own XDG conditions suppress it

To remove an autostart entry, click the 🗑️ trash icon next to it in
the same section.

**What it does internally**: `shutil.copy2(source_desktop_path, target)` with
the packaged basename retained, plus an XDG filter (Hidden / NoDisplay /
Type=Service excluded) so only user-launchable apps appear in the picker.
Method 3 below establishes the same per-user XDG override identity but does
not promise byte-for-byte metadata equivalence. No sudo / no pkexec is needed
because autostart is per-user state.

### Method 2 — An application's explicit login-start control

Use this only when the application labels and documents the control as
**Start/Launch at login**. Do not infer autostart from a similarly named
runtime preference: for example, “open previous databases on startup” controls
what an already launched application opens; it does not start that application
at login.

Applications may implement login start with an XDG desktop entry, a systemd
user unit, or another maintained desktop mechanism. Do not assume byte or
mechanism equivalence. Verify the result after enabling it:

```bash
find ~/.config/autostart ~/.config/systemd/user \
  -maxdepth 1 -type f -print 2>/dev/null
```

### Method 3 — Manual file-copy (advanced / SSH / CLI fallback)

For headless setups, SSH sessions, or when neither Welcome dialog nor
per-app GUI is available:

```bash
# Export an exact basename from /usr/share/applications first. Example:
# export DESKTOP_ID=org.keepassxc.KeePassXC.desktop
desktop_id=${DESKTOP_ID:?export DESKTOP_ID with an exact packaged desktop basename}
source_desktop="/usr/share/applications/$desktop_id"
user_desktop="$HOME/.config/autostart/$desktop_id"
test -f "$source_desktop"
test ! -L "$source_desktop"
install -d -m 0700 "$HOME/.config/autostart"
install -m 0600 -- "$source_desktop" "$user_desktop"
```

A copied launcher is user-owned and may not inherit a later packaged launcher
change. Recheck its `Exec=` line after relevant application updates.

### Method 4 — systemd user units (background services)

For background services (NOT desktop apps) — daemons that should restart on
failure or wait for `graphical-session.target` — first place the reviewed
executable at `~/.local/bin/myservice`. The following refuses a missing,
symlinked or non-executable command and an already existing unit instead of
silently publishing a broken or overwritten service:

```bash
(
set -euo pipefail
service_exec="$HOME/.local/bin/myservice"
unit_dir="$HOME/.config/systemd/user"
unit="$unit_dir/myservice.service"
test -f "$service_exec"
test ! -L "$service_exec"
test -x "$service_exec"
install -d -m 0700 "$unit_dir"
test ! -e "$unit"
test ! -L "$unit"
stage=$(mktemp -d "$unit_dir/.myservice.XXXXXXXX")
trap 'rm -f -- "$stage/myservice.service"; rmdir -- "$stage"' EXIT
cat > "$stage/myservice.service" <<'EOF'
[Unit]
Description=My background service
After=graphical-session.target

[Service]
Type=simple
ExecStart=%h/.local/bin/myservice
Restart=on-failure

[Install]
WantedBy=graphical-session.target
EOF
chmod 0600 "$stage/myservice.service"
systemd-analyze verify "$stage/myservice.service"
mv -T -- "$stage/myservice.service" "$unit"
rmdir -- "$stage"
trap - EXIT
systemctl --user daemon-reload
systemctl --user enable --now myservice.service
systemctl --user --no-pager status myservice.service
)
```

`systemd-xdg-autostart-generator` may translate XDG autostart entries into
transient user units at session start. That implementation detail does not
make every application-owned login-start control equivalent.

### User-level versus system-wide XDG autostart

Both are supported XDG/GNOME mechanisms:

- `~/.config/autostart/` is the right scope for one user's explicit opt-in.
- `/etc/xdg/autostart/` is administrator-managed policy for every user and is
  the mechanism GNOME documents for system-wide autostart.

A system-wide entry does not inherently make GTK windows hidden. Choose scope
by ownership and intended audience. A user entry with the same desktop-file
basename takes precedence over the system entry.

### Other supported and unsupported choices

- `gnome-tweaks` **Startup Applications** is GNOME's documented optional GUI;
  NoID Privacy does not preinstall it because Welcome already covers this task.
- GNOME Settings on the shipped image has no app-autostart control; use one of
  the documented paths above.
- NoID Privacy does not use the implementation-specific
  `X-GNOME-Autostart-Phase=*` key. Standard XDG keys are sufficient for these
  application entries.

### Disabling autostart for an app

Find what's in autostart:
```bash
ls -la ~/.config/autostart/ /etc/xdg/autostart/
```

To keep an exact user entry while disabling it:
```bash
desktop_id=${DESKTOP_ID:?export DESKTOP_ID with the exact user desktop basename}
user_desktop="$HOME/.config/autostart/$desktop_id"
test -f "$user_desktop"
test ! -L "$user_desktop"
desktop-file-edit --set-key=Hidden --set-value=true "$user_desktop"
grep -qx 'Hidden=true' "$user_desktop"
```

To delete only that user-created entry instead:
```bash
desktop_id=${DESKTOP_ID:?export DESKTOP_ID with the exact user desktop basename}
user_desktop="$HOME/.config/autostart/$desktop_id"
test -f "$user_desktop"
test ! -L "$user_desktop"
rm -- "$user_desktop"
```

For a system-wide entry, create a same-basename user override with
`Hidden=true`; merely deleting a user copy exposes the system entry again.
Verify at the next graphical login using that application's documented process
or status interface rather than a generic substring-only `pgrep`.

---

## See also

- [06-vpn-setup.md](06-vpn-setup.md) — ProtonVPN-specific autostart guidance
- [26-optional-packages.md](26-optional-packages.md) — what else is/isn't pre-installed
- [GNOME Help: start applications automatically](https://help.gnome.org/gnome-help/shell-apps-auto-start.html)
- [GNOME administration: dconf lockdown](https://help.gnome.org/system-admin-guide/dconf-lockdown.html)
- [GNOME administration: system-wide autostart](https://help.gnome.org/system-admin-guide/autostart-applications.html)
GNOME_EXT_EOF

publish_doc "$GNOME_EXT_DOC"
log "  [OK] gnome-extensions-autostart.md written"

# ------------------------------------------------------------------------------
# Phase 6 — Verification
# ------------------------------------------------------------------------------
PHASE="P6-verify"
log "Running verification"

checks=0
fails=0

check() {
    local desc=$1
    shift
    checks=$((checks + 1))
    if "$@" >/dev/null 2>&1; then
        log "  [OK] $desc"
    else
        fails=$((fails + 1))
        log "  [FAIL] $desc"
    fi
}

# ---- 00-README.md ----
check "00-README.md exists" test -f "$README_DOC"

readme_size=$(stat -c %s "$README_DOC" 2>/dev/null || echo 0)
readme_size=${readme_size:-0}
check "00-README.md > 4KB (actual: ${readme_size} bytes)" \
    test "$readme_size" -gt 4096

# Structure: master index must reference the Tier-A + major Modules docs.
# Keyword checks: case-insensitive grep -qi DIRECTLY on the deployed file
# (Lesson #30). Two failure classes occur ONLY inside the Anaconda %post
# bash: strict-case grep dropped matches despite byte-identical content,
# and the echo-bash-variable pipeline dropped matches even with -qi —
# direct-file grep (the M99 cross-check form) is the reliable variant.
for kw in "01-getting-started.md" "06-vpn-setup.md" "22-disk-encryption.md" "noid-status" "noid-welcome.sh" "Task-based reference" "CLI tools"; do
    if grep -qiF -- "$kw" /usr/share/doc/noid-privacy/00-README.md 2>/dev/null; then
        checks=$((checks + 1))
        log "  [OK] 00-README.md references: $kw"
    else
        checks=$((checks + 1))
        fails=$((fails + 1))
        log "  [FAIL] 00-README.md missing: $kw"
    fi
done

# ---- 01-getting-started.md ----
check "01-getting-started.md exists" test -f "$GETSTART_DOC"

getstart_size=$(stat -c %s "$GETSTART_DOC" 2>/dev/null || echo 0)
getstart_size=${getstart_size:-0}
check "01-getting-started.md > 4KB (actual: ${getstart_size} bytes)" \
    test "$getstart_size" -gt 4096

# Structure: triage + key commands
# Direct-file fixed-string grep (see 00-README block above for rationale).
for kw in "CRITICAL" "IMPORTANT" "RECOMMENDED" "luksHeaderBackup" "06-vpn-setup" "noid-status" "noid-update-all.sh" "noid-welcome.sh"; do
    if grep -qiF -- "$kw" /usr/share/doc/noid-privacy/01-getting-started.md 2>/dev/null; then
        checks=$((checks + 1))
        log "  [OK] 01-getting-started.md references: $kw"
    else
        checks=$((checks + 1))
        fails=$((fails + 1))
        log "  [FAIL] 01-getting-started.md missing: $kw"
    fi
done

# ---- 06-vpn-setup.md ----
check "06-vpn-setup.md exists" test -f "$VPN_DOC"

vpn_size=$(stat -c %s "$VPN_DOC" 2>/dev/null || echo 0)
vpn_size=${vpn_size:-0}
check "06-vpn-setup.md > 6KB (actual: ${vpn_size} bytes)" \
    test "$vpn_size" -gt 6144

# Structure: 4 provider options + killswitch verification + troubleshooting.
# Direct-file fixed-string grep + -qiF (see 00-README block above — both failure classes
# hit THIS doc's keywords first: "Mullvad" case, "killswitch" pipeline).
for kw in "ProtonVPN" "Mullvad" "Generic WireGuard" "OpenVPN" "nmcli connection import" "TunnelVision" "Troubleshooting" "killswitch" "noid-vpn" "am.i.mullvad.net"; do
    if grep -qiF -- "$kw" /usr/share/doc/noid-privacy/06-vpn-setup.md 2>/dev/null; then
        checks=$((checks + 1))
        log "  [OK] 06-vpn-setup.md references: $kw"
    else
        checks=$((checks + 1))
        fails=$((fails + 1))
        log "  [FAIL] 06-vpn-setup.md missing: $kw"
    fi
done

# ---- gnome-extensions-autostart.md ----
check "gnome-extensions-autostart.md exists" test -f "$GNOME_EXT_DOC"

gnomeext_size=$(stat -c %s "$GNOME_EXT_DOC" 2>/dev/null || echo 0)
gnomeext_size=${gnomeext_size:-0}
check "gnome-extensions-autostart.md > 4KB (actual: ${gnomeext_size} bytes)" \
    test "$gnomeext_size" -gt 4096

# Structure: 2 pre-installed extensions + autostart best-practice methods + opt-in alternatives
# Direct-file fixed-string grep (see 00-README block above for rationale).
# shellcheck disable=SC2088  # literal Markdown keyword, not a shell path
for kw in "Just-Perfection" "AppIndicator" "gnome-tweaks" "Vitals" "Autostart" "~/.config/autostart" "systemd user units" "system-wide XDG autostart" "it **cannot bypass" "a dconf lock** by writing"; do
    if grep -qiF -- "$kw" /usr/share/doc/noid-privacy/gnome-extensions-autostart.md 2>/dev/null; then
        checks=$((checks + 1))
        log "  [OK] gnome-extensions-autostart.md references: $kw"
    else
        checks=$((checks + 1))
        fails=$((fails + 1))
        log "  [FAIL] gnome-extensions-autostart.md missing: $kw"
    fi
done

# ---- Permissions and direct-payload ownership ----
rpm_query_ok=0
if rpm -qa >/dev/null 2>&1; then
    rpm_query_ok=1
fi
check "RPM database is queryable for documentation ownership" \
    test "$rpm_query_ok" -eq 1

rpm_path_unowned() {
    [ "$rpm_query_ok" -eq 1 ] \
        && ! rpm -qf -- "$1" >/dev/null 2>&1
}
for doc in 00-README.md 01-getting-started.md 06-vpn-setup.md gnome-extensions-autostart.md; do
    doc_path="$DOC_DIR/$doc"
    check "$doc is not a symlink" test ! -L "$doc_path"
    doc_meta=$(stat -c '%u:%g:%a:%h' "$doc_path" 2>/dev/null || true)
    check "$doc metadata root:root 0644, one link (actual: ${doc_meta:-missing})" \
        test "$doc_meta" = "0:0:644:1"
    check "$doc is a direct Module 29 payload without an RPM owner" \
        rpm_path_unowned "$doc_path"
done

log "Verification: $((checks - fails))/$checks passed"
if [ "$fails" -gt 0 ]; then
    die "$fails verification check(s) FAILED"
fi

# ------------------------------------------------------------------------------
# Phase 7 — Publish health stamp
# ------------------------------------------------------------------------------
# The stamp lets 99-finalize verify module success via one machine-parseable
# file instead of duplicating Phase-6 checks.
PHASE="P7-stamp"
# M29_HEALTH_PUBLICATION_BEGIN
if [ ! -d "$STAMP_DIR" ] || [ -L "$STAMP_DIR" ] \
   || [ "$(stat -Lc '%u:%g:%a' -- "$STAMP_DIR" 2>/dev/null || true)" != \
        0:0:755 ] \
   || ! matchpathcon -V "$STAMP_DIR" >/dev/null; then
    die "shared health-stamp directory drifted before Module 29 publication"
fi

verify_m29_health_stamp() {
    local path="$1"
    [ -f "$path" ] \
        && [ ! -L "$path" ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' -- "$path" 2>/dev/null || true)" = \
            0:0:644:1 ] \
        && [ "$(wc -l < "$path")" -eq 10 ] \
        && [ "$(grep -c '^module=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^name=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^version=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^status=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^timestamp=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^checks_passed=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^checks_total=' "$path" || true)" -eq 1 ] \
        && grep -qFx '# NoID Privacy — Module 29 Health Stamp' "$path" \
        && grep -qFx \
            '# Written at end of %post verification when all checks pass.' \
            "$path" \
        && grep -qFx \
            '# Format: shell-sourceable key=value. See docs/engineering-health-stamp-pattern.md.' \
            "$path" \
        && grep -qFx 'module=29' "$path" \
        && grep -qFx 'name=user-docs' "$path" \
        && grep -qFx 'version=1' "$path" \
        && grep -qFx 'status=ok' "$path" \
        && grep -Eq \
            '^timestamp=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' \
            "$path" \
        && grep -qFx "checks_passed=$((checks - fails))" "$path" \
        && grep -qFx "checks_total=$checks" "$path"
}

STAMP_TMP=$(mktemp "$STAMP_DIR/.stamp-29-user-docs.ok.XXXXXXXX")
cat > "$STAMP_TMP" <<STAMP_EOF
# NoID Privacy — Module 29 Health Stamp
# Written at end of %post verification when all checks pass.
# Format: shell-sourceable key=value. See docs/engineering-health-stamp-pattern.md.
module=29
name=user-docs
version=1
status=ok
timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
checks_passed=$((checks - fails))
checks_total=$checks
STAMP_EOF

chmod 0644 "$STAMP_TMP"
chown root:root "$STAMP_TMP"
restorecon -F -- "$STAMP_TMP" \
    || die "cannot label Module 29 health-stamp candidate"
matchpathcon -V "$STAMP_TMP" >/dev/null \
    || die "Module 29 health-stamp candidate label differs"
verify_m29_health_stamp "$STAMP_TMP" \
    || die "staged Module 29 health-stamp contract is invalid"
sync -- "$STAMP_TMP" \
    || die "cannot sync Module 29 health-stamp candidate"
if ! mv -fT -- "$STAMP_TMP" "$STAMP"; then
    rm -f -- "$STAMP" || true
    die "cannot publish Module 29 health stamp"
fi
STAMP_TMP=""
STAMP_PUBLICATION_ACTIVE=1
restorecon -F -- "$STAMP" \
    || die "cannot label published Module 29 health stamp"
matchpathcon -V "$STAMP" >/dev/null \
    || die "published Module 29 health-stamp label differs"
sync -- "$STAMP" \
    || die "cannot sync published Module 29 health stamp"
sync -- "$STAMP_DIR" \
    || die "cannot sync Module 29 health-stamp directory"
verify_m29_health_stamp "$STAMP" \
    || die "published Module 29 health-stamp contract is invalid"
STAMP_PUBLICATION_ACTIVE=0
log "  [OK] exact Module 29 health stamp published atomically"
# M29_HEALTH_PUBLICATION_END

trap - EXIT
log "=== Module 29 User Documentation complete ==="
%end

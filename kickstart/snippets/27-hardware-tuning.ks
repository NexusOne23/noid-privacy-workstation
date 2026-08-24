# ============================================================================
# Module 27 — Hardware Abstraction
# Status: LOCKED 2026-08-11 (v49) — keep thermal applicability Fedora/upstream-owned.
#
# Covers:
#   STEP 1    Fedora/kernel-owned I/O scheduler policy; remove the retired
#             NoID Privacy per-device override
#   STEP 1c   NIC Wake-on-LAN disable via systemd .link; EEE stays with the
#             Fedora/systemd/driver stack
#             (PCI/USB bus-backed Ethernet only — see scope note below)
#   STEP 1.5  Platform suspend-mode ownership — kernel/firmware default;
#             no chassis-wide command-line override
#   STEP 1.5b CPU boost/governor ownership stays with kernel + tuned; remove
#             the retired unconditional Intel HWP dynamic-boost override
#   STEP 2    earlyoom config + enable (replaces M08-masked systemd-oomd)
#   STEP 2b   tuned + tuned-ppd enable (F44 default PowerProfiles backend);
#             neutralize the invalid built-in-governor module reload
#   STEP 2c   Upstream thermald hardware applicability (intel_lpmd unit is
#             M08-masked under the single-EPP-writer policy)
#   STEP 3    Fedora zram-generator-defaults policy; remove retired NoID Privacy
#             compression/priority overrides
#   STEP 3b   noexec UDisks mounts for USB storage and recognized SD media;
#             external NTFS prefers ntfs3 with ntfs-3g fallback
#   STEP 4    SELinux restorecon + matchpathcon verification
#   STEP 5    verification (native udev/.link parsing + exact artifacts;
#             hardware behavior is a mandatory three-pass pre-ship gate)
#
# Build-vs-target constraint:
#   The Anaconda build chroot is a qemu VM and cannot prove target-hardware
#   behavior. M27 therefore leaves thermal and Intel active-idle applicability
#   to the Fedora/upstream daemons' maintained runtime probes. Declarative
#   mechanisms that do belong to NoID Privacy still bake cleanly into the
#   squashfs (STEP 1c .link and STEP 3b UDisks mount override).
#
# Deliberate deviations / constraint notes:
#   - STEP 1c WoL scope is a whitelist: [Match] Type=ether + Path=pci-* usb-*.
#     Excludes WLAN (Type=wlan), WireGuard (link/none), the VPN-killswitch
#     dummy (IS ether but has no ID_PATH — the trap Path= closes), bridges/
#     veth/tun and platform-bus Ethernet. systemd 259's .link EEE setter uses
#     the legacy 32-bit ethtool ioctl; modern link modes above bit 32 are not
#     representable and make the kernel warn on otherwise healthy hardware.
#     NoID Privacy therefore makes no unbenchmarked global EEE choice and
#     leaves EEE with Fedora, the driver and the link partner. systemd-udevd
#     applies the remaining Wake-on-LAN .link
#     during link setup, before normal NetworkManager management; this does
#     not claim anything about the hardware state before udev sees the link.
#     The runtime gate requires every driver-visible WoL state to be `d`.
#     A driver such as virtio_net that implements neither get_wol nor set_wol
#     is recorded as unsupported (N/A), after the effective .link winner is
#     proven. The reference e1000e device exposes WoL and verifies `d`.
#   - STEP 3b uses UDisks' maintained per-device mount override. A blanket
#     `sync` default is deliberately absent: physical VFAT/exFAT/NTFS/ext4
#     testing showed a severe latency/throughput cost, while mount(8) says it
#     may also shorten limited-write media life. Filesystem-specific UDisks
#     defaults still merge in (including `flush` for vfat). `noexec` blocks
#     direct native execution from dynamically mounted USB/SD
#     media, including media behind an already-authorized reader. It does not
#     stop an interpreter from reading a script (`bash media/script.sh`).
#     This is a UDisks default rather than an authorization boundary: an
#     explicit UDisks caller may request the upstream-allowed `exec` option,
#     and administrator-owned fstab/direct mounts remain outside the override.
#     It does not promise safe removal during active I/O; GNOME/UDisks
#     eject or power-off remains required to flush in-flight data and device
#     caches. For external NTFS only, the same udev-scoped UDisks interface
#     restores upstream's `ntfs3,ntfs` driver order: Fedora 44 reverses that
#     order, but its current ntfs-3g RW path fails on the tested clean volume
#     while Fedora's in-tree ntfs3 succeeds. ntfs-3g remains the fallback.
#     NoID Privacy does not own the administrator's global
#     /etc/udisks2/mount_options.conf.
#     The retired rule wrote `write through` to queue/write_cache. Kernel ABI
#     documentation says that changes only the kernel's view, not the device,
#     and may suppress necessary cache flushes, so it is fail-closed absent.
#   - STEP 2c leaves hardware applicability to thermald's maintained probe.
#     Upstream thermald explicitly blocklists Lenovo's dytc_lapmode path to
#     avoid competing with in-firmware thermal management; its adaptive
#     compatibility path exits successfully and the enabled unit remains
#     inactive. ConditionVirtualization=no can also make the enabled unit
#     legitimately inactive. Neither case is active thermald protection.
#     intel_lpmd.service is M08-masked under the single-EPP-writer policy —
#     the package ships, the unit does not run.
#   - STEP 1/1.5b/3 deliberately do not select a universal scheduler,
#     Intel-only boost value, compression algorithm or swap priority. Those
#     choices are device/workload dependent. Fedora/kernel/tuned remain the
#     maintained owners; old NoID Privacy overrides are removed on upgrade.
#   - Fedora 44 builds cpufreq_conservative into the kernel, but TuneD's
#     generic balanced profile still requests a module remove/reinsert and
#     logs an error. Before disabling the inherited modules plug-in, compose
#     proves the Fedora profile's sole modules entry is that reload and every
#     installed kernel builds the governor in. GNOME's three standard Power
#     Mode names remain unchanged.
#   - REJECTED: chassis-aware auto-profile-setting (firstboot
#     powerprofilesctl heuristic) — profile selection stays user-driven
#     via the GNOME UI; only the daemon ships. Do not re-propose.
#   - REMOVED: the Comet Lake cAVS audio workaround (modprobe
#     blacklist + dracut hook + firstboot detect/remove service). The
#     snd_soc_avs NHLT-stub NULL-deref class is fixed in the kernel 7.0.x
#     line (stub-aware iterator); removal also restored the SOF/AVS DSP
#     path. Do not re-add — history in git.
#   - M02 intentionally carries no generic performance profile. M27 adds no
#     custom BBR/qdisc/socket-buffer/read-ahead/governor value. GNOME's
#     tuned-backed Power Mode is the supported user-selected profile surface:
#     Fedora's `powersave` and server-oriented `throughput-performance`
#     profiles retain all of their upstream behavior, including the latter's
#     VM, network and read-ahead tuning when the user selects Performance.
#
# Cross-Module:
#   - Module 08: systemd-oomd masked -> earlyoom replaces it here
#   - Module 02: security/privacy sysctls only; no NoID Privacy VM/network tuning
#   - Module 01: rejects retired chassis-wide backlight/sleep arguments
#   - Module 21: no M27 scheduler or performance setting is embedded in the
#     initramfs; M27 owns no Dracut/BLS writer
#   - Module 23: NetworkManager leaves Wake-on-LAN unmanaged (`ignore`) so
#                this pre-NetworkManager device policy remains authoritative;
#                an explicit per-connection value is the supported opt-in.
#   - Module 13: AIDE tracks /etc/udev/rules.d NORMAL
# ============================================================================

# ---------------------------------------------------------------------------
# Packages
# ---------------------------------------------------------------------------
%packages --exclude-weakdeps
earlyoom
# tuned + tuned-ppd explicit: --exclude-weakdeps strips them from the
# @workstation-product-environment Recommends chain; without them no
# PowerProfiles D-Bus service exists and the GNOME Power Mode toggle
# disappears (kernel HWP/EPP still works autonomously). See STEP 2b.
tuned
tuned-ppd
# thermald: Fedora-packaged, upstream runtime-conditional userspace thermal
# management. Blocklisted platforms exit cleanly without a failed unit; STEP
# 2c leaves hardware applicability entirely with the packaged daemon.
# Kernel/firmware thermal protections remain independent of this daemon.
# intel-lpmd: package intentionally installed, but its unit is M08-masked
# (single-EPP-writer policy — tuned/tuned-ppd is the one power/EPP backend).
thermald
intel-lpmd
# Explicitly retain Fedora's packaged zram policy. M27 does not replace its
# size, compression or priority values.
zram-generator-defaults
# Maintained dynamic-mount and safe-power-off backend for STEP 3b.
udisks2
%end

# ---------------------------------------------------------------------------
# %post — Module 27 hardware-aware configuration
# ---------------------------------------------------------------------------
%post --erroronfail --log=/var/log/ks-27-hardware-tuning.log
set -euo pipefail

log() { echo "[noid-27-hardware] $*"; }
log "=== Module 27 post-install: hardware abstraction ==="

REQUIRED_PACKAGES=(
    earlyoom
    tuned
    tuned-ppd
    thermald
    intel-lpmd
    zram-generator-defaults
    udisks2
)

# ====================================================================
# STEP 1: I/O scheduler policy — Fedora/kernel owned
# ====================================================================
# Scheduler trade-offs depend on controller queues, latency/throughput goals,
# cgroup fairness, kernel and workload. Fedora 44 already ships the maintained
# systemd-udev rule at /usr/lib/udev/rules.d/60-block-scheduler.rules and each
# block driver exposes its supported set. A distro-wide NoID Privacy override would
# freeze an unbenchmarked hardware bet and can override Fedora's later fixes.
log "STEP 1: retaining Fedora/kernel I/O scheduler policy"
rm -f /etc/udev/rules.d/60-noid-iosched.rules
log "  [OK] retired NoID Privacy scheduler override absent"

# NOTE: USB/SD dynamic-mount defaults live in STEP 3b below. The retired
# queue/write_cache rule is removed there because it could suppress real
# device-cache flushes without changing the device.

# ====================================================================
# STEP 1c: NIC Wake-on-LAN disable; Fedora/driver-owned EEE
# ====================================================================
# Method: native systemd .link [Link] WakeOnLan=off
# (systemd v258+; F44 ships v259), applied by systemd-udevd during link setup
# before normal NetworkManager management. This is manager-independent and
# declarative (no Lesson-#16 build-vs-target problem).
# A matching custom .link wins before Fedora's 99-default.link, so it must
# carry the vendor naming/MAC policies too. Omitting them leaves a PCI NIC at
# its kernel ethN name and can strand installer-created NetworkManager and
# firewalld state under the earlier predictable name.
#
# SCOPE = PCI/USB bus-backed Ethernet ONLY (whitelist, fits default-deny):
#   Type=ether        -> excludes WLAN (Type=wlan) / WWAN
#   Path=pci-* usb-*  -> selected bus paths only; excludes WireGuard (link/none),
#                        the VPN-killswitch dummy (IS ether but no ID_PATH —
#                        the trap Path= closes), bridges/veth/tun and
#                        platform-bus Ethernet. PCI virtual NICs can match.
# Energy-Efficient Ethernet deliberately remains untouched. systemd 259 reads
# and writes .link EEE through ETHTOOL_GEEE/ETHTOOL_SEEE, whose legacy ABI can
# carry only the first 32 link-mode bits. On current Realtek hardware this
# makes the kernel warn twice during boot even though the link is functional.
# A distro-wide EEE override was only a speculative stability preference, not
# a security/privacy boundary or a hardware-proven fix.
# Source contract: systemd.link(5).

log "STEP 1c: writing /etc/systemd/network/10-noid-no-wol.link (WoL off; EEE vendor-owned)"

mkdir -p /etc/systemd/network
rm -f /etc/systemd/network/10-noid-no-eee.link
cat > /etc/systemd/network/10-noid-no-wol.link <<'WOL_LINK_EOF'
# NoID Privacy — disable Wake-on-LAN on PCI/USB Ethernet (Module 27)
#
# SCOPE: PCI/USB bus-backed Ethernet only. Type=ether excludes WLAN/WWAN;
# Path=pci-*|usb-* selects those bus paths and excludes VPN tunnels
# (WireGuard = link/none; VPN-killswitch dummy = ether but no ID_PATH),
# bridges, veth, tun and platform-bus Ethernet. PCI virtual NICs can match.
# Whitelist, not blacklist.
[Match]
Type=ether
Path=pci-* usb-*

[Link]
# Preserve Fedora systemd-udev's 99-default.link behavior. The compose and
# candidate runtime gates compare these values with the installed vendor file
# so a future Fedora policy change becomes release-visible.
NamePolicy=keep kernel database onboard slot path
AlternativeNamesPolicy=database onboard slot path mac
MACAddressPolicy=persistent
# systemd.link(5) defines `off` as disabling every Wake-on-LAN mode. Module
# 23's NetworkManager default is `ignore`, which deliberately leaves this
# earlier systemd-udevd device state unchanged. An explicit per-connection
# NetworkManager WoL value remains the administrator opt-in.
WakeOnLan=off
WOL_LINK_EOF

chmod 644 /etc/systemd/network/10-noid-no-wol.link
chown root:root /etc/systemd/network/10-noid-no-wol.link
log "  [OK] WoL-disable .link written; EEE remains vendor-owned"

# ====================================================================
# STEP 1.5: Platform suspend-mode selection — VENDOR OWNED
# ====================================================================
# Chassis type alone cannot select a reliable sleep state. The kernel already
# chooses among the platform-supported s2idle/deep states using firmware/ACPI
# information and maintained quirks. M01 removes and rejects the former global
# `mem_sleep_default=s2idle` override. A future exception must be model-specific
# and retain suspend/resume, wake-source and overnight battery-drain evidence.
log "STEP 1.5: kernel/firmware owns platform suspend mode (no global override)"

# ====================================================================
# STEP 1.5b: CPU performance policy — kernel + tuned owned
# ====================================================================
# Dynamic boost, EPP and governor choices change power, temperature, acoustic
# and performance behavior. Fedora's tuned/tuned-ppd stack already provides a
# user-selected, hardware-aware Power Mode. M27 does not silently add a second
# CPU-policy writer or advertise an unretained battery/performance result.
log "STEP 1.5b: retaining kernel/tuned CPU performance ownership"
rm -f /etc/tmpfiles.d/noid-hwp-dynamic-boost.conf
log "  [OK] retired NoID Privacy HWP dynamic-boost override absent"

# ====================================================================
# STEP 2: earlyoom configuration
# ====================================================================
# earlyoom replaces masked systemd-oomd (Module 08) with process-level
# low-memory handling. This is an explicit image policy, not a claim that one
# OOM mechanism is universally faster or more correct for every workload.
#
# -m 5 / -s 5: trigger only when both available memory and free swap (when
#               present) fall below 5%; zram counts as swap
# -r 3600: retain one hourly health sample; monitoring cadence is unchanged
# --prefer: add 300 to matching browser-process oom_score values
# --avoid: subtract 300 from matching critical-process oom_score values
# These are soft selection biases, not ordering guarantees or immunity.
#
# The compatibility choice is process-level selection rather than
# systemd-oomd's cgroup-level selection. Runtime tests pin the exact argv.

log "STEP 2: writing /etc/default/earlyoom"

cat > /etc/default/earlyoom <<'EARLYOOM_EOF'
# NoID Privacy — earlyoom config (Module 27)
# Replaces masked systemd-oomd (Module 08).
#
# -r 3600 retains one hourly health sample without filling the persistent
# journal. It changes reporting only; monitoring and low-memory handling keep
# their adaptive polling cadence.
#
# earlyoom acts only when both the memory and swap thresholds are crossed.
# `--prefer` and `--avoid` adjust a matching process's oom_score by +300 and
# -300 respectively; neither is a hard kill order or immunity rule. Linux
# comm names are limited to 15 bytes, hence the two truncated Firefox Fission
# process names below.
#
# Note: the single quotes around each regex are
# REQUIRED — they're literal in the EnvironmentFile= value (per systemd
# documentation: outer double quotes around the value are stripped, inner
# quotes are kept verbatim). When ExecStart= expands $EARLYOOM_ARGS, systemd's
# tokenizer DOES respect the inner single quotes as quote-protectors per
# systemd.exec(5) "Environment"/"EnvironmentFile" + "Variable expansion"
# sections. So `--prefer '^(Web Content|...)'` becomes ONE arg with the literal
# regex `^(Web Content|...)` — the embedded space inside the regex is preserved.
# Verification must read the running process's NUL-delimited argv; `systemctl
# show ... ExecStart` reports only the unexpanded unit declaration:
# `sudo cat /proc/"$(systemctl show earlyoom -p MainPID --value)"/cmdline |
# tr '\0' '\n'` prints each argument on its own line.
EARLYOOM_ARGS="-m 5 -s 5 -r 3600 --prefer '^(Web Content|Isolated Web Co|Privileged Cont|firefox|chromium|chrome)' --avoid '^(systemd|Xwayland|pipewire|gnome-shell|gdm)'"
EARLYOOM_EOF

chmod 644 /etc/default/earlyoom
chown root:root /etc/default/earlyoom

# Enable earlyoom (error-capture to log instead of silent `|| true` —
# verify 5.2 catches a missing symlink anyway, the message aids diagnosis).
if systemctl --root=/ is-enabled earlyoom.service >/dev/null 2>&1; then
    log "  [OK] earlyoom.service already enabled (Fedora preset)"
elif systemctl --root=/ enable earlyoom.service 2>&1 | tee -a /var/log/ks-27-hardware-tuning.log; then
    log "  [OK] earlyoom configured + enabled"
else
    log "  [WARN] earlyoom.service enable returned non-zero — verify post-boot via:"
    log "         systemctl status earlyoom.service && systemctl cat earlyoom.service"
fi

# ====================================================================
# STEP 2b: tuned + tuned-ppd enable
# ====================================================================
# F44's default power-profile stack (TunedReplacesPower-profiles-daemon
# since F41). Shipped explicitly in %packages above because
# --exclude-weakdeps strips them from the @workstation Recommends chain.
# tuned.service applies profiles locally; tuned-ppd.service is the D-Bus
# shim (net.hadess.PowerProfiles + org.freedesktop.UPower.PowerProfiles)
# that GNOME Settings -> Power Mode talks to. Fedora's signed tuned-ppd
# configuration maps Power Saver to `powersave`, Balanced to `balanced`
# (`balanced-battery` on battery), and Performance to the server-oriented
# `throughput-performance` profile. The two Balanced mappings alone are
# redirected to the child profiles below. tuned-ppd has no drop-in merge for
# this map, so M27 must replace the complete package-owned file. Validate its
# semantic Fedora baseline first; otherwise a package update could add a key
# that a stale NoID Privacy copy would silently discard.
# Fedora builds cpufreq_conservative into its kernel, so TuneD's generic
# balanced profile cannot remove/reinsert it as a module. Red Hat's documented
# child-profile mechanism disables the inherited modules plug-in only after
# compose proves its sole Fedora entry is that invalid reload and the installed
# kernels build the governor in. Governor, EPP, boost, ACPI platform and device
# policy remain inherited.
# Ships ONLY the daemon — chassis-aware auto-profile-setting stays
# REJECTED (profile selection is user-driven via the GNOME UI).
log "STEP 2b: installing valid Balanced child profiles and enabling tuned services"
TUNED_VENDOR_PPD=/etc/tuned/ppd.conf
# Fedora 44 tuned-ppd 2.27.0-1.fc44 ships the same 249-byte mapping as
# upstream TuneD v2.27.0. Query the RPM payload digest rather than hashing the
# live config so an exact prior NoID Privacy application remains idempotent
# while a changed package baseline still fails closed.
TUNED_VENDOR_PPD_PAYLOAD=249:9c0ef6b27a67b5dd3b4d02f521730b8d2570c33d5df198a97d12c10b91e48111
tuned_vendor_ppd_payload=$(
    rpm -q --qf '[%{FILENAMES}\t%{FILESIZES}\t%{FILEDIGESTS}\n]' tuned-ppd \
        2>/dev/null | awk -F '\t' \
        '$1 == "/etc/tuned/ppd.conf" { print $2 ":" $3; found = 1 }
         END { if (!found) exit 1 }' || true
)
vendor_ppd_contract=$(
    sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' \
        "$TUNED_VENDOR_PPD" 2>/dev/null || true
)
expected_vendor_ppd_contract=$(
    cat <<'NOID_TUNED_VENDOR_PPD_CONTRACT_EOF'
[main]
default=balanced
battery_detection=true
sysfs_acpi_monitor=true
[profiles]
power-saver=powersave
balanced=balanced
performance=throughput-performance
[battery]
balanced=balanced-battery
NOID_TUNED_VENDOR_PPD_CONTRACT_EOF
)
expected_noid_ppd_contract=$(
    cat <<'NOID_TUNED_CURRENT_PPD_CONTRACT_EOF'
[main]
default=balanced
battery_detection=true
sysfs_acpi_monitor=true
[profiles]
power-saver=powersave
balanced=noid-balanced
performance=throughput-performance
[battery]
balanced=noid-balanced-battery
NOID_TUNED_CURRENT_PPD_CONTRACT_EOF
)
if [ ! -f "$TUNED_VENDOR_PPD" ] || [ -L "$TUNED_VENDOR_PPD" ] || \
   [ "$(stat -Lc '%u:%g:%a:%h' "$TUNED_VENDOR_PPD" 2>/dev/null || true)" != 0:0:644:1 ] || \
   [ "$(rpm -qf --qf '%{NAME}' "$TUNED_VENDOR_PPD" 2>/dev/null || true)" != tuned-ppd ] || \
   [ "$tuned_vendor_ppd_payload" != "$TUNED_VENDOR_PPD_PAYLOAD" ] || \
   { [ "$vendor_ppd_contract" != "$expected_vendor_ppd_contract" ] && \
     [ "$vendor_ppd_contract" != "$expected_noid_ppd_contract" ]; }; then
    log "  [FAIL] Fedora tuned-ppd mapping contract drifted; refusing a stale full-file replacement"
    exit 1
fi
log "  [OK] Fedora tuned-ppd payload exact; existing map is vendor or current NoID Privacy"
install -d -m 0755 \
    /etc/tuned/profiles/noid-balanced \
    /etc/tuned/profiles/noid-balanced-battery
cat > /etc/tuned/profiles/noid-balanced/tuned.conf <<'NOID_TUNED_BALANCED_EOF'
# NoID Privacy — retain Fedora's Balanced policy while disabling the
# inapplicable cpufreq_conservative module reload. Fedora 44 builds that
# governor into the kernel, so it cannot be removed/reinserted as a module.
[main]
summary=Fedora Balanced without the inapplicable built-in governor reload
include=balanced

[modules]
enabled=0
NOID_TUNED_BALANCED_EOF
cat > /etc/tuned/profiles/noid-balanced-battery/tuned.conf <<'NOID_TUNED_BATTERY_EOF'
# NoID Privacy — battery counterpart to noid-balanced. All Fedora
# balanced-battery policy remains inherited; only the inherited invalid
# cpufreq_conservative module reload is disabled.
[main]
summary=Fedora Balanced Battery without the inapplicable built-in governor reload
include=balanced-battery

[modules]
enabled=0
NOID_TUNED_BATTERY_EOF
cat > /etc/tuned/ppd.conf <<'NOID_TUNED_PPD_EOF'
[main]
# Keep GNOME's three standard Power Mode choices. Only the Balanced mappings
# use NoID Privacy child profiles that neutralize Fedora's invalid built-in-module
# reload; CPU policy remains owned by TuneD.
default=balanced
battery_detection=true
sysfs_acpi_monitor=true

[profiles]
# PPD = TuneD
power-saver=powersave
balanced=noid-balanced
performance=throughput-performance

[battery]
# PPD = TuneD
balanced=noid-balanced-battery
NOID_TUNED_PPD_EOF
cat > /etc/tuned/recommend.conf <<'NOID_TUNED_RECOMMEND_EOF'
# NoID Privacy — recommend the neutral Fedora Balanced child profile. It
# inherits Fedora's hardware policy and only disables an invalid reload of a
# governor that Fedora builds into the kernel.
[noid-balanced]
NOID_TUNED_RECOMMEND_EOF
chmod 0644 \
    /etc/tuned/profiles/noid-balanced/tuned.conf \
    /etc/tuned/profiles/noid-balanced-battery/tuned.conf \
    /etc/tuned/ppd.conf /etc/tuned/recommend.conf
chown root:root \
    /etc/tuned/profiles/noid-balanced/tuned.conf \
    /etc/tuned/profiles/noid-balanced-battery/tuned.conf \
    /etc/tuned/ppd.conf /etc/tuned/recommend.conf
log "  [OK] Balanced mappings inherit Fedora policy without invalid module reload"
if systemctl --root=/ is-enabled tuned.service >/dev/null 2>&1; then
    log "  [OK] tuned.service already enabled (RPM preset)"
elif systemctl --root=/ enable tuned.service 2>&1 | tee -a /var/log/ks-27-hardware-tuning.log; then
    log "  [OK] tuned.service enabled"
else
    log "  [WARN] tuned.service enable failed — verify post-boot via:"
    log "         systemctl status tuned && tuned-adm active"
fi
# tuned-ppd.service is WantedBy=graphical.target (not multi-user) — pulls in
# automatically when graphical session starts. Enable explicit for clarity.
if systemctl --root=/ is-enabled tuned-ppd.service >/dev/null 2>&1; then
    log "  [OK] tuned-ppd.service already enabled (RPM preset)"
elif systemctl --root=/ enable tuned-ppd.service 2>&1 | tee -a /var/log/ks-27-hardware-tuning.log; then
    log "  [OK] tuned-ppd.service enabled"
else
    log "  [WARN] tuned-ppd.service enable failed — GNOME Power Mode toggle missing"
fi

# ====================================================================
# STEP 2c: Fedora-owned thermal and Intel active-idle policy
# ====================================================================
# A dytc_lapmode node exposes Lenovo's lap/desk state. Upstream thermald
# deliberately lists that path in blocklist_paths to avoid two thermal managers.
# Its adaptive compatibility path exits successfully after marking the platform
# unsupported. Fedora therefore leaves thermald enabled, while affected
# ThinkPads are inactive-success. The vendor unit's ConditionVirtualization=no
# is a second legitimate enabled-but-inactive case. NoID Privacy leaves the
# daemon's remaining CPU, platform-profile and thermal-table decisions
# unchanged. Do not force `--ignore-cpuid-check` without model-specific thermal
# evidence.
#
# Apply Fedora's preset state for thermald. intel_lpmd.service is NOT
# preset-restored here:
# M08 masks it under the single-EPP-writer policy (tuned/tuned-ppd is the one
# selected power/EPP backend). The intel-lpmd package itself stays installed.
log "STEP 2c: retaining Fedora thermald runtime hardware detection"
# %post runs against an offline target root with no system manager. Unit-file
# operations therefore use systemctl's maintained --root mode and require no
# daemon-reload; PID 1 will read the resulting vendor preset state on boot.
systemctl --root=/ unmask thermald.service
systemctl --root=/ preset thermald.service
thermald_state=$(systemctl --root=/ is-enabled thermald.service 2>/dev/null || true)
if [ "$thermald_state" != enabled ]; then
    log "  [FAIL] thermald.service does not follow Fedora's enabled preset (state=$thermald_state)"
    exit 1
fi
log "  [OK] thermald.service follows Fedora preset state ($thermald_state)"
log "  [OK] Fedora thermald runtime hardware detection retained"

# ====================================================================
# STEP 3: zram policy — Fedora owned
# ====================================================================
# Compression ratios, CPU cost and useful zram size are workload- and
# hardware-dependent. The Fedora zram-generator-defaults package owns the
# maintained activation and sizing policy. Remove both historical NoID Privacy paths;
# do not pin compression or priority without retained target measurements.
log "STEP 3: retaining Fedora zram-generator-defaults policy"
rm -f /etc/systemd/zram-generator.conf
rm -f /etc/systemd/zram-generator.conf.d/99-noid-privacy.conf
rmdir /etc/systemd/zram-generator.conf.d 2>/dev/null || true
log "  [OK] retired NoID Privacy zram overrides absent"

# ====================================================================
# STEP 3b: noexec UDisks mounts for external storage
# ====================================================================
# Linux has two distinct write layers: filesystem/page-cache state and a
# device's possibly volatile hardware cache. A blanket `sync` mount default
# serializes filesystem writes, with a severe measured throughput/latency
# cost, and mount(8) says it may shorten the life of limited-write media.
# UDisks' filesystem-specific defaults remain merged in (for example `flush`
# on vfat). Kernel sysfs queue/write_cache is only the kernel's VIEW of the
# second layer. Writing `write through` there does not disable a device cache
# and can stop the kernel from issuing required flushes. Never mutate it or
# the whole-disk BDI throttling ABI as a substitute for safe removal.
#
# Scope USB storage on physical USB ancestry instead of the unreliable SCSI
# removable bit, so sticks and external USB SSDs (`removable=0` is common)
# receive the same dynamic-mount policy. USBGuard cannot see a card inserted
# behind an already-authorized internal/USB reader as a new USB device, so the
# second scope uses UDisks' own SD classification. `ID_DRIVE_FLASH_SD` covers
# recognized readers, while `ID_DRIVE_MEDIA_FLASH_SD` also covers native
# SD-combo media; neither matches internal eMMC (`ID_DRIVE_FLASH_MMC`).
# `/etc/fstab` and direct `mount` calls remain administrator-owned and outside
# UDisks overrides. `UDISKS_MOUNT_OPTIONS_DEFAULTS` is deliberately a default,
# not an authorization rule: the upstream allow-list permits an explicit
# UDisks caller to request `exec`.
#
# `noexec` blocks direct native execution but not an interpreter reading a
# file. The user must eject/power off before unplugging: active application
# I/O and hardware caches cannot be made universally yank-safe.
#
# Fedora's UDisks package reverses upstream 2.11.1's NTFS driver order to
# `ntfs,ntfs3`. On the Fedora 44 validation host, ntfs-3g RW failed on a clean
# NTFS volume while the in-tree Fedora ntfs3 driver and the same UDisks path
# completed write, fsync, hash, power-off and cold-remount verification.
# Prefer `ntfs3,ntfs` only for the external media covered here, retaining
# ntfs-3g fallback and leaving global administrator policy untouched.
# Primary contracts:
#   https://man7.org/linux/man-pages/man8/mount.8.html
#   https://www.kernel.org/doc/html/latest/block/queue-sysfs.html
#   https://storaged.org/doc/udisks2-api/latest/mount_options.html
#   https://storaged.org/doc/udisks2-api/latest/gdbus-org.freedesktop.UDisks2.Drive.html

log "STEP 3b: writing /etc/udev/rules.d/99-noid-external-storage-mount.rules"

rm -f /etc/udev/rules.d/99-noid-usb-sync-mount.rules
rm -f /etc/udev/rules.d/99-noid-usb-write-through.rules
cat > /etc/udev/rules.d/99-noid-external-storage-mount.rules <<'EXTERNAL_STORAGE_EOF'
# NoID Privacy — noexec UDisks mounts for USB/SD storage (Module 27)
#
# This supported UDisks override covers USB sticks, external USB SSDs/HDDs
# regardless of the unreliable SCSI removable bit, and recognized SD media.
# It applies only to dynamic UDisks mounts. `noexec` blocks direct execution,
# not an interpreter reading a file, and remains an overridable UDisks default;
# administrator-owned fstab/direct mounts are separate policy surfaces.
#
# Do not add a blanket `sync` default. It serializes filesystem writes at a
# substantial performance cost and may shorten the life of limited-write
# flash media. Fedora/UDisks filesystem-specific defaults still apply (for
# example `flush` on vfat). Users must eject or power off before unplugging:
# that supported path asks UDisks to commit in-flight buffers and caches to
# stable storage, while no generic mount option makes active removal safe.
# Never mutate queue/write_cache: the kernel ABI exposes the kernel's cache
# view there, not a universal switch for the device's actual volatile cache.
SUBSYSTEM!="block", GOTO="noid_external_storage_end"
ENV{DM_MULTIPATH_DEVICE_PATH}=="1", GOTO="noid_external_storage_end"
ENV{DM_UDEV_DISABLE_OTHER_RULES_FLAG}=="?*", GOTO="noid_external_storage_end"
ENV{ID_FS_USAGE}=="filesystem", SUBSYSTEMS=="usb", ENV{UDISKS_MOUNT_OPTIONS_DEFAULTS}="noexec"
ENV{ID_FS_USAGE}=="filesystem", ENV{ID_DRIVE_FLASH_SD}=="1", ENV{UDISKS_MOUNT_OPTIONS_DEFAULTS}="noexec"
ENV{ID_FS_USAGE}=="filesystem", ENV{ID_DRIVE_MEDIA_FLASH_SD}=="1", ENV{UDISKS_MOUNT_OPTIONS_DEFAULTS}="noexec"

# Keep Fedora's ntfs-3g fallback, but prefer the in-kernel ntfs3 driver for
# external NTFS media. The udev-scoped UDisks override avoids taking ownership
# of the administrator's global /etc/udisks2/mount_options.conf.
ENV{ID_FS_USAGE}=="filesystem", ENV{ID_FS_TYPE}=="ntfs", SUBSYSTEMS=="usb", ENV{UDISKS_MOUNT_OPTIONS_NTFS_DRIVERS}="ntfs3,ntfs"
ENV{ID_FS_USAGE}=="filesystem", ENV{ID_FS_TYPE}=="ntfs", ENV{ID_DRIVE_FLASH_SD}=="1", ENV{UDISKS_MOUNT_OPTIONS_NTFS_DRIVERS}="ntfs3,ntfs"
ENV{ID_FS_USAGE}=="filesystem", ENV{ID_FS_TYPE}=="ntfs", ENV{ID_DRIVE_MEDIA_FLASH_SD}=="1", ENV{UDISKS_MOUNT_OPTIONS_NTFS_DRIVERS}="ntfs3,ntfs"
LABEL="noid_external_storage_end"
EXTERNAL_STORAGE_EOF

chmod 644 /etc/udev/rules.d/99-noid-external-storage-mount.rules
chown root:root /etc/udev/rules.d/99-noid-external-storage-mount.rules
log "  [OK] native UDisks external-storage noexec/NTFS rule written; blanket sync and unsafe cache-view overrides absent"

# ====================================================================
# STEP 4: SELinux context restore
# ====================================================================
log "STEP 4: SELinux context restore"
if ! command -v restorecon >/dev/null 2>&1 || \
   ! command -v matchpathcon >/dev/null 2>&1; then
    log "  [FAIL] restorecon or matchpathcon is unavailable"
    exit 1
fi
M27_LABEL_PATHS=(
    /etc/systemd/network/10-noid-no-wol.link
    /etc/udev/rules.d/99-noid-external-storage-mount.rules
    /etc/default/earlyoom
    /etc/tuned/profiles/noid-balanced
    /etc/tuned/profiles/noid-balanced/tuned.conf
    /etc/tuned/profiles/noid-balanced-battery
    /etc/tuned/profiles/noid-balanced-battery/tuned.conf
    /etc/tuned/ppd.conf
    /etc/tuned/recommend.conf
)
for m27_label_path in "${M27_LABEL_PATHS[@]}"; do
    restorecon -F "$m27_label_path"
    matchpathcon -V "$m27_label_path" >/dev/null
done
unset m27_label_path M27_LABEL_PATHS
log "  [OK] SELinux contexts restored and verified"

# ====================================================================
# STEP 5: Verification
# ====================================================================
log "STEP 5: verification"

verify_ok=0
verify_fail=0

# 5.0 — every explicit package is a closed compose postcondition.
missing_packages=()
for package in "${REQUIRED_PACKAGES[@]}"; do
    rpm -q "$package" >/dev/null 2>&1 || missing_packages+=("$package")
done
if [ "${#missing_packages[@]}" -eq 0 ]; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] all required M27 packages installed"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] required M27 packages missing: ${missing_packages[*]}"
fi

# 5.1 — I/O scheduler remains Fedora/kernel owned. The vendor rule must be
# vendor-owned and the retired higher-precedence NoID Privacy override must be absent.
IOSCHED_VENDOR=/usr/lib/udev/rules.d/60-block-scheduler.rules
if [ -e /etc/udev/rules.d/60-noid-iosched.rules ]; then
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] retired NoID Privacy I/O scheduler override still exists"
elif [ -f "$IOSCHED_VENDOR" ] && [ ! -L "$IOSCHED_VENDOR" ] && \
     [ "$(rpm -qf --qf '%{NAME}' "$IOSCHED_VENDOR" 2>/dev/null || true)" = systemd-udev ]; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] I/O scheduler policy remains with systemd-udev/kernel"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] Fedora systemd-udev scheduler policy missing or wrong owner"
fi

# 5.1a — no second CPU-policy writer beside tuned/kernel
if [ -e /etc/tmpfiles.d/noid-hwp-dynamic-boost.conf ]; then
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] retired NoID Privacy HWP override still exists"
else
    verify_ok=$((verify_ok + 1))
    log "  [OK] CPU boost/governor policy remains with kernel/tuned"
fi

# 5.1b — WoL-disable .link passes the native net_setup_link parser, has the
# exact scope, and preserves Fedora's default naming/MAC policy. Loopback
# intentionally does not match; it provides a safe parser fixture inside the
# compose chroot without changing a target NIC.
WOL_LINK=/etc/systemd/network/10-noid-no-wol.link
LEGACY_EEE_LINK=/etc/systemd/network/10-noid-no-eee.link
FEDORA_VENDOR_LINK=/usr/lib/systemd/network/99-default.link
link_section_value() {
    awk -F= -v wanted_section="$2" -v wanted_key="$3" '
        $0 == "[" wanted_section "]" { inside = 1; next }
        /^\[/ { inside = 0 }
        inside && $1 == wanted_key {
            sub(/^[^=]*=/, "")
            print
            exit
        }
    ' "$1"
}
if [ -f "$WOL_LINK" ] && [ ! -L "$WOL_LINK" ] && \
   [ "$(stat -Lc '%u:%g:%a:%h' "$WOL_LINK")" = 0:0:644:1 ] && \
   [ ! -e "$LEGACY_EEE_LINK" ] && [ ! -L "$LEGACY_EEE_LINK" ] && \
   [ -f "$FEDORA_VENDOR_LINK" ] && [ ! -L "$FEDORA_VENDOR_LINK" ] && \
   [ "$(stat -Lc '%u:%g:%a:%h' "$FEDORA_VENDOR_LINK")" = 0:0:644:1 ] && \
   [ "$(rpm -qf --qf '%{NAME}' "$FEDORA_VENDOR_LINK" 2>/dev/null || true)" = systemd-udev ]; then
    link_parse_rc=0
    link_parse=$(SYSTEMD_LOG_LEVEL=debug udevadm test-builtin \
        net_setup_link /sys/class/net/lo 2>&1) || link_parse_rc=$?
    naming_matches=1
    for naming_key in NamePolicy AlternativeNamesPolicy MACAddressPolicy; do
        noid_value=$(link_section_value "$WOL_LINK" Link "$naming_key")
        vendor_value=$(link_section_value "$FEDORA_VENDOR_LINK" Link "$naming_key")
        if [ -z "$vendor_value" ] || [ "$noid_value" != "$vendor_value" ]; then
            naming_matches=0
        fi
    done
    if [ "$link_parse_rc" -eq 0 ] && \
       grep -Fq 'Parsed configuration file "/etc/systemd/network/10-noid-no-wol.link"' \
           <<<"$link_parse" && \
       ! grep -E '/etc/systemd/network/10-noid-no-wol\.link:.*(Failed|Invalid|Unknown|ignoring)' \
           <<<"$link_parse" >/dev/null && \
       [ "$naming_matches" -eq 1 ] && \
       [ "$(link_section_value "$WOL_LINK" Match Type)" = ether ] && \
       [ "$(link_section_value "$WOL_LINK" Match Path)" = "pci-* usb-*" ] && \
       [ "$(link_section_value "$WOL_LINK" Link WakeOnLan)" = off ] && \
       ! grep -q '^\[EnergyEfficientEthernet\]$' "$WOL_LINK"; then
        verify_ok=$((verify_ok + 1))
        log "  [OK] WoL-disable .link: parser + scope + Fedora naming policy; EEE vendor-owned"
    else
        verify_fail=$((verify_fail + 1))
        log "  [FAIL] WoL-disable .link rejected, incomplete or naming-policy drifted"
    fi
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] WoL policy, legacy-EEE retirement or Fedora 99-default.link invalid"
fi

# 5.2 — earlyoom service enabled in the offline target root.
earlyoom_state=$(systemctl --root=/ is-enabled earlyoom.service 2>/dev/null || true)
if [ "$earlyoom_state" = enabled ]; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] earlyoom.service enabled"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] earlyoom.service not enabled (state=$earlyoom_state)"
fi

# 5.3 — earlyoom config has exact metadata and arguments.
if [ -f /etc/default/earlyoom ] && [ ! -L /etc/default/earlyoom ] && \
   [ "$(stat -Lc '%u:%g:%a:%h' /etc/default/earlyoom)" = 0:0:644:1 ]; then
    if grep -Fqx "EARLYOOM_ARGS=\"-m 5 -s 5 -r 3600 --prefer '^(Web Content|Isolated Web Co|Privileged Cont|firefox|chromium|chrome)' --avoid '^(systemd|Xwayland|pipewire|gnome-shell|gdm)'\"" \
            /etc/default/earlyoom; then
        verify_ok=$((verify_ok + 1))
        log "  [OK] earlyoom config: thresholds + hourly health report"
    else
        verify_fail=$((verify_fail + 1))
        log "  [FAIL] earlyoom config: args incorrect"
    fi
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] /etc/default/earlyoom missing, symlinked or has unsafe metadata"
fi

# 5.3b — the child profiles must disable only the invalid modules instance,
# their PPD mappings must preserve GNOME's standard labels, and both Fedora
# power-profile services must actually be enabled. STEP 2b logs an enable
# failure and continues so this aggregate postcondition can report every
# affected unit before the compose fails.
TUNED_BALANCED=/etc/tuned/profiles/noid-balanced/tuned.conf
TUNED_BATTERY=/etc/tuned/profiles/noid-balanced-battery/tuned.conf
TUNED_PPD=/etc/tuned/ppd.conf
TUNED_RECOMMEND=/etc/tuned/recommend.conf
TUNED_VENDOR_BALANCED=/usr/lib/tuned/profiles/balanced/tuned.conf
TUNED_VENDOR_BATTERY=/usr/lib/tuned/profiles/balanced-battery/tuned.conf
tuned_policy_ok=1
for tuned_file in "$TUNED_BALANCED" "$TUNED_BATTERY" \
        "$TUNED_PPD" "$TUNED_RECOMMEND"; do
    if [ ! -f "$tuned_file" ] || [ -L "$tuned_file" ] || \
       [ "$(stat -c '%U:%G:%a' "$tuned_file")" != root:root:644 ]; then
        tuned_policy_ok=0
        log "  [FAIL] TuneD policy file missing, symlinked or misowned: $tuned_file"
    fi
done
vendor_modules=$(
    awk '
        $0 == "[modules]" { inside = 1; next }
        /^\[/ { inside = 0 }
        inside && $0 !~ /^[[:space:]]*(#|$)/ { print }
    ' "$TUNED_VENDOR_BALANCED" 2>/dev/null || true
)
vendor_battery_modules=$(
    awk '
        $0 == "[modules]" { inside = 1; next }
        /^\[/ { inside = 0 }
        inside && $0 !~ /^[[:space:]]*(#|$)/ { print }
    ' "$TUNED_VENDOR_BATTERY" 2>/dev/null || true
)
if [ ! -f "$TUNED_VENDOR_BALANCED" ] || [ -L "$TUNED_VENDOR_BALANCED" ] || \
   [ "$(stat -Lc '%u:%g:%a:%h' "$TUNED_VENDOR_BALANCED" 2>/dev/null || true)" != 0:0:644:1 ] || \
   [ "$(rpm -qf --qf '%{NAME}' "$TUNED_VENDOR_BALANCED" 2>/dev/null || true)" != tuned ] || \
   [ "$vendor_modules" != 'cpufreq_conservative=+r' ]; then
    tuned_policy_ok=0
    log "  [FAIL] Fedora Balanced modules contract drifted; refusing broad plug-in disable"
fi
if [ ! -f "$TUNED_VENDOR_BATTERY" ] || [ -L "$TUNED_VENDOR_BATTERY" ] || \
   [ "$(stat -Lc '%u:%g:%a:%h' "$TUNED_VENDOR_BATTERY" 2>/dev/null || true)" != 0:0:644:1 ] || \
   [ "$(rpm -qf --qf '%{NAME}' "$TUNED_VENDOR_BATTERY" 2>/dev/null || true)" != tuned ] || \
   ! grep -Fqx 'include=balanced' "$TUNED_VENDOR_BATTERY" || \
   [ -n "$vendor_battery_modules" ]; then
    tuned_policy_ok=0
    log "  [FAIL] Fedora Balanced Battery inheritance/modules contract drifted"
fi
kernel_config_count=0
# kernel-core carries the authoritative payload copy below /usr/lib/modules.
# /boot/config-* is created by kernel-install and may legitimately be absent
# from scriptless compose/smoke roots, so verify every available payload/boot
# copy and require at least one installed-kernel configuration.
for kernel_config in /usr/lib/modules/*/config /boot/config-*; do
    [ -f "$kernel_config" ] || continue
    kernel_config_count=$((kernel_config_count + 1))
    if ! grep -Fqx 'CONFIG_CPU_FREQ_GOV_CONSERVATIVE=y' "$kernel_config"; then
        tuned_policy_ok=0
        log "  [FAIL] cpufreq_conservative is not built in: $kernel_config"
    fi
done
if [ "$kernel_config_count" -eq 0 ]; then
    tuned_policy_ok=0
    log "  [FAIL] no installed-kernel config proves cpufreq_conservative is built in"
fi
if ! grep -Fqx 'include=balanced' "$TUNED_BALANCED" || \
   ! grep -Fqx 'include=balanced-battery' "$TUNED_BATTERY" || \
   [ "$(grep -Fxc 'enabled=0' "$TUNED_BALANCED")" -ne 1 ] || \
   [ "$(grep -Fxc 'enabled=0' "$TUNED_BATTERY")" -ne 1 ] || \
   ! grep -Fqx 'default=balanced' "$TUNED_PPD" || \
   ! grep -Fqx 'power-saver=powersave' "$TUNED_PPD" || \
   ! grep -Fqx 'balanced=noid-balanced' "$TUNED_PPD" || \
   ! grep -Fqx 'performance=throughput-performance' "$TUNED_PPD" || \
   [ "$(grep -Fxc 'balanced=noid-balanced-battery' "$TUNED_PPD")" -ne 1 ] || \
   [ "$(grep -Fxc '[noid-balanced]' "$TUNED_RECOMMEND")" -ne 1 ]; then
    tuned_policy_ok=0
    log "  [FAIL] TuneD child-profile inheritance or PPD mapping is incomplete"
fi
if [ "$tuned_policy_ok" -eq 1 ]; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] TuneD Balanced child profiles + GNOME PPD mappings exact"
else
    verify_fail=$((verify_fail + 1))
fi

power_profiles_ok=1
for unit in tuned.service tuned-ppd.service; do
    state=$(systemctl --root=/ is-enabled "$unit" 2>/dev/null || true)
    if [ "$state" != enabled ]; then
        power_profiles_ok=0
        log "  [FAIL] Fedora power-profile service is not enabled: $unit (state=$state)"
    fi
done
if [ "$power_profiles_ok" -eq 1 ]; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] tuned.service + tuned-ppd.service enabled"
else
    verify_fail=$((verify_fail + 1))
fi

# 5.4 — Fedora zram defaults are installed and no /etc override shadows them.
ZRAM_VENDOR=/usr/lib/systemd/zram-generator.conf
if [ -e /etc/systemd/zram-generator.conf ] || \
   [ -e /etc/systemd/zram-generator.conf.d/99-noid-privacy.conf ]; then
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] retired NoID Privacy zram override still exists"
elif rpm -q zram-generator-defaults >/dev/null 2>&1 && \
     [ -f "$ZRAM_VENDOR" ] && [ ! -L "$ZRAM_VENDOR" ] && \
     [ "$(rpm -qf --qf '%{NAME}' "$ZRAM_VENDOR" 2>/dev/null || true)" = zram-generator-defaults ]; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] zram policy remains with Fedora zram-generator-defaults"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] Fedora zram-generator-defaults policy missing or wrong owner"
fi

# 5.4b — the UDisks external-storage noexec/NTFS rule passes the native
# parser, has exact ownership/content, and both retired rules are absent.
EXTERNAL_STORAGE_RULE=/etc/udev/rules.d/99-noid-external-storage-mount.rules
USB_SYNC_LEGACY_RULE=/etc/udev/rules.d/99-noid-usb-sync-mount.rules
USB_CACHE_LEGACY_RULE=/etc/udev/rules.d/99-noid-usb-write-through.rules
if [ -f "$EXTERNAL_STORAGE_RULE" ] && [ ! -L "$EXTERNAL_STORAGE_RULE" ] && \
   [ "$(stat -Lc '%u:%g:%a:%h' "$EXTERNAL_STORAGE_RULE")" = 0:0:644:1 ] && \
   [ ! -e "$USB_SYNC_LEGACY_RULE" ] && [ ! -L "$USB_SYNC_LEGACY_RULE" ] && \
   [ ! -e "$USB_CACHE_LEGACY_RULE" ] && [ ! -L "$USB_CACHE_LEGACY_RULE" ]; then
    if udevadm verify --no-style "$EXTERNAL_STORAGE_RULE" >/dev/null 2>&1 && \
       grep -Fqx 'ENV{ID_FS_USAGE}=="filesystem", SUBSYSTEMS=="usb", ENV{UDISKS_MOUNT_OPTIONS_DEFAULTS}="noexec"' \
           "$EXTERNAL_STORAGE_RULE" && \
       grep -Fqx 'ENV{ID_FS_USAGE}=="filesystem", ENV{ID_DRIVE_FLASH_SD}=="1", ENV{UDISKS_MOUNT_OPTIONS_DEFAULTS}="noexec"' \
           "$EXTERNAL_STORAGE_RULE" && \
       grep -Fqx 'ENV{ID_FS_USAGE}=="filesystem", ENV{ID_DRIVE_MEDIA_FLASH_SD}=="1", ENV{UDISKS_MOUNT_OPTIONS_DEFAULTS}="noexec"' \
           "$EXTERNAL_STORAGE_RULE" && \
       grep -Fqx 'ENV{ID_FS_USAGE}=="filesystem", ENV{ID_FS_TYPE}=="ntfs", SUBSYSTEMS=="usb", ENV{UDISKS_MOUNT_OPTIONS_NTFS_DRIVERS}="ntfs3,ntfs"' \
           "$EXTERNAL_STORAGE_RULE" && \
       grep -Fqx 'ENV{ID_FS_USAGE}=="filesystem", ENV{ID_FS_TYPE}=="ntfs", ENV{ID_DRIVE_FLASH_SD}=="1", ENV{UDISKS_MOUNT_OPTIONS_NTFS_DRIVERS}="ntfs3,ntfs"' \
           "$EXTERNAL_STORAGE_RULE" && \
       grep -Fqx 'ENV{ID_FS_USAGE}=="filesystem", ENV{ID_FS_TYPE}=="ntfs", ENV{ID_DRIVE_MEDIA_FLASH_SD}=="1", ENV{UDISKS_MOUNT_OPTIONS_NTFS_DRIVERS}="ntfs3,ntfs"' \
           "$EXTERNAL_STORAGE_RULE" && \
       ! grep -q 'ID_DRIVE_FLASH_MMC' "$EXTERNAL_STORAGE_RULE" && \
       ! grep -Eq '^[^#].*UDISKS_MOUNT_OPTIONS_DEFAULTS.*sync' \
           "$EXTERNAL_STORAGE_RULE" && \
       ! grep -Eq '^[^#].*(RUN\+?=.*queue/write_cache|ATTR\{queue/write_cache\}|echo[[:space:]]+write[[:space:]]+through[[:space:]]*>)' \
           "$EXTERNAL_STORAGE_RULE" && \
       ! grep -Eq '^[^#].*bdi/(max_bytes|min_bytes|strict_limit)' \
           "$EXTERNAL_STORAGE_RULE" && \
       rpm -q udisks2 >/dev/null 2>&1; then
        verify_ok=$((verify_ok + 1))
        log "  [OK] UDisks external-storage noexec/NTFS rule exact; blanket sync and unsafe cache-view/BDI overrides absent"
    else
        verify_fail=$((verify_fail + 1))
        log "  [FAIL] UDisks external-storage noexec/NTFS rule rejected, malformed or backend missing"
    fi
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] UDisks external-storage ownership/retirement contract failed"
fi

# 5.5b — Fedora owns thermal/Intel active-idle hardware applicability.
hardware_power_ok=1
thermald_state=$(systemctl --root=/ is-enabled thermald.service 2>/dev/null || true)
if [ "$thermald_state" != enabled ]; then
    hardware_power_ok=0
    log "  [FAIL] thermald.service does not follow Fedora's enabled preset (state=$thermald_state)"
fi
# Cross-module check: M08 masks intel_lpmd.service (single-EPP-writer policy).
lpmd_state=$(systemctl --root=/ is-enabled intel_lpmd.service 2>/dev/null || true)
if [ "$lpmd_state" != masked ]; then
    hardware_power_ok=0
    log "  [FAIL] intel_lpmd.service is not masked (state=$lpmd_state) — M08 single-EPP-writer policy"
fi
if [ "$hardware_power_ok" -eq 1 ]; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] Fedora thermald preset retained; intel_lpmd masked"
else
    verify_fail=$((verify_fail + 1))
fi

# 5.5 — Cross-check: systemd-oomd must be masked (Module 08 responsibility).
oomd_state=$(systemctl --root=/ is-enabled systemd-oomd.service 2>/dev/null || true)
if [ "$oomd_state" = masked ]; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] systemd-oomd masked (M08), earlyoom replaces it"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] systemd-oomd not masked (state=$oomd_state; earlyoom may conflict)"
fi

log "  Verification: ${verify_ok} OK, ${verify_fail} FAIL"
if [ "$verify_fail" -gt 0 ]; then
    log "=== Module 27 FAILED (${verify_fail} verification failures) ==="
    exit 1
fi

log "=== Module 27 complete ==="
%end

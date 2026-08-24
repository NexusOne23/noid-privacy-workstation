# ============================================================================
# Module 01 — Kernel cmdline + GRUB + Secure Boot
# Status: LOCKED 2026-08-10 (v63) — carry neutral UTC into Anaconda's interactive Live-install defaults.
#
# Covers:
#   - Kernel baseline cmdline via the `bootloader --append=` directive below.
#     The canonical set is recorded in manifests/kernel-cmdline.tsv and its
#     exact views live in these synchronization points:
#       (a) the bootloader --append= directive          (install-time)
#       (b) the interactive-defaults.ks mirror, STEP 1b (Anaconda live-install)
#       (c) NOID_BASE_ARGS in STEP 4b + canonicalizer   (firstboot enforcement;
#           intel_iommu factored out into dynamic CPU_EXTRA)
#       (d) is_noid_managed_arg in STEP 4b + canonicalizer (inherited dedup)
#   - /usr/libexec/noid-verify-target-karg-payload: compose-time proof that the
#     interactive installer contains the complete target post-script byte for
#     byte and both surfaces carry one active, conflict-free
#     module.sig_enforce=1 contract. Actual Live and installed BLS
#     effectiveness remains a pre-ship runtime claim.
#   - Hardware-conditional extras (CPU vendor and GPU vendor only)
#   - LUKS unlock-retry (STEP 4b target + STEP 4c fallback):
#     rd.luks.options=<UUID>=tries=0,discard
#   - GRUB config (timeout, menu visibility, os-prober off)
#   - DNF config (installonly_limit=3, weak_deps off, countme off,
#     gpgcheck + localpkg_gpgcheck explicit)
#   - UEFI-only package set (no BIOS legacy install path)
#   - GRUB password infrastructure, opt-in (STEP 5b, noid-grub-password)
#   - root-only System.map policy for /boot and /usr/lib/modules (STEP 9 —
#     preserves native target-kernel kmod/depmod integration)
#
# KSPP compliance: all cmdline flags except the deliberate deviations below,
# one kernel-build limitation (cfi=kcfi needs a clang-built kernel; Fedora
# ships GCC builds) and two presentation tokens (`rhgb` for Plymouth and
# `quiet` for reduced kernel/systemd console output).
#
# Deliberate deviations (decided + verified; do not re-litigate without
# new evidence):
#   - No ,nosmt suffixes (mds / mmio_stale_data / retbleed / tsx_async_abort
#     apply WITHOUT it). Linux enables the available per-vulnerability
#     mitigations but retains SMT. On an affected CPU this deliberately leaves
#     cross-thread exposure that full mitigation would close by disabling SMT;
#     on an unaffected CPU a conditional ,nosmt policy would not disable it.
#     The image default accepts that residual risk for a general single-user
#     workstation because the performance impact is workload- and
#     topology-dependent, not a defensible universal percentage.
#     Primary contracts:
#       https://docs.kernel.org/admin-guide/hw-vuln/attack_vector_controls.html
#       https://docs.kernel.org/admin-guide/hw-vuln/mds.html
#   - lockdown=integrity, not =confidentiality: integrity mode disables kernel
#     interfaces that let user space modify the running kernel. Confidentiality
#     additionally disables interfaces that expose kernel information; that
#     stronger boundary is outside this workstation's reviewed compatibility
#     contract and is not required for its signed-boot integrity policy.
#   - iommu=force NOT set: verified crashes on platforms whose BIOS lacks
#     DMAR Platform Opt-In. intel_iommu=on + iommu.strict=1 +
#     iommu.passthrough=0 already give Translated-domain DMA protection.
#     iommu=pt likewise removed (passthrough = identity mapping = no DMA
#     protection for host devices; only useful for VFIO passthrough hosts).
#   - oops=panic NOT set: a hostile recoverable-oops would force a
#     panic-reboot and destabilize VPN + rotated MAC. Module 02 ships the
#     softer equivalent (oops_limit/warn_limit=100 + panic=-1).
#   - UMASK=027 in login.defs SKIPPED: dnf5 issue #1908 breaks non-root dnf
#     with mode-640 state files (Kicksecure security-misc #185 reverted the
#     same change). Module 10 applies umask 027 to interactive shells.
#   - kernel.yama.ptrace_scope=2 (not 3) is the sysctl-side sibling — see
#     the Module 02 header.
#
# Token notes (recurring review questions):
#   - Global slab_debug/slub_debug is deliberately absent in production. Fedora
#     already enables hardened freelists, hardened usercopy and allocator
#     initialization; forcing red-zones and sanity checks on every cache is a
#     broad diagnostic tax. The managed-family filter still removes inherited
#     legacy values during upgrades.
#   - KFENCE remains sampled at 100 ms, but kfence.deferrable=1 lets an idle CPU
#     defer the sampling timer instead of waking solely for a low-frequency
#     diagnostic allocation.
#   - random.trust_cpu=off + random.trust_bootloader=off: RDRAND/EFI-RNG
#     remain ONE entropy source among many instead of the sole CSPRNG seed.
#   - l1tf=full + l1d_flush=on + kvm-intel.vmentry_l1d_flush=always are
#     Intel-only; no-ops on AMD (handled dynamically via CPU_EXTRA).
#   - spectre_v2=on already enforces the user-space Spectre-v2 mitigation.
#     The managed-family filter removes the formerly emitted redundant override.
# ============================================================================

# ---------------------------------------------------------------------------
# %pre — UEFI firmware enforcement (revised)
# ---------------------------------------------------------------------------
# NoID Privacy's supported boot architecture is UEFI-based (including access to
# platform-security attributes where firmware/fwupd expose them and support for
# a signed Fedora boot chain when firmware Secure Boot is enabled). On BIOS
# firmware these layers are unavailable or differ materially.
# Better to fail fast with a clear error than to ship half-NoID Privacy.
#
# Defense layers blocking BIOS install:
#   1. THIS %pre block — fail-fast for the compose VM and an explicit
#      inst.ks= path that parses this source before storage changes.
#   2. -grub2-pc package — prevents a BIOS bootloader from being installed.
#
# The shipped interactive Live installer does not parse this build-time %pre;
# on that path the package exclusion is the final enforcement layer and may
# fail only when Anaconda reaches bootloader installation. Do not describe the
# interactive path as a guaranteed pre-write abort.
%pre --erroronfail --log=/var/log/ks-pre-uefi-check.log
if [ ! -d /sys/firmware/efi ]; then
    echo "==============================================" >&2
    echo "  NoID Privacy Workstation requires UEFI" >&2
    echo "==============================================" >&2
    echo "" >&2
    echo "  This system booted in BIOS/Legacy mode." >&2
    echo "" >&2
    echo "  NoID Privacy's supported boot architecture requires UEFI for:" >&2
    echo "    - the Fedora shim/GRUB/kernel signature path when Secure Boot is enabled" >&2
    echo "    - platform security attributes exposed by firmware and fwupd" >&2
    echo "    - the documented UEFI/MOK and platform-inspection workflows" >&2
    echo "" >&2
    echo "  BIOS mode is outside the supported and verified NoID Privacy" >&2
    echo "  boot trust boundary, so installation stops before disk writes." >&2
    echo "" >&2
    echo "  Reboot in UEFI mode and try again." >&2
    echo "" >&2
    echo "  If your firmware is in 'Legacy' or 'CSM' mode, enter" >&2
    echo "  firmware setup and switch boot mode" >&2
    echo "  to 'UEFI' (sometimes labeled 'EFI Boot' or 'UEFI only')." >&2
    echo "==============================================" >&2
    exit 1
fi
%end

# ---------------------------------------------------------------------------
# Top-level: bootloader directive
# ---------------------------------------------------------------------------
# Anaconda writes this into GRUB_CMDLINE_LINUX AND all BLS entries directly.
# Hardware-specific flags (intel_iommu, amd_iommu, tsx) are
# appended in %post based on live detection.
# UEFI-only install policy: grub2-pc binary EXCLUDED (no BIOS bootloader
# install path); grub2-pc-modules INCLUDED (static files required by lorax
# for the hybrid Live-ISO BIOS El Torito leg — no runtime attack surface).
# --location is omitted deliberately. Pykickstart records the historical
# default (`mbr`), while Anaconda selects the native EFI installation path
# because the %pre gate above has already proved UEFI firmware. Do not cite
# omission itself as a BIOS defense.
# Single-line: pykickstart does NOT support `\` line-continuation in
# command directives.
# loglevel=4 retains KERN_ERR/CRIT/ALERT/EMERG diagnostics: printk emits only
# priorities numerically lower than the console loglevel. This is
# load-bearing with rd.emergency=halt + rd.shell=0: recovery stays shell-free,
# but an early storage/LUKS failure must not become an opaque black screen.
# `quiet` is interpreted by both the kernel and systemd. Fedora's kernel maps
# it to CONSOLE_LOGLEVEL_QUIET=3, which would suppress KERN_ERR; the later
# `loglevel=4` token deliberately restores the load-bearing threshold. Keep
# that order: manifests/kernel-cmdline.tsv and the exact-order contract bind
# it. PID 1 independently drops to SHOW_STATUS_ERROR, avoiding the normal
# `[ OK ] Started ...` flood while preserving failures. The journal retains
# every message either way.
bootloader --timeout=3 --append="rhgb quiet init_on_alloc=1 init_on_free=1 slab_nomerge pti=on vsyscall=none vdso32=0 debugfs=off page_alloc.shuffle=1 randomize_kstack_offset=on spec_store_bypass_disable=on module.sig_enforce=1 iommu.strict=1 iommu.passthrough=0 lockdown=integrity mitigations=auto proc_mem.force_override=never hash_pointers=always hardened_usercopy=1 kfence.sample_interval=100 kfence.deferrable=1 efi=disable_early_pci_dma ia32_emulation=0 bdev_allow_write_mounted=0 rd.emergency=halt rd.shell=0 loglevel=4 systemd.ssh_auto=no random.trust_cpu=off random.trust_bootloader=off audit=1 audit_backlog_limit=8192 zswap.enabled=0 intel_iommu=on kvm.nx_huge_pages=force mmio_stale_data=full retbleed=auto gather_data_sampling=force reg_file_data_sampling=on indirect_target_selection=force vmscape=force efi_pstore.pstore_disable=1 erst_disable spectre_v2=on spectre_bhi=on mds=full tsx_async_abort=full srbds=on spec_rstack_overflow=safe-ret tsa=on"

# ---------------------------------------------------------------------------
# Packages: kernel + UEFI bootloader chain
# ---------------------------------------------------------------------------
# --exclude-weakdeps: prevent Recommends/Suggests weak-dep chains from pulling
# back packages that later Modules (05, 08, 09) explicitly exclude. Flag is
# set on every %packages block across all snippets for defensive consistency
# (Anaconda merges %packages sections but flag propagation between them is
# implementation-dependent — set per-block to guarantee behavior).
%packages --exclude-weakdeps
# Kernel core
kernel
kernel-core
kernel-modules
kernel-modules-core
kernel-modules-extra

# Live-ISO support — required by livemedia-creator --make-iso for the
# squashfs+overlay live-boot stack. Without this, lmc warns "dracut-live
# package is missing" and Live-Boot from USB fails to construct the rw
# overlay (read-only squashfs only).
dracut-live
# Generic hardware initramfs for Live-Boot portability — without this the
# initramfs is built host-specific and won't boot on different hardware.
dracut-config-generic
# NoID Privacy is daily-driver, not rescue-kernel image — exclude rescue-config
# to prevent a "Rescue" entry in GRUB on installed system.
-dracut-config-rescue

# Bootloader — UEFI install policy (revised: grub2-pc binary
# excluded, but grub2-pc-modules required by lorax for Live-ISO BIOS El Torito
# leg, aligned with Fedora 44 upstream Live-ISO packaging)
grub2-efi-x64
grub2-efi-x64-modules
# grub2-efi-x64-cdboot provides gcdx64.efi — REQUIRED by lorax x86.tmpl
# (line 65: `%if exists("boot/efi/EFI/*/gcdx64.efi")`). Without it, lorax
# silently skips the entire efi.tmpl include block → xorriso fails with
# "Cannot determine attributes of source file 'EFI/BOOT'". Discovered in
# during an rc.5 build session.
grub2-efi-x64-cdboot
grub2-common
grub2-tools
grub2-tools-efi
grub2-tools-extra
grub2-tools-minimal
grub2-pc-modules

# Secure Boot chain
shim-x64
mokutil

# Firmware updates (fwupd capsules)
fwupd
efibootmgr

# Hardware detection (lspci)
pciutils

# Kernel tools (grubby for BLS manipulation, kernel-install hooks)
grubby

# Crypto-policy data plus its separately packaged switching/verification tool.
# Weak dependencies are disabled, so both halves of the STEP 7 contract are
# explicit.
crypto-policies
crypto-policies-scripts

# EXCLUDE grub2-pc: the binary that drives grub2-install for MBR/BIOS —
# without it Anaconda cannot install a BIOS bootloader (UEFI-only policy).
-grub2-pc
%end

# ---------------------------------------------------------------------------
# %post — Module 01 config hardening + hardware detection
# ---------------------------------------------------------------------------
%post --erroronfail --log=/var/log/ks-01-bootloader.log
set -euo pipefail

log() { echo "[noid-01-kernel] $*"; }
log "=== Module 01 post-install: kernel + grub + hardware detection ==="

# ====================================================================
# STEP 1: /etc/default/grub (non-cmdline settings)
# ====================================================================
# F44 BLS-first: /etc/default/grub may not exist at %post time — Anaconda's
# bootloader-installer runs AFTER kickstart %post sections. With set -euo
# pipefail a missing file would crash the entire post-install chain (observed). Defensive: ensure file exists with Fedora defaults, then patch.
if [ ! -f /etc/default/grub ]; then
    log "STEP 1: /etc/default/grub missing — creating from Fedora defaults"
    cat > /etc/default/grub <<'GRUB_DEFAULTS_EOF'
GRUB_TIMEOUT=5
GRUB_DISTRIBUTOR="$(sed 's, release .*$,,g' /etc/system-release)"
GRUB_DEFAULT=saved
GRUB_DISABLE_SUBMENU=true
GRUB_TERMINAL_OUTPUT="console"
GRUB_CMDLINE_LINUX=""
GRUB_DISABLE_RECOVERY="true"
GRUB_ENABLE_BLSCFG=true
GRUB_DEFAULTS_EOF
    chmod 0644 /etc/default/grub
fi

sed -i \
    -e 's/^GRUB_TIMEOUT=.*/GRUB_TIMEOUT=3/' \
    -e 's/^GRUB_TERMINAL_OUTPUT=.*/GRUB_TERMINAL_OUTPUT="console"/' \
    /etc/default/grub

# GRUB_DISABLE_OS_PROBER=true (add or replace)
if grep -q '^GRUB_DISABLE_OS_PROBER=' /etc/default/grub; then
    sed -i 's/^GRUB_DISABLE_OS_PROBER=.*/GRUB_DISABLE_OS_PROBER=true/' /etc/default/grub
else
    echo 'GRUB_DISABLE_OS_PROBER=true' >> /etc/default/grub
fi

log "STEP 1: /etc/default/grub patched (timeout=3, os-prober=off, terminal=console)"
command -v restorecon >/dev/null 2>&1 \
    || { log "STEP 1: restorecon is unavailable"; exit 1; }
command -v matchpathcon >/dev/null 2>&1 \
    || { log "STEP 1: matchpathcon is unavailable"; exit 1; }
restorecon -F /etc/default/grub
matchpathcon -V /etc/default/grub
log "STEP 1: /etc/default/grub SELinux label matches policy"

# ====================================================================
# STEP 1b: Start the NoID Privacy interactive kickstart for the Live-Installer
# ====================================================================
# The Anaconda Live-Installer (cockpit/web-UI) does NOT load the build-time
# master.ks — end-user installs parse
# /usr/share/anaconda/interactive-defaults.ks instead, which by default has
# NO bootloader directive: the installed system would get only
# `rd.luks.uuid=... rhgb quiet` and lose every hardening karg. Fix: mirror
# the M01 bootloader directive into that file. STEP 4b appends the target
# `%post` to this SAME parsed kickstart; a detached post-scripts directory is
# not an execution boundary in the Fedora 44 Anaconda build. Args MUST stay
# byte-identical to the directive above (sync point (b) — see header). If
# upstream removes the file, switch to /etc/anaconda/profile.d once it
# gains extra_arguments support.
log "STEP 1b: starting NoID Privacy interactive-defaults.ks for Live-Installer"
mkdir -p /usr/share/anaconda
cat > /usr/share/anaconda/interactive-defaults.ks <<'INTERACTIVE_DEFAULTS_EOF'
# NoID Privacy Workstation — Anaconda interactive install defaults
# Loaded by Anaconda when no explicit kickstart is passed on cmdline.
# Source-of-truth: M01 installer defaults in
# kickstart/snippets/01-bootloader.ks (mirror — keep both in sync when updating
# either). Liveinst does not parse master.ks, so state the neutral timezone here
# until the user consciously changes it after installation.
#
# WARNING: do not edit on installed system. To customize, update Module 01
# in noid-privacy-fedora source tree and rebuild the ISO.
timezone UTC --utc
bootloader --timeout=3 --append="rhgb quiet init_on_alloc=1 init_on_free=1 slab_nomerge pti=on vsyscall=none vdso32=0 debugfs=off page_alloc.shuffle=1 randomize_kstack_offset=on spec_store_bypass_disable=on module.sig_enforce=1 iommu.strict=1 iommu.passthrough=0 lockdown=integrity mitigations=auto proc_mem.force_override=never hash_pointers=always hardened_usercopy=1 kfence.sample_interval=100 kfence.deferrable=1 efi=disable_early_pci_dma ia32_emulation=0 bdev_allow_write_mounted=0 rd.emergency=halt rd.shell=0 loglevel=4 systemd.ssh_auto=no random.trust_cpu=off random.trust_bootloader=off audit=1 audit_backlog_limit=8192 zswap.enabled=0 intel_iommu=on kvm.nx_huge_pages=force mmio_stale_data=full retbleed=auto gather_data_sampling=force reg_file_data_sampling=on indirect_target_selection=force vmscape=force efi_pstore.pstore_disable=1 erst_disable spectre_v2=on spectre_bhi=on mds=full tsx_async_abort=full srbds=on spec_rstack_overflow=safe-ret tsa=on"
INTERACTIVE_DEFAULTS_EOF
chmod 0644 /usr/share/anaconda/interactive-defaults.ks
log "STEP 1b: interactive kickstart base deployed (target post appended in STEP 4b)"

# ====================================================================
# STEP 2: /etc/dnf/dnf.conf (weak_deps off, installonly_limit=3)
# ====================================================================
cat > /etc/dnf/dnf.conf <<'DNF_EOF'
# NoID Privacy — DNF config (Module 01)
[main]
# fastestmirror=False. Rationale: countme=False
# below blocks Fedora's count-me mirror tracking, but fastestmirror=True
# would still ping multiple mirrors per refresh to measure latency, which
# leaks DNS+TCP-handshake metadata to several mirrors per dnf operation.
# Privacy-consistent default: trust the metalink ordering; user can flip
# this to True locally if mirror performance is poor in their region.
fastestmirror=False
max_parallel_downloads=10
installonly_limit=3
# defaultyes=False: dnf prompts user with [y/N] (default No) for every
# transaction confirmation — privacy/hardening posture requires deliberate
# acknowledgement instead of Enter-key-auto-yes (default-No is the
# deliberate hardening choice).
defaultyes=False
countme=False
install_weak_deps=False
# Explicit GPG-check directives. Defaults
# in /usr/lib/dnf/dnf.conf are gpgcheck=True (Fedora override) but DNF5
# stock default is False — drift-prone if Fedora overrides change. Plus:
# localpkg_gpgcheck DNF5-default=False allows `dnf install ./package.rpm`
# without signature validation (supply-chain risk for user-fetched RPMs).
# clean_requirements_on_remove=True is Fedora default but explicit = drift-proof.
# repo_gpgcheck NOT set globally — per-repo (Module 08/14 use trust-exception
# repo_gpgcheck=0 for Cisco openh264 + negativo17 with documented rationale).
gpgcheck=True
localpkg_gpgcheck=True
clean_requirements_on_remove=True
# An install-time audit observed RPM Fusion metalink resolution from a
# qemu-NAT environment returning a far-region mirror (RPMFusion geo-IP detection
# failed in qemu-NAT: 5x curl 6/7 + DNS SERVFAIL, no data fetched). Resolution:
# Fedora MirrorManager is geo-aware automatically (no dnf.conf key required);
# RPM Fusion is handled separately by Module 08 STEP 7c through its maintained
# HTTPS metalink.
# Note: dnf5 has no [main] `country=` key — such a directive is silently ignored.
DNF_EOF
log "STEP 2: /etc/dnf/dnf.conf written"

# ====================================================================
# STEP 2b: Authenticated mirror transport — HTTPS metalink + HTTPS mirrors
# ====================================================================
# Require the metadata endpoint itself to use HTTPS and ask MirrorManager for
# HTTPS mirrors only. Repository checksums and OpenPGP signatures remain the
# content-integrity layers; authenticated transport separately protects mirror
# identity and keeps requested metadata/package paths off a passive link.
# Scope: fedora*.repo metalinks (RPM Fusion / VSCodium / negativo17 use HTTPS
# baseurl= directly). Idempotent and fail-closed on unsupported syntax.
REPO_DIR=/etc/yum.repos.d
repos_patched=0
repo_has_unrestricted_metalink() {
    [ -f "$1" ] && [ ! -L "$1" ] || return 0
    awk '
        /^[[:space:]]*metalink[[:space:]]*=/ {
            url = $0
            sub(/^[[:space:]]*metalink[[:space:]]*=[[:space:]]*/, "", url)
            sub(/[[:space:]#;].*$/, "", url)
            if (url !~ /^https:\/\// ||
                    url !~ /[?&]protocol=https([&#]|$)/) {
                bad = 1
            }
        }
        END { exit bad ? 0 : 1 }
    ' "$1"
}
restrict_repo_metalinks() {
    [ -f "$1" ] && [ ! -L "$1" ] || return 1
    sed -i -E '
        /^[[:space:]]*metalink[[:space:]]*=/ {
            /[?&]protocol=https([&#;[:space:]]|$)/! {
                s|^([[:space:]]*metalink[[:space:]]*=[[:space:]]*https://[^[:space:]#;]+)([[:space:]]*([#;].*)?)$|\1\&protocol=https\2|
            }
        }
    ' "$1"
    ! repo_has_unrestricted_metalink "$1"
}
for repo in "$REPO_DIR"/fedora*.repo; do
    [ -e "$repo" ] || [ -L "$repo" ] || continue
    if [ ! -f "$repo" ] || [ -L "$repo" ]; then
        log "  [FAIL] $(basename "$repo"): repository config is not a regular non-symlink file"
        exit 1
    fi
    if repo_has_unrestricted_metalink "$repo"; then
        if ! restrict_repo_metalinks "$repo"; then
            log "  [FAIL] $(basename "$repo"): unsupported or unrestricted metalink syntax"
            exit 1
        fi
        repos_patched=$((repos_patched + 1))
        log "  [patched] $(basename "$repo"): metalink restricted to HTTPS mirrors"
    fi
done
# Fail-visible, line-complete drift check: `sed` exits 0 even when its pattern
# matched nothing, and a file-level positive grep can hide one unrestricted
# line behind another already-correct line. Inspect every active metalink line.
metalink_unrestricted=0
repos_inspected=0
for repo in "$REPO_DIR"/fedora*.repo; do
    [ -e "$repo" ] || [ -L "$repo" ] || continue
    if [ ! -f "$repo" ] || [ -L "$repo" ]; then
        log "  [FAIL] $(basename "$repo"): repository config became unsafe"
        metalink_unrestricted=$((metalink_unrestricted + 1))
        continue
    fi
    repos_inspected=$((repos_inspected + 1))
    if repo_has_unrestricted_metalink "$repo"; then
        log "  [FAIL] $(basename "$repo"): metalink endpoint/filter is not HTTPS-only (vendor .repo format drift?)"
        metalink_unrestricted=$((metalink_unrestricted + 1))
    fi
done
if [ "$repos_inspected" -eq 0 ]; then
    log "STEP 2b FAILED: no regular Fedora repository config was inspected"
    exit 1
fi
if [ "$metalink_unrestricted" -gt 0 ]; then
    log "STEP 2b FAILED: $metalink_unrestricted Fedora repo config(s) violate the HTTPS transport contract"
    exit 1
fi
log "STEP 2b: Fedora metadata/mirror transport restricted to HTTPS ($repos_patched repos patched, 0 unrestricted)"

# ====================================================================
# STEP 3: REMOVED — GRUB menu_auto_hide stays (Fedora Speed-mode)
# ====================================================================
# Was: noid-grub-menu-show.service (menu always visible). Reverted in favor
# of the Fedora default Speed-mode — menu_auto_hide=1 is set by
# grub-set-bootflag after the first successful boot (~3s boot-time saving);
# the GRUB menu stays reachable via ESC during POST (Fedora uses ESC/F8,
# NOT SHIFT).
log "STEP 3: skipped — Decision #9 reverted in v13 (menu_auto_hide stays = NoID Privacy Speed-mode)"

# ====================================================================
# STEP 4: Hardware detection + cmdline extras
# ====================================================================
log "STEP 4: hardware detection..."

# SHARED-LOGIC-MARKER: this CPU+GPU detection is logging-only here
# (build-VM context, target write deferred to STEP 4b). When the detection
# logic in the STEP 4b post-script changes (new CPU vendor or GPU class),
# update both for diagnostic consistency.
CPU_EXTRA=""
if grep -q GenuineIntel /proc/cpuinfo 2>/dev/null; then
    # Intel-specific CPU-vulnerability mitigations (no-ops on AMD) — see
    # the header Token notes.
    CPU_EXTRA="intel_iommu=on tsx=off l1tf=full l1d_flush=on kvm-intel.vmentry_l1d_flush=always"
    log "  CPU: Intel → $CPU_EXTRA"
elif grep -q AuthenticAMD /proc/cpuinfo 2>/dev/null; then
    CPU_EXTRA="amd_iommu=on"
    log "  CPU: AMD → $CPU_EXTRA"
else
    log "  CPU: neither Intel nor AMD (unsupported for IOMMU flags)"
fi

GPU_EXTRA=""
HAS_NVIDIA=0
if command -v lspci >/dev/null 2>&1; then
    if lspci -nn 2>/dev/null | grep -qE "VGA.*NVIDIA|3D controller.*NVIDIA|Display controller.*NVIDIA"; then
        # Do NOT blacklist nouveau here — the image ships nouveau+NVK as
        # default (Module 19: docs-only, manual opt-in; akmod-nvidia's RPM
        # scriptlet creates the blacklist itself). GPU_EXTRA stays empty.
        HAS_NVIDIA=1
        log "  GPU: NVIDIA detected (nouveau+NVK default, see 19-nvidia-drivers.md for proprietary opt-in)"
    elif lspci -nn 2>/dev/null | grep -qE "VGA.*AMD|VGA.*ATI|VGA.*Radeon"; then
        log "  GPU: AMD (amdgpu auto-loads, no blacklist)"
    elif lspci -nn 2>/dev/null | grep -qE "VGA.*Intel"; then
        log "  GPU: Intel integrated (i915 auto-loads)"
    else
        log "  GPU: not identified"
    fi
else
    log "  GPU: lspci missing, skipping GPU detection"
fi

# ====================================================================
# STEP 4 hardware detection: NO direct cmdline write at compose-time
# ====================================================================
# Compose-time grubby/cmdline writes freeze build-VM state (sparse
# /etc/kernel/cmdline + build-VM UUID) into the squashfs; the end-user
# install then inherits it because kernel-install's 90-loaderentry.install
# prefers /etc/kernel/cmdline over /proc/cmdline. STEP 4 is therefore
# logging-only (HAS_NVIDIA feeds STEP 5); all target cmdline
# writes are deferred to the STEP 4b post-script, which runs in the real
# target sysroot AFTER bootloader install.
log "STEP 4: hardware detection (logging only — cmdline write deferred to STEP 4b)"

# ====================================================================
# STEP 4b: Executable Anaconda end-user-install target kernel-cmdline contract
# ====================================================================
# Native mechanism: Fedora 44 liveinst parses
# /usr/share/anaconda/interactive-defaults.ks when no explicit kickstart was
# passed. Its packaged appendPostScripts() helper is not called by the shipped
# execution path, so a detached /usr/share/anaconda/post-scripts/*.ks file is
# only inert source. Generate the target `%post` once, then append those exact
# bytes to the interactive kickstart Anaconda actually parses. The post runs
# chrooted in the real target sysroot after bootloader installation, with the
# target /etc/fstab and real root/LUKS UUIDs.
#
# Nested-heredoc avoidance (CRITICAL): ksflatten would stop at a literal
# inner `%end` ("Section %post does not end with %end"). Workaround: printf
# for the outer %post/%end markers + heredoc for the script body only.
log "STEP 4b: generating and binding the interactive target-karg post-script"
TARGET_KARG_FRAGMENT=/usr/share/anaconda/noid-target-kernel-cmdline.ks
{
    printf '%s\n' '%post --erroronfail --interpreter=/bin/bash --log=/var/log/noid-anaconda-kernel-cmdline.log'
    cat <<'NOID_KARGS_EOF'
set -euo pipefail

log() { echo "[noid-target-kargs] $*"; }
log "=== NoID Privacy target kernel cmdline post-script ==="

# Base kernel-cmdline tokens are defined by NOID_BASE_ARGS below. The compose
# `bootloader --append=` string is the Intel build-time variant and therefore
# additionally contains `intel_iommu=on`; it is intentionally not byte-identical
# to this hardware-neutral base. Structural tests derive both classifications.
# plymouth.use-simpledrm=1 is NOT here — it's NVIDIA-conditional via
# GPU_EXTRA (AMD RDNA3 + LUKS regression
# https://forums.almalinux.org/t/plymouth-luks-password-prompt-does-not-show-typing-feedback-on-systems-with-rdna3-amd-gpu-kernel-6-12/7111).
NOID_BASE_ARGS="rhgb quiet init_on_alloc=1 init_on_free=1 slab_nomerge pti=on vsyscall=none vdso32=0 debugfs=off page_alloc.shuffle=1 randomize_kstack_offset=on spec_store_bypass_disable=on module.sig_enforce=1 iommu.strict=1 iommu.passthrough=0 lockdown=integrity mitigations=auto proc_mem.force_override=never hash_pointers=always hardened_usercopy=1 kfence.sample_interval=100 kfence.deferrable=1 efi=disable_early_pci_dma ia32_emulation=0 bdev_allow_write_mounted=0 rd.emergency=halt rd.shell=0 loglevel=4 systemd.ssh_auto=no random.trust_cpu=off random.trust_bootloader=off audit=1 audit_backlog_limit=8192 zswap.enabled=0 kvm.nx_huge_pages=force mmio_stale_data=full retbleed=auto gather_data_sampling=force reg_file_data_sampling=on indirect_target_selection=force vmscape=force efi_pstore.pstore_disable=1 erst_disable spectre_v2=on spectre_bhi=on mds=full tsx_async_abort=full srbds=on spec_rstack_overflow=safe-ret tsa=on"

# Hardware-conditional extras detected on REAL target hardware (not build VM).
# SHARED-LOGIC-MARKER: identical CPU detection in compose-time STEP 4 above
# (build-VM context) — when CPU_EXTRA changes here, also update STEP 4 logging.
CPU_EXTRA=""
if grep -q GenuineIntel /proc/cpuinfo 2>/dev/null; then
    CPU_EXTRA="intel_iommu=on tsx=off l1tf=full l1d_flush=on kvm-intel.vmentry_l1d_flush=always"
elif grep -q AuthenticAMD /proc/cpuinfo 2>/dev/null; then
    CPU_EXTRA="amd_iommu=on"
fi

# GPU_EXTRA: plymouth.use-simpledrm=1 ONLY for NVIDIA. Vendor's
# 99-nvidia-dracut.conf OMITS nvidia from initramfs by design (slimmer
# initramfs, simpler kernel updates) — without simpledrm, LUKS prompt
# renders to wrong/blank framebuffer because no GPU driver is available
# pre-pivot. On Intel/AMD: GPU drivers (i915/amdgpu/nouveau) ARE in
# initramfs by default, simpledrm is NOT needed AND can regress AMD RDNA3
# LUKS prompt input echo (AlmaLinux 9.5 / kernel 6.12 forum thread).
GPU_EXTRA=""
if command -v lspci >/dev/null 2>&1; then
    if lspci -nn 2>/dev/null | grep -qE "VGA.*NVIDIA|3D controller.*NVIDIA|Display controller.*NVIDIA"; then
        GPU_EXTRA="plymouth.use-simpledrm=1"
    fi
fi

NOID_TARGET_ARGS=$(echo "$NOID_BASE_ARGS $CPU_EXTRA $GPU_EXTRA" | tr -s ' ' | sed 's/^ //;s/ $//')
log "target NoID Privacy args: $NOID_TARGET_ARGS"

# Helper: append args to current set, deduping
append_args() {
    for arg in $1; do
        # Fedora's 92-tuned.install owns this literal GRUB/BLS transport macro.
        # It is not a kernel argument and must never enter /etc/kernel/cmdline.
        [ "$arg" = "\$tuned_params" ] && continue
        case " $current " in
            *" $arg "*) ;;
            *) current="$current $arg" ;;
        esac
    done
    current=$(echo "$current" | tr -s ' ' | sed 's/^ //;s/ $//')
}

# Collect existing kernel cmdline state from /etc/default/grub +
# /etc/kernel/cmdline + BLS entries
current=""
if [ -f /etc/default/grub ]; then
    grub_current=$(grep -E '^GRUB_CMDLINE_LINUX=' /etc/default/grub | head -1 | sed 's/^[^"]*"\(.*\)"$/\1/' || true)
    append_args "$grub_current"
fi
if [ -f /etc/kernel/cmdline ]; then
    kernel_current=$(tr -s '[:space:]' ' ' < /etc/kernel/cmdline | sed 's/^ //;s/ $//' || true)
    append_args "$kernel_current"
fi
if [ -d /boot/loader/entries ]; then
    for entry in /boot/loader/entries/*.conf; do
        [ -f "$entry" ] || continue
        bls_current=$(awk '$1=="options" {$1=""; sub(/^ /, ""); print; exit}' "$entry" || true)
        append_args "$bls_current"
    done
fi

# Derive root= from target /etc/fstab (authoritative for real install)
root_spec=""
root_opts=""
if [ -f /etc/fstab ]; then
    root_spec=$(awk '$1 !~ /^#/ && $2 == "/" {print $1; exit}' /etc/fstab || true)
    root_opts=$(awk '$1 !~ /^#/ && $2 == "/" {print $4; exit}' /etc/fstab || true)
fi

root_args=""
if [ -n "$root_spec" ] && [ "$root_spec" != "none" ]; then
    root_args="root=$root_spec ro"
fi

rootflags=""
for opt in $(printf '%s\n' "$root_opts" | tr ',' ' '); do
    case "$opt" in
        subvol=*|subvolid=*) rootflags="${rootflags:+$rootflags,}$opt" ;;
    esac
done
if [ -n "$rootflags" ]; then
    root_args="$root_args rootflags=$rootflags"
fi

# Fallback: if /etc/fstab gave no root, try to keep existing root from BLS
if [ -z "$root_args" ]; then
    for arg in $current; do
        case "$arg" in
            root=*|rootflags=*|ro|rw)
                case " $root_args " in
                    *" $arg "*) ;;
                    *) root_args="$root_args $arg" ;;
                esac
                ;;
        esac
    done
    root_args=$(echo "$root_args" | tr -s ' ' | sed 's/^ //;s/ $//')
fi

if ! echo " $root_args " | grep -q ' root='; then
    log "FAIL: could not determine target root= from /etc/fstab or BLS"
    exit 1
fi

# Filter NoID Privacy-managed arg families from existing $current.
# Without this filter, hostile/stale build-state values (e.g. module.sig_
# enforce=0 if some upstream changed default) survive the merge as
# duplicates next to our intended values — kernel uses last value, but
# parser semantics for duplicates are version-dependent and risky.
is_noid_managed_arg() {
    case "$1" in
        rhgb|quiet|slab_nomerge|efi=disable_early_pci_dma|erst_disable)
            return 0 ;;
        plymouth.use-simpledrm=*|init_on_alloc=*|init_on_free=*|pti=*|vsyscall=*|vdso32=*|debugfs=*|page_alloc.shuffle=*|randomize_kstack_offset=*|spec_store_bypass_disable=*|module.sig_enforce=*|iommu.strict=*|iommu.passthrough=*|lockdown=*|slab_debug=*|slub_debug=*|mitigations=*|proc_mem.force_override=*|hash_pointers=*|hardened_usercopy=*|kfence.sample_interval=*|kfence.deferrable=*|ia32_emulation=*|bdev_allow_write_mounted=*|rd.emergency=*|rd.shell=*|loglevel=*|systemd.ssh_auto=*|random.trust_cpu=*|random.trust_bootloader=*|intel_iommu=*|amd_iommu=*|tsx=*|l1tf=*|l1d_flush=*|kvm-intel.vmentry_l1d_flush=*|acpi_backlight=*|mem_sleep_default=*|audit=*|audit_backlog_limit=*|zswap.enabled=*|kvm.nx_huge_pages=*|mmio_stale_data=*|retbleed=*|gather_data_sampling=*|reg_file_data_sampling=*|indirect_target_selection=*|vmscape=*|efi_pstore.pstore_disable=*|spectre_v2=*|spectre_v2_user=*|spectre_bhi=*|mds=*|tsx_async_abort=*|srbds=*|spec_rstack_overflow=*|tsa=*)
            return 0 ;;
    esac
    return 1
}

# Build merged final cmdline: root_args first, then non-managed inherited
# args (Live-ISO/install-only stuff filtered out), the per-LUKS option, then
# NoID Privacy target args.
merged=""
for arg in $root_args; do
    case " $merged " in
        *" $arg "*) ;;
        *) merged="$merged $arg" ;;
    esac
done
for arg in $current; do
    if is_noid_managed_arg "$arg"; then
        continue
    fi
    case "$arg" in
        # Strip root + Live-ISO + install-only args from inherited state
        root=*|rootflags=*|ro|rw|BOOT_IMAGE=*|initrd=*|inst.*|stage2=*|rd.live.*|liveimg|check)
            continue ;;
    esac
    case " $merged " in
        *" $arg "*) ;;
        *) merged="$merged $arg" ;;
    esac
done

# Publish the per-volume initramfs option before the installed system's first
# boot whenever Anaconda's target BLS already exposes the LUKS UUID. This keeps
# the normal encrypted-install path byte-aligned with the firstboot
# canonicalizer and avoids manufacturing a needless first-session delta.
LUKS_UUID=$(printf '%s\n' "$current" | tr ' ' '\n' \
    | sed -n 's/^rd\.luks\.uuid=luks-\([0-9a-fA-F-]\{20,\}\)$/\1/p' \
    | head -1)
if [ -n "$LUKS_UUID" ]; then
    LUKS_KARG="rd.luks.options=${LUKS_UUID}=tries=0,discard"
    case " $merged " in
        *" $LUKS_KARG "*) ;;
        *) merged="$merged $LUKS_KARG" ;;
    esac
    log "target LUKS unlock-retry arg: $LUKS_KARG"
fi
for arg in $NOID_TARGET_ARGS; do
    case " $merged " in
        *" $arg "*) ;;
        *) merged="$merged $arg" ;;
    esac
done
merged=$(echo "$merged" | tr -s ' ' | sed 's/^ //;s/ $//')

if [ -z "$merged" ]; then
    log "FAIL: computed empty kernel cmdline"
    exit 1
fi
case " $merged " in
    *" \$tuned_params "*)
        log "FAIL: tuned BLS transport macro entered semantic kernel cmdline"
        exit 1
        ;;
esac

# /etc/default/grub gets cmdline WITHOUT root=/rootflags=/ro/rw — those
# are managed by Anaconda's bootloader-installer + kernel-install per BLS
# entry. GRUB_CMDLINE_LINUX is just the additional kargs portion.
grub_default_args=""
for arg in $merged; do
    case "$arg" in
        root=*|rootflags=*|ro|rw) continue ;;
    esac
    case " $grub_default_args " in
        *" $arg "*) ;;
        *) grub_default_args="$grub_default_args $arg" ;;
    esac
done
grub_default_args=$(echo "$grub_default_args" | tr -s ' ' | sed 's/^ //;s/ $//')

if grep -q '^GRUB_CMDLINE_LINUX=' /etc/default/grub 2>/dev/null; then
    # awk-based replacement instead of sed-escape.
    # sed needs to escape /, &, \ in replacement — fragile with future kargs
    # that may contain paths/URLs. awk -v passes value as literal.
    awk -v new="$grub_default_args" '
        /^GRUB_CMDLINE_LINUX=/ { print "GRUB_CMDLINE_LINUX=\"" new "\""; next }
        { print }
    ' /etc/default/grub > /etc/default/grub.new && mv /etc/default/grub.new /etc/default/grub
    chmod 0644 /etc/default/grub
else
    printf 'GRUB_CMDLINE_LINUX="%s"\n' "$grub_default_args" >> /etc/default/grub
fi
command -v restorecon >/dev/null 2>&1 \
    || { log "FAIL: restorecon is unavailable"; exit 1; }
command -v matchpathcon >/dev/null 2>&1 \
    || { log "FAIL: matchpathcon is unavailable"; exit 1; }
restorecon -F /etc/default/grub
matchpathcon -V /etc/default/grub

# /etc/kernel/cmdline is the canonical input for future kernel-install
# transactions (preferred over /proc/cmdline by 90-loaderentry.install).
mkdir -p /etc/kernel
printf '%s\n' "$merged" > /etc/kernel/cmdline
chmod 0644 /etc/kernel/cmdline

# Fedora's 92-tuned.install adds one literal $tuned_params transport macro to
# each normal BLS options line after 90-loaderentry.install consumes the
# semantic /etc/kernel/cmdline. Bind that native division exactly: the macro is
# required in BLS, but forbidden from the kernel-install source and GRUB args.
#
# Anaconda has already installed the kernel, generated the initramfs and
# published these BLS entries before this target %post runs. Calling
# `kernel-install add` again solely to change their options executes every
# install plugin, including Fedora's dracut generator, and redundantly rebuilds
# the same initramfs. Update only the existing Type #1 entry field atomically;
# future real kernel transactions still use the complete native plugin stack.
publish_target_bls_options() {
    local bls_dir=$1 options=$2 entry temporary option_count
    local -a entries=()

    if [ ! -d "$bls_dir" ] || [ -L "$bls_dir" ]; then
        log "FAIL: BLS directory is missing or symlinked: $bls_dir"
        return 1
    fi

    shopt -s nullglob
    entries=("$bls_dir"/*.conf)
    if [ "${#entries[@]}" -eq 0 ]; then
        log "FAIL: no BLS entries found under $bls_dir"
        return 1
    fi

    # Validate the complete set before replacing the first entry. A malformed
    # later entry must not leave an avoidable partial publication.
    for entry in "${entries[@]}"; do
        if [ ! -f "$entry" ] || [ -L "$entry" ]; then
            log "FAIL: BLS entry is non-regular or symlinked: $entry"
            return 1
        fi
        option_count=$(awk '$1=="options" {count++} END {print count+0}' "$entry")
        if [ "$option_count" -ne 1 ]; then
            log "FAIL: BLS entry has noncanonical options cardinality: $entry"
            return 1
        fi
    done

    for entry in "${entries[@]}"; do
        temporary=$(mktemp "$bls_dir/.noid-bls.XXXXXXXX")
        if ! awk -v options="$options" '
            $1=="options" { count++; print "options " options; next }
            { print }
            END { if (count != 1) exit 7 }
        ' "$entry" > "$temporary"; then
            rm -f -- "$temporary"
            log "FAIL: BLS entry changed during publication: $entry"
            return 1
        fi
        if ! chmod 0644 "$temporary" \
                || ! chown root:root "$temporary" \
                || ! restorecon -F "$temporary" \
                || ! matchpathcon -V "$temporary"; then
            rm -f -- "$temporary"
            log "FAIL: could not prepare atomic BLS replacement: $entry"
            return 1
        fi
        if ! sync -- "$temporary" || ! mv -fT "$temporary" "$entry"; then
            rm -f -- "$temporary"
            log "FAIL: could not publish atomic BLS replacement: $entry"
            return 1
        fi
        if ! matchpathcon -V "$entry"; then
            log "FAIL: published BLS entry has the wrong SELinux label: $entry"
            return 1
        fi
    done
    sync -- "$bls_dir"
}

fail=0
bls_count=0
expected_bls_options="$merged \$tuned_params"
publish_target_bls_options /boot/loader/entries "$expected_bls_options"
if [ -d /boot/loader/entries ]; then
    for entry in /boot/loader/entries/*.conf; do
        [ -f "$entry" ] && [ ! -L "$entry" ] || continue
        bls_count=$((bls_count + 1))
        actual_bls_options=$(awk '$1=="options" {$1=""; sub(/^ /, ""); count++; value=$0} END {if (count == 1) print value}' "$entry")
        if [ "$actual_bls_options" != "$expected_bls_options" ]; then
            log "FAIL: $entry is not semantic cmdline plus one tuned macro"
            fail=$((fail + 1))
        fi
    done
fi
if [ "$bls_count" -eq 0 ]; then
    log "FAIL: no BLS entries found under /boot/loader/entries"
    fail=$((fail + 1))
fi
if ! grep -q 'root=' /etc/kernel/cmdline; then
    log "FAIL: /etc/kernel/cmdline missing root="
    fail=$((fail + 1))
fi
if ! grep -q 'module.sig_enforce=1' /etc/kernel/cmdline; then
    log "FAIL: /etc/kernel/cmdline missing module.sig_enforce=1"
    fail=$((fail + 1))
fi
if [ "$fail" -ne 0 ]; then
    log "FAIL: $fail kernel-cmdline verification failures"
    exit 1
fi

# These two files exist only to bind and verify the installer payload before
# this target %post runs. They are authored by M01 rather than owned by an RPM,
# so removing anaconda-core later cannot remove them. Leave no inert installer
# implementation behind on the installed workstation.
remove_installer_only_payload() {
    local path=$1 expected_metadata=$2
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
        return 0
    fi
    if [ ! -f "$path" ] || [ -L "$path" ]; then
        log "FAIL: installer-only payload is non-regular/symlinked: $path"
        return 1
    fi
    if [ "$(stat -c '%U:%G:%a' -- "$path")" != "$expected_metadata" ]; then
        log "FAIL: installer-only payload metadata differs: $path"
        return 1
    fi
    rm -f -- "$path"
    if [ -e "$path" ] || [ -L "$path" ]; then
        log "FAIL: installer-only payload survived removal: $path"
        return 1
    fi
}
remove_installer_only_payload \
    /usr/share/anaconda/noid-target-kernel-cmdline.ks root:root:644
remove_installer_only_payload \
    /usr/libexec/noid-verify-target-karg-payload root:root:755
log "removed installer-only target fragment and compose verifier"

log "final /etc/kernel/cmdline: $(cat /etc/kernel/cmdline)"
log "=== NoID Privacy target kernel cmdline post-script complete ==="
NOID_KARGS_EOF
    printf '%s\n' '%end'
} > "$TARGET_KARG_FRAGMENT"
chmod 0644 "$TARGET_KARG_FRAGMENT"
chown root:root "$TARGET_KARG_FRAGMENT"

# A single source block drives both the separately inspectable audit fragment
# and the executable kickstart. Appending, rather than duplicating the body in
# this module, makes byte drift impossible. Remove the obsolete detached path
# so a future Anaconda behavior change cannot execute a second copy.
rm -f /usr/share/anaconda/post-scripts/90-noid-kernel-cmdline.ks
cat "$TARGET_KARG_FRAGMENT" >> /usr/share/anaconda/interactive-defaults.ks
chmod 0644 /usr/share/anaconda/interactive-defaults.ks
chown root:root /usr/share/anaconda/interactive-defaults.ks
sync -- "$TARGET_KARG_FRAGMENT"
sync -- /usr/share/anaconda/interactive-defaults.ks
log "  [OK] target-karg post-script is byte-bound into interactive-defaults.ks"

# The live-image compose has a build-internal BLS entry whose root topology is
# deliberately not propagated to end-user installations. Prove the two payloads
# that Anaconda uses for the real target here; M01 firstboot -> M20 -> M21
# ordering and the three-pass runtime gate prove the resulting installed BLS.
log "STEP 4b.1: installing target-karg payload verifier"
install -d -m 0755 -o root -g root /usr/libexec
cat > /usr/libexec/noid-verify-target-karg-payload <<'KARG_PAYLOAD_VERIFY_EOF'
#!/bin/bash
# Read-only compose-time verifier for the M01 target-install karg payload.
# The target %post removes this verifier and its standalone fragment after their
# last use; M41 later removes anaconda-core and the interactive-installer file.
# Every authoritative caller therefore runs before target cleanup.
set -euo pipefail

INTERACTIVE=/usr/share/anaconda/interactive-defaults.ks
TARGET_POST=/usr/share/anaconda/noid-target-kernel-cmdline.ks
EXPECTED_METADATA=root:root:644

fail() {
    echo "noid-verify-target-karg-payload: FAIL: $*" >&2
    exit 1
}

check_payload_file() {
    local path=$1
    [ -f "$path" ] && [ ! -L "$path" ] || fail "missing/non-regular/symlinked payload: $path"
    [ "$(stat -c '%U:%G:%a' -- "$path")" = "$EXPECTED_METADATA" ] || \
        fail "wrong metadata on payload: $path"
}

# Require exactly one active assignment, exactly one member of the
# module.sig_enforce family, and require that member to be =1. Anchored active
# lines mean a comment containing the desired token cannot satisfy the proof.
check_single_sig_assignment() {
    local path=$1 prefix=$2
    awk -v prefix="$prefix" '
        index($0, prefix) == 1 {
            records++
            if (substr($0, length($0), 1) != "\"") next
            value = substr($0, length(prefix) + 1,
                           length($0) - length(prefix) - 1)
            count = split(value, fields, /[[:space:]]+/)
            for (i = 1; i <= count; i++) {
                if (fields[i] ~ /^module[.]sig_enforce=/) family++
                if (fields[i] == "module.sig_enforce=1") exact++
            }
        }
        END { exit !(records == 1 && family == 1 && exact == 1) }
    ' "$path"
}

check_single_active_marker() {
    local path=$1 marker=$2
    local found
    # grep -F preserves backslash bytes such as the printf format's literal
    # \n; awk -v would interpret them while importing the marker.
    found=$(sed 's/^[[:space:]]*//' "$path" | grep -cFx -- "$marker" || true)
    [ "$found" -eq 1 ]
}

check_payload_file "$INTERACTIVE"
check_payload_file "$TARGET_POST"

# The complete target fragment must be the exact tail of the kickstart that
# liveinst parses. This proves execution reachability, not merely the presence
# of a second correct-looking but inert file.
target_bytes=$(stat -c %s -- "$TARGET_POST")
interactive_bytes=$(stat -c %s -- "$INTERACTIVE")
[ "$target_bytes" -gt 0 ] && [ "$interactive_bytes" -gt "$target_bytes" ] || \
    fail "interactive/target payload sizes are invalid"
tail -c "$target_bytes" -- "$INTERACTIVE" | cmp -s - "$TARGET_POST" || \
    fail "target post-script is not the exact interactive kickstart tail"
[ "$(grep -cFx '%post --erroronfail --interpreter=/bin/bash --log=/var/log/noid-anaconda-kernel-cmdline.log' "$INTERACTIVE")" -eq 1 ] || \
    fail "interactive kickstart lacks one exact target %post opener"
[ "$(grep -cFx '%end' "$INTERACTIVE")" -eq 1 ] || \
    fail "interactive kickstart lacks one exact target %end"
check_single_sig_assignment "$INTERACTIVE" 'bootloader --timeout=3 --append="' || \
    fail "interactive installer lacks one conflict-free active module.sig_enforce=1"
check_single_sig_assignment "$TARGET_POST" 'NOID_BASE_ARGS="' || \
    fail "target post-script lacks one conflict-free active module.sig_enforce=1"

# Bind the target assignment to its durable publication and BLS postcondition;
# merely retaining a correct-looking variable assignment is not sufficient.
for marker in \
        'printf '\''%s\n'\'' "$merged" > /etc/kernel/cmdline' \
        'publish_target_bls_options /boot/loader/entries "$expected_bls_options"' \
        'expected_bls_options="$merged \$tuned_params"'; do
    check_single_active_marker "$TARGET_POST" "$marker" || \
        fail "target post-script is missing load-bearing marker: $marker"
done

echo "noid-verify-target-karg-payload: PASS: installer and target-post contracts are exact"
KARG_PAYLOAD_VERIFY_EOF
chmod 0755 /usr/libexec/noid-verify-target-karg-payload
chown root:root /usr/libexec/noid-verify-target-karg-payload
if ! /usr/libexec/noid-verify-target-karg-payload; then
    log "  [FAIL] target-karg payload verification failed"
    exit 1
fi
log "  [OK] target-karg payload verifier installed and passed"

# Closed firstboot merger. grubby is retained below as Fedora's native
# hardware/LUKS mutation mechanism, but this helper is the final authority for
# ordering and byte parity. It preserves dynamic target arguments, emits every
# NoID Privacy-managed family once in manifest order, and publishes one exact options
# line to /etc/kernel/cmdline and every normal BLS entry.
cat > /usr/libexec/noid-canonicalize-kernel-cmdline <<'CMDLINE_CANONICALIZER_EOF'
#!/bin/bash
set -euo pipefail

[ "$#" -eq 1 ] && [ "$1" = --publish ] || {
    echo "usage: $0 --publish" >&2
    exit 2
}

ROOT=
CMDLINE_FILE=/proc/cmdline
CPUINFO_FILE=/proc/cpuinfo
LSPCI_BIN=lspci

if [ "${NOID_TEST_MODE:-0}" = 1 ]; then
    ROOT=${NOID_TEST_ROOT:?NOID_TEST_ROOT is required in test mode}
    CMDLINE_FILE=${NOID_TEST_CMDLINE_FILE:?NOID_TEST_CMDLINE_FILE is required in test mode}
    CPUINFO_FILE=${NOID_TEST_CPUINFO_FILE:?NOID_TEST_CPUINFO_FILE is required in test mode}
    LSPCI_BIN=${NOID_TEST_LSPCI_BIN:?NOID_TEST_LSPCI_BIN is required in test mode}
    [[ "$ROOT" = /* ]] && [ -d "$ROOT" ] && [ ! -L "$ROOT" ] \
        || { echo "ERROR: invalid test root" >&2; exit 2; }
    ROOT=$(realpath -e "$ROOT")
    [[ "$CMDLINE_FILE" = "$ROOT"/* ]] \
        && [[ "$CPUINFO_FILE" = "$ROOT"/* ]] \
        && [[ "$LSPCI_BIN" = "$ROOT"/* ]] \
        || { echo "ERROR: test inputs must remain below the test root" >&2; exit 2; }
elif [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: must run as root" >&2
    exit 1
fi

root_path() { printf '%s%s\n' "$ROOT" "$1"; }
KERNEL_CMDLINE=$(root_path /etc/kernel/cmdline)
GRUB_DEFAULT=$(root_path /etc/default/grub)
BLS_DIR=$(root_path /boot/loader/entries)
FSTAB=$(root_path /etc/fstab)
GAMING_FLAG=$(root_path /var/lib/noid-privacy/gaming-mode.enabled)

NOID_BASE_ARGS="rhgb quiet init_on_alloc=1 init_on_free=1 slab_nomerge pti=on vsyscall=none vdso32=0 debugfs=off page_alloc.shuffle=1 randomize_kstack_offset=on spec_store_bypass_disable=on module.sig_enforce=1 iommu.strict=1 iommu.passthrough=0 lockdown=integrity mitigations=auto proc_mem.force_override=never hash_pointers=always hardened_usercopy=1 kfence.sample_interval=100 kfence.deferrable=1 efi=disable_early_pci_dma ia32_emulation=0 bdev_allow_write_mounted=0 rd.emergency=halt rd.shell=0 loglevel=4 systemd.ssh_auto=no random.trust_cpu=off random.trust_bootloader=off audit=1 audit_backlog_limit=8192 zswap.enabled=0 kvm.nx_huge_pages=force mmio_stale_data=full retbleed=auto gather_data_sampling=force reg_file_data_sampling=on indirect_target_selection=force vmscape=force efi_pstore.pstore_disable=1 erst_disable spectre_v2=on spectre_bhi=on mds=full tsx_async_abort=full srbds=on spec_rstack_overflow=safe-ret tsa=on"

# M01 is the sole canonical publisher for these managed boot arguments. The
# Gaming helper expresses its reviewed profile choice through one empty,
# private-state receipt; accepting raw grubby output here would create a second
# authority and let the next firstboot reconciliation silently undo the choice.
# The receipt therefore authorizes only the two documented compatibility
# values, only with exact metadata, and never supplies arbitrary arguments.
gaming_mode=off
if [ -e "$GAMING_FLAG" ] || [ -L "$GAMING_FLAG" ]; then
    gaming_state_dir=$(dirname "$GAMING_FLAG")
    if [ -n "$ROOT" ]; then
        gaming_expected_meta="$(id -u):$(id -g):644:1:0"
        gaming_expected_dir="$(id -u):$(id -g):755"
    else
        gaming_expected_meta=0:0:644:1:0
        gaming_expected_dir=0:0:755
    fi
    [ -d "$gaming_state_dir" ] && [ ! -L "$gaming_state_dir" ] \
        && [ "$(stat -c '%u:%g:%a' "$gaming_state_dir" 2>/dev/null || true)" = "$gaming_expected_dir" ] \
        && [ -f "$GAMING_FLAG" ] && [ ! -L "$GAMING_FLAG" ] \
        && [ "$(stat -c '%u:%g:%a:%h:%s' "$GAMING_FLAG" 2>/dev/null || true)" = "$gaming_expected_meta" ] \
        || { echo "ERROR: unsafe Gaming profile receipt" >&2; exit 1; }
    if [ -z "$ROOT" ]; then
        command -v matchpathcon >/dev/null 2>&1 \
            || { echo "ERROR: matchpathcon is unavailable" >&2; exit 1; }
        matchpathcon -V "$GAMING_FLAG" >&2 \
            || { echo "ERROR: Gaming profile receipt label differs" >&2; exit 1; }
    fi
    gaming_mode=on
    NOID_BASE_ARGS=${NOID_BASE_ARGS/vdso32=0/vdso32=1}
    NOID_BASE_ARGS=${NOID_BASE_ARGS/ia32_emulation=0/ia32_emulation=1}
fi
case " $NOID_BASE_ARGS " in
    *" vdso32=1 "*" ia32_emulation=1 "*)
        [ "$gaming_mode" = on ] \
            || { echo "ERROR: Gaming profile values lack exact authority" >&2; exit 1; }
        ;;
    *" vdso32=0 "*" ia32_emulation=0 "*)
        [ "$gaming_mode" = off ] \
            || { echo "ERROR: hardened profile values differ" >&2; exit 1; }
        ;;
    *)
        echo "ERROR: incomplete ia32/vDSO32 profile" >&2
        exit 1
        ;;
esac

CPU_EXTRA=""
if grep -q GenuineIntel "$CPUINFO_FILE" 2>/dev/null; then
    CPU_EXTRA="intel_iommu=on tsx=off l1tf=full l1d_flush=on kvm-intel.vmentry_l1d_flush=always"
elif grep -q AuthenticAMD "$CPUINFO_FILE" 2>/dev/null; then
    CPU_EXTRA="amd_iommu=on"
fi

GPU_EXTRA=""
lspci_output=""
if command -v "$LSPCI_BIN" >/dev/null 2>&1; then
    lspci_output=$("$LSPCI_BIN" -nn 2>/dev/null) || {
        echo "ERROR: PCI inventory failed" >&2
        exit 1
    }
fi
if grep -qE "VGA.*NVIDIA|3D controller.*NVIDIA|Display controller.*NVIDIA" \
        <<< "$lspci_output"; then
    GPU_EXTRA="plymouth.use-simpledrm=1"
fi
NOID_TARGET_ARGS=$(printf '%s\n' "$NOID_BASE_ARGS $CPU_EXTRA $GPU_EXTRA" \
    | tr -s ' ' | sed 's/^ //;s/ $//')

is_noid_managed_arg() {
    case "$1" in
        rhgb|quiet|slab_nomerge|efi=disable_early_pci_dma|erst_disable)
            return 0 ;;
        plymouth.use-simpledrm=*|init_on_alloc=*|init_on_free=*|pti=*|vsyscall=*|vdso32=*|debugfs=*|page_alloc.shuffle=*|randomize_kstack_offset=*|spec_store_bypass_disable=*|module.sig_enforce=*|iommu.strict=*|iommu.passthrough=*|lockdown=*|slab_debug=*|slub_debug=*|mitigations=*|proc_mem.force_override=*|hash_pointers=*|hardened_usercopy=*|kfence.sample_interval=*|kfence.deferrable=*|ia32_emulation=*|bdev_allow_write_mounted=*|rd.emergency=*|rd.shell=*|loglevel=*|systemd.ssh_auto=*|random.trust_cpu=*|random.trust_bootloader=*|intel_iommu=*|amd_iommu=*|tsx=*|l1tf=*|l1d_flush=*|kvm-intel.vmentry_l1d_flush=*|acpi_backlight=*|mem_sleep_default=*|audit=*|audit_backlog_limit=*|zswap.enabled=*|kvm.nx_huge_pages=*|mmio_stale_data=*|retbleed=*|gather_data_sampling=*|reg_file_data_sampling=*|indirect_target_selection=*|vmscape=*|efi_pstore.pstore_disable=*|spectre_v2=*|spectre_v2_user=*|spectre_bhi=*|mds=*|tsx_async_abort=*|srbds=*|spec_rstack_overflow=*|tsa=*)
            return 0 ;;
    esac
    return 1
}

current=""
append_current() {
    local arg
    for arg in $1; do
        # 92-tuned.install places this literal only in BLS for GRUB expansion.
        # Never import the transport macro into semantic kernel arguments.
        [ "$arg" = "\$tuned_params" ] && continue
        case " $current " in *" $arg "*) ;; *) current="$current $arg" ;; esac
    done
    current=$(printf '%s\n' "$current" | tr -s ' ' | sed 's/^ //;s/ $//')
}

if [ -f "$KERNEL_CMDLINE" ] && [ ! -L "$KERNEL_CMDLINE" ]; then
    append_current "$(tr -s '[:space:]' ' ' < "$KERNEL_CMDLINE")"
fi
shopt -s nullglob
for entry in "$BLS_DIR"/*.conf; do
    [ -f "$entry" ] && [ ! -L "$entry" ] || continue
    case "$(basename "$entry")" in noid-generic-fallback-*.conf) continue ;; esac
    append_current "$(awk '$1=="options" {$1=""; sub(/^ /, ""); print; exit}' "$entry")"
done
if [ -f "$GRUB_DEFAULT" ] && [ ! -L "$GRUB_DEFAULT" ]; then
    append_current "$(sed -n 's/^GRUB_CMDLINE_LINUX="\(.*\)"$/\1/p' "$GRUB_DEFAULT" | head -1)"
fi
durable_current=$current
[ -f "$CMDLINE_FILE" ] && [ ! -L "$CMDLINE_FILE" ] \
    || { echo "ERROR: active cmdline input missing or symlinked" >&2; exit 1; }
# The running command line is read for two narrow recoveries only: a root=
# and ro/rw fallback when no durable source carries them, and the LUKS UUID
# further below. It must NOT reach the publication merge -- see the guard
# there. `current` therefore stays the union for those lookups while
# `durable_current` remains the set of tokens that may be made permanent.
append_current "$(tr -s '[:space:]' ' ' < "$CMDLINE_FILE")"

root_spec=""; root_mode=""
for arg in $current; do
    case "$arg" in
        root=*) [ -n "$root_spec" ] || root_spec=$arg ;;
        ro|rw) [ -n "$root_mode" ] || root_mode=$arg ;;
    esac
done
if [ -z "$root_spec" ] && [ -f "$FSTAB" ] && [ ! -L "$FSTAB" ]; then
    fstab_root=$(awk '$1 !~ /^#/ && $2=="/" {print $1; exit}' "$FSTAB")
    [ -z "$fstab_root" ] || root_spec="root=$fstab_root"
fi
[ -n "$root_spec" ] || { echo "ERROR: no target root= argument" >&2; exit 1; }
[ -n "$root_mode" ] || root_mode=ro

# Root topology is owned by the installed root record in fstab. Fedora's
# 20-grub.install may regenerate /etc/kernel/cmdline while a Btrfs default-
# subvolume root is mounted at its path and thereby resurrect a stale
# rootflags=subvol= selector. Preserve every non-topology root flag, but replace
# subvol=/subvolid= exclusively from fstab whenever one real root record exists.
rootflag_options=""
append_rootflag_option() {
    local option=$1
    [ -n "$option" ] || return 0
    case ",$rootflag_options," in
        *",$option,"*) ;;
        *) rootflag_options="${rootflag_options:+$rootflag_options,}$option" ;;
    esac
}
fstab_root_options=""
fstab_root_records=0
if [ -f "$FSTAB" ] && [ ! -L "$FSTAB" ]; then
    fstab_root_records=$(awk '$1 !~ /^#/ && $2=="/" {count++} END {print count+0}' "$FSTAB")
    [ "$fstab_root_records" -le 1 ] \
        || { echo "ERROR: multiple target root records in fstab" >&2; exit 1; }
    if [ "$fstab_root_records" -eq 1 ]; then
        fstab_root_options=$(awk '$1 !~ /^#/ && $2=="/" {print $4; exit}' "$FSTAB")
    fi
fi
for arg in $durable_current; do
    case "$arg" in
        rootflags=*)
            for option in $(printf '%s\n' "${arg#rootflags=}" | tr ',' ' '); do
                case "$option" in
                    subvol=*|subvolid=*)
                        # With no authoritative fstab root record, retain the
                        # existing selector rather than guessing topology.
                        [ "$fstab_root_records" -eq 1 ] && continue
                        ;;
                esac
                append_rootflag_option "$option"
            done
            ;;
    esac
done
if [ "$fstab_root_records" -eq 1 ]; then
    for option in $(printf '%s\n' "$fstab_root_options" | tr ',' ' '); do
        case "$option" in
            subvol=*|subvolid=*) append_rootflag_option "$option" ;;
        esac
    done
fi
rootflags=""
[ -z "$rootflag_options" ] || rootflags="rootflags=$rootflag_options"

# Only a durable source may contribute to what gets published. Merging the
# active /proc/cmdline here made every one-boot GRUB-prompt edit permanent: a
# troubleshooting `nomodeset` survives the very driver install it was typed for
# (both noid-nvidia-install.sh and noid-update-all.sh call this with
# --publish), and `enforcing=0` becomes a silent, permanent SELinux downgrade
# that M01's firstboot service then seals as the trusted baseline. The strip
# list below cannot help: it names Live/installer-only tokens, not the
# difference between "configured" and "typed once at the boot menu".
[ -n "$durable_current" ] || {
    echo "ERROR: no durable kernel command line source to canonicalize" >&2
    exit 1
}
merged="$root_spec $root_mode${rootflags:+ $rootflags}"
for arg in $durable_current; do
    is_noid_managed_arg "$arg" && continue
    case "$arg" in
        root=*|rootflags=*|ro|rw|BOOT_IMAGE=*|initrd=*|inst.*|stage2=*|rd.live.*|liveimg|check|noid.initramfs=generic-fallback)
            continue ;;
    esac
    case " $merged " in *" $arg "*) ;; *) merged="$merged $arg" ;; esac
done
# Name what the running boot carries but no durable source does, so a
# deliberate one-boot argument is visibly not adopted rather than silently
# dropped. Diagnostic only: nothing here changes what is published.
active_only=""
for arg in $current; do
    case " $durable_current " in *" $arg "*) continue ;; esac
    is_noid_managed_arg "$arg" && continue
    case "$arg" in
        root=*|rootflags=*|ro|rw|BOOT_IMAGE=*|initrd=*|inst.*|stage2=*|rd.live.*|liveimg|check|noid.initramfs=generic-fallback)
            continue ;;
    esac
    active_only="${active_only:+$active_only }$arg"
done
[ -z "$active_only" ] || \
    echo "NOTE: active-only kernel argument(s) not made durable: $active_only" >&2

LUKS_UUID=$(sed -n 's/.*rd\.luks\.uuid=luks-\([0-9a-fA-F-]\{20,\}\).*/\1/p' \
    "$CMDLINE_FILE" | head -1)
if [ -n "$LUKS_UUID" ]; then
    LUKS_KARG="rd.luks.options=${LUKS_UUID}=tries=0,discard"
    case " $merged " in *" $LUKS_KARG "*) ;; *) merged="$merged $LUKS_KARG" ;; esac
fi
for arg in $NOID_TARGET_ARGS; do
    case " $merged " in *" $arg "*) ;; *) merged="$merged $arg" ;; esac
done
merged=$(printf '%s\n' "$merged" | tr -s ' ' | sed 's/^ //;s/ $//')
case " $merged " in
    *" \$tuned_params "*)
        echo "ERROR: tuned BLS transport macro entered semantic kernel cmdline" >&2
        exit 1
        ;;
esac

managed=""
for arg in $merged; do
    is_noid_managed_arg "$arg" || continue
    managed="${managed:+$managed }$arg"
done
[ "$managed" = "$NOID_TARGET_ARGS" ] \
    || { echo "ERROR: canonical managed-token order differs" >&2; exit 1; }

grub_args=""
for arg in $merged; do
    case "$arg" in root=*|rootflags=*|ro|rw) continue ;; esac
    grub_args="${grub_args:+$grub_args }$arg"
done

atomic_text() {
    local path=$1 value=$2 mode=$3 directory temporary
    directory=$(dirname "$path")
    [ -d "$directory" ] && [ ! -L "$directory" ] \
        || { echo "ERROR: unsafe destination directory: $directory" >&2; return 1; }
    [ ! -L "$path" ] || { echo "ERROR: symlinked destination: $path" >&2; return 1; }
    temporary=$(mktemp "$directory/.noid-cmdline.XXXXXXXX")
    printf '%s\n' "$value" > "$temporary"
    chmod "$mode" "$temporary"
    [ -n "$ROOT" ] || chown root:root "$temporary"
    sync -- "$temporary"
    mv -fT "$temporary" "$path"
    if [ -z "$ROOT" ]; then
        command -v restorecon >/dev/null 2>&1 \
            || { echo "ERROR: restorecon is unavailable" >&2; return 1; }
        command -v matchpathcon >/dev/null 2>&1 \
            || { echo "ERROR: matchpathcon is unavailable" >&2; return 1; }
        restorecon -F "$path"
        # stdout is the canonical cmdline API consumed by command
        # substitution. Keep matchpathcon's successful "verified" diagnostics
        # visible on stderr so they cannot become part of the evidence hash.
        matchpathcon -V "$path" >&2
    fi
    sync -- "$directory"
}

atomic_text "$KERNEL_CMDLINE" "$merged" 0644
bls_options="$merged \$tuned_params"

[ -d "$BLS_DIR" ] && [ ! -L "$BLS_DIR" ] \
    || { echo "ERROR: BLS directory missing or symlinked" >&2; exit 1; }
bls_count=0
for entry in "$BLS_DIR"/*.conf; do
    [ -f "$entry" ] && [ ! -L "$entry" ] || continue
    case "$(basename "$entry")" in noid-generic-fallback-*.conf) continue ;; esac
    temporary=$(mktemp "$BLS_DIR/.noid-bls.XXXXXXXX")
    if ! awk -v options="$bls_options" '
        $1=="options" { count++; print "options " options; next }
        { print }
        END { if (count != 1) exit 7 }
    ' "$entry" > "$temporary"; then
        rm -f "$temporary"
        echo "ERROR: BLS entry has noncanonical options cardinality: $entry" >&2
        exit 1
    fi
    chmod 0644 "$temporary"
    [ -n "$ROOT" ] || chown root:root "$temporary"
    sync -- "$temporary"
    mv -fT "$temporary" "$entry"
    bls_count=$((bls_count + 1))
done
[ "$bls_count" -gt 0 ] || { echo "ERROR: no normal BLS entries" >&2; exit 1; }
sync -- "$BLS_DIR"

if [ -f "$GRUB_DEFAULT" ] && [ ! -L "$GRUB_DEFAULT" ]; then
    grub_new=$(awk -v new="$grub_args" '
        /^GRUB_CMDLINE_LINUX=/ { count++; print "GRUB_CMDLINE_LINUX=\"" new "\""; next }
        { print }
        END { if (count != 1) exit 7 }
    ' "$GRUB_DEFAULT") || { echo "ERROR: GRUB cmdline assignment cardinality differs" >&2; exit 1; }
    atomic_text "$GRUB_DEFAULT" "$grub_new" 0644
else
    echo "ERROR: GRUB defaults are missing or symlinked" >&2
    exit 1
fi

[ "$(tr -d '\n' < "$KERNEL_CMDLINE")" = "$merged" ] \
    || { echo "ERROR: kernel cmdline publication differs" >&2; exit 1; }
for entry in "$BLS_DIR"/*.conf; do
    [ -f "$entry" ] && [ ! -L "$entry" ] || continue
    case "$(basename "$entry")" in noid-generic-fallback-*.conf) continue ;; esac
    [ "$(awk '$1=="options" {$1=""; sub(/^ /, ""); print}' "$entry")" = "$bls_options" ] \
        || { echo "ERROR: normal BLS options differ: $entry" >&2; exit 1; }
done
[ "$(sed -n 's/^GRUB_CMDLINE_LINUX="\(.*\)"$/\1/p' "$GRUB_DEFAULT")" = "$grub_args" ] \
    || { echo "ERROR: GRUB cmdline publication differs" >&2; exit 1; }
printf '%s\n' "$merged"
CMDLINE_CANONICALIZER_EOF
chmod 0755 /usr/libexec/noid-canonicalize-kernel-cmdline
chown root:root /usr/libexec/noid-canonicalize-kernel-cmdline

# M20 intentionally removes Anaconda's rootflags=subvol=root selector after it
# has made the running root the Btrfs default. That changes the canonical next-
# boot bytes after M01 has already prepared or sealed them. This M01-owned
# helper performs the narrow evidence handoff: the only accepted topology
# mutation is removal of one exact Anaconda root selector, while the only
# other active/durable delta allowed is NVIDIA's non-security framebuffer
# token. Evidence is rebound before grubby mutates /boot, so interruption is
# recoverable by the firstboot state machine rather than becoming a hash drift.
cat > /usr/libexec/noid-rebind-firstboot-rootflags <<'ROOTFLAGS_REBIND_EOF'
#!/bin/bash
set -euo pipefail

case "$#:${1:-}" in
    1:--prepare|1:--verify|1:--recover) operation=$1 ;;
    *) echo "usage: $0 {--prepare|--verify|--recover}" >&2; exit 2 ;;
esac

fail() { echo "noid-rebind-firstboot-rootflags: $*" >&2; exit 1; }
ROOT=
CMDLINE_FILE=/proc/cmdline
BOOT_ID_FILE=/proc/sys/kernel/random/boot_id
EXPECTED_OWNER=root:root
GRUBBY_BIN=grubby
if [ "${NOID_TEST_MODE:-0}" = 1 ]; then
    ROOT=${NOID_TEST_ROOT:?NOID_TEST_ROOT is required in test mode}
    CMDLINE_FILE=${NOID_TEST_CMDLINE_FILE:?NOID_TEST_CMDLINE_FILE is required in test mode}
    BOOT_ID_FILE=${NOID_TEST_BOOT_ID_FILE:?NOID_TEST_BOOT_ID_FILE is required in test mode}
    EXPECTED_OWNER=${NOID_TEST_OWNER:?NOID_TEST_OWNER is required in test mode}
    GRUBBY_BIN=${NOID_TEST_GRUBBY_BIN:?NOID_TEST_GRUBBY_BIN is required in test mode}
    [[ "$ROOT" = /* ]] && [ -d "$ROOT" ] && [ ! -L "$ROOT" ] \
        || fail "invalid test root"
    ROOT=$(realpath -e "$ROOT")
    [[ "$CMDLINE_FILE" = "$ROOT"/* ]] \
        && [[ "$BOOT_ID_FILE" = "$ROOT"/* ]] \
        && [[ "$GRUBBY_BIN" = "$ROOT"/* ]] \
        || fail "test inputs must remain below the test root"
    [ -f "$GRUBBY_BIN" ] && [ ! -L "$GRUBBY_BIN" ] && [ -x "$GRUBBY_BIN" ] \
        || fail "test grubby is missing, unsafe or not executable"
elif [ "$(id -u)" -ne 0 ]; then
    fail "must run as root"
fi
rpath() { printf '%s%s\n' "$ROOT" "$1"; }
KERNEL_CMDLINE=$(rpath /etc/kernel/cmdline)
FSTAB=$(rpath /etc/fstab)
STATE_DIR=$(rpath /var/lib/noid-privacy)
STATE_FILE="$STATE_DIR/.firstboot-cmdline-done"
REBOOT_STATE="$STATE_DIR/.firstboot-cmdline-reboot-required"

active_cmdline_value() {
    local result="" arg recovery_marker_count=0
    for arg in $(tr -s '[:space:]' ' ' < "$CMDLINE_FILE"); do
        case "$arg" in
            BOOT_IMAGE=*|initrd=*) continue ;;
            noid.initramfs=generic-fallback)
                recovery_marker_count=$((recovery_marker_count + 1))
                continue
                ;;
        esac
        result="${result:+$result }$arg"
    done
    [ "$recovery_marker_count" -le 1 ] \
        || fail "active cmdline repeats the Generic recovery marker"
    printf '%s\n' "$result"
}

line_sha256() {
    printf '%s\n' "$1" | sha256sum | awk '{print $1}'
}

reviewed_transition_value() {
    local input=$1 result="" arg root_selector_count=0 framebuffer_count=0
    for arg in $input; do
        case "$arg" in
            rootflags=subvol=root|rootflags=subvol=/root)
                root_selector_count=$((root_selector_count + 1))
                continue
                ;;
            plymouth.use-simpledrm=1)
                framebuffer_count=$((framebuffer_count + 1))
                continue
                ;;
        esac
        result="${result:+$result }$arg"
    done
    [ "$root_selector_count" -le 1 ] && [ "$framebuffer_count" -le 1 ] \
        || return 1
    printf '%s\n' "$result"
}

remove_one_root_selector() {
    local input=$1 result="" arg removed=0
    for arg in $input; do
        case "$arg" in
            rootflags=subvol=root|rootflags=subvol=/root)
                removed=$((removed + 1))
                continue
                ;;
        esac
        result="${result:+$result }$arg"
    done
    [ "$removed" -eq 1 ] || return 1
    printf '%s\n' "$result"
}

fstab_uses_btrfs_default_root() {
    [ -f "$FSTAB" ] && [ ! -L "$FSTAB" ] && awk '
        $1 !~ /^#/ && $2 == "/" {
            roots++
            count = split($4, options, ",")
            for (idx = 1; idx <= count; idx++) {
                if (options[idx] ~ /^subvol(id)?=/) bad = 1
            }
        }
        END { exit !(roots == 1 && !bad) }
    ' "$FSTAB"
}

valid_success_state() {
    [ -f "$STATE_FILE" ] && [ ! -L "$STATE_FILE" ] \
        && [ "$(stat -c '%U:%G:%a' "$STATE_FILE")" = "$EXPECTED_OWNER:644" ] \
        && awk '
            NR == 1 { ok = ($0 == "NOID_FIRSTBOOT_CMDLINE_V2"); next }
            NR == 2 { ok = ok && ($0 ~ /^desired_sha256=[0-9a-f]{64}$/); next }
            NR == 3 { ok = ok && ($0 ~ /^active_sha256=[0-9a-f]{64}$/); next }
            END { exit !(NR == 3 && ok) }
        ' "$STATE_FILE"
}

valid_reboot_state() {
    [ -f "$REBOOT_STATE" ] && [ ! -L "$REBOOT_STATE" ] \
        && [ "$(stat -c '%U:%G:%a' "$REBOOT_STATE")" = "$EXPECTED_OWNER:600" ] \
        && awk '
            NR == 1 { ok = ($0 == "NOID_FIRSTBOOT_CMDLINE_REBOOT_REQUIRED_V2"); next }
            NR == 2 { ok = ok && ($0 ~ /^active_sha256=[0-9a-f]{64}$/); next }
            NR == 3 { ok = ok && ($0 ~ /^desired_sha256=[0-9a-f]{64}$/); next }
            NR == 4 { ok = ok && ($0 ~ /^prepared_boot_id=[0-9a-f-]{36}$/); next }
            NR == 5 { ok = ok && ($0 ~ /^recovery_attempt=[01]$/); next }
            END { exit !(NR == 5 && ok) }
        ' "$REBOOT_STATE"
}

write_reboot_state() {
    local active_hash=$1 desired_hash=$2 boot_id=$3 recovery_attempt=$4 tmp
    tmp=$(mktemp "$STATE_DIR/.firstboot-cmdline-rebind.XXXXXXXX")
    printf '%s\n' NOID_FIRSTBOOT_CMDLINE_REBOOT_REQUIRED_V2 \
        "active_sha256=$active_hash" \
        "desired_sha256=$desired_hash" \
        "prepared_boot_id=$boot_id" \
        "recovery_attempt=$recovery_attempt" > "$tmp"
    chmod 0600 "$tmp"
    [ "${NOID_TEST_MODE:-0}" = 1 ] || chown root:root "$tmp"
    sync -- "$tmp"
    mv -fT "$tmp" "$REBOOT_STATE"
    sync -- "$STATE_DIR"
}

if [ "$operation" = --recover ] \
        && [ ! -e "$REBOOT_STATE" ] && [ ! -L "$REBOOT_STATE" ]; then
    exit 0
fi

[ -f "$KERNEL_CMDLINE" ] && [ ! -L "$KERNEL_CMDLINE" ] \
    && [ "$(wc -l < "$KERNEL_CMDLINE")" -eq 1 ] \
    || fail "canonical kernel cmdline is missing, unsafe or multiline"
[ -f "$CMDLINE_FILE" ] && [ ! -L "$CMDLINE_FILE" ] \
    || fail "active kernel cmdline source is missing or unsafe"
[ -f "$BOOT_ID_FILE" ] && [ ! -L "$BOOT_ID_FILE" ] \
    || fail "kernel boot ID source is missing or unsafe"
boot_id=$(cat "$BOOT_ID_FILE")
[[ "$boot_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] \
    || fail "kernel boot ID is invalid"

durable=$(cat "$KERNEL_CMDLINE")
active=$(active_cmdline_value)
durable_hash=$(line_sha256 "$durable")
active_hash=$(line_sha256 "$active")

if [ "$operation" = --recover ]; then
    valid_reboot_state || fail "invalid pending evidence at recovery boundary"
    [ ! -e "$STATE_FILE" ] && [ ! -L "$STATE_FILE" ] \
        || fail "success and reboot evidence coexist during recovery"
    marker_desired=$(awk -F= '$1 == "desired_sha256" {print $2}' "$REBOOT_STATE")
    marker_boot_id=$(awk -F= '$1 == "prepared_boot_id" {print $2}' "$REBOOT_STATE")
    recovery_attempt=$(awk -F= '$1 == "recovery_attempt" {print $2}' "$REBOOT_STATE")

    # Same-boot evidence is still inside its ordinary M20 transaction. If the
    # durable bytes already match, publication also completed before the prior
    # boot stopped and normal firstboot validation can finish the lifecycle.
    if [ "$marker_boot_id" = "$boot_id" ] || [ "$durable_hash" = "$marker_desired" ]; then
        exit 0
    fi
    [ "$recovery_attempt" -eq 0 ] \
        || fail "rootflags publication already consumed its recovery attempt"
    [ "$active" = "$durable" ] \
        || fail "interrupted rootflags recovery did not boot its prepared bytes"
    recovered_desired=$(remove_one_root_selector "$durable") \
        || fail "interrupted rootflags state lacks one reviewed selector"
    [ "$(line_sha256 "$recovered_desired")" = "$marker_desired" ] \
        || fail "interrupted rootflags state does not lead to planned bytes"
    fstab_uses_btrfs_default_root \
        || fail "interrupted rootflags state lacks the selector-free fstab contract"

    "$GRUBBY_BIN" --update-kernel=ALL \
        --remove-args="rootflags=subvol=root rootflags=subvol=/root" \
        || fail "cannot recover interrupted rootflags publication"
    [ "$(cat "$KERNEL_CMDLINE")" = "$recovered_desired" ] \
        || fail "recovered rootflags publication did not produce planned bytes"
    write_reboot_state "$active_hash" "$marker_desired" "$boot_id" 1
    echo "noid-rebind-firstboot-rootflags: recovered one interrupted boot-policy publication" >&2
    exit 0
fi

if [ "$operation" = --verify ]; then
    if valid_reboot_state; then
        [ "$(awk -F= '$1 == "active_sha256" {print $2}' "$REBOOT_STATE")" = "$active_hash" ] \
            || fail "reboot evidence lost active-byte binding"
        [ "$(awk -F= '$1 == "desired_sha256" {print $2}' "$REBOOT_STATE")" = "$durable_hash" ] \
            || fail "reboot evidence lost durable-byte binding"
        [ "$(awk -F= '$1 == "prepared_boot_id" {print $2}' "$REBOOT_STATE")" = "$boot_id" ] \
            || fail "reboot evidence was not prepared in this boot"
    elif valid_success_state; then
        [ "$(awk -F= '$1 == "desired_sha256" {print $2}' "$STATE_FILE")" = "$durable_hash" ] \
            && [ "$(awk -F= '$1 == "active_sha256" {print $2}' "$STATE_FILE")" = "$active_hash" ] \
            && [ "$active" = "$durable" ] \
            || fail "success evidence does not bind unchanged boot bytes"
    else
        fail "no valid M01 evidence exists after rootflags publication"
    fi
    ! printf '%s\n' "$durable" | tr ' ' '\n' \
        | grep -qE '^rootflags=subvol=/?root$' \
        || fail "durable cmdline still contains the Anaconda root selector"
    exit 0
fi

# The target post and M01 canonicalizer must already have made all security
# bytes active. Ignore only NVIDIA's framebuffer token and, on a bounded
# recovery retry, the reviewed obsolete root selector.
active_reviewed=$(reviewed_transition_value "$active") \
    || fail "active cmdline repeats a reviewed transition token"
durable_reviewed=$(reviewed_transition_value "$durable") \
    || fail "durable cmdline repeats a reviewed transition token"
[ "$active_reviewed" = "$durable_reviewed" ] \
    || fail "active/durable delta exceeds the reviewed root-selector/framebuffer transition before M20"

desired=""
removed=0
for arg in $durable; do
    case "$arg" in
        rootflags=subvol=root|rootflags=subvol=/root)
            removed=$((removed + 1))
            continue
            ;;
    esac
    desired="${desired:+$desired }$arg"
done
[ "$removed" -le 1 ] || fail "multiple Anaconda root selectors are present"
desired_hash=$(line_sha256 "$desired")

recovery_attempt=0
if valid_success_state; then
    [ ! -e "$REBOOT_STATE" ] && [ ! -L "$REBOOT_STATE" ] \
        || fail "success and reboot evidence coexist"
    [ "$(awk -F= '$1 == "desired_sha256" {print $2}' "$STATE_FILE")" = "$durable_hash" ] \
        && [ "$(awk -F= '$1 == "active_sha256" {print $2}' "$STATE_FILE")" = "$active_hash" ] \
        && [ "$active" = "$durable" ] \
        || fail "success evidence does not bind the pre-M20 bytes"
elif valid_reboot_state; then
    [ ! -e "$STATE_FILE" ] && [ ! -L "$STATE_FILE" ] \
        || fail "success and reboot evidence coexist"
    [ "$(awk -F= '$1 == "active_sha256" {print $2}' "$REBOOT_STATE")" = "$active_hash" ] \
        && [ "$(awk -F= '$1 == "desired_sha256" {print $2}' "$REBOOT_STATE")" = "$durable_hash" ] \
        && [ "$(awk -F= '$1 == "prepared_boot_id" {print $2}' "$REBOOT_STATE")" = "$boot_id" ] \
        || fail "pending evidence does not bind the pre-M20 bytes in this boot"
    recovery_attempt=$(awk -F= '$1 == "recovery_attempt" {print $2}' "$REBOOT_STATE")
else
    fail "M01 produced no valid evidence before M20"
fi

if [ "$removed" -eq 0 ]; then
    # Idempotent retry or a future installer that already follows the Btrfs
    # default. No topology mutation means the existing evidence remains exact.
    exit 0
fi

# Removing the old seal first is deliberately recoverable: interruption in
# the tiny gap leaves no false success and M01 reconstructs evidence next boot.
if [ -e "$STATE_FILE" ] || [ -L "$STATE_FILE" ]; then
    rm -f -- "$STATE_FILE"
    sync -- "$STATE_DIR"
fi
write_reboot_state "$active_hash" "$desired_hash" "$boot_id" "$recovery_attempt"
ROOTFLAGS_REBIND_EOF
chmod 0755 /usr/libexec/noid-rebind-firstboot-rootflags
chown root:root /usr/libexec/noid-rebind-firstboot-rootflags

# Supported post-install kernel-argument writers must not leave M01's exact
# active/durable success seal stale. NVIDIA RPM scriptlets are the first such
# lifecycle. Open the seal only from a healthy state immediately before the
# mutation; a later M01 run publishes either a new seal or exact reboot
# evidence. The legacy recovery accepts only the already-observed pre-helper
# NVIDIA/root-selector delta and exists for upgrades from affected images.
cat > /usr/libexec/noid-firstboot-cmdline-transition <<'CMDLINE_TRANSITION_EOF'
#!/bin/bash
# Open a reviewed post-install kernel-command-line transition without leaving
# M01's byte-bound success evidence stale. The recovery mode exists only for
# systems affected before this transaction helper was shipped.
set -euo pipefail

case "$#:${1:-}" in
    1:--invalidate-nvidia-install|1:--invalidate-nvidia-rollback|1:--invalidate-hardening-profile)
        operation=$1
        ;;
    1:--recover-legacy-nvidia-transition)
        operation=$1
        ;;
    *)
        echo "usage: $0 {--invalidate-nvidia-install|--invalidate-nvidia-rollback|--invalidate-hardening-profile|--recover-legacy-nvidia-transition}" >&2
        exit 2
        ;;
esac

fail() { echo "noid-firstboot-cmdline-transition: $*" >&2; exit 1; }
ROOT=
CMDLINE_FILE=/proc/cmdline
EXPECTED_OWNER=root:root
if [ "${NOID_TEST_MODE:-0}" = 1 ]; then
    ROOT=${NOID_TEST_ROOT:?NOID_TEST_ROOT is required in test mode}
    CMDLINE_FILE=${NOID_TEST_CMDLINE_FILE:?NOID_TEST_CMDLINE_FILE is required in test mode}
    EXPECTED_OWNER=${NOID_TEST_OWNER:?NOID_TEST_OWNER is required in test mode}
    [[ "$ROOT" = /* ]] && [ -d "$ROOT" ] && [ ! -L "$ROOT" ] \
        || fail "invalid test root"
    ROOT=$(realpath -e "$ROOT")
    [[ "$CMDLINE_FILE" = "$ROOT"/* ]] \
        || fail "test inputs must remain below the test root"
elif [ "$(id -u)" -ne 0 ]; then
    fail "must run as root"
fi
rpath() { printf '%s%s\n' "$ROOT" "$1"; }
STATE_DIR=$(rpath /var/lib/noid-privacy)
STATE_FILE="$STATE_DIR/.firstboot-cmdline-done"
REBOOT_STATE="$STATE_DIR/.firstboot-cmdline-reboot-required"
KERNEL_CMDLINE=$(rpath /etc/kernel/cmdline)
FSTAB=$(rpath /etc/fstab)
BOOT_MODEL=$(rpath /.snapshots/.noid-state/boot-model.ready)
BOOT_ID_FILE=$(rpath /proc/sys/kernel/random/boot_id)

line_sha256() {
    printf '%s\n' "$1" | sha256sum | awk '{print $1}'
}

active_cmdline_value() {
    local result="" arg recovery_marker_count=0
    [ -f "$CMDLINE_FILE" ] && [ ! -L "$CMDLINE_FILE" ] \
        || fail "active kernel cmdline source is missing or unsafe"
    for arg in $(tr -s '[:space:]' ' ' < "$CMDLINE_FILE"); do
        case "$arg" in
            BOOT_IMAGE=*|initrd=*) continue ;;
            noid.initramfs=generic-fallback)
                recovery_marker_count=$((recovery_marker_count + 1))
                continue
                ;;
        esac
        result="${result:+$result }$arg"
    done
    [ "$recovery_marker_count" -le 1 ] \
        || fail "active cmdline repeats the Generic recovery marker"
    printf '%s\n' "$result"
}

valid_success_state() {
    [ -f "$STATE_FILE" ] && [ ! -L "$STATE_FILE" ] \
        && [ "$(stat -c '%U:%G:%a' "$STATE_FILE")" = "$EXPECTED_OWNER:644" ] \
        && awk '
            NR == 1 { ok = ($0 == "NOID_FIRSTBOOT_CMDLINE_V2"); next }
            NR == 2 { ok = ok && ($0 ~ /^desired_sha256=[0-9a-f]{64}$/); next }
            NR == 3 { ok = ok && ($0 ~ /^active_sha256=[0-9a-f]{64}$/); next }
            END { exit !(NR == 3 && ok) }
        ' "$STATE_FILE"
}

valid_reboot_state() {
    [ -f "$REBOOT_STATE" ] && [ ! -L "$REBOOT_STATE" ] \
        && [ "$(stat -c '%U:%G:%a' "$REBOOT_STATE")" = "$EXPECTED_OWNER:600" ] \
        && awk '
            NR == 1 { ok = ($0 == "NOID_FIRSTBOOT_CMDLINE_REBOOT_REQUIRED_V2"); next }
            NR == 2 { ok = ok && ($0 ~ /^active_sha256=[0-9a-f]{64}$/); next }
            NR == 3 { ok = ok && ($0 ~ /^desired_sha256=[0-9a-f]{64}$/); next }
            NR == 4 { ok = ok && ($0 ~ /^prepared_boot_id=[0-9a-f-]{36}$/); next }
            NR == 5 { ok = ok && ($0 ~ /^recovery_attempt=[01]$/); next }
            END { exit !(NR == 5 && ok) }
        ' "$REBOOT_STATE"
}

valid_default_subvolume_model() {
    [ -f "$BOOT_MODEL" ] && [ ! -L "$BOOT_MODEL" ] \
        && [ "$(stat -c '%U:%G:%a' "$BOOT_MODEL")" = "$EXPECTED_OWNER:600" ] \
        && awk -F= '
            $1 == "MODEL" && $2 == "default-subvolume-v1" { model++ }
            $1 == "SNAPSHOTS_FSROOT" && $2 == "/snapshots" { snapshots++ }
            $1 == "LIBVIRT_FSROOT" && $2 == "/libvirt" { libvirt++ }
            END { exit !(NR == 3 && model == 1 && snapshots == 1 && libvirt == 1) }
        ' "$BOOT_MODEL" \
        && [ -f "$FSTAB" ] && [ ! -L "$FSTAB" ] \
        && awk '
            $1 !~ /^#/ && $2 == "/" {
                roots++
                count = split($4, options, ",")
                for (idx = 1; idx <= count; idx++) {
                    if (options[idx] ~ /^subvol(id)?=/) bad = 1
                }
            }
            END { exit !(roots == 1 && !bad) }
        ' "$FSTAB"
}

remove_success_state() {
    local expected_hash=$1
    [ "$(sha256sum "$STATE_FILE" | awk '{print $1}')" = "$expected_hash" ] \
        || fail "success evidence changed during validation"
    rm -f -- "$STATE_FILE"
    sync -- "$STATE_DIR"
    [ ! -e "$STATE_FILE" ] && [ ! -L "$STATE_FILE" ] \
        || fail "success evidence removal did not commit"
}

remove_reboot_state() {
    local expected_hash=$1
    [ "$(sha256sum "$REBOOT_STATE" | awk '{print $1}')" = "$expected_hash" ] \
        || fail "reboot evidence changed during validation"
    rm -f -- "$REBOOT_STATE"
    sync -- "$STATE_DIR"
    [ ! -e "$REBOOT_STATE" ] && [ ! -L "$REBOOT_STATE" ] \
        || fail "reboot evidence removal did not commit"
}

[ -f "$KERNEL_CMDLINE" ] && [ ! -L "$KERNEL_CMDLINE" ] \
    && [ "$(wc -l < "$KERNEL_CMDLINE")" -eq 1 ] \
    || fail "canonical kernel cmdline is missing, unsafe or multiline"

evidence_kind=
if valid_success_state \
        && [ ! -e "$REBOOT_STATE" ] && [ ! -L "$REBOOT_STATE" ]; then
    evidence_kind=success
elif [ "$operation" = --invalidate-hardening-profile ] \
        && [ ! -e "$STATE_FILE" ] && [ ! -L "$STATE_FILE" ] \
        && valid_reboot_state; then
    # A reviewed profile may be toggled again before the requested reboot.
    # Its existing pending record is authority only when it still binds this
    # boot and both current byte surfaces exactly; remove it before replacing
    # the durable target. NVIDIA package transitions retain the stricter
    # success-only precondition.
    evidence_kind=reboot
else
    fail "one exact firstboot command-line evidence object is required"
fi

durable=$(cat "$KERNEL_CMDLINE")
active=$(active_cmdline_value)

if [ "$evidence_kind" = reboot ]; then
    reboot_hash=$(sha256sum "$REBOOT_STATE" | awk '{print $1}')
    sealed_active=$(awk -F= '$1 == "active_sha256" {print $2}' "$REBOOT_STATE")
    sealed_desired=$(awk -F= '$1 == "desired_sha256" {print $2}' "$REBOOT_STATE")
    prepared_boot_id=$(awk -F= '$1 == "prepared_boot_id" {print $2}' "$REBOOT_STATE")
    [ -f "$BOOT_ID_FILE" ] && [ ! -L "$BOOT_ID_FILE" ] \
        || fail "kernel boot-ID source is missing or unsafe"
    boot_id=$(cat "$BOOT_ID_FILE")
    case "$boot_id" in
        ????????-????-????-????-????????????) ;;
        *) fail "invalid kernel boot ID" ;;
    esac
    [ "$prepared_boot_id" = "$boot_id" ] \
        && [ "$sealed_active" = "$(line_sha256 "$active")" ] \
        && [ "$sealed_desired" = "$(line_sha256 "$durable")" ] \
        && [ "$active" != "$durable" ] \
        || fail "pending evidence does not bind this boot and its active/durable bytes"
    remove_reboot_state "$reboot_hash"
    logger -t noid-firstboot-cmdline-transition -- \
        "opened hardening-profile replacement from exact pending evidence" \
        2>/dev/null || true
    exit 0
fi

state_hash=$(sha256sum "$STATE_FILE" | awk '{print $1}')
sealed_desired=$(awk -F= '$1 == "desired_sha256" {print $2}' "$STATE_FILE")
sealed_active=$(awk -F= '$1 == "active_sha256" {print $2}' "$STATE_FILE")

if [ "$operation" != --recover-legacy-nvidia-transition ]; then
    [ "$active" = "$durable" ] \
        && [ "$sealed_active" = "$(line_sha256 "$active")" ] \
        && [ "$sealed_desired" = "$(line_sha256 "$durable")" ] \
        || fail "success evidence does not bind unchanged active/durable bytes"
    remove_success_state "$state_hash"
    logger -t noid-firstboot-cmdline-transition -- \
        "opened ${operation#--invalidate-} kernel-command-line transition" \
        2>/dev/null || true
    exit 0
fi

# Legacy recovery is deliberately narrower than ordinary invalidation. The
# sealed bytes must be recoverable from both live surfaces by removing only:
# one obsolete Anaconda Btrfs selector from the running boot, and NVIDIA RPM
# blacklist/modeset or NoID Privacy framebuffer tokens absent from that running boot.
if [ "${NOID_TEST_MODE:-0}" != 1 ]; then
    rpm -q akmod-nvidia >/dev/null 2>&1 \
        || rpm -q akmod-nvidia-580xx >/dev/null 2>&1 \
        || fail "legacy NVIDIA recovery requires an installed managed NVIDIA branch"
elif [ "${NOID_TEST_NVIDIA_PRESENT:-0}" != 1 ]; then
    fail "test fixture did not authorize an installed NVIDIA branch"
fi

base_active=""
active_root_selectors=0
for arg in $active; do
    case "$arg" in
        rootflags=subvol=root|rootflags=subvol=/root)
            active_root_selectors=$((active_root_selectors + 1))
            continue
            ;;
    esac
    base_active="${base_active:+$base_active }$arg"
done
[ "$active_root_selectors" -le 1 ] \
    || fail "running boot repeats the legacy Btrfs root selector"
if [ "$active_root_selectors" -eq 1 ]; then
    valid_default_subvolume_model \
        || fail "running legacy selector lacks the completed default-subvolume contract"
fi
[ "$sealed_active" = "$(line_sha256 "$base_active")" ] \
    && [ "$sealed_desired" = "$(line_sha256 "$base_active")" ] \
    || fail "legacy active bytes do not reduce to the sealed pre-NVIDIA state"

normalized_durable=""
nvidia_delta=0
append_normalized() {
    normalized_durable="${normalized_durable:+$normalized_durable }$1"
}
for arg in $durable; do
    case "$arg" in
        rd.driver.blacklist=*|modprobe.blacklist=*)
            prefix=${arg%%=*}=
            values=${arg#*=}
            retained=""
            removed_here=0
            for value in $(printf '%s\n' "$values" | tr ',' ' '); do
                case "$value" in
                    nouveau|nova_core)
                        removed_here=$((removed_here + 1))
                        ;;
                    *) retained="${retained:+$retained,}$value" ;;
                esac
            done
            if [ "$removed_here" -gt 0 ]; then
                candidate="${prefix}${retained}"
                if [ -n "$retained" ]; then
                    append_normalized "$candidate"
                fi
                nvidia_delta=$((nvidia_delta + removed_here))
            else
                append_normalized "$arg"
            fi
            ;;
        nvidia-drm.modeset=1|nvidia-drm.fbdev=1|plymouth.use-simpledrm=1)
            case " $base_active " in
                *" $arg "*) append_normalized "$arg" ;;
                *) nvidia_delta=$((nvidia_delta + 1)) ;;
            esac
            ;;
        *) append_normalized "$arg" ;;
    esac
done
[ "$nvidia_delta" -gt 0 ] \
    || fail "durable bytes contain no reviewed legacy NVIDIA delta"
[ "$normalized_durable" = "$base_active" ] \
    && [ "$sealed_desired" = "$(line_sha256 "$normalized_durable")" ] \
    || fail "durable bytes exceed the reviewed legacy NVIDIA transition"

remove_success_state "$state_hash"
logger -t noid-firstboot-cmdline-transition -- \
    "recovered one legacy NVIDIA command-line transition" 2>/dev/null || true
echo "noid-firstboot-cmdline-transition: recovered one exact legacy NVIDIA transition" >&2
CMDLINE_TRANSITION_EOF
chmod 0755 /usr/libexec/noid-firstboot-cmdline-transition
chown root:root /usr/libexec/noid-firstboot-cmdline-transition

# ====================================================================
# STEP 4c: Firstboot verifier/fallback for hardware-conditional + LUKS kargs
# ====================================================================
# Defense-in-depth after the executable STEP 4b contract. The ordinary path
# arrives with every install-time-known security argument already active; this
# service verifies/canonicalizes those bytes and covers interrupted installs or
# hardware that changed after installation. It applies corrections through
# grubby + the closed canonicalizer, is state-gated, and is skipped in Live-ISO
# mode. It ALSO reconciles the LUKS unlock-retry karg
# (rd.luks.options=<UUID>=tries=0,discard) — the volume-specific form derived
# from the active rd.luks.uuid=. systemd also accepts a global option list, but
# binding this policy to the root LUKS UUID avoids affecting unrelated volumes.
log "STEP 4c: install noid-firstboot-cmdline.service (firstboot defense-in-depth)"

cat > /usr/local/sbin/noid-firstboot-cmdline.sh <<'CMDLINE_EOF'
#!/bin/bash
# noid-firstboot-cmdline.sh — apply hardware-conditional + LUKS-retry kernel
# cmdline kargs at firstboot of installed system.
#
# Reason: STEP 4b is now embedded in the interactive kickstart that Fedora 44
# liveinst actually parses. This service is the closed runtime verifier and
# fallback for interrupted installation or post-install hardware changes.
# Idempotent: state-file /var/lib/noid-privacy/.firstboot-cmdline-done.
# Skip in Live-ISO mode (rd.live.image kernel cmdline arg).

set -euo pipefail

STATE_DIR="/var/lib/noid-privacy"
STATE_FILE="$STATE_DIR/.firstboot-cmdline-done"
REBOOT_STATE="$STATE_DIR/.firstboot-cmdline-reboot-required"
LOG_TAG="noid-firstboot-cmdline"
CMDLINE_FILE=/proc/cmdline
BOOT_ID_FILE=/proc/sys/kernel/random/boot_id

log() { logger -t "$LOG_TAG" -- "$*" 2>/dev/null || true; echo "[$LOG_TAG] $*"; }

active_cmdline_value() {
    local result="" active_arg recovery_marker_count=0
    for active_arg in $(tr -s '[:space:]' ' ' < "$CMDLINE_FILE"); do
        case "$active_arg" in
            BOOT_IMAGE=*|initrd=*) continue ;;
            noid.initramfs=generic-fallback)
                recovery_marker_count=$((recovery_marker_count + 1))
                continue
                ;;
        esac
        result="${result:+$result }$active_arg"
    done
    if [ "$recovery_marker_count" -gt 1 ]; then
        log "ERROR: active cmdline repeats the Generic recovery marker" >&2
        return 1
    fi
    printf '%s\n' "$result"
}

line_sha256() {
    printf '%s\n' "$1" | sha256sum | awk '{print $1}'
}

valid_reboot_state() {
    [ -f "$REBOOT_STATE" ] && [ ! -L "$REBOOT_STATE" ] \
        && [ "$(stat -c '%U:%G:%a' "$REBOOT_STATE")" = root:root:600 ] \
        && awk '
            NR == 1 { ok = ($0 == "NOID_FIRSTBOOT_CMDLINE_REBOOT_REQUIRED_V2"); next }
            NR == 2 { ok = ok && ($0 ~ /^active_sha256=[0-9a-f]{64}$/); next }
            NR == 3 { ok = ok && ($0 ~ /^desired_sha256=[0-9a-f]{64}$/); next }
            NR == 4 { ok = ok && ($0 ~ /^prepared_boot_id=[0-9a-f-]{36}$/); next }
            NR == 5 { ok = ok && ($0 ~ /^recovery_attempt=[01]$/); next }
            END { exit !(NR == 5 && ok) }
        ' "$REBOOT_STATE"
}

write_reboot_state() {
    local active_hash=$1 desired_hash=$2 prepared_boot_id=$3 recovery_attempt=$4
    local reboot_tmp
    reboot_tmp=$(mktemp "$STATE_DIR/.firstboot-cmdline-reboot.XXXXXXXX")
    printf '%s\n' NOID_FIRSTBOOT_CMDLINE_REBOOT_REQUIRED_V2 \
        "active_sha256=$active_hash" \
        "desired_sha256=$desired_hash" \
        "prepared_boot_id=$prepared_boot_id" \
        "recovery_attempt=$recovery_attempt" > "$reboot_tmp"
    chmod 0600 "$reboot_tmp"
    chown root:root "$reboot_tmp"
    sync -- "$reboot_tmp"
    mv -fT "$reboot_tmp" "$REBOOT_STATE"
    sync -- "$STATE_DIR"
}

# Skip in Live-ISO mode
if grep -q "rd.live.image" "$CMDLINE_FILE" 2>/dev/null; then
    log "skip: rd.live.image (Live-ISO mode)"
    exit 0
fi

# M20 writes its exact selector-free plan before mutating BLS bytes. If power
# stopped the machine in that narrow window, recover the already-authorized
# topology publication before the canonicalizer runs. The helper permits this
# once, binds the new boot identity and never broadens the security-karg delta.
if ! /usr/libexec/noid-rebind-firstboot-rootflags --recover; then
    log "ERROR: interrupted rootflags publication is not safely recoverable"
    exit 1
fi

# Idempotent, but never let an unsafe/invalid evidence object suppress this
# load-bearing firstboot transition. The unit deliberately starts every boot;
# a valid closed record makes that invocation a cheap no-op.
if [ -e "$STATE_FILE" ] || [ -L "$STATE_FILE" ]; then
    if [ -f "$STATE_FILE" ] && [ ! -L "$STATE_FILE" ] \
       && [ "$(stat -c '%U:%G:%a' "$STATE_FILE")" = root:root:644 ] \
       && awk '
            NR == 1 { ok = ($0 == "NOID_FIRSTBOOT_CMDLINE_V2"); next }
            NR == 2 { ok = ok && ($0 ~ /^desired_sha256=[0-9a-f]{64}$/); next }
            NR == 3 { ok = ok && ($0 ~ /^active_sha256=[0-9a-f]{64}$/); next }
            END { exit !(NR == 3 && ok) }
       ' "$STATE_FILE" \
       && [ ! -e "$REBOOT_STATE" ] && [ ! -L "$REBOOT_STATE" ] \
       && [ -f /etc/kernel/cmdline ] && [ ! -L /etc/kernel/cmdline ] \
       && [ "$(wc -l < /etc/kernel/cmdline)" -eq 1 ]; then
        sealed_desired=$(awk -F= '$1 == "desired_sha256" {print $2}' "$STATE_FILE")
        sealed_active=$(awk -F= '$1 == "active_sha256" {print $2}' "$STATE_FILE")
        current_durable=$(cat /etc/kernel/cmdline)
        current_active=$(active_cmdline_value)
        if [ "$sealed_desired" = "$(line_sha256 "$current_durable")" ] \
           && [ "$sealed_active" = "$(line_sha256 "$current_active")" ] \
           && [ "$current_active" = "$current_durable" ]; then
            log "skip: valid state record matches active and durable bytes"
            exit 0
        fi
    fi
    log "ERROR: invalid firstboot cmdline evidence; refusing false idempotency"
    exit 1
fi

# CPU vendor detection
CPU_EXTRA=""
if grep -q GenuineIntel /proc/cpuinfo 2>/dev/null; then
    CPU_EXTRA="intel_iommu=on tsx=off l1tf=full l1d_flush=on kvm-intel.vmentry_l1d_flush=always"
    log "CPU: Intel — adds: $CPU_EXTRA"
elif grep -q AuthenticAMD /proc/cpuinfo 2>/dev/null; then
    CPU_EXTRA="amd_iommu=on"
    log "CPU: AMD — adds: $CPU_EXTRA"
else
    log "CPU: unknown vendor — no CPU_EXTRA"
fi

# Reconcile inherited compose-time vendor state before applying the detected
# target vendor. A fallback run on AMD must not retain intel_iommu=on merely
# because the build VM was Intel-oriented.
if ! grubby --update-kernel=ALL --remove-args="intel_iommu=on amd_iommu=on"; then
    log "ERROR: failed to remove inherited vendor-specific IOMMU arguments"
    exit 1
fi

# grubby owns the BLS entries and /etc/kernel/cmdline, but legacy tooling can
# later regenerate from /etc/default/grub. Reconcile that second persistence
# surface too, otherwise a compose-host vendor argument can reappear on a
# future grub2-mkconfig run.
if [ -f /etc/default/grub ] && grep -q '^GRUB_CMDLINE_LINUX=' /etc/default/grub; then
    sed -i -E '/^GRUB_CMDLINE_LINUX=/ {
        s/(^|[[:space:]"])intel_iommu=on([[:space:]"]|$)/\1\2/g
        s/(^|[[:space:]"])amd_iommu=on([[:space:]"]|$)/\1\2/g
        s/[[:space:]]+/ /g
        s/="[[:space:]]*/="/
        s/[[:space:]]+"$/"/
    }' /etc/default/grub
fi

# GPU vendor detection (NVIDIA → plymouth.use-simpledrm=1)
GPU_EXTRA=""
if command -v lspci >/dev/null 2>&1; then
    if lspci -nn 2>/dev/null | grep -qE "VGA.*NVIDIA|3D controller.*NVIDIA|Display controller.*NVIDIA"; then
        GPU_EXTRA="plymouth.use-simpledrm=1"
        log "GPU: NVIDIA — adds: $GPU_EXTRA"
    fi
fi

# Backlight and suspend-mode selection remain with the kernel, firmware and
# their maintained model-specific quirks. Chassis class alone does not prove
# that acpi_backlight=native or mem_sleep_default=s2idle is correct. Remove the
# two retired NoID Privacy arguments if an older candidate left them behind.
if ! grubby --update-kernel=ALL \
        --remove-args="acpi_backlight=native mem_sleep_default=s2idle"; then
    log "ERROR: failed to remove retired portable-chassis arguments"
    exit 1
fi
if [ -f /etc/default/grub ] && grep -q '^GRUB_CMDLINE_LINUX=' /etc/default/grub; then
    sed -i -E '/^GRUB_CMDLINE_LINUX=/ {
        s/(^|[[:space:]"])acpi_backlight=[^[:space:]"]+([[:space:]"]|$)/\1\2/g
        s/(^|[[:space:]"])mem_sleep_default=[^[:space:]"]+([[:space:]"]|$)/\1\2/g
        s/[[:space:]]+/ /g
        s/="[[:space:]]*/="/
        s/[[:space:]]+"$/"/
    }' /etc/default/grub
fi

EXTRA=$(echo "$CPU_EXTRA $GPU_EXTRA" | tr -s ' ' | sed 's/^ //;s/ $//')

if [ -z "$EXTRA" ]; then
    log "no hardware-conditional kargs to apply"
else
    log "applying: $EXTRA"
    # grubby --update-kernel=ALL handles dedup + BLS regen + /etc/kernel/cmdline
    if ! grubby --update-kernel=ALL --args="$EXTRA"; then
        log "ERROR: grubby hardware-karg update failed; leaving service retryable"
        exit 1
    fi
    # /etc/default/grub GRUB_CMDLINE_LINUX — idempotent append (skip if already present)
    if [ -f /etc/default/grub ] && grep -q '^GRUB_CMDLINE_LINUX=' /etc/default/grub; then
        for arg in $EXTRA; do
            if ! grep -qE "GRUB_CMDLINE_LINUX=.*[ \"]${arg}([ \"])" /etc/default/grub; then
                sed -i 's|^\(GRUB_CMDLINE_LINUX=".*\)"$|\1 '"$arg"'"|' /etc/default/grub
                log "/etc/default/grub: appended $arg"
            else
                log "/etc/default/grub: $arg already present (skip)"
            fi
        done
    fi
fi

# LUKS unlock-retry: tries=0 = unlimited passphrase prompts, so a single typo
# can't exhaust attempts and freeze the boot under rd.emergency=halt. Per-UUID
# form (only one systemd honors) from the live rd.luks.uuid=; discard kept.
LUKS_UUID=$(sed -n 's/.*rd\.luks\.uuid=luks-\([0-9a-fA-F-]\{20,\}\).*/\1/p' "$CMDLINE_FILE" 2>/dev/null | head -1 || true)
if [ -n "$LUKS_UUID" ]; then
    LUKS_KARG="rd.luks.options=${LUKS_UUID}=tries=0,discard"
    if grep -qF "$LUKS_KARG" "$CMDLINE_FILE" 2>/dev/null; then
        log "LUKS: $LUKS_KARG already active (skip)"
    else
        log "LUKS: applying $LUKS_KARG (unlimited unlock retries)"
        if ! grubby --update-kernel=ALL --args="$LUKS_KARG"; then
            log "ERROR: grubby LUKS-karg update failed; leaving service retryable"
            exit 1
        fi
        if [ -f /etc/default/grub ] && grep -q '^GRUB_CMDLINE_LINUX=' /etc/default/grub; then
            if ! grep -qF "$LUKS_KARG" /etc/default/grub; then
                sed -i 's|^\(GRUB_CMDLINE_LINUX=".*\)"$|\1 '"$LUKS_KARG"'"|' /etc/default/grub
                log "/etc/default/grub: appended LUKS unlock-retry karg"
            fi
        fi
    fi
else
    log "LUKS: no rd.luks.uuid on cmdline — skipping unlock-retry karg"
fi

# grubby above is the native mutator, but it does not guarantee canonical
# ordering. Close every durable surface through the shared merger before any
# success marker can be published.
if ! CANONICAL_CMDLINE=$(/usr/libexec/noid-canonicalize-kernel-cmdline --publish); then
    log "ERROR: canonical kernel-cmdline merger failed; leaving service retryable"
    exit 1
fi

active_cmdline=$(active_cmdline_value)
active_sha256=$(line_sha256 "$active_cmdline")
desired_sha256=$(line_sha256 "$CANONICAL_CMDLINE")
boot_id=$(cat "$BOOT_ID_FILE")
case "$boot_id" in
    ????????-????-????-????-????????????) ;;
    *) log "ERROR: invalid kernel boot ID"; exit 1 ;;
esac
mkdir -p "$STATE_DIR"
active_pending=0

if [ "$active_cmdline" != "$CANONICAL_CMDLINE" ]; then
    if [ -e "$REBOOT_STATE" ] || [ -L "$REBOOT_STATE" ]; then
        if ! valid_reboot_state; then
            log "ERROR: invalid firstboot cmdline reboot evidence"
            exit 1
        fi
        marker_active=$(awk -F= '$1 == "active_sha256" {print $2}' "$REBOOT_STATE")
        marker_desired=$(awk -F= '$1 == "desired_sha256" {print $2}' "$REBOOT_STATE")
        marker_boot_id=$(awk -F= '$1 == "prepared_boot_id" {print $2}' "$REBOOT_STATE")
        recovery_attempt=$(awk -F= '$1 == "recovery_attempt" {print $2}' "$REBOOT_STATE")
        if [ "$marker_active" != "$active_sha256" ] \
           || [ "$marker_desired" != "$desired_sha256" ]; then
            log "ERROR: firstboot reboot evidence does not bind active/durable bytes"
            exit 1
        fi
        if [ "$marker_boot_id" = "$boot_id" ]; then
            log "pending: prepared cmdline is awaiting its first user-controlled reboot"
        elif [ "$recovery_attempt" -eq 0 ]; then
            # A power loss may occur after M20 durably rebinds this evidence
            # but before grubby publishes the root-selector removal. The
            # canonicalizer has repaired all durable sources in this boot.
            # Rearm once; a second boot with the same old active bytes fails.
            write_reboot_state "$active_sha256" "$desired_sha256" "$boot_id" 1
            log "pending: recovered one interrupted boot-policy publication; reboot once"
        else
            log "ERROR: active cmdline still differs after the requested reboot"
            exit 1
        fi
    else
        write_reboot_state "$active_sha256" "$desired_sha256" "$boot_id" 0
    fi
    log "durable cmdline is canonical; one user-controlled reboot is required before sealing"
    active_pending=1
fi

if [ "$active_pending" -eq 0 ] \
        && { [ -e "$REBOOT_STATE" ] || [ -L "$REBOOT_STATE" ]; }; then
    if ! valid_reboot_state \
       || ! grep -qxF "desired_sha256=$desired_sha256" "$REBOOT_STATE"; then
        log "ERROR: invalid firstboot cmdline reboot evidence"
        exit 1
    fi
    rm -f "$REBOOT_STATE"
fi

# Durable postcondition: the sentinel is allowed only when every required
# target argument is present in the kernel-install source of truth. /proc/
# cmdline still represents the current boot and cannot prove next-boot state.
for required_arg in $EXTRA ${LUKS_KARG:-}; do
    [ -n "$required_arg" ] || continue
    if ! tr ' ' '\n' < /etc/kernel/cmdline | grep -qxF "$required_arg"; then
        log "ERROR: durable kernel cmdline missing required argument: $required_arg"
        exit 1
    fi
done

for retired_family in acpi_backlight mem_sleep_default; do
    if tr ' ' '\n' < /etc/kernel/cmdline | grep -q "^${retired_family}="; then
        log "ERROR: durable kernel cmdline retains retired argument family: $retired_family"
        exit 1
    fi
    if [ -f /etc/default/grub ] && \
            grep -qE "GRUB_CMDLINE_LINUX=.*([ \"]|^)${retired_family}=" /etc/default/grub; then
        log "ERROR: /etc/default/grub retains retired argument family: $retired_family"
        exit 1
    fi
done

case "$CPU_EXTRA" in
    intel_iommu=on*) FORBIDDEN_CPU_ARGS="amd_iommu=on" ;;
    amd_iommu=on*)   FORBIDDEN_CPU_ARGS="intel_iommu=on" ;;
    *)               FORBIDDEN_CPU_ARGS="intel_iommu=on amd_iommu=on" ;;
esac
for forbidden_arg in $FORBIDDEN_CPU_ARGS; do
    if tr ' ' '\n' < /etc/kernel/cmdline | grep -qxF "$forbidden_arg"; then
        log "ERROR: durable kernel cmdline retains wrong-vendor argument: $forbidden_arg"
        exit 1
    fi
    if [ -f /etc/default/grub ] && grep -qE "GRUB_CMDLINE_LINUX=.*([ \"]|=)${forbidden_arg}([ \"]|$)" /etc/default/grub; then
        log "ERROR: /etc/default/grub retains wrong-vendor argument: $forbidden_arg"
        exit 1
    fi
done

# === HTTPS-only metalink re-application ===
# Defense-in-depth: M01 STEP 2b applies &protocol=https to fedora*.repo at
# install-time, but fedora-cisco-openh264.repo gets reverted POST-%post
# (evidence: ks-01.log "[patched] 4 repos" but live shows
# only 3/4 patched — cisco mtime 28s after STEP 2b log close. Likely cause:
# Anaconda's repo-restore at install-end OR fedora-repos %posttrans
# scriptlet that re-installs default repo files after %post phase).
# Re-apply at firstboot when all Anaconda transactions are done. Idempotent:
# ^metalink=...$ regex only matches lines without &protocol=https present.
# Pattern parallels the master.ks SSH-fix:
# Anaconda Network-Task runs after %post and re-adds ssh — same architectural
# pattern. There: declarative kickstart-directive. Here: no metalink-protocol
# directive exists, so re-apply at firstboot via this existing service.
HTTPS_PATCHED=0
repo_has_unrestricted_metalink() {
    [ -f "$1" ] && [ ! -L "$1" ] || return 0
    awk '
        /^[[:space:]]*metalink[[:space:]]*=/ {
            url = $0
            sub(/^[[:space:]]*metalink[[:space:]]*=[[:space:]]*/, "", url)
            sub(/[[:space:]#;].*$/, "", url)
            if (url !~ /^https:\/\// ||
                    url !~ /[?&]protocol=https([&#]|$)/) {
                bad = 1
            }
        }
        END { exit bad ? 0 : 1 }
    ' "$1"
}
restrict_repo_metalinks() {
    [ -f "$1" ] && [ ! -L "$1" ] || return 1
    sed -i -E '
        /^[[:space:]]*metalink[[:space:]]*=/ {
            /[?&]protocol=https([&#;[:space:]]|$)/! {
                s|^([[:space:]]*metalink[[:space:]]*=[[:space:]]*https://[^[:space:]#;]+)([[:space:]]*([#;].*)?)$|\1\&protocol=https\2|
            }
        }
    ' "$1"
    ! repo_has_unrestricted_metalink "$1"
}
for repo in /etc/yum.repos.d/fedora*.repo; do
    [ -e "$repo" ] || [ -L "$repo" ] || continue
    if [ ! -f "$repo" ] || [ -L "$repo" ]; then
        log "ERROR: unsafe Fedora repository config: $(basename "$repo")"
        exit 1
    fi
    if repo_has_unrestricted_metalink "$repo"; then
        if ! restrict_repo_metalinks "$repo"; then
            log "ERROR: metalink HTTPS-restrict could not parse $(basename "$repo")"
            exit 1
        fi
        HTTPS_PATCHED=$((HTTPS_PATCHED + 1))
        log "metalink HTTPS-restricted: $(basename "$repo")"
    fi
done
[ "$HTTPS_PATCHED" -gt 0 ] && log "metalink HTTPS-restrict: $HTTPS_PATCHED repos patched at firstboot"
# A reformatted vendor metalink= line can make sed a silent no-op. Verify every
# active line and keep the oneshot retryable instead of sealing degraded state.
metalink_unrestricted=0
repos_inspected=0
for repo in /etc/yum.repos.d/fedora*.repo; do
    [ -e "$repo" ] || [ -L "$repo" ] || continue
    if [ ! -f "$repo" ] || [ -L "$repo" ]; then
        log "ERROR: Fedora repository config became unsafe: $(basename "$repo")"
        metalink_unrestricted=$((metalink_unrestricted + 1))
        continue
    fi
    repos_inspected=$((repos_inspected + 1))
    if repo_has_unrestricted_metalink "$repo"; then
        log "ERROR: $(basename "$repo") violates the HTTPS metadata/mirror transport contract"
        metalink_unrestricted=$((metalink_unrestricted + 1))
    fi
done
if [ "$repos_inspected" -eq 0 ]; then
    log "ERROR: no regular Fedora repository config was inspected; leaving service retryable"
    exit 1
fi
if [ "$metalink_unrestricted" -gt 0 ]; then
    log "ERROR: $metalink_unrestricted Fedora repo config(s) remain unrestricted; leaving service retryable"
    exit 1
fi

# === GRUB_DISABLE_OS_PROBER=true re-apply ===
# Defense-in-depth: M01 STEP 1 adds this directive at install-time, but
# Anaconda bootloader-install runs AFTER %post and regenerates /etc/default/
# grub from Anaconda's template — dropping our line. Re-apply at firstboot
# (post-Anaconda) ensures live state matches source intent. Idempotent.
# Functional impact is doc-only (os-prober not installed on NoID Privacy), but
# audit-thoroughness doctrine requires source↔live parity.
if [ -f /etc/default/grub ]; then
    if grep -q '^GRUB_DISABLE_OS_PROBER=' /etc/default/grub; then
        if ! grep -q '^GRUB_DISABLE_OS_PROBER=true$' /etc/default/grub; then
            sed -i 's|^GRUB_DISABLE_OS_PROBER=.*|GRUB_DISABLE_OS_PROBER=true|' /etc/default/grub
            log "/etc/default/grub: GRUB_DISABLE_OS_PROBER=true (sed-replaced)"
        fi
    else
        echo 'GRUB_DISABLE_OS_PROBER=true' >> /etc/default/grub
        log "/etc/default/grub: GRUB_DISABLE_OS_PROBER=true (appended — Anaconda overwrote M01 STEP 1)"
    fi
fi
command -v restorecon >/dev/null 2>&1 \
    || { log "ERROR: restorecon is unavailable"; exit 1; }
command -v matchpathcon >/dev/null 2>&1 \
    || { log "ERROR: matchpathcon is unavailable"; exit 1; }
restorecon -F /etc/default/grub
if ! matchpathcon -V /etc/default/grub; then
    log "ERROR: /etc/default/grub SELinux label differs after convergence"
    exit 1
fi

# A pending first-session delta is an expected, explicit lifecycle state: all
# durable files and dependent firstboot preparation may complete, but the
# active/durable equality seal remains forbidden until the user restarts from
# the bottom action in NoID Privacy Welcome. Returning success lets the ordered
# M20/M21 preparation chain finish in this session without pretending that the
# running kernel already consumed the new bytes.
if [ "$active_pending" -eq 1 ]; then
    log "pending: restart from NoID Privacy Welcome to activate and seal hardening"
    exit 0
fi

state_tmp=$(mktemp "$STATE_DIR/.firstboot-cmdline-done.XXXXXXXX")
printf '%s\n' NOID_FIRSTBOOT_CMDLINE_V2 \
    "desired_sha256=$desired_sha256" \
    "active_sha256=$(printf '%s\n' "$active_cmdline" | sha256sum | awk '{print $1}')" \
    > "$state_tmp"
chmod 0644 "$state_tmp"
chown root:root "$state_tmp"
sync -- "$state_tmp"
mv -fT "$state_tmp" "$STATE_FILE"
sync -- "$STATE_DIR"
log "done"
CMDLINE_EOF
chmod 755 /usr/local/sbin/noid-firstboot-cmdline.sh
chown root:root /usr/local/sbin/noid-firstboot-cmdline.sh

cat > /etc/systemd/system/noid-firstboot-cmdline.service <<'CMDLINE_SVC_EOF'
[Unit]
Description=NoID Privacy: apply hardware-conditional + LUKS-retry kernel cmdline kargs (firstboot)
Documentation=file:///usr/local/sbin/noid-firstboot-cmdline.sh
After=local-fs.target
Before=multi-user.target graphical.target
ConditionKernelCommandLine=!rd.live.image

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/noid-firstboot-cmdline.sh
RemainAfterExit=no
UMask=0077
StandardOutput=journal+console
StandardError=journal+console

# 2026-baseline sandbox — script writes to /boot (BLS + grubenv),
# /etc/default/grub, /etc/kernel/cmdline, /etc/yum.repos.d (metalink
# HTTPS-restrict re-apply), /var/lib/noid-privacy (state), /var/log
# (logger). ReadWritePaths whitelists exactly these.
#
# SystemCallFilter is INTENTIONALLY absent. Live first-boot
# evidence: SIGSYS kill at script line 90 `sed -i 's|^GRUB_CMDLINE_LINUX=...
# ' /etc/default/grub` + grubby-internal `sed -i` calls. The
# `~@privileged @resources` filter blocks rename() (sed -i atomic-
# rename) + scriptlet execve() paths. Lesson #16 build-vs-target
# seccomp-incompatibility class for tools that manipulate /etc/* +
# /boot/* via atomic-replace. Service is oneshot + sentinel-gated +
# IPAddressDeny=any retained → small attack-window acceptable.
NoNewPrivileges=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
ProtectKernelLogs=yes
ProtectHostname=yes
ProtectClock=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/boot /etc/default /etc/kernel /etc/yum.repos.d /var/lib/noid-privacy /var/log
PrivateTmp=yes
RestrictAddressFamilies=AF_UNIX
RestrictNamespaces=yes
MemoryDenyWriteExecute=yes
IPAddressDeny=any
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
CMDLINE_SVC_EOF
chmod 644 /etc/systemd/system/noid-firstboot-cmdline.service
chown root:root /etc/systemd/system/noid-firstboot-cmdline.service
if ! systemctl enable noid-firstboot-cmdline.service; then
    log "ERROR: could not enable noid-firstboot-cmdline.service"
    exit 1
fi
log "STEP 4c: noid-firstboot-cmdline.service installed + enabled"

# Build-time-state-leak guard: neither success evidence nor an armed transition
# may survive the qemu install phase into the installed disk image. Reject an
# unexpected object type and verify the absence postcondition instead of
# swallowing a failed deletion.
for stale_state in \
        /var/lib/noid-privacy/.firstboot-cmdline-done \
        /var/lib/noid-privacy/.firstboot-cmdline-reboot-required; do
    if [ -e "$stale_state" ] || [ -L "$stale_state" ]; then
        if [ ! -f "$stale_state" ] || [ -L "$stale_state" ]; then
            log "ERROR: unsafe build-time firstboot state object: $stale_state"
            exit 1
        fi
        if ! rm -f -- "$stale_state"; then
            log "ERROR: could not remove build-time firstboot state: $stale_state"
            exit 1
        fi
    fi
    if [ -e "$stale_state" ] || [ -L "$stale_state" ]; then
        log "ERROR: build-time firstboot state survived cleanup: $stale_state"
        exit 1
    fi
done
log "STEP 4c: build-time success/reboot evidence is absent"

# ====================================================================
# STEP 5: NVIDIA info (detection only, no blacklist or dracut)
# ====================================================================
# Image ships nouveau+NVK as default (Module 19: docs-only, manual opt-in).
# On opt-in the akmod-nvidia RPM scriptlets create the nouveau blacklist +
# nvidia.conf; the vendor dracut config deliberately OMITS nvidia from the
# initramfs — LUKS-prompt visibility comes from the NVIDIA-conditional
# plymouth.use-simpledrm=1 in GPU_EXTRA (STEP 4b).
if [ "$HAS_NVIDIA" = "1" ]; then
    log "STEP 5: NVIDIA GPU detected — nouveau+NVK active as default"
    log "  User can opt-in to proprietary: see /usr/share/doc/noid-privacy/19-nvidia-drivers.md"
else
    log "STEP 5: no NVIDIA GPU detected"
fi

# ====================================================================
# STEP 5b: GRUB password infrastructure — opt-in bootloader lockdown
# ====================================================================
# Stock /etc/grub.d/01_users (grub2-tools) defines a GRUB superuser when
# /boot/grub2/user.cfg exists. Fedora BLS entries remain unrestricted for
# normal selection, while edit/command access requires authentication. Without
# it, physical
# access at the GRUB menu allows karg tampering (init=/bin/sh etc.).
# Here: verify 01_users exists, install the noid-grub-password helper,
# ship the user doc. NOT enabled by default — a pre-installed password
# would be an undocumented lock on a generic image; opt-in is one command.

log "STEP 5b: GRUB password infrastructure (opt-in)"

# 5b.1 — Verify the load-bearing stock 01_users behavior, not just its path.
if [ ! -x /etc/grub.d/01_users ]; then
    log "  [FAIL] /etc/grub.d/01_users missing or not executable"
    exit 1
fi
if ! users_template=$(/etc/grub.d/01_users) || \
   ! grep -qF 'set superusers="root"' <<<"$users_template" || \
   ! grep -qF 'password_pbkdf2 root ${GRUB2_PASSWORD}' <<<"$users_template"; then
    log "  [FAIL] stock 01_users authentication behavior differs"
    exit 1
fi
log "  [OK] stock 01_users root/password_pbkdf2 behavior verified"

# 5b.2 — Install CLI helper
cat > /usr/local/sbin/noid-grub-password <<'GRUBPW_EOF'
#!/bin/bash
# noid-grub-password — interactive GRUB bootloader password setup
#
# Usage: sudo noid-grub-password [--remove]
#
# What this does:
#   1. Shows its own TTY prompts and confirms the password twice
#   2. Generates a PBKDF2 hash via grub2-mkpasswd-pbkdf2
#   3. Verifies Fedora's 01_users + unrestricted BLS menu semantics
#   4. Publishes /boot/grub2/user.cfg atomically with mode 600
#
# After this runs:
#   - GRUB edit-mode (`e` key) prompts for password "root"
#   - Normal boot selection works WITHOUT password
#     (Fedora's normal-boot menu remains usable; only admin paths lock)
#
# To disable later:
#   sudo noid-grub-password --remove
#
# To reset password:
#   sudo noid-grub-password  # just re-run, overwrites user.cfg

set -euo pipefail

# shellcheck source=/dev/null
[ ! -r /usr/local/lib/noid-privacy/agent-install-format.sh ] || \
    NOID_FMT_AUTO_TITLE="NoID Privacy — GRUB Password" \
    NOID_FMT_AUTO_SUBTITLE="Bootloader edit protection" \
    . /usr/local/lib/noid-privacy/agent-install-format.sh

usage() { echo "usage: sudo noid-grub-password [--remove]"; }
operation=setup
case "${1:-}" in
    "") ;;
    --remove) operation=remove ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
esac

if [ "$(id -u)" != "0" ]; then
    echo "ERROR: must be run as root (sudo)" >&2
    exit 1
fi

USER_CFG=/boot/grub2/user.cfg
GRUB_CFG=/boot/grub2/grub.cfg
USERS_SCRIPT=/etc/grub.d/01_users
BLS_DIR=/boot/loader/entries
BOOT_LOCK=/run/lock/noid-boot-mutation.lock
BOOT_GUARD=/usr/libexec/noid-boot-mutation-guard
TMP_CFG=""
TMP_GRUB=""
PASSWORD_ONE=""
PASSWORD_TWO=""
cleanup() {
    unset PASSWORD_ONE PASSWORD_TWO HASH_OUTPUT HASH HASHES USERS_TEMPLATE
    [ -z "$TMP_CFG" ] || rm -f -- "$TMP_CFG"
    [ -z "$TMP_GRUB" ] || rm -f -- "$TMP_GRUB"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

for tool in chown chmod flock grep grub2-mkconfig grub2-mkpasswd-pbkdf2 \
        mktemp mv sync; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "ERROR: required command missing: $tool" >&2
        exit 1
    }
done
[ -x "$USERS_SCRIPT" ] || {
    echo "ERROR: $USERS_SCRIPT missing or not executable" >&2
    exit 1
}
USERS_TEMPLATE=$($USERS_SCRIPT) || {
    echo "ERROR: $USERS_SCRIPT execution failed" >&2
    exit 1
}
if ! grep -qF 'set superusers="root"' <<<"$USERS_TEMPLATE" || \
   ! grep -qF 'password_pbkdf2 root ${GRUB2_PASSWORD}' <<<"$USERS_TEMPLATE"; then
    echo "ERROR: stock 01_users authentication behavior differs" >&2
    exit 1
fi
[ -d "$BLS_DIR" ] || {
    echo "ERROR: BLS directory missing: $BLS_DIR" >&2
    exit 1
}

acquire_boot_contract() {
    [ -f "$BOOT_LOCK" ] && [ ! -L "$BOOT_LOCK" ] || {
        echo "ERROR: shared boot-mutation lock is missing or unsafe" >&2
        exit 1
    }
    [ -f "$BOOT_GUARD" ] && [ ! -L "$BOOT_GUARD" ] \
        && [ -x "$BOOT_GUARD" ] || {
        echo "ERROR: boot-mutation guard is missing or unsafe" >&2
        exit 1
    }
    exec 9<>"$BOOT_LOCK"
    flock -w 300 9 || {
        echo "ERROR: timed out waiting for another boot mutation" >&2
        exit 75
    }
    boot_basis=$($BOOT_GUARD) || {
        echo "ERROR: M21 boot basis is not in a confirmed terminal state" >&2
        exit 1
    }
    case "$boot_basis" in
        basis=hostonly|basis=generic) ;;
        *) echo "ERROR: boot-mutation guard returned an invalid basis" >&2; exit 1 ;;
    esac
}

if [ "$operation" = remove ]; then
    acquire_boot_contract
    [ -f "$GRUB_CFG" ] && [ ! -L "$GRUB_CFG" ] || {
        echo "ERROR: $GRUB_CFG missing or unsafe" >&2
        exit 1
    }
    if ! grep -qF 'set superusers="root"' "$GRUB_CFG" || \
       ! grep -qF 'password_pbkdf2 root ${GRUB2_PASSWORD}' "$GRUB_CFG"; then
        echo "ERROR: current grub.cfg lacks the stock root authorization block" >&2
        exit 1
    fi
    if [ ! -e "$USER_CFG" ]; then
        echo "[OK] GRUB password already disabled; $USER_CFG is absent."
        exit 0
    fi
    [ -f "$USER_CFG" ] && [ ! -L "$USER_CFG" ] || {
        echo "ERROR: refusing to remove a non-regular or symlinked $USER_CFG" >&2
        exit 1
    }
    rm -f -- "$USER_CFG"
    [ ! -e "$USER_CFG" ] || {
        echo "ERROR: $USER_CFG removal postcondition failed" >&2
        exit 1
    }
    sync -- /boot/grub2
    echo "[OK] GRUB password disabled under the confirmed boot-mutation contract."
    exit 0
fi

echo "=========================================="
echo " NoID Privacy — GRUB bootloader password"
echo "=========================================="
echo
echo "This will set a password that guards GRUB edit-mode + command line."
echo "Normal boot-menu selection stays password-free."
echo
echo "You will be prompted twice for the new password. Input is hidden."
echo

# Fedora's grub2-mkpasswd-pbkdf2 writes both prompts to stdout. Capturing its
# output directly therefore makes an interactive invocation appear hung.
# Prompt visibly on /dev/tty first, then feed the confirmed secret to the tool
# while capturing its stdout for exact hash extraction.
[ -r /dev/tty ] && [ -w /dev/tty ] || {
    echo "ERROR: an interactive TTY is required" >&2
    exit 2
}
printf 'Enter new GRUB password: ' >/dev/tty
IFS= read -r -s PASSWORD_ONE </dev/tty || { echo >&2; exit 2; }
printf '\nReenter new GRUB password: ' >/dev/tty
IFS= read -r -s PASSWORD_TWO </dev/tty || { echo >&2; exit 2; }
printf '\n' >/dev/tty
if [ -z "$PASSWORD_ONE" ]; then
    echo "ERROR: empty GRUB passwords are not accepted" >&2
    exit 2
fi
if [ "$PASSWORD_ONE" != "$PASSWORD_TWO" ]; then
    echo "ERROR: passwords do not match" >&2
    exit 2
fi

if ! HASH_OUTPUT=$(printf '%s\n%s\n' "$PASSWORD_ONE" "$PASSWORD_TWO" | \
        LC_ALL=C grub2-mkpasswd-pbkdf2 2>&1); then
    unset PASSWORD_ONE PASSWORD_TWO
    echo "ERROR: grub2-mkpasswd-pbkdf2 failed" >&2
    exit 2
fi
unset PASSWORD_ONE PASSWORD_TWO

# Require exactly one complete PBKDF2-SHA512 result; prompts/diagnostics cannot
# be mistaken for the credential record.
mapfile -t HASHES < <(grep -oE \
    'grub\.pbkdf2\.sha512\.[0-9]+\.[0-9A-Fa-f]+\.[0-9A-Fa-f]+' \
    <<<"$HASH_OUTPUT")
unset HASH_OUTPUT
if [ "${#HASHES[@]}" -ne 1 ]; then
    echo "ERROR: expected exactly one PBKDF2-SHA512 hash" >&2
    exit 3
fi
HASH=${HASHES[0]}

# Human input and PBKDF2 generation intentionally happen before the shared
# lock. Only the bounded /boot transaction is serialized. The M21 guard rejects
# pending-reboot, retry and active Generic-fallback states, so a credential
# change cannot alter the boot path during the candidate/fallback trial.
acquire_boot_contract

# Stage and validate the Fedora authorization structure before publishing a
# new credential. 01_users sources user.cfg dynamically, so this can be done
# while a first-time user.cfg is absent or the previous credential remains.
umask 077
TMP_GRUB=$(mktemp "${GRUB_CFG}.tmp.XXXXXX") || exit 4
echo "Staging regenerated $GRUB_CFG..."
grub2-mkconfig -o "$TMP_GRUB" || {
    echo "ERROR: grub2-mkconfig failed; credential was not published" >&2
    exit 4
}
if ! grep -qF 'set superusers="root"' "$TMP_GRUB" || \
   ! grep -qF 'password_pbkdf2 root ${GRUB2_PASSWORD}' "$TMP_GRUB"; then
    echo "ERROR: generated grub.cfg lacks the stock root authorization block" >&2
    exit 4
fi
shopt -s nullglob
BLS_ENTRIES=("$BLS_DIR"/*.conf)
shopt -u nullglob
[ "${#BLS_ENTRIES[@]}" -gt 0 ] || {
    echo "ERROR: no BLS entries found" >&2
    exit 4
}
for entry in "${BLS_ENTRIES[@]}"; do
    [ "$(grep -cFx 'grub_arg --unrestricted' "$entry")" -eq 1 ] || {
        echo "ERROR: normal BLS entry is not exactly unrestricted: $entry" >&2
        exit 4
    }
done

chmod 0600 "$TMP_GRUB"
chown root:root "$TMP_GRUB"
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F "$TMP_GRUB" >/dev/null \
        || { echo "ERROR: could not label staged grub.cfg" >&2; exit 4; }
fi
sync -- "$TMP_GRUB"
mv -fT -- "$TMP_GRUB" "$GRUB_CFG"
TMP_GRUB=""
sync -- "$GRUB_CFG"
sync -- /boot/grub2

# Create beside the destination, fix metadata, then atomically replace.
TMP_CFG=$(mktemp "${USER_CFG}.tmp.XXXXXX") || exit 5
cat > "$TMP_CFG" <<CFG
# NoID Privacy — GRUB bootloader password (generated by noid-grub-password)
# This file is sourced by /etc/grub.d/01_users at grub.cfg-regeneration time.
# Mode 600: only root can read (hash is brute-forceable if disclosed).
GRUB2_PASSWORD=$HASH
CFG
unset HASH
chmod 600 "$TMP_CFG"
chown root:root "$TMP_CFG"
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F "$TMP_CFG" >/dev/null \
        || { echo "ERROR: could not label staged user.cfg" >&2; exit 5; }
fi
sync -- "$TMP_CFG"
mv -fT -- "$TMP_CFG" "$USER_CFG"
TMP_CFG=""
sync -- "$USER_CFG"
sync -- /boot/grub2

echo
echo "[OK] $USER_CFG atomically published (root:root, mode 600)"
echo "DONE. Generated GRUB authorization structure verified."
echo "  - Username: root"
echo "  - Test: reboot + press 'e' at GRUB menu → should prompt for password"
echo
echo "To remove safely: sudo noid-grub-password --remove"
GRUBPW_EOF
chmod 755 /usr/local/sbin/noid-grub-password
chown root:root /usr/local/sbin/noid-grub-password
log "  [OK] /usr/local/sbin/noid-grub-password installed"

# 5b.3 — Ship user doc
mkdir -p /usr/share/doc/noid-privacy
cat > /usr/share/doc/noid-privacy/01-grub-password.md <<'GRUBDOC_EOF'
# GRUB Bootloader Password — NoID Privacy

## What This Protects Against

Without a GRUB password, anyone with **physical access** to a booted
(but not logged-in) system can press `e` at the GRUB menu and edit the
kernel cmdline to do things like:

- `init=/bin/sh` → drops to a single-user shell with root privileges
- Remove `lockdown=integrity` → disable kernel lockdown mode
- Remove `rd.shell=0 rd.emergency=halt` → re-enable the initramfs failure shell
- Add `selinux=0` → disable SELinux

LUKS still protects data-at-rest, but the attacker can:
- Modify the unencrypted `/boot` partition (tamper with initramfs or kernel)
- Boot into a rescue-scenario that bypasses the login manager
- Enroll new LUKS passphrases if the device is later unlocked by you

**A GRUB password stops unauthenticated GRUB edit/command access.** It does not
authenticate files on the unencrypted `/boot`, protect firmware settings, or
turn physical access into a verified-boot guarantee.

When firmware Secure Boot is enabled, the firmware/shim/GRUB/kernel signature
path provides a separate trust layer for the components and keys it covers.
`module.sig_enforce=1` is narrower: after the kernel starts, it requires valid
signatures for loadable kernel modules. It does not authenticate `grub.cfg` or
the separate initramfs. Enrolling a MOK adds a trusted signing key; it expands
the trust set and is not evidence that the current `/boot` contents are intact.

## How to Enable

Run the helper (one command, interactive):

```bash
sudo noid-grub-password
```

This:
1. Shows two hidden-input TTY prompts and checks they match
2. Generates a PBKDF2-SHA512 hash
3. Verifies the stock `/etc/grub.d/01_users` root authorization block and
   Fedora's `grub_arg --unrestricted` normal BLS entries
4. Regenerates and verifies `/boot/grub2/grub.cfg`
5. Atomically publishes `/boot/grub2/user.cfg` with
   `GRUB2_PASSWORD=<hash>` (root:root, mode 600)

The "username" for the GRUB password prompt is `root` (hardcoded by
`/etc/grub.d/01_users`).

## Behavior After Enabling

| GRUB action | Password required? |
|---|---|
| Default boot selection | no |
| Boot entry selection (up/down arrow) | no |
| `e` edit-mode (edit kernel cmdline) | **yes** |
| `c` drop to GRUB command line | **yes** |

This preserves Fedora's ordinary normal-boot menu behavior while protecting
edit/command access. A custom menu entry without `--unrestricted` can have
different selection behavior; the helper verifies the installed Fedora BLS
entries rather than making a universal claim about custom entries.

## How to Change Password

Just re-run `sudo noid-grub-password`. It overwrites `/boot/grub2/user.cfg`.

## How to Remove

```bash
sudo noid-grub-password --remove
```

The helper takes the shared boot-mutation lock and refuses the change while
M21 still has a candidate reboot, retry or Generic fallback transition armed.
It removes only the regular credential file after verifying the current Fedora
authorization structure; it does not bypass the guarded boot lifecycle.

## Trust Chain

- `grub2-tools` ships `/etc/grub.d/01_users` — standard Fedora package file,
  signed via RPM GPG (rpmkeys --verify grub2-tools).
- `grub2-mkpasswd-pbkdf2` generates a self-describing PBKDF2-SHA512 record; the
  iteration count is part of that record. This is password storage, not a
  certification claim.
- `/boot/grub2/user.cfg` is mode 600, root-only. Hash is brute-forceable if
  disclosed; protect the file's permissions.

## Verify It's Active

```bash
# Check user.cfg exists
ls -l /boot/grub2/user.cfg

# Check it's referenced in grub.cfg (01_users script inlined)
grep -A2 password_pbkdf2 /boot/grub2/grub.cfg
```

## Related Hardening

- LUKS2 encryption (M22 `22-disk-encryption.md`) — protects data-at-rest
- Secure Boot + MOK (M19 `19-secure-boot-mok.md`) — separate boot/key trust
  boundary; enroll only a key whose provenance you verified
- `module.sig_enforce=1` kcmdline flag (M01) — enforces signatures on loadable
  kernel modules after kernel start; it is not `/boot` integrity

GRUB password closes the runtime-kargs-edit attack; the other three close
the evil-maid + data-at-rest attacks.
GRUBDOC_EOF
chmod 644 /usr/share/doc/noid-privacy/01-grub-password.md
log "  [OK] /usr/share/doc/noid-privacy/01-grub-password.md written"

# ====================================================================
# STEP 6: REMOVED — never run grub2-mkconfig in %post
# ====================================================================
# Running grub2-mkconfig in kickstart %post is a known anti-pattern on
# BLS-default Fedora: Anaconda's bootloader-install runs AFTER %post, and a
# pre-created grub.cfg makes its gen_grub_cfgstub abort the whole
# bootloader install (BLS entries not yet populated, grubenv blsdir wrong).
# Trust Anaconda: it picks up our /etc/default/grub edits when IT runs
# grub2-mkconfig at the right time. The noid-grub-password helper's own
# installed-system call stages the file and runs only under the shared boot-
# mutation lock after M21 reports a terminal basis.
log "STEP 6: skipped — grub2-mkconfig deferred to Anaconda's own bootloader install"

# ====================================================================
# STEP 7: Explicit crypto-policy DEFAULT
# ====================================================================
# Capture diagnostics and fail closed: the declared system-wide policy is a
# security contract, not a best-effort preference.
CRYPTO_POLICY_LOG=/var/log/noid-crypto-policy.err
if ! command -v update-crypto-policies >/dev/null 2>&1; then
    log "STEP 7: FAIL: update-crypto-policies is unavailable"
    exit 1
fi
if ! update-crypto-policies --set DEFAULT 2>"$CRYPTO_POLICY_LOG"; then
    log "STEP 7: FAIL: could not apply DEFAULT (see $CRYPTO_POLICY_LOG)"
    exit 1
fi
if ! active_crypto_policy=$(update-crypto-policies --show 2>>"$CRYPTO_POLICY_LOG"); then
    log "STEP 7: FAIL: could not read active policy (see $CRYPTO_POLICY_LOG)"
    exit 1
fi
if [ "$active_crypto_policy" != DEFAULT ] \
   || ! update-crypto-policies --check >>"$CRYPTO_POLICY_LOG" 2>&1; then
    log "STEP 7: FAIL: DEFAULT policy postcondition differs (see $CRYPTO_POLICY_LOG)"
    exit 1
fi
rm -f -- "$CRYPTO_POLICY_LOG"
log "STEP 7: crypto-policy DEFAULT applied and generated state verified"

# ====================================================================
# STEP 8: REMOVED — stale-EFI-cleanup firstboot service dropped
# ====================================================================
# Anaconda handles UEFI boot-entry idempotency natively; auto-removing
# foreign firmware boot entries diverged from the UEFI spec and never
# matched real firmware behavior. Placeholder kept because the repo's
# orphan/squash release workflow makes the removal commit unreachable
# from main — the in-file note is the durable record (STEP 3/6 convention).

# ============================================================================
# STEP 9: Protect both RPM-shipped System.map copies without deleting them
# ============================================================================
# Fedora kernel-core ships world-readable symbol tables at both
# /boot/System.map-VERSION and /usr/lib/modules/VERSION/System.map. Mode 0600
# keeps their symbol tables out of unprivileged local reads while retaining the
# package-native files. Retention is load-bearing: RPM Fusion's generated kmod
# scriptlet checks these exact paths before selecting target-specific
# `depmod -aeF <map> <kver>`; deleting both makes its fallback `depmod -a`
# refresh only the running kernel during an old->new kernel transaction.
# (a) the kernel-install hook protects both paths on every future `add`;
# (b) the %post-time pass covers every install-time kernel. M13 therefore keeps
# both files inside AIDE scope, and M33 documents only their intentional mode
# difference from the RPM payload.

log "STEP 9: deploy /etc/kernel/install.d/99-noid-protect-system-map.install"

mkdir -p /etc/kernel/install.d
cat > /etc/kernel/install.d/99-noid-protect-system-map.install <<'SYSMAP_HOOK_EOF'
#!/bin/bash
#
# NoID Privacy — protect kernel System.map files post-install
#
# Called by kernel-install(8) on `add` (kernel package install) and `remove`
# (kernel package uninstall) events. We act only on `add` — the kernel rpm
# uninstall already removes both RPM-owned paths.
#
# Rationale: see Module 01 STEP 9. Both package files remain available to the
# native generated-kmod target-kernel depmod contract, but are root-only.
#
# Hook ordering: 99-* runs last (after grub-mkconfig, dracut, BLS entry
# creation and package-owned mode publication). Safe by lexical ordering.

set -euo pipefail

COMMAND="${1:-}"
KERNEL_VERSION="${2:-}"

case "$COMMAND" in
    add)
        [[ "$KERNEL_VERSION" =~ ^[A-Za-z0-9._+-]+$ ]] || {
            printf 'noid-system-map: invalid kernel version: %q\n' \
                "$KERNEL_VERSION" >&2
            exit 1
        }
        for system_map in \
            "/boot/System.map-${KERNEL_VERSION}" \
            "/usr/lib/modules/${KERNEL_VERSION}/System.map"; do
            if [ -e "$system_map" ] || [ -L "$system_map" ]; then
                [ -f "$system_map" ] && [ ! -L "$system_map" ] || {
                    printf 'noid-system-map: unsafe package path: %q\n' \
                        "$system_map" >&2
                    exit 1
                }
                chown root:root -- "$system_map"
                chmod 0600 -- "$system_map"
            fi
        done
        ;;
    *)
        # Other events (remove, etc.) — no action
        ;;
esac

exit 0
SYSMAP_HOOK_EOF
chmod 755 /etc/kernel/install.d/99-noid-protect-system-map.install
chown root:root /etc/kernel/install.d/99-noid-protect-system-map.install
rm -f -- /etc/kernel/install.d/99-noid-remove-system-map.install

# %post-time protection — cover both copies already on disk at install-time.
# Anaconda's kernel-install runs BEFORE this %post, so the hook deployed
# above only covers FUTURE kernel installs.
shopt -s nullglob
install_time_system_maps=(/boot/System.map-* /usr/lib/modules/*/System.map)
for system_map in "${install_time_system_maps[@]}"; do
    [ -f "$system_map" ] && [ ! -L "$system_map" ] || {
        printf 'noid-system-map: unsafe install-time package path: %q\n' \
            "$system_map" >&2
        exit 1
    }
    chown root:root -- "$system_map"
    chmod 0600 -- "$system_map"
done
shopt -u nullglob

log "STEP 9: System.map protection hook installed + install-time maps secured root-only"

log "=== Module 01 complete ==="
%end

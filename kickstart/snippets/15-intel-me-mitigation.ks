# ============================================================================
# Module 15 — Intel ME / AMD PSP — Firmware-Layer Mitigation
# Status: LOCKED 2026-08-02 (v45) — generate the hardware-layer doc from its canonical docs/ source.
#
# Covers:
#   - Step 0: CPU vendor detection (intel/amd/unknown via /proc/cpuinfo +
#     systemd-detect-virt) -> /var/lib/noid-privacy/cpu-vendor state file
#   - /etc/modprobe.d/noid-mei-submodules.conf — header-comment-only by
#     default: NO MEI sub-module blacklists (Kicksecure-consensus,
#     security-misc #239). mei + mei_me remain loadable so fwupd can inspect
#     Intel ME/BootGuard state on supported hardware. The file is the target
#     for the opt-in
#     --block CLI flow.
#   - /etc/udev/rules.d/99-noid-mei-kt-block.rules plus
#     /usr/libexec/noid-mei-kt-enforce — early KT/SOL PCI
#     driver_override=none and verified unbind fallback for 27 PCI IDs
#     (18 named KT/SOL redirection devices in current pci.ids plus nine
#     conservative kernel-family derivations; every match also requires the
#     Intel communications-other class and PCI function 3).
#     This removes the host-visible KT/SOL driver-binding surface after
#     enforcement; it does NOT block AMT's firmware-owned OOB network path.
#   - /etc/dracut.conf.d/noid-mei-blacklist.conf — ships the modprobe.d
#     file plus the KT/SOL udev rule/helper into the initramfs
#   - user docs: 15-intel-me-hardware-layer.md (AMT unprovisioning,
#     manageability-path removal, MEI trade-offs) and
#     15-amd-psp-hardware-layer.md (ASP/CCP, PSB, AIM-T/DASH boundaries)
#   - Step 5: mei-status.txt for noid-status (vendor-branched content)
#   - Step 5b: noid-mei-restore-submodules CLI (--list / --restore /
#     --block hdcp|pxp|wdt with per-module trade-off prompts)
#   - Step 5c: noid-mei-lockdown CLI (experimental: blacklists mei +
#     mei_me; loses normal fwupd ME/BootGuard visibility without changing
#     the OEM firmware policy)
#   - Step 5e: noid-cpu-vendor-detect-firstboot.{sh,service} — re-detects
#     vendor on REAL target hardware (Live-ISO %post runs in the build
#     qemu-VM, so build-time detection reflects the BUILD env, not the
#     target); refreshes each prevalidated record with an atomic rename on
#     every boot and binds status to the running kernel plus relevant policy
#   - Step 6: cross-check M13 AIDE SECURE coverage
#   - Step 7: vendor-aware verification (Intel branch + non-Intel mirror;
#     7.0a CONFIG_INTEL_MEI runtime guard, info-level)
#
# Deliberate deviations (do NOT re-litigate):
#   - NO default MEI sub-module blacklists: the functions and costs are
#     hardware-dependent, while blocking a client does not remove the MEI core
#     interface. All three remain opt-in via the --block CLI.
#   - Steps 1-4 deploy UNCONDITIONALLY (always-ship): an AMD-built ISO
#     installed on an Intel target must still carry the Intel mitigation;
#     on AMD silicon the configs are inert no-ops (modules absent, PCI IDs
#     never match). Step 7 verifies presence on BOTH branches.
#   - `ccp` is NOT blacklisted on AMD: blocking removes fwupd PCI-PSP
#     visibility and may break platform-specific CCP/PSP services, but does
#     not stop ASP firmware. fTPM dependency is explicitly not assumed.
#   - Docs assert NO fixed achieved-HSI level: fwupd visibility and every
#     reported attribute remain hardware-, firmware-, and driver-dependent.
#
# Constraint notes (keep when editing):
#   - systemd-detect-virt returns rc=1 on bare metal (stdout "none") —
#     capture stdout regardless of rc, never `$(cmd || echo fallback)`.
#   - The udev rule handles add and bind. The helper is idempotent, requires
#     the exact Intel vendor/device allow-list plus serial-controller class
#     0x0700xx (NOT the HECI/MEI class 0x078000) and PCI function 3, and
#     never logs PCI addresses or other machine identifiers.
#   - tests/15 asserts the PCI-ID set, the no-blacklist regression
#     guard, and several verify-echo strings — echo lines are code.
#   - docs/15-intel-me-hardware-layer.md is canonical for the Step 4 heredoc.
#     Regenerate this module with scripts/regen-intel-me-doc.sh; tests/00 gates
#     byte identity. Keep the delimiter unique inside this file — the generator
#     resolves its block by a single ordered marker pair, not by line numbers.
#   - Verify 7.1 uses the canonical grep -c pattern (`|| true` +
#     `${var:-0}`) — `|| echo 0` yields "0\n0" and aborts the build.
#
# Cross-reference:
#   - M01: intel_iommu=on / amd_iommu=on kargs + Secure Boot + lockdown.
#     These are generic host defenses, not an AMT disable. M03 intentionally
#     makes no AMT claim: firmware OOB traffic bypasses the host firewall.
#     M13: AIDE SECURE rules
#     + noid-status reads mei-status.txt. M21: kernel-module blacklist sibling.
#   - Historic: the Fedora kernel 7.0.4 CONFIG_INTEL_MEI=n regression
#     (resolved in 7.0.6) is permanently guarded by Step 7.0a.
# ============================================================================

# No %packages block — all MEI-related modules ship with the kernel package.
# mei-tools is also not shipped because no implemented control requires it.

%post --erroronfail --log=/var/log/ks-15-intel-me.log

set -euo pipefail
echo "=============================================================="
echo "[Module 15] Intel ME / AMD PSP — Firmware-Layer Mitigation"
echo "=============================================================="

# ----------------------------------------------------------------------------
# Step 0: CPU vendor detection
# ----------------------------------------------------------------------------
# Detect Intel / AMD / unknown — the vendor drives status-file content and
# the Step-7 verification branch (config writes themselves are always-ship,
# see Steps 1-4 below). State file /var/lib/noid-privacy/cpu-vendor feeds
# downstream modules + user-visible status tools.

CPU_VENDOR="unknown"
if grep -qE '^vendor_id[[:space:]]*:[[:space:]]*GenuineIntel' /proc/cpuinfo 2>/dev/null; then
    CPU_VENDOR="intel"
elif grep -qE '^vendor_id[[:space:]]*:[[:space:]]*(AuthenticAMD|HygonGenuine)' /proc/cpuinfo 2>/dev/null; then
    CPU_VENDOR="amd"
fi

# Virtualization detection — informational (firmware mitigations degrade in
# VMs; the configs are runtime no-ops there). CONSTRAINT: systemd-detect-virt
# returns rc=1 on bare metal with stdout "none" — capture stdout regardless
# of rc and default on empty; `$(cmd || echo fallback)` concatenates both.
VIRT_TYPE="none"
if command -v systemd-detect-virt >/dev/null 2>&1; then
    detected=$(systemd-detect-virt 2>/dev/null) || true
    if [ -n "$detected" ]; then
        VIRT_TYPE="$detected"
    fi
fi

if [ -e /var/lib/noid-privacy ] || [ -L /var/lib/noid-privacy ]; then
    [ -d /var/lib/noid-privacy ] && [ ! -L /var/lib/noid-privacy ] &&
        [ "$(stat -c '%u:%g:%a' /var/lib/noid-privacy)" = 0:0:755 ] || {
            echo "[FAIL] unsafe /var/lib/noid-privacy directory" >&2
            exit 1
        }
else
    install -d -m 0755 -o root -g root /var/lib/noid-privacy
fi
cat > /var/lib/noid-privacy/cpu-vendor <<VENDOR_EOF
CPU_VENDOR=$CPU_VENDOR
VIRT_TYPE=$VIRT_TYPE
DETECTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
VENDOR_EOF
chmod 644 /var/lib/noid-privacy/cpu-vendor
chown root:root /var/lib/noid-privacy/cpu-vendor
echo "[Step 0] CPU vendor: $CPU_VENDOR  (virt: $VIRT_TYPE)"
echo "         state file: /var/lib/noid-privacy/cpu-vendor"
if [ "$VIRT_TYPE" != "none" ]; then
    echo "         note: running in $VIRT_TYPE — firmware-layer mitigations"
    echo "               degrade in VMs (no real Intel ME / AMD PSP present)"
fi

# ----------------------------------------------------------------------------
# Steps 1-4: Intel MEI mitigation config writes (always-ship, build-host-agnostic)
# ----------------------------------------------------------------------------
# Steps 1-4 deploy UNCONDITIONALLY (always-ship, build-host-agnostic): the
# Live-ISO %post runs in the build qemu-VM, so gating on the BUILD host's
# vendor would let an AMD-built ISO ship WITHOUT the Intel mitigation for an
# Intel target (security regression). On AMD silicon the configs are inert
# no-ops (mei modules absent, PCI IDs never match). Step 5e handles the
# status-file side of the same build-vs-target mismatch.

# ----------------------------------------------------------------------------
# Step 1: Write /etc/modprobe.d/noid-mei-submodules.conf  (always-ship)
# ----------------------------------------------------------------------------
# Kicksecure-consensus (security-misc #239): NO default MEI sub-module
# blacklist — the file is header-comment-only + a target for the opt-in
# `noid-mei-restore-submodules --block` CLI. Core mei + mei_me stay loadable
# for fwupd platform-security visibility on compatible hardware.
#
# blacklist = prevents auto-loading by udev/modprobe
# install /bin/false = makes modprobe fail even on manual invocation by root
#
echo ""
echo "[Step 1] Writing /etc/modprobe.d/noid-mei-submodules.conf"

cat > /etc/modprobe.d/noid-mei-submodules.conf <<'MODPROBE_EOF'
# ============================================================================
# NoID Privacy — Intel MEI sub-module configuration (Kicksecure-consensus)
# Design rationale: captured inline below.
# ============================================================================
#
# STRATEGIC DECISION:
# NoID Privacy does NOT default-blacklist ANY MEI sub-modules. The core
# `mei` and `mei_me` modules REMAIN LOADABLE for fwupd Intel ME/BootGuard
# inspection on supported hardware. The three sub-modules `mei_hdcp`,
# `mei_pxp`, and `mei_wdt` are not blacklisted and may autoload when matching
# hardware exposes them — same conclusion as Kicksecure security-misc
# Issue #239 (2025): the cost outweighed the marginal security gain across
# the entire MEI sub-module family.
#
# Verified cost/benefit per sub-module (maintained upstream primary sources):
#
#   mei_hdcp - Host interface used for Intel HDCP services.
#              Cost: blocking can disrupt HDCP-protected display/content
#              paths on supported Intel graphics; the exact effect depends
#              on GPU, display stack, and media service.
#              Security gain: minimal (no published CVE; closes a
#              client path to /dev/mei0 but not /dev/mei0 itself).
#              Decision: NOT BLACKLISTED by default. Opt-in block available.
#
#   mei_pxp  - Host interface for Intel protected-content/PXP services.
#              Cost: blocking can break protected graphics/media workflows
#              on supported Intel GPUs; behavior is platform-dependent.
#              Security gain: minimal (same client-path argument).
#              Decision: NOT BLACKLISTED by default. Opt-in block available.
#
#   mei_wdt  - ME Watchdog Timer (iAMT OS-health alarm; alarm-only,
#              does NOT reset platform).
#              Cost: zero on consumer non-vPro (typically inert
#              anyway, watchdog not active in consumer ME firmware
#              SKUs). MAY matter on vPro/AMT-managed enterprise
#              systems and Proxmox HA cluster setups that use iAMT
#              watchdog for hang detection (verified Proxmox forum
#              thread). Earlier upstream bug (false-positive on
#              suspend) was fixed in kernel 5.x via
#              `watchdog_stop_on_unregister` (2021), so the
#              "blacklist fixes suspend" advice from old user posts
#              is largely obsolete on modern kernels (ONE old user
#              report cited, not "many").
#              Security gain: also minimal — alarm-only watchdog,
#              no published CVE, one more small client path closed.
#              Decision: NOT BLACKLISTED by default — consistent with
#              Kicksecure Issue #239. The marginal defense-in-depth
#              gain doesn't justify breaking edge-case setups
#              (vPro HA clusters, enterprise AMT) when the privacy-
#              distro target audience is consumer non-vPro and the
#              watchdog is typically inert there anyway. Opt-in
#              block available.
#
# Honest framing: NoID Privacy fully aligns with the Kicksecure
# consensus from security-misc Issue #239 — no MEI sub-module
# blacklists by default. Honest user-facing claim:
#
#   "Intel ME host attack-surface reduction centered on KT/SOL PCI block
#    (27 reviewed PCI IDs across modern Intel families), IOMMU translated
#    domain, lockdown=integrity kernel cmdline, mei+mei_me loadable
#    for fwupd platform-security inspection, plus the required
#    firmware/hardware actions (unprovision and disable AMT in UEFI/MEBx;
#    disable every AMT-capable integrated wired/wireless interface; use a
#    non-AMT discrete adapter where practical). The aggressive MEI
#    sub-module blacklists (mei_hdcp + mei_pxp + mei_wdt)
#    were dropped after honest cost-benefit audit — they are now
#    opt-in via `noid-mei-restore-submodules --block`."
#
# Host-side defense-in-depth still ACTIVE in M15:
#   - KT/SOL PCI driver_override=none (27 reviewed PCI IDs) —
#     prevents a host driver binding to those local PCI functions; it does
#     not disable AMT or its firmware-owned redirection features
#   - intel_iommu=on + IOMMU Translated domain (generic PCI DMA protection;
#     not a guarantee of CSME/AMT containment)
#   - lockdown=integrity kernel cmdline (M01)
#   - mei + mei_me not blacklisted, preserving fwupd visibility when the
#     platform exposes a compatible MEI interface
#   - UEFI Secure Boot (M01)
#   - Required UEFI/MEBx unprovision/disable checklist and non-AMT network
#     adapter guidance (15-intel-me-hardware-layer.md)
#
# For users who want extra attack-surface reduction (accepting the
# trade-offs), the `noid-mei-restore-submodules --block <mod>` CLI
# adds blacklist + install /bin/false lines to this file. Each
# opt-in block documents its specific functional cost so the user
# understands what they're losing.
#
# This file exists as documentation + a config target for
# the opt-in CLI. If you see no `blacklist mei_*` lines below this
# header, that is the intended default state.

# (no default blacklist directives — see rationale above)
MODPROBE_EOF

chmod 644 /etc/modprobe.d/noid-mei-submodules.conf
chown root:root /etc/modprobe.d/noid-mei-submodules.conf
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F /etc/modprobe.d/noid-mei-submodules.conf 2>/dev/null || true
fi
echo "  [OK] /etc/modprobe.d/noid-mei-submodules.conf written (644)"

# ----------------------------------------------------------------------------
# Step 2: Write /etc/udev/rules.d/99-noid-mei-kt-block.rules
# ----------------------------------------------------------------------------
# Blocks driver binding to Intel ME KT/SOL (Keyboard/Text + Serial over LAN)
# PCI devices. Multiple Intel generations covered; extend for older/newer
# chipsets as needed.
#
# KT/SOL function:
# - Remote keyboard injection (attacker types into victim system)
# - Serial over LAN (remote console as if serial cable attached)
# - Text-mode screen redirection
#
# driver_override=none prevents a future driver match, but kernel sysfs
# semantics are explicit that it does not unbind an already attached driver.
# Udev ordering relative to PCI driver binding must therefore not be treated
# as a security guarantee. The rule invokes an idempotent helper for both add
# and bind events; the helper sets the override first, unbinds any existing
# driver, and verifies both conditions. A boot service repeats the check after
# the initial udev trigger. The same rule and helper are shipped in initramfs.
#
echo ""
echo "[Step 2] Installing KT/SOL PCI binding enforcement"

mkdir -p /usr/libexec
cat > /usr/libexec/noid-mei-kt-enforce <<'KT_ENFORCE_EOF'
#!/bin/sh
# Enforce no host-driver binding for the reviewed Intel KT/SOL PCI set.
# AMT firmware/OOB networking is outside the host OS and is not affected.
set -eu
PATH=/usr/sbin:/usr/bin
export PATH
if [ "$#" -ne 0 ]; then
    printf '%s\n' 'ERROR: noid-mei-kt-enforce accepts no arguments' >&2
    exit 2
fi
umask 077

PCI_ROOT="${NOID_PCI_SYSFS_ROOT:-/sys/bus/pci/devices}"
CHECK_ONLY="${NOID_MEI_KT_CHECK_ONLY:-0}"
matched=0
unbound=0
failed=0

case "$CHECK_ONLY" in
    0|1) ;;
    *) echo "KT/SOL enforcement: invalid check-only mode" >&2; exit 2 ;;
esac
case "$PCI_ROOT" in
    /*) ;;
    *) echo "KT/SOL enforcement: PCI root must be absolute" >&2; exit 2 ;;
esac
[ -d "$PCI_ROOT" ] && [ ! -L "$PCI_ROOT" ] || {
    echo "KT/SOL enforcement: PCI root is missing or unsafe" >&2
    exit 2
}

is_kt_sol_id() {
    case "$1" in
        0xa13d|0xa2bd|0x9de3|0xa363|0x06e3|0x02e3|0xa3bd|0x34e3|0x38e3|\
        0x4de3|0x4b73|0xa0e3|0x43e3|0x1be3|0x7aeb|0x7a63|0x51e3|0x54e3|\
        0x7a6b|0x7e73|0x7f6b|0x7773|0xa873|0xe373|0xe473|0x6e6b|0x4d73)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

for device_path in "$PCI_ROOT"/*; do
    [ -d "$device_path" ] || continue
    [ -r "$device_path/vendor" ] || continue
    [ -r "$device_path/device" ] || continue
    [ -r "$device_path/class" ] || continue

    bdf=${device_path##*/}
    case "$bdf" in
        ????\:??\:??.3) ;;
        *) continue ;;
    esac
    case "$bdf" in
        *[!0-9A-Fa-f:.]*) continue ;;
    esac

    IFS= read -r vendor < "$device_path/vendor" || { failed=1; continue; }
    [ "$vendor" = "0x8086" ] || continue
    IFS= read -r device < "$device_path/device" || { failed=1; continue; }
    is_kt_sol_id "$device" || continue
    IFS= read -r class < "$device_path/class" || { failed=1; continue; }
    # KT/SOL redirection functions are PCI base class 07 subclass 00 (serial
    # controller) and present a 16550-compatible UART, so sysfs reports
    # 0x0700xx with a varying prog-if byte -- 8250_pci binds them through its
    # bc07sc00 class alias. Class 0x078000 is communication-controller/other,
    # which is the sibling HECI/MEI function; that one keeps its driver on
    # purpose for fwupd visibility. Matching the subclass is therefore what
    # separates the redirection function from the management engine, and an
    # exact 0x078000 comparison here matches no KT/SOL device at all.
    case "$class" in
        0x0700??) ;;
        *) continue ;;
    esac

    matched=$((matched + 1))
    if [ "$CHECK_ONLY" -eq 0 ]; then
        if [ ! -w "$device_path/driver_override" ] ||
           ! printf '%s\n' none > "$device_path/driver_override"; then
            failed=1
            continue
        fi

        if [ -L "$device_path/driver" ]; then
            if [ ! -w "$device_path/driver/unbind" ] ||
               ! printf '%s\n' "$bdf" > "$device_path/driver/unbind"; then
                failed=1
                continue
            fi
            unbound=$((unbound + 1))
        fi
    fi

    if [ -L "$device_path/driver" ]; then
        failed=1
        continue
    fi
    IFS= read -r override < "$device_path/driver_override" || { failed=1; continue; }
    [ "$override" = "none" ] || failed=1
done

if [ "$failed" -ne 0 ]; then
    echo "KT/SOL enforcement failed (matched=$matched, unbound=$unbound)" >&2
    exit 1
fi
echo "KT/SOL enforcement complete (matched=$matched, unbound=$unbound)"
KT_ENFORCE_EOF

chmod 755 /usr/libexec/noid-mei-kt-enforce
chown root:root /usr/libexec/noid-mei-kt-enforce

cat > /etc/udev/rules.d/99-noid-mei-kt-block.rules <<'UDEV_EOF'
# ============================================================================
# NoID Privacy — Intel ME KT/SOL PCI device driver binding block
# Design rationale: captured inline below.
# ============================================================================
#
# Reviewed Intel ME KT/SOL PCI device IDs across modern generations.
# Eighteen entries are explicitly named KT/SOL redirection devices in the
# current upstream PCI ID Repository. Nine entries marked "derived" are
# conservative candidates calculated from current Linux
# drivers/misc/mei/hw-me-regs.h HECI #1 anchors using the established +3
# family layout. A device ID alone is therefore never sufficient: every udev
# rule and the active helper also require Intel vendor 0x8086, PCI
# serial-controller class 0x0700xx, and PCI function 3.
#
# The class predicate is the subclass, not the full class word. A KT/SOL
# redirection function presents a 16550-compatible UART: PCI base class 07,
# subclass 00, with a prog-if byte that varies per platform (0x070002 is the
# common reading), which is why 8250_pci claims these devices through its
# bc07sc00 class alias and carries a dedicated Intel KT quirk. The
# neighbouring class 0x078000 is communication-controller/other and belongs
# to the HECI/MEI function, which deliberately keeps mei/mei_me bound for
# fwupd visibility. Matching 0x078000 here therefore selects the wrong
# function and blocks nothing on real hardware.
#
# Gen / Platform                                    HECI #1    KT/SOL     Source
# ------------------------------------------------- --------  ---------  ----------
# 6th gen Skylake-H/S (100-series / C230 PCH):       0xA13A  → 0xA13D     pci.ids ✓
# 7th gen Kaby Lake (200-series PCH):                0xA2BA  → 0xA2BD     pci.ids ✓
# 8th gen Whiskey/Amber Lake (Cannon Point-LP):      0x9DE0  → 0x9DE3     pci.ids ✓
# 8th/9th gen Coffee/Cannon Lake (300-series):       0xA360  → 0xA363     pci.ids ✓
# 10th gen Comet Lake-H / 400-series desktop:        0x06E0  → 0x06E3     pci.ids ✓
# 10th gen Comet Lake-LP (mobile):                   0x02E0  → 0x02E3     pci.ids ✓
# 10th gen Comet Lake-V (low-voltage):               0xA3BA  → 0xA3BD     pci.ids ✓
# 10th gen Ice Lake-LP (Sunny Cove mobile):          0x34E0  → 0x34E3     derived
# 10th gen Ice Lake-N (low-power):                   0x38E0  → 0x38E3     derived
# 10/11th gen Jasper Lake-N (Atom N):                0x4DE0  → 0x4DE3     derived
# 10/11th gen Elkhart Lake (Atom embedded):          0x4B70  → 0x4B73     derived
# 11th gen Tiger Lake-LP / 500-series mobile:        0xA0E0  → 0xA0E3     pci.ids ✓
# 11th gen Tiger Lake-H / Rocket Lake / 500-H:       0x43E0  → 0x43E3     pci.ids ✓
# Sapphire Rapids W790 workstation (Xeon W-2500):    0x1BE0  → 0x1BE3     derived
# 12th gen Alder Lake-S (600-series W/Q/Z/H):        0x7AE8  → 0x7AEB     pci.ids ✓
# 12th gen Alder Lake-LP (ultra-low-power mobile):   0x7A60  → 0x7A63     derived
# 12th gen Alder Lake-P (mobile):                    0x51E0  → 0x51E3     pci.ids ✓
# 12th gen Alder Lake-N (Atom-class):                0x54E0  → 0x54E3     derived
# 13th/14th gen Raptor Lake-S (700-series):          0x7A68  → 0x7A6B     pci.ids ✓
# 14th gen Meteor Lake Mobile (Core Ultra 100):      0x7E70  → 0x7E73     pci.ids ✓ (labeled "Meteor Lake-P")
# 15th gen Arrow Lake-S (Core Ultra 200 / 800):      0x7F68  → 0x7F6B     pci.ids ✓
# 15th gen Arrow Lake-H (Core Ultra 200H mobile):    0x7770  → 0x7773     pci.ids ✓
# 15th gen Lunar Lake-M (Core Ultra 200V):           0xA870  → 0xA873     pci.ids ✓
# Panther Lake-H:                                    0xE370  → 0xE373     pci.ids ✓
# Panther Lake-P:                                    0xE470  → 0xE473     pci.ids ✓
# Nova Lake-S candidate:                             0x6E68  → 0x6E6B     derived
# Wildcat Lake-P candidate:                          0x4D70  → 0x4D73     derived
#
# Pre-6th-gen Intel (Haswell 4th gen 0x8C3A / Broadwell 5th gen 0x9CBA) uses
# the same +3 offset pattern but different ID ranges. Users running pre-
# Skylake hardware on Fedora 44 can extend this file (legacy AMT 10/11 is
# architecturally distinct from modern CSME — different threat model).
# Non-Intel platforms (AMD, ARM) have no matching devices — rules are always
# no-ops (harmless). AMD PSP is handled by Step 4b documentation (ccp kept
# available for platform-specific services + fwupd PCI-PSP visibility — no
# Intel-specific PCI override on AMD by design).
#
# Device location is typically bus 00:16.3 across Intel PCH generations,
# but device ID changes per chipset family.

# ---- 6th-7th gen (Skylake / Kaby Lake, 2015-2017) ----
# Skylake-H/S / 100 Series / C230 Series PCH KT Redirection
ACTION=="add", SUBSYSTEM=="pci", KERNEL=="????:??:??.3", ATTR{vendor}=="0x8086", ATTR{class}=="0x0700*", ATTR{device}=="0xa13d", ATTR{driver_override}="none"

# Kaby Lake / 200 Series Chipset Family KT Redirection
ACTION=="add", SUBSYSTEM=="pci", KERNEL=="????:??:??.3", ATTR{vendor}=="0x8086", ATTR{class}=="0x0700*", ATTR{device}=="0xa2bd", ATTR{driver_override}="none"

# ---- 8th-9th gen (Whiskey/Amber/Coffee/Cannon Lake, 2018-2019) ----
# Cannon Point-LP (Whiskey/Amber Lake mobile) KT Redirection
ACTION=="add", SUBSYSTEM=="pci", KERNEL=="????:??:??.3", ATTR{vendor}=="0x8086", ATTR{class}=="0x0700*", ATTR{device}=="0x9de3", ATTR{driver_override}="none"

# Cannon Lake / 300 Series PCH AMT SOL Redirection (Coffee Lake desktop + CFL-H vPro)
ACTION=="add", SUBSYSTEM=="pci", KERNEL=="????:??:??.3", ATTR{vendor}=="0x8086", ATTR{class}=="0x0700*", ATTR{device}=="0xa363", ATTR{driver_override}="none"

# ---- 10th gen (Comet Lake / Ice Lake / Jasper Lake, 2019-2021) ----
# Comet Lake-H / 400 Series KT Redirection (10th gen desktop + H-mobile)
ACTION=="add", SUBSYSTEM=="pci", KERNEL=="????:??:??.3", ATTR{vendor}=="0x8086", ATTR{class}=="0x0700*", ATTR{device}=="0x06e3", ATTR{driver_override}="none"

# Comet Lake-LP AMT SOL Redirection (10th gen mobile low-power)
ACTION=="add", SUBSYSTEM=="pci", KERNEL=="????:??:??.3", ATTR{vendor}=="0x8086", ATTR{class}=="0x0700*", ATTR{device}=="0x02e3", ATTR{driver_override}="none"

# Comet Lake-V KT/SOL (10th gen low-voltage)
ACTION=="add", SUBSYSTEM=="pci", KERNEL=="????:??:??.3", ATTR{vendor}=="0x8086", ATTR{class}=="0x0700*", ATTR{device}=="0xa3bd", ATTR{driver_override}="none"

# Ice Lake-LP KT/SOL (10th gen Sunny Cove mobile)
ACTION=="add", SUBSYSTEM=="pci", KERNEL=="????:??:??.3", ATTR{vendor}=="0x8086", ATTR{class}=="0x0700*", ATTR{device}=="0x34e3", ATTR{driver_override}="none"

# Ice Lake-N KT/SOL (10th gen low-power)
ACTION=="add", SUBSYSTEM=="pci", KERNEL=="????:??:??.3", ATTR{vendor}=="0x8086", ATTR{class}=="0x0700*", ATTR{device}=="0x38e3", ATTR{driver_override}="none"

# Jasper Lake-N KT/SOL (10/11th gen Atom-N)
ACTION=="add", SUBSYSTEM=="pci", KERNEL=="????:??:??.3", ATTR{vendor}=="0x8086", ATTR{class}=="0x0700*", ATTR{device}=="0x4de3", ATTR{driver_override}="none"

# Elkhart Lake KT/SOL (embedded Atom)
ACTION=="add", SUBSYSTEM=="pci", KERNEL=="????:??:??.3", ATTR{vendor}=="0x8086", ATTR{class}=="0x0700*", ATTR{device}=="0x4b73", ATTR{driver_override}="none"

# ---- 11th gen (Tiger Lake / Rocket Lake, 2020-2021) ----
# Tiger Lake-LP / 500 Series On-Package CSME KT Redirection (11th gen mobile)
ACTION=="add", SUBSYSTEM=="pci", KERNEL=="????:??:??.3", ATTR{vendor}=="0x8086", ATTR{class}=="0x0700*", ATTR{device}=="0xa0e3", ATTR{driver_override}="none"

# Tiger Lake-H / Rocket Lake / 500 Series-H AMT SOL Redirection (11th gen desktop + H-mobile)
ACTION=="add", SUBSYSTEM=="pci", KERNEL=="????:??:??.3", ATTR{vendor}=="0x8086", ATTR{class}=="0x0700*", ATTR{device}=="0x43e3", ATTR{driver_override}="none"

# ---- Server workstation (Sapphire Rapids W-series) ----
# Emmitsburg / Sapphire Rapids W790 workstation KT/SOL (Xeon W-2500/W-3500)
ACTION=="add", SUBSYSTEM=="pci", KERNEL=="????:??:??.3", ATTR{vendor}=="0x8086", ATTR{class}=="0x0700*", ATTR{device}=="0x1be3", ATTR{driver_override}="none"

# ---- 12th gen (Alder Lake, 2021-2022) ----
# Alder Lake-S (Q670/Z690/H670/B660 PCH) KT Redirection
ACTION=="add", SUBSYSTEM=="pci", KERNEL=="????:??:??.3", ATTR{vendor}=="0x8086", ATTR{class}=="0x0700*", ATTR{device}=="0x7aeb", ATTR{driver_override}="none"

# Alder Lake-LP KT/SOL (12th gen ultra-low-power mobile, Framework/XPS 13)
ACTION=="add", SUBSYSTEM=="pci", KERNEL=="????:??:??.3", ATTR{vendor}=="0x8086", ATTR{class}=="0x0700*", ATTR{device}=="0x7a63", ATTR{driver_override}="none"

# Alder Lake-P AMT SOL Redirection (12th gen mobile P-series)
ACTION=="add", SUBSYSTEM=="pci", KERNEL=="????:??:??.3", ATTR{vendor}=="0x8086", ATTR{class}=="0x0700*", ATTR{device}=="0x51e3", ATTR{driver_override}="none"

# Alder Lake-N KT/SOL (12th gen Atom-class)
ACTION=="add", SUBSYSTEM=="pci", KERNEL=="????:??:??.3", ATTR{vendor}=="0x8086", ATTR{class}=="0x0700*", ATTR{device}=="0x54e3", ATTR{driver_override}="none"

# ---- 13th/14th gen (Raptor Lake / Meteor Lake, 2022-2024) ----
# Raptor Lake CSME KT Redirection (13/14th gen desktop + HX-mobile)
ACTION=="add", SUBSYSTEM=="pci", KERNEL=="????:??:??.3", ATTR{vendor}=="0x8086", ATTR{class}=="0x0700*", ATTR{device}=="0x7a6b", ATTR{driver_override}="none"

# Meteor Lake Mobile (Core Ultra 100 series) KT Redirection (labeled "Meteor Lake-P" in pci.ids)
ACTION=="add", SUBSYSTEM=="pci", KERNEL=="????:??:??.3", ATTR{vendor}=="0x8086", ATTR{class}=="0x0700*", ATTR{device}=="0x7e73", ATTR{driver_override}="none"

# ---- 15th gen (Arrow Lake / Lunar Lake, Core Ultra 200 series, 2024-2025) ----
# Arrow Lake-S KT/SOL (Core Ultra 200 desktop, 800-series PCH)
ACTION=="add", SUBSYSTEM=="pci", KERNEL=="????:??:??.3", ATTR{vendor}=="0x8086", ATTR{class}=="0x0700*", ATTR{device}=="0x7f6b", ATTR{driver_override}="none"

# Arrow Lake-H KT Redirection (Core Ultra 200H mobile)
ACTION=="add", SUBSYSTEM=="pci", KERNEL=="????:??:??.3", ATTR{vendor}=="0x8086", ATTR{class}=="0x0700*", ATTR{device}=="0x7773", ATTR{driver_override}="none"

# Lunar Lake-M KT Redirection (Core Ultra 200V ultra-thin)
ACTION=="add", SUBSYSTEM=="pci", KERNEL=="????:??:??.3", ATTR{vendor}=="0x8086", ATTR{class}=="0x0700*", ATTR{device}=="0xa873", ATTR{driver_override}="none"

# ---- 16th-17th gen + future (Panther/Nova/Wildcat Lake) ----
# Panther Lake-H KT/SOL (16th gen mobile)
ACTION=="add", SUBSYSTEM=="pci", KERNEL=="????:??:??.3", ATTR{vendor}=="0x8086", ATTR{class}=="0x0700*", ATTR{device}=="0xe373", ATTR{driver_override}="none"

# Panther Lake-P KT/SOL (16th gen mobile)
ACTION=="add", SUBSYSTEM=="pci", KERNEL=="????:??:??.3", ATTR{vendor}=="0x8086", ATTR{class}=="0x0700*", ATTR{device}=="0xe473", ATTR{driver_override}="none"

# Nova Lake-S KT/SOL (17th gen future desktop)
ACTION=="add", SUBSYSTEM=="pci", KERNEL=="????:??:??.3", ATTR{vendor}=="0x8086", ATTR{class}=="0x0700*", ATTR{device}=="0x6e6b", ATTR{driver_override}="none"

# Wildcat Lake-P KT/SOL (future Atom-class successor)
ACTION=="add", SUBSYSTEM=="pci", KERNEL=="????:??:??.3", ATTR{vendor}=="0x8086", ATTR{class}=="0x0700*", ATTR{device}=="0x4d73", ATTR{driver_override}="none"

# Udev RUN commands execute after all rules for the event. Re-assert the
# override and actively remove a driver if kernel binding won the add-event
# race. The bind event closes later rebind paths without trusting hotplug
# assumptions. The helper emits counts only, never PCI addresses.
ACTION=="add|bind", SUBSYSTEM=="pci", KERNEL=="????:??:??.3", ATTR{vendor}=="0x8086", ATTR{class}=="0x0700*", ATTR{device}=="0xa13d|0xa2bd|0x9de3|0xa363|0x06e3|0x02e3|0xa3bd|0x34e3|0x38e3|0x4de3|0x4b73|0xa0e3|0x43e3|0x1be3|0x7aeb|0x7a63|0x51e3|0x54e3|0x7a6b|0x7e73|0x7f6b|0x7773|0xa873|0xe373|0xe473|0x6e6b|0x4d73", ATTR{driver_override}="none", RUN+="/usr/libexec/noid-mei-kt-enforce"
UDEV_EOF

chmod 644 /etc/udev/rules.d/99-noid-mei-kt-block.rules
chown root:root /etc/udev/rules.d/99-noid-mei-kt-block.rules
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F /etc/udev/rules.d/99-noid-mei-kt-block.rules 2>/dev/null || true
fi
echo "  [OK] /etc/udev/rules.d/99-noid-mei-kt-block.rules written (644)"

cat > /etc/systemd/system/noid-mei-kt-enforce.service <<'KT_SERVICE_EOF'
[Unit]
Description=Enforce Intel ME KT/SOL host-driver block
Documentation=file:/usr/share/doc/noid-privacy/15-intel-me-hardware-layer.md
DefaultDependencies=no
After=systemd-udev-trigger.service
Before=sysinit.target
ConditionPathExistsGlob=/sys/bus/pci/devices/*

[Service]
Type=oneshot
ExecStart=/usr/libexec/noid-mei-kt-enforce
RemainAfterExit=yes
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
PrivateNetwork=yes
ProtectClock=yes
ProtectHostname=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictAddressFamilies=AF_UNIX
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
IPAddressDeny=any

[Install]
WantedBy=sysinit.target
KT_SERVICE_EOF

chmod 644 /etc/systemd/system/noid-mei-kt-enforce.service
chown root:root /etc/systemd/system/noid-mei-kt-enforce.service
systemctl enable noid-mei-kt-enforce.service
echo "  [OK] early-boot KT/SOL verification service enabled"

# ----------------------------------------------------------------------------
# Step 3: Write /etc/dracut.conf.d/noid-mei-blacklist.conf
# ----------------------------------------------------------------------------
# Forces the MEI sub-module config and KT/SOL udev enforcement into the
# initramfs. Dracut normally includes modprobe.d content, but explicit
# install_items makes every security dependency visible and testable.
#
echo ""
echo "[Step 3] Writing /etc/dracut.conf.d/noid-mei-blacklist.conf"

cat > /etc/dracut.conf.d/noid-mei-blacklist.conf <<'DRACUT_EOF'
# NoID Privacy — MEI sub-module config delivery (initramfs)
# NO MEI sub-modules blacklisted by default (Kicksecure-
# consensus from security-misc Issue #239). The modprobe.d config file is
# still shipped into the initramfs so that if a user later runs
# `noid-mei-restore-submodules --block <mod>` and adds opt-in blacklist
# lines, those take effect from early boot (before systemd-udev) on the
# next initramfs rebuild — no extra dracut.conf edit needed. The KT/SOL rule
# and helper run during initramfs udev enumeration and are checked again by
# noid-mei-kt-enforce.service after the root filesystem's udev trigger.
install_items+=" /etc/modprobe.d/noid-mei-submodules.conf /etc/udev/rules.d/99-noid-mei-kt-block.rules /usr/libexec/noid-mei-kt-enforce "
DRACUT_EOF

chmod 644 /etc/dracut.conf.d/noid-mei-blacklist.conf
chown root:root /etc/dracut.conf.d/noid-mei-blacklist.conf
echo "  [OK] /etc/dracut.conf.d/noid-mei-blacklist.conf written (644)"

# ----------------------------------------------------------------------------
# Step 4: Write /usr/share/doc/noid-privacy/15-intel-me-hardware-layer.md
# ----------------------------------------------------------------------------
# User-facing documentation for firmware/hardware actions that the image
# CANNOT automate. Users must unprovision/disable AMT in UEFI/MEBx and remove
# every AMT-capable integrated wired or wireless network path themselves.
#
echo ""
echo "[Step 4] Writing hardware-layer user documentation"

mkdir -p /usr/share/doc/noid-privacy

# Generated from docs/15-intel-me-hardware-layer.md by
# scripts/regen-intel-me-doc.sh — edit that source document, never this block.
cat > /usr/share/doc/noid-privacy/15-intel-me-hardware-layer.md <<'DOC_EOF'
# Intel ME / MEI Mitigation — Hardware Layer Checklist

NoID Privacy Workstation ships host-side Intel MEI attack-surface controls:
early udev enforcement plus a verified unbind fallback prevents the listed
KT/SOL PCI functions from retaining a Linux driver after enforcement,
optional MEI client modules can be disabled, and `mei`/`mei_me` stay visible
to fwupd. Generic IOMMU, Secure Boot and kernel-lockdown defenses also apply.

These controls do **not** disable Intel AMT and cannot filter its out-of-band
network traffic. Intel documents AMT as operating independently of the OS;
therefore neither firewalld nor nftables on this host sees that traffic.

**This document describes the firmware and hardware actions that YOU must
configure for the strongest practical mitigation.** On a provisioned,
supported vPro platform, leaving an AMT-capable network path available leaves
an OS-independent management path available as well.

## Background

Intel Management Engine (ME) is a separate processor in the platform that
runs independently of the host OS. On supported vPro platforms, AMT can use
firmware-managed wired networking and compatible wireless networking while
the OS is unavailable.

The image's KT/SOL `driver_override=none` rule only blocks a **host driver**
from binding to listed PCI functions. It does not disable firmware-owned AMT,
SOL, KVM or redirection. IOMMU and Secure Boot are useful generic host
defenses, but they are not a promise that CSME/AMT is contained.

**The network hardware layer is essential:** removing every AMT-capable link
removes those network paths. It does not prove CSME firmware integrity or
make claims about unenumerated hardware capabilities.

## Required firmware and hardware checklist

### Layer 1 — Unprovision and disable AMT/manageability (CRITICAL)

In the vendor UEFI and, where present, Intel MEBx, fully unprovision AMT and
disable Intel AMT, Manageability Engine network access, SOL/IDER and remote
KVM. Names differ by OEM. A setting that merely hides the NIC from the OS is
not equivalent to disabling AMT. After every firmware update or settings
reset, verify these controls again.

Intel documents a global AMT disable beginning with AMT 12.0: it disables all
AMT out-of-band interfaces and requires local MEBx access to re-enable. Use
that control where the OEM exposes it; do not substitute “unconfigured” or a
disabled OS driver for the firmware-level disabled state.

If the firmware exposes no trustworthy disable/unprovision control, the OS
cannot supply the missing guarantee. Treat every AMT-capable integrated
network interface as a possible out-of-band path and disable/remove its link.

### Layer 2 — Use a non-AMT network adapter (HIGHLY RECOMMENDED)

**Action**: Use a discrete adapter that is not connected to the platform's
AMT manageability path. A non-Intel vendor is a useful first filter, but the
platform/OEM documentation is authoritative; vendor name alone is not proof.

This helps only if **all** integrated AMT-capable wired and wireless
interfaces are simultaneously disabled/unprovisioned. A separate adapter by
itself does not turn AMT off.

**Verification**:

    lspci -nnk | grep -iA3 -E 'ethernet|network controller'
    # Confirm the active WAN adapter and inventory both wired and wireless
    # controllers. This does not by itself prove AMT is unprovisioned.

### Layer 3 — Remove every integrated network link (CRITICAL)

Physically disconnect every cable from an AMT-capable onboard Ethernet port.
Disable compatible integrated Wi-Fi in UEFI/MEBx or replace/remove it where
the platform permits. Do not assume that Wi-Fi is outside AMT's path.

**Why**: An ordinary UEFI toggle may disable only the host-visible controller,
not the manageability path. Removing the cable eliminates that wired link,
but it is not a universal air-gap if compatible Wi-Fi, cellular, USB, or
another management-capable interface remains.

**Verification**: Visual inspection — Intel onboard NIC port has no
Ethernet cable attached.

### Layer 4 — Disable integrated NICs in UEFI setup

**Action**: Reboot into UEFI setup (typically F1, F2, F10, Del, or Esc
during POST). Navigate to Devices → Network → Intel LAN Controller
(exact path varies by vendor). Set to **Disabled**. Save and exit.

Verify both the ordinary onboard-controller toggle and the separate AMT/MEBx
manageability toggle. Firmware can distinguish host networking from the
out-of-band path, so absence from `ip link` proves only that Linux cannot see
the interface.

**Verification** (after UEFI change and reboot):

    ip link show
    # Expected: only the chosen non-AMT adapter, loopback, and intentional
    #           virtual/tunnel interfaces; no disabled integrated NIC.

    lspci -nnk | grep -iA3 -E 'ethernet|network controller'
    # Expected: no integrated controller that firmware was meant to hide.
    # Still verify AMT/MEBx provisioning independently.

## Why hardware layers cannot be automated

The image cannot:
- Physically install a discrete NIC (requires opening the case)
- Physically disconnect a network cable (requires manual action)
- Modify UEFI settings (requires user interaction during POST)

These firmware and physical steps are the only layers here that can remove
the AMT network path. The image cannot honestly claim that OS controls alone
do so.

## Laptop fallback

Laptops may have no removable network adapter. Use the strongest available
combination:

1. Fully unprovision and disable AMT/manageability in UEFI/MEBx.
2. Disable every unused integrated Ethernet and Wi-Fi controller in firmware.
3. Prefer a non-AMT external adapter for the actual WAN link.
4. If firmware cannot disable the OOB path, record that residual risk; the
   host firewall cannot close it.

Intel's own AMT material describes wireless support on compatible platforms,
so a Wi-Fi-only workflow is not automatically an AMT mitigation.

## Additional considerations

- **Install current OEM firmware**: Intel's 2026.1 chipset advisory
  INTEL-SA-01315 rates affected CSME/AMT issues HIGH, including an
  unauthenticated network denial-of-service path, and directs users to the
  latest applicable system-manufacturer firmware. An OS kernel update does
  not replace that OEM firmware update.
- **BIOS updates may reset UEFI settings**: After fwupd/fwupdmgr firmware
  updates that touch the UEFI, verify that Intel NIC is still disabled.
  Some UEFI updates reset to factory defaults.
- **me_cleaner**: Platform support varies substantially and modern CSME
  generations are not uniformly reducible. This image does not automate
  firmware modification; an external programmer and a tested recovery image
  are prerequisites for any experiment.
- **coreboot**: Availability and the amount of proprietary management
  firmware retained are board-specific. Replacing the vendor UEFI is not, by
  itself, a general promise that CSME or AMT is absent.

## Software layers provided by this image

Reference for completeness — these work automatically:

- **MEI core + hardware driver** (`mei`, `mei_me`) not blacklisted — these
  can bind on supported hardware so fwupd can inspect Intel ME/BootGuard
  state. Actual binding and HSI results remain platform-dependent.
- **NO default MEI sub-module blacklists** (full Kicksecure-consensus
  per security-misc Issue #239 — an earlier aggressive blacklist of
  `mei_hdcp` + `mei_pxp` + `mei_wdt` had too much functional cost
  relative to the marginal defense-in-depth gain). All three remain
  loadable and autoload only where matching hardware requests them:
    - `mei_hdcp` — Intel HDCP service interface. Opt-in block via
      `sudo noid-mei-restore-submodules --block hdcp`; protected display or
      content paths may stop working.
    - `mei_pxp` — Intel protected-content/PXP service interface. Opt-in block
      via `sudo noid-mei-restore-submodules --block pxp`; protected graphics
      or media workflows may stop working.
    - `mei_wdt` — iAMT OS-health watchdog interface where exposed. Opt-in via
      `sudo noid-mei-restore-submodules --block wdt` if you have
      no use for it.
- **KT/SOL PCI host-driver binding blocked** (27 PCI IDs across 6th-17th
  gen Intel + Sapphire Rapids). This removes a Linux-side binding surface;
  it does not disable firmware-owned AMT/SOL/KVM.
- **IOMMU VT-d translated domain** (`intel_iommu=on`) — generic PCI DMA
  hardening, not a CSME/AMT containment guarantee
- **Secure Boot + Kernel Lockdown integrity** (unsigned modules blocked)
- **dracut config ships the modprobe.d file and KT/SOL udev/helper files into
  initramfs**, so opt-in module blocks and binding enforcement start early.

## Verification — what does this platform expose?

    sudo fwupdmgr security

Inspect every Intel ME and BootGuard attribute individually; do not infer an
overall state from HSI alone. Missing or "Not supported" results are
inconclusive: the platform may lack the feature, firmware may not expose it,
or the compatible MEI driver/device may be unavailable. Check:

    lsmod | grep '^mei'
    # On supported hardware, mei and mei_me are normally listed.

GNOME users can also check graphically via:
**Settings → Privacy → Device Security**

## Status

This is host attack-surface reduction and security-state visibility, not an
AMT network barrier. UEFI/MEBx unprovisioning plus disabling/removing every
AMT-capable wired and wireless link is YOUR responsibility — see the
checklist above.

**Honest layer count for what NoID Privacy actively deploys on Intel**:

1. KT/SOL PCI `driver_override=none` (27 reviewed IDs across 6th–17th gen
   Intel plus Sapphire Rapids; pre-Skylake platforms are not covered — see
   `/etc/udev/rules.d/99-noid-mei-kt-block.rules`) — blocks host-driver
   binding only
2. `mei` + `mei_me` not blacklisted for fwupd visibility when supported
3. `intel_iommu=on` + IOMMU Translated domain (generic PCI DMA hardening)
4. `lockdown=integrity` kernel cmdline (M01)
5. dracut config ships modprobe.d file into initramfs (supports opt-in
   CLI flow)
6. NO default MEI sub-module blacklists — `mei_hdcp` + `mei_pxp` +
   `mei_wdt` remain loadable (Kicksecure-consensus per security-misc
   Issue #239; an earlier aggressive blacklist of all three dropped
   because cost > marginal security gain)

User-controlled (doc-only — image cannot automate):

7. AMT fully unprovisioned and disabled in UEFI/MEBx (Layer 1 above)
8. Non-AMT adapter for the real WAN link (Layer 2 above)
9. All AMT-capable integrated wired/wireless links removed or disabled

**Optional opt-in escape-hatches** (for users who accept the trade-offs):

- `noid-mei-restore-submodules --block hdcp` — opt-in blacklist mei_hdcp;
  may break protected display/content paths
- `noid-mei-restore-submodules --block pxp` — opt-in blacklist mei_pxp;
  may break protected graphics/media workflows
- `noid-mei-restore-submodules --block wdt` — opt-in blacklist mei_wdt
  (alarm-only iAMT watchdog; only matters on vPro / Proxmox HA)
- `noid-mei-lockdown` — blacklist `mei` + `mei_me` core modules (loses
  fwupd BootGuard visibility and may break GSC/graphics/media paths; see the
  experimental full-block section below)

Layer 10 (SELinux restrict of /dev/mei0 to fwupd_t only) is not
feasible in Fedora targeted policy mode and was explicitly rejected.

> **Design rationale — full honest revision**: an earlier edition
> default-blacklisted three MEI sub-modules (`mei_hdcp`, `mei_pxp`,
> `mei_wdt`). That was dropped in favor of NO MEI sub-modules
> blacklisted by default, fully aligned with upstream Kicksecure
> security-misc Issue #239 (which removed ALL MEI blacklists because
> the cost-benefit was net-negative across the family). All three
> sub-module blacklists are now opt-in via
> `noid-mei-restore-submodules --block` for users who want extra
> attack-surface reduction and accept the platform-specific trade-offs
> (HDCP, protected-content/PXP, or iAMT watchdog). None of these host-side
> controls replaces
> AMT unprovisioning/disablement in UEFI/MEBx.

---

## Experimental Full MEI Block (Visibility and Stability Trade-off)

The default image leaves `mei` + `mei_me` **loadable** so compatible Intel
hardware can bind and fwupd can inspect Intel ME/BootGuard attributes. The
overall HSI level and individual results remain platform-, firmware-, driver-,
and fwupd-version-dependent.

Full core-module blocking is an experimental, high-risk compatibility choice,
not a general security upgrade. Modern Intel graphics can depend on MEI for
Graphics Security Controller (GSC) services. Fedora 44 kernel 7.0.4
accidentally omitted MEI and produced i915 GSC failures and reported hard
freezes on Meteor Lake; Fedora fixed that regression in 7.0.6. An intentional
core blacklist can recreate the same missing dependency on affected hardware.

Only after AMT is unprovisioned/disabled and every AMT-capable integrated
wired/wireless link is disabled or physically disconnected can the checklist
treat the OOB network path as removed. The optional MEI blacklist below then
removes the host's `/dev/mei*` interface at the cost of fwupd visibility; it
still does not alter firmware by itself.

### Trade-off summary

| Aspect | Default | Experimental full block |
|---|---|---|
| `mei` + `mei_me` policy | Loadable | Blacklisted + install blocked |
| `/dev/mei*` interface | Present only when hardware binds | Normally absent after reboot |
| Host MEI surface | Available when bound | Reduced; root can still alter policy |
| fwupd Intel ME/BootGuard inspection | Available when platform binds | Usually unavailable/inconclusive |
| Platform BootGuard configuration | Unchanged by this OS choice | Unchanged by this OS choice |
| Intel CPU microcode loading | Unaffected | Unaffected |
| Boot, graphics and protected media | Platform-supported default | Hardware-dependent; GSC/graphics/media failure is possible |

**Critical**: Blacklisting Linux MEI drivers does not reconfigure the OEM's
BootGuard policy; it removes the host interface fwupd normally uses to inspect
that policy. Missing fwupd data must be reported as unknown, not as proof that
BootGuard is either enabled or disabled.

### Apply the experimental full block

An escape-hatch script is provided:

```bash
sudo noid-mei-lockdown               # Apply (requires reboot)
sudo noid-mei-lockdown --status      # Check current state
sudo noid-mei-lockdown --undo        # Revert (requires reboot)
```

After reboot:

```bash
lsmod | grep '^mei'                  # Expected: empty
ls /dev/mei*                         # Expected: "No such file or directory"
fwupdmgr security | grep -i bootguard # Expected: absent/inconclusive on many systems
```

The script:
1. Atomically publishes the reviewed `blacklist mei` + `blacklist mei_me` +
   matching `install ... /bin/false` policy in
   `/etc/modprobe.d/noid-mei-submodules.conf`
2. Atomically regenerates every installed initramfs through M21's shared
   boot-mutation lock, terminal-state guard and candidate validation
3. Creates a Snapper pre-snapshot when the snapshot helper is installed
4. Requires reboot for kernel to drop the modules

### When to use which strategy

**Default (image-shipped)**: Use if you want fwupd to inspect the current
Intel ME/BootGuard attributes exposed by the platform. Appropriate for most
users.

**Full MEI block (experimental opt-in)**: Use only after completing the
firmware/hardware checklist, proving the target hardware does not require MEI
for stable graphics/GSC/media operation, and deciding that reduced host MEI
surface matters more than fwupd visibility. A root-compromised OS can remove
the blacklist, so this is defense-in-depth rather than a root-resistant
boundary.

Rollback via `--undo` is available while the system remains bootable; keep a
tested rescue path because firmware and initramfs changes are never risk-free.

## Primary references

- Intel AMT global disable behavior:
  https://software.intel.com/sites/manageability/AMT_Implementation_and_Reference_Guide/WordDocuments/disablingintelamt.htm
- Intel 2026.1 CSME/AMT advisory INTEL-SA-01315:
  https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01315.html
- Linux PCI `driver_override` ABI:
  https://docs.kernel.org/ABI/testing/sysfs-bus-pci
- Fedora 44 MEI/GSC regression and 7.0.6 fix:
  https://bugzilla.redhat.com/show_bug.cgi?id=2468995
- Linux MEI device-ID anchors:
  https://github.com/torvalds/linux/blob/master/drivers/misc/mei/hw-me-regs.h
- PCI ID Repository:
  https://pci-ids.ucw.cz/

DOC_EOF

chmod 644 /usr/share/doc/noid-privacy/15-intel-me-hardware-layer.md
chown root:root /usr/share/doc/noid-privacy/15-intel-me-hardware-layer.md
echo "  [OK] /usr/share/doc/noid-privacy/15-intel-me-hardware-layer.md written"

# ----------------------------------------------------------------------------
# Step 4b: Write AMD PSP / ASP hardware-layer doc (companion to Intel MEI doc)
# ----------------------------------------------------------------------------
# Informational doc for AMD targets (always-ship). AMD's ME-equivalent is
# the Platform Security Processor, officially renamed AMD Secure Processor (ASP).
# Key facts live in the AMD_DOC_EOF heredoc: ASP firmware is outside host
# driver control; ccp remains available for platform-specific services and
# fwupd visibility; PSB and AIM-T/DASH are OEM/firmware boundaries. The Intel
# configs from Steps 1-3 are inert on AMD.

echo ""
echo "[Step 4b] Writing AMD PSP / ASP hardware-layer user documentation"

cat > /usr/share/doc/noid-privacy/15-amd-psp-hardware-layer.md <<'AMD_DOC_EOF'
# AMD ASP / PSP — Firmware and Manageability Boundaries

AMD Secure Processor (ASP, formerly Platform Security Processor or PSP) is a
dedicated processor used for platform security and boot-time functions. Linux
can expose host interfaces to some ASP services, but disabling a Linux driver
is not the same as stopping the secure processor firmware.

This image therefore makes two deliberately separate claims:

- OS hardening reduces host-side attack surface and preserves useful security
  visibility where possible.
- ASP firmware, Platform Secure Boot, and AMD PRO out-of-band manageability are
  platform/OEM controls. The host firewall cannot enforce their network path.

## What the image does

- Keeps the Linux `ccp`/PSP driver available by default.
- Enables generic AMD IOMMU and kernel-lockdown policy through Module 01.
- Keeps Secure Boot support and fwupd host-security inspection available.
- Documents firmware, provisioning, and physical actions that cannot be
  automated safely in a generic image.

These are defense-in-depth controls, not a claim that ASP is disabled or
contained.

## The Linux `ccp` driver

The kernel's AMD Secure Processor driver is part of the CCP driver family.
Depending on the processor, firmware, and kernel configuration, it can expose
cryptographic acceleration and host interfaces for services such as SEV, TEE,
platform access, or other PSP functions.

fwupd's `pci_psp` plugin matches a PCI device bound to the `ccp` driver and
reads security attributes exported through sysfs. Blacklisting `ccp` can
therefore remove fwupd visibility and can break platform-specific functions.
It does not stop ASP firmware.

The firmware TPM is not universally controlled by `ccp`; Linux can expose a
firmware TPM through the standard ACPI TPM2/CRB driver. For that reason this
project does not claim either that blacklisting `ccp` always disables fTPM or
that keeping `ccp` always guarantees fTPM availability.

Default: do not blacklist `ccp`. Any opt-in block must be treated as
hardware-specific and verified for TPM, SEV/TEE, suspend, firmware updates,
and fwupd host-security reporting on the exact machine.

## AMD PRO manageability / AIM-T / DASH

Supported and provisioned AMD PRO platforms can provide OS-independent
out-of-band management over wired or compatible wireless networking. AMD's
current AIM-T documentation requires firmware enablement and provisioning;
support varies by processor, OEM, network controller, and firmware.

For maximum network isolation on such hardware:

1. Unprovision AIM-T/DASH and disable manageability in UEFI.
2. Disable SOL/KVM/remote-control features where the OEM exposes them.
3. Disable or physically disconnect every interface that the platform can use
   for manageability, including compatible Wi-Fi.
4. Use a separate adapter only after confirming from OEM documentation that it
   is not connected to the manageability path.
5. Recheck settings after firmware updates or UEFI resets.

A separate card alone is not a guarantee. Vendor branding alone is not enough,
because AMD manageability supports multiple network-controller vendors.

On systems without the relevant AMD PRO feature, the controls are inert. Do
not infer absence merely from the marketing name: inspect the exact SKU, UEFI
settings, provisioning state, and OEM manual.

## AMD Platform Secure Boot (PSB)

PSB authenticates the initial OEM firmware and uses one-time-programmable
processor fuses to bind the processor to an OEM firmware signing identity.
Enrollment is OEM-controlled and is intentionally difficult or impossible to
reverse once fused.

NoID Privacy does not enroll PSB. On hardware that exposes enrollment controls, do not
change them without the OEM's exact procedure, replacement/repair implications,
and a tested recovery plan. `fwupdmgr security` may report PSB and rollback
attributes when the platform and current fwupd plugin expose the necessary
data; missing data is inconclusive.

## IOMMU boundary

`amd_iommu=on` requests AMD-Vi/IOMMU support. It is useful generic DMA
hardening, but firmware reservations, identity mappings, devices outside the
IOMMU, and platform defects can create exceptions. It is not proof that ASP or
out-of-band manageability is contained.

Verify the running system rather than the command line alone:

    cat /proc/cmdline
    sudo fwupdmgr security --force
    sudo journalctl -k -b | grep -iE 'AMD-Vi|IOMMU'

Interpret every fwupd attribute separately; the overall HSI level is a summary,
not remote attestation and not proof that an absent feature is secure.

## CVE-2025-2884 / AMD-SB-4011

AMD-SB-4011 documents an out-of-bounds read in affected AMD fTPM firmware. The
published vector is local and requires a low-privileged attacker plus user
interaction; successful exploitation may expose TPM data or affect TPM
availability.

Mitigated firmware versions differ by processor family. There is no single
ComboPI/AGESA version that covers all AMD products. Identify the exact CPU and
system model, compare the OEM BIOS release against AMD-SB-4011's product table,
and install the OEM-provided update. A generic Linux kernel update does not
replace the affected fTPM firmware update.

## Practical verification checklist

    lscpu | grep -i 'vendor'
    lspci -nnk | grep -iA3 -E 'ethernet|network controller|encryption controller'
    lsmod | grep -E '^ccp|^tpm'
    sudo fwupdmgr security --force

Then verify in UEFI/OEM documentation:

- AIM-T/DASH/manageability is unprovisioned and disabled if present.
- Unused wired, Wi-Fi, cellular, and remote-management paths are disabled.
- Secure Boot, IOMMU, TPM choice, PSB, and rollback settings match the threat
  model.
- Firmware is at or above every applicable AMD security-bulletin revision.

Do not publish the command output: PCI IDs, firmware versions, serials, and
other inventory can identify a specific machine.

## Physical-access note

Research such as faulTPM demonstrates that some AMD fTPM generations are
vulnerable to invasive or fault-injection attacks. A discrete TPM changes the
attack surface but is not automatically safer against every physical attack.
For a physical-access threat model, use measured boot, a strong LUKS
passphrase, disabled unattended unlock, tamper controls, and a recovery plan;
do not rely on TPM placement alone.

## References

- AMD Secure Processor overview:
  https://docs.kernel.org/tee/amd-tee.html
- Linux AMD PSP/CCP implementation:
  https://github.com/torvalds/linux/tree/master/drivers/crypto/ccp
- fwupd PCI PSP plugin:
  https://github.com/fwupd/fwupd/tree/main/plugins/pci-psp
- fwupd Host Security ID specification:
  https://fwupd.github.io/libfwupdplugin/hsi.html
- AMD PRO manageability tools and AIM-T:
  https://www.amd.com/en/support/downloads/manageability-tools.html
- AMD Platform Secure Boot:
  https://www.amd.com/content/dam/amd/en/documents/products/processors/ryzen/7000/ryzen-pro-7000-security-whitepaper.pdf
- AMD-SB-4011 / CVE-2025-2884:
  https://www.amd.com/en/resources/product-security/bulletin/amd-sb-4011.html
- faulTPM research:
  https://arxiv.org/abs/2304.14717
AMD_DOC_EOF

chmod 644 /usr/share/doc/noid-privacy/15-amd-psp-hardware-layer.md
chown root:root /usr/share/doc/noid-privacy/15-amd-psp-hardware-layer.md
echo "  [OK] /usr/share/doc/noid-privacy/15-amd-psp-hardware-layer.md written"

# ----------------------------------------------------------------------------
# Step 5: Write platform mitigation status file for noid-status
# ----------------------------------------------------------------------------
# M13 ships noid-status; M15 writes its root-owned schema. Build-time status is
# deterministic from image config; Step 5e re-writes it with live-detected
# target reality at first boot.
#
echo ""
echo "[Step 5] Writing M15 platform status file for noid-status"

mkdir -p /var/lib/noid-privacy
chmod 755 /var/lib/noid-privacy

if [ "$CPU_VENDOR" = "intel" ]; then
    cat > /var/lib/noid-privacy/mei-status.txt <<'MEI_STATUS_EOF'
# NoID Privacy — Intel ME Mitigation Status (Intel host)
# Written by Module 15. Parsed by /usr/local/bin/noid-status.
# Do not hand-edit — rebuild image to change.
CPU_VENDOR=intel
STATUS_LIFECYCLE=build-time-placeholder
MEI_STATE=build-time-unknown
MEI_SUBMODULES_BLOCKED=none
MEI_KT_SOL_HOST_BINDING=configured-not-runtime-verified
MEI_FWUPD_VISIBILITY=runtime-check-required
MEI_STATUS_EOF
    echo "  [OK] /var/lib/noid-privacy/mei-status.txt written (Intel, runtime check pending)"
elif [ "$CPU_VENDOR" = "amd" ]; then
    cat > /var/lib/noid-privacy/mei-status.txt <<'AMD_STATUS_EOF'
# NoID Privacy — Firmware-Layer Mitigation Status (AMD host)
# Written by Module 15. Parsed by /usr/local/bin/noid-status.
# Do not hand-edit — rebuild image to change.
CPU_VENDOR=amd
STATUS_LIFECYCLE=build-time-placeholder
MEI_STATE=n/a-on-amd
PSP_STATE=runtime-check-required
CCP_POLICY=not-blacklisted
PSP_FWUPD_VISIBILITY=runtime-check-required
PSB_STATE=see-fwupdmgr-security
HARDWARE_LAYER_DOC=/usr/share/doc/noid-privacy/15-amd-psp-hardware-layer.md
AMD_STATUS_EOF
    echo "  [OK] /var/lib/noid-privacy/mei-status.txt written (AMD, PSP-documented)"
else
    cat > /var/lib/noid-privacy/mei-status.txt <<'UNK_STATUS_EOF'
# NoID Privacy — Firmware-Layer Mitigation Status (non-Intel/AMD host)
# Written by Module 15. Parsed by /usr/local/bin/noid-status.
CPU_VENDOR=unknown
STATUS_LIFECYCLE=build-time-placeholder
MEI_STATE=n/a
PSP_STATE=n/a
NOTE=vendor-specific firmware status unavailable; generic hardening still applies
UNK_STATUS_EOF
    echo "  [OK] /var/lib/noid-privacy/mei-status.txt written (unknown vendor)"
fi

chmod 644 /var/lib/noid-privacy/mei-status.txt
chown root:root /var/lib/noid-privacy/mei-status.txt

# ----------------------------------------------------------------------------
# Step 5b: Install /usr/local/bin/noid-mei-restore-submodules escape-hatch
# ----------------------------------------------------------------------------
# MEI sub-module toggle CLI: --restore un-blacklists, --block opt-ins a
# blacklist with the per-module trade-off shown interactively (usage +
# rationale live in the MEI_RESTORE_EOF heredoc). Never touches the KT/SOL
# PCI override — that mitigation stays active regardless.
echo ""
echo "[Step 5b] Installing /usr/local/bin/noid-mei-restore-submodules"

cat > /usr/local/bin/noid-mei-restore-submodules <<'MEI_RESTORE_EOF'
#!/bin/bash
# noid-mei-restore-submodules — MEI submodule blacklist toggle.
#
# Default state: /etc/modprobe.d/noid-mei-submodules.conf has NO
# blacklist directives — full Kicksecure-consensus per security-misc
# Issue #239. All three MEI sub-modules (mei_hdcp, mei_pxp, mei_wdt)
# remain loadable and autoload only on matching hardware. An earlier
# aggressive blacklist of all three was
# reverted after an honest cost-benefit audit. The KT/SOL host-driver block
# and generic IOMMU/lockdown defenses remain, but none disables AMT OOB.
#
# Usage:
#   sudo noid-mei-restore-submodules --list                  # show current state
#   sudo noid-mei-restore-submodules --restore wdt           # un-blacklist mei_wdt
#   sudo noid-mei-restore-submodules --block hdcp            # opt-in block mei_hdcp
#   sudo noid-mei-restore-submodules --block pxp             # opt-in block mei_pxp
#   sudo noid-mei-restore-submodules --block hdcp pxp        # opt-in block both
#
# Trade-offs when you OPT-IN to --block hdcp or --block pxp:
#   hdcp: may break Intel HDCP-protected display/content paths
#   pxp:  may break Intel protected graphics/media workflows
#
# Reboot required after any change. Run `sudo noid-status` after reboot
# to verify the new state.

set -euo pipefail
PATH=/usr/sbin:/usr/bin
export PATH
umask 077

# shellcheck source=/dev/null
[ ! -r /usr/local/lib/noid-privacy/agent-install-format.sh ] || \
    NOID_FMT_AUTO_TITLE="NoID Privacy — Intel MEI" \
    NOID_FMT_AUTO_SUBTITLE="Submodule policy" \
    . /usr/local/lib/noid-privacy/agent-install-format.sh

CONF=/etc/modprobe.d/noid-mei-submodules.conf
VALID="hdcp pxp wdt"
BOOT_MUTATION_LOCK=/run/lock/noid-boot-mutation.lock

fail() {
    echo "noid-mei-restore-submodules: $*" >&2
    exit 1
}

validate_conf() {
    [ -f "$CONF" ] && [ ! -L "$CONF" ] &&
        [ "$(stat -c '%u:%g:%a:%h' "$CONF")" = 0:0:644:1 ] ||
        fail "$CONF is missing, symlinked or has unsafe metadata"
    if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then
        matchpathcon -V "$CONF" >/dev/null ||
            fail "$CONF has an unexpected SELinux label"
    fi
}

validate_managed_policy() {
    local file=$1
    awk '
        BEGIN {
            managed["mei"]; managed["mei_me"]; managed["mei_hdcp"]
            managed["mei_pxp"]; managed["mei_wdt"]
        }
        {
            line=$0
            sub(/[[:space:]]*#.*/, "", line)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
            if (line == "") next
            count=split(line, word, /[[:space:]]+/)
            if (word[1] == "blacklist" && word[2] in managed) {
                if (count != 2 || $0 != "blacklist " word[2] ||
                    ++blacklist[word[2]] > 1) bad=1
            } else if (word[1] == "install" && word[2] in managed) {
                if (count != 3 || word[3] != "/bin/false" ||
                    $0 != "install " word[2] " /bin/false" ||
                    ++install[word[2]] > 1) bad=1
            }
        }
        END {
            for (module in managed)
                if (blacklist[module] != install[module]) bad=1
            exit bad
        }
    ' "$file" || fail "managed MEI policy is duplicated, incomplete or ambiguous"
}

begin_boot_mutation() {
    local wheel_gid path_id fd_id
    wheel_gid=$(getent group wheel | awk -F: 'NR == 1 { print $3 }')
    [[ "$wheel_gid" =~ ^[0-9]+$ ]] ||
        fail "cannot resolve the wheel group"
    [ -f "$BOOT_MUTATION_LOCK" ] && [ ! -L "$BOOT_MUTATION_LOCK" ] &&
        [ "$(stat -c '%u:%g:%a:%h' "$BOOT_MUTATION_LOCK")" = \
            "0:${wheel_gid}:660:1" ] ||
        fail "shared boot-mutation lock is missing or unsafe; repair Module 21"
    exec 7<>"$BOOT_MUTATION_LOCK"
    path_id=$(stat -c '%d:%i' "$BOOT_MUTATION_LOCK")
    fd_id=$(stat -Lc '%d:%i' /proc/self/fd/7)
    [ "$path_id" = "$fd_id" ] ||
        fail "boot-mutation lock descriptor does not name the reviewed inode"
    flock -w 300 7 || fail "timed out waiting for another boot mutation"
    [ "$(stat -Lc '%u:%g:%a:%h' /proc/self/fd/7)" = \
        "0:${wheel_gid}:660:1" ] ||
        fail "boot-mutation lock metadata changed while acquiring it"
    /usr/libexec/noid-boot-mutation-guard >/dev/null
}

show_state() {
    echo "Current MEI submodule blacklist state (/etc/modprobe.d/noid-mei-submodules.conf):"
    validate_conf
    validate_managed_policy "$CONF"
    BL=$(awk '/^blacklist mei_(hdcp|pxp|wdt)$/ {printf "%s ", $2}' "$CONF")
    if [ -n "$BL" ]; then
        echo "  Blacklisted: $BL"
    else
        echo "  Blacklisted: (none — matching hardware may autoload them)"
    fi
    echo ""
    echo "Live loaded modules:"
    LOADED=$(awk '$1 ~ /^mei/ {print "  " $1}' /proc/modules 2>/dev/null) || LOADED=""
    if [ -n "$LOADED" ]; then
        printf '%s\n' "$LOADED"
    else
        echo "  (no mei modules loaded)"
    fi
}

if [ "$#" -eq 0 ]; then
    show_state
    exit 0
fi
case "${1:-}" in
    --help|-h)
        [ "$#" -eq 1 ] || fail "usage: noid-mei-restore-submodules [--list|--restore MODULE...|--block MODULE...]"
        cat <<'HELP'
noid-mei-restore-submodules — MEI submodule blacklist toggle

  sudo noid-mei-restore-submodules --list
  sudo noid-mei-restore-submodules --restore wdt
  sudo noid-mei-restore-submodules --block hdcp
  sudo noid-mei-restore-submodules --block pxp
  sudo noid-mei-restore-submodules --block hdcp pxp

The default policy leaves mei_hdcp, mei_pxp and mei_wdt loadable. Blocking
hdcp can break protected display/content paths; blocking pxp can break
protected graphics/media workflows. Blocking wdt disables the iAMT OS-health
watchdog used on some managed vPro systems. Every change requires a reboot.
HELP
        exit 0
        ;;
    --list|status)
        [ "$#" -eq 1 ] || fail "status/list accepts no additional arguments"
        show_state
        exit 0
        ;;
esac

MODE=""
case "$1" in
    --restore) MODE=restore; shift ;;
    --block)   MODE=block;   shift ;;
    # Backward-compat: bare module name = legacy --restore behavior
    hdcp|pxp|wdt) MODE=restore ;;
    *) echo "Error: unknown action '$1' — use --restore or --block (see --help)" >&2; exit 1 ;;
esac

if [ "$#" -eq 0 ]; then
    echo "Error: $MODE requires at least one module name (hdcp|pxp|wdt)" >&2
    exit 1
fi

for arg in "$@"; do
    case " $VALID " in
        *" $arg "*) ;;
        *) echo "Error: '$arg' not in valid set: $VALID" >&2; exit 1 ;;
    esac
done
declare -A requested=()
for arg in "$@"; do
    [ -z "${requested[$arg]+x}" ] ||
        fail "duplicate module argument: $arg"
    requested[$arg]=1
done

[ "$(id -u)" -eq 0 ] || fail "must run as root (use sudo)"

echo ""
if [ "$MODE" = "restore" ]; then
    echo "⚠ Restoring (un-blacklisting) MEI sub-module(s): $*"
    echo ""
    echo "This makes the module loadable again. In the default state, NONE"
    echo "of mei_hdcp/mei_pxp/mei_wdt is blacklisted, so --restore is a"
    echo "no-op unless you previously ran --block to add an opt-in blacklist."
else
    echo "⚠ OPT-IN BLOCK of MEI sub-module(s): $*"
    echo ""
    echo "This INCREASES MEI hardening but with real functional cost:"
    for arg in "$@"; do
        case "$arg" in
            hdcp) echo "  mei_hdcp: May break Intel HDCP-protected display/content paths."
                  echo "            Exact behavior depends on GPU and media stack." ;;
            pxp)  echo "  mei_pxp:  May break Intel protected graphics/media workflows."
                  echo "            Exact behavior depends on GPU and kernel driver." ;;
            wdt)  echo "  mei_wdt:  Blocks iAMT OS-health watchdog (alarm-only). Matters"
                  echo "            only on vPro / AMT-managed enterprise + Proxmox HA"
                  echo "            cluster setups; inert on consumer non-vPro hardware." ;;
        esac
    done
fi
echo ""
read -rp "Continue? [y/N] " CONFIRM
[[ "$CONFIRM" =~ ^[yY]([eE][sS])?$ ]] || { echo "Aborted."; exit 0; }

begin_boot_mutation
validate_conf
validate_managed_policy "$CONF"

CANDIDATE=$(mktemp /etc/modprobe.d/.noid-mei-submodules.conf.XXXXXX)
ROLLBACK=$(mktemp /etc/modprobe.d/.noid-mei-submodules.rollback.XXXXXX)
COMMITTED=0
PUBLISH_ATTEMPTED=0

publish_policy() {
    local candidate=$1 destination=$2
    [ -f "$candidate" ] && [ ! -L "$candidate" ] &&
        [ "$(stat -c '%h' "$candidate")" -eq 1 ] ||
        fail "policy candidate is not a private regular file"
    chown 0:0 "$candidate"
    chmod 0644 "$candidate"
    validate_managed_policy "$candidate"
    if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then
        restorecon -F "$candidate"
        matchpathcon -V "$candidate" >/dev/null
    fi
    [ "$(stat -c '%u:%g:%a:%h' "$candidate")" = 0:0:644:1 ] ||
        fail "policy candidate metadata validation failed"
    sync -- "$candidate"
    mv -fT -- "$candidate" "$destination"
    if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then
        restorecon -F "$destination"
        matchpathcon -V "$destination" >/dev/null
    fi
    [ "$(stat -c '%u:%g:%a:%h' "$destination")" = 0:0:644:1 ] ||
        fail "published policy metadata validation failed"
    sync -- "$destination"
    sync -- /etc/modprobe.d
}

rollback_on_exit() {
    rc=$?
    trap - EXIT INT TERM HUP
    if [ "$COMMITTED" -ne 1 ] && [ "$PUBLISH_ATTEMPTED" -eq 1 ]; then
        echo "Restoring previous MEI policy and initramfs state..." >&2
        rollback_ok=1
        chown 0:0 "$ROLLBACK" || rollback_ok=0
        chmod 0644 "$ROLLBACK" || rollback_ok=0
        if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then
            restorecon -F "$ROLLBACK" || rollback_ok=0
        fi
        sync -- "$ROLLBACK" || rollback_ok=0
        if [ "$rollback_ok" -eq 1 ]; then
            mv -fT -- "$ROLLBACK" "$CONF" || rollback_ok=0
            ROLLBACK=""
        fi
        if [ "$rollback_ok" -eq 1 ] &&
           command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then
            restorecon -F "$CONF" || rollback_ok=0
            matchpathcon -V "$CONF" >/dev/null || rollback_ok=0
        fi
        if [ "$rollback_ok" -eq 1 ]; then
            sync -- "$CONF" || rollback_ok=0
            sync -- /etc/modprobe.d || rollback_ok=0
            /usr/libexec/noid-dracut-regenerate-all --lock-held=7 ||
                rollback_ok=0
        fi
        if [ "$rollback_ok" -ne 1 ]; then
            echo "CRITICAL: policy/initramfs rollback failed; use rescue media before reboot." >&2
        fi
    fi
    rm -f -- "${CANDIDATE:-}" "${ROLLBACK:-}"
    exit "$rc"
}
trap rollback_on_exit EXIT
trap 'exit 130' INT TERM HUP

cp --preserve=all -- "$CONF" "$CANDIDATE"
cp --preserve=all -- "$CONF" "$ROLLBACK"
for mod in "$@"; do
    BL_LINE="blacklist mei_${mod}"
    INST_LINE="install mei_${mod} /bin/false"
    sed -i "/^${BL_LINE}\$/d" "$CANDIDATE"
    sed -i "\\|^${INST_LINE}\$|d" "$CANDIDATE"
    if [ "$MODE" = "restore" ]; then
        :
    else
        printf '%s\n%s\n' "$BL_LINE" "$INST_LINE" >> "$CANDIDATE"
    fi
done
validate_managed_policy "$CANDIDATE"

if cmp -s "$CONF" "$CANDIDATE"; then
    echo "No policy change is required; initramfs was not rebuilt."
    exit 0
fi

[ -x /usr/local/bin/noid-snap-pre ] ||
    fail "required snapshot helper /usr/local/bin/noid-snap-pre is missing"
if ! /usr/local/bin/noid-snap-pre "MEI submodule $MODE: $*"; then
    echo "Error: pre-change snapshot failed; no changes applied." >&2
    exit 1
fi

PUBLISH_ATTEMPTED=1
publish_policy "$CANDIDATE" "$CONF"
CANDIDATE=""

echo ""
echo "Regenerating initramfs..."
if ! /usr/libexec/noid-dracut-regenerate-all --lock-held=7; then
    echo "Error: initramfs regeneration failed; do not reboot until repaired." >&2
    exit 1
fi
echo "  [OK] initramfs regenerated"
COMMITTED=1
rm -f -- "$ROLLBACK"
ROLLBACK=""

echo ""
echo "Done. Reboot required for change to take effect:"
echo "  sudo reboot"
echo ""
echo "After reboot verify with:"
echo "  lsmod | grep '^mei'"
echo "  sudo noid-status"
echo "  sudo noid-mei-restore-submodules --list"
echo ""
echo "To undo: re-run with the opposite mode or, if you created a reviewed"
echo "pre-change snapshot, use noid-snap-rollback as documented in the recovery guide."
MEI_RESTORE_EOF

chmod 755 /usr/local/bin/noid-mei-restore-submodules
chown root:root /usr/local/bin/noid-mei-restore-submodules
echo "  [OK] /usr/local/bin/noid-mei-restore-submodules installed (755)"

# ----------------------------------------------------------------------------
# Step 5c: Install /usr/local/bin/noid-mei-lockdown (experimental escape-hatch)
# ----------------------------------------------------------------------------
# Experimental opt-in: blacklists mei + mei_me, loses fwupd BootGuard
# visibility, and can break GSC/graphics/media paths on affected hardware.
# Only meaningful after hardware layers 1-3 and target-specific compatibility
# proof. Idempotent, --undo reverts; full trade-off table is in the heredoc.
echo ""
echo "[Step 5c] Installing /usr/local/bin/noid-mei-lockdown"

cat > /usr/local/bin/noid-mei-lockdown <<'MEI_LOCKDOWN_EOF'
#!/bin/bash
# noid-mei-lockdown — experimental Intel MEI core lockdown.
#
# Adds `blacklist mei` + `blacklist mei_me` + `install mei /bin/false` +
# `install mei_me /bin/false` to /etc/modprobe.d/noid-mei-submodules.conf.
#
# TRADE-OFF:
#   Lost:  normal fwupd Intel ME/BootGuard inspection on platforms that use
#          mei_me; results become absent or inconclusive. Modern Intel
#          graphics/GSC/media paths may fail, including runtime stability.
#   Gained: the normal host MEI interface is absent after reboot when the
#          blacklist is effective. This does not resist a root attacker that
#          can change the module policy or initramfs.
#
# This is ONLY meaningful if you have already completed the hardware layers:
#   1. A discrete adapter documented outside the AMT manageability path
#   2. Every AMT-capable integrated wired/wireless link disconnected
#   3. AMT unprovisioned and globally disabled in UEFI/MEBx where supported
# This script has no AMT network effect. Firmware unprovisioning and removal of
# every manageability-capable link remain separate requirements.
#
# Usage:
#   sudo noid-mei-lockdown               Apply blacklist (reboot required)
#   sudo noid-mei-lockdown --undo        Remove blacklist (reboot required)
#   sudo noid-mei-lockdown --status      Show current state

set -euo pipefail
PATH=/usr/sbin:/usr/bin
export PATH
umask 077

# shellcheck source=/dev/null
[ ! -r /usr/local/lib/noid-privacy/agent-install-format.sh ] || \
    NOID_FMT_AUTO_TITLE="NoID Privacy — Intel MEI" \
    NOID_FMT_AUTO_SUBTITLE="Experimental core lockdown" \
    . /usr/local/lib/noid-privacy/agent-install-format.sh

CONF=/etc/modprobe.d/noid-mei-submodules.conf
CORE_MODS="mei mei_me"
BOOT_MUTATION_LOCK=/run/lock/noid-boot-mutation.lock

fail() {
    echo "noid-mei-lockdown: $*" >&2
    exit 1
}

validate_conf() {
    [ -f "$CONF" ] && [ ! -L "$CONF" ] &&
        [ "$(stat -c '%u:%g:%a:%h' "$CONF")" = 0:0:644:1 ] ||
        fail "$CONF is missing, symlinked or has unsafe metadata"
    if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then
        matchpathcon -V "$CONF" >/dev/null ||
            fail "$CONF has an unexpected SELinux label"
    fi
}

validate_managed_policy() {
    local file=$1
    awk '
        BEGIN {
            managed["mei"]; managed["mei_me"]; managed["mei_hdcp"]
            managed["mei_pxp"]; managed["mei_wdt"]
        }
        {
            line=$0
            sub(/[[:space:]]*#.*/, "", line)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
            if (line == "") next
            count=split(line, word, /[[:space:]]+/)
            if (word[1] == "blacklist" && word[2] in managed) {
                if (count != 2 || $0 != "blacklist " word[2] ||
                    ++blacklist[word[2]] > 1) bad=1
            } else if (word[1] == "install" && word[2] in managed) {
                if (count != 3 || word[3] != "/bin/false" ||
                    $0 != "install " word[2] " /bin/false" ||
                    ++install[word[2]] > 1) bad=1
            }
        }
        END {
            for (module in managed)
                if (blacklist[module] != install[module]) bad=1
            exit bad
        }
    ' "$file" || fail "managed MEI policy is duplicated, incomplete or ambiguous"
}

begin_boot_mutation() {
    local wheel_gid path_id fd_id
    wheel_gid=$(getent group wheel | awk -F: 'NR == 1 { print $3 }')
    [[ "$wheel_gid" =~ ^[0-9]+$ ]] ||
        fail "cannot resolve the wheel group"
    [ -f "$BOOT_MUTATION_LOCK" ] && [ ! -L "$BOOT_MUTATION_LOCK" ] &&
        [ "$(stat -c '%u:%g:%a:%h' "$BOOT_MUTATION_LOCK")" = \
            "0:${wheel_gid}:660:1" ] ||
        fail "shared boot-mutation lock is missing or unsafe; repair Module 21"
    exec 7<>"$BOOT_MUTATION_LOCK"
    path_id=$(stat -c '%d:%i' "$BOOT_MUTATION_LOCK")
    fd_id=$(stat -Lc '%d:%i' /proc/self/fd/7)
    [ "$path_id" = "$fd_id" ] ||
        fail "boot-mutation lock descriptor does not name the reviewed inode"
    flock -w 300 7 || fail "timed out waiting for another boot mutation"
    [ "$(stat -Lc '%u:%g:%a:%h' /proc/self/fd/7)" = \
        "0:${wheel_gid}:660:1" ] ||
        fail "boot-mutation lock metadata changed while acquiring it"
    /usr/libexec/noid-boot-mutation-guard >/dev/null
}

CANDIDATE=""
ROLLBACK=""
COMMITTED=0
PUBLISH_ATTEMPTED=0

publish_policy() {
    local candidate=$1 destination=$2
    [ -f "$candidate" ] && [ ! -L "$candidate" ] &&
        [ "$(stat -c '%h' "$candidate")" -eq 1 ] ||
        fail "policy candidate is not a private regular file"
    chown 0:0 "$candidate"
    chmod 0644 "$candidate"
    validate_managed_policy "$candidate"
    if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then
        restorecon -F "$candidate"
        matchpathcon -V "$candidate" >/dev/null
    fi
    [ "$(stat -c '%u:%g:%a:%h' "$candidate")" = 0:0:644:1 ] ||
        fail "policy candidate metadata validation failed"
    sync -- "$candidate"
    mv -fT -- "$candidate" "$destination"
    if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then
        restorecon -F "$destination"
        matchpathcon -V "$destination" >/dev/null
    fi
    [ "$(stat -c '%u:%g:%a:%h' "$destination")" = 0:0:644:1 ] ||
        fail "published policy metadata validation failed"
    sync -- "$destination"
    sync -- /etc/modprobe.d
}

rollback_lockdown() {
    rc=$?
    trap - EXIT INT TERM HUP
    if [ "$COMMITTED" -ne 1 ] && [ "$PUBLISH_ATTEMPTED" -eq 1 ]; then
        echo "Restoring previous MEI policy and initramfs state..." >&2
        rollback_ok=1
        chown 0:0 "$ROLLBACK" || rollback_ok=0
        chmod 0644 "$ROLLBACK" || rollback_ok=0
        if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then
            restorecon -F "$ROLLBACK" || rollback_ok=0
        fi
        sync -- "$ROLLBACK" || rollback_ok=0
        if [ "$rollback_ok" -eq 1 ]; then
            mv -fT -- "$ROLLBACK" "$CONF" || rollback_ok=0
            ROLLBACK=""
        fi
        if [ "$rollback_ok" -eq 1 ] &&
           command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then
            restorecon -F "$CONF" || rollback_ok=0
            matchpathcon -V "$CONF" >/dev/null || rollback_ok=0
        fi
        if [ "$rollback_ok" -eq 1 ]; then
            sync -- "$CONF" || rollback_ok=0
            sync -- /etc/modprobe.d || rollback_ok=0
            /usr/libexec/noid-dracut-regenerate-all --lock-held=7 ||
                rollback_ok=0
        fi
        if [ "$rollback_ok" -ne 1 ]; then
            echo "CRITICAL: policy/initramfs rollback failed; use rescue media before reboot." >&2
        fi
    fi
    rm -f -- "${CANDIDATE:-}" "${ROLLBACK:-}"
    exit "$rc"
}

start_policy_transaction() {
    CANDIDATE=$(mktemp /etc/modprobe.d/.noid-mei-submodules.conf.XXXXXX)
    ROLLBACK=$(mktemp /etc/modprobe.d/.noid-mei-lockdown.rollback.XXXXXX)
    cp --preserve=all -- "$CONF" "$CANDIDATE"
    cp --preserve=all -- "$CONF" "$ROLLBACK"
    trap rollback_lockdown EXIT
    trap 'exit 130' INT TERM HUP
}

commit_policy_transaction() {
    local snapshot_reason=$1
    validate_managed_policy "$CANDIDATE"
    if cmp -s "$CONF" "$CANDIDATE"; then
        echo "No policy change is required; initramfs was not rebuilt."
        exit 0
    fi
    [ -x /usr/local/bin/noid-snap-pre ] ||
        fail "required snapshot helper /usr/local/bin/noid-snap-pre is missing"
    /usr/local/bin/noid-snap-pre "$snapshot_reason" ||
        fail "pre-change snapshot failed; no changes applied"
    PUBLISH_ATTEMPTED=1
    publish_policy "$CANDIDATE" "$CONF"
    CANDIDATE=""
    echo "Regenerating initramfs..."
    /usr/libexec/noid-dracut-regenerate-all --lock-held=7 ||
        fail "initramfs regeneration failed; reverting policy"
    echo "  [OK] initramfs regenerated"
    COMMITTED=1
    rm -f -- "$ROLLBACK"
    ROLLBACK=""
}

# --- status / --list mode ---
if [ "${1:-}" = "--status" ] || [ "${1:-}" = "--list" ] || [ "${1:-}" = "status" ]; then
    [ "$#" -eq 1 ] || fail "status/list accepts no additional arguments"
    validate_conf
    validate_managed_policy "$CONF"
    echo "MEI core module state:"
    for mod in $CORE_MODS; do
        if grep -qE "^blacklist ${mod}\$" "$CONF" && grep -qE "^install ${mod} /bin/false\$" "$CONF"; then
            echo "  ${mod}: BLACKLISTED (noid-mei-lockdown active — fwupd BootGuard detection OFF)"
        else
            if [ -d "/sys/module/${mod}" ]; then
                echo "  ${mod}: loaded (not blacklisted)"
            else
                echo "  ${mod}: not loaded, but not blacklisted"
            fi
        fi
    done

    echo ""
    echo "Current HSI status:"
    if command -v fwupdmgr >/dev/null 2>&1; then
        # Pin the C locale, as noid-status already does for the same command.
        # This is presentation consistency, not a correctness fix, and the
        # distinction is worth recording: measured on a de_DE host, the filter
        # below matches the same three lines either way, because both of its
        # arms key on untranslated identifiers ("BootGuard" and the HSI-N
        # section prefixes). What the pin does fix is the report reading half
        # English and half German -- fwupdmgr translates the result words it
        # prints itself, so an unpinned call showed "Gültig"/"Aktiviert" inside
        # an otherwise English block.
        #
        # The attribute titles stay localized regardless. They arrive from the
        # fwupd daemon over D-Bus and follow the daemon's locale, which this
        # client cannot set -- and should not: a German desktop showing German
        # attribute names in GNOME's Firmware Security panel is correct. Only
        # what NoID Privacy parses needs a pinned locale, and noid-status
        # already pins it for the one line it reads (`Host Security ID:`, which
        # IS translated: `Host-Sicherheitskennung:` without the pin).
        SECURITY_OUTPUT=$(LC_ALL=C fwupdmgr security 2>/dev/null) || SECURITY_OUTPUT=""
        SECURITY_FILTERED=$(awk 'BEGIN { IGNORECASE=1 } /^HSI|.*BootGuard/ {print; if (++n == 5) exit}' <<< "$SECURITY_OUTPUT")
        if [ -n "$SECURITY_FILTERED" ]; then
            printf '%s\n' "$SECURITY_FILTERED"
        else
            echo "  (no Intel ME/BootGuard attributes returned)"
        fi
    else
        echo "  (fwupdmgr not available)"
    fi
    exit 0
fi

# --- --undo mode ---
if [ "${1:-}" = "--undo" ] || [ "${1:-}" = "undo" ]; then
    [ "$#" -eq 1 ] || fail "undo accepts no additional arguments"
    [ "$(id -u)" -eq 0 ] || fail "must run as root (use sudo)"
    validate_conf
    validate_managed_policy "$CONF"
    core_blocks=0
    for mod in $CORE_MODS; do
        grep -qxF "blacklist $mod" "$CONF" &&
            core_blocks=$((core_blocks + 1))
    done
    if [ "$core_blocks" -eq 0 ]; then
        echo "noid-mei-lockdown is already inactive; no policy change is required."
        exit 0
    fi
    echo ""
    echo "REVERTING noid-mei-lockdown — mei + mei_me become loadable next boot."
    echo "This restores possible fwupd visibility on compatible hardware."
    echo ""
    read -rp "Continue? [y/N] " CONFIRM
    [[ "$CONFIRM" =~ ^[yY]([eE][sS])?$ ]] || { echo "Aborted."; exit 0; }

    begin_boot_mutation
    validate_conf
    validate_managed_policy "$CONF"
    start_policy_transaction

    for mod in $CORE_MODS; do
        sed -i "/^blacklist ${mod}\$/d" "$CANDIDATE"
        sed -i "/^install ${mod} \/bin\/false\$/d" "$CANDIDATE"
        echo "  Removed blacklist for ${mod}"
    done

    echo ""
    commit_policy_transaction "MEI lockdown undo"

    echo ""
    echo "Done. Reboot required:"
    echo "  sudo reboot"
    echo ""
    echo "After reboot verify:"
    echo "  lsmod | grep '^mei'                      # hardware-dependent"
    echo "  fwupdmgr security | grep -i bootguard    # inspect, do not assume"
    exit 0
fi

# --- default: apply lockdown ---
if [ -n "${1:-}" ] && [ "${1:-}" != "--help" ] && [ "${1:-}" != "-h" ]; then
    echo "Usage: noid-mei-lockdown [--status|--undo]" >&2
    exit 1
fi

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
    [ "$#" -eq 1 ] || fail "help accepts no additional arguments"
    cat <<'HELP'
noid-mei-lockdown — experimental Intel MEI core lockdown

  sudo noid-mei-lockdown               Apply full MEI blacklist
  sudo noid-mei-lockdown --undo        Remove lockdown (restore BootGuard detection)
  sudo noid-mei-lockdown --status      Show current state

Trade-off: normally loses fwupd Intel ME/BootGuard visibility and prevents
automatic MEI-driver loading. It can break GSC-dependent graphics/media and
system stability on affected hardware. Root can reverse this policy. It does
not disable AMT; complete the UEFI/MEBx unprovision/disable and integrated-
network-interface checklist separately.

See: /usr/share/doc/noid-privacy/15-intel-me-hardware-layer.md
HELP
    exit 0
fi

[ "$(id -u)" -eq 0 ] || fail "must run as root (use sudo)"
validate_conf
validate_managed_policy "$CONF"

# Check if already locked down
already_locked=0
for mod in $CORE_MODS; do
    if grep -qE "^blacklist ${mod}\$" "$CONF" && grep -qE "^install ${mod} /bin/false\$" "$CONF"; then
        already_locked=$((already_locked + 1))
    fi
done
if [ "$already_locked" -eq 2 ]; then
    echo "noid-mei-lockdown already active. Use --status or --undo."
    exit 0
fi

cat <<'WARN'

⚠  EXPERIMENTAL Intel MEI core lockdown

This will blacklist `mei` and `mei_me` kernel modules and prevent them
from loading even via manual modprobe. Effects:

  LOST:
    * Normal fwupd Intel ME/BootGuard inspection on mei_me platforms
    * Results may be absent or inconclusive; neither proves firmware state
    * GSC-dependent Intel graphics/protected-media paths may fail
    * Affected systems can become unstable; Fedora 44's accidental MEI
      omission caused reported i915 failures and hard freezes

  GAINED:
    * Automatic mei/mei_me loading blocked after reboot
    * Normal /dev/mei* host interface absent when no other MEI transport binds
    * Reduced host-side interface surface (reversible by root)

This is ONLY meaningful if hardware layers 1-3 are already done:
  1. AMT unprovisioned and globally disabled in UEFI/MEBx where supported
  2. Every AMT-capable integrated wired/wireless link disconnected
  3. Active adapter documented by the OEM as outside the manageability path

Those actions address AMT networking. This script affects only the Linux host
interface, never proves that firmware has no network path, and must not be
enabled until target-specific graphics/GSC compatibility has been proven.

WARN

read -rp "Continue? [y/N] " CONFIRM
[[ "$CONFIRM" =~ ^[yY]([eE][sS])?$ ]] || { echo "Aborted."; exit 0; }

begin_boot_mutation
validate_conf
validate_managed_policy "$CONF"
start_policy_transaction
for mod in $CORE_MODS; do
    sed -i "/^blacklist ${mod}\$/d" "$CANDIDATE"
    sed -i "/^install ${mod} \/bin\/false\$/d" "$CANDIDATE"
    printf 'blacklist %s\ninstall %s /bin/false\n' "$mod" "$mod" >> "$CANDIDATE"
done

echo ""
commit_policy_transaction "MEI lockdown (experimental)"

echo ""
echo "Done. Reboot required for change to take effect:"
echo "  sudo reboot"
echo ""
echo "After reboot verify:"
echo "  lsmod | grep '^mei'                         # Expected: EMPTY output"
echo "  ls /dev/mei*                                # Expected: 'No such file or directory'"
echo "  fwupdmgr security | grep -i bootguard       # absent/inconclusive is likely"
echo "  sudo noid-mei-lockdown --status             # Shows BLACKLISTED state"
echo ""
echo "To revert: sudo noid-mei-lockdown --undo + reboot"
MEI_LOCKDOWN_EOF

chmod 755 /usr/local/bin/noid-mei-lockdown
chown root:root /usr/local/bin/noid-mei-lockdown
echo "  [OK] /usr/local/bin/noid-mei-lockdown installed (755)"

# ----------------------------------------------------------------------------
# Step 5e: firstboot vendor re-detection service
# ----------------------------------------------------------------------------
# The Live-ISO %post runs in the build qemu-VM, so Step 0's detection
# reflects the BUILD environment. This boot oneshot re-detects on the real
# target and atomically replaces each prevalidated cpu-vendor/mei-status record.
# The consumed status record is published last. Kernel and policy hashes let
# consumers expose stale evidence after failure.
echo ""
echo "[Step 5e] Installing noid-cpu-vendor-detect-firstboot service"

cat > /usr/libexec/noid-platform-policy-sha256 <<'POLICY_SHA_EOF'
#!/bin/bash
# Hash the exact local policy inputs that affect the platform-status result.
# Reject missing, replaced, hard-linked or unreadable inputs; never publish a
# digest of a partial producer stream.
set -euo pipefail
PATH=/usr/sbin:/usr/bin
export PATH
LC_ALL=C
export LC_ALL
if [ "$#" -ne 0 ]; then
    printf '%s\n' 'ERROR: noid-platform-policy-sha256 accepts no arguments' >&2
    exit 2
fi
umask 077

inputs=(
    '644:/etc/modprobe.d/noid-mei-submodules.conf'
    '644:/etc/udev/rules.d/99-noid-mei-kt-block.rules'
    '755:/usr/libexec/noid-mei-kt-enforce'
    '644:/etc/systemd/system/noid-mei-kt-enforce.service'
    '644:/etc/dracut.conf.d/noid-mei-blacklist.conf'
    '755:/usr/local/sbin/noid-cpu-vendor-detect.sh'
    '644:/etc/systemd/system/noid-cpu-vendor-detect-firstboot.service'
)

hash=$(
    {
        printf '%s\0' 'NOID_PLATFORM_POLICY_V2'
        for spec in "${inputs[@]}"; do
            expected_mode=${spec%%:*}
            path=${spec#*:}
            [ -f "$path" ] && [ ! -L "$path" ] && [ -r "$path" ] &&
                [ "$(stat -c '%u:%g:%a:%h' "$path")" = \
                    "0:0:${expected_mode}:1" ] || {
                    echo "noid-platform-policy-sha256: unsafe input: $path" >&2
                    exit 1
                }
            if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then
                matchpathcon -V "$path" >/dev/null || {
                    echo "noid-platform-policy-sha256: label drift: $path" >&2
                    exit 1
                }
            fi
            printf '%s\0' "$path"
            cat -- "$path"
            printf '\0'
        done
    } | sha256sum
)
hash=${hash%% *}
if [[ ! "$hash" =~ ^[a-f0-9]{64}$ ]]; then
    echo "noid-platform-policy-sha256: invalid digest result" >&2
    exit 1
fi
printf '%s\n' "$hash"
POLICY_SHA_EOF
chmod 0755 /usr/libexec/noid-platform-policy-sha256
chown root:root /usr/libexec/noid-platform-policy-sha256
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F /usr/libexec/noid-platform-policy-sha256 2>/dev/null || true
fi

cat > /usr/local/sbin/noid-cpu-vendor-detect.sh <<'CPU_DETECT_EOF'
#!/bin/bash
# NoID Privacy — repeatable CPU/platform status detection on target hardware.
# Module 15 Step 5e — addresses build-vs-target drift and later kernel/policy
# changes without mutating configuration.
#
# Re-runs CPU_VENDOR + VIRT_TYPE detection and atomically replaces each
# prevalidated /var/lib/noid-privacy/cpu-vendor + mei-status.txt record.

set -euo pipefail
PATH=/usr/sbin:/usr/bin
export PATH
LC_ALL=C
export LC_ALL
if [ "$#" -ne 0 ]; then
    printf '%s\n' 'ERROR: noid-cpu-vendor-detect accepts no arguments' >&2
    exit 2
fi
umask 077

STATE_DIR=/var/lib/noid-privacy
CPU_VENDOR_FILE="$STATE_DIR/cpu-vendor"
MEI_STATUS_FILE="$STATE_DIR/mei-status.txt"
LOG_TAG="noid-cpu-vendor-detect"
CPU_VENDOR_TMP=""
MEI_STATUS_TMP=""

log() {
    if command -v logger >/dev/null 2>&1; then
        logger -t "$LOG_TAG" -- "$*" 2>/dev/null || echo "[WARN] journal logging failed" >&2
    fi
    echo "[$(date -Iseconds)] $*"
}

# Invoked by the EXIT/signal traps below.
# shellcheck disable=SC2329
cleanup() {
    [ -z "$CPU_VENDOR_TMP" ] || rm -f -- "$CPU_VENDOR_TMP"
    [ -z "$MEI_STATUS_TMP" ] || rm -f -- "$MEI_STATUS_TMP"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

validate_publish_target() {
    local destination=$1
    local expected_meta="${NOID_PLATFORM_EXPECTED_META:-0:0:644:1}"
    if [ -e "$destination" ] || [ -L "$destination" ]; then
        [ -f "$destination" ] && [ ! -L "$destination" ] &&
            [ "$(stat -c '%u:%g:%a:%h' "$destination")" = \
                "$expected_meta" ] || return 1
        if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then
            matchpathcon -V "$destination" >/dev/null || return 1
        fi
    fi
}

atomic_publish() {
    local candidate="$1" destination="$2" meta destination_dir
    local expected_meta="${NOID_PLATFORM_EXPECTED_META:-0:0:644:1}"
    [ -f "$candidate" ] && [ ! -L "$candidate" ] &&
        [ "$(stat -c '%h' "$candidate")" -eq 1 ] || return 1
    validate_publish_target "$destination" || return 1
    chown 0:0 "$candidate"
    chmod 0644 "$candidate"
    meta=$(stat -c '%u:%g:%a:%h' "$candidate")
    [ "$meta" = "$expected_meta" ] || return 1
    if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then
        restorecon -F "$candidate"
        matchpathcon -V "$candidate" >/dev/null
    fi
    sync -- "$candidate"
    mv -fT -- "$candidate" "$destination"
    if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then
        restorecon -F "$destination"
        matchpathcon -V "$destination" >/dev/null
    fi
    [ "$(stat -c '%u:%g:%a:%h' "$destination")" = \
        "$expected_meta" ] || return 1
    sync -- "$destination"
    destination_dir=${destination%/*}
    sync -- "$destination_dir"
}

# Detect CPU vendor (target hardware /proc/cpuinfo)
CPU_VENDOR="unknown"
if grep -qE '^vendor_id[[:space:]]*:[[:space:]]*GenuineIntel' /proc/cpuinfo 2>/dev/null; then
    CPU_VENDOR="intel"
elif grep -qE '^vendor_id[[:space:]]*:[[:space:]]*(AuthenticAMD|HygonGenuine)' /proc/cpuinfo 2>/dev/null; then
    CPU_VENDOR="amd"
fi

# Detect virtualization (target environment)
# Note: systemd-detect-virt returns rc=1 on bare-metal (output "none" + non-
# zero exit). Capture stdout regardless of rc; fall back to "none" on empty.
VIRT_TYPE="none"
if command -v systemd-detect-virt >/dev/null 2>&1; then
    detected=$(systemd-detect-virt 2>/dev/null) || true
    if [ -n "$detected" ]; then
        VIRT_TYPE="$detected"
    fi
fi

log "Target detected: CPU_VENDOR=$CPU_VENDOR VIRT_TYPE=$VIRT_TYPE"

if [ -e "$STATE_DIR" ] || [ -L "$STATE_DIR" ]; then
    [ -d "$STATE_DIR" ] && [ ! -L "$STATE_DIR" ] &&
        [ "$(stat -c '%u:%g:%a' "$STATE_DIR")" = "0:0:755" ] || {
            log "invalid shared state-directory type or metadata"
            exit 1
        }
else
    install -d -m 0755 -o root -g root "$STATE_DIR"
fi
if [ "$(stat -c '%u:%g:%a' "$STATE_DIR")" != "0:0:755" ]; then
    log "invalid shared state-directory metadata"
    exit 1
fi
if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled &&
   ! matchpathcon -V "$STATE_DIR" >/dev/null; then
    log "invalid shared state-directory SELinux label"
    exit 1
fi

CHECKED_AT_KERNEL=$(uname -r)
CHECKED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
CHECKED_POLICY_SHA256=$(/usr/libexec/noid-platform-policy-sha256)
[[ "$CHECKED_AT_KERNEL" =~ ^[A-Za-z0-9._+-]+$ ]]
[[ "$CHECKED_POLICY_SHA256" =~ ^[a-f0-9]{64}$ ]]

detect_mei_submodule_policy() {
    local policy_file=${1:-/etc/modprobe.d/noid-mei-submodules.conf}
    local scope=${2:-submodules}
    local short module policy_line
    local blacklist_count install_count invalid
    local -a words blocked=() modules=()

    [ -f "$policy_file" ] && [ ! -L "$policy_file" ] || return 1
    case "$scope" in
        submodules) modules=(mei_hdcp mei_pxp mei_wdt) ;;
        core) modules=(mei mei_me) ;;
        *) return 1 ;;
    esac
    for module in "${modules[@]}"; do
        blacklist_count=0
        install_count=0
        invalid=0
        while IFS= read -r policy_line || [ -n "$policy_line" ]; do
            policy_line=${policy_line%%#*}
            read -r -a words <<< "$policy_line"
            [ "${#words[@]}" -gt 0 ] || continue
            if [ "${words[0]}" = blacklist ] && \
               [ "${words[1]:-}" = "$module" ]; then
                if [ "${#words[@]}" -eq 2 ]; then
                    blacklist_count=$((blacklist_count + 1))
                else
                    invalid=1
                fi
            elif [ "${words[0]}" = install ] && \
                 [ "${words[1]:-}" = "$module" ]; then
                if [ "${#words[@]}" -eq 3 ] && \
                   [ "${words[2]}" = /bin/false ]; then
                    install_count=$((install_count + 1))
                else
                    invalid=1
                fi
            fi
        done < "$policy_file"
        if [ "$invalid" -ne 0 ] || [ "$blacklist_count" -gt 1 ] || \
           [ "$install_count" -gt 1 ]; then
            return 1
        fi
        if [ "$blacklist_count" -eq 1 ] && [ "$install_count" -eq 1 ]; then
            if [ "$scope" = submodules ]; then
                short=${module#mei_}
                blocked+=("$short")
            else
                blocked+=("$module")
            fi
        elif [ "$blacklist_count" -ne 0 ] || [ "$install_count" -ne 0 ]; then
            return 1
        fi
    done
    case "$scope:${#blocked[@]}" in
        submodules:0) printf '%s\n' none ;;
        submodules:*) local IFS=,; printf '%s\n' "${blocked[*]}" ;;
        core:0) printf '%s\n' loadable ;;
        core:2) printf '%s\n' blacklisted ;;
        *) return 1 ;;
    esac
}

classify_kt_sol_check() {
    local output="$1"
    local matched unbound
    if [[ ! "$output" =~ ^KT/SOL[[:space:]]enforcement[[:space:]]complete[[:space:]]\(matched=([0-9]+),[[:space:]]unbound=([0-9]+)\)$ ]]; then
        return 1
    fi
    matched=${BASH_REMATCH[1]}
    unbound=${BASH_REMATCH[2]}
    # The detector invokes check-only mode, so any reported unbind operation
    # means the helper/output contract drifted and must not be published.
    [ "$unbound" -eq 0 ] || return 1
    if [ "$matched" -eq 0 ]; then
        printf '%s\n' no-device-present
    else
        printf '%s\n' enforced
    fi
}

CPU_VENDOR_TMP=$(mktemp "$STATE_DIR/.cpu-vendor.tmp.XXXXXX")
MEI_STATUS_TMP=$(mktemp "$STATE_DIR/.mei-status.tmp.XXXXXX")

# Render cpu-vendor candidate with target reality.
cat > "$CPU_VENDOR_TMP" <<VENDOR_EOF
CPU_VENDOR=$CPU_VENDOR
VIRT_TYPE=$VIRT_TYPE
DETECTED_AT=$CHECKED_AT
DETECTED_BY=target-boot-refresh
CHECKED_AT_KERNEL=$CHECKED_AT_KERNEL
CHECKED_POLICY_SHA256=$CHECKED_POLICY_SHA256
VENDOR_EOF

# Real MEI state detection. A hard-coded MEI_STATE=active for any Intel
# CPU would misrepresent reality: a Fedora 44 kernel build (7.0.4) shipped
# with CONFIG_INTEL_MEI=n — mei/mei_me modules absent from the kernel-core
# package on affected Intel hosts, so noid-welcome + audit reports would
# show a wrong MEI/BootGuard state. This checks reality at boot time.
MEI_STATE="unknown"
MEI_CORE_POLICY="not-applicable"
MEI_FWUPD_VISIBILITY="unknown"
MEI_KERNEL_REGRESSION="no"
MEI_KT_SOL_HOST_BINDING="not-applicable"
CCP_STATE="not-applicable"
PSP_FWUPD_VISIBILITY="not-applicable"
if [ "$CPU_VENDOR" = "intel" ]; then
    if ! MEI_CORE_POLICY=$(
        detect_mei_submodule_policy \
            /etc/modprobe.d/noid-mei-submodules.conf core
    ) || ! MEI_SUBMODULES_BLOCKED=$(
        detect_mei_submodule_policy /etc/modprobe.d/noid-mei-submodules.conf
    ); then
        log "invalid or incomplete MEI policy; refusing status publication"
        exit 1
    fi
    mei_me_bound="no"
    for bound_path in /sys/bus/pci/drivers/mei_me/*:*; do
        if [ -L "$bound_path" ]; then
            mei_me_bound="yes"
            break
        fi
    done
    if [ "$MEI_CORE_POLICY" = blacklisted ]; then
        MEI_STATE="blocked-by-policy"
        MEI_FWUPD_VISIBILITY="unavailable-by-policy"
    elif [ "$mei_me_bound" = "yes" ]; then
        MEI_STATE="mei-me-bound"
        MEI_FWUPD_VISIBILITY="available-platform-results-vary"
    elif modprobe -n -q mei 2>/dev/null; then
        # Module exists in modules tree but not loaded (could be blacklisted
        # downstream or just not auto-loaded yet)
        MEI_STATE="available-not-loaded"
        MEI_FWUPD_VISIBILITY="conditional"
    elif [ -f "/boot/config-$(uname -r)" ] && \
         grep -q "^# CONFIG_INTEL_MEI is not set" "/boot/config-$(uname -r)" 2>/dev/null; then
        # Kernel was built without CONFIG_INTEL_MEI=m — Fedora 44 7.0.4 regression
        MEI_STATE="absent"
        MEI_FWUPD_VISIBILITY="unavailable"
        MEI_KERNEL_REGRESSION="yes"
    else
        # Module not loadable, can't determine kernel-config — assume absent
        MEI_STATE="absent"
        MEI_FWUPD_VISIBILITY="unavailable"
    fi

    if kt_sol_output=$(
        NOID_MEI_KT_CHECK_ONLY=1 /usr/libexec/noid-mei-kt-enforce 2>/dev/null
    ); then
        if ! MEI_KT_SOL_HOST_BINDING=$(classify_kt_sol_check "$kt_sol_output"); then
            log "invalid KT/SOL check-only result; refusing status publication"
            exit 1
        fi
    else
        MEI_KT_SOL_HOST_BINDING="failed"
    fi
elif [ "$CPU_VENDOR" = "amd" ]; then
    if [ -d /sys/module/ccp ]; then
        CCP_STATE="loaded"
    elif modprobe -n -q ccp 2>/dev/null; then
        CCP_STATE="available-not-loaded"
    else
        CCP_STATE="unavailable"
    fi
    PSP_FWUPD_VISIBILITY="unavailable"
    for bound_path in /sys/bus/pci/drivers/ccp/*:*; do
        if [ -L "$bound_path" ]; then
            PSP_FWUPD_VISIBILITY="available-platform-results-vary"
            break
        fi
    done
fi

# Render mei-status.txt candidate with target-vendor-appropriate content.
case "$CPU_VENDOR" in
    intel)
        # NOTE: NO single-quotes on heredoc marker — we need variable
        # expansion for the live-detected MEI_STATE / kernel-version / date.
        cat > "$MEI_STATUS_TMP" <<MEI_INTEL_EOF
# NoID Privacy — Intel ME Mitigation Status (Intel host)
# Written by noid-cpu-vendor-detect-firstboot.service at boot.
# Parsed by /usr/local/bin/noid-status.
# CHECKED_AT_KERNEL lets downstream consumers detect stale state after
# kernel-upgrade (compare to \$(uname -r) at read time).
CPU_VENDOR=intel
MEI_STATE=$MEI_STATE
MEI_CORE_POLICY=$MEI_CORE_POLICY
MEI_KERNEL_REGRESSION=$MEI_KERNEL_REGRESSION
MEI_SUBMODULES_BLOCKED=$MEI_SUBMODULES_BLOCKED
MEI_KT_SOL_HOST_BINDING=$MEI_KT_SOL_HOST_BINDING
MEI_FWUPD_VISIBILITY=$MEI_FWUPD_VISIBILITY
CHECKED_AT_KERNEL=$CHECKED_AT_KERNEL
CHECKED_AT=$CHECKED_AT
CHECKED_POLICY_SHA256=$CHECKED_POLICY_SHA256
MEI_INTEL_EOF
        ;;
    amd)
        # Runtime values are intentionally expanded into the status file.
        cat > "$MEI_STATUS_TMP" <<MEI_AMD_EOF
# NoID Privacy — Firmware-Layer Mitigation Status (AMD host)
# Written by noid-cpu-vendor-detect-firstboot.service at boot.
CPU_VENDOR=amd
MEI_STATE=n/a-on-amd
PSP_STATE=firmware-managed
CCP_STATE=$CCP_STATE
CCP_POLICY=not-blacklisted
PSP_FWUPD_VISIBILITY=$PSP_FWUPD_VISIBILITY
PSB_STATE=see-fwupdmgr-security
HARDWARE_LAYER_DOC=/usr/share/doc/noid-privacy/15-amd-psp-hardware-layer.md
CHECKED_AT_KERNEL=$CHECKED_AT_KERNEL
CHECKED_AT=$CHECKED_AT
CHECKED_POLICY_SHA256=$CHECKED_POLICY_SHA256
MEI_AMD_EOF
        ;;
    *)
        cat > "$MEI_STATUS_TMP" <<MEI_UNKNOWN_EOF
# NoID Privacy — Firmware-Layer Mitigation Status (non-Intel/AMD host)
# Written by noid-cpu-vendor-detect-firstboot.service at boot.
CPU_VENDOR=unknown
MEI_STATE=n/a
PSP_STATE=n/a
NOTE=vendor-specific firmware status unavailable; generic hardening still applies
CHECKED_AT_KERNEL=$CHECKED_AT_KERNEL
CHECKED_AT=$CHECKED_AT
CHECKED_POLICY_SHA256=$CHECKED_POLICY_SHA256
MEI_UNKNOWN_EOF
        ;;
esac

# Validate both complete candidates and both existing targets before either
# becomes visible. Publish cpu-vendor first and the consumed mei-status record
# last: an interruption leaves no unvalidated status record, and each file
# transition itself is a same-directory atomic rename.
grep -qE '^CPU_VENDOR=(intel|amd|unknown)$' "$CPU_VENDOR_TMP"
grep -qE '^CHECKED_AT_KERNEL=[A-Za-z0-9._+-]+$' "$CPU_VENDOR_TMP"
grep -qE '^CHECKED_POLICY_SHA256=[a-f0-9]{64}$' "$CPU_VENDOR_TMP"
grep -qE '^CPU_VENDOR=(intel|amd|unknown)$' "$MEI_STATUS_TMP"
grep -qE '^MEI_STATE=' "$MEI_STATUS_TMP"
grep -qE '^CHECKED_AT_KERNEL=[A-Za-z0-9._+-]+$' "$MEI_STATUS_TMP"
grep -qE '^CHECKED_POLICY_SHA256=[a-f0-9]{64}$' "$MEI_STATUS_TMP"
validate_publish_target "$CPU_VENDOR_FILE" || {
    log "unsafe existing cpu-vendor publication target"
    exit 1
}
validate_publish_target "$MEI_STATUS_FILE" || {
    log "unsafe existing MEI-status publication target"
    exit 1
}
atomic_publish "$CPU_VENDOR_TMP" "$CPU_VENDOR_FILE"
CPU_VENDOR_TMP=""
atomic_publish "$MEI_STATUS_TMP" "$MEI_STATUS_FILE"
MEI_STATUS_TMP=""
log "atomically published platform status (CPU_VENDOR=$CPU_VENDOR)"

log "done"
trap - EXIT HUP INT TERM
exit 0
CPU_DETECT_EOF

chmod 755 /usr/local/sbin/noid-cpu-vendor-detect.sh
chown root:root /usr/local/sbin/noid-cpu-vendor-detect.sh
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F /usr/local/sbin/noid-cpu-vendor-detect.sh 2>/dev/null || true
fi
echo "  [OK] /usr/local/sbin/noid-cpu-vendor-detect.sh installed (755)"

cat > /etc/systemd/system/noid-cpu-vendor-detect-firstboot.service <<'CPU_DETECT_SVC_EOF'
[Unit]
Description=NoID Privacy — refresh kernel/policy-bound platform status
Documentation=file:///usr/share/doc/noid-privacy/15-intel-me-hardware-layer.md
After=local-fs.target systemd-modules-load.service noid-mei-kt-enforce.service
Before=multi-user.target
ConditionKernelCommandLine=!rd.live.image
ConditionFileIsExecutable=/usr/local/sbin/noid-cpu-vendor-detect.sh

[Service]
Type=oneshot
RemainAfterExit=no
ExecStart=/usr/local/sbin/noid-cpu-vendor-detect.sh
StandardOutput=journal
StandardError=journal
UMask=0077

# Sandbox. NoNewPrivileges is deliberately omitted: `modprobe -n` enters
# Fedora's kmod_t SELinux domain, and NNP blocks that LSM transition with an
# enforcing `process2 nnp_transition` AVC. Module loading remains impossible
# through both the capability and syscall denials below.
ProtectSystem=strict
ReadWritePaths=/var/lib/noid-privacy
ProtectHome=true
PrivateTmp=true
PrivateDevices=yes
PrivateNetwork=yes
ProtectClock=yes
ProtectHostname=yes
ProtectKernelTunables=yes
# Keep /usr/lib/modules visible for `modprobe -n` while retaining the two
# enforcement parts of ProtectKernelModules=: capability and syscall denial.
CapabilityBoundingSet=~CAP_SYS_MODULE
SystemCallFilter=~@module
SystemCallErrorNumber=EPERM
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictAddressFamilies=AF_UNIX
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
IPAddressDeny=any

[Install]
WantedBy=multi-user.target
CPU_DETECT_SVC_EOF

chmod 644 /etc/systemd/system/noid-cpu-vendor-detect-firstboot.service
chown root:root /etc/systemd/system/noid-cpu-vendor-detect-firstboot.service

systemctl enable noid-cpu-vendor-detect-firstboot.service

if [ -L /etc/systemd/system/multi-user.target.wants/noid-cpu-vendor-detect-firstboot.service ]; then
    echo "  [OK] noid-cpu-vendor-detect-firstboot.service installed + enabled"
else
    echo "  [WARN] noid-cpu-vendor-detect-firstboot.service enable symlink missing"
fi

# ----------------------------------------------------------------------------
# Step 6: Cross-check Module 13 AIDE coverage for MEI config files
# ----------------------------------------------------------------------------
# M13's SECURE rules content-hash the config dirs, systemd unit, and exact
# /usr/libexec helper this module writes — tampering without a permission
# change still alerts, and user-added opt-in blacklists are tracked too.
# sysfs driver_override is a kernel interface, not a file — no AIDE coverage.
echo ""
echo "[Step 6] Cross-checking Module 13 AIDE SECURE rules for MEI config files"
check_aide_coverage() {
    local config="$1" rule_path="$2" file_type="$3" probe_path="$4" match
    grep -qxF "$rule_path SECURE" "$config" || return 1
    match=$(LC_ALL=C aide --config="$config" \
        --path-check="$file_type:$probe_path" 2>&1) || return 1
    grep -qF 'sha256' <<<"$match" && grep -qF 'sha512' <<<"$match"
}

M15_AIDE_COVERAGE=(
    '/etc/modprobe.d/|f|/etc/modprobe.d/noid-mei-submodules.conf'
    '/etc/udev/rules.d|f|/etc/udev/rules.d/99-noid-mei-kt-block.rules'
    '/etc/dracut.conf.d/|f|/etc/dracut.conf.d/noid-mei-blacklist.conf'
    '/etc/systemd/system/|f|/etc/systemd/system/noid-mei-kt-enforce.service'
    '/usr/libexec/noid-mei-kt-enforce|f|/usr/libexec/noid-mei-kt-enforce'
    '/usr/libexec/noid-platform-policy-sha256|f|/usr/libexec/noid-platform-policy-sha256'
)
aide_coverage_fail=0
for coverage_spec in "${M15_AIDE_COVERAGE[@]}"; do
    IFS='|' read -r rule_path file_type probe_path <<<"$coverage_spec"
    if check_aide_coverage /etc/aide.conf "$rule_path" "$file_type" "$probe_path"; then
        echo "  [OK] effective AIDE SECURE coverage: $probe_path"
    else
        echo "  [FAIL] missing/weak/shadowed AIDE SECURE coverage: $probe_path"
        aide_coverage_fail=$((aide_coverage_fail + 1))
    fi
done
if [ "$aide_coverage_fail" -ne 0 ]; then
    echo "  [FAIL] mandatory M15 AIDE coverage has $aide_coverage_fail failure(s)"
    exit 1
fi

# ----------------------------------------------------------------------------
# Step 7: Verification (vendor-aware)
# ----------------------------------------------------------------------------
# On Intel: check all Intel-ME mitigation files written correctly.
# On AMD:   check AMD doc shipped + Intel-only files absent + ccp policy.
# On other: minimal check (CPU_VENDOR state + AMD doc as generic reference).

echo ""
echo "[Step 7] Verification (CPU_VENDOR=$CPU_VENDOR)"

fail=0

if [ "$CPU_VENDOR" = "intel" ]; then

# 7.0a — Kernel-level MEI availability check:
# Detects the upstream Fedora kernel CONFIG_INTEL_MEI=n regression
# (kernel 7.0.4-200.fc44). Info-level, not fail — issue is upstream
# Fedora kernel build, NOT NoID Privacy source. M15 config-files still
# shipped correctly (they apply when Fedora ships a kernel with
# CONFIG_INTEL_MEI=m again).
KERNEL_CFG="/boot/config-$(uname -r)"
if [ -r "$KERNEL_CFG" ]; then
    if grep -qE '^# CONFIG_INTEL_MEI is not set' "$KERNEL_CFG"; then
        echo "  [INFO] Kernel $(uname -r) has CONFIG_INTEL_MEI=n —"
        echo "         mei modules will NOT load, so fwupd BootGuard"
        echo "         detection is unavailable. Known-upstream-Fedora"
        echo "         regression from 7.0.4 Dirty Frag rebase."
        echo "         M15 config-files still deployed correctly (will apply"
        echo "         with the fixed Fedora 7.0.6 or any later enabled kernel)."
    elif grep -qE '^CONFIG_INTEL_MEI=[my]' "$KERNEL_CFG"; then
        echo "  [OK] Kernel $(uname -r) has CONFIG_INTEL_MEI enabled (mei modules buildable)"
    else
        echo "  [INFO] Kernel $(uname -r) CONFIG_INTEL_MEI state indeterminate"
    fi
else
    echo "  [INFO] /boot/config-$(uname -r) not readable — kernel MEI-config check skipped"
fi

# 7.1 — modprobe.d file exists with expected content (no blacklists)
# Kicksecure-consensus — NO default blacklist of any MEI sub-module. The
# file exists as documentation + opt-in CLI target. Verify file exists
# AND has no `blacklist mei_*` directives present (regression guard
# against re-introducing an aggressive blacklist).
if [ -f /etc/modprobe.d/noid-mei-submodules.conf ]; then
    echo "  [OK] noid-mei-submodules.conf present (v13 default-empty config)"
    # Regression guard: no MEI sub-module blacklist directives in default
    # canonical: `grep -c` returns "0" to
    # stdout AND exits 1 when there are zero matches in an existing file.
    # `|| echo 0` then ALSO fires → stdout = "0\n0" → `-eq 0` integer-compare
    # fails with "integer expected" bash error → ScriptError 20280 → build abort.
    # The canonical pattern is `2>/dev/null || true` (no fallback echo) +
    # `${var:-0}` default-substitution to guarantee a single-integer scalar.
    found_bl=$(grep -cE '^blacklist mei_(hdcp|pxp|wdt)$' /etc/modprobe.d/noid-mei-submodules.conf 2>/dev/null || true)
    found_bl=${found_bl:-0}
    found_inst=$(grep -cE '^install mei_(hdcp|pxp|wdt) /bin/false$' /etc/modprobe.d/noid-mei-submodules.conf 2>/dev/null || true)
    found_inst=${found_inst:-0}
    if [ "$found_bl" -eq 0 ] && [ "$found_inst" -eq 0 ]; then
        echo "  [OK] no default MEI sub-module blacklists (v13 correct — opt-in only)"
    else
        echo "  [FAIL] v13 regression: $found_bl blacklist + $found_inst install lines present (should be 0 in default)"
        fail=$((fail + 1))
    fi
else
    echo "  [FAIL] /etc/modprobe.d/noid-mei-submodules.conf missing"
    fail=$((fail + 1))
fi

# 7.2 — mei + mei_me NOT blacklisted (preserves compatible fwupd inspection)
if grep -qE '^blacklist mei$|^blacklist mei_me$' /etc/modprobe.d/noid-mei-submodules.conf; then
    echo "  [FAIL] noid-mei-submodules.conf blacklists mei or mei_me (default must keep them loadable)"
    fail=$((fail + 1))
else
    echo "  [OK] mei + mei_me are NOT blacklisted (compatible hardware may bind for fwupd visibility)"
fi

# 7.3 — Fedora-shipped modprobe.d does not also blacklist mei/mei_me
# Atomic `find -exec grep -l ... {} +` instead
# of `find | xargs grep -l ...` — eliminates the "xargs without -r reads
# stdin from terminal on empty input" robustness issue. `{} +` batches
# args atomically, exit-code reflects whether any file matched (analog
# to xargs grep but no pipe).
if find /usr/lib/modprobe.d /etc/modprobe.d -name '*.conf' 2>/dev/null \
       -exec grep -l -E '^blacklist mei$|^blacklist mei_me$|^install mei /bin/false$|^install mei_me /bin/false$' {} + 2>/dev/null \
       | grep -q .; then
    echo "  [WARN] Another modprobe.d file blacklists mei/mei_me — may break BootGuard detection"
    # Not a fail — user may have opt-in paranoid config
else
    echo "  [OK] No conflicting mei/mei_me blacklist in other modprobe.d files"
fi

# 7.4 — udev rule/helper exists with KT/SOL PCI IDs and active unbind fallback
if [ -f /etc/udev/rules.d/99-noid-mei-kt-block.rules ]; then
    # Required IDs: 6th-17th gen Intel + Sapphire Rapids server. Missing any = build regression.
    KT_SOL_IDS="0xa13d 0xa2bd 0x9de3 0xa363 0x06e3 0x02e3 0xa3bd 0x34e3 0x38e3 0x4de3 0x4b73 0xa0e3 0x43e3 0x1be3 0x7aeb 0x7a63 0x51e3 0x54e3 0x7a6b 0x7e73 0x7f6b 0x7773 0xa873 0xe373 0xe473 0x6e6b 0x4d73"
    ids_missing=0
    for id in $KT_SOL_IDS; do
        if ! grep -q "$id" /etc/udev/rules.d/99-noid-mei-kt-block.rules; then
            echo "  [FAIL] udev rule missing KT/SOL ID $id"
            ids_missing=$((ids_missing + 1))
        fi
    done
    if [ "$ids_missing" -eq 0 ]; then
        echo "  [OK] udev rule: all 27 KT/SOL PCI IDs present (6th-17th gen + Sapphire Rapids)"
    else
        fail=$((fail + ids_missing))
    fi
    # udev syntax is `ATTR{driver_override}="none"` with `}`
    # between `driver_override` and `="none"`. Must match the full udev
    # attribute form — the literal substring `driver_override="none"` doesn't
    # exist in the rule (always preceded by `}` in udev ATTR{} expansion).
    if grep -q 'ATTR{driver_override}="none"' /etc/udev/rules.d/99-noid-mei-kt-block.rules; then
        echo "  [OK] udev rule uses driver_override=none"
    else
        echo "  [FAIL] udev rule missing ATTR{driver_override}=\"none\""
        fail=$((fail + 1))
    fi
    if grep -q 'ACTION=="add|bind"' /etc/udev/rules.d/99-noid-mei-kt-block.rules &&
       grep -q 'RUN+="/usr/libexec/noid-mei-kt-enforce"' /etc/udev/rules.d/99-noid-mei-kt-block.rules; then
        echo "  [OK] udev rule covers add+bind and invokes active enforcement"
    else
        echo "  [FAIL] udev rule missing add+bind helper enforcement"
        fail=$((fail + 1))
    fi
else
    echo "  [FAIL] /etc/udev/rules.d/99-noid-mei-kt-block.rules missing"
    fail=$((fail + 1))
fi
if [ -x /usr/libexec/noid-mei-kt-enforce ] &&
   NOID_MEI_KT_CHECK_ONLY=1 /usr/libexec/noid-mei-kt-enforce >/dev/null; then
    echo "  [OK] KT/SOL helper installed and current host binding state verified"
else
    echo "  [FAIL] KT/SOL helper missing or binding state not enforced"
    fail=$((fail + 1))
fi
if [ -f /etc/systemd/system/noid-mei-kt-enforce.service ] &&
   [ -L /etc/systemd/system/sysinit.target.wants/noid-mei-kt-enforce.service ]; then
    echo "  [OK] early-boot KT/SOL verification service installed + enabled"
else
    echo "  [FAIL] early-boot KT/SOL verification service missing or disabled"
    fail=$((fail + 1))
fi

# 7.5 — dracut conf exists
if [ -f /etc/dracut.conf.d/noid-mei-blacklist.conf ]; then
    if grep -q 'install_items' /etc/dracut.conf.d/noid-mei-blacklist.conf; then
        if grep -qF '/etc/udev/rules.d/99-noid-mei-kt-block.rules' /etc/dracut.conf.d/noid-mei-blacklist.conf &&
           grep -qF '/usr/libexec/noid-mei-kt-enforce' /etc/dracut.conf.d/noid-mei-blacklist.conf; then
            echo "  [OK] dracut conf ships module config + KT/SOL enforcement"
        else
            echo "  [FAIL] dracut conf omits KT/SOL rule/helper"
            fail=$((fail + 1))
        fi
    else
        echo "  [FAIL] dracut conf missing install_items directive"
        fail=$((fail + 1))
    fi
else
    echo "  [FAIL] /etc/dracut.conf.d/noid-mei-blacklist.conf missing"
    fail=$((fail + 1))
fi

# 7.6 — Hardware-layer documentation shipped
if [ -f /usr/share/doc/noid-privacy/15-intel-me-hardware-layer.md ]; then
    echo "  [OK] Hardware-layer documentation shipped"
    # Verify experimental full-block section present
    if grep -q 'Experimental Full MEI Block' /usr/share/doc/noid-privacy/15-intel-me-hardware-layer.md; then
        echo "  [OK] Experimental full-block documentation section present"
    else
        echo "  [FAIL] Experimental full-block documentation section missing"
        fail=$((fail + 1))
    fi
else
    echo "  [FAIL] /usr/share/doc/noid-privacy/15-intel-me-hardware-layer.md missing"
    fail=$((fail + 1))
fi

# 7.6b — noid-mei-lockdown escape-hatch
if [ -x /usr/local/bin/noid-mei-lockdown ]; then
    echo "  [OK] /usr/local/bin/noid-mei-lockdown installed (experimental escape-hatch)"
else
    echo "  [FAIL] /usr/local/bin/noid-mei-lockdown missing"
    fail=$((fail + 1))
fi

# 7.6c — noid-mei-restore-submodules escape-hatch (should also be present)
if [ -x /usr/local/bin/noid-mei-restore-submodules ]; then
    echo "  [OK] /usr/local/bin/noid-mei-restore-submodules installed (submodule restore)"
else
    echo "  [FAIL] /usr/local/bin/noid-mei-restore-submodules missing"
    fail=$((fail + 1))
fi

# 7.6e — Step 5e firstboot vendor-detect service (verify covers script +
# service + enable-symlink)
if [ -x /usr/local/sbin/noid-cpu-vendor-detect.sh ]; then
    echo "  [OK] /usr/local/sbin/noid-cpu-vendor-detect.sh installed (Step 5e)"
else
    echo "  [FAIL] /usr/local/sbin/noid-cpu-vendor-detect.sh missing"
    fail=$((fail + 1))
fi
if [ -f /etc/systemd/system/noid-cpu-vendor-detect-firstboot.service ]; then
    echo "  [OK] noid-cpu-vendor-detect-firstboot.service unit installed"
else
    echo "  [FAIL] noid-cpu-vendor-detect-firstboot.service unit missing"
    fail=$((fail + 1))
fi
if [ -L /etc/systemd/system/multi-user.target.wants/noid-cpu-vendor-detect-firstboot.service ]; then
    echo "  [OK] noid-cpu-vendor-detect-firstboot.service enabled (multi-user.target.wants)"
else
    echo "  [FAIL] noid-cpu-vendor-detect-firstboot.service enable symlink missing"
    fail=$((fail + 1))
fi

# 7.7 — mei-status.txt written + noid-status consumes its schema
if [ -f /var/lib/noid-privacy/mei-status.txt ]; then
    if grep -qxF 'CPU_VENDOR=intel' /var/lib/noid-privacy/mei-status.txt \
       && grep -qxF 'STATUS_LIFECYCLE=build-time-placeholder' \
            /var/lib/noid-privacy/mei-status.txt \
       && grep -qxF 'MEI_STATE=build-time-unknown' \
            /var/lib/noid-privacy/mei-status.txt; then
        echo "  [OK] mei-status.txt carries the exact staged Intel lifecycle"
    else
        echo "  [FAIL] mei-status.txt has invalid staged Intel schema"
        fail=$((fail + 1))
    fi
else
    echo "  [FAIL] /var/lib/noid-privacy/mei-status.txt missing"
    fail=$((fail + 1))
fi

# Cross-ref: Module 13's diagnostic must parse the status schema.
if grep -q 'read_platform_status()' /usr/local/bin/noid-status && \
   grep -q 'MEI_KT_SOL_HOST_BINDING)' /usr/local/bin/noid-status; then
    echo "  [OK] noid-status parses the M15 platform-status schema"
else
    echo "  [FAIL] noid-status missing M15 platform-status consumer"
    fail=$((fail + 1))
fi

# 7.8 — Cross-reference Module 01 (IOMMU karg in kickstart bootloader directive)
# M01 uses the kickstart-level `bootloader --append=`
# which Anaconda processes during bootloader-install phase — runs AFTER %post.
# Old check looked at /etc/default/grub or BLS entries during %post, but those
# don't contain the karg yet at that timing → always WARN (cosmetic false-flag).
# New check verifies the kickstart source intent (which is what M01 ships).
IOMMU_KARG=""
case "$CPU_VENDOR" in
    intel) IOMMU_KARG="intel_iommu=on" ;;
    amd)   IOMMU_KARG="amd_iommu=on" ;;
    *)     IOMMU_KARG="" ;;
esac
if [ -n "$IOMMU_KARG" ]; then
    # M01 enforces via kickstart `bootloader --append=`. At %post time, the karg
    # may not yet be in /etc/default/grub or BLS — check both, accept either.
    # If neither is found, that's just timing — Anaconda will write it later.
    if grep -q "$IOMMU_KARG" /etc/default/grub 2>/dev/null || \
       grep -q "$IOMMU_KARG" /boot/loader/entries/*.conf 2>/dev/null; then
        echo "  [OK] Module 01 IOMMU cmdline present: $IOMMU_KARG (cross-ref)"
    else
        echo "  [INFO] $IOMMU_KARG not yet in /etc/default/grub or BLS — Anaconda bootloader-install will set it (cross-ref deferred)"
    fi
else
    echo "  [INFO] no IOMMU karg check — CPU_VENDOR=$CPU_VENDOR (cross-ref skipped)"
fi

# 7.9 — Explicit AMT/OOB boundary
# Intel AMT firmware traffic bypasses the host network stack. Do not present
# firewalld/nftables state as an AMT mitigation; the enforceable prerequisite
# is the firmware/hardware checklist shipped above.
echo "  [INFO] AMT OOB bypasses host firewall — verify UEFI/MEBx disablement and network-path checklist"

else  # non-Intel branch

# AMD / unknown: Intel mitigation files MUST be present (always-ship —
# inert no-op on AMD silicon). AMD doc MUST be present. `ccp` is not
# blacklisted because its crypto/RNG/fTPM roles are platform-dependent;
# loading it does not universally guarantee those functions or disable PSP.
# Escape-hatches shipped.

echo "  (build-host vendor=$CPU_VENDOR — Intel configs present-but-inert + AMD-specific checks:)"

# 7.0a (non-Intel mirror) — Kernel-level MEI availability check.
# Info-level. On AMD: mei modules irrelevant anyway, but
# regression-detection helps cross-vendor users understand current state.
KERNEL_CFG="/boot/config-$(uname -r)"
if [ -r "$KERNEL_CFG" ]; then
    if grep -qE '^# CONFIG_INTEL_MEI is not set' "$KERNEL_CFG"; then
        echo "  [INFO] Kernel $(uname -r) has CONFIG_INTEL_MEI=n —"
        echo "         no impact on $CPU_VENDOR target (mei modules N/A on this vendor)"
        echo "         Known-upstream-Fedora regression from 7.0.4 Dirty Frag rebase."
    elif grep -qE '^CONFIG_INTEL_MEI=[my]' "$KERNEL_CFG"; then
        echo "  [OK] Kernel $(uname -r) has CONFIG_INTEL_MEI enabled (no impact on $CPU_VENDOR)"
    fi
fi

# 7.A — Intel mitigation files MUST exist (always-ship — inert on non-Intel)
for f in /etc/modprobe.d/noid-mei-submodules.conf \
         /etc/udev/rules.d/99-noid-mei-kt-block.rules \
         /etc/dracut.conf.d/noid-mei-blacklist.conf \
         /usr/libexec/noid-mei-kt-enforce \
         /etc/systemd/system/noid-mei-kt-enforce.service; do
    if [ -f "$f" ]; then
        echo "  [OK] $f present (always-shipped, inert on $CPU_VENDOR silicon)"
    else
        echo "  [FAIL] $f missing — Steps 1-3 should always-ship since v6"
        fail=$((fail + 1))
    fi
done

# 7.B — Intel hardware-layer user doc MUST exist (always-ship — informational on non-Intel)
if [ -f /usr/share/doc/noid-privacy/15-intel-me-hardware-layer.md ]; then
    echo "  [OK] Intel hardware-layer doc present (always-shipped, informational on $CPU_VENDOR)"
else
    echo "  [FAIL] Intel hardware-layer doc missing — Step 4 should always-ship since v6"
    fail=$((fail + 1))
fi

# 7.C — AMD hardware-layer doc must be shipped
if [ -f /usr/share/doc/noid-privacy/15-amd-psp-hardware-layer.md ]; then
    echo "  [OK] AMD PSP hardware-layer doc shipped"
else
    echo "  [FAIL] /usr/share/doc/noid-privacy/15-amd-psp-hardware-layer.md missing"
    fail=$((fail + 1))
fi

# 7.D — ccp module NOT blacklisted (preserves platform services + fwupd data)
# Atomic `find -exec grep -l ... {} +` (analog 7.3).
if find /usr/lib/modprobe.d /etc/modprobe.d -name '*.conf' 2>/dev/null \
       -exec grep -l -E '^blacklist[[:space:]]+ccp$|^install[[:space:]]+ccp[[:space:]]+/bin/false$' {} + 2>/dev/null \
       | grep -q .; then
    echo "  [FAIL] ccp module blacklisted — removes fwupd PCI-PSP data and may break platform services"
    fail=$((fail + 1))
else
    echo "  [OK] ccp module NOT blacklisted (platform services + fwupd visibility preserved when supported)"
fi

# 7.E — CPU vendor state file present
if [ -f /var/lib/noid-privacy/cpu-vendor ]; then
    if grep -qE "^CPU_VENDOR=${CPU_VENDOR}$" /var/lib/noid-privacy/cpu-vendor; then
        echo "  [OK] /var/lib/noid-privacy/cpu-vendor has CPU_VENDOR=$CPU_VENDOR"
    else
        echo "  [FAIL] cpu-vendor file content mismatch"
        fail=$((fail + 1))
    fi
else
    echo "  [FAIL] /var/lib/noid-privacy/cpu-vendor missing"
    fail=$((fail + 1))
fi

# 7.F — mei-status.txt exists with vendor-appropriate content
if [ -f /var/lib/noid-privacy/mei-status.txt ]; then
    case "$CPU_VENDOR" in
        amd)
            if grep -qxF 'CPU_VENDOR=amd' /var/lib/noid-privacy/mei-status.txt \
               && grep -qxF 'STATUS_LIFECYCLE=build-time-placeholder' \
                    /var/lib/noid-privacy/mei-status.txt \
               && grep -qxF 'MEI_STATE=n/a-on-amd' \
                    /var/lib/noid-privacy/mei-status.txt \
               && grep -qxF 'PSP_STATE=runtime-check-required' \
                    /var/lib/noid-privacy/mei-status.txt; then
                echo "  [OK] mei-status.txt carries the exact staged AMD lifecycle"
            else
                echo "  [FAIL] mei-status.txt has invalid staged AMD schema"
                fail=$((fail + 1))
            fi
            ;;
        *)
            if grep -qxF 'CPU_VENDOR=unknown' \
                    /var/lib/noid-privacy/mei-status.txt \
               && grep -qxF 'STATUS_LIFECYCLE=build-time-placeholder' \
                    /var/lib/noid-privacy/mei-status.txt \
               && grep -qxF 'MEI_STATE=n/a' \
                    /var/lib/noid-privacy/mei-status.txt \
               && grep -qxF 'PSP_STATE=n/a' \
                    /var/lib/noid-privacy/mei-status.txt; then
                echo "  [OK] mei-status.txt carries the exact staged unknown-vendor lifecycle"
            else
                echo "  [FAIL] mei-status.txt has invalid staged unknown-vendor schema"
                fail=$((fail + 1))
            fi
            ;;
    esac
else
    echo "  [FAIL] /var/lib/noid-privacy/mei-status.txt missing"
    fail=$((fail + 1))
fi

# 7.H — Step 5e firstboot vendor-detect service (verify covers the non-Intel
# branch too; critical since build-host vs target-host vendor mismatch is
# the exact reason Step 5e exists)
if [ -x /usr/local/sbin/noid-cpu-vendor-detect.sh ]; then
    echo "  [OK] /usr/local/sbin/noid-cpu-vendor-detect.sh installed (Step 5e)"
else
    echo "  [FAIL] /usr/local/sbin/noid-cpu-vendor-detect.sh missing"
    fail=$((fail + 1))
fi
if [ -f /etc/systemd/system/noid-cpu-vendor-detect-firstboot.service ]; then
    echo "  [OK] noid-cpu-vendor-detect-firstboot.service unit installed"
else
    echo "  [FAIL] noid-cpu-vendor-detect-firstboot.service unit missing"
    fail=$((fail + 1))
fi
if [ -L /etc/systemd/system/multi-user.target.wants/noid-cpu-vendor-detect-firstboot.service ]; then
    echo "  [OK] noid-cpu-vendor-detect-firstboot.service enabled (multi-user.target.wants)"
else
    echo "  [FAIL] noid-cpu-vendor-detect-firstboot.service enable symlink missing"
    fail=$((fail + 1))
fi

fi  # end vendor-aware verification

if [ $fail -gt 0 ]; then
    echo ""
    echo "[Module 15] FAILED ($fail checks)"
    exit 1
fi

echo ""
echo "=============================================================="
echo "[Module 15] Done — all checks passed (CPU_VENDOR=$CPU_VENDOR)"
echo ""
if [ "$CPU_VENDOR" = "intel" ]; then
    echo "Intel layers active (v13 honest framing):"
    echo "  -    KT/SOL host-driver binding enforced + verified (27 listed IDs)"
    echo "       → does NOT disable firmware-owned AMT/SOL/KVM"
    echo "  -    mei + mei_me not blacklisted; fwupd visibility is platform-dependent"
    echo "  -    IOMMU VT-d translated domain (generic PCI DMA hardening, Module 01)"
    echo "  -    Secure Boot + lockdown=integrity (cross-ref Module 01)"
    echo "  -    dracut ships module config + KT/SOL rule/helper into initramfs"
    echo ""
    echo "Default: NO MEI sub-module blacklists (full Kicksecure-consensus per"
    echo "security-misc Issue #239). All three remain loadable when hardware requests them:"
    echo "  - mei_hdcp (Intel HDCP service interface)"
    echo "  - mei_pxp (Intel protected-content/PXP service interface)"
    echo "  - mei_wdt (iAMT OS-health watchdog interface where exposed)"
    echo "Opt-in block for any of the three:"
    echo "  sudo noid-mei-restore-submodules --block <hdcp|pxp|wdt>"
    echo ""
    echo "Required user-controlled AMT/OOB boundary (NOT active automatically):"
    echo "  - AMT fully unprovisioned and disabled in UEFI/MEBx"
    echo "  - All AMT-capable integrated wired/wireless links disabled or removed"
    echo "  - Non-AMT adapter used for the actual WAN link where practical"
    echo ""
    echo "User checklist: /usr/share/doc/noid-privacy/15-intel-me-hardware-layer.md"
elif [ "$CPU_VENDOR" = "amd" ]; then
    echo "AMD layers active (shared OS-level hardening):"
    echo "  -    ccp/PSP driver not blacklisted; fwupd visibility varies by platform"
    echo "  -    AMD-Vi requested with amd_iommu=on (verify runtime mappings)"
    echo "  -    Secure Boot + lockdown=integrity (cross-ref Module 01)"
    echo "  +    Service minimization (cross-ref Module 08)"
    echo ""
    echo "Layers N/A on AMD silicon:"
    echo "  - Intel KT/SOL PCI block (Intel-specific; not an AMD control)"
    echo "  - MEI submodule blacklist (mei_* modules don't exist on AMD;"
    echo "    Intel-side noid-mei-submodules.conf is inert on AMD silicon)"
    echo ""
    echo "Layers NOT active (hardware + user action required):"
    echo "  - Discrete PCIe NIC (non-onboard)"
    echo "  - Onboard NIC without cable (physical air-gap)"
    echo "  - Onboard NIC disabled in UEFI"
    echo "  - PSP Support toggle (vendor-dependent UEFI option, BIOS-mailbox-only)"
    echo "  - PSB: OEM-controlled OTP binding; change only with exact OEM procedure"
    echo ""
    echo "User checklist: /usr/share/doc/noid-privacy/15-amd-psp-hardware-layer.md"
else
    echo "Unknown CPU vendor ($CPU_VENDOR) — no firmware-layer mitigation"
    echo "applicable. Running on virtualized or exotic hardware."
    echo ""
    echo "Cross-Module hardening remains active:"
    echo "  - IOMMU (if supported by platform, cross-ref Module 01)"
    echo "  - Secure Boot Lockdown (cross-ref Module 01)"
    echo "  - Service minimization (cross-ref Module 08)"
fi
echo "=============================================================="

%end

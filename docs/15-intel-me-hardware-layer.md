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


# ==============================================================================
# Module 19 — NVIDIA + Secure Boot MOK Documentation + opt-in helper
# Status: LOCKED 2026-08-22 (v75) — correct exact-kmod repair semantics and diagnostics.
#
# Documentation-first NVIDIA delivery: NO NVIDIA firstboot service, NO driver
# package install at build, and NO kernel-cmdline/modprobe.d driver change at
# build. A post-Shell user-session service and two direct-launch wrappers may
# select GTK's supported GL renderer for future GTK applications on the exact
# portable non-NVIDIA-primary/NVIDIA-offload topology described below; they
# never install/select a GPU driver or enable background application activity.
#
# Covers:
#   - 19-nvidia-drivers.md (NVIDIA_DOC_EOF): Nouveau plus generation-supported
#     Mesa default rationale, per-generation driver matrix (main vs maintained
#     580xx), F44 Wayland package correctness (akmod-nvidia explicitly plus
#     xorg-x11-drv-nvidia-cuda for nvidia-smi; DNF necessarily resolves the
#     xorg-x11-drv-nvidia base driver), AIDE evidence/review integration,
#     switcheroo-control single-GPU opt-in mask, installer file-table,
#     LUKS-prompt/initramfs rationale, troubleshooting + rollback
#   - 19-secure-boot-mok.md (MOK_DOC_EOF): signature chain
#     (shim->grub->vmlinuz->modules), key-FIRST enrollment workflow,
#     6-step MokManager walkthrough, troubleshooting, why-not-automated
#   - Phase 3c: /usr/local/bin/noid-nvidia-install.sh (NVIDIA_INSTALL_EOF) —
#     trade-off matrix first, lspci codename detection (GB/AD/GA/TU ->
#     main, GV/GP/GM -> 580xx, GK/GF -> maintained-policy refusal), guarded
#     mixed-generation overrides, signing gates, early-KMS initramfs setup,
#     conservative laptop lid safety default, --dry-run/--force-branch/--rollback,
#     and boot-ID-bound post-reboot verification of the initial activation
#   - Phase 3b: exact portable NVIDIA-offload topology matcher, post-Shell
#     D-Bus/systemd activation environment, app-scoped GNOME Settings and
#     GNOME Software wrappers, an explicit Flatpak-store plugin scope, XDG
#     launcher + dnf5 self-healing action, and reversible auto/on/off GTK4 GL
#     policy; Mutter's native udev tag excludes only a connectorless dGPU
#     display node while preserving its application render node
#   - Phase 4: verification (docs present + perms + NO NVIDIA RPMs at build)
#
# Deliberate deviations (do NOT re-litigate):
#   - The Firefox HW-decode helper was REMOVED: its sole function
#     was MOZ_DISABLE_RDD_SANDBOX=1, which disables the media-decoder sandbox
#     (Mozilla flags this as a major security risk) — inappropriate for a
#     hardened image. Intel/AMD retain their vendor VA-API paths; Nouveau may
#     use only profiles exposed by its active Mesa/firmware combination. A bare
#     NVIDIA PCI identity never justifies an automatic Freeworld swap. Do not
#     re-add the sandbox bypass.
#   - NEVER add the redundant nvidia-drm.modeset=1 kernel arg: KMS is the
#     maintained module default. Keep one canonical boot policy instead of
#     carrying an unmanaged duplicate. The modeset sysfs param is root-only
#     (0400) — read it via sudo or the check always-fails as the user.
#   - nvidia-in-initramfs is the NoID Privacy default, overriding RPM Fusion's
#     simpledrm-only advice. On an encrypted-root machine whose boot display
#     routes through NVIDIA, the prompt may fail to re-render after the
#     simpledrm->KMS handover. The managed early-KMS path covers that measured
#     compatibility case; plymouth.use-simpledrm=1 (M01) remains the early
#     framebuffer path and fallback.
#   - Kepler/Fermi installs are REFUSED (proprietary branches are EOL and
#     outside the maintained-driver policy; compatibility is not assured).
#
# Constraint notes (keep when editing):
#   - Signing ORDER is load-bearing: install akmods + kmodgenca BEFORE
#     akmod-nvidia. brp-kmodsign signs only if the key exists at %posttrans
#     build time; an unsigned .ko is rejected by module.sig_enforce=1. Do not
#     promise nouveau fallback or GDM success while the RPM blacklist is active.
#   - The akmod package's native `%posttrans` starts the initial build in the
#     background, and every akmods invocation serializes on
#     /run/akmods/akmods.lock. The installer waits on that vendor lock and then
#     runs plain branch-scoped akmods: an already-current native result is not
#     rebuilt. Only a failed artifact/integrity gate gets one serialized
#     branch-scoped `akmods --rebuild --force` repair attempt. akmods can still
#     exit 0 when an individual module build FAILS. The authoritative gate
#     rejects fresh failed logs and binds all four module files to the
#     running/target kernel, selected branch, kmod/userspace EVR and exact
#     akmods certificate serial. A non-empty sig_id is insufficient.
#   - kernel-install hooks run INSIDE the rpm %posttrans (rpmdb lock held);
#     the durable queue writes a persistent task, synchronously acquires a
#     shutdown/sleep inhibitor, then starts a unique post-transaction worker.
#     Workers serialize, preserve the prior image until a candidate verifies,
#     publish a ready artifact and resume pending work after power loss. Offline
#     updates are queued before their reboot rather than deferred past it.
#   - Driver-only updates (same kernel) are covered by the dnf5 actions hook
#     (libdnf5-plugin-actions, M26) — the kernel-install hook only fires on
#     kernel changes. M25's process/lock-bound update-window validator skips
#     both hooks only while the exact noid-update-all process still owns its
#     workflow lock (M25 then runs the canonical M21 regenerator under the
#     shared lock and explicitly waits on this queue for exact NVIDIA
#     freshness/enrollment evidence). Mere marker existence is never trusted.
#   - The queue accepts exactly one installed kernel release or exactly
#     `--resume`. Unknown options, extra arguments, unsafe kernel payloads and
#     malformed/misowned markers are rejected before state, inhibitor, worker
#     or desktop-notification publication.
#   - The dracut conf adds nvidia CONDITIONALLY (module built for target
#     $kernel; empty $kernel = fail-safe on) so a brand-new kernel's 50-dracut
#     does not E-FAIL before akmods has built.
#   - F44 rpmdb is SQLite-WAL in a root-only dir: unprivileged `rpm -q`
#     intermittently fails ("attempt to write a readonly database") — every
#     rpm query in the helpers runs via sudo; the WAL-immune /sys + lspci
#     checks run FIRST so non-NVIDIA systems short-circuit without a sudo
#     prompt.
#   - rpmfusion-nonfree-nvidia-driver enable-flip uses a SECTION-AWARE sed
#     (/^\[section\]$/,/^\[/) — a blanket enabled=0->1 sed also flips the
#     -debuginfo + -source subrepos, which must stay enabled=0 (see M08).
#   - dnf installs pass --setopt=install_weak_deps=False explicitly (defense
#     against a user-modified /etc/dnf/dnf.conf).
#   - sudo combines the invoking user's umask with its policy umask unless
#     umask_override is enabled. The interactive 0027 policy must therefore
#     never reach DNF/akmods/depmod: their public system metadata is generated
#     through a command-local 0022 wrapper. MOK/state secrets retain explicit
#     restrictive modes; the global shell and sudo policies stay unchanged.
#   - M17 owns both the general, user-adjustable GNOME idle auto-suspend default
#     and the independent explicit lid-action choice for every GPU. The NVIDIA
#     helper neither overwrites nor removes either user choice. Repeated local
#     failures and public NVIDIA suspend/resume reports justify only a
#     kernel-SW_LID-gated lower logind default that makes lid close lock instead
#     of suspend. Its own file is removed by --rollback and remains non-fatal;
#     M17's lexically later explicit choice survives. This does NOT prove every
#     NVIDIA GPU is defective. Trade-off: no automatic lid-close sleep while
#     the compatibility default is effective.
#   - The GTK4 GL workaround is automatic only on portable systems with one
#     Intel/AMD boot VGA plus a non-primary NVIDIA GPU under runtime PM. The
#     hardware match is driver-agnostic (Nouveau/Mesa or proprietary), while
#     Intel-only, AMD-only, NVIDIA-only and NVIDIA-primary/MUX paths retain
#     GTK's maintained default. Automatic session propagation happens only
#     after GNOME Shell starts, so the compositor never inherits the override
#     and can leave the offload dGPU suspended. GNOME Software's existing
#     background-service mask is untouched: its wrapper handles explicit
#     launches only. An administrator-set GSK_RENDERER wins, and an explicit
#     `off` disables the managed automation. NVIDIA install/rollback never owns
#     this independent policy. The post-Shell user unit keeps only the enforced
#     AF_UNIX socket allowlist; it does not claim a private network namespace
#     that an unprivileged user manager may be unable to create.
#   - The post-boot service does not re-read shim's MokListRT through mokutil.
#     On the reference kernel, that sysfs read requires CAP_SYS_ADMIN; mokutil
#     0.7.2 spins on the resulting zero-length read when the capability is
#     deliberately absent. Granting the broad capability to this root service
#     is unnecessary. The reboot gate instead binds the prepared exact
#     initramfs, exact signed on-disk module set, matching live GNU build IDs,
#     immutable signature enforcement and successful loaded-driver use. Direct
#     installer/update paths retain the explicit MOK enrollment check before
#     approving an image for a future boot.
#   - tests/19-nvidia-install.sh asserts dozens of fixed strings inside the
#     installer heredoc (deployed bytes) + the 'Phase 3c' heading in this
#     file; tests/19-nvidia-mok-docs asserts the %post section above the
#     first heredoc never installs akmod packages.
#
# Cross-reference:
#   - M01: lockdown=integrity + module.sig_enforce=1 + plymouth.use-simpledrm
#     + install_weak_deps=False. M08: rpmfusion-nonfree repo (enabled=0
#     default; helper flips the -driver repo only). M25: update orchestrator
#     rebuild path + sig gate. M26: libdnf5-plugin-actions.
#
# Package modifications: dbus-tools — required by the post-Shell GTK session
# activation helper; M41 preserves its explicit user reason before autoremove.
# ==============================================================================

%packages --exclude-weakdeps
dbus-tools
%end

%post --log=/var/log/ks-19-nvidia-mok-docs.log --erroronfail
# ==============================================================================
# Module 19 — Hardware Documentation (%post)
# ==============================================================================
set -e
set -o pipefail

PHASE=""

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [M19] ${PHASE}: $*"; }
die() { log "FAIL: $*"; exit 1; }

log "=== Module 19 Hardware Documentation start ==="

# ------------------------------------------------------------------------------
# Phase 1 — Ensure doc directory
# ------------------------------------------------------------------------------
PHASE="P1-setup"
log "Creating /usr/share/doc/noid-privacy/"

mkdir -p /usr/share/doc/noid-privacy

# ------------------------------------------------------------------------------
# Phase 2 — Write 19-nvidia-drivers.md
# ------------------------------------------------------------------------------
PHASE="P2-nvidia-doc"
log "Writing 19-nvidia-drivers.md"

cat > /usr/share/doc/noid-privacy/19-nvidia-drivers.md <<'NVIDIA_DOC_EOF'
# NVIDIA Driver Guide — NoID Privacy Workstation

This image ships with the in-tree **Nouveau** kernel driver and Mesa's
generation-supported NVIDIA userspace as its default stack. Mesa documents
NVK Vulkan support for Kepler and newer GPUs; older GPUs retain their
generation-supported Nouveau/Mesa interfaces without a Vulkan promise. No
proprietary driver is installed automatically. This document explains your
options if you want to opt into the proprietary driver.

## Default Behavior

On first boot, your NVIDIA GPU (if present) uses the **in-tree Nouveau**
kernel driver. Kepler and newer GPUs can use **NVK**, Mesa's modern NVIDIA
Vulkan driver. Exact feature support remains generation- and version-specific.

Nouveau and NVK are actively maintained components of the upstream Linux and
Mesa graphics stacks. Exact feature support and performance depend on the GPU
generation, firmware, kernel, Mesa version, workload, display topology, and
power-management state; this guide intentionally does not promise benchmark
parity with NVIDIA's driver.

### What you get with Nouveau + generation-supported Mesa drivers (2026)

| Use case | In-tree/Mesa boundary |
|---|---|
| GNOME desktop and browser rendering | Supported; validate acceleration and stability on the actual GPU |
| Video decode/encode | Codec, firmware, generation, and Mesa-driver dependent; no universal 4K/HDR guarantee |
| Vulkan/OpenGL games | Supported feature set and frame rate are game- and generation-dependent |
| CUDA applications | NVIDIA's CUDA stack requires NVIDIA's userspace driver |
| NVIDIA-specific DLSS/NVENC/G-Sync features | Use the NVIDIA driver when the application explicitly requires them |

**Bottom line**: stay with the in-tree default unless a tested workload or a
required NVIDIA-specific interface gives you a concrete reason to opt in.

## GTK4 launch stall on a runtime-suspended hybrid dGPU

GTK 4.16 and newer normally select the Vulkan GSK renderer on Wayland. On a
portable hybrid system, NVIDIA Vulkan ICD discovery can wake a runtime-suspended
offload GPU even when the application renders on the integrated GPU. A
2026-07-27 recheck on the Fedora 44 reference hybrid used GTK 4.22.4 and three
fresh, standalone Text Editor 50.1 processes from an initially suspended dGPU.
The native Vulkan path reached its first Wayland surface in 2.283–2.401 seconds
and woke the dGPU; GTK's supported GL renderer took 0.201–0.276 seconds and
left it `suspended`.

NoID Privacy therefore selects GTK's supported GL renderer automatically for
future systemd/D-Bus-activated GTK applications only when all conservative
hardware facts match: a portable chassis, exactly one Intel/AMD boot VGA, and
a separate non-primary NVIDIA GPU managed by PCI runtime PM. GNOME Settings and
explicit GNOME Software launches use narrow wrappers because GNOME Shell starts
those paths directly. This PCI-topology rule covers both Nouveau/Mesa and the
proprietary driver. It does **not** match Intel-only, AMD-only, NVIDIA-only or
NVIDIA-primary/MUX systems.

This selects only GTK 4's GSK renderer backend; it does not select a physical
GPU. The automatic helper and both wrappers never set `DRI_PRIME`,
`__NV_PRIME_RENDER_OFFLOAD`, `__GLX_VENDOR_LIBRARY_NAME`,
`__VK_LAYER_NV_optimus` or `VK_LOADER_DRIVERS_SELECT`. GNOME's native
switcheroo-control path therefore remains authoritative for
**Launch Using Discrete Graphics Card**, and applications that deliberately
request the dGPU retain the NVIDIA OpenGL/Vulkan offload environment. Non-GTK
renderers ignore `GSK_RENDERER`: Steam/Proton games, Godot's Vulkan/OpenGL rendering drivers and
the Android Emulator's own `-gpu` mode are not redirected to the iGPU or to
software rendering by this policy. A GTK launcher surface may use GSK GL, but
that does not change the launched workload's GPU selection.

GTK documents renderer environment variables as debugging controls rather than
stable end-user configuration. A login-wide automatic override also caused
GNOME Shell to retain a proprietary-driver dGPU context and prevent deep
runtime suspend. The automatic one-shot therefore waits until GNOME Shell is
already running, then updates only the user manager and D-Bus activation
environment. GNOME Shell never inherits `GSK_RENDERER`. Inspect the policy,
force GL login-wide as an explicit diagnostic opt-in, disable the automatic
rule, or return to topology-based selection with:

```bash
noid-toggle-gsk-gl status
sudo noid-toggle-gsk-gl on
sudo noid-toggle-gsk-gl off
sudo noid-toggle-gsk-gl auto
```

Policy changes take effect after a complete logout/login; close already running
applications before comparing launch times. The exact value is `gl`, not the
deprecated `ngl` alias. Manual `on` remains login-wide and can keep an offload
dGPU awake. If applications hang, render incorrectly, or battery use increases,
return to the post-Shell automatic policy:

```bash
sudo noid-toggle-gsk-gl auto
```

The one-shot needs only the session's local Unix sockets. Its systemd sandbox
therefore enforces `RestrictAddressFamilies=AF_UNIX`; it deliberately does not
claim `PrivateNetwork=yes`, because a user service manager may be unable to
create that namespace and systemd then continues without it.

`off` writes only NoID Privacy's managed application-policy marker; `auto`
removes only that exact marker. A separately managed `GSK_RENDERER` value or
policy file is never overwritten. The installer migrates the exact legacy
vendor-generator mask to the equivalent `off` state and removes the retired
vendor generator.

The system XDG launcher shadows only the same vendor desktop-file ID, retains
the current Fedora launcher fields and translations, and sets
`DBusActivatable=false` so the standardized `Exec` path reaches the wrapper.
A dnf5 post-transaction action regenerates that launcher after
`gnome-control-center` updates. This avoids a duplicate D-Bus service name.
A user launcher under `$XDG_DATA_HOME` still has higher precedence.

The normal GNOME Software launcher stays on the explicit Flatpak-only plugin scope.
This module may select only its GTK renderer.
Fedora-RPM one-shot is a separate named launch path. It adds GNOME Software's
`appstream` and `dnf5` plugins for that process without persisting the choice.
Neither path unmasks or enables
`gnome-software.service`, a timer, unattended installation or telemetry. The
NoID Privacy silent-machine and explicit-launch-only contracts remain unchanged.

Manual `on` uses a host `/etc/environment.d` setting and does not cross the
Flatpak sandbox boundary. Apply the same opt-in only to a specifically affected
Flatpak application, and reverse it with:

```bash
flatpak override --user --env=GSK_RENDERER=gl APP_ID
flatpak override --user --unset-env=GSK_RENDERER APP_ID
```

Known-issue references: [GTK renderer selection](https://docs.gtk.org/gtk4/running.html),
[Desktop Entry precedence and activation](https://specifications.freedesktop.org/desktop-entry/latest-single/),
[D-Bus activation environment](https://dbus.freedesktop.org/doc/dbus-update-activation-environment.1.html),
[NVIDIA runtime D3](https://download.nvidia.com/XFree86/Linux-x86_64/580.173.02/README/dynamicpowermanagement.html),
the [NVIDIA switcheroo-control workflow](https://docs.nvidia.com/datacenter/tesla/driver-installation-guide/optimus-laptops-and-multi-gpu-desktop-systems.html),
the [Android Emulator acceleration modes](https://developer.android.com/studio/run/emulator-acceleration),
the [Godot renderer overview](https://docs.godotengine.org/en/stable/tutorials/rendering/renderers.html)
and the [Vulkan loader driver interface](https://github.com/KhronosGroup/Vulkan-Loader/blob/main/docs/LoaderDriverInterface.md).
Remove the automatic workaround when the NVIDIA ICD/device-enumeration path is
fixed and verified on the affected topology; a GTK version change alone is not
proof.

## First-pointer stall on a connectorless offload GPU

Mutter normally enumerates every DRM primary node as a possible display GPU.
On the reference hybrid laptop, the NVIDIA `cardN` node has no connector,
encoder, CRTC or plane because every display is wired to the Intel GPU. Mutter
nevertheless admits that node and creates its renderer data during compositor
initialization. The first focused cursor lazily creates Mutter's native cursor
renderer, which then probes hardware-cursor support for every admitted GPU and
discovers that this node has no cursor plane. That unnecessary all-GPU cursor
probe caused the reproducible first-pointer pause; the ELAN touchpad itself had
already initialized before GDM.

NoID Privacy uses Mutter's maintained `mutter-device-ignore` udev tag only when
a stricter hardware match succeeds: portable chassis, one Intel/AMD boot GPU
with an internal panel, a separate runtime-managed NVIDIA GPU, a render node
for that GPU, and zero connector objects on its primary node. A dGPU with even
one wired connector, a primary/MUX NVIDIA GPU, a desktop, or an incomplete
topology is left unchanged. The rule applies to Nouveau and the proprietary
driver because it identifies PCI/DRM topology rather than a driver name.

Only the NVIDIA `cardN` KMS node receives the Mutter-specific tag. Its
`renderD*` node, device permissions, switcheroo-control tag and driver
configuration remain unchanged. Games, CUDA, Godot and the Android Emulator can
therefore continue to open the render node and use GNOME's normal
**Launch Using Discrete Graphics Card** environment; the compositor merely stops
treating a GPU with no display pipeline as a display GPU. Administrators can
mask the vendor rule with an identically named
`/etc/udev/rules.d/62-noid-mutter-headless-offload.rules`
symlink to `/dev/null`. Apply either state at the next complete logout/login or
reboot.

This remains necessary in Fedora's Mutter 50.3 source and in upstream
`main` at commit `a413815cd408495903e20d69bf7c490698deab20` (2026-07-28):
both still admit every seat DRM primary node unless
`mutter-device-ignore` is present, and both initialize cursor support across
all admitted GPUs. Remove the rule only after the installed Mutter source
rejects this connectorless offload node natively and a logout/login A/B test on
the affected topology confirms that the first-pointer pause does not return.

## Should you install the proprietary driver?

**Do not install it speculatively.** The cost (MOK enrollment, an out-of-tree
module build, proprietary userspace, and ongoing kernel-update maintenance) is
only justified by a concrete workload. The old Firefox helper that disabled the
RDD media sandbox is deliberately not shipped; proprietary NVIDIA video decode
is therefore not promised by this setup.

### Install proprietary ONLY if you need one of these

- **CUDA** — ML training, AI inference, scientific compute
- **DLSS** — Deep Learning Super Sampling (AAA gaming upscaling)
- **A game whose measured performance or ray-tracing path requires the NVIDIA stack**
- **NVENC** — hardware-accelerated video encoding (streaming/rendering)
- **G-Sync + HDR** — high-end multi-monitor gaming setups

### Do NOT install proprietary if

- You just want a working desktop (nouveau is fine)
- You browse the web, watch videos, do office work (the in-tree/Mesa path is fine)
- You prefer the kernel's in-tree driver maintenance/review path and do not need NVIDIA-specific interfaces
- You want the in-tree driver lifecycle (proprietary akmod rebuilds add delay and AIDE drift that must be reviewed)
- You have a pre-Maxwell GPU (old proprietary branches are outside this image's maintained-driver policy; Kepler remains on Nouveau/NVK)

### The cost if you do install

- **One activation reboot** when the exact akmods MOK is already enrolled;
  a new enrollment adds the MokManager reboot and its follow-up boot
- **Manual MokManager navigation for a new key** — skipping it leaves the key
  unenrolled and the NVIDIA activation unverified
- **Ongoing maintenance** — akmods rebuilds the module on every kernel update; AIDE reports the changed `.ko` files until the user reviews trust state
- **Black-screen risk** if MokManager blue screen is skipped or mis-navigated (recovery via Ctrl+Alt+F3 TTY + rollback)

Time varies with package download, module compilation, firmware UI, and the
machine. Do not start immediately before you need the system.

## Per-Generation Driver Matrix (2026 best practice)

### Modern Generations (Current RPM Fusion main branch)

| Generation | Codenames | Example GPUs | Best 2026 Choice |
|---|---|---|---|
| **Blackwell** (2025) | GB* | RTX 5090, 5080, 5070 | `akmod-nvidia` (current RPM Fusion main branch, open kernel module) |
| **Ada Lovelace** (2022) | AD* | RTX 4090, 4080, 4070, 4060 | `akmod-nvidia` (current RPM Fusion main branch, open kernel module) |
| **Ampere** (2020) | GA* | RTX 3090, 3080, 3070, 3060, 3050 | `akmod-nvidia` (current RPM Fusion main branch, open kernel module) |
| **Turing** (2018) | TU* | RTX 2080 Ti-2060, GTX 1660/1650 Super | `akmod-nvidia` (current RPM Fusion main branch, open kernel module) |

**Install command (Fedora 44 GNOME Wayland session)**:
```bash
sudo dnf install akmod-nvidia xorg-x11-drv-nvidia-cuda
```

Package notes (corrected for F44 + NoID Privacy `install_weak_deps=False`):

- **`akmod-nvidia`** — kernel-module build package; DNF resolves its exact
  driver/userspace dependencies from the enabled RPM Fusion repositories. That
  includes the base `xorg-x11-drv-nvidia` package through its
  `nvidia-kmod-common` capability; the historical package name does not make it
  an optional X11-session-only component.
- **`xorg-x11-drv-nvidia-cuda`** — misleadingly named: despite "xorg-x11",
  this is the CUDA + userspace utilities package (provides `nvidia-smi`).
  GNOME 50 on F44 has no X11 session — but you still need this package
  because `nvidia-smi` is required for the verification steps.
- Optional: `nvidia-settings` — GUI config panel (Wayland-compatible in
  the supported driver). Install separately if you want a GUI; not required by
  this helper.

For Blackwell/Ada/Ampere/Turing, current NVIDIA releases provide open
kernel-module source. The userspace components remain proprietary. Verify the
actually installed module/package; do not infer it merely from a branch number.

### Maxwell/Pascal/Volta (maintained R580 branch)

NVIDIA's post-R580 branches dropped support for Maxwell, Pascal, and Volta.
These generations therefore use the separate 580.xx branch. NVIDIA's support
commitment is product-specific: GeForce products have received critical
security-only updates since October 2025 through October 2028; NVIDIA's
February 2026 Quadro plan describes one year of full R580 support followed by
critical security updates through October 2028. NVIDIA's CUDA guidance calls
R580 the final pre-Turing-capable LTS branch and gives it a June 2028 lifecycle.
The package choice below is the same, but the guide does not collapse those
different commitments into one universal label.

R580's upstream supported-products list also contains specific
Turing/Ampere/Ada products. That overlap can cover a reviewed mixed system,
but only after every exact PCI product is checked; generation prefixes alone
are insufficient. Blackwell is different: NVIDIA requires the open kernel
module there, while the legacy-capable R580 package uses the proprietary
module flavor needed by Maxwell/Pascal/Volta. The helper therefore never
accepts a Blackwell-plus-legacy proprietary plan.

| Generation | Codenames | Example GPUs | Best 2026 Choice |
|---|---|---|---|
| **Volta** (2017) | GV* | Titan V, Quadro GV100 | `akmod-nvidia-580xx` (maintained R580) OR NVK |
| **Pascal** (2016) | GP* | GTX 1080 Ti, 1080, 1070, 1060, 1050 Ti | `akmod-nvidia-580xx` (maintained R580) OR NVK |
| **Maxwell** (2014) | GM* | GTX 980 Ti, 980, 970, 960, 750 Ti | **NVK recommended** (no GSP firmware) |

**Install command for Maxwell/Pascal/Volta (F44 Wayland-only)**:
```bash
sudo dnf install akmod-nvidia-580xx xorg-x11-drv-nvidia-580xx-cuda
```

(The branch-matched `-580xx-cuda` package supplies the utilities used by the
verification steps. Do not mix it with the unversioned main-branch CUDA package.)

**For Maxwell**: We recommend staying on NVK (already default). The 580.xx
branch cannot use NVIDIA's open kernel module; NVIDIA documents the proprietary
kernel-module flavor as required for Maxwell, Pascal, and Volta. If you need
proprietary on Maxwell for a specific workload, the command is the same as
Pascal/Volta.

### Deprecated Generations (NOT recommended, 2026 EOL status)

| Generation | Codenames | Status | Our Recommendation |
|---|---|---|---|
| **Kepler** (2012-2014) | GK* | 470 is NVIDIA's last proprietary branch; outside this image's maintained-driver policy | **Nouveau + NVK** |
| **Fermi** (2010-2011) | GF* | 390 is the legacy branch; outside this image's maintained-driver policy | **Nouveau only** |
| **Tesla 2.0** (2006-2008) | G8x/G9x/GT2xx | No driver branch accepted by this helper | **Nouveau only** |
| **Pre-Tesla** (2000-2005) | NV30/NV40 | No modern proprietary support | **Nouveau + alternative DE** (GNOME 50 is Wayland-only; consider Kicksecure/XFCE if you need X11) |

**Do NOT install proprietary drivers for Kepler/Fermi/Tesla on this image.**
These old branches do not meet this image's maintained-driver policy. Whether a
distribution patch happens to compile them for one kernel does not restore a
current vendor support commitment, so the helper refuses them.

`noid-nvidia-install.sh` refuses install on Kepler and Fermi to enforce this.

## Detecting your GPU

```bash
lspci -nn | grep -iE 'VGA|3D|Display' | grep -i NVIDIA
```

Example output:
```
01:00.0 VGA compatible controller [0300]: NVIDIA Corporation GA107 [GeForce RTX xxxx] [10de:xxxx] (rev a1)
```

The **codename** is the part like `GB202` (Blackwell), `GA107` (Ampere),
`AD103` (Ada), `TU116` (Turing), or `GV100` (Volta). Match the first two
letters (`GB`, `AD`, `GA`, `TU`, `GV`, `GP`, `GM`, `GK`, `GF`) to the tables
above to determine your generation.

## Harmless nouveau boot message

On nouveau-driven Turing/Ampere and newer GPUs the journal may show, once per
boot, a line like "nouveau 0000:NN:00.0: gsp: failed to create debugfs root".
With NoID Privacy's `debugfs=off` flag, failure to create a debugfs entry is expected.
If graphics are otherwise working, that line alone is not evidence of a driver
failure; investigate it together with real display/rendering symptoms.

## After installing the proprietary driver

1. **Reboot**. Your system will show the blue MokManager screen (if MOK
   enrollment was triggered). See `19-secure-boot-mok.md` for the MOK
   enrollment walkthrough.
2. **Verify kernel module loaded**: `lsmod | grep nvidia` should show
   `nvidia`, `nvidia_drm`, `nvidia_modeset`, `nvidia_uvm`.
3. **Verify version**: `modinfo -F version nvidia`
4. **Test**: `nvidia-smi` should show your GPU with driver version.

## Updates

When the user explicitly runs `noid-update-all.sh`, its DNF phase updates the
enabled NVIDIA repository and packages and verifies/rebuilds the module and
initramfs. The weekly timer is a reminder only; it does not install updates.

## AIDE integration

After installing the proprietary driver, AIDE (filesystem intrusion
detection, Module 13) will flag newly created files as "added" on the next
scan:

- `/usr/lib/modules/*/extra/nvidia/*.ko.xz`
- `/etc/dracut.conf.d/99-noid-nvidia-initramfs.conf`
- `/etc/kernel/install.d/95-noid-nvidia-initramfs.install`
- `/usr/libexec/noid-nvidia-initramfs-rebuild`
- `/usr/libexec/noid-nvidia-initramfs-queue`
- `/usr/libexec/noid-nvidia-reboot-guard`
- `/usr/libexec/noid-nvidia-verify`
- `/usr/libexec/noid-nvidia-rebind-evidence`
- `/usr/libexec/noid-nvidia-initramfs-dnf-action`
- `/usr/libexec/noid-nvidia-postboot-verify`
- `/etc/systemd/system/noid-nvidia-reboot-guard.service`
- `/etc/systemd/system/noid-nvidia-initramfs-resume.service`
- `/etc/systemd/system/noid-nvidia-postboot-verify.service`
- `/etc/dnf/libdnf5-plugins/actions.d/noid-nvidia-initramfs.actions`
- `/var/lib/noid-nvidia-integrity/`
- `/etc/systemd/logind.conf.d/99-noid-nvidia-lid.conf` (laptops only)

These paths are plausible consequences of the reviewed driver workflow, but
the actual report still must be checked against the RPM transaction, package
signatures and installed files. The updater preserves this drift. If the user
deliberately chooses a new AIDE trust boundary, prepare a separate candidate:

```bash
sudo noid-aide-baseline-review prepare
# Review the candidate report and metadata yourself, then use the tool's
# exact SHA-256 commit flow. Never copy aide.db.new.gz into place directly.
```

`noid-update-all.sh` runs a check against an existing baseline after its DNF
transaction; it never accepts the result or replaces the database. The reminder
timer never installs updates or changes AIDE trust state.

Every subsequent kernel update produces the same pattern: `akmods` rebuilds
the NVIDIA module against the new kernel, and AIDE can report the new module
file in `/usr/lib/modules/<new-kernel>/extra/nvidia/`. That report remains
evidence until the user reviews it.

## Debug-kernel boundary

The image does not install Fedora's separate `kernel-debug*` flavor, and this
helper supports only the kernel that is currently running plus its exact
matching `kernel-devel-$(uname -r)` build tree. It does not claim that a debug
kernel inherently conflicts with akmods, and it does not prepare an unbooted
debug-kernel entry. If you deliberately boot another kernel flavor, treat it
as outside this helper's verified activation path and establish its matching
devel tree, module, signature and initramfs evidence before relying on it.

## Hybrid GPU (Intel+NVIDIA or AMD+NVIDIA laptops)

NoID Privacy ships `switcheroo-control` enabled by default, so on a hybrid
system (e.g. a laptop with Intel UHD + NVIDIA dGPU) GNOME's right-click menu
on app icons already shows "Launch Using Discrete Graphics Card" for selectively using
the NVIDIA GPU — no action needed.

(If you previously masked it via the single-GPU opt-in below, undo that with
`sudo systemctl unmask switcheroo-control.service`, followed by
`sudo systemctl enable --now switcheroo-control.service`.)

### Single-GPU systems — opt-in masking

NoID Privacy ships `switcheroo-control` enabled by default for hybrid-laptop
compatibility. On a single-GPU desktop/workstation (one GPU connected to
displays, regardless of how many cards are physically present — for example
a system with NVIDIA dGPU as primary + Intel iGPU with no outputs), the
service has no functional purpose and can still be disabled as a policy choice.
Module 08 already applies the project hardening for the service; this opt-in is
therefore only about removing an unnecessary active service after the real
topology has been verified.

To mask it:

```bash
# Verify single-GPU first — if both lspci lines below show DRM cards
# AND both have outputs, you have hybrid graphics and should NOT mask.
lspci -nn | grep -E 'VGA|3D|Display'

# Check which DRM cards have connectors with displays attached:
for c in /sys/class/drm/card?-*; do
    [ -f "$c/status" ] || continue
    s=$(cat "$c/status" 2>/dev/null)
    [ "$s" = "connected" ] && echo "ACTIVE: $(basename "$c")"
done

# If only ONE DRM card shows ACTIVE outputs → safe to mask:
sudo systemctl disable --now switcheroo-control.service
sudo systemctl mask switcheroo-control.service
```

Reverse later with `sudo systemctl unmask switcheroo-control` followed by
`sudo systemctl enable --now switcheroo-control` (for example before using a
second GPU that needs the service).

## What the installer creates automatically

When you run `noid-nvidia-install.sh` (which drives `dnf install
akmod-nvidia` plus the NoID Privacy hooks), the following are put in place.

Two things are **not** done through NoID Privacy-owned `/etc/modprobe.d/`
files. The RPM Fusion transaction supplies the base
`xorg-x11-drv-nvidia` dependency and mutates the persistent BLS command line
for its nouveau blacklist; the helper invalidates, canonicalizes and reseals
that boot-argument evidence around the transaction. DRM modesetting is the
NVIDIA module's maintained default, so the helper creates no
`/etc/modprobe.d/nvidia.conf` either. The files that DO get created:

| File | Content | Purpose |
|---|---|---|
| `/usr/lib/dracut/dracut.conf.d/99-nvidia-dracut.conf` | `omit_drivers+=" nvidia … "` | Vendor-shipped (RPM Fusion). OMITS nvidia from initramfs by default. |
| `/etc/dracut.conf.d/99-noid-nvidia-initramfs.conf` | conditional `add_drivers+=" nvidia … "` | **NoID Privacy override** — makes nvidia-drm available in the initramfs so it can re-render an installer-selected encrypted-root prompt when the boot display needs the NVIDIA KMS handover. Unencrypted roots have no such prompt. Gated on the module being built for the target `$kernel`, so a brand-new kernel does not E-FAIL before akmods runs. Removed by `--rollback`. |
| `/etc/kernel/install.d/95-noid-nvidia-initramfs.install` | kernel-install hook | On a direct or offline `dnf install kernel-*`, writes a durable post-transaction task after kernel-install creates the stock recovery image. `akmods` runs only after the transaction releases the rpmdb lock. The hook skips during `noid-update-all.sh` because that orchestrator explicitly enters and waits on the same queue. Removed by `--rollback`. |
| `/usr/libexec/noid-nvidia-verify` | read-only integrity verifier | Requires the complete branch pair, matching akmod/CUDA/kmod EVR, the branch-required module flavor (`Dual MIT/GPL` main, `NVIDIA` R580), all four modules for the exact kernel and signatures made by the exact local akmods certificate; update workers also require that certificate to be enrolled. Removed by `--rollback`. |
| `/usr/libexec/noid-nvidia-rebind-evidence` | M21 evidence bridge | After M21 validates and atomically replaces a managed NVIDIA initramfs, re-verifies the current module/certificate identity and atomically rebinds an existing exact `ready` or `prepared` pre-reboot record to the newly published SHA-256. Historical `active` boot evidence is never rewritten. Removed by `--rollback`. |
| `/usr/libexec/noid-nvidia-postboot-verify` + `noid-nvidia-postboot-verify.service` | initial-activation verifier | After the required reboot, binds the prepared image and package identity to a different kernel boot ID, signature enforcement, exact live/disk GNU build IDs for all four loaded modules, NVIDIA PCI binding and an unprivileged `nvidia-smi` query. Together with the prepared image's exact signed-module byte checks, this verifies the runtime signed-module chain without granting the verifier `CAP_SYS_ADMIN` merely to re-read firmware MOK variables. A failed check publishes durable degraded evidence. Removed by `--rollback`. |
| `/usr/libexec/noid-nvidia-initramfs-queue` + `noid-nvidia-reboot-guard.service` | durable queue + inhibitor | Writes a unique persistent task before acquiring a block shutdown/sleep inhibitor and scheduling the worker. Failed tasks keep the inhibitor; boot-time resume handles power loss. Removed by `--rollback`. |
| `/usr/libexec/noid-nvidia-initramfs-rebuild` | serialized worker | Rejects fresh akmods failures and stale/mismatched modules, then delegates candidate construction and complete Root/LUKS/Plymouth/MEI/basis/NVIDIA validation to M21's canonical atomic regenerator before publishing a SHA-256-bound ready artifact. Removed by `--rollback`. |
| `/usr/libexec/noid-nvidia-initramfs-dnf-action` | dnf5 actions target | Fires on an `akmod-nvidia` driver-only update and enters the same durable inhibited queue. It skips during `noid-update-all.sh`, which explicitly enters and waits on that queue. Removed by `--rollback`. |
| `/etc/dnf/libdnf5-plugins/actions.d/noid-nvidia-initramfs.actions` | dnf5 actions rule | `post_transaction:akmod-nvidia:in:enabled=host-only raise_error=1:` → the wrapper above. Covers driver-only host updates on the same kernel via any dnf path without mutating the host during installroot transactions (the kernel-install hook only covers kernel changes). Needs `libdnf5-plugin-actions` (M26). Removed by `--rollback`. |
| `/etc/systemd/logind.conf.d/99-noid-nvidia-lid.conf` (kernel `SW_LID` only) | `HandleLidSwitch=lock` + `HandleLidSwitchExternalPower=lock` | **NoID Privacy compatibility default** — lid-close locks instead of entering an unobserved suspend path. This lower conditional override replaces systemd's vendor lid default only when the kernel exposes a real lid switch. M17's explicit user choice has later precedence and is never touched. Removed by `--rollback`. |

You do **not** need to create or modify these files manually. They are
listed here for verification.

### Why the NVIDIA workflow changes the lid-close default

The base image already defaults GNOME idle auto-suspend to off for uninterrupted
local agent workflows. That general policy is not locked: each user can enable
Automatic Suspend independently for AC or battery in Settings → Power. The
NVIDIA helper neither writes nor removes those dconf values, so installing or
rolling back a GPU driver cannot overwrite that user choice.

Repeated local suspend/resume failures made an unattended NVIDIA lid-close
suspend too costly as an installation default, and public reports show failures
across multiple GPUs, driver branches, kernels and desktops. NVIDIA's own power-
management guide also describes two different suspend mechanisms, platform/GPU
requirements for s2idle and workload-dependent video-memory preservation.

The kernel-lid-only policy is a conservative compatibility decision, not proof
that every NVIDIA GPU fails or that one Xid identifies every failure. When it
is effective, its cost is no automatic lid-close sleep. The screen still locks.
Use NoID Privacy Tools → **Laptop Lid Close**, or the matching native CLI, to
inspect the real hardware and effective normal/external-power/docked state:

```bash
noid-toggle-lid-action status
noid-toggle-lid-action suspend  # explicit choice; confirmation required
noid-toggle-lid-action lock
noid-toggle-lid-action reset    # return to this lower NVIDIA/Fedora policy
```

The explicit M17 choice survives NVIDIA install and rollback. NVIDIA rollback
removes only `/etc/systemd/logind.conf.d/99-noid-nvidia-lid.conf`; it never
removes `/etc/systemd/logind.conf.d/99-noid-user-lid-action.conf`. Save work
and retain the exact GPU, driver, kernel and previous-boot journal when
validating suspend/resume.

Evidence reviewed 2026-07-13 includes NVIDIA open-kernel-module issues #795,
#830, #1117 and #1157 plus NVIDIA's “Configuring Power Management Support”
driver documentation. These reports establish a real failure class, not
universal incidence or one universal root cause.

### Installer-selected encrypted-root prompt — NVIDIA in initramfs

Root encryption is selected in the installer; do not infer it from the image
name. Check the live root source with `findmnt -no SOURCE /` and its parent
stack with `lsblk -s -o NAME,TYPE,FSTYPE,MOUNTPOINTS <source>`. If the root
stack includes a `crypt` mapping, identify its backing device and use
`cryptsetup luksDump <device>` for the actual LUKS2/keyslot/KDF evidence.

On an encrypted-root system whose boot display is driven by NVIDIA, the LUKS
prompt may need nvidia-drm to re-render it after the firmware/simpledrm handover.
`noid-nvidia-install.sh` makes the driver available in the initramfs via
`/etc/dracut.conf.d/99-noid-nvidia-initramfs.conf`; `plymouth.use-simpledrm=1`
(Module 01) stays as the early framebuffer path and fallback. An unencrypted
root has no pre-root LUKS prompt; hybrid and desktop display routing must be
measured rather than inferred from chassis type.

> NOTE: RPM Fusion's Howto recommends simpledrm-only (no nvidia in initramfs).
> Whether simpledrm alone is sufficient depends on the actual boot-display
> routing. NoID Privacy keeps the NVIDIA modules available as a conservative encrypted-
> root compatibility path; this is not a guarantee for every firmware/display.

Verify simpledrm is active:
```bash
grep -oE "plymouth\.use-simpledrm=[0-9]+" /proc/cmdline
# Expected: plymouth.use-simpledrm=1
```

If missing (e.g. an older NoID Privacy image installed before this fix landed
in Module 01), rerun the managed NVIDIA helper. It verifies and, if needed,
updates every BLS entry while holding the shared boot-mutation lock and only
after M21 has reached a confirmed terminal basis:
```bash
/usr/local/bin/noid-nvidia-install.sh
```

Do not substitute a bare `grubby --update-kernel=ALL` command: that bypasses
the M21 terminal-state guard and the other NoID Privacy boot-image writers.

The helper owns the conditional dracut configuration and post-transaction
hooks. Do not copy or edit RPM Fusion's vendor file: doing so loses the helper's
module-existence/signature gates and can create a broken image on the next
kernel transaction.

## Troubleshooting

**Black screen after reboot (LUKS prompt not visible)**

First establish whether root is encrypted and whether this is the unlock prompt
or a later GDM/driver failure. If it is the encrypted-root prompt on an NVIDIA-
driven boot display, verify the managed initramfs evidence:

```bash
sudo lsinitrd /boot/initramfs-$(uname -r).img | grep nvidia
sudo /usr/libexec/noid-nvidia-verify "$(uname -r)" --require-enrolled
# If invalid or incomplete, enter the durable guarded recovery queue:
sudo /usr/libexec/noid-nvidia-initramfs-queue "$(uname -r)"
```

Do not reboot while the queue guard is active. If the current system remains
reachable, use a TTY and `noid-nvidia-install.sh --rollback`. If the encrypted-
root prompt itself is unusable, try a known prior kernel boot entry if one is
present, or use Fedora live media to unlock/chroot and repair. Snapper snapshots
are not GRUB entries on this image because no grub-btrfs integration is shipped.

**Module not loading (lsmod shows no nvidia)**

Check if akmods finished building:

```bash
sudo systemctl status akmods.service
ls /usr/lib/modules/$(uname -r)/extra/nvidia/
```

If the directory is empty, akmods hasn't built the module yet. Wait a few
minutes after first install, then check again. If it still fails:

```bash
/usr/local/bin/noid-nvidia-install.sh
```

**akmods/dracut after kernel update**

`noid-update-all.sh` (Module 25) enters M19's durable queue and waits for exact
module/MOK/initramfs evidence after a kernel or NVIDIA driver change. Manual DNF
kernel and driver transactions use the same post-transaction queue. Inspect or
resume it with:

```bash
sudo systemctl status noid-nvidia-reboot-guard.service
sudo /usr/libexec/noid-nvidia-initramfs-queue --resume
```

The queue builds akmods after the RPM transaction releases its lock, verifies
fresh branch/certificate/EVR identity, and delegates the boot image to M21's
canonical same-filesystem candidate validator. The prior image remains
published until the complete candidate passes.

**Secure Boot: module signature verification failed**

See `19-secure-boot-mok.md` for MOK enrollment instructions. The NVIDIA
kernel module must be signed with your enrolled MOK key.

## Rollback (if something breaks)

**Easy path** — the helper's `--rollback` flag does all the steps below:

```bash
noid-nvidia-install.sh --rollback
```

Do not substitute a partial manual package/config removal on a booted system.
The managed rollback also stops the durable queue, removes hooks and its
NVIDIA-owned compatibility policy, and atomically rebuilds every
installed-kernel image through the shared M21 validator. An explicit lid choice
made through NoID Privacy Tools remains user-owned. Each prior image remains
published until its nouveau candidate passes the complete boot-content gates.

After reboot the graphics driver returns to the in-tree Nouveau/Mesa path. The
enrolled MOK and unrelated dependencies may remain; inspect/remove them
separately if desired.

If you cannot boot at all, try a known prior kernel boot entry if available, or
use Fedora live media to unlock/chroot and remove the packages. A Snapper root
snapshot can support a documented manual recovery after the root filesystem is
reachable; it is not directly selectable from GRUB on this image.

## References

- [RPM Fusion NVIDIA Howto](https://rpmfusion.org/Howto/NVIDIA)
- [NVIDIA Unix Driver Portal](https://www.nvidia.com/en-us/drivers/unix/)
- [Mesa NVK Documentation](https://docs.mesa3d.org/drivers/nvk.html)
- [NVIDIA Maxwell/Pascal/Volta Support Plan](https://nvidia.custhelp.com/app/answers/detail/a_id/5676)
- [NVIDIA Quadro Maxwell/Pascal/Volta Support Plan](https://nvidia.custhelp.com/app/answers/detail/a_id/5706)
- [NVIDIA CUDA Architecture Support Guidance](https://developer.nvidia.com/blog/navigating-gpu-architecture-support-a-guide-for-nvidia-cuda-developers/)
- [NVIDIA R580.173.02 Supported Products](https://download.nvidia.com/XFree86/Linux-x86_64/580.173.02/README/supportedchips.html)
- [NVIDIA R610 Kernel-Module Flavors and Support](https://download.nvidia.com/XFree86/Linux-x86_64/610.43.03/README/kernel_open.html)
- [NVIDIA Open Kernel Modules — Supported GPUs](https://github.com/NVIDIA/open-gpu-kernel-modules#compatible-gpus)
- [Fedora Secure Boot + NVIDIA](https://docs.fedoraproject.org/en-US/quick-docs/how-to-set-nvidia-as-primary-gpu-on-optimus-based-laptops/)

NVIDIA_DOC_EOF

chmod 0644 /usr/share/doc/noid-privacy/19-nvidia-drivers.md
log "  [OK] 19-nvidia-drivers.md written"

# ------------------------------------------------------------------------------
# Phase 3 — Write 19-secure-boot-mok.md
# ------------------------------------------------------------------------------
PHASE="P3-mok-doc"
log "Writing 19-secure-boot-mok.md"

cat > /usr/share/doc/noid-privacy/19-secure-boot-mok.md <<'MOK_DOC_EOF'
# Secure Boot + MOK Enrollment Guide — NoID Privacy Workstation

This document explains how to enroll a Machine Owner Key (MOK) on this image.
You need this if you want to load out-of-tree kernel modules (the NVIDIA
driver stack, VirtualBox, VMware, some WiFi drivers, etc.) while keeping Secure
Boot enabled.

## Background

**Secure Boot** is a UEFI firmware setting; the image supports it but cannot
enable it on your behalf. Check the live firmware state with `mokutil
--sb-state`. NoID Privacy configures `lockdown=integrity` and
`module.sig_enforce=1`, so unsigned kernel modules are refused even when the
firmware's Secure Boot setting is disabled. With Secure Boot enabled:

- The Fedora kernel and its in-tree modules (including nouveau, amdgpu, i915)
  are signed by Fedora's CA and load automatically.
- Third-party out-of-tree kernel modules (from `akmods` packages like
  `akmod-nvidia`, `akmod-VirtualBox`, etc.) are NOT signed by Fedora's CA.
  Without additional action, they refuse to load.

**Machine Owner Key (MOK)** is the mechanism that lets you add your own
trusted key to the shim bootloader's keyring. Once your MOK is enrolled,
the shim trusts modules signed with that key. Fedora's `akmods` package
auto-generates a per-machine MOK and signs akmod-built modules with it.

## Signature chain

The complete cryptographic trust chain from UEFI firmware to loaded kernel
module:

```
UEFI Firmware (Platform Key)
    | verifies
    v
shim.efi                    (signed: Microsoft UEFI CA)
    | verifies via vendor_cert[] + MokListRT
    v
grubx64.efi                 (signed: Fedora Secure Boot CA)
    | verifies via shim_lock_protocol
    v
vmlinuz                     (signed: Fedora Secure Boot CA)
    | verifies module signatures via kernel keyring
    v
kernel modules:
    - in-tree               -> Fedora Secure Boot CA
      (nouveau, amdgpu, i915, iwlwifi, ath10k, xe, ...)
    - out-of-tree           -> your enrolled MOK
      (nvidia, VirtualBox, wl, evdi, ...)
```

With firmware Secure Boot enabled, every boot-chain link is verified
cryptographically. If any signature
fails, the chain breaks: either the boot stops (for shim/grub/vmlinuz), or
the module refuses to load with `Module has invalid signature` in `dmesg`
(for kernel modules). `lockdown=integrity` (Module 01) enforces this at
runtime even for modules loaded after boot, and `module.sig_enforce=1`
(Module 01) refuses any unsigned module unconditionally.

## When you need MOK enrollment

You need to enroll a MOK if you install any of these package families:

- `akmod-nvidia` / `akmod-nvidia-580xx` (NVIDIA out-of-tree kernel modules)
- `akmod-VirtualBox` (Oracle VirtualBox host kernel modules)
- `kmod-VirtualBox` (prebuilt VirtualBox modules)
- `akmod-wl` (Broadcom WiFi)
- Any `akmod-*` or `kmod-*` package that ships an out-of-tree kernel module

You do NOT need MOK enrollment for:

- Fedora's in-tree drivers (nouveau, amdgpu, i915, xe, iwlwifi, ath10k, etc.)
- Flatpaks
- RPMs that don't ship kernel modules (most applications)

An RPM package signature and a kernel-module signature are separate trust
checks. Fedora-signed RPM metadata does not imply that every file in the RPM is
a kernel module signed by Fedora's Secure Boot key; most RPMs contain no kernel
module at all. The no-MOK case above is specifically Fedora's in-tree module
set authenticated by the kernel's trusted keys.

## The enrollment workflow

### Step 1: Generate the MOK key FIRST

Generate your signing key BEFORE installing any akmod package, so akmods signs
the module during its very first build:

```bash
sudo dnf install akmods        # provides kmodgenca (if not already installed)
sudo kmodgenca -a
```

This creates the selected paths
`/etc/pki/akmods/certs/public_key.der` and
`/etc/pki/akmods/private/private_key.priv`. They may be symlinks to a
per-machine named certificate and private key. The dereferenced key targets
are mode 0640 and owned `root:akmods`; the akmods group needs read access to
sign modules at build time. The `-a` flag is idempotent — it does nothing if a
key already exists. After generation, test this exact selected certificate
rather than searching the display names of every enrolled key:

```bash
sudo mokutil --test-key /etc/pki/akmods/certs/public_key.der
```

Read the result text (`is already enrolled` or `is not enrolled`); mokutil's
exit status for this reporting command is not a conventional success boolean.

> WHY FIRST: akmods signs a module only if the signing key exists AT BUILD TIME
> (the `brp-kmodsign` build step). Installing `akmod-nvidia` BEFORE the key
> exists produces an UNSIGNED module — and on this image (`module.sig_enforce=1`)
> an unsigned module is refused. The resulting nouveau/GDM state depends on the
> blacklist, initramfs and services; no fallback is promised. Generating the key
> first avoids this failure class. (The
> `noid-nvidia-install.sh` helper does this ordering for you.)

### Step 2: Install your akmods-based package

Install whichever package ships an out-of-tree kernel module. Example for NVIDIA
(Fedora 44 GNOME 50 Wayland-only):

```bash
sudo dnf install akmod-nvidia xorg-x11-drv-nvidia-cuda
```

`akmod-nvidia` requires the `nvidia-kmod-common` capability provided by the
base `xorg-x11-drv-nvidia` package, so DNF necessarily installs that package
even on a Wayland-only system. Do not add it as a redundant explicit request.
The akmod transaction builds and installs the kernel-specific
`kmod-nvidia-<kernel>` package; `xorg-x11-drv-nvidia-cuda` provides
`nvidia-smi`. The akmods build signs the module with your Step 1 key. See
`19-nvidia-drivers.md` for the full install walkthrough and branch-selection
logic.

### Step 3: Import the public key into the MOK pending queue

```bash
sudo mokutil --import /etc/pki/akmods/certs/public_key.der
```

`mokutil` will prompt you to set a **MOK password**. It authorizes this pending
MokManager enrollment and is not your login password. Keep it until the exact
certificate is confirmed enrolled.

### Step 4: Reboot

```bash
sudo reboot
```

### Step 5: The MokManager blue screen

On the next boot, **before** the Fedora boot logo, a blue screen appears
with the title **"Perform MOK management"**. This is the shim's MokManager
prompt. It looks like this:

```
Perform MOK management

 Continue boot
 Enroll MOK
 Enroll key from disk
 Enroll hash from disk
```

**Do NOT press Enter on "Continue boot"** — that would skip enrollment.

Instead:

1. Use arrow keys to select **"Enroll MOK"** → press Enter
2. Select **"View key 0"** to see the key fingerprint (optional sanity check)
3. Back out and select **"Continue"** → press Enter
4. Select **"Yes"** when asked "Enroll the key(s)?" → press Enter
5. Enter the **MOK password** you set in Step 3
6. Select **"Reboot"** → press Enter

The system will reboot. The MOK is then stored in the firmware-backed MOK
trust database until it is explicitly deleted or that trust state is reset.

### Step 6: Verify enrollment

After the second reboot, verify:

```bash
sudo mokutil --test-key /etc/pki/akmods/certs/public_key.der
```

It must report that this exact certificate is already enrolled. You should also
see:

```bash
sudo dmesg | grep -iE 'Loading of .* is rejected|module verification failed|unsigned module loading'
```

This should print nothing. Any match is a signing or loading failure that must
be resolved before relying on the module.

And verify your kernel module loaded:

```bash
lsmod | grep nvidia       # or virtualbox, wl, etc.
```

Should show the module. If empty, the module failed to load — check
`journalctl -b | grep -i nvidia` (or equivalent) for errors.

## Troubleshooting

### "Module fails to load with 'Operation not permitted'"

The kernel is in lockdown=integrity mode and refusing your unsigned module.
Check:

1. Did you run `mokutil --import` and reboot through MokManager?
2. Did `akmods.service` successfully build the module?
   ```bash
   sudo systemctl status akmods.service
   ls /var/cache/akmods/
   ```
3. Is the module signed with the right key?
   ```bash
   sudo /usr/libexec/noid-nvidia-verify "$(uname -r)" --require-enrolled
   ```
   This binds all four modules to the exact selected akmods certificate,
   branch, package EVR and running kernel.

### "I pressed 'Continue boot' by mistake"

No harm done. The MOK is still pending. Reboot again — the blue screen
should reappear while the import request remains pending. Check with `sudo
mokutil --list-new`; if the certificate is no longer pending, re-run `sudo
mokutil --import /etc/pki/akmods/certs/public_key.der` and try again.

### "I forgot the MOK password"

Cancel only the pending import request, then import the same public certificate
again and choose a new one-time password:
```bash
sudo mokutil --revoke-import
sudo mokutil --import /etc/pki/akmods/certs/public_key.der
```
Then reboot into MokManager again. This does not reset or delete any already
enrolled MOK.

### "The blue screen doesn't appear at all"

Check your UEFI Secure Boot is actually enabled:
```bash
mokutil --sb-state
sudo mokutil --list-new
```
The first command reports the live firmware state; the second reports pending
enrollment requests. If Secure Boot is disabled, the firmware boot chain is not
being enforced. That does **not** make unsigned modules load on NoID Privacy because
`module.sig_enforce=1` still refuses them. If you intended verified boot,
re-enable Secure Boot in firmware; if the certificate is no longer pending,
import it again and reboot.

### "The module is loaded but there's a screen glitch/black screen"

First run the exact verifier above. If it passes, enrollment/signature mismatch
is not the cause covered by this guide; investigate the display path and driver
compatibility. To fall back to nouveau:

From a reachable TTY, run as the normal user:

```bash
noid-nvidia-install.sh --rollback
```

This is intentionally not a raw package-removal/Dracut recipe: the helper owns
the queue shutdown, complete package scope and atomic boot-image rollback.

See `19-nvidia-drivers.md` section "Rollback" for details.

## Checking your Secure Boot state

```bash
mokutil --sb-state          # Reports the live firmware state
sudo mokutil --test-key /etc/pki/akmods/certs/public_key.der
sudo mokutil --list-new     # Lists pending MOKs before enrollment
```

## Why we don't automate this

This image ships with **manual MOK enrollment** because:

1. **MokManager is unavoidably interactive** — no automation skips the
   blue password screen.
2. **No unattended completion** — the helper can queue the certificate with an
   interactively entered one-time password, but firmware confirmation still
   requires the user at the console. NoID Privacy stores no enrollment password
   for later automation.
3. **User sovereignty** — you should know when you're trusting third-party
   code in your kernel. Making it a deliberate act is a security feature,
   not a UX flaw.

## References

- [Fedora Secure Boot Documentation](https://fedoraproject.org/wiki/Secureboot)
- [RPM Fusion Secure Boot Howto](https://rpmfusion.org/Howto/Secure%20Boot)
- [Shim Source](https://github.com/rhboot/shim)
- [mokutil upstream manual source](https://github.com/lcp/mokutil/blob/master/man/mokutil.1)
MOK_DOC_EOF

chmod 0644 /usr/share/doc/noid-privacy/19-secure-boot-mok.md
log "  [OK] 19-secure-boot-mok.md written"

# ------------------------------------------------------------------------------
# Phase 3b — Install the topology-gated GTK4 GL renderer policy
# ------------------------------------------------------------------------------
PHASE="P3b-gsk-toggle"
log "Installing NVIDIA-offload topology probe, Settings wrapper and policy toggle"

cat > /usr/libexec/noid-gsk-hybrid-match <<'GSK_MATCH_EOF'
#!/usr/bin/bash
# Exit zero only for the conservative portable iGPU-primary/NVIDIA-offload
# topology affected by Vulkan ICD discovery. The optional card mode further
# qualifies a connectorless offload KMS node for Mutter's own udev ignore tag.
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH LC_ALL=C.UTF-8

SYS_ROOT=/sys
CHASSIS_TYPE_FILE=/sys/class/dmi/id/chassis_type

[ "$#" -le 2 ] || exit 1
[ -f "$CHASSIS_TYPE_FILE" ] && [ ! -L "$CHASSIS_TYPE_FILE" ] || exit 1
# This renderer workaround deliberately requires a portable DMI identity before
# changing an application's renderer. It is independent of the lid policy,
# which detects the kernel input subsystem's real SW_LID capability instead.
case "$(cat "$CHASSIS_TYPE_FILE" 2>/dev/null || true)" in
    8|9|10|11|14|30|31|32) ;;
    *) exit 1 ;;
esac

if [ "$#" -ne 0 ]; then
    [ "$#" -eq 2 ] && [ "$1" = --mutter-headless-card ] || exit 1
    card=$2
    card_name=${card##*/}
    [[ "$card_name" =~ ^card[0-9]+$ ]] || exit 1
    [ "$card" = "$SYS_ROOT/class/drm/$card_name" ] || exit 1
    [ -e "$card" ] || exit 1
    real_card=$(readlink -f -- "$card" 2>/dev/null || true)
    case "$real_card" in
        "$SYS_ROOT"/devices/*/drm/"$card_name") ;;
        *) exit 1 ;;
    esac

    device=$(readlink -f -- "$real_card/device" 2>/dev/null || true)
    [ -n "$device" ] && [ -d "$device" ] || exit 1
    case "$(cat "$device/class" 2>/dev/null || true)" in
        0x030000|0x030200) ;;
        *) exit 1 ;;
    esac
    [ "$(cat "$device/vendor" 2>/dev/null || true)" = 0x10de ] || exit 1
    [ "$(cat "$device/boot_vga" 2>/dev/null || echo 0)" != 1 ] || exit 1
    [ "$(cat "$device/power/control" 2>/dev/null || true)" = auto ] || exit 1

    # A static physical connector is initialized before drm_dev_register()
    # exposes the card to userspace. Dynamic DP-MST connectors always have a
    # static root connector, so a truly connectorless node has no cardN-* child.
    for connector in "$real_card"/"$card_name"-*; do
        [ ! -e "$connector" ] || exit 1
    done

    render_count=0
    for render in "$device"/drm/renderD[0-9]*; do
        [ -e "$render" ] || continue
        render_name=${render##*/}
        [[ "$render_name" =~ ^renderD[0-9]+$ ]] || continue
        [ "$(readlink -f -- "$render/device" 2>/dev/null || true)" = "$device" ] \
            || continue
        render_count=$((render_count + 1))
    done
    [ "$render_count" -ge 1 ] || exit 1

    primary_count=0
    supported_primary_count=0
    internal_panel_count=0
    declare -A card_seen=()
    for candidate in "$SYS_ROOT"/class/drm/card*; do
        [ -e "$candidate" ] || continue
        candidate_name=${candidate##*/}
        [[ "$candidate_name" =~ ^card[0-9]+$ ]] || continue
        candidate_real=$(readlink -f -- "$candidate" 2>/dev/null || true)
        candidate_device=$(
            readlink -f -- "$candidate_real/device" 2>/dev/null || true
        )
        [ -n "$candidate_device" ] && [ -d "$candidate_device" ] || continue
        [ -z "${card_seen[$candidate_device]:-}" ] || continue
        card_seen[$candidate_device]=1
        [ "$(cat "$candidate_device/boot_vga" 2>/dev/null || echo 0)" = 1 ] \
            || continue
        primary_count=$((primary_count + 1))
        case "$(cat "$candidate_device/vendor" 2>/dev/null || true)" in
            0x8086|0x1002)
                supported_primary_count=$((supported_primary_count + 1))
                ;;
        esac
        for connector in \
                "$candidate_real"/"$candidate_name"-eDP-* \
                "$candidate_real"/"$candidate_name"-LVDS-* \
                "$candidate_real"/"$candidate_name"-DSI-*; do
            [ -e "$connector" ] || continue
            internal_panel_count=$((internal_panel_count + 1))
        done
    done

    [ "$primary_count" -eq 1 ] \
        && [ "$supported_primary_count" -eq 1 ] \
        && [ "$internal_panel_count" -ge 1 ] \
        || exit 1
    printf '%s\n' mutter-device-ignore
    exit 0
fi

gpu_count=0
primary_count=0
supported_primary_count=0
nvidia_offload_count=0
declare -A seen=()
for card in "$SYS_ROOT"/class/drm/card*; do
    [ -e "$card" ] || continue
    card_name=${card##*/}
    [[ "$card_name" =~ ^card[0-9]+$ ]] || continue
    link=$card/device
    [ -e "$link" ] || continue
    device=$(readlink -f "$link" 2>/dev/null || true)
    [ -n "$device" ] && [ -d "$device" ] || continue
    [ -z "${seen[$device]:-}" ] || continue
    seen[$device]=1
    class=$(cat "$device/class" 2>/dev/null || true)
    case "$class" in 0x030000|0x030200) ;; *) continue ;; esac
    vendor=$(cat "$device/vendor" 2>/dev/null || true)
    boot_vga=$(cat "$device/boot_vga" 2>/dev/null || echo 0)
    control=$(cat "$device/power/control" 2>/dev/null || true)
    runtime_status=$(cat "$device/power/runtime_status" 2>/dev/null || true)
    gpu_count=$((gpu_count + 1))
    if [ "$boot_vga" = 1 ]; then
        primary_count=$((primary_count + 1))
        case "$vendor" in
            0x8086|0x1002)
                supported_primary_count=$((supported_primary_count + 1))
                ;;
        esac
    fi
    if [ "$vendor" = 0x10de ] && [ "$boot_vga" != 1 ] \
            && [ "$control" = auto ]; then
        case "$runtime_status" in
            active|suspended|suspending|resuming)
                nvidia_offload_count=$((nvidia_offload_count + 1))
                ;;
        esac
    fi
done

[ "$gpu_count" -eq 2 ] \
    && [ "$primary_count" -eq 1 ] \
    && [ "$supported_primary_count" -eq 1 ] \
    && [ "$nvidia_offload_count" -eq 1 ]
GSK_MATCH_EOF
chmod 0755 /usr/libexec/noid-gsk-hybrid-match
chown root:root /usr/libexec/noid-gsk-hybrid-match

cat > /etc/udev/rules.d/62-noid-mutter-headless-offload.rules <<'GSK_MUTTER_RULE_EOF'
# NoID Privacy — keep connectorless NVIDIA offload KMS nodes out of Mutter.
# The render node remains available to switcheroo-control and applications.
ACTION=="add|change", SUBSYSTEM=="drm", KERNEL=="card[0-9]*", TAG=="switcheroo-discrete-gpu", PROGRAM=="/usr/libexec/noid-gsk-hybrid-match --mutter-headless-card /sys/class/drm/%k", RESULT=="mutter-device-ignore", TAG+="mutter-device-ignore"
GSK_MUTTER_RULE_EOF
chmod 0644 /etc/udev/rules.d/62-noid-mutter-headless-offload.rules
chown root:root /etc/udev/rules.d/62-noid-mutter-headless-offload.rules

cat > /usr/libexec/noid-gsk-session-environment <<'GSK_SESSION_HELPER_EOF'
#!/usr/bin/bash
# Apply the hybrid-GPU GTK renderer workaround only after GNOME Shell started.
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH LC_ALL=C.UTF-8
umask 077

MATCHER=/usr/libexec/noid-gsk-hybrid-match
MODE=/etc/xdg/noid-privacy/gsk-renderer.mode
UID_NOW=$(id -u)
GID_NOW=$(id -g)
RUNTIME_ROOT=${XDG_RUNTIME_DIR:-}
STATE_DIR=$RUNTIME_ROOT/noid-gsk-session-environment
MARKER=$STATE_DIR/applied

fail() {
    echo "noid-gsk-session-environment: $*" >&2
    exit 1
}

[ "$#" -eq 1 ] || fail "usage: noid-gsk-session-environment {apply|clear}"
case "$1" in
    apply|clear) action=$1 ;;
    *) fail "usage: noid-gsk-session-environment {apply|clear}" ;;
esac

[ "$RUNTIME_ROOT" = "/run/user/$UID_NOW" ] \
    && [ -d "$RUNTIME_ROOT" ] && [ ! -L "$RUNTIME_ROOT" ] \
    && [ "$(stat -c '%u:%g:%a' "$RUNTIME_ROOT" 2>/dev/null || true)" = \
         "$UID_NOW:$GID_NOW:700" ] \
    || fail "private runtime root is unavailable or unsafe"
[ -d "$STATE_DIR" ] && [ ! -L "$STATE_DIR" ] \
    && [ "$(stat -c '%u:%g:%a' "$STATE_DIR" 2>/dev/null || true)" = \
         "$UID_NOW:$GID_NOW:700" ] \
    || fail "private runtime directory is unavailable"

case "$action" in
    apply)
        # A login/admin selection, including an intentionally empty value, wins.
        [ "${GSK_RENDERER+x}" != x ] || exit 0

        # The exact managed `off` marker and every independent/unsafe object
        # both fail safely to GTK's vendor renderer.
        if [ -e "$MODE" ] || [ -L "$MODE" ]; then
            exit 0
        fi

        # The hardened user-service namespace maps host root to an unprivileged
        # identity. Validate the effective boundary instead of owner names:
        # exact mode, no symlink, executable, and not user-writable.
        [ -f "$MATCHER" ] && [ ! -L "$MATCHER" ] && [ -x "$MATCHER" ] \
            && [ ! -w "$MATCHER" ] \
            && [ "$(stat -c '%a' "$MATCHER" 2>/dev/null || true)" = 755 ] \
            || fail "topology matcher is missing or unsafe"
        "$MATCHER" || exit 0

        /usr/bin/dbus-update-activation-environment --systemd GSK_RENDERER=gl
        systemctl --user show-environment | grep -qxF GSK_RENDERER=gl \
            || fail "user-manager renderer postcondition failed"
        printf '%s\n' gl-session-apps >"$MARKER"
        chmod 0600 "$MARKER"
        ;;
    clear)
        [ -e "$MARKER" ] || exit 0
        [ -f "$MARKER" ] && [ ! -L "$MARKER" ] \
            && [ "$(stat -c '%u:%g:%a' "$MARKER" 2>/dev/null || true)" = \
                 "$UID_NOW:$GID_NOW:600" ] \
            && [ "$(cat "$MARKER")" = gl-session-apps ] \
            || fail "runtime ownership marker is unsafe"

        if systemctl --user show-environment | grep -qxF GSK_RENDERER=gl; then
            systemctl --user unset-environment GSK_RENDERER
            if systemctl --user show-environment | grep -q '^GSK_RENDERER='; then
                fail "user-manager renderer cleanup failed"
            fi
        fi
        rm -f -- "$MARKER"
        ;;
esac
GSK_SESSION_HELPER_EOF
chmod 0755 /usr/libexec/noid-gsk-session-environment
chown root:root /usr/libexec/noid-gsk-session-environment

install -d -m 0755 -o root -g root /usr/lib/systemd/user \
    /etc/systemd/user/gnome-session.target.wants
cat > /usr/lib/systemd/user/noid-gsk-session-environment.service <<'GSK_SESSION_UNIT_EOF'
[Unit]
Description=NoID Privacy — avoid hybrid-GPU GTK Vulkan launch stalls after GNOME Shell starts
Documentation=https://github.com/NexusOne23/noid-privacy-workstation
After=org.gnome.Shell@user.service
Before=gnome-session.target
PartOf=gnome-session.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/libexec/noid-gsk-session-environment apply
ExecStop=/usr/libexec/noid-gsk-session-environment clear
RuntimeDirectory=noid-gsk-session-environment
RuntimeDirectoryMode=0700
UMask=0077
TimeoutStartSec=5
TimeoutStopSec=5
NoNewPrivileges=yes
CapabilityBoundingSet=
KeyringMode=private
PrivateDevices=yes
PrivateTmp=yes
ProtectClock=yes
ProtectHostname=yes
ProtectKernelLogs=yes
ProtectProc=invisible
ProcSubset=pid
ProtectSystem=strict
ProtectHome=read-only
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
SystemCallArchitectures=native

[Install]
WantedBy=gnome-session.target
GSK_SESSION_UNIT_EOF
chmod 0644 /usr/lib/systemd/user/noid-gsk-session-environment.service
chown root:root /usr/lib/systemd/user/noid-gsk-session-environment.service

gsk_session_enable=/etc/systemd/user/gnome-session.target.wants/noid-gsk-session-environment.service
gsk_session_target=/usr/lib/systemd/user/noid-gsk-session-environment.service
if [ ! -e "$gsk_session_enable" ] && [ ! -L "$gsk_session_enable" ]; then
    ln -s "$gsk_session_target" "$gsk_session_enable"
elif [ ! -L "$gsk_session_enable" ] \
        || [ "$(readlink "$gsk_session_enable" 2>/dev/null || true)" != \
             "$gsk_session_target" ]; then
    die "refusing to replace an independent GTK session unit enablement"
fi

cat > /usr/local/bin/noid-toggle-gsk-gl <<'GSK_TOGGLE_EOF'
#!/usr/bin/bash
# Reversible app-scoped/manual policy for the GTK4 NVIDIA-offload workaround.
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH LC_ALL=C.UTF-8
umask 077

# shellcheck source=/dev/null
[ ! -r /usr/local/lib/noid-privacy/agent-install-format.sh ] || \
    NOID_FMT_AUTO_TITLE="NoID Privacy — GTK Renderer" \
    NOID_FMT_AUTO_SUBTITLE="Application compatibility override" \
    . /usr/local/lib/noid-privacy/agent-install-format.sh

ENV_DIR=/etc/environment.d
TARGET=$ENV_DIR/90-noid-gsk-renderer.conf
POLICY_DIR=/etc/xdg/noid-privacy
MODE=$POLICY_DIR/gsk-renderer.mode
MATCHER=/usr/libexec/noid-gsk-hybrid-match
LEGACY_MASK=/etc/systemd/user-environment-generators/55-noid-gsk-renderer
temporary=

usage() {
    echo "usage: noid-toggle-gsk-gl {auto|on|off|status}"
}
fail() {
    echo "noid-toggle-gsk-gl: $*" >&2
    exit 1
}
managed_content() {
    printf '%s\n' \
        '# NoID Privacy explicit GTK4 GL renderer opt-in' \
        'GSK_RENDERER=gl'
}
legacy_content() {
    printf '%s\n' 'GSK_RENDERER=gl'
}
managed_mode_content() {
    printf '%s\n' 'off'
}
safe_target_metadata() {
    [ "$(stat -c '%U:%G:%a' "$TARGET")" = root:root:644 ] \
        && case "$(stat -c '%C' "$TARGET")" in
            *:object_r:etc_t:s0) return 0 ;;
            *) return 1 ;;
        esac
}
safe_mode_metadata() {
    [ "$(stat -c '%U:%G:%a' "$MODE")" = root:root:644 ] \
        && case "$(stat -c '%C' "$MODE")" in
            *:object_r:etc_t:s0) return 0 ;;
            *) return 1 ;;
        esac
}
cleanup() {
    [ -z "$temporary" ] || rm -f -- "$temporary"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

[ "$#" -eq 1 ] || { usage >&2; exit 2; }
action=$1
case "$action" in auto|on|off|status) ;; *) usage >&2; exit 2 ;; esac

[ -f "$MATCHER" ] && [ ! -L "$MATCHER" ] && [ -x "$MATCHER" ] \
    || fail "topology matcher is missing or unsafe: $MATCHER"

file_state=absent
if [ -e "$TARGET" ] || [ -L "$TARGET" ]; then
    if [ ! -f "$TARGET" ] || [ -L "$TARGET" ]; then
        file_state=unsafe
    elif cmp -s "$TARGET" <(managed_content); then
        if safe_target_metadata; then
            file_state=on
        else
            file_state=unsafe-metadata
        fi
    elif cmp -s "$TARGET" <(legacy_content); then
        file_state=legacy-on
    else
        file_state=modified
    fi
fi

mode_state=auto
if [ -e "$MODE" ] || [ -L "$MODE" ]; then
    if [ ! -f "$MODE" ] || [ -L "$MODE" ]; then
        mode_state=unsafe
    elif cmp -s "$MODE" <(managed_mode_content); then
        if safe_mode_metadata; then
            mode_state=off
        else
            mode_state=unsafe-metadata
        fi
    else
        mode_state=modified
    fi
fi

legacy_mask_state=absent
if [ -e "$LEGACY_MASK" ] || [ -L "$LEGACY_MASK" ]; then
    if [ -L "$LEGACY_MASK" ] \
            && [ "$(readlink "$LEGACY_MASK" 2>/dev/null || true)" = /dev/null ]; then
        legacy_mask_state=managed
    else
        legacy_mask_state=independent
    fi
fi

if [ "$action" = status ]; then
    echo "system_override=$file_state"
    echo "mode=$mode_state"
    echo "legacy_generator_override=$legacy_mask_state"
    if "$MATCHER"; then
        echo "topology=portable-nvidia-offload"
    else
        echo "topology=vendor-default"
    fi
    if [ "$file_state" = on ] || [ "$file_state" = legacy-on ]; then
        echo "effective_future_apps=gl-manual-system"
    elif [ "$file_state" != absent ] || [ "$mode_state" = modified ] \
            || [ "$mode_state" = unsafe ] \
            || [ "$mode_state" = unsafe-metadata ] \
            || [ "$legacy_mask_state" = independent ]; then
        echo "effective_future_apps=administrator-controlled"
    elif [ "$mode_state" = off ]; then
        echo "effective_future_apps=vendor-default"
    elif "$MATCHER"; then
        echo "effective_future_apps=gl-session-apps-auto"
    else
        echo "effective_future_apps=vendor-default"
    fi
    case "$file_state" in
        unsafe|unsafe-metadata|modified) exit 1 ;;
    esac
    case "$mode_state" in
        unsafe|unsafe-metadata|modified) exit 1 ;;
    esac
    exit 0
fi

[ "$(id -u)" -eq 0 ] || fail "$action requires root; use sudo"
for command in chown chmod cmp install mktemp mv readlink restorecon rm stat sync; do
    command -v "$command" >/dev/null 2>&1 || fail "required command missing: $command"
done
if [ ! -e "$ENV_DIR" ]; then
    install -d -m 0755 -o root -g root "$ENV_DIR"
fi
[ -d "$ENV_DIR" ] && [ ! -L "$ENV_DIR" ] \
    || fail "$ENV_DIR is missing, symlinked or not a directory"
if [ ! -e "$POLICY_DIR" ]; then
    install -d -m 0755 -o root -g root "$POLICY_DIR"
fi
[ -d "$POLICY_DIR" ] && [ ! -L "$POLICY_DIR" ] \
    || fail "$POLICY_DIR is missing, symlinked or not a directory"

publish_target() {
    temporary=$(mktemp "$ENV_DIR/.90-noid-gsk-renderer.XXXXXX")
    managed_content >"$temporary"
    chown root:root "$temporary"
    chmod 0644 "$temporary"
    restorecon -F "$temporary"
    sync -- "$temporary"
    mv -fT -- "$temporary" "$TARGET"
    temporary=
    chown root:root "$TARGET"
    chmod 0644 "$TARGET"
    restorecon -F "$TARGET"
    sync -- "$TARGET"
    sync -- "$ENV_DIR"
    cmp -s "$TARGET" <(managed_content) \
        || fail "published renderer opt-in failed its byte postcondition"
    safe_target_metadata \
        || fail "published renderer opt-in failed its metadata postcondition"
}

remove_target() {
    case "$file_state" in
        absent) return 0 ;;
        on|legacy-on|unsafe-metadata)
            if ! cmp -s "$TARGET" <(managed_content) \
                    && ! cmp -s "$TARGET" <(legacy_content); then
                fail "renderer file changed during validation; refusing removal"
            fi
            rm -f -- "$TARGET"
            sync -- "$ENV_DIR"
            [ ! -e "$TARGET" ] && [ ! -L "$TARGET" ] \
                || fail "renderer opt-in removal failed"
            ;;
        *) fail "refusing to remove an unsafe or independently modified $TARGET" ;;
    esac
}

remove_mode() {
    case "$mode_state" in
        auto) return 0 ;;
        off|unsafe-metadata)
            cmp -s "$MODE" <(managed_mode_content) \
                || fail "renderer mode changed during validation"
            rm -f -- "$MODE"
            sync -- "$POLICY_DIR"
            [ ! -e "$MODE" ] && [ ! -L "$MODE" ] \
                || fail "renderer mode removal failed"
            ;;
        *) fail "refusing to remove an unsafe or independently modified $MODE" ;;
    esac
}

remove_legacy_mask() {
    case "$legacy_mask_state" in
        absent) return 0 ;;
        managed)
            [ -L "$LEGACY_MASK" ] \
                && [ "$(readlink "$LEGACY_MASK")" = /dev/null ] \
                || fail "legacy generator mask changed during validation"
            rm -f -- "$LEGACY_MASK"
            sync -- "$(dirname "$LEGACY_MASK")"
            [ ! -e "$LEGACY_MASK" ] && [ ! -L "$LEGACY_MASK" ] \
                || fail "legacy generator mask removal failed"
            ;;
        *) fail "refusing to replace an independently managed legacy generator override" ;;
    esac
}

publish_mode() {
    case "$mode_state" in
        auto|unsafe-metadata) ;;
        off) return 0 ;;
        *) fail "refusing to overwrite an unsafe or independently modified $MODE" ;;
    esac
    temporary=$(mktemp "$POLICY_DIR/.gsk-renderer.mode.XXXXXX")
    managed_mode_content >"$temporary"
    chown root:root "$temporary"
    chmod 0644 "$temporary"
    restorecon -F "$temporary"
    sync -- "$temporary"
    mv -fT -- "$temporary" "$MODE"
    temporary=
    chown root:root "$MODE"
    chmod 0644 "$MODE"
    restorecon -F "$MODE"
    sync -- "$MODE"
    sync -- "$POLICY_DIR"
    cmp -s "$MODE" <(managed_mode_content) \
        || fail "published renderer mode failed its byte postcondition"
    safe_mode_metadata \
        || fail "published renderer mode failed its metadata postcondition"
}

case "$action" in
    on)
        case "$file_state" in on|absent|legacy-on|unsafe-metadata) ;; *)
            fail "refusing to overwrite an unsafe or independently modified $TARGET"
        esac
        case "$mode_state" in auto|off|unsafe-metadata) ;; *)
            fail "refusing to overwrite an unsafe or independently modified $MODE"
        esac
        [ "$legacy_mask_state" != independent ] \
            || fail "refusing to replace an independently managed legacy generator override"
        remove_mode
        remove_legacy_mask
        case "$file_state" in
            on) ;;
            absent|legacy-on|unsafe-metadata) publish_target ;;
        esac
        echo "GTK4 GL renderer opt-in enabled system-wide for future login sessions."
        echo "Warning: this can keep an offload dGPU awake and increase energy use."
        echo "Log out completely and log in again before testing applications."
        ;;
    off)
        case "$file_state" in on|absent|legacy-on|unsafe-metadata) ;; *)
            fail "refusing to remove an unsafe or independently modified $TARGET"
        esac
        case "$mode_state" in auto|off|unsafe-metadata) ;; *)
            fail "refusing to overwrite an unsafe or independently modified $MODE"
        esac
        [ "$legacy_mask_state" != independent ] \
            || fail "refusing to replace an independently managed legacy generator override"
        remove_target
        remove_legacy_mask
        publish_mode
        echo "Automatic NVIDIA-hybrid GL selection disabled for future login sessions."
        echo "Log out completely and log in again before testing applications."
        ;;
    auto)
        case "$file_state" in on|absent|legacy-on|unsafe-metadata) ;; *)
            fail "refusing to remove an unsafe or independently modified $TARGET"
        esac
        case "$mode_state" in auto|off|unsafe-metadata) ;; *)
            fail "refusing to overwrite an unsafe or independently modified $MODE"
        esac
        [ "$legacy_mask_state" != independent ] \
            || fail "refusing to replace an independently managed legacy generator override"
        remove_target
        remove_mode
        remove_legacy_mask
        if "$MATCHER"; then
            echo "Automatic policy restored for future GTK application launches."
        else
            echo "Automatic policy restored: this topology retains GTK's default renderer."
        fi
        echo "Log out completely and log in again before testing applications."
        ;;
esac
GSK_TOGGLE_EOF

chmod 0755 /usr/local/bin/noid-toggle-gsk-gl
chown root:root /usr/local/bin/noid-toggle-gsk-gl

cat > /usr/local/bin/gnome-control-center <<'GSK_SETTINGS_WRAPPER_EOF'
#!/usr/bin/bash
# App-scoped renderer workaround for GNOME Settings on hybrid NVIDIA laptops.
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
# The matcher owns its deterministic C locale. The wrapped GUI must inherit
# the user's locale so GTK/gettext can select the session translations.
export PATH

VENDOR=/usr/bin/gnome-control-center
MATCHER=/usr/libexec/noid-gsk-hybrid-match
MODE=/etc/xdg/noid-privacy/gsk-renderer.mode

[ -f "$VENDOR" ] && [ ! -L "$VENDOR" ] && [ -x "$VENDOR" ] \
    || { echo "NoID Privacy: GNOME Settings vendor executable is unavailable" >&2; exit 126; }

# Preserve an administrator/session selection, including an empty value.
if [ "${GSK_RENDERER+x}" = x ]; then
    exec "$VENDOR" "$@"
fi

# Any mode object that is not the exact managed regular file fails safely to
# GTK's vendor default rather than guessing at administrator intent.
if [ -e "$MODE" ] || [ -L "$MODE" ]; then
    exec "$VENDOR" "$@"
fi

if [ -f "$MATCHER" ] && [ ! -L "$MATCHER" ] && [ -x "$MATCHER" ] \
        && "$MATCHER"; then
    exec env GSK_RENDERER=gl "$VENDOR" "$@"
fi
exec "$VENDOR" "$@"
GSK_SETTINGS_WRAPPER_EOF
chmod 0755 /usr/local/bin/gnome-control-center
chown root:root /usr/local/bin/gnome-control-center

cat > /usr/local/bin/gnome-software <<'GSK_SOFTWARE_WRAPPER_EOF'
#!/usr/bin/bash
# Explicit Flatpak store plus app-scoped renderer policy for GNOME Software.
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
# The matcher owns its deterministic C locale. The wrapped GUI must inherit
# the user's locale so GTK/gettext can select the session translations.
export PATH

VENDOR=/usr/bin/gnome-software
MATCHER=/usr/libexec/noid-gsk-hybrid-match
MODE=/etc/xdg/noid-privacy/gsk-renderer.mode
NOID_SOFTWARE_PLUGINS=flatpak,icons,hardcoded-blocklist,malcontent,modalias,os-release,provenance,provenance-license,generic-updates

[ -f "$VENDOR" ] && [ ! -L "$VENDOR" ] && [ -x "$VENDOR" ] \
    || { echo "NoID Privacy: GNOME Software vendor executable is unavailable" >&2; exit 126; }

# GNOME Software is the explicit Flatpak application store. Native packages,
# firmware and system updates retain their deliberate NoID Privacy CLI/GUI workflows.
# Preserve an administrator plugin selection, including an empty value.
if [ "${GNOME_SOFTWARE_PLUGINS_ALLOWLIST+x}" != x ] \
        && [ "${GNOME_SOFTWARE_PLUGINS_BLOCKLIST+x}" != x ]; then
    export GNOME_SOFTWARE_PLUGINS_ALLOWLIST="$NOID_SOFTWARE_PLUGINS"
fi

# Preserve an administrator/session renderer selection, including an empty
# value. The application plugin scope above remains independent.
if [ "${GSK_RENDERER+x}" = x ]; then
    exec "$VENDOR" "$@"
fi

# Any mode object that is not the exact managed regular file fails safely to
# GTK's vendor default rather than guessing at administrator intent.
if [ -e "$MODE" ] || [ -L "$MODE" ]; then
    exec "$VENDOR" "$@"
fi

if [ -f "$MATCHER" ] && [ ! -L "$MATCHER" ] && [ -x "$MATCHER" ] \
        && "$MATCHER"; then
    exec env GSK_RENDERER=gl "$VENDOR" "$@"
fi
exec "$VENDOR" "$@"
GSK_SOFTWARE_WRAPPER_EOF
chmod 0755 /usr/local/bin/gnome-software
chown root:root /usr/local/bin/gnome-software

cat > /usr/libexec/noid-gsk-settings-launcher-sync <<'GSK_DESKTOP_SYNC_EOF'
#!/usr/bin/bash
# Rebuild the XDG-precedence Settings launcher from the current Fedora source.
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH LC_ALL=C.UTF-8
umask 077

SOURCE=/usr/share/applications/org.gnome.Settings.desktop
DEST_DIR=/usr/local/share/applications
DEST=$DEST_DIR/org.gnome.Settings.desktop
temporary=

fail() {
    echo "noid-gsk-settings-launcher-sync: $*" >&2
    exit 1
}
cleanup() {
    [ -z "$temporary" ] || rm -f -- "$temporary"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

[ "$(id -u)" -eq 0 ] || fail "root privileges are required"
[ -f "$SOURCE" ] && [ ! -L "$SOURCE" ] \
    || fail "vendor launcher is missing, symlinked or not a regular file"
exec_count=$(awk '$0 == "Exec=gnome-control-center" { count++ } END { print count + 0 }' "$SOURCE")
dbus_count=$(awk '$0 == "DBusActivatable=true" { count++ } END { print count + 0 }' "$SOURCE")
[ "$exec_count" -eq 1 ] \
    || fail "vendor launcher has $exec_count exact Exec anchors, expected 1"
[ "$dbus_count" -eq 1 ] \
    || fail "vendor launcher has $dbus_count exact DBusActivatable anchors, expected 1"

if [ ! -e "$DEST_DIR" ]; then
    install -d -m 0755 -o root -g root "$DEST_DIR"
fi
[ -d "$DEST_DIR" ] && [ ! -L "$DEST_DIR" ] \
    || fail "$DEST_DIR is missing, symlinked or not a directory"

temporary=$(mktemp --suffix=.desktop "$DEST_DIR/.org.gnome.Settings.XXXXXX")
awk '
    $0 == "Exec=gnome-control-center" {
        print "Exec=/usr/local/bin/gnome-control-center"
        next
    }
    $0 == "DBusActivatable=true" {
        print "DBusActivatable=false"
        next
    }
    { print }
' "$SOURCE" >"$temporary"
desktop-file-validate "$temporary" \
    || fail "generated launcher failed desktop-file validation"
chown root:root "$temporary"
chmod 0644 "$temporary"
restorecon -F "$temporary"
sync -- "$temporary"
mv -fT -- "$temporary" "$DEST"
temporary=
chown root:root "$DEST"
chmod 0644 "$DEST"
restorecon -F "$DEST"
sync -- "$DEST"
sync -- "$DEST_DIR"

[ "$(stat -c '%U:%G:%a' "$DEST")" = root:root:644 ] \
    || fail "published launcher metadata is not root:root:0644"
[ "$(grep -c '^Exec=/usr/local/bin/gnome-control-center$' "$DEST")" -eq 1 ] \
    || fail "published launcher does not contain one wrapped Exec"
[ "$(grep -c '^DBusActivatable=false$' "$DEST")" -eq 1 ] \
    || fail "published launcher does not disable D-Bus activation exactly once"
! grep -q '^DBusActivatable=true$' "$DEST" \
    || fail "published launcher retained active D-Bus activation"
desktop-file-validate "$DEST" \
    || fail "published launcher failed desktop-file validation"
GSK_DESKTOP_SYNC_EOF
chmod 0755 /usr/libexec/noid-gsk-settings-launcher-sync
chown root:root /usr/libexec/noid-gsk-settings-launcher-sync

install -d -m 0755 -o root -g root /etc/dnf/libdnf5-plugins/actions.d
cat > /etc/dnf/libdnf5-plugins/actions.d/noid-gsk-settings-launcher.actions <<'GSK_DESKTOP_ACTION_EOF'
# Refresh the XDG admin launcher after Fedora replaces its source desktop file.
post_transaction:gnome-control-center:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/libexec/noid-gsk-settings-launcher-sync\ >/dev/null
GSK_DESKTOP_ACTION_EOF
chmod 0644 /etc/dnf/libdnf5-plugins/actions.d/noid-gsk-settings-launcher.actions
chown root:root /etc/dnf/libdnf5-plugins/actions.d/noid-gsk-settings-launcher.actions

# Retire the earlier D-Bus service shadow. A duplicate service name produces an
# error-level broker message each time a user bus starts.
rm -f -- /usr/local/share/dbus-1/services/org.gnome.Settings.service
/usr/libexec/noid-gsk-settings-launcher-sync

# Migrate the exact legacy NoID Privacy generator mask to the app-scoped off
# marker. Preserve any independently managed object at either path.
legacy_mask=/etc/systemd/user-environment-generators/55-noid-gsk-renderer
mode_dir=/etc/xdg/noid-privacy
mode_file=$mode_dir/gsk-renderer.mode
if [ -L "$legacy_mask" ] \
        && [ "$(readlink "$legacy_mask" 2>/dev/null || true)" = /dev/null ]; then
    if [ ! -e "$mode_file" ] && [ ! -L "$mode_file" ]; then
        install -d -m 0755 -o root -g root "$mode_dir"
        mode_temp=$(mktemp "$mode_dir/.gsk-renderer.mode.XXXXXX")
        printf '%s\n' off >"$mode_temp"
        chmod 0644 "$mode_temp"
        chown root:root "$mode_temp"
        restorecon -F "$mode_temp" 2>/dev/null || true
        sync -- "$mode_temp"
        mv -fT -- "$mode_temp" "$mode_file"
        sync -- "$mode_dir"
    fi
    if [ -f "$mode_file" ] && [ ! -L "$mode_file" ] \
            && cmp -s "$mode_file" <(printf '%s\n' off); then
        rm -f -- "$legacy_mask"
    else
        log "  [WARN] Preserved legacy renderer mask beside an independent mode file"
    fi
fi
rm -f -- /usr/lib/systemd/user-environment-generators/55-noid-gsk-renderer

log "  [OK] GTK renderer policy installed (post-Shell app activation gate)"

# ------------------------------------------------------------------------------
# Phase 3c — Install /usr/local/bin/noid-nvidia-install.sh
# ------------------------------------------------------------------------------
# User-invoked opt-in Stage-1 installer (dependency chain up to MOK import +
# reboot). Runs only on deliberate opt-in (welcome dialog or manual), opens
# with the trade-off matrix + "Recommended: SKIP" disclaimer. Branch select
# via lspci codename (main / 580xx / REFUSE — see header). Stage 2 (the MOK
# blue screen) is UEFI-level and inherently user-interactive — the script
# only queues the key via mokutil --import.
PHASE="P3c-nvidia-install"
log "Installing /usr/local/bin/noid-nvidia-install.sh"

cat > /usr/local/bin/noid-nvidia-install.sh <<'NVIDIA_INSTALL_EOF'
#!/bin/bash
# =============================================================================
# noid-nvidia-install.sh — opt-in NVIDIA proprietary driver installer (Stage 1)
# =============================================================================
# Installs akmod-nvidia (or akmod-nvidia-580xx for legacy GPUs), generates the
# MOK key, and imports it into the MOK pending queue. After this script runs,
# the user must reboot and complete the 6-step MokManager blue screen flow.
#
# Usage:
#   noid-nvidia-install.sh                      interactive install
#   noid-nvidia-install.sh --dry-run            show plan, no changes
#   noid-nvidia-install.sh --force-branch=580xx override auto-detection
#   noid-nvidia-install.sh --force-branch=main  override to mainline
#   noid-nvidia-install.sh --rollback           uninstall proprietary driver
#   noid-nvidia-install.sh --help               this help
#
# Refuses root; invokes sudo internally.
# Prerequisite: NoID Privacy Workstation image (Fedora 44+, RPM Fusion).
# =============================================================================
set -euo pipefail

FMT_LIB=/usr/local/lib/noid-privacy/agent-install-format.sh
# shellcheck source=/dev/null
if [ -r "$FMT_LIB" ]; then . "$FMT_LIB"; else
    fmt_banner(){ echo "== $1 =="; [ -n "${2:-}" ] && echo "   $2"; }
    fmt_step(){ echo "[$1/$2] $3"; }; fmt_ok(){ echo "  OK: $1"; }
    fmt_info(){ echo "  - $1"; }; fmt_warn(){ echo "  ! $1" >&2; }
    fmt_err(){ echo "  ERROR: $1" >&2; }; fmt_note(){ echo "$1"; }
    fmt_done(){ echo "$1"; }
fi
RED=${_F_RED:-}
GREEN=${_F_GREEN:-}
YELLOW=${_F_YEL:-}
CYAN=${_F_BLUE:-}
BOLD=${_F_B:-}
NC=${_F_RST:-}

if [ "$(id -u)" -eq 0 ]; then
    fmt_err "Do not run as root or via sudo; this helper invokes sudo internally."
    echo "Run as your normal user: /usr/local/bin/noid-nvidia-install.sh" >&2
    exit 1
fi

# M10 deliberately gives interactive shells umask 0027. sudo inherits that
# restriction by default, which makes depmod's public modules.dep/alias maps
# unreadable to ordinary modinfo consumers. Scope Fedora's system-file umask to
# only the package/kmod generators; do not relax the caller or sudo globally.
run_system_root() {
    sudo /usr/bin/sh -c 'umask 022; exec "$@"' noid-system-root "$@"
}

# Return the only safe repair verb for one exact generated kmod package.
# A missing package needs DNF install semantics; --rebuild changes akmods'
# nested DNF verb to `reinstall` and therefore cannot create it. Prove that a
# failed exact query was a normal absence through a second rpmdb inventory
# query instead of turning an rpmdb/read failure into an install decision.
exact_kmod_repair_mode() {
    local exact_kmod=${1:-}
    shift || return 2
    [ -n "$exact_kmod" ] && [ "$#" -gt 0 ] || return 2
    if "$@" -q "$exact_kmod" >/dev/null 2>&1; then
        printf 'rebuild\n'
    elif "$@" -qa --qf '%{NAME}\n' >/dev/null 2>&1; then
        printf 'install\n'
    else
        return 1
    fi
}

BOOT_MUTATION_LOCK=/run/lock/noid-boot-mutation.lock
NVIDIA_INSTALL_MARKER=/run/noid-nvidia-install-running
NVIDIA_REPO=/etc/yum.repos.d/rpmfusion-nonfree-nvidia-driver.repo
BOOT_MUTATION_BASIS=
build_marker=
managed_dnf_candidate=
managed_dnf_marker_active=0
prepared_candidate=
declare -a NVIDIA_RPM_NAMES=()

begin_boot_mutation() {
    [ -e "$BOOT_MUTATION_LOCK" ] || {
        echo "${RED}ERROR${NC}: shared boot-mutation lock is missing; repair Module 21 first." >&2
        exit 1
    }
    fmt_info "Waiting for the shared boot-mutation boundary (up to 30 minutes)"
    exec 7>"$BOOT_MUTATION_LOCK"
    flock -w 1800 7 || {
        echo "${RED}ERROR${NC}: timed out waiting for another boot mutation." >&2
        exit 1
    }
    BOOT_MUTATION_BASIS=$(sudo /usr/libexec/noid-boot-mutation-guard)
    case "$BOOT_MUTATION_BASIS" in
        basis=hostonly|basis=generic) ;;
        *)
            echo "${RED}ERROR${NC}: M21 returned an invalid stable-basis record." >&2
            exit 1
            ;;
    esac
    fmt_ok "boot-mutation boundary ready (${BOOT_MUTATION_BASIS})"
}

publish_managed_dnf_marker() {
    local start_time expected metadata
    start_time=$(awk '{print $22}' "/proc/$$/stat")
    expected=$(printf 'pid=%s\nstart_time=%s' "$$" "$start_time")
    managed_dnf_candidate=$(sudo mktemp \
        /run/.noid-nvidia-install-running.XXXXXX) \
        || return 1
    if ! printf '%s\n' "$expected" \
            | sudo tee "$managed_dnf_candidate" >/dev/null \
            || ! sudo chown root:root "$managed_dnf_candidate" \
            || ! sudo chmod 0600 "$managed_dnf_candidate" \
            || ! sudo restorecon -F "$managed_dnf_candidate" \
            || ! sudo sync -- "$managed_dnf_candidate"; then
        sudo rm -f -- "$managed_dnf_candidate" 2>/dev/null || true
        managed_dnf_candidate=
        return 1
    fi
    if ! sudo mv -fT -- "$managed_dnf_candidate" \
            "$NVIDIA_INSTALL_MARKER"; then
        sudo rm -f -- "$managed_dnf_candidate" 2>/dev/null || true
        managed_dnf_candidate=
        return 1
    fi
    managed_dnf_candidate=
    managed_dnf_marker_active=1
    if ! sudo restorecon -F "$NVIDIA_INSTALL_MARKER" \
            || ! sudo sync -- "$NVIDIA_INSTALL_MARKER" \
            || ! sudo sync -- /run; then
        remove_managed_dnf_marker || true
        return 1
    fi
    metadata=$(sudo stat -c '%U:%G:%a' "$NVIDIA_INSTALL_MARKER" 2>/dev/null) \
        || {
            remove_managed_dnf_marker || true
            return 1
        }
    if [ "$metadata" != root:root:600 ] \
            || ! sudo awk -v pid="$$" -v start_time="$start_time" '
                NR == 1 { first=($0 == "pid=" pid) }
                NR == 2 { second=($0 == "start_time=" start_time) }
                END { exit !(NR == 2 && first && second) }
            ' "$NVIDIA_INSTALL_MARKER"; then
        remove_managed_dnf_marker || true
        return 1
    fi
}

remove_managed_dnf_marker() {
    local start_time metadata
    [ "$managed_dnf_marker_active" -eq 1 ] || return 0
    start_time=$(awk '{print $22}' "/proc/$$/stat")
    if ! sudo test -f "$NVIDIA_INSTALL_MARKER" \
            || sudo test -L "$NVIDIA_INSTALL_MARKER"; then
        echo "${RED}ERROR${NC}: managed NVIDIA DNF marker changed type or disappeared." >&2
        return 1
    fi
    metadata=$(sudo stat -c '%U:%G:%a' "$NVIDIA_INSTALL_MARKER" 2>/dev/null) \
        || return 1
    if [ "$metadata" != root:root:600 ] \
            || ! sudo awk -v pid="$$" -v start_time="$start_time" '
                NR == 1 { first=($0 == "pid=" pid) }
                NR == 2 { second=($0 == "start_time=" start_time) }
                END { exit !(NR == 2 && first && second) }
            ' "$NVIDIA_INSTALL_MARKER"; then
        echo "${RED}ERROR${NC}: managed NVIDIA DNF marker identity changed; refusing blind removal." >&2
        return 1
    fi
    sudo rm -f -- "$NVIDIA_INSTALL_MARKER" \
        && sudo sync -- /run \
        && ! sudo test -e "$NVIDIA_INSTALL_MARKER" \
        && ! sudo test -L "$NVIDIA_INSTALL_MARKER" \
        || return 1
    managed_dnf_marker_active=0
}

cleanup_runtime_artifacts() {
    local cleanup_rc=0
    if [ -n "$build_marker" ]; then
        sudo rm -f -- "$build_marker" 2>/dev/null || cleanup_rc=1
        build_marker=
    fi
    if [ -n "$managed_dnf_candidate" ]; then
        sudo rm -f -- "$managed_dnf_candidate" 2>/dev/null || cleanup_rc=1
        managed_dnf_candidate=
    fi
    if [ -n "$prepared_candidate" ]; then
        sudo rm -f -- "$prepared_candidate" 2>/dev/null || cleanup_rc=1
        prepared_candidate=
    fi
    if [ "$managed_dnf_marker_active" -eq 1 ]; then
        remove_managed_dnf_marker || cleanup_rc=1
    fi
    if [ "$cleanup_rc" -ne 0 ]; then
        echo "${YELLOW}WARN${NC}: a validated NVIDIA runtime marker could not be cleaned up." >&2
    fi
}

query_installed_nvidia_rpm_names() {
    local inventory rpm_name
    local -A seen=()
    NVIDIA_RPM_NAMES=()
    if ! inventory=$(sudo rpm -qa --qf '%{NAME}\n' 2>/dev/null); then
        echo "${RED}ERROR${NC}: could not query the installed RPM inventory." >&2
        return 1
    fi
    while IFS= read -r rpm_name; do
        case "$rpm_name" in
            akmod-nvidia*|kmod-nvidia*|xorg-x11-drv-nvidia*|nvidia-settings*|nvidia-persistenced*)
                if [ -z "${seen[$rpm_name]+x}" ]; then
                    NVIDIA_RPM_NAMES+=("$rpm_name")
                    seen["$rpm_name"]=1
                fi
                ;;
        esac
    done <<<"$inventory"
}

verify_nvidia_repo_state() {
    local expected=$1 metadata
    sudo test -f "$NVIDIA_REPO" \
        && ! sudo test -L "$NVIDIA_REPO" \
        || return 1
    metadata=$(sudo stat -c '%U:%G:%a' "$NVIDIA_REPO" 2>/dev/null) \
        || return 1
    [ "$metadata" = root:root:644 ] || return 1
    sudo awk -v expected="$expected" '
        /^[[:space:]]*($|#)/ { next }
        /^\[[^][]+\]$/ {
            section=substr($0, 2, length($0)-2)
            sections++
            section_count[section]++
            next
        }
        {
            active_lines++
            separator=index($0, "=")
            if (!separator) {
                invalid=1
                next
            }
            key=substr($0, 1, separator-1)
            value=substr($0, separator+1)
            key_count[section, key]++
            key_value[section, key]=value
        }
        END {
            main="rpmfusion-nonfree-nvidia-driver"
            debug=main "-debuginfo"
            source=main "-source"
            common_key="file:///etc/pki/rpm-gpg/RPM-GPG-KEY-rpmfusion-nonfree-fedora-$releasever"
            if (invalid || sections != 3 || active_lines != 18 ||
                    section_count[main] != 1 ||
                    section_count[debug] != 1 ||
                    section_count[source] != 1 ||
                    key_count[main, "name"] != 1 ||
                    key_value[main, "name"] != "RPM Fusion for Fedora $releasever - Nonfree - NVIDIA Driver" ||
                    key_count[main, "metalink"] != 1 ||
                    key_value[main, "metalink"] != "https://mirrors.rpmfusion.org/metalink?repo=nonfree-fedora-nvidia-driver-$releasever&arch=$basearch" ||
                    key_count[debug, "name"] != 1 ||
                    key_value[debug, "name"] != "RPM Fusion for Fedora $releasever - Nonfree - NVIDIA Driver Debug" ||
                    key_count[debug, "metalink"] != 1 ||
                    key_value[debug, "metalink"] != "https://mirrors.rpmfusion.org/metalink?repo=nonfree-fedora-nvidia-driver-debug-$releasever&arch=$basearch" ||
                    key_count[source, "name"] != 1 ||
                    key_value[source, "name"] != "RPM Fusion for Fedora $releasever - Nonfree - NVIDIA Driver Source" ||
                    key_count[source, "metalink"] != 1 ||
                    key_value[source, "metalink"] != "https://mirrors.rpmfusion.org/metalink?repo=nonfree-fedora-nvidia-driver-source-$releasever&arch=$basearch") {
                exit 1
            }
            for (s=1; s<=3; s++) {
                current=(s == 1 ? main : (s == 2 ? debug : source))
                if (key_count[current, "enabled"] != 1 ||
                        key_count[current, "gpgcheck"] != 1 ||
                        key_value[current, "gpgcheck"] != "1" ||
                        key_count[current, "gpgkey"] != 1 ||
                        key_value[current, "gpgkey"] != common_key ||
                        key_count[current, "skip_if_unavailable"] != 1 ||
                        key_value[current, "skip_if_unavailable"] != "True") {
                    exit 1
                }
            }
            if (key_value[debug, "enabled"] != "0" ||
                    key_value[source, "enabled"] != "0") {
                exit 1
            }
            if (expected == "either") {
                exit !(key_value[main, "enabled"] == "0" ||
                    key_value[main, "enabled"] == "1")
            }
            exit !(key_value[main, "enabled"] == expected)
        }
    ' "$NVIDIA_REPO"
}

set_nvidia_repo_state() {
    local expected=$1
    verify_nvidia_repo_state either || {
        echo "${RED}ERROR${NC}: NVIDIA repository file failed its exact precondition." >&2
        return 1
    }
    sudo sed -i \
        "/^\[rpmfusion-nonfree-nvidia-driver\]$/,/^\[/ s/^enabled=.*/enabled=${expected}/" \
        "$NVIDIA_REPO" \
        && sudo chown root:root "$NVIDIA_REPO" \
        && sudo chmod 0644 "$NVIDIA_REPO" \
        && sudo restorecon -F "$NVIDIA_REPO" \
        && sudo sync -- "$NVIDIA_REPO" \
        && sudo sync -- "$(dirname "$NVIDIA_REPO")" \
        && verify_nvidia_repo_state "$expected"
}

refuse_independent_nvidia_config() {
    local path found=0
    for path in \
            /etc/modprobe.d/nvidia.conf \
            /etc/modprobe.d/blacklist-nouveau.conf \
            /etc/dracut.conf.d/nvidia.conf; do
        if sudo test -e "$path" || sudo test -L "$path"; then
            printf '  %s\n' "$path" >&2
            found=1
        fi
    done
    if [ "$found" -eq 1 ]; then
        echo "${RED}ERROR${NC}: rollback found NVIDIA configuration not owned by NoID Privacy." >&2
        echo "Review and remove or migrate those files explicitly, then rerun rollback." >&2
        return 1
    fi
}

trap cleanup_runtime_artifacts EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

reconcile_firstboot_cmdline_evidence() {
    local context=$1 success_state=0 reboot_state=0
    if ! sudo systemctl start noid-firstboot-cmdline.service; then
        echo "${RED}ERROR${NC}: ${context} changed boot arguments, but M01 evidence revalidation failed; do not reboot." >&2
        return 1
    fi
    if sudo test -f /var/lib/noid-privacy/.firstboot-cmdline-done \
            && [ "$(sudo stat -c '%U:%G:%a' /var/lib/noid-privacy/.firstboot-cmdline-done)" = root:root:644 ]; then
        success_state=1
    fi
    if sudo test -f /var/lib/noid-privacy/.firstboot-cmdline-reboot-required \
            && [ "$(sudo stat -c '%U:%G:%a' /var/lib/noid-privacy/.firstboot-cmdline-reboot-required)" = root:root:600 ]; then
        reboot_state=1
    fi
    case "$success_state:$reboot_state" in
        1:0|0:1) ;;
        *)
            echo "${RED}ERROR${NC}: ${context} left ambiguous firstboot command-line evidence; do not reboot." >&2
            return 1
            ;;
    esac
}

# --- return-to-menu prompt -------------------------------------------------
return_to_menu_prompt() {
    # Welcome-spawned terminals set NOID_WELCOME_SPAWN=1 and hold via the
    # wrapper's single close prompt; a second hold here would make the user
    # press ENTER twice. The prompt below stays for standalone CLI runs.
    if [ -n "${NOID_WELCOME_SPAWN:-}" ]; then
        return 0
    fi
    echo
    echo "──────────────────────────────────────────────────────"
    # Detect an existing welcome process to avoid a duplicate window.
    if pgrep -f "noid-welcome\.sh" >/dev/null 2>&1; then
        read -rp "Press Enter to close terminal (welcome menu still open) ... " _ans
        return
    fi
    read -rp "Re-open welcome menu? [Y/n] " ans
    case "${ans:-Y}" in
        [nN]|[nN][oO])
            echo "OK. Re-open anytime with: noid-welcome.sh --again"
            ;;
        *)
            if [ -x /usr/local/bin/noid-welcome.sh ]; then
                nohup /usr/local/bin/noid-welcome.sh --again </dev/null >/dev/null 2>&1 &
                disown 2>/dev/null || true
                echo "Welcome menu re-opened. You can close this terminal."
            else
                echo "noid-welcome.sh not found. Close this terminal when done."
            fi
            ;;
    esac
}

# --- Mode + override parsing ------------------------------------------------
MODE="install"
FORCE_BRANCH=""
for arg in "$@"; do
    case "$arg" in
        --dry-run|--dry) MODE="dry-run" ;;
        --rollback|-r) MODE="rollback" ;;
        --force-branch=main)   FORCE_BRANCH="main" ;;
        --force-branch=580xx)  FORCE_BRANCH="580xx" ;;
        --force-branch=*)
            echo "unknown branch override '${arg#--force-branch=}' (try: main, 580xx)" >&2
            exit 2
            ;;
        --help|-h)
            cat <<HELP
noid-nvidia-install.sh — opt-in NVIDIA proprietary driver installer (Stage 1)

Usage:
  noid-nvidia-install.sh                      interactive install (auto-branch)
  noid-nvidia-install.sh --dry-run            show planned actions only
  noid-nvidia-install.sh --force-branch=main  force current main branch (Turing+ only)
  noid-nvidia-install.sh --force-branch=580xx force 580.xx (Maxwell/Pascal/Volta)
  noid-nvidia-install.sh --rollback           remove proprietary driver
  noid-nvidia-install.sh --help               this help

This is Stage 1 (install + MOK import). Stage 2 (MOK blue screen) is
UEFI-level, inherently user-interactive.

Full walkthrough: /usr/share/doc/noid-privacy/19-nvidia-drivers.md
MOK details:      /usr/share/doc/noid-privacy/19-secure-boot-mok.md
HELP
            exit 0
            ;;
        "") ;;
        *)
            echo "unknown argument '$arg' (try --help)" >&2
            exit 2
            ;;
    esac
done

# --- GPU detection via lspci codename ---------------------------------------
# Extracts first NVIDIA GPU's codename prefix (GB/AD/GA/TU/GV/GP/GM/GK/GF).
# Logic: `lspci -nn` returns VGA/3D/Display controllers. We grep for NVIDIA
# lines, then regex-extract the device-name portion which contains the
# codename like "GA107" (Ampere) or "TU116" (Turing).
detect_nvidia_gpu() {
    if ! command -v lspci >/dev/null 2>&1; then
        return 1
    fi
    # Get ALL NVIDIA GPU lines (for multi-NVIDIA detection).
    # append `|| true` so a grep-miss (no NVIDIA line) doesn't
    # trigger `set -euo pipefail` termination — we want the function to
    # return 1 below via the $-z check, not have the whole script die here.
    local all_nvidia_lines
    all_nvidia_lines=$(lspci -nn 2>/dev/null | grep -iE 'VGA|3D|Display' | grep -i nvidia || true)
    if [ -z "$all_nvidia_lines" ]; then
        return 1
    fi
    # Classify each display adapter independently. Keep duplicates: two GA
    # adapters are two classified adapters, not one prefix minus one unknown.
    local gpu_line gpu_codename gpu_prefix all_prefixes=""
    local classified_count=0 unknown_count=0
    while IFS= read -r gpu_line; do
        gpu_codename=$(echo "$gpu_line" | sed -nE \
            's/.*NVIDIA Corporation ([A-Z]{2}[0-9]+[A-Z]*) .*/\1/p' || true)
        if [ -z "$gpu_codename" ]; then
            gpu_codename=$(echo "$gpu_line" \
                | grep -oE '(GB|AD|GA|TU|GV|GP|GM|GK|GF)[0-9]+[A-Z]*' \
                | head -1 || true)
        fi
        if [ -n "$gpu_codename" ]; then
            gpu_prefix=${gpu_codename:0:2}
            all_prefixes+="${gpu_prefix} "
            classified_count=$((classified_count + 1))
        else
            all_prefixes+="UNKNOWN "
            unknown_count=$((unknown_count + 1))
        fi
    done <<<"$all_nvidia_lines"
    DETECTED_ALL_PREFIXES="${all_prefixes% }"
    DETECTED_CLASSIFIED_COUNT="$classified_count"
    DETECTED_UNKNOWN_COUNT="$unknown_count"
    local nvidia_count
    nvidia_count=$(echo "$all_nvidia_lines" | wc -l)
    DETECTED_NVIDIA_COUNT="$nvidia_count"
    if [ "$((DETECTED_CLASSIFIED_COUNT + DETECTED_UNKNOWN_COUNT))" \
            -ne "$DETECTED_NVIDIA_COUNT" ]; then
        return 1
    fi

    # Pick first GPU for primary detection (most common single-NVIDIA case)
    local line
    line=$(echo "$all_nvidia_lines" | head -1)
    local codename
    # Example line: "01:00.0 VGA compatible controller [0300]: NVIDIA Corporation GA107 [GeForce RTX xxxx] [10de:xxxx]"
    # We want "GA107" — the word immediately after "Corporation"
    # `|| true` guards both extractors against set -e + empty match.
    codename=$(echo "$line" | sed -nE 's/.*NVIDIA Corporation ([A-Z]{2}[0-9]+[A-Z]*) .*/\1/p' || true)
    if [ -z "$codename" ]; then
        # Fallback: try to find GB/AD/GA/TU/GV/GP/GM/GK/GF prefix codename anywhere
        codename=$(echo "$line" | grep -oE '(GB|AD|GA|TU|GV|GP|GM|GK|GF)[0-9]+[A-Z]*' | head -1 || true)
    fi
    DETECTED_GPU_LINE="$line"
    DETECTED_CODENAME="$codename"
    DETECTED_PREFIX="${codename:0:2}"
    return 0
}

# Map codename prefix → full generation name | year | recommended branch.
# Delimit fields explicitly so multi-word names never lose their year.
generation_info() {
    case "$1" in
        GB) echo "Blackwell|(2025)|main"        ;;
        AD) echo "Ada Lovelace|(2022)|main"     ;;
        GA) echo "Ampere|(2020)|main"           ;;
        TU) echo "Turing|(2018)|main"           ;;
        GV) echo "Volta|(2017)|580xx"           ;;
        GP) echo "Pascal|(2016)|580xx"          ;;
        GM) echo "Maxwell|(2014)|580xx"         ;;
        GK) echo "Kepler|(2012)|REFUSE"         ;;
        GF) echo "Fermi|(2010)|REFUSE"          ;;
        *)  echo "Unknown||UNKNOWN"              ;;
    esac
}

# --- ROLLBACK MODE ---------------------------------------------------------
if [ "$MODE" = "rollback" ]; then
    fmt_banner "NoID Privacy NVIDIA Rollback" "Return to Nouveau + Mesa"
    echo "This will:"
    echo "  1. Remove all NVIDIA RPMs: akmod-nvidia*, kmod-nvidia*,"
    echo "     xorg-x11-drv-nvidia*, nvidia-settings, nvidia-persistenced"
    echo "  2. Preserve and refuse independently managed NVIDIA modprobe/dracut files"
    echo "  3. Remove only NoID Privacy nvidia-initramfs config + lifecycle helpers"
    echo "  4. Remove the NVIDIA laptop lid-close safety default"
    echo "     GNOME auto-suspend and the explicit M17 lid choice remain user-owned."
    echo "     The independent GTK renderer opt-in, if selected, remains user-owned."
    echo "  5. Atomically regenerate the initramfs -> back to nouveau"
    echo "  6. On next boot: system returns to the in-tree Nouveau/Mesa path"
    echo
    echo "  Note: Module 01 adds plymouth.use-simpledrm=1 only when NVIDIA is"
    echo "  detected during OS installation; this helper adds it for later"
    echo "  NVIDIA changes. Rollback leaves that display fallback enabled."
    echo
    echo "${YELLOW}This does NOT remove your enrolled MOK. You can list enrolled MOKs"
    echo "via: mokutil --list-enrolled. To remove a MOK: mokutil --delete <file>${NC}"
    echo
    read -rp "Proceed with rollback? [y/N] " ans
    case "${ans:-n}" in
        [yY]|[yY][eE][sS]) ;;
        *) echo "Cancelled."; return_to_menu_prompt; exit 0 ;;
    esac

    refuse_independent_nvidia_config || exit 1
    if ! query_installed_nvidia_rpm_names; then
        exit 1
    fi
    nvidia_rpms=("${NVIDIA_RPM_NAMES[@]}")

    fmt_step 1 4 "Snapshot + remove NVIDIA packages"
    begin_boot_mutation

    if ! command -v noid-snap-pre >/dev/null 2>&1 \
            || ! sudo noid-snap-pre "NVIDIA proprietary driver rollback"; then
        echo "${RED}ERROR${NC}: rollback snapshot failed; no packages were removed." >&2
        exit 1
    fi

    # Stop queued workers before removing their packages/files. Candidate-image
    # writes are atomic, so interruption keeps the prior BLS image intact.
    sudo systemctl stop 'noid-nvidia-initramfs-*.service' \
        noid-nvidia-initramfs-resume.service \
        noid-nvidia-reboot-guard.service \
        noid-nvidia-postboot-verify.service 2>/dev/null || true
    sudo systemctl disable noid-nvidia-initramfs-resume.service \
        noid-nvidia-postboot-verify.service \
        2>/dev/null || true

    # RPM Fusion's package scripts mutate the persistent BLS command line.
    # Open M01's byte-bound evidence only after the snapshot and immediately
    # before that transaction; every exit after this point remains fail-closed.
    sudo /usr/libexec/noid-firstboot-cmdline-transition \
        --invalidate-nvidia-rollback

    if [ "${#nvidia_rpms[@]}" -eq 0 ]; then
        echo "No NVIDIA RPMs installed — nothing to remove."
    else
        echo "Removing:"
        printf '  %s\n' "${nvidia_rpms[@]}"
        if ! run_system_root /usr/bin/dnf remove -y "${nvidia_rpms[@]}"; then
            if ! reconcile_firstboot_cmdline_evidence "failed NVIDIA rollback"; then
                exit 1
            fi
            echo "${RED}ERROR${NC}: NVIDIA package rollback failed." >&2
            exit 1
        fi
    fi
    if ! query_installed_nvidia_rpm_names; then
        reconcile_firstboot_cmdline_evidence "incomplete NVIDIA rollback" \
            || exit 1
        echo "${RED}ERROR${NC}: RPM inventory could not be verified after rollback." >&2
        exit 1
    fi
    if [ "${#NVIDIA_RPM_NAMES[@]}" -gt 0 ]; then
        reconcile_firstboot_cmdline_evidence "incomplete NVIDIA rollback" \
            || exit 1
        echo "${RED}ERROR${NC}: NVIDIA packages remain after rollback transaction." >&2
        printf '%s\n' "${NVIDIA_RPM_NAMES[@]}" >&2
        exit 1
    fi

    fmt_step 2 4 "Remove NVIDIA policy + lifecycle hooks"
    # NoID Privacy early-KMS additions (created during install) — remove all so
    # the initramfs returns to slim/nouveau and kernel updates stop rebuilding
    # nvidia into the initramfs.
    sudo rm -f /etc/dracut.conf.d/99-noid-nvidia-initramfs.conf
    sudo rm -f /etc/kernel/install.d/95-noid-nvidia-initramfs.install
    sudo rm -f /usr/libexec/noid-nvidia-initramfs-rebuild
    sudo rm -f /usr/libexec/noid-nvidia-initramfs-queue
    sudo rm -f /usr/libexec/noid-nvidia-reboot-guard
    sudo rm -f /usr/libexec/noid-nvidia-initramfs-dnf-action
    sudo rm -f /usr/libexec/noid-nvidia-verify
    sudo rm -f /usr/libexec/noid-nvidia-rebind-evidence
    sudo rm -f /usr/libexec/noid-nvidia-postboot-verify
    sudo rm -f /etc/dnf/libdnf5-plugins/actions.d/noid-nvidia-initramfs.actions
    sudo rm -f /etc/systemd/system/noid-nvidia-reboot-guard.service
    sudo rm -f /etc/systemd/system/noid-nvidia-initramfs-resume.service
    sudo rm -f /etc/systemd/system/noid-nvidia-postboot-verify.service
    sudo rm -rf /var/lib/noid-nvidia-integrity
    sudo systemctl daemon-reload
    # Defensively strip the nouveau-blacklist kernel args the driver RPM's %post
    # writes into the BLS entries. The RPM %postun normally removes them on the
    # dnf remove above, but don't rely on it — leaving rd.driver.blacklist=nouveau
    # / nvidia-drm.modeset=1 behind is untidy and can confuse a future re-install.
    # Idempotent (no-op if already gone).
    if ! sudo grubby --update-kernel=ALL \
            --remove-args="rd.driver.blacklist=nouveau modprobe.blacklist=nouveau nvidia-drm.modeset=1"; then
        echo "${RED}ERROR${NC}: could not remove NVIDIA/nouveau boot arguments." >&2
        exit 1
    fi
    if ! sudo /usr/libexec/noid-canonicalize-kernel-cmdline --publish \
            >/dev/null; then
        echo "${RED}ERROR${NC}: canonical boot-argument rollback failed; do not reboot." >&2
        exit 1
    fi
    reconcile_firstboot_cmdline_evidence "NVIDIA rollback"
    fmt_step 3 4 "Restore + verify every boot image"
    fmt_info "Atomically regenerating and validating every installed initramfs for nouveau"
    if ! sudo -C 8 /usr/libexec/noid-dracut-regenerate-all \
            --lock-held=7; then
        echo "${RED}ERROR${NC}: guarded all-kernel initramfs rollback failed; do not reboot." >&2
        exit 1
    fi
    # Restore the NoID Privacy privacy default for the special main-branch repository.
    # Legacy updates use the ordinary RPM Fusion nonfree update repository.
    if ! set_nvidia_repo_state 0; then
        echo "${RED}ERROR${NC}: could not restore the NVIDIA repository privacy default." >&2
        exit 1
    fi
    echo "  [OK] NVIDIA main-branch repository restored to disabled default"
    # Clear stale akmods failure logs for both supported branches so a later
    # build attempt starts from the same state.
    fmt_step 4 4 "Restore privacy defaults"
    sudo rm -f /var/cache/akmods/nvidia/*.failed.log \
        /var/cache/akmods/nvidia-580xx/*.failed.log 2>/dev/null || true
    # Only the NVIDIA-specific lower lid policy belongs to this rollback.
    # M17's general idle policy, explicit 99-noid-user-lid-action.conf and
    # every user-db override remain untouched.
    sudo rm -f /etc/systemd/logind.conf.d/99-noid-nvidia-lid.conf
    fmt_done "NVIDIA rollback complete"
    fmt_warn "A reboot is required to switch back to the in-tree Nouveau/Mesa path."
    echo
    read -rp "Reboot now? [y/N] " ans
    case "${ans:-n}" in
        [yY]|[yY][eE][sS])
            echo "Rebooting in 5 seconds — press Ctrl+C to cancel ..."
            sleep 5
            sudo systemctl reboot
            ;;
        *)
            echo "OK — reboot manually when ready: sudo reboot"
            return_to_menu_prompt
            ;;
    esac
    exit 0
fi

# --- TRADE-OFF MATRIX (shown first, always) ---------------------------------
NVIDIA_BANNER_SUBTITLE="Informed Decision · signed modules + boot images"
[ "$MODE" = "dry-run" ] \
    && NVIDIA_BANNER_SUBTITLE="Informed Decision · dry run · no changes"
fmt_banner "NoID Privacy NVIDIA Setup" "$NVIDIA_BANNER_SUBTITLE"
cat <<MATRIX
${BOLD}${YELLOW}Recommended for most users: SKIP THIS.${NC}${YELLOW}
The in-tree Nouveau/Mesa path is the default. Install the NVIDIA stack only for a
specific, tested workload that needs its userspace interfaces or performs
insufficiently on the in-tree stack.${NC}

${BOLD}Trade-off matrix (Nouveau/Mesa default vs Proprietary):${NC}

  Requirement                  | Default decision
  ─────────────────────────────|────────────────────────────────────────
  Desktop/browser/office       | Try the Nouveau/Mesa path first
  Vulkan/OpenGL game           | Benchmark that game on this exact GPU
  Video decode/encode          | Verify codec + generation support; no promise
  CUDA application             | NVIDIA userspace driver required
  DLSS/NVENC/G-Sync dependency | NVIDIA driver normally required

${BOLD}Cost of installing proprietary:${NC}

  ⚠ Some GPU-accelerated apps can fail or behave inconsistently until reboot
     — SAVE & CLOSE your work first
     After install the GL/EGL libraries switch to NVIDIA while the running
     session may still use nouveau. Finish what you are doing before continuing
     and do not treat the mixed pre-reboot session as a supported steady state.

  ⚠ 1 reboot when the exact akmods MOK is already enrolled; otherwise the
     enrollment flow includes the MokManager reboot and its follow-up boot

  ⚠ New MOK enrollment uses manual UEFI blue-screen navigation
     Press arrow keys + enter. Skipping enrollment leaves the exact key
     untrusted; the resulting graphics/fallback state must be diagnosed rather
     than assumed. Recovery may require TTY or live-media chroot.

  ⚠ Ongoing maintenance burden
     - Every kernel update: akmods rebuilds the module; duration is hardware-dependent
     - Every kernel update: AIDE may report changed .ko files for your review
     - Occasional NVIDIA security updates per RPM Fusion

  ⚠ Graphics-start risk on skipped/broken MOK enrollment
     MokManager "Continue boot" bypasses enrollment, so the signed NVIDIA
     modules remain untrusted. Whether nouveau loads or GDM fails depends on
     the installed blacklist, initramfs and service state; no fallback promise.

Package download, compilation and firmware interaction time vary by machine.
One activation reboot is needed when the exact key is already enrolled; a new
key enrollment adds the MokManager reboot and its follow-up boot.

Docs:
  /usr/share/doc/noid-privacy/19-nvidia-drivers.md
  /usr/share/doc/noid-privacy/19-secure-boot-mok.md

MATRIX

# Detect GPU now that user has seen the matrix
if ! detect_nvidia_gpu; then
    echo "${YELLOW}No NVIDIA GPU detected via lspci.${NC}"
    echo "This script only runs on systems with an NVIDIA GPU."
    echo "If you believe this is wrong, check: lspci -nn | grep -i nvidia"
    return_to_menu_prompt
    exit 0
fi

gen_info=$(generation_info "$DETECTED_PREFIX")
IFS='|' read -r gen_name gen_year gen_branch <<<"$gen_info"

echo "${BOLD}Detected GPU:${NC}"
echo "  $DETECTED_GPU_LINE"
echo
echo "  Codename:   ${DETECTED_CODENAME:-unknown}"
echo "  Generation: ${gen_name} ${gen_year}"
echo "  Branch:     ${gen_branch}"
echo

# Classify every detected adapter. This must not extrapolate from the first
# lspci line: a secondary Kepler/Fermi or unknown adapter is still relevant to
# a global nouveau blacklist and to the claim that one branch covers all GPUs.
if [ "${DETECTED_NVIDIA_COUNT:-1}" -gt 1 ]; then
    has_main=0
    has_580xx=0
    has_refuse=0
    has_unknown=0
    has_blackwell=0
    for p in ${DETECTED_ALL_PREFIXES:-}; do
        case "$p" in
            GB) has_main=1; has_blackwell=1 ;;
            AD|GA|TU) has_main=1 ;;
            GV|GP|GM) has_580xx=1 ;;
            GK|GF) has_refuse=1 ;;
            *) has_unknown=1 ;;
        esac
    done
    if [ "$has_refuse" -eq 1 ]; then
        cat <<MULTI_REFUSE
${RED}${BOLD}⛔ UNSUPPORTED NVIDIA GENERATION IN MULTI-GPU SYSTEM${NC}

At least one detected GPU (${DETECTED_ALL_PREFIXES}) is Kepler/Fermi class.
The maintained main/580xx branches do not support it, and the proprietary
RPM globally suppresses nouveau. Installing would therefore strand that GPU.
The --force-branch option deliberately cannot override this maintained-driver policy.
MULTI_REFUSE
        return_to_menu_prompt
        exit 1
    elif [ "$has_unknown" -eq 1 ] && [ -z "$FORCE_BRANCH" ]; then
        echo "${YELLOW}At least one NVIDIA GPU has an unknown codename (${DETECTED_ALL_PREFIXES}).${NC}"
        echo "Re-run with --force-branch=main or --force-branch=580xx only after verifying support."
        return_to_menu_prompt
        exit 1
    elif [ "$has_blackwell" -eq 1 ] && [ "$has_580xx" -eq 1 ]; then
        cat <<BLACKWELL_MIXED
${RED}${BOLD}⛔ BLACKWELL + LEGACY MODULE-FLAVOR CONFLICT${NC}

Blackwell requires NVIDIA's open kernel module. Maxwell/Pascal/Volta require
the proprietary module flavor supplied by the legacy-capable R580 package.
Because the proprietary install globally suppresses nouveau, neither branch
can safely cover this inventory and --force-branch cannot override it.
BLACKWELL_MIXED
        return_to_menu_prompt
        exit 1
    elif [ "$has_blackwell" -eq 1 ] && [ "$FORCE_BRANCH" = 580xx ]; then
        cat <<BLACKWELL_R580
${RED}${BOLD}⛔ BLACKWELL CANNOT USE THE R580 OVERRIDE${NC}

At least one detected GPU is Blackwell, which requires NVIDIA's open kernel
module. The legacy-capable R580 package uses the proprietary module flavor.
An unknown second GPU does not make that known incompatibility overridable.
BLACKWELL_R580
        return_to_menu_prompt
        exit 1
    elif [ "$has_580xx" -eq 1 ] && [ "$FORCE_BRANCH" = main ]; then
        cat <<MIXED_MAIN
${RED}${BOLD}⛔ MAIN BRANCH CANNOT COVER THIS MIXED INVENTORY${NC}

At least one detected GPU is Maxwell/Pascal/Volta, which the current main
branch excludes. A global NVIDIA install also suppresses nouveau, so
--force-branch=main would knowingly strand that legacy GPU. An unknown second
GPU does not make this known incompatibility overridable.

R580 supports Maxwell/Pascal/Volta and also specific Turing/Ampere/Ada
products, but support is product-specific. Verify every exact PCI product
against NVIDIA's R580 supported-products list before using
--force-branch=580xx.
MIXED_MAIN
        return_to_menu_prompt
        exit 1
    elif [ "$has_main" -eq 1 ] && [ "$has_580xx" -eq 1 ] \
            && [ -z "$FORCE_BRANCH" ]; then
        cat <<MIXED
${RED}${BOLD}⛔ MIXED NVIDIA GENERATIONS DETECTED${NC}

Your system has ${DETECTED_NVIDIA_COUNT} NVIDIA GPUs spanning ${BOLD}different
driver branches${NC} (generation prefixes: ${DETECTED_ALL_PREFIXES}):
  - mainline branch (Blackwell/Ada/Ampere/Turing) → akmod-nvidia
  - legacy-LTS branch (Volta/Pascal/Maxwell)      → akmod-nvidia-580xx

No safe branch can be selected from generation prefixes alone. The current
main branch excludes the legacy GPU. R580 covers Maxwell/Pascal/Volta and
specific Turing/Ampere/Ada products, but its newer-product coverage must be
checked by exact PCI product; a generation label is not sufficient evidence.

Options:
  1. Use Nouveau/Mesa for both (current default — recommended for dual-gen)
  2. Verify every exact GPU in NVIDIA's R580 supported-products list, then use:
       noid-nvidia-install.sh --force-branch=580xx
     This is an explicit reviewed override; the helper cannot derive product
     support from these codename prefixes.
  3. Physically remove one GPU (hardware solution).

MIXED
        return_to_menu_prompt
        exit 1
    elif [ -n "$FORCE_BRANCH" ] && \
            { [ "$has_main" -eq 1 ] && [ "$has_580xx" -eq 1 ] || \
              [ "$has_unknown" -eq 1 ]; }; then
        echo "${YELLOW}Advanced multi-GPU override selected: ${FORCE_BRANCH}.${NC}"
        if [ "$has_main" -eq 1 ] && [ "$has_580xx" -eq 1 ]; then
            echo "You confirmed every exact GPU against NVIDIA's R580 supported-products list."
        else
            echo "Only GPUs supported by that branch are expected to work; no automatic nouveau fallback is promised."
        fi
        echo
    elif [ "$has_main" -eq 1 ] && [ "$has_580xx" -eq 0 ] \
            && [ "$has_unknown" -eq 0 ]; then
        echo "${YELLOW}Multiple NVIDIA GPUs detected (${DETECTED_NVIDIA_COUNT}), all mainline-compatible.${NC}"
        echo "Proceeding with mainline branch (akmod-nvidia) — covers all detected GPUs."
        echo
    elif [ "$has_580xx" -eq 1 ] && [ "$has_main" -eq 0 ] \
            && [ "$has_unknown" -eq 0 ]; then
        echo "${YELLOW}Multiple NVIDIA GPUs detected (${DETECTED_NVIDIA_COUNT}), all legacy-LTS-compatible.${NC}"
        echo "Proceeding with 580xx branch — covers all detected GPUs."
        echo
    fi
fi

# --- REFUSE PATH for Kepler/Fermi ------------------------------------------
if [ "$gen_branch" = "REFUSE" ]; then
    cat <<REFUSE
${RED}${BOLD}⛔ REFUSING TO INSTALL${NC}

Your GPU is ${gen_name} ${gen_year}. NVIDIA's last supported driver
for this generation is ${RED}470.xx (Kepler) / 390.xx (Fermi)${NC} —
those legacy branches are outside this image's maintained-driver policy;
vendor security and current-kernel compatibility are not assured here.

Running an out-of-tree module outside the accepted maintenance policy
contradicts the security posture of this hardened image.

${BOLD}Your system already has the in-tree Nouveau/Mesa path${NC}, which:
  - Uses the in-tree kernel driver
  - Retains Mesa's generation-supported userspace (NVK supports Kepler+)
  - Uses the kernel/Mesa upstream maintenance path
  - Can support normal desktop rendering; exact Vulkan/media/game support varies

This is the correct driver for your hardware in 2026.

For a workload that the in-tree stack cannot support, use supported hardware;
prices and availability are outside this installer's security decision.

Docs: /usr/share/doc/noid-privacy/19-nvidia-drivers.md
REFUSE
    return_to_menu_prompt
    exit 1
fi

# --- Branch override -------------------------------------------------------
# Apply the documented escape hatch after the non-overridable Kepler/Fermi
# policy gate, but before UNKNOWN/mixed-family bail-outs consume it.
auto_branch="$gen_branch"
if [ -n "$FORCE_BRANCH" ]; then
    # A force option is an escape hatch for an unknown adapter or for an
    # explicitly disclosed mixed/partly unknown multi-GPU topology. It must
    # never turn an unambiguous all-main or all-R580 inventory into a known
    # incompatible package plan.
    advanced_multi_override=0
    if [ "${DETECTED_NVIDIA_COUNT:-1}" -gt 1 ] \
            && { [ "${has_unknown:-0}" -eq 1 ] \
                || { [ "${has_main:-0}" -eq 1 ] \
                    && [ "${has_580xx:-0}" -eq 1 ]; }; }; then
        advanced_multi_override=1
    fi
    if [ "$auto_branch" != UNKNOWN ] \
            && [ "$FORCE_BRANCH" != "$auto_branch" ] \
            && [ "$advanced_multi_override" -eq 0 ]; then
        echo "${RED}ERROR${NC}: --force-branch=${FORCE_BRANCH} conflicts with the detected ${gen_name} ${gen_year} GPU inventory." >&2
        echo "The detected adapters require --force-branch=${auto_branch}; refusing a known-incompatible driver plan." >&2
        return_to_menu_prompt
        exit 1
    fi
    echo "${YELLOW}Branch override: using ${FORCE_BRANCH} (auto-detected: ${auto_branch})${NC}"
    gen_branch="$FORCE_BRANCH"
fi

# --- REFUSE PATH for unknown codename --------------------------------------
if [ "$gen_branch" = "UNKNOWN" ]; then
    echo "${YELLOW}Unknown NVIDIA codename '${DETECTED_CODENAME}' — cannot auto-select branch.${NC}"
    echo
    echo "You may force a branch manually if you know which NVIDIA driver"
    echo "series supports your GPU:"
    echo "  noid-nvidia-install.sh --force-branch=main     (Turing/Ampere/Ada/Blackwell)"
    echo "  noid-nvidia-install.sh --force-branch=580xx    (Maxwell/Pascal/Volta)"
    echo
    echo "See /usr/share/doc/noid-privacy/19-nvidia-drivers.md for the full"
    echo "per-generation matrix."
    return_to_menu_prompt
    exit 1
fi

# --- Branch selection ------------------------------------------------------
COMMON_NVIDIA_REPOS="fedora,updates,rpmfusion-free,rpmfusion-free-updates,rpmfusion-nonfree,rpmfusion-nonfree-updates"
case "$gen_branch" in
    main)
        AKMOD_PKG="akmod-nvidia"
        CUDA_PKG="xorg-x11-drv-nvidia-cuda"
        NVIDIA_DNF_REPOS="${COMMON_NVIDIA_REPOS},rpmfusion-nonfree-nvidia-driver"
        ;;
    580xx)
        AKMOD_PKG="akmod-nvidia-580xx"
        CUDA_PKG="xorg-x11-drv-nvidia-580xx-cuda"
        NVIDIA_DNF_REPOS="$COMMON_NVIDIA_REPOS"
        ;;
    *)
        echo "${RED}ERROR${NC}: internal branch mismatch ($gen_branch)" >&2
        exit 1
        ;;
esac
NVIDIA_INSTALL_MANIFEST=(akmods "$AKMOD_PKG" "$CUDA_PKG")
AKMOD_NAME="${AKMOD_PKG#akmod-}"

# A dry-run must stay sudo-free and must never consult or mutate the host RPMDB.
if [ "$MODE" = "dry-run" ]; then
    fmt_step 1 1 "Resolved install plan"
    cat <<DRYPLAN
Branch: ${gen_branch}
Packages: ${NVIDIA_INSTALL_MANIFEST[*]}
Repositories: ${NVIDIA_DNF_REPOS}
The real run performs an --assumeno solver gate before any package transaction.
DRYPLAN
    return_to_menu_prompt
    exit 0
fi

# Refuse cross-branch residue. Switching branches is an explicit rollback then
# fresh-install operation; never ask DNF to erase or replace a live graphics
# stack implicitly.
if ! query_installed_nvidia_rpm_names; then
    exit 1
fi
installed_nvidia_names=("${NVIDIA_RPM_NAMES[@]}")
opposite_branch_packages=()
for nv_pkg in "${installed_nvidia_names[@]}"; do
    case "$gen_branch:$nv_pkg" in
        main:*580xx*) opposite_branch_packages+=("$nv_pkg") ;;
        580xx:*580xx*) ;;
        580xx:akmod-nvidia|580xx:akmod-nvidia-open|580xx:kmod-nvidia|580xx:kmod-nvidia-*|580xx:xorg-x11-drv-nvidia|580xx:xorg-x11-drv-nvidia-*)
            opposite_branch_packages+=("$nv_pkg") ;;
    esac
done
if [ "${#opposite_branch_packages[@]}" -gt 0 ]; then
    echo "${RED}ERROR${NC}: packages from the opposite NVIDIA branch are installed:" >&2
    printf '  %s\n' "${opposite_branch_packages[@]}" >&2
    echo "Run noid-nvidia-install.sh --rollback, reboot into nouveau, then install the selected branch." >&2
    exit 1
fi

# --- Already-installed state -----------------------------------------------
# Do not short-circuit here. A repeated helper run deliberately re-verifies the
# exact module/certificate/package identity, republishes the persistent update
# hooks and reapplies the user-selected suspend policy. An already coherent
# running-kernel module is not rebuilt; a failed integrity gate gets one
# explicit serialized repair build.
manifest_preinstalled=0
if sudo rpm -q "$AKMOD_PKG" "$CUDA_PKG" >/dev/null 2>&1; then
    manifest_preinstalled=1
    echo "${GREEN}Already installed:${NC} the complete ${gen_branch} manifest is present."
    echo "This run will verify it, repair only if needed, and reapply all NoID Privacy NVIDIA postconditions."
fi

# --- Informed consent prompt -----------------------------------------------
cat <<PLAN
${BOLD}${CYAN}Install plan:${NC}

  1. Resolve the exact package plan and create a pre-change snapshot
  2. Generate the MOK signing key first, then install
     $AKMOD_PKG $CUDA_PKG  (branch-coherent userspace + signed module)
  3. Wait for the native akmods build and verify the exact signed module set
  4. Verify plymouth.use-simpledrm=1 in kernel cmdline (LUKS-prompt
     visibility — added by Module 01 only when NVIDIA was detected during OS
     installation; this helper adds it otherwise)
  5. Confirm the exact signing certificate used by every NVIDIA module
  6. Check whether that certificate is enrolled; if not, request its MOK import
     (you will set and confirm a one-time enrollment password), then reboot

PLAN

echo
echo "${YELLOW}Reminder: SAVE & CLOSE your apps now — new apps may not relaunch until the reboot.${NC}"
read -rp "Proceed with install? [y/N] " ans
case "${ans:-n}" in
    [yY]|[yY][eE][sS]) ;;
    *) echo "Cancelled."; return_to_menu_prompt; exit 0 ;;
esac

# Resolve the complete explicit manifest before changing the RPM database. DNF5
# returns 1 for the expected --assumeno refusal after a successful solve; accept
# only that exact state (or rc=0 when the full manifest is already installed).
fmt_step 1 6 "Resolve exact package plan"
fmt_info "Refreshing only the repositories required by the selected branch"
solver_rc=0
solver_output=$(run_system_root /usr/bin/env LC_ALL=C /usr/bin/dnf --assumeno --refresh \
    --setopt=install_weak_deps=False --repo="$NVIDIA_DNF_REPOS" \
    install "${NVIDIA_INSTALL_MANIFEST[@]}" 2>&1) || solver_rc=$?
if [ "$solver_rc" -eq 1 ] \
        && grep -qF 'Transaction Summary:' <<<"$solver_output" \
        && grep -qF 'Operation aborted by the user.' <<<"$solver_output" \
        && ! grep -qE 'Failed to resolve|Problem:' <<<"$solver_output"; then
    echo "  [OK] branch-coherent package manifest resolved without mutation"
elif [ "$solver_rc" -eq 0 ] \
        && sudo rpm -q "${NVIDIA_INSTALL_MANIFEST[@]}" >/dev/null 2>&1; then
    echo "  [OK] complete branch-coherent package manifest is already installed"
else
    echo "${RED}ERROR${NC}: NVIDIA package solver rejected the exact ${gen_branch} manifest." >&2
    printf '%s\n' "$solver_output" >&2
    echo "No NVIDIA package transaction was started." >&2
    exit 1
fi

fmt_info "Creating a pre-install snapshot before repository or boot changes"
begin_boot_mutation

if ! command -v noid-snap-pre >/dev/null 2>&1 \
        || ! sudo noid-snap-pre "NVIDIA proprietary driver install (${gen_branch})"; then
    echo "${RED}ERROR${NC}: pre-install snapshot failed; no repository was changed." >&2
    exit 1
fi

# --- Step 2: prepare MOK signing key, then install driver ------------------
fmt_step 2 6 "Prepare signing key + install ${AKMOD_PKG}"
# Persist only the repository state required by the selected branch. M08 ships
# the special main-driver repository disabled (privacy default). Main enables it
# for future updates; 580xx keeps it disabled because legacy updates come from
# rpmfusion-nonfree-updates. The scoped DNF transaction below does not depend on
# this persistent setting.
#
# Section-aware sed — update enabled ONLY
# inside the [rpmfusion-nonfree-nvidia-driver] block (between this section
# header and the next ^[ header line). Earlier bug: blanket
# `s/^enabled=0$/enabled=1/` also enabled the -debuginfo + -source subrepos,
# which 08-service-min's third-party-repos heredoc explicitly says must stay
# enabled=0 ("they only matter to developers debugging crashes; never needed
# at runtime") — search M08 source for rpmfusion-nonfree-nvidia-driver-debuginfo.
# `dnf config-manager --set-enabled` would also work — sed kept for offline
# build chroot where dnf metadata may not be loaded yet.
if [ "$gen_branch" = main ]; then
    NVIDIA_REPO_ENABLED=1
else
    NVIDIA_REPO_ENABLED=0
fi
if ! set_nvidia_repo_state "$NVIDIA_REPO_ENABLED"; then
    echo "${RED}ERROR${NC}: could not set the NoID Privacy-owned NVIDIA repository state." >&2
    exit 1
fi
# CRITICAL ORDERING: the MOK signing key MUST exist on disk BEFORE
# akmod-nvidia is installed. The akmod build runs in the RPM %posttrans (async),
# and brp-kmodsign signs the .ko ONLY if /etc/pki/akmods/private/private_key.priv
# is present AT BUILD TIME. On a fresh install that dir is empty, so generate the
# key first: (1) pull just the akmods framework (ships kmodgenca; no build yet),
# (2) create the key, (3) THEN install akmod-nvidia so its first build is signed.
# This is the Fedora/RPM-Fusion-documented order.
publish_managed_dnf_marker || {
    echo "${RED}ERROR${NC}: could not publish the validated NVIDIA DNF marker." >&2
    exit 1
}
run_system_root /usr/bin/dnf --setopt=install_weak_deps=False \
    --repo="$NVIDIA_DNF_REPOS" install -y akmods
if sudo test -f /etc/pki/akmods/certs/public_key.der; then
    fmt_ok "MOK signing key already present; build will be signed"
else
    sudo kmodgenca -a
    fmt_ok "MOK signing key generated; build will be signed"
fi

# Initial driver installation adds nouveau/NVIDIA arguments through the RPM
# scriptlets. Invalidate only a currently exact M01 seal immediately before
# that mutation, then synchronously publish new byte-bound evidence regardless
# of whether DNF succeeds or fails part-way through the transaction.
#
# The akmod package's %posttrans starts its first build asynchronously. Create
# the freshness marker before that transaction so the native result itself can
# satisfy the authoritative gate; do not start a second forced build beside it.
build_marker=$(sudo mktemp /run/noid-nvidia-build.XXXXXX)
sudo /usr/libexec/noid-firstboot-cmdline-transition \
    --invalidate-nvidia-install
driver_dnf_rc=0
run_system_root /usr/bin/dnf --setopt=install_weak_deps=False \
    --repo="$NVIDIA_DNF_REPOS" \
    install -y "$AKMOD_PKG" "$CUDA_PKG" || driver_dnf_rc=$?
marker_cleanup_rc=0
remove_managed_dnf_marker || marker_cleanup_rc=$?
driver_context="NVIDIA package installation"
if [ "$driver_dnf_rc" -ne 0 ]; then
    driver_context="failed NVIDIA package installation"
elif [ "$marker_cleanup_rc" -ne 0 ]; then
    driver_context="NVIDIA package installation with invalid runtime-marker cleanup"
fi
if ! reconcile_firstboot_cmdline_evidence "$driver_context"; then
    exit 1
fi
if [ "$driver_dnf_rc" -ne 0 ]; then
    echo "${RED}ERROR${NC}: NVIDIA package installation failed (exit ${driver_dnf_rc})." >&2
    exit "$driver_dnf_rc"
fi
if [ "$marker_cleanup_rc" -ne 0 ]; then
    echo "${RED}ERROR${NC}: NVIDIA package installation completed, but its runtime marker could not be removed safely." >&2
    exit 1
fi
fmt_ok "branch-coherent packages installed"

# Install one fail-closed verifier and use the same bytes for the initial build,
# later kernel/driver rebuilds and post-reboot evidence. A non-empty sig_id is
# not identity: the verifier binds all four NVIDIA modules to the exact akmods
# certificate serial, selected branch, kmod owner EVR, userspace EVR and kernel.
sudo install -d -m 0755 /usr/libexec /var/lib/noid-nvidia-integrity
sudo tee /usr/libexec/noid-nvidia-verify >/dev/null <<'VERIFY_NV_EOF'
#!/bin/bash
# Verify one complete NVIDIA kernel-module set against the installed RPM branch
# and the exact local akmods certificate. Read-only; emits a compact evidence
# record on success. `--newer-than FILE` requires every module file to be newer
# than the build-start marker; `--require-enrolled` additionally binds the exact
# certificate to the live MOK trust state.
set -euo pipefail

fail() {
    echo "noid-nvidia-verify: $*" >&2
    exit 1
}
normalize_hex() {
    tr -d '[:space:]:' | tr '[:lower:]' '[:upper:]'
}

[ "$(id -u)" -eq 0 ] || fail "must run as root"
kver="${1:-}"
case "$kver" in
    ''|[!A-Za-z0-9]*|*[!A-Za-z0-9._+-]*) fail "invalid kernel release" ;;
esac
shift
freshness_marker=''
require_enrolled=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --newer-than)
            [ "$#" -ge 2 ] || fail "--newer-than requires a marker path"
            freshness_marker="$2"
            shift 2
            ;;
        --require-enrolled)
            require_enrolled=1
            shift
            ;;
        *) fail "unknown argument: $1" ;;
    esac
done
if [ -n "$freshness_marker" ] && [ ! -f "$freshness_marker" ]; then
    fail "freshness marker is absent: $freshness_marker"
fi

cert=/etc/pki/akmods/certs/public_key.der
[ -r "$cert" ] || fail "akmods public certificate is absent or unreadable"
cert_serial=$(openssl x509 -inform DER -in "$cert" -noout -serial 2>/dev/null \
    | sed 's/^serial=//' | normalize_hex)
[ -n "$cert_serial" ] || fail "could not read akmods certificate serial"
if [ "$require_enrolled" -eq 1 ]; then
    mok_result=$(env LC_ALL=C mokutil --test-key "$cert" 2>&1 || true)
    grep -qF ' is already enrolled' <<<"$mok_result" \
        || fail "exact akmods certificate is not enrolled"
fi

main_akmod=0; main_cuda=0; legacy_akmod=0; legacy_cuda=0
rpm -q akmod-nvidia >/dev/null 2>&1 && main_akmod=1
rpm -q xorg-x11-drv-nvidia-cuda >/dev/null 2>&1 && main_cuda=1
rpm -q akmod-nvidia-580xx >/dev/null 2>&1 && legacy_akmod=1
rpm -q xorg-x11-drv-nvidia-580xx-cuda >/dev/null 2>&1 && legacy_cuda=1

if [ "$main_akmod" -eq 1 ] && [ "$main_cuda" -eq 1 ] \
        && [ "$legacy_akmod" -eq 0 ] && [ "$legacy_cuda" -eq 0 ]; then
    branch=main
    akmod_pkg=akmod-nvidia
    cuda_pkg=xorg-x11-drv-nvidia-cuda
    expected_kmod="kmod-nvidia-${kver}"
    expected_module_license='Dual MIT/GPL'
elif [ "$legacy_akmod" -eq 1 ] && [ "$legacy_cuda" -eq 1 ] \
        && [ "$main_akmod" -eq 0 ] && [ "$main_cuda" -eq 0 ]; then
    branch=580xx
    akmod_pkg=akmod-nvidia-580xx
    cuda_pkg=xorg-x11-drv-nvidia-580xx-cuda
    expected_kmod="kmod-nvidia-580xx-${kver}"
    expected_module_license='NVIDIA'
else
    fail "partial, mixed or missing NVIDIA akmod/CUDA branch"
fi

q_evr='%{EPOCHNUM}:%{VERSION}-%{RELEASE}'
akmod_evr=$(rpm -q --qf "$q_evr" "$akmod_pkg")
cuda_evr=$(rpm -q --qf "$q_evr" "$cuda_pkg")
akmod_version=$(rpm -q --qf '%{VERSION}' "$akmod_pkg")
[ "$akmod_evr" = "$cuda_evr" ] \
    || fail "akmod/userspace EVR mismatch: $akmod_evr != $cuda_evr"

modules=(nvidia nvidia_modeset nvidia_drm nvidia_uvm)
for module in "${modules[@]}"; do
    module_path=$(modinfo -F filename "$module" -k "$kver" 2>/dev/null) \
        || fail "$module does not resolve for $kver"
    canonical_path=$(readlink -f -- "$module_path") \
        || fail "$module path cannot be canonicalized"
    case "$canonical_path" in
        "/usr/lib/modules/${kver}/extra/nvidia/"*) ;;
        *) fail "$module resolves outside the expected kernel/driver directory" ;;
    esac
    [ -f "$canonical_path" ] || fail "$module file is absent"
    # Freshness gate: prove this module was (re)built during THIS attempt. The
    # installed *.ko.xz mtime is NOT usable — Fedora clamps packaged-file mtimes
    # to SOURCE_DATE_EPOCH (the %changelog date) for reproducible builds, so a
    # freshly built module is always "older" than a just-created marker. The
    # owning kmod RPM's BUILDTIME header is excluded from that clamp and is the
    # correct fresh-build signal.
    if [ -n "$freshness_marker" ]; then
        module_buildtime=$(rpm -qf --qf '%{BUILDTIME}' "$canonical_path" 2>/dev/null || true)
        marker_mtime=$(stat -c %Y "$freshness_marker" 2>/dev/null || true)
        case "$module_buildtime" in ''|*[!0-9]*) fail "$module owning kmod BUILDTIME did not resolve" ;; esac
        case "$marker_mtime" in ''|*[!0-9]*) fail "freshness marker mtime did not resolve" ;; esac
        [ "$module_buildtime" -ge "$marker_mtime" ] \
            || fail "$module kmod was not built after this rebuild started"
    fi

    owner_record=$(rpm -qf --qf '%{NAME}|%{EPOCHNUM}:%{VERSION}-%{RELEASE}' \
        "$canonical_path" 2>/dev/null) || fail "$module file has no RPM owner"
    IFS='|' read -r owner_name owner_evr <<<"$owner_record"
    [ "$owner_name" = "$expected_kmod" ] \
        || fail "$module owner $owner_name is not $expected_kmod"
    [ "$owner_evr" = "$akmod_evr" ] \
        || fail "$module owner EVR $owner_evr is not $akmod_evr"

    module_version=$(modinfo -F version "$module" -k "$kver" 2>/dev/null)
    [ "$module_version" = "$akmod_version" ] \
        || fail "$module version $module_version is not $akmod_version"
    module_license=$(modinfo -F license "$module" -k "$kver" 2>/dev/null)
    [ "$module_license" = "$expected_module_license" ] \
        || fail "$module license $module_license is not $expected_module_license for $branch"
    module_vermagic=$(modinfo -F vermagic "$module" -k "$kver" 2>/dev/null)
    case "$module_vermagic" in
        "$kver "*) ;;
        *) fail "$module vermagic does not target $kver" ;;
    esac
    module_sig_id=$(modinfo -F sig_id "$module" -k "$kver" 2>/dev/null)
    [ "$module_sig_id" = 'PKCS#7' ] || fail "$module lacks a PKCS#7 signature"
    module_sig_key=$(modinfo -F sig_key "$module" -k "$kver" 2>/dev/null \
        | normalize_hex)
    [ "$module_sig_key" = "$cert_serial" ] \
        || fail "$module signature does not match the local akmods certificate"
done

printf 'branch=%s\nkernel=%s\nevr=%s\nmodules=verified\ncertificate=matched\n' \
    "$branch" "$kver" "$akmod_evr"
[ "$require_enrolled" -eq 0 ] || printf 'mok=enrolled\n'
VERIFY_NV_EOF
sudo chmod 0755 /usr/libexec/noid-nvidia-verify
sudo chown root:root /usr/libexec/noid-nvidia-verify /var/lib/noid-nvidia-integrity
if command -v restorecon >/dev/null 2>&1; then
    sudo restorecon -F /usr/libexec/noid-nvidia-verify \
        /var/lib/noid-nvidia-integrity || {
        echo "${RED}ERROR${NC}: SELinux relabel failed for NVIDIA integrity verifier." >&2
        exit 1
    }
fi

# M21 is the canonical writer for every later initramfs. Its candidate gate
# verifies exact NVIDIA bytes before publication; this M19-owned bridge then
# keeps only mutable pre-reboot evidence bound to that newly published image.
# Historical *.active evidence describes an image that actually booted and
# must never be rewritten after the fact.
sudo tee /usr/libexec/noid-nvidia-rebind-evidence >/dev/null <<'REBIND_NV_EOF'
#!/bin/bash
set -euo pipefail
umask 077

STATE_DIR=${NOID_TEST_STATE_DIR:-/var/lib/noid-nvidia-integrity}
BOOT_DIR=${NOID_TEST_BOOT_DIR:-/boot}
VERIFY=${NOID_TEST_VERIFY:-/usr/libexec/noid-nvidia-verify}
EXPECTED_OWNER=${NOID_TEST_OWNER:-root:root}
tmp=''

cleanup() {
    rm -f -- "${tmp:-}"
}
trap cleanup EXIT INT TERM HUP

fail() {
    echo "noid-nvidia-rebind-evidence: $*" >&2
    exit 1
}

read_identity() {
    local require_enrolled=$1 output evr expected_fields
    local -a fields=()
    if [ "$require_enrolled" -eq 1 ]; then
        output=$("$VERIFY" "$kver" --require-enrolled) \
            || fail "current enrolled NVIDIA identity is invalid"
    else
        output=$("$VERIFY" "$kver") \
            || fail "current NVIDIA identity is invalid"
    fi
    mapfile -t fields <<<"$output"
    expected_fields=5
    [ "$require_enrolled" -eq 0 ] || expected_fields=6
    [ "${#fields[@]}" -eq "$expected_fields" ] \
        || fail "current NVIDIA identity schema is invalid"
    case "${fields[0]}" in branch=main|branch=580xx) ;; *)
        fail "current NVIDIA branch identity is invalid" ;;
    esac
    [ "${fields[1]}" = "kernel=$kver" ] \
        || fail "current NVIDIA kernel identity is invalid"
    evr=${fields[2]#evr=}
    [ "${fields[2]}" = "evr=$evr" ] && [ -n "$evr" ] \
        || fail "current NVIDIA package identity is invalid"
    case "$evr" in *[!A-Za-z0-9._:+~-]*)
        fail "current NVIDIA package identity is unsafe" ;;
    esac
    [ "${fields[3]}" = modules=verified ] \
        && [ "${fields[4]}" = certificate=matched ] \
        || fail "current NVIDIA verification fields are invalid"
    if [ "$require_enrolled" -eq 1 ]; then
        [ "${fields[5]}" = mok=enrolled ] \
            || fail "current NVIDIA enrollment identity is invalid"
    fi
    printf '%s\n' "$output"
}

[ "${NOID_TEST_MODE:-0}" = 1 ] || [ "$(id -u)" -eq 0 ] \
    || fail "must run as root"
[ "$#" -eq 1 ] || fail "usage: noid-nvidia-rebind-evidence KERNEL"
kver=$1
case "$kver" in
    ''|[!A-Za-z0-9]*|*[!A-Za-z0-9._+-]*) fail "invalid kernel release" ;;
esac
[ -d "$STATE_DIR" ] && [ ! -L "$STATE_DIR" ] \
    || fail "state directory is missing or unsafe"
[ "$(stat -c '%U:%G:%a' "$STATE_DIR" 2>/dev/null)" \
        = "$EXPECTED_OWNER:755" ] \
    || fail "state directory ownership or mode is invalid"
[ -x "$VERIFY" ] && [ -f "$VERIFY" ] && [ ! -L "$VERIFY" ] \
    || fail "NVIDIA identity verifier is missing or unsafe"
[ "$(stat -c '%U:%G:%a:%h' "$VERIFY" 2>/dev/null)" \
        = "$EXPECTED_OWNER:755:1" ] \
    || fail "NVIDIA identity verifier ownership or mode is invalid"

image="$BOOT_DIR/initramfs-${kver}.img"
[ -f "$image" ] && [ ! -L "$image" ] \
    || fail "published initramfs is missing or unsafe"
[ "$(stat -c '%U:%G:%a:%h' "$image" 2>/dev/null)" \
        = "$EXPECTED_OWNER:600:1" ] \
    || fail "published initramfs ownership or mode is invalid"
image_hash=$(sha256sum "$image" 2>/dev/null | awk '{print $1}')
[[ "$image_hash" =~ ^[0-9a-f]{64}$ ]] \
    || fail "published initramfs hash is invalid"

rebind_record() {
    local record=$1 suffix=$2 old_hash boot_id mok_state verify_output evr
    local enrolled_output
    local -a lines=()
    [ -f "$record" ] && [ ! -L "$record" ] \
        || fail "${suffix} evidence is missing or unsafe"
    [ "$(stat -c '%U:%G:%a:%h' "$record" 2>/dev/null)" \
            = "$EXPECTED_OWNER:600:1" ] \
        || fail "${suffix} evidence ownership or mode is invalid"
    mapfile -t lines <"$record" \
        || fail "cannot read ${suffix} evidence"

    case "$suffix" in
        ready)
            [ "${#lines[@]}" -eq 8 ] && [ "$(wc -l <"$record")" -eq 8 ] \
                || fail "ready evidence does not have the exact schema"
            [ "${lines[0]}" = status=ready ] \
                || fail "ready evidence status is invalid"
            case "${lines[1]}" in branch=main|branch=580xx) ;; *)
                fail "ready evidence branch is invalid" ;;
            esac
            [ "${lines[2]}" = "kernel=$kver" ] \
                || fail "ready evidence kernel is invalid"
            evr=${lines[3]#evr=}
            [ "${lines[3]}" = "evr=$evr" ] && [ -n "$evr" ] \
                || fail "ready evidence package identity is invalid"
            case "$evr" in *[!A-Za-z0-9._:+~-]*)
                fail "ready evidence package identity is unsafe" ;;
            esac
            [ "${lines[4]}" = modules=verified ] \
                && [ "${lines[5]}" = certificate=matched ] \
                && [ "${lines[6]}" = mok=enrolled ] \
                || fail "ready evidence verification fields are invalid"
            old_hash=${lines[7]#initramfs_sha256=}
            [[ "$old_hash" =~ ^[0-9a-f]{64}$ ]] \
                || fail "ready evidence initramfs hash is invalid"
            verify_output=$(read_identity 1)
            tmp=$(mktemp "$STATE_DIR/.ready-rebind.XXXXXX") \
                || fail "cannot allocate ready evidence candidate"
            {
                printf 'status=ready\n'
                printf '%s\n' "$verify_output"
                printf 'initramfs_sha256=%s\n' "$image_hash"
            } >"$tmp"
            ;;
        prepared)
            [ "${#lines[@]}" -eq 9 ] && [ "$(wc -l <"$record")" -eq 9 ] \
                || fail "prepared evidence does not have the exact schema"
            [ "${lines[0]}" = status=prepared-awaiting-reboot-validation ] \
                || fail "prepared evidence status is invalid"
            case "${lines[1]}" in branch=main|branch=580xx) ;; *)
                fail "prepared evidence branch is invalid" ;;
            esac
            [ "${lines[2]}" = "kernel=$kver" ] \
                || fail "prepared evidence kernel is invalid"
            evr=${lines[3]#evr=}
            [ "${lines[3]}" = "evr=$evr" ] && [ -n "$evr" ] \
                || fail "prepared evidence package identity is invalid"
            case "$evr" in *[!A-Za-z0-9._:+~-]*)
                fail "prepared evidence package identity is unsafe" ;;
            esac
            [ "${lines[4]}" = modules=verified ] \
                && [ "${lines[5]}" = certificate=matched ] \
                || fail "prepared evidence verification fields are invalid"
            old_hash=${lines[6]#initramfs_sha256=}
            [[ "$old_hash" =~ ^[0-9a-f]{64}$ ]] \
                || fail "prepared evidence initramfs hash is invalid"
            boot_id=${lines[7]#prepared_boot_id=}
            [[ "$boot_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] \
                && [ "${lines[7]}" = "prepared_boot_id=$boot_id" ] \
                || fail "prepared evidence boot ID is invalid"
            case "${lines[8]}" in
                mok=pending-enrollment) mok_state=pending-enrollment ;;
                mok=enrolled) mok_state=enrolled ;;
                *) fail "prepared evidence MOK state is invalid" ;;
            esac
            verify_output=$(read_identity 0)
            if [ "$mok_state" = enrolled ]; then
                enrolled_output=$(read_identity 1)
                [ "$enrolled_output" = "${verify_output}"$'\n'mok=enrolled ] \
                    || fail "current enrolled NVIDIA identity changed between checks"
            fi
            tmp=$(mktemp "$STATE_DIR/.prepared-rebind.XXXXXX") \
                || fail "cannot allocate prepared evidence candidate"
            {
                printf 'status=prepared-awaiting-reboot-validation\n'
                printf '%s\n' "$verify_output"
                printf 'initramfs_sha256=%s\n' "$image_hash"
                printf 'prepared_boot_id=%s\n' "$boot_id"
                printf 'mok=%s\n' "$mok_state"
            } >"$tmp"
            ;;
        *) fail "internal evidence selector is invalid" ;;
    esac

    if cmp -s "$tmp" "$record"; then
        rm -f -- "$tmp"
        tmp=''
        return 0
    fi
    chmod 0600 "$tmp"
    sync -- "$tmp"
    mv -fT -- "$tmp" "$record"
    tmp=''
    sync -- "$record"
    sync -- "$STATE_DIR"
    printf 'NoID Privacy: rebound NVIDIA %s evidence for %s.\n' \
        "$suffix" "$kver"
}

ready_record="$STATE_DIR/${kver}.ready"
prepared_record="$STATE_DIR/${kver}.prepared"
if [ -e "$prepared_record" ] || [ -L "$prepared_record" ]; then
    # Prepared is the stronger state: it retains the originating boot ID and
    # requires a different-boot live verification before activation becomes
    # trusted. Validate/rebind it first, then retire any ready record left by
    # the former non-exclusive writers. A malformed prepared record remains a
    # hard failure and leaves both files intact for review.
    rebind_record "$prepared_record" prepared
    if [ -e "$ready_record" ] || [ -L "$ready_record" ]; then
        rm -f -- "$ready_record" \
            || fail "cannot retire superseded ready evidence for ${kver}"
        sync -- "$STATE_DIR"
        printf 'NoID Privacy: retired superseded NVIDIA ready evidence for %s.\n' \
            "$kver"
    fi
elif [ -e "$ready_record" ] || [ -L "$ready_record" ]; then
    rebind_record "$ready_record" ready
fi
REBIND_NV_EOF

# --- Step 3: build the akmod kernel module (precheck + authoritative verify) -
fmt_step 3 6 "Build + verify NVIDIA kernel modules"
if [ "$manifest_preinstalled" -eq 1 ]; then
    fmt_info "Verifying the current module set; a rebuild runs only if integrity repair is required."
else
    fmt_info "Waiting for RPM Fusion's single native post-transaction build; no duplicate rebuild is started."
fi
fmt_info "The serialized native build can take several minutes; live akmods output follows when its build lock is available."
kver=$(uname -r)
exact_kmod="kmod-${AKMOD_NAME}-${kver}"

# Pre-build gate: akmods runs the compile as the UNPRIVILEGED
# 'akmods' user. It needs the kernel-devel build tree AND traversal access down
# /usr/src. A missing kernel-devel OR a 0700 /usr/src (older M10 dir-harden)
# makes akmods report "directories missing" while STILL exiting 0 — which would
# silently carry us to MOK + reboot with no module = black screen. Gate on the
# build tree being readable by the akmods user BEFORE trusting any build.
BUILD_TREE="/usr/src/kernels/${kver}"
if ! sudo -u akmods test -r "${BUILD_TREE}/Makefile" 2>/dev/null; then
    echo
    echo "  ${RED}[FAIL]${NC} kernel build tree not accessible to the akmods build user:"
    echo "    ${BUILD_TREE}/Makefile  (unreadable as user 'akmods')"
    if [ ! -d "${BUILD_TREE}" ]; then
        echo "  Cause: kernel-devel for the running kernel is missing."
        echo "  Fix:   sudo dnf install kernel-devel-${kver}"
    else
        echo "  Cause: a parent dir (likely /usr/src) is not traversable by 'akmods'"
        echo "         (/usr/src mode $(stat -c '%a' /usr/src 2>/dev/null) — needs 0755)."
        echo "  Fix:   sudo chmod 0755 /usr/src"
    fi
    echo "  Then re-run this installer."
    return_to_menu_prompt
    exit 1
fi

# The akmod package's native %posttrans build is asynchronous. All vendor
# builders serialize on /run/akmods/akmods.lock; wait on that exact lock, then
# run plain branch-scoped akmods. Whichever process wins builds once, and the
# later process sees the current kmod and does not rebuild it.
#
# Repeated helper runs accept an already coherent module set without an
# artificial rebuild. A fresh/partial install still requires a kmod BUILDTIME
# at or after the pre-transaction marker. Only a failed first integrity gate
# gets one branch-scoped repair attempt after serialization: install semantics
# for a missing exact kmod, rebuild/reinstall semantics for an installed one.
# Both attempts reject fresh *.failed.log evidence because akmods can return
# zero even when one individual build failed.
NVIDIA_STATE_DIR=/var/lib/noid-nvidia-integrity
mark_nvidia_degraded() {
    local reason="$1" degraded_tmp
    reason=${reason//$'\n'/; }
    degraded_tmp=$(sudo mktemp "$NVIDIA_STATE_DIR/.degraded.XXXXXX") \
        || return 1
    if ! printf 'status=degraded\nkernel=%s\nreason=%s\n' "$kver" "$reason" \
            | sudo tee "$degraded_tmp" >/dev/null \
            || ! sudo chmod 0600 "$degraded_tmp" \
            || ! sudo sync -- "$degraded_tmp" \
            || ! sudo mv -fT -- "$degraded_tmp" "$NVIDIA_STATE_DIR/degraded" \
            || ! sudo sync -- "$NVIDIA_STATE_DIR/degraded" \
            || ! sudo sync -- "$NVIDIA_STATE_DIR"; then
        sudo rm -f -- "$degraded_tmp"
        return 1
    fi
}
printf 'status=building\nkernel=%s\n' "$kver" \
    | sudo tee "$NVIDIA_STATE_DIR/pending" >/dev/null
sudo chmod 0600 "$NVIDIA_STATE_DIR/pending"

akmods_rc=0
if ! run_system_root /usr/bin/flock -w 900 \
        /run/akmods/akmods.lock /usr/bin/true; then
    akmods_rc=124
else
    run_system_root /usr/bin/akmods \
        --kernels "$kver" --akmod "$AKMOD_NAME" \
        || akmods_rc=$?
fi
new_failure_log=$(sudo find /var/cache/akmods -type f -name '*.failed.log' \
    -path '*nvidia*' -newer "$build_marker" -print -quit 2>/dev/null || true)
verify_output=''
verify_rc=0
if [ "$akmods_rc" -eq 0 ] && [ -z "$new_failure_log" ]; then
    if [ "$manifest_preinstalled" -eq 1 ]; then
        verify_output=$(sudo /usr/libexec/noid-nvidia-verify \
            "$kver" 2>&1) || verify_rc=$?
    else
        verify_output=$(sudo /usr/libexec/noid-nvidia-verify \
            "$kver" --newer-than "$build_marker" 2>&1) || verify_rc=$?
    fi
else
    verify_rc=1
fi

# One repair build is justified only after the native/current module set failed
# the complete integrity gate. Replace the marker so failure-log and BUILDTIME
# freshness refer to this repair attempt alone.
if [ "$akmods_rc" -ne 0 ] || [ -n "$new_failure_log" ] \
        || [ "$verify_rc" -ne 0 ]; then
    fmt_warn "Native/current NVIDIA module verification failed; starting one serialized repair build."
    sudo rm -f "$build_marker"
    build_marker=
    build_marker=$(sudo mktemp /run/noid-nvidia-build.XXXXXX)
    akmods_rc=0
    verify_output=''
    verify_rc=0
    repair_mode=$(exact_kmod_repair_mode "$exact_kmod" sudo rpm) \
        || repair_mode=unavailable
    case "$repair_mode" in
        install)
            run_system_root /usr/bin/akmods --force \
                --kernels "$kver" --akmod "$AKMOD_NAME" \
                || akmods_rc=$?
            ;;
        rebuild)
            run_system_root /usr/bin/akmods --rebuild --force \
                --kernels "$kver" --akmod "$AKMOD_NAME" \
                || akmods_rc=$?
            ;;
        *)
            akmods_rc=1
            verify_output='RPM inventory is unreadable; refusing to guess install versus reinstall semantics.'
            ;;
    esac
    new_failure_log=$(sudo find /var/cache/akmods -type f -name '*.failed.log' \
        -path '*nvidia*' -newer "$build_marker" -print -quit 2>/dev/null || true)
    if [ "$akmods_rc" -eq 0 ] && [ -z "$new_failure_log" ] \
            && sudo rpm -q "$exact_kmod" >/dev/null 2>&1; then
        verify_output=$(sudo /usr/libexec/noid-nvidia-verify \
            "$kver" --newer-than "$build_marker" 2>&1) || verify_rc=$?
    else
        verify_rc=1
    fi
fi
if [ "$akmods_rc" -ne 0 ] || [ -n "$new_failure_log" ] \
        || [ "$verify_rc" -ne 0 ]; then
    mark_nvidia_degraded "akmods-or-artifact-integrity-failure"
    sudo rm -f "$build_marker"
    build_marker=
    echo
    echo "  ${RED}${BOLD}[FAIL]${NC} NVIDIA build/integrity gate failed for ${kver}."
    echo "  akmods rc: ${akmods_rc}"
    [ -z "$new_failure_log" ] || echo "  fresh failure log: $new_failure_log"
    [ -z "$verify_output" ] || printf '  verifier: %s\n' "$verify_output"
    echo "  ${BOLD}DO NOT REBOOT${NC}; signed-but-stale or branch-skewed modules are not accepted."
    echo "  Evidence marker: ${NVIDIA_STATE_DIR}/degraded"
    echo "  Debug: sudo systemctl status akmods.service; inspect /var/cache/akmods/"
    echo "  Retry this helper, or roll back (as your normal user, NOT sudo):"
    echo "    /usr/local/bin/noid-nvidia-install.sh --rollback"
    if command -v notify-send >/dev/null 2>&1 && [ -S "/run/user/$(id -u)/bus" ]; then
        notify-send --urgency=critical --icon=dialog-error --app-name="NoID Privacy" \
            "NVIDIA integrity gate FAILED — DO NOT REBOOT" \
            "Undo (run as your user, not sudo): /usr/local/bin/noid-nvidia-install.sh --rollback" \
            2>/dev/null || true
    fi
    return_to_menu_prompt
    exit 1
fi
sudo rm -f "$build_marker"
build_marker=
sudo rm -f "$NVIDIA_STATE_DIR/degraded"
printf '%s\n' "$verify_output" | sed 's/^/  [OK] /'
fmt_ok "exact NVIDIA module set is fresh and branch/certificate/kernel coherent"

# Module built OK. Root encryption is installer-selected. When the live root is
# encrypted and the boot display routes through NVIDIA, placing nvidia-drm in the
# initramfs gives Plymouth a maintained KMS path to re-render the unlock prompt.
# On an unencrypted or iGPU-driven system this is only a compatibility provision,
# not evidence that NVIDIA owns the boot display. plymouth.use-simpledrm=1 stays
# as the early framebuffer path and fallback.
echo
echo "  -> Configuring NVIDIA early-KMS for LUKS-prompt visibility ..."
sudo tee /etc/dracut.conf.d/99-noid-nvidia-initramfs.conf >/dev/null <<'DRACUT_NV_EOF'
# NoID Privacy — include NVIDIA in the initramfs so the LUKS passphrase prompt is
# re-rendered by nvidia-drm after the simpledrm->KMS handover when an installer-
# selected encrypted root and boot-display routing require it. Created by
# noid-nvidia-install.sh; removed by --rollback.
# Only bake nvidia in when its module is actually built for the target $kernel
# (dracut sets $kernel before sourcing conf.d). On a brand-new kernel whose akmod
# hasn't built yet, this stays off so the kernel-install 50-dracut does not E-FAIL
# on the missing module; the post-transaction helper rebuilds the initramfs WITH
# nvidia once akmods produces it. Empty $kernel (--regenerate-all) = fail-safe on.
_noid_nvko="/usr/lib/modules/${kernel}/extra/nvidia/nvidia.ko"
if [ -z "${kernel:-}" ] || [ -e "${_noid_nvko}.xz" ] || [ -e "${_noid_nvko}.zst" ] || [ -e "${_noid_nvko}" ]; then
    add_drivers+=" nvidia nvidia_modeset nvidia_drm nvidia_uvm "
fi
unset _noid_nvko
DRACUT_NV_EOF
# Kernel-update robustness for a DIRECT `dnf install kernel-*` (the
# noid-update-all.sh path also does akmods+dracut). kernel-install runs the 95-
# hook LATE (after 50-dracut) but INSIDE the rpm %posttrans, which holds the rpmdb
# lock; akmods installs its built kmod via its own `dnf install`, so the build +
# nvidia-initramfs rebuild are deferred to a transient unit running the helper
# below (detached, after the lock is released). Both removed by --rollback.
sudo tee /usr/libexec/noid-nvidia-initramfs-rebuild >/dev/null <<'HELPER_NV_EOF'
#!/bin/bash
# NoID Privacy — build the nvidia akmod for $1 + bake it into that kernel's
# initramfs (LUKS-prompt re-render). Run detached (post-transaction) by the
# 95-noid-nvidia-initramfs.install kernel-install hook (kernel changes) and by
# the noid-nvidia-initramfs-dnf-action hook (driver-only updates).
set -euo pipefail
umask 022

kernel_release_is_valid() {
    local candidate="${1:-}"
    case "$candidate" in
        ''|[!A-Za-z0-9]*|*[!A-Za-z0-9._+-]*) return 1 ;;
        *) return 0 ;;
    esac
}

root_owned_nonwritable() {
    local path="$1" metadata uid gid mode
    metadata=$(stat -c '%u:%g:%a' -- "$path") || return 1
    IFS=: read -r uid gid mode <<<"$metadata"
    [ "$uid:$gid" = '0:0' ] || return 1
    case "$mode" in ''|*[!0-7]*) return 1 ;; esac
    (( (8#$mode & 0022) == 0 ))
}

installed_kernel_is_valid() {
    local candidate="$1"
    local modules="/usr/lib/modules/$candidate"
    local kernel_tree="$modules/kernel"
    local module_image="$modules/vmlinuz"
    local boot_image="/boot/vmlinuz-$candidate"
    kernel_release_is_valid "$candidate" || return 1
    [ -d "$modules" ] && [ ! -L "$modules" ] \
        && [ -d "$kernel_tree" ] && [ ! -L "$kernel_tree" ] \
        && [ -f "$module_image" ] && [ ! -L "$module_image" ] \
        && [ -f "$boot_image" ] && [ ! -L "$boot_image" ] \
        || return 1
    root_owned_nonwritable "$modules" \
        && root_owned_nonwritable "$kernel_tree" \
        && root_owned_nonwritable "$module_image" \
        && root_owned_nonwritable "$boot_image"
}

case "$#" in 1|2) ;; *) exit 2 ;; esac
kver="${1:-}"
installed_kernel_is_valid "$kver" || exit 1
queued_marker="${2:-}"

# Desktop feedback for these detached/background paths. loginctl->DBUS so a root
# transient unit reaches the logged-in session; silent when no graphical session
# (tty/ssh/cron) or while noid-update-all runs (it shows inline progress instead).
_notify() {
    if [ -x /usr/libexec/noid-update-window-active ] \
            && /usr/libexec/noid-update-window-active; then
        return 0
    fi
    command -v notify-send >/dev/null 2>&1 || return 0
    local urgency="$1" icon="$2" title="$3" body="$4" u uid
    for u in $(loginctl list-users --no-legend 2>/dev/null | awk '$2!="root"{print $2}'); do
        uid=$(id -u "$u" 2>/dev/null) || continue
        [ -S "/run/user/$uid/bus" ] || continue
        sudo -u "$u" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" \
            notify-send --urgency="$urgency" --icon="$icon" --app-name="NoID Privacy" \
            "$title" "$body" 2>/dev/null || true
    done
}

state_dir=/var/lib/noid-nvidia-integrity
queue_dir="$state_dir/queue"
if [ -n "$queued_marker" ]; then
    marker_metadata=''
    marker_kernel=''
    marker_name=''
    marker_source=''
    marker_token=''
    case "$queued_marker" in "$queue_dir/"*.pending) ;; *) exit 1 ;; esac
    marker_name=${queued_marker#"$queue_dir/"}
    marker_token=${marker_name%.pending}
    [ "$marker_name" = "$marker_token.pending" ] || exit 1
    case "$marker_token" in ''|*[!A-Za-z0-9_-]*) exit 1 ;; esac
    [ -f "$queued_marker" ] && [ ! -L "$queued_marker" ] || exit 1
    marker_metadata=$(stat -c '%u:%g:%a:%h' -- "$queued_marker") || exit 1
    [ "$marker_metadata" = '0:0:600:1' ] || exit 1
    mapfile -t marker_record <"$queued_marker"
    [ "${#marker_record[@]}" -eq 2 ] || exit 1
    marker_kernel="${marker_record[0]}"
    marker_source="${marker_record[1]}"
    [ "$marker_kernel" = "kernel=$kver" ] || exit 1
    case "$marker_source" in
        source=post-transaction|source=manual-direct) ;;
        *) exit 1 ;;
    esac
else
    install -d -m 0755 "$queue_dir"
    queued_marker="$queue_dir/manual-$$.pending"
    printf 'kernel=%s\nsource=manual-direct\n' "$kver" >"$queued_marker"
    chmod 0600 "$queued_marker"
    sync -- "$queued_marker"
    sync -- "$queue_dir"
fi

_notify normal /usr/share/pixmaps/noid-privacy-logo.png \
    "NVIDIA — rebuilding boot image" \
    "Building the NVIDIA module + initramfs for kernel ${kver} in the background. Do not reboot until this finishes."

# Serialize against M21 convergence and every supported NoID Privacy BLS,
# initramfs or kernel transaction before taking M19's narrower worker lock.
defer_for_m21() {
    local reason=$1 deferred_marker
    deferred_marker=${queued_marker%.pending}.deferred
    mv -fT -- "$queued_marker" "$deferred_marker"
    sync -- "$deferred_marker"
    sync -- "$queue_dir"
    _notify normal dialog-information \
        "NVIDIA boot-image rebuild deferred" \
        "${reason}; the durable task will resume on a later boot."
    exit 75
}
[ -e /run/lock/noid-boot-mutation.lock ] \
    || defer_for_m21 "The shared M21 boot-mutation lock is missing"
exec 8>/run/lock/noid-boot-mutation.lock
flock -n 8 || defer_for_m21 "Another boot mutation is active"
if ! basis_record=$(/usr/libexec/noid-boot-mutation-guard); then
    defer_for_m21 "M21 boot recovery or reboot validation must finish first"
fi
case "$basis_record" in
    basis=hostonly|basis=generic) ;;
    *) defer_for_m21 "M21 returned an invalid stable-basis record" ;;
esac

# Serialize all NVIDIA akmods/dracut writers. Multiple kernel and driver
# transactions may queue independently, but they must never race one image.
exec 9>/run/lock/noid-nvidia-initramfs.lock
flock -w 1800 9 || exit 1
build_marker=$(mktemp /run/noid-nvidia-build.XXXXXX)
trap 'rm -f "$build_marker"' EXIT

_degraded() {
    local reason="$1"
    reason=${reason//$'\n'/; }
    printf 'status=degraded\nkernel=%s\nreason=%s\n' "$kver" "$reason" \
        >"$state_dir/degraded"
    chmod 0600 "$state_dir/degraded"
    printf 'status=degraded\nkernel=%s\nreason=%s\n' "$kver" "$reason" \
        >"${queued_marker%.pending}.failed"
    chmod 0600 "${queued_marker%.pending}.failed"
    _notify critical dialog-error \
        "NVIDIA initramfs rebuild FAILED" \
        "${reason}. Reboot remains inhibited. Run: sudo /usr/libexec/noid-nvidia-initramfs-queue --resume"
    exit 1
}

main_akmod=0
legacy_akmod=0
rpm -q akmod-nvidia >/dev/null 2>&1 && main_akmod=1
rpm -q akmod-nvidia-580xx >/dev/null 2>&1 && legacy_akmod=1
case "$main_akmod:$legacy_akmod" in
    1:0) akmod_name=nvidia ;;
    0:1) akmod_name=nvidia-580xx ;;
    *) _degraded "partial, mixed or missing NVIDIA akmod branch" ;;
esac

# Fedora's own kernel-install hook (/usr/lib/kernel/install.d/
# 95-akmodsposttrans.install) restarts akmods@<kver>.service --no-block for
# the same new kernel, so a second, independent builder can be running right
# now. Wait only while that exact instance has a live start/stop operation.
# akmods@.service and the global boot akmods.service both use
# RemainAfterExit=yes: `systemctl is-active` therefore also returns success for
# active/exited after all work is complete. Treating that as "still building"
# imposed the full 900-second timeout on every later worker.
native_akmods_running() {
    local unit active sub
    unit="akmods@${kver}.service"
    active=$(/usr/bin/systemctl show "$unit" --property=ActiveState --value \
        2>/dev/null || true)
    sub=$(/usr/bin/systemctl show "$unit" --property=SubState --value \
        2>/dev/null || true)
    case "$active:$sub" in
        activating:*|deactivating:*|active:running) return 0 ;;
        *) return 1 ;;
    esac
}

# See the interactive copy above. This worker is already root, so callers pass
# rpm directly. The inventory probe keeps an rpmdb failure distinct from a
# normal not-installed result.
exact_kmod_repair_mode() {
    local exact_kmod=${1:-}
    shift || return 2
    [ -n "$exact_kmod" ] && [ "$#" -gt 0 ] || return 2
    if "$@" -q "$exact_kmod" >/dev/null 2>&1; then
        printf 'rebuild\n'
    elif "$@" -qa --qf '%{NAME}\n' >/dev/null 2>&1; then
        printf 'install\n'
    else
        return 1
    fi
}

akmods_wait=0
while native_akmods_running; do
    if [ "$akmods_wait" -ge 900 ]; then
        _degraded "native akmods@${kver} did not settle within 900 seconds"
    fi
    /usr/bin/sleep 5
    akmods_wait=$((akmods_wait + 5))
done
akmods_rc=0
akmods_failure_log=
depmod_rc=0
verify_rc=0
verify_output=
prebuilt_kmod=0
exact_kmod="kmod-${akmod_name}-${kver}"
repair_mode=$(exact_kmod_repair_mode "$exact_kmod" rpm) \
    || _degraded "RPM inventory is unreadable; refusing to guess install versus reinstall semantics"
if [ "$repair_mode" = rebuild ]; then
    # A kmod for this exact kernel already exists (typically the native
    # akmods build that just finished). Plain akmods re-validates the
    # akmod↔kmod version pairing and rebuilds only on mismatch — no
    # duplicate forced build of an already-current module set.
    prebuilt_kmod=1
    akmods --kernels "$kver" --akmod "$akmod_name" \
        >/dev/null 2>&1 || akmods_rc=$?
else
    # --rebuild changes akmods' nested DNF verb to `reinstall`, which cannot
    # create this known-absent package. --force retries prior build failures
    # while retaining the required `install` verb.
    akmods --force --kernels "$kver" --akmod "$akmod_name" \
        >/dev/null 2>&1 || akmods_rc=$?
fi
akmods_failure_log=$(find /var/cache/akmods -type f -name '*.failed.log' \
    -path '*nvidia*' -newer "$build_marker" -print -quit 2>/dev/null || true)

# Generated kmod RPMs normally refresh this index from their scriptlet. Own the
# exact target-kernel convergence here as defense in depth as well: it repairs
# older NoID Privacy images that deleted both System.map paths, survives an incomplete
# native scriptlet, and makes every resume self-contained before modinfo-based
# verification.
refresh_target_index() {
    /usr/sbin/depmod -a "$kver"
}
refresh_target_index || depmod_rc=$?

if [ "$prebuilt_kmod" -eq 1 ]; then
    # Accepted a pre-existing/native kmod: its files may predate this
    # worker's build_marker, so the newer-than gate would false-fail.
    # Staleness is still impossible — the verifier enforces exact
    # akmod/CUDA/kmod EVR pairing and the exact local signing certificate.
    verify_output=$(/usr/libexec/noid-nvidia-verify "$kver" \
        --require-enrolled 2>&1) \
        || verify_rc=$?
else
    verify_output=$(/usr/libexec/noid-nvidia-verify "$kver" \
        --newer-than "$build_marker" --require-enrolled 2>&1) \
        || verify_rc=$?
fi

# A pre-existing package can still contain damaged or same-EVR bytes that
# plain akmods considers current. Only that installed-package state may use
# rebuild/reinstall, and it gets exactly one serialized repair attempt.
if [ "$prebuilt_kmod" -eq 1 ] \
        && { [ "$akmods_rc" -ne 0 ] || [ -n "$akmods_failure_log" ] \
             || [ "$depmod_rc" -ne 0 ] || [ "$verify_rc" -ne 0 ]; }; then
    : > "$build_marker"
    akmods_rc=0
    depmod_rc=0
    verify_rc=0
    verify_output=
    akmods --rebuild --force --kernels "$kver" --akmod "$akmod_name" \
        >/dev/null 2>&1 || akmods_rc=$?
    akmods_failure_log=$(find /var/cache/akmods -type f -name '*.failed.log' \
        -path '*nvidia*' -newer "$build_marker" -print -quit 2>/dev/null || true)
    refresh_target_index || depmod_rc=$?
    verify_output=$(/usr/libexec/noid-nvidia-verify "$kver" \
        --newer-than "$build_marker" --require-enrolled 2>&1) \
        || verify_rc=$?
    prebuilt_kmod=0
fi

[ "$akmods_rc" -eq 0 ] || _degraded "akmods returned ${akmods_rc}"
[ -z "$akmods_failure_log" ] || _degraded "akmods wrote ${akmods_failure_log}"
rpm -q "$exact_kmod" >/dev/null 2>&1 \
    || _degraded "akmods did not install the exact generated package ${exact_kmod}"
[ "$depmod_rc" -eq 0 ] || _degraded "target depmod failed for ${kver}"
[ "$verify_rc" -eq 0 ] \
    || _degraded "${verify_output:-NVIDIA module verification failed}"

# Delegate the complete Root/LUKS/Plymouth/MEI/basis/NVIDIA validation and
# same-filesystem publication to M21's one canonical boot-image writer.
final_image="/boot/initramfs-${kver}.img"
/usr/libexec/noid-dracut-regenerate-all --lock-held=8 --kernel="$kver" \
    || _degraded "canonical guarded initramfs regeneration failed for ${kver}"
[ -f "$final_image" ] && [ ! -L "$final_image" ] \
    || _degraded "published initramfs is missing or unsafe"

prepared_record="$state_dir/${kver}.prepared"
if [ -e "$prepared_record" ] || [ -L "$prepared_record" ]; then
    # The canonical regenerator has just invoked the rebind bridge, which
    # validates and refreshes this stronger pre-reboot record. Never add a
    # weaker ready record beside it: post-boot verification still owns the
    # transition to active evidence.
    [ -f "$prepared_record" ] && [ ! -L "$prepared_record" ] \
        && [ "$(stat -c '%U:%G:%a:%h' "$prepared_record" 2>/dev/null)" \
            = root:root:600:1 ] \
        || _degraded "prepared NVIDIA evidence is unsafe after regeneration"
    rm -f -- "$state_dir/${kver}.ready" \
        || _degraded "cannot retire superseded ready evidence for ${kver}"
    sync -- "$state_dir"
    notification_title="NVIDIA boot image prepared"
    notification_body="Exact NVIDIA modules + initramfs verified for ${kver}; post-reboot validation remains pending."
else
    ready_tmp=$(mktemp "$state_dir/.ready.XXXXXX")
    {
        printf 'status=ready\n'
        printf '%s\n' "$verify_output"
        printf 'initramfs_sha256=%s\n' \
            "$(sha256sum "$final_image" | awk '{print $1}')"
    } >"$ready_tmp"
    chmod 0600 "$ready_tmp"
    sync -- "$ready_tmp"
    mv -fT -- "$ready_tmp" "$state_dir/${kver}.ready"
    sync -- "$state_dir/${kver}.ready"
    sync -- "$state_dir"
    notification_title="NVIDIA boot image ready"
    notification_body="Exact NVIDIA modules + initramfs verified for ${kver}. Reboot may proceed."
fi
rm -f "$queued_marker" "${queued_marker%.pending}.failed" "$state_dir/degraded"
sync -- "$queue_dir"
sync -- "$state_dir"
_notify normal /usr/share/pixmaps/noid-privacy-logo.png \
    "$notification_title" "$notification_body"
HELPER_NV_EOF

# Durable queue: create a persistent kernel task first, synchronously acquire a
# shutdown/sleep inhibitor, then schedule a uniquely named worker. Failed work
# leaves its marker in place, so the inhibitor stays active and boot-time resume
# requeues it after power loss. This closes the gap inherent in a bare fixed-name
# `systemd-run --no-block` call.
sudo tee /usr/libexec/noid-nvidia-reboot-guard >/dev/null <<'GUARD_NV_EOF'
#!/bin/bash
set -euo pipefail

queue_dir=/var/lib/noid-nvidia-integrity/queue
install -d -m 0755 "$queue_dir"

verify_inhibitor() {
    local pid="${1:-}" inhibitors
    case "$pid" in ''|*[!0-9]*) return 2 ;; esac

    for _ in {1..50}; do
        kill -0 "$pid" 2>/dev/null || return 1
        inhibitors=$(/usr/bin/busctl --json=short call \
            org.freedesktop.login1 /org/freedesktop/login1 \
            org.freedesktop.login1.Manager ListInhibitors \
            --no-pager 2>/dev/null) || inhibitors=''
        if [ -n "$inhibitors" ] && printf '%s\n' "$inhibitors" \
                | /usr/bin/jq -e --argjson pid "$pid" '
                    .type == "a(ssssuu)" and
                    any(.data[0][];
                        ((.[0] | split(":") | sort)
                            == ["shutdown", "sleep"]) and
                        .[1] == "NoID Privacy" and
                        .[2] == "NVIDIA-module-and-initramfs-verification-pending" and
                        .[3] == "block" and
                        .[4] == 0 and
                        .[5] == $pid)
                ' >/dev/null; then
            return 0
        fi
        sleep 0.1
    done

    printf 'NoID Privacy: exact NVIDIA shutdown inhibitor was not acquired\n' >&2
    return 1
}

if [ "${1:-}" = '--verify-inhibitor' ]; then
    [ "$#" -eq 2 ] || exit 2
    verify_inhibitor "$2"
    exit $?
fi
[ "$#" -eq 0 ] || exit 2

while find "$queue_dir" -maxdepth 1 -type f -name '*.pending' -print -quit \
        | grep -q .; do
    sleep 1
done
GUARD_NV_EOF

sudo tee /usr/libexec/noid-nvidia-initramfs-queue >/dev/null <<'QUEUE_NV_EOF'
#!/bin/bash
set -euo pipefail
state_dir=/var/lib/noid-nvidia-integrity
queue_dir="$state_dir/queue"

kernel_release_is_valid() {
    local candidate="${1:-}"
    case "$candidate" in
        ''|[!A-Za-z0-9]*|*[!A-Za-z0-9._+-]*) return 1 ;;
        *) return 0 ;;
    esac
}

root_owned_nonwritable() {
    local path="$1" metadata uid gid mode
    metadata=$(stat -c '%u:%g:%a' -- "$path") || return 1
    IFS=: read -r uid gid mode <<<"$metadata"
    [ "$uid:$gid" = '0:0' ] || return 1
    case "$mode" in ''|*[!0-7]*) return 1 ;; esac
    (( (8#$mode & 0022) == 0 ))
}

installed_kernel_is_valid() {
    local candidate="$1"
    local modules="/usr/lib/modules/$candidate"
    local kernel_tree="$modules/kernel"
    local module_image="$modules/vmlinuz"
    local boot_image="/boot/vmlinuz-$candidate"
    kernel_release_is_valid "$candidate" || return 1
    [ -d "$modules" ] && [ ! -L "$modules" ] \
        && [ -d "$kernel_tree" ] && [ ! -L "$kernel_tree" ] \
        && [ -f "$module_image" ] && [ ! -L "$module_image" ] \
        && [ -f "$boot_image" ] && [ ! -L "$boot_image" ] \
        || return 1
    root_owned_nonwritable "$modules" \
        && root_owned_nonwritable "$kernel_tree" \
        && root_owned_nonwritable "$module_image" \
        && root_owned_nonwritable "$boot_image"
}

read_marker_kernel() {
    local marker="$1" suffix="$2" name token metadata kver
    local -a record=()
    case "$suffix" in pending|deferred) ;; *) return 1 ;; esac
    case "$marker" in "$queue_dir/"*) ;; *) return 1 ;; esac
    name=${marker#"$queue_dir/"}
    token=${name%."$suffix"}
    [ "$name" = "$token.$suffix" ] || return 1
    case "$token" in ''|*[!A-Za-z0-9_-]*) return 1 ;; esac
    [ -f "$marker" ] && [ ! -L "$marker" ] || return 1
    metadata=$(stat -c '%u:%g:%a:%h' -- "$marker") || return 1
    [ "$metadata" = '0:0:600:1' ] || return 1
    mapfile -t record <"$marker" || return 1
    [ "${#record[@]}" -eq 2 ] || return 1
    case "${record[0]}" in kernel=*) kver=${record[0]#kernel=} ;; *) return 1 ;; esac
    case "${record[1]}" in
        source=post-transaction|source=manual-direct) ;;
        *) return 1 ;;
    esac
    installed_kernel_is_valid "$kver" || return 1
    printf '%s\n' "$kver"
}

acquire_boot_mutation() {
    [ -e /run/lock/noid-boot-mutation.lock ] || return 1
    exec 8>/run/lock/noid-boot-mutation.lock
    flock -w 1800 8 || return 1
    /usr/libexec/noid-boot-mutation-guard >/dev/null
}

release_boot_mutation() {
    flock -u 8 || return 1
    exec 8>&-
}

schedule_marker() {
    local marker="$1" token kver unit
    case "$marker" in "$queue_dir/"*.pending) ;; *) return 1 ;; esac
    token=${marker##*/}
    token=${token%.pending}
    case "$token" in ''|*[!A-Za-z0-9_-]*) return 1 ;; esac
    kver=$(read_marker_kernel "$marker" pending) || return 1
    unit="noid-nvidia-initramfs-${token}.service"
    if systemctl is-active --quiet "$unit"; then
        return 0
    fi
    systemd-run --no-block --collect \
        --unit="${unit%.service}" \
        --description="NoID Privacy: verified NVIDIA initramfs for ${kver}" \
        /usr/libexec/noid-nvidia-initramfs-rebuild "$kver" "$marker" >/dev/null
}

promote_deferred() {
    local marker pending
    shopt -s nullglob
    for marker in "$queue_dir"/*.deferred; do
        pending=${marker%.deferred}.pending
        [ ! -e "$pending" ] || return 1
        mv -fT -- "$marker" "$pending" || return 1
        sync -- "$pending"
        sync -- "$queue_dir"
    done
}

schedule_all_pending() {
    local marker found=0 rc=0
    shopt -s nullglob
    for marker in "$queue_dir"/*.pending; do
        found=1
        schedule_marker "$marker" || rc=1
    done
    [ "$found" -eq 0 ] || return "$rc"
}

validate_resume_queue() {
    local marker
    shopt -s nullglob
    for marker in "$queue_dir"/*.deferred; do
        read_marker_kernel "$marker" deferred >/dev/null || return 1
    done
    for marker in "$queue_dir"/*.pending; do
        read_marker_kernel "$marker" pending >/dev/null || return 1
    done
}

mode=queue
kver=''
case "${1:-}" in
    --resume)
        [ "$#" -eq 1 ] || exit 2
        mode=resume
        ;;
    -*)
        exit 2
        ;;
    *)
        [ "$#" -eq 1 ] || exit 2
        kver="$1"
        installed_kernel_is_valid "$kver" || exit 1
        ;;
esac
install -d -m 0755 "$queue_dir"

if [ "$mode" = resume ]; then
    acquire_boot_mutation
    validate_resume_queue
    promote_deferred
    if ! find "$queue_dir" -maxdepth 1 -type f -name '*.pending' \
            -print -quit | grep -q .; then
        release_boot_mutation
        exit 0
    fi
    systemctl start noid-nvidia-reboot-guard.service
    release_boot_mutation
    schedule_all_pending
    exit $?
fi

acquire_boot_mutation
installed_kernel_is_valid "$kver" || exit 1
token=$(printf '%s\n' "${kver}:$(date +%s%N):$$" | sha256sum | cut -c1-24)
marker="$queue_dir/${token}.pending"
marker_tmp=$(mktemp "$queue_dir/.pending.XXXXXX")
trap 'rm -f "${marker_tmp:-}"' EXIT
printf 'kernel=%s\nsource=post-transaction\n' "$kver" >"$marker_tmp"
chmod 0600 "$marker_tmp"
sync -- "$marker_tmp"
mv -fT -- "$marker_tmp" "$marker"
marker_tmp=''
sync -- "$marker"
sync -- "$queue_dir"

# Type=exec plus the unit's synchronous login1 post-check makes this return only
# after the exact systemd-inhibit MainPID holds the required block lock.
systemctl start noid-nvidia-reboot-guard.service
release_boot_mutation
schedule_marker "$marker"
printf '%s\n' "$marker"
QUEUE_NV_EOF

sudo tee /etc/systemd/system/noid-nvidia-reboot-guard.service >/dev/null <<'GUARD_UNIT_NV_EOF'
[Unit]
Description=NoID Privacy NVIDIA pending boot-image shutdown guard
After=local-fs.target dbus.service

[Service]
Type=exec
ExecStart=/usr/bin/systemd-inhibit --what=shutdown:sleep --who="NoID Privacy" --why=NVIDIA-module-and-initramfs-verification-pending --mode=block /usr/libexec/noid-nvidia-reboot-guard
ExecStartPost=/usr/libexec/noid-nvidia-reboot-guard --verify-inhibitor $MAINPID
TimeoutStartSec=15s
TimeoutStopSec=15s
Restart=on-failure
RestartSec=1s
GUARD_UNIT_NV_EOF

sudo tee /etc/systemd/system/noid-nvidia-initramfs-resume.service >/dev/null <<'RESUME_UNIT_NV_EOF'
[Unit]
Description=Resume durable NoID Privacy NVIDIA boot-image tasks
Requires=noid-dracut-hostonly-firstboot.service
After=local-fs.target noid-dracut-hostonly-firstboot.service
ConditionDirectoryNotEmpty=/var/lib/noid-nvidia-integrity/queue

[Service]
Type=oneshot
ExecStart=/usr/libexec/noid-nvidia-initramfs-queue --resume

[Install]
WantedBy=multi-user.target
RESUME_UNIT_NV_EOF

sudo tee /usr/libexec/noid-nvidia-postboot-verify >/dev/null <<'POSTBOOT_NV_EOF'
#!/bin/bash
# Promote an initial NVIDIA install from reboot-prepared to live-verified only
# after the exact signed modules, boot image, PCI binding and userspace control
# path have all been proven on the boot that will consume them.
set -uo pipefail
umask 077

ROOT=${NOID_TEST_ROOT:-}
rpath() { printf '%s%s\n' "$ROOT" "$1"; }
STATE_DIR=$(rpath /var/lib/noid-nvidia-integrity)
BOOT_DIR=$(rpath /boot)
SYS_MODULE=$(rpath /sys/module)
PCI_DEVICES=$(rpath /sys/bus/pci/devices)
BOOT_ID_FILE=$(rpath /proc/sys/kernel/random/boot_id)
MODULE_SIG_ENFORCE=$(rpath /sys/module/module/parameters/sig_enforce)
BOOT_LOCK=$(rpath /run/lock/noid-boot-mutation.lock)
VERIFY=${NOID_TEST_VERIFY:-/usr/libexec/noid-nvidia-verify}
MODINFO=${NOID_TEST_MODINFO:-/usr/sbin/modinfo}
OBJCOPY=${NOID_TEST_OBJCOPY:-/usr/bin/objcopy}
XZ=${NOID_TEST_XZ:-/usr/bin/xz}
ZSTD=${NOID_TEST_ZSTD:-/usr/bin/zstd}
GZIP=${NOID_TEST_GZIP:-/usr/bin/gzip}
NVIDIA_SMI=${NOID_TEST_NVIDIA_SMI:-/usr/bin/nvidia-smi}
RUNUSER=${NOID_TEST_RUNUSER:-/usr/bin/runuser}
BOOT_GUARD=${NOID_TEST_BOOT_GUARD:-/usr/libexec/noid-boot-mutation-guard}
EXPECTED_OWNER=${NOID_TEST_OWNER:-root:root}
KVER=${NOID_TEST_KERNEL:-$(uname -r)}
DEGRADED="$STATE_DIR/degraded"
IDENTITY_TMP=''

cleanup() {
    [ -z "$IDENTITY_TMP" ] || rm -rf -- "$IDENTITY_TMP"
}
trap cleanup EXIT

raw_fail() {
    echo "noid-nvidia-postboot-verify: $*" >&2
    exit 1
}

publish_degraded() {
    local reason=$1 tmp=''
    reason=${reason//$'\n'/; }
    reason=${reason//[^[:alnum:]_.:,;=+@%\/ -]/_}
    tmp=$(mktemp "$STATE_DIR/.degraded.XXXXXX") \
        || raw_fail "cannot allocate degraded evidence"
    if ! printf 'status=degraded\nkernel=%s\nphase=postboot\nreason=%s\n' \
            "$KVER" "$reason" >"$tmp" \
            || ! chmod 0600 "$tmp" \
            || ! sync -- "$tmp" \
            || ! mv -fT -- "$tmp" "$DEGRADED" \
            || ! sync -- "$DEGRADED" \
            || ! sync -- "$STATE_DIR"; then
        raw_fail "${reason}; degraded evidence publication also failed"
    fi
    logger -t noid-nvidia-postboot-verify -- \
        "post-boot validation failed for ${KVER}: ${reason}" 2>/dev/null || true
    raw_fail "$reason"
}

[ "${NOID_TEST_MODE:-0}" = 1 ] || [ "$(id -u)" -eq 0 ] \
    || raw_fail "must run as root"
[ -d "$STATE_DIR" ] && [ ! -L "$STATE_DIR" ] \
    || raw_fail "state directory is missing or unsafe"
[ "$(stat -c '%U:%G:%a' "$STATE_DIR" 2>/dev/null)" = "$EXPECTED_OWNER:755" ] \
    || raw_fail "state directory ownership or mode is invalid"

shopt -s nullglob
prepared_files=("$STATE_DIR"/*.prepared)
case "${#prepared_files[@]}" in
    0) exit 0 ;;
    1) ;;
    *) publish_degraded "multiple reboot-prepared records exist" ;;
esac
prepared=${prepared_files[0]}
[ -f "$BOOT_LOCK" ] && [ ! -L "$BOOT_LOCK" ] \
    || publish_degraded "shared boot-mutation lock is missing or unsafe"
exec 7>"$BOOT_LOCK" || publish_degraded "cannot open shared boot-mutation lock"
flock -w 90 7 || publish_degraded "shared boot-mutation lock stayed busy"
[ -x "$BOOT_GUARD" ] || publish_degraded "boot-mutation guard is unavailable"
boot_basis=$("$BOOT_GUARD" 2>&1) \
    || publish_degraded "boot-mutation contract is not terminal: ${boot_basis}"
case "$boot_basis" in basis=hostonly|basis=generic) ;; *)
    publish_degraded "boot-mutation guard returned invalid evidence" ;;
esac
[ -f "$prepared" ] && [ ! -L "$prepared" ] \
    || publish_degraded "reboot-prepared record is missing or unsafe"
[ "$(stat -c '%U:%G:%a' "$prepared" 2>/dev/null)" = "$EXPECTED_OWNER:600" ] \
    || publish_degraded "reboot-prepared record ownership or mode is invalid"

prepared_name=${prepared##*/}
prepared_kver=${prepared_name%.prepared}
case "$prepared_kver" in
    ''|*[!A-Za-z0-9._+-]*)
        publish_degraded "reboot-prepared record has an invalid kernel name"
        ;;
esac
[ "$prepared_kver" = "$KVER" ] \
    || publish_degraded "prepared kernel ${prepared_kver} is not running kernel ${KVER}"

mapfile -t record <"$prepared" \
    || publish_degraded "cannot read reboot-prepared record"
[ "${#record[@]}" -eq 9 ] && [ "$(wc -l <"$prepared")" -eq 9 ] \
    || publish_degraded "reboot-prepared record does not have the exact schema"
[ "${record[0]}" = status=prepared-awaiting-reboot-validation ] \
    || publish_degraded "reboot-prepared status is invalid"
case "${record[1]}" in branch=main|branch=580xx) branch=${record[1]#branch=} ;; *)
    publish_degraded "reboot-prepared branch is invalid" ;;
esac
[ "${record[2]}" = "kernel=$KVER" ] \
    || publish_degraded "reboot-prepared kernel field is invalid"
evr=${record[3]#evr=}
[ "${record[3]}" = "evr=$evr" ] && [ -n "$evr" ] \
    || publish_degraded "reboot-prepared package identity is invalid"
case "$evr" in *[!A-Za-z0-9._:+~-]*)
    publish_degraded "reboot-prepared package identity is unsafe" ;;
esac
[ "${record[4]}" = modules=verified ] \
    || publish_degraded "reboot-prepared module evidence is invalid"
[ "${record[5]}" = certificate=matched ] \
    || publish_degraded "reboot-prepared certificate evidence is invalid"
image_hash=${record[6]#initramfs_sha256=}
[[ "$image_hash" =~ ^[0-9a-f]{64}$ ]] \
    || publish_degraded "reboot-prepared initramfs hash is invalid"
prepared_boot_id=${record[7]#prepared_boot_id=}
[[ "$prepared_boot_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] \
    && [ "${record[7]}" = "prepared_boot_id=$prepared_boot_id" ] \
    || publish_degraded "reboot-prepared boot ID is invalid"
case "${record[8]}" in mok=pending-enrollment|mok=enrolled) ;; *)
    publish_degraded "reboot-prepared MOK state is invalid" ;;
esac

boot_id=$(<"$BOOT_ID_FILE")
[[ "$boot_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] \
    || publish_degraded "kernel boot ID is invalid"
[ "$boot_id" != "$prepared_boot_id" ] \
    || publish_degraded "NVIDIA path has not crossed the required reboot boundary"

verify_output=$("$VERIFY" "$KVER" 2>&1) \
    || publish_degraded "exact module/certificate verifier failed: ${verify_output}"
expected_verify=$(printf \
    'branch=%s\nkernel=%s\nevr=%s\nmodules=verified\ncertificate=matched' \
    "$branch" "$KVER" "$evr")
[ "$verify_output" = "$expected_verify" ] \
    || publish_degraded "exact module/certificate verifier returned mismatched evidence"
[ -f "$MODULE_SIG_ENFORCE" ] && [ ! -L "$MODULE_SIG_ENFORCE" ] \
    && [ "$(<"$MODULE_SIG_ENFORCE")" = Y ] \
    || publish_degraded "running kernel does not enforce module signatures"

final_image="$BOOT_DIR/initramfs-${KVER}.img"
[ -f "$final_image" ] && [ ! -L "$final_image" ] \
    || publish_degraded "published initramfs is missing or unsafe"
actual_hash=$(sha256sum "$final_image" 2>/dev/null | awk '{print $1}')
[ "$actual_hash" = "$image_hash" ] \
    || publish_degraded "published initramfs changed after preparation"

[ -x "$NVIDIA_SMI" ] \
    || publish_degraded "nvidia-smi is missing or not executable"
if [ "${NOID_TEST_MODE:-0}" = 1 ]; then
    smi_output=$($NVIDIA_SMI --query-gpu=pci.bus_id \
        --format=csv,noheader,nounits 2>&1) \
        || publish_degraded "unprivileged nvidia-smi query failed: ${smi_output}"
else
    [ -x "$RUNUSER" ] || publish_degraded "runuser is unavailable"
    smi_output=$($RUNUSER --user=nobody -- "$NVIDIA_SMI" \
        --query-gpu=pci.bus_id --format=csv,noheader,nounits 2>&1) \
        || publish_degraded "unprivileged nvidia-smi query failed: ${smi_output}"
fi

for module in nvidia nvidia_modeset nvidia_drm nvidia_uvm; do
    [ -d "$SYS_MODULE/$module" ] && [ ! -L "$SYS_MODULE/$module" ] \
        || publish_degraded "required module ${module} is not loaded"
    [ -f "$SYS_MODULE/$module/version" ] \
        && [ ! -L "$SYS_MODULE/$module/version" ] \
        && [ -f "$SYS_MODULE/$module/srcversion" ] \
        && [ ! -L "$SYS_MODULE/$module/srcversion" ] \
        || publish_degraded "loaded module ${module} lacks immutable identity fields"
    live_version=$(<"$SYS_MODULE/$module/version")
    live_srcversion=$(<"$SYS_MODULE/$module/srcversion")
    disk_version=$("$MODINFO" -F version "$module" -k "$KVER" 2>/dev/null) \
        || publish_degraded "cannot resolve on-disk version for ${module}"
    disk_srcversion=$("$MODINFO" -F srcversion "$module" -k "$KVER" 2>/dev/null) \
        || publish_degraded "cannot resolve on-disk srcversion for ${module}"
    [ -n "$live_version" ] && [ "$live_version" = "$disk_version" ] \
        && [ -n "$live_srcversion" ] \
        && [ "$live_srcversion" = "$disk_srcversion" ] \
        || publish_degraded "loaded/on-disk module identity differs for ${module}"

    live_build_id="$SYS_MODULE/$module/notes/.note.gnu.build-id"
    [ -f "$live_build_id" ] && [ ! -L "$live_build_id" ] \
        || publish_degraded "loaded module ${module} lacks a GNU build ID"
    module_path=$("$MODINFO" -F filename "$module" -k "$KVER" 2>/dev/null) \
        || publish_degraded "cannot resolve on-disk path for ${module}"
    [ -f "$module_path" ] && [ ! -L "$module_path" ] \
        || publish_degraded "on-disk module ${module} is missing or unsafe"
    IDENTITY_TMP=$(mktemp -d "/tmp/noid-nvidia-postboot.XXXXXX") \
        || publish_degraded "cannot allocate module identity workspace"
    module_elf="$IDENTITY_TMP/module.ko"
    disk_build_id="$IDENTITY_TMP/build-id.note"
    case "$module_path" in
        *.ko.xz) "$XZ" -dc -- "$module_path" >"$module_elf" ;;
        *.ko.zst) "$ZSTD" -qdc -- "$module_path" >"$module_elf" ;;
        *.ko.gz) "$GZIP" -dc -- "$module_path" >"$module_elf" ;;
        *.ko) cp -- "$module_path" "$module_elf" ;;
        *) publish_degraded "on-disk module ${module} has unsupported compression" ;;
    esac || publish_degraded "cannot unpack on-disk module ${module}"
    "$OBJCOPY" --dump-section ".note.gnu.build-id=$disk_build_id" \
        "$module_elf" 2>/dev/null \
        || publish_degraded "cannot extract on-disk GNU build ID for ${module}"
    [ -s "$disk_build_id" ] && cmp -s -- "$live_build_id" "$disk_build_id" \
        || publish_degraded "loaded/on-disk GNU build ID differs for ${module}"
    rm -rf -- "$IDENTITY_TMP" \
        || publish_degraded "cannot retire module identity workspace"
    IDENTITY_TMP=''
done
for conflicting in nouveau nova_core; do
    [ ! -e "$SYS_MODULE/$conflicting" ] && [ ! -L "$SYS_MODULE/$conflicting" ] \
        || publish_degraded "conflicting module ${conflicting} is loaded"
done

sysfs_bdfs=()
for device_path in "$PCI_DEVICES"/*; do
    [ -e "$device_path/vendor" ] || continue
    vendor=$(<"$device_path/vendor")
    [ "$vendor" = 0x10de ] || continue
    class=$(<"$device_path/class")
    case "$class" in 0x0300*|0x0302*|0x0380*) ;; *) continue ;; esac
    [ -L "$device_path/driver" ] \
        || publish_degraded "NVIDIA display device ${device_path##*/} has no driver"
    driver=$(basename "$(readlink -f "$device_path/driver")")
    [ "$driver" = nvidia ] \
        || publish_degraded "NVIDIA display device ${device_path##*/} uses ${driver}"
    sysfs_bdfs+=("${device_path##*/}")
done
[ "${#sysfs_bdfs[@]}" -gt 0 ] \
    || publish_degraded "no NVIDIA display-class PCI device was found"

smi_bdfs=()
while IFS= read -r raw_bdf; do
    raw_bdf=${raw_bdf//[[:space:]]/}
    raw_bdf=${raw_bdf,,}
    case "$raw_bdf" in
        0000????:??:??.?) normalized_bdf=${raw_bdf:4} ;;
        ????:??:??.?) normalized_bdf=$raw_bdf ;;
        *) publish_degraded "nvidia-smi returned an invalid PCI bus ID" ;;
    esac
    [[ "$normalized_bdf" =~ ^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$ ]] \
        || publish_degraded "nvidia-smi returned an unsafe PCI bus ID"
    smi_bdfs+=("$normalized_bdf")
done <<<"$smi_output"
[ "${#smi_bdfs[@]}" -gt 0 ] \
    || publish_degraded "nvidia-smi returned no GPU"
sysfs_set=$(printf '%s\n' "${sysfs_bdfs[@]}" | LC_ALL=C sort -u)
smi_set=$(printf '%s\n' "${smi_bdfs[@]}" | LC_ALL=C sort -u)
[ "$smi_set" = "$sysfs_set" ] \
    || publish_degraded "nvidia-smi and sysfs PCI device sets differ"
[ "$(printf '%s\n' "${smi_bdfs[@]}" | LC_ALL=C sort -u | wc -l)" \
        -eq "${#smi_bdfs[@]}" ] \
    || publish_degraded "nvidia-smi returned a duplicate PCI bus ID"

active="$STATE_DIR/${KVER}.active"
active_tmp=$(mktemp "$STATE_DIR/.active.XXXXXX") \
    || publish_degraded "cannot allocate active evidence"
if ! {
        printf 'status=active\n'
        printf '%s\n' "$verify_output"
        printf 'booted_initramfs_sha256=%s\n' "$actual_hash"
        printf 'postboot=verified\n'
        printf 'loaded_modules=verified\n'
        printf 'loaded_module_identity=verified\n'
        printf 'kernel_signature_enforcement=verified\n'
        printf 'runtime_signed_module_chain=verified\n'
        printf 'pci_binding=verified\n'
        printf 'nvidia_smi=verified\n'
        printf 'verified_boot_id=%s\n' "$boot_id"
    } >"$active_tmp" \
        || ! chmod 0600 "$active_tmp" \
        || ! sync -- "$active_tmp" \
        || ! mv -fT -- "$active_tmp" "$active" \
        || ! sync -- "$active" \
        || ! sync -- "$STATE_DIR"; then
    publish_degraded "active evidence publication failed"
fi
if ! rm -f -- "$prepared" "$STATE_DIR/${KVER}.ready" "$DEGRADED" \
        || ! sync -- "$STATE_DIR"; then
    publish_degraded "active evidence committed but stale state cleanup failed"
fi
logger -t noid-nvidia-postboot-verify -- \
    "post-boot NVIDIA path verified for ${KVER} on boot ${boot_id}" \
    2>/dev/null || true
printf 'NoID Privacy: NVIDIA post-boot path verified for %s.\n' "$KVER"
POSTBOOT_NV_EOF

sudo tee /etc/systemd/system/noid-nvidia-postboot-verify.service >/dev/null <<'POSTBOOT_UNIT_NV_EOF'
[Unit]
Description=NoID Privacy NVIDIA initial-install post-boot verification
Documentation=file:///usr/share/doc/noid-privacy/19-nvidia-drivers.md
After=local-fs.target noid-firstboot-cmdline.service noid-dracut-hostonly-firstboot.service display-manager.service
ConditionKernelCommandLine=!rd.live.image
ConditionPathExistsGlob=/var/lib/noid-nvidia-integrity/*.prepared

[Service]
Type=oneshot
ExecStart=/usr/libexec/noid-nvidia-postboot-verify
TimeoutStartSec=3min
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_SETUID CAP_SETGID
ProtectSystem=strict
# Rollback may remove the optional persistent state tree before systemd builds
# the namespace; keep the condition authoritative without a 226/NAMESPACE race.
ReadWritePaths=-/var/lib/noid-nvidia-integrity /run/lock
ProtectHome=yes
PrivateTmp=yes
PrivateNetwork=yes
ProtectProc=invisible
ProtectKernelTunables=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectHostname=yes
ProtectClock=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
LockPersonality=yes
SystemCallArchitectures=native
SystemCallFilter=~@mount @reboot @swap @module @raw-io @clock @debug @obsolete @cpu-emulation
IPAddressDeny=any
RestrictAddressFamilies=AF_UNIX

[Install]
WantedBy=graphical.target
POSTBOOT_UNIT_NV_EOF

sudo tee /etc/kernel/install.d/95-noid-nvidia-initramfs.install >/dev/null <<'KINST_NV_EOF'
#!/bin/bash
# NoID Privacy — rebuild new-kernel initramfs WITH nvidia (LUKS-prompt). add-only.
set -euo pipefail
[ "${1:-}" = "add" ] || exit 0
KVER="${2:-}"
[ -n "$KVER" ] || exit 0
command -v akmods >/dev/null 2>&1 || exit 0
if ! rpm_inventory=$(rpm -qa --qf '%{NAME}\n' 2>/dev/null); then
    echo "noid-nvidia kernel-install: RPM inventory query failed" >&2
    exit 1
fi
main_akmod=0
legacy_akmod=0
while IFS= read -r rpm_name; do
    case "$rpm_name" in
        akmod-nvidia) main_akmod=1 ;;
        akmod-nvidia-580xx) legacy_akmod=1 ;;
    esac
done <<<"$rpm_inventory"
case "$main_akmod:$legacy_akmod" in
    0:0) exit 0 ;;
    1:0|0:1) ;;
    *)
        echo "noid-nvidia kernel-install: mixed NVIDIA akmod branches" >&2
        exit 1
        ;;
esac
[ -x /usr/libexec/noid-nvidia-initramfs-queue ] || exit 1
# The interactive installer owns the shared boot lock and performs the exact
# synchronous rebuild itself. Do not recursively queue from its DNF transaction.
if [ -f /run/noid-nvidia-install-running ] \
        && [ ! -L /run/noid-nvidia-install-running ] \
        && [ "$(stat -c '%U:%G:%a' /run/noid-nvidia-install-running \
            2>/dev/null || true)" = root:root:600 ]; then
    installer_pid=$(sed -n 's/^pid=//p' /run/noid-nvidia-install-running)
    installer_start=$(sed -n 's/^start_time=//p' /run/noid-nvidia-install-running)
    case "$installer_pid:$installer_start" in
        *[!0-9:]*|:*|*:) ;;
        *)
            if [ -r "/proc/$installer_pid/stat" ] \
                    && [ "$(awk '{print $22}' "/proc/$installer_pid/stat")" = "$installer_start" ] \
                    && tr '\0' '\n' < "/proc/$installer_pid/cmdline" \
                        | grep -qF 'noid-nvidia-install.sh'; then
                exit 0
            fi
            ;;
    esac
fi
# Skip only during a validated noid-update-all window: the orchestrator rebuilds
# akmods + the nvidia-initramfs after its dnf step. A stale path must never skip
# this durable queue and leave the newly installed kernel without fresh modules.
if [ -x /usr/libexec/noid-update-window-active ] \
        && /usr/libexec/noid-update-window-active; then
    exit 0
fi
# kernel-install runs inside the rpm %posttrans, which holds the rpmdb lock; akmods
# installs its freshly built kmod via its own `dnf install`, so it must run AFTER
# this transaction releases the lock. Queue it even during system-update.target:
# the acquired block shutdown inhibitor prevents an offline update reboot from
# passing pending verification. The persistent marker lets the boot-time resume
# service requeue the task if an interruption still occurs.
exec /usr/libexec/noid-nvidia-initramfs-queue "$KVER"
KINST_NV_EOF
sudo chmod 0644 /etc/dracut.conf.d/99-noid-nvidia-initramfs.conf
sudo chmod 0755 /usr/libexec/noid-nvidia-initramfs-rebuild \
                /usr/libexec/noid-nvidia-rebind-evidence \
                /usr/libexec/noid-nvidia-initramfs-queue \
                /usr/libexec/noid-nvidia-reboot-guard \
                /usr/libexec/noid-nvidia-postboot-verify \
                /etc/kernel/install.d/95-noid-nvidia-initramfs.install
sudo chmod 0644 /etc/systemd/system/noid-nvidia-reboot-guard.service \
                /etc/systemd/system/noid-nvidia-initramfs-resume.service \
                /etc/systemd/system/noid-nvidia-postboot-verify.service
sudo chown root:root /usr/libexec/noid-nvidia-initramfs-rebuild \
                     /usr/libexec/noid-nvidia-rebind-evidence \
                     /usr/libexec/noid-nvidia-initramfs-queue \
                     /usr/libexec/noid-nvidia-reboot-guard \
                     /usr/libexec/noid-nvidia-postboot-verify \
                     /etc/kernel/install.d/95-noid-nvidia-initramfs.install \
                     /etc/dracut.conf.d/99-noid-nvidia-initramfs.conf \
                     /etc/systemd/system/noid-nvidia-reboot-guard.service \
                     /etc/systemd/system/noid-nvidia-initramfs-resume.service \
                     /etc/systemd/system/noid-nvidia-postboot-verify.service
if command -v restorecon >/dev/null 2>&1; then
    sudo restorecon -F /usr/libexec/noid-nvidia-initramfs-rebuild \
        /usr/libexec/noid-nvidia-rebind-evidence \
        /usr/libexec/noid-nvidia-initramfs-queue \
        /usr/libexec/noid-nvidia-reboot-guard \
        /usr/libexec/noid-nvidia-postboot-verify \
        /etc/kernel/install.d/95-noid-nvidia-initramfs.install \
        /etc/dracut.conf.d/99-noid-nvidia-initramfs.conf \
        /etc/systemd/system/noid-nvidia-reboot-guard.service \
        /etc/systemd/system/noid-nvidia-initramfs-resume.service \
        /etc/systemd/system/noid-nvidia-postboot-verify.service || {
        echo "${RED}ERROR${NC}: SELinux relabel failed for durable NVIDIA rebuild units." >&2
        exit 1
    }
fi
sudo systemctl daemon-reload
sudo systemctl enable noid-nvidia-initramfs-resume.service \
    noid-nvidia-postboot-verify.service

# Driver-only update path. The 95- kernel-install hook above only fires on kernel
# changes. An akmod-nvidia driver bump on the SAME kernel rebuilds the module (via
# its own %posttrans) but nothing regenerates the nvidia-in-initramfs → stale boot
# image (skew survives the next reboot since nvidia is baked into the initramfs).
# A dnf5 actions hook (libdnf5-plugin-actions, M26) covers every dnf path incl. a
# manual `dnf upgrade`; noid-update-all rebuilds inline instead and is skipped via
# M25's process/lock-bound update-window validator. The wrapper durably queues the work and
# acquires a shutdown inhibitor before returning; the worker starts only after
# the DNF transaction releases its rpmdb lock. All pieces are removed by rollback.
sudo tee /usr/libexec/noid-nvidia-initramfs-dnf-action >/dev/null <<'DNFACTION_NV_EOF'
#!/bin/bash
# NoID Privacy — dnf5 actions hook target. Fires when a dnf transaction brings an
# nvidia driver package in. Skipped during noid-update-all (the orchestrator
# rebuilds the initramfs inline, with terminal/GUI progress). Otherwise prints a
# one-line notice to stderr (the dnf5 actions plugin consumes stdout as its IPC
# channel), creates a durable task and acquires a shutdown inhibitor. A direct
# synchronous rebuild here would deadlock on the rpmdb lock the running DNF holds.
set -euo pipefail

if [ -x /usr/libexec/noid-update-window-active ] \
        && /usr/libexec/noid-update-window-active; then
    exit 0
fi
[ -f /run/noid-nvidia-install-running ] \
    && [ ! -L /run/noid-nvidia-install-running ] \
    && [ "$(stat -c '%U:%G:%a' /run/noid-nvidia-install-running \
        2>/dev/null || true)" = root:root:600 ] \
    && installer_pid=$(sed -n 's/^pid=//p' /run/noid-nvidia-install-running) \
    && installer_start=$(sed -n 's/^start_time=//p' /run/noid-nvidia-install-running) \
    && [[ "$installer_pid:$installer_start" =~ ^[0-9]+:[0-9]+$ ]] \
    && [ -r "/proc/$installer_pid/stat" ] \
    && [ "$(awk '{print $22}' "/proc/$installer_pid/stat")" = "$installer_start" ] \
    && tr '\0' '\n' < "/proc/$installer_pid/cmdline" \
        | grep -qF 'noid-nvidia-install.sh' \
    && exit 0
[ -x /usr/libexec/noid-nvidia-initramfs-queue ] || exit 1
echo "NoID Privacy: NVIDIA driver updated — boot-image verification queued; shutdown/sleep is inhibited until success." >&2
exec /usr/libexec/noid-nvidia-initramfs-queue "$(uname -r)" >/dev/null
DNFACTION_NV_EOF
sudo mkdir -p /etc/dnf/libdnf5-plugins/actions.d
sudo tee /etc/dnf/libdnf5-plugins/actions.d/noid-nvidia-initramfs.actions >/dev/null <<'DNFACTIONS_NV_EOF'
# NoID Privacy — rebuild the nvidia-in-initramfs (LUKS-prompt) after a driver-only
# update on the running kernel. The kernel-install hook only covers kernel changes;
# this covers akmod-nvidia driver bumps on the same kernel via any dnf path.
post_transaction:akmod-nvidia:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/libexec/noid-nvidia-initramfs-dnf-action\ >/dev/null
post_transaction:akmod-nvidia-580xx:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/libexec/noid-nvidia-initramfs-dnf-action\ >/dev/null
DNFACTIONS_NV_EOF
sudo chmod 0755 /usr/libexec/noid-nvidia-initramfs-dnf-action
sudo chmod 0644 /etc/dnf/libdnf5-plugins/actions.d/noid-nvidia-initramfs.actions
sudo chown root:root /usr/libexec/noid-nvidia-initramfs-dnf-action \
                     /etc/dnf/libdnf5-plugins/actions.d/noid-nvidia-initramfs.actions
if command -v restorecon >/dev/null 2>&1; then
    sudo restorecon -F /usr/libexec/noid-nvidia-initramfs-dnf-action \
        /etc/dnf/libdnf5-plugins/actions.d/noid-nvidia-initramfs.actions || {
        echo "${RED}ERROR${NC}: SELinux relabel failed for NVIDIA DNF action." >&2
        exit 1
    }
fi

echo "  -> Regenerating initramfs for ${kver} (now WITH nvidia) ..."
if ! run_system_root /usr/bin/depmod -a "${kver}"; then
    mark_nvidia_degraded "depmod-failure"
    echo "  ${RED}[FAIL]${NC} depmod failed; refusing to build/approve the boot image." >&2
    exit 1
fi
INITIAL_FINAL_IMAGE="/boot/initramfs-${kver}.img"
if ! sudo -C 8 /usr/libexec/noid-dracut-regenerate-all \
        --lock-held=7 --kernel="$kver" \
        --allow-pending-mok; then
    mark_nvidia_degraded "canonical-guarded-initramfs-failure"
    echo "  ${RED}[FAIL]${NC} canonical guarded initramfs regeneration failed; DO NOT REBOOT." >&2
    exit 1
fi
if ! sudo test -f "$INITIAL_FINAL_IMAGE" \
        || sudo test -L "$INITIAL_FINAL_IMAGE"; then
    mark_nvidia_degraded "published-initramfs-missing-or-unsafe"
    echo "  ${RED}[FAIL]${NC} published initramfs is missing or unsafe; DO NOT REBOOT." >&2
    exit 1
fi
prepared_boot_id=$(cat /proc/sys/kernel/random/boot_id)
if ! [[ "$prepared_boot_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
    mark_nvidia_degraded "invalid-preparation-boot-id"
    echo "  ${RED}[FAIL]${NC} kernel boot ID is invalid; refusing reboot-ready evidence." >&2
    exit 1
fi
prepared_tmp=$(sudo mktemp "$NVIDIA_STATE_DIR/.prepared.XXXXXX")
prepared_candidate=$prepared_tmp
{
    printf 'status=prepared-awaiting-reboot-validation\n'
    printf '%s\n' "$verify_output"
    printf 'initramfs_sha256=%s\n' \
        "$(sudo sha256sum "$INITIAL_FINAL_IMAGE" | awk '{print $1}')"
    printf 'prepared_boot_id=%s\n' "$prepared_boot_id"
} | sudo tee "$prepared_tmp" >/dev/null
sudo chmod 0600 "$prepared_tmp"
sudo sync -- "$prepared_tmp"
sudo rm -f -- "$NVIDIA_STATE_DIR/${kver}.ready"
sudo sync -- "$NVIDIA_STATE_DIR"
sudo mv -fT -- "$prepared_tmp" "$NVIDIA_STATE_DIR/${kver}.prepared"
prepared_candidate=
sudo sync -- "$NVIDIA_STATE_DIR/${kver}.prepared"
sudo sync -- "$NVIDIA_STATE_DIR"
sudo rm -f "$NVIDIA_STATE_DIR/pending" "$NVIDIA_STATE_DIR/degraded"
echo "  [OK] initramfs regenerated with all four verified NVIDIA modules"

# Conservative NVIDIA lid safety default. M17 owns the general, user-adjustable
# GNOME idle auto-suspend default and its lexically later explicit lid choice on
# every graphics stack. This helper must not overwrite either. Repeated local
# failures and public reports establish a costly NVIDIA suspend/resume class,
# but not universal incidence, one affected generation or one root cause. Only
# a kernel-proven SW_LID trigger gets this --rollback-removable lower default.
echo
echo "  -> Applying NoID Privacy NVIDIA laptop lid-close safety default ..."
echo "     GNOME idle auto-suspend remains the base image's user-adjustable policy."
echo "     Any explicit NoID Privacy Tools lid choice remains higher-priority and untouched."
# Lid-close = lock (not suspend) on LAPTOPS only. Lid-close is handled by
#     systemd-logind; there is no GNOME/dconf lid key.
#     Module 10 intentionally leaves lid behavior vendor-owned; this conditional
#     file replaces the vendor's two suspend actions only after NVIDIA opt-in.
#     M17's 99-noid-user-lid-action.conf sorts later and remains authoritative.
#     HandleLidSwitchDocked remains at the systemd vendor default. Desktops have
#     no lid and are skipped.
#     Effective on the next NVIDIA activation reboot; no live logind restart (would kill
#     the running session, systemd #17308).
nv_is_laptop=0
shopt -s nullglob
for nv_sw_path in /sys/class/input/event*/device/capabilities/sw; do
    [ -r "$nv_sw_path" ] || continue
    nv_sw_bitmap=$(<"$nv_sw_path") || continue
    nv_sw_bitmap=${nv_sw_bitmap//$'\n'/ }
    nv_sw_word=${nv_sw_bitmap##* }
    [[ "$nv_sw_word" =~ ^[[:xdigit:]]+$ ]] || continue
    # Linux input-event bit zero is SW_LID; in a multiword sysfs bitmap the
    # least-significant word is printed last.
    if (( (0x$nv_sw_word & 1) == 1 )); then
        nv_is_laptop=1
        break
    fi
done
shopt -u nullglob
if [ "$nv_is_laptop" -eq 1 ]; then
    if sudo install -d -m 0755 /etc/systemd/logind.conf.d \
            && sudo tee /etc/systemd/logind.conf.d/99-noid-nvidia-lid.conf >/dev/null <<'LOGIND_NV_EOF'
# NoID Privacy - conservative NVIDIA lid-close safety default. Laptop only.
# Repeated local failures justify lock instead of unobserved suspend; this does
# not claim every GPU fails. M10 leaves the vendor lid policy untouched.
# Created by noid-nvidia-install.sh; removed by --rollback.
# M17's explicit 99-noid-user-lid-action.conf sorts later and is never changed.
[Login]
HandleLidSwitch=lock
HandleLidSwitchExternalPower=lock
LOGIND_NV_EOF
    then
        if sudo chmod 0644 /etc/systemd/logind.conf.d/99-noid-nvidia-lid.conf \
                && sudo chown root:root /etc/systemd/logind.conf.d/99-noid-nvidia-lid.conf; then
            if command -v restorecon >/dev/null 2>&1 \
                    && ! sudo restorecon -F /etc/systemd/logind.conf.d/99-noid-nvidia-lid.conf; then
                echo "  ${YELLOW}[warn]${NC} SELinux relabel failed for the lid policy"
            fi
            echo "  [OK] laptop: lid-close = lock, not suspend (effective on reboot)"
        else
            echo "  ${YELLOW}[warn]${NC} lid-policy permissions/ownership failed — install continues"
        fi
    else
        echo "  ${YELLOW}[warn]${NC} could not write lid policy — skipping (install continues)"
    fi
else
    echo "  [--] desktop (no lid): lid policy not needed"
fi

# --- Step 4: Plymouth simpledrm (early flash + fallback) -------------------
# Step 2 added nvidia to the initramfs so nvidia-drm re-renders the LUKS prompt
# after the simpledrm->KMS handover (the actual fix for display-on-dGPU). The
# plymouth.use-simpledrm=1 flag (Module 01) still provides the early
# firmware-framebuffer flash before nvidia-drm binds, and is the fallback if the
# in-initramfs nvidia ever fails to load — so we keep it.
fmt_step 4 6 "Verify boot-display fallback"
if grep -qE "plymouth\.use-simpledrm=1" /proc/cmdline; then
    echo "  [OK] plymouth.use-simpledrm=1 already active in current cmdline"
elif sudo grubby --update-kernel=ALL --args='plymouth.use-simpledrm=1'; then
    echo "  [OK] plymouth.use-simpledrm=1 added to all BLS entries (effective on reboot)"
else
    echo "  ${RED}[FAIL]${NC} grubby could not add the simpledrm fallback; DO NOT REBOOT." >&2
    exit 1
fi
if ! sudo grubby --info=ALL | awk '
    /^args=/ {total++; if ($0 !~ /plymouth\.use-simpledrm=1/) missing++}
    END {exit !(total > 0 && missing == 0)}
'; then
    echo "  ${RED}[FAIL]${NC} at least one boot entry lacks plymouth.use-simpledrm=1." >&2
    exit 1
fi
echo "  [OK] every BLS boot entry has the simpledrm fallback"

# --- Step 5: confirm MOK signing key present (generated in Step 2) ----------
fmt_step 5 6 "Confirm exact signing certificate"
if sudo test -f /etc/pki/akmods/certs/public_key.der; then
    echo "  [OK] MOK key present: /etc/pki/akmods/certs/public_key.der"
else
    # Step 2 creates the key before the build + the Step-3 sign gate hard-exits
    # on an unsigned module, so reaching here is a real anomaly — fail loudly.
    echo "  ${RED}[FAIL]${NC} signing key not found: /etc/pki/akmods/certs/public_key.der"
    echo "         Re-run:  sudo kmodgenca -a && sudo akmods --rebuild --force --kernels $(uname -r) --akmod $AKMOD_NAME"
    return_to_menu_prompt; exit 1
fi

# --- Step 6: MOK import -----------------------------------------------------
fmt_step 6 6 "Check or request certificate enrollment"
# mokutil 0.7.x reports an already-enrolled key with exit status 1 on Fedora;
# its C-locale result text is the usable state indication, not rc==0.
MOK_RECORD_STATE=
mok_test_output=$(sudo env LC_ALL=C mokutil --test-key \
    /etc/pki/akmods/certs/public_key.der 2>&1 || true)
if grep -qF ' is already enrolled' <<<"$mok_test_output"; then
    MOK_STATUS_TEXT="exact akmods certificate already enrolled; no new MOK request"
    MOK_RECORD_STATE=enrolled
    echo "  [OK] $MOK_STATUS_TEXT"
else
    cat <<STEP4

${YELLOW}The exact certificate is not enrolled. mokutil will now prompt for a
one-time MOK password.${NC}
  - Enter a memorable password (only needed ONCE on the blue screen)
  - You will be asked to type it TWICE for confirmation
  - WRITE THIS PASSWORD DOWN — you cannot recover if forgotten
  - It does NOT need to match your login password

STEP4
    read -rp "Press Enter to continue to mokutil ..."
    if sudo mokutil --import /etc/pki/akmods/certs/public_key.der; then
        MOK_STATUS_TEXT="exact akmods certificate queued; MokManager enrollment pending"
        MOK_RECORD_STATE=pending-enrollment
        echo
        echo "  [OK] $MOK_STATUS_TEXT"
    else
        mark_nvidia_degraded "mok-import-failure"
        echo "  ${RED}[FAIL]${NC} mokutil --import failed"
        return_to_menu_prompt
        exit 1
    fi
fi

# The first eight fields were durably published before the interactive MOK
# step. Complete the exact nine-line schema through a same-directory candidate
# and atomic rename; never expose a partially appended ready record. A crash
# before publication leaves the intentionally invalid eight-line record, which
# the post-boot verifier rejects closed.
prepared_record="$NVIDIA_STATE_DIR/${kver}.prepared"
if ! prepared_final=$(sudo mktemp "$NVIDIA_STATE_DIR/.prepared-final.XXXXXX"); then
    mark_nvidia_degraded "prepared-evidence-candidate-allocation-failure"
    echo "  ${RED}[FAIL]${NC} could not allocate reboot-ready NVIDIA evidence." >&2
    exit 1
fi
prepared_candidate=$prepared_final
if ! sudo /usr/bin/sh -c '
        set -eu
        umask 077
        cat "$1"
        printf "mok=%s\n" "$2"
    ' noid-nvidia-prepared "$prepared_record" "$MOK_RECORD_STATE" \
        | sudo tee "$prepared_final" >/dev/null \
        || ! sudo chmod 0600 "$prepared_final" \
        || ! sudo awk -v expected="mok=${MOK_RECORD_STATE}" '
            NR == 9 && $0 == expected {last_ok=1}
            END {exit !(NR == 9 && last_ok)}
        ' "$prepared_final" \
        || ! sudo sync -- "$prepared_final" \
        || ! sudo mv -fT -- "$prepared_final" "$prepared_record" \
        || ! sudo sync -- "$prepared_record" \
        || ! sudo sync -- "$NVIDIA_STATE_DIR"; then
    sudo rm -f -- "$prepared_final"
    prepared_candidate=
    mark_nvidia_degraded "prepared-evidence-finalization-failure"
    echo "  ${RED}[FAIL]${NC} could not atomically finalize reboot-ready NVIDIA evidence." >&2
    exit 1
fi
prepared_final=
prepared_candidate=

# --- Post-install summary ---------------------------------------------------
fmt_done "NVIDIA Stage 1 preparation complete"
cat <<NEXT

Post-reboot runtime validation is still required.

MOK state: ${MOK_STATUS_TEXT}

${BOLD}${YELLOW}NEXT STEPS (CRITICAL):${NC}${YELLOW}

  1. REBOOT your system: sudo reboot

  2. If a new certificate was queued, the "Perform MOK management" BLUE
     SCREEN will appear BEFORE the Fedora boot logo. If the exact certificate
     was already enrolled, skip this step. Navigate with ARROW KEYS + ENTER:

     a. Arrow-down to "Enroll MOK" → ENTER
        (DO NOT press Enter on the default "Continue boot"!)

     b. Optional: "View key 0" to sanity-check the fingerprint
        → ENTER (shows SHA256 → press any key to return)

     c. Arrow-select "Continue" → ENTER

     d. "Enroll the key(s)?" → select "Yes" → ENTER

     e. Enter the MOK password you set above (may not echo)
        Press ENTER when done.

     f. Select "Reboot" → ENTER

  3. After the second reboot, verify the driver is active:
        sudo mokutil --test-key /etc/pki/akmods/certs/public_key.der
        sudo /usr/libexec/noid-nvidia-verify "\$(uname -r)" --require-enrolled
        lsmod | grep nvidia
        nvidia-smi        (should show your GPU)${NC}

${BOLD}If the blue screen does not appear or you pressed "Continue boot"
by mistake:${NC} inspect the pending request with
     sudo mokutil --list-new
If the certificate is no longer pending, re-run this script or manually run:
     sudo mokutil --import /etc/pki/akmods/certs/public_key.der
(then reboot and complete the pending MokManager request)

${BOLD}Recovery if you hit a black screen after reboot:${NC}
  Ctrl+Alt+F3  → log in at TTY as your normal user (NOT root) →
  /usr/local/bin/noid-nvidia-install.sh --rollback
  (The script refuses root; it invokes sudo internally when needed.)
  Then reboot → system returns to the in-tree Nouveau/Mesa path.

${BOLD}Full MOK walkthrough with screenshots:${NC}
  /usr/share/doc/noid-privacy/19-secure-boot-mok.md

${BOLD}Reboot now? (Recommended — the module + MOK queue are ready.)${NC}
NEXT

read -rp "Reboot now? [y/N] " ans
case "${ans:-n}" in
    [yY]|[yY][eE][sS])
        echo "Rebooting in 5 seconds — press Ctrl+C to cancel ..."
        sleep 5
        sudo systemctl reboot
        ;;
    *)
        echo "OK — reboot manually when ready: sudo reboot"
        return_to_menu_prompt
        ;;
esac
exit 0
NVIDIA_INSTALL_EOF

chmod 0755 /usr/local/bin/noid-nvidia-install.sh
chown root:root /usr/local/bin/noid-nvidia-install.sh
log "  [OK] /usr/local/bin/noid-nvidia-install.sh installed (0755)"

# Defensive restorecon (%post-written files usually inherit bin_t, but the
# explicit call guards SELinux-init edge cases).
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F /usr/local/bin/noid-nvidia-install.sh \
        /usr/local/bin/noid-toggle-gsk-gl \
        /usr/local/bin/gnome-control-center \
        /usr/local/bin/gnome-software \
        /usr/libexec/noid-gsk-hybrid-match \
        /usr/libexec/noid-gsk-session-environment \
        /usr/libexec/noid-gsk-settings-launcher-sync \
        /etc/udev/rules.d/62-noid-mutter-headless-offload.rules \
        /usr/lib/systemd/user/noid-gsk-session-environment.service \
        /usr/local/share/applications/org.gnome.Settings.desktop \
        /etc/dnf/libdnf5-plugins/actions.d/noid-gsk-settings-launcher.actions \
        2>/dev/null || true
    restorecon -F \
        /etc/systemd/user/gnome-session.target.wants/noid-gsk-session-environment.service \
        2>/dev/null || true
    log "  [OK] restorecon applied to Module 19 helpers"
fi

# ------------------------------------------------------------------------------
# Phase 4 — Verification
# ------------------------------------------------------------------------------
PHASE="P4-verify"
log "Running verification"

checks=0
fails=0

check() {
    checks=$((checks + 1))
    if eval "$1" >/dev/null 2>&1; then
        log "  [OK] $2"
    else
        fails=$((fails + 1))
        log "  [FAIL] $2"
    fi
}

# M19_USER_UNIT_COMPOSE_VERIFY_BEGIN
verify_gsk_user_unit() {
    local unit_path="$1" runtime_parent="${2:-/run}"
    local runtime_dir metadata unit_dir rc=0
    [ -f "$unit_path" ] && [ ! -L "$unit_path" ] || return 1
    [ -d "$runtime_parent" ] && [ ! -L "$runtime_parent" ] || return 1
    runtime_dir=$(mktemp -d \
        "$runtime_parent/noid-m19-systemd-verify.XXXXXX") || return 1
    metadata=$(LC_ALL=C stat -c '%u:%g:%a:%F' "$runtime_dir" \
        2>/dev/null || true)
    [ "$metadata" = \
        "$(id -u):$(id -g):700:directory" ] || rc=1
    unit_dir=$(dirname -- "$unit_path")
    if [ "$rc" -eq 0 ] \
       && ! /usr/bin/env -i \
            PATH=/usr/sbin:/usr/bin HOME="$runtime_parent" LC_ALL=C \
            XDG_RUNTIME_DIR="$runtime_dir" \
            SYSTEMD_UNIT_PATH="$unit_dir:/etc/systemd/user:/usr/lib/systemd/user" \
            /usr/bin/systemd-analyze --user --recursive-errors=no \
            verify "$unit_path"; then
        rc=1
    fi
    # systemd-analyze creates XDG_RUNTIME_DIR/systemd during offline verify.
    # Delete only children of this freshly created, private mount boundary.
    if ! find "$runtime_dir" -xdev -mindepth 1 -delete 2>/dev/null \
       || ! rmdir -- "$runtime_dir" 2>/dev/null; then
        rc=1
    fi
    return "$rc"
}
# M19_USER_UNIT_COMPOSE_VERIFY_END

# File existence
check "[ -f /usr/share/doc/noid-privacy/19-nvidia-drivers.md ]" \
    "19-nvidia-drivers.md exists"
check "[ -f /usr/share/doc/noid-privacy/19-secure-boot-mok.md ]" \
    "19-secure-boot-mok.md exists"

# File permissions (must be world-readable)
check "[ \"$(stat -c %a /usr/share/doc/noid-privacy/19-nvidia-drivers.md)\" = '644' ]" \
    "19-nvidia-drivers.md perms=0644"
check "[ \"$(stat -c %a /usr/share/doc/noid-privacy/19-secure-boot-mok.md)\" = '644' ]" \
    "19-secure-boot-mok.md perms=0644"

# Content sanity (heredoc delivery worked, not empty)
nvidia_size=$(stat -c %s /usr/share/doc/noid-privacy/19-nvidia-drivers.md 2>/dev/null || echo 0)
mok_size=$(stat -c %s /usr/share/doc/noid-privacy/19-secure-boot-mok.md 2>/dev/null || echo 0)
check "[ \"$nvidia_size\" -gt 1024 ]" \
    "19-nvidia-drivers.md > 1KB (actual: ${nvidia_size} bytes)"
check "[ \"$mok_size\" -gt 1024 ]" \
    "19-secure-boot-mok.md > 1KB (actual: ${mok_size} bytes)"

# Sanity: Module 19 did NOT accidentally install NVIDIA packages
if ! nvidia_inventory=$(rpm -qa --qf '%{NAME}\n' 2>/dev/null); then
    die "RPM inventory query failed; cannot verify the no-NVIDIA build contract"
fi
nvidia_rpms=0
while IFS= read -r rpm_name; do
    case "$rpm_name" in
        akmod-nvidia*|kmod-nvidia*|nvidia-settings*|nvidia-persistenced*|xorg-x11-drv-nvidia*)
            nvidia_rpms=$((nvidia_rpms + 1))
            ;;
    esac
done <<<"$nvidia_inventory"
check "[ \"$nvidia_rpms\" -eq 0 ]" \
    "no NVIDIA RPMs installed at build (Module 19 defers install to user, actual count: ${nvidia_rpms})"

# Stage 1 install helper (Phase 3c)
check "[ -f /usr/local/bin/noid-nvidia-install.sh ]" \
    "/usr/local/bin/noid-nvidia-install.sh exists"
check "[ -x /usr/local/bin/noid-nvidia-install.sh ]" \
    "/usr/local/bin/noid-nvidia-install.sh executable"
check "[ \"$(stat -c %a /usr/local/bin/noid-nvidia-install.sh 2>/dev/null)\" = '755' ]" \
    "/usr/local/bin/noid-nvidia-install.sh perms=0755"
check "bash -n /usr/local/bin/noid-nvidia-install.sh" \
    "noid-nvidia-install.sh syntax (bash -n) valid"
check "[ -f /usr/local/bin/noid-toggle-gsk-gl ] && [ ! -L /usr/local/bin/noid-toggle-gsk-gl ]" \
    "/usr/local/bin/noid-toggle-gsk-gl is a regular file"
check "[ -x /usr/local/bin/noid-toggle-gsk-gl ]" \
    "/usr/local/bin/noid-toggle-gsk-gl executable"
check "[ \"$(stat -c %U:%G:%a /usr/local/bin/noid-toggle-gsk-gl 2>/dev/null)\" = 'root:root:755' ]" \
    "/usr/local/bin/noid-toggle-gsk-gl metadata=root:root:0755"
check "bash -n /usr/local/bin/noid-toggle-gsk-gl" \
    "noid-toggle-gsk-gl syntax (bash -n) valid"
check "[ -f /usr/local/bin/gnome-control-center ] && [ ! -L /usr/local/bin/gnome-control-center ] && [ -x /usr/local/bin/gnome-control-center ]" \
    "GNOME Settings renderer wrapper is regular and executable"
check "[ \"$(stat -c %U:%G:%a /usr/local/bin/gnome-control-center 2>/dev/null)\" = 'root:root:755' ]" \
    "GNOME Settings renderer wrapper metadata=root:root:0755"
check "bash -n /usr/local/bin/gnome-control-center" \
    "GNOME Settings renderer wrapper syntax valid"
check "[ -f /usr/local/bin/gnome-software ] && [ ! -L /usr/local/bin/gnome-software ] && [ -x /usr/local/bin/gnome-software ]" \
    "GNOME Software renderer wrapper is regular and executable"
check "[ \"$(stat -c %U:%G:%a /usr/local/bin/gnome-software 2>/dev/null)\" = 'root:root:755' ]" \
    "GNOME Software renderer wrapper metadata=root:root:0755"
check "bash -n /usr/local/bin/gnome-software" \
    "GNOME Software renderer wrapper syntax valid"
check "! grep -qE 'systemctl|--gapplication-service|--autostart' /usr/local/bin/gnome-software" \
    "GNOME Software wrapper cannot manage or background-start its service"
check "[ -L /etc/systemd/user/gnome-software.service ] && [ \"$(readlink /etc/systemd/user/gnome-software.service 2>/dev/null)\" = /dev/null ]" \
    "GNOME Software silent-machine service mask remains exact"
check "[ -f /usr/libexec/noid-gsk-session-environment ] && [ ! -L /usr/libexec/noid-gsk-session-environment ] && [ -x /usr/libexec/noid-gsk-session-environment ]" \
    "post-Shell GTK session helper is regular and executable"
check "[ \"$(stat -c %U:%G:%a /usr/libexec/noid-gsk-session-environment 2>/dev/null)\" = 'root:root:755' ]" \
    "post-Shell GTK session helper metadata=root:root:0755"
check "bash -n /usr/libexec/noid-gsk-session-environment" \
    "post-Shell GTK session helper syntax valid"
check "rpm -q dbus-tools >/dev/null 2>&1 && [ -x /usr/bin/dbus-update-activation-environment ] && [ ! -L /usr/bin/dbus-update-activation-environment ] && [ \"$(rpm -qf --qf '%{NAME}' /usr/bin/dbus-update-activation-environment 2>/dev/null)\" = dbus-tools ]" \
    "post-Shell GTK session helper has its exact Fedora dbus-tools runtime"
check "[ -f /usr/lib/systemd/user/noid-gsk-session-environment.service ] && [ ! -L /usr/lib/systemd/user/noid-gsk-session-environment.service ]" \
    "post-Shell GTK user unit is a regular distribution unit"
check "[ \"$(stat -c %U:%G:%a /usr/lib/systemd/user/noid-gsk-session-environment.service 2>/dev/null)\" = 'root:root:644' ]" \
    "post-Shell GTK user unit metadata=root:root:0644"
checks=$((checks + 1))
gsk_verify_output=""
if gsk_verify_output=$(verify_gsk_user_unit \
        /usr/lib/systemd/user/noid-gsk-session-environment.service 2>&1); then
    log "  [OK] post-Shell GTK user unit validates"
else
    fails=$((fails + 1))
    log "  [FAIL] post-Shell GTK user unit validates"
    while IFS= read -r line || [ -n "$line" ]; do
        log "  [DIAG] $line"
    done <<< "$gsk_verify_output"
fi
check "grep -qxF 'RestrictAddressFamilies=AF_UNIX' /usr/lib/systemd/user/noid-gsk-session-environment.service && ! grep -qE '^(PrivateNetwork|IPAddressDeny)=' /usr/lib/systemd/user/noid-gsk-session-environment.service" \
    "post-Shell GTK user unit uses only its enforceable AF_UNIX socket boundary"
check "[ -L /etc/systemd/user/gnome-session.target.wants/noid-gsk-session-environment.service ] && [ \"$(readlink /etc/systemd/user/gnome-session.target.wants/noid-gsk-session-environment.service 2>/dev/null)\" = /usr/lib/systemd/user/noid-gsk-session-environment.service ]" \
    "post-Shell GTK user unit has the exact global enablement"
check "[ ! -e /etc/systemd/user/noid-gsk-session-environment.service ] && [ ! -L /etc/systemd/user/noid-gsk-session-environment.service ]" \
    "no administrator unit shadows the distribution GTK session unit"
check "[ -f /usr/libexec/noid-gsk-settings-launcher-sync ] && [ ! -L /usr/libexec/noid-gsk-settings-launcher-sync ] && [ -x /usr/libexec/noid-gsk-settings-launcher-sync ]" \
    "GNOME Settings launcher sync helper is regular and executable"
check "[ \"$(stat -c %U:%G:%a /usr/libexec/noid-gsk-settings-launcher-sync 2>/dev/null)\" = 'root:root:755' ]" \
    "GNOME Settings launcher sync helper metadata=root:root:0755"
check "bash -n /usr/libexec/noid-gsk-settings-launcher-sync" \
    "GNOME Settings launcher sync helper syntax valid"
check "[ -f /usr/local/share/applications/org.gnome.Settings.desktop ] && [ ! -L /usr/local/share/applications/org.gnome.Settings.desktop ]" \
    "GNOME Settings XDG admin launcher is a regular file"
check "[ \"$(stat -c %U:%G:%a /usr/local/share/applications/org.gnome.Settings.desktop 2>/dev/null)\" = 'root:root:644' ]" \
    "GNOME Settings XDG admin launcher metadata=root:root:0644"
check "grep -qxF 'Exec=/usr/local/bin/gnome-control-center' /usr/local/share/applications/org.gnome.Settings.desktop" \
    "GNOME Settings launcher selects the application wrapper"
check "grep -qxF 'DBusActivatable=false' /usr/local/share/applications/org.gnome.Settings.desktop && ! grep -q '^DBusActivatable=true$' /usr/local/share/applications/org.gnome.Settings.desktop" \
    "GNOME Settings launcher uses its Exec path"
check "desktop-file-validate /usr/local/share/applications/org.gnome.Settings.desktop" \
    "GNOME Settings XDG admin launcher validates"
check "grep -qxF 'post_transaction:gnome-control-center:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/libexec/noid-gsk-settings-launcher-sync\\ >/dev/null' /etc/dnf/libdnf5-plugins/actions.d/noid-gsk-settings-launcher.actions" \
    "GNOME Settings launcher has exact dnf5 self-healing action"
check "[ ! -e /usr/local/share/dbus-1/services/org.gnome.Settings.service ] && [ ! -L /usr/local/share/dbus-1/services/org.gnome.Settings.service ]" \
    "GNOME Settings has no duplicate D-Bus service shadow"
check "[ -f /usr/libexec/noid-gsk-hybrid-match ] && [ ! -L /usr/libexec/noid-gsk-hybrid-match ] && [ -x /usr/libexec/noid-gsk-hybrid-match ]" \
    "NVIDIA-offload GTK topology matcher is regular and executable"
check "[ \"$(stat -c %U:%G:%a /usr/libexec/noid-gsk-hybrid-match 2>/dev/null)\" = 'root:root:755' ]" \
    "NVIDIA-offload GTK topology matcher metadata=root:root:0755"
check "bash -n /usr/libexec/noid-gsk-hybrid-match" \
    "NVIDIA-offload GTK topology matcher syntax valid"
check "[ -f /etc/udev/rules.d/62-noid-mutter-headless-offload.rules ] && [ ! -L /etc/udev/rules.d/62-noid-mutter-headless-offload.rules ]" \
    "connectorless offload GPU Mutter rule is a regular file"
check "[ \"$(stat -c %U:%G:%a /etc/udev/rules.d/62-noid-mutter-headless-offload.rules 2>/dev/null)\" = 'root:root:644' ]" \
    "connectorless offload GPU Mutter rule metadata=root:root:0644"
check "udevadm verify /etc/udev/rules.d/62-noid-mutter-headless-offload.rules" \
    "connectorless offload GPU Mutter rule validates"
check "[ ! -e /etc/environment.d/90-noid-gsk-renderer.conf ] && [ ! -L /etc/environment.d/90-noid-gsk-renderer.conf ]" \
    "GTK4 GL renderer policy has no compose-host static override"
check "[ ! -e /etc/xdg/noid-privacy/gsk-renderer.mode ] && [ ! -L /etc/xdg/noid-privacy/gsk-renderer.mode ]" \
    "GTK4 renderer policy has no compose-host mode override"
check "[ ! -e /usr/lib/systemd/user-environment-generators/55-noid-gsk-renderer ] && [ ! -L /usr/lib/systemd/user-environment-generators/55-noid-gsk-renderer ]" \
    "retired GTK renderer vendor generator is absent"
check "[ ! -e /etc/systemd/user-environment-generators/55-noid-gsk-renderer ] && [ ! -L /etc/systemd/user-environment-generators/55-noid-gsk-renderer ]" \
    "legacy GTK renderer generator override is absent during compose"

log "Verification: $((checks - fails))/$checks passed"
if [ "$fails" -gt 0 ]; then
    die "$fails verification check(s) FAILED"
fi

log "=== Module 19 Hardware Documentation complete ==="
%end

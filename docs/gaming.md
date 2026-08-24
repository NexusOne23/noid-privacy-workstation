# Gaming Mode (Steam / Proton) — opt-in

NoID Privacy Workstation is hardened, not gaming-tuned. Its opt-in helper
changes the two repository-managed settings known to be required by the
documented Steam/Proton path, then installs the RPM Fusion Steam package only
after the required reboot has made 32-bit execution live. Other hardening
remains unchanged. Enabling and disabling verify every configured boot entry
and the SELinux boolean; a failed policy transition attempts to restore the
prior state and exits non-zero.

> **Honest scope:** Gaming-Mode removes *NoID Privacy's* blockers. It does **not**
> guarantee that every game runs — Proton per-title compatibility and
> anti-cheat support (including title-specific EAC/BattlEye support) are
> upstream/vendor boundaries. They do not affect every title or distribution
> identically, and NoID Privacy cannot guarantee them.

---

## What's already open by design

The maintainer built the hardening gaming-aware. The classic Steam-breakers are
deliberately left enabled:

| Surface | NoID Privacy state | Why it's fine for gaming |
|---|---|---|
| `vm.max_map_count` | Fedora vendor policy (`/usr/lib/sysctl.d/10-map-count.conf`; verify with `sysctl vm.max_map_count`) | NoID Privacy does not override this workload-dependent ceiling |
| `user.max_user_namespaces` | **256** (not KSPP-0) | Proton pressure-vessel / bwrap need userns (M02) |
| `/home` `noexec` | **off** (only `nosuid,nodev`) | Proton games execute from `~/.local/share/Steam` (M22) |
| SMT / mitigations | `mitigations=auto` (no `,nosmt`) | retains SMT; the throughput effect of disabling it is workload- and CPU-topology-dependent (M01) |
| `ntsync` | not blocked, loads on demand | Wine/Proton fsync path available (M21) |
| hardened_malloc | not installed | no malloc-incompatibility crashes |

`/tmp` + `/dev/shm` `noexec`, `selinuxuser_execstack` / `execheap`, and the
other listed controls are not changed by this helper. A particular title may
still conflict with them; investigate that title instead of assuming universal
compatibility.

---

## The two repository-managed settings Gaming Mode relaxes

### 1. `ia32_emulation=0` → `=1` (32-bit execution)

The kernel cmdline (Module 01) ships `ia32_emulation=0 vdso32=0`, disabling
32-bit execution entirely. Steam's launcher is **i686 (32-bit)**, so without
this flag the launcher binary itself cannot exec — Steam, 32-bit Proton games,
and the whole 32-bit multilib are non-executable.

- **Relaxation:** `ia32_emulation=1 vdso32=1` through the shared boot-mutation
  lock/guard, with Fedora's `grubby` updating and verifying every BLS entry.
  This is a **boot parameter → a REBOOT is required** to apply (and to revert).
- **Trade-off:** re-opens the 32-bit syscall/ABI attack surface (KSPP recommends
  off on pure-64-bit systems). A real, documented, opt-in security relaxation —
  not a no-op.

### 2. `selinuxuser_execmod=off` → `on` (W^X for Wine)

Module 12 sets the `selinuxuser_execmod` SELinux boolean **off** (write-xor-
execute hardening for the user domain). Wine/Proton's `wineboot.exe` loads
Windows DLLs (e.g. `ntdll.dll`) from the Proton prefix and calls
`mprotect(PROT_EXEC)` on those file-mappings — the `execmod` permission. With
the boolean off, that `mprotect` is denied, `wineboot` dies, and every Proton
game window flashes for a few seconds and crashes.

- **Relaxation:** `setsebool -P selinuxuser_execmod on` (live, no reboot).
- **Trade-off:** re-opens W^X for unconfined home content while Gaming-Mode is
  on. **SELinux stays in Enforcing mode** throughout — only this one boolean
  changes.
- **Why a global boolean and not a custom label:** this is the established 2026
  compatibility path for this policy. A targeted `steam_lib_t` label would be
  brittle here —
  Proton writes fresh DLLs per-game into `compatdata/*/pfx/`, so the label would
  need a perpetual `fcontext` + `restorecon` treadmill. Tracked as future
  tech-debt, not shipped.

Native Linux games (no Windows-DLL text-relocation loads) need only blocker #1.
Proton/Wine games need both.

---

## How to enable / disable

Gaming Mode is an installed-system feature. The Setup group is intentionally
absent on transient Live media, where there is no durable BLS policy and an RPM
transaction would modify only the disposable overlay. The CLI status remains
available there, reports the next-boot state as not applicable, and rejects
`on`/`off` without changing the Live session.

### GUI (recommended)

**NoID Privacy Setup** (the welcome app, also in the app grid) → **Gaming Mode
(Steam / Proton)** group → toggle **Enable Gaming Mode**.

- Enabling opens a confirmation dialog, publishes the compatibility policy and
  tells you to restart. Setup then exposes **Complete Steam installation**;
  after the reboot that row opens the visible DNF transaction. The separation
  is required because Steam pulls i686 RPMs whose package scriptlets cannot
  execute while the current kernel still has `ia32_emulation=0`.
- Disabling restores full hardening (also needs a reboot for the 32-bit flip).

### CLI

```bash
sudo noid-toggle-gaming on       # prepare compatibility policy
sudo reboot
sudo noid-toggle-gaming on       # install Steam after IA32 is live
sudo noid-toggle-gaming off      # restore full hardening (Steam left installed)
noid-toggle-gaming               # status (no root needed)
noid-toggle-gaming status        # same — shows flag, ia32 (boot/next), execmod, Steam
```

When Steam is absent, the first `on` intentionally performs no DNF transaction.
**Reboot**, then rerun `on` (or use Setup's completion row) to install Steam.
If Steam is already installed, `on` only selects/verifies the compatibility
policy and still reports whether the reboot is pending.

Default state is **OFF**: no flag file, full hardening, `ia32_emulation=0`,
`selinuxuser_execmod=off`.

Running `off` when the hardened policy is already exact is a true no-op.
Running `on` against an already-exact compatibility policy never rewrites
BLS/kernel-command-line bytes, but it can still perform the separate Steam
installation when Steam is absent and live IA32 execution has been proven. A
real policy transition is published by M01 from the exact, validated Gaming
receipt and is recorded through the same firstboot command-line evidence
contract as other supported boot writers. Toggling back before the requested
reboot safely replaces that exact same-boot pending record.

---

## Steam delivery

Steam is installed from **RPM Fusion nonfree** (`dnf install steam`), which
pulls `steam-devices` (controller udev rules) plus the required 32-bit multilib
stack. The helper refuses that transaction until `/proc/cmdline` proves both
`ia32_emulation=1` and `vdso32=1` in the current boot; persisted BLS arguments
alone are not execution evidence. After installation it executes the installed
i686 loader and, when present, Fedora's `fc-cache-32` helper before claiming
success. DNF displays the current package set, download size and disk change;
those moving repository values are deliberately not hard-coded here. Flathub
marks its Steam package unverified and describes it as a community package not
officially supported by Valve. It is therefore not part of NoID Privacy's
publisher-verified Flatpak subset, so the RPM is the delivery path.

`off` does **not** uninstall Steam — remove it manually with
`sudo dnf remove steam` if you want.

---

## Controllers

USBGuard is whitelist-only. When you plug a controller it is blocked until you
allow it:

- A desktop notification (`usbguard-notifier`) prompts you — one click allows the
  device for the session.
- This is **session-only** by default (re-blocked on reboot/re-plug). Gaming-Mode
  does **not** auto-add a permanent gamepad allow-rule, because a persistent
  HID-class allow-rule would widen the BadUSB-HID-injection surface. If you want
  it permanent, add a scoped USBGuard rule yourself
  (`Security > USB` reasoning in the USBGuard docs).

For games without native controller support, Steam Input emulates keyboard/mouse
from the pad; on Wayland this triggers the GNOME RemoteDesktop portal prompt
(local input injection, not network remote access) — allow it.

---

## What is NOT touched

Gaming-Mode relaxes exactly the two blockers above. It does not change:

- `/tmp` + `/dev/shm` `noexec` (some titles or tools may still need separate
  investigation)
- `selinuxuser_execstack` / `selinuxuser_execheap` (stay off; a real Proton run
  needed neither — some anti-cheat or Mono/.NET-heavy titles *might*, verify
  per-title)
- SMT / CPU mitigations
- the firewall, USBGuard whitelist, AIDE, auditd, LUKS, or any other layer
- SELinux mode — stays **Enforcing**

---

## Reverting completely

```bash
sudo noid-toggle-gaming off
sudo reboot
# optional: remove Steam + its data
sudo dnf remove steam
```

After reboot, verify that `noid-toggle-gaming status` shows the repository
default restored (`ia32_emulation` off in both current and next boot,
`selinuxuser_execmod` off, no flag file). Steam and its user data are separate
state and remain unless explicitly removed.

---

## See also

- [`docs/scope.md`](scope.md) — why NoID Privacy is not a gaming-*optimized* rig
- [`docs/performance-profile.md`](performance-profile.md) — the honest hardening
  perf cost
- `noid-status` — one-screen hardening state (shows SELinux mode, kernel cmdline)

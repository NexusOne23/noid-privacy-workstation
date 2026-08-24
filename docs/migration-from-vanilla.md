# Migration from Vanilla Fedora

How to evaluate a subset of NoID Privacy hardening on an already-installed
vanilla Fedora 44 Workstation. This is a design guide, not an executable
migration recipe: copying raw kickstart fragments bypasses their ordering,
package, SELinux, systemd and postcondition contracts.

## Scope

This doc is for users who:

- Already have a working Fedora 44 install with data they don't want
  to lose.
- Want to adopt most of NoID Privacy's hardening incrementally.
- Accept that in-place migration cannot achieve 100% parity with a
  fresh NoID Privacy install (LUKS2 already-decided, partition layout fixed,
  and Module 01 boot policy spans the durable kernel command line, GRUB
  defaults and every normal BLS entry).

## What is not safely release-qualified for in-place migration

- **LUKS2 full-disk encryption** — requires install-time decision.
  Workaround: backup, reinstall with encryption, restore data.
- **Module 22 storage topology** — individual mount flags can be changed, but
  the installer-selected partition/subvolume layout cannot be reconstructed
  non-disruptively and is not claimed equivalent.

## What can be evaluated through a reviewed migration transaction

Listed in order of safety (safest first):

### Tier 1: Lower-impact changes (still require review and rollback)

- **M01 boot policy** — adapt M01's canonical transaction to converge
  `/etc/kernel/cmdline`, `/etc/default/grub` and every normal BLS entry, with
  captured prior bytes and postcondition checks. Updating only one GRUB file
  is not parity. Caveat: `lockdown=integrity` may reject unsigned modules;
  validate a recovery boot path before rebooting.
- **M02 sysctl hardening** — review and copy all three owned files:
  `/etc/sysctl.d/99-audit-fixes.conf`, `99-hardening.conf` and
  `99-userns.conf`. Preserve their lexical relationship to M07's
  `98-privacy-network.conf`, then apply with `sysctl --system`.
- **M05 LAN isolation and resolver policy** — M05 owns the Quad9
  systemd-resolved drop-in, LAN-discovery dconf locks and the wider LAN policy;
  do not reduce it to one copied file.
- **M07 physical-interface IPv6-off policy** — this is a locked
  NetworkManager/sysctl transaction with a published runtime status, not a
  supported two-file copy. VPN-internal IPv6 remains a distinct boundary.
- **M11 time synchronization** — M11 owns the chrony NTS configuration and
  restricted service contract. DNS/systemd-resolved policy belongs to M05.
- **M12 auditd** — stage the exact validated rules for the next boot and verify
  the effective immutable policy after reboot. A running NoID Privacy policy
  ends with `-e 2`; do not weaken that boundary or claim `augenrules --load`
  replaced immutable live rules.
- **M13 AIDE** — install and validate the complete M13 workflow first. On a
  NoID Privacy image, `noid-aide-baseline-review prepare` creates only a candidate;
  the user reviews its report and commits the exact displayed SHA-256. Never
  activate `.new.gz` directly or delegate acceptance of local trust state.
- **M17 GNOME hardening** — owns the broader
  `/etc/dconf/db/distro.d/10-noid-gnome-privacy` profile and locks plus related
  GNOME/session policy; it is not covered by M05.
- **M26 optional packages doc** — read `/usr/share/doc/noid-privacy/26-optional-packages.md`
  and add packages on a need-basis.

### Tier 2: Service minimisation (may break workflows)

- **M08 service masking** — apply only reviewed entries from M08's explicit
  `MASK_LIST_EOF`; M05, M11 and M24 add service-specific masks. The set evolves,
  so the source and its structural tests are authoritative rather than a
  copied count.
  Dangerous without
  review: may break avahi/wsdd discovery, CUPS printing, thermald
  auto-throttling. Recommendation: cherry-pick, don't bulk-apply.
- **M14 USBGuard** — inventory and individually review the exact currently
  connected devices, then construct a narrow policy and test recovery before
  enabling whitelist-only enforcement. Never bless every connected device
  automatically; an already-connected untrusted device must not become a
  permanent allow rule.

### Tier 3: Networking hardening (breaks connectivity during transition)

- **M03 firewalld/topology boundary** — owns `block-lan-out`, physical-link
  topology and related firewalld/netdev policy. Apply only through a reviewed
  migration transaction during a planned maintenance window; a raw
  `firewall-cmd --runtime-to-permanent` is not source parity.
- **M04 ARP hardening** — install the closed pre-network identity guard,
  transactional permanent-gateway pinning and the awaited NM pre-up hook.
  M03 consumes the validated identity directly for its fail-closed XDP return
  gate; there is no non-enforcing nft shadow table. Standard RFC 5227 ARP/ACD
  remains enabled. A same-IP/new-MAC transition removes only the exact stale
  managed pin and requires two time-separated matching raw observations with
  no conflicting kernel-neighbour identity; ambiguity fails closed. Ethernet
  MACs are not authenticated, so verify unexpected gateway changes with the
  network operator.
- **M06 VPN safety/WAN-strict layer** — owns genuine VPN-interface
  classification, the inbound-DROP `noid-vpn` zone and the
  `inet noid_wan_strict` table/controller. Test with VPN up and down and every
  runtime mode; separately verify any provider route/DNS killswitch.

### Tier 4: Advanced (recommended: fresh install)

- **M15 Intel ME mitigation** — requires careful dracut + initramfs
  regeneration and exact PCI-driver postchecks. A broken retrofit can prevent
  boot or hide supported MEI/fwupd visibility; it does not change the
  firmware-enforced Boot Guard hardware state.
- **M16 Firefox hardening** — best done per-profile manually rather
  than system-wide on an existing install (profile conflicts).
- **M20 snapper** — requires Btrfs root; retrofit is possible on
  Btrfs-installed systems but adds pre/post-transaction snapshot
  retention that can fill disk fast.

## Migration script (not currently shipped)

There is no supported automated migration tool. Treat the list above as a
review map, not as commands to copy. A future helper would need to:

1. Detect Fedora version + edition.
2. Back up original configs to `/var/lib/noid-migrate/backup/`.
3. Apply Tier-1 only (safe, additive).
4. Log every change + recovery command.
5. Leave Tier-2+ as manual user decisions.

## Migration execution boundary

Do not download a `.ks` file and execute or extract arbitrary heredocs from it
on a live host. Build a reviewed migration package or script that owns exact
paths, captures the prior bytes and state, applies modules in dependency order,
and verifies every postcondition. If that artifact does not exist, a fresh
install from a verified ISO is the supported deterministic path.

For AIDE on an already installed NoID Privacy system, inspect the installed workflow:

```bash
sudo noid-aide-baseline-review status
sudo noid-aide-baseline-review prepare
# Review the candidate report and metadata yourself. Commit only the exact
# SHA-256 printed by the tool, using its explicit interactive confirmation.
```

Neither this documentation nor an agent can decide that changed local files
belong in the trusted baseline.

## Testing post-migration

Repository structural tests validate source invariants; they are not a live
system migration verifier. Use them while developing a migration artifact:

```bash
cd noid-privacy-workstation
bash tests/run-all.sh
```

A green structural suite does not establish installed-state parity. A migration
also needs path/mode/owner/hash manifests, runtime unit and SELinux checks,
reboot persistence tests and an explained transformation list.

## Reverting

Do not assume every change is easily reversible. A root snapshot covers the
expected root Btrfs state, not the separate `/home` subvolume, and rollback
requires a system that can still boot. Keep independent backups before any
migration. On an already installed, qualifying NoID Privacy layout, first require
`sudo /usr/libexec/noid-snapper-status` to report `boot=ready`; a root snapshot
can then be one additional recovery layer:

```bash
sudo noid-snap-pre "pre-noid-migration"
# ... apply changes ...
# If unhappy:
sudo snapper -c root list
sudo noid-snap-rollback <snapshot-number>
sudo reboot
```

A generic pre-existing Snapper setup does not inherit NoID Privacy's fstab/BLS/default-
subvolume contract. Follow that system's maintained recovery procedure rather
than assuming the NoID Privacy wrapper is applicable.

## When to fresh-install instead

Fresh-install is strongly recommended if you:

- Don't already have LUKS2 FDE (can't add non-disruptively).
- Want release-qualified source/image parity rather than a best-effort
  in-place reconstruction. The ISO is not claimed byte-reproducible across
  arbitrary hosts.
- Are on an older Fedora release (F43 or below) and need to upgrade
  anyway.
- Have accumulated significant `/etc` cruft from previous OS installs.

## References

- [`docs/build.md`](build.md) — how to build the NoID Privacy ISO
- [`INDEX.md`](../INDEX.md) — per-Module source tree
- [`docs/known-failures.md`](known-failures.md) — per-Module failure
  modes (useful to anticipate migration issues)

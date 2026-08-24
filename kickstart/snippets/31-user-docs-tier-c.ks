# ============================================================================
# Module 31 — User Documentation Tier C (architecture + troubleshooting + product boundaries)
# Status: LOCKED 2026-08-22 (v78) — scope the dated PQ evidence without claiming an exact v1.7 package manifest.
#
# Ships:
#   - 99-troubleshooting.md  cross-cutting FAQ + decision trees
#   - 00-architecture.md     module design + principles + dependencies
#   - 27-performance.md      honest defaults, opt-ins + measurement boundary
#   - threat-model.md        canonical product attacker/coverage boundary
#   - scope.md               canonical audience + explicit anti-targets
#   - post-quantum-readiness.md  canonical PQ capability/residual-risk status
#   - performance-profile.md canonical source-level performance rationale
#   - licensing.md           canonical multi-license repository inventory
#
# Yelp / Mallard integration INTENTIONALLY SKIPPED — rationale in
# docs/decision-yelp-mallard-skip.md (hardened-distro peer consensus is
# markdown; maintenance cost + CVE surface + GNOME lock-in don't justify
# the investment). Do not re-propose without revisiting that doc.
#
# Doc-accuracy constraints (verified; keep on future edits):
#   - firewalld verbs: `--delete-policy` + `--reload` (the
#     --remove-policy/--add-policy forms do NOT exist); no gateway-
#     exception claim anywhere (block-lan-out has none).
#   - Boot recovery: rescue.target/emergency.target provide NO maintenance
#     shell on the installed system (root account locked, SULOGIN_FORCE
#     unset — sulogin reports the locked account and boot continues). The
#     documented ladder is: older kernel -> systemd.unit=multi-user.target
#     text login (user account + sudo; snapshot rollback works there) ->
#     systemd.mask=<unit> one-boot -> init=/bin/bash last resort (remount
#     rw + touch /.autorelabel) -> live media. tests/31 pins the no-shell
#     warning + the text-login ladder.
#   - Snapshot rollback is CLI-only through `noid-snap-rollback` — the
#     bootable-GRUB-snapshot layer was removed with M20.
#   - Reviewed counters: bootloader cmdline count = a range (varies by CPU
#     vendor + build); M02 sysctl counts are live-verifiable (sudo required —
#     the file is 0640); M08 has exactly 82 source masks and the cross-module
#     unique total is 96. The live count can include Fedora preset masks.
#   - The %post verification keyword stays GENERIC "Module structure" —
#     a hardcoded module-count keyword broke a build when modules were
#     added.
#   - GNOME Software FAQs: usable AppStream application metadata, not
#     repository origin, determines whether its package backend can expose
#     a working Remove action; upstream gnome-software stays resident after
#     a manual launch (native masked D-Bus route — graceful complete-quit
#     documented).
#
# Doc-aggregator duty (class): 00-architecture.md quotes counts and
# listings from master.ks + many modules. Three M08-propagation misses in
# one cycle established the duty: when M08's mask heredoc changes, grep
# ALL user-docs for "M08" counter references in the same cycle. Same for
# master.ks %include changes (module-structure heading + dependency arrow
# + reserved-module list).
#
# Conventions: [M31] log-prefix. Verify-block keyword checks use literal
# grep -Fqi (Lesson #30). Package modifications: NONE.
#
# Shipped Markdown target: /usr/share/doc/noid-privacy/99-troubleshooting.md
# Shipped Markdown heredoc: TRB_EOF
# Shipped Markdown target: /usr/share/doc/noid-privacy/00-architecture.md
# Shipped Markdown heredoc: ARCH_EOF
# Shipped Markdown target: /usr/share/doc/noid-privacy/27-performance.md
# Shipped Markdown heredoc: PERFORMANCE_EOF
# Shipped Markdown target: /usr/share/doc/noid-privacy/threat-model.md
# Shipped Markdown heredoc: NOID_THREAT_MODEL_DOC_EOF
# Shipped Markdown target: /usr/share/doc/noid-privacy/scope.md
# Shipped Markdown heredoc: NOID_SCOPE_DOC_EOF
# Shipped Markdown target: /usr/share/doc/noid-privacy/post-quantum-readiness.md
# Shipped Markdown heredoc: NOID_PQ_DOC_EOF
# Shipped Markdown target: /usr/share/doc/noid-privacy/performance-profile.md
# Shipped Markdown heredoc: NOID_PERFORMANCE_PROFILE_DOC_EOF
# Shipped Markdown target: /usr/share/doc/noid-privacy/licensing.md
# Shipped Markdown heredoc: NOID_LICENSING_DOC_EOF
# ============================================================================

%packages --exclude-weakdeps
# No packages.
%end

%post --log=/var/log/ks-31-user-docs-tier-c.log --erroronfail
set -euo pipefail

PHASE=""
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [M31] ${PHASE}: $*"; }
die() { log "FAIL: $*"; exit 1; }
DOC_TMP=""
DOC_PUBLICATION_ACTIVE=0
DOC_PUBLISHED_TARGET=""
DOC_PUBLISHED_ID=""
STAMP_TMP=""
STAMP_PUBLICATION_ACTIVE=0
STAMP_DIR=/var/lib/noid-privacy
STAMP="$STAMP_DIR/stamp-31-user-docs-tier-c.ok"
cleanup() {
    local current_id
    if [ "${DOC_PUBLICATION_ACTIVE:-0}" -eq 1 ] \
       && [ -n "${DOC_PUBLISHED_TARGET:-}" ] \
       && [ -n "${DOC_PUBLISHED_ID:-}" ]; then
        current_id=$(stat -Lc '%d:%i' -- "$DOC_PUBLISHED_TARGET" \
            2>/dev/null || true)
        if [ "$current_id" = "$DOC_PUBLISHED_ID" ]; then
            if ! rm -f -- "$DOC_PUBLISHED_TARGET"; then
                log "FAIL: could not retire unverified Tier-C document"
            fi
            sync -- "$(dirname "$DOC_PUBLISHED_TARGET")" \
                >/dev/null 2>&1 || true
        fi
    fi
    if [ -n "${DOC_TMP:-}" ]; then
        rm -f -- "$DOC_TMP" || true
    fi
    if [ -n "${STAMP_TMP:-}" ]; then
        rm -f -- "$STAMP_TMP" || true
    fi
    if [ "${STAMP_PUBLICATION_ACTIVE:-0}" -eq 1 ]; then
        if ! rm -f -- "$STAMP"; then
            log "FAIL: could not retire incomplete Module 31 health stamp"
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
    chmod 0644 -- "$DOC_TMP"
    chown root:root -- "$DOC_TMP"
    [ "$(stat -Lc '%u:%g:%a:%h' -- "$DOC_TMP" 2>/dev/null || true)" = \
        "0:0:644:1" ] \
        || die "staged Tier-C document metadata differs: $target"
    sync -- "$DOC_TMP" \
        || die "cannot sync staged Tier-C documentation: $target"
    DOC_PUBLISHED_TARGET=$target
    DOC_PUBLISHED_ID=$(stat -Lc '%d:%i' -- "$DOC_TMP")
    DOC_PUBLICATION_ACTIVE=1
    if ! mv -fT -- "$DOC_TMP" "$target"; then
        # Keep publication tracking armed. GNU mv normally fails before the
        # rename, but a wrapper/filesystem failure may be reported after the
        # staged inode became canonical. cleanup() removes only that exact
        # inode and therefore never removes an unrelated pre-existing target.
        die "cannot publish Tier-C documentation: $target"
    fi
    DOC_TMP=""
    restorecon -F -- "$target" \
        || die "restorecon failed for Tier-C documentation: $target"
    matchpathcon -V "$target" >/dev/null \
        || die "SELinux context differs for Tier-C documentation: $target"
    [ "$(stat -Lc '%u:%g:%a:%h' -- "$target" 2>/dev/null || true)" = \
        "0:0:644:1" ] \
        || die "published Tier-C document metadata differs: $target"
    sync -- "$target" "$DOC_DIR" \
        || die "cannot sync published Tier-C documentation: $target"
    DOC_PUBLICATION_ACTIVE=0
    DOC_PUBLISHED_TARGET=""
    DOC_PUBLISHED_ID=""
}

log "=== Module 31 User Documentation Tier C start ==="
command -v restorecon >/dev/null 2>&1 \
    || die "restorecon is required for fail-closed SELinux labeling"
command -v matchpathcon >/dev/null 2>&1 \
    || die "matchpathcon is required for fail-closed SELinux verification"

# M31_HEALTH_INVALIDATION_BEGIN
# This stamp covers all eight Tier-C and product-boundary documents. Validate
# shared state without normalizing drift, then retire any earlier success
# before the first owned documentation mutation.
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
        || die "cannot invalidate stale Module 31 health stamp"
    sync -- "$STAMP_DIR"
fi
log "  [OK] prior Module 31 health stamp is absent"
# M31_HEALTH_INVALIDATION_END

# ------------------------------------------------------------------------------
# Phase 1 — Ensure doc directory
# ------------------------------------------------------------------------------
PHASE="P1-setup"
DOC_DIR=/usr/share/doc/noid-privacy
if [ -e "$DOC_DIR" ] || [ -L "$DOC_DIR" ]; then
    [ -d "$DOC_DIR" ] && [ ! -L "$DOC_DIR" ] \
        || die "$DOC_DIR exists but is not a real directory"
    [ "$(stat -Lc '%u:%g:%a' -- "$DOC_DIR" 2>/dev/null || true)" = \
        "0:0:755" ] \
        || die "$DOC_DIR existing metadata differs from root:root 0755"
else
    install -d -m 0755 -o root -g root -- "$DOC_DIR"
fi
restorecon -F -- "$DOC_DIR" \
    || die "restorecon failed for Tier-C document directory"
matchpathcon -V "$DOC_DIR" >/dev/null \
    || die "$DOC_DIR SELinux context differs"

# ------------------------------------------------------------------------------
# Phase 2 — 99-troubleshooting.md (meta-FAQ + decision trees)
# ------------------------------------------------------------------------------
PHASE="P2-troubleshoot"
log "Writing 99-troubleshooting.md"

TRB_DOC="$DOC_DIR/99-troubleshooting.md"
DOC_TMP=$(mktemp "$DOC_DIR/.99-troubleshooting.md.XXXXXXXX")
cat > "$DOC_TMP" <<'TRB_EOF'
# Troubleshooting — Cross-cutting FAQ + Decision Trees

Most per-Module docs have their own Troubleshooting section for
issues specific to that component. This doc covers issues that
**span multiple Modules** OR that are the typical first-stop when
"something feels off" and you don't yet know what.

For component-specific troubleshooting, jump directly to:

| Symptom | Read |
|---------|------|
| USB device won't work | [14-usbguard.md](14-usbguard.md) → Troubleshooting |
| Firefox breaks on specific site | [16-firefox-hardening.md](16-firefox-hardening.md) → Troubleshooting |
| NVIDIA driver / Secure Boot MOK issue | [19-nvidia-drivers.md](19-nvidia-drivers.md) + [19-secure-boot-mok.md](19-secure-boot-mok.md) |
| Need to roll back a bad update | [20-rollback-recovery.md](20-rollback-recovery.md) → Rollback from a working boot |
| Firmware update (`fwupdmgr`) failing | [24-firmware-updates.md](24-firmware-updates.md) → Troubleshooting |
| Local AI (Ollama/RamaLama/LM Studio) not using GPU | [28-local-ai.md](28-local-ai.md) → GPU boundary |
| VPN won't come up or leaks IP | [06-vpn-setup.md](06-vpn-setup.md) → Troubleshooting |
| DNS resolving wrong / slow | [11-dns-custom.md](11-dns-custom.md) → Troubleshooting |
| Clock years wrong / NTS cannot authenticate | [11-time-recovery.md](11-time-recovery.md) → Deliberate local-VT procedure |

## Decision tree — "Something doesn't work"

Run through these checks in order. Stop at the first that reveals
the problem.

### Step 1 — `noid-status`

```bash
noid-status
```

Review every non-OK warning or failure and corroborate it with the owning
component's detailed status. `noid-status` is a selected overview, not proof
that an unlisted component is healthy.

### Step 2 — Recent warnings + errors

```bash
journalctl -b -p notice --no-pager
```

Shows everything at notice level or higher since last boot, including the
plain `logger` output used by the topology and VPN-zone dispatchers.
Common signals:

| Log line contains | Likely means |
|-------------------|--------------|
| `noid-lan-topology` | Topology policy refresh/degraded-state evidence; this is not a per-packet drop log |
| `type=AVC` | SELinux denied something (jump to AVC section below) |
| `noid-vpn-zone` | NM dispatcher ran for a VPN interface |
| `noid-audit-notify` | Audit event triggered the desktop notifier |
| `aide-check` | AIDE integrity check result |

NoID Privacy keeps firewalld `LogDenied=off` to avoid retaining destination
metadata for every denied packet. Confirm that setting with
`sudo firewall-cmd --get-log-denied`; inspect policy state and the bounded
topology controller evidence instead of expecting a `block-lan-out_DROP`
packet tag:

```bash
sudo firewall-cmd --get-log-denied
sudo firewall-cmd --info-policy block-lan-out
sudo journalctl -b -t noid-lan-topology --no-pager
```

### Step 3 — Failed services

```bash
systemctl --failed
systemctl --user --failed
```

Any entry here needs investigation:

```bash
# Enter one exact system-unit name printed by `systemctl --failed`.
read -r -p 'Exact failed system unit name: ' UNIT
if [[ "$UNIT" =~ ^[A-Za-z0-9_.@:-]+\.(service|socket|timer|mount|automount|path|target|slice|scope|device|swap)$ ]]; then
    systemctl status -- "$UNIT" -l
    sudo journalctl -u "$UNIT" --since today --no-pager | tail -40
else
    printf 'Invalid systemd unit name\n' >&2
fi
```

For a failed user unit, use the same validated name with `systemctl --user
status -- "$UNIT" -l` and `journalctl --user -u "$UNIT" ...`; do not add
`sudo` to user-session commands.

### Step 4 — USBGuard / kernel device blocking

If a newly attached USB function does not work or its expected device node is
absent, USBGuard may have left the device enumerated but unauthorized:

```bash
sudo usbguard list-devices   # inspect the explicit allow/block/reject target
```

Allow the device per [14-usbguard.md](14-usbguard.md).

## Boot-level problems

### What does NOT work on this image (read first)

The root account is locked and `SULOGIN_FORCE` is not set.
`systemd.unit=rescue.target` and `systemd.unit=emergency.target`
therefore provide **no maintenance shell** here: `sulogin` reports the
locked root account and the boot moves on past it. **DO NOT use** these
targets expecting a rescue shell. Recovery does not need the root
account — your normal user account plus `sudo` is the supported
maintenance identity (see the ladder below).

The initramfs is equally shell-free by design (`rd.shell=0
rd.emergency=halt`): an early storage/LUKS failure halts the machine
with the error still readable on the console (`loglevel=4` keeps kernel
errors and more-severe messages visible). `quiet` sits alongside it and
only reduces systemd's per-unit status output to failures, so a normal
boot stays clean while this diagnostic path is unchanged. The LUKS
prompt itself never strands you — unlock
retries are unlimited (`tries=0`).

If you enabled the optional GRUB password
([01-grub-password.md](01-grub-password.md)), every GRUB-edit step below
asks for it first. If that password is lost too, use Step 5 (live media).

### Recovery ladder — try in this order

**Step 1 — Boot an older kernel (no editing needed).**
Tap Esc repeatedly during the transition from firmware to Fedora to reveal
the hidden GRUB menu, then pick the previous kernel entry. Firmware hotkeys
such as F8 can open a machine-specific firmware boot menu instead; use the
hardware vendor's documented key if Esc does not reveal GRUB.
`installonly_limit=3` keeps the last three kernels installed.

**Step 2 — Text-mode login (`systemd.unit=multi-user.target`).**
The standard path when the desktop or login screen no longer starts:

1. At the GRUB menu press `e` on the default entry.
2. Append ` systemd.unit=multi-user.target` to the `linux ...` line,
   press Ctrl-X.
3. Unlock LUKS, log in at the text console **with your normal user
   account**, and repair via `sudo` — including the checked snapshot
   rollback using an exact snapshot ID:

   ```bash
   sudo snapper -c root list
   read -r -p 'Exact root snapshot ID to roll back to: ' SNAPSHOT_ID
   if [[ "$SNAPSHOT_ID" =~ ^[1-9][0-9]*$ ]]; then
       sudo noid-snap-rollback "$SNAPSHOT_ID"
   else
       printf 'Invalid snapshot ID\n' >&2
   fi
   ```

   See [20-rollback-recovery.md](20-rollback-recovery.md) "Rollback from a working boot"

**Step 3 — Disable one wedged unit for a single boot (`systemd.mask=`).**
When one specific unit blocks the boot or your input devices, append
` systemd.mask=<unit>.service` instead (repeat the argument for several
units). The unit is masked for THIS boot only and returns on the next
boot. Example: the replacement-keyboard flow in
[14-usbguard.md](14-usbguard.md).

**Step 4 — Last resort: `init=/bin/bash`.**
Append ` init=/bin/bash` to the `linux ...` line. After the LUKS unlock
you get a minimal root shell *instead of* systemd — no services, no
D-Bus, no SELinux policy loaded, so snapshot rollback is NOT available
here. For a persistent minimal fix:
`mount -o remount,rw /`, apply the change, `touch /.autorelabel` (files
written without the loaded SELinux policy need a relabel), then
`sync` and `/sbin/reboot -f`. Anyone at the GRUB menu can take this same path —
that is exactly the edit-access the optional GRUB password closes
([01-grub-password.md](01-grub-password.md)); the LUKS passphrase still
gates it either way. Scope note: `rd.shell=0` does not affect
`init=/bin/bash` — it only removes the initramfs failure shell
(`rd.emergency=shell` has no effect while `rd.shell=0` is set).

**Step 5 — Live media.**
If the installed system cannot reach any of the above, boot Fedora live
media, unlock the LUKS volume and inspect/chroot from there — see the
live-media section in [20-rollback-recovery.md](20-rollback-recovery.md).

### Boot hangs on "A start job is running for…"

Usually a service waiting on network or a stuck daemon. Note the unit
name in the message and wait out its timeout first (systemd then
continues or marks the unit failed). Once the system is up:

```bash
systemctl --failed
```

Use the validated unit-name recipe in Step 3 of the main decision tree to
inspect the exact failed unit. If the boot never completes, reboot and use
Step 2 or Step 3 above (`systemd.unit=multi-user.target`, or one exact
`systemd.mask=UNIT.service` argument for one boot).

### Forgot LUKS passphrase

If you have your recovery key (see
[01-getting-started.md](01-getting-started.md) step 2), unlock with it
at the passphrase prompt. To restore the normal passphrase:

```bash
# After booted (from within the unlocked system)
lsblk -f
read -r -p 'Exact crypto_LUKS device path: ' LUKS_DEV
sudo cryptsetup isLuks "$LUKS_DEV"
sudo cryptsetup luksDump "$LUKS_DEV"
sudo cryptsetup luksChangeKey "$LUKS_DEV"
```

Verify the exact `crypto_LUKS` backing device; do not copy a device name from
another machine. `luksChangeKey` changes one existing keyslot after
authenticating it—it does not rotate the volume key or repair a missing unlock
method. If no valid passphrase, recovery key, keyfile or enrolled token
remains, the volume cannot be unlocked by design. A header backup preserves
metadata and keyslots; it does not reveal or replace a missing unlock secret.

## SELinux denials (AVC)

### A legitimate app is blocked by SELinux

Do not treat an AVC as proof that the base policy needs a new allow rule.
Wrong labels, unsupported paths, application configuration and packaging bugs
are more common first causes. Keep SELinux enforcing while you investigate:

```bash
# 1. Reproduce once, then inspect the complete recent AVC events
sudo ausearch -m avc,user_avc,selinux_err,user_selinux_err -ts recent -i

# 2. Check the affected path against the policy-owned label
read -er -p 'Exact existing absolute path from the AVC: ' AFFECTED_PATH
if [[ "$AFFECTED_PATH" == /* ]] && { [ -e "$AFFECTED_PATH" ] || [ -L "$AFFECTED_PATH" ]; }; then
    ls -Zd -- "$AFFECTED_PATH"
    matchpathcon -V -- "$AFFECTED_PATH"
    sudo restorecon -n -v -- "$AFFECTED_PATH"
else
    printf 'Path must be absolute and must currently exist\n' >&2
fi

# 3. Interpret the denial after preserving the raw event
sudo ausearch -m avc -ts recent --raw | audit2why
```

Fix a wrong label with a persistent `semanage fcontext` mapping plus
`restorecon`, or correct the application/package configuration. Report a base
policy or packaging defect upstream. Only if those causes are excluded should
an experienced SELinux policy author generate a module from a narrowly
reproduced event, inspect the generated `.te` source and compile/install it
through the reviewed local-policy workflow.

`audit2allow` output is a proposal, not a security decision; feeding all
recent AVCs into it can combine unrelated denials and grant more access than
intended.

**DO NOT run `sudo setenforce 0`** to "fix" a single denial. That
disables the entire MAC layer for the system.

### Common FPs you may see on this image

Per [02-system-security.md](02-system-security.md) "Common false
positives", some AVC denials are benign only after investigation. The optional
audit popup plugin is not an AVC suppressor: it handles 16 reviewed keyed
integrity-change categories, while every AVC remains queryable. With immutable
mode active, runtime `auditctl` rule edits are rejected; make any justified
persistent rule change in source for the next boot.

## AIDE reports unexpected changes

### Decision tree

```
Did I run noid-update-all.sh since last AIDE check?
├── YES → Correlate the report with the exact package/firmware transaction.
│          After a successful DNF step, update-all runs a check only when an
│          active baseline exists and the user did not explicitly skip it.
│          It never accepts drift or creates a baseline. Continue below for
│          anything not fully explained by verified transaction evidence.
│
└── NO  → Investigate.
    │
    Did I install/remove packages via plain dnf?
    ├── YES → Correlate every path with the transaction, RPM ownership and
    │          signature. A package operation explains timing; it does not by
    │          itself prove every reported change is trusted.
    │
    └── NO  → The changes are UNEXPECTED. Read them carefully:
        `sudo journalctl -u aide-check.service | tail -40`
        │
        ├── Paths resemble a documented high-churn class → verify the exact
        │   process, operation, path, timing and final state. Do not extend an
        │   exclusion merely because the name looks familiar.
        │
        ├── Paths look system-generated and you can't tell if they're
        │   benign → ask in a trusted community / read the
        │   corresponding Module's discovery doc.
        │
        └── Paths look TAMPERED (random /usr/bin/* changes, new root
            setuid binaries, etc.) → SUSPECT BREACH. Minimize further
            activity, disconnect unneeded networks without destroying
            evidence, record what was observed, and investigate from trusted
            live media or a forensic image. Do not rebaseline or delete the
            evidence merely to clear the alert.
```

## Network / connectivity

### Internet not working (VPN is up)

```bash
# Identify active profiles/interfaces without assuming a provider or name
nmcli -f NAME,TYPE,DEVICE connection show --active
ip -4 route show default
ip -6 route show default
resolvectl status
```

Compare the effective routes and selected DNS `~.` scope with the current
documentation for the exact VPN client/profile. For a self-managed WireGuard
profile, `AllowedIPs` controls routed prefixes; provider applications and
OpenVPN profiles may implement full-tunnel and killswitch behavior differently.
If you choose to use an external IP-check site, that is an explicit request to
that third party; prefer the endpoint documented by your selected provider.

### Internet not working (VPN is down)

VPN behavior depends on the selected mode. Direct WAN is available during the
documented bootstrap grace state or when WAN-strict is explicitly paused or
disabled. Once WAN-strict has been armed with literal or runtime-confirmed
endpoint tuples, a VPN
drop intentionally does not restore unrestricted physical-WAN egress. Inspect
the actual state first:

```bash
sudo noid-toggle-wan-strict status
ip -4 route show default
ip -6 route show default
sudo nft list table inet noid_wan_strict
```

Use `sudo noid-wan-strict pause 5` (accepted range: 1–1440 minutes) only when
you deliberately accept bounded direct physical-WAN access.
`noid-toggle-wan-strict` owns only `on|off|status`; it has no pause action.
Do **not** delete `block-lan-out`: that policy is the independent
LAN-destination boundary, not the VPN killswitch.

No host firewall can make a universal “no leak” claim for firmware OOB paths,
an explicitly allowed LAN peer, provider-client rules, or traffic before its
policy is active.

Captive portal specifics: see
[00-cheatsheet.md](00-cheatsheet.md) → "Captive portal on public
Wi-Fi".

### Can't reach a device on my own LAN

Intentional — the `block-lan-out` policy blocks outbound to RFC1918
and link-local ranges (the gateway included). See
[03-firewall-zones.md](03-firewall-zones.md) → "How to allow a
specific LAN device" for the allow-flow.

## Performance

### System feels sluggish

```bash
# Memory pressure?
free -h
cat /proc/pressure/memory   # PSI metric

# CPU pressure?
cat /proc/pressure/cpu
top -b -n 1 | head -20

# Is earlyoom thrashing? (image ships it enabled)
systemctl status earlyoom
journalctl -u earlyoom --no-pager | tail -20
```

If earlyoom has been killing apps, first correlate the timestamps with memory
and swap pressure. Edit only the `-m` and `-s` percentages in the single
`EARLYOOM_ARGS` line with `sudoedit /etc/default/earlyoom`; preserve the quoted
regular expressions and the other arguments. Higher percentages kill earlier;
lower percentages leave less recovery margin and can expose the host to a
full OOM stall. Apply and verify with:

```bash
sudo systemctl restart earlyoom
systemctl status earlyoom --no-pager
EARLYOOM_PID=$(systemctl show earlyoom -p MainPID --value)
if [[ "$EARLYOOM_PID" =~ ^[1-9][0-9]*$ ]]; then
    sudo cat -- "/proc/$EARLYOOM_PID/cmdline" | tr '\0' ' '
    printf '\n'
else
    printf 'earlyoom has no running MainPID\n' >&2
fi
```

### Disk full

```bash
# Common culprits (stay on the root filesystem)
sudo du -xhs /var/log /var/lib/aide /var/lib/snapper \
  /var/cache/libdnf5 /var/cache/dnf5daemon-server
sudo journalctl --disk-usage

# Inspect the shipped retention state and measured snapshot inventory
systemctl status noid-snapper-prune.timer
sudo snapper -c root list
```

The image already caps the system journal at 30 days/500 MiB and gives eligible
root snapshots a checked 30-day deletion target. Do not vacuum evidence or
delete a snapshot merely because it is old-looking. If emergency space recovery
requires deleting a specifically reviewed snapshot, record why first and
understand that deletion removes that rollback/forensic evidence; `/home` is a
separate subvolume and is not recovered by root snapshots.

## Notifications / desktop integration

### AIDE notification didn't show today

The daily timer intentionally remains disabled until you have reviewed and
activated an AIDE baseline. With no active baseline, no daily notification is
expected and the check-only wrapper refuses to invent one.

```bash
# Timer still scheduled?
systemctl status aide-check.timer

# Last run result?
sudo journalctl -u aide-check.service --no-pager | tail -20

# Explicit supported check-only run (never creates or replaces a baseline)
sudo noid-aide-check.sh
```

If you've disabled AIDE notifications via `noid-toggle-aide-popup
off`, they're logged-only (no popup). Re-enable with `on`.

### audit-notify isn't firing on a keyed critical event

```bash
sudo noid-toggle-audit-notify status
# Refresh auditd's detailed plugin/queue state file (not the shorter
# kernel-facing status printed by `auditctl -s`).
sudo auditctl --signal state
sudo grep -E 'Number of active plugins|plugin queue|overflow' \
  /run/audit/auditd.state
sudo journalctl -t noid-audit-notify --no-pager -n 40
```

The systemd unit is an opt-in controller; auditd owns the actual plugin and
feeds it into auparse. Status reports the persistent degraded marker plus
delivery/suppression/queue metrics. Popups are deliberately suppressed if the
event AUID has no matching unlocked active local graphical session.
`auditctl --signal state` asks auditd to refresh its detailed state file;
`auditctl -s` reports the shorter kernel audit status and does not replace
the plugin queue evidence above.

### GNOME Shell notification drawer empty

If notify-send works but notifications don't appear in GNOME:

```bash
# Is org.freedesktop.Notifications D-Bus service up?
dbus-send --session --print-reply \
    --dest=org.freedesktop.DBus \
    /org/freedesktop/DBus org.freedesktop.DBus.ListNames | \
    grep Notification
```

If not: log out + log back in to re-start the GNOME session.

### GNOME Software shows only Flatpaks; how do I browse Fedora RPMs?

That is the intentional fast, silent-machine default, not a missing Fedora
package backend. Open **NoID Privacy Setup -> GNOME Software Sources -> Open
GNOME Software with Fedora RPMs**, or right-click **Software** in the app grid
and choose **Open GNOME Software with Fedora RPMs**. The equivalent command is:

```bash
/usr/local/bin/noid-gnome-software-rpm
```

The action is deliberately per-launch. It changes no repository and no saved
setting, does not enable firmware handling, and the next ordinary launch is
Flatpak-only again. It displays application metadata from **all enabled DNF
repositories**, not only Fedora's official repositories; check the displayed
source and `dnf repolist --enabled` when origin matters. Choose **Quit
completely** afterward to release GNOME Software and its idle DNF5 backend. A
busy cursor for several seconds is expected while an RPM catalog job settles:
the helper checks every 250 ms for at most 90 seconds and refuses to kill a DNF
session that remains active.

See `18-flatpak-trust-model.md` for the package-format decision and the separate
manual-only AppImage exception policy.

### GNOME Software stays running after I close the window

NoID Privacy masks `gnome-software` at the
systemd-user level via `/etc/systemd/user/gnome-software.service ->
/dev/null`. Fedora's RPM-owned D-Bus descriptor routes unsolicited activation
to that exact unit and remains pristine; there is deliberately no
higher-priority service descriptor with the same name. A manual launch still
works because the separate admin desktop entry sets `DBusActivatable=false`
and executes `gnome-software` directly; the running application then acquires
its own D-Bus name.

After plugin setup, upstream GNOME Software 50 creates its update monitor
unconditionally. The monitor calls `g_application_hold()` and releases that
hold only when the monitor is finalized during application shutdown. Closing
the last window therefore does not end the process. The locked
`allow-updates=false` and `download-updates=false` settings stop its unattended
update work; they do not remove that upstream lifetime hold. No maintained
inactivity-timeout option exists.

To end it cleanly, right-click **Software** in the app grid or dash and choose
**Quit completely** (German: **Vollständig beenden**). The same native action
is available on the command line:

```bash
/usr/local/bin/noid-gnome-software-quit
```

It first uses GNOME Software's own supported `gnome-software --quit` path,
which asks its job manager to shut down before quitting the application.
Fedora 44's D-Bus-activatable `dnf5daemon-server` has no inactivity timeout,
so the action then stops that backend only after its D-Bus object tree contains
no dynamic package-manager Session. A root-owned helper performs that check;
the exact argumentless command has a wheel-only `sudo -n` rule, so the desktop
action can never open an authentication dialog. If any DNF session remains, it
fails closed and leaves the daemon running.

The next manual package operation activates the daemon again through its
native D-Bus service. The GNOME Software service mask and native unsolicited
D-Bus denial remain unchanged.

NoID Privacy does not attach a timeout or window watcher: either could terminate
the application during a real installation and would duplicate upstream
lifecycle logic. The window close button retains normal GNOME semantics; the
standard freedesktop desktop action makes the distinct complete-quit operation
explicit.

### A third-party app (Chrome, etc.) won't uninstall via GNOME Software

GNOME Software manages an RPM as an application only when its package backend
can associate it with usable AppStream application metadata. Repository origin
alone does not decide this: Fedora and third-party repositories can provide
such metadata, while an individual vendor RPM or repository may omit it. If an
installed package has no working application entry/**Remove** action, use DNF
with the exact package name rather than repeatedly clicking a nonfunctional UI
row.

Preview the removal, review dependencies, then repeat without `--assumeno` only
if the transaction is the one you intend:

```bash
read -r -p 'Exact installed RPM package name: ' PACKAGE
if [[ "$PACKAGE" =~ ^[A-Za-z0-9][A-Za-z0-9+_.-]*$ ]] && rpm -q -- "$PACKAGE"; then
    sudo dnf remove --assumeno "$PACKAGE"
else
    printf 'Package name is invalid or not installed\n' >&2
fi
```

Find candidates with `rpm -qa | grep -Fi -- 'SEARCH_TEXT'`, then enter the
exact selected package name above. Only after the preview is exactly the
transaction you intend should you run `sudo dnf remove "$PACKAGE"` in the
same shell.

### Bluetooth is off by default — how to enable

NoID Privacy ships with Bluetooth **default-disabled** (service stopped +
rfkill-blocked at install per M08). The bluez + gnome-bluetooth +
NetworkManager-bluetooth packages ARE installed so the GNOME Settings
BT-panel exists and works — they're just not running.

**Two authoritative ways to enable**:

1. **noid-welcome** dialog → "Hardware Privacy" → Bluetooth SwitchRow
2. **CLI**: `sudo noid-toggle-bluetooth on`

Both call the same privileged helper and verify its complete state transition:
service started, every Bluetooth rfkill controller unblocked, WirePlumber
policy restored and `/var/lib/noid-privacy/bluetooth-disabled.flag` removed.

GNOME Settings remains the native panel for pairing and device management
*after* that opt-in. Its radio switch is not equivalent to the NoID Privacy helper: it
cannot change the root-owned flag or WirePlumber policy, and the default-state
udev enforcer can re-block an external unblock while the flag exists.

**To re-disable the complete NoID Privacy state**, use the Welcome SwitchRow or
`sudo noid-toggle-bluetooth off`. That restores the flag, WirePlumber policy,
service and all-controller rfkill postconditions together.

## Package / update issues

### Update fails with a signature error

Do not bypass signature checking and do not import every file matching a
wildcard. First verify the clock, release identity, repository configuration
and installed Fedora key package:

```bash
date --iso-8601=seconds
rpm -E %fedora
rpm -q fedora-gpg-keys fedora-repos
rpm -V fedora-gpg-keys fedora-repos
grep -R '^[[:space:]]*gpgcheck=' /etc/yum.repos.d/
```

If verification reports unexplained drift, stop and compare the affected
package/key with Fedora's current signed release material from a separate
trusted path. Keep `gpgcheck=1`; `--nogpgcheck` turns the failure into a
supply-chain bypass. Once the trust problem is resolved, run the supported
user-operated `noid-update-all.sh`.

### The update preview reports package conflicts

This image uses `--exclude-weakdeps` in kickstart. After install,
review the proposed transaction without applying it:

```bash
sudo dnf upgrade --refresh --best --assumeno
sudo dnf upgrade --refresh --best --allowerasing --assumeno
```

`--allowerasing` can remove installed packages; the second command is a preview,
not approval. Resolve the exact repository/package conflict, then use
`noid-update-all.sh` for the real update. For RPM Fusion + codec /
proprietary-driver conflicts, see
[19-nvidia-drivers.md](19-nvidia-drivers.md) + relevant RPM Fusion
docs.

### Update broke the system, need to roll back

See [20-rollback-recovery.md](20-rollback-recovery.md). Short
version:

1. `sudo snapper -c root list` — find the pre-update snapshot number
2. Run the validated `SNAPSHOT_ID` recipe in "Recovery ladder — Step 2"
3. `sudo reboot` into the rolled-back state

If the system no longer boots to the graphical login, boot to the text
console instead: append ` systemd.unit=multi-user.target` at the GRUB editor
(press `e`), unlock LUKS, log in with your user account, then run the same
two snapper commands. rescue/emergency targets provide no shell on this
image — see "Boot-level problems" above.

## Where to dig deeper

- Per-Module discovery docs: `kickstart/snippets/NN-name.ks` header
  comments (rationale, decisions, trade-offs)
- Per-Module install logs: `/var/log/ks-NN-name.log` — written during image
  installation and retained on the installed system for 30 days by
  `noid-install-logs-prune.timer`; use the journal for later runtime events
- Audit log: `sudo journalctl -t noid-audit-notify`, `sudo ausearch`
- `noid-help <topic>` — jump to the topic's user doc
- `noid-help search <keyword>` — grep all user docs

## Reporting a real bug / security issue

Build scripts live in the NoID Privacy Workstation project. When opening an
issue, create evidence locally first and review/redact it before uploading:

- Relevant, redacted fields from `noid-status --json`
- Exact reproduction commands with secrets, usernames, account names, private
  paths, hostnames, IP/MAC addresses and VPN endpoints removed
- `uname -r` plus exact versions of the affected packages
- Only the relevant, redacted journal lines—not an unreviewed full boot log

Never upload a LUKS header backup, passphrase, recovery key, AIDE database,
raw audit log or unreviewed diagnostic bundle. These can expose unlock metadata,
local identities, paths, network identifiers and security events.

TRB_EOF
publish_doc "$TRB_DOC"
log "  [OK] 99-troubleshooting.md written"

# ------------------------------------------------------------------------------
# Phase 3 — 00-architecture.md
# ------------------------------------------------------------------------------
PHASE="P3-architecture"
log "Writing 00-architecture.md"

ARCH_DOC="$DOC_DIR/00-architecture.md"
DOC_TMP=$(mktemp "$DOC_DIR/.00-architecture.md.XXXXXXXX")
cat > "$DOC_TMP" <<'ARCH_EOF'
# NoID Privacy Workstation — Architecture

For users who want to understand the design of the image — what
hardens what, in what order, with what trade-offs. If you just want
to USE the image, [01-getting-started.md](01-getting-started.md) is
the right place to start.

## Module structure (41 functional modules + 99-finalize)

The image is composed of **37 sequentially-numbered Modules (M01-M37)** +
**1 sub-numbered Module (M11b manual DNS diagnostics)** +
**3 reserved-numbered Modules (M40 audit-bundle integration, M41 anaconda-
cleanup safety-net, M42 30-day forensic retention)** + a `99-finalize`
snippet that runs last. Total:
41 functional modules + 99-finalize = 42 kickstart snippets.
Each Module is a self-contained %post block that (a) installs its
config, (b) verifies its own artifacts, (c) optionally writes a health
stamp to `/var/lib/noid-privacy/stamp-<N>-<name>.ok`.

The reserved-numbered Modules (M40, M41, M42) are out-of-band specialized
modules added late: M40 wires the noid-privacy-linux
audit tool into the image, M41 adds an anaconda-cleanup safety-net
that runs post-install, M42 ships the 30-day forensic-retention masterplan
(audit-log/AIDE/snapper/install-time/libvirt-tuned/dnf5/UPower/NetworkManager
retention timers). They use reserved numbers (40+) to avoid
renumbering existing M01-M37 cross-references.

The snippets are assembled into a single kickstart by `master.ks`
via `%include` statements in a specific order (dependency-driven —
see [Dependency ordering](#dependency-ordering) below).

### Kernel & boot (1, 2, 21, 22)
- **01 bootloader** — GRUB + Secure Boot + a broad KSPP/hardening
  kernel-cmdline set (the exact token count varies by CPU vendor and
  build — Intel vs AMD pull different vulnerability mitigations)
  (`lockdown=integrity`, `module.sig_enforce=1`,
  `intel_iommu=on`/`amd_iommu=on` (vendor-auto-detected),
  `init_on_alloc=1`, `slab_nomerge`, `pti=on`, etc.)
- **02 sysctl** — the M02 kernel-hardening parameter set across
  `/etc/sysctl.d/99-hardening.conf` + `99-audit-fixes.conf` (3) +
  `99-userns.conf` (1) (Kicksecure security-misc alignment +
  Mullvad/ANSSI additions + rp_filter strict + src_valid_mark=1;
  performance/VM/network tuning remains Fedora/kernel vendor policy;
  `fs.binfmt_misc.status` is not treated as a regular sysctl; M21 masks the
  native binfmt automount/registration units). **M07 adds 1 static parameter**
  via `98-privacy-network.conf`. **M07 keeps exactly 1 durable assignment**
  for the most recently selected physical interface in
  `99-wan-ipv6-off.conf` (for example,
  `net.ipv6.conf.<wan-iface>.disable_ipv6=1`) while enforcing and verifying
  the live disable on every physical `pre-up`; thus multiple live physical
  interfaces can be disabled even though only one selected identity is
  durable. Verify the live hardening count with
  `sudo grep -cE '^-?[a-z]+\.' /etc/sysctl.d/99-hardening.conf` (the file is
  root-only, mode 0640 — `sudo` is required).
- **21 kernel-module-policy** — 134 normalized identities: 53 canonical
  loadable modules receive dual modprobe enforcement, while 8 built-ins,
  43 absent identities, 2 historical aliases and 28 supported modules are
  recorded without being miscounted as effective blocks. FireWire is omitted
  from early boot; binfmt automount/registration is natively masked. The
  Live/installer initramfs remains generic, then the installed system performs
  verified sloppy host-only regeneration from its real storage topology
  (squashfs remains supported for the NoID Privacy Live ISO).
- **22 LUKS + partitioning + mount-hardening** — LUKS2/Argon2id guidance
  and header-backup helper, periodic-TRIM (`nodiscard` + `fstrim.timer`)
  policy, `/tmp` tmpfs+noexec, `/dev/shm` noexec, `/home`
  nosuid+nodev+nodiscard, `/var`/`/var/tmp` self-bind

### Network (3, 4, 5, 6, 7, 11, 11b, 23, 24)
- **03 firewalld** — DROP default, always-active block-lan-out policy,
  allow-host-ipv6 override
- **04 arp-hardening** — an exact permanent kernel neighbour pin for the
  learned IPv4 gateway, closed state/sysctl guards and awaited first-boot/
  pre-up relearning; M04 owns no nftables ARP mirror
- **05 lan-isolation** — Layer 5-7 protocols (mDNS/SMB/WSD/NetBIOS/
  CUPS-browse/SSDP/LLDP) off; service masking for
  avahi-daemon/wsdd/cups; strict-default global/physical Quad9 DoT;
  `noid-dns-mode` provides the atomic strict/opportunistic/off/reset selector
  without rewriting VPN/private profiles; M23 supplies best-effort
  opportunistic DoT only when their transport remains unset
- **06 VPN zone safety layer** — NM dispatcher validates VPN connection types
  and enforces the inbound-DROP firewalld `noid-vpn` zone; any provider
  route/DNS killswitch remains separately testable
- **07 ipv6-bundle** — physical-WAN v6 disable for the selected interface,
  default-off coverage for newly appearing interfaces, NDP hardening and
  RFC 6724 gai.conf precedence
- **11 dns-ntp** — chrony with 6 operator-supported public/production EU NTS
  servers, IPv4-only, declaratively offline until gateway/XDP readiness,
  `minsources=3`, per-server `maxpoll 11` (NTS-KE
  handshake-rate halved at steady-state, ~34min poll-ceiling). A dated
  operator manifest plus the candidate gate distinguish source availability,
  source selection and authenticated NTS from a permanent reliability claim.
  DNS lives in M05.
- **11b dns diagnostics** — manual, read-only local resolver/route/journal
  evidence via `noid-dns-diagnose`; active queries require an explicit
  user-supplied target. No timer, fixed target, automatic cache mutation or
  resolver restart is installed.
- **23 networkmanager** — ethernet MAC randomization, wifi scan-rand-mac,
  explicit IPv4/IPv6 DHCP hostname suppression (the separate
  `hostname-mode=none` setting only leaves the transient local hostname
  unmanaged), plus TunnelVision
  CVE-2024-3661 mitigation (`ignore-auto-routes` and specific DHCP-route
  cleanup)
- **24 firmware-fwupd** — LVFS remote policy, passim P2P disabled and
  `fwupd-refresh.timer` masked. User-invoked refresh/update remains an explicit
  LVFS network request and leaves ordinary fwupd/journal evidence.

### Identity, auth, integrity (9, 10, 12, 13)
- **09 ssh** — client hardening plus a dormant server-hardening template;
  `openssh-server` is excluded, so no inbound SSH server ships
- **10 pam-login** — PAM faillock, pwquality, YESCRYPT hashing,
  login.defs UMASK=022 (Fedora default — intentionally NOT 027 per
  Kicksecure security-misc #185, dnf5#1908), five-path native tmpfiles SUID
  reduction with four Fedora load-bearing paths retained,
  coredump 6-layer block
- **12 selinux-auditd** — SELinux enforcing, 132 ABI-complete auditd rules (immutable
  via `-e 2`), opt-in auditd/auparse complete-event desktop notifications
  for 16 keyed integrity categories with exact local AUID/session binding,
  custom NoID Privacy SELinux policy module
  (switcheroo nnp_transition + usbguard GDM/machined/logind
  perm-bundle dir-enumeration `{ getattr read open search }`)
- **13 aide** — AIDE configuration, reviewed candidate/commit workflow and a
  daily check timer that remains disabled until an active user-reviewed
  baseline exists; also ships the GTK4/libadwaita Welcome hub + `noid-status`

### Hardware (14, 15, 19, 27)
- **14 usbguard** — USB whitelisting, firstboot emergency→real state
  machine, usbguard-notifier user service
- **15 intel-me** — Intel ME multi-layer mitigation (Kicksecure-consensus,
  security-misc #239): KT/SOL PCI driver_override (27 PCI IDs 6th-17th gen —
  the load-bearing defense) + mei + mei_me loaded for fwupd BootGuard
  detection + intel_iommu=on + lockdown=integrity. NO default MEI sub-module blacklist —
  mei_hdcp + mei_pxp + mei_wdt all LOAD by default (the aggressive
  blacklist was dropped after honest cost-benefit audit — 4K HDCP streams +
  HuC HW-accel HEVC/AV1 decode + iAMT watchdog cost outweighed marginal
  security gain; opt-in block via noid-mei-restore-submodules --block).
  **AMD PSP note**: the host OS cannot disable the PSP; the exact firmware and
  exposed controls are product-specific. 15-amd-psp-hardware-layer.md explains
  BIOS-layer options + CVE-2025-2884 + opt-in ccp blacklist trade-off
- **19 hardware-docs** — NVIDIA + Secure Boot MOK documentation
  (manual opt-in, zero auto-install)
- **27 hardware-abstraction** — Fedora/kernel-owned I/O scheduler and zram
  policy, tuned-backed user-selected Power Mode, earlyoom, physical-NIC
  Wake-on-LAN policy with vendor-owned EEE, UDisks USB/SD noexec defaults,
  scoped external-NTFS driver priority and Fedora-owned thermal/Intel
  active-idle hardware detection.
  It ships no NoID Privacy-specific scheduler, HWP boost, zram compression/priority,
  BBR/qdisc, socket-buffer, swappiness, read-ahead or Dracut performance tweak.

### Services + desktop (8, 17, 18, 36)
- **08 service-minimization** — 82 systemd units masked in M08 (see
  [08-masked-services.md](08-masked-services.md); the source test pins the
  reviewed count, including the complete modular-libvirt service/socket set).
  M05 adds 8 more (avahi×2, wsdd×2, cups×4), M11 masks
  `systemd-timesyncd.service`, M24 masks `fwupd-refresh.timer` +
  `fwupd-refresh.service` (2 unique to M24; passim.service is masked
  by both M08 and M24 but counted once in M08 A2), M18 masks
  `flatpak-add-fedora-repos.service`, and M21 masks the binfmt automount plus
  registration service → **96 source-
  deployed system-wide unique masked units**. The live count can be
  higher when Fedora contributes additional preset masks.
- **17 gnome-hardening** — dconf defaults/locks and D-Bus overrides that
  disable the specifically enumerated GNOME discovery/telemetry surfaces
- **18 flatpak-sandboxing** — verified/full remote trust documentation and
  D-Bus overrides. Flatseal is documented as an optional user install; no
  Flatseal installer/service is shipped.
- **36 noid-network** — GTK4 front-end with the persistent suite identity,
  adaptive section navigation, a state-truthful global/physical DNS page and
  formatted read-only WAN-strict, firewalld and nftables audits. DNS, LAN and
  ARP mutations stay in narrow root-owned CLIs invoked through the established
  privilege router.

### Applications (16, 19→NVIDIA, 28, 35, 37)
- **16 firefox** — locally maintained NoID Privacy derivative of the reviewed arkenfox
  v144.0 snapshot (no automatic upstream import), uBlock Origin with phishing
  + LAN-intrusion blocklists, provider-compatible system/VPN DNS by default,
  Total Cookie Protection and FPP
- **28 local-ai** — documentation-only; user picks
  RamaLama (Option A, Fedora-native, rootless Podman, --network=none)
  / Ollama / LM Studio / llama.cpp. VSCodium editor integration uses the
  reviewed llama-vscode path, with Cline documented as a separately trusted
  agentic alternative.
- **35 thunderbird** — locally maintained NoID Privacy derivative of the reviewed
  HorlogeSkynet v140.2 snapshot plus AutoConfig (mozilla.cfg + autoconfig.js +
  local-settings.js) + DKIM Verifier XPI pre-installed at
  `/usr/lib64/thunderbird/distribution/extensions/` (replaces the deprecated
  B16b implementation; no automatic upstream user.js import)
- **37 noid-tools** — GTK4/libadwaita front-end for the curated local helper
  inventory, including the managed DNS transport selector. It adds no parallel
  privileged backend: state-changing rows call the existing root-owned helpers
  through their established authorization paths.

### Storage + updates (20, 25, 26)
- **20 snapper** — btrfs pre-update snapshots + CLI rollback
  (`noid-snap-rollback` with checked fstab/BLS/default state)
- **25 update-process** — noid-update-all.sh (snapshot + DNF + Flatpak
  + firmware plus check-only AIDE drift evidence after successful DNF when an
  active baseline exists and the user has not skipped it), weekly notification
- **26 package-set** — reviewed optional/default-package exclusions,
  Tier-1 additions and package verification sweep. The Bluetooth stack
  and GNOME/NetworkManager controls remain installed but disabled until
  `noid-toggle-bluetooth on`.

### User docs (29, 30, 31)
- **29 user-docs** (Tier-A) — 00-README, 01-getting-started, 06-vpn-setup and
  gnome-extensions-autostart.
  The Welcome implementation is the M13 Python GTK4/libadwaita application
  with the `--again` entry point
- **30 user-docs-tier-b** — 02-system-security, 03-firewall-zones,
  05-lan-isolation, 08-masked-services, 11-dns-custom, 00-cheatsheet +
  noid-help CLI navigator
- **31 user-docs-tier-c** (this Module) — 99-troubleshooting +
  00-architecture + 27-performance + threat-model + scope +
  post-quantum-readiness + performance-profile + licensing

### Branding (32)
- **32 branding** — derivative release/console identity in `/etc/os-release`,
  `/etc/issue` and `/etc/system-release`, plus manifest-verified
  wallpaper/logo/Plymouth assets. No `/etc/issue.d` trademark artifact is
  shipped. Complements
  Module 26 logo-package replacement plus generic release notes.

### Operational hygiene + browser isolation (33, 34)
- **33 operational-hygiene** — an RFC 9700/provider account-access checklist,
  precise Firefox profile-data-separation guidance and an integrity-evidence
  guide. `noid-integrity-check` inventories RPM verification records, installed
  system timers, cron entries and Flatpak history, and prints the manual
  external-account review action. `noid-firefox-create-isolated-profile`
  creates a persistent dedicated profile through the shared M16 hardening
  helper. No timers, services, autostart or network requests are added —
  user-invoked only.
- **34 firefox-playground** — second pre-configured Firefox profile
  ("playground") with amnesic behavior (Private-Browsing-always +
  clearOnShutdown), its own GNOME Dash icon + auto-pin. Complements
  the productive profile shipped by M16 — one-click untrusted browsing
  with browser-data separation. Like every same-user Firefox profile, it is
  not an OS/filesystem sandbox against malware running as that user.

### Finalize (99)
- **99 finalize** — cross-Module sanity verification that rejects any
  compose-created active/candidate AIDE database. MUST be last; baseline trust
  remains a later, explicit user decision.

## Design principles

### 1. Silent-Machine baseline (explicit)
After install + LAN/WAN connection: **no project telemetry and no LAN
discovery broadcasts**. Documented DHCP/ARP link control and NTS clock sync
remain. DNS diagnostics are local unless the user explicitly invokes
`noid-dns-diagnose probe TARGET`. User actions, installed apps, VPN clients
and firmware OOB can create additional traffic.

Concretely this means the enumerated defaults for abrt, GeoClue,
gnome-software periodic fetch,
fwupd-refresh.timer, dnf-makecache.timer, packagekit, goa-daemon,
trackerd/localsearch, PackageKit D-Bus auto-activation, ModemManager,
and selected GNOME telemetry settings are off. This is not a claim that every
installed application or user-triggered operation is network-silent.

### 2. Defense in depth
Sensitive controls have 3+ independent enforcement layers. Examples:
- VPN safety: physical-interface DROP + LAN isolation + validated
  `noid-vpn` zone; route/DNS leak prevention requires a verified provider or
  profile killswitch
- IPv6 disable: sysctl default-off + per-physical pre-up/live enforcement with
  one durable selected-interface assignment + NM `ipv6.method=disabled`
- USB: USBGuard daemon + auditd watch + SELinux `usbguard_tmpfs_t`
  confinement
- Intel MEI: KT/SOL host-driver binding block + optional sub-module blocks +
  fwupd visibility. AMT OOB bypasses the host firewall and requires
  UEFI/MEBx unprovisioning plus removal of all AMT-capable network paths.

### 3. Neutral image (provider-agnostic)
Ships no VPN provider, cloud account or pre-installed credentials. Thunderbird
is mandatory and locally hardened, but no mail account is configured. User
brings their own provider profiles and account credentials.

### 4. Scoped Reversibility
Many user-facing hardening controls have documented opt-outs:
- Masked services → the owning module's service-specific supported recovery
  path; a bare `systemctl unmask` can be incomplete when policy is reasserted
- Module denies → the owning module's reviewed helper or documented policy
  change; do not delete broad `noid-*.conf` globs
- Kernel cmdline → use the documented control-specific helper. Maintained
  NoID Privacy BLS writers serialize through M21's shared lock and terminal-
  state guard; a bare `grubby --update-kernel=ALL` bypasses that contract.
- FPP relax (all profiles) → `noid-firefox-relax-fpp` / revert via `--restore`
- Intel MEI submodules → `noid-mei-restore-submodules`
- MEI full lockdown → `noid-mei-lockdown` (loses BootGuard detection)

This is not universal or necessarily one-click. Storage layout, encryption,
firmware and some image-policy changes require a reviewed migration or
reinstall, and every opt-out must retain its documented security/privacy cost.
No black-box hardening. No hidden cryptographic mods. No LD_PRELOAD
surprises.

### 5. Source-of-truth lives in kickstart snippets
`kickstart/snippets/NN-name.ks` is authoritative for the %post
behavior of Module N. User-facing markdown documents describe but
do NOT define that behavior. Any drift between doc and source → doc
is wrong, fix the doc.

Runtime state is captured in:
- `/var/lib/noid-privacy/stamp-<N>-<name>.ok` — health stamps for the current
  adopter Modules enumerated by `99-finalize` in `EXPECTED_STAMPS`; other
  Modules retain their own validators
- `/var/lib/noid-privacy/usbguard-status.txt` — USBGuard state (M14)
- `/var/lib/noid-privacy/mei-status.txt` — Intel ME config (M15)

### 6. Transparent trade-offs
Every decision that favors privacy over convenience, or vice-versa,
is documented at the decision point:
- `/home` NOT noexec (breaks Flatpak, documented trade-off)
- `/dev/shm` noexec (workloads that require executable shared-memory mappings
  need an explicit compatibility/security review)
- `/var/tmp` no noexec (package/build/install compatibility baseline; the
  historical dracut failure RHBZ#2274246 was fixed in dracut 102)
- mei+mei_me LOADED despite MEI risk (trades local-attack-surface
  for fwupd BootGuard detection)

## Dependency ordering

`master.ks` `%include` order is dependency-driven:

```
01 → 02 → 03 → 04 → 05 → 06 → 07 → 08 → 09 → 10 →
11 → 11b → 12 → 13 → 14 → 15 → 16 → 17 → 18 → 19 →
20 → 21 → 22 → 23 → 24 → 25 → 26 → 27 → 28 → 29 →
30 → 31 → 32 → 33 → 34 → 35 → 36 → 40 → 37 → 41 → 42 → 99
```

Critical constraints (master.ks `Snippet order CRITICAL
CONSTRAINTS`):
- **99 must be LAST** — it verifies the final composed filesystem and rejects
  build-time AIDE trust state
- **13 before 14, 15** — welcome script reads status files from 14/15
- **01 before 99** — bootloader artifacts must exist for final cross-checks
- **11b after 11** — M11b imports DNS resolution baseline from M11
  chrony+resolved + cross-ref helper functions
- **34 after 16** — M34 firefox-playground depends on
  `/usr/share/noid-firefox/user.js` shipped by M16
- **41 before 99** — M41 anaconda-cleanup removes liveuser/GDM
  auto-login/sudoers before final artifact verification
- **42 before 99** — M42 installs the shared 30-day retention policy and
  timers before M99 verifies the final artifact state
- **40 logical position any time before 99** — audit-bundle is
  independent supply-chain payload (no inter-module deps beyond M32
  HTTP staging pattern reuse)

Cross-Module contracts are verified in `99-finalize` through owning-module
validators and, for the current adopter set, exact health stamps enumerated in
`EXPECTED_STAMPS`.

## Health stamp pattern (engineering)

Modules can emit a stamp file at end of successful %post:

```
/var/lib/noid-privacy/stamp-<N>-<name>.ok
```

Format: `key=value` shell-sourceable.
Fields: `module`, `name`, `version`, `status=ok`, `timestamp`,
`checks_passed`, `checks_total`.

99-finalize iterates all stamps and asserts `status=ok`. New
Modules adopt the pattern; existing ones use per-artifact checks.
Migration is opt-in + incremental. See `docs/engineering-health-stamp-pattern.md`
in the project repo (not shipped in the image).

## Threat model (short version)

### Mitigated or made more observable

- LAN peer reachability and common discovery traffic are reduced by the
  physical-interface, topology and service policies. This does not hide public
  Internet traffic from an ISP.
- When the user supplies and verifies a VPN/profile killswitch, it can add an
  ISP-observer boundary; no VPN or provider killswitch is bundled.
- TunnelVision-style DHCP routes, gateway ARP changes and selected LAN-policy
  drift are blocked or surfaced by layered controls with documented recovery
  paths; no control is a categorical defense against every active-LAN attack.
- USBGuard limits newly attached devices according to its active policy. It is
  not a guarantee against electrical-damage devices or already trusted gear.
- Module policy, signature enforcement and lockdown reduce kernel attack
  surface; they do not prevent kernel zero-days.
- Firefox FPP and policy reduce selected fingerprinting inputs; they do not
  make browsers anonymous or unlinkable.
- After the user reviews and activates a baseline, AIDE supplies later file
  drift evidence. It does not prevent persistent malware or classify drift.
- Snapper can aid recovery for covered root-state snapshots when the machine
  still boots; the separate `/home` subvolume is not rolled back.
- Enumerated unattended telemetry/discovery defaults are disabled. Manual
  firmware requests, applications, account logins and user actions can still
  contact their respective services.

### Out of scope or residual limitations
- Active state-level attacker with physical access. Secure Boot can constrain
  some boot-chain substitutions when firmware keys/state are trustworthy; it
  does not make the LUKS header or platform firmware tamper-proof.
- Compromise of Fedora's trusted signing/build infrastructure. GPG/RPM and
  module-signature verification authenticate the configured upstream trust
  chain; they cannot detect malicious artifacts authorized by that chain.
- Zero-day kernel exploits against running processes (mitigations=auto
  reduces exploitability, doesn't eliminate)
- AMD PSP firmware-level attacks (not host-disableable; controls are
  product-specific, see
  [15-amd-psp-hardware-layer.md](15-amd-psp-hardware-layer.md))
- Compromised hardware, including physical fault-injection attacks against
  platform TPM implementations; feasibility and required access are
  hardware/attack specific.
- User-targeted phishing and social engineering remain material risks;
  technical controls can reduce impact but cannot establish user intent.

## How to verify a running system matches image intent

```bash
# Full hardening state — one screen
noid-status

# Detailed state per component
sestatus
sudo auditctl -s
cat /sys/kernel/security/lockdown
sudo firewall-cmd --list-all-policies
resolvectl status
sudo chronyc tracking
sudo fwupdmgr security
mokutil --sb-state
sudo usbguard list-devices
sudo snapper -c root list | head -5
sudo journalctl -u aide-check.service --no-pager | tail -10
```

If any of the above shows unexpected state, investigate per
[99-troubleshooting.md](99-troubleshooting.md).

## References

- Per-Module discovery: `kickstart/snippets/NN-name.ks` header
  comments (in source tree)
- `INDEX.md` — semantic navigation of Modules (source tree)
- `CONTRIBUTING.md` — Module lifecycle + pre-LOCK gate (source tree)
- `docs/engineering-health-stamp-pattern.md` — stamp design (source tree)
- [01-getting-started.md](01-getting-started.md) — user onboarding
- [00-README.md](00-README.md) — master doc index

ARCH_EOF
publish_doc "$ARCH_DOC"
log "  [OK] 00-architecture.md written"

# ------------------------------------------------------------------------------
# Phase 4 — 27-performance.md
# ------------------------------------------------------------------------------
PHASE="P4-performance"
log "Writing 27-performance.md"

PERFORMANCE_DOC="$DOC_DIR/27-performance.md"
DOC_TMP=$(mktemp "$DOC_DIR/.27-performance.md.XXXXXXXX")
cat > "$DOC_TMP" <<'PERFORMANCE_EOF'
# Performance policy, profiles and measurement

NoID Privacy does not promise a universal performance gain. Security,
integrity, privacy and audit controls can cost CPU time, memory, I/O or latency;
the size of that cost depends on the machine and workload. The image has no
published controlled benchmark set comparing stock Fedora with NoID Privacy, so percentages or
"zero downside" claims are not treated as evidence.

## What owns performance policy

Module 27 is the one hardware/performance boundary. It deliberately delegates
workload-dependent tuning to maintained Fedora and kernel mechanisms:

- Fedora's `systemd-udev` rule and each block driver select I/O schedulers.
  No `/etc/udev/rules.d/60-noid-iosched.rules` override is installed.
- Fedora's `zram-generator-defaults` package owns zram activation, size,
  compression and priority. No NoID Privacy zram override is installed.
- The kernel and Fedora's `tuned`/`tuned-ppd` stack own CPU boost, EPP and
  governor behavior. No unconditional Intel HWP dynamic-boost write is made.
  The internal `noid-balanced` child profiles retain Fedora's policy and
  disable only its inapplicable built-in-governor module reload.
- Module 02 stays security/privacy-only. Neither M02 nor M27 installs BBR, a
  qdisc, socket ceilings, swappiness, swap readahead, writeback, block
  read-ahead or a command-line/initramfs performance setting.

This avoids freezing a result from one SSD, CPU, RAM size, VPN or benchmark as
a distro-wide truth. BFQ, mq-deadline and `none` make different fairness,
latency, overhead and throughput trade-offs. zram algorithms similarly trade
compression ratio and memory recovery against CPU work.

## Explicit functional and stability policy

M27 still owns several non-benchmark decisions:

- `earlyoom` is the image's process-level low-memory handler; M08 masks the
  competing systemd-oomd service.
- Wake-on-LAN is disabled on physical PCI/USB wired NICs. EEE remains with
  Fedora, each driver and the link partner; NoID Privacy does not force a
  distro-wide EEE state through systemd 259's legacy 32-bit ioctl.
- Dynamically mounted USB/SD storage uses UDisks' `noexec` default, including
  USB SSDs/HDDs that report `removable=0`. It blocks direct execution, not an
  interpreter reading a file, and an explicit allowed `exec` request can
  override the default. Blanket `sync` is absent: VFAT/exFAT/NTFS/ext4 testing
  showed a large performance cost, while mount(8) says it may shorten
  limited-write media life. UDisks filesystem defaults still merge in
  (`flush` on vfat). External NTFS prefers Fedora's in-tree `ntfs3` with
  ntfs-3g fallback because Fedora 44's current ntfs-3g RW path failed on the
  validation volume. Neither policy alters the device-cache state or makes
  active-I/O unplugging safe: eject/power off before disconnecting.
- Fedora's `thermald` runtime probe decides thermal-protection
  applicability. A Lenovo `dytc_lapmode` sensor is inventory, not a reason to
  disable thermal protection. `intel_lpmd.service` is masked under the
  single-EPP-writer policy (tuned/tuned-ppd is the one power backend).
- M17 defaults GNOME idle auto-suspend to off on AC and battery without
  locking either setting; users can re-enable it in GNOME Settings. The
  kernel/firmware still owns the platform suspend mode. NVIDIA installations
  keep their separate documented laptop lid policy in Module 19.

These choices are verified for actual behavior during the three lifecycle
passes. They are not presented as universal throughput improvements.

## Supported opt-in: GNOME Power Mode

Use **GNOME Settings → Power → Power Mode**. Fedora's `tuned-ppd` maps the GNOME
selection to a tuned profile. The public choices remain `Balanced`,
`Performance` and `Power Saver`; the internal `noid-balanced` name only removes
the invalid module reload. `Balanced` is the normal baseline. The other two
are explicit choices; available profiles and their effect vary by hardware
and may change speed, power draw, temperature, acoustics and battery life.

Check the effective state:

```bash
busctl get-property net.hadess.PowerProfiles /net/hadess/PowerProfiles \
  net.hadess.PowerProfiles ActiveProfile
tuned-adm active
systemctl is-active tuned.service tuned-ppd.service
```

NoID Privacy does not ship BBR/fq as a hidden or default optimization. Network
congestion control depends on route, RTT, loss, workload and VPN transport, and
can change externally observable traffic behavior. A future network profile
requires an explicit privacy decision plus retained no-VPN, WireGuard and
OpenVPN measurements.

## Measure instead of guessing

Record the exact build, firmware, kernel, microcode, power source/profile,
thermal state and workload. Reboot between A/B states, control warm/cold caches,
repeat runs and report variation rather than one favorable result.

```bash
cat /etc/noid-build-info
uname -r
lscpu
systemd-analyze time
systemd-analyze blame
free -h
swapon --show
tuned-adm active
```

Measure the real target workload on its real target hardware. Do not disable
SELinux, audit, IOMMU, CPU mitigations, lockdown, ASLR or memory hardening based
on a percentage measured on another system. If performance becomes a release
criterion, retain the reproducible benchmark procedure and raw results with the
release evidence.

Source-level rationale: `docs/performance-profile.md` in the project tree.
PERFORMANCE_EOF
publish_doc "$PERFORMANCE_DOC"
log "  [OK] 27-performance.md written"

# ------------------------------------------------------------------------------
# Phase 4b — Canonical product-boundary source documents
# ------------------------------------------------------------------------------
PHASE="P4b-product-boundaries"
log "Writing canonical product-boundary documentation"

# Generated from docs/threat-model.md by scripts/regen-product-boundary-docs.sh.
THREAT_MODEL_DOC="$DOC_DIR/threat-model.md"
DOC_TMP=$(mktemp "$DOC_DIR/.threat-model.md.XXXXXXXX")
cat > "$DOC_TMP" <<'NOID_THREAT_MODEL_DOC_EOF'
# Threat Model

This document describes the attacker classes NoID Privacy Workstation
aims to defend against, the trust assumptions made, and the defences in
depth that implement those goals.

## Summary — who this protects, who it doesn't

| Threat class | Coverage | Primary mechanism / boundary |
|---|---|---|
| Ad / tracker fingerprinting | Mitigated | NoID Privacy Firefox Hardening v1.0 (arkenfox v144.0 derived) + FPP + uBlock; behavior and account identity remain linkable |
| ISP + local-network surveillance | Partial | Strict-default global/physical Quad9 DoT, best-effort opportunistic DNS for unset VPN/private profiles, optional VPN and LAN isolation; opportunistic transport can be downgraded to DNS/53, and without a VPN the ISP still sees destination IPs/timing |
| Data broker profiling | Partial | dFPI (Total Cookie Protection) and MAC randomization reduce passive linkage; logins and behavior can still identify the user |
| Local-network (LAN) attacks | Strong layered mitigation | inbound IP DROP, topology-aware LAN-egress guard, permanent gateway/approved-peer neighbour pins, and native IPv4 conflict detection; DHCP, EAPOL and standard ARP remain necessary link traffic |
| Software supply chain | Partial | signed/pinned sources and integrity checks reduce risk; upstream Fedora and explicitly selected third parties remain trusted |
| Browser memory corruption | Mitigated | Firefox Fission, seccomp, namespaces, SELinux, and timely updates reduce impact; they do not eliminate engine vulnerabilities |
| Kernel exploits | Mitigated | 106 static sysctl assignments + one generated durable assignment for the selected physical interface and event-time enforcement on every physical pre-up + a 134-state module inventory with 53 effective loadable-module denies + 50 shared kernel-command-line tokens (+ up to 7 hardware-conditional); built-ins and kernel zero-days remain residual risk |
| USB attack devices | Strong mitigation after enrollment | USBGuard default block plus firstboot policy; already-authorized or controller-level attacks remain possible |
| Evil-maid at rest | Conditional | LUKS2 + Secure Boot, only if encryption is selected and firmware/key state remains trustworthy |
| Intel ME / AMT persistence | Limited host-side reduction | KT/SOL driver-binding block + fwupd visibility; AMT requires UEFI/MEBx and hardware/network-path action outside the host firewall |
| AMD PSP persistence | Documentation + generic layers | PSP is below the host-OS boundary and is not host-disableable; IOMMU/Secure Boot, available fwupd inspection, and PSB/CVE guidance do not disable it |
| — | — | — |
| State-level traffic analysis | ❌ | Beyond desktop-OS threat model |
| Targeted endpoint-exploit (APT) | ❌ | No VM-boundary (use Qubes) |
| Compromised VPN provider | ❌ | User's responsibility (choose no-logs provider) |
| Account-linking (Gmail, GitHub) | ❌ | Defeats pseudonymity (user choice) |
| Physical coercion | ❌ | "$5 wrench attack" — no OS defends this |
| Zero-days between disclosure + update | ❌ | Normal AV-gap |
| Upstream Fedora supply-chain | ❌ | xz-utils-class events (koji reproducibility partial) |
| Social engineering / phishing | ❌* | (*NoID Privacy Firefox hardening + uBO partial, user vigilance required) |

See [`scope.md`](scope.md) for the full out-of-scope list with per-threat rationale.

---

## VPN clarification (important)

NoID Privacy Workstation is **VPN-optional and provider-neutral**:

- The image does **not** ship a hardcoded VPN client
- Users install a provider client or import a generic NetworkManager
  WireGuard/OpenVPN profile
- A provider client may supply its own persistent killswitch; that capability
  and configuration must be verified for the selected client
- Image-level safety net: `50-vpn-zone-enforce` NM dispatcher ensures
  genuine VPN interfaces land in the inbound-DROP `noid-vpn` zone
- Independent WAN-strict layer: after a supported profile yields an exact
  `server IP + TCP/UDP + port` tuple, physical-WAN egress is limited to those
  tuples. Unknown profile schemas fail closed; provider route/DNS behavior is
  still tested separately.

The runtime mode is part of this claim. `GRACE_BOOTSTRAP` is a deliberate,
non-expiring onboarding/no-VPN decision state with direct IPv4 WAN; it is not
strict protection. The nft `inet` output/forward hooks cover IPv4/IPv6 traffic
through the initial host network stack. They are not a malware-proof boundary:
`CAP_NET_RAW`/`AF_PACKET` link-layer injection, `CAP_NET_ADMIN` firewall or
route control, `CAP_SYS_ADMIN` network-namespace/device control, non-IP link
traffic and firmware out-of-band paths remain outside M06's claim. Ordinary
unprivileged applications receive none of those capabilities by default; the
three-pass candidate gate verifies that raw/packet sockets and an nft mutation
are rejected for UID 65534.

The **LAN-isolation + WAN-only** architecture is independent of VPN:
the static policy blocks known local/link-local/multicast ranges and the
topology-aware nftables guard additionally blocks every directly connected
prefix, regardless of whether that prefix uses private or public address
space. A default-drop XDP program additionally rejects unsolicited physical
ingress before AF_PACKET; its TC companion admits only bounded reverse tuples
that were observed leaving after nftables filtering. Explicit per-IP NoID Privacy
Network exceptions are the only LAN application-data escape hatch. DHCP,
EAPOL and standard ARP—including native IPv4 conflict detection—remain
necessary link boundaries; this does not authorize ordinary IP traffic addressed to
the gateway. Direct-to-ISP is available during the
initial bootstrap-grace state or by an explicit WAN-strict pause/disable; once
strict VPN tuples are armed, disconnecting the tunnel does not silently restore
direct internet egress.

---

## Design principles

1. **Silent-machine baseline** — no NoID Privacy telemetry and no LAN discovery
   broadcasts. Documented automatic control traffic still exists where the
   configured function requires it, including DHCP/ARP and enabled NTS/DNS
   health checks; user-installed applications can add their own traffic.
2. **Defense in depth** — independent controls are used where the platform
   permits. Intel AMT is an explicit boundary: host firewall, IOMMU and
   KT/SOL driver-binding controls do not disable its firmware OOB path.
   UEFI/MEBx unprovisioning plus disabling every AMT-capable wired/wireless
   interface is a user-controlled prerequisite.
3. **Reversibility** — hardening decisions are documented with their
   trade-off + reversal procedure. Users who need a specific hardening
   off can revert.
4. **Integrity failures stay visible** — AIDE reports file-integrity drift and
   returns a non-zero status; it is detection, not a boot gate. When LUKS is
   selected, failure to unlock the root volume prevents that encrypted system
   from booting. When Secure Boot is actually enabled in platform firmware, its
   signature policy rejects an untrusted boot component; this image requires
   UEFI but cannot itself enable or provision firmware Secure Boot.

## Attacker classes (in-scope)

### 1. Passive network surveillance

- **Capability**: full packet capture on any network the user touches
  (home, café, office, mobile hotspot).
- **Defences** (image-level, without VPN):
  - Firefox, Thunderbird and ordinary resolver clients use systemd-resolved.
    Without a more-specific link scope, global Quad9 uses strict authenticated
    DoT and fails closed when port 853 or certificate validation is unavailable.
    The user may explicitly select opportunistic global + physical transport
    for VPN/captive-portal compatibility, which permits downgrade to DNS/53, or
    an explicit plaintext recovery mode through `noid-dns-mode`.
    An active VPN/private `~.` link resolver supersedes the global scope.
    NoID Privacy does not rewrite that profile: an unset
    `connection.dns-over-tls` inherits the image's generic `opportunistic`
    connection default, while an explicit profile value wins. This best-effort
    mode tries DoT but permits DNS/53 fallback, cannot authenticate the resolver
    in systemd-resolved's opportunistic mode, and is not MITM-resistant. A user
    may opt into a separate browser Secure DNS provider, with that bypass made
    explicit.
  - Chrony NTS-only (no plaintext NTP, 6 configured operator-supported EU
    endpoints; candidate runtime evidence must prove current authenticated
    operation).
  - No mDNS/WSD/SSDP/LLMNR/NetBIOS broadcasts (services masked + ports
    blocked in block-lan-out policy).
  - Physical-WAN IPv6 is disabled through default-off kernel policy,
    per-physical-pre-up enforcement and NetworkManager
    `ipv6.method=disabled`; VPN-internal IPv6 remains a separate profile
    boundary.
  - Firefox ECH (Encrypted Client Hello) enabled; it hides the inner
    ClientHello/SNI only where a valid ECH configuration is obtained and ECH
    is successfully negotiated.
- **Defences** (optional VPN layer, user-installed):
  - Image ships `50-vpn-zone-enforce` dispatcher to ensure genuine VPN
    interfaces land in firewalld `noid-vpn` (target DROP).
  - WAN-strict allows only exact saved VPN endpoint transport/port tuples on
    physical interfaces after strict mode is armed; same-IP other-port traffic
    remains blocked.
  - A provider client may add a stronger route/DNS killswitch; verify its
    behavior with the tunnel both up and down.
  - Image is **provider-neutral** — no hardcoded VPN dependency.
- **Residual risk**: without VPN, the ISP sees destination IPs and encrypted
  traffic metadata. With VPN, the ISP still sees the VPN endpoint IP and
  timing/volume; transport-specific metadata can reveal more. The VPN provider
  can observe the tunnel's egress side and could be compelled to log.

### 2. Network tracking across locations

- **Capability**: correlate the user's device across multiple physical
  networks via MAC address, hostname, DHCP options.
- **Defences**:
  - Fedora/NetworkManager `wifi.cloned-mac-address=stable-ssid`: a stable
    pseudonymous MAC per SSID, interface and installation identity (different
    across SSIDs, stable within the same SSID).
  - Ethernet uses a stable pseudonymous cloned MAC per connection profile;
    this is not automatic per-physical-LAN separation.
  - DHCP uses the active cloned MAC as its client identity and does not
    advertise the hostname.
- **Residual risk**: the same Wi-Fi network can recognize repeat visits;
  operators sharing an identical SSID can compare the same pseudonym, and a
  reused Ethernet profile remains linkable across wired LANs. MAC addresses
  are not authentication, and timing and traffic-fingerprinting attacks remain.

### 3. Browser fingerprinting

- **Capability**: server-side fingerprinting via Canvas, WebGL,
  AudioContext, fonts, screen metrics, WebRTC leaks.
- **Defences**:
  - NoID Privacy Firefox Hardening v1.0 user.js (hundreds of active
    profile-hardening preferences, embedded, derived from arkenfox v144.0
    released 2026-04-20, MIT — absorbed 2026-04-22, no upstream fetch).
  - FPP (`privacy.fingerprintingProtection=true`) with +AllTargets and
    targeted excludes for known-breakage keys (real timezone, real
    dark/light theme, real keyboard).
  - Canvas + WebGL randomization active.
  - WebRTC `media.peerconnection.enabled=false`.
- **Residual risk**: behavioural fingerprinting (keystroke dynamics,
  mouse patterns, scroll timing) cannot be blocked at the browser layer.

### 4. USB attack devices

- **Capability**: attacker has brief physical access to plug a malicious
  USB device (O.MG cable, Rubber Ducky, BadUSB, keyloggers).
- **Defences**:
  - USBGuard whitelist policy (any new device blocked until explicitly
    allowed).
  - Firstboot policy captures the user's legit USB baseline.
  - USBGuard's implicit-block policy deauthorizes new devices at the
    kernel USB-authorization layer until explicitly allowed.
- **Residual risk**: USBGuard does not make already-authorized devices,
  internal/controller-level paths, malicious charging hardware or
  electrical-damage devices trustworthy. Sustained physical access remains
  outside this device-enrollment boundary.

### 5. Local network attacker (hostile LAN)

- **Capability**: attacker on the same WiFi/wired network (café,
  conference, workplace) performs ARP spoofing, DHCP exhaustion, rogue
  DNS, lateral-move scans.
- **Defences**:
  - Bounded gateway/approved-peer learning followed by exact permanent kernel
    neighbour pins. The nft ARP table holds coordination state only and has no
    packet hook, so RFC 5227 conflict detection and address defence still work.
  - firewalld `drop` zone default, LAN-drop-all policy (block-lan-out).
  - A default-drop XDP/TC pair rejects unsolicited physical frames before raw
    packet sockets and admits gateway IPv4 only as a bounded reverse flow.
  - No LAN-reachable application services are enabled by the image
    (`openssh-server` is absent; mDNS/wsdd/Samba are not exposed). Loopback
    listeners and required client/control-plane sockets are a separate boundary.
  - Per-connection stable MAC reduces cross-network tracking; native ACD
    catches duplicate IPv4 assignment while permanent pins resist ordinary
    gateway/approved-peer cache replacement.
- **Residual risk**: DHCP/EAPOL and standard ARP are unavoidable link
  exchanges and ARP remains visible to packet sockets. Ethernet/Wi-Fi source
  MACs are not cryptographic: an
  attacker who spoofs the pinned gateway and guesses an active reverse tuple
  can reach later conntrack/firewall layers. Encrypted-but-visible VPN or
  encrypted-DNS flows can also reveal this is a hardened host.

### 6. Commodity malware / drive-by

- **Capability**: user clicks a malicious link; visits a compromised
  site; runs a curl|bash from a stranger's docs page; opens a malicious
  PDF.
- **Defences**:
  - Flatpak sandboxing and global sensitive-directory/D-Bus denials for GUI
    apps installed as Flatpaks (see `18-flatpak-trust-model.md` shipped in
    `/usr/share/doc/noid-privacy/`). Native GUI apps remain outside Flatpak and
    rely on their own sandboxing plus the host SELinux/systemd/browser layers.
  - SELinux enforcing constrains policy-covered actions; immutable auditd
    rules preserve selected security-relevant event evidence. Neither is a
    categorical privilege-escalation detector.
  - After the user reviews and accepts a baseline and enables its timer, AIDE
    daily scans detect covered file drift.
  - Hardened sysctl (user.max_user_namespaces=256,
    kernel.unprivileged_bpf_disabled=1 — irreversible for the running boot).
  - No setuid shells. A native tmpfiles/dnf5 policy removes five unnecessary
    SUID workflows while retaining Fedora privilege on four load-bearing
    account/consolehelper/GNOME paths; every remaining SUID binary stays an
    explicit RPM/AIDE/runtime audit item.
  - bubblewrap available (Flatpak's sandbox substrate).
- **Residual risk**: sophisticated exploit chains targeting 0-day
  kernel vulnerabilities can bypass sandboxing.

### 7. Firmware-level (Intel ME / AMT, AMD PSP / ASP)

- **Capability**: Intel Management Engine firmware receives remote
  command, uses KT/SOL redirection to inject keystrokes or read serial
  consoles; AMT allows out-of-band remote administration. AMD Platform
  Security Processor (PSP, formerly ASP) is a below-OS security
  coprocessor, but is not itself an AMT-equivalent remote-management stack;
  product-specific AMD DASH/AIM-T capability is a separate OOB boundary.
- **Host-side controls — Intel** (Module 15):
    1. `mei` + `mei_me` core modules kept available for supported fwupd
       attributes. The overall HSI score remains platform-, firmware-,
       runtime-, and fwupd-version-dependent.
    2. KT/SOL PCI functions (27 IDs across 6th–17th Intel gen +
       Sapphire Rapids workstation) use `driver_override=none`, preventing a
       Linux driver binding but not disabling firmware-owned AMT/SOL/KVM.
    3. Generic IOMMU translated domains, UEFI Secure Boot and
       `lockdown=integrity` harden the host; they are not AMT containment.
    4. Required user action: fully unprovision/disable AMT in UEFI/MEBx,
       disable/remove every AMT-capable integrated Ethernet and compatible
       Wi-Fi path, and use a non-AMT adapter for WAN where practical.

  **Sub-modules `mei_hdcp`/`mei_pxp`/`mei_wdt` are LOADED by default**
  (cost outweighed benefit per Kicksecure security-misc Issue #239,
  2025). Each remains opt-in blockable via
  `noid-mei-restore-submodules --block hdcp|pxp|wdt` (choose one token):
  - `mei_hdcp` block → 4K Netflix/Disney+/Prime HDCP streams downgrade.
  - `mei_pxp` block → HuC HW-accel HEVC/AV1 decode breaks on Gen12+ iGPU.
  - `mei_wdt` block → breaks platforms that use the ME watchdog for remote
    management/recovery; opt in only when that function is not required.
- **Defences — AMD (awareness / docs only — PSP not host-disableable)** (Module 15 Step 4b):
    1. `ccp` module **kept available by default** because it can back
       platform crypto, RNG, and fTPM functions. Those dependencies vary by
       machine: neither loading nor blacklisting `ccp` universally controls
       fTPM or disables the PSP.
    2. IOMMU isolation (`amd_iommu=on`, auto-set via CPU detection).
    3. Platform Secure Boot (PSB) awareness — product-specific provisioning
       can burn irreversible OTP fuses; the user doc warns against enabling it
       without exact vendor documentation and a recovery plan.
    4. UEFI Secure Boot + lockdown=integrity (shared with Intel path).
    5. Available fwupd security attributes can surface some platform state;
       they do not guarantee PSP coverage or a particular HSI level.
    6. CVE awareness documentation — CVE-2025-2884 (TCG TPM 2.0
       reference-code out-of-bounds read, CVSS 6.6 medium).
       [AMD-SB-4011](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-4011.html)
       is authoritative: affected TPM implementation and
       minimum firmware differ by processor family, so there is no universal
       AGESA version. Also tracked: CVE-2021-3764
       (`ccp_run_aes_gcm_cmd()` local DoS; use the maintained Fedora kernel)
       and faulTPM (fault-injection attacks on Ryzen fTPM).
- **Residual risk**: ME/PSP firmware below the OS boundary is not fully
  controllable by the host. Blacklisting the Linux `ccp` driver does not
  switch off PSP firmware and can remove useful host functions. Mitigations
  reduce but do not eliminate firmware-class threats on either vendor.
  Intel documents AMT as operating independently of the OS, so host
  firewalld/nftables rules cannot enforce the LAN/WAN claim against AMT OOB.
  Pre-compromised PSP/ME firmware from factory = out-of-scope (see
  `scope.md` §4).

## Trust assumptions (things we trust)

- The Linux kernel, compiled by Fedora, signed by Fedora's release key.
- Fedora 44 repositories and GPG keys (imported at install time).
- Platform firmware and its configured UEFI Secure Boot trust anchors; when
  Secure Boot is enabled, Fedora's currently signed shim/GRUB/kernel chain. The
  exact Microsoft/OEM CA set is platform- and firmware-state-dependent and is
  not provisioned by this image.
- Firefox release binaries and Mozilla CA (required for Firefox to trust
  certs — no realistic alternative).
- arkenfox upstream as the historical source of the Firefox user.js
  baseline (v144.0 snapshot absorbed into this repo 2026-04-22; no
  runtime network trust in arkenfox post-absorption).
- HorlogeSkynet upstream as the historical source of the Thunderbird user.js
  baseline (tagged v140.2 snapshot); the carried NoID Privacy derivative is maintained
  and embedded locally, with no build/runtime upstream-user.js fetch.
- uBlock Origin's image seed at the pinned GitHub release tag, plus the fixed
  official channel and Firefox native-signature boundary used only by the
  user-started Update All transaction for later versions.
- VSCodium's upstream repository and signing identity. The local key material
  is accepted only after an exact full-fingerprint match
  (`1302DE60231889FE1EBACADC54678CF75A278D9C`); package and repository-metadata
  signatures are required. This removes first-import TOFU but does not remove
  trust in the upstream key holder, repository or binaries.

### Repository metadata and package-signature boundary

DNF treats RPM payload-signature enforcement (`gpgcheck`, exposed by DNF5 as
effective `pkg_gpgcheck`) separately from OpenPGP verification of repository
metadata (`repo_gpgcheck`). NoID Privacy requires payload-signature
verification for every enabled repository and treats a missing package check
as an update error. `noid-update-all.sh` inventories DNF5's effective state
after the user-started metadata refresh and reports every enabled repository
without metadata OpenPGP verification separately. The live inventory is
authoritative because enabled repositories are user-changeable.

NoID Privacy Workstation enables metadata verification whenever the publisher
supplies a DNF-compatible `repomd.xml` signature; the shipped VSCodium
repository is the current example (`repo_gpgcheck=1` plus an exact locally
pinned signing key).
The Fedora 44 Cisco OpenH264 endpoint configured by Module 08 does not publish
`repomd.xml.asc`, so that repository deliberately keeps `repo_gpgcheck=0`.
Enabling it would make the metadata refresh fail; it cannot create a signature
that the distribution endpoint does not supply.

For Cisco OpenH264, the accepted residual boundary is an HTTPS Fedora
metalink, a local Fedora package key and mandatory RPM payload-signature
verification. This prevents an unsigned payload from satisfying the
transaction, but it does not OpenPGP-authenticate repository metadata or its
freshness: a compromised trusted distribution path can hide updates or change
which still-valid signed candidates are visible. Fedora builds and signs the
RPMs, Cisco distributes those exact binaries, and `skip_if_unavailable=False`
makes a distribution-path outage visible instead of silently dropping the
repository.

## Trust non-assumptions (things we don't trust)

- Intel Management Engine firmware, AMT SKU configuration.
- OEM UEFI firmware SMM drivers (partial mitigation via Secure Boot +
  IOMMU).
- Upstream Fedora `audit` rules (we override with 132 hardened
  b64/b32-complete rules).
- Fedora default `systemctl list-unit-files` state (the project masks an
  explicit cross-module set of unused units; `MASK_LIST_EOF` in Module 08 and
  the service-specific modules are authoritative because the set evolves).
- Fedora default DNS resolver config (we replace it with strict authenticated
  global + physical Quad9 DoT; the explicit compatibility mode permits a
  documented DNS/53 downgrade, while provider-neutral VPN/private DNS takes
  precedence; Firefox and Thunderbird follow that system path by default).
- Fedora default GNOME dconf profile (we override with `/etc/dconf/db/distro.d/`).

## Post-Quantum Cryptography (PQC) status

**Threat model**: a future cryptographically relevant quantum computer
(CRQC) would break RSA, ECC (including Curve25519 and NIST P-curves), and
finite-field DH. NIST says no one knows when such a machine will exist;
estimates range from a few years to a few decades. Symmetric 256-bit
cryptography retains a conservative margin of roughly 128 bits against ideal
generic quantum key search, rather than suffering Shor's exponential
public-key break.

**Active threat today**: "harvest now, decrypt later" — an adversary records
classically protected traffic now and attacks its public-key exchange after a
CRQC arrives. Short-lived ephemeral Curve25519 keys give forward secrecy
against later long-term-key theft, but do not make a recorded Curve25519
exchange PQ-resistant.

### Coverage matrix (layers controlled by NoID Privacy)

| Layer | Mechanism | PQ status |
|-------|-----------|-----------|
| Disk-at-rest (LUKS) | Expected AES-XTS with two AES-256 keys + Argon2id keyslot; verify installed header/keyslot | Strong symmetric PQ margin when observed; passphrase and parameters still matter |
| SSH transport | hybrid algorithms first, Curve25519 fallback (Module 09) | Hybrid only when `mlkem768x25519` or `sntrup761x25519` is negotiated |
| TLS 1.3 (Firefox + Thunderbird) | explicit hybrid-client pref, NSS 3.118+ default group | Hybrid-capable; selected peer and handshake determine coverage |
| DNS transport | Strict authenticated global + physical Quad9 DoT by default; optional opportunistic/off selector; VPN/private per-link DNS precedence with NoID Privacy's best-effort opportunistic fallback for unset profiles; Thunderbird/DKIM follow the active OS/VPN resolver; optional browser Secure DNS | No image-wide PQ guarantee; active resolver, DNS/53 downgrade, compatibility fallback and endpoint negotiation are scope-dependent |
| Browser HTTPS | Firefox/NSS hybrid-capable client | Hybrid only when the connection negotiates `X25519MLKEM768` |

### Upstream-dependent gaps (NOT fixable by NoID Privacy)

| Layer | Mechanism | PQ status |
|-------|-----------|-----------|
| WireGuard (provider-managed or self-managed) | classical Curve25519 handshake; an independently provisioned strong preshared key can add a symmetric layer | No standardised interoperable PQ handshake mode verified in this audit |
| OpenPGP / GnuPG email | installed client support and correspondent keys vary | RFC 9980 defines PQ/traditional algorithms; installed GnuPG 2.4.9 has no PQ public-key algorithm and generic Thunderbird/GnuPG interoperability is not established |
| Secure Boot chain | platform/upstream classical signatures | Platform/distribution migration required |
| MOK keys (NVIDIA-driver signing, Module 19) | local classical signature | No PQ kernel-module-signing path provided |
| Fedora RPM signatures | upstream classical signatures | Distribution migration required |

Lockdown, Secure Boot, signed repositories, TLS, and AIDE remain useful
defence-in-depth today, but none converts a classical signature or key exchange
into a PQ one. The image cannot fix peer, protocol, firmware, or distribution
signature gaps unilaterally.

### HNDL priorities

- Long-lived public-key-encrypted mail is a high-priority concern because the
  original ciphertext may already have been copied.
- WireGuard and any TLS/SSH session that negotiates a classical fallback remain
  recordable classical exchanges.
- Browser TLS and SSH have hybrid-capable client paths, but each session must
  be verified rather than labelled globally protected.
- LUKS has a strong symmetric margin but still depends on passphrase entropy,
  KDF parameters, and protection against offline copies.

### Maintenance posture

- **Watch-items** (release backlog): IETF WireGuard-PQ extension drafts,
  RFC 9980 implementation/interoperability in GnuPG and Thunderbird, and the
  UEFI/Microsoft Secure Boot PQ-key migration timeline.
- Re-verify the actual negotiated algorithms and package capabilities for each
  release; client capability is not equivalent to endpoint coverage.

For a full user-facing PQ status guide (configuration knobs, opt-out
options, future-proofing recommendations), see
[`docs/post-quantum-readiness.md`](post-quantum-readiness.md).

## Scope boundary

For explicit out-of-scope threats (physical seizure, evil-maid on the
BIOS flash, state-actor custom 0-day), see [`docs/scope.md`](scope.md).
NOID_THREAT_MODEL_DOC_EOF
publish_doc "$THREAT_MODEL_DOC"

# Generated from docs/scope.md by scripts/regen-product-boundary-docs.sh.
SCOPE_DOC="$DOC_DIR/scope.md"
DOC_TMP=$(mktemp "$DOC_DIR/.scope.md.XXXXXXXX")
cat > "$DOC_TMP" <<'NOID_SCOPE_DOC_EOF'
# Scope — Target Audience, Anti-Targets, Out-of-Scope

NoID Privacy Workstation 44 is a LAN-isolated, WAN-client-oriented hardening of
Fedora Workstation 44 that preserves a general-purpose GNOME desktop. Hardening
has workload- and hardware-dependent performance, power and memory costs. See
[`docs/performance-profile.md`](performance-profile.md) for the honest
accounting.

It is *not* a classified-data workstation, Tor-anonymity OS, or
compartmented national-security system. This document lists target
audience, explicit anti-targets, and the attacker classes + use-cases
that are **out of scope** so users can make informed deployment
decisions.

## Target audience — ideal user

- **Privacy-aware** + Linux-affine + Fedora-familiar
- **Single-user** workstation (developer / sysadmin / creator / researcher)
- Accepts **WAN-only workflow** — direct-to-internet or optional via VPN
- **LAN-isolation is a feature, not a bug** (no printer-sharing, no
  NAS-mount, no smart-home-hub integration, no Bonjour/mDNS)
- **Threat-model fit**: privacy + surveillance-resistance, NOT state-
  level anonymity

## Anti-targets — explicitly NOT for

- **Gaming-first rigs** — NoID Privacy is not latency/throughput-tuned for
  competitive play: congestion control/qdisc remain Fedora/kernel policy, and
  the hardening has workload-dependent costs on allocation-/syscall-heavy paths
  (see [`docs/performance-profile.md`](performance-profile.md) for the
  honest cost breakdown). **Gaming Mode** can relax the two repository-managed
  compatibility settings, then install Steam after the required reboot
  (32-bit execution + the Wine W^X SELinux boolean). That makes gaming
  possible, not guaranteed: Proton, GPU drivers and
  anti-cheat support remain title-, vendor- and version-dependent.
- **Multi-user / family systems** — single-user design; LAN-isolation
  blocks the shared-printer / shared-NAS / shared-media use-cases
  families depend on
- **Enterprise / AD / LDAP** — `sssd` and centralized-management integration
  are not shipped. The image assumes one user on one machine.
- **Operational whistleblowing** — Tor Browser is available as an
  optional Flatpak install, but the image is *not a Tor-default OS*.
  Use **Tails** (amnesic) or **Whonix** (VM-isolated Tor) for real
  operational anonymity.
- **Home-server / NAS / smart-home hub** — local and directly connected
  destinations are blocked by default. Access requires a deliberate per-peer
  exception in NoID Privacy Network.
- **ARM architecture** — `x86_64` hardcoded in the metalink URL; no
  aarch64 build. Raspberry Pi and Apple Silicon unsupported.
- **Non-UEFI systems** — BIOS-only legacy hardware is rejected. TPM 2.0 is
  optional and is not used for automatic LUKS unlock by this image. Secure Boot
  is strongly recommended, but its enabled/key state is controlled by platform
  firmware rather than the installer.

## Architecture — the four pillars (why the anti-targets exist)

1. **LAN-isolated** — the host OS accepts no new inbound connections on a
   physical LAN/WLAN and blocks host-generated application traffic to the
   directly connected network, including unusual/public prefixes. DHCP,
   EAPOL and standard ARP—including IPv4 conflict detection, address defence
   and gateway resolution—remain; ordinary IP traffic addressed to LAN peers or the gateway is not a
   control-plane exception.
   Per-IP exceptions are explicit through the Network app. Firmware OOB such
   as Intel AMT is outside the host firewall and requires the UEFI/MEBx and
   hardware checklist in Module 15.
2. **WAN-only** — egress goes to public internet only. Direct-to-ISP is
   supported in bootstrap-grace or through an explicit strict-mode
   pause/disable. VPN is **optional and provider-neutral** — the user installs
   a provider client or imports a generic NetworkManager WireGuard/OpenVPN
   profile. The image ships no hardcoded client, but its independent WAN-strict
   layer restricts physical egress to exact supported VPN endpoint
   `IP + transport + port` tuples after strict mode is armed. Provider
   route/DNS killswitch behavior remains a separate verification target.
   `GRACE_BOOTSTRAP` is an explicit unexpired
   onboarding/no-VPN-decision state with direct IPv4 WAN, not a protected
   strict mode. M06's nft `inet` output/forward boundary covers host-stack
   IPv4/IPv6 traffic; `CAP_NET_RAW` link-layer injection, privileged network
   administration/namespaces, non-IP paths and firmware out-of-band traffic
   remain outside that claim.
3. **Hardened host baseline** — 106 static sysctl params + one generated
   durable parameter for the selected physical interface and event-time
   enforcement on every physical pre-up + 50 shared
   kernel-command-line tokens, plus up to 7 conditional tokens
   (Intel CPU: 5 or AMD CPU: 1 — mutually exclusive — plus NVIDIA GPU: 1,
   LUKS unlock-retry: 1), + a
   134-state module
   policy with 53 effective loadable-module denies +
   SELinux enforcing + custom NoID Privacy SELinux module v1.7 + reviewed
   systemd service hardening drop-ins
   + optional installer-selected LUKS2 + a Secure-Boot-capable Fedora chain
   when firmware Secure Boot is enabled + **vendor-aware firmware posture** (Intel
   ME: one host-side ME-specific control — KT/SOL PCI driver_override=none
   — + 3 opt-in MEI sub-module blocks per Kicksecure-consensus v13, with
   generic IOMMU isolation + core `mei`/`mei_me` kept available for fwupd
   attributes on supported platforms (no fixed HSI level is promised); AMD
   PSP: awareness/docs only — `ccp` remains available for platform-dependent
   crypto/fTPM functions, while generic IOMMU and available fwupd attributes
   do not disable PSP, plus PSB OTP warnings +
   CVE-2025-2884/2021-3764/faulTPM documentation) + USBGuard + AIDE.
4. **Privacy-focused defaults** — NoID Privacy Firefox Hardening v1.0 (derived from arkenfox
   v144.0, MIT — embedded in repo since 2026-04-22) + FPP (Fingerprint
   Protection) + uBlock Origin + provider-compatible system/VPN DNS by
   default (strict global/physical Quad9 when no VPN/private scope is active) + MAC randomization
   + Cookie-isolation (dFPI, Total Cookie Protection) + no project telemetry
   (the two GNOME outbound telemetry settings closed) + Canvas + WebGL
   randomization active.

---

## Out-of-scope attacker classes + use-cases

The following sections enumerate specific threats and use-cases that
are **explicitly out of scope**. Users with these requirements should
use a different tool.

## Physical access attacks

### 1. Full physical seizure + forensic tooling
Attacker takes the device, images the disk, submits to a forensics lab
with commercial tools (Cellebrite, GrayKey, X-Ways).

**Why out of scope**: when the user selects disk encryption, the current
release expects LUKS2 AES-XTS with two AES-256 keys and an Argon2id passphrase
keyslot. The actual container, cipher and active keyslot KDF must be verified
on the installed system. Offline resistance then depends strongly on
passphrase entropy and those observed parameters. Encryption is not selected
or verified merely by booting the live image, and this is not an amnesic
system: the installed disk retains state.

### 2. Evil-maid on the EFI partition or GRUB
Attacker has brief physical access while the system is running or in
suspend, modifies `/boot/efi/EFI/*`, injects malicious bootloader, waits
for user to boot (unlocks LUKS → captures passphrase).

**Why out of scope**: Secure Boot + lockdown=integrity + module signing
make this harder but not impossible. An attacker who can flash the
motherboard BIOS or substitute a signed-but-backdoored Microsoft-CA
shim bypasses this chain. Mitigations that would help: (a) TPM-bound
LUKS keys with PCR measurements tying unlock to firmware+bootloader
state, (b) tamper-evident seals on the device. NoID Privacy does not implement
(a) as a generic default because PCR policy, recovery-key handling,
firmware/update transitions and re-enrollment must be designed and tested for
the exact platform; (b) is an operational procedure outside the image.

### 3. Cold-boot attack on RAM
Attacker with physical access dumps LUKS master key from RAM within
seconds of power-off.

**Why out of scope**: not defended. For highly sensitive data, fully shut down
rather than suspend and retain physical custody until volatile memory has lost
state. A self-encrypting drive is not a substitute for this RAM boundary, and
NoID Privacy makes no universal memory-encryption or cold-boot-resistance claim.

## Firmware-level attacks

### 4. Malicious BIOS/UEFI from factory
OEM ships hardware with a pre-compromised EFI firmware containing
backdoored UEFI drivers that the Secure Boot chain cannot detect.

**Why out of scope**: the host OS cannot establish a trustworthy root below
already-compromised platform firmware. The user necessarily trusts the OEM and
hardware/firmware supply chain beyond what this image can verify.
Mitigations: buy through a reviewed supply chain, apply the exact
manufacturer-signed firmware intended for the platform, and inspect the
platform security attributes that fwupd actually exposes. A published update
checksum authenticates downloaded bytes only under the vendor's signing or
publication trust; it does not prove that the running firmware was never
compromised.

### 5. Intel ME persistent firmware malware
ME firmware is compromised below the OS; no OS-level mitigation catches
it.

**Why out of scope**: the ME mitigation (Module 15, v13
Kicksecure-consensus) reduces
attack surface but does not eliminate a pre-compromised ME. Hardware
mitigations include keeping firmware current and applying the Module 15
hardware checklist. Supported fwupd MEI attributes can expose BootGuard state,
but the overall HSI
level remains hardware-, firmware-, runtime-, and fwupd-version-dependent. See
the installed [Intel ME hardware-layer guide](15-intel-me-hardware-layer.md).

### 6. Compromised SSD firmware
Attacker replaces or modifies SSD firmware to exfiltrate data or
establish persistence below the filesystem.

**Why out of scope**: the host cannot reliably inspect or confine a malicious
storage controller below its command interface. LUKS protects plaintext at
rest when correctly enabled and unlocked only on a trusted host, but it does
not make malicious device firmware trustworthy.

## State-actor and APT threats

### 7. Custom 0-day exploit chain
Attacker with nation-state budget develops a privilege-escalation chain
targeting a specific Module of the image (e.g. a kernel 0-day combined
with a SELinux domain bypass).

**Why out of scope**: the controls may reduce exploitability or persistence
options, but they cannot promise resistance to a tailored zero-day chain. AIDE
and audit logs are after-the-fact signals and can be evaded or modified by a
privileged attacker; they do not guarantee detection before persistence.

### 8. Targeted supply-chain attack on Fedora infrastructure
Fedora's build servers are compromised; malicious packages are signed
by Fedora's legitimate key and published to mirrors.

**Why out of scope**: a malicious package signed and published through trusted
Fedora infrastructure passes this image's normal package-authentication gate.
Fedora's package-level reproducibility work may support investigation, but this
project does not provide an independent Fedora rebuild/attestation layer.

### 9. Targeted supply-chain attack on uBlock Origin
Upstream compromise: attacker releases a malicious uBO XPI.

**Partial defence**: Module 16 pins the image/recovery seed to a specific uBO
release tag and SHA-256, so a force-moved tag cannot redirect the build. Later
versions advance only in a user-started Update All transaction through the
fixed official repository, release digest, structure/identity/compatibility
checks and Firefox's native signature verdict. That moving release channel is
still an explicit upstream trust boundary; local validation cannot prove that
an upstream-authorized release is benign.

(arkenfox is no longer fetched at build time: the NoID Privacy Firefox user.js
was absorbed 2026-04-22 and is shipped as an in-repo derivative work
of v144.0. Future version bumps require an explicit in-repo refresh +
review, not an automatic upstream fetch. Thunderbird follows the same local
derivative contract for its tagged HorlogeSkynet v140.2 basis; Update All
reapplies local NoID Privacy bytes and never imports either upstream `user.js`.)

## Application-layer threats

### 10. Malicious Wayland compositor / compromised GNOME Shell
A compromised GNOME Shell extension or compositor can observe or manipulate
the graphical session. Ordinary Wayland clients do not automatically receive
global capture privileges, but trusted portals and input/capture grants remain
security boundaries.

**Why out of scope**: GNOME Shell extensions run in the compositor's session
context; compromising Shell exposes that session. NoID Privacy ships reviewed
extension seeds and disables background extension updates. A user-started
Update All run advances non-RPM system extensions through EGO; EGO does not
provide a cryptographic publisher signature, so this owner-selected convenience
path trusts the fixed EGO identity plus structural and compatibility checks.
Those payloads remain trusted code.

### 11. DNS leak via application bypassing system resolver
Firefox and Thunderbird use the system resolver by default. Without a
more-specific per-link scope, that resolver uses strict authenticated global
Quad9 DoT and fails closed when TLS cannot be used. The user can explicitly
select opportunistic global + physical transport for VPN/captive-portal
compatibility, which permits downgrade to DNS/53, or plaintext recovery mode.
VPN/private `~.` link DNS is deliberately provider-neutral and takes
precedence. NoID Privacy does not rewrite those profiles: an unset
`connection.dns-over-tls` inherits the image's generic `opportunistic`
connection default, while an explicit profile value wins. That best-effort mode
tries DoT but permits unauthenticated DNS/53 fallback and is not MITM-resistant.
An app with its own bundled resolver—or a user-enabled browser Secure DNS
provider—can bypass the system/VPN resolver path.

**Why out of scope**: per-app DNS bypass is possible and not blocked.
NoID Privacy cannot force an application-controlled resolver through the configured
system DNS path without a separate endpoint allow-list, which is not shipped.

## Sociotechnical threats

### 12. Coercion to unlock
User is compelled (legally or physically) to unlock the device.

**Why out of scope**: no OS protects against a user who unlocks their
own disk. Mitigation: duress passphrase features (cryptsetup
`--header` + spare key) are a manual workflow outside the image scope.

### 13. Phishing / social engineering
User enters credentials into a phishing page that looks legitimate.

**Partial defence**: Firefox + uBlock filter lists and Quad9's malware-blocking
resolver can reject some known malicious destinations. Firefox credential
saving is disabled by the project policy, but Thunderbird and an explicitly
used external password manager remain separate credential stores. These
controls do not recognize every phishing site; user verification is required.

### 14. Maliciously crafted media file
PDF, video, image with an embedded exploit targeting the renderer.

**Partial defence**: Flatpak sandboxing for media apps; Firefox
sandboxing for web media. But if the user opens a file with a host-
native tool (e.g. `xdg-open` → `papers`), no extra isolation applies.

## Operational non-scope

### 15. Unattended daily-driver data loss
User makes a mistake — `rm -rf`, pours coffee on the laptop, LUKS key
forgotten.

**Not in scope**: backups are the user's responsibility. NoID Privacy ships
Btrfs root-subvolume snapshots (when the required layout exists) which aid
system rollback but do not snapshot the separate `/home` subvolume and are not
a backup (same disk = single point of failure). Use external 3-2-1
backups for data safety.

### 16. Regulatory compliance (HIPAA, PCI, FedRAMP)
NoID Privacy does not claim compliance with any regulatory framework.

**Not in scope**: compliance is the deployer's problem. The image
provides documented controls that may *simplify* part of a compliance project but
does not substitute for the accreditation work.

---

## TL;DR

NoID Privacy Workstation is a **LAN-isolated, WAN-client-oriented Fedora 44
daily-driver**, subject to documented DHCP/EAPOL/standard-ARP, explicit-peer and
firmware-OOB boundaries. It
raises the bar for passive surveillance, commodity malware, local LAN
attackers, USB attack devices, and fingerprinting. It is **not**:

- A classified-data workstation.
- An amnesic live system (use Tails).
- A compartmented security kernel (use Qubes).
- A forensically-resistant device (use dedicated cold-storage + travel
  laptops).
- A system that promises resistance to tailored state-actor exploit chains.

Choose the right tool for the threat model you're actually facing.
NOID_SCOPE_DOC_EOF
publish_doc "$SCOPE_DOC"

# Generated from docs/post-quantum-readiness.md by
# scripts/regen-product-boundary-docs.sh.
PQ_DOC="$DOC_DIR/post-quantum-readiness.md"
DOC_TMP=$(mktemp "$DOC_DIR/.post-quantum-readiness.md.XXXXXXXX")
cat > "$DOC_TMP" <<'NOID_PQ_DOC_EOF'
# Post-Quantum Cryptography (PQC) Readiness — NoID Privacy Workstation

**Package and standards evidence last verified**: 2026-08-02. The observed
Fedora 44 environment used OpenSSH 10.2p1, OpenSSL 3.5.7, OpenVPN 2.7.5,
Firefox 153, Thunderbird 152, NSS 3.125, and GnuPG 2.4.9. This dated snapshot
supports the assessment below but is not an exact v1.7 ISO package manifest;
Fedora packages remain updateable.

**Endpoint probe observations last rerun**: 2026-08-02. They are deliberately
dated separately because remote endpoint support can change without a local
package or source change.

**Purpose**: document which NoID Privacy transports can negotiate a
post-quantum hybrid, which ones remain classical, and how to verify the result
instead of inferring it from a client setting.

## Threat model

A sufficiently capable cryptographically relevant quantum computer (CRQC)
would break the integer-factorisation and discrete-log assumptions behind RSA,
finite-field DH, and ECC (including X25519 and Ed25519). NIST says that nobody
knows when such a machine will exist; estimates range from a few years to a few
decades. There is no “2030–2040 NIST consensus.”

The present concern is *harvest now, decrypt later* (HNDL): an adversary can
record classically protected traffic now and attack its public-key exchange
later. Rotating an ephemeral X25519 key quickly provides forward secrecy
against later theft of a long-term key, but it does **not** make a recorded
X25519 exchange resistant to a future CRQC. Confidentiality lifetime and the
actually negotiated key exchange matter.

Symmetric cryptography is affected differently. Generic quantum key search is
commonly modelled as reducing an ideal 256-bit key to roughly 128-bit work. It
does not give the exponential break that Shor's algorithm gives RSA and ECC.

## Current coverage

### SSH transport — hybrid preferred, classical fallback retained

Module 09 configures both the SSH client and the opt-in SSH server template:

```text
KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256@libssh.org,curve25519-sha256
```

- `mlkem768x25519-sha256` combines FIPS 203 ML-KEM-768 with X25519 and
  became OpenSSH's default in 10.0.
- `sntrup761x25519-sha512@openssh.com` is the older hybrid fallback available
  in OpenSSH 9.x.
- the two Curve25519 entries are compatibility fallbacks and are
  classical-only.

An SSH session is hybrid-protected only when the negotiated algorithm is one
of the first two entries. The image does not claim that every peer supports
them. The `openssh-server` package is excluded from the image and
`sshd-unix-local.socket` is additionally masked. If the user installs the
server package, Fedora's preset can enable `sshd.service`; follow the installed
`ssh-server-opt-in.md` procedure immediately to keep every listener closed
until the hardened configuration and first public key are ready.

### LUKS2 disk encryption — symmetric boundary

When encryption is selected, the current release expects LUKS2 with
`aes-xts-plain64`, a 512-bit combined XTS key (two AES-256 keys), and an
Argon2id passphrase keyslot. Those are installed-state claims: identify the
root mapping and verify the active keyslot with `cryptsetup luksDump` rather
than inferring the KDF from `lsblk` or the image defaults.

- AES-256 is not vulnerable to Shor's public-key break; the conservative
  generic quantum-search estimate is roughly 128-bit work.
- Argon2id raises the cost of passphrase guessing, but the passphrase's entropy
  and the actual LUKS parameters remain essential. “Memory-hard” is not a
  promise that quantum computation can provide no advantage.
- LUKS is an at-rest symmetric-encryption boundary, not a PQ public-key
  transport. A copied disk image can still be attacked offline.

Accordingly, the configuration has a strong symmetric post-quantum margin,
but the project does not label disk compromise “zero risk” or “fully quantum
safe.”

### Firefox and Thunderbird TLS — hybrid-capable, peer-dependent

NSS 3.105 added `mlkem768x25519` support; NSS 3.118 made it the default group.
NoID Privacy also sets `security.tls.enable_kyber=true` explicitly in the
Firefox and Thunderbird profiles so the intended client capability does not
depend only on an upstream default. The historical preference name still says
“kyber”; current NSS negotiates `X25519MLKEM768`, which combines the
FIPS 203-standardized ML-KEM with X25519. RFC 9954 defines the generic TLS 1.3
hybrid-key-exchange encoding, while the concrete `X25519MLKEM768` group
specification remains an IETF Internet-Draft as of the verification date.

This establishes **client capability**, not endpoint coverage. A connection is
hybrid-protected only if the peer supports the group and the TLS handshake
actually selects it. Otherwise TLS can fall back to classical X25519 or another
classical group.

On 2026-08-02, a direct OpenSSL 3.5 probe restricted to
`X25519MLKEM768` succeeded against the Cloudflare PQ test endpoint. Quad9's
two documented IPv4 DoT addresses showed session-dependent behavior: the
primary address completed `X25519MLKEM768` in two of six hybrid-only sessions
and rejected the other four handshakes. The secondary address rejected all six
hybrid-only sessions. A separate unrestricted session to the secondary address
nevertheless negotiated `X25519MLKEM768`. This establishes that some observed
Quad9 sessions can negotiate the hybrid group. It does not establish consistent
endpoint-wide support. These are dated endpoint observations, not a claim about
all Cloudflare or Quad9 sessions; the verification commands below are the source
of truth for a later release.

ECH is a separate property. Enabling ECH in Firefox hides the inner ClientHello
and SNI only where Firefox obtains a valid ECH configuration and the connection
successfully negotiates ECH. A preference alone does not hide every SNI.

## Upstream- and peer-dependent gaps

### WireGuard and provider VPNs

WireGuard's handshake remains based on Curve25519. NoID Privacy has not found a
standardised, interoperable WireGuard PQ mode in the upstream protocol as of
the verification date. Frequent WireGuard handshakes do not remove HNDL risk
for recorded classical exchanges. WireGuard's optional preshared key can add a
strong symmetric layer only when it is independently generated, exchanged and
protected correctly; it is not a standardised PQ public-key handshake or a
reason to advertise every provider tunnel as PQ-protected.

OpenVPN 2.7 with OpenSSL 3.5 can restrict the TLS control-channel group to
`X25519MLKEM768`, but **both peers must support it**. Installing those versions
or selecting “OpenVPN” in a provider GUI does not prove that a provider endpoint
negotiated the group. NoID Privacy therefore does not present any provider's
OpenVPN mode as a verified PQ alternative; inspect the exact OpenVPN connection
log for the negotiated key agreement.

The data channel uses symmetric encryption, but its traffic keys are delivered
through the control channel. A classical control-channel exchange remains
relevant to HNDL.

### Tor

Tor's short-lived classical circuit keys are not a PQ substitute: a future CRQC
could attack the public values in a recorded circuit handshake. Tor may still
be useful for routing anonymity, but layering Tor over WireGuard does not make
either classical key exchange post-quantum secure. End-to-end hybrid TLS can
independently protect application payloads where the destination supports it.

### OpenPGP email

RFC 9980, published as an IETF Proposed Standard in June 2026, defines
PQ/traditional composite algorithms for OpenPGP. Standardisation is not an
implementation guarantee: the installed Fedora 44 GnuPG 2.4.9 reports no
Kyber/PQ public-key algorithm, while upstream GnuPG 2.5 does. The system
Thunderbird/GnuPG workflow must not be assumed to interoperate with RFC 9980
keys until its installed versions document and demonstrate support.

Upstream declared GnuPG 2.4 end-of-life on 2026-06-30. Fedora 44 still
delivered 2.4.9 on the verification date, so keep the Fedora package fully
updated and track the distribution's migration rather than silently replacing
it with an unreviewed third-party build. Upstream 2.5 capability alone still
does not prove Thunderbird interoperability with RFC 9980 keys.

Proton Mail began a gradual, provider-specific PQ OpenPGP rollout in May 2026.
That is a useful option for eligible Proton Mail accounts, but it does not make
the generic Thunderbird/GnuPG path PQ-capable and does not by itself establish
interoperability with arbitrary OpenPGP correspondents.

Long-lived, public-key-encrypted mail remains a high-priority HNDL concern. Do
not promise that old archives can simply be made safe later: an adversary may
already possess the original ciphertext.

### Secure Boot, MOK, and RPM signatures

The platform Secure Boot chain, Fedora shim/kernel signatures, the optional
NVIDIA MOK workflow, and Fedora RPM signatures use classical public-key
signatures. Their exact algorithms and key sizes are properties of the
platform and current upstream packages, not a universal constant the image can
replace.

TLS transport, AIDE, Secure Boot lockdown, and signed repositories are useful
defence-in-depth today, but they do not convert a classical signature into a PQ
signature. DNF mirror selection is fallback, not independent cross-validation,
and a repository HTTPS connection is hybrid only when its own TLS stack and
selected mirror negotiate a hybrid group.

## Verification

### SSH

After connecting:

```bash
read -r -p 'Exact SSH destination (for example user@host): ' SSH_DEST
if [[ -n "$SSH_DEST" && "$SSH_DEST" != -* && "$SSH_DEST" != *[[:space:]]* ]]; then
    ssh -vv "$SSH_DEST" 2>&1 | grep -F 'kex: algorithm:'
else
    printf 'Invalid SSH destination\n' >&2
fi
```

Expected hybrid result:

```text
debug1: kex: algorithm: mlkem768x25519-sha256
```

`sntrup761x25519-sha512@openssh.com` is also hybrid. A Curve25519-only result
means the session used the documented classical fallback; it does not prove a
particular peer version.

### TLS endpoint probe

With Fedora 44's OpenSSL 3.5:

```bash
read -r -p 'Exact TLS DNS name (without scheme or port): ' TLS_HOST
if [[ "$TLS_HOST" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$ ]] &&
   [[ "$TLS_HOST" =~ [A-Za-z0-9]$ ]] && [[ "$TLS_HOST" == *.* ]] &&
   [[ "$TLS_HOST" != *..* ]]; then
    openssl s_client \
      -connect "${TLS_HOST}:443" \
      -servername "$TLS_HOST" \
      -groups X25519MLKEM768 \
      -brief </dev/null
else
    printf 'Invalid DNS name\n' >&2
fi
```

A successful handshake restricted to that group demonstrates endpoint support
at test time. A failure can also reflect a middlebox or endpoint-specific
configuration. Firefox's own connection can be checked at
<https://pq.cloudflareresearch.com/>; this tests that endpoint and session, not
the whole web.

### OpenVPN

OpenVPN 2.7 reports the selected group in its connection log. Look for a line
containing:

```text
key agreement: X25519MLKEM768
```

For a self-managed deployment, `tls-groups X25519MLKEM768` can make absence of
hybrid support fail closed. Do not inject that option into a provider profile
unless the provider documents support; it can make the connection unusable.

## Maintenance posture

- Re-run the endpoint probes for each release; do not preserve a server-support
  observation as a timeless product claim.
- Track RFC 9980 implementation and interoperability in GnuPG/Thunderbird,
  WireGuard protocol work, and platform/distribution signature migrations.
- Treat package updates as capability changes that require re-verification.
- Preserve classical fallbacks only where interoperability is an explicit
  product requirement, and report when one was negotiated.

## Primary references

- NIST PQC overview and CRQC timing uncertainty:
  <https://www.nist.gov/cybersecurity-and-privacy/what-post-quantum-cryptography>
- NIST FIPS 203 (ML-KEM): <https://csrc.nist.gov/pubs/fips/203/final>
- OpenSSH PQ status (`mlkem768x25519-sha256` default in 10.0):
  <https://www.openssh.org/pq.html>
- NSS 3.105 release notes (ML-KEM support):
  <https://firefox-source-docs.mozilla.org/security/nss/releases/nss_3_105.html>
- NSS 3.118 release notes (ML-KEM hybrid default):
  <https://firefox-source-docs.mozilla.org/security/nss/releases/nss_3_118.html>
- IETF RFC 9954 (Hybrid Key Exchange in TLS 1.3):
  <https://www.rfc-editor.org/rfc/rfc9954.html>
- IETF TLS ECDHE-MLKEM group draft:
  <https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/>
- IETF RFC 9980 (Post-Quantum Cryptography in OpenPGP):
  <https://datatracker.ietf.org/doc/rfc9980/>
- GnuPG upstream 2.5 Kyber capability example:
  <https://lists.gnupg.org/pipermail/gnupg-users/2026-April/068248.html>
- GnuPG upstream branch/EOL status:
  <https://gnupg.org/blog/20250827-new-repository.html>
- OpenVPN PQ test guidance:
  <https://community.openvpn.net/PQCryptoOpenVPN/>
- WireGuard protocol: <https://www.wireguard.com/protocol/>
- Proton Mail's provider-specific gradual PQ rollout:
  <https://proton.me/blog/introducing-post-quantum-encryption>

## See also

- [`docs/threat-model.md`](threat-model.md)
- [`docs/scope.md`](scope.md)
- [`docs/35-thunderbird-smartcard.md`](35-thunderbird-smartcard.md)
NOID_PQ_DOC_EOF
publish_doc "$PQ_DOC"

# Generated from docs/performance-profile.md by
# scripts/regen-product-boundary-docs.sh.
PERFORMANCE_PROFILE_DOC="$DOC_DIR/performance-profile.md"
DOC_TMP=$(mktemp "$DOC_DIR/.performance-profile.md.XXXXXXXX")
cat > "$DOC_TMP" <<'NOID_PERFORMANCE_PROFILE_DOC_EOF'
# Performance profile and measurement boundary

NoID Privacy changes kernel command-line options, sysctls, service activation,
audit rules, SELinux policy, I/O behavior and scheduled integrity work. Those
changes can improve idle behavior in one workload and reduce throughput in
another. The project has not published a controlled benchmark set comparing
stock Fedora with NoID Privacy, so this document does not invent percentages,
boot seconds or memory savings.

## Likely cost centers

- Kernel memory-initialization options `init_on_alloc` and `init_on_free`
  zero newly allocated and freed memory, adding work on allocation-heavy
  paths. `slab_nomerge` deliberately gives up some allocator cache merging
  for heap-layout isolation, so its memory/performance effect is
  workload-dependent. No global `slab_debug` option is enabled.
- Strict IOMMU behavior can reduce I/O throughput or increase CPU work on some
  devices and drivers.
- CPU-vulnerability mitigations vary substantially by CPU generation,
  microcode, kernel and workload.
- SELinux and audit rule evaluation add access/syscall-path work. Volume rises
  with build systems, package transactions and other fork/file-heavy tasks.
- AIDE is scheduled rather than continuous, but its filesystem scan consumes
  CPU and storage bandwidth while active.
- Privacy DNS/TLS layers and firewall policy evaluation can add latency, but
  WAN/provider conditions usually dominate interactive network measurements.

## Likely savings or idle reductions

- Masked or disabled background services cannot consume resources while they
  remain inactive.
- Disabled automatic package/firmware polling removes those scheduled wakeups.
- zram can avoid slower disk swap under memory pressure, with a CPU/compression
  trade-off.
- Hardware-specific I/O scheduler choices may help or hurt depending on the
  device, kernel and workload; NoID Privacy therefore leaves scheduler
  selection with Fedora, the block driver and the kernel.

Bluetooth, location, printing/discovery, smartcard, indexing and similar
features are deliberately constrained or off by default. Their absence is a
functional/privacy decision, not a performance claim.

## Module 27 ownership

Module 27 is the existing hardware/performance boundary; a second performance
module would duplicate ownership. Its default policy is deliberately small:

- Fedora's `systemd-udev` rule and the kernel select I/O schedulers. No
  `/etc/udev/rules.d/60-noid-iosched.rules` override is shipped.
- Fedora's `zram-generator-defaults` package owns zram size, compression and
  priority. No NoID Privacy zram configuration override is shipped.
- The kernel plus Fedora's `tuned`/`tuned-ppd` stack own CPU boost, EPP and
  governor behavior. No unconditional Intel HWP dynamic-boost write is shipped.
  `noid-balanced` and `noid-balanced-battery` inherit Fedora's corresponding
  profiles and disable only their invalid attempt to reload
  `cpufreq_conservative`, which Fedora 44 builds into the kernel.
- M02 remains security/privacy-only. M27 does not add BBR, a qdisc, socket
  ceilings, swappiness, swap readahead, writeback, block read-ahead or a
  command-line/initramfs performance setting.

M27 still owns explicitly documented functional or stability choices:
earlyoom as the image's process-level low-memory policy, physical-wired-NIC
Wake-on-LAN disable, UDisks `noexec` defaults for USB/SD storage, a scoped
`ntfs3,ntfs` driver order for external NTFS, and the hardware-conditional
thermald decision. EEE remains with Fedora, each driver and the link partner
because systemd 259's legacy 32-bit EEE ioctl cannot represent modern link
modes safely. The external-storage policy covers sticks and USB SSDs/HDDs
regardless of the unreliable removable bit. Blanket `sync` was removed after
VFAT/exFAT/NTFS/ext4 testing showed its large performance cost; mount(8) also
says it may shorten limited-write media life. UDisks filesystem defaults still
merge in (`flush` on vfat). Neither `noexec` nor NTFS driver selection changes
the device-cache view or replaces eject/power-off, and an explicit allowed
`exec` request can override the default. No BDI throttle or `queue/write_cache`
mutation is shipped. These choices are verified as behavior and carry their
own trade-off; they are not advertised as universal throughput improvements.

## Supported user-selected performance surface

Use GNOME Settings → Power → Power Mode. Fedora's `tuned-ppd` translates that
selection to the configured tuned profile. The public choices remain
`Balanced`, `Performance` and `Power Saver`; the internal `noid-balanced`
names only remove the inapplicable module reload and do not add a CPU-policy
writer. `Balanced` remains the normal baseline; the other two are explicit
user choices and can change throughput, responsiveness, power draw,
temperature and fan behavior.

Verify the effective selection with:

```bash
busctl get-property net.hadess.PowerProfiles /net/hadess/PowerProfiles \
  net.hadess.PowerProfiles ActiveProfile
tuned-adm active
tuned-adm verify --ignore-missing
systemctl is-active tuned.service tuned-ppd.service
```

`--ignore-missing` is TuneD's native verification mode for settings that the
current hardware or driver does not expose. It still rejects a different value
for every exposed setting. This matters, for example, on Intel `intel_pstate`
systems where TuneD can apply Fedora's `boost=1` through the global
`no_turbo=0` control even though no per-policy `boost` file exists to read
back.

NoID Privacy does not ship BBR/fq as a hidden or default optimization. Network
congestion control is route, RTT, loss, workload and VPN-transport dependent;
changing it can also change externally observable traffic behavior. Any future
network profile needs a separate explicit privacy decision and retained
no-VPN, WireGuard and OpenVPN measurements.

## Measure the installed system

Record the exact image/source revision, firmware, kernel, microcode, power
profile, thermal state and workload before comparing results. At minimum:

```bash
cat /etc/noid-build-info
uname -r
lscpu
systemd-analyze time
systemd-analyze blame
systemctl --failed
free -h
swapon --show
```

For a meaningful A/B comparison:

1. Use the same machine, firmware settings, power source and storage.
2. Compare against the Fedora 44 package/kernel versions represented by the
   compose, not an unrelated newer installation.
3. Reboot between states, warm or cold caches consistently, and repeat enough
   times to report variation rather than one favorable result.
4. Measure the actual target workload (build, database, browser, media, VM or
   ML job) and keep thermal throttling visible.
5. Change one hardening control at a time, document the security cost, and use
   the module's supported escape hatch where one exists.

Do not disable SELinux, audit, IOMMU, CPU mitigations or memory hardening based
on a generic percentage from another machine. If performance is a release
criterion, add the reproducible benchmark and raw results to the release
evidence rather than converting an expectation into a README claim.
NOID_PERFORMANCE_PROFILE_DOC_EOF
publish_doc "$PERFORMANCE_PROFILE_DOC"

# Generated from LICENSING.md by scripts/regen-product-boundary-docs.sh.
LICENSING_DOC="$DOC_DIR/licensing.md"
DOC_TMP=$(mktemp "$DOC_DIR/.licensing.md.XXXXXXXX")
cat > "$DOC_TMP" <<'NOID_LICENSING_DOC_EOF'
# NoID Privacy Workstation — Licensing Overview

This file is a human-readable summary of how the repository is licensed. The
canonical license for NoID Privacy's own code and machine-readable policy is
GNU General Public License v3 or later in the repository-root `COPYING`, except
for the exact file-level exceptions inventoried below.

This is a multi-license repository. Different categories of content are
released under different licenses, summarized below:

  1. NoID Privacy's own code/policy ........ GPL-3.0-or-later
  2. NoID Privacy documentation ............ CC-BY-SA-4.0
  3. Third-party/separate code ............. exact license listed below
  4. Branding assets ....................... license listed per asset below

Each third-party component retains its own upstream license. The full text
of the GNU General Public License v3 is in the `COPYING` file at the
repository root.

================================================================================
TRADEMARK NOTICE
================================================================================

"Fedora" is a registered trademark of Red Hat, Inc. NoID Privacy Workstation
is an independent derivative work built on top of Fedora Linux and is NOT
affiliated with, endorsed by, or sponsored by the Fedora Project or Red Hat,
Inc. Official, unmodified Fedora software is available at
https://fedoraproject.org/.

Other trademarks referenced in this project (GNOME, Red Hat, Flatpak, Firefox,
Thunderbird, etc.) are the property of their respective owners. See
`docs/trademark-notice.md` for full details on the rebranding strategy and
trademark attributions.

The "NoID Privacy" name and original NoID Privacy branding assets in `branding/`
(logo, plymouth theme, app icons, avatar) are the exclusive property of the
NoID Privacy project. ALL RIGHTS RESERVED. They are NOT covered by the GPL
or CC BY-SA licenses below. Redistribution of the branding assets — or use
of the "NoID Privacy" name — as part of a different or modified distribution
requires explicit written permission.

The default wallpaper (`branding/wallpaper.png` + `branding/wallpaper-dark.png`,
deployed to `/usr/share/backgrounds/noid-privacy/default{,-dark}.png`) is GNOME's
`drool-l` / `drool-d` artwork from the `gnome-backgrounds` package
(<https://gitlab.gnome.org/GNOME/gnome-backgrounds>), licensed under
**CC-BY-SA-3.0**. Attribution is required for redistribution; derivative
works must use the same license.

================================================================================
1. NoID Privacy's own code and machine-readable policy
================================================================================

GNU General Public License, version 3 or later (GPL-3.0-or-later)

Copyright (C) 2026 NoID Privacy contributors

This category includes:

  - `kickstart/`, `scripts/`, `manifests/`, and `tests/` except
    `tests/README.md`
  - NoID Privacy-owned non-Markdown repository/CI configuration (`.gitattributes`,
    `.gitignore`, `.github/*.yml`, `.github/workflows/*.yml`)
  - `branding/SHA256SUMS` and `branding/icons/regenerate-icons.sh`
  - `overrides/noid-lan-xdp/noid-lan-xdp.sh`
  - `thunderbird/autoconfig.js`, `thunderbird/local-settings.js` and
    `thunderbird/mozilla.cfg`
  - NoID Privacy override sections in
    `thunderbird/noid-thunderbird-hardening.js` (the embedded upstream base is
    MIT; see section 3)

It excludes the separately licensed Lorax patches, Anaconda Live-source
derivative, XDP BPF source/object, Firefox derivative, vendored upstream
subtree, upstream license texts, documentation and branding assets listed
below.

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program. If not, see <https://www.gnu.org/licenses/>. The full license
text is also included in the `COPYING` file at the repository root.

================================================================================
2. NoID Privacy documentation
================================================================================

Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0)

This category includes the NoID Privacy-owned root Markdown files (`README.md`,
`INDEX.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
`SECURITY.md`, `AGENTS.md`, `LICENSING.md`), `docs/`, `tests/README.md`,
`.github/ISSUE_TEMPLATE/*.md`, `.github/pull_request_template.md`,
`overrides/noid-lan-xdp/README.md`, and Markdown shipped as user-facing
documentation from a Kickstart heredoc. It does not relicense third-party
notices or source code merely because those files use Markdown.

You are free to:
  - Share — copy and redistribute the material in any medium or format
  - Adapt — remix, transform, and build upon the material for any purpose,
    even commercially.

Under the following terms:
  - Attribution — You must give appropriate credit, provide a link to the
    license, and indicate if changes were made.
  - ShareAlike — If you remix, transform, or build upon the material, you must
    distribute your contributions under the same license as the original.

Full legal code: https://creativecommons.org/licenses/by-sa/4.0/legalcode

================================================================================
3. Third-party and separately licensed source — exact licenses retained
================================================================================

NoID Privacy derives, bundles, or vendors the following third-party components. Each
retains its own upstream license; where content is embedded in a NoID Privacy file,
the upstream notice is retained in-file.

--- REPOSITORY SOURCE WITH A FILE-LEVEL LICENSE EXCEPTION ---

  - Lorax monitor shutdown-drain patch — GPL-2.0-or-later
    `overrides/lorax/0001-drain-monitor-before-shutdown.patch` modifies
    Fedora Lorax's `pylorax/monitor.py`, whose header grants GPL version 2 or
    any later version. The patch retains that license rather than inheriting
    NoID Privacy's GPL-3.0-or-later default.

  - Lorax Live required-space compose patch — GPL-2.0-or-later
    `overrides/lorax/0002-precompute-live-required-space.patch` modifies
    Fedora Lorax's `pylorax/creator.py`, whose header grants GPL version 2 or
    any later version. The patch retains that license rather than inheriting
    NoID Privacy's GPL-3.0-or-later default.

  - Lorax cancelled-process cleanup patch — GPL-2.0-or-later
    `overrides/lorax/0003-terminate-cancelled-process.patch` modifies Fedora
    Lorax's `pylorax/executils.py`, whose header grants GPL version 2 or any
    later version. The patch retains that license rather than inheriting the
    NoID Privacy GPL-3.0-or-later default.

  - Lorax Live boot-menu defaults patch — GPL-2.0-or-later
    `overrides/lorax/0004-live-menu-default.patch` modifies Fedora Lorax
    template files `live/config_files/x86/grub2-{bios,efi}.cfg`, distributed
    by `lorax-templates-generic` under GPL-2.0-or-later. The patch retains that
    license rather than inheriting the NoID Privacy GPL-3.0-or-later default.

  - Anaconda Live OS initialization derivative — GPL-2.0-or-later
    `overrides/anaconda/live-os-initialization.py` modifies Fedora Anaconda's
    `pyanaconda/modules/payloads/source/live_os/initialization.py`, whose
    retained header grants GPL version 2 or any later version. Its generated
    copy inside `kickstart/snippets/17-gnome-hardening.ks` retains the same
    notice; GPL-2.0-or-later permits that combined Kickstart payload to be
    distributed under this project's GPL-3.0-or-later choice.

  - NoID Privacy physical-link XDP BPF program — GPL-2.0-only
    `overrides/noid-lan-xdp/noid-lan-xdp.bpf.c` carries the exact SPDX
    identifier and is the corresponding source for the committed
    `noid-lan-xdp.bpf.o.b64` object. The controller shell script remains
    GPL-3.0-or-later and its README remains CC-BY-SA-4.0.

    The complete GNU GPL version 2 text used by these exceptions is retained
    at `licenses/GPL-2.0.txt`.

--- DERIVED (modified upstream sources, embedded in NoID Privacy's own files) ---

  - arkenfox user.js v144.0 — MIT
    https://github.com/arkenfox/user.js
    Basis of `firefox/noid-firefox-hardening.js` (NoID Privacy Firefox Hardening),
    embedded into M16 as a gzip+base64 blob via
    `scripts/regen-firefox-embed.sh`. The exact tag `144.0` notice (commit
    `bb45863be796d331717e2b5d6e490f0d3e3cf93f`, SHA-256
    `2bf289bdd22188ccff2bf34c9a20a75c45b84f42f887da7e177d9bfd1bac3c1a`)
    is retained in-file and at `licenses/arkenfox-user.js-MIT.txt`, then
    installed to `/usr/share/licenses/noid-privacy/`. The combined Firefox
    derivative carries both upstream and NoID Privacy copyright notices and is
    distributed under MIT so it has one unambiguous file-level license.

  - HorlogeSkynet thunderbird-user.js v140.2 — MIT
    https://github.com/HorlogeSkynet/thunderbird-user.js
    Basis of `thunderbird/noid-thunderbird-hardening.js` (NoID Privacy Thunderbird
    Hardening), embedded into M35 as a gzip+base64 blob via
    `scripts/regen-thunderbird-embed.sh`. The exact annotated tag `v140.2`
    notice (commit `556709d1a4beced21f9888fb9b55dd623b415008`, SHA-256
    `e0bfbe5467925aa73c30bb5d7e9e23fef1a2f6285b0c5dd62a5c7ab091fc5331`)
    is retained in-file and at
    `licenses/horlogeskynet-thunderbird-user.js-MIT.txt`, then installed to
    `/usr/share/licenses/noid-privacy/`. That combined file explicitly marks
    the HorlogeSkynet base as MIT and NoID Privacy override sections as
    GPL-3.0-or-later.

--- BUNDLED / FETCHED AT BUILD TIME (pinned release tag or reviewed source
    revision + SHA256 verified; installed into the built image, not stored in
    this repository) ---

  - uBlock Origin (XPI) — GPL-3.0-or-later
    https://github.com/gorhill/uBlock
  - DKIM Verifier v6.3.0 (XPI) — MIT/X11
    https://github.com/lieser/dkim_verifier
  - Just Perfection GNOME Shell extension v36 — GPL-3.0-only
    https://gitlab.com/l3nn4rt/just-perfection-gnome-shell-desktop
    M17 downloads the GNOME Extensions release archive by exact version,
    byte count and SHA-256, validates its closed tree, and installs the
    extension system-wide. Upstream declares the extension GPL-3.0-only;
    downstream redistribution must preserve the applicable license notices
    and corresponding-source obligations.
  - NoID Privacy for Linux (`noid-privacy-linux.sh`) — GPL-3.0-or-later
    https://github.com/NexusOne23/noid-privacy-linux
    A sibling NoID Privacy project, bundled by M40 as the `noid-audit` companion.

--- THIRD-PARTY RPM REPOSITORY PACKAGES ---

  - VSCodium (`codium` RPM) — MIT, with bundled third-party notices
    https://github.com/VSCodium/vscodium
    M08 installs the vendor-built RPM from VSCodium's separately configured
    repository after pinning its signing-key fingerprint. It is not a Fedora
    package. The installed RPM metadata and its shipped license/notice files
    remain the authority for the exact package version in an image.

--- DESIGN-TIME TOOLS (not vendored, not shipped) ---

  - kernel-hardening-checker (Alexander Popov) — GPL-3.0-only
    https://github.com/a13xp0p0v/kernel-hardening-checker
    A build-/design-time tool used to review kernel hardening configuration.
    It is run from its own upstream checkout. No part of it is stored in this
    repository or installed into the image, so it carries no NoID Privacy
    derivative and imposes no distribution obligation here. The attribution is
    kept because its findings informed M01/M02 hardening decisions.

--- LICENSE TEXTS AND NOTICES ---

  - `COPYING`, `licenses/GPL-2.0.txt`,
    `licenses/arkenfox-user.js-MIT.txt`, and
    `licenses/horlogeskynet-thunderbird-user.js-MIT.txt` retain exact license
    or notice text for the corresponding works. Including those texts does not
    relicense them as NoID Privacy documentation.

--- DISTRO PACKAGES ---

  Fedora packages installed via kickstart `%packages` (and shipped inside the
  built ISO) retain their respective upstream licenses (most commonly GPL,
  LGPL, MIT, BSD, Apache — see Fedora Package Licensing guidelines). The built
  ISO is an **independent derivative work based on Fedora 44** (not a Fedora
  Remix — see `docs/trademark-notice.md` for the canonical positioning per
  Fedora Trademark Guidelines). Redistributing the ISO carries the corresponding-
  source obligations of the GPL/copyleft packages it contains (Fedora mirrors
  provide the matching source).

================================================================================
4. Branding assets
================================================================================

The "NoID Privacy" name and original NoID Privacy artwork are not covered by
the software or documentation licenses above. The project reserves all rights
to these assets:

  - `branding/noid-privacy-logo.png`
  - `branding/noid-privacy-logo-512.png`
  - `branding/noid-privacy-avatar-*.png`
  - `branding/plymouth/*.png`
  - `branding/icons/noid-privacy-*.png`

The Firefox Playground launcher references the unmodified `firefox` icon
installed by Fedora's Firefox package through standard icon-theme lookup; this
repository does not ship a copy or modified derivative of Mozilla's Firefox
logo. The generator (`branding/icons/regenerate-icons.sh`) and integrity manifest
(`branding/SHA256SUMS`) are project code/policy under GPL-3.0-or-later as
listed in section 1, not proprietary artwork.

The default wallpapers are a separate upstream exception:

  - `branding/wallpaper.png`
  - `branding/wallpaper-dark.png`

They are GNOME's `drool-l` / `drool-d` artwork from `gnome-backgrounds`,
licensed under CC-BY-SA-3.0:
https://gitlab.gnome.org/GNOME/gnome-backgrounds

Attribution is required for redistribution; derivative wallpaper works must
use the same license. The asset integrity manifest records bytes only and does
not change the license of any listed asset.

================================================================================
ACKNOWLEDGMENTS (design inspiration — NOT copied code)
================================================================================

NoID Privacy's hardening surfaces are independent re-implementations, not verbatim
copies. The following projects and baselines were studied as references and
shaped NoID Privacy's design direction; we gratefully acknowledge their work:

  - secureblue            https://github.com/secureblue/secureblue
  - Kicksecure / security-misc   https://www.kicksecure.com/
  - Kernel Self-Protection Project (KSPP)   https://kspp.github.io/
  - CIS Benchmarks        https://www.cisecurity.org/
  - Mozilla Security / Firefox hardening guidance
  - The arkenfox and HorlogeSkynet user.js projects (also credited above as
    directly-derived sources)

Crediting these projects does not imply their endorsement of NoID Privacy.
NOID_LICENSING_DOC_EOF
publish_doc "$LICENSING_DOC"
log "  [OK] canonical product-boundary documentation written and labeled fail-closed"

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

verify_owned_regular() {
    local path="$1" expected_mode="$2"
    [ -f "$path" ] &&
        [ ! -L "$path" ] &&
        [ "$(stat -Lc '%u:%g:%a:%h' -- "$path" 2>/dev/null)" = \
            "0:0:${expected_mode}:1" ] &&
        matchpathcon -V "$path" >/dev/null
}

# Files exist + min size
for pair in \
    "99-troubleshooting.md:5120" \
    "00-architecture.md:5120" \
    "27-performance.md:3072" \
    "threat-model.md:20000" \
    "scope.md:14000" \
    "post-quantum-readiness.md:9000" \
    "performance-profile.md:5000" \
    "licensing.md:12000"; do
    f="${pair%:*}"
    min="${pair#*:}"
    path="/usr/share/doc/noid-privacy/$f"
    check "$f exists" test -f "$path"
    sz=$(stat -c %s "$path" 2>/dev/null || echo 0)
    sz=${sz:-0}
    check "$f >= ${min} bytes (actual: $sz)" test "$sz" -ge "$min"
    check "$f regular root:root 0644 link-count=1" \
        verify_owned_regular "$path" 644
done

for kw in "systemd-udev" "zram-generator-defaults" \
          "tuned-ppd" "NoID Privacy does not ship BBR/fq" \
          "Measure instead of guessing"; do
    check "27-performance references: $kw" \
        grep -qF -- "$kw" /usr/share/doc/noid-privacy/27-performance.md
done

for mapping in \
    "threat-model.md|scope.md" \
    "threat-model.md|post-quantum-readiness.md" \
    "scope.md|performance-profile.md"; do
    source_doc=${mapping%%|*}
    target_doc=${mapping#*|}
    check "$source_doc links to installed $target_doc" \
        grep -qF -- "]($target_doc)" "/usr/share/doc/noid-privacy/$source_doc"
done
for topic in threat-model scope post-quantum-readiness \
             performance-profile licensing; do
    check "noid-help opens canonical topic: $topic" \
        env PAGER=true /usr/local/bin/noid-help "$topic"
done

# Structural markers — troubleshooting must have decision tree + cross-refs
# Case-insensitive literal grep -Fqi (the robust Lesson #30 pattern).
for kw in "Decision tree" "noid-status" "journalctl" "systemctl --failed" "SELinux" "audit2allow" "AIDE" "Forgot LUKS" "emergency.target" "Reporting a real bug"; do
    check "99-troubleshooting references: $kw" \
        grep -Fqi -- "$kw" /usr/share/doc/noid-privacy/99-troubleshooting.md
done

# Architecture markers — keyword stays GENERIC "Module structure" (a
# hardcoded module-count keyword drifted when modules were added; the
# generic form survives future count changes). grep -Fqi per Lesson #30.
for kw in "Module structure" "Silent-Machine" "Defense in depth" "Neutral image" "Reversibility" "Source-of-truth" "Threat model" "Dependency ordering" "kickstart/snippets/"; do
    check "00-architecture references: $kw" \
        grep -Fqi -- "$kw" /usr/share/doc/noid-privacy/00-architecture.md
done

# References to existing docs (not dead links)
# Case-insensitive literal grep -Fqi (the robust Lesson #30 pattern).
for link in "01-getting-started.md" "00-README.md" "14-usbguard.md" "20-rollback-recovery.md" "28-local-ai.md"; do
    check "cross-ref to existing doc: $link" \
        grep -Fqi -- "$link" \
        /usr/share/doc/noid-privacy/99-troubleshooting.md \
        /usr/share/doc/noid-privacy/00-architecture.md
done

log "Verification: $((checks - fails))/$checks passed"
if [ "$fails" -gt 0 ]; then
    die "$fails verification check(s) FAILED"
fi

# ------------------------------------------------------------------------------
# Phase 7 — Health stamp
# ------------------------------------------------------------------------------
PHASE="P7-stamp"
# M31_HEALTH_PUBLICATION_BEGIN
if [ ! -d "$STAMP_DIR" ] || [ -L "$STAMP_DIR" ] \
   || [ "$(stat -Lc '%u:%g:%a' -- "$STAMP_DIR" 2>/dev/null || true)" != \
        0:0:755 ] \
   || ! matchpathcon -V "$STAMP_DIR" >/dev/null; then
    die "shared health-stamp directory drifted before Module 31 publication"
fi

verify_m31_health_stamp() {
    local path="$1"
    [ -f "$path" ] \
        && [ ! -L "$path" ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' -- "$path" 2>/dev/null || true)" = \
            0:0:644:1 ] \
        && [ "$(wc -l < "$path")" -eq 8 ] \
        && [ "$(grep -c '^module=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^name=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^version=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^status=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^timestamp=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^checks_passed=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^checks_total=' "$path" || true)" -eq 1 ] \
        && grep -qFx '# NoID Privacy — Module 31 Health Stamp' "$path" \
        && grep -qFx 'module=31' "$path" \
        && grep -qFx 'name=user-docs-tier-c' "$path" \
        && grep -qFx 'version=1' "$path" \
        && grep -qFx 'status=ok' "$path" \
        && grep -Eq \
            '^timestamp=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' \
            "$path" \
        && grep -qFx "checks_passed=$((checks - fails))" "$path" \
        && grep -qFx "checks_total=$checks" "$path"
}

STAMP_TMP=$(mktemp "$STAMP_DIR/.stamp-31-user-docs-tier-c.ok.XXXXXXXX")
cat > "$STAMP_TMP" <<STAMP_EOF
# NoID Privacy — Module 31 Health Stamp
module=31
name=user-docs-tier-c
version=1
status=ok
timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
checks_passed=$((checks - fails))
checks_total=$checks
STAMP_EOF

chmod 0644 "$STAMP_TMP"
chown root:root "$STAMP_TMP"
restorecon -F -- "$STAMP_TMP" \
    || die "cannot label Module 31 health-stamp candidate"
matchpathcon -V "$STAMP_TMP" >/dev/null \
    || die "Module 31 health-stamp candidate label differs"
verify_m31_health_stamp "$STAMP_TMP" \
    || die "staged Module 31 health-stamp contract is invalid"
sync -- "$STAMP_TMP" \
    || die "cannot sync Module 31 health-stamp candidate"
if ! mv -fT -- "$STAMP_TMP" "$STAMP"; then
    rm -f -- "$STAMP" || true
    die "cannot publish Module 31 health stamp"
fi
STAMP_TMP=""
STAMP_PUBLICATION_ACTIVE=1
restorecon -F -- "$STAMP" \
    || die "cannot label published Module 31 health stamp"
matchpathcon -V "$STAMP" >/dev/null \
    || die "published Module 31 health-stamp label differs"
sync -- "$STAMP" \
    || die "cannot sync published Module 31 health stamp"
sync -- "$STAMP_DIR" \
    || die "cannot sync Module 31 health-stamp directory"
verify_m31_health_stamp "$STAMP" \
    || die "published Module 31 health-stamp contract is invalid"
STAMP_PUBLICATION_ACTIVE=0
log "  [OK] exact Module 31 health stamp published atomically"
# M31_HEALTH_PUBLICATION_END

trap - EXIT INT TERM
log "=== Module 31 User Documentation Tier C complete ==="
%end

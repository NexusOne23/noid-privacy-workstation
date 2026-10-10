# ============================================================================
# Module 31 — User Documentation Tier C (architecture + troubleshooting + product boundaries)
# Status: LOCKED 2026-10-04 (v99) — synchronize the architecture mask inventory with kernel-tools activation guards.
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
#   - /usr/share/licenses/noid-privacy/{COPYING,GPL-2.0.txt} license texts
#   - /usr/share/noid-privacy/source/noid-lan-xdp/  GPL-2.0 corresponding
#     source of the Module 03 XDP object (source + build script)
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
#     the file is 0640); M08 has exactly 83 source masks and the cross-module
#     unique total is 99. The live count can include Fedora preset masks.
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
# grep -Fqi. Package modifications: NONE.
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
    local target=$1 parent=${2:-$DOC_DIR}
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
    sync -- "$target" "$parent" \
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
# This stamp covers all eight Tier-C and product-boundary documents and the
# two license texts. Validate
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
    systemctl --full status -- "$UNIT"
    sudo journalctl -u "$UNIT" --since today --no-pager | tail -40
else
    printf 'Invalid systemd unit name\n' >&2
fi
```

For a failed user unit, use the same validated name with `systemctl --user
--full status -- "$UNIT"` and `journalctl --user -u "$UNIT" ...`; do not add
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
Show the hidden GRUB menu: press Esc, F4 or F8, or hold Shift, during GRUB's
hidden timeout (right after the firmware logo), then pick the previous kernel
entry.
`installonly_limit=3` keeps the last three kernels installed.

**Step 2 — Text-mode login (`systemd.unit=multi-user.target`).**
The standard path when the desktop or login screen no longer starts:

1. Show the GRUB menu as in Step 1 and press `e` on the default entry.
2. Append ` systemd.unit=multi-user.target` to the `linux ...` line,
   press Ctrl-X.
3. Unlock LUKS, log in at the text console **with your normal user
   account**, and repair via `sudo` — including the checked snapshot
   rollback using an exact snapshot ID:

   ```bash
   (
   set -euo pipefail
   sudo snapper -c root list
   read -r -p 'Exact root snapshot ID to roll back to: ' SNAPSHOT_ID
   if [[ "$SNAPSHOT_ID" =~ ^[1-9][0-9]*$ ]]; then
       sudo noid-snap-rollback "$SNAPSHOT_ID"
   else
       printf 'Invalid snapshot ID\n' >&2
       exit 1
   fi
   )
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
(
set -euo pipefail
lsblk -f
read -r -p 'Exact crypto_LUKS device path: ' LUKS_DEV
test -b "$LUKS_DEV"
sudo cryptsetup isLuks "$LUKS_DEV"
sudo cryptsetup luksDump "$LUKS_DEV"
sudo cryptsetup luksChangeKey "$LUKS_DEV"
)
```

Verify the exact `crypto_LUKS` backing device; do not copy a device name from
another machine. `luksChangeKey` changes one existing keyslot after
authenticating it—it does not rotate the volume key or repair a missing unlock
method. If no valid passphrase, recovery key, keyfile or enrolled token
remains, the volume cannot be unlocked by design. A header backup preserves
metadata and keyslots; it does not reveal or replace a missing unlock secret.

## Accounts and login

### A second user account cannot log in

Interactive logins are limited to members of `wheel` (see
[02-system-security.md](02-system-security.md), "Interactive login is limited
to the `wheel` group"). A standard account created in GNOME Settings → Users is
refused at the login screen and at the text console. An administrator can
admit it with `sudo usermod -aG wheel USERNAME`, which also grants that user
`sudo` rights; there is no non-administrator desktop-user option.

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
ip -4 rule show
ip -6 rule show
ip -4 route show table all default
ip -6 route show table all default
resolvectl status
```

Compare the routing rules, default routes and selected DNS `~.` scope with the current
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
ip -4 rule show
ip -6 rule show
ip -4 route show table all default
ip -6 route show table all default
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

1. **NoID Privacy Setup** (`noid-welcome.sh --again`) → **Hardware Privacy** →
   *Disable Bluetooth* switch
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
3. Only after the helper confirms success, run `sudo reboot` into the rolled-back state

If the system no longer boots to the graphical login, boot to the text
console instead: show the hidden GRUB menu (see "Recovery ladder — Step 1"
above), press `e`, append ` systemd.unit=multi-user.target`, boot with Ctrl-X,
unlock LUKS, log in with your user account, then run the same two commands.
rescue/emergency targets provide no shell on this image — see "Boot-level
problems" above.

## Where to dig deeper

- Per-Module design rationale: header comments of
  `kickstart/snippets/NN-name.ks` in the project repository (not installed)
- Per-Module build logs (`/var/log/ks-NN-name.log`) stay in the compose
  environment: the image build removes them before the Live image is sealed,
  the installed-target transition removes installer logs before the first
  login, and `noid-install-logs-prune.timer` caps the remaining one-shot
  install logs at 30 days; use the journal for runtime events
- Audit log: `sudo journalctl -t noid-audit-notify`, `sudo ausearch`
- `noid-help <topic>` — jump to the topic's user doc
- `noid-help search <keyword>` — grep all user docs

## Reporting a real bug or a security issue

Ordinary bugs: open an issue at
<https://github.com/NexusOne23/noid-privacy-workstation/issues>. **Security
vulnerabilities: do not open a public issue**; report them privately through
the repository's *Security → Advisories → Report a vulnerability* form as
described in the project's `SECURITY.md`. In both cases create evidence
locally first and review/redact it before uploading:

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
  `intel_iommu=on` on Intel (vendor-auto-detected; AMD-Vi needs no token),
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
  `net/ipv6/conf/<wan-iface>/disable_ipv6=1`) while enforcing and verifying
  the live disable on every physical `pre-up`; thus multiple live physical
  interfaces can be disabled even though only one selected identity is
  durable. Verify the live hardening count with
  `sudo grep -cE '^-?[a-z]+\.' /etc/sysctl.d/99-hardening.conf` (the file is
  root-only, mode 0640 — `sudo` is required).
- **21 kernel-module-policy** — 134 normalized identities: 52 canonical
  loadable modules receive dual modprobe enforcement, while 10 built-ins,
  45 absent identities, 2 historical aliases, 23 supported modules and the
  ntfs/ntfs3 alternative pair (whichever NTFS driver Fedora builds) are
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
  CVE-2024-3661 mitigation (IPv6 `ignore-auto-routes` and post-DHCP removal
  of every non-default IPv4 DHCP route; IPv4 keeps its DHCP default route)
- **24 firmware-fwupd** — LVFS remote policy, passim P2P disabled and
  `fwupd-refresh.timer` masked. User-invoked refresh/update remains an explicit
  LVFS network request and leaves ordinary fwupd/journal evidence.

### Identity, auth, integrity (9, 10, 12, 13)
- **09 ssh** — client hardening plus a dormant server-hardening template;
  `openssh-server` is excluded, so no inbound SSH server ships
- **10 pam-login** — pam_access wheel-only interactive login, PAM faillock,
  pwquality, YESCRYPT hashing,
  login.defs UMASK=022 (Fedora default — intentionally NOT 027 per
  Kicksecure security-misc #185, dnf5#1908), five-path native tmpfiles SUID
  reduction with four Fedora load-bearing paths retained,
  coredump 6-layer block
- **12 selinux-auditd** — SELinux enforcing, 132 paired b64/b32 auditd rules (immutable
  via `-e 2`), opt-in auditd/auparse complete-event desktop notifications
  for 16 keyed integrity categories with exact local AUID/session binding,
  custom NoID Privacy SELinux policy module `noid-selinux-fixes`
  (switcheroo nnp_transition, audit-notify sandbox mounton, usbguard userdb
  lookups and logind directory walk, AIDE ESP statfs, Yescrypt HugeTLB work
  area)
- **13 aide** — AIDE configuration, reviewed candidate/commit workflow and a
  daily check timer that remains disabled until an active user-reviewed
  baseline exists; also ships the GTK4/libadwaita Welcome hub + `noid-status`

### Hardware (14, 15, 19, 27)
- **14 usbguard** — USB whitelisting, firstboot emergency→real state
  machine, usbguard-notifier user service
- **15 intel-me** — Intel ME multi-layer mitigation (Kicksecure-consensus,
  security-misc #239): KT/SOL PCI driver_override (27 PCI IDs from 6th-gen
  Skylake through Panther Lake plus Nova/Wildcat Lake candidates and
  Sapphire Rapids W790 — removes host-driver binding only) + mei + mei_me
  loaded for fwupd BootGuard
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
- **08 service-minimization** — 83 systemd units masked in M08 (see
  [08-masked-services.md](08-masked-services.md); the source test pins the
  reviewed count, including the complete modular-libvirt service/socket set).
  M05 adds 8 more (avahi×2, wsdd×2, cups×4), M11 masks
  `systemd-timesyncd.service`, M24 masks `fwupd-refresh.timer` +
  `fwupd-refresh.service` (2 unique to M24; passim.service is masked
  by both M08 and M24 but counted once in M08 A2), M18 masks
  `flatpak-add-fedora-repos.service`, and M21 masks the binfmt automount plus
  registration service. M26 masks `cpupower.service` and `kvm_stat.service`
  → **99 source-
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
  HorlogeSkynet v140.3 snapshot plus AutoConfig (mozilla.cfg + autoconfig.js +
  local-settings.js) + DKIM Verifier XPI pre-installed at
  `/usr/lib64/thunderbird/distribution/extensions/` (no automatic upstream
  user.js import)
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
- Canvas readback on one site → `noid-firefox-relax-fpp --site <domain>` /
  revert via `--site-restore <domain>`
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
- **11b after 11** — M11b imports the DNS/NTP baseline and helper
  cross-references (resolved policy from M05, chrony from M11)
- **34 after 16** — M34 firefox-playground depends on
  `/usr/share/noid-firefox/user.js` shipped by M16
- **41 before 99** — M41 anaconda-cleanup removes liveuser/GDM
  auto-login/sudoers before final artifact verification
- **42 before 99** — M42 installs the shared 30-day retention policy and
  timers before M99 verifies the final artifact state
- **40 any position before 99 and before 37** — audit-bundle is an
  independent supply-chain payload (no inter-module deps beyond M32
  HTTP staging pattern reuse)
- **37 after 40** — M37's build-time curated-helper verification requires
  `noid-audit`, which M40 installs

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
# Selected hardening overview — one screen
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
  (`flush` on vfat). External NTFS prefers Fedora's in-tree `ntfs3`, when the
  running kernel builds it, with ntfs-3g fallback because Fedora 44's current
  ntfs-3g RW path failed on the validation volume. Neither policy alters the
  device-cache state or makes active-I/O unplugging safe: eject/power off
  before disconnecting.
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
| Kernel exploits | Mitigated | 106 static sysctl assignments + one generated durable assignment for the selected physical interface and event-time enforcement on every physical pre-up + a 134-row module inventory (52 effective loadable-module denies, 10 built-in, 45 absent, 2 alias, 23 supported and the 2-member ntfs/ntfs3 alternative pair) + 49 shared kernel-command-line tokens (+ up to 7 conditional: Intel 5 (none on AMD), NVIDIA 1, and one LUKS unlock-retry token per encrypted volume on the reference layout); built-ins and kernel zero-days remain residual risk |
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
traffic and firmware out-of-band paths remain outside M06's claim. So does a
process in the active local session that uses NetworkManager's polkit policy
(`settings.modify.own`, Fedora's local-wheel `settings.modify.system`,
`network-control`) to add a VPN profile or reapply a route: every loaded
profile's literal endpoint becomes an exact durable WAN-strict tuple, so
WAN-strict constrains ordinary sockets, not a session process that
reconfigures NetworkManager. Ordinary unprivileged applications receive none
of those kernel capabilities by default; the three-pass candidate gate
verifies that raw/packet sockets and an nft mutation are rejected for UID
65534.

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
   configured function requires it, including DHCP/ARP and NTS time
   synchronization; DNS diagnostics send a query only when the user runs
   `noid-dns-diagnose probe TARGET`; user-installed applications can add
   their own traffic.
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
    remains blocked. Saved profiles include any profile a process in the active
    session adds through NetworkManager.
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
    targeted excludes that keep the real timezone, colour scheme, window
    size, browser/user-agent identity, keyboard layout, site zoom and system
    locale (see the `[SECTION: STABILITY]` FPP block in
    `firefox/noid-firefox-hardening.js`).
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
    neighbour pins. No ARP-family packet filter is installed, so RFC 5227
    conflict detection and address defence still work.
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
  consoles; AMT allows out-of-band remote administration. AMD Secure
  Processor (ASP, formerly Platform Security Processor/PSP) is a below-OS
  security coprocessor, but is not itself an AMT-equivalent
  remote-management stack; product-specific AMD DASH/AIM-T capability is a
  separate OOB boundary.
- **Host-side controls — Intel** (Module 15):
    1. `mei` + `mei_me` core modules kept available for supported fwupd
       attributes. The overall HSI score remains platform-, firmware-,
       runtime-, and fwupd-version-dependent.
    2. KT/SOL PCI functions (27 IDs from 6th-gen Skylake through Panther
       Lake, the Nova/Wildcat Lake candidates and the Sapphire Rapids
       workstation) use `driver_override=none`, preventing a
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
  - `mei_hdcp` block → may disrupt Intel HDCP-protected display/content
    paths; the effect depends on GPU, display stack and media service.
  - `mei_pxp` block → may break Intel protected graphics/media (PXP)
    workflows; the effect is platform-dependent.
  - `mei_wdt` block → removes the alarm-only iAMT OS-health watchdog alerts
    on vPro/AMT-managed systems; no cost on consumer non-vPro hardware.
- **Defences — AMD (awareness / docs only — PSP not host-disableable)** (Module 15 Step 4b):
    1. The `ccp`/PSP driver **stays active**: Fedora 44 builds it into the
       kernel (`CONFIG_CRYPTO_DEV_CCP_DD=y`; only `ccp-crypto` is a module),
       so a modprobe.d blacklist would not apply. It can back platform
       crypto, RNG, fTPM and fwupd PSP visibility; those dependencies vary by
       machine, and neither the driver nor its absence universally controls
       fTPM or disables the PSP.
    2. IOMMU isolation through the kernel's default-on AMD-Vi driver (where
       firmware exposes it) plus the shared `iommu.strict=1` and
       `iommu.passthrough=0` tokens; AMD needs no vendor-specific token.
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
       AGESA version. Also tracked: faulTPM (fault-injection attacks on
       Ryzen fTPM).
- **Residual risk**: ME/PSP firmware below the OS boundary is not fully
  controllable by the host. Disabling the Linux `ccp` driver (on Fedora 44
  a kernel-level change, not a modprobe blacklist) would not switch off PSP
  firmware and would remove useful host functions. Mitigations
  reduce but do not eliminate firmware-class threats on either vendor.
  Intel documents AMT as operating independently of the OS, so host
  firewalld/nftables rules cannot enforce the LAN/WAN claim against AMT OOB.
  Pre-compromised PSP/ME firmware from factory = out-of-scope (see
  `scope.md` §4 and §5).

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
  baseline (tagged v140.3 snapshot); the carried NoID Privacy derivative is maintained
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

The opt-in codec helper also handles the observed case where Quad9's filtered
service refuses Cisco's distribution name. Only after a failed OpenH264 DNF
transaction and exact runtime proof of that filtered-only condition does it
route one retry through Quad9's documented no-threat-blocking service using
strict authenticated DoT (`dns10.quad9.net`). Threat blocking is therefore
absent for that resolver path during the bounded retry, while DNS transport
authentication and RPM payload-signature enforcement remain active. The
override is runtime-only, serialized with the DNS-mode selector and must be
proven restored before unrelated codec work or overall success can continue.

## Trust non-assumptions (things we don't trust)

- Intel Management Engine firmware, AMT SKU configuration.
- OEM UEFI firmware SMM drivers (partial mitigation via Secure Boot +
  IOMMU).
- Upstream Fedora `audit` rules (we override with 132 hardened rules in
  exact b64/b32 pairs).
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
| WireGuard (provider-managed or self-managed) | classical Curve25519 handshake; an independently provisioned strong preshared key can add a symmetric layer | No standardised interoperable PQ handshake mode verified in this assessment |
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
   remain outside that claim, as does a process in the active local session
   that adds a VPN profile or reapplies a route through NetworkManager's
   polkit policy (its literal endpoint becomes a durable WAN-strict tuple).
3. **Hardened host baseline** — 106 static sysctl params + one generated
   durable parameter for the selected physical interface and event-time
   enforcement on every physical pre-up + 49 shared
   kernel-command-line tokens, plus up to 7 conditional tokens
   (Intel CPU: 5, none on AMD, plus NVIDIA GPU: 1,
   LUKS unlock-retry: 1 per encrypted volume, 1 on the reference layout), + a
   134-row module
   policy with 52 effective loadable-module denies +
   SELinux enforcing + the custom NoID Privacy SELinux module (noid-selinux-fixes) + reviewed
   systemd service hardening drop-ins
   + optional installer-selected LUKS2 + a Secure-Boot-capable Fedora chain
   when firmware Secure Boot is enabled + **vendor-aware firmware posture** (Intel
   ME: one host-side ME-specific control — KT/SOL PCI driver_override=none
   — + 3 opt-in MEI sub-module blocks per the Kicksecure consensus, with
   generic IOMMU isolation + core `mei`/`mei_me` kept available for fwupd
   attributes on supported platforms (no fixed HSI level is promised); AMD
   PSP: awareness/docs only — `ccp` remains available for platform-dependent
   crypto/fTPM functions, while generic IOMMU and available fwupd attributes
   do not disable PSP, plus PSB OTP warnings +
   CVE-2025-2884/faulTPM documentation) + USBGuard + AIDE.
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

**Why out of scope**: the ME mitigation (Module 15, Kicksecure
consensus) reduces
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

(arkenfox is not fetched at build time: the NoID Privacy Firefox user.js ships
as an in-repo derivative work of the v144.0 snapshot. Future version bumps
require an explicit in-repo refresh + review, not an automatic upstream
fetch. Thunderbird follows the same local
derivative contract for its tagged HorlogeSkynet v140.3 basis; Update All
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

**Why out of scope**: the image provides no protection against compelled
disclosure of a working unlock secret. A detached LUKS header and an additional
keyslot are not duress-passphrase features: `--header` selects separate metadata,
and another bound keyslot provides another way to unlock the same volume.
NoID Privacy ships no duress-unlock or plausible-deniability workflow.

### 13. Phishing / social engineering
User enters credentials into a phishing page that looks legitimate.

**Partial defence**: Firefox + uBlock filter lists and Quad9's malware-blocking
resolver can reject some known malicious destinations. Firefox credential
saving is disabled by the project policy, but Thunderbird and an explicitly
used external password manager remain separate credential stores. These
controls do not recognize every phishing site; user verification is required.

### 14. Maliciously crafted media file
PDF, video, image with an embedded exploit targeting the renderer.

**Partial defence**: Flatpak sandboxing for Flatpak media apps and Firefox's
sandbox for web media. A host-native tool (e.g. `xdg-open` → `papers`) does not
acquire a Flatpak boundary merely through the file-opening association.
Application-specific process isolation and the system's access controls still
apply according to their actual configuration; none guarantees that a crafted
file cannot exploit its renderer.

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

**Package and standards evidence last verified**: 2026-10-02. The observed
Fedora 44 environment used OpenSSH 10.2p1, OpenSSL 3.5.8, OpenVPN 2.7.7,
Firefox 156, Thunderbird 156, NSS 3.129, and GnuPG 2.4.9. This dated snapshot
supports the assessment below but is not an exact release-ISO package manifest;
Fedora packages remain updateable.

**Endpoint probe observations last rerun**: 2026-09-02. They are deliberately
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
hybrid-key-exchange design, and RFC 10024 (Proposed Standard, August 2026)
specifies the concrete `X25519MLKEM768` group.

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
nevertheless negotiated `X25519MLKEM768`. On the 2026-09-02 rerun with
OpenSSL 3.5.7, the Cloudflare endpoint again completed the hybrid-only
handshake, while both Quad9 addresses rejected all six hybrid-only sessions and
an unrestricted session to the secondary address negotiated classical X25519.
Taken together, these dated observations establish that some Quad9 sessions
can negotiate the hybrid group. It does not establish consistent endpoint-wide
support, and the 2026-09-02 series shows that a whole probe run can pass
without a single hybrid Quad9 handshake. These are dated endpoint
observations, not a claim about all Cloudflare or Quad9 sessions; the
verification commands below are the source of truth for a later release.

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
      -verify_hostname "$TLS_HOST" \
      -verify_return_error \
      -tls1_3 \
      -groups X25519MLKEM768 \
      -brief </dev/null
else
    printf 'Invalid DNS name\n' >&2
fi
```

A successful, certificate-verified TLS 1.3 handshake restricted to that group
demonstrates support by the authenticated endpoint at test time. Require exit
status zero and inspect the reported protocol, negotiated group and verification
result. Without `-verify_return_error`, this diagnostic client can continue
after certificate errors; SNI alone does not verify the hostname. A failure can
also reflect certificate, clock, network or endpoint-specific configuration
problems. Firefox's own connection can be checked at
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
- IETF RFC 10024 (PQ/T Hybrid Key Agreement Mechanisms for TLS 1.3):
  <https://www.rfc-editor.org/rfc/rfc10024.html>
- IETF RFC 9980 (Post-Quantum Cryptography in OpenPGP):
  <https://datatracker.ietf.org/doc/rfc9980/>
- GnuPG upstream 2.5 Kyber capability example:
  <https://lists.gnupg.org/pipermail/gnupg-users/2026-April/068248.html>
- GnuPG upstream branch/EOL status:
  <https://gnupg.org/blog/20250827-new-repository.html>
- OpenVPN PQ test guidance:
  <https://community.openvpn.net/PQCryptoOpenVPN/>
- OpenSSL 3.5 diagnostic client verification options:
  <https://docs.openssl.org/3.5/man1/openssl-s_client/>
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
`ntfs3,ntfs` driver order for external NTFS; thermald keeps Fedora's preset and
its own hardware probe (intel_lpmd is masked by M08 under the single-EPP-writer
policy). EEE remains with Fedora, each driver and the link partner
because systemd 259's legacy 32-bit EEE ioctl cannot represent modern link
modes safely. The external-storage policy covers sticks and USB SSDs/HDDs
regardless of the unreliable removable bit. Blanket `sync` is not used:
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

## Firefox's first page and the uBlock Origin startup cache

Firefox's web cache and uBlock Origin's filter-engine cache are separate.
The productive profile clears the web cache and form data on normal shutdown;
it retains cookies and site storage. These defaults are defined in the repository
source `firefox/noid-firefox-hardening.js`.
Normal shutdown with these defaults has been verified to preserve uBO's
filter-engine cache in the installed v1.9 candidate.

uBO can hold requests until its filtering engine is ready. Without a valid
saved engine, it builds that engine from the filter lists. Its saved startup
state is called a **selfie**. In the shipped uBO 1.75.0, creation is deferred:
the default timer is 53 seconds, with a later alarm as a second path. Filter
updates can invalidate and reschedule this state. Repeated brief sessions can
therefore end before a usable selfie is saved, repeating the startup work.
This does not mean Firefox deleted the filter cache when it closed.
See upstream's [cache storage](https://github.com/gorhill/uBlock/blob/1.75.0/src/js/cachestorage.js),
[selfie lifecycle](https://github.com/gorhill/uBlock/blob/1.75.0/src/js/storage.js)
and [startup sequence](https://github.com/gorhill/uBlock/blob/1.75.0/src/js/start.js).

To diagnose this without changing protection settings:

1. Open uBO's dashboard, then **Support**, and inspect **Troubleshooting
   Information**. Record `allReadyAfter` and whether it includes `(selfie)`.
2. Leave Firefox open for a few minutes once, quit normally, then reopen it
   and record the same fields. This gives uBO time to finish its own deferred
   work; it is not a guarantee that every future launch will reuse a selfie.
3. Compare the first and subsequent page requests separately. If uBO is
   already ready before the first request, investigate DNS, TCP/TLS and server
   response time rather than attributing that delay to filter loading.

Keep shutdown clearing, filtering during startup, the selected filter lists,
DNS validation and encrypted transport unchanged. Do not infer that an
extension was reinstalled or its storage cleared from a slow launch alone;
check the active profile, extension state and measured startup data.

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

Also record the observable milestones: power-on, disk-unlock prompt, password
submission, login screen, login submission and usable desktop. Report manual
input waits separately. `systemd-analyze` totals and `blame` entries are service
measurements, not desktop-readiness measurements: parallel work and one-time
post-install jobs can finish after the desktop is usable. Pair them with the
critical chain and journal ordering before calling a long-running service a
boot bottleneck. Keep first installed boot, later cold boots and reboots as
separate samples. When joining guest logs with host screenshots, calibrate
their clocks and reject joins affected by clock steps.

For a meaningful A/B comparison:

1. Use the same machine, firmware settings, power source and storage.
2. Compare against the Fedora 44 package/kernel versions represented by the
   compose, not an unrelated newer installation.
3. Reboot between states, warm or cold caches consistently, and repeat enough
   times to report variation rather than one favorable result.
4. Measure the actual target workload (build, database, browser, media, VM or
   ML job) and keep thermal throttling visible.
5. Preserve protection settings during the baseline comparison. Attribute
   delays with service dependencies, application readiness, cache state and
   network timings before proposing a change.

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
repository root and is installed as `/usr/share/licenses/noid-privacy/COPYING`.

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
(logo, Plymouth watermark, app icons, avatar) are the exclusive property of the
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

  - `kickstart/`, `scripts/`, `manifests/`, and `tests/` except the
    Markdown documentation `tests/README.md`, `tests/smoke/README.md` and
    `scripts/anaconda-patch/README.md`
  - NoID Privacy-owned non-Markdown repository/CI configuration (`.gitattributes`,
    `.gitignore`, `.github/*.yml`, `.github/workflows/*.yml`)
  - `branding/SHA256SUMS` and `branding/icons/regenerate-icons.sh`
  - `overrides/noid-lan-xdp/noid-lan-xdp.sh`
  - `thunderbird/autoconfig.js`, `thunderbird/dkim-compatibility.json`,
    `thunderbird/local-settings.js` and `thunderbird/mozilla.cfg`
  - NoID Privacy override sections in
    `thunderbird/noid-thunderbird-hardening.js` (the embedded upstream base is
    MIT; see section 3)

It excludes the separately licensed Lorax patches, Anaconda Live-source
derivative, XDP BPF source/object (including its base64 embed in
`kickstart/snippets/03-firewalld.ks`), Firefox derivative, upstream license
texts (including their embedded copies in
`kickstart/snippets/31-user-docs-tier-c.ks`), Fedora's retained release
checksum manifest, Flathub's retained remote descriptor, documentation and
branding assets listed below. No upstream source tree is vendored into this
repository.

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program. If not, see <https://www.gnu.org/licenses/>. The full license
text is also included in the `COPYING` file at the repository root and is
installed as `/usr/share/licenses/noid-privacy/COPYING`.

================================================================================
2. NoID Privacy documentation
================================================================================

Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0)

This category includes the NoID Privacy-owned root Markdown files (`README.md`,
`INDEX.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
`SECURITY.md`, `AGENTS.md`, `LICENSING.md`), `docs/` except
`docs/screenshots/` (section 4), `tests/README.md`, `tests/smoke/README.md`,
`scripts/anaconda-patch/README.md`,
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
    `noid-lan-xdp.bpf.o.b64` object. `scripts/regen-lan-xdp-embed.sh` embeds
    that same object as the base64 heredoc `NOID_LAN_XDP_OBJECT_B64_EOF` in
    `kickstart/snippets/03-firewalld.ks`, which installs it as
    `/usr/lib/noid-privacy/noid-lan-xdp.bpf.o`. The embedded block stays
    GPL-2.0-only and is a separate work aggregated into that GPL-3.0-or-later
    Kickstart file, not relicensed by it. The controller shell script remains
    GPL-3.0-or-later and its README remains CC-BY-SA-4.0.

    The corresponding source travels with the object in every image: Module 31
    installs `noid-lan-xdp.bpf.c` and `build-lan-xdp-object.sh`, the script
    that controls its compilation, under
    `/usr/share/noid-privacy/source/noid-lan-xdp/`. They are byte-identical to
    `overrides/noid-lan-xdp/noid-lan-xdp.bpf.c` and
    `scripts/build-lan-xdp-object.sh`, and the script rebuilds and verifies the
    object from a repository checkout. The same files are published in the
    repository named by `NOID_REPO` in `/etc/noid-build-info`
    (<https://github.com/NexusOne23/noid-privacy-workstation>) at the release
    tag named by `NOID_VERSION`. That parentless release commit carries the
    exact tree of the build commit recorded as `NOID_SOURCE_COMMIT`; the build
    commit itself is not published, so the copy shipped in the image is the
    authoritative source for that image.

    The complete GNU GPL version 2 text used by these exceptions is retained
    at `licenses/GPL-2.0.txt` and installed as
    `/usr/share/licenses/noid-privacy/GPL-2.0.txt`.

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

  - HorlogeSkynet thunderbird-user.js v140.3 — MIT
    https://github.com/HorlogeSkynet/thunderbird-user.js
    Basis of `thunderbird/noid-thunderbird-hardening.js` (NoID Privacy Thunderbird
    Hardening), embedded into M35 as a gzip+base64 blob via
    `scripts/regen-thunderbird-embed.sh`. The exact annotated tag `v140.3`
    notice (commit `78aaf2644d20f8f077a361a0370686e92c8cc942`, SHA-256
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
  - Just Perfection GNOME Shell extension v37 — GPL-3.0-only
    https://gitlab.gnome.org/jrahmatzadeh/just-perfection
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
    relicense them as NoID Privacy documentation. The image installs all four
    under `/usr/share/licenses/noid-privacy/` (`COPYING`, `GPL-2.0.txt` and the
    two MIT notices), and the GPL-2.0-only XDP object's corresponding source
    under `/usr/share/noid-privacy/source/noid-lan-xdp/`.

--- UPSTREAM RELEASE DATA (retained verbatim) ---

  - Fedora Server 44 release checksum manifest
    `scripts/fedora-base/Fedora-Server-44-1.7-x86_64-CHECKSUM` is the Fedora
    Project's clear-signed `CHECKSUM` file for the 44-1.7 Server media,
    retained unmodified so `scripts/verify-fedora-base-iso.sh` can check its
    OpenPGP signature and the base-ISO digest. It is Fedora release data, not
    NoID Privacy-authored code, and section 1 does not relicense it.

  - Flathub remote descriptor
    `manifests/flathub.flatpakrepo` (with its byte-identical embed in
    `kickstart/snippets/18-flatpak-sandboxing.ks`) is Flathub's published
    `flathub.flatpakrepo`, including Flathub's public signing key, retained
    unmodified and pinned by size and SHA-256. It is Flathub remote data, not
    NoID Privacy-authored code, and section 1 does not relicense it.

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

Product screenshots are a separate exception:

  - `docs/screenshots/*.png`

The NoID Privacy marks in them remain all rights reserved; the GNOME `drool`
wallpaper remains CC-BY-SA-3.0 (`gnome-backgrounds`); third-party application
icons and logos remain the property of their owners. The screenshots are
provided for documentation of this project only and are not licensed under
CC BY-SA 4.0.

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
# Phase 4c — License texts for NoID Privacy's own code
# ------------------------------------------------------------------------------
# NoID Privacy's own scripts and machine-readable policy are GPL-3.0-or-later;
# the physical-link XDP object that Module 03 installs is GPL-2.0-only. Ship
# both complete license texts beside the MIT notices that Modules 16 and 35
# install. The two heredocs and their named SHA-256 fields are generated from
# COPYING and licenses/GPL-2.0.txt by scripts/regen-product-boundary-docs.sh.
PHASE="P4c-license-texts"
LICENSE_DIR=/usr/share/licenses/noid-privacy
if [ -e "$LICENSE_DIR" ] || [ -L "$LICENSE_DIR" ]; then
    [ -d "$LICENSE_DIR" ] && [ ! -L "$LICENSE_DIR" ] \
        || die "$LICENSE_DIR exists but is not a real directory"
    [ "$(stat -Lc '%u:%g:%a' -- "$LICENSE_DIR" 2>/dev/null || true)" = \
        "0:0:755" ] \
        || die "$LICENSE_DIR existing metadata differs from root:root 0755"
else
    install -d -m 0755 -o root -g root -- "$LICENSE_DIR"
fi
restorecon -F -- "$LICENSE_DIR" \
    || die "restorecon failed for license directory"
matchpathcon -V "$LICENSE_DIR" >/dev/null \
    || die "$LICENSE_DIR SELinux context differs"

verify_license_digest() {
    local expected=$1 path=$2
    printf '%s  %s\n' "$expected" "$path" | sha256sum -c - >/dev/null 2>&1
}

NOID_GPL3_LICENSE_SHA256=8ceb4b9ee5adedde47b31e975c1d90c73ad27b6b165a1dcd80c7c545eb65b903
DOC_TMP=$(mktemp "$LICENSE_DIR/.COPYING.XXXXXXXX")
cat > "$DOC_TMP" <<'NOID_GPL3_LICENSE_EOF'
                    GNU GENERAL PUBLIC LICENSE
                       Version 3, 29 June 2007

 Copyright (C) 2007 Free Software Foundation, Inc. <http://fsf.org/>
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.

                            Preamble

  The GNU General Public License is a free, copyleft license for
software and other kinds of works.

  The licenses for most software and other practical works are designed
to take away your freedom to share and change the works.  By contrast,
the GNU General Public License is intended to guarantee your freedom to
share and change all versions of a program--to make sure it remains free
software for all its users.  We, the Free Software Foundation, use the
GNU General Public License for most of our software; it applies also to
any other work released this way by its authors.  You can apply it to
your programs, too.

  When we speak of free software, we are referring to freedom, not
price.  Our General Public Licenses are designed to make sure that you
have the freedom to distribute copies of free software (and charge for
them if you wish), that you receive source code or can get it if you
want it, that you can change the software or use pieces of it in new
free programs, and that you know you can do these things.

  To protect your rights, we need to prevent others from denying you
these rights or asking you to surrender the rights.  Therefore, you have
certain responsibilities if you distribute copies of the software, or if
you modify it: responsibilities to respect the freedom of others.

  For example, if you distribute copies of such a program, whether
gratis or for a fee, you must pass on to the recipients the same
freedoms that you received.  You must make sure that they, too, receive
or can get the source code.  And you must show them these terms so they
know their rights.

  Developers that use the GNU GPL protect your rights with two steps:
(1) assert copyright on the software, and (2) offer you this License
giving you legal permission to copy, distribute and/or modify it.

  For the developers' and authors' protection, the GPL clearly explains
that there is no warranty for this free software.  For both users' and
authors' sake, the GPL requires that modified versions be marked as
changed, so that their problems will not be attributed erroneously to
authors of previous versions.

  Some devices are designed to deny users access to install or run
modified versions of the software inside them, although the manufacturer
can do so.  This is fundamentally incompatible with the aim of
protecting users' freedom to change the software.  The systematic
pattern of such abuse occurs in the area of products for individuals to
use, which is precisely where it is most unacceptable.  Therefore, we
have designed this version of the GPL to prohibit the practice for those
products.  If such problems arise substantially in other domains, we
stand ready to extend this provision to those domains in future versions
of the GPL, as needed to protect the freedom of users.

  Finally, every program is threatened constantly by software patents.
States should not allow patents to restrict development and use of
software on general-purpose computers, but in those that do, we wish to
avoid the special danger that patents applied to a free program could
make it effectively proprietary.  To prevent this, the GPL assures that
patents cannot be used to render the program non-free.

  The precise terms and conditions for copying, distribution and
modification follow.

                       TERMS AND CONDITIONS

  0. Definitions.

  "This License" refers to version 3 of the GNU General Public License.

  "Copyright" also means copyright-like laws that apply to other kinds of
works, such as semiconductor masks.

  "The Program" refers to any copyrightable work licensed under this
License.  Each licensee is addressed as "you".  "Licensees" and
"recipients" may be individuals or organizations.

  To "modify" a work means to copy from or adapt all or part of the work
in a fashion requiring copyright permission, other than the making of an
exact copy.  The resulting work is called a "modified version" of the
earlier work or a work "based on" the earlier work.

  A "covered work" means either the unmodified Program or a work based
on the Program.

  To "propagate" a work means to do anything with it that, without
permission, would make you directly or secondarily liable for
infringement under applicable copyright law, except executing it on a
computer or modifying a private copy.  Propagation includes copying,
distribution (with or without modification), making available to the
public, and in some countries other activities as well.

  To "convey" a work means any kind of propagation that enables other
parties to make or receive copies.  Mere interaction with a user through
a computer network, with no transfer of a copy, is not conveying.

  An interactive user interface displays "Appropriate Legal Notices"
to the extent that it includes a convenient and prominently visible
feature that (1) displays an appropriate copyright notice, and (2)
tells the user that there is no warranty for the work (except to the
extent that warranties are provided), that licensees may convey the
work under this License, and how to view a copy of this License.  If
the interface presents a list of user commands or options, such as a
menu, a prominent item in the list meets this criterion.

  1. Source Code.

  The "source code" for a work means the preferred form of the work
for making modifications to it.  "Object code" means any non-source
form of a work.

  A "Standard Interface" means an interface that either is an official
standard defined by a recognized standards body, or, in the case of
interfaces specified for a particular programming language, one that
is widely used among developers working in that language.

  The "System Libraries" of an executable work include anything, other
than the work as a whole, that (a) is included in the normal form of
packaging a Major Component, but which is not part of that Major
Component, and (b) serves only to enable use of the work with that
Major Component, or to implement a Standard Interface for which an
implementation is available to the public in source code form.  A
"Major Component", in this context, means a major essential component
(kernel, window system, and so on) of the specific operating system
(if any) on which the executable work runs, or a compiler used to
produce the work, or an object code interpreter used to run it.

  The "Corresponding Source" for a work in object code form means all
the source code needed to generate, install, and (for an executable
work) run the object code and to modify the work, including scripts to
control those activities.  However, it does not include the work's
System Libraries, or general-purpose tools or generally available free
programs which are used unmodified in performing those activities but
which are not part of the work.  For example, Corresponding Source
includes interface definition files associated with source files for
the work, and the source code for shared libraries and dynamically
linked subprograms that the work is specifically designed to require,
such as by intimate data communication or control flow between those
subprograms and other parts of the work.

  The Corresponding Source need not include anything that users
can regenerate automatically from other parts of the Corresponding
Source.

  The Corresponding Source for a work in source code form is that
same work.

  2. Basic Permissions.

  All rights granted under this License are granted for the term of
copyright on the Program, and are irrevocable provided the stated
conditions are met.  This License explicitly affirms your unlimited
permission to run the unmodified Program.  The output from running a
covered work is covered by this License only if the output, given its
content, constitutes a covered work.  This License acknowledges your
rights of fair use or other equivalent, as provided by copyright law.

  You may make, run and propagate covered works that you do not
convey, without conditions so long as your license otherwise remains
in force.  You may convey covered works to others for the sole purpose
of having them make modifications exclusively for you, or provide you
with facilities for running those works, provided that you comply with
the terms of this License in conveying all material for which you do
not control copyright.  Those thus making or running the covered works
for you must do so exclusively on your behalf, under your direction
and control, on terms that prohibit them from making any copies of
your copyrighted material outside their relationship with you.

  Conveying under any other circumstances is permitted solely under
the conditions stated below.  Sublicensing is not allowed; section 10
makes it unnecessary.

  3. Protecting Users' Legal Rights From Anti-Circumvention Law.

  No covered work shall be deemed part of an effective technological
measure under any applicable law fulfilling obligations under article
11 of the WIPO copyright treaty adopted on 20 December 1996, or
similar laws prohibiting or restricting circumvention of such
measures.

  When you convey a covered work, you waive any legal power to forbid
circumvention of technological measures to the extent such circumvention
is effected by exercising rights under this License with respect to
the covered work, and you disclaim any intention to limit operation or
modification of the work as a means of enforcing, against the work's
users, your or third parties' legal rights to forbid circumvention of
technological measures.

  4. Conveying Verbatim Copies.

  You may convey verbatim copies of the Program's source code as you
receive it, in any medium, provided that you conspicuously and
appropriately publish on each copy an appropriate copyright notice;
keep intact all notices stating that this License and any
non-permissive terms added in accord with section 7 apply to the code;
keep intact all notices of the absence of any warranty; and give all
recipients a copy of this License along with the Program.

  You may charge any price or no price for each copy that you convey,
and you may offer support or warranty protection for a fee.

  5. Conveying Modified Source Versions.

  You may convey a work based on the Program, or the modifications to
produce it from the Program, in the form of source code under the
terms of section 4, provided that you also meet all of these conditions:

    a) The work must carry prominent notices stating that you modified
    it, and giving a relevant date.

    b) The work must carry prominent notices stating that it is
    released under this License and any conditions added under section
    7.  This requirement modifies the requirement in section 4 to
    "keep intact all notices".

    c) You must license the entire work, as a whole, under this
    License to anyone who comes into possession of a copy.  This
    License will therefore apply, along with any applicable section 7
    additional terms, to the whole of the work, and all its parts,
    regardless of how they are packaged.  This License gives no
    permission to license the work in any other way, but it does not
    invalidate such permission if you have separately received it.

    d) If the work has interactive user interfaces, each must display
    Appropriate Legal Notices; however, if the Program has interactive
    interfaces that do not display Appropriate Legal Notices, your
    work need not make them do so.

  A compilation of a covered work with other separate and independent
works, which are not by their nature extensions of the covered work,
and which are not combined with it such as to form a larger program,
in or on a volume of a storage or distribution medium, is called an
"aggregate" if the compilation and its resulting copyright are not
used to limit the access or legal rights of the compilation's users
beyond what the individual works permit.  Inclusion of a covered work
in an aggregate does not cause this License to apply to the other
parts of the aggregate.

  6. Conveying Non-Source Forms.

  You may convey a covered work in object code form under the terms
of sections 4 and 5, provided that you also convey the
machine-readable Corresponding Source under the terms of this License,
in one of these ways:

    a) Convey the object code in, or embodied in, a physical product
    (including a physical distribution medium), accompanied by the
    Corresponding Source fixed on a durable physical medium
    customarily used for software interchange.

    b) Convey the object code in, or embodied in, a physical product
    (including a physical distribution medium), accompanied by a
    written offer, valid for at least three years and valid for as
    long as you offer spare parts or customer support for that product
    model, to give anyone who possesses the object code either (1) a
    copy of the Corresponding Source for all the software in the
    product that is covered by this License, on a durable physical
    medium customarily used for software interchange, for a price no
    more than your reasonable cost of physically performing this
    conveying of source, or (2) access to copy the
    Corresponding Source from a network server at no charge.

    c) Convey individual copies of the object code with a copy of the
    written offer to provide the Corresponding Source.  This
    alternative is allowed only occasionally and noncommercially, and
    only if you received the object code with such an offer, in accord
    with subsection 6b.

    d) Convey the object code by offering access from a designated
    place (gratis or for a charge), and offer equivalent access to the
    Corresponding Source in the same way through the same place at no
    further charge.  You need not require recipients to copy the
    Corresponding Source along with the object code.  If the place to
    copy the object code is a network server, the Corresponding Source
    may be on a different server (operated by you or a third party)
    that supports equivalent copying facilities, provided you maintain
    clear directions next to the object code saying where to find the
    Corresponding Source.  Regardless of what server hosts the
    Corresponding Source, you remain obligated to ensure that it is
    available for as long as needed to satisfy these requirements.

    e) Convey the object code using peer-to-peer transmission, provided
    you inform other peers where the object code and Corresponding
    Source of the work are being offered to the general public at no
    charge under subsection 6d.

  A separable portion of the object code, whose source code is excluded
from the Corresponding Source as a System Library, need not be
included in conveying the object code work.

  A "User Product" is either (1) a "consumer product", which means any
tangible personal property which is normally used for personal, family,
or household purposes, or (2) anything designed or sold for incorporation
into a dwelling.  In determining whether a product is a consumer product,
doubtful cases shall be resolved in favor of coverage.  For a particular
product received by a particular user, "normally used" refers to a
typical or common use of that class of product, regardless of the status
of the particular user or of the way in which the particular user
actually uses, or expects or is expected to use, the product.  A product
is a consumer product regardless of whether the product has substantial
commercial, industrial or non-consumer uses, unless such uses represent
the only significant mode of use of the product.

  "Installation Information" for a User Product means any methods,
procedures, authorization keys, or other information required to install
and execute modified versions of a covered work in that User Product from
a modified version of its Corresponding Source.  The information must
suffice to ensure that the continued functioning of the modified object
code is in no case prevented or interfered with solely because
modification has been made.

  If you convey an object code work under this section in, or with, or
specifically for use in, a User Product, and the conveying occurs as
part of a transaction in which the right of possession and use of the
User Product is transferred to the recipient in perpetuity or for a
fixed term (regardless of how the transaction is characterized), the
Corresponding Source conveyed under this section must be accompanied
by the Installation Information.  But this requirement does not apply
if neither you nor any third party retains the ability to install
modified object code on the User Product (for example, the work has
been installed in ROM).

  The requirement to provide Installation Information does not include a
requirement to continue to provide support service, warranty, or updates
for a work that has been modified or installed by the recipient, or for
the User Product in which it has been modified or installed.  Access to a
network may be denied when the modification itself materially and
adversely affects the operation of the network or violates the rules and
protocols for communication across the network.

  Corresponding Source conveyed, and Installation Information provided,
in accord with this section must be in a format that is publicly
documented (and with an implementation available to the public in
source code form), and must require no special password or key for
unpacking, reading or copying.

  7. Additional Terms.

  "Additional permissions" are terms that supplement the terms of this
License by making exceptions from one or more of its conditions.
Additional permissions that are applicable to the entire Program shall
be treated as though they were included in this License, to the extent
that they are valid under applicable law.  If additional permissions
apply only to part of the Program, that part may be used separately
under those permissions, but the entire Program remains governed by
this License without regard to the additional permissions.

  When you convey a copy of a covered work, you may at your option
remove any additional permissions from that copy, or from any part of
it.  (Additional permissions may be written to require their own
removal in certain cases when you modify the work.)  You may place
additional permissions on material, added by you to a covered work,
for which you have or can give appropriate copyright permission.

  Notwithstanding any other provision of this License, for material you
add to a covered work, you may (if authorized by the copyright holders of
that material) supplement the terms of this License with terms:

    a) Disclaiming warranty or limiting liability differently from the
    terms of sections 15 and 16 of this License; or

    b) Requiring preservation of specified reasonable legal notices or
    author attributions in that material or in the Appropriate Legal
    Notices displayed by works containing it; or

    c) Prohibiting misrepresentation of the origin of that material, or
    requiring that modified versions of such material be marked in
    reasonable ways as different from the original version; or

    d) Limiting the use for publicity purposes of names of licensors or
    authors of the material; or

    e) Declining to grant rights under trademark law for use of some
    trade names, trademarks, or service marks; or

    f) Requiring indemnification of licensors and authors of that
    material by anyone who conveys the material (or modified versions of
    it) with contractual assumptions of liability to the recipient, for
    any liability that these contractual assumptions directly impose on
    those licensors and authors.

  All other non-permissive additional terms are considered "further
restrictions" within the meaning of section 10.  If the Program as you
received it, or any part of it, contains a notice stating that it is
governed by this License along with a term that is a further
restriction, you may remove that term.  If a license document contains
a further restriction but permits relicensing or conveying under this
License, you may add to a covered work material governed by the terms
of that license document, provided that the further restriction does
not survive such relicensing or conveying.

  If you add terms to a covered work in accord with this section, you
must place, in the relevant source files, a statement of the
additional terms that apply to those files, or a notice indicating
where to find the applicable terms.

  Additional terms, permissive or non-permissive, may be stated in the
form of a separately written license, or stated as exceptions;
the above requirements apply either way.

  8. Termination.

  You may not propagate or modify a covered work except as expressly
provided under this License.  Any attempt otherwise to propagate or
modify it is void, and will automatically terminate your rights under
this License (including any patent licenses granted under the third
paragraph of section 11).

  However, if you cease all violation of this License, then your
license from a particular copyright holder is reinstated (a)
provisionally, unless and until the copyright holder explicitly and
finally terminates your license, and (b) permanently, if the copyright
holder fails to notify you of the violation by some reasonable means
prior to 60 days after the cessation.

  Moreover, your license from a particular copyright holder is
reinstated permanently if the copyright holder notifies you of the
violation by some reasonable means, this is the first time you have
received notice of violation of this License (for any work) from that
copyright holder, and you cure the violation prior to 30 days after
your receipt of the notice.

  Termination of your rights under this section does not terminate the
licenses of parties who have received copies or rights from you under
this License.  If your rights have been terminated and not permanently
reinstated, you do not qualify to receive new licenses for the same
material under section 10.

  9. Acceptance Not Required for Having Copies.

  You are not required to accept this License in order to receive or
run a copy of the Program.  Ancillary propagation of a covered work
occurring solely as a consequence of using peer-to-peer transmission
to receive a copy likewise does not require acceptance.  However,
nothing other than this License grants you permission to propagate or
modify any covered work.  These actions infringe copyright if you do
not accept this License.  Therefore, by modifying or propagating a
covered work, you indicate your acceptance of this License to do so.

  10. Automatic Licensing of Downstream Recipients.

  Each time you convey a covered work, the recipient automatically
receives a license from the original licensors, to run, modify and
propagate that work, subject to this License.  You are not responsible
for enforcing compliance by third parties with this License.

  An "entity transaction" is a transaction transferring control of an
organization, or substantially all assets of one, or subdividing an
organization, or merging organizations.  If propagation of a covered
work results from an entity transaction, each party to that
transaction who receives a copy of the work also receives whatever
licenses to the work the party's predecessor in interest had or could
give under the previous paragraph, plus a right to possession of the
Corresponding Source of the work from the predecessor in interest, if
the predecessor has it or can get it with reasonable efforts.

  You may not impose any further restrictions on the exercise of the
rights granted or affirmed under this License.  For example, you may
not impose a license fee, royalty, or other charge for exercise of
rights granted under this License, and you may not initiate litigation
(including a cross-claim or counterclaim in a lawsuit) alleging that
any patent claim is infringed by making, using, selling, offering for
sale, or importing the Program or any portion of it.

  11. Patents.

  A "contributor" is a copyright holder who authorizes use under this
License of the Program or a work on which the Program is based.  The
work thus licensed is called the contributor's "contributor version".

  A contributor's "essential patent claims" are all patent claims
owned or controlled by the contributor, whether already acquired or
hereafter acquired, that would be infringed by some manner, permitted
by this License, of making, using, or selling its contributor version,
but do not include claims that would be infringed only as a
consequence of further modification of the contributor version.  For
purposes of this definition, "control" includes the right to grant
patent sublicenses in a manner consistent with the requirements of
this License.

  Each contributor grants you a non-exclusive, worldwide, royalty-free
patent license under the contributor's essential patent claims, to
make, use, sell, offer for sale, import and otherwise run, modify and
propagate the contents of its contributor version.

  In the following three paragraphs, a "patent license" is any express
agreement or commitment, however denominated, not to enforce a patent
(such as an express permission to practice a patent or covenant not to
sue for patent infringement).  To "grant" such a patent license to a
party means to make such an agreement or commitment not to enforce a
patent against the party.

  If you convey a covered work, knowingly relying on a patent license,
and the Corresponding Source of the work is not available for anyone
to copy, free of charge and under the terms of this License, through a
publicly available network server or other readily accessible means,
then you must either (1) cause the Corresponding Source to be so
available, or (2) arrange to deprive yourself of the benefit of the
patent license for this particular work, or (3) arrange, in a manner
consistent with the requirements of this License, to extend the patent
license to downstream recipients.  "Knowingly relying" means you have
actual knowledge that, but for the patent license, your conveying the
covered work in a country, or your recipient's use of the covered work
in a country, would infringe one or more identifiable patents in that
country that you have reason to believe are valid.

  If, pursuant to or in connection with a single transaction or
arrangement, you convey, or propagate by procuring conveyance of, a
covered work, and grant a patent license to some of the parties
receiving the covered work authorizing them to use, propagate, modify
or convey a specific copy of the covered work, then the patent license
you grant is automatically extended to all recipients of the covered
work and works based on it.

  A patent license is "discriminatory" if it does not include within
the scope of its coverage, prohibits the exercise of, or is
conditioned on the non-exercise of one or more of the rights that are
specifically granted under this License.  You may not convey a covered
work if you are a party to an arrangement with a third party that is
in the business of distributing software, under which you make payment
to the third party based on the extent of your activity of conveying
the work, and under which the third party grants, to any of the
parties who would receive the covered work from you, a discriminatory
patent license (a) in connection with copies of the covered work
conveyed by you (or copies made from those copies), or (b) primarily
for and in connection with specific products or compilations that
contain the covered work, unless you entered into that arrangement,
or that patent license was granted, prior to 28 March 2007.

  Nothing in this License shall be construed as excluding or limiting
any implied license or other defenses to infringement that may
otherwise be available to you under applicable patent law.

  12. No Surrender of Others' Freedom.

  If conditions are imposed on you (whether by court order, agreement or
otherwise) that contradict the conditions of this License, they do not
excuse you from the conditions of this License.  If you cannot convey a
covered work so as to satisfy simultaneously your obligations under this
License and any other pertinent obligations, then as a consequence you may
not convey it at all.  For example, if you agree to terms that obligate you
to collect a royalty for further conveying from those to whom you convey
the Program, the only way you could satisfy both those terms and this
License would be to refrain entirely from conveying the Program.

  13. Use with the GNU Affero General Public License.

  Notwithstanding any other provision of this License, you have
permission to link or combine any covered work with a work licensed
under version 3 of the GNU Affero General Public License into a single
combined work, and to convey the resulting work.  The terms of this
License will continue to apply to the part which is the covered work,
but the special requirements of the GNU Affero General Public License,
section 13, concerning interaction through a network will apply to the
combination as such.

  14. Revised Versions of this License.

  The Free Software Foundation may publish revised and/or new versions of
the GNU General Public License from time to time.  Such new versions will
be similar in spirit to the present version, but may differ in detail to
address new problems or concerns.

  Each version is given a distinguishing version number.  If the
Program specifies that a certain numbered version of the GNU General
Public License "or any later version" applies to it, you have the
option of following the terms and conditions either of that numbered
version or of any later version published by the Free Software
Foundation.  If the Program does not specify a version number of the
GNU General Public License, you may choose any version ever published
by the Free Software Foundation.

  If the Program specifies that a proxy can decide which future
versions of the GNU General Public License can be used, that proxy's
public statement of acceptance of a version permanently authorizes you
to choose that version for the Program.

  Later license versions may give you additional or different
permissions.  However, no additional obligations are imposed on any
author or copyright holder as a result of your choosing to follow a
later version.

  15. Disclaimer of Warranty.

  THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY
APPLICABLE LAW.  EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT
HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY
OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE.  THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM
IS WITH YOU.  SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF
ALL NECESSARY SERVICING, REPAIR OR CORRECTION.

  16. Limitation of Liability.

  IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MODIFIES AND/OR CONVEYS
THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES, INCLUDING ANY
GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE
USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED TO LOSS OF
DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD
PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER PROGRAMS),
EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF
SUCH DAMAGES.

  17. Interpretation of Sections 15 and 16.

  If the disclaimer of warranty and limitation of liability provided
above cannot be given local legal effect according to their terms,
reviewing courts shall apply local law that most closely approximates
an absolute waiver of all civil liability in connection with the
Program, unless a warranty or assumption of liability accompanies a
copy of the Program in return for a fee.

                     END OF TERMS AND CONDITIONS

            How to Apply These Terms to Your New Programs

  If you develop a new program, and you want it to be of the greatest
possible use to the public, the best way to achieve this is to make it
free software which everyone can redistribute and change under these terms.

  To do so, attach the following notices to the program.  It is safest
to attach them to the start of each source file to most effectively
state the exclusion of warranty; and each file should have at least
the "copyright" line and a pointer to where the full notice is found.

    <one line to give the program's name and a brief idea of what it does.>
    Copyright (C) <year>  <name of author>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

Also add information on how to contact you by electronic and paper mail.

  If the program does terminal interaction, make it output a short
notice like this when it starts in an interactive mode:

    <program>  Copyright (C) <year>  <name of author>
    This program comes with ABSOLUTELY NO WARRANTY; for details type `show w'.
    This is free software, and you are welcome to redistribute it
    under certain conditions; type `show c' for details.

The hypothetical commands `show w' and `show c' should show the appropriate
parts of the General Public License.  Of course, your program's commands
might be different; for a GUI interface, you would use an "about box".

  You should also get your employer (if you work as a programmer) or school,
if any, to sign a "copyright disclaimer" for the program, if necessary.
For more information on this, and how to apply and follow the GNU GPL, see
<http://www.gnu.org/licenses/>.

  The GNU General Public License does not permit incorporating your program
into proprietary programs.  If your program is a subroutine library, you
may consider it more useful to permit linking proprietary applications with
the library.  If this is what you want to do, use the GNU Lesser General
Public License instead of this License.  But first, please read
<http://www.gnu.org/philosophy/why-not-lgpl.html>.
NOID_GPL3_LICENSE_EOF
verify_license_digest "$NOID_GPL3_LICENSE_SHA256" "$DOC_TMP" \
    || die "staged GPL-3.0 license text differs from its pinned SHA-256"
publish_doc "$LICENSE_DIR/COPYING" "$LICENSE_DIR"

NOID_GPL2_LICENSE_SHA256=ddb9db7630752f8fdc6898f7c99a99eaeeac5213627ecb093df9c82f56175dc7
DOC_TMP=$(mktemp "$LICENSE_DIR/.GPL-2.0.txt.XXXXXXXX")
cat > "$DOC_TMP" <<'NOID_GPL2_LICENSE_EOF'
		    GNU GENERAL PUBLIC LICENSE
		       Version 2, June 1991

 Copyright (C) 1989, 1991 Free Software Foundation, Inc.
 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.

			    Preamble

  The licenses for most software are designed to take away your
freedom to share and change it.  By contrast, the GNU General Public
License is intended to guarantee your freedom to share and change free
software--to make sure the software is free for all its users.  This
General Public License applies to most of the Free Software
Foundation's software and to any other program whose authors commit to
using it.  (Some other Free Software Foundation software is covered by
the GNU Lesser General Public License instead.)  You can apply it to
your programs, too.

  When we speak of free software, we are referring to freedom, not
price.  Our General Public Licenses are designed to make sure that you
have the freedom to distribute copies of free software (and charge for
this service if you wish), that you receive source code or can get it
if you want it, that you can change the software or use pieces of it
in new free programs; and that you know you can do these things.

  To protect your rights, we need to make restrictions that forbid
anyone to deny you these rights or to ask you to surrender the rights.
These restrictions translate to certain responsibilities for you if you
distribute copies of the software, or if you modify it.

  For example, if you distribute copies of such a program, whether
gratis or for a fee, you must give the recipients all the rights that
you have.  You must make sure that they, too, receive or can get the
source code.  And you must show them these terms so they know their
rights.

  We protect your rights with two steps: (1) copyright the software, and
(2) offer you this license which gives you legal permission to copy,
distribute and/or modify the software.

  Also, for each author's protection and ours, we want to make certain
that everyone understands that there is no warranty for this free
software.  If the software is modified by someone else and passed on, we
want its recipients to know that what they have is not the original, so
that any problems introduced by others will not reflect on the original
authors' reputations.

  Finally, any free program is threatened constantly by software
patents.  We wish to avoid the danger that redistributors of a free
program will individually obtain patent licenses, in effect making the
program proprietary.  To prevent this, we have made it clear that any
patent must be licensed for everyone's free use or not licensed at all.

  The precise terms and conditions for copying, distribution and
modification follow.

		    GNU GENERAL PUBLIC LICENSE
   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION

  0. This License applies to any program or other work which contains
a notice placed by the copyright holder saying it may be distributed
under the terms of this General Public License.  The "Program", below,
refers to any such program or work, and a "work based on the Program"
means either the Program or any derivative work under copyright law:
that is to say, a work containing the Program or a portion of it,
either verbatim or with modifications and/or translated into another
language.  (Hereinafter, translation is included without limitation in
the term "modification".)  Each licensee is addressed as "you".

Activities other than copying, distribution and modification are not
covered by this License; they are outside its scope.  The act of
running the Program is not restricted, and the output from the Program
is covered only if its contents constitute a work based on the
Program (independent of having been made by running the Program).
Whether that is true depends on what the Program does.

  1. You may copy and distribute verbatim copies of the Program's
source code as you receive it, in any medium, provided that you
conspicuously and appropriately publish on each copy an appropriate
copyright notice and disclaimer of warranty; keep intact all the
notices that refer to this License and to the absence of any warranty;
and give any other recipients of the Program a copy of this License
along with the Program.

You may charge a fee for the physical act of transferring a copy, and
you may at your option offer warranty protection in exchange for a fee.

  2. You may modify your copy or copies of the Program or any portion
of it, thus forming a work based on the Program, and copy and
distribute such modifications or work under the terms of Section 1
above, provided that you also meet all of these conditions:

    a) You must cause the modified files to carry prominent notices
    stating that you changed the files and the date of any change.

    b) You must cause any work that you distribute or publish, that in
    whole or in part contains or is derived from the Program or any
    part thereof, to be licensed as a whole at no charge to all third
    parties under the terms of this License.

    c) If the modified program normally reads commands interactively
    when run, you must cause it, when started running for such
    interactive use in the most ordinary way, to print or display an
    announcement including an appropriate copyright notice and a
    notice that there is no warranty (or else, saying that you provide
    a warranty) and that users may redistribute the program under
    these conditions, and telling the user how to view a copy of this
    License.  (Exception: if the Program itself is interactive but
    does not normally print such an announcement, your work based on
    the Program is not required to print an announcement.)

These requirements apply to the modified work as a whole.  If
identifiable sections of that work are not derived from the Program,
and can be reasonably considered independent and separate works in
themselves, then this License, and its terms, do not apply to those
sections when you distribute them as separate works.  But when you
distribute the same sections as part of a whole which is a work based
on the Program, the distribution of the whole must be on the terms of
this License, whose permissions for other licensees extend to the
entire whole, and thus to each and every part regardless of who wrote it.

Thus, it is not the intent of this section to claim rights or contest
your rights to work written entirely by you; rather, the intent is to
exercise the right to control the distribution of derivative or
collective works based on the Program.

In addition, mere aggregation of another work not based on the Program
with the Program (or with a work based on the Program) on a volume of
a storage or distribution medium does not bring the other work under
the scope of this License.

  3. You may copy and distribute the Program (or a work based on it,
under Section 2) in object code or executable form under the terms of
Sections 1 and 2 above provided that you also do one of the following:

    a) Accompany it with the complete corresponding machine-readable
    source code, which must be distributed under the terms of Sections
    1 and 2 above on a medium customarily used for software interchange; or,

    b) Accompany it with a written offer, valid for at least three
    years, to give any third party, for a charge no more than your
    cost of physically performing source distribution, a complete
    machine-readable copy of the corresponding source code, to be
    distributed under the terms of Sections 1 and 2 above on a medium
    customarily used for software interchange; or,

    c) Accompany it with the information you received as to the offer
    to distribute corresponding source code.  (This alternative is
    allowed only for noncommercial distribution and only if you
    received the program in object code or executable form with such
    an offer, in accord with Subsection b above.)

The source code for a work means the preferred form of the work for
making modifications to it.  For an executable work, complete source
code means all the source code for all modules it contains, plus any
associated interface definition files, plus the scripts used to
control compilation and installation of the executable.  However, as a
special exception, the source code distributed need not include
anything that is normally distributed (in either source or binary
form) with the major components (compiler, kernel, and so on) of the
operating system on which the executable runs, unless that component
itself accompanies the executable.

If distribution of executable or object code is made by offering
access to copy from a designated place, then offering equivalent
access to copy the source code from the same place counts as
distribution of the source code, even though third parties are not
compelled to copy the source along with the object code.

  4. You may not copy, modify, sublicense, or distribute the Program
except as expressly provided under this License.  Any attempt
otherwise to copy, modify, sublicense or distribute the Program is
void, and will automatically terminate your rights under this License.
However, parties who have received copies, or rights, from you under
this License will not have their licenses terminated so long as such
parties remain in full compliance.

  5. You are not required to accept this License, since you have not
signed it.  However, nothing else grants you permission to modify or
distribute the Program or its derivative works.  These actions are
prohibited by law if you do not accept this License.  Therefore, by
modifying or distributing the Program (or any work based on the
Program), you indicate your acceptance of this License to do so, and
all its terms and conditions for copying, distributing or modifying
the Program or works based on it.

  6. Each time you redistribute the Program (or any work based on the
Program), the recipient automatically receives a license from the
original licensor to copy, distribute or modify the Program subject to
these terms and conditions.  You may not impose any further
restrictions on the recipients' exercise of the rights granted herein.
You are not responsible for enforcing compliance by third parties to
this License.

  7. If, as a consequence of a court judgment or allegation of patent
infringement or for any other reason (not limited to patent issues),
conditions are imposed on you (whether by court order, agreement or
otherwise) that contradict the conditions of this License, they do not
excuse you from the conditions of this License.  If you cannot
distribute so as to satisfy simultaneously your obligations under this
License and any other pertinent obligations, then as a consequence you
may not distribute the Program at all.  For example, if a patent
license would not permit royalty-free redistribution of the Program by
all those who receive copies directly or indirectly through you, then
the only way you could satisfy both it and this License would be to
refrain entirely from distribution of the Program.

If any portion of this section is held invalid or unenforceable under
any particular circumstance, the balance of the section is intended to
apply and the section as a whole is intended to apply in other
circumstances.

It is not the purpose of this section to induce you to infringe any
patents or other property right claims or to contest validity of any
such claims; this section has the sole purpose of protecting the
integrity of the free software distribution system, which is
implemented by public license practices.  Many people have made
generous contributions to the wide range of software distributed
through that system in reliance on consistent application of that
system; it is up to the author/donor to decide if he or she is willing
to distribute software through any other system and a licensee cannot
impose that choice.

This section is intended to make thoroughly clear what is believed to
be a consequence of the rest of this License.

  8. If the distribution and/or use of the Program is restricted in
certain countries either by patents or by copyrighted interfaces, the
original copyright holder who places the Program under this License
may add an explicit geographical distribution limitation excluding
those countries, so that distribution is permitted only in or among
countries not thus excluded.  In such case, this License incorporates
the limitation as if written in the body of this License.

  9. The Free Software Foundation may publish revised and/or new versions
of the General Public License from time to time.  Such new versions will
be similar in spirit to the present version, but may differ in detail to
address new problems or concerns.

Each version is given a distinguishing version number.  If the Program
specifies a version number of this License which applies to it and "any
later version", you have the option of following the terms and conditions
either of that version or of any later version published by the Free
Software Foundation.  If the Program does not specify a version number of
this License, you may choose any version ever published by the Free Software
Foundation.

  10. If you wish to incorporate parts of the Program into other free
programs whose distribution conditions are different, write to the author
to ask for permission.  For software which is copyrighted by the Free
Software Foundation, write to the Free Software Foundation; we sometimes
make exceptions for this.  Our decision will be guided by the two goals
of preserving the free status of all derivatives of our free software and
of promoting the sharing and reuse of software generally.

			    NO WARRANTY

  11. BECAUSE THE PROGRAM IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW.  EXCEPT WHEN
OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED
OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.  THE ENTIRE RISK AS
TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU.  SHOULD THE
PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING,
REPAIR OR CORRECTION.

  12. IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
REDISTRIBUTE THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES,
INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING
OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED
TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY
YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER
PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE
POSSIBILITY OF SUCH DAMAGES.

		     END OF TERMS AND CONDITIONS

	    How to Apply These Terms to Your New Programs

  If you develop a new program, and you want it to be of the greatest
possible use to the public, the best way to achieve this is to make it
free software which everyone can redistribute and change under these terms.

  To do so, attach the following notices to the program.  It is safest
to attach them to the start of each source file to most effectively
convey the exclusion of warranty; and each file should have at least
the "copyright" line and a pointer to where the full notice is found.

    <one line to give the program's name and a brief idea of what it does.>
    Copyright (C) <year>  <name of author>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA


Also add information on how to contact you by electronic and paper mail.

If the program is interactive, make it output a short notice like this
when it starts in an interactive mode:

    Gnomovision version 69, Copyright (C) year name of author
    Gnomovision comes with ABSOLUTELY NO WARRANTY; for details type `show w'.
    This is free software, and you are welcome to redistribute it
    under certain conditions; type `show c' for details.

The hypothetical commands `show w' and `show c' should show the appropriate
parts of the General Public License.  Of course, the commands you use may
be called something other than `show w' and `show c'; they could even be
mouse-clicks or menu items--whatever suits your program.

You should also get your employer (if you work as a programmer) or your
school, if any, to sign a "copyright disclaimer" for the program, if
necessary.  Here is a sample; alter the names:

  Yoyodyne, Inc., hereby disclaims all copyright interest in the program
  `Gnomovision' (which makes passes at compilers) written by James Hacker.

  <signature of Ty Coon>, 1 April 1989
  Ty Coon, President of Vice

This General Public License does not permit incorporating your program into
proprietary programs.  If your program is a subroutine library, you may
consider it more useful to permit linking proprietary applications with the
library.  If this is what you want to do, use the GNU Lesser General
Public License instead of this License.
NOID_GPL2_LICENSE_EOF
verify_license_digest "$NOID_GPL2_LICENSE_SHA256" "$DOC_TMP" \
    || die "staged GPL-2.0 license text differs from its pinned SHA-256"
publish_doc "$LICENSE_DIR/GPL-2.0.txt" "$LICENSE_DIR"
log "  [OK] GPL-3.0 and GPL-2.0 license texts installed in $LICENSE_DIR"

# ------------------------------------------------------------------------------
# Phase 4d — Corresponding source of the GPL-2.0-only XDP object
# ------------------------------------------------------------------------------
# GPL-2.0 section 3(a): the object Module 03 installs travels with its complete
# machine-readable source and the script that controls its compilation, so the
# offer does not depend on a remote commit staying reachable. The two heredocs
# and their named SHA-256 fields are generated from
# overrides/noid-lan-xdp/noid-lan-xdp.bpf.c and scripts/build-lan-xdp-object.sh
# by scripts/regen-product-boundary-docs.sh.
PHASE="P4d-xdp-corresponding-source"
XDP_SOURCE_PARENT=/usr/share/noid-privacy/source
XDP_SOURCE_DIR=$XDP_SOURCE_PARENT/noid-lan-xdp
for source_dir in /usr/share/noid-privacy "$XDP_SOURCE_PARENT" "$XDP_SOURCE_DIR"; do
    if [ -e "$source_dir" ] || [ -L "$source_dir" ]; then
        [ -d "$source_dir" ] && [ ! -L "$source_dir" ] \
            || die "$source_dir exists but is not a real directory"
        [ "$(stat -Lc '%u:%g:%a' -- "$source_dir" 2>/dev/null || true)" = \
            "0:0:755" ] \
            || die "$source_dir existing metadata differs from root:root 0755"
    else
        install -d -m 0755 -o root -g root -- "$source_dir"
    fi
    restorecon -F -- "$source_dir" \
        || die "restorecon failed for $source_dir"
    matchpathcon -V "$source_dir" >/dev/null \
        || die "$source_dir SELinux context differs"
done

NOID_LAN_XDP_SOURCE_SHA256=5241d7eedb81aa8ee17698d12653062f418351b5625573c92e765ebdb8f39fc6
DOC_TMP=$(mktemp "$XDP_SOURCE_DIR/.noid-lan-xdp.bpf.c.XXXXXXXX")
cat > "$DOC_TMP" <<'NOID_LAN_XDP_SOURCE_EOF'
// SPDX-License-Identifier: GPL-2.0-only
/*
 * NoID Privacy Workstation — physical-link XDP ingress boundary.
 *
 * Native-driver XDP runs before skb allocation. Generic XDP necessarily uses
 * an skb, but the kernel executes it before ptype_all packet taps (including
 * ordinary AF_PACKET capture). Default verdict is XDP_DROP. It passes only:
 *   - checksum-valid, unfragmented TCP/UDP frames matching the explicit
 *     inbound selector of an exact interface/IP/MAC administrator-approved
 *     LAN peer binding;
 *   - checksum-valid, unfragmented replies to short-lived IPv4 flows observed
 *     by the TC egress program, and only when the Ethernet source is the
 *     pinned WAN gateway or an outbound-approved exact LAN peer binding on
 *     that interface;
 *   - EAPOL, which is required for WPA-Enterprise / wired 802.1X;
 *   - structurally valid DHCPv4 server replies matching an exact, short-lived
 *     (interface, transaction ID, BOOTP chaddr) request observed at TC egress;
 *   - structurally valid standard ARP. RFC 5227 Address Conflict Detection
 *     requires requests, replies, probes and announcements to reach the
 *     kernel; permanent neighbour pins provide gateway/peer anti-replacement.
 *
 * The global LAN opt-in is an explicit map bit. It is controlled by the same
 * root transaction as firewalld, topology, WAN-strict and ARP state.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define NOID_EAPOL_ETHERTYPE 0x888e
#define NOID_DHCP_MAGIC 0x63825363
#define NOID_ARPHRD_ETHER 1
#define NOID_ARPOP_REQUEST 1
#define NOID_ARPOP_REPLY 2
#define NOID_ICMP_ECHOREPLY 0
#define NOID_ICMP_DEST_UNREACH 3
#define NOID_ICMP_ECHO 8
#define NOID_ICMP_TIME_EXCEEDED 11
#define NOID_TCP_FLOW_NS (2ULL * 60 * 60 * 1000000000)
#define NOID_UDP_FLOW_NS (5ULL * 60 * 1000000000)
#define NOID_ICMP_FLOW_NS (60ULL * 1000000000)
#define NOID_DHCP_FLOW_NS (90ULL * 1000000000)
#define NOID_IPV4_MAX_LEN 1500
#define NOID_IP_RF 0x8000
#define NOID_IP_MF 0x2000
#define NOID_IP_OFFSET 0x1fff
#define NOID_PEER_OUTBOUND 0x01
#define NOID_PEER_INBOUND 0x02

enum noid_xdp_stat {
    NOID_XDP_PASS_GLOBAL = 0,
    NOID_XDP_PASS_PEER = 1,
    NOID_XDP_PASS_EAPOL = 2,
    NOID_XDP_PASS_DHCP = 3,
    NOID_XDP_PASS_ARP_STANDARD = 4,
    NOID_XDP_PASS_FLOW = 5,
    NOID_XDP_PASS_ICMP_ERROR = 6,
    NOID_XDP_DROP_FRAGMENT = 7,
    NOID_XDP_DROP_DEFAULT = 8,
    NOID_XDP_STAT_MAX = 9,
};

struct noid_mac {
    __u8 addr[ETH_ALEN];
};

struct noid_link_mac {
    __u32 ifindex;
    struct noid_mac mac;
    __u8 pad[2];
};

struct noid_peer4 {
    __u32 ifindex;
    __be32 ip;
    struct noid_mac mac;
    __u8 pad[2];
};

struct noid_peer4_policy {
    __u8 direction;
    __u8 protocol;
    __u16 port_start;
    __u16 port_end;
    __u8 pad[2];
};

struct noid_dhcp4 {
    __u32 ifindex;
    __be32 xid;
    struct noid_mac mac;
    __u8 pad[2];
};

struct noid_flow4 {
    __u32 ifindex;
    __be32 remote_ip;
    __be32 local_ip;
    __be16 remote_port;
    __be16 local_port;
    __u8 protocol;
    __u8 pad[3];
};

struct noid_expiry {
    __u64 expires_ns;
};

/* UAPI headers do not expose struct vlan_hdr consistently across distros. */
struct noid_vlan_hdr {
    __be16 tci;
    __be16 encapsulated_proto;
} __attribute__((packed));

struct noid_arphdr {
    __be16 hardware_type;
    __be16 protocol_type;
    __u8 hardware_len;
    __u8 protocol_len;
    __be16 operation;
} __attribute__((packed));

struct noid_arp_eth_ipv4 {
    struct noid_arphdr header;
    __u8 sender_mac[ETH_ALEN];
    __be32 sender_ip;
    __u8 target_mac[ETH_ALEN];
    __be32 target_ip;
} __attribute__((packed));

struct noid_dhcp_min {
    __u8 op;
    __u8 htype;
    __u8 hlen;
    __u8 hops;
    __be32 xid;
    __be16 secs;
    __be16 flags;
    __be32 ciaddr;
    __be32 yiaddr;
    __be32 siaddr;
    __be32 giaddr;
    __u8 chaddr[16];
    __u8 sname[64];
    __u8 file[128];
    __be32 magic;
} __attribute__((packed));

struct noid_eapol {
    __u8 version;
    __u8 type;
    __be16 body_length;
} __attribute__((packed));

struct noid_icmp_min {
    __u8 type;
    __u8 code;
    __be16 checksum;
    __be16 identifier;
    __be16 sequence;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct noid_link_mac);
    __type(value, __u8);
} noid_xdp_gateway_macs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct noid_peer4);
    __type(value, struct noid_peer4_policy);
} noid_xdp_peer4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, struct noid_link_mac);
    __type(value, __u8);
} noid_xdp_local_macs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 256);
    __type(key, struct noid_dhcp4);
    __type(value, struct noid_expiry);
} noid_xdp_dhcp_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct noid_flow4);
    __type(value, struct noid_expiry);
} noid_xdp_flows_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} noid_xdp_global_allow SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, NOID_XDP_STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} noid_xdp_stats SEC(".maps");

static __always_inline int noid_verdict(__u32 reason, int action)
{
    __u64 *counter = bpf_map_lookup_elem(&noid_xdp_stats, &reason);

    if (counter)
        *counter += 1;
    return action;
}

static __always_inline int noid_mac_is_present(void *map, __u32 ifindex,
                                                const __u8 addr[ETH_ALEN])
{
    struct noid_link_mac key = { .ifindex = ifindex };

    __builtin_memcpy(key.mac.addr, addr, ETH_ALEN);
    if (bpf_map_lookup_elem(map, &key))
        return 1;
    return 0;
}

static __always_inline int noid_mac_equal(const __u8 left[ETH_ALEN],
                                           const __u8 right[ETH_ALEN])
{
#pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        if (left[i] != right[i])
            return 0;
    }
    return 1;
}

static __always_inline int noid_mac_is_broadcast(const __u8 addr[ETH_ALEN])
{
#pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        if (addr[i] != 0xff)
            return 0;
    }
    return 1;
}

static __always_inline int noid_mac_is_unicast_source(const __u8 addr[ETH_ALEN])
{
    __u8 present = 0;

    if (addr[0] & 1)
        return 0;
#pragma unroll
    for (int i = 0; i < ETH_ALEN; i++)
        present |= addr[i];
    return present != 0;
}

/*
 * NetworkManager applies a stable/randomized cloned MAC before address
 * acquisition. The controller necessarily seeds the map earlier, while the
 * permanent hardware MAC is still active. TC egress is the first trusted
 * observation point after that transition: a source MAC on a frame that has
 * reached this physical egress qdisc is locally emitted, not LAN supplied.
 * Register it before the matching DHCP/ARP reply can reach XDP ingress.
 */
static __always_inline void noid_record_local_source_mac(
    __u32 ifindex, const __u8 addr[ETH_ALEN])
{
    struct noid_link_mac key = { .ifindex = ifindex };
    __u8 allowed = 1;

    if (!noid_mac_is_unicast_source(addr))
        return;
    __builtin_memcpy(key.mac.addr, addr, ETH_ALEN);
    if (!bpf_map_lookup_elem(&noid_xdp_local_macs, &key))
        bpf_map_update_elem(&noid_xdp_local_macs, &key, &allowed, BPF_ANY);
}

static __always_inline int noid_mac_is_eapol_group(const __u8 addr[ETH_ALEN])
{
    const __u8 group[ETH_ALEN] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03 };

    return noid_mac_equal(addr, group);
}

/*
 * Validate a complete Internet one's-complement checksum, including the
 * checksum field. Words are summed in host order; on little-endian BPF this
 * byte-swaps every word consistently, so a valid folded result is still
 * 0xffff. NOID_IPV4_MAX_LEN bounds both verifier work and hostile CPU cost.
 */
struct noid_checksum_loop {
    void *start;
    void *packet_end;
    __u32 length;
    __u32 sum;
    __u8 valid;
};

static long noid_checksum_step(__u32 index, void *opaque)
{
    struct noid_checksum_loop *state = opaque;
    __u32 offset;
    __u8 *cursor;
    __u16 word = 0;

    if (index >= (NOID_IPV4_MAX_LEN + 1) / 2)
        return 1;
    offset = index * 2;
    cursor = state->start + offset;
    if (offset >= state->length)
        return 1;
    if ((void *)(cursor + 1) > state->packet_end) {
        state->valid = 0;
        return 1;
    }
    if (offset + 1 < state->length) {
        if ((void *)(cursor + 2) > state->packet_end) {
            state->valid = 0;
            return 1;
        }
        __builtin_memcpy(&word, cursor, sizeof(word));
    } else {
        word = *cursor;
    }
    state->sum += word;
    return 0;
}

static __attribute__((noinline)) int noid_checksum_valid(
    void *start, __u32 length, void *packet_end, __u32 seed)
{
    struct noid_checksum_loop state = {
        .start = start,
        .packet_end = packet_end,
        .length = length,
        .sum = seed,
        .valid = 1,
    };
    long iterations;

    if (!length || length > NOID_IPV4_MAX_LEN)
        return 0;
    iterations = bpf_loop((length + 1) / 2, noid_checksum_step, &state, 0);
    if (iterations < 0 || !state.valid)
        return 0;
    state.sum = (state.sum & 0xffff) + (state.sum >> 16);
    state.sum = (state.sum & 0xffff) + (state.sum >> 16);
    return (__u16)state.sum == 0xffff;
}

static __attribute__((noinline)) int noid_ipv4_transport_checksum_valid(
    struct iphdr *ip, void *transport, __u16 transport_length,
    void *packet_end)
{
    __u16 *source = (__u16 *)&ip->saddr;
    __u16 *destination = (__u16 *)&ip->daddr;
    __u32 seed = source[0] + source[1] + destination[0] + destination[1];

    seed += bpf_htons((__u16)ip->protocol);
    seed += bpf_htons(transport_length);
    return noid_checksum_valid(transport, transport_length, packet_end, seed);
}

static __always_inline struct noid_peer4_policy *noid_peer4_policy(
    __u32 ifindex, __be32 ip, const __u8 addr[ETH_ALEN])
{
    struct noid_peer4 key = { .ifindex = ifindex, .ip = ip };

    __builtin_memcpy(key.mac.addr, addr, ETH_ALEN);
    return bpf_map_lookup_elem(&noid_xdp_peer4, &key);
}

static __always_inline int noid_flow4_is_live(struct noid_flow4 *key)
{
    struct noid_expiry *value;

    value = bpf_map_lookup_elem(&noid_xdp_flows_v4, key);
    if (!value)
        return 0;
    if (value->expires_ns > bpf_ktime_get_ns())
        return 1;
    bpf_map_delete_elem(&noid_xdp_flows_v4, key);
    return 0;
}

static __always_inline int noid_dhcp4_is_live(__u32 ifindex, __be32 xid,
                                               const __u8 chaddr[ETH_ALEN])
{
    struct noid_dhcp4 key = { .ifindex = ifindex, .xid = xid };
    struct noid_expiry *value;

    __builtin_memcpy(key.mac.addr, chaddr, ETH_ALEN);
    value = bpf_map_lookup_elem(&noid_xdp_dhcp_v4, &key);
    if (!value)
        return 0;
    if (value->expires_ns > bpf_ktime_get_ns())
        return 1;
    bpf_map_delete_elem(&noid_xdp_dhcp_v4, &key);
    return 0;
}

SEC("xdp")
int noid_lan_xdp(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    void *network;
    __be16 protocol;
    __u32 zero = 0;
    __u8 *global;
    int from_gateway;

    if ((void *)(eth + 1) > data_end)
        return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);

    global = bpf_map_lookup_elem(&noid_xdp_global_allow, &zero);
    if (global && *global)
        return noid_verdict(NOID_XDP_PASS_GLOBAL, XDP_PASS);

    from_gateway = noid_mac_is_present(&noid_xdp_gateway_macs,
                                       ctx->ingress_ifindex,
                                       eth->h_source);

    protocol = eth->h_proto;
    network = eth + 1;

    /* Accept up to two 802.1Q/802.1ad tags before the real EtherType. */
#pragma unroll
    for (int i = 0; i < 2; i++) {
        struct noid_vlan_hdr *vlan;

        if (protocol != bpf_htons(ETH_P_8021Q) &&
            protocol != bpf_htons(ETH_P_8021AD))
            break;
        vlan = network;
        if ((void *)(vlan + 1) > data_end)
            return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
        protocol = vlan->encapsulated_proto;
        network = vlan + 1;
    }

    /* A third VLAN tag is outside the release-qualified link contract. */
    if (protocol == bpf_htons(ETH_P_8021Q) ||
        protocol == bpf_htons(ETH_P_8021AD))
        return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);

    if (protocol == bpf_htons(NOID_EAPOL_ETHERTYPE)) {
        struct noid_eapol *eapol = network;
        __u16 body_length;

        if ((void *)(eapol + 1) > data_end ||
            !noid_mac_is_unicast_source(eth->h_source) ||
            (!noid_mac_is_eapol_group(eth->h_dest) &&
             !noid_mac_is_present(&noid_xdp_local_macs,
                                  ctx->ingress_ifindex, eth->h_dest)) ||
            eapol->version < 1 || eapol->version > 3 || eapol->type > 4)
            return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
        body_length = bpf_ntohs(eapol->body_length);
        if ((void *)(eapol + 1) + body_length > data_end)
            return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
        return noid_verdict(NOID_XDP_PASS_EAPOL, XDP_PASS);
    }

    if (protocol == bpf_htons(ETH_P_ARP)) {
        struct noid_arp_eth_ipv4 *arp = network;
        __u16 operation;

        if ((void *)(arp + 1) > data_end)
            return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
        if (arp->header.hardware_type != bpf_htons(NOID_ARPHRD_ETHER) ||
            arp->header.protocol_type != bpf_htons(ETH_P_IP) ||
            arp->header.hardware_len != ETH_ALEN ||
            arp->header.protocol_len != sizeof(__be32))
            return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
        if (!noid_mac_is_unicast_source(eth->h_source) ||
            !noid_mac_equal(eth->h_source, arp->sender_mac))
            return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
        operation = bpf_ntohs(arp->header.operation);
        if (operation == NOID_ARPOP_REQUEST) {
            /* RFC 826 ignores target_mac in a request. Broadcast Probes and
             * Announcements plus valid unicast requests must reach native
             * IPv4 ACD and ordinary neighbour handling. */
            if (!noid_mac_is_broadcast(eth->h_dest) &&
                !noid_mac_is_present(&noid_xdp_local_macs,
                                     ctx->ingress_ifindex, eth->h_dest))
                return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
            return noid_verdict(NOID_XDP_PASS_ARP_STANDARD, XDP_PASS);
        }
        if (operation == NOID_ARPOP_REPLY) {
            /* Unicast replies correlate both Ethernet/ARP target MACs.
             * RFC 5227 also permits broadcast replies; their ARP target must
             * still be one of this interface's local MACs. */
            if (!noid_mac_is_present(&noid_xdp_local_macs,
                                     ctx->ingress_ifindex, arp->target_mac))
                return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
            if (!noid_mac_is_broadcast(eth->h_dest) &&
                (!noid_mac_equal(eth->h_dest, arp->target_mac) ||
                 !noid_mac_is_present(&noid_xdp_local_macs,
                                      ctx->ingress_ifindex, eth->h_dest)))
                return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
            return noid_verdict(NOID_XDP_PASS_ARP_STANDARD, XDP_PASS);
        }
        return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
    }

    if (protocol == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = network;
        __u32 ihl;
        __u16 total_length;
        __u16 payload_length;
        __u16 fragment;
        void *ip_end;
        struct noid_peer4_policy *peer_policy;
        int peer_present;
        int peer_outbound;
        int peer_inbound;
        int gateway_flow_authorized;
        __u8 peer_protocol = 0;
        __u16 peer_port_start = 0;
        __u16 peer_port_end = 0;
        int link_authorized;
        struct udphdr *udp;
        struct noid_dhcp_min *dhcp;
        struct noid_flow4 flow = {};

        if ((void *)ip + sizeof(struct iphdr) > data_end)
            return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
        if (ip->version != 4)
            return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
        ihl = ip->ihl * 4;
        if (ihl < sizeof(struct iphdr) || ihl > 60 ||
            (void *)ip + ihl > data_end)
            return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
        total_length = bpf_ntohs(ip->tot_len);
        if (total_length < ihl || total_length > NOID_IPV4_MAX_LEN ||
            (void *)ip + total_length > data_end || ip->ttl == 0 ||
            !noid_mac_is_unicast_source(eth->h_source) ||
            !noid_checksum_valid(ip, ihl, data_end, 0))
            return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
        ip_end = (void *)ip + total_length;
        payload_length = total_length - ihl;

        fragment = bpf_ntohs(ip->frag_off);
        if (fragment & (NOID_IP_RF | NOID_IP_MF | NOID_IP_OFFSET))
            return noid_verdict(NOID_XDP_DROP_FRAGMENT, XDP_DROP);

        peer_policy = noid_peer4_policy(ctx->ingress_ifindex, ip->saddr,
                                        eth->h_source);
        peer_present = peer_policy != 0;
        peer_outbound = 0;
        peer_inbound = 0;
        if (peer_policy) {
            peer_outbound = (peer_policy->direction & NOID_PEER_OUTBOUND) != 0;
            peer_inbound = (peer_policy->direction & NOID_PEER_INBOUND) != 0;
            peer_protocol = peer_policy->protocol;
            peer_port_start = peer_policy->port_start;
            peer_port_end = peer_policy->port_end;
        }
        /* An exact peer policy is more specific than the interface gateway
         * MAC role. This prevents a gateway/peer MAC overlap from widening an
         * inbound-only peer through correlated outbound-flow admission. */
        gateway_flow_authorized = from_gateway && !peer_present;
        link_authorized = 0;
        if (noid_mac_is_present(&noid_xdp_local_macs,
                                ctx->ingress_ifindex, eth->h_dest)) {
            if (peer_present)
                link_authorized = 1;
            else if (from_gateway)
                link_authorized = 1;
        }

        if (ip->protocol == IPPROTO_UDP) {
            __u16 udp_length;
            int is_dhcp;

            udp = (void *)ip + ihl;
            if (payload_length < sizeof(*udp) ||
                (void *)(udp + 1) > data_end ||
                (void *)(udp + 1) > ip_end)
                return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
            udp_length = bpf_ntohs(udp->len);
            is_dhcp = udp->source == bpf_htons(67) &&
                      udp->dest == bpf_htons(68);
            if (!is_dhcp && !link_authorized)
                return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
            if (udp_length < sizeof(*udp) || udp_length != payload_length ||
                udp->check == 0 ||
                !noid_ipv4_transport_checksum_valid(ip, udp, udp_length,
                                                     data_end))
                return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);

            /* DHCP is the only pre-gateway IPv4 ingress bootstrap. */
            if (is_dhcp) {
                dhcp = (void *)(udp + 1);
                if ((void *)(dhcp + 1) > data_end ||
                    (void *)(dhcp + 1) > ip_end || dhcp->op != 2 ||
                    dhcp->htype != NOID_ARPHRD_ETHER ||
                    dhcp->hlen != ETH_ALEN ||
                    dhcp->magic != bpf_htonl(NOID_DHCP_MAGIC) ||
                    !noid_mac_is_present(&noid_xdp_local_macs,
                                         ctx->ingress_ifindex,
                                         dhcp->chaddr) ||
                    (!noid_mac_is_broadcast(eth->h_dest) &&
                     !noid_mac_equal(eth->h_dest, dhcp->chaddr)))
                    return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
                if (noid_dhcp4_is_live(ctx->ingress_ifindex, dhcp->xid,
                                       dhcp->chaddr))
                    return noid_verdict(NOID_XDP_PASS_DHCP, XDP_PASS);
                return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
            }

            if (peer_inbound && peer_protocol == IPPROTO_UDP &&
                bpf_ntohs(udp->dest) >= peer_port_start &&
                bpf_ntohs(udp->dest) <= peer_port_end)
                return noid_verdict(NOID_XDP_PASS_PEER, XDP_PASS);

            flow.ifindex = ctx->ingress_ifindex;
            flow.remote_ip = ip->saddr;
            flow.local_ip = ip->daddr;
            flow.remote_port = udp->source;
            flow.local_port = udp->dest;
            flow.protocol = IPPROTO_UDP;
        } else if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)ip + ihl;
            __u32 tcp_header_length;

            if (payload_length < sizeof(*tcp) ||
                (void *)(tcp + 1) > data_end ||
                (void *)(tcp + 1) > ip_end)
                return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
            tcp_header_length = tcp->doff * 4;
            if (tcp_header_length < sizeof(*tcp) ||
                tcp_header_length > payload_length || tcp->res1 != 0 ||
                !link_authorized ||
                !noid_ipv4_transport_checksum_valid(ip, tcp, payload_length,
                                                     data_end))
                return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
            if (peer_inbound && peer_protocol == IPPROTO_TCP &&
                bpf_ntohs(tcp->dest) >= peer_port_start &&
                bpf_ntohs(tcp->dest) <= peer_port_end)
                return noid_verdict(NOID_XDP_PASS_PEER, XDP_PASS);
            flow.ifindex = ctx->ingress_ifindex;
            flow.remote_ip = ip->saddr;
            flow.local_ip = ip->daddr;
            flow.remote_port = tcp->source;
            flow.local_port = tcp->dest;
            flow.protocol = IPPROTO_TCP;
        } else if (ip->protocol == IPPROTO_ICMP) {
            struct noid_icmp_min *icmp = (void *)ip + ihl;

            if (payload_length < sizeof(*icmp) ||
                (void *)(icmp + 1) > data_end ||
                (void *)(icmp + 1) > ip_end ||
                !link_authorized ||
                !noid_checksum_valid(icmp, payload_length, data_end, 0))
                return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
            if (icmp->type == NOID_ICMP_ECHOREPLY) {
                if (icmp->code != 0)
                    return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
                flow.ifindex = ctx->ingress_ifindex;
                flow.remote_ip = ip->saddr;
                flow.local_ip = ip->daddr;
                flow.remote_port = icmp->identifier;
                flow.protocol = IPPROTO_ICMP;
            } else if (icmp->type == NOID_ICMP_DEST_UNREACH ||
                       icmp->type == NOID_ICMP_TIME_EXCEEDED) {
                struct iphdr *inner = (void *)(icmp + 1);
                __u32 inner_ihl;
                __u16 inner_fragment;

                if ((void *)(inner + 1) > data_end ||
                    (void *)(inner + 1) > ip_end || inner->version != 4 ||
                    (icmp->type == NOID_ICMP_DEST_UNREACH &&
                     icmp->code > 15) ||
                    (icmp->type == NOID_ICMP_TIME_EXCEEDED &&
                     icmp->code > 1))
                    return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
                inner_ihl = inner->ihl * 4;
                if (inner_ihl < sizeof(*inner) ||
                    (void *)inner + inner_ihl + 8 > ip_end ||
                    bpf_ntohs(inner->tot_len) < inner_ihl + 8 ||
                    !noid_checksum_valid(inner, inner_ihl, data_end, 0))
                    return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
                inner_fragment = bpf_ntohs(inner->frag_off);
                if (inner_fragment & (NOID_IP_RF | NOID_IP_OFFSET))
                    return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
                flow.ifindex = ctx->ingress_ifindex;
                flow.remote_ip = inner->daddr;
                flow.local_ip = inner->saddr;
                flow.protocol = inner->protocol;
                if (inner->protocol == IPPROTO_TCP ||
                    inner->protocol == IPPROTO_UDP) {
                    __be16 *ports = (void *)inner + inner_ihl;

                    /* Keep a verifier-visible packet-pointer bounds check;
                     * otherwise LLVM folds it into the already proven scalar
                     * inner-length relation, which the verifier cannot link
                     * back to this variable-offset pointer. */
                    asm volatile("" : "+r"(ports));
                    if ((void *)(ports + 2) > data_end)
                        return noid_verdict(NOID_XDP_DROP_DEFAULT,
                                             XDP_DROP);
                    flow.local_port = ports[0];
                    flow.remote_port = ports[1];
                } else {
                    return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
                }
                if ((gateway_flow_authorized || peer_outbound) &&
                    noid_flow4_is_live(&flow))
                    return noid_verdict(NOID_XDP_PASS_ICMP_ERROR,
                                         XDP_PASS);
                return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
            } else {
                return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
            }
        } else {
            return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
        }

        if ((gateway_flow_authorized || peer_outbound) &&
            noid_flow4_is_live(&flow)) {
            return noid_verdict(NOID_XDP_PASS_FLOW, XDP_PASS);
        }
    }

    return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
}

/*
 * Record only packets that reached the physical egress qdisc. Socket-originated
 * IP traffic has already passed the nftables/firewalld output hooks here;
 * AF_PACKET senders (NetworkManager's DHCP client, any CAP_NET_RAW process)
 * bypass those hooks but not this qdisc. XDP can therefore admit only the
 * reverse tuple, for a bounded time, before AF_PACKET delivery. Ingress never
 * refreshes a flow lifetime.
 */
SEC("tc")
int noid_lan_egress(struct __sk_buff *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    void *network;
    __be16 protocol;
    struct iphdr *ip;
    __u32 ihl;
    __u16 fragment;
    struct noid_flow4 flow = {};
    struct noid_expiry value = {};

    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    noid_record_local_source_mac(ctx->ifindex, eth->h_source);
    protocol = eth->h_proto;
    network = eth + 1;

#pragma unroll
    for (int i = 0; i < 2; i++) {
        struct noid_vlan_hdr *vlan;

        if (protocol != bpf_htons(ETH_P_8021Q) &&
            protocol != bpf_htons(ETH_P_8021AD))
            break;
        vlan = network;
        if ((void *)(vlan + 1) > data_end)
            return TC_ACT_OK;
        protocol = vlan->encapsulated_proto;
        network = vlan + 1;
    }
    if (protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    ip = network;
    if ((void *)ip + sizeof(*ip) > data_end || ip->version != 4)
        return TC_ACT_OK;
    ihl = ip->ihl * 4;
    if (ihl < sizeof(*ip) || (void *)ip + ihl > data_end)
        return TC_ACT_OK;
    fragment = bpf_ntohs(ip->frag_off);
    if ((fragment & NOID_IP_OFFSET) != 0)
        return TC_ACT_OK;

    flow.ifindex = ctx->ifindex;
    flow.remote_ip = ip->daddr;
    flow.local_ip = ip->saddr;
    flow.protocol = ip->protocol;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ihl;

        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        flow.remote_port = tcp->dest;
        flow.local_port = tcp->source;
        value.expires_ns = bpf_ktime_get_ns() + NOID_TCP_FLOW_NS;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ihl;

        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        if (udp->source == bpf_htons(68) && udp->dest == bpf_htons(67)) {
            struct noid_dhcp_min *dhcp = (void *)(udp + 1);
            struct noid_dhcp4 dhcp_key = { .ifindex = ctx->ifindex };
            struct noid_expiry dhcp_expiry = {
                .expires_ns = bpf_ktime_get_ns() + NOID_DHCP_FLOW_NS,
            };

            if ((void *)(dhcp + 1) > data_end || dhcp->op != 1 ||
                dhcp->htype != NOID_ARPHRD_ETHER ||
                dhcp->hlen != ETH_ALEN ||
                dhcp->magic != bpf_htonl(NOID_DHCP_MAGIC))
                return TC_ACT_OK;
            dhcp_key.xid = dhcp->xid;
            __builtin_memcpy(dhcp_key.mac.addr, dhcp->chaddr, ETH_ALEN);
            bpf_map_update_elem(&noid_xdp_dhcp_v4, &dhcp_key, &dhcp_expiry,
                                BPF_ANY);
        }
        flow.remote_port = udp->dest;
        flow.local_port = udp->source;
        value.expires_ns = bpf_ktime_get_ns() + NOID_UDP_FLOW_NS;
    } else if (ip->protocol == IPPROTO_ICMP) {
        struct noid_icmp_min *icmp = (void *)ip + ihl;

        if ((void *)(icmp + 1) > data_end ||
            icmp->type != NOID_ICMP_ECHO)
            return TC_ACT_OK;
        flow.remote_port = icmp->identifier;
        value.expires_ns = bpf_ktime_get_ns() + NOID_ICMP_FLOW_NS;
    } else {
        return TC_ACT_OK;
    }

    bpf_map_update_elem(&noid_xdp_flows_v4, &flow, &value, BPF_ANY);
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
NOID_LAN_XDP_SOURCE_EOF
verify_license_digest "$NOID_LAN_XDP_SOURCE_SHA256" "$DOC_TMP" \
    || die "staged XDP source differs from its pinned SHA-256"
publish_doc "$XDP_SOURCE_DIR/noid-lan-xdp.bpf.c" "$XDP_SOURCE_DIR"

NOID_LAN_XDP_BUILD_SCRIPT_SHA256=d90bf55b5f0282621056dd845c50b9edad9078bea56f01d56bf773086c1bc496
DOC_TMP=$(mktemp "$XDP_SOURCE_DIR/.build-lan-xdp-object.sh.XXXXXXXX")
cat > "$DOC_TMP" <<'NOID_LAN_XDP_BUILD_SCRIPT_EOF'
#!/usr/bin/env bash
# Reproducibly compile and verify the NoID Privacy physical-link BPF payload.
# Run inside an updated Fedora 44 environment with clang, libbpf-devel,
# binutils and bpftool installed.
# Usage: scripts/build-lan-xdp-object.sh [--check]
set -euo pipefail
export LC_ALL=C.UTF-8
export PATH=/usr/sbin:/usr/bin

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE="$REPO_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.c"
SOURCE_DIR="${SOURCE%/*}"
OBJECT_B64="$REPO_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.o.b64"
CONTROLLER="$REPO_ROOT/overrides/noid-lan-xdp/noid-lan-xdp.sh"
MODE=build
case "$#:${1:-}" in
    0:) ;;
    1:--check) MODE=check ;;
    1:-h|1:--help)
        echo "Usage: scripts/build-lan-xdp-object.sh [--check]"
        exit 0
        ;;
    *)
        echo "Usage: scripts/build-lan-xdp-object.sh [--check]" >&2
        exit 2
        ;;
esac

log() { echo "[build-lan-xdp-object] $*"; }
for command in clang strip base64 sha256sum; do
    command -v "$command" >/dev/null 2>&1 || {
        log "ERROR: missing build command: $command"
        exit 2
    }
done
if [ ! -r /etc/os-release ] \
   || ! grep -qE '^VERSION_ID="?44"?$' /etc/os-release \
   || ! grep -qE '^(ID|ID_LIKE)=.*fedora' /etc/os-release; then
    log "ERROR: the pinned object must be built on Fedora 44"
    exit 2
fi

tmp=$(mktemp /var/tmp/noid-lan-xdp-object.XXXXXX)
verify_root=''
controller_candidate=''
object_candidate=''
trap '[ -z "$verify_root" ] || rm -rf "$verify_root"; rm -f "$tmp" "$controller_candidate" "$object_candidate"' EXIT
clang -target bpf -O2 -g -Wall -Wextra -Werror \
    -fdebug-prefix-map="$SOURCE_DIR=/usr/src/noid-privacy-fedora" \
    -c "$SOURCE" -o "$tmp"
# Remove host/toolchain DWARF while retaining BTF/BTF.ext required for typed
# maps and verifier diagnostics. GNU binutils strip on Fedora supports eBPF.
strip --strip-debug "$tmp"
hash=$(sha256sum "$tmp" | awk '{print $1}')

if [ "$(id -u)" -eq 0 ] && command -v bpftool >/dev/null 2>&1 \
   && mountpoint -q /sys/fs/bpf; then
    verify_root="/sys/fs/bpf/noid_lan_xdp_verify_${$}"
    mkdir -p "$verify_root/progs" "$verify_root/maps"
    bpftool prog loadall "$tmp" "$verify_root/progs" pinmaps "$verify_root/maps"
    rm -rf "$verify_root"
    verify_root=''
    log "kernel verifier accepted both programs"
else
    log "NOTICE: kernel verifier skipped (requires root, bpftool and bpffs)"
fi

current_hash=$(base64 -d "$OBJECT_B64" | sha256sum | awk '{print $1}')
mapfile -t controller_hashes < <(
    sed -n 's/^OBJECT_SHA256=\([0-9a-f]\{64\}\)$/\1/p' "$CONTROLLER"
)
[ "${#controller_hashes[@]}" -eq 1 ] || {
    log "ERROR: controller has no unique object hash"
    exit 3
}
controller_hash=${controller_hashes[0]}
if [ "$MODE" = check ]; then
    [ "$controller_hash" = "$current_hash" ] || {
        log "DRIFT: controller hash and repository object disagree"
        exit 1
    }
    [ "$hash" = "$current_hash" ] || {
        log "DRIFT: rebuilt $hash, repository pins $current_hash"
        exit 1
    }
    log "REPRODUCIBLE: rebuilt object matches $hash"
    exit 0
fi
if [ "$controller_hash" != "$current_hash" ]; then
    log "NOTICE: repairing an interrupted object/controller publication"
fi

object_candidate=$(mktemp "${OBJECT_B64}.tmp.XXXXXX")
chmod --reference="$OBJECT_B64" "$object_candidate"
base64 -w76 "$tmp" > "$object_candidate"
[ "$(base64 -d "$object_candidate" | sha256sum | awk '{print $1}')" = "$hash" ] \
    || { log "ERROR: staged base64 object digest mismatch"; exit 4; }

controller_candidate=$(mktemp "${CONTROLLER}.tmp.XXXXXX")
chmod --reference="$CONTROLLER" "$controller_candidate"
sed "s/^OBJECT_SHA256=${controller_hash}$/OBJECT_SHA256=${hash}/" \
    "$CONTROLLER" > "$controller_candidate"
[ "$(grep -Fxc "OBJECT_SHA256=$hash" "$controller_candidate" || true)" -eq 1 ] \
    || { log "ERROR: staged controller has no unique updated digest"; exit 4; }
bash -n "$controller_candidate" \
    || { log "ERROR: staged controller is invalid Bash"; exit 4; }

mv -T "$object_candidate" "$OBJECT_B64"
object_candidate=''
mv -T "$controller_candidate" "$CONTROLLER"
controller_candidate=''
"$REPO_ROOT/scripts/regen-lan-xdp-embed.sh"
log "updated object, controller hash and M03 embed: $hash"
NOID_LAN_XDP_BUILD_SCRIPT_EOF
verify_license_digest "$NOID_LAN_XDP_BUILD_SCRIPT_SHA256" "$DOC_TMP" \
    || die "staged XDP build script differs from its pinned SHA-256"
publish_doc "$XDP_SOURCE_DIR/build-lan-xdp-object.sh" "$XDP_SOURCE_DIR"
log "  [OK] GPL-2.0 XDP corresponding source installed in $XDP_SOURCE_DIR"

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

verify_owned_directory() {
    local path="$1"
    [ -d "$path" ] &&
        [ ! -L "$path" ] &&
        [ "$(stat -Lc '%u:%g:%a' -- "$path" 2>/dev/null)" = "0:0:755" ] &&
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

# License texts: exact metadata and the generator-pinned digests.
for pair in \
    "COPYING:$NOID_GPL3_LICENSE_SHA256" \
    "GPL-2.0.txt:$NOID_GPL2_LICENSE_SHA256"; do
    f="${pair%%:*}"
    digest="${pair#*:}"
    path="$LICENSE_DIR/$f"
    check "license text $f regular root:root 0644 link-count=1" \
        verify_owned_regular "$path" 644
    check "license text $f matches its pinned SHA-256" \
        verify_license_digest "$digest" "$path"
done

# Corresponding source of the XDP object: exact metadata and pinned digests.
for source_dir in /usr/share/noid-privacy "$XDP_SOURCE_PARENT" "$XDP_SOURCE_DIR"; do
    check "source directory $source_dir real root:root 0755 with its context" \
        verify_owned_directory "$source_dir"
done
for pair in \
    "noid-lan-xdp.bpf.c:$NOID_LAN_XDP_SOURCE_SHA256" \
    "build-lan-xdp-object.sh:$NOID_LAN_XDP_BUILD_SCRIPT_SHA256"; do
    f="${pair%%:*}"
    digest="${pair#*:}"
    path="$XDP_SOURCE_DIR/$f"
    check "XDP source $f regular root:root 0644 link-count=1" \
        verify_owned_regular "$path" 644
    check "XDP source $f matches its pinned SHA-256" \
        verify_license_digest "$digest" "$path"
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
# Case-insensitive literal grep -Fqi (the robust direct-file pattern).
for kw in "Decision tree" "noid-status" "journalctl" "systemctl --failed" "SELinux" "audit2allow" "AIDE" "Forgot LUKS" "emergency.target" "Reporting a real bug"; do
    check "99-troubleshooting references: $kw" \
        grep -Fqi -- "$kw" /usr/share/doc/noid-privacy/99-troubleshooting.md
done

# Architecture markers — keyword stays GENERIC "Module structure" (a
# hardcoded module-count keyword drifted when modules were added; the
# generic form survives future count changes). Literal grep -Fqi.
for kw in "Module structure" "Silent-Machine" "Defense in depth" "Neutral image" "Reversibility" "Source-of-truth" "Threat model" "Dependency ordering" "kickstart/snippets/"; do
    check "00-architecture references: $kw" \
        grep -Fqi -- "$kw" /usr/share/doc/noid-privacy/00-architecture.md
done

# References to existing docs (not dead links)
# Case-insensitive literal grep -Fqi (the robust direct-file pattern).
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

# ==============================================================================
# Module 20 — Snapper Snapshots + CLI Rollback
# Status: LOCKED 2026-08-02 (v47) — provide the Snapper plugin boundary.
#
# Scope: explicit Btrfs rollback snapshots plus checked CLI rollback from a
# working boot or a writable installed-system recovery shell. The boot chain
# mounts the Btrfs default subvolume; no bootable GRUB snapshot entries are
# shipped.
#
# Covers:
#   - Step 1: M01 prerequisite check (installonly_limit=3 — retains three
#     recent /boot kernels for rollback compatibility)
#   - Step 2: /etc/snapper/configs/root (SNAPPER_ROOT_CONFIG_EOF heredoc):
#     explicit-only policy, TIMELINE off (privacy: no hourly FS-activity
#     fingerprint), independent NUMBER_LIMIT=50 count cleanup plus a 30-day
#     time-prune target, valid inactive quota hints and no non-root Snapper ACL;
#     registration via /etc/sysconfig/snapper sed
#   - Step 3: noid-snapper-init.{sh,service} idempotent boot gate — migrates
#     the boot chain once to the native Btrfs-default-subvolume contract,
#     mounts stable top-level `snapshots` and nodatacow `libvirt` subvolumes,
#     reconciles the exact `snapperd_data_t` state boundary, creates the
#     baseline snapshot and writes the completion marker only after every
#     layout/boot postcondition passes; later boots verify the exact marker,
#     labels and complete rollback model before M21 may run
#   - Step 10: root-owned noid-snapper-{create,status,rollback} helpers plus an
#     exact passwordless read-only status sudo rule; snapshot creation refuses
#     to start below the measured 5%/2-GiB operational free-space reserve
#   - Step 4: snapper-cleanup.{timer,service} drop-ins (installed-only;
#     OnCalendar=daily + Persistent)
#   - Step 11: 20-rollback-recovery.md (RECOVERY_DOC_EOF) — checked CLI guide
#   - Step 11b: noid-snap-pre ad-hoc standalone rollback-point helper
#     (SNAP_PRE_EOF; Snapper `single`, never an orphaned `pre`)
#   - Step 11d: /etc/logrotate.d/snapper uses maxage 30 + rotate 30 +
#     size->maxsize (maxage is evaluated at the weekly/size-triggered rotation,
#     so this is an age target rather than an exact 30-day deletion deadline)
#   - Step 11e: noid-snapper-prune.{sh,service,timer} — TIME-based 30-day
#     target (daily 07:40 +20min jitter; authoritative Snapper JSON; active or
#     default rollback roots are reported as protected and never mis-deleted)
#   - Steps 12-13: restorecon + verification
#
# Deliberate deviations (do NOT re-litigate):
#   - Scope reduced: the bootable GRUB snapshot layer was REMOVED
#     (boom profile/BLS entries, per-boot detection + zenity prompt, pkexec +
#     polkit rule, kernel-install options-restore hook, boom-boot package).
#     Rollback is CLI-only by design; bootable snapshot entries can return
#     natively via snapm once its btrfs backend ships. Do not re-add boom.
#   - dnf5 Actions auto-snapshots (pre/post per dnf transaction) are
#     deliberately NOT shipped: Silent-Machine = explicit user-invoked
#     rollback points; noid-update-all.sh covers upgrades, noid-snap-pre
#     covers ad-hoc operations; auto-Actions would add a retention candidate
#     for every short-lived dnf call. Users can opt in manually
#     via a libdnf5-plugins actions.d file.
#   - python3-dnf-plugin-snapper is EXCLUDED (legacy DNF4-only plugin that
#     DNF5 does not load; noid-snap-pre is the explicit replacement).
#     grub-btrfs is NEVER installed: it is outside this image's reviewed
#     Fedora-BLS/ext4-/boot CLI rollback contract. tests/20 pins both.
#   - /home and /boot are outside snapshot scope by design: home rollback
#     would destroy user work (opt-in config documented in the recovery
#     doc); /boot is ext4 — installonly_limit=3 covers the kernel side.
#   - No X-GNOME-Autostart-Phase key and no OnlyShowIn anywhere (GNOME 49+
#     rejects the autostart key; zenity/xdg-open are DE-agnostic) — tests/20
#     asserts the key never returns as an active line.
#   - No menu_auto_hide warning check: M01 reversed that decision (Speed-mode
#     hides the GRUB menu by default; Fedora reveals it with ESC/F8 — not
#     SHIFT, which is the Debian/Ubuntu keystatus patch).
#
# Constraint notes (keep when editing):
#   - Fedora's snapper reads /etc/sysconfig/snapper (SUSE-style) — a
#     /etc/default/snapper file is IGNORED (old orphan is removed in Step 2).
#   - snapper has NO config-level exclude: `EXCLUDE_PATTERN` is not a valid
#     key (silently ignored); the only real exclude is a separate btrfs
#     subvolume (snapper on / auto-excludes nested subvols). The config
#     heredoc documents this; tests/20 asserts the wording.
#   - Timer drop-in trap: an empty-value reset of one relative timer clears
#     ALL upstream relative timers (OnBootSec= included) — the drop-in resets
#     both explicitly, then sets OnCalendar=daily + Persistent=true (the
#     CLEANUP_TIMER_EOF heredoc documents the incident).
#   - %post chroot cannot reliably create subvols at / -> first-boot oneshot
#     with ConditionKernelCommandLine=!rd.live.image (live-ISO root is
#     overlay-on-squashfs, not btrfs).
#   - init-service sandbox deliberately SKIPS ProtectSystem=strict +
#     RestrictNamespaces + SystemCallFilter (would block `btrfs subvolume
#     create` at /).
#   - /etc/logrotate.d/snapper IS %config(noreplace): the Step-11d 30/30 policy
#     survives RPM upgrades — the vendor default lands as a .rpmnew file and
#     never replaces the modified policy. M99 build-verify asserts it at build.
#   - Non-root Snapper authorization is deliberately empty. `noid-status`
#     receives only fixed sanitized fields through the exact root-owned status
#     helper; arbitrary list/create/delete/rollback access is not granted.
#
# Cross-reference:
#   - M01: installonly_limit=3 + GRUB_TIMEOUT. M13: AIDE /.snapshots
#     exclusion + noid-status snapshot count. M25: pre-update snapshot
#     integration. M42: forensic-retention pair
#     (wtmp/btmp logrotate). M99: cross-module verify.
# ==============================================================================

%packages --exclude-weakdeps
snapper
# python3-snapper was removed from F44 (snapper migrated to D-Bus interface
# only — Python bindings dropped upstream). The CLI `snapper` binary is what
# noid-update-all.sh uses; the python module was only ever an internal
# convenience that no NoID Privacy code depended on.
# Legacy Python DNF4 plugin; DNF5 does not load it. Exclude its unused
# python3-dnf dependency chain and automatic per-DNF4-transaction snapshots.
-python3-dnf-plugin-snapper
# grub-btrfs is outside the reviewed Fedora-BLS/ext4-/boot CLI recovery model.
-grub-btrfs
%end

%post --erroronfail --log=/var/log/ks-20-snapper.log
set -euo pipefail

echo "[Module 20] Snapper snapshots + CLI rollback — start"

# ============================================================================
# Step 1 — Verify prerequisites from Module 01
# ============================================================================

# Module 01 must have set one exact installonly_limit=3 in dnf.conf. Rollback
# may need a still-installed kernel because /boot is outside the snapshot.
if [ "$(grep -cE '^[[:space:]]*installonly_limit[[:space:]]*=' \
        /etc/dnf/dnf.conf 2>/dev/null || true)" -ne 1 ] \
        || ! grep -qxF 'installonly_limit=3' /etc/dnf/dnf.conf; then
    echo "[Module 20] FAIL: required installonly_limit=3 is absent from /etc/dnf/dnf.conf"
    exit 1
fi

# No menu_auto_hide check here: M01 reversed that decision (Speed-mode hides
# the GRUB menu by default; reach it via ESC/F8 during POST).

# ============================================================================
# Step 2 — Create /etc/snapper/configs/root (explicit-only policy)
# ============================================================================

# We need the root filesystem subvol to exist. In kickstart %post, / is the
# actual target root. snapper create-config would set up a .snapshots subvol.
# BUT: in %post chroot the subvol creation may fail because we're mounted at /mnt/sysimage.
# Strategy: write config directly, create .snapshots subvol on first boot via oneshot.

# Fedora's snapper 0.13.0 build scans this configured libexec path before and
# after every snapshot operation, but the Fedora package does not own the
# terminal `plugins` directory. Upstream's package specification does. Keep an
# empty, root-owned directory so "no plugins installed" is a clean state rather
# than six caught ENOENT exceptions per snapshot creation. No hooks are shipped.
install -d -m 0755 -o root -g root /usr/libexec/snapper/plugins

# Write snapper config manually (skip snapper create-config which needs live fs)
mkdir -p /etc/snapper/configs
cat > /etc/snapper/configs/root <<'SNAPPER_ROOT_CONFIG_EOF'
# NoID Privacy — snapper config for root subvol
# Generated by Module 20 kickstart snippet
# Policy: explicit rollback points only; independent count cleanup +
#         measured 30-day prune target via noid-snapper-prune.timer

SUBVOLUME="/"
FSTYPE="btrfs"
QGROUP=""
# Qgroups are deliberately disabled: SPACE_LIMIT/FREE_LIMIT retain valid
# upstream defaults so Snapper can parse the config without warnings, but they
# are inactive without quota accounting and ranged NUMBER_LIMIT values.
# `/usr/libexec/noid-snapper-create` instead performs the measured preflight
# used by every NoID Privacy snapshot creator. It is a race-aware operational reserve,
# not a mathematical guarantee against concurrent filesystem growth.
SPACE_LIMIT="0.5"
FREE_LIMIT="0.2"

# Number cleanup (explicit update pairs, baseline and ad-hoc single points)
# Keep all Snapper operations root-only. The fixed noid-snapper-status helper
# exports only a sanitized count/boot-model/retention summary to Wheel users.
ALLOW_USERS=""
ALLOW_GROUPS=""
SYNC_ACL="no"
# NOTE: snapper has NO config-level exclude. `EXCLUDE_PATTERN` is
# NOT a valid snapper option — verified against the snapper 0.13.0 config-
# template (/usr/share/snapper/config-templates/default) + manpage; unknown
# keys are silently ignored, so the previous `EXCLUDE_PATTERN=…` line was a
# pure no-op (removed). To keep a path OUT of snapshots + comparison + cleanup
# it MUST be a separate btrfs subvolume — snapper running on `/` auto-excludes
# every nested subvolume. The /etc/snapper/filters/*.txt mechanism only hides
# paths from `snapper diff` OUTPUT; it does NOT affect snapshotting or cleanup.
# Implication: if libvirt/VM images are ever added, make /var/lib/libvirt a
# separate nodatacow subvolume (SUSE/Arch best practice) so VM runtime sockets
# can never break snapper's empty-pre-post comparison.
BACKGROUND_COMPARISON="yes"
NUMBER_CLEANUP="yes"
NUMBER_MIN_AGE="1800"
# NUMBER_LIMIT was raised from 5 to 50 and NUMBER_LIMIT_IMPORTANT from 3 to 5.
# The previous count limit trapped users who run several update phases in one
# day. Count cleanup and the NoID Privacy 30-day timer are independent bounds: at the
# documented low snapshot rate the age target can bind first, while frequent
# ad-hoc snapshots can make count cleanup remove the oldest eligible points
# before 30 days. NUMBER_MIN_AGE protects only the first 30 minutes. Snapper
# counts normal and important limits independently. `important=yes` affects
# count cleanup but is not an exception to the 30-day pruner. Active/default
# roots remain protected until another root is selected. Neither mechanism
# guarantees a minimum 30-day history; export long-term baselines off-host.
NUMBER_LIMIT="50"
NUMBER_LIMIT_IMPORTANT="5"

# Timeline OFF (privacy: no hourly filesystem activity fingerprinting)
TIMELINE_CREATE="no"
TIMELINE_CLEANUP="no"
TIMELINE_MIN_AGE="1800"
TIMELINE_LIMIT_HOURLY="0"
TIMELINE_LIMIT_DAILY="0"
TIMELINE_LIMIT_WEEKLY="0"
TIMELINE_LIMIT_MONTHLY="0"
TIMELINE_LIMIT_YEARLY="0"

# Empty pre/post pair cleanup
EMPTY_PRE_POST_CLEANUP="yes"
EMPTY_PRE_POST_MIN_AGE="1800"
SNAPPER_ROOT_CONFIG_EOF

chmod 640 /etc/snapper/configs/root
chown root:root /etc/snapper/configs/root

# Register the config where Fedora's snapper actually reads it:
# /etc/sysconfig/snapper (SUSE-style). A /etc/default/snapper file
# (Debian-style) is IGNORED entirely — without this sed, SNAPPER_CONFIGS=""
# stays empty and snapper list-configs returns nothing.
if [ -f /etc/sysconfig/snapper ]; then
    sed -i 's|^SNAPPER_CONFIGS="[^"]*"|SNAPPER_CONFIGS="root"|' /etc/sysconfig/snapper
fi
# Drop the Debian-style orphan from earlier image versions.
rm -f /etc/default/snapper

# ============================================================================
# Step 3 — Boot gate: first-boot bootstrap plus later contract verification
# ============================================================================

# snapper needs /.snapshots as a btrfs subvolume. We can't create it in %post
# chroot reliably (kickstart runs against /mnt/sysimage, subvol creation may
# have mount-point issues). Instead: oneshot service at first boot.

cat > /usr/local/bin/noid-snapper-init.sh <<'SNAPPER_INIT_EOF'
#!/bin/bash
#
# noid-snapper-init — idempotent Snapper bootstrap and boot-contract gate
#
# On the first installed boot it creates the stable subvolumes, validates the
# root config and creates the initial baseline snapshot. On every later boot
# it revalidates the private completion record and complete rollback model.
#
# Idempotency via the stable /.snapshots/.noid-state/init.done marker, which
# is outside every selectable root and therefore survives rollback.

set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH LC_ALL=C.UTF-8
unset BASH_ENV CDPATH ENV GLOBIGNORE PYTHONPATH PYTHONHOME

MARKER="/.snapshots/.noid-state/init.done"
LOG_TAG="noid-snapper-init"
TOP=/run/noid-snapper-top
fstab_new=''
boot_state_new=''

require_tools() {
    local tool
    for tool in "$@"; do
        command -v "$tool" >/dev/null 2>&1 || {
            printf '%s: ERROR: required tool missing: %s\n' \
                "$LOG_TAG" "$tool" >&2
            exit 1
        }
    done
}

# The filesystem probe and its journal diagnostic are needed even on a
# supported non-Btrfs installation, where the Snapper workflow exits cleanly.
require_tools findmnt logger

fail() {
    logger -t "$LOG_TAG" "ERROR: $*"
    exit 1
}

reconcile_snapshot_state_labels() {
    [ "$(findmnt --target /.snapshots -n -o TARGET 2>/dev/null)" = /.snapshots ] \
        && [ "$(findmnt --target /.snapshots -n -o FSROOT 2>/dev/null)" = /snapshots ] \
        && [ "$(findmnt --target /.snapshots -n -o FSTYPE 2>/dev/null)" = btrfs ] \
        || fail "stable snapshot-state mount is unavailable for SELinux reconciliation"
    [ -d /.snapshots ] && [ ! -L /.snapshots ] \
        && [ -d /.snapshots/.noid-state ] \
        && [ ! -L /.snapshots/.noid-state ] \
        && [ "$(stat -c '%u:%g:%a:%F' /.snapshots/.noid-state \
                2>/dev/null || true)" = '0:0:700:directory' ] \
        || fail "stable snapshot-state directories are unsafe"
    restorecon -F /.snapshots /.snapshots/.noid-state \
        || fail "stable snapshot-state SELinux reconciliation failed"
    matchpathcon -V /.snapshots >/dev/null \
        && matchpathcon -V /.snapshots/.noid-state >/dev/null \
        || fail "stable snapshot-state SELinux labels differ"
}

cleanup_init() {
    local rc=$? cleanup_failed=0
    trap - EXIT
    if command -v mountpoint >/dev/null 2>&1 && mountpoint -q "$TOP"; then
        if ! umount "$TOP"; then
            logger -t "$LOG_TAG" \
                "ERROR: temporary Btrfs top-level mount could not be removed"
            cleanup_failed=1
        fi
    fi
    if [ -n "$fstab_new" ] && ! rm -f -- "$fstab_new"; then
        logger -t "$LOG_TAG" "ERROR: unpublished fstab candidate cleanup failed"
        cleanup_failed=1
    fi
    if [ -n "$boot_state_new" ] && ! rm -f -- "$boot_state_new"; then
        logger -t "$LOG_TAG" "ERROR: unpublished boot-state candidate cleanup failed"
        cleanup_failed=1
    fi
    [ "$cleanup_failed" -eq 0 ] || [ "$rc" -ne 0 ] || rc=1
    exit "$rc"
}
trap cleanup_init EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# The supported Snapper classic rollback model requires a Btrfs root. A custom
# Anaconda layout may deliberately use another filesystem; that makes M20
# inapplicable, not a failed boot prerequisite for M21's topology-independent
# initramfs convergence. An unreadable root filesystem type remains a failure.
root_fstype=$(findmnt -n -o FSTYPE / 2>/dev/null) \
    || fail "cannot determine the root filesystem type"
if [ "$root_fstype" != btrfs ]; then
    non_btrfs_message="root filesystem is $root_fstype; Snapper bootstrap is not applicable"
    if ! logger -t "$LOG_TAG" "$non_btrfs_message"; then
        printf '%s: %s\n' "$LOG_TAG" "$non_btrfs_message" >&2
    fi
    exit 0
fi

# On Btrfs, the boot loader must mount the default subvolume. Anaconda
# initially emits both
# rootflags=subvol=root and an fstab subvol=root selector; either selector
# overrides Snapper's default. Migrate in a power-loss-safe order:
#   1. create/verify stable top-level data subvolumes and an fstab candidate;
#   2. make the currently running root the Btrfs default (old selectors still
#      boot it if power disappears here);
#   3. preflight the stable mounts, then publish fstab;
#   4. remove rootflags selectors from every current/future BLS source.
[ -f /etc/fstab ] && [ ! -L /etc/fstab ] \
    || fail "/etc/fstab is missing, non-regular or a symlink"
# Closed inventory for every PATH-resolved program used by the Btrfs path.
# Shell builtins and the separately authenticated /usr/libexec helpers are not
# repeated here.
require_tools awk btrfs chattr chmod chown cp find grep grubby install lsattr \
    matchpathcon mkdir mktemp mount mountpoint mv python3 restorecon rm snapper \
    stat sync systemctl tr umount
[ -x /usr/libexec/noid-rebind-firstboot-rootflags ] \
    || fail "M01 rootflags evidence handoff helper is unavailable"

# A valid completion record is not merely an existence marker. Revalidate its
# exact private bytes and the full live rollback contract on every boot before
# allowing the ordered M21 boot-image gate to proceed. This makes corruption
# or a stale/symlinked marker a visible failure instead of a condition-skip.
if [ -e "$MARKER" ] || [ -L "$MARKER" ]; then
    reconcile_snapshot_state_labels
    [ -f "$MARKER" ] && [ ! -L "$MARKER" ] && [ ! -s "$MARKER" ] \
        && [ "$(stat -c '%u:%g:%a:%h' "$MARKER" 2>/dev/null || true)" = \
            0:0:600:1 ] \
        || fail "completion marker is malformed or has unsafe metadata"
    matchpathcon -V "$MARKER" >/dev/null \
        || fail "completion marker SELinux label differs"
    [ -f /usr/libexec/noid-snapper-status ] \
        && [ ! -L /usr/libexec/noid-snapper-status ] \
        && [ -x /usr/libexec/noid-snapper-status ] \
        || fail "rollback-model verifier is missing or unsafe"
    completed_status=$(/usr/libexec/noid-snapper-status) \
        || fail "completed rollback model cannot be verified"
    case "$completed_status" in
        *' boot=ready '*) exit 0 ;;
        *) fail "completion marker exists but rollback model is not ready" ;;
    esac
fi

root_entries=$(awk '$1 !~ /^#/ && $2 == "/" {count++} END {print count+0}' /etc/fstab)
[ "$root_entries" -eq 1 ] || fail "expected exactly one root fstab entry, found $root_entries"
[ "$(awk '$1 !~ /^#/ && $2 == "/" {print NF}' /etc/fstab)" -ge 6 ] \
    || fail "root fstab entry is incomplete"
root_spec=$(awk '$1 !~ /^#/ && $2 == "/" {print $1}' /etc/fstab)
root_fstype=$(awk '$1 !~ /^#/ && $2 == "/" {print $3}' /etc/fstab)
root_opts=$(awk '$1 !~ /^#/ && $2 == "/" {print $4}' /etc/fstab)
[ "$root_fstype" = btrfs ] || fail "root fstab entry is not btrfs"
case "$root_spec" in *[[:space:]]*|'') fail "invalid root fstab source" ;; esac

selector_count=0
for opt in $(printf '%s\n' "$root_opts" | tr ',' ' '); do
    case "$opt" in
        subvol=root|subvol=/root) selector_count=$((selector_count + 1)) ;;
        subvol=*|subvolid=*) fail "unsupported root selector in fstab: $opt" ;;
    esac
done
[ "$selector_count" -le 1 ] || fail "duplicate root subvolume selectors in fstab"

root_id=$(btrfs inspect-internal rootid / 2>/dev/null) || fail "cannot determine running root subvolume ID"
case "$root_id" in ''|*[!0-9]*) fail "invalid running root subvolume ID: $root_id" ;; esac
[ "$root_id" -gt 5 ] || fail "running root is the Btrfs top level, not a rollback-capable subvolume"
root_fsroot=$(findmnt -n -o FSROOT / 2>/dev/null) || fail "cannot determine running root FSROOT"
root_rel=${root_fsroot#/}
[ -n "$root_rel" ] || fail "running root FSROOT unexpectedly names the top level"

install -d -m 0700 -o root -g root "$TOP"
[ -d "$TOP" ] && [ ! -L "$TOP" ] \
    && [ "$(stat -c '%u:%g:%a:%F' "$TOP" 2>/dev/null || true)" = \
        '0:0:700:directory' ] \
    || fail "temporary Btrfs top-level mountpoint is unsafe"
mount -t btrfs -o subvolid=5 "$root_spec" "$TOP" \
    || fail "cannot mount Btrfs top level for rollback bootstrap"

# Keep the snapshot store outside every selectable root. A nested
# root/.snapshots subvolume would disappear from the namespace after Snapper
# selects a different root. An earlier NoID Privacy layout is migrated by one same-FS
# subvolume rename before any default/boot selector changes.
[ ! -L /.snapshots ] || fail "/.snapshots is a symlink"
mkdir -p /.snapshots
[ -d /.snapshots ] && [ ! -L /.snapshots ] \
    || fail "/.snapshots is not a safe directory"
if [ ! -e "$TOP/snapshots" ]; then
    if btrfs subvolume show /.snapshots >/dev/null 2>&1; then
        old_snapshots="$TOP/$root_rel/.snapshots"
        [ -e "$old_snapshots" ] || fail "nested snapshot store is not reachable from the top level"
        mv "$old_snapshots" "$TOP/snapshots" \
            || fail "cannot migrate nested snapshot store to top-level snapshots"
    else
        [ ! -L /.snapshots ] || fail "/.snapshots is a symlink"
        [ -z "$(find /.snapshots -mindepth 1 -print -quit 2>/dev/null)" ] \
            || fail "ordinary /.snapshots directory is not empty"
        btrfs subvolume create "$TOP/snapshots" \
            || fail "cannot create top-level snapshots subvolume"
    fi
fi
btrfs subvolume show "$TOP/snapshots" >/dev/null 2>&1 \
    || fail "top-level snapshots path is not a Btrfs subvolume"
if [ -e "$TOP/snapshots" ] \
        && btrfs subvolume show /.snapshots >/dev/null 2>&1 \
        && [ "$(findmnt -n -o FSROOT /.snapshots 2>/dev/null || true)" != /snapshots ]; then
    fail "top-level snapshots collides with a different nested snapshot store"
fi

# Keep libvirt data outside selectable roots as a stable top-level nodatacow
# subvolume. Never copy live or populated VM data implicitly. On the fresh
# image the RPM-owned tree is a directory-only skeleton and is safe to copy.
[ ! -L /var/lib/libvirt ] || fail "/var/lib/libvirt is a symlink"
mkdir -p /var/lib/libvirt
[ -d /var/lib/libvirt ] && [ ! -L /var/lib/libvirt ] \
    || fail "/var/lib/libvirt is not a safe directory"
# Sample the libvirt daemons at each gate instead of once up front. A single
# snapshot taken here is stale by the time the later gates run, and the last
# one below even reports "became active", which a stale value can never
# observe. The window is real rather than theoretical: Fedora's
# fedora-release-common preset carries `enable virtqemud.service`, so the unit
# is WantedBy=multi-user.target and is queued into the same boot transaction
# as this one, while its sockets can pull it in at any moment.
libvirt_idle() {
    for unit in libvirtd virtqemud virtstoraged virtnetworkd; do
        if systemctl is-active --quiet "$unit" 2>/dev/null; then
            return 1
        fi
    done
    return 0
}
if [ ! -e "$TOP/libvirt" ]; then
    if btrfs subvolume show /var/lib/libvirt >/dev/null 2>&1; then
        libvirt_idle \
            || fail "libvirt is active before nested storage migration"
        old_libvirt="$TOP/$root_rel/var/lib/libvirt"
        [ -e "$old_libvirt" ] || fail "nested libvirt subvolume is not reachable from the top level"
        mv "$old_libvirt" "$TOP/libvirt" \
            || fail "cannot migrate nested libvirt subvolume to top level"
    else
        [ ! -L /var/lib/libvirt ] || fail "/var/lib/libvirt is a symlink"
        libvirt_idle || fail "libvirt is active before storage isolation completed"
        [ -z "$(find /var/lib/libvirt -mindepth 1 ! -type d -print -quit 2>/dev/null)" ] \
            || fail "/var/lib/libvirt contains non-directory state; explicit migration required"
        btrfs subvolume create "$TOP/libvirt" \
            || fail "cannot create top-level libvirt subvolume"
        chattr +C "$TOP/libvirt" || fail "cannot set nodatacow on libvirt subvolume"
        cp -a --reflink=never /var/lib/libvirt/. "$TOP/libvirt"/ \
            || fail "cannot copy the libvirt directory skeleton"
    fi
fi
btrfs subvolume show "$TOP/libvirt" >/dev/null 2>&1 \
    || fail "top-level libvirt path is not a Btrfs subvolume"
if [ -e "$TOP/libvirt" ] \
        && btrfs subvolume show /var/lib/libvirt >/dev/null 2>&1 \
        && [ "$(findmnt -n -o FSROOT /var/lib/libvirt 2>/dev/null || true)" != /libvirt ]; then
    fail "top-level libvirt collides with a different nested libvirt subvolume"
fi
if [ "$(findmnt -n -o FSROOT /var/lib/libvirt 2>/dev/null || true)" != /libvirt ]; then
    libvirt_idle || fail "libvirt became active before stable storage was mounted"
    [ -z "$(find /var/lib/libvirt -mindepth 1 ! -type d -print -quit 2>/dev/null)" ] \
        || fail "unmounted /var/lib/libvirt gained non-directory state before stable storage publication"
fi
lsattr -d "$TOP/libvirt" 2>/dev/null | awk '{print $1}' | grep -q 'C' \
    || fail "top-level libvirt subvolume is not nodatacow"

# Commit the top-level subvolume creation/rename and nodatacow metadata before
# any fstab/default-root publication can make those paths boot-critical.
sync -- "$TOP/snapshots" "$TOP/libvirt" "$TOP"

# Build a complete fstab candidate before changing boot selection. Drop only
# the reviewed Anaconda root selector and replace any stale NoID Privacy-managed
# snapshot/libvirt mount entries with the stable top-level mounts.
fstab_new=$(mktemp /etc/.fstab.noid-snapper.XXXXXX)
awk '
    function without_root_selector(options,    n,a,i,out) {
        n=split(options,a,","); out=""
        for (i=1; i<=n; i++) {
            if (a[i] == "subvol=root" || a[i] == "subvol=/root") continue
            out=(out == "" ? a[i] : out "," a[i])
        }
        return (out == "" ? "defaults" : out)
    }
    $1 !~ /^#/ && ($2 == "/.snapshots" || $2 == "/var/lib/libvirt") {next}
    $1 !~ /^#/ && $2 == "/" {
        $4=without_root_selector($4)
        print $1 "\t" $2 "\t" $3 "\t" $4 "\t" $5 "\t" $6
        next
    }
    {print}
' /etc/fstab > "$fstab_new" || fail "cannot build fstab rollback-model candidate"
printf '%s\t/.snapshots\tbtrfs\tsubvol=snapshots,nosuid,nodev,noexec,x-systemd.device-timeout=0\t0\t0\n' \
    "$root_spec" >> "$fstab_new"
printf '%s\t/var/lib/libvirt\tbtrfs\tsubvol=libvirt,nosuid,nodev,x-systemd.device-timeout=0\t0\t0\n' \
    "$root_spec" >> "$fstab_new"
[ "$(awk '$1 !~ /^#/ && $2 == "/" {count++} END {print count+0}' "$fstab_new")" -eq 1 ] \
    || fail "fstab candidate lost the unique root entry"

# Set the current root as default first. Until the final grubby step, the old
# rootflags selector still independently boots the same subvolume.
btrfs subvolume set-default "$root_id" / \
    || fail "cannot set the running root as Btrfs default"
default_id=$(btrfs subvolume get-default / 2>/dev/null | awk '$1 == "ID" {print $2}')
[ "$default_id" = "$root_id" ] || fail "Btrfs default postcondition failed"

# Prove both new mounts in the real namespace before publishing the fstab that
# will make them boot-critical. A power loss before fstab publication leaves
# the old selector-based boot intact; a power loss afterward reuses mounts that
# already passed their exact FSROOT postconditions.
mkdir -p /.snapshots /var/lib/libvirt
mountpoint -q /.snapshots || mount -t btrfs \
    -o subvol=snapshots,nosuid,nodev,noexec "$root_spec" /.snapshots \
    || fail "cannot preflight stable /.snapshots subvolume"
mountpoint -q /var/lib/libvirt || mount -t btrfs \
    -o subvol=libvirt,nosuid,nodev "$root_spec" /var/lib/libvirt \
    || fail "cannot preflight stable /var/lib/libvirt subvolume"
[ "$(findmnt --target /.snapshots -n -o TARGET 2>/dev/null)" = /.snapshots ] \
    && [ "$(findmnt --target /.snapshots -n -o FSROOT 2>/dev/null)" = /snapshots ] \
    || fail "/.snapshots is not the exact top-level /snapshots mount"
[ "$(findmnt --target /var/lib/libvirt -n -o TARGET 2>/dev/null)" = /var/lib/libvirt ] \
    && [ "$(findmnt --target /var/lib/libvirt -n -o FSROOT 2>/dev/null)" = /libvirt ] \
    || fail "/var/lib/libvirt is not the exact top-level /libvirt mount"

chown root:root "$fstab_new"
chmod 0644 "$fstab_new"
mv -fT -- "$fstab_new" /etc/fstab || fail "cannot publish fstab rollback model"
fstab_new=''
command -v restorecon >/dev/null 2>&1 && restorecon -F /etc/fstab \
    || [ ! -x /usr/sbin/restorecon ] || fail "cannot label /etc/fstab"
sync -- /etc/fstab
sync -- /etc
systemctl daemon-reload || fail "cannot regenerate units from the published fstab"
install -d -m 0700 -o root -g root /.snapshots/.noid-state
reconcile_snapshot_state_labels

# `grubby` owns all installed BLS entries and /etc/kernel/cmdline. Before it
# removes the obsolete root selector, ask the M01-owned helper to prove that
# all security bytes are already active and durably bind the exact planned
# post-removal cmdline. This prevents the ordered M20 topology change from
# invalidating M01 evidence and leaves a recoverable transition if power is
# lost during publication.
/usr/libexec/noid-rebind-firstboot-rootflags --prepare \
    || fail "cannot prepare the M01-bound rootflags transition"
grubby --update-kernel=ALL \
    --remove-args="rootflags=subvol=root rootflags=subvol=/root" \
    || fail "cannot remove explicit root subvolume selectors from BLS"
[ -f /etc/kernel/cmdline ] && [ ! -L /etc/kernel/cmdline ] \
    || fail "/etc/kernel/cmdline is missing, non-regular or a symlink"
grep -qE '(^|[[:space:]])root=[^[:space:]]+' /etc/kernel/cmdline \
    || fail "/etc/kernel/cmdline lost root="
if tr ' ' '\n' < /etc/kernel/cmdline | grep -qE '^rootflags=.*(subvol=|subvolid=)'; then
    fail "/etc/kernel/cmdline still overrides the Btrfs default subvolume"
fi
bls_count=0
for entry in /boot/loader/entries/*.conf; do
    [ -e "$entry" ] || continue
    [ -f "$entry" ] && [ ! -L "$entry" ] \
        || fail "$entry is not a regular non-symlink BLS entry"
    bls_count=$((bls_count + 1))
    options=$(awk '$1 == "options" {$1=""; sub(/^ /,""); print; exit}' "$entry")
    printf '%s\n' "$options" | tr ' ' '\n' | grep -qE '^root=[^[:space:]]+' \
        || fail "$entry lost root="
    if printf '%s\n' "$options" | tr ' ' '\n' \
            | grep -qE '^rootflags=.*(subvol=|subvolid=)'; then
        fail "$entry still overrides the Btrfs default subvolume"
    fi
done
[ "$bls_count" -gt 0 ] || fail "no BLS entries available for rollback-model verification"
/usr/libexec/noid-rebind-firstboot-rootflags --verify \
    || fail "M01 evidence does not bind the published rootflags transition"

boot_state=/.snapshots/.noid-state/boot-model.ready
boot_state_new=$(mktemp /.snapshots/.noid-state/.boot-model.XXXXXX)
printf 'MODEL=default-subvolume-v1\nSNAPSHOTS_FSROOT=/snapshots\nLIBVIRT_FSROOT=/libvirt\n' \
    > "$boot_state_new"
chown root:root "$boot_state_new"
chmod 0600 "$boot_state_new"
mv -fT -- "$boot_state_new" "$boot_state"
boot_state_new=''
sync -- "$boot_state"
sync -- /.snapshots/.noid-state
sync -- /etc/fstab
sync -- /boot

# Verify snapper sees the config
if ! snapper list-configs 2>/dev/null | grep -q '^root '; then
    logger -t "$LOG_TAG" "snapper does not see root config despite /etc/snapper/configs/root"
    exit 1
fi

# Create initial "baseline" snapshot (marks the fresh-install state)
baseline_exists() {
    snapper -c root --jsonout --iso list --disable-used-space 2>/dev/null \
        | python3 -I -c '
import json, sys
rows = json.load(sys.stdin).get("root", [])
raise SystemExit(0 if any(
    isinstance(row, dict)
    and type(row.get("number")) is int
    and row["number"] > 0
    and row.get("description") == "baseline-install"
    for row in rows
) else 1)
'
}
if ! baseline_exists; then
    if ! /usr/libexec/noid-snapper-create single "baseline-install" important; then
        logger -t "$LOG_TAG" "baseline snapshot creation failed"
        exit 1
    fi
fi
if ! baseline_exists; then
    logger -t "$LOG_TAG" "baseline snapshot postcondition failed"
    exit 1
fi

install -m 0600 -o root -g root /dev/null "$MARKER"
matchpathcon -V "$MARKER" >/dev/null \
    || fail "completion marker SELinux label differs"
sync -- "$MARKER"
sync -- /.snapshots/.noid-state
logger -t "$LOG_TAG" "initialization complete"
SNAPPER_INIT_EOF

chmod 755 /usr/local/bin/noid-snapper-init.sh
chown root:root /usr/local/bin/noid-snapper-init.sh

cat > /etc/systemd/system/noid-snapper-init.service <<'SNAPPER_INIT_SERVICE_EOF'
[Unit]
Description=NoID Privacy — Snapper Bootstrap and Boot Verification
Documentation=file:///usr/share/doc/noid-privacy/20-rollback-recovery.md
Requires=noid-firstboot-cmdline.service
After=local-fs.target noid-firstboot-cmdline.service
Before=noid-dracut-hostonly-firstboot.service multi-user.target
# The first boot moves /var/lib/libvirt into a stable top-level subvolume, so
# no libvirt daemon may hold that tree open while it happens. Fedora's
# fedora-release-common preset enables virtqemud.service (WantedBy=
# multi-user.target), which puts it in the same boot transaction as this unit
# with nothing ordering the two. Since this unit additionally waits for the
# firstboot cmdline work, libvirt would otherwise win the race on essentially
# every real boot and the bootstrap would fail closed for good. Ordering only:
# a failure here does not keep the daemons from starting afterwards.
Before=libvirtd.service virtqemud.service virtstoraged.service virtnetworkd.service
# Skip in live-ISO mode. Snapper requires a Btrfs root;
# live-ISO root is overlay-on-squashfs (NOT btrfs). The unit condition skips
# execution there; installed Btrfs systems run the gate normally.
ConditionKernelCommandLine=!rd.live.image

[Service]
Type=oneshot
# The helper performs the first migration once. On later boots it verifies the
# exact completion marker and full rollback model locally, without mutation.
ExecStart=/usr/local/bin/noid-snapper-init.sh
RemainAfterExit=yes

# The initializer must publish /.snapshots and /var/lib/libvirt into the boot
# mount namespace. Any systemd filesystem-namespace directive would make those
# successful mounts private to the oneshot, so this unit intentionally keeps
# only hardening that does not create a mount namespace.
NoNewPrivileges=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
ProtectHostname=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX
MemoryDenyWriteExecute=yes
IPAddressDeny=any

[Install]
WantedBy=multi-user.target
SNAPPER_INIT_SERVICE_EOF

chmod 644 /etc/systemd/system/noid-snapper-init.service
chown root:root /etc/systemd/system/noid-snapper-init.service

systemctl enable noid-snapper-init.service

# ============================================================================
# Step 4 — Enable snapper-cleanup.timer (but NOT timeline)
# ============================================================================

# Enforce explicit-only snapshot creation even if an upstream preset changes.
systemctl disable snapper-timeline.timer snapper-boot.timer >/dev/null \
    || { echo "[Module 20] FAIL: automatic Snapper timers could not be disabled"; exit 1; }

# snapper-cleanup.timer runs hourly by default, processes NUMBER_LIMIT retention
systemctl enable snapper-cleanup.timer

# Drop-ins bind the RPM timer and service to the installed lifecycle. The Live
# root is overlayfs while the reviewed Snapper root config targets Btrfs `/`;
# neither a scheduled nor a direct cleanup may therefore reach the Live image.
# The timer drop-in also lowers cleanup frequency to daily: with
# TIMELINE_CREATE=no there is nothing to do hourly, and hourly wakeups add a
# filesystem-activity fingerprint (privacy). The heredoc documents the
# relative-timer reset trap.
mkdir -p \
    /etc/systemd/system/snapper-cleanup.timer.d \
    /etc/systemd/system/snapper-cleanup.service.d
cat > /etc/systemd/system/snapper-cleanup.timer.d/99-noid-frequency.conf <<'CLEANUP_TIMER_EOF'
# NoID Privacy — replace upstream OnBootSec=10m + OnUnitActiveSec=1h with
# deterministic OnCalendar=daily + Persistent=true. An enabled unit remains
# installed in the image, but systemd must not schedule it on a Live boot.
#
# Reboot testing exposed an empirical bug: the prior version of this
# drop-in used `OnUnitActiveSec=` empty + `OnUnitActiveSec=1d` to preserve
# the upstream `OnBootSec=10m` initial-fire and only override the recurring
# interval. systemd's relative-timer-list-replace-quirk meant the empty-
# value-reset cleared OnBootSec=10m as well as OnUnitActiveSec=1h, leaving
# the timer with ONLY `OnUnitActiveSec=1d`. Since OnUnitActiveSec is
# computed relative to last-service-active-time (zero on a freshly-booted
# system that never fired the service), the timer never had a defined
# trigger time post-boot. Result: snapper-cleanup.service never ran,
# NUMBER snapshots accumulated unbounded (17 visible after 50min uptime
# despite NUMBER_LIMIT=5).
#
# Fix: OnCalendar=daily fires deterministically at midnight regardless of
# boot timing. Persistent=true catches a missed fire after reboot. Both
# user-invoked update pairs and ad-hoc single points use NUMBER cleanup, so
# the visible count may temporarily exceed its configured limit between daily
# runs. Every project-owned creator separately enforces the measured free-space
# admission reserve; no exact per-day creation rate is assumed.
[Unit]
ConditionKernelCommandLine=!rd.live.image

[Timer]
# Reset all upstream relative timers explicitly (defense against the same
# systemd-quirk that bit the earlier drop-in):
OnBootSec=
OnUnitActiveSec=
# Deterministic schedule:
OnCalendar=daily
Persistent=true
CLEANUP_TIMER_EOF

cat > /etc/systemd/system/snapper-cleanup.service.d/99-noid-live-guard.conf <<'CLEANUP_SERVICE_EOF'
# NoID Privacy — the shipped root config is valid only after installation onto
# Btrfs. Refuse direct/manual cleanup as well as timer activation on Live.
[Unit]
ConditionKernelCommandLine=!rd.live.image
Requires=noid-snapper-init.service
After=noid-snapper-init.service
CLEANUP_SERVICE_EOF

chmod 0644 \
    /etc/systemd/system/snapper-cleanup.timer.d/99-noid-frequency.conf \
    /etc/systemd/system/snapper-cleanup.service.d/99-noid-live-guard.conf
chown root:root \
    /etc/systemd/system/snapper-cleanup.timer.d/99-noid-frequency.conf \
    /etc/systemd/system/snapper-cleanup.service.d/99-noid-live-guard.conf

# snapper-timeline.timer is explicitly NOT enabled (privacy: no hourly snapshots)
# snapper-boot.timer is explicitly NOT enabled (rollback points require an
# explicit user-initiated operation)

# ============================================================================
# Step 10 — Root-owned snapshot creation, status and rollback boundaries
# ============================================================================

mkdir -p /usr/libexec /etc/sudoers.d

cat > /usr/libexec/noid-snapper-create <<'SNAPPER_CREATE_EOF'
#!/bin/bash
# Canonical NoID Privacy snapshot creator. Every project-owned creation path uses this
# measured preflight instead of inert Snapper SPACE_LIMIT/FREE_LIMIT claims.
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH LC_ALL=C.UTF-8
umask 077

fail() { echo "noid-snapper-create: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || fail "must run as root"

mode=${1:-}
snap_args=()
case "$#:$mode" in
    2:pre)
        desc=$2
        snap_args=(--type pre --print-number --description "$desc" --cleanup-algorithm number)
        ;;
    3:post)
        pre=$2; desc=$3
        [[ "$pre" =~ ^[1-9][0-9]*$ ]] || fail "post snapshot requires a positive pre-number"
        snap_args=(--type post --pre-number "$pre" --print-number --description "$desc" --cleanup-algorithm number)
        ;;
    2:single)
        desc=$2
        snap_args=(--type single --print-number --description "$desc" --cleanup-algorithm number)
        ;;
    3:single)
        desc=$2
        [ "$3" = important ] || fail "unknown single-snapshot flag: $3"
        snap_args=(--type single --print-number --description "$desc" --cleanup-algorithm number --userdata important=yes)
        ;;
    *)
        fail "usage: noid-snapper-create pre DESCRIPTION | post PRE_NUMBER DESCRIPTION | single DESCRIPTION [important]"
        ;;
esac
case "$desc" in *$'\n'*|'') fail "description must be one non-empty line" ;; esac

[ "$(findmnt -n -o FSTYPE / 2>/dev/null)" = btrfs ] || fail "root is not Btrfs"
[ "$(findmnt -n -o FSROOT /.snapshots 2>/dev/null)" = /snapshots ] \
    || fail "stable /.snapshots mount is unavailable"
btrfs subvolume show /.snapshots >/dev/null 2>&1 \
    || fail "/.snapshots is not a Btrfs subvolume"
snapper list-configs 2>/dev/null | awk '$1 == "root" {found=1} END {exit !found}' \
    || fail "Snapper root config is unavailable"
[ -f /usr/libexec/noid-snapper-status ] \
    && [ ! -L /usr/libexec/noid-snapper-status ] \
    && [ -x /usr/libexec/noid-snapper-status ] \
    || fail "rollback-model verifier is missing or unsafe"
snapshot_status=$(/usr/libexec/noid-snapper-status) \
    || fail "rollback-model status is unavailable"
case "$snapshot_status" in
    *' boot=ready '*) ;;
    *) fail "snapshot creation is blocked until the rollback boot model is ready" ;;
esac

# This is an admission preflight, not an absolute quota. Refuse below both the
# fixed 2-GiB floor and a 5% filesystem operational reserve. Concurrent writes
# can race any userspace measurement; callers must still handle ENOSPC.
read -r total_blocks available_blocks block_size < <(stat -f -c '%b %a %S' /)
for value in "$total_blocks" "$available_blocks" "$block_size"; do
    [[ "$value" =~ ^[0-9]+$ ]] || fail "invalid statfs free-space result"
done
available_bytes=$((available_blocks * block_size))
minimum_bytes=$((2 * 1024 * 1024 * 1024))
if [ "$available_bytes" -lt "$minimum_bytes" ] \
        || [ $((available_blocks * 100)) -lt $((total_blocks * 5)) ]; then
    fail "snapshot refused: available space is below the 5%/2-GiB operational reserve"
fi

number=$(snapper -c root create "${snap_args[@]}") \
    || fail "snapper create failed"
[[ "$number" =~ ^[1-9][0-9]*$ ]] || fail "snapper returned an invalid snapshot number"
printf '%s\n' "$number"
SNAPPER_CREATE_EOF

cat > /usr/libexec/noid-snapper-status <<'SNAPPER_STATUS_EOF'
#!/bin/bash
# Fixed-schema, read-only root helper consumed by noid-status. It never accepts
# user arguments and never exposes descriptions, paths, users or arbitrary
# Snapper operations.
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH LC_ALL=C.UTF-8 TZ=UTC
unset BASH_ENV CDPATH ENV GLOBIGNORE PYTHONPATH PYTHONHOME
umask 077
[ "$(id -u)" -eq 0 ] || exit 1
[ "$#" -eq 0 ] || exit 2

json=$(snapper -c root --jsonout --iso list --disable-used-space 2>/dev/null) || exit 1
parsed=$(printf '%s' "$json" | python3 -I -c '
import json, sys
obj = json.load(sys.stdin)
rows = obj.get("root")
if not isinstance(rows, list):
    raise SystemExit(1)
numbers = []
defaults = []
active = []
seen = set()
for row in rows:
    if not isinstance(row, dict) or type(row.get("number")) is not int:
        raise SystemExit(1)
    number = row["number"]
    if number < 0 or number in seen:
        raise SystemExit(1)
    seen.add(number)
    if type(row.get("default")) is not bool or type(row.get("active")) is not bool:
        raise SystemExit(1)
    if number > 0:
        numbers.append(number)
    if row.get("default") is True:
        defaults.append(number)
    if row.get("active") is True:
        active.append(number)
if len(defaults) > 1 or len(active) > 1:
    raise SystemExit(1)
print(len(numbers), defaults[0] if defaults else "none", active[0] if active else "none")
') || exit 1
read -r count default_snapshot active_snapshot <<<"$parsed"
[[ "$count" =~ ^[0-9]+$ ]] || exit 1
[[ "$default_snapshot" =~ ^(none|[0-9]+)$ ]] || exit 1
[[ "$active_snapshot" =~ ^(none|[0-9]+)$ ]] || exit 1

boot_model=degraded
root_id=$(btrfs inspect-internal rootid / 2>/dev/null || true)
default_id=$(btrfs subvolume get-default / 2>/dev/null | awk '$1 == "ID" {print $2}')
has_mount_option() {
    local target=$1 wanted=$2 options
    options=$(findmnt --target "$target" -n -o OPTIONS 2>/dev/null) || return 1
    printf '%s\n' "$options" | tr ',' '\n' | grep -qxF "$wanted"
}

fstab_contract_ready() {
    [ -f /etc/fstab ] && [ ! -L /etc/fstab ] || return 1
    awk '
        function hasselector(options,    n,a,i) {
            n=split(options,a,",")
            for (i=1; i<=n; i++)
                if (a[i] ~ /^(subvol|subvolid)=/) return 1
            return 0
        }
        $1 !~ /^#/ && $2 == "/" {
            root_count++; root_spec=$1
            if (NF < 6 || $3 != "btrfs" || hasselector($4)) bad=1
        }
        $1 !~ /^#/ && $2 == "/.snapshots" {
            snapshots_count++; snapshots_spec=$1
            if (NF != 6 || $3 != "btrfs" \
                    || $4 != "subvol=snapshots,nosuid,nodev,noexec,x-systemd.device-timeout=0" \
                    || $5 != "0" || $6 != "0") bad=1
        }
        $1 !~ /^#/ && $2 == "/var/lib/libvirt" {
            libvirt_count++; libvirt_spec=$1
            if (NF != 6 || $3 != "btrfs" \
                    || $4 != "subvol=libvirt,nosuid,nodev,x-systemd.device-timeout=0" \
                    || $5 != "0" || $6 != "0") bad=1
        }
        END {
            if (bad || root_count != 1 || snapshots_count != 1 || libvirt_count != 1 \
                    || root_spec == "" || snapshots_spec != root_spec \
                    || libvirt_spec != root_spec) exit 1
        }
    ' /etc/fstab
}

boot_sources_ready() {
    local entry options root_count bls_count=0
    [ -f /etc/kernel/cmdline ] && [ ! -L /etc/kernel/cmdline ] || return 1
    root_count=$(tr ' ' '\n' < /etc/kernel/cmdline \
        | grep -cE '^root=[^[:space:]]+' || true)
    [ "$root_count" -eq 1 ] || return 1
    ! tr ' ' '\n' < /etc/kernel/cmdline \
        | grep -qE '^rootflags=.*(subvol=|subvolid=)' || return 1
    for entry in /boot/loader/entries/*.conf; do
        [ -e "$entry" ] || continue
        [ -f "$entry" ] && [ ! -L "$entry" ] || return 1
        bls_count=$((bls_count + 1))
        [ "$(awk '$1 == "options" {count++} END {print count+0}' "$entry")" -eq 1 ] \
            || return 1
        options=$(awk '$1 == "options" {$1=""; sub(/^ /,""); print}' "$entry")
        root_count=$(printf '%s\n' "$options" | tr ' ' '\n' \
            | grep -cE '^root=[^[:space:]]+' || true)
        [ "$root_count" -eq 1 ] || return 1
        ! printf '%s\n' "$options" | tr ' ' '\n' \
            | grep -qE '^rootflags=.*(subvol=|subvolid=)' || return 1
    done
    [ "$bls_count" -gt 0 ]
}

state_contract_ready() {
    local state=/.snapshots/.noid-state/boot-model.ready
    [ -d /.snapshots/.noid-state ] && [ ! -L /.snapshots/.noid-state ] \
        && [ "$(stat -c '%u:%g:%a:%F' /.snapshots/.noid-state \
                2>/dev/null)" = '0:0:700:directory' ] \
        && matchpathcon -V /.snapshots >/dev/null 2>&1 \
        && matchpathcon -V /.snapshots/.noid-state >/dev/null 2>&1 \
        || return 1
    [ -f "$state" ] && [ ! -L "$state" ] || return 1
    [ "$(stat -c '%u:%g:%a:%h:%F' "$state" 2>/dev/null)" = \
        '0:0:600:1:regular file' ] || return 1
    matchpathcon -V "$state" >/dev/null 2>&1 || return 1
    [ "$(cat "$state")" = $'MODEL=default-subvolume-v1\nSNAPSHOTS_FSROOT=/snapshots\nLIBVIRT_FSROOT=/libvirt' ]
}

mount_contract_ready() {
    local root_device
    root_device=$(findmnt --target / -n -o MAJ:MIN 2>/dev/null) || return 1
    [ -n "$root_device" ] \
        && [ "$(findmnt --target /.snapshots -n -o MAJ:MIN 2>/dev/null)" = "$root_device" ] \
        && [ "$(findmnt --target /var/lib/libvirt -n -o MAJ:MIN 2>/dev/null)" = "$root_device" ] \
        || return 1
    [ "$(findmnt --target /.snapshots -n -o TARGET 2>/dev/null)" = /.snapshots ] \
        && [ "$(findmnt --target /.snapshots -n -o FSTYPE 2>/dev/null)" = btrfs ] \
        && [ "$(findmnt --target /.snapshots -n -o FSROOT 2>/dev/null)" = /snapshots ] \
        && has_mount_option /.snapshots nosuid \
        && has_mount_option /.snapshots nodev \
        && has_mount_option /.snapshots noexec \
        && [ "$(findmnt --target /var/lib/libvirt -n -o TARGET 2>/dev/null)" = /var/lib/libvirt ] \
        && [ "$(findmnt --target /var/lib/libvirt -n -o FSTYPE 2>/dev/null)" = btrfs ] \
        && [ "$(findmnt --target /var/lib/libvirt -n -o FSROOT 2>/dev/null)" = /libvirt ] \
        && has_mount_option /var/lib/libvirt nosuid \
        && has_mount_option /var/lib/libvirt nodev
}

contract_ready=0
if [[ "$root_id" =~ ^[0-9]+$ ]] && [ "$root_id" -gt 5 ] \
        && [[ "$default_id" =~ ^[0-9]+$ ]] && [ "$default_id" -gt 5 ] \
        && state_contract_ready && fstab_contract_ready \
        && boot_sources_ready && mount_contract_ready; then
    contract_ready=1
fi
if [ "$contract_ready" -eq 1 ] && [ "$root_id" = "$default_id" ]; then
    boot_model=ready
elif [ "$contract_ready" -eq 1 ] \
        && [[ "$default_snapshot" =~ ^[1-9][0-9]*$ ]] \
        && [ "$(btrfs inspect-internal rootid "/.snapshots/$default_snapshot/snapshot" 2>/dev/null || true)" = "$default_id" ] \
        && [ "$(btrfs property get -ts "/.snapshots/$default_snapshot/snapshot" ro 2>/dev/null || true)" = ro=false ]; then
    boot_model=reboot-required
fi

# BEGIN RETENTION_STATUS_READER
read_retention_status() {
    local file="${1:-/.snapshots/.noid-state/retention.status}"
    local expected_file_meta="${2:-0:0:600:1:regular file}"
    local expected_dir_meta="${3:-0:0:700:directory}"
    local now_epoch=${4:-} max_age=${5:-172800} future_skew=${6:-300}
    local dir state removed recent protected failures checked_at checked_epoch
    local -a lines=()
    if [ -z "$now_epoch" ]; then
        now_epoch=$(date +%s 2>/dev/null) || return 1
    fi
    [[ "$now_epoch" =~ ^(0|[1-9][0-9]*)$ ]] \
        && [[ "$max_age" =~ ^(0|[1-9][0-9]*)$ ]] \
        && [[ "$future_skew" =~ ^(0|[1-9][0-9]*)$ ]] \
        || return 1
    dir=${file%/*}
    [ -d "$dir" ] && [ ! -L "$dir" ] \
        && [ "$(stat -c '%u:%g:%a:%F' "$dir" 2>/dev/null || true)" = \
            "$expected_dir_meta" ] \
        && [ -f "$file" ] && [ ! -L "$file" ] \
        && [ "$(stat -c '%u:%g:%a:%h:%F' "$file" 2>/dev/null || true)" = \
            "$expected_file_meta" ] \
        || return 1
    mapfile -t lines < "$file" || return 1
    [ "${#lines[@]}" -eq 6 ] || return 1
    [[ "${lines[0]}" =~ ^STATUS=(ok|protected|clock-guard|degraded)$ ]] \
        || return 1
    [[ "${lines[1]}" =~ ^REMOVED=(0|[1-9][0-9]*)$ ]] || return 1
    [[ "${lines[2]}" =~ ^RECENT=(0|[1-9][0-9]*)$ ]] || return 1
    [[ "${lines[3]}" =~ ^PROTECTED=(0|[1-9][0-9]*)$ ]] || return 1
    [[ "${lines[4]}" =~ ^FAILURES=(0|[1-9][0-9]*)$ ]] || return 1
    [[ "${lines[5]}" =~ ^CHECKED_AT=([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z)$ ]] \
        || return 1
    state=${lines[0]#STATUS=}
    removed=${lines[1]#REMOVED=}
    recent=${lines[2]#RECENT=}
    protected=${lines[3]#PROTECTED=}
    failures=${lines[4]#FAILURES=}
    checked_at=${lines[5]#CHECKED_AT=}
    [ "$(date -u -d "$checked_at" +%FT%TZ 2>/dev/null || true)" = \
        "$checked_at" ] || return 1
    checked_epoch=$(date -u -d "$checked_at" +%s 2>/dev/null) || return 1
    [[ "$checked_epoch" =~ ^(0|[1-9][0-9]*)$ ]] || return 1
    if [ "$checked_epoch" -gt "$now_epoch" ]; then
        [ $((checked_epoch - now_epoch)) -le "$future_skew" ] || return 1
    else
        [ $((now_epoch - checked_epoch)) -le "$max_age" ] || return 1
    fi
    case "$state" in
        ok)
            [ "$protected" -eq 0 ] && [ "$failures" -eq 0 ] || return 1
            ;;
        protected)
            [ "$protected" -gt 0 ] && [ "$failures" -eq 0 ] || return 1
            ;;
        degraded)
            [ "$failures" -gt 0 ] || return 1
            ;;
        clock-guard)
            [ "$removed" -eq 0 ] && [ "$recent" -eq 0 ] \
                && [ "$protected" -eq 0 ] && [ "$failures" -eq 0 ] \
                || return 1
            ;;
    esac
    printf '%s\n' "$state"
}
# END RETENTION_STATUS_READER

retention=$(read_retention_status 2>/dev/null || true)
[ -n "$retention" ] || retention=unknown

printf 'count=%s boot=%s default=%s active=%s retention=%s\n' \
    "$count" "$boot_model" "$default_snapshot" "$active_snapshot" "$retention"
SNAPPER_STATUS_EOF

cat > /usr/libexec/noid-snapper-rollback <<'SNAPPER_ROLLBACK_EOF'
#!/bin/bash
# Checked wrapper around Snapper's maintained classic rollback. It validates
# that the boot chain follows the Btrfs default and leaves persistent evidence
# if interruption occurs between request and verified default publication.
# Btrfs root selection and /boot mutation share one transaction boundary:
# /boot is outside the snapshot and must never be rebuilt against the old
# running root after a different default root has been selected for reboot.
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH LC_ALL=C.UTF-8 TZ=UTC
unset PYTHONPATH PYTHONHOME
umask 077

BOOT_LOCK=/run/lock/noid-boot-mutation.lock
BOOT_GUARD=/usr/libexec/noid-boot-mutation-guard
ROLLBACK_LOCK=/run/lock/noid-snapper-rollback.lock
pending_new=''
ready_new=''

fail() { echo "noid-snapper-rollback: $*" >&2; exit 1; }
cleanup_rollback_candidates() {
    local rc=$? cleanup_failed=0
    trap - EXIT
    if [ -n "$pending_new" ] && ! rm -f -- "$pending_new"; then
        echo "noid-snapper-rollback: unpublished pending-state cleanup failed" >&2
        cleanup_failed=1
    fi
    if [ -n "$ready_new" ] && ! rm -f -- "$ready_new"; then
        echo "noid-snapper-rollback: unpublished ready-state cleanup failed" >&2
        cleanup_failed=1
    fi
    [ "$cleanup_failed" -eq 0 ] || [ "$rc" -ne 0 ] || rc=1
    exit "$rc"
}
trap cleanup_rollback_candidates EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
[ "$(id -u)" -eq 0 ] || fail "must run as root"
case "$#:${1:-}" in
    1:--resume) resume=1; target='' ;;
    1:*) resume=0; target=$1 ;;
    *) fail "usage: noid-snapper-rollback SNAPSHOT_NUMBER | --resume" ;;
esac

# Acquire a real shutdown/sleep inhibitor when logind is available. Recovery
# shells without logind are already operator-controlled and continue under the
# process lock below.
if [ "${NOID_SNAPPER_INHIBITED:-0}" != 1 ] \
        && systemctl is-active --quiet systemd-logind.service 2>/dev/null; then
    exec systemd-inhibit --what=shutdown:sleep --mode=block \
        --why="NoID Privacy verified Snapper rollback" \
        env -i PATH="$PATH" LC_ALL=C.UTF-8 TZ=UTC NOID_SNAPPER_INHIBITED=1 \
        "$0" "$@"
fi

for path in "$BOOT_LOCK" "$BOOT_GUARD"; do
    [ -f "$path" ] && [ ! -L "$path" ] \
        || fail "required boot-mutation artifact is missing or unsafe: $path"
done
[ -x "$BOOT_GUARD" ] || fail "boot-mutation guard is not executable"
exec 8<>"$BOOT_LOCK"
flock -w 300 8 || fail "timed out waiting for another boot mutation"
guard_args=()
[ "$resume" -eq 0 ] || guard_args=(--snapper-resume)
boot_basis=$("$BOOT_GUARD" "${guard_args[@]}") \
    || fail "M21 or Snapper boot state is not safe for rollback"
case "$boot_basis" in
    basis=hostonly|basis=generic) ;;
    *) fail "boot-mutation guard returned an invalid basis" ;;
esac

exec 9>"$ROLLBACK_LOCK"
flock -n 9 || fail "another rollback is active"

status=$(/usr/libexec/noid-snapper-status) || fail "cannot read rollback model status"
case "$status" in
    *' boot=ready '*) ;;
    *' boot=reboot-required '*)
        [ "$resume" -eq 1 ] \
            || fail "a rollback root is already selected; reboot or resume the recorded operation"
        ;;
    *) fail "Btrfs default-subvolume boot model is degraded" ;;
esac
[ "$(findmnt --target /.snapshots -n -o TARGET 2>/dev/null)" = /.snapshots ] \
    && [ "$(findmnt --target /.snapshots -n -o FSROOT 2>/dev/null)" = /snapshots ] \
    || fail "stable snapshot-state mount is unavailable"
[ -d /.snapshots/.noid-state ] && [ ! -L /.snapshots/.noid-state ] \
    || fail "stable snapshot-state directory is unavailable"
[ "$(stat -c '%u:%g:%a:%F' /.snapshots/.noid-state 2>/dev/null || true)" = \
    '0:0:700:directory' ] || fail "stable snapshot-state directory metadata is unsafe"
matchpathcon -V /.snapshots >/dev/null \
    && matchpathcon -V /.snapshots/.noid-state >/dev/null \
    || fail "stable snapshot-state SELinux labels differ"

snapshot_matches() {
    local wanted=$1 expected_description=${2-}
    snapper -c root --jsonout --iso list --disable-used-space 2>/dev/null \
        | python3 -I -c '
import json, sys
wanted = int(sys.argv[1])
expected = sys.argv[2]
rows = json.load(sys.stdin).get("root", [])
raise SystemExit(0 if any(
    isinstance(row, dict)
    and type(row.get("number")) is int
    and row.get("number") == wanted
    and (not expected or row.get("description") == expected)
    for row in rows
) else 1)
' "$wanted" "$expected_description"
}

snapshot_fstab_safe() {
    local number=$1 fstab="/.snapshots/$1/snapshot/etc/fstab" current_spec target_spec
    [ -f "$fstab" ] && [ ! -L "$fstab" ] || return 1
    current_spec=$(awk '$1 !~ /^#/ && $2 == "/" {print $1}' /etc/fstab)
    target_spec=$(awk '$1 !~ /^#/ && $2 == "/" {print $1}' "$fstab")
    [ -n "$current_spec" ] && [ "$target_spec" = "$current_spec" ] || return 1
    awk '
        function hasselector(options,    n,a,i) {
            n=split(options,a,",")
            for (i=1; i<=n; i++)
                if (a[i] ~ /^(subvol|subvolid)=/) return 1
            return 0
        }
        $1 !~ /^#/ && $2 == "/" {
            root_count++; root_spec=$1
            if (NF < 6 || $3 != "btrfs" || hasselector($4)) bad=1
        }
        $1 !~ /^#/ && $2 == "/.snapshots" {
            snapshots_count++; snapshots_spec=$1
            if (NF != 6 || $3 != "btrfs" \
                    || $4 != "subvol=snapshots,nosuid,nodev,noexec,x-systemd.device-timeout=0" \
                    || $5 != "0" || $6 != "0") bad=1
        }
        $1 !~ /^#/ && $2 == "/var/lib/libvirt" {
            libvirt_count++; libvirt_spec=$1
            if (NF != 6 || $3 != "btrfs" \
                    || $4 != "subvol=libvirt,nosuid,nodev,x-systemd.device-timeout=0" \
                    || $5 != "0" || $6 != "0") bad=1
        }
        END {
            if (bad || root_count != 1 || snapshots_count != 1 || libvirt_count != 1 \
                    || root_spec == "" || snapshots_spec != root_spec \
                    || libvirt_spec != root_spec) exit 1
        }
    ' "$fstab"
}

snapshot_kernel_cmdline_safe() {
    local number=$1 cmdline="/.snapshots/$1/snapshot/etc/kernel/cmdline" root_count
    [ -f "$cmdline" ] && [ ! -L "$cmdline" ] || return 1
    root_count=$(tr ' ' '\n' < "$cmdline" \
        | grep -cE '^root=[^[:space:]]+' || true)
    [ "$root_count" -eq 1 ] || return 1
    ! tr ' ' '\n' < "$cmdline" \
        | grep -qE '^rootflags=.*(subvol=|subvolid=)'
}

verify_published_default() {
    local number=$1 target_number=$2 new_id default_id ro
    [[ "$number" =~ ^[1-9][0-9]*$ ]] || return 1
    snapshot_matches "$number" "NoID Privacy rollback to snapshot $target_number" || return 1
    snapshot_fstab_safe "$number" || return 1
    snapshot_kernel_cmdline_safe "$number" || return 1
    new_id=$(btrfs inspect-internal rootid "/.snapshots/$number/snapshot" 2>/dev/null) || return 1
    default_id=$(btrfs subvolume get-default / 2>/dev/null | awk '$1 == "ID" {print $2}')
    [ "$new_id" = "$default_id" ] || return 1
    ro=$(btrfs property get -ts "/.snapshots/$number/snapshot" ro 2>/dev/null) || return 1
    [ "$ro" = 'ro=false' ] || return 1
}

pending=/.snapshots/.noid-state/rollback.pending
ready=/.snapshots/.noid-state/rollback.ready
if [ "$resume" -eq 1 ]; then
    [ -f "$pending" ] && [ ! -L "$pending" ] || fail "no pending rollback"
    [ "$(stat -c '%u:%g:%a:%h:%F' "$pending" 2>/dev/null || true)" = \
        '0:0:600:1:regular file' ] \
        && matchpathcon -V "$pending" >/dev/null \
        || fail "pending rollback state metadata or SELinux label is invalid"
    [ "$(wc -l < "$pending")" -eq 3 ] || fail "pending rollback state is invalid"
    target=$(awk -F= '$1 == "TARGET" {print $2}' "$pending")
    original_default_id=$(awk -F= '$1 == "ORIGINAL_DEFAULT_ID" {print $2}' "$pending")
    requested_at=$(awk -F= '$1 == "REQUESTED_AT" {print $2}' "$pending")
    [[ "$target" =~ ^[1-9][0-9]*$ ]] \
        && [[ "$original_default_id" =~ ^[1-9][0-9]*$ ]] \
        && [[ "$requested_at" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] \
        || fail "pending rollback state is invalid"
    current_default_id=$(btrfs subvolume get-default / 2>/dev/null | awk '$1 == "ID" {print $2}')
    [[ "$current_default_id" =~ ^[1-9][0-9]*$ ]] \
        || fail "current Btrfs default is invalid"
    default_number=$(snapper -c root --jsonout --iso list --disable-used-space 2>/dev/null \
        | python3 -I -c '
import json, sys
rows = json.load(sys.stdin).get("root", [])
values = [
    r.get("number") for r in rows
    if isinstance(r, dict)
    and type(r.get("number")) is int
    and r.get("default") is True
]
print(values[0] if len(values) == 1 else "")
')
    if [ "$current_default_id" != "$original_default_id" ] \
            && [ -n "$default_number" ] \
            && verify_published_default "$default_number" "$target"; then
        new_number=$default_number
    elif [ "$current_default_id" = "$original_default_id" ]; then
        resume=0
    else
        fail "Btrfs default changed but does not match the recorded rollback"
    fi
fi

if [ "$resume" -eq 0 ]; then
    [[ "$target" =~ ^[1-9][0-9]*$ ]] || fail "snapshot number must be a positive integer"
    snapshot_matches "$target" || fail "snapshot $target does not exist"
    snapshot_fstab_safe "$target" \
        || fail "snapshot $target predates the default-subvolume boot model or has unsafe fstab state"
    snapshot_kernel_cmdline_safe "$target" \
        || fail "snapshot $target has unsafe future-kernel command-line state"
    original_default_id=$(btrfs subvolume get-default / 2>/dev/null | awk '$1 == "ID" {print $2}')
    [[ "$original_default_id" =~ ^[1-9][0-9]*$ ]] \
        || fail "current Btrfs default is invalid"
    current_root_id=$(btrfs inspect-internal rootid / 2>/dev/null)
    [[ "$current_root_id" =~ ^[1-9][0-9]*$ ]] \
        || fail "running Btrfs root is invalid"
    [ "$current_root_id" = "$original_default_id" ] \
        || fail "running root is not the current Btrfs default"
    pending_new=$(mktemp /.snapshots/.noid-state/.rollback-pending.XXXXXX)
    printf 'TARGET=%s\nORIGINAL_DEFAULT_ID=%s\nREQUESTED_AT=%s\n' \
        "$target" "$original_default_id" "$(date -u +%FT%TZ)" > "$pending_new"
    chown root:root "$pending_new"; chmod 0600 "$pending_new"
    mv -fT -- "$pending_new" "$pending"
    pending_new=''
    [ "$(stat -c '%u:%g:%a:%h:%F' "$pending" 2>/dev/null || true)" = \
        '0:0:600:1:regular file' ] \
        && matchpathcon -V "$pending" >/dev/null \
        || fail "pending rollback state publication is unsafe"
    sync -- "$pending"
    sync -- /.snapshots/.noid-state

    new_number=$(snapper --quiet --ambit classic -c root rollback --print-number \
        --description "NoID Privacy rollback to snapshot $target" \
        --cleanup-algorithm number "$target") \
        || fail "snapper rollback failed; pending evidence retained"
    [[ "$new_number" =~ ^[1-9][0-9]*$ ]] \
        || fail "snapper returned an invalid rollback snapshot number"
    sync
    verify_published_default "$new_number" "$target" \
        || fail "rollback default postcondition failed; pending evidence retained"
fi

ready_new=$(mktemp /.snapshots/.noid-state/.rollback-ready.XXXXXX)
printf 'TARGET=%s\nDEFAULT_SNAPSHOT=%s\nVERIFIED_AT=%s\n' \
    "$target" "$new_number" "$(date -u +%FT%TZ)" > "$ready_new"
chown root:root "$ready_new"; chmod 0600 "$ready_new"
mv -fT -- "$ready_new" "$ready"
ready_new=''
[ "$(stat -c '%u:%g:%a:%h:%F' "$ready" 2>/dev/null || true)" = \
    '0:0:600:1:regular file' ] \
    && matchpathcon -V "$ready" >/dev/null \
    || fail "ready rollback state publication is unsafe"
sync -- "$ready"
sync -- /.snapshots/.noid-state
rm -f "$pending"
sync -- /.snapshots/.noid-state
echo "Verified rollback root #$new_number is the Btrfs default. Reboot only when ready."
SNAPPER_ROLLBACK_EOF

chmod 0755 /usr/libexec/noid-snapper-create \
    /usr/libexec/noid-snapper-status /usr/libexec/noid-snapper-rollback
chown root:root /usr/libexec/noid-snapper-create \
    /usr/libexec/noid-snapper-status /usr/libexec/noid-snapper-rollback
mkdir -p /usr/local/sbin
ln -sfn /usr/libexec/noid-snapper-rollback /usr/local/sbin/noid-snap-rollback

cat > /etc/sudoers.d/noid-snapper-status <<'SNAPPER_STATUS_SUDO_EOF'
# NoID Privacy: expose only the fixed, argument-free snapshot summary.
Cmnd_Alias NOID_SNAPPER_STATUS = /usr/libexec/noid-snapper-status ""
%wheel ALL=(root) NOPASSWD: NOID_SNAPPER_STATUS
SNAPPER_STATUS_SUDO_EOF
chmod 0440 /etc/sudoers.d/noid-snapper-status
chown root:root /etc/sudoers.d/noid-snapper-status
visudo -cf /etc/sudoers.d/noid-snapper-status >/dev/null \
    || { echo "[Module 20] FAIL: invalid noid-snapper-status sudoers rule"; exit 1; }

# ============================================================================
# Step 11 — Install user-facing recovery documentation
# ============================================================================

mkdir -p /usr/share/doc/noid-privacy
cat > /usr/share/doc/noid-privacy/20-rollback-recovery.md <<'RECOVERY_DOC_EOF'
# NoID Privacy — Snapshot Rollback Recovery Guide

## What rollback covers (and what it does NOT)

This system provides a checked Snapper rollback path for the root filesystem.
It is available only when the installed root filesystem is Btrfs. On an ext4,
XFS or other non-Btrfs root, the first-boot initializer records a local journal
message and exits successfully without creating or validating Snapper state.
The independent M21 initramfs convergence still runs for that topology.
The first-boot initializer makes the running root the Btrfs default, removes
explicit root-subvolume selectors from fstab/BLS and mounts the snapshot store
from a stable top-level subvolume. `noid-snap-rollback` refuses to proceed if
any part of that boot contract has drifted.

### Rollback restores:
- The RPM database and package payload stored in the root subvolume
  (state at snapshot time; separate mounts listed below are not restored)
- `/etc/` configurations (PAM, firewall, sysctl, systemd units, etc.)
- System binaries and libraries under `/usr/`
- Kernel modules under `/usr/lib/modules/` (not `/boot/` images)
- Module-specific customizations (SELinux policy, udev rules, polkit)
- `/var/log/` — logs live in the root subvolume, so they are rolled back
  too. Keeping logs across a rollback would need a separate `/var/log`
  subvolume, which this image does not create.
- `/var/tmp/` — it is aged as temporary data, but remains in the root
  subvolume and is therefore rolled back with `/var`.

### Rollback does NOT restore:
- **`/home/`** — personal files, settings, and data stay at their current
  state. The `home` btrfs subvolume is not tracked by snapper in this
  image (deliberately — system rollback should not destroy user work).
- **`/boot/`** — Fedora puts `/boot/` on ext4, not btrfs, so kernel
  images are outside snapshot scope. `installonly_limit=3` keeps the
  three most recent kernels available, improving the chance that a recent
  rolled-back root still has a matching kernel; older points can require a
  kernel reinstall.
- **`/tmp/`** — it is a RAM-backed tmpfs and therefore outside the Btrfs
  root snapshot.
- **`/var/lib/libvirt/`** — VM disks and runtime state stay on the stable
  top-level `libvirt` subvolume so live VM data is never rolled back
  implicitly. `/etc/libvirt` is in the root snapshot, so validate that its
  older configuration still matches the current VM state before starting VMs.

### For personal file recovery
This tool is **not a file-recovery solution**. If you accidentally deleted a
file under `/home/`, stop writing to the affected filesystem and recover from a
known backup. Filesystem-level salvage is an offline, destructive-risk workflow
whose exact commands depend on the device and damage state; use maintained
Btrfs documentation and work on a copy rather than improvising against the
mounted home subvolume.

If you want `/home` snapshot capability, you can opt into it manually:

```bash
sudo snapper -c home create-config /home
# Edit /etc/snapper/configs/home: set TIMELINE_CREATE="no" (privacy)
# Add "home" to SNAPPER_CONFIGS in /etc/sysconfig/snapper
# (e.g.: sudo sed -i 's|SNAPPER_CONFIGS="root"|SNAPPER_CONFIGS="root home"|' /etc/sysconfig/snapper)
```

Note: enabling timeline snapshots on `/home` creates an hourly
filesystem-activity fingerprint that slightly weakens privacy posture.
The image ships without this config deliberately.

## Rollback from a working boot

The supported wrapper checks the native Btrfs-default boot model, the selected
snapshot's fstab, the persistent snapshot-store mount and the newly published
read-write default. It holds a shutdown/sleep inhibitor when logind is running
and the shared boot-mutation lock for the complete root-selection transaction.
It requires a confirmed M21 host-only or recovered-Generic basis and leaves a
root-only pending record if the operation is interrupted. After a different
Btrfs default is published, the central guard refuses every later initramfs,
BLS and GRUB mutation until that root has booted. Do not bypass the wrapper
with raw `snapper rollback`, `dracut`, `grubby` or `grub2-mkconfig` commands.
Until reboot, the status helper reports the valid transition as
`boot=reboot-required`; `boot=degraded` remains a hard stop.

```bash
# 1. List snapshots to find the one you want
sudo snapper -c root list

# 2. Publish a verified read-write rollback root
sudo noid-snap-rollback <N>

# 3. Reboot into the rolled-back state
sudo reboot
```

To resume an operation whose persistent pending record survived interruption,
run `sudo noid-snap-rollback --resume`. Its narrow resume path still takes the
same boot lock, validates the M21 basis and accepts only the recorded Snapper
transaction; other boot writers remain blocked until recovery is complete.

## Recovery-shell boundaries

GRUB rescue is a boot-loader prompt, not a Linux shell; it has neither Snapper
nor access to this helper. `systemd.unit=rescue.target` and
`systemd.unit=emergency.target` provide no maintenance shell on this image
(the root account is locked and SULOGIN_FORCE is not set). If the installed
kernel can still reach userspace, edit its GRUB entry with `e`, append
`systemd.unit=multi-user.target`, boot, unlock the volume and log in at the
text console with your user account. Confirm that `/` is writable, then run
the same checked wrapper via sudo (snapperd and systemd-logind are available
at multi-user.target). This path still depends on a usable installed root and
matching `/boot` kernel.

If the installed root cannot reach multi-user.target, use Fedora live media to
unlock and inspect it. Do not run a raw `snapper rollback` or rename subvolumes
from GRUB or an improvised partial chroot. The release gate exercises the exact
live-media unlock/mount/chroot path in a disposable encrypted VM; follow the
candidate's tested recovery transcript rather than substituting device names.

`installonly_limit=3` keeps the three most recent kernels in `/boot`, so the
kernel that matches a recent snapshot is normally still present. If a much
older snapshot needs a pruned kernel, reinstall it first with
`sudo dnf install kernel-<VERSION>`.

## Verify Rollback Success

After reboot:

```bash
# Running root ID must equal the selected Btrfs default; mounts stay stable
sudo /usr/libexec/noid-snapper-status
findmnt / /.snapshots /var/lib/libvirt

# Should show pre-update packages
sudo rpm -qa | sort > /tmp/post-rollback-packages.txt

# AIDE is evidence, not an automatic success oracle after rollback
sudo /usr/local/sbin/noid-aide-check.sh
```

Rollback restores the older root copy of the AIDE database and `/var/log` while
leaving `/boot`, `/home` and `/var/lib/libvirt` at their current state. Review
the database age, the rollback ready/pending record and every reported
difference. Never accept or replace an AIDE database merely to make this
transition appear clean.

## Troubleshooting

**"snapper rollback fails"**
- Run `sudo /usr/libexec/noid-snapper-status` and inspect
  `systemctl status noid-snapper-init.service`.
- Confirm `findmnt / /.snapshots /var/lib/libvirt` before retrying.
- Do not bypass a degraded boot model with a manual subvolume swap.

**"Snapshot is missing a matching kernel"**
- The matching kernel may have been pruned by installonly_limit=3
- Boot normally and `sudo dnf install kernel-<VERSION>`, or roll back to a
  newer snapshot whose kernel is still present

## Ad-hoc Snapshots (outside noid-update-all.sh)

The user-invoked update flow (`/usr/local/bin/noid-update-all.sh`) creates a
paired pre/post transaction when its Snapper preflight succeeds. The weekly
timer is a notification only; it never runs the update. For operations OUTSIDE
the orchestrator — manual `dnf install X`, editing /etc files, testing
experimental packages — use `noid-snap-pre` to create one standalone rollback
point before the operation:

```bash
# Create a described standalone rollback point before the operation
sudo noid-snap-pre "installing signal-desktop"

# Run your operation
sudo dnf install signal-desktop

# If it breaks the system: sudo noid-snap-rollback <N> ; sudo reboot
```

`python3-dnf-plugin-snapper` is intentionally NOT installed because it is a
legacy Python DNF4 plugin that DNF5 does not load. Installing it would pull
the unused Python-DNF4 dependency path and would create automatic snapshots
only when DNF4 is invoked. `noid-snap-pre` is the explicit DNF5-compatible
replacement for ad-hoc rollback points. It creates a standalone Snapper
`single` snapshot through the root-owned canonical creator, including its
measured free-space preflight.

**When to use `noid-snap-pre`:**
- Before `sudo dnf install/remove/upgrade/downgrade` any package manually
- Before editing /etc/ files (PAM config, firewall rules, sysctl)
- Before testing experimental kernel modules (akmod-evdi, akmod-nvidia)
- Before enrolling a new MOK key
- Before disabling/unlocking any hardening (e.g. USBGuard allow-device --permanent)

Two independent cleanup bounds apply. The daily
`noid-snapper-prune.timer` targets deletion of snapshots older than 30 days
using Snapper's machine-readable identity/date state. Snapper's daily number
cleanup separately keeps the youngest eligible normal/important points under
`NUMBER_LIMIT=50` / `NUMBER_LIMIT_IMPORTANT=5` after `NUMBER_MIN_AGE=1800`.
At a low snapshot rate the age target can bind first; frequent ad-hoc
snapshots can reach the count bound and lose older points before 30 days.
Neither setting guarantees a minimum 30-day history.

A snapshot that is the active or Btrfs-default rollback root cannot be deleted
and is reported as `protected` until another root is selected. Large clock
discontinuities defer destructive expiry for a later stable run.
Retention evidence older than 48 hours or over five minutes in the future is
reported as `unknown`, never as a current successful result.
`important=yes` is not an indefinite exception to the age pruner. Export any
long-term recovery point off-host instead of relying on either local bound.

## Architecture References

- Snapper: https://github.com/openSUSE/snapper
- Btrfs subvolume and non-recursive snapshot semantics:
  https://btrfs.readthedocs.io/en/latest/btrfs-subvolume.html
- DNF5 Actions plugin (available opt-in transaction hooks):
  https://dnf5.readthedocs.io/en/latest/libdnf5_plugins/actions.8.html
RECOVERY_DOC_EOF

chmod 644 /usr/share/doc/noid-privacy/20-rollback-recovery.md
chown root:root /usr/share/doc/noid-privacy/20-rollback-recovery.md

# ============================================================================
# Step 11b — Install noid-snap-pre helper (ad-hoc snapshot convenience)
# ============================================================================
# Convenience wrapper for dnf/config-edits outside the user-invoked
# noid-update-all.sh flow. The legacy Python DNF4 Snapper plugin is not loaded
# by DNF5; this explicit helper fills the gap without adding automatic work.
#
# DELIBERATE DECISION (do not re-litigate): automatic pre/post snapshots on
# every dnf transaction (a libdnf5-plugins actions.d file) are NOT shipped —
# Silent-Machine = explicit user-invoked rollback points; noid-update-all.sh
# covers upgrades (the primary risk vector), noid-snap-pre covers ad-hoc
# operations; auto-Actions would add a retention candidate for every
# short-lived dnf call. Users can opt in manually via their own .actions file.

cat > /usr/local/bin/noid-snap-pre <<'SNAP_PRE_EOF'
#!/bin/bash
# noid-snap-pre — create a described standalone rollback point before an
# ad-hoc operation
#
# Thin wrapper around the canonical measured creator:
#   /usr/libexec/noid-snapper-create single "..."
#
# `single` is deliberate: Snapper `pre` snapshots require a corresponding
# `post`, while this helper creates one independent point before an operation.
#
# After creating the snapshot, run your actual operation. If it goes wrong:
#   sudo noid-snap-rollback <N> ; sudo reboot
# See /usr/share/doc/noid-privacy/20-rollback-recovery.md.

set -euo pipefail

SNAP_PRE_MODE=standalone
if [ "${1:-}" = "--embedded" ]; then
    SNAP_PRE_MODE=embedded
    shift
fi

# shellcheck source=/dev/null
if [ -r /usr/local/lib/noid-privacy/agent-install-format.sh ]; then
    if [ "$SNAP_PRE_MODE" = embedded ]; then
        NOID_FMT_AUTO_TITLE='' NOID_FMT_AUTO_SUBTITLE='' \
            . /usr/local/lib/noid-privacy/agent-install-format.sh
    else
        NOID_FMT_AUTO_TITLE="NoID Privacy — Snapshot" \
        NOID_FMT_AUTO_SUBTITLE="Pre-change rollback point" \
            . /usr/local/lib/noid-privacy/agent-install-format.sh
    fi
fi

usage() {
    echo 'usage: noid-snap-pre [--embedded] [DESCRIPTION]'
}

case "${1:-}" in
    --help|-h)
        [ "$#" -eq 1 ] || { usage >&2; exit 2; }
        usage
        exit 0
        ;;
esac
[ "$#" -le 1 ] || { usage >&2; exit 2; }

if [ "$(id -u)" -ne 0 ]; then
    echo "This helper must be run as root (use sudo)." >&2
    exit 1
fi

DESC="${1:-ad-hoc rollback point}"

if [ ! -x /usr/libexec/noid-snapper-create ]; then
    echo "Error: canonical snapshot creator is unavailable." >&2
    exit 1
fi

SNAP_NUM=$(/usr/libexec/noid-snapper-create single "$DESC") || {
    echo "Error: rollback-point preflight or creation failed." >&2
    exit 1
}

if [ "$SNAP_PRE_MODE" = embedded ]; then
    echo "Rollback snapshot #${SNAP_NUM} created."
else
    echo "Standalone rollback snapshot #${SNAP_NUM} created: $DESC"
    echo ""
    echo "Next: run your operation (e.g. sudo dnf install X)."
    echo "If it breaks the system: sudo noid-snap-rollback <N> ; sudo reboot"
fi
SNAP_PRE_EOF

chmod 755 /usr/local/bin/noid-snap-pre
chown root:root /usr/local/bin/noid-snap-pre

# ============================================================================
# Step 11d — apply the Snapper log's 30-day maxage target
# ============================================================================
# Vendor ships maxage 60 + rotate 99 + size 10M. Set maxage 30 + rotate 30
# AND pin the weekly interval locally while converting size->maxsize: a bare
# `size` trigger is
# mutually exclusive with the time interval (logrotate(8)), so the active log
# would rotate only after reaching 10M and maxage — which is evaluated only at
# a rotation event — could remain unevaluated for a long time. `maxsize`
# preserves the explicit weekly interval (weekly OR at 10M, whichever comes
# first). Rotated logs older than 30 days are therefore
# removed at the next rotation; this is not an exact day-30 deadline.
# %config(noreplace) makes the policy survive RPM upgrades (vendor default ->
# .rpmnew). The independently pruned daily wtmp/btmp policy is owned by M42.
echo "[Module 20] Step 11d: applying /etc/logrotate.d/snapper maxage/rotation policy"
[ -f /etc/logrotate.d/snapper ] && [ ! -L /etc/logrotate.d/snapper ] \
    || { echo "[Module 20] FAIL: RPM-owned /etc/logrotate.d/snapper is missing or unsafe"; exit 1; }
sed -i \
    -e '/^[[:space:]]*\(hourly\|daily\|weekly\|monthly\|yearly\)[[:space:]]*$/d' \
    -e '/^[[:space:]]*maxage[[:space:]]\+[0-9]\+$/i\    weekly' \
    -e 's/^[[:space:]]*maxage[[:space:]]\+[0-9]\+$/    maxage 30/' \
    -e 's/^[[:space:]]*rotate[[:space:]]\+[0-9]\+$/    rotate 30/' \
    -e 's/^[[:space:]]*size[[:space:]]\+[0-9]\+[kKmMgG]*$/    maxsize 10M/' \
    /etc/logrotate.d/snapper
chown root:root /etc/logrotate.d/snapper
chmod 0644 /etc/logrotate.d/snapper

# ============================================================================
# Step 11e — noid-snapper-prune.sh + service + timer (independent time-based
#                30-day target)
# ============================================================================
# TIME-based 30-day target on top of snapper's COUNT-based NUMBER_LIMIT —
# parses authoritative Snapper JSON; daily 07:40 +20min jitter (after
# audit-prune 07:35). Active/default roots are protected, never mis-deleted.
echo "[Module 20] Step 11e: writing noid-snapper-prune.sh + service + timer"

mkdir -p /usr/local/sbin
cat > /usr/local/sbin/noid-snapper-prune.sh <<'SNAPPER_PRUNE_EOF'
#!/bin/bash
# NoID Privacy — measured 30-day target for deletable Snapper snapshots.
# Snapper's machine-readable state, not directory names or mutable info.xml,
# supplies snapshot identity, timestamp and active/default protection flags.

set -u
set -o pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH LC_ALL=C.UTF-8 TZ=UTC
unset PYTHONPATH PYTHONHOME
umask 077

CUTOFF_DAYS=30
MAX_CLOCK_STEP=172800
MAX_FUTURE_SKEW=300
LOG_TAG=noid-snapper-prune
LOGGER="${NOID_SNAPPER_LOGGER:-logger}"
SNAPPER="${NOID_SNAPPER_BIN:-snapper}"
STATE_DIR="${NOID_SNAPPER_STATE_DIR:-/.snapshots/.noid-state}"
NOW_EPOCH="${NOID_SNAPPER_NOW_EPOCH:-$(date +%s)}"
CLOCK_STATE="$STATE_DIR/prune-clock.state"
STATUS_FILE="$STATE_DIR/retention.status"
STATE_UID=$(id -u)
STATE_GID=$(id -g)
status_tmp=''
clock_tmp=''
rows=''
cleanup_prune_candidates() {
    local rc=$? cleanup_failed=0 candidate
    trap - EXIT
    for candidate in "$status_tmp" "$clock_tmp" "$rows"; do
        [ -z "$candidate" ] || rm -f -- "$candidate" || cleanup_failed=1
    done
    if [ "$cleanup_failed" -ne 0 ]; then
        "$LOGGER" -t "$LOG_TAG" \
            "FAILED: private retention candidate cleanup failed" || true
        [ "$rc" -ne 0 ] || rc=1
    fi
    exit "$rc"
}
trap cleanup_prune_candidates EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
if [ "$STATE_DIR" = /.snapshots/.noid-state ]; then
    [ "$(findmnt --target /.snapshots -n -o TARGET 2>/dev/null)" = /.snapshots ] \
        && [ "$(findmnt --target /.snapshots -n -o FSROOT 2>/dev/null)" = /snapshots ] \
        && [ "$(findmnt --target /.snapshots -n -o MAJ:MIN 2>/dev/null)" \
             = "$(findmnt --target / -n -o MAJ:MIN 2>/dev/null)" ] \
        || { "$LOGGER" -t "$LOG_TAG" "FAILED: stable snapshot-state mount unavailable"; exit 1; }
    [ -d "$STATE_DIR" ] && [ ! -L "$STATE_DIR" ] \
        || { "$LOGGER" -t "$LOG_TAG" "FAILED: stable snapshot-state directory unavailable"; exit 1; }
    matchpathcon -V /.snapshots >/dev/null 2>&1 \
        && matchpathcon -V "$STATE_DIR" >/dev/null 2>&1 \
        || { "$LOGGER" -t "$LOG_TAG" "FAILED: stable snapshot-state SELinux labels differ"; exit 1; }
else
    # Explicit fixture path used only by the repository behavioral test.
    mkdir -p "$STATE_DIR" || exit 1
fi
[ "$(stat -c '%u:%g:%a:%F' "$STATE_DIR" 2>/dev/null || true)" = \
    "$STATE_UID:$STATE_GID:700:directory" ] \
    || { "$LOGGER" -t "$LOG_TAG" "FAILED: unsafe snapshot-state directory metadata"; exit 1; }

retire_status() {
    [ "$(stat -c '%u:%g:%a:%F' "$STATE_DIR" 2>/dev/null || true)" = \
        "$STATE_UID:$STATE_GID:700:directory" ] || return 1
    rm -f -- "$STATUS_FILE" || return 1
    [ ! -e "$STATUS_FILE" ] && [ ! -L "$STATUS_FILE" ] || return 1
    sync -- "$STATE_DIR"
}

validate_status() {
    local expected_state=$1 expected_removed=$2 expected_recent=$3
    local expected_protected=$4 expected_failures=$5 expected_checked_at=$6
    local -a lines=()
    [ -f "$STATUS_FILE" ] && [ ! -L "$STATUS_FILE" ] \
        && [ "$(stat -c '%u:%g:%a:%h:%F' "$STATUS_FILE" \
                2>/dev/null || true)" = \
            "$STATE_UID:$STATE_GID:600:1:regular file" ] \
        || return 1
    mapfile -t lines < "$STATUS_FILE" || return 1
    [ "${#lines[@]}" -eq 6 ] \
        && [ "${lines[0]}" = "STATUS=$expected_state" ] \
        && [ "${lines[1]}" = "REMOVED=$expected_removed" ] \
        && [ "${lines[2]}" = "RECENT=$expected_recent" ] \
        && [ "${lines[3]}" = "PROTECTED=$expected_protected" ] \
        && [ "${lines[4]}" = "FAILURES=$expected_failures" ] \
        && [ "${lines[5]}" = "CHECKED_AT=$expected_checked_at" ]
}

write_status() {
    local state=$1 removed=$2 recent=$3 protected=$4 failures=$5
    local checked_at
    if ! checked_at=$(date -u -d "@$NOW_EPOCH" +%FT%TZ); then
        retire_status || true
        return 1
    fi
    if ! status_tmp=$(mktemp "$STATE_DIR/.snapper-retention.XXXXXX"); then
        retire_status || true
        return 1
    fi
    if ! printf 'STATUS=%s\nREMOVED=%s\nRECENT=%s\nPROTECTED=%s\nFAILURES=%s\nCHECKED_AT=%s\n' \
            "$state" "$removed" "$recent" "$protected" "$failures" \
            "$checked_at" > "$status_tmp" \
            || ! chmod 0600 "$status_tmp"; then
        rm -f -- "$status_tmp"
        status_tmp=''
        retire_status || true
        return 1
    fi
    if ! mv -fT -- "$status_tmp" "$STATUS_FILE"; then
        rm -f -- "$status_tmp"
        status_tmp=''
        retire_status || true
        return 1
    fi
    status_tmp=''
    if ! validate_status "$state" "$removed" "$recent" \
            "$protected" "$failures" "$checked_at" \
            || ! sync -- "$STATUS_FILE" \
            || ! sync -- "$STATE_DIR"; then
        retire_status || true
        return 1
    fi
}

validate_clock_state() {
    local expected=${1:-} value
    local -a lines=()
    [ -f "$CLOCK_STATE" ] && [ ! -L "$CLOCK_STATE" ] \
        && [ "$(stat -c '%u:%g:%a:%h:%F' "$CLOCK_STATE" \
                2>/dev/null || true)" = \
            "$STATE_UID:$STATE_GID:600:1:regular file" ] \
        || return 1
    mapfile -t lines < "$CLOCK_STATE" || return 1
    [ "${#lines[@]}" -eq 1 ] \
        && [[ "${lines[0]}" =~ ^LAST_EPOCH=(0|[1-9][0-9]*)$ ]] \
        || return 1
    value=${lines[0]#LAST_EPOCH=}
    [ -z "$expected" ] || [ "$value" = "$expected" ]
}

case "$NOW_EPOCH" in ''|*[!0-9]*)
    "$LOGGER" -t "$LOG_TAG" "FAILED: invalid current epoch"
    exit 1
    ;;
esac
date -u -d "@$NOW_EPOCH" +%FT%TZ >/dev/null 2>&1 || {
    "$LOGGER" -t "$LOG_TAG" "FAILED: current epoch is outside the supported date range"
    exit 1
}

# Refuse destructive expiry on the first observation, a backward step or a
# >48-hour forward step. Record the new anchor and require a later stable run.
# This delays cleanup after long downtime by one run rather than interpreting a
# clock discontinuity as proof that every recovery point suddenly expired.
clock_guard=0
previous=''
if validate_clock_state; then
    previous=$(sed -n 's/^LAST_EPOCH=//p' "$CLOCK_STATE")
fi
if ! [[ "$previous" =~ ^[0-9]+$ ]]; then
    clock_guard=1
elif [ "$NOW_EPOCH" -lt "$previous" ] \
        || [ $((NOW_EPOCH - previous)) -gt "$MAX_CLOCK_STEP" ]; then
    clock_guard=1
fi
clock_tmp=$(mktemp "$STATE_DIR/.snapper-prune-clock.XXXXXX") || exit 1
if ! printf 'LAST_EPOCH=%s\n' "$NOW_EPOCH" > "$clock_tmp" \
        || ! chmod 0600 "$clock_tmp" \
        || ! mv -fT -- "$clock_tmp" "$CLOCK_STATE"; then
    rm -f -- "$clock_tmp"
    clock_tmp=''
    exit 1
fi
clock_tmp=''
if ! validate_clock_state "$NOW_EPOCH" \
        || ! sync -- "$CLOCK_STATE" \
        || ! sync -- "$STATE_DIR"; then
    exit 1
fi

if [ "$clock_guard" -eq 1 ]; then
    write_status clock-guard 0 0 0 0 || exit 1
    "$LOGGER" -t "$LOG_TAG" \
        "clock continuity not established; destructive snapshot expiry deferred to a later stable run"
    exit 0
fi

CUTOFF_EPOCH=$((NOW_EPOCH - CUTOFF_DAYS * 86400))
rows=$(mktemp "$STATE_DIR/.snapper-rows.XXXXXX") || exit 1
if ! "$SNAPPER" -c root --utc --iso --jsonout list --disable-used-space 2>/dev/null \
        | python3 -I -c '
from datetime import datetime, timezone
import json, sys

now = int(sys.argv[1])
max_future_skew = int(sys.argv[2])
obj = json.load(sys.stdin)
rows = obj.get("root")
if not isinstance(rows, list):
    raise SystemExit(1)
seen = set()
output = []
for row in rows:
    if not isinstance(row, dict):
        raise SystemExit(1)
    number = row.get("number")
    if type(number) is not int or number < 0 or number in seen:
        raise SystemExit(1)
    seen.add(number)
    if number == 0:
        continue
    date = row.get("date")
    default = row.get("default")
    active = row.get("active")
    if not isinstance(date, str) or not date or type(default) is not bool or type(active) is not bool:
        raise SystemExit(1)
    if "\t" in date or "\n" in date:
        raise SystemExit(1)
    try:
        parsed = datetime.fromisoformat(date.replace("Z", "+00:00"))
    except (OverflowError, OSError, ValueError):
        raise SystemExit(1)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    epoch = int(parsed.timestamp())
    if epoch < 0 or epoch > now + max_future_skew:
        raise SystemExit(1)
    output.append((number, epoch, date, default, active))
for number, epoch, date, default, active in output:
    print(f"{number}\t{epoch}\t{date}\t{int(default)}\t{int(active)}")
' "$NOW_EPOCH" "$MAX_FUTURE_SKEW" > "$rows"; then
    if ! write_status degraded 0 0 0 1; then
        "$LOGGER" -t "$LOG_TAG" \
            "FAILED: degraded retention status publication failed; prior status retired or untrusted" \
            || true
    fi
    "$LOGGER" -t "$LOG_TAG" "FAILED: Snapper JSON state is unavailable or malformed"
    exit 1
fi

REMOVED=0
RECENT=0
PROTECTED=0
FAILURES=0
while IFS=$'\t' read -r num snap_epoch date_str is_default is_active; do
    if ! [[ "$num" =~ ^[1-9][0-9]*$ ]] \
            || ! [[ "$snap_epoch" =~ ^[0-9]+$ ]] \
            || ! [[ "$is_default" =~ ^[01]$ ]] \
            || ! [[ "$is_active" =~ ^[01]$ ]]; then
        FAILURES=$((FAILURES + 1))
        "$LOGGER" -t "$LOG_TAG" "FAILED: invalid authoritative row for snapshot ${num:-unknown}"
        continue
    fi
    if [ "$snap_epoch" -ge "$CUTOFF_EPOCH" ]; then
        RECENT=$((RECENT + 1))
        continue
    fi
    if [ "$is_default" -eq 1 ] || [ "$is_active" -eq 1 ]; then
        PROTECTED=$((PROTECTED + 1))
        "$LOGGER" -t "$LOG_TAG" \
            "PROTECTED: old snapshot $num is active/default and cannot be expired while selected"
        continue
    fi
    if "$SNAPPER" -c root delete --sync "$num" >/dev/null 2>&1; then
        REMOVED=$((REMOVED + 1))
        "$LOGGER" -t "$LOG_TAG" "deleted snapshot $num (date=$date_str)"
    else
        FAILURES=$((FAILURES + 1))
        "$LOGGER" -t "$LOG_TAG" "FAILED to delete snapshot $num (date=$date_str)"
    fi
done < "$rows"

if [ "$FAILURES" -gt 0 ]; then
    state=degraded
elif [ "$PROTECTED" -gt 0 ]; then
    state=protected
else
    state=ok
fi
write_status "$state" "$REMOVED" "$RECENT" "$PROTECTED" "$FAILURES" || exit 1
"$LOGGER" -t "$LOG_TAG" \
    "completed: $REMOVED deleted | $RECENT recent | $PROTECTED protected active/default | $FAILURES failures"
[ "$FAILURES" -eq 0 ] || exit 1
SNAPPER_PRUNE_EOF

chmod 0755 /usr/local/sbin/noid-snapper-prune.sh
chown root:root /usr/local/sbin/noid-snapper-prune.sh

cat > /etc/systemd/system/noid-snapper-prune.service <<'SNAPPER_PRUNE_SERVICE_EOF'
[Unit]
Description=NoID Privacy prune eligible Snapper snapshots beyond the 30-day target
Documentation=man:snapper(8) man:snapper-configs(5)
After=snapperd.service noid-snapper-init.service
Requires=snapperd.service noid-snapper-init.service
RequiresMountsFor=/.snapshots
ConditionKernelCommandLine=!rd.live.image
ConditionPathExists=/.snapshots/.noid-state/init.done

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/noid-snapper-prune.sh

# Sandbox (not as strict as audit/install-logs - snapper needs D-Bus)
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/log -/.snapshots/.noid-state
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native
PrivateNetwork=yes
RestrictAddressFamilies=AF_UNIX
RestrictNamespaces=yes
# CapabilityBoundingSet: minimal - snapper-delete goes via D-Bus to snapperd
CapabilityBoundingSet=CAP_DAC_READ_SEARCH

# Low priority
Nice=19
IOSchedulingClass=idle
IOSchedulingPriority=7
SNAPPER_PRUNE_SERVICE_EOF

cat > /etc/systemd/system/noid-snapper-prune.timer <<'SNAPPER_PRUNE_TIMER_EOF'
[Unit]
Description=Daily NoID Privacy Snapper 30-day retention target
Documentation=man:systemd.timer(5)
ConditionKernelCommandLine=!rd.live.image

[Timer]
# Daily at 07:40 with 20min jitter (stagger from audit-prune at 07:35)
OnCalendar=07:40:00
RandomizedDelaySec=20m
Persistent=true

[Install]
WantedBy=timers.target
SNAPPER_PRUNE_TIMER_EOF

chmod 0644 /etc/systemd/system/noid-snapper-prune.{service,timer}
chown root:root /etc/systemd/system/noid-snapper-prune.{service,timer}

if ! systemctl daemon-reload; then
    echo "[Module 20] FAIL: systemd daemon-reload failed"
    exit 1
fi
if systemctl enable noid-snapper-prune.timer 2>/dev/null; then
    echo "[Module 20] noid-snapper-prune.timer enabled"
else
    echo "[Module 20] FAIL: noid-snapper-prune.timer could not be enabled"
    exit 1
fi

# ============================================================================
# Step 12 — SELinux contexts (restorecon for custom paths)
# ============================================================================

# Every target is one exact path (regular files plus the empty plugin
# directory); recursive relabeling would broaden M20's ownership boundary. A
# missing tool or failed label reconciliation is a build failure, not a warning
# hidden from the installation evidence.
command -v restorecon >/dev/null 2>&1 \
    || { echo "[Module 20] FAIL: restorecon is unavailable"; exit 1; }
restorecon -F \
    /usr/libexec/snapper/plugins \
    /usr/local/bin/noid-snapper-init.sh \
    /usr/local/bin/noid-snap-pre \
    /usr/libexec/noid-snapper-create \
    /usr/libexec/noid-snapper-status \
    /usr/libexec/noid-snapper-rollback \
    /usr/local/sbin/noid-snapper-prune.sh \
    /etc/sudoers.d/noid-snapper-status \
    /etc/systemd/system/noid-snapper-init.service \
    /etc/systemd/system/noid-snapper-prune.service \
    /etc/systemd/system/noid-snapper-prune.timer \
    /etc/systemd/system/snapper-cleanup.service.d/99-noid-live-guard.conf \
    /etc/systemd/system/snapper-cleanup.timer.d/99-noid-frequency.conf \
    /etc/snapper/configs/root \
    /etc/logrotate.d/snapper \
    /usr/share/doc/noid-privacy/20-rollback-recovery.md \
    || { echo "[Module 20] FAIL: SELinux label reconciliation failed"; exit 1; }

# ============================================================================
# Step 13 — Verification
# ============================================================================

echo "[Module 20] Verification"

# 13.1 — Packages installed (python3-snapper removed in F44 — D-Bus migration)
rpm -q snapper                >/dev/null || { echo "[Module 20] FAIL: snapper not installed"; exit 1; }

# 13.2 — Excluded packages must be absent
if rpm -q python3-dnf-plugin-snapper >/dev/null 2>&1; then
    echo "[Module 20] FAIL: legacy DNF4 Snapper plugin is installed (unused by DNF5; automatic DNF4 snapshots are outside policy)"
    exit 1
fi
if rpm -q grub-btrfs >/dev/null 2>&1; then
    echo "[Module 20] FAIL: grub-btrfs is installed (outside the reviewed Fedora-BLS/ext4-/boot CLI rollback model)"
    exit 1
fi

# 13.2b — Fedora omits Snapper's configured plugin directory. The deliberately
# empty boundary must remain root-owned so an absent optional hook set is both
# log-clean and non-writable by unprivileged users.
[ -d /usr/libexec/snapper/plugins ] \
    && [ ! -L /usr/libexec/snapper/plugins ] \
    && [ "$(stat -c '%u:%g:%a:%F' /usr/libexec/snapper/plugins \
            2>/dev/null || true)" = '0:0:755:directory' ] \
    || { echo "[Module 20] FAIL: empty Snapper plugin boundary is missing or unsafe"; exit 1; }

# 13.3 — Snapper root config contains every exact security/retention value.
[ -f /etc/snapper/configs/root ] || { echo "[Module 20] FAIL: /etc/snapper/configs/root missing"; exit 1; }
for snapper_config_entry in \
    'SUBVOLUME="/"' \
    'FSTYPE="btrfs"' \
    'QGROUP=""' \
    'SPACE_LIMIT="0.5"' \
    'FREE_LIMIT="0.2"' \
    'ALLOW_USERS=""' \
    'ALLOW_GROUPS=""' \
    'SYNC_ACL="no"' \
    'BACKGROUND_COMPARISON="yes"' \
    'NUMBER_CLEANUP="yes"' \
    'NUMBER_MIN_AGE="1800"' \
    'NUMBER_LIMIT="50"' \
    'NUMBER_LIMIT_IMPORTANT="5"' \
    'TIMELINE_CREATE="no"' \
    'TIMELINE_CLEANUP="no"' \
    'TIMELINE_MIN_AGE="1800"' \
    'TIMELINE_LIMIT_HOURLY="0"' \
    'TIMELINE_LIMIT_DAILY="0"' \
    'TIMELINE_LIMIT_WEEKLY="0"' \
    'TIMELINE_LIMIT_MONTHLY="0"' \
    'TIMELINE_LIMIT_YEARLY="0"' \
    'EMPTY_PRE_POST_CLEANUP="yes"' \
    'EMPTY_PRE_POST_MIN_AGE="1800"'; do
    grep -qxF "$snapper_config_entry" /etc/snapper/configs/root \
        || { echo "[Module 20] FAIL: Snapper root config drifted: $snapper_config_entry"; exit 1; }
done
unset snapper_config_entry

# 13.4 — /etc/sysconfig/snapper exists and lists root config (the file
# Fedora's snapper actually reads — Step 2 sed-patches it)
[ -f /etc/sysconfig/snapper ] || { echo "[Module 20] FAIL: /etc/sysconfig/snapper missing (snapper-libs RPM)"; exit 1; }
[ "$(grep -c '^SNAPPER_CONFIGS=' /etc/sysconfig/snapper)" -eq 1 ] \
    && grep -qxF 'SNAPPER_CONFIGS="root"' /etc/sysconfig/snapper \
    || { echo "[Module 20] FAIL: /etc/sysconfig/snapper does not select only the root config"; exit 1; }

# 13.5 — cleanup stays enabled for installed systems but every cleanup/prune
# activation surface rejects a Live kernel command line.
if ! systemctl is-enabled snapper-cleanup.timer >/dev/null 2>&1; then
    echo "[Module 20] FAIL: snapper-cleanup.timer not enabled"
    exit 1
fi
for guard in \
    /etc/systemd/system/snapper-cleanup.timer.d/99-noid-frequency.conf \
    /etc/systemd/system/snapper-cleanup.service.d/99-noid-live-guard.conf \
    /etc/systemd/system/noid-snapper-prune.service \
    /etc/systemd/system/noid-snapper-prune.timer; do
    [ -f "$guard" ] || { echo "[Module 20] FAIL: missing Live guard: $guard"; exit 1; }
    [ "$(grep -c '^ConditionKernelCommandLine=!rd\.live\.image$' "$guard")" -eq 1 ] \
        || { echo "[Module 20] FAIL: invalid Live guard: $guard"; exit 1; }
done
for silent_timer in snapper-timeline.timer snapper-boot.timer; do
    if systemctl is-enabled --quiet "$silent_timer" 2>/dev/null; then
        echo "[Module 20] FAIL: $silent_timer is enabled (explicit-only snapshot policy)"
        exit 1
    fi
done
unset silent_timer

# 13.6 — Helper scripts exist with correct permissions
for script in \
    /usr/local/bin/noid-snapper-init.sh \
    /usr/local/bin/noid-snap-pre \
    /usr/local/sbin/noid-snap-rollback \
    /usr/libexec/noid-snapper-create \
    /usr/libexec/noid-snapper-status \
    /usr/libexec/noid-snapper-rollback; do
    [ -x "$script" ] || { echo "[Module 20] FAIL: $script missing or not executable"; exit 1; }
    bash -n "$script" 2>/dev/null || { echo "[Module 20] FAIL: $script syntax error"; exit 1; }
done
[ -f /etc/sudoers.d/noid-snapper-status ] \
    || { echo "[Module 20] FAIL: noid-snapper-status sudoers rule missing"; exit 1; }
visudo -cf /etc/sudoers.d/noid-snapper-status >/dev/null \
    || { echo "[Module 20] FAIL: noid-snapper-status sudoers rule invalid"; exit 1; }

# 13.7 — Service unit exists + enabled
[ -f /etc/systemd/system/noid-snapper-init.service ] || { echo "[Module 20] FAIL: noid-snapper-init.service missing"; exit 1; }
systemctl is-enabled noid-snapper-init.service    >/dev/null 2>&1 || { echo "[Module 20] FAIL: noid-snapper-init.service not enabled"; exit 1; }

# 13.9 — Recovery doc
[ -f /usr/share/doc/noid-privacy/20-rollback-recovery.md ] || { echo "[Module 20] FAIL: recovery doc missing"; exit 1; }
rec_size=$(stat -c %s /usr/share/doc/noid-privacy/20-rollback-recovery.md)
[ "$rec_size" -gt 2000 ] || { echo "[Module 20] FAIL: recovery doc too small ($rec_size bytes)"; exit 1; }

# 13.10 — logrotate Snapper policy
[ -f /etc/logrotate.d/snapper ] && [ ! -L /etc/logrotate.d/snapper ] \
    || { echo "[Module 20] FAIL: /etc/logrotate.d/snapper missing or unsafe"; exit 1; }
[ "$(stat -c '%u:%g:%a:%h:%F' /etc/logrotate.d/snapper 2>/dev/null || true)" = \
    '0:0:644:1:regular file' ] \
    || { echo "[Module 20] FAIL: /etc/logrotate.d/snapper metadata is unsafe"; exit 1; }
[ "$(grep -cE '^[[:space:]]*weekly[[:space:]]*$' /etc/logrotate.d/snapper)" -eq 1 ] \
    && ! grep -qE '^[[:space:]]*(hourly|daily|monthly|yearly)[[:space:]]*$' \
        /etc/logrotate.d/snapper \
    || { echo "[Module 20] FAIL: /etc/logrotate.d/snapper is not explicitly weekly"; exit 1; }
[ "$(grep -cE '^[[:space:]]*maxage[[:space:]]+30$' /etc/logrotate.d/snapper)" -eq 1 ] || \
    { echo "[Module 20] FAIL: /etc/logrotate.d/snapper maxage not set to 30"; exit 1; }
[ "$(grep -cE '^[[:space:]]*rotate[[:space:]]+30$' /etc/logrotate.d/snapper)" -eq 1 ] || \
    { echo "[Module 20] FAIL: /etc/logrotate.d/snapper rotate not set to 30"; exit 1; }
[ "$(grep -cE '^[[:space:]]*maxsize[[:space:]]+10M$' /etc/logrotate.d/snapper)" -eq 1 ] \
    && ! grep -qE '^[[:space:]]*size[[:space:]]+' /etc/logrotate.d/snapper || \
    { echo "[Module 20] FAIL: /etc/logrotate.d/snapper size not converted to maxsize (weekly maxage evaluation would be lost)"; exit 1; }

# 13.11 — noid-snapper-prune
[ -x /usr/local/sbin/noid-snapper-prune.sh ] || { echo "[Module 20] FAIL: noid-snapper-prune.sh missing or not executable"; exit 1; }
[ -f /etc/systemd/system/noid-snapper-prune.service ] || { echo "[Module 20] FAIL: noid-snapper-prune.service missing"; exit 1; }
[ -f /etc/systemd/system/noid-snapper-prune.timer ] || { echo "[Module 20] FAIL: noid-snapper-prune.timer missing"; exit 1; }
bash -n /usr/local/sbin/noid-snapper-prune.sh 2>/dev/null || { echo "[Module 20] FAIL: noid-snapper-prune.sh bash -n syntax error"; exit 1; }

echo "[Module 20] Done — all verification checks passed"

%end

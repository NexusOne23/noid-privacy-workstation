# ============================================================================
# Module 22 — LUKS + Partitioning + Mount Hardening
# Status: LOCKED 2026-08-02 (v28) — retain the scrub cap after empty resume.
#
# Covers:
#   - STEP 1: /usr/local/bin/noid-mount-hardening.sh (SCRIPT_EOF) — firstboot
#     fstab hardening (matrix in the script header: /tmp + /dev/shm + /boot +
#     /boot/efi = nosuid,nodev,noexec; / = nodiscard; /home =
#     nosuid,nodev,nodiscard; /var + /var/tmp = nosuid,nodev)
#     with append_fstab_opt/ensure_mount_options helpers + post-patch verify
#   - STEP 2: noid-mount-hardening.service (SVC_EOF) — early-boot oneshot,
#     marker-gated, host mount namespace, ConditionKernelCommandLine=
#     !rd.live.image (never mutates the Live-ISO overlay fstab)
#   - STEP 2a: noid-live-mount-hardening.sh (LIVE_MOUNT_SCRIPT_EOF) +
#     noid-live-mount-hardening.service (LIVE_MOUNT_SERVICE_EOF) — live-media
#     /tmp + /dev/shm reconciliation, ConditionKernelCommandLine=rd.live.image
#   - STEP 2b: noid-btrfs-scrub + btrfs-scrub.service/.timer — monthly,
#     rate-limited data-integrity scrub with interrupted-scrub resume
#     (Fedora's btrfs-progs ships no scrub timer; replicated blocks can be
#     repaired from a verified copy, while unreplicated corruption is detected)
#   - STEP 3: user doc 22-disk-encryption.md (DOC_EOF) — LUKS verification,
#     argon2id memory upgrade, TPM2 omission rationale, header backup,
#     additional drives, mount matrix, TRIM, partition layout, 3-2-1 backups
#   - STEP 3b: /usr/local/bin/noid-luks-backup.sh (LUKS_BACKUP_EOF) — opt-in
#     header-backup wrapper (auto-detect LUKS + removable media, SHA256,
#     --verify/--list-existing, refuse-root + sudo-internal)
#
# NOT covered (Anaconda owns these at install time): partition layout, LUKS
# parameters (LUKS2 + installed Argon2id parameters) and filesystem choice.
# Btrfs enables M20 snapshots and STEP 2b scrub; those features are cleanly not
# applicable on other filesystems. Anaconda generates a NEW /etc/fstab during
# install, so mount hardening MUST run at first boot against that file.
#
# Deliberate deviations (do NOT re-litigate):
#   - noexec is OMITTED on /home (Flatpak user installs, AppImages, Steam),
#     /var (RPM scriptlets, dracut) and /var/tmp (DNF/RPM + system-upgrade).
#   - TPM2 auto-unlock is NOT enrolled (doc carries the rationale: hardware
#     binding, evil-maid surface, supply-chain trust).
#   - Argon2id memory/time parameters are hardware-benchmarked by the installer;
#     a reviewed 2 GiB option is documented but not forced.
#   - The mount-hardening service intentionally skips every systemd filesystem
#     namespace directive (PrivateTmp, ProtectHome, ProtectSystem,
#     ProtectKernelTunables/Modules/ControlGroups/Clock/Logs and
#     ReadOnly/ReadWritePaths). Even with PrivateMounts=no, any such directive
#     creates a service-private mount namespace, so successful remounts would
#     disappear when the oneshot exits. Network/process hardening remains.
#   - Custom scrub units instead of the btrfsmaintenance package (native
#     systemd, scrub-only; balance/defrag omitted, trim = fstrim.timer). The
#     native Btrfs per-device limit is authoritative; idle I/O priority alone
#     is ineffective with common schedulers such as mq-deadline and none.
#
# Constraint notes (keep when editing):
#   - append_fstab_opt escapes / in the mountpoint regex via bash parameter
#     expansion BEFORE sed (unescaped /tmp broke the sed address — exit 4,
#     silently fatal under set -eu). tests/22-luks-partitioning-mount
#     EXTRACTS both helpers from the heredoc (function header to a `}` at
#     column 1) and runs them against a mock fstab — keep that layout.
#   - `mount -o remount $mp` does NOT re-read fstab; remount passes ONLY the
#     hardcoded security flags (SEC_FLAGS) — a `defaults`/`size=`/
#     `x-systemd.*` token in remount opts neutralizes flag application.
#   - tests/22-luks-backup-wrapper pins dozens of fixed strings inside the
#     LUKS_BACKUP_EOF heredoc (deployed bytes) + the 'STEP 3b' heading +
#     verify-echo strings ('LUKS backup wrapper perms=0755') in this file.
#
# Cross-reference:
#   - M01: SecureBoot chain. M15: BootGuard (TPM2 rationale cross-ref).
#     M20: snapper requires btrfs; scrub complements snapshots. M42:
#     forensic-retention sibling.
# ============================================================================

# ---------------------------------------------------------------------------
# %post — Module 22 mount hardening + documentation
# ---------------------------------------------------------------------------
%post --erroronfail --log=/var/log/ks-22-luks-partitioning.log
set -euo pipefail

log() { echo "[noid-22-mount] $*"; }
log "=== Module 22 post-install: mount hardening + LUKS documentation ==="

# ====================================================================
# STEP 1: Firstboot mount hardening script
# ====================================================================
log "STEP 1: writing /usr/local/bin/noid-mount-hardening.sh"

cat > /usr/local/bin/noid-mount-hardening.sh <<'SCRIPT_EOF'
#!/usr/bin/env bash
# NoID Privacy — Mount Option Hardening (Module 22)
# Runs at first boot to harden /etc/fstab after Anaconda generates it.
# Idempotent: safe to run multiple times.
#
# Hardening matrix (current upstream mount/Btrfs behavior plus the DISA RHEL 9
# /var nodev requirement; exact references are in the installed guide):
#   /tmp      nosuid,nodev,noexec     — classic exploit payload target
#   /dev/shm  nosuid,nodev,noexec     — exploit fallback when /tmp blocked
#                                       (Electron/V8 JIT uses mprotect fallback)
#   /          nodiscard               — disable Btrfs continuous async discard
#   /home     nosuid,nodev,nodiscard  — noexec deliberately omitted
#                                       (breaks Flatpak user installs, AppImages, Steam)
#   /var      nosuid,nodev            — DISA STIG RHEL 9 V-257869 (nodev);
#                                       nosuid is defense in depth. noexec
#                                       omitted (breaks RPM scriptlets + dracut).
#                                       Covers /var/lib/*, /var/log/* via inherit.
#   /var/tmp  nosuid,nodev            — noexec deliberately omitted for the
#                                       package/build/install compatibility baseline.
#                                       Redundant given /var but kept as defense-in-depth.
#   /boot     nosuid,nodev,noexec     — kernel+initramfs, no need for SUID/dev/exec
#   /boot/efi nosuid,nodev,noexec     — VFAT ESP, defense-in-depth

set -euo pipefail

log() { echo "[noid-mount-hardening] $*"; }

FSTAB_FINAL="/etc/fstab"
FSTAB_DIR="$(dirname -- "$FSTAB_FINAL")"
FSTAB=""
FSTAB_WORK=""
CHANGED=0

cleanup_fstab_work() {
    if [ -n "$FSTAB_WORK" ] && [ -e "$FSTAB_WORK" ]; then
        rm -f -- "$FSTAB_WORK"
    fi
}
trap cleanup_fstab_work EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# Never edit the boot-critical fstab in place. Work on a same-filesystem copy,
# validate it with libmount, sync it, then publish it with one rename. Thus a
# hard cut leaves either the old complete file or the new complete file.
if [ ! -f "$FSTAB_FINAL" ] || [ -L "$FSTAB_FINAL" ]; then
    log "FAIL: $FSTAB_FINAL is not a regular non-symlink file"
    exit 1
fi
FSTAB_WORK=$(mktemp "$FSTAB_DIR/.noid-fstab.XXXXXX")
if ! cp --preserve=all -- "$FSTAB_FINAL" "$FSTAB_WORK"; then
    log "FAIL: could not create private fstab transaction copy"
    exit 1
fi
FSTAB="$FSTAB_WORK"

# Helper: append an option to field 4 of an fstab line matching mnt_regex.
# Forward slashes in mnt_regex are auto-escaped so they don't collide with
# sed's / delimiter (the original implementation had this bug and failed
# silently on paths like /tmp, /dev/shm).
# Returns 0 on success, 1 if line not found or option not present after patch.
append_fstab_opt() {
    local mnt_regex="$1" opt="$2"
    # Auto-escape forward slashes for sed address delimiter
    local escaped="${mnt_regex//\//\\/}"

    # Pre-check: line must exist
    if ! grep -qE "${mnt_regex}" "$FSTAB"; then
        log "  WARN: no fstab line matched ${mnt_regex}"
        return 1
    fi

    # Patch field 4 (options column)
    sed -i -E "/${escaped}/ s/^([[:space:]]*[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+)([^[:space:]]+)(.*)$/\1\2,${opt}\3/" "$FSTAB"

    # Post-check: option must now be present on the matching line
    if ! grep -E "${mnt_regex}" "$FSTAB" | grep -qE "(,|^|[[:space:]])${opt}([,[:space:]]|$)"; then
        log "  FAIL: option ${opt} not present after sed on lines matching ${mnt_regex}"
        return 1
    fi
    return 0
}

# Return success only when /etc/fstab has an active entry whose exact field 2
# is the requested mountpoint. This is the shared boundary for patching,
# runtime reconciliation and verification: an inherited directory is not a
# distinct mount and cannot receive independent mount flags.
fstab_has_mountpoint() {
    local mp="$1"
    awk -v mp="$mp" '
        $1 !~ /^#/ && $2 == mp { found=1 }
        END { exit !found }
    ' "$FSTAB"
}

# Helper: ensure each option in $2 (comma-separated) is present on the fstab
# line for mountpoint $1. Matches ANY source column (UUID=, LABEL=, tmpfs,
# /dev/xxx, path for bind). Skips with a journal message when no line exists.
# Sets CHANGED=1 when any option was appended. Returns 1 on patch failure.
ensure_mount_options() {
    local mp="$1" opts="$2"
    # Escape regex metachars in the path. Only `.` appears in normal mountpoints.
    local mp_re="${mp//./\\.}"
    local pattern="^[[:space:]]*[^[:space:]#]+[[:space:]]+${mp_re}[[:space:]]"
    if ! fstab_has_mountpoint "$mp"; then
        log "  $mp: no fstab entry, skipping"
        return 0
    fi
    local opt
    for opt in ${opts//,/ }; do
        if grep -E "$pattern" "$FSTAB" | grep -qE "(,|^|[[:space:]])${opt}([,[:space:]]|$)"; then
            continue   # already hardened
        fi
        if append_fstab_opt "$pattern" "$opt"; then
            log "  $mp: appended $opt"
            CHANGED=1
        else
            log "  FAIL: could not add $opt to $mp"
            return 1
        fi
    done
    return 0
}

# --- /tmp: tmpfs nosuid,nodev,noexec,size=4G when no entry exists ---
# Respect a custom separate /tmp filesystem instead of adding a duplicate
# target. Only the NoID Privacy-created tmpfs receives the 4 GiB cap.
if ! grep -qE '^[[:space:]]*[^[:space:]#]+[[:space:]]+/tmp[[:space:]]' "$FSTAB"; then
    {
        echo ""
        echo "# NoID Privacy — /tmp hardening (Module 22)"
        echo "tmpfs /tmp tmpfs defaults,nosuid,nodev,noexec,size=4G 0 0"
    } >> "$FSTAB"
    log "/tmp: added tmpfs entry with nosuid,nodev,noexec,size=4G"
    CHANGED=1
else
    ensure_mount_options /tmp "nosuid,nodev,noexec"
fi

# --- /dev/shm: tmpfs nosuid,nodev,noexec ---
if ! grep -qE '^[[:space:]]*[^[:space:]#]+[[:space:]]+/dev/shm[[:space:]]' "$FSTAB"; then
    {
        echo ""
        echo "# NoID Privacy — /dev/shm hardening (Module 22)"
        echo "tmpfs /dev/shm tmpfs defaults,nosuid,nodev,noexec 0 0"
    } >> "$FSTAB"
    log "/dev/shm: added tmpfs entry with nosuid,nodev,noexec"
    CHANGED=1
else
    ensure_mount_options /dev/shm "nosuid,nodev,noexec"
fi

# --- Btrfs discard policy: periodic fstrim only, never async mount discard ---
# Since Linux 6.2 Btrfs defaults to discard=async on discard-capable devices.
# Explicit nodiscard on every Btrfs fstab entry prevents continuous allocation
# notifications. dm-crypt still permits discard pass-through so the deliberate
# weekly fstrim operation can reach the device; permission is not a generator.
ensure_mount_options / "nodiscard"

# --- /home: btrfs subvol — nosuid,nodev,nodiscard (NO noexec) ---
ensure_mount_options /home "nosuid,nodev,nodiscard"

# --- /var: DISA STIG RHEL 9 V-257869 (nodev); nosuid defense in depth (NO noexec, breaks RPM)
# /var is typically on the root subvol (no separate mount). Self-bind-mount gives
# us mount-level nosuid+nodev for ordinary descendants. Every nested mount is a
# separate policy boundary and must carry its own flags. /var/tmp still gets
# its own bind-mount below as defense-in-depth.
if grep -qE '^[[:space:]]*[^[:space:]#]+[[:space:]]+/var[[:space:]]' "$FSTAB"; then
    ensure_mount_options /var "nosuid,nodev,private"
else
    {
        echo ""
        echo "# NoID Privacy — /var hardening (Module 22; DISA STIG RHEL 9 V-257869 nodev; nosuid defense-in-depth)"
        echo "/var /var none bind,nosuid,nodev,private 0 0"
    } >> "$FSTAB"
    log "/var: added private self-bind-mount with nosuid,nodev"
    CHANGED=1
fi

# --- /var/tmp: persistent temp — nosuid,nodev (NO noexec, breaks DNF/RPM + upgrades)
# If no /var/tmp fstab entry exists (typical single-root layout), add a
# self-bind-mount so persistence is preserved while gaining the mount options.
if grep -qE '^[[:space:]]*[^[:space:]#]+[[:space:]]+/var/tmp[[:space:]]' "$FSTAB"; then
    ensure_mount_options /var/tmp "nosuid,nodev"
else
    {
        echo ""
        echo "# NoID Privacy — /var/tmp hardening (Module 22; no noexec, breaks DNF/RPM)"
        echo "/var/tmp /var/tmp none bind,nosuid,nodev 0 0"
    } >> "$FSTAB"
    log "/var/tmp: added self-bind-mount with nosuid,nodev"
    CHANGED=1
fi

# --- /boot: separate Anaconda partition — nosuid,nodev,noexec ---
ensure_mount_options /boot "nosuid,nodev,noexec"

# --- /boot/efi: VFAT ESP — nosuid,nodev,noexec ---
ensure_mount_options /boot/efi "nosuid,nodev,noexec"

# Validate and durably publish the complete fstab transaction before asking
# PID 1 or mount(8) to consume it. findmnt uses libmount's maintained fstab
# parser and returns non-zero for parse/usability errors.
if ! findmnt --verify --tab-file "$FSTAB" >/dev/null; then
    log "FAIL: candidate fstab did not pass findmnt --verify"
    exit 1
fi
if [ "$(stat -c '%U:%G:%a' "$FSTAB")" != "root:root:644" ]; then
    CHANGED=1
fi
if [ "$CHANGED" -eq 1 ]; then
    chown root:root "$FSTAB"
    chmod 0644 "$FSTAB"
    if command -v restorecon >/dev/null 2>&1 && [ -f /sys/fs/selinux/enforce ]; then
        restorecon -F "$FSTAB"
    fi
    sync "$FSTAB"
    mv -fT -- "$FSTAB" "$FSTAB_FINAL"
    FSTAB_WORK=""
    sync "$FSTAB_DIR"
else
    rm -f -- "$FSTAB_WORK"
    FSTAB_WORK=""
fi
FSTAB="$FSTAB_FINAL"
trap - EXIT HUP INT TERM

# --- Apply policy to currently mounted filesystems ---
# Always reconcile the runtime state, even when fstab was already patched by a
# previous failed/private-namespace run. Otherwise removing a false sentinel
# would keep retrying without ever repairing the kernel mount table.
if [ "$CHANGED" -eq 1 ]; then
    log "fstab changed — reloading systemd and reconciling mounts"
else
    log "fstab already hardened — reconciling effective mounts"
fi
systemctl daemon-reload

    # Root-cause fix: `mount -o remount $mp` does NOT
    # re-read fstab. Per mount(8): "The mount command does not read fstab(5)
    # when a remount operation is performed". So plain `mount -o remount /tmp`
    # remounts with the CURRENT in-kernel options, leaving NEW fstab options
    # (noexec, etc.) inactive until next boot. Live validation found /tmp
    # had nosuid,nodev BUT NO noexec despite fstab having noexec.
    # Fix v1: parse desired options from fstab field 4 and pass explicitly.
    #
    # Follow-up root-cause fix: installed-system first-boot
    # audit revealed the v1 fix was INCOMPLETE — passing the full fstab field-4
    # (e.g. "defaults,nosuid,nodev,noexec,size=4G") to `mount -o remount` results
    # in exit=0 but flags NOT applied for /tmp /dev/shm /boot /boot/efi (only
    # /var /var/tmp work because they're fresh bind-mounts). /home additionally
    # WARN'd because `x-systemd.device-timeout=0` is a systemd-only pseudo-option
    # that mount(8) rejects.
    # Root cause: `defaults` keyword in remount opts neutralizes flag-application
    # via mount(8)'s option parser. Plus `size=4G` and `x-systemd.*` confuse the
    # remount path further.
    # Fix v2: pass ONLY hardcoded security flags (nosuid, nodev, noexec) via
    # remount. mount(8) preserves all other in-kernel options unchanged. Live-
    # verified live: `mount -o remount,nosuid,nodev,
    # noexec /boot` applied flags correctly + preserved relatime,seclabel.
    declare -A SEC_FLAGS=(
        [/]="nodiscard"
        [/tmp]="nosuid,nodev,noexec"
        [/dev/shm]="nosuid,nodev,noexec"
        [/home]="nosuid,nodev,nodiscard"
        [/var]="nosuid,nodev"
        [/var/tmp]="nosuid,nodev"
        [/boot]="nosuid,nodev,noexec"
        [/boot/efi]="nosuid,nodev,noexec"
)
# Mount newly-created fstab entries and remount existing entries in the
# HOST namespace. /var must precede its nested /var/tmp bind. The service
# deliberately has no systemd filesystem-sandbox directives because any
# of them would make these successful operations private to the oneshot.
for mp in / /var /var/tmp /tmp /dev/shm /home /boot /boot/efi; do
    if ! fstab_has_mountpoint "$mp"; then
        log "  $mp: no fstab entry, skipping runtime reconciliation"
        continue
    fi
    if findmnt -n -M "$mp" >/dev/null 2>&1; then
        if ! mount -o "remount,${SEC_FLAGS[$mp]}" "$mp"; then
            log "FAIL: $mp remount with security flags (${SEC_FLAGS[$mp]}) failed"
            exit 1
        fi
    else
        if ! mount "$mp"; then
            log "FAIL: initial mount of $mp failed"
            exit 1
        fi
    fi
done

# A self-bind inherits the propagation class of its source. The root mount is
# shared on Fedora, so leaving /var shared makes every nested mount below /var
# propagate into the peer view at /root/var as well. That produced two stacked
# /var/lib/libvirt mounts after Snapper initialization. fstab's `private`
# option is the persistent contract; make the already-mounted self-bind private
# explicitly because remount changes VFS flags but not propagation class.
if ! mount --make-private /var; then
    log "FAIL: could not make /var mount propagation private"
    exit 1
fi
if [ "$(findmnt -n -M /var -o PROPAGATION 2>/dev/null || true)" != private ]; then
    log "FAIL: /var mount propagation is not private"
    exit 1
fi

# --- Post-patch integrity verification: fail loudly if fstab is wrong ---
check_opt_present() {
    local mnt="$1" opt="$2"
    local pattern="^[[:space:]]*[^[:space:]#]+[[:space:]]+${mnt}[[:space:]]"
    if ! fstab_has_mountpoint "$mnt"; then
        return 0   # no entry for this mount at all — not our failure
    fi
    if grep -E "$pattern" "$FSTAB" | grep -qE "(,|^|[[:space:]])${opt}([,[:space:]]|$)"; then
        return 0
    fi
    log "VERIFY FAIL: ${mnt} missing option ${opt} in fstab"
    return 1
}

verify_ok=1
for pair in "/tmp:nosuid" "/tmp:nodev" "/tmp:noexec" \
            "/dev/shm:nosuid" "/dev/shm:nodev" "/dev/shm:noexec" \
            "/:nodiscard" "/home:nosuid" "/home:nodev" "/home:nodiscard" \
            "/var:nosuid" "/var:nodev" "/var:private" \
            "/var/tmp:nosuid" "/var/tmp:nodev" \
            "/boot:nosuid" "/boot:nodev" "/boot:noexec" \
            "/boot/efi:nosuid" "/boot/efi:nodev" "/boot/efi:noexec"; do
    mnt="${pair%:*}"
    opt="${pair##*:}"
    check_opt_present "$mnt" "$opt" || verify_ok=0
done

if [ "$verify_ok" -eq 0 ]; then
    log "Mount hardening verification FAILED — inspect /etc/fstab manually"
    exit 1
fi

# Verify the effective kernel mount table, not merely fstab. This catches a
# private-namespace regression and any mount(8) success that did not apply the
# requested flag. Every matrix target present as a distinct fstab mount is
# mandatory; absent optional targets inherit their parent mount's policy.
verify_effective_opt() {
    local mp="$1" opt="$2" options
    if ! fstab_has_mountpoint "$mp"; then
        return 0
    fi
    if ! options="$(findmnt -n -M "$mp" -o OPTIONS)"; then
        log "VERIFY FAIL: $mp is not a distinct mounted target"
        return 1
    fi
    # findmnt reports active positive flags. For Btrfs it deliberately omits
    # the negative/default `nodiscard` spelling: the observable postcondition
    # is the absence of `discard` and every `discard=*` mode.
    if [ "$opt" = "nodiscard" ]; then
        if tr ',' '\n' <<< "$options" | grep -Eq '^discard($|=)'; then
            log "VERIFY FAIL: $mp has continuous discard enabled ($options)"
            return 1
        fi
        return 0
    fi
    if ! tr ',' '\n' <<< "$options" | grep -qx "$opt"; then
        log "VERIFY FAIL: $mp missing effective kernel option $opt ($options)"
        return 1
    fi
}

for pair in "/tmp:nosuid" "/tmp:nodev" "/tmp:noexec" \
            "/dev/shm:nosuid" "/dev/shm:nodev" "/dev/shm:noexec" \
            "/:nodiscard" "/home:nosuid" "/home:nodev" "/home:nodiscard" \
            "/var:nosuid" "/var:nodev" \
            "/var/tmp:nosuid" "/var/tmp:nodev" \
            "/boot:nosuid" "/boot:nodev" "/boot:noexec" \
            "/boot/efi:nosuid" "/boot/efi:nodev" "/boot/efi:noexec"; do
    mnt="${pair%:*}"
    opt="${pair##*:}"
    verify_effective_opt "$mnt" "$opt" || verify_ok=0
done

# A direct execution probe proves noexec semantics independently of the option
# string. Interpreting the file with `sh file` would bypass noexec and is not a
# valid test, so invoke the executable path itself.
NOEXEC_PROBE=""
cleanup_noexec_probe() {
    if [ -n "$NOEXEC_PROBE" ]; then
        rm -f -- "$NOEXEC_PROBE" \
            || { log "VERIFY FAIL: could not remove noexec probe $NOEXEC_PROBE"; return 1; }
        NOEXEC_PROBE=""
    fi
}
trap cleanup_noexec_probe EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
for mp in /tmp /dev/shm /boot /boot/efi; do
    if ! fstab_has_mountpoint "$mp"; then
        continue
    fi
    NOEXEC_PROBE="$(mktemp "$mp/.noid-noexec-probe.XXXXXX")"
    printf '#!/bin/sh\nexit 0\n' > "$NOEXEC_PROBE"
    chmod 0700 "$NOEXEC_PROBE"
    set +e
    "$NOEXEC_PROBE" >/dev/null 2>&1
    probe_rc=$?
    set -e
    cleanup_noexec_probe
    if [ "$probe_rc" -eq 0 ]; then
        log "VERIFY FAIL: executable probe ran from noexec target $mp"
        verify_ok=0
    fi
done
trap - EXIT HUP INT TERM

if [ "$verify_ok" -eq 0 ]; then
    log "Effective mount-hardening verification FAILED"
    exit 1
fi

# The sentinel is atomically and durably published only after fstab, effective
# kernel flags and direct noexec probes all pass. A failed, namespace-confined
# or power-interrupted run must retry.
STATE_DIR=/var/lib/noid-privacy
MARKER="$STATE_DIR/.mount-hardening-done"
MARKER_WORK=""
cleanup_marker_work() {
    if [ -n "$MARKER_WORK" ] && [ -e "$MARKER_WORK" ]; then
        rm -f -- "$MARKER_WORK"
    fi
}
install -d -m 0755 -o root -g root "$STATE_DIR"
if [ ! -d "$STATE_DIR" ] || [ -L "$STATE_DIR" ] || \
   [ "$(stat -c '%U:%G:%a' "$STATE_DIR")" != "root:root:755" ]; then
    log "FAIL: invalid shared state-directory metadata"
    exit 1
fi
MARKER_WORK=$(mktemp "$STATE_DIR/.mount-hardening-done.tmp.XXXXXX")
trap cleanup_marker_work EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
chown root:root "$MARKER_WORK"
chmod 0600 "$MARKER_WORK"
if command -v restorecon >/dev/null 2>&1 && [ -f /sys/fs/selinux/enforce ]; then
    restorecon -F "$MARKER_WORK"
fi
sync "$MARKER_WORK"
mv -fT -- "$MARKER_WORK" "$MARKER"
MARKER_WORK=""
sync "$STATE_DIR"
trap - EXIT HUP INT TERM

log "Mount hardening complete — fstab and effective kernel checks passed"
SCRIPT_EOF

chmod 755 /usr/local/bin/noid-mount-hardening.sh
chown root:root /usr/local/bin/noid-mount-hardening.sh
log "  [OK] noid-mount-hardening.sh written"

# ====================================================================
# STEP 2: Systemd firstboot service
# ====================================================================
log "STEP 2: writing noid-mount-hardening.service"

cat > /etc/systemd/system/noid-mount-hardening.service <<'SVC_EOF'
[Unit]
Description=NoID Privacy: harden mount options in /etc/fstab (first boot)
DefaultDependencies=no
After=local-fs.target
Before=basic.target
Wants=local-fs.target
ConditionPathExists=!/var/lib/noid-privacy/.mount-hardening-done
# Live-ISO guard: this firstboot one-shot must not fire in the Live-ISO env
# (rd.live.image) where it would mutate the ephemeral overlay /etc/fstab; only the
# installed system (no rd.live.image) hardens the real fstab at firstboot.
ConditionKernelCommandLine=!rd.live.image

[Service]
Type=oneshot
ExecStart=/usr/local/bin/noid-mount-hardening.sh
RemainAfterExit=yes

# baseline sandbox: universally-safe directives.
NoNewPrivileges=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX
MemoryDenyWriteExecute=yes
IPAddressDeny=any
UMask=0077

# Do not add PrivateTmp/ProtectHome/ProtectSystem/ProtectKernel*/ProtectClock,
# ReadOnlyPaths, ReadWritePaths or PrivateMounts here. Those directives create
# a private mount namespace, preventing this unit's remounts from reaching PID
# 1 and the rest of the installed system.

[Install]
WantedBy=basic.target
SVC_EOF

chmod 644 /etc/systemd/system/noid-mount-hardening.service
chown root:root /etc/systemd/system/noid-mount-hardening.service
systemctl enable noid-mount-hardening.service
log "  [OK] noid-mount-hardening.service written + enabled"

# ====================================================================
# STEP 2a: Live-media mount hardening
# ====================================================================
# Live media has no persistent fstab to rewrite, but the documented exploit-
# staging boundary still applies. Reconcile the two ephemeral tmpfs mounts in
# the host namespace on every live boot and prove noexec by direct execution.
cat > /usr/local/bin/noid-live-mount-hardening.sh <<'LIVE_MOUNT_SCRIPT_EOF'
#!/bin/bash
set -euo pipefail

case " $(</proc/cmdline) " in
    *" rd.live.image "*) ;;
    *) exit 0 ;;
esac
NOEXEC_PROBE=""
cleanup_noexec_probe() {
    if [ -n "$NOEXEC_PROBE" ]; then
        rm -f -- "$NOEXEC_PROBE" \
            || { echo "could not remove live noexec probe: $NOEXEC_PROBE" >&2; return 1; }
        NOEXEC_PROBE=""
    fi
}
trap cleanup_noexec_probe EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
for mp in /tmp /dev/shm; do
    mountpoint -q "$mp" || { echo "live mount target missing: $mp" >&2; exit 1; }
    mount -o remount,nosuid,nodev,noexec "$mp"
    options=$(findmnt -n -M "$mp" -o OPTIONS)
    for opt in nosuid nodev noexec; do
        tr ',' '\n' <<< "$options" | grep -qx "$opt" \
            || { echo "$mp missing $opt after live remount" >&2; exit 1; }
    done
    NOEXEC_PROBE=$(mktemp "$mp/.noid-live-noexec.XXXXXX")
    printf '#!/bin/sh\nexit 0\n' > "$NOEXEC_PROBE"
    chmod 0700 "$NOEXEC_PROBE"
    set +e
    "$NOEXEC_PROBE" >/dev/null 2>&1
    probe_rc=$?
    set -e
    cleanup_noexec_probe
    [ "$probe_rc" -ne 0 ] \
        || { echo "direct execution succeeded from $mp" >&2; exit 1; }
done
trap - EXIT HUP INT TERM
LIVE_MOUNT_SCRIPT_EOF
chmod 0755 /usr/local/bin/noid-live-mount-hardening.sh
chown root:root /usr/local/bin/noid-live-mount-hardening.sh

cat > /etc/systemd/system/noid-live-mount-hardening.service <<'LIVE_MOUNT_SERVICE_EOF'
[Unit]
Description=NoID Privacy: enforce noexec on live-media temporary filesystems
DefaultDependencies=no
After=local-fs.target
Before=basic.target
Wants=local-fs.target
ConditionKernelCommandLine=rd.live.image

[Service]
Type=oneshot
ExecStart=/usr/local/bin/noid-live-mount-hardening.sh
RemainAfterExit=yes
NoNewPrivileges=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX
MemoryDenyWriteExecute=yes
IPAddressDeny=any
UMask=0077

# Like the installed reconciler, this unit intentionally has no directive
# that creates a private mount namespace.
[Install]
WantedBy=basic.target
LIVE_MOUNT_SERVICE_EOF
chmod 0644 /etc/systemd/system/noid-live-mount-hardening.service
chown root:root /etc/systemd/system/noid-live-mount-hardening.service
systemctl enable noid-live-mount-hardening.service
log "  [OK] live-media /tmp + /dev/shm hardening installed + enabled"

# ====================================================================
# STEP 2b: Monthly btrfs scrub timer (data-integrity verification)
# ====================================================================
# Fedora's btrfs-progs ships no scrub timer, so the btrfs root filesystem
# is never checksum-verified unless the admin does it by hand. A monthly
# scrub surfaces bit-rot and failing-disk errors early. Replicated blocks can
# be repaired from a verified copy; unreplicated corruption is detected and
# reported. Since kernel 6.19, suspend and similar events can cancel a scrub.
# The wrapper resumes saved progress while preserving a native 128 MiB/s cap
# even though btrfs-progs 7.0 does not accept --limit on `scrub resume`.
# NoID Privacy-owned units avoid the broader btrfsmaintenance package surface;
# trim remains handled by Fedora's fstrim.timer.
log "STEP 2b: writing resumable btrfs scrub helper + service + timer"

cat > /usr/libexec/noid-btrfs-scrub <<'SCRUB_SCRIPT_EOF'
#!/usr/bin/env bash
# Resume an interrupted Btrfs scrub or start a new one while preserving every
# pre-existing per-device scrub limit. btrfs-progs 7.0 supports --limit only on
# `scrub start`, so resumed work needs a temporary explicit device limit. The
# original limits are committed to a private transaction file before mutation;
# a service restart performs recovery from those values instead of treating a
# leaked temporary 128M value as the new baseline.
set -euo pipefail
export LC_ALL=C
umask 077

BTRFS=/usr/sbin/btrfs
MOUNT=/
RATE_LIMIT=128M
STATE_DIR=/var/lib/noid-btrfs-scrub
STATE_FILE="$STATE_DIR/limit-transaction"
LOCK_FILE="$STATE_DIR/lock"
declare -a DEVICE_IDS=()
declare -a OLD_LIMITS=()
declare -a CURRENT_DEVICE_IDS=()
declare -a CURRENT_LIMITS=()
FILESYSTEM_UUID=""
PENDING_RC=1

fail() {
    echo "noid-btrfs-scrub: $*" >&2
    exit 1
}

if [ ! -d "$STATE_DIR" ] || [ -L "$STATE_DIR" ] || \
   [ "$(stat -c '%U:%G:%a' "$STATE_DIR" 2>/dev/null)" != "root:root:700" ]; then
    fail "private StateDirectory is missing or has unsafe metadata"
fi
exec {LOCK_FD}>"$LOCK_FILE"
chmod 0600 "$LOCK_FILE"
/usr/bin/flock -n "$LOCK_FD" || fail "another scrub transaction owns the state lock"

limit_snapshot=$("$BTRFS" scrub limit --raw "$MOUNT")
FILESYSTEM_UUID=$(awk '$1 == "UUID:" && NF == 2 { print $2 }' \
    <<<"$limit_snapshot")
if ! [[ "$FILESYSTEM_UUID" =~ ^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$ ]]; then
    fail "Btrfs filesystem UUID could not be parsed"
fi
while read -r devid old_limit _path; do
    if [[ "$devid" =~ ^[0-9]+$ ]] && \
       { [ "$old_limit" = "-" ] || [[ "$old_limit" =~ ^[0-9]+$ ]]; }; then
        CURRENT_DEVICE_IDS+=("$devid")
        CURRENT_LIMITS+=("$old_limit")
    fi
done <<<"$limit_snapshot"

if [ "${#CURRENT_DEVICE_IDS[@]}" -eq 0 ]; then
    fail "no Btrfs device limits could be enumerated"
fi

write_state() {
    local pending_rc="$1" tmp="" i
    tmp=$(mktemp --tmpdir="$STATE_DIR" '.limit-transaction.XXXXXXXX') || return 1
    {
        printf 'version=1\n'
        printf 'uuid=%s\n' "$FILESYSTEM_UUID"
        printf 'pending_rc=%s\n' "$pending_rc"
        for i in "${!DEVICE_IDS[@]}"; do
            printf 'device=%s:%s\n' "${DEVICE_IDS[$i]}" "${OLD_LIMITS[$i]}"
        done
    } >"$tmp" || { rm -f -- "$tmp"; return 1; }
    chmod 0600 "$tmp" || { rm -f -- "$tmp"; return 1; }
    sync "$tmp" || { rm -f -- "$tmp"; return 1; }
    mv -fT -- "$tmp" "$STATE_FILE" || { rm -f -- "$tmp"; return 1; }
    sync "$STATE_DIR"
}

clear_state() {
    rm -f -- "$STATE_FILE" && sync "$STATE_DIR"
}

load_state() {
    local key value state_version="" state_uuid="" state_pending=""
    local state_devices=0 seen id limit existing
    [ -f "$STATE_FILE" ] && [ ! -L "$STATE_FILE" ] || return 1
    [ "$(stat -c '%U:%G:%a' "$STATE_FILE" 2>/dev/null)" = "root:root:600" ] \
        || return 1
    DEVICE_IDS=()
    OLD_LIMITS=()
    while IFS='=' read -r key value; do
        case "$key" in
            version)
                [ -z "$state_version" ] && [ "$value" = 1 ] || return 1
                state_version=$value
                ;;
            uuid)
                [ -z "$state_uuid" ] && \
                    [[ "$value" =~ ^[0-9A-Fa-f-]{36}$ ]] || return 1
                state_uuid=$value
                ;;
            pending_rc)
                [ -z "$state_pending" ] && [[ "$value" =~ ^[0-9]+$ ]] && \
                    [ "$value" -le 255 ] || return 1
                state_pending=$value
                ;;
            device)
                [[ "$value" =~ ^([0-9]+):(-|[0-9]+)$ ]] || return 1
                id=${BASH_REMATCH[1]}
                limit=${BASH_REMATCH[2]}
                seen=0
                for existing in "${DEVICE_IDS[@]}"; do
                    [ "$existing" != "$id" ] || seen=1
                done
                [ "$seen" -eq 0 ] || return 1
                DEVICE_IDS+=("$id")
                OLD_LIMITS+=("$limit")
                state_devices=$((state_devices + 1))
                ;;
            *) return 1 ;;
        esac
    done <"$STATE_FILE"
    [ "$state_version" = 1 ] && [ "$state_uuid" = "$FILESYSTEM_UUID" ] && \
        [ -n "$state_pending" ] && [ "$state_devices" -gt 0 ] || return 1
    PENDING_RC=$state_pending
}

validate_saved_devices() {
    local saved current found
    for saved in "${DEVICE_IDS[@]}"; do
        found=0
        for current in "${CURRENT_DEVICE_IDS[@]}"; do
            [ "$saved" != "$current" ] || found=1
        done
        [ "$found" -eq 1 ] || return 1
    done
}

restore_saved_limits() {
    local restore_rc=0 i restore_value
    for i in "${!DEVICE_IDS[@]}"; do
        restore_value="${OLD_LIMITS[$i]}"
        [ "$restore_value" != "-" ] || restore_value=0
        "$BTRFS" scrub limit --devid "${DEVICE_IDS[$i]}" \
            --limit "$restore_value" "$MOUNT" || restore_rc=1
    done
    return "$restore_rc"
}

apply_rate_limit() {
    local devid
    for devid in "${DEVICE_IDS[@]}"; do
        "$BTRFS" scrub limit --devid "$devid" --limit "$RATE_LIMIT" "$MOUNT"
    done
}

recover_saved_state() {
    load_state || fail "saved limit transaction is invalid; refusing to guess"
    validate_saved_devices || \
        fail "saved limit transaction does not match the current device set"
    if ! restore_saved_limits; then
        fail "saved original limits could not be restored; state retained"
    fi
    if ! clear_state; then
        write_state "$PENDING_RC" || true
        fail "original limits restored but transaction state could not be cleared"
    fi
    exit "$PENDING_RC"
}

restore_limits() {
    local rc=$? restore_rc=0
    trap - EXIT HUP INT TERM
    write_state "$rc" || \
        echo "noid-btrfs-scrub: could not record final scrub status" >&2
    restore_saved_limits || restore_rc=1
    if [ "$restore_rc" -ne 0 ]; then
        echo "noid-btrfs-scrub: original limits not fully restored; state retained" >&2
        exit 1
    fi
    if ! clear_state; then
        write_state "$rc" || true
        echo "noid-btrfs-scrub: original limits restored but state cleanup failed" >&2
        exit 1
    fi
    exit "$rc"
}

if [ -e "$STATE_FILE" ] || [ -L "$STATE_FILE" ]; then
    recover_saved_state
fi

DEVICE_IDS=("${CURRENT_DEVICE_IDS[@]}")
OLD_LIMITS=("${CURRENT_LIMITS[@]}")
write_state 1 || fail "original device limits could not be committed"

trap restore_limits EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

apply_rate_limit

resume_rc=0
"$BTRFS" scrub resume -B -d "$MOUNT" || resume_rc=$?
case "$resume_rc" in
    0) exit 0 ;;
    # btrfs-progs 7.0 sets every device to unlimited before discovering that
    # there is no saved work and returning 2. Reapply the cap so the following
    # `scrub start --limit` snapshots 128M, not unlimited, as its old value.
    # It restores that old value immediately after launching its worker.
    2) apply_rate_limit ;;
    *) exit "$resume_rc" ;;
esac

"$BTRFS" scrub start -B -d --limit "$RATE_LIMIT" "$MOUNT"
SCRUB_SCRIPT_EOF
chmod 0755 /usr/libexec/noid-btrfs-scrub
chown root:root /usr/libexec/noid-btrfs-scrub
log "  [OK] /usr/libexec/noid-btrfs-scrub written (0755)"

cat > /etc/systemd/system/btrfs-scrub.service <<'SCRUB_SVC_EOF'
[Unit]
Description=NoID Privacy: monthly btrfs scrub of / (data-integrity verification)
Documentation=man:btrfs-scrub(8)
StartLimitIntervalSec=1h
StartLimitBurst=3

[Service]
Type=oneshot
# Background chore: cap each device at 128 MiB/s, retain best-effort CPU/I/O
# priority, and never time out — a scrub can legitimately take hours. Kernel
# 6.19+ can cancel scrub during suspend; a bounded on-failure restart lets the
# helper resume saved progress. Exit 3 means uncorrectable errors and must stay
# failed for explicit review rather than retrying automatically.
Nice=19
IOSchedulingClass=idle
TimeoutStartSec=infinity
ExecCondition=/usr/bin/findmnt -n -M / -t btrfs
ExecStart=/usr/libexec/noid-btrfs-scrub
Restart=on-failure
RestartSec=5min
RestartPreventExitStatus=3
StateDirectory=noid-btrfs-scrub
StateDirectoryMode=0700

# Live-probed on Fedora 44/systemd 259 with `btrfs scrub status /`. These
# process/network/home restrictions do not hide the root mount or its Btrfs
# control ioctl. Filesystem namespace restrictions beyond ProtectHome are
# deliberately omitted because this unit must retain the host root mount.
NoNewPrivileges=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native
MemoryDenyWriteExecute=yes
IPAddressDeny=any
ProtectHome=yes
UMask=0077
SCRUB_SVC_EOF

cat > /etc/systemd/system/btrfs-scrub.timer <<'SCRUB_TIMER_EOF'
[Unit]
Description=NoID Privacy: monthly btrfs scrub schedule

[Timer]
OnCalendar=monthly
RandomizedDelaySec=6h
Persistent=true

[Install]
WantedBy=timers.target
SCRUB_TIMER_EOF

chmod 644 /etc/systemd/system/btrfs-scrub.service /etc/systemd/system/btrfs-scrub.timer
chown root:root /etc/systemd/system/btrfs-scrub.service /etc/systemd/system/btrfs-scrub.timer
systemctl enable btrfs-scrub.timer
log "  [OK] resumable btrfs-scrub.timer written + enabled (monthly, rate-limited)"

# ====================================================================
# STEP 3: User documentation
# ====================================================================
log "STEP 3: writing /usr/share/doc/noid-privacy/22-disk-encryption.md"

mkdir -p /usr/share/doc/noid-privacy

cat > /usr/share/doc/noid-privacy/22-disk-encryption.md <<'DOC_EOF'
# Disk Encryption & Mount Hardening — NoID Privacy

## Encryption

NoID Privacy relies on Fedora's Anaconda installer for disk encryption.
During installation, choose **"Encrypt my data"** in the storage dialog.
The current release expects the following installed layout when encryption is
selected, but the actual container, cipher and active keyslot KDF are installed
state and must be verified after installation:

- **LUKS2**; the expected active passphrase keyslot uses **Argon2id**
  (memory-hard), but this is not inferable from `lsblk` alone
- **AES-XTS-plain64** with a 512-bit combined key (two AES-256 keys; this
  must not be described as 512-bit security strength)
- **btrfs** filesystem with subvolumes for `/` and `/home`
- Separate `/boot` (ext4) and `/boot/efi` (FAT32) outside encryption

### Verifying Encryption Parameters

Confirm Anaconda enabled the expected LUKS2 parameters:

```bash
# Find your LUKS partition first
lsblk -f | grep crypto_LUKS

# Dump the LUKS header (replace nvme0n1p3 with your partition)
sudo cryptsetup luksDump /dev/nvme0n1p3 | grep -E 'Version:|Cipher|PBKDF:|Memory'
```

The exact values must be read from the installed keyslot. A typical compliant
result contains:
```
Version:        2
Cipher:         aes-xts-plain64
PBKDF:          argon2id
Memory:         <installed value in KiB>
```

If an active passphrase keyslot shows `pbkdf2` instead of `argon2id`, do not
silently relabel it compliant. A conversion changes a disk-unlock boundary:
retain an independently stored header backup and tested recovery path, identify
the exact keyslot, and follow the maintained `cryptsetup-luksConvertKey(8)`
procedure for the installed version. A representative command shape is:

```bash
# Create and verify an offline header backup before any key operation
noid-luks-backup.sh

# Convert the existing keyslot to argon2id
slot=0  # replace with the exact active passphrase slot from luksDump
sudo cryptsetup luksConvertKey /dev/nvme0n1p3 --key-slot "$slot" --pbkdf argon2id \
    --pbkdf-memory 1048576 --pbkdf-parallel 4
```

### Optional — review or raise the Argon2 memory cost

Cryptsetup benchmarks Argon2 parameters against the available machine and its
configured time/memory limits; this image does not enforce a universal
Anaconda value. RFC 9106's first general recommendation uses 2 GiB, while its
memory-constrained recommendation uses 64 MiB. Its application examples also
include other profiles; these are not proof that one value fits every boot
environment.

If the early-boot environment reliably has enough memory, 2 GiB can raise the
cost per guess. Measure unlock behavior and retain a tested header backup and
recovery path:

```bash
# Create and verify an offline header backup first
noid-luks-backup.sh

# Upgrade one exact keyslot to Argon2id with a 2 GiB memory request
slot=0  # replace with the exact active passphrase slot from luksDump
sudo cryptsetup luksConvertKey /dev/nvme0n1p3 \
    --key-slot "$slot" --pbkdf argon2id --pbkdf-memory 2097152
```

Do not blindly select a “maximum”: cryptsetup may reduce a requested memory cap
after benchmarking or because of available memory, and excessive early-boot
requirements can make recovery harder. Passphrase entropy remains critical
regardless of the memory figure.

**Verify after upgrade**:
```bash
sudo cryptsetup luksDump /dev/nvme0n1p3 | grep Memory
# Record the observed value; do not infer it from the requested cap.
```

### TPM2 Auto-Unlock — not enrolled or supported automatically

Modern Linux systems support TPM2-bound LUKS unlock via
`systemd-cryptenroll --tpm2-device=auto`, allowing password-less boot.

NoID Privacy **deliberately does NOT enroll TPM2 by default** for three reasons aligned
with the privacy-image threat model:

1. **Hardware binding** — TPM2-bound LUKS keys are tied to specific motherboard
   firmware state. If the motherboard fails or you migrate the drive to a
   different machine, you cannot decrypt the drive without a backup recovery
   passphrase. For privacy-conscious users, this trades hardware-failure
   recoverability for unlock convenience.
2. **Unattended-unlock boundary** — a bare TPM unlock can release a volume key
   without user presence unless it is combined with an appropriate PIN and
   measured/signed PCR policy. Passphrase-only unlock avoids unattended key
   release, but does **not** eliminate evil-maid attacks: a compromised boot
   chain or physical input-capture device can target the entered passphrase.
3. **Supply-chain trust** — TPM2 unlock requires trusting the TPM firmware,
   the platform vendor's BIOS implementation, and the Secure Boot chain
   (cross-ref Module 01 SecureBoot + Module 15 BootGuard). Privacy-image
   philosophy: minimize required trust assertions.

If you choose TPM2 unlock, follow the current Fedora/systemd documentation for
the exact platform and design a PCR policy, user-presence/PIN requirement,
recovery key and update/recovery test. NoID Privacy intentionally provides no generic
copy-paste enrollment command because a weak or unmeasured enrollment would
create a false security boundary.

### LUKS Header Backup (CRITICAL)

LUKS2 keeps redundant metadata, but damage to both metadata areas or required
keyslots can make the volume inaccessible. Create and test an offline header
backup immediately after installation.

#### Easy path — use the opt-in helper

NoID Privacy ships `noid-luks-backup.sh` which auto-detects your LUKS partition(s),
auto-detects mounted removable media, and wraps `cryptsetup luksHeaderBackup`
with a private staging directory, structural `luksDump` check, SHA-256
post-backup hash, durable file/directory sync, and explicit reminders to copy
to a second stick in a different physical location. An interrupted transaction
cleans its private staging directory; a fully published and verified file is
never deleted merely because the later evidence-log step failed.

The automatic path intentionally fails closed unless the target filesystem can
enforce a private `root:root` mode-0700 staging directory. Use a filesystem with
per-file POSIX ownership and modes, such as ext4, XFS or Btrfs, directly or
inside a LUKS container. Typical FAT32/exFAT desktop mounts cannot satisfy this
contract and are rejected. Reformatting a device erases its contents; copy any
existing data elsewhere first.

```bash
noid-luks-backup.sh                   # interactive backup
noid-luks-backup.sh --list-existing   # find backups on mounted media
noid-luks-backup.sh --verify FILE     # sanity-check a backup file
```

This is also available as "Back up LUKS header" in the first-boot
welcome menu (`noid-welcome.sh --again`).

The helper proves that cryptsetup produced a structurally parseable file with
the expected ownership, mode and hash, and that the mounted filesystem accepted
the synchronization requests. It does not perform a destructive header restore
or prove that removable-media hardware will never fail. Keep two copies, use
the desktop's safe-remove action, and periodically repeat `--verify`.

#### Manual walkthrough

If you prefer explicit control, use a POSIX-permissions-capable encrypted
external filesystem. If you enroll a recovery key, do that **before** the
header backup so the backup actually contains that keyslot:

```bash
# 1. Find your LUKS partition
lsblk -f | grep crypto_LUKS
# Example output: nvme0n1p3  crypto_LUKS  2  <uuid>

# 2. Optional: enroll and record a recovery key (this changes the header)
sudo systemd-cryptenroll /dev/nvme0n1p3 --recovery-key

# 3. Back up the resulting header to an EXTERNAL encrypted/POSIX USB filesystem
backup="/run/media/$USER/USB_LABEL/luks-header-$(date -u +%Y%m%dT%H%M%SZ).bin"
sudo cryptsetup luksHeaderBackup /dev/nvme0n1p3 --header-backup-file "$backup"
sudo chown "$(id -u):$(id -g)" "$backup"
chmod 0600 "$backup"
cryptsetup luksDump "$backup" >/dev/null
sha256sum "$backup"
sync "$backup"
sync "$(dirname -- "$backup")"

# 4. Copy the .bin file to a SECOND USB stick, stored in a DIFFERENT
#    physical location (friend's house, bank safe, parents' place).
#    Two copies, two places.
```

**Store the backup offline** — USB stick in a safe, separate location.
The header backup + recovery key together can decrypt the drive even if
you forget your passphrase. Never save the header on the same encrypted
disk it protects — that defeats the purpose.

A header backup plus any passphrase valid when that backup was created remains
able to decrypt the data even if that passphrase is later changed or removed
from the live header. Protect or securely retire old backups accordingly.

### Changing LUKS Passphrase

```bash
# Add a new passphrase (keeps old one active)
sudo cryptsetup luksAddKey /dev/nvme0n1p3

# Remove old passphrase (after verifying new one works)
sudo cryptsetup luksRemoveKey /dev/nvme0n1p3
```

Back up the header again after every keyslot, token, recovery-key or PBKDF
change. Do not remove the last independently tested unlock method.

### Additional drives (secondary SSD/HDD)

If you have additional drives beyond the OS installation drive (secondary
SSD, HDD for data, external NVMe), **encrypt them too**. Unencrypted
secondary drives are a common blind spot: anyone with physical access or
a recovery boot can read them unprotected.

```bash
# Replace nvme1n1 with your actual device (CHECK lsblk FIRST — this ERASES all data!)
sudo cryptsetup luksFormat --type luks2 \
    --cipher aes-xts-plain64 \
    --key-size 512 \
    --pbkdf argon2id \
    /dev/nvme1n1

# Open and create a single Btrfs filesystem
sudo cryptsetup open /dev/nvme1n1 luks-data
sudo mkfs.btrfs -L data /dev/mapper/luks-data
sudo install -d -m 0755 /mnt/data

# Auto-unlock on boot (requires separate passphrase OR keyfile on OS drive):
# sudo install -d -m 0700 -o root -g root /etc/luks-keys
# sudo dd if=/dev/urandom of=/etc/luks-keys/data.key bs=64 count=1 status=none conv=fsync
# sudo chmod 400 /etc/luks-keys/data.key
# sudo cryptsetup luksAddKey /dev/nvme1n1 /etc/luks-keys/data.key
# echo "luks-data  UUID=$(sudo blkid -s UUID -o value /dev/nvme1n1)  /etc/luks-keys/data.key  discard,nofail" | sudo tee -a /etc/crypttab
# echo "/dev/mapper/luks-data  /mnt/data  btrfs  nosuid,nodev,noexec,nodiscard,nofail,x-systemd.device-timeout=10s  0 0" | sudo tee -a /etc/fstab
```

Review `/etc/crypttab` and `/etc/fstab` first and add exactly one entry to each;
blindly appending a duplicate makes boot behavior ambiguous. A keyfile on the
OS drive couples the secondary drive's confidentiality to successful unlock of
the OS drive. External drives that travel should use a long independent
passphrase instead. Back up the header after adding the key.
For a drive that may be absent, `nofail` must be present in both entries; the
fstab device timeout also bounds the wait for a missing mapper.

## Mount Hardening

NoID Privacy applies these mount options at first boot:

| Mount | Options | Why / Deliberate omissions |
|-------|---------|-----|
| `/tmp` | nosuid,nodev,**noexec**,size=4G | Classic exploit payload target |
| `/dev/shm` | nosuid,nodev,**noexec** | Exploit fallback when `/tmp` is blocked; modern Electron/V8 handles noexec via `mprotect` fallback |
| `/var` | nosuid,nodev | DISA STIG RHEL 9 V-257869 requires `nodev`; `nosuid` is NoID Privacy defense in depth. Self-bind-mount. **noexec deliberately omitted** — breaks RPM scriptlets, dracut, systemd units, Ansible. Ordinary descendants inherit the flags; every nested mount remains its own policy boundary. |
| `/var/tmp` | nosuid,nodev | Persistent sibling of `/tmp`. **noexec deliberately omitted** for the package/build/install compatibility baseline. The historical dracut failure RHBZ#2274246 was fixed in dracut 102 and is not a current justification. Self-bind-mount when no existing entry; redundant given `/var` above but kept as defense-in-depth. |
| `/` | nodiscard | Disables Btrfs continuous async discard; weekly `fstrim.timer` batches disclosure. |
| `/home` | nosuid,nodev,nodiscard | **noexec deliberately omitted** — breaks Flatpak user installs, AppImages, `~/.local/bin`, Steam |
| `/boot` | nosuid,nodev,**noexec** | Kernel + initramfs — no legitimate SUID/device/exec needs |
| `/boot/efi` | nosuid,nodev,**noexec** | VFAT ESP defense-in-depth (VFAT ignores Unix perms, but kernel still enforces mount flags) |

The matrix applies to targets present as distinct `/etc/fstab` entries. M22
creates entries for `/tmp`, `/dev/shm`, `/var` and `/var/tmp`; a layout without
a separate `/home` or `/boot` inherits its parent filesystem's mount flags and
cannot receive independent `nosuid`, `nodev` or `noexec` flags there.
`/boot/efi` is not applicable on a system without an ESP entry.

These options are the project's compatibility baseline, but no mount policy can
promise compatibility with every application. If an application requires
executing from `/tmp` (rare), you can remount temporarily:

```bash
sudo mount -o remount,exec /tmp
# ... run your application ...
sudo mount -o remount,noexec /tmp
```

### Verifying Mount Hardening

Confirm the firstboot service applied the hardening:

```bash
for mp in / /tmp /dev/shm /var /var/tmp /home /boot /boot/efi; do
    printf '%-12s %s\n' "$mp" "$(findmnt -n "$mp" -o OPTIONS 2>/dev/null \
        | grep -oE 'nosuid|nodev|noexec' | tr '\n' ' ')"
done
```

Expected for each target present as a distinct fstab mount:
- `/tmp`, `/dev/shm`, `/boot`, `/boot/efi` → `nosuid nodev noexec`
- `/` → continuous discard disabled by policy (the kernel often omits the
  negative/default `nodiscard` token from `findmnt` output)
- `/var`, `/var/tmp` → `nosuid nodev` (noexec deliberately omitted)
- `/home` → `nosuid nodev`, plus the same continuous-discard policy as `/`

If any option is missing and the system has been booted at least once,
inspect the firstboot log:

```bash
sudo journalctl -u noid-mount-hardening.service --no-pager
```

To re-run the hardening manually (idempotent):

```bash
sudo rm -f /var/lib/noid-privacy/.mount-hardening-done
sudo systemctl restart noid-mount-hardening.service
```

## Btrfs Scrub

`btrfs-scrub.timer` starts a checksum-validation pass monthly with a native
128 MiB/s per-device limit. `Nice=19` and idle I/O priority remain additional
best-effort hints; the Btrfs limit is the dependable cap on schedulers that do
not implement idle priority.

The service has a native `findmnt` execution condition and starts the helper
only when `/` is Btrfs. On ext4 or XFS roots, a scheduled activation is skipped
without entering a failed or restart state; Btrfs scrub is not applicable.

Kernel 6.19 and newer can cancel a scrub during suspend, hibernate, filesystem
freeze or signal delivery. The service makes bounded retries and resumes saved
progress. Because Fedora 44's `btrfs scrub resume` has no `--limit` option, the
wrapper snapshots every existing per-device limit, applies 128 MiB/s during the
resume and restores the exact prior values on success, failure or signal. Exit
status 3 (uncorrectable errors) is left failed for explicit review instead of
being retried automatically. Before changing a limit, the wrapper atomically
records every original value in systemd's root-private
`/var/lib/noid-btrfs-scrub` state directory. If restoration fails, the bounded
service restart performs recovery only from that saved transaction; it neither
treats a leaked 128 MiB/s value as the original nor starts a duplicate scrub.
The transaction is removed only after every original value is restored.

A scrub detects checksum, metadata-header, superblock and read errors. It can
repair damage only when Btrfs has another verified copy. On the reference
single-device layout, metadata uses DUP and can normally be repaired from its
second copy; data uses `single`, so damaged data is detected but has no
filesystem replica to copy from. NOCOW/NODATASUM file data is outside the data
checksum guarantee. Scrub is not `fsck` and not a backup.

```bash
systemctl status btrfs-scrub.timer
sudo btrfs scrub status /
sudo journalctl -u btrfs-scrub.service --no-pager
```

## SSD TRIM / Discard

NoID Privacy explicitly mounts the Btrfs root and home subvolumes with `nodiscard` and
uses Fedora's `fstrim.timer` for a weekly batch. This avoids Btrfs' Linux 6.2+
default `discard=async`, which would otherwise emit discard requests as freed
extents accumulate.

- **Periodic TRIM** (NoID Privacy default): Batched weekly, reducing the timing detail
  exposed compared with continuous discard
- **Continuous discard**: Real-time block-free notification to SSD,
  exposing finer-grained filesystem allocation patterns through the LUKS layer

The dm-crypt mapping intentionally permits discard pass-through: without that
gate the weekly `fstrim` request could not reach the SSD. The permission itself
does not issue discard requests; `nodiscard` prevents Btrfs from generating
continuous requests, while the timer is the sole normal generator.

To verify all three layers:

```bash
findmnt -n -o OPTIONS /
findmnt -n -o OPTIONS /home
root_crypt_source=$(findmnt -n -o SOURCE / | sed -E 's|\[.*\]$||')
sudo cryptsetup status "${root_crypt_source#/dev/mapper/}"
systemctl status fstrim.timer
```

The two `findmnt` results must contain neither `discard` nor any
`discard=*` mode. Linux normally omits the negative/default `nodiscard` token
from the effective mount-option display; its absence is not a failure. The
crypt mapping is expected to show discard permission, and the timer is expected
to be enabled for the weekly batch.

For maximum paranoia (at cost of SSD performance over time):

```bash
sudo systemctl disable --now fstrim.timer
```

## Recommended Partition Layout

The table records the Fedora 44 Workstation automatic layout observed on the
reference installation. Firmware, storage topology and future installer
policy can change it; review Anaconda's proposed layout before installation
and verify the installed result with `lsblk`.

| Partition | Size | Type | Purpose |
|-----------|------|------|---------|
| /boot/efi | 600 MB | FAT32 | UEFI Secure Boot chain |
| /boot | 2 GiB | ext4 | Kernels, initramfs, BLS entries |
| / (LUKS) | Rest | btrfs | Encrypted root + home (subvolumes) |

**No disk-backed swap by default** — Fedora uses zram (compressed RAM swap).
It keeps this swap state in volatile memory, but it cannot retain a hibernation
image across power-off. Hibernate, hybrid sleep and suspend-then-hibernate are
therefore unavailable in the default layout. Enabling them requires a
deliberately provisioned encrypted disk-backed swap/resume target, verified
initramfs configuration and real power-cycle testing; zram alone is not enough.

**btrfs is required** for the snapshot-rollback feature (Module 20).
If you choose ext4 or XFS, snapshot-based rollback will not be available.

## Backup Strategy

**Important: Snapper snapshots are NOT a backup.** Snapper (Module 20)
can protect captured root-subvolume state against some misconfiguration and bad
updates, but does not include the separate `/home` subvolume. Snapshots live on the SAME encrypted volume
as the original data. They do not protect against:

- Physical drive failure
- LUKS header corruption
- Ransomware that encrypts all accessible data (including snapshots)
- Device theft or loss

For real data safety you need **off-device backups**.

### Recommended backup scope

| Target | Location | Frequency | Tool |
|--------|----------|-----------|------|
| `/home/<user>/` (personal files) | External encrypted USB/NVMe | Weekly (manual) | `rsync` / `borg` / `restic` |
| `/etc/` (system config) | External encrypted drive | After any major config change | `rsync -aAX --numeric-ids` |
| **LUKS header** of OS + data drives | **USB stick (physical safe)** | After every keyslot/token/PBKDF change | `noid-luks-backup.sh` |
| **Recovery key / passphrase** | **Paper in safe + USB stick (off-site)** | Once, on setup | Write down or `systemd-cryptenroll --recovery-key` output |

### Minimum viable (2 commands)

If you only do one thing, do these two commands after finishing setup:

```bash
# 1. Create a durably synchronized header backup on external media (CRITICAL)
noid-luks-backup.sh

# 2. Back up your home directory (run weekly)
rsync -aAX --numeric-ids \
    "/home/$USER/" /mnt/encrypted-usb/home-backup/
```

### Better: encrypted deduplicating backups (borg)

For real backup hygiene, install Fedora's signed `borgbackup` package. Run the
example manually, or explicitly opt into a schedule after deciding when the
external drive will be attached. These commands intentionally use the Borg 1.4
CLI shipped by Fedora 44; Borg 2 uses a different command syntax.

```bash
sudo dnf install borgbackup

# One-time init on external drive
borg init --encryption=repokey-blake2 /mnt/external/borg-repo

# Export the repository key to separate protected media and retain its passphrase
borg key export /mnt/external/borg-repo /mnt/second-protected-media/borg-repo.key

# Weekly snapshot
borg create --stats --compression zstd,3 \
    /mnt/external/borg-repo::$(date +%Y-%m-%d) \
    "/home/$USER"
```

The normal user cannot read every root-owned file below `/etc`; back up system
configuration separately with the root-owned `rsync -aAX --numeric-ids`
workflow from the table instead of silently accepting a partial Borg archive.

### Backup verification

An untested backup is not a dependable recovery plan. Quarterly, restore a
sample and periodically test a full recovery in an isolated destination. One
successful file restore is evidence for that file, not proof of every archive.

```bash
# Verify repository metadata and all stored data (can take a long time)
borg check --verify-data /mnt/external/borg-repo

# Pick a backup archive
borg list /mnt/external/borg-repo

# Borg extracts relative to the current directory; use a fresh private target.
archive=2026-04-15  # replace with an exact archive name from `borg list`
restore_dir=$(mktemp -d /var/tmp/noid-borg-test-restore.XXXXXX)
(cd "$restore_dir" && \
    borg extract "/mnt/external/borg-repo::${archive}" \
        "home/$USER/Documents/important.pdf")
# After inspecting/copying the restored sample:
rm -rf -- "$restore_dir"
```

`/var/tmp` is inside the root state covered by NoID Privacy's Snapper layout. For a
sensitive or full restore, use a dedicated encrypted external destination so a
temporary plaintext copy is not retained by a root snapshot.

### Off-site copy

A backup on an external drive sitting next to your computer protects against
drive failure and ransomware, but NOT against theft, fire, or flood. For
full protection, keep a second copy at a different physical location (family
member's place, bank safe deposit box, or a client-side-encrypted remote
target). A remote provider can still observe account, timing, size and network
metadata even when file contents are encrypted.

## Primary references

- [current cryptsetup manual pages and source](https://gitlab.com/cryptsetup/cryptsetup/-/tree/main/man)
- [cryptsetup FAQ — header backup and recovery](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/FAQ.md)
- [RFC 9106 — Argon2](https://www.rfc-editor.org/rfc/rfc9106.html)
- [systemd-cryptenroll](https://www.freedesktop.org/software/systemd/man/latest/systemd-cryptenroll.html)
- [Fedora Btrfs installer layout](https://fedoraproject.org/wiki/Btrfs)
- [Btrfs mount options and discard](https://btrfs.readthedocs.io/en/latest/ch-mount-options.html)
- [Btrfs scrub semantics](https://btrfs.readthedocs.io/en/latest/btrfs-scrub.html)
- [GNU `sync` durability contract](https://www.gnu.org/software/coreutils/manual/html_node/sync-invocation.html)
- [DISA STIG document library](https://public.cyber.mil/stigs/downloads/)
- [BorgBackup documentation](https://borgbackup.readthedocs.io/en/stable/)
DOC_EOF

chmod 644 /usr/share/doc/noid-privacy/22-disk-encryption.md
log "  [OK] documentation written"

# ====================================================================
# STEP 3b: LUKS header backup wrapper
# ====================================================================
# User-invoked opt-in helper for the critical first-day task ("Back up your
# LUKS header", 01-getting-started.md). Wraps cryptsetup luksHeaderBackup
# with LUKS + removable-media auto-detection, SHA256, --verify and
# --list-existing modes (full design in the heredoc header). Invoked from
# noid-welcome.sh; refuses root, sudo internally.
log "STEP 3b: writing /usr/local/bin/noid-luks-backup.sh"

cat > /usr/local/bin/noid-luks-backup.sh <<'LUKS_BACKUP_EOF'
#!/bin/bash
# =============================================================================
# noid-luks-backup.sh — opt-in LUKS header backup wrapper
# =============================================================================
# Backs up your LUKS header (both LUKS1 and LUKS2 supported — cryptsetup
# handles both transparently) to external removable media. This is the #1
# critical first-day task per docs/01-getting-started.md because loss of both
# metadata copies or required keyslots can make the volume inaccessible.
#
# Usage:
#   noid-luks-backup.sh                   interactive backup
#   noid-luks-backup.sh --list-existing   find prior backups on mounted media
#   noid-luks-backup.sh --verify FILE     sanity-check an existing backup file
#   noid-luks-backup.sh --expert-target DIR
#                                         use an unverified block mount
#   noid-luks-backup.sh --help            this help
#
# Refuses root; invokes sudo internally for cryptsetup, root-private staging,
# atomic publication and root-owned evidence.
# =============================================================================
set -euo pipefail

FMT_LIB=/usr/local/lib/noid-privacy/agent-install-format.sh
# shellcheck source=/dev/null
if [ -r "$FMT_LIB" ]; then . "$FMT_LIB"; else
    fmt_banner(){ echo "== $1 =="; [ -n "${2:-}" ] && echo "   $2"; }
    fmt_step(){ echo "[$1/$2] $3"; }; fmt_ok(){ echo "  OK: $1"; }
    fmt_info(){ echo "  - $1"; }
    # shellcheck disable=SC2329 # complete fallback presentation API
    fmt_warn(){ echo "  ! $1" >&2; }
    fmt_err(){ echo "  ERROR: $1" >&2; }
    # shellcheck disable=SC2329 # complete fallback presentation API
    fmt_note(){ echo "$1"; }
    fmt_done(){ echo "$1"; }
fi
RED=${_F_RED:-}
GREEN=${_F_GREEN:-}
YELLOW=${_F_YEL:-}
BOLD=${_F_B:-}
NC=${_F_RST:-}

# --- return-to-menu prompt (unified pattern) ----------------------
# Installed-system audit fix: when this script
# is launched FROM the welcome dialog (the typical flow), the welcome window
# stays open in the background while the spawned terminal runs. Original
# logic always offered "Return to welcome menu? [Y/n]" + on Y spawned a NEW
# noid-welcome.sh --again instance. With NON_UNIQUE app-id, that creates a
# DUPLICATE welcome window — confusing UX. Plus the "re-open" offer is
# nonsensical when the original welcome is still visible.
# Fix: detect if noid-welcome.sh is already running. If yes → just wait for
# Enter (terminal closes, user sees existing welcome). If no → offer re-open.
return_to_menu_prompt() {
    # Welcome-spawned terminals set NOID_WELCOME_SPAWN=1 and hold via the
    # wrapper's single close prompt; a second hold here would make the user
    # press ENTER twice. The prompt below stays for standalone CLI runs.
    if [ -n "${NOID_WELCOME_SPAWN:-}" ]; then
        return 0
    fi
    echo
    echo "──────────────────────────────────────────────────────"
    if pgrep -f "noid-welcome\.sh" >/dev/null 2>&1; then
        # Welcome dialog still open in background — just close terminal
        read -rp "Press Enter to close terminal (welcome menu still open) ... " _ans || return
        return
    fi
    # Welcome was closed — offer re-open
    read -rp "Re-open welcome menu? [Y/n] " ans || ans="n"
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

# --- mode parsing -----------------------------------------------------------
MODE="interactive"
EXPERT_TARGET=""
case "$#:${1:-}" in
    0:) ;;
    1:--list-existing) MODE="list" ;;
    2:--verify) MODE="verify"; VERIFY_FILE="$2" ;;
    2:--expert-target) EXPERT_TARGET="$2" ;;
    1:--help|1:-h)
        cat <<HELP
noid-luks-backup.sh — LUKS header backup wrapper (LUKS1 + LUKS2)

Usage:
  noid-luks-backup.sh                   interactive backup
  noid-luks-backup.sh --list-existing   find backups on mounted removable media
  noid-luks-backup.sh --verify FILE     sanity-check an existing backup
  noid-luks-backup.sh --expert-target DIR
                                        use a block mount whose external-media
                                        topology cannot be verified
  noid-luks-backup.sh --help            this help

This script is a wrapper around: cryptsetup luksHeaderBackup
Automatic backups require per-file POSIX ownership and modes (for example
ext4, XFS or Btrfs, directly or inside a LUKS container). Typical FAT32/exFAT
desktop mounts cannot enforce the private root:root mode-0700 staging contract
and are rejected. Reformatting erases the target; copy existing data first.
Docs: /usr/share/doc/noid-privacy/22-disk-encryption.md
HELP
        exit 0
        ;;
    *)
        echo "invalid arguments (try --help)" >&2
        exit 2
        ;;
esac

if [ "$(id -u)" -eq 0 ]; then
    fmt_err "do not run as root or via sudo; this helper invokes sudo internally."
    echo "Run as your normal user: /usr/local/bin/noid-luks-backup.sh" >&2
    exit 1
fi

# --- detect all LUKS partitions (LUKS1 + LUKS2) ---------------------------
# Expand to any crypto_LUKS container regardless of underlying type.
# Previously restricted to $3 == "part" (Fedora default LUKS-on-partition).
# Now also catches:
#   - LUKS-on-LVM     (TYPE=lvm)    e.g. vg00-data
#   - LUKS-on-RAID    (TYPE=raid*)  mdadm + cryptsetup
#   - LUKS-on-mpath   (TYPE=mpath)  multipath SAN setups
# Once LUKS is OPENED, mapped device has FSTYPE of inner FS (ext4/btrfs), not
# crypto_LUKS — so no false positives on already-mapped devices.
detect_luks_partitions() {
    lsblk -rpno NAME,FSTYPE,TYPE,SIZE 2>/dev/null | \
        awk '$2 == "crypto_LUKS" { print $1, $4 }'
}

# --- verify mounted removable media topology (USB sticks, SD cards) --------
# BEGIN LUKS_REMOVABLE_TOPOLOGY_FUNCTIONS
MOUNT_CANONICAL=""
MOUNT_SOURCE=""
MOUNT_DISKS=""
MOUNT_TRANSPORTS=""

inspect_block_mount() {
    local candidate="$1" mount_target topology
    MOUNT_CANONICAL=""
    MOUNT_SOURCE=""
    MOUNT_DISKS=""
    MOUNT_TRANSPORTS=""

    MOUNT_CANONICAL=$(readlink -e -- "$candidate" 2>/dev/null) || return 1
    [ -d "$MOUNT_CANONICAL" ] || return 1
    case "$MOUNT_CANONICAL" in
        *$'\n'*|*$'\t'*) return 1 ;;
    esac
    mount_target=$(findmnt -rn -T "$MOUNT_CANONICAL" -o TARGET 2>/dev/null) || \
        return 1
    mount_target=$(readlink -e -- "$mount_target" 2>/dev/null) || return 1
    [ "$mount_target" = "$MOUNT_CANONICAL" ] || return 1
    MOUNT_SOURCE=$(findmnt -rn -T "$MOUNT_CANONICAL" -o SOURCE 2>/dev/null) || \
        return 1
    # findmnt can suffix a Btrfs subvolume as /dev/…[/subvolume]. lsblk needs
    # the underlying block-device path only.
    MOUNT_SOURCE="${MOUNT_SOURCE%%\[*}"
    topology=$(lsblk -srpno NAME,TYPE,RM,TRAN "$MOUNT_SOURCE" 2>/dev/null) || \
        return 1
    [ -n "$topology" ] || return 1
    MOUNT_DISKS=$(awk '$2 == "disk" { print $1 }' <<<"$topology" | \
        paste -sd, -)
    [ -n "$MOUNT_DISKS" ] || return 1
    MOUNT_TRANSPORTS=$(awk '$2 == "disk" {
        printf "%s%s(rm=%s,tran=%s)", sep, $1, $3, ($4 == "" ? "none" : $4)
        sep=","
    }' <<<"$topology")
}

is_verified_removable_mount() {
    local candidate="$1" source_luks="${2:-}" target_topology source_topology
    local target_disk source_disks
    inspect_block_mount "$candidate" || return 1
    target_topology=$(lsblk -srpno NAME,TYPE,RM,TRAN "$MOUNT_SOURCE" 2>/dev/null) || \
        return 1
    # Every physical disk backing the target must be removable/external. A
    # composite filesystem spanning one USB device and one internal disk is not
    # an offline backup target merely because one member is removable.
    if ! awk '$2 == "disk" {
                  found=1
                  if ($3 != "1" && $4 != "usb" && $4 != "mmc" &&
                      $4 != "ieee1394") {
                      unsafe=1
                  }
              }
              END { exit(found && !unsafe ? 0 : 1) }' <<<"$target_topology"; then
        return 1
    fi
    if [ -n "$source_luks" ]; then
        source_topology=$(lsblk -srpno NAME,TYPE "$source_luks" 2>/dev/null) || \
            return 1
        source_disks=$(awk '$2 == "disk" { print $1 }' <<<"$source_topology")
        [ -n "$source_disks" ] || return 1
        while IFS= read -r target_disk; do
            if grep -Fxq -- "$target_disk" <<<"$source_disks"; then
                return 1
            fi
        done < <(tr ',' '\n' <<<"$MOUNT_DISKS")
    fi
}

print_mount_topology() {
    echo "  Mountpoint:  $MOUNT_CANONICAL"
    echo "  Block source: $MOUNT_SOURCE"
    echo "  Physical disk topology: $MOUNT_TRANSPORTS"
}

# Use id -un as $USER fallback (su/sudo/cron contexts may unset USER).
detect_removable_mounts() {
    local source_luks="${1:-}" whoami_user="${USER:-$(id -un)}" candidate
    # /run/media/$user/* is GNOME's auto-mount point for removable
    if [ -d "/run/media/$whoami_user" ]; then
        while IFS= read -r -d '' candidate; do
            if is_verified_removable_mount "$candidate" "$source_luks"; then
                printf '%s\n' "$MOUNT_CANONICAL"
            fi
        done < <(find "/run/media/$whoami_user" -maxdepth 1 -mindepth 1 \
            -type d -print0 2>/dev/null)
    fi
    # /media/$user/* is fallback for some distros (we're Fedora so shouldn't matter)
    if [ -d "/media/$whoami_user" ]; then
        while IFS= read -r -d '' candidate; do
            if is_verified_removable_mount "$candidate" "$source_luks"; then
                printf '%s\n' "$MOUNT_CANONICAL"
            fi
        done < <(find "/media/$whoami_user" -maxdepth 1 -mindepth 1 \
            -type d -print0 2>/dev/null)
    fi
}
# END LUKS_REMOVABLE_TOPOLOGY_FUNCTIONS

# BEGIN LUKS_BACKUP_TRANSACTION_FUNCTIONS
SUCCESS_LOG=/var/lib/noid-privacy/luks-backup.log
SUCCESS_LOG_LOCK=/run/lock/noid-luks-backup.lock
VERIFIED_SHA=""
VERIFIED_SIZE=""
FAILED_BACKUP_PATH=""
BACKUP_STAGE_DIR=""
BACKUP_WORK_PATH=""
BACKUP_STAGE_HANDLE=""
BACKUP_PARENT_HANDLE=""
BACKUP_PUBLISH_PATH=""
BACKUP_STAGE_FD=""
BACKUP_PARENT_FD=""
BACKUP_TRANSACTION_ACTIVE=0
BACKUP_DISPLAY_PATH=""
BACKUP_STAGED_IDENTITY=""
BACKUP_ARTIFACT_VERIFIED=0

close_stage_handle() {
    local rc=0
    if [ -n "$BACKUP_STAGE_FD" ]; then
        exec {BACKUP_STAGE_FD}<&- || rc=1
        BACKUP_STAGE_FD=""
    fi
    BACKUP_STAGE_HANDLE=""
    return "$rc"
}

close_parent_handle() {
    local rc=0
    if [ -n "$BACKUP_PARENT_FD" ]; then
        exec {BACKUP_PARENT_FD}<&- || rc=1
        BACKUP_PARENT_FD=""
    fi
    BACKUP_PARENT_HANDLE=""
    BACKUP_PUBLISH_PATH=""
    return "$rc"
}

close_backup_handles() {
    local rc=0
    close_stage_handle || rc=1
    close_parent_handle || rc=1
    return "$rc"
}

quarantine_backup() {
    local path="$1" reason="$2" quarantine_base="${3:-$1}"
    local display_base="${4:-$quarantine_base}" suffix quarantine_path
    FAILED_BACKUP_PATH=""
    echo "  ${RED}[FAIL]${NC} $reason" >&2
    if ! sudo test -e "$path" && ! sudo test -L "$path"; then
        return 0
    fi
    # Never move an artifact out of the root-only staging directory unless
    # the target filesystem has first enforced a private mode on the file.
    if ! sudo chmod 0600 "$path"; then
        echo "  Unverified artifact remains inside private staging: $path" >&2
        return 1
    fi
    suffix=$(date -u +%Y%m%dT%H%M%SZ)
    quarantine_path="${quarantine_base}.FAILED-${suffix}-$$"
    FAILED_BACKUP_PATH="${display_base}.FAILED-${suffix}-$$"
    if sudo mv -nT -- "$path" "$quarantine_path" && \
       ! sudo test -e "$path" && ! sudo test -L "$path"; then
        echo "  Unverified artifact quarantined: $FAILED_BACKUP_PATH" >&2
    else
        echo "  Could not quarantine unverified artifact without overwrite: $path" >&2
        return 1
    fi
}

cleanup_backup_stage() {
    local rc=0
    if [ -z "$BACKUP_STAGE_DIR" ]; then
        close_stage_handle
        return
    fi
    if ! sudo rmdir -- "$BACKUP_STAGE_DIR"; then
        echo "  ${RED}[FAIL]${NC} could not remove private staging directory:" >&2
        echo "  $BACKUP_STAGE_DIR" >&2
        rc=1
    else
        BACKUP_STAGE_DIR=""
        BACKUP_WORK_PATH=""
    fi
    close_stage_handle || rc=1
    return "$rc"
}

quarantine_published_artifact() {
    local reason="$1" published_identity="" suffix quarantine_path
    FAILED_BACKUP_PATH=""
    echo "  ${RED}[FAIL]${NC} $reason" >&2
    # Publication happens only after the file is owned by the invoking user.
    # Keep all operations on this user-controlled destination unprivileged: a
    # concurrent path exchange can then neither chmod nor inspect a root-owned
    # target through sudo.
    if ! published_identity=$(stat -Lc '%d:%i' \
            "$BACKUP_PUBLISH_PATH" 2>/dev/null) || \
       [ "$published_identity" != "$BACKUP_STAGED_IDENTITY" ]; then
        echo "  Could not bind published artifact to the staged inode; refusing path-based quarantine" >&2
        return 1
    fi
    if ! chmod 0600 "$BACKUP_PUBLISH_PATH"; then
        echo "  Could not enforce private mode on published artifact" >&2
        return 1
    fi
    suffix=$(date -u +%Y%m%dT%H%M%SZ)
    quarantine_path="${BACKUP_PUBLISH_PATH}.FAILED-${suffix}-$$"
    FAILED_BACKUP_PATH="${BACKUP_DISPLAY_PATH}.FAILED-${suffix}-$$"
    if mv -nT -- "$BACKUP_PUBLISH_PATH" "$quarantine_path" && \
       [ ! -e "$BACKUP_PUBLISH_PATH" ] && \
       [ ! -L "$BACKUP_PUBLISH_PATH" ]; then
        echo "  Unverified artifact quarantined: $FAILED_BACKUP_PATH" >&2
    else
        echo "  Could not quarantine unverified artifact without overwrite: $BACKUP_PUBLISH_PATH" >&2
        return 1
    fi
}

abort_backup_transaction() {
    local path="$1" reason="$2" quarantine_base="${3:-$1}"
    local display_base="${4:-$quarantine_base}"
    quarantine_backup "$path" "$reason" "$quarantine_base" "$display_base" || true
    cleanup_backup_stage || true
    close_parent_handle || true
    BACKUP_TRANSACTION_ACTIVE=0
    return 1
}

backup_transaction_exit_cleanup() {
    local rc=$?
    trap - EXIT HUP INT TERM
    if [ "$BACKUP_TRANSACTION_ACTIVE" -eq 1 ]; then
        if [ "$BACKUP_ARTIFACT_VERIFIED" -ne 1 ] && \
           [ -n "$BACKUP_WORK_PATH" ]; then
            quarantine_backup "$BACKUP_WORK_PATH" \
                "backup transaction interrupted before verified completion" \
                "$BACKUP_PUBLISH_PATH" "$BACKUP_DISPLAY_PATH" || true
        fi
        # A signal can arrive after the atomic rename but before ordinary shell
        # control flow records publication. Only quarantine the destination
        # when its inode is the exact staged inode; never move an unrelated
        # collision that appeared at the destination.
        if [ "$BACKUP_ARTIFACT_VERIFIED" -ne 1 ] && \
           [ -n "$BACKUP_STAGED_IDENTITY" ] && \
           [ -n "$BACKUP_PUBLISH_PATH" ] && \
           { [ -z "$BACKUP_WORK_PATH" ] || \
             { ! sudo test -e "$BACKUP_WORK_PATH" && \
               ! sudo test -L "$BACKUP_WORK_PATH"; }; }; then
            quarantine_published_artifact \
                "backup transaction interrupted before verified completion" || true
        fi
        cleanup_backup_stage || true
        close_parent_handle || true
        BACKUP_TRANSACTION_ACTIVE=0
    fi
    exit "$rc"
}

prepare_backup_stage() {
    local backup_path="$1" parent canonical_parent stage_parent stage_meta
    local backup_name
    BACKUP_STAGE_DIR=""
    BACKUP_WORK_PATH=""
    BACKUP_STAGE_HANDLE=""
    BACKUP_PARENT_HANDLE=""
    BACKUP_PUBLISH_PATH=""
    close_backup_handles || return 1
    if [ -e "$backup_path" ] || [ -L "$backup_path" ]; then
        echo "  ${RED}[FAIL]${NC} destination already exists; refusing overwrite" >&2
        return 1
    fi
    parent=${backup_path%/*}
    canonical_parent=$(readlink -e -- "$parent" 2>/dev/null) || return 1
    [ "$parent" = "$canonical_parent" ] || return 1
    backup_name=${backup_path##*/}
    [ -n "$backup_name" ] && [ "$backup_name" != . ] && [ "$backup_name" != .. ] \
        || return 1

    # Pin the selected mount and use the open handle for every privileged path
    # operation. A process that can rename entries in the user-owned mount root
    # can no longer redirect sudo/cryptsetup through a replacement symlink.
    exec {BACKUP_PARENT_FD}<"$canonical_parent" || return 1
    BACKUP_PARENT_HANDLE="/proc/$$/fd/$BACKUP_PARENT_FD"
    [ -d "$BACKUP_PARENT_HANDLE" ] || { close_backup_handles; return 1; }
    BACKUP_PUBLISH_PATH="$BACKUP_PARENT_HANDLE/$backup_name"
    if [ -e "$BACKUP_PUBLISH_PATH" ] || [ -L "$BACKUP_PUBLISH_PATH" ]; then
        close_backup_handles
        return 1
    fi
    if ! BACKUP_STAGE_DIR=$(mktemp -d --tmpdir="$BACKUP_PARENT_HANDLE" \
            '.noid-luks-backup.XXXXXXXX'); then
        close_backup_handles
        return 1
    fi
    stage_parent=$(dirname -- "$BACKUP_STAGE_DIR")
    if [ "$stage_parent" != "$BACKUP_PARENT_HANDLE" ] || \
       ! sudo test -d "$BACKUP_STAGE_DIR" || sudo test -L "$BACKUP_STAGE_DIR"; then
        echo "  ${RED}[FAIL]${NC} unsafe backup staging directory" >&2
        sudo rmdir -- "$BACKUP_STAGE_DIR" 2>/dev/null || true
        BACKUP_STAGE_DIR=""
        close_backup_handles
        return 1
    fi
    exec {BACKUP_STAGE_FD}<"$BACKUP_STAGE_DIR" || {
        sudo rmdir -- "$BACKUP_STAGE_DIR" 2>/dev/null || true
        BACKUP_STAGE_DIR=""
        close_backup_handles
        return 1
    }
    BACKUP_STAGE_HANDLE="/proc/$$/fd/$BACKUP_STAGE_FD"
    if ! sudo chown root:root "$BACKUP_STAGE_HANDLE" || \
       ! sudo chmod 0700 "$BACKUP_STAGE_HANDLE" || \
       ! stage_meta=$(sudo stat -c '%U:%G:%a' "$BACKUP_STAGE_HANDLE") || \
       [ "$stage_meta" != "root:root:700" ]; then
        echo "  ${RED}[FAIL]${NC} target filesystem cannot enforce root:root 0700 staging" >&2
        echo "  Use ext4, XFS or Btrfs directly or inside a LUKS container;" >&2
        echo "  typical FAT32/exFAT desktop mounts are unsupported. Reformatting erases data." >&2
        sudo rmdir -- "$BACKUP_STAGE_DIR" 2>/dev/null || true
        BACKUP_STAGE_DIR=""
        close_backup_handles
        return 1
    fi
    BACKUP_WORK_PATH="$BACKUP_STAGE_HANDLE/header.bin"
}

commit_success_log() {
    local timestamp="$1" sha="$2"
    sudo install -d -m 0755 -o root -g root /var/lib/noid-privacy
    sudo install -d -m 0755 -o root -g root /run/lock
    sudo flock -x "$SUCCESS_LOG_LOCK" /bin/bash -s -- \
        "$SUCCESS_LOG" "$timestamp" "$sha" <<'SUCCESS_LOG_ROOT_EOF'
set -euo pipefail
log_file="$1"
timestamp="$2"
sha="$3"
tmp=$(mktemp "${log_file}.tmp.XXXXXX")
cleanup_tmp() { [ -z "$tmp" ] || rm -f -- "$tmp"; }
trap cleanup_tmp EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
if [ -e "$log_file" ]; then
    [ -f "$log_file" ] && [ ! -L "$log_file" ]
    [ "$(stat -c '%U:%G:%a' "$log_file")" = 'root:wheel:640' ]
    cat "$log_file" > "$tmp"
fi
printf '%s\t%s\n' "$timestamp" "$sha" >> "$tmp"
chown root:wheel "$tmp"
chmod 0640 "$tmp"
if command -v restorecon >/dev/null 2>&1 && [ -f /sys/fs/selinux/enforce ]; then
    restorecon -F "$tmp"
fi
mv -fT -- "$tmp" "$log_file"
tmp=""
sync "$log_file"
sync "$(dirname -- "$log_file")"
trap - EXIT HUP INT TERM
SUCCESS_LOG_ROOT_EOF
}

perform_backup_transaction() {
    local luks_dev="$1" backup_path="$2"
    local size meta expected_meta sha_line sha timestamp published_size published_meta
    local published_sha_line published_identity display_identity
    VERIFIED_SHA=""
    VERIFIED_SIZE=""
    FAILED_BACKUP_PATH=""
    BACKUP_STAGE_DIR=""
    BACKUP_WORK_PATH=""
    BACKUP_DISPLAY_PATH="$backup_path"
    BACKUP_STAGED_IDENTITY=""
    BACKUP_ARTIFACT_VERIFIED=0
    BACKUP_TRANSACTION_ACTIVE=1

    if ! prepare_backup_stage "$backup_path"; then
        BACKUP_TRANSACTION_ACTIVE=0
        return 1
    fi
    if ! sudo cryptsetup luksHeaderBackup "$luks_dev" \
            --header-backup-file "$BACKUP_WORK_PATH"; then
        abort_backup_transaction "$BACKUP_WORK_PATH" \
            "cryptsetup luksHeaderBackup failed" \
            "$BACKUP_PUBLISH_PATH" "$backup_path"
        return 1
    fi
    if ! sudo chown "$(id -un):$(id -gn)" "$BACKUP_WORK_PATH" || \
       ! sudo chmod 0600 "$BACKUP_WORK_PATH"; then
        abort_backup_transaction "$BACKUP_WORK_PATH" \
            "backup ownership/mode setup failed" \
            "$BACKUP_PUBLISH_PATH" "$backup_path"
        return 1
    fi
    if ! sudo test -f "$BACKUP_WORK_PATH" || sudo test -L "$BACKUP_WORK_PATH"; then
        abort_backup_transaction "$BACKUP_WORK_PATH" \
            "backup is not a regular non-symlink file" \
            "$BACKUP_PUBLISH_PATH" "$backup_path"
        return 1
    fi
    if ! size=$(sudo stat -c %s "$BACKUP_WORK_PATH") || \
       ! [[ "$size" =~ ^[0-9]+$ ]] || [ "$size" -lt 1048576 ]; then
        abort_backup_transaction "$BACKUP_WORK_PATH" \
            "backup size/stat postcondition failed" \
            "$BACKUP_PUBLISH_PATH" "$backup_path"
        return 1
    fi
    expected_meta="$(id -un):$(id -gn):600"
    if ! meta=$(sudo stat -c '%U:%G:%a' "$BACKUP_WORK_PATH") || \
       [ "$meta" != "$expected_meta" ]; then
        abort_backup_transaction "$BACKUP_WORK_PATH" \
            "backup filesystem cannot enforce owner/mode $expected_meta" \
            "$BACKUP_PUBLISH_PATH" "$backup_path"
        return 1
    fi
    if ! BACKUP_STAGED_IDENTITY=$(sudo stat -Lc '%d:%i' \
            "$BACKUP_WORK_PATH") || \
       ! [[ "$BACKUP_STAGED_IDENTITY" =~ ^[0-9]+:[0-9]+$ ]]; then
        abort_backup_transaction "$BACKUP_WORK_PATH" \
            "backup inode identity postcondition failed" \
            "$BACKUP_PUBLISH_PATH" "$backup_path"
        return 1
    fi
    if ! sha_line=$(sudo sha256sum -- "$BACKUP_WORK_PATH") || \
       ! [[ "$sha_line" =~ ^([a-f0-9]{64})[[:space:]]+.+$ ]]; then
        abort_backup_transaction "$BACKUP_WORK_PATH" \
            "backup SHA-256 calculation failed" \
            "$BACKUP_PUBLISH_PATH" "$backup_path"
        return 1
    fi
    sha=${BASH_REMATCH[1]}
    if ! sudo cryptsetup luksDump "$BACKUP_WORK_PATH" >/dev/null 2>&1; then
        abort_backup_transaction "$BACKUP_WORK_PATH" \
            "cryptsetup luksDump failed; backup is not structurally valid" \
            "$BACKUP_PUBLISH_PATH" "$backup_path"
        return 1
    fi
    if ! sudo sync "$BACKUP_WORK_PATH"; then
        abort_backup_transaction "$BACKUP_WORK_PATH" \
            "backup file could not be synchronized to persistent storage" \
            "$BACKUP_PUBLISH_PATH" "$backup_path"
        return 1
    fi

    # Publish without ever replacing a pre-existing path. GNU mv -n reports
    # success even when it skips, so the disappearance of the staged file is
    # the decisive postcondition.
    if [ -e "$backup_path" ] || [ -L "$backup_path" ] || \
       sudo test -e "$BACKUP_PUBLISH_PATH" || \
       sudo test -L "$BACKUP_PUBLISH_PATH" || \
       ! sudo mv -nT -- "$BACKUP_WORK_PATH" "$BACKUP_PUBLISH_PATH" || \
       sudo test -e "$BACKUP_WORK_PATH" || sudo test -L "$BACKUP_WORK_PATH"; then
        abort_backup_transaction "$BACKUP_WORK_PATH" \
            "destination collision or atomic publication failure" \
            "$BACKUP_PUBLISH_PATH" "$backup_path"
        return 1
    fi
    if ! cleanup_backup_stage; then
        quarantine_published_artifact \
            "private staging cleanup failed after publication" || true
        cleanup_backup_stage || true
        close_parent_handle || true
        BACKUP_TRANSACTION_ACTIVE=0
        return 1
    fi

    # Re-read through the pinned parent and require the user-facing path to
    # resolve to that same inode. A mount/path swap cannot obtain success.
    if ! test -f "$BACKUP_PUBLISH_PATH" || \
       test -L "$BACKUP_PUBLISH_PATH" || \
       ! published_size=$(stat -c %s "$BACKUP_PUBLISH_PATH") || \
       [ "$published_size" != "$size" ] || \
       ! published_meta=$(stat -c '%U:%G:%a' "$BACKUP_PUBLISH_PATH") || \
       [ "$published_meta" != "$expected_meta" ] || \
       ! published_sha_line=$(sha256sum -- "$BACKUP_PUBLISH_PATH") || \
       ! [[ "$published_sha_line" =~ ^([a-f0-9]{64})[[:space:]]+.+$ ]] || \
       [ "${BASH_REMATCH[1]}" != "$sha" ] || \
       ! cryptsetup luksDump "$BACKUP_PUBLISH_PATH" >/dev/null 2>&1 || \
       ! published_identity=$(stat -Lc '%d:%i' "$BACKUP_PUBLISH_PATH") || \
       [ "$published_identity" != "$BACKUP_STAGED_IDENTITY" ] || \
       ! display_identity=$(stat -Lc '%d:%i' "$backup_path") || \
       [ "$display_identity" != "$published_identity" ]; then
        quarantine_published_artifact \
            "published backup failed final postcondition verification" || true
        close_parent_handle || true
        BACKUP_TRANSACTION_ACTIVE=0
        return 1
    fi
    # The file sync makes its bytes/metadata durable; syncing the exact parent
    # makes the rename and staging-directory removal durable before success is
    # recorded. This is the strongest generic userspace guarantee a mounted
    # removable filesystem can expose.
    if ! sync "$BACKUP_PUBLISH_PATH" || \
       ! sync "$BACKUP_PARENT_HANDLE"; then
        echo "  ${RED}[FAIL]${NC} backup verified, but durable media sync failed" >&2
        echo "  Verified file remains at: $backup_path" >&2
        close_parent_handle || true
        BACKUP_TRANSACTION_ACTIVE=0
        return 1
    fi
    BACKUP_ARTIFACT_VERIFIED=1
    timestamp=$(date -Iseconds)
    if ! commit_success_log "$timestamp" "$sha"; then
        echo "  ${RED}[FAIL]${NC} backup verified, but success log commit failed" >&2
        echo "  Verified file remains at: $backup_path" >&2
        close_parent_handle || true
        BACKUP_TRANSACTION_ACTIVE=0
        return 1
    fi
    VERIFIED_SHA="$sha"
    VERIFIED_SIZE="$size"
    close_parent_handle
    BACKUP_TRANSACTION_ACTIVE=0
    return 0
}
# END LUKS_BACKUP_TRANSACTION_FUNCTIONS

# One persistent trap owns unexpected-exit cleanup for the whole helper. Signal
# traps convert asynchronous termination into the EXIT path with a stable code.
trap backup_transaction_exit_cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# --- LIST mode: show existing backups on mounted media ----------------------
if [ "$MODE" = "list" ]; then
    fmt_banner "NoID Privacy LUKS Header Backup" "Find recovery artifacts on removable media"
    fmt_step 1 1 "Search mounted removable media"
    mounts=$(detect_removable_mounts "")
    if [ -z "$mounts" ]; then
        echo "${YELLOW}No removable media mounted.${NC}"
        echo "Plug in a USB stick and mount it via GNOME Files, then re-run."
        return_to_menu_prompt
        exit 0
    fi
    found=0
    while IFS= read -r mpoint; do
        echo "Searching: $mpoint"
        matches=$(find "$mpoint" -maxdepth 3 -type f -name 'luks-header-*.bin' 2>/dev/null)
        if [ -n "$matches" ]; then
            while IFS= read -r f; do
                sz=$(stat -c %s "$f" 2>/dev/null || echo 0)
                mt=$(stat -c %y "$f" 2>/dev/null | cut -d. -f1 || echo unknown)
                echo "  ${GREEN}[FOUND]${NC} $f  (${sz} bytes, $mt)"
                found=$((found + 1))
            done <<<"$matches"
        fi
    done <<<"$mounts"
    echo
    if [ "$found" -eq 0 ]; then
        echo "${YELLOW}No backups found.${NC} Consider running: noid-luks-backup.sh"
    else
        echo "${GREEN}${found} backup file(s) found.${NC}"
    fi
    return_to_menu_prompt
    exit 0
fi

# --- VERIFY mode: sanity-check existing backup file -------------------------
if [ "$MODE" = "verify" ]; then
    if [ -z "${VERIFY_FILE:-}" ] || [ ! -f "$VERIFY_FILE" ] || \
       [ -L "$VERIFY_FILE" ] || [ ! -r "$VERIFY_FILE" ]; then
        echo "${RED}ERROR${NC}: --verify requires a readable regular non-symlink file" >&2
        echo "Usage: noid-luks-backup.sh --verify /path/to/luks-header-*.bin" >&2
        exit 2
    fi
    VERIFY_CANONICAL=$(readlink -e -- "$VERIFY_FILE") || {
        echo "${RED}ERROR${NC}: could not resolve verification path" >&2
        exit 2
    }
    VERIFY_FILE="$VERIFY_CANONICAL"
    fmt_banner "NoID Privacy LUKS Header Backup" "Verify an existing recovery artifact"
    fmt_step 1 1 "Validate file structure + integrity"
    fmt_info "File: $VERIFY_FILE"
    sz=$(stat -c %s "$VERIFY_FILE" 2>/dev/null || echo 0)
    echo "  Size: ${sz} bytes"
    # LUKS1 header ~2 MiB, LUKS2 header ~16 MiB. 1 MB threshold catches both.
    if [ "$sz" -lt 1048576 ]; then
        echo "  ${YELLOW}[warn]${NC} File smaller than 1 MB — unlikely to be a valid LUKS header"
    fi
    # cryptsetup can read a dump from the backup file
    if cryptsetup luksDump "$VERIFY_FILE" >/dev/null 2>&1; then
        echo "  ${GREEN}[OK]${NC} cryptsetup luksDump succeeds on backup"
        echo
        echo "Header summary:"
        cryptsetup luksDump "$VERIFY_FILE" 2>/dev/null | \
            grep -E '^(Version|Cipher|UUID|Keyslots)' | head -10 | sed 's/^/  /'
    else
        echo "  ${RED}[FAIL]${NC} cryptsetup cannot parse this file — not a valid LUKS header"
        return_to_menu_prompt
        exit 1
    fi
    # SHA-256 for later integrity comparison.
    sha=$(sha256sum -- "$VERIFY_FILE" 2>/dev/null | awk '{print $1}')
    echo "  SHA256: $sha"
    return_to_menu_prompt
    exit 0
fi

# --- INTERACTIVE mode: full backup flow -------------------------------------
fmt_banner "NoID Privacy LUKS Header Backup" "Structurally verified offline header backup"
cat <<INTRO
This is a critical first-day task. Damage to required LUKS1/LUKS2 metadata or
keyslots can make the volume inaccessible; an offline header backup provides
an additional recovery path.

This script will:
  1. Detect your LUKS1/LUKS2 partition(s)
  2. Detect mounted removable media (USB stick, SD card)
  3. Save the header as: luks-header-\$(date -u +%Y%m%dT%H%M%SZ).bin
  4. Print the SHA256 so you can verify integrity later
  5. Remind you to copy to a SECOND stick stored in a SECOND location

${YELLOW}Security note:${NC} the backup plus any passphrase valid when it was
created can decrypt the data even if that passphrase is later changed or
removed from the live header. Store it ONLY on trusted removable media; do
NOT save it on a network drive or the same disk it came from.

INTRO

# Step 1: detect LUKS partitions (LUKS1 + LUKS2 both reported as crypto_LUKS)
fmt_step 1 4 "Detect encrypted volumes"
luks_list=$(detect_luks_partitions)
if [ -z "$luks_list" ]; then
    echo "  ${RED}[ERROR]${NC} no crypto_LUKS partition found via lsblk"
    echo "  Are you sure this system has disk encryption?"
    return_to_menu_prompt
    exit 1
fi

luks_count=$(echo "$luks_list" | wc -l)
if [ "$luks_count" -eq 1 ]; then
    luks_dev=$(echo "$luks_list" | awk '{print $1}')
    luks_sz=$(echo "$luks_list" | awk '{print $2}')
    fmt_ok "single LUKS partition: $luks_dev ($luks_sz)"
else
    echo "  Multiple LUKS partitions detected — pick one:"
    i=1
    while IFS= read -r line; do
        echo "    $i) $line"
        i=$((i + 1))
    done <<<"$luks_list"
    echo
    read -rp "Select partition [1-$((i - 1))]: " choice || choice=""
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -ge "$i" ]; then
        echo "  ${RED}[ERROR]${NC} invalid selection"
        return_to_menu_prompt
        exit 1
    fi
    luks_dev=$(echo "$luks_list" | sed -n "${choice}p" | awk '{print $1}')
    fmt_ok "selected: $luks_dev"
fi

# Step 2: detect removable media mount point
fmt_step 2 4 "Select verified removable media"
if [ -n "$EXPERT_TARGET" ]; then
    if ! inspect_block_mount "$EXPERT_TARGET"; then
        echo "  ${RED}[ERROR]${NC} expert target is not a distinct block-device mountpoint"
        return_to_menu_prompt
        exit 1
    fi
    target_dir="$MOUNT_CANONICAL"
    echo "  ${RED}${BOLD}EXPERT OVERRIDE${NC}: removable/external topology and"
    echo "  separation from the source disk have NOT been verified. A same-disk"
    echo "  backup does not protect against disk loss."
    print_mount_topology
    read -rp 'Type exactly "USE UNVERIFIED TARGET" to continue: ' expert_ack || \
        expert_ack=""
    if [ "$expert_ack" != "USE UNVERIFIED TARGET" ]; then
        echo "Cancelled."
        return_to_menu_prompt
        exit 1
    fi
else
    mounts=$(detect_removable_mounts "$luks_dev")
fi
if [ -z "$EXPERT_TARGET" ] && [ -z "$mounts" ]; then
    whoami_user="${USER:-$(id -un)}"
    echo "  ${RED}[ERROR]${NC} no verified removable block-device mount found"
    echo
    echo "  Plug in an external USB stick (or SD card), wait for GNOME to"
    echo "  auto-mount it, then re-run this script. Ordinary directories and"
    echo "  targets on the source disk are deliberately rejected."
    echo "  You can verify via: ls /run/media/${whoami_user}/"
    echo "  For unusual external hardware: --expert-target /mounted/path"
    return_to_menu_prompt
    exit 1
fi

if [ -z "$EXPERT_TARGET" ]; then
    mount_count=$(echo "$mounts" | wc -l)
    if [ "$mount_count" -eq 1 ]; then
        target_dir="$mounts"
        fmt_ok "single verified removable mount: $target_dir"
    else
        echo "  Multiple verified removable media detected — pick one:"
        i=1
        while IFS= read -r line; do
            echo "    $i) $line"
            i=$((i + 1))
        done <<<"$mounts"
        echo
        read -rp "Select target [1-$((i - 1))]: " choice || choice=""
        if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -ge "$i" ]; then
            echo "  ${RED}[ERROR]${NC} invalid selection"
            return_to_menu_prompt
            exit 1
        fi
        target_dir=$(echo "$mounts" | sed -n "${choice}p")
        fmt_ok "selected: $target_dir"
    fi
    if ! is_verified_removable_mount "$target_dir" "$luks_dev"; then
        echo "  ${RED}[ERROR]${NC} target topology changed during selection"
        return_to_menu_prompt
        exit 1
    fi
    print_mount_topology
fi

# Verify target is writable
if ! [ -w "$target_dir" ]; then
    echo "  ${RED}[ERROR]${NC} $target_dir is not writable"
    echo "  The USB stick may be mounted read-only or permissions differ."
    return_to_menu_prompt
    exit 1
fi

# Step 3: build a privacy-preserving filename + confirm. Do not put the
# hostname or a hardware identifier onto removable media.
BACKUP_NAME="luks-header-$(date -u +%Y%m%dT%H%M%SZ).bin"
BACKUP_PATH="$target_dir/$BACKUP_NAME"

if [ -e "$BACKUP_PATH" ] || [ -L "$BACKUP_PATH" ]; then
    echo
    echo "  ${RED}[ERROR]${NC} destination path already exists; refusing overwrite:"
    echo "  $BACKUP_PATH"
    echo "  Wait one second and rerun to generate a fresh timestamped name."
    return_to_menu_prompt
    exit 1
fi

echo
echo "${BOLD}About to back up:${NC}"
echo "  Source:      $luks_dev"
echo "  Destination: $BACKUP_PATH"
echo
read -rp "Proceed? [y/N] " ans || ans=""
case "${ans:-n}" in
    [yY]|[yY][eE][sS]) ;;
    *) echo "Cancelled."; return_to_menu_prompt; exit 0 ;;
esac

# Steps 3-4: write, verify every postcondition, then commit success evidence.
fmt_step 3 4 "Create private header backup"
fmt_info "Authorization covers cryptsetup, private staging/publication and root-owned evidence."
if ! perform_backup_transaction "$luks_dev" "$BACKUP_PATH"; then
    return_to_menu_prompt
    exit 1
fi

fmt_step 4 4 "Verify + record backup evidence"
sz="$VERIFIED_SIZE"
sha="$VERIFIED_SHA"
echo "  Size: ${sz} bytes"
echo "  SHA256: $sha"
fmt_ok "regular-file, metadata, SHA-256, luksDump and durable-sync checks passed"
fmt_ok "success evidence committed atomically"
fmt_done "LUKS header backup complete"

cat <<SUMMARY

${BOLD}Backup file:${NC} $BACKUP_PATH
${BOLD}SHA256:${NC}      $sha

${BOLD}${YELLOW}NOW DO THIS:${NC}${YELLOW}

  1. Copy $BACKUP_NAME to a SECOND USB stick
     (rsync / cp / drag-and-drop — any method).
  2. Store the SECOND stick in a DIFFERENT physical location
     (friend's house, bank safe, parents' place, locked drawer).
  3. Write the SHA256 hash on paper, stored with one of the sticks —
     use this later to verify the backup is uncorrupted:
         sha256sum /path/to/backup.bin
     Compare the output against your written hash.${NC}

${BOLD}Verify anytime:${NC}
  noid-luks-backup.sh --verify $BACKUP_PATH

${BOLD}Find backups on mounted media:${NC}
  noid-luks-backup.sh --list-existing

Docs: /usr/share/doc/noid-privacy/22-disk-encryption.md
SUMMARY

return_to_menu_prompt
exit 0
LUKS_BACKUP_EOF

chmod 0755 /usr/local/bin/noid-luks-backup.sh
chown root:root /usr/local/bin/noid-luks-backup.sh
log "  [OK] /usr/local/bin/noid-luks-backup.sh installed (0755)"

# ====================================================================
# STEP 4: SELinux context restore
# ====================================================================
log "STEP 4: SELinux context restore"
command -v restorecon >/dev/null 2>&1 \
    || { log "  [FAIL] restorecon is unavailable"; exit 1; }
restorecon -F \
    /usr/local/bin/noid-mount-hardening.sh \
    /usr/local/bin/noid-live-mount-hardening.sh \
    /usr/local/bin/noid-luks-backup.sh \
    /usr/libexec/noid-btrfs-scrub \
    /etc/systemd/system/noid-mount-hardening.service \
    /etc/systemd/system/noid-live-mount-hardening.service \
    /etc/systemd/system/btrfs-scrub.service \
    /etc/systemd/system/btrfs-scrub.timer \
    /usr/share/doc/noid-privacy/22-disk-encryption.md \
    || { log "  [FAIL] SELinux label reconciliation failed"; exit 1; }
log "  [OK] restorecon complete"

# ====================================================================
# STEP 5: Verification
# ====================================================================
log "STEP 5: verification"

verify_ok=0
verify_fail=0

# 5.1 — Script exists, executable and syntactically valid
if [ -x /usr/local/bin/noid-mount-hardening.sh ] && \
        bash -n /usr/local/bin/noid-mount-hardening.sh 2>/dev/null; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] mount hardening script exists + executable + syntax valid"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] mount hardening script missing, non-executable or invalid"
fi

# 5.2 — Service unit exists
if [ -f /etc/systemd/system/noid-mount-hardening.service ]; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] service unit exists"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] service unit missing"
fi

# 5.3 — Service has ConditionPathExists (idempotency)
if grep -q 'ConditionPathExists=!/var/lib/noid-privacy/.mount-hardening-done' \
        /etc/systemd/system/noid-mount-hardening.service 2>/dev/null; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] service has idempotency condition"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] service missing idempotency condition"
fi

# 5.4 — Service is enabled in its declared early-boot target. This unit uses
# WantedBy=basic.target so mount policy finishes before ordinary services;
# checking the later multi-user target would reject a correctly enabled unit.
if [ -L /etc/systemd/system/basic.target.wants/noid-mount-hardening.service ]; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] service enabled"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] service not enabled"
fi

# 5.4a — Live-media reconciler is executable and syntactically valid
if [ -x /usr/local/bin/noid-live-mount-hardening.sh ] && \
        bash -n /usr/local/bin/noid-live-mount-hardening.sh 2>/dev/null; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] live-media mount hardening script exists + syntax valid"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] live-media mount hardening script missing or invalid"
fi

# 5.4b — Live-media unit exists and is enabled in its declared target
if [ -f /etc/systemd/system/noid-live-mount-hardening.service ] && \
        [ -L /etc/systemd/system/basic.target.wants/noid-live-mount-hardening.service ]; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] live-media mount hardening service exists + enabled"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] live-media mount hardening service missing or not enabled"
fi

# 5.5 — Documentation exists with non-trivial size
if [ -f /usr/share/doc/noid-privacy/22-disk-encryption.md ]; then
    doc_size=$(stat -c %s /usr/share/doc/noid-privacy/22-disk-encryption.md 2>/dev/null || echo 0)
    doc_size=${doc_size:-0}
    if [ "$doc_size" -gt 1024 ]; then
        verify_ok=$((verify_ok + 1))
        log "  [OK] documentation ${doc_size} bytes"
    else
        verify_fail=$((verify_fail + 1))
        log "  [FAIL] documentation too small (${doc_size} bytes)"
    fi
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] documentation missing"
fi

# 5.6 — LUKS backup wrapper exists, executable, correct perms
if [ -x /usr/local/bin/noid-luks-backup.sh ]; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] LUKS backup wrapper exists + executable"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] LUKS backup wrapper missing or not executable"
fi

luks_wrap_perm=$(stat -c %a /usr/local/bin/noid-luks-backup.sh 2>/dev/null || echo 000)
if [ "$luks_wrap_perm" = "755" ]; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] LUKS backup wrapper perms=0755"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] LUKS backup wrapper perms=$luks_wrap_perm (expected 755)"
fi

if bash -n /usr/local/bin/noid-luks-backup.sh 2>/dev/null; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] LUKS backup wrapper syntax valid"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] LUKS backup wrapper has syntax errors"
fi

# 5.7 — btrfs scrub service unit exists
if [ -f /etc/systemd/system/btrfs-scrub.service ]; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] btrfs-scrub.service unit exists"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] btrfs-scrub.service unit missing"
fi

# 5.8 — btrfs scrub timer unit exists
if [ -f /etc/systemd/system/btrfs-scrub.timer ]; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] btrfs-scrub.timer unit exists"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] btrfs-scrub.timer unit missing"
fi

# 5.9 — btrfs scrub timer is enabled
if [ -L /etc/systemd/system/timers.target.wants/btrfs-scrub.timer ]; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] btrfs-scrub.timer enabled"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] btrfs-scrub.timer not enabled"
fi

# 5.10 — systemd parses every M22 unit as installed
if systemd-analyze verify \
        /etc/systemd/system/noid-mount-hardening.service \
        /etc/systemd/system/noid-live-mount-hardening.service \
        /etc/systemd/system/btrfs-scrub.service \
        /etc/systemd/system/btrfs-scrub.timer >/dev/null 2>&1; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] all M22 systemd units pass parser verification"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] an M22 systemd unit failed parser verification"
fi

# 5.11 — scrub helper is an executable, syntactically valid build artifact
if [ -x /usr/libexec/noid-btrfs-scrub ] && \
        [ ! -L /usr/libexec/noid-btrfs-scrub ] && \
        [ "$(stat -c '%U:%G:%a' /usr/libexec/noid-btrfs-scrub 2>/dev/null)" = \
            root:root:755 ] && \
        bash -n /usr/libexec/noid-btrfs-scrub; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] resumable btrfs scrub helper metadata + syntax verified"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] resumable btrfs scrub helper is invalid"
fi

# 5.12 — service and helper retain the filesystem gate, bounded retry and
# native bandwidth contracts
if grep -Fxq 'ExecCondition=/usr/bin/findmnt -n -M / -t btrfs' \
        /etc/systemd/system/btrfs-scrub.service && \
   grep -Fxq 'ExecStart=/usr/libexec/noid-btrfs-scrub' \
        /etc/systemd/system/btrfs-scrub.service && \
   grep -Fxq 'Restart=on-failure' \
        /etc/systemd/system/btrfs-scrub.service && \
   grep -Fxq 'RestartPreventExitStatus=3' \
        /etc/systemd/system/btrfs-scrub.service && \
   grep -Fxq 'StateDirectory=noid-btrfs-scrub' \
        /etc/systemd/system/btrfs-scrub.service && \
   grep -Fxq 'StateDirectoryMode=0700' \
        /etc/systemd/system/btrfs-scrub.service && \
   grep -Fq 'write_state 1 || fail "original device limits could not be committed"' \
        /usr/libexec/noid-btrfs-scrub && \
   grep -Fq 'recover_saved_state' /usr/libexec/noid-btrfs-scrub && \
   grep -Fq '2) apply_rate_limit ;;' /usr/libexec/noid-btrfs-scrub && \
   grep -Fq '"$BTRFS" scrub start -B -d --limit "$RATE_LIMIT" "$MOUNT"' \
        /usr/libexec/noid-btrfs-scrub && \
   grep -Fq '"$BTRFS" scrub resume -B -d "$MOUNT"' \
        /usr/libexec/noid-btrfs-scrub; then
    verify_ok=$((verify_ok + 1))
    log "  [OK] btrfs scrub gate, resume, retry and per-device limit contracts verified"
else
    verify_fail=$((verify_fail + 1))
    log "  [FAIL] btrfs scrub lifecycle contract is incomplete"
fi

log "  Verification: ${verify_ok} OK, ${verify_fail} FAIL"

# Abort build on verify-failures (match M19 pattern).
# Earlier M22 only logged failures and continued — safe for
# mount-hardening + docs but risky for the helper scripts.
if [ "$verify_fail" -gt 0 ]; then
    log "  ABORT: ${verify_fail} verification check(s) FAILED — build aborted"
    exit 1
fi

log "=== Module 22 complete ==="
%end

#!/bin/bash
# 22-luks-partitioning-mount — regression test for M22 append_fstab_opt sed bug
#
# Background: M22 v2 shipped a broken append_fstab_opt helper (sed using / as
# address delimiter with regex containing unescaped /tmp → sed exit 4,
# mount-hardening.service FAIL at first boot, silently — set -eu swallowed it).
# Fix in v3: bash parameter expansion `${mnt_regex//\//\\/}` + post-patch verify.
#
# This test extracts ensure_mount_options from 22-luks-partitioning.ks, runs
# it against a mock fstab matching what Anaconda writes, and asserts:
#   1. /tmp gains nosuid + noexec + nodev in the expected position
#   2. Idempotent — second call does not duplicate the option
#   3. Behavior on an already-present option: no-op, no error
#   4. Edge case — mountpoint not in fstab: helper returns zero without mutation
#
# Why this test matters: bash -n passed M22 v2 (syntax was fine). Only
# semantic testing against real-shape fstab input catches this class of bug.
# → This is the canonical "E2E mock-data test" referenced in CONTRIBUTING.md.

set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/22-luks-partitioning.ks"
M99_FILE="$PROJECT_ROOT/kickstart/snippets/99-finalize.ks"

test_start "22-luks-partitioning-mount"

# --- 0. Source M22 helpers into this shell ----------------------------------

if [ ! -f "$KS_FILE" ]; then
    _fail "M22 snippet missing at expected path: $KS_FILE"
    test_finish
    exit 1
fi

TMPDIR="$(mktemp -d /var/tmp/noid-m22-test.XXXXXXXX)"
trap 'rm -rf "$TMPDIR"' EXIT

extract_heredoc "$KS_FILE" "LUKS_BACKUP_EOF" "$TMPDIR/luks-backup.sh" \
    || _fail "LUKS backup helper extraction"
extract_heredoc "$KS_FILE" "SCRIPT_EOF" "$TMPDIR/mount-hardening.sh" \
    || _fail "mount-hardening helper extraction"
extract_heredoc "$KS_FILE" "DOC_EOF" "$TMPDIR/22-disk-encryption.md" \
    || _fail "LUKS documentation extraction"
extract_heredoc "$KS_FILE" "SVC_EOF" "$TMPDIR/noid-mount-hardening.service" \
    || _fail "mount-hardening unit extraction"
extract_heredoc "$KS_FILE" "LIVE_MOUNT_SCRIPT_EOF" "$TMPDIR/live-mount-script" \
    || _fail "live mount script extraction"
extract_heredoc "$KS_FILE" "LIVE_MOUNT_SERVICE_EOF" \
    "$TMPDIR/noid-live-mount-hardening.service" \
    || _fail "live mount service extraction"
extract_heredoc "$KS_FILE" "SCRUB_SVC_EOF" "$TMPDIR/btrfs-scrub.service" \
    || _fail "btrfs scrub service extraction"
extract_heredoc "$KS_FILE" "SCRUB_TIMER_EOF" "$TMPDIR/btrfs-scrub.timer" \
    || _fail "btrfs scrub timer extraction"
extract_heredoc "$KS_FILE" "SCRUB_SCRIPT_EOF" "$TMPDIR/noid-btrfs-scrub" \
    || _fail "btrfs scrub helper extraction"
assert_cmd_success "LUKS backup helper is valid bash" bash -n "$TMPDIR/luks-backup.sh"
assert_cmd_success "resumable btrfs scrub helper is valid bash" \
    bash -n "$TMPDIR/noid-btrfs-scrub"

# `systemd-analyze verify` resolves every ExecStart= executable against the
# running host.  Parse isolated copies with neutral executable paths so this
# source-tree test does not depend on an already-installed NoID Privacy image. The
# exact production paths and the extracted helper syntax are asserted
# separately below.
UNIT_VERIFY_DIR="$TMPDIR/systemd-verify"
mkdir -p "$UNIT_VERIFY_DIR"
for unit in \
    noid-mount-hardening.service \
    noid-live-mount-hardening.service \
    btrfs-scrub.service \
    btrfs-scrub.timer; do
    cp -- "$TMPDIR/$unit" "$UNIT_VERIFY_DIR/$unit"
done
sed -i 's#^ExecStart=.*$#ExecStart=/usr/bin/true#' \
    "$UNIT_VERIFY_DIR"/*.service
assert_cmd_success "all M22 systemd units pass the systemd parser" \
    systemd-analyze verify \
        "$UNIT_VERIFY_DIR/noid-mount-hardening.service" \
        "$UNIT_VERIFY_DIR/noid-live-mount-hardening.service" \
        "$UNIT_VERIFY_DIR/btrfs-scrub.service" \
        "$UNIT_VERIFY_DIR/btrfs-scrub.timer"
assert_grep_fixed 'install -d -m 0755 -o root -g root /var/lib/noid-privacy' \
    "$KS_FILE" "M22 preserves the shared root:root 0755 state-directory contract"
assert_not_grep 'install -d -m 0700 /var/lib/noid-privacy' "$KS_FILE" \
    "M22 never makes the shared state container root-only"
assert_not_grep 'hostname.*luks-header\|luks-header-.*hostname' \
    "$TMPDIR/luks-backup.sh" \
    "removable-media backup filename does not disclose hostname"
assert_grep_fixed 'luks-header-$(date -u +%Y%m%dT%H%M%SZ).bin' \
    "$TMPDIR/luks-backup.sh" \
    "LUKS backup uses a privacy-preserving UTC timestamp"
assert_not_grep 'blocks this attack class entirely' \
    "$TMPDIR/22-disk-encryption.md" \
    "passphrase-only mode is not misrepresented as complete evil-maid defense"
assert_not_grep "Anaconda's default.*1048576" \
    "$TMPDIR/22-disk-encryption.md" \
    "documentation does not invent a universal Anaconda Argon2 memory value"
assert_grep_fixed 'DISA STIG RHEL 9 V-257869 requires `nodev`' \
    "$TMPDIR/22-disk-encryption.md" \
    "disk guide attributes only the actual /var STIG rule"
assert_not_grep 'V-257869+V-257870' "$KS_FILE" \
    "unrelated /var/log STIG rule cannot be attributed to /var"
assert_grep_fixed 'Typical FAT32/exFAT desktop mounts cannot satisfy this' \
    "$TMPDIR/22-disk-encryption.md" \
    "easy path discloses its removable-filesystem requirement"
assert_grep_fixed 'historical dracut failure RHBZ#2274246 was fixed in dracut 102' \
    "$TMPDIR/22-disk-encryption.md" \
    "disk guide treats the dracut noexec defect as historical"
assert_not_grep 'breaks DNF/RPM scriptlets and Fedora system-upgrade (RHBZ#2274246)' \
    "$TMPDIR/22-disk-encryption.md" \
    "disk guide does not use a fixed dracut bug as current evidence"
assert_grep_fixed '| /boot | 2 GiB | ext4 |' \
    "$TMPDIR/22-disk-encryption.md" \
    "reference Fedora 44 automatic layout records the observed 2 GiB boot partition"
assert_not_grep 'The Anaconda defaults are recommended:' \
    "$TMPDIR/22-disk-encryption.md" \
    "reference-host partition sizes are not universalized as installer defaults"
if cmp -s "$TMPDIR/22-disk-encryption.md" "$PROJECT_ROOT/docs/22-disk-encryption.md"; then
    _pass "standalone and installed disk-encryption documentation match"
else
    _fail "standalone and installed disk-encryption documentation drift"
fi
assert_grep_fixed 'sudo systemctl restart noid-mount-hardening.service' \
    "$TMPDIR/22-disk-encryption.md" \
    "manual mount-hardening rerun restarts the active oneshot"
assert_not_grep 'sudo systemctl start noid-mount-hardening.service' \
    "$TMPDIR/22-disk-encryption.md" \
    "manual rerun cannot silently no-op on an active RemainAfterExit unit"
assert_not_grep 'borg extract .*--target\|--target /tmp' \
    "$TMPDIR/22-disk-encryption.md" \
    "Borg restore guidance does not use a nonexistent target option"
assert_grep_fixed 'mktemp -d /var/tmp/noid-borg-test-restore.XXXXXX' \
    "$TMPDIR/22-disk-encryption.md" \
    "Borg restore guidance creates its private target under /var/tmp"
assert_grep_fixed '(cd "$restore_dir" &&' "$TMPDIR/22-disk-encryption.md" \
    "Borg extracts relative to the selected restore directory"

# The first-boot unit must operate in PID 1's mount namespace. Several
# seemingly unrelated Protect*= settings imply a private mount namespace and
# previously made all successful remounts disappear at service exit.
assert_grep_fixed 'DefaultDependencies=no' "$KS_FILE" \
    "mount hardening is explicitly ordered in early boot"
assert_grep_fixed 'Before=basic.target' "$KS_FILE" \
    "mount hardening completes before ordinary basic services"
assert_grep_fixed 'WantedBy=basic.target' "$KS_FILE" \
    "mount hardening is pulled into early boot"
assert_grep_fixed '/etc/systemd/system/basic.target.wants/noid-mount-hardening.service' \
    "$KS_FILE" "M22 verifies the declared basic.target enablement link"
assert_grep_fixed '/etc/systemd/system/basic.target.wants/noid-mount-hardening.service' \
    "$M99_FILE" "M99 verifies the declared basic.target enablement link"
assert_not_grep 'multi-user.target.wants/noid-mount-hardening.service' "$KS_FILE" \
    "M22 has no stale multi-user.target verification"
assert_not_grep 'multi-user.target.wants/noid-mount-hardening.service' "$M99_FILE" \
    "M99 has no stale multi-user.target verification"
mount_namespace_re='^(PrivateTmp|PrivateMounts|PrivateDevices|ProtectHome|ProtectSystem|ProtectKernelTunables|ProtectKernelModules|ProtectKernelLogs|ProtectControlGroups|ProtectClock|ProtectProc|ReadOnlyPaths|ReadWritePaths|InaccessiblePaths|TemporaryFileSystem|BindPaths|BindReadOnlyPaths|RootDirectory)='
assert_not_grep_extended "$mount_namespace_re" \
    "$TMPDIR/noid-mount-hardening.service" \
    "mount hardening unit remains in PID 1's mount namespace"
assert_not_grep '^ExecStartPost=.*mount-hardening-done' "$KS_FILE" \
    "mount hardening marker is not written unconditionally by systemd"
assert_grep_fixed 'verify_effective_opt' "$KS_FILE" \
    "mount hardening verifies the effective kernel mount table"
assert_grep_fixed '#   - STEP 2a: noid-live-mount-hardening.sh' "$KS_FILE" \
    "M22 header inventories the live-media reconciler"
assert_grep_fixed '#     /boot/efi = nosuid,nodev,noexec; / = nodiscard; /home =' \
    "$KS_FILE" "M22 header inventories the root and home discard policy"
assert_grep_fixed 'targets present as distinct `/etc/fstab` entries' \
    "$TMPDIR/22-disk-encryption.md" \
    "disk guide scopes independent mount flags to distinct fstab targets"
assert_grep_fixed '.noid-noexec-probe.' "$KS_FILE" \
    "mount hardening performs direct noexec probes"
assert_grep_fixed 'ensure_mount_options / "nodiscard"' "$KS_FILE" \
    "Btrfs root explicitly disables continuous async discard"
assert_grep_fixed 'ensure_mount_options /home "nosuid,nodev,nodiscard"' "$KS_FILE" \
    "Btrfs home explicitly disables continuous async discard"
assert_grep_fixed '[/]="nodiscard"' "$KS_FILE" \
    "runtime root remount applies nodiscard immediately"
assert_grep_fixed '/var /var none bind,nosuid,nodev,private 0 0' "$KS_FILE" \
    "/var self-bind has a persistent private propagation contract"
assert_grep_fixed 'mount --make-private /var' "$KS_FILE" \
    "current /var mount is made private before nested mounts can propagate"
assert_grep_fixed 'findmnt -n -M /var -o PROPAGATION' "$KS_FILE" \
    "private propagation is verified in the effective mount table"
assert_grep_fixed "grep -qE '^[[:space:]]*[^[:space:]#]+[[:space:]]+/tmp[[:space:]]'" \
    "$KS_FILE" "a custom separate /tmp entry is hardened instead of duplicated"
assert_not_grep "grep -qE '^[[:space:]]*tmpfs[[:space:]]+/tmp[[:space:]]'" \
    "$KS_FILE" "tmpfs-only detection cannot create a duplicate /tmp target"
assert_grep_fixed 'FSTAB_WORK=$(mktemp "$FSTAB_DIR/.noid-fstab.XXXXXX")' "$KS_FILE" \
    "fstab edits use a same-directory transaction file"
assert_grep_fixed 'findmnt --verify --tab-file "$FSTAB"' "$KS_FILE" \
    "libmount validates the complete candidate fstab"
assert_grep_fixed 'sync "$FSTAB"' "$KS_FILE" \
    "candidate fstab bytes and metadata are durable before rename"
assert_grep_fixed 'mv -fT -- "$FSTAB" "$FSTAB_FINAL"' "$KS_FILE" \
    "fstab publishes atomically"
assert_grep_fixed 'sync "$FSTAB_DIR"' "$KS_FILE" \
    "fstab rename is durable in its parent directory"
assert_grep_fixed 'MARKER_WORK=$(mktemp "$STATE_DIR/.mount-hardening-done.tmp.XXXXXX")' \
    "$KS_FILE" "completion marker is staged privately"
assert_grep_fixed 'sync "$MARKER_WORK"' "$KS_FILE" \
    "completion marker bytes and metadata are durable before rename"
assert_grep_fixed 'mv -fT -- "$MARKER_WORK" "$MARKER"' "$KS_FILE" \
    "completion marker publishes atomically"
assert_grep_fixed 'sync "$STATE_DIR"' "$KS_FILE" \
    "completion-marker rename is durable"
assert_grep_fixed 'permission itself' "$TMPDIR/22-disk-encryption.md" \
    "documentation distinguishes dm-crypt pass-through from discard generation"
assert_grep_fixed '| `/` | nodiscard |' "$TMPDIR/22-disk-encryption.md" \
    "mount-hardening table includes the root discard policy"
assert_grep_fixed '| `/home` | nosuid,nodev,nodiscard |' "$TMPDIR/22-disk-encryption.md" \
    "mount-hardening table includes home discard policy"
assert_grep_fixed 'Hibernate, hybrid sleep and suspend-then-hibernate are' \
    "$TMPDIR/22-disk-encryption.md" \
    "installed doc states the zram-only hibernation boundary"
assert_grep_fixed 'encrypted disk-backed swap/resume target' \
    "$TMPDIR/22-disk-encryption.md" \
    "installed doc states the explicit hibernation prerequisite"
assert_grep_fixed '128 MiB/s per-device limit' "$TMPDIR/22-disk-encryption.md" \
    "installed guide documents the scrub performance boundary"
assert_grep_fixed 'data uses `single`' "$TMPDIR/22-disk-encryption.md" \
    "installed guide does not overclaim single-device data repair"
assert_not_grep 'subvol=data' "$TMPDIR/22-disk-encryption.md" \
    "additional-drive example does not mount an uncreated subvolume"
assert_grep_fixed 'nosuid,nodev,noexec,nodiscard,nofail,x-systemd.device-timeout=10s  0 0' \
    "$TMPDIR/22-disk-encryption.md" \
    "optional Btrfs drive retains periodic-only discard and cannot break boot"
assert_grep_fixed '`nofail` must be present in both entries' \
    "$TMPDIR/22-disk-encryption.md" \
    "optional-drive guide explains both generated systemd dependencies"
assert_grep_fixed 'backup actually contains that keyslot' \
    "$TMPDIR/22-disk-encryption.md" \
    "recovery key is enrolled before its header backup"
assert_grep_fixed 'valid when that backup was created remains' \
    "$TMPDIR/22-disk-encryption.md" \
    "old-header backup credential persistence is disclosed"
assert_grep_fixed "sed -E 's|\\[.*\\]$||'" "$TMPDIR/22-disk-encryption.md" \
    "LUKS status command strips the Btrfs subvolume suffix"
sample_source=$(printf '%s\n' '/dev/mapper/luks-example[/root]' \
    | sed -E 's|\[.*\]$||')
sample_mapping=${sample_source#/dev/mapper/}
assert_eq 'luks-example' "$sample_mapping" \
    "documented LUKS status derivation resolves a Btrfs root mapping"
assert_cmd_success "live mount script syntax" bash -n "$TMPDIR/live-mount-script"
assert_grep_fixed 'ConditionKernelCommandLine=rd.live.image' \
    "$TMPDIR/noid-live-mount-hardening.service" \
    "live mount reconciler runs only on live media"
assert_grep_fixed '*" rd.live.image "*)' "$TMPDIR/live-mount-script" \
    "live script matches the complete kernel-command-line token"
assert_not_grep 'grep -qw rd.live.image' "$TMPDIR/live-mount-script" \
    "regex matching cannot misclassify a lookalike kernel argument"
assert_grep_fixed 'mount -o remount,nosuid,nodev,noexec "$mp"' "$TMPDIR/live-mount-script" \
    "live tmpfs mounts receive the documented flags"
assert_grep_fixed 'direct execution succeeded from $mp' "$TMPDIR/live-mount-script" \
    "live noexec policy is verified behaviorally"
COMPOSE_NOEXEC_PROBE="$TMPDIR/compose-noexec-probe.sh"
sed -n '/^NOEXEC_PROBE=""$/,/^for mp in \/tmp \/dev\/shm \/boot \/boot\/efi; do$/p' \
    "$KS_FILE" > "$COMPOSE_NOEXEC_PROBE"
for probe_script in "$COMPOSE_NOEXEC_PROBE" "$TMPDIR/live-mount-script"; do
    assert_grep_fixed 'trap cleanup_noexec_probe EXIT' "$probe_script" \
        "$(basename "$probe_script") cleans an interrupted noexec probe"
    assert_grep_fixed "trap 'exit 143' TERM" "$probe_script" \
        "$(basename "$probe_script") converts TERM into an EXIT-cleanup path"
    assert_not_grep 'rm -f.*NOEXEC_PROBE.*|| true' "$probe_script" \
        "$(basename "$probe_script") cannot hide noexec-probe cleanup failure"
done
assert_not_grep_extended "$mount_namespace_re" \
    "$TMPDIR/noid-live-mount-hardening.service" \
    "Live mount hardening remains in PID 1's mount namespace"
for directive in \
    NoNewPrivileges=yes \
    LockPersonality=yes \
    RestrictRealtime=yes \
    RestrictSUIDSGID=yes \
    SystemCallArchitectures=native \
    MemoryDenyWriteExecute=yes \
    IPAddressDeny=any \
    ProtectHome=yes \
    UMask=0077; do
    assert_grep_fixed "$directive" "$TMPDIR/btrfs-scrub.service" \
        "scrub sandbox retains live-probed directive $directive"
done
assert_not_grep '^PrivateDevices=yes$\|^ProtectSystem=\|^RestrictAddressFamilies=' \
    "$TMPDIR/btrfs-scrub.service" \
    "scrub sandbox does not hide devices/root or assume an unprobed socket family"
assert_grep_fixed 'ExecStart=/usr/libexec/noid-btrfs-scrub' \
    "$TMPDIR/btrfs-scrub.service" \
    "scrub service delegates to the resumable rate-limit wrapper"
assert_grep_fixed 'ExecCondition=/usr/bin/findmnt -n -M / -t btrfs' \
    "$TMPDIR/btrfs-scrub.service" \
    "non-Btrfs roots skip scrub before the helper and retry policy"
assert_grep_fixed 'without entering a failed or restart state' \
    "$TMPDIR/22-disk-encryption.md" \
    "disk guide documents the clean non-Btrfs scrub boundary"
assert_grep_fixed 'Restart=on-failure' "$TMPDIR/btrfs-scrub.service" \
    "interrupted scrub receives a bounded recovery attempt"
assert_grep_fixed 'RestartPreventExitStatus=3' "$TMPDIR/btrfs-scrub.service" \
    "uncorrectable scrub errors remain visible instead of looping"
assert_grep_fixed 'StateDirectory=noid-btrfs-scrub' \
    "$TMPDIR/btrfs-scrub.service" \
    "scrub recovery state has a systemd-owned private directory"
assert_grep_fixed 'StateDirectoryMode=0700' "$TMPDIR/btrfs-scrub.service" \
    "scrub recovery state is root-private"
assert_grep_fixed '"$BTRFS" scrub resume -B -d "$MOUNT"' \
    "$TMPDIR/noid-btrfs-scrub" \
    "saved scrub progress is resumed without an unsupported limit option"
assert_grep_fixed '2) apply_rate_limit ;;' \
    "$TMPDIR/noid-btrfs-scrub" \
    "an empty btrfs-progs 7.0 resume reapplies the scrub limit"
assert_grep_fixed "grep -Fq '2) apply_rate_limit ;;'" "$KS_FILE" \
    "M22 compose verification pins the empty-resume rate-limit repair"
assert_grep_fixed '"$BTRFS" scrub start -B -d --limit "$RATE_LIMIT" "$MOUNT"' \
    "$TMPDIR/noid-btrfs-scrub" \
    "new scrub retains the native per-device bandwidth cap"
assert_grep_fixed '"$BTRFS" scrub limit --devid "${DEVICE_IDS[$i]}"' \
    "$TMPDIR/noid-btrfs-scrub" \
    "every pre-existing device limit is restored"
assert_grep_fixed 'write_state 1 || fail "original device limits could not be committed"' \
    "$TMPDIR/noid-btrfs-scrub" \
    "original limits are durable before temporary mutation"
assert_grep_fixed 'recover_saved_state' "$TMPDIR/noid-btrfs-scrub" \
    "a restart recovers the saved transaction before scrub I/O"
assert_grep_fixed 'all M22 systemd units pass parser verification' "$KS_FILE" \
    "M22 compose verification includes the real systemd parser"
assert_grep_fixed 'btrfs scrub gate, resume, retry and per-device limit contracts verified' \
    "$KS_FILE" "M22 compose verification pins the scrub lifecycle contract"
assert_grep_fixed '[ -x /usr/local/bin/noid-live-mount-hardening.sh ]' "$KS_FILE" \
    "M22 verifies the live-media reconciler executable"
assert_grep_fixed '[ -L /etc/systemd/system/basic.target.wants/noid-live-mount-hardening.service ]' \
    "$KS_FILE" "M22 verifies live-media service enablement"
assert_not_grep 'restorecon.*2>/dev/null.*|| true' "$KS_FILE" \
    "M22 SELinux reconciliation cannot hide a failure"
assert_not_grep 'restorecon -R ' "$KS_FILE" \
    "M22 relabeling stays on exact regular files"
assert_grep_fixed 'SELinux label reconciliation failed' "$KS_FILE" \
    "M22 SELinux reconciliation is a build postcondition"

# Exercise the resumable scrub wrapper with a deterministic two-device mock.
# The fixture proves that a fresh run, a resumed run, an uncorrectable error,
# a partial limit-setup failure and a signal all restore the original limits.
SCRUB_MOCK="$TMPDIR/mock-btrfs"
SCRUB_LOG="$TMPDIR/mock-btrfs.log"
SCRUB_STATE="$TMPDIR/scrub-state"
SCRUB_UNDER_TEST="$TMPDIR/noid-btrfs-scrub-under-test"
mkdir -m 0700 "$SCRUB_STATE"
scrub_state_owner=$(stat -c '%U:%G' "$SCRUB_STATE")
sed \
    -e "s#^BTRFS=/usr/sbin/btrfs\$#BTRFS=$SCRUB_MOCK#" \
    -e "s#^STATE_DIR=/var/lib/noid-btrfs-scrub\$#STATE_DIR=$SCRUB_STATE#" \
    -e "s#root:root:700#$scrub_state_owner:700#g" \
    -e "s#root:root:600#$scrub_state_owner:600#g" \
    "$TMPDIR/noid-btrfs-scrub" > "$SCRUB_UNDER_TEST"
chmod 0700 "$SCRUB_UNDER_TEST"
cat > "$SCRUB_MOCK" <<'SCRUB_MOCK_EOF'
#!/bin/bash
set -eu
printf '%s\n' "$*" >> "$SCRUB_MOCK_LOG"
if [ "$1:$2:${3:-}" = "scrub:limit:--raw" ]; then
    cat <<'LIMITS'
UUID: 11111111-2222-4333-8444-555555555555
Id  Limit  Path
--  -----  ----
1   -      /dev/mock1
2   4096   /dev/mock2
LIMITS
    exit 0
fi
if [ "$1:$2" = "scrub:limit" ]; then
    if [ "$SCRUB_SCENARIO" = "limit_failure" ] && \
       [ "${4:-}" = "2" ] && [ "${6:-}" = "128M" ]; then
        exit 1
    fi
    if [ "$SCRUB_SCENARIO" = "restore_failure" ] && \
       [ "${4:-}" = "2" ] && [ "${6:-}" = "4096" ]; then
        exit 1
    fi
    exit 0
fi
if [ "$1:$2" = "scrub:resume" ]; then
    case "$SCRUB_SCENARIO" in
        fresh|uncorrectable|restore_failure) exit 2 ;;
        resume) exit 0 ;;
        interrupted)
            kill -TERM "$PPID"
            sleep 0.1
            exit 1
            ;;
    esac
fi
if [ "$1:$2" = "scrub:start" ]; then
    [ "$SCRUB_SCENARIO" != "uncorrectable" ] || exit 3
    exit 0
fi
exit 1
SCRUB_MOCK_EOF
chmod 0700 "$SCRUB_MOCK"

run_scrub_fixture() {
    local scenario="$1" expected_rc="$2" rc
    : > "$SCRUB_LOG"
    set +e
    SCRUB_SCENARIO="$scenario" SCRUB_MOCK_LOG="$SCRUB_LOG" \
        "$SCRUB_UNDER_TEST" >"$TMPDIR/scrub-${scenario}.out" 2>&1
    rc=$?
    set -e
    assert_eq "$expected_rc" "$rc" "scrub fixture $scenario exit status"
    assert_grep_fixed 'scrub limit --devid 1 --limit 0 /' "$SCRUB_LOG" \
        "scrub fixture $scenario restores the prior unlimited device"
    assert_grep_fixed 'scrub limit --devid 2 --limit 4096 /' "$SCRUB_LOG" \
        "scrub fixture $scenario restores the prior numeric device limit"
}

run_scrub_fixture fresh 0
assert_grep_fixed 'scrub resume -B -d /' "$SCRUB_LOG" \
    "fresh scrub checks for resumable progress first"
assert_grep_fixed 'scrub start -B -d --limit 128M /' "$SCRUB_LOG" \
    "fresh scrub starts with the native bandwidth cap"
if awk '
    $0 == "scrub resume -B -d /" { window=1; next }
    $0 == "scrub start -B -d --limit 128M /" { window=0 }
    window &&
        $0 == "scrub limit --devid 1 --limit 128M /" { device_1=1 }
    window &&
        $0 == "scrub limit --devid 2 --limit 128M /" { device_2=1 }
    END { exit !(device_1 && device_2) }
' "$SCRUB_LOG"; then
    _pass "fresh scrub reapplies every device limit after empty resume"
else
    _fail "fresh scrub did not reapply every device limit after empty resume"
fi

run_scrub_fixture resume 0
assert_not_grep 'scrub start ' "$SCRUB_LOG" \
    "successful resume does not restart completed work from zero"

run_scrub_fixture uncorrectable 3
assert_grep_fixed 'scrub start -B -d --limit 128M /' "$SCRUB_LOG" \
    "uncorrectable result still came from a rate-limited scrub"

run_scrub_fixture limit_failure 1
assert_not_grep 'scrub resume ' "$SCRUB_LOG" \
    "partial limit setup failure aborts before scrub I/O"

run_scrub_fixture interrupted 143
assert_not_grep 'scrub start ' "$SCRUB_LOG" \
    "signal interruption cannot continue into a fresh scrub"

run_scrub_fixture restore_failure 1
assert_file_exists "$SCRUB_STATE/limit-transaction" \
    "failed limit restore retains the original transaction"
assert_grep_fixed 'pending_rc=0' "$SCRUB_STATE/limit-transaction" \
    "saved transaction retains the completed scrub result"

run_scrub_fixture recovery 0
assert_not_grep 'scrub resume ' "$SCRUB_LOG" \
    "recovery-only restart does not resume scrub I/O"
assert_not_grep 'scrub start ' "$SCRUB_LOG" \
    "recovery-only restart does not start duplicate scrub I/O"
if [ ! -e "$SCRUB_STATE/limit-transaction" ] && \
   [ ! -L "$SCRUB_STATE/limit-transaction" ]; then
    _pass "successful recovery clears the saved limit transaction"
else
    _fail "successful recovery clears the saved limit transaction"
fi

# Exercise systemd's real [Install] parser in an isolated root. A fixed-string
# WantedBy assertion alone previously passed while M22/M99 checked the wrong
# multi-user.target symlink and aborted a canonical build.
SYSTEMD_ROOT="$TMPDIR/systemd-root"
mkdir -p "$SYSTEMD_ROOT/etc/systemd/system"
cp "$TMPDIR/noid-mount-hardening.service" "$SYSTEMD_ROOT/etc/systemd/system/"
assert_cmd_success "systemctl materializes the declared enablement link" \
    systemctl --root="$SYSTEMD_ROOT" enable noid-mount-hardening.service
if [ -L "$SYSTEMD_ROOT/etc/systemd/system/basic.target.wants/noid-mount-hardening.service" ]; then
    _pass "systemd enable creates basic.target.wants link"
else
    _fail "systemd enable did not create basic.target.wants link"
fi

# Extract the three helper functions. Use awk to grab everything between
# the function header and the matching `}`. This is approximate but
# works for the current M22 layout (top-level single-line-body `{ ... }`
# pattern would not; M22 uses multi-line bodies).
#
# We look for function declarations: `FOO() {` ... `}` at line-start.
# (M22's helpers are top-level, so their closing `}` is at column 1.)

extract_function() {
    local name="$1"
    local src="$2"
    awk -v n="$name" '
        $0 ~ "^" n "\\(\\) *\\{" { in_fn=1 }
        in_fn { print }
        in_fn && /^\}$/ { in_fn=0; exit }
    ' "$src"
}

{
    extract_function "append_fstab_opt" "$KS_FILE"
    echo ""
    extract_function "fstab_has_mountpoint" "$KS_FILE"
    echo ""
    extract_function "ensure_mount_options" "$KS_FILE"
    echo ""
    extract_function "verify_effective_opt" "$KS_FILE"
} > "$TMPDIR/helpers.sh"

if [ ! -s "$TMPDIR/helpers.sh" ]; then
    _fail "could not extract helper functions from $KS_FILE"
    test_finish
    exit 1
fi

# Sanity: extracted file must be syntactically valid shell
if ! bash -n "$TMPDIR/helpers.sh" 2>/dev/null; then
    _fail "extracted helpers have syntax errors (M22 snippet changed layout?)"
    test_finish
    exit 1
fi
_pass "extracted helpers parse ok"

# Sanity: helpers must reference the v3 sed delimiter fix (bash parameter
# expansion). If someone reverts to `sed -i -E "/${mnt_regex}/..."` this
# regresses.
if grep -q '${mnt_regex//\\//\\\\/}\|escaped_mnt' "$TMPDIR/helpers.sh" \
   || grep -q '${.*\/\/\\\/\\\\\/}' "$TMPDIR/helpers.sh" \
   || grep -qF 'escaped=${' "$TMPDIR/helpers.sh"; then
    _pass "v3 sed-delimiter fix present"
else
    _fail "v3 sed-delimiter fix (bash parameter expansion escape) missing"
fi

# --- 1. Build mock Anaconda-style fstab ------------------------------------

FSTAB="$TMPDIR/fstab"
cat > "$FSTAB" <<'EOF'
# /etc/fstab as written by Anaconda
UUID=11111111-1111-1111-1111-111111111111 /        btrfs subvol=root,compress=zstd:1,noatime 0 0
UUID=22222222-2222-2222-2222-222222222222 /home    btrfs subvol=home,compress=zstd:1,noatime 0 0
UUID=33333333-3333-3333-3333-333333333333 /tmp     ext4  defaults,x-systemd.growfs  0 0
tmpfs                                     /dev/shm tmpfs defaults                   0 0
UUID=44444444-4444-4444-4444-444444444444 /boot    ext4  defaults                   1 2
UUID=55555555-5555-5555-5555-555555555555 /boot/efi vfat umask=0077,shortname=winnt 0 2
EOF

# Source helpers into this shell so we can call them directly
# (FSTAB variable is picked up by their script, per M22 pattern).
# The helpers call `log "..."` — define a no-op to silence stderr.
log() { :; }
# CHANGED is set by the helpers; pre-init to avoid set -u trouble
# shellcheck disable=SC2034
CHANGED=0
export FSTAB
# shellcheck disable=SC1091
. "$TMPDIR/helpers.sh"

_pass "mock fstab built + helpers sourced"

assert_cmd_success "exact fstab target detector accepts /tmp" \
    fstab_has_mountpoint /tmp
assert_cmd_failure "exact fstab target detector rejects an inherited directory" \
    fstab_has_mountpoint /nonexistent

# findmnt does not print the negative/default Btrfs `nodiscard` token. Exercise
# the production verifier against the observable positive discard modes.
# shellcheck disable=SC2317,SC2329 # invoked indirectly by the sourced verifier.
findmnt() { printf '%s\n' "$FINDMNT_OPTIONS"; }
FINDMNT_OPTIONS='rw,relatime,ssd,space_cache=v2'
assert_cmd_success "effective nodiscard accepts absence of discard tokens" \
    verify_effective_opt / nodiscard
FINDMNT_OPTIONS='rw,relatime,discard'
assert_cmd_failure "effective nodiscard rejects discard" \
    verify_effective_opt / nodiscard
FINDMNT_OPTIONS='rw,relatime,discard=async'
assert_cmd_failure "effective nodiscard rejects discard=async" \
    verify_effective_opt /home nodiscard
FINDMNT_OPTIONS='rw,nosuid,nodev'
assert_cmd_success "ordinary positive mount option remains required" \
    verify_effective_opt /home nosuid
assert_cmd_failure "missing ordinary positive mount option still fails" \
    verify_effective_opt /home noexec
unset -f findmnt

# --- 2. Exercise ensure_mount_options for /tmp ------------------------------

# Exit early if ensure_mount_options isn't defined
if ! declare -F ensure_mount_options >/dev/null; then
    _fail "ensure_mount_options not defined after source (extraction failed)"
    test_finish
    exit 1
fi

# Exit codes under set -e: wrap each call so a failure is caught as failure,
# not as a test-harness abort.
for opt in nosuid noexec nodev; do
    if ensure_mount_options /tmp "$opt" 2>/dev/null; then
        _pass "ensure_mount_options /tmp $opt → success"
    else
        _fail "ensure_mount_options /tmp $opt → non-zero exit"
    fi
done

# --- 3. Verify each option is present on the /tmp line --------------------

for opt in nosuid noexec nodev; do
    # Match on the /tmp row (3rd UUID) — must contain the option as a
    # comma-list element (not as a substring of some other token).
    if awk '$2=="/tmp"' "$FSTAB" | grep -qE "(,|[[:space:]])${opt}(,|[[:space:]]|\$)"; then
        _pass "/tmp contains $opt in mount-opts field"
    else
        _fail "/tmp missing $opt in mount-opts field (fstab line: $(awk '$2=="/tmp"' "$FSTAB"))"
    fi
done

# --- 4. Idempotency: re-running must not duplicate ---------------------------

for opt in nosuid noexec nodev; do
    ensure_mount_options /tmp "$opt" 2>/dev/null || true
done

# No option should appear twice on the /tmp line
dups=0
for opt in nosuid noexec nodev; do
    count=$(awk '$2=="/tmp"' "$FSTAB" | grep -oE "\\b${opt}\\b" | wc -l || true)
    if [ "$count" -gt 1 ]; then
        dups=$((dups + 1))
        _fail "idempotency: $opt appears $count times on /tmp line (expected 1)"
    fi
done
if [ "$dups" -eq 0 ]; then
    _pass "idempotency: no option duplicated on /tmp line after second run"
fi

# --- 5. Edge case: mountpoint not in fstab ---------------------------------

# /nonexistent is NOT in the mock fstab. ensure_mount_options must handle
# this gracefully: return 0 (no fatal error, "skipping" is the intentional
# semantic) AND NOT modify the fstab file.
fstab_before=$(sha256sum "$FSTAB" | awk '{print $1}')
set +e
ensure_mount_options /nonexistent nosuid 2>/dev/null
rc=$?
set -e
fstab_after=$(sha256sum "$FSTAB" | awk '{print $1}')

if [ "$rc" -eq 0 ]; then
    _pass "absent-mountpoint: returned 0 cleanly (graceful skip)"
else
    _fail "absent-mountpoint: unexpectedly returned non-zero (rc=$rc)"
fi

if [ "$fstab_before" = "$fstab_after" ]; then
    _pass "absent-mountpoint: fstab unchanged (no corruption)"
else
    _fail "absent-mountpoint: fstab was modified despite mountpoint missing"
fi

# Exercise the production runtime loop against a valid layout without separate
# /home, /boot or /boot/efi mounts. Only targets present in fstab may reach
# findmnt/mount; inherited directories must be skipped cleanly.
RUNTIME_LOOP="$TMPDIR/runtime-mount-loop"
awk '
    /^for mp in \/ \/var \/var\/tmp \/tmp \/dev\/shm \/home \/boot \/boot\/efi; do$/ {
        in_loop=1
    }
    in_loop { print }
    in_loop && /^done$/ { exit }
' "$TMPDIR/mount-hardening.sh" > "$RUNTIME_LOOP"
if [ -s "$RUNTIME_LOOP" ]; then
    _pass "runtime mount loop extracted"
else
    _fail "runtime mount loop extracted"
fi

RUNTIME_FSTAB="$TMPDIR/runtime-fstab"
cat > "$RUNTIME_FSTAB" <<'RUNTIME_FSTAB_EOF'
tmpfs /        tmpfs defaults 0 0
/var  /var     none  bind,nosuid,nodev,private 0 0
/var/tmp /var/tmp none bind,nosuid,nodev 0 0
tmpfs /tmp     tmpfs defaults,nosuid,nodev,noexec 0 0
tmpfs /dev/shm tmpfs defaults,nosuid,nodev,noexec 0 0
RUNTIME_FSTAB_EOF
RUNTIME_CALLS="$TMPDIR/runtime-mount-calls"
{
    cat <<'RUNTIME_HARNESS_HEAD'
#!/bin/bash
set -euo pipefail
FSTAB=$1
MOUNT_CALLS=$2
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
log() { :; }
findmnt() {
    /usr/bin/awk -v mp="${3-}" '$1 !~ /^#/ && $2 == mp { found=1 } END { exit !found }' "$FSTAB"
}
mount() { printf '%s\n' "$*" >> "$MOUNT_CALLS"; }
RUNTIME_HARNESS_HEAD
    extract_function "fstab_has_mountpoint" "$KS_FILE"
    cat "$RUNTIME_LOOP"
} > "$TMPDIR/runtime-mount-harness.sh"
assert_cmd_success "runtime loop harness parses" \
    bash -n "$TMPDIR/runtime-mount-harness.sh"
assert_cmd_success "runtime loop accepts inherited home and boot directories" \
    bash "$TMPDIR/runtime-mount-harness.sh" "$RUNTIME_FSTAB" "$RUNTIME_CALLS"
runtime_call_count=$(wc -l < "$RUNTIME_CALLS")
assert_eq "5" "$runtime_call_count" \
    "runtime loop touches only the five distinct fixture mounts"
assert_not_grep_extended ' /home$| /boot$| /boot/efi$' "$RUNTIME_CALLS" \
    "runtime loop never mounts absent optional targets"
assert_grep_fixed '-o remount,nodiscard /' "$RUNTIME_CALLS" \
    "runtime loop still reconciles the present root target"

# --- 6. The /dev/shm line (tmpfs) must also be patchable --------------------

ensure_mount_options /dev/shm noexec 2>/dev/null || true
ensure_mount_options /dev/shm nosuid 2>/dev/null || true
ensure_mount_options /dev/shm nodev  2>/dev/null || true

for opt in noexec nosuid nodev; do
    if awk '$2=="/dev/shm"' "$FSTAB" | grep -qE "(,|[[:space:]])${opt}(,|[[:space:]]|\$)"; then
        _pass "/dev/shm contains $opt"
    else
        _fail "/dev/shm missing $opt (line: $(awk '$2=="/dev/shm"' "$FSTAB"))"
    fi
done

# --- 7. Exercise the complete durable fstab transaction --------------------

awk '
    /^FSTAB_FINAL=/ { in_tx=1 }
    in_tx { print }
    in_tx && /^trap - EXIT HUP INT TERM$/ { exit }
' "$TMPDIR/mount-hardening.sh" \
    | sed 's#FSTAB_FINAL="/etc/fstab"#FSTAB_FINAL="$TX_FSTAB"#' \
    > "$TMPDIR/fstab-transaction.body"

{
    cat <<'HARNESS_HEAD'
#!/bin/bash
set -euo pipefail
log() { :; }
chown() { :; }
restorecon() { :; }
sync() {
    if [ "${FAIL_FSTAB_SYNC:-0}" = 1 ] && \
       [[ "${1:-}" == */.noid-fstab.* ]]; then
        return 1
    fi
    /usr/bin/sync "$@"
}
HARNESS_HEAD
    cat "$TMPDIR/fstab-transaction.body"
} > "$TMPDIR/fstab-transaction.sh"
chmod 0700 "$TMPDIR/fstab-transaction.sh"
assert_cmd_success "complete fstab transaction harness parses" \
    bash -n "$TMPDIR/fstab-transaction.sh"

write_transaction_fstab() {
    cat > "$1" <<'FSTAB_EOF'
tmpfs /         tmpfs defaults 0 0
tmpfs /home     tmpfs defaults 0 0
none  /tmp      tmpfs defaults 0 0
tmpfs /dev/shm  tmpfs defaults 0 0
tmpfs /boot     tmpfs defaults 0 0
tmpfs /boot/efi tmpfs defaults 0 0
FSTAB_EOF
}

TX_FSTAB="$TMPDIR/transaction-fstab"
write_transaction_fstab "$TX_FSTAB"
if TX_FSTAB="$TX_FSTAB" bash "$TMPDIR/fstab-transaction.sh" \
        >"$TMPDIR/fstab-transaction.out" 2>&1; then
    _pass "complete fstab transaction publishes a validated candidate"
else
    sed 's/^/    | /' "$TMPDIR/fstab-transaction.out" >&2
    _fail "complete fstab transaction publishes a validated candidate"
fi
tmp_rows=$(awk '$2=="/tmp" {count++} END {print count+0}' "$TX_FSTAB")
assert_eq "1" "$tmp_rows" \
    "custom noncanonical /tmp remains one target after the complete transaction"
for opt in nosuid nodev noexec; do
    if awk '$2=="/tmp" {print $4}' "$TX_FSTAB" | tr ',' '\n' | grep -qx "$opt"; then
        _pass "complete transaction hardens custom /tmp with $opt"
    else
        _fail "complete transaction hardens custom /tmp with $opt"
    fi
done

write_transaction_fstab "$TX_FSTAB"
tx_before=$(sha256sum "$TX_FSTAB" | awk '{print $1}')
if FAIL_FSTAB_SYNC=1 TX_FSTAB="$TX_FSTAB" \
        bash "$TMPDIR/fstab-transaction.sh" \
        >"$TMPDIR/fstab-sync-failure.out" 2>&1; then
    _fail "candidate-file sync failure aborts publication"
else
    _pass "candidate-file sync failure aborts publication"
fi
tx_after=$(sha256sum "$TX_FSTAB" | awk '{print $1}')
assert_eq "$tx_before" "$tx_after" \
    "sync failure leaves the original fstab byte-identical"
if compgen -G "$TMPDIR/.noid-fstab.*" >/dev/null; then
    _fail "sync failure cleans the private fstab transaction file"
else
    _pass "sync failure cleans the private fstab transaction file"
fi

# --- finalize --------------------------------------------------------------

test_finish

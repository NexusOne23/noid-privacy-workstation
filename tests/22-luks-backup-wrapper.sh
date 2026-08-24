#!/bin/bash
# 22-luks-backup-wrapper — opt-in LUKS backup helper regression test
#
# Covers: noid-luks-backup.sh heredoc shipped by Module 22 Step 3b, including
# refuse-root pattern, LUKS2 partition auto-detect via lsblk, removable-media
# auto-detect via /run/media, default filename convention, SHA256 verification,
# --verify + --list-existing modes, return-to-menu prompt, M22 verify checks.
#
# Would catch: helper deleted, refuse-root stripped, detection regex broken,
# filename convention changed, return-to-menu pattern missing, or a partial /
# unverifiable artifact being reported as a completed backup.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/22-luks-partitioning.ks"

test_start "22-luks-backup-wrapper"

assert_file_exists "$KS_FILE"
assert_cmd_success "bash -n $KS_FILE" bash -n "$KS_FILE"

# --- Heredoc presence + script path ----------------------------------------
assert_grep_fixed "cat > /usr/local/bin/noid-luks-backup.sh <<'LUKS_BACKUP_EOF'" "$KS_FILE"
assert_grep_fixed 'LUKS_BACKUP_EOF' "$KS_FILE"
assert_grep_fixed 'chmod 0755 /usr/local/bin/noid-luks-backup.sh' "$KS_FILE"

# --- Extract heredoc + syntax-check extracted script -----------------------
TMP_SCRIPT="$(mktemp --suffix=.sh)"
TX_HARNESS="${TMP_SCRIPT}.transaction"
TOPO_HARNESS="${TMP_SCRIPT}.topology"
TX_FIXTURE="$(mktemp -d)"
trap 'rm -f "$TMP_SCRIPT" "$TX_HARNESS" "$TOPO_HARNESS"; rm -rf "$TX_FIXTURE"' EXIT
extract_heredoc "$KS_FILE" "LUKS_BACKUP_EOF" "$TMP_SCRIPT"
assert_cmd_success "extracted LUKS backup script parses (bash -n)" bash -n "$TMP_SCRIPT"

# --- Refuse-root pattern (mirrors noid-complete-setup.sh) ------------------
assert_grep_fixed 'if [ "$(id -u)" -eq 0 ]; then' "$TMP_SCRIPT"
assert_grep_fixed 'do not run as root' "$TMP_SCRIPT"

# --- Shared guided terminal presentation ----------------------------------
assert_grep_fixed 'FMT_LIB=/usr/local/lib/noid-privacy/agent-install-format.sh' \
    "$TMP_SCRIPT" "LUKS helper shares the Setup installer presentation"
assert_grep_fixed 'fmt_banner "NoID Privacy LUKS Header Backup"' "$TMP_SCRIPT" \
    "every LUKS mode has the common Setup identity"
for phase in \
    'fmt_step 1 4 "Detect encrypted volumes"' \
    'fmt_step 2 4 "Select verified removable media"' \
    'fmt_step 3 4 "Create private header backup"' \
    'fmt_step 4 4 "Verify + record backup evidence"'; do
    assert_grep_fixed "$phase" "$TMP_SCRIPT" \
        "LUKS backup exposes guided phase: $phase"
done
assert_grep_fixed 'fmt_done "LUKS header backup complete"' "$TMP_SCRIPT" \
    "LUKS backup ends with a concise verified summary"

# --- Return-to-menu pattern (unified) -----------------------------
assert_grep_fixed 'return_to_menu_prompt()' "$TMP_SCRIPT"
assert_grep_fixed 'Re-open welcome menu? [Y/n]' "$TMP_SCRIPT"
assert_grep_fixed 'noid-welcome.sh --again' "$TMP_SCRIPT"
assert_grep_fixed 'NOID_WELCOME_SPAWN' "$TMP_SCRIPT" \
    "welcome-spawned runs skip the standalone hold (wrapper owns the prompt)"

# --- Mode/flag parsing -----------------------------------------------------
assert_grep_fixed '--list-existing' "$TMP_SCRIPT"
assert_grep_fixed '--verify' "$TMP_SCRIPT"
assert_grep_fixed '1:--help|1:-h)' "$TMP_SCRIPT"
assert_grep_fixed 'case "$#:${1:-}" in' "$TMP_SCRIPT" \
    "argument arity is part of mode selection"
assert_grep_fixed '2:--verify) MODE="verify"; VERIFY_FILE="$2" ;;' "$TMP_SCRIPT"
assert_grep_fixed '2:--expert-target) EXPERT_TARGET="$2" ;;' "$TMP_SCRIPT"
assert_grep_fixed 'Automatic backups require per-file POSIX ownership and modes' \
    "$TMP_SCRIPT" "help discloses the secure staging filesystem contract"
assert_grep_fixed 'typical FAT32/exFAT desktop mounts are unsupported' \
    "$TMP_SCRIPT" "failure output gives an actionable filesystem diagnosis"
assert_grep_fixed 'Reformatting erases data.' \
    "$TMP_SCRIPT" "filesystem recovery guidance carries its destructive warning"

# --- LUKS partition detection via lsblk ------------------------------------
# Filter no longer requires TYPE=part (covers LUKS-on-LVM + LUKS-on-RAID)
assert_grep_fixed 'detect_luks_partitions()' "$TMP_SCRIPT"
assert_grep_fixed 'crypto_LUKS' "$TMP_SCRIPT"
assert_grep_fixed 'lsblk -rpno NAME,FSTYPE,TYPE,SIZE' "$TMP_SCRIPT" \
    "lsblk supplies canonical full paths for partitions, LVM and multipath"
# Filter matches any crypto_LUKS container regardless of TYPE.
# Assert the active awk filter (uncommented line containing the awk call) uses
# the broad form, not TYPE=part. Match the exact shell text of the awk filter.
assert_grep_fixed 'awk '\''$2 == "crypto_LUKS" { print $1, $4 }'\''' "$TMP_SCRIPT" \
    "awk filter matches crypto_LUKS (any TYPE, covers LVM/RAID)"
# Ensure the OLD restrictive filter is absent in active code (comments OK):
# the active filter line must not contain '&& $3 == "part"' anymore.
if awk '!/^[[:space:]]*#/ && /\$3 == "part"/ { found = 1 } END { exit !found }' \
        "$TMP_SCRIPT"; then
    _fail "restrictive TYPE=part filter still in active code"
else
    _pass "restrictive TYPE=part filter removed from active code"
fi

# --- Removable-media detection via /run/media -----------------------------
# Use id -un fallback for $USER (robust under su/cron/systemd-run)
assert_grep_fixed 'detect_removable_mounts()' "$TMP_SCRIPT"
assert_grep_fixed '/run/media/$whoami_user' "$TMP_SCRIPT"
assert_grep_fixed '${USER:-$(id -un)}' "$TMP_SCRIPT"
assert_grep_fixed 'findmnt -rn -T "$MOUNT_CANONICAL" -o TARGET' "$TMP_SCRIPT"
assert_grep_fixed 'lsblk -srpno NAME,TYPE,RM,TRAN "$MOUNT_SOURCE"' "$TMP_SCRIPT"
assert_grep_fixed 'grep -Fxq -- "$target_disk"' "$TMP_SCRIPT" \
    "target and source physical-disk sets are compared"
assert_grep_fixed 'USE UNVERIFIED TARGET' "$TMP_SCRIPT" \
    "expert override requires an exact risk acknowledgement"

# Exercise the topology classifier independently of the interactive UI.
sed -n \
    '/^# BEGIN LUKS_REMOVABLE_TOPOLOGY_FUNCTIONS$/,/^# END LUKS_REMOVABLE_TOPOLOGY_FUNCTIONS$/p' \
    "$TMP_SCRIPT" > "$TOPO_HARNESS"
# shellcheck source=/dev/null
. "$TOPO_HARNESS"

TOPO_ROOT="$TX_FIXTURE/topology"
TOPO_TARGET="$TOPO_ROOT/removable media"
mkdir -p "$TOPO_TARGET"
TOPO_SCENARIO="verified_usb"

findmnt() {
    local candidate="" output=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            -T) candidate="$2"; shift 2 ;;
            -o) output="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    case "$output" in
        TARGET)
            if [ "$TOPO_SCENARIO" = "ordinary_directory" ]; then
                printf '%s\n' "$TOPO_ROOT"
            else
                printf '%s\n' "$candidate"
            fi
            ;;
        SOURCE)
            case "$TOPO_SCENARIO" in
                verified_usb|same_disk) printf '%s\n' /dev/mock-usb1 ;;
                removable_rm) printf '%s\n' /dev/mock-sd1 ;;
                *) printf '%s\n' /dev/mock-internal1 ;;
            esac
            ;;
        *) return 1 ;;
    esac
}

lsblk() {
    local device="${!#}"
    [ "$TOPO_SCENARIO" != "non_block_source" ] || return 1
    case "$device:$TOPO_SCENARIO" in
        /dev/mock-usb1:same_disk)
            printf '%s\n' '/dev/mock-usb1 part 0' '/dev/sda disk 0 usb'
            ;;
        /dev/mock-usb1:mixed_target)
            printf '%s\n' '/dev/mock-usb1 part 0' \
                '/dev/sdb disk 0 usb' '/dev/nvme1n1 disk 0 nvme'
            ;;
        /dev/mock-usb1:*)
            printf '%s\n' '/dev/mock-usb1 part 0' '/dev/sdb disk 0 usb'
            ;;
        /dev/mock-sd1:*)
            printf '%s\n' '/dev/mock-sd1 part 1' '/dev/mmcblk0 disk 1'
            ;;
        /dev/mock-internal1:*)
            printf '%s\n' '/dev/mock-internal1 part 0' '/dev/nvme0n1 disk 0 nvme'
            ;;
        /dev/mock-luks:same_disk)
            printf '%s\n' '/dev/mock-luks part' '/dev/sda disk'
            ;;
        /dev/mock-luks:*)
            printf '%s\n' '/dev/mock-luks part' '/dev/nvme0n1 disk'
            ;;
        *) return 1 ;;
    esac
}

TOPO_SCENARIO="verified_usb"
if is_verified_removable_mount "$TOPO_TARGET" /dev/mock-luks; then
    _pass "USB topology on a different physical disk is accepted"
else
    _fail "USB topology on a different physical disk is accepted"
fi
TOPO_SCENARIO="removable_rm"
if is_verified_removable_mount "$TOPO_TARGET" /dev/mock-luks; then
    _pass "RM=1 topology is accepted without a transport string"
else
    _fail "RM=1 topology is accepted without a transport string"
fi
TOPO_SCENARIO="ordinary_directory"
if is_verified_removable_mount "$TOPO_TARGET" /dev/mock-luks; then
    _fail "ordinary directory beneath a mount is rejected"
else
    _pass "ordinary directory beneath a mount is rejected"
fi
TOPO_SCENARIO="internal_disk"
if is_verified_removable_mount "$TOPO_TARGET" /dev/mock-luks; then
    _fail "internal non-removable topology is rejected"
else
    _pass "internal non-removable topology is rejected"
fi
TOPO_SCENARIO="mixed_target"
if is_verified_removable_mount "$TOPO_TARGET" /dev/mock-luks; then
    _fail "composite target with an internal member is rejected"
else
    _pass "composite target with an internal member is rejected"
fi
TOPO_SCENARIO="same_disk"
if is_verified_removable_mount "$TOPO_TARGET" /dev/mock-luks; then
    _fail "target on the source physical disk is rejected"
else
    _pass "target on the source physical disk is rejected"
fi
TOPO_SCENARIO="non_block_source"
if inspect_block_mount "$TOPO_TARGET"; then
    _fail "mount without a resolvable block topology is rejected"
else
    _pass "mount without a resolvable block topology is rejected"
fi
TOPO_SCENARIO="internal_disk"
if inspect_block_mount "$TOPO_TARGET"; then
    _pass "expert path still requires a real block-backed mountpoint"
else
    _fail "expert path still requires a real block-backed mountpoint"
fi

# --- Default filename convention (no machine identifier on removable media)
assert_grep_fixed 'BACKUP_NAME="luks-header-$(date -u +%Y%m%dT%H%M%SZ).bin"' \
    "$TMP_SCRIPT" "filename uses a UTC timestamp and confirms collisions"
assert_not_grep 'host_sanitized\|\$(hostname' "$TMP_SCRIPT" \
    "backup filename contains no hostname"

# --- Core cryptsetup call --------------------------------------------------
assert_grep_fixed 'cryptsetup luksHeaderBackup' "$TMP_SCRIPT"
assert_grep_fixed 'luksDump' "$TMP_SCRIPT"

# --- Post-backup: chown + chmod 0600 (backup file is sensitive) ------------
# Use id -un/id -gn for $USER/$GROUP robustness (su/cron/systemd-run safe)
assert_grep_fixed 'chown "$(id -un):$(id -gn)"' "$TMP_SCRIPT"
assert_grep_fixed 'chmod 0600' "$TMP_SCRIPT"

# --- Transactional postconditions -----------------------------------------
assert_grep_fixed 'perform_backup_transaction()' "$TMP_SCRIPT"
assert_grep_fixed 'prepare_backup_stage "$backup_path"' "$TMP_SCRIPT"
assert_grep_fixed "'.noid-luks-backup.XXXXXXXX'" "$TMP_SCRIPT"
assert_grep_fixed 'BACKUP_PARENT_HANDLE="/proc/$$/fd/$BACKUP_PARENT_FD"' \
    "$TMP_SCRIPT" "the selected removable mount is pinned by an open handle"
assert_grep_fixed 'BACKUP_STAGE_HANDLE="/proc/$$/fd/$BACKUP_STAGE_FD"' \
    "$TMP_SCRIPT" "privileged staging I/O is relative to a pinned directory"
assert_grep_fixed 'stage_meta" != "root:root:700"' "$TMP_SCRIPT"
assert_grep_fixed 'published_sha_line=$(sha256sum -- "$BACKUP_PUBLISH_PATH")' \
    "$TMP_SCRIPT" "published-file verification is unprivileged"
assert_not_grep 'sudo sha256sum -- "$BACKUP_PUBLISH_PATH"' "$TMP_SCRIPT" \
    "a replaced published path is never hashed through sudo"
assert_grep_fixed 'cryptsetup luksDump "$BACKUP_PUBLISH_PATH"' "$TMP_SCRIPT"
assert_grep_fixed 'sudo mv -nT -- "$BACKUP_WORK_PATH" "$BACKUP_PUBLISH_PATH"' \
    "$TMP_SCRIPT" "publication stays inside the pinned removable mount"
assert_grep_fixed 'sudo mv -nT -- "$path" "$quarantine_path"' "$TMP_SCRIPT" \
    "quarantine never overwrites an earlier failed artifact"
assert_grep_fixed 'quarantine_published_artifact()' "$TMP_SCRIPT" \
    "published quarantine is bound to the staged inode"
assert_grep_fixed 'mv -nT -- "$BACKUP_PUBLISH_PATH" "$quarantine_path"' \
    "$TMP_SCRIPT" "published quarantine remains unprivileged"
assert_grep_fixed 'sudo sync "$BACKUP_WORK_PATH"' "$TMP_SCRIPT" \
    "verified staging bytes are synchronized before publication"
assert_grep_fixed 'sync "$BACKUP_PUBLISH_PATH"' "$TMP_SCRIPT" \
    "published backup bytes and metadata are synchronized"
assert_grep_fixed 'sync "$BACKUP_PARENT_HANDLE"' "$TMP_SCRIPT" \
    "destination rename is synchronized through the exact parent directory"
assert_not_grep 'Overwrite?' "$TMP_SCRIPT" \
    "the privileged backup path never overwrites an existing destination"
assert_grep_fixed 'if ! commit_success_log "$timestamp" "$sha"; then' "$TMP_SCRIPT"
assert_grep_fixed 'if ! perform_backup_transaction "$luks_dev" "$BACKUP_PATH"; then' \
    "$TMP_SCRIPT"
assert_not_grep 'sudo tee -a /var/lib/noid-privacy/luks-backup.log' "$TMP_SCRIPT" \
    "success evidence is never appended before atomic verification completes"

# --- Success flag for gap-detection (log append) ---------------------------
assert_grep_fixed '/var/lib/noid-privacy/luks-backup.log' "$TMP_SCRIPT"
# Store only the two fields consumed by noid-status. Persisting the source
# device and removable-media label would expose unnecessary local metadata.
assert_grep_extended "printf '%s\\\\t%s\\\\n'" "$TMP_SCRIPT" \
    "luks-backup.log stores only timestamp and hash"
assert_not_grep '"$luks_dev" "$BACKUP_PATH" "$sha"' "$TMP_SCRIPT" \
    "luks-backup.log omits device and removable-media identifiers"
assert_grep_fixed 'chown root:wheel "$tmp"' "$TMP_SCRIPT"
assert_grep_fixed 'chmod 0640 "$tmp"' "$TMP_SCRIPT"
assert_grep_fixed 'mv -fT -- "$tmp" "$log_file"' "$TMP_SCRIPT"
assert_grep_fixed 'sync "$log_file"' "$TMP_SCRIPT" \
    "success evidence is durable before the helper reports completion"
assert_grep_fixed 'sync "$(dirname -- "$log_file")"' "$TMP_SCRIPT" \
    "success-log rename is durable in its parent directory"
assert_grep_fixed '[ -L "$VERIFY_FILE" ]' "$TMP_SCRIPT" \
    "verify mode rejects symlink inputs"
assert_grep_fixed 'VERIFY_CANONICAL=$(readlink -e -- "$VERIFY_FILE")' "$TMP_SCRIPT" \
    "verify mode canonicalizes to an absolute non-option path"
assert_grep_fixed 'cryptsetup luksDump "$VERIFY_FILE"' "$TMP_SCRIPT" \
    "verify mode parses only a file readable by the invoking user"
assert_not_grep 'sudo cryptsetup luksDump "$VERIFY_FILE"' "$TMP_SCRIPT" \
    "verify mode is not a root-file confused deputy"
assert_not_grep_extended '^[[:space:]]*read -rp .* (ans|choice|_ans)$' "$TMP_SCRIPT" \
    "EOF cannot bypass the helper's explicit prompt defaults"
assert_grep_fixed 'trap backup_transaction_exit_cleanup EXIT' "$TMP_SCRIPT" \
    "one persistent EXIT trap owns interrupted-transaction cleanup"
assert_grep_fixed "trap 'exit 143' TERM" "$TMP_SCRIPT" \
    "TERM is converted into the EXIT cleanup path"

# --- Mocked transaction failure matrix ------------------------------------
# Source only the marked, side-effect-free function block. The sudo and
# cryptsetup mocks below make every postcondition independently testable
# without a real encrypted device, removable disk or root privilege.
sed -n \
    '/^# BEGIN LUKS_BACKUP_TRANSACTION_FUNCTIONS$/,/^# END LUKS_BACKUP_TRANSACTION_FUNCTIONS$/p' \
    "$TMP_SCRIPT" > "$TX_HARNESS"
# shellcheck source=/dev/null
. "$TX_HARNESS"

# shellcheck disable=SC2034 # consumed by functions sourced from TX_HARNESS
RED=""
# shellcheck disable=SC2034 # consumed by functions sourced from TX_HARNESS
NC=""
SCENARIO="success"
LOG_CALLS=0
TX_PATH="$TX_FIXTURE/luks-header-test.bin"
RMDIR_FAIL_MARKER="$TX_FIXTURE/rmdir-failed-once"
PUBLISHED_SWAP_MARKER="$TX_FIXTURE/published-path-swapped"
PUBLISHED_SWAP_ORIGINAL="$TX_FIXTURE/published-original.bin"
SWAP_VICTIM="$TX_FIXTURE/stage-swap-victim"
mkdir -p "$SWAP_VICTIM"

sudo() {
    local cmd="$1"
    shift
    if [ "$cmd" = "cryptsetup" ]; then
        case "$1" in
            luksHeaderBackup)
                if [ "$SCENARIO" = "stage_handle_swap" ]; then
                    local moved_stage="${BACKUP_STAGE_DIR}.moved"
                    mv -- "$BACKUP_STAGE_DIR" "$moved_stage"
                    ln -s -- "$SWAP_VICTIM" "$BACKUP_STAGE_DIR"
                    truncate -s 2097152 "$4"
                    rm -f -- "$BACKUP_STAGE_DIR"
                    mv -- "$moved_stage" "$BACKUP_STAGE_DIR"
                    return 0
                fi
                truncate -s 2097152 "$4"
                [ "$SCENARIO" != "backup_fail" ]
                return
                ;;
            luksDump)
                [ "$SCENARIO" != "parse_fail" ]
                return
                ;;
        esac
    fi
    if [ "$cmd" = "chown" ] && [ "${1:-}" = "root:root" ] && \
       [ -d "${2:-}" ]; then
        return 0
    fi
    if [ "$cmd" = "stat" ]; then
        local last="${!#}"
        if [ -d "$last" ] && \
           [ "$last" = "${BACKUP_STAGE_HANDLE:-}" ]; then
            if [ "$SCENARIO" = "stage_meta_fail" ]; then
                printf '%s\n' 'root:root:755'
            else
                printf '%s\n' 'root:root:700'
            fi
            return 0
        fi
        if [ "$SCENARIO" = "stat_fail" ] && [ "${1:-}" = "-c" ] && \
           [ "${2:-}" = "%s" ]; then
            return 1
        fi
    fi
    if [ "$cmd" = "sha256sum" ] && [ "$SCENARIO" = "sha_fail" ]; then
        return 1
    fi
    if [ "$cmd" = "sync" ]; then
        if [ "$SCENARIO" = "stage_sync_fail" ]; then
            return 1
        fi
        if [ "$SCENARIO" = "parent_sync_fail" ] && [ -d "${1:-}" ]; then
            return 1
        fi
    fi
    if [ "$cmd" = "rmdir" ] && [ "$SCENARIO" = "cleanup_fail" ]; then
        if [ ! -e "$RMDIR_FAIL_MARKER" ]; then
            : > "$RMDIR_FAIL_MARKER"
            return 1
        fi
    fi
    if [ "$cmd" = "mv" ] && [ "$SCENARIO" = "publish_collision" ] && \
       [ "${1:-}" = "-nT" ] && [[ "${4:-}" != *.FAILED-* ]]; then
        printf '%s\n' collision > "$4"
    fi
    command "$cmd" "$@"
}

cryptsetup() {
    [ "${1:-}" = "luksDump" ]
}

sha256sum() {
    local last="${!#}"
    if [ "$SCENARIO" = "published_path_swap" ] && \
       [ "$last" = "${BACKUP_PUBLISH_PATH:-}" ] && \
       [ ! -e "$PUBLISHED_SWAP_MARKER" ]; then
        mv -- "$last" "$PUBLISHED_SWAP_ORIGINAL"
        printf '%s\n' replacement > "$last"
        truncate -s 2097152 "$last"
        chmod 0600 "$last"
        : > "$PUBLISHED_SWAP_MARKER"
    fi
    command sha256sum "$@"
}

sync() {
    if [ "$SCENARIO" = "parent_sync_fail" ] && [ -d "${1:-}" ]; then
        return 1
    fi
    command sync "$@"
}

commit_success_log() {
    LOG_CALLS=$((LOG_CALLS + 1))
    [ "$SCENARIO" != "log_fail" ]
}

reset_transaction_fixture() {
    close_backup_handles 2>/dev/null || true
    rm -f "$TX_PATH" "${TX_PATH}.FAILED-"* "$RMDIR_FAIL_MARKER" \
        "$PUBLISHED_SWAP_MARKER" "$PUBLISHED_SWAP_ORIGINAL"
    LOG_CALLS=0
    VERIFIED_SHA=""
    VERIFIED_SIZE=""
    # shellcheck disable=SC2034 # reset for the sourced transaction function
    FAILED_BACKUP_PATH=""
    # shellcheck disable=SC2034 # reset for the sourced transaction function
    BACKUP_STAGE_DIR=""
    # shellcheck disable=SC2034 # reset for the sourced transaction function
    BACKUP_WORK_PATH=""
    # shellcheck disable=SC2034 # reset for the sourced transaction function
    BACKUP_STAGE_HANDLE=""
    # shellcheck disable=SC2034 # reset for the sourced transaction function
    BACKUP_PARENT_HANDLE=""
    # shellcheck disable=SC2034 # reset for the sourced transaction function
    BACKUP_PUBLISH_PATH=""
    # shellcheck disable=SC2034 # reset for the sourced transaction function
    BACKUP_STAGE_FD=""
    # shellcheck disable=SC2034 # reset for the sourced transaction function
    BACKUP_PARENT_FD=""
    # shellcheck disable=SC2034 # reset for the sourced transaction function
    BACKUP_TRANSACTION_ACTIVE=0
    # shellcheck disable=SC2034 # reset for the sourced transaction function
    BACKUP_DISPLAY_PATH=""
    # shellcheck disable=SC2034 # reset for the sourced transaction function
    BACKUP_STAGED_IDENTITY=""
    # shellcheck disable=SC2034 # reset for the sourced transaction function
    BACKUP_ARTIFACT_VERIFIED=0
}

assert_no_private_stage() {
    if compgen -G "$TX_FIXTURE/.noid-luks-backup.*" >/dev/null; then
        _fail "$1 leaves no private staging directory"
    else
        _pass "$1 leaves no private staging directory"
    fi
}

assert_quarantined_failure() {
    local scenario="$1"
    reset_transaction_fixture
    SCENARIO="$scenario"
    if perform_backup_transaction /dev/mock-luks "$TX_PATH" \
            >"$TX_FIXTURE/$scenario.out" 2>&1; then
        _fail "transaction rejects $scenario"
    else
        _pass "transaction rejects $scenario"
    fi
    if [ ! -e "$TX_PATH" ] && compgen -G "${TX_PATH}.FAILED-*" >/dev/null; then
        _pass "$scenario artifact is quarantined"
    else
        _fail "$scenario artifact is quarantined"
    fi
    assert_eq "0" "$LOG_CALLS" "$scenario cannot commit success evidence"
    assert_no_private_stage "$scenario"
}

assert_quarantined_failure backup_fail
assert_quarantined_failure parse_fail
assert_quarantined_failure stat_fail
assert_quarantined_failure sha_fail
assert_quarantined_failure stage_sync_fail
assert_quarantined_failure cleanup_fail

reset_transaction_fixture
SCENARIO="stage_meta_fail"
if perform_backup_transaction /dev/mock-luks "$TX_PATH" \
        >"$TX_FIXTURE/stage_meta_fail.out" 2>&1; then
    _fail "transaction rejects a filesystem without root:root 0700 staging"
else
    _pass "transaction rejects a filesystem without root:root 0700 staging"
fi
assert_eq "0" "$LOG_CALLS" "unsafe staging metadata cannot commit success evidence"
assert_no_private_stage "stage metadata failure"

reset_transaction_fixture
SCENARIO="success"
printf '%s\n' original > "$TX_PATH"
if perform_backup_transaction /dev/mock-luks "$TX_PATH" \
        >"$TX_FIXTURE/existing.out" 2>&1; then
    _fail "transaction refuses a pre-existing regular destination"
else
    _pass "transaction refuses a pre-existing regular destination"
fi
assert_grep_fixed 'original' "$TX_PATH" "pre-existing destination is unchanged"
assert_eq "0" "$LOG_CALLS" "destination collision cannot commit success evidence"

reset_transaction_fixture
SCENARIO="success"
SYMLINK_TARGET="$TX_FIXTURE/symlink-target"
printf '%s\n' protected > "$SYMLINK_TARGET"
ln -s "$SYMLINK_TARGET" "$TX_PATH"
if perform_backup_transaction /dev/mock-luks "$TX_PATH" \
        >"$TX_FIXTURE/symlink.out" 2>&1; then
    _fail "transaction refuses a symlink destination"
else
    _pass "transaction refuses a symlink destination"
fi
assert_grep_fixed 'protected' "$SYMLINK_TARGET" "symlink target is untouched"
assert_eq "0" "$LOG_CALLS" "symlink destination cannot commit success evidence"

reset_transaction_fixture
SCENARIO="stage_handle_swap"
if perform_backup_transaction /dev/mock-luks "$TX_PATH" \
        >"$TX_FIXTURE/stage_handle_swap.out" 2>&1; then
    _pass "pinned stage survives a rename-and-symlink path swap"
else
    _fail "pinned stage survives a rename-and-symlink path swap"
fi
assert_file_exists "$TX_PATH" \
    "path-swap-resistant transaction still publishes the verified backup"
if [ -e "$SWAP_VICTIM/header.bin" ] || [ -L "$SWAP_VICTIM/header.bin" ]; then
    _fail "replacement symlink cannot redirect privileged header output"
else
    _pass "replacement symlink cannot redirect privileged header output"
fi
assert_eq "1" "$LOG_CALLS" \
    "path-swap-resistant transaction commits one success record"
assert_no_private_stage "stage handle path swap"

reset_transaction_fixture
SCENARIO="publish_collision"
if perform_backup_transaction /dev/mock-luks "$TX_PATH" \
        >"$TX_FIXTURE/publish_collision.out" 2>&1; then
    _fail "transaction rejects a collision injected at publication"
else
    _pass "transaction rejects a collision injected at publication"
fi
assert_grep_fixed 'collision' "$TX_PATH" "late collision is never overwritten"
if compgen -G "${TX_PATH}.FAILED-*" >/dev/null; then
    _pass "verified staged artifact is quarantined after a late collision"
else
    _fail "verified staged artifact is quarantined after a late collision"
fi
assert_eq "0" "$LOG_CALLS" "late collision cannot commit success evidence"
assert_no_private_stage "late publication collision"

reset_transaction_fixture
SCENARIO="published_path_swap"
if perform_backup_transaction /dev/mock-luks "$TX_PATH" \
        >"$TX_FIXTURE/published_path_swap.out" 2>&1; then
    _fail "transaction rejects a replaced published path"
else
    _pass "transaction rejects a replaced published path"
fi
assert_grep_fixed 'replacement' "$TX_PATH" \
    "replacement destination remains untouched"
assert_file_exists "$PUBLISHED_SWAP_ORIGINAL" \
    "the originally published backup remains separately identifiable"
if compgen -G "${TX_PATH}.FAILED-*" >/dev/null; then
    _fail "replacement inode is never mislabeled as the failed backup"
else
    _pass "replacement inode is never mislabeled as the failed backup"
fi
assert_eq "0" "$LOG_CALLS" \
    "replaced published path cannot commit success evidence"
assert_no_private_stage "published path replacement"

reset_transaction_fixture
SCENARIO="log_fail"
if perform_backup_transaction /dev/mock-luks "$TX_PATH" \
        >"$TX_FIXTURE/log_fail.out" 2>&1; then
    _fail "transaction rejects success-log commit failure"
else
    _pass "transaction rejects success-log commit failure"
fi
assert_file_exists "$TX_PATH" "verified artifact remains available after log failure"
assert_eq "1" "$LOG_CALLS" "log commit was attempted exactly once"
assert_not_grep 'Backup complete' "$TX_FIXTURE/log_fail.out" \
    "log failure cannot print the completion claim"

reset_transaction_fixture
SCENARIO="parent_sync_fail"
if perform_backup_transaction /dev/mock-luks "$TX_PATH" \
        >"$TX_FIXTURE/parent_sync_fail.out" 2>&1; then
    _fail "transaction rejects a parent-directory durability failure"
else
    _pass "transaction rejects a parent-directory durability failure"
fi
assert_file_exists "$TX_PATH" \
    "structurally verified file remains available after media sync failure"
assert_eq "0" "$LOG_CALLS" \
    "media sync failure cannot commit success evidence"
assert_no_private_stage "parent-directory sync failure"

reset_transaction_fixture
SCENARIO="success"
if perform_backup_transaction /dev/mock-luks "$TX_PATH" \
        >"$TX_FIXTURE/success.out" 2>&1; then
    _pass "fully verified transaction succeeds"
else
    _fail "fully verified transaction succeeds"
fi
assert_file_exists "$TX_PATH" "verified backup remains at the destination"
assert_eq "1" "$LOG_CALLS" "successful transaction commits one log record"
assert_eq "2097152" "$VERIFIED_SIZE" "verified size is exported to the summary"
if [[ "$VERIFIED_SHA" =~ ^[a-f0-9]{64}$ ]]; then
    _pass "successful transaction exports a valid SHA-256"
else
    _fail "successful transaction exports a valid SHA-256"
fi

# An asynchronous termination must stop control flow, quarantine any staged
# artifact, clean the private directory and close the pinned parent handle.
INTERRUPT_EVENTS="$TX_FIXTURE/interrupt-events"
INTERRUPT_OUTPUT="$TX_FIXTURE/interrupt-output"
set +e
(
    # shellcheck disable=SC2317,SC2329 # invoked indirectly by the sourced EXIT handler
    quarantine_backup() { printf '%s\n' quarantine >> "$INTERRUPT_EVENTS"; }
    # shellcheck disable=SC2317,SC2329 # invoked indirectly by the sourced EXIT handler
    cleanup_backup_stage() { printf '%s\n' cleanup >> "$INTERRUPT_EVENTS"; }
    # shellcheck disable=SC2317,SC2329 # invoked indirectly by the sourced EXIT handler
    close_parent_handle() { printf '%s\n' close >> "$INTERRUPT_EVENTS"; }
    BACKUP_TRANSACTION_ACTIVE=1
    BACKUP_WORK_PATH=/mock/private/header.bin
    BACKUP_PUBLISH_PATH=/mock/published.bin
    BACKUP_DISPLAY_PATH=/display/published.bin
    BACKUP_STAGED_IDENTITY=""
    BACKUP_ARTIFACT_VERIFIED=0
    trap backup_transaction_exit_cleanup EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    kill -TERM "$BASHPID"
    printf '%s\n' continued
) >"$INTERRUPT_OUTPUT" 2>&1
interrupt_rc=$?
set -e
assert_eq "143" "$interrupt_rc" \
    "TERM exits through the transaction cleanup path"
assert_grep_fixed 'quarantine' "$INTERRUPT_EVENTS" \
    "TERM quarantines the staged artifact"
assert_grep_fixed 'cleanup' "$INTERRUPT_EVENTS" \
    "TERM cleans the private staging directory"
assert_grep_fixed 'close' "$INTERRUPT_EVENTS" \
    "TERM closes the pinned publication handle"
assert_not_grep 'continued' "$INTERRUPT_OUTPUT" \
    "TERM cannot continue into a completion claim"

# Exercise the real EXIT handler on both sides of the durable-verification
# boundary. A rename-complete but unverified artifact must be identified by its
# original inode and quarantined; a fully verified artifact must remain.
POST_PUBLISH_DIR="$TX_FIXTURE/post-publish-interrupt"
POST_PUBLISH_STAGE="$POST_PUBLISH_DIR/.stage"
POST_PUBLISH_PATH="$POST_PUBLISH_DIR/header.bin"
mkdir -p "$POST_PUBLISH_STAGE"
truncate -s 2097152 "$POST_PUBLISH_STAGE/header.bin"
BACKUP_STAGED_IDENTITY=$(stat -Lc '%d:%i' "$POST_PUBLISH_STAGE/header.bin")
mv -- "$POST_PUBLISH_STAGE/header.bin" "$POST_PUBLISH_PATH"
BACKUP_STAGE_DIR="$POST_PUBLISH_STAGE"
BACKUP_WORK_PATH="$POST_PUBLISH_STAGE/header.bin"
BACKUP_PUBLISH_PATH="$POST_PUBLISH_PATH"
BACKUP_DISPLAY_PATH="$POST_PUBLISH_PATH"
BACKUP_TRANSACTION_ACTIVE=1
BACKUP_ARTIFACT_VERIFIED=0
set +e
(
    trap backup_transaction_exit_cleanup EXIT
    trap 'exit 143' TERM
    kill -TERM "$BASHPID"
    printf '%s\n' continued
) >"$TX_FIXTURE/post-publish-interrupt.out" 2>&1
post_publish_rc=$?
set -e
assert_eq "143" "$post_publish_rc" \
    "TERM after publication exits through cleanup"
if [ ! -e "$POST_PUBLISH_PATH" ] && \
   compgen -G "${POST_PUBLISH_PATH}.FAILED-*" >/dev/null; then
    _pass "TERM quarantines the exact staged inode after publication"
else
    _fail "TERM quarantines the exact staged inode after publication"
fi
if [ ! -d "$POST_PUBLISH_STAGE" ]; then
    _pass "post-publication interruption removes the private stage"
else
    _fail "post-publication interruption removes the private stage"
fi

VERIFIED_SIGNAL_DIR="$TX_FIXTURE/verified-signal"
VERIFIED_SIGNAL_STAGE="$VERIFIED_SIGNAL_DIR/.stage"
VERIFIED_SIGNAL_PATH="$VERIFIED_SIGNAL_DIR/header.bin"
mkdir -p "$VERIFIED_SIGNAL_STAGE"
truncate -s 2097152 "$VERIFIED_SIGNAL_STAGE/header.bin"
# shellcheck disable=SC2034 # consumed by the sourced EXIT handler
BACKUP_STAGED_IDENTITY=$(stat -Lc '%d:%i' "$VERIFIED_SIGNAL_STAGE/header.bin")
mv -- "$VERIFIED_SIGNAL_STAGE/header.bin" "$VERIFIED_SIGNAL_PATH"
BACKUP_STAGE_DIR="$VERIFIED_SIGNAL_STAGE"
# shellcheck disable=SC2034 # consumed by the sourced EXIT handler
BACKUP_WORK_PATH="$VERIFIED_SIGNAL_STAGE/header.bin"
# shellcheck disable=SC2034 # consumed by the sourced EXIT handler
BACKUP_PUBLISH_PATH="$VERIFIED_SIGNAL_PATH"
# shellcheck disable=SC2034 # consumed by the sourced EXIT handler
BACKUP_DISPLAY_PATH="$VERIFIED_SIGNAL_PATH"
# shellcheck disable=SC2034 # consumed by the sourced EXIT handler
BACKUP_TRANSACTION_ACTIVE=1
# shellcheck disable=SC2034 # consumed by the sourced EXIT handler
BACKUP_ARTIFACT_VERIFIED=1
set +e
(
    trap backup_transaction_exit_cleanup EXIT
    trap 'exit 143' TERM
    kill -TERM "$BASHPID"
    printf '%s\n' continued
) >"$TX_FIXTURE/verified-signal.out" 2>&1
verified_signal_rc=$?
set -e
assert_eq "143" "$verified_signal_rc" \
    "TERM after durable verification exits through cleanup"
assert_file_exists "$VERIFIED_SIGNAL_PATH" \
    "durably verified artifact survives later interruption"
if compgen -G "${VERIFIED_SIGNAL_PATH}.FAILED-*" >/dev/null; then
    _fail "durably verified artifact is never relabeled as failed"
else
    _pass "durably verified artifact is never relabeled as failed"
fi
if [ ! -d "$VERIFIED_SIGNAL_STAGE" ]; then
    _pass "post-verification interruption removes the private stage"
else
    _fail "post-verification interruption removes the private stage"
fi

# --- M22 verify block covers the new wrapper -------------------------------
assert_grep_fixed '[ -x /usr/local/bin/noid-luks-backup.sh ]' "$KS_FILE"
assert_grep_fixed 'LUKS backup wrapper perms=0755' "$KS_FILE"
assert_grep_fixed 'bash -n /usr/local/bin/noid-luks-backup.sh' "$KS_FILE"

# --- STEP 3b phase header present ------------------------------
assert_grep_fixed 'STEP 3b' "$KS_FILE"

# --- SELinux restorecon covers the wrapper and fails closed ----------------
SELINUX_BLOCK="$TX_FIXTURE/selinux-publication.sh"
sed -n '/^log "STEP 4: SELinux context restore"$/,/^log "  \[OK\] restorecon complete"$/p' \
    "$KS_FILE" > "$SELINUX_BLOCK"
assert_grep_fixed '/usr/local/bin/noid-luks-backup.sh' "$SELINUX_BLOCK" \
    "restorecon transaction covers the LUKS backup wrapper"
assert_grep_fixed '|| { log "  [FAIL] SELinux label reconciliation failed"; exit 1; }' \
    "$SELINUX_BLOCK" "wrapper relabel transaction fails closed"

test_finish

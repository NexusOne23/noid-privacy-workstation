#!/bin/bash
# 20-snapper-structural — M20 regression test
#
# Covers: native Btrfs-default boot selection, stable top-level subvolumes,
# root-only checked create/status/rollback helpers, standalone ad-hoc points,
# retention state machine, NO X-GNOME-Autostart-Phase and installonly_limit=3.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/20-snapper.ks"
RUNTIME_GATE="$PROJECT_ROOT/tests/pre-ship/20-snapper-rollback-runtime.sh"
TEST_LEDGER="$PROJECT_ROOT/tests/README.md"
TEST_STRATEGY="$PROJECT_ROOT/docs/test-strategy.md"
RETENTION_DOC="$PROJECT_ROOT/docs/log-retention.md"
TMPDIR="$(mktemp -d /var/tmp/noid-test20.XXXXXX)"
trap 'rm -rf "$TMPDIR"' EXIT

test_start "20-snapper-structural"

assert_file_exists "$KS_FILE"
assert_cmd_success "bash -n $KS_FILE" bash -n "$KS_FILE"
assert_file_exists "$RUNTIME_GATE"
assert_file_exists "$TEST_LEDGER"
assert_file_exists "$TEST_STRATEGY"
assert_file_exists "$RETENTION_DOC"
assert_cmd_success "runtime rollback gate is executable" test -x "$RUNTIME_GATE"
assert_cmd_success "runtime rollback gate parses" bash -n "$RUNTIME_GATE"
assert_cmd_success "runtime rollback gate passes ShellCheck" \
    shellcheck -S warning "$RUNTIME_GATE"
assert_cmd_failure "runtime gate refuses an absent pass identity" \
    bash "$RUNTIME_GATE"
assert_cmd_failure "runtime gate refuses an unknown pass identity" \
    bash "$RUNTIME_GATE" source-host
assert_not_grep 'echo .*SKIP' "$RUNTIME_GATE" \
    "runtime rollback gate contains no success-producing skip path"
assert_grep_fixed 'pass intentionally selects a just-created disposable rollback root' \
    "$RUNTIME_GATE" \
    "destructive candidate-only boundary is explicit"
assert_grep_fixed 'kvm|qemu)' "$RUNTIME_GATE" \
    "destructive lifecycle proof is confined to a disposable QEMU/KVM VM"
assert_not_grep 'exec sudo' "$RUNTIME_GATE" \
    "runtime gate never re-executes a mutable relative script as root"
assert_grep_fixed 'export BASH_ENV=/dev/null' "$RUNTIME_GATE" \
    "runtime gate closes inherited Bash startup code"
assert_grep_fixed 'flock -n 7' "$RUNTIME_GATE" \
    "one runtime-gate lock serializes every lifecycle pass"
for runtime_payload in \
        SNAPPER_ROOT_CONFIG_EOF SNAPPER_INIT_EOF \
        SNAPPER_INIT_SERVICE_EOF CLEANUP_TIMER_EOF CLEANUP_SERVICE_EOF \
        SNAPPER_CREATE_EOF SNAPPER_STATUS_EOF SNAPPER_ROLLBACK_EOF \
        SNAPPER_STATUS_SUDO_EOF SNAPPER_PRUNE_EOF \
        SNAPPER_PRUNE_SERVICE_EOF SNAPPER_PRUNE_TIMER_EOF \
        BOOT_MUTATION_GUARD_EOF BOOT_MUTATION_TMPFILES_EOF; do
    assert_grep_fixed "$runtime_payload" "$RUNTIME_GATE" \
        "runtime gate extracts canonical payload: $runtime_payload"
done
assert_grep_fixed 'installed payload differs from canonical source' \
    "$RUNTIME_GATE" "runtime gate binds installed M20/M21 bytes to the checkout"
assert_grep_fixed 'require_rpm_file /usr/bin/snapper snapper 755' \
    "$RUNTIME_GATE" "runtime gate authenticates the executed Snapper binary"
assert_grep_fixed 'require_rpm_file /usr/bin/btrfs btrfs-progs 755' \
    "$RUNTIME_GATE" "runtime gate authenticates the destructive Btrfs binary"
assert_grep_fixed 'status_boot == reboot-required' "$RUNTIME_GATE" \
    "runtime gate observes the valid pre-reboot transition"
assert_grep_fixed '[[ ! -e $PROBE && ! -L $PROBE ]]' "$RUNTIME_GATE" \
    "reboot pass proves target snapshot content became active"
assert_grep_fixed '/usr/libexec/noid-snapper-rollback --resume' "$RUNTIME_GATE" \
    "fresh-install resumes exact persistent helper evidence after interruption"
assert_grep_fixed \
    'pending rollback must be resumed by fresh-install before its selected-root reboot' \
    "$RUNTIME_GATE" \
    "reboot cannot turn an unbooted pending selection into apparent rollback proof"
assert_grep_fixed 'root_id != "$gate_staged_from"' "$RUNTIME_GATE" \
    "reboot resumes pending helper evidence only from the newly booted root"
assert_grep_fixed 'prepared gate and ready rollback target differ' "$RUNTIME_GATE" \
    "reboot reconstructs only an exact post-publication crash window"
assert_grep_fixed 'gate_phase != passed' "$RUNTIME_GATE" \
    "reboot verification is idempotent after durable success"
# A STATUS=prepared record carries two empty SELECTED_* fields. TAB is an IFS
# whitespace character, so `IFS=$'\t' read` collapses the empty run and shifts
# STAGED_FROM_ROOT_ID into gate_selected, silently emptying gate_staged_from --
# which load_gate_state assigns as a global from inside publish_gate_state,
# overwriting the correct value AFTER the irreversible rollback has run.
assert_grep_fixed "IFS='|' read -r gate_phase gate_target gate_selected" \
    "$RUNTIME_GATE" \
    "gate record uses a separator that preserves its empty fields"
assert_not_grep "IFS=\$'\\\\t' read -r gate_phase" "$RUNTIME_GATE" \
    "gate record is never split on an IFS whitespace character"
assert_grep_fixed 'if any("|" in field or "\n" in field for field in record)' \
    "$RUNTIME_GATE" \
    "gate record refuses a field that would break its own framing"
assert_grep_fixed 'rollback gate evidence record framing is invalid' \
    "$RUNTIME_GATE" \
    "a shifted or truncated gate record fails loudly instead of emptying a global"
# The producer-side round-trip is asserted below, once the parser has been
# extracted through the existing unique-marker awk (see RUNTIME_STATE_PARSER).
assert_grep_fixed \
    "complete M21's reboot pass before Snapper fresh-install" "$RUNTIME_GATE" \
    "runtime gate names the required terminal M21 predecessor"
assert_grep_fixed \
    'M21 `fresh-install` and `reboot` must both pass before' "$TEST_STRATEGY" \
    "test strategy requires separate M21 and Snapper reboot transactions"
m21_fresh_line=$(grep -nF \
    'sudo bash tests/pre-ship/21-dracut-hostonly-runtime.sh fresh-install' \
    "$TEST_LEDGER" | cut -d: -f1 || true)
m21_reboot_line=$(grep -nF \
    'sudo bash tests/pre-ship/21-dracut-hostonly-runtime.sh reboot' \
    "$TEST_LEDGER" | cut -d: -f1 || true)
snapper_fresh_line=$(grep -nF \
    'sudo bash tests/pre-ship/20-snapper-rollback-runtime.sh fresh-install' \
    "$TEST_LEDGER" | cut -d: -f1 || true)
snapper_reboot_line=$(grep -nF \
    'sudo bash tests/pre-ship/20-snapper-rollback-runtime.sh reboot' \
    "$TEST_LEDGER" | cut -d: -f1 || true)
if [ -n "$m21_fresh_line" ] && [ -n "$m21_reboot_line" ] \
        && [ -n "$snapper_fresh_line" ] && [ -n "$snapper_reboot_line" ] \
        && [ "$m21_fresh_line" -lt "$m21_reboot_line" ] \
        && [ "$m21_reboot_line" -lt "$snapper_fresh_line" ] \
        && [ "$snapper_fresh_line" -lt "$snapper_reboot_line" ]; then
    _pass "canonical ledger serializes M21 and Snapper across two reboots"
else
    _fail "canonical ledger overlaps the guarded M21 and Snapper boot transactions"
fi

RUNTIME_SOURCE_EXTRACTOR="$TMPDIR/runtime-source-extractor.py"
runtime_source_extractor_rc=0
awk '
    /<<'\''EXTRACT_SOURCES_PYEOF'\''/ {
        if (seen++) exit 2
        capture=1
        next
    }
    capture && $0 == "EXTRACT_SOURCES_PYEOF" {
        capture=0
        closed++
        next
    }
    capture { print }
    END {
        if (seen != 1 || closed != 1 || capture) exit 3
    }
' "$RUNTIME_GATE" >"$RUNTIME_SOURCE_EXTRACTOR" \
    || runtime_source_extractor_rc=$?
assert_eq 0 "$runtime_source_extractor_rc" \
    "runtime canonical-source extractor has one exact embedded program"
mkdir "$TMPDIR/runtime-source-payloads"
assert_cmd_success "runtime canonical-source extractor resolves every payload" \
    python3 -I "$RUNTIME_SOURCE_EXTRACTOR" \
        "$KS_FILE" \
        "$PROJECT_ROOT/kickstart/snippets/21-kernel-module-blacklist.ks" \
        "$TMPDIR/runtime-source-payloads"
for runtime_payload in \
        SNAPPER_ROOT_CONFIG_EOF SNAPPER_INIT_EOF \
        SNAPPER_INIT_SERVICE_EOF CLEANUP_TIMER_EOF CLEANUP_SERVICE_EOF \
        SNAPPER_CREATE_EOF SNAPPER_STATUS_EOF SNAPPER_ROLLBACK_EOF \
        SNAPPER_STATUS_SUDO_EOF SNAPPER_PRUNE_EOF \
        SNAPPER_PRUNE_SERVICE_EOF SNAPPER_PRUNE_TIMER_EOF; do
    extract_heredoc "$KS_FILE" "$runtime_payload" \
        "$TMPDIR/runtime-source-expected" \
        || _fail "canonical source payload extraction: $runtime_payload"
    assert_cmd_success "runtime source bytes: $runtime_payload" \
        cmp -s "$TMPDIR/runtime-source-expected" \
            "$TMPDIR/runtime-source-payloads/$runtime_payload"
done
for runtime_payload in BOOT_MUTATION_GUARD_EOF BOOT_MUTATION_TMPFILES_EOF; do
    extract_heredoc \
        "$PROJECT_ROOT/kickstart/snippets/21-kernel-module-blacklist.ks" \
        "$runtime_payload" "$TMPDIR/runtime-source-expected" \
        || _fail "canonical source payload extraction: $runtime_payload"
    assert_cmd_success "runtime source bytes: $runtime_payload" \
        cmp -s "$TMPDIR/runtime-source-expected" \
            "$TMPDIR/runtime-source-payloads/$runtime_payload"
done

RUNTIME_FSTAB_PARSER="$TMPDIR/runtime-fstab-parser.py"
runtime_fstab_parser_rc=0
awk '
    /<<'\''FSTAB_PY'\''/ {
        if (seen++) exit 2
        capture=1
        next
    }
    capture && $0 == "FSTAB_PY" {
        capture=0
        closed++
        next
    }
    capture { print }
    END {
        if (seen != 1 || closed != 1 || capture) exit 3
    }
' "$RUNTIME_GATE" >"$RUNTIME_FSTAB_PARSER" || runtime_fstab_parser_rc=$?
assert_eq 0 "$runtime_fstab_parser_rc" \
    "runtime fstab parser extracts from unique markers"
cat >"$TMPDIR/runtime-safe.fstab" <<'RUNTIME_SAFE_FSTAB_EOF'
UUID=noid-test	/	btrfs	compress=zstd:1,nodiscard	0	0
UUID=noid-test	/.snapshots	btrfs	subvol=snapshots,nosuid,nodev,noexec,x-systemd.device-timeout=0	0	0
UUID=noid-test	/var/lib/libvirt	btrfs	subvol=libvirt,nosuid,nodev,x-systemd.device-timeout=0	0	0
RUNTIME_SAFE_FSTAB_EOF
assert_cmd_success "runtime fstab parser accepts the exact managed rows" \
    python3 -I "$RUNTIME_FSTAB_PARSER" "$TMPDIR/runtime-safe.fstab"
sed 's/noexec,x-systemd/noexec,exec,x-systemd/' \
    "$TMPDIR/runtime-safe.fstab" >"$TMPDIR/runtime-weakened.fstab"
assert_cmd_failure \
    "runtime fstab parser rejects a contradictory post-snapshot exec option" \
    python3 -I "$RUNTIME_FSTAB_PARSER" "$TMPDIR/runtime-weakened.fstab"

RUNTIME_STATE_PARSER="$TMPDIR/runtime-state-parser.py"
runtime_state_parser_rc=0
awk '
    /<<'\''PARSE_GATE_STATE_PYEOF'\''/ {
        if (seen++) exit 2
        capture=1
        next
    }
    capture && $0 == "PARSE_GATE_STATE_PYEOF" {
        capture=0
        closed++
        next
    }
    capture { print }
    END {
        if (seen != 1 || closed != 1 || capture) exit 3
    }
' "$RUNTIME_GATE" >"$RUNTIME_STATE_PARSER" || runtime_state_parser_rc=$?
assert_eq 0 "$runtime_state_parser_rc" \
    "runtime gate state parser extracts from unique markers"
cat >"$TMPDIR/runtime-prepared.state" <<'RUNTIME_PREPARED_EOF'
STATUS=prepared
TARGET=7
STAGED_FROM_ROOT_ID=42
PREPARED_AT=2026-07-29T12:34:56Z
RUNTIME_PREPARED_EOF
# Pipe-separated, not tab: this assertion only ever proved the producer, and a
# tab record read back through `IFS=$'\t' read` silently dropped the two empty
# SELECTED_* fields on the consumer side. The round-trip is asserted above.
assert_eq 'prepared|7|||42|2026-07-29T12:34:56Z' \
    "$(python3 -I "$RUNTIME_STATE_PARSER" "$TMPDIR/runtime-prepared.state")" \
    "runtime state parser accepts the exact prepared schema"
# Prove the consumer too, not just the producer. Reading that same record back
# with the gate's own field list is what the tab separator silently broke: the
# two empty SELECTED_* fields collapsed and STAGED_FROM_ROOT_ID landed in
# gate_selected, leaving gate_staged_from empty after an irreversible rollback.
IFS='|' read -r g_phase g_target g_selected g_selected_id g_staged g_stamp \
    g_extra < <(python3 -I "$RUNTIME_STATE_PARSER" "$TMPDIR/runtime-prepared.state")
assert_eq "prepared" "$g_phase" "prepared record round-trips its phase"
assert_eq "7" "$g_target" "prepared record round-trips its target"
assert_eq "" "$g_selected" "prepared record round-trips an absent snapshot"
assert_eq "" "$g_selected_id" "prepared record round-trips an absent root id"
assert_eq "42" "$g_staged" \
    "prepared record round-trips STAGED_FROM_ROOT_ID across the empty fields"
assert_eq "2026-07-29T12:34:56Z" "$g_stamp" "prepared record round-trips its stamp"
assert_eq "" "${g_extra:-}" "prepared record carries no seventh field"
cat >"$TMPDIR/runtime-invalid.state" <<'RUNTIME_INVALID_EOF'
STATUS=prepared
TARGET=7
TARGET=8
PREPARED_AT=2026-07-29T12:34:56Z
RUNTIME_INVALID_EOF
assert_cmd_failure "runtime state parser rejects duplicate/reordered fields" \
    python3 -I "$RUNTIME_STATE_PARSER" "$TMPDIR/runtime-invalid.state"

RUNTIME_PROBE_CREATOR="$TMPDIR/runtime-probe-creator.py"
runtime_probe_parser_rc=0
awk '
    /<<'\''CREATE_ROLLBACK_PROBE_PYEOF'\''/ {
        if (seen++) exit 2
        capture=1
        next
    }
    capture && $0 == "CREATE_ROLLBACK_PROBE_PYEOF" {
        capture=0
        closed++
        next
    }
    capture { print }
    END {
        if (seen != 1 || closed != 1 || capture) exit 3
    }
' "$RUNTIME_GATE" >"$RUNTIME_PROBE_CREATOR" || runtime_probe_parser_rc=$?
assert_eq 0 "$runtime_probe_parser_rc" \
    "runtime exclusive probe creator extracts from unique markers"
RUNTIME_PROBE="$TMPDIR/runtime-probe"
assert_cmd_success "runtime probe creator publishes a new exact file" \
    python3 -I "$RUNTIME_PROBE_CREATOR" "$RUNTIME_PROBE"
assert_eq 'this file must disappear after the tested rollback' \
    "$(cat "$RUNTIME_PROBE")" "runtime probe creator publishes exact bytes"
runtime_probe_before=$(sha256sum "$RUNTIME_PROBE")
assert_cmd_failure "runtime probe creator refuses an existing path" \
    python3 -I "$RUNTIME_PROBE_CREATOR" "$RUNTIME_PROBE"
assert_eq "$runtime_probe_before" "$(sha256sum "$RUNTIME_PROBE")" \
    "runtime probe refusal preserves existing bytes"

# installonly_limit guard (must be 3 to keep old kernels for rollback)
assert_grep_fixed 'installonly_limit=3' "$KS_FILE"
assert_grep_fixed 'required installonly_limit=3 is absent' "$KS_FILE" \
    "missing rollback kernel retention is a build failure"
assert_not_grep 'WARNING: installonly_limit=3' "$KS_FILE" \
    "rollback kernel retention is not reduced to a warning"

# Snapper config for root
assert_grep_fixed "/etc/snapper/configs/root" "$KS_FILE"
assert_grep_fixed 'SNAPPER_ROOT_CONFIG_EOF' "$KS_FILE"
assert_grep_fixed "/etc/sysconfig/snapper" "$KS_FILE"
assert_grep_fixed \
    'install -d -m 0755 -o root -g root /usr/libexec/snapper/plugins' \
    "$KS_FILE" \
    "empty root-owned plugin directory makes the no-plugin state log-clean"
assert_grep_fixed \
    'empty Snapper plugin boundary is missing or unsafe' "$KS_FILE" \
    "build verification rejects an absent or writable plugin boundary"
assert_grep_fixed "/usr/libexec/snapper/plugins \\" "$KS_FILE" \
    "Snapper plugin boundary receives its exact default SELinux label"

# Init script with idempotency marker
assert_grep_fixed "/usr/local/bin/noid-snapper-init.sh" "$KS_FILE"
assert_grep_fixed "/.snapshots/.noid-state/init.done" "$KS_FILE"
assert_grep_fixed "/etc/systemd/system/noid-snapper-init.service" "$KS_FILE"
assert_grep_fixed 'chown root:root /etc/systemd/system/noid-snapper-init.service' \
    "$KS_FILE" "Snapper init unit publishes with explicit root ownership"
assert_grep_fixed 'chown root:root /usr/share/doc/noid-privacy/20-rollback-recovery.md' \
    "$KS_FILE" "Snapper recovery guide publishes with explicit root ownership"
assert_grep_fixed 'Requires=noid-firstboot-cmdline.service' "$KS_FILE" \
    "Snapper refuses to finalize BLS state after a failed M01 cmdline pass"
assert_grep_fixed 'After=local-fs.target noid-firstboot-cmdline.service' "$KS_FILE" \
    "Snapper is ordered after M01 cmdline reconciliation"
assert_grep_fixed 'Before=noid-dracut-hostonly-firstboot.service multi-user.target' \
    "$KS_FILE" "Snapper finalizes BLS/root topology before M21 publication"
# virtqemud.service is preset-enabled by fedora-release-common, so it shares
# this unit's boot transaction. Without ordering it reaches active first and
# the libvirt storage gate fails closed on every boot, permanently.
assert_grep_fixed \
    'Before=libvirtd.service virtqemud.service virtstoraged.service virtnetworkd.service' \
    "$KS_FILE" "Snapper migrates libvirt storage before any libvirt daemon starts"
extract_heredoc "$KS_FILE" "SNAPPER_INIT_EOF" "$TMPDIR/snapper-init.sh" \
    || _fail "snapper init heredoc extraction"
extract_heredoc "$KS_FILE" "SNAPPER_INIT_SERVICE_EOF" \
    "$TMPDIR/snapper-init.service" || _fail "snapper init unit extraction"
assert_cmd_success "snapper initializer passes ShellCheck" \
    shellcheck -S warning "$TMPDIR/snapper-init.sh"
assert_grep_fixed 'require_tools findmnt logger' "$TMPDIR/snapper-init.sh" \
    "topology probe preflights its filesystem and journal tools"
assert_grep_fixed \
    "require_tools awk btrfs chattr chmod chown cp find grep grubby install lsattr \\" \
    "$TMPDIR/snapper-init.sh" \
    "Btrfs bootstrap preflights the first segment of its closed command inventory"
assert_grep_fixed \
    "matchpathcon mkdir mktemp mount mountpoint mv python3 restorecon rm snapper \\" \
    "$TMPDIR/snapper-init.sh" \
    "Btrfs bootstrap preflights the second segment of its closed command inventory"
assert_grep_fixed 'stat sync systemctl tr umount' "$TMPDIR/snapper-init.sh" \
    "Btrfs bootstrap preflights the final segment of its closed command inventory"
require_tools_line=$(grep -nF 'require_tools findmnt logger' \
    "$TMPDIR/snapper-init.sh" | cut -d: -f1 || true)
root_probe_line=$(grep -nF 'root_fstype=$(findmnt -n -o FSTYPE /' \
    "$TMPDIR/snapper-init.sh" | cut -d: -f1 || true)
if [ -n "$require_tools_line" ] && [ -n "$root_probe_line" ] \
        && [ "$require_tools_line" -lt "$root_probe_line" ]; then
    _pass "topology-neutral tool preflight precedes the root filesystem probe"
else
    _fail "root filesystem probe can run before its tool preflight"
fi
assert_grep_fixed 'root_fstype=$(findmnt -n -o FSTYPE / 2>/dev/null)' \
    "$TMPDIR/snapper-init.sh" \
    "initializer reads the installed root filesystem type once"
assert_grep_fixed 'cannot determine the root filesystem type' \
    "$TMPDIR/snapper-init.sh" \
    "an unverifiable root filesystem remains a hard failure"
assert_grep_fixed 'Snapper bootstrap is not applicable' "$TMPDIR/snapper-init.sh" \
    "non-Btrfs roots have an explicit local skip record"
assert_grep_fixed "printf '%s: %s\\n' \"\$LOG_TAG\" \"\$non_btrfs_message\" >&2" \
    "$TMPDIR/snapper-init.sh" \
    "non-Btrfs skip remains locally visible if the journal write fails"
assert_not_grep 'required rollback invariant unavailable' "$TMPDIR/snapper-init.sh" \
    "non-Btrfs roots are not misclassified as failed boot prerequisites"
assert_cmd_success "non-Btrfs initializer exits cleanly before mutation" \
    bash -c '
        findmnt() { printf "%s\\n" ext4; }
        logger() { :; }
        mountpoint() { return 1; }
        source "$1"
    ' bash "$TMPDIR/snapper-init.sh"
assert_cmd_failure "unreadable root filesystem type fails closed" \
    bash -c '
        findmnt() { return 1; }
        logger() { :; }
        mountpoint() { return 1; }
        source "$1"
    ' bash "$TMPDIR/snapper-init.sh"
assert_grep_fixed 'baseline snapshot postcondition failed' "$TMPDIR/snapper-init.sh" \
    "baseline creation is verified before completion marker"
assert_grep_fixed 'row.get("description") == "baseline-install"' "$TMPDIR/snapper-init.sh" \
    "baseline identity comes from machine-readable Snapper state"
assert_grep_fixed 'reconcile_snapshot_state_labels()' "$TMPDIR/snapper-init.sh" \
    "initializer owns one exact stable-state SELinux reconciliation path"
assert_grep_fixed 'restorecon -F /.snapshots /.snapshots/.noid-state' \
    "$TMPDIR/snapper-init.sh" \
    "initializer repairs only the two exact stable snapshot-state directories"
assert_grep_fixed 'matchpathcon -V "$MARKER"' "$TMPDIR/snapper-init.sh" \
    "initializer verifies the durable completion marker label"
assert_grep_fixed 'sync -- "$MARKER"' "$TMPDIR/snapper-init.sh" \
    "stable completion marker is durable before init success"
assert_grep_fixed 'completion marker is malformed or has unsafe metadata' \
    "$TMPDIR/snapper-init.sh" \
    "later boots fail closed on an untrusted initializer marker"
assert_grep_fixed 'completed_status=$(/usr/libexec/noid-snapper-status)' \
    "$TMPDIR/snapper-init.sh" \
    "later boots revalidate the complete rollback model"
assert_not_grep 'ConditionPathExists=!/.snapshots/.noid-state/init.done' \
    "$TMPDIR/snapper-init.service" \
    "a mere marker path cannot condition-skip rollback-model verification"
assert_grep_fixed 'trap cleanup_init EXIT' "$TMPDIR/snapper-init.sh" \
    "initializer cleanup remains active on every exit"
for signal_trap in \
    "trap 'exit 129' HUP" \
    "trap 'exit 130' INT" \
    "trap 'exit 143' TERM"; do
    assert_grep_fixed "$signal_trap" "$TMPDIR/snapper-init.sh" \
        "initializer signal handling exits instead of continuing boot mutation"
done
assert_not_grep 'trap cleanup_init EXIT HUP INT TERM' "$TMPDIR/snapper-init.sh" \
    "initializer never swallows termination through a shared cleanup trap"
assert_grep_fixed '[ -n "$fstab_new" ] && ! rm -f -- "$fstab_new"' \
    "$TMPDIR/snapper-init.sh" \
    "initializer removes an unpublished fstab candidate on interruption"
assert_grep_fixed '[ -n "$boot_state_new" ] && ! rm -f -- "$boot_state_new"' \
    "$TMPDIR/snapper-init.sh" \
    "initializer removes unpublished boot-state evidence on interruption"
assert_grep_fixed 'temporary Btrfs top-level mount could not be removed' \
    "$TMPDIR/snapper-init.sh" \
    "initializer cannot report success while exposing the Btrfs top level"
assert_grep_fixed 'temporary Btrfs top-level mountpoint is unsafe' \
    "$TMPDIR/snapper-init.sh" \
    "initializer requires an exact private top-level mountpoint"
assert_not_grep 'mkdir -p /var/lib/noid-privacy' "$TMPDIR/snapper-init.sh" \
    "first-boot initializer carries no dead legacy state directory"
assert_not_grep_extended \
    '^(PrivateTmp|PrivateMounts|ProtectSystem|ProtectHome|ProtectKernelLogs|ProtectClock|ProtectKernelTunables|ProtectKernelModules|ProtectControlGroups)=' \
    "$TMPDIR/snapper-init.service" \
    "Snapper initializer has no directive that creates a private mount namespace"
assert_not_grep 'snapper .*create-config' "$TMPDIR/snapper-init.sh" \
    "first boot never overwrites the reviewed root config as a fallback"
assert_grep_fixed 'btrfs subvolume set-default "$root_id" /' "$TMPDIR/snapper-init.sh" \
    "running root becomes the native Btrfs default before selector removal"
assert_grep_fixed '--remove-args="rootflags=subvol=root rootflags=subvol=/root"' \
    "$TMPDIR/snapper-init.sh" "BLS root selector is removed explicitly"
assert_grep_fixed '/usr/libexec/noid-rebind-firstboot-rootflags --prepare' \
    "$TMPDIR/snapper-init.sh" \
    "M20 binds the planned topology bytes before grubby publication"
assert_grep_fixed '/usr/libexec/noid-rebind-firstboot-rootflags --verify' \
    "$TMPDIR/snapper-init.sh" \
    "M20 verifies M01 evidence after grubby publication"
assert_grep_fixed 'subvol=snapshots,nosuid,nodev,noexec' "$TMPDIR/snapper-init.sh" \
    "snapshot store is a stable hardened top-level mount"
assert_grep_fixed 'subvol=libvirt,nosuid,nodev' "$TMPDIR/snapper-init.sh" \
    "libvirt store is a stable top-level mount"
layout_sync_line=$(grep -nF 'sync -- "$TOP/snapshots" "$TOP/libvirt" "$TOP"' \
    "$TMPDIR/snapper-init.sh" | cut -d: -f1 || true)
set_default_line=$(grep -nF 'btrfs subvolume set-default "$root_id" /' \
    "$TMPDIR/snapper-init.sh" | cut -d: -f1 || true)
if [ -n "$layout_sync_line" ] && [ -n "$set_default_line" ] \
        && [ "$layout_sync_line" -lt "$set_default_line" ]; then
    _pass "stable subvolume metadata is durable before boot selection changes"
else
    _fail "boot selection can outlive unpublished stable subvolume metadata"
fi
assert_grep_fixed '[ ! -L /.snapshots ] || fail "/.snapshots is a symlink"' \
    "$TMPDIR/snapper-init.sh" "snapshot mountpoint rejects symlinks before mutation"
assert_grep_fixed '[ ! -L /var/lib/libvirt ] || fail "/var/lib/libvirt is a symlink"' \
    "$TMPDIR/snapper-init.sh" "libvirt mountpoint rejects symlinks before mutation"
assert_grep_fixed '/var/lib/libvirt contains non-directory state; explicit migration required' \
    "$TMPDIR/snapper-init.sh" \
    "every populated libvirt entry type is visible failure, not false success"
assert_grep_fixed 'find /var/lib/libvirt -mindepth 1 ! -type d -print -quit' \
    "$TMPDIR/snapper-init.sh" \
    "libvirt migration rejects symlinks, devices and FIFOs as well as files and sockets"
assert_grep_fixed 'libvirt is active before nested storage migration' \
    "$TMPDIR/snapper-init.sh" "nested libvirt migration refuses live VM services"
# Each gate must re-read the daemon state. A single snapshot taken before the
# first gate cannot observe the "became active" case the third gate reports.
assert_eq 3 "$(grep -c '^[[:space:]]*libvirt_idle ' "$TMPDIR/snapper-init.sh")" \
    "every libvirt storage gate re-samples the daemons instead of a stale flag"
assert_not_grep 'libvirt_busy' "$TMPDIR/snapper-init.sh" \
    "no stale libvirt activity snapshot survives"
set_default_line=$(grep -nF 'btrfs subvolume set-default "$root_id" /' \
    "$TMPDIR/snapper-init.sh" | cut -d: -f1 || true)
grubby_line=$(grep -nF 'grubby --update-kernel=ALL' \
    "$TMPDIR/snapper-init.sh" | cut -d: -f1 || true)
rebind_prepare_line=$(grep -nF '/usr/libexec/noid-rebind-firstboot-rootflags --prepare' \
    "$TMPDIR/snapper-init.sh" | cut -d: -f1 || true)
rebind_verify_line=$(grep -nF '/usr/libexec/noid-rebind-firstboot-rootflags --verify' \
    "$TMPDIR/snapper-init.sh" | cut -d: -f1 || true)
if [ -n "$set_default_line" ] && [ -n "$grubby_line" ] \
        && [ "$set_default_line" -lt "$grubby_line" ]; then
    _pass "power-loss-safe order sets the current default before removing rootflags"
else
    _fail "rootflags are removed before a safe Btrfs default exists"
fi
if [ -n "$rebind_prepare_line" ] && [ -n "$grubby_line" ] \
        && [ -n "$rebind_verify_line" ] \
        && [ "$rebind_prepare_line" -lt "$grubby_line" ] \
        && [ "$grubby_line" -lt "$rebind_verify_line" ]; then
    _pass "M01 evidence handoff brackets the complete rootflags publication"
else
    _fail "rootflags publication escapes the M01 evidence handoff"
fi
assert_not_grep 'systemctl daemon-reload.*[|][|][[:space:]]*true' "$KS_FILE" \
    "systemd reload failure is not swallowed"
assert_grep_fixed 'mv -fT -- "$fstab_new" /etc/fstab' "$TMPDIR/snapper-init.sh" \
    "rollback-model fstab publishes through exact-target atomic rename"
assert_grep_fixed 'sync -- /etc' "$TMPDIR/snapper-init.sh" \
    "fstab publication makes its directory entry durable"
assert_grep_fixed 'mv -fT -- "$boot_state_new" "$boot_state"' \
    "$TMPDIR/snapper-init.sh" "boot-model evidence publishes atomically"
assert_grep_fixed 'sync -- /.snapshots/.noid-state' "$TMPDIR/snapper-init.sh" \
    "first-boot evidence makes stable state-directory metadata durable"

# X-GNOME-Autostart-Phase MUST NOT be present as an active .desktop
# entry line (GNOME 49+ bug). Comments about the removal are allowed.
if grep -Pn '^\s*X-GNOME-Autostart-Phase\s*=' "$KS_FILE" >/dev/null 2>&1; then
    _fail "X-GNOME-Autostart-Phase= line present (regression)"
else
    _pass "no active X-GNOME-Autostart-Phase= line (hold)"
fi

# dnf-plugin-snapper for pre/post snapshot hooks
assert_grep_extended 'dnf-plugin-snapper|dnf-plugins.*snapper|python3-dnf-plugin-snapper' "$KS_FILE"

# Correct permissions on config file (640 = root-read + root-write only)
assert_grep_extended 'chmod 640 /etc/snapper/configs/root|chmod 0640 /etc/snapper/configs/root' "$KS_FILE"

# Snapshot mutation stays root-only; a fixed helper provides sanitized status.
assert_grep_fixed 'ALLOW_GROUPS=""' "$KS_FILE" \
    "snapper config grants no non-root group"
assert_grep_fixed 'SYNC_ACL="no"' "$KS_FILE" \
    "snapper config SYNC_ACL=no (Privacy-Minimization)"
assert_grep_fixed 'SPACE_LIMIT="0.5"' "$KS_FILE" \
    "inactive space hint retains a valid upstream-parsable value"
assert_grep_fixed 'FREE_LIMIT="0.2"' "$KS_FILE" \
    "inactive free-space hint retains a valid upstream-parsable value"
assert_not_grep 'SPACE_LIMIT=""\|FREE_LIMIT=""' "$KS_FILE" \
    "Snapper cleanup cannot emit empty-limit parse errors"
assert_grep_fixed 'grep -qxF "$snapper_config_entry" /etc/snapper/configs/root' \
    "$KS_FILE" "M20 verifies every deployed root-config value exactly"
assert_grep_fixed 'Snapper root config drifted' "$KS_FILE" \
    "M20 fails closed on root-config writer/postcondition drift"
assert_grep_fixed 'Neither setting guarantees a minimum 30-day history.' "$KS_FILE" \
    "recovery guide discloses the independent count and age bounds"
assert_grep_fixed 'timer is a notification only' "$KS_FILE" \
    "recovery guide does not misreport the update reminder as execution"
assert_not_grep 'outside weekly noid-update-all.sh' "$KS_FILE" \
    "ad-hoc guidance treats the update orchestrator as user-invoked"
assert_grep_fixed 'frequent ad-hoc' "$KS_FILE" \
    "retention guidance discloses early count-bound eviction"
assert_grep_fixed '`/var/tmp/` — it is aged as temporary data, but remains in the root' \
    "$KS_FILE" "rollback guide correctly includes disk-backed /var/tmp"
assert_grep_fixed 'VM disks and runtime state stay on the stable' \
    "$KS_FILE" "rollback guide discloses the stable libvirt exclusion"
assert_grep_fixed 'legacy Python DNF4 plugin that DNF5 does not load' "$KS_FILE" \
    "DNF plugin rationale distinguishes incompatibility from non-integration"
assert_not_grep 'breaks dnf5\|breaks with dnf5' "$KS_FILE" \
    "DNF4 plugin is not falsely claimed to break DNF5"
assert_grep_fixed 'outside this image'\''s reviewed' "$KS_FILE" \
    "grub-btrfs exclusion is tied to the reviewed product contract"
assert_not_grep 'grub-btrfs.*broken for Fedora' "$KS_FILE" \
    "grub-btrfs exclusion avoids an unsupported universal breakage claim"
assert_not_grep 'safety cap for the rare case' "$KS_FILE" \
    "retention guidance cannot misstate count cleanup as a rare fallback"
assert_not_grep 'restorecon -R ' "$KS_FILE" \
    "regular-file SELinux reconciliation is non-recursive"
assert_not_grep 'restorecon.*2>/dev/null.*|| true' "$KS_FILE" \
    "M20 SELinux reconciliation cannot hide a failure"
assert_grep_fixed 'SELinux label reconciliation failed' "$KS_FILE" \
    "M20 exact SELinux reconciliation is fail-closed"
assert_grep_fixed 'removed at the next qualifying rotation' "$RETENTION_DOC" \
    "retention matrix states logrotate maxage timing exactly"
assert_grep_fixed "grep -cE '^[[:space:]]*weekly[[:space:]]*$'" "$KS_FILE" \
    "Snapper log rotation pins its weekly cadence locally"
assert_not_grep 'snapper.log` | weekly or at 10 MiB; archives max 30 days' \
    "$RETENTION_DOC" \
    "retention matrix makes no exact day-30 Snapper-log promise"
assert_not_grep_extended 'Runs once per system|we only want pre-update snapshots' \
    "$KS_FILE" \
    "Snapper comments match the recurring boot gate and explicit snapshot policy"

for spec in \
    'SNAPPER_CREATE_EOF:snapper-create.sh' \
    'SNAPPER_STATUS_EOF:snapper-status.sh' \
    'SNAPPER_ROLLBACK_EOF:snapper-rollback.sh' \
    'SNAP_PRE_EOF:snap-pre.sh'; do
    marker=${spec%%:*}; output=${spec#*:}
    extract_heredoc "$KS_FILE" "$marker" "$TMPDIR/$output" \
        || _fail "$marker extraction"
    assert_cmd_success "$marker parses" bash -n "$TMPDIR/$output"
    assert_cmd_success "$marker passes ShellCheck" \
        shellcheck -S warning "$TMPDIR/$output"
done
assert_grep_fixed '5%/2-GiB operational reserve' "$TMPDIR/snapper-create.sh" \
    "canonical snapshot creator enforces measured free-space preflight"
assert_grep_fixed 'snapshot creation is blocked until the rollback boot model is ready' \
    "$TMPDIR/snapper-create.sh" \
    "canonical creator refuses a selected or degraded rollback transition"
assert_cmd_success "ad-hoc rollback helper help is unprivileged and side-effect-free" \
    bash "$TMPDIR/snap-pre.sh" --help
set +e
bash "$TMPDIR/snap-pre.sh" one two >/dev/null 2>&1
snap_pre_extra_rc=$?
set -e
assert_eq 2 "$snap_pre_extra_rc" \
    "ad-hoc rollback helper rejects ambiguous extra descriptions"
assert_grep_fixed '/usr/libexec/noid-snapper-create single "$DESC"' \
    "$TMPDIR/snap-pre.sh" \
    "standalone ad-hoc point uses Snapper single rather than orphaned pre"
assert_not_grep '/usr/libexec/noid-snapper-create pre "$DESC"' \
    "$TMPDIR/snap-pre.sh" \
    "ad-hoc helper cannot create a pre snapshot without a post pair"
mkdir -p "$TMPDIR/snap-pre-mock-bin"
cat > "$TMPDIR/snap-pre-mock-bin/id" <<'SNAP_PRE_ID_MOCK_EOF'
#!/bin/bash
[ "${1:-}" = -u ] || exit 2
printf '0\n'
SNAP_PRE_ID_MOCK_EOF
cat > "$TMPDIR/snap-pre-create-mock" <<'SNAP_PRE_CREATE_MOCK_EOF'
#!/bin/bash
printf '%s\n' "$*" > "$MOCK_SNAP_PRE_CALL"
printf '73\n'
SNAP_PRE_CREATE_MOCK_EOF
chmod 0755 "$TMPDIR/snap-pre-mock-bin/id" "$TMPDIR/snap-pre-create-mock"
sed "s#/usr/libexec/noid-snapper-create#$TMPDIR/snap-pre-create-mock#g" \
    "$TMPDIR/snap-pre.sh" > "$TMPDIR/snap-pre-fixture.sh"
if snap_pre_output=$(env PATH="$TMPDIR/snap-pre-mock-bin:$PATH" \
        MOCK_SNAP_PRE_CALL="$TMPDIR/snap-pre.call" \
        bash "$TMPDIR/snap-pre-fixture.sh" "before fixture operation" 2>&1); then
    _pass "ad-hoc helper executes the standalone creator path"
else
    _fail "ad-hoc helper executes the standalone creator path: $snap_pre_output"
fi
assert_eq 'single before fixture operation' "$(cat "$TMPDIR/snap-pre.call")" \
    "ad-hoc helper passes the exact single-snapshot argv"
printf '%s\n' "$snap_pre_output" > "$TMPDIR/snap-pre.output"
assert_grep_fixed 'Standalone rollback snapshot #73 created: before fixture operation' \
    "$TMPDIR/snap-pre.output" \
    "ad-hoc helper reports the created standalone rollback point"
if snap_pre_embedded_output=$(env PATH="$TMPDIR/snap-pre-mock-bin:$PATH" \
        MOCK_SNAP_PRE_CALL="$TMPDIR/snap-pre-embedded.call" \
        bash "$TMPDIR/snap-pre-fixture.sh" --embedded \
        "before embedded fixture operation" 2>&1); then
    _pass "embedded rollback helper executes the same standalone creator path"
else
    _fail "embedded rollback helper executes the creator path: $snap_pre_embedded_output"
fi
assert_eq 'single before embedded fixture operation' \
    "$(cat "$TMPDIR/snap-pre-embedded.call")" \
    "embedded helper preserves the exact snapshot description"
assert_eq 'Rollback snapshot #73 created.' "$snap_pre_embedded_output" \
    "embedded helper emits one concise caller-owned progress line"
printf '%s\n' "$snap_pre_embedded_output" > "$TMPDIR/snap-pre-embedded.output"
assert_not_grep 'Next: run your operation' \
    "$TMPDIR/snap-pre-embedded.output" \
    "embedded helper does not interrupt its parent workflow with standalone guidance"
assert_grep_fixed '[ "$#" -eq 0 ] || exit 2' "$TMPDIR/snapper-status.sh" \
    "privileged status helper accepts no user-controlled argument"
assert_grep_fixed 'boot_model=reboot-required' "$TMPDIR/snapper-status.sh" \
    "published rollback default is a distinct valid pre-reboot state"
assert_grep_fixed 'boot_sources_ready()' "$TMPDIR/snapper-status.sh" \
    "status validates future-kernel and every BLS boot source"
assert_grep_fixed 'fstab_contract_ready()' "$TMPDIR/snapper-status.sh" \
    "status validates the complete stable-mount fstab contract"
assert_grep_fixed \
    '$4 != "subvol=snapshots,nosuid,nodev,noexec,x-systemd.device-timeout=0"' \
    "$TMPDIR/snapper-status.sh" \
    "status accepts only the exact NoID Privacy-owned hardened snapshot mount row"
assert_grep_fixed 'matchpathcon -V /.snapshots/.noid-state' \
    "$TMPDIR/snapper-status.sh" \
    "status rejects an unlabeled stable snapshot-state directory"
assert_grep_fixed 'matchpathcon -V "$state"' "$TMPDIR/snapper-status.sh" \
    "status rejects mislabeled boot-model evidence"
assert_grep_fixed '%wheel ALL=(root) NOPASSWD: NOID_SNAPPER_STATUS' "$KS_FILE" \
    "sudo boundary permits only the fixed status command"
assert_grep_fixed 'Cmnd_Alias NOID_SNAPPER_STATUS = /usr/libexec/noid-snapper-status ""' \
    "$KS_FILE" "sudo boundary permits no status-helper arguments"
assert_grep_fixed 'verify_published_default "$new_number"' "$TMPDIR/snapper-rollback.sh" \
    "rollback verifies the exact read-write Btrfs default before success"
assert_grep_fixed \
    '$4 != "subvol=libvirt,nosuid,nodev,x-systemd.device-timeout=0"' \
    "$TMPDIR/snapper-rollback.sh" \
    "rollback accepts only the exact NoID Privacy-owned isolated libvirt mount row"
assert_grep_fixed '[ "$current_root_id" = "$original_default_id" ]' \
    "$TMPDIR/snapper-rollback.sh" \
    "classic rollback ambit is bound to the verified running Btrfs default"
assert_grep_fixed 'snapper --quiet --ambit classic -c root rollback --print-number' \
    "$TMPDIR/snapper-rollback.sh" \
    "rollback suppresses progress text and bypasses only failed ambit auto-detection"
assert_not_grep 'snapper -c root rollback --print-number' \
    "$TMPDIR/snapper-rollback.sh" \
    "rollback never depends on Snapper auto ambit detection"
assert_grep_fixed 'rollback.pending' "$TMPDIR/snapper-rollback.sh" \
    "rollback interruption leaves persistent evidence"
assert_grep_fixed 'ORIGINAL_DEFAULT_ID=%s' "$TMPDIR/snapper-rollback.sh" \
    "pending rollback binds resume to the original Btrfs default"
assert_grep_fixed 'mv -fT -- "$pending_new" "$pending"' \
    "$TMPDIR/snapper-rollback.sh" "pending rollback evidence publishes atomically"
assert_grep_fixed 'mv -fT -- "$ready_new" "$ready"' \
    "$TMPDIR/snapper-rollback.sh" "ready rollback evidence publishes atomically"
assert_grep_fixed 'sync -- /.snapshots/.noid-state' \
    "$TMPDIR/snapper-rollback.sh" \
    "rollback evidence rename and retirement are directory-durable"
assert_grep_fixed 'matchpathcon -V /.snapshots/.noid-state' \
    "$TMPDIR/snapper-rollback.sh" \
    "rollback refuses an unlabeled stable state boundary"
assert_grep_fixed 'matchpathcon -V "$pending"' "$TMPDIR/snapper-rollback.sh" \
    "rollback authenticates the pending record label before resume"
assert_grep_fixed 'matchpathcon -V "$ready"' "$TMPDIR/snapper-rollback.sh" \
    "rollback verifies the published ready-record label"
assert_grep_fixed 'trap cleanup_rollback_candidates EXIT' \
    "$TMPDIR/snapper-rollback.sh" \
    "rollback removes unpublished state candidates on every exit"
for signal_trap in \
    "trap 'exit 129' HUP" \
    "trap 'exit 130' INT" \
    "trap 'exit 143' TERM"; do
    assert_grep_fixed "$signal_trap" "$TMPDIR/snapper-rollback.sh" \
        "rollback signal handling exits instead of continuing root selection"
done
assert_not_grep 'trap .* EXIT HUP INT TERM' \
    "$TMPDIR/snapper-rollback.sh" \
    "rollback never swallows termination through a shared cleanup trap"
assert_grep_fixed '[ -n "$pending_new" ] && ! rm -f -- "$pending_new"' \
    "$TMPDIR/snapper-rollback.sh" \
    "rollback interruption removes only its unpublished pending candidate"
assert_grep_fixed '[ -n "$ready_new" ] && ! rm -f -- "$ready_new"' \
    "$TMPDIR/snapper-rollback.sh" \
    "rollback interruption removes only its unpublished ready candidate"
assert_grep_fixed '[ "$cleanup_failed" -eq 0 ] || [ "$rc" -ne 0 ] || rc=1' \
    "$TMPDIR/snapper-rollback.sh" \
    "rollback cannot report success when candidate cleanup fails"
assert_grep_fixed 'NoID Privacy rollback to snapshot $target_number' "$TMPDIR/snapper-rollback.sh" \
    "resume accepts only the recorded target's exact rollback artifact"
assert_grep_fixed "*' boot=reboot-required '*)" "$TMPDIR/snapper-rollback.sh" \
    "resume accepts the verified default-selected pre-reboot state"
assert_grep_fixed 'snapshot_kernel_cmdline_safe "$number"' "$TMPDIR/snapper-rollback.sh" \
    "rollback verifies future-kernel command-line safety"
assert_grep_fixed 'BOOT_LOCK=/run/lock/noid-boot-mutation.lock' \
    "$TMPDIR/snapper-rollback.sh" "rollback joins the global boot transaction"
assert_grep_fixed 'BOOT_GUARD=/usr/libexec/noid-boot-mutation-guard' \
    "$TMPDIR/snapper-rollback.sh" "rollback requires the central basis guard"
assert_grep_fixed 'flock -w 300 8' "$TMPDIR/snapper-rollback.sh" \
    "rollback waits on the global boot lock"
assert_grep_fixed 'guard_args=(--snapper-resume)' "$TMPDIR/snapper-rollback.sh" \
    "only the checked resume path requests the narrow guard exception"
assert_grep_fixed 'boot_basis=$("$BOOT_GUARD" "${guard_args[@]}")' \
    "$TMPDIR/snapper-rollback.sh" "rollback binds itself to the guarded M21 basis"
boot_lock_line=$(grep -nF 'flock -w 300 8' "$TMPDIR/snapper-rollback.sh" | cut -d: -f1 || true)
rollback_lock_line=$(grep -nF 'flock -n 9' "$TMPDIR/snapper-rollback.sh" | cut -d: -f1 || true)
publish_default_line=$(grep -nF 'snapper --quiet --ambit classic -c root rollback --print-number' \
    "$TMPDIR/snapper-rollback.sh" | cut -d: -f1 || true)
if [ -n "$boot_lock_line" ] && [ -n "$rollback_lock_line" ] \
        && [ -n "$publish_default_line" ] \
        && [ "$boot_lock_line" -lt "$rollback_lock_line" ] \
        && [ "$rollback_lock_line" -lt "$publish_default_line" ]; then
    _pass "global boot lock precedes the local rollback lock and default publication"
else
    _fail "Snapper rollback lock ordering does not protect the complete boot transaction"
fi
assert_grep_fixed 'central guard refuses every later initramfs' "$KS_FILE" \
    "user documentation names the post-selection boot-mutation freeze"
assert_grep_fixed 'Do not bypass the wrapper' "$KS_FILE" \
    "user documentation forbids raw rollback and boot-writer bypasses"

# Strict privacy retention: important/baseline snapshots must not bypass the
# 30-day time cutoff. Count-based Snapper cleanup may still prioritize them
# inside that window, but the NoID Privacy prune script has no indefinite exception.
extract_heredoc "$KS_FILE" "SNAPPER_PRUNE_EOF" "$TMPDIR/snapper-prune.sh" \
    || _fail "snapper prune heredoc extraction"
assert_cmd_success "snapper pruner passes ShellCheck" \
    shellcheck -S warning "$TMPDIR/snapper-prune.sh"
assert_grep_fixed 'CUTOFF_DAYS=30' "$TMPDIR/snapper-prune.sh"
assert_grep_fixed 'matchpathcon -V "$STATE_DIR"' "$TMPDIR/snapper-prune.sh" \
    "production retention refuses an unlabeled stable state directory"
assert_grep_fixed 'set -o pipefail' "$TMPDIR/snapper-prune.sh" \
    "Snapper-list producer failure cannot be hidden by valid JSON output"
assert_grep_fixed 'trap cleanup_prune_candidates EXIT' "$TMPDIR/snapper-prune.sh" \
    "pruner cleans private candidates on every exit"
for signal_trap in \
    "trap 'exit 129' HUP" \
    "trap 'exit 130' INT" \
    "trap 'exit 143' TERM"; do
    assert_grep_fixed "$signal_trap" "$TMPDIR/snapper-prune.sh" \
        "pruner signal handling exits instead of continuing deletion"
done
assert_not_grep 'trap .* EXIT HUP INT TERM' \
    "$TMPDIR/snapper-prune.sh" \
    "pruner never swallows termination through a shared cleanup trap"
assert_grep_fixed 'validate_clock_state "$NOW_EPOCH"' "$TMPDIR/snapper-prune.sh" \
    "retention clock publication has an exact schema postcondition"
assert_not_grep 'SKIPPED_IMPORTANT' "$TMPDIR/snapper-prune.sh" \
    "snapper prune has no important=yes retention bypass"
assert_not_grep 'preserved important snapshot' "$TMPDIR/snapper-prune.sh" \
    "snapper prune does not preserve important snapshots indefinitely"
assert_grep_fixed '"$SNAPPER" -c root delete --sync "$num"' "$TMPDIR/snapper-prune.sh"
assert_grep_fixed 'FAILURES=$((FAILURES + 1))' "$TMPDIR/snapper-prune.sh" \
    "snapshot metadata/deletion failures are counted"
assert_grep_fixed '[ "$FAILURES" -eq 0 ] || exit 1' "$TMPDIR/snapper-prune.sh" \
    "snapshot retention failures propagate to systemd"
assert_grep_fixed 'row.get("default")' "$TMPDIR/snapper-prune.sh" \
    "pruner consumes authoritative default state"
assert_grep_fixed 'row.get("active")' "$TMPDIR/snapper-prune.sh" \
    "pruner consumes authoritative active state"
assert_grep_fixed 'state=protected' "$TMPDIR/snapper-prune.sh" \
    "undeletable active/default roots are surfaced explicitly"
assert_grep_fixed 'clock continuity not established' "$TMPDIR/snapper-prune.sh" \
    "large or first-observation clock state defers destructive expiry"
assert_grep_fixed 'MAX_FUTURE_SKEW=300' "$TMPDIR/snapper-prune.sh" \
    "future-dated snapshot metadata has a bounded tolerance"
assert_grep_fixed 'sync -- "$CLOCK_STATE"' "$TMPDIR/snapper-prune.sh" \
    "retention clock anchor is durably published"
assert_grep_fixed 'sync -- "$STATUS_FILE"' "$TMPDIR/snapper-prune.sh" \
    "retention result is durably published"
assert_grep_fixed 'retire_status || true' "$TMPDIR/snapper-prune.sh" \
    "failed retention publication retires prior status evidence"
assert_not_grep 'write_status degraded 0 0 0 1 || true' \
    "$TMPDIR/snapper-prune.sh" \
    "failed degraded publication is diagnosed rather than silently swallowed"
assert_grep_fixed 'sync -- "$STATE_DIR"' "$TMPDIR/snapper-prune.sh" \
    "retention rename metadata is durable in the stable state directory"
assert_grep_fixed 'stable snapshot-state mount unavailable' "$TMPDIR/snapper-prune.sh" \
    "production pruner refuses rollback-local state storage"
assert_grep_fixed 'RequiresMountsFor=/.snapshots' "$KS_FILE" \
    "pruner unit requires the stable snapshot mount"
assert_grep_fixed 'ReadWritePaths=/var/log -/.snapshots/.noid-state' "$KS_FILE" \
    "missing state cannot fail before the pruner's own diagnostic"
assert_grep_fixed 'systemctl disable snapper-timeline.timer snapper-boot.timer' \
    "$KS_FILE" \
    "explicit-only policy disables both automatic snapshot timers"

# The reviewed root config targets installed Btrfs `/`. The enabled vendor
# cleanup and project prune timers must not schedule on the Live overlay, and
# the services independently reject direct activation there.
for spec in \
    'CLEANUP_TIMER_EOF:snapper-cleanup.timer' \
    'CLEANUP_SERVICE_EOF:snapper-cleanup.service' \
    'SNAPPER_PRUNE_SERVICE_EOF:noid-snapper-prune.service' \
    'SNAPPER_PRUNE_TIMER_EOF:noid-snapper-prune.timer'; do
    marker=${spec%%:*}; output=${spec#*:}
    extract_heredoc "$KS_FILE" "$marker" "$TMPDIR/$output" \
        || _fail "$marker extraction"
    assert_eq 1 \
        "$(grep -c '^ConditionKernelCommandLine=!rd\.live\.image$' "$TMPDIR/$output")" \
        "$output has one exact installed-only lifecycle guard"
done
assert_grep_fixed 'OnCalendar=daily' "$TMPDIR/snapper-cleanup.timer" \
    "vendor cleanup retains the deterministic installed schedule"
assert_grep_fixed 'Persistent=true' "$TMPDIR/snapper-cleanup.timer" \
    "vendor cleanup retains installed catch-up semantics"
assert_grep_fixed 'Requires=noid-snapper-init.service' \
    "$TMPDIR/snapper-cleanup.service" \
    "vendor cleanup requires the verified Snapper boot gate"
assert_grep_fixed 'After=noid-snapper-init.service' \
    "$TMPDIR/snapper-cleanup.service" \
    "persistent cleanup catch-up cannot race first-boot topology publication"
assert_grep_fixed 'OnCalendar=07:40:00' "$TMPDIR/noid-snapper-prune.timer" \
    "30-day pruner retains the installed schedule"
assert_grep_fixed 'Persistent=true' "$TMPDIR/noid-snapper-prune.timer" \
    "30-day pruner retains installed catch-up semantics"
assert_grep_fixed 'assert_live_condition_rejects snapper-cleanup.timer' \
    "$RUNTIME_GATE" "VM gate proves the vendor timer is inactive on Live"
assert_grep_fixed 'assert_live_condition_rejects snapper-cleanup.service' \
    "$RUNTIME_GATE" "VM gate proves direct vendor cleanup is refused on Live"
assert_grep_fixed 'assert_live_condition_rejects noid-snapper-prune.timer' \
    "$RUNTIME_GATE" "VM gate proves the project prune timer is inactive on Live"
assert_grep_fixed 'assert_installed_timer snapper-cleanup.timer' \
    "$RUNTIME_GATE" "VM gate proves the vendor timer is scheduled after install"
assert_grep_fixed 'assert_installed_timer noid-snapper-prune.timer' \
    "$RUNTIME_GATE" "VM gate proves the project prune timer is scheduled after install"

cat > "$TMPDIR/mock-snapper" <<'MOCK_SNAPPER_EOF'
#!/bin/bash
printf 'bad=%s args=' "${MOCK_BAD:-unset}" >> "$MOCK_CALL_LOG"
printf '%q ' "$@" >> "$MOCK_CALL_LOG"
printf '\n' >> "$MOCK_CALL_LOG"
if [ "${MOCK_BAD:-0}" = 1 ]; then
    printf '%s\n' '{bad json'
    exit 0
fi
if [ "${MOCK_FUTURE:-0}" = 1 ]; then
    printf '%s\n' '{"root":[{"number":9,"default":false,"active":false,"date":"2099-01-01T00:00:00+00:00"}]}'
    exit 0
fi
if [ "${MOCK_PIPEFAIL:-0}" = 1 ]; then
    printf '%s\n' '{"root":[{"number":2,"default":false,"active":false,"date":"2020-01-02T00:00:00+00:00"}]}'
    exit 74
fi
if [ "${MOCK_SIGNAL_DELETE:-0}" = 1 ]; then
    case " $* " in
        *' list '*)
            printf '%s\n' '{"root":[
 {"number":1,"default":true,"active":false,"date":"2020-01-01T00:00:00+00:00"},
 {"number":2,"default":false,"active":false,"date":"2020-01-02T00:00:00+00:00"},
 {"number":4,"default":false,"active":false,"date":"2020-01-04T00:00:00+00:00"}
]}'
            exit 0
            ;;
        *' delete --sync 2 '*)
            printf '%s\n' "$*" >> "$MOCK_DELETE_LOG"
            kill -TERM "$PPID"
            sleep 0.2
            exit 0
            ;;
        *' delete --sync '*)
            printf '%s\n' "$*" >> "$MOCK_DELETE_LOG"
            exit 0
            ;;
    esac
fi
case " $* " in
    *' list '*)
        cat <<'JSON_EOF'
{"root":[
 {"number":0,"default":false,"active":false,"date":""},
 {"number":1,"default":true,"active":false,"date":"2020-01-01T00:00:00+00:00"},
 {"number":2,"default":false,"active":false,"date":"2020-01-02T00:00:00+00:00"},
 {"number":3,"default":false,"active":false,"date":"2033-05-10T00:00:00+00:00"}
]}
JSON_EOF
        ;;
    *' delete --sync '*) printf '%s\n' "$*" >> "$MOCK_DELETE_LOG" ;;
    *) exit 2 ;;
esac
MOCK_SNAPPER_EOF
chmod 0755 "$TMPDIR/mock-snapper"
mkdir -p "$TMPDIR/prune-state"
chmod 0700 "$TMPDIR/prune-state"
: > "$TMPDIR/delete.log"
: > "$TMPDIR/call.log"
prune_env=(
    NOID_SNAPPER_LOGGER=/bin/true
    NOID_SNAPPER_BIN="$TMPDIR/mock-snapper"
    NOID_SNAPPER_STATE_DIR="$TMPDIR/prune-state"
    MOCK_DELETE_LOG="$TMPDIR/delete.log"
    MOCK_CALL_LOG="$TMPDIR/call.log"
)
assert_cmd_success "first retention observation establishes clock anchor only" \
    env "${prune_env[@]}" NOID_SNAPPER_NOW_EPOCH=2000000000 \
        bash "$TMPDIR/snapper-prune.sh"
assert_eq "" "$(cat "$TMPDIR/delete.log")" \
    "clock guard performs no destructive deletion"
if prune_output=$(env "${prune_env[@]}" NOID_SNAPPER_NOW_EPOCH=2000000060 \
        bash "$TMPDIR/snapper-prune.sh" 2>&1); then
    _pass "stable retention run deletes only eligible old snapshot"
else
    _fail "stable retention run deletes only eligible old snapshot: $prune_output; calls=$(tr '\n' ';' < "$TMPDIR/call.log")"
fi
assert_grep_fixed '-c root delete --sync 2' "$TMPDIR/delete.log" \
    "eligible old snapshot is deleted through the root config"
assert_not_grep 'delete --sync 1' "$TMPDIR/delete.log" \
    "old default snapshot remains protected"
assert_grep_fixed 'STATUS=protected' "$TMPDIR/prune-state/retention.status" \
    "protected retention exception is durable status"

# A publication failure during a malformed-state pass must not leave the
# previous successful `protected` status available to the fixed reader.
# shellcheck disable=SC2317,SC2329 # exported failure-injection command double.
mv() {
    local target="${*: -1}"
    if [ -n "${MOCK_FAIL_MV_TARGET:-}" ] \
       && [ "$target" = "$MOCK_FAIL_MV_TARGET" ]; then
        return 70
    fi
    command mv "$@"
}
export -f mv
if env "${prune_env[@]}" MOCK_BAD=1 \
        MOCK_FAIL_MV_TARGET="$TMPDIR/prune-state/retention.status" \
        NOID_SNAPPER_NOW_EPOCH=2000000120 \
        bash "$TMPDIR/snapper-prune.sh" >/dev/null 2>&1; then
    _fail "malformed Snapper JSON with failed status publication was accepted"
else
    _pass "malformed Snapper JSON preserves its original failure"
fi
if [ ! -e "$TMPDIR/prune-state/retention.status" ] \
        && [ ! -L "$TMPDIR/prune-state/retention.status" ]; then
    _pass "failed degraded publication retires stale protected evidence"
else
    _fail "failed degraded publication retires stale protected evidence"
fi
unset -f mv

if env "${prune_env[@]}" MOCK_BAD=1 NOID_SNAPPER_NOW_EPOCH=2000000120 \
        bash "$TMPDIR/snapper-prune.sh" >/dev/null 2>&1; then
    _fail "malformed Snapper JSON was accepted"
else
    _pass "malformed Snapper JSON fails visibly"
fi
: > "$TMPDIR/delete.log"
if env "${prune_env[@]}" MOCK_FUTURE=1 NOID_SNAPPER_NOW_EPOCH=2000000180 \
        bash "$TMPDIR/snapper-prune.sh" >/dev/null 2>&1; then
    _fail "future-dated Snapper metadata was accepted"
else
    _pass "future-dated Snapper metadata fails before deletion"
fi
assert_eq "" "$(cat "$TMPDIR/delete.log")" \
    "future-dated metadata causes no destructive deletion"

# A Snapper producer that returns non-zero after emitting valid JSON is still
# a failed authoritative read. Without pipefail, Python's success hides it.
: > "$TMPDIR/delete.log"
if env "${prune_env[@]}" MOCK_PIPEFAIL=1 \
        NOID_SNAPPER_NOW_EPOCH=2000000240 \
        bash "$TMPDIR/snapper-prune.sh" >/dev/null 2>&1; then
    _fail "non-zero Snapper list producer was hidden by valid JSON"
else
    _pass "non-zero Snapper list producer remains a visible failure"
fi
assert_eq "" "$(cat "$TMPDIR/delete.log")" \
    "failed authoritative list performs no destructive deletion"

# TERM during a delete must stop the loop after the in-flight child returns.
# A shared EXIT/TERM cleanup trap would swallow the signal and delete #4 too.
: > "$TMPDIR/delete.log"
if env "${prune_env[@]}" MOCK_SIGNAL_DELETE=1 \
        NOID_SNAPPER_NOW_EPOCH=2000000300 \
        bash "$TMPDIR/snapper-prune.sh" >/dev/null 2>&1; then
    _fail "TERM during retention deletion was swallowed"
else
    _pass "TERM during retention deletion stops the pruner"
fi
assert_grep_fixed '-c root delete --sync 2' "$TMPDIR/delete.log" \
    "signal fixture reached the in-flight eligible deletion"
assert_not_grep 'delete --sync 4' "$TMPDIR/delete.log" \
    "termination prevents every later destructive deletion"

# The privileged fixed-schema reader accepts only exact, internally coherent
# producer output; duplicates and optimistic state/counter mismatches become
# `unknown` instead of silently selecting one STATUS line.
retention_reader="$TMPDIR/retention-status-reader.sh"
sed -n '/^# BEGIN RETENTION_STATUS_READER$/,/^# END RETENTION_STATUS_READER$/p' \
    "$TMPDIR/snapper-status.sh" > "$retention_reader"
# The fragment is sourced into this shell instead of running inside its own
# helper, so it loses that helper's `export PATH LC_ALL=C.UTF-8 TZ=UTC` header.
# It compares `stat -c %F` against the English `directory`/`regular file`
# literals below, and that field is translated: on a localized test host the
# reader would return empty and this fixture would report a defect that does not
# exist in the shipped helper. Reproduce the helper's own parse locale.
LC_ALL=C.UTF-8
export LC_ALL
# shellcheck disable=SC1090
. "$retention_reader"
reader_dir="$TMPDIR/retention-reader"
reader_file="$reader_dir/retention.status"
mkdir -m 0700 "$reader_dir"
reader_uid=$(id -u)
reader_gid=$(id -g)
reader_dir_meta="$reader_uid:$reader_gid:700:directory"
reader_file_meta="$reader_uid:$reader_gid:600:1:regular file"
cat > "$reader_file" <<'RETENTION_STATUS_EOF'
STATUS=protected
REMOVED=1
RECENT=2
PROTECTED=1
FAILURES=0
CHECKED_AT=2033-05-18T03:33:20Z
RETENTION_STATUS_EOF
chmod 0600 "$reader_file"
assert_eq protected \
    "$(read_retention_status "$reader_file" "$reader_file_meta" \
        "$reader_dir_meta" 2000000060)" \
    "retention reader accepts the exact coherent producer schema"
assert_cmd_failure "retention reader rejects evidence older than 48 hours" \
    read_retention_status "$reader_file" "$reader_file_meta" \
        "$reader_dir_meta" 2000172801
assert_cmd_failure "retention reader rejects evidence over five minutes in the future" \
    read_retention_status "$reader_file" "$reader_file_meta" \
        "$reader_dir_meta" 1999999699
printf '%s\n' STATUS=ok >> "$reader_file"
assert_cmd_failure "retention reader rejects duplicate status fields" \
    read_retention_status "$reader_file" "$reader_file_meta" \
        "$reader_dir_meta" 2000000060
sed -i '$d; s/^STATUS=protected$/STATUS=ok/' "$reader_file"
assert_cmd_failure "retention reader rejects optimistic state/counter mismatch" \
    read_retention_status "$reader_file" "$reader_file_meta" \
        "$reader_dir_meta" 2000000060

# EXCLUDE_PATTERN is NOT a valid snapper config option (verified
# against the snapper 0.13.0 config-template + manpage) — unknown keys are
# silently ignored, so the old EXCLUDE_PATTERN line was a pure no-op and was
# removed. snapper's only real exclude is a separate btrfs subvolume; the
# config heredoc now documents that. Assert the corrected guidance is present.
assert_grep_fixed 'NOT a valid snapper option' "$KS_FILE" \
    "M20: EXCLUDE_PATTERN no-op removed, correct (subvolume) mechanism documented"

test_finish

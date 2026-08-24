#!/bin/bash
# 25-update-process-structural — M25 regression test
#
# Covers: noid-update-all.sh contract, check-only AIDE evidence, pending-reboot
# marker, update-reminder user timer, NO X-GNOME-Autostart-Phase.
# Would catch: automatic AIDE trust mutation, wrong marker path, missing
# native permission-policy reconciliation
# re-enforcement, regression of deprecated autostart key.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/25-update-process.ks"
M13_FILE="$PROJECT_ROOT/kickstart/snippets/13-aide-welcome.ks"
M17_FILE="$PROJECT_ROOT/kickstart/snippets/17-gnome-hardening.ks"
M35_FILE="$PROJECT_ROOT/kickstart/snippets/35-thunderbird.ks"
KNOWN_FAILURES="$PROJECT_ROOT/docs/known-failures.md"
TMPDIR="$(mktemp -d /var/tmp/noid-test25.XXXXXX)"
WINDOW_WORKER_PID=
WINDOW_GUARD_PID=
FIREFOX_ZOMBIE_PARENT_PID=
cleanup_test() {
    if [ -n "${FIREFOX_ZOMBIE_PARENT_PID:-}" ]; then
        : > "$TMPDIR/firefox-zombie.release"
        wait "$FIREFOX_ZOMBIE_PARENT_PID" 2>/dev/null || true
    fi
    if [ -n "${WINDOW_GUARD_PID:-}" ]; then
        kill "$WINDOW_GUARD_PID" 2>/dev/null || true
        wait "$WINDOW_GUARD_PID" 2>/dev/null || true
    fi
    if [ -n "${WINDOW_WORKER_PID:-}" ]; then
        kill "$WINDOW_WORKER_PID" 2>/dev/null || true
        wait "$WINDOW_WORKER_PID" 2>/dev/null || true
    fi
    rm -rf "$TMPDIR"
}
trap cleanup_test EXIT

test_start "25-update-process-structural"

assert_file_exists "$KS_FILE"
assert_cmd_success "bash -n $KS_FILE" bash -n "$KS_FILE"
assert_not_grep 'structurally impossible' "$KS_FILE" \
    "resource controls are described as bounds, not impossibility proofs"
assert_not_grep 'guaranteed forward progress' "$KS_FILE" \
    "best-effort I/O is not described as a hard scheduling guarantee"
assert_grep_fixed '9 main update steps + 4 nested' "$KS_FILE" \
    "module inventory counts all four shipped sub-steps"
assert_grep_fixed '8b config-drift evidence' "$KS_FILE" \
    "module inventory names the config-drift evidence sub-step"
assert_not_grep 'systemd-run expands' "$KS_FILE" \
    "retired systemd-run constraints are not presented as active code"
assert_not_grep '/boot/loader/entries is 0700' "$KS_FILE" \
    "retired boot-loader-entry constraints are not presented as active code"

# Main CLI tool + permissions
assert_grep_fixed "/usr/local/bin/noid-update-all.sh" "$KS_FILE"
assert_grep_extended 'chmod 755 /usr/local/bin/noid-update-all\.sh' "$KS_FILE"

# Heredoc marker
assert_grep_fixed 'NOID_UPDATE_EOF' "$KS_FILE"
assert_grep_fixed 'sudo chmod 0700 /boot/grub2' "$KS_FILE" \
    "update workflow restores package-declared GRUB directory mode"
assert_grep_fixed 'sudo ln -s ../default/grub /etc/sysconfig/grub' "$KS_FILE" \
    "update workflow restores the RPM-owned GRUB compatibility symlink"
assert_not_grep_extended '^[[:space:]]*(sudo[[:space:]]+)?rpm[[:space:]]+--restore' "$KS_FILE" \
    "update workflow never overwrites reviewed NoID Privacy customizations wholesale"

# CLI parsing must finish before root checks or any updater side effect.
extract_heredoc "$KS_FILE" "NOID_UPDATE_EOF" "$TMPDIR/noid-update-all.sh" \
    || _fail "noid-update-all extraction"
extract_heredoc "$KS_FILE" "PENDING_REBOOT_EOF" \
    "$TMPDIR/noid-pending-reboot-check.sh" \
    || _fail "pending-reboot notifier extraction"
extract_heredoc "$KS_FILE" "AUTOSTART_EOF" \
    "$TMPDIR/noid-pending-reboot.desktop" \
    || _fail "pending-reboot autostart extraction"
extract_heredoc "$KS_FILE" "NOID_UPDATE_WINDOW_EOF" \
    "$TMPDIR/noid-update-window-active" \
    || _fail "update-window validator extraction"
extract_heredoc "$KS_FILE" "NOID_UPDATE_LOCK_GUARD_EOF" \
    "$TMPDIR/noid-update-lock-guardian" \
    || _fail "update-lock guardian extraction"
extract_heredoc "$KS_FILE" "REBOOT_BLOCK_STATE_EOF" \
    "$TMPDIR/noid-reboot-block-state" \
    || _fail "reboot-block publisher extraction"
extract_heredoc "$KS_FILE" "REBOOT_READINESS_EOF" \
    "$TMPDIR/noid-reboot-readiness" \
    || _fail "canonical reboot-readiness extraction"
extract_heredoc "$M13_FILE" "CLAUDE_INSTALL_EOF" "$TMPDIR/noid-claude-install" \
    || _fail "noid-claude-install extraction"
extract_heredoc "$M13_FILE" "CODEX_INSTALL_EOF" "$TMPDIR/noid-codex-install" \
    || _fail "noid-codex-install extraction"
assert_grep_fixed 'sudo /usr/libexec/noid-snapper-create pre' \
    "$TMPDIR/noid-update-all.sh" \
    "update pre-snapshot uses the canonical measured creator"
assert_grep_fixed 'sudo /usr/libexec/noid-snapper-create post' \
    "$TMPDIR/noid-update-all.sh" \
    "update post-snapshot uses the same canonical creator"
assert_not_grep 'sudo snapper create' "$TMPDIR/noid-update-all.sh" \
    "updater has no weaker direct snapshot-creation path"
sed -n '/^finalize_post_snapshot()/,/^}$/p' \
    "$TMPDIR/noid-update-all.sh" > "$TMPDIR/finalize-post-snapshot.function"
printf '#!/bin/sh\nexit 0\n' > "$TMPDIR/noid-snapper-create"
chmod 0755 "$TMPDIR/noid-snapper-create"
sed -i "s#/usr/libexec/noid-snapper-create#$TMPDIR/noid-snapper-create#g" \
    "$TMPDIR/finalize-post-snapshot.function"
sed -n '/^# Survive a terminal close/,/^trap cleanup EXIT$/p' \
    "$TMPDIR/noid-update-all.sh" \
    | sed -n '/^cleanup()/,/^}$/p' > "$TMPDIR/update-cleanup.function"
assert_cmd_success "post-snapshot finalizer extracts" \
    bash -n "$TMPDIR/finalize-post-snapshot.function"
assert_cmd_success "update cleanup trap extracts" \
    bash -n "$TMPDIR/update-cleanup.function"
assert_cmd_success "reboot-block publisher parses" \
    bash -n "$TMPDIR/noid-reboot-block-state"
assert_cmd_success "reboot-block publisher passes ShellCheck" \
    shellcheck -S warning "$TMPDIR/noid-reboot-block-state"
fixture_uid=$(id -u)
fixture_gid=$(id -g)
mkdir "$TMPDIR/reboot-state"
chmod 0755 "$TMPDIR/reboot-state"
cp -- "$TMPDIR/noid-reboot-block-state" "$TMPDIR/reboot-block-state-fixture"
sed -i \
    -e "s#STATE_DIR=/run/noid-privacy#STATE_DIR=$TMPDIR/reboot-state#" \
    -e 's/^\[ "$(id -u)" -eq 0 \] || fail "must run as root"$/:/' \
    -e "s/0:0/$fixture_uid:$fixture_gid/g" \
    -e "s/-o root -g root/-o $fixture_uid -g $fixture_gid/g" \
    -e "s/chown root:root/chown $fixture_uid:$fixture_gid/g" \
    "$TMPDIR/reboot-block-state-fixture"
chmod 0755 "$TMPDIR/reboot-block-state-fixture"
assert_cmd_success "reboot-block publisher writes a closed atomic record" \
    "$TMPDIR/reboot-block-state-fixture" --publish nvidia kernel-cmdline nvidia
assert_eq $'schema=1\nblockers=kernel-cmdline,nvidia' \
    "$(cat "$TMPDIR/reboot-state/reboot-blocked")" \
    "reboot-block record is sorted, deduplicated and exact"
assert_eq "$fixture_uid:$fixture_gid:644:1" \
    "$(stat -Lc '%u:%g:%a:%h' "$TMPDIR/reboot-state/reboot-blocked")" \
    "reboot-block record has exact publication metadata"
assert_cmd_failure "reboot-block publisher rejects unknown reason codes" \
    "$TMPDIR/reboot-block-state-fixture" --publish arbitrary
assert_cmd_success "reboot-block publisher clears a valid owned record" \
    "$TMPDIR/reboot-block-state-fixture" --clear
assert_cmd_failure "reboot-block publisher refuses a symlink record" \
    bash -c '
        ln -s -- target "$1/reboot-blocked"
        "$2" --clear
    ' _ "$TMPDIR/reboot-state" "$TMPDIR/reboot-block-state-fixture"
rm -f -- "$TMPDIR/reboot-state/reboot-blocked"
assert_cmd_success "canonical reboot-readiness helper parses" \
    bash -n "$TMPDIR/noid-reboot-readiness"
assert_cmd_success "canonical reboot-readiness helper passes ShellCheck" \
    shellcheck -S warning "$TMPDIR/noid-reboot-readiness"
sed -n '/^resolve_reboot_state() {$/,/^}$/p' \
    "$TMPDIR/noid-reboot-readiness" > "$TMPDIR/resolve-reboot-state.function"
run_reboot_matrix_fixture() {
    local kernel=$1 nvidia=$2 firmware=$3 recommended=$4 policy=$5 blockers=$6
    KERNEL_PENDING=$kernel NVIDIA_PENDING=$nvidia FIRMWARE_PENDING=$firmware \
        RECOMMENDED=$recommended POLICY_PENDING=$policy BLOCKERS=$blockers bash -c '
            . "$1"
            resolve_reboot_state "$KERNEL_PENDING" "$NVIDIA_PENDING" \
                "$FIRMWARE_PENDING" "$RECOMMENDED" "$POLICY_PENDING" \
                "$BLOCKERS"
            printf "%s:%s:%s\n" "$REBOOT_ACTIVATION" \
                "$REBOOT_SAFETY" "$REBOOT_BLOCKERS"
        ' _ "$TMPDIR/resolve-reboot-state.function"
}
assert_eq 'required:safe:none' \
    "$(run_reboot_matrix_fixture 1 0 0 0 0 none)" \
    "a verified newer kernel is required and safe"
assert_eq 'required:blocked:nvidia' \
    "$(run_reboot_matrix_fixture 1 0 0 0 0 nvidia)" \
    "activation need and NVIDIA safety remain independent"
assert_eq 'none:blocked:initramfs' \
    "$(run_reboot_matrix_fixture 0 0 0 0 0 initramfs)" \
    "boot repair remains visible without an activation delta"
assert_eq 'recommended:safe:none' \
    "$(run_reboot_matrix_fixture 0 0 0 1 0 none)" \
    "soft reboot advice remains distinct from safety"
assert_eq 'required:safe:none' \
    "$(run_reboot_matrix_fixture 0 0 0 0 1 none)" \
    "prepared firstboot policy is a canonical required activation"
assert_cmd_failure "empty reboot-state flag is rejected by the closed schema" \
    bash -c '. "$1"; resolve_reboot_state "" 0 0 0 0 none' _ \
    "$TMPDIR/resolve-reboot-state.function"
assert_cmd_failure "non-boolean reboot-state flag is rejected" \
    bash -c '. "$1"; resolve_reboot_state 0 0 2 0 0 none' _ \
    "$TMPDIR/resolve-reboot-state.function"

# Execute the complete reader against an isolated NVIDIA evidence tree. M19's
# durable degraded marker must remain reboot-blocking without relying on a
# queued task or a currently active systemd inhibitor.
mkdir -p "$TMPDIR/readiness-bin" "$TMPDIR/readiness-modules/7.1.8-test" \
    "$TMPDIR/readiness-nvidia" "$TMPDIR/readiness-run"
chmod 0755 "$TMPDIR/readiness-nvidia" "$TMPDIR/readiness-run"
cat > "$TMPDIR/readiness-bin/uname" <<'READINESS_UNAME_EOF'
#!/bin/sh
printf '%s\n' 7.1.8-test
READINESS_UNAME_EOF
cat > "$TMPDIR/readiness-bin/modinfo" <<'READINESS_MODINFO_EOF'
#!/bin/sh
if [ -n "${READINESS_MODINFO_VERSION:-}" ]; then
    printf '%s\n' "$READINESS_MODINFO_VERSION"
    exit 0
fi
exit 1
READINESS_MODINFO_EOF
cat > "$TMPDIR/readiness-bin/systemctl" <<'READINESS_SYSTEMCTL_EOF'
#!/bin/sh
printf '%s\n' inactive
exit 3
READINESS_SYSTEMCTL_EOF
chmod 0755 "$TMPDIR/readiness-bin/uname" "$TMPDIR/readiness-bin/modinfo" \
    "$TMPDIR/readiness-bin/systemctl"
cp -- "$TMPDIR/noid-reboot-readiness" "$TMPDIR/reboot-readiness-fixture"
chmod 0755 "$TMPDIR/reboot-readiness-fixture"
sed -i \
    -e "s#PATH=/usr/sbin:/usr/bin#PATH=$TMPDIR/readiness-bin:/usr/sbin:/usr/bin#" \
    -e "s#block_state=/run/noid-privacy/reboot-blocked#block_state=$TMPDIR/readiness-run/reboot-blocked#" \
    -e "s#firstboot_marker=/var/lib/noid-privacy/.firstboot-cmdline-reboot-required#firstboot_marker=$TMPDIR/readiness-run/firstboot-required#" \
    -e "s#nvidia_state_dir=/var/lib/noid-nvidia-integrity#nvidia_state_dir=$TMPDIR/readiness-nvidia#" \
    -e "s#find /lib/modules #find $TMPDIR/readiness-modules #" \
    -e "s#/proc/driver/nvidia/version#$TMPDIR/readiness-nvidia/running-version#" \
    -e "s/!= 0:0:755/!= $fixture_uid:$fixture_gid:755/g" \
    -e "s/= 0:0:600:1/= $fixture_uid:$fixture_gid:600:1/g" \
    "$TMPDIR/reboot-readiness-fixture"
readiness_output=$("$TMPDIR/reboot-readiness-fixture")
assert_grep_fixed 'safety=safe' <(printf '%s\n' "$readiness_output") \
    "managed NVIDIA state with an inactive guard and no failure is safe"
assert_grep_fixed 'blockers=none' <(printf '%s\n' "$readiness_output") \
    "negative NVIDIA fixture proves the reader does not always block"
printf '%s\n' \
    'NVRM version: NVIDIA UNIX Open Kernel Module for x86_64  610.57.04  Release Build  (fixture)' \
    > "$TMPDIR/readiness-nvidia/running-version"
READINESS_MODINFO_VERSION=610.57.04
export READINESS_MODINFO_VERSION
readiness_output=$("$TMPDIR/reboot-readiness-fixture")
assert_grep_fixed 'nvidia_running=610.57.04' \
    <(printf '%s\n' "$readiness_output") \
    "canonical reader accepts the live Open Kernel Module NVRM format"
assert_grep_fixed 'safety=safe' <(printf '%s\n' "$readiness_output") \
    "matching Open Kernel Module runtime and disk versions remain safe"
printf '%s\n' \
    'NVRM version: NVIDIA UNIX x86_64 Kernel Module  610.57.04  Release Build  (fixture)' \
    > "$TMPDIR/readiness-nvidia/running-version"
readiness_output=$("$TMPDIR/reboot-readiness-fixture")
assert_grep_fixed 'nvidia_running=610.57.04' \
    <(printf '%s\n' "$readiness_output") \
    "canonical reader retains the proprietary Kernel Module NVRM format"
unset READINESS_MODINFO_VERSION
rm -f -- "$TMPDIR/readiness-nvidia/running-version"
printf '%s\n' NOID_FIRSTBOOT_CMDLINE_REBOOT_REQUIRED_V2 \
    'active_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
    'desired_sha256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' \
    'prepared_boot_id=00000000-0000-0000-0000-000000000000' \
    'recovery_attempt=0' \
    > "$TMPDIR/readiness-run/firstboot-required"
chmod 0600 "$TMPDIR/readiness-run/firstboot-required"
readiness_output=$("$TMPDIR/reboot-readiness-fixture")
assert_grep_fixed 'activation=required' <(printf '%s\n' "$readiness_output") \
    "safe firstboot policy evidence requires activation in every consumer"
assert_grep_fixed 'safety=safe' <(printf '%s\n' "$readiness_output") \
    "safe firstboot policy evidence does not invent a boot blocker"
rm -f -- "$TMPDIR/readiness-run/firstboot-required"
ln -s -- unsafe-target "$TMPDIR/readiness-run/firstboot-required"
readiness_output=$("$TMPDIR/reboot-readiness-fixture")
assert_grep_fixed 'activation=required' <(printf '%s\n' "$readiness_output") \
    "unsafe firstboot marker still preserves the activation requirement"
assert_grep_fixed 'blockers=state-unsafe' <(printf '%s\n' "$readiness_output") \
    "unsafe firstboot marker blocks restart fail-closed"
rm -f -- "$TMPDIR/readiness-run/firstboot-required"
printf 'status=degraded\nkernel=7.1.8-test\nreason=fixture\n' \
    > "$TMPDIR/readiness-nvidia/degraded"
chmod 0600 "$TMPDIR/readiness-nvidia/degraded"
readiness_output=$("$TMPDIR/reboot-readiness-fixture")
assert_grep_fixed 'safety=blocked' <(printf '%s\n' "$readiness_output") \
    "durable NVIDIA degradation blocks reboot without a live queue"
assert_grep_fixed 'blockers=nvidia' <(printf '%s\n' "$readiness_output") \
    "valid NVIDIA degradation receives the closed NVIDIA reason code"
chmod 0666 "$TMPDIR/readiness-nvidia/degraded"
readiness_output=$("$TMPDIR/reboot-readiness-fixture")
assert_grep_fixed 'blockers=nvidia-state' <(printf '%s\n' "$readiness_output") \
    "unsafe NVIDIA degradation metadata fails closed as unsafe state"
rm -f -- "$TMPDIR/readiness-nvidia/degraded"
printf '%s\n' 'malformed NVIDIA runtime evidence' \
    > "$TMPDIR/readiness-nvidia/running-version"
readiness_output=$("$TMPDIR/reboot-readiness-fixture")
assert_grep_fixed 'blockers=nvidia-state' <(printf '%s\n' "$readiness_output") \
    "present but malformed NVIDIA runtime evidence fails closed"
rm -f -- "$TMPDIR/readiness-nvidia/running-version"
cat > "$TMPDIR/readiness-bin/systemctl" <<'READINESS_SYSTEMCTL_FAIL_EOF'
#!/bin/sh
exit 1
READINESS_SYSTEMCTL_FAIL_EOF
chmod 0755 "$TMPDIR/readiness-bin/systemctl"
readiness_output=$("$TMPDIR/reboot-readiness-fixture")
assert_grep_fixed 'blockers=nvidia-state' <(printf '%s\n' "$readiness_output") \
    "a failed managed NVIDIA guard query cannot be mistaken for inactive"
assert_cmd_success "successful post-snapshot closes its pairing state" \
    env FINALIZER="$TMPDIR/finalize-post-snapshot.function" bash -c '
        . "$FINALIZER"
        snapper() { :; }
        sudo() { return 0; }
        logger() { :; }
        GREEN= RED= NC=
        snap_num=42
        finalize_post_snapshot
        [ -z "$snap_num" ]
    '
assert_cmd_failure "failed post-snapshot cannot return a green finalizer result" \
    env FINALIZER="$TMPDIR/finalize-post-snapshot.function" bash -c '
        . "$FINALIZER"
        snapper() { :; }
        sudo() { return 9; }
        logger() { :; }
        GREEN= RED= NC=
        snap_num=42
        finalize_post_snapshot
    '
set +e
env FINALIZER="$TMPDIR/finalize-post-snapshot.function" \
    CLEANUP_FN="$TMPDIR/update-cleanup.function" bash -c '
        . "$FINALIZER"
        . "$CLEANUP_FN"
        snapper() { :; }
        sudo() {
            if [[ "$*" == *"noid-snapper-create post"* ]]; then
                return 9
            fi
            return 0
        }
        logger() { :; }
        _release_update_lock_guard() { :; }
        RED= GREEN= NC=
        snap_num=42
        RPM_SIBLING_LIST=
        UPDATE_MARKER_OWNED=0
        SUDO_KEEPALIVE_PID=
        cleanup
    ' >/dev/null 2>&1
post_cleanup_rc=$?
set -e
assert_eq 1 "$post_cleanup_rc" \
    "EXIT fallback converts an unpaired pre-snapshot into process failure"
post_finalize_line=$(grep -nF 'if ! finalize_post_snapshot; then' \
    "$TMPDIR/noid-update-all.sh" | tail -n 1 | cut -d: -f1 || true)
summary_line=$(grep -nF '  Update Summary' \
    "$TMPDIR/noid-update-all.sh" | head -n 1 | cut -d: -f1 || true)
if [ -n "$post_finalize_line" ] && [ -n "$summary_line" ] \
        && [ "$post_finalize_line" -lt "$summary_line" ]; then
    _pass "normal post-snapshot result is known before the Update Summary"
else
    _fail "normal post-snapshot finalization must precede the Update Summary"
fi
assert_cmd_success "update --help is side-effect-free and successful" \
    bash "$TMPDIR/noid-update-all.sh" --help
assert_cmd_success "update-window validator parses" \
    bash -n "$TMPDIR/noid-update-window-active"
assert_cmd_success "update-lock guardian parses" \
    bash -n "$TMPDIR/noid-update-lock-guardian"
assert_cmd_success "pending-reboot notifier parses" \
    bash -n "$TMPDIR/noid-pending-reboot-check.sh"
assert_cmd_success "pending-reboot --help is immediate and side-effect-free" \
    timeout 2 bash "$TMPDIR/noid-pending-reboot-check.sh" --help
cat > "$TMPDIR/reboot-readiness-safe" <<'SAFE_READINESS_EOF'
#!/bin/sh
cat <<'EOF'
schema=1
activation=none
safety=safe
blockers=none
running_kernel=7.1.8-test
latest_kernel=7.1.8-test
nvidia_running=unavailable
nvidia_installed=unavailable
EOF
SAFE_READINESS_EOF
chmod 0755 "$TMPDIR/reboot-readiness-safe"
cp -- "$TMPDIR/noid-pending-reboot-check.sh" \
    "$TMPDIR/noid-pending-reboot-status-fixture.sh"
sed -i "s#/usr/libexec/noid-reboot-readiness#$TMPDIR/reboot-readiness-safe#g" \
    "$TMPDIR/noid-pending-reboot-status-fixture.sh"
pending_status_output=""
if pending_status_output=$(timeout 2 \
        bash "$TMPDIR/noid-pending-reboot-status-fixture.sh" --status 2>&1) \
        && grep -qF 'NoID Privacy — Pending Reboot' \
            <<<"$pending_status_output" \
        && grep -qF 'Reboot required:' <<<"$pending_status_output"; then
    _pass "pending-reboot --status bypasses the autostart delay and reports state"
else
    _fail "pending-reboot --status is slow, failed or omitted its state"
fi
assert_grep_fixed 'if [ "$MODE" = notify ]; then' \
    "$TMPDIR/noid-pending-reboot-check.sh" \
    "only the login notifier enters the GNOME readiness delay"
assert_grep_fixed 'kernel and NVIDIA activation state' \
    "$TMPDIR/noid-pending-reboot-check.sh" \
    "interactive reboot-status subtitle fits the shared 52-column banner"
assert_grep_fixed 'sleep 15' "$TMPDIR/noid-pending-reboot-check.sh" \
    "login notification retains its GNOME readiness delay"
assert_grep_fixed 'Verified system changes — REBOOT REQUIRED' \
    "$TMPDIR/noid-pending-reboot-check.sh" \
    "activation notifier covers verified installation and update changes"
assert_grep_fixed 'A verified boot-policy or update activation is pending.' \
    "$TMPDIR/noid-pending-reboot-check.sh" \
    "activation notifier explains both canonical activation causes"
assert_grep_fixed '--icon=system-reboot-symbolic' \
    "$TMPDIR/noid-pending-reboot-check.sh" \
    "activation notifier uses Fedora's neutral reboot icon"
assert_not_grep 'Verified update activation — REBOOT REQUIRED' \
    "$TMPDIR/noid-pending-reboot-check.sh" \
    "first-install boot-policy activation is not mislabeled as an update"
assert_cmd_success "pending-reboot autostart validates" \
    desktop-file-validate "$TMPDIR/noid-pending-reboot.desktop"
assert_cmd_success "update-window validator passes ShellCheck" \
    shellcheck -S warning "$TMPDIR/noid-update-window-active"
assert_cmd_success "update-lock guardian passes ShellCheck" \
    shellcheck -S warning "$TMPDIR/noid-update-lock-guardian"
sed -n '/^parse_dnf_reboot_hint()/,/^}$/p' \
    "$TMPDIR/noid-update-all.sh" > "$TMPDIR/parse-dnf-reboot-hint.sh"
sed -n '/^parse_dnf_service_units()/,/^}$/p' \
    "$TMPDIR/noid-update-all.sh" > "$TMPDIR/parse-dnf-service-units.sh"
assert_cmd_success "DNF reboot JSON parser accepts the no-reboot schema" \
    bash -c '. "$1"; [ "$(parse_dnf_reboot_hint <<< "$2")" = no ]' _ \
    "$TMPDIR/parse-dnf-reboot-hint.sh" \
    '[{"type":"reboot","reboot_required":false,"packages":[]}]'
assert_cmd_success "DNF reboot JSON parser accepts the reboot schema" \
    bash -c '. "$1"; [ "$(parse_dnf_reboot_hint <<< "$2")" = yes ]' _ \
    "$TMPDIR/parse-dnf-reboot-hint.sh" \
    '[{"type":"reboot","reboot_required":true,"packages":["kernel"]}]'
assert_cmd_failure "DNF reboot JSON parser rejects ambiguous records" \
    bash -c '. "$1"; parse_dnf_reboot_hint <<< "$2"' _ \
    "$TMPDIR/parse-dnf-reboot-hint.sh" \
    '[{"type":"reboot","reboot_required":false},{"type":"reboot","reboot_required":true}]'
assert_cmd_success "DNF service JSON parser accepts and sorts exact units" \
    bash -c '. "$1"; [ "$(parse_dnf_service_units <<< "$2")" = "$3" ]' _ \
    "$TMPDIR/parse-dnf-service-units.sh" \
    '[{"type":"unit","unit":"z.service"},{"type":"unit","unit":"system-a\\x2db.mount"}]' \
    $'system-a\\x2db.mount\nz.service'
assert_cmd_failure "DNF service JSON parser rejects duplicate units" \
    bash -c '. "$1"; parse_dnf_service_units <<< "$2"' _ \
    "$TMPDIR/parse-dnf-service-units.sh" \
    '[{"type":"unit","unit":"a.service"},{"type":"unit","unit":"a.service"}]'
assert_grep_fixed 'env LC_ALL=C dnf --config=/dev/null' \
    "$TMPDIR/noid-update-all.sh" \
    "service-restart hint ignores the system DNF configuration"
assert_grep_fixed '--setopt="reposdir=$needs_svc_repos" --no-plugins' \
    "$TMPDIR/noid-update-all.sh" \
    "service-restart hint parses no repository files or transaction plugins"
assert_grep_fixed 'timeout --signal=TERM --kill-after=5s 20s' \
    "$TMPDIR/noid-update-all.sh" \
    "service-restart hint has a deterministic outer deadline"
assert_eq 1 "$(grep -cF '        needs-restarting -s -C --json' \
    "$TMPDIR/noid-update-all.sh")" \
    "service-restart hint has no network-capable retry path"
assert_not_grep 'needs-restarting -s --json' \
    "$TMPDIR/noid-update-all.sh" \
    "service-restart hint never retries without cache-only mode"

# Execute the shipped query block with an isolated empty user home/cache and a
# deterministic DNF cache-miss result. This proves the advisory remains one
# bounded cache-only attempt, surfaces one warning with DNF's diagnostic and
# never reaches a network-capable fallback. Static grep alone would not prove
# the rc/warning path or detect a second invocation hidden in surrounding flow.
sed -n '/^needs_svc_err=/,/^\[\[ -z "\$needs_svc_err" \]\] || rm -f -- "\$needs_svc_err"$/p' \
    "$TMPDIR/noid-update-all.sh" > "$TMPDIR/needs-svc-query.sh"
assert_cmd_success "extracted DNF service query parses" \
    bash -n "$TMPDIR/needs-svc-query.sh"
mkdir -p "$TMPDIR/needs-svc-bin" "$TMPDIR/needs-svc-home/.cache" \
    "$TMPDIR/needs-svc-runtime"
cat > "$TMPDIR/needs-svc-bin/dnf" <<'NEEDS_SVC_DNF_EOF'
#!/bin/bash
printf '%s\n' "$*" >> "$DNF_CALL_LOG"
echo 'fixture: cache unavailable' >&2
exit 2
NEEDS_SVC_DNF_EOF
chmod 0755 "$TMPDIR/needs-svc-bin/dnf"
needs_svc_output=$(env \
    HOME="$TMPDIR/needs-svc-home" \
    XDG_CACHE_HOME="$TMPDIR/needs-svc-home/.cache" \
    XDG_RUNTIME_DIR="$TMPDIR/needs-svc-runtime" \
    DNF_CALL_LOG="$TMPDIR/needs-svc-calls" \
    PATH="$TMPDIR/needs-svc-bin:/usr/bin" \
    bash -c '
        set -uo pipefail
        . "$1"
        YELLOW=
        NC=
        WARNINGS=0
        . "$2"
        printf "fixture-warnings=%s\n" "$WARNINGS"
    ' _ "$TMPDIR/parse-dnf-service-units.sh" \
        "$TMPDIR/needs-svc-query.sh")
assert_eq 1 "$(wc -l < "$TMPDIR/needs-svc-calls")" \
    "empty user cache causes exactly one DNF service query"
needs_svc_call=$(cat "$TMPDIR/needs-svc-calls")
if [[ $needs_svc_call =~ ^--config=/dev/null[[:space:]]--setopt=reposdir=([^[:space:]]+)[[:space:]]--no-plugins[[:space:]]needs-restarting[[:space:]]-s[[:space:]]-C[[:space:]]--json$ ]]; then
    _pass "executed failure path is repository-free, plugin-free and cache-only"
    needs_svc_repo_arg=${BASH_REMATCH[1]}
else
    _fail "executed failure path changed its hermetic DNF argument contract"
    needs_svc_repo_arg=""
fi
if [ -n "$needs_svc_repo_arg" ] && [ ! -e "$needs_svc_repo_arg" ]; then
    _pass "private empty repository directory is retired after the query"
else
    _fail "private empty repository directory leaked after the query"
fi
if grep -qF 'WARN: DNF service-restart query failed or returned inconsistent data (rc=2) — fixture: cache unavailable' \
        <<<"$needs_svc_output"; then
    _pass "DNF cache-miss diagnostic is a visible advisory warning"
else
    _fail "DNF cache-miss diagnostic was lost or misclassified"
fi
if grep -qF 'fixture-warnings=1' <<<"$needs_svc_output"; then
    _pass "DNF cache miss increments only the warning summary"
else
    _fail "DNF cache miss did not produce exactly one warning"
fi
set +e
unknown_output=$(bash "$TMPDIR/noid-update-all.sh" --definitely-unsupported 2>&1)
unknown_rc=$?
set -e
assert_eq "2" "$unknown_rc" "unknown update option is rejected"
if grep -qF 'unsupported argument' <<<"$unknown_output"; then
    _pass "unknown option explains the rejection"
else
    _fail "unknown option lacks rejection message"
fi
parse_line=$(grep -n '^if \[ "\$#" -gt 0 \]; then$' \
    "$TMPDIR/noid-update-all.sh" | head -n 1 | cut -d: -f1 || true)
root_guard_line=$(grep -n '^if \[ "\$(id -u)" -eq 0 \]; then$' \
    "$TMPDIR/noid-update-all.sh" | head -n 1 | cut -d: -f1 || true)
if [ -n "$parse_line" ] && [ -n "$root_guard_line" ] \
        && [ "$parse_line" -lt "$root_guard_line" ]; then
    _pass "argument validation precedes every privileged workflow path"
else
    _fail "argument validation must precede the root/workflow guard"
fi

# Agent payload updates stay delegated to their consent-gated helpers. Extract
# the bounded block so unrelated DNF/fwupd and browser-extension traffic cannot
# make the agent-specific negative assertions pass or fail accidentally.
sed -n '/^# \[6\] NoID Privacy-managed AI coding agents/,/^# \[7\] Repo Signature/p' \
    "$TMPDIR/noid-update-all.sh" > "$TMPDIR/nonrpm-block.sh"
assert_grep_fixed 'noid-claude-install:Claude-Code' "$TMPDIR/nonrpm-block.sh" \
    "Claude refresh is delegated to the opt-in helper"
assert_grep_fixed 'noid-codex-install:OpenAI-Codex' "$TMPDIR/nonrpm-block.sh" \
    "Codex refresh is delegated to the opt-in helper"
assert_grep_fixed '"$agent_helper" --update' "$TMPDIR/nonrpm-block.sh" \
    "helpers run their non-interactive consent-gated update mode"
assert_grep_fixed 'agent-updates.log' "$TMPDIR/nonrpm-block.sh" \
    "the evidence-ledger contract is stated where the updates run"
assert_grep_fixed 'JP_SEED_VERSION=' "$TMPDIR/nonrpm-block.sh" \
    "Just-Perfection retains an exact reproducible first-install seed"
# Update All must still never call the agent CLIs' own self-updaters directly;
# those refreshes are delegated to the M13 opt-in helpers (asserted above).
for forbidden in 'claude update' 'codex update' 'download_url='; do
    assert_not_grep "$forbidden" "$TMPDIR/nonrpm-block.sh" \
        "Update All does not call an agent self-updater directly: $forbidden"
done
# Restored extension-update behavior (v70): VSCodium via codium's documented
# updater + Open-VSX REST fallback (agent extensions skipped — handled in Step
# 6); non-RPM GNOME extensions refresh from EGO, including the managed
# Just-Perfection identity, while RPM-owned extensions remain DNF-owned.
assert_grep_fixed 'codium --update-extensions' "$TMPDIR/nonrpm-block.sh" \
    "VSCodium extensions refresh through codium's documented updater"
assert_grep_fixed 'codium --install-extension' "$TMPDIR/nonrpm-block.sh" \
    "VSCodium REST fallback force-installs the true-latest build"
assert_grep_fixed 'anthropic.claude-code|openai.chatgpt' "$TMPDIR/nonrpm-block.sh" \
    "VSCodium extension update skips the Step 6 agent extensions"
assert_grep_fixed "--data-urlencode \"uuid=\${ego_uuid}\"" "$TMPDIR/nonrpm-block.sh" \
    "unmanaged non-RPM GNOME extensions refresh from EGO"
assert_grep_fixed "curl -fsS --proto '=https' --tlsv1.2 --max-time 15" \
    "$TMPDIR/nonrpm-block.sh" \
    "EGO metadata query has an explicit HTTPS/TLS floor"
assert_grep_fixed \
    "curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2" \
    "$TMPDIR/nonrpm-block.sh" \
    "EGO archive redirects remain on HTTPS with an explicit TLS floor"
assert_grep_fixed '--max-redirs 3 --max-time 60' "$TMPDIR/nonrpm-block.sh" \
    "EGO archive redirect traversal is bounded"
assert_grep_fixed 'is RPM-managed (updated via DNF)' "$TMPDIR/nonrpm-block.sh" \
    "RPM-owned GNOME extensions are left to DNF"
assert_not_grep_extended '^.*\[ "\$ext_path" = "\$JP_PATH" \] && continue' \
    "$TMPDIR/nonrpm-block.sh" \
    "managed Just-Perfection participates in the explicit EGO update"
assert_grep_fixed 'no artifact signature' "$TMPDIR/nonrpm-block.sh" \
    "Just-Perfection EGO trust trade-off is named at the update boundary"
assert_grep_fixed 'EGO update check unavailable; installed extension left unchanged (retry later)' \
    "$TMPDIR/nonrpm-block.sh" \
    "an unavailable EGO check is a visible retryable warning"
assert_grep_fixed 'WARNINGS=$((WARNINGS + 1))' "$TMPDIR/nonrpm-block.sh" \
    "an unavailable EGO channel reaches the non-blocking warning summary"
assert_grep_fixed 'DEFERRED_LIST+=("GNOME-extension-check")' \
    "$TMPDIR/nonrpm-block.sh" \
    "an unavailable EGO check is named as deferred work"
assert_grep_fixed 'ego_info_rc=$?' "$TMPDIR/nonrpm-block.sh" \
    "EGO metadata transport status is retained separately from response bytes"
assert_grep_fixed 'EGO returned an empty successful response' \
    "$TMPDIR/nonrpm-block.sh" \
    "a successful but empty EGO response remains a hard validation error"
assert_grep_fixed 'ego_download_rc=$?' "$TMPDIR/nonrpm-block.sh" \
    "EGO archive transport status is classified separately from artifact validation"
assert_grep_fixed 'download unavailable; installed extension left unchanged (retry later)' \
    "$TMPDIR/nonrpm-block.sh" \
    "a retryable EGO archive outage does not turn the full update red"
assert_grep_fixed 'downloaded artifact is missing or outside policy' \
    "$TMPDIR/nonrpm-block.sh" \
    "a successful but invalid EGO artifact remains a hard error"
assert_not_grep 'sudo unzip' "$TMPDIR/nonrpm-block.sh" \
    "network archives are never overlaid into a system extension as root"
assert_grep_fixed 'RENAME_EXCHANGE' "$TMPDIR/nonrpm-block.sh" \
    "validated GNOME trees replace the active tree atomically"
assert_grep_fixed 'installed ${ext_ver} is newer than registry ${latest}; no downgrade' \
    "$TMPDIR/nonrpm-block.sh" \
    "Open-VSX fallback explicitly rejects downgrades"
assert_grep_fixed "curl -fsS --proto '=https' --tlsv1.2 --max-time 10" \
    "$TMPDIR/nonrpm-block.sh" \
    "Open-VSX metadata query has an explicit HTTPS/TLS floor"
assert_grep_fixed 'managed agent extensions present; using per-extension native updates' \
    "$TMPDIR/nonrpm-block.sh" \
    "global VSCodium updater is bypassed when an agent namespace is installed"
assert_grep_fixed 'VSX_VERSION_PY' "$TMPDIR/nonrpm-block.sh" \
    "REST version precedence uses the bounded numeric comparator"
assert_grep_fixed 'capture_codium_inventory' "$TMPDIR/nonrpm-block.sh" \
    "VSCodium inventory captures diagnostics outside parsed stdout"
assert_not_grep 'codium --list-extensions --show-versions 2>&1' \
    "$TMPDIR/nonrpm-block.sh" \
    "VSCodium inventory never merges stderr into extension rows"
assert_not_grep 'LC_ALL=C sort -V' "$TMPDIR/nonrpm-block.sh" \
    "REST fallback never applies GNU version ordering to pre-release values"
assert_not_grep 'User-Agent: noid-update-all' "$TMPDIR/noid-update-all.sh" \
    "marketplace requests do not disclose a distribution-specific user agent"

# Forked %config(noreplace) siblings are review evidence, not an informational
# line that may coexist with a green summary. Exercise the exact Step 8b body
# with a private /etc fixture, including NUL-safe names and an incomplete scan.
RPM_SIBLING_BLOCK="$TMPDIR/rpm-sibling-block.sh"
RPM_SIBLING_ETC="$TMPDIR/rpm-sibling-etc"
RPM_SIBLING_RUNTIME="$TMPDIR/rpm-sibling-runtime"
sed -n '/^# \[8b\] Forked-config drift evidence/,/^# \[9\] Reboot Check/p' \
    "$TMPDIR/noid-update-all.sh" | sed '$d' \
    | sed 's|sudo find /etc -xdev|sudo find "${RPM_FIXTURE_ETC:?}" -xdev|' \
    > "$RPM_SIBLING_BLOCK"
assert_cmd_success "config-drift scan fixture parses" bash -n "$RPM_SIBLING_BLOCK"
mkdir -p "$RPM_SIBLING_ETC" "$RPM_SIBLING_RUNTIME"
run_rpm_sibling_fixture() {
    local fail_find=$1
    env RPM_FIXTURE_ETC="$RPM_SIBLING_ETC" \
        RPM_FIXTURE_FIND_FAIL="$fail_find" \
        XDG_RUNTIME_DIR="$RPM_SIBLING_RUNTIME" \
        bash -c '
            set -uo pipefail
            sudo() {
                if [ "${RPM_FIXTURE_FIND_FAIL:-0}" = 1 ] \
                        && [ "${1:-}" = find ]; then
                    return 9
                fi
                "$@"
            }
            step() { :; }
            RED= GREEN= YELLOW= NC=
            WARNINGS=0 ERRORS=0 RPM_SIBLING_LIST=
            . "$1"
            printf "WARNINGS=%s ERRORS=%s\n" "$WARNINGS" "$ERRORS"
        ' _ "$RPM_SIBLING_BLOCK"
}
rpm_sibling_output=$(run_rpm_sibling_fixture 0)
assert_grep_fixed 'no .rpmnew/.rpmsave/.rpmorig files' \
    <(printf '%s\n' "$rpm_sibling_output") \
    "empty config-drift scan reports a clean state"
assert_grep_fixed 'WARNINGS=0 ERRORS=0' \
    <(printf '%s\n' "$rpm_sibling_output") \
    "empty config-drift scan leaves the summary green"
printf '%s\n' 'vendor replacement' \
    > "$RPM_SIBLING_ETC/chrony config.rpmnew"
printf '%s\n' 'saved local state' > "$RPM_SIBLING_ETC/auditd.conf.rpmsave"
ln -s auditd.conf.rpmsave "$RPM_SIBLING_ETC/not-a-regular.rpmorig"
rpm_sibling_output=$(run_rpm_sibling_fixture 0)
assert_grep_fixed '2 vendor-default sibling file(s) present' \
    <(printf '%s\n' "$rpm_sibling_output") \
    "regular config siblings are counted exactly"
assert_grep_fixed "$RPM_SIBLING_ETC/chrony config.rpmnew" \
    <(printf '%s\n' "$rpm_sibling_output") \
    "NUL-safe scan preserves a sibling path containing whitespace"
assert_not_grep 'not-a-regular.rpmorig' \
    <(printf '%s\n' "$rpm_sibling_output") \
    "symlink lookalikes are excluded from config-drift evidence"
assert_grep_fixed 'WARNINGS=1 ERRORS=0' \
    <(printf '%s\n' "$rpm_sibling_output") \
    "config siblings produce one review warning in the summary"
rpm_sibling_output=$(run_rpm_sibling_fixture 1)
assert_grep_fixed 'config-drift scan under /etc failed or was incomplete' \
    <(printf '%s\n' "$rpm_sibling_output") \
    "an incomplete scan is explicitly reported"
assert_grep_fixed 'WARNINGS=0 ERRORS=1' \
    <(printf '%s\n' "$rpm_sibling_output") \
    "an incomplete config-drift scan cannot reach a green summary"
assert_eq 0 "$(find "$RPM_SIBLING_RUNTIME" -mindepth 1 -print | wc -l)" \
    "config-drift scan removes its private evidence file"

# Explicit uBO/DKIM updates use their official browser marketplaces, stable
# compatibility-filtered metadata, exact marketplace digests and the shared
# bounded XPI validator. Thunderbird background add-on checks remain disabled.
assert_not_grep 'https://api.github.com/repos/gorhill/uBlock/releases/latest' \
    "$TMPDIR/noid-update-all.sh" "uBO no longer consumes GitHub's shared unauthenticated quota"
assert_not_grep 'https://api.github.com/repos/lieser/dkim_verifier/releases/latest' \
    "$TMPDIR/noid-update-all.sh" "DKIM no longer consumes GitHub's shared unauthenticated quota"
assert_grep_fixed 'marketplace=amo' "$TMPDIR/noid-update-all.sh" \
    "managed uBO resolves through Firefox's official marketplace"
assert_grep_fixed 'marketplace=atn' "$TMPDIR/noid-update-all.sh" \
    "managed DKIM resolves through Thunderbird's official marketplace"
assert_grep_fixed 'fetch_marketplace_xpi "$marketplace" "$expected_id"' \
    "$TMPDIR/noid-update-all.sh" \
    "both managed extensions reuse the origin- and digest-bound marketplace resolver"
assert_grep_fixed 'payload_matches "$LATEST_XPI_PATH" "$LATEST_XPI_SHA256"' \
    "$TMPDIR/noid-update-all.sh" \
    "managed marketplace bytes are re-verified after entering root-publisher staging"
assert_grep_fixed 'MARKETPLACE_ERROR_CLASS=availability' \
    "$TMPDIR/noid-update-all.sh" \
    "marketplace transport failures carry an explicit retryable class"
assert_grep_fixed 'MARKETPLACE_ERROR_CLASS=validation' \
    "$TMPDIR/noid-update-all.sh" \
    "received marketplace bytes return to the hard validation class"
assert_grep_fixed 'marketplace check unavailable' \
    "$TMPDIR/noid-update-all.sh" \
    "browser marketplace outages are visible non-blocking warnings"
assert_grep_fixed 'could not be authenticated through the fixed' \
    "$TMPDIR/noid-update-all.sh" \
    "browser marketplace validation failures remain blocking errors"
assert_grep_fixed 'extension-updates.log' "$TMPDIR/noid-update-all.sh" \
    "non-agent extension updates append local SHA-256 evidence"

# --- Add-on check state: the patch-age surface noid-status renders ----------
# The append-only ledger above records version CHANGES only, so a component
# that has been current for a year is indistinguishable there from one never
# checked. Every authenticated marketplace check must therefore also publish a
# bounded last-check record, including the runs that changed nothing and the
# ones that failed — otherwise noid-status reports a reassuring age no check
# ever established.
assert_grep_fixed \
    'EXTENSION_CHECK_STATE="${XDG_STATE_HOME:-$HOME/.local/state}/noid-privacy/extension-checks"' \
    "$TMPDIR/noid-update-all.sh" \
    "add-on check state path matches the noid-status consumer literally"
assert_grep_fixed 'record_extension_check() {' "$TMPDIR/noid-update-all.sh" \
    "the updater publishes a bounded add-on last-check record"
assert_grep_fixed 'case "$result" in current|updated|failed) ;; *) return 1 ;; esac' \
    "$TMPDIR/noid-update-all.sh" \
    "only the three defined check outcomes are accepted"
assert_grep_fixed 'grep -v "^component=${component} "' "$TMPDIR/noid-update-all.sh" \
    "one line per component keeps the check state bounded"
assert_grep_fixed 'mv -fT -- "$tmp" "$EXTENSION_CHECK_STATE"' \
    "$TMPDIR/noid-update-all.sh" \
    "the check state is replaced atomically, never edited in place"
for check_site in \
    'record_extension_check firefox-ubo "$ubo_check_result"' \
    'record_extension_check thunderbird-dkim "$dkim_check_result"' \
    'record_extension_check "${product}-marketplace" "$check_result"'; do
    assert_grep_fixed "$check_site" "$TMPDIR/noid-update-all.sh" \
        "managed component publishes its check outcome: $check_site"
done
assert_grep_fixed 'record_extension_check "${product}-marketplace" failed' \
    "$TMPDIR/noid-update-all.sh" \
    "a marketplace step that cannot start is recorded as a failed check"
for unauthenticated in 'ubo_check_result=failed' 'dkim_check_result=failed'; do
    assert_grep_fixed "$unauthenticated" "$TMPDIR/noid-update-all.sh" \
        "an unauthenticated managed channel never reports a current check: $unauthenticated"
done
# The uBO loop reports each per-profile failure as an ERRORS increment plus
# `continue`, so a run in which every profile failed validation leaves the
# update counter at zero. The check outcome must follow the error delta, not
# that counter, or the patch-age surface would call such a run "current".
assert_grep_fixed 'ubo_errors_before=$ERRORS' "$TMPDIR/noid-update-all.sh" \
    "uBO check outcome samples the error counter before its profile loop"
assert_grep_fixed 'if [ "$ERRORS" -ne "$ubo_errors_before" ]; then' \
    "$TMPDIR/noid-update-all.sh" \
    "a uBO run whose profiles all failed validation is never reported as current"

# Behavioural: drive the shipped recorder rather than a reimplementation.
EXT_CHECK_FN="$TMPDIR/record-extension-check.sh"
sed -n '/^record_extension_check() {/,/^}/p' "$TMPDIR/noid-update-all.sh" \
    > "$EXT_CHECK_FN"
assert_cmd_success "extracted add-on check recorder parses" \
    bash -n "$EXT_CHECK_FN"

EXT_CHECK_HOME="$TMPDIR/ext-check-home"
# The caller names the state root explicitly. A counter incremented inside the
# helper would be lost: every call here runs in a command substitution, so a
# shared root would silently let an earlier case's records satisfy a later
# bounded-growth assertion.
ext_check_run() {
    local label="$1"
    shift
    XDG_STATE_HOME="$EXT_CHECK_HOME/$label" bash -c '
        set -uo pipefail
        EXTENSION_CHECK_STATE="${XDG_STATE_HOME}/noid-privacy/extension-checks"
        . "$1"
        shift
        while [ "$#" -gt 0 ]; do
            record_extension_check "$1" "$2" || exit 1
            shift 2
        done
        cat "$EXTENSION_CHECK_STATE"
    ' _ "$EXT_CHECK_FN" "$@"
}

ext_check_lines=$(ext_check_run three-components \
    firefox-ubo current thunderbird-dkim current firefox-marketplace failed | wc -l)
assert_eq 3 "$ext_check_lines" "three components produce exactly three records"

ext_check_lines=$(ext_check_run repeated \
    firefox-ubo current firefox-ubo updated firefox-ubo current | wc -l)
assert_eq 1 "$ext_check_lines" \
    "repeated checks of one component never grow the state file"

ext_check_record=$(ext_check_run format firefox-ubo current \
    | sed -E 's/checked=[^ ]+/checked=T/')
assert_eq 'component=firefox-ubo checked=T result=current' "$ext_check_record" \
    "published record matches the format noid-status parses"
ext_check_meta=$(stat -c '%a' \
    "$EXT_CHECK_HOME/format/noid-privacy/extension-checks")
assert_eq 600 "$ext_check_meta" "the check state stays user-private"
ext_check_dir_meta=$(stat -c '%a' "$EXT_CHECK_HOME/format/noid-privacy")
assert_eq 700 "$ext_check_dir_meta" "the state directory stays user-private"

assert_cmd_failure "an undefined check outcome is refused" \
    env XDG_STATE_HOME="$EXT_CHECK_HOME/reject-outcome" bash -c '
        set -uo pipefail
        EXTENSION_CHECK_STATE="${XDG_STATE_HOME}/noid-privacy/extension-checks"
        . "$1"
        record_extension_check firefox-ubo bogus
    ' _ "$EXT_CHECK_FN"
assert_cmd_failure "an unsafe component name is refused" \
    env XDG_STATE_HOME="$EXT_CHECK_HOME/reject-name" bash -c '
        set -uo pipefail
        EXTENSION_CHECK_STATE="${XDG_STATE_HOME}/noid-privacy/extension-checks"
        . "$1"
        record_extension_check "../escape" current
    ' _ "$EXT_CHECK_FN"
assert_grep_fixed 'defaultPref("extensions.update.enabled", false);' "$M35_FILE" \
    "Thunderbird background extension updates are disabled"
assert_grep_fixed 'publish_managed_dkim_xpi' "$TMPDIR/noid-update-all.sh" \
    "DKIM current and active copies use the bounded root publisher"
assert_grep_fixed '"$FIREFOX_XPI_SIGNATURE_VERIFIER" "$MARKETPLACE_PATH"' \
    "$TMPDIR/noid-update-all.sh" \
    "uBO candidate passes Firefox native signature verification before publication"
assert_grep_fixed 'UBO_POLICY_VALIDATOR=/usr/local/lib/noid-privacy/validate-ubo-policy.py' \
    "$TMPDIR/noid-update-all.sh" \
    "uBO policy validator has one canonical root-owned path"
assert_grep_fixed 'UBO_POLICY_SOURCE=/usr/share/noid-firefox/uBlock0@raymondhill.net.json' \
    "$TMPDIR/noid-update-all.sh" \
    "uBO managed filter-list policy has one canonical opt-out-independent source"
assert_not_grep 'UBO_MANAGED_POLICY=' "$TMPDIR/noid-update-all.sh" \
    "uBO executable updates do not require the optional active policy copy"
assert_grep_fixed '"$UBO_POLICY_VALIDATOR" "$LATEST_XPI_PATH"' \
    "$TMPDIR/noid-update-all.sh" \
    "uBO candidate must support the complete managed filter-list policy"
assert_grep_fixed '"$UBO_POLICY_VALIDATOR" "$ubo_target"' \
    "$TMPDIR/noid-update-all.sh" \
    "each installed uBO copy is checked against the managed filter-list policy"
assert_grep_fixed 'restored to the authenticated policy-compatible release' \
    "$TMPDIR/noid-update-all.sh" \
    "same-version uBO drift is repaired to authenticated compatible bytes"
assert_grep_fixed 'no implicit downgrade' "$TMPDIR/noid-update-all.sh" \
    "a newer incompatible manual uBO copy fails visibly without a downgrade"
ubo_policy_line=$(grep -nF '"$UBO_POLICY_VALIDATOR" "$LATEST_XPI_PATH"' \
    "$TMPDIR/noid-update-all.sh" | head -n1 | cut -d: -f1 || true)
ubo_profile_copy_line=$(grep -nF \
    'noid_atomic_install_file "$LATEST_XPI_PATH" "$ubo_target" 644' \
    "$TMPDIR/noid-update-all.sh" | head -n1 | cut -d: -f1 || true)
if [ -n "$ubo_policy_line" ] && [ -n "$ubo_profile_copy_line" ] \
        && [ "$ubo_policy_line" -lt "$ubo_profile_copy_line" ]; then
    _pass "uBO policy incompatibility stops the candidate before any profile copy"
else
    _fail "uBO candidate policy validation must precede every profile copy"
fi
assert_grep_fixed 'uBO seed supports the complete root-managed filter-list policy' \
    "$KS_FILE" \
    "M25 build gate replays the uBO policy validator against the image seed"
assert_grep_fixed '"$FIREFOX_XPI_SIGNATURE_VERIFIER" "$ubo_target"' \
    "$TMPDIR/noid-update-all.sh" \
    "installed uBO bytes pass Firefox native signature verification before no-downgrade"
assert_grep_fixed '"$FIREFOX_XPI_SIGNATURE_VERIFIER" "$target"' \
    "$TMPDIR/noid-update-all.sh" \
    "every installed AMO XPI is natively re-verified before no-downgrade comparison"
assert_grep_fixed 'update_marketplace_extensions firefox amo' \
    "$TMPDIR/noid-update-all.sh" \
    "all additional Firefox profile extensions reconcile through AMO"
assert_grep_fixed 'update_marketplace_extensions thunderbird atn' \
    "$TMPDIR/noid-update-all.sh" \
    "all additional Thunderbird profile extensions reconcile through ATN"
assert_grep_fixed 'addons.mozilla.org/api/v5/addons/search/' \
    "$TMPDIR/noid-update-all.sh" \
    "AMO lookup uses the official compatibility-filterable search API"
assert_grep_fixed 'services.addons.thunderbird.net/api/v4/addons/search/' \
    "$TMPDIR/noid-update-all.sh" \
    "ATN lookup uses the official compatibility-filterable search API"
assert_grep_fixed '"appversion": sys.argv[2]' "$TMPDIR/noid-update-all.sh" \
    "marketplace selection is bound to the installed browser version"
assert_grep_fixed 'non-numeric marketplace version is not safely orderable' \
    "$TMPDIR/noid-update-all.sh" \
    "unorderable marketplace versions have an explicit non-downgrade path"
assert_grep_fixed 'Firefox is running — profile hardening deferred' \
    "$TMPDIR/noid-update-all.sh" \
    "a running Firefox makes total update coverage visibly incomplete"
assert_grep_fixed 'DEFERRED_LIST+=("Firefox profile hardening")' \
    "$TMPDIR/noid-update-all.sh" \
    "a live Firefox is named as a deferred sub-step"
assert_grep_fixed '"Deferred:" "${DEFERRED_LIST[*]}"' \
    "$TMPDIR/noid-update-all.sh" \
    "the summary distinguishes a normal runtime deferral from an error"
assert_not_grep 'Firefox is running — close it and re-run; executable extension bytes were not replaced in use' \
    "$TMPDIR/noid-update-all.sh" \
    "a user-open browser is not misreported as an updater failure"

# Exercise the exact process-state guard against a live process and a real
# unreaped child. pgrep is mocked only to make the candidate PID deterministic;
# the helper still reads the kernel's live /proc status for that PID.
sed -n '/^browser_process_active()/,/^}$/p' \
    "$TMPDIR/noid-update-all.sh" > "$TMPDIR/browser-process-active.sh"
assert_cmd_success "browser process-state guard parses" \
    bash -n "$TMPDIR/browser-process-active.sh"
assert_cmd_success "a live process keeps Firefox profile mutation deferred" \
    env BROWSER_GUARD="$TMPDIR/browser-process-active.sh" bash -c '
        . "$BROWSER_GUARD"
        pgrep() { printf "%s\n" "$$"; }
        browser_process_active firefox firefox-bin
    '
assert_cmd_success "a live process keeps Thunderbird executable updates blocked" \
    env BROWSER_GUARD="$TMPDIR/browser-process-active.sh" bash -c '
        . "$BROWSER_GUARD"
        pgrep() { printf "%s\n" "$$"; }
        browser_process_active thunderbird thunderbird-bin
    '
assert_grep_fixed '[ -e "/proc/${browser_pid}" ] && return 0' \
    "$TMPDIR/browser-process-active.sh" \
    "an extant process with unreadable status fails closed as active"
python3 - "$TMPDIR/firefox-zombie.pid" "$TMPDIR/firefox-zombie.release" <<'PY' &
import os
import pathlib
import sys
import time

pid_file = pathlib.Path(sys.argv[1])
release_file = pathlib.Path(sys.argv[2])
child = os.fork()
if child == 0:
    os._exit(0)
pid_file.write_text(f"{child}\n", encoding="ascii")
while not release_file.exists():
    time.sleep(0.02)
os.waitpid(child, 0)
PY
FIREFOX_ZOMBIE_PARENT_PID=$!
for _ in {1..100}; do
    [ -s "$TMPDIR/firefox-zombie.pid" ] && break
    sleep 0.02
done
assert_file_exists "$TMPDIR/firefox-zombie.pid"
firefox_zombie_pid=$(<"$TMPDIR/firefox-zombie.pid")
for _ in {1..100}; do
    [ "$(awk '$1 == "State:" { print $2; exit }' \
        "/proc/${firefox_zombie_pid}/status" 2>/dev/null || true)" = Z ] && break
    sleep 0.02
done
assert_eq Z "$(awk '$1 == "State:" { print $2; exit }' \
    "/proc/${firefox_zombie_pid}/status" 2>/dev/null || true)" \
    "fixture child reached the kernel zombie state"
assert_cmd_success "an unreaped Firefox candidate does not defer profile mutation" \
    env BROWSER_GUARD="$TMPDIR/browser-process-active.sh" \
        FIREFOX_ZOMBIE_PID="$firefox_zombie_pid" bash -c '
            . "$BROWSER_GUARD"
            pgrep() { printf "%s\n" "$FIREFOX_ZOMBIE_PID"; }
            ! browser_process_active firefox firefox-bin
        '
assert_cmd_success "an unreaped Thunderbird candidate does not block executable updates" \
    env BROWSER_GUARD="$TMPDIR/browser-process-active.sh" \
        FIREFOX_ZOMBIE_PID="$firefox_zombie_pid" bash -c '
            . "$BROWSER_GUARD"
            pgrep() { printf "%s\n" "$FIREFOX_ZOMBIE_PID"; }
            ! browser_process_active thunderbird thunderbird-bin
        '
: > "$TMPDIR/firefox-zombie.release"
wait "$FIREFOX_ZOMBIE_PARENT_PID"
FIREFOX_ZOMBIE_PARENT_PID=
assert_grep_fixed 'profile_userjs_noid_managed "${pdir}"' \
    "$TMPDIR/noid-update-all.sh" \
    "older securely identified NoID Privacy Firefox profiles enter automatic convergence"
assert_grep_fixed 'managed_firefox_playground_profile "$profile_name"' \
    "$TMPDIR/noid-update-all.sh" \
    "the reserved M34 playground enters automatic incomplete-profile repair"
assert_grep_fixed '[ ! -e "$pdir/user.js" ] && [ ! -L "$pdir/user.js" ]' \
    "$TMPDIR/noid-update-all.sh" \
    "a safely registered Firefox profile with no user.js enters automatic hardening"
assert_grep_fixed 'profile_auto_hardening_excluded "${pdir}"' \
    "$TMPDIR/noid-update-all.sh" \
    "automatic Firefox enrollment respects the explicit exclusion"
assert_grep_fixed 'for i in "${!FIREFOX_RECONCILE_NAMES[@]}"; do' \
    "$TMPDIR/noid-update-all.sh" \
    "managed incomplete Firefox profiles participate in the re-apply pass"
assert_not_grep 'network\.trr\.' "$TMPDIR/noid-update-all.sh" \
    "Update All never resets a user-selected Firefox/Thunderbird Secure DNS preference"
assert_eq 2 "$(grep -c '^    classify_firefox_profiles$' "$TMPDIR/noid-update-all.sh")" \
    "Firefox profiles are classified before the workflow and after reconciliation"
assert_grep_fixed 'Thunderbird is running — profile hardening deferred' \
    "$TMPDIR/noid-update-all.sh" \
    "a running Thunderbird is a visible retryable deferral"
assert_grep_fixed 'DEFERRED_LIST+=("Thunderbird profile hardening")' \
    "$TMPDIR/noid-update-all.sh" \
    "a running Thunderbird is named in the deferred summary"
assert_grep_fixed 'browser_process_active thunderbird thunderbird-bin' \
    "$TMPDIR/noid-update-all.sh" \
    "Thunderbird uses the same zombie-safe process-state guard"
assert_grep_fixed '/usr/local/bin/noid-thunderbird-harden-profile --automatic' \
    "$TMPDIR/noid-update-all.sh" \
    "Update All invokes only the safe automatic Thunderbird profile mode"
assert_not_grep 'noid-thunderbird-harden-profile --all' \
    "$TMPDIR/noid-update-all.sh" \
    "Update All never invokes the explicit overwrite-all Thunderbird mode"
assert_grep_fixed '/usr/share/noid-thunderbird/user.js derivative' \
    "$TMPDIR/noid-update-all.sh" \
    "Thunderbird profile refresh documents its reviewed local derivative source"
assert_grep_fixed 'never fetches' "$TMPDIR/noid-update-all.sh" \
    "Thunderbird profile refresh explicitly excludes an upstream user.js fetch"

# The updater accepts one exact bounded count record and rejects duplicate,
# malformed and impossible helper output.
sed -n '/^parse_thunderbird_automatic_result()/,/^}$/p' \
    "$TMPDIR/noid-update-all.sh" > "$TMPDIR/tb-automatic-result-parser.sh"
assert_cmd_success "Thunderbird automatic-result parser is valid bash" \
    bash -n "$TMPDIR/tb-automatic-result-parser.sh"
assert_eq '2 1 3' "$(env PARSER="$TMPDIR/tb-automatic-result-parser.sh" bash -c '
    . "$PARSER"
    parse_thunderbird_automatic_result \
        $'"'"'human diagnostic\nNOID_RESULT eligible=2 changed=1 protected=3\nDone.'"'"'
')" "Thunderbird automatic-result parser accepts one exact result"
assert_cmd_failure "Thunderbird automatic-result parser rejects duplicates" \
    env PARSER="$TMPDIR/tb-automatic-result-parser.sh" bash -c '
        . "$PARSER"
        parse_thunderbird_automatic_result \
            $'"'"'NOID_RESULT eligible=1 changed=0 protected=0\nNOID_RESULT eligible=1 changed=0 protected=0'"'"'
    '
assert_cmd_failure "Thunderbird automatic-result parser rejects impossible counts" \
    env PARSER="$TMPDIR/tb-automatic-result-parser.sh" bash -c '
        . "$PARSER"
        parse_thunderbird_automatic_result \
            "NOID_RESULT eligible=1 changed=2 protected=0"
    '

# M25 validates the deployed Thunderbird policy against a complete hard-coded
# document, and M35 is that document's only producer. Nothing bound the two:
# adding one legitimate key to M35's payload kept M35's own substring
# assertions green while every installed host's update run turned red, with no
# self-healing path -- the republish loop compares source against destination,
# finds them equal, and leaves the drifted document in place for the validator
# to reject. Run M25's shipped comparison against M35's shipped bytes instead
# of restating either side here, then prove the comparison stays falsifiable.
if python3 - "$M35_FILE" "$TMPDIR/noid-update-all.sh" <<'PY'
from pathlib import Path
import json
import subprocess
import sys
import tempfile

m35 = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
updater = Path(sys.argv[2]).read_text(encoding="utf-8").splitlines()

opener = 'cat > "$POLICIES_CANDIDATE" <<\'POLICIES_JSON_EOF\''
if m35.count(opener) != 1:
    raise SystemExit("M35 no longer publishes exactly one policy heredoc")
start = m35.index(opener) + 1
if "POLICIES_JSON_EOF" not in m35[start:]:
    raise SystemExit("M35 policy heredoc is unterminated")
emitted = "\n".join(m35[start:m35.index("POLICIES_JSON_EOF", start)]) + "\n"
json.loads(emitted)

path_line = 'path = "/etc/thunderbird/policies/policies.json"'
if updater.count(path_line) != 1:
    raise SystemExit("M25 no longer validates one fixed policy path")
anchor = updater.index(path_line)
opens = [i for i in range(anchor) if updater[i].strip() == "if ! python3 -c '"]
closes = [i for i in range(anchor, len(updater)) if updater[i] == "'; then"]
if not opens or not closes:
    raise SystemExit("M25 policy validator is no longer an inline python3 -c block")
source = "\n".join(updater[opens[-1] + 1:closes[0]])
source = source.replace(path_line, "path = sys.argv[1]")


def verdict(document):
    with tempfile.NamedTemporaryFile("w", suffix=".json") as handle:
        handle.write(document)
        handle.flush()
        return subprocess.run(
            [sys.executable, "-c", source, handle.name]).returncode


if verdict(emitted) != 0:
    print("M25 rejects the exact policy M35 publishes:", file=sys.stderr)
    print(emitted, file=sys.stderr)
    raise SystemExit(1)

widened = json.loads(emitted)
widened["policies"]["3rdparty"] = {"Extensions": {}}
for label, document in (("an added policy key", widened),
                        ("an emptied policy set", {"policies": {}})):
    if verdict(json.dumps(document)) == 0:
        print("M25 validator accepts " + label, file=sys.stderr)
        raise SystemExit(1)
PY
then
    _pass "M25's policy validator accepts exactly the document M35 publishes"
else
    _fail "M25's policy expectation drifted from M35's published policy"
fi

# Execute the exact profile-classification functions with a private registry.
# A secure M34 marker opts the reserved playground into repair; a safely
# identified older NoID Privacy profile also converges. Successful repair must refresh
# the final hardened/unhardened lists in the same run.
printf '%s\n' 'set -euo pipefail' > "$TMPDIR/firefox-profile-classifier.sh"
sed -n '/^managed_firefox_playground_profile()/,/^}$/p' \
    "$TMPDIR/noid-update-all.sh" >> "$TMPDIR/firefox-profile-classifier.sh"
sed -n '/^classify_firefox_profiles()/,/^}$/p' \
    "$TMPDIR/noid-update-all.sh" >> "$TMPDIR/firefox-profile-classifier.sh"
assert_cmd_success "Firefox profile classifier parses" \
    bash -n "$TMPDIR/firefox-profile-classifier.sh"
FIREFOX_CLASSIFIER_HOME="$TMPDIR/firefox-classifier-home"
FIREFOX_CLASSIFIER_CONFIG="$FIREFOX_CLASSIFIER_HOME/custom-config"
mkdir -p "$FIREFOX_CLASSIFIER_CONFIG/noid-privacy" \
    "$TMPDIR/profile-default" "$TMPDIR/profile-playground" \
    "$TMPDIR/profile-stale" "$TMPDIR/profile-new" \
    "$TMPDIR/profile-excluded" "$TMPDIR/profile-personal"
printf '%s\n' 'user_pref("fixture.foreign", true);' \
    > "$TMPDIR/profile-personal/user.js"
printf '%s\n' NOID_FIREFOX_PLAYGROUND_READY_V1 \
    > "$FIREFOX_CLASSIFIER_CONFIG/noid-privacy/firefox-playground-init.done"
chmod 0600 "$FIREFOX_CLASSIFIER_CONFIG/noid-privacy/firefox-playground-init.done"
cat >> "$TMPDIR/firefox-profile-classifier.sh" <<'FIREFOX_CLASSIFIER_FIXTURE'
list_registered_profiles() {
    printf 'default-release\t%s\t0\t0\n' "$FIXTURE_ROOT/profile-default"
    printf 'playground\t%s\t0\t0\n' "$FIXTURE_ROOT/profile-playground"
    printf 'stale\t%s\t0\t0\n' "$FIXTURE_ROOT/profile-stale"
    printf 'new\t%s\t0\t0\n' "$FIXTURE_ROOT/profile-new"
    printf 'excluded\t%s\t0\t0\n' "$FIXTURE_ROOT/profile-excluded"
    printf 'personal\t%s\t0\t0\n' "$FIXTURE_ROOT/profile-personal"
}
profile_dir_for() {
    case "$1" in
        default-release) printf '%s\n' "$FIXTURE_ROOT/profile-default" ;;
        playground) printf '%s\n' "$FIXTURE_ROOT/profile-playground" ;;
        stale) printf '%s\n' "$FIXTURE_ROOT/profile-stale" ;;
        new) printf '%s\n' "$FIXTURE_ROOT/profile-new" ;;
        excluded) printf '%s\n' "$FIXTURE_ROOT/profile-excluded" ;;
        personal) printf '%s\n' "$FIXTURE_ROOT/profile-personal" ;;
        *) return 1 ;;
    esac
}
profile_hardening_complete() {
    [ "$1" = default-release ] || { [ "$1" = playground ] && [ -e "$FIXTURE_ROOT/playground-repaired" ]; }
}
profile_userjs_noid_managed() {
    [ "$1" = "$FIXTURE_ROOT/profile-stale" ]
}
profile_auto_hardening_excluded() {
    [ "$1" = "$FIXTURE_ROOT/profile-excluded" ]
}
array_csv() { local IFS=,; printf '%s\n' "$*"; }

classify_firefox_profiles
[ "$(array_csv "${HARDENED_NAMES[@]}")" = default-release ]
[ "$(array_csv "${FIREFOX_RECONCILE_NAMES[@]}")" = default-release,playground,stale,new ]
[ "$(array_csv "${UNHARDENED_NAMES[@]}")" = playground,stale,new,excluded,personal ]

: > "$FIXTURE_ROOT/playground-repaired"
classify_firefox_profiles
[ "$(array_csv "${HARDENED_NAMES[@]}")" = default-release,playground ]
[ "$(array_csv "${FIREFOX_RECONCILE_NAMES[@]}")" = default-release,playground,stale,new ]
[ "$(array_csv "${UNHARDENED_NAMES[@]}")" = stale,new,excluded,personal ]

rm -f "$FIXTURE_ROOT/playground-repaired" \
    "$XDG_CONFIG_HOME/noid-privacy/firefox-playground-init.done"
classify_firefox_profiles
[ "$(array_csv "${FIREFOX_RECONCILE_NAMES[@]}")" = default-release,playground,stale,new ]
[ "$(array_csv "${UNHARDENED_NAMES[@]}")" = playground,stale,new,excluded,personal ]
FIREFOX_CLASSIFIER_FIXTURE
assert_cmd_success "managed Firefox classifier converges and refreshes exact lists" \
    env HOME="$FIREFOX_CLASSIFIER_HOME" XDG_CONFIG_HOME="$FIREFOX_CLASSIFIER_CONFIG" \
    FIXTURE_ROOT="$TMPDIR" \
    bash "$TMPDIR/firefox-profile-classifier.sh"

MARKETPLACE_BLOCK="$TMPDIR/marketplace-block.sh"
sed -n '/^browser_extension_inventory()/,/^publish_managed_dkim_xpi()/p' \
    "$TMPDIR/noid-update-all.sh" > "$MARKETPLACE_BLOCK"
assert_not_grep_extended '^[[:space:]]*set [+-]e' "$MARKETPLACE_BLOCK" \
    "marketplace reconciliation never changes global orchestrator shell state"

NUMERIC_VERSION="$TMPDIR/numeric-version.py"
UBO_CANDIDATE_ACTION="$TMPDIR/ubo-candidate-action.sh"
DKIM_PUBLISHER="$TMPDIR/dkim-publish.sh"
MARKETPLACE_PARSER="$TMPDIR/marketplace-xpi-release.py"
BROWSER_EXTENSION_INVENTORY="$TMPDIR/browser-extension-inventory.py"
extract_heredoc "$TMPDIR/noid-update-all.sh" NUMERIC_VERSION_PY \
    "$NUMERIC_VERSION" || _fail "numeric version comparator extraction"
{
    sed -n '/^numeric_version_is_newer()/,/^}$/p' \
        "$TMPDIR/noid-update-all.sh"
    sed -n '/^ubo_candidate_action()/,/^}$/p' \
        "$TMPDIR/noid-update-all.sh"
} > "$UBO_CANDIDATE_ACTION"
extract_heredoc "$TMPDIR/noid-update-all.sh" DKIM_PUBLISH_EOF \
    "$DKIM_PUBLISHER" || _fail "DKIM publisher extraction"
extract_heredoc "$TMPDIR/noid-update-all.sh" MARKETPLACE_XPI_RELEASE_PY \
    "$MARKETPLACE_PARSER" || _fail "marketplace XPI parser extraction"
extract_heredoc "$TMPDIR/noid-update-all.sh" BROWSER_EXTENSION_INVENTORY_PY \
    "$BROWSER_EXTENSION_INVENTORY" || _fail "browser extension inventory extraction"
assert_cmd_success "numeric extension comparator syntax" \
    python3 -m py_compile "$NUMERIC_VERSION"
assert_cmd_success "uBO candidate action parser syntax" \
    bash -n "$UBO_CANDIDATE_ACTION"
assert_cmd_success "DKIM root publisher parses" bash -n "$DKIM_PUBLISHER"
assert_cmd_success "marketplace XPI parser syntax" \
    python3 -m py_compile "$MARKETPLACE_PARSER"
assert_cmd_success "browser extension inventory syntax" \
    python3 -m py_compile "$BROWSER_EXTENSION_INVENTORY"
assert_cmd_success "DKIM root publisher passes ShellCheck" \
    shellcheck -s bash -S warning "$DKIM_PUBLISHER"
assert_grep_fixed '/var/lib/noid-privacy/managed-extensions/dkim_verifier@pl.xpi' \
    "$DKIM_PUBLISHER" "DKIM publisher allowlists the durable current slot"
assert_grep_fixed '/usr/lib64/thunderbird/distribution/extensions/dkim_verifier@pl.xpi' \
    "$DKIM_PUBLISHER" "DKIM publisher allowlists only the active distribution slot"
assert_grep_fixed '/var/tmp/noid-xpi-update.*/payload.xpi' "$DKIM_PUBLISHER" \
    "DKIM publisher accepts only updater-owned private staging"
assert_grep_fixed "stat -c '%u:%g:%a' \"\$parent\"" "$DKIM_PUBLISHER" \
    "DKIM publisher requires an existing exact root-owned parent"
# The publisher may create its own parent -- no module provisions
# /var/lib/noid-privacy/managed-extensions at build time, so without this the
# very first publication exits 2 and the DKIM update channel is dead for good.
# What must never happen is creating one below an unchecked location, so the
# grandparent is checked before the mkdir, exactly as
# publish_managed_thunderbird_config does, and the metadata is re-asserted after.
# The expected grandparent is derived from the destination the case arm already
# validated. Written as one literal equality it silently made the second
# allow-listed destination unreachable: /usr/lib64/thunderbird/distribution is
# not /var/lib/noid-privacy, so every publication to the active distribution
# slot exited 2 while the durable slot advanced without it.
assert_grep_fixed 'allowed_grandparent=/var/lib/noid-privacy' "$DKIM_PUBLISHER" \
    "DKIM publisher binds the durable slot to its own grandparent"
assert_grep_fixed 'allowed_grandparent=/usr/lib64/thunderbird/distribution' \
    "$DKIM_PUBLISHER" \
    "DKIM publisher binds the distribution slot to its own grandparent"
assert_grep_fixed '"$grandparent" = "$allowed_grandparent"' "$DKIM_PUBLISHER" \
    "DKIM publisher checks the grandparent the destination allows"
assert_not_grep_extended '\$grandparent" = /' "$DKIM_PUBLISHER" \
    "DKIM publisher never pins the grandparent to one hardcoded path again"
assert_grep_fixed 'install -d -m 0755 -o root -g root "$parent"' "$DKIM_PUBLISHER" \
    "DKIM publisher provisions its own durable slot instead of failing closed forever"
dkim_pin_line=$(grep -nF '"$grandparent" = "$allowed_grandparent"' "$DKIM_PUBLISHER" \
    | head -1 | cut -d: -f1 || true)
dkim_mkdir_line=$(grep -nF 'install -d -m 0755 -o root -g root "$parent"' \
    "$DKIM_PUBLISHER" | head -1 | cut -d: -f1 || true)
if [ -n "$dkim_pin_line" ] && [ -n "$dkim_mkdir_line" ] \
   && [ "$dkim_pin_line" -lt "$dkim_mkdir_line" ]; then
    _pass "DKIM publisher never creates a parent below an unchecked location"
else
    _fail "DKIM publisher must pin the grandparent before creating the parent"
fi
unset dkim_pin_line dkim_mkdir_line
# Drive the real derivation, both destinations, instead of only greping for the
# pin. Nothing here ever executed the publisher with the distribution slot, so
# a pin that rejected it read as correct for as long as it existed. The case
# arm and the two path derivations are lifted verbatim out of the shipped
# publisher, so this cannot pass against a source that lost them.
dkim_case_block=$(awk '/^case "\$destination" in$/,/^esac$/' "$DKIM_PUBLISHER")
# Execute the shipped comparison, never a restatement of it: a probe that
# rebuilds the test it is checking passes against the very regression it exists
# to catch.
# `|| true` is load-bearing under `set -euo pipefail`: without it a source that
# lost the line makes this substitution kill the whole test file, so the
# assertions below never report and the run is silently truncated instead of
# failing loudly. The same shape above needs it for the same reason.
dkim_equality=$(grep -F '"$grandparent" = ' "$DKIM_PUBLISHER" \
    | head -1 | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*\\$//' || true)
if [ -z "$dkim_case_block" ] || [ -z "$dkim_equality" ]; then
    _fail "DKIM publisher destination case arm not found for the derivation check"
else
    for dkim_probe_destination in \
        /var/lib/noid-privacy/managed-extensions/dkim_verifier@pl.xpi \
        /usr/lib64/thunderbird/distribution/extensions/dkim_verifier@pl.xpi; do
        dkim_probe_result=$(
            destination="$dkim_probe_destination"
            eval "$dkim_case_block"
            parent=${destination%/*}
            # Consumed by the shipped comparison eval'd below, which ShellCheck
            # cannot see into.
            # shellcheck disable=SC2034
            grandparent=${parent%/*}
            if eval "$dkim_equality"; then
                printf 'reachable'
            else
                printf 'refused'
            fi
        ) || dkim_probe_result="exited-nonzero"
        assert_eq "reachable" "$dkim_probe_result" \
            "DKIM publisher accepts its allow-listed destination ${dkim_probe_destination}"
    done
fi
# A destination outside the allow-list must still terminate the publisher.
dkim_probe_result=$(
    destination=/tmp/evil/dkim_verifier@pl.xpi
    eval "$dkim_case_block" 2>/dev/null
    printf 'accepted'
) || dkim_probe_result="rejected"
assert_eq "rejected" "$dkim_probe_result" \
    "DKIM publisher still refuses a destination outside the allow-list"
unset dkim_case_block dkim_equality dkim_probe_destination dkim_probe_result
TB_CONFIG_PUBLISHER="$TMPDIR/thunderbird-config-publish.sh"
extract_heredoc "$TMPDIR/noid-update-all.sh" TB_CONFIG_PUBLISH_EOF \
    "$TB_CONFIG_PUBLISHER" || _fail "Thunderbird config publisher extraction"
assert_cmd_success "Thunderbird config root publisher parses" \
    bash -n "$TB_CONFIG_PUBLISHER"
assert_cmd_success "Thunderbird config root publisher passes ShellCheck" \
    shellcheck -s bash -S warning "$TB_CONFIG_PUBLISHER"
assert_grep_fixed \
    '/usr/share/noid-thunderbird/noid-locale.js::/etc/thunderbird/pref/noid-locale.js' \
    "$TB_CONFIG_PUBLISHER" \
    "Thunderbird config publisher allowlists the locale pair"
assert_grep_fixed \
    '/usr/share/noid-thunderbird/policies.json::/etc/thunderbird/policies/policies.json' \
    "$TB_CONFIG_PUBLISHER" \
    "Thunderbird config publisher allowlists the policy pair"
assert_not_grep '::/usr/lib64/thunderbird/' "$TB_CONFIG_PUBLISHER" \
    "M25 config publisher does not duplicate M35 package-tree ownership"
assert_not_grep 'sudo install -Dm644' "$TMPDIR/noid-update-all.sh" \
    "Thunderbird config convergence has no non-atomic direct sudo install path"
assert_grep_fixed 'TB_DKIM_CURRENT_VALID=0' "$TMPDIR/noid-update-all.sh" \
    "missing/invalid DKIM current state enters the authenticated repair path"
assert_grep_fixed 'durable DKIM current slot restored at' "$TMPDIR/noid-update-all.sh" \
    "equal latest DKIM bytes repair the durable slot without requiring a newer release"
assert_grep_fixed 'Updates applied with ${WARNINGS} warning(s)' \
    "$TMPDIR/noid-update-all.sh" \
    "non-blocking warnings never produce a false all-systems-current claim"

MANAGED_XPI_RESOLVER="$TMPDIR/managed-xpi-resolver.sh"
sed -n '/^fetch_latest_xpi()/,/^}$/p' "$TMPDIR/noid-update-all.sh" \
    > "$MANAGED_XPI_RESOLVER"
assert_cmd_success "managed-XPI marketplace handoff parses" \
    bash -n "$MANAGED_XPI_RESOLVER"
run_managed_xpi_handoff_fixture() {
    local component=$1 expected_marketplace=$2 expected_identity=$3
    local expected_package=$4 expected_product_version=$5
    assert_cmd_success "managed $component marketplace bytes enter bounded staging" \
        env FIXTURE_COMPONENT="$component" \
            FIXTURE_MARKETPLACE="$expected_marketplace" \
            FIXTURE_IDENTITY="$expected_identity" \
            FIXTURE_PACKAGE="$expected_package" \
            FIXTURE_PRODUCT_VERSION="$expected_product_version" \
            bash -c '
                set -euo pipefail
                . "$1"
                fixture_root=$2
                marketplace_root="$fixture_root/marketplace-$FIXTURE_COMPONENT"
                fixture_bytes="authenticated-$FIXTURE_COMPONENT-payload"
                mkdir -p "$marketplace_root"
                UBO_POLICY_VALIDATOR=fixture_ubo_policy_validator
                UBO_POLICY_SOURCE="$fixture_root/managed-ubo-policy.json"

                payload_matches() {
                    [ -f "$1" ] && [ ! -L "$1" ] \
                        && [ "$(sha256sum "$1" | awk "{print \$1}")" = "$2" ]
                }
                trusted_root_file() { return 0; }
                fixture_ubo_policy_validator() { return 0; }
                sudo() {
                    [ "$1" = rpm ]
                    [ "${!#}" = "$FIXTURE_PACKAGE" ]
                    printf "%s\n" "$FIXTURE_PRODUCT_VERSION"
                }
                fetch_marketplace_xpi() {
                    [ "$1" = "$FIXTURE_MARKETPLACE" ]
                    [ "$2" = "$FIXTURE_IDENTITY" ]
                    [ "$3" = "$FIXTURE_PRODUCT_VERSION" ]
                    MARKETPLACE_WORK=$marketplace_root
                    MARKETPLACE_PATH="$marketplace_root/payload.xpi"
                    printf "%s\n" "$fixture_bytes" > "$MARKETPLACE_PATH"
                    MARKETPLACE_VERSION=9.8.7
                    MARKETPLACE_SIZE=$(stat -c "%s" "$MARKETPLACE_PATH")
                    MARKETPLACE_SHA256=$(sha256sum "$MARKETPLACE_PATH" \
                        | awk "{print \$1}")
                    MARKETPLACE_ERROR=
                }
                cleanup_marketplace_xpi() {
                    [ -z "${MARKETPLACE_WORK:-}" ] \
                        || rm -rf --one-file-system -- "$MARKETPLACE_WORK"
                    MARKETPLACE_WORK=
                    MARKETPLACE_PATH=
                }
                cleanup_latest_xpi() {
                    [ -z "${LATEST_XPI_WORK:-}" ] \
                        || rm -rf --one-file-system -- "$LATEST_XPI_WORK"
                    LATEST_XPI_WORK=
                    LATEST_XPI_PATH=
                }
                mktemp() {
                    command mktemp -d "$fixture_root/noid-xpi-update.XXXXXX"
                }

                fetch_latest_xpi "$FIXTURE_COMPONENT"
                [ "$LATEST_XPI_VERSION" = 9.8.7 ]
                [ "$LATEST_XPI_PRODUCT_VERSION" = "$FIXTURE_PRODUCT_VERSION" ]
                [ "$LATEST_XPI_SIZE" = "$(stat -c "%s" "$LATEST_XPI_PATH")" ]
                payload_matches "$LATEST_XPI_PATH" "$LATEST_XPI_SHA256"
                [ "$(stat -c "%a" "$LATEST_XPI_WORK")" = 700 ]
                [ "$(stat -c "%a" "$LATEST_XPI_PATH")" = 600 ]
                [ ! -e "$marketplace_root" ]
                cleanup_latest_xpi
                [ -z "$(find "$fixture_root" -maxdepth 1 \
                    -name "noid-xpi-update.*" -print -quit)" ]
            ' _ "$MANAGED_XPI_RESOLVER" \
            "$TMPDIR/managed-handoff-$component"
}
run_managed_xpi_handoff_fixture \
    ubo amo uBlock0@raymondhill.net firefox 153.0
run_managed_xpi_handoff_fixture \
    dkim atn dkim_verifier@pl thunderbird 152.0

assert_cmd_success "managed marketplace failure stays fail-closed and visible" \
    bash -c '
        set -euo pipefail
        . "$1"
        UBO_POLICY_VALIDATOR=fixture_ubo_policy_validator
        UBO_POLICY_SOURCE=/fixture/managed-ubo-policy.json
        payload_matches() { return 1; }
        trusted_root_file() { return 0; }
        fixture_ubo_policy_validator() { return 0; }
        sudo() { printf "%s\n" 153.0; }
        fetch_marketplace_xpi() {
            MARKETPLACE_ERROR="fixture marketplace unavailable"
            MARKETPLACE_ERROR_CLASS=availability
            MARKETPLACE_WORK=
            MARKETPLACE_PATH=
            return 1
        }
        cleanup_marketplace_xpi() {
            MARKETPLACE_WORK=
            MARKETPLACE_PATH=
        }
        cleanup_latest_xpi() { :; }
        rc=0
        fetch_latest_xpi ubo || rc=$?
        [ "$rc" -eq 1 ]
        [ "$LATEST_XPI_ERROR" = "fixture marketplace unavailable" ]
        [ "$LATEST_XPI_ERROR_CLASS" = availability ]
        [ -z "$LATEST_XPI_WORK" ]
        [ -z "$LATEST_XPI_PATH" ]
    ' _ "$MANAGED_XPI_RESOLVER"

assert_cmd_success "numeric comparator advances a true newer release" \
    python3 "$NUMERIC_VERSION" 6.3.1 6.3.0
assert_cmd_failure "numeric comparator rejects an equal release" \
    python3 "$NUMERIC_VERSION" 6.3.0 6.3.0
assert_cmd_failure "numeric comparator rejects a downgrade" \
    python3 "$NUMERIC_VERSION" 6.2.9 6.3.0
assert_eq advance "$(bash -c '. "$1"; ubo_candidate_action 1.74.0 1.73.0 0 0' \
    _ "$UBO_CANDIDATE_ACTION")" \
    "a newer authenticated uBO candidate repairs even an incompatible current copy"
assert_eq repair "$(bash -c '. "$1"; ubo_candidate_action 1.73.0 1.73.0 0 0' \
    _ "$UBO_CANDIDATE_ACTION")" \
    "equal-version incompatible uBO bytes enter the repair path"
assert_eq repair "$(bash -c '. "$1"; ubo_candidate_action 1.73.0 1.73.0.0 1 0' \
    _ "$UBO_CANDIDATE_ACTION")" \
    "numerically equal but noncanonical uBO bytes enter the repair path"
assert_eq keep "$(bash -c '. "$1"; ubo_candidate_action 1.73.0 1.74.0 1 0' \
    _ "$UBO_CANDIDATE_ACTION")" \
    "a compatible manually newer uBO copy is preserved"
assert_eq reject "$(bash -c '. "$1"; ubo_candidate_action 1.73.0 1.74.0 0 0' \
    _ "$UBO_CANDIDATE_ACTION")" \
    "an incompatible manually newer uBO copy fails without implicit downgrade"
assert_cmd_failure "uBO candidate action rejects malformed state flags" \
    bash -c '. "$1"; ubo_candidate_action 1.73.0 1.73.0 yes 0' \
        _ "$UBO_CANDIDATE_ACTION"

python3 - "$TMPDIR" <<'MARKETPLACE_FIXTURES_PY'
import copy
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
digest = "b" * 64
amo = {
    "count": 1, "next": None, "previous": None,
    "results": [{
        "guid": "fixture@example.org", "type": "extension",
        "is_disabled": False,
        "current_version": {
            "version": "2.4.0",
            "compatibility": {"firefox": {"min": "128.0", "max": "*"}},
            "file": {
                "status": "public", "size": 1234, "hash": "sha256:" + digest,
                "url": "https://addons.mozilla.org/firefox/downloads/file/1234/fixture-2.4.0.xpi",
            },
        },
    }],
}
atn = {
    "count": 1, "next": None, "previous": None,
    "results": [{
        "guid": "fixture-tb@example.org", "type": "extension",
        "is_disabled": False,
        "current_version": {
            "version": "7.1",
            "compatibility": {"thunderbird": {"min": "128.0", "max": "*"}},
            "files": [{
                "platform": "all", "status": "public", "size": 4321,
                "hash": "sha256:" + digest,
                "url": "https://addons.thunderbird.net/thunderbird/downloads/file/4321/fixture-tb-7.1.xpi?src=",
            }],
        },
    }],
}
for name, value in (("amo-marketplace.json", amo), ("atn-marketplace.json", atn)):
    (root / name).write_text(json.dumps(value), encoding="utf-8")
wrong = copy.deepcopy(amo)
wrong["results"][0]["guid"] = "attacker@example.org"
(root / "amo-wrong-guid.json").write_text(json.dumps(wrong), encoding="utf-8")
nonnumeric = copy.deepcopy(amo)
nonnumeric["results"][0]["current_version"]["version"] = "2.4beta"
(root / "amo-nonnumeric.json").write_text(json.dumps(nonnumeric), encoding="utf-8")
amo_bad_origin = copy.deepcopy(amo)
amo_bad_origin["results"][0]["current_version"]["file"]["url"] = (
    "https://example.org/firefox/downloads/file/1234/fixture-2.4.0.xpi"
)
(root / "amo-bad-origin.json").write_text(
    json.dumps(amo_bad_origin), encoding="utf-8"
)
atn_bad_origin = copy.deepcopy(atn)
atn_bad_origin["results"][0]["current_version"]["files"][0]["url"] = (
    "https://example.org/thunderbird/downloads/file/4321/fixture-tb-7.1.xpi"
)
(root / "atn-bad-origin.json").write_text(
    json.dumps(atn_bad_origin), encoding="utf-8"
)

home = root / "inventory-home"
ff_root = home / ".config" / "mozilla" / "firefox"
ff_profile = ff_root / "Profiles" / "default"
(ff_profile / "extensions").mkdir(parents=True)
ff_id = "{01234567-89ab-cdef-0123-456789abcdef}"
ff_xpi = ff_profile / "extensions" / f"{ff_id}.xpi"
ff_xpi.write_bytes(b"fixture")
(ff_profile / "extensions" / "uBlock0@raymondhill.net.xpi").write_bytes(b"seed")
(ff_profile / "extensions.json").write_text(json.dumps({"addons": [
    {"id": ff_id, "version": "1.0", "type": "extension",
     "location": "app-profile", "path": str(ff_xpi)},
    {"id": "uBlock0@raymondhill.net", "version": "1.73.0", "type": "extension",
     "location": "app-profile",
     "path": str(ff_profile / "extensions" / "uBlock0@raymondhill.net.xpi")},
]}), encoding="utf-8")
ff_root.mkdir(parents=True, exist_ok=True)
(ff_root / "profiles.ini").write_text(
    "[Profile0]\nName=fixture\nIsRelative=1\nPath=Profiles/default\n"
    "[ProfileGroups]\nStartWithLastProfile=1\n",
    encoding="utf-8")

tb_root = home / ".thunderbird"
tb_profile = home / "absolute-thunderbird-profile"
(tb_profile / "extensions").mkdir(parents=True)
tb_xpi = tb_profile / "extensions" / "fixture-tb@example.org.xpi"
tb_xpi.write_bytes(b"fixture")
(tb_profile / "extensions.json").write_text(json.dumps({"addons": [
    {"id": "fixture-tb@example.org", "version": "4.0", "type": "extension",
     "location": "app-profile", "path": str(tb_xpi)},
]}), encoding="utf-8")
tb_root.mkdir(parents=True)
(tb_root / "profiles.ini").write_text(
    f"[Profile0]\nName=absolute-fixture\nIsRelative=0\nPath={tb_profile}\n",
    encoding="utf-8")
MARKETPLACE_FIXTURES_PY

expected_marketplace_sha=$(printf 'b%.0s' {1..64})
assert_cmd_success "AMO compatible release metadata is accepted" \
    bash -c 'test "$(python3 "$1" "$2" amo fixture@example.org)" = "$3"' _ \
    "$MARKETPLACE_PARSER" "$TMPDIR/amo-marketplace.json" \
    $'2.4.0\t1234\t'"$expected_marketplace_sha"$'\thttps://addons.mozilla.org/firefox/downloads/file/1234/fixture-2.4.0.xpi'
assert_cmd_success "ATN compatible release metadata is accepted" \
    python3 "$MARKETPLACE_PARSER" "$TMPDIR/atn-marketplace.json" \
        atn fixture-tb@example.org
assert_cmd_failure "marketplace parser rejects GUID substitution" \
    python3 "$MARKETPLACE_PARSER" "$TMPDIR/amo-wrong-guid.json" \
        amo fixture@example.org
assert_cmd_success "non-numeric marketplace release has dedicated status 3" \
    bash -c 'rc=0; python3 "$1" "$2" amo fixture@example.org || rc=$?; [ "$rc" -eq 3 ]' _ \
    "$MARKETPLACE_PARSER" "$TMPDIR/amo-nonnumeric.json"
assert_cmd_failure "AMO metadata rejects an unreviewed download origin" \
    python3 "$MARKETPLACE_PARSER" "$TMPDIR/amo-bad-origin.json" \
        amo fixture@example.org
assert_cmd_failure "ATN metadata rejects an unreviewed download origin" \
    python3 "$MARKETPLACE_PARSER" "$TMPDIR/atn-bad-origin.json" \
        atn fixture-tb@example.org
assert_cmd_success "Firefox inventory includes brace GUIDs and excludes managed uBO" \
    python3 "$BROWSER_EXTENSION_INVENTORY" firefox \
        "$TMPDIR/firefox-inventory.tsv" "$TMPDIR/inventory-home/.config" \
        "$TMPDIR/inventory-home"
assert_grep_fixed $'{01234567-89ab-cdef-0123-456789abcdef}\t1.0\t' \
    "$TMPDIR/firefox-inventory.tsv" \
    "Firefox inventory preserves a valid legacy brace GUID"
assert_not_grep 'uBlock0@raymondhill.net' "$TMPDIR/firefox-inventory.tsv" \
    "dedicated uBO payload is excluded from generic AMO ownership"
assert_eq 1 "$(wc -l < "$TMPDIR/firefox-inventory.tsv")" \
    "Firefox inventory ignores the non-profile registry section"
cp -a "$TMPDIR/inventory-home" "$TMPDIR/inventory-duplicate-home"
cat >> "$TMPDIR/inventory-duplicate-home/.config/mozilla/firefox/profiles.ini" <<'DUPLICATE_PROFILE_EOF'
[Profile0]
Name=duplicate
IsRelative=1
Path=Profiles/default
DUPLICATE_PROFILE_EOF
assert_cmd_failure "Firefox inventory rejects duplicate profile sections" \
    python3 "$BROWSER_EXTENSION_INVENTORY" firefox \
        "$TMPDIR/firefox-inventory-duplicate.tsv" \
        "$TMPDIR/inventory-duplicate-home/.config" \
        "$TMPDIR/inventory-duplicate-home"
assert_cmd_success "Thunderbird inventory covers registered absolute profiles under home" \
    python3 "$BROWSER_EXTENSION_INVENTORY" thunderbird \
        "$TMPDIR/thunderbird-inventory.tsv" "$TMPDIR/inventory-home/.config" \
        "$TMPDIR/inventory-home"
assert_grep_fixed $'fixture-tb@example.org\t4.0\t' \
    "$TMPDIR/thunderbird-inventory.tsv" \
    "Thunderbird inventory includes the profile-owned ATN extension"

# Exercise the exact EGO archive parser, including the Info-ZIP symlink class
# that motivated the transactional publisher. No downloaded path reaches the
# root transaction until this parser accepts every entry and exact metadata.
EGO_VALIDATOR="$TMPDIR/ego-validate.py"
EGO_PUBLISHER="$TMPDIR/ego-publish.sh"
EGO_EXCHANGE="$TMPDIR/ego-exchange.py"
extract_heredoc "$TMPDIR/noid-update-all.sh" EGO_VALIDATE_PY "$EGO_VALIDATOR" \
    || _fail "EGO archive validator extraction"
extract_heredoc "$TMPDIR/noid-update-all.sh" EGO_PUBLISH_EOF "$EGO_PUBLISHER" \
    || _fail "EGO atomic publisher extraction"
extract_heredoc "$TMPDIR/noid-update-all.sh" EGO_EXCHANGE_PY "$EGO_EXCHANGE" \
    || _fail "EGO exchange primitive extraction"
assert_cmd_success "EGO atomic publisher parses" bash -n "$EGO_PUBLISHER"
assert_cmd_success "EGO atomic publisher passes ShellCheck" \
    shellcheck -s bash -S warning "$EGO_PUBLISHER"
python3 - "$TMPDIR" <<'PY'
import json
import stat
import sys
import zipfile

root = sys.argv[1]
metadata = {"uuid": "fixture@example.org", "version": 2,
            "shell-version": ["50"]}
def base(bundle):
    bundle.writestr("metadata.json", json.dumps(metadata))
with zipfile.ZipFile(root + "/ego-good.zip", "w") as bundle:
    base(bundle)
    bundle.writestr("extension.js", "reviewed fixture bytes\n")
with zipfile.ZipFile(root + "/ego-traversal.zip", "w") as bundle:
    base(bundle)
    bundle.writestr("../outside", "forbidden\n")
with zipfile.ZipFile(root + "/ego-symlink.zip", "w") as bundle:
    base(bundle)
    link = zipfile.ZipInfo("vendor-link")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    bundle.writestr(link, "/etc")
PY
assert_cmd_success "exact EGO bundle fixture validates and extracts" \
    python3 "$EGO_VALIDATOR" "$TMPDIR/ego-good.zip" "$TMPDIR/ego-good" \
        fixture@example.org 2 50
assert_grep_fixed 'reviewed fixture bytes' "$TMPDIR/ego-good/extension.js" \
    "validated EGO fixture preserves exact regular-file bytes"
assert_cmd_failure "EGO validator rejects parent traversal" \
    python3 "$EGO_VALIDATOR" "$TMPDIR/ego-traversal.zip" \
        "$TMPDIR/ego-traversal" fixture@example.org 2 50
assert_cmd_failure "EGO validator rejects symlink archive entries" \
    python3 "$EGO_VALIDATOR" "$TMPDIR/ego-symlink.zip" \
        "$TMPDIR/ego-symlink" fixture@example.org 2 50
assert_cmd_failure "EGO validator rejects a UUID mismatch" \
    python3 "$EGO_VALIDATOR" "$TMPDIR/ego-good.zip" \
        "$TMPDIR/ego-wrong-uuid" other@example.org 2 50
assert_cmd_failure "EGO validator rejects a version mismatch" \
    python3 "$EGO_VALIDATOR" "$TMPDIR/ego-good.zip" \
        "$TMPDIR/ego-wrong-version" fixture@example.org 3 50
assert_cmd_failure "EGO validator rejects a shell-major mismatch" \
    python3 "$EGO_VALIDATOR" "$TMPDIR/ego-good.zip" \
        "$TMPDIR/ego-wrong-shell" fixture@example.org 2 49
ego_bound_sha=$(python3 "$EGO_VALIDATOR" "$TMPDIR/ego-good.zip" \
    "$TMPDIR/ego-bound" fixture@example.org 2 50)
if [[ "$ego_bound_sha" =~ ^[0-9a-f]{64}$ ]]; then
    _pass "EGO validator emits one exact final-tree SHA-256"
else
    _fail "EGO validator final-tree identity is malformed"
fi
EGO_TREE_DIGEST="$TMPDIR/ego-tree-digest.py"
extract_heredoc "$EGO_PUBLISHER" EGO_TREE_DIGEST_PY "$EGO_TREE_DIGEST" \
    || _fail "EGO publisher tree-digest extraction"
assert_cmd_success "EGO root-side tree digest parser is valid Python" \
    python3 -m py_compile "$EGO_TREE_DIGEST"
assert_eq "$ego_bound_sha" \
    "$(python3 "$EGO_TREE_DIGEST" "$TMPDIR/ego-bound")" \
    "root candidate digest matches the exact unprivileged validated tree"
printf '%s\n' 'same metadata, substituted extension code' \
    > "$TMPDIR/ego-bound/extension.js"
tampered_ego_sha=$(python3 "$EGO_TREE_DIGEST" "$TMPDIR/ego-bound")
if [ "$tampered_ego_sha" != "$ego_bound_sha" ]; then
    _pass "post-validation EGO byte substitution changes the publication identity"
else
    _fail "post-validation EGO byte substitution escaped the publication identity"
fi
assert_grep_fixed '[ "$actual_tree_sha" = "$expected_tree_sha" ] || exit 2' \
    "$EGO_PUBLISHER" \
    "EGO publisher rejects candidate bytes not bound to validation"
assert_grep_fixed '[ "$parent" = /usr/share/gnome-shell/extensions ]' \
    "$EGO_PUBLISHER" \
    "EGO publisher requires the one canonical system-extension parent"
assert_grep_fixed "stat -c '%u:%g:%a' \"\$parent\"" "$EGO_PUBLISHER" \
    "EGO publisher verifies root-owned non-writable parent metadata"
mkdir "$TMPDIR/ego-old" "$TMPDIR/ego-new"
printf 'old\n' > "$TMPDIR/ego-old/value"
printf 'new\n' > "$TMPDIR/ego-new/value"
assert_cmd_success "kernel supports atomic directory exchange" \
    python3 "$EGO_EXCHANGE" "$TMPDIR/ego-old" "$TMPDIR/ego-new"
assert_eq new "$(cat "$TMPDIR/ego-old/value")" \
    "atomic exchange publishes the complete new tree"
assert_eq old "$(cat "$TMPDIR/ego-new/value")" \
    "atomic exchange retains the complete old tree for cleanup"
assert_grep_fixed 'restorecon -RF "$candidate"' "$EGO_PUBLISHER" \
    "SELinux labeling succeeds before the public path changes"
assert_grep_fixed '/var/tmp/noid-ego-extension.*/staged' "$EGO_PUBLISHER" \
    "root publisher accepts only the updater-owned staging namespace"

# Run the exact Step 6c block against a fake Codium/Open-VSX channel. This
# proves the global CLI is not merely followed by a cosmetic agent skip, native
# failures are visible, exact REST advancement is postcondition-checked and an
# older registry value cannot downgrade the installed extension.
VSX_BLOCK="$TMPDIR/vsx-block.sh"
sed -n '/^# \[6c\] VSCodium Extensions/,/^# \[7\] Repo Signature/p' \
    "$TMPDIR/noid-update-all.sh" > "$VSX_BLOCK"
mkdir "$TMPDIR/vsx-bin"
cat > "$TMPDIR/vsx-bin/codium" <<'VSX_CODIUM_EOF'
#!/bin/bash
printf '%s\n' "$*" >>"$FAKE_VSX_LOG"
case "${1:-}" in
    --list-extensions)
        [ -z "${FAKE_VSX_LIST_STDERR:-}" ] \
            || printf '%s\n' "$FAKE_VSX_LIST_STDERR" >&2
        cat "$FAKE_VSX_STATE"
        exit "${FAKE_VSX_LIST_RC:-0}"
        ;;
    --update-extensions)
        echo native-global
        exit "${FAKE_VSX_NATIVE_RC:-0}"
        ;;
    --install-extension)
        spec=$2
        if [[ "$spec" == *@* ]]; then
            identity=${spec%@*}
            version=${spec##*@}
            awk -F@ -v identity="$identity" -v version="$version" '
                BEGIN { IGNORECASE=1 }
                tolower($1) == tolower(identity) {
                    print identity "@" version; found=1; next
                }
                { print }
                END { if (!found) print identity "@" version }
            ' "$FAKE_VSX_STATE" >"$FAKE_VSX_STATE.new"
            mv "$FAKE_VSX_STATE.new" "$FAKE_VSX_STATE"
        fi
        echo installed
        exit "${FAKE_VSX_INSTALL_RC:-0}"
        ;;
esac
exit 2
VSX_CODIUM_EOF
cat > "$TMPDIR/vsx-bin/curl" <<'VSX_CURL_EOF'
#!/bin/bash
url=
for argument; do
    [[ "$argument" == https://* ]] && url=$argument
done
path=${url#https://open-vsx.org/api/}
publisher=${path%%/*}
rest=${path#*/}
name=${rest%%/*}
platform=${rest#*/}
platform=${platform%%/*}
printf '{"namespace":"%s","name":"%s","version":"%s","targetPlatform":"%s"}\n' \
    "$publisher" "$name" "$FAKE_VSX_LATEST" "$platform"
VSX_CURL_EOF
chmod +x "$TMPDIR/vsx-bin/codium" "$TMPDIR/vsx-bin/curl"
VSX_RUNNER="$TMPDIR/vsx-runner.sh"
{
    printf '%s\n' '#!/bin/bash' 'set -uo pipefail'
    printf 'PATH=%q:/usr/bin\n' "$TMPDIR/vsx-bin"
    printf '%s\n' 'RED= GREEN= YELLOW= NC=' \
        'ERRORS=0; WARNINGS=0; SKIPPED_LIST=()' 'step() { :; }'
    cat "$VSX_BLOCK"
    printf '%s\n' 'printf "WARNINGS=%s ERRORS=%s\n" "$WARNINGS" "$ERRORS"'
} > "$VSX_RUNNER"
chmod +x "$VSX_RUNNER"

printf '%s\n' 'anthropic.claude-code@2.1.210' \
    'openai.chatgpt@26.1.0' > "$TMPDIR/vsx-state"
: > "$TMPDIR/vsx-calls"
FAKE_VSX_STATE="$TMPDIR/vsx-state" FAKE_VSX_LOG="$TMPDIR/vsx-calls" \
FAKE_VSX_LATEST=99.0.0 bash "$VSX_RUNNER" > "$TMPDIR/vsx-agent-only.out"
assert_not_grep '^--update-extensions$\|^--install-extension' \
    "$TMPDIR/vsx-calls" \
    "agent-only inventory performs no general extension mutation"
assert_grep_fixed 'no non-agent extensions are installed; Step 6 owns any managed agent extensions' \
    "$TMPDIR/vsx-agent-only.out" \
    "agent-only inventory points to its actual update owner"
assert_grep_fixed 'no additional VSCodium extensions require Open-VSX reconciliation' \
    "$TMPDIR/vsx-agent-only.out" \
    "agent-only inventory reports the exact empty Step 6c scope"
assert_not_grep 'VSCodium extension versions are current$' \
    "$TMPDIR/vsx-agent-only.out" \
    "Step 6c never certifies agent versions it deliberately skipped"

printf '%s\n' 'anthropic.claude-code@2.1.210' \
    'redhat.vscode-yaml@1.0.0' > "$TMPDIR/vsx-state"
: > "$TMPDIR/vsx-calls"
FAKE_VSX_STATE="$TMPDIR/vsx-state" FAKE_VSX_LOG="$TMPDIR/vsx-calls" \
FAKE_VSX_LATEST=2.0.0 FAKE_VSX_LIST_STDERR='fixture Electron diagnostic' \
    bash "$VSX_RUNNER" > "$TMPDIR/vsx-agent.out"
assert_not_grep '^--update-extensions$' "$TMPDIR/vsx-calls" \
    "global Codium updater never touches an installed managed agent"
assert_not_grep 'install-extension anthropic.claude-code' "$TMPDIR/vsx-calls" \
    "general extension path never installs the Claude agent"
assert_grep_fixed '--install-extension redhat.vscode-yaml@2.0.0 --force' \
    "$TMPDIR/vsx-calls" "non-agent REST advancement uses the exact version"
assert_grep_fixed 'anthropic.claude-code@2.1.210' "$TMPDIR/vsx-state" \
    "agent extension remains byte-channel owned by Step 6"
assert_grep_fixed 'redhat.vscode-yaml@2.0.0' "$TMPDIR/vsx-state" \
    "non-agent exact advancement satisfies its postcondition"
assert_not_grep 'malformed VSCodium extension inventory row' \
    "$TMPDIR/vsx-agent.out" \
    "successful Codium stderr diagnostics never become inventory rows"
assert_grep_fixed 'WARNINGS=0 ERRORS=0' "$TMPDIR/vsx-agent.out" \
    "successful Codium stderr diagnostics do not fail the update"

printf '%s\n' 'redhat.vscode-yaml@3.0.0' > "$TMPDIR/vsx-state"
: > "$TMPDIR/vsx-calls"
FAKE_VSX_STATE="$TMPDIR/vsx-state" FAKE_VSX_LOG="$TMPDIR/vsx-calls" \
FAKE_VSX_LATEST=2.0.0 FAKE_VSX_NATIVE_RC=42 \
    bash "$VSX_RUNNER" > "$TMPDIR/vsx-downgrade.out"
assert_grep_fixed '--update-extensions' "$TMPDIR/vsx-calls" \
    "agent-free profile uses Codium's global native updater first"
assert_not_grep 'redhat.vscode-yaml@2.0.0' "$TMPDIR/vsx-calls" \
    "older Open-VSX value is never installed"
assert_grep_fixed 'native VSCodium extension update reported a failure' \
    "$TMPDIR/vsx-downgrade.out" "native CLI failure is not reported as green"
assert_grep_fixed 'no downgrade' "$TMPDIR/vsx-downgrade.out" \
    "registry regression is explicit"
assert_grep_fixed 'WARNINGS=0 ERRORS=1' "$TMPDIR/vsx-downgrade.out" \
    "native failure makes the total extension-update run visibly incomplete"

printf '%s\n' 'redhat.vscode-yaml@1.0.0-beta' > "$TMPDIR/vsx-state"
: > "$TMPDIR/vsx-calls"
FAKE_VSX_STATE="$TMPDIR/vsx-state" FAKE_VSX_LOG="$TMPDIR/vsx-calls" \
FAKE_VSX_LATEST=2.0.0 bash "$VSX_RUNNER" > "$TMPDIR/vsx-unordered.out"
assert_not_grep 'install-extension redhat.vscode-yaml@2.0.0' \
    "$TMPDIR/vsx-calls" \
    "unorderable installed version is left to Codium's native update path"
assert_grep_fixed 'version ordering is unprovable' \
    "$TMPDIR/vsx-unordered.out" \
    "unparseable version pairs never produce a false installed-newer claim"
assert_not_grep 'installed 1.0.0-beta is newer than registry' \
    "$TMPDIR/vsx-unordered.out" \
    "unparseable version pairs have no false green no-downgrade result"
assert_grep_fixed 'WARNINGS=1 ERRORS=0' "$TMPDIR/vsx-unordered.out" \
    "unorderable native-owned version state is an explicit warning"

printf '%s\n' 'redhat.vscode-yaml@3.0.0' > "$TMPDIR/vsx-state"
: > "$TMPDIR/vsx-calls"
FAKE_VSX_STATE="$TMPDIR/vsx-state" FAKE_VSX_LOG="$TMPDIR/vsx-calls" \
FAKE_VSX_LATEST=3.0.0-beta bash "$VSX_RUNNER" \
    > "$TMPDIR/vsx-prerelease.out"
assert_not_grep 'install-extension redhat.vscode-yaml@3.0.0-beta' \
    "$TMPDIR/vsx-calls" \
    "REST fallback cannot replace a release with a pre-release"
assert_grep_fixed 'redhat.vscode-yaml@3.0.0' "$TMPDIR/vsx-state" \
    "installed release survives a registry pre-release response"
assert_grep_fixed 'Open-VSX REST channel unavailable for 1 extension state(s)' \
    "$TMPDIR/vsx-prerelease.out" \
    "an unavailable Open-VSX response is an explicit retryable warning"
assert_grep_fixed 'WARNINGS=1 ERRORS=0' "$TMPDIR/vsx-prerelease.out" \
    "an unavailable Open-VSX response leaves a successful native run non-blocking"

printf '%s\n' 'redhat.vscode-yaml@1.25.2026071400' > "$TMPDIR/vsx-state"
: > "$TMPDIR/vsx-calls"
FAKE_VSX_STATE="$TMPDIR/vsx-state" FAKE_VSX_LOG="$TMPDIR/vsx-calls" \
FAKE_VSX_LATEST=1.25.2026071508 bash "$VSX_RUNNER" \
    > "$TMPDIR/vsx-datestamp.out"
assert_grep_fixed '--install-extension redhat.vscode-yaml@1.25.2026071508 --force' \
    "$TMPDIR/vsx-calls" \
    "date-stamped registry segments beyond nine digits advance exactly"
assert_grep_fixed 'redhat.vscode-yaml@1.25.2026071508' "$TMPDIR/vsx-state" \
    "date-stamped advancement satisfies its exact postcondition"

# Every duplicated runtime pin must equal its canonical reviewed installer or
# image-build pin. A one-sided version bump is a test failure.
pin_value() {
    local values count
    values=$(sed -n "s/^$2=\"\([^\"]*\)\"$/\1/p" "$1")
    count=$(grep -c . <<<"$values" || true)
    [ "$count" -eq 1 ] && [ -n "$values" ] || return 1
    printf '%s\n' "$values"
}
assert_pin_eq() {
    local canonical_file=$1 canonical_name=$2 runtime_file=$3 runtime_name=$4
    local description=$5 canonical_value runtime_value
    if ! canonical_value=$(pin_value "$canonical_file" "$canonical_name"); then
        _fail "$description (missing or duplicate canonical pin $canonical_name)"
        return
    fi
    if ! runtime_value=$(pin_value "$runtime_file" "$runtime_name"); then
        _fail "$description (missing or duplicate runtime pin $runtime_name)"
        return
    fi
    assert_eq "$canonical_value" "$runtime_value" "$description"
}
assert_grep_extended '^EXT_VERSION="[0-9]+\.[0-9]+\.[0-9]+"$' \
    "$TMPDIR/noid-claude-install" \
    "Claude installer pins its VSCodium extension version"
assert_grep_extended '^EXT_SHA256="[a-f0-9]{64}"$' "$TMPDIR/noid-claude-install" \
    "Claude installer pins its VSCodium extension SHA-256"
assert_grep_extended '^EXT_SIZE="[0-9]+"$' "$TMPDIR/noid-claude-install" \
    "Claude installer pins its VSCodium extension byte count"
for helper in noid-claude-install noid-codex-install; do
    assert_grep_fixed '--update' "$TMPDIR/$helper" \
        "$helper exposes the consent-gated update mode"
    assert_grep_fixed 'agent-updates.log' "$TMPDIR/$helper" \
        "$helper records update evidence in the agent ledger"
    assert_grep_fixed 'exit 3' "$TMPDIR/$helper" \
        "$helper reports the never-opted-in state distinctly"
    assert_not_grep 'install.sh' "$TMPDIR/$helper" \
        "$helper never falls back to a remote shell installer"
done
assert_grep_fixed '.local/share/claude/versions' "$TMPDIR/noid-claude-install" \
    "Claude update path is bound to the NoID Privacy-managed layout"
assert_grep_fixed 'CODEX_LATEST_URL="https://github.com/openai/codex/releases/latest"' \
    "$TMPDIR/noid-codex-install" \
    "Codex update resolves the newest official release without the shared REST quota"
assert_not_grep 'api.github.com/repos/openai/codex/releases/latest' \
    "$TMPDIR/noid-codex-install" \
    "Codex update does not reintroduce the exhausted unauthenticated API path"
assert_pin_eq "$M17_FILE" JP_VERSION \
    "$TMPDIR/noid-update-all.sh" JP_SEED_VERSION \
    "Just-Perfection image and runtime seed versions match"
assert_pin_eq "$M17_FILE" JP_SHA256 \
    "$TMPDIR/noid-update-all.sh" JP_SEED_SHA256 \
    "Just-Perfection image and runtime seed digests match"
assert_pin_eq "$M35_FILE" DKIM_VERIFIER_SHA256 \
    "$TMPDIR/noid-update-all.sh" TB_DKIM_SEED_SHA256 \
    "Thunderbird build and runtime seed XPI digests match"

# Identity primitive fixtures cover exact bytes, partial/truncated data,
# digest mismatch, malformed digest and symlink substitution.
awk '/^payload_matches\(\) \{/{copy=1} copy{print} copy && /^\}/{exit}' \
    "$TMPDIR/noid-update-all.sh" > "$TMPDIR/payload-matches.sh"
printf 'complete reviewed payload\n' > "$TMPDIR/payload.good"
good_sha=$(sha256sum "$TMPDIR/payload.good" | awk '{print $1}')
printf 'complete reviewed' > "$TMPDIR/payload.partial"
ln -s payload.good "$TMPDIR/payload.link"
assert_cmd_success "exact payload fixture is accepted" \
    bash -c '. "$1"; payload_matches "$2" "$3"' _ \
    "$TMPDIR/payload-matches.sh" "$TMPDIR/payload.good" "$good_sha"
assert_cmd_failure "partial payload fixture is rejected" \
    bash -c '. "$1"; payload_matches "$2" "$3"' _ \
    "$TMPDIR/payload-matches.sh" "$TMPDIR/payload.partial" "$good_sha"
assert_cmd_failure "identity mismatch fixture is rejected" \
    bash -c '. "$1"; payload_matches "$2" "$3"' _ \
    "$TMPDIR/payload-matches.sh" "$TMPDIR/payload.good" \
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
assert_cmd_failure "malformed digest fixture is rejected" \
    bash -c '. "$1"; payload_matches "$2" "$3"' _ \
    "$TMPDIR/payload-matches.sh" "$TMPDIR/payload.good" not-a-digest
assert_cmd_failure "symlink payload fixture is rejected" \
    bash -c '. "$1"; payload_matches "$2" "$3"' _ \
    "$TMPDIR/payload-matches.sh" "$TMPDIR/payload.link" "$good_sha"
assert_grep_fixed 'canonical Thunderbird DKIM XPI is missing, symlinked or differs' \
    "$TMPDIR/noid-update-all.sh" \
    "Thunderbird source identity mismatch blocks redeploy"
assert_grep_fixed 'installed Thunderbird DKIM XPI differs from the validated current source' \
    "$TMPDIR/noid-update-all.sh" \
    "Thunderbird destination identity is verified after commit"

# Package, Flatpak and firmware subcommands must not report success after a
# failed mutation. Cleanup covers both Flatpak installation scopes.
assert_not_grep 'dnf clean expire-cache' "$TMPDIR/noid-update-all.sh" \
    "documented --refresh owns metadata freshness without a redundant cache mutation"
assert_grep_fixed 'LC_ALL=C dnf "$1" upgrade --refresh -y' \
    "$TMPDIR/noid-update-all.sh" \
    "DNF transaction forces one authoritative metadata refresh"
assert_grep_fixed "dnf_signature_setopt='--setopt=*.pkg_gpgcheck=True'" \
    "$TMPDIR/noid-update-all.sh" \
    "DNF transaction enforces package signature checks at command-line priority"
assert_grep_fixed '_ "$dnf_signature_setopt"' "$TMPDIR/noid-update-all.sh" \
    "DNF transaction consumes the canonical signature guard argument"
assert_grep_fixed 'openh264_opted_in()' "$TMPDIR/noid-update-all.sh" \
    "codec update policy handles partial explicit installations"
assert_grep_fixed 'dnf --cacheonly check-upgrade "$@"' \
    "$TMPDIR/noid-update-all.sh" \
    "DNF success is followed by the documented cached completeness check"
assert_grep_fixed 'DNF left update candidates unresolved' \
    "$TMPDIR/noid-update-all.sh" \
    "DNF5 partial success cannot claim that every RPM is current"
assert_not_grep 'dnf upgrade --refresh -y --best' \
    "$TMPDIR/noid-update-all.sh" \
    "one third-party dependency skew cannot block unrelated Fedora updates"

awk '
    /^verify_dnf_completeness\(\)/ { copy=1 }
    copy { print }
    copy && /^}$/ { exit }
' "$TMPDIR/noid-update-all.sh" > "$TMPDIR/dnf-completeness.function"
mkdir "$TMPDIR/dnf-postflight-bin"
cat > "$TMPDIR/dnf-postflight-bin/dnf" <<'DNF_POSTFLIGHT_EOF'
#!/bin/bash
printf '%s\n' "${FAKE_DNF_OUTPUT:-}"
exit "${FAKE_DNF_RC:-0}"
DNF_POSTFLIGHT_EOF
chmod +x "$TMPDIR/dnf-postflight-bin/dnf"
run_dnf_postflight_fixture() {
    local fake_rc=$1 expected_warnings=$2 expected_errors=$3 output
    output=$(PATH="$TMPDIR/dnf-postflight-bin:/usr/bin" \
        FAKE_DNF_RC="$fake_rc" FAKE_DNF_OUTPUT='mesa fixture remains' \
        bash -c '
            sudo() {
                while [[ "${1:-}" == *=* ]]; do export "$1"; shift; done
                "$@"
            }
            RED= GREEN= YELLOW= NC=
            WARNINGS=0 ERRORS=0
            . "$1"
            verify_dnf_completeness --exclude=codec || true
            printf "WARNINGS=%s ERRORS=%s\n" "$WARNINGS" "$ERRORS"
        ' _ "$TMPDIR/dnf-completeness.function")
    assert_grep_fixed "WARNINGS=${expected_warnings} ERRORS=${expected_errors}" \
        <(printf '%s\n' "$output") \
        "DNF postflight exit ${fake_rc} reaches the correct summary state"
}
run_dnf_postflight_fixture 0 0 0
run_dnf_postflight_fixture 100 1 0
run_dnf_postflight_fixture 1 0 1

awk '
    /^openh264_opted_in\(\)/ { copy=1 }
    copy { print }
    copy && /^}$/ { exit }
' "$TMPDIR/noid-update-all.sh" > "$TMPDIR/openh264-optin.function"
mkdir "$TMPDIR/openh264-optin-bin"
cat > "$TMPDIR/openh264-optin-bin/rpm" <<'OPENH264_RPM_EOF'
#!/bin/bash
[[ $1 == -q && ",${FAKE_CODEC_PACKAGES:-}," == *",$2,"* ]]
OPENH264_RPM_EOF
chmod 0755 "$TMPDIR/openh264-optin-bin/rpm"
run_openh264_optin_fixture() {
    local installed=$1 expected_rc=$2 actual_rc=0
    PATH="$TMPDIR/openh264-optin-bin:/usr/bin" \
        FAKE_CODEC_PACKAGES="$installed" bash -c '
            sudo() { "$@"; }
            . "$1"
            openh264_opted_in
        ' _ "$TMPDIR/openh264-optin.function" || actual_rc=$?
    assert_eq "$expected_rc" "$actual_rc" \
        "codec opt-in state for installed set '${installed:-none}'"
}
run_openh264_optin_fixture '' 1
run_openh264_optin_fixture openh264 0
run_openh264_optin_fixture mozilla-openh264 0
run_openh264_optin_fixture gstreamer1-plugin-openh264 0

sed -n '/^newest_installed_kernel_package()/,/^}$/p' \
    "$TMPDIR/noid-update-all.sh" > "$TMPDIR/newest-kernel.function"
assert_cmd_success "newest-kernel package query parses" \
    bash -n "$TMPDIR/newest-kernel.function"
assert_eq kernel-7.1.10-200.fc44.x86_64 "$(
    FAKE_KERNEL_INVENTORY=$'kernel-7.1.9-200.fc44.x86_64\nkernel-7.1.10-200.fc44.x86_64' \
        bash -c '
            sudo() { printf "%s\n" "$FAKE_KERNEL_INVENTORY"; }
            . "$1"
            newest_installed_kernel_package
        ' _ "$TMPDIR/newest-kernel.function"
)" "kernel inventory selects the highest installed version"
assert_eq kernel-7.1.10-200.fc44.x86_64 "$(
    FAKE_KERNEL_INVENTORY=$'kernel-7.1.10-200.fc44.x86_64\nkernel-7.1.9-200.fc44.x86_64' \
        bash -c '
            sudo() { printf "%s\n" "$FAKE_KERNEL_INVENTORY"; }
            . "$1"
            newest_installed_kernel_package
        ' _ "$TMPDIR/newest-kernel.function"
)" "later inventory order cannot make an older parallel kernel newest"
assert_cmd_failure "malformed kernel inventory cannot produce a partial identity" \
    env FAKE_KERNEL_INVENTORY=$'kernel-7.1.10-200.fc44.x86_64\nunexpected diagnostic' \
        bash -c '
            sudo() { printf "%s\n" "$FAKE_KERNEL_INVENTORY"; }
            . "$1"
            newest_installed_kernel_package
        ' _ "$TMPDIR/newest-kernel.function"
assert_cmd_failure "failed kernel RPM query cannot synthesize a package identity" \
    bash -c '
        sudo() {
            printf "%s\n" "package kernel is not installed"
            return 1
        }
        . "$1"
        newest_installed_kernel_package
    ' _ "$TMPDIR/newest-kernel.function"
assert_cmd_success "Step 9 delegates kernel and NVIDIA state to the canonical reader" \
    python3 - "$TMPDIR/noid-update-all.sh" <<'PY'
import sys

text = open(sys.argv[1], encoding='utf-8').read()
start = text.index('# [9] Reboot Check')
end = text.index('# Run `needs-restarting -s`', start)
step = text[start:end]
for duplicate in ('newest_installed_kernel_package',
                  '/proc/driver/nvidia/version', 'modinfo -F version nvidia'):
    assert duplicate not in step
assert step.count('dnf needs-restarting --json') == 1
summary = text.index('# Complete the boot-scoped safety transaction', end)
reader = text.index('if ! load_reboot_readiness; then', summary)
publisher = text.index('/usr/libexec/noid-reboot-block-state --clear', summary)
assert publisher < reader
PY
kernel_baseline_line=$(grep -nF 'kernel_before=$(newest_installed_kernel_package)' \
    "$TMPDIR/noid-update-all.sh" | head -1 | cut -d: -f1 || true)
boot_guard_line_for_baseline=$(grep -nF \
    'sudo /usr/libexec/noid-boot-mutation-guard' \
    "$TMPDIR/noid-update-all.sh" | head -1 | cut -d: -f1 || true)
if [ -n "$kernel_baseline_line" ] && [ -n "$boot_guard_line_for_baseline" ] \
        && [ "$boot_guard_line_for_baseline" -lt "$kernel_baseline_line" ]; then
    _pass "kernel/boot-input baselines are captured only after the shared boot guard"
else
    _fail "kernel/boot-input baselines remain racy with the prior boot-lock owner"
fi

assert_grep_fixed 'dnf --cacheonly repo info --enabled --json' \
    "$TMPDIR/noid-update-all.sh" \
    "repository trust postflight reads DNF5 effective enabled-repository state"
assert_grep_fixed 'dnf -q --cacheonly repoquery --unneeded' \
    "$TMPDIR/noid-update-all.sh" \
    "optional orphan inventory reuses the refreshed root cache"
assert_not_grep 'grep -InE.*gpgcheck' "$TMPDIR/noid-update-all.sh" \
    "repository trust is not inferred from incomplete repo-file text matching"
assert_grep_fixed '✓ Checked update sources are current' \
    "$TMPDIR/noid-update-all.sh" \
    "green summary stays scoped to update sources actually checked"
assert_not_grep 'All systems up to date' "$TMPDIR/noid-update-all.sh" \
    "green summary does not imply unperformed system-wide integrity evidence"
assert_grep_fixed \
    'Listed metadata lacks DNF repository-metadata OpenPGP verification' \
    "$TMPDIR/noid-update-all.sh" \
    "metadata-signature exception names the remaining trust boundary"
awk '
    /^repo_security_inventory\(\)/ { copy=1 }
    copy { print }
    copy && /^}$/ { exit }
' "$TMPDIR/noid-update-all.sh" > "$TMPDIR/repo-security-inventory.function"
assert_cmd_success "effective signed-repository fixture is accepted" \
    bash -c '. "$1"; printf "%s\n" "$2" | repo_security_inventory' _ \
    "$TMPDIR/repo-security-inventory.function" \
    '[{"id":"signed","is_enabled":true,"pkg_gpgcheck":true,"repo_gpgcheck":true}]'
repo_relaxed_output=$(
    bash -c '. "$1"; printf "%s\n" "$2" | repo_security_inventory' _ \
        "$TMPDIR/repo-security-inventory.function" \
        '[{"id":"fedora","is_enabled":true,"pkg_gpgcheck":true,"repo_gpgcheck":false}]'
)
assert_eq $'METADATA\tfedora' "$repo_relaxed_output" \
    "effective metadata-only relaxation remains informational"
repo_unsigned_output=$(
    bash -c '. "$1"; printf "%s\n" "$2" | repo_security_inventory' _ \
        "$TMPDIR/repo-security-inventory.function" \
        '[{"id":"unsafe","is_enabled":true,"pkg_gpgcheck":false,"repo_gpgcheck":false}]'
)
assert_grep_fixed $'PACKAGE\tunsafe' <(printf '%s\n' "$repo_unsigned_output") \
    "effective disabled package verification is detected"
assert_cmd_failure "missing effective signature fields are rejected" \
    bash -c '. "$1"; printf "%s\n" "$2" | repo_security_inventory' _ \
    "$TMPDIR/repo-security-inventory.function" \
    '[{"id":"incomplete","is_enabled":true}]'

assert_grep_fixed 'sudo /usr/local/sbin/noid-codium-launcher-sync >/dev/null' \
    "$TMPDIR/noid-update-all.sh" \
    "supported updates re-prove VSCodium's native default-GPU overlays"
assert_grep_fixed \
    'VSCodium RPM payload pristine; native default-GPU launchers converged' \
    "$TMPDIR/noid-update-all.sh" \
    "successful VSCodium launcher convergence is reported precisely"
assert_grep_fixed 'VSCodium launcher convergence failed' \
    "$TMPDIR/noid-update-all.sh" \
    "VSCodium desktop-routing failure reaches the update error gate"
assert_grep_fixed 'ERRORS=$((ERRORS + 1))' "$TMPDIR/noid-update-all.sh"
dnf_complete_line=$(grep -nF 'OK${NC}: DNF transaction completed' \
    "$TMPDIR/noid-update-all.sh" | head -n 1 | cut -d: -f1 || true)
codium_converge_line=$(grep -nF \
    'VSCodium native default-GPU launcher convergence' \
    "$TMPDIR/noid-update-all.sh" | head -n 1 | cut -d: -f1 || true)
xdp_converge_line=$(grep -nF \
    'Physical-link XDP/TC post-update verification' \
    "$TMPDIR/noid-update-all.sh" | head -n 1 | cut -d: -f1 || true)
if [ -n "$dnf_complete_line" ] && [ -n "$codium_converge_line" ] \
        && [ -n "$xdp_converge_line" ] \
        && [ "$dnf_complete_line" -lt "$codium_converge_line" ] \
        && [ "$codium_converge_line" -lt "$xdp_converge_line" ]; then
    _pass "VSCodium overlays converge immediately after the DNF transaction"
else
    _fail "VSCodium overlay convergence ordering is incomplete"
fi

assert_grep_fixed 'sudo /usr/local/sbin/noid-lan-topology-refresh.sh' "$KS_FILE" \
    "DNF path reloads the physical-link boundary"
assert_grep_fixed 'sudo /usr/local/sbin/noid-lan-xdp status' "$KS_FILE" \
    "DNF path verifies exact live XDP/TC postconditions"
assert_grep_fixed '/usr/local/bin/noid-lan-xdp-notify --force' "$KS_FILE" \
    "failed post-update XDP/TC verification notifies the desktop user"
assert_not_grep 'systemctl stop NetworkManager.service' "$TMPDIR/noid-update-all.sh" \
    "XDP-only update incompatibility does not strand WAN repair access"
assert_grep_fixed 'case "$xdp_health" in' "$TMPDIR/noid-update-all.sh" \
    "XDP health is parsed as an explicit state machine"
assert_grep_fixed 'hardware/kernel lacks the qualified XDP path' "$TMPDIR/noid-update-all.sh" \
    "documented DEGRADED hardware is reported as a warning"
assert_grep_fixed 'WARNINGS=$((WARNINGS + 1))' "$TMPDIR/noid-update-all.sh"
assert_grep_fixed 'flatpak uninstall --system --unused' "$KS_FILE" \
    "system-scope unused Flatpaks are cleaned"
assert_grep_fixed 'flatpak --user uninstall --unused' "$KS_FILE" \
    "user-scope unused Flatpaks are cleaned"
assert_grep_fixed 'flatpak list --system --columns=ref' \
    "$TMPDIR/noid-update-all.sh" \
    "system Flatpak update is gated by the local installed-ref inventory"
assert_grep_fixed 'flatpak --user list --columns=ref' \
    "$TMPDIR/noid-update-all.sh" \
    "user Flatpak update is gated by the local installed-ref inventory"
assert_grep_fixed 'no installed Flatpak refs; catalog-only refresh not needed' \
    "$TMPDIR/noid-update-all.sh" \
    "empty installations do not download unrelated AppStream catalogs"
assert_grep_fixed 'Flatpak 1.18 can exit zero after an optional related-ref mutation failed' \
    "$KNOWN_FAILURES" \
    "known-failure guidance records Flatpak's exit-zero related-ref boundary"
assert_grep_fixed 'A real non-zero Flatpak process status remains a' \
    "$KNOWN_FAILURES" \
    "related-ref warning does not soften a real Flatpak process failure"
assert_grep_fixed 'reducing libostree from its default eight concurrent requests to' \
    "$KNOWN_FAILURES" \
    "known-failure guidance does not retain the disproven concurrency diagnosis"
assert_grep_fixed 'Do not persist an HTTP/1.1 downgrade' "$KNOWN_FAILURES" \
    "Flatpak recovery guidance preserves native transport negotiation"
sed -n '/^    flatpak_rc=0$/,/^    # Runtime sandbox-boundary postflight/p' \
    "$TMPDIR/noid-update-all.sh" | sed '$d' \
    > "$TMPDIR/flatpak-scope-update.block"
assert_cmd_success "Flatpak scope-update fixture extracts" \
    bash -n "$TMPDIR/flatpak-scope-update.block"

run_flatpak_scope_fixture() {
    local mode=$1 expected_warnings=$2 expected_errors=$3 output calls
    : > "$TMPDIR/flatpak-scope.calls"
    printf '0\n' > "$TMPDIR/flatpak-scope.count"
    output=$(env FP_MODE="$mode" FP_CALLS="$TMPDIR/flatpak-scope.calls" \
        FP_COUNT="$TMPDIR/flatpak-scope.count" XDG_RUNTIME_DIR="$TMPDIR" \
        FP_BLOCK="$TMPDIR/flatpak-scope-update.block" bash -c '
            flatpak() {
                printf "%s\n" "$*" >> "$FP_CALLS"
                case "$*" in
                    "list --system --columns=ref")
                        case "$FP_MODE" in
                            system|both|system-related-fail|system-related-recovers|system-related-hard-fail)
                                printf "%s\n" "org.example.System/x86_64/stable"
                                ;;
                            system-fail) printf "%s\n" "inventory failed"; return 42 ;;
                        esac
                        ;;
                    "--user list --columns=ref")
                        case "$FP_MODE" in
                            user|both) printf "%s\n" "org.example.User/x86_64/stable" ;;
                        esac
                        ;;
                    update\ --system*)
                        count=$(<"$FP_COUNT")
                        printf "%s\n" "$((count + 1))" > "$FP_COUNT"
                        if [[ "$FP_MODE" == system-related-fail \
                                || "$FP_MODE" == system-related-hard-fail \
                                || ( "$FP_MODE" == system-related-recovers && "$count" -eq 0 ) ]]; then
                            printf "%s\n" \
                                "Warning: Failed to install org.example.Driver: fixture transport"
                            if [[ "$FP_MODE" == system-related-hard-fail ]]; then
                                return 42
                            fi
                            return 0
                        else
                            printf "%s\n" "fixture transaction"
                        fi
                        ;;
                    --user\ update*|uninstall\ --system*|--user\ uninstall*)
                        printf "%s\n" "fixture transaction"
                        ;;
                    *) return 64 ;;
                esac
            }
            sudo() {
                if [ "${1:-}" = LC_ALL=C ]; then
                    shift
                fi
                "$@"
            }
            sleep() { :; }
            human_duration() { printf "%ss" "$1"; }
            RED= GREEN= YELLOW= NC=
            ERRORS=0
            WARNINGS=0
            NOID_SKIP_FLATPAK_CLEANUP=0
            . "$FP_BLOCK"
            printf "WARNINGS=%s ERRORS=%s FLATPAK_RC=%s SYSTEM=%s USER=%s\n" \
                "$WARNINGS" "$ERRORS" "$flatpak_rc" "$system_has_refs" "$user_has_refs"
        ')
    calls=$(<"$TMPDIR/flatpak-scope.calls")
    assert_grep_fixed "WARNINGS=$expected_warnings" <(printf '%s\n' "$output") \
        "Flatpak $mode fixture returns the expected warning count"
    assert_grep_fixed "ERRORS=$expected_errors" <(printf '%s\n' "$output") \
        "Flatpak $mode fixture returns the expected error count"
    case "$mode" in
        empty)
            assert_grep_fixed 'SYSTEM=0 USER=0' <(printf '%s\n' "$output") \
                "empty Flatpak fixture proves both scopes empty"
            assert_not_grep_extended '^[[:space:]]+SKIP:' \
                <(printf '%s\n' "$output") \
                "empty-scope Flatpak SKIP messages align with other statuses"
            assert_not_grep_extended '(^| )update( |$)|(^| )uninstall( |$)' \
                <(printf '%s\n' "$calls") \
                "empty Flatpak scopes perform no catalog-only update or cleanup"
            ;;
        system)
            assert_grep_fixed 'update --system --noninteractive -y' \
                <(printf '%s\n' "$calls") \
                "populated system scope still runs its real update"
            assert_grep_fixed 'uninstall --system --unused -y --noninteractive' \
                <(printf '%s\n' "$calls") \
                "populated system scope still runs unused-runtime cleanup"
            assert_not_grep_fixed '--user update' <(printf '%s\n' "$calls") \
                "empty user scope is not refreshed by a system-only update"
            ;;
        user)
            assert_grep_fixed '--user update --noninteractive -y' \
                <(printf '%s\n' "$calls") \
                "populated user scope still runs its real update"
            assert_grep_fixed '--user uninstall --unused -y --noninteractive' \
                <(printf '%s\n' "$calls") \
                "populated user scope still runs unused-runtime cleanup"
            assert_not_grep_fixed 'update --system' <(printf '%s\n' "$calls") \
                "empty system scope is not refreshed by a user-only update"
            ;;
        system-fail)
            assert_grep_fixed 'FLATPAK_RC=42' <(printf '%s\n' "$output") \
                "Flatpak inventory failure remains a hard update error"
            assert_not_grep_extended '(^| )update( |$)|(^| )uninstall( |$)' \
                <(printf '%s\n' "$calls") \
                "failed Flatpak inventory cannot authorize a transaction"
            ;;
        system-related-fail)
            assert_eq 3 "$(grep -c '^update --system' <<<"$calls")" \
                "exit-zero related-ref failure is retried only to the fixed bound"
            assert_grep_fixed 'FLATPAK_RC=0' <(printf '%s\n' "$output") \
                "persistent exit-zero related-ref failure remains non-blocking"
            ;;
        system-related-recovers)
            assert_eq 2 "$(grep -c '^update --system' <<<"$calls")" \
                "resumable related-ref retry stops immediately after recovery"
            assert_grep_fixed 'FLATPAK_RC=0' <(printf '%s\n' "$output") \
                "recovered related-ref transaction remains successful"
            ;;
        system-related-hard-fail)
            assert_eq 1 "$(grep -c '^update --system' <<<"$calls")" \
                "real Flatpak failure is not hidden behind related-ref retries"
            assert_grep_fixed 'FLATPAK_RC=42' <(printf '%s\n' "$output") \
                "non-zero Flatpak process status remains a hard error"
            ;;
    esac
}
run_flatpak_scope_fixture empty 0 0
run_flatpak_scope_fixture system 0 0
run_flatpak_scope_fixture user 0 0
run_flatpak_scope_fixture system-fail 0 1
run_flatpak_scope_fixture system-related-fail 1 0
run_flatpak_scope_fixture system-related-recovers 0 0
run_flatpak_scope_fixture system-related-hard-fail 0 1
assert_grep_fixed 'fp_min="1.18.1"' "$KS_FILE" \
    "update postflight requires the August 2026 Flatpak security release"
assert_grep_fixed 'portal_min="1.22.1"' "$KS_FILE" \
    "update postflight requires the June 2026 portal security fixes"
sed -n '/^    portal_ver=$/,/^    if \[\[ ! -x \/usr\/bin\/bwrap/p' \
    "$TMPDIR/noid-update-all.sh" | sed '$d' > "$TMPDIR/portal-postflight.sh"
assert_cmd_success "portal postflight fixture extracts" \
    bash -n "$TMPDIR/portal-postflight.sh"
run_portal_postflight_fixture() {
    local mode=$1 expected_errors=$2 output
    output=$(FAKE_PORTAL_MODE="$mode" PORTAL_BLOCK="$TMPDIR/portal-postflight.sh" \
        bash -c '
            sudo() {
                case "$FAKE_PORTAL_MODE" in
                    current) printf "%s\\n" 1.22.1; return 0 ;;
                    old) printf "%s\\n" 1.20.0; return 0 ;;
                    missing) printf "%s\\n" "package xdg-desktop-portal is not installed"; return 1 ;;
                    malformed) printf "%s\\n" "not-a-version"; return 0 ;;
                esac
            }
            RED= GREEN= NC=
            ERRORS=0
            source "$PORTAL_BLOCK"
            printf "ERRORS=%s\\n" "$ERRORS"
        ')
    assert_grep_fixed "ERRORS=$expected_errors" <(printf '%s\n' "$output") \
        "portal postflight ${mode} result"
    if [ "$mode" = missing ]; then
        assert_not_grep 'security baseline)' <(printf '%s\n' "$output") \
            "missing portal package cannot become a green version result"
    fi
}
run_portal_postflight_fixture current 0
run_portal_postflight_fixture old 1
run_portal_postflight_fixture missing 1
run_portal_postflight_fixture malformed 1
assert_grep_fixed 'bubblewrap uses the non-setuid user-namespace path' "$KS_FILE" \
    "update postflight rejects deprecated setuid bubblewrap"
assert_not_grep 'flatpak ${fp_ver} >= ${fp_min} (CVE baseline)' "$KS_FILE" \
    "stale Flatpak 1.16.4 CVE-baseline message cannot return"
assert_grep_fixed 'restorecon -F /usr/local/bin/noid-update-all.sh' "$KS_FILE" \
    "updater SELinux labeling remains an installation postcondition"
assert_not_grep 'restorecon -F /usr/local/bin/noid-update-all.sh 2>/dev/null || true' \
    "$KS_FILE" "updater SELinux labeling failures cannot be swallowed"
assert_grep_fixed 'LC_ALL=C fwupdmgr refresh --force 2>&1' \
    "$TMPDIR/noid-update-all.sh" \
    "network-facing fwupd refresh stays in the unprivileged client"
assert_not_grep 'sudo LC_ALL=C fwupdmgr refresh --force' \
    "$TMPDIR/noid-update-all.sh" \
    "fwupd network metadata is never parsed by a root client"
assert_grep_fixed 'LC_ALL=C fwupdmgr update --no-reboot-check 2>&1' \
    "$TMPDIR/noid-update-all.sh" \
    "firmware deployment uses PolicyKit and defers reboot control to the orchestrator"
assert_not_grep 'sudo fwupdmgr update' "$TMPDIR/noid-update-all.sh" \
    "fwupd update client is never run as root"
assert_grep_fixed 'LC_ALL=C fwupdmgr check-reboot-needed --json' \
    "$TMPDIR/noid-update-all.sh" \
    "firmware reboot state uses fwupd's dedicated noninteractive command"
assert_grep_fixed 'fw_refresh_rc=${PIPESTATUS[0]}' "$KS_FILE" \
    "fwupd refresh status is captured"
assert_grep_fixed 'fw_update_rc=${PIPESTATUS[0]}' "$KS_FILE" \
    "fwupd update status is captured"
assert_not_grep 'fwupdmgr update 2>&1 | sed.*|| true' "$KS_FILE" \
    "fwupd mutation failure is not swallowed"
assert_grep_fixed 'settle_fwupd_daemon()' "$TMPDIR/noid-update-all.sh" \
    "updater owns a bounded native fwupd lifecycle helper"
assert_grep_fixed 'sudo LC_ALL=C fwupdmgr quit' \
    "$TMPDIR/noid-update-all.sh" \
    "fwupd settlement uses its native update-aware API with normal sudo semantics"
assert_grep_fixed 'fw_quit_deadline=$((SECONDS + 30))' \
    "$TMPDIR/noid-update-all.sh" \
    "fwupd shutdown observation is bounded"
assert_grep_fixed 'settle_fwupd_daemon' "$TMPDIR/noid-update-all.sh" \
    "firmware step returns the daemon to on-demand dormancy"
assert_not_grep_extended '^[[:space:]]*(sudo[[:space:]]+)?(kill|pkill|killall).*fwupd' \
    "$TMPDIR/noid-update-all.sh" \
    "updater never signals the firmware daemon"
assert_not_grep 'systemctl stop fwupd.service' "$TMPDIR/noid-update-all.sh" \
    "updater never bypasses fwupd's in-progress update protection"

# Exercise dormant, successful and failed native-quit branches without a
# firmware daemon or privileged operation.
awk '
    /^settle_fwupd_daemon\(\) \{/ { capture=1 }
    capture { print }
    capture && /^}$/ { exit }
' "$TMPDIR/noid-update-all.sh" >"$TMPDIR/settle-fwupd.function"
assert_cmd_success "fwupd lifecycle helper extracts" \
    bash -n "$TMPDIR/settle-fwupd.function"
mkdir -p "$TMPDIR/fwupd-fake-bin"
cat >"$TMPDIR/fwupd-fake-bin/systemctl" <<'FAKE_FWUPD_SYSTEMCTL_EOF'
#!/bin/bash
if [[ $* == "--quiet is-active fwupd.service" ]]; then
    [[ $(<"$FWUPD_STATE") == active ]]
    exit
fi
exit 97
FAKE_FWUPD_SYSTEMCTL_EOF
cat >"$TMPDIR/fwupd-fake-bin/sudo" <<'FAKE_FWUPD_SUDO_EOF'
#!/bin/bash
printf '%s\n' "$*" >>"$FWUPD_SUDO_LOG"
if [[ ${FWUPD_SUDO_RC:-0} -ne 0 ]]; then
    exit "$FWUPD_SUDO_RC"
fi
printf '%s\n' inactive >"$FWUPD_STATE"
printf '%s\n' 'Idle…'
FAKE_FWUPD_SUDO_EOF
chmod 0755 "$TMPDIR/fwupd-fake-bin/"*
printf '%s\n' inactive >"$TMPDIR/fwupd.state"
: >"$TMPDIR/fwupd-sudo.log"
assert_cmd_success "dormant fwupd path is a no-op" \
    env PATH="$TMPDIR/fwupd-fake-bin:/usr/bin" \
        FWUPD_STATE="$TMPDIR/fwupd.state" \
        FWUPD_SUDO_LOG="$TMPDIR/fwupd-sudo.log" \
        bash -c '. "$1"; RED= GREEN= NC=; ERRORS=0; settle_fwupd_daemon; [[ $ERRORS -eq 0 && ! -s "$2" ]]' \
        _ "$TMPDIR/settle-fwupd.function" "$TMPDIR/fwupd-sudo.log"
printf '%s\n' active >"$TMPDIR/fwupd.state"
: >"$TMPDIR/fwupd-sudo.log"
assert_cmd_success "active fwupd uses native quit and becomes dormant" \
    env PATH="$TMPDIR/fwupd-fake-bin:/usr/bin" \
        FWUPD_STATE="$TMPDIR/fwupd.state" \
        FWUPD_SUDO_LOG="$TMPDIR/fwupd-sudo.log" \
        bash -c '. "$1"; RED= GREEN= NC=; ERRORS=0; settle_fwupd_daemon; [[ $ERRORS -eq 0 && $(<"$2") == inactive ]]' \
        _ "$TMPDIR/settle-fwupd.function" "$TMPDIR/fwupd.state"
assert_eq 'LC_ALL=C fwupdmgr quit' \
    "$(<"$TMPDIR/fwupd-sudo.log")" \
    "fwupd lifecycle helper invokes only the reviewed native quit command"
printf '%s\n' active >"$TMPDIR/fwupd.state"
: >"$TMPDIR/fwupd-sudo.log"
assert_cmd_success "failed fwupd quit becomes a completeness error" \
    env PATH="$TMPDIR/fwupd-fake-bin:/usr/bin" \
        FWUPD_STATE="$TMPDIR/fwupd.state" \
        FWUPD_SUDO_LOG="$TMPDIR/fwupd-sudo.log" FWUPD_SUDO_RC=7 \
        bash -c '. "$1"; RED= GREEN= NC=; ERRORS=0; settle_fwupd_daemon; rc=$?; [[ $rc -eq 1 && $ERRORS -eq 1 && $(<"$2") == active ]]' \
        _ "$TMPDIR/settle-fwupd.function" "$TMPDIR/fwupd.state"
assert_grep_fixed 'fedora-cisco-openh264 metalink reachable (HTTP 200)' \
    "$TMPDIR/noid-update-all.sh" \
    "repository probe reports the endpoint it actually contacted"
sed -n '/^probe_openh264_http()/,/^}$/p' "$TMPDIR/noid-update-all.sh" \
    > "$TMPDIR/probe-openh264-http.function"
assert_cmd_success "OpenH264 HTTP probe function parses" \
    bash -n "$TMPDIR/probe-openh264-http.function"
run_openh264_http_fixture() {
    local curl_value=$1 curl_rc=$2 expected=$3 actual
    actual=$(FAKE_CURL_VALUE="$curl_value" FAKE_CURL_RC="$curl_rc" \
        PROBE_FN="$TMPDIR/probe-openh264-http.function" bash -c '
            source "$PROBE_FN"
            curl() {
                printf "%s" "$FAKE_CURL_VALUE"
                return "$FAKE_CURL_RC"
            }
            probe_openh264_http https://example.invalid/metalink
        ')
    assert_eq "$expected" "$actual" \
        "OpenH264 HTTP probe maps curl ${curl_value}/${curl_rc}"
}
run_openh264_http_fixture 200 0 200
run_openh264_http_fixture 403 0 403
run_openh264_http_fixture 000 7 000
assert_not_grep '|| echo "000"' "$TMPDIR/noid-update-all.sh" \
    "OpenH264 probe never concatenates curl output and fallback status"
assert_grep_fixed "curl --proto '=https' --tlsv1.2 --max-time 10" \
    "$TMPDIR/noid-update-all.sh" \
    "repository probe has an explicit HTTPS/TLS floor"
assert_grep_fixed 'checks only Fedora'\''s public metalink' \
    "$TMPDIR/noid-update-all.sh" \
    "repository probe does not claim package-host reachability"
assert_not_grep 'Cisco-CDN' "$TMPDIR/noid-update-all.sh" \
    "repository probe does not collapse OpenH264 provenance into a CDN label"
assert_grep_fixed "openh264_release=\$(/usr/bin/rpm -E '%fedora'" \
    "$TMPDIR/noid-update-all.sh" \
    "OpenH264 probe derives the running Fedora release"
assert_grep_fixed "openh264_arch=\$(/usr/bin/rpm -E '%_arch'" \
    "$TMPDIR/noid-update-all.sh" \
    "OpenH264 probe derives the running RPM architecture"
assert_not_grep 'fedora-cisco-openh264-44&arch=x86_64' \
    "$TMPDIR/noid-update-all.sh" \
    "OpenH264 probe has no stale release/architecture literal"

# The managed Just-Perfection identity stays mandatory; its failures and any
# non-RPM EGO/VSCodium update failures participate in the ERRORS gate.
assert_grep_fixed 'metadata UUID/path identity invalid; update state is unprovable' "$KS_FILE" \
    "every non-RPM GNOME extension identity mismatch is a completeness error"
assert_grep_fixed 'ERRORS=$((ERRORS + 1))' "$TMPDIR/nonrpm-block.sh" \
    "non-RPM identity failure reaches the final error gate"

# Firefox langpack staleness recovery after a browser major upgrade
assert_grep_fixed 'reset_stale_langpack' "$KS_FILE"
assert_grep_fixed "ffver=\$(sudo rpm -q --qf '%{VERSION}\\n' firefox 2>/dev/null) || return 1" \
    "$TMPDIR/noid-update-all.sh" \
    "Firefox langpack reset requires a successful privileged RPM query"
assert_grep_fixed '[[ "$ffmaj" =~ ^[0-9]+$ ]] || return 1' \
    "$TMPDIR/noid-update-all.sh" \
    "Firefox langpack reset accepts only a numeric RPM major version"

# rpm reports a missing package on stdout while returning rc=1. Exercise that
# real shape so the diagnostic can never be mistaken for a Firefox version.
awk '
    /^reset_stale_langpack\(\)/ { copy=1 }
    copy { print }
    copy && /^}$/ { exit }
' "$TMPDIR/noid-update-all.sh" > "$TMPDIR/reset-stale-langpack.function"
RPM_QUERY_PROFILE="$TMPDIR/rpm-query-profile"
mkdir -p "$RPM_QUERY_PROFILE/extensions"
printf '%s\n' '{"addons":[{"type":"locale","version":"999.0"}]}' \
    > "$RPM_QUERY_PROFILE/extensions.json"
printf '%s\n' 'langpack sentinel' \
    > "$RPM_QUERY_PROFILE/extensions/langpack-fixture.xpi"
if bash -c \
    'sudo() { printf "%s\n" "package firefox is not installed"; return 1; }; . "$1"; reset_stale_langpack "$2"' \
    _ "$TMPDIR/reset-stale-langpack.function" "$RPM_QUERY_PROFILE"; then
    _fail "failed Firefox RPM query is rejected before langpack mutation"
else
    _pass "failed Firefox RPM query is rejected before langpack mutation"
fi
assert_file_exists "$RPM_QUERY_PROFILE/extensions.json" \
    "failed Firefox RPM query preserves extensions.json"
assert_file_exists "$RPM_QUERY_PROFILE/extensions/langpack-fixture.xpi" \
    "failed Firefox RPM query preserves installed langpack bytes"

MALFORMED_LANGPACK_PROFILE="$TMPDIR/malformed-langpack-profile"
mkdir -p "$MALFORMED_LANGPACK_PROFILE/extensions"
printf '%s\n' '{"addons":[' > "$MALFORMED_LANGPACK_PROFILE/extensions.json"
printf '%s\n' startup > "$MALFORMED_LANGPACK_PROFILE/addonStartup.json.lz4"
printf '%s\n' sentinel > "$MALFORMED_LANGPACK_PROFILE/extensions/0.xpi"
printf '%s\n' \
    'user_pref("extensions.installedDistroAddon.langpack-de", true);' \
    > "$MALFORMED_LANGPACK_PROFILE/prefs.js"
assert_cmd_failure "malformed Firefox extension metadata fails closed" \
    bash -c '
        sudo() { printf "%s\n" 153.0; }
        . "$1"
        reset_stale_langpack "$2"
    ' _ "$TMPDIR/reset-stale-langpack.function" "$MALFORMED_LANGPACK_PROFILE"
assert_file_exists "$MALFORMED_LANGPACK_PROFILE/extensions.json" \
    "malformed Firefox metadata is preserved for diagnosis"
assert_file_exists "$MALFORMED_LANGPACK_PROFILE/addonStartup.json.lz4" \
    "malformed Firefox metadata cannot clear startup state"
assert_file_exists "$MALFORMED_LANGPACK_PROFILE/extensions/0.xpi" \
    "malformed Firefox metadata cannot synthesize an extension identity"
assert_grep_fixed 'extensions.installedDistroAddon.langpack-de' \
    "$MALFORMED_LANGPACK_PROFILE/prefs.js" \
    "malformed Firefox metadata cannot edit profile preferences"

LANGPACK_PROFILE="$TMPDIR/langpack-profile"
mkdir -p "$LANGPACK_PROFILE/extensions"
printf '%s\n' '{"addons":[' \
    '{"type":"locale","id":"langpack-de@firefox.mozilla.org","version":"152.0"},' \
    '{"type":"locale","id":"langpack-fr@firefox.mozilla.org","version":"153.0"}' \
    ']}' > "$LANGPACK_PROFILE/extensions.json"
printf '%s\n' stale > \
    "$LANGPACK_PROFILE/extensions/langpack-de@firefox.mozilla.org.xpi"
printf '%s\n' current > \
    "$LANGPACK_PROFILE/extensions/langpack-fr@firefox.mozilla.org.xpi"
printf '%s\n' startup > "$LANGPACK_PROFILE/addonStartup.json.lz4"
printf '%s\n' \
    'user_pref("extensions.installedDistroAddon.langpack-de", true);' \
    'user_pref("browser.startup.homepage", "about:blank");' \
    > "$LANGPACK_PROFILE/prefs.js"
assert_cmd_success "stale Firefox langpack state is reset" \
    bash -c '
        sudo() { printf "%s\n" 153.0; }
        . "$1"
        reset_stale_langpack "$2"
    ' _ "$TMPDIR/reset-stale-langpack.function" "$LANGPACK_PROFILE"
assert_cmd_failure "only the proven-stale profile langpack is removed" \
    test -e "$LANGPACK_PROFILE/extensions/langpack-de@firefox.mozilla.org.xpi"
assert_file_exists \
    "$LANGPACK_PROFILE/extensions/langpack-fr@firefox.mozilla.org.xpi" \
    "a current additional profile langpack is preserved"
assert_cmd_failure "generated Firefox extension registration is rebuilt" \
    test -e "$LANGPACK_PROFILE/extensions.json"
assert_cmd_failure "generated Firefox startup cache is rebuilt" \
    test -e "$LANGPACK_PROFILE/addonStartup.json.lz4"
assert_not_grep 'extensions.installedDistroAddon.langpack-' \
    "$LANGPACK_PROFILE/prefs.js" \
    "stale distro-langpack installation preferences are cleared"
assert_grep_fixed 'browser.startup.homepage' "$LANGPACK_PROFILE/prefs.js" \
    "unrelated Firefox preferences survive langpack repair"
assert_cmd_success "Firefox extension inventory precedes destructive langpack reset" \
    python3 - "$TMPDIR/noid-update-all.sh" <<'PY'
import sys

text = open(sys.argv[1], encoding="utf-8").read()
marketplace = text.index('update_marketplace_extensions firefox amo')
reset = text.index('if reset_stale_langpack "$profile_path"; then', marketplace)
assert marketplace < reset
PY
assert_grep_fixed 'after extension reconciliation' \
    "$TMPDIR/noid-update-all.sh" \
    "langpack success text names the safe same-run ordering"

AIDE_STEP_BLOCK="$TMPDIR/aide-step.block"
sed -n '/^step "8" "AIDE Integrity Evidence"$/,/^step "9" /p' \
    "$TMPDIR/noid-update-all.sh" > "$AIDE_STEP_BLOCK"
assert_grep_fixed 'WARNINGS=$((WARNINGS + 1))' \
    "$AIDE_STEP_BLOCK" \
    "reviewable AIDE differences participate in the warning summary"

# Update-time AIDE is check-only; baseline review belongs to M13.
assert_grep_fixed 'AIDE Integrity Evidence' "$KS_FILE"
assert_not_grep 'mv -f /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz' "$KS_FILE"
sed -n '/^read_aide_database_state()/,/^}$/p' \
    "$TMPDIR/noid-update-all.sh" > "$TMPDIR/read-aide-state.function"
assert_cmd_success "fixed AIDE state consumer parses" \
    bash -n "$TMPDIR/read-aide-state.function"
assert_grep_fixed 'sudo -n /usr/libexec/noid-aide-status' \
    "$TMPDIR/read-aide-state.function" \
    "updater reads AIDE state across the existing fixed root boundary"
assert_not_grep '\[ ! -s /var/lib/aide/aide.db.gz \]' \
    "$TMPDIR/noid-update-all.sh" \
    "updater never mistakes the root-only AIDE directory for an absent baseline"
run_aide_state_fixture() {
    local fixture_output=$1 fixture_rc=$2 expected=$3
    local actual
    actual=$(FAKE_AIDE_OUTPUT="$fixture_output" FAKE_AIDE_RC="$fixture_rc" \
        bash -c '
            sudo() {
                printf "%s\n" "$FAKE_AIDE_OUTPUT"
                return "$FAKE_AIDE_RC"
            }
            . "$1"
            read_aide_database_state
        ' _ "$TMPDIR/read-aide-state.function")
    assert_eq "$expected" "$actual" \
        "AIDE fixed-schema state maps to ${expected}"
}
run_aide_state_fixture $'NOID_AIDE_STATE_V1\nSTATE=active' 0 active
run_aide_state_fixture $'NOID_AIDE_STATE_V1\nSTATE=absent' 0 absent
run_aide_state_fixture $'NOID_AIDE_STATE_V1\nSTATE=unsafe' 0 unsafe
run_aide_state_fixture $'NOID_AIDE_STATE_V1\nSTATE=active\nEXTRA=forbidden' 0 unavailable
run_aide_state_fixture '' 1 unavailable

# Native M10 permission reconciliation after package-owned modes may change.
assert_grep_fixed 'systemd-tmpfiles --create' "$KS_FILE" \
    "update workflow uses the native permission owner"
assert_grep_fixed '/etc/tmpfiles.d/90-noid-permission-policy.conf' "$KS_FILE"
assert_not_grep 'noid-suid-harden' "$KS_FILE" \
    "update workflow contains no obsolete chmod helper"

# NVIDIA update path delegates to M19's single exact verifier and durable queue.
# This covers both maintained branches, fresh module identity, enrolled exact
# MOK, atomic initramfs evidence and a reboot inhibitor on failure.
assert_grep_fixed 'akmod-nvidia-580xx' "$TMPDIR/noid-update-all.sh" \
    "update workflow detects the maintained 580xx branch"

# Extract the one-shot inventory trigger and prove that rpmdb failure is
# distinct from a successful empty inventory, while both akmod and CUDA EVRs
# participate in the branch identity.
awk '
    /^nvidia_branch_evr\(\)/ { copy=1 }
    copy { print }
    copy && /^}$/ { exit }
' "$TMPDIR/noid-update-all.sh" > "$TMPDIR/nvidia-branch-evr.function"
assert_cmd_failure "failed NVIDIA rpmdb inventory fails closed" bash -c '
    sudo() { return 1; }
    . "$1"
    nvidia_branch_evr
' _ "$TMPDIR/nvidia-branch-evr.function"
missing_nvidia=$(bash -c '
    sudo() { return 0; }
    . "$1"
    nvidia_branch_evr
' _ "$TMPDIR/nvidia-branch-evr.function")
assert_eq "none" "$missing_nvidia" \
    "successful empty inventory is an exact unmanaged state"
main_nvidia=$(bash -c '
    sudo() {
        printf "akmod-nvidia\t3:610.1-1.fc44.x86_64\n"
        printf "xorg-x11-drv-nvidia-cuda\t3:610.1-1.fc44.x86_64\n"
    }
    . "$1"
    nvidia_branch_evr
' _ "$TMPDIR/nvidia-branch-evr.function")
assert_eq "main:akmod=3:610.1-1.fc44.x86_64:cuda=3:610.1-1.fc44.x86_64" \
    "$main_nvidia" \
    "successful main-branch inventory binds both exact package EVRs"
main_cuda_changed=$(bash -c '
    sudo() {
        printf "akmod-nvidia\t3:610.1-1.fc44.x86_64\n"
        printf "xorg-x11-drv-nvidia-cuda\t3:610.2-1.fc44.x86_64\n"
    }
    . "$1"
    nvidia_branch_evr
' _ "$TMPDIR/nvidia-branch-evr.function")
[ "$main_cuda_changed" != "$main_nvidia" ] \
    && _pass "CUDA-only EVR movement changes the NVIDIA trigger identity" \
    || _fail "CUDA-only EVR movement changes the NVIDIA trigger identity"
main_missing_cuda=$(bash -c '
    sudo() {
        printf "akmod-nvidia\t3:610.1-1.fc44.x86_64\n"
    }
    . "$1"
    nvidia_branch_evr
' _ "$TMPDIR/nvidia-branch-evr.function")
assert_grep_fixed 'partial:main-akmod=3:610.1-1.fc44.x86_64:main-cuda=missing' \
    <(printf '%s\n' "$main_missing_cuda") \
    "an akmod without its CUDA half is an explicit partial branch"
cuda_without_akmod=$(bash -c '
    sudo() {
        printf "xorg-x11-drv-nvidia-cuda\t3:610.1-1.fc44.x86_64\n"
    }
    . "$1"
    nvidia_branch_evr
' _ "$TMPDIR/nvidia-branch-evr.function")
assert_grep_fixed 'partial:main-akmod=missing:main-cuda=3:610.1-1.fc44.x86_64' \
    <(printf '%s\n' "$cuda_without_akmod") \
    "CUDA-only NVIDIA residue cannot be mistaken for an unmanaged host"
cross_branch_cuda=$(bash -c '
    sudo() {
        printf "akmod-nvidia\t3:610.1-1.fc44.x86_64\n"
        printf "xorg-x11-drv-nvidia-cuda\t3:610.1-1.fc44.x86_64\n"
        printf "xorg-x11-drv-nvidia-580xx-cuda\t3:580.2-1.fc44.x86_64\n"
    }
    . "$1"
    nvidia_branch_evr
' _ "$TMPDIR/nvidia-branch-evr.function")
assert_grep_fixed 'partial:main-akmod=3:610.1-1.fc44.x86_64' \
    <(printf '%s\n' "$cross_branch_cuda") \
    "cross-branch CUDA residue invalidates an otherwise complete branch"
assert_grep_fixed 'mixed:*|partial:*)' "$TMPDIR/noid-update-all.sh" \
    "post-DNF partial or mixed NVIDIA topology is rejected explicitly"
assert_grep_fixed 'register_reboot_blocker nvidia || true' \
    "$TMPDIR/noid-update-all.sh" \
    "invalid NVIDIA topology persists a closed reboot blocker"
assert_not_grep 'rpm -q akmod-nvidia 2>/dev/null || true' \
    "$TMPDIR/noid-update-all.sh" \
    "NVIDIA detection never preserves a failed rpm diagnostic"
assert_grep_fixed '/usr/libexec/noid-nvidia-initramfs-queue' "$TMPDIR/noid-update-all.sh"
assert_grep_fixed '"$new_kver" --require-enrolled' "$TMPDIR/noid-update-all.sh" \
    "update verification requires the exact enrolled MOK"
assert_grep_fixed '/var/lib/noid-nvidia-integrity/${new_kver}.ready' \
    "$TMPDIR/noid-update-all.sh" "update requires the worker ready artifact"
assert_grep_fixed 'actual_initramfs_hash' "$TMPDIR/noid-update-all.sh"
assert_grep_fixed '"$actual_initramfs_hash" == "$expected_initramfs_hash"' \
    "$TMPDIR/noid-update-all.sh" "ready evidence is bound to the published initramfs"
assert_grep_fixed '${queued_marker%.pending}.failed' "$TMPDIR/noid-update-all.sh" \
    "worker failure is observed without waiting for timeout"
assert_grep_fixed 'NVIDIA integrity verification FAILED' "$TMPDIR/noid-update-all.sh" \
    "critical notification title (noid-update-all.sh)"
assert_grep_fixed 'noid-nvidia-initramfs-queue --resume' "$TMPDIR/noid-update-all.sh" \
    "failed update points to durable recovery"
assert_grep_fixed 'noid-nvidia-install.sh --rollback' "$TMPDIR/noid-update-all.sh" \
    "failed update points to full NVIDIA rollback"
assert_not_grep 'sudo akmods --force' "$TMPDIR/noid-update-all.sh" \
    "updater does not duplicate the canonical M19 builder"
assert_not_grep 'sudo dracut -f' "$TMPDIR/noid-update-all.sh" \
    "updater contains no independent direct Dracut writer"
assert_grep_fixed 'exec 7>"$BOOT_MUTATION_LOCK"' \
    "$TMPDIR/noid-update-all.sh" "interactive updater owns the standardized lock descriptor"
assert_grep_fixed 'sudo -C 8 /usr/libexec/noid-dracut-regenerate-all' \
    "$TMPDIR/noid-update-all.sh" "boot-input changes enter the canonical atomic validator"
assert_grep_fixed '--lock-held=7' \
    "$TMPDIR/noid-update-all.sh" "canonical updater rebuild inherits its shared lease"
assert_grep_fixed '--kernel="$target_kernel"' \
    "$TMPDIR/noid-update-all.sh" \
    "a new non-NVIDIA kernel rebuild is scoped to that exact image"
assert_grep_fixed 'no boot-image input changed; native package hooks retained the existing images' \
    "$TMPDIR/noid-update-all.sh" \
    "an empty DNF transaction cannot trigger an all-kernel rebuild"
assert_grep_fixed 'is owned by the exact NVIDIA module/initramfs worker below' \
    "$TMPDIR/noid-update-all.sh" \
    "managed NVIDIA targets never receive a duplicate generic rebuild"
assert_grep_fixed 'BOOT_IMAGE_GLOBAL_REBUILD=1' \
    "$TMPDIR/noid-update-all.sh" \
    "post-trigger global boot-input changes retain all-kernel convergence"
assert_grep_fixed 'reconcile_branding_after_dnf()' \
    "$TMPDIR/noid-update-all.sh" \
    "orchestrated updates invoke one canonical branding convergence path"
assert_grep_fixed 'sudo "$BRANDING_RESTORE_HELPER"' \
    "$TMPDIR/noid-update-all.sh" \
    "M25 delegates branding policy to M32's helper"
assert_grep_fixed 'plymouth_before_sha' \
    "$TMPDIR/noid-update-all.sh" \
    "Plymouth rebuild decision records the pre-transaction source bytes"
assert_grep_fixed 'plymouth_after_sha' \
    "$TMPDIR/noid-update-all.sh" \
    "Plymouth rebuild decision records the converged source bytes"
assert_not_grep 'WatermarkVerticalAlignment=\.96' \
    "$TMPDIR/noid-update-all.sh" \
    "M25 has no drift-prone Fedora default-value matcher"
assert_not_grep 'UseFirmwareBackground=true' \
    "$TMPDIR/noid-update-all.sh" \
    "M25 does not duplicate M32's Plymouth layout policy"

awk '
    /^reconcile_branding_after_dnf\(\)/ { copy=1 }
    copy { print }
    copy && /^}$/ { exit }
' "$TMPDIR/noid-update-all.sh" > "$TMPDIR/branding-reconcile.function"
run_branding_fixture() {
    local before_content=$1 after_content=$2 dnf_ok=${3:-1}
    local root="$TMPDIR/branding-fixture"
    rm -rf "$root"
    mkdir -p "$root"
    printf '%s\n' "$before_content" > "$root/bgrt.plymouth"
    cat > "$root/restore" <<FIXTURE_EOF
#!/bin/bash
printf '%s\n' '$after_content' > '$root/bgrt.plymouth'
FIXTURE_EOF
    chmod 0755 "$root/restore"
    BRAND_ROOT="$root" BRAND_DNF_OK="$dnf_ok" bash -c '
        sudo() { "$@"; }
        RED= GREEN= YELLOW= NC=
        DNF_SUCCEEDED=$BRAND_DNF_OK
        ERRORS=0
        BOOT_IMAGE_GLOBAL_REBUILD=0
        BOOT_IMAGE_REBUILD_REASON=
        BRANDING_RESTORE_HELPER="$BRAND_ROOT/restore"
        BGRT_PLY_UPGRADE="$BRAND_ROOT/bgrt.plymouth"
        plymouth_before_sha=$(sha256sum "$BGRT_PLY_UPGRADE" | awk "{print \$1}")
        . "$1"
        reconcile_branding_after_dnf
        printf "GLOBAL=%s\nERRORS=%s\n" "$BOOT_IMAGE_GLOBAL_REBUILD" "$ERRORS"
    ' _ "$TMPDIR/branding-reconcile.function"
}
branding_unchanged=$(run_branding_fixture canonical canonical)
assert_grep_fixed 'GLOBAL=0' <(printf '%s\n' "$branding_unchanged") \
    "canonical post-transaction Plymouth bytes do not rebuild all kernels"
branding_changed=$(run_branding_fixture drifted canonical)
assert_grep_fixed 'GLOBAL=1' <(printf '%s\n' "$branding_changed") \
    "a real managed Plymouth byte change rebuilds all kernels"
branding_failed_dnf=$(run_branding_fixture drifted canonical 0)
assert_grep_fixed 'GLOBAL=1' <(printf '%s\n' "$branding_failed_dnf") \
    "a managed Plymouth byte change converges even when DNF exited nonzero"

awk '
    /^regenerate_changed_boot_images\(\)/ { copy=1 }
    copy { print }
    copy && /^}$/ { exit }
' "$TMPDIR/noid-update-all.sh" > "$TMPDIR/boot-image-decision.function"
run_boot_image_fixture() {
    local dnf_ok=$1 global=$2 target=$3 nvidia_target=$4
    DNF_OK="$dnf_ok" GLOBAL="$global" TARGET="$target" \
        NVIDIA_TARGET="$nvidia_target" bash -c '
            sudo() { printf "SUDO %s\n" "$*"; }
            RED= GREEN= YELLOW= NC=
            DNF_SUCCEEDED=$DNF_OK
            BOOT_IMAGE_GLOBAL_REBUILD=$GLOBAL
            BOOT_IMAGE_REBUILD_REASON=fixture
            ERRORS=0
            . "$1"
            regenerate_changed_boot_images "$TARGET" "$NVIDIA_TARGET" || true
            printf "ERRORS=%s\n" "$ERRORS"
        ' _ "$TMPDIR/boot-image-decision.function"
}
no_change_output=$(run_boot_image_fixture 1 0 '' '')
assert_not_grep '^SUDO ' <(printf '%s\n' "$no_change_output") \
    "successful no-op DNF does not invoke Dracut"
target_output=$(run_boot_image_fixture 1 0 7.2.0-fixture.x86_64 '')
assert_grep_fixed '--kernel=7.2.0-fixture.x86_64' \
    <(printf '%s\n' "$target_output") \
    "new non-NVIDIA kernel invokes one exact target rebuild"
nvidia_output=$(run_boot_image_fixture 1 0 '' 7.2.0-nvidia.x86_64)
assert_not_grep '^SUDO ' <(printf '%s\n' "$nvidia_output") \
    "managed NVIDIA target defers without a duplicate generic rebuild"
global_output=$(run_boot_image_fixture 1 1 '' '')
assert_grep_fixed 'SUDO -C 8 /usr/libexec/noid-dracut-regenerate-all --lock-held=7' \
    <(printf '%s\n' "$global_output") \
    "global NoID Privacy boot-input drift still rebuilds every installed image"
assert_not_grep '--kernel=' <(printf '%s\n' "$global_output") \
    "global convergence is not narrowed to one kernel"
failed_dnf_global=$(run_boot_image_fixture 0 1 '' '')
assert_grep_fixed 'SUDO -C 8 /usr/libexec/noid-dracut-regenerate-all --lock-held=7' \
    <(printf '%s\n' "$failed_dnf_global") \
    "queued global boot-input drift is rebuilt even when DNF exited nonzero"
failed_dnf_noop=$(run_boot_image_fixture 0 0 '' '')
assert_not_grep '^SUDO ' <(printf '%s\n' "$failed_dnf_noop") \
    "a DNF failure with no boot-input change invokes no Dracut"
assert_not_grep_extended 'BOOT_MUTATION_OWNER|BOOT_MUTATION_CLAIM|--lock-owner' \
    "$TMPDIR/noid-update-all.sh" "updater has no racy process-claim authority"

# reboot detection via direct kernel-version compare.
# Regression guards target RUNTIME-CODE patterns only (the design must
# not regress to a state-persisting design).
if grep -nF 'sudo tee /var/lib/noid-privacy/pending-reboot.txt' "$KS_FILE" >/dev/null 2>&1; then
    _fail "pending-reboot.txt state-write code reappeared (design: kernel-diff direct)"
else
    _pass "no pending-reboot.txt state-write (direct-compare reboot detection)"
fi
if grep -nF 'cat > /etc/sudoers.d/noid-pending-reboot' "$KS_FILE" >/dev/null 2>&1; then
    _fail "noid-pending-reboot sudoers heredoc reappeared (design: no privileged file ops)"
else
    _pass "no noid-pending-reboot sudoers heredoc (no-privileged-cleanup)"
fi
# Reboot-needed detection MUST be kernel-version-diff (uname -r vs /lib/modules)
assert_grep_fixed 'find /lib/modules -mindepth 1 -maxdepth 1 -type d' "$KS_FILE" \
    "kernel-version-diff via /lib/modules"
assert_grep_fixed '[ -e /run/noid-privacy/audit-storage-degraded ]' \
    "$KS_FILE" "reboot helper reads the runtime audit-storage marker"
assert_grep_fixed \
    'if [ "$MODE" = notify ] && [ "$audit_storage_degraded" -eq 1 ]; then' \
    "$KS_FILE" "login notifier re-nags while the audit-storage marker persists"
assert_grep_fixed "stat -Lc '%u:%g:%a:%h'" "$KS_FILE" \
    "pending-reboot artifacts require exact owner, mode and link count"
assert_grep_fixed 'bash -n /usr/local/bin/noid-pending-reboot-check.sh' "$KS_FILE" \
    "module verification rejects a malformed pending-reboot notifier"
assert_grep_fixed "grep -qFx 'Exec=/usr/local/bin/noid-pending-reboot-check.sh'" \
    "$KS_FILE" "module verification binds the autostart to the notifier"
assert_grep_fixed 'pending_reboot_desktop_valid=0' "$KS_FILE" \
    "module verification rejects an invalid pending-reboot desktop entry"

# Update reminder user timer (notifies user after update complete)
assert_grep_extended 'noid-update-reminder\.timer' "$KS_FILE"
assert_grep_fixed 'noid-user-firstrun applies preset' "$KS_FILE" \
    "timer enablement names M17's explicit preset application"
assert_grep_fixed "oncalendar_value=\$(sed -n 's/^OnCalendar=//p'" "$KS_FILE" \
    "semantic timer verification reads the shipped artifact"
assert_grep_fixed '"$oncalendar_value" >/dev/null 2>&1' "$KS_FILE" \
    "systemd-analyze parses the extracted timer expression"
assert_not_grep 'systemd-analyze calendar --iterations=5 "Mon *-*-* 10:00:00"' \
    "$KS_FILE" "timer semantic verification has no tautological literal copy"

# X-GNOME-Autostart-Phase MUST NOT be present as an active .desktop
# entry line (GNOME 49+ bug). Comments about removal are allowed.
if grep -Pn '^\s*X-GNOME-Autostart-Phase\s*=' "$KS_FILE" >/dev/null 2>&1; then
    _fail "X-GNOME-Autostart-Phase= line present (regression)"
else
    _pass "no active X-GNOME-Autostart-Phase= line (hold)"
fi

# Root-guard: script must refuse to be run as root (must be invoked as
# normal user; sudo is called internally where needed).
assert_grep_extended '"\$\(id -u\)"|\[ "\$\(id -u\)" -eq 0 \]' "$KS_FILE"
assert_grep_fixed 'do not run this script as root' "$KS_FILE"
assert_grep_fixed 'UPDATE_LOCK=/run/lock/noid-update-all.lock' "$TMPDIR/noid-update-all.sh" \
    "whole update workflow uses one cross-session lock"
assert_grep_fixed 'prime_sudo_credential()' "$TMPDIR/noid-update-all.sh" \
    "update has one explicit pre-mutation authentication boundary"
assert_grep_fixed '_emit_marker "CANCELLED authentication"' \
    "$TMPDIR/noid-update-all.sh" \
    "declined authentication has a machine-readable GUI result"
assert_grep_fixed 'exit 125' "$TMPDIR/noid-update-all.sh" \
    "declined authentication exits before update work"
assert_not_grep \
    'sudo -A -v 2>/dev/null; } || sudo -v' "$TMPDIR/noid-update-all.sh" \
    "cancelled graphical askpass cannot fall through to terminal sudo"
awk '
    /^prime_sudo_credential\(\) \{$/ { copy=1 }
    copy { print }
    copy && /^}$/ { exit }
' "$TMPDIR/noid-update-all.sh" > "$TMPDIR/prime-sudo.function"
assert_cmd_success "authentication helper parses in isolation" \
    bash -n "$TMPDIR/prime-sudo.function"
: > "$TMPDIR/prime-sudo.log"
assert_cmd_failure \
    "cancelled graphical authentication returns failure without terminal fallback" \
    env SUDO_ASKPASS=/fixture/askpass PRIME_LOG="$TMPDIR/prime-sudo.log" \
    bash -c '
        . "$1"
        sudo() { printf "%s\n" "$*" >> "$PRIME_LOG"; return 1; }
        prime_sudo_credential
    ' _ "$TMPDIR/prime-sudo.function"
assert_eq '-A -v' "$(<"$TMPDIR/prime-sudo.log")" \
    "graphical cancellation makes exactly one askpass-mode sudo attempt"
: > "$TMPDIR/prime-sudo.log"
assert_cmd_success "terminal launch uses its native sudo prompt exactly once" \
    env -u SUDO_ASKPASS PRIME_LOG="$TMPDIR/prime-sudo.log" \
    bash -c '
        . "$1"
        sudo() { printf "%s\n" "$*" >> "$PRIME_LOG"; return 0; }
        prime_sudo_credential
    ' _ "$TMPDIR/prime-sudo.function"
assert_eq '-v' "$(<"$TMPDIR/prime-sudo.log")" \
    "terminal launch never receives the graphical -A selector"
assert_cmd_success \
    "authentication cancellation precedes marker publication and snapshots" \
    python3 - "$TMPDIR/noid-update-all.sh" <<'PY'
import sys
text = open(sys.argv[1], encoding='utf-8').read()
cancel = text.index('_emit_marker "CANCELLED authentication"')
publish = text.index('# Publish a durable, process-bound update window')
step = text.index('step "1" "Snapper Pre-Snapshot"')
assert cancel < publish < step
PY
assert_grep_fixed 'flock --nonblock --conflict-exit-code 75 --no-fork "$UPDATE_LOCK"' \
    "$TMPDIR/noid-update-all.sh" \
    "overlapping update workflows are rejected"
assert_not_grep 'sudo touch /run/noid-update-running' \
    "$TMPDIR/noid-update-all.sh" \
    "updater never publishes an existence-only suppression marker"
assert_grep_fixed 'mv -fT -- "$temporary" "$marker"' \
    "$TMPDIR/noid-update-all.sh" \
    "process-bound update record is published atomically"
assert_grep_fixed 'sudo /usr/libexec/noid-update-window-active' \
    "$TMPDIR/noid-update-all.sh" \
    "updater verifies its own published suppression authority"
assert_grep_fixed '/usr/bin/flock --nonblock --conflict-exit-code 75 --no-fork "$UPDATE_LOCK"' \
    "$TMPDIR/noid-update-all.sh" \
    "updater retains a live kernel-lock owner for its full workflow"
assert_grep_fixed 'update lock guardian readiness timed out' \
    "$TMPDIR/noid-update-all.sh" \
    "lock readiness has a distinct bounded timeout result"
assert_cmd_success "live unready lock guardian is stopped before wait" \
    python3 - "$TMPDIR/noid-update-all.sh" <<'PY'
import sys

text = open(sys.argv[1], encoding="utf-8").read()
start = text.index('if [ "$lock_ready" -ne 1 ]; then')
end = text.index('rm -f -- "$UPDATE_LOCK_READY"', start)
block = text[start:end]
live = block.index('if kill -0 "$UPDATE_LOCK_GUARD_PID"')
kill = block.index('kill "$UPDATE_LOCK_GUARD_PID"', live)
wait = block.index('wait "$UPDATE_LOCK_GUARD_PID"', kill)
timeout = block.index('readiness timed out', wait)
dead_wait = block.index('wait "$UPDATE_LOCK_GUARD_PID"', wait + 1)
assert live < kill < wait < timeout < dead_wait
PY
assert_grep_fixed 'f /run/lock/noid-update-all.lock 0660 root wheel -' "$KS_FILE" \
    "tmpfiles recreates the system-wide workflow lock after every boot"
assert_grep_fixed 'process_matches || inactive' \
    "$TMPDIR/noid-update-window-active" \
    "validator checks the exact updater identity before and after lock proof"
assert_grep_fixed 'guardian_matches || inactive' \
    "$TMPDIR/noid-update-window-active" \
    "validator checks the exact live lock owner before and after contention proof"
assert_grep_fixed '$2 == "FLOCK" && $4 == "WRITE" && $5 == owner' \
    "$TMPDIR/noid-update-window-active" \
    "validator binds guardian PID and lock inode through /proc/locks"
assert_grep_fixed 'tr '\''\0'\'' '\''\n'\'' <"/proc/$pid/cmdline" | grep -Fqx -- "$UPDATER"' \
    "$TMPDIR/noid-update-window-active" \
    "validator binds argv to the canonical updater path"
assert_grep_fixed 'flock --nonblock 9' "$TMPDIR/noid-update-window-active" \
    "validator requires the workflow lock to remain held"

# Execute the exact validator logic against a transformed private fixture.
# Only absolute paths, expected uid/gid names and the root guard are adapted;
# the schema, /proc checks, argv binding, FD scan and flock proof are unchanged.
current_user=$(id -un)
current_group=$(id -gn)
sed \
    -e "s#MARKER=/run/noid-update-running#MARKER=$TMPDIR/window.marker#" \
    -e "s#LOCK=/run/lock/noid-update-all.lock#LOCK=$TMPDIR/update.lock#" \
    -e "s#UPDATER=/usr/local/bin/noid-update-all.sh#UPDATER=$TMPDIR/noid-update-all.fixture#" \
    -e "s#GUARDIAN=/usr/libexec/noid-update-lock-guardian#GUARDIAN=$TMPDIR/noid-update-lock-guardian#" \
    -e "s#root:root:600:1#$current_user:$current_group:600:1#" \
    -e "s#root:wheel:660#$current_user:$current_group:660#" \
    -e 's#^\[ "$(id -u)" -eq 0 \] || inactive$#:#' \
    "$TMPDIR/noid-update-window-active" > "$TMPDIR/window-active.fixture"
cat > "$TMPDIR/noid-update-all.fixture" <<FIXTURE_EOF
#!/usr/bin/bash
set -euo pipefail
proc_stat=\$(<"/proc/\$\$/stat")
proc_tail=\${proc_stat##*) }
read -r -a proc_fields <<<"\$proc_tail"
proc_start=\${proc_fields[19]}
ready="$TMPDIR/window-guard.ready.\$\$"
: >"\$ready"
chmod 0600 "\$ready"
if [ "\${NOLOCK:-0}" != 1 ]; then
    /usr/bin/flock --nonblock --no-fork "$TMPDIR/update.lock" /usr/bin/bash \
        "$TMPDIR/noid-update-lock-guardian" "\$\$" "\$proc_start" "\$ready" &
else
    /usr/bin/bash -c '
        exec 8<>"\$1"
        shift
        exec /usr/bin/bash "\$@"
    ' _ "$TMPDIR/update.lock" "$TMPDIR/noid-update-lock-guardian" \
        "\$\$" "\$proc_start" "\$ready" &
fi
guard_pid=\$!
for _ in {1..100}; do
    [ "\$(cat "\$ready" 2>/dev/null || true)" = ready ] && break
    kill -0 "\$guard_pid" 2>/dev/null || exit 1
    sleep 0.02
done
[ "\$(cat "\$ready" 2>/dev/null || true)" = ready ] || exit 1
rm -f -- "\$ready"
printf '%s %s\n' "\$\$" "\$guard_pid" >"$TMPDIR/window-worker.pid"
while :; do sleep 1; done
FIXTURE_EOF
chmod 0755 "$TMPDIR/noid-update-all.fixture"
chmod 0755 "$TMPDIR/noid-update-lock-guardian"
install -m 0660 /dev/null "$TMPDIR/update.lock"

start_window_worker() {
    local no_lock=${1:-0}
    # The fixture lives on executable /var/tmp, but Bash remains the explicit
    # interpreter and the canonical script path is an exact argv element.
    NOLOCK=$no_lock /usr/bin/bash "$TMPDIR/noid-update-all.fixture" &
    WINDOW_WORKER_PID=$!
    for _ in {1..50}; do
        if [ -s "$TMPDIR/window-worker.pid" ]; then
            read -r WINDOW_WORKER_PID WINDOW_GUARD_PID \
                <"$TMPDIR/window-worker.pid"
            return 0
        fi
        sleep 0.02
    done
    return 1
}
stop_window_worker() {
    kill "$WINDOW_WORKER_PID" 2>/dev/null || true
    kill "$WINDOW_GUARD_PID" 2>/dev/null || true
    wait "$WINDOW_WORKER_PID" 2>/dev/null || true
    wait "$WINDOW_GUARD_PID" 2>/dev/null || true
    WINDOW_WORKER_PID=
    WINDOW_GUARD_PID=
    rm -f "$TMPDIR/window-worker.pid"
}
write_window_marker() {
    local stat_line stat_tail
    local -a stat_fields=()
    stat_line=$(<"/proc/$WINDOW_WORKER_PID/stat")
    stat_tail=${stat_line##*) }
    read -r -a stat_fields <<<"$stat_tail"
    printf 'pid=%s\nstart_time=%s\nuid=%s\nlock_pid=%s\n' \
        "$WINDOW_WORKER_PID" "${stat_fields[19]}" "$(id -u)" \
        "$WINDOW_GUARD_PID" \
        >"$TMPDIR/window.marker"
    chmod 0600 "$TMPDIR/window.marker"
}

assert_cmd_success "fixture updater acquires its workflow lock" \
    start_window_worker 0
write_window_marker
assert_cmd_success "live exact process/argv/fd/flock tuple is active" \
    bash "$TMPDIR/window-active.fixture"
printf 'extra=forbidden\n' >>"$TMPDIR/window.marker"
assert_cmd_failure "marker with an extra schema row is inactive" \
    bash "$TMPDIR/window-active.fixture"
write_window_marker
sed -i 's/^start_time=.*/start_time=1/' "$TMPDIR/window.marker"
assert_cmd_failure "PID start-time mismatch is inactive" \
    bash "$TMPDIR/window-active.fixture"
write_window_marker
mv "$TMPDIR/window.marker" "$TMPDIR/window.target"
ln -s window.target "$TMPDIR/window.marker"
assert_cmd_failure "symlink marker is inactive" \
    bash "$TMPDIR/window-active.fixture"
rm -f "$TMPDIR/window.marker"
mv "$TMPDIR/window.target" "$TMPDIR/window.marker"
stop_window_worker
assert_cmd_failure "stale marker after owner exit is inactive" \
    bash "$TMPDIR/window-active.fixture"

assert_cmd_success "fixture updater without flock starts" start_window_worker 1
write_window_marker
assert_cmd_failure "open lock FD without a held flock is inactive" \
    bash "$TMPDIR/window-active.fixture"
stop_window_worker
rm -f "$TMPDIR/window.marker"
assert_grep_fixed 'BOOT_MUTATION_LOCK=/run/lock/noid-boot-mutation.lock' \
    "$TMPDIR/noid-update-all.sh" "DNF/kernel phase uses the shared boot lock"
assert_grep_fixed 'sudo /usr/libexec/noid-boot-mutation-guard' \
    "$TMPDIR/noid-update-all.sh" "DNF/kernel phase requires a stable M21 basis"
assert_grep_fixed 'sudo /usr/libexec/noid-canonicalize-kernel-cmdline --publish' \
    "$TMPDIR/noid-update-all.sh" \
    "post-DNF phase repairs kernel-install GRUB command-line drift"
assert_grep_fixed 'obsolete Btrfs root selector survived canonical convergence' \
    "$TMPDIR/noid-update-all.sh" \
    "default-subvolume updates reject a resurrected root selector"
assert_not_grep 'DNF failed; kernel command-line convergence was not started' \
    "$TMPDIR/noid-update-all.sh" \
    "kernel command-line convergence is decoupled from the DNF exit code"
assert_not_grep 'DNF failed; boot-image regeneration was not started' \
    "$TMPDIR/noid-update-all.sh" \
    "boot-image regeneration is decoupled from the DNF exit code"
assert_not_grep 'DNF failed; branding convergence was not started' \
    "$TMPDIR/noid-update-all.sh" \
    "branding convergence is decoupled from the DNF exit code"
assert_not_grep 'DNF failed; VSCodium launcher convergence was not started' \
    "$TMPDIR/noid-update-all.sh" \
    "VSCodium launcher convergence is decoupled from the DNF exit code"
assert_grep_fixed 'AIDE check skipped because the DNF transaction failed' \
    "$TMPDIR/noid-update-all.sh" \
    "AIDE evidence remains gated on a successful DNF transaction"
awk '
    /^echo "  -> Canonical post-DNF kernel command-line convergence\.\.\."$/ { copy=1 }
    copy { print }
    copy && /^fi$/ { exit }
' "$TMPDIR/noid-update-all.sh" > "$TMPDIR/cmdline-converge.block"
assert_grep_fixed 'noid-canonicalize-kernel-cmdline' \
    "$TMPDIR/cmdline-converge.block" \
    "the cmdline convergence block was extracted for execution"
assert_not_grep 'DNF_SUCCEEDED' "$TMPDIR/cmdline-converge.block" \
    "the cmdline convergence block carries no DNF gate"
run_cmdline_fixture() {
    local before_sha=$1 published_sha=$2 canonicalize_rc=$3
    CMD_BEFORE="$before_sha" CMD_PUBLISHED="$published_sha" \
        CMD_CANON_RC="$canonicalize_rc" bash -c '
        sudo() {
            case "$1" in
                /usr/libexec/noid-canonicalize-kernel-cmdline)
                    printf "CANONICALIZE\n" >&2
                    return "$CMD_CANON_RC" ;;
                awk) return 1 ;;
                sha256sum) printf "%s  /etc/kernel/cmdline\n" "$CMD_PUBLISHED" ;;
                grep) return 1 ;;
                *) return 0 ;;
            esac
        }
        RED= GREEN= YELLOW= NC=
        ERRORS=0
        DNF_SUCCEEDED=0
        BOOT_IMAGE_GLOBAL_REBUILD=0
        BOOT_IMAGE_REBUILD_REASON=
        cmdline_before_sha=$CMD_BEFORE
        . "$1"
        printf "GLOBAL=%s ERRORS=%s\n" "$BOOT_IMAGE_GLOBAL_REBUILD" "$ERRORS"
    ' _ "$TMPDIR/cmdline-converge.block" 2>&1
}
cmdline_ok=$(run_cmdline_fixture beforesha beforesha 0)
assert_grep_fixed 'CANONICALIZE' <(printf '%s\n' "$cmdline_ok") \
    "cmdline convergence executes despite a nonzero DNF exit"
assert_grep_fixed 'durable kernel command line and normal BLS entries converged' \
    <(printf '%s\n' "$cmdline_ok") \
    "an unchanged durable cmdline reports plain convergence"
assert_grep_fixed 'GLOBAL=0 ERRORS=0' <(printf '%s\n' "$cmdline_ok") \
    "an unchanged durable cmdline queues no global rebuild"
cmdline_changed=$(run_cmdline_fixture beforesha differentsha 0)
assert_grep_fixed 'GLOBAL=1 ERRORS=0' <(printf '%s\n' "$cmdline_changed") \
    "a changed durable cmdline queues the all-kernel rebuild"
cmdline_failed=$(run_cmdline_fixture beforesha beforesha 1)
assert_grep_fixed 'canonical kernel command-line convergence failed; do not reboot' \
    <(printf '%s\n' "$cmdline_failed") \
    "a failed publisher blocks with do-not-reboot"
assert_grep_fixed 'GLOBAL=0 ERRORS=1' <(printf '%s\n' "$cmdline_failed") \
    "a failed publisher counts one workflow error"
unset -f run_cmdline_fixture
awk '
    /^echo "  -> VSCodium native default-GPU launcher convergence\.\.\."$/ { copy=1 }
    copy { print }
    copy && /^fi$/ { exit }
' "$TMPDIR/noid-update-all.sh" > "$TMPDIR/codium-converge.block"
assert_grep_fixed 'sudo /usr/local/sbin/noid-codium-launcher-sync' \
    "$TMPDIR/codium-converge.block" \
    "the VSCodium convergence block invokes the canonical publisher"
assert_not_grep 'DNF_SUCCEEDED' "$TMPDIR/codium-converge.block" \
    "the VSCodium convergence block carries no DNF gate"
sed 's#/usr/local/sbin/noid-codium-launcher-sync#/usr/bin/true#g' \
    "$TMPDIR/codium-converge.block" > "$TMPDIR/codium-converge.fixture"
run_codium_fixture() {
    local sync_rc=$1
    CODIUM_SYNC_RC="$sync_rc" bash -c '
        sudo() {
            if [ "$1" = /usr/bin/true ]; then
                printf "CODIUM_SYNC\n" >&2
                return "$CODIUM_SYNC_RC"
            fi
            return 0
        }
        RED= GREEN= YELLOW= NC=
        ERRORS=0
        DNF_SUCCEEDED=0
        . "$1"
        printf "ERRORS=%s\n" "$ERRORS"
    ' _ "$TMPDIR/codium-converge.fixture" 2>&1
}
codium_ok=$(run_codium_fixture 0)
assert_grep_fixed 'CODIUM_SYNC' <(printf '%s\n' "$codium_ok") \
    "VSCodium convergence executes despite a nonzero DNF exit"
assert_grep_fixed 'RPM payload pristine; native default-GPU launchers converged' \
    <(printf '%s\n' "$codium_ok") \
    "successful VSCodium convergence reports the exact postcondition"
assert_grep_fixed 'ERRORS=0' <(printf '%s\n' "$codium_ok") \
    "successful VSCodium convergence adds no workflow error"
codium_failed=$(run_codium_fixture 1)
assert_grep_fixed 'VSCodium launcher convergence failed' \
    <(printf '%s\n' "$codium_failed") \
    "a failed VSCodium publisher remains visible after a nonzero DNF exit"
assert_grep_fixed 'ERRORS=1' <(printf '%s\n' "$codium_failed") \
    "a failed VSCodium publisher counts one workflow error"
unset -f run_codium_fixture
boot_guard_line=$(grep -nF 'sudo /usr/libexec/noid-boot-mutation-guard' \
    "$TMPDIR/noid-update-all.sh" | head -1 | cut -d: -f1 || true)
dnf_line=$(grep -nF "sudo sh -c 'umask 022; LC_ALL=C dnf \"\$1\" upgrade --refresh -y'" \
    "$TMPDIR/noid-update-all.sh" | head -1 | cut -d: -f1 || true)
cmdline_converge_line=$(grep -nF 'sudo /usr/libexec/noid-canonicalize-kernel-cmdline --publish' \
    "$TMPDIR/noid-update-all.sh" | head -1 | cut -d: -f1 || true)
dracut_line=$(grep -nF 'sudo -C 8 /usr/libexec/noid-dracut-regenerate-all' \
    "$TMPDIR/noid-update-all.sh" | head -1 | cut -d: -f1 || true)
boot_release_line=$(grep -nF 'flock -u 7' \
    "$TMPDIR/noid-update-all.sh" | head -1 | cut -d: -f1 || true)
identity_queue_line=$(grep -nF 'systemctl start noid-identity-bls-refresh.service' \
    "$TMPDIR/noid-update-all.sh" | head -1 | cut -d: -f1 || true)
nvidia_queue_line=$(grep -nF 'queued_marker=$(sudo /usr/libexec/noid-nvidia-initramfs-queue' \
    "$TMPDIR/noid-update-all.sh" | head -1 | cut -d: -f1 || true)
if [ -n "$boot_guard_line" ] && [ -n "$dnf_line" ] \
        && [ -n "$cmdline_converge_line" ] && [ -n "$dracut_line" ] \
        && [ -n "$boot_release_line" ] && [ -n "$identity_queue_line" ] \
        && [ -n "$nvidia_queue_line" ] \
        && [ "$boot_guard_line" -lt "$dnf_line" ] \
        && [ "$dnf_line" -lt "$cmdline_converge_line" ] \
        && [ "$cmdline_converge_line" -lt "$dracut_line" ] \
        && [ "$dracut_line" -lt "$boot_release_line" ] \
        && [ "$dnf_line" -lt "$boot_release_line" ] \
        && [ "$boot_release_line" -lt "$identity_queue_line" ] \
        && [ "$identity_queue_line" -lt "$nvidia_queue_line" ]; then
    _pass "update lock spans DNF, then drains M32 before entering M19"
else
    _fail "update boot-mutation lock ordering is incomplete or deadlocking"
fi

# --- Step 1b retired: no image-staged VSCodium extension ---
assert_not_grep '/etc/skel/.vscode-oss' "$KS_FILE" \
    "no VSCodium extension is staged into /etc/skel"
assert_not_grep 'CLAUDE_CODE_EXT_VERSION=' "$KS_FILE" \
    "the retired image pre-stage pin constants are gone"
assert_grep_fixed 'no VSCodium extension is image-staged' "$KS_FILE" \
    "the retired pre-stage is documented as an explicit boundary"
assert_grep_fixed 'offers its VSIX behind a separate informed' "$KS_FILE" \
    "Codex extension is not silently image-staged"
assert_grep_fixed 'noid-claude-install now mirrors that structure exactly' "$KS_FILE" \
    "Claude extension opt-in mirrors the Codex structure"

# --- Step 3c GTK4 update GUI -------------------------------
# The GTK4 + libadwaita + Vte app + graphical askpass are shipped, and the
# .desktop launches the GUI directly (not the old terminal launcher).
assert_grep_fixed "cat > /usr/local/bin/noid-update <<'NOID_UPDATE_APP_EOF'" "$KS_FILE"
UPDATE_APP="$TMPDIR/noid-update"
extract_heredoc "$KS_FILE" "NOID_UPDATE_APP_EOF" "$UPDATE_APP" || \
    _fail "NOID_UPDATE_APP_EOF extraction"
assert_cmd_success "Update GUI parses" python3 -m py_compile "$UPDATE_APP"
assert_grep_fixed "APP_ID = 'com.noidprivacy.Update'" "$KS_FILE"
assert_grep_extended "gi\.require_version\('Vte', '3\.91'\)" "$KS_FILE" "app pins Vte 3.91"
assert_grep_fixed "cat > /usr/local/bin/noid-askpass <<'NOID_ASKPASS_EOF'" "$KS_FILE"
assert_grep_fixed 'zenity --password' "$KS_FILE"
assert_grep_extended '^Exec=/usr/local/bin/noid-update$' \
    "$KS_FILE" \
    "desktop Exec inherits GTK's maintained renderer selection"
assert_not_grep 'Exec=.*GSK_RENDERER=.*noid-update' "$KS_FILE" \
    "Update launcher does not pin a renderer"
assert_grep_extended '^StartupWMClass=com\.noidprivacy\.Update$' "$KS_FILE" "desktop StartupWMClass set"
assert_grep_fixed 'import noid_ui' "$UPDATE_APP" \
    "Update imports the shared UI contract"
assert_grep_fixed 'evidence_clamp.set_maximum_size(420)' "$UPDATE_APP" \
    "Update keeps the single AIDE option in a compact centered card"
assert_grep_fixed "evidence.set_title('After the update')" "$UPDATE_APP" \
    "Update idle page has one clear secondary-options group"
assert_grep_fixed "self.aide_check.set_title('Verify files with AIDE')" "$UPDATE_APP" \
    "Update AIDE switch uses concise action-oriented wording"
assert_grep_fixed "start, 'Start Update'" "$UPDATE_APP" \
    "Update primary action has an explicit accessible name"
assert_grep_fixed 'Gtk.AccessibleRole.PRESENTATION' "$UPDATE_APP" \
    "Update step numbering and progress glyphs are presentation-only"
assert_grep_fixed 'noid_ui.accessible_row(r)' "$UPDATE_APP" \
    "Update step rows publish title and description semantics"
assert_grep_fixed "super().__init__(APP_ID, 'noid-privacy-update', UPDATE_CSS)" \
    "$UPDATE_APP" "Update uses the shared one-instance application base"
assert_grep_fixed "'NoID Privacy Update', 'User-controlled system maintenance'" \
    "$UPDATE_APP" "Update uses the common identity header"
assert_grep_fixed "('Agents + extensions', 'Consent-gated agents + editor/GNOME updates')" \
    "$UPDATE_APP" "Update checklist label is valid under AdwActionRow markup"
assert_not_grep "'Agents & extensions'" "$UPDATE_APP" \
    "Update checklist has no unescaped markup ampersand"
assert_grep_fixed 'self.toast_overlay = Adw.ToastOverlay()' "$UPDATE_APP" \
    "Update reboot/start failures can reach an in-app toast"
assert_grep_fixed 'os.path.isfile(UPDATE_SCRIPT)' "$UPDATE_APP" \
    "Update validates a regular orchestrator before mutation"
assert_grep_fixed 'os.access(UPDATE_SCRIPT, os.X_OK)' "$UPDATE_APP" \
    "Update validates an executable orchestrator before mutation"
assert_grep_fixed 'tempfile.mkstemp(' "$UPDATE_APP" \
    "Update requires private marker creation before child start"
assert_grep_fixed 'child_env = dict(os.environ)' "$UPDATE_APP" \
    "Update child environment has one value per key"
assert_grep_fixed 'subprocess.SubprocessError' "$UPDATE_APP" \
    "bounded NVIDIA probe handles timeouts without crashing completion"
assert_grep_fixed 'except FileNotFoundError:' "$UPDATE_APP" \
    "normal non-NVIDIA hosts are a silent negative reboot probe"
assert_not_grep 'keeps running in the background' "$UPDATE_APP" \
    "Update makes no false detached-background claim"
assert_grep_fixed 'This window owns the interactive update terminal' "$UPDATE_APP" \
    "Update blocks close while its PTY is active"
assert_grep_fixed "elif parts[0] == 'CANCELLED'" "$UPDATE_APP" \
    "Update consumes the explicit authentication-cancel marker"
assert_grep_fixed 'if self.cancelled_before_start:' "$UPDATE_APP" \
    "Update distinguishes cancellation from an attempted update failure"
assert_grep_fixed "self.hero_title.set_label('Update cancelled')" "$UPDATE_APP" \
    "Update presents an honest cancelled state"
assert_grep_fixed 'No update step or ' "$UPDATE_APP" \
    "cancelled state states the exact no-mutation boundary"

assert_cmd_success "each GUI run clears the three canonical reboot fields" \
    python3 - "$UPDATE_APP" <<'PY'
import ast, sys

tree = ast.parse(open(sys.argv[1], encoding='utf-8').read())
window = next(node for node in tree.body
              if isinstance(node, ast.ClassDef) and node.name == 'UpdateWindow')
start = next(node for node in window.body
             if isinstance(node, ast.FunctionDef) and node.name == '_on_start')
cleared = set()
for node in ast.walk(start):
    if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Constant) \
            or node.value.value is not None:
        continue
    for target in node.targets:
        if isinstance(target, ast.Attribute) \
                and isinstance(target.value, ast.Name) \
                and target.value.id == 'self':
            cleared.add(target.attr)
assert {'_reboot_activation', '_reboot_safety', '_reboot_blockers'} <= cleared
assert '_reboot_state' not in cleared
PY

assert_cmd_success "cancelled child release precedes normal error completion" \
    python3 - "$UPDATE_APP" <<'PY'
import ast, sys
text = open(sys.argv[1], encoding='utf-8').read()
tree = ast.parse(text)
window = next(node for node in tree.body
              if isinstance(node, ast.ClassDef) and node.name == 'UpdateWindow')
handler = next(node for node in window.body
               if isinstance(node, ast.FunctionDef)
               and node.name == '_on_child_exited')
body = ast.get_source_segment(text, handler)
assert body.index('self.running = False') < body.index(
    'if self.cancelled_before_start:') < body.index('_completion_snapshot(')
cancel = next(node for node in window.body
              if isinstance(node, ast.FunctionDef)
              and node.name == '_finish_cancelled')
cancel_body = ast.get_source_segment(text, cancel)
assert "self.done_btnbox.set_visible(True)" in cancel_body
PY

assert_cmd_success "VTE spawn uses the exact Fedora 44 named ABI" \
    python3 - "$UPDATE_APP" <<'PY'
import ast, sys
tree = ast.parse(open(sys.argv[1], encoding='utf-8').read())
calls = [n for n in ast.walk(tree)
         if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
         and n.func.attr == 'spawn_async']
required = {'pty_flags', 'working_directory', 'argv', 'envv', 'spawn_flags',
            'child_setup', 'timeout', 'cancellable', 'callback', 'user_data'}
assert len(calls) == 1
call = calls[0]
assert not call.args
assert {kw.arg for kw in call.keywords} == required
values = {kw.arg: kw.value for kw in call.keywords}
assert isinstance(values['timeout'], ast.UnaryOp)
assert isinstance(values['callback'], ast.Attribute)
assert values['callback'].attr == '_spawn_done'
PY

assert_cmd_success "Update completion state is honest for success and failures" \
    python3 - "$UPDATE_APP" <<'PY'
import ast, sys
tree = ast.parse(open(sys.argv[1], encoding='utf-8').read())
selected = []
for node in tree.body:
    if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == 'TOTAL_STEPS'
            for t in node.targets):
        selected.append(node)
    if isinstance(node, ast.FunctionDef) and node.name == '_completion_snapshot':
        selected.append(node)
ns = {}
exec(compile(ast.Module(body=selected, type_ignores=[]), '<completion>', 'exec'), ns)
snap = ns['_completion_snapshot']
assert snap(0, 1) == (['pending'] * 10, 0, 0.0)
states, done, fraction = snap(4, 1)
assert states == ['done', 'done', 'done', 'error'] + ['pending'] * 6
assert done == 3 and fraction == 3 / 10
states, done, fraction = snap(10, 2)
assert states == ['done'] * 9 + ['error']
assert done == 9 and fraction == 9 / 10
assert snap(10, 0) == (['done'] * 10, 10, 1.0)
# STEPFAIL attribution: exactly the failing steps show as errors — a step-2
# failure no longer blames reboot, and the finishing steps stay done.
states, done, fraction = snap(10, 1, {2})
assert states == ['done', 'error'] + ['done'] * 8
assert done == 9 and fraction == 9 / 10
states, done, fraction = snap(10, 1, {2, 10})
assert states == ['done', 'error'] + ['done'] * 7 + ['error']
assert done == 8 and fraction == 8 / 10
states, done, fraction = snap(5, 1, {3})
assert states == ['done', 'done', 'error', 'done', 'done'] + ['pending'] * 5
assert done == 4 and fraction == 4 / 10
PY

assert_cmd_success "GUI preserves the distinct config-drift marker row" \
    python3 - "$UPDATE_APP" <<'PY'
import ast, sys

tree = ast.parse(open(sys.argv[1], encoding='utf-8').read())
selected = []
for node in tree.body:
    if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == 'STEP_MARKER_ROWS'
            for target in node.targets):
        selected.append(node)
    if isinstance(node, ast.FunctionDef) and node.name == '_marker_row':
        selected.append(node)
ns = {}
exec(compile(ast.Module(body=selected, type_ignores=[]), '<marker-row>', 'exec'), ns)
row = ns['_marker_row']
assert row('8') == 8
assert row('8b') == 9
assert row('9') == 10
assert row('unknown') is None
PY
assert_grep_fixed "('Config drift',      '.rpmnew / .rpmsave evidence')" \
    "$UPDATE_APP" "GUI gives config-drift evidence its own checklist row"

assert_cmd_success "Update canonical reboot reader is silent for a safe normal host" \
    python3 - "$UPDATE_APP" <<'PY'
import ast
import contextlib
import io
import subprocess
import sys
from types import SimpleNamespace
from unittest import mock

tree = ast.parse(open(sys.argv[1], encoding='utf-8').read())
window = next(node for node in tree.body
              if isinstance(node, ast.ClassDef) and node.name == 'UpdateWindow')
probe = next(node for node in window.body
             if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
             and node.name == '_reboot_readiness')
probe_class = ast.ClassDef(
    name='Probe', bases=[], keywords=[], body=[probe], decorator_list=[])
module = ast.fix_missing_locations(ast.Module(body=[probe_class], type_ignores=[]))
namespace = {'subprocess': subprocess, 'sys': sys}
exec(compile(module, '<reboot-probe>', 'exec'), namespace)

record = '\n'.join((
    'schema=1', 'activation=none', 'safety=safe', 'blockers=none',
    'running_kernel=7.1.8-test', 'latest_kernel=7.1.8-test',
    'nvidia_running=unavailable', 'nvidia_installed=unavailable', ''))
stderr = io.StringIO()
with mock.patch.object(subprocess, 'run', return_value=SimpleNamespace(
        returncode=0, stdout=record)), \
     contextlib.redirect_stderr(stderr):
    assert namespace['Probe']._reboot_readiness() == ('none', 'safe', 'none')
assert stderr.getvalue() == ''
PY

assert_cmd_success "blocked GUI completion offers no restart action" \
    python3 - "$UPDATE_APP" <<'PY'
import ast, sys
text = open(sys.argv[1], encoding='utf-8').read()
tree = ast.parse(text)
window = next(node for node in tree.body
              if isinstance(node, ast.ClassDef) and node.name == 'UpdateWindow')
finish = next(node for node in window.body
              if isinstance(node, ast.FunctionDef) and node.name == '_finish')
blocked = next(node for node in ast.walk(finish)
               if isinstance(node, ast.If)
               and ast.get_source_segment(text, node.test) == "safety == 'blocked'")
blocked_text = '\n'.join(ast.get_source_segment(text, node) or ''
                         for node in blocked.body)
assert "Gtk.Button(label='Close')" in blocked_text
assert 'Restart now' not in blocked_text
assert '_on_reboot' not in blocked_text
PY

# Marker side-channel that drives the GUI progress (env-guarded; CLI no-op).
assert_grep_fixed '_emit_marker' "$KS_FILE"
assert_grep_fixed 'NOID_UPDATE_MARKER_FILE' "$KS_FILE"
assert_grep_fixed '_emit_marker "WARNINGS $WARNINGS"' \
    "$TMPDIR/noid-update-all.sh" \
    "orchestrator publishes its final non-blocking warning count to the GUI"
assert_grep_fixed "elif parts[0] == 'WARNINGS' and len(parts) >= 2:" \
    "$UPDATE_APP" \
    "Update GUI consumes the count-only final warning marker"
assert_grep_fixed "self.hero_title.set_label('Update complete with warnings')" \
    "$UPDATE_APP" \
    "successful warning runs do not render as either green or failed"
assert_grep_fixed 'if status == 0 and self.warning_count' \
    "$UPDATE_APP" \
    "warning completion language is restricted to successful non-blocking runs"
assert_grep_fixed "'warning needs' if self.warning_count == 1 else 'warnings need'" \
    "$UPDATE_APP" \
    "warning completion language agrees in singular and plural runs"
# Per-step error attribution: the orchestrator flushes STEPFAIL at every step
# transition AND once before the terminal exit gate (step 9 has no successor).
assert_grep_fixed '_emit_marker "STEPFAIL $_LAST_STEP"' "$TMPDIR/noid-update-all.sh"
assert_eq "2" "$(grep -c '^[[:space:]]*_flush_step_errors$' "$TMPDIR/noid-update-all.sh")" \
    "STEPFAIL flush runs at step transitions and before the exit gate"

# --- Step 8 AIDE check-only evidence ---------------------------------------
assert_grep_fixed 'step "8" "AIDE Integrity Evidence"' "$TMPDIR/noid-update-all.sh" \
    "updater labels AIDE as evidence, not baseline replacement"
assert_grep_fixed 'sudo /usr/local/sbin/noid-aide-check.sh' "$TMPDIR/noid-update-all.sh" \
    "updater runs the check-only wrapper"
sed -n '/^step "8" "AIDE Integrity Evidence"$/,/^# \[9\] Reboot Check/p' \
    "$TMPDIR/noid-update-all.sh" > "$TMPDIR/aide-check-block.sh"
assert_grep_fixed 'aide_rc=0' "$TMPDIR/aide-check-block.sh" \
    "AIDE check initializes an explicit result without shell-state changes"
assert_grep_fixed 'sudo /usr/local/sbin/noid-aide-check.sh >/dev/null 2>&1 || aide_rc=$?' \
    "$TMPDIR/aide-check-block.sh" \
    "AIDE check captures its result without arming errexit"
assert_not_grep '^[[:space:]]*set [+-]e' "$TMPDIR/aide-check-block.sh" \
    "AIDE check never changes the orchestrator errexit state"
assert_grep_fixed 'the updater did NOT absorb the drift' "$TMPDIR/noid-update-all.sh" \
    "drift remains visible for review"
assert_grep_fixed "child_env['NOID_SKIP_AIDE_CHECK'] = '1'" "$UPDATE_APP" \
    "GUI skip option controls only the check"
assert_not_grep 'NOID_AIDE_MODE' "$KS_FILE" \
    "superseded rebaseline modes are absent"
assert_not_grep 'aide --update' "$TMPDIR/noid-update-all.sh" \
    "updater never generates or commits a replacement database"
assert_not_grep 'aide.db.new.gz' "$TMPDIR/noid-update-all.sh" \
    "updater never touches an AIDE candidate database"
assert_not_grep 'systemd-run --quiet --unit=noid-aide-rebaseline' "$KS_FILE" \
    "no background trust-replacement unit is scheduled"
assert_grep_fixed 'aide_artifacts=0' "$KS_FILE" \
    "module verifier tracks obsolete AIDE artifacts independently"
assert_grep_fixed 'if [ "$aide_artifacts" -eq 0 ]; then' "$KS_FILE" \
    "module verifier emits the aggregate AIDE success only at zero"
assert_not_grep "cat > /etc/systemd/system/noid-aide-rebaseline-on-boot.service" "$KS_FILE" \
    "no post-boot trust-replacement service is installed"
assert_grep_fixed 'obsolete automatic AIDE replacement artifact present' "$KS_FILE" \
    "module verification rejects stale automatic artifacts"

test_finish

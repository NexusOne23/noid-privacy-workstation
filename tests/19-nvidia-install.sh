#!/bin/bash
# 19-nvidia-install — Stage 1 NVIDIA install helper regression test
#
# Covers: noid-nvidia-install.sh heredoc shipped by Module 19 Phase 3c,
# including trade-off matrix, GPU-generation-detection (lspci codename),
# branch selection (main vs 580xx), Kepler/Fermi refuse-path, complete MOK
# walkthrough text, F44 Wayland package correctness (no redundant explicit base
# driver request; DNF still resolves that required package),
# rollback mode, return-to-menu prompt.
#
# Would catch: helper deleted, trade-off matrix stripped, detection broken,
# branch selection regex broken, refuse-path for legacy GPUs removed,
# xorg-x11-drv-nvidia accidentally re-added, MOK walkthrough text incomplete.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/19-nvidia-mok-docs.ks"
M08_FILE="$PROJECT_ROOT/kickstart/snippets/08-service-minimization.ks"

test_start "19-nvidia-install"

assert_file_exists "$KS_FILE"
assert_cmd_success "bash -n $KS_FILE" bash -n "$KS_FILE"

# --- Heredoc presence + script path ----------------------------------------
assert_grep_fixed "cat > /usr/local/bin/noid-nvidia-install.sh <<'NVIDIA_INSTALL_EOF'" "$KS_FILE"
assert_grep_extended '^NVIDIA_INSTALL_EOF$' "$KS_FILE" \
    "NVIDIA installer heredoc has its closing terminator"
assert_grep_fixed 'chmod 0755 /usr/local/bin/noid-nvidia-install.sh' "$KS_FILE"

# --- Extract heredoc + syntax-check extracted script -----------------------
TMP_SCRIPT="$(mktemp --suffix=.sh)"
TMP_VERIFIER="$(mktemp --suffix=.sh)"
TMP_REBIND="$(mktemp --suffix=.sh)"
TMP_REBUILD="$(mktemp --suffix=.sh)"
TMP_QUEUE="$(mktemp --suffix=.sh)"
TMP_GUARD="$(mktemp --suffix=.sh)"
TMP_GUARD_UNIT="$(mktemp --suffix=.service)"
TMP_KINST="$(mktemp --suffix=.sh)"
TMP_DNFACTION="$(mktemp --suffix=.sh)"
TMP_RESUME="$(mktemp --suffix=.service)"
TMP_POSTBOOT="$(mktemp --suffix=.sh)"
TMP_POSTBOOT_UNIT="$(mktemp --suffix=.service)"
TMP_DOC="$(mktemp --suffix=.md)"
TMP_SYSTEM_RUNNER="$(mktemp --suffix=.sh)"
TMP_NATIVE_AKMODS="$(mktemp --suffix=.sh)"
TMP_RPM_QUERY="$(mktemp --suffix=.sh)"
TMP_REPO_VERIFY="$(mktemp --suffix=.sh)"
TMP_M08_REPO="$(mktemp --suffix=.repo)"
# /tmp is intentionally noexec on the hardened host; PATH fixtures must live
# beside the repository test and are removed by the EXIT trap.
FIXTURE_DIR="$(mktemp -d "$PROJECT_ROOT/.test-nvidia-fixture.XXXXXX")"
trap 'rm -f "$TMP_SCRIPT" "$TMP_VERIFIER" "$TMP_REBIND" "$TMP_REBUILD" "$TMP_QUEUE" "$TMP_GUARD" "$TMP_GUARD_UNIT" "$TMP_KINST" "$TMP_DNFACTION" "$TMP_RESUME" "$TMP_POSTBOOT" "$TMP_POSTBOOT_UNIT" "$TMP_DOC" "$TMP_SYSTEM_RUNNER" "$TMP_NATIVE_AKMODS" "$TMP_RPM_QUERY" "$TMP_REPO_VERIFY" "$TMP_M08_REPO"; rm -rf "$FIXTURE_DIR"' EXIT
extract_heredoc "$KS_FILE" "NVIDIA_INSTALL_EOF" "$TMP_SCRIPT"
extract_heredoc "$KS_FILE" "NVIDIA_DOC_EOF" "$TMP_DOC"
assert_cmd_success "extracted NVIDIA-install script parses (bash -n)" bash -n "$TMP_SCRIPT"
if command -v shellcheck >/dev/null 2>&1; then
    assert_cmd_success "extracted NVIDIA-install script passes ShellCheck" \
        shellcheck -S warning "$TMP_SCRIPT"
else
    _pass "shellcheck unavailable — NVIDIA installer lint skipped"
fi
extract_heredoc "$TMP_SCRIPT" "VERIFY_NV_EOF" "$TMP_VERIFIER"
assert_cmd_success "extracted NVIDIA integrity verifier parses (bash -n)" \
    bash -n "$TMP_VERIFIER"
extract_heredoc "$TMP_SCRIPT" "REBIND_NV_EOF" "$TMP_REBIND"
assert_cmd_success "extracted NVIDIA evidence bridge parses (bash -n)" \
    bash -n "$TMP_REBIND"
assert_grep_fixed 'sudo tee /usr/libexec/noid-nvidia-rebind-evidence' \
    "$TMP_SCRIPT" "installer publishes the M19-owned evidence bridge"
assert_grep_fixed 'sudo rm -f /usr/libexec/noid-nvidia-rebind-evidence' \
    "$TMP_SCRIPT" "rollback retires the evidence bridge"
assert_grep_fixed "/usr/libexec/noid-nvidia-rebind-evidence \\" \
    "$TMP_SCRIPT" "evidence bridge receives executable lifecycle metadata"
extract_heredoc "$TMP_SCRIPT" "HELPER_NV_EOF" "$TMP_REBUILD"
extract_heredoc "$TMP_SCRIPT" "QUEUE_NV_EOF" "$TMP_QUEUE"
extract_heredoc "$TMP_SCRIPT" "GUARD_NV_EOF" "$TMP_GUARD"
extract_heredoc "$TMP_SCRIPT" "GUARD_UNIT_NV_EOF" "$TMP_GUARD_UNIT"
extract_heredoc "$TMP_SCRIPT" "KINST_NV_EOF" "$TMP_KINST"
extract_heredoc "$TMP_SCRIPT" "DNFACTION_NV_EOF" "$TMP_DNFACTION"
extract_heredoc "$TMP_SCRIPT" "RESUME_UNIT_NV_EOF" "$TMP_RESUME"
extract_heredoc "$TMP_SCRIPT" "POSTBOOT_NV_EOF" "$TMP_POSTBOOT"
extract_heredoc "$TMP_SCRIPT" "POSTBOOT_UNIT_NV_EOF" "$TMP_POSTBOOT_UNIT"
for helper_script in "$TMP_REBIND" "$TMP_REBUILD" "$TMP_QUEUE" "$TMP_GUARD" \
        "$TMP_KINST" "$TMP_DNFACTION"; do
    assert_cmd_success "extracted NVIDIA lifecycle helper parses: $(basename "$helper_script")" \
        bash -n "$helper_script"
done
assert_cmd_success "extracted NVIDIA post-boot verifier parses" \
    bash -n "$TMP_POSTBOOT"
if command -v shellcheck >/dev/null 2>&1; then
    for helper_script in "$TMP_VERIFIER" "$TMP_REBIND" "$TMP_REBUILD" "$TMP_QUEUE" \
            "$TMP_GUARD" "$TMP_KINST" "$TMP_DNFACTION" "$TMP_POSTBOOT"; do
        assert_cmd_success \
            "extracted NVIDIA lifecycle helper passes ShellCheck: $(basename "$helper_script")" \
            shellcheck -S warning "$helper_script"
    done
else
    _pass "shellcheck unavailable — NVIDIA lifecycle-helper lint skipped"
fi

# M21 can legitimately regenerate a fully verified managed NVIDIA image after
# M19 has published its pre-reboot record. The bridge must replace only that
# record's current identity/hash binding, preserve prepared boot/MOK state and
# reject ambiguous or malformed state before changing either artifact.
REBIND_ROOT="$FIXTURE_DIR/rebind"
REBIND_STATE="$REBIND_ROOT/state"
REBIND_BOOT="$REBIND_ROOT/boot"
REBIND_VERIFY="$REBIND_ROOT/verify"
REBIND_KVER=9.9.9-200.fc44.x86_64
REBIND_OWNER="$(id -un):$(id -gn)"
mkdir -p "$REBIND_STATE" "$REBIND_BOOT"
chmod 0755 "$REBIND_STATE"
cat >"$REBIND_VERIFY" <<'REBIND_VERIFY_FIXTURE_EOF'
#!/bin/bash
[ "$#" -ge 1 ] || exit 2
printf 'branch=main\n'
printf 'kernel=%s\n' "$1"
printf 'evr=3:fixture-current-1.fc44\n'
printf 'modules=verified\n'
printf 'certificate=matched\n'
if [ "${2:-}" = --require-enrolled ]; then
    [ "$#" -eq 2 ] || exit 2
    printf 'mok=enrolled\n'
else
    [ "$#" -eq 1 ] || exit 2
fi
REBIND_VERIFY_FIXTURE_EOF
chmod 0755 "$REBIND_VERIFY"
printf 'new validated initramfs bytes\n' \
    >"$REBIND_BOOT/initramfs-${REBIND_KVER}.img"
chmod 0600 "$REBIND_BOOT/initramfs-${REBIND_KVER}.img"
REBIND_IMAGE_HASH=$(sha256sum "$REBIND_BOOT/initramfs-${REBIND_KVER}.img" \
    | awk '{print $1}')
REBIND_OLD_HASH=$(printf '0%.0s' {1..64})

run_rebind_fixture() {
    env NOID_TEST_MODE=1 \
        NOID_TEST_STATE_DIR="$REBIND_STATE" \
        NOID_TEST_BOOT_DIR="$REBIND_BOOT" \
        NOID_TEST_VERIFY="$REBIND_VERIFY" \
        NOID_TEST_OWNER="$REBIND_OWNER" \
        bash "$TMP_REBIND" "$REBIND_KVER"
}

cat >"$REBIND_STATE/${REBIND_KVER}.ready" <<REBIND_READY_OLD_EOF
status=ready
branch=main
kernel=${REBIND_KVER}
evr=3:fixture-old-1.fc44
modules=verified
certificate=matched
mok=enrolled
initramfs_sha256=${REBIND_OLD_HASH}
REBIND_READY_OLD_EOF
chmod 0600 "$REBIND_STATE/${REBIND_KVER}.ready"
assert_cmd_success "M21 bridge rebinds an exact ready record" \
    run_rebind_fixture
cat >"$REBIND_ROOT/expected.ready" <<REBIND_READY_EXPECTED_EOF
status=ready
branch=main
kernel=${REBIND_KVER}
evr=3:fixture-current-1.fc44
modules=verified
certificate=matched
mok=enrolled
initramfs_sha256=${REBIND_IMAGE_HASH}
REBIND_READY_EXPECTED_EOF
assert_cmd_success "ready evidence gets current identity and image hash" \
    cmp -s "$REBIND_ROOT/expected.ready" \
        "$REBIND_STATE/${REBIND_KVER}.ready"
assert_eq 600 "$(stat -c %a "$REBIND_STATE/${REBIND_KVER}.ready")" \
    "rebound ready evidence stays private"

sed -i 's/evr=3:fixture-current-1.fc44/evr=3:fixture-stale-1.fc44/' \
    "$REBIND_STATE/${REBIND_KVER}.ready"
assert_cmd_success "matching image hash does not hide stale ready identity" \
    run_rebind_fixture
assert_cmd_success "ready identity is current even when its old hash matched" \
    cmp -s "$REBIND_ROOT/expected.ready" \
        "$REBIND_STATE/${REBIND_KVER}.ready"

rm -f "$REBIND_STATE/${REBIND_KVER}.ready"
REBIND_BOOT_ID=11111111-2222-3333-4444-555555555555
cat >"$REBIND_STATE/${REBIND_KVER}.prepared" <<REBIND_PREPARED_OLD_EOF
status=prepared-awaiting-reboot-validation
branch=main
kernel=${REBIND_KVER}
evr=3:fixture-old-1.fc44
modules=verified
certificate=matched
initramfs_sha256=${REBIND_OLD_HASH}
prepared_boot_id=${REBIND_BOOT_ID}
mok=pending-enrollment
REBIND_PREPARED_OLD_EOF
chmod 0600 "$REBIND_STATE/${REBIND_KVER}.prepared"
assert_cmd_success "M21 bridge rebinds an exact prepared record" \
    run_rebind_fixture
cat >"$REBIND_ROOT/expected.prepared" <<REBIND_PREPARED_EXPECTED_EOF
status=prepared-awaiting-reboot-validation
branch=main
kernel=${REBIND_KVER}
evr=3:fixture-current-1.fc44
modules=verified
certificate=matched
initramfs_sha256=${REBIND_IMAGE_HASH}
prepared_boot_id=${REBIND_BOOT_ID}
mok=pending-enrollment
REBIND_PREPARED_EXPECTED_EOF
assert_cmd_success "prepared evidence preserves boot/MOK state while rebinding" \
    cmp -s "$REBIND_ROOT/expected.prepared" \
        "$REBIND_STATE/${REBIND_KVER}.prepared"

# Older writers could leave the weaker ready record beside prepared evidence.
# The bridge must validate/rebind prepared first and only then retire ready;
# blindly failing the pair leaves the guarded initramfs path permanently
# wedged, while preferring ready would discard the reboot-bound MOK state.
cat >"$REBIND_STATE/${REBIND_KVER}.ready" <<REBIND_READY_SUPERSEDED_EOF
status=ready
branch=main
kernel=${REBIND_KVER}
evr=3:fixture-stale-1.fc44
modules=verified
certificate=matched
mok=enrolled
initramfs_sha256=${REBIND_OLD_HASH}
REBIND_READY_SUPERSEDED_EOF
chmod 0600 "$REBIND_STATE/${REBIND_KVER}.ready"
assert_cmd_success "M21 bridge resolves legacy ready/prepared coexistence" \
    run_rebind_fixture
assert_cmd_failure "validated prepared evidence retires superseded ready" \
    test -e "$REBIND_STATE/${REBIND_KVER}.ready"
assert_cmd_success "coexistence recovery preserves exact prepared evidence" \
    cmp -s "$REBIND_ROOT/expected.prepared" \
        "$REBIND_STATE/${REBIND_KVER}.prepared"

sed -i '$d' "$REBIND_STATE/${REBIND_KVER}.prepared"
REBIND_MALFORMED_HASH=$(sha256sum \
    "$REBIND_STATE/${REBIND_KVER}.prepared" | awk '{print $1}')
assert_cmd_failure "M21 bridge rejects a truncated prepared schema" \
    run_rebind_fixture
assert_eq "$REBIND_MALFORMED_HASH" \
    "$(sha256sum "$REBIND_STATE/${REBIND_KVER}.prepared" | awk '{print $1}')" \
    "failed prepared validation is non-mutating"

rm -f "$REBIND_STATE/${REBIND_KVER}.prepared"
printf 'historical boot evidence\n' \
    >"$REBIND_STATE/${REBIND_KVER}.active"
chmod 0600 "$REBIND_STATE/${REBIND_KVER}.active"
REBIND_ACTIVE_HASH=$(sha256sum "$REBIND_STATE/${REBIND_KVER}.active" \
    | awk '{print $1}')
assert_cmd_success "M21 bridge ignores historical active evidence" \
    run_rebind_fixture
assert_eq "$REBIND_ACTIVE_HASH" \
    "$(sha256sum "$REBIND_STATE/${REBIND_KVER}.active" | awk '{print $1}')" \
    "historical active evidence remains immutable"

# Fedora's native akmods@ unit is Type=oneshot + RemainAfterExit=yes. The
# NoID Privacy worker may wait for activating/running, but active/exited is already
# complete and must never incur the 900-second fallback delay.
awk '
    /^native_akmods_running\(\)/ { copy=1 }
    copy { print }
    copy && /^}/ { exit }
' "$TMP_REBUILD" > "$TMP_NATIVE_AKMODS"
assert_cmd_success "native akmods state classifier parses" \
    bash -n "$TMP_NATIVE_AKMODS"
assert_not_grep 'akmods.service' "$TMP_NATIVE_AKMODS" \
    "native wait never observes the persistent global boot service"
cat > "$FIXTURE_DIR/systemctl" <<'FIXTURE_SYSTEMCTL_EOF'
#!/bin/bash
case "$*" in
    *--property=ActiveState*) printf '%s\n' "${FIXTURE_ACTIVE_STATE:?}" ;;
    *--property=SubState*) printf '%s\n' "${FIXTURE_SUB_STATE:?}" ;;
    *) exit 2 ;;
esac
FIXTURE_SYSTEMCTL_EOF
chmod 0755 "$FIXTURE_DIR/systemctl"
sed -i "s|/usr/bin/systemctl|$FIXTURE_DIR/systemctl|g" "$TMP_NATIVE_AKMODS"
for running_state in activating:start deactivating:stop active:running; do
    active=${running_state%%:*}
    sub=${running_state#*:}
    assert_cmd_success "native akmods state is still running: $running_state" \
        env FIXTURE_ACTIVE_STATE="$active" FIXTURE_SUB_STATE="$sub" \
        kver=fixture bash -c '. "$1"; native_akmods_running' _ \
        "$TMP_NATIVE_AKMODS"
done
for settled_state in active:exited inactive:dead failed:failed; do
    active=${settled_state%%:*}
    sub=${settled_state#*:}
    assert_cmd_failure "native akmods state is settled: $settled_state" \
        env FIXTURE_ACTIVE_STATE="$active" FIXTURE_SUB_STATE="$sub" \
        kver=fixture bash -c '. "$1"; native_akmods_running' _ \
        "$TMP_NATIVE_AKMODS"
done

cat > "$FIXTURE_DIR/id" <<'FIXTURE_ID_EOF'
#!/bin/bash
if [ "${1:-}" = -u ]; then echo 1000; else exec /usr/bin/id "$@"; fi
FIXTURE_ID_EOF
cat > "$FIXTURE_DIR/lspci" <<'FIXTURE_LSPCI_EOF'
#!/bin/bash
printf '%s\n' "${NOID_LSPCI_FIXTURE:-}"
FIXTURE_LSPCI_EOF
cat > "$FIXTURE_DIR/sudo" <<'FIXTURE_SUDO_EOF'
#!/bin/bash
exec "$@"
FIXTURE_SUDO_EOF
chmod 0755 "$FIXTURE_DIR/id" "$FIXTURE_DIR/lspci" "$FIXTURE_DIR/sudo"

{
    printf '%s\n' 'declare -a NVIDIA_RPM_NAMES=()' 'RED=' 'NC='
    awk '
        /^query_installed_nvidia_rpm_names\(\)/ { copy=1 }
        copy { print }
        copy && /^}/ { exit }
    ' "$TMP_SCRIPT"
} >"$TMP_RPM_QUERY"
cat >"$FIXTURE_DIR/rpm" <<'FIXTURE_RPM_EOF'
#!/bin/bash
case "${RPM_QUERY_FIXTURE:?}" in
    failure) exit 77 ;;
    empty) exit 0 ;;
    populated)
        printf '%s\n' bash akmod-nvidia xorg-x11-drv-nvidia-cuda coreutils
        ;;
    *) exit 78 ;;
esac
FIXTURE_RPM_EOF
chmod 0755 "$FIXTURE_DIR/rpm"
assert_cmd_failure "installed NVIDIA inventory query fails closed on rpmdb failure" \
    env PATH="$FIXTURE_DIR:$PATH" RPM_QUERY_FIXTURE=failure \
    bash -c '. "$1"; query_installed_nvidia_rpm_names' _ "$TMP_RPM_QUERY"
assert_cmd_success "successful empty RPM inventory remains an exact empty array" \
    env PATH="$FIXTURE_DIR:$PATH" RPM_QUERY_FIXTURE=empty \
    bash -c '. "$1"; query_installed_nvidia_rpm_names; [ "${#NVIDIA_RPM_NAMES[@]}" -eq 0 ]' \
    _ "$TMP_RPM_QUERY"
assert_eq $'akmod-nvidia\nxorg-x11-drv-nvidia-cuda' "$(
    env PATH="$FIXTURE_DIR:$PATH" RPM_QUERY_FIXTURE=populated \
        bash -c '. "$1"; query_installed_nvidia_rpm_names; printf "%s\n" "${NVIDIA_RPM_NAMES[@]}"' \
        _ "$TMP_RPM_QUERY"
)" "installed NVIDIA inventory keeps only exact NVIDIA package families"

{
    cat <<'REPO_VERIFY_PREAMBLE_EOF'
sudo() {
    if [ "${1:-}" = stat ] && [ "${2:-}" = -c ] \
            && [ "${3:-}" = '%U:%G:%a' ]; then
        printf '%s\n' root:root:644
        return 0
    fi
    command "$@"
}
REPO_VERIFY_PREAMBLE_EOF
    awk '
        /^verify_nvidia_repo_state\(\)/ { copy=1 }
        copy && /^set_nvidia_repo_state\(\)/ { exit }
        copy { print }
    ' "$TMP_SCRIPT"
} >"$TMP_REPO_VERIFY"
extract_heredoc "$M08_FILE" "NOID_NVIDIA_DRIVER_REPO_EOF" "$TMP_M08_REPO"
assert_cmd_success "M08 canonical disabled NVIDIA repository validates against M19" \
    bash -c '. "$1"; NVIDIA_REPO=$2; verify_nvidia_repo_state 0' \
    _ "$TMP_REPO_VERIFY" "$TMP_M08_REPO"
NVIDIA_REPO_FIXTURE="$FIXTURE_DIR/rpmfusion-nonfree-nvidia-driver.repo"
cat >"$NVIDIA_REPO_FIXTURE" <<'REPO_FIXTURE_EOF'
[rpmfusion-nonfree-nvidia-driver]
name=RPM Fusion for Fedora $releasever - Nonfree - NVIDIA Driver
metalink=https://mirrors.rpmfusion.org/metalink?repo=nonfree-fedora-nvidia-driver-$releasever&arch=$basearch
enabled=1
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-rpmfusion-nonfree-fedora-$releasever
skip_if_unavailable=True
[rpmfusion-nonfree-nvidia-driver-debuginfo]
name=RPM Fusion for Fedora $releasever - Nonfree - NVIDIA Driver Debug
metalink=https://mirrors.rpmfusion.org/metalink?repo=nonfree-fedora-nvidia-driver-debug-$releasever&arch=$basearch
enabled=0
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-rpmfusion-nonfree-fedora-$releasever
skip_if_unavailable=True
[rpmfusion-nonfree-nvidia-driver-source]
name=RPM Fusion for Fedora $releasever - Nonfree - NVIDIA Driver Source
metalink=https://mirrors.rpmfusion.org/metalink?repo=nonfree-fedora-nvidia-driver-source-$releasever&arch=$basearch
enabled=0
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-rpmfusion-nonfree-fedora-$releasever
skip_if_unavailable=True
REPO_FIXTURE_EOF
assert_cmd_success "exact NVIDIA repository fixture validates" \
    bash -c '. "$1"; NVIDIA_REPO=$2; verify_nvidia_repo_state 1' \
    _ "$TMP_REPO_VERIFY" "$NVIDIA_REPO_FIXTURE"
sed -i '0,/^gpgcheck=1$/s//gpgcheck=0/' "$NVIDIA_REPO_FIXTURE"
assert_cmd_failure "disabled NVIDIA package-signature gate fails closed" \
    bash -c '. "$1"; NVIDIA_REPO=$2; verify_nvidia_repo_state 1' \
    _ "$TMP_REPO_VERIFY" "$NVIDIA_REPO_FIXTURE"
sed -i '0,/^gpgcheck=0$/s//gpgcheck=1/' "$NVIDIA_REPO_FIXTURE"
printf '%s\n' 'enabled=0' >>"$NVIDIA_REPO_FIXTURE"
assert_cmd_failure "duplicate repository enabled keys fail closed" \
    bash -c '. "$1"; NVIDIA_REPO=$2; verify_nvidia_repo_state 1' \
    _ "$TMP_REPO_VERIFY" "$NVIDIA_REPO_FIXTURE"
cat >"$NVIDIA_REPO_FIXTURE" <<'REPO_DUPLICATE_FIXTURE_EOF'
[rpmfusion-nonfree-nvidia-driver]
name=RPM Fusion for Fedora $releasever - Nonfree - NVIDIA Driver
metalink=https://mirrors.rpmfusion.org/metalink?repo=nonfree-fedora-nvidia-driver-$releasever&arch=$basearch
enabled=1
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-rpmfusion-nonfree-fedora-$releasever
skip_if_unavailable=True
[rpmfusion-nonfree-nvidia-driver]
enabled=1
[rpmfusion-nonfree-nvidia-driver-debuginfo]
name=RPM Fusion for Fedora $releasever - Nonfree - NVIDIA Driver Debug
metalink=https://mirrors.rpmfusion.org/metalink?repo=nonfree-fedora-nvidia-driver-debug-$releasever&arch=$basearch
enabled=0
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-rpmfusion-nonfree-fedora-$releasever
skip_if_unavailable=True
[rpmfusion-nonfree-nvidia-driver-source]
name=RPM Fusion for Fedora $releasever - Nonfree - NVIDIA Driver Source
metalink=https://mirrors.rpmfusion.org/metalink?repo=nonfree-fedora-nvidia-driver-source-$releasever&arch=$basearch
enabled=0
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-rpmfusion-nonfree-fedora-$releasever
skip_if_unavailable=True
REPO_DUPLICATE_FIXTURE_EOF
assert_cmd_failure "duplicate repository sections fail closed" \
    bash -c '. "$1"; NVIDIA_REPO=$2; verify_nvidia_repo_state 1' \
    _ "$TMP_REPO_VERIFY" "$NVIDIA_REPO_FIXTURE"

awk '
    /^run_system_root\(\)/ { copy=1 }
    copy { print }
    copy && /^}/ { exit }
' "$TMP_SCRIPT" > "$TMP_SYSTEM_RUNNER"
runner_umask=$(umask 027; PATH="$FIXTURE_DIR:$PATH" bash -c \
    '. "$1"; run_system_root /usr/bin/sh -c umask' _ "$TMP_SYSTEM_RUNNER")
assert_eq 0022 "$runner_umask" \
    "system metadata generator gets command-local public-file umask"
assert_grep_fixed 'sudo /usr/bin/sh -c '\''umask 022; exec "$@"'\'' noid-system-root "$@"' \
    "$TMP_SYSTEM_RUNNER" "root system-command wrapper preserves argument boundaries"

# --- Refuse-root pattern ---------------------------------------------------
assert_grep_fixed 'if [ "$(id -u)" -eq 0 ]; then' "$TMP_SCRIPT"

# --- Shared guided terminal presentation -----------------------------------
assert_grep_fixed 'FMT_LIB=/usr/local/lib/noid-privacy/agent-install-format.sh' \
    "$TMP_SCRIPT" "NVIDIA helper shares the Setup installer presentation"
assert_grep_fixed 'fmt_banner "NoID Privacy NVIDIA Setup"' "$TMP_SCRIPT" \
    "NVIDIA install starts with the common Setup identity"
for phase in \
    'fmt_step 1 6 "Resolve exact package plan"' \
    'fmt_step 2 6 "Prepare signing key + install ${AKMOD_PKG}"' \
    'fmt_step 3 6 "Build + verify NVIDIA kernel modules"' \
    'fmt_step 4 6 "Verify boot-display fallback"' \
    'fmt_step 5 6 "Confirm exact signing certificate"' \
    'fmt_step 6 6 "Check or request certificate enrollment"'; do
    assert_grep_fixed "$phase" "$TMP_SCRIPT" \
        "NVIDIA install exposes guided phase: $phase"
done
assert_grep_fixed \
    'fmt_info "The serialized native build can take several minutes; live akmods output follows when its build lock is available."' \
    "$TMP_SCRIPT" "NVIDIA build cannot look silently stalled"
assert_grep_fixed 'fmt_banner "NoID Privacy NVIDIA Rollback"' "$TMP_SCRIPT" \
    "NVIDIA rollback has a distinct terminal identity"
assert_grep_fixed 'fmt_step 3 4 "Restore + verify every boot image"' \
    "$TMP_SCRIPT" "NVIDIA rollback exposes its long boot-image phase"
assert_grep_fixed 'fmt_done "NVIDIA Stage 1 preparation complete"' \
    "$TMP_SCRIPT" "NVIDIA install ends with a concise preparation summary"

# --- Return-to-menu pattern (unified) -----------------------------
assert_grep_fixed 'return_to_menu_prompt()' "$TMP_SCRIPT"
assert_grep_fixed 'NOID_WELCOME_SPAWN' "$TMP_SCRIPT" \
    "welcome-spawned runs skip the standalone hold (wrapper owns the prompt)"
assert_grep_fixed 'Re-open welcome menu? [Y/n]' "$TMP_SCRIPT"

# --- Mode/flag parsing (install + dry-run + rollback + force-branch) -------
assert_grep_fixed '--dry-run|--dry' "$TMP_SCRIPT"
assert_grep_fixed '--rollback|-r' "$TMP_SCRIPT"
assert_grep_fixed '--force-branch=main' "$TMP_SCRIPT"
assert_grep_fixed '--force-branch=580xx' "$TMP_SCRIPT"
assert_grep_fixed '--help|-h' "$TMP_SCRIPT"

# --- Trade-off matrix (the "decision-first" design) ------------------------
assert_grep_fixed 'Informed Decision' "$TMP_SCRIPT"
assert_grep_fixed 'Recommended for most users: SKIP THIS' "$TMP_SCRIPT"
assert_grep_fixed 'Nouveau/Mesa default' "$TMP_SCRIPT"
assert_not_grep 'Nouveau + NVK is the default' "$TMP_SCRIPT" \
    "installer does not promise NVK for every NVIDIA generation"
assert_grep_fixed 'Trade-off matrix' "$TMP_SCRIPT"
# Each capability decision we care about, without unverifiable benchmark claims
assert_grep_fixed 'CUDA application' "$TMP_SCRIPT"
assert_grep_fixed 'DLSS' "$TMP_SCRIPT"
assert_grep_fixed 'Benchmark that game on this exact GPU' "$TMP_SCRIPT"
assert_grep_fixed 'NVENC' "$TMP_SCRIPT"

# --- GPU-generation detection via lspci codename --------------------------
assert_grep_fixed 'detect_nvidia_gpu()' "$TMP_SCRIPT"
# All 9 generation codename prefixes must be handled in generation_info()
for prefix in GB AD GA TU GV GP GM GK GF; do
    assert_grep_fixed "$prefix)" "$TMP_SCRIPT"
done

# --- Branch selection: mainline packages ----------------------------------
assert_grep_fixed 'AKMOD_PKG="akmod-nvidia"' "$TMP_SCRIPT"
assert_grep_fixed 'AKMOD_PKG="akmod-nvidia-580xx"' "$TMP_SCRIPT"
assert_grep_fixed 'CUDA_PKG="xorg-x11-drv-nvidia-cuda"' "$TMP_SCRIPT"
assert_grep_fixed 'CUDA_PKG="xorg-x11-drv-nvidia-580xx-cuda"' "$TMP_SCRIPT"
assert_grep_fixed 'NVIDIA_INSTALL_MANIFEST=(akmods "$AKMOD_PKG" "$CUDA_PKG")' "$TMP_SCRIPT"
assert_grep_fixed 'run_system_root /usr/bin/env LC_ALL=C /usr/bin/dnf --assumeno --refresh' \
    "$TMP_SCRIPT" \
    "complete NVIDIA manifest is solver-checked before installation"
assert_not_grep 'sudo env LC_ALL=C dnf' "$TMP_SCRIPT" \
    "solver check cannot bypass the scoped 0022 system-root wrapper"
assert_grep_fixed '--repo="$NVIDIA_DNF_REPOS"' "$TMP_SCRIPT" \
    "solver and install are confined to reviewed Fedora/RPM Fusion repos"
assert_not_grep '--allowerasing' "$TMP_SCRIPT" \
    "installer never silently erases an opposite graphics branch"
assert_grep_fixed 'opposite_branch_packages=()' "$TMP_SCRIPT"
assert_grep_fixed 'Run noid-nvidia-install.sh --rollback, reboot into nouveau' "$TMP_SCRIPT"
assert_grep_fixed 'akmod-nvidia-580xx xorg-x11-drv-nvidia-580xx-cuda' "$KS_FILE" \
    "installed legacy documentation uses the branch-matched CUDA package"
assert_grep_fixed '1. Resolve the exact package plan and create a pre-change snapshot' \
    "$TMP_SCRIPT" "printed plan matches progress Step 1"
assert_grep_fixed '2. Generate the MOK signing key first, then install' \
    "$TMP_SCRIPT" "printed plan matches progress Step 2"
assert_grep_fixed '3. Wait for the native akmods build and verify the exact signed module set' \
    "$TMP_SCRIPT" "printed plan matches progress Step 3"
assert_grep_fixed '4. Verify plymouth.use-simpledrm=1 in kernel cmdline' \
    "$TMP_SCRIPT" "printed plan matches progress Step 4"
assert_grep_fixed '5. Confirm the exact signing certificate used by every NVIDIA module' \
    "$TMP_SCRIPT" "printed plan matches progress Step 5"
assert_grep_fixed '6. Check whether that certificate is enrolled; if not, request its MOK import' \
    "$TMP_SCRIPT" "printed plan matches progress Step 6"
assert_grep_fixed 'added by Module 01 only when NVIDIA was detected during OS' \
    "$TMP_SCRIPT" "simpledrm plan states M01's hardware-conditional behavior"
assert_grep_fixed 'installation; this helper adds it otherwise' "$TMP_SCRIPT" \
    "simpledrm plan states the helper fallback"
assert_not_grep 'set as default by Module 01' "$TMP_SCRIPT" \
    "simpledrm plan contains no false universal-default claim"

# --- F44 Wayland-only package correctness ---------------------------------
# MUST install xorg-x11-drv-nvidia-cuda (ships nvidia-smi; badly named)
assert_grep_fixed 'xorg-x11-drv-nvidia-cuda' "$TMP_SCRIPT"
assert_grep_fixed 'Applying NoID Privacy NVIDIA laptop lid-close safety default' "$TMP_SCRIPT" \
    "installer retains the project-selected NVIDIA lid safety policy"
assert_not_grep '20-noid-nvidia-suspend' "$TMP_SCRIPT" \
    "installer cannot create or delete the base GNOME power policy"
assert_not_grep_extended '^[[:space:]]*sleep-inactive-(ac|battery)-type=' "$TMP_SCRIPT" \
    "installer cannot overwrite a user's automatic-suspend choice"
assert_grep_fixed 'HandleLidSwitch=lock' "$TMP_SCRIPT"
assert_grep_fixed 'HandleLidSwitchExternalPower=lock' "$TMP_SCRIPT"
assert_not_grep_extended 'crashes in the s2idle suspend path on Ampere/Ada|Xid 154' \
    "$TMP_SCRIPT" "installer contains no universal GPU/Xid claim"
# The helper explicitly requests only akmod + verification utilities and lets
# DNF resolve the branch's driver dependencies. Allow "-cuda", reject an
# unnecessary explicit bare-package request.
if grep -E 'dnf[[:space:]]+install[^#]*xorg-x11-drv-nvidia([^-]|$)' "$TMP_SCRIPT" >/dev/null 2>&1; then
    _fail "Stage 1 explicitly requests the bare xorg-x11-drv-nvidia package"
else
    _pass "Stage 1 leaves base-driver dependency resolution to DNF"
fi

# --- Kepler/Fermi refuse-path (outside maintained-driver policy) ----------
assert_grep_fixed 'REFUSING TO INSTALL' "$TMP_SCRIPT"
assert_grep_fixed 'outside this image' "$TMP_SCRIPT"

# --- MOK import + complete 6-step blue-screen walkthrough -----------------
assert_grep_fixed 'kmodgenca -a' "$TMP_SCRIPT"
assert_grep_fixed 'mokutil --import /etc/pki/akmods/certs/public_key.der' "$TMP_SCRIPT"
assert_grep_fixed 'Perform MOK management' "$TMP_SCRIPT"
assert_grep_fixed 'Enroll MOK' "$TMP_SCRIPT"
assert_grep_fixed 'Continue boot' "$TMP_SCRIPT"   # the DEFAULT button to AVOID
assert_grep_fixed 'View key 0' "$TMP_SCRIPT"
assert_grep_fixed 'Enroll the key(s)' "$TMP_SCRIPT"
assert_grep_fixed 'Arrow-select "Continue"' "$TMP_SCRIPT" \
    "MOK walkthrough carries the Continue selection step"
assert_grep_fixed 'Enter the MOK password you set above' "$TMP_SCRIPT" \
    "MOK walkthrough carries the password-entry step"
assert_grep_fixed 'Select "Reboot"' "$TMP_SCRIPT" \
    "MOK walkthrough carries the final reboot selection"

# --- Post-reboot verification commands ------------------------------------
assert_grep_fixed 'sudo mokutil --test-key /etc/pki/akmods/certs/public_key.der' "$TMP_SCRIPT"
assert_grep_fixed 'lsmod | grep nvidia' "$TMP_SCRIPT"

# --- Boot-ID-bound automatic initial-activation verification ---------------
assert_grep_fixed 'prepared_boot_id=$(cat /proc/sys/kernel/random/boot_id)' \
    "$TMP_SCRIPT" "pre-reboot evidence records the exact preparation boot"
assert_grep_fixed "printf 'prepared_boot_id=%s\\n' \"\$prepared_boot_id\"" \
    "$TMP_SCRIPT" "prepared record carries the boot-boundary field"
assert_grep_fixed '[ "${#record[@]}" -eq 9 ]' "$TMP_POSTBOOT" \
    "post-boot verifier accepts only the exact nine-line evidence schema"
assert_grep_fixed '[ "$boot_id" != "$prepared_boot_id" ]' "$TMP_POSTBOOT" \
    "post-boot verifier requires a real reboot boundary"
assert_grep_fixed 'verify_output=$("$VERIFY" "$KVER" 2>&1)' \
    "$TMP_POSTBOOT" "post-boot verifier reuses exact signed-module identity"
assert_not_grep '--require-enrolled' "$TMP_POSTBOOT" \
    "post-boot sandbox never grants CAP_SYS_ADMIN merely to re-read MokListRT"
assert_grep_fixed '[ "$(<"$MODULE_SIG_ENFORCE")" = Y ]' "$TMP_POSTBOOT" \
    "runtime verification requires kernel signature enforcement"
assert_grep_fixed 'for module in nvidia nvidia_modeset nvidia_drm nvidia_uvm; do' \
    "$TMP_POSTBOOT" "post-boot gate covers the exact four NVIDIA modules"
assert_grep_fixed '[ "$live_version" = "$disk_version" ]' "$TMP_POSTBOOT" \
    "post-boot gate binds every loaded module to the verified disk version"
assert_grep_fixed '[ "$live_srcversion" = "$disk_srcversion" ]' "$TMP_POSTBOOT" \
    "post-boot gate binds every loaded module to the verified disk srcversion"
assert_grep_fixed 'cmp -s -- "$live_build_id" "$disk_build_id"' \
    "$TMP_POSTBOOT" \
    "post-boot gate binds every loaded module to its exact disk GNU build ID"
assert_grep_fixed "printf 'runtime_signed_module_chain=verified\\n'" \
    "$TMP_POSTBOOT" \
    "active evidence records the verified runtime signed-module chain"
assert_grep_fixed 'for conflicting in nouveau nova_core; do' "$TMP_POSTBOOT" \
    "post-boot gate rejects conflicting in-tree drivers"
assert_grep_fixed '[ "$smi_set" = "$sysfs_set" ]' "$TMP_POSTBOOT" \
    "unprivileged nvidia-smi devices must equal NVIDIA-bound PCI devices"
assert_grep_fixed '0000????:??:??.?) normalized_bdf=${raw_bdf:4}' \
    "$TMP_POSTBOOT" \
    "post-boot gate normalizes nvidia-smi's eight-digit PCI domain"
assert_grep_fixed 'ConditionPathExistsGlob=/var/lib/noid-nvidia-integrity/*.prepared' \
    "$TMP_POSTBOOT_UNIT" "completed systems skip the initial-activation unit silently"
assert_grep_fixed 'TimeoutStartSec=3min' "$TMP_POSTBOOT_UNIT" \
    "post-boot lock/verification window is bounded without the tested two-minute race"
assert_grep_fixed 'CapabilityBoundingSet=CAP_SETUID CAP_SETGID' "$TMP_POSTBOOT_UNIT" \
    "post-boot service keeps only capabilities needed for the nobody probe"
assert_not_grep 'CAP_SYS_ADMIN' "$TMP_POSTBOOT_UNIT" \
    "post-boot service does not gain the broad firmware-variable read capability"
assert_grep_fixed 'NoNewPrivileges=yes' "$TMP_POSTBOOT_UNIT"
assert_grep_fixed 'PrivateNetwork=yes' "$TMP_POSTBOOT_UNIT"
assert_grep_fixed 'ReadWritePaths=-/var/lib/noid-nvidia-integrity /run/lock' \
    "$TMP_POSTBOOT_UNIT" "post-boot verifier can mutate only evidence and its lock"
assert_grep_fixed 'systemctl enable noid-nvidia-initramfs-resume.service' "$TMP_SCRIPT"
assert_grep_fixed 'noid-nvidia-postboot-verify.service' "$TMP_SCRIPT"
assert_grep_fixed 'rm -f /usr/libexec/noid-nvidia-postboot-verify' "$TMP_SCRIPT"
assert_grep_fixed 'rm -f /etc/systemd/system/noid-nvidia-postboot-verify.service' \
    "$TMP_SCRIPT"

# Execute the verifier against a synthetic sysfs/boot/state tree. The success
# case proves promotion only after a different boot ID; the negative case
# proves a same-boot invocation remains fail-closed and leaves durable evidence.
POSTBOOT_ROOT="$FIXTURE_DIR/postboot-root"
POSTBOOT_KVER=fixture-kernel
POSTBOOT_OWNER="$(id -un):$(id -gn)"
install -d -m 0755 \
    "$POSTBOOT_ROOT/var/lib/noid-nvidia-integrity" \
    "$POSTBOOT_ROOT/boot" \
    "$POSTBOOT_ROOT/proc/sys/kernel/random" \
    "$POSTBOOT_ROOT/run/lock" \
    "$POSTBOOT_ROOT/sys/module/module/parameters" \
    "$POSTBOOT_ROOT/sys/module/nvidia/notes" \
    "$POSTBOOT_ROOT/sys/module/nvidia_modeset/notes" \
    "$POSTBOOT_ROOT/sys/module/nvidia_drm/notes" \
    "$POSTBOOT_ROOT/sys/module/nvidia_uvm/notes" \
    "$POSTBOOT_ROOT/sys/bus/pci/devices/0000:01:00.0" \
    "$POSTBOOT_ROOT/sys/bus/pci/drivers/nvidia"
printf '%s\n' fixture-initramfs >"$POSTBOOT_ROOT/boot/initramfs-${POSTBOOT_KVER}.img"
POSTBOOT_IMAGE_HASH=$(sha256sum "$POSTBOOT_ROOT/boot/initramfs-${POSTBOOT_KVER}.img" \
    | awk '{print $1}')
POSTBOOT_PREPARED_ID=11111111-1111-1111-1111-111111111111
POSTBOOT_RUNNING_ID=22222222-2222-2222-2222-222222222222
printf '%s\n' "$POSTBOOT_RUNNING_ID" \
    >"$POSTBOOT_ROOT/proc/sys/kernel/random/boot_id"
printf '%s\n' Y >"$POSTBOOT_ROOT/sys/module/module/parameters/sig_enforce"
for postboot_module in nvidia nvidia_modeset nvidia_drm nvidia_uvm; do
    printf '%s\n' fixture-version \
        >"$POSTBOOT_ROOT/sys/module/$postboot_module/version"
    printf '%s\n' fixture-srcversion \
        >"$POSTBOOT_ROOT/sys/module/$postboot_module/srcversion"
    printf '%s\n' "fixture-build-id-$postboot_module" \
        >"$POSTBOOT_ROOT/sys/module/$postboot_module/notes/.note.gnu.build-id"
    printf '%s\n' "fixture-build-id-$postboot_module" \
        >"$FIXTURE_DIR/$postboot_module.ko"
done
printf '%s\n' 0x10de >"$POSTBOOT_ROOT/sys/bus/pci/devices/0000:01:00.0/vendor"
printf '%s\n' 0x030200 >"$POSTBOOT_ROOT/sys/bus/pci/devices/0000:01:00.0/class"
ln -s "$POSTBOOT_ROOT/sys/bus/pci/drivers/nvidia" \
    "$POSTBOOT_ROOT/sys/bus/pci/devices/0000:01:00.0/driver"
: >"$POSTBOOT_ROOT/run/lock/noid-boot-mutation.lock"
cat >"$FIXTURE_DIR/postboot-guard" <<'POSTBOOT_GUARD_FIXTURE_EOF'
#!/bin/bash
printf '%s\n' basis=hostonly
POSTBOOT_GUARD_FIXTURE_EOF
cat >"$FIXTURE_DIR/postboot-verify" <<'POSTBOOT_VERIFY_FIXTURE_EOF'
#!/bin/bash
[ "$#" -eq 1 ] || exit 73
printf '%s\n' \
    branch=main \
    kernel=fixture-kernel \
    evr=3:fixture-1.fc44 \
    modules=verified \
    certificate=matched
POSTBOOT_VERIFY_FIXTURE_EOF
cat >"$FIXTURE_DIR/postboot-modinfo" <<'POSTBOOT_MODINFO_FIXTURE_EOF'
#!/bin/bash
[ "$#" -eq 5 ] && [ "$1" = -F ] && [ "$4" = -k ] \
    && [ "$5" = fixture-kernel ] || exit 74
case "$3" in nvidia|nvidia_modeset|nvidia_drm|nvidia_uvm) ;; *) exit 75 ;; esac
case "$2" in
    version) printf '%s\n' fixture-version ;;
    srcversion) printf '%s\n' fixture-srcversion ;;
    filename) printf '%s/%s.ko\n' "$POSTBOOT_FIXTURE_DIR" "$3" ;;
    *) exit 76 ;;
esac
POSTBOOT_MODINFO_FIXTURE_EOF
cat >"$FIXTURE_DIR/postboot-objcopy" <<'POSTBOOT_OBJCOPY_FIXTURE_EOF'
#!/bin/bash
[ "$#" -eq 3 ] && [ "$1" = --dump-section ] || exit 77
case "$2" in .note.gnu.build-id=*) output=${2#*=} ;; *) exit 78 ;; esac
cp -- "$3" "$output"
POSTBOOT_OBJCOPY_FIXTURE_EOF
cat >"$FIXTURE_DIR/postboot-smi" <<'POSTBOOT_SMI_FIXTURE_EOF'
#!/bin/bash
printf '%s\n' 00000000:01:00.0
POSTBOOT_SMI_FIXTURE_EOF
chmod 0755 "$FIXTURE_DIR/postboot-guard" "$FIXTURE_DIR/postboot-verify" \
    "$FIXTURE_DIR/postboot-modinfo" "$FIXTURE_DIR/postboot-objcopy" \
    "$FIXTURE_DIR/postboot-smi"

write_postboot_prepared() {
    local prepared_id=$1
    cat >"$POSTBOOT_ROOT/var/lib/noid-nvidia-integrity/${POSTBOOT_KVER}.prepared" <<POSTBOOT_RECORD_EOF
status=prepared-awaiting-reboot-validation
branch=main
kernel=${POSTBOOT_KVER}
evr=3:fixture-1.fc44
modules=verified
certificate=matched
initramfs_sha256=${POSTBOOT_IMAGE_HASH}
prepared_boot_id=${prepared_id}
mok=enrolled
POSTBOOT_RECORD_EOF
    chmod 0600 "$POSTBOOT_ROOT/var/lib/noid-nvidia-integrity/${POSTBOOT_KVER}.prepared"
}

run_postboot_fixture() {
    env NOID_TEST_MODE=1 \
        NOID_TEST_ROOT="$POSTBOOT_ROOT" \
        NOID_TEST_KERNEL="$POSTBOOT_KVER" \
        NOID_TEST_OWNER="$POSTBOOT_OWNER" \
        NOID_TEST_VERIFY="$FIXTURE_DIR/postboot-verify" \
        NOID_TEST_MODINFO="$FIXTURE_DIR/postboot-modinfo" \
        NOID_TEST_OBJCOPY="$FIXTURE_DIR/postboot-objcopy" \
        NOID_TEST_NVIDIA_SMI="$FIXTURE_DIR/postboot-smi" \
        NOID_TEST_BOOT_GUARD="$FIXTURE_DIR/postboot-guard" \
        POSTBOOT_FIXTURE_DIR="$FIXTURE_DIR" \
        bash "$TMP_POSTBOOT"
}

write_postboot_prepared "$POSTBOOT_PREPARED_ID"
assert_cmd_success "post-boot fixture promotes a different-boot activation" \
    run_postboot_fixture
assert_file_exists \
    "$POSTBOOT_ROOT/var/lib/noid-nvidia-integrity/${POSTBOOT_KVER}.active" \
    "post-boot success publishes active evidence"
assert_cmd_failure "post-boot success consumes prepared evidence" \
    test -e "$POSTBOOT_ROOT/var/lib/noid-nvidia-integrity/${POSTBOOT_KVER}.prepared"
assert_grep_fixed 'kernel_signature_enforcement=verified' \
    "$POSTBOOT_ROOT/var/lib/noid-nvidia-integrity/${POSTBOOT_KVER}.active"
assert_grep_fixed 'loaded_module_identity=verified' \
    "$POSTBOOT_ROOT/var/lib/noid-nvidia-integrity/${POSTBOOT_KVER}.active"
assert_grep_fixed 'runtime_signed_module_chain=verified' \
    "$POSTBOOT_ROOT/var/lib/noid-nvidia-integrity/${POSTBOOT_KVER}.active"

write_postboot_prepared "$POSTBOOT_RUNNING_ID"
assert_cmd_failure "same-boot fixture cannot claim post-reboot activation" \
    run_postboot_fixture
assert_file_exists \
    "$POSTBOOT_ROOT/var/lib/noid-nvidia-integrity/${POSTBOOT_KVER}.prepared" \
    "failed same-boot validation preserves prepared evidence"
assert_grep_fixed 'reason=NVIDIA path has not crossed the required reboot boundary' \
    "$POSTBOOT_ROOT/var/lib/noid-nvidia-integrity/degraded"

write_postboot_prepared "$POSTBOOT_PREPARED_ID"
printf '%s\n' mismatched-srcversion \
    >"$POSTBOOT_ROOT/sys/module/nvidia_drm/srcversion"
assert_cmd_failure "different loaded module identity cannot become active" \
    run_postboot_fixture
assert_grep_fixed \
    'reason=loaded/on-disk module identity differs for nvidia_drm' \
    "$POSTBOOT_ROOT/var/lib/noid-nvidia-integrity/degraded"
printf '%s\n' fixture-srcversion \
    >"$POSTBOOT_ROOT/sys/module/nvidia_drm/srcversion"

write_postboot_prepared "$POSTBOOT_PREPARED_ID"
printf '%s\n' mismatched-build-id \
    >"$POSTBOOT_ROOT/sys/module/nvidia_drm/notes/.note.gnu.build-id"
assert_cmd_failure "different loaded GNU build ID cannot become active" \
    run_postboot_fixture
assert_grep_fixed \
    'reason=loaded/on-disk GNU build ID differs for nvidia_drm' \
    "$POSTBOOT_ROOT/var/lib/noid-nvidia-integrity/degraded"
printf '%s\n' fixture-build-id-nvidia_drm \
    >"$POSTBOOT_ROOT/sys/module/nvidia_drm/notes/.note.gnu.build-id"

# The MOK result completes the reboot-ready record through a same-directory
# candidate and atomic rename. Appending directly could expose a torn nine-line
# schema across an interrupted write or immediate reboot.
assert_grep_fixed 'prepared_final=$(sudo mktemp "$NVIDIA_STATE_DIR/.prepared-final.XXXXXX")' \
    "$TMP_SCRIPT" "MOK evidence gets a private same-directory candidate"
assert_grep_fixed 'NR == 9 && $0 == expected {last_ok=1}' "$TMP_SCRIPT" \
    "MOK evidence candidate must have the exact final schema"
assert_grep_fixed 'sudo mv -fT -- "$prepared_final" "$prepared_record"' \
    "$TMP_SCRIPT" "MOK evidence is published atomically"
assert_grep_fixed 'sudo sync -- "$prepared_record"' "$TMP_SCRIPT" \
    "published MOK evidence is durable before reboot is offered"
assert_not_grep 'tee -a "$NVIDIA_STATE_DIR/${kver}.prepared"' "$TMP_SCRIPT" \
    "MOK evidence is never completed by an in-place append"

# --- Black-screen recovery path (Ctrl+Alt+F3 + rollback) ------------------
assert_grep_fixed 'Ctrl+Alt+F3' "$TMP_SCRIPT"
assert_grep_fixed '--rollback' "$TMP_SCRIPT"

# --- Rollback mode: remove owned state without deleting independent config --
assert_grep_fixed '/etc/modprobe.d/nvidia.conf' "$TMP_SCRIPT"
assert_grep_fixed '/etc/modprobe.d/blacklist-nouveau.conf' "$TMP_SCRIPT"
assert_grep_fixed 'rollback found NVIDIA configuration not owned by NoID Privacy' \
    "$TMP_SCRIPT" "rollback refuses independent NVIDIA configuration before mutation"
assert_not_grep 'sudo rm -f /etc/modprobe.d/nvidia.conf' "$TMP_SCRIPT" \
    "rollback never deletes an independent nvidia.conf"
assert_not_grep 'sudo rm -f /etc/modprobe.d/blacklist-nouveau.conf' "$TMP_SCRIPT" \
    "rollback never deletes an independent nouveau blacklist"
assert_not_grep 'sudo rm -f /etc/dracut.conf.d/nvidia.conf' "$TMP_SCRIPT" \
    "rollback never deletes an independent dracut policy"
assert_grep_fixed '/usr/libexec/noid-dracut-regenerate-all' "$TMP_SCRIPT" \
    "rollback uses M21's canonical regenerator"
assert_not_grep_extended '^[[:space:]]*(sudo[[:space:]]+)?dracut[[:space:]]' "$TMP_SCRIPT" \
    "M19 contains no independent installed-host Dracut writer"

# --- exact, branch-scoped akmods install/rebuild state machine -------------
assert_grep_fixed 'AKMOD_NAME="${AKMOD_PKG#akmod-}"' "$TMP_SCRIPT" \
    "interactive installer derives the selected akmod name"
assert_eq 2 "$(grep -c '^exact_kmod_repair_mode() {' "$TMP_SCRIPT")" \
    "interactive and background paths each carry the exact kmod state classifier"
assert_grep_fixed '1:0) akmod_name=nvidia ;;' "$TMP_REBUILD" \
    "background worker selects only the installed main branch"
assert_grep_fixed '0:1) akmod_name=nvidia-580xx ;;' "$TMP_REBUILD" \
    "background worker selects only the installed legacy branch"
assert_grep_fixed 'akmods --force --kernels "$kver" --akmod "$akmod_name"' \
    "$TMP_REBUILD" "missing background kmod uses install semantics, never reinstall"
assert_grep_fixed 'akmods --rebuild --force --kernels "$kver" --akmod "$akmod_name"' \
    "$TMP_REBUILD" "failed prebuilt integrity receives one exact repair rebuild"
assert_grep_fixed 'rpm -q "$exact_kmod" >/dev/null 2>&1' "$TMP_REBUILD" \
    "background worker requires the exact generated kmod RPM postcondition"
assert_grep_fixed 'run_system_root /usr/bin/akmods --force' "$TMP_SCRIPT" \
    "interactive missing-kmod repair uses install semantics"
assert_grep_fixed 'run_system_root /usr/bin/akmods --rebuild --force' \
    "$TMP_SCRIPT" "interactive installed-kmod repair uses reinstall semantics"
assert_grep_fixed 'starting one serialized repair build.' "$TMP_SCRIPT" \
    "interactive status text covers both install and reinstall repair modes"
assert_not_grep_fixed 'starting one serialized repair rebuild.' "$TMP_SCRIPT" \
    "interactive status text does not mislabel missing-kmod installation"
assert_grep_fixed 'sudo rpm -q "$exact_kmod" >/dev/null 2>&1' "$TMP_SCRIPT" \
    "interactive repair requires the exact generated kmod RPM postcondition"
assert_cmd_success "unreadable RPM repair inventory preserves its diagnostic" \
    python3 - "$TMP_SCRIPT" <<'PY'
import sys

text = open(sys.argv[1], encoding='utf-8').read()
repair = text.index('repair_mode=$(exact_kmod_repair_mode "$exact_kmod" sudo rpm)')
init = text.rfind("verify_output=''", 0, repair)
message = text.index(
    "verify_output='RPM inventory is unreadable; refusing to guess install versus reinstall semantics.'",
    repair)
end = text.index('\nfi\nif [ "$akmods_rc" -ne 0 ]', message)
assert init != -1 and init < repair < message
assert "verify_output=''" not in text[message:end]
assert "printf '  verifier: %s\\n' \"$verify_output\"" in text[end:]
PY
assert_grep_fixed 'umask 022' "$TMP_REBUILD" \
    "background akmods worker generates public system metadata"
system_root_calls=$(grep -Ec 'run_system_root /usr/bin/(env|dnf|akmods|depmod)' \
    "$TMP_SCRIPT")
assert_eq 8 "$system_root_calls" \
    "every interactive DNF, akmods and depmod operation uses the scoped wrapper"
assert_not_grep_extended '^[[:space:]]*(if ! )?sudo[[:space:]]+(dnf|akmods|depmod)([[:space:]]|$)' \
    "$TMP_SCRIPT" "no interactive system-metadata mutator inherits umask 0027"
for state_script in "$TMP_SCRIPT" "$TMP_REBUILD"; do
    state_function=$(mktemp)
    sed -n '/^exact_kmod_repair_mode() {$/,/^}$/p' "$state_script" \
        > "$state_function"
    assert_cmd_success "missing exact kmod selects install semantics" \
        bash -c '
            rpm() { [ "$1" = -qa ]; }
            . "$1"
            [ "$(exact_kmod_repair_mode fixture-kmod rpm)" = install ]
        ' _ "$state_function"
    assert_cmd_success "installed exact kmod selects rebuild semantics" \
        bash -c '
            rpm() { return 0; }
            . "$1"
            [ "$(exact_kmod_repair_mode fixture-kmod rpm)" = rebuild ]
        ' _ "$state_function"
    assert_cmd_failure "unreadable RPM inventory never degrades to install semantics" \
        bash -c '
            rpm() { return 1; }
            . "$1"
            exact_kmod_repair_mode fixture-kmod rpm
        ' _ "$state_function"
    rm -f "$state_function"
done
assert_grep_fixed 'noid-snap-pre "NVIDIA proprietary driver install' "$TMP_SCRIPT" \
    "install requires a pre-change snapshot"
assert_grep_fixed 'noid-snap-pre "NVIDIA proprietary driver rollback"' "$TMP_SCRIPT" \
    "rollback requires a pre-change snapshot"
assert_not_grep 'rpmfusion-nonfree-nvidia-driver\.repo.*[|][|][[:space:]]*true' "$TMP_SCRIPT" \
    "NVIDIA repository enable failure is not swallowed"
assert_grep_fixed 'verify_nvidia_repo_state "$expected"' "$TMP_SCRIPT" \
    "branch-specific NVIDIA repository state has an exact postcondition"
assert_grep_fixed 'section_count[debug] != 1' "$TMP_SCRIPT" \
    "repository validation rejects duplicate or missing debug sections"
assert_grep_fixed 'key_value[source, "enabled"] != "0"' "$TMP_SCRIPT" \
    "repository validation keeps source and debug repositories disabled"
assert_grep_fixed 'key_value[current, "gpgcheck"] != "1"' "$TMP_SCRIPT" \
    "repository validation requires package-signature enforcement in every section"
assert_grep_fixed 'active_lines != 18' "$TMP_SCRIPT" \
    "repository validation rejects unknown active options"
assert_grep_fixed 'could not restore the NVIDIA repository privacy default' "$TMP_SCRIPT" \
    "rollback treats repository privacy convergence as fatal"
assert_grep_fixed 'reconcile_firstboot_cmdline_evidence "incomplete NVIDIA rollback"' \
    "$TMP_SCRIPT" "post-transaction inventory failure still closes M01 evidence"
assert_grep_fixed '/usr/libexec/noid-firstboot-cmdline-transition' "$TMP_SCRIPT" \
    "NVIDIA install and rollback use M01's evidence transaction"
assert_grep_fixed 'left ambiguous firstboot command-line evidence' "$TMP_SCRIPT" \
    "NVIDIA transitions require exactly one terminal M01 evidence object"
assert_not_grep 'reconcile_firstboot_cmdline_evidence .*|| true' "$TMP_SCRIPT" \
    "failed M01 evidence reconciliation is never swallowed"

install_open_line=$(grep -nF -- '--invalidate-nvidia-install' "$TMP_SCRIPT" | cut -d: -f1 || true)
install_dnf_line=$(grep -nF 'install -y "$AKMOD_PKG" "$CUDA_PKG" || driver_dnf_rc=$?' \
    "$TMP_SCRIPT" | cut -d: -f1 || true)
install_close_line=$(grep -nF 'reconcile_firstboot_cmdline_evidence "$driver_context"' \
    "$TMP_SCRIPT" | cut -d: -f1 || true)
rollback_open_line=$(grep -nF -- '--invalidate-nvidia-rollback' "$TMP_SCRIPT" | cut -d: -f1 || true)
rollback_dnf_line=$(grep -nF 'run_system_root /usr/bin/dnf remove -y "${nvidia_rpms[@]}"' \
    "$TMP_SCRIPT" | cut -d: -f1 || true)
rollback_canonical_line=$(grep -nF 'sudo /usr/libexec/noid-canonicalize-kernel-cmdline --publish' \
    "$TMP_SCRIPT" | cut -d: -f1 || true)
rollback_close_line=$(grep -nF 'reconcile_firstboot_cmdline_evidence "NVIDIA rollback"' \
    "$TMP_SCRIPT" | cut -d: -f1 || true)
rollback_dracut_evidence_line=$(grep -nF 'sudo -C 8 /usr/libexec/noid-dracut-regenerate-all' \
    "$TMP_SCRIPT" | head -1 | cut -d: -f1 || true)
if [ -n "$install_open_line" ] && [ -n "$install_dnf_line" ] \
        && [ -n "$install_close_line" ] \
        && [ "$install_open_line" -lt "$install_dnf_line" ] \
        && [ "$install_dnf_line" -lt "$install_close_line" ]; then
    _pass "NVIDIA install opens and reseals M01 evidence around its RPM mutation"
else
    _fail "NVIDIA install M01 evidence transaction ordering differs"
fi
if [ -n "$rollback_open_line" ] && [ -n "$rollback_dnf_line" ] \
        && [ -n "$rollback_canonical_line" ] && [ -n "$rollback_close_line" ] \
        && [ -n "$rollback_dracut_evidence_line" ] \
        && [ "$rollback_open_line" -lt "$rollback_dnf_line" ] \
        && [ "$rollback_dnf_line" -lt "$rollback_canonical_line" ] \
        && [ "$rollback_canonical_line" -lt "$rollback_close_line" ] \
        && [ "$rollback_close_line" -lt "$rollback_dracut_evidence_line" ]; then
    _pass "NVIDIA rollback converges and reseals M01 evidence before initramfs"
else
    _fail "NVIDIA rollback M01 evidence transaction ordering differs"
fi

# --- Phase 4 verify block covers the new install script -------------------
assert_grep_fixed '[ -x /usr/local/bin/noid-nvidia-install.sh ]' "$KS_FILE"
assert_grep_fixed 'noid-nvidia-install.sh syntax' "$KS_FILE"

# --- Phase 3c header present -----------------------------------------------
assert_grep_fixed 'Phase 3c' "$KS_FILE"

# --- mixed-generation multi-NVIDIA detection -----------------------
# detect_nvidia_gpu must enumerate ALL NVIDIA GPUs and expose prefixes+count
# so we can bail out cleanly on mixed mainline + 580xx setups.
assert_grep_fixed 'DETECTED_ALL_PREFIXES' "$TMP_SCRIPT"
assert_grep_fixed 'DETECTED_NVIDIA_COUNT' "$TMP_SCRIPT"
assert_grep_fixed 'MIXED NVIDIA GENERATIONS DETECTED' "$TMP_SCRIPT"
# The mixed-branch error path itself names both reviewed overrides.
sed -n '/MIXED NVIDIA GENERATIONS DETECTED/,/return 1/p' \
    "$TMP_SCRIPT" > "$FIXTURE_DIR/mixed-generation-branch.sh"
assert_grep_fixed '--force-branch=main' "$FIXTURE_DIR/mixed-generation-branch.sh"
assert_grep_fixed '--force-branch=580xx' "$FIXTURE_DIR/mixed-generation-branch.sh"
assert_grep_fixed 'has_refuse=0' "$TMP_SCRIPT" \
    "multi-GPU classification tracks unsupported generations"
assert_grep_fixed 'has_unknown=0' "$TMP_SCRIPT" \
    "multi-GPU classification tracks unknown generations"
assert_grep_fixed 'while IFS= read -r gpu_line; do' "$TMP_SCRIPT" \
    "multi-GPU classification processes every display adapter independently"
assert_grep_fixed 'classified_count=$((classified_count + 1))' "$TMP_SCRIPT"
assert_grep_fixed 'unknown_count=$((unknown_count + 1))' "$TMP_SCRIPT"
assert_not_grep 'DETECTED_NVIDIA_COUNT - n_prefixes' "$TMP_SCRIPT" \
    "unique-prefix arithmetic cannot reclassify duplicate adapters as unknown"
assert_grep_fixed '&& [ -z "$FORCE_BRANCH" ]; then' "$TMP_SCRIPT" \
    "documented branch override bypasses only the mixed/unknown auto-selection bail-out"
refuse_line=$(grep -n '^# --- REFUSE PATH for Kepler/Fermi' "$TMP_SCRIPT" | cut -d: -f1 || true)
override_line=$(grep -n '^# --- Branch override' "$TMP_SCRIPT" | cut -d: -f1 || true)
unknown_line=$(grep -n '^# --- REFUSE PATH for unknown codename' "$TMP_SCRIPT" | cut -d: -f1 || true)
if [ -n "$refuse_line" ] && [ -n "$override_line" ] && [ -n "$unknown_line" ] \
        && [ "$refuse_line" -lt "$override_line" ] \
        && [ "$override_line" -lt "$unknown_line" ]; then
    _pass "force-branch applies after the non-overridable EOL gate and before UNKNOWN"
else
    _fail "force-branch ordering does not implement the advertised escape hatch"
fi
assert_grep_fixed 'no automatic nouveau fallback is promised' "$TMP_SCRIPT" \
    "mixed-branch warning does not promise an impossible fallback"

# Execute the sudo-free dry-run against synthetic lspci matrices. These cases
# validate adapter counts and branch families rather than merely grepping code.
run_gpu_fixture() {
    local name="$1" expected_rc="$2" expected_text="$3" payload="$4" output rc
    shift 4
    set +e
    output=$(printf 'n\n' | env TERM=dumb PATH="$FIXTURE_DIR:$PATH" \
        NOID_LSPCI_FIXTURE="$payload" bash "$TMP_SCRIPT" --dry-run "$@" 2>&1)
    rc=$?
    set -e
    if [ "$rc" -eq "$expected_rc" ] && grep -qF "$expected_text" <<<"$output"; then
        _pass "GPU fixture: $name"
    else
        _fail "GPU fixture: $name (rc=$rc, expected=$expected_rc, missing: $expected_text)"
    fi
}

ga_line='01:00.0 VGA compatible controller [0300]: NVIDIA Corporation GA107 [GeForce RTX] [10de:25a2]'
ga_line_2='02:00.0 3D controller [0302]: NVIDIA Corporation GA107 [GeForce RTX] [10de:25a2]'
gb_line='01:00.0 VGA compatible controller [0300]: NVIDIA Corporation GB202 [GeForce RTX] [10de:2b85]'
ad_line='01:00.0 3D controller [0302]: NVIDIA Corporation AD107GLM [RTX Ada] [10de:28ba]'
tu_line='02:00.0 3D controller [0302]: NVIDIA Corporation TU116 [GeForce GTX] [10de:2184]'
gp_line='03:00.0 VGA compatible controller [0300]: NVIDIA Corporation GP104 [GeForce GTX] [10de:1b80]'
gk_line='04:00.0 VGA compatible controller [0300]: NVIDIA Corporation GK104 [GeForce GTX] [10de:1180]'
unknown_line='05:00.0 3D controller [0302]: NVIDIA Corporation Device [10de:9999]'
audio_line='01:00.1 Audio device [0403]: NVIDIA Corporation HDMI Audio [10de:228b]'

run_gpu_fixture duplicate-prefix-main 0 'all mainline-compatible' "$ga_line"$'\n'"$ga_line_2"
run_gpu_fixture distinct-prefix-same-family 0 'all mainline-compatible' "$ga_line"$'\n'"$tu_line"
run_gpu_fixture multiword-generation-display 0 'Generation: Ada Lovelace (2022)' "$ad_line"
run_gpu_fixture duplicate-prefix-legacy 0 'xorg-x11-drv-nvidia-580xx-cuda' "$gp_line"$'\n'"${gp_line/03:00.0/04:00.0}"
run_gpu_fixture mixed-family 1 'MIXED NVIDIA GENERATIONS DETECTED' "$ga_line"$'\n'"$gp_line"
run_gpu_fixture unknown-secondary 1 'unknown codename' "$ga_line"$'\n'"$unknown_line"
run_gpu_fixture refused-secondary 1 'UNSUPPORTED NVIDIA GENERATION IN MULTI-GPU SYSTEM' "$ga_line"$'\n'"$gk_line"
run_gpu_fixture non-display-controller-ignored 0 'Packages: akmods akmod-nvidia xorg-x11-drv-nvidia-cuda' "$ga_line"$'\n'"$audio_line"
run_gpu_fixture single-main-rejects-legacy-force 1 \
    'refusing a known-incompatible driver plan' "$ga_line" --force-branch=580xx
run_gpu_fixture single-legacy-rejects-main-force 1 \
    'refusing a known-incompatible driver plan' "$gp_line" --force-branch=main
run_gpu_fixture uniform-main-rejects-legacy-force 1 \
    'refusing a known-incompatible driver plan' \
    "$ga_line"$'\n'"$ga_line_2" --force-branch=580xx
run_gpu_fixture mixed-family-allows-disclosed-force 0 \
    'Packages: akmods akmod-nvidia-580xx xorg-x11-drv-nvidia-580xx-cuda' \
    "$ga_line"$'\n'"$gp_line" --force-branch=580xx
run_gpu_fixture mixed-family-rejects-main-force 1 \
    'MAIN BRANCH CANNOT COVER THIS MIXED INVENTORY' \
    "$ga_line"$'\n'"$gp_line" --force-branch=main
run_gpu_fixture blackwell-legacy-refuses-auto 1 \
    'BLACKWELL + LEGACY MODULE-FLAVOR CONFLICT' \
    "$gb_line"$'\n'"$gp_line"
run_gpu_fixture blackwell-legacy-refuses-r580-force 1 \
    'BLACKWELL + LEGACY MODULE-FLAVOR CONFLICT' \
    "$gb_line"$'\n'"$gp_line" --force-branch=580xx
run_gpu_fixture legacy-unknown-rejects-main-force 1 \
    'MAIN BRANCH CANNOT COVER THIS MIXED INVENTORY' \
    "$gp_line"$'\n'"$unknown_line" --force-branch=main
run_gpu_fixture blackwell-unknown-rejects-r580-force 1 \
    'BLACKWELL CANNOT USE THE R580 OVERRIDE' \
    "$gb_line"$'\n'"$unknown_line" --force-branch=580xx
run_gpu_fixture unknown-allows-reviewed-force 0 \
    'Packages: akmods akmod-nvidia xorg-x11-drv-nvidia-cuda' \
    "$unknown_line" --force-branch=main

# --- Exact artifact verifier replaces path-exists/non-empty-signature guesses -
assert_grep_fixed '/usr/libexec/noid-nvidia-verify' "$TMP_SCRIPT"
assert_grep_fixed 'cert_serial=$(openssl x509 -inform DER' "$TMP_VERIFIER"
assert_grep_fixed 'module_sig_key' "$TMP_VERIFIER"
assert_grep_fixed '[ "$module_sig_key" = "$cert_serial" ]' "$TMP_VERIFIER"
assert_grep_fixed '[ "$owner_name" = "$expected_kmod" ]' "$TMP_VERIFIER"
assert_grep_fixed '[ "$owner_evr" = "$akmod_evr" ]' "$TMP_VERIFIER"
assert_grep_fixed '[ "$akmod_evr" = "$cuda_evr" ]' "$TMP_VERIFIER"
assert_grep_fixed 'modules=(nvidia nvidia_modeset nvidia_drm nvidia_uvm)' "$TMP_VERIFIER"
assert_grep_fixed "expected_module_license='Dual MIT/GPL'" "$TMP_VERIFIER" \
    "main branch requires NVIDIA's open-kernel-module flavor"
assert_grep_fixed "expected_module_license='NVIDIA'" "$TMP_VERIFIER" \
    "R580 branch requires NVIDIA's proprietary module flavor"
assert_grep_fixed '[ "$module_license" = "$expected_module_license" ]' \
    "$TMP_VERIFIER" "every module is bound to the selected branch flavor"
assert_grep_fixed '[ "$module_buildtime" -ge "$marker_mtime" ]' "$TMP_VERIFIER" \
    "freshness gate compares unclamped RPM BUILDTIME (installed file mtime is SOURCE_DATE_EPOCH-clamped)"
assert_grep_fixed '--newer-than "$build_marker" --require-enrolled' "$TMP_SCRIPT" \
    "background rebuild requires fresh modules and enrolled exact MOK"
assert_grep_fixed "grep -qF ' is already enrolled'" "$TMP_VERIFIER" \
    "verifier checks exact MOK enrollment result"
assert_grep_fixed "-name '*.failed.log'" "$TMP_SCRIPT"
assert_grep_fixed '/var/lib/noid-nvidia-integrity' "$TMP_SCRIPT"

# --- recovery instructions say "as your normal user" (not sudo) ----
assert_grep_fixed 'as your normal user (NOT root)' "$TMP_SCRIPT"

# --- akmods output NOT truncated via tail -5 -----------------------
assert_not_grep 'akmods --rebuild --force 2>&1 | tail -5' "$TMP_SCRIPT"

# --- fail-safe akmods build (pre-gate + authoritative verify) -
# Pre-build gate: the kernel-devel build tree must be readable by the akmods
# build user (catches missing kernel-devel OR a non-traversable /usr/src 0700).
assert_grep_fixed 'sudo -u akmods test -r "${BUILD_TREE}/Makefile"' "$TMP_SCRIPT" \
    "pre-build gate verifies akmods-user can read the build tree"
assert_grep_fixed 'sudo dnf install kernel-devel-${kver}' "$TMP_SCRIPT" \
    "missing kernel-devel actionable fix message"
# Authoritative post-build gate: exact module identity plus fresh failure-log
# detection — akmods can exit 0 on per-module build failure.
assert_grep_fixed 'modinfo -F filename "$module" -k "$kver"' "$TMP_VERIFIER" \
    "authoritative per-module identity gate"
assert_grep_fixed '[ "$akmods_rc" -ne 0 ] || [ -n "$new_failure_log" ]' "$TMP_SCRIPT" \
    "akmods rc and fresh failed.log are both fatal"
# Hard-exit on failure with DO-NOT-REBOOT (was: [warn] + continue → black screen).
assert_grep_fixed 'DO NOT REBOOT' "$TMP_SCRIPT" \
    "build failure warns DO NOT REBOOT (black-screen prevention)"
assert_grep_fixed 'sudo systemctl status akmods.service' "$TMP_SCRIPT"
# The initial image is delegated only after the exact module build succeeds.
assert_grep_fixed 'sudo -C 8 /usr/libexec/noid-dracut-regenerate-all' \
    "$TMP_SCRIPT" "sudo preserves the shared lock descriptor for the root helper"
assert_grep_fixed '--lock-held=7 --kernel="$kver"' \
    "$TMP_SCRIPT" "initial image inherits the exact shared-lock lease"
assert_grep_fixed '--allow-pending-mok' "$TMP_SCRIPT" \
    "only the pre-enrollment initial image uses the explicit pending-MOK exception"
# Rollback strips the RPM's nouveau-blacklist kernel args + clears failed.log.
assert_grep_fixed 'rd.driver.blacklist=nouveau modprobe.blacklist=nouveau nvidia-drm.modeset=1' "$TMP_SCRIPT" \
    "rollback removes RPM nouveau-blacklist kernel args"

# --- rollback disclaimer lists ALL removed packages ---------------
assert_grep_fixed 'akmod-nvidia*, kmod-nvidia*' "$TMP_SCRIPT" \
    "rollback disclaimer lists kmod-nvidia*"
assert_grep_fixed 'nvidia-settings, nvidia-persistenced' "$TMP_SCRIPT" \
    "rollback disclaimer lists nvidia-settings + nvidia-persistenced"

# --- NVIDIA early-KMS for LUKS-prompt visibility -----------
# Installer ships a dracut conf that ADDS nvidia to the initramfs so nvidia-drm
# re-renders the LUKS prompt after the simpledrm->KMS handover (display-on-dGPU).
assert_grep_fixed '/etc/dracut.conf.d/99-noid-nvidia-initramfs.conf' "$TMP_SCRIPT" \
    "installer creates the nvidia-initramfs dracut conf"
assert_grep_fixed 'add_drivers+=" nvidia nvidia_modeset nvidia_drm nvidia_uvm "' "$TMP_SCRIPT" \
    "dracut conf adds nvidia modules to initramfs"
# Kernel-install hook rebuilds new-kernel initramfs WITH nvidia (direct dnf path).
assert_grep_fixed '/etc/kernel/install.d/95-noid-nvidia-initramfs.install' "$TMP_SCRIPT" \
    "installer creates the kernel-install initramfs hook"
assert_grep_fixed "rpm_inventory=\$(rpm -qa --qf '%{NAME}\\n'" "$TMP_KINST" \
    "kernel-install hook uses one fail-closed RPM inventory query"
assert_grep_fixed 'RPM inventory query failed' "$TMP_KINST" \
    "kernel-install hook never treats rpmdb failure as no NVIDIA"
assert_grep_fixed "root:root:600" "$TMP_KINST" \
    "kernel-install skip marker requires exact root-owned private metadata"
# M21 performs image-content validation; M19 retains the exact module identity
# gate and refuses to approve a missing/unsafe published image.
assert_grep_fixed 'published-initramfs-missing-or-unsafe' "$TMP_SCRIPT" \
    "initial install refuses missing canonical publication"
assert_not_grep 'depmod -a.*[|][|][[:space:]]*true' "$TMP_SCRIPT" \
    "depmod failure is not swallowed"
assert_eq 1 "$(grep -cF '/usr/sbin/depmod -a "$kver"' \
    "$TMP_REBUILD" || true)" \
    "background worker has one canonical target-kernel index refresher"
assert_grep_fixed '[ "$depmod_rc" -eq 0 ] || _degraded "target depmod failed for ${kver}"' \
    "$TMP_REBUILD" \
    "target-kernel depmod failure keeps the reboot path fail-closed"
worker_akmods_gate_line=$(grep -nF \
    'akmods_failure_log=$(find /var/cache/akmods' \
    "$TMP_REBUILD" | head -n1 | cut -d: -f1)
worker_depmod_line=$(grep -nF 'refresh_target_index || depmod_rc=$?' \
    "$TMP_REBUILD" | head -n1 | cut -d: -f1)
worker_verify_line=$(grep -nF \
    $'verify_output=$(/usr/libexec/noid-nvidia-verify "$kver" \\' \
    "$TMP_REBUILD" | head -n1 | cut -d: -f1)
if [ "$worker_akmods_gate_line" -lt "$worker_depmod_line" ] \
        && [ "$worker_depmod_line" -lt "$worker_verify_line" ]; then
    _pass "target depmod runs after akmods gates and before module verification"
else
    _fail "target depmod runs after akmods gates and before module verification"
fi
for nvidia_action_pkg in akmod-nvidia akmod-nvidia-580xx; do
    assert_grep_fixed \
        "post_transaction:${nvidia_action_pkg}:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/libexec/noid-nvidia-initramfs-dnf-action\\ >/dev/null" \
        "$TMP_SCRIPT" "${nvidia_action_pkg} host updates trigger initramfs rebuild"
done
assert_grep_fixed 'systemd-inhibit --what=shutdown:sleep' "$TMP_SCRIPT" \
    "pending rebuild holds a shutdown/sleep block inhibitor"
assert_grep_fixed 'Type=exec' "$TMP_GUARD_UNIT" \
    "guard tracks systemd-inhibit's successful exec"
assert_not_grep 'Type=notify' "$TMP_GUARD_UNIT" \
    "systemd-inhibit cannot strip the notification socket from a notify guard"
assert_not_grep 'systemd-notify' "$TMP_GUARD" \
    "guard never relies on notification state sanitized by systemd-inhibit"
assert_grep_fixed \
    'ExecStartPost=/usr/libexec/noid-nvidia-reboot-guard --verify-inhibitor $MAINPID' \
    "$TMP_GUARD_UNIT" \
    "synchronous start verifies the exact systemd-inhibit MainPID"
assert_grep_fixed 'org.freedesktop.login1.Manager ListInhibitors' "$TMP_GUARD" \
    "guard verifies its inhibitor through login1's maintained D-Bus API"
assert_grep_fixed '.type == "a(ssssuu)"' "$TMP_GUARD" \
    "login1 inhibitor response signature is pinned"
assert_grep_fixed '== ["shutdown", "sleep"]' "$TMP_GUARD" \
    "guard requires the complete shutdown and sleep scope"
assert_grep_fixed '.[1] == "NoID Privacy"' "$TMP_GUARD" \
    "guard requires its exact login1 identity"
assert_grep_fixed \
    '.[2] == "NVIDIA-module-and-initramfs-verification-pending"' \
    "$TMP_GUARD" "guard requires its exact login1 reason"
assert_grep_fixed '.[3] == "block"' "$TMP_GUARD" \
    "guard cannot accept a bounded delay inhibitor"
assert_grep_fixed '.[4] == 0' "$TMP_GUARD" \
    "guard requires a root-owned inhibitor"
assert_grep_fixed '.[5] == $pid' "$TMP_GUARD" \
    "guard rejects another process's inhibitor"
assert_grep_fixed 'kill -0 "$pid"' "$TMP_GUARD" \
    "guard rejects a stale inhibitor process identity"
assert_grep_fixed 'queue_dir="$state_dir/queue"' "$TMP_QUEUE" \
    "rebuild tasks have persistent queue state"
assert_grep_fixed 'systemd-run --no-block --collect' "$TMP_QUEUE" \
    "queue schedules uniquely named post-transaction workers"
assert_grep_fixed "''|[!A-Za-z0-9]*|*[!A-Za-z0-9._+-]*) return 1" \
    "$TMP_QUEUE" "queue rejects option-shaped kernel releases"
assert_grep_fixed '[ "$#" -eq 1 ] || exit 2' "$TMP_QUEUE" \
    "queue has an exact one-argument command contract"
assert_grep_fixed 'installed_kernel_is_valid "$kver" || exit 1' "$TMP_QUEUE" \
    "queue accepts only a present root-owned kernel payload"
assert_grep_fixed "[ \"\$metadata\" = '0:0:600:1' ] || return 1" \
    "$TMP_QUEUE" "resume accepts only exact root-owned marker metadata"
assert_grep_fixed 'source=post-transaction|source=manual-direct' "$TMP_QUEUE" \
    "resume accepts only the two producer-owned marker schemas"
assert_grep_fixed 'validate_resume_queue' "$TMP_QUEUE" \
    "resume validates every retained task before acquiring its inhibitor"
assert_grep_fixed 'sync -- "$marker"' "$TMP_QUEUE" \
    "queue syncs the durable marker before publishing its inhibitor"
for rejected_queue_argv in '--status' '--resume extra'; do
    read -r -a rejected_queue_args <<<"$rejected_queue_argv"
    queue_trace="$FIXTURE_DIR/queue-reject-${rejected_queue_argv//[^A-Za-z]/_}.trace"
    if bash -x "$TMP_QUEUE" "${rejected_queue_args[@]}" \
            >"$FIXTURE_DIR/queue-reject.out" 2>"$queue_trace"; then
        _fail "queue rejects unsupported argv before state publication: $rejected_queue_argv"
    else
        _pass "queue rejects unsupported argv before state publication: $rejected_queue_argv"
    fi
    assert_not_grep 'install -d -m 0755' "$queue_trace" \
        "rejected queue argv creates no state directory"
    assert_not_grep 'acquire_boot_mutation' "$queue_trace" \
        "rejected queue argv acquires no boot-mutation lease"
    assert_not_grep 'systemctl start noid-nvidia-reboot-guard.service' "$queue_trace" \
        "rejected queue argv publishes no reboot inhibitor"
done
assert_grep_fixed 'case "$#" in 1|2) ;; *) exit 2 ;; esac' "$TMP_REBUILD" \
    "worker accepts only direct or queued exact argument shapes"
assert_grep_fixed 'installed_kernel_is_valid "$kver" || exit 1' "$TMP_REBUILD" \
    "worker rejects nonexistent or unsafe kernel payloads before feedback"
assert_grep_fixed '[ "$marker_name" = "$marker_token.pending" ] || exit 1' \
    "$TMP_REBUILD" "worker confines a retained marker to one exact queue entry"
rebuild_trace="$FIXTURE_DIR/rebuild-reject-status.trace"
if bash -x "$TMP_REBUILD" --status \
        >"$FIXTURE_DIR/rebuild-reject.out" 2>"$rebuild_trace"; then
    _fail "worker rejects an option-shaped kernel release"
else
    _pass "worker rejects an option-shaped kernel release"
fi
assert_not_grep '_notify normal' "$rebuild_trace" \
    "rejected worker target emits no desktop notification"
assert_not_grep 'install -d -m 0755' "$rebuild_trace" \
    "rejected worker target creates no NVIDIA state"
assert_grep_fixed 'BOOT_MUTATION_LOCK=/run/lock/noid-boot-mutation.lock' "$TMP_SCRIPT" \
    "interactive install and rollback share the boot-mutation lock"
assert_grep_fixed 'sudo /usr/libexec/noid-boot-mutation-guard' "$TMP_SCRIPT" \
    "interactive install and rollback require a stable M21 basis"
assert_grep_fixed '/usr/local/bin/noid-nvidia-install.sh' "$TMP_DOC" \
    "installed NVIDIA guide uses the coordinated helper for BLS repair"
assert_grep_fixed 'Do not substitute a bare `grubby --update-kernel=ALL`' \
    "$TMP_DOC" "installed NVIDIA guide warns against bypassing M21"
assert_not_grep_extended '^[[:space:]]*sudo[[:space:]]+grubby[[:space:]]+--update-kernel=ALL' \
    "$TMP_DOC" "installed NVIDIA guide contains no executable bare BLS writer"
assert_grep_fixed 'exec 8>/run/lock/noid-boot-mutation.lock' "$TMP_REBUILD" \
    "background worker takes the shared boot-mutation lock"
assert_grep_fixed 'flock -n 8 || defer_for_m21' "$TMP_REBUILD" \
    "colliding worker defers immediately instead of inhibiting M21 reboot"
assert_not_grep_extended 'flock -w [0-9]+ 8' "$TMP_REBUILD" \
    "worker never waits on the global lock while its inhibitor is active"
shared_worker_line=$(grep -nF 'exec 8>/run/lock/noid-boot-mutation.lock' \
    "$TMP_REBUILD" | cut -d: -f1 || true)
nvidia_worker_line=$(grep -nF 'exec 9>/run/lock/noid-nvidia-initramfs.lock' \
    "$TMP_REBUILD" | cut -d: -f1 || true)
if [ -n "$shared_worker_line" ] && [ -n "$nvidia_worker_line" ] \
        && [ "$shared_worker_line" -lt "$nvidia_worker_line" ]; then
    _pass "NVIDIA worker takes the global lock before its narrower lock"
else
    _fail "NVIDIA worker lock order can deadlock"
fi
assert_grep_fixed 'mv -fT -- "$queued_marker" "$deferred_marker"' "$TMP_REBUILD" \
    "a collided worker becomes durable deferred work"
assert_grep_fixed 'for marker in "$queue_dir"/*.deferred; do' "$TMP_QUEUE" \
    "resume recognizes every durable deferred work item"
assert_grep_fixed 'sync -- "$pending"' "$TMP_QUEUE" \
    "deferred work promotion persists its renamed marker"
assert_grep_fixed 'Requires=noid-dracut-hostonly-firstboot.service' "$TMP_RESUME" \
    "NVIDIA boot resume requires M21 recovery/convergence first"
assert_grep_fixed 'After=local-fs.target noid-dracut-hostonly-firstboot.service' \
    "$TMP_RESUME" "NVIDIA boot resume is ordered after M21"
queue_guard_line=$(grep -nF 'acquire_boot_mutation' "$TMP_QUEUE" | tail -1 | cut -d: -f1 || true)
marker_line=$(grep -nF 'mv -fT -- "$marker_tmp" "$marker"' "$TMP_QUEUE" | cut -d: -f1 || true)
if [ -n "$queue_guard_line" ] && [ -n "$marker_line" ] \
        && [ "$queue_guard_line" -lt "$marker_line" ]; then
    _pass "normal NVIDIA queue guard precedes marker and inhibitor publication"
else
    _fail "normal NVIDIA queue can publish work before M21 is stable"
fi
assert_grep_fixed 'NVIDIA_INSTALL_MARKER=/run/noid-nvidia-install-running' "$TMP_SCRIPT" \
    "interactive DNF transaction has an exact recursion marker"
assert_grep_fixed 'managed_dnf_candidate=$(sudo mktemp' \
    "$TMP_SCRIPT" "interactive recursion marker starts as a private same-directory candidate"
assert_grep_fixed 'sudo mv -fT -- "$managed_dnf_candidate"' \
    "$TMP_SCRIPT" "interactive recursion marker publishes atomically"
assert_grep_fixed 'trap cleanup_runtime_artifacts EXIT' "$TMP_SCRIPT" \
    "one persistent EXIT cleanup covers every installer exit"
assert_grep_fixed 'sudo rm -f -- "$managed_dnf_candidate"' "$TMP_SCRIPT" \
    "signal cleanup removes an unpublished recursion-marker candidate"
assert_grep_fixed 'sudo rm -f -- "$prepared_candidate"' "$TMP_SCRIPT" \
    "signal cleanup removes an unpublished reboot-evidence candidate"
assert_not_grep 'trap .*sudo rm -f "\$build_marker".* EXIT' "$TMP_SCRIPT" \
    "build freshness handling never replaces the runtime-marker cleanup trap"
assert_grep_fixed 'managed NVIDIA DNF marker identity changed; refusing blind removal' \
    "$TMP_SCRIPT" "runtime marker cleanup is identity-bound"
assert_grep_fixed 'noid-nvidia-install-running' "$TMP_KINST" \
    "kernel hook skips the installer-owned synchronous transaction"
assert_grep_fixed 'noid-nvidia-install-running' "$TMP_DNFACTION" \
    "driver hook skips the installer-owned synchronous transaction"
assert_grep_fixed 'root:root:600' "$TMP_DNFACTION" \
    "driver hook trusts only the exact private recursion-marker metadata"
for update_consumer in "$TMP_REBUILD" "$TMP_KINST" "$TMP_DNFACTION"; do
    assert_grep_fixed '/usr/libexec/noid-update-window-active' "$update_consumer" \
        "NVIDIA update suppression requires M25's live process/lock proof"
    assert_not_grep '\[ -e /run/noid-update-running \]' "$update_consumer" \
        "stale update-marker existence cannot suppress an NVIDIA path"
done
assert_not_grep 'noid-nvidia-initramfs-drvupd' "$TMP_SCRIPT" \
    "fixed collision-prone driver-update unit name is absent"
assert_grep_fixed 'ConditionDirectoryNotEmpty=/var/lib/noid-nvidia-integrity/queue' "$TMP_SCRIPT" \
    "boot resumes power-loss-interrupted rebuild tasks"
assert_grep_fixed 'systemctl enable noid-nvidia-initramfs-resume.service' "$TMP_SCRIPT"
assert_not_grep 'system-update-pre.target system-update.target.*exit 0' "$TMP_KINST" \
    "offline update does not defer verification past its reboot"
assert_grep_fixed 'the acquired block shutdown inhibitor prevents an offline update reboot from' \
    "$TMP_KINST" "kernel hook explains the offline-update reboot guard"
assert_grep_fixed 'service requeue the task if an interruption still occurs.' \
    "$TMP_KINST" "kernel hook explains durable boot-time resume"
assert_not_grep 'prevent the offline update' "$TMP_KINST" \
    "kernel hook contains no garbled offline-update sentence"
marker_line=$(grep -nF 'mv -fT -- "$marker_tmp" "$marker"' "$TMP_QUEUE" | cut -d: -f1 || true)
marker_sync_line=$(grep -nF 'sync -- "$queue_dir"' "$TMP_QUEUE" | tail -1 | cut -d: -f1 || true)
guard_line=$(grep -nF 'systemctl start noid-nvidia-reboot-guard.service' "$TMP_QUEUE" | tail -n1 | cut -d: -f1 || true)
release_line=$(grep -nF 'release_boot_mutation' "$TMP_QUEUE" | tail -n1 | cut -d: -f1 || true)
schedule_line=$(grep -nF 'schedule_marker "$marker"' "$TMP_QUEUE" | tail -n1 | cut -d: -f1 || true)
if [ -n "$marker_line" ] && [ -n "$marker_sync_line" ] && [ -n "$guard_line" ] \
        && [ -n "$release_line" ] && [ -n "$schedule_line" ] \
        && [ "$marker_line" -lt "$marker_sync_line" ] \
        && [ "$marker_sync_line" -lt "$guard_line" ] \
        && [ "$guard_line" -lt "$release_line" ] \
        && [ "$release_line" -lt "$schedule_line" ] \
        && [ "$guard_line" -lt "$schedule_line" ]; then
    _pass "durable marker and acquired guard precede lock release and worker scheduling"
else
    _fail "durable NVIDIA queue ordering is unsafe"
fi
promote_line=$(grep -nF 'promote_deferred' "$TMP_QUEUE" | tail -n1 | cut -d: -f1 || true)
resume_guard_line=$(grep -nF 'systemctl start noid-nvidia-reboot-guard.service' \
    "$TMP_QUEUE" | head -1 | cut -d: -f1 || true)
resume_release_line=$(grep -nF 'release_boot_mutation' "$TMP_QUEUE" \
    | tail -n2 | head -1 | cut -d: -f1 || true)
resume_schedule_line=$(grep -nF 'schedule_all_pending' "$TMP_QUEUE" \
    | tail -1 | cut -d: -f1 || true)
if [ -n "$promote_line" ] && [ -n "$resume_guard_line" ] \
        && [ -n "$resume_release_line" ] && [ -n "$resume_schedule_line" ] \
        && [ "$promote_line" -lt "$resume_guard_line" ] \
        && [ "$resume_guard_line" -lt "$resume_release_line" ] \
        && [ "$resume_release_line" -lt "$resume_schedule_line" ]; then
    _pass "resume publishes pending work before guard, releases its lock, then schedules"
else
    _fail "resumed NVIDIA queue can lose its guard or collide with its own lock"
fi
assert_grep_fixed 'flock -w 1800 9' "$TMP_REBUILD" \
    "concurrent NVIDIA module builders serialize after the global lock"
assert_grep_fixed '/usr/libexec/noid-dracut-regenerate-all --lock-held=8 --kernel="$kver"' \
    "$TMP_REBUILD" "worker delegates publication to the canonical M21 writer"
assert_grep_fixed 'mv -fT -- "$ready_tmp" "$state_dir/${kver}.ready"' "$TMP_REBUILD" \
    "successful rebuild publishes a persistent ready artifact"
assert_grep_fixed 'rebind_record "$prepared_record" prepared' "$TMP_REBIND" \
    "bridge validates stronger prepared evidence before coexistence recovery"
assert_grep_fixed 'rm -f -- "$ready_record"' "$TMP_REBIND" \
    "bridge retires the superseded mutable ready record"
assert_not_grep 'multiple pre-reboot evidence records exist' "$TMP_REBIND" \
    "legacy ready/prepared coexistence no longer wedges the bridge"
assert_not_grep '\.active' "$TMP_REBIND" \
    "bridge cannot rewrite historical active evidence"
completion_remove_line=$(grep -nF \
    'rm -f "$queued_marker" "${queued_marker%.pending}.failed" "$state_dir/degraded"' \
    "$TMP_REBUILD" | cut -d: -f1 || true)
completion_sync_line=$(grep -nF 'sync -- "$queue_dir"' "$TMP_REBUILD" | tail -1 | cut -d: -f1 || true)
if [ -n "$completion_remove_line" ] && [ -n "$completion_sync_line" ] \
        && [ "$completion_remove_line" -lt "$completion_sync_line" ]; then
    _pass "successful rebuild durably removes completed and failed queue markers"
else
    _fail "successful rebuild can leave completed queue markers after power loss"
fi
# Rollback removes BOTH new files (back to slim/nouveau initramfs).
assert_grep_fixed 'rm -f /etc/dracut.conf.d/99-noid-nvidia-initramfs.conf' "$TMP_SCRIPT" \
    "rollback removes the nvidia-initramfs dracut conf"
assert_grep_fixed 'rm -f /etc/kernel/install.d/95-noid-nvidia-initramfs.install' "$TMP_SCRIPT" \
    "rollback removes the kernel-install hook"
assert_grep_fixed '/var/cache/akmods/nvidia/*.failed.log' "$TMP_SCRIPT" \
    "rollback clears main-branch akmods failure evidence"
assert_grep_fixed '/var/cache/akmods/nvidia-580xx/*.failed.log' "$TMP_SCRIPT" \
    "rollback clears legacy-branch akmods failure evidence"
# Rollback now offers a reboot prompt (was: only re-open welcome menu).
assert_grep_fixed 'A reboot is required to switch back to the in-tree Nouveau/Mesa path' "$TMP_SCRIPT" \
    "rollback prompts to reboot"
# Upfront warning: the mixed pre-reboot userspace/kernel state is not a
# supported steady state, without claiming that every application must fail.
assert_grep_fixed 'Some GPU-accelerated apps can fail or behave inconsistently until reboot' \
    "$TMP_SCRIPT" "upfront warning discloses the pre-reboot graphics risk"
assert_not_grep "GPU apps won't launch until you reboot" "$TMP_SCRIPT" \
    "upfront warning makes no universal application-failure claim"

# Generic iGPU presence does not prove an affected active hybrid renderer path.
# The driver installer keeps the vendor GTK renderer default and does not own
# the independent, cross-driver renderer opt-in.
assert_not_grep 'tee /etc/environment.d/90-noid-gsk-renderer.conf' "$TMP_SCRIPT" \
    "installer does not publish an unproven global GTK renderer override"
assert_not_grep 'GSK_RENDERER=gl' "$TMP_SCRIPT" \
    "installer retains the maintained GTK renderer default"
assert_not_grep 'rm -f /etc/environment.d/90-noid-gsk-renderer.conf' "$TMP_SCRIPT" \
    "NVIDIA rollback cannot remove the independent cross-driver GTK opt-in"
assert_grep_fixed 'The independent GTK renderer opt-in, if selected, remains user-owned.' \
    "$TMP_SCRIPT" "rollback discloses the separate GTK workaround ownership"
rollback_dracut_line=$(grep -nF 'sudo -C 8 /usr/libexec/noid-dracut-regenerate-all' \
    "$TMP_SCRIPT" | head -1 | cut -d: -f1 || true)
assert_not_grep 'sudo dconf update' "$TMP_SCRIPT" \
    "NVIDIA install and rollback leave the base/user dconf policy untouched"
assert_grep_fixed 'Atomically regenerating and validating every installed initramfs for nouveau' \
    "$TMP_SCRIPT" "rollback covers every installed kernel rather than only uname -r"
rollback_config_line=$(grep -nF 'rm -f /etc/dracut.conf.d/99-noid-nvidia-initramfs.conf' \
    "$TMP_SCRIPT" | head -1 | cut -d: -f1 || true)
if [ -n "$rollback_config_line" ] && [ -n "$rollback_dracut_line" ] \
        && [ "$rollback_config_line" -lt "$rollback_dracut_line" ]; then
    _pass "rollback removes NVIDIA inclusion policy before canonical regeneration"
else
    _fail "rollback can regenerate before retiring NVIDIA inclusion policy"
fi
assert_grep_fixed 'BOOT_MUTATION_BASIS=$(sudo /usr/libexec/noid-boot-mutation-guard)' \
    "$TMP_SCRIPT" "interactive candidates bind to the stable M21 basis"
assert_grep_fixed 'Step 2 creates the key before the build + the Step-3 sign gate hard-exits' \
    "$TMP_SCRIPT" "signing anomaly comment points to the actual progress steps"
assert_not_grep 'Step 1 creates the key' "$TMP_SCRIPT" \
    "signing anomaly comment carries no stale key-generation step"
assert_not_grep_extended 'BOOT_MUTATION_OWNER|BOOT_MUTATION_CLAIM|--lock-owner' \
    "$TMP_SCRIPT" "interactive helper has no racy process-claim authority"
assert_not_grep 'Module 01 universal default' "$TMP_SCRIPT" \
    "NVIDIA-conditional simpledrm policy is not documented as universal"
assert_not_grep 'security score of 7.6' "$KS_FILE" \
    "switcheroo guidance does not cite the stale pre-hardening score"

test_finish

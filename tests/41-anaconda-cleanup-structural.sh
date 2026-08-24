#!/bin/bash
# 41-anaconda-cleanup-structural — first-boot privilege-remnant cleanup gates

set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/41-anaconda-cleanup.ks"
FIRSTBOOT_RUNTIME="$PROJECT_ROOT/tests/pre-ship/41-installed-firstboot-runtime.sh"
IDENTITY_UNIQUENESS="$PROJECT_ROOT/tests/pre-ship/41-host-identity-uniqueness.sh"
TMPDIR="$(mktemp -d)"
M41_STAMP_TEST_ROOT=""
M41_MARKER_TEST_ROOT=""
M41_METADATA_TEST_ROOT=""
M41_GSK_TEST_ROOT=""
cleanup_m41_test() {
    rm -rf -- "$TMPDIR"
    [ -z "$M41_STAMP_TEST_ROOT" ] \
        || rm -rf -- "$M41_STAMP_TEST_ROOT"
    [ -z "$M41_MARKER_TEST_ROOT" ] \
        || rm -rf -- "$M41_MARKER_TEST_ROOT"
    [ -z "$M41_METADATA_TEST_ROOT" ] \
        || rm -rf -- "$M41_METADATA_TEST_ROOT"
    [ -z "$M41_GSK_TEST_ROOT" ] \
        || rm -rf -- "$M41_GSK_TEST_ROOT"
}
trap cleanup_m41_test EXIT

test_start "41-anaconda-cleanup-structural"

extract_function() { # NAME SOURCE TARGET [append]
    local name=$1 source=$2 target=$3 mode=${4:-write} body
    body=$(awk -v wanted="$name" '
        $0 ~ "^" wanted "\\(\\) *\\{" { in_function=1 }
        in_function { print }
        in_function && /^\}$/ { exit }
    ' "$source")
    if [ -z "$body" ]; then
        _fail "function extraction produced no body: $name from $source"
        test_finish
        exit 1
    fi
    if [ "$mode" = append ]; then
        printf '%s\n' "$body" >> "$target"
    else
        printf '%s\n' "$body" > "$target"
    fi
}

assert_file_exists "$KS_FILE"
assert_cmd_success "M41 snippet bash -n clean" bash -n "$KS_FILE"
if (extract_function no_such_m41_function "$KS_FILE" \
        "$TMPDIR/missing-function.sh") >/dev/null 2>&1; then
    _fail "missing function extraction fails closed"
else
    _pass "missing function extraction fails closed"
fi
assert_file_executable "$FIRSTBOOT_RUNTIME" \
    "installed firstboot release gate is executable"
assert_cmd_success "installed firstboot release gate parses" \
    bash -n "$FIRSTBOOT_RUNTIME"
assert_file_executable "$IDENTITY_UNIQUENESS" \
    "two-install host-identity gate is executable"
assert_cmd_success "two-install host-identity gate parses" \
    bash -n "$IDENTITY_UNIQUENESS"
assert_grep_fixed 'fresh-install) BOOTS=(0)' "$FIRSTBOOT_RUNTIME" \
    "fresh-install release gate audits its complete first boot"
assert_grep_fixed 'reboot) BOOTS=(-1 0)' "$FIRSTBOOT_RUNTIME" \
    "reboot release gate binds both lifecycle journals"
assert_grep_fixed \
    "find -P /var/log -mindepth 1 -maxdepth 1 -name 'ks-*.log'" \
    "$FIRSTBOOT_RUNTIME" \
    "runtime requires installed Kickstart evidence to be absent"
assert_grep_fixed \
    'installed root retains Anaconda log payload' "$FIRSTBOOT_RUNTIME" \
    "runtime requires installed Anaconda log payload to be absent"
assert_grep_fixed '/usr/local/bin/noid-host-identity --check' \
    "$FIRSTBOOT_RUNTIME" \
    "runtime validates installed machine-local identities without printing them"
assert_grep_fixed 'rpm -Va --nodeps --nodigest --nosize --nomtime' \
    "$FIRSTBOOT_RUNTIME" \
    "runtime verifies metadata without treating intended content as drift"
assert_grep_fixed 'classify_m41_rpm_verify()' "$FIRSTBOOT_RUNTIME" \
    "runtime isolates M41-owned RPM verification fields"
for rpm_status_position in \
        'substr(status, 2, 1)' \
        'substr(status, 5, 1)' \
        'substr(status, 6, 1)' \
        'substr(status, 7, 1)'; do
    assert_grep_fixed "$rpm_status_position" "$FIRSTBOOT_RUNTIME" \
        "runtime checks M41-owned RPM status field: $rpm_status_position"
done
assert_grep_fixed 'if (status == "missing") {' "$FIRSTBOOT_RUNTIME" \
    "runtime separates absent RPM paths from existing-path metadata drift"
assert_grep_fixed 'missing package symlink %s' "$FIRSTBOOT_RUNTIME" \
    "runtime still rejects package symlinks left absent by Live-image transfer"
assert_grep_fixed 'rpm -qa --qf' "$FIRSTBOOT_RUNTIME" \
    "runtime inventories installed RPM file records without resolving live paths"
assert_not_grep_extended 'rpm[[:space:]]+-qf([[:space:]]|$)' \
    "$FIRSTBOOT_RUNTIME" \
    "runtime never queries an already-missing path through rpm -qf"
assert_grep_fixed \
    'find -P /etc/sysconfig /usr/lib/grub -xdev -print0' \
    "$FIRSTBOOT_RUNTIME" \
    "runtime enumerates every actual path in both M41 label scopes"
assert_grep_fixed 'matchpathcon -V "$scope_path"' "$FIRSTBOOT_RUNTIME" \
    "runtime proves every actual M41 scope label"
assert_grep_fixed 'interaction_config=/etc/sysconfig/anaconda' \
    "$FIRSTBOOT_RUNTIME" \
    "runtime audits Anaconda's non-RPM-owned post-install interface"
assert_grep_fixed \
    "stat -c '%u:%g:%a:%h' \"\$interaction_config\"" \
    "$FIRSTBOOT_RUNTIME" \
    "runtime requires exact readable interaction-config metadata"
assert_grep_fixed \
    'journalctl -b "$boot" -o short-monotonic --no-pager --quiet' \
    "$FIRSTBOOT_RUNTIME" \
    "no-match journal queries suppress non-evidence status banners"
for firstboot_regression in \
        'Could not read /etc/sysconfig/anaconda' \
        'usericon.*not a regular file' \
        'gnome-session-manager@gnome-initial-setup' \
        'ANOM_ABEND.*comm="gnome-session' \
        'Configuration file .*world-inaccessible'; do
    assert_grep_fixed "$firstboot_regression" "$FIRSTBOOT_RUNTIME" \
        "runtime rejects firstboot regression: $firstboot_regression"
done
extract_function classify_m41_rpm_verify "$FIRSTBOOT_RUNTIME" \
    "$TMPDIR/firstboot-rpm-classifier.sh"
assert_cmd_success "installed runtime RPM classifier parses" \
    bash -n "$TMPDIR/firstboot-rpm-classifier.sh"
# shellcheck source=/dev/null
. "$TMPDIR/firstboot-rpm-classifier.sh"
cat >"$TMPDIR/rpm-verify-fixture" <<'RPM_VERIFY_FIXTURE_EOF'
missing   c /etc/sysconfig/samba
..5......  c /etc/sysconfig/snapper
.M.......    /etc/sysconfig/mode
....L....    /usr/lib/grub/package-link
.....U...    /etc/sysconfig/owner
......G..    /usr/lib/grub/group
........P    /etc/sysconfig/capability
.........    /etc/sysconfig/exact
.M.......    /outside/mode
bad          /etc/sysconfig/malformed
RPM_VERIFY_FIXTURE_EOF
assert_cmd_success "installed runtime RPM classifier runs" \
    classify_m41_rpm_verify \
        "$TMPDIR/rpm-verify-fixture" \
        "$TMPDIR/rpm-verify-drift" \
        "$TMPDIR/rpm-verify-missing"
if grep -qxF '/etc/sysconfig/samba' "$TMPDIR/rpm-verify-missing" \
   && [ "$(wc -l <"$TMPDIR/rpm-verify-missing")" -eq 1 ] \
   && grep -qxF '.M.......    /etc/sysconfig/mode' \
        "$TMPDIR/rpm-verify-drift" \
   && grep -qxF '....L....    /usr/lib/grub/package-link' \
        "$TMPDIR/rpm-verify-drift" \
   && grep -qxF '.....U...    /etc/sysconfig/owner' \
        "$TMPDIR/rpm-verify-drift" \
   && grep -qxF '......G..    /usr/lib/grub/group' \
        "$TMPDIR/rpm-verify-drift" \
   && grep -qxF 'bad          /etc/sysconfig/malformed' \
        "$TMPDIR/rpm-verify-drift" \
   && [ "$(wc -l <"$TMPDIR/rpm-verify-drift")" -eq 5 ] \
   && ! grep -qF '/etc/sysconfig/snapper' "$TMPDIR/rpm-verify-drift" \
   && ! grep -qF '/etc/sysconfig/capability' "$TMPDIR/rpm-verify-drift" \
   && ! grep -qF '/outside/' "$TMPDIR/rpm-verify-drift"; then
    _pass "installed runtime accepts content/capability/absence outside M41 ownership while rejecting mode/link/owner/group drift"
else
    _fail "installed runtime RPM metadata classifier contract"
fi
extract_function classify_missing_rpm_path "$FIRSTBOOT_RUNTIME" \
    "$TMPDIR/missing-rpm-path-classifier.sh"
assert_cmd_success "missing RPM path classifier parses" \
    bash -n "$TMPDIR/missing-rpm-path-classifier.sh"
# shellcheck source=/dev/null
. "$TMPDIR/missing-rpm-path-classifier.sh"
cat >"$TMPDIR/rpm-file-records-fixture" <<'RPM_FILE_RECORDS_FIXTURE_EOF'
/etc/sysconfig/regular	100644	0
/etc/sysconfig/link	120777	0
/etc/sysconfig/ghost	100644	64
/etc/sysconfig/conflict	100644	0
/etc/sysconfig/conflict	120777	0
/etc/sysconfig/malformed	not-octal	0
RPM_FILE_RECORDS_FIXTURE_EOF
assert_eq non-symlink \
    "$(classify_missing_rpm_path "$TMPDIR/rpm-file-records-fixture" /etc/sysconfig/regular)" \
    "missing regular-file metadata is preserved as non-symlink evidence"
assert_eq symlink \
    "$(classify_missing_rpm_path "$TMPDIR/rpm-file-records-fixture" /etc/sysconfig/link)" \
    "missing symlink metadata remains release-blocking evidence"
assert_eq ghost \
    "$(classify_missing_rpm_path "$TMPDIR/rpm-file-records-fixture" /etc/sysconfig/ghost)" \
    "missing ghost metadata is intentionally ignored"
assert_eq conflict \
    "$(classify_missing_rpm_path "$TMPDIR/rpm-file-records-fixture" /etc/sysconfig/conflict)" \
    "conflicting missing-path ownership fails closed"
assert_eq malformed \
    "$(classify_missing_rpm_path "$TMPDIR/rpm-file-records-fixture" /etc/sysconfig/malformed)" \
    "malformed missing-path metadata fails closed"
assert_eq unknown \
    "$(classify_missing_rpm_path "$TMPDIR/rpm-file-records-fixture" /etc/sysconfig/absent)" \
    "unowned missing paths fail closed"
extract_heredoc "$KS_FILE" "CLEANUP_EOF" "$TMPDIR/cleanup.sh" || \
    _fail "cleanup script extraction"
extract_heredoc "$KS_FILE" "HOST_IDENTITY_EOF" \
    "$TMPDIR/noid-host-identity" || _fail "host-identity helper extraction"
extract_heredoc "$KS_FILE" "HOST_IDENTITY_SERVICE_EOF" \
    "$TMPDIR/noid-host-identity.service" || \
    _fail "host-identity service extraction"
extract_heredoc "$KS_FILE" "SERVICE_EOF" "$TMPDIR/cleanup.service" || \
    _fail "service extraction"
extract_heredoc "$KS_FILE" "MAINTENANCE_SERVICE_EOF" \
    "$TMPDIR/maintenance.service" || _fail "maintenance service extraction"
extract_heredoc "$KS_FILE" "GDM_GATE_EOF" "$TMPDIR/gdm-gate.conf" || \
    _fail "GDM cleanup gate extraction"
extract_heredoc "$KS_FILE" "USER_SESSIONS_GATE_EOF" \
    "$TMPDIR/user-sessions-gate.conf" || \
    _fail "systemd-user-sessions cleanup gate extraction"
assert_cmd_success "first-boot cleanup bash -n clean" bash -n "$TMPDIR/cleanup.sh"
extract_function installer_evidence_root_is_safe "$TMPDIR/cleanup.sh" \
    "$TMPDIR/installer-evidence-root-predicate.sh"
cat > "$TMPDIR/installer-evidence-root-runner.sh" <<'M41_EVIDENCE_RUNNER_EOF'
#!/bin/bash
set -euo pipefail
. /mnt/installer-evidence-root-predicate.sh
chmod "$M41_TEST_ROOT_MODE" /root
case "$M41_TEST_EXPECT" in
    pass) installer_evidence_root_is_safe ;;
    fail) ! installer_evidence_root_is_safe ;;
    *) exit 2 ;;
esac
M41_EVIDENCE_RUNNER_EOF
chmod 0700 "$TMPDIR/installer-evidence-root-runner.sh"
if command -v bwrap >/dev/null 2>&1; then
    assert_cmd_success \
        "Fedora root:root 0550 boundary permits installer-evidence retirement" \
        bwrap --unshare-user --uid 0 --gid 0 --die-with-parent \
            --ro-bind / / --dev-bind /dev /dev --proc /proc \
            --bind "$TMPDIR" /mnt \
            --tmpfs /root \
            --setenv M41_TEST_ROOT_MODE 0550 \
            --setenv M41_TEST_EXPECT pass \
            /bin/bash /mnt/installer-evidence-root-runner.sh
    assert_cmd_success "non-Fedora 0700 /root boundary fails closed" \
        bwrap --unshare-user --uid 0 --gid 0 --die-with-parent \
            --ro-bind / / --dev-bind /dev /dev --proc /proc \
            --bind "$TMPDIR" /mnt \
            --tmpfs /root \
            --setenv M41_TEST_ROOT_MODE 0700 \
            --setenv M41_TEST_EXPECT fail \
            /bin/bash /mnt/installer-evidence-root-runner.sh
else
    _fail "bubblewrap is required for the M41 installer-evidence boundary fixture"
fi
assert_cmd_success "host-identity helper bash -n clean" \
    bash -n "$TMPDIR/noid-host-identity"
assert_grep_fixed '/usr/bin/uuidgen --random' "$TMPDIR/noid-host-identity" \
    "NVMe host identity uses the installed native random UUID generator"
assert_grep_fixed '/usr/bin/mcookie' "$TMPDIR/noid-host-identity" \
    "BRLAPI key uses Fedora's package-native mcookie primitive"
assert_grep_fixed 'refusing repair while an NVMe-over-Fabrics controller is active' \
    "$TMPDIR/noid-host-identity" \
    "manual identity repair refuses active NVMe-over-Fabrics"
assert_grep_fixed 'validate_install_marker' "$TMPDIR/noid-host-identity" \
    "installed identity rotation is retry-safe behind validated evidence"
assert_grep_fixed 'resumed incomplete pre-install NVMe identity publication' \
    "$TMPDIR/noid-host-identity" \
    "an interrupted first NVMe pair publication resumes before login"
assert_grep_fixed \
    'installed identity evidence exists; refusing automatic NVMe repair' \
    "$TMPDIR/noid-host-identity" \
    "established installed NVMe identity corruption never auto-rotates"
assert_grep_fixed \
    'incomplete NVMe identity with an active fabric requires manual recovery' \
    "$TMPDIR/noid-host-identity" \
    "automatic retry never changes an active NVMe-over-Fabrics identity"
assert_grep_fixed 'resumed incomplete pre-install BRLAPI key publication' \
    "$TMPDIR/noid-host-identity" \
    "an interrupted first BRLAPI publication resumes before login"
assert_grep_fixed 'NVME_HOSTNQN' "$TMPDIR/noid-host-identity" \
    "NVMe host ID and NQN are validated as one related pair"
assert_not_grep 'echo.*hostid\|echo.*hostnqn\|echo.*BRLAPI' \
    "$TMPDIR/noid-host-identity" \
    "host-identity helper does not print machine-identifying values"
assert_grep_fixed 'machine_id=' "$IDENTITY_UNIQUENESS" \
    "two-install gate compares a private machine-id digest"
assert_grep_fixed 'random_seed=' "$IDENTITY_UNIQUENESS" \
    "two-install gate compares a private random-seed digest"
assert_grep_fixed 'brlapi_key=' "$IDENTITY_UNIQUENESS" \
    "two-install gate compares a private BRLAPI digest"
assert_grep_fixed 'nvme_hostid=' "$IDENTITY_UNIQUENESS" \
    "two-install gate compares a private NVMe host-ID digest"
assert_grep_fixed 'nvme_hostnqn=' "$IDENTITY_UNIQUENESS" \
    "two-install gate compares a private NVMe host-NQN digest"
assert_grep_fixed 'if [ "$#" -ne 1 ]; then' "$TMPDIR/cleanup.sh" \
    "privileged cleanup requires exactly one mode argument"
assert_grep_fixed 'MODE=$1' "$TMPDIR/cleanup.sh" \
    "cleanup reads its mode only after the arity gate"
assert_not_grep 'MODE=${1:-}' "$TMPDIR/cleanup.sh" \
    "cleanup has no defaulting parser that can hide missing arguments"
assert_grep_fixed 'if [[ $# -ne 1 ]]; then' "$FIRSTBOOT_RUNTIME" \
    "installed release gate requires exactly one lifecycle argument"
assert_grep_fixed 'PASS_ID=$1' "$FIRSTBOOT_RUNTIME" \
    "installed release gate reads its lifecycle only after the arity gate"
assert_not_grep 'PASS_ID=${1:-}' "$FIRSTBOOT_RUNTIME" \
    "installed release gate has no defaulting parser that can hide missing arguments"

# Execute the exact cleanup parser plus a non-mutating reached marker. Every
# surplus vector must stop before the selected security/maintenance body, and
# terminal-control bytes supplied after a valid mode must never be reflected.
awk '
    /^if \[ "\$#" -ne 1 \]; then$/ { in_parser=1 }
    in_parser && /^SECURITY_MARKER=/ { exit }
    in_parser { print }
' "$TMPDIR/cleanup.sh" > "$TMPDIR/cleanup-argument-parser.sh"
printf '%s\n' 'printf "REACHED mode=%s\\n" "$MODE"' \
    >> "$TMPDIR/cleanup-argument-parser.sh"
assert_cmd_success "isolated cleanup argument parser is valid bash" \
    bash -n "$TMPDIR/cleanup-argument-parser.sh"

run_m41_argument_case() { # NAME EXPECTED_RC EXPECTED_STDOUT EXPECTED_STDERR -- ARGS...
    local name=$1 expected_rc=$2 expected_stdout=$3 expected_stderr=$4
    local rc
    shift 4
    [ "$1" = -- ] || {
        _fail "$name fixture separator"
        return
    }
    shift
    set +e
    bash "$TMPDIR/cleanup-argument-parser.sh" "$@" \
        > "$TMPDIR/m41-arg.stdout" 2> "$TMPDIR/m41-arg.stderr"
    rc=$?
    set -e
    assert_eq "$expected_rc" "$rc" "$name exit status"
    assert_eq "$expected_stdout" "$(cat "$TMPDIR/m41-arg.stdout")" \
        "$name stdout"
    assert_eq "$expected_stderr" "$(cat "$TMPDIR/m41-arg.stderr")" \
        "$name stderr"
    if LC_ALL=C grep -q $'\033' \
            "$TMPDIR/m41-arg.stdout" "$TMPDIR/m41-arg.stderr"; then
        _fail "$name emits terminal-control bytes"
    else
        _pass "$name emits no terminal-control bytes"
    fi
}

parser_usage="Usage: $TMPDIR/cleanup-argument-parser.sh {--security|--maintenance}"
run_m41_argument_case "exact security mode" 0 \
    'REACHED mode=security' '' -- --security
run_m41_argument_case "exact maintenance mode" 0 \
    'REACHED mode=maintenance' '' -- --maintenance
run_m41_argument_case "missing cleanup mode" 2 '' "$parser_usage" --
run_m41_argument_case "surplus security mode" 2 '' "$parser_usage" \
    -- --security extra
run_m41_argument_case "hostile surplus maintenance mode" 2 '' "$parser_usage" \
    -- --maintenance $'line\n\033[31mhostile'
run_m41_argument_case "unknown cleanup mode" 2 '' "$parser_usage" \
    -- --unexpected

# The complete read-only release gate performs its arity check before root,
# host-identity or evidence inspection, so hostile surplus input can be tested
# directly without touching the live system.
set +e
bash "$FIRSTBOOT_RUNTIME" fresh-install $'line\n\033[31mhostile' \
    > "$TMPDIR/firstboot-arg.stdout" 2> "$TMPDIR/firstboot-arg.stderr"
firstboot_arg_rc=$?
set -e
assert_eq 2 "$firstboot_arg_rc" \
    "installed release gate rejects hostile surplus arguments"
assert_eq '' "$(cat "$TMPDIR/firstboot-arg.stdout")" \
    "installed release gate hostile rejection has no stdout"
assert_eq "Usage: sudo bash $FIRSTBOOT_RUNTIME {fresh-install|reboot}" \
    "$(cat "$TMPDIR/firstboot-arg.stderr")" \
    "installed release gate emits one fixed usage line"
if LC_ALL=C grep -q $'\033' \
        "$TMPDIR/firstboot-arg.stdout" "$TMPDIR/firstboot-arg.stderr"; then
    _fail "installed release gate reflects terminal-control bytes"
else
    _pass "installed release gate reflects no terminal-control bytes"
fi
mkdir -p "$TMPDIR/systemd/gdm.service.d"
mkdir -p "$TMPDIR/systemd/systemd-user-sessions.service.d"
install -m 0644 "$TMPDIR/noid-host-identity.service" \
    "$TMPDIR/systemd/noid-host-identity.service"
sed -i \
    's|^ExecStart=/usr/local/bin/noid-host-identity --ensure$|ExecStart=/usr/bin/true --ensure|' \
    "$TMPDIR/systemd/noid-host-identity.service"
install -m 0644 "$TMPDIR/cleanup.service" \
    "$TMPDIR/systemd/noid-anaconda-cleanup.service"
install -m 0644 "$TMPDIR/maintenance.service" \
    "$TMPDIR/systemd/noid-anaconda-maintenance.service"
install -m 0644 "$TMPDIR/gdm-gate.conf" \
    "$TMPDIR/systemd/gdm.service.d/40-noid-anaconda-cleanup.conf"
install -m 0644 "$TMPDIR/user-sessions-gate.conf" \
    "$TMPDIR/systemd/systemd-user-sessions.service.d/40-noid-anaconda-cleanup.conf"
assert_cmd_success "generated cleanup/login unit graph verifies" \
    env SYSTEMD_UNIT_PATH="$TMPDIR/systemd:/usr/lib/systemd/system" \
    systemd-analyze verify noid-host-identity.service \
        noid-anaconda-cleanup.service \
        noid-anaconda-maintenance.service gdm.service \
        systemd-user-sessions.service

# The account-removal purpose of this module must be a postcondition, not a
# best-effort command followed by a permanent success marker. Scope identity
# decisions to the local files database so a remote NSS identity cannot grant
# authority to delete local state.
assert_not_grep 'userdel.*|| true' "$TMPDIR/cleanup.sh" \
    "liveuser deletion failure is not swallowed"
assert_grep_fixed 'getent -s files passwd liveuser' "$TMPDIR/cleanup.sh" \
    "liveuser identity checks use only the local passwd database"
assert_grep_fixed 'for identity_db in passwd shadow group gshadow; do' \
    "$TMPDIR/cleanup.sh" \
    "all local identity databases must be enumerable before absence is trusted"
assert_grep_fixed 'verify_local_identity_databases_readable()' \
    "$TMPDIR/cleanup.sh" "local identity readability gate is isolated"
assert_eq "2" \
    "$(grep -cFx 'verify_local_identity_databases_readable' \
        "$TMPDIR/cleanup.sh")" \
    "identity databases are checked before mutation and rechecked before success"
assert_grep_fixed 'getent -s files shadow liveuser' "$TMPDIR/cleanup.sh" \
    "local shadow state is included in cleanup and final verification"
assert_grep_fixed 'pwconv' "$TMPDIR/cleanup.sh" \
    "orphan shadow state uses shadow-utils lock-aware reconciliation"
assert_grep_fixed 'getent -s files group liveuser' "$TMPDIR/cleanup.sh" \
    "local liveuser group state is included in the cleanup boundary"
assert_grep_fixed 'groupdel liveuser' "$TMPDIR/cleanup.sh" \
    "an empty exact liveuser private-group remnant is removed natively"
assert_grep_fixed 'getent -s files gshadow liveuser' "$TMPDIR/cleanup.sh" \
    "local gshadow state is included in cleanup and final verification"
assert_grep_fixed 'grpconv' "$TMPDIR/cleanup.sh" \
    "orphan gshadow state uses shadow-utils lock-aware reconciliation"
assert_grep_fixed \
    'refusing to remove malformed or member-bearing liveuser group' \
    "$TMPDIR/cleanup.sh" \
    "member-bearing local groups fail closed instead of losing memberships"
assert_not_grep 'sed .*/etc/shadow' "$TMPDIR/cleanup.sh" \
    "cleanup never edits the shadow database without its native locking tool"
assert_not_grep_extended \
    '^[[:space:]]*userdel[[:space:]]+-r([[:space:]]|$)' \
    "$TMPDIR/cleanup.sh" \
    "cleanup never trusts the passwd home field as a recursive delete target"
assert_grep_fixed 'userdel returned nonzero after removing the local account' \
    "$TMPDIR/cleanup.sh" \
    "split account/home removal failure reaches explicit home cleanup"
assert_grep_fixed '[ "$liveuser_uid" -lt 1000 ]' "$TMPDIR/cleanup.sh" \
    "liveuser mutation rejects system and root UIDs"
assert_grep_fixed '[ "$liveuser_uid" -ge 60000 ]' "$TMPDIR/cleanup.sh" \
    "liveuser mutation stays inside the normal local UID range"
assert_grep_fixed '$3 == uid { count++ }' "$TMPDIR/cleanup.sh" \
    "liveuser process signaling requires a unique local UID"
assert_not_grep 'pkill -KILL -u "$liveuser_uid".*|| true' \
    "$TMPDIR/cleanup.sh" \
    "liveuser process-signaling failures are not swallowed"
assert_grep_fixed 'FAILED: liveuser processes remain after SIGKILL' \
    "$TMPDIR/cleanup.sh" \
    "liveuser process absence is verified before account deletion"
assert_grep_fixed 'quarantine_exact_liveuser_remnant()' \
    "$TMPDIR/cleanup.sh" \
    "account remnants use one recoverable exact-path transaction"
assert_grep_fixed \
    '/home/liveuser /home/.noid-liveuser-quarantine home-entry' \
    "$TMPDIR/cleanup.sh" \
    "preserved-home data moves to a root-private same-filesystem quarantine"
assert_grep_fixed \
    '/var/spool/mail/.noid-liveuser-quarantine mail-entry' \
    "$TMPDIR/cleanup.sh" \
    "mail state is quarantined instead of destroyed"
assert_not_grep 'rm -rf -- "$liveuser_remnant"' "$TMPDIR/cleanup.sh" \
    "the first-boot safety-net never recursively deletes possible user data"
assert_not_grep 'rm -rf /home/liveuser' "$KS_FILE" \
    "M41 comments and payload carry no stale destructive home-cleanup contract"
assert_grep_fixed 'mv --update=none-fail -T -- "$source" "$destination"' \
    "$TMPDIR/cleanup.sh" \
    "quarantine publication fails rather than overwriting a recovery target"
assert_not_grep 'mv --no-clobber' "$TMPDIR/cleanup.sh" \
    "quarantine publication never reports a skipped collision as success"
assert_grep_fixed 'findmnt -rn -o TARGET' "$TMPDIR/cleanup.sh" \
    "mounted sources or descendants block quarantine for manual review"
assert_grep_fixed 'sync -- "$quarantine_dir" "$source_parent"' \
    "$TMPDIR/cleanup.sh" \
    "rename durability does not dereference a quarantined symlink"
assert_grep_fixed 'root:mail:775' "$TMPDIR/cleanup.sh" \
    "mail-spool writability is limited to the exact documented Fedora exception"
assert_grep_fixed 'FAILED postcondition: liveuser account still exists' \
    "$TMPDIR/cleanup.sh" "liveuser absence is verified before success"
assert_grep_fixed 'FAILED postcondition: exact liveuser remnant still exists' \
    "$TMPDIR/cleanup.sh" "exact liveuser path absence is verified"
assert_grep_fixed \
    'FAILED postcondition: local liveuser authentication state still exists' \
    "$TMPDIR/cleanup.sh" \
    "passwd-adjacent local authentication state is a final postcondition"
assert_grep_fixed 'root_password_hash_is_locked()' "$TMPDIR/cleanup.sh" \
    "root password-field lock recognition is isolated for behavioral testing"
assert_grep_fixed '/usr/bin/passwd -l root' "$TMPDIR/cleanup.sh" \
    "the native shadow-utils path restores the installed root-password lock"
assert_eq "2" \
    "$(grep -cFx 'ensure_local_root_password_locked' "$TMPDIR/cleanup.sh")" \
    "root password lock is converged before cleanup and rechecked before success"
assert_grep_fixed 'FAILED postcondition: active sudoers entry still references liveuser' \
    "$TMPDIR/cleanup.sh" "liveuser sudoers absence is verified"
assert_not_grep 'FAILED: cannot scan sudoers drop-ins for liveuser' \
    "$TMPDIR/cleanup.sh" "retired broad sudoers deletion path is absent"
assert_grep_fixed 'FAILED: cannot parse or inspect the active sudoers policy' \
    "$TMPDIR/cleanup.sh" "sudoers parse/read failures fail closed during cleanup"
assert_grep_fixed \
    "parse_output=\$(LC_ALL=C /usr/sbin/visudo -cf \"\$sudoers_file\" 2>&1)" \
    "$TMPDIR/cleanup.sh" \
    "sudoers scan follows visudo's complete native include graph"
assert_not_grep 'for candidate in "$sudoers_dir"/*' "$TMPDIR/cleanup.sh" \
    "sudoers scan is not limited to the conventional drop-in directory"
assert_grep_fixed \
    'FAILED postcondition: cannot parse or inspect active sudoers policy' \
    "$TMPDIR/cleanup.sh" "sudoers postcondition read failures fail closed"
assert_grep_fixed \
    'retire_exact_noid_live_sudoers /etc/sudoers.d/liveuser-nopasswd' \
    "$TMPDIR/cleanup.sh" "cleanup owns only M17's exact Live sudoers path"
assert_grep_fixed \
    'USBGUARD_LIVEUSER_IPC=/etc/usbguard/IPCAccessControl.d/liveuser' \
    "$TMPDIR/cleanup.sh" \
    "cleanup owns only the exact Live-user USBGuard IPC path"
assert_grep_fixed \
    'retire_exact_liveuser_usbguard_ipc "$USBGUARD_LIVEUSER_IPC"' \
    "$TMPDIR/cleanup.sh" \
    "installed transition retires the copied Live-user USBGuard IPC profile"
assert_grep_fixed \
    '<(emit_noid_usbguard_user_ipc_profile); then' \
    "$TMPDIR/cleanup.sh" \
    "Live-user USBGuard IPC retirement requires exact NoID Privacy profile bytes"
assert_grep_fixed \
    'FAILED: preserving noncanonical USBGuard Live-user IPC state' \
    "$TMPDIR/cleanup.sh" \
    "modified USBGuard authorization is preserved and fails closed"
assert_grep_fixed \
    'FAILED postcondition: USBGuard Live-user IPC state still exists' \
    "$TMPDIR/cleanup.sh" \
    "stale Live-user USBGuard IPC is a final blocking postcondition"
assert_not_grep_extended 'rm[[:space:]]+-rf.*USBGUARD_LIVEUSER_IPC|rm[[:space:]]+-rf.*IPCAccessControl' \
    "$TMPDIR/cleanup.sh" \
    "installer transition never recursively deletes USBGuard IPC state"
assert_not_grep '/etc/sudoers.d/[*]liveuser[*]' "$TMPDIR/cleanup.sh" \
    "cleanup never wildcard-deletes administrator sudoers files"
assert_grep_fixed \
    'FAILED: preserving unexplained active liveuser sudoers authorization' \
    "$TMPDIR/cleanup.sh" \
    "unknown liveuser authorization is preserved and fails closed"
assert_grep_fixed \
    'retire_exact_fedora_live_polkit_rule "$LIVE_POLKIT_RULE"' \
    "$TMPDIR/cleanup.sh" \
    "signed Fedora's runtime-only Live installer rule has an exact owner"
assert_grep_fixed \
    'FAILED postcondition: Fedora Live-installer polkit rule still exists' \
    "$TMPDIR/cleanup.sh" \
    "Live installer polkit authorization must be absent before success"
assert_grep_fixed \
    'retire_exact_noid_liveinst_umask_wrapper "$LIVEINST_UMASK_WRAPPER"' \
    "$TMPDIR/cleanup.sh" \
    "installed transition retires only M17's named Live launcher wrapper"
assert_grep_fixed \
    '<(emit_noid_liveinst_umask_wrapper); then' \
    "$TMPDIR/cleanup.sh" \
    "Live launcher retirement is authorized by exact M17 wrapper bytes"
assert_grep_fixed \
    'FAILED postcondition: M17 Live-installer wrapper still exists' \
    "$TMPDIR/cleanup.sh" \
    "Live launcher shadow must be absent before installed GDM starts"
assert_grep_fixed \
    'FAILED postcondition: GDM still targets liveuser for automatic/timed login' \
    "$TMPDIR/cleanup.sh" "all liveuser GDM login targets are verified absent"
assert_grep_fixed 'reconcile_gdm_log_directory "$GDM_LOG_DIR"' \
    "$TMPDIR/cleanup.sh" \
    "pre-login transition establishes GDM's native log-directory contract"
assert_grep_fixed 'chown "$expected_uid:$gdm_gid" -- "$target"' \
    "$TMPDIR/cleanup.sh" \
    "GDM log directory uses the native root:gdm ownership contract"
assert_grep_fixed 'chmod 0711 -- "$target"' "$TMPDIR/cleanup.sh" \
    "GDM log directory uses the native 0711 mode"
assert_grep_fixed 'restorecon -F -- "$target"' "$TMPDIR/cleanup.sh" \
    "GDM log directory is relabeled before the first daemon start"
assert_grep_fixed 'matchpathcon -V "$GDM_LOG_DIR"' \
    "$TMPDIR/cleanup.sh" \
    "pre-login completion rechecks the GDM log-directory SELinux label"
assert_grep_fixed \
    'FAILED postcondition: GDM log directory contract drifted before login' \
    "$TMPDIR/cleanup.sh" \
    "GDM cannot start after metadata or label drift"
assert_not_grep 'restorecon -RF -- "$target"' "$TMPDIR/cleanup.sh" \
    "GDM log reconciliation never relabels existing log payload recursively"
assert_grep_fixed 'TimedLoginEnable=False' "$TMPDIR/cleanup.sh" \
    "installed target disables Live timed login"
assert_grep_fixed '# TimedLogin=liveuser  ## removed by noid-anaconda-cleanup' \
    "$TMPDIR/cleanup.sh" "installed target retires the Live timed-login user"
assert_grep_fixed '# TimedLoginDelay=1  ## removed by noid-anaconda-cleanup' \
    "$TMPDIR/cleanup.sh" "installed target retires the Live re-login delay"
assert_grep_fixed 'systemctl disable --now chronyd.service' "$TMPDIR/cleanup.sh" \
    "target cleanup disables and stops ordinary chronyd"
assert_grep_fixed 'systemctl enable --now chronyd-restricted.service' \
    "$TMPDIR/cleanup.sh" \
    "target cleanup enables and starts the restricted chronyd provider"
assert_grep_fixed 'active restricted chronyd-provider' \
    "$KS_FILE" "module scope names the fail-closed chronyd provider change"
chrony_reconcile_line=$(grep -nF 'systemctl disable --now chronyd.service' \
    "$TMPDIR/cleanup.sh" | cut -d: -f1)
done_marker_line=$(grep -nF \
    'DONE_VALUE=$(date -u +"%Y-%m-%dT%H:%M:%SZ cleanup_count=$CLEANUP_COUNT")' \
    "$TMPDIR/cleanup.sh" | cut -d: -f1)
if [ -n "$chrony_reconcile_line" ] && [ -n "$done_marker_line" ] \
   && [ "$chrony_reconcile_line" -lt "$done_marker_line" ]; then
    _pass "chronyd provider is reconciled before the done marker"
else
    _fail "cleanup can seal success before chronyd provider reconciliation"
fi

# Never create /var/lib/AccountsService/users as a regular file on systems
# without AccountsService, never delete unrelated identity state, and never
# hide NM's post-archive reload failure.
assert_not_grep 'touch /var/lib/AccountsService/users.*|| true' "$TMPDIR/cleanup.sh" \
    "AccountsService nudge is not an unconditional swallowed touch"
assert_grep_fixed \
    'ACCOUNTS_LIVEUSER_ENTRY=$ACCOUNTS_USERS_DIR/liveuser' \
    "$TMPDIR/cleanup.sh" "AccountsService cleanup targets only liveuser"
assert_not_grep 'for user_file in /var/lib/AccountsService/users/' \
    "$TMPDIR/cleanup.sh" \
    "AccountsService cleanup never scans and deletes unrelated identities"
assert_grep_fixed \
    'FAILED postcondition: AccountsService liveuser state still exists' \
    "$TMPDIR/cleanup.sh" \
    "AccountsService liveuser absence is rechecked before success"
assert_grep_fixed 'GHOST_COUNT=$((GHOST_COUNT + 1))' "$TMPDIR/cleanup.sh" \
    "NetworkManager reload is keyed to actual compose-profile archives"
assert_grep_fixed \
    'BUILD_NM_MANIFEST=/usr/lib/noid-privacy/anaconda-build-nm-profile-sha256' \
    "$TMPDIR/cleanup.sh" \
    "runtime NetworkManager cleanup requires build-owned exact-byte evidence"
assert_grep_fixed \
    '[ -n "${BUILD_NM_DIGEST_SEEN[$actual_profile_sha]:-}" ] || continue' \
    "$TMPDIR/cleanup.sh" \
    "an unrecorded NetworkManager profile is never archived"
assert_grep_fixed '[ "$base" = "$ifname.nmconnection" ]' \
    "$TMPDIR/cleanup.sh" \
    "runtime profile name remains bound to the recorded interface"
assert_not_grep 'nmcli connection reload.*|| true' "$TMPDIR/cleanup.sh" \
    "NetworkManager reload failure is visible"
# The compose profile is bound to the build VM's interface name, so every real
# installation archives it on its first boot and reaches the reload branch. This
# unit is only `After=NetworkManager.service`, which a dependency-failed NM job
# satisfies, and gdm.service hard-requires this unit: an unconditional reload
# against an absent daemon therefore removes the graphical login entirely.
# The archival itself is already durable at that point; NetworkManager re-reads
# system-connections on its next start.
assert_grep_fixed 'systemctl is-active --quiet NetworkManager.service' \
    "$TMPDIR/cleanup.sh" \
    "the post-archive reload is gated on a running NetworkManager"
assert_grep_fixed 'the archived compose profile is already off disk' \
    "$TMPDIR/cleanup.sh" \
    "an inactive NetworkManager is reported, not treated as a cleanup failure"
assert_grep_fixed 'systemctl reload NetworkManager.service' "$TMPDIR/cleanup.sh" \
    "missing nmcli has a checked NetworkManager reload fallback"
assert_grep_fixed 'FAILED: cannot count regular passwd users' "$TMPDIR/cleanup.sh" \
    "passwd count failure has an explicit diagnostic"
assert_grep_fixed 'FAILED: cannot inspect preserved home directories' "$TMPDIR/cleanup.sh" \
    "home count failure has an explicit diagnostic"
assert_grep_fixed '[ -e /run/livesys ]' "$TMPDIR/cleanup.sh" \
    "script-level Live ISO guard is type-agnostic"
assert_not_grep 'touch /etc/gdm/run-initial-setup' "$TMPDIR/cleanup.sh" \
    "cleanup never creates the obsolete GDM marker"
assert_grep_fixed 'reconcile_gdm_initial_setup_policy' "$TMPDIR/cleanup.sh" \
    "GDM policy is isolated for behavioral fixture coverage"
assert_grep_fixed 'gis_initial_setup_enable=false' "$TMPDIR/cleanup.sh" \
    "preserved-home reinstall selects the actual GDM disable value"
assert_grep_fixed 'GDM InitialSetupEnable did not converge' "$TMPDIR/cleanup.sh" \
    "GDM policy has an exact postcondition"

# Exercise all three GDM policy branches against isolated files. GDM 50.1
# ignores the retired marker, so only the exact InitialSetupEnable result can
# distinguish a fresh install from a preserved-home reinstall.
extract_function root_password_hash_is_locked "$TMPDIR/cleanup.sh" \
    "$TMPDIR/root-lock-function.sh"
assert_cmd_success "isolated root-lock predicate is valid bash" \
    bash -n "$TMPDIR/root-lock-function.sh"
# shellcheck source=/dev/null
. "$TMPDIR/root-lock-function.sh"
for locked_hash in '!' '!!' '!$y$preserved-hash' '*'; do
    if root_password_hash_is_locked "$locked_hash"; then
        _pass "root lock predicate accepts locked field: $locked_hash"
    else
        _fail "root lock predicate rejected locked field: $locked_hash"
    fi
done
for unlocked_hash in '' '$y$unlocked-hash'; do
    if root_password_hash_is_locked "$unlocked_hash"; then
        _fail "root lock predicate accepted unlocked field: ${unlocked_hash:-empty}"
    else
        _pass "root lock predicate rejects unlocked field: ${unlocked_hash:-empty}"
    fi
done

# The account-facing path must disappear without deleting bytes. Exercise a
# regular tree, a symlink, collisions, mount evidence and an interruption after
# rename against the exact production helper.
remnant_uid=$(id -u)
remnant_gid=$(id -g)
remnant_user=$(id -un)
remnant_group=$(id -gn)
remnant_root="$TMPDIR/live-remnant"
remnant_mail_parent="$remnant_root/mail"
extract_function trusted_nonwritable_directory "$TMPDIR/cleanup.sh" \
    "$TMPDIR/live-remnant-functions.raw"
extract_function trusted_quarantine_source_parent "$TMPDIR/cleanup.sh" \
    "$TMPDIR/live-remnant-functions.raw" append
extract_function quarantine_exact_liveuser_remnant "$TMPDIR/cleanup.sh" \
    "$TMPDIR/live-remnant-functions.raw" append
sed -e "s/0:0/$remnant_uid:$remnant_gid/g" \
    -e "s#/var/spool/mail#$remnant_mail_parent#g" \
    -e "s/root:mail:775/$remnant_user:$remnant_group:775/g" \
    "$TMPDIR/live-remnant-functions.raw" \
    > "$TMPDIR/live-remnant-functions.sh"
assert_cmd_success "isolated Live-remnant quarantine functions are valid bash" \
    bash -n "$TMPDIR/live-remnant-functions.sh"
# shellcheck source=/dev/null
. "$TMPDIR/live-remnant-functions.sh"
# These fixture replacements are called from the production helper sourced
# above; ShellCheck cannot follow that indirect call graph.
# shellcheck disable=SC2317,SC2329
log() { :; }
# shellcheck disable=SC2317,SC2329
restorecon() { :; }
# shellcheck disable=SC2317,SC2329
matchpathcon() { :; }
findmnt() {
    [ -z "${M41_FINDMNT_FIXTURE:-}" ] \
        || printf '%s\n' "$M41_FINDMNT_FIXTURE"
}

remnant_parent="$remnant_root/home"
remnant_quarantine="$remnant_parent/.noid-liveuser-quarantine"
remnant_source="$remnant_parent/liveuser"
mkdir -p "$remnant_source/Documents"
printf '%s\n' 'must survive first boot' \
    > "$remnant_source/Documents/user-data.txt"
chmod 0755 "$remnant_parent"
CLEANUP_COUNT=0
quarantine_exact_liveuser_remnant "$remnant_source" "$remnant_quarantine" \
    home-entry "$remnant_uid" "$remnant_gid"
assert_cmd_failure "account-facing home path is absent after quarantine" \
    test -e "$remnant_source"
assert_grep_fixed 'must survive first boot' \
    "$remnant_quarantine/home-entry/Documents/user-data.txt" \
    "preserved-home bytes survive first-boot cleanup"
assert_eq 1 "$CLEANUP_COUNT" \
    "successful Live-home quarantine contributes one cleanup item"

rm -rf -- "$remnant_quarantine"
mkdir -p "$remnant_source"
printf '%s\n' 'must survive unsafe parent' > "$remnant_source/value"
chmod 0775 "$remnant_parent"
assert_cmd_failure "group-writable general parent blocks quarantine" \
    quarantine_exact_liveuser_remnant "$remnant_source" \
        "$remnant_quarantine" home-entry "$remnant_uid" "$remnant_gid"
assert_grep_fixed 'must survive unsafe parent' "$remnant_source/value" \
    "unsafe-parent rejection preserves the source bytes"
chmod 0755 "$remnant_parent"

# Exercise Fedora's exact native mail-spool exception, including the retained
# canonical-directory boundary that prevents accepting a symlinked parent.
remnant_mail_real="$remnant_root/mail-real"
mkdir -p "$remnant_mail_real"
chmod 0775 "$remnant_mail_real"
ln -s "$remnant_mail_real" "$remnant_mail_parent"
mkdir -p "$remnant_mail_parent/liveuser"
printf '%s\n' 'must survive symlinked mail parent' \
    > "$remnant_mail_parent/liveuser/value"
assert_cmd_failure "symlinked mail-spool exception is rejected" \
    quarantine_exact_liveuser_remnant "$remnant_mail_parent/liveuser" \
        "$remnant_mail_parent/.noid-liveuser-quarantine" mail-entry \
        "$remnant_uid" "$remnant_gid"
assert_grep_fixed 'must survive symlinked mail parent' \
    "$remnant_mail_parent/liveuser/value" \
    "symlinked mail-parent rejection preserves source bytes"
rm -f -- "$remnant_mail_parent"
mv -- "$remnant_mail_real" "$remnant_mail_parent"
CLEANUP_COUNT=0
quarantine_exact_liveuser_remnant "$remnant_mail_parent/liveuser" \
    "$remnant_mail_parent/.noid-liveuser-quarantine" mail-entry \
    "$remnant_uid" "$remnant_gid"
assert_grep_fixed 'must survive symlinked mail parent' \
    "$remnant_mail_parent/.noid-liveuser-quarantine/mail-entry/value" \
    "exact native writable mail-spool exception preserves bytes"
assert_eq 1 "$CLEANUP_COUNT" \
    "exact native writable mail-spool exception is accepted"

rm -rf -- "$remnant_source" "$remnant_quarantine"
external_target="$remnant_root/external-data"
printf '%s\n' 'external bytes' > "$external_target"
ln -s "$external_target" "$remnant_source"
CLEANUP_COUNT=0
quarantine_exact_liveuser_remnant "$remnant_source" "$remnant_quarantine" \
    home-entry "$remnant_uid" "$remnant_gid"
assert_grep_fixed 'external bytes' "$external_target" \
    "quarantining a symlink never dereferences or deletes its target"
if [ -L "$remnant_quarantine/home-entry" ]; then
    _pass "exact Live-home symlink itself is quarantined"
else
    _fail "exact Live-home symlink itself is quarantined"
fi

rm -rf -- "$remnant_quarantine"
mkdir -p "$remnant_source" "$remnant_quarantine"
chmod 0700 "$remnant_quarantine"
printf '%s\n' source > "$remnant_source/value"
printf '%s\n' existing > "$remnant_quarantine/home-entry"
assert_cmd_failure "existing recovery target blocks a destructive overwrite" \
    quarantine_exact_liveuser_remnant "$remnant_source" \
        "$remnant_quarantine" home-entry "$remnant_uid" "$remnant_gid"
assert_grep_fixed source "$remnant_source/value" \
    "quarantine collision preserves the source tree"
assert_grep_fixed existing "$remnant_quarantine/home-entry" \
    "quarantine collision preserves prior recovery evidence"

rm -rf -- "$remnant_source" "$remnant_quarantine"
mkdir -p "$remnant_source" "$remnant_quarantine"
chmod 0700 "$remnant_quarantine"
printf '%s\n' source-race > "$remnant_source/value"
set +e
(
    # Inject a destination after the helper's precheck but immediately before
    # its production mv call.
    # shellcheck disable=SC2317,SC2329
    mv() {
        printf '%s\n' competing-race > "$remnant_quarantine/home-entry"
        /usr/bin/mv "$@"
    }
    quarantine_exact_liveuser_remnant "$remnant_source" \
        "$remnant_quarantine" home-entry "$remnant_uid" "$remnant_gid"
)
remnant_race_rc=$?
set -e
assert_eq 1 "$remnant_race_rc" \
    "publication-time recovery collision fails closed"
assert_grep_fixed source-race "$remnant_source/value" \
    "publication-time collision preserves the source tree"
assert_grep_fixed competing-race "$remnant_quarantine/home-entry" \
    "publication-time collision preserves the competing recovery target"

rm -rf -- "$remnant_source" "$remnant_quarantine"
mkdir -p "$remnant_source"
printf '%s\n' mounted > "$remnant_source/value"
M41_FINDMNT_FIXTURE="$remnant_source/nested"
assert_cmd_failure "nested mount evidence blocks the rename" \
    quarantine_exact_liveuser_remnant "$remnant_source" \
        "$remnant_quarantine" home-entry "$remnant_uid" "$remnant_gid"
unset M41_FINDMNT_FIXTURE
assert_grep_fixed mounted "$remnant_source/value" \
    "mount-bearing source remains untouched for manual review"

rm -rf -- "$remnant_source" "$remnant_quarantine"
mkdir -p "$remnant_source" "$remnant_quarantine"
chmod 0700 "$remnant_quarantine"
printf '%s\n' durable > "$remnant_source/value"
set +e
(
    # Invoked indirectly by quarantine_exact_liveuser_remnant in this subshell.
    # shellcheck disable=SC2317,SC2329
    sync() { return 1; }
    quarantine_exact_liveuser_remnant "$remnant_source" \
        "$remnant_quarantine" home-entry "$remnant_uid" "$remnant_gid"
)
remnant_sync_rc=$?
set -e
assert_eq 1 "$remnant_sync_rc" \
    "post-rename durability failure remains visible"
assert_grep_fixed durable "$remnant_quarantine/home-entry/value" \
    "post-rename failure retains the complete quarantined tree"
retry_sync_log="$TMPDIR/live-remnant-retry-sync.log"
set +e
(
    # shellcheck disable=SC2317,SC2329
    sync() {
        printf '%s\n' "$*" >> "$retry_sync_log"
    }
    quarantine_exact_liveuser_remnant "$remnant_source" \
        "$remnant_quarantine" home-entry "$remnant_uid" "$remnant_gid"
)
remnant_retry_rc=$?
set -e
assert_eq 0 "$remnant_retry_rc" \
    "retry after atomic rename revalidates the published quarantine"
assert_grep_fixed "$remnant_quarantine" "$retry_sync_log" \
    "retry makes the quarantine directory durable"
assert_grep_fixed "$remnant_parent" "$retry_sync_log" \
    "retry makes the source parent durable"

# Exact known Live-authorization bytes may be retired. Modified or unrelated
# administrator policies must remain present and become a blocking diagnostic.
extract_function trusted_nonwritable_directory "$TMPDIR/cleanup.sh" \
    "$TMPDIR/live-auth-functions.sh"
extract_function emit_noid_liveinst_umask_wrapper "$TMPDIR/cleanup.sh" \
    "$TMPDIR/live-auth-functions.sh" append
extract_function retire_exact_noid_liveinst_umask_wrapper \
    "$TMPDIR/cleanup.sh" "$TMPDIR/live-auth-functions.sh" append
extract_function retire_exact_noid_live_sudoers "$TMPDIR/cleanup.sh" \
    "$TMPDIR/live-auth-functions.sh" append
extract_function active_liveuser_sudoers_refs "$TMPDIR/cleanup.sh" \
    "$TMPDIR/live-auth-functions.sh" append
extract_function retire_exact_fedora_live_polkit_rule "$TMPDIR/cleanup.sh" \
    "$TMPDIR/live-auth-functions.sh" append
assert_cmd_success "isolated Live-authorization functions are valid bash" \
    bash -n "$TMPDIR/live-auth-functions.sh"
# shellcheck source=/dev/null
. "$TMPDIR/live-auth-functions.sh"
# Called indirectly by the sourced functions above.
# shellcheck disable=SC2317,SC2329
log() { :; }

# The PATH shadow is build-owned only while the Live installer is available.
# Exact bytes retire; changed bytes and symlinks remain visible and blocking.
(
    wrapper_parent="$TMPDIR/liveinst-wrapper-exact"
    wrapper_target="$wrapper_parent/liveinst"
    mkdir -p "$wrapper_parent"
    chmod 0755 "$wrapper_parent"
    emit_noid_liveinst_umask_wrapper > "$wrapper_target"
    chmod 0755 "$wrapper_target"
    # The sourced retirement function invokes this fixture-local replacement.
    # shellcheck disable=SC2317,SC2329
    matchpathcon() { :; }
    CLEANUP_COUNT=0
    retire_exact_noid_liveinst_umask_wrapper "$wrapper_target" \
        "$(id -u):$(id -g):755:1" "$(id -u):$(id -g)"
    [ ! -e "$wrapper_target" ] && [ ! -L "$wrapper_target" ] \
        && [ "$CLEANUP_COUNT" -eq 1 ]
) && _pass "exact M17 Live-installer wrapper is retired" \
  || _fail "exact M17 Live-installer wrapper retirement"
(
    wrapper_parent="$TMPDIR/liveinst-wrapper-modified"
    wrapper_target="$wrapper_parent/liveinst"
    mkdir -p "$wrapper_parent"
    chmod 0755 "$wrapper_parent"
    printf '%s\n' 'administrator-modified bytes' > "$wrapper_target"
    chmod 0755 "$wrapper_target"
    # shellcheck disable=SC2317,SC2329
    matchpathcon() { :; }
    CLEANUP_COUNT=0
    ! retire_exact_noid_liveinst_umask_wrapper "$wrapper_target" \
        "$(id -u):$(id -g):755:1" "$(id -u):$(id -g)" \
        && grep -qxF 'administrator-modified bytes' "$wrapper_target" \
        && [ "$CLEANUP_COUNT" -eq 0 ]
) && _pass "modified Live-installer wrapper is preserved and blocks cleanup" \
  || _fail "modified Live-installer wrapper fail-closed behavior"
(
    wrapper_parent="$TMPDIR/liveinst-wrapper-symlink"
    wrapper_target="$wrapper_parent/liveinst"
    wrapper_victim="$wrapper_parent/victim"
    mkdir -p "$wrapper_parent"
    chmod 0755 "$wrapper_parent"
    printf '%s\n' 'must survive' > "$wrapper_victim"
    ln -s "$wrapper_victim" "$wrapper_target"
    # shellcheck disable=SC2317,SC2329
    matchpathcon() { :; }
    CLEANUP_COUNT=0
    ! retire_exact_noid_liveinst_umask_wrapper "$wrapper_target" \
        "$(id -u):$(id -g):755:1" "$(id -u):$(id -g)" \
        && [ -L "$wrapper_target" ] \
        && grep -qxF 'must survive' "$wrapper_victim" \
        && [ "$CLEANUP_COUNT" -eq 0 ]
) && _pass "symlinked Live-installer wrapper path is preserved and blocks cleanup" \
  || _fail "symlinked Live-installer wrapper fail-closed behavior"

# Anaconda copies M14's exact Live-user ACL into the installed root. Exercise
# the separately owned, byte-gated retirement before the broader sudoers and
# polkit fixtures below.
extract_function trusted_nonwritable_directory "$TMPDIR/cleanup.sh" \
    "$TMPDIR/live-usbguard-ipc-functions.sh"
extract_function emit_noid_usbguard_user_ipc_profile "$TMPDIR/cleanup.sh" \
    "$TMPDIR/live-usbguard-ipc-functions.sh" append
extract_function retire_exact_liveuser_usbguard_ipc "$TMPDIR/cleanup.sh" \
    "$TMPDIR/live-usbguard-ipc-functions.sh" append
assert_cmd_success "isolated Live USBGuard IPC retirement functions are valid bash" \
    bash -n "$TMPDIR/live-usbguard-ipc-functions.sh"
(
    # shellcheck source=/dev/null
    . "$TMPDIR/live-usbguard-ipc-functions.sh"
    ipc_parent="$TMPDIR/live-usbguard-ipc-exact"
    ipc_target="$ipc_parent/liveuser"
    mkdir -p "$ipc_parent"
    chmod 0755 "$ipc_parent"
    emit_noid_usbguard_user_ipc_profile > "$ipc_target"
    chmod 0600 "$ipc_target"
    # The sourced retirement function invokes this fixture-local replacement.
    # shellcheck disable=SC2317,SC2329
    matchpathcon() { :; }
    CLEANUP_COUNT=0
    retire_exact_liveuser_usbguard_ipc "$ipc_target" \
        "$(id -u):$(id -g):600:1" "$(id -u):$(id -g)"
    [ ! -e "$ipc_target" ] && [ ! -L "$ipc_target" ] \
        && [ "$CLEANUP_COUNT" -eq 1 ]
) && _pass "exact copied Live-user USBGuard IPC profile is retired" \
  || _fail "exact copied Live-user USBGuard IPC retirement"
(
    # shellcheck source=/dev/null
    . "$TMPDIR/live-usbguard-ipc-functions.sh"
    ipc_parent="$TMPDIR/live-usbguard-ipc-modified"
    ipc_target="$ipc_parent/liveuser"
    mkdir -p "$ipc_parent"
    chmod 0755 "$ipc_parent"
    printf '%s\n' 'administrator-modified bytes' > "$ipc_target"
    chmod 0600 "$ipc_target"
    # The sourced retirement function invokes this fixture-local replacement.
    # shellcheck disable=SC2317,SC2329
    matchpathcon() { :; }
    CLEANUP_COUNT=0
    ! retire_exact_liveuser_usbguard_ipc "$ipc_target" \
        "$(id -u):$(id -g):600:1" "$(id -u):$(id -g)" \
        && grep -qxF 'administrator-modified bytes' "$ipc_target" \
        && [ "$CLEANUP_COUNT" -eq 0 ]
) && _pass "modified Live-user USBGuard IPC state is preserved and blocks cleanup" \
  || _fail "modified Live-user USBGuard IPC fail-closed behavior"

fixture_uid=$(id -u)
fixture_gid=$(id -g)
auth_root="$TMPDIR/live-auth"
sudoers_dir="$auth_root/sudoers.d"
polkit_dir="$auth_root/polkit-rules.d"
mkdir -p "$sudoers_dir" "$polkit_dir"
chmod 0755 "$auth_root" "$sudoers_dir" "$polkit_dir"
external_sudoers="$auth_root/external-policy"
printf '%s\n' '# no Live authorization' > "$external_sudoers"
chmod 0440 "$external_sudoers"
printf '%s\n' \
    'Defaults env_reset' \
    "@includedir $sudoers_dir" \
    "@include $external_sudoers" > "$auth_root/sudoers"
chmod 0440 "$auth_root/sudoers"
live_sudoers="$sudoers_dir/liveuser-nopasswd"
printf '%s\n' \
    'Defaults:liveuser verifypw=any' \
    'liveuser ALL=(ALL) NOPASSWD: ALL' > "$live_sudoers"
chmod 0440 "$live_sudoers"
CLEANUP_COUNT=0
retire_exact_noid_live_sudoers "$live_sudoers" \
    "$fixture_uid:$fixture_gid:440:1" "$fixture_uid:$fixture_gid"
if [ ! -e "$live_sudoers" ] && [ ! -L "$live_sudoers" ]; then
    _pass "byte-exact M17 Live sudoers policy is retired"
else
    _fail "byte-exact M17 Live sudoers policy remains"
fi
assert_eq 1 "$CLEANUP_COUNT" \
    "exact M17 sudoers retirement contributes one cleanup item"

printf '%s\n' \
    'Defaults:liveuser verifypw=any' \
    'liveuser ALL=(ALL) NOPASSWD: ALL' \
    '# administrator changed this file' > "$live_sudoers"
chmod 0440 "$live_sudoers"
if retire_exact_noid_live_sudoers "$live_sudoers" \
        "$fixture_uid:$fixture_gid:440:1" "$fixture_uid:$fixture_gid"; then
    _fail "modified Live sudoers bytes are rejected"
else
    _pass "modified Live sudoers bytes are rejected"
fi
assert_grep_fixed '# administrator changed this file' "$live_sudoers" \
    "modified sudoers policy is preserved for review"

rm -f -- "$live_sudoers"
unknown_sudoers="$sudoers_dir/local-admin"
printf '%s\n' 'liveuser ALL=(root) /usr/bin/id' > "$unknown_sudoers"
chmod 0440 "$unknown_sudoers"
if active_liveuser_sudoers_refs "$auth_root/sudoers" "$sudoers_dir"; then
    _pass "unexplained active liveuser sudoers authorization is detected"
else
    _fail "unexplained active liveuser sudoers authorization was missed"
fi
assert_grep_fixed 'liveuser ALL=(root) /usr/bin/id' "$unknown_sudoers" \
    "unknown administrator sudoers bytes remain untouched"
chmod 0640 "$unknown_sudoers"
printf '%s\n' '# liveuser is mentioned only in a comment' > "$unknown_sudoers"
chmod 0440 "$unknown_sudoers"
set +e
active_liveuser_sudoers_refs "$auth_root/sudoers" "$sudoers_dir"
sudoers_comment_rc=$?
set -e
assert_eq 1 "$sudoers_comment_rc" \
    "comment-only liveuser text is not misclassified as authorization"

chmod 0640 "$external_sudoers"
printf '%s\n' 'liveuser ALL=(root) /usr/bin/true' > "$external_sudoers"
chmod 0440 "$external_sudoers"
if active_liveuser_sudoers_refs "$auth_root/sudoers"; then
    _pass "active liveuser policy in an external nested include is detected"
else
    _fail "active liveuser policy in an external nested include was missed"
fi
assert_grep_fixed 'liveuser ALL=(root) /usr/bin/true' "$external_sudoers" \
    "external administrator include remains untouched"
chmod 0640 "$external_sudoers"
printf '%s\n' '# no Live authorization' > "$external_sudoers"
chmod 0440 "$external_sudoers"

live_polkit="$polkit_dir/20-livesys-gnome.rules"
cat > "$live_polkit" <<'LIVE_POLKIT_FIXTURE_EOF'
polkit.addRule(function(action, subject) {
    if (!subject.local)
        return undefined;
    if (subject.user !== 'liveuser')
        return undefined;
    if (action.id.indexOf('org.fedoraproject.pkexec.liveinst') !== 0)
        return undefined;
    return 'yes';
});
LIVE_POLKIT_FIXTURE_EOF
chmod 0644 "$live_polkit"
CLEANUP_COUNT=0
retire_exact_fedora_live_polkit_rule "$live_polkit" \
    "$fixture_uid:$fixture_gid:644:1" "$fixture_uid:$fixture_gid"
if [ ! -e "$live_polkit" ] && [ ! -L "$live_polkit" ]; then
    _pass "byte-exact signed-Fedora Live polkit rule is retired"
else
    _fail "byte-exact signed-Fedora Live polkit rule remains"
fi
assert_eq 1 "$CLEANUP_COUNT" \
    "exact Fedora polkit retirement contributes one cleanup item"
printf '%s\n' 'polkit.addRule(function() { return true; });' > "$live_polkit"
chmod 0644 "$live_polkit"
if retire_exact_fedora_live_polkit_rule "$live_polkit" \
        "$fixture_uid:$fixture_gid:644:1" "$fixture_uid:$fixture_gid"; then
    _fail "modified Live polkit bytes are rejected"
else
    _pass "modified Live polkit bytes are rejected"
fi
assert_grep_fixed 'return true' "$live_polkit" \
    "modified polkit rule is preserved for review"

# Exercise the exact pre-GDM log-directory reconciler. The function's numeric
# root/group constants are replaced only in the isolated user-owned fixture;
# its metadata, label, idempotence and unsafe-type decisions remain unchanged.
extract_function reconcile_gdm_log_directory "$TMPDIR/cleanup.sh" \
    "$TMPDIR/gdm-log-function.raw"
sed -e "s/local expected_uid=0/local expected_uid=$fixture_uid/" \
    -e "s/0:0:755/$fixture_uid:$fixture_gid:755/" \
    -e "s|getent -s files group gdm|printf 'gdm:x:$fixture_gid:'|" \
    "$TMPDIR/gdm-log-function.raw" > "$TMPDIR/gdm-log-function.sh"
assert_cmd_success "isolated GDM log reconciler is valid bash" \
    bash -n "$TMPDIR/gdm-log-function.sh"
# shellcheck source=/dev/null
. "$TMPDIR/gdm-log-function.sh"
# Called indirectly by the extracted production function.
# shellcheck disable=SC2317,SC2329
log() { :; }
M41_GDM_LABEL_OK=0
# shellcheck disable=SC2317,SC2329
restorecon() { M41_GDM_LABEL_OK=1; }
# shellcheck disable=SC2317,SC2329
matchpathcon() { [ "$M41_GDM_LABEL_OK" -eq 1 ]; }

gdm_log_parent="$TMPDIR/gdm-log-native"
gdm_log_fixture="$gdm_log_parent/gdm"
mkdir -p "$gdm_log_parent"
chmod 0755 "$gdm_log_parent"
CLEANUP_COUNT=0
GDM_LOG_GID=""
reconcile_gdm_log_directory "$gdm_log_fixture"
assert_eq "$fixture_uid:$fixture_gid:711" \
    "$(stat -Lc '%u:%g:%a' -- "$gdm_log_fixture")" \
    "missing GDM log directory converges to native ownership and mode"
assert_eq "$fixture_gid" "$GDM_LOG_GID" \
    "GDM log reconciliation retains the verified local group postcondition"
assert_eq "1" "$M41_GDM_LABEL_OK" \
    "new GDM log directory is relabeled before use"
assert_eq "1" "$CLEANUP_COUNT" \
    "new GDM log directory contributes one cleanup item"

CLEANUP_COUNT=0
reconcile_gdm_log_directory "$gdm_log_fixture"
assert_eq "0" "$CLEANUP_COUNT" \
    "canonical GDM log directory reconciliation is idempotent"

chmod 0700 "$gdm_log_fixture"
M41_GDM_LABEL_OK=0
CLEANUP_COUNT=0
reconcile_gdm_log_directory "$gdm_log_fixture"
assert_eq "$fixture_uid:$fixture_gid:711" \
    "$(stat -Lc '%u:%g:%a' -- "$gdm_log_fixture")" \
    "existing GDM log metadata is restored to the native contract"
assert_eq "1" "$M41_GDM_LABEL_OK" \
    "existing GDM log label drift is repaired"
assert_eq "1" "$CLEANUP_COUNT" \
    "metadata and label drift contributes one cleanup item"

rm -rf -- "$gdm_log_fixture"
ln -s / "$gdm_log_fixture"
M41_GDM_LABEL_OK=0
CLEANUP_COUNT=0
if reconcile_gdm_log_directory "$gdm_log_fixture"; then
    _fail "symlinked GDM log path is rejected before mutation"
else
    _pass "symlinked GDM log path is rejected before mutation"
fi
assert_eq "/" "$(readlink -- "$gdm_log_fixture")" \
    "unsafe GDM log symlink is preserved for review"
assert_eq "0" "$CLEANUP_COUNT" \
    "rejected GDM log path does not claim a cleanup item"

extract_function gdm_daemon_key_value_count "$TMPDIR/cleanup.sh" \
    "$TMPDIR/gdm-login-functions.raw"
extract_function retire_liveuser_gdm_login "$TMPDIR/cleanup.sh" \
    "$TMPDIR/gdm-login-functions.raw" append
sed "s/0:0:644:1/$fixture_uid:$fixture_gid:644:1/g" \
    "$TMPDIR/gdm-login-functions.raw" \
    > "$TMPDIR/gdm-login-functions.sh"
assert_cmd_success "isolated GDM Live-login functions are valid bash" \
    bash -n "$TMPDIR/gdm-login-functions.sh"
# shellcheck source=/dev/null
. "$TMPDIR/gdm-login-functions.sh"
# Called indirectly by the extracted production function.
# shellcheck disable=SC2317,SC2329
log() { :; }
restorecon() { :; }
matchpathcon() { :; }

login_fixture_dir="$TMPDIR/gdm-live-login"
mkdir -p "$login_fixture_dir"
login_custom_conf="$login_fixture_dir/custom.conf"
printf '%s' \
    $'[daemon]\nAutomaticLoginEnable=True\nAutomaticLogin=liveuser\nTimedLoginEnable=true\nTimedLogin=liveuser\nTimedLoginDelay=1\n\n[security]\nAutomaticLogin=liveuser\n' \
    > "$login_custom_conf"
chmod 0644 "$login_custom_conf"
CLEANUP_COUNT=0
retire_liveuser_gdm_login "$login_custom_conf"
assert_eq "0" \
    "$(gdm_daemon_key_value_count \
        "$login_custom_conf" AutomaticLogin liveuser)" \
    "GDM daemon automatic login no longer targets liveuser"
assert_eq "0" \
    "$(gdm_daemon_key_value_count \
        "$login_custom_conf" TimedLogin liveuser)" \
    "GDM daemon timed login no longer targets liveuser"
assert_grep_fixed 'AutomaticLoginEnable=False' "$login_custom_conf" \
    "liveuser automatic login is disabled"
assert_grep_fixed 'TimedLoginEnable=False' "$login_custom_conf" \
    "liveuser timed login is disabled"
assert_grep_fixed '[security]' "$login_custom_conf" \
    "GDM Live-login retirement preserves unrelated sections"
assert_eq "1" \
    "$(awk '/^\[security\]$/{in_security=1; next} in_security && /^AutomaticLogin=liveuser$/{count++} END{print count+0}' \
        "$login_custom_conf")" \
    "an inert same-named key outside daemon remains untouched"
assert_eq "1" "$CLEANUP_COUNT" \
    "GDM Live-login retirement records one atomic policy change"

unrelated_login_conf="$TMPDIR/gdm-unrelated-login.conf"
printf '%s' \
    $'[daemon]\nAutomaticLoginEnable=True\nAutomaticLogin=alice\nTimedLoginEnable=True\nTimedLogin=alice\nTimedLoginDelay=1\n' \
    > "$unrelated_login_conf"
chmod 0644 "$unrelated_login_conf"
unrelated_before=$(sha256sum "$unrelated_login_conf" | awk '{print $1}')
CLEANUP_COUNT=0
retire_liveuser_gdm_login "$unrelated_login_conf"
assert_eq "$unrelated_before" \
    "$(sha256sum "$unrelated_login_conf" | awk '{print $1}')" \
    "legitimate non-liveuser automatic login bytes remain unchanged"
assert_eq "0" "$CLEANUP_COUNT" \
    "unchanged non-liveuser login does not increment cleanup evidence"

duplicate_login_conf="$TMPDIR/gdm-duplicate-login.conf"
printf '%s' \
    $'[daemon]\nAutomaticLogin=liveuser\n[daemon]\nAutomaticLoginEnable=True\n' \
    > "$duplicate_login_conf"
chmod 0644 "$duplicate_login_conf"
duplicate_login_before=$(sha256sum "$duplicate_login_conf" | awk '{print $1}')
CLEANUP_COUNT=0
if retire_liveuser_gdm_login "$duplicate_login_conf"; then
    _fail "duplicate GDM daemon sections are rejected before Live-login edits"
else
    _pass "duplicate GDM daemon sections are rejected before Live-login edits"
fi
assert_eq "$duplicate_login_before" \
    "$(sha256sum "$duplicate_login_conf" | awk '{print $1}')" \
    "malformed GDM Live-login bytes are not partially rewritten"

extract_function reconcile_gdm_initial_setup_policy "$TMPDIR/cleanup.sh" \
    "$TMPDIR/gdm-policy-function.raw"
sed "s/0:0:644:1/$fixture_uid:$fixture_gid:644:1/g" \
    "$TMPDIR/gdm-policy-function.raw" \
    > "$TMPDIR/gdm-policy-function.sh"
assert_cmd_success "isolated GDM policy function is valid bash" \
    bash -n "$TMPDIR/gdm-policy-function.sh"
# shellcheck source=/dev/null
. "$TMPDIR/gdm-policy-function.sh"
# The sourced GDM policy function invokes this fixture-local replacement.
# shellcheck disable=SC2317,SC2329
log() { :; }

run_gdm_policy_fixture() {
    local fixture_name=$1
    local human_users=$2
    local home_users=$3
    local expected=$4
    local initial_payload=$5
    local fixture_dir="$TMPDIR/gdm-$fixture_name"
    local custom_conf="$fixture_dir/custom.conf"
    local daemon_value
    local legacy_marker="$fixture_dir/run-initial-setup"
    local first_count

    mkdir -p "$fixture_dir"
    printf '%s' "$initial_payload" > "$custom_conf"
    chmod 0644 "$custom_conf"
    touch "$legacy_marker"
    CLEANUP_COUNT=0
    reconcile_gdm_initial_setup_policy \
        "$human_users" "$home_users" "$custom_conf" "$legacy_marker"
    assert_eq "1" "$(grep -ciE '^[[:space:]]*InitialSetupEnable[[:space:]]*=' \
        "$custom_conf")" "$fixture_name has one exact GDM policy key"
    assert_grep_extended \
        "^[[:space:]]*InitialSetupEnable[[:space:]]*=[[:space:]]*${expected}[[:space:]]*$" \
        "$custom_conf" "$fixture_name converges InitialSetupEnable=$expected"
    daemon_value=$(awk '
        /^[[:space:]]*\[[^]]+\][[:space:]]*$/ {
            section = $0
            gsub(/[[:space:]]/, "", section)
            in_daemon = (section == "[daemon]")
            next
        }
        in_daemon && /^[[:space:]]*InitialSetupEnable[[:space:]]*=/ {
            sub(/^[^=]*=/, "")
            gsub(/[[:space:]]/, "")
            print
        }
    ' "$custom_conf")
    assert_eq "$expected" "$daemon_value" \
        "$fixture_name places the policy key inside [daemon]"
    if [ ! -e "$legacy_marker" ] && [ ! -L "$legacy_marker" ]; then
        _pass "$fixture_name retires the obsolete GDM marker"
    else
        _fail "$fixture_name leaves the obsolete GDM marker"
    fi

    first_count=$CLEANUP_COUNT
    reconcile_gdm_initial_setup_policy \
        "$human_users" "$home_users" "$custom_conf" "$legacy_marker"
    assert_eq "$first_count" "$CLEANUP_COUNT" \
        "$fixture_name GDM policy is idempotent"
}

run_gdm_policy_fixture fresh 0 0 true $'[daemon]\n'
run_gdm_policy_fixture reinstall 0 1 false \
    $'[daemon]\nInitialSetupEnable=true\n'
run_gdm_policy_fixture normal 1 1 true \
    $'[security]\nInitialSetupEnable=true\n[daemon]\nInitialSetupEnable=false\n'

malformed_dir="$TMPDIR/gdm-duplicate-daemon"
mkdir -p "$malformed_dir"
printf '%s' $'[daemon]\nInitialSetupEnable=true\n[daemon]\n' \
    > "$malformed_dir/custom.conf"
touch "$malformed_dir/run-initial-setup"
CLEANUP_COUNT=0
if reconcile_gdm_initial_setup_policy 0 1 \
        "$malformed_dir/custom.conf" "$malformed_dir/run-initial-setup"; then
    _fail "duplicate [daemon] sections are rejected"
else
    _pass "duplicate [daemon] sections are rejected"
fi
assert_eq "2" "$(grep -cE '^[[:space:]]*\[daemon\][[:space:]]*$' \
    "$malformed_dir/custom.conf")" \
    "malformed GDM section structure is preserved for review"
assert_grep_fixed 'InitialSetupEnable=true' "$malformed_dir/custom.conf" \
    "malformed GDM policy bytes are not partially rewritten"
if [ -f "$malformed_dir/run-initial-setup" ]; then
    _pass "obsolete GDM marker remains when policy convergence fails"
else
    _fail "failed GDM convergence retired the diagnostic marker prematurely"
fi

# Build-time NetworkManager evidence records only an exact, active, unowned,
# conventional Ethernet profile. Interface absence alone is deliberately not
# runtime deletion authority.
extract_function compose_nm_connection_value "$KS_FILE" \
    "$TMPDIR/compose-nm-functions.sh"
extract_function is_compose_nm_profile "$KS_FILE" \
    "$TMPDIR/compose-nm-functions.sh" append
assert_cmd_success "isolated compose NetworkManager functions are valid bash" \
    bash -n "$TMPDIR/compose-nm-functions.sh"
# shellcheck source=/dev/null
. "$TMPDIR/compose-nm-functions.sh"

fake_sys_class="$TMPDIR/fake-sys-class-net"
empty_sys_class="$TMPDIR/empty-sys-class-net"
mkdir -p "$fake_sys_class/enp0s2" "$empty_sys_class"
compose_profile="$TMPDIR/enp0s2.nmconnection"
printf '%s' \
    $'[connection]\nid=enp0s2\ntype=ethernet\ninterface-name=enp0s2\n\n[ipv4]\nmethod=auto\n' \
    > "$compose_profile"
chmod 0600 "$compose_profile"
fixture_metadata="$(id -u):$(id -g):600:1"
if is_compose_nm_profile \
        "$compose_profile" "$fake_sys_class" "$fixture_metadata"; then
    _pass "active conventional compose Ethernet profile is recordable"
else
    _fail "active conventional compose Ethernet profile was rejected"
fi
if is_compose_nm_profile \
        "$compose_profile" "$empty_sys_class" "$fixture_metadata"; then
    _fail "profile for an absent compose interface is recordable"
else
    _pass "profile for an absent compose interface is not recordable"
fi
printf '%s' \
    $'[connection]\nid=other\ntype=ethernet\ninterface-name=enp0s2\n' \
    > "$compose_profile"
chmod 0600 "$compose_profile"
if is_compose_nm_profile \
        "$compose_profile" "$fake_sys_class" "$fixture_metadata"; then
    _fail "mismatched NetworkManager id/basename is recordable"
else
    _pass "mismatched NetworkManager id/basename is not recordable"
fi
printf '%s' \
    $'[connection]\nid=enp0s2\ntype=bridge\ninterface-name=enp0s2\n' \
    > "$compose_profile"
chmod 0600 "$compose_profile"
if is_compose_nm_profile \
        "$compose_profile" "$fake_sys_class" "$fixture_metadata"; then
    _fail "non-Ethernet compose profile is recordable"
else
    _pass "non-Ethernet compose profile is not recordable"
fi
assert_grep_fixed \
    'sha256sum -- "$compose_profile"' "$KS_FILE" \
    "manifest contains exact profile digests rather than machine identifiers"
assert_not_grep 'uuid=' "$KS_FILE" \
    "M41 manifest never embeds NetworkManager UUIDs"

# The generated Anaconda interaction file is intentionally not RPM-owned, but
# GNOME Initial Setup is an unprivileged documented consumer. Exercise the
# narrow pre-GDM metadata bridge independently from the deferred RPM scan.
assert_grep_fixed 'reconcile_anaconda_interaction_config_access()' \
    "$TMPDIR/cleanup.sh" \
    "Anaconda interaction-config access repair is isolated and testable"
assert_grep_fixed \
    'reconcile_anaconda_interaction_config_access' "$TMPDIR/cleanup.sh" \
    "pre-login security cleanup invokes the interaction-config repair"
interaction_functions="$TMPDIR/anaconda-interaction-functions.sh"
extract_function reconcile_anaconda_interaction_config_access \
    "$TMPDIR/cleanup.sh" "$interaction_functions"
assert_cmd_success "isolated Anaconda interaction-config repair is valid bash" \
    bash -n "$interaction_functions"
# shellcheck source=/dev/null
. "$interaction_functions"

interaction_root="$TMPDIR/anaconda-interaction"
interaction_parent="$interaction_root/sysconfig"
interaction_path="$interaction_parent/anaconda"
interaction_target="$interaction_root/outside-target"
interaction_bin="$interaction_root/bin"
mkdir -p "$interaction_parent" "$interaction_bin"
chmod 0750 "$interaction_parent"
printf '%s\n' \
    '# This file has been generated by the Anaconda Installer 44.30' \
    '' \
    '[General]' \
    'post_install_tools_disabled = 0' > "$interaction_path"
chmod 0640 "$interaction_path"
interaction_sha=$(sha256sum "$interaction_path" | awk '{print $1}')
cat > "$interaction_bin/restorecon" <<'INTERACTION_RESTORECON_EOF'
#!/usr/bin/env bash
exit 0
INTERACTION_RESTORECON_EOF
cat > "$interaction_bin/matchpathcon" <<'INTERACTION_MATCHPATH_EOF'
#!/usr/bin/env bash
exit 0
INTERACTION_MATCHPATH_EOF
chmod 0700 "$interaction_bin/restorecon" "$interaction_bin/matchpathcon"
interaction_old_path=$PATH
PATH="$interaction_bin:/usr/sbin:/usr/bin:/sbin:/bin"
export PATH
hash -r
# The extracted production helper invokes this test double after sourcing.
# shellcheck disable=SC2329
log() { :; }
CLEANUP_COUNT=0
assert_cmd_success \
    "pre-login bridge publishes only the expected Anaconda interaction path" \
    reconcile_anaconda_interaction_config_access \
        "$interaction_path" "$fixture_uid:$fixture_gid" \
        "$fixture_uid:$fixture_gid"
assert_eq 0755 "$(stat -c '%04a' -- "$interaction_parent")" \
    "Anaconda interaction-config parent becomes traversable before GDM"
assert_eq 0644 "$(stat -c '%04a' -- "$interaction_path")" \
    "Anaconda interaction config becomes readable before GDM"
assert_eq "$interaction_sha" \
    "$(sha256sum "$interaction_path" | awk '{print $1}')" \
    "Anaconda interaction bytes survive metadata-only publication"
assert_eq 2 "$CLEANUP_COUNT" \
    "both repaired permission attributes enter cleanup evidence"
interaction_first_count=$CLEANUP_COUNT
assert_cmd_success "Anaconda interaction-config repair is retry-safe" \
    reconcile_anaconda_interaction_config_access \
        "$interaction_path" "$fixture_uid:$fixture_gid" \
        "$fixture_uid:$fixture_gid"
assert_eq "$interaction_first_count" "$CLEANUP_COUNT" \
    "idempotent interaction-config repair adds no cleanup evidence"

chmod 0600 "$interaction_path"
if reconcile_anaconda_interaction_config_access \
        "$interaction_path" "$fixture_uid:$fixture_gid" \
        "$fixture_uid:$fixture_gid"; then
    _fail "unexpected restrictive interaction-config metadata is broadened"
else
    _pass "unexpected interaction-config metadata fails closed"
fi
assert_eq 0600 "$(stat -c '%04a' -- "$interaction_path")" \
    "failed interaction-config validation preserves its mode"
chmod 0644 "$interaction_path"
printf '%s\n' 'outside bytes must survive' > "$interaction_target"
interaction_target_sha=$(sha256sum "$interaction_target" | awk '{print $1}')
mv -- "$interaction_path" "$interaction_root/anaconda-regular"
ln -s -- "$interaction_target" "$interaction_path"
if reconcile_anaconda_interaction_config_access \
        "$interaction_path" "$fixture_uid:$fixture_gid" \
        "$fixture_uid:$fixture_gid"; then
    _fail "symlinked Anaconda interaction config is followed"
else
    _pass "symlinked Anaconda interaction config fails closed"
fi
assert_eq "$interaction_target_sha" \
    "$(sha256sum "$interaction_target" | awk '{print $1}')" \
    "interaction-config symlink rejection preserves its target"
PATH=$interaction_old_path
export PATH
hash -r

# Fedora Anaconda 44's live-image workaround re-copies /etc/sysconfig and
# /usr/lib/grub without rsync's permission/owner preservation. Exercise the
# exact firstboot reconciler against package-owned, unowned, missing-ok,
# co-owned and hostile type/conflict fixtures.
assert_grep_fixed 'reconcile_live_image_rpm_metadata()' \
    "$TMPDIR/cleanup.sh" \
    "Anaconda live-image metadata repair is isolated and testable"
assert_grep_extended \
    '^reconcile_live_image_rpm_metadata$' "$TMPDIR/cleanup.sh" \
    "firstboot invokes the exact live-image metadata reconciler"
assert_grep_fixed '/etc/sysconfig' "$TMPDIR/cleanup.sh" \
    "RPM-native reconciliation covers Anaconda's sysconfig workaround tree"
assert_grep_fixed '/usr/lib/grub' "$TMPDIR/cleanup.sh" \
    "RPM-native reconciliation covers Anaconda's GRUB library workaround tree"
assert_grep_fixed '/boot/grub2' "$TMPDIR/cleanup.sh" \
    "NoID Privacy-owned bootloader metadata exclusion is explicitly documented"
assert_grep_fixed '%{FILELINKTOS}' "$TMPDIR/cleanup.sh" \
    "RPM-declared link identity drives skipped-symlink restoration"
assert_not_grep 'rpm --restore' "$TMPDIR/cleanup.sh" \
    "metadata convergence never broadly restores whole package payloads"
assert_not_grep 'rpm --setperms' "$TMPDIR/cleanup.sh" \
    "metadata convergence never changes out-of-scope package paths"
assert_not_grep 'rpm --setugids' "$TMPDIR/cleanup.sh" \
    "ownership convergence never changes out-of-scope package paths"
assert_not_grep 'chmod -R' "$TMPDIR/cleanup.sh" \
    "metadata convergence never recursively invents permission policy"
assert_grep_fixed \
    "[ \"\$(stat -c '%h' -- \"\$path\" 2>/dev/null)\" = 1 ]" \
    "$TMPDIR/cleanup.sh" \
    "mutable package file/link paths reject hard-link aliases before mutation"
assert_grep_fixed \
    'FAILED: package path link-count postcondition did not converge' \
    "$TMPDIR/cleanup.sh" \
    "mutable package paths retain a single-link postcondition"
assert_not_grep 'restorecon -RF -- "$scope_a" "$scope_b"' \
    "$TMPDIR/cleanup.sh" \
    "metadata convergence never relabels unowned administrator paths"
assert_grep_fixed 'restorecon -F -- "$key"' "$TMPDIR/cleanup.sh" \
    "SELinux convergence is confined to the validated RPM path set"
assert_grep_fixed 'RPM_METADATA_CANDIDATE=""' "$TMPDIR/cleanup.sh" \
    "RPM manifest has explicit signal/exit cleanup ownership"
assert_grep_fixed \
    'FAILED: could not retire staged RPM metadata manifest' \
    "$TMPDIR/cleanup.sh" \
    "runtime cleanup reports RPM manifest retirement failures"

metadata_functions="$TMPDIR/live-image-rpm-metadata-functions.sh"
extract_function resolve_local_rpm_user "$TMPDIR/cleanup.sh" \
    "$metadata_functions"
extract_function resolve_local_rpm_group "$TMPDIR/cleanup.sh" \
    "$metadata_functions" append
extract_function reconcile_live_image_rpm_metadata "$TMPDIR/cleanup.sh" \
    "$metadata_functions" append
assert_cmd_success "isolated live-image RPM metadata functions are valid bash" \
    bash -n "$metadata_functions"
# shellcheck source=/dev/null
. "$metadata_functions"

metadata_root=$(mktemp -d /var/tmp/noid-m41-rpm-metadata.XXXXXXXX)
M41_METADATA_TEST_ROOT=$metadata_root
metadata_scope_a="$metadata_root/etc-sysconfig"
metadata_scope_b="$metadata_root/usr-lib-grub"
metadata_bin="$metadata_root/bin"
metadata_manifest="$metadata_root/manifest"
metadata_owned_a="$metadata_scope_a/owned.conf"
metadata_owned_b="$metadata_scope_b/owned.mod"
metadata_unowned="$metadata_scope_a/admin-unowned.conf"
metadata_target="$metadata_root/symlink-target"
metadata_link="$metadata_scope_b/package-link"
metadata_missing_link="$metadata_scope_a/package-link"
mkdir -p "$metadata_scope_a" "$metadata_scope_b" "$metadata_bin"
printf '%s\n' 'package bytes must survive' > "$metadata_owned_a"
printf '%s\n' 'module bytes must survive' > "$metadata_owned_b"
printf '%s\n' 'administrator bytes must survive' > "$metadata_unowned"
printf '%s\n' 'symlink target bytes must survive' > "$metadata_target"
ln -s -- "$metadata_target" "$metadata_link"
chmod 0750 "$metadata_scope_a" "$metadata_scope_b"
chmod 0640 "$metadata_owned_a" "$metadata_owned_b"
chmod 0600 "$metadata_unowned" "$metadata_target"
metadata_user=$(id -un)
metadata_group=$(id -gn)
metadata_owned_a_sha=$(sha256sum "$metadata_owned_a" | awk '{print $1}')
metadata_owned_b_sha=$(sha256sum "$metadata_owned_b" | awk '{print $1}')
metadata_unowned_sha=$(sha256sum "$metadata_unowned" | awk '{print $1}')
metadata_target_sha=$(sha256sum "$metadata_target" | awk '{print $1}')

cat > "$metadata_bin/rpm" <<'M41_METADATA_RPM_EOF'
#!/usr/bin/env bash
set -euo pipefail
[ "$1" = -qa ] || exit 64
/usr/bin/cat -- "$FAKE_RPM_MANIFEST"
M41_METADATA_RPM_EOF
cat > "$metadata_bin/restorecon" <<'M41_METADATA_RESTORECON_EOF'
#!/usr/bin/env bash
exit 0
M41_METADATA_RESTORECON_EOF
cat > "$metadata_bin/matchpathcon" <<'M41_METADATA_MATCHPATH_EOF'
#!/usr/bin/env bash
exit 0
M41_METADATA_MATCHPATH_EOF
chmod 0700 "$metadata_bin/rpm" "$metadata_bin/restorecon" \
    "$metadata_bin/matchpathcon"

# The production helper requires root-owned trusted roots. The behavioral
# fixture keeps the same canonical/non-writable boundary under its test UID.
trusted_nonwritable_directory() {
    local path=$1
    local mode
    [ -d "$path" ] && [ ! -L "$path" ] \
        && [ "$(readlink -e -- "$path" 2>/dev/null)" = "$path" ] \
        || return 1
    mode=$(stat -c '%a' -- "$path") || return 1
    (( (8#$mode & 0022) == 0 ))
}
log() { :; }
old_path=$PATH
PATH="$metadata_bin:/usr/sbin:/usr/bin:/sbin:/bin"
export PATH
hash -r
assert_eq "$metadata_bin/rpm" "$(command -v rpm)" \
    "behavioral fixture resolves the isolated RPM metadata provider"
FAKE_RPM_MANIFEST=$metadata_manifest
export FAKE_RPM_MANIFEST
RPM_METADATA_CANDIDATE=""
CLEANUP_COUNT=0

printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$metadata_scope_a" 40755 "$metadata_user" "$metadata_group" 0 "" \
    "$metadata_scope_a" 40755 "$metadata_user" "$metadata_group" 0 "" \
    "$metadata_owned_a" 100644 "$metadata_user" "$metadata_group" 0 "" \
    "$metadata_scope_a/missing-ok" 100600 \
        "$metadata_user" "$metadata_group" 8 "" \
    "$metadata_scope_a/missing-required" 100644 \
        "$metadata_user" "$metadata_group" 0 "" \
    "$metadata_scope_a/missing-ghost" 100600 \
        "$metadata_user" "$metadata_group" 64 "" \
    "$metadata_scope_b" 40755 "$metadata_user" "$metadata_group" 0 "" \
    "$metadata_owned_b" 100644 "$metadata_user" "$metadata_group" 0 "" \
    "$metadata_link" 120777 "$metadata_user" "$metadata_group" 0 \
        "$metadata_target" \
    "$metadata_missing_link" 120777 \
        "$metadata_user" "$metadata_group" 0 "../symlink-target" \
    > "$metadata_manifest"

assert_cmd_success \
    "RPM-native metadata converges only validated package-owned fixture paths" \
    reconcile_live_image_rpm_metadata "$metadata_scope_a" "$metadata_scope_b"
assert_eq 0755 "$(stat -c '%04a' -- "$metadata_scope_a")" \
    "package-owned sysconfig directory mode is restored"
assert_eq 0755 "$(stat -c '%04a' -- "$metadata_scope_b")" \
    "package-owned GRUB library directory mode is restored"
assert_eq 0644 "$(stat -c '%04a' -- "$metadata_owned_a")" \
    "package-owned sysconfig file mode is restored"
assert_eq 0644 "$(stat -c '%04a' -- "$metadata_owned_b")" \
    "package-owned GRUB library file mode is restored"
assert_eq "$metadata_owned_a_sha" \
    "$(sha256sum "$metadata_owned_a" | awk '{print $1}')" \
    "sysconfig content survives metadata-only convergence"
assert_eq "$metadata_owned_b_sha" \
    "$(sha256sum "$metadata_owned_b" | awk '{print $1}')" \
    "GRUB module content survives metadata-only convergence"
assert_eq 0600 "$(stat -c '%04a' -- "$metadata_unowned")" \
    "unowned administrator file mode remains untouched"
assert_eq "$metadata_unowned_sha" \
    "$(sha256sum "$metadata_unowned" | awk '{print $1}')" \
    "unowned administrator bytes remain untouched"
assert_eq "$metadata_target_sha" \
    "$(sha256sum "$metadata_target" | awk '{print $1}')" \
    "package symlink convergence never dereferences its target"
assert_eq "$metadata_target" "$(readlink -- "$metadata_link")" \
    "package symlink identity remains intact"
assert_eq "../symlink-target" "$(readlink -- "$metadata_missing_link")" \
    "RPM-declared symlink skipped by rsync is restored exactly"
if [ ! -e "$metadata_scope_a/missing-required" ] \
   && [ ! -L "$metadata_scope_a/missing-required" ]; then
    _pass "metadata-only convergence never recreates absent package content"
else
    _fail "metadata-only convergence recreated absent package content"
fi
assert_eq 5 "$CLEANUP_COUNT" \
    "four corrected modes and one restored symlink enter cleanup evidence"
first_metadata_count=$CLEANUP_COUNT
assert_cmd_success "RPM-native metadata convergence is retry-safe" \
    reconcile_live_image_rpm_metadata "$metadata_scope_a" "$metadata_scope_b"
assert_eq "$first_metadata_count" "$CLEANUP_COUNT" \
    "idempotent RPM metadata rerun adds no cleanup evidence"

# Conflicting co-owner metadata must be rejected before the first validated
# path is changed.
chmod 0640 "$metadata_owned_a"
printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$metadata_scope_a" 40755 "$metadata_user" "$metadata_group" 0 "" \
    "$metadata_owned_a" 100644 "$metadata_user" "$metadata_group" 0 "" \
    "$metadata_owned_a" 100600 "$metadata_user" "$metadata_group" 0 "" \
    "$metadata_scope_b" 40755 "$metadata_user" "$metadata_group" 0 "" \
    > "$metadata_manifest"
if reconcile_live_image_rpm_metadata \
        "$metadata_scope_a" "$metadata_scope_b"; then
    _fail "conflicting package metadata fails closed"
else
    _pass "conflicting package metadata fails closed"
fi
assert_eq 0640 "$(stat -c '%04a' -- "$metadata_owned_a")" \
    "metadata conflict is detected before partial chmod"
if [ -n "${RPM_METADATA_CANDIDATE:-}" ]; then
    /usr/bin/rm -f -- "$RPM_METADATA_CANDIDATE"
    RPM_METADATA_CANDIDATE=""
fi

# A package regular-file record can never authorize following a symlink.
type_mismatch="$metadata_scope_a/type-mismatch"
ln -s -- "$metadata_target" "$type_mismatch"
printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$metadata_scope_a" 40755 "$metadata_user" "$metadata_group" 0 "" \
    "$type_mismatch" 100644 "$metadata_user" "$metadata_group" 0 "" \
    "$metadata_scope_b" 40755 "$metadata_user" "$metadata_group" 0 "" \
    > "$metadata_manifest"
if reconcile_live_image_rpm_metadata \
        "$metadata_scope_a" "$metadata_scope_b"; then
    _fail "RPM/object type mismatch fails closed"
else
    _pass "RPM/object type mismatch fails closed"
fi
assert_eq "$metadata_target" "$(readlink -- "$type_mismatch")" \
    "type mismatch preserves the unexpected symlink for review"
assert_eq "$metadata_target_sha" \
    "$(sha256sum "$metadata_target" | awk '{print $1}')" \
    "type mismatch never mutates the symlink target"
if [ -n "${RPM_METADATA_CANDIDATE:-}" ]; then
    /usr/bin/rm -f -- "$RPM_METADATA_CANDIDATE"
    RPM_METADATA_CANDIDATE=""
fi

# A package regular-file record cannot authorize chmod/chown through a
# hard-linked alias outside the validated path set.
hardlink_peer="$metadata_root/hardlink-peer"
hardlink_path="$metadata_scope_a/hardlink"
printf '%s\n' 'hard-linked bytes must survive' > "$hardlink_peer"
chmod 0640 "$hardlink_peer"
ln -- "$hardlink_peer" "$hardlink_path"
hardlink_sha=$(sha256sum "$hardlink_peer" | awk '{print $1}')
printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$metadata_scope_a" 40755 "$metadata_user" "$metadata_group" 0 "" \
    "$hardlink_path" 100644 "$metadata_user" "$metadata_group" 0 "" \
    "$metadata_scope_b" 40755 "$metadata_user" "$metadata_group" 0 "" \
    > "$metadata_manifest"
if reconcile_live_image_rpm_metadata \
        "$metadata_scope_a" "$metadata_scope_b"; then
    _fail "hard-linked package path fails closed"
else
    _pass "hard-linked package path fails closed"
fi
assert_eq 2 "$(stat -c '%h' -- "$hardlink_path")" \
    "hard-link rejection preserves both aliases"
assert_eq 0640 "$(stat -c '%04a' -- "$hardlink_peer")" \
    "hard-link rejection occurs before package-mode mutation"
assert_eq "$hardlink_sha" \
    "$(sha256sum "$hardlink_peer" | awk '{print $1}')" \
    "hard-link rejection preserves aliased bytes"
if [ -n "${RPM_METADATA_CANDIDATE:-}" ]; then
    /usr/bin/rm -f -- "$RPM_METADATA_CANDIDATE"
    RPM_METADATA_CANDIDATE=""
fi

printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$metadata_scope_a" 40755 "$metadata_user" "$metadata_group" 0 "" \
    "$metadata_scope_b" 40755 "$metadata_user" "$metadata_group" 0 "" \
    "$metadata_link" 120777 "$metadata_user" "$metadata_group" 0 \
        "../different-target" \
    > "$metadata_manifest"
if reconcile_live_image_rpm_metadata \
        "$metadata_scope_a" "$metadata_scope_b"; then
    _fail "existing package symlink target drift fails closed"
else
    _pass "existing package symlink target drift fails closed"
fi
assert_eq "$metadata_target" "$(readlink -- "$metadata_link")" \
    "unexpected package symlink target is preserved for review"
if [ -n "${RPM_METADATA_CANDIDATE:-}" ]; then
    /usr/bin/rm -f -- "$RPM_METADATA_CANDIDATE"
    RPM_METADATA_CANDIDATE=""
fi
PATH=$old_path
export PATH
hash -r

metadata_reconcile_line=$(grep -nFx \
    'reconcile_live_image_rpm_metadata' "$TMPDIR/cleanup.sh" \
    | cut -d: -f1)
interaction_reconcile_line=$(grep -nFx \
    'reconcile_anaconda_interaction_config_access' "$TMPDIR/cleanup.sh" \
    | cut -d: -f1)
gis_policy_line=$(grep -nFx \
    "reconcile_gdm_initial_setup_policy \\" "$TMPDIR/cleanup.sh" \
    | cut -d: -f1)
if [ -n "$interaction_reconcile_line" ] && [ -n "$gis_policy_line" ] \
   && [ "$interaction_reconcile_line" -lt "$gis_policy_line" ]; then
    _pass "Anaconda interaction config is published before GIS policy and GDM"
else
    _fail "GIS can start before Anaconda interaction-config publication"
fi
installer_remove_line=$(grep -nF \
    '/usr/bin/dnf5 --cacheonly --assumeyes remove' "$TMPDIR/cleanup.sh" \
    | cut -d: -f1)
if [ -n "$metadata_reconcile_line" ] && [ -n "$installer_remove_line" ] \
   && [ "$metadata_reconcile_line" -lt "$installer_remove_line" ]; then
    _pass "RPM metadata converges while installer package ownership still exists"
else
    _fail "installer packages can disappear before RPM metadata convergence"
fi

# The complete installer stack is one DNF5-owned dependency-checked
# transaction. Direct RPM erasure would leave libdnf5 reason/history state
# stale; forced --nodeps/--noscripts erasure could also corrupt dependencies.
for pkg in anaconda-core anaconda-gui anaconda-tui anaconda-widgets \
           anaconda-widgets-devel anaconda-dracut anaconda-realmd \
           anaconda-install-env-deps anaconda-install-img-deps \
           lorax lorax-docs lorax-lmc-novirt lorax-lmc-virt \
           lorax-templates-generic livesys-scripts; do
    assert_grep_fixed "$pkg" "$TMPDIR/cleanup.sh" "installer cleanup includes $pkg"
done
assert_grep_fixed '/usr/bin/dnf5 --cacheonly --assumeyes remove' \
    "$TMPDIR/cleanup.sh" \
    "installer packages are removed through DNF5's native system-state path"
assert_grep_fixed '--no-autoremove "${INSTALLER_PKGS[@]}"' \
    "$TMPDIR/cleanup.sh" \
    "installer removal stays scoped until deliberate leaf reasons converge"
assert_not_grep 'rpm -e ' "$TMPDIR/cleanup.sh" \
    "installer removal never bypasses DNF5 state tracking"
assert_not_grep 'rpm -e --noscripts' "$TMPDIR/cleanup.sh" \
    "RPM uninstall scriptlets are not bypassed"
assert_not_grep 'rpm -e --nodeps' "$TMPDIR/cleanup.sh" \
    "RPM dependency checks are not bypassed"
assert_not_grep 'rpm-verify-allowlist' "$TMPDIR/cleanup.sh" \
    "cleanup has no obsolete Live-installer RPM drift allowlist"
assert_not_grep_extended \
    'rm[[:space:]]+-f[[:space:]]+--[[:space:]]+/usr/bin/liveinst' \
    "$TMPDIR/cleanup.sh" \
    "cleanup never hand-deletes Fedora's package-owned Live installer"
assert_grep_fixed 'LIVESYS_RPMSAVE=/etc/sysconfig/livesys.rpmsave' \
    "$TMPDIR/cleanup.sh" "known Livesys config residue has an explicit owner"
assert_grep_fixed "'livesys_session=gnome'" "$TMPDIR/cleanup.sh" \
    "fresh-created M17 Livesys bytes are recognized exactly"
assert_grep_fixed "'# Session type for desktop environment livesys setup'" \
    "$TMPDIR/cleanup.sh" "Fedora-vendor M17 Livesys bytes are recognized exactly"
assert_grep_fixed 'REVIEW: preserving noncanonical $LIVESYS_RPMSAVE' \
    "$TMPDIR/cleanup.sh" "unexpected administrator Livesys state is preserved"
assert_not_grep 'rm -f -- /etc/sysconfig/livesys.rpmsave' "$TMPDIR/cleanup.sh" \
    "Livesys RPM residue is never removed without the byte-shape gate"

# Live-image package reasons are not authoritative on the installed target.
# Preserve intentional leaf packages through DNF5's native reason model before
# allowing autoremove to resolve genuine installer orphans.
assert_grep_fixed 'PERSISTENT_LEAF_PKGS=(' "$TMPDIR/cleanup.sh" \
    "intentional leaf packages have an explicit reason-convergence set"
mapfile -t persistent_leaf_packages < <(awk '
    /^PERSISTENT_LEAF_PKGS=\($/ { active=1; next }
    active && /^\)$/ { exit }
    active && /^[[:space:]]+[A-Za-z0-9][A-Za-z0-9+._-]*$/ {
        gsub(/^[[:space:]]+|[[:space:]]+$/, "")
        print
    }
' "$TMPDIR/cleanup.sh")
assert_eq 12 "${#persistent_leaf_packages[@]}" \
    "intentional leaf-package array has the published exact count"
assert_eq 12 "$(printf '%s\n' "${persistent_leaf_packages[@]}" | sort -u | wc -l)" \
    "intentional leaf-package array contains no duplicate"
for pkg in openssl gdb gdb-headless binutils ctags source-highlight \
           smartmontools smartmontools-selinux kexec-tools hfsplus-tools \
           python3-libdnf5 dbus-tools; do
    assert_grep_fixed "$pkg" "$TMPDIR/cleanup.sh" \
        "intentional leaf reason set includes $pkg"
done
assert_grep_fixed 'rpm -q python3-libdnf5' "$TMPDIR/cleanup.sh" \
    "VSCodium trust binding is a hard pre-autoremove runtime invariant"
assert_grep_fixed 'rpm -q dbus-tools' "$TMPDIR/cleanup.sh" \
    "GTK session activation binding is a hard pre-autoremove runtime invariant"
assert_grep_fixed \
    "rpm -qf --qf '%{NAME}'" "$TMPDIR/cleanup.sh" \
    "GTK session activation binary is bound to its exact Fedora package owner"
assert_grep_fixed \
    'converging 12 intentional leaf-package reasons before autoremove' \
    "$TMPDIR/cleanup.sh" "leaf-package reason count matches the closed array"

# Execute the exact M19 runtime precondition from M41. This is the regression
# that removed dbus-tools on an installed hybrid-GPU system: every invalid
# package/path/owner shape must stop maintenance before autoremove can run.
M41_GSK_TEST_ROOT=$(mktemp -d "$PROJECT_ROOT/.test-41-gsk.XXXXXXXX")
gsk_runtime_gate="$M41_GSK_TEST_ROOT/gsk-runtime-gate.sh"
gsk_runtime_binary="$M41_GSK_TEST_ROOT/dbus-update-activation-environment"
{
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
        "GSK_ACTIVATION_UPDATER=$gsk_runtime_binary" \
        'log() { :; }' \
        'rpm() {' \
        '    if [ "$1" = -q ] && [ "$2" = dbus-tools ]; then' \
        '        [ "${FAKE_DBUS_TOOLS_INSTALLED:-1}" -eq 1 ]' \
        '        return' \
        '    fi' \
        '    if [ "$1" = -qf ] && [ "$2" = --qf ]; then' \
        '        printf "%s" "${FAKE_ACTIVATION_OWNER:-dbus-tools}"' \
        '        return' \
        '    fi' \
        '    return 64' \
        '}'
    sed -n \
        '/^# M41_GSK_RUNTIME_GATE_BEGIN$/,/^# M41_GSK_RUNTIME_GATE_END$/p' \
        "$TMPDIR/cleanup.sh"
    printf '%s\n' 'printf "REACHED\n"'
} > "$gsk_runtime_gate"
chmod 0700 "$gsk_runtime_gate"
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' > "$gsk_runtime_binary"
chmod 0700 "$gsk_runtime_binary"
assert_cmd_success "isolated GTK activation-runtime gate parses" \
    bash -n "$gsk_runtime_gate"
assert_cmd_success "GTK activation-runtime gate accepts the exact package contract" \
    bash "$gsk_runtime_gate"
assert_cmd_failure "GTK activation-runtime gate rejects a missing dbus-tools package" \
    env FAKE_DBUS_TOOLS_INSTALLED=0 bash "$gsk_runtime_gate"
assert_cmd_failure "GTK activation-runtime gate rejects the wrong RPM owner" \
    env FAKE_ACTIVATION_OWNER=other-package bash "$gsk_runtime_gate"
chmod 0600 "$gsk_runtime_binary"
assert_cmd_failure "GTK activation-runtime gate rejects a non-executable updater" \
    bash "$gsk_runtime_gate"
rm -f -- "$gsk_runtime_binary"
ln -s /bin/true "$gsk_runtime_binary"
assert_cmd_failure "GTK activation-runtime gate rejects a symlinked updater" \
    bash "$gsk_runtime_gate"
rm -f -- "$gsk_runtime_binary"
assert_grep_fixed \
    '/usr/bin/dnf5 --cacheonly --assumeyes mark user' \
    "$TMPDIR/cleanup.sh" \
    "intentional leaves use the maintained noninteractive DNF5 user reason"
assert_grep_fixed '--skip-unavailable "${PERSISTENT_LEAF_PKGS[@]}"' \
    "$TMPDIR/cleanup.sh" \
    "absent optional leaves do not invalidate reason convergence"
assert_grep_fixed '"${PERSISTENT_LEAF_PKGS[@]}"' "$TMPDIR/cleanup.sh" \
    "DNF5 reason convergence consumes only the static leaf-package array"
assert_grep_fixed \
    '( umask 022; /usr/bin/dnf5 --cacheonly --assumeyes mark user' \
    "$TMPDIR/cleanup.sh" \
    "reason convergence preserves unprivileged-readable DNF5 system state"
assert_grep_fixed \
    '( umask 022; /usr/bin/dnf5 --cacheonly autoremove -y )' \
    "$TMPDIR/cleanup.sh" \
    "autoremove preserves unprivileged-readable DNF5 system state"
mark_line=$(grep -nF '/usr/bin/dnf5 --cacheonly --assumeyes mark user' \
    "$TMPDIR/cleanup.sh" | cut -d: -f1)
autoremove_line=$(grep -nF '/usr/bin/dnf5 --cacheonly autoremove -y' \
    "$TMPDIR/cleanup.sh" | cut -d: -f1)
if [ -n "$mark_line" ] && [ -n "$autoremove_line" ] \
   && [ "$mark_line" -lt "$autoremove_line" ]; then
    _pass "intentional leaf reasons converge before autoremove"
else
    _fail "autoremove can run before intentional leaf reason convergence"
fi
assert_not_grep '--exclude=' "$TMPDIR/cleanup.sh" \
    "persistent package intent is not hidden in a transaction-local exclusion"
assert_not_grep 'non-fatal, orphans remain' "$TMPDIR/cleanup.sh" \
    "autoremove failure is never sealed as successful maintenance"
assert_grep_fixed \
    'FAILED: dnf autoremove failed — package hygiene remains retryable' \
    "$TMPDIR/cleanup.sh" \
    "autoremove failure has a terminal retryable diagnostic"
assert_grep_fixed 'exit 1' \
    <(sed -n '/FAILED: dnf autoremove failed/,/^fi$/p' "$TMPDIR/cleanup.sh") \
    "autoremove failure exits before completion-marker publication"
assert_grep_fixed 'INSTALLER_ONLY_PKGS=(' "$FIRSTBOOT_RUNTIME" \
    "installed release gate carries a closed installer-package absence set"
assert_grep_fixed \
    '[[ ! -e /usr/local/bin/liveinst && ! -L /usr/local/bin/liveinst ]]' \
    "$FIRSTBOOT_RUNTIME" \
    "installed release gate rejects the copied M17 Live launcher wrapper"
for pkg in anaconda anaconda-core anaconda-gui anaconda-tui anaconda-widgets \
           anaconda-widgets-devel anaconda-webui anaconda-live anaconda-dracut \
           anaconda-realmd anaconda-install-env-deps \
           anaconda-install-img-deps lorax lorax-lmc-novirt lorax-lmc-virt \
           lorax-templates-generic lorax-templates-rhel lorax-docs \
           livesys-scripts; do
    assert_grep_extended "^[[:space:]]{4}${pkg}$" "$FIRSTBOOT_RUNTIME" \
        "installed release gate rejects installer package $pkg"
done
assert_grep_fixed 'dnf5 --cacheonly repoquery --installed --unneeded' \
    "$FIRSTBOOT_RUNTIME" \
    "installed release gate verifies dependency-reason convergence offline"
assert_grep_fixed 'DNF5 still classifies installed packages as unneeded' \
    "$FIRSTBOOT_RUNTIME" \
    "installed release gate fails on orphaned first-boot dependencies"
assert_grep_fixed 'repoquery --userinstalled' \
    "$FIRSTBOOT_RUNTIME" \
    "installed release gate verifies the native dbus-tools user reason"
assert_not_grep 'repoquery --installed --userinstalled' \
    "$FIRSTBOOT_RUNTIME" \
    "installed release gate avoids the DNF5 5.4 mutually exclusive reason filters"
assert_grep_fixed \
    'dbus-tools does not retain the required user-installed reason' \
    "$FIRSTBOOT_RUNTIME" \
    "installed release gate fails if dbus-tools loses its explicit reason"

# Execute the exact installed-candidate package gate with deterministic local
# RPM/DNF providers. This proves all three fail paths as well as the clean
# transition; the live-host run separately supplies the real remnant finding.
package_gate_fixture="$TMPDIR/installed-package-gate.sh"
{
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
        "tmp_dir=$TMPDIR/installed-package-gate-state" \
        'mkdir -p "$tmp_dir"' \
        'fail() { printf "FAIL:%s\\n" "$*" >&2; exit 1; }' \
        'rpm() {' \
        '    [ "$1" = -q ] || return 64' \
        '    [ "${FAKE_INSTALLED_PACKAGE:-}" = "$2" ]' \
        '}' \
        'dnf5() {' \
        '    [ "${FAKE_DNF_QUERY_FAIL:-0}" -eq 0 ] || return 65' \
        '    case " $* " in' \
        '        *" --unneeded "*)' \
        '            [ -z "${FAKE_UNNEEDED_PACKAGE:-}" ] || printf "%s\\n" "$FAKE_UNNEEDED_PACKAGE"' \
        '            ;;' \
        '        *" --userinstalled "*)' \
        '            [ "${FAKE_DBUS_TOOLS_USER_REASON:-1}" -eq 0 ] || printf "%s\\n" dbus-tools' \
        '            ;;' \
        '        *) return 66 ;;' \
        '    esac' \
        '}'
    sed -n \
        '/^# M41_INSTALLER_PACKAGE_GATE_BEGIN$/,/^# M41_INSTALLER_PACKAGE_GATE_END$/p' \
        "$FIRSTBOOT_RUNTIME"
    printf '%s\n' 'printf "REACHED\\n"'
} > "$package_gate_fixture"
chmod 0700 "$package_gate_fixture"
assert_cmd_success "installed package-gate fixture parses" \
    bash -n "$package_gate_fixture"
assert_cmd_success "installed package gate accepts a complete clean transition" \
    bash "$package_gate_fixture"
assert_cmd_failure "installed package gate rejects a direct installer remnant" \
    env FAKE_INSTALLED_PACKAGE=anaconda bash "$package_gate_fixture"
assert_cmd_failure "installed package gate rejects an unneeded dependency" \
    env FAKE_UNNEEDED_PACKAGE=blivet-data bash "$package_gate_fixture"
assert_cmd_failure "installed package gate rejects a DNF reason-query failure" \
    env FAKE_DNF_QUERY_FAIL=1 bash "$package_gate_fixture"
assert_cmd_failure "installed package gate rejects a lost dbus-tools user reason" \
    env FAKE_DBUS_TOOLS_USER_REASON=0 bash "$package_gate_fixture"

# Execute the exact autoremove transaction. A failed DNF operation must exit
# before the reached marker and retire its private diagnostic file; a success
# records the real before/after delta and reaches subsequent maintenance.
autoremove_fixture="$TMPDIR/autoremove-transaction.sh"
autoremove_scratch="$TMPDIR/autoremove-scratch"
mkdir -p "$autoremove_scratch"
{
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
        "export TMPDIR=$autoremove_scratch" \
        "FAKE_RPM_AFTER=$TMPDIR/autoremove-rpm-after" \
        'CLEANUP_COUNT=0' \
        'log() { :; }' \
        'forward_log_tail() { tail -50 "$1" >/dev/null 2>&1 || true; }' \
        'rpm() {' \
        '    if [ -e "$FAKE_RPM_AFTER" ]; then' \
        '        printf "%s\\n" package-a' \
        '    else' \
        '        : > "$FAKE_RPM_AFTER"' \
        '        printf "%s\\n" package-a package-b' \
        '    fi' \
        '}' \
        'dnf5() {' \
        '    printf "%s\\n" diagnostic' \
        '    [ "${FAKE_AUTOREMOVE_FAIL:-0}" -eq 0 ]' \
        '}'
    sed -n \
        '/^# M41_AUTOREMOVE_TRANSACTION_BEGIN$/,/^# M41_AUTOREMOVE_TRANSACTION_END$/p' \
        "$TMPDIR/cleanup.sh" | sed 's#/usr/bin/dnf5#dnf5#'
    printf '%s\n' 'printf "REACHED cleanup_count=%s\\n" "$CLEANUP_COUNT"'
} > "$autoremove_fixture"
chmod 0700 "$autoremove_fixture"
assert_cmd_success "isolated autoremove transaction parses" \
    bash -n "$autoremove_fixture"
rm -f -- "$TMPDIR/autoremove-rpm-after"
set +e
autoremove_success_output=$(bash "$autoremove_fixture")
autoremove_success_rc=$?
set -e
assert_eq 0 "$autoremove_success_rc" \
    "successful autoremove reaches later maintenance"
assert_eq 'REACHED cleanup_count=1' \
    "$autoremove_success_output" \
    "successful autoremove records its exact package delta"
rm -f -- "$TMPDIR/autoremove-rpm-after"
set +e
FAKE_AUTOREMOVE_FAIL=1 bash "$autoremove_fixture" \
    > "$TMPDIR/autoremove-fail.stdout" 2> "$TMPDIR/autoremove-fail.stderr"
autoremove_fail_rc=$?
set -e
assert_eq 1 "$autoremove_fail_rc" \
    "failed autoremove keeps maintenance retryable"
assert_not_grep 'REACHED' "$TMPDIR/autoremove-fail.stdout" \
    "failed autoremove cannot reach completion-marker work"
if [ -z "$(find "$autoremove_scratch" -mindepth 1 -maxdepth 1 \
        -name 'noid-autoremove.*' -print -quit)" ]; then
    _pass "failed autoremove retires its private diagnostic file"
else
    _fail "failed autoremove leaves its private diagnostic file"
fi

assert_eq 5 \
    "$(grep -cE '^[[:space:]]*forward_log_tail[[:space:]]' \
        "$TMPDIR/cleanup.sh" || true)" \
    "success and every DNF failure use the non-blocking forwarding helper"
extract_function forward_log_tail "$TMPDIR/cleanup.sh" \
    "$TMPDIR/forward-log-tail.sh"
if (
    # shellcheck source=/dev/null
    . "$TMPDIR/forward-log-tail.sh"
    # Consumed by the sourced production function.
    # shellcheck disable=SC2034
    LOG_TAG=noid-m41-fixture
    # shellcheck disable=SC2317,SC2329
    logger() { return 3; }
    printf '%s\n\n' 'diagnostic line' > "$TMPDIR/dnf-tail.log"
    forward_log_tail "$TMPDIR/dnf-tail.log" dnf-fixture
    forward_log_tail "$TMPDIR/missing-dnf-tail.log" dnf-fixture
); then
    _pass "DNF diagnostic forwarding cannot abort on logger or tail failure"
else
    _fail "DNF diagnostic forwarding leaked a non-zero status"
fi

# Service activation and its main isolation boundaries are mandatory.
assert_grep_fixed 'IPAddressDeny=any' "$TMPDIR/cleanup.service" \
    "pre-login security cleanup cannot access the network"
assert_grep_fixed 'RestrictAddressFamilies=AF_UNIX' \
    "$TMPDIR/cleanup.service" \
    "pre-login cleanup retains only local IPC sockets"
assert_grep_fixed 'UMask=0077' "$TMPDIR/cleanup.service" \
    "pre-login cleanup scratch and evidence default to private modes"
assert_grep_fixed 'NoNewPrivileges=no' "$TMPDIR/cleanup.service" \
    "native account tools retain required SELinux transitions"
assert_grep_fixed 'IPAddressDeny=any' "$TMPDIR/maintenance.service"
assert_grep_fixed 'RestrictAddressFamilies=AF_UNIX' "$TMPDIR/maintenance.service"
assert_grep_fixed 'UMask=0077' "$TMPDIR/maintenance.service" \
    "maintenance scratch output is private unless DNF explicitly selects 022"
assert_grep_fixed 'NoNewPrivileges=no' "$TMPDIR/maintenance.service" \
    "RPM scriptlets retain required SELinux domain-transition capability"
assert_not_grep '^NoNewPrivileges=yes$' "$TMPDIR/maintenance.service" \
    "maintenance does not block RPM SELinux transitions with no_new_privs"
assert_grep_fixed \
    'CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_CHOWN CAP_FOWNER CAP_KILL CAP_SETUID CAP_SETGID' \
    "$TMPDIR/maintenance.service" \
    "deferred package scriptlets retain the previously validated capability boundary"
assert_grep_fixed 'MemoryDenyWriteExecute=yes' "$TMPDIR/cleanup.service" \
    "pre-login security transition retains executable-memory denial"
assert_grep_fixed \
    'After=noid-anaconda-cleanup.service gdm.service display-manager.service' \
    "$TMPDIR/maintenance.service" \
    "package hygiene starts only after both security cleanup and GDM"
assert_grep_fixed \
    'ExecStart=/usr/libexec/noid-anaconda-cleanup.sh --maintenance' \
    "$TMPDIR/maintenance.service" \
    "package hygiene uses the isolated maintenance mode"
assert_grep_fixed \
    'ExecStart=/usr/libexec/noid-anaconda-cleanup.sh --security' \
    "$TMPDIR/cleanup.service" \
    "GDM-gated service invokes only pre-login security mode"
assert_grep_fixed \
    'Before=systemd-user-sessions.service getty.target gdm.service display-manager.service' \
    "$TMPDIR/cleanup.service" \
    "Live authorization is retired before every local login surface opens"
assert_grep_fixed \
    'Requires=noid-host-identity.service noid-anaconda-cleanup.service' \
    "$TMPDIR/gdm-gate.conf" \
    "GDM requires successful firstboot cleanup"
assert_grep_fixed \
    'After=noid-host-identity.service noid-anaconda-cleanup.service' \
    "$TMPDIR/gdm-gate.conf" \
    "GDM starts only after cleanup completes"
assert_grep_fixed \
    'Requires=noid-host-identity.service noid-anaconda-cleanup.service' \
    "$TMPDIR/user-sessions-gate.conf" \
    "systemd user sessions require successful firstboot cleanup"
assert_grep_fixed \
    'After=noid-host-identity.service noid-anaconda-cleanup.service' \
    "$TMPDIR/user-sessions-gate.conf" \
    "systemd user sessions start only after cleanup completes"
assert_not_grep \
    'ConditionPathExists=!/var/lib/noid-privacy/anaconda-cleanup.done' \
    "$TMPDIR/cleanup.service" \
    "mere marker existence can never suppress post-power-loss validation"
assert_grep_fixed 'Validated prior cleanup completion marker' \
    "$TMPDIR/cleanup.sh" "later boots accept only fully validated evidence"
assert_grep_fixed 'Retired incomplete cleanup marker' "$TMPDIR/cleanup.sh" \
    "incomplete marker evidence triggers full convergence"
validated_marker_line=$(grep -nF \
    'Validated prior cleanup completion marker — no mutation needed' \
    "$TMPDIR/cleanup.sh" | cut -d: -f1)
retire_evidence_line=$(grep -nF \
    '    retire_installer_evidence || exit 1' \
    "$TMPDIR/cleanup.sh" | cut -d: -f1)
first_cleanup_line=$(grep -nF '# ----- 1. liveuser account + /home/liveuser -----' \
    "$TMPDIR/cleanup.sh" | cut -d: -f1)
if [ -n "$validated_marker_line" ] && [ -n "$retire_evidence_line" ] \
   && [ -n "$first_cleanup_line" ] \
   && [ "$validated_marker_line" -lt "$retire_evidence_line" ] \
   && [ "$retire_evidence_line" -lt "$first_cleanup_line" ]; then
    _pass "installer evidence retires only after prior-success reconciliation"
else
    _fail "installer evidence retirement can repeat after validated success"
fi
assert_grep_fixed 'systemctl daemon-reload' "$KS_FILE" \
    "systemd sees the unit before enable"
assert_grep_fixed 'publish_root_file "$CLEANUP_SOURCE"' "$KS_FILE" \
    "cleanup executable uses guarded atomic publication"
assert_grep_fixed 'publish_root_file "$IDENTITY_SOURCE"' "$KS_FILE" \
    "host-identity executable uses guarded atomic publication"
assert_grep_fixed 'publish_root_file "$IDENTITY_SERVICE_SOURCE"' "$KS_FILE" \
    "host-identity service uses guarded atomic publication"
assert_grep_fixed \
    'publish_root_file "$BUILD_NM_CANDIDATE" "$BUILD_NM_MANIFEST" 0644' \
    "$KS_FILE" "compose manifest uses guarded atomic publication"
assert_grep_fixed 'publish_root_file "$SERVICE_SOURCE"' "$KS_FILE" \
    "cleanup service uses guarded atomic publication"
assert_grep_fixed 'publish_root_file "$MAINTENANCE_SERVICE_SOURCE"' "$KS_FILE" \
    "maintenance service uses guarded atomic publication"
assert_grep_fixed 'publish_root_file "$GDM_GATE_SOURCE"' "$KS_FILE" \
    "GDM cleanup gate uses guarded atomic publication"
assert_grep_fixed 'publish_root_file "$USER_SESSIONS_GATE_SOURCE"' \
    "$KS_FILE" \
    "systemd-user-sessions cleanup gate uses guarded atomic publication"
assert_not_grep 'cat > /usr/libexec/noid-anaconda-cleanup.sh' "$KS_FILE" \
    "cleanup executable is never truncated in place"
assert_not_grep 'cat > /etc/systemd/system/noid-anaconda-cleanup.service' \
    "$KS_FILE" "cleanup service is never truncated in place"
assert_grep_fixed 'M41_RUNTIME_MARKER_CLEANUP_BEGIN' "$TMPDIR/cleanup.sh" \
    "runtime marker has one exact EXIT/signal cleanup boundary"
assert_grep_fixed 'FAILED: could not retire staged runtime policy candidate' \
    "$TMPDIR/cleanup.sh" \
    "runtime EXIT/signal cleanup owns non-marker policy candidates"
assert_eq 3 \
    "$(grep -cF 'RUNTIME_CANDIDATE=$candidate' "$TMPDIR/cleanup.sh")" \
    "all three runtime atomic policy writers register their candidate"
assert_grep_fixed 'DONE_PUBLISHED=1' "$TMPDIR/cleanup.sh" \
    "published runtime evidence remains removable until final durability"
assert_grep_fixed 'matchpathcon -V "$DONE_MARKER"' "$TMPDIR/cleanup.sh" \
    "runtime completion cannot suppress retries with a wrong SELinux label"
assert_grep_fixed 'checks_total=15' "$KS_FILE" \
    "all fifteen build contracts participate in the health gate"
assert_grep_fixed '[ "$SERVICE_ENABLED" = enabled ]' "$KS_FILE" \
    "service enablement requires the exact canonical state"
assert_grep_fixed \
    '[ ! -e /var/lib/noid-privacy/anaconda-cleanup.done ]' \
    "$KS_FILE" \
    "a stale runtime marker cannot be baked into the image"
assert_grep_fixed \
    'systemd-analyze verify' "$KS_FILE" \
    "systemd validates the complete cleanup and login dependency graph"
assert_grep_fixed 'stamp-41-anaconda-cleanup.ok' "$KS_FILE"
assert_grep_fixed \
    'publish_root_file "$STAMP_CANDIDATE" "$STAMP" 0644' "$KS_FILE" \
    "health evidence is published atomically"
assert_grep_fixed 'prior Module 41 health stamp is absent' "$KS_FILE" \
    "old M41 success evidence is retired before payload mutation"
assert_grep_fixed 'cleanup_m41_build_candidates()' "$KS_FILE" \
    "all incomplete M41 payload and health candidates share one exit cleanup"
assert_grep_fixed "trap 'exit 143' TERM" "$KS_FILE" \
    "TERM is converted into the exact M41 cleanup path"
assert_grep_fixed 'verify_m41_health_stamp()' "$KS_FILE" \
    "staged and final M41 evidence share one exact validator"
assert_grep_fixed 'matchpathcon -V "$STAMP_CANDIDATE"' "$KS_FILE" \
    "M41 validates the staged stamp SELinux context"
assert_grep_fixed 'matchpathcon -V "$STAMP"' "$KS_FILE" \
    "M41 validates the final stamp SELinux context"
assert_grep_fixed 'STAMP_PUBLISHED=1' "$KS_FILE" \
    "M41 marks the final stamp removable until all postconditions pass"
assert_grep_fixed 'version=4' "$KS_FILE" \
    "M41 health evidence advances with final-payload byte binding"
assert_grep_fixed "stat -Lc '%u:%g:%a:%h'" "$KS_FILE" \
    "M41 verifies exact ownership, mode and link count"
assert_grep_fixed \
    'all seven final M41 payloads match their publication candidates' \
    "$KS_FILE" \
    "the final build gate rebinds every M41 payload to its candidate digest"
for m41_hash_field in identity_sha256 identity_service_sha256 \
        cleanup_sha256 security_service_sha256 \
        maintenance_service_sha256 gdm_gate_sha256 \
        user_sessions_gate_sha256; do
    assert_grep_fixed "${m41_hash_field}=\$" "$KS_FILE" \
        "M41 health evidence records $m41_hash_field"
done

m41_invalidate_line=$(grep -nF \
    '# M41_HEALTH_INVALIDATION_BEGIN' "$KS_FILE" | cut -d: -f1)
m41_first_payload_line=$(grep -nF \
    "cat > \"\$CLEANUP_SOURCE\" <<'CLEANUP_EOF'" \
    "$KS_FILE" | cut -d: -f1)
m41_publish_line=$(grep -nF \
    'written atomically with exact metadata and context' \
    "$KS_FILE" | cut -d: -f1)
m41_complete_line=$(grep -nF \
    'log "=== Module 41 anaconda-cleanup complete ==="' \
    "$KS_FILE" | cut -d: -f1)
if [ -n "$m41_invalidate_line" ] && [ -n "$m41_first_payload_line" ] \
   && [ -n "$m41_publish_line" ] && [ -n "$m41_complete_line" ] \
   && [ "$m41_invalidate_line" -lt "$m41_first_payload_line" ] \
   && [ "$m41_publish_line" -lt "$m41_complete_line" ]; then
    _pass "M41 retires old health before mutation and completes after publication"
else
    _fail "M41 retires old health before mutation and completes after publication"
fi

# Execute the exact runtime done-marker cleanup/publication blocks. An injected
# rename failure, label failure or TERM after publish must leave no existence
# marker that could suppress the next boot's retry.
marker_root=$(mktemp -d /var/tmp/noid-m41-runtime-marker.XXXXXXXX)
M41_MARKER_TEST_ROOT="$marker_root"
marker_state="$marker_root/state"
marker_bin="$marker_root/bin"
marker_script="$marker_root/publish.sh"
marker_reconcile="$marker_root/reconcile.sh"
runtime_candidate_script="$marker_root/runtime-candidate.sh"
marker_reached="$marker_root/reconcile-reached"
mkdir -p "$marker_state" "$marker_bin"
chmod 0755 "$marker_root" "$marker_state" "$marker_bin"
marker_uid=$(id -u)
marker_gid=$(id -g)
cat > "$marker_bin/restorecon" <<'M41_MARKER_RESTORECON_EOF'
#!/usr/bin/env bash
set -euo pipefail
target="${!#}"
case "${FAKE_MARKER_RESTORECON:-}" in
    fail-final)
        case "$target" in
            */anaconda-cleanup.done) exit 1 ;;
        esac
        ;;
    signal-final)
        case "$target" in
            */anaconda-cleanup.done)
                kill -TERM "$PPID"
                sleep 1
                ;;
        esac
        ;;
esac
exit 0
M41_MARKER_RESTORECON_EOF
cat > "$marker_bin/matchpathcon" <<'M41_MARKER_MATCHPATH_EOF'
#!/usr/bin/env bash
exit 0
M41_MARKER_MATCHPATH_EOF
cat > "$marker_bin/mv" <<'M41_MARKER_MV_EOF'
#!/usr/bin/env bash
set -euo pipefail
[ "${FAKE_MARKER_MV_FAIL:-0}" -ne 1 ] || exit 1
exec /usr/bin/mv "$@"
M41_MARKER_MV_EOF
chmod 0700 "$marker_bin/restorecon" "$marker_bin/matchpathcon" \
    "$marker_bin/mv"
{
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
        "PATH=$marker_bin:/usr/sbin:/usr/bin:/sbin:/bin" 'export PATH' \
        'log() { :; }' \
        "DONE_MARKER=$marker_state/anaconda-cleanup.done" \
        "STATE_DIR=$marker_state" \
        'CLEANUP_COUNT=7'
    sed -n \
        '/^# M41_RUNTIME_MARKER_CLEANUP_BEGIN$/,/^# M41_RUNTIME_MARKER_CLEANUP_END$/p' \
        "$TMPDIR/cleanup.sh" |
        sed "s/0:0:644:1/$marker_uid:$marker_gid:644:1/g"
    sed -n \
        '/^# M41_RUNTIME_MARKER_PUBLICATION_BEGIN$/,/^# M41_RUNTIME_MARKER_PUBLICATION_END$/p' \
        "$TMPDIR/cleanup.sh" |
        sed -e "s/chown root:root/chown $marker_uid:$marker_gid/" \
            -e "s/0:0:644:1/$marker_uid:$marker_gid:644:1/g"
} > "$marker_script"
chmod 0700 "$marker_script"
assert_cmd_success "isolated runtime marker transaction is valid bash" \
    bash -n "$marker_script"
{
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
        "PATH=$marker_bin:/usr/sbin:/usr/bin:/sbin:/bin" 'export PATH' \
        'log() { :; }' \
        "DONE_MARKER=$marker_state/anaconda-cleanup.done" \
        "STATE_DIR=$marker_state"
    sed -n \
        '/^# M41_RUNTIME_MARKER_CLEANUP_BEGIN$/,/^# M41_RUNTIME_MARKER_CLEANUP_END$/p' \
        "$TMPDIR/cleanup.sh" |
        sed "s/0:0:644:1/$marker_uid:$marker_gid:644:1/g"
    sed -n \
        '/^# M41_RUNTIME_MARKER_RECONCILE_BEGIN$/,/^# M41_RUNTIME_MARKER_RECONCILE_END$/p' \
        "$TMPDIR/cleanup.sh"
    printf 'printf reached > %q\n' "$marker_reached"
} > "$marker_reconcile"
chmod 0700 "$marker_reconcile"
assert_cmd_success "isolated runtime marker reconciliation is valid bash" \
    bash -n "$marker_reconcile"

{
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
        'log() { :; }' \
        "DONE_MARKER=$marker_state/anaconda-cleanup.done"
    sed -n \
        '/^# M41_RUNTIME_MARKER_CLEANUP_BEGIN$/,/^# M41_RUNTIME_MARKER_CLEANUP_END$/p' \
        "$TMPDIR/cleanup.sh"
    printf 'RUNTIME_CANDIDATE=%q\n' "$marker_state/.runtime-policy-candidate"
    printf 'printf staged > "$RUNTIME_CANDIDATE"\n'
    printf '%s\n' 'exit 143'
} > "$runtime_candidate_script"
chmod 0700 "$runtime_candidate_script"
assert_cmd_success "isolated runtime policy-candidate cleanup is valid bash" \
    bash -n "$runtime_candidate_script"
set +e
bash "$runtime_candidate_script"
runtime_candidate_rc=$?
set -e
assert_eq 143 "$runtime_candidate_rc" \
    "runtime TERM preserves the original signal exit status"
if [ ! -e "$marker_state/.runtime-policy-candidate" ]; then
    _pass "runtime TERM retires the exact staged policy candidate"
else
    _fail "runtime TERM leaves a staged policy candidate behind"
fi

printf '%s\n' '2026-07-29T06:30:00Z cleanup_count=12' \
    > "$marker_state/anaconda-cleanup.done"
chmod 0644 "$marker_state/anaconda-cleanup.done"
rm -f -- "$marker_reached"
assert_cmd_success "later boot accepts an exact durable runtime marker" \
    bash "$marker_reconcile"
if [ -f "$marker_state/anaconda-cleanup.done" ] \
   && [ ! -e "$marker_reached" ]; then
    _pass "valid prior marker returns before cleanup mutation"
else
    _fail "valid prior marker returns before cleanup mutation"
fi

printf '%s\n' 'partial' > "$marker_state/anaconda-cleanup.done"
chmod 0644 "$marker_state/anaconda-cleanup.done"
rm -f -- "$marker_reached"
assert_cmd_success "later boot retires an incomplete runtime marker" \
    bash "$marker_reconcile"
if [ ! -e "$marker_state/anaconda-cleanup.done" ] \
   && [ -f "$marker_reached" ]; then
    _pass "incomplete prior marker reaches full-convergence path"
else
    _fail "incomplete prior marker reaches full-convergence path"
fi

mkdir "$marker_state/anaconda-cleanup.done"
assert_cmd_failure "unexpected marker directory fails closed" \
    bash "$marker_reconcile"
if [ -d "$marker_state/anaconda-cleanup.done" ]; then
    _pass "unexpected marker directory is preserved for review"
else
    _fail "unexpected marker directory is preserved for review"
fi
rmdir "$marker_state/anaconda-cleanup.done"

assert_cmd_failure "runtime marker rejects an atomic rename failure" \
    env FAKE_MARKER_MV_FAIL=1 bash "$marker_script"
if [ ! -e "$marker_state/anaconda-cleanup.done" ] \
   && [ -z "$(find "$marker_state" -maxdepth 1 \
        -name '.anaconda-cleanup.done.*' -print -quit)" ]; then
    _pass "runtime rename failure leaves no marker or candidate"
else
    _fail "runtime rename failure leaves no marker or candidate"
fi

assert_cmd_failure "runtime marker rejects a final-label failure" \
    env FAKE_MARKER_RESTORECON=fail-final bash "$marker_script"
if [ ! -e "$marker_state/anaconda-cleanup.done" ]; then
    _pass "runtime final-label failure retires the published marker"
else
    _fail "runtime final-label failure retires the published marker"
fi

set +e
env FAKE_MARKER_RESTORECON=signal-final bash "$marker_script"
marker_signal_rc=$?
set -e
assert_eq 143 "$marker_signal_rc" \
    "runtime TERM after publish exits through exact marker cleanup"
if [ ! -e "$marker_state/anaconda-cleanup.done" ] \
   && [ -z "$(find "$marker_state" -maxdepth 1 \
        -name '.anaconda-cleanup.done.*' -print -quit)" ]; then
    _pass "runtime TERM after publish leaves no retry-suppressing evidence"
else
    _fail "runtime TERM after publish leaves retry-suppressing evidence"
fi

assert_cmd_success "runtime marker publishes after every final gate" \
    bash "$marker_script"
assert_grep_extended \
    '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z cleanup_count=7$' \
    "$marker_state/anaconda-cleanup.done" \
    "runtime marker has the exact one-line schema"
assert_eq "$marker_uid:$marker_gid:644:1" \
    "$(stat -Lc '%u:%g:%a:%h' "$marker_state/anaconda-cleanup.done")" \
    "runtime marker has exact ownership, mode and link count"
rm -f -- "$marker_state/anaconda-cleanup.done"

# Execute the exact production health-boundary blocks against disposable
# state. The fixture injects candidate/final label and rename failures; none
# may leave either old or newly plausible success evidence behind.
m41_stamp_root=$(mktemp -d /var/tmp/noid-m41-health-stamp.XXXXXXXX)
M41_STAMP_TEST_ROOT="$m41_stamp_root"
m41_stamp_state="$m41_stamp_root/state"
m41_stamp_bin="$m41_stamp_root/bin"
m41_stamp_invalidate="$m41_stamp_root/invalidate.sh"
m41_stamp_publish="$m41_stamp_root/publish.sh"
m41_stamp_uid=$(id -u)
m41_stamp_gid=$(id -g)
m41_checks_total=$(sed -n \
    's/^checks_total=\([1-9][0-9]*\)$/\1/p' "$KS_FILE")
assert_eq 15 "$m41_checks_total" \
    "health fixture derives the current M41 verification count"
printf -v m41_sha_seed '%064d' 0
m41_identity_sha=${m41_sha_seed//0/a}
m41_identity_service_sha=${m41_sha_seed//0/b}
m41_cleanup_sha=${m41_sha_seed//0/c}
m41_security_service_sha=${m41_sha_seed//0/d}
m41_maintenance_service_sha=${m41_sha_seed//0/e}
m41_gdm_gate_sha=${m41_sha_seed//0/f}
m41_user_sessions_gate_sha=${m41_sha_seed//0/1}
mkdir -p "$m41_stamp_bin"

cat > "$m41_stamp_bin/restorecon" <<'M41_STAMP_RESTORECON_EOF'
#!/usr/bin/env bash
set -euo pipefail
target="${!#}"
if [ "${FAKE_RESTORECON_SIGNAL:-}" = candidate ]; then
    case "$target" in
        */.stamp-41-anaconda-cleanup.*)
            kill -TERM "$PPID"
            sleep 1
            ;;
    esac
fi
case "${FAKE_RESTORECON_FAIL:-}" in
    all) exit 1 ;;
    final)
        case "$target" in
            */stamp-41-anaconda-cleanup.ok) exit 1 ;;
        esac
        ;;
esac
exit 0
M41_STAMP_RESTORECON_EOF
cat > "$m41_stamp_bin/matchpathcon" <<'M41_STAMP_MATCHPATHCON_EOF'
#!/usr/bin/env bash
exit 0
M41_STAMP_MATCHPATHCON_EOF
cat > "$m41_stamp_bin/mv" <<'M41_STAMP_MV_EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "${FAKE_MV_FAIL:-0}" -eq 1 ]; then
    exit 1
fi
exec /usr/bin/mv "$@"
M41_STAMP_MV_EOF
chmod 0700 "$m41_stamp_bin/restorecon" \
    "$m41_stamp_bin/matchpathcon" "$m41_stamp_bin/mv"

{
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
        'log() { :; }'
    sed -n \
        '/^# M41_HEALTH_INVALIDATION_BEGIN$/,/^# M41_HEALTH_INVALIDATION_END$/p' \
        "$KS_FILE" |
        sed -e "s|/var/lib/noid-privacy|$m41_stamp_state|g" \
            -e "s|/usr/sbin/restorecon|$m41_stamp_bin/restorecon|g" \
            -e "s|/usr/sbin/matchpathcon|$m41_stamp_bin/matchpathcon|g" \
            -e "s/-o root -g root/-o $m41_stamp_uid -g $m41_stamp_gid/" \
            -e "s/0:0:755/$m41_stamp_uid:$m41_stamp_gid:755/"
} > "$m41_stamp_invalidate"
{
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
        'log() { :; }' \
        'fail() { exit 1; }' \
        "M41_STATE_DIR=$m41_stamp_state" \
        'STAMP="$M41_STATE_DIR/stamp-41-anaconda-cleanup.ok"' \
        "checks_total=$m41_checks_total" \
        'verify_fail=0' 'SERVICE_ENABLED=enabled' \
        'verify_owned_regular() {' \
        '    local path=$1 mode=$2' \
        "    [ -f \"\$path\" ] && [ ! -L \"\$path\" ] \\" \
        "        && [ \"\$(stat -Lc '%u:%g:%a:%h' \"\$path\")\" = \"$m41_stamp_uid:$m41_stamp_gid:\${mode}:1\" ]" \
        '}'
    sed -n \
        '/^# M41_ROOT_PUBLICATION_BEGIN$/,/^# M41_ROOT_PUBLICATION_END$/p' \
        "$KS_FILE" |
        sed -e "s|/usr/sbin/restorecon|$m41_stamp_bin/restorecon|g" \
            -e "s|/usr/sbin/matchpathcon|$m41_stamp_bin/matchpathcon|g" \
            -e "s/-o root -g root/-o $m41_stamp_uid -g $m41_stamp_gid/g" \
            -e "s/0:0/$m41_stamp_uid:$m41_stamp_gid/g"
    sed -n \
        '/^# M41_BUILD_CLEANUP_BEGIN$/,/^# M41_BUILD_CLEANUP_END$/p' \
        "$KS_FILE"
    printf '%s\n' \
        "IDENTITY_EXPECTED_SHA=$m41_identity_sha" \
        "IDENTITY_SERVICE_EXPECTED_SHA=$m41_identity_service_sha" \
        "CLEANUP_EXPECTED_SHA=$m41_cleanup_sha" \
        "SERVICE_EXPECTED_SHA=$m41_security_service_sha" \
        "MAINTENANCE_SERVICE_EXPECTED_SHA=$m41_maintenance_service_sha" \
        "GDM_GATE_EXPECTED_SHA=$m41_gdm_gate_sha" \
        "USER_SESSIONS_GATE_EXPECTED_SHA=$m41_user_sessions_gate_sha"
    sed -n \
        '/^# M41_HEALTH_PUBLICATION_BEGIN$/,/^# M41_HEALTH_PUBLICATION_END$/p' \
        "$KS_FILE" |
        sed -e "s|/usr/sbin/restorecon|$m41_stamp_bin/restorecon|g" \
            -e "s|/usr/sbin/matchpathcon|$m41_stamp_bin/matchpathcon|g" \
            -e "s/chown root:root/chown $m41_stamp_uid:$m41_stamp_gid/" \
            -e "s/0:0:755/$m41_stamp_uid:$m41_stamp_gid:755/"
} > "$m41_stamp_publish"
chmod 0700 "$m41_stamp_invalidate" "$m41_stamp_publish"

mkdir -m 0755 "$m41_stamp_state"
printf '%s\n' 'module=41' 'name=anaconda-cleanup' 'status=ok' \
    > "$m41_stamp_state/stamp-41-anaconda-cleanup.ok"
assert_cmd_success "M41 rerun invalidates its prior build-success stamp" \
    env PATH="$m41_stamp_bin:$PATH" "$m41_stamp_invalidate"
if [ ! -e "$m41_stamp_state/stamp-41-anaconda-cleanup.ok" ]; then
    _pass "M41 old success evidence is absent before payload publication"
else
    _fail "M41 old success evidence is absent before payload publication"
fi

chmod 0777 "$m41_stamp_state"
printf '%s\n' 'must-survive' \
    > "$m41_stamp_state/stamp-41-anaconda-cleanup.ok"
assert_cmd_failure "M41 rejects shared state-directory metadata drift" \
    env PATH="$m41_stamp_bin:$PATH" "$m41_stamp_invalidate"
assert_eq "$m41_stamp_uid:$m41_stamp_gid:777" \
    "$(stat -c '%u:%g:%a' "$m41_stamp_state")" \
    "M41 does not normalize drifted shared-directory metadata"
assert_grep_fixed 'must-survive' \
    "$m41_stamp_state/stamp-41-anaconda-cleanup.ok" \
    "M41 does not touch evidence through a drifted state boundary"
rm "$m41_stamp_state/stamp-41-anaconda-cleanup.ok"
chmod 0755 "$m41_stamp_state"

assert_cmd_failure "M41 rejects a health-stamp candidate label failure" \
    env PATH="$m41_stamp_bin:$PATH" FAKE_RESTORECON_FAIL=all \
        "$m41_stamp_publish"
if [ ! -e "$m41_stamp_state/stamp-41-anaconda-cleanup.ok" ] \
   && [ -z "$(find "$m41_stamp_state" -maxdepth 1 \
        -name '.stamp-41-anaconda-cleanup.*' -print -quit)" ]; then
    _pass "M41 candidate-label failure leaves no plausible health evidence"
else
    _fail "M41 candidate-label failure leaves no plausible health evidence"
fi

assert_cmd_failure "M41 retires a stamp after final-label failure" \
    env PATH="$m41_stamp_bin:$PATH" FAKE_RESTORECON_FAIL=final \
        "$m41_stamp_publish"
if [ ! -e "$m41_stamp_state/stamp-41-anaconda-cleanup.ok" ]; then
    _pass "M41 final-label failure removes the published success stamp"
else
    _fail "M41 final-label failure removes the published success stamp"
fi

assert_cmd_failure "M41 rejects an atomic health-stamp rename failure" \
    env PATH="$m41_stamp_bin:$PATH" FAKE_MV_FAIL=1 "$m41_stamp_publish"
if [ ! -e "$m41_stamp_state/stamp-41-anaconda-cleanup.ok" ] \
   && [ -z "$(find "$m41_stamp_state" -maxdepth 1 \
        -name '.stamp-41-anaconda-cleanup.*' -print -quit)" ]; then
    _pass "M41 rename failure leaves no stamp or staged candidate"
else
    _fail "M41 rename failure leaves no stamp or staged candidate"
fi

set +e
env PATH="$m41_stamp_bin:$PATH" FAKE_RESTORECON_SIGNAL=candidate \
    "$m41_stamp_publish"
m41_stamp_signal_rc=$?
set -e
assert_eq 143 "$m41_stamp_signal_rc" \
    "M41 TERM exits through the build-candidate cleanup path"
if [ ! -e "$m41_stamp_state/stamp-41-anaconda-cleanup.ok" ] \
   && [ -z "$(find "$m41_stamp_state" -maxdepth 1 \
        -name '.stamp-41-anaconda-cleanup.*' -print -quit)" ]; then
    _pass "M41 TERM leaves no final stamp or staged candidate"
else
    _fail "M41 TERM leaves no final stamp or staged candidate"
fi

# A pre-existing symlink at the final path must be replaced, never followed.
printf '%s\n' 'must-not-be-overwritten' > "$m41_stamp_root/symlink-victim"
ln -s "$m41_stamp_root/symlink-victim" \
    "$m41_stamp_state/stamp-41-anaconda-cleanup.ok"
assert_cmd_success "M41 replaces rather than follows a final-path symlink" \
    env PATH="$m41_stamp_bin:$PATH" "$m41_stamp_publish"
assert_cmd_success "M41 health publication ends as a regular non-symlink" \
    bash -c '[ -f "$1" ] && [ ! -L "$1" ]' _ \
        "$m41_stamp_state/stamp-41-anaconda-cleanup.ok"
assert_grep_fixed 'must-not-be-overwritten' \
    "$m41_stamp_root/symlink-victim" \
    "M41 publisher leaves a symlink target untouched"
assert_grep_fixed '# NoID Privacy — Module 41 Health Stamp' \
    "$m41_stamp_state/stamp-41-anaconda-cleanup.ok" \
    "M41 health stamp identifies its module"
assert_grep_fixed \
    '# Written at end of %post verification when all checks pass.' \
    "$m41_stamp_state/stamp-41-anaconda-cleanup.ok" \
    "M41 health stamp records its success boundary"
assert_grep_fixed \
    '# Format: shell-sourceable key=value. See docs/engineering-health-stamp-pattern.md.' \
    "$m41_stamp_state/stamp-41-anaconda-cleanup.ok" \
    "M41 health stamp identifies its canonical schema"
assert_grep_fixed 'module=41' \
    "$m41_stamp_state/stamp-41-anaconda-cleanup.ok"
assert_grep_fixed 'name=anaconda-cleanup' \
    "$m41_stamp_state/stamp-41-anaconda-cleanup.ok"
assert_grep_fixed "checks_passed=$m41_checks_total" \
    "$m41_stamp_state/stamp-41-anaconda-cleanup.ok"
assert_grep_fixed 'service_enabled=enabled' \
    "$m41_stamp_state/stamp-41-anaconda-cleanup.ok"
assert_grep_fixed "identity_sha256=$m41_identity_sha" \
    "$m41_stamp_state/stamp-41-anaconda-cleanup.ok"
assert_grep_fixed "identity_service_sha256=$m41_identity_service_sha" \
    "$m41_stamp_state/stamp-41-anaconda-cleanup.ok"
assert_grep_fixed "cleanup_sha256=$m41_cleanup_sha" \
    "$m41_stamp_state/stamp-41-anaconda-cleanup.ok"
assert_grep_fixed "security_service_sha256=$m41_security_service_sha" \
    "$m41_stamp_state/stamp-41-anaconda-cleanup.ok"
assert_grep_fixed \
    "maintenance_service_sha256=$m41_maintenance_service_sha" \
    "$m41_stamp_state/stamp-41-anaconda-cleanup.ok"
assert_grep_fixed "gdm_gate_sha256=$m41_gdm_gate_sha" \
    "$m41_stamp_state/stamp-41-anaconda-cleanup.ok"
assert_grep_fixed \
    "user_sessions_gate_sha256=$m41_user_sessions_gate_sha" \
    "$m41_stamp_state/stamp-41-anaconda-cleanup.ok"
assert_eq 18 \
    "$(wc -l < "$m41_stamp_state/stamp-41-anaconda-cleanup.ok")" \
    "M41 published health stamp has the exact eighteen-line schema"

assert_grep_fixed "stat -Lc '%u:%g:%a' -- \"\$STATE_DIR\"" \
    "$TMPDIR/cleanup.sh" \
    "runtime directory metadata is filesystem-independent"
assert_not_grep \
    "stat -Lc '%u:%g:%a:%h' -- \"\\\$STATE_DIR\"" \
    "$TMPDIR/cleanup.sh" \
    "runtime never assumes a Btrfs-specific directory link count"
assert_grep_fixed \
    "cmp -s /etc/systemd/system/gdm.service.d/40-noid-anaconda-cleanup.conf" \
    "$KS_FILE" "M41 verifies the exact GDM success-gate bytes"
assert_grep_fixed \
    "cmp -s /etc/systemd/system/systemd-user-sessions.service.d/40-noid-anaconda-cleanup.conf" \
    "$KS_FILE" "M41 verifies the exact user-session success-gate bytes"
assert_grep_fixed 'readlink -f' "$KS_FILE" \
    "M41 verifies the graphical-target symlink destination"
assert_not_grep 'restorecon .*2>/dev/null || true' "$KS_FILE" \
    "M41 does not hide SELinux relabel failures"

test_finish

#!/usr/bin/env bash
# Installed-candidate zero-unexplained-denial gate for the current boot.
# Build-installer permissive AVCs are classified separately and never cross
# this boundary into an enforcing installed-system exception.
set -euo pipefail

TEST_NAME=31-installed-enforcing-avc
if [ "$(id -u)" -ne 0 ]; then
    if sudo -n true >/dev/null 2>&1; then
        exec sudo -n "$0"
    fi
    echo "FAIL  $TEST_NAME: run as root or establish sudo credentials first" >&2
    exit 2
fi
for tool in getenforce auditctl ausearch awk grep mktemp rm; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "FAIL  $TEST_NAME: missing command: $tool" >&2
        exit 2
    }
done

WORK_DIR=$(mktemp -d /var/tmp/noid-enforcing-avc.XXXXXX)
trap 'rm -rf -- "$WORK_DIR"' EXIT

[ "$(getenforce)" = Enforcing ] || {
    echo "FAIL  $TEST_NAME: SELinux is not enforcing" >&2
    exit 1
}

# BEGIN SELINUX_KERNEL_POLICY_SCHEMA_GATE
# Enforcing mode is not complete evidence when the loaded base policy predates
# security classes or permissions used by the running kernel. Fedora 44's
# maintained policy currently leaves the newer extensions below unavailable
# under handle_unknown=allow, so report that vendor boundary without making the
# supported platform impossible to release. The established F44 baseline stays
# fail-closed, and an enabled policy capability makes its associated extension
# paths mandatory.
SELINUXFS_ROOT=/sys/fs/selinux

require_selinux_baseline_path() {
    local relative_path=$1
    [ -e "$SELINUXFS_ROOT/$relative_path" ] || {
        echo "FAIL  $TEST_NAME: loaded SELinux policy regressed below the Fedora 44 schema baseline at $relative_path" >&2
        exit 1
    }
}

require_selinux_capability_schema_path() {
    local capability=$1 relative_path=$2
    [ -e "$SELINUXFS_ROOT/$relative_path" ] || {
        echo "FAIL  $TEST_NAME: loaded SELinux policy enables $capability but lacks its associated extension schema at $relative_path" >&2
        exit 1
    }
}

require_memfd_capability_schema_path() {
    require_selinux_capability_schema_path memfd_class "$1"
}

read_selinux_boolean_file() {
    local relative_path=$1 description=$2 value=''
    [ -f "$SELINUXFS_ROOT/$relative_path" ] || {
        echo "FAIL  $TEST_NAME: loaded SELinux policy lacks $description" >&2
        exit 1
    }
    # selinuxfs boolean pseudo-files expose one byte without a trailing newline;
    # bash read then returns EOF status even though it populated the value.
    if ! IFS= read -r value < "$SELINUXFS_ROOT/$relative_path" && \
       [ -z "$value" ]; then
        echo "FAIL  $TEST_NAME: cannot read SELinux $description" >&2
        exit 2
    fi
    case "$value" in
        0|1) printf '%s\n' "$value" ;;
        *)
            echo "FAIL  $TEST_NAME: invalid SELinux $description value" >&2
            exit 2
            ;;
    esac
}

read_selinux_policy_capability() {
    local capability=$1 value
    value=$(read_selinux_boolean_file "policy_capabilities/$capability" \
        "policy capability $capability") || exit $?
    printf '%s\n' "$value"
}

# These are the established kernel-facing vectors in Fedora 44's current base
# policy. Losing any of them is a regression, not the known extension gap.
while IFS=' ' read -r security_class permission; do
    [ -n "$security_class" ] || continue
    require_selinux_baseline_path "class/$security_class/perms/$permission"
done <<'BASELINE_PERMISSIONS_EOF'
system ipc_info
system syslog_read
system syslog_mod
system syslog_console
system module_request
system module_load
bpf map_create
bpf map_read
bpf map_write
bpf prog_load
bpf prog_run
io_uring override_creds
io_uring sqpoll
io_uring cmd
BASELINE_PERMISSIONS_EOF

SELINUX_EXTENSION_TOTAL=0
SELINUX_EXTENSION_PRESENT=0
observe_selinux_extension_path() {
    local relative_path=$1
    SELINUX_EXTENSION_TOTAL=$((SELINUX_EXTENSION_TOTAL + 1))
    if [ -e "$SELINUXFS_ROOT/$relative_path" ]; then
        SELINUX_EXTENSION_PRESENT=$((SELINUX_EXTENSION_PRESENT + 1))
    fi
}

visit_memfd_extension_paths() {
    local visitor=$1 permission
    "$visitor" class/memfd_file
    while IFS= read -r permission; do
        [ -n "$permission" ] || continue
        "$visitor" "class/memfd_file/perms/$permission"
    done <<'MEMFD_PERMISSIONS_EOF'
ioctl
read
write
create
getattr
setattr
lock
relabelfrom
relabelto
append
map
unlink
link
rename
execute
quotaon
mounton
audit_access
open
execmod
watch
watch_mount
watch_sb
watch_with_perm
watch_reads
watch_mountns
execute_no_trans
entrypoint
MEMFD_PERMISSIONS_EOF
}

visit_memfd_extension_paths observe_selinux_extension_path

while IFS=' ' read -r security_class permission; do
    [ -n "$security_class" ] || continue
    observe_selinux_extension_path "class/$security_class/perms/$permission"
done <<'KERNEL_PERMISSIONS_EOF'
system firmware_load
system kexec_image_load
system kexec_initramfs_load
system policy_load
system x509_certificate_load
bpf map_create_as
bpf prog_load_as
io_uring allowed
KERNEL_PERMISSIONS_EOF

MEMFD_CLASS_CAP=$(read_selinux_policy_capability memfd_class)
BPF_TOKEN_PERMS_CAP=$(read_selinux_policy_capability bpf_token_perms)
DENY_UNKNOWN=$(read_selinux_boolean_file deny_unknown deny_unknown)
REJECT_UNKNOWN=$(read_selinux_boolean_file reject_unknown reject_unknown)

# Once a loaded policy opts into either kernel behavior, missing associated
# schema is inconsistent and must never be accepted as the Fedora 44 gap.
if [ "$MEMFD_CLASS_CAP" = 1 ]; then
    visit_memfd_extension_paths require_memfd_capability_schema_path
fi
if [ "$BPF_TOKEN_PERMS_CAP" = 1 ]; then
    require_selinux_capability_schema_path \
        bpf_token_perms class/bpf/perms/map_create_as
    require_selinux_capability_schema_path \
        bpf_token_perms class/bpf/perms/prog_load_as
fi

if [ "$SELINUX_EXTENSION_PRESENT" -eq "$SELINUX_EXTENSION_TOTAL" ] && \
   [ "$MEMFD_CLASS_CAP" = 1 ] && [ "$BPF_TOKEN_PERMS_CAP" = 1 ]; then
    SELINUX_SCHEMA_COVERAGE=complete
else
    SELINUX_SCHEMA_COVERAGE=partial
    if [ "$DENY_UNKNOWN" = 0 ]; then
        HANDLE_UNKNOWN=allow
    else
        HANDLE_UNKNOWN=deny
    fi
    echo "WARN  $TEST_NAME: SELinux kernel-extension coverage is partial ($SELINUX_EXTENSION_PRESENT/$SELINUX_EXTENSION_TOTAL paths, memfd_class=$MEMFD_CLASS_CAP, bpf_token_perms=$BPF_TOKEN_PERMS_CAP, handle_unknown=$HANDLE_UNKNOWN)" >&2
fi
[ -n "${HANDLE_UNKNOWN:-}" ] || {
    if [ "$DENY_UNKNOWN" = 0 ]; then
        HANDLE_UNKNOWN=allow
    else
        HANDLE_UNKNOWN=deny
    fi
}
# END SELINUX_KERNEL_POLICY_SCHEMA_GATE

audit_status=$(auditctl -s)
enabled=$(awk '$1 == "enabled" {print $2}' <<< "$audit_status")
lost=$(awk '$1 == "lost" {print $2}' <<< "$audit_status")
[ "$enabled" = 2 ] || {
    echo "FAIL  $TEST_NAME: audit is not immutable/enabled=2" >&2
    exit 1
}
[[ $lost =~ ^[0-9]+$ ]] && [ "$lost" -eq 0 ] || {
    echo "FAIL  $TEST_NAME: audit reports lost events (${lost:-unknown})" >&2
    exit 1
}

search_rc=0
ausearch --input-logs -m AVC,USER_AVC -ts boot --raw \
    > "$WORK_DIR/avc.log" 2> "$WORK_DIR/ausearch.err" || search_rc=$?
case "$search_rc" in
    0)
        denial_count=$(grep -Eic 'type=(AVC|USER_AVC)|avc:[[:space:]]+denied' \
            "$WORK_DIR/avc.log" || true)
        echo "FAIL  $TEST_NAME: $denial_count enforcing-boot AVC record(s); no allowlist applies" >&2
        exit 1
        ;;
    1)
        [ ! -s "$WORK_DIR/avc.log" ] || {
            echo "FAIL  $TEST_NAME: ausearch returned no-match with nonempty output" >&2
            exit 2
        }
        [ ! -s "$WORK_DIR/ausearch.err" ] || {
            awk '{ print "  ausearch: " $0 }' "$WORK_DIR/ausearch.err" >&2
            echo "FAIL  $TEST_NAME: ausearch emitted diagnostics while reading audit logs" >&2
            exit 2
        }
        ;;
    *)
        awk '{ print "  ausearch: " $0 }' "$WORK_DIR/ausearch.err" >&2
        echo "FAIL  $TEST_NAME: ausearch failed (rc=$search_rc)" >&2
        exit 2
        ;;
esac

echo "PASS  $TEST_NAME: SELinux=enforcing kernel-policy-baseline=complete extension-coverage=$SELINUX_SCHEMA_COVERAGE handle-unknown=$HANDLE_UNKNOWN reject-unknown=$REJECT_UNKNOWN audit=immutable lost=0 AVC=0"

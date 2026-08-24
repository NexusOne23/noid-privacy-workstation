#!/bin/bash
# M14 candidate runtime gate — least-privilege named USBGuard IPC.
# Run as root in Live, fresh-install and reboot candidate passes.
set -euo pipefail
export LC_ALL=C.UTF-8 LANG=C.UTF-8

TEST_NAME=14-usbguard-runtime
PASS_ID=${1:-invalid}
fail() { echo "FAIL  $TEST_NAME [$PASS_ID]: $*" >&2; exit 1; }
note() { echo "  [$PASS_ID] $*"; }

[ "$#" -eq 1 ] || {
    echo "usage: $0 {live|fresh-install|reboot}" >&2
    exit 2
}
case "$PASS_ID" in
    live|fresh-install|reboot) ;;
    *)
        echo "usage: $0 {live|fresh-install|reboot}" >&2
        exit 2
        ;;
esac

if [ "$(id -u)" -ne 0 ]; then
    if sudo -n true >/dev/null 2>&1; then
        exec sudo -n "$0" "$PASS_ID"
    fi
    fail "run as root or establish sudo credentials first"
fi
grep -q '^ID=noid-privacy-workstation$' /etc/os-release 2>/dev/null || \
    fail "not running inside the NoID Privacy candidate"
for tool in awk cmp getent grep id matchpathcon mktemp rm runuser sed \
            sha256sum stat systemctl tr usbguard; do
    command -v "$tool" >/dev/null 2>&1 || fail "missing command: $tool"
done

runtime_tmp=$(mktemp -d /var/tmp/noid-usbguard-runtime.XXXXXX)
trap 'rm -rf -- "$runtime_tmp"' EXIT

DAEMON_CONF=/etc/usbguard/usbguard-daemon.conf
IPC_DIR=/etc/usbguard/IPCAccessControl.d
RULES=/etc/usbguard/rules.conf
ELIGIBLE=/usr/libexec/noid-eligible-user

for path in "$DAEMON_CONF" "$RULES"; do
    [ -f "$path" ] && [ ! -L "$path" ] && [ -s "$path" ] || \
        fail "missing, empty, non-regular or symlinked USBGuard artifact: $path"
    [ "$(stat -c '%U:%G:%a:%h' "$path")" = root:root:600:1 ] || \
        fail "USBGuard policy metadata is not root:root 0600 with one link: $path"
    matchpathcon -V "$path" >/dev/null 2>&1 || \
        fail "USBGuard policy SELinux label differs: $path"
done
[ -f "$ELIGIBLE" ] && [ ! -L "$ELIGIBLE" ] && [ -x "$ELIGIBLE" ] || \
    fail "shared eligible-user classifier is missing, non-regular or symlinked"
[ "$(stat -c '%U:%G:%a:%h' "$ELIGIBLE")" = root:root:755:1 ] || \
    fail "shared eligible-user classifier metadata differs"
matchpathcon -V "$ELIGIBLE" >/dev/null 2>&1 || \
    fail "shared eligible-user classifier SELinux label differs"
[ -d "$IPC_DIR" ] && [ ! -L "$IPC_DIR" ] || \
    fail "IPC access-control path is not a real directory"
[ "$(stat -Lc '%U:%G:%a' "$IPC_DIR")" = root:root:755 ] || \
    fail "IPC directory metadata is not root:root 0755"
matchpathcon -V "$IPC_DIR" >/dev/null 2>&1 || \
    fail "IPC directory SELinux label differs"

grep -qxF 'ImplicitPolicyTarget=block' "$DAEMON_CONF" || \
    fail "implicit USB policy is not block"
grep -qxF 'AuthorizedDefault=none' "$DAEMON_CONF" || \
    fail "kernel-side default authorization is not none"
grep -qxF 'IPCAccessControlFiles=/etc/usbguard/IPCAccessControl.d/' \
    "$DAEMON_CONF" || fail "named IPC access-control directory is not configured"
if grep -Eq '^[[:space:]]*(IPCAllowedGroups|IPCAllowedUsers)[[:space:]]*=' \
        "$DAEMON_CONF"; then
    fail "broad group/user IPC authorization is active"
fi

emit_profile() {
    case "$1" in
        user)
            printf '%s\n' \
                'Devices=list,modify,listen' \
                'Policy=list' \
                'Parameters=list,listen' \
                'Exceptions=listen'
            ;;
        root)
            printf '%s\n' \
                'Devices=list,modify,listen' \
                'Policy=list,modify' \
                'Parameters=list,modify,listen' \
                'Exceptions=listen'
            ;;
        *) return 1 ;;
    esac
}

check_acl() {
    local name=$1 profile=$2 target="$IPC_DIR/$1"
    [ -f "$target" ] && [ ! -L "$target" ] || \
        fail "named IPC ACL is missing, non-regular or symlinked"
    [ "$(stat -Lc '%u:%g:%a:%h' "$target")" = 0:0:600:1 ] || \
        fail "named IPC ACL owner/mode/link identity is invalid"
    matchpathcon -V "$target" >/dev/null 2>&1 || \
        fail "named IPC ACL SELinux label differs"
    cmp -s "$target" <(emit_profile "$profile") || \
        fail "named IPC ACL bytes do not match the $profile profile"
}

check_acl root root

declare -a eligible_users=()
while IFS=: read -r name _ uid _ _ _ _; do
    "$ELIGIBLE" account-uid "$uid" || continue
    eligible_users+=("$name")
    check_acl "$name" user
    if getent group usbguard >/dev/null 2>&1 && \
       id -nG "$name" 2>/dev/null | tr ' ' '\n' | grep -qx usbguard; then
        fail "eligible user retains legacy supplementary usbguard membership"
    fi
done < <(getent passwd)
[ "${#eligible_users[@]}" -gt 0 ] || fail "no eligible user found for IPC checks"

is_expected_acl_name() {
    local candidate=$1 user
    [ "$candidate" = root ] && return 0
    for user in "${eligible_users[@]}"; do
        [ "$candidate" = "$user" ] && return 0
    done
    return 1
}

shopt -s nullglob dotglob
for acl in "$IPC_DIR"/*; do
    [ -f "$acl" ] && [ ! -L "$acl" ] || fail "unexpected non-regular IPC entry"
    is_expected_acl_name "${acl##*/}" || fail "IPC ACL exists for an ineligible identity"
done
shopt -u nullglob dotglob
note "named root/user ACL bytes, metadata and account scope verified"

query_rules_by_label() {
    local label=$1 destination=$2 stderr_file=$3
    if ! usbguard list-rules --label "$label" \
            >"$destination" 2>"$stderr_file"; then
        sed 's/^/  usbguard: /' "$stderr_file" >&2
        fail "cannot query USBGuard rules with label $label"
    fi
}

is_exact_ipc_denial() {
    local stdout_file=$1 stderr_file=$2
    [ ! -s "$stdout_file" ] \
        && grep -qF 'IPC ERROR:' "$stderr_file" \
        && grep -qF 'Permission denied' "$stderr_file"
}

for unit in usbguard.service usbguard-dbus.service; do
    systemctl is-enabled --quiet "$unit" || fail "$unit is not enabled"
    systemctl is-active --quiet "$unit" || fail "$unit is not active"
done
query_rules_by_label GNOME_SETTINGS_DAEMON_RULE \
    "$runtime_tmp/gnome-rules.out" "$runtime_tmp/gnome-rules.err"
if [ -s "$runtime_tmp/gnome-rules.out" ]; then
    fail "GNOME's global USBGuard allow wildcard is present"
fi

probe_user=${eligible_users[0]}
rules_hash_before=$(sha256sum "$RULES" | awk '{print $1}')
original_parameter=$(runuser -u "$probe_user" -- \
    usbguard get-parameter ImplicitPolicyTarget 2>/dev/null) || \
    fail "normal user cannot read the implicit policy parameter"
[ "$original_parameter" = block ] || fail "runtime implicit policy is not block"

runuser -u "$probe_user" -- usbguard list-devices >/dev/null || \
    fail "normal user cannot list devices"
runuser -u "$probe_user" -- usbguard list-rules >/dev/null || \
    fail "normal user cannot list policy"

allowed_id=$(runuser -u "$probe_user" -- usbguard list-devices -a 2>/dev/null | \
    awk 'NR == 1 { sub(/:$/, "", $1); if ($1 ~ /^[0-9]+$/) print $1 }')
[ -n "$allowed_id" ] || fail "no allowed device is available for an idempotent modify probe"
runuser -u "$probe_user" -- usbguard allow-device "$allowed_id" >/dev/null 2>&1 || \
    fail "normal user lacks notifier-compatible device modification"

set +e
runuser -u "$probe_user" -- usbguard set-parameter \
    ImplicitPolicyTarget "$original_parameter" \
    >"$runtime_tmp/set-parameter.out" 2>"$runtime_tmp/set-parameter.err"
set_parameter_rc=$?
set -e
if [ "$set_parameter_rc" -eq 0 ]; then
    fail "normal user can write the fail-closed daemon parameter"
fi
if ! is_exact_ipc_denial "$runtime_tmp/set-parameter.out" \
        "$runtime_tmp/set-parameter.err"; then
    sed 's/^/  usbguard: /' "$runtime_tmp/set-parameter.err" >&2
    fail "parameter probe failed for a reason other than IPC authorization denial"
fi
[ "$(usbguard get-parameter ImplicitPolicyTarget)" = block ] || \
    fail "denied parameter probe changed the implicit policy"

probe_label=NOID_RUNTIME_IPC_PROBE
set +e
runuser -u "$probe_user" -- usbguard append-rule \
    "block id ffff:ffff label \"$probe_label\"" \
    >"$runtime_tmp/append-rule.out" 2>"$runtime_tmp/append-rule.err"
append_rule_rc=$?
set -e
if [ "$append_rule_rc" -eq 0 ]; then
    cleanup_ok=1
    while read -r rule_id _; do
        [[ $rule_id =~ ^[0-9]+:$ ]] || continue
        if ! usbguard remove-rule "${rule_id%:}" >/dev/null 2>&1; then
            cleanup_ok=0
        fi
    done < <(usbguard list-rules --label "$probe_label" 2>/dev/null)
    [ "$cleanup_ok" -eq 1 ] || \
        fail "normal user appended policy and exact cleanup failed"
    query_rules_by_label "$probe_label" \
        "$runtime_tmp/post-cleanup.out" "$runtime_tmp/post-cleanup.err"
    if [ -s "$runtime_tmp/post-cleanup.out" ]; then
        fail "normal user appended policy and cleanup left a durable rule"
    fi
    fail "normal user appended durable USBGuard policy"
fi
if ! is_exact_ipc_denial "$runtime_tmp/append-rule.out" \
        "$runtime_tmp/append-rule.err"; then
    sed 's/^/  usbguard: /' "$runtime_tmp/append-rule.err" >&2
    fail "policy probe failed for a reason other than IPC authorization denial"
fi
query_rules_by_label "$probe_label" \
    "$runtime_tmp/denied-probe.out" "$runtime_tmp/denied-probe.err"
if [ -s "$runtime_tmp/denied-probe.out" ]; then
    fail "denied policy probe left a durable rule"
fi

rules_hash_after=$(sha256sum "$RULES" | awk '{print $1}')
[ "$rules_hash_after" = "$rules_hash_before" ] || \
    fail "rules.conf changed during denied IPC probes"

echo "PASS: $TEST_NAME [$PASS_ID] named ACLs enforce device-only modification"

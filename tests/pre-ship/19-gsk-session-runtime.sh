#!/usr/bin/env bash
# Candidate gate for the post-Shell hybrid-GPU GTK activation environment.
set -euo pipefail
export LC_ALL=C
export PATH=/usr/local/bin:/usr/sbin:/usr/bin
export BASH_ENV=/dev/null
export ENV=/dev/null
IFS=$' \t\n'
umask 077
unset CDPATH GLOBIGNORE TMPDIR

TEST_NAME=19-gsk-session-runtime
PASS_ID=unresolved
fail() {
    echo "FAIL  $TEST_NAME [$PASS_ID]: $*" >&2
    exit 1
}

[[ $# -eq 1 ]] || {
    echo "Usage: bash $0 {live|fresh-install|reboot}" >&2
    exit 2
}
PASS_ID=$1
case "$PASS_ID" in
    live|fresh-install|reboot) ;;
    *) fail "pass identity must be live, fresh-install or reboot" ;;
esac

for required_command in \
        awk cmp dirname getent grep id loginctl matchpathcon mktemp python3 \
        readlink rm rpm sed sha256sum stat systemctl systemd-run tail timeout tr; do
    command -v "$required_command" >/dev/null 2>&1 || \
        fail "required command missing: $required_command"
done

SCRIPT_PATH=$(readlink -e -- "$0") || fail "cannot resolve gate path"
REPO_ROOT=$(cd "$(dirname "$SCRIPT_PATH")/../.." && pwd -P) || \
    fail "cannot resolve repository root"
M19_REPO="$REPO_ROOT/kickstart/snippets/19-nvidia-mok-docs.ks"
M13_REPO="$REPO_ROOT/kickstart/snippets/13-aide-welcome.ks"
for repository_source in "$M13_REPO" "$M19_REPO"; do
    [[ -f $repository_source && ! -L $repository_source \
       && -s $repository_source \
       && $(readlink -e -- "$repository_source") == "$repository_source" ]] || \
        fail "canonical source is missing, empty, symlinked or non-canonical"
done

USER_UID=$(id -u)
USER_GID=$(id -g)
[[ $USER_UID -ne 0 ]] || fail "run as the normal GNOME user, not root"
PASSWD_HOME=$(getent passwd "$USER_UID" | awk -F: 'NR == 1 { print $6 }') || \
    fail "cannot resolve account home"
[[ -n $PASSWD_HOME && ${HOME:-} == "$PASSWD_HOME" ]] || \
    fail "HOME differs from the account database"
[[ $(grep -c '^ID=noid-privacy-workstation$' /etc/os-release 2>/dev/null || true) \
    -eq 1 ]] || fail "not running inside the NoID Privacy candidate"

RUNTIME_ROOT=${XDG_RUNTIME_DIR:-}
[[ $RUNTIME_ROOT == "/run/user/$USER_UID" \
   && -d $RUNTIME_ROOT && ! -L $RUNTIME_ROOT \
   && $(readlink -e -- "$RUNTIME_ROOT") == "$RUNTIME_ROOT" \
   && $(stat -c '%u:%g:%a' -- "$RUNTIME_ROOT") == \
      "$USER_UID:$USER_GID:700" ]] || \
    fail "XDG runtime directory is unavailable or unsafe"
matchpathcon -V "$RUNTIME_ROOT" >/dev/null || \
    fail "XDG runtime directory SELinux label differs"
SESSION_BUS="$RUNTIME_ROOT/bus"
[[ ${DBUS_SESSION_BUS_ADDRESS:-} == "unix:path=$SESSION_BUS" ]] || \
    fail "session D-Bus address is not the canonical user-bus socket"
[[ -S $SESSION_BUS && ! -L $SESSION_BUS \
   && $(readlink -e -- "$SESSION_BUS") == "$SESSION_BUS" \
   && $(stat -c '%u:%g:%a:%h' -- "$SESSION_BUS") == \
      "$USER_UID:$USER_GID:666:1" ]] || \
    fail "session D-Bus socket metadata is invalid"
matchpathcon -V "$SESSION_BUS" >/dev/null || \
    fail "session D-Bus socket SELinux label differs"

TEST_TMP=$(mktemp -d /tmp/noid-gsk-runtime.XXXXXXXX) || \
    fail "cannot create private runtime workspace"
cleanup() {
    rm -rf -- "$TEST_TMP"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

python3 -I - "$M13_REPO" "$M19_REPO" "$TEST_TMP" <<'EXTRACT_GSK_PYEOF' || \
    fail "cannot extract unique canonical renderer payloads"
import pathlib
import re
import sys

format_source, renderer_source, output_path = map(pathlib.Path, sys.argv[1:])
payloads = (
    (format_source, "FMT_EOF",
     "/usr/local/lib/noid-privacy/agent-install-format.sh",
     "agent-install-format.sh"),
    (renderer_source, "GSK_MATCH_EOF", "/usr/libexec/noid-gsk-hybrid-match",
     "noid-gsk-hybrid-match"),
    (renderer_source, "GSK_SESSION_HELPER_EOF",
     "/usr/libexec/noid-gsk-session-environment",
     "noid-gsk-session-environment"),
    (renderer_source, "GSK_SESSION_UNIT_EOF",
     "/usr/lib/systemd/user/noid-gsk-session-environment.service",
     "noid-gsk-session-environment.service"),
    (renderer_source, "GSK_TOGGLE_EOF", "/usr/local/bin/noid-toggle-gsk-gl",
     "noid-toggle-gsk-gl"),
)
for source_path, marker, target, name in payloads:
    source = source_path.read_text(encoding="utf-8")
    pattern = re.compile(
        rf"^cat > {re.escape(target)} <<'{re.escape(marker)}'\n"
        rf"(.*?)^{re.escape(marker)}$",
        re.MULTILINE | re.DOTALL,
    )
    matches = pattern.findall(source)
    assert len(matches) == 1, (marker, len(matches))
    (output_path / name).write_text(matches[0], encoding="utf-8")
EXTRACT_GSK_PYEOF

require_root_file() {
    local path=$1 mode=$2 canonical metadata
    [[ -f $path && ! -L $path && -s $path ]] || \
        fail "root payload is missing, empty, non-regular or symlinked: $path"
    canonical=$(readlink -e -- "$path") || \
        fail "cannot canonicalize root payload: $path"
    [[ $canonical == "$path" ]] || fail "root payload path is non-canonical: $path"
    metadata=$(stat -c '%u:%g:%a:%h' -- "$path") || \
        fail "cannot inspect root payload: $path"
    [[ $metadata == "0:0:$mode:1" ]] || \
        fail "root payload metadata differs: $path ($metadata)"
    matchpathcon -V "$path" >/dev/null || \
        fail "root payload SELinux label differs: $path"
}
require_equal() {
    cmp -s -- "$1" "$2" || fail "byte mismatch: $1 != $2"
}

unit_name=noid-gsk-session-environment.service
unit=/usr/lib/systemd/user/$unit_name
helper=/usr/libexec/noid-gsk-session-environment
activation_updater=/usr/bin/dbus-update-activation-environment
matcher=/usr/libexec/noid-gsk-hybrid-match
toggle=/usr/local/bin/noid-toggle-gsk-gl
format_library=/usr/local/lib/noid-privacy/agent-install-format.sh
enable=/etc/systemd/user/gnome-session.target.wants/$unit_name
system_override=/etc/environment.d/90-noid-gsk-renderer.conf
mode=/etc/xdg/noid-privacy/gsk-renderer.mode
legacy=/etc/systemd/user-environment-generators/55-noid-gsk-renderer

for specification in \
        "$format_library|644|$TEST_TMP/agent-install-format.sh" \
        "$matcher|755|$TEST_TMP/noid-gsk-hybrid-match" \
        "$helper|755|$TEST_TMP/noid-gsk-session-environment" \
        "$toggle|755|$TEST_TMP/noid-toggle-gsk-gl" \
        "$unit|644|$TEST_TMP/noid-gsk-session-environment.service"; do
    IFS='|' read -r installed installed_mode canonical <<< "$specification"
    require_root_file "$installed" "$installed_mode"
    require_equal "$canonical" "$installed"
done

[[ -x $activation_updater && ! -L $activation_updater \
   && $(readlink -e -- "$activation_updater") == "$activation_updater" \
   && $(rpm -qf --qf '%{NAME}' "$activation_updater" 2>/dev/null) == \
      dbus-tools ]] || \
    fail "GTK session activation updater is missing, unsafe or not owned by dbus-tools"
rpm -q dbus-tools >/dev/null 2>&1 || \
    fail "required GTK session activation package dbus-tools is absent"

[[ -L $enable ]] || \
    fail "global GNOME-session enablement is not a symlink"
[[ $(readlink -- "$enable") == "$unit" \
   && $(readlink -e -- "$enable") == "$unit" \
   && $(stat -c '%u:%g:%h' -- "$enable") == "0:0:1" ]] || \
    fail "global GNOME-session enablement is not exact"
matchpathcon -V "$enable" >/dev/null || \
    fail "global GNOME-session enablement SELinux label differs"
[[ ! -e /etc/systemd/user/$unit_name \
   && ! -L /etc/systemd/user/$unit_name \
   && ! -e /etc/systemd/user/$unit_name.d \
   && ! -L /etc/systemd/user/$unit_name.d ]] || \
    fail "administrator unit shadow or unit-specific drop-in changes the candidate"

vendor_dropin=/usr/lib/systemd/user/service.d/10-timeout-abort.conf
require_root_file "$vendor_dropin" 644
[[ $(rpm -qf --qf '%{NAME}|%{FILEDIGESTALGO}\n' "$vendor_dropin") == \
    "systemd|8" ]] || \
    fail "Fedora user-service timeout drop-in has no SHA-256 systemd owner"
vendor_dropin_digest=$(rpm -qf \
    --qf '[%{FILENAMES}|%{FILEDIGESTS}\n]' "$vendor_dropin" | \
    awk -F'|' -v path="$vendor_dropin" '
        $1 == path { digest=$2; count++ }
        END {
            if (count != 1 || digest !~ /^[0-9a-f]{64}$/) exit 1
            print digest
        }
    ') || fail "cannot resolve the timeout drop-in RPM digest"
[[ $(sha256sum -- "$vendor_dropin" | awk '{ print $1 }') == \
    "$vendor_dropin_digest" ]] || \
    fail "Fedora user-service timeout drop-in differs from its RPM payload"

unit_state=$(timeout --signal=TERM --kill-after=2s 8s \
    systemctl --user show "$unit_name" \
    -p LoadState -p FragmentPath -p DropInPaths -p UnitFileState \
    -p ActiveState -p SubState -p Result -p ExecMainStatus \
    -p Type -p RemainAfterExit -p RuntimeDirectory -p RuntimeDirectoryMode \
    -p UMask -p TimeoutStartUSec -p TimeoutStopUSec \
    -p PrivateNetwork -p NoNewPrivileges -p CapabilityBoundingSet \
    -p KeyringMode -p PrivateDevices -p PrivateTmp \
    -p ProtectClock -p ProtectHostname -p ProtectKernelLogs \
    -p ProtectProc -p ProcSubset -p ProtectSystem -p ProtectHome \
    -p ProtectKernelTunables -p ProtectKernelModules -p ProtectControlGroups \
    -p RestrictAddressFamilies -p RestrictNamespaces -p RestrictRealtime \
    -p RestrictSUIDSGID -p LockPersonality -p MemoryDenyWriteExecute \
    -p SystemCallArchitectures -p SystemCallErrorNumber) || \
    fail "could not inspect the effective GTK session unit"

declare -A unit_properties=()
while IFS='=' read -r property value; do
    [[ -n $property && -z ${unit_properties[$property]+x} ]] || \
        fail "effective unit properties are malformed or duplicated"
    unit_properties[$property]=$value
done <<< "$unit_state"
require_unit_property() {
    local property=$1 expected=$2
    [[ ${unit_properties[$property]+x} \
       && ${unit_properties[$property]} == "$expected" ]] || \
        fail "effective unit property differs: $property"
}
while IFS='|' read -r property expected; do
    require_unit_property "$property" "$expected"
done <<EOF
LoadState|loaded
FragmentPath|$unit
DropInPaths|$vendor_dropin
UnitFileState|enabled
ActiveState|active
SubState|exited
Result|success
ExecMainStatus|0
Type|oneshot
RemainAfterExit|yes
RuntimeDirectory|noid-gsk-session-environment
RuntimeDirectoryMode|0700
UMask|0077
TimeoutStartUSec|5s
TimeoutStopUSec|5s
PrivateNetwork|no
NoNewPrivileges|yes
CapabilityBoundingSet|
KeyringMode|private
PrivateDevices|yes
PrivateTmp|yes
ProtectClock|yes
ProtectHostname|yes
ProtectKernelLogs|yes
ProtectProc|invisible
ProcSubset|pid
ProtectSystem|strict
ProtectHome|read-only
ProtectKernelTunables|yes
ProtectKernelModules|yes
ProtectControlGroups|yes
RestrictAddressFamilies|AF_UNIX
RestrictNamespaces|yes
RestrictRealtime|yes
RestrictSUIDSGID|yes
LockPersonality|yes
MemoryDenyWriteExecute|yes
SystemCallArchitectures|native
SystemCallErrorNumber|1
EOF
[[ ${#unit_properties[@]} -eq 39 ]] || \
    fail "effective unit property set is incomplete or extended"

session_id=$(timeout --signal=TERM --kill-after=2s 8s \
    loginctl show-user "$USER_UID" -p Display --value 2>/dev/null) || \
    fail "could not identify logind's primary graphical session"
[[ $session_id =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || \
    fail "logind did not publish one valid primary graphical session"
session_state=$(timeout --signal=TERM --kill-after=2s 8s \
    loginctl show-session "$session_id" \
    -p User -p Class -p Type -p Remote -p Active -p State 2>/dev/null) || \
    fail "could not inspect logind's primary graphical session"
declare -A session_properties=()
while IFS='=' read -r property value; do
    [[ -n $property && -z ${session_properties[$property]+x} ]] || \
        fail "primary session properties are malformed or duplicated"
    session_properties[$property]=$value
done <<< "$session_state"
[[ ${#session_properties[@]} -eq 6 \
   && ${session_properties[User]:-} == "$USER_UID" \
   && ${session_properties[Class]:-} == user \
   && ${session_properties[Type]:-} =~ ^(wayland|x11)$ \
   && ${session_properties[Remote]:-} == no \
   && ${session_properties[Active]:-} == yes \
   && ${session_properties[State]:-} == active ]] || \
    fail "primary graphical session is not this active local normal-user login"

for override in "$system_override" "$mode" "$legacy"; do
    [[ ! -e $override && ! -L $override ]] || \
        fail "candidate default is changed by an override: $override"
done
status_output=$("$toggle" status) || fail "renderer status helper rejected default state"
mapfile -t status_lines <<< "$status_output"
[[ ${#status_lines[@]} -eq 5 ]] || \
    fail "renderer status output has unexpected fields"
require_status_line() {
    local expected=$1 count=0 line
    for line in "${status_lines[@]}"; do
        [[ $line != "$expected" ]] || count=$((count + 1))
    done
    [[ $count -eq 1 ]] || fail "renderer status field differs: $expected"
}
require_status_line system_override=absent
require_status_line mode=auto
require_status_line legacy_generator_override=absent

shell_pid=$(timeout --signal=TERM --kill-after=2s 8s \
    systemctl --user show org.gnome.Shell@user.service \
    -p MainPID --value 2>/dev/null) || fail "could not identify GNOME Shell"
[[ $shell_pid =~ ^[1-9][0-9]*$ && -r /proc/$shell_pid/environ \
   && -r /proc/$shell_pid/cmdline ]] || fail "GNOME Shell MainPID is not live"
mapfile -d '' -t shell_argv < "/proc/$shell_pid/cmdline"
[[ ${#shell_argv[@]} -ge 2 \
   && ${shell_argv[0]} == /usr/bin/gnome-shell \
   && ${shell_argv[1]} == --mode=user ]] || \
    fail "systemd MainPID is not the user GNOME Shell"
mapfile -t shell_renderer < <(
    tr '\0' '\n' < "/proc/$shell_pid/environ" | grep '^GSK_RENDERER=' || true
)
[[ ${#shell_renderer[@]} -eq 0 ]] || \
    fail "GNOME Shell inherited the application-only renderer override"

state_dir=$RUNTIME_ROOT/noid-gsk-session-environment
marker=$state_dir/applied
[[ -d $state_dir && ! -L $state_dir \
   && $(readlink -e -- "$state_dir") == "$state_dir" \
   && $(stat -c '%u:%g:%a' -- "$state_dir") == \
      "$USER_UID:$USER_GID:700" ]] || \
    fail "private session state directory is absent or unsafe"
manager_environment=$(timeout --signal=TERM --kill-after=2s 8s \
    systemctl --user show-environment) || \
    fail "could not inspect the user-manager activation environment"
mapfile -t manager_renderer < <(
    grep '^GSK_RENDERER=' <<< "$manager_environment" || true
)
if "$matcher"; then
    topology=portable-nvidia-offload
    require_status_line topology=portable-nvidia-offload
    require_status_line effective_future_apps=gl-session-apps-auto
    [[ ${#manager_renderer[@]} -eq 1 \
       && ${manager_renderer[0]} == GSK_RENDERER=gl ]] || \
        fail "user-manager GSK renderer drifted from the matched policy"
    [[ -f $marker && ! -L $marker \
       && $(readlink -e -- "$marker") == "$marker" \
       && $(stat -c '%u:%g:%a:%h' -- "$marker") == \
          "$USER_UID:$USER_GID:600:1" ]] || \
        fail "managed session renderer marker is absent or unsafe"
    grep -qxF gl-session-apps "$marker" || \
        fail "managed session renderer marker bytes are invalid"
else
    topology=vendor-default
    require_status_line topology=vendor-default
    require_status_line effective_future_apps=vendor-default
    [[ ${#manager_renderer[@]} -eq 0 ]] || \
        fail "unmatched candidate user manager contains a renderer override"
    [[ ! -e $marker && ! -L $marker ]] || \
        fail "unmatched topology has a managed renderer marker"
fi

probe_code=$'import errno, socket\nunix_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\nunix_socket.close()\ntry:\n    socket.socket(socket.AF_INET, socket.SOCK_STREAM)\nexcept OSError as exc:\n    raise SystemExit(0 if exc.errno == errno.EAFNOSUPPORT else 2)\nraise SystemExit(1)\n'
probe_unit=noid-gsk-af-probe-${PASS_ID//-/_}-${TEST_TMP##*.}.service
[[ $(timeout --signal=TERM --kill-after=2s 8s \
        systemctl --user show "$probe_unit" -p LoadState --value) == not-found ]] || \
    fail "private AF_UNIX probe unit name is already in use"
if ! timeout --signal=TERM --kill-after=2s 10s \
        systemd-run --user --wait --pipe --collect --quiet --unit="$probe_unit" \
        --property=PrivateNetwork=no \
        --property=RestrictAddressFamilies=AF_UNIX \
        --property=SystemCallArchitectures=native \
        /usr/bin/python3 -I -c "$probe_code" \
        >"$TEST_TMP/af-probe.log" 2>&1; then
    tail -n 100 "$TEST_TMP/af-probe.log" | sed 's/^/    /' >&2
    fail "AF_UNIX sandbox did not allow AF_UNIX and reject AF_INET"
fi
[[ $(timeout --signal=TERM --kill-after=2s 8s \
        systemctl --user show "$probe_unit" -p LoadState --value) == not-found ]] || \
    fail "private AF_UNIX probe unit was not collected"

echo "PASS  $TEST_NAME [$PASS_ID]: topology=$topology, source-bound post-Shell activation and AF_UNIX sandbox exact"

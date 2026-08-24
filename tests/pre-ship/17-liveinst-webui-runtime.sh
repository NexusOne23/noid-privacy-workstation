#!/usr/bin/env bash
# Candidate lifecycle gate for F-AUDIT-226.
# Disposable Live-VM sequence:
#   baseline -> launch installer -> active -> close normally -> closed
#   launch again -> active -> error-exit
set -euo pipefail

TEST_NAME=17-liveinst-webui-runtime
PASS_ID=${1:-}
PHASE=${2:-}
case "$PASS_ID:$PHASE" in
    live:baseline|live:active|live:closed|live:error-exit|\
    fresh-install:absent|reboot:absent) ;;
    *)
        echo "Usage: sudo bash $0 live {baseline|active|closed|error-exit}" >&2
        echo "       sudo bash $0 {fresh-install|reboot} absent" >&2
        exit 2
        ;;
esac

fail() { echo "FAIL  $TEST_NAME [$PASS_ID/$PHASE]: $*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || fail "must run as root"
grep -q '^ID=noid-privacy-workstation$' /etc/os-release 2>/dev/null || \
    fail "not running inside the NoID Privacy candidate"

path_unit=noid-liveinst-webui-lifecycle.path
helper_unit=noid-liveinst-webui-lifecycle.service
webui_unit=webui-cockpit-ws.service
pid_file=/run/anaconda/webui_script.pid
webui_script=/usr/libexec/anaconda/webui-desktop
liveinst_launcher=/usr/share/applications/anaconda.desktop
liveinst_updates=/boot/loader/noid-privacy/liveinst-updates.img
lifecycle_helper=/usr/local/libexec/noid-liveinst-webui-lifecycle
liveinst_umask_wrapper=/usr/local/bin/liveinst
lifecycle_path=/usr/lib/systemd/system/$path_unit
lifecycle_service=/usr/lib/systemd/system/$helper_unit
lifecycle_wants=/etc/systemd/system/multi-user.target.wants/$path_unit

for required_command in \
    awk cat desktop-file-validate grep gzip matchpathcon python3 readlink rpm \
    sha256sum sleep ss stat systemctl; do
    command -v "$required_command" >/dev/null 2>&1 || \
        fail "required command is unavailable: $required_command"
done

verify_noid_file() {
    local file=$1 expected_mode=$2
    [[ -f $file && ! -L $file ]] || fail "NoID Privacy lifecycle file missing or unsafe: $file"
    [[ $(stat -c '%U:%G:%a:%h' "$file") == "root:root:$expected_mode:1" ]] || \
        fail "NoID Privacy lifecycle file metadata differs: $file"
    matchpathcon -V "$file" >/dev/null 2>&1 || \
        fail "NoID Privacy lifecycle file SELinux context differs: $file"
}

verify_rpm_file() {
    local package=$1 file=$2 record_mode=$3 fs_mode=$4 record
    local dump_path expected_size expected_mtime expected_sha expected_mode
    local expected_owner expected_group dump_config dump_doc dump_rdev dump_linkto extra
    [[ -f $file && ! -L $file ]] || fail "RPM payload missing or unsafe: $file"
    [[ $(rpm -qf --qf '%{NAME}\n' "$file" 2>/dev/null) == "$package" ]] || \
        fail "RPM owner differs for $file"
    record=$(rpm -q --dump "$package" 2>/dev/null | \
        awk -v path="$file" '$1 == path {print; found=1} END {exit !found}') || \
        fail "no exact RPM dump record for $file"
    read -r dump_path expected_size expected_mtime expected_sha expected_mode \
        expected_owner expected_group dump_config dump_doc dump_rdev dump_linkto extra \
        <<<"$record"
    [[ $dump_path == "$file" && $expected_mode == "$record_mode" \
       && ${dump_config:-}:${dump_doc:-}:${dump_rdev:-}:${dump_linkto:-} == 0:0:0:X \
       && -z ${extra:-} ]] || \
        fail "RPM record shape differs for $file"
    [[ $(stat -c '%s:%Y:%U:%G:%a' "$file") == \
       "$expected_size:$expected_mtime:$expected_owner:$expected_group:$fs_mode" ]] || \
        fail "RPM metadata differs for $file"
    [[ $(sha256sum "$file" | awk '{print $1}') == "$expected_sha" ]] || \
        fail "RPM digest differs for $file"
}

listener_rows() {
    ss -H -ltnp 'sport = :80' 2>/dev/null || true
}

assert_anaconda_public_umask() {
    local proc_dir arg saw_anaconda saw_liveinst backend_count=0
    for proc_dir in /proc/[0-9]*; do
        [[ -r $proc_dir/cmdline && -r $proc_dir/status ]] || continue
        saw_anaconda=0
        saw_liveinst=0
        while IFS= read -r -d '' arg; do
            case "$arg" in
                anaconda|*/anaconda) saw_anaconda=1 ;;
                --liveinst) saw_liveinst=1 ;;
            esac
        done < "$proc_dir/cmdline"
        [[ $saw_anaconda -eq 1 && $saw_liveinst -eq 1 ]] || continue
        [[ $(stat -c '%u' "$proc_dir") == 0 ]] || \
            fail "Live Anaconda backend is not root-owned: ${proc_dir##*/}"
        grep -qE '^Umask:[[:space:]]+0022$' "$proc_dir/status" || \
            fail "Live Anaconda backend did not inherit public umask 0022"
        backend_count=$((backend_count + 1))
    done
    [[ $backend_count -gt 0 ]] || \
        fail "no active Live Anaconda backend was available for umask verification"
}

assert_webui_listener() {
    local rows control_group row remaining pid proc_cgroup
    local row_pid_count listener_count=0
    rows=$(listener_rows)
    [[ -n $rows ]] || fail "WebUI has no loopback TCP/80 listener"
    control_group=$(systemctl show "$webui_unit" -p ControlGroup --value)
    [[ $control_group == /* && $control_group != *..* && $control_group != *//* ]] || \
        fail "WebUI service control-group path is not canonical: $control_group"

    while IFS= read -r row; do
        [[ -n $row ]] || continue
        [[ $row == *"127.0.0.1:80"* ]] || \
            fail "WebUI listener is not IPv4 loopback-only: $row"
        [[ ! $row =~ (^|[[:space:]])(0\.0\.0\.0|\[::\]|\*):80 ]] || \
            fail "WebUI listener is remotely exposed: $row"
        remaining=$row
        row_pid_count=0
        while [[ $remaining =~ pid=([1-9][0-9]*) ]]; do
            pid=${BASH_REMATCH[1]}
            proc_cgroup=$(awk -F: \
                '$1 == "0" && $2 == "" {print $3; found++}
                 END {exit found != 1}' "/proc/$pid/cgroup" 2>/dev/null) || \
                fail "cannot bind TCP/80 listener PID $pid to one unified cgroup"
            [[ $proc_cgroup == "$control_group" \
               || $proc_cgroup == "$control_group"/* ]] || \
                fail "TCP/80 listener PID $pid is outside $webui_unit"
            ((row_pid_count += 1))
            remaining=${remaining#*"pid=$pid"}
        done
        ((row_pid_count > 0)) || fail "TCP/80 listener has no attributable process: $row"
        ((listener_count += 1))
    done <<<"$rows"
    ((listener_count > 0)) || fail "WebUI listener inventory is empty"
}

assert_no_webui() {
    local rows
    [[ $(systemctl show "$webui_unit" -p ActiveState --value) == inactive ]] || \
        fail "$webui_unit is not inactive"
    [[ $(systemctl show "$webui_unit" -p SubState --value) == dead ]] || \
        fail "$webui_unit is not dead"
    [[ $(systemctl show "$webui_unit" -p MainPID --value) == 0 ]] || \
        fail "$webui_unit still has a MainPID"
    rows=$(listener_rows)
    [[ -z $rows ]] || fail "TCP/80 listener remains: $rows"
}

read_exact_webui_pid() {
    [[ -f $pid_file && ! -L $pid_file ]] || fail "WebUI PID file missing or unsafe"
    local payload pid_owner pid_group pid_mode pid_links pid_parent pid_parent_mode
    local uid_record
    pid_parent=${pid_file%/*}
    [[ -d $pid_parent && ! -L $pid_parent ]] || \
        fail "WebUI PID-file parent is missing or unsafe"
    read -r pid_owner pid_group pid_parent_mode < <(
        stat -c '%U %G %a' "$pid_parent"
    )
    [[ $pid_owner:$pid_group == root:root \
       && $pid_parent_mode =~ ^[0-7]{3,4}$ ]] || \
        fail "WebUI PID-file parent metadata differs"
    (( (8#$pid_parent_mode & 8#022) == 0 )) || \
        fail "WebUI PID-file parent is group/other-writable"
    read -r pid_owner pid_group pid_mode pid_links < <(
        stat -c '%U %G %a %h' "$pid_file"
    )
    [[ $pid_owner:$pid_group:$pid_links == root:root:1 ]] || \
        fail "WebUI PID-file identity metadata differs"
    [[ $pid_mode =~ ^[0-7]{3,4}$ ]] || fail "WebUI PID-file mode is not octal"
    # Fedora creates this file through shell redirection and retains its inode
    # across launches.  A graphical first launch yields 0644; a first launch
    # from the hardened umask-0027 interactive shell yields 0640.  Match the runtime
    # helper's security boundary: caller-specific read bits may differ, but no
    # group/other write bit is accepted.
    (( (8#$pid_mode & 8#022) == 0 )) || \
        fail "WebUI PID file is group/other-writable"
    payload=$(cat "$pid_file")
    [[ $payload =~ ^[1-9][0-9]*$ ]] || fail "WebUI PID is not canonical"
    [[ -r /proc/$payload/cmdline ]] || fail "WebUI PID is not live"
    uid_record=$(awk \
        '$1 == "Uid:" {print $2, $3, $4, $5; found++}
         END {exit found != 1}' "/proc/$payload/status" 2>/dev/null) || \
        fail "WebUI PID has no unique readable UID record"
    [[ $uid_record == "0 0 0 0" ]] || fail "WebUI PID is not entirely root-owned"
    mapfile -d '' -t webui_argv < "/proc/$payload/cmdline"
    [[ ${#webui_argv[@]} -eq 4 \
       && (${webui_argv[0]} == /usr/bin/bash || ${webui_argv[0]} == /bin/bash) \
       && ${webui_argv[1]} == "$webui_script" \
       && ${webui_argv[2]} == -t \
       && ${webui_argv[3]} == live ]] || fail "WebUI argv differs"
    WEBUI_PID=$payload
}

terminate_exact_webui_pid() {
    if ! python3 - "$WEBUI_PID" "$webui_script" <<'NOID_LIVEINST_PIDFD_SIGNAL_EOF'
import os
import select
import signal
import sys


def reject(message: str) -> None:
    raise SystemExit(f"pidfd signal validation failed: {message}")


try:
    pid = int(sys.argv[1])
except (IndexError, ValueError):
    reject("PID argument is not one decimal integer")
if pid <= 1:
    reject("PID is outside the allowed process range")
try:
    expected_script = os.fsencode(sys.argv[2])
except IndexError:
    reject("WebUI script argument is missing")

try:
    pidfd = os.pidfd_open(pid, 0)
except OSError as exc:
    reject(f"cannot open PID descriptor: {exc}")
try:
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    if poller.poll(0):
        reject("WebUI process exited before identity validation")
    try:
        status = open(f"/proc/{pid}/status", "rb").read().splitlines()
        arguments = open(f"/proc/{pid}/cmdline", "rb").read().rstrip(b"\0").split(b"\0")
    except OSError as exc:
        reject(f"cannot inspect WebUI process: {exc}")
    uid_records = [line for line in status if line.startswith(b"Uid:")]
    if len(uid_records) != 1:
        reject("WebUI process has no unique UID record")
    try:
        uid_fields = [int(field) for field in uid_records[0].split()[1:]]
    except ValueError:
        reject("WebUI UID record is malformed")
    if uid_fields != [0, 0, 0, 0]:
        reject("WebUI process is not entirely root-owned")
    if len(arguments) != 4:
        reject("WebUI process argument count differs")
    if arguments[0] not in (b"/usr/bin/bash", b"/bin/bash"):
        reject("WebUI process interpreter differs")
    if arguments[1:] != [expected_script, b"-t", b"live"]:
        reject("WebUI process command line differs")
    if poller.poll(0):
        reject("WebUI process exited during identity validation")
    try:
        signal.pidfd_send_signal(pidfd, signal.SIGTERM)
    except OSError as exc:
        reject(f"cannot signal WebUI process descriptor: {exc}")
finally:
    os.close(pidfd)
NOID_LIVEINST_PIDFD_SIGNAL_EOF
    then
        fail "could not terminate the exact pidfd-bound WebUI process"
    fi
}

verify_noid_file "$lifecycle_helper" 755
verify_noid_file "$lifecycle_path" 644
verify_noid_file "$lifecycle_service" 644
[[ -L $lifecycle_wants \
   && $(readlink "$lifecycle_wants") == "$lifecycle_path" ]] || \
    fail "lifecycle path enablement link differs"
[[ $(systemctl show "$path_unit" -p FragmentPath --value) == "$lifecycle_path" ]] || \
    fail "loaded lifecycle path fragment differs"
[[ $(systemctl show "$helper_unit" -p FragmentPath --value) == "$lifecycle_service" ]] || \
    fail "loaded lifecycle service fragment differs"
grep -qxF 'PathChanged=/run/anaconda/webui_script.pid' \
    "$lifecycle_path" || fail "path contract differs"
grep -qxF 'ConditionKernelCommandLine=rd.live.image' \
    "$lifecycle_path" || fail "path Live condition differs"
grep -qxF 'ConditionKernelCommandLine=rd.live.image' \
    "$lifecycle_service" || fail "helper Live condition differs"
grep -qxF 'ExecStart=/usr/local/libexec/noid-liveinst-webui-lifecycle' \
    "$lifecycle_service" || fail "helper executable contract differs"
grep -qxF 'ProtectSystem=strict' "$lifecycle_service" || \
    fail "helper filesystem protection differs"
grep -qxF 'RestrictAddressFamilies=AF_UNIX' "$lifecycle_service" || \
    fail "helper address-family restriction differs"
grep -qxF 'CapabilityBoundingSet=' "$lifecycle_service" || \
    fail "helper capability boundary differs"

if [[ $PASS_ID == live ]]; then
    grep -qw 'rd.live.image' /proc/cmdline || fail "Live pass lacks rd.live.image"
    verify_rpm_file anaconda-live /usr/bin/liveinst 0100755 755
    verify_rpm_file anaconda-webui /usr/libexec/anaconda/webui-desktop 0100755 755
    verify_rpm_file anaconda-webui \
        /usr/libexec/anaconda/cockpit-coproc-wrapper.sh 0100755 755
    verify_rpm_file anaconda-webui \
        /usr/lib/systemd/system/webui-cockpit-ws.service 0100644 644
    verify_noid_file "$liveinst_umask_wrapper" 755
    liveinst_resolved=$(command -v liveinst 2>/dev/null || true)
    [[ -n $liveinst_resolved \
       && $liveinst_resolved -ef $liveinst_umask_wrapper ]] || \
        fail "Live launcher does not resolve through the public-umask wrapper"
    cmp -s "$liveinst_umask_wrapper" <(printf '%s\n' \
        '#!/usr/bin/bash' \
        'umask 022' \
        'exec /usr/bin/liveinst "$@"') || \
        fail "Live-installer public-umask wrapper bytes differ"
    [[ -f $liveinst_updates && ! -L $liveinst_updates ]] || \
        fail "Live-installer updates image is missing or unsafe"
    [[ $(stat -c '%U:%G:%a:%h' "$liveinst_updates") == root:root:644:1 ]] || \
        fail "Live-installer updates image metadata differs"
    matchpathcon -V "$liveinst_updates" >/dev/null 2>&1 || \
        fail "Live-installer updates image SELinux context differs"
    gzip -t "$liveinst_updates" || fail "Live-installer updates image is invalid"
    [[ -f $liveinst_launcher && ! -L $liveinst_launcher ]] || \
        fail "ephemeral installer launcher is missing or unsafe"
    [[ $(stat -c '%U:%G:%a:%h' "$liveinst_launcher") == root:root:644:1 ]] || \
        fail "ephemeral installer launcher metadata differs"
    [[ $(grep -c '^Exec=' "$liveinst_launcher" || true) -eq 1 ]] || \
        fail "ephemeral installer launcher has a non-closed Exec schema"
    [[ $(grep -Fxc "Exec=liveinst --updates=file://$liveinst_updates" \
        "$liveinst_launcher" || true) -eq 1 ]] || \
        fail "ephemeral installer launcher does not use the reviewed updates image"
    desktop-file-validate "$liveinst_launcher" || \
        fail "ephemeral installer launcher does not validate"
    systemctl --quiet is-active "$path_unit" || fail "lifecycle path unit is not active"
    [[ $(systemctl show "$path_unit" -p Result --value) == success ]] || \
        fail "lifecycle path unit result differs"
    case "$PHASE" in
        baseline)
            assert_no_webui
            [[ $(systemctl show "$helper_unit" -p ActiveState --value) == inactive ]] || \
                fail "helper unexpectedly active before installer launch"
            ;;
        active)
            read_exact_webui_pid
            assert_anaconda_public_umask
            [[ $(systemctl show "$webui_unit" -p ActiveState --value) == active ]] || \
                fail "WebUI service is not active while installer is open"
            [[ $(systemctl show "$webui_unit" -p MainPID --value) =~ ^[1-9][0-9]*$ ]] || \
                fail "WebUI service has no live MainPID"
            [[ $(systemctl show "$helper_unit" -p ActiveState --value) == activating ]] || \
                fail "pidfd companion is not waiting in activating state"
            helper_pid=$(systemctl show "$helper_unit" -p MainPID --value)
            [[ $helper_pid =~ ^[1-9][0-9]*$ && -r /proc/$helper_pid/cmdline ]] || \
                fail "pidfd companion MainPID is not live"
            assert_webui_listener
            ;;
        closed)
            for _ in {1..100}; do
                [[ $(systemctl show "$helper_unit" -p ActiveState --value) == inactive ]] \
                    && break
                sleep 0.1
            done
            [[ $(systemctl show "$helper_unit" -p ActiveState --value) == inactive ]] || \
                fail "helper did not finish after normal browser close"
            [[ $(systemctl show "$helper_unit" -p Result --value) == success ]] || \
                fail "helper result is not success after normal close"
            assert_no_webui
            ;;
        error-exit)
            read_exact_webui_pid
            terminate_exact_webui_pid
            for _ in {1..100}; do
                [[ $(systemctl show "$helper_unit" -p ActiveState --value) == inactive ]] \
                    && break
                sleep 0.1
            done
            [[ $(systemctl show "$helper_unit" -p Result --value) == success ]] || \
                fail "helper result is not success after WebUI error exit"
            assert_no_webui
            ;;
    esac
else
    ! grep -qw 'rd.live.image' /proc/cmdline || fail "installed pass is still Live"
    for package in anaconda-live anaconda-webui; do
        ! rpm -q "$package" >/dev/null 2>&1 || \
            fail "installer-only package remains installed: $package"
    done
    for payload in \
        /usr/local/bin/liveinst \
        /usr/bin/liveinst \
        /usr/libexec/anaconda/webui-desktop \
        /usr/libexec/anaconda/cockpit-coproc-wrapper.sh \
        /usr/lib/systemd/system/webui-cockpit-ws.service; do
        [[ ! -e $payload && ! -L $payload ]] || \
            fail "installer-only RPM payload remains: $payload"
    done
    [[ $(systemctl show "$webui_unit" -p LoadState --value) == not-found ]] || \
        fail "$webui_unit still has a loadable unit"
    [[ $(systemctl show "$path_unit" -p ActiveState --value) == inactive ]] || \
        fail "Live-only path unit active on installed root"
    [[ $(systemctl show "$path_unit" -p ConditionResult --value) == no ]] || \
        fail "path Live condition did not reject installed root"
    [[ $(systemctl show "$helper_unit" -p ActiveState --value) == inactive ]] || \
        fail "Live-only helper active on installed root"
    assert_no_webui
fi

echo "PASS  $TEST_NAME [$PASS_ID/$PHASE]: exact WebUI lifecycle and RPM-pristine boundary verified"

#!/usr/bin/env bash
# Candidate gate for F287/F288. Start it from serial/SSH before bringing the
# local GDM greeter to the foreground; it waits up to 30 seconds and captures
# the active greeter before a Live timed auto-login can retire that session.
set -euo pipefail
export LC_ALL=C

TEST_NAME=17-greeter-identity-runtime
PASS_ID=${1:-}
case "$PASS_ID" in
    live|fresh-install|reboot) ;;
    *) echo "Usage: sudo bash $0 {live|fresh-install|reboot}" >&2; exit 2 ;;
esac

fail() { echo "FAIL  $TEST_NAME [$PASS_ID]: $*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || fail "run as root from serial/SSH while GDM is foreground"
grep -q '^ID=noid-privacy-workstation$' /etc/os-release 2>/dev/null || \
    fail "not running inside the NoID Privacy candidate"
for command_name in awk env getent grep id loginctl matchpathcon ps setpriv \
        sleep stat systemctl tr; do
    command -v "$command_name" >/dev/null 2>&1 || \
        fail "required command missing: $command_name"
done

property_once() {
    local key=$1 properties=$2
    awk -v wanted="$key" '
        index($0, wanted "=") == 1 {
            count++
            value=substr($0, length(wanted) + 2)
        }
        END {
            if (count != 1) exit 1
            print value
        }
    ' <<<"$properties"
}

session_is_active_greeter() {
    local session=$1 properties class active state
    properties=$(loginctl show-session "$session" \
        -p Class -p Active -p State 2>/dev/null) || return 1
    class=$(property_once Class "$properties") || return 1
    active=$(property_once Active "$properties") || return 1
    state=$(property_once State "$properties") || return 1
    [[ $class == greeter && $active == yes && $state == active ]]
}

declare -a greeter_sessions=()
declare -a greeter_snapshots=()

capture_active_greeter_snapshots() {
    local -a session_ids=()
    local session properties class active state

    for _ in {1..600}; do
        mapfile -t session_ids < <(
            loginctl list-sessions --no-legend --no-pager 2>/dev/null | \
                awk '{ print $1 }'
        )
        for session in "${session_ids[@]}"; do
            [[ $session =~ ^[A-Za-z0-9_.-]+$ ]] || \
                fail "unsafe logind session ID"
            properties=$(loginctl show-session "$session" \
                -p User -p Name -p Class -p Type -p Remote -p Active -p State \
                2>/dev/null) || continue
            class=$(property_once Class "$properties") || continue
            [[ $class == greeter ]] || continue
            active=$(property_once Active "$properties") || \
                fail "greeter $session has ambiguous Active"
            state=$(property_once State "$properties") || \
                fail "greeter $session has ambiguous State"
            [[ $active == yes && $state == active ]] || continue
            greeter_sessions+=("$session")
            greeter_snapshots+=("$properties")
        done
        (( ${#greeter_sessions[@]} > 0 )) && return 0
        sleep 0.05
    done
    return 1
}

manager_retired_cleanly() {
    local uid=$1 properties active result
    for _ in {1..40}; do
        properties=$(systemctl show "user@${uid}.service" \
            -p ActiveState -p Result 2>/dev/null) || return 1
        active=$(property_once ActiveState "$properties") || return 1
        result=$(property_once Result "$properties") || return 1
        [[ $active == inactive && $result == success ]] && return 0
        [[ $active == failed || $result != success ]] && return 1
        sleep 0.05
    done
    return 1
}

capture_active_greeter_snapshots || \
    fail "no active Class=greeter session observed within 30 seconds"

gate=/usr/libexec/noid-eligible-user
[[ -f $gate && ! -L $gate && -x $gate \
   && $(stat -c '%U:%G:%a:%h' "$gate") == root:root:755:1 ]] || \
    fail "persistent-user/logind gate metadata invalid"
matchpathcon -V "$gate" >/dev/null 2>&1 || \
    fail "persistent-user/logind gate SELinux label invalid"

greeter_count=${#greeter_sessions[@]}
retired_manager_count=0
for index in "${!greeter_sessions[@]}"; do
    session=${greeter_sessions[$index]}
    properties=${greeter_snapshots[$index]}
    class=$(property_once Class "$properties") || fail "session $session has ambiguous Class"
    [[ $class == greeter ]] || fail "captured session $session is not a greeter"

    uid=$(property_once User "$properties") || fail "greeter $session has ambiguous User"
    name=$(property_once Name "$properties") || fail "greeter $session has ambiguous Name"
    type=$(property_once Type "$properties") || fail "greeter $session has ambiguous Type"
    remote=$(property_once Remote "$properties") || fail "greeter $session has ambiguous Remote"
    active=$(property_once Active "$properties") || fail "greeter $session has ambiguous Active"
    state=$(property_once State "$properties") || fail "greeter $session has ambiguous State"
    [[ $uid =~ ^[0-9]+$ && $name =~ ^[A-Za-z0-9_.-]+$ ]] || \
        fail "greeter identity is not safely representable"
    case "$type" in wayland|x11) ;; *) fail "greeter $session is not graphical" ;; esac
    [[ $remote == no && $active == yes && $state == active ]] || \
        fail "greeter $session is not the active local foreground session"

    if "$gate" account-uid "$uid"; then
        fail "root account-uid gate accepted greeter $name/$uid"
    fi
    passwd_record=$(getent passwd "$uid") || fail "greeter $name/$uid has no NSS record"
    [[ -n $passwd_record && $passwd_record != *$'\n'* \
       && $(awk -F: '{ print NF }' <<<"$passwd_record") == 7 ]] || \
        fail "greeter $name/$uid NSS record is ambiguous"
    IFS=: read -r passwd_name _ passwd_uid gid _ home _ <<<"$passwd_record"
    [[ $passwd_name == "$name" && $passwd_uid == "$uid" && $gid =~ ^[0-9]+$ ]] || \
        fail "greeter logind and NSS identities disagree"
    if setpriv --reuid="$uid" --regid="$gid" --clear-groups "$gate" account; then
        fail "current-identity account gate accepted greeter $name/$uid"
    fi
    if setpriv --reuid="$uid" --regid="$gid" --clear-groups "$gate" graphical; then
        fail "graphical gate accepted Class=greeter identity $name/$uid"
    fi

    for unit in usbguard-notifier.service noid-agent-policy-adapters.service; do
        if unit_properties=$(setpriv --reuid="$uid" --regid="$gid" --clear-groups \
                env HOME="$home" XDG_RUNTIME_DIR="/run/user/$uid" \
                DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" \
                systemctl --user show "$unit" \
                    -p LoadState -p ActiveState -p Result 2>/dev/null); then
            load_state=$(property_once LoadState "$unit_properties") || \
                fail "$unit exposed an ambiguous greeter LoadState"
            active_state=$(property_once ActiveState "$unit_properties") || \
                fail "$unit exposed an ambiguous greeter ActiveState"
            result=$(property_once Result "$unit_properties") || \
                fail "$unit exposed an ambiguous greeter Result"
        else
            # The Live ISO intentionally performs a timed auto-login one second
            # after logout. The greeter may therefore retire between the
            # logind snapshot above and this bus query. Accept only a completed,
            # successful manager retirement; a bus failure while the greeter
            # remains foreground is still a hard failure.
            if session_is_active_greeter "$session"; then
                fail "could not query active greeter user manager for $unit"
            fi
            manager_retired_cleanly "$uid" || \
                fail "greeter user manager vanished without clean retirement"
            retired_manager_count=$((retired_manager_count + 1))
            break
        fi
        [[ $load_state == loaded && $active_state == inactive ]] || \
            fail "$unit was not an inactive greeter unit ($load_state/$active_state/$result)"
        case "$result" in
            success|exec-condition) ;;
            *) fail "$unit did not expose a clean greeter skip result ($result)" ;;
        esac
    done

    if ps -e -o euid=,args= | awk -v uid="$uid" \
            '$1 == uid && $2 == "/usr/bin/usbguard-notifier" { found=1 } END { exit !found }'; then
        fail "usbguard-notifier process is running as greeter $name/$uid"
    fi
    adapter_state=$home/.local/state/noid-privacy/agent-policy-adapters.done
    [[ ! -e $adapter_state && ! -L $adapter_state ]] || \
        fail "adapter state was written into greeter home: $adapter_state"
    ipc_file=/etc/usbguard/IPCAccessControl.d/$name
    [[ ! -e $ipc_file && ! -L $ipc_file ]] || \
        fail "per-greeter USBGuard IPC grant exists: $ipc_file"
    # Fedora's USBGuard package does not guarantee that a legacy supplementary
    # group exists.  NoID Privacy no longer creates it and named IPC ACL files
    # are the sole authorization source.  If another package or an upgraded
    # system retains the group, the greeter still must never be a member.
    if getent group usbguard >/dev/null 2>&1 && \
       id -nG "$name" 2>/dev/null | tr ' ' '\n' | grep -qx usbguard; then
        fail "greeter $name is a supplementary usbguard member"
    fi
done

echo "PASS  $TEST_NAME [$PASS_ID]: $greeter_count active greeter identity/identities observed; clean unit skip or manager retirement, with no notifier or state/IPC write (retired=$retired_manager_count)"

#!/usr/bin/env bash
# End an explicitly opened GNOME Software session and release its idle DNF5
# backend. This is deliberately an explicit desktop action, never a timer.
set -euo pipefail
umask 077

PATH=/usr/local/bin:/usr/bin
export PATH

if [[ $# -ne 0 ]]; then
    echo "Usage: noid-gnome-software-quit" >&2
    exit 2
fi
if [[ $EUID -eq 0 ]]; then
    echo "noid-gnome-software-quit: run as the desktop user, not root" >&2
    exit 1
fi
if [[ -z ${DBUS_SESSION_BUS_ADDRESS:-} ]]; then
    echo "noid-gnome-software-quit: session D-Bus address is unavailable" >&2
    exit 1
fi

owner_state() {
    local result
    result=$(/usr/bin/gdbus call --session \
        --dest org.freedesktop.DBus \
        --object-path /org/freedesktop/DBus \
        --method org.freedesktop.DBus.NameHasOwner \
        org.gnome.Software 2>/dev/null) || {
        echo "noid-gnome-software-quit: cannot query the session bus" >&2
        return 1
    }
    case "$result" in
        '(true,)') printf '%s\n' owned ;;
        '(false,)') printf '%s\n' unowned ;;
        *)
            echo "noid-gnome-software-quit: unexpected session-bus reply" >&2
            return 1
            ;;
    esac
}

state=$(owner_state) || exit 1
if [[ $state == owned ]]; then
    # GNOME Software's supported --quit path shuts down its job manager before
    # releasing the application. Never replace this with a signal or timeout
    # that could interrupt a package transaction.
    if ! /usr/bin/gnome-software --quit; then
        state=$(owner_state) || exit 1
        if [[ $state == owned ]]; then
            echo "noid-gnome-software-quit: graceful application shutdown failed" >&2
            exit 1
        fi
    fi
fi

# A remote --quit request may return before the application has released its
# well-known name. Bound only this observation loop; never kill the process.
deadline=$((SECONDS + 90))
while :; do
    state=$(owner_state) || exit 1
    [[ $state == owned ]] || break
    if (( SECONDS >= deadline )); then
        echo "noid-gnome-software-quit: application still owns its D-Bus name" >&2
        exit 1
    fi
    /usr/bin/sleep 0.25
done

# The root helper independently verifies that the system DNF daemon is idle.
# -n makes this action fail closed instead of ever opening an auth dialog.
/usr/bin/sudo -n /usr/local/sbin/noid-gnome-software-backend-stop

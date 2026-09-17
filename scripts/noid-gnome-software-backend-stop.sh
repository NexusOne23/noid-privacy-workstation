#!/usr/bin/env bash
# Stop Fedora's D-Bus-activatable DNF5 daemon only when it has no sessions.
# The next deliberate package operation can activate it again natively.
set -euo pipefail
umask 077

PATH=/usr/bin
export PATH
LC_ALL=C
export LC_ALL

if [[ $# -ne 0 ]]; then
    echo "Usage: noid-gnome-software-backend-stop" >&2
    exit 2
fi
if [[ $EUID -ne 0 ]]; then
    echo "noid-gnome-software-backend-stop: root privileges required" >&2
    exit 1
fi

unit=dnf5daemon-server.service
bus_name=org.rpm.dnf.v0

if ! /usr/bin/systemctl --quiet is-active "$unit"; then
    state=$(/usr/bin/systemctl show "$unit" --property=ActiveState --value \
        2>/dev/null || true)
    [[ $state == inactive ]] || {
        echo "noid-gnome-software-backend-stop: unsafe service state: ${state:-unknown}" >&2
        exit 1
    }
    exit 0
fi

# dnf5daemon-server has no upstream idle timeout. Its root object exists even
# without clients; every live Session adds descendants below this closed tree.
# GNOME Software can release its own bus name just before its DNF plugin drops
# the last Session object, so observe that graceful teardown for a bounded
# interval. Never stop through a live package-manager session.
expected_tree=$'/\n/org\n/org/rpm\n/org/rpm/dnf\n/org/rpm/dnf/v0'
deadline=$((SECONDS + 90))
while :; do
    if ! actual_tree=$(/usr/bin/busctl --system tree "$bus_name" \
            --list --no-pager 2>/dev/null); then
        # A concurrent native shutdown is safe; every other query failure is
        # fail-closed rather than evidence that no DNF Session exists.
        if ! /usr/bin/systemctl --quiet is-active "$unit" \
           && [[ $(/usr/bin/systemctl show "$unit" --property=ActiveState \
                --value 2>/dev/null || true) == inactive ]]; then
            exit 0
        fi
        echo "noid-gnome-software-backend-stop: cannot inspect DNF5 sessions" >&2
        exit 1
    fi
    [[ $actual_tree != "$expected_tree" ]] || break
    if (( SECONDS >= deadline )); then
        echo "noid-gnome-software-backend-stop: DNF5 still has an active session" >&2
        exit 1
    fi
    /usr/bin/sleep 0.25
done

/usr/bin/systemctl stop "$unit"
state=$(/usr/bin/systemctl show "$unit" --property=ActiveState --value \
    2>/dev/null || true)
[[ $state == inactive ]] || {
    echo "noid-gnome-software-backend-stop: service did not become inactive" >&2
    exit 1
}

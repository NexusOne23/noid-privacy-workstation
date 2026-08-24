#!/usr/bin/env bash
# Open one explicit GNOME Software session with the native RPM catalog added.
# The ordinary launcher remains Flatpak-only; this helper writes no state.
set -euo pipefail
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

if [[ $# -ne 0 ]]; then
    echo "Usage: noid-gnome-software-rpm" >&2
    exit 2
fi
if [[ $EUID -eq 0 ]]; then
    echo "noid-gnome-software-rpm: run as the desktop user, not root" >&2
    exit 1
fi

SOFTWARE=/usr/local/bin/gnome-software
RPM_PLUGINS=flatpak,appstream,dnf5,icons,hardcoded-blocklist,malcontent,modalias,os-release,provenance,provenance-license,generic-updates

notify_failure() {
    local english=$1 german=$2 title body
    case ${LANGUAGE:-${LC_MESSAGES:-${LANG:-}}} in
        de*|*:de*)
            title='Fedora-RPM-Ansicht konnte nicht geöffnet werden'
            body=$german
            ;;
        *)
            title='Could not open the Fedora RPM view'
            body=$english
            ;;
    esac
    echo "noid-gnome-software-rpm: $english" >&2
    if [[ -x /usr/bin/notify-send && -n ${DBUS_SESSION_BUS_ADDRESS:-} ]]; then
        /usr/bin/notify-send --app-name='NoID Privacy' \
            --icon=org.gnome.Software "$title" "$body" >/dev/null 2>&1 || true
    fi
}

if [[ -z ${DBUS_SESSION_BUS_ADDRESS:-} ]]; then
    notify_failure \
        'session D-Bus address is unavailable' \
        'Die Sitzungs-D-Bus-Adresse ist nicht verfügbar.'
    exit 1
fi
if [[ ! -f $SOFTWARE || -L $SOFTWARE || ! -x $SOFTWARE ]]; then
    notify_failure \
        'the trusted GNOME Software launcher is unavailable' \
        'Der vertrauenswürdige GNOME-Software-Starter ist nicht verfügbar.'
    exit 1
fi

# Do not silently override an administrator-owned plugin policy. The regular
# wrapper deliberately gives either variable precedence, including an empty
# value; this named one-shot follows the same ownership boundary.
if [[ ${GNOME_SOFTWARE_PLUGINS_ALLOWLIST+x} == x \
      || ${GNOME_SOFTWARE_PLUGINS_BLOCKLIST+x} == x ]]; then
    notify_failure \
        'an administrator/session plugin policy is already set' \
        'Eine Administrator-/Sitzungsrichtlinie für Plugins ist bereits gesetzt.'
    exit 1
fi

owner_reply=$(LC_ALL=C /usr/bin/gdbus call --session \
    --dest org.freedesktop.DBus \
    --object-path /org/freedesktop/DBus \
    --method org.freedesktop.DBus.NameHasOwner org.gnome.Software \
    2>/dev/null) || {
        notify_failure \
            'cannot query the GNOME Software session state' \
            'Der Sitzungsstatus von GNOME Software kann nicht geprüft werden.'
        exit 1
    }
case $owner_reply in
    '(false,)') ;;
    '(true,)')
        notify_failure \
            'GNOME Software is already running; choose Quit completely first' \
            'GNOME Software läuft bereits. Wählen Sie zuerst „Vollständig beenden“.'
        exit 1
        ;;
    *)
        notify_failure \
            'the session bus returned an unexpected ownership reply' \
            'Der Sitzungsbus hat eine unerwartete Statusantwort geliefert.'
        exit 1
        ;;
esac

export GNOME_SOFTWARE_PLUGINS_ALLOWLIST=$RPM_PLUGINS
exec "$SOFTWARE"

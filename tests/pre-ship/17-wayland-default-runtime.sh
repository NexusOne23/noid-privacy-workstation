#!/usr/bin/env bash
# Candidate-only GTK/Qt strict-default and explicit-recovery behavior gate.
set -euo pipefail
export LC_ALL=C
export PATH=/usr/sbin:/usr/bin
ulimit -c 0

TEST_NAME=17-wayland-default-runtime
PASS_ID=${1:-}
case "$PASS_ID" in
    live) ;;
    fresh-install) ;;
    reboot) ;;
    *)
        echo "Usage: bash $0 {live|fresh-install|reboot}" >&2
        exit 2
        ;;
esac
fail() { echo "FAIL  $TEST_NAME [$PASS_ID]: $*" >&2; exit 1; }

[[ $EUID -ne 0 ]] || fail "run as the normal GNOME user, not root"
for required_command in \
    awk gdbus grep gsettings keepassxc matchpathcon mktemp python3 readlink rm \
    rpm sleep stat systemctl; do
    command -v "$required_command" >/dev/null 2>&1 || \
        fail "required command missing: $required_command"
done

grep -q '^ID=noid-privacy-workstation$' /etc/os-release 2>/dev/null || \
    fail "not running inside the NoID Privacy candidate"
[[ ${XDG_CURRENT_DESKTOP:-} == *GNOME* ]] || fail "active desktop is not GNOME"
[[ -n ${DBUS_SESSION_BUS_ADDRESS:-} ]] || fail "session D-Bus address is missing"

policy=/etc/environment.d/45-noid-wayland.conf
qt_wayland_plugin=/usr/lib64/qt5/plugins/platforms/libqwayland-generic.so
keepassxc_binary=/usr/bin/keepassxc
[[ -f $policy && ! -L $policy \
   && $(stat -c '%U:%G:%a:%h' "$policy") == root:root:644:1 ]] || \
    fail "Wayland environment policy metadata invalid"
[[ -f $qt_wayland_plugin && ! -L $qt_wayland_plugin \
   && $(stat -c '%U:%G:%a:%h' "$qt_wayland_plugin") == root:root:755:1 ]] || \
    fail "Qt5 Wayland platform plugin metadata invalid"
[[ -x $keepassxc_binary && ! -L $keepassxc_binary \
   && $(stat -c '%U:%G:%a:%h' "$keepassxc_binary") == root:root:755:1 ]] || \
    fail "KeePassXC executable metadata invalid"
for root_file in "$policy" "$qt_wayland_plugin" "$keepassxc_binary"; do
    matchpathcon -V "$root_file" >/dev/null 2>&1 || \
        fail "SELinux context invalid: $root_file"
done
mapfile -t policy_assignments < <(
    awk '
        /^[[:space:]]*($|#)/ { next }
        { print }
    ' "$policy"
)
[[ ${#policy_assignments[@]} -eq 2 \
   && ${policy_assignments[0]} == GDK_BACKEND=wayland \
   && ${policy_assignments[1]} == QT_QPA_PLATFORM=wayland ]] || \
    fail "Wayland environment policy assignments differ"

[[ $(rpm -qf --qf '%{NAME}' "$qt_wayland_plugin" 2>/dev/null) == qt5-qtwayland ]] || \
    fail "Qt5 Wayland platform plugin missing or owned by the wrong package"
[[ $(rpm -qf --qf '%{NAME}' "$keepassxc_binary" 2>/dev/null) == keepassxc ]] || \
    fail "KeePassXC executable is owned by the wrong package"
fedora_key=dbfcf71c6d9f90a6
for package in qt5-qtwayland keepassxc python3-gobject gtk4; do
    package_record=$(rpm -q --qf \
        '%{NAME}|%{EPOCHNUM}|%{RELEASE}|%{VENDOR}|%{RSAHEADER:pgpsig}\n' \
        "$package" 2>/dev/null) || fail "required package missing: $package"
    [[ $package_record != *$'\n'* ]] || \
        fail "multiple installed package records found: $package"
    IFS='|' read -r package_name package_epoch package_release \
        package_vendor package_signature <<<"$package_record"
    [[ $package_name == "$package" \
       && $package_epoch == 0 \
       && $package_release == *.fc44 \
       && $package_vendor == "Fedora Project" \
       && ${package_signature,,} == *"key id $fedora_key"* ]] || \
        fail "package provenance differs from Fedora 44: $package"
done
rpm_verify=$(rpm -V qt5-qtwayland keepassxc python3-gobject gtk4 2>&1) || \
    fail "Wayland probe package verification reported drift"
[[ -z $rpm_verify ]] || fail "Wayland probe package payload differs from its RPM record"

manager_environment=$(systemctl --user show-environment) || \
    fail "cannot read user-manager environment"
manager_value() {
    local key=$1
    awk -F= -v wanted="$key" '
        $1 == wanted {
            count++
            value=substr($0, length(wanted) + 2)
        }
        END {
            if (count != 1) exit 1
            print value
        }
    ' <<<"$manager_environment"
}
for environment_name in \
    GDK_BACKEND QT_QPA_PLATFORM XDG_CURRENT_DESKTOP XDG_RUNTIME_DIR \
    WAYLAND_DISPLAY DISPLAY XAUTHORITY DBUS_SESSION_BUS_ADDRESS; do
    manager_setting=$(manager_value "$environment_name") || \
        fail "user manager lacks one unambiguous $environment_name"
    [[ ${!environment_name:-} == "$manager_setting" ]] || \
        fail "caller and user-manager $environment_name differ"
done
[[ $GDK_BACKEND == wayland ]] || fail "session GTK default is not wayland"
[[ $QT_QPA_PLATFORM == wayland ]] || fail "session Qt default is not wayland"
[[ $XDG_CURRENT_DESKTOP == *GNOME* ]] || fail "manager desktop is not GNOME"
[[ $XDG_RUNTIME_DIR == "/run/user/$UID" \
   && -d $XDG_RUNTIME_DIR && ! -L $XDG_RUNTIME_DIR \
   && $(readlink -e "$XDG_RUNTIME_DIR") == "$XDG_RUNTIME_DIR" \
   && $(stat -c '%u:%a' "$XDG_RUNTIME_DIR") == "$UID:700" ]] || \
    fail "session runtime directory is not the private logind root"
[[ $DBUS_SESSION_BUS_ADDRESS == "unix:path=$XDG_RUNTIME_DIR/bus" ]] || \
    fail "session D-Bus address is outside the private runtime root"
session_bus=$XDG_RUNTIME_DIR/bus
[[ -S $session_bus && ! -L $session_bus \
   && $(stat -c '%u:%h' "$session_bus") == "$UID:1" ]] || \
    fail "session D-Bus socket is missing or unsafe"
[[ $WAYLAND_DISPLAY =~ ^[A-Za-z0-9_.-]+$ ]] || \
    fail "Wayland display name is malformed"
wayland_socket=$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY
[[ -S $wayland_socket && ! -L $wayland_socket \
   && $(stat -c '%u:%h' "$wayland_socket") == "$UID:1" ]] || \
    fail "Wayland display socket is missing or unsafe"
[[ $DISPLAY =~ ^:[0-9]+(\.[0-9]+)?$ ]] || fail "X11 display name is malformed"
[[ $XAUTHORITY == "$XDG_RUNTIME_DIR"/* \
   && -f $XAUTHORITY && ! -L $XAUTHORITY \
   && $(readlink -e "$XAUTHORITY") == "$XAUTHORITY" \
   && $(stat -c '%u:%a:%h' "$XAUTHORITY") == "$UID:600:1" ]] || \
    fail "Xwayland authority file is missing or unsafe"

[[ $(gsettings get org.gnome.mutter experimental-features) == '@as []' ]] || \
    fail "Mutter experimental-features is not the reviewed empty set"

gtk_probe='import gi
gi.require_version("Gdk", "4.0")
gi.require_version("Gtk", "4.0")
from gi.repository import Gdk, Gtk
Gtk.init()
display = Gdk.Display.get_default()
assert display is not None
print(display.__gtype__.name)'

gtk_native=$(/usr/bin/python3 -c "$gtk_probe") || fail "GTK native-default probe failed"
[[ $gtk_native == GdkWaylandDisplay ]] || \
    fail "GTK default opened $gtk_native instead of GdkWaylandDisplay"
gtk_x11=$(GDK_BACKEND=x11 /usr/bin/python3 -c "$gtk_probe") || \
    fail "documented GTK X11 recovery failed"
[[ $gtk_x11 == GdkX11Display ]] || \
    fail "GTK recovery opened $gtk_x11 instead of GdkX11Display"
sleep 2
[[ $(gdbus call --session --dest org.freedesktop.DBus \
        --object-path /org/freedesktop/DBus \
        --method org.freedesktop.DBus.NameHasOwner org.gnome.Shell) == \
        '(true,)' ]] || fail "GNOME Shell disappeared after the X11 client exited"
gtk_x11_again=$(GDK_BACKEND=x11 /usr/bin/python3 -c "$gtk_probe") || \
    fail "second documented GTK X11 recovery failed after client teardown"
[[ $gtk_x11_again == GdkX11Display ]] || \
    fail "second GTK recovery opened $gtk_x11_again instead of GdkX11Display"
[[ $(gdbus call --session --dest org.freedesktop.DBus \
        --object-path /org/freedesktop/DBus \
        --method org.freedesktop.DBus.NameHasOwner org.gnome.Shell) == \
        '(true,)' ]] || fail "GNOME Shell disappeared after the second X11 client exited"
gtk_after_x11=$(/usr/bin/python3 -c "$gtk_probe") || \
    fail "GTK Wayland probe failed after both X11 client lifecycles"
[[ $gtk_after_x11 == GdkWaylandDisplay ]] || \
    fail "Wayland session did not survive both X11 client lifecycles"
[[ $(gsettings get org.gnome.mutter experimental-features) == '@as []' ]] || \
    fail "Mutter experimental-features changed during the X11 client lifecycle"
if GDK_BACKEND=wayland WAYLAND_DISPLAY=noid-audit-missing \
        /usr/bin/python3 -c "$gtk_probe" >/dev/null 2>&1; then
    fail "strict GTK default silently fell back without a Wayland compositor"
fi

tmp=$(mktemp -d "$XDG_RUNTIME_DIR/noid-wayland-runtime.XXXXXX")
trap 'rm -rf -- "$tmp"' EXIT HUP INT TERM
QT_FORCE_STDERR_LOGGING=1 WAYLAND_DEBUG=client \
    "$keepassxc_binary" --config "$tmp/keepassxc.ini" --debug-info \
    >"$tmp/qt-wayland.out" 2>"$tmp/qt-wayland.err" || \
    fail "shipped KeePassXC cannot start with the strict Qt Wayland default"
grep -Eq '^Qt 5\.[0-9.]+$' "$tmp/qt-wayland.out" || \
    fail "KeePassXC is no longer the reviewed Qt5 client"
grep -Eq -- ' -> wl_display#[0-9]+[.]get_registry' "$tmp/qt-wayland.err" || \
    fail "KeePassXC did not establish a native Wayland protocol connection"
# Qt accepts a semicolon-separated QPA selector as an explicit fallback list.
# The exact single `wayland` value above, the user-manager byte check and this
# real wl_display handshake therefore prove the intended no-fallback default.
# Do not point a Qt GUI at a deliberately missing socket: Qt aborts when no QPA
# plugin can initialize, creating an ANOM_ABEND record in the immutable audit
# trail even with core files disabled. That is test-generated crash noise, not
# additional evidence about the already-closed selector.

QT_QPA_PLATFORM=xcb "$keepassxc_binary" \
    --config "$tmp/keepassxc-xcb.ini" --debug-info \
    >"$tmp/qt-xcb-env.out" 2>"$tmp/qt-xcb-env.err" || \
    fail "documented Qt xcb environment recovery failed"
grep -Eq '^Qt 5\.[0-9.]+$' "$tmp/qt-xcb-env.out" || \
    fail "Qt xcb environment probe malformed"
QT_QPA_PLATFORM=wayland "$keepassxc_binary" -platform xcb \
    --config "$tmp/keepassxc-xcb-arg.ini" --debug-info \
    >"$tmp/qt-xcb-arg.out" 2>"$tmp/qt-xcb-arg.err" || \
    fail "Qt -platform xcb did not override the Wayland environment default"
grep -Eq '^Qt 5\.[0-9.]+$' "$tmp/qt-xcb-arg.out" || \
    fail "Qt xcb argument probe malformed"

echo "PASS  $TEST_NAME [$PASS_ID]: GTK and shipped Qt5 KeePassXC use native Wayland by default; two successive explicit x11 clients and xcb recovery work, the empty Mutter feature set persists and GNOME survives both X11 client lifecycles"

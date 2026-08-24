#!/bin/bash
# M17 GNOME hardening smoke test: dconf profile + db writes
set -euo pipefail
. "$(dirname "$0")/lib.sh"

smoke_start "M17-gnome"

PROJECT_ROOT="$(project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/17-gnome-hardening.ks"
M08_KS_FILE="$PROJECT_ROOT/kickstart/snippets/08-service-minimization.ks"
M14_KS_FILE="$PROJECT_ROOT/kickstart/snippets/14-usbguard.ks"

TMP_POST=$(mktemp --tmpdir smoke-m17-post-XXXXXX.sh)
smoke_register_temp_file "$TMP_POST"

extract_post "$KS_FILE" "$TMP_POST"

# The sandbox deliberately has no network and this smoke test targets the
# GNOME/dconf filesystem behavior, not the separately SHA-pinned extension
# transaction. Replace only the extracted copy's closed download/publication
# block with the exact path of the fixture created below.
sed -i '/^JP_VERSION="36"$/,/^unset -f jp_cleanup$/c\
JP_VERSION="36"\
JP_UUID="just-perfection-desktop@just-perfection"\
JP_EXT_DIR="/usr/share/gnome-shell/extensions/${JP_UUID}"' \
    "$TMP_POST"

# Minimal already-installed extension fixture for the later production
# postcondition; download/hash behavior is covered structurally, not here.
JP_FIXTURE="$SANDBOX_DIR/usr/share/gnome-shell/extensions/just-perfection-desktop@just-perfection"
mkdir -p "$JP_FIXTURE/schemas"
printf '%s\n' '{"version": 36}' > "$JP_FIXTURE/metadata.json"
: > "$JP_FIXTURE/schemas/gschemas.compiled"

# M17 runs after M08 in master.ks and now fail-closes unless the two reviewed
# late-skel Agent privacy templates exist with exact Root metadata. This smoke
# executes M17 in isolation, so reproduce only that load-bearing M08 output
# from its canonical heredocs; do not invent fixture bytes.
extract_m08_template() {
    local marker=$1 target=$2
    mkdir -p "$(dirname "$target")"
    awk -v m="$marker" '
        $0 ~ "<<[[:space:]]*[\047\"]?" m "[\047\"]?([[:space:]]|$)" { in_hd=1; next }
        in_hd && $0 == m { exit }
        in_hd { print }
    ' "$M08_KS_FILE" > "$target"
    [ -s "$target" ]
    chown root:root "$target"
    chmod 0644 "$target"
}
extract_m08_template CODIUM_SETTINGS_EOF \
    "$SANDBOX_DIR/etc/skel/.config/VSCodium/User/settings.json"
extract_m08_template CLAUDE_SETTINGS_EOF \
    "$SANDBOX_DIR/etc/skel/.claude/settings.json"

# M17 runs after M14 and verifies the exact safe static-notifier integration.
# The prepared rootfs supplies Fedora's signed vendor unit; reproduce only
# M14's load-bearing distro link after proving both the vendor target and the
# canonical M14 source contract. A hand-authored replacement unit would hide
# package/source drift and is therefore forbidden here.
NOTIFIER_TARGET=/usr/lib/systemd/user/usbguard-notifier.service
NOTIFIER_WANTS=/usr/lib/systemd/user/graphical-session.target.wants/usbguard-notifier.service
if [ "$(stat -c '%U:%G:%a' "$SANDBOX_DIR$NOTIFIER_TARGET" 2>/dev/null || true)" != \
        root:root:644 ]; then
    _fail "prepared rootfs lacks the exact Fedora usbguard-notifier vendor unit"
    exit 1
fi
if ! grep -qF 'ln -sfn /usr/lib/systemd/user/usbguard-notifier.service' \
        "$M14_KS_FILE" \
   || ! grep -qF '/usr/lib/systemd/user/graphical-session.target.wants/usbguard-notifier.service' \
        "$M14_KS_FILE"; then
    _fail "canonical M14 static-notifier link contract differs"
    exit 1
fi
install -d -m 0755 -o root -g root \
    "$SANDBOX_DIR/usr/lib/systemd/user/graphical-session.target.wants"
ln -sfn "$NOTIFIER_TARGET" "$SANDBOX_DIR$NOTIFIER_WANTS"

# Bubblewrap's user namespace cannot relabel a newly created security.selinux
# xattr even when the sandbox process is UID 0. Seed only the empty inode that
# M17 will overwrite, and label it from the prepared Fedora rootfs policy with
# setfiles' native alternate-root mode. The production %post must still write
# and validate the complete drop-in; this fixture supplies only the kernel
# capability that the namespace intentionally withholds.
GIS_STOP_DIR=/etc/systemd/user/gnome-session-manager@gnome-initial-setup.service.d
GIS_STOP_CONF=$GIS_STOP_DIR/50-noid-clean-stop.conf
install -d -m 0755 -o root -g root "$SANDBOX_DIR$GIS_STOP_DIR"
install -m 0644 -o root -g root /dev/null "$SANDBOX_DIR$GIS_STOP_CONF"
setfiles -F -r "$SANDBOX_DIR" \
    "$SANDBOX_DIR/etc/selinux/targeted/contexts/files/file_contexts" \
    "$SANDBOX_DIR$GIS_STOP_CONF"

# `dconf update` and offline `systemctl mask` both operate entirely inside the
# disposable rootfs. Running them is part of the smoke value; the former stub
# made the module's own compiled-database verification fail by construction.
# M17's native user-unit parser also needs only the read-only cgroup controller
# inventory; the shared harness deliberately withholds the rest of host sysfs.
export SMOKE_BIND_CGROUP=1

if run_in_sandbox "$TMP_POST"; then
    _pass "M17 %post executed without error"
else
    _fail "M17 %post returned non-zero"
fi

# Keep this load-bearing instance-only override independently observable. If
# the full %post stops here, the smoke output must distinguish metadata/label
# drift from later Live-installer publication failures that are only fallout.
assert_in_sandbox \
    '[ "$(stat -Lc "%U:%G:%a" /etc/systemd/user/gnome-session-manager@gnome-initial-setup.service.d)" = root:root:755 ] && matchpathcon -V /etc/systemd/user/gnome-session-manager@gnome-initial-setup.service.d && [ "$(stat -Lc "%U:%G:%a:%h" /etc/systemd/user/gnome-session-manager@gnome-initial-setup.service.d/50-noid-clean-stop.conf)" = root:root:644:1 ] && matchpathcon -V /etc/systemd/user/gnome-session-manager@gnome-initial-setup.service.d/50-noid-clean-stop.conf' \
    "GNOME Initial Setup instance-only clean-stop metadata and labels"

# Target files exist
assert_in_sandbox '[ -f /etc/dconf/profile/user ]' \
    "/etc/dconf/profile/user"
assert_in_sandbox '[ -f /etc/dconf/db/distro.d/10-noid-gnome-privacy ]' \
    "dconf db/distro.d/10-noid-gnome-privacy"
assert_in_sandbox '[ -f /etc/dconf/db/distro.d/locks/10-noid-gnome-privacy ]' \
    "dconf locks/10-noid-gnome-privacy"
assert_in_sandbox \
    '[ -f /boot/loader/noid-privacy/liveinst-updates.img ] && [ ! -L /boot/loader/noid-privacy/liveinst-updates.img ] && gzip -t /boot/loader/noid-privacy/liveinst-updates.img' \
    "validated Live-installer updates image"
assert_in_sandbox \
    '[ "$(grep -Fxc "Exec=liveinst" /usr/share/applications/liveinst.desktop)" -eq 1 ] && ! grep -q "^Exec=.*--updates=" /usr/share/applications/liveinst.desktop' \
    "RPM-owned Live-installer launcher remains pristine at compose time"
assert_in_sandbox \
    '[ "$(stat -c "%U:%G:%a:%h" /usr/local/bin/liveinst)" = root:root:755:1 ] && [ "$(wc -l < /usr/local/bin/liveinst)" -eq 3 ] && [ "$(grep -Fxc "#!/usr/bin/bash" /usr/local/bin/liveinst)" -eq 1 ] && [ "$(grep -Fxc "umask 022" /usr/local/bin/liveinst)" -eq 1 ] && [ "$(grep -Fxc '\''exec /usr/bin/liveinst "$@"'\'' /usr/local/bin/liveinst)" -eq 1 ] && [ "$(PATH=/usr/local/bin:/usr/bin command -v liveinst)" = /usr/local/bin/liveinst ]' \
    "Live-only public-umask wrapper is exact and wins the Live PATH"
assert_in_sandbox \
    'grep -qF "noid_liveinst_updates=/boot/loader/noid-privacy/liveinst-updates.img" /var/lib/livesys/livesys-session-extra && grep -qF "mv -fT -- \"\$noid_liveinst_tmp\" \"\$noid_liveinst_desktop\"" /var/lib/livesys/livesys-session-extra' \
    "ephemeral Live hook owns atomic launcher wiring"

# GOA + Identity use an immediate static mask with /bin/false fallback.
assert_in_sandbox '[ -f /usr/local/share/dbus-1/services/org.gnome.OnlineAccounts.service ]' \
    "GOA dbus override"
assert_in_sandbox '[ -f /usr/local/share/dbus-1/services/org.gnome.Identity.service ]' \
    "Identity dbus override"
assert_in_sandbox 'grep -q "Exec=/bin/false" /usr/local/share/dbus-1/services/org.gnome.OnlineAccounts.service' \
    "GOA override executes /bin/false"
assert_in_sandbox 'grep -qxF "SystemdService=noid-blocked-session-service.service" /usr/local/share/dbus-1/services/org.gnome.OnlineAccounts.service' \
    "GOA override routes to the common static mask"
assert_in_sandbox '[ -L /etc/systemd/user/noid-blocked-session-service.service ] && [ "$(readlink /etc/systemd/user/noid-blocked-session-service.service)" = /dev/null ]' \
    "common D-Bus denial unit is masked"
assert_in_sandbox '[ -f /etc/dbus-1/session.d/20-noid-blocked-services.conf ]' \
    "reference-bus send-deny policy"
assert_in_sandbox 'grep -qxF "    <deny send_destination=\"org.gnome.OnlineAccounts\"/>" /etc/dbus-1/session.d/20-noid-blocked-services.conf' \
    "GOA reference-bus denial"
for tracker_name in \
    org.freedesktop.Tracker3.Miner.Files \
    org.freedesktop.Tracker3.Miner.Files.Control \
    org.freedesktop.Tracker3.Writeback \
    org.freedesktop.portal.Tracker; do
    assert_in_sandbox "[ ! -e /usr/local/share/dbus-1/services/$tracker_name.service ] && [ ! -L /usr/local/share/dbus-1/services/$tracker_name.service ]" \
        "no delayed admin override for $tracker_name"
done

# Privacy-relevant dconf keys in the db (content check)
# GNOME telemetry channels are `report-technical-problems` + `send-software-usage-stats`
# (both under /org/gnome/desktop/privacy — M17 writes them both false).
assert_in_sandbox 'grep -q "^send-software-usage-stats=false" /etc/dconf/db/distro.d/10-noid-gnome-privacy' \
    "software usage stats disabled"
assert_in_sandbox 'grep -q "^report-technical-problems=false" /etc/dconf/db/distro.d/10-noid-gnome-privacy' \
    "technical problem reporting disabled"
assert_in_sandbox '[ "$(grep -Fxc "show-hidden=true" /etc/dconf/db/distro.d/10-noid-gnome-privacy)" -eq 2 ] && ! grep -q "^show-hidden-files=" /etc/dconf/db/distro.d/10-noid-gnome-privacy' \
    "active GTK3 and GTK4 hidden-file defaults replace the ignored Nautilus key"
assert_in_sandbox 'grep -q "^default-sort-order='\''name'\''" /etc/dconf/db/distro.d/10-noid-gnome-privacy' \
    "Nautilus name sort default"
assert_in_sandbox 'grep -q "^default-sort-in-reverse-order=false" /etc/dconf/db/distro.d/10-noid-gnome-privacy' \
    "Nautilus ascending sort default"
assert_in_sandbox '[ "$(DCONF_PROFILE=user dconf read -d /org/gtk/settings/file-chooser/show-hidden)" = true ] && [ "$(DCONF_PROFILE=user dconf read -d /org/gtk/gtk4/settings/file-chooser/show-hidden)" = true ]' \
    "compiled dconf database exposes both Nautilus hidden-file defaults"
assert_in_sandbox '[ "$(DCONF_PROFILE=user dconf read -d /org/gnome/nautilus/preferences/default-sort-order)" = "'\''name'\''" ] && [ "$(DCONF_PROFILE=user dconf read -d /org/gnome/nautilus/preferences/default-sort-in-reverse-order)" = false ]' \
    "compiled dconf database exposes generic-folder Name A-Z defaults"

smoke_finish

# ============================================================================
# Module 17 — GNOME Privacy + Security Hardening
# Status: LOCKED 2026-08-11 (v111) — scope the Liveinst umask rationale to verified launch paths.
#
# Covers:
#   - dconf privacy profile /etc/dconf/db/distro.d/10-noid-gnome-privacy
#     (17 sections; per-key rationale inline in DCONF_PRIVACY_EOF) + locks
#     file /etc/dconf/db/distro.d/locks/10-noid-gnome-privacy with 8
#     security-critical locks (DCONF_LOCKS_EOF)
#   - separate /etc/dconf/db/distro.d/12-noid-agent-workflow-power defaults:
#     no early idle dim and no idle auto-suspend on AC/battery; screen
#     blank/lock and low-battery power saver remain independent, and no power
#     key is locked so each user can restore GNOME's suspend policy
#   - noid-toggle-lid-action: general laptop/convertible lid-close control via
#     systemd-logind's maintained drop-in interface. It detects the kernel
#     SW_LID capability (never DMI/battery guesses), reports effective battery,
#     external-power and docked states, refuses desktops, and transactionally
#     applies or resets an explicit user choice without owning the lower
#     Fedora/NVIDIA policy
#   - dconf override + lock 15-noid-events-hide: enables the 2 curated
#     extensions (Just-Perfection events-hide + AppIndicator tray compat)
#     and locks ONLY events-button; precedence 15 > 10 overrides the
#     enabled-extensions=@as [] baseline
#   - Just-Perfection v36 build-time install (SHA256-pinned download from
#     extensions.gnome.org, closed archive validation, atomic tree/cache
#     publication and strict schema compile); AppIndicator ships as Fedora RPM
#     via M26
#   - D-Bus admin service overrides for GOA and Identity route unsolicited
#     activation to one statically masked user unit, with Exec=/bin/false as
#     the non-systemd-bus fallback. GNOME Software and Tracker3 keep Fedora's
#     native SystemdService descriptors and their own masked units, avoiding
#     duplicate-name diagnostics and the activation delay caused by
#     false-process overrides. A mandatory session-bus send policy closes the
#     GOA/Identity/Tracker fallback activation path; RPM-owned /usr/share
#     payloads remain byte-pristine. /etc/goa.conf uses a fail-closed provider
#     allowlist as the independent provider-layer block.
#   - GNOME Software's RPM launcher is mirrored into the standard
#     /usr/local/share/applications admin tier with DBusActivatable=false plus
#     freedesktop desktop actions for the named one-shot Fedora-RPM view and
#     GNOME Software's own graceful --quit path plus a session-aware release
#     of its idle DNF5 backend. The privileged
#     stop helper refuses every non-idle DNF object tree; its sudoers command
#     accepts no arguments. Explicit app-grid launch therefore follows the
#     Fedora Exec path, while an unsolicited bus request follows Fedora's
#     native service descriptor to the globally masked gnome-software.service.
#     A package-scoped DNF5 action regenerates the admin launcher after
#     gnome-software updates.
#   - user-unit masks declared by MASK_UNITS via /etc/systemd/user -> /dev/null,
#     including both GNOME USB-protection activation paths
#   - Step 3b: noid-user-firstrun user service (GNOME region sync, one-time
#     native Nautilus Downloads A-Z metadata unless the user already owns a
#     sort choice, native qemu:///session max_core compatibility without
#     overwriting conflicting user settings, exact preset/start/postcondition for the update timer and
#     exact root-owned static-link/start postcondition for the USB notifier;
#     independent atomic task state and retry-on-failure)
#   - Step 3c: required WirePlumber microphone-policy component + persistent
#     dynamic setting + transactional noid-toggle-microphone CLI. Current and
#     future capture sources stay muted while the privacy default is active;
#     GNOME dconf remains an independent application-permission layer.
#   - Step 3d: GDM greeter location-off dconf db (greeter gnome-shell can
#     D-Bus-activate geoclue at permission lookup)
#   - systemd environment-generators 99-noid-xdg-cleanup (system + user):
#     strip trailing slashes from XDG_DATA_DIRS after the flatpak
#     generators
#   - noid-gnome-shell-privacy-cleanup.service (user, GNOME shutdown target):
#     after GNOME producers stop, wipes gnome-shell application_state +
#     session-active-history.json and ~/.cache/thumbnails through an openat2
#     symlink/mount boundary; a host-scoped gnome-shell DNF action verifies
#     that both upstream payload names still exist after every package update;
#     Mozilla owns its live/stale profile locks
#   - evidence-bounded, application-overridable JIT-disable defaults
#     (JavaScriptCoreUseJIT=0 + GJS_DISABLE_JIT=1)
#     + strict native-Wayland GTK/Qt defaults (GDK_BACKEND + QT_QPA_PLATFORM)
#     via /etc/environment.d; these are application-overridable compatibility
#     defaults, not a session security boundary
#   - native XDG admin MIME defaults for text/plain and application/x-zerosize;
#     both resolve to Fedora's org.gnome.TextEditor desktop entry instead of
#     falling through a missing legacy gedit entry to the much heavier VSCodium
#   - gnome-initial-setup vendor.conf (skip 4 pages) + gnome-tour reinstall
#     guard + 3 further autostart Hidden=true overrides
#   - Step 7c: Live-mode livesys-session-extra hook (fills GNOME-flavor
#     livesys gaps: liveuser unlock + parser-verified passwordless sudo
#     commands/validation + GDM automatic/timed login, seeds rootless
#     Podman VFS storage because the Live home itself is overlay-backed, and
#     carries the reviewed VSCodium/Claude privacy templates into the account
#     that livesys created before M08 populated /etc/skel; Live-ISO-only,
#     M41 noid-anaconda-cleanup reverts on install) +
#     pidfd-bound systemd path companion stops Fedora's root Cockpit WebUI
#     service when the exact Live-installer browser process exits, while M17
#     leaves the RPM-owned Anaconda executable/module bytes pristine; the
#     ephemeral post-livesys launcher passes a deterministic Live-only updates
#     image that teaches the exact Anaconda 44.30 payload to consume Lorax's
#     strict compose-time required-space manifest, with Fedora's original
#     full-tree scan retained as the invalid/missing-manifest fallback +
#     livesys_session=gnome + graphical.target default
#
# Deliberate deviations (do NOT re-litigate):
#   - GNOME's USB-protection service + target are masked: runtime evidence
#     proves the plugin can inject `allow id *:*` even with the Dconf value
#     false. USBGuard is the sole authority; the notifier surfaces blocks.
#   - evolution source-registry + calendar-factory + addressbook-factory
#     are UNMASKED (masked state caused per-boot D-Bus cascade failures
#     from the shell calendar widget); alarm-notify + user-prompter stay
#     masked. at-spi is NEVER masked (accessibility).
#   - gnome-software's user unit is masked by M08 to remove background
#     activation. Fedora's RPM-owned D-Bus descriptor routes unsolicited
#     activation directly to that mask; no duplicate admin service descriptor
#     is installed. The distinct higher-priority desktop entry sets
#     DBusActivatable=false, so an explicit app-grid/CLI launch executes the
#     Fedora command directly and can then acquire its bus name. Its service
#     name is deliberately absent from the mandatory send-deny policy.
#   - location is user-toggleable (camera/microphone model — NOT locked;
#     geoclue unmasked in M08; default stays enabled=false).
#   - the extensions master switch is locked ON
#     (`disable-user-extensions=false`) so GNOME's crash-recovery cannot
#     permanently disable the curated extensions;
#     allow-extension-installation locked false.
#   - mic + cam dconf keys are NOT locked (Welcome toggles persist).
#   - The XDG env-generators are cosmetic-only vs dbus-broker duplicate-
#     name spam (upstream double-scan of /usr/share — bus1/dbus-broker
#     #339); retained as architecturally correct cleanup.
#   - gnome-tour is excluded by M26. Its autostart override remains only as
#     defense in depth if a later package transaction reinstalls the weak dep.
#
# Constraint notes (keep when editing):
#   - Session D-Bus admin overrides live in /usr/local/share/dbus-1/services,
#     which precedes /usr/share in the standard XDG service search. Only GOA
#     and Identity require that fallback tier. GNOME Software and Tracker keep
#     Fedora's native SystemdService routes so their masks fail immediately
#     without duplicate-name diagnostics. Never rewrite the RPM-owned vendor
#     descriptors. Fedora's GOA/Identity descriptors have only Exec routes;
#     live verification showed that the mandatory send policy alone starts
#     both processes before returning AccessDenied, so their two admin
#     descriptors and resulting lower-priority duplicate diagnostics remain a
#     deliberate fail-closed trade-off.
#   - Fedora-stock Mutter is deliberate. GNOME closed MR !5023 after solving
#     the cursor-cache defect differently in commit a4a851d4, which is already
#     part of the official 50.3 tag. Do not restore the redundant local RPM.
#   - M17 owns the general lid-action CLI and its higher-priority explicit
#     user-choice file. M19 owns only its lower NVIDIA compatibility default;
#     driver install/rollback must never create, rewrite or remove the explicit
#     user choice.
#   - Verify counters are gated: expected_sections=17 +
#     expected_locks=8 must move in the SAME commit as any dconf change.
#   - uint32 prefixes in dconf keys are type-required (silently ignored
#     without them); no inline comments on sysctl-style value lines.
#   - Step 7.10/7.10b version greps are pipefail-safe (`|| true` +
#     fallback) — a bare grep no-match otherwise kills the %post.
#   - tests/17 asserts code strings (paths, heredoc markers, liveuser
#     lines) + whole-file negative on an at-spi mask line.
#
# Cross-references:
#   - M08: shared dconf profile + distro.d; geoclue conf.d override is the
#     effective location egress block. M10: lifecycle-only logind drop-in,
#     with no competing graphical idle/power timer.
#     M13: AIDE rules cover the new paths; welcome toggles drive the same
#     gsettings keys. M14: USBGuard layering (media-handling + autorun).
#     M16: app-level Firefox hardening, orthogonal. M25: extension
#     runtime-update path. M26: AppIndicator RPM.
# ============================================================================

%packages --exclude-weakdeps
# Load-bearing for the validated admin launcher generation and update hook.
desktop-file-utils
# Load-bearing for the first-login XDG Downloads lookup. `gio` is supplied by
# GNOME's already-required glib2 package.
xdg-user-dirs
# Load-bearing for the native gzip-cpio updates image consumed by liveinst.
cpio
gzip
%end

%post --erroronfail --log=/var/log/ks-17-gnome-hardening.log

#==============================================================================
# Module 17 — GNOME Hardening
#==============================================================================

set -euo pipefail
PATH=/usr/sbin:/usr/bin
export PATH

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [Module 17] $*"
}

log "=== Start Module 17: GNOME Privacy + Security Hardening ==="

#------------------------------------------------------------------------------
# Variables
#------------------------------------------------------------------------------
DCONF_PROFILE_DIR="/etc/dconf/profile"
DCONF_DB_DIR="/etc/dconf/db/distro.d"
DCONF_LOCKS_DIR="/etc/dconf/db/distro.d/locks"
DBUS_ADMIN_DIR="/usr/local/share/dbus-1/services"
DBUS_VENDOR_DIR="/usr/share/dbus-1/services"
GNOME_SOFTWARE_ADMIN_SERVICE="$DBUS_ADMIN_DIR/org.gnome.Software.service"
GNOME_SOFTWARE_VENDOR_SERVICE="$DBUS_VENDOR_DIR/org.gnome.Software.service"
DBUS_POLICY_DIR="/etc/dbus-1/session.d"
DBUS_BLOCK_POLICY="$DBUS_POLICY_DIR/20-noid-blocked-services.conf"
DBUS_BLOCK_SYSTEMD_SERVICE="noid-blocked-session-service.service"
DESKTOP_ADMIN_DIR="/usr/local/share/applications"
GNOME_SOFTWARE_VENDOR_DESKTOP="/usr/share/applications/org.gnome.Software.desktop"
GNOME_SOFTWARE_ADMIN_DESKTOP="$DESKTOP_ADMIN_DIR/org.gnome.Software.desktop"
GNOME_SOFTWARE_LAUNCHER_SYNC="/usr/local/sbin/noid-gnome-software-launcher-sync"
GNOME_SOFTWARE_LAUNCHER_ACTION="/etc/dnf/libdnf5-plugins/actions.d/noid-gnome-software-launcher.actions"
GNOME_SOFTWARE_QUIT="/usr/local/bin/noid-gnome-software-quit"
GNOME_SOFTWARE_RPM="/usr/local/bin/noid-gnome-software-rpm"
GNOME_SOFTWARE_BACKEND_STOP="/usr/local/sbin/noid-gnome-software-backend-stop"
GNOME_SOFTWARE_QUIT_SUDOERS="/etc/sudoers.d/48-noid-gnome-software-quit"
SYSTEMD_USER_DIR="/etc/systemd/user"
ANACONDA_CORE_NEVRA="anaconda-core-44.30-2.fc44.x86_64"
ANACONDA_LIVE_NEVRA="anaconda-live-44.30-2.fc44.noarch"
ANACONDA_VENDOR_LIVE_OS_INIT="/usr/lib64/python3.14/site-packages/pyanaconda/modules/payloads/source/live_os/initialization.py"
ANACONDA_VENDOR_LIVEINST="/usr/bin/liveinst"
LIVEINST_VENDOR_DESKTOP="/usr/share/applications/liveinst.desktop"
LIVEINST_UPDATE_DIR="/boot/loader/noid-privacy"
LIVEINST_UPDATE_IMAGE="$LIVEINST_UPDATE_DIR/liveinst-updates.img"
LIVEINST_UPDATE_SOURCE_SHA256="73fc1d452704547ef1c1759ebd925234e5a4d9c2e856486f33989242807148b0"

PRIVACY_PROFILE="$DCONF_DB_DIR/10-noid-gnome-privacy"
PRIVACY_LOCKS="$DCONF_LOCKS_DIR/10-noid-gnome-privacy"
AGENT_POWER_PROFILE="$DCONF_DB_DIR/12-noid-agent-workflow-power"
LID_ACTION_HELPER="/usr/local/bin/noid-toggle-lid-action"
LID_ACTION_SUDOERS="/etc/sudoers.d/49-noid-lid-action"

MASK_UNITS=(
    # Evolution: ONLY alarm-notify + user-prompter stay masked. source-
    # registry, calendar-factory AND addressbook-factory are deliberately
    # UNMASKED — masked state caused per-boot D-Bus cascade failures from
    # the shell calendar widget chain (Sources5/Calendar8/AddressBook10);
    # with no user-configured sources they serve 0 items and stay dormant.
    evolution-alarm-notify.service
    evolution-user-prompter.service
    localsearch-3.service
    localsearch-control-3.service
    localsearch-writeback-3.service
    # tinysparql portal: defense-in-depth — without the mask, D-Bus/portal
    # activation could trigger LocalSearch indirectly.
    tinysparql-xdg-portal-3.service
    "$DBUS_BLOCK_SYSTEMD_SERVICE"
    org.gnome.SettingsDaemon.Sharing.service
    org.gnome.SettingsDaemon.Smartcard.service
    org.gnome.SettingsDaemon.UsbProtection.service
    org.gnome.SettingsDaemon.UsbProtection.target
    gvfs-goa-volume-monitor.service
)

# Tracker3 keeps Fedora's RPM-owned service descriptors. Each descriptor has
# its own SystemdService, and the matching unit above is masked; dbus-broker
# therefore rejects activation immediately instead of waiting on /bin/false.
TRACKER_DBUS_NAMES=(
    org.freedesktop.Tracker3.Miner.Files
    org.freedesktop.Tracker3.Miner.Files.Control
    org.freedesktop.Tracker3.Writeback
    org.freedesktop.portal.Tracker
)
DBUS_ADMIN_BLOCKED_NAMES=(
    org.gnome.OnlineAccounts
    org.gnome.Identity
)
DBUS_POLICY_BLOCKED_NAMES=(
    org.gnome.OnlineAccounts
    org.gnome.Identity
    "${TRACKER_DBUS_NAMES[@]}"
)
DBUS_VENDOR_SPECS=(
    'org.gnome.Software|gnome-software'
    'org.gnome.OnlineAccounts|gnome-online-accounts'
    'org.gnome.Identity|gnome-online-accounts'
    'org.freedesktop.Tracker3.Miner.Files|localsearch'
    'org.freedesktop.Tracker3.Miner.Files.Control|localsearch'
    'org.freedesktop.Tracker3.Writeback|localsearch'
    'org.freedesktop.portal.Tracker|tinysparql'
)

#------------------------------------------------------------------------------
# Step 1: Ensure dconf profile exists
#------------------------------------------------------------------------------
log "Step 1/8: Ensure /etc/dconf/profile/user exists"
mkdir -p "$DCONF_PROFILE_DIR"
if [ ! -f "$DCONF_PROFILE_DIR/user" ]; then
    # Fallback in case Module 08 hasn't run yet (lexical order should prevent
    # this, but defensive).
    # Include site-db (see Module 08 fix rationale).
    cat > "$DCONF_PROFILE_DIR/user" <<'PROFILE_EOF'
user-db:user
system-db:site
system-db:distro
PROFILE_EOF
    chmod 644 "$DCONF_PROFILE_DIR/user"
    log "  Created $DCONF_PROFILE_DIR/user (fallback; Module 08 should have created it)"
else
    log "  $DCONF_PROFILE_DIR/user already exists (from Module 08)"
fi

#------------------------------------------------------------------------------
# Step 2: Write dconf privacy profile
#------------------------------------------------------------------------------
log "Step 2/8: Write $PRIVACY_PROFILE"
mkdir -p "$DCONF_DB_DIR"
cat > "$PRIVACY_PROFILE" <<'DCONF_PRIVACY_EOF'
# NoID Privacy Workstation 44 — GNOME Privacy + Security Hardening
# Module 17
# Design rationale: per-key, captured inline below.
#
# Loaded via /etc/dconf/profile/user (system-db:distro) — Module 08 shared profile
# Lexical ordering: 00-noid-gnome-software (Module 08) → 10-noid-gnome-privacy (Module 17)

[org/gnome/desktop/privacy]
# Recent files tracking — disabled
remember-recent-files=false
# `recent-files-max-age` is schema type `i` (signed); zero means expire
# immediately if recent-file tracking is ever enabled. `old-files-age` below is
# the separate unsigned (`u`) key and therefore retains its uint32 prefix.
recent-files-max-age=0
# App usage tracking — disabled
remember-app-usage=false
# Trash + temp file cleanup — automatically after 1 day (privacy tightening;
# was 7d). Privacy-image philosophy: minimize on-disk artefacts of deleted/
# discarded content. 1 day = enough buffer to undo accidental deletes within
# same day, but no week-long forensic exposure for sensitive deletions.
remove-old-trash-files=true
remove-old-temp-files=true
old-files-age=uint32 1
# Crash reports + software usage stats — disabled (redundant with Fedora defaults but explicit)
report-technical-problems=false
send-software-usage-stats=false
# Camera + microphone both disabled by default (defensive symmetry). User
# re-enables per device in GNOME Settings → Privacy when needed for voice
# or video calls. Neither key is locked — user toggles are honored.
disable-camera=true
disable-microphone=true
# GNOME USB-protection UI is disabled; USBGuard is the sole admission authority.
#
# Runtime testing proved the gsd-usb-protection plugin can inject an
# `allow id *:* label "GNOME_SETTINGS_DAEMON_RULE"` rule into USBGuard's
# runtime after session unlock/hotplug, which neutralizes USBGuard's
# default-deny policy during normal use. Every freshly inserted USB stick
# is silently allowed because Rule 5 (`*:*`) matches before the
# `ImplicitPolicyTarget=block` default could. Module 14 usbguard-notifier
# then sees no block-events and stays silent.
#
# The Dconf value alone is not a security boundary: false was effective in
# GSettings while the wildcard was still reproduced. The corresponding GSD
# service and target are therefore masked in Step 6. This false value merely
# keeps the GNOME UI consistent with that intentional disablement.
# usbguard-notifier (Module 14 Step 7c with --wait) surfaces block-
# events to the user via desktop notification → user decides per-device
# via `usbguard allow-device <id>` or the noid-usbguard-allow-device CLI.
#
# Lockscreen-period USB blocking is preserved by USBGuard's daemon-level
# config (Module 14 Step 1: ImplicitPolicyTarget=block + PresentDevicePolicy
# =apply-policy + InsertedDevicePolicy=apply-policy, all 24/7).
#
# Cross-ref: host diagnosis (usbguard-notifier vs usb-protection) +
#            M14 cross-module note.
usb-protection=false

[org/gnome/system/location]
# Location off by default but user-toggleable (camera/
# microphone model — NOT locked; geoclue unmasked in M08 so the toggle works).
enabled=false
max-accuracy-level='country'

[org/gnome/desktop/media-handling]
# No automount, no auto-open, no autorun — belt+suspenders with Module 14 USBGuard
automount=false
automount-open=false
autorun-never=true
# Fedora default whitelist for "safe" content types (install media, ostree images)
autorun-x-content-start-app=['x-content/unix-software', 'x-content/ostree-repository']

[org/gtk/settings/file-chooser]
# Nautilus 50 ignores its deprecated `show-hidden-files` key. On first launch
# it migrates this GTK3 value into the GTK4 schema below, so both defaults must
# agree or that migration would write a false user value over the GTK4 default.
# Neither key is locked; a user's later Nautilus toggle remains authoritative.
show-hidden=true

[org/gtk/gtk4/settings/file-chooser]
# Active Nautilus 50 hidden-file preference after the one-time GTK migration.
show-hidden=true

[org/gnome/nautilus/preferences]
# Maintained generic-folder sorting defaults. Nautilus deliberately gives the
# XDG Downloads folder its own mtime-descending fallback, so Step 3b seeds that
# one folder through Nautilus' native GIO metadata only when no user sort choice
# exists. All values remain unlocked and user-overridable.
default-sort-order='name'
default-sort-in-reverse-order=false

[org/gnome/desktop/screensaver]
# Lock after idle screen-shield activation. In GNOME 50, lock-delay=0 still
# waits for the shell's minimum 10-second idle fade; it is not a zero-time lock.
lock-enabled=true
# uint32 prefix for 'u' type
lock-delay=uint32 0
# No user switcher on lockscreen (single-user target)
user-switch-enabled=false

[org/gnome/desktop/session]
# Single user-controlled graphical blank timer. At 300 seconds GNOME Shell
# starts its 10-second screen-shield fade and schedules the lock no earlier
# than that fade. When the shield reports ActiveChanged(true), GNOME Settings
# Daemon blanks the monitors immediately; its 30-second active-shield idle
# watch is a recovery path, not an additional post-shield delay.
# The separate agent-workflow profile below disables early panel dimming and
# idle auto-suspend by default without changing this blank/lock timer.
idle-delay=uint32 300

[org/gnome/desktop/notifications]
# No notification content on lockscreen (prevent info leak)
show-in-lock-screen=false

[org/gnome/shell]
# Extension installation lockdown — prevents extensions.gnome.org installs + manual .zip
# Shell extensions run unsandboxed with full JS access to gnome-shell process
# RPM-installed extensions can still be enabled by user (disable-user-extensions=false)
allow-extension-installation=false
disable-user-extensions=false
enabled-extensions=@as []

[org/gnome/desktop/search-providers]
# No external app search providers in Activities overlay
# Prevents leak of Contacts / Nautilus file names / running apps state via shell DBus
disable-external=true

[org/gnome/desktop/thumbnailers]
# Disable all external thumbnailer programs — kills parser-CVE attack vector
# (thumbnail parsers for PDF/video/office are notorious vuln source)
# Trade-off: no preview thumbnails for video/PDF/office in Nautilus
disable-all=true

[org/gnome/desktop/remote-desktop/rdp]
# RDP explicitly off (belt+suspenders to GSD Sharing mask)
enable=false

[org/gnome/desktop/remote-desktop/vnc]
# VNC explicitly off (belt+suspenders to GSD Sharing mask)
enable=false

[org/gnome/mutter]
# Keep Fedora/GNOME's default persistent Xwayland lifecycle. A reproduced
# GNOME 50 session failure followed the last-X11-client teardown path while
# autoclose-xwayland was selected. One hardware observation alone does not
# prove a universal Mutter defect, but this optional feature is unnecessary
# for the documented threat model and its failure mode takes down the desktop.
# Native Wayland remains the default below; Xwayland stays available only for
# explicit compatibility use.
# GNOME 50 Mutter retains scale-monitor-framebuffer and xwayland-native-scaling as
# legacy schema enum nicks, but its runtime parser no longer recognizes or
# implements them as selectable experimental features. No experimental Mutter
# feature is selected.
experimental-features=@as []

[org/gnome/settings-daemon/plugins/housekeeping]
# GNOME 49+ Foundation donation reminder: GNOME Settings Daemon 50.1 checks
# after one hour and then daily, while allowing a reminder once per 365 days.
# Disabled as an unsolicited UX notification. Users can still donate directly.
donation-reminder-enabled=false

[org/gnome/desktop/sound]
# Enable software amplification so GNOME can extend the output slider to the
# audio stack's amplified maximum and mark the normal maximum as 100%; the
# exact ceiling is stack-dependent. This can help quiet sources but may clip
# or distort. NOT locked: the user can disable "Allow volume above 100%".
allow-volume-above-100-percent=true
# Keep the maintained gsettings-desktop-schemas default explicit: Fedora's
# installed freedesktop XDG sound theme handles event sounds until the user
# chooses otherwise. GNOME Control Center creates the per-user __custom theme
# only after choosing Click, Hum, String or Swing. This unlocked default does
# not claim to preset the alert-chooser label; a user override wins.
theme-name='freedesktop'
DCONF_PRIVACY_EOF
chmod 644 "$PRIVACY_PROFILE"
privacy_bytes=$(stat -c%s "$PRIVACY_PROFILE")
log "  Written $PRIVACY_PROFILE ($privacy_bytes bytes)"

# Agent and long-running local workflows must not be interrupted merely because
# the graphical seat is idle. These are dconf defaults, never locks: user-db
# values continue to win and GNOME Settings can re-enable either suspend mode.
# Automatic Screen Blank + lock remain owned by idle-delay/lock-enabled above,
# and Automatic Power Saver at low battery remains at GNOME's maintained value.
cat > "$AGENT_POWER_PROFILE" <<'DCONF_AGENT_POWER_EOF'
# NoID Privacy Workstation 44 — user-adjustable agent workflow power defaults
[org/gnome/settings-daemon/plugins/power]
# Avoid the half-idle-delay brightness transition during monitored workflows.
idle-dim=false
# Keep local agents and long jobs running while the seat is idle. No timeout is
# changed, so re-enabling either GNOME toggle restores its visible delay.
sleep-inactive-ac-type='nothing'
sleep-inactive-battery-type='nothing'
DCONF_AGENT_POWER_EOF
chmod 0644 "$AGENT_POWER_PROFILE"
agent_power_bytes=$(stat -c%s "$AGENT_POWER_PROFILE")
log "  Written $AGENT_POWER_PROFILE ($agent_power_bytes bytes; defaults only)"

# GNOME 50 has no Settings key for lid-close action. Use systemd-logind's
# maintained administrator drop-in surface, but only after proving that the
# kernel exposes the input subsystem's SW_LID capability. The helper owns one
# explicit, lexically last user-choice file; reset removes only that file so a
# lower Fedora or NVIDIA compatibility policy becomes effective again.
install -d -m 0755 -o root -g root /usr/local/bin
cat > /usr/local/bin/noid-toggle-lid-action <<'NOID_LID_ACTION_EOF'
#!/usr/bin/env bash
# Show or change the native systemd-logind lid-close action.
set -euo pipefail
umask 077

PATH=/usr/local/bin:/usr/bin:/usr/sbin
export PATH

# shellcheck source=/dev/null
[ ! -r /usr/local/lib/noid-privacy/agent-install-format.sh ] || \
    NOID_FMT_AUTO_TITLE="NoID Privacy — Lid Close" \
    NOID_FMT_AUTO_SUBTITLE="Native systemd-logind policy" \
    . /usr/local/lib/noid-privacy/agent-install-format.sh

PROGRAM=noid-toggle-lid-action
LOGIN1_DEST=org.freedesktop.login1
LOGIN1_PATH=/org/freedesktop/login1
LOGIN1_MANAGER=org.freedesktop.login1.Manager

die() {
    echo "$PROGRAM: ERROR: $*" >&2
    exit 1
}

usage() {
    cat <<'USAGE'
Usage: noid-toggle-lid-action [status|suspend|lock|reset]

  status   Show detected lid hardware, managed policy and effective logind state
  suspend  Suspend when the lid closes on battery or external power
  lock     Lock when the lid closes on battery or external power
  reset    Remove the choice and return to the lower NoID Privacy/Fedora policy

Docked/clamshell behavior remains separately owned by systemd-logind and is
always shown by status. Desktops without a kernel SW_LID device are reported
as such and reject all changes without writing a policy file.
USAGE
}

# Tests exercise the complete transaction against a user-owned /var/tmp tree.
# This mode never invokes sudo and is rejected for root. Production paths and
# commands remain fixed constants and cannot be redirected before elevation.
TEST_ROOT=${NOID_LID_TEST_ROOT:-}
if [[ -n $TEST_ROOT ]]; then
    [[ $EUID -ne 0 ]] || die "fixture mode refuses root"
    [[ $TEST_ROOT == /var/tmp/noid-lid-fixture.* ]] \
        || die "fixture root is outside the closed /var/tmp prefix"
    [[ -d $TEST_ROOT && ! -L $TEST_ROOT && -O $TEST_ROOT ]] \
        || die "fixture root is not one owned real directory"
    INPUT_ROOT=$TEST_ROOT/sys/class/input
    POLICY_DIR=$TEST_ROOT/etc/systemd/logind.conf.d
    POLICY_FILE=$POLICY_DIR/99-noid-user-lid-action.conf
    SYSTEMCTL=$TEST_ROOT/bin/systemctl
    BUSCTL=$TEST_ROOT/bin/busctl
    INHIBIT=$TEST_ROOT/bin/systemd-inhibit
    RESTORECON=$TEST_ROOT/bin/restorecon
    EXPECTED_OWNER=$(id -un):$(id -gn)
else
    INPUT_ROOT=/sys/class/input
    POLICY_DIR=/etc/systemd/logind.conf.d
    POLICY_FILE=$POLICY_DIR/99-noid-user-lid-action.conf
    SYSTEMCTL=/usr/bin/systemctl
    BUSCTL=/usr/bin/busctl
    INHIBIT=/usr/bin/systemd-inhibit
    RESTORECON=/usr/sbin/restorecon
    EXPECTED_OWNER=root:root
fi

render_policy() {
    local action=$1
    printf '%s\n' \
        '# NoID Privacy — explicit administrator lid-close choice.' \
        '# Managed by noid-toggle-lid-action; do not edit in place.' \
        '[Login]' \
        "HandleLidSwitch=$action" \
        "HandleLidSwitchExternalPower=$action"
}

lid_devices() {
    local event raw last name
    shopt -s nullglob
    for event in "$INPUT_ROOT"/event*; do
        [[ -r $event/device/capabilities/sw ]] || continue
        raw=$(<"$event/device/capabilities/sw") || continue
        raw=${raw//$'\n'/ }
        last=${raw##* }
        [[ $last =~ ^[[:xdigit:]]+$ ]] || continue
        # Linux input-event bit 0 is SW_LID. In multiword sysfs bitmaps the
        # least-significant word is printed last, so only that word is needed.
        (( (0x$last & 1) == 1 )) || continue
        name=$(<"$event/device/name") || name=unknown
        printf '%s|%s\n' "${event##*/}" "$name"
    done
    shopt -u nullglob
}

has_lid() {
    [[ -n $(lid_devices) ]]
}

policy_state() {
    local metadata
    if [[ ! -e $POLICY_FILE && ! -L $POLICY_FILE ]]; then
        printf '%s\n' none
        return 0
    fi
    [[ -f $POLICY_FILE && ! -L $POLICY_FILE ]] || {
        printf '%s\n' modified
        return 0
    }
    metadata=$(stat -Lc '%U:%G:%a:%h' "$POLICY_FILE" 2>/dev/null || true)
    [[ $metadata == "$EXPECTED_OWNER:644:1" ]] || {
        printf '%s\n' modified
        return 0
    }
    if cmp -s "$POLICY_FILE" <(render_policy suspend); then
        printf '%s\n' suspend
    elif cmp -s "$POLICY_FILE" <(render_policy lock); then
        printf '%s\n' lock
    else
        printf '%s\n' modified
    fi
}

manager_value() {
    local property=$1 reply
    reply=$("$BUSCTL" get-property "$LOGIN1_DEST" "$LOGIN1_PATH" \
        "$LOGIN1_MANAGER" "$property" 2>/dev/null) || return 1
    [[ $reply =~ ^s\ \"([^\"]*)\"$ ]] || return 1
    printf '%s\n' "${BASH_REMATCH[1]}"
}

can_suspend() {
    local reply
    reply=$("$BUSCTL" call "$LOGIN1_DEST" "$LOGIN1_PATH" \
        "$LOGIN1_MANAGER" CanSuspend 2>/dev/null) || return 1
    [[ $reply == 's "yes"' || $reply == 's "challenge"' ]]
}

status() {
    local devices managed normal external docked blockers
    devices=$(lid_devices)
    managed=$(policy_state)
    normal=$(manager_value HandleLidSwitch 2>/dev/null || printf unavailable)
    external=$(manager_value HandleLidSwitchExternalPower 2>/dev/null \
        || printf unavailable)
    docked=$(manager_value HandleLidSwitchDocked 2>/dev/null || printf unavailable)

    echo "NoID Privacy — Laptop Lid Action"
    if [[ -n $devices ]]; then
        echo "Hardware: PRESENT (kernel SW_LID)"
        while IFS='|' read -r event name; do
            printf '  %s: %s\n' "$event" "$name"
        done <<<"$devices"
    else
        echo "Hardware: ABSENT (desktop or no kernel SW_LID device)"
    fi
    case "$managed" in
        none) echo "Explicit choice: none (lower NoID Privacy/Fedora policy)" ;;
        suspend|lock) echo "Explicit choice: $managed" ;;
        modified) echo "Explicit choice: UNKNOWN (managed file changed independently)" ;;
    esac
    printf 'Effective: lid=%s external-power=%s docked=%s\n' \
        "$normal" "$external" "$docked"

    blockers=$("$INHIBIT" --list --no-legend 2>/dev/null \
        | awk '$0 ~ /handle-lid-switch/ && $NF == "block" {print}' || true)
    if [[ -n $blockers ]]; then
        echo "Handler: another process currently owns handle-lid-switch"
        printf '%s\n' "$blockers" | sed 's/^/  /'
    else
        echo "Handler: systemd-logind (no blocking handle-lid-switch inhibitor)"
    fi
}

publish_policy() {
    local action=$1 temporary
    temporary=$(mktemp "$POLICY_DIR/.99-noid-user-lid-action.conf.XXXXXX")
    trap 'rm -f -- "${temporary:-}"' RETURN
    render_policy "$action" >"$temporary"
    chmod 0644 "$temporary"
    if [[ -z $TEST_ROOT ]]; then
        chown root:root "$temporary"
    fi
    if [[ -x $RESTORECON ]]; then
        "$RESTORECON" -F "$temporary"
    fi
    sync -- "$temporary"
    mv -fT -- "$temporary" "$POLICY_FILE"
    temporary=
    trap - RETURN
    sync -- "$POLICY_FILE"
    sync -- "$POLICY_DIR"
}

remove_policy() {
    rm -f -- "$POLICY_FILE"
    sync -- "$POLICY_DIR"
}

restore_prior_policy() {
    local prior=$1
    case "$prior" in
        none) remove_policy ;;
        suspend|lock) publish_policy "$prior" ;;
        *) return 1 ;;
    esac
    "$SYSTEMCTL" reload systemd-logind.service
}

apply_as_admin() {
    local action=$1 prior actual external
    [[ -n $TEST_ROOT || $EUID -eq 0 ]] || die "internal apply requires root"
    has_lid || die "no kernel SW_LID device; refusing to write laptop policy"
    [[ -x $SYSTEMCTL && -x $BUSCTL ]] \
        || die "required native systemd command is unavailable"

    if [[ -z $TEST_ROOT ]]; then
        [[ -f /usr/local/bin/noid-toggle-lid-action \
            && ! -L /usr/local/bin/noid-toggle-lid-action ]] \
            || die "installed helper is missing or symlinked"
        [[ $(stat -Lc '%U:%G:%a:%h' \
            /usr/local/bin/noid-toggle-lid-action 2>/dev/null || true) \
            == root:root:755:1 ]] \
            || die "installed helper metadata is not root:root:0755"
    fi

    if [[ ! -e $POLICY_DIR ]]; then
        install -d -m 0755 "$POLICY_DIR"
        [[ -z $TEST_ROOT ]] && chown root:root "$POLICY_DIR"
    fi
    [[ -d $POLICY_DIR && ! -L $POLICY_DIR ]] \
        || die "logind drop-in directory is missing, symlinked or not a directory"
    [[ $(stat -Lc '%U:%G:%a' "$POLICY_DIR" 2>/dev/null || true) \
        == "$EXPECTED_OWNER:755" ]] \
        || die "logind drop-in directory metadata is not trusted"

    prior=$(policy_state)
    [[ $prior != modified ]] \
        || die "managed policy changed independently; refusing to overwrite it"
    if [[ $action == reset && $prior == none ]]; then
        return 0
    fi

    case "$action" in
        suspend|lock) publish_policy "$action" ;;
        reset) remove_policy ;;
        *) die "invalid internal action" ;;
    esac

    if ! "$SYSTEMCTL" reload systemd-logind.service; then
        restore_prior_policy "$prior" >/dev/null 2>&1 \
            || die "logind reload failed and prior policy restoration failed"
        die "logind reload failed; prior policy restored"
    fi

    if [[ $action == suspend || $action == lock ]]; then
        actual=$(manager_value HandleLidSwitch 2>/dev/null || true)
        external=$(manager_value HandleLidSwitchExternalPower 2>/dev/null || true)
        if [[ $actual != "$action" || $external != "$action" \
            || $(policy_state) != "$action" ]]; then
            restore_prior_policy "$prior" >/dev/null 2>&1 \
                || die "effective-state mismatch and prior restoration failed"
            die "effective logind state did not match; prior policy restored"
        fi
    else
        if [[ $(policy_state) != none ]] \
            || ! manager_value HandleLidSwitch >/dev/null \
            || ! manager_value HandleLidSwitchExternalPower >/dev/null \
            || ! manager_value HandleLidSwitchDocked >/dev/null; then
            restore_prior_policy "$prior" >/dev/null 2>&1 \
                || die "reset verification failed and prior restoration failed"
            die "reset verification failed; prior policy restored"
        fi
    fi
}

if [[ ${1:-} == --apply-root ]]; then
    [[ $# -eq 2 ]] || die "invalid internal invocation"
    apply_as_admin "$2"
    exit 0
fi

action=${1:-status}
[[ $# -le 1 ]] || { usage >&2; exit 2; }
case "$action" in
    -h|--help|help)
        usage
        exit 0
        ;;
esac
[[ $EUID -ne 0 ]] || die "run as the desktop user, not through sudo"

case "$action" in
    status)
        status
        ;;
    suspend|lock|reset)
        has_lid || {
            status
            die "this machine has no kernel SW_LID device; no change made"
        }
        [[ $(policy_state) != modified ]] \
            || die "managed policy changed independently; review it before changing"
        if [[ $action == suspend ]]; then
            can_suspend || die "systemd-logind reports that suspend is unavailable"
            echo "Warning: lid-close suspend can expose GPU/firmware resume defects."
            read -r -p "Set lid-close to suspend on battery and external power? [y/N] " answer
            [[ ${answer:-n} =~ ^[Yy]([Ee][Ss])?$ ]] || {
                echo "Cancelled; no change made."
                exit 0
            }
        fi
        if [[ -n $TEST_ROOT ]]; then
            "$0" --apply-root "$action"
        else
            /usr/bin/sudo -n /usr/local/bin/noid-toggle-lid-action \
                --apply-root "$action"
        fi
        status
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac
NOID_LID_ACTION_EOF
chmod 0755 "$LID_ACTION_HELPER"
chown root:root "$LID_ACTION_HELPER"
command -v restorecon >/dev/null 2>&1 && restorecon -F "$LID_ACTION_HELPER"
cat > "$LID_ACTION_SUDOERS" <<'NOID_LID_ACTION_SUDO_EOF'
# NoID Privacy — closed privilege bridge for the M17 lid-action helper.
%wheel ALL=(root) NOPASSWD: /usr/local/bin/noid-toggle-lid-action --apply-root suspend
%wheel ALL=(root) NOPASSWD: /usr/local/bin/noid-toggle-lid-action --apply-root lock
%wheel ALL=(root) NOPASSWD: /usr/local/bin/noid-toggle-lid-action --apply-root reset
NOID_LID_ACTION_SUDO_EOF
chmod 0440 "$LID_ACTION_SUDOERS"
chown root:root "$LID_ACTION_SUDOERS"
command -v restorecon >/dev/null 2>&1 && restorecon -F "$LID_ACTION_SUDOERS"
if ! visudo -cf "$LID_ACTION_SUDOERS" >/dev/null 2>&1; then
    rm -f -- "$LID_ACTION_SUDOERS"
    log "  FAIL: lid-action sudoers policy is invalid"
    exit 1
fi
log "  Written $LID_ACTION_HELPER + exact three-action NOPASSWD bridge"

#------------------------------------------------------------------------------
# Step 2b: Just-Perfection GNOME Shell Extension
# (events-section hide in clock-menu)
#------------------------------------------------------------------------------
# Just-Perfection hides the empty events-section in the clock menu (UI-only
# — the unmasked evolution backend stays healthy, no log-spam regression).
# GNOME-hosted and GPL-3.0-only. Static review of the pinned v36 payload found no
# network or telemetry code; this statement is scoped to that pinned payload.
# Build-time SHA256-pinned download + closed archive validation + atomic
# system-wide publication + strict schema compile; the dconf override/lock pair
# is written below (background + precedence in the EVENTS_HIDE_EOF heredoc).
# Runtime updates use M25's separate explicit EGO transaction.
log "Step 2b/8: Just-Perfection extension (events-section hide)"

JP_VERSION="36"
JP_UUID="just-perfection-desktop@just-perfection"
JP_URL="https://extensions.gnome.org/extension-data/just-perfection-desktopjust-perfection.v${JP_VERSION}.shell-extension.zip"
JP_SHA256="4aef633af6345755d8982f14821d1c276b539faa10c2eddc596a27359ebe3281"
JP_SIZE="230176"
JP_ENTRY_COUNT="74"
JP_EXPANDED_SIZE="864052"
JP_EXT_PARENT="/usr/share/gnome-shell/extensions"
JP_EXT_DIR="${JP_EXT_PARENT}/${JP_UUID}"
JP_CACHE_DIR="/var/lib/noid-privacy/cache"
JP_STATE_DIR="${JP_CACHE_DIR%/*}"
JP_CACHE_ZIP="${JP_CACHE_DIR}/just-perfection-v${JP_VERSION}.shell-extension.zip"
JP_WORK=""
JP_TMPZIP=""
JP_CANDIDATE=""
JP_CACHE_CANDIDATE=""

jp_cleanup() {
    if [ -n "$JP_CACHE_CANDIDATE" ] \
       && [ -f "$JP_CACHE_CANDIDATE" ] \
       && [ ! -L "$JP_CACHE_CANDIDATE" ]; then
        rm -f -- "$JP_CACHE_CANDIDATE"
    fi
    if [ -n "$JP_CANDIDATE" ] \
       && [ -d "$JP_CANDIDATE" ] \
       && [ ! -L "$JP_CANDIDATE" ]; then
        rm -rf --one-file-system -- "$JP_CANDIDATE"
    fi
    if [ -n "$JP_WORK" ] && [ -d "$JP_WORK" ] && [ ! -L "$JP_WORK" ]; then
        rm -rf --one-file-system -- "$JP_WORK"
    fi
}
trap jp_cleanup EXIT
trap 'exit 1' HUP INT TERM

for jp_parent in "$JP_EXT_PARENT" /var/lib; do
    if [ ! -d "$jp_parent" ] || [ -L "$jp_parent" ] \
       || [ "$(stat -c '%U:%G:%a' "$jp_parent" 2>/dev/null || true)" != \
            root:root:755 ]; then
        log "  FAIL: unsafe Just-Perfection parent: $jp_parent"
        exit 1
    fi
done
if [ -e "$JP_STATE_DIR" ] || [ -L "$JP_STATE_DIR" ]; then
    if [ ! -d "$JP_STATE_DIR" ] || [ -L "$JP_STATE_DIR" ] \
       || [ "$(stat -c '%U:%G:%a' "$JP_STATE_DIR" 2>/dev/null || true)" != \
            root:root:755 ]; then
        log "  FAIL: unsafe Just-Perfection state directory"
        exit 1
    fi
else
    install -d -m 0755 -o root -g root "$JP_STATE_DIR"
fi
restorecon -F "$JP_STATE_DIR"
matchpathcon -V "$JP_STATE_DIR" >/dev/null 2>&1 || {
    log "  FAIL: Just-Perfection state-directory SELinux context differs"
    exit 1
}
if [ -e "$JP_CACHE_DIR" ] || [ -L "$JP_CACHE_DIR" ]; then
    if [ ! -d "$JP_CACHE_DIR" ] || [ -L "$JP_CACHE_DIR" ] \
       || [ "$(stat -c '%U:%G:%a' "$JP_CACHE_DIR" 2>/dev/null || true)" != \
            root:root:755 ]; then
        log "  FAIL: unsafe Just-Perfection cache directory"
        exit 1
    fi
else
    install -d -m 0755 -o root -g root "$JP_CACHE_DIR"
fi
restorecon -F "$JP_CACHE_DIR"
matchpathcon -V "$JP_CACHE_DIR" >/dev/null 2>&1 || {
    log "  FAIL: Just-Perfection cache-directory SELinux context differs"
    exit 1
}
if { [ -e "$JP_CACHE_ZIP" ] || [ -L "$JP_CACHE_ZIP" ]; } \
   && { [ ! -f "$JP_CACHE_ZIP" ] || [ -L "$JP_CACHE_ZIP" ]; }; then
    log "  FAIL: unsafe Just-Perfection cache entry"
    exit 1
fi
if { [ -e "$JP_EXT_DIR" ] || [ -L "$JP_EXT_DIR" ]; } \
   && { [ ! -d "$JP_EXT_DIR" ] || [ -L "$JP_EXT_DIR" ]; }; then
    log "  FAIL: unsafe pre-existing Just-Perfection extension root"
    exit 1
fi

JP_WORK=$(mktemp -d /var/tmp/noid-just-perfection.XXXXXXXX)
chmod 0700 "$JP_WORK"
JP_TMPZIP="$JP_WORK/extension.zip"
jp_cache_refresh=0
if [ -f "$JP_CACHE_ZIP" ] \
   && [ "$(stat -c '%s:%h' "$JP_CACHE_ZIP" 2>/dev/null || true)" = \
        "$JP_SIZE:1" ] \
   && [ "$(sha256sum "$JP_CACHE_ZIP" | awk '{print $1}')" = "$JP_SHA256" ]; then
    cp -- "$JP_CACHE_ZIP" "$JP_TMPZIP"
    chmod 0600 "$JP_TMPZIP"
    if [ "$(stat -c '%U:%G:%a' "$JP_CACHE_ZIP")" != root:root:644 ]; then
        jp_cache_refresh=1
        log "  CACHE REPAIR: reviewed bytes have non-canonical metadata"
    else
        log "  CACHE HIT: $JP_CACHE_ZIP (size/SHA-256 verified)"
    fi
else
    if [ -f "$JP_CACHE_ZIP" ]; then
        cache_sha256=$(sha256sum "$JP_CACHE_ZIP" | awk '{print $1}')
        log "  CACHE MISS: bytes differ (cache=${cache_sha256:0:16} vs expected=${JP_SHA256:0:16})"
    fi
    log "  FETCHING: $JP_URL"
    if ! curl -fsS --retry 3 --retry-delay 2 --retry-all-errors \
            --proto '=https' --tlsv1.2 --max-redirs 0 --connect-timeout 15 \
            --max-time 60 --max-filesize "$JP_SIZE" \
            -o "$JP_TMPZIP" "$JP_URL"; then
        log "  FAIL: curl failed for $JP_URL"
        log "  Required pinned Just-Perfection payload unavailable — aborting build"
        exit 1
    fi
    chmod 0600 "$JP_TMPZIP"
    jp_cache_refresh=1
fi
if [ ! -f "$JP_TMPZIP" ] || [ -L "$JP_TMPZIP" ] \
   || [ "$(stat -c '%s:%h' "$JP_TMPZIP" 2>/dev/null || true)" != \
        "$JP_SIZE:1" ]; then
    log "  FAIL: Just-Perfection archive size/inode contract differs"
    exit 1
fi
download_sha256=$(sha256sum "$JP_TMPZIP" | awk '{print $1}')
if [ "$download_sha256" != "$JP_SHA256" ]; then
    log "  FAIL: SHA256 mismatch — payload=${download_sha256} expected=${JP_SHA256}"
    exit 1
fi

if [ "$jp_cache_refresh" -eq 1 ]; then
    JP_CACHE_CANDIDATE=$(mktemp "$JP_CACHE_DIR/.just-perfection-v${JP_VERSION}.XXXXXXXX")
    cp -- "$JP_TMPZIP" "$JP_CACHE_CANDIDATE"
    chown root:root "$JP_CACHE_CANDIDATE"
    chmod 0644 "$JP_CACHE_CANDIDATE"
    sync -- "$JP_CACHE_CANDIDATE"
    mv -fT -- "$JP_CACHE_CANDIDATE" "$JP_CACHE_ZIP"
    JP_CACHE_CANDIDATE=""
    restorecon -F "$JP_CACHE_ZIP"
    if [ "$(stat -c '%U:%G:%a:%s:%h' "$JP_CACHE_ZIP" \
            2>/dev/null || true)" != "root:root:644:$JP_SIZE:1" ] \
       || [ "$(sha256sum "$JP_CACHE_ZIP" | awk '{print $1}')" != "$JP_SHA256" ] \
       || ! matchpathcon -V "$JP_CACHE_ZIP" >/dev/null 2>&1; then
        log "  FAIL: published Just-Perfection cache postcondition differs"
        exit 1
    fi
    sync -- "$JP_CACHE_ZIP" "$JP_CACHE_DIR"
    log "  Cached reviewed v${JP_VERSION} archive atomically"
fi

JP_CANDIDATE=$(mktemp -d "$JP_EXT_PARENT/.${JP_UUID}.noid-new.XXXXXXXX")
python3 -B - "$JP_TMPZIP" "$JP_CANDIDATE" "$JP_UUID" "$JP_VERSION" \
        "$JP_ENTRY_COUNT" "$JP_EXPANDED_SIZE" <<'JP_ARCHIVE_PY'
import json
import os
from pathlib import PurePosixPath
import shutil
import stat
import sys
import zipfile

archive, output, expected_uuid, expected_version, expected_count, expected_total = sys.argv[1:]
expected_count = int(expected_count)
expected_total = int(expected_total)

def reject(message):
    raise ValueError(message)

output_meta = os.lstat(output)
if not stat.S_ISDIR(output_meta.st_mode) or stat.S_ISLNK(output_meta.st_mode):
    reject("candidate root is not a real directory")
if os.listdir(output):
    reject("candidate root is not empty")

with zipfile.ZipFile(archive) as bundle:
    entries = bundle.infolist()
    if len(entries) != expected_count:
        reject("entry count differs from reviewed archive")
    seen = set()
    total = 0
    normalized = []
    for entry in entries:
        name = entry.filename
        if not name or len(name.encode("utf-8")) > 4096:
            reject("invalid entry name")
        if name.startswith("/") or "\\" in name:
            reject("non-relative POSIX entry")
        parts = PurePosixPath(name).parts
        if not parts or any(part in ("", ".", "..") for part in parts):
            reject("unsafe entry component")
        path = "/".join(parts)
        if path in seen:
            reject("duplicate normalized entry")
        seen.add(path)
        if entry.flag_bits & 1:
            reject("encrypted entry")
        mode = (entry.external_attr >> 16) & 0xFFFF
        file_type = stat.S_IFMT(mode)
        if entry.is_dir():
            if file_type not in (0, stat.S_IFDIR):
                reject("directory/type mismatch")
        else:
            if file_type not in (0, stat.S_IFREG):
                reject("non-regular archive entry")
            if entry.file_size < 0 or entry.file_size > expected_total:
                reject("entry size outside reviewed bound")
            total += entry.file_size
            if total > expected_total:
                reject("expanded archive exceeds reviewed size")
        normalized.append((entry, parts))
    if total != expected_total:
        reject("expanded archive size differs")
    if bundle.testzip() is not None:
        reject("archive CRC failure")
    try:
        metadata_raw = bundle.read("metadata.json")
        metadata = json.loads(metadata_raw.decode("utf-8"))
    except (KeyError, UnicodeError, json.JSONDecodeError) as exc:
        reject(f"metadata unreadable: {exc}")
    if metadata.get("uuid") != expected_uuid:
        reject("metadata UUID differs")
    if str(metadata.get("version", "")) != expected_version:
        reject("metadata version differs")
    shells = metadata.get("shell-version")
    if not isinstance(shells, list) or "50" not in {str(value) for value in shells}:
        reject("GNOME 50 compatibility missing")
    for entry, parts in normalized:
        destination = os.path.join(output, *parts)
        if entry.is_dir():
            os.makedirs(destination, mode=0o700, exist_ok=True)
            continue
        os.makedirs(os.path.dirname(destination), mode=0o700, exist_ok=True)
        with bundle.open(entry) as source, open(destination, "xb") as target:
            shutil.copyfileobj(source, target, length=1024 * 1024)
        os.chmod(destination, 0o600)
JP_ARCHIVE_PY
if find -P "$JP_CANDIDATE" -xdev -mindepth 1 \
        \( -type l -o \( ! -type d ! -type f \) \) -print -quit | grep -q .; then
    log "  FAIL: staged Just-Perfection tree contains an unsafe inode"
    exit 1
fi
if [ ! -d "$JP_CANDIDATE/schemas" ] \
   || ! glib-compile-schemas --strict "$JP_CANDIDATE/schemas"; then
    log "  FAIL: Just-Perfection schema compilation failed"
    exit 1
fi
chown -R root:root "$JP_CANDIDATE"
find -P "$JP_CANDIDATE" -xdev -type d -exec chmod 0755 {} +
find -P "$JP_CANDIDATE" -xdev -type f -exec chmod 0644 {} +
restorecon -RF "$JP_CANDIDATE"
find -P "$JP_CANDIDATE" -xdev -type f -exec sync -- {} +
sync -- "$JP_CANDIDATE" "$JP_EXT_PARENT"

if [ -d "$JP_EXT_DIR" ]; then
    # Both trees are siblings. RENAME_EXCHANGE leaves either complete tree at
    # the public path across every interruption point.
    python3 -B - "$JP_EXT_DIR" "$JP_CANDIDATE" <<'JP_EXCHANGE_PY'
import ctypes
import os
import sys

old, new = map(os.fsencode, sys.argv[1:])
libc = ctypes.CDLL(None, use_errno=True)
renameat2 = libc.renameat2
renameat2.argtypes = [
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_uint,
]
renameat2.restype = ctypes.c_int
if renameat2(-100, old, -100, new, 2) != 0:  # AT_FDCWD, RENAME_EXCHANGE
    error = ctypes.get_errno()
    raise OSError(error, os.strerror(error))
JP_EXCHANGE_PY
    sync -- "$JP_EXT_DIR" "$JP_EXT_PARENT"
    rm -rf --one-file-system -- "$JP_CANDIDATE"
    JP_CANDIDATE=""
else
    mv -T -- "$JP_CANDIDATE" "$JP_EXT_DIR"
    JP_CANDIDATE=""
    sync -- "$JP_EXT_DIR" "$JP_EXT_PARENT"
fi
restorecon -RF "$JP_EXT_DIR"
if [ "$(stat -c '%U:%G:%a' "$JP_EXT_DIR/metadata.json" 2>/dev/null || true)" != \
        root:root:644 ] \
   || [ "$(stat -c '%U:%G:%a' "$JP_EXT_DIR/schemas/gschemas.compiled" \
        2>/dev/null || true)" != root:root:644 ] \
   || ! matchpathcon -V "$JP_EXT_DIR/metadata.json" >/dev/null 2>&1 \
   || ! matchpathcon -V "$JP_EXT_DIR/schemas/gschemas.compiled" \
        >/dev/null 2>&1; then
    log "  FAIL: published Just-Perfection metadata/schema contract differs"
    exit 1
fi
sync -- "$JP_EXT_DIR" "$JP_EXT_PARENT"
log "  Published $JP_UUID v$JP_VERSION atomically ($JP_ENTRY_COUNT archive entries)"

rm -rf --one-file-system -- "$JP_WORK"
JP_WORK=""
JP_TMPZIP=""
trap - EXIT HUP INT TERM
unset -f jp_cleanup

# dconf override (precedence 15 > 10 = overrides M17 enabled-extensions=[] baseline)
cat > "${DCONF_DB_DIR}/15-noid-events-hide" <<'EVENTS_HIDE_EOF'
# NoID Privacy — Hide Events-Section in GNOME Shell Date Menu
# Module 17 extension — Just-Perfection (events-section hide in clock-menu)
#
# Background: GNOME Shell Calendar Widget queries evolution-data-server
# for events. M17 unmasked evolution-source-registry + evolution-
# calendar-factory to stop cascade-fail log-spam (M12). However, with no
# calendar sources registered (NoID Privacy default = no GOA accounts, no local
# calendar, no CalDAV), widget displays "No events today" — visual clutter.
#
# Solution: Just-Perfection extension hides events-button section in
# clock menu (UI-only hide; backend D-Bus chain stays healthy, no log-spam).
#
# Native > Hacky: GNOME Shell Extensions are 1st-class GNOME API; Just-
# Perfection is hosted on gitlab.gnome.org/jrahmatzadeh/just-perfection
# (GNOME project infrastructure). GPL-3.0-only. A source audit of the exact pinned
# release found no network or telemetry sender; future-version claims require
# a fresh audit.
#
# File-precedence: 15 > 10 (overrides M17's enabled-extensions=@as [] baseline
# in 10-noid-gnome-privacy with 2-extension default: Just-Perfection +
# AppIndicator. AppIndicator UUID added alongside Just-Perfection
# for broader app tray-icon compatibility — RPM-installed via M26 and
# updated through user-initiated dnf/M25 flows. The shipped build has no
# intended network role; future package versions remain an audit target).
#
# support-notifier-type=0 disables the donation-reminder notification that
# Just-Perfection shows after each version-update (schema default = 1 =
# "New Releases"). Triggered by SupportNotifier.js after extension load
# when current version != last-showed-version. NOT locked: user can re-
# enable via dconf-editor / gnome-extensions-app preferences if they want
# to support the project (privacy-distro philosophy: NoID Privacy makes opt-out
# the default, opt-in stays user-driven).

[org/gnome/shell]
enabled-extensions=['just-perfection-desktop@just-perfection', 'appindicatorsupport@rgcjonas.gmail.com']

[org/gnome/shell/extensions/just-perfection]
events-button=false
support-notifier-type=0
EVENTS_HIDE_EOF
chmod 644 "${DCONF_DB_DIR}/15-noid-events-hide"
log "  Written ${DCONF_DB_DIR}/15-noid-events-hide (extension enable + events-button=false)"

# dconf lock for events-button only (user can enable other Just-Perfection features)
cat > "${DCONF_LOCKS_DIR}/15-noid-events-hide" <<'EVENTS_LOCK_EOF'
# NoID Privacy — Lock events-button visibility off
# Prevents per-user override via dconf-editor or gnome-extensions-app.
# User can still enable/disable other Just-Perfection features (only this
# specific key locked).
/org/gnome/shell/extensions/just-perfection/events-button
EVENTS_LOCK_EOF
chmod 644 "${DCONF_LOCKS_DIR}/15-noid-events-hide"
log "  Written ${DCONF_LOCKS_DIR}/15-noid-events-hide (events-button lock)"

# SELinux context restore for newly-created paths
if command -v restorecon >/dev/null 2>&1; then
    restorecon -RF "$JP_EXT_DIR"
    restorecon -F "${DCONF_DB_DIR}/15-noid-events-hide"
    restorecon -F "${DCONF_LOCKS_DIR}/15-noid-events-hide"
fi

#------------------------------------------------------------------------------
# Step 3: Write dconf locks file
#------------------------------------------------------------------------------
log "Step 3/8: Write $PRIVACY_LOCKS"
mkdir -p "$DCONF_LOCKS_DIR"
cat > "$PRIVACY_LOCKS" <<'DCONF_LOCKS_EOF'
# NoID Privacy Workstation 44 — Locks for security-critical GNOME keys (Module 17)
#
# User CANNOT re-enable these via GNOME Settings UI (shown grayed out).
# Reactivation: edit this file (remove lock) + dconf update. Root only.
#
# NOT locked (user-adjustable via Settings UI).

# Autorun — security critical (binary execution from untrusted media)
/org/gnome/desktop/media-handling/autorun-never

# Thumbnailer parser CVE protection
/org/gnome/desktop/thumbnailers/disable-all

# Remote Desktop server — never exposed
/org/gnome/desktop/remote-desktop/rdp/enable
/org/gnome/desktop/remote-desktop/vnc/enable

# Lockscreen privacy — no notification content leak
/org/gnome/desktop/notifications/show-in-lock-screen

# Extension installation lockdown — shell JS security boundary
/org/gnome/shell/allow-extension-installation

# Extension master-switch — locked on so GNOME's crash-recovery service
# (org.gnome.Shell-disable-extensions.service) cannot permanently disable the
# curated NoID Privacy extensions after a one-off gnome-shell crash. Individual
# extensions stay user-toggleable via enabled-extensions (not locked).
/org/gnome/shell/disable-user-extensions

# GNOME 49+ Foundation donation reminder — locked off (NoID Privacy workstation UX)
/org/gnome/settings-daemon/plugins/housekeeping/donation-reminder-enabled
DCONF_LOCKS_EOF
chmod 644 "$PRIVACY_LOCKS"
log "  Written $PRIVACY_LOCKS"

#------------------------------------------------------------------------------
# Step 3b: Transactional per-user first-login service
#------------------------------------------------------------------------------
# T1 fills an otherwise-empty GNOME region from /etc/locale.conf. T2 seeds the
# XDG Downloads folder's native Nautilus metadata to Name A-Z only when no user
# sort state exists. T3 creates or safely completes the native per-user
# libvirt qemu.conf so the hard inherited core limit does not break VM starts.
# T4/T5 apply only the two reviewed NoID Privacy user-unit contracts, start the
# units in the already-live first session and prove their
# postconditions. Each task receives its own versioned, fsync-backed atomic
# marker only after its exact postcondition; partial failure returns non-zero
# and retries only unfinished work while the graphical session remains active.
# Logout cancels a queued retry; the next login resumes unfinished work.
log "Step 3b/8: transactional user first-login (region + Downloads A-Z + libvirt session + 2 exact user units)"

mkdir -p /usr/lib/systemd/user
cat > /usr/lib/systemd/user/noid-user-firstrun.service <<'FIRSTRUN_SVC_EOF'
[Unit]
Description=NoID Privacy — Transactional per-user first-login setup
Documentation=file:///usr/share/doc/noid-privacy/17-gnome-hardening.md
PartOf=graphical-session.target
After=graphical-session.target
ConditionEnvironment=XDG_SESSION_CLASS=user
StartLimitIntervalSec=5min
StartLimitBurst=5

[Service]
Type=oneshot
ExecCondition=/usr/bin/systemctl --user --quiet is-active graphical-session.target
ExecStart=/usr/local/libexec/noid-user-firstrun
RemainAfterExit=no
Restart=on-failure
RestartSec=30s
TimeoutStartSec=2min
UMask=0077

[Install]
WantedBy=graphical-session.target
FIRSTRUN_SVC_EOF
chmod 0644 /usr/lib/systemd/user/noid-user-firstrun.service

mkdir -p /usr/local/libexec
cat > /usr/local/libexec/noid-user-firstrun <<'FIRSTRUN_SCRIPT_EOF'
#!/bin/bash
# noid-user-firstrun — transactional per-user setup
#
# Five closed tasks own independent, versioned markers. A task marker is
# published only after its effective postcondition. The complete marker is
# therefore a derived result, never a substitute for the task evidence.
set -uo pipefail

if [ "$#" -ne 0 ]; then
    printf '%s\n' \
        'noid-user-firstrun: ERROR: this internal helper accepts no arguments' >&2
    exit 2
fi

export LC_ALL=C

# GNOME Initial Setup can start a graphical target for a pseudo-user session.
# Exit successfully before deriving or touching any home path unless systemd's
# session class identifies a real logged-in user.
if [ "${XDG_SESSION_CLASS:-}" != user ]; then
    printf 'noid-user-firstrun: skipping non-user session class\n' >&2
    exit 0
fi

for required_command in \
    chmod flock gio gsettings mkdir mktemp mv readlink rm stat sync systemctl \
    xdg-user-dir; do
    command -v "$required_command" >/dev/null 2>&1 || {
        printf 'noid-user-firstrun: required command missing: %s\n' \
            "$required_command" >&2
        exit 1
    }
done

[[ "${HOME:-}" == /* && "$HOME" != / ]] || {
    printf 'noid-user-firstrun: HOME must be an absolute non-root path\n' >&2
    exit 1
}

CONFIG_HOME="${XDG_CONFIG_HOME:-${HOME}/.config}"
STATE_DIR="${CONFIG_HOME}/noid-user-firstrun"
LIBVIRT_CONFIG_DIR="${CONFIG_HOME}/libvirt"
LIBVIRT_QEMU_CONF="${LIBVIRT_CONFIG_DIR}/qemu.conf"
LEGACY_SENTINEL="${HOME}/.config/noid-user-firstrun.done"
LOCALE_CONF="${NOID_FIRSTRUN_LOCALE_CONF:-/etc/locale.conf}"
UPDATE_UNIT=noid-update-reminder.timer
NOTIFIER_UNIT=usbguard-notifier.service
NOTIFIER_WANTS=/usr/lib/systemd/user/graphical-session.target.wants/usbguard-notifier.service
NOTIFIER_TARGET=/usr/lib/systemd/user/usbguard-notifier.service
STATIC_OWNER=0:0
NAUTILUS_SORT_BY_ATTRIBUTE=metadata::nautilus-icon-view-sort-by
NAUTILUS_SORT_REVERSED_ATTRIBUTE=metadata::nautilus-icon-view-sort-reversed

fail() {
    printf 'noid-user-firstrun: %s\n' "$*" >&2
    return 1
}

[[ "$CONFIG_HOME" == /* && "$CONFIG_HOME" != / ]] || \
    { fail "configuration home must be an absolute non-root path"; exit 1; }
if [[ -e "$STATE_DIR" || -L "$STATE_DIR" ]]; then
    [[ -d "$STATE_DIR" && ! -L "$STATE_DIR" && -O "$STATE_DIR" ]] || \
        { fail "state path is not an owned real directory: $STATE_DIR"; exit 1; }
else
    if ! mkdir -p -- "$STATE_DIR"; then
        fail "cannot create state directory: $STATE_DIR"
        exit 1
    fi
fi
chmod 0700 -- "$STATE_DIR" || { fail "cannot protect state directory"; exit 1; }
[[ $(stat -c '%u:%a' "$STATE_DIR" 2>/dev/null) == "$EUID:700" ]] || \
    { fail "state directory metadata differs after protection"; exit 1; }

# systemd serializes the unit, but the user may also invoke the helper
# manually. Lock the owned state directory itself before cleanup or task work.
exec {state_lock_fd}<"$STATE_DIR" || { fail "cannot open state directory lock"; exit 1; }
flock -x "$state_lock_fd" || { fail "cannot lock first-login state"; exit 1; }

# Clean only exact, regular, owned temporary files from a killed prior run.
shopt -s nullglob
for stale_tmp in "$STATE_DIR"/.noid-firstrun.*; do
    if [[ -f "$stale_tmp" && ! -L "$stale_tmp" && -O "$stale_tmp" ]]; then
        rm -f -- "$stale_tmp" || { fail "cannot remove stale state temporary"; exit 1; }
    fi
done
unset stale_tmp

marker_path() {
    printf '%s/%s-v2.done\n' "$STATE_DIR" "$1"
}

marker_valid() {
    local task=$1 marker expected expected_size actual
    marker=$(marker_path "$task")
    expected=$(printf 'version=2\nstatus=complete\ntask=%s' "$task")
    expected_size=$((${#expected} + 1))
    [[ -f "$marker" && ! -L "$marker" \
       && $(stat -c '%u:%a:%h:%s' "$marker" 2>/dev/null) == \
            "$EUID:600:1:$expected_size" ]] || return 1
    actual=$(<"$marker") || return 1
    [[ "$actual" == "$expected" ]]
}

mark_done() {
    local task=$1 marker tmp
    marker=$(marker_path "$task")
    if ! tmp=$(mktemp --tmpdir="$STATE_DIR" .noid-firstrun.XXXXXX); then
        fail "cannot allocate state temporary for $task"
        return 1
    fi
    if ! printf 'version=2\nstatus=complete\ntask=%s\n' "$task" > "$tmp" \
       || ! chmod 0600 "$tmp" \
       || ! sync -- "$tmp" \
       || ! mv -fT -- "$tmp" "$marker" \
       || ! sync -- "$STATE_DIR"; then
        rm -f -- "$tmp"
        fail "cannot durably publish state for $task"
        return 1
    fi
}

# `complete` is derived evidence, so it must not survive while any required
# task marker is absent or invalid. Invalidate it durably before attempting
# repairs; a failed repair can then never leave false global completion.
for required_task in region nautilus_download_sort libvirt_qemu_core noid_update_reminder usbguard_notifier; do
    if ! marker_valid "$required_task"; then
        complete_marker=$(marker_path complete)
        if [[ -e "$complete_marker" || -L "$complete_marker" ]]; then
            [[ ! -d "$complete_marker" || -L "$complete_marker" ]] || {
                fail "complete marker is an unexpected directory"
                exit 1
            }
            rm -f -- "$complete_marker" || {
                fail "cannot invalidate stale complete marker"
                exit 1
            }
            sync -- "$STATE_DIR" || {
                fail "cannot durably invalidate stale complete marker"
                exit 1
            }
        fi
        break
    fi
done
unset complete_marker required_task

read_region() {
    local raw
    if ! raw=$(gsettings get org.gnome.system.locale region 2>/dev/null); then
        fail "cannot read GNOME region"
        return 1
    fi
    [[ "$raw" == \'*\' && "$raw" == *\' ]] || {
        fail "GNOME region is not a string GVariant"
        return 1
    }
    REGION_VALUE=${raw:1:${#raw}-2}
    [[ -z "$REGION_VALUE" || "$REGION_VALUE" =~ ^[A-Za-z0-9_.@-]+$ ]] || {
        fail "GNOME region contains unsupported characters"
        return 1
    }
}

read_system_lang() {
    local raw line value="" count=0
    [[ -r "$LOCALE_CONF" && -f "$LOCALE_CONF" && ! -L "$LOCALE_CONF" ]] || {
        fail "locale configuration is not a readable regular file: $LOCALE_CONF"
        return 1
    }
    while IFS= read -r raw || [[ -n "$raw" ]]; do
        line=${raw%$'\r'}
        if [[ "$line" =~ ^[[:space:]]*LANG[[:space:]]*=(.*)$ ]]; then
            count=$((count + 1))
            value=${BASH_REMATCH[1]}
        fi
    done < "$LOCALE_CONF"
    [[ "$count" -eq 1 ]] || { fail "locale configuration must contain one LANG assignment"; return 1; }
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    if [[ "$value" == \"*\" && "$value" == *\" ]] \
       || [[ "$value" == \'*\' && "$value" == *\' ]]; then
        value=${value:1:${#value}-2}
    fi
    [[ "$value" =~ ^[A-Za-z0-9_.@-]+$ ]] || {
        fail "LANG has an unsupported or empty value"
        return 1
    }
    SYSTEM_LANG=$value
}

sync_region() {
    command -v gsettings >/dev/null 2>&1 || { fail "gsettings is unavailable"; return 1; }
    read_region || return 1
    # A non-empty current value is user-owned; never overwrite it.
    if [[ -n "$REGION_VALUE" ]]; then
        return 0
    fi
    read_system_lang || return 1
    if ! gsettings set org.gnome.system.locale region "$SYSTEM_LANG" 2>/dev/null; then
        fail "cannot set GNOME region"
        return 1
    fi
    read_region || return 1
    [[ "$REGION_VALUE" == "$SYSTEM_LANG" ]] || {
        fail "GNOME region postcondition differs from LANG"
        return 1
    }
}

resolve_download_dir() {
    local raw canonical home_canonical
    if ! raw=$(xdg-user-dir DOWNLOAD 2>/dev/null); then
        fail "cannot resolve the XDG Downloads directory"
        return 1
    fi
    [[ "$raw" == /* && "$raw" != / \
       && "$raw" != *$'\n'* && "$raw" != *$'\r'* ]] || {
        fail "XDG Downloads must resolve to one absolute non-root path"
        return 1
    }
    [[ -d "$raw" ]] || {
        fail "XDG Downloads directory does not exist"
        return 1
    }
    canonical=$(readlink -f -- "$raw" 2>/dev/null) || {
        fail "cannot canonicalize the XDG Downloads directory"
        return 1
    }
    home_canonical=$(readlink -f -- "$HOME" 2>/dev/null) || {
        fail "cannot canonicalize HOME"
        return 1
    }
    [[ "$canonical" == /* && "$canonical" != / ]] || {
        fail "canonical XDG Downloads path is unsafe"
        return 1
    }
    # xdg-user-dirs returns HOME when a special directory is disabled. In that
    # case there is no distinct Downloads view to initialize.
    if [[ "$canonical" == "$home_canonical" ]]; then
        DOWNLOAD_DIR=
        return 0
    fi
    DOWNLOAD_DIR=$canonical
}

read_nautilus_download_sort_metadata() {
    local output line sort_by_prefix reversed_prefix
    local sort_by_count=0 reversed_count=0
    if ! output=$(gio info \
            --attributes="$NAUTILUS_SORT_BY_ATTRIBUTE,$NAUTILUS_SORT_REVERSED_ATTRIBUTE" \
            "$DOWNLOAD_DIR" 2>/dev/null); then
        fail "cannot read Nautilus Downloads sort metadata"
        return 1
    fi
    NAUTILUS_SORT_BY_PRESENT=0
    NAUTILUS_SORT_REVERSED_PRESENT=0
    NAUTILUS_SORT_BY_VALUE=
    NAUTILUS_SORT_REVERSED_VALUE=
    sort_by_prefix="  $NAUTILUS_SORT_BY_ATTRIBUTE: "
    reversed_prefix="  $NAUTILUS_SORT_REVERSED_ATTRIBUTE: "
    while IFS= read -r line; do
        if [[ "$line" == "$sort_by_prefix"* ]]; then
            sort_by_count=$((sort_by_count + 1))
            NAUTILUS_SORT_BY_PRESENT=1
            NAUTILUS_SORT_BY_VALUE=${line#"$sort_by_prefix"}
        elif [[ "$line" == "$reversed_prefix"* ]]; then
            reversed_count=$((reversed_count + 1))
            NAUTILUS_SORT_REVERSED_PRESENT=1
            NAUTILUS_SORT_REVERSED_VALUE=${line#"$reversed_prefix"}
        fi
    done <<< "$output"
    [[ "$sort_by_count" -le 1 && "$reversed_count" -le 1 ]] || {
        fail "Nautilus Downloads sort metadata is ambiguous"
        return 1
    }
}

sync_nautilus_download_sort() {
    resolve_download_dir || return 1
    [[ -n "$DOWNLOAD_DIR" ]] || return 0
    read_nautilus_download_sort_metadata || return 1

    if [[ "$NAUTILUS_SORT_BY_PRESENT" -eq 0 \
       && "$NAUTILUS_SORT_REVERSED_PRESENT" -eq 0 ]]; then
        gio set -t string "$DOWNLOAD_DIR" \
            "$NAUTILUS_SORT_BY_ATTRIBUTE" name >/dev/null 2>&1 || {
            fail "cannot initialize Nautilus Downloads name sorting"
            return 1
        }
        gio set -t string "$DOWNLOAD_DIR" \
            "$NAUTILUS_SORT_REVERSED_ATTRIBUTE" false >/dev/null 2>&1 || {
            fail "cannot initialize Nautilus Downloads ascending sorting"
            return 1
        }
    elif [[ "$NAUTILUS_SORT_BY_PRESENT" -eq 1 \
         && "$NAUTILUS_SORT_BY_VALUE" == name \
         && "$NAUTILUS_SORT_REVERSED_PRESENT" -eq 0 ]]; then
        # Recover the exact prefix left if the first of the two native metadata
        # writes completed before an interruption. Every other pre-existing
        # state is user-owned and remains untouched.
        gio set -t string "$DOWNLOAD_DIR" \
            "$NAUTILUS_SORT_REVERSED_ATTRIBUTE" false >/dev/null 2>&1 || {
            fail "cannot complete Nautilus Downloads ascending sorting"
            return 1
        }
    else
        return 0
    fi

    read_nautilus_download_sort_metadata || return 1
    [[ "$NAUTILUS_SORT_BY_PRESENT" -eq 1 \
       && "$NAUTILUS_SORT_BY_VALUE" == name \
       && "$NAUTILUS_SORT_REVERSED_PRESENT" -eq 1 \
       && "$NAUTILUS_SORT_REVERSED_VALUE" == false ]] || {
        fail "Nautilus Downloads A-Z postcondition differs"
        return 1
    }
}

read_libvirt_qemu_core() {
    local line assignment_re max_zero_re dump_zero_re size
    assignment_re='^[[:space:]]*(max_core|dump_guest_core)[[:space:]]*='
    max_zero_re='^[[:space:]]*max_core[[:space:]]*=[[:space:]]*0[[:space:]]*(#.*)?$'
    dump_zero_re='^[[:space:]]*dump_guest_core[[:space:]]*=[[:space:]]*0[[:space:]]*(#.*)?$'
    LIBVIRT_MAX_COUNT=0
    LIBVIRT_DUMP_COUNT=0
    LIBVIRT_MAX_OK=0
    LIBVIRT_DUMP_OK=0

    [[ -f "$LIBVIRT_QEMU_CONF" && ! -L "$LIBVIRT_QEMU_CONF" \
       && -O "$LIBVIRT_QEMU_CONF" ]] || {
        fail "libvirt qemu configuration is not an owned regular file: $LIBVIRT_QEMU_CONF"
        return 1
    }
    [[ $(stat -c '%u:%h' "$LIBVIRT_QEMU_CONF" 2>/dev/null) == "$EUID:1" ]] || {
        fail "libvirt qemu configuration owner or link count differs"
        return 1
    }
    size=$(stat -c '%s' "$LIBVIRT_QEMU_CONF" 2>/dev/null) || {
        fail "cannot measure libvirt qemu configuration"
        return 1
    }
    [[ "$size" -le 1048576 ]] || {
        fail "libvirt qemu configuration exceeds the 1 MiB safety bound"
        return 1
    }

    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ "$line" =~ $assignment_re ]] || continue
        case ${BASH_REMATCH[1]} in
            max_core)
                LIBVIRT_MAX_COUNT=$((LIBVIRT_MAX_COUNT + 1))
                [[ "$line" =~ $max_zero_re ]] && LIBVIRT_MAX_OK=1
                ;;
            dump_guest_core)
                LIBVIRT_DUMP_COUNT=$((LIBVIRT_DUMP_COUNT + 1))
                [[ "$line" =~ $dump_zero_re ]] && LIBVIRT_DUMP_OK=1
                ;;
        esac
    done < "$LIBVIRT_QEMU_CONF"

    [[ "$LIBVIRT_MAX_COUNT" -le 1 && "$LIBVIRT_DUMP_COUNT" -le 1 ]] || {
        fail "libvirt qemu configuration contains duplicate active core settings"
        return 1
    }
    [[ "$LIBVIRT_MAX_COUNT" -eq 0 || "$LIBVIRT_MAX_OK" -eq 1 ]] || {
        fail "existing max_core setting is user-owned and not zero"
        return 1
    }
    [[ "$LIBVIRT_DUMP_COUNT" -eq 0 || "$LIBVIRT_DUMP_OK" -eq 1 ]] || {
        fail "existing dump_guest_core setting is user-owned and not zero"
        return 1
    }
}

sync_libvirt_qemu_core() {
    local tmp fingerprint_before fingerprint_after line existed=0
    LIBVIRT_MAX_COUNT=0
    LIBVIRT_DUMP_COUNT=0
    LIBVIRT_MAX_OK=0
    LIBVIRT_DUMP_OK=0

    if [[ -e "$LIBVIRT_CONFIG_DIR" || -L "$LIBVIRT_CONFIG_DIR" ]]; then
        [[ -d "$LIBVIRT_CONFIG_DIR" && ! -L "$LIBVIRT_CONFIG_DIR" \
           && -O "$LIBVIRT_CONFIG_DIR" ]] || {
            fail "libvirt configuration path is not an owned real directory"
            return 1
        }
    else
        mkdir -m 0700 -- "$LIBVIRT_CONFIG_DIR" || {
            fail "cannot create libvirt configuration directory"
            return 1
        }
    fi
    chmod 0700 -- "$LIBVIRT_CONFIG_DIR" || {
        fail "cannot protect libvirt configuration directory"
        return 1
    }
    [[ $(stat -c '%u:%a' "$LIBVIRT_CONFIG_DIR" 2>/dev/null) == "$EUID:700" ]] || {
        fail "libvirt configuration directory metadata differs"
        return 1
    }

    if [[ -e "$LIBVIRT_QEMU_CONF" || -L "$LIBVIRT_QEMU_CONF" ]]; then
        existed=1
        read_libvirt_qemu_core || return 1
        chmod 0600 -- "$LIBVIRT_QEMU_CONF" || {
            fail "cannot protect libvirt qemu configuration"
            return 1
        }
        if [[ "$LIBVIRT_MAX_COUNT" -eq 1 && "$LIBVIRT_DUMP_COUNT" -eq 1 ]]; then
            [[ $(stat -c '%u:%a:%h' "$LIBVIRT_QEMU_CONF" 2>/dev/null) == "$EUID:600:1" ]] || {
                fail "libvirt qemu configuration metadata differs"
                return 1
            }
            return 0
        fi
        fingerprint_before=$(stat -Lc '%d:%i:%s:%Y:%Z' "$LIBVIRT_QEMU_CONF" 2>/dev/null) || {
            fail "cannot fingerprint libvirt qemu configuration"
            return 1
        }
    fi

    tmp=$(mktemp --tmpdir="$LIBVIRT_CONFIG_DIR" .noid-qemu.conf.XXXXXX) || {
        fail "cannot allocate libvirt qemu configuration temporary"
        return 1
    }
    chmod 0600 -- "$tmp" || {
        rm -f -- "$tmp"
        fail "cannot protect libvirt qemu configuration temporary"
        return 1
    }

    if [[ "$existed" -eq 1 ]]; then
        if ! while IFS= read -r line || [[ -n "$line" ]]; do
            printf '%s\n' "$line"
        done < "$LIBVIRT_QEMU_CONF" > "$tmp"; then
            rm -f -- "$tmp"
            fail "cannot copy existing libvirt qemu configuration"
            return 1
        fi
        printf '\n' >> "$tmp" || {
            rm -f -- "$tmp"
            fail "cannot extend libvirt qemu configuration"
            return 1
        }
    else
        printf '%s\n' \
            '# NoID Privacy — libvirt qemu:///session core-dump boundary' \
            '# max_core=0 prevents libvirt from raising the inherited hard limit.' \
            '# dump_guest_core=0 documents the intended default; max_core is the boundary.' \
            > "$tmp" || {
            rm -f -- "$tmp"
            fail "cannot initialize libvirt qemu configuration"
            return 1
        }
    fi
    if [[ "$LIBVIRT_MAX_COUNT" -eq 0 ]] \
       && ! printf 'max_core = 0\n' >> "$tmp"; then
        rm -f -- "$tmp"
        fail "cannot append max_core setting"
        return 1
    fi
    if [[ "$LIBVIRT_DUMP_COUNT" -eq 0 ]] \
       && ! printf 'dump_guest_core = 0\n' >> "$tmp"; then
        rm -f -- "$tmp"
        fail "cannot append dump_guest_core setting"
        return 1
    fi
    sync -- "$tmp" || {
        rm -f -- "$tmp"
        fail "cannot durably stage libvirt qemu configuration"
        return 1
    }

    if [[ "$existed" -eq 1 ]]; then
        fingerprint_after=$(stat -Lc '%d:%i:%s:%Y:%Z' "$LIBVIRT_QEMU_CONF" 2>/dev/null) || {
            rm -f -- "$tmp"
            fail "libvirt qemu configuration vanished during update"
            return 1
        }
        [[ "$fingerprint_after" == "$fingerprint_before" ]] || {
            rm -f -- "$tmp"
            fail "libvirt qemu configuration changed concurrently"
            return 1
        }
        mv -fT -- "$tmp" "$LIBVIRT_QEMU_CONF" || {
            rm -f -- "$tmp"
            fail "cannot atomically publish libvirt qemu configuration"
            return 1
        }
    else
        if ! mv -T --update=none-fail -- "$tmp" "$LIBVIRT_QEMU_CONF"; then
            rm -f -- "$tmp"
            fail "libvirt qemu configuration appeared concurrently"
            return 1
        fi
    fi
    sync -- "$LIBVIRT_CONFIG_DIR" || {
        fail "cannot durably publish libvirt qemu configuration"
        return 1
    }
    read_libvirt_qemu_core || return 1
    [[ "$LIBVIRT_MAX_COUNT" -eq 1 && "$LIBVIRT_MAX_OK" -eq 1 \
       && "$LIBVIRT_DUMP_COUNT" -eq 1 && "$LIBVIRT_DUMP_OK" -eq 1 \
       && $(stat -c '%u:%a:%h' "$LIBVIRT_QEMU_CONF" 2>/dev/null) == "$EUID:600:1" ]] || {
        fail "libvirt qemu configuration postcondition differs"
        return 1
    }
}

activate_update_unit() {
    command -v systemctl >/dev/null 2>&1 || { fail "systemctl is unavailable"; return 1; }
    systemctl --user daemon-reload >/dev/null 2>&1 || {
        fail "user-manager daemon-reload failed for $UPDATE_UNIT"
        return 1
    }
    systemctl --user preset "$UPDATE_UNIT" >/dev/null 2>&1 || {
        fail "user preset failed for $UPDATE_UNIT"
        return 1
    }
    systemctl --user is-enabled --quiet "$UPDATE_UNIT" >/dev/null 2>&1 || {
        fail "unit is not enabled after preset: $UPDATE_UNIT"
        return 1
    }
    systemctl --user start "$UPDATE_UNIT" >/dev/null 2>&1 || {
        fail "first-session start failed for $UPDATE_UNIT"
        return 1
    }
    systemctl --user is-active --quiet "$UPDATE_UNIT" >/dev/null 2>&1 || {
        fail "unit is not active after start: $UPDATE_UNIT"
        return 1
    }
}

activate_static_notifier() {
    command -v readlink >/dev/null 2>&1 || { fail "readlink is unavailable"; return 1; }
    command -v stat >/dev/null 2>&1 || { fail "stat is unavailable"; return 1; }
    command -v systemctl >/dev/null 2>&1 || { fail "systemctl is unavailable"; return 1; }
    [[ -L "$NOTIFIER_WANTS" ]] || {
        fail "static notifier wants link is absent or not a symbolic link"
        return 1
    }
    [[ $(stat -c '%u:%g' "$NOTIFIER_WANTS" 2>/dev/null) == "$STATIC_OWNER" ]] || {
        fail "static notifier wants link is not root-owned"
        return 1
    }
    [[ $(readlink -- "$NOTIFIER_WANTS" 2>/dev/null) == "$NOTIFIER_TARGET" ]] || {
        fail "static notifier wants link target differs"
        return 1
    }
    [[ -f "$NOTIFIER_TARGET" && ! -L "$NOTIFIER_TARGET" ]] || {
        fail "static notifier unit target is not a regular non-symlink file"
        return 1
    }
    [[ $(stat -c '%u:%g:%a' "$NOTIFIER_TARGET" 2>/dev/null) == "$STATIC_OWNER:644" ]] || {
        fail "static notifier unit target metadata differs"
        return 1
    }
    systemctl --user daemon-reload >/dev/null 2>&1 || {
        fail "user-manager daemon-reload failed for $NOTIFIER_UNIT"
        return 1
    }
    systemctl --user start "$NOTIFIER_UNIT" >/dev/null 2>&1 || {
        fail "first-session start failed for $NOTIFIER_UNIT"
        return 1
    }
    systemctl --user is-active --quiet "$NOTIFIER_UNIT" >/dev/null 2>&1 || {
        fail "unit is not active after start: $NOTIFIER_UNIT"
        return 1
    }
}

failures=0
if ! marker_valid region; then
    if sync_region && mark_done region; then
        :
    else
        failures=$((failures + 1))
    fi
fi

if ! marker_valid nautilus_download_sort; then
    if sync_nautilus_download_sort && mark_done nautilus_download_sort; then
        :
    else
        failures=$((failures + 1))
    fi
fi

if ! marker_valid libvirt_qemu_core; then
    if sync_libvirt_qemu_core && mark_done libvirt_qemu_core; then
        :
    else
        failures=$((failures + 1))
    fi
fi

if ! marker_valid noid_update_reminder; then
    if activate_update_unit && mark_done noid_update_reminder; then
        :
    else
        failures=$((failures + 1))
    fi
fi

if ! marker_valid usbguard_notifier; then
    if activate_static_notifier && mark_done usbguard_notifier; then
        :
    else
        failures=$((failures + 1))
    fi
fi

if [[ "$failures" -ne 0 ]]; then
    fail "$failures task(s) incomplete; successful tasks retained for retry"
    exit 1
fi

for required_task in region nautilus_download_sort libvirt_qemu_core noid_update_reminder usbguard_notifier; do
    marker_valid "$required_task" || { fail "required task marker missing: $required_task"; exit 1; }
done
marker_valid complete || mark_done complete || exit 1

# An empty v1 sentinel could hide failures forever. Retire it only after the
# complete v2 transaction has been durably published.
if [[ -e "$LEGACY_SENTINEL" || -L "$LEGACY_SENTINEL" ]]; then
    [[ -f "$LEGACY_SENTINEL" && ! -L "$LEGACY_SENTINEL" && -O "$LEGACY_SENTINEL" ]] || {
        fail "legacy sentinel is not an owned regular file"
        exit 1
    }
    rm -f -- "$LEGACY_SENTINEL" || { fail "cannot retire legacy sentinel"; exit 1; }
fi
exit 0
FIRSTRUN_SCRIPT_EOF
chmod 0755 /usr/local/libexec/noid-user-firstrun

# Enable for all future users via systemd's auto-discovery — drop-in symlink
# in /usr/lib/systemd/user/graphical-session.target.wants/ so every user's
# graphical-session.target activation includes our firstrun service. No
# per-user `systemctl --user enable` is needed thanks to this approach.
mkdir -p /usr/lib/systemd/user/graphical-session.target.wants
ln -sf /usr/lib/systemd/user/noid-user-firstrun.service \
    /usr/lib/systemd/user/graphical-session.target.wants/noid-user-firstrun.service

log "  [OK] noid-user-firstrun.service deployed (5 transactional tasks)"

#------------------------------------------------------------------------------
# Step 3c: Persistent WirePlumber microphone policy
#------------------------------------------------------------------------------
# The dconf default disable-microphone=true gates only the GNOME app-permission
# layer (sandboxed-app portal). It does NOT mute the PipeWire capture sources, so
# the raw mic would otherwise remain live. A required WirePlumber 0.5 Lua
# component owns the actual capture-source policy. Its default is disabled=true;
# `wpctl settings --save` persists an explicit user choice in WirePlumber state.
# New sources are handled at object discovery, setting transitions reconcile all
# current sources, and a one-second in-process integrity fallback closes
# node/route-specific event gaps without spawning a watcher process. The CLI
# changes both GNOME and WirePlumber layers transactionally and fails back to
# disabled.
# Mic only — camera has no capture-source-mute / LED equivalent.
log "Step 3c/8: persistent WirePlumber microphone policy"

mkdir -p /etc/wireplumber/wireplumber.conf.d
mkdir -p /usr/local/share/wireplumber/scripts
mkdir -p /usr/local/bin

# Retire the v1 one-shot. It could miss late/new nodes and swallowed all mute
# failures; leaving its unit behind would create two competing policy owners.
rm -f /usr/local/libexec/noid-mic-privacy-enforce
rm -f /usr/lib/systemd/user/noid-mic-privacy-enforce.service
rm -f /usr/lib/systemd/user/graphical-session.target.wants/noid-mic-privacy-enforce.service

cat > /etc/wireplumber/wireplumber.conf.d/90-noid-microphone-privacy.conf <<'NOID_MIC_WP_CONF_EOF'
# NoID Privacy — persistent microphone capture-source enforcement
#
# The GNOME disable-microphone key is a separate application-permission layer.
# This WirePlumber policy owns actual PipeWire Audio/Source mute enforcement.

wireplumber.settings.schema = {
  noid.microphone.disabled = {
    name = "NoID Privacy microphone disabled"
    description = "Persistently mute every current and future audio capture source"
    type = "bool"
    default = true
  }
}

wireplumber.components = [
  {
    name = noid-microphone-privacy.lua
    type = script/lua
    provides = noid.microphone.privacy
    requires = [ support.settings, support.standard-event-source, api.mixer ]
  }
]

wireplumber.profiles = {
  main = {
    noid.microphone.privacy = required
  }
}
NOID_MIC_WP_CONF_EOF

cat > /usr/local/share/wireplumber/scripts/noid-microphone-privacy.lua <<'NOID_MIC_WP_LUA_EOF'
-- NoID Privacy — persistent WirePlumber microphone policy
--
-- When noid.microphone.disabled is true, mute every existing or newly-created
-- Audio/Source node and immediately reverse later unmute attempts. When the
-- setting changes to false, unmute the sources that currently exist once; later
-- user or hardware mute choices remain untouched.

local log = Log.open_topic ("noid-microphone")

local SETTING = "noid.microphone.disabled"
local ENFORCEMENT_INTERVAL_MSEC = 1000
local ENFORCEMENT_COALESCE_MSEC = 50
local pending_enforcement = {}
local mixer = Plugin.find ("mixer-api")

if not mixer then
  error ("required mixer-api is unavailable")
end

local sources = ObjectManager {
  Interest {
    type = "node",
    Constraint { "media.class", "matches", "Audio/Source*", type = "pw-global" },
  }
}

local function current_mute (node)
  local node_id = node["bound-id"]
  if not node_id then
    return nil
  end

  local volume = mixer:call ("get-volume", node_id)
  if volume and volume.mute ~= nil then
    return volume.mute
  end
  return nil
end

local function set_mute (node, desired, force, reason)
  local node_id = node["bound-id"]
  if not node_id then
    return false
  end

  local current = current_mute (node)
  if current == desired and not force then
    return true
  end

  -- Component dependencies guarantee that mixer-api is loaded before this
  -- script, but its object manager learns about a newly-bound node
  -- asynchronously. Defer until its effective route state is readable; the
  -- mixer changed signal and bounded fallback both retry the reconciliation.
  if current == nil then
    log:debug (node, string.format (
      "mixer state not readable yet; deferred mute=%s (%s)",
      tostring (desired), reason))
    return false
  end

  local success = mixer:call ("set-volume", node_id, { mute = desired })
  if success then
    log:info (node, string.format ("set mute=%s (%s)", tostring (desired), reason))
    return true
  end

  log:warning (node, string.format (
    "failed to set mute=%s through mixer-api (%s)", tostring (desired), reason))
  return false
end

local function apply_to_all (desired, force, reason)
  for node in sources:iterate () do
    set_mute (node, desired, force, reason)
  end
end

local function schedule_enforcement (node, reason)
  local node_id = node["bound-id"]
  if not node_id or pending_enforcement[node_id] then
    return
  end

  pending_enforcement[node_id] = Core.timeout_add (
    ENFORCEMENT_COALESCE_MSEC, function ()
      pending_enforcement[node_id] = nil
      if (node:get_active_features () & Feature.Proxy.BOUND) ~= 0 and
          Settings.get_boolean (SETTING) then
        set_mute (node, true, false, reason)
      end
    end)
end

sources:connect ("object-added", function (_, node)
  if Settings.get_boolean (SETTING) then
    if not set_mute (node, true, true,
        "capture source added while privacy policy is active") then
      schedule_enforcement (node,
        "capture source became mixer-ready while privacy policy is active")
    end
  end
end)

local enforce_unmute_hook = SimpleEventHook {
  name = "noid/microphone-privacy-enforce",
  interests = {
    EventInterest {
      Constraint { "event.type", "=", "node-params-changed" },
      Constraint { "media.class", "matches", "Audio/Source*" },
    },
  },
  execute = function (event)
    if Settings.get_boolean (SETTING) then
      schedule_enforcement (event:get_subject (),
        "node parameter changed while privacy policy is active")
    end
  end,
}

-- mixer-api tracks the effective device Route for ACP/UCM-backed ALSA nodes.
-- Hardware mute keys and panel controls change this state without necessarily
-- changing the node Props parameter observed by the standard event source.
mixer:connect ("changed", function (_, changed_id)
  if not Settings.get_boolean (SETTING) then
    return
  end
  for node in sources:iterate () do
    if node["bound-id"] == changed_id then
      schedule_enforcement (node,
        "mixer route changed while privacy policy is active")
      return
    end
  end
end)

Settings.subscribe (SETTING, function ()
  local disabled = Settings.get_boolean (SETTING)
  apply_to_all (disabled, true, "privacy setting changed")
end)

enforce_unmute_hook:register ()
sources:activate ()

-- Covers sources already known if component activation occurs after discovery;
-- object-added covers the normal asynchronous discovery path. Force the native
-- mixer write once so a restored software mute also reconciles the UCM route,
-- its ALSA capture control and any kernel-managed microphone-mute LED.
if Settings.get_boolean (SETTING) then
  apply_to_all (true, true, "privacy component initialized")
end

-- Event signals are authoritative. This low-frequency integrity fallback reads
-- mixer-api's effective state and writes only when a source actually drifted.
Core.timeout_add (ENFORCEMENT_INTERVAL_MSEC, function ()
  if Settings.get_boolean (SETTING) then
    apply_to_all (true, false, "periodic privacy integrity check")
  end
  return true
end)
NOID_MIC_WP_LUA_EOF

cat > /usr/local/bin/noid-toggle-microphone <<'NOID_MIC_TOGGLE_EOF'
#!/bin/bash
# noid-toggle-microphone — transactional two-layer microphone privacy control
set -Eeuo pipefail
export LC_ALL=C.UTF-8
export PATH=/usr/bin

# shellcheck source=/dev/null
[ ! -r /usr/local/lib/noid-privacy/agent-install-format.sh ] || \
    NOID_FMT_AUTO_TITLE="NoID Privacy — Microphone" \
    NOID_FMT_AUTO_SUBTITLE="GNOME and WirePlumber policy" \
    . /usr/local/lib/noid-privacy/agent-install-format.sh

readonly GNOME_SCHEMA="org.gnome.desktop.privacy"
readonly GNOME_KEY="disable-microphone"
readonly WP_KEY="noid.microphone.disabled"

WP_ACTIVE=""
WP_SAVED=""
SOURCE_IDS=()
SOURCE_STATE="unavailable"

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'USAGE_EOF'
Usage: noid-toggle-microphone on|off|status

  on      Allow GNOME application access and unmute current capture sources.
  off     Block GNOME application access and persistently enforce source mute.
  status  Show both policy layers and the current PipeWire source state.
USAGE_EOF
}

gnome_get() {
    local value
    value=$(gsettings get "$GNOME_SCHEMA" "$GNOME_KEY" 2>/dev/null) || return 1
    case "$value" in
        true|false) printf '%s\n' "$value" ;;
        *) return 1 ;;
    esac
}

gnome_set() {
    local value=$1
    local _ current
    gsettings set "$GNOME_SCHEMA" "$GNOME_KEY" "$value" >/dev/null || return 1
    # dconf commits asynchronously; a successful setter can briefly be followed
    # by the previous value in a separate gsettings process.
    for _ in {1..30}; do
        current=$(gnome_get) || current=""
        [[ $current == "$value" ]] && return 0
        sleep 0.1
    done
    return 1
}

wp_get() {
    local output
    output=$(wpctl settings "$WP_KEY" 2>/dev/null) || return 1
    output=${output//$'\r'/}
    if [[ $output =~ ^Value:[[:space:]]+(true|false)([[:space:]]+\(Saved:[[:space:]]+(true|false)\))?$ ]]; then
        WP_ACTIVE=${BASH_REMATCH[1]}
        WP_SAVED=${BASH_REMATCH[3]:-}
        return 0
    fi
    return 1
}

wp_set_saved() {
    local value=$1
    local _ state_home state_file
    state_home=${XDG_STATE_HOME:-"$HOME/.local/state"}
    [[ $state_home == /* ]] || state_home="$HOME/.local/state"
    state_file="$state_home/wireplumber/sm-settings"
    wpctl settings --save "$WP_KEY" "$value" >/dev/null 2>&1 || return 1
    # WirePlumber first updates metadata, then flushes persistent state
    # asynchronously. Require both postconditions before reporting success.
    for _ in {1..40}; do
        if wp_get && [[ $WP_ACTIVE == "$value" && $WP_SAVED == "$value" ]] &&
           [[ -f $state_file && ! -L $state_file ]] &&
           grep -qxF "$WP_KEY=$value" "$state_file"; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

load_source_ids() {
    local output
    output=$(python3 - <<'PY_EOF'
import json
import subprocess
import sys

try:
    proc = subprocess.run(
        ["pw-dump"], check=True, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, text=True, timeout=5,
    )
    objects = json.loads(proc.stdout)
except (OSError, subprocess.SubprocessError, UnicodeError, json.JSONDecodeError):
    raise SystemExit(1)

ids = set()
for obj in objects:
    if obj.get("type") != "PipeWire:Interface:Node":
        continue
    props = obj.get("info", {}).get("props", {})
    media_class = props.get("media.class")
    if media_class == "Audio/Source" or (
            isinstance(media_class, str) and media_class.startswith("Audio/Source/")):
        node_id = obj.get("id")
        if isinstance(node_id, int) and node_id >= 0:
            ids.add(node_id)

for node_id in sorted(ids):
    print(node_id)
PY_EOF
    ) || return 1

    SOURCE_IDS=()
    if [[ -n $output ]]; then
        mapfile -t SOURCE_IDS <<<"$output"
    fi
}

set_sources_mute() {
    local desired=$1
    local node_id
    load_source_ids || return 1
    for node_id in "${SOURCE_IDS[@]}"; do
        wpctl set-mute "$node_id" "$desired" >/dev/null 2>&1 || return 1
    done
}

source_state() {
    local node_id output mute_state
    local muted=0
    local unmuted=0
    SOURCE_STATE="unavailable"
    load_source_ids || return 1
    if ((${#SOURCE_IDS[@]} == 0)); then
        SOURCE_STATE="not-present"
        return 0
    fi
    for node_id in "${SOURCE_IDS[@]}"; do
        output=$(wpctl get-volume "$node_id" 2>/dev/null) || {
            return 1
        }
        # WirePlumber renders `Volume: %.2f` with an optional `[MUTED]`
        # suffix. Reject successful-but-unexpected output instead of treating
        # every string without that suffix as proof that capture is unmuted.
        if [[ $output =~ ^Volume:[[:space:]]+[0-9]+(\.[0-9]+)?([[:space:]]+\[MUTED\])?$ ]]; then
            if [[ -n ${BASH_REMATCH[2]:-} ]]; then
                mute_state=muted
            else
                mute_state=unmuted
            fi
        else
            return 1
        fi
        case "$mute_state" in
            muted) ((muted += 1)) ;;
            unmuted) ((unmuted += 1)) ;;
        esac
    done
    if ((muted > 0 && unmuted == 0)); then
        SOURCE_STATE="muted"
    elif ((unmuted > 0 && muted == 0)); then
        SOURCE_STATE="unmuted"
    else
        SOURCE_STATE="mixed"
    fi
}

force_disabled() {
    local failed=0
    gnome_set true || failed=1
    wp_set_saved true || failed=1
    set_sources_mute 1 || failed=1
    return "$failed"
}

verify_mode() {
    local mode=$1
    local gnome_value
    gnome_value=$(gnome_get) || return 1
    wp_get || return 1
    source_state || return 1
    case "$mode" in
        off)
            [[ $gnome_value == true && $WP_ACTIVE == true && $WP_SAVED == true &&
               ($SOURCE_STATE == muted || $SOURCE_STATE == not-present) ]]
            ;;
        on)
            [[ $gnome_value == false && $WP_ACTIVE == false && $WP_SAVED == false &&
               ($SOURCE_STATE == unmuted || $SOURCE_STATE == not-present) ]]
            ;;
        *) return 1 ;;
    esac
}

show_status() {
    local gnome_value="unknown"
    local wp_value="unknown"
    local saved_value="default"
    local state="unavailable"
    local coherent=1

    gnome_value=$(gnome_get) || coherent=0
    if wp_get; then
        wp_value=$WP_ACTIVE
        [[ -z $WP_SAVED ]] || saved_value=$WP_SAVED
    else
        coherent=0
    fi
    source_state || coherent=0
    state=$SOURCE_STATE

    printf 'gnome_disable_microphone=%s\n' "$gnome_value"
    printf 'wireplumber_policy_disabled=%s\n' "$wp_value"
    printf 'wireplumber_saved_value=%s\n' "$saved_value"
    printf 'capture_sources=%s\n' "${#SOURCE_IDS[@]}"
    printf 'capture_source_mute=%s\n' "$state"

    if [[ $gnome_value == true && $wp_value == true &&
          ($saved_value == true || $saved_value == default) &&
          ($state == muted || $state == not-present) ]]; then
        printf 'microphone=off\n'
    elif [[ $gnome_value == false && $wp_value == false &&
            $saved_value == false &&
            ($state == unmuted || $state == not-present) ]]; then
        printf 'microphone=on\n'
    else
        printf 'microphone=degraded\n'
        coherent=0
    fi
    return $((coherent == 1 ? 0 : 1))
}

case "${1:-}" in
    off)
        [[ $# -eq 1 ]] || { usage >&2; exit 2; }
        force_disabled || die "microphone disable incomplete; privacy-safe layers were retained where possible"
        verify_mode off || die "microphone disable postcondition failed"
        printf 'Microphone: OFF (GNOME access blocked; WirePlumber persistent mute active)\n'
        ;;
    on)
        [[ $# -eq 1 ]] || { usage >&2; exit 2; }
        # Keep the GNOME application block engaged until policy and source
        # unmute both succeed. Any failure returns to the privacy-safe state.
        if ! wp_set_saved false || ! set_sources_mute 0 || ! gnome_set false ||
           ! verify_mode on; then
            if force_disabled; then
                die "microphone enable failed; restored the disabled state"
            fi
            die "microphone enable failed and fail-closed restoration was incomplete"
        fi
        printf 'Microphone: ON (GNOME access allowed; persistent mute inactive)\n'
        ;;
    status)
        [[ $# -eq 1 ]] || { usage >&2; exit 2; }
        show_status
        ;;
    -h|--help|help)
        [[ $# -eq 1 ]] || { usage >&2; exit 2; }
        usage
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac
NOID_MIC_TOGGLE_EOF

chmod 0755 /etc/wireplumber/wireplumber.conf.d
chmod 0755 /usr/local/share/wireplumber /usr/local/share/wireplumber/scripts
chmod 0644 /etc/wireplumber/wireplumber.conf.d/90-noid-microphone-privacy.conf
chmod 0644 /usr/local/share/wireplumber/scripts/noid-microphone-privacy.lua
chmod 0755 /usr/local/bin/noid-toggle-microphone
chown root:root \
    /etc/wireplumber/wireplumber.conf.d/90-noid-microphone-privacy.conf \
    /usr/local/share/wireplumber/scripts/noid-microphone-privacy.lua \
    /usr/local/bin/noid-toggle-microphone

spa-json-dump /etc/wireplumber/wireplumber.conf.d/90-noid-microphone-privacy.conf \
    >/dev/null || { log "  FAIL: microphone WirePlumber config invalid"; exit 1; }
bash -n /usr/local/bin/noid-toggle-microphone || {
    log "  FAIL: noid-toggle-microphone syntax invalid"
    exit 1
}
if grep -qF 'noid.microphone.privacy = required' \
       /etc/wireplumber/wireplumber.conf.d/90-noid-microphone-privacy.conf \
   && grep -qF 'api.mixer' \
       /etc/wireplumber/wireplumber.conf.d/90-noid-microphone-privacy.conf \
   && grep -qF 'ENFORCEMENT_INTERVAL_MSEC = 1000' \
       /usr/local/share/wireplumber/scripts/noid-microphone-privacy.lua \
   && grep -qF 'Plugin.find ("mixer-api")' \
       /usr/local/share/wireplumber/scripts/noid-microphone-privacy.lua \
   && grep -qF 'mixer:connect ("changed"' \
       /usr/local/share/wireplumber/scripts/noid-microphone-privacy.lua \
   && grep -qF 'mixer:call ("set-volume"' \
       /usr/local/share/wireplumber/scripts/noid-microphone-privacy.lua \
   && grep -qF 'wpctl settings --save "$WP_KEY" "$value"' \
       /usr/local/bin/noid-toggle-microphone; then
    log "  [OK] required persistent WirePlumber microphone policy deployed"
else
    log "  FAIL: microphone policy deployment postcondition failed"
    exit 1
fi

#------------------------------------------------------------------------------
# Step 3d: GDM greeter location-off
#------------------------------------------------------------------------------
# The greeter's gnome-shell can D-Bus-activate geoclue at its permission lookup
# (observed at boot) even though the schema default for the key is already
# false. Make the off-state explicit in the gdm dconf database so the greeter
# session never requests a location. The effective egress block is the M08
# geoclue conf.d override (all sources disabled); this is the greeter-side belt.
# Compiled by the Step 4 dconf update below.
mkdir -p /etc/dconf/db/gdm.d
cat > /etc/dconf/db/gdm.d/01-noid-location <<'GDM_LOC_EOF'
# NoID Privacy — GDM greeter never requests geolocation.
# Schema default is already false, but the greeter's gnome-shell can still
# D-Bus-activate geoclue at the permission lookup (observed at boot). This makes
# the off-state explicit in the gdm dconf database. The effective egress block is
# the geoclue conf.d override (all sources disabled) managed by noid-location-apply.
[org/gnome/system/location]
enabled=false
GDM_LOC_EOF
chmod 0644 /etc/dconf/db/gdm.d/01-noid-location
chown root:root /etc/dconf/db/gdm.d/01-noid-location

#------------------------------------------------------------------------------
# Step 4: Compile dconf database
#------------------------------------------------------------------------------
log "Step 4/8: Compile dconf database"
if ! dconf update; then
    log "  FAIL: dconf update failed"
    exit 1
fi
if [ -s /etc/dconf/db/distro ]; then
    distro_db_size=$(stat -c%s /etc/dconf/db/distro)
    log "  /etc/dconf/db/distro binary database compiled ($distro_db_size bytes)"
else
    log "  FAIL: /etc/dconf/db/distro missing or empty after successful dconf update"
    exit 1
fi

#------------------------------------------------------------------------------
# Step 5: Native D-Bus activation denial; vendor RPM payloads stay pristine
#------------------------------------------------------------------------------
log "Step 5/8: immediate native D-Bus denial for GNOME Software/GOA/Tracker"
install -d -m 0755 -o root -g root "$DBUS_ADMIN_DIR" "$DBUS_POLICY_DIR"

cat > "$DBUS_ADMIN_DIR/org.gnome.OnlineAccounts.service" <<'GOA_EOF'
[D-BUS Service]
Name=org.gnome.OnlineAccounts
Exec=/bin/false
SystemdService=noid-blocked-session-service.service
GOA_EOF
chmod 644 "$DBUS_ADMIN_DIR/org.gnome.OnlineAccounts.service"
chown root:root "$DBUS_ADMIN_DIR/org.gnome.OnlineAccounts.service"

cat > "$DBUS_ADMIN_DIR/org.gnome.Identity.service" <<'IDENTITY_EOF'
[D-BUS Service]
Name=org.gnome.Identity
Exec=/bin/false
SystemdService=noid-blocked-session-service.service
IDENTITY_EOF
chmod 644 "$DBUS_ADMIN_DIR/org.gnome.Identity.service"
chown root:root "$DBUS_ADMIN_DIR/org.gnome.Identity.service"

# Retire the former GNOME Software admin service override. Fedora's descriptor
# already carries SystemdService=gnome-software.service, and M08 masks that
# exact unit globally. Keeping a higher-priority descriptor would add no
# protection and makes dbus-broker report a duplicate name at every session
# start/reload. The separate admin *desktop* entry below remains: it selects
# direct Exec only for a deliberate app-grid/CLI launch.
rm -f -- "$GNOME_SOFTWARE_ADMIN_SERVICE"

# /etc/goa.conf provider allowlist — independent defense in depth per
# https://gnome.pages.gitlab.gnome.org/gnome-online-accounts/configuration.html
# GOA 3.58.1 does not treat disable=all specially: it compares "all" with each
# real provider name and would therefore load every provider. Its supported
# enable allowlist instead loads only named matches. The project-reserved,
# deliberately unmatched __noid_none__ token encodes an empty subset and keeps
# later provider additions denied by default. The D-Bus route above prevents
# process activation independently. Both sysadmin-owned layers survive RPM
# upgrades without rewriting package payloads.
cat > /etc/goa.conf <<'GOA_CONF_EOF'
# NoID Privacy — GNOME Online Accounts hard-block (sysadmin layer)
# GOA's enable key is a provider allowlist. This deliberately unmatched,
# project-reserved value represents an empty allowed subset; do not replace it
# with disable=all, which GOA 3.58.1 interprets as an ordinary provider name.
# The separate admin D-Bus route blocks process activation independently.
[providers]
enable=__noid_none__
GOA_CONF_EOF
chmod 644 /etc/goa.conf
chown root:root /etc/goa.conf
if [ -L /etc/goa.conf ] \
   || [ "$(stat -c '%U:%G:%a' /etc/goa.conf 2>/dev/null || true)" != root:root:644 ] \
   || [ "$(grep -Fxc '[providers]' /etc/goa.conf 2>/dev/null || true)" -ne 1 ] \
   || [ "$(grep -Ec '^(enable|disable)=' /etc/goa.conf 2>/dev/null || true)" -ne 1 ] \
   || ! grep -qxF 'enable=__noid_none__' /etc/goa.conf; then
    log "  FAIL: GOA empty-provider allowlist postcondition failed"
    exit 1
fi

# Retire the former Tracker /bin/false overrides exactly. Fedora's descriptors
# already route these names to the four separately masked user units. Keeping
# those native routes lets dbus-broker reject Nautilus' unconditional
# LocalSearch connection from static unit state without spawning a false
# helper process.
for service_name in "${TRACKER_DBUS_NAMES[@]}"; do
    rm -f -- "$DBUS_ADMIN_DIR/${service_name}.service"
done

# A reference dbus-daemon enforces send_destination before Exec activation.
# dbus-broker 37 relies on SystemdService routing for the immediate denial, so
# the policy is a fallback/defense-in-depth layer rather than the only block.
# GNOME Software is excluded because explicit direct launch must retain normal
# application IPC after it acquires org.gnome.Software.
cat > "$DBUS_BLOCK_POLICY" <<'DBUS_BLOCK_POLICY_EOF'
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <!--
    NoID Privacy: deny messages before the session bus can activate services
    that the silent-machine policy deliberately suppresses.
  -->
  <policy context="mandatory">
    <deny send_destination="org.gnome.OnlineAccounts"/>
    <deny send_destination="org.gnome.Identity"/>
    <deny send_destination="org.freedesktop.Tracker3.Miner.Files"/>
    <deny send_destination="org.freedesktop.Tracker3.Miner.Files.Control"/>
    <deny send_destination="org.freedesktop.Tracker3.Writeback"/>
    <deny send_destination="org.freedesktop.portal.Tracker"/>
  </policy>
</busconfig>
DBUS_BLOCK_POLICY_EOF
chmod 0644 "$DBUS_BLOCK_POLICY"
chown root:root "$DBUS_BLOCK_POLICY"
if command -v restorecon >/dev/null 2>&1; then
    restorecon -RF "$DBUS_ADMIN_DIR" "$DBUS_POLICY_DIR"
fi

log "  Installed ${#DBUS_ADMIN_BLOCKED_NAMES[@]} static-mask admin routes; retired ${#TRACKER_DBUS_NAMES[@]} delayed Tracker overrides"
log "  Installed ${#DBUS_POLICY_BLOCKED_NAMES[@]} mandatory session-bus send denials"
log "  Installed /etc/goa.conf empty provider allowlist (independent provider layer)"

# The Fedora launcher is DBusActivatable=true, which instructs compliant
# desktops to ignore its Exec line. The service denial above would therefore
# also block an intentional app-grid click unless the admin desktop tier
# explicitly selects direct execution. Keep the two namespaces separate:
# bus service denial for unsolicited activation, desktop-file override for
# deliberate user launch. The helper validates the signed RPM payload before
# generating an atomic admin copy and never writes under /usr/share.
install -d -m 0755 -o root -g root /usr/local/bin /usr/local/sbin

# Closing GNOME Software's last window leaves its upstream update-monitor hold
# alive. Its native --quit path releases the application's DNF session, but
# Fedora 44's dnf5daemon-server has no idle timer and remains resident. Keep
# this cleanup explicit: the user helper waits for the application bus name to
# disappear, then the root helper observes a bounded graceful DNF Session
# teardown and accepts only the daemon's five fixed parent objects before
# stopping the D-Bus-activatable service. A timer or window watcher could race
# a real installation.
cat > /usr/local/bin/noid-gnome-software-quit <<'NOID_GS_QUIT_EOF'
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
NOID_GS_QUIT_EOF
chmod 0755 "$GNOME_SOFTWARE_QUIT"
chown root:root "$GNOME_SOFTWARE_QUIT"

cat > /usr/local/bin/noid-gnome-software-rpm <<'NOID_GS_RPM_EOF'
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
NOID_GS_RPM_EOF
chmod 0755 "$GNOME_SOFTWARE_RPM"
chown root:root "$GNOME_SOFTWARE_RPM"

cat > /usr/local/sbin/noid-gnome-software-backend-stop <<'NOID_GS_BACKEND_STOP_EOF'
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
NOID_GS_BACKEND_STOP_EOF
chmod 0755 "$GNOME_SOFTWARE_BACKEND_STOP"
chown root:root "$GNOME_SOFTWARE_BACKEND_STOP"

cat > "$GNOME_SOFTWARE_QUIT_SUDOERS" <<'NOID_GS_QUIT_SUDO_EOF'
# NoID Privacy — let an active local administrator release GNOME Software's
# idle-or-settling DNF5 backend without an authentication dialog. The
# root-owned helper accepts no arguments, bounds its graceful wait and
# independently refuses DNF sessions that remain active.
%wheel ALL=(root) NOPASSWD: /usr/local/sbin/noid-gnome-software-backend-stop ""
NOID_GS_QUIT_SUDO_EOF
chmod 0440 "$GNOME_SOFTWARE_QUIT_SUDOERS"
chown root:root "$GNOME_SOFTWARE_QUIT_SUDOERS"
if ! visudo -cf "$GNOME_SOFTWARE_QUIT_SUDOERS" >/dev/null 2>&1; then
    rm -f -- "$GNOME_SOFTWARE_QUIT_SUDOERS"
    log "  FAIL: GNOME Software complete-quit sudoers contract is invalid"
    exit 1
fi

cat > /usr/local/sbin/noid-gnome-software-launcher-sync <<'NOID_GS_LAUNCHER_SYNC_EOF'
#!/usr/bin/env bash
# Publish an admin GNOME Software launcher that preserves explicit user launch
# while the separate session-bus admin descriptor blocks unsolicited starts.
# Standard desktop actions expose the one-shot RPM view and GNOME Software's
# own graceful --quit path; closing its last window alone intentionally leaves
# the upstream process held.
set -euo pipefail
umask 022
export LC_ALL=C
export PATH=/usr/sbin:/usr/bin

if [[ $# -ne 0 ]]; then
    echo "Usage: noid-gnome-software-launcher-sync" >&2
    exit 2
fi

VENDOR_FILE=/usr/share/applications/org.gnome.Software.desktop
ADMIN_DIR=/usr/local/share/applications
ADMIN_FILE=$ADMIN_DIR/org.gnome.Software.desktop
EXPECTED_PACKAGE=gnome-software

fail() {
    echo "noid-gnome-software-launcher-sync: $*" >&2
    exit 1
}

[[ $EUID -eq 0 ]] || fail "must run as root"
for command_name in awk chmod chown desktop-file-edit desktop-file-install \
        desktop-file-validate grep install matchpathcon mktemp mv rm rmdir rpm \
        sha256sum restorecon stat sync; do
    command -v "$command_name" >/dev/null 2>&1 || \
        fail "required command missing: $command_name"
done

[[ -f $VENDOR_FILE && ! -L $VENDOR_FILE ]] || \
    fail "vendor launcher is missing, non-regular or symlinked"
[[ $(rpm -qf --qf '%{NAME}\n' "$VENDOR_FILE" 2>/dev/null || true) == \
   "$EXPECTED_PACKAGE" ]] || fail "vendor launcher RPM owner differs"

dump_record=$(rpm -q --dump "$EXPECTED_PACKAGE" 2>/dev/null | \
    awk -v path="$VENDOR_FILE" \
        '$1 == path {print; found=1} END {exit !found}') || dump_record=
read -r dump_path expected_size expected_mtime expected_sha expected_mode \
    expected_owner expected_group dump_config dump_doc dump_rdev dump_caps \
    dump_extra <<< "$dump_record"
[[ $dump_path == "$VENDOR_FILE" \
   && $expected_mode == 0100644 \
   && ${dump_config:-}:${dump_doc:-}:${dump_rdev:-}:${dump_caps:-} == 0:0:0:X \
   && -z ${dump_extra:-} ]] || fail "vendor launcher RPM record is malformed"
[[ $(stat -c '%s:%Y:%U:%G:%a' "$VENDOR_FILE" 2>/dev/null || true) == \
   "$expected_size:$expected_mtime:$expected_owner:$expected_group:644" ]] || \
    fail "vendor launcher metadata differs from the RPM record"
[[ $(sha256sum "$VENDOR_FILE" | awk '{print $1}') == "$expected_sha" ]] || \
    fail "vendor launcher bytes differ from the RPM record"

vendor_actions_count=$(awk '
    $0 == "[Desktop Entry]" { in_entry=1; next }
    /^\[/ { in_entry=0 }
    in_entry && /^Actions=/ { count++ }
    END { print count + 0 }
' "$VENDOR_FILE")
[[ $vendor_actions_count -le 1 ]] || fail "vendor launcher has duplicate Actions keys"
vendor_actions=$(awk '
    $0 == "[Desktop Entry]" { in_entry=1; next }
    /^\[/ { in_entry=0 }
    in_entry && /^Actions=/ { print substr($0, 9) }
' "$VENDOR_FILE")
vendor_actions=${vendor_actions%;}
for noid_action in NoIDFedoraRPM NoIDQuit; do
    case ";$vendor_actions;" in
        *";$noid_action;"*)
            fail "vendor launcher already owns the $noid_action action"
            ;;
    esac
    [[ $(grep -c "^\[Desktop Action $noid_action\]$" "$VENDOR_FILE") -eq 0 ]] || \
        fail "vendor launcher already owns the $noid_action action group"
done
if [[ -n $vendor_actions ]]; then
    admin_actions="$vendor_actions;NoIDFedoraRPM;NoIDQuit;"
else
    admin_actions='NoIDFedoraRPM;NoIDQuit;'
fi

if [[ -e $ADMIN_DIR || -L $ADMIN_DIR ]]; then
    [[ -d $ADMIN_DIR && ! -L $ADMIN_DIR \
       && $(stat -c '%U:%G:%a' "$ADMIN_DIR" 2>/dev/null || true) == \
          root:root:755 ]] || fail "admin application directory is unsafe"
else
    install -d -m 0755 -o root -g root "$ADMIN_DIR"
fi

tmp_dir=$(mktemp -d -- "$ADMIN_DIR/.noid-gnome-software.XXXXXXXX") || \
    fail "cannot allocate an admin-directory temporary"
candidate=$tmp_dir/org.gnome.Software.desktop
cleanup() {
    if [[ -n ${candidate:-} && -e ${candidate:-} ]]; then
        rm -f -- "$candidate"
    fi
    if [[ -n ${tmp_dir:-} && -d ${tmp_dir:-} ]]; then
        rmdir -- "$tmp_dir" 2>/dev/null || true
    fi
}
trap cleanup EXIT HUP INT TERM

desktop-file-install \
    --dir="$tmp_dir" \
    --mode=0644 \
    --set-key=DBusActivatable \
    --set-value=false \
    "$VENDOR_FILE" || fail "cannot generate the admin launcher"
[[ -f $candidate && ! -L $candidate ]] || fail "generated launcher is unsafe"
printf '\n[Desktop Action NoIDFedoraRPM]\nName=Open GNOME Software with Fedora RPMs\nName[de]=GNOME Software mit Fedora-RPMs öffnen\nExec=/usr/local/bin/noid-gnome-software-rpm\n\n[Desktop Action NoIDQuit]\nName=Quit completely\nName[de]=Vollständig beenden\nExec=/usr/local/bin/noid-gnome-software-quit\n' \
    >> "$candidate" || fail "cannot add the NoID Privacy desktop actions"
desktop-file-edit \
    --set-key=Actions \
    --set-value="$admin_actions" \
    "$candidate" || fail "cannot publish the complete-quit action reference"
chown root:root "$candidate"
chmod 0644 "$candidate"
desktop-file-validate "$candidate" || fail "generated launcher is invalid"
[[ $(grep -c '^DBusActivatable=' "$candidate") -eq 1 ]] || \
    fail "generated launcher activation key count differs"
grep -qxF 'DBusActivatable=false' "$candidate" || \
    fail "generated launcher does not force direct execution"
grep -qxF 'Exec=gnome-software %U' "$candidate" || \
    fail "generated launcher lost Fedora's explicit execution path"
grep -qxF "Actions=$admin_actions" "$candidate" || \
    fail "generated launcher action list differs"
[[ $(grep -c '^\[Desktop Action NoIDQuit\]$' "$candidate") -eq 1 ]] || \
    fail "generated launcher complete-quit action count differs"
[[ $(grep -c '^\[Desktop Action NoIDFedoraRPM\]$' "$candidate") -eq 1 ]] || \
    fail "generated launcher Fedora RPM action count differs"
grep -qxF 'Exec=/usr/local/bin/noid-gnome-software-rpm' "$candidate" || \
    fail "generated launcher lost the Fedora RPM one-shot path"
grep -qxF 'Exec=/usr/local/bin/noid-gnome-software-quit' "$candidate" || \
    fail "generated launcher lost the graceful complete-quit path"

sync -- "$candidate"
mv -fT -- "$candidate" "$ADMIN_FILE"
candidate=
restorecon -F "$ADMIN_FILE" || fail "cannot label the admin launcher"
[[ $(stat -c '%U:%G:%a' "$ADMIN_FILE" 2>/dev/null || true) == \
   root:root:644 ]] || fail "published launcher metadata differs"
matchpathcon -V "$ADMIN_FILE" >/dev/null 2>&1 || \
    fail "published launcher SELinux context differs"
sync -- "$ADMIN_FILE"
sync -- "$ADMIN_DIR"
rmdir -- "$tmp_dir"
tmp_dir=
trap - EXIT HUP INT TERM
NOID_GS_LAUNCHER_SYNC_EOF
chmod 0755 "$GNOME_SOFTWARE_LAUNCHER_SYNC"
chown root:root "$GNOME_SOFTWARE_LAUNCHER_SYNC"

install -d -m 0755 -o root -g root /etc/dnf/libdnf5-plugins/actions.d
cat > "$GNOME_SOFTWARE_LAUNCHER_ACTION" <<'NOID_GS_LAUNCHER_ACTION_EOF'
# Regenerate only NoID Privacy's admin-owned GNOME Software launcher after the
# signed Fedora package changes. The RPM-owned desktop and D-Bus files remain
# pristine. stdout is reserved for libdnf5 action IPC; stderr stays visible.
# Format: callback:package_filter:direction:options:command
post_transaction:gnome-software:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-gnome-software-launcher-sync\ >/dev/null
NOID_GS_LAUNCHER_ACTION_EOF
chmod 0644 "$GNOME_SOFTWARE_LAUNCHER_ACTION"
chown root:root "$GNOME_SOFTWARE_LAUNCHER_ACTION"

if command -v restorecon >/dev/null 2>&1; then
    restorecon -F "$GNOME_SOFTWARE_QUIT" \
        "$GNOME_SOFTWARE_RPM" \
        "$GNOME_SOFTWARE_BACKEND_STOP" \
        "$GNOME_SOFTWARE_QUIT_SUDOERS" \
        "$GNOME_SOFTWARE_LAUNCHER_SYNC" \
        "$GNOME_SOFTWARE_LAUNCHER_ACTION"
fi
"$GNOME_SOFTWARE_LAUNCHER_SYNC"
log "  Installed explicit-launch/complete-quit split + idle-only DNF5 release"

#------------------------------------------------------------------------------
# Step 5b: Reject the retired RPM rewrite/reassert mechanism
#------------------------------------------------------------------------------
# The standard XDG admin directory is package-independent and higher priority,
# so package transactions require no mutation hook. Remove only the two known
# obsolete NoID Privacy artifacts if an iterative compose root happens to contain them.
rm -f /usr/local/sbin/noid-dbus-suppress-reassert /etc/dnf/libdnf5-plugins/actions.d/noid-dbus-suppress.actions
log "Step 5b/8: retired RPM-payload rewrite and dnf reassert hook absent"

#------------------------------------------------------------------------------
# Step 6: Mask security/privacy-sensitive user units system-wide
#------------------------------------------------------------------------------
log "Step 6/8: Mask ${#MASK_UNITS[@]} user services system-wide"
mkdir -p "$SYSTEMD_USER_DIR"

for unit in "${MASK_UNITS[@]}"; do
    ln -sf /dev/null "$SYSTEMD_USER_DIR/$unit"
done
log "  Declared ${#MASK_UNITS[@]} user-service masks; Step 7.3 verifies every target"

#------------------------------------------------------------------------------
# Step 6b:
# XDG_DATA_DIRS trailing-slash cleanup via systemd environment-generator
# (architectural improvement — supersedes the env.d-only approach; cosmetic-only impact
# on dbus-broker duplicate-name spam — UPSTREAM bug remains)
#------------------------------------------------------------------------------
# env-generators (system + user) strip trailing slashes from XDG_DATA_DIRS
# after the flatpak generators — env.d alone never reached the GDM-greeter
# session. HONEST scope: this is architectural cleanup only; the dbus-broker
# duplicate-name log-spam persists regardless (upstream double-scan of
# /usr/share via session.conf fallback + XDG_DATA_DIRS — bus1/dbus-broker
# #339, cross-distro). Generators retained as POSIX-correct + future-proof.
# Legacy env.d file removed below.
log "Step 6b/8: XDG_DATA_DIRS trailing-slash cleanup via systemd env-generators (v14 architectural-improvement, cosmetic-only on duplicate-name spam — upstream-bug remains)"

# Cleanup legacy v10 env.d file
rm -f /etc/environment.d/50-noid-xdg-paths.conf 2>/dev/null

# System-level generator (applies to PID 1 children incl. user@.service)
mkdir -p /etc/systemd/system-environment-generators
chmod 755 /etc/systemd/system-environment-generators
cat > /etc/systemd/system-environment-generators/99-noid-xdg-cleanup <<'XDG_GEN_EOF'
#!/usr/bin/sh
# NoID Privacy — strip trailing slashes from XDG_DATA_DIRS (Module 17)
# Runs AFTER 60-flatpak-system-only which outputs paths with trailing slashes.
# Per systemd.environment-generator(7), $XDG_DATA_DIRS contains the
# already-merged value from earlier generators.
# Canonicalizes Flatpak's path spelling; dbus-broker's independent upstream
# double-scan still emits the duplicate-name diagnostic documented above.
if [ "$#" -ne 0 ]; then
    printf '%s\n' \
        'noid-xdg-cleanup: ERROR: this internal helper accepts no arguments' >&2
    exit 2
fi

xdg="${XDG_DATA_DIRS:-/usr/local/share:/usr/share}"
cleaned=""
sep=""
old_IFS="$IFS"
IFS=":"
for component in $xdg; do
    cleaned="${cleaned}${sep}${component%/}"
    sep=":"
done
IFS="$old_IFS"
printf 'XDG_DATA_DIRS=%s\n' "$cleaned"
XDG_GEN_EOF
chmod 755 /etc/systemd/system-environment-generators/99-noid-xdg-cleanup
chown root:root /etc/systemd/system-environment-generators/99-noid-xdg-cleanup
log "  /etc/systemd/system-environment-generators/99-noid-xdg-cleanup installed (755)"

# User-level generator (applies to user@$UID.service incl. GDM-greeter)
mkdir -p /etc/systemd/user-environment-generators
chmod 755 /etc/systemd/user-environment-generators
cat > /etc/systemd/user-environment-generators/99-noid-xdg-cleanup <<'XDG_GEN_EOF'
#!/usr/bin/sh
# NoID Privacy — strip trailing slashes from XDG_DATA_DIRS (Module 17)
# Runs AFTER 60-flatpak which outputs paths with trailing slashes.
# Per systemd.environment-generator(7), $XDG_DATA_DIRS contains the
# already-merged value from earlier generators (incl. 30-systemd-environment-
# d-generator + 60-flatpak in user-environment-generators).
# Canonicalizes Flatpak's path spelling; dbus-broker's independent upstream
# double-scan still emits the duplicate-name diagnostic documented above.
if [ "$#" -ne 0 ]; then
    printf '%s\n' \
        'noid-xdg-cleanup: ERROR: this internal helper accepts no arguments' >&2
    exit 2
fi

xdg="${XDG_DATA_DIRS:-/usr/local/share:/usr/share}"
cleaned=""
sep=""
old_IFS="$IFS"
IFS=":"
for component in $xdg; do
    cleaned="${cleaned}${sep}${component%/}"
    sep=":"
done
IFS="$old_IFS"
printf 'XDG_DATA_DIRS=%s\n' "$cleaned"
XDG_GEN_EOF
chmod 755 /etc/systemd/user-environment-generators/99-noid-xdg-cleanup
chown root:root /etc/systemd/user-environment-generators/99-noid-xdg-cleanup
log "  /etc/systemd/user-environment-generators/99-noid-xdg-cleanup installed (755)"

#------------------------------------------------------------------------------
# Step 6c: Privacy cleanup user-service for GNOME shell
# tracking files (application_state + session-active-history.json)
#------------------------------------------------------------------------------
# GNOME shell persists app-usage + session-activity files despite
# remember-app-usage=false (partial respect; session history has no toggle).
# Missing files are a valid clean/idempotent runtime state after logout. Schema
# drift is therefore checked against the signed, RPM-owned Shell payload at
# install time and after each inbound gnome-shell transaction instead of
# turning a clean user profile into a false warning. The package action uses
# libdnf5's documented host-only + raise_error contract and keeps stdout away
# from its plain-mode IPC parser.
# The GNOME shutdown target orders this cleanup after the session producers
# and before the user bus restart. The helper preflights every directory with
# openat2 NO_SYMLINKS/NO_XDEV, quarantines the exact thumbnail inode before
# recursion and exposes every unsafe path or failed deletion. Mozilla profile
# locks are application-owned recovery state and are never removed here.
log "Step 6c/8: Deploy privacy cleanup user-service for GNOME shell tracking files"

cat > /usr/local/sbin/noid-verify-gnome-privacy-contract <<'NOID_GNOME_PRIVACY_CONTRACT_EOF'
#!/bin/bash
# Fail visibly if GNOME Shell moves the private state files cleaned at logout.
# Absence in a user profile is correct after cleanup; the authoritative schema
# evidence is the current, signed gnome-shell payload that produces the data.
set -euo pipefail
PATH=/usr/sbin:/usr/bin
export PATH

if [ "$#" -ne 0 ]; then
    printf '%s\n' \
        'noid-verify-gnome-privacy-contract: ERROR: this internal helper accepts no arguments' >&2
    exit 2
fi

fail() {
    printf 'noid-verify-gnome-privacy-contract: ERROR: %s\n' "$*" >&2
    exit 1
}

command -v /usr/bin/rpm >/dev/null 2>&1 || fail "rpm is unavailable"
/usr/bin/rpm -q gnome-shell >/dev/null 2>&1 || fail "gnome-shell is not installed"

shell_payloads=()
shell_payload_list=$(/usr/bin/rpm -ql gnome-shell) || \
    fail "cannot enumerate gnome-shell payload"
while IFS= read -r package_path; do
    case "$package_path" in
        */usr/lib64/gnome-shell/libshell-*.so)
            shell_payloads+=("$package_path")
            ;;
    esac
done <<< "$shell_payload_list"

[[ ${#shell_payloads[@]} -eq 1 ]] || \
    fail "expected exactly one RPM-owned libshell payload; found ${#shell_payloads[@]}"
shell_payload=${shell_payloads[0]}
[[ -f $shell_payload && ! -L $shell_payload && -r $shell_payload ]] || \
    fail "GNOME Shell payload is not one readable regular file: $shell_payload"
owner=$(/usr/bin/rpm -qf --qf '%{NAME}\n' "$shell_payload" 2>/dev/null) || \
    fail "cannot authenticate GNOME Shell payload ownership"
[[ $owner == gnome-shell ]] || \
    fail "GNOME Shell payload owner differs: $owner"

dump_record=$(/usr/bin/rpm -q --dump gnome-shell 2>/dev/null | \
    /usr/bin/awk -v path="$shell_payload" \
        '$1 == path {print; found=1} END {exit !found}') || \
    fail "GNOME Shell payload lacks one RPM file record"
read -r dump_path expected_size expected_mtime expected_sha expected_mode \
    expected_owner expected_group dump_config dump_doc dump_rdev dump_caps \
    dump_extra <<< "$dump_record"
[[ $dump_path == "$shell_payload" \
   && $expected_mode == 0100755 \
   && ${dump_config:-}:${dump_doc:-}:${dump_rdev:-}:${dump_caps:-} == 0:0:0:X \
   && -z ${dump_extra:-} ]] || \
    fail "GNOME Shell RPM file record differs"
[[ $(stat -c '%s:%Y:%U:%G:%a' "$shell_payload" 2>/dev/null || true) == \
   "$expected_size:$expected_mtime:$expected_owner:$expected_group:755" ]] || \
    fail "GNOME Shell payload metadata differs from its RPM record"
[[ $(sha256sum "$shell_payload" | /usr/bin/awk '{print $1}') == \
   "$expected_sha" ]] || \
    fail "GNOME Shell payload digest differs from its RPM record"

for state_name in application_state session-active-history.json; do
    grep -aFq -- "$state_name" "$shell_payload" || \
        fail "GNOME private-state schema drift: missing $state_name"
done

evr=$(/usr/bin/rpm -q --qf '%{EVR}\n' gnome-shell) || \
    fail "cannot read gnome-shell EVR"
printf 'noid-verify-gnome-privacy-contract: OK: gnome-shell=%s payload=%s\n' \
    "$evr" "$shell_payload"
NOID_GNOME_PRIVACY_CONTRACT_EOF
chmod 0755 /usr/local/sbin/noid-verify-gnome-privacy-contract
chown root:root /usr/local/sbin/noid-verify-gnome-privacy-contract
command -v restorecon >/dev/null 2>&1 && \
    restorecon -F /usr/local/sbin/noid-verify-gnome-privacy-contract

mkdir -p /etc/dnf/libdnf5-plugins/actions.d
cat > /etc/dnf/libdnf5-plugins/actions.d/noid-gnome-privacy-contract.actions <<'NOID_GNOME_PRIVACY_ACTION_EOF'
# GNOME Shell private-state producer contract. A renamed/removed producer path
# requires review before the logout cleanup can truthfully claim coverage.
# Format: callback:package_filter:direction:options:command
post_transaction:gnome-shell:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-verify-gnome-privacy-contract\ >/dev/null
NOID_GNOME_PRIVACY_ACTION_EOF
chmod 0644 /etc/dnf/libdnf5-plugins/actions.d/noid-gnome-privacy-contract.actions
chown root:root /etc/dnf/libdnf5-plugins/actions.d/noid-gnome-privacy-contract.actions
command -v restorecon >/dev/null 2>&1 && \
    restorecon -F /etc/dnf/libdnf5-plugins/actions.d/noid-gnome-privacy-contract.actions

if ! /usr/local/sbin/noid-verify-gnome-privacy-contract >/dev/null; then
    log "  FAIL: GNOME privacy-state producer contract differs"
    exit 1
fi

mkdir -p /usr/local/libexec
cat > /usr/local/libexec/noid-gnome-privacy-cleanup <<'NOID_GNOME_CLEANUP_EOF'
#!/usr/bin/python3
"""Symlink- and mount-safe GNOME tracking/cache cleanup at session shutdown."""

from __future__ import annotations

import ctypes
import errno
import os
import secrets
import stat
import sys
from contextlib import ExitStack
from dataclasses import dataclass


AT_FDCWD = -100
SYS_OPENAT2 = 437

RESOLVE_NO_XDEV = 0x01
RESOLVE_NO_MAGICLINKS = 0x02
RESOLVE_NO_SYMLINKS = 0x04
RESOLVE_BENEATH = 0x08

DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
ROOT_RESOLVE = RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS
CHILD_RESOLVE = (
    RESOLVE_BENEATH
    | RESOLVE_NO_XDEV
    | RESOLVE_NO_MAGICLINKS
    | RESOLVE_NO_SYMLINKS
)
QUARANTINE_PREFIX = ".noid-thumbnails-delete-"


class OpenHow(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_uint64),
        ("mode", ctypes.c_uint64),
        ("resolve", ctypes.c_uint64),
    ]


LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.syscall.restype = ctypes.c_long


class CleanupError(RuntimeError):
    """A safety precondition or exact cleanup postcondition failed."""


@dataclass
class TreePlan:
    parent_fd: int
    name: str
    tree_fd: int | None
    identity: tuple[int, int] | None


def _openat2(dir_fd: int, path: str, flags: int, resolve: int) -> int:
    raw_path = os.fsencode(path)
    how = OpenHow(flags=flags, mode=0, resolve=resolve)
    fd = LIBC.syscall(
        SYS_OPENAT2,
        dir_fd,
        ctypes.c_char_p(raw_path),
        ctypes.byref(how),
        ctypes.sizeof(how),
    )
    if fd < 0:
        saved_errno = ctypes.get_errno()
        raise OSError(saved_errno, os.strerror(saved_errno), path)
    return int(fd)


def _owned_absolute_root(path: str, label: str) -> int | None:
    if not os.path.isabs(path) or os.path.normpath(path) == os.sep:
        raise CleanupError(f"{label} must be an absolute non-root path")
    try:
        fd = _openat2(AT_FDCWD, os.path.normpath(path), DIR_FLAGS, ROOT_RESOLVE)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise CleanupError(f"unsafe or inaccessible {label}: {exc}") from exc
    metadata = os.fstat(fd)
    if metadata.st_uid != os.getuid():
        os.close(fd)
        raise CleanupError(f"{label} is not owned by uid {os.getuid()}")
    return fd


def _open_child_dir(parent_fd: int, name: str, label: str) -> int:
    try:
        return _openat2(parent_fd, name, DIR_FLAGS, CHILD_RESOLVE)
    except OSError as exc:
        if exc.errno == errno.EXDEV:
            raise CleanupError(f"mount boundary refused at {label}") from exc
        raise CleanupError(f"unsafe directory refused at {label}: {exc}") from exc


def _identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def _lstat(parent_fd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _preflight_tree(tree_fd: int, label: str) -> None:
    """Prove that every directory is beneath this tree and on its mount."""
    with os.scandir(tree_fd) as entries:
        for entry in entries:
            metadata = entry.stat(follow_symlinks=False)
            if not stat.S_ISDIR(metadata.st_mode):
                continue
            child_fd = _open_child_dir(tree_fd, entry.name, f"{label}/{entry.name}")
            try:
                if _identity(os.fstat(child_fd)) != _identity(metadata):
                    raise CleanupError(f"directory raced during preflight: {label}/{entry.name}")
                _preflight_tree(child_fd, f"{label}/{entry.name}")
            finally:
                os.close(child_fd)


def _prepare_tree(parent_fd: int, name: str, label: str) -> TreePlan | None:
    metadata = _lstat(parent_fd, name)
    if metadata is None:
        return None
    if not stat.S_ISDIR(metadata.st_mode):
        return TreePlan(parent_fd, name, None, None)

    tree_fd = _open_child_dir(parent_fd, name, label)
    if _identity(os.fstat(tree_fd)) != _identity(metadata):
        os.close(tree_fd)
        raise CleanupError(f"directory raced while opening: {label}")
    try:
        _preflight_tree(tree_fd, label)
    except Exception:
        os.close(tree_fd)
        raise
    return TreePlan(parent_fd, name, tree_fd, _identity(metadata))


def _remove_contents(tree_fd: int, label: str) -> int:
    removed = 0
    while True:
        with os.scandir(tree_fd) as entries:
            names = [entry.name for entry in entries]
        if not names:
            return removed
        for name in names:
            metadata = _lstat(tree_fd, name)
            if metadata is None:
                continue
            child_label = f"{label}/{name}"
            if not stat.S_ISDIR(metadata.st_mode):
                os.unlink(name, dir_fd=tree_fd)
                removed += 1
                continue

            child_fd = _open_child_dir(tree_fd, name, child_label)
            try:
                child_identity = _identity(os.fstat(child_fd))
                if child_identity != _identity(metadata):
                    raise CleanupError(f"directory raced while deleting: {child_label}")
                removed += _remove_contents(child_fd, child_label)
            finally:
                os.close(child_fd)
            current = _lstat(tree_fd, name)
            if current is None:
                continue
            if _identity(current) != child_identity or not stat.S_ISDIR(current.st_mode):
                raise CleanupError(f"directory identity changed before removal: {child_label}")
            os.rmdir(name, dir_fd=tree_fd)
            removed += 1


def _execute_tree(plan: TreePlan, label: str) -> int:
    if plan.tree_fd is None:
        current = _lstat(plan.parent_fd, plan.name)
        if current is None:
            return 0
        if stat.S_ISDIR(current.st_mode):
            raise CleanupError(f"non-directory changed into a directory: {label}")
        os.unlink(plan.name, dir_fd=plan.parent_fd)
        return 1

    quarantine = f"{QUARANTINE_PREFIX}{os.getpid()}-{secrets.token_hex(8)}"
    os.rename(
        plan.name,
        quarantine,
        src_dir_fd=plan.parent_fd,
        dst_dir_fd=plan.parent_fd,
    )
    moved = _lstat(plan.parent_fd, quarantine)
    if moved is None or _identity(moved) != plan.identity or not stat.S_ISDIR(moved.st_mode):
        raise CleanupError(f"directory identity changed during quarantine: {label}")

    removed = _remove_contents(plan.tree_fd, label)
    current = _lstat(plan.parent_fd, quarantine)
    if current is None or _identity(current) != plan.identity or not stat.S_ISDIR(current.st_mode):
        raise CleanupError(f"quarantine identity changed before removal: {label}")
    os.rmdir(quarantine, dir_fd=plan.parent_fd)
    return removed + 1


def _prepare_gnome_data(data_fd: int | None) -> tuple[int | None, list[str]]:
    if data_fd is None:
        return None, []
    try:
        shell_fd = _open_child_dir(data_fd, "gnome-shell", "XDG_DATA_HOME/gnome-shell")
    except CleanupError as exc:
        cause = exc.__cause__
        if isinstance(cause, OSError) and cause.errno == errno.ENOENT:
            return None, []
        raise

    names: list[str] = []
    for name in ("application_state", "session-active-history.json"):
        metadata = _lstat(shell_fd, name)
        if metadata is None:
            continue
        if stat.S_ISDIR(metadata.st_mode):
            os.close(shell_fd)
            raise CleanupError(f"refusing directory at XDG_DATA_HOME/gnome-shell/{name}")
        names.append(name)
    return shell_fd, names


def _resolve_xdg_root(variable: str, fallback: str) -> str:
    value = os.environ.get(variable)
    if value:
        if not os.path.isabs(value):
            raise CleanupError(f"{variable} must be absolute when set")
        return value
    return fallback


def cleanup() -> tuple[int, int]:
    home = os.environ.get("HOME")
    if not home or not os.path.isabs(home):
        raise CleanupError("HOME must be set to an absolute path")
    data_home = _resolve_xdg_root("XDG_DATA_HOME", os.path.join(home, ".local/share"))
    cache_home = _resolve_xdg_root("XDG_CACHE_HOME", os.path.join(home, ".cache"))

    with ExitStack() as stack:
        data_fd = _owned_absolute_root(data_home, "XDG_DATA_HOME")
        if data_fd is not None:
            stack.callback(os.close, data_fd)
        cache_fd = _owned_absolute_root(cache_home, "XDG_CACHE_HOME")
        if cache_fd is not None:
            stack.callback(os.close, cache_fd)

        shell_fd, data_names = _prepare_gnome_data(data_fd)
        if shell_fd is not None:
            stack.callback(os.close, shell_fd)
        cache_plans: list[tuple[TreePlan, str]] = []
        if cache_fd is not None:
            with os.scandir(cache_fd) as entries:
                cache_names = sorted(
                    entry.name
                    for entry in entries
                    if entry.name == "thumbnails"
                    or entry.name.startswith(QUARANTINE_PREFIX)
                )
            for name in cache_names:
                label = (
                    "XDG_CACHE_HOME/thumbnails"
                    if name == "thumbnails"
                    else f"XDG_CACHE_HOME/{name}"
                )
                plan = _prepare_tree(cache_fd, name, label)
                if plan is None:
                    continue
                cache_plans.append((plan, label))
                if plan.tree_fd is not None:
                    stack.callback(os.close, plan.tree_fd)

        removed_data = 0
        if shell_fd is not None:
            for name in data_names:
                current = _lstat(shell_fd, name)
                if current is None:
                    continue
                if stat.S_ISDIR(current.st_mode):
                    raise CleanupError(f"tracked file changed into a directory: {name}")
                os.unlink(name, dir_fd=shell_fd)
                removed_data += 1
        removed_cache = sum(
            _execute_tree(plan, label) for plan, label in cache_plans
        )
        return removed_data, removed_cache


def main(argv: list[str]) -> int:
    if argv in (["-h"], ["--help"]):
        print("Usage: noid-gnome-privacy-cleanup")
        return 0
    if argv:
        print("Usage: noid-gnome-privacy-cleanup", file=sys.stderr)
        return 2
    try:
        removed_data, removed_cache = cleanup()
    except (CleanupError, OSError) as exc:
        print(f"noid-gnome-privacy-cleanup: ERROR: {exc}", file=sys.stderr)
        return 1
    print(
        "noid-gnome-privacy-cleanup: OK: "
        f"tracking={removed_data} cache_entries={removed_cache}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
NOID_GNOME_CLEANUP_EOF
chmod 0755 /usr/local/libexec/noid-gnome-privacy-cleanup
chown root:root /usr/local/libexec/noid-gnome-privacy-cleanup
command -v restorecon >/dev/null 2>&1 && \
    restorecon -F /usr/local/libexec/noid-gnome-privacy-cleanup

CLEANUP_SVC="/etc/systemd/user/noid-gnome-shell-privacy-cleanup.service"
cat > "$CLEANUP_SVC" <<'CLEANUP_SVC_EOF'
[Unit]
Description=NoID Privacy — wipe GNOME shell tracking and thumbnail cache after session shutdown
Documentation=https://github.com/NexusOne23/noid-privacy-workstation
DefaultDependencies=no
After=graphical-session.target gnome-session.target gnome-session-initialized.target gnome-session-manager.target org.gnome.Shell@user.service
Before=gnome-session-shutdown.target gnome-session-restart-dbus.service

[Service]
Type=oneshot
Slice=-.slice
ExecStart=/usr/local/libexec/noid-gnome-privacy-cleanup
TimeoutStartSec=30

[Install]
WantedBy=gnome-session-shutdown.target
CLEANUP_SVC_EOF
chmod 0644 "$CLEANUP_SVC"
chown root:root "$CLEANUP_SVC"
command -v restorecon >/dev/null 2>&1 && restorecon -F "$CLEANUP_SVC"

# Global enable: GNOME starts its shutdown target only after conflicting
# session targets stop. The explicit Before= edge keeps cleanup within that
# transaction and ahead of the final D-Bus restart.
rm -f /etc/systemd/user/graphical-session.target.wants/noid-gnome-shell-privacy-cleanup.service
mkdir -p /etc/systemd/user/gnome-session-shutdown.target.wants
ln -sf "$CLEANUP_SVC" \
       /etc/systemd/user/gnome-session-shutdown.target.wants/noid-gnome-shell-privacy-cleanup.service

log "  noid-gnome-shell-privacy-cleanup.service deployed at GNOME shutdown"

#------------------------------------------------------------------------------
# Step 6d: JIT-Disable in WebKitGTK + GJS
#------------------------------------------------------------------------------
# These supported variables disable the covered runtimes' documented main
# JavaScript JIT tiers. That narrows exposure to vulnerabilities which require
# enabled JIT compilation; it does not make either engine memory-safe, replace
# WebKit's sandbox or cover Firefox/Chromium. The performance cost can be
# material and is application/workload-specific, so both defaults remain
# explicitly application-overridable. environment.d (not profile.d) covers
# GNOME Shell and its launched applications. Exact boundary and recovery are
# deployed in JIT_ENV_EOF and behavior-tested in every candidate lifecycle.
log "Step 6d/8: Deploy JIT-disable env-vars (WebKitGTK + GJS)"

mkdir -p /etc/environment.d
cat > /etc/environment.d/40-noid-disable-jit.conf <<'JIT_ENV_EOF'
# NoID Privacy Workstation — JIT-Disable for GNOME JS runtimes
#
# Purpose: disable the documented main JavaScript JIT tiers in the supported
# WebKitGTK + GJS versions. This narrows exposure to vulnerabilities that
# require enabled JIT compilation. It does not make the engines memory-safe,
# replace WebKitGTK's content-process sandbox, prevent a sandbox escape or
# affect Firefox/Chromium.
#
# The cost can be material, but is application- and workload-specific; the
# release gate proves effective tier state, not a universal latency number.
# A reviewed incompatible or performance-critical application can opt out:
#   GJS:    env -u GJS_DISABLE_JIT gjs-application [arguments...]
#   WebKit: env JavaScriptCoreUseJIT=1 webkit-application [arguments...]
# GJS disables JIT when its variable has any value, so it must be unset.
#
# Read by systemd-environment-d-generator(8) at user-session start →
# propagated to all systemd-user services + GUI apps spawned by gnome-shell.
#
# Cross-references:
#   - https://trac.webkit.org/wiki/EnvironmentVariables
#   - https://gitlab.gnome.org/GNOME/gjs/-/blob/1.88.1/doc/Environment.md
#   - https://gitlab.gnome.org/GNOME/gjs/-/blob/1.88.1/gjs/engine.cpp
#   - https://github.com/WebKit/WebKit/blob/webkitgtk-2.52.5/Source/JavaScriptCore/runtime/VM.cpp
JavaScriptCoreUseJIT=0
GJS_DISABLE_JIT=1
JIT_ENV_EOF
chmod 0644 /etc/environment.d/40-noid-disable-jit.conf
chown root:root /etc/environment.d/40-noid-disable-jit.conf
command -v restorecon >/dev/null 2>&1 && restorecon -F /etc/environment.d/40-noid-disable-jit.conf

log "  /etc/environment.d/40-noid-disable-jit.conf deployed (JavaScriptCoreUseJIT=0 + GJS_DISABLE_JIT=1)"

#------------------------------------------------------------------------------
# Step 6e: Strict native-Wayland defaults for covered GTK/Qt applications
#------------------------------------------------------------------------------
# These values avoid an accidental GTK/Qt X11 fallback in the normal GNOME
# session. They do not prevent an application, wrapper or caller from choosing
# another backend; Qt's -platform option overrides its environment variable.
# Electron and other toolkits own separate backend selection. Detail and both
# supported recovery forms are in WAYLAND_ENV_EOF.
log "Step 6e/8: Deploy strict native-Wayland GTK/Qt defaults"

mkdir -p /etc/environment.d
cat > /etc/environment.d/45-noid-wayland.conf <<'WAYLAND_ENV_EOF'
# NoID Privacy Workstation — strict native-Wayland application defaults
#
# Purpose: select native Wayland for covered GTK and Qt applications in the
# normal GNOME session and avoid an unintended X11 fallback. This is a strict
# compatibility default, not a security boundary: applications and launchers
# can override it, Qt's `-platform` option overrides QT_QPA_PLATFORM, and
# Electron/Chromium and other toolkits use separate selectors. Xwayland remains
# installed for deliberate compatibility and is not torn down automatically
# when its last client exits.
#
# Recovery for a reviewed X11-only or broken native-Wayland application:
#   GTK: env GDK_BACKEND=x11 application [arguments...]
#   Qt:  env QT_QPA_PLATFORM=xcb application [arguments...]
#        application -platform xcb [arguments...]
# These opt-outs reintroduce X11/Xwayland's weaker client-isolation boundary.
# If no Wayland compositor is available, the strict defaults intentionally
# fail instead of silently falling back; use one of the explicit overrides.
#
# environment.d chosen over profile.d for gnome-shell coverage:
#   environment.d → read by systemd-environment-d-generator at user-session
#                   start → propagated to systemd-user-manager (covers GUI
#                   apps spawned from gnome-shell)
#   profile.d     → only affects login shells (gnome-shell does NOT source
#                   /etc/profile.d/*)
#
# Cross-references:
#   - https://www.freedesktop.org/software/systemd/man/latest/environment.d.html
#   - https://docs.gtk.org/gtk4/running.html#GDK_BACKEND
#   - https://doc.qt.io/qt-6/qguiapplication.html#QGuiApplication
GDK_BACKEND=wayland
QT_QPA_PLATFORM=wayland
WAYLAND_ENV_EOF
chmod 0644 /etc/environment.d/45-noid-wayland.conf
chown root:root /etc/environment.d/45-noid-wayland.conf
command -v restorecon >/dev/null 2>&1 && restorecon -F /etc/environment.d/45-noid-wayland.conf

log "  /etc/environment.d/45-noid-wayland.conf deployed (strict, application-overridable defaults)"

#------------------------------------------------------------------------------
# Step 6f: Native GNOME Text Editor defaults for plain and empty text files
#------------------------------------------------------------------------------
# Fedora's distribution MIME list may still name org.gnome.gedit.desktop even
# when that desktop file is no longer installed. With VSCodium present, the
# unresolved vendor default can then fall through to codium.desktop. The XDG
# MIME Applications specification assigns system administrators the
# /etc/xdg/mimeapps.list tier, so keep package-owned /usr/share bytes pristine
# and publish only the two exact defaults needed here.
log "Step 6f/8: Select GNOME Text Editor for plain and empty text files"

install -d -m 0755 -o root -g root /etc/xdg
cat > /etc/xdg/mimeapps.list <<'MIMEAPPS_EOF'
[Default Applications]
application/x-zerosize=org.gnome.TextEditor.desktop;
text/plain=org.gnome.TextEditor.desktop;
MIMEAPPS_EOF
chmod 0644 /etc/xdg/mimeapps.list
chown root:root /etc/xdg/mimeapps.list
command -v restorecon >/dev/null 2>&1 && restorecon -F /etc/xdg/mimeapps.list

log "  /etc/xdg/mimeapps.list deployed (GNOME Text Editor for text/plain + empty files)"

#------------------------------------------------------------------------------
# Step 7: Verification
#------------------------------------------------------------------------------
log "Step 7/8: Verification"
fail=0

# 7.1: Required files
for path in \
    "$DCONF_PROFILE_DIR/user" \
    "$PRIVACY_PROFILE" \
    "$PRIVACY_LOCKS" \
    "$AGENT_POWER_PROFILE" \
    "$LID_ACTION_HELPER" \
    "$LID_ACTION_SUDOERS"
do
    if [ ! -f "$path" ]; then
        log "  FAIL: $path missing"
        fail=$((fail + 1))
    fi
done

# 7.1b: Agent workflow power defaults are one exact, user-overridable keyfile.
# Validate metadata, schema and the complete three-key identity. The shared
# privacy lock file must not silently turn these defaults into policy locks.
agent_power_key_count=$(grep -cE \
    '^(idle-dim|sleep-inactive-(ac|battery)-type)=' \
    "$AGENT_POWER_PROFILE" 2>/dev/null || true)
agent_power_key_count=${agent_power_key_count:-0}
agent_power_assignment_count=$(grep -cE '^[a-z][a-z-]*=' \
    "$AGENT_POWER_PROFILE" 2>/dev/null || true)
agent_power_assignment_count=${agent_power_assignment_count:-0}
if [ ! -f "$AGENT_POWER_PROFILE" ] || [ -L "$AGENT_POWER_PROFILE" ] \
   || [ "$(stat -c '%U:%G:%a:%h' "$AGENT_POWER_PROFILE" 2>/dev/null || true)" != \
        root:root:644:1 ] \
   || [ "$(grep -Fxc '[org/gnome/settings-daemon/plugins/power]' \
        "$AGENT_POWER_PROFILE" 2>/dev/null || true)" -ne 1 ] \
   || [ "$agent_power_key_count" -ne 3 ] \
   || [ "$agent_power_assignment_count" -ne 3 ] \
   || ! grep -qxF 'idle-dim=false' "$AGENT_POWER_PROFILE" \
   || ! grep -qxF "sleep-inactive-ac-type='nothing'" "$AGENT_POWER_PROFILE" \
   || ! grep -qxF "sleep-inactive-battery-type='nothing'" "$AGENT_POWER_PROFILE" \
   || grep -Eq '^(sleep-inactive-(ac|battery)-timeout|idle-delay)=' \
        "$AGENT_POWER_PROFILE" \
   || grep -Eq '/org/gnome/settings-daemon/plugins/power/(idle-dim|sleep-inactive-(ac|battery)-type)$' \
        "$PRIVACY_LOCKS"; then
    log "  FAIL: user-adjustable agent workflow power defaults invalid"
    fail=$((fail + 1))
else
    log "  OK: exact user-adjustable agent workflow power defaults"
fi

# 7.1c: The lid-action helper is one root-owned, immutable executable source
# payload. Behavioral desktop/SW_LID/rollback coverage lives in its fixture.
if [ ! -f "$LID_ACTION_HELPER" ] || [ -L "$LID_ACTION_HELPER" ] \
   || [ "$(stat -c '%U:%G:%a:%h' "$LID_ACTION_HELPER" 2>/dev/null || true)" != \
        root:root:755:1 ] \
   || ! bash -n "$LID_ACTION_HELPER" \
   || ! "$LID_ACTION_HELPER" --help >/dev/null; then
    log "  FAIL: native lid-action helper invalid"
    fail=$((fail + 1))
else
    log "  OK: native lid-action helper"
fi
lid_sudo_grants=$(grep -cFx \
    '%wheel ALL=(root) NOPASSWD: /usr/local/bin/noid-toggle-lid-action --apply-root suspend' \
    "$LID_ACTION_SUDOERS" 2>/dev/null || true)
lid_sudo_grants=$((lid_sudo_grants + $(grep -cFx \
    '%wheel ALL=(root) NOPASSWD: /usr/local/bin/noid-toggle-lid-action --apply-root lock' \
    "$LID_ACTION_SUDOERS" 2>/dev/null || true)))
lid_sudo_grants=$((lid_sudo_grants + $(grep -cFx \
    '%wheel ALL=(root) NOPASSWD: /usr/local/bin/noid-toggle-lid-action --apply-root reset' \
    "$LID_ACTION_SUDOERS" 2>/dev/null || true)))
if [ ! -f "$LID_ACTION_SUDOERS" ] || [ -L "$LID_ACTION_SUDOERS" ] \
   || [ "$(stat -c '%U:%G:%a:%h' "$LID_ACTION_SUDOERS" 2>/dev/null || true)" != \
        root:root:440:1 ] \
   || [ "$(grep -cEv '^[[:space:]]*(#|$)' \
        "$LID_ACTION_SUDOERS" 2>/dev/null || true)" -ne 3 ] \
   || [ "$lid_sudo_grants" -ne 3 ] \
   || grep -qE 'NOPASSWD:[[:space:]]+ALL' "$LID_ACTION_SUDOERS" \
   || ! visudo -cf "$LID_ACTION_SUDOERS" >/dev/null 2>&1; then
    log "  FAIL: lid-action privilege boundary invalid"
    fail=$((fail + 1))
else
    log "  OK: exact three-action lid privilege boundary"
fi

# 7.2: dconf binary database compiled
if [ ! -f /etc/dconf/db/distro ]; then
    log "  FAIL: /etc/dconf/db/distro not compiled"
    fail=$((fail + 1))
fi

# 7.2b: first-login helper must retain its closed, transactional contract.
firstrun_script=/usr/local/libexec/noid-user-firstrun
firstrun_unit=/usr/lib/systemd/user/noid-user-firstrun.service
firstrun_notifier=/usr/lib/systemd/user/usbguard-notifier.service
firstrun_notifier_wants=/usr/lib/systemd/user/graphical-session.target.wants/usbguard-notifier.service
if [ "$(stat -c '%U:%G:%a' "$firstrun_script" 2>/dev/null || true)" != \
        root:root:755 ] \
   || [ "$(stat -c '%U:%G:%a' "$firstrun_unit" 2>/dev/null || true)" != \
        root:root:644 ] \
   || grep -qF 'preset-all' "$firstrun_script" 2>/dev/null \
   || grep -qF 'ConditionPathExists=' "$firstrun_unit" 2>/dev/null \
   || ! grep -qxF 'UPDATE_UNIT=noid-update-reminder.timer' "$firstrun_script" \
   || ! grep -qxF 'NOTIFIER_UNIT=usbguard-notifier.service' "$firstrun_script" \
   || ! grep -qxF 'NOTIFIER_WANTS=/usr/lib/systemd/user/graphical-session.target.wants/usbguard-notifier.service' "$firstrun_script" \
   || ! grep -qxF 'NOTIFIER_TARGET=/usr/lib/systemd/user/usbguard-notifier.service' "$firstrun_script" \
   || ! grep -qxF 'NAUTILUS_SORT_BY_ATTRIBUTE=metadata::nautilus-icon-view-sort-by' "$firstrun_script" \
   || ! grep -qxF 'NAUTILUS_SORT_REVERSED_ATTRIBUTE=metadata::nautilus-icon-view-sort-reversed' "$firstrun_script" \
   || ! grep -qxF 'LIBVIRT_CONFIG_DIR="${CONFIG_HOME}/libvirt"' "$firstrun_script" \
   || ! grep -qxF 'LIBVIRT_QEMU_CONF="${LIBVIRT_CONFIG_DIR}/qemu.conf"' "$firstrun_script" \
   || ! grep -qF 'for required_task in region nautilus_download_sort libvirt_qemu_core noid_update_reminder usbguard_notifier; do' "$firstrun_script" \
   || ! grep -qF 'existing max_core setting is user-owned and not zero' "$firstrun_script" \
   || ! grep -qF 'existing dump_guest_core setting is user-owned and not zero' "$firstrun_script" \
   || ! grep -qF 'mv -T --update=none-fail -- "$tmp" "$LIBVIRT_QEMU_CONF"' "$firstrun_script" \
   || ! grep -qF "printf 'max_core = 0\\n'" "$firstrun_script" \
   || ! grep -qF "printf 'dump_guest_core = 0\\n'" "$firstrun_script" \
   || ! grep -qF 'xdg-user-dir DOWNLOAD' "$firstrun_script" \
   || ! grep -qF 'gio set -t string "$DOWNLOAD_DIR"' "$firstrun_script" \
   || ! grep -qF 'systemctl --user preset "$UPDATE_UNIT"' "$firstrun_script" \
   || ! grep -qF 'systemctl --user start "$UPDATE_UNIT"' "$firstrun_script" \
   || ! grep -qF 'systemctl --user is-enabled --quiet "$UPDATE_UNIT"' "$firstrun_script" \
   || ! grep -qF 'systemctl --user is-active --quiet "$UPDATE_UNIT"' "$firstrun_script" \
   || grep -qF 'preset "$NOTIFIER_UNIT"' "$firstrun_script" \
   || grep -qF 'is-enabled --quiet "$NOTIFIER_UNIT"' "$firstrun_script" \
   || ! grep -qF '[[ -L "$NOTIFIER_WANTS" ]]' "$firstrun_script" \
   || ! grep -qF 'readlink -- "$NOTIFIER_WANTS"' "$firstrun_script" \
   || ! grep -qF 'systemctl --user start "$NOTIFIER_UNIT"' "$firstrun_script" \
   || ! grep -qF 'systemctl --user is-active --quiet "$NOTIFIER_UNIT"' "$firstrun_script" \
   || ! grep -qF 'mark_done complete' "$firstrun_script" \
   || ! grep -qxF 'PartOf=graphical-session.target' "$firstrun_unit" \
   || ! grep -qxF 'ConditionEnvironment=XDG_SESSION_CLASS=user' "$firstrun_unit" \
   || ! grep -qxF 'ExecCondition=/usr/bin/systemctl --user --quiet is-active graphical-session.target' \
        "$firstrun_unit" \
   || ! grep -qF 'if [ "${XDG_SESSION_CLASS:-}" != user ]; then' "$firstrun_script" \
   || ! grep -qF 'Restart=on-failure' "$firstrun_unit" \
   || [ ! -L /usr/lib/systemd/user/graphical-session.target.wants/noid-user-firstrun.service ] \
   || [ "$(readlink /usr/lib/systemd/user/graphical-session.target.wants/noid-user-firstrun.service)" != \
        /usr/lib/systemd/user/noid-user-firstrun.service ] \
   || [ "$(stat -c '%U:%G:%a' "$firstrun_notifier" 2>/dev/null || true)" != \
        root:root:644 ] \
   || [ ! -L "$firstrun_notifier_wants" ] \
   || [ "$(stat -c '%U:%G' "$firstrun_notifier_wants" 2>/dev/null || true)" != \
        root:root ] \
   || [ "$(readlink "$firstrun_notifier_wants" 2>/dev/null || true)" != \
        "$firstrun_notifier" ]; then
    log "  FAIL: transactional per-task first-login contract invalid"
    fail=$((fail + 1))
else
    log "  OK: transactional per-task first-login contract exact"
fi

# 7.3: All masked units as symlinks to /dev/null (loop uses MASK_UNITS array
# dynamically; includes both GNOME USB-protection activation paths)
for unit in "${MASK_UNITS[@]}"; do
    if [ ! -L "$SYSTEMD_USER_DIR/$unit" ]; then
        log "  FAIL: $unit not masked (no symlink)"
        fail=$((fail + 1))
    else
        target=$(readlink "$SYSTEMD_USER_DIR/$unit")
        if [ "$target" != "/dev/null" ]; then
            log "  FAIL: $unit symlink targets $target (expected /dev/null)"
            fail=$((fail + 1))
        fi
    fi
done

# 7.4: the two fallback-only admin routes use one immediate static mask.
# Software and Tracker have no stale admin override, the reference-bus policy
# is exact, and all seven vendor descriptors remain byte/metadata-pristine.
m17_dbus_fail=0
if [ -e "$GNOME_SOFTWARE_ADMIN_SERVICE" ] \
   || [ -L "$GNOME_SOFTWARE_ADMIN_SERVICE" ] \
   || ! grep -qxF 'SystemdService=gnome-software.service' \
        "$GNOME_SOFTWARE_VENDOR_SERVICE"; then
    log "  FAIL: GNOME Software native masked-activation route is not exact"
    fail=$((fail + 1))
    m17_dbus_fail=1
fi
for service_name in "${DBUS_ADMIN_BLOCKED_NAMES[@]}"; do
    admin_file="$DBUS_ADMIN_DIR/${service_name}.service"
    if [ "$(stat -c '%U:%G:%a' "$admin_file" 2>/dev/null || true)" != \
         root:root:644 ] \
       || [ "$(wc -l < "$admin_file" 2>/dev/null || true)" -ne 4 ] \
       || ! grep -qxF '[D-BUS Service]' "$admin_file" \
       || ! grep -qxF "Name=$service_name" "$admin_file" \
       || ! grep -qxF 'Exec=/bin/false' "$admin_file" \
       || ! grep -qxF \
            "SystemdService=$DBUS_BLOCK_SYSTEMD_SERVICE" "$admin_file" \
       || ! matchpathcon -V "$admin_file" >/dev/null 2>&1; then
        log "  FAIL: D-Bus static-mask admin route is not exact: $admin_file"
        fail=$((fail + 1))
        m17_dbus_fail=1
    fi
done

for service_name in "${TRACKER_DBUS_NAMES[@]}"; do
    admin_file="$DBUS_ADMIN_DIR/${service_name}.service"
    if [ -e "$admin_file" ] || [ -L "$admin_file" ]; then
        log "  FAIL: delayed Tracker D-Bus admin override remains: $admin_file"
        fail=$((fail + 1))
        m17_dbus_fail=1
    fi
done

if [ "$(stat -c '%U:%G:%a' "$DBUS_BLOCK_POLICY" 2>/dev/null || true)" != \
     root:root:644 ] \
   || [ "$(grep -c '^[[:space:]]*<deny send_destination=' \
        "$DBUS_BLOCK_POLICY" 2>/dev/null || true)" -ne \
        "${#DBUS_POLICY_BLOCKED_NAMES[@]}" ] \
   || ! grep -qxF '  <policy context="mandatory">' "$DBUS_BLOCK_POLICY" \
   || ! matchpathcon -V "$DBUS_BLOCK_POLICY" >/dev/null 2>&1; then
    log "  FAIL: mandatory D-Bus send-deny policy metadata or shape invalid"
    fail=$((fail + 1))
    m17_dbus_fail=1
fi
for service_name in "${DBUS_POLICY_BLOCKED_NAMES[@]}"; do
    if ! grep -qxF \
            "    <deny send_destination=\"$service_name\"/>" \
            "$DBUS_BLOCK_POLICY"; then
        log "  FAIL: mandatory D-Bus send denial missing: $service_name"
        fail=$((fail + 1))
        m17_dbus_fail=1
    fi
done

for spec in "${DBUS_VENDOR_SPECS[@]}"; do
    IFS='|' read -r service_name vendor_package <<< "$spec"
    vendor_file="$DBUS_VENDOR_DIR/${service_name}.service"
    if [ ! -f "$vendor_file" ] || [ -L "$vendor_file" ] \
       || [ "$(rpm -qf --qf '%{NAME}\n' "$vendor_file" 2>/dev/null || true)" != \
            "$vendor_package" ]; then
        log "  FAIL: vendor D-Bus descriptor ownership invalid: $vendor_file"
        fail=$((fail + 1))
        m17_dbus_fail=1
        continue
    fi
    dump_record=$(rpm -q --dump "$vendor_package" 2>/dev/null | \
        awk -v path="$vendor_file" '$1 == path {print; found=1} END {exit !found}') || \
        dump_record=""
    read -r dump_path expected_size expected_mtime expected_sha expected_mode \
        expected_owner expected_group dump_config dump_doc dump_rdev dump_caps \
        dump_extra <<< "$dump_record"
    if [ "$dump_path" != "$vendor_file" ] \
       || [ "$expected_mode" != 0100644 ] \
       || [ "${dump_config:-}:${dump_doc:-}:${dump_rdev:-}:${dump_caps:-}" != \
            0:0:0:X ] \
       || [ -n "${dump_extra:-}" ] \
       || [ "$(stat -c '%s:%Y:%U:%G:%a' "$vendor_file" 2>/dev/null || true)" != \
            "$expected_size:$expected_mtime:$expected_owner:$expected_group:644" ] \
       || [ "$(sha256sum "$vendor_file" | awk '{print $1}')" != "$expected_sha" ]; then
        log "  FAIL: RPM-owned D-Bus descriptor drifted: $vendor_file"
        fail=$((fail + 1))
        m17_dbus_fail=1
    fi
done
if [ "$m17_dbus_fail" -eq 0 ]; then
    log "  OK: ${#DBUS_ADMIN_BLOCKED_NAMES[@]} static-mask admin routes; ${#TRACKER_DBUS_NAMES[@]} immediate native Tracker routes; ${#DBUS_VENDOR_SPECS[@]} RPM vendor descriptors byte-pristine"
else
    log "  FAIL: one or more D-Bus denial/vendor integrity contracts failed"
fi

# 7.4b: the explicit GNOME Software launcher is generated from the current
# Fedora desktop entry with DBusActivatable=false, the named one-shot Fedora
# RPM action and a complete-quit action.
# This bypasses only the native masked service-file path for an intentional
# app-grid Exec launch, uses upstream's graceful --quit path, then releases
# only a DNF5 daemon whose dynamic Session objects are all gone.
m17_launcher_tmp=$(mktemp -d /var/tmp/noid-m17-launcher.XXXXXXXX)
m17_vendor_actions_count=$(awk '
    $0 == "[Desktop Entry]" { in_entry=1; next }
    /^\[/ { in_entry=0 }
    in_entry && /^Actions=/ { count++ }
    END { print count + 0 }
' "$GNOME_SOFTWARE_VENDOR_DESKTOP" 2>/dev/null || true)
m17_vendor_actions_count=${m17_vendor_actions_count:-0}
m17_vendor_actions=$(awk '
    $0 == "[Desktop Entry]" { in_entry=1; next }
    /^\[/ { in_entry=0 }
    in_entry && /^Actions=/ { print substr($0, 9) }
' "$GNOME_SOFTWARE_VENDOR_DESKTOP" 2>/dev/null || true)
m17_vendor_actions=${m17_vendor_actions%;}
if [ -n "$m17_vendor_actions" ]; then
    m17_admin_actions="$m17_vendor_actions;NoIDFedoraRPM;NoIDQuit;"
else
    m17_admin_actions='NoIDFedoraRPM;NoIDQuit;'
fi
m17_launcher_expected="$m17_launcher_tmp/org.gnome.Software.desktop"
m17_launcher_expected_ok=1
if [ "$m17_vendor_actions_count" -gt 1 ] \
   || [[ ";$m17_vendor_actions;" == *';NoIDFedoraRPM;'* ]] \
   || [[ ";$m17_vendor_actions;" == *';NoIDQuit;'* ]] \
   || grep -Eq '^\[Desktop Action (NoIDFedoraRPM|NoIDQuit)\]$' \
        "$GNOME_SOFTWARE_VENDOR_DESKTOP" \
   || ! desktop-file-install --dir="$m17_launcher_tmp" --mode=0644 \
        --set-key=DBusActivatable --set-value=false \
        "$GNOME_SOFTWARE_VENDOR_DESKTOP" \
   || ! printf '\n[Desktop Action NoIDFedoraRPM]\nName=Open GNOME Software with Fedora RPMs\nName[de]=GNOME Software mit Fedora-RPMs öffnen\nExec=/usr/local/bin/noid-gnome-software-rpm\n\n[Desktop Action NoIDQuit]\nName=Quit completely\nName[de]=Vollständig beenden\nExec=/usr/local/bin/noid-gnome-software-quit\n' \
        >> "$m17_launcher_expected" \
   || ! desktop-file-edit --set-key=Actions \
        --set-value="$m17_admin_actions" "$m17_launcher_expected"; then
    m17_launcher_expected_ok=0
fi
if [ "$(stat -c '%U:%G:%a' "$GNOME_SOFTWARE_LAUNCHER_SYNC" 2>/dev/null || true)" != \
     root:root:755 ] \
   || [ ! -f "$GNOME_SOFTWARE_QUIT" ] \
   || [ -L "$GNOME_SOFTWARE_QUIT" ] \
   || [ "$(stat -c '%U:%G:%a' "$GNOME_SOFTWARE_QUIT" 2>/dev/null || true)" != \
        root:root:755 ] \
   || ! bash -n "$GNOME_SOFTWARE_QUIT" \
   || ! grep -qxF \
        '/usr/bin/sudo -n /usr/local/sbin/noid-gnome-software-backend-stop' \
        "$GNOME_SOFTWARE_QUIT" \
   || [ ! -f "$GNOME_SOFTWARE_RPM" ] \
   || [ -L "$GNOME_SOFTWARE_RPM" ] \
   || [ "$(stat -c '%U:%G:%a' "$GNOME_SOFTWARE_RPM" 2>/dev/null || true)" != \
        root:root:755 ] \
   || ! bash -n "$GNOME_SOFTWARE_RPM" \
   || ! grep -qxF \
        'RPM_PLUGINS=flatpak,appstream,dnf5,icons,hardcoded-blocklist,malcontent,modalias,os-release,provenance,provenance-license,generic-updates' \
        "$GNOME_SOFTWARE_RPM" \
   || ! grep -qxF 'exec "$SOFTWARE"' "$GNOME_SOFTWARE_RPM" \
   || grep -qF 'fwupd' "$GNOME_SOFTWARE_RPM" \
   || [ ! -f "$GNOME_SOFTWARE_BACKEND_STOP" ] \
   || [ -L "$GNOME_SOFTWARE_BACKEND_STOP" ] \
   || [ "$(stat -c '%U:%G:%a' "$GNOME_SOFTWARE_BACKEND_STOP" 2>/dev/null || true)" != \
        root:root:755 ] \
   || ! bash -n "$GNOME_SOFTWARE_BACKEND_STOP" \
   || ! grep -qF "expected_tree=\$'/\\n/org\\n/org/rpm\\n/org/rpm/dnf\\n/org/rpm/dnf/v0'" \
        "$GNOME_SOFTWARE_BACKEND_STOP" \
   || ! grep -qxF '/usr/bin/systemctl stop "$unit"' \
        "$GNOME_SOFTWARE_BACKEND_STOP" \
   || [ ! -f "$GNOME_SOFTWARE_QUIT_SUDOERS" ] \
   || [ -L "$GNOME_SOFTWARE_QUIT_SUDOERS" ] \
   || [ "$(stat -c '%U:%G:%a' "$GNOME_SOFTWARE_QUIT_SUDOERS" 2>/dev/null || true)" != \
        root:root:440 ] \
   || [ "$(grep -cEv '^[[:space:]]*(#|$)' \
        "$GNOME_SOFTWARE_QUIT_SUDOERS" 2>/dev/null || true)" -ne 1 ] \
   || ! grep -qxF \
        '%wheel ALL=(root) NOPASSWD: /usr/local/sbin/noid-gnome-software-backend-stop ""' \
        "$GNOME_SOFTWARE_QUIT_SUDOERS" \
   || ! visudo -cf "$GNOME_SOFTWARE_QUIT_SUDOERS" >/dev/null 2>&1 \
   || [ "$(stat -c '%U:%G:%a' "$GNOME_SOFTWARE_LAUNCHER_ACTION" 2>/dev/null || true)" != \
        root:root:644 ] \
   || ! grep -qxF \
        'post_transaction:gnome-software:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-gnome-software-launcher-sync\ >/dev/null' \
        "$GNOME_SOFTWARE_LAUNCHER_ACTION" \
   || [ "$(stat -c '%U:%G:%a' "$GNOME_SOFTWARE_ADMIN_DESKTOP" 2>/dev/null || true)" != \
        root:root:644 ] \
   || ! matchpathcon -V "$GNOME_SOFTWARE_ADMIN_DESKTOP" >/dev/null 2>&1 \
   || ! grep -qxF 'DBusActivatable=false' "$GNOME_SOFTWARE_ADMIN_DESKTOP" \
   || ! grep -qxF 'Exec=gnome-software %U' "$GNOME_SOFTWARE_ADMIN_DESKTOP" \
   || ! grep -qxF "Actions=$m17_admin_actions" \
        "$GNOME_SOFTWARE_ADMIN_DESKTOP" \
   || [ "$(grep -c '^\[Desktop Action NoIDQuit\]$' \
        "$GNOME_SOFTWARE_ADMIN_DESKTOP")" -ne 1 ] \
   || [ "$(grep -c '^\[Desktop Action NoIDFedoraRPM\]$' \
        "$GNOME_SOFTWARE_ADMIN_DESKTOP")" -ne 1 ] \
   || ! grep -qxF 'Exec=/usr/local/bin/noid-gnome-software-rpm' \
        "$GNOME_SOFTWARE_ADMIN_DESKTOP" \
   || ! grep -qxF 'Exec=/usr/local/bin/noid-gnome-software-quit' \
        "$GNOME_SOFTWARE_ADMIN_DESKTOP" \
   || ! desktop-file-validate "$GNOME_SOFTWARE_ADMIN_DESKTOP" \
   || [ "$m17_launcher_expected_ok" -ne 1 ] \
   || ! cmp -s "$m17_launcher_expected" \
        "$GNOME_SOFTWARE_ADMIN_DESKTOP"; then
    m17_launcher_detail() {
        log "    DETAIL: $1"
    }
    [ "$(stat -c '%U:%G:%a' "$GNOME_SOFTWARE_LAUNCHER_SYNC" \
        2>/dev/null || true)" = root:root:755 ] || \
        m17_launcher_detail "launcher-sync helper metadata differs"
    if [ ! -f "$GNOME_SOFTWARE_QUIT" ] || [ -L "$GNOME_SOFTWARE_QUIT" ] \
       || [ "$(stat -c '%U:%G:%a' "$GNOME_SOFTWARE_QUIT" \
            2>/dev/null || true)" != root:root:755 ]; then
        m17_launcher_detail "complete-quit helper trust metadata differs"
    fi
    bash -n "$GNOME_SOFTWARE_QUIT" || \
        m17_launcher_detail "complete-quit helper syntax is invalid"
    grep -qxF \
        '/usr/bin/sudo -n /usr/local/sbin/noid-gnome-software-backend-stop' \
        "$GNOME_SOFTWARE_QUIT" || \
        m17_launcher_detail "complete-quit helper root bridge differs"
    if [ ! -f "$GNOME_SOFTWARE_RPM" ] || [ -L "$GNOME_SOFTWARE_RPM" ] \
       || [ "$(stat -c '%U:%G:%a' "$GNOME_SOFTWARE_RPM" \
            2>/dev/null || true)" != root:root:755 ]; then
        m17_launcher_detail "Fedora-RPM helper trust metadata differs"
    fi
    bash -n "$GNOME_SOFTWARE_RPM" || \
        m17_launcher_detail "Fedora-RPM helper syntax is invalid"
    grep -qxF \
        'RPM_PLUGINS=flatpak,appstream,dnf5,icons,hardcoded-blocklist,malcontent,modalias,os-release,provenance,provenance-license,generic-updates' \
        "$GNOME_SOFTWARE_RPM" || \
        m17_launcher_detail "Fedora-RPM helper allowlist differs"
    grep -qxF 'exec "$SOFTWARE"' "$GNOME_SOFTWARE_RPM" || \
        m17_launcher_detail "Fedora-RPM helper trusted exec differs"
    if grep -qF 'fwupd' "$GNOME_SOFTWARE_RPM"; then
        m17_launcher_detail "Fedora-RPM helper unexpectedly enables fwupd"
    fi
    if [ ! -f "$GNOME_SOFTWARE_BACKEND_STOP" ] \
       || [ -L "$GNOME_SOFTWARE_BACKEND_STOP" ] \
       || [ "$(stat -c '%U:%G:%a' "$GNOME_SOFTWARE_BACKEND_STOP" \
            2>/dev/null || true)" != root:root:755 ]; then
        m17_launcher_detail "backend-stop helper trust metadata differs"
    fi
    bash -n "$GNOME_SOFTWARE_BACKEND_STOP" || \
        m17_launcher_detail "backend-stop helper syntax is invalid"
    grep -qF \
        "expected_tree=\$'/\\n/org\\n/org/rpm\\n/org/rpm/dnf\\n/org/rpm/dnf/v0'" \
        "$GNOME_SOFTWARE_BACKEND_STOP" || \
        m17_launcher_detail "backend-stop object-tree boundary differs"
    grep -qxF '/usr/bin/systemctl stop "$unit"' \
        "$GNOME_SOFTWARE_BACKEND_STOP" || \
        m17_launcher_detail "backend-stop native stop action differs"
    if [ ! -f "$GNOME_SOFTWARE_QUIT_SUDOERS" ] \
       || [ -L "$GNOME_SOFTWARE_QUIT_SUDOERS" ] \
       || [ "$(stat -c '%U:%G:%a' "$GNOME_SOFTWARE_QUIT_SUDOERS" \
            2>/dev/null || true)" != root:root:440 ]; then
        m17_launcher_detail "complete-quit sudoers trust metadata differs"
    fi
    [ "$(grep -cEv '^[[:space:]]*(#|$)' \
        "$GNOME_SOFTWARE_QUIT_SUDOERS" 2>/dev/null || true)" = 1 ] || \
        m17_launcher_detail "complete-quit sudoers active-command count differs"
    grep -qxF \
        '%wheel ALL=(root) NOPASSWD: /usr/local/sbin/noid-gnome-software-backend-stop ""' \
        "$GNOME_SOFTWARE_QUIT_SUDOERS" || \
        m17_launcher_detail "complete-quit sudoers command differs"
    visudo -cf "$GNOME_SOFTWARE_QUIT_SUDOERS" >/dev/null 2>&1 || \
        m17_launcher_detail "complete-quit sudoers syntax is invalid"
    [ "$(stat -c '%U:%G:%a' "$GNOME_SOFTWARE_LAUNCHER_ACTION" \
        2>/dev/null || true)" = root:root:644 ] || \
        m17_launcher_detail "launcher action metadata differs"
    grep -qxF \
        'post_transaction:gnome-software:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-gnome-software-launcher-sync\ >/dev/null' \
        "$GNOME_SOFTWARE_LAUNCHER_ACTION" || \
        m17_launcher_detail "launcher action command differs"
    [ "$(stat -c '%U:%G:%a' "$GNOME_SOFTWARE_ADMIN_DESKTOP" \
        2>/dev/null || true)" = root:root:644 ] || \
        m17_launcher_detail "admin desktop metadata differs"
    matchpathcon -V "$GNOME_SOFTWARE_ADMIN_DESKTOP" >/dev/null 2>&1 || \
        m17_launcher_detail "admin desktop SELinux context differs"
    grep -qxF 'DBusActivatable=false' "$GNOME_SOFTWARE_ADMIN_DESKTOP" || \
        m17_launcher_detail "admin desktop direct-Exec selector differs"
    grep -qxF 'Exec=gnome-software %U' "$GNOME_SOFTWARE_ADMIN_DESKTOP" || \
        m17_launcher_detail "admin desktop Fedora Exec differs"
    grep -qxF "Actions=$m17_admin_actions" \
        "$GNOME_SOFTWARE_ADMIN_DESKTOP" || \
        m17_launcher_detail "admin desktop action list differs"
    [ "$(grep -c '^\[Desktop Action NoIDQuit\]$' \
        "$GNOME_SOFTWARE_ADMIN_DESKTOP" 2>/dev/null || true)" = 1 ] || \
        m17_launcher_detail "admin complete-quit action count differs"
    [ "$(grep -c '^\[Desktop Action NoIDFedoraRPM\]$' \
        "$GNOME_SOFTWARE_ADMIN_DESKTOP" 2>/dev/null || true)" = 1 ] || \
        m17_launcher_detail "admin Fedora-RPM action count differs"
    grep -qxF 'Exec=/usr/local/bin/noid-gnome-software-rpm' \
        "$GNOME_SOFTWARE_ADMIN_DESKTOP" || \
        m17_launcher_detail "admin Fedora-RPM action Exec differs"
    grep -qxF 'Exec=/usr/local/bin/noid-gnome-software-quit' \
        "$GNOME_SOFTWARE_ADMIN_DESKTOP" || \
        m17_launcher_detail "admin complete-quit action Exec differs"
    desktop-file-validate "$GNOME_SOFTWARE_ADMIN_DESKTOP" >/dev/null 2>&1 || \
        m17_launcher_detail "admin desktop validation failed"
    [ "$m17_launcher_expected_ok" -eq 1 ] || \
        m17_launcher_detail "vendor-derived comparison launcher generation failed"
    if [ "$m17_launcher_expected_ok" -eq 1 ] \
       && ! cmp -s "$m17_launcher_expected" \
            "$GNOME_SOFTWARE_ADMIN_DESKTOP"; then
        m17_launcher_detail "admin desktop differs from vendor-derived candidate"
    fi
    unset -f m17_launcher_detail
    log "  FAIL: GNOME Software Flatpak/RPM/complete-quit split invalid"
    fail=$((fail + 1))
else
    log "  OK: activation denied; default Flatpak-only; Fedora-RPM one-shot; complete quit idle-safe"
fi
rm -rf -- "$m17_launcher_tmp"
unset m17_vendor_actions_count m17_vendor_actions m17_admin_actions \
    m17_launcher_expected m17_launcher_expected_ok

# 7.5: dconf profile has expected sections
# grep -c prints "0" + exits 1 on zero matches. Using `|| echo 0` would then
# produce multi-line "0\n0" value that breaks -ne arithmetic. Use `|| true` +
# ${var:-0} default pattern (consistent with Module 03/11/12/14).
# bumped 15 → 17 after replacing Nautilus' ignored visibility key with the
# active GTK3 migration source and GTK4 runtime schema. Pre-bump verification
# would fail closed rather than ship an uncounted key.
expected_sections=17
actual_sections=$(grep -c '^\[org/' "$PRIVACY_PROFILE" 2>/dev/null || true)
actual_sections=${actual_sections:-0}
if [ "$actual_sections" -ne "$expected_sections" ]; then
    log "  FAIL: dconf profile sections: expected $expected_sections, got $actual_sections"
    fail=$((fail + 1))
else
    log "  OK: dconf profile has $actual_sections sections"
fi

# 7.6: dconf locks file has expected count (same pattern as above)
# 10 → 8 after the 2 org.gnome.system.location locks were
# removed (location rebuilt to the camera/microphone model — user-toggleable,
# not locked). Keep expected_locks in sync with grep -c '^/org/' (class).
expected_locks=8
actual_locks=$(grep -c '^/org/' "$PRIVACY_LOCKS" 2>/dev/null || true)
actual_locks=${actual_locks:-0}
if [ "$actual_locks" -ne "$expected_locks" ]; then
    log "  FAIL: dconf locks: expected $expected_locks, got $actual_locks"
    fail=$((fail + 1))
else
    log "  OK: $actual_locks security-critical locks"
fi

# 7.7: JIT selections are exact, explicit defaults. Runtime proof owns whether
# the installed GJS/WebKit versions honor them; this is only the byte contract.
JIT_ENV=/etc/environment.d/40-noid-disable-jit.conf
jit_active=$(awk '!/^[[:space:]]*(#|$)/ { print }' "$JIT_ENV" 2>/dev/null || true)
if [ ! -f "$JIT_ENV" ] || [ -L "$JIT_ENV" ] \
   || [ "$(stat -c '%U:%G:%a:%h' "$JIT_ENV" 2>/dev/null || true)" != root:root:644:1 ] \
   || ! matchpathcon -V "$JIT_ENV" >/dev/null 2>&1 \
   || [ "$jit_active" != $'JavaScriptCoreUseJIT=0\nGJS_DISABLE_JIT=1' ]; then
    log "  FAIL: evidence-bounded application-overridable JIT defaults invalid"
    fail=$((fail + 1))
fi

# 7.7b: strict Wayland defaults have exact bytes and metadata. This validates
# the selected default, not an unbypassable application/session boundary.
WAYLAND_ENV=/etc/environment.d/45-noid-wayland.conf
if [ ! -f "$WAYLAND_ENV" ] || [ -L "$WAYLAND_ENV" ] \
   || [ "$(stat -c '%U:%G:%a' "$WAYLAND_ENV" 2>/dev/null || true)" != root:root:644 ] \
   || [ "$(grep -cE '^(GDK_BACKEND|QT_QPA_PLATFORM)=' "$WAYLAND_ENV" 2>/dev/null || true)" -ne 2 ] \
   || ! grep -qxF 'GDK_BACKEND=wayland' "$WAYLAND_ENV" \
   || ! grep -qxF 'QT_QPA_PLATFORM=wayland' "$WAYLAND_ENV"; then
    log "  FAIL: strict application-overridable Wayland defaults invalid"
    fail=$((fail + 1))
fi

# 7.7c: the XDG administrator default is exact and its target is a validated
# Fedora desktop entry that advertises both MIME types.
MIME_DEFAULTS=/etc/xdg/mimeapps.list
TEXT_EDITOR_DESKTOP=/usr/share/applications/org.gnome.TextEditor.desktop
if [ ! -f "$MIME_DEFAULTS" ] || [ -L "$MIME_DEFAULTS" ] \
   || [ "$(stat -c '%U:%G:%a' "$MIME_DEFAULTS" 2>/dev/null || true)" != root:root:644 ] \
   || ! cmp -s "$MIME_DEFAULTS" <(printf '%s\n' \
        '[Default Applications]' \
        'application/x-zerosize=org.gnome.TextEditor.desktop;' \
        'text/plain=org.gnome.TextEditor.desktop;') \
   || [ ! -f "$TEXT_EDITOR_DESKTOP" ] || [ -L "$TEXT_EDITOR_DESKTOP" ] \
   || ! desktop-file-validate "$TEXT_EDITOR_DESKTOP" >/dev/null 2>&1 \
   || ! grep -qE '^MimeType=([^;]+;)*text/plain;' "$TEXT_EDITOR_DESKTOP" \
   || ! grep -qE '^MimeType=([^;]+;)*application/x-zerosize;' "$TEXT_EDITOR_DESKTOP"; then
    log "  FAIL: native GNOME Text Editor MIME default is invalid"
    fail=$((fail + 1))
fi

# 7.8: no Mutter experimental feature selected
if ! grep -q '^experimental-features=@as \[\]$' "$PRIVACY_PROFILE"; then
    log "  FAIL: mutter experimental-features line malformed"
    fail=$((fail + 1))
fi

# 7.9: Cross-ref check — Module 08 gnome-software profile should exist
if [ ! -f "$DCONF_DB_DIR/00-noid-gnome-software" ]; then
    log "  WARN: Module 08 gnome-software profile missing — order may be wrong"
fi

# 7.10: Required pinned Just-Perfection extension + dconf override + lock.
if [ ! -f "$JP_EXT_DIR/metadata.json" ]; then
    log "  FAIL: required Just-Perfection extension metadata missing"
    fail=$((fail + 1))
else
    # v27: pipefail-safe extraction (mirror v26 appindicator fix). A grep
    # no-match under `set -euo pipefail` returns non-zero and would KILL the
    # %post (the same ship-blocking failure class previously seen in
    # the pre-v26 appindicator line). Just-Perfection currently ships a
    # "version" key, but harden defensively against future metadata.json shape
    # drift. `|| true` + "unknown" fallback keeps the verify-log informative
    # without aborting.
    jp_installed_ver=$(grep -oE '"version": *[0-9]+' "$JP_EXT_DIR/metadata.json" 2>/dev/null | grep -oE '[0-9]+' | head -1 || true)
    [ -n "$jp_installed_ver" ] || jp_installed_ver="unknown"
    log "  OK: Just-Perfection extension v$jp_installed_ver installed ($JP_EXT_DIR)"
    if [ ! -f "$JP_EXT_DIR/schemas/gschemas.compiled" ]; then
        log "  FAIL: Just-Perfection gschemas.compiled missing"
        fail=$((fail + 1))
    fi
fi
if [ ! -f "${DCONF_DB_DIR}/15-noid-events-hide" ]; then
    log "  FAIL: ${DCONF_DB_DIR}/15-noid-events-hide missing"
    fail=$((fail + 1))
else
    if ! grep -q "events-button=false" "${DCONF_DB_DIR}/15-noid-events-hide"; then
        log "  FAIL: 15-noid-events-hide missing events-button=false"
        fail=$((fail + 1))
    fi
fi
if [ ! -f "${DCONF_LOCKS_DIR}/15-noid-events-hide" ]; then
    log "  FAIL: ${DCONF_LOCKS_DIR}/15-noid-events-hide lock missing"
    fail=$((fail + 1))
fi

# 7.10b: AppIndicator extension presence (RPM-installed
# via M26 gnome-shell-extension-appindicator). M26 MUST_PRESENT is the
# authoritative ship-gate for the RPM — here we only WARN if the extension
# dir is absent (tray-icon-using apps will lose their indicator, but no
# functional regression for non-tray apps).
APPINDICATOR_EXT_DIR="/usr/share/gnome-shell/extensions/appindicatorsupport@rgcjonas.gmail.com"
if [ ! -f "$APPINDICATOR_EXT_DIR/metadata.json" ]; then
    log "  WARN: AppIndicator extension not installed at $APPINDICATOR_EXT_DIR"
    log "        (apps with tray-icon-only features will lose their indicator —"
    log "         M26 v18 should install gnome-shell-extension-appindicator RPM)"
else
    # gnome-shell-extension-appindicator metadata.json ships only "shell-version"
    # (= GNOME-major-compat array), NOT a "version" field for the extension itself.
    # Different shape from Just-Perfection metadata.json. v26 fix: query rpm for
    # the package version as fallback when metadata.json lacks "version" — keeps
    # the log informative without pipefail-killing the script on grep no-match.
    # Pipeline wrapped with `|| true` to swallow grep-no-match under set -o
    # pipefail (script-wide).
    appindicator_ver=$(grep -oE '"version": *[0-9]+' "$APPINDICATOR_EXT_DIR/metadata.json" 2>/dev/null | grep -oE '[0-9]+' | head -1 || true)
    if [ -z "$appindicator_ver" ]; then
        appindicator_ver=$(rpm -q --qf '%{VERSION}' gnome-shell-extension-appindicator 2>/dev/null || echo "unknown")
    fi
    log "  OK: AppIndicator extension v$appindicator_ver installed ($APPINDICATOR_EXT_DIR)"
fi
# Verify enabled-extensions array in 15-noid-events-hide includes AppIndicator
if ! grep -q "appindicatorsupport@rgcjonas.gmail.com" "${DCONF_DB_DIR}/15-noid-events-hide" 2>/dev/null; then
    log "  FAIL: 15-noid-events-hide missing AppIndicator UUID in enabled-extensions"
    fail=$((fail + 1))
fi

# 7.11: systemd environment-generators for XDG_DATA_DIRS
# trailing-slash cleanup. Both system + user level must exist + be executable
# for the dbus-broker duplicate-name fix to work across GDM-greeter + all
# user sessions.
for gen_path in \
    /etc/systemd/system-environment-generators/99-noid-xdg-cleanup \
    /etc/systemd/user-environment-generators/99-noid-xdg-cleanup
do
    if [ ! -x "$gen_path" ]; then
        log "  FAIL: $gen_path missing or not executable (XDG-cleanup generator)"
        fail=$((fail + 1))
    fi
done

# 7.12: Privacy cleanup runs inside GNOME's ordered shutdown transaction.
CLEANUP_SVC_PATH="/etc/systemd/user/noid-gnome-shell-privacy-cleanup.service"
CLEANUP_HELPER_PATH="/usr/local/libexec/noid-gnome-privacy-cleanup"
CLEANUP_WANTS_PATH="/etc/systemd/user/gnome-session-shutdown.target.wants/noid-gnome-shell-privacy-cleanup.service"
if [ ! -f "$CLEANUP_SVC_PATH" ] || [ -L "$CLEANUP_SVC_PATH" ] \
   || [ "$(stat -c '%U:%G:%a' "$CLEANUP_SVC_PATH" 2>/dev/null || true)" != "root:root:644" ]; then
    log "  FAIL: $CLEANUP_SVC_PATH missing or metadata invalid"
    fail=$((fail + 1))
fi
if [ ! -x "$CLEANUP_HELPER_PATH" ] || [ -L "$CLEANUP_HELPER_PATH" ] \
   || [ "$(stat -c '%U:%G:%a' "$CLEANUP_HELPER_PATH" 2>/dev/null || true)" != "root:root:755" ] \
   || ! python3 -c 'import pathlib; p=pathlib.Path("/usr/local/libexec/noid-gnome-privacy-cleanup"); compile(p.read_bytes(), str(p), "exec")'; then
    log "  FAIL: $CLEANUP_HELPER_PATH missing, metadata invalid or Python-invalid"
    fail=$((fail + 1))
fi
if [ ! -L "$CLEANUP_WANTS_PATH" ] \
   || [ "$(readlink -f "$CLEANUP_WANTS_PATH" 2>/dev/null || true)" != "$CLEANUP_SVC_PATH" ]; then
    log "  FAIL: $CLEANUP_WANTS_PATH missing or targets the wrong unit"
    fail=$((fail + 1))
fi
if [ -f "$CLEANUP_SVC_PATH" ] \
   && { ! grep -qxF 'DefaultDependencies=no' "$CLEANUP_SVC_PATH" \
        || ! grep -qxF 'Before=gnome-session-shutdown.target gnome-session-restart-dbus.service' "$CLEANUP_SVC_PATH" \
        || ! grep -qxF 'ExecStart=/usr/local/libexec/noid-gnome-privacy-cleanup' "$CLEANUP_SVC_PATH" \
        || grep -q '^ExecStop=' "$CLEANUP_SVC_PATH"; }; then
    log "  FAIL: $CLEANUP_SVC_PATH shutdown ordering/execution contract invalid"
    fail=$((fail + 1))
fi

if [ "$fail" -gt 0 ]; then
    log "=== Module 17 FAILED with $fail errors ==="
    exit 1
fi

#------------------------------------------------------------------------------
# Step 7b: GNOME first-boot flow customization
#------------------------------------------------------------------------------
# vendor.conf skips the 4 pages already covered by NoID Privacy hardening (privacy/
# goa/software/parental-controls — rationale in GIS_VENDOR_EOF heredoc);
# welcome/language/keyboard/account/timezone stay user-facing. M26 excludes
# gnome-tour; the override below is retained only against a later weak-dep
# reinstall.

log "Step 7b/8: GNOME flow customization (initial-setup retirement + vendor.conf + gnome-tour reinstall guard)"

# 7b.0: retire only the GNOME Initial Setup kiosk session cleanly.
#
# Fedora/GDM deliberately presents the initial-setup greeter through its
# locked-down dconf profile. gnome-session 50.1 handles SIGTERM/SIGINT by
# requesting even a forced logout; the lockdown rejects that request and the
# manager remains alive until Fedora's global 45-second stop timeout aborts it.
# The account has already been handed to GDM and the GNOME session targets have
# stopped before systemd stops this manager. Use SIGHUP's normal session-hangup
# semantics for this one instance; systemd treats SIGHUP as a clean termination
# for a non-oneshot service. Keep GNOME's documented five-second stop bound as
# a fallback. Normal user sessions and the GDM lockdown remain unchanged.
GIS_SESSION_STOP_UNIT=gnome-session-manager@gnome-initial-setup.service
GIS_SESSION_STOP_DIR=/etc/systemd/user/gnome-session-manager@gnome-initial-setup.service.d
GIS_SESSION_STOP_CONF=$GIS_SESSION_STOP_DIR/50-noid-clean-stop.conf
mkdir -p "$GIS_SESSION_STOP_DIR"
chmod 0755 "$GIS_SESSION_STOP_DIR"
chown root:root "$GIS_SESSION_STOP_DIR"
restorecon -F "$GIS_SESSION_STOP_DIR"
cat > "$GIS_SESSION_STOP_CONF" <<'GIS_SESSION_STOP_EOF'
# NoID Privacy — clean retirement of GNOME Initial Setup's kiosk session
[Service]
KillSignal=SIGHUP
TimeoutStopSec=5s
GIS_SESSION_STOP_EOF
chmod 0644 "$GIS_SESSION_STOP_CONF"
chown root:root "$GIS_SESSION_STOP_CONF"
restorecon -F "$GIS_SESSION_STOP_CONF"

# `systemd-analyze verify` defaults to the system manager even when handed a
# user-unit path.  Even in user mode its dependency graph and generators can
# observe unrelated units being published concurrently by Anaconda's parallel
# %post scripts.  Give the native user-manager parser its required private
# runtime directory, disable generators and make only the literal requested
# instance fatal.  Invalid directives in this exact drop-in still fail.
GIS_VERIFY_RUNTIME=$(mktemp -d /run/noid-m17-systemd-verify.XXXXXXXX)
case "$GIS_VERIFY_RUNTIME" in
    /run/noid-m17-systemd-verify.*) ;;
    *)
        log "  FAIL: unsafe systemd user-unit verification directory"
        exit 1
        ;;
esac
chmod 0700 "$GIS_VERIFY_RUNTIME"
chown root:root "$GIS_VERIFY_RUNTIME"
gis_verify_rc=0
XDG_RUNTIME_DIR="$GIS_VERIFY_RUNTIME" systemd-analyze --user \
    --recursive-errors=no --generators=no verify "$GIS_SESSION_STOP_UNIT" \
    >"$GIS_VERIFY_RUNTIME/verify.log" 2>&1 || gis_verify_rc=$?
if [ "$gis_verify_rc" -ne 0 ]; then
    log "  systemd user-unit parser diagnostics:"
    sed -n '1,80p' "$GIS_VERIFY_RUNTIME/verify.log" >&2
fi
if ! find "$GIS_VERIFY_RUNTIME" -depth -delete; then
    log "  FAIL: could not retire systemd user-unit verification directory"
    exit 1
fi

if [ "$(stat -Lc '%U:%G:%a' "$GIS_SESSION_STOP_DIR")" != root:root:755 ] \
   || ! matchpathcon -V "$GIS_SESSION_STOP_DIR" >/dev/null 2>&1 \
   || [ "$(stat -Lc '%U:%G:%a:%h' "$GIS_SESSION_STOP_CONF")" != root:root:644:1 ] \
   || ! matchpathcon -V "$GIS_SESSION_STOP_CONF" >/dev/null 2>&1 \
   || [ "$(grep -c '^KillSignal=SIGHUP$' "$GIS_SESSION_STOP_CONF")" -ne 1 ] \
   || [ "$(grep -c '^TimeoutStopSec=5s$' "$GIS_SESSION_STOP_CONF")" -ne 1 ] \
   || [ "$gis_verify_rc" -ne 0 ]; then
    log "  FAIL: GNOME Initial Setup clean-stop instance contract invalid"
    exit 1
fi
log "  [OK] GNOME Initial Setup kiosk manager has an instance-only clean stop and 5s fallback"

# 7b.1-7b.3: single-writer helper + dnf5 recovery action.
# Three of the five flow files live at package-owned paths WITHOUT %config
# protection and are silently stomped by routine updates:
#   - /usr/share/gnome-initial-setup/vendor.conf (gnome-initial-setup, plain
#     payload file — an upgrade reverts the page-skip with no signal)
#   - /etc/xdg/autostart/geoclue-demo-agent.desktop (geoclue2, plain)
#   - /etc/xdg/autostart/org.gnome.Evolution-alarm-notify.desktop
#     (evolution-data-server, plain)
# localsearch-3.desktop is %config(noreplace) (update-safe, kept in the same
# writer for uniformity) and org.gnome.Tour.desktop is a NoID Privacy-owned
# override of the /usr/share/applications copy (unowned path, update-safe).
# Same recovery pattern as the launcher/identity actions: one idempotent
# helper owns all five writes; %post runs it once at build, a libdnf5-actions
# file re-runs it after transactions of the owning packages.
#
# M26 excludes gnome-tour in the image package transaction and verifies it is
# absent. Keep this NoID Privacy-owned path only as defense in depth: a later package
# transaction may reinstall the weak dependency, at which point Hidden=true +
# X-GNOME-Autostart-enabled=false still prevent automatic launch.
mkdir -p /usr/local/sbin
cat > /usr/local/sbin/noid-restore-gnome-flow <<'GNOME_FLOW_EOF'
#!/bin/bash
# noid-restore-gnome-flow — (re-)write the NoID Privacy GNOME first-boot flow
# files: gnome-initial-setup vendor.conf plus the autostart Hidden overrides.
# vendor.conf and two of the autostart targets are plain package-owned files
# (gnome-initial-setup / geoclue2 / evolution-data-server) that routine
# upgrades silently revert. Auto-invoked by /etc/dnf/libdnf5-plugins/
# actions.d/noid-gnome-flow.actions; safe to run manually. Idempotent.
set -euo pipefail

PATH=/usr/sbin:/usr/bin
export PATH

if [ "$#" -ne 0 ]; then
    printf '%s\n' \
        'noid-restore-gnome-flow: ERROR: this internal helper accepts no arguments' >&2
    exit 2
fi

LOG_TAG="noid-restore-gnome-flow"
log() { logger -t "$LOG_TAG" -- "$*" 2>/dev/null || true; echo "[$LOG_TAG] $*"; }
fail() { log "FAIL: $*"; exit 1; }
[ "$(id -u)" -eq 0 ] || fail "must run as root"

for command_name in cat chmod chown cmp id install logger matchpathcon mktemp \
        mv rm restorecon stat sync; do
    command -v "$command_name" >/dev/null 2>&1 || \
        fail "required command missing: $command_name"
done

flow_tmp=""
cleanup() {
    if [ -n "$flow_tmp" ] && [ -f "$flow_tmp" ] && [ ! -L "$flow_tmp" ]; then
        rm -f -- "$flow_tmp"
    fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

for flow_dir in /usr/share/gnome-initial-setup /etc/xdg/autostart; do
    if [ -e "$flow_dir" ] || [ -L "$flow_dir" ]; then
        [ -d "$flow_dir" ] && [ ! -L "$flow_dir" ] \
            && [ "$(stat -c '%U:%G:%a' "$flow_dir" 2>/dev/null || true)" = \
                root:root:755 ] \
            || fail "unsafe managed directory: $flow_dir"
    else
        install -d -m 0755 -o root -g root "$flow_dir" \
            || fail "cannot create managed directory: $flow_dir"
    fi
    restorecon -F "$flow_dir" || fail "cannot label managed directory: $flow_dir"
    matchpathcon -V "$flow_dir" >/dev/null 2>&1 \
        || fail "managed-directory SELinux context differs: $flow_dir"
done

changed=0
write_file() {
    # write_file <dst> — content on stdin; publish only when bytes differ
    local dst=$1
    if { [ -e "$dst" ] || [ -L "$dst" ]; } \
       && { [ ! -f "$dst" ] || [ -L "$dst" ]; }; then
        fail "unsafe managed target: $dst"
    fi
    flow_tmp=$(mktemp "${dst}.XXXXXXXX") || fail "mktemp failed for $dst"
    cat > "$flow_tmp" || fail "cannot stage bytes for $dst"
    chmod 0644 "$flow_tmp" || fail "cannot set candidate mode for $dst"
    chown root:root "$flow_tmp" || fail "cannot set candidate owner for $dst"
    sync -- "$flow_tmp" || fail "cannot sync candidate for $dst"
    if [ -f "$dst" ] && [ ! -L "$dst" ] \
       && [ "$(stat -c '%U:%G:%a:%h' "$dst" 2>/dev/null || true)" = \
            root:root:644:1 ] \
       && cmp -s "$flow_tmp" "$dst" \
       && matchpathcon -V "$dst" >/dev/null 2>&1; then
        rm -f -- "$flow_tmp"
        flow_tmp=""
        return 0
    fi
    mv -fT -- "$flow_tmp" "$dst" || fail "cannot publish $dst"
    flow_tmp=""
    restorecon -F "$dst" || fail "cannot label $dst"
    [ "$(stat -c '%U:%G:%a:%h' "$dst" 2>/dev/null || true)" = \
        root:root:644:1 ] || fail "published metadata differs for $dst"
    matchpathcon -V "$dst" >/dev/null 2>&1 \
        || fail "published SELinux context differs for $dst"
    sync -- "$dst" "${dst%/*}" || fail "cannot sync published $dst"
    changed=1
    log "restored: $dst"
}

write_file /usr/share/gnome-initial-setup/vendor.conf <<'VENDOR_EOF'
# NoID Privacy Workstation — gnome-initial-setup customization
# Skips pages that are either redundant with NoID Privacy dconf-locks, or with NoID Privacy
# Module 17 D-Bus overrides, or not relevant to a privacy-workstation use-case.
#
# Pages NOT skipped (intentionally user-facing):
#   - welcome (single branded page)
#   - language, keyboard (user choice)
#   - account (end-user account creation — liveuser is locked)
#   - timezone (user can adjust)

[pages]
skip=privacy;goa;software;parental-controls

[branding]
distro=NoID Privacy Workstation
VENDOR_EOF

write_file /etc/xdg/autostart/org.gnome.Tour.desktop <<'TOUR_EOF'
[Desktop Entry]
Type=Application
Name=GNOME Tour (disabled by NoID Privacy)
Comment=GNOME Tour autostart disabled — NoID Privacy welcome handles first-boot flow
Exec=/bin/true
Hidden=true
NoDisplay=true
X-GNOME-Autostart-enabled=false
TOUR_EOF

for autostart_target in \
    "localsearch-3.desktop|Tracker File System Miner" \
    "org.gnome.Evolution-alarm-notify.desktop|Evolution Alarm Notify" \
    "geoclue-demo-agent.desktop|Geoclue Demo Agent"
do
    fname="${autostart_target%%|*}"
    label="${autostart_target##*|}"
    write_file "/etc/xdg/autostart/${fname}" <<AUTOSTART_EOF
[Desktop Entry]
Type=Application
Name=${label} (disabled by NoID Privacy)
Comment=Autostart suppressed — NoID Privacy hardening
Exec=/bin/true
Hidden=true
NoDisplay=true
X-GNOME-Autostart-enabled=false
AUTOSTART_EOF
done

if [ "$changed" -eq 1 ]; then
    log "GNOME flow files re-applied after package transaction"
else
    log "GNOME flow files already current — no changes"
fi
trap - EXIT HUP INT TERM
exit 0
GNOME_FLOW_EOF
chmod 0755 /usr/local/sbin/noid-restore-gnome-flow
chown root:root /usr/local/sbin/noid-restore-gnome-flow
restorecon -F /usr/local/sbin/noid-restore-gnome-flow 2>/dev/null || true

mkdir -p /etc/dnf/libdnf5-plugins/actions.d
cat > /etc/dnf/libdnf5-plugins/actions.d/noid-gnome-flow.actions <<'GNOME_FLOW_ACTION_EOF'
# NoID Privacy — GNOME first-boot flow recovery for package payload stomps.
# gnome-initial-setup upgrades reinstall stock vendor.conf (drops the
# page-skip); geoclue2 / evolution-data-server upgrades reinstall their
# stock /etc/xdg/autostart entries (re-enable the suppressed autostarts).
# None of those files carry %config protection. The helper re-writes all
# NoID Privacy flow files idempotently.
# Format: callback:package_filter:direction:options:command
# (field semantics documented in noid-identity.actions).
post_transaction:gnome-initial-setup:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-restore-gnome-flow\ >/dev/null
post_transaction:geoclue2:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-restore-gnome-flow\ >/dev/null
post_transaction:evolution-data-server:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-restore-gnome-flow\ >/dev/null
GNOME_FLOW_ACTION_EOF
chmod 0644 /etc/dnf/libdnf5-plugins/actions.d/noid-gnome-flow.actions
chown root:root /etc/dnf/libdnf5-plugins/actions.d/noid-gnome-flow.actions
restorecon -F /etc/dnf/libdnf5-plugins/actions.d/noid-gnome-flow.actions 2>/dev/null || true

if /usr/local/sbin/noid-restore-gnome-flow; then
    log "  [OK] GNOME flow files written via noid-restore-gnome-flow (single writer)"
else
    log "  FAIL: noid-restore-gnome-flow initial run failed"
    fail=$((fail + 1))
fi

# 7b.4: Verification
if [ ! -f /usr/share/gnome-initial-setup/vendor.conf ]; then
    log "  FAIL: vendor.conf write missing"
    fail=$((fail + 1))
fi
if ! grep -q '^skip=privacy;goa;software;parental-controls$' /usr/share/gnome-initial-setup/vendor.conf 2>/dev/null; then
    log "  FAIL: vendor.conf skip line malformed"
    fail=$((fail + 1))
fi
if ! grep -q '^Hidden=true$' /etc/xdg/autostart/org.gnome.Tour.desktop 2>/dev/null; then
    log "  FAIL: gnome-tour autostart override Hidden=true missing"
    fail=$((fail + 1))
fi
for fname in localsearch-3.desktop org.gnome.Evolution-alarm-notify.desktop geoclue-demo-agent.desktop; do
    if ! grep -q '^Hidden=true$' "/etc/xdg/autostart/${fname}" 2>/dev/null; then
        log "  FAIL: ${fname} Hidden=true override missing"
        fail=$((fail + 1))
    fi
done
if [ ! -x /usr/local/sbin/noid-restore-gnome-flow ]; then
    log "  FAIL: noid-restore-gnome-flow helper missing or not executable"
    fail=$((fail + 1))
fi
for flow_pkg in gnome-initial-setup geoclue2 evolution-data-server; do
    if ! grep -qxF \
        "post_transaction:${flow_pkg}:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-restore-gnome-flow\\ >/dev/null" \
        /etc/dnf/libdnf5-plugins/actions.d/noid-gnome-flow.actions 2>/dev/null; then
        log "  FAIL: noid-gnome-flow.actions trigger missing: ${flow_pkg}"
        fail=$((fail + 1))
    fi
done
unset flow_pkg

if [ "$fail" -gt 0 ]; then
    log "=== Module 17 FAILED at Step 7b with $fail errors ==="
    exit 1
fi

#------------------------------------------------------------------------------
# Step 7c: Live-mode GDM auto-login + graphical.target default
#------------------------------------------------------------------------------
# Fills the GNOME-flavor livesys gaps via the livesys-session-extra hook:
# (1) autouser=0 trap — with gnome-initial-setup installed, livesys-main
# never unlocks liveuser (account stays LOCKED); (2) livesys-gnome writes
# AutomaticLogin only under its own runtime conditions and provides no timed
# logout recovery, so M17 converges both for the NoID Privacy Live path;
# (3) liveuser
# is created before M08 populates /etc/skel, so its always-present
# VSCodium/Claude privacy templates otherwise never reach the Live home.
# Live-mode-ONLY safety: livesys.service is rd.live.image-conditioned and the
# M41 noid-anaconda-cleanup safety net removes liveuser + login policy on
# install. Per-gap detail is in LIVESYS_EXTRA_EOF.

log "Step 7c/8: Live-mode GDM auto-login + graphical.target default"

# 7c.0: livesys_session=gnome enables the stock livesys-gnome session
# script (installer .desktop rename + NoDisplay flip + the polkit rule that
# lets liveuser run liveinst without admin auth + dock favorite) — the
# canonical Fedora workflow; a custom installer .desktop without the polkit
# rule yields a dead auth prompt.
echo "[Step 7c.0] /etc/sysconfig/livesys: livesys_session=gnome"
# Surface which path triggered (sed-update vs
# create-fallback) for debugging clarity. The sed targets an existing
# `livesys_session=` line; if /etc/sysconfig/livesys doesn't exist or has no
# matching line, fall through to creating a fresh file with the required line.
if sed -i 's|^livesys_session=.*|livesys_session=gnome|' /etc/sysconfig/livesys 2>/dev/null \
        && grep -q '^livesys_session=gnome$' /etc/sysconfig/livesys 2>/dev/null; then
    log "  [OK] /etc/sysconfig/livesys: livesys_session=gnome (sed-updated existing)"
else
    echo 'livesys_session=gnome' > /etc/sysconfig/livesys
    log "  [OK] /etc/sysconfig/livesys: livesys_session=gnome (created fresh — sed had no target line)"
fi

# 7c.0a: Keep Fedora's package-owned /usr/bin/liveinst pristine while giving
# every supported Live launch (desktop or shell) Fedora's public system-file
# umask. A direct launch from an interactive Live shell can inherit the privacy
# workstation's 0027 umask; Anaconda/Dracut otherwise carry that restrictive
# process umask into the target run.
# Dracut's iSCSI module creates public systemd units/drop-ins with ordinary
# mkdir/redirection, embedding 0750/0640 files in the first installed
# initramfs and making systemd report them as world-inaccessible. /usr/local
# precedes /usr in Fedora's normal PATH, so this narrow wrapper covers the
# existing `Exec=liveinst` launcher and a direct shell invocation without
# changing Fedora's executable or polkit action. M41 retires only these exact
# bytes before the installed graphical login is released.
LIVEINST_UMASK_WRAPPER=/usr/local/bin/liveinst
if [ -e "$LIVEINST_UMASK_WRAPPER" ] || [ -L "$LIVEINST_UMASK_WRAPPER" ]; then
    log "  FAIL: reserved Live-installer wrapper path already exists"
    exit 1
fi
install -d -o root -g root -m 0755 /usr/local/bin
cat > "$LIVEINST_UMASK_WRAPPER" <<'NOID_LIVEINST_UMASK_EOF'
#!/usr/bin/bash
umask 022
exec /usr/bin/liveinst "$@"
NOID_LIVEINST_UMASK_EOF
chown root:root "$LIVEINST_UMASK_WRAPPER"
chmod 0755 "$LIVEINST_UMASK_WRAPPER"
restorecon -F "$LIVEINST_UMASK_WRAPPER"
hash -r
if [ "$(stat -c '%U:%G:%a:%h' "$LIVEINST_UMASK_WRAPPER" 2>/dev/null)" != \
        root:root:755:1 ] \
   || ! matchpathcon -V "$LIVEINST_UMASK_WRAPPER" >/dev/null \
   || ! cmp -s "$LIVEINST_UMASK_WRAPPER" <(cat <<'NOID_LIVEINST_UMASK_POST_EOF'
#!/usr/bin/bash
umask 022
exec /usr/bin/liveinst "$@"
NOID_LIVEINST_UMASK_POST_EOF
); then
    log "  FAIL: Live-installer public-umask wrapper postcondition failed"
    exit 1
fi

# 7c.0b: Bind Fedora's auxiliary root WebUI service to its actual browser
# lifecycle without modifying any RPM-owned Anaconda file. Fedora liveinst
# writes /run/anaconda/webui_script.pid immediately after starting the exact
# `/usr/libexec/anaconda/webui-desktop -t live` process. A Live-only systemd
# path unit consumes the close-after-write event; the companion validates the
# root-owned PID record and exact argv, opens a Linux pidfd (no PID-reuse race),
# waits for that process instance to exit, then stops only
# webui-cockpit-ws.service. systemd's control-group stop owns all descendants.
# Invalid/stale lifecycle state is visible as a failed companion unit and still
# attempts the same narrow service stop rather than leaving a root listener.
mkdir -p /usr/local/libexec /usr/lib/systemd/system \
    /etc/systemd/system/multi-user.target.wants
cat > /usr/local/libexec/noid-liveinst-webui-lifecycle <<'NOID_LIVEINST_WEBUI_LIFECYCLE_EOF'
#!/usr/bin/python3
"""Bind Fedora's Live-installer WebUI service to the exact WebUI process."""

from __future__ import annotations

import os
import re
import select
import stat
import subprocess
import sys
import time
from pathlib import Path


CMDLINE = Path("/proc/cmdline")
PID_FILE = Path("/run/anaconda/webui_script.pid")
PROC_ROOT = Path("/proc")
SYSTEMCTL = "/usr/bin/systemctl"
SERVICE = "webui-cockpit-ws.service"
WEBUI_SCRIPT = "/usr/libexec/anaconda/webui-desktop"
REQUIRED_UID = 0
REQUIRED_GID = 0
PIDFILE_ATTEMPTS = 50
PIDFILE_RETRY_SECONDS = 0.1


class LifecycleError(RuntimeError):
    """A lifecycle identity or postcondition could not be proven."""


def _is_live_boot() -> bool:
    try:
        tokens = CMDLINE.read_text(encoding="utf-8").split()
    except (OSError, UnicodeError) as exc:
        raise LifecycleError(f"cannot read kernel command line: {exc}") from exc
    return "rd.live.image" in tokens


def _read_pid_file() -> int:
    try:
        parent = os.lstat(PID_FILE.parent)
    except OSError as exc:
        raise LifecycleError(f"cannot inspect PID-file directory: {exc}") from exc
    if not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode):
        raise LifecycleError("PID-file parent is not a real directory")
    if parent.st_uid != REQUIRED_UID or parent.st_gid != REQUIRED_GID:
        raise LifecycleError("PID-file parent ownership differs")
    if parent.st_mode & 0o022:
        raise LifecycleError("PID-file parent is group/other-writable")

    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        descriptor = os.open(PID_FILE, flags)
    except OSError as exc:
        raise LifecycleError(f"cannot safely open WebUI PID file: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise LifecycleError("WebUI PID file is not one regular inode")
        if metadata.st_uid != REQUIRED_UID or metadata.st_gid != REQUIRED_GID:
            raise LifecycleError("WebUI PID-file ownership differs")
        if metadata.st_mode & 0o022:
            raise LifecycleError("WebUI PID file is group/other-writable")
        payload = os.read(descriptor, 64)
        if os.read(descriptor, 1):
            raise LifecycleError("WebUI PID file exceeds the closed format")
    finally:
        os.close(descriptor)

    if not re.fullmatch(rb"[1-9][0-9]*\n?", payload):
        raise LifecycleError("WebUI PID file is not one canonical decimal PID")
    pid = int(payload)
    if pid <= 1:
        raise LifecycleError("WebUI PID is outside the allowed process range")
    return pid


def _proc_bytes(pid: int, name: str) -> bytes:
    try:
        return (PROC_ROOT / str(pid) / name).read_bytes()
    except OSError as exc:
        raise LifecycleError(f"cannot read /proc/{pid}/{name}: {exc}") from exc


def _validate_webui_process(pid: int) -> None:
    status_lines = _proc_bytes(pid, "status").splitlines()
    uid_lines = [line for line in status_lines if line.startswith(b"Uid:")]
    if len(uid_lines) != 1:
        raise LifecycleError("WebUI process has no unique Uid record")
    try:
        uid_fields = [int(field) for field in uid_lines[0].split()[1:]]
    except ValueError as exc:
        raise LifecycleError("WebUI process Uid record is malformed") from exc
    if uid_fields != [REQUIRED_UID] * 4:
        raise LifecycleError("WebUI process is not entirely root-owned")

    arguments = _proc_bytes(pid, "cmdline").rstrip(b"\0").split(b"\0")
    expected_tail = [os.fsencode(WEBUI_SCRIPT), b"-t", b"live"]
    if len(arguments) != 4:
        raise LifecycleError("WebUI process argument count differs")
    if arguments[0] not in (b"/usr/bin/bash", b"/bin/bash"):
        raise LifecycleError("WebUI process interpreter differs")
    if arguments[1:] != expected_tail:
        raise LifecycleError("WebUI process command line differs")


def _bind_webui_pidfd() -> tuple[int, int]:
    last_error: LifecycleError | None = None
    for attempt in range(PIDFILE_ATTEMPTS):
        pidfd = -1
        try:
            pid = _read_pid_file()
            try:
                pidfd = os.pidfd_open(pid, 0)
            except OSError as exc:
                raise LifecycleError(f"cannot open pidfd for WebUI PID {pid}: {exc}") from exc
            poller = select.poll()
            poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
            if poller.poll(0):
                raise LifecycleError("WebUI process exited before identity validation")
            _validate_webui_process(pid)
            if poller.poll(0):
                raise LifecycleError("WebUI process exited during identity validation")
            return pidfd, pid
        except LifecycleError as exc:
            last_error = exc
            if pidfd >= 0:
                os.close(pidfd)
            if attempt + 1 < PIDFILE_ATTEMPTS:
                time.sleep(PIDFILE_RETRY_SECONDS)
    raise last_error or LifecycleError("WebUI PID binding failed without a diagnostic")


def _wait_for_exit(pidfd: int) -> None:
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    while True:
        try:
            events = poller.poll()
        except InterruptedError:
            continue
        if events:
            return


def _stop_webui_service() -> None:
    try:
        stopped = subprocess.run(
            [SYSTEMCTL, "stop", SERVICE],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise LifecycleError(f"cannot stop {SERVICE}: {exc}") from exc
    if stopped.returncode != 0:
        detail = stopped.stderr.strip() or f"exit {stopped.returncode}"
        raise LifecycleError(f"failed to stop {SERVICE}: {detail}")

    try:
        shown = subprocess.run(
            [
                SYSTEMCTL,
                "show",
                SERVICE,
                "--property=ActiveState",
                "--property=SubState",
                "--property=MainPID",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise LifecycleError(f"cannot inspect {SERVICE} postcondition: {exc}") from exc
    if shown.returncode != 0:
        detail = shown.stderr.strip() or f"exit {shown.returncode}"
        raise LifecycleError(f"cannot inspect {SERVICE} postcondition: {detail}")
    properties: dict[str, str] = {}
    for line in shown.stdout.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in properties:
            raise LifecycleError("service postcondition output is not a unique key/value set")
        properties[key] = value
    expected = {"ActiveState": "inactive", "SubState": "dead", "MainPID": "0"}
    if properties != expected:
        raise LifecycleError(f"service postcondition differs: {properties!r}")


def main(argv: list[str]) -> int:
    if argv:
        print(
            "noid-liveinst-webui-lifecycle: ERROR: "
            "this internal helper accepts no arguments",
            file=sys.stderr,
        )
        return 2

    try:
        if not _is_live_boot():
            print("noid-liveinst-webui-lifecycle: non-Live root; no action")
            return 0
    except LifecycleError as exc:
        print(f"noid-liveinst-webui-lifecycle: ERROR: {exc}", file=sys.stderr)
        return 1

    pidfd = -1
    pid: int | None = None
    try:
        pidfd, pid = _bind_webui_pidfd()
        print(f"noid-liveinst-webui-lifecycle: bound WebUI PID {pid}")
        _wait_for_exit(pidfd)
        _stop_webui_service()
    except LifecycleError as exc:
        # A malformed/stale Fedora lifecycle record must not leave the known
        # Live-only root WebUI listener behind. Stop only its exact unit and
        # retain a failed companion unit so the drift is visible.
        cleanup_error: LifecycleError | None = None
        try:
            _stop_webui_service()
        except LifecycleError as stop_exc:
            cleanup_error = stop_exc
        detail = str(exc)
        if cleanup_error is not None:
            detail += f"; fail-closed stop also failed: {cleanup_error}"
        print(f"noid-liveinst-webui-lifecycle: ERROR: {detail}", file=sys.stderr)
        return 1
    finally:
        if pidfd >= 0:
            os.close(pidfd)
    print(f"noid-liveinst-webui-lifecycle: stopped {SERVICE} after WebUI PID {pid}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
NOID_LIVEINST_WEBUI_LIFECYCLE_EOF
chmod 0755 /usr/local/libexec/noid-liveinst-webui-lifecycle
chown root:root /usr/local/libexec/noid-liveinst-webui-lifecycle

cat > /usr/lib/systemd/system/noid-liveinst-webui-lifecycle.service <<'NOID_LIVEINST_WEBUI_SERVICE_EOF'
[Unit]
Description=NoID Privacy — bind Live installer Cockpit WebUI to its browser lifecycle
Documentation=file:///usr/share/doc/noid-privacy/17-gnome-hardening.md
ConditionKernelCommandLine=rd.live.image
After=webui-cockpit-ws.service

[Service]
Type=oneshot
ExecStart=/usr/local/libexec/noid-liveinst-webui-lifecycle
TimeoutStartSec=infinity
KillMode=control-group
NoNewPrivileges=yes
PrivateDevices=yes
PrivateTmp=yes
ProtectClock=yes
ProtectControlGroups=yes
ProtectHome=yes
ProtectHostname=yes
ProtectKernelLogs=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectSystem=strict
RestrictAddressFamilies=AF_UNIX
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
CapabilityBoundingSet=
SystemCallArchitectures=native
UMask=0077
NOID_LIVEINST_WEBUI_SERVICE_EOF

cat > /usr/lib/systemd/system/noid-liveinst-webui-lifecycle.path <<'NOID_LIVEINST_WEBUI_PATH_EOF'
[Unit]
Description=NoID Privacy — observe Fedora Live-installer WebUI lifecycle record
Documentation=file:///usr/share/doc/noid-privacy/17-gnome-hardening.md
ConditionKernelCommandLine=rd.live.image

[Path]
PathChanged=/run/anaconda/webui_script.pid
Unit=noid-liveinst-webui-lifecycle.service

[Install]
WantedBy=multi-user.target
NOID_LIVEINST_WEBUI_PATH_EOF

chmod 0644 \
    /usr/lib/systemd/system/noid-liveinst-webui-lifecycle.service \
    /usr/lib/systemd/system/noid-liveinst-webui-lifecycle.path
chown root:root \
    /usr/lib/systemd/system/noid-liveinst-webui-lifecycle.service \
    /usr/lib/systemd/system/noid-liveinst-webui-lifecycle.path
ln -sfn /usr/lib/systemd/system/noid-liveinst-webui-lifecycle.path \
    /etc/systemd/system/multi-user.target.wants/noid-liveinst-webui-lifecycle.path

# 7c.0c: Remove Anaconda's synchronous full-tree scan from the normal Live GUI
# startup path through Fedora's own supported liveinst updates mechanism.
#
# Anaconda 44.30's Live source task runs `du --bytes --summarize` across the
# complete mounted SquashFS before the WebUI becomes usable. On the reference
# image that is 128,769 entries and accounts for the reproduced multi-second
# click-to-window pause. Lorax already owns the final mounted tree immediately
# before mksquashfs; the private, exact-version compose override computes the
# same value there once and writes a strict manifest below /boot/loader.
#
# Keep /usr/bin/liveinst and the package-owned Anaconda module byte-pristine in
# the SquashFS. Fedora liveinst natively accepts --updates=file://... and applies
# a gzip-cpio overlay before importing Anaconda. The overlay changes only the
# exact initialization.py derivative embedded below. Missing, malformed,
# symlinked, misowned, writable, out-of-range or version-mismatched manifest
# data falls back to Fedora's original du implementation.
log "  Build native Live-installer required-space updates overlay"

if [ "$(rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' anaconda-core)" != \
        "$ANACONDA_CORE_NEVRA" ] \
   || [ "$(rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' anaconda-live)" != \
        "$ANACONDA_LIVE_NEVRA" ]; then
    log "  FAIL: unsupported Anaconda package identity for Live updates overlay"
    exit 1
fi
expected_anaconda_init_dump="$ANACONDA_VENDOR_LIVE_OS_INIT 6790 1774530610 0dbcdeccf8d9ee0a1e36700b32adf3d0ef9eef7b9ea310386c60996439c946b6 0100644 root root 0 0 0 X"
actual_anaconda_init_dump=$(rpm -q --dump anaconda-core \
    | awk -v path="$ANACONDA_VENDOR_LIVE_OS_INIT" '$1 == path { print; count++ } END { if (count != 1) exit 1 }') \
    || {
        log "  FAIL: cannot resolve unique package metadata for Anaconda Live source"
        exit 1
    }
expected_liveinst_dump="$ANACONDA_VENDOR_LIVEINST 9203 1774530610 99fa227f7ec0e2ae79dcf648fafa316b79c384d173c886385cb9879c890eef59 0100755 root root 0 0 0 X"
actual_liveinst_dump=$(rpm -q --dump anaconda-live \
    | awk -v path="$ANACONDA_VENDOR_LIVEINST" '$1 == path { print; count++ } END { if (count != 1) exit 1 }') \
    || {
        log "  FAIL: cannot resolve unique package metadata for liveinst"
        exit 1
    }
if [ "$actual_anaconda_init_dump" != "$expected_anaconda_init_dump" ] \
   || [ "$actual_liveinst_dump" != "$expected_liveinst_dump" ] \
   || [ "$(sha256sum "$ANACONDA_VENDOR_LIVE_OS_INIT" | awk '{print $1}')" != \
        "0dbcdeccf8d9ee0a1e36700b32adf3d0ef9eef7b9ea310386c60996439c946b6" ] \
   || [ "$(sha256sum "$ANACONDA_VENDOR_LIVEINST" | awk '{print $1}')" != \
        "99fa227f7ec0e2ae79dcf648fafa316b79c384d173c886385cb9879c890eef59" ]; then
    log "  FAIL: Anaconda Live source or liveinst differs from the reviewed RPM payload"
    exit 1
fi
if [ ! -f "$LIVEINST_VENDOR_DESKTOP" ] \
   || [ -L "$LIVEINST_VENDOR_DESKTOP" ] \
   || [ "$(stat -c '%U:%G:%a:%h' "$LIVEINST_VENDOR_DESKTOP")" != root:root:644:1 ] \
   || [ "$(grep -Fxc 'Exec=liveinst' "$LIVEINST_VENDOR_DESKTOP" || true)" -ne 1 ] \
   || grep -q '^Exec=.*--updates=' "$LIVEINST_VENDOR_DESKTOP"; then
    log "  FAIL: branded liveinst desktop contract differs before updates wiring"
    exit 1
fi

for liveinst_update_parent in /boot /boot/loader; do
    liveinst_update_parent_meta=$(stat -c '%u:%g:%a' \
        "$liveinst_update_parent" 2>/dev/null || true)
    liveinst_update_parent_mode=${liveinst_update_parent_meta##*:}
    if [ ! -d "$liveinst_update_parent" ] \
       || [ -L "$liveinst_update_parent" ] \
       || [[ ! "$liveinst_update_parent_meta" =~ ^0:0:[0-7]{3,4}$ ]] \
       || (( (8#$liveinst_update_parent_mode & 8#022) != 0 )); then
        log "  FAIL: unsafe Live-installer updates parent: $liveinst_update_parent"
        exit 1
    fi
done
if [ -L "$LIVEINST_UPDATE_DIR" ] \
   || { [ -e "$LIVEINST_UPDATE_DIR" ] && [ ! -d "$LIVEINST_UPDATE_DIR" ]; }; then
    log "  FAIL: unsafe pre-existing Live-installer updates directory"
    exit 1
fi
install -d -m 0755 -o root -g root "$LIVEINST_UPDATE_DIR"
if [ "$(stat -c '%u:%g:%a' "$LIVEINST_UPDATE_DIR" 2>/dev/null || true)" != \
        0:0:755 ] \
   || [ -L "$LIVEINST_UPDATE_DIR" ]; then
    log "  FAIL: Live-installer updates directory postcondition differs"
    exit 1
fi
liveinst_update_stage=$(mktemp -d /var/tmp/noid-liveinst-update.XXXXXXXX)
liveinst_update_candidate=$(mktemp "$LIVEINST_UPDATE_DIR/.liveinst-updates.img.XXXXXXXX")
noid_liveinst_update_cleanup() {
    rm -rf -- "$liveinst_update_stage"
    rm -f -- "$liveinst_update_candidate"
}
trap noid_liveinst_update_cleanup EXIT
trap 'exit 1' HUP INT TERM

liveinst_update_root="$liveinst_update_stage/root"
liveinst_update_extract="$liveinst_update_stage/extracted"
liveinst_update_source="$liveinst_update_root$ANACONDA_VENDOR_LIVE_OS_INIT"
install -d -m 0755 -o root -g root \
    "$(dirname "$liveinst_update_source")" "$liveinst_update_extract"
cat > "$liveinst_update_source" <<'NOID_LIVEINST_REQUIRED_SPACE_EOF'
#
# Copyright (C) 2019 Red Hat, Inc.
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions of
# the GNU General Public License v.2, or (at your option) any later version.
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY expressed or implied, including the implied warranties of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General
# Public License for more details.  You should have received a copy of the
# GNU General Public License along with this program; if not, write to the
# Free Software Foundation, Inc., 31 Milk Street #960789 Boston, MA
# 02196 USA.  Any Red Hat trademarks that are incorporated in the
# source code or documentation are not subject to the GNU General Public
# License and may only be used or replicated with the express permission of
# Red Hat, Inc.
#
# NoID Privacy modification notice (2026-07-27): a Live-media-only updates.img
# overlay can consume a strict Lorax-generated required-space manifest and
# otherwise falls back to Fedora's original du calculation below.
#
import os
import re
import stat
from collections import namedtuple

import blivet.util
from blivet.size import Size

from pyanaconda.anaconda_loggers import get_module_logger
from pyanaconda.core.util import execWithCapture
from pyanaconda.modules.common.constants.objects import DEVICE_TREE
from pyanaconda.modules.common.constants.services import STORAGE
from pyanaconda.modules.common.errors.payload import SourceSetupError
from pyanaconda.modules.common.structures.storage import DeviceData
from pyanaconda.modules.common.task import Task
from pyanaconda.modules.payloads.source.mount_tasks import SetUpMountTask

log = get_module_logger(__name__)

SetupLiveOSResult = namedtuple("SetupLiveOSResult", ["required_space"])

REQUIRED_SPACE_MANIFEST_PARTS = (
    "boot",
    "loader",
    "noid-privacy",
    "live-required-space-v1",
)
REQUIRED_SPACE_MANIFEST_MAGIC = b"NOID_LIVE_REQUIRED_SPACE_V1"
REQUIRED_SPACE_MANIFEST_HEADROOM = 64 * 1024 * 1024
REQUIRED_SPACE_MANIFEST_UID = 0
REQUIRED_SPACE_MANIFEST_GID = 0
REQUIRED_SPACE_MANIFEST_MODE = 0o644
REQUIRED_SPACE_MINIMUM = 1024 * 1024 * 1024
REQUIRED_SPACE_MAXIMUM = (1 << 63) - 1
SUPPORTED_ANACONDA_BASE_SHA256 = (
    b"0dbcdeccf8d9ee0a1e36700b32adf3d0ef9eef7b9ea310386c60996439c946b6"
)


class DetectLiveOSImageTask(Task):
    """Detect a Live OS image in the system."""

    @property
    def name(self):
        return "Detect a Live OS image"

    def run(self):
        """Run the task.

        Check /run/rootfsbase to detect a squashfs+overlayfs base image.

        :return: a path of a block device or None
        """
        block_device = \
            self._check_block_device("/dev/mapper/live-base") or \
            self._check_block_device("/dev/mapper/live-osimg-min") or \
            self._check_mount_point("/run/rootfsbase")

        if not block_device:
            raise SourceSetupError("No Live OS image found!")

        log.debug("Detected the Live OS image '%s'.", block_device)
        return block_device

    def _check_block_device(self, block_device):
        """Check the specified block device."""
        log.debug("Checking the %s block device.", block_device)

        try:
            if stat.S_ISBLK(os.stat(block_device)[stat.ST_MODE]):
                return block_device
        except FileNotFoundError:
            pass

        return None

    def _check_mount_point(self, mount_point):
        """Check a block device at the specified mount point."""
        log.debug("Checking the %s mount point.", mount_point)

        if not os.path.exists(mount_point):
            return None

        try:
            block_device = execWithCapture("findmnt", ["-n", "-o", "SOURCE", mount_point]).strip()
            return block_device or None
        except (OSError, FileNotFoundError):
            pass

        return None


class SetUpLiveOSSourceTask(SetUpMountTask):
    """Task to set up a Live OS image."""

    def __init__(self, image_path, target_mount):
        """Create a new task.

        :param image_path: a path to a Live OS image
        :param target_mount: a path to a mount point
        """
        super().__init__(target_mount)
        self._image_path = image_path

    def run(self):
        """Run the task."""
        super().run()

        required_space = self._calculate_required_space()
        return SetupLiveOSResult(required_space=required_space)

    def _read_precalculated_required_space(self):
        """Read the strict compose-time size manifest from the mounted source."""
        current = self._target_mount
        try:
            for component in REQUIRED_SPACE_MANIFEST_PARTS[:-1]:
                current = os.path.join(current, component)
                metadata = os.lstat(current)
                if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                    raise ValueError("a manifest parent is not a real directory")
                if metadata.st_uid != REQUIRED_SPACE_MANIFEST_UID \
                        or metadata.st_gid != REQUIRED_SPACE_MANIFEST_GID:
                    raise ValueError("manifest parent ownership differs")
                if metadata.st_mode & 0o022:
                    raise ValueError("a manifest parent is group/other-writable")

            manifest_path = os.path.join(
                self._target_mount,
                *REQUIRED_SPACE_MANIFEST_PARTS,
            )
            descriptor = os.open(
                manifest_path,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
            )
            try:
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise ValueError("manifest is not one regular inode")
                if metadata.st_uid != REQUIRED_SPACE_MANIFEST_UID \
                        or metadata.st_gid != REQUIRED_SPACE_MANIFEST_GID:
                    raise ValueError("manifest ownership differs")
                if stat.S_IMODE(metadata.st_mode) != REQUIRED_SPACE_MANIFEST_MODE:
                    raise ValueError("manifest mode differs")
                payload = os.read(descriptor, 256)
                if os.read(descriptor, 1):
                    raise ValueError("manifest exceeds the closed format")
            finally:
                os.close(descriptor)
        except FileNotFoundError:
            log.debug("No compose-time Live OS required-space manifest is available.")
            return None
        except (OSError, ValueError) as error:
            log.warning(
                "Ignoring invalid compose-time Live OS required-space manifest: %s",
                error,
            )
            return None

        pattern = (
            re.escape(REQUIRED_SPACE_MANIFEST_MAGIC)
            + rb"\nbytes=([0-9]{20})"
            + rb"\nheadroom="
            + str(REQUIRED_SPACE_MANIFEST_HEADROOM).encode("ascii")
            + rb"\nanaconda_base_sha256="
            + re.escape(SUPPORTED_ANACONDA_BASE_SHA256)
            + rb"\n"
        )
        match = re.fullmatch(pattern, payload)
        if not match:
            log.warning(
                "Ignoring malformed compose-time Live OS required-space manifest."
            )
            return None

        required_space = int(match.group(1))
        if not REQUIRED_SPACE_MINIMUM <= required_space <= REQUIRED_SPACE_MAXIMUM:
            log.warning(
                "Ignoring out-of-range compose-time Live OS required-space value."
            )
            return None
        log.info(
            "Using compose-time Live OS required space: %s",
            Size(required_space),
        )
        return required_space

    def _calculate_required_space(self):
        """
        Calculate the disk space required for the live OS.

        Prefer the strict compose-time manifest when this exact downstream
        Live image supplies one. Missing or invalid metadata retains Fedora's
        original full-tree calculation as a correctness fallback.
        """
        precalculated_space = self._read_precalculated_required_space()
        if precalculated_space is not None:
            return precalculated_space

        exclude_patterns = [
            "/dev/",
            "/proc/",
            "/tmp/*",
            "/sys/",
            "/run/",
            "/boot/*rescue*",
            "/boot/loader/",
            "/boot/efi/loader/",
            "/etc/machine-id",
            "/etc/machine-info"
        ]

        # Build the `du` command
        du_cmd_args = ["--bytes", "--summarize", self._target_mount]
        for pattern in exclude_patterns:
            du_cmd_args.extend(["--exclude", f"{self._target_mount}{pattern}"])

        try:
            # Execute the `du` command
            result = execWithCapture("du", du_cmd_args)
            # Parse the output for the total size
            # When du has errors, it outputs error messages but the summary is on the last line
            lines = result.strip().split('\n')
            # Get the last line which contains the summary
            last_line = lines[-1]
            required_space = last_line.split()[0]  # First column is the total
            log.debug("Required space: %s", Size(required_space))
            return int(required_space)
        except (OSError, FileNotFoundError) as e:
            raise SourceSetupError(str(e)) from e

    @property
    def name(self):
        return "Set up a Live OS image"

    def _do_mount(self):
        """Run live installation source setup.

        Mount the live device and copy from it instead of the overlay at /.
        """
        device_path = self._get_device_path()
        self._mount_device(device_path)

    def _get_device_path(self):
        """Get a device path of the block device."""
        log.debug("Resolving %s.", self._image_path)
        device_tree = STORAGE.get_proxy(DEVICE_TREE)

        # Get the device name.
        device_id = device_tree.ResolveDevice(self._image_path)

        if not device_id:
            raise SourceSetupError("Failed to resolve the Live OS image.")

        # Get the device path.
        device_data = DeviceData.from_structure(
            device_tree.GetDeviceData(device_id)
        )
        device_path = device_data.path

        if not stat.S_ISBLK(os.stat(device_path)[stat.ST_MODE]):
            raise SourceSetupError("{} is not a valid block device.".format(device_path))

        return device_path

    def _mount_device(self, device_path):
        """Mount the specified device."""
        log.debug("Mounting %s at %s.", device_path, self._target_mount)

        try:
            rc = blivet.util.mount(
                device_path,
                self._target_mount,
                fstype="auto",
                options="ro"
            )
        except OSError as e:
            raise SourceSetupError(str(e)) from e

        if rc != 0:
            raise SourceSetupError("Failed to mount the Live OS image.")
NOID_LIVEINST_REQUIRED_SPACE_EOF
chmod 0644 "$liveinst_update_source"
chown root:root "$liveinst_update_source"
if [ "$(sha256sum "$liveinst_update_source" | awk '{print $1}')" != \
        "$LIVEINST_UPDATE_SOURCE_SHA256" ]; then
    log "  FAIL: embedded Live-installer overlay source drifted"
    exit 1
fi
python3 -B - "$liveinst_update_source" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1])
compile(source.read_bytes(), str(source), "exec")
PY

# Keep every newc metadata field stable across identical inputs. The reviewed
# vendor-source mtime is already pinned by rpm --dump above.
liveinst_update_mtime=$(stat -c '%Y' "$ANACONDA_VENDOR_LIVE_OS_INIT")
while IFS= read -r -d '' liveinst_update_entry; do
    touch -h -d "@$liveinst_update_mtime" "$liveinst_update_entry"
done < <(find "$liveinst_update_root" -print0)
(
    cd "$liveinst_update_root"
    find . -print0 \
        | LC_ALL=C sort -z \
        | cpio --null --quiet --format=newc --reproducible --owner=0:0 -o \
        | gzip -n -9 > "$liveinst_update_candidate"
)
chmod 0644 "$liveinst_update_candidate"
chown root:root "$liveinst_update_candidate"
gzip -t "$liveinst_update_candidate"
(
    cd "$liveinst_update_extract"
    gzip -dc "$liveinst_update_candidate" \
        | cpio --quiet --no-absolute-filenames -idu
)
liveinst_update_listing=$(find "$liveinst_update_extract" -mindepth 1 \
    -printf '%P\n' | LC_ALL=C sort)
expected_liveinst_update_listing=$(printf '%s\n' \
    usr \
    usr/lib64 \
    usr/lib64/python3.14 \
    usr/lib64/python3.14/site-packages \
    usr/lib64/python3.14/site-packages/pyanaconda \
    usr/lib64/python3.14/site-packages/pyanaconda/modules \
    usr/lib64/python3.14/site-packages/pyanaconda/modules/payloads \
    usr/lib64/python3.14/site-packages/pyanaconda/modules/payloads/source \
    usr/lib64/python3.14/site-packages/pyanaconda/modules/payloads/source/live_os \
    usr/lib64/python3.14/site-packages/pyanaconda/modules/payloads/source/live_os/initialization.py)
if [ "$liveinst_update_listing" != "$expected_liveinst_update_listing" ] \
   || ! cmp -s "$liveinst_update_source" \
        "$liveinst_update_extract$ANACONDA_VENDOR_LIVE_OS_INIT"; then
    log "  FAIL: Live-installer updates archive content differs"
    exit 1
fi
mv -fT -- "$liveinst_update_candidate" "$LIVEINST_UPDATE_IMAGE"
liveinst_update_candidate=
restorecon -RF "$LIVEINST_UPDATE_DIR"
if [ "$(stat -c '%U:%G:%a:%h' "$LIVEINST_UPDATE_IMAGE" \
        2>/dev/null || true)" != root:root:644:1 ] \
   || ! matchpathcon -V "$LIVEINST_UPDATE_DIR" >/dev/null 2>&1 \
   || ! matchpathcon -V "$LIVEINST_UPDATE_IMAGE" >/dev/null 2>&1; then
    log "  FAIL: published Live-installer updates image metadata/label differs"
    exit 1
fi
sync -- "$LIVEINST_UPDATE_IMAGE" "$LIVEINST_UPDATE_DIR"

desktop-file-validate "$LIVEINST_VENDOR_DESKTOP"
if [ "$(grep -Fxc 'Exec=liveinst' "$LIVEINST_VENDOR_DESKTOP" || true)" -ne 1 ] \
   || grep -q '^Exec=.*--updates=' "$LIVEINST_VENDOR_DESKTOP" \
   || [ "$(sha256sum "$ANACONDA_VENDOR_LIVE_OS_INIT" | awk '{print $1}')" != \
        "0dbcdeccf8d9ee0a1e36700b32adf3d0ef9eef7b9ea310386c60996439c946b6" ] \
   || [ "$(sha256sum "$ANACONDA_VENDOR_LIVEINST" | awk '{print $1}')" != \
        "99fa227f7ec0e2ae79dcf648fafa316b79c384d173c886385cb9879c890eef59" ]; then
    log "  FAIL: pristine Live-installer payload postcondition failed"
    exit 1
fi
noid_liveinst_update_cleanup
trap - EXIT HUP INT TERM
unset -f noid_liveinst_update_cleanup
log "  [OK] native Live-installer updates image published; launcher wiring deferred to Live overlay"

# 7c.1: Write livesys-session-extra hook (sourced by livesys-main on live boot only)
mkdir -p /var/lib/livesys
cat > /var/lib/livesys/livesys-session-extra <<'LIVESYS_EXTRA_EOF'
#!/bin/sh
# NoID Privacy Workstation — fill livesys-gnome gaps on Live ISO boot
# Sourced by /usr/libexec/livesys/livesys-main when livesys.service runs.
# Active ONLY on Live USB boot (livesys.service has ConditionKernelCommandLine=rd.live.image).
# Has NO effect on installed system.
#
# Defensive guard for liveuser operations after a pre-GDM boot hang.
# The affected VM hung before GDM rendered (graphical.target unreached). Likely
# cause: livesys-main hang in our hook OR plymouth blocking. Mitigation:
#   - Guard `passwd -d liveuser` with `id liveuser` check (no-op if user absent)
#
# NOTE on Wayland: Fedora removed the GNOME X11 session in Fedora 43, so the
# Fedora 44 / GNOME 50 session is Wayland. WaylandEnable=true is the maintained
# GDM default and must not be disabled here.

# Gap 1 fix: unlock liveuser (livesys-main skipped this for GNOME flavor)
# Defensive: only run if user actually exists (some Anaconda paths may skip
# user-creation on certain failure modes — rather no-op than block livesys)
if id liveuser >/dev/null 2>&1; then
    if ! passwd -d liveuser >/dev/null 2>&1; then
        echo "[noid-live] WARNING: could not unlock liveuser" >&2
    fi
    if ! usermod -aG wheel liveuser >/dev/null 2>&1; then
        echo "[noid-live] WARNING: could not add liveuser to wheel" >&2
    fi

    # User-home state may persist independently of the stateless Live root.
    # Keep every Root-driven home mutation in a caught subshell: a hostile or
    # simply customized persistent home must never abort the sourced
    # livesys-main parent before sudoers/GDM/final setup are written.
    if ! (
    noid_live_uid=$(id -u liveuser)
    noid_live_gid=$(id -g liveuser)
    if [ ! -d /home/liveuser ] || [ -L /home/liveuser ] \
       || [ "$(stat -c '%u:%g' -- /home/liveuser 2>/dev/null)" != \
            "${noid_live_uid}:${noid_live_gid}" ]; then
        echo "[noid-live] ERROR: liveuser home is missing, symlinked, or misowned" >&2
        exit 1
    fi

    # All Live-home writes are Root-driven before the graphical session. Walk
    # every parent explicitly so install(1) never follows a pre-existing link.
    noid_live_dir() {
        noid_live_dir_path=$1
        if [ -L "$noid_live_dir_path" ] \
           || { [ -e "$noid_live_dir_path" ] && [ ! -d "$noid_live_dir_path" ]; }; then
            echo "[noid-live] ERROR: unsafe Live config directory: $noid_live_dir_path" >&2
            exit 1
        fi
        if ! install -d -m 0700 -o "$noid_live_uid" -g "$noid_live_gid" \
                -- "$noid_live_dir_path" \
           || [ -L "$noid_live_dir_path" ] \
           || [ "$(stat -c '%u:%g:%a' -- "$noid_live_dir_path" 2>/dev/null)" != \
                "${noid_live_uid}:${noid_live_gid}:700" ]; then
            echo "[noid-live] ERROR: could not secure Live config directory: $noid_live_dir_path" >&2
            exit 1
        fi
    }

    # M08 installs these canonical always-present privacy templates after the
    # base Live account has already been created. Seed only exact reviewed
    # bytes. An existing identical file is harmless (future livesys may learn
    # to copy late skel state); a different persistent file is explicitly
    # preserved rather than overwritten or allowed to abort essential setup.
    noid_live_seed_template() {
        noid_live_source=$1
        noid_live_destination=$2
        if [ ! -f "$noid_live_source" ] || [ -L "$noid_live_source" ] \
           || [ "$(stat -c '%u:%g:%a' -- "$noid_live_source" 2>/dev/null)" != \
                "0:0:644" ]; then
            echo "[noid-live] ERROR: invalid reviewed Live template: $noid_live_source" >&2
            exit 1
        fi
        if [ -L "$noid_live_destination" ] \
           || { [ -e "$noid_live_destination" ] && [ ! -f "$noid_live_destination" ]; }; then
            echo "[noid-live] ERROR: unsafe Live template target: $noid_live_destination" >&2
            exit 1
        fi
        if [ -e "$noid_live_destination" ] \
           && ! cmp -s -- "$noid_live_source" "$noid_live_destination"; then
            echo "[noid-live] WARNING: preserving different persistent Live template: $noid_live_destination" >&2
            return 0
        fi

        # Publish a fully secured same-directory candidate even when an exact
        # regular destination already exists. That avoids chmod/chown through
        # a path controlled by a persistent user and makes a late symlink swap
        # an atomic replacement target, never a dereference target.
        noid_live_tmp=$(mktemp "${noid_live_destination}.noid-seed.XXXXXXXX") || {
            echo "[noid-live] ERROR: could not stage Live template" >&2
            exit 1
        }
        if ! install -m 0644 -o "$noid_live_uid" -g "$noid_live_gid" \
                -- "$noid_live_source" "$noid_live_tmp" \
           || [ -L "$noid_live_tmp" ] \
           || [ "$(stat -c '%u:%g:%a' -- "$noid_live_tmp" 2>/dev/null)" != \
                "${noid_live_uid}:${noid_live_gid}:644" ] \
           || ! cmp -s -- "$noid_live_source" "$noid_live_tmp" \
           || ! mv -fT -- "$noid_live_tmp" "$noid_live_destination"; then
            rm -f -- "$noid_live_tmp"
            echo "[noid-live] ERROR: could not seed Live template: $noid_live_destination" >&2
            exit 1
        fi
        if [ -L "$noid_live_destination" ] \
           || [ "$(stat -c '%u:%g:%a' -- "$noid_live_destination" 2>/dev/null)" != \
                "${noid_live_uid}:${noid_live_gid}:644" ] \
           || ! cmp -s -- "$noid_live_source" "$noid_live_destination"; then
            echo "[noid-live] ERROR: Live template postcondition failed: $noid_live_destination" >&2
            exit 1
        fi
    }

    noid_live_dir /home/liveuser/.config

    # Rootless Podman's default overlay driver cannot create another overlay
    # store below the Live session's overlay-backed /home. Ptyxis probes Podman
    # at startup, so the unsupported nesting otherwise surfaces immediately as
    # an error even before a user starts a container. VFS is Podman's native
    # no-overlay fallback. This file exists only in liveuser's ephemeral home;
    # installed Btrfs users retain Podman's maintained default storage driver.
    noid_live_dir /home/liveuser/.config/containers
    noid_live_storage=/home/liveuser/.config/containers/storage.conf
    if [ -L "$noid_live_storage" ] \
       || { [ -e "$noid_live_storage" ] && [ ! -f "$noid_live_storage" ]; }; then
        echo "[noid-live] ERROR: unsafe Live Podman config: $noid_live_storage" >&2
        exit 1
    fi
    noid_live_storage_tmp=$(mktemp "${noid_live_storage}.noid-seed.XXXXXXXX") || {
        echo "[noid-live] ERROR: could not stage Live Podman config" >&2
        exit 1
    }
    cat > "$noid_live_storage_tmp" <<'NOID_LIVE_STORAGE_EOF'
[storage]
driver = "vfs"
NOID_LIVE_STORAGE_EOF
    if [ "$(cat "$noid_live_storage_tmp" 2>/dev/null)" != '[storage]
driver = "vfs"' ]; then
        rm -f -- "$noid_live_storage_tmp"
        echo "[noid-live] ERROR: Live Podman config staging failed" >&2
        exit 1
    fi
    if ! chown --no-dereference "$noid_live_uid:$noid_live_gid" \
            "$noid_live_storage_tmp" \
       || ! chmod 0600 "$noid_live_storage_tmp"; then
        rm -f -- "$noid_live_storage_tmp"
        echo "[noid-live] ERROR: could not secure staged Live Podman config" >&2
        exit 1
    fi
    if [ -e "$noid_live_storage" ] \
       && ! cmp -s -- "$noid_live_storage_tmp" "$noid_live_storage"; then
        rm -f -- "$noid_live_storage_tmp"
        echo "[noid-live] WARNING: preserving different persistent Live Podman config: $noid_live_storage" >&2
    else
        if ! mv -fT -- "$noid_live_storage_tmp" "$noid_live_storage"; then
            rm -f -- "$noid_live_storage_tmp"
            echo "[noid-live] ERROR: could not publish Live Podman config" >&2
            exit 1
        fi
        if [ -L "$noid_live_storage" ] \
           || [ "$(stat -c '%u:%g:%a' -- "$noid_live_storage" 2>/dev/null)" != \
                "${noid_live_uid}:${noid_live_gid}:600" ] \
           || [ "$(cat "$noid_live_storage" 2>/dev/null)" != '[storage]
driver = "vfs"' ]; then
            echo "[noid-live] ERROR: Live Podman config postcondition failed" >&2
            exit 1
        fi
    fi

    # Agent binaries and extensions remain absent until an explicit opt-in.
    # These two files contain only the always-present hardened configuration
    # floor and are copied byte-for-byte from M08's reviewed skel payloads.
    noid_live_dir /home/liveuser/.config/VSCodium
    noid_live_dir /home/liveuser/.config/VSCodium/User
    noid_live_dir /home/liveuser/.claude
    noid_live_seed_template \
        /etc/skel/.config/VSCodium/User/settings.json \
        /home/liveuser/.config/VSCodium/User/settings.json
    noid_live_seed_template \
        /etc/skel/.claude/settings.json \
        /home/liveuser/.claude/settings.json
    ); then
        echo "[noid-live] WARNING: Live user-home privacy seeding was incomplete; preserving the user-owned home and continuing essential Live setup" >&2
    fi
fi

# Gap 1b fix: NOPASSWD sudoers for liveuser
# Fedora's signed F44 livesys-scripts 0.9.6 creates the passwordless liveuser
# and adds it to wheel, but does not install a liveuser sudoers drop-in. Without
# this M17-owned rule, `sudo dnf ...` blocks on a password prompt → users can't
# install anything in Live mode. The direct
# NOPASSWD rule is sufficient for commands but not for `sudo -v`: sudoers'
# default verifypw=all also sees Fedora's PASSWD-tagged %wheel entry. Scope
# verifypw=any to liveuser so validation is passwordless only while at least
# one current-host NOPASSWD entry still exists. This changes no command
# authorization and fails back to authentication if the direct rule is lost.
# LIVE-MODE-ONLY (M41 noid-anaconda-cleanup removes liveuser + sudoers.d
# entries on install).
live_sudoers=/etc/sudoers.d/liveuser-nopasswd
live_sudoers_tmp=$(mktemp /etc/sudoers.d/.liveuser-nopasswd.XXXXXXXX) || {
    echo "[noid-live] ERROR: could not stage Live sudoers policy" >&2
    exit 1
}
cat > "$live_sudoers_tmp" <<'NOID_LIVEUSER_SUDOERS_EOF'
Defaults:liveuser verifypw=any
liveuser ALL=(ALL) NOPASSWD: ALL
NOID_LIVEUSER_SUDOERS_EOF
if ! chmod 0440 "$live_sudoers_tmp" \
   || ! /usr/sbin/visudo -cf "$live_sudoers_tmp" >/dev/null \
   || ! mv -fT -- "$live_sudoers_tmp" "$live_sudoers"; then
    rm -f -- "$live_sudoers_tmp"
    echo "[noid-live] ERROR: could not publish validated Live sudoers policy" >&2
    exit 1
fi
if [ -L "$live_sudoers" ] \
   || [ "$(stat -Lc '%u:%g:%a:%h' "$live_sudoers" 2>/dev/null)" != \
        "0:0:440:1" ] \
   || [ "$(grep -cEv '^[[:space:]]*(#|$)' "$live_sudoers" || true)" -ne 2 ] \
   || [ "$(grep -cFx 'Defaults:liveuser verifypw=any' "$live_sudoers" || true)" -ne 1 ] \
   || [ "$(grep -cFx 'liveuser ALL=(ALL) NOPASSWD: ALL' "$live_sudoers" || true)" -ne 1 ] \
   || ! /usr/sbin/visudo -cf "$live_sudoers" >/dev/null; then
    rm -f -- "$live_sudoers"
    echo "[noid-live] ERROR: Live sudoers postcondition failed" >&2
    exit 1
fi

# Gap 1c fix: unlock root for emergency shell access
# livesys-main has `passwd -d root` UNCONDITIONAL (outside autouser=1 block).
# VM testing showed root still locked → some part of livesys-main must
# fail silently before reaching that line. Mirror the unlock here defensively.
if ! passwd -d root >/dev/null 2>&1; then
    echo "[noid-live] WARNING: could not unlock live root account" >&2
fi

# Gap 1d REVERTED for the v1.0 release. The historic block
# deployed openssh-server + ssh-keygen -A + firewall
# ssh-allow + sshd enable+start + /etc/ssh/sshd_config.d/01-noid-hardening.conf
# + /home/liveuser/.ssh/authorized_keys with build-host Ed25519 key for VM-
# based post-install audit access. Removed for v1.0 ship — no SSH server in
# default NoID Privacy image. Cross-ref M09 + M26. Pre-ship gate
# tests/pre-ship/09-ssh-fix-phase-disabled.sh.

# Install-icon now handled by stock livesys-gnome session
# script. Setting livesys_session=gnome (M17 %post-install, see Step 7d
# below) makes /usr/libexec/livesys/sessions.d/livesys-gnome run on Live
# boot — that script does the canonical work:
#   - mv /usr/share/applications/liveinst.desktop → anaconda.desktop
#   - sed NoDisplay=true → false (so app-grid + dock show "Install to
#     Hard Drive")
#   - install /usr/share/polkit-1/rules.d/20-livesys-gnome.rules (polkit
#     JS bypass: liveuser may invoke org.fedoraproject.pkexec.liveinst
#     without admin auth — a user reported an "auth prompt that
#     doesn't work" because OUR custom Install-NoID Privacy.desktop bypassed
#     livesys-gnome and the polkit rule was never created)
# Custom Install-NoID Privacy.desktop creation REMOVED in favor of stock workflow.
# The dock pin for anaconda.desktop is added below in livesys-session-extra
# (which runs AFTER livesys-gnome per /usr/libexec/livesys/livesys-main).

# Fedora's signed livesys-gnome normally renames liveinst.desktop to
# anaconda.desktop in the ephemeral Live overlay. Wiring that runtime copy to
# the reviewed local updates image is only a startup optimization: any missing
# or invalid input must leave the sourced livesys parent running so GDM,
# dconf, daemon-reload and Fedora's trailing home/marker convergence still run.
# When the stock launcher exists but this wiring is unavailable, the installer
# retains its native full-tree size calculation.
if ! (
noid_liveinst_desktop=/usr/share/applications/anaconda.desktop
noid_liveinst_updates=/boot/loader/noid-privacy/liveinst-updates.img
noid_liveinst_expected="Exec=liveinst --updates=file://$noid_liveinst_updates"
noid_liveinst_tmp=""
if [ ! -f "$noid_liveinst_updates" ] || [ -L "$noid_liveinst_updates" ] \
   || [ "$(stat -c '%U:%G:%a:%h' "$noid_liveinst_updates" 2>/dev/null)" != \
        root:root:644:1 ] \
   || ! gzip -t "$noid_liveinst_updates"; then
    echo "[noid-live] WARNING: Live-installer updates image is unsafe" >&2
    exit 1
fi
if [ ! -f "$noid_liveinst_desktop" ] || [ -L "$noid_liveinst_desktop" ] \
   || [ "$(stat -c '%U:%G:%a:%h' "$noid_liveinst_desktop" 2>/dev/null)" != \
        root:root:644:1 ] \
   || ! desktop-file-validate "$noid_liveinst_desktop"; then
    echo "[noid-live] WARNING: post-livesys installer launcher contract differs" >&2
    exit 1
fi
noid_liveinst_exec_count=$(grep -c '^Exec=' "$noid_liveinst_desktop" || true)
noid_liveinst_stock_count=$(grep -Fxc 'Exec=liveinst' \
    "$noid_liveinst_desktop" || true)
noid_liveinst_current_count=$(grep -Fxc "$noid_liveinst_expected" \
    "$noid_liveinst_desktop" || true)
if [ "$noid_liveinst_exec_count" -ne 1 ] \
   || { [ "$noid_liveinst_stock_count" -ne 1 ] \
        && [ "$noid_liveinst_current_count" -ne 1 ]; }; then
    echo "[noid-live] WARNING: installer launcher Exec contract differs" >&2
    exit 1
fi
if [ "$noid_liveinst_stock_count" -eq 1 ]; then
    noid_liveinst_tmp=$(mktemp --suffix=.desktop \
        /usr/share/applications/.anaconda.noid.XXXXXXXX) || {
            echo "[noid-live] WARNING: cannot stage installer launcher" >&2
            exit 1
        }
    if ! sed "s#^Exec=liveinst\$#$noid_liveinst_expected#" \
            "$noid_liveinst_desktop" > "$noid_liveinst_tmp" \
       || ! chown root:root "$noid_liveinst_tmp" \
       || ! chmod 0644 "$noid_liveinst_tmp" \
       || [ "$(grep -Fxc "$noid_liveinst_expected" \
            "$noid_liveinst_tmp" 2>/dev/null)" -ne 1 ] \
       || [ "$(grep -c '^Exec=' "$noid_liveinst_tmp" || true)" -ne 1 ] \
       || ! desktop-file-validate "$noid_liveinst_tmp" \
       || ! sync -- "$noid_liveinst_tmp"; then
        rm -f -- "$noid_liveinst_tmp"
        echo "[noid-live] WARNING: staged installer launcher is invalid" >&2
        exit 1
    fi
    if ! mv -fT -- "$noid_liveinst_tmp" "$noid_liveinst_desktop"; then
        rm -f -- "$noid_liveinst_tmp"
        echo "[noid-live] WARNING: cannot publish installer launcher" >&2
        exit 1
    fi
    noid_liveinst_tmp=""
fi
if ! restorecon -F "$noid_liveinst_desktop" \
   || [ "$(stat -c '%U:%G:%a:%h' "$noid_liveinst_desktop" 2>/dev/null)" != \
        root:root:644:1 ] \
   || [ "$(grep -Fxc "$noid_liveinst_expected" \
        "$noid_liveinst_desktop" 2>/dev/null)" -ne 1 ] \
   || [ "$(grep -c '^Exec=' "$noid_liveinst_desktop" || true)" -ne 1 ] \
   || ! desktop-file-validate "$noid_liveinst_desktop" \
   || ! sync -- "$noid_liveinst_desktop" /usr/share/applications; then
    echo "[noid-live] WARNING: published installer launcher postcondition failed" >&2
    exit 1
fi
); then
    logger -t noid-live-session-extra -- \
        "optional installer --updates wiring unavailable; continuing essential Live convergence" \
        2>/dev/null || :
fi

# Gap 2 fix: livesys-gnome writes AutomaticLogin only when its runtime
# condition matches; it does not provide TimedLogin after an intentional
# logout. Converge both for the NoID Privacy Live path. WaylandEnable=true is
# GDM's maintained default but explicit here so another drop-in cannot change
# the Live session backend. M41 noid-anaconda-cleanup removes all five
# Live-login lines on install.
mkdir -p /etc/gdm
cat > /etc/gdm/custom.conf <<'GDM_EOF'
# NoID Privacy Live ISO — GDM auto-login for liveuser
# Written by /var/lib/livesys/livesys-session-extra on Live boot only.
# M41 noid-anaconda-cleanup removes this during install.
[daemon]
AutomaticLoginEnable=true
AutomaticLogin=liveuser
TimedLoginEnable=true
TimedLogin=liveuser
TimedLoginDelay=1
WaylandEnable=true

[security]

[xdmcp]

[chooser]

[debug]
GDM_EOF

# 7c.5: Live-only GNOME session policy + optional installer favorite
# ---------------------------------------------------------------------------
# GNOME Shell's `disable-log-out` lockdown also removes its complete Power Off
# submenu on this release, including Restart and Power Off. Do not set or lock
# that key. GDM's maintained TimedLogin keys above instead make an intentional
# logout recover automatically without hiding any session power action.
#
# livesys-gnome (just ran above this hook) renamed liveinst.desktop →
# anaconda.desktop and added it to its OWN gschema favorite-apps override.
# Our system-wide dconf distro-default (M34: 16-noid-firefox-playground)
# takes precedence over gschema, so anaconda would NOT appear in the dock
# without this. Write a Live-mode-only site.d keyfile (higher priority
# than distro.d) that keeps our 6 pinned apps PLUS anaconda.desktop at end.
# This change lives in the squashfs OVERLAY (tmpfs) and does NOT survive
# Anaconda install — installed system gets the clean M34 distro default.
mkdir -p /etc/dconf/db/site.d
if [ -f /usr/share/applications/anaconda.desktop ]; then
    cat > /etc/dconf/db/site.d/10-noid-live-favorites <<'FAVS_EOF'
[org/gnome/shell]
favorite-apps=['org.mozilla.firefox.desktop', 'net.thunderbird.Thunderbird.desktop', 'org.gnome.Software.desktop', 'org.gnome.Nautilus.desktop', 'org.gnome.Ptyxis.desktop', 'org.gnome.Settings.desktop', 'anaconda.desktop']
FAVS_EOF
else
    rm -f /etc/dconf/db/site.d/10-noid-live-favorites
fi

# Live-only screen-lock neutralisation. The installed-system distro.d default
# is lock-enabled=true with idle-delay=300, which is correct once a real
# account with a real password exists. In the Live session it is a hard
# lockout: this hook clears liveuser's password above, the image ships
# authselect `without-nullok`, and pam_unix documents that a blank stored
# password is refused unless nullok is set -- so the GDM unlock dialog can
# never be satisfied. user-switch-enabled=false removes the usual escape and
# pam_faillock then locks the account after repeated attempts, leaving a hard
# reset as the only way out, potentially in the middle of an unattended
# Anaconda transaction. Disable the idle blank and the lock for Live only;
# this keyfile lives in the squashfs overlay and never reaches an install.
# Disjoint keys from the favorites keyfile above, so both can coexist.
# Deliberately NOT under site.d/locks: the Live user stays free to re-enable
# the blank timer. The retired basename 10-noid-live-session is not reused.
cat > /etc/dconf/db/site.d/10-noid-live-screensaver <<'LIVE_SCREENSAVER_EOF'
[org/gnome/desktop/screensaver]
lock-enabled=false

[org/gnome/desktop/session]
idle-delay=uint32 0
LIVE_SCREENSAVER_EOF

if ! dconf update 2>/dev/null; then
    logger -t noid-live-session-extra -- "failed to compile Live GNOME session policy" 2>/dev/null || :
    exit 1
fi

# Fedora livesys-main deliberately disables firstboot, mdmonitor, cron and
# related Live-only services with `systemctl --no-reload`. That changes the
# unit search path after PID 1 loaded the initial boot transaction. Complete
# Fedora's deferred native operation exactly once after all session hooks so
# later dynamic session-owned units see the final search path; daemon-reload
# changes no active service state. Earlier boot-critical units own their own
# pre-start publication and cannot rely on this later session hook.
if ! systemctl daemon-reload; then
    echo "[noid-live] ERROR: could not reload systemd after livesys unit changes" >&2
    exit 1
fi
LIVESYS_EXTRA_EOF
chmod 0755 /var/lib/livesys/livesys-session-extra
chown root:root /var/lib/livesys/livesys-session-extra
log "  [OK] /var/lib/livesys/livesys-session-extra written (liveuser unlock + Podman VFS + Agent config floor + GDM autologin)"

# 7c.2: graphical.target as default (otherwise live boot stops at multi-user.target = tty1)
# systemctl set-default writes /etc/systemd/system/default.target → /lib/systemd/system/graphical.target
systemctl set-default graphical.target
default_target=$(systemctl get-default 2>/dev/null || echo "unknown")
log "  [OK] systemctl get-default → $default_target"

# 7c.3: Verification
if [ ! -f /var/lib/livesys/livesys-session-extra ]; then
    log "  FAIL: livesys-session-extra not written"
    fail=$((fail + 1))
fi
if [ ! -x /var/lib/livesys/livesys-session-extra ]; then
    log "  FAIL: livesys-session-extra not executable (mode 0755 expected)"
    fail=$((fail + 1))
fi
if ! grep -qF 'passwd -d liveuser' /var/lib/livesys/livesys-session-extra 2>/dev/null; then
    log "  FAIL: livesys-session-extra missing passwd -d liveuser"
    fail=$((fail + 1))
fi
if ! grep -qF 'AutomaticLogin=liveuser' /var/lib/livesys/livesys-session-extra 2>/dev/null; then
    log "  FAIL: livesys-session-extra missing AutomaticLogin=liveuser"
    fail=$((fail + 1))
fi
if ! grep -qF 'TimedLoginEnable=true' /var/lib/livesys/livesys-session-extra 2>/dev/null \
   || ! grep -qF 'TimedLogin=liveuser' /var/lib/livesys/livesys-session-extra 2>/dev/null \
   || ! grep -qF 'TimedLoginDelay=1' /var/lib/livesys/livesys-session-extra 2>/dev/null; then
    log "  FAIL: livesys-session-extra missing Live logout recovery"
    fail=$((fail + 1))
fi
if grep -qF 'disable-log-out=true' /var/lib/livesys/livesys-session-extra 2>/dev/null \
   || grep -qF '/org/gnome/desktop/lockdown/disable-log-out' \
        /var/lib/livesys/livesys-session-extra 2>/dev/null; then
    log "  FAIL: livesys-session-extra still hides the GNOME Power Off submenu"
    fail=$((fail + 1))
fi
liveinst_lifecycle_helper=/usr/local/libexec/noid-liveinst-webui-lifecycle
liveinst_lifecycle_service=/usr/lib/systemd/system/noid-liveinst-webui-lifecycle.service
liveinst_lifecycle_path=/usr/lib/systemd/system/noid-liveinst-webui-lifecycle.path
liveinst_lifecycle_wants=/etc/systemd/system/multi-user.target.wants/noid-liveinst-webui-lifecycle.path
liveinst_update_image=/boot/loader/noid-privacy/liveinst-updates.img
liveinst_vendor_init=/usr/lib64/python3.14/site-packages/pyanaconda/modules/payloads/source/live_os/initialization.py
liveinst_umask_wrapper=/usr/local/bin/liveinst
if [ "$(stat -c '%U:%G:%a:%h' "$liveinst_umask_wrapper" 2>/dev/null || true)" != \
        root:root:755:1 ] \
   || ! matchpathcon -V "$liveinst_umask_wrapper" >/dev/null \
   || [ "$(PATH=/usr/local/bin:/usr/bin command -v liveinst 2>/dev/null || true)" != \
        "$liveinst_umask_wrapper" ] \
   || ! cmp -s "$liveinst_umask_wrapper" <(cat <<'NOID_LIVEINST_UMASK_VERIFY_EOF'
#!/usr/bin/bash
umask 022
exec /usr/bin/liveinst "$@"
NOID_LIVEINST_UMASK_VERIFY_EOF
) \
   || [ "$(stat -c '%U:%G:%a' "$liveinst_lifecycle_helper" 2>/dev/null || true)" != \
        root:root:755 ] \
   || [ "$(stat -c '%U:%G:%a' "$liveinst_lifecycle_service" 2>/dev/null || true)" != \
        root:root:644 ] \
   || [ "$(stat -c '%U:%G:%a' "$liveinst_lifecycle_path" 2>/dev/null || true)" != \
        root:root:644 ] \
   || [ ! -L "$liveinst_lifecycle_wants" ] \
   || [ "$(readlink "$liveinst_lifecycle_wants" 2>/dev/null || true)" != \
        "$liveinst_lifecycle_path" ] \
   || ! python3 -c 'import pathlib; p=pathlib.Path("/usr/local/libexec/noid-liveinst-webui-lifecycle"); compile(p.read_bytes(), str(p), "exec")' \
   || ! grep -qxF 'PathChanged=/run/anaconda/webui_script.pid' "$liveinst_lifecycle_path" \
   || ! grep -qxF 'Unit=noid-liveinst-webui-lifecycle.service' "$liveinst_lifecycle_path" \
   || ! grep -qxF 'ConditionKernelCommandLine=rd.live.image' "$liveinst_lifecycle_path" \
   || ! grep -qxF 'ConditionKernelCommandLine=rd.live.image' "$liveinst_lifecycle_service" \
   || ! grep -qxF 'ExecStart=/usr/local/libexec/noid-liveinst-webui-lifecycle' \
        "$liveinst_lifecycle_service" \
   || ! grep -qxF 'TimeoutStartSec=infinity' "$liveinst_lifecycle_service" \
   || ! grep -qF 'os.pidfd_open(pid, 0)' "$liveinst_lifecycle_helper" \
   || ! grep -qF '[SYSTEMCTL, "stop", SERVICE]' "$liveinst_lifecycle_helper"; then
    log "  FAIL: Live-installer WebUI lifecycle contract invalid"
    fail=$((fail + 1))
fi
if [ "$(stat -c '%U:%G:%a:%h' "$liveinst_update_image" 2>/dev/null || true)" != \
        root:root:644:1 ] \
   || ! gzip -t "$liveinst_update_image" \
   || [ "$(grep -Fxc 'Exec=liveinst' \
        /usr/share/applications/liveinst.desktop 2>/dev/null || true)" -ne 1 ] \
   || grep -q '^Exec=.*--updates=' /usr/share/applications/liveinst.desktop \
   || ! grep -qF \
        'noid_liveinst_updates=/boot/loader/noid-privacy/liveinst-updates.img' \
        /var/lib/livesys/livesys-session-extra \
   || ! grep -qF \
        'mv -fT -- "$noid_liveinst_tmp" "$noid_liveinst_desktop"' \
        /var/lib/livesys/livesys-session-extra \
   || [ "$(sha256sum "$liveinst_vendor_init" 2>/dev/null | awk '{print $1}')" != \
        "0dbcdeccf8d9ee0a1e36700b32adf3d0ef9eef7b9ea310386c60996439c946b6" ] \
   || [ "$(sha256sum /usr/bin/liveinst 2>/dev/null | awk '{print $1}')" != \
        "99fa227f7ec0e2ae79dcf648fafa316b79c384d173c886385cb9879c890eef59" ]; then
    log "  FAIL: Live-installer required-space updates contract invalid"
    fail=$((fail + 1))
fi
if ! grep -qF 'driver = "vfs"' /var/lib/livesys/livesys-session-extra 2>/dev/null \
   || ! grep -qF '/home/liveuser/.config/containers/storage.conf' \
        /var/lib/livesys/livesys-session-extra 2>/dev/null; then
    log "  FAIL: livesys-session-extra missing Live-only Podman VFS seed"
    fail=$((fail + 1))
fi
for live_agent_template in \
    /etc/skel/.config/VSCodium/User/settings.json \
    /etc/skel/.claude/settings.json
do
    if [ ! -f "$live_agent_template" ] || [ -L "$live_agent_template" ] \
       || [ "$(stat -c '%U:%G:%a' -- "$live_agent_template" 2>/dev/null)" != \
            "root:root:644" ]; then
        log "  FAIL: invalid Live Agent config source: $live_agent_template"
        fail=$((fail + 1))
    fi
done
if ! grep -qF 'noid_live_seed_template' /var/lib/livesys/livesys-session-extra 2>/dev/null \
   || ! grep -qF '/home/liveuser/.config/VSCodium/User/settings.json' \
        /var/lib/livesys/livesys-session-extra 2>/dev/null \
   || ! grep -qF '/home/liveuser/.claude/settings.json' \
        /var/lib/livesys/livesys-session-extra 2>/dev/null; then
    log "  FAIL: livesys-session-extra missing Live Agent config floor"
    fail=$((fail + 1))
fi
if [ "$default_target" != "graphical.target" ]; then
    log "  FAIL: default.target is $default_target (expected graphical.target)"
    fail=$((fail + 1))
fi

if [ "$fail" -gt 0 ]; then
    log "=== Module 17 FAILED at Step 7c with $fail errors ==="
    exit 1
fi

# User-facing target for the Documentation= links on this module's user units.
# M13 normally creates this shared directory first; retain local ownership of
# the precondition so an isolated/reordered module run cannot fail late.
mkdir -p /usr/share/doc/noid-privacy
cat > /usr/share/doc/noid-privacy/17-gnome-hardening.md <<'GNOME_DOC_EOF'
# GNOME Privacy + Security Defaults

Module 17 applies system dconf defaults/locks and session helpers without
replacing GNOME itself.

## Enforced defaults

- Remote Desktop (RDP/VNC), removable-media autorun and thumbnail generation
  are locked off.
- Lock-screen notification content and in-session extension installation are
  locked off.
- Location, camera and microphone application access default to off. A required
  WirePlumber policy additionally mutes every current and future audio capture
  source and reverses unmute drift while its persistent disabled setting is on.
- GNOME usage/statistics reporting and the configured background search/index
  services are disabled.

These are operating-system controls, not physical disconnects. Firmware,
external capture devices, administrator changes and applications granted a
different permission remain separate trust boundaries.

## User controls and diagnostics

The Setup app can deliberately re-enable microphone, camera, Bluetooth and
location access. Inspect the effective GNOME privacy keys with:

```bash
gsettings list-recursively org.gnome.desktop.privacy
gsettings get org.gnome.system.location enabled
noid-toggle-microphone status
wpctl settings noid.microphone.disabled
```

Root can change a locked dconf policy by editing the matching file under
`/etc/dconf/db/distro.d/` or `/etc/dconf/db/distro.d/locks/` and then running
`dconf update`.

## Silent integration-service activation

GNOME Software keeps Fedora's RPM-owned D-Bus descriptor. Its native
`SystemdService=gnome-software.service` route reaches the globally masked user
unit immediately; no higher-priority service descriptor duplicates that name.
The separate administrator desktop entry uses `DBusActivatable=false` only for
a deliberate app-grid or CLI launch.

GOA and Identity are different: Fedora's descriptors expose only an `Exec`
route. On the validated Fedora 44 session, removing the two administrator
descriptors caused both processes to start even though the mandatory D-Bus
policy then returned `AccessDenied`. Their higher-priority descriptors
therefore route activation to the common static mask. dbus-broker consequently
reports that the lower-priority vendor names are duplicates at session start
or configuration reload; those two diagnostics are the known cost of
preventing the processes from spawning without modifying RPM payloads.

LocalSearch/Tinysparql use Fedora's native `SystemdService` routes like GNOME
Software. Their service units are masked and no `/usr/local` service
descriptors should exist.

## Live installer WebUI lifecycle

Only on `rd.live.image`, `noid-liveinst-webui-lifecycle.path` observes the
PID record written by Fedora's own `liveinst`. The companion validates that
the record names the exact root-owned `webui-desktop -t live` process, binds a
pidfd to that process instance and waits. When the installer browser exits, it
stops only `webui-cockpit-ws.service`; systemd then terminates the complete
service cgroup. Invalid PID metadata or a failed stop remains visible as a
failed unit. Fedora's `/usr/bin/liveinst`, `webui-desktop`, WebUI service and
Cockpit wrapper remain RPM-pristine.

The Live-only `/usr/local/bin/liveinst` wrapper leaves Fedora's executable and
polkit action unchanged. It scopes only the inherited umask to `0022` before
exec, so Anaconda's installed-target Dracut run creates public systemd metadata
as `0644/0755`. Module 41 removes the byte-exact wrapper before GDM opens the
installed session; a changed object at that path blocks cleanup for review.

## Live installer startup

The normal Live desktop launcher passes Fedora's supported
`--updates=file:///boot/loader/noid-privacy/liveinst-updates.img` option to the
RPM-pristine `liveinst`. That deterministic, Live-only gzip-cpio overlay changes
only Anaconda 44.30's Live-source initialization module. It consumes a
root-owned, non-writable required-space manifest that the exact-version Lorax
compose override writes from the final mounted tree immediately before
SquashFS creation. This moves the full-tree size calculation from every
installer start to the one-time image build.

The manifest binds its format, 64 MiB safety headroom and reviewed upstream
Anaconda source hash. Any missing, malformed, symlinked, writable, misowned,
out-of-range or mismatched manifest is ignored and Fedora's original
`du --bytes --summarize` calculation runs instead. `/boot/loader/` is excluded
from Anaconda's Live payload copy, so neither this updates image nor the
compose manifest is installed on the target system. A deliberate terminal
launch can select the same native path with:

```bash
liveinst --updates=file:///boot/loader/noid-privacy/liveinst-updates.img
```

## Logout data minimization

GNOME's shutdown target runs `noid-gnome-shell-privacy-cleanup.service` after
the session producers stop and before the user bus restarts. It removes the
two GNOME Shell tracking records and the complete XDG thumbnail-cache tree.
The helper refuses symlinked path components and nested/bind mount crossings,
preflights the complete tree and reports any incomplete cleanup in the user
journal instead of silently succeeding. A later invocation resumes any
strictly named exact-inode quarantine left by abrupt termination.

Firefox and Thunderbird `lock` and `.parentlock` files are deliberately not
cleanup data. They remain application-owned recovery and second-instance
protection state, including after a crash.

## JavaScript JIT hardening and cost

`GJS_DISABLE_JIT=1` and `JavaScriptCoreUseJIT=0` are system-session defaults
for GJS and WebKitGTK applications. On the audited Fedora 44 packages they
disable the documented main JavaScript JIT tiers. This narrows exposure to
vulnerabilities which require enabled JIT compilation.
It does not make either engine memory-safe, replace WebKitGTK's content-process
sandbox, prevent sandbox escapes or affect Firefox/Chromium.

The compatibility/performance cost can be material and depends on the
application and workload. The three-pass release gate re-verifies the
effective tier state after package updates; it deliberately does not claim a
universal latency figure.

For a reviewed application whose functionality or measured workload requires
JIT, use a per-launch override rather than changing the system default:

```bash
env -u GJS_DISABLE_JIT gjs-application [arguments...]
env JavaScriptCoreUseJIT=1 webkit-application [arguments...]
```

GJS treats any set value as disablement, so its opt-out must unset the
variable. These overrides restore JIT compilation for that application's
compatibility or performance.

## Native-Wayland application defaults

`GDK_BACKEND=wayland` and `QT_QPA_PLATFORM=wayland` are strict defaults for
covered GTK and Qt applications. They avoid an unintended X11 fallback, but
they are not an enforcement or anti-downgrade boundary: applications can
select another backend, Qt's `-platform` argument overrides its environment
value, and Electron/Chromium uses separate controls. Xwayland remains available
for deliberate compatibility. No Mutter experimental feature is selected, so
Xwayland is not torn down automatically when its last client exits.

NoID Privacy includes Fedora's Qt5 Wayland plugin because the shipped KeePassXC is a
Qt5 application. For a reviewed application that cannot use native Wayland,
the explicit recovery forms are:

```bash
env GDK_BACKEND=x11 gtk-application [arguments...]
env QT_QPA_PLATFORM=xcb qt-application [arguments...]
qt-application -platform xcb [arguments...]
```

These overrides deliberately re-enter X11/Xwayland's weaker client-isolation
boundary. Without a Wayland compositor, the strict defaults fail rather than
silently selecting X11.

## Display, lock and sleep ownership

GNOME owns graphical-session dimming, blanking, locking and automatic suspend.
The NoID Privacy defaults are user-adjustable: Automatic Screen Blank is five
minutes, screen locking is enabled and `lock-delay` is zero. Early idle dimming
is off, so the panel retains its chosen brightness until the screen-shield
transition. GNOME Shell starts its ten-second screen-shield fade at five minutes,
and `lock-delay=0` schedules the lock no earlier than that fade. Once the shield
reports itself active, GNOME Settings Daemon blanks the monitors immediately;
its separate 30-second active-shield idle watch is a recovery path rather than
an extra delay. Therefore `lock-delay=0` is not a literal zero-second lock.

Automatic Suspend is a separate visible GNOME control. It defaults to off on AC
and battery so an unattended local agent or long-running task is not suspended.
No power key is locked: users can re-enable either side and retain GNOME's
visible delay. Automatic Screen Blank, screen locking and low-battery Automatic
Power Saver remain independent. The trade-off is higher idle energy use and
faster battery drain when a user intentionally leaves the machine running.

GNOME 50 does not expose the lid-close action in Settings. NoID Privacy Tools
therefore includes **Laptop Lid Close**, backed by the native
`noid-toggle-lid-action` CLI:

```bash
noid-toggle-lid-action status
noid-toggle-lid-action suspend
noid-toggle-lid-action lock
noid-toggle-lid-action reset
```

`status` detects the real kernel `SW_LID` input capability and reports the
effective logind actions for normal, external-power and docked/clamshell use.
It does not infer a laptop from a battery or DMI chassis label. A desktop
without `SW_LID` is shown as such and every mutation is refused without
creating a policy file. `suspend` requires confirmation and verifies that
logind supports suspend; `lock` avoids automatic lid-close sleep; `reset`
removes only the explicit choice and returns to the lower NoID Privacy/Fedora
policy. Docked behavior is always displayed but remains separately owned by
logind. Every change uses a native logind drop-in, reloads logind, verifies its
D-Bus state and restores the prior policy if either step fails.
The three mutations use a closed `%wheel` NOPASSWD bridge for only the helper's
internal `suspend`, `lock` and `reset` transactions, so NoID Privacy Tools never
opens a password prompt and grants no general root command.

M10 does not install a second logind idle timer or duplicate power/suspend/
hibernate actions. The optional proprietary NVIDIA workflow may add its lower,
reversible laptop lid compatibility default after installation. An explicit
choice made through NoID Privacy Tools has higher precedence, survives NVIDIA
driver changes and is never removed by NVIDIA rollback.

The default NoID Privacy storage layout has zram but no persistent disk-backed swap, so
hibernate, hybrid sleep and suspend-then-hibernate have no resume image and are
not supported by default. Enabling them is a separate encrypted-storage,
initramfs and real power-cycle validation task.

Inspect the effective state with:

```bash
gsettings list-recursively org.gnome.desktop.session
gsettings list-recursively org.gnome.desktop.screensaver
gsettings list-recursively org.gnome.settings-daemon.plugins.power
systemd-analyze cat-config systemd/logind.conf
systemd-analyze cat-config systemd/sleep.conf
systemd-inhibit --list
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanSuspend
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanHibernate
```

The first-login helper synchronizes an otherwise-empty GNOME region from
`/etc/locale.conf`. It also resolves the native XDG Downloads directory and,
only when Nautilus has no existing per-folder sort metadata, initializes
`metadata::nautilus-icon-view-sort-by=name` and
`metadata::nautilus-icon-view-sort-reversed=false` through GIO. Existing sort
metadata is treated as user-owned and is never replaced; later changes in
Nautilus update the same unlocked metadata. If Downloads is disabled by mapping
it to the home directory, no folder metadata is written.

The same transaction owns the functional half of libvirt's core-limit
compatibility. `qemu:///session` reads
`${XDG_CONFIG_HOME:-$HOME/.config}/libvirt/qemu.conf`; it cannot read or fall
back to `/etc/libvirt/qemu.conf`. The helper creates or atomically completes the
user file with one active `max_core = 0` and `dump_guest_core = 0`. This avoids
libvirt trying to raise NoID Privacy's already-effective hard user core limit
to unlimited and failing VM startup. It adds no new security boundary in the
user session: that hard inherited limit already holds. `dump_guest_core = 0`
documents the intended default but can be overridden by guest XML; `max_core`
is the file-size boundary. A regular, single-link, user-owned file with both
exact values is preserved byte-for-byte. Conflicting or duplicate active
values, symlinks, hardlinks, foreign ownership and files over 1 MiB fail visibly
instead of being overwritten.

The helper then applies the exact preset and starts
`noid-update-reminder.timer`, verifies the
exact root-owned static graphical-session wants link and starts
`usbguard-notifier.service`. The notifier is deliberately static and is never
sent through a preset or `is-enabled` gate. Each task gets an fsync-backed
atomic mode-0600 marker only after its postcondition; partial failures retry
without repeating successful tasks. Completion is derived from all five
markers under
`~/.config/noid-user-firstrun/`. The obsolete empty
`~/.config/noid-user-firstrun.done` file is ignored and retired only after a
successful version-2 transaction. Retries remain bounded to the active
graphical session: logout cancels queued work, and a later login starts any
unfinished tasks again without replaying completed tasks.
GNOME_DOC_EOF
chmod 0644 /usr/share/doc/noid-privacy/17-gnome-hardening.md

#------------------------------------------------------------------------------
# Step 8: Summary
#------------------------------------------------------------------------------
log "Step 8/8: Summary"
log "=== Module 17: GNOME Privacy + Security Hardening COMPLETE ==="
log "    dconf: $actual_sections sections, $actual_locks security-critical locks"
log "    D-Bus: ${#DBUS_ADMIN_BLOCKED_NAMES[@]} static-mask admin routes; ${#TRACKER_DBUS_NAMES[@]} native masked Tracker routes; ${#DBUS_VENDOR_SPECS[@]} RPM vendor files pristine"
log "    Masked: ${#MASK_UNITS[@]} user units verified against /dev/null in Step 7.3"
log "    GNOME 50 (F44) mutter experimental-features: @as []"
log "    Extensions configured: 2 (Just-Perfection events-button hide + AppIndicator tray-icon compat)"
log "    Text files: GNOME Text Editor is the XDG admin default for plain and empty files"
log "    Privacy cleanup: ordered GNOME-shutdown helper (tracking files + symlink/mount-safe thumbnail tree; Mozilla locks untouched)"
log "    First-boot flow: gnome-initial-setup vendor.conf (4 pages skipped) + gnome-tour reinstall guard"
log "    Live-mode: compose-sized installer + pidfd WebUI + livesys hook + Podman VFS + Agent config floor + graphical.target"

%end

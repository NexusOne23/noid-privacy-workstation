# ============================================================================
# Module 37 — NoID Privacy Tools App
# Status: LOCKED 2026-08-10 (v33) — classify the post-Tools host-identity lifecycle helper as transaction recovery.
#
# Standalone GTK4 + libadwaita helper-command launcher, one of the four
# NoID Privacy first-party apps beside Setup, Update and Network. Ships:
#   - /usr/local/bin/noid-tools                     Python 3 + Adw GUI
#   - /usr/share/applications/noid-tools.desktop    (StartupWMClass=
#     com.noidprivacy.Tools, Categories=System;)
#   + health stamp
#
# Purpose: discoverability for noid-* helper CLIs that have safe, fixed
# launcher actions. Advanced argument-requiring recovery tools remain in the
# complete `noid-help commands` inventory and are explicitly classified out
# of this GUI. Multi-verb helpers expose a drop-down whose FIRST entry is
# read-only/interactive-safe (state-changing verbs are explicit choices or
# carry an explicit action label). Run opens the shared transient-terminal
# contract: exactly one "Press ENTER to close" hold, then a clean exit 0.
#
# Constraint notes (keep on future edits):
#   - Adw group/row titles, descriptions and subtitles are Pango markup:
#     a bare '&' silently breaks rendering — always '&amp;'. Verb labels
#     stay <= 14 chars; row subtitles sit in one 80-120 char band to target
#     consistent compact wrapping at the default layout. The verb selector
#     is a minimum-width Gtk.DropDown suffix (an Adw.ComboRow lets a wrapping
#     subtitle squeeze its selected label into an ellipsized stub);
#     tests/37 gates all three source contracts.
#   - The curated CATALOG plus exact SWEEP_EXCLUDE basenames must jointly
#     cover every /usr/local/{bin,sbin}/noid-* deploy target in this
#     repository. Fedora's /usr merge makes /usr/local/sbin a symlink to
#     bin, so source spelling is not a runtime boundary. tests/37 resolves
#     direct, continued and variable-directory writers; the image verify
#     additionally requires the fresh-install runtime sweep to be empty.
#   - The uncurated runtime sweep scans the unified /usr/local/bin
#     directory, skips curated and explicitly excluded BASENAMES plus a
#     closed set of packaging/editor backup suffixes, and accepts portable
#     noid-* names including uppercase, underscores and non-.sh extensions.
#     It reports executables, non-executables and symlinks alike. A new
#     shipped helper must therefore receive an explicit curated/excluded
#     classification.
#   - Privilege UX: a closed (helper path, action label) manifest adds
#     `/usr/bin/sudo --` only for helpers/actions whose producer contract
#     requires root. Per-user/self-elevating actions stay unprivileged.
#     The terminal provides the controlling TTY for sudo authentication.
#   - The terminal wrapper exports NOID_WELCOME_SPAWN=1 — the shared
#     "the launching app owns the single close prompt" contract consumed
#     by noid-luks-backup.sh / noid-complete-setup.sh /
#     noid-nvidia-install.sh (their standalone return_to_menu_prompt
#     becomes a no-op).
# ============================================================================

%post --erroronfail --log=/var/log/ks-37-noid-tools-app.log
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

log() { echo "[noid-37-noid-tools-app] $*"; }
fail() {
    log "FAIL: $*"
    exit 1
}

ROOT_PUBLICATION_TMP=""

# Root-owned payloads are validated before publication, staged beside their
# destination and renamed atomically. Canonical parent checks reject symlink or
# writable-directory traversal before any destination is touched.
ensure_root_dir() {
    local path=$1 mode=${2:-0755} current="" component metadata component_mode
    case "$path" in
        /*) ;;
        *) fail "directory path is not absolute: $path" ;;
    esac
    while IFS= read -r component; do
        [ -n "$component" ] || continue
        current="$current/$component"
        [ ! -L "$current" ] || fail "symlinked directory component: $current"
        if [ -e "$current" ]; then
            [ -d "$current" ] || fail "non-directory path component: $current"
        else
            install -d -m 0755 -o root -g root -- "$current" \
                || fail "cannot create directory: $current"
        fi
        [ "$(readlink -e -- "$current" 2>/dev/null)" = "$current" ] \
            || fail "non-canonical directory component: $current"
        metadata=$(stat -Lc '%u:%g:%a' -- "$current" 2>/dev/null) \
            || fail "cannot inspect directory: $current"
        case "$metadata" in
            0:0:*) component_mode=${metadata##*:} ;;
            *) fail "directory is not root-owned: $current ($metadata)" ;;
        esac
        [[ "$component_mode" =~ ^[0-7]{3,4}$ ]] \
            || fail "directory mode is invalid: $current ($component_mode)"
        (( (8#$component_mode & 0022) == 0 )) \
            || fail "directory is writable by group/other: $current ($component_mode)"
    done < <(printf '%s\n' "${path#/}" | tr '/' '\n')
    chmod "$mode" -- "$path" || fail "cannot set directory mode: $path"
    chown root:root -- "$path" || fail "cannot set directory owner: $path"
    [ "$(stat -Lc '%u:%g:%a' -- "$path" 2>/dev/null)" = \
        "0:0:${mode#0}" ] || fail "directory postcondition failed: $path"
}

publish_root_file() {
    local source=$1 destination=$2 requested_mode=$3
    local parent temporary mode=${requested_mode#0}
    local parent_metadata parent_mode source_metadata source_mode
    parent=${destination%/*}
    [ -f "$source" ] && [ ! -L "$source" ] \
        || fail "publication source is missing, non-regular or symlinked: $source"
    [ "$(readlink -e -- "$source" 2>/dev/null)" = "$source" ] \
        || fail "publication source is non-canonical: $source"
    source_metadata=$(stat -Lc '%u:%g:%a:%h' -- "$source" 2>/dev/null) \
        || fail "cannot inspect publication source: $source"
    case "$source_metadata" in
        0:0:*:1)
            source_mode=${source_metadata#0:0:}
            source_mode=${source_mode%:1}
            ;;
        *) fail "publication source metadata is unsafe: $source ($source_metadata)" ;;
    esac
    [[ "$source_mode" =~ ^[0-7]{3,4}$ ]] \
        || fail "publication source mode is invalid: $source ($source_mode)"
    (( (8#$source_mode & 0022) == 0 )) \
        || fail "publication source is group/other-writable: $source ($source_mode)"
    [ -d "$parent" ] && [ ! -L "$parent" ] \
        || fail "publication parent is unsafe: $parent"
    [ "$(readlink -e -- "$parent" 2>/dev/null)" = "$parent" ] \
        || fail "publication parent is non-canonical: $parent"
    parent_metadata=$(stat -Lc '%u:%g:%a' -- "$parent" 2>/dev/null) \
        || fail "cannot inspect publication parent: $parent"
    case "$parent_metadata" in
        0:0:*) parent_mode=${parent_metadata##*:} ;;
        *) fail "publication parent is not root-owned: $parent ($parent_metadata)" ;;
    esac
    [[ "$parent_mode" =~ ^[0-7]{3,4}$ ]] \
        || fail "publication parent mode is invalid: $parent ($parent_mode)"
    (( (8#$parent_mode & 0022) == 0 )) \
        || fail "publication parent is writable by group/other: $parent ($parent_mode)"
    [ ! -e "$destination" ] || [ -f "$destination" ] || [ -L "$destination" ] \
        || fail "publication target is neither a regular file nor a symlink: $destination"
    temporary=$(mktemp "$parent/.noid-tools-publish.XXXXXXXX") \
        || fail "cannot stage: $destination"
    ROOT_PUBLICATION_TMP=$temporary
    if ! install -m "$requested_mode" -o root -g root -- "$source" "$temporary"; then
        rm -f -- "$temporary"
        ROOT_PUBLICATION_TMP=""
        fail "cannot stage: $destination"
    fi
    restorecon -F -- "$temporary" || {
        rm -f -- "$temporary"
        ROOT_PUBLICATION_TMP=""
        fail "cannot label staged file: $destination"
    }
    matchpathcon -V "$temporary" >/dev/null || {
        rm -f -- "$temporary"
        ROOT_PUBLICATION_TMP=""
        fail "staged-file label differs from policy: $destination"
    }
    sync -- "$temporary" || {
        rm -f -- "$temporary"
        ROOT_PUBLICATION_TMP=""
        fail "cannot sync staged file: $destination"
    }

    # Ignore ordinary termination signals only across the bounded rename,
    # final-label, postcondition and durability window. Outside this window,
    # the module traps abort and retire every registered staging path.
    trap '' HUP INT TERM
    if ! mv -fT -- "$temporary" "$destination"; then
        trap 'exit 129' HUP
        trap 'exit 130' INT
        trap 'exit 143' TERM
        rm -f -- "$temporary"
        ROOT_PUBLICATION_TMP=""
        fail "cannot publish: $destination"
    fi
    ROOT_PUBLICATION_TMP=""
    if ! restorecon -F -- "$destination" \
       || ! matchpathcon -V "$destination" >/dev/null; then
        rm -f -- "$destination" || true
        sync -- "$parent" >/dev/null 2>&1 || true
        trap 'exit 129' HUP
        trap 'exit 130' INT
        trap 'exit 143' TERM
        fail "published-file label differs from policy: $destination"
    fi
    if ! { [ -f "$destination" ] && [ ! -L "$destination" ] \
           && cmp -s -- "$source" "$destination" \
           && [ "$(stat -Lc '%u:%g:%a:%h' -- "$destination" 2>/dev/null)" = \
                "0:0:$mode:1" ] \
           && [ "$(readlink -e -- "$destination" 2>/dev/null)" = \
                "$destination" ]; }; then
        rm -f -- "$destination" || true
        sync -- "$parent" >/dev/null 2>&1 || true
        trap 'exit 129' HUP
        trap 'exit 130' INT
        trap 'exit 143' TERM
        fail "publication postcondition failed: $destination"
    fi
    if ! sync -- "$destination" || ! sync -- "$parent"; then
        rm -f -- "$destination" || true
        sync -- "$parent" >/dev/null 2>&1 || true
        trap 'exit 129' HUP
        trap 'exit 130' INT
        trap 'exit 143' TERM
        fail "cannot make publication durable: $destination"
    fi
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
}

log "=== Module 37 post-install: NoID Privacy Tools App ==="

TOOLS_CANDIDATE=""
DESKTOP_CANDIDATE=""
STAMP_CANDIDATE=""
STAMP_DIR=/var/lib/noid-privacy
STAMP="$STAMP_DIR/stamp-37-noid-tools-app.ok"
STAMP_PUBLICATION_ACTIVE=0
cleanup_candidates() {
    local saved_rc=$? candidate cleanup_failed=0
    trap - EXIT
    trap '' HUP INT TERM
    for candidate in \
        "${ROOT_PUBLICATION_TMP:-}" \
        "${TOOLS_CANDIDATE:-}" \
        "${DESKTOP_CANDIDATE:-}" \
        "${STAMP_CANDIDATE:-}"; do
        [ -n "$candidate" ] || continue
        if ! rm -f -- "$candidate"; then
            log "FAIL: could not retire staged Module 37 payload: $candidate"
            cleanup_failed=1
        fi
    done
    if [ "${STAMP_PUBLICATION_ACTIVE:-0}" -eq 1 ]; then
        if ! rm -f -- "$STAMP"; then
            log "FAIL: could not retire incomplete Module 37 health stamp"
            cleanup_failed=1
        fi
        sync -- "$STAMP_DIR" >/dev/null 2>&1 || true
    fi
    if [ "$saved_rc" -eq 0 ] && [ "$cleanup_failed" -ne 0 ]; then
        exit 1
    fi
    return "$saved_rc"
}
trap cleanup_candidates EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# M37_HEALTH_INVALIDATION_BEGIN
# Validate shared state without normalizing drift, then retire any earlier
# success before the first directory or installed-payload mutation.
if { [ -e "$STAMP_DIR" ] || [ -L "$STAMP_DIR" ]; } \
   && { [ ! -d "$STAMP_DIR" ] || [ -L "$STAMP_DIR" ]; }; then
    fail "$STAMP_DIR exists but is not a real directory"
fi
if [ ! -e "$STAMP_DIR" ]; then
    install -d -m 0755 -o root -g root "$STAMP_DIR"
fi
if [ "$(stat -Lc '%u:%g:%a' -- "$STAMP_DIR" 2>/dev/null || true)" != \
        0:0:755 ]; then
    fail "$STAMP_DIR metadata is not root:root 0755"
fi
if [ ! -x /usr/sbin/restorecon ] || [ ! -x /usr/sbin/matchpathcon ] \
   || ! /usr/sbin/restorecon -F -- "$STAMP_DIR" \
   || ! /usr/sbin/matchpathcon -V "$STAMP_DIR" >/dev/null; then
    fail "$STAMP_DIR SELinux context is not canonical"
fi
if [ -e "$STAMP" ] || [ -L "$STAMP" ]; then
    if [ ! -f "$STAMP" ] && [ ! -L "$STAMP" ]; then
        fail "health-stamp target is not a file or symlink: $STAMP"
    fi
    rm -f -- "$STAMP" \
        || fail "cannot invalidate stale Module 37 health stamp"
    sync -- "$STAMP_DIR"
fi
log "  [OK] prior Module 37 health stamp is absent"
# M37_HEALTH_INVALIDATION_END

ensure_root_dir /usr/local/bin 0755
ensure_root_dir /usr/share/applications 0755
TOOLS_CANDIDATE=$(mktemp /var/tmp/noid-tools.XXXXXXXX) \
    || fail "cannot create noid-tools candidate"
DESKTOP_CANDIDATE=$(mktemp --suffix=.desktop \
    /var/tmp/noid-tools-desktop.XXXXXXXX) \
    || fail "cannot create noid-tools.desktop candidate"

# ---------------------------------------------------------------------------
# STEP 1: Deploy /usr/local/bin/noid-tools (Python 3 + GTK4 + Adw 1)
# ---------------------------------------------------------------------------

cat > "$TOOLS_CANDIDATE" <<'NOID_TOOLS_PY_EOF'
#!/usr/bin/python3
"""NoID Privacy Tools — curated helper-command launcher (GTK4 + libadwaita).

Safely fixed-action noid-* helper CLIs in one place: grouped, described rows
with a Run action. Advanced argument-requiring commands remain discoverable
through noid-help. One of the four NoID Privacy first-party apps beside Setup,
Update and Network.

Contract per row:
  - Single-verb helpers show a plain Run action.
  - Multi-verb helpers expose their verbs in a drop-down with an explicit
    minimum width so row text cannot squeeze it below the reviewed layout.
    The first entry is always read-only or interactive-safe; verbs that
    change state are explicit selections.
  - Run opens a transient terminal with exactly ONE close prompt
    ("Press ENTER to close") and exits 0 afterwards, so no terminal adds
    a second process-failed hold.

The sweep group lists every clean-name post-install noid-* addition that is
neither curated nor explicitly classified. Safe regular executables can be
asked for --help; non-runnable entries remain visible for review.
"""

import os
import re
import sys
import shlex
import stat
import subprocess
from pathlib import Path

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw
sys.path.insert(0, '/usr/lib/noid-privacy')
import noid_ui

APP_ID = 'com.noidprivacy.Tools'
SUDO = '/usr/bin/sudo'

# Reviewed minimum width for every verb drop-down. GTK may allocate more for
# font/accessibility needs; it must not allocate less than this compact floor.
VERB_DROPDOWN_MIN_WIDTH = 128

# --- Curated helper catalog --------------------------------------------------
# Entry: (emoji, title, subtitle, path, verbs)
#   verbs: list of (label, [extra argv]) — index 0 is the drop-down default
#   and MUST be read-only/interactive-safe; state-changing verbs are
#   explicit choices. Labels <= 14 chars, subtitles in the 80-120 char
#   band (uniform two-line wrap); titles/subtitles/descriptions are Pango
#   markup — escape '&' as '&amp;'.
CATALOG = [
    ('System Status &amp; Diagnostics',
     'Non-remediating defaults for hardening and privacy diagnostics; the '
     'Online audit action explicitly permits network probes.',
     [
         ('📊', 'System Status Overview',
          'One read-only screen for AIDE, audit, firewall, VPN, USBGuard, '
          'LUKS, Secure Boot and kernel lockdown state',
          '/usr/local/bin/noid-status', [('Show', [])]),
         ('📖', 'Help Topics',
          'The guided noid-help index: per-topic explanations plus the '
          'complete inventory of helper commands',
          '/usr/local/bin/noid-help',
          [('Topics', []), ('Commands', ['commands'])]),
         ('🔍', 'Privacy Audit',
          'The bundled NoID Privacy audit for Linux — scores the posture, '
          'reports UNKNOWN and does not remediate by default',
          '/usr/local/bin/noid-audit',
          [('Offline', []), ('Online', ['--online'])]),
         ('🧮', 'Integrity Spot-Check',
          'Cross-checks SUID binaries, services, timers, cron jobs and RPM '
          'verification as live package and runtime evidence',
          '/usr/local/bin/noid-integrity-check',
          [('Standard', []), ('Extended', ['--all']),
           ('Brief', ['--brief'])]),
         ('🩺', 'DNS Diagnosis',
          'Shows resolver, link and route state; Evidence adds the recent '
          'systemd-resolved warnings and errors',
          '/usr/local/bin/noid-dns-diagnose',
          [('Status', ['status']), ('Evidence', ['evidence'])]),
         ('♻️', 'Pending-Reboot Check',
          'Reports whether an installed kernel or driver update still '
          'needs one restart to become active',
          '/usr/local/bin/noid-pending-reboot-check.sh',
          [('Check', ['--status'])]),
     ]),
    ('Integrity &amp; Notifications',
     'AIDE stays a user-owned trust decision: you review and commit every '
     'baseline yourself. These rows manage that workflow and the alerts.',
     [
         ('🧾', 'AIDE Baseline Review',
          'Prepare a new baseline candidate, review the diff, then commit '
          'its exact hash — never automatic',
          '/usr/local/sbin/noid-aide-baseline-review',
          [('Status', ['status']), ('Prepare', ['prepare'])]),
         ('🛡️', 'AIDE Daily Check',
          'Controls both layers together: the silent daily scan timer and '
          'the desktop notification popup',
          '/usr/local/sbin/noid-toggle-aide',
          [('Status', ['status']), ('Enable', ['on']),
           ('Disable', ['off'])]),
         ('💬', 'AIDE Popup Only',
          'Controls the desktop notification layer only — the silent '
          'daily scan timer keeps its own setting',
          '/usr/local/bin/noid-toggle-aide-popup',
          [('Status', ['status']), ('Enable', ['on']),
           ('Disable', ['off'])]),
         ('🔔', 'Audit Event Alerts',
          'Desktop notifications for selected high-signal audit events '
          'reviewed by NoID Privacy, not every audit record',
          '/usr/local/sbin/noid-toggle-audit-notify',
          [('Status', ['status']), ('Enable', ['on']),
           ('Disable', ['off'])]),
         ('🔬', 'Run AIDE Check Now',
          'Runs the supported AIDE check-only workflow now and writes a '
          'timestamped report without replacing its baseline',
          '/usr/local/sbin/noid-aide-check.sh', [('Run check', [])]),
     ]),
    ('Network',
     'WAN policy, LAN boundary and gateway pinning from the CLI side. '
     'The Network app is the full graphical surface for the same '
     'controls.',
     [
         ('🔒', 'WAN-Egress-Strict',
          'Pins endpoints from recognized NetworkManager VPN profile schemas '
          'and blocks other physical WAN paths',
          '/usr/local/sbin/noid-toggle-wan-strict',
          [('Status', ['status']), ('Enable', ['on']),
           ('Disable', ['off'])]),
         ('🌐', 'DNS Privacy Transport',
          'Strict Quad9 DoT globally and on physical links; VPN compatibility '
          'and plaintext recovery stay explicit',
          '/usr/local/sbin/noid-dns-mode',
          [('Status', ['status']), ('Strict', ['strict']),
           ('VPN compat.', ['opportunistic']), ('Plaintext', ['off']),
           ('Reset', ['reset'])]),
         ('📡', 'WAN-Strict Operations',
          'Pause briefly for captive portals, resume early, or rescan the '
          'NetworkManager profiles for endpoints',
          '/usr/local/sbin/noid-wan-strict',
          [('Status', ['status']), ('Pause 5 min', ['pause', '5']),
           ('Pause 30 min', ['pause', '30']), ('Resume', ['resume']),
           ('Block WAN', ['arm-empty', '--yes']),
           ('Rescan', ['scan-profiles'])]),
         ('🚧', 'LAN Exceptions',
          'Lists the per-IP LAN allow-list and the global enforcement '
          'state; add or revert entries in Network',
          '/usr/local/bin/noid-lan-allow',
          [('List', ['--list']), ('Global state', ['--global-state'])]),
         ('🧭', 'Network Audits',
          'Runs the read-only WAN, firewall, nftables and tunnel-MTU audits; '
          'the Network app remains the full graphical surface',
          '/usr/local/bin/noid-network-audit',
          [('WAN', ['wan']), ('Firewall', ['firewall']),
           ('nftables', ['nft']), ('Tunnel MTU', ['mtu'])]),
         ('🧱', 'LAN XDP Boundary',
          'Verifies the exact live XDP and TC attachment identity on every '
          'managed physical interface without changing policy',
          '/usr/local/sbin/noid-lan-xdp', [('Status', ['status'])]),
         ('🚦', 'Autostart Network Gate',
          'Reports whether the physical-link gate used by network-dependent '
          'desktop autostarts is currently open; runs no command',
          '/usr/local/bin/noid-autostart-netwait', [('Check', ['--check'])]),
         ('🧲', 'Gateway ARP Pin',
          'Shows the anti-spoofing gateway MAC binding; Re-learn fixes '
          '"no internet" after a router or link swap',
          '/usr/local/sbin/noid-arp-hardening.sh',
          [('Status', ['status']), ('Re-learn', ['refresh'])]),
     ]),
    ('Hardware &amp; Privacy Toggles',
     'The switches the Setup app exposes, plus the CLI-only extras. '
     'Status never changes anything; Enable/Disable do exactly one '
     'thing each.',
     [
         ('📶', 'Bluetooth',
          'Disable combines the rfkill block with WirePlumber bluez '
          'probe silencing; Enable restores normal use',
          '/usr/local/sbin/noid-toggle-bluetooth',
          [('Status', ['status']), ('Enable', ['on']),
           ('Disable', ['off'])]),
         ('📍', 'Location Services',
          'Controls GNOME’s global location-services choice while preserving '
          'the separate per-application permissions',
          '/usr/local/sbin/noid-toggle-location',
          [('Status', ['status']), ('Enable', ['on']),
           ('Disable', ['off'])]),
         ('🎤', 'Microphone',
          'Controls both layers: the GNOME app-permission block and the '
          'persistent PipeWire source policy',
          '/usr/local/bin/noid-toggle-microphone',
          [('Status', ['status']), ('Enable', ['on']),
           ('Disable', ['off'])]),
         ('🕘', 'Bash History',
          'Ephemeral keeps shell history in RAM only for this host; '
          'Persistent restores the on-disk default',
          '/usr/local/bin/noid-toggle-bash-history',
          [('Status', ['status']), ('Ephemeral', ['ephemeral']),
           ('Persistent', ['default'])]),
         ('🎮', 'Gaming Mode',
          'Re-opens 32-bit execution (reboot) and the Wine W^X boolean '
          'for Steam/Proton, installs Steam itself',
          '/usr/local/sbin/noid-toggle-gaming',
          [('Status', ['status']), ('Enable', ['on']),
           ('Disable', ['off'])]),
         ('🖨️', 'Printing',
          'Unmasks the local CUPS print stack on demand; network '
          'auto-discovery stays off and printers are added by address',
          '/usr/local/sbin/noid-toggle-printing',
          [('Status', ['status']), ('Enable', ['on']),
           ('Disable', ['off'])]),
         ('🎨', 'GTK GL Renderer',
          'Automatic only on portable NVIDIA-offload hybrids; manual on/off '
          'and topology-auto reset take effect after a re-login',
          '/usr/local/bin/noid-toggle-gsk-gl',
          [('Status', ['status']), ('Automatic', ['auto']), ('Enable', ['on']),
           ('Disable', ['off'])]),
         ('💤', 'Laptop Lid Close',
          'Shows real SW_LID hardware and effective logind state; choose '
          'Suspend, Lock or reset to the lower policy',
          '/usr/local/bin/noid-toggle-lid-action',
          [('Status', ['status']), ('Suspend', ['suspend']),
           ('Lock', ['lock']), ('Reset', ['reset'])]),
         ('🧷', 'USBGuard Devices',
          'Shows runtime versus persistent authorization, allows blocked '
          'devices and revokes exact durable rules',
          '/usr/local/bin/noid-usbguard-devices',
          [('Manage', []), ('Overview', ['status']),
           ('Allow', ['allow']), ('Revoke', ['revoke'])]),
     ]),
    ('Encryption &amp; Recovery',
     'Prepare recovery paths before you need them, and manage the '
     'boot/platform safeguards.',
     [
         ('🔐', 'LUKS Header Backup',
          'Guided, verified header backup to removable media — the '
          'recommended first-day recovery preparation',
          '/usr/local/bin/noid-luks-backup.sh',
          [('Backup', []), ('List backups', ['--list-existing'])]),
         ('📸', 'Pre-Change Snapshot',
          'Creates a Snapper checkpoint named "manual checkpoint" so a '
          'risky system change can be rolled back',
          '/usr/local/bin/noid-snap-pre',
          [('Create', ['manual checkpoint'])]),
         ('⏱️', 'Time Recovery (NTS)',
          'Assisted recovery for the rare case that secure time sync '
          'cannot start because the clock drifted far',
          '/usr/local/sbin/noid-time-recovery',
          [('Usage', ['--help'])]),
         ('🗝️', 'GRUB Password',
          'Protects boot-entry editing with a password; Set prompts '
          'interactively, Remove reverts to default',
          '/usr/local/sbin/noid-grub-password',
          [('Set', []), ('Remove', ['--remove'])]),
         ('⚙️', 'Intel ME Lockdown',
          'Shows the Intel Management Engine submodule lockdown state; '
          'Undo reverts the applied lockdown',
          '/usr/local/bin/noid-mei-lockdown',
          [('Status', ['--status']), ('Undo', ['--undo'])]),
         ('🔧', 'Intel ME Submodules',
          'Fine-grained blocking or restoring of single MEI submodules '
          '(hdcp/pxp/wdt) — read the usage first',
          '/usr/local/bin/noid-mei-restore-submodules',
          [('Usage', ['--help'])]),
     ]),
    ('Firefox &amp; Thunderbird',
     'Per-profile browser and mail hardening helpers — relaxations are '
     'explicit and reversible.',
     [
         ('🦊', 'Relax Fingerprint Protection',
          'Explicitly relaxes fingerprint protection in all registered '
          'Firefox profiles; Restore removes only that override',
          '/usr/local/bin/noid-firefox-relax-fpp',
          [('Usage', ['--help']), ('Apply', []),
           ('Restore', ['--restore'])]),
         ('📹', 'Relax WebRTC',
          'Explicitly allows WebRTC in all registered Firefox profiles; '
          'Restore removes only that compatibility override',
          '/usr/local/bin/noid-firefox-relax-webrtc',
          [('Usage', ['--help']), ('Apply', []),
           ('Restore', ['--restore'])]),
         ('🎞️', 'Firefox DRM',
          'Enables or disables Widevine playback (Netflix and similar) '
          'per profile — off by default for privacy',
          '/usr/local/bin/noid-firefox-drm',
          [('Status', ['status']), ('Enable', ['enable']),
           ('Disable', ['disable'])]),
         ('🧪', 'Isolated Firefox Profile',
          'Creates separate task-specific registered Firefox profiles beside '
          'your main profile; List shows the existing set',
          '/usr/local/bin/noid-firefox-create-isolated-profile',
          [('List', ['--list']), ('Usage', ['--help'])]),
         ('🧰', 'Firefox Profile Hardening',
          'Lists profile hardening state; Apply all repairs every safely '
          'eligible registered Firefox profile',
          '/usr/local/bin/noid-firefox-harden-profile',
          [('Status', []), ('Apply all', ['--all'])]),
         ('✉️', 'Thunderbird Profile Hardening',
          'Re-applies the complete NoID Privacy mail hardening to every '
          'registered Thunderbird profile; safe to repeat',
          '/usr/local/bin/noid-thunderbird-harden-profile',
          [('Apply all', ['--all'])]),
     ]),
    ('Repositories &amp; Optional Software',
     'Repository trust policy and opt-in drivers.',
     [
         ('📦', 'Third-Party Repos',
          'The curated third-party repository policy (RPM Fusion, '
          'negativo17, VSCodium): inspect, thin, restore',
          '/usr/local/bin/noid-toggle-thirdparty-repos',
          [('Status', ['status']), ('List', ['list']),
           ('Minimal', ['minimal']), ('Restore', ['restore'])]),
         ('🧊', 'Fedora Flatpaks Remote',
          'Enables or disables the Fedora flatpak remote that exists '
          'beside the default flathub-verified subset',
          '/usr/local/sbin/noid-toggle-fedora-flatpaks',
          [('Status', ['status']), ('Enable', ['on']),
           ('Disable', ['off'])]),
         ('🖥️', 'DisplayLink Driver',
          'Opt-in driver for DisplayLink docks and USB display adapters, '
          'including its reviewed managed-uninstall path',
          '/usr/local/bin/noid-install-displaylink',
          [('Usage', ['--help']), ('Install', ['--akmod']),
           ('Uninstall', ['--uninstall'])]),
     ]),
    ('Opt-in Installers',
     'The same pinned, fingerprint-verified installers the Setup app '
     'offers — every component behind its own prompt.',
     [
         ('🧠', 'Claude Code CLI / Extension',
          'Pinned native CLI and/or VSCodium extension from Anthropic — '
          'exact bytes, no npm, no remote installer',
          '/usr/local/bin/noid-claude-install',
          [('Install', []), ('Update', ['--update'])]),
         ('🤖', 'Codex CLI / Extension',
          'Pinned native CLI and/or VSIX from OpenAI — telemetry-aware '
          'prompts, no npm, no remote installer',
          '/usr/local/bin/noid-codex-install',
          [('Install', []), ('Update', ['--update'])]),
         ('🛰️', 'Proton VPN',
          'Official Proton Fedora repository; the signing-key fingerprint '
          'is verified before anything is trusted',
          '/usr/local/bin/noid-protonvpn-install',
          [('Install', []), ('Uninstall', ['--uninstall'])]),
         ('🔏', 'Mullvad VPN',
          'Official Mullvad repository; the code-signing key fingerprint '
          'is verified before anything is trusted',
          '/usr/local/bin/noid-mullvad-install',
          [('Install', []), ('Uninstall', ['--uninstall'])]),
         ('🎯', 'NVIDIA Driver',
          'Proprietary driver with a Secure-Boot MOK walkthrough where '
          'required; Dry-run previews every change',
          '/usr/local/bin/noid-nvidia-install.sh',
          [('Dry-run', ['--dry-run']), ('Install', []),
           ('Rollback', ['--rollback'])]),
         ('🎬', 'Multimedia Codecs',
          'H.264/H.265 codecs plus supported GPU decode drivers; actual '
          'hardware acceleration remains device-dependent',
          '/usr/local/bin/noid-complete-setup.sh',
          [('Dry-run', ['--dry-run']), ('Install', [])]),
     ]),
    ('System Update',
     'The full update workflow — the Update app runs the same script '
     'with a graphical progress view.',
     [
         ('🔄', 'Full System Update',
          'DNF, Flatpak, firmware and browser-hardening updates; AIDE '
          'check-only evidence runs only with an active baseline',
          '/usr/local/bin/noid-update-all.sh',
          [('Run update', [])]),
    ]),
]

# Closed privilege manifest. A catalog action receives root only when its
# exact (canonical helper path, visible action label) pair appears here.
# tests/37 binds this set to the reviewed producer contracts and rejects
# stale or unknown entries.
SUDO_ACTIONS = {
    ('/usr/local/sbin/noid-aide-check.sh', 'Run check'),
    ('/usr/local/sbin/noid-aide-baseline-review', 'Status'),
    ('/usr/local/sbin/noid-aide-baseline-review', 'Prepare'),
    ('/usr/local/sbin/noid-toggle-aide', 'Enable'),
    ('/usr/local/sbin/noid-toggle-aide', 'Disable'),
    ('/usr/local/bin/noid-toggle-aide-popup', 'Enable'),
    ('/usr/local/bin/noid-toggle-aide-popup', 'Disable'),
    ('/usr/local/sbin/noid-toggle-audit-notify', 'Enable'),
    ('/usr/local/sbin/noid-toggle-audit-notify', 'Disable'),
    ('/usr/local/sbin/noid-toggle-wan-strict', 'Enable'),
    ('/usr/local/sbin/noid-toggle-wan-strict', 'Disable'),
    ('/usr/local/sbin/noid-wan-strict', 'Status'),
    ('/usr/local/sbin/noid-wan-strict', 'Pause 5 min'),
    ('/usr/local/sbin/noid-wan-strict', 'Pause 30 min'),
    ('/usr/local/sbin/noid-wan-strict', 'Resume'),
    ('/usr/local/sbin/noid-wan-strict', 'Block WAN'),
    ('/usr/local/sbin/noid-wan-strict', 'Rescan'),
    ('/usr/local/sbin/noid-arp-hardening.sh', 'Status'),
    ('/usr/local/sbin/noid-arp-hardening.sh', 'Re-learn'),
    # M11b reads root-only resolver server state for the complete record and
    # refuses a non-root caller outright, so an unprivileged row could only
    # ever print its "Re-run: sudo noid-dns-diagnose evidence" hint. `Status`
    # stays unprivileged because it needs none of that state.
    ('/usr/local/bin/noid-dns-diagnose', 'Evidence'),
    ('/usr/local/sbin/noid-toggle-bluetooth', 'Enable'),
    ('/usr/local/sbin/noid-toggle-bluetooth', 'Disable'),
    ('/usr/local/bin/noid-toggle-bash-history', 'Ephemeral'),
    ('/usr/local/bin/noid-toggle-bash-history', 'Persistent'),
    ('/usr/local/sbin/noid-toggle-gaming', 'Enable'),
    ('/usr/local/sbin/noid-toggle-gaming', 'Disable'),
    ('/usr/local/sbin/noid-toggle-printing', 'Enable'),
    ('/usr/local/sbin/noid-toggle-printing', 'Disable'),
    ('/usr/local/bin/noid-toggle-gsk-gl', 'Automatic'),
    ('/usr/local/bin/noid-toggle-gsk-gl', 'Enable'),
    ('/usr/local/bin/noid-toggle-gsk-gl', 'Disable'),
    ('/usr/local/bin/noid-usbguard-devices', 'Overview'),
    ('/usr/local/bin/noid-usbguard-devices', 'Manage'),
    ('/usr/local/bin/noid-usbguard-devices', 'Allow'),
    ('/usr/local/bin/noid-usbguard-devices', 'Revoke'),
    ('/usr/local/bin/noid-snap-pre', 'Create'),
    ('/usr/local/sbin/noid-grub-password', 'Set'),
    ('/usr/local/sbin/noid-grub-password', 'Remove'),
    ('/usr/local/bin/noid-mei-lockdown', 'Undo'),
    ('/usr/local/bin/noid-toggle-thirdparty-repos', 'Minimal'),
    ('/usr/local/bin/noid-toggle-thirdparty-repos', 'Restore'),
    ('/usr/local/sbin/noid-toggle-fedora-flatpaks', 'Enable'),
    ('/usr/local/sbin/noid-toggle-fedora-flatpaks', 'Disable'),
    ('/usr/local/bin/noid-install-displaylink', 'Install'),
    ('/usr/local/bin/noid-install-displaylink', 'Uninstall'),
}

# Closed review manifest for multi-verb rows whose default has no argv.
# "read-only" means the bare helper invokes only its reporting/default
# non-remediating path; ordinary service/access logging can still occur.
# "interactive-confirmed" means the producer source was reviewed and tests/37
# binds its confirmation prompt before the first selected mutation. Any new
# empty-argv default fails the catalog gate until it is classified here.
EMPTY_ARGV_DEFAULT_SAFETY = {
    '/usr/local/bin/noid-help': 'read-only',
    '/usr/local/bin/noid-audit': 'read-only',
    '/usr/local/bin/noid-integrity-check': 'read-only',
    '/usr/local/bin/noid-firefox-harden-profile': 'read-only',
    '/usr/local/bin/noid-usbguard-devices': 'interactive-confirmed',
    '/usr/local/bin/noid-luks-backup.sh': 'interactive-confirmed',
    '/usr/local/sbin/noid-grub-password': 'interactive-confirmed',
    '/usr/local/bin/noid-claude-install': 'interactive-confirmed',
    '/usr/local/bin/noid-codex-install': 'interactive-confirmed',
    '/usr/local/bin/noid-protonvpn-install': 'interactive-confirmed',
    '/usr/local/bin/noid-mullvad-install': 'interactive-confirmed',
}

# Exact basenames and reviewed semantic classes for shipped executables that
# are not safe fixed-action Tools rows. Dictionary membership intentionally
# remains the runtime exclusion test; the values make the reason auditable and
# tests/37 rejects an unknown class. A new producer must therefore become a
# curated row or state why it is not one instead of disappearing behind a name
# heuristic.
SWEEP_EXCLUDE = {
    'noid-arp-state-guard.sh': 'internal-hook',
    'noid-askpass': 'app-support',
    'noid-audit-notify-controller': 'facade-backend',
    'noid-audit-prune.sh': 'internal-hook',
    'noid-audit-space-alert': 'internal-hook',
    'noid-audit-space-critical': 'internal-hook',
    'noid-auditd-rotate.sh': 'internal-hook',
    'noid-bluetooth-apply-default': 'internal-hook',
    'noid-codium-launcher-sync': 'transaction-recovery',
    'noid-cpu-vendor-detect.sh': 'internal-hook',
    'noid-firefox-playground-init.sh': 'session-worker',
    'noid-firefox-reassert': 'transaction-recovery',
    'noid-firefox-setup.sh': 'session-worker',
    'noid-firewalld-zone-enforce.sh': 'internal-hook',
    'noid-firstboot-cmdline.sh': 'internal-hook',
    'noid-firstboot-setup.sh': 'session-worker',
    'noid-fss-keys-init.sh': 'internal-hook',
    'noid-gnome-software-backend-stop': 'app-support',
    'noid-gnome-software-launcher-sync': 'transaction-recovery',
    'noid-gnome-software-quit': 'app-support',
    'noid-gnome-software-rpm': 'app-support',
    'noid-host-identity': 'transaction-recovery',
    'noid-install-logs-prune.sh': 'internal-hook',
    'noid-lan-topology-boot-refresh.sh': 'internal-hook',
    'noid-lan-topology-refresh.sh': 'internal-hook',
    'noid-live-avatar-backfill.sh': 'internal-hook',
    'noid-lan-xdp-notify': 'session-worker',
    'noid-live-mount-hardening.sh': 'internal-hook',
    'noid-location-apply': 'facade-backend',
    'noid-location-sync-watch': 'session-worker',
    'noid-misc-logs-prune.sh': 'internal-hook',
    'noid-mount-hardening.sh': 'internal-hook',
    'noid-network': 'app-surface',
    'noid-nm-privacy-prune.sh': 'internal-hook',
    'noid-nm-scope-physical-profiles': 'internal-hook',
    'noid-privacy-linux.sh': 'facade-backend',
    'noid-restore-branding': 'transaction-recovery',
    'noid-restore-gnome-flow': 'transaction-recovery',
    'noid-restore-identity': 'transaction-recovery',
    'noid-selinux-policy-reconcile': 'transaction-recovery',
    'noid-snap-rollback': 'required-arguments',
    'noid-snapper-init.sh': 'internal-hook',
    'noid-snapper-prune.sh': 'internal-hook',
    'noid-thunderbird-reassert': 'transaction-recovery',
    'noid-tools': 'app-surface',
    'noid-update': 'app-surface',
    'noid-update-all-launcher.sh': 'app-support',
    'noid-usbguard-add-user.sh': 'internal-hook',
    'noid-usbguard-allow-device': 'facade-backend',
    'noid-usbguard-firstboot.sh': 'internal-hook',
    'noid-usbguard-remove-gnome-wildcard': 'internal-hook',
    'noid-user-avatar-backfill.sh': 'internal-hook',
    'noid-verify-gnome-privacy-contract': 'transaction-recovery',
    'noid-wan-ipv6-disable.sh': 'internal-hook',
    'noid-wan-strict-bootstrap.sh': 'facade-backend',
    'noid-wan-strict-publish-status': 'internal-hook',
    'noid-wan-strict-scan-profiles.sh': 'facade-backend',
    'noid-welcome.sh': 'app-surface',
    'noid-wireguard-mtu-reconcile': 'internal-hook',
}

SWEEP_DIR = '/usr/local/bin'
SWEEP_NAME_RE = re.compile(r'noid-[A-Za-z0-9._-]+')
SWEEP_STRAY_SUFFIXES = ('.bak', '.rpmnew', '.rpmorig', '.rpmsave', '~')


class InventoryError(RuntimeError):
    """The helper directory could not be inspected through its trusted path."""


def _is_safe_executable(path, allow_root_only=False):
    """Require a closed root-owned executable, optionally root-access-only."""
    try:
        metadata = os.lstat(path)
    except OSError:
        return False
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == 0
        and metadata.st_gid == 0
        and metadata.st_nlink == 1
        and metadata.st_mode & 0o7022 == 0
        and metadata.st_mode & 0o111 != 0
        and (allow_root_only or os.access(path, os.X_OK))
    )


def _is_safe_privilege_launcher(path=SUDO):
    """Accept the canonical root-owned setuid launcher, but no writable form."""
    try:
        metadata = os.lstat(path)
    except OSError:
        return False
    mode = stat.S_IMODE(metadata.st_mode)
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == 0
        and metadata.st_gid == 0
        and metadata.st_nlink == 1
        and mode & 0o4000 != 0
        and mode & 0o3000 == 0
        and mode & 0o022 == 0
        and mode & 0o111 == 0o111
        and os.access(path, os.X_OK)
    )


def _action_argv(path, label, extra):
    """Build exact argv, adding sudo only for a reviewed catalog action."""
    command = [path] + list(extra)
    if (path, label) in SUDO_ACTIONS:
        return [SUDO, '--'] + command
    return command


def _spawn_terminal(shell_cmd):
    """Open a graphical terminal running the given shell command.

    SHARED-LOGIC marker: keep in sync with the Setup (M13) and Network
    (M36) copies — each first-party app stays standalone by design.
    """
    candidates = [
        ('/usr/bin/ptyxis', ['/usr/bin/ptyxis', '--', '/usr/bin/bash', '-c']),
        ('/usr/bin/gnome-terminal',
         ['/usr/bin/gnome-terminal', '--', '/usr/bin/bash', '-c']),
        ('/usr/bin/xterm', ['/usr/bin/xterm', '-e', '/usr/bin/bash', '-c']),
    ]
    for binary, argv in candidates:
        if _is_safe_executable(binary):
            try:
                subprocess.Popen(argv + [shell_cmd],
                                 stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL,
                                 start_new_session=True)
                return True
            except OSError as exc:
                print(f'Cannot start terminal {binary}: {exc}',
                      file=sys.stderr)
                continue
    return False


def run_in_terminal(argv):
    """Run one helper argv in a transient terminal with ONE close prompt.

    Same contract as the Setup app wrapper: NOID_WELCOME_SPAWN=1 marks an
    app-owned terminal (companion scripts skip their standalone hold),
    the wrapper always holds once so output stays readable on every
    terminal, and the trailing `exit 0` keeps Ptyxis from stacking its own
    process-failed hold on a non-zero helper exit."""
    return _spawn_terminal(
        'NOID_WELCOME_SPAWN=1 ' + shlex.join(argv) + '; rc=$?; echo; '
        '[ $rc -ne 0 ] && echo "Command exited with error (rc=$rc)"; '
        'read -r -p "Press ENTER to close..." || :; exit 0')


def _sweep_entries():
    """Return every clean-name, unclassified post-install noid-* entry.

    Curated BASENAMES are skipped wherever they live, so a stale bin copy of
    a curated sbin helper cannot resurface as runnable. Entry type and execute
    mode never suppress evidence: the GUI decides whether an entry is safe to
    run, while fresh-image verification fails on every unclassified match."""
    curated = {Path(entry[3]).name
               for _t, _d, entries in CATALOG for entry in entries}
    directory = Path(SWEEP_DIR)
    try:
        metadata = os.lstat(directory)
        resolved = directory.resolve(strict=True)
    except OSError as exc:
        raise InventoryError(f'cannot inspect {SWEEP_DIR}') from exc
    if (not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_mode & 0o022
            or resolved != directory):
        raise InventoryError(f'unsafe helper directory: {SWEEP_DIR}')

    found = []
    try:
        items = sorted(directory.iterdir(), key=lambda item: item.name)
    except OSError as exc:
        raise InventoryError(f'cannot enumerate {SWEEP_DIR}') from exc
    for item in items:
        name = item.name
        if (not SWEEP_NAME_RE.fullmatch(name)
                or name.endswith(SWEEP_STRAY_SUFFIXES)
                or name in SWEEP_EXCLUDE or name in curated):
            continue
        found.append(str(item))
    return found


# --- Window ------------------------------------------------------------------

class ToolsWindow(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app,
                         default_width=noid_ui.DEFAULT_WIDTH,
                         default_height=noid_ui.DEFAULT_HEIGHT)
        self.set_title('NoID Privacy Tools')

        toolbar = Adw.ToolbarView()
        self.set_content(toolbar)
        toolbar.add_top_bar(noid_ui.app_header(
            'NoID Privacy Tools', 'Helper commands, curated',
            'noid-privacy-tools'))

        self.toast_overlay = Adw.ToastOverlay()
        page = Adw.PreferencesPage()
        self.toast_overlay.set_child(page)
        toolbar.set_content(self.toast_overlay)

        for group_title, group_desc, entries in CATALOG:
            group = Adw.PreferencesGroup()
            group.set_title(group_title)
            group.set_description(group_desc)
            for emoji, title, subtitle, path, verbs in entries:
                group.add(self._tool_row(emoji, title, subtitle, path, verbs))
            page.add(group)

        page.add(self._sweep_group())

    def _toast(self, message, timeout=4):
        noid_ui.toast(self.toast_overlay, message, timeout)

    def _run_button(self, title, get_argv):
        button = Gtk.Button(label='Run')
        button.add_css_class('suggested-action')
        button.set_valign(Gtk.Align.CENTER)
        noid_ui.accessible(
            button, f'Run: {title}',
            f'Run the selected {title} action in a terminal')
        button.connect('clicked', lambda _b: self._run(get_argv()))
        return button

    def _run(self, argv):
        if argv is None:
            self._toast('Select an action first.', 4)
            return
        if argv[:2] == [SUDO, '--']:
            helper = argv[2] if len(argv) > 2 else ''
            safe = (_is_safe_privilege_launcher()
                    and _is_safe_executable(helper, allow_root_only=True))
        else:
            helper = argv[0] if argv else ''
            safe = _is_safe_executable(helper)
        if not safe:
            self._toast(f'Helper is missing or unsafe: {helper}', 5)
            return
        if not run_in_terminal(argv):
            self._toast(
                'Could not open a terminal. Run the command from Ptyxis '
                'instead.', 5)

    @staticmethod
    def _selected_argv(path, verbs, dropdown):
        selected = dropdown.get_selected()
        if selected >= len(verbs):
            return None
        label, extra = verbs[selected]
        return _action_argv(path, label, extra)

    def _tool_row(self, emoji, title, subtitle, path, verbs):
        row = Adw.ActionRow()
        row.set_title(title)
        row.set_subtitle(subtitle)
        if len(verbs) == 1:
            get_argv = (lambda p=path, v=verbs:
                        _action_argv(p, v[0][0], v[0][1]))
        else:
            # Minimum-width Gtk.DropDown suffix instead of Adw.ComboRow: the
            # combo row lets a wrapping subtitle squeeze its selected label
            # into an ellipsized stub, while the explicit floor protects the
            # compact default layout and still permits accessibility growth.
            dropdown = Gtk.DropDown.new_from_strings(
                [label for label, _argv in verbs])
            dropdown.set_selected(0)
            dropdown.set_valign(Gtk.Align.CENTER)
            dropdown.set_size_request(VERB_DROPDOWN_MIN_WIDTH, -1)
            noid_ui.accessible(
                dropdown, f'{title} action',
                f'Choose which {title} action Run executes')
            row.add_suffix(dropdown)
            get_argv = (lambda p=path, v=verbs, d=dropdown:
                        self._selected_argv(p, v, d))
        noid_ui.add_emoji_prefix(row, emoji)
        row.add_suffix(self._run_button(title, get_argv))
        root_only = all((path, label) in SUDO_ACTIONS
                        for label, _extra in verbs)
        if not _is_safe_executable(path, allow_root_only=root_only):
            row.set_sensitive(False)
            row.set_subtitle(
                subtitle + ' — missing or unsafe on this system')
        noid_ui.accessible_row(row)
        return row

    def _sweep_group(self):
        group = Adw.PreferencesGroup()
        group.set_title('Other Detected Helpers')
        group.set_description(
            'noid-* commands added after installation that have no curated '
            'entry above. Run requests --help from safe executables.')
        try:
            extras = _sweep_entries()
        except InventoryError:
            row = Adw.ActionRow()
            row.set_title('Inventory unavailable')
            row.set_subtitle(
                'The helper directory could not be inspected safely')
            noid_ui.add_emoji_prefix(row, '⚠️')
            noid_ui.accessible_row(row)
            group.add(row)
            return group
        if not extras:
            row = Adw.ActionRow()
            row.set_title('(none)')
            row.set_subtitle('Every installed helper has a curated entry')
            noid_ui.add_emoji_prefix(row, '🗃️')
            noid_ui.accessible_row(row)
            group.add(row)
            return group
        for path in extras:
            name = Path(path).name
            row = Adw.ActionRow()
            row.set_title(name)
            runnable = _is_safe_executable(path)
            if runnable:
                row.set_subtitle(
                    'Uncurated trusted executable — Run requests its --help')
            else:
                row.set_subtitle(
                    'Uncurated non-runnable entry — review it from a terminal')
            noid_ui.add_emoji_prefix(row, '🗃️')
            if runnable:
                row.add_suffix(self._run_button(
                    name, lambda p=path: [p, '--help']))
            noid_ui.accessible_row(row)
            group.add(row)
        return group


class NoIDToolsApp(noid_ui.NoIDApplication):
    def __init__(self):
        super().__init__(APP_ID, 'noid-privacy-tools')

    def do_activate(self):
        win = self.props.active_window
        if win is None:
            win = ToolsWindow(self)
        win.present()


def main():
    args = sys.argv[1:]
    if args == ['--verify-fresh-inventory']:
        try:
            extras = _sweep_entries()
        except InventoryError as exc:
            print(f'Fresh-image helper inventory unavailable: {exc}',
                  file=sys.stderr)
            return 2
        if extras:
            print('Fresh image has unclassified noid-* helpers:',
                  file=sys.stderr)
            for path in extras:
                print(f'  {path}', file=sys.stderr)
            return 1
        print('OK: fresh-image helper inventory is fully classified')
        return 0

    if args == ['--verify-privilege-launcher']:
        if not _is_safe_privilege_launcher():
            print(f'Unsafe or unavailable privilege launcher: {SUDO}',
                  file=sys.stderr)
            return 1
        print(f'OK: privilege launcher is trusted: {SUDO}')
        return 0

    if args in (['--help'], ['-h']):
        print(__doc__ or '')
        print('\nUsage:')
        print('  noid-tools          Open the NoID Privacy Tools launcher')
        return 0
    if args:
        print(f'Unknown argument: {ascii(args[0])}', file=sys.stderr)
        return 2

    app = NoIDToolsApp()
    return app.run([sys.argv[0]])


if __name__ == '__main__':
    sys.exit(main())
NOID_TOOLS_PY_EOF
python3 -c 'import ast, pathlib, sys; ast.parse(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))' \
    "$TOOLS_CANDIDATE" \
    || fail "noid-tools candidate has invalid Python syntax"
PYTHONPATH=/usr/lib/noid-privacy python3 "$TOOLS_CANDIDATE" --help \
    | grep -q '^  noid-tools' \
    || fail "noid-tools candidate import/help smoke failed"
PYTHONPATH=/usr/lib/noid-privacy \
    python3 "$TOOLS_CANDIDATE" --verify-privilege-launcher \
    >/dev/null \
    || fail "noid-tools rejected the canonical privilege launcher"
if PYTHONPATH=/usr/lib/noid-privacy \
        python3 "$TOOLS_CANDIDATE" --invalid-noid-tools-option \
        >/dev/null 2>&1; then
    fail "noid-tools candidate accepts an unknown argument"
fi

publish_root_file "$TOOLS_CANDIDATE" /usr/local/bin/noid-tools 0755
log "STEP 1: /usr/local/bin/noid-tools deployed (Python 3 + GTK4 + Adw + shared UI)"

# ---------------------------------------------------------------------------
# STEP 2: Deploy /usr/share/applications/noid-tools.desktop
# ---------------------------------------------------------------------------

cat > "$DESKTOP_CANDIDATE" <<'NOID_TOOLS_DESKTOP_EOF'
[Desktop Entry]
Version=1.0
Type=Application
Name=NoID Privacy Tools
GenericName=Helper Command Launcher
Comment=Discover and run the NoID Privacy helper commands
Exec=/usr/local/bin/noid-tools
Icon=noid-privacy-tools
StartupWMClass=com.noidprivacy.Tools
StartupNotify=true
Categories=System;
Terminal=false
Keywords=NoID Privacy;Privacy;Tools;CLI;Helper;Hardening;Toggle;
NOID_TOOLS_DESKTOP_EOF
/usr/bin/desktop-file-validate "$DESKTOP_CANDIDATE" \
    || fail "noid-tools.desktop candidate is invalid"
publish_root_file "$DESKTOP_CANDIDATE" \
    /usr/share/applications/noid-tools.desktop 0644
log "STEP 2: /usr/share/applications/noid-tools.desktop deployed"

# ---------------------------------------------------------------------------
# STEP 3: Verify
# ---------------------------------------------------------------------------

log "STEP 3: Module 37 verify"
ver_ok=0
ver_fail=0
if [ -f /usr/local/bin/noid-tools ] \
        && [ ! -L /usr/local/bin/noid-tools ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' /usr/local/bin/noid-tools)" = "0:0:755:1" ] \
        && cmp -s -- "$TOOLS_CANDIDATE" /usr/local/bin/noid-tools \
        && /usr/sbin/matchpathcon -V /usr/local/bin/noid-tools >/dev/null; then
    log "  ✓ /usr/local/bin/noid-tools exact bytes, metadata and label"
    ver_ok=$((ver_ok + 1))
else
    log "  ✗ /usr/local/bin/noid-tools bytes/metadata/label verification failed"
    ver_fail=$((ver_fail + 1))
fi
if python3 -c "import ast; ast.parse(open('/usr/local/bin/noid-tools', encoding='utf-8').read())" 2>/dev/null; then
    log "  ✓ noid-tools Python syntax valid"
    ver_ok=$((ver_ok + 1))
else
    log "  ✗ noid-tools Python syntax ERROR"
    ver_fail=$((ver_fail + 1))
fi
if [ -f /usr/lib/noid-privacy/noid_ui.py ] \
        && [ ! -L /usr/lib/noid-privacy/noid_ui.py ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' \
            /usr/lib/noid-privacy/noid_ui.py 2>/dev/null)" = "0:0:644:1" ] \
        && [ "$(readlink -e -- /usr/lib/noid-privacy/noid_ui.py \
            2>/dev/null)" = /usr/lib/noid-privacy/noid_ui.py ] \
        && /usr/sbin/matchpathcon -V /usr/lib/noid-privacy/noid_ui.py \
            >/dev/null \
        && grep -q '^import noid_ui$' /usr/local/bin/noid-tools \
        && /usr/local/bin/noid-tools --help 2>/dev/null \
            | grep -q '^  noid-tools'; then
    log "  ✓ shared UI contract is canonical and noid-tools --help executes"
    ver_ok=$((ver_ok + 1))
else
    log "  ✗ noid-tools import/--help smoke test failed"
    ver_fail=$((ver_fail + 1))
fi
# Every curated helper path referenced by the catalog must exist in the
# installed image (the catalog would otherwise ship dead rows).
catalog_paths=$(grep -oE "'/usr/local/(bin|sbin)/noid-[A-Za-z0-9._-]+'" \
        /usr/local/bin/noid-tools | tr -d "'" | sort -u || true)
catalog_path_count=$(printf '%s\n' "$catalog_paths" \
    | grep -c '^/usr/local/' || true)
catalog_missing=0
if [ "$catalog_path_count" -lt 40 ]; then
    log "  ✗ curated helper inventory is implausibly small ($catalog_path_count paths)"
    catalog_missing=1
fi
while IFS= read -r helper_path; do
    [ -n "$helper_path" ] || continue
    helper_metadata=$(stat -Lc '%u:%g:%a:%h' -- "$helper_path" \
        2>/dev/null || true)
    helper_safe=0
    if [ ! -f "$helper_path" ] || [ -L "$helper_path" ] \
            || [ ! -x "$helper_path" ] \
            || ! [[ "$helper_metadata" =~ ^0:0:[0-7]{3,4}:1$ ]]; then
        :
    else
        helper_mode=${helper_metadata#0:0:}
        helper_mode=${helper_mode%:1}
        if (( (8#$helper_mode & 07022) == 0 )); then
            helper_safe=1
        fi
    fi
    if [ "$helper_safe" -ne 1 ]; then
        log "  ✗ curated helper missing, unsafe or not executable: $helper_path ($helper_metadata)"
        catalog_missing=$((catalog_missing + 1))
    fi
done <<< "$catalog_paths"
if [ "$catalog_missing" -eq 0 ]; then
    log "  ✓ every curated helper path is installed + executable"
    ver_ok=$((ver_ok + 1))
else
    ver_fail=$((ver_fail + 1))
fi
if /usr/local/bin/noid-tools --verify-fresh-inventory; then
    log "  ✓ fresh-image helper inventory fully classified"
    ver_ok=$((ver_ok + 1))
else
    log "  ✗ fresh-image helper inventory has unclassified entries"
    ver_fail=$((ver_fail + 1))
fi
if [ -f /usr/share/applications/noid-tools.desktop ] \
        && [ ! -L /usr/share/applications/noid-tools.desktop ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' /usr/share/applications/noid-tools.desktop)" = "0:0:644:1" ] \
        && cmp -s -- "$DESKTOP_CANDIDATE" \
            /usr/share/applications/noid-tools.desktop \
        && /usr/sbin/matchpathcon -V /usr/share/applications/noid-tools.desktop \
            >/dev/null; then
    log "  ✓ noid-tools.desktop exact bytes, metadata and label"
    ver_ok=$((ver_ok + 1))
else
    log "  ✗ noid-tools.desktop bytes/metadata/label verification failed"
    ver_fail=$((ver_fail + 1))
fi
if /usr/bin/desktop-file-validate \
        /usr/share/applications/noid-tools.desktop 2>/dev/null; then
    log "  ✓ noid-tools.desktop validates"
    ver_ok=$((ver_ok + 1))
else
    log "  ✗ noid-tools.desktop validation FAIL"
    ver_fail=$((ver_fail + 1))
fi

# Module 37 health-stamp (shell-sourceable key=value; M99
# EXPECTED_STAMPS verifies presence at finalize).
if [ "$ver_fail" -eq 0 ]; then
# M37_HEALTH_PUBLICATION_BEGIN
    if [ ! -d "$STAMP_DIR" ] || [ -L "$STAMP_DIR" ] \
       || [ "$(stat -Lc '%u:%g:%a' -- "$STAMP_DIR" 2>/dev/null || true)" != \
            0:0:755 ] \
       || ! /usr/sbin/matchpathcon -V "$STAMP_DIR" >/dev/null; then
        fail "shared health-stamp directory drifted before Module 37 publication"
    fi
    verify_m37_health_stamp() {
        local path="$1"
        [ -f "$path" ] \
            && [ ! -L "$path" ] \
            && [ "$(stat -Lc '%u:%g:%a:%h' -- "$path" 2>/dev/null || true)" = \
                0:0:644:1 ] \
            && [ "$(wc -l < "$path")" -eq 10 ] \
            && [ "$(grep -c '^module=' "$path" || true)" -eq 1 ] \
            && [ "$(grep -c '^name=' "$path" || true)" -eq 1 ] \
            && [ "$(grep -c '^version=' "$path" || true)" -eq 1 ] \
            && [ "$(grep -c '^status=' "$path" || true)" -eq 1 ] \
            && [ "$(grep -c '^timestamp=' "$path" || true)" -eq 1 ] \
            && [ "$(grep -c '^checks_passed=' "$path" || true)" -eq 1 ] \
            && [ "$(grep -c '^checks_total=' "$path" || true)" -eq 1 ] \
            && grep -qFx '# NoID Privacy — Module 37 Health Stamp' "$path" \
            && grep -qFx \
                '# Written at end of %post verification when all checks pass.' \
                "$path" \
            && grep -qFx \
                '# Format: shell-sourceable key=value. See docs/engineering-health-stamp-pattern.md.' \
                "$path" \
            && grep -qFx 'module=37' "$path" \
            && grep -qFx 'name=noid-tools-app' "$path" \
            && grep -qFx 'version=1' "$path" \
            && grep -qFx 'status=ok' "$path" \
            && grep -Eq \
                '^timestamp=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' \
                "$path" \
            && grep -qFx "checks_passed=${ver_ok}" "$path" \
            && grep -qFx "checks_total=$((ver_ok + ver_fail))" "$path"
    }
    STAMP_CANDIDATE=$(mktemp \
        "$STAMP_DIR/.stamp-37-noid-tools-app.ok.XXXXXXXX") \
        || fail "cannot create Module 37 health-stamp candidate"
    cat > "$STAMP_CANDIDATE" <<STAMP_EOF
# NoID Privacy — Module 37 Health Stamp
# Written at end of %post verification when all checks pass.
# Format: shell-sourceable key=value. See docs/engineering-health-stamp-pattern.md.
module=37
name=noid-tools-app
version=1
status=ok
timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
checks_passed=${ver_ok}
checks_total=$((ver_ok + ver_fail))
STAMP_EOF
    chown root:root -- "$STAMP_CANDIDATE"
    chmod 0644 -- "$STAMP_CANDIDATE"
    /usr/sbin/restorecon -F -- "$STAMP_CANDIDATE" \
        || fail "cannot label Module 37 health-stamp candidate"
    /usr/sbin/matchpathcon -V "$STAMP_CANDIDATE" >/dev/null \
        || fail "Module 37 health-stamp candidate label differs"
    verify_m37_health_stamp "$STAMP_CANDIDATE" \
        || fail "staged Module 37 health-stamp contract is invalid"
    sync -- "$STAMP_CANDIDATE" \
        || fail "cannot sync Module 37 health-stamp candidate"
    STAMP_PUBLICATION_ACTIVE=1
    publish_root_file "$STAMP_CANDIDATE" "$STAMP" 0644
    /usr/sbin/matchpathcon -V "$STAMP" >/dev/null \
        || fail "published Module 37 health-stamp label differs"
    sync -- "$STAMP" \
        || fail "cannot sync published Module 37 health stamp"
    sync -- "$STAMP_DIR" \
        || fail "cannot sync Module 37 health-stamp directory"
    verify_m37_health_stamp "$STAMP" \
        || fail "published Module 37 health-stamp contract is invalid"
    rm -f -- "$STAMP_CANDIDATE"
    STAMP_CANDIDATE=""
    STAMP_PUBLICATION_ACTIVE=0
    log "  ✓ exact M37 health stamp published atomically: $STAMP"
# M37_HEALTH_PUBLICATION_END
else
    log "  ✗ M37 verification FAILED ($ver_fail failures) — no health stamp"
    exit 1
fi

log "=== Module 37 complete: NoID Privacy Tools App installed ==="

%end

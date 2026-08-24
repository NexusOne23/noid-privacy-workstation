# ============================================================================
# Module 36 — NoID Privacy Network App
# Status: LOCKED 2026-08-07 (v52) — distinguish best-effort tunnel DoT from the global selector.
#
# Standalone GTK4 + libadwaita network-management GUI, one of the four
# NoID Privacy first-party apps beside Setup, Update and Tools. Ships:
#   - /usr/local/bin/noid-network                   Python 3 + Adw GUI
#   - /usr/local/bin/noid-network-audit             closed read-only audits
#   - /usr/share/applications/noid-network.desktop  (StartupWMClass=
#     com.noidprivacy.Network, Categories=Settings;Security;)
#   + health stamp
#
# Four subsystems on one surface (ViewSwitcher pages):
#   1. WAN Privacy — toggle WAN-egress-strict through the session privilege
#      router; pause/resume/arm-empty/reset via noid-wan-strict. Pinned-endpoints list
#      reads /var/lib/noid-privacy/wan-strict-endpoints.txt (mode 0644 so
#      the GUI displays endpoints without re-auth; auto-populated via the
#      scan-profiles path-unit on profile changes).
#   2. LAN Exceptions — direction-aware per-IP exceptions via
#      noid-lan-allow --add, with TCP/UDP port selectors for inbound traffic;
#      ComboRow durations (Permanent / 15 / 60 / 240 min), edit/revert actions,
#      and the emergency global override behind a destructive-action confirm.
#   3. DNS Privacy — global Quad9 plus managed physical-link DNSOverTLS mode
#      with strict/opportunistic/off choices. VPN/private per-link transport
#      is not rewritten; unset profiles inherit M23's best-effort opportunistic
#      default, explicit profile values win, and routing precedence is shown.
#   4. Network Status — VPN (nmcli), killswitch, default zone, WAN-strict
#      state, LAN-block state, DNS (resolvectl), gateway ARP-hardening status
#      + re-learn button (after a router hardware swap) + 4 shell-free
#      terminal launchers for formatted WAN/firewalld/nftables/MTU audits.
#
# Constraint notes (keep on future edits):
#   - Backend CLIs ship elsewhere: noid-toggle-wan-strict + noid-wan-strict
#     (M06), noid-lan-allow (M05), noid-arp-hardening.sh (M04). Icon via M32
#     branding pipeline. M08 pins uncached polkit AUTH_ADMIN to the exact
#     wan-strict, lan-allow, DNS-mode and arp-hardening program paths. The M04
#     state file
#     is mode 0644 so the status display reads it non-privileged.
#   - Privilege UX: an exact, already-authorized noninteractive sudo rule is
#     honored only when `sudo -n -l -l -- <argv>` shows the matching entry
#     tagged `!authenticate`; a bare policy-permission answer is not
#     evidence of a passwordless route and must not select sudo. Otherwise
#     installed sessions execute the exact pinned backend directly through
#     pkexec (never `pkexec bash -c`). The exact Live ISO session always uses
#     its passwordless `sudo -n --` route because liveuser deliberately has no
#     password and cannot satisfy AUTH_ADMIN. All routes preserve argv
#     boundaries. Resync polls 500ms x 120 = 60s before timeout, then gives
#     TERM and KILL four nonblocking polls each. A root child the session
#     cannot signal becomes an explicit orphaned error instead of freezing
#     GTK. Success is toasted only on rc=0; pkexec-cancel (rc=126) stays
#     separate from failures.
#   - .desktop Categories stays "Settings;Security;" (single menu placement;
#     3 main categories triggered a desktop-file-validate multi-menu hint).
# ============================================================================

%post --erroronfail --log=/var/log/ks-36-noid-network-app.log
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

log() { echo "[noid-36-noid-network-app] $*"; }
fail() {
    log "FAIL: $*"
    exit 1
}

ROOT_PUBLICATION_TMP=""

# Root-owned payloads are validated before publication, staged beside their
# destination and renamed atomically. Canonical parent checks reject symlink or
# writable-directory traversal before any destination is touched.
ensure_root_dir() {
    local path=$1 mode=${2:-0755} current="" component metadata current_mode
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
            0:0:*) current_mode=${metadata##*:} ;;
            *) fail "directory is not root-owned: $current ($metadata)" ;;
        esac
        [[ "$current_mode" =~ ^[0-7]{3,4}$ ]] \
            || fail "directory mode is invalid: $current ($current_mode)"
        (( (8#$current_mode & 0022) == 0 )) \
            || fail "directory is group/other-writable: $current ($current_mode)"
    done < <(printf '%s\n' "${path#/}" | tr '/' '\n')
    chmod "$mode" -- "$path" || fail "cannot set directory mode: $path"
    chown root:root -- "$path" || fail "cannot set directory owner: $path"
    [ "$(stat -Lc '%u:%g:%a' -- "$path" 2>/dev/null)" = \
        "0:0:${mode#0}" ] || fail "directory postcondition failed: $path"
    restorecon -F -- "$path" || fail "cannot label directory: $path"
    matchpathcon -V "$path" >/dev/null \
        || fail "directory label differs from policy: $path"
    sync -- "$path" || fail "cannot sync directory: $path"
}

publish_root_file() {
    local source=$1 destination=$2 requested_mode=$3
    local parent temporary mode=${requested_mode#0} source_state parent_state
    local source_mode parent_mode
    parent=${destination%/*}
    [ -f "$source" ] && [ ! -L "$source" ] \
        || fail "publication source is missing, non-regular or symlinked: $source"
    [ "$(readlink -e -- "$source" 2>/dev/null)" = "$source" ] \
        || fail "publication source is non-canonical: $source"
    source_state=$(stat -Lc '%u:%g:%a:%h' -- "$source" 2>/dev/null) \
        || fail "cannot inspect publication source: $source"
    case "$source_state" in
        0:0:*:1)
            source_mode=${source_state#0:0:}
            source_mode=${source_mode%:1}
            ;;
        *) fail "publication source metadata is unsafe: $source ($source_state)" ;;
    esac
    [[ "$source_mode" =~ ^[0-7]{3,4}$ ]] \
        || fail "publication source mode is invalid: $source ($source_mode)"
    (( (8#$source_mode & 0022) == 0 )) \
        || fail "publication source is group/other-writable: $source ($source_mode)"
    [ -d "$parent" ] && [ ! -L "$parent" ] \
        || fail "publication parent is unsafe: $parent"
    [ "$(readlink -e -- "$parent" 2>/dev/null)" = "$parent" ] \
        || fail "publication parent is non-canonical: $parent"
    parent_state=$(stat -Lc '%u:%g:%a' -- "$parent" 2>/dev/null) \
        || fail "cannot inspect publication parent: $parent"
    case "$parent_state" in
        0:0:*) parent_mode=${parent_state##*:} ;;
        *) fail "publication parent is not root-owned: $parent ($parent_state)" ;;
    esac
    [[ "$parent_mode" =~ ^[0-7]{3,4}$ ]] \
        || fail "publication parent mode is invalid: $parent ($parent_mode)"
    (( (8#$parent_mode & 0022) == 0 )) \
        || fail "publication parent is writable by group/other: $parent ($parent_mode)"
    [ ! -e "$destination" ] || [ -f "$destination" ] || [ -L "$destination" ] \
        || fail "publication target is neither a regular file nor a symlink: $destination"
    temporary=$(mktemp "$parent/.noid-network-publish.XXXXXXXX") \
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

log "=== Module 36 post-install: NoID Privacy Network App ==="

NETWORK_CANDIDATE=""
AUDIT_CANDIDATE=""
DESKTOP_CANDIDATE=""
STAMP_CANDIDATE=""
STAMP_DIR=/var/lib/noid-privacy
STAMP="$STAMP_DIR/stamp-36-noid-network.ok"
STAMP_PUBLICATION_ACTIVE=0
cleanup_candidates() {
    local saved_rc=$? candidate cleanup_failed=0
    trap - EXIT
    trap '' HUP INT TERM
    for candidate in \
        "${ROOT_PUBLICATION_TMP:-}" \
        "${NETWORK_CANDIDATE:-}" \
        "${AUDIT_CANDIDATE:-}" \
        "${DESKTOP_CANDIDATE:-}" \
        "${STAMP_CANDIDATE:-}"; do
        [ -n "$candidate" ] || continue
        if ! rm -f -- "$candidate"; then
            log "FAIL: could not retire staged Module 36 payload: $candidate"
            cleanup_failed=1
        fi
    done
    if [ "${STAMP_PUBLICATION_ACTIVE:-0}" -eq 1 ]; then
        if ! rm -f -- "$STAMP"; then
            log "FAIL: could not retire incomplete Module 36 health stamp"
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

# M36_HEALTH_INVALIDATION_BEGIN
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
        || fail "cannot invalidate stale Module 36 health stamp"
    sync -- "$STAMP_DIR"
fi
log "  [OK] prior Module 36 health stamp is absent"
# M36_HEALTH_INVALIDATION_END

ensure_root_dir /usr/local/bin 0755
ensure_root_dir /usr/share/applications 0755
NETWORK_CANDIDATE=$(mktemp /var/tmp/noid-network.XXXXXXXX) \
    || fail "cannot create noid-network candidate"
AUDIT_CANDIDATE=$(mktemp /var/tmp/noid-network-audit.XXXXXXXX) \
    || fail "cannot create noid-network-audit candidate"
DESKTOP_CANDIDATE=$(mktemp --suffix=.desktop \
    /var/tmp/noid-network-desktop.XXXXXXXX) \
    || fail "cannot create noid-network.desktop candidate"

# ---------------------------------------------------------------------------
# STEP 1: Deploy /usr/local/bin/noid-network (Python 3 + GTK4 + Adw 1)
# ---------------------------------------------------------------------------

cat > "$NETWORK_CANDIDATE" <<'NOID_NETWORK_PY_EOF'
#!/usr/bin/python3
"""NoID Privacy Network — Network management GUI app (GTK4 + libadwaita).

Standalone GUI for WAN-egress-strict + LAN per-IP exceptions + DNS
transport + Network state. One of the four NoID Privacy first-party apps
beside Setup, Update and Tools.

Sections (ViewSwitcher tabs):
  1. WAN Privacy    — toggle WAN-egress-strict + pause + endpoint list
  2. LAN Exceptions — add IPv4 exceptions, revoke valid legacy entries + global
  3. DNS Privacy    — strict-default global + physical DoT selector
  4. Network Status — VPN / killswitch / firewall / DNS + gateway ARP-hardening
                      status + re-learn (router-swap recovery)

Backend CLIs:
  /usr/local/sbin/noid-toggle-wan-strict on|off|status
  /usr/local/sbin/noid-wan-strict       status|pause|resume|arm-empty|reset|scan-profiles
  /usr/local/bin/noid-lan-allow         --add <IPv4> --direction ...|--revert|--list|on|off|status
  /usr/local/sbin/noid-dns-mode         status|opportunistic|strict|off|reset
  /usr/local/sbin/noid-arp-hardening.sh refresh   (re-learn gateway MAC, privileged)

Polkit AUTH_ADMIN (uncached): /etc/polkit-1/rules.d/60-noid-toggle-privacy-services.rules
"""

import sys
import os
import signal
import ipaddress
import json
import pwd
import re
import stat
import subprocess
import uuid
from pathlib import Path

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw, GLib
sys.path.insert(0, '/usr/lib/noid-privacy')
import noid_ui

APP_ID = 'com.noidprivacy.Network'

# --- Constants ---------------------------------------------------------------

WAN_STATEFILE = '/var/lib/noid-privacy/wan-strict-endpoints.txt'
WAN_STATE_DIR = '/var/lib/noid-privacy'
WAN_STATE_HEADER = 'NOID-WAN-ENDPOINTS-V2'
WAN_STATUS_FILE = '/run/noid-privacy/wan-strict-status'
WAN_RUNTIME_DIR = '/run/noid-privacy'
WAN_TOGGLE_CLI = '/usr/local/sbin/noid-toggle-wan-strict'
WAN_STRICT_CLI = '/usr/local/sbin/noid-wan-strict'
LAN_ALLOW_CLI = '/usr/local/bin/noid-lan-allow'
DNS_MODE_CLI = '/usr/local/sbin/noid-dns-mode'
ARP_CLI = '/usr/local/sbin/noid-arp-hardening.sh'
ARP_STATE = '/var/lib/noid-privacy/arp-hardening.state'  # mode 0644 (GUI-readable)
ARP_STATE_DIR = '/var/lib/noid-privacy'
ARP_DISABLED = '/var/lib/noid-privacy/arp-hardening.disabled'
ARP_DISPATCHER = '/etc/NetworkManager/dispatcher.d/90-arp-hardening'
ARP_PREUP = '/etc/NetworkManager/dispatcher.d/pre-up.d/90-arp-hardening'
ARP_NOWAIT = '/etc/NetworkManager/dispatcher.d/no-wait.d/90-arp-hardening'
ARP_TEMPLATE = '/usr/share/noid-privacy/arp-hardening/90-arp-hardening.template'
NETWORK_AUDIT_CLI = '/usr/local/bin/noid-network-audit'
SUDO_CLI = '/usr/bin/sudo'
PKEXEC_CLI = '/usr/bin/pkexec'
NMCLI_CLI = '/usr/bin/nmcli'
IP_CLI = '/usr/bin/ip'
FIREWALL_CLI = '/usr/bin/firewall-cmd'
RESOLVECTL_CLI = '/usr/bin/resolvectl'
ACTION_POLL_LIMIT = 120
ACTION_TERM_GRACE_POLLS = 4
ACTION_KILL_GRACE_POLLS = 4
PRIVILEGED_STDERR_TAIL_LIMIT = 4096
ROOT_STATE_MAX_BYTES = 1024 * 1024

# --- Helpers -----------------------------------------------------------------

def _read_root_published_ascii(path, parent, mode, label):
    """Read one root-published file through a closed metadata boundary."""
    try:
        parent_info = os.lstat(parent)
        parent_mode = stat.S_IMODE(parent_info.st_mode)
        if (not stat.S_ISDIR(parent_info.st_mode)
                or parent_info.st_uid != 0 or parent_info.st_gid != 0
                or parent_mode & 0o022
                or os.path.realpath(parent) != parent):
            raise ValueError(f'{label} parent metadata mismatch')
    except OSError as exc:
        raise ValueError(f'cannot inspect {label} parent') from exc

    info = os.lstat(path)
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != 0 or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) != mode
            or info.st_size > ROOT_STATE_MAX_BYTES):
        raise ValueError(f'{label} metadata mismatch')
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if ((opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)
                or not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1 or opened.st_uid != 0
                or opened.st_gid != 0
                or stat.S_IMODE(opened.st_mode) != mode
                or opened.st_size > ROOT_STATE_MAX_BYTES):
            raise ValueError(f'{label} identity changed while opening')
        with os.fdopen(fd, 'r', encoding='ascii', newline='') as stream:
            fd = -1
            content = stream.read(ROOT_STATE_MAX_BYTES + 1)
            if len(content) > ROOT_STATE_MAX_BYTES:
                raise ValueError(f'{label} exceeds the read bound')
            return content
    finally:
        if fd >= 0:
            os.close(fd)


def _wan_runtime_mode():
    """Read the root-published, machine-readable nft/timer postcondition."""
    try:
        content = _read_root_published_ascii(
            WAN_STATUS_FILE, WAN_RUNTIME_DIR, 0o644, 'WAN runtime status')
    except FileNotFoundError:
        return 'UNKNOWN'
    except (OSError, UnicodeError, ValueError) as exc:
        print(f'Cannot inspect WAN runtime status: {exc}', file=sys.stderr)
        return 'ERROR'
    if content.count('\n') != 1 or not content.endswith('\n') \
            or not content.startswith('MODE='):
        return 'ERROR'
    mode = content[5:-1]
    if mode not in {
            'DISABLED', 'GRACE_BOOTSTRAP', 'GRACE_PAUSED',
            'STRICT', 'STRICT_EMPTY', 'ERROR'}:
        return 'ERROR'
    return mode


def _wan_feature_enabled(mode):
    """Feature state comes only from a valid published runtime mode."""
    return mode in {'GRACE_BOOTSTRAP', 'GRACE_PAUSED', 'STRICT', 'STRICT_EMPTY'}


def _wan_mode_text(mode):
    return {
        'DISABLED': (
            'DISABLED — user opt-out',
            'Direct physical-WAN egress is possible.'),
        'GRACE_BOOTSTRAP': (
            'GRACE — bootstrap',
            'No VPN endpoint is pinned; direct WAN is temporarily allowed.'),
        'GRACE_PAUSED': (
            'GRACE — temporarily paused',
            'Direct WAN is allowed until the auto-resume timer fires.'),
        'STRICT': (
            'STRICT — endpoint-reconciled',
            'Physical WAN is restricted to durable VPN tuples; DNS candidates are bounded.'),
        'STRICT_EMPTY': (
            'STRICT — no endpoints',
            'Fail-closed: ordinary physical WAN is blocked; only the documented '
            'systemd-resolved bootstrap exception remains.'),
        'ERROR': (
            'ERROR — runtime state invalid',
            'Do not assume protection; inspect noid-wan-strict.service.'),
        'UNKNOWN': (
            'UNKNOWN — runtime state unavailable',
            'No verified postcondition was published after boot. The toggle '
            'stays locked until a verified state exists; inspect '
            'noid-wan-strict.service in a terminal.'),
    }[mode]


def _group_wan_endpoint_records(records):
    """Group durable provenance by the exact tuple nftables enforces."""
    grouped = {}
    for proto, address, port, family, source, profile, fingerprint, expiry \
            in records:
        key = (family, address, port, proto)
        grouped.setdefault(key, set()).add(
            (source, profile, fingerprint, expiry))
    return [
        (proto, address, port, family, tuple(sorted(details)))
        for (family, address, port, proto), details
        in sorted(grouped.items())
    ]


def _is_live_session():
    """Recognize only NoID Privacy's passwordless Fedora Live session."""
    try:
        username = pwd.getpwuid(os.getuid()).pw_name
        cmdline = Path('/proc/cmdline').read_text(
            encoding='ascii', errors='strict').split()
        live_boot = any(token == 'rd.live.image'
                        or token.startswith('rd.live.image=')
                        for token in cmdline)
        return (username == 'liveuser' and live_boot
                and Path('/run/initramfs/livedev').exists())
    except (KeyError, OSError, UnicodeError) as exc:
        print(f'Cannot verify Live privilege route: {exc}', file=sys.stderr)
        return False


def _noninteractive_sudo_authorizes(argv):
    """True only when sudo policy runs this exact argv without a password.

    A plain `sudo -l <cmd>` exit status is not that proof. sudo(8) documents it
    as "permitted by the security policy", which the image's own
    `%wheel ALL=(ALL) ALL` rule satisfies for every wheel member, and whether
    `-l` may run unprompted is governed by sudoers(5) `listpw`, whose default
    `any` is already satisfied by the unrelated NOPASSWD drop-ins this image
    ships for the lid-action and GNOME-software helpers. The probe therefore
    reported success for every backend, the sudo route was taken, and
    `sudo -n --` then failed with "a password is required" because none of
    these backends has a sudoers rule at all -- they are polkit-only. Every
    privileged action in this app failed that way on a default installation
    while the provisioned AUTH_ADMIN route went unused.

    The verbose listing does carry the needed evidence: it prints the matching
    entry only, tagging a passwordless rule as `Options: !authenticate`. That
    output is translated, so the C locale is forced -- the same reason every
    other helper here pins it.
    """
    environment = dict(os.environ, LC_ALL='C.UTF-8', LANG='C.UTF-8')
    try:
        result = subprocess.run(
            ['/usr/bin/sudo', '-n', '-l', '-l', '--'] + argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
            text=True,
            timeout=3,
            check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f'Cannot verify noninteractive sudo route: {exc}',
              file=sys.stderr)
        return False
    if result.returncode != 0:
        return False
    listing = result.stdout or ''
    return ('!authenticate' in listing
            and listing.count('Matched:') == 1)


def _privileged_argv(argv):
    """Return a direct, shell-free privilege route for one backend argv."""
    if _is_live_session() or _noninteractive_sudo_authorizes(argv):
        # livesys-session-extra installs exact liveuser NOPASSWD sudo and the
        # installer removes both account and sudoers entry before first boot.
        # Installed systems may also carry an explicit owner-authorized rule.
        # Failure stays fail-closed: sudo -n never asks and returns non-zero.
        return [SUDO_CLI, '-n', '--'] + argv
    return [PKEXEC_CLI] + argv


def _privileged_async(argv):
    """Spawn one privileged backend action. Return its Popen handle."""
    try:
        proc = subprocess.Popen(
            _privileged_argv(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            start_new_session=True)
    except OSError as exc:
        print(f'Cannot start privileged action: {exc}', file=sys.stderr)
        return None
    # poll()/wait() with an unread PIPE can deadlock when a backend emits
    # enough diagnostics to fill the kernel buffer. Drain it on every GUI
    # poll without blocking and retain only a bounded tail for the toast.
    try:
        os.set_blocking(proc.stderr.fileno(), False)
    except (OSError, ValueError) as exc:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except (ProcessLookupError, OSError):
            pass
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, OSError):
                pass
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                print('Cannot reap privileged action after launch failure',
                      file=sys.stderr)
        try:
            proc.stderr.close()
        except (OSError, ValueError):
            pass
        print(f'Cannot secure privileged diagnostics pipe: {exc}',
              file=sys.stderr)
        return None
    proc._noid_stderr_tail = b''
    return proc


def _drain_privileged_stderr(proc, final=False):
    """Drain a nonblocking backend stderr pipe into one bounded byte tail."""
    stream = getattr(proc, 'stderr', None)
    if stream is None:
        return
    tail = getattr(proc, '_noid_stderr_tail', b'')
    while True:
        try:
            chunk = os.read(stream.fileno(), 4096)
        except BlockingIOError:
            break
        except (OSError, ValueError):
            break
        if not chunk:
            break
        tail = (tail + chunk)[-PRIVILEGED_STDERR_TAIL_LIMIT:]
    proc._noid_stderr_tail = tail
    if final:
        try:
            stream.close()
        except (OSError, ValueError):
            pass


def _finish_privileged_action(proc, attempts):
    """Return (state, rc) for an asynchronous privileged process.

    States: pending, success, cancelled, failed, spawn-error, timeout,
    orphaned. After the 60-second action bound, TERM and KILL each receive a
    bounded two-second polling grace. An unprivileged GUI cannot necessarily
    signal a backend after pkexec has changed it to root; that case remains
    responsive and becomes an explicit orphaned error instead of an unbounded
    wait on GTK's main thread.
    """
    attempts[0] += 1
    if proc is None:
        return ('spawn-error', None)

    _drain_privileged_stderr(proc)
    rc = proc.poll()
    if rc is None:
        if getattr(proc, '_noid_orphan_reported', False):
            return ('pending', None)
        if attempts[0] < ACTION_POLL_LIMIT:
            return ('pending', None)
        if not getattr(proc, '_noid_timeout_started', False):
            proc._noid_timeout_started = True
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except OSError as exc:
                print(f'Cannot terminate timed-out action: {exc}',
                      file=sys.stderr)
            return ('pending', None)
        kill_at = ACTION_POLL_LIMIT + ACTION_TERM_GRACE_POLLS
        if attempts[0] < kill_at:
            return ('pending', None)
        if not getattr(proc, '_noid_kill_sent', False):
            proc._noid_kill_sent = True
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError as exc:
                print(f'Cannot kill timed-out action: {exc}', file=sys.stderr)
            return ('pending', None)
        orphan_at = kill_at + ACTION_KILL_GRACE_POLLS
        if attempts[0] < orphan_at:
            return ('pending', None)
        proc._noid_orphan_reported = True
        return ('orphaned', None)

    # poll() has collected the child; wait() makes that lifecycle contract
    # explicit and returns immediately for an already-collected process.
    rc = proc.wait()
    _drain_privileged_stderr(proc, final=True)
    if getattr(proc, '_noid_timeout_started', False):
        return ('timeout', rc)
    if rc == 0:
        return ('success', rc)
    if rc == 126:
        return ('cancelled', rc)
    return ('failed', rc)


def _privileged_stderr_tail(proc):
    """Return a sanitized single-line tail retained by the async drainer."""
    data = getattr(proc, '_noid_stderr_tail', b'')
    if not data:
        return ''
    if isinstance(data, bytes):
        data = data.decode('utf-8', 'replace')
    # Backends are local and root-owned, but terminal escape/control bytes
    # still do not belong in a graphical toast.
    data = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', data)
    line = next(
        (candidate.strip() for candidate in reversed(data.splitlines())
         if candidate.strip()),
        '')
    line = ''.join(
        char if char == '\t' or ord(char) >= 0x20 else ' '
        for char in line if char != '\x7f')
    return ' '.join(line.split())[:200]


def _privileged_failure_text(state, rc, detail=''):
    if state == 'cancelled':
        return 'Cancelled — no change made'
    if state == 'spawn-error':
        return 'ERROR — privileged action could not be started'
    if state == 'timeout':
        return 'ERROR — privileged action timed out and was stopped'
    if state == 'orphaned':
        return ('ERROR — privileged action timed out but could not be stopped; '
                'check the system state before retrying')
    base = f'ERROR — privileged action failed (exit {rc})'
    return f'{base}: {detail}' if detail else base


def _spawn_terminal(command_argv):
    """Open a graphical terminal and preserve exact command argv boundaries."""
    if (not isinstance(command_argv, (list, tuple)) or not command_argv
            or not all(isinstance(arg, str) and arg for arg in command_argv)):
        return False
    candidates = [
        ('/usr/bin/ptyxis', ['--']),
        ('/usr/bin/gnome-terminal', ['--']),
        ('/usr/bin/xterm', ['-e']),
    ]
    for terminal, prefix in candidates:
        if os.path.isfile(terminal) and os.access(terminal, os.X_OK):
            try:
                subprocess.Popen([terminal] + prefix + list(command_argv),
                                 stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL,
                                 start_new_session=True)
                return True
            except OSError as exc:
                print(f'Cannot start terminal {terminal}: {exc}', file=sys.stderr)
                continue
    return False


def _run_cmd_checked(argv, timeout=3):
    """Run a non-privileged command and return (exit status, stdout)."""
    try:
        result = subprocess.run(argv, capture_output=True, text=True,
                                timeout=timeout)
        if result.returncode != 0:
            detail = result.stderr.strip() or f'exit {result.returncode}'
            print(f'Command failed ({argv[0]}): {detail}', file=sys.stderr)
        return result.returncode, result.stdout
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f'Command failed ({argv[0]}): {exc}', file=sys.stderr)
        return 127, ''


def _run_cmd(argv, timeout=3):
    """Run a non-privileged command and return stdout only on success."""
    rc, output = _run_cmd_checked(argv, timeout)
    return output if rc == 0 else ''


def _nmcli_fields(line, expected):
    """Decode one escaped nmcli terse row with an exact field count."""
    fields = []
    field = []
    escaped = False
    for char in line:
        if escaped:
            if char not in (':', '\\'):
                return None
            field.append(char)
            escaped = False
        elif char == '\\':
            escaped = True
        elif char == ':':
            fields.append(''.join(field))
            field = []
        else:
            field.append(char)
    if escaped:
        return None
    fields.append(''.join(field))
    return fields if len(fields) == expected else None


def _active_nm_connections():
    """Return a closed list of active NM records, or None when unverifiable."""
    rc, output = _run_cmd_checked([
        NMCLI_CLI, '--terse', '--escape', 'yes',
        '--fields', 'UUID,NAME,TYPE,DEVICE',
        'connection', 'show', '--active',
    ], timeout=4)
    if rc != 0:
        return None
    records = []
    seen_uuids = set()
    for line in output.splitlines():
        parts = _nmcli_fields(line, 4)
        if parts is None or not parts[0] or not parts[1] or not parts[2]:
            return None
        try:
            connection_uuid = str(uuid.UUID(parts[0]))
        except ValueError:
            return None
        if connection_uuid != parts[0] or connection_uuid in seen_uuids:
            return None
        seen_uuids.add(connection_uuid)
        records.append({
            'uuid': connection_uuid,
            'name': parts[1],
            'type': parts[2],
            'device': parts[3],
        })
    return records


def _device_address(device):
    """Return one canonical global address for a verified NM device."""
    if not device or device == '--':
        return ''
    rc, output = _run_cmd_checked(
        [IP_CLI, '-j', 'address', 'show', 'dev', device], timeout=3)
    if rc != 0:
        return ''
    try:
        payload = json.loads(output)
    except (TypeError, json.JSONDecodeError):
        return ''
    if (not isinstance(payload, list) or len(payload) != 1
            or not isinstance(payload[0], dict)
            or payload[0].get('ifname') != device
            or not isinstance(payload[0].get('addr_info'), list)):
        return ''
    addresses = []
    for entry in payload[0]['addr_info']:
        if not isinstance(entry, dict) or entry.get('scope') != 'global':
            continue
        family = entry.get('family')
        value = entry.get('local')
        if family not in ('inet', 'inet6') or not isinstance(value, str):
            continue
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError:
            continue
        if ((family == 'inet') != isinstance(parsed, ipaddress.IPv4Address)
                or parsed.is_unspecified or parsed.is_multicast
                or parsed.is_loopback):
            continue
        addresses.append((0 if family == 'inet' else 1, str(parsed)))
    return sorted(addresses)[0][1] if addresses else ''


def _dns_mode_state():
    """Consume the DNS backend's closed machine-readable state."""
    rc, output = _run_cmd_checked(
        [DNS_MODE_CLI, '--status-machine'], timeout=5)
    if rc != 0:
        return None
    lines = output.splitlines()
    if len(lines) != 8 or lines[0] != 'NOID-DNS-MODE-V2':
        return None
    state = {}
    for line in lines[1:]:
        if line.count('=') != 1:
            return None
        key, value = line.split('=', 1)
        if key in state or not key or not value:
            return None
        state[key] = value
    if set(state) != {
            'selection', 'configured', 'runtime_global',
            'physical_configured', 'physical_runtime', 'scope', 'link_mode'}:
        return None
    if state['selection'] not in {
            'default', 'off', 'opportunistic', 'strict', 'invalid'}:
        return None
    if state['configured'] not in {
            'no', 'opportunistic', 'yes', 'unknown'}:
        return None
    if state['runtime_global'] not in {
            'no', 'opportunistic', 'yes', 'unknown'}:
        return None
    if state['physical_configured'] not in {
            'none', 'default', 'no', 'opportunistic', 'yes', 'mixed',
            'unknown'}:
        return None
    if state['physical_runtime'] not in {
            'none', 'no', 'opportunistic', 'yes', 'mixed', 'unknown'}:
        return None
    if state['scope'] not in {
            'global', 'physical', 'link', 'mixed', 'unknown'}:
        return None
    if state['link_mode'] not in {
            'none', 'no', 'opportunistic', 'yes', 'mixed', 'unknown'}:
        return None
    return state


def _validate_ip(text):
    """Return (family, address_str) on success, (None, None) on failure."""
    text = (text or '').strip()
    try:
        ip = ipaddress.ip_address(text)
        family = 'ipv4' if isinstance(ip, ipaddress.IPv4Address) else 'ipv6'
        return (family, str(ip))
    except ValueError:
        return (None, None)


def _validate_endpoint_ip(text):
    """Mirror M06's canonical, non-loopback endpoint-address contract."""
    family, canonical = _validate_ip(text)
    if canonical is None:
        return (None, None)
    ip = ipaddress.ip_address(canonical)
    if ip.is_unspecified or ip.is_multicast or ip.is_loopback:
        return (None, None)
    return (family, canonical)


def _wan_endpoint_records():
    """Return validated display tuples and an optional closed-state error."""
    try:
        content = _read_root_published_ascii(
            WAN_STATEFILE, WAN_STATE_DIR, 0o644, 'WAN endpoint state')
    except FileNotFoundError:
        return ([], None)
    except (OSError, UnicodeError, ValueError) as exc:
        detail = getattr(exc, 'strerror', None) or str(exc) \
            or type(exc).__name__
        return ([], f'Cannot read endpoint state: {detail}')

    lines = content.splitlines()
    if not lines:
        return ([], None)
    if lines[0] != WAN_STATE_HEADER:
        return (
            [],
            'Unknown/legacy endpoint state; strict bootstrap will fail closed.',
        )

    endpoints = []
    records = set()
    for line in lines[1:]:
        parts = line.split(' ')
        if (len(parts) != 7 or any(not part for part in parts)
                or parts[2] not in ('literal', 'authenticated', 'retained')
                or parts[3] not in ('tcp', 'udp')
                or re.fullmatch(r'[0-9a-f]{64}', parts[1]) is None
                or not parts[5].isdigit()
                or not parts[6].isdigit()):
            return (
                [],
                'Invalid endpoint state entry; strict bootstrap will fail closed.',
            )
        try:
            profile_uuid = str(uuid.UUID(parts[0]))
            port = int(parts[5], 10)
            expiry = int(parts[6], 10)
        except ValueError:
            profile_uuid, port, expiry = '', 0, -1
        family, canonical = _validate_endpoint_ip(parts[4])
        expiry_valid = ((parts[2] == 'literal' and expiry == 0)
                        or (parts[2] in ('authenticated', 'retained')
                            and expiry > 0))
        if (profile_uuid != parts[0] or family is None
                or canonical is None or not 1 <= port <= 65535
                or not expiry_valid):
            return (
                [],
                'Invalid endpoint state entry; strict bootstrap will fail closed.',
            )
        record = (
            profile_uuid, parts[1], parts[2], parts[3],
            canonical, port, expiry,
        )
        if record in records:
            return (
                [],
                'Duplicate endpoint state entry; strict bootstrap will fail closed.',
            )
        records.add(record)
        # Must stay in lockstep with the eight names
        # _group_wan_endpoint_records() unpacks: proto, address, port, family,
        # source, profile, fingerprint, expiry. Dropping the fingerprint and
        # pre-truncating the profile here raised ValueError in the consumer and
        # would also have collapsed two distinct provenance records that share
        # an endpoint into one. The row subtitle does its own [:8] truncation,
        # so the full UUID belongs in the tuple.
        endpoints.append((
            parts[3], canonical, port, family, parts[2],
            profile_uuid, parts[1], expiry,
        ))
    return (endpoints, None)


def _arp_state():
    """Parse the M04 arp-hardening.state file (mode 0644) into a dict.

    Returns {} unless parent/file metadata, the complete five-record schema
    and M04's marker/dispatcher lifecycle match exactly. A consistent empty
    pre-learning state returns {}; corruption returns {'ERROR': ...}. State is
    data, never shell input."""
    state = {}
    invalid = {'ERROR': 'state-contract'}
    expected = {'ENABLED', 'WAN_IFACE', 'GATEWAY_IP',
                'GATEWAY_MAC', 'LEARNED_AT'}
    try:
        parent = os.lstat(ARP_STATE_DIR)
        dispatcher_parent = os.lstat(os.path.dirname(ARP_DISPATCHER))
        preup_parent = os.lstat(os.path.dirname(ARP_PREUP))
        nowait_parent = os.lstat(os.path.dirname(ARP_NOWAIT))
        template = os.lstat(ARP_TEMPLATE)
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0
                or parent.st_gid != 0
                or stat.S_IMODE(parent.st_mode) != 0o755
                or not stat.S_ISDIR(dispatcher_parent.st_mode)
                or dispatcher_parent.st_uid != 0
                or dispatcher_parent.st_gid != 0
                or stat.S_IMODE(dispatcher_parent.st_mode) != 0o755
                or not stat.S_ISDIR(preup_parent.st_mode)
                or preup_parent.st_uid != 0 or preup_parent.st_gid != 0
                or stat.S_IMODE(preup_parent.st_mode) != 0o755
                or not stat.S_ISDIR(nowait_parent.st_mode)
                or nowait_parent.st_uid != 0 or nowait_parent.st_gid != 0
                or stat.S_IMODE(nowait_parent.st_mode) != 0o755
                or not stat.S_ISREG(template.st_mode)
                or template.st_uid != 0 or template.st_gid != 0
                or template.st_nlink != 1
                or stat.S_IMODE(template.st_mode) != 0o644):
            return invalid
    except OSError as exc:
        print(f'Cannot inspect ARP state parent: {exc}', file=sys.stderr)
        return invalid
    try:
        metadata = os.lstat(ARP_STATE)
    except FileNotFoundError:
        if (os.path.lexists(ARP_DISABLED)
                or os.path.lexists(ARP_DISPATCHER)
                or os.path.lexists(ARP_PREUP)
                or os.path.lexists(ARP_NOWAIT)):
            return invalid
        return {}
    except OSError as exc:
        print(f'Cannot inspect ARP hardening state: {exc}', file=sys.stderr)
        return invalid
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
            or metadata.st_gid != 0 or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o644):
        return invalid
    try:
        with open(ARP_STATE, 'r', encoding='ascii') as stream:
            for line in stream:
                line = line.rstrip('\n')
                if not line or '=' not in line:
                    return invalid
                key, val = line.split('=', 1)
                if key not in expected or key in state or not val:
                    return invalid
                state[key] = val
    except (OSError, UnicodeError) as exc:
        print(f'Cannot read ARP hardening state: {exc}', file=sys.stderr)
        return invalid
    if set(state) != expected or state['ENABLED'] not in ('0', '1'):
        return invalid
    if not re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}', state['WAN_IFACE']):
        return invalid
    try:
        if str(ipaddress.IPv4Address(state['GATEWAY_IP'])) != state['GATEWAY_IP']:
            return invalid
    except ipaddress.AddressValueError:
        return invalid
    if not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',
                        state['GATEWAY_MAC']):
        return invalid
    if not re.fullmatch(
            r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z',
            state['LEARNED_AT']):
        return invalid
    try:
        if state['ENABLED'] == '1':
            if os.path.lexists(ARP_DISABLED):
                return invalid
            dispatcher = os.lstat(ARP_DISPATCHER)
            preup = os.lstat(ARP_PREUP)
            nowait = os.lstat(ARP_NOWAIT)
            if (not stat.S_ISLNK(dispatcher.st_mode)
                    or os.readlink(ARP_DISPATCHER)
                    != 'no-wait.d/90-arp-hardening'
                    or not stat.S_ISREG(preup.st_mode)
                    or preup.st_uid != 0 or preup.st_gid != 0
                    or preup.st_nlink != 1
                    or stat.S_IMODE(preup.st_mode) != 0o700
                    or not stat.S_ISREG(nowait.st_mode)
                    or nowait.st_uid != 0 or nowait.st_gid != 0
                    or nowait.st_nlink != 1
                    or stat.S_IMODE(nowait.st_mode) != 0o700):
                return invalid
        else:
            marker = os.lstat(ARP_DISABLED)
            if (not stat.S_ISREG(marker.st_mode) or marker.st_uid != 0
                    or marker.st_gid != 0 or marker.st_nlink != 1
                    or stat.S_IMODE(marker.st_mode) != 0o600
                    or marker.st_size != 0
                    or os.path.lexists(ARP_DISPATCHER)
                    or os.path.lexists(ARP_PREUP)
                    or os.path.lexists(ARP_NOWAIT)):
                return invalid
    except OSError:
        return invalid
    return state


def _current_gateway_mac(gw_ip, iface):
    """Exact kernel pin from `ip neigh` (non-privileged), or ''.

    This proves installed kernel/state parity; it is not an independent live
    observation of the router behind a permanent neighbour entry."""
    if not gw_ip or not iface:
        return ''
    out = _run_cmd([IP_CLI, '-4', 'neigh', 'show', 'to', gw_ip,
                    'dev', iface])
    matches = []
    for line in out.split('\n'):
        parts = line.split()
        if 'lladdr' in parts and parts[-1].lower() == 'permanent':
            idx = parts.index('lladdr')
            if idx + 1 < len(parts):
                matches.append(parts[idx + 1].lower())
    return matches[0] if len(matches) == 1 else ''


LAN_DURATION_PRESETS = (
    (None, 'Permanent'),
    (15, '15 minutes'),
    (60, '60 minutes'),
    (240, '4 hours'),
)


def _lan_duration_options(kind, duration):
    """Return lossless GUI minute choices and the selected index."""
    choices = list(LAN_DURATION_PRESETS)
    if kind == 'permanent':
        if duration != 0:
            raise ValueError('permanent LAN exception has nonzero duration')
        return choices, 0
    if (kind != 'temporary' or duration < 60 or duration > 86400
            or duration % 60 != 0):
        raise ValueError('temporary LAN duration is outside the CLI contract')
    minutes = duration // 60
    for index, (value, _label) in enumerate(choices):
        if value == minutes:
            return choices, index
    choices.append((minutes, f'{minutes} minutes (existing)'))
    return choices, len(choices) - 1


# --- Window ------------------------------------------------------------------

class NetworkWindow(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app,
                         default_width=noid_ui.DEFAULT_WIDTH,
                         default_height=noid_ui.DEFAULT_HEIGHT)
        self.set_title('NoID Privacy Network')

        toolbar = Adw.ToolbarView()
        self.set_content(toolbar)

        # ToastOverlay wraps the stack (for in-app notifications)
        self.toast_overlay = Adw.ToastOverlay()

        # 4-page ViewStack
        self.stack = Adw.ViewStack()
        self.toast_overlay.set_child(self.stack)
        toolbar.set_content(self.toast_overlay)

        # Row tracking for dynamic groups
        self._wan_endpoint_rows = []
        self._lan_exception_rows = []
        self._lan_revert_buttons = []
        self._lan_edit_buttons = []
        self._action_busy = False

        self._build_wan_page()
        self._build_lan_page()
        self._build_dns_page()
        self._build_status_page()

        # Keep the same persistent identity header as Setup, Update and Tools.
        # Wide section navigation gets its own row below that header; the
        # shared breakpoint moves it to the bottom on narrow windows.
        header, section_bar, switcher_bar = noid_ui.sectioned_app_bars(
            self, 'NoID Privacy Network', 'Privacy controls and local state',
            'noid-privacy-network', self.stack)
        toolbar.add_top_bar(header)
        toolbar.add_top_bar(section_bar)
        toolbar.add_bottom_bar(switcher_bar)
        self.stack.connect('notify::visible-child-name', self._on_page_changed)
        self.connect('close-request', self._on_close_request)
        self._sync_control_sensitivity()

    def _toast(self, msg, timeout=3):
        noid_ui.toast(self.toast_overlay, msg, timeout)

    def _action_row(self, emoji, title, subtitle, callback):
        return noid_ui.action_row(emoji, title, subtitle, callback)

    def _refresh_button(self, callback, label='Refresh this section'):
        return noid_ui.icon_button(
            'view-refresh-symbolic', label, lambda _button: callback())

    def _open_audit(self, mode):
        if mode not in {'wan', 'firewall', 'nft', 'mtu'}:
            self._toast('Unknown network audit mode.', 5)
            return
        command = [
            '/usr/bin/env', 'NOID_NETWORK_GUI=1',
            NETWORK_AUDIT_CLI, mode,
        ]
        if not _spawn_terminal(command):
            self._toast('Could not open a terminal. Use Ptyxis and run the command manually.', 5)

    def _start_privileged(self, argv):
        if self._action_busy:
            self._toast('Another privileged network action is still running.')
            return False, None
        self._action_busy = True
        self._sync_control_sensitivity()
        return True, _privileged_async(argv)

    def _sync_wan_controls(self):
        mode = _wan_runtime_mode()
        title, detail = _wan_mode_text(mode)
        actual = _wan_feature_enabled(mode)
        if self.wan_switch.get_active() != actual:
            self.wan_switch.handler_block_by_func(self._on_wan_toggle)
            self.wan_switch.set_active(actual)
            self.wan_switch.handler_unblock_by_func(self._on_wan_toggle)
        self.wan_switch.set_subtitle(f'{title}. {detail}')
        valid = mode not in {'ERROR', 'UNKNOWN'}
        policy_loaded = mode not in {'ERROR', 'UNKNOWN', 'DISABLED'}
        self.wan_switch.set_sensitive(valid and not self._action_busy)
        for row in getattr(self, 'wan_pause_rows', []):
            row.set_sensitive(mode in {'STRICT', 'STRICT_EMPTY'}
                              and not self._action_busy)
        if hasattr(self, 'wan_resume_row'):
            self.wan_resume_row.set_sensitive(
                mode == 'GRACE_PAUSED' and not self._action_busy)
        if hasattr(self, 'wan_reset_row'):
            self.wan_reset_row.set_sensitive(
                policy_loaded and not self._action_busy)
        if hasattr(self, 'wan_arm_empty_row'):
            self.wan_arm_empty_row.set_sensitive(
                policy_loaded and mode != 'STRICT_EMPTY'
                and not self._action_busy)

    def _sync_lan_controls(self):
        state = self._lan_global_state()
        actual = state == 'ALLOWED'
        if self.lan_global_switch.get_active() != actual:
            self.lan_global_switch.handler_block_by_func(
                self._on_lan_global_toggle)
            self.lan_global_switch.set_active(actual)
            self.lan_global_switch.handler_unblock_by_func(
                self._on_lan_global_toggle)
        self.lan_global_switch.set_subtitle(
            'ERROR — enforcement state is unverifiable; control disabled'
            if state == 'INCONSISTENT'
            else ('On — all locally classified destinations are reachable'
                  if actual
                  else 'Off (default) — only per-IP exceptions are reachable'))
        self.lan_global_switch.set_sensitive(
            state != 'INCONSISTENT' and not self._action_busy)
        for widget in (getattr(self, 'lan_ip_entry', None),
                       getattr(self, 'lan_direction', None),
                       getattr(self, 'lan_protocol', None),
                       getattr(self, 'lan_ports_entry', None),
                       getattr(self, 'lan_duration', None),
                       getattr(self, 'lan_add_button', None)):
            if widget is not None:
                widget.set_sensitive(not self._action_busy)
        relearn = getattr(self, 'status_arp_relearn_row', None)
        if relearn is not None:
            arp_state = _arp_state()
            arp_known = arp_state.get('ENABLED') in ('0', '1')
            relearn.set_sensitive(arp_known and not self._action_busy)
            if arp_state.get('ERROR'):
                relearn.set_subtitle(
                    'Unavailable — M04 gateway state is inconsistent')
            elif arp_state.get('ENABLED') == '0':
                relearn.set_subtitle(
                    'Re-detect the gateway and re-enable its permanent kernel pin')
            elif arp_known:
                relearn.set_subtitle(
                    'Re-detect + pin the current gateway MAC (fixes "no internet" '
                    'after a router/hardware swap)')
            else:
                relearn.set_subtitle(
                    'Unavailable — initial gateway learning has not completed')
        for button in self._lan_revert_buttons:
            button.set_sensitive(not self._action_busy)
        for button in self._lan_edit_buttons:
            button.set_sensitive(not self._action_busy)
        self._sync_lan_selector_visibility()

    def _sync_lan_selector_visibility(self):
        if not hasattr(self, 'lan_direction'):
            return
        inbound_capable = self.lan_direction.get_selected() in (1, 2)
        self.lan_protocol.set_visible(inbound_capable)
        self.lan_ports_entry.set_visible(inbound_capable)
        self.lan_protocol.set_sensitive(inbound_capable and not self._action_busy)
        self.lan_ports_entry.set_sensitive(inbound_capable and not self._action_busy)

    def _on_lan_direction_changed(self, _row, _pspec):
        self._sync_lan_selector_visibility()

    def _sync_control_sensitivity(self):
        if hasattr(self, 'wan_switch'):
            self._sync_wan_controls()
        if hasattr(self, 'lan_global_switch'):
            self._sync_lan_controls()
        if hasattr(self, 'dns_mode'):
            self._sync_dns_controls()

    def _on_page_changed(self, _stack, _pspec):
        page = self.stack.get_visible_child_name()
        if page == 'wan':
            self._refresh_wan_endpoints()
        elif page == 'lan':
            self._refresh_lan_page()
        elif page == 'dns':
            self._refresh_dns_page()
        elif page == 'status':
            self._refresh_status()

    def _on_close_request(self, _window):
        if not self._action_busy:
            return False
        dialog = Adw.AlertDialog.new(
            'Network action still running',
            'Keep this window open until the privileged action finishes. '
            'Its controls will unlock automatically when the verified backend '
            'state is available.')
        dialog.add_response('keep-open', 'Keep window open')
        dialog.set_default_response('keep-open')
        dialog.set_close_response('keep-open')
        dialog.present(self)
        return True

    # ========================================================================
    # WAN Privacy Page
    # ========================================================================

    def _build_wan_page(self):
        page = Adw.PreferencesPage()

        # --- Group 1: Strict mode toggle ---
        grp_strict = Adw.PreferencesGroup()
        grp_strict.set_title('WAN-egress-strict')
        grp_strict.set_description(
            'Pin exact VPN server IP + transport + port tuples and block '
            'other physical-WAN traffic. Closes the SO_BINDTODEVICE bypass '
            'and enforces '
            'tunnel-only egress for supported NetworkManager WireGuard and '
            'OpenVPN profile schemas; unknown schemas fail closed.')

        self.wan_switch = Adw.SwitchRow()
        self.wan_switch.set_title('WAN physical-egress policy enabled')
        noid_ui.add_emoji_prefix(self.wan_switch, '🔒')
        initial_mode = _wan_runtime_mode()
        initial_title, initial_detail = _wan_mode_text(initial_mode)
        self.wan_switch.set_active(_wan_feature_enabled(initial_mode))
        self.wan_switch.set_subtitle(f'{initial_title}. {initial_detail}')
        self.wan_switch.set_sensitive(initial_mode not in {'ERROR', 'UNKNOWN'})
        self.wan_switch.connect('notify::active', self._on_wan_toggle)
        grp_strict.add(self.wan_switch)
        page.add(grp_strict)

        # --- Group 2: Temporary pause ---
        grp_pause = Adw.PreferencesGroup()
        grp_pause.set_title('Temporary Pause')
        grp_pause.set_description(
            'Pause strict mode for captive-portal logins or troubleshooting. '
            'Auto-resumes via systemd-run timer.')

        pause_5 = self._action_row(
            '⏸', 'Pause 5 minutes',
            'Bypass strict mode temporarily — auto-resume after 5 min',
            lambda r: self._wan_pause(5))
        pause_30 = self._action_row(
            '⏸', 'Pause 30 minutes',
            'Bypass strict mode temporarily — auto-resume after 30 min',
            lambda r: self._wan_pause(30))
        self.wan_resume_row = self._action_row(
            '▶', 'Resume now',
            'End any active pause + return to strict mode',
            lambda r: self._wan_resume())
        self.wan_pause_rows = [pause_5, pause_30]
        for pause_row in self.wan_pause_rows:
            grp_pause.add(pause_row)
        grp_pause.add(self.wan_resume_row)
        page.add(grp_pause)

        # --- Group 3: Pinned endpoints ---
        self.wan_endpoints_group = Adw.PreferencesGroup()
        self.wan_endpoints_group.set_title('Pinned VPN Endpoint Tuples')
        self.wan_endpoints_group.set_description(
            'Durable literal/runtime-confirmed records; transient DNS candidates are not shown.')
        self.wan_endpoints_group.set_header_suffix(
            self._refresh_button(
                self._refresh_wan_endpoints, 'Refresh pinned VPN endpoints'))
        page.add(self.wan_endpoints_group)

        # Initial load (state-file mode 0644)
        self._refresh_wan_endpoints()

        # --- Group 4: Explicit bootstrap/strict-empty decisions ---
        grp_reset = Adw.PreferencesGroup()
        grp_reset.set_title('No-VPN Posture')
        # Name the outcome, not the internal state. The earlier title read as
        # a hardening switch, while the actual effect is that this machine has
        # no ordinary network access until a VPN comes up; STRICT_EMPTY stays
        # in the subtitle because `noid-wan-strict status` prints that word.
        self.wan_arm_empty_row = self._action_row(
            '⛔', 'Block internet until a VPN connects',
            'No ordinary network access from this machine — enters STRICT_EMPTY',
            lambda r: self._wan_arm_empty_confirm())
        grp_reset.add(self.wan_arm_empty_row)
        self.wan_reset_row = self._action_row(
            '🔄', 'Restore onboarding/bootstrap mode',
            'Clear endpoint state + armed marker — direct physical WAN becomes available',
            lambda r: self._wan_reset_confirm())
        grp_reset.add(self.wan_reset_row)
        page.add(grp_reset)

        self.stack.add_titled_with_icon(
            page, 'wan', 'WAN Privacy', 'network-vpn-symbolic')

    def _on_wan_toggle(self, switch, _pspec):
        """Switch active means the published M06 policy is loaded."""
        mode = 'on' if switch.get_active() else 'off'
        if mode == 'off':
            # Off needs strong confirm (removes critical privacy protection)
            self._wan_off_confirm(switch)
        else:
            started, proc = self._start_privileged([WAN_TOGGLE_CLI, 'on'])
            if started:
                GLib.timeout_add(
                    500, self._resync_wan_switch, proc, [0])
            else:
                self._sync_wan_controls()

    def _wan_off_confirm(self, switch):
        dialog = Adw.AlertDialog.new(
            'Disable WAN-egress-strict?',
            'This removes critical privacy protection. Direct physical-WAN traffic + '
            'SO_BINDTODEVICE bypass become possible. Continue?')
        dialog.add_response('cancel', 'Cancel')
        dialog.add_response('disable', 'Disable')
        dialog.set_response_appearance('disable',
                                       Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response('cancel')
        dialog.set_close_response('cancel')

        def on_response(_d, response):
            if response == 'disable':
                # Dialog is the confirmation boundary. --yes lets the
                # pinned CLI run directly, preserving M08 polkit scope.
                started, proc = self._start_privileged(
                    [WAN_TOGGLE_CLI, 'off', '--yes'])
                if started:
                    GLib.timeout_add(
                        500, self._resync_wan_switch, proc, [0])
                else:
                    self._sync_wan_controls()
            else:
                self._sync_wan_controls()

        dialog.connect('response', on_response)
        dialog.present(self)

    def _resync_wan_switch(self, proc, attempts):
        state, rc = _finish_privileged_action(proc, attempts)
        if state == 'pending':
            return True
        if state == 'orphaned':
            self._toast(_privileged_failure_text(state, rc))
            return True
        self._action_busy = False
        runtime_mode = _wan_runtime_mode()
        mode_title = _wan_mode_text(runtime_mode)[0]
        self._refresh_wan_endpoints()
        # Only toast on real state-change. Installed pkexec cancel = rc 126.
        if state == 'success':
            self._toast(f'WAN-egress-strict: {mode_title}')
        else:
            self._toast(_privileged_failure_text(state, rc, _privileged_stderr_tail(proc)))
        self._sync_control_sensitivity()
        return False

    def _wan_pause(self, minutes):
        started, proc = self._start_privileged(
            [WAN_STRICT_CLI, 'pause', str(minutes)])
        if started:
            GLib.timeout_add(500, self._wait_then_refresh_wan, proc,
                             f'Strict mode paused {minutes} min', [0])

    def _wan_resume(self):
        started, proc = self._start_privileged([WAN_STRICT_CLI, 'resume'])
        if started:
            GLib.timeout_add(500, self._wait_then_refresh_wan, proc,
                             'Strict mode resumed', [0])

    def _wait_then_refresh_wan(self, proc, msg, attempts):
        """Poll privileged action, then refresh endpoints + toast only on rc=0."""
        state, rc = _finish_privileged_action(proc, attempts)
        if state == 'pending':
            return True
        if state == 'orphaned':
            self._toast(_privileged_failure_text(state, rc))
            return True
        self._action_busy = False
        self._refresh_wan_endpoints()
        if state == 'success' and msg:
            self._toast(msg)
        elif state != 'success':
            self._toast(_privileged_failure_text(state, rc, _privileged_stderr_tail(proc)))
        self._sync_control_sensitivity()
        return False

    def _wan_reset_confirm(self):
        dialog = Adw.AlertDialog.new(
            'Restore onboarding/bootstrap mode?',
            'Clear all durable/candidate endpoint state and the armed marker. '
            'This deliberately restores direct-WAN bootstrap grace.')
        dialog.add_response('cancel', 'Cancel')
        dialog.add_response('reset', 'Reset')
        dialog.set_response_appearance('reset',
                                       Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response('cancel')
        dialog.set_close_response('cancel')

        def on_response(_d, response):
            if response == 'reset':
                started, proc = self._start_privileged(
                    [WAN_STRICT_CLI, 'reset', '--yes'])
                if started:
                    GLib.timeout_add(500, self._wait_then_refresh_wan, proc,
                                     'Bootstrap grace restored', [0])

        dialog.connect('response', on_response)
        dialog.present(self)

    def _wan_arm_empty_confirm(self):
        dialog = Adw.AlertDialog.new(
            'Block internet until a VPN connects?',
            'Enter STRICT_EMPTY with no VPN endpoint. Application and '
            'forwarded physical WAN stay blocked; only the documented '
            'systemd-resolved bootstrap exception remains until a supported '
            'VPN connects or you restore onboarding/bootstrap mode.')
        dialog.add_response('cancel', 'Cancel')
        dialog.add_response('block', 'Block WAN')
        dialog.set_response_appearance(
            'block', Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response('cancel')
        dialog.set_close_response('cancel')

        def on_response(_d, response):
            if response == 'block':
                started, proc = self._start_privileged(
                    [WAN_STRICT_CLI, 'arm-empty', '--yes'])
                if started:
                    GLib.timeout_add(
                        500, self._wait_then_refresh_wan, proc,
                        'STRICT_EMPTY active — ordinary physical WAN blocked',
                        [0])

        dialog.connect('response', on_response)
        dialog.present(self)

    def _refresh_wan_endpoints(self):
        # Remove existing rows
        for row in self._wan_endpoint_rows:
            self.wan_endpoints_group.remove(row)
        self._wan_endpoint_rows = []

        # The backend load is all-or-nothing: one bad line fails the whole
        # bootstrap and no tuple is enforced. Never render otherwise-valid
        # lines as pinned when the file is rejected.
        endpoints, read_error = _wan_endpoint_records()

        if read_error:
            row = Adw.ActionRow()
            row.set_title('Endpoint state error')
            row.set_subtitle(read_error)
            noid_ui.accessible_row(row)
            self._wan_endpoint_rows.append(row)
            self.wan_endpoints_group.add(row)

        if not endpoints and read_error is None:
            row = Adw.ActionRow()
            row.set_title('(no endpoints pinned)')
            row.set_subtitle(
                'No durable endpoint record. Runtime status distinguishes '
                'never-armed grace from fail-closed STRICT_EMPTY.')
            noid_ui.accessible_row(row)
            self._wan_endpoint_rows.append(row)
            self.wan_endpoints_group.add(row)
        else:
            for proto, ip, port, family, details \
                    in _group_wan_endpoint_records(endpoints):
                emoji = '🌐' if family == 'ipv4' else '🌍'
                row = Adw.ActionRow()
                endpoint_label = f'{ip}:{port}' if family == 'ipv4' else f'[{ip}]:{port}'
                row.set_title(f'{proto.upper()} {endpoint_label}')
                sources = sorted({item[0] for item in details})
                profiles = sorted({item[1] for item in details})
                expiries = sorted({item[3] for item in details})
                if len(details) == 1:
                    row.set_subtitle(
                        f'Exact {family} tuple; source={sources[0]}; '
                        f'profile={profiles[0][:8]}; expiry={expiries[0]}')
                else:
                    row.set_subtitle(
                        f'Exact {family} tuple; records={len(details)}; '
                        f'sources={",".join(sources)}; '
                        f'profiles={len(profiles)}; '
                        f'expiries={",".join(str(value) for value in expiries)}')
                noid_ui.add_emoji_prefix(row, emoji)
                self._wan_endpoint_rows.append(row)
                self.wan_endpoints_group.add(row)

        self._sync_wan_controls()

    # ========================================================================
    # LAN Exceptions Page
    # ========================================================================

    def _set_lan_duration_options(self, kind='permanent', duration=0):
        choices, selected = _lan_duration_options(kind, duration)
        self._lan_duration_minutes = [minutes for minutes, _label in choices]
        self.lan_duration.set_model(
            Gtk.StringList.new([label for _minutes, label in choices]))
        self.lan_duration.set_selected(selected)

    def _build_lan_page(self):
        page = Adw.PreferencesPage()

        # --- Group 1: Add exception form ---
        grp_add = Adw.PreferencesGroup()
        grp_add.set_title('Add LAN Exception')
        grp_add.set_description(
            'Authorize one directly attached IPv4 peer as outbound only, '
            'inbound only, or both directions. Inbound-capable rules require '
            'one explicit TCP/UDP destination port or range. '
            'Service discovery (mDNS/SMB/WSD) stays off — connect by IP only. '
            'New IPv6 grants remain unavailable until the XDP/NDP peer '
            'contract exists.')

        self.lan_ip_entry = Adw.EntryRow()
        self.lan_ip_entry.set_title('IPv4 address (e.g. 192.168.1.50)')
        noid_ui.accessible_row(
            self.lan_ip_entry,
            'Enter the one directly attached IPv4 peer to allow')
        grp_add.add(self.lan_ip_entry)

        self.lan_direction = Adw.ComboRow()
        self.lan_direction.set_title('Direction')
        self.lan_direction.set_subtitle(
            'Outbound replies are admitted only for a guest-observed flow')
        self.lan_direction.set_model(Gtk.StringList.new(
            ['Outbound only', 'Inbound only', 'Both directions']))
        self.lan_direction.set_selected(0)
        self.lan_direction.connect(
            'notify::selected', self._on_lan_direction_changed)
        noid_ui.accessible_row(self.lan_direction)
        grp_add.add(self.lan_direction)

        self.lan_protocol = Adw.ComboRow()
        self.lan_protocol.set_title('Inbound protocol')
        self.lan_protocol.set_model(Gtk.StringList.new(['TCP', 'UDP']))
        self.lan_protocol.set_selected(0)
        noid_ui.accessible_row(self.lan_protocol)
        grp_add.add(self.lan_protocol)

        self.lan_ports_entry = Adw.EntryRow()
        self.lan_ports_entry.set_title(
            'Inbound destination port or range (e.g. 443 or 5000-5010)')
        noid_ui.accessible_row(
            self.lan_ports_entry,
            'Enter one TCP or UDP destination port or continuous port range')
        grp_add.add(self.lan_ports_entry)

        self.lan_duration = Adw.ComboRow()
        self.lan_duration.set_title('Duration')
        self.lan_duration.set_subtitle(
            'Temporary exceptions use a reboot-safe fail-closed deadline')
        self._set_lan_duration_options()
        noid_ui.accessible_row(self.lan_duration)
        grp_add.add(self.lan_duration)

        add_row = Adw.ActionRow()
        add_row.set_title('Add Exception')
        add_row.set_subtitle(
            'Inserts a priority="-100" accept rich-rule into block-lan-out')
        self.lan_add_button = Gtk.Button(label='Add')
        self.lan_add_button.add_css_class('suggested-action')
        self.lan_add_button.set_valign(Gtk.Align.CENTER)
        noid_ui.accessible(
            self.lan_add_button, 'Add LAN exception',
            'Add the entered IPv4 peer with the selected duration')
        self.lan_add_button.connect('clicked', lambda b: self._lan_add())
        add_row.add_suffix(self.lan_add_button)
        add_row.set_activatable_widget(self.lan_add_button)
        noid_ui.accessible_row(add_row)
        grp_add.add(add_row)

        self._sync_lan_selector_visibility()

        page.add(grp_add)

        # --- Group 2: Active exceptions ---
        self.lan_active_group = Adw.PreferencesGroup()
        self.lan_active_group.set_title('Active Exceptions')
        self.lan_active_group.set_description(
            'Currently allowed IPs. Click delete to revert immediately.')
        self.lan_active_group.set_header_suffix(
            self._refresh_button(
                self._refresh_lan_page, 'Refresh LAN state and exceptions'))
        page.add(self.lan_active_group)

        # --- Group 3: Global toggle (legacy) ---
        grp_global = Adw.PreferencesGroup()
        grp_global.set_title('Global Override (emergency)')
        grp_global.set_description(
            'Emergency escape hatch: disable host LAN destination blocking '
            'entirely — allows directly connected and statically classified '
            'local destinations. Turning it back Off restores the exact '
            'hardened boundary (re-derived from the live interfaces, verified, '
            'fail-closed). Per-IP exceptions above are preferred for normal use.')

        self.lan_global_switch = Adw.SwitchRow()
        self.lan_global_switch.set_title('Allow all local destinations')
        self.lan_global_switch.set_subtitle(
            'Off (default) = only per-IP exceptions are reachable')
        noid_ui.add_emoji_prefix(self.lan_global_switch, '🔓')
        initial_lan_state = self._lan_global_state()
        self.lan_global_switch.set_active(initial_lan_state == 'ALLOWED')
        if initial_lan_state == 'INCONSISTENT':
            self.lan_global_switch.set_sensitive(False)
            self.lan_global_switch.set_subtitle(
                'ERROR — enforcement state is unverifiable; control disabled')
        self.lan_global_switch.connect('notify::active',
                                       self._on_lan_global_toggle)
        grp_global.add(self.lan_global_switch)

        page.add(grp_global)

        self.stack.add_titled_with_icon(
            page, 'lan', 'LAN Exceptions', 'network-server-symbolic')
        self._refresh_lan_page()

    def _lan_add(self):
        ip_text = self.lan_ip_entry.get_text().strip()
        family, ip_norm = _validate_ip(ip_text)
        if family is None:
            self._toast(f'Invalid IP address: {ip_text}', timeout=4)
            return
        if family != 'ipv4':
            self._toast(
                'IPv6 LAN exceptions are not supported by the current XDP/NDP boundary.',
                timeout=5)
            return

        duration_idx = self.lan_duration.get_selected()
        if duration_idx >= len(self._lan_duration_minutes):
            self._toast('Invalid duration selection', timeout=4)
            return
        minutes = self._lan_duration_minutes[duration_idx]

        direction = {0: 'outbound', 1: 'inbound', 2: 'both'}.get(
            self.lan_direction.get_selected())
        if direction is None:
            self._toast('Invalid direction selection', timeout=4)
            return
        argv = [LAN_ALLOW_CLI, '--add', ip_norm, '--direction', direction]
        selector_text = 'correlated replies only'
        if direction in ('inbound', 'both'):
            protocol = {0: 'tcp', 1: 'udp'}.get(
                self.lan_protocol.get_selected())
            ports = self.lan_ports_entry.get_text().strip()
            match = re.fullmatch(r'([1-9][0-9]{0,4})(?:-([1-9][0-9]{0,4}))?',
                                 ports)
            if protocol is None or match is None:
                self._toast(
                    'Inbound rules require TCP or UDP and a port/range from 1 to 65535.',
                    timeout=5)
                return
            port_start = int(match.group(1), 10)
            port_end = int(match.group(2) or match.group(1), 10)
            if port_start > port_end or port_end > 65535:
                self._toast('Invalid port range: require 1 <= start <= end <= 65535',
                            timeout=5)
                return
            argv.extend(['--protocol', protocol, '--ports', ports])
            selector_text = f'{protocol.upper()} {ports}'
        if minutes is not None:
            argv.extend(['--temp', str(minutes)])
        lifetime = 'permanent' if minutes is None else f'{minutes} min'
        msg = f'Committed {direction} exception: {ip_norm} ({selector_text}, {lifetime})'

        started, proc = self._start_privileged(argv)
        if not started:
            return
        # clear_input=True → input clears only after the privileged action succeeds.
        # Preserves IP-text on cancel/auth-fail so user can retry without re-typing.
        GLib.timeout_add(500, self._wait_then_refresh_lan, proc, msg, [0], True)

    def _wait_then_refresh_lan(self, proc, msg, attempts, clear_input=False):
        state, rc = _finish_privileged_action(proc, attempts)
        if state == 'pending':
            return True
        if state == 'orphaned':
            self._toast(_privileged_failure_text(state, rc))
            return True
        self._action_busy = False
        self._refresh_lan_page()
        # Show success only for rc=0. Installed pkexec cancel = rc 126.
        if state == 'success':
            if msg:
                self._toast(msg)
            if clear_input:
                # Caller asked to clear the LAN-IP entry on success
                self.lan_ip_entry.set_text('')
        else:
            self._toast(_privileged_failure_text(state, rc, _privileged_stderr_tail(proc)))
        self._sync_control_sensitivity()
        return False

    def _refresh_lan_page(self):
        """Refresh both independently sourced LAN views as one UI event."""
        self._refresh_lan_exceptions()
        self._sync_lan_controls()

    def _refresh_lan_exceptions(self):
        # Remove existing rows
        for row in self._lan_exception_rows:
            self.lan_active_group.remove(row)
        self._lan_exception_rows = []
        self._lan_revert_buttons = []
        self._lan_edit_buttons = []

        rc, output = _run_cmd_checked(
            [LAN_ALLOW_CLI, '--list-machine'], timeout=4)
        if rc != 0:
            row = Adw.ActionRow()
            row.set_title('Exception state unavailable')
            row.set_subtitle(
                'The backend list command failed; no empty-state claim is made')
            noid_ui.add_emoji_prefix(row, '⚠️')
            self._lan_exception_rows.append(row)
            self.lan_active_group.add(row)
            return
        exceptions = []
        malformed = False
        lines = output.splitlines()
        if not lines or lines[0] != 'NOID-LAN-EXCEPTIONS-V2':
            malformed = True
            lines = []
        for line in lines[1:]:
            parts = line.split('\t')
            if len(parts) != 8 or any(not part for part in parts):
                malformed = True
                continue
            ip, direction, protocol, start_s, end_s, kind, duration_s, expires_s = parts
            family, canonical = _validate_ip(ip)
            try:
                start = int(start_s, 10)
                end = int(end_s, 10)
                duration = int(duration_s, 10)
                expires = int(expires_s, 10)
            except ValueError:
                malformed = True
                continue
            selector_ok = (
                direction == 'outbound' and protocol == 'none'
                and start == 0 and end == 0)
            selector_ok = selector_ok or (
                direction in ('inbound', 'both')
                and protocol in ('tcp', 'udp')
                and 1 <= start <= end <= 65535)
            lifetime_ok = (
                kind == 'permanent' and duration == 0 and expires == 0)
            lifetime_ok = lifetime_ok or (
                kind == 'temporary' and 60 <= duration <= 86400
                and duration % 60 == 0 and expires > 0)
            if (family != 'ipv4' or canonical != ip
                    or not selector_ok or not lifetime_ok):
                malformed = True
                continue
            exceptions.append((ip, direction, protocol, start, end,
                               kind, duration, expires))

        if malformed:
            # The backend contract is all-or-nothing. A malformed stdout row
            # indicates protocol drift or corruption, so no otherwise-valid
            # record may be presented as an enforceable exception.
            exceptions = []
            row = Adw.ActionRow()
            row.set_title('Invalid backend exception record')
            row.set_subtitle(
                'The closed list schema failed; no entries were rendered. '
                'Inspect noid-lan-allow --list')
            noid_ui.add_emoji_prefix(row, '⚠️')
            self._lan_exception_rows.append(row)
            self.lan_active_group.add(row)

        if not exceptions and not malformed:
            row = Adw.ActionRow()
            row.set_title('(no exceptions)')
            row.set_subtitle('Add an IP above to allow specific LAN traffic')
            noid_ui.accessible_row(row)
            self._lan_exception_rows.append(row)
            self.lan_active_group.add(row)
        else:
            for (ip, direction, protocol, start, end,
                 kind, duration, expires) in exceptions:
                row = Adw.ActionRow()
                row.set_title(ip)
                selector = ('correlated replies only' if direction == 'outbound'
                            else f'{protocol.upper()} ports {start}-{end}')
                lifetime = ('permanent' if kind == 'permanent'
                            else f'temporary, deadline epoch {expires}')
                row.set_subtitle(
                    f'{direction}; {selector}; {lifetime}')
                noid_ui.add_emoji_prefix(row, '🌐')
                edit_btn = noid_ui.icon_button(
                    'document-edit-symbolic', f'Edit exception for {ip}',
                    lambda _button, values=(ip, direction, protocol, start, end,
                                             kind, duration):
                        self._lan_load_for_edit(*values))
                row.add_suffix(edit_btn)
                revert_btn = noid_ui.icon_button(
                    'user-trash-symbolic', f'Revert exception for {ip}',
                    lambda _button, addr=ip: self._lan_revert(addr))
                row.add_suffix(revert_btn)
                self._lan_edit_buttons.append(edit_btn)
                self._lan_revert_buttons.append(revert_btn)
                self._lan_exception_rows.append(row)
                self.lan_active_group.add(row)

    def _lan_load_for_edit(self, ip, direction, protocol, start, end,
                           kind, duration):
        self.lan_ip_entry.set_text(ip)
        self.lan_direction.set_selected(
            {'outbound': 0, 'inbound': 1, 'both': 2}[direction])
        if protocol in ('tcp', 'udp'):
            self.lan_protocol.set_selected(0 if protocol == 'tcp' else 1)
            self.lan_ports_entry.set_text(
                str(start) if start == end else f'{start}-{end}')
        else:
            self.lan_ports_entry.set_text('')
        self._set_lan_duration_options(kind, duration)
        self._sync_lan_selector_visibility()
        self.lan_ip_entry.grab_focus()
        self._toast(
            'Exception loaded into the form. Add re-applies this peer as a '
            'narrowing-first, fail-closed replacement; on failure '
            'the old grant is withdrawn, not restored.')

    def _lan_revert(self, ip):
        started, proc = self._start_privileged(
            [LAN_ALLOW_CLI, '--revert', ip])
        if started:
            GLib.timeout_add(500, self._wait_then_refresh_lan, proc,
                             f'Reverted exception: {ip}', [0])

    def _lan_global_state(self):
        """Return the backend's cross-layer LAN state contract."""
        state = _run_cmd([LAN_ALLOW_CLI, '--global-state']).strip()
        return state if state in ('BLOCKED', 'ALLOWED') else 'INCONSISTENT'

    def _on_lan_global_toggle(self, switch, _pspec):
        """Switch active = ALLOWED globally (block-lan-out detached)."""
        if switch.get_active():
            # Switching ON allow-all — destructive, needs confirm
            dialog = Adw.AlertDialog.new(
                'Allow all local destinations?',
                'This disables the host LAN destination boundary. Directly '
                'connected peers (including unusual public-prefix LANs) and '
                'the policy’s statically classified local ranges become reachable. '
                'Turning this back Off restores the exact hardened boundary. '
                'Per-IP exceptions are usually safer. Continue?')
            dialog.add_response('cancel', 'Cancel')
            dialog.add_response('continue', 'Allow all local destinations')
            dialog.set_response_appearance(
                'continue', Adw.ResponseAppearance.DESTRUCTIVE)
            dialog.set_default_response('cancel')
            dialog.set_close_response('cancel')

            def on_response(_d, response):
                if response == 'continue':
                    started, proc = self._start_privileged(
                        [LAN_ALLOW_CLI, 'on', '--yes'])
                    if started:
                        GLib.timeout_add(500, self._resync_lan_global, switch,
                                         proc, [0])
                    else:
                        self._sync_lan_controls()
                else:
                    self._sync_lan_controls()

            dialog.connect('response', on_response)
            dialog.present(self)
        else:
            # Switching OFF allow-all = restoring default. No confirm needed.
            started, proc = self._start_privileged([LAN_ALLOW_CLI, 'off'])
            if started:
                GLib.timeout_add(
                    500, self._resync_lan_global, switch, proc, [0])
            else:
                self._sync_lan_controls()

    def _resync_lan_global(self, switch, proc, attempts):
        action_state, rc = _finish_privileged_action(proc, attempts)
        if action_state == 'pending':
            return True
        if action_state == 'orphaned':
            self._toast(_privileged_failure_text(action_state, rc))
            return True
        self._action_busy = False
        state = self._lan_global_state()
        actual = state == 'ALLOWED'
        if switch.get_active() != actual:
            switch.handler_block_by_func(self._on_lan_global_toggle)
            switch.set_active(actual)
            switch.handler_unblock_by_func(self._on_lan_global_toggle)
        # Only toast on real state-change. Installed pkexec cancel = rc 126.
        if state == 'INCONSISTENT':
            self._toast('ERROR — LAN enforcement layers are inconsistent')
        elif action_state == 'success':
            self._toast('All local-destination traffic ALLOWED' if actual
                        else 'LAN traffic BLOCKED (default hardened)')
        else:
            self._toast(_privileged_failure_text(action_state, rc, _privileged_stderr_tail(proc)))
        self._sync_control_sensitivity()
        return False

    # ========================================================================
    # DNS Privacy Page
    # ========================================================================

    def _build_dns_page(self):
        page = Adw.PreferencesPage()

        mode_group = Adw.PreferencesGroup()
        mode_group.set_title('DNS-over-TLS Policy')
        mode_group.set_description(
            'Controls NoID Privacy’s certificate-named global Quad9 resolver '
            'and managed physical Ethernet/Wi-Fi profiles together. VPN, '
            'tunnel, bridge and private per-link profiles are not rewritten; '
            'an unset transport independently inherits NoID Privacy’s generic '
            'best-effort opportunistic default, which can fall back to DNS/53.')

        self.dns_mode = Adw.ComboRow()
        self.dns_mode.set_title('Global + physical DNS transport')
        self.dns_mode.set_subtitle(
            'Strict is the image default; opportunistic is the explicit VPN '
            'or captive-portal compatibility mode')
        self.dns_mode.set_model(Gtk.StringList.new([
            'Strict (default) — authenticated, fail closed',
            'Opportunistic — pre-VPN / captive portal',
            'Off — plaintext DNS',
        ]))
        self.dns_mode.set_selected(0)
        noid_ui.add_emoji_prefix(self.dns_mode, '🌐')
        noid_ui.accessible_row(self.dns_mode)
        self.dns_mode.connect(
            'notify::selected', self._on_dns_mode_changed)
        mode_group.add(self.dns_mode)
        page.add(mode_group)

        state_group = Adw.PreferencesGroup()
        state_group.set_title('Effective DNS State')
        state_group.set_description(
            'Selection, merged systemd-resolved configuration and live '
            'routing scope are checked independently; a VPN override is never '
            'misreported as global strict transport.')
        state_group.set_header_suffix(
            self._refresh_button(
                self._refresh_dns_page, 'Refresh DNS privacy state'))
        self.dns_selection_row = noid_ui.status_row('⚙️')
        self.dns_runtime_row = noid_ui.status_row('🔐')
        self.dns_physical_row = noid_ui.status_row('📡')
        self.dns_scope_row = noid_ui.status_row('🧭')
        state_group.add(self.dns_selection_row)
        state_group.add(self.dns_runtime_row)
        state_group.add(self.dns_physical_row)
        state_group.add(self.dns_scope_row)
        page.add(state_group)

        reset_group = Adw.PreferencesGroup()
        reset_group.set_title('Recovery')
        reset_group.set_description(
            'Remove only the selector-owned override and return to the '
            'NoID Privacy image policy. Custom provider files stay untouched.')
        self.dns_reset_row = self._action_row(
            '↩️', 'Reset to image DNS transport',
            'Remove the selector override and restore strict global + physical DoT',
            lambda _row: self._apply_dns_mode('reset'))
        reset_group.add(self.dns_reset_row)
        page.add(reset_group)

        self.stack.add_titled_with_icon(
            page, 'dns', 'DNS Privacy', 'network-transmit-receive-symbolic')
        self._refresh_dns_page()

    def _sync_dns_controls(self, state=None):
        state = _dns_mode_state() if state is None else state
        valid = (
            state is not None
            and state['selection'] != 'invalid'
            and state['configured'] in {'no', 'opportunistic', 'yes'}
            and state['runtime_global'] in {'no', 'opportunistic', 'yes'}
            and state['physical_configured'] in {
                'none', 'default', 'no', 'opportunistic', 'yes', 'mixed'}
            and state['physical_runtime'] in {
                'none', 'no', 'opportunistic', 'yes', 'mixed'}
        )
        if valid:
            selected = {
                'yes': 0,
                'opportunistic': 1,
                'no': 2,
            }[state['configured']]
            if self.dns_mode.get_selected() != selected:
                self.dns_mode.handler_block_by_func(
                    self._on_dns_mode_changed)
                self.dns_mode.set_selected(selected)
                self.dns_mode.handler_unblock_by_func(
                    self._on_dns_mode_changed)
        self.dns_mode.set_sensitive(valid and not self._action_busy)
        self.dns_reset_row.set_sensitive(valid and not self._action_busy)

    def _refresh_dns_page(self):
        state = _dns_mode_state()
        if state is None:
            self.dns_selection_row.set_title('DNS selector state unavailable')
            self.dns_selection_row.set_subtitle(
                'The versioned noid-dns-mode status could not be verified')
            self.dns_runtime_row.set_title('Resolver runtime UNKNOWN')
            self.dns_runtime_row.set_subtitle(
                'Do not assume encrypted or authenticated DNS transport')
            self.dns_physical_row.set_title('Physical-link policy UNKNOWN')
            self.dns_physical_row.set_subtitle(
                'No Ethernet/Wi-Fi transport claim is made')
            self.dns_scope_row.set_title('Active DNS path UNKNOWN')
            self.dns_scope_row.set_subtitle(
                'No routing-scope claim is made')
            self.dns_mode.set_sensitive(False)
            self.dns_reset_row.set_sensitive(False)
            return

        selection_labels = {
            'default': 'Image default (strict)',
            'opportunistic': 'Explicit opportunistic mode',
            'strict': 'Strict authenticated mode',
            'off': 'Plaintext DNS mode',
            'invalid': 'ERROR — unsafe or malformed selector file',
        }
        value_labels = {
            'no': 'off / plaintext DNS',
            'opportunistic': 'opportunistic / DNS-over-TLS with DNS/53 fallback',
            'yes': 'strict / authenticated DNS-over-TLS, fail closed',
            'unknown': 'UNKNOWN',
        }
        link_labels = {
            'no': 'DoT=no; effective per-link setting',
            'opportunistic': 'opportunistic DoT',
            'yes': 'strict DoT',
            'mixed': 'mixed per-link modes',
            'unknown': 'UNKNOWN',
        }
        physical_labels = {
            'none': 'no managed physical profile',
            'default': 'profile default / not explicitly converged',
            **link_labels,
        }
        self.dns_selection_row.set_title('Selected NoID Privacy DNS policy')
        self.dns_selection_row.set_subtitle(
            selection_labels[state['selection']])
        self.dns_runtime_row.set_title('Merged and live global transport')
        self.dns_runtime_row.set_subtitle(
            f"Configured: {value_labels[state['configured']]}; "
            f"runtime: {value_labels[state['runtime_global']]}")
        self.dns_physical_row.set_title('Managed physical-profile transport')
        self.dns_physical_row.set_subtitle(
            'Profile: '
            f"{physical_labels.get(state['physical_configured'], state['physical_configured'])}; "
            'runtime: '
            f"{physical_labels.get(state['physical_runtime'], state['physical_runtime'])}")
        self.dns_scope_row.set_title('Active DNS routing scope')
        if state['scope'] == 'link':
            self.dns_scope_row.set_subtitle(
                'VPN/private ~. link takes precedence '
                f"({link_labels.get(state['link_mode'], state['link_mode'])}); "
                'the active link profile is not rewritten by this control')
        elif state['scope'] == 'physical':
            self.dns_scope_row.set_subtitle(
                'A NoID Privacy-managed physical ~. link currently owns DNS routing')
        elif state['scope'] == 'mixed':
            self.dns_scope_row.set_subtitle(
                'Physical and VPN/private ~. routes coexist; inspect before '
                'making an active-path claim')
        elif state['scope'] == 'global':
            self.dns_scope_row.set_subtitle(
                'Global resolver path is active; the mode above governs its '
                'upstream transport')
        else:
            self.dns_scope_row.set_subtitle(
                'UNKNOWN — no effective transport claim is made')
        self._sync_dns_controls(state)

    def _on_dns_mode_changed(self, row, _pspec):
        mode = {0: 'strict', 1: 'opportunistic', 2: 'off'}.get(
            row.get_selected())
        if mode is None:
            self._refresh_dns_page()
            return
        state = _dns_mode_state()
        current = None if state is None else {
            'opportunistic': 'opportunistic',
            'yes': 'strict',
            'no': 'off',
        }.get(state['configured'])
        if mode == current:
            return
        if mode == 'strict':
            dialog = Adw.AlertDialog.new(
                'Use strict authenticated DNS-over-TLS?',
                'Global Quad9 and managed physical Ethernet/Wi-Fi DNS will use '
                'authenticated TLS and fail closed. If this network blocks '
                'TCP port 853 or requires a captive portal, DNS stops until '
                'you choose Opportunistic or Off. VPN/private profiles are '
                'not rewritten.')
            dialog.add_response('cancel', 'Cancel')
            dialog.add_response('strict', 'Use strict DoT')
            dialog.set_default_response('cancel')
            dialog.set_close_response('cancel')

            def strict_response(_dialog, response):
                if response == 'strict':
                    self._apply_dns_mode('strict')
                else:
                    self._refresh_dns_page()

            dialog.connect('response', strict_response)
            dialog.present(self)
            return
        if mode == 'opportunistic':
            dialog = Adw.AlertDialog.new(
                'Enable pre-VPN DNS compatibility?',
                'Global Quad9 and managed physical Ethernet/Wi-Fi will try DoT '
                'but may downgrade to unauthenticated plaintext DNS on port '
                '53. Use this before VPN setup when strict DoT on the physical '
                'uplink prevents resolving the VPN endpoint. This mode persists '
                'until Strict is selected again. It does not control tunnel '
                'DNS; unset VPN/private profiles separately inherit the '
                'best-effort opportunistic default and explicit values win.')
            dialog.add_response('cancel', 'Cancel')
            dialog.add_response('opportunistic', 'Enable compatibility')
            dialog.set_default_response('cancel')
            dialog.set_close_response('cancel')

            def opportunistic_response(_dialog, response):
                if response == 'opportunistic':
                    self._apply_dns_mode('opportunistic')
                else:
                    self._refresh_dns_page()

            dialog.connect('response', opportunistic_response)
            dialog.present(self)
            return
        if mode == 'off':
            dialog = Adw.AlertDialog.new(
                'Disable NoID Privacy DNS-over-TLS?',
                'This deliberately permits plaintext global and physical-link '
                'DNS on port 53. Use it only for recovery or a network that '
                'cannot carry DoT. VPN/private profiles are not rewritten.')
            dialog.add_response('cancel', 'Cancel')
            dialog.add_response('off', 'Use plaintext DNS')
            dialog.set_response_appearance(
                'off', Adw.ResponseAppearance.DESTRUCTIVE)
            dialog.set_default_response('cancel')
            dialog.set_close_response('cancel')

            def off_response(_dialog, response):
                if response == 'off':
                    self._apply_dns_mode('off')
                else:
                    self._refresh_dns_page()

            dialog.connect('response', off_response)
            dialog.present(self)
            return
        self._refresh_dns_page()

    def _apply_dns_mode(self, mode):
        if mode not in {'opportunistic', 'strict', 'off', 'reset'}:
            self._toast('Unknown DNS transport mode.', 5)
            self._refresh_dns_page()
            return
        started, proc = self._start_privileged([DNS_MODE_CLI, mode])
        if started:
            GLib.timeout_add(
                500, self._wait_then_refresh_dns, proc, mode, [0])
        else:
            self._refresh_dns_page()

    def _wait_then_refresh_dns(self, proc, mode, attempts):
        state, rc = _finish_privileged_action(proc, attempts)
        if state == 'pending':
            return True
        if state == 'orphaned':
            self._toast(_privileged_failure_text(state, rc))
            return True
        self._action_busy = False
        self._refresh_dns_page()
        if state == 'success':
            label = {
                'opportunistic': (
                    'VPN-compatible opportunistic DoT selected globally and on physical links'),
                'strict': (
                    'Strict authenticated DoT selected globally and on physical links'),
                'off': (
                    'Plaintext selected for global and physical DNS recovery'),
                'reset': (
                    'DNS transport reset to the strict image policy'),
            }[mode]
            self._toast(label)
        else:
            self._toast(_privileged_failure_text(
                state, rc, _privileged_stderr_tail(proc)))
        self._sync_control_sensitivity()
        return False

    # ========================================================================
    # Network Status Page
    # ========================================================================

    def _build_status_page(self):
        page = Adw.PreferencesPage()

        # --- Group 1: VPN ---
        self.status_vpn_group = Adw.PreferencesGroup()
        self.status_vpn_group.set_title('VPN State')
        self.status_vpn_group.set_description(
            'Active VPN tunnel and any separately named NetworkManager '
            'killswitch profile. Refreshes on tab entry or by button.')
        self.status_vpn_group.set_header_suffix(
            self._refresh_button(self._refresh_status, 'Refresh network status'))

        self.status_vpn_row = noid_ui.status_row('🔐')
        self.status_ks_row = noid_ui.status_row('🛡️')
        self.status_vpn_row.set_use_markup(False)
        self.status_ks_row.set_use_markup(False)
        self.status_vpn_group.add(self.status_vpn_row)
        self.status_vpn_group.add(self.status_ks_row)
        page.add(self.status_vpn_group)

        # --- Group 2: Firewall ---
        self.status_fw_group = Adw.PreferencesGroup()
        self.status_fw_group.set_title('Firewall')
        self.status_fw_group.set_description(
            "firewalld default zone + NoID Privacy's WAN-egress-strict + "
            'block-lan-out policy state at a glance.')
        self.status_default_zone_row = noid_ui.status_row('🔥')
        self.status_wan_strict_row = noid_ui.status_row('🔒')
        self.status_lan_block_row = noid_ui.status_row('🚧')
        self.status_fw_group.add(self.status_default_zone_row)
        self.status_fw_group.add(self.status_wan_strict_row)
        self.status_fw_group.add(self.status_lan_block_row)
        page.add(self.status_fw_group)

        # --- Group 3: DNS ---
        self.status_dns_group = Adw.PreferencesGroup()
        self.status_dns_group.set_title('DNS')
        self.status_dns_group.set_description(
            'Active DNS resolver per link (systemd-resolved). A VPN/private '
            '~. scope takes precedence; otherwise a managed physical ~. '
            'scope or the global Quad9 path is used.')
        self.status_dns_row = noid_ui.status_row('🌐')
        self.status_dns_group.add(self.status_dns_row)
        page.add(self.status_dns_group)

        # --- Group 3b: Gateway ARP-Hardening (router-swap recovery) ---
        self.status_arp_group = Adw.PreferencesGroup()
        self.status_arp_group.set_title('Gateway ARP-Hardening')
        self.status_arp_group.set_description(
            'Anti-spoofing uses a permanent kernel neighbour pin while the '
            'validated gateway identity also feeds the fail-closed XDP LAN '
            'boundary. The pin can go stale after a router swap (same IP, NEW '
            'MAC). Re-learn to validate and pin the gateway on the current '
            'interface.')
        self.status_arp_row = noid_ui.status_row('🛡️')
        self.status_arp_group.add(self.status_arp_row)

        # Re-learn action — shared _action_row pattern (emoji prefix + chevron
        # + whole-row activate), identical to the WAN "Reset all pinned
        # endpoints" maintenance action it mirrors.
        self.status_arp_relearn_row = self._action_row(
            '🔄', 'Re-learn gateway',
            'Re-detect + pin the gateway MAC on the current interface (fixes '
            '"no internet" after a router swap or a Wi-Fi/Ethernet switch)',
            lambda r: self._arp_relearn())
        self.status_arp_group.add(self.status_arp_relearn_row)
        page.add(self.status_arp_group)

        # --- Group 4: Tools ---
        grp_tools = Adw.PreferencesGroup()
        grp_tools.set_title('Tools')
        grp_tools.set_description(
            'Run complete read-only checks in a formatted terminal. These '
            'audits do not reload, reset or change the network policy.')
        grp_tools.add(self._action_row(
            '🔍', 'Audit WAN-egress-strict',
            'Service, published runtime mode, endpoint reconciliation, '
            'counters and timers',
            lambda r: self._open_audit('wan')))
        grp_tools.add(self._action_row(
            '🛡', 'Audit firewall policy',
            'Runtime/permanent block-lan-out and DROP-zone configuration '
            'with dynamic interface bindings explained',
            lambda r: self._open_audit('firewall')))
        grp_tools.add(self._action_row(
            '📊', 'Audit nftables rules and counters',
            'Kernel ruleset, NoID Privacy hooks/priorities and complete named '
            'counter objects without truncation',
            lambda r: self._open_audit('nft')))
        grp_tools.add(self._action_row(
            '📐', 'Audit tunnel MTU',
            'WireGuard tunnel MTU against the outer link of its endpoint '
            'route; reports an oversized tunnel that stalls large TLS '
            'handshakes and prints the exact temporary correction',
            lambda r: self._open_audit('mtu')))
        page.add(grp_tools)

        self._refresh_status()

        self.stack.add_titled_with_icon(
            page, 'status', 'Network Status', 'view-list-symbolic')

    def _refresh_status(self):
        # VPN + killswitch use one closed snapshot so both rows describe the
        # same NetworkManager state.
        connections = _active_nm_connections()
        vpn = self._get_vpn_state(connections)
        if connections is None:
            self.status_vpn_row.set_title('VPN state unavailable')
            self.status_vpn_row.set_subtitle(
                'NetworkManager active-connection output could not be verified')
        elif vpn:
            address = f'IP {vpn["ip"]}' if vpn['ip'] else 'IP unavailable'
            self.status_vpn_row.set_title(f'VPN active: {vpn["name"]}')
            self.status_vpn_row.set_subtitle(
                f'{address} via {vpn["device"]} ({vpn["type"]})')
        else:
            self.status_vpn_row.set_title('No VPN connection active')
            self.status_vpn_row.set_subtitle(
                'Set up a VPN client (ProtonVPN, Mullvad, IVPN, or import a '
                'WireGuard/OpenVPN profile) and connect first')

        # Killswitch
        ks = self._get_killswitch_state(connections)
        if connections is None:
            self.status_ks_row.set_title('Killswitch profile state unavailable')
            self.status_ks_row.set_subtitle(
                'No name-based claim is made because NetworkManager output '
                'could not be verified')
        elif ks:
            self.status_ks_row.set_title('Named killswitch profile detected')
            self.status_ks_row.set_subtitle(
                f'Connection {ks["name"]}, autoconnect-priority {ks["priority"]}')
        else:
            self.status_ks_row.set_title('No named NetworkManager killswitch profile detected')
            self.status_ks_row.set_subtitle(
                'This is not a universal killswitch verdict: VPN clients may '
                'enforce one without a separately named NetworkManager profile')

        # Default zone
        default_zone = _run_cmd(
            [FIREWALL_CLI, '--get-default-zone']).strip()
        self.status_default_zone_row.set_title('Firewall default zone')
        self.status_default_zone_row.set_subtitle(default_zone or '(unknown)')

        # WAN-strict state from the root-published actual nft/timer
        # postcondition. Missing state is UNKNOWN, never optimistic STRICT.
        wan_mode = _wan_runtime_mode()
        mode_title, mode_detail = _wan_mode_text(wan_mode)
        self.status_wan_strict_row.set_title('WAN-egress-strict')
        self.status_wan_strict_row.set_subtitle(
            f'{mode_title}. {mode_detail}')

        # LAN block state
        lan_state = self._lan_global_state()
        self.status_lan_block_row.set_title('block-lan-out')
        if lan_state == 'BLOCKED':
            self.status_lan_block_row.set_subtitle(
                'ACTIVE — locally classified destinations blocked; '
                'per-IP exceptions only')
        elif lan_state == 'ALLOWED':
            self.status_lan_block_row.set_subtitle(
                'ALLOWED — firewalld, topology and WAN-strict synchronized; '
                'ARP/pins unchanged')
        else:
            self.status_lan_block_row.set_subtitle(
                'ERROR — enforcement layers disagree; do not assume a boundary')

        # DNS (resolvectl)
        dns = self._get_dns_summary()
        self.status_dns_row.set_title('DNS resolver')
        self.status_dns_row.set_subtitle(dns or '(no DNS info)')

        # Gateway ARP-hardening (router-swap recovery)
        self._refresh_arp()

    def _refresh_arp(self):
        """Render gateway ARP-hardening state + MAC match/mismatch.

        Reads the mode-0644 state file + `ip neigh` directly (non-privileged);
        the privileged re-learn runs through _arp_relearn()."""
        st = _arp_state()
        if st.get('ERROR'):
            self.status_arp_row.set_title(
                'ARP-hardening ERROR — state inconsistent')
            self.status_arp_row.set_subtitle(
                'The root-owned gateway identity, marker or dispatcher '
                'lifecycle does not match M04; networking fails closed until '
                'the state is repaired')
            return
        if not st.get('GATEWAY_IP'):
            self.status_arp_row.set_title('ARP-hardening: not active')
            self.status_arp_row.set_subtitle(
                'No validated gateway identity (firstboot learning pending)')
            return
        gw_ip = st.get('GATEWAY_IP', '')
        pinned = st.get('GATEWAY_MAC', '').lower()
        if st.get('ENABLED') == '0':
            self.status_arp_row.set_title('Permanent gateway pin disabled')
            self.status_arp_row.set_subtitle(
                f'Gateway identity {gw_ip} / {pinned} remains validated for '
                'the fail-closed XDP LAN boundary; re-learn to re-enable the '
                'kernel neighbour pin')
            return
        current = _current_gateway_mac(gw_ip, st.get('WAN_IFACE', ''))
        if not current:
            self.status_arp_row.set_title(
                'ARP-hardening DEGRADED — gateway pin missing')
            self.status_arp_row.set_subtitle(
                f'Gateway {gw_ip} should be pinned to {pinned}, but the kernel '
                'neighbour entry is missing. WAN return traffic is dropped '
                'until re-learn — commonly after a router swap or a change of '
                'the active link (e.g. Wi-Fi/Ethernet) on the same router.')
        elif current == pinned:
            self.status_arp_row.set_title('ARP-hardening active — MAC match')
            self.status_arp_row.set_subtitle(
                f'Gateway {gw_ip} pinned to {pinned} — kernel pin matches state')
        else:
            self.status_arp_row.set_title('ARP-hardening MAC mismatch')
            self.status_arp_row.set_subtitle(
                f'Gateway {gw_ip}: state {pinned}, kernel pin {current} — '
                're-learn to restore one authoritative binding')

    def _arp_relearn(self):
        """Re-learn the gateway MAC through the privilege router.

        Takes NO user input: noid-arp-hardening.sh refresh auto-detects WAN
        iface and gateway, so there is no shell or argument-injection surface.
        """
        started, proc = self._start_privileged([ARP_CLI, 'refresh'])
        if started:
            GLib.timeout_add(500, self._wait_then_refresh_arp, proc, [0])

    def _wait_then_refresh_arp(self, proc, attempts):
        state, rc = _finish_privileged_action(proc, attempts)
        if state == 'pending':
            return True
        if state == 'orphaned':
            self._toast(_privileged_failure_text(state, rc))
            return True
        self._action_busy = False
        self._refresh_arp()
        if state == 'success':
            self._toast('Gateway re-learned — ARP hardening re-pinned')
        else:
            self._toast(_privileged_failure_text(state, rc, _privileged_stderr_tail(proc)))
        self._sync_control_sensitivity()
        return False

    def _get_vpn_state(self, connections):
        """Scan active connections for VPN/wireguard. Return dict or None."""
        if connections is None:
            return None
        for connection in connections:
            ctype = connection['type'].lower()
            if ctype not in {'vpn', 'wireguard'}:
                continue
            return {
                'name': connection['name'],
                'type': ctype,
                'device': connection['device'],
                'ip': _device_address(connection['device']),
            }
        return None

    def _get_killswitch_state(self, connections):
        """Find a killswitch-named active connection. Return dict or None."""
        if connections is None:
            return None
        for connection in connections:
            name = connection['name']
            if 'killswitch' not in name.lower():
                continue
            rc, priority_output = _run_cmd_checked([
                NMCLI_CLI, '--get-values',
                'connection.autoconnect-priority',
                'connection', 'show', 'uuid', connection['uuid'],
            ], timeout=3)
            priority = priority_output.strip()
            prio = priority if (
                rc == 0 and re.fullmatch(r'-?[0-9]+', priority)
            ) else 'unavailable'
            return {'name': name, 'priority': prio}
        return None

    def _get_dns_summary(self):
        """Return short DNS-resolver summary from resolvectl."""
        rc, out = _run_cmd_checked([RESOLVECTL_CLI, 'dns'])
        if rc != 0:
            return 'UNKNOWN — resolvectl query failed'
        # Find Link entries
        active = []
        for line in out.split('\n'):
            line = line.strip()
            if line.startswith('Link') and ':' in line:
                _, dns = line.split(':', 1)
                dns = dns.strip()
                if dns:
                    active.append(line)
        if active:
            return '\n'.join(active)
        # Fallback: global DNS
        for line in out.split('\n'):
            line = line.strip()
            if line.startswith('Global:') and ':' in line:
                return line
        return None


# --- Application -------------------------------------------------------------

# Deep-link targets, keyed by the exact Adw.ViewStack child names this window
# registers. A caller that names a section lands on it instead of dropping the
# user on WAN Privacy with an unexplained instruction to find another tab —
# Setup's network-printer step is the first such caller. Only these four names
# are accepted; anything else is rejected before the GUI is instantiated.
NETWORK_SECTIONS = ('wan', 'lan', 'dns', 'status')


def _requested_section(argv):
    """Return one exact validated --section value, or None for no arguments."""
    if not argv:
        return None
    if len(argv) == 2 and argv[0] == '--section':
        requested = argv[1]
    elif len(argv) == 1 and argv[0].startswith('--section='):
        requested = argv[0].split('=', 1)[1]
    else:
        raise ValueError(
            'expected no arguments, --section NAME, or --section=NAME')
    if requested not in NETWORK_SECTIONS:
        raise ValueError('unknown --section %r' % requested)
    return requested


def _print_usage(stream):
    print(__doc__ or '', file=stream)
    print('\nUsage:', file=stream)
    print('  noid-network                 Open the NoID Privacy Network management GUI',
          file=stream)
    print('  noid-network --section NAME  Open directly on one tab', file=stream)
    print('                               NAME: %s'
          % ' | '.join(NETWORK_SECTIONS), file=stream)


class NoIDNetworkApp(noid_ui.NoIDApplication):
    def __init__(self, section=None):
        super().__init__(APP_ID, 'noid-privacy-network')
        self._section = section

    def do_activate(self):
        win = self.props.active_window
        if win is None:
            win = NetworkWindow(self)
        # Switch an already-open window too: a second launch that names a
        # section is a request to go there, not just to raise the window.
        if self._section is not None:
            stack = getattr(win, 'stack', None)
            if stack is not None and stack.get_child_by_name(self._section):
                stack.set_visible_child_name(self._section)
        win.present()


def main():
    argv = sys.argv[1:]
    if argv in (['--help'], ['-h']):
        _print_usage(sys.stdout)
        return 0

    try:
        requested_section = _requested_section(argv)
    except ValueError as error:
        print('noid-network: %s' % error, file=sys.stderr)
        _print_usage(sys.stderr)
        return 2

    app = NoIDNetworkApp(requested_section)
    return app.run([sys.argv[0]])


if __name__ == '__main__':
    sys.exit(main())
NOID_NETWORK_PY_EOF
python3 -c 'import ast, pathlib, sys; ast.parse(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))' \
    "$NETWORK_CANDIDATE" \
    || fail "noid-network candidate has invalid Python syntax"
PYTHONPATH=/usr/lib/noid-privacy python3 "$NETWORK_CANDIDATE" --help \
    | grep -q '^  noid-network' \
    || fail "noid-network candidate import/help smoke failed"
publish_root_file "$NETWORK_CANDIDATE" /usr/local/bin/noid-network 0755
log "STEP 1: /usr/local/bin/noid-network deployed (Python 3 + GTK4 + Adw + shared UI)"

# ---------------------------------------------------------------------------
# STEP 2: Deploy /usr/local/bin/noid-network-audit
# ---------------------------------------------------------------------------

cat > "$AUDIT_CANDIDATE" <<'NOID_NETWORK_AUDIT_EOF'
#!/bin/bash
# noid-network-audit — closed, read-only WAN/firewalld/nftables/MTU audits.
# Every privileged command is fixed below. No user input becomes a command,
# and none of the four modes reloads, resets or changes network state.

set -uo pipefail

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

FMT_LIB=/usr/local/lib/noid-privacy/agent-install-format.sh
FMT_PARENT=/usr/local/lib/noid-privacy
FORMAT_TRUSTED=0
# shellcheck source=/dev/null
if [ -d "$FMT_PARENT" ] && [ ! -L "$FMT_PARENT" ] \
        && [ "$(/usr/bin/readlink -e -- "$FMT_PARENT" 2>/dev/null)" = \
            "$FMT_PARENT" ] \
        && [ "$(/usr/bin/stat -Lc '%u:%g:%a' -- "$FMT_PARENT" 2>/dev/null)" = \
            "0:0:755" ] \
        && [ -f "$FMT_LIB" ] && [ ! -L "$FMT_LIB" ] \
        && [ "$(/usr/bin/readlink -e -- "$FMT_LIB" 2>/dev/null)" = \
            "$FMT_LIB" ] \
        && [ "$(/usr/bin/stat -Lc '%u:%g:%a:%h' -- "$FMT_LIB" 2>/dev/null)" = \
            "0:0:644:1" ] \
        && /usr/sbin/matchpathcon -V "$FMT_PARENT" >/dev/null \
        && /usr/sbin/matchpathcon -V "$FMT_LIB" >/dev/null; then
    . "$FMT_LIB"
    FORMAT_TRUSTED=1
else
    fmt_banner() { printf '== %s ==\n' "$1"; [ -z "${2:-}" ] || printf '   %s\n' "$2"; }
    fmt_step() { printf '\n[%s/%s] %s\n' "$1" "$2" "$3"; }
    fmt_ok() { printf '  OK: %s\n' "$1"; }
    fmt_info() { printf '  - %s\n' "$1"; }
    fmt_err() { printf '  ERROR: %s\n' "$1" >&2; }
    fmt_note() { printf '%s\n' "$1"; }
    fmt_done() { printf '\nOK: %s\n' "$1"; }
fi

SUDO=/usr/bin/sudo
SYSTEMCTL=/usr/bin/systemctl
FIREWALL=/usr/bin/firewall-cmd
NFT=/usr/sbin/nft
JQ=/usr/bin/jq
AWK=/usr/bin/awk
STAT=/usr/bin/stat
WC=/usr/bin/wc
SED=/usr/bin/sed
DIFF=/usr/bin/diff
GREP=/usr/bin/grep
TRUE=/usr/bin/true
READLINK=/usr/bin/readlink
MATCHPATHCON=/usr/sbin/matchpathcon
IP=/usr/sbin/ip
WG=/usr/bin/wg
CAT=/usr/bin/cat
HEAD=/usr/bin/head
NMCLI=/usr/bin/nmcli
BUSCTL=/usr/bin/busctl
WAN_TOGGLE=/usr/local/sbin/noid-toggle-wan-strict
WAN_STATUS=/usr/local/sbin/noid-wan-strict
WAN_STATUS_FILE=/run/noid-privacy/wan-strict-status
SELF=/usr/local/bin/noid-network-audit
SELF_PARENT=/usr/local/bin
WG_QUICK_DIR=/etc/wireguard

MODE=
WORKER_MODE=
GUI_HOLD=${NOID_NETWORK_GUI:-0}
overall=0
CMD_OUTPUT=
CMD_RC=0

case "$GUI_HOLD" in
    0|1) ;;
    *) GUI_HOLD=0 ;;
esac

usage() {
    cat <<'USAGE_EOF'
Usage: noid-network-audit <wan|firewall|nft|mtu>

  wan       Service, published mode, endpoint reconciliation and timers
  firewall  Runtime/permanent block-lan-out and DROP-zone parity
  nft       Kernel ruleset, NoID Privacy hooks/priorities and named counters
  mtu       WireGuard tunnel MTU against the outer link of its endpoint route

All checks are read-only. No policy is reloaded, reset or changed.
USAGE_EOF
}

finish() {
    local rc=$1
    if [ "$rc" -eq 0 ]; then
        fmt_done "Audit complete — every checked postcondition passed"
    else
        fmt_err "Audit complete — one or more postconditions failed"
        fmt_note "Review the failed step above; this tool made no changes."
    fi
    if [ "$GUI_HOLD" = "1" ] && [ -t 0 ]; then
        printf '\n'
        read -r -p "Press ENTER to close..." || :
    fi
    return "$rc"
}

require_binaries() {
    local path
    for path in "$SUDO" "$SYSTEMCTL" "$FIREWALL" "$NFT" "$JQ" "$AWK" \
                "$STAT" "$WC" "$SED" "$DIFF" "$GREP" "$TRUE" \
                "$READLINK" "$MATCHPATHCON" "$IP" "$WG" "$CAT" "$HEAD" \
                "$NMCLI" "$BUSCTL"; do
        if [ ! -x "$path" ]; then
            fmt_err "Required executable is missing: $path"
            return 1
        fi
    done
}

validate_self() {
    [ -d "$SELF_PARENT" ] && [ ! -L "$SELF_PARENT" ] \
        && [ "$("$READLINK" -e -- "$SELF_PARENT" 2>/dev/null)" = \
            "$SELF_PARENT" ] \
        && [ "$("$STAT" -Lc '%u:%g:%a' -- "$SELF_PARENT" 2>/dev/null)" = \
            "0:0:755" ] \
        && [ -f "$SELF" ] && [ ! -L "$SELF" ] \
        && [ "$("$READLINK" -e -- "$SELF" 2>/dev/null)" = "$SELF" ] \
        && [ "$("$STAT" -Lc '%u:%g:%a:%h' -- "$SELF" 2>/dev/null)" = \
            "0:0:755:1" ] \
        && "$MATCHPATHCON" -V "$SELF_PARENT" >/dev/null \
        && "$MATCHPATHCON" -V "$SELF" >/dev/null
}

prepare_admin() {
    # `sudo -n -v` validates a credential timestamp, not whether a concrete
    # NOPASSWD command is authorized; on sudo 1.9 it can fail even for this
    # host's active NOPASSWD: ALL rule. Probe one inert exact command instead.
    if ! "$SUDO" -n -- "$TRUE" 2>/dev/null; then
        fmt_info "Administrator authentication is required for kernel firewall state."
        if ! "$SUDO" -v; then
            fmt_err "Administrator authentication failed; no audit command ran"
            return 1
        fi
        if ! "$SUDO" -n -- "$TRUE" 2>/dev/null; then
            fmt_err "Administrator route is still unavailable after authentication"
            return 1
        fi
    fi
    fmt_info "Administrator route ready (the fixed root worker is non-interactive)"
}

root_capture() {
    CMD_OUTPUT=$("$@" 2>&1)
    CMD_RC=$?
    return 0
}

show_capture() {
    local label=$1
    if [ -n "$CMD_OUTPUT" ]; then
        printf '%s\n' "$CMD_OUTPUT"
    fi
    if [ "$CMD_RC" -eq 0 ]; then
        fmt_ok "$label"
        return 0
    fi
    fmt_err "$label failed (exit $CMD_RC)"
    overall=1
    return 1
}

read_runtime_mode() {
    local parent metadata line bytes lines mode
    parent=${WAN_STATUS_FILE%/*}
    if [ ! -d "$parent" ] || [ -L "$parent" ] \
       || [ "$("$READLINK" -e -- "$parent" 2>/dev/null)" != "$parent" ] \
       || [ "$("$STAT" -Lc '%u:%g:%a' "$parent" 2>/dev/null)" != \
            "0:0:755" ] \
       || ! "$MATCHPATHCON" -V "$parent" >/dev/null; then
        return 1
    fi
    if [ ! -f "$WAN_STATUS_FILE" ] || [ -L "$WAN_STATUS_FILE" ]; then
        return 1
    fi
    metadata=$("$STAT" -Lc '%u:%g:%a:%h' "$WAN_STATUS_FILE" 2>/dev/null) || return 1
    [ "$metadata" = "0:0:644:1" ] \
        && [ "$("$READLINK" -e -- "$WAN_STATUS_FILE" 2>/dev/null)" = \
            "$WAN_STATUS_FILE" ] \
        && "$MATCHPATHCON" -V "$WAN_STATUS_FILE" >/dev/null \
        || return 1
    IFS= read -r line < "$WAN_STATUS_FILE" || return 1
    bytes=$("$WC" -c < "$WAN_STATUS_FILE") || return 1
    lines=$("$WC" -l < "$WAN_STATUS_FILE") || return 1
    [ "$lines" -eq 1 ] && [ "$bytes" -eq $((${#line} + 1)) ] || return 1
    case "$line" in
        MODE=DISABLED|MODE=GRACE_BOOTSTRAP|MODE=GRACE_PAUSED|MODE=STRICT|MODE=STRICT_EMPTY|MODE=ERROR)
            mode=${line#MODE=}
            printf '%s\n' "$mode"
            ;;
        *) return 1 ;;
    esac
}

# WireGuard data-message encapsulation, per RFC-less but fixed wire format:
# type+reserved 4 + receiver index 4 + counter 8 + Poly1305 tag 16 = 32 bytes,
# plus the outer IP and UDP headers. WireGuard also pads the plaintext to a
# 16-byte boundary, so the usable inner MTU is floored to a multiple of 16.
# NetworkManager's `wireguard.mtu=0` default does not derive this from the
# current routes (wg-quick does), so a reduced outer link silently produces an
# oversized tunnel. The symptom is outer fragmentation and stalled large TLS
# handshakes, not an obvious link failure.
WG_PAD=16
WG_TRAILER=32

mtu_overhead_for_family() {
    case "$1" in
        inet6) printf '%s' $((40 + 8 + WG_TRAILER)) ;;
        *)     printf '%s' $((20 + 8 + WG_TRAILER)) ;;
    esac
}

mtu_safe_inner() {
    local outer=$1 overhead=$2 usable
    usable=$((outer - overhead))
    [ "$usable" -ge "$WG_PAD" ] || return 1
    printf '%s' $((usable / WG_PAD * WG_PAD))
}

mtu_endpoint_family() {
    case "$1" in
        \[*\]:*|*:*:*) printf 'inet6' ;;
        *)             printf 'inet' ;;
    esac
}

mtu_endpoint_host() {
    local ep=$1
    case "$ep" in
        \[*\]:*) ep=${ep#[}; printf '%s' "${ep%%]*}" ;;
        *)       printf '%s' "${ep%:*}" ;;
    esac
}

mtu_read_link() {
    local value
    value=$("$CAT" "/sys/class/net/$1/mtu" 2>/dev/null) || return 1
    case "$value" in
        ''|*[!0-9]*) return 1 ;;
    esac
    printf '%s' "$value"
}

# A full-tunnel peer (AllowedIPs 0.0.0.0/0) is only reachable because
# WireGuard marks its own encrypted packets and a policy rule exempts that
# mark. An unmarked `ip route get` therefore returns the tunnel itself and
# would measure the inner link as if it were the outer one.
mtu_tunnel_fwmark() {
    local mark
    mark=$("$WG" show "$1" fwmark 2>/dev/null) || return 1
    case "$mark" in
        ''|off|none) return 1 ;;
    esac
    printf '%s' "$mark"
}

# Emits "<outer device> <route MTU or 0>". Returns 2 when the endpoint routes
# back into the tunnel, which means the outer link is not determinable here.
mtu_route_lookup() {
    local host=$1 mark=$2 tunnel=$3 out first flattened fields
    local dev='' route_mtu=0 i j
    if [ -n "$mark" ]; then
        out=$("$IP" route get "$host" mark "$mark" 2>/dev/null) || return 1
    else
        out=$("$IP" route get "$host" 2>/dev/null) || return 1
    fi
    [ -n "$out" ] || return 1
    first=$(printf '%s\n' "$out" | "$HEAD" -1)
    read -ra fields <<<"$first"
    for ((i = 0; i < ${#fields[@]}; i++)); do
        [ "${fields[i]}" = dev ] || continue
        dev=${fields[i + 1]}
        break
    done
    [ -n "$dev" ] || return 1
    [ "$dev" != "$tunnel" ] || return 2
    # A route-scoped or PMTU-cached `mtu N` overrides the device MTU and can
    # appear on the cache continuation line, so scan the whole answer.
    flattened=${out//$'\n'/ }
    read -ra fields <<<"$flattened"
    for ((i = 0; i < ${#fields[@]}; i++)); do
        [ "${fields[i]}" = mtu ] || continue
        j=$((i + 1))
        [ "$j" -lt "${#fields[@]}" ] || continue
        if [ "${fields[j]}" = lock ]; then
            j=$((j + 1))
            [ "$j" -lt "${#fields[@]}" ] || continue
        fi
        case "${fields[j]}" in
            ''|*[!0-9]*) ;;
            *) route_mtu=${fields[j]} ;;
        esac
        [ "$route_mtu" -eq 0 ] || break
    done
    printf '%s %s' "$dev" "$route_mtu"
}

# Emit "yes", "link" or "no" when the tunnel's IPv6 state is observable.
# RFC 8200 section 5 sets 1280 bytes as the minimum IPv6 link MTU. A global/ULA
# address or an IPv6 AllowedIP proves user traffic or configured peer intent.
# Link-local alone is reported but does not block an otherwise IPv4-only
# correction: NetworkManager commonly assigns it to WireGuard devices that
# carry no usable IPv6. Read failure is distinct from "no": an unknown state
# must never authorize a sub-1280 command.
mtu_tunnel_ipv6_state() {
    local addresses allowed
    addresses=$("$IP" -6 addr show dev "$1" 2>/dev/null) || return 1
    if printf '%s\n' "$addresses" | "$GREP" -qE 'inet6 .* scope global'; then
        printf 'yes'
        return 0
    fi
    allowed=$("$WG" show "$1" allowed-ips 2>/dev/null) || return 1
    if printf '%s\n' "$allowed" | "$GREP" -q ':'; then
        printf 'yes'
    elif printf '%s\n' "$addresses" | "$GREP" -qE 'inet6 .* scope link'; then
        printf 'link'
    else
        printf 'no'
    fi
}

# Emit "<UUID> <flags>" only when NetworkManager exposes an exact active
# profile for this device and its Settings.Connection flags are readable.
# The flags are the ownership boundary: zero is a persistent profile. Any
# UNSAVED, NM_GENERATED, VOLATILE or EXTERNAL bit means another lifecycle owns
# the runtime object and the audit must not advise turning it into a disk file.
mtu_nm_profile_state() {
    local iface=$1 uuid listing path answer type flags
    uuid=$("$NMCLI" -g GENERAL.CON-UUID device show "$iface" 2>/dev/null) \
        || return 1
    case "$uuid" in
        ????????-????-????-????-????????????) ;;
        *) return 1 ;;
    esac
    listing=$("$NMCLI" -t -f UUID,DBUS-PATH connection show 2>/dev/null) \
        || return 1
    path=$(printf '%s\n' "$listing" | "$AWK" -F: -v u="$uuid" \
        '$1 == u { sub(/^[^:]*:/, ""); print; exit }')
    case "$path" in
        /org/freedesktop/NetworkManager/Settings/*) ;;
        *) return 1 ;;
    esac
    case "${path#/org/freedesktop/NetworkManager/Settings/}" in
        ''|*[!0-9]*) return 1 ;;
    esac
    answer=$("$BUSCTL" get-property org.freedesktop.NetworkManager "$path" \
        org.freedesktop.NetworkManager.Settings.Connection Flags 2>/dev/null) \
        || return 1
    read -r type flags _ <<<"$answer"
    [ "$type" = u ] || return 1
    case "$flags" in
        ''|*[!0-9]*) return 1 ;;
    esac
    printf '%s %s' "$uuid" "$flags"
}

# Explain the exact native repair for the observed owner without performing
# it. A live `ip link set` is always temporary. Durable advice is printed only
# after positive ownership evidence: zero NM flags for a persistent profile,
# or a regular non-symlinked wg-quick file at its canonical path. Everything
# else stays with the provider/client that created the tunnel.
mtu_fix_guidance() {
    local iface=$1 safe=$2 nm_state uuid flags quick_file
    fmt_info "Immediate diagnostic correction (runtime only):"
    fmt_info "  sudo ip link set dev $(printf '%q' "$iface") mtu $safe"

    nm_state=$(mtu_nm_profile_state "$iface")
    if [ -n "$nm_state" ]; then
        uuid=${nm_state%% *}
        flags=${nm_state##* }
        if [ "$flags" -eq 0 ]; then
            fmt_info "Durable owner: persistent NetworkManager WireGuard profile."
            fmt_info "Save the same computed MTU for future activations with:"
            fmt_info "  sudo nmcli connection modify uuid $(printf '%q' "$uuid") wireguard.mtu $safe"
            fmt_info "That profile edit does not change the already-active link; use"
            fmt_info "the runtime command above now or reconnect when convenient."
        else
            fmt_info "Durable owner: a runtime/provider-managed NetworkManager profile"
            fmt_info "(connection flags $flags); do not persist this generated profile."
            fmt_info "Set WireGuard MTU $safe in the owning VPN app if it exposes an"
            fmt_info "MTU setting. Otherwise the runtime correction lasts only until"
            fmt_info "that app reconfigures or recreates the tunnel; report the value"
            fmt_info "and outer-link evidence above to the provider."
        fi
        return
    fi

    quick_file="$WG_QUICK_DIR/$iface.conf"
    if [ -f "$quick_file" ] && [ ! -L "$quick_file" ]; then
        fmt_info "Durable owner: canonical wg-quick configuration $quick_file"
        fmt_info "Add or replace this line in its [Interface] section:"
        fmt_info "  MTU = $safe"
        fmt_info "Then recreate the tunnel when convenient; this audit does not edit"
        fmt_info "a configuration that can contain private key material."
        return
    fi

    fmt_info "Durable owner: not provable from NetworkManager or a canonical"
    fmt_info "wg-quick file. Set MTU $safe in the application or service that"
    fmt_info "creates $iface; do not create a competing NetworkManager profile."
}

audit_mtu() {
    local iface tun_mtu endpoints ep fam host dev outer_mtu overhead safe
    local worst_safe worst_detail tunnels count index
    local fwmark lookup lookup_rc route_mtu peers unresolved ipv6_state
    fmt_banner "WireGuard tunnel MTU audit" \
        "Tunnel MTU · outer endpoint route · safe encapsulated maximum"
    fmt_note "Read-only: this mode inspects link and route state and changes nothing."

    tunnels=$("$IP" -d -o link show type wireguard 2>/dev/null \
        | "$AWK" -F': ' '{print $2}' | "$AWK" '{print $1}')
    if [ -z "$tunnels" ]; then
        fmt_step 1 1 "Enumerate kernel WireGuard interfaces"
        fmt_ok "No WireGuard tunnel is present; nothing to compare"
        return
    fi

    count=$(printf '%s\n' "$tunnels" | "$WC" -l)
    index=0
    while read -r iface; do
        [ -n "$iface" ] || continue
        index=$((index + 1))
        fmt_step "$index" "$count" "Compare $iface against its outer endpoint route"

        if ! tun_mtu=$(mtu_read_link "$iface"); then
            fmt_err "Cannot read the configured MTU of $iface"
            overall=1
            continue
        fi
        fmt_info "Tunnel MTU: $tun_mtu"

        fwmark=$(mtu_tunnel_fwmark "$iface") || fwmark=''
        [ -n "$fwmark" ] && fmt_info "Peer routing evaluated with WireGuard fwmark $fwmark"

        # Peers without a known endpoint are kept in this list on purpose. If
        # they were filtered out here, an unevaluable peer would disappear and
        # a second, healthy peer could still produce a green verdict.
        endpoints=$("$WG" show "$iface" endpoints 2>/dev/null | "$AWK" '{print $2}')
        if [ -z "$endpoints" ]; then
            fmt_err "No peer is configured on $iface; nothing can be evaluated"
            fmt_info "This is indeterminate, not a pass: reconnect the tunnel and re-run"
            overall=1
            continue
        fi

        worst_safe=''
        worst_detail=''
        peers=0
        unresolved=0
        while read -r ep; do
            [ -n "$ep" ] || continue
            peers=$((peers + 1))
            if [ "$ep" = '(none)' ]; then
                fmt_err "Peer $peers has no known endpoint; its outer link is unknown"
                unresolved=$((unresolved + 1))
                continue
            fi
            fam=$(mtu_endpoint_family "$ep")
            host=$(mtu_endpoint_host "$ep")
            lookup=$(mtu_route_lookup "$host" "$fwmark" "$iface")
            lookup_rc=$?
            if [ "$lookup_rc" -ne 0 ]; then
                if [ "$lookup_rc" -eq 2 ]; then
                    fmt_err "Peer $ep routes back through $iface itself"
                    fmt_info "A full-tunnel peer without a usable fwmark exemption cannot"
                    fmt_info "reveal its outer link; the comparison is indeterminate"
                else
                    fmt_err "Peer $ep has no resolvable outer route"
                fi
                unresolved=$((unresolved + 1))
                continue
            fi
            dev=${lookup%% *}
            route_mtu=${lookup##* }
            if ! outer_mtu=$(mtu_read_link "$dev"); then
                fmt_err "Peer $ep resolved to $dev with an unreadable MTU"
                unresolved=$((unresolved + 1))
                continue
            fi
            # A route-scoped MTU is a stricter local ceiling than the device.
            if [ "$route_mtu" -gt 0 ] && [ "$route_mtu" -lt "$outer_mtu" ]; then
                outer_mtu=$route_mtu
                dev="$dev route-mtu"
            fi
            overhead=$(mtu_overhead_for_family "$fam")
            if ! safe=$(mtu_safe_inner "$outer_mtu" "$overhead"); then
                fmt_err "Peer $ep outer MTU $outer_mtu is too small to carry any payload"
                unresolved=$((unresolved + 1))
                continue
            fi
            if [ -z "$worst_safe" ] || [ "$safe" -lt "$worst_safe" ]; then
                worst_safe=$safe
                worst_detail="outer $dev MTU $outer_mtu, $fam endpoint, overhead $overhead"
            fi
        done <<<"$endpoints"

        if [ "$unresolved" -gt 0 ]; then
            fmt_err "$unresolved of $peers peer endpoints could not be evaluated"
            overall=1
        fi
        if [ -z "$worst_safe" ]; then
            fmt_err "No peer endpoint yielded a usable outer link for $iface"
            overall=1
            continue
        fi

        # "Local" is exact: a passive audit sees this host's links and routes.
        # A smaller PMTU further along the path cannot be excluded from here.
        fmt_info "Locally fragmentation-free maximum: $worst_safe ($worst_detail)"
        if [ "$tun_mtu" -le "$worst_safe" ]; then
            if [ "$unresolved" -gt 0 ]; then
                fmt_info "$iface fits every evaluated peer, but the verdict stays open"
            else
                fmt_ok "$iface fits its outer link without local fragmentation"
            fi
            continue
        fi

        fmt_err "$iface exceeds the local maximum by $((tun_mtu - worst_safe)) bytes"
        fmt_info "Effect: outer WireGuard packets fragment; large TLS handshakes"
        fmt_info "        (NTS-KE, package metadata, browser) can stall or fail"
        overall=1
        if [ "$worst_safe" -lt 1280 ]; then
            if ! ipv6_state=$(mtu_tunnel_ipv6_state "$iface"); then
                fmt_err "No correction printed: IPv6 state for $iface is unreadable"
                fmt_info "A sub-1280 MTU is safe only after the tunnel is proven IPv4-only."
                fmt_info "Restore readable WireGuard/link state and re-run the audit."
                continue
            fi
            if [ "$ipv6_state" = yes ]; then
                fmt_err "No safe correction exists for $iface on this outer path"
                fmt_info "The tunnel carries or is configured for IPv6, and RFC 8200"
                fmt_info "section 5 requires a minimum IPv6 link MTU of 1280; the"
                fmt_info "computed maximum is $worst_safe. Lowering the tunnel would"
                fmt_info "break IPv6 instead of fixing the stall. Use a larger outer"
                fmt_info "path, or remove IPv6 from this tunnel first."
                continue
            fi
            if [ "$ipv6_state" = link ]; then
                fmt_info "Only IPv6 link-local state is present on $iface; lowering"
                fmt_info "below 1280 can disable that link-local state, but no global"
                fmt_info "address or IPv6 peer AllowedIP would lose user traffic."
            fi
        fi
        mtu_fix_guidance "$iface" "$worst_safe"
        fmt_info "The activation/route-change reconciler already attempted the"
        fmt_info "same lower-only live correction. An oversized result here means"
        fmt_info "that attempt did not complete or later state changed. Inspect:"
        fmt_info "  journalctl -b -t noid-wireguard-mtu --no-pager"
        fmt_info "This read-only audit does not retry the mutation and never edits"
        fmt_info "or reconnects the provider-owned profile."
    done <<<"$tunnels"
}

audit_wan() {
    local mode unit details expected_enabled expected_active expected_sub
    fmt_banner "WAN-egress-strict audit" "Mode · endpoints · counters · systemd units"
    fmt_note "Read-only: endpoint details are displayed only in this local terminal."

    fmt_step 1 4 "Validate the root-published runtime contract"
    if mode=$(read_runtime_mode); then
        fmt_info "Published mode: $mode"
        if [ "$mode" = "ERROR" ]; then
            fmt_err "The publisher explicitly reports ERROR"
            overall=1
        else
            fmt_ok "Runtime status file has exact ownership, mode and closed schema"
        fi
    else
        mode=UNKNOWN
        fmt_err "Runtime status file is missing, untrusted or malformed"
        overall=1
    fi

    fmt_step 2 4 "Verify cross-layer service/table/flag consistency"
    if [ ! -x "$WAN_TOGGLE" ]; then
        fmt_err "Missing backend: $WAN_TOGGLE"
        overall=1
    else
        root_capture "$WAN_TOGGLE" status
        show_capture "WAN cross-layer status command completed" || :
        if [ "$CMD_RC" -eq 0 ]; then
            if [[ "$CMD_OUTPUT" == *"Layer consistency: exact "* ]]; then
                fmt_ok "Service, nft table and disable flag form an exact postcondition"
            else
                fmt_err "Backend did not report exact layer consistency"
                overall=1
            fi
        fi
    fi

    fmt_step 3 4 "Inspect reconciled endpoints, grace state and live counters"
    if [ ! -x "$WAN_STATUS" ]; then
        fmt_err "Missing backend: $WAN_STATUS"
        overall=1
    else
        root_capture "$WAN_STATUS" status
        show_capture "Full WAN-strict backend status completed" || :
    fi

    fmt_step 4 4 "Inspect persistent services, profile watcher and expiry timer"
    for unit in noid-wan-strict.service \
                noid-wan-strict-status-publish.service \
                noid-wan-strict-scan-profiles.path \
                noid-wan-strict-endpoint-expiry.timer; do
        if ! details=$("$SYSTEMCTL" show "$unit" --no-pager \
                -p LoadState -p UnitFileState -p ActiveState -p SubState -p Result \
                2>&1); then
            printf '%s\n' "$details"
            fmt_err "Could not inspect $unit"
            overall=1
            continue
        fi

        case "$unit:$mode" in
            noid-wan-strict-status-publish.service:*)
                expected_enabled=enabled
                expected_active=inactive
                expected_sub=dead
                ;;
            noid-wan-strict.service:DISABLED)
                expected_enabled=disabled
                expected_active=inactive
                expected_sub=dead
                ;;
            *:DISABLED)
                expected_enabled=disabled
                expected_active=inactive
                expected_sub=dead
                ;;
            noid-wan-strict.service:*)
                expected_enabled=enabled
                expected_active=active
                expected_sub=exited
                ;;
            *)
                expected_enabled=enabled
                expected_active=active
                expected_sub=waiting
                ;;
        esac

        printf '  %s\n%s\n' "$unit" "$details"
        if printf '%s\n' "$details" | "$GREP" -qxF 'LoadState=loaded' \
                && printf '%s\n' "$details" | "$GREP" -qxF \
                    "UnitFileState=$expected_enabled" \
                && printf '%s\n' "$details" | "$GREP" -qxF \
                    "ActiveState=$expected_active" \
                && printf '%s\n' "$details" | "$GREP" -qxF \
                    "SubState=$expected_sub" \
                && printf '%s\n' "$details" | "$GREP" -qxF 'Result=success'; then
            fmt_ok "$unit matches its exact $mode runtime contract"
        else
            fmt_err "$unit differs from its exact $mode runtime contract"
            overall=1
        fi
    done
}

normalize_policy() {
    "$SED" -E '1{s/, active//;s/ \(active\)$//}'
}

normalize_drop_zone() {
    "$SED" -E '1{s/, active//;s/ \(active\)$//};/^[[:space:]]*interfaces:/d'
}

field_value() {
    local key=$1
    "$AWK" -F: -v key="$key" '
        $1 ~ "^[[:space:]]*" key "$" {
            value=substr($0, index($0, ":") + 1)
            sub(/^[[:space:]]+/, "", value)
            print value
            exit
        }'
}

audit_firewall() {
    local policy_runtime='' policy_permanent='' drop_runtime='' drop_permanent=''
    local policy_ok=0 drop_ok=0 runtime_ifaces permanent_ifaces
    fmt_banner "Firewall policy audit" "Runtime · permanent · policy · DROP zone"
    fmt_note "Dynamic runtime interface bindings are reported separately from saved policy."

    fmt_step 1 4 "Verify firewalld daemon and permanent configuration syntax"
    root_capture "$FIREWALL" --state
    show_capture "firewalld daemon reports a healthy running state" || :
    root_capture "$FIREWALL" --check-config
    show_capture "Permanent firewalld configuration passes --check-config" || :

    fmt_step 2 4 "Read block-lan-out in runtime and permanent scopes"
    root_capture "$FIREWALL" --info-policy=block-lan-out
    policy_runtime=$CMD_OUTPUT
    if show_capture "Runtime block-lan-out policy is readable"; then
        policy_ok=$((policy_ok + 1))
    fi
    printf '\n'
    root_capture "$FIREWALL" --permanent --info-policy=block-lan-out
    policy_permanent=$CMD_OUTPUT
    if show_capture "Permanent block-lan-out policy is readable"; then
        policy_ok=$((policy_ok + 1))
    fi

    fmt_step 3 4 "Read DROP zone in runtime and permanent scopes"
    root_capture "$FIREWALL" --info-zone=drop
    drop_runtime=$CMD_OUTPUT
    if show_capture "Runtime DROP zone is readable"; then
        drop_ok=$((drop_ok + 1))
    fi
    printf '\n'
    root_capture "$FIREWALL" --permanent --info-zone=drop
    drop_permanent=$CMD_OUTPUT
    if show_capture "Permanent DROP zone is readable"; then
        drop_ok=$((drop_ok + 1))
    fi

    fmt_step 4 4 "Compare saved policy with the effective runtime semantics"
    if [ "$policy_ok" -eq 2 ]; then
        if [ "$(printf '%s\n' "$policy_runtime" | normalize_policy)" = \
             "$(printf '%s\n' "$policy_permanent" | normalize_policy)" ]; then
            fmt_ok "block-lan-out runtime and permanent policy are identical"
        else
            fmt_err "block-lan-out runtime/permanent configuration drift detected"
            "$DIFF" -u \
                <(printf '%s\n' "$policy_permanent" | normalize_policy) \
                <(printf '%s\n' "$policy_runtime" | normalize_policy) || :
            overall=1
        fi
    else
        fmt_err "Policy parity cannot be proven because one scope was unreadable"
        overall=1
    fi

    if [ "$drop_ok" -eq 2 ]; then
        runtime_ifaces=$(printf '%s\n' "$drop_runtime" | field_value interfaces)
        permanent_ifaces=$(printf '%s\n' "$drop_permanent" | field_value interfaces)
        fmt_info "Runtime interface bindings: ${runtime_ifaces:-none}"
        fmt_info "Permanent interface bindings: ${permanent_ifaces:-none}"
        if [ "$(printf '%s\n' "$drop_runtime" | normalize_drop_zone)" = \
             "$(printf '%s\n' "$drop_permanent" | normalize_drop_zone)" ]; then
            fmt_ok "DROP-zone configuration matches; interface-only delta is expected runtime state"
        else
            fmt_err "DROP-zone configuration drift exists beyond interface bindings"
            "$DIFF" -u \
                <(printf '%s\n' "$drop_permanent" | normalize_drop_zone) \
                <(printf '%s\n' "$drop_runtime" | normalize_drop_zone) || :
            overall=1
        fi
    else
        fmt_err "DROP-zone parity cannot be proven because one scope was unreadable"
        overall=1
    fi
}

nft_summary() {
    # shellcheck disable=SC2016
    "$JQ" -r '
        . as $root
        | ([$root.nftables[] | select(has("table"))] | length) as $tables
        | ([$root.nftables[] | select(has("chain"))] | length) as $chains
        | ([$root.nftables[] | select(has("rule"))] | length) as $rules
        | ([$root.nftables[] | select(has("counter"))] | length) as $counters
        | "tables=\($tables), chains=\($chains), rules=\($rules), named counters=\($counters)"
    '
}

audit_nft() {
    local mode ruleset_json noid_json noid_human noid_counters firewalld_counters
    local topology counters expected_topology expected_counters
    fmt_banner "nftables kernel audit" "Rules · hooks · priorities · named counters"
    fmt_note "Read-only kernel inspection; numeric output avoids resolver/network lookups."

    mode=$(read_runtime_mode 2>/dev/null || printf 'UNKNOWN\n')

    fmt_step 1 4 "Parse the complete in-kernel nftables ruleset as JSON"
    root_capture "$NFT" -n -p -y -j list ruleset
    ruleset_json=$CMD_OUTPUT
    if [ "$CMD_RC" -ne 0 ]; then
        show_capture "Kernel ruleset JSON is readable" || :
    elif ! printf '%s\n' "$ruleset_json" | "$JQ" -e \
            '.nftables | type == "array"' >/dev/null 2>&1; then
        fmt_err "nft returned malformed or unsupported JSON"
        overall=1
    else
        fmt_info "$(printf '%s\n' "$ruleset_json" | nft_summary)"
        fmt_ok "Complete kernel ruleset is structurally valid JSON"
    fi

    fmt_step 2 4 "Inspect the full NoID Privacy WAN-strict table without truncation"
    root_capture "$NFT" -n -p -y list table inet noid_wan_strict
    noid_human=$CMD_OUTPUT
    if [ "$CMD_RC" -ne 0 ]; then
        if [ "$mode" = "DISABLED" ]; then
            fmt_info "NoID Privacy table is absent, matching the explicit DISABLED mode"
        else
            printf '%s\n' "$noid_human"
            fmt_err "NoID Privacy WAN-strict table is absent while mode is $mode"
            overall=1
        fi
        noid_json=
    else
        printf '%s\n' "$noid_human"
        if [ "$mode" = "DISABLED" ]; then
            fmt_err "NoID Privacy table is present despite explicit DISABLED mode"
            overall=1
        else
            fmt_ok "Full inet noid_wan_strict table is readable"
        fi
        root_capture "$NFT" -n -p -y -j list table inet noid_wan_strict
        noid_json=$CMD_OUTPUT
        if [ "$CMD_RC" -ne 0 ] || ! printf '%s\n' "$noid_json" \
                | "$JQ" -e '.nftables | type == "array"' >/dev/null 2>&1; then
            fmt_err "NoID Privacy table JSON could not be validated"
            overall=1
            noid_json=
        fi
    fi

    fmt_step 3 4 "Verify NoID Privacy base-chain hooks, priorities and named counters"
    if [ -z "$noid_json" ]; then
        if [ "$mode" = "DISABLED" ]; then
            fmt_info "Topology check is not applicable while WAN-strict is disabled"
        else
            fmt_err "Topology check unavailable because the NoID Privacy table is unreadable"
            overall=1
        fi
    else
        topology=$(printf '%s\n' "$noid_json" | "$JQ" -r '
            [.nftables[] | .chain?
             | select(. != null)
             | [.name, .type, .hook, (.prio | tostring), .policy]]
            | sort | .[] | @tsv')
        expected_topology=$'forward\tfilter\tforward\t-5\taccept\noutput\tfilter\toutput\t-5\taccept'
        if [ "$topology" = "$expected_topology" ]; then
            fmt_ok "output/forward hooks use the exact filter priority -5 contract"
        else
            fmt_err "NoID Privacy base-chain hook or priority contract differs"
            printf '%s\n' "$topology"
            overall=1
        fi
        counters=$(printf '%s\n' "$noid_json" | "$JQ" -r '
            [.nftables[] | .counter?
             | select(. != null) | .name] | sort | .[]')
        expected_counters=$'wan_blocked_v4\nwan_blocked_v6\nwan_passed_v4\nwan_passed_v6'
        if [ "$counters" = "$expected_counters" ]; then
            fmt_ok "All four closed WAN pass/block counter objects exist"
        else
            fmt_err "NoID Privacy named-counter object set differs"
            printf '%s\n' "$counters"
            overall=1
        fi
        root_capture "$NFT" -n -p -y list counters table inet noid_wan_strict
        noid_counters=$CMD_OUTPUT
        if [ "$CMD_RC" -eq 0 ]; then
            printf '%s\n' "$noid_counters"
            fmt_ok "NoID Privacy live packet/byte counters are readable"
        else
            printf '%s\n' "$noid_counters"
            fmt_err "NoID Privacy counter read failed (exit $CMD_RC)"
            overall=1
        fi
    fi

    fmt_step 4 4 "Inspect every named firewalld counter object"
    root_capture "$NFT" -n -p -y list counters table inet firewalld
    firewalld_counters=$CMD_OUTPUT
    if [ "$CMD_RC" -ne 0 ]; then
        printf '%s\n' "$firewalld_counters"
        fmt_err "firewalld named-counter inspection failed (exit $CMD_RC)"
        overall=1
    elif [ -z "$firewalld_counters" ]; then
        fmt_info "No named firewalld counter objects are present (command succeeded)"
        fmt_ok "firewalld counter-object inspection completed without truncation"
    else
        printf '%s\n' "$firewalld_counters"
        fmt_ok "All named firewalld counter objects were displayed"
    fi
}

case "$#" in
    1)
        MODE=$1
        ;;
    2)
        MODE=$1
        WORKER_MODE=$2
        [ -n "$WORKER_MODE" ] || {
            usage >&2
            exit 2
        }
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac

if [ "$MODE" = "--help" ] || [ "$MODE" = "-h" ]; then
    [ "$#" -eq 1 ] || {
        usage >&2
        exit 2
    }
    usage
    exit 0
fi
case "$MODE" in
    wan|firewall|nft|mtu) ;;
    *)
        usage >&2
        exit 2
        ;;
esac

case "$WORKER_MODE" in
    '')
        ;;
    --root-worker)
        [ "$(/usr/bin/id -u)" -eq 0 ] || {
            fmt_err "The internal audit worker requires root"
            exit 126
        }
        GUI_HOLD=0
        ;;
    --root-worker-gui)
        [ "$(/usr/bin/id -u)" -eq 0 ] || {
            fmt_err "The internal audit worker requires root"
            exit 126
        }
        GUI_HOLD=1
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac

if ! require_binaries; then
    finish 1
    exit $?
fi
if ! validate_self; then
    fmt_err "Installed audit worker path or metadata is unsafe"
    finish 1
    exit $?
fi

if [ "$(/usr/bin/id -u)" -ne 0 ]; then
    if ! prepare_admin; then
        finish 1
        exit $?
    fi
    worker_flag=--root-worker
    [ "$GUI_HOLD" = "1" ] && worker_flag=--root-worker-gui
    # One fixed root-owned worker replaces one PAM/logind session per command.
    # PAM session handling stays enabled; the audit does not weaken sudoers.
    exec "$SUDO" -n -- "$SELF" "$MODE" "$worker_flag"
fi
fmt_info "Administrator worker active (all commands remain fixed and read-only)"
if [ "$FORMAT_TRUSTED" -ne 1 ]; then
    fmt_err "Shared formatter metadata is invalid; using the built-in safe fallback"
    overall=1
fi

case "$MODE" in
    wan) audit_wan ;;
    firewall) audit_firewall ;;
    nft) audit_nft ;;
    mtu) audit_mtu ;;
esac

finish "$overall"
exit $?
NOID_NETWORK_AUDIT_EOF
bash -n "$AUDIT_CANDIDATE" \
    || fail "noid-network-audit candidate has invalid Bash syntax"
bash "$AUDIT_CANDIDATE" --help | grep -q '^Usage: noid-network-audit' \
    || fail "noid-network-audit candidate help smoke failed"
publish_root_file "$AUDIT_CANDIDATE" /usr/local/bin/noid-network-audit 0755
log "STEP 2: /usr/local/bin/noid-network-audit deployed (closed read-only modes)"

# ---------------------------------------------------------------------------
# STEP 3: Deploy /usr/share/applications/noid-network.desktop
# ---------------------------------------------------------------------------

cat > "$DESKTOP_CANDIDATE" <<'NOID_NETWORK_DESKTOP_EOF'
[Desktop Entry]
Version=1.0
Type=Application
Name=NoID Privacy Network
GenericName=Network Privacy Manager
Comment=Manage WAN, LAN and DNS privacy policy with verified local state
Exec=/usr/local/bin/noid-network
Icon=noid-privacy-network
StartupWMClass=com.noidprivacy.Network
StartupNotify=true
Categories=Settings;Security;
Terminal=false
Keywords=NoID Privacy;Privacy;Network;VPN;WAN;LAN;DNS;DoT;Firewall;Strict;
NOID_NETWORK_DESKTOP_EOF
[ -x /usr/bin/desktop-file-validate ] \
    || fail "desktop-file-validate missing — desktop-file-utils is required"
/usr/bin/desktop-file-validate "$DESKTOP_CANDIDATE" \
    || fail "noid-network.desktop candidate validation failed"
publish_root_file "$DESKTOP_CANDIDATE" \
    /usr/share/applications/noid-network.desktop 0644
log "STEP 3: /usr/share/applications/noid-network.desktop deployed"

# ---------------------------------------------------------------------------
# STEP 4: Verify
# ---------------------------------------------------------------------------

log "STEP 4: Module 36 verify"
ver_ok=0
ver_fail=0
if [ -f /usr/local/bin/noid-network ] \
        && [ ! -L /usr/local/bin/noid-network ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' /usr/local/bin/noid-network)" = "0:0:755:1" ] \
        && cmp -s -- "$NETWORK_CANDIDATE" /usr/local/bin/noid-network \
        && /usr/sbin/matchpathcon -V /usr/local/bin/noid-network >/dev/null; then
    log "  ✓ /usr/local/bin/noid-network exact bytes, metadata and label"
    ver_ok=$((ver_ok + 1))
else
    log "  ✗ noid-network bytes/metadata/label verification failed"
    ver_fail=$((ver_fail + 1))
fi
if python3 -c "import ast; ast.parse(open('/usr/local/bin/noid-network').read())" 2>/dev/null; then
    log "  ✓ noid-network Python syntax valid"
    ver_ok=$((ver_ok + 1))
else
    log "  ✗ noid-network Python syntax ERROR"
    ver_fail=$((ver_fail + 1))
fi
if [ -f /usr/lib/noid-privacy/noid_ui.py ] \
        && grep -q '^import noid_ui$' /usr/local/bin/noid-network \
        && /usr/local/bin/noid-network --help 2>/dev/null \
            | grep -q '^  noid-network'; then
    log "  ✓ noid-network imports and --help executes"
    ver_ok=$((ver_ok + 1))
else
    log "  ✗ noid-network import/--help smoke test failed"
    ver_fail=$((ver_fail + 1))
fi
if [ -f /usr/local/bin/noid-network-audit ] \
        && [ ! -L /usr/local/bin/noid-network-audit ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' /usr/local/bin/noid-network-audit)" = "0:0:755:1" ] \
        && cmp -s -- "$AUDIT_CANDIDATE" /usr/local/bin/noid-network-audit \
        && /usr/sbin/matchpathcon -V /usr/local/bin/noid-network-audit >/dev/null \
        && bash -n /usr/local/bin/noid-network-audit \
        && /usr/local/bin/noid-network-audit --help 2>/dev/null \
            | grep -q '^Usage: noid-network-audit'; then
    log "  ✓ noid-network-audit exact executable, syntax and help smoke valid"
    ver_ok=$((ver_ok + 1))
else
    log "  ✗ noid-network-audit deployment/syntax/help verification failed"
    ver_fail=$((ver_fail + 1))
fi
verify_backend_trust() {
    local backend=$1 canonical=$2
    [ -f "$backend" ] && [ ! -L "$backend" ] && [ ! -L "$canonical" ] \
        && [ -x "$backend" ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' -- "$backend" 2>/dev/null || true)" = \
             0:0:755:1 ] \
        && [ "$(readlink -e -- "$backend" 2>/dev/null || true)" = \
             "$canonical" ] \
        && [ "$backend" -ef "$canonical" ] \
        && /usr/sbin/matchpathcon -V "$backend" >/dev/null
}

backend_fail=0
# Fedora 44's filesystem package deliberately owns /usr/local/sbin as the
# relative symlink "bin". Bind that exact alias before accepting the public
# administrator paths; arbitrary parent redirects remain fail-closed.
if [ ! -L /usr/local/sbin ] \
   || [ "$(readlink -- /usr/local/sbin 2>/dev/null || true)" != bin ] \
   || [ "$(readlink -e -- /usr/local/sbin 2>/dev/null || true)" != \
        /usr/local/bin ]; then
    log "  ✗ Fedora unified local-sbin alias trust contract failed"
    backend_fail=1
fi
while IFS='|' read -r backend canonical; do
    if ! verify_backend_trust "$backend" "$canonical"; then
        log "  ✗ backend trust contract failed: $backend"
        backend_fail=1
    fi
done <<'NOID_M36_BACKEND_PATHS_EOF'
/usr/local/sbin/noid-toggle-wan-strict|/usr/local/bin/noid-toggle-wan-strict
/usr/local/sbin/noid-wan-strict|/usr/local/bin/noid-wan-strict
/usr/local/bin/noid-lan-allow|/usr/local/bin/noid-lan-allow
/usr/local/sbin/noid-dns-mode|/usr/local/bin/noid-dns-mode
/usr/local/sbin/noid-arp-hardening.sh|/usr/local/bin/noid-arp-hardening.sh
NOID_M36_BACKEND_PATHS_EOF
if [ "$backend_fail" -eq 0 ]; then
    log "  ✓ all five privileged backends have exact metadata, canonical aliases and labels"
    ver_ok=$((ver_ok + 1))
else
    ver_fail=$((ver_fail + 1))
fi
if [ -f /usr/share/applications/noid-network.desktop ] \
        && [ ! -L /usr/share/applications/noid-network.desktop ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' /usr/share/applications/noid-network.desktop)" = "0:0:644:1" ] \
        && cmp -s -- "$DESKTOP_CANDIDATE" \
            /usr/share/applications/noid-network.desktop \
        && /usr/sbin/matchpathcon -V \
            /usr/share/applications/noid-network.desktop >/dev/null; then
    log "  ✓ noid-network.desktop exact bytes, metadata and label"
    ver_ok=$((ver_ok + 1))
else
    log "  ✗ noid-network.desktop bytes/metadata/label verification failed"
    ver_fail=$((ver_fail + 1))
fi
if /usr/bin/desktop-file-validate \
        /usr/share/applications/noid-network.desktop 2>/dev/null; then
    log "  ✓ noid-network.desktop validates"
    ver_ok=$((ver_ok + 1))
else
    log "  ✗ noid-network.desktop validation FAIL"
    ver_fail=$((ver_fail + 1))
fi

# Module 36 health-stamp (shell-sourceable key=value; M99
# EXPECTED_STAMPS verifies presence at finalize).
if [ "$ver_fail" -eq 0 ]; then
# M36_HEALTH_PUBLICATION_BEGIN
    if [ ! -d "$STAMP_DIR" ] || [ -L "$STAMP_DIR" ] \
       || [ "$(stat -Lc '%u:%g:%a' -- "$STAMP_DIR" 2>/dev/null || true)" != \
            0:0:755 ] \
       || ! /usr/sbin/matchpathcon -V "$STAMP_DIR" >/dev/null; then
        fail "shared health-stamp directory drifted before Module 36 publication"
    fi
    verify_m36_health_stamp() {
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
            && grep -qFx '# NoID Privacy — Module 36 Health Stamp' "$path" \
            && grep -qFx \
                '# Written at end of %post verification when all checks pass.' \
                "$path" \
            && grep -qFx \
                '# Format: shell-sourceable key=value. See docs/engineering-health-stamp-pattern.md.' \
                "$path" \
            && grep -qFx 'module=36' "$path" \
            && grep -qFx 'name=noid-network-app' "$path" \
            && grep -qFx 'version=1' "$path" \
            && grep -qFx 'status=ok' "$path" \
            && grep -Eq \
                '^timestamp=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' \
                "$path" \
            && grep -qFx "checks_passed=${ver_ok}" "$path" \
            && grep -qFx "checks_total=$((ver_ok + ver_fail))" "$path"
    }
    STAMP_CANDIDATE=$(mktemp \
        "$STAMP_DIR/.stamp-36-noid-network.ok.XXXXXXXX") \
        || fail "cannot create Module 36 health-stamp candidate"
    cat > "$STAMP_CANDIDATE" <<STAMP_EOF
# NoID Privacy — Module 36 Health Stamp
# Written at end of %post verification when all checks pass.
# Format: shell-sourceable key=value. See docs/engineering-health-stamp-pattern.md.
module=36
name=noid-network-app
version=1
status=ok
timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
checks_passed=${ver_ok}
checks_total=$((ver_ok + ver_fail))
STAMP_EOF
    chown root:root -- "$STAMP_CANDIDATE"
    chmod 0644 -- "$STAMP_CANDIDATE"
    /usr/sbin/restorecon -F -- "$STAMP_CANDIDATE" \
        || fail "cannot label Module 36 health-stamp candidate"
    /usr/sbin/matchpathcon -V "$STAMP_CANDIDATE" >/dev/null \
        || fail "Module 36 health-stamp candidate label differs"
    verify_m36_health_stamp "$STAMP_CANDIDATE" \
        || fail "staged Module 36 health-stamp contract is invalid"
    sync -- "$STAMP_CANDIDATE" \
        || fail "cannot sync Module 36 health-stamp candidate"
    STAMP_PUBLICATION_ACTIVE=1
    publish_root_file "$STAMP_CANDIDATE" "$STAMP" 0644
    /usr/sbin/matchpathcon -V "$STAMP" >/dev/null \
        || fail "published Module 36 health-stamp label differs"
    sync -- "$STAMP" \
        || fail "cannot sync published Module 36 health stamp"
    sync -- "$STAMP_DIR" \
        || fail "cannot sync Module 36 health-stamp directory"
    verify_m36_health_stamp "$STAMP" \
        || fail "published Module 36 health-stamp contract is invalid"
    rm -f -- "$STAMP_CANDIDATE"
    STAMP_CANDIDATE=""
    STAMP_PUBLICATION_ACTIVE=0
    log "  ✓ exact M36 health stamp published atomically: $STAMP"
# M36_HEALTH_PUBLICATION_END
else
    log "  ✗ M36 verification FAILED ($ver_fail failures) — no health stamp"
    exit 1
fi

log "=== Module 36 complete: NoID Privacy Network App installed ==="

%end

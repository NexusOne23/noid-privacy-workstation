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

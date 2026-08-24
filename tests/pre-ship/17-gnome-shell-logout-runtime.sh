#!/usr/bin/env bash
# F284 gate: bracket three real installed-system logout/re-login transitions.
# Run prepare, log out normally and log in again, then run verify.
set -euo pipefail

TEST_NAME=17-gnome-shell-logout-runtime
PASS_ID=${1:-}
CYCLE=${2:-}
PHASE=${3:-}
case "$PASS_ID:$CYCLE:$PHASE" in
    fresh-install:1:prepare|fresh-install:1:verify|fresh-install:2:prepare|fresh-install:2:verify|reboot:1:prepare|reboot:1:verify) ;;
    *)
        echo "Usage: sudo bash $0 {fresh-install 1|fresh-install 2|reboot 1} {prepare|verify}" >&2
        exit 2
        ;;
esac

fail() { echo "FAIL  $TEST_NAME [$PASS_ID/$CYCLE/$PHASE]: $*" >&2; exit 1; }
pass() { echo "PASS  $TEST_NAME [$PASS_ID/$CYCLE/$PHASE]: $*"; }

[[ $EUID -eq 0 ]] || fail "run through sudo from the normal GNOME user"
TEST_UID=${SUDO_UID:-}
[[ $TEST_UID =~ ^[1-9][0-9]*$ ]] || fail "SUDO_UID does not identify the normal graphical user"
grep -q '^ID=noid-privacy-workstation$' /etc/os-release 2>/dev/null || fail "not running inside the NoID Privacy candidate"
for command_name in awk ausearch journalctl loginctl mktemp python3 readlink sed stat systemctl tail; do
    command -v "$command_name" >/dev/null 2>&1 || fail "required command missing: $command_name"
done

select_session() {
    local candidate class type remote active state
    local -a matches=()
    while read -r candidate _; do
        [[ -n $candidate ]] || continue
        class=$(loginctl show-session "$candidate" -p Class --value 2>/dev/null) || continue
        type=$(loginctl show-session "$candidate" -p Type --value 2>/dev/null) || continue
        remote=$(loginctl show-session "$candidate" -p Remote --value 2>/dev/null) || continue
        active=$(loginctl show-session "$candidate" -p Active --value 2>/dev/null) || continue
        state=$(loginctl show-session "$candidate" -p State --value 2>/dev/null) || continue
        [[ $class == user && $type =~ ^(wayland|x11)$ && $remote == no && $active == yes && $state == active ]] || continue
        matches+=("$candidate")
    done < <(loginctl list-sessions --no-legend 2>/dev/null | awk -v uid="$TEST_UID" '$2 == uid {print $1, $2}')
    [[ ${#matches[@]} -eq 1 ]] || fail "expected one active local graphical Class=user session, found ${#matches[@]}"
    printf '%s\n' "${matches[0]}"
}

shell_property() {
    systemctl --user --machine="$TEST_UID@" show org.gnome.Shell@user.service -p "$1" --value 2>/dev/null
}

audit_shell_abends() {
    local output rc
    set +e
    output=$(ausearch -m ANOM_ABEND --start boot --raw 2>/dev/null)
    rc=$?
    set -e
    [[ $rc -eq 0 || $rc -eq 1 ]] || fail "ausearch could not read current-boot anomalies"
    awk 'index($0, "exe=\"/usr/bin/gnome-shell\"") { count++ } END { print count + 0 }' <<<"$output"
}

state_dir=/run/noid-privacy
[[ -d $state_dir && ! -L $state_dir ]] || \
    fail "shared NoID Privacy runtime directory is missing, non-directory or symlinked"
[[ $(stat -c '%U:%G:%a' "$state_dir") == root:root:755 ]] || \
    fail "shared NoID Privacy runtime directory metadata differs"
marker=$state_dir/noid-f284-shell-${PASS_ID}-${CYCLE}.state
boot_id=$(< /proc/sys/kernel/random/boot_id)
session_id=$(select_session)
main_pid=$(shell_property MainPID) || fail "could not query GNOME Shell MainPID"
[[ $main_pid =~ ^[1-9][0-9]*$ && -r /proc/$main_pid/exe ]] || fail "GNOME Shell MainPID is not live"
[[ $(readlink -e "/proc/$main_pid/exe") == /usr/bin/gnome-shell ]] || fail "GNOME Shell MainPID executable differs"

if [[ $PHASE == prepare ]]; then
    [[ ! -e $marker && ! -L $marker ]] || fail "cycle marker already exists"
    [[ $(shell_property ActiveState) == active ]] || fail "GNOME Shell unit is not active"
    [[ $(shell_property SubState) == running ]] || fail "GNOME Shell unit is not running"
    [[ $(loginctl show-session "$session_id" -p LockedHint --value 2>/dev/null) == no ]] || \
        fail "graphical session is locked; unlock it before bracketing a normal UI logout"
    cursor=$(journalctl -b -n 1 --show-cursor --no-pager 2>/dev/null |
        sed -n 's/^-- cursor: //p' | tail -n 1)
    [[ -n $cursor ]] || fail "could not capture the current journal cursor"
    audit_count=$(audit_shell_abends)
    [[ $audit_count =~ ^[0-9]+$ ]] || fail "invalid audit anomaly baseline"
    umask 077
    printf 'boot=%s\nsession=%s\nshell_pid=%s\naudit_count=%s\ncursor=%s\n' "$boot_id" "$session_id" "$main_pid" "$audit_count" "$cursor" >"$marker"
    [[ $(stat -c '%u:%g:%a:%h' "$marker") == 0:0:600:1 ]] || \
        fail "cycle marker metadata invalid"
    pass "unlocked transition baseline sealed; log out now from inside this session — GNOME's Log Out entry, or gnome-session-quit --logout --no-prompt where GNOME hides it — then log in again"
    exit 0
fi

[[ -f $marker && ! -L $marker \
   && $(stat -c '%u:%g:%a:%h' "$marker") == 0:0:600:1 ]] || \
    fail "safe prepare marker is missing"
old_boot=$(sed -n 's/^boot=//p' "$marker")
old_session=$(sed -n 's/^session=//p' "$marker")
old_pid=$(sed -n 's/^shell_pid=//p' "$marker")
old_audit_count=$(sed -n 's/^audit_count=//p' "$marker")
cursor=$(sed -n 's/^cursor=//p' "$marker")
[[ $old_boot == "$boot_id" ]] || fail "verification is not in the prepared boot"
[[ $old_session != "$session_id" ]] || fail "no new graphical session was observed"
[[ $old_pid =~ ^[1-9][0-9]*$ && $old_pid != "$main_pid" ]] || fail "GNOME Shell PID did not change across logout"
[[ $old_audit_count =~ ^[0-9]+$ && -n $cursor ]] || fail "prepare marker is malformed"

[[ $(shell_property ActiveState) == active ]] || fail "new GNOME Shell unit is not active"
[[ $(shell_property SubState) == running ]] || fail "new GNOME Shell unit is not running"
[[ $(shell_property Result) == success ]] || fail "new GNOME Shell unit result is not success"
[[ $(shell_property ExecMainStatus) == 0 ]] || fail "new GNOME Shell exit status is not zero"

journal_file=$(mktemp -p /var/tmp noid-f284-journal.XXXXXX)
trap 'rm -f -- "$journal_file"' EXIT
journalctl -b --after-cursor="$cursor" -o json --no-pager >"$journal_file" 2>/dev/null || fail "could not read the bracketed transition journal"
if ! python3 - "$journal_file" "$old_pid" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
old_pid = sys.argv[2]
shutdown_seen = False
bad = []
needles = (
    "incorrect pop",
    "status=11/segv",
    "code=dumped",
    "core-dump",
    "general protection fault",
    "segfault",
    "signal 11",
    "anom_abend",
)
for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
    try:
        row = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"journal JSON line {number} is invalid: {exc}")
    message = str(row.get("MESSAGE", ""))
    exe = str(row.get("_EXE", ""))
    comm = str(row.get("_COMM", ""))
    user_unit = str(row.get("_SYSTEMD_USER_UNIT", ""))
    related = (
        exe == "/usr/bin/gnome-shell"
        or comm == "gnome-shell"
        or user_unit == "org.gnome.Shell@user.service"
        or "gnome-shell" in message.lower()
        or "org.gnome.Shell@user.service" in message
        or f"gnome-shell[{old_pid}]" in message
    )
    if exe == "/usr/bin/gnome-shell" and message.endswith("Shutting down GNOME Shell"):
        shutdown_seen = True
    lowered = message.lower()
    if related and any(needle in lowered for needle in needles):
        bad.append(f"line {number}: {message}")
if not shutdown_seen:
    raise SystemExit("old Shell did not record normal shutdown")
if bad:
    raise SystemExit("native/precursor failure in transition: " + " | ".join(bad[:8]))
PY
then
    fail "transition journal contains a GNOME Shell crash or its F284 precursor"
fi

new_audit_count=$(audit_shell_abends)
[[ $new_audit_count == "$old_audit_count" ]] || fail "GNOME Shell ANOM_ABEND count changed: $old_audit_count -> $new_audit_count"
rm -f -- "$marker"
trap - EXIT
rm -f -- "$journal_file"
pass "normal Shell shutdown, new healthy session and unchanged native-crash evidence proved"

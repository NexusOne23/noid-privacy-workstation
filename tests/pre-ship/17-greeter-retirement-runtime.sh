#!/usr/bin/env bash
# Release gate for clean pre-user GNOME Shell retirement. Run after the normal
# graphical user has logged in. The Live automatic-login path may correctly
# bypass a pre-user Shell; in that case the gate binds the exact active user
# Shell and still rejects native-crash evidence. A Fedora first installed boot
# may use the exact org.gnome.Shell@initial-setup.service instead of the
# ordinary org.gnome.Shell@gdm.service; later boots must use GDM. The reboot
# pass also audits the preceding normal reboot, which catches shutdown-only
# crashes after the pre-user session has disappeared.
set -euo pipefail
export LC_ALL=C

TEST_NAME=17-greeter-retirement-runtime
PASS_ID=${1:-}
case "$PASS_ID" in
    live|fresh-install) BOOTS=(0) ;;
    reboot) BOOTS=(-1 0) ;;
    *)
        echo "Usage: sudo bash $0 {live|fresh-install|reboot}" >&2
        exit 2
        ;;
esac

fail() {
    echo "FAIL  $TEST_NAME [$PASS_ID]: $*" >&2
    exit 1
}
pass() {
    echo "PASS  $TEST_NAME [$PASS_ID]: $*"
}

[[ $EUID -eq 0 ]] || fail "run as root after the normal graphical login"
grep -q '^ID=noid-privacy-workstation$' /etc/os-release 2>/dev/null || \
    fail "not running inside the NoID Privacy candidate"
if [[ $PASS_ID == live ]]; then
    grep -qw 'rd.live.image' /proc/cmdline || \
        fail "live pass is not running from Live media"
    liveuser_record=$(getent passwd liveuser) || \
        fail "Live automatic-login account is absent"
    [[ $liveuser_record == liveuser:*:/home/liveuser:* ]] || \
        fail "Live automatic-login account identity is invalid"
    grep -qxF 'AutomaticLoginEnable=true' /etc/gdm/custom.conf || \
        fail "Live GDM automatic login is not enabled"
    grep -qxF 'AutomaticLogin=liveuser' /etc/gdm/custom.conf || \
        fail "Live GDM automatic-login target differs"
fi
for command_name in getent journalctl mktemp python3 stat; do
    command -v "$command_name" >/dev/null 2>&1 || \
        fail "required command missing: $command_name"
done

gdm_record=$(getent passwd gdm) || fail "GDM account is absent"
[[ -n $gdm_record && $gdm_record != *$'\n'* ]] || \
    fail "GDM account lookup is ambiguous"
IFS=: read -r gdm_name _ gdm_uid _ _ _ _ <<<"$gdm_record"
[[ $gdm_name == gdm && $gdm_uid =~ ^[1-9][0-9]*$ ]] || \
    fail "GDM account identity is invalid"

tmp_dir=$(mktemp -d /var/tmp/noid-greeter-retirement.XXXXXXXX)
trap 'rm -rf -- "$tmp_dir"' EXIT
[[ -d $tmp_dir && ! -L $tmp_dir ]] || fail "temporary evidence directory is unsafe"
# Owner and mode are the security properties here. A directory link count is
# not: Btrfs reports 1 for an empty directory, tmpfs and a fresh overlayfs upper
# directory report 2, so pinning it made the Live pass unpassable by
# construction. Directories cannot be hard-linked, and mktemp -d already
# guarantees exclusive creation.
[[ $(stat -c '%u:%a' "$tmp_dir") == 0:700 ]] || \
    fail "temporary evidence directory metadata differs"

append_journal_query() {
    local rc=0
    journalctl "$@" >>"$journal_file" 2>/dev/null || rc=$?
    case "$rc" in
        0|1) ;;
        *) fail "journal query failed for $boot_label boot (rc=$rc)" ;;
    esac
}

for boot in "${BOOTS[@]}"; do
    boot_label=current
    [[ $boot == 0 ]] || boot_label=previous
    journal_file=$tmp_dir/$boot_label.json
    : >"$journal_file"
    # Use indexed journal fields for the two exact Fedora pre-user Shell units.
    # Both GDM and Initial Setup use transient UIDs, so bind user-manager
    # records to systemd's stable identifier plus the exact unit name instead
    # of the static gdm account UID. The parser below permits Initial Setup
    # only on the first installed boot. Add only the two native-crash record
    # classes from broader audit/kernel streams; do not export an entire
    # long-lived system journal.
    for pre_user_unit in \
        org.gnome.Shell@gdm.service \
        org.gnome.Shell@initial-setup.service; do
        append_journal_query -b "$boot" -o json --no-pager \
            "_SYSTEMD_USER_UNIT=$pre_user_unit"
    done
    # GDM's exact Live automatic-login path can enter the liveuser session
    # without creating a pre-user Shell. Retain the active Shell rows only in
    # that lifecycle so the parser can distinguish that native path from
    # missing journal evidence and still reject a crash/restart.
    if [[ $PASS_ID == live && $boot == 0 ]]; then
        append_journal_query -b "$boot" -o json --no-pager \
            '_SYSTEMD_USER_UNIT=org.gnome.Shell@user.service'
    fi
    append_journal_query -b "$boot" -o json --no-pager \
        SYSLOG_IDENTIFIER=systemd \
        --grep='org\.gnome\.Shell@(gdm|initial-setup)\.service'
    append_journal_query -b "$boot" -o json --no-pager \
        _TRANSPORT=audit --grep='ANOM_ABEND.*gnome-shell'
    append_journal_query -b "$boot" -o json --no-pager \
        _TRANSPORT=kernel --grep='gnome-shell.*segfault'
    [[ -s $journal_file && ! -L $journal_file ]] || \
        fail "$boot_label boot journal evidence is empty or unsafe"

    if ! python3 - "$journal_file" "$boot_label" "$PASS_ID" <<'PY'
import json
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
boot_label = sys.argv[2]
pass_id = sys.argv[3]
bad = []
rows = []
gdm_unit = "org.gnome.Shell@gdm.service"
initial_setup_unit = "org.gnome.Shell@initial-setup.service"
queried_units = {gdm_unit, initial_setup_unit}
active_user_unit = "org.gnome.Shell@user.service"
allowed_units = {gdm_unit}
if pass_id == "fresh-install" or (
        pass_id == "reboot" and boot_label == "previous"):
    allowed_units.add(initial_setup_unit)
needles = (
    "status=11/segv",
    "failed with result 'core-dump'",
    'failed with result "core-dump"',
    "code=dumped",
    "segfault at",
    "signal 11",
    "sig=11",
    "anom_abend",
)

for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
    try:
        row = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{boot_label} journal JSON line {number} is invalid: {exc}")
    rows.append((number, row))

observed_units = {
    str(row.get("_SYSTEMD_USER_UNIT", ""))
    for _, row in rows
    if str(row.get("_SYSTEMD_USER_UNIT", "")) in queried_units
}
unexpected_units = observed_units - allowed_units
if unexpected_units:
    raise SystemExit(
        f"{boot_label} boot contains an unexpected pre-user Shell unit: "
        + ", ".join(sorted(unexpected_units))
    )
if not observed_units:
    if pass_id != "live" or boot_label != "current":
        raise SystemExit(f"{boot_label} boot has no pre-user Shell unit evidence")
    live_rows = [
        (number, row)
        for number, row in rows
        if str(row.get("_SYSTEMD_USER_UNIT", "")) == active_user_unit
    ]
    if not live_rows:
        raise SystemExit(
            f"{boot_label} Live boot has neither pre-user nor active user Shell evidence")
    live_starts = sum(
        str(row.get("MESSAGE", "")).startswith("Running GNOME Shell")
        for _, row in live_rows
    )
    if live_starts < 1:
        raise SystemExit(
            f"{boot_label} Live boot has no active user Shell start evidence")
    bad = []
    for number, row in rows:
        message = str(row.get("MESSAGE", ""))
        lowered = message.lower()
        user_unit = str(row.get("_SYSTEMD_USER_UNIT", ""))
        if user_unit == active_user_unit and any(
                needle in lowered for needle in needles):
            bad.append(f"line {number}: {message}")
        elif user_unit != active_user_unit and "gnome-shell" in lowered and any(
                needle in lowered for needle in needles):
            bad.append(f"line {number}: {message}")
    if bad:
        raise SystemExit(
            f"{boot_label} Live automatic-login Shell has native-crash evidence: "
            + " | ".join(bad[:8])
        )
    print(
        f"{boot_label}: Live automatic login correctly bypassed the pre-user "
        f"Shell; {active_user_unit}:starts={live_starts} native_crashes=0"
    )
    raise SystemExit(0)

greeter_uids = {
    str(row.get("_UID", ""))
    for _, row in rows
    if str(row.get("_SYSTEMD_USER_UNIT", "")) in observed_units
    and str(row.get("_UID", ""))
}
greeter_pids = {
    str(row.get("_PID", ""))
    for _, row in rows
    if str(row.get("_SYSTEMD_USER_UNIT", "")) in observed_units
    and str(row.get("_PID", ""))
}
if not greeter_uids or not greeter_pids:
    raise SystemExit(f"{boot_label} boot has no greeter UID/PID identity evidence")

for number, row in rows:
    message = str(row.get("MESSAGE", ""))
    lowered = message.lower()
    exe = str(row.get("_EXE", ""))
    uid = str(row.get("_UID", ""))
    user_unit = str(row.get("_SYSTEMD_USER_UNIT", ""))
    exact_shell = (
        user_unit in observed_units
        or any(unit in message for unit in observed_units)
        or (uid in greeter_uids and exe == "/usr/bin/gnome-shell")
        or (
            'comm="gnome-shell"' in message
            and any(
                re.search(
                    rf"(?:^|\s)uid={re.escape(greeter_uid)}(?:\s|$)",
                    message,
                )
                is not None
                for greeter_uid in greeter_uids
            )
        )
        or (
            "gnome-shell" in lowered
            and any(
                re.search(rf"\[{re.escape(greeter_pid)}\]", message)
                is not None
                or re.search(
                    rf"(?:^|\s)pid={re.escape(greeter_pid)}(?:\s|$)",
                    message,
                )
                is not None
                for greeter_pid in greeter_pids
            )
        )
    )
    if exact_shell and any(needle in lowered for needle in needles):
        bad.append(f"line {number}: {message}")

if bad:
    raise SystemExit(
        f"{boot_label} boot contains a pre-user Shell native crash: "
        + " | ".join(bad[:8])
    )

results = []
for unit in sorted(observed_units):
    started = sum(
        str(row.get("_SYSTEMD_USER_UNIT", "")) == unit
        and str(row.get("MESSAGE", "")).startswith("Running GNOME Shell")
        for _, row in rows
    )
    shutdown = sum(
        str(row.get("_SYSTEMD_USER_UNIT", "")) == unit
        and str(row.get("MESSAGE", "")) == "Shutting down GNOME Shell"
        for _, row in rows
    )
    stopped = sum(
        str(row.get("MESSAGE", "")).startswith(
            f"Stopped {unit} - GNOME Shell")
        for _, row in rows
    )
    if started < 1:
        raise SystemExit(
            f"{boot_label} boot has no observed Shell start for {unit}")
    if shutdown < 1:
        raise SystemExit(
            f"{boot_label} boot has no clean Shell shutdown marker for {unit}")
    if stopped < 1:
        raise SystemExit(
            f"{boot_label} boot has no completed Shell unit stop for {unit}")
    results.append(
        f"{unit}:starts={started},shutdowns={shutdown},stops={stopped}")

print(
    f"{boot_label}: {'; '.join(results)} "
    f"greeter_uids={len(greeter_uids)} native_crashes=0"
)
PY
    then
        fail "$boot_label boot did not retire every permitted pre-user Shell cleanly"
    fi
done

pass "${#BOOTS[@]} boot lifecycle(s) have clean pre-user Shell shutdown and zero native-crash evidence"

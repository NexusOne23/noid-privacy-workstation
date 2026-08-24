#!/usr/bin/python3
"""NoID Privacy audit-event notification delivery.

The auditd-hosted plugin (/usr/local/bin/audit-notify.sh) owns event assembly,
filtering, coalescing and rate limiting, but it cannot deliver anything: auditd
execve()s it without a domain transition, so it runs in auditd_t, which holds
no setuid/setgid capability and no access to a user session bus.  It therefore
queues one bounded request per surviving event under /run/noid-privacy and
noid-audit-event-notify.path starts this drain in ordinary init context, where
the session gauntlet and setpriv route below actually work.

This mirrors the split M12 already uses for the audit-storage marker.  The
session gauntlet is the reviewed one moved out of the plugin unchanged: only
the event AUID's own unlocked, active, local, graphical seat is ever notified.
"""

import json
import os
import pathlib
import pwd
import stat
import subprocess
import sys
import syslog


RUNTIME_DIR = pathlib.Path("/run/noid-privacy")
SPOOL_DIR = RUNTIME_DIR / "audit-notify.d"
# One drain handles at most this many requests.  DirectoryNotEmpty= is level
# triggered, so a longer backlog simply restarts this unit instead of letting a
# single invocation run unbounded.
DRAIN_LIMIT = 64
REQUEST_FIELDS = ("serial", "auid", "key", "command", "path")
FIELD_LIMITS = {"key": 64, "command": 64, "path": 512}
# The spool is produced by root (auditd) and consumed by root (this drain).
# Naming the expected owner lets the behavior fixtures exercise the metadata
# predicates without being root; tests/12 pins these two values structurally so
# the seam cannot silently become a weaker check.
TRUSTED_UID = 0
TRUSTED_GID = 0


def sanitize_text(value, limit=512):
    """Bound untrusted audit text and remove UI control characters."""
    if not value or value in {"(null)", "?"}:
        return ""
    cleaned = "".join(
        ch if ch.isprintable() and ch not in "\r\n" else " " for ch in value
    )
    return " ".join(cleaned.split())[:limit]


def _run(command, timeout=3):
    return subprocess.run(
        command,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        env={"PATH": "/usr/sbin:/usr/bin", "LANG": "C.UTF-8"},
    ).stdout


def _properties(session):
    output = _run(
        [
            "/usr/bin/loginctl",
            "show-session",
            session,
            "--property=User",
            "--property=Seat",
            "--property=Remote",
            "--property=Class",
            "--property=Type",
            "--property=State",
            "--property=Active",
            "--property=LockedHint",
        ]
    )
    result = {}
    for line in output.splitlines():
        if "=" in line:
            name, value = line.split("=", 1)
            result[name] = value
    return result


def resolve_local_target(uid):
    """Resolve only the event AUID's unlocked active local graphical seat."""
    sessions = json.loads(
        _run(["/usr/bin/loginctl", "list-sessions", "--json=short"])
    )
    saw_locked = False
    for row in sessions:
        session = str(row.get("session", ""))
        if row.get("uid") != uid or not row.get("seat"):
            continue
        if not session or len(session) > 128 or not all(
            character.isalnum() or character in "_.-" for character in session
        ):
            continue
        properties = _properties(session)
        if properties.get("User") != str(uid):
            continue
        if (
            properties.get("Remote") != "no"
            or properties.get("Class") != "user"
        ):
            continue
        if properties.get("Type") not in {"wayland", "x11"}:
            continue
        if (
            properties.get("Active") != "yes"
            or properties.get("State") != "active"
        ):
            continue
        seat = properties.get("Seat", "")
        if not seat or len(seat) > 128 or not all(
            character.isalnum() or character in "_.-" for character in seat
        ):
            continue
        active_session = _run(
            [
                "/usr/bin/loginctl",
                "show-seat",
                seat,
                "--property=ActiveSession",
                "--value",
            ]
        ).strip()
        if active_session != session:
            continue
        if properties.get("LockedHint") != "no":
            saw_locked = True
            continue

        runtime = pathlib.Path(f"/run/user/{uid}")
        bus = runtime / "bus"
        account = pwd.getpwuid(uid)
        # Inspect the bus AS the target user, not as root. The unit keeps only
        # CAP_SETGID/CAP_SETUID, so this process has no CAP_DAC_OVERRIDE and
        # cannot even traverse the 0700 /run/user/<uid> that user owns -- a
        # root lstat() here fails with EACCES on every real desktop. This is
        # the same route the sibling audit-storage notifier uses. `stat` does
        # not dereference without -L, so a symlink still fails closed, and the
        # explicit LC_ALL keeps the translated %F string out of the compare.
        #
        # The watchdog runs INSIDE setpriv, as the target uid. A Python-side
        # `timeout=` cannot police this child: on expiry CPython calls
        # os.kill(SIGKILL), and this process is uid 0 with a bounding set of
        # only CAP_SETGID/CAP_SETUID -- no CAP_KILL -- so signalling a child
        # that already dropped to another uid raises PermissionError out of
        # Popen.__exit__, which then blocks in an unbounded wait(). Verified on
        # a live host: "SIGKILL -> Operation not permitted", child still alive.
        try:
            bus_status = _run(
                [
                    "/usr/bin/setpriv",
                    f"--reuid={uid}",
                    f"--regid={account.pw_gid}",
                    "--init-groups",
                    "--reset-env",
                    "/usr/bin/timeout",
                    "--signal=TERM",
                    "--kill-after=1s",
                    "3s",
                    "/usr/bin/env",
                    "LC_ALL=C.UTF-8",
                    "/usr/bin/stat",
                    "-c",
                    "%F:%u",
                    str(bus),
                ],
                # Outer backstop only, and deliberately longer than the inner
                # 3s + 1s kill-after: if it fired first it would re-enter the
                # unkillable-child path this construction exists to avoid.
                timeout=10,
            ).strip()
        except subprocess.CalledProcessError as error:
            raise RuntimeError("active-session-bus-invalid") from error
        if bus_status != f"socket:{uid}":
            raise RuntimeError("active-session-bus-invalid")
        return {
            "uid": uid,
            "gid": account.pw_gid,
            "home": account.pw_dir,
            "runtime": str(runtime),
            "bus": str(bus),
        }, "ready"
    return None, "locked" if saw_locked else "no-active-local-session"


def deliver_notification(target, event):
    body = f"Check: sudo ausearch -k {event['key']} -ts recent"
    if event["path"]:
        body = f"{event['path']}\n\n{body}"
    # Same reason as the bus probe above: the watchdog has to be inside setpriv
    # so it runs as the target uid and can signal its own child. GNOME Shell's
    # notification service being wedged is an ordinary desktop condition, and
    # without this the drain hangs there until systemd kills the cgroup at
    # TimeoutStartSec -- which skips the finally: that retires the request, so
    # the level-triggered path unit re-triggers on the same file forever.
    command = [
        "/usr/bin/setpriv",
        f"--reuid={target['uid']}",
        f"--regid={target['gid']}",
        "--init-groups",
        "--reset-env",
        "/usr/bin/timeout",
        "--signal=TERM",
        "--kill-after=1s",
        "5s",
        "/usr/bin/env",
        f"HOME={target['home']}",
        f"XDG_RUNTIME_DIR={target['runtime']}",
        f"DBUS_SESSION_BUS_ADDRESS=unix:path={target['bus']}",
        "/usr/bin/notify-send",
        "--urgency=critical",
        "--icon=dialog-warning",
        "--",
        f"auditd: {event['key']}",
        body,
    ]
    subprocess.run(
        command,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        # Outer backstop only; the inner 5s + 1s kill-after must expire first.
        timeout=12,
        env={"PATH": "/usr/sbin:/usr/bin", "LANG": "C.UTF-8"},
    )


def spool_is_trusted():
    """Refuse to drain anything but a root-owned private directory."""
    try:
        status = SPOOL_DIR.lstat()
    except FileNotFoundError:
        return None
    return (
        stat.S_ISDIR(status.st_mode)
        and status.st_uid == TRUSTED_UID
        and status.st_gid == TRUSTED_GID
        and stat.S_IMODE(status.st_mode) == 0o700
    )


def read_request(path):
    """Parse one spool entry, or raise ValueError if it is not exact."""
    status = path.lstat()
    if (
        not stat.S_ISREG(status.st_mode)
        or status.st_uid != TRUSTED_UID
        or status.st_gid != TRUSTED_GID
        or stat.S_IMODE(status.st_mode) != 0o600
        or status.st_nlink != 1
    ):
        raise ValueError("request metadata is not root-owned private regular")
    fields = {}
    with path.open("r", encoding="utf-8") as stream:
        for line in stream.read(8192).splitlines():
            name, separator, value = line.partition("=")
            if not separator or name not in REQUEST_FIELDS or name in fields:
                raise ValueError("request carries an unexpected field")
            fields[name] = value
    if set(fields) != set(REQUEST_FIELDS):
        raise ValueError("request is missing a mandatory field")
    for name in ("serial", "auid"):
        if not fields[name].isdigit():
            raise ValueError(f"{name} is not a plain decimal number")
        fields[name] = int(fields[name], 10)
    if fields["auid"] < 1000 or fields["auid"] > 4294967294:
        raise ValueError("auid is outside the notifiable range")
    for name, limit in FIELD_LIMITS.items():
        fields[name] = sanitize_text(fields[name], limit)
    if not fields["key"]:
        raise ValueError("request carries no audit key")
    return fields


def retire_request(path):
    """Retire one handled entry without aborting the rest of the drain."""
    try:
        path.unlink(missing_ok=True)
    except OSError as error:
        # A directory or otherwise unremovable entry is not traversed or
        # recursively deleted.  Keep processing valid requests and leave a
        # precise alert for the operator instead of raising out of an except or
        # finally suite and abandoning the whole spool.
        syslog.syslog(
            syslog.LOG_ALERT,
            "audit notification request retirement failed "
            f"({type(error).__name__})",
        )
        return False
    return True


def main():
    if len(sys.argv) != 1:
        print(
            "ERROR: noid-audit-event-notify accepts no arguments",
            file=sys.stderr,
        )
        return 2
    syslog.openlog("noid-audit-event-notify", syslog.LOG_PID, syslog.LOG_AUTH)
    trusted = spool_is_trusted()
    if trusted is None:
        return 0
    if not trusted:
        # Deliberately leave an untrusted directory untouched: consuming or
        # deleting attacker-controlled entries would turn this closed metadata
        # gate into traversal.  The producer no longer recreates missing parent
        # directories, so this state requires external metadata drift and is
        # surfaced by both this nonzero unit and its LOG_ALERT.
        syslog.syslog(
            syslog.LOG_ALERT,
            f"refusing unsafe audit notification spool metadata: {SPOOL_DIR}",
        )
        return 1
    failed = 0
    for name in sorted(os.listdir(SPOOL_DIR))[:DRAIN_LIMIT]:
        entry = SPOOL_DIR / name
        try:
            event = read_request(entry)
        except (OSError, ValueError, UnicodeDecodeError) as error:
            syslog.syslog(
                syslog.LOG_ALERT,
                f"discarding malformed audit notification request: {error}",
            )
            failed = 1
            if not retire_request(entry):
                failed = 1
            continue
        try:
            target, reason = resolve_local_target(event["auid"])
            if target is None:
                syslog.syslog(
                    syslog.LOG_INFO,
                    f"audit notification not delivered ({reason}): "
                    f"key={event['key']} auid={event['auid']}",
                )
            else:
                deliver_notification(target, event)
        except (
            OSError,
            KeyError,
            ValueError,
            RuntimeError,
            subprocess.SubprocessError,
        ) as error:
            syslog.syslog(
                syslog.LOG_ALERT,
                "audit notification delivery failed "
                f"({type(error).__name__}): key={event['key']} "
                f"auid={event['auid']}",
            )
            failed = 1
        finally:
            # Always retire the request. DirectoryNotEmpty= re-triggers this
            # unit while anything remains, so a retained entry would spin the
            # notifier instead of surfacing the failure the syslog line above
            # already records.
            if not retire_request(entry):
                failed = 1
    return failed


if __name__ == "__main__":
    raise SystemExit(main())

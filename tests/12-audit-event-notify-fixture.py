#!/usr/bin/python3
"""Behavior fixtures for the M12 audit-event notification drain.

The auditd-hosted plugin cannot deliver: it runs in auditd_t, which holds no
setuid/setgid capability and cannot reach a session_dbusd_tmp_t session bus.
This drain owns the session gauntlet and the setpriv/notify-send route, so the
exact-AUID/local-seat and bounded-delivery guarantees are asserted here.
"""

import importlib.machinery
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest import mock

# Loading the repository notifier must never leave host-path-bearing bytecode
# in the public source surface, even when this fixture is invoked directly.
sys.dont_write_bytecode = True


def load_notifier(path):
    loader = importlib.machinery.SourceFileLoader("noid_audit_event_notify", path)
    specification = importlib.util.spec_from_loader(loader.name, loader)
    if specification is None or specification.loader is None:
        raise RuntimeError(f"cannot import notifier: {path}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    # In production both constants are 0 and the drain runs as root; tests/12
    # pins those shipped values structurally. Rebinding them here is what lets
    # an unprivileged run exercise the very metadata predicates that would
    # otherwise be skipped, which is the failure mode this whole change is
    # about.
    assert (module.TRUSTED_UID, module.TRUSTED_GID) == (0, 0)
    module.TRUSTED_UID = os.getuid()
    module.TRUSTED_GID = os.getgid()
    return module


# Session properties per session id, so a stub can discriminate. An earlier
# version returned one fixed block for every id and listed only one non-target
# row that was ALSO seatless -- the seat predicate discarded it before the AUID
# predicate was ever consulted. Mutation testing against the real notifier
# showed the consequence: deleting the uid check, the User check, the
# Remote/Class gate, the Type gate, the seat ActiveSession gate or the
# hardlink check each left this fixture printing PASS.
GOOD = {
    "User": "1000", "Seat": "seat0", "Remote": "no", "Class": "user",
    "Type": "wayland", "State": "active", "Active": "yes", "LockedHint": "no",
}
# A seated session of a DIFFERENT uid: the case the AUID guarantee exists for.
OTHER = dict(GOOD, User="2000")

SESSIONS = [
    {"session": "remote", "uid": 2000, "seat": None},
    {"session": "9", "uid": 2000, "seat": "seat0"},
    {"session": "2", "uid": 1000, "seat": "seat0"},
]


def _render(properties):
    return "".join(f"{key}={value}\n" for key, value in properties.items())


def _fake_logind(command, timeout=3, overrides=None, active_session="2"):
    del timeout
    if "list-sessions" in command:
        return json.dumps(SESSIONS)
    if "show-session" in command:
        session = command[command.index("show-session") + 1]
        properties = dict(OTHER if session == "9" else GOOD)
        if overrides and session == "2":
            properties.update(overrides)
        return _render(properties)
    if "show-seat" in command:
        return f"{active_session}\n"
    raise AssertionError(command)


TARGET = {
    "uid": 1000,
    "gid": 1000,
    "home": "/home/alice",
    "runtime": "/run/user/1000",
    "bus": "/run/user/1000/bus",
}


def write_request(spool, serial, auid=1000, key="sudoers", path="/etc/sudoers"):
    entry = spool / f"{serial:020d}-{auid}"
    entry.write_text(
        f"serial={serial}\nauid={auid}\nkey={key}\n"
        f"command=visudo\npath={path}\n",
        encoding="utf-8",
    )
    entry.chmod(0o600)
    return entry


def logind_with_bus(bus_status):
    """logind stub whose setpriv'd bus probe returns a chosen `stat -c` value.

    The bus is deliberately inspected as the target user: the unit keeps only
    CAP_SETGID/CAP_SETUID, so root has no CAP_DAC_OVERRIDE and cannot traverse
    the user's own 0700 /run/user/<uid>.
    """

    def runner(command, timeout=3):
        if command[0] == "/usr/bin/setpriv":
            assert "--init-groups" in command and "--reset-env" in command
            # The bus probe needs its watchdog inside setpriv for the same
            # reason delivery does: uid 0 without CAP_KILL cannot signal a
            # child that already dropped to the target uid, so a Python-side
            # timeout would raise PermissionError and then block in wait().
            watchdog = command.index("/usr/bin/timeout")
            assert watchdog > command.index("/usr/bin/setpriv")
            assert watchdog < command.index("/usr/bin/stat")
            assert command[watchdog + 1 : watchdog + 4] == [
                "--signal=TERM",
                "--kill-after=1s",
                "3s",
            ]
            # Locale must be pinned: `stat -c %F` is translated, and comparing
            # a translated type string to an English literal is exactly the
            # defect that took the LAN topology guard down on German installs.
            assert "LC_ALL=C.UTF-8" in command
            # No -L: a symlink must not be dereferenced into a valid socket.
            assert "-L" not in command
            if bus_status is None:
                raise subprocess.CalledProcessError(1, command)
            return bus_status
        return _fake_logind(command, timeout)

    return runner


def test_exact_local_auid_session(module):
    fake_account = SimpleNamespace(pw_gid=1000, pw_dir="/home/alice")
    with mock.patch.object(
        module, "_run", side_effect=logind_with_bus("socket:1000\n")
    ), mock.patch.object(module.pwd, "getpwuid", return_value=fake_account):
        target, reason = module.resolve_local_target(1000)
    assert reason == "ready"
    assert target == TARGET

    # A bus owned by anyone else, a non-socket, and an unreadable bus all fail
    # closed rather than delivering to the wrong seat.
    for rejected in ("socket:1001", "regular file:1000", "symbolic link:1000", None):
        with mock.patch.object(
            module, "_run", side_effect=logind_with_bus(rejected)
        ), mock.patch.object(module.pwd, "getpwuid", return_value=fake_account):
            try:
                module.resolve_local_target(1000)
            except RuntimeError as error:
                assert str(error) == "active-session-bus-invalid"
            else:
                raise AssertionError(f"bus {rejected!r} did not fail closed")

    def locked_logind(command, timeout=3):
        value = _fake_logind(command, timeout)
        return value.replace("LockedHint=no", "LockedHint=yes")

    with mock.patch.object(module, "_run", side_effect=locked_logind):
        target, reason = module.resolve_local_target(1000)
    assert target is None and reason == "locked"


def test_every_session_gate_fails_closed(module):
    """Each gate alone must be able to reject; none may be shadowed."""
    fake_account = SimpleNamespace(pw_gid=1000, pw_dir="/home/alice")

    # A seated session belonging to a DIFFERENT uid must never be selected --
    # neither by the list-sessions uid field nor by the show-session User
    # property. Ask for uid 2000's target while only uid 1000 holds the seat's
    # ActiveSession: session "9" is uid 2000 and seated, so it passes the row
    # filter and is rejected further in.
    with mock.patch.object(
        module, "_run", side_effect=logind_with_bus("socket:2000\n")
    ), mock.patch.object(module.pwd, "getpwuid", return_value=fake_account):
        target, reason = module.resolve_local_target(2000)
    assert target is None, "a foreign uid's seated session was selected"
    assert reason == "no-active-local-session"

    # Every property gate, one at a time, against the otherwise-valid session.
    for overrides, description in (
        ({"User": "1001"}, "show-session User disagreeing with the row uid"),
        ({"Remote": "yes"}, "a remote session"),
        ({"Class": "greeter"}, "a greeter session"),
        ({"Class": "manager"}, "a manager session"),
        ({"Type": "tty"}, "a non-graphical session"),
        ({"Type": ""}, "a session with no type"),
        ({"Active": "no"}, "an inactive session"),
        ({"State": "closing"}, "a closing session"),
        ({"State": "online"}, "a merely online session"),
        ({"Seat": ""}, "a session whose properties carry no seat"),
        ({"Seat": "seat0/../etc"}, "a seat id with path characters"),
    ):
        def stub(command, timeout=3, _o=overrides):
            return _fake_logind(command, timeout, overrides=_o)

        with mock.patch.object(
            module, "_run", side_effect=stub
        ), mock.patch.object(module.pwd, "getpwuid", return_value=fake_account):
            target, reason = module.resolve_local_target(1000)
        assert target is None, f"delivered to {description}"
        assert reason == "no-active-local-session"

    # The seat's ActiveSession must be this very session: a background session
    # on the same seat must not receive another session's audit detail.
    def not_foreground(command, timeout=3):
        return _fake_logind(command, timeout, active_session="9")

    with mock.patch.object(
        module, "_run", side_effect=not_foreground
    ), mock.patch.object(module.pwd, "getpwuid", return_value=fake_account):
        target, reason = module.resolve_local_target(1000)
    assert target is None, "delivered to a session that is not the seat's active one"

    # The row-level uid filter is shadowed by the User property gate for
    # correctness, so it can only be pinned by its observable effect: a session
    # belonging to another uid must not be interrogated at all. Without it the
    # drain queries every seated session on the machine on every audit event.
    queried = []

    def recording(command, timeout=3):
        if "show-session" in command:
            queried.append(command[command.index("show-session") + 1])
        return logind_with_bus("socket:1000\n")(command, timeout)

    with mock.patch.object(
        module, "_run", side_effect=recording
    ), mock.patch.object(module.pwd, "getpwuid", return_value=fake_account):
        module.resolve_local_target(1000)
    assert "9" not in queried, (
        "a session belonging to another uid was interrogated; the row-level "
        "uid filter is gone"
    )
    assert queried == ["2"]

    # A session id that is not a plain token is rejected before any lookup.
    def hostile_session_id(command, timeout=3):
        if "list-sessions" in command:
            return json.dumps([{"session": "2;rm -rf /", "uid": 1000, "seat": "seat0"}])
        return _fake_logind(command, timeout)

    with mock.patch.object(module, "_run", side_effect=hostile_session_id):
        target, reason = module.resolve_local_target(1000)
    assert target is None, "accepted a session id outside the token charset"


def test_bounded_delivery(module):
    calls = []

    def capture(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0)

    event = {
        "key": "sudoers",
        "path": "/etc/sudoers\n--urgency=normal",
    }
    event["path"] = module.sanitize_text(event["path"])
    with mock.patch.object(module.subprocess, "run", side_effect=capture):
        module.deliver_notification(TARGET, event)
    command = calls[0][0]
    assert command[0] == "/usr/bin/setpriv"
    assert "--reuid=1000" in command and "--regid=1000" in command
    assert command[-3] == "--"
    assert command[-1].splitlines()[0] == "/etc/sudoers --urgency=normal"
    assert command[-1].count("\n") == 2
    # The watchdog must run INSIDE setpriv, as the target uid. This process is
    # uid 0 with a bounding set of CAP_SETGID/CAP_SETUID only, so it has no
    # CAP_KILL: on expiry subprocess's own timeout calls os.kill on a child
    # that already dropped to another uid, raises PermissionError out of
    # Popen.__exit__ and then blocks in an unbounded wait(). Verified live.
    watchdog = command.index("/usr/bin/timeout")
    assert watchdog > command.index("/usr/bin/setpriv")
    assert watchdog < command.index("/usr/bin/notify-send")
    assert command[watchdog + 1 : watchdog + 4] == [
        "--signal=TERM",
        "--kill-after=1s",
        "5s",
    ]
    # The Python-side timeout is only an outer backstop and must outlast the
    # inner watchdog, or it fires first and re-enters that same trap.
    assert calls[0][1]["timeout"] > 5 + 1


def test_hardlinked_request_is_refused(module):
    """A second link to a request means another writer can still reach it."""
    with tempfile.TemporaryDirectory() as temporary:
        spool = pathlib.Path(temporary)
        entry = write_request(spool, 50)
        module.read_request(entry)
        (spool / "second-link").hardlink_to(entry)
        try:
            module.read_request(entry)
        except ValueError:
            pass
        else:
            raise AssertionError("accepted a hardlinked request")


def test_spool_trust_is_exact(module):
    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary)
        with mock.patch.object(module, "SPOOL_DIR", root / "absent"):
            assert module.spool_is_trusted() is None
            # Nothing queued is a clean no-op, not a failure the path unit
            # would then keep retrying.
            with mock.patch.object(module.syslog, "openlog"):
                assert module.main() == 0

        spool = root / "audit-notify.d"
        spool.mkdir(mode=0o700)
        with mock.patch.object(module, "SPOOL_DIR", spool):
            assert module.spool_is_trusted() is True
            spool.chmod(0o777)
            assert module.spool_is_trusted() is False
            with mock.patch.object(module.syslog, "openlog"), mock.patch.object(
                module.syslog, "syslog"
            ), mock.patch.object(
                module,
                "resolve_local_target",
                side_effect=AssertionError("must refuse before delivery"),
            ):
                assert module.main() == 1
            spool.chmod(0o700)

        # A symlink pointing at a valid directory must still be refused.
        link = root / "linked"
        link.symlink_to(spool)
        with mock.patch.object(module, "SPOOL_DIR", link):
            assert module.spool_is_trusted() is False


def test_request_parsing_is_exact(module):
    with tempfile.TemporaryDirectory() as temporary:
        spool = pathlib.Path(temporary)
        entry = write_request(spool, 42)
        parsed = module.read_request(entry)
        assert parsed == {
            "serial": 42,
            "auid": 1000,
            "key": "sudoers",
            "command": "visudo",
            "path": "/etc/sudoers",
        }

        for content in (
            "serial=42\nauid=1000\nkey=sudoers\ncommand=visudo\n",
            "serial=42\nauid=1000\nkey=sudoers\ncommand=visudo\npath=/x\nextra=1\n",
            "serial=x\nauid=1000\nkey=sudoers\ncommand=visudo\npath=/x\n",
            "serial=42\nauid=42\nkey=sudoers\ncommand=visudo\npath=/x\n",
            "serial=42\nauid=1000\nkey=\ncommand=visudo\npath=/x\n",
            "serial=42\nauid=1000\nkey=sudoers\nkey=other\ncommand=v\npath=/x\n",
        ):
            entry.write_text(content, encoding="utf-8")
            entry.chmod(0o600)
            try:
                module.read_request(entry)
            except ValueError:
                pass
            else:
                raise AssertionError(f"accepted a malformed request: {content!r}")

        # Metadata is part of the contract: a group- or world-writable request
        # is refused before any of its fields are read.
        write_request(spool, 43)
        loose = spool / f"{43:020d}-1000"
        loose.chmod(0o666)
        try:
            module.read_request(loose)
        except ValueError:
            pass
        else:
            raise AssertionError("accepted a world-writable request")


def test_drain_retires_every_request(module):
    with tempfile.TemporaryDirectory() as temporary:
        spool = pathlib.Path(temporary) / "audit-notify.d"
        spool.mkdir(mode=0o700)
        write_request(spool, 10, key="sudoers")
        write_request(spool, 11, key="identity")
        (spool / "malformed").write_text("garbage\n", encoding="utf-8")
        (spool / "malformed").chmod(0o600)

        delivered = []
        with mock.patch.object(module, "SPOOL_DIR", spool), mock.patch.object(
            module, "resolve_local_target", return_value=(TARGET, "ready")
        ), mock.patch.object(
            module, "deliver_notification",
            side_effect=lambda _target, event: delivered.append(event["key"]),
        ), mock.patch.object(module.syslog, "openlog"), mock.patch.object(
            module.syslog, "syslog"
        ):
            result = module.main()
        assert sorted(delivered) == ["identity", "sudoers"]
        # The malformed entry is reported as a failure, and every entry is
        # retired: DirectoryNotEmpty= is level-triggered, so a retained request
        # would restart this unit forever instead of surfacing the problem.
        assert result == 1
        assert os.listdir(spool) == []


def test_unremovable_entry_does_not_abort_drain(module):
    with tempfile.TemporaryDirectory() as temporary:
        spool = pathlib.Path(temporary) / "audit-notify.d"
        spool.mkdir(mode=0o700)
        # Sort before the valid request and fail unlink with IsADirectoryError.
        # The drain must log that one retirement failure and continue.
        (spool / "000-invalid-directory").mkdir()
        write_request(spool, 12, key="sudoers")
        delivered = []
        with mock.patch.object(module, "SPOOL_DIR", spool), mock.patch.object(
            module, "resolve_local_target", return_value=(TARGET, "ready")
        ), mock.patch.object(
            module, "deliver_notification",
            side_effect=lambda _target, event: delivered.append(event["key"]),
        ), mock.patch.object(module.syslog, "openlog"), mock.patch.object(
            module.syslog, "syslog"
        ) as syslog_write:
            assert module.main() == 1
        assert delivered == ["sudoers"]
        assert os.listdir(spool) == ["000-invalid-directory"]
        assert any(
            "request retirement failed (IsADirectoryError)" in call.args[1]
            for call in syslog_write.call_args_list
        )


def test_absent_session_is_not_a_failure(module):
    with tempfile.TemporaryDirectory() as temporary:
        spool = pathlib.Path(temporary) / "audit-notify.d"
        spool.mkdir(mode=0o700)
        write_request(spool, 20)
        with mock.patch.object(module, "SPOOL_DIR", spool), mock.patch.object(
            module, "resolve_local_target",
            return_value=(None, "no-active-local-session"),
        ), mock.patch.object(
            module, "deliver_notification",
            side_effect=AssertionError("delivered without a target"),
        ), mock.patch.object(module.syslog, "openlog"), mock.patch.object(
            module.syslog, "syslog"
        ):
            assert module.main() == 0
        assert os.listdir(spool) == []


def test_delivery_failure_is_reported_and_retired(module):
    with tempfile.TemporaryDirectory() as temporary:
        spool = pathlib.Path(temporary) / "audit-notify.d"
        spool.mkdir(mode=0o700)
        write_request(spool, 30)
        with mock.patch.object(module, "SPOOL_DIR", spool), mock.patch.object(
            module, "resolve_local_target", return_value=(TARGET, "ready")
        ), mock.patch.object(
            module, "deliver_notification",
            side_effect=module.subprocess.SubprocessError("notify-send failed"),
        ), mock.patch.object(module.syslog, "openlog"), mock.patch.object(
            module.syslog, "syslog"
        ) as syslog_write:
            assert module.main() == 1
        assert os.listdir(spool) == []
        assert syslog_write.call_count == 1


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: 12-audit-event-notify-fixture.py NOTIFIER")
    notifier_path = sys.argv[1]
    module = load_notifier(notifier_path)
    # module.main() models systemd's argumentless ExecStart, not this fixture's
    # own NOTIFIER operand. Keep argv at the production boundary while the
    # behavior tests call main() directly in the current interpreter.
    with mock.patch.object(sys, "argv", [notifier_path]):
        test_exact_local_auid_session(module)
        test_every_session_gate_fails_closed(module)
        test_bounded_delivery(module)
        test_spool_trust_is_exact(module)
        test_request_parsing_is_exact(module)
        test_hardlinked_request_is_refused(module)
        test_drain_retires_every_request(module)
        test_unremovable_entry_does_not_abort_drain(module)
        test_absent_session_is_not_a_failure(module)
        test_delivery_failure_is_reported_and_retired(module)
    print(
        "PASS: exact local AUID session, every session gate fails closed, "
        "bounded delivery under a target-uid watchdog, exact spool trust, "
        "exact request parsing, hardlinked request refused, every request "
        "retired, unremovable entry contained, absent session is not a failure, "
        "delivery failure is reported"
    )


if __name__ == "__main__":
    main()

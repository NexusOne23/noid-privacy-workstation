#!/usr/bin/python3
"""Behavior fixtures for the M12 auditd/auparse notification plugin.

Delivery is NOT covered here: the plugin runs in auditd_t and only queues
requests. The session gauntlet and the setpriv/notify-send route live in
noid-audit-event-notify and are covered by 12-audit-event-notify-fixture.py.
"""

import importlib.machinery
import importlib.util
import pathlib
import stat
import sys
import tempfile
from types import SimpleNamespace
from unittest import mock

# Loading the repository plugin must never leave host-path-bearing bytecode in
# the public source surface, even when this fixture is invoked directly.
sys.dont_write_bytecode = True


def load_plugin(path):
    loader = importlib.machinery.SourceFileLoader("noid_audit_notify", path)
    specification = importlib.util.spec_from_loader(loader.name, loader)
    if specification is None or specification.loader is None:
        raise RuntimeError(f"cannot import plugin: {path}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def record(record_type, serial, fields=""):
    return f"type={record_type} msg=audit(1752420000.{serial:03d}:{serial}):{fields}\n"


def recording_handoff(sink):
    """Stand in for queue_notification, which signals success by return value.

    A bare list.append would return None, which _handle reads as a refused
    handoff — the stub has to model the real contract.
    """

    def handoff(event):
        sink.append(event)
        return True

    return handoff


def test_interlaced_complete_events(module):
    events = []
    assembler = module.FeedAssembler(events.append)
    records = [
        record(
            "SYSCALL",
            100,
            ' arch=c000003e syscall=257 success=yes exit=3 items=1 '
            'ppid=1 pid=2 auid=1000 uid=0 comm="visudo" '
            'exe="/usr/sbin/visudo" key="sudoers"',
        ),
        record(
            "SYSCALL",
            101,
            ' arch=c000003e syscall=257 success=yes exit=3 items=1 '
            'ppid=1 pid=3 auid=1000 uid=0 comm="usermod" '
            'exe="/usr/sbin/usermod" key="identity"',
        ),
        record(
            "PATH",
            101,
            " item=0 name=2F6574632F706173737764 inode=2 dev=00:00 "
            "mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL",
        ),
        record(
            "PATH",
            100,
            ' item=0 name="/etc/sudoers" inode=1 dev=00:00 mode=0100644 '
            "ouid=0 ogid=0 rdev=00:00 nametype=NORMAL",
        ),
        record("EOE", 101),
        record("EOE", 100),
        record(
            "SYSCALL",
            102,
            ' arch=c000003e syscall=257 success=yes exit=3 items=0 '
            'ppid=1 pid=4 auid=4294967295 uid=0 comm="daemon" '
            'exe="/usr/bin/daemon" key="firewall"',
        ),
        record("EOE", 102),
        # comm is process-controlled. A renamed executable must not select
        # itself into the routine-daemon suppression set.
        record(
            "SYSCALL",
            103,
            ' arch=c000003e syscall=257 success=yes exit=3 items=0 '
            'ppid=1 pid=5 auid=1000 uid=0 comm="kmod" '
            'exe="/var/tmp/renamed-helper" key="sudoers"',
        ),
        record("EOE", 103),
        # The reviewed comm+absolute-executable pair remains suppressible.
        record(
            "SYSCALL",
            104,
            ' arch=c000003e syscall=257 success=yes exit=3 items=0 '
            'ppid=1 pid=6 auid=1000 uid=0 comm="kmod" '
            'exe="/usr/bin/kmod" key="sudoers"',
        ),
        record("EOE", 104),
    ]
    for audit_record in records:
        assembler.feed(audit_record)
    assembler.flush()
    critical = [event for event in events if event is not None]
    assert critical == [
        {
            "serial": 100,
            "key": "sudoers",
            "auid": 1000,
            "command": "visudo",
            "path": "/etc/sudoers",
        },
        {
            "serial": 101,
            "key": "identity",
            "auid": 1000,
            "command": "usermod",
            "path": "/etc/passwd",
        },
        {
            "serial": 103,
            "key": "sudoers",
            "auid": 1000,
            "command": "kmod",
            "path": "/var/tmp/renamed-helper",
        },
    ]


def test_crash_durable_atomic_state(module):
    with tempfile.TemporaryDirectory() as temporary:
        target = pathlib.Path(temporary) / "state"
        with mock.patch.object(
            module.os, "fsync", wraps=module.os.fsync
        ) as fsync:
            module.atomic_write(target, "state=healthy\n", 0o640)
        assert target.read_text(encoding="utf-8") == "state=healthy\n"
        assert stat.S_IMODE(target.stat().st_mode) == 0o640
        assert fsync.call_count == 2


def test_atomic_write_fd_ownership_and_parent_contract(module):
    """A transferred fd is never closed twice, even after replacement fails."""
    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary)
        target = root / "state"
        opened_fds = []
        real_fdopen = module.os.fdopen

        def recording_fdopen(fd, *args, **kwargs):
            opened_fds.append(fd)
            return real_fdopen(fd, *args, **kwargs)

        with mock.patch.object(
            module.os, "fdopen", side_effect=recording_fdopen
        ), mock.patch.object(
            module.os, "replace", side_effect=OSError("fixture replacement")
        ), mock.patch.object(
            module.os, "close", wraps=module.os.close
        ) as explicit_close:
            try:
                module.atomic_write(target, "state=failed\n", 0o600)
            except OSError:
                pass
            else:
                raise AssertionError("replacement failure was swallowed")
        assert len(opened_fds) == 1
        assert all(
            call.args != (opened_fds[0],)
            for call in explicit_close.call_args_list
        ), "atomic_write double-closed the fd transferred to fdopen"
        assert list(root.iterdir()) == []

        missing_target = root / "missing-parent" / "state"
        try:
            module.atomic_write(missing_target, "state=failed\n", 0o600)
        except FileNotFoundError:
            pass
        else:
            raise AssertionError("atomic_write recreated an unowned parent")
        assert not missing_target.parent.exists()


def test_degraded_marker_failure_is_nonfatal(module):
    plugin = module.AuditNotificationPlugin()
    with mock.patch.object(
        module, "atomic_write", side_effect=OSError("read-only state")
    ), mock.patch.object(
        plugin, "write_health", side_effect=OSError("read-only runtime")
    ), mock.patch.object(module.syslog, "syslog") as syslog_write:
        persisted = plugin.mark_degraded("fixture-failure")
    assert persisted is False
    assert syslog_write.call_count == 2


def test_unexpected_worker_failure_is_contained(module):
    plugin = module.AuditNotificationPlugin()
    plugin.running = False
    plugin.events.put_nowait({"serial": 1, "auid": 1000, "key": "sudoers"})
    degraded = []
    with mock.patch.object(
        plugin, "_handle", side_effect=TypeError("fixture")
    ), mock.patch.object(
        plugin, "mark_degraded", side_effect=degraded.append
    ), mock.patch.object(plugin, "write_health"):
        plugin._worker()
    assert degraded == ["notification-worker-TypeError"]
    assert plugin.stats["handoff_failures"] == 1
    assert plugin.events.unfinished_tasks == 0


def test_startup_failures_are_nonzero(module):
    """Both startup guards must be exercised on any host.

    Neither branch may depend on whether the build host happens to have a real
    /run/noid-privacy: a CI container has none, an installed host does.
    """
    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary)

        plugin = module.AuditNotificationPlugin()
        degraded = []
        with mock.patch.object(module, "RUNTIME_DIR", root / "absent"), \
                mock.patch.object(
                    plugin, "mark_degraded", side_effect=degraded.append
                ), mock.patch.object(module.syslog, "openlog"):
            result = plugin.run()
        assert result == 1
        assert degraded == ["runtime-directory-missing"]
        assert plugin.worker.is_alive() is False

        plugin = module.AuditNotificationPlugin()
        degraded = []
        with mock.patch.object(module, "RUNTIME_DIR", root), \
                mock.patch.object(
                    module, "SPOOL_DIR", root / "audit-notify.d"
                ), mock.patch.object(
                    plugin, "write_health", side_effect=OSError("read-only")
                ), mock.patch.object(
                    plugin, "mark_degraded", side_effect=degraded.append
                ), mock.patch.object(module.syslog, "openlog"):
            result = plugin.run()
        assert result == 1
        assert degraded == ["initial-health-write-failed"]
        assert plugin.worker.is_alive() is False
        # The spool must be private the moment it exists; the drain refuses
        # any other shape.
        spool = root / "audit-notify.d"
        assert stat.S_IMODE(spool.stat().st_mode) == 0o700


def test_reload_defers_health_io(module):
    plugin = module.AuditNotificationPlugin()
    with mock.patch.object(
        plugin,
        "write_health",
        side_effect=AssertionError("signal handler performed I/O"),
    ):
        plugin.reload(None, None)
    assert plugin.health_refresh_requested is True


def test_clean_dispatcher_eof_is_normal(module):
    """auditd reload retires the plugin by EOF without degrading it."""
    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary)
        runtime = root / "runtime"
        runtime.mkdir()
        health = runtime / "audit-notify.health"
        degraded_marker = runtime / "audit-notify-degraded"
        plugin = module.AuditNotificationPlugin()
        with mock.patch.object(module, "RUNTIME_DIR", runtime), \
                mock.patch.object(module, "SPOOL_DIR", runtime / "spool"), \
                mock.patch.object(module, "HEALTH_FILE", health), \
                mock.patch.object(module, "DEGRADED_MARKER", degraded_marker), \
                mock.patch.object(
                    module.select, "select", return_value=([0], [], [])
                ), mock.patch.object(module.os, "read", return_value=b""), \
                mock.patch.object(module.os, "set_blocking"), \
                mock.patch.object(module.signal, "signal"), \
                mock.patch.object(module.syslog, "openlog"), \
                mock.patch.object(
                    plugin, "mark_degraded", wraps=plugin.mark_degraded
                ) as mark_degraded:
            assert plugin.run() == 0
        assert mark_degraded.call_count == 0
        assert "state=stopped\n" in health.read_text(encoding="utf-8")
        assert not degraded_marker.exists()
        assert plugin.worker.is_alive() is False


def test_bounded_handoff(module):
    event = {
        "serial": 42,
        "key": "sudoers",
        "auid": 1000,
        "command": "visudo",
        "path": "/etc/sudoers",
    }
    with tempfile.TemporaryDirectory() as temporary:
        spool = pathlib.Path(temporary) / "audit-notify.d"
        spool.mkdir(mode=0o700)
        staged_paths = []
        real_replace = module.os.replace

        def inspect_replace(source, destination):
            staged_paths.append(pathlib.Path(source))
            assert pathlib.Path(source).parent == spool.parent
            assert pathlib.Path(source).parent != spool
            return real_replace(source, destination)

        with mock.patch.object(module, "SPOOL_DIR", spool), mock.patch.object(
            module, "atomic_write", wraps=module.atomic_write
        ) as atomic_write, mock.patch.object(
            module.os, "replace", side_effect=inspect_replace
        ):
            assert module.queue_notification(dict(event)) is True
            assert atomic_write.call_args.kwargs["temporary_parent"] == spool.parent
            assert len(staged_paths) == 1
            entries = sorted(spool.iterdir())
            assert len(entries) == 1
            # Serial and AUID are integers validated in parse_complete_event,
            # so an audit key can never steer the request out of the spool.
            assert entries[0].name == f"{42:020d}-1000"
            assert stat.S_IMODE(entries[0].stat().st_mode) == 0o600
            assert entries[0].read_text(encoding="utf-8") == (
                "serial=42\nauid=1000\nkey=sudoers\n"
                "command=visudo\npath=/etc/sudoers\n"
            )

            # A stalled or disabled drain must bound the spool rather than let
            # auditd fill the runtime tmpfs. There is already one request:
            # fill to limit - 1, prove one final request is accepted, then
            # prove the exact full boundary rejects the next request.
            for filler in range(module.SPOOL_LIMIT - 2):
                (spool / f"filler-{filler:04d}").write_text(
                    "", encoding="utf-8"
                )
            assert len(list(spool.iterdir())) == module.SPOOL_LIMIT - 1
            assert module.queue_notification(dict(event, serial=43)) is True
            assert len(list(spool.iterdir())) == module.SPOOL_LIMIT
            assert module.queue_notification(dict(event, serial=44)) is False


def test_update_window_authority(module):
    with mock.patch.object(
        module.subprocess, "run", return_value=SimpleNamespace(returncode=0)
    ) as run:
        assert module.update_window_active() is True
        assert run.call_args.kwargs["timeout"] == 1
        assert run.call_args.args[0] == [str(module.UPDATE_WINDOW_HELPER)]
    with mock.patch.object(
        module.subprocess, "run", return_value=SimpleNamespace(returncode=1)
    ):
        assert module.update_window_active() is False
    with mock.patch.object(
        module.subprocess,
        "run",
        side_effect=module.subprocess.TimeoutExpired("validator", 1),
    ):
        assert module.update_window_active() is False

    event = {
        "serial": 150,
        "key": "sysctl",
        "auid": 1000,
        "command": "sysctl",
        "path": "/etc/sysctl.d/90-example.conf",
    }
    plugin = module.AuditNotificationPlugin()
    with mock.patch.object(
        module, "update_window_active", return_value=True
    ), mock.patch.object(
        module, "queue_notification", side_effect=AssertionError("must suppress")
    ):
        plugin._handle(dict(event))
    assert plugin.stats["notifications_suppressed"] == 1
    assert plugin.stats["last_suppression_reason"] == "reviewed-update-window"

    queued = []
    plugin = module.AuditNotificationPlugin()
    with mock.patch.object(
        module, "update_window_active", return_value=False
    ), mock.patch.object(
        module, "queue_notification", side_effect=recording_handoff(queued)
    ):
        plugin._handle(dict(event))
    assert len(queued) == 1
    assert plugin.stats["notifications_queued"] == 1
    assert plugin.stats["notifications_suppressed"] == 0

    # Keys outside the narrow update allowlist never pay or trust the helper.
    event["key"] = "sudoers"
    plugin = module.AuditNotificationPlugin()
    with mock.patch.object(
        module, "update_window_active", side_effect=AssertionError("unexpected")
    ), mock.patch.object(module, "queue_notification", return_value=True):
        plugin._handle(dict(event))


def test_spool_bound_is_a_recorded_suppression(module):
    """A full spool suppresses visibly instead of dropping silently."""
    plugin = module.AuditNotificationPlugin()
    event = {
        "serial": 300,
        "key": "sudoers",
        "auid": 1000,
        "command": "visudo",
        "path": "/etc/sudoers",
    }
    degraded = []
    with mock.patch.object(
        module, "queue_notification", return_value=False
    ), mock.patch.object(
        plugin, "mark_degraded", side_effect=degraded.append
    ):
        plugin._handle(dict(event))
    assert plugin.stats["notifications_suppressed"] == 1
    assert plugin.stats["last_suppression_reason"] == "notification-spool-full"
    assert plugin.stats["notifications_queued"] == 0
    assert degraded == ["notification-spool-full"]
    # A refused handoff must not arm the rate limit, or the retry after the
    # drain catches up would be suppressed too.
    assert plugin.rates == {}


def test_coalescing_and_rate_limit(module):
    plugin = module.AuditNotificationPlugin()
    event = {
        "serial": 200,
        "key": "sudoers",
        "auid": 1000,
        "command": "visudo",
        "path": "/etc/sudoers",
    }
    plugin.enqueue(dict(event))
    event["serial"] = 201
    plugin.enqueue(dict(event))
    assert plugin.events.qsize() == 1
    assert plugin.stats["coalesced_events"] == 1

    queued = plugin.events.get_nowait()
    plugin.pending.clear()
    handoffs = []
    with mock.patch.object(
        module, "queue_notification", side_effect=recording_handoff(handoffs)
    ):
        plugin._handle(dict(queued))
        plugin._handle(dict(queued))
    assert len(handoffs) == 1
    assert plugin.stats["notifications_suppressed"] == 1
    assert plugin.stats["last_suppression_reason"] == "rate-limit"


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: 12-audit-notify-fixture.py PLUGIN")
    module = load_plugin(sys.argv[1])
    test_interlaced_complete_events(module)
    test_crash_durable_atomic_state(module)
    test_atomic_write_fd_ownership_and_parent_contract(module)
    test_degraded_marker_failure_is_nonfatal(module)
    test_unexpected_worker_failure_is_contained(module)
    test_startup_failures_are_nonzero(module)
    test_reload_defers_health_io(module)
    test_clean_dispatcher_eof_is_normal(module)
    test_bounded_handoff(module)
    test_update_window_authority(module)
    test_spool_bound_is_a_recorded_suppression(module)
    test_coalescing_and_rate_limit(module)
    print(
        "PASS: interlaced events, crash-durable/nonfatal state, host-independent "
        "startup guards, exact fd/parent ownership, bounded spool handoff, "
        "durably degraded spool-bound "
        "suppression, process-bound update suppression, deferred signal-safe "
        "health refresh, clean dispatcher EOF lifecycle, "
        "coalescing and rate limit"
    )


if __name__ == "__main__":
    main()

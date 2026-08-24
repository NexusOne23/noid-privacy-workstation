#!/usr/bin/python3
"""NoID Privacy opt-in auditd notification plugin.

auditd sends string records on stdin.  The maintained auparse feed API owns
event assembly, including interlaced/out-of-order records and EOE timeouts.
Only a complete critical event is queued for the notification worker.

Desktop delivery deliberately does NOT happen here.  auditd execve()s this
plugin without a domain transition, so it runs in auditd_t, and the Fedora
targeted policy grants that domain neither CAP_SETUID/CAP_SETGID nor any
access to a user session bus.  This plugin therefore owns parsing, filtering,
coalescing and rate limiting, and hands each surviving event to
noid-audit-event-notify.service through a bounded /run spool.
"""

import datetime as dt
import os
import pathlib
import queue
import select
import signal
import subprocess
import sys
import syslog
import tempfile
import threading
import time

import auparse


CRITICAL_KEYS = frozenset(
    {
        "identity",
        "sudoers",
        "audit_config",
        "aide_integrity",
        "bootloader",
        "sysctl",
        "systemd",
        "firewall",
        "pam_changes",
        "network_config",
        "user_mgmt",
        "su_usage",
        "luks",
        "login_config",
        "security_config",
        "cron",
    }
)
ROUTINE_PROCESSES = frozenset(
    {
        ("systemd-udevd", "/usr/lib/systemd/systemd-udevd"),
        ("udevd", "/usr/lib/systemd/systemd-udevd"),
        ("kmod", "/usr/bin/kmod"),
        ("auditd", "/usr/sbin/auditd"),
        ("auditctl", "/usr/sbin/auditctl"),
        ("systemd-sysctl", "/usr/lib/systemd/systemd-sysctl"),
    }
)
UPDATE_SUPPRESSED_KEYS = frozenset(
    {"sysctl", "systemd", "bootloader", "network_config"}
)
UPDATE_WINDOW_HELPER = pathlib.Path("/usr/libexec/noid-update-window-active")
RUNTIME_DIR = pathlib.Path("/run/noid-privacy")
HEALTH_FILE = RUNTIME_DIR / "audit-notify.health"
SPOOL_DIR = RUNTIME_DIR / "audit-notify.d"
DEGRADED_MARKER = RUNTIME_DIR / "audit-notify-degraded"
RATE_LIMIT_SECONDS = 300
QUEUE_LIMIT = 512
SPOOL_LIMIT = 64
EOE_TIMEOUT_SECONDS = 2


def utc_now():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def sanitize_text(value, limit=512):
    """Bound untrusted audit text and remove UI control characters."""
    if not value or value in {"(null)", "?"}:
        return ""
    cleaned = "".join(
        ch if ch.isprintable() and ch not in "\r\n" else " " for ch in value
    )
    return " ".join(cleaned.split())[:limit]


def atomic_write(path, content, mode, temporary_parent=None):
    """Replace one file without recreating or weakening its owned parent."""
    if temporary_parent is None:
        temporary_parent = path.parent
    fd, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=temporary_parent
    )
    try:
        os.fchmod(fd, mode)
        stream = os.fdopen(fd, "w", encoding="utf-8")
        # fdopen() owns the descriptor from this point, including every error
        # path through write/flush/fsync.  Clear our ownership before any of
        # those operations so another thread can never have a reused descriptor
        # closed by the cleanup handler below.
        fd = -1
        with stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        # A cross-directory rename needs both directory entries persisted.
        # dict.fromkeys keeps the ordinary same-directory path to one fsync.
        for directory in dict.fromkeys((path.parent, temporary_parent)):
            directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except BaseException:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _record_fields(parser):
    fields = {}
    if not parser.first_field():
        return fields
    while True:
        name = parser.get_field_name()
        raw = parser.get_field_str()
        try:
            interpreted = parser.interpret_field()
        except RuntimeError:
            interpreted = raw
        fields[name] = (raw, interpreted)
        if not parser.next_field():
            return fields


def parse_complete_event(parser):
    """Return one bounded critical-event dictionary, or None."""
    key = ""
    auid_raw = ""
    command = ""
    executable = ""
    primary_path = ""
    fallback_path = ""

    for record_number in range(parser.get_num_records()):
        if not parser.goto_record_num(record_number):
            continue
        record_type = parser.get_type_name()
        fields = _record_fields(parser)
        if record_type == "SYSCALL":
            key = fields.get("key", ("", ""))[1]
            auid_raw = fields.get("auid", ("", ""))[0]
            command = fields.get("comm", ("", ""))[1]
            executable = fields.get("exe", ("", ""))[1]
        elif record_type == "PATH":
            path_value = fields.get("name", ("", ""))[1]
            item = fields.get("item", ("", ""))[0]
            if item == "0":
                primary_path = path_value
            elif not fallback_path:
                fallback_path = path_value

    key = sanitize_text(key, 64)
    command = sanitize_text(command, 64)
    executable = sanitize_text(executable, 512)
    if key not in CRITICAL_KEYS or (command, executable) in ROUTINE_PROCESSES:
        return None
    if auid_raw in {"", "unset", "4294967295", "-1"}:
        return None
    try:
        auid = int(auid_raw, 10)
    except ValueError:
        return None
    if auid < 1000 or auid > 4294967294:
        return None

    timestamp = parser.get_timestamp()
    return {
        "serial": int(timestamp.serial),
        "key": key,
        "auid": auid,
        "command": command,
        "path": sanitize_text(primary_path or fallback_path or executable),
    }


class FeedAssembler:
    """Small testable wrapper around the supported auparse feed interface."""

    def __init__(self, event_handler):
        self.event_handler = event_handler
        self.parser = auparse.AuParser(auparse.AUSOURCE_FEED, None)
        self.parser.set_eoe_timeout(EOE_TIMEOUT_SECONDS)
        # python3-audit requires a Python function object here; it rejects a
        # bound method even though both are callable. Retain the closure for
        # the parser lifetime and delegate into the supplied event handler.
        def event_ready(parser, callback_type, _user_data):
            if callback_type == auparse.AUPARSE_CB_EVENT_READY:
                self.event_handler(parse_complete_event(parser))

        self._callback = event_ready
        self.parser.add_callback(self._callback, None)

    def feed(self, data):
        self.parser.feed(data)

    def age(self):
        self.parser.feed_age_events()

    def flush(self):
        self.parser.flush_feed()


def update_window_active():
    """Trust only M25's process/lock-bound update-window validator."""
    try:
        result = subprocess.run(
            [str(UPDATE_WINDOW_HELPER)],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=1,
            env={"PATH": "/usr/sbin:/usr/bin", "LANG": "C.UTF-8"},
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def queue_notification(event):
    """Hand one surviving event to the normally-domained delivery notifier.

    Delivery cannot happen in this process.  auditd execve()s the plugin from
    bin_t with execute_no_trans, so it stays in auditd_t, and `setpriv` changes
    credentials without changing the SELinux domain.  Verified against the
    installed targeted policy: auditd_t holds `capability { audit_control
    audit_write chown fsetid net_bind_service setpcap sys_nice sys_resource }`
    (no setuid/setgid), and /run/user/<uid>/bus is session_dbusd_tmp_t, for
    which auditd_t has no sock_file access and no connectto on the session
    bus daemon.  Granting the two capabilities alone would therefore only move
    the failure one step later, so the whole delivery path lives in
    noid-audit-event-notify.service instead — the same split M12 already uses
    for the audit-storage marker.

    The spool is bounded: a stalled or disabled notifier can never let auditd
    fill the runtime tmpfs.  Returns False when the bound is reached so the
    caller records a suppression instead of an unnoticed drop.
    """
    if len(os.listdir(SPOOL_DIR)) >= SPOOL_LIMIT:
        return False
    request = (
        f"serial={event['serial']}\n"
        f"auid={event['auid']}\n"
        f"key={event['key']}\n"
        f"command={event['command']}\n"
        f"path={event['path']}\n"
    )
    # Both components are integers validated in parse_complete_event, so the
    # name cannot carry a separator or escape the spool directory.
    name = f"{event['serial']:020d}-{event['auid']}"
    # Stage in the sibling runtime directory, not inside the directory watched
    # by DirectoryNotEmpty=.  The watcher can therefore see only a completely
    # written request after the same-filesystem atomic rename, never mkstemp's
    # in-flight file.  SPOOL_DIR.parent also keeps behavior fixtures isolated.
    atomic_write(
        SPOOL_DIR / name,
        request,
        0o600,
        temporary_parent=SPOOL_DIR.parent,
    )
    return True


class AuditNotificationPlugin:
    def __init__(self):
        self.running = True
        self.health_refresh_requested = False
        self.events = queue.Queue(maxsize=QUEUE_LIMIT)
        self.pending = set()
        self.rates = {}
        self.lock = threading.Lock()
        self.stats = {
            "complete_events": 0,
            "critical_events": 0,
            "notifications_queued": 0,
            "notifications_suppressed": 0,
            "coalesced_events": 0,
            "queue_drops": 0,
            "handoff_failures": 0,
            "last_event_serial": 0,
            "last_suppression_reason": "none",
            "last_input_at": "never",
            "last_queued_at": "never",
        }
        self.assembler = FeedAssembler(self.enqueue)
        self.worker = threading.Thread(target=self._worker, name="notify-worker", daemon=True)

    def enqueue(self, event):
        with self.lock:
            self.stats["complete_events"] += 1
            if event is None:
                return
            self.stats["critical_events"] += 1
            self.stats["last_event_serial"] = event["serial"]
            token = (event["auid"], event["key"])
            if token in self.pending:
                self.stats["coalesced_events"] += 1
                return
            self.pending.add(token)
        try:
            self.events.put_nowait(event)
        except queue.Full:
            with self.lock:
                self.pending.discard(token)
                self.stats["queue_drops"] += 1
            self.mark_degraded("notification-queue-overflow")

    def write_health(self, state="running"):
        with self.lock:
            snapshot = dict(self.stats)
        lines = [
            f"state={state}",
            f"pid={os.getpid()}",
            f"updated_at={utc_now()}",
            f"persistent_degraded={'yes' if DEGRADED_MARKER.exists() else 'no'}",
        ]
        lines.extend(f"{name}={value}" for name, value in snapshot.items())
        atomic_write(HEALTH_FILE, "\n".join(lines) + "\n", 0o640)

    def mark_degraded(self, reason):
        """Publish degraded state without ever killing the dispatcher worker."""
        reason = sanitize_text(reason, 80) or "unspecified-plugin-failure"
        marker_persisted = True
        try:
            atomic_write(
                DEGRADED_MARKER,
                "status=degraded\n"
                f"reason={reason}\n"
                f"detected_at={utc_now()}\n"
                "remediation=review-audit-notify-health-before-removing-this-marker\n",
                0o600,
            )
        except OSError as error:
            marker_persisted = False
            syslog.syslog(
                syslog.LOG_CRIT,
                "audit notification degradation marker write failed: "
                f"{type(error).__name__}",
            )
        syslog.syslog(syslog.LOG_ALERT, f"audit notification degraded: {reason}")
        try:
            self.write_health("degraded")
        except OSError:
            pass
        return marker_persisted

    def _suppress(self, reason):
        with self.lock:
            self.stats["notifications_suppressed"] += 1
            self.stats["last_suppression_reason"] = reason

    def _handle(self, event):
        token = (event["auid"], event["key"])
        try:
            if event["key"] in UPDATE_SUPPRESSED_KEYS and update_window_active():
                self._suppress("reviewed-update-window")
                return
            now = time.monotonic()
            if now - self.rates.get(token, -RATE_LIMIT_SECONDS) < RATE_LIMIT_SECONDS:
                self._suppress("rate-limit")
                return
            if not queue_notification(event):
                self._suppress("notification-spool-full")
                self.mark_degraded("notification-spool-full")
                return
            self.rates[token] = now
            with self.lock:
                self.stats["notifications_queued"] += 1
                self.stats["last_queued_at"] = utc_now()
                self.stats["last_suppression_reason"] = "none"
        except (OSError, KeyError, ValueError, RuntimeError) as error:
            with self.lock:
                self.stats["handoff_failures"] += 1
            self.mark_degraded(type(error).__name__)
        finally:
            with self.lock:
                self.pending.discard(token)

    def _worker(self):
        while self.running or not self.events.empty():
            try:
                event = self.events.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._handle(event)
            except Exception as error:
                with self.lock:
                    self.stats["handoff_failures"] += 1
                self.mark_degraded(f"notification-worker-{type(error).__name__}")
            finally:
                self.events.task_done()
                try:
                    self.write_health()
                except OSError:
                    self.mark_degraded("health-write-failed")

    def stop(self, _signum, _frame):
        self.running = False

    def reload(self, _signum, _frame):
        # Python runs signal handlers on the main thread.  Do not acquire
        # self.lock or perform filesystem I/O here: a signal may interrupt that
        # same thread while it already owns the non-reentrant lock.
        self.health_refresh_requested = True

    def run(self):
        syslog.openlog("noid-audit-notify", syslog.LOG_PID, syslog.LOG_AUTH)
        try:
            # M05's /etc/tmpfiles.d/noid-runtime.conf boot-creates this
            # directory with the exact 0755 root:root shape, so neither the
            # mkdir nor the chmod was ever load-bearing -- but both were fatal.
            # auditd execve()s this plugin without a domain transition, so it
            # runs in auditd_t, and the Fedora targeted policy grants that
            # domain { add_name remove_name write } on var_run_t:dir but NOT
            # setattr. chmod(2) performs the SELinux setattr check even when
            # the mode is already correct, so os.chmod raised OSError on every
            # enforcing installation and the plugin returned 1 before handling
            # a single event. The controller's health poll then never observed
            # state=running, reverted active=no and reported that auditd had
            # not started a healthy plugin. Verify the directory instead of
            # reshaping it; reshaping is exactly what auditd_t may not do.
            if not RUNTIME_DIR.is_dir():
                self.mark_degraded("runtime-directory-missing")
                return 1
            # Mode 0700 carries no group/other bits, so no umask can widen it
            # and no follow-up chmod is needed. The new name transitions to
            # auditd_var_run_t, where auditd_t does hold create/write/unlink --
            # unlike the var_run_t parent it may only add names to.
            SPOOL_DIR.mkdir(mode=0o700, exist_ok=True)
            self.write_health()
        except OSError:
            self.mark_degraded("initial-health-write-failed")
            return 1
        self.worker.start()
        signal.signal(signal.SIGTERM, self.stop)
        signal.signal(signal.SIGINT, self.stop)
        signal.signal(signal.SIGHUP, self.reload)
        os.set_blocking(0, False)
        last_health = time.monotonic()
        exit_status = 0
        try:
            while self.running:
                readable, _, _ = select.select([0], [], [], 1.0)
                if readable:
                    chunk = os.read(0, 65536)
                    if not chunk:
                        # auditd owns this pipe and closes it whenever a
                        # configuration reload retires or replaces the plugin,
                        # including an unchanged active=yes reload. Clean EOF
                        # is therefore the normal dispatcher lifecycle. The
                        # controller independently requires active=yes to map
                        # to an exact live plugin PID; parser, I/O, worker,
                        # queue and health failures remain degraded here.
                        break
                    with self.lock:
                        self.stats["last_input_at"] = utc_now()
                    self.assembler.feed(chunk.decode("utf-8", "replace"))
                else:
                    self.assembler.age()
                if self.health_refresh_requested:
                    self.health_refresh_requested = False
                    self.write_health()
                    last_health = time.monotonic()
                elif time.monotonic() - last_health >= 5:
                    self.write_health()
                    last_health = time.monotonic()
        except (OSError, RuntimeError) as error:
            self.mark_degraded(type(error).__name__)
            exit_status = 1
        finally:
            try:
                self.assembler.flush()
            except (OSError, RuntimeError):
                self.mark_degraded("auparse-flush-failed")
                exit_status = 1
            self.running = False
            self.worker.join(timeout=5)
            if self.worker.is_alive() or not self.events.empty():
                self.mark_degraded("notification-worker-stop-timeout")
                exit_status = 1
            try:
                self.write_health("stopped")
            except OSError:
                self.mark_degraded("final-health-write-failed")
                exit_status = 1
        return exit_status


def main():
    if len(sys.argv) != 1:
        print("ERROR: audit-notify.sh accepts no arguments", file=sys.stderr)
        return 2
    return AuditNotificationPlugin().run()


if __name__ == "__main__":
    raise SystemExit(main())

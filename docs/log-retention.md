# NoID Privacy — 30-day retention boundary

## Policy and scope

NoID Privacy keeps a short local integrity trail for troubleshooting and incident
response, while preventing NoID Privacy-managed logs and snapshots from becoming a
long-term activity archive. The policy has two explicit forms:

> At each successful scheduled run, NoID Privacy removes records older than
> 30 days from the age-managed sources explicitly listed below. Daemon-owned
> state that cannot be changed safely while live uses the documented lifecycle
> boundary instead.

Eligible Snapper snapshots use the same 30-day deletion target, with no
`important=yes` or install-baseline exemption. A snapshot that is active or the
Btrfs default cannot be deleted and remains visibly `protected` until another
root is selected. The first observation and a large/backward clock step enter
`clock-guard`, deliberately deferring destructive expiry until a later stable
run. Snapshot retention is therefore a measured target, not an absolute
maximum-age promise.

Running-VM swtpm logs have the same safety exception. Libvirt labels each
active TPM log with that VM's private `svirt_image_t` MCS category; the system
`logrotate_t` domain intentionally cannot read it. NoID Privacy reports such a
basename as `protected` and defers rotation until libvirt restores `virt_log_t`
after the VM stops. A continuously running guest can therefore keep its active
TPM log beyond the target. The policy never weakens VM isolation merely to
enforce log age.

NetworkManager's global `seen-bssids` and `timestamps` databases are another
explicit lifecycle exception. NetworkManager 1.56.1 loads them into memory at
startup, updates the in-memory databases during the session and writes them
back to disk. It exposes no maintained runtime-clear operation. M42 therefore
atomically replaces both files only while NetworkManager has no main process,
ordered before every daemon start. A long bootless session can retain this
global history beyond 30 days. The daily job still sanitizes exact legacy
generated profile keys, but it neither pretends that truncating the live files
cleared RAM nor restarts networking and active VPN sessions merely to enforce
an age limit.

This is a scoped retention policy, not a claim that every old byte has been
physically erased. The timer can run after the exact boundary when the machine
is powered off or suspended; `Persistent=true` catches up at the next boot.
Log rotation also has a small scheduling interval. File and record age is
evaluated against wall time, so a backward or otherwise incorrect system clock
can defer expiry until time catches up. Failures return a non-zero service
status instead of being reported as successful.

For rows with an independent mtime/record-age pruner, 30 days is the maximum
age at a successful scheduled run, not a guarantee of 30 complete days of
history. A logrotate-only `maxage` is weaker: it is evaluated only when that
log rotates, so `snapper.log` can remain beyond day 30 until its next weekly or
size-triggered rotation. Source-owned space/count ceilings can evict records
sooner. In particular, auditd's 10 × 64-MiB ring covered only about 31 hours
under the measured 2026-07-12/13 Workstation/agent load; complete audit
coverage can shorten it further. Journald likewise has a 500-MiB ceiling.
Capacity, rotation cadence and age are independent boundaries and must be
reported.

The active AIDE, libvirt QEMU, tuned, DNF5 and closed/restored swtpm logs use
`copytruncate` because their writers do not share one maintained portable
reopen contract; libvirt's `virtlogd` `SIGUSR1` operation re-executes while
retaining file descriptors. A few records can be lost in the short interval
between copying and truncating. Auditd is different and uses its native
`auditctl --signal rotate` interface, so it does not need `copytruncate`.

## Covered sources

| Source | Boundary | Mechanism / owner |
| --- | --- | --- |
| systemd journal | 30 days, 500 MiB ceiling | `MaxRetentionSec=30day`, `SystemMaxUse=500M`, `MaxFileSec=1week` — M08 |
| current `/var/log/audit/audit.log` | daily rotation | native `auditctl --signal rotate` request — M42 |
| rotated `/var/log/audit/audit.log.[0-9]+` | at most 30 days; 640-MiB ring may evict earlier | numeric-only relative-mtime prune — M42; size/count ring — M12 |
| Anaconda, `ks-*.log`, exact NoID Privacy target-karg/firstboot/crypto-policy-error logs and `/root/*-ks.cfg`; legacy/imported `ks-10-authselect.err` if present | 30 days | exact relative-mtime prune — M42; the current image verifies `ks-10-authselect.err` during compose and removes it before publication |
| active `/var/log/aide/aide.log` | daily rotation | dedicated logrotate stanza — M42 |
| exact shared-log archives and timestamped NoID Privacy AIDE check/review reports | 30 days | numeric/dateext-only archive matching plus exact report-name mtime prune; independent of logrotate's rotate-time-only `maxage` evaluation — M42 |
| user-owned AIDE database and accepted-database archives | no automatic deletion | trust evidence is outside log retention; review/export/remove it explicitly — M13 |
| active libvirt QEMU, tuned and DNF5 logs | daily rotation | dedicated system-logrotate stanzas — M42 |
| stopped/restored per-VM swtpm logs | daily rotation when labeled `virt_log_t`; removed-domain logs at Fedora's default `var_log_t` label require exact tss ownership, safe mode and one link; active `svirt_image_t` logs are visibly protected/deferred | isolated exact-path rotation in `noid-misc-logs-prune` — M42 |
| their numeric/dateext archives | 30 days | exact numeric or `YYYYMMDD` archive matching, `maxage 30` plus independent mtime prune — M42 |
| UPower `history-*.dat` | loaded-device records: native 7-day save-time cap; old whole files: stopped-daemon pre-start prune | UPower 1.91.3 culls records in its own consistent writer; M42 never infers inactivity from mtime and never deletes while the daemon owns that writer |
| NetworkManager global `seen-bssids` and `timestamps` | cleared before every daemon start; a bootless session may exceed 30 days | stopped-daemon, main-PID-verified atomic replacement ordered through the NetworkManager unit — M42 |
| legacy/imported per-profile `[wifi]` / `[802-11-wireless] seen-bssids=` and `[connection] timestamp=` | stripped daily when present | section-aware, metadata-guarded atomic exchange; native offline parse, exact per-file `nmcli connection load` while the daemon runs, and byte-for-byte rollback on rejection — M42 |
| `wtmp` and `btmp` | daily rotation; archives max 30 days | replacement logrotate stanzas without the stock `minsize` bypass plus independent exact archive prune — M42 |
| `snapper.log` | weekly or at 10 MiB; archives older than 30 days removed at the next qualifying rotation | `maxsize`, rotate-time-only `maxage 30`, `rotate 30` — M20 |
| every eligible numbered Snapper snapshot | 30-day target | authoritative Snapper JSON plus `snapper -c root delete --sync`; includes `important=yes` and `baseline-install`, protects active/default roots and guards discontinuous clocks — M20 |

Saved Wi-Fi profiles are not deleted: SSIDs, credentials, manual `bssid=`
pins and MAC-cloning settings are user configuration rather than generated
connection history. NetworkManager's private `internal-*.lease` files are also
retained for lease continuity; they can reveal a last assigned address and a
per-interface recency signal through their mtime. Paired Bluetooth devices are
retained when the user opts into Bluetooth. Those deliberate exceptions avoid
forced daily reacquisition or re-authentication and are documented here rather
than hidden behind an absolute privacy claim.

Clearing NetworkManager's global generated state at the next daemon start has
bounded UX effects: hidden SSIDs can take another scan cycle to rediscover, and
equal-priority autoconnect candidates lose their last-activation recency
tie-break. Assign explicit `autoconnect-priority` values when deterministic
preference between saved networks matters.

## Not covered by this mechanism

The retention jobs do not delete or age:

- user documents, downloads, shell history, browser profiles, mail, chat,
  Flatpak/app data or backups;
- saved Wi-Fi profiles, NetworkManager's private `internal-*.lease` state and
  opted-in Bluetooth pairing state;
- required system identity/configuration such as `/etc/machine-id`, account
  records and firmware-update state;
- consent/update evidence in `~/.local/state/noid-privacy/agent-updates.log`
  and `~/.local/state/noid-privacy/extension-updates.log`, and LUKS-backup
  safety evidence in `/var/lib/noid-privacy/luks-backup.log`;
- the add-on last-check state in `~/.local/state/noid-privacy/extension-checks`.
  It needs no ageing rule: it keeps exactly one overwritten line per managed
  component, and `noid-status` reads it to report add-on patch age without
  issuing any network request;
- data written to other filesystems, removable media, cloud services or
  remote logs;
- freed blocks, Btrfs copy-on-write remnants, SSD over-provisioned areas,
  controller caches or prior disk images.

Deleting a file is not cryptographic sanitization. Full-disk encryption
protects data while the volume is locked, but an unlocked system or a storage
forensics workflow has a different threat model. Use an amnesic live system or
appropriate media sanitization when that is the requirement.

## Scheduled activity

The relevant jobs are staggered and use `RandomizedDelaySec=`. Times are base
times, not exact execution deadlines:

| Base time | Job | Action |
| --- | --- | --- |
| daily | system logrotate | rotate active AIDE/libvirt/tuned/DNF5/wtmp/btmp logs |
| before every NetworkManager start | `noid-nm-privacy-prune` | atomically clear the two global RAM-backed history databases while no daemon process exists |
| daily (00:00) + up to 2 h jitter | `noid-nm-privacy-prune` | sanitize exact legacy generated keys in system profiles; defer global state while the daemon runs |
| before every UPower start | `noid-misc-logs-prune` | prune exact old UPower history files while no daemon process can own the native writer |
| 07:00, only after the user accepts a baseline and enables AIDE | `aide-check.service` | integrity check with a timestamped report |
| 07:25 | `noid-auditd-rotate` | force auditd rotation |
| 07:30 | `noid-install-logs-prune` | prune install-time artifacts |
| 07:35 | `noid-audit-prune` | prune rotated audit logs |
| 07:40 | `noid-snapper-prune` | prune eligible snapshots beyond the target; report protected/clock-guard state |
| 07:45 + up to 20 min jitter | `noid-misc-logs-prune` | rotate closed/restored swtpm logs; defer active VM-protected logs; prune exact AIDE/log/accounting archives; defer UPower files while its daemon runs |

`Persistent=true` means missed NoID Privacy timers run after the next boot. Logrotate
is driven by Fedora's normal `logrotate.timer`. The other M42 timer windows are
07:25 + up to 15 minutes, 07:30 + up to 30 minutes and 07:35 + up to
25 minutes; systemd's timer accuracy can add a small scheduling offset.

UPower 1.91.3 culls loaded-device records older than seven days whenever its
native writer saves them, but a quiet device file can have an older mtime and
UPower exposes no cooperating external-prune lock. NoID Privacy therefore never
uses mtime as proof that a device is inactive: it removes exact old whole files
only at the stopped-daemon boundary before UPower starts. A continuously running
bootless session can retain such an untouched file beyond 30 days; the next
UPower start restores the boundary without a daily daemon restart or writer race.

## AIDE and baseline trade-off

NoID Privacy serializes AIDE checks and explicit candidate preparation/commit with
`/var/lock/noid-aide.lock`, uses one AIDE worker, and applies memory and time
limits. Each run gets a timestamped report. Preparing a candidate never makes
it active; the user must review the report and confirm the exact SHA-256. M42
keeps the shared `aide.log` under daily rotation and independently deletes its
exact old archives plus timestamped reports based on their original mtime. It
does not rotate those immutable reports because rotation would refresh their
archive mtime and extend retention.

The active AIDE database and its accepted-database archives are trust evidence,
not ordinary logs, and are never removed by the scheduled retention job. The
`baseline-install` Snapper snapshot is different: it is a root recovery
snapshot and becomes deletion-eligible under M20's documented 30-day target
unless it is active/default at that run. Export a trusted AIDE
database to controlled off-host storage when required and verify the copy:

```bash
sudo gunzip -t /var/lib/aide/aide.db.gz
sudo cp -p /var/lib/aide/aide.db.gz /path/to/off-host/aide-install.db.gz
sudo sha256sum /var/lib/aide/aide.db.gz | \
    sudo tee /path/to/off-host/aide-install.db.gz.sha256
sudo cmp /var/lib/aide/aide.db.gz /path/to/off-host/aide-install.db.gz
```

Off-host storage has its own confidentiality and retention policy; NoID Privacy does
not choose or mount it automatically.

## Inspection and opt-out

Inspect current state before changing it:

```bash
systemctl list-timers 'noid-*prune*' noid-auditd-rotate.timer
systemctl --failed
sudo test ! -e /run/noid-privacy/audit-storage-degraded
sudo journalctl -u noid-snapper-prune.service \
  -u noid-misc-logs-prune.service --since today
sudo cat /usr/local/sbin/noid-misc-logs-prune.sh
```

Disabling only the NetworkManager timer stops the daily profile pass, but the
pre-start global-history boundary remains attached to NetworkManager. Use the
root-owned marker as well for a complete opt-out:

```bash
sudo install -m 0600 -o root -g root /dev/null \
  /etc/noid-privacy/disable-nm-history-prune
sudo systemctl disable --now noid-nm-privacy-prune.timer

# Restore the shipped behavior:
sudo rm -f /etc/noid-privacy/disable-nm-history-prune
sudo systemctl enable --now noid-nm-privacy-prune.timer
```

The marker is evaluated on every service start; no daemon reload is needed.
Removing it does not interrupt the current connection. Global state is cleared
at the next ordinary NetworkManager start. An administrator can choose a
maintenance-window restart for immediate effect, but M42 never does so
automatically because that would drop networking and active VPN sessions.

Changing only a script's `CUTOFF_DAYS` does not update related logrotate or
journald limits. Treat the boundary as a cross-module policy and change every
row that applies. Package upgrades may create `.rpmnew` files for modified
package-owned logrotate stanzas; review them rather than replacing NoID Privacy's
active policy blindly.

## Primary implementation references

- [NetworkManager 1.56.1 settings database startup and shutdown](https://github.com/NetworkManager/NetworkManager/blob/1.56.1/src/core/settings/nm-settings.c)
  and its documented
  [`connection.timestamp`](https://networkmanager.dev/docs/api/latest/settings-connection.html)
  / [`802-11-wireless.seen-bssids`](https://networkmanager.dev/docs/api/latest/settings-802-11-wireless.html)
  read-only state.
- [UPower 1.91.3 history implementation](https://gitlab.freedesktop.org/upower/upower/-/blob/v1.91.3/src/up-history.c),
  including its native seven-day loaded-record ceiling.
- [libvirt 12.0.0 `virtlogd` configuration](https://gitlab.com/libvirt/libvirt/-/blob/v12.0.0/src/logging/virtlogd.conf)
  and [daemon re-exec semantics](https://gitlab.com/libvirt/libvirt/-/blob/v12.0.0/docs/manpages/virtlogd.rst);
  `SIGUSR1` retains file descriptors and is not a reopen-based logrotate hook.
- [Linux Audit userspace 4.1.4's daemon-control rationale](https://github.com/linux-audit/audit-userspace/blob/v4.1.4/README.md#starting-and-stopping-the-daemon),
  including the native `auditctl --signal` path that preserves the initiating
  login identity.
- [`logrotate(8)` 3.22.0](https://github.com/logrotate/logrotate/blob/3.22.0/logrotate.8.in)
  for `maxage`, `copytruncate` and their timing/loss-window semantics.

## Ownership

- M08: journald time/space ceiling.
- M13: AIDE check wrapper and explicit user-owned candidate review/commit.
- M20: Snapper log maxage policy and snapshot deletion target.
- M25: update-time check-only AIDE evidence; no database replacement or pruning.
- M42: audit/install/misc/NetworkManager pruning, daily audit rotation and
  active-log policies; AIDE trust databases are excluded.
- M99: build-time presence checks and rejection of compose-created AIDE trust state.

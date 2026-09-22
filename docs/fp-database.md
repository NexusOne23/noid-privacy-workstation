# Expected-change and false-positive review database

An event is not benign merely because it resembles a prior event. Match the
process, path, package/version, operation, timing and final state; investigate
anything that differs. This document records scoped expected-change classes and
the reason the image suppresses some volatile paths.

## AIDE exclusions and boundaries

Module 13 excludes selected high-churn/self-referential paths from AIDE. These
are monitoring-scope decisions, not alternative integrity guarantees.

| Path/class | Why excluded | What remains |
|---|---|---|
| directory entry `/etc/pam.d`, `/root`, `/boot/grub2` | expected parent-directory metadata churn | children remain covered by broader rules; confirm exact anchored regex |
| `/var/log/audit` | AIDE activity itself changes audit logs | auditd retention/permissions; log contents are outside AIDE coverage |
| `/var/log/journal` | active journal files rotate/change continuously | journald controls/retention; FSS is not assumed available on every build |
| `boot.log` and dated rotations | truncate/rewrite/rotation behavior | log integrity is outside AIDE; use journal/build evidence for diagnosis |
| `/.snapshots` | recursively indexing every root snapshot multiplies database size and change reports | active root is tracked; Btrfs CoW is not authenticated integrity |
| runtime-generated firewall/USB/policy state listed in M13 | generated after the compose baseline and expected to change | generator/config/helper code remains tracked where listed |
| AIDE/retention report directories | the scanner/pruner writes timestamped output | report review/permissions; not content monitoring by the same database |

The EFI System Partition is **not excluded**. It uses a VFAT-safe `ESP` rule
that tracks ownership/mode/size and SHA-256/SHA-512 content without relying on
inode, ACL or xattr semantics. Secure Boot is not a substitute for AIDE coverage
of bootloader/config files.

Check the exact rule match:

```bash
sudo aide --config=/etc/aide.conf \
  --path-check=f:/boot/efi/EFI/fedora/shimx64.efi
grep -nE '^ESP =|^/boot/efi ESP|^!/boot/efi' /etc/aide.conf
```

Any unanchored/widened exclusion is a security regression. Review
`kickstart/snippets/13-aide-welcome.ks` before adding another path.

## AIDE return codes

AIDE uses bit values for added, removed and changed entries; codes 1–7 can be a
successful integrity comparison that found differences. Higher/error codes or a
missing candidate database are not ordinary drift.

```bash
set +e
sudo /usr/local/sbin/noid-aide-check.sh
rc=$?
set -e
printf 'AIDE rc=%s\n' "$rc"
```

The supported wrapper validates the active database/configuration boundary,
serializes the run and preserves a timestamped report while returning AIDE's
bitmask. The service declares 1–7 as successful execution so systemd does not
confuse “differences found” with “scanner failed”. The user still must review
those differences. Never commit a baseline candidate solely because the
service status is green.

## SELinux AVC review

Do not maintain a blanket “benign AVC” list across Fedora policy/kernel
versions. For each recurrence:

```bash
sudo ausearch -m AVC,USER_AVC -ts boot | tail -100
sudo audit2why -a 2>/dev/null | tail -100
rpm -qf /path/from-the-denial 2>/dev/null || true
systemctl --failed
```

Verify whether the denied action completed, whether it was required and whether
the domain/path/package match the reviewed case. Do not pipe an unexplained AVC
into `audit2allow` and install the result.

## Firewall denial logging

`LogDenied=off` is the release default. When temporarily enabled for diagnosis,
ordinary gateway/client discovery, retransmissions and blocked LAN application
attempts can appear. A gateway source address or familiar destination port is
not enough to classify traffic benign; confirm the source MAC/interface,
connection owner, timing and intended workflow.

```bash
firewall-cmd --get-log-denied
journalctl -u firewalld --since '10 minutes ago'
sudo nft monitor trace
```

Turn expensive/verbose tracing off after the bounded diagnostic.

## Listener review

Loopback-only is a narrower exposure than wildcard/LAN binding, but any local
process may still connect. Attribute every listener to an executable, user,
service/container and expected feature:

```bash
sudo ss -lntup
sudo lsof -nP -i 2>/dev/null | head -100
systemctl --type=service --state=running
systemctl --user --type=service --state=running
```

Examples that may be legitimate only while their feature is active:

- a WireGuard UDP socket associated with the reviewed NetworkManager/VPN
  interface (`wg show`);
- a loopback IPC/API listener owned by VSCodium, an AI extension or a local
  model server;
- a loopback mail bridge owned by the explicitly launched bridge process.

Encrypted protocol traffic is still parser/DoS attack surface, and a wildcard
socket is not safe merely because the protocol normally authenticates peers.
The inbound DROP policy is defense in depth, not a reason to ignore the owner.

## Adding an expected-change entry

1. Reproduce under a disposable or well-observed state.
2. Capture the exact source, operation, path/socket and final result.
3. Exclude compromise indicators and explain why the operation is necessary.
4. Prefer fixing the noisy producer or narrowing the monitored attribute over
   excluding a subtree.
5. Add a structural/runtime regression test for the intended scope.
6. Record the security visibility lost by any suppression.

If the cause cannot be explained and reproduced, it is not a false positive.

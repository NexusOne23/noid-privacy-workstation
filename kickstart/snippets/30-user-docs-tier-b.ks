# ============================================================================
# Module 30 — User Documentation Tier B (Module-specific user-docs + CLI)
# Status: LOCKED 2026-08-12 (v58) — document the provider-choice and location trade-off.
#
# Ships:
#   - 02-system-security.md   sysctl / SELinux / auditd / kernel lockdown
#   - 03-firewall-zones.md    firewalld zones + block-lan-out + how to allow
#   - 05-lan-isolation.md     LAN isolation rationale + per-device allow
#   - 08-masked-services.md   masked services + excluded packages + undo paths
#   - 11-dns-custom.md        change DNS provider + NTP adjustment
#   - 00-cheatsheet.md        quick reference of noid-* commands + diagnostics
#   - /usr/local/bin/noid-help  docs + complete installed command inventory
#   - /usr/local/bin/noid       discoverable `noid --help` entry point
#
# Doc-accuracy constraints (verified; keep on future edits):
#   - noid-update-all.sh is documented WITHOUT sudo (the script root-guards
#     and refuses sudo invocation).
#   - Captive-portal flow uses the complete `noid-lan-allow` boundary, never
#     a firewalld-only policy deletion. Prefer one exact temporary peer; use
#     the disclosed broad `on`/immediate-`off` path only when the portal's
#     local endpoints cannot be identified.
#   - bluetooth + geoclue are NOT in the /dev/null mask list (they ship off
#     via rfkill/flag + gsettings; re-enable via noid-toggle-bluetooth /
#     noid-toggle-location) — the doc keeps them OUT of the mask list.
#   - avahi: base package installed + daemon masked; discovery sub-packages
#     and PipeWire's optional RAOP/AirPlay config are excluded (D4/D5).
#   - Reviewed counters: M08 has exactly 82 source masks and all NoID Privacy modules
#     deploy 96 unique masks. tests/08-mask-list-structural.sh pins M08; the
#     live count can additionally include Fedora preset masks.
#
# Doc-aggregator duty (class — M30 is HIGH-risk): the Tier-B docs quote
# other modules' counts/lists (M02 sysctl, M08/M05/M11/M24 masks, M12
# auditd rules, M11 NTS server set). When an upstream module changes such
# content, re-verify the corresponding doc sections in the SAME cycle
# (tests/30 pins the NTS server list + several mask-list entries against
# the extracted heredocs).
#
# Conventions: [M30] log-prefix (NoID Privacy-wide [M##] pattern). Verify-block
# keyword checks use literal grep -Fqi (Lesson #30).
#
# Cross-references: every doc points to its owning module's kickstart
# snippet for authoritative source. Package modifications: NONE.
#
# Shipped Markdown target: /usr/share/doc/noid-privacy/02-system-security.md
# Shipped Markdown heredoc: SYSCTL_EOF
# Shipped Markdown target: /usr/share/doc/noid-privacy/03-firewall-zones.md
# Shipped Markdown heredoc: FW_EOF
# Shipped Markdown target: /usr/share/doc/noid-privacy/05-lan-isolation.md
# Shipped Markdown heredoc: LAN_EOF
# Shipped Markdown target: /usr/share/doc/noid-privacy/08-masked-services.md
# Shipped Markdown heredoc: SVC_EOF
# Shipped Markdown target: /usr/share/doc/noid-privacy/11-dns-custom.md
# Shipped Markdown heredoc: DNS_EOF
# Shipped Markdown target: /usr/share/doc/noid-privacy/00-cheatsheet.md
# Shipped Markdown heredoc: CHEAT_EOF
# ============================================================================

%packages --exclude-weakdeps
# No packages.
%end

%post --log=/var/log/ks-30-user-docs-tier-b.log --erroronfail
set -euo pipefail

PHASE=""
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [M30] ${PHASE}: $*"; }
die() { log "FAIL: $*"; exit 1; }
DOC_TMP=""
BIN_TMP=""
STAMP_TMP=""
STAMP_PUBLICATION_ACTIVE=0
STAMP_DIR=/var/lib/noid-privacy
STAMP="$STAMP_DIR/stamp-30-user-docs-tier-b.ok"
cleanup() {
    if [ -n "${DOC_TMP:-}" ]; then
        rm -f -- "$DOC_TMP" || true
    fi
    if [ -n "${BIN_TMP:-}" ]; then
        rm -f -- "$BIN_TMP" || true
    fi
    if [ -n "${STAMP_TMP:-}" ]; then
        rm -f -- "$STAMP_TMP" || true
    fi
    if [ "${STAMP_PUBLICATION_ACTIVE:-0}" -eq 1 ]; then
        if ! rm -f -- "$STAMP"; then
            log "FAIL: could not retire incomplete Module 30 health stamp"
        fi
        sync -- "$STAMP_DIR" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

publish_doc() {
    local target=$1
    [ -n "$DOC_TMP" ] || die "internal error: no document temporary file"
    chmod 0644 -- "$DOC_TMP"
    chown root:root -- "$DOC_TMP"
    sync -- "$DOC_TMP" \
        || die "cannot sync staged Tier-B documentation: $target"
    mv -fT -- "$DOC_TMP" "$target"
    DOC_TMP=""
    restorecon -F -- "$target" \
        || die "restorecon failed for Tier-B documentation: $target"
    matchpathcon -V "$target" >/dev/null \
        || die "SELinux context differs for Tier-B documentation: $target"
    sync -- "$target" "$DOC_DIR" \
        || die "cannot sync published Tier-B documentation: $target"
}

publish_bin() {
    local target=$1
    [ -n "$BIN_TMP" ] || die "internal error: no executable temporary file"
    bash -n "$BIN_TMP" \
        || die "bash syntax invalid before publishing: $target"
    chmod 0755 -- "$BIN_TMP"
    chown root:root -- "$BIN_TMP"
    sync -- "$BIN_TMP" \
        || die "cannot sync staged Tier-B executable: $target"
    mv -fT -- "$BIN_TMP" "$target"
    BIN_TMP=""
    restorecon -F -- "$target" \
        || die "restorecon failed for Tier-B executable: $target"
    matchpathcon -V "$target" >/dev/null \
        || die "SELinux context differs for Tier-B executable: $target"
    sync -- "$target" "$BIN_DIR" \
        || die "cannot sync published Tier-B executable: $target"
}

log "=== Module 30 User Documentation Tier B start ==="
command -v restorecon >/dev/null 2>&1 \
    || die "restorecon is required for fail-closed SELinux labeling"
command -v matchpathcon >/dev/null 2>&1 \
    || die "matchpathcon is required for fail-closed SELinux verification"

# M30_HEALTH_INVALIDATION_BEGIN
# This stamp covers six documents and both CLI entry points. Validate the shared
# state boundary without normalizing drift, then retire prior success before
# the first owned document or executable mutation.
PHASE="P0-health-invalidation"
if { [ -e "$STAMP_DIR" ] || [ -L "$STAMP_DIR" ]; } \
   && { [ ! -d "$STAMP_DIR" ] || [ -L "$STAMP_DIR" ]; }; then
    die "$STAMP_DIR exists but is not a real directory"
fi
if [ ! -e "$STAMP_DIR" ]; then
    install -d -m 0755 -o root -g root "$STAMP_DIR"
fi
if [ "$(stat -Lc '%u:%g:%a' -- "$STAMP_DIR" 2>/dev/null || true)" != \
        0:0:755 ]; then
    die "$STAMP_DIR metadata is not root:root 0755"
fi
if ! restorecon -F -- "$STAMP_DIR" \
   || ! matchpathcon -V "$STAMP_DIR" >/dev/null; then
    die "$STAMP_DIR SELinux context is not canonical"
fi
if [ -e "$STAMP" ] || [ -L "$STAMP" ]; then
    if [ ! -f "$STAMP" ] && [ ! -L "$STAMP" ]; then
        die "health-stamp target is not a file or symlink: $STAMP"
    fi
    rm -f -- "$STAMP" \
        || die "cannot invalidate stale Module 30 health stamp"
    sync -- "$STAMP_DIR"
fi
log "  [OK] prior Module 30 health stamp is absent"
# M30_HEALTH_INVALIDATION_END

# ------------------------------------------------------------------------------
# Phase 1 — Ensure doc directory
# ------------------------------------------------------------------------------
PHASE="P1-setup"
DOC_DIR=/usr/share/doc/noid-privacy
BIN_DIR=/usr/local/bin
for dir in "$DOC_DIR" "$BIN_DIR"; do
    if [ -e "$dir" ] || [ -L "$dir" ]; then
        [ -d "$dir" ] && [ ! -L "$dir" ] \
            || die "$dir exists but is not a real directory"
        [ "$(stat -c '%u:%g:%a' -- "$dir" 2>/dev/null)" = "0:0:755" ] \
            || die "$dir existing metadata differs from root:root 0755"
    else
        install -d -m 0755 -o root -g root -- "$dir"
    fi
    restorecon -F -- "$dir" \
        || die "restorecon failed for payload directory: $dir"
    matchpathcon -V "$dir" >/dev/null \
        || die "$dir SELinux context differs"
done

# ------------------------------------------------------------------------------
# Phase 2 — 02-system-security.md
# ------------------------------------------------------------------------------
PHASE="P2-sysctl"
log "Writing 02-system-security.md"

SYSCTL_DOC="$DOC_DIR/02-system-security.md"
DOC_TMP=$(mktemp "$DOC_DIR/.02-system-security.md.XXXXXXXX")
cat > "$DOC_TMP" <<'SYSCTL_EOF'
# System Security — sysctl + SELinux + auditd + Kernel Lockdown

This doc covers the kernel + policy hardening active from boot. You
normally don't interact with any of it — it just runs. But if you
hit unexpected permission denials or want to verify the hardening
is active, this is where to look.

## What's active

### 1. Sysctl parameters

The kernel-hardening parameter set lives in
`/etc/sysctl.d/99-hardening.conf` (the main set — verify the live count
with `sudo grep -cE '^-?[a-z]+\.' /etc/sysctl.d/99-hardening.conf`, the file
is root-only mode 0640) plus three
small fixed-size files: `99-audit-fixes.conf` (3 params:
oops_limit/warn_limit/panic), `99-userns.conf` (1 param:
user.max_user_namespaces=256), and `98-privacy-network.conf` (1 boot-default
parameter from M07: `net.ipv4.ip_forward=0`). An active libvirt routed/NAT
network legitimately changes the runtime value to `1` while it forwards VM
traffic; inspect both the configured boot default and current value rather
than calling that state drift. On
first boot, `noid-wan-ipv6-disable-firstboot.service` (Module 07)
generates `99-wan-ipv6-off.conf` with 1 per-WAN parameter
(`net.ipv6.conf.<iface>.disable_ipv6=1`) per detected WAN interface.
Categories:

- **KASLR + kernel pointer leak prevention** (`kernel.kptr_restrict=2`,
  `kernel.dmesg_restrict=1`, `kernel.unprivileged_bpf_disabled=1`; value 1
  cannot be cleared during the running boot)
- **Network stack hardening** (SYN cookies, IP spoofing, ICMP redirects,
  source routing blocked)
- **TCP timestamp privacy without a protocol downgrade** — NoID Privacy leaves the
  maintained Linux default `net.ipv4.tcp_timestamps=1`; Linux documents a
  random offset for each connection, retaining RFC 7323 RTT measurement and
  PAWS instead of claiming an unmeasured benefit from disabling them
- **Memory safety** (`vm.mmap_rnd_bits=32`, ASLR maximum, kexec disabled)
- **User namespaces limited** (`user.max_user_namespaces=256` —
  allows Flatpak/Podman rootless but caps quantity)

### 2. SELinux in enforcing mode (targeted policy)

- `sestatus` shows `enforcing` (not permissive)
- Violations logged to `/var/log/audit/audit.log`
- Optional desktop notification for the 16 reviewed keyed integrity-change
  categories via Module 12's auditd/auparse plugin. SELinux AVCs remain in the
  audit log but are not indiscriminately shown as popups.

### 3. Auditd (132 ABI-complete rules, immutable)

- Monitors `/etc`, `/boot`, kernel modules, privileged syscalls,
  network config changes
- Rules in `/etc/audit/rules.d/*.rules`, compiled to
  `/etc/audit/audit.rules` at boot
- **Immutable mode (`-e 2`)**: rules cannot be modified after boot.
  Kernel refuses rule changes until reboot.
- Logs to `/var/log/audit/audit.log` (root-only)

### 4. Kernel lockdown mode = integrity

- `/sys/kernel/security/lockdown` shows `[integrity]`
- Disables kernel interfaces that let userspace modify the running kernel,
  including unrestricted kexec and direct kernel-memory access
- Fedora's Secure Boot and kernel-module signature enforcement are separate,
  complementary controls; do not attribute every unsigned-module rejection to
  lockdown alone

## Checking current state

One-screen selected posture overview:
```bash
noid-status
```

Individual checks:
```bash
# SELinux
sestatus

# Auditd
sudo auditctl -s           # enabled=2 means immutable until reboot
sudo auditctl -l | wc -l   # loaded rule count (132 in the reviewed image)
sudo ausearch -ts today    # today's events

# Lockdown
cat /sys/kernel/security/lockdown

# Selected active sysctl parameters
sudo sysctl -a | grep -E 'kptr_restrict|dmesg_restrict|mmap_rnd_bits|max_user_namespaces'

# M07's boot default and its current, possibly libvirt-overridden value
sudo grep -F 'net.ipv4.ip_forward = 0' /etc/sysctl.d/98-privacy-network.conf
sudo sysctl net.ipv4.ip_forward
```

## Reading audit logs

The audit log is verbose and dense. Three patterns:

```bash
# Today's denials only
sudo ausearch -m avc -ts today

# Why was a specific operation denied? (uses sealert)
sudo ausearch -m avc -ts recent | audit2why

# Summary of events by type
sudo aureport --summary -ts today
```

The optional Module 12 popups cover reviewed keyed configuration/integrity
events, not the unbounded stream of SELinux AVC denials. Toggle the plugin with:
```bash
sudo noid-toggle-audit-notify off
sudo noid-toggle-audit-notify on
sudo noid-toggle-audit-notify status  # includes root-owned delivery health
```

## Common false positives

M12's `audit-notify.sh` does NOT maintain a static suppress file. auditd feeds
records into the maintained auparse complete-event assembler, after which the
plugin applies bounded notification-only policy:

- `auid=unset` events (kernel / early-boot) → skipped
- `systemd-udevd`, `kmod`, `auditd` self-activity → skipped
- Events during a running `noid-update-all.sh` (marker file
  `/run/noid-update-running`) → retained by auditd, no popup for the four
  reviewed update keys
- The event AUID must match an unlocked active local graphical logind seat;
  remote, locked, background and other-user sessions receive no path

Repeated AVCs remain an investigation/audit-policy matter rather than popup
filter entries. Example Fedora patterns that still require evidence-based
classification:

- AIDE access denial on the VFAT ESP is **not automatically benign**:
  `/boot/efi` is content-tracked with the filesystem-specific `ESP` rule.
  Confirm the denied operation, current SELinux label and whether the AIDE
  comparison completed before classifying it.
- systemd-logind getattr on `usbguard_tmpfs_t` (benign — logind
  enumerates tmpfs, USBGuard mount is shielded)
- Sandboxed image loaders can legitimately exercise new file types and paths,
  but an AVC still needs its exact source/target contexts and operation checked
  before it is classified

Do not silence an unexplained event at the audit layer. With auditd immutable
mode (`-e 2`) active, runtime rule changes are rejected until reboot. If a
fully investigated keyed event is only popup noise, change the reviewed
notification policy in the canonical plugin source while preserving the audit
rule and record:

```bash
# See the exact keyed event before changing popup policy
sudo ausearch -k sudoers -ts recent

# Check immutable state. enabled=2 means the loaded rules cannot be changed
# until reboot; investigate now and make any reviewed persistent policy edit
# for the next boot rather than claiming a runtime exclusion succeeded.
sudo auditctl -s
```

## Changing the policy (advanced)

If a legitimate app is blocked by SELinux, first identify the exact denial and
fix a wrong label, packaging defect, configuration mismatch or supported
SELinux Boolean at its root. Do not generate a broad allow module as the first
response:

```bash
# Explain the reviewed recent denial
sudo ausearch -m avc -ts recent | audit2allow -w

# Only if the root-cause review proves a local policy is necessary:
sudo ausearch -m avc -ts recent | audit2allow -R
```

Generated rules can grant more access than intended. Narrow the input to the
one application/event, inspect the proposed interfaces and resulting `.te`
source, and obtain policy review before compiling or installing a module.
Switching to permissive globally (`sudo setenforce 0`) defeats the entire MAC
layer and is not a fix.

## Applying a reviewed sysctl exception

```bash
# Example runtime exception for a kernel debugger; this exposes kernel
# pointers and weakens KASLR until it is restored or the machine reboots.
ORIGINAL_KPTR=$(sudo sysctl -n kernel.kptr_restrict)
sudo sysctl -w kernel.kptr_restrict=0
# Do the one reviewed diagnostic, then restore immediately:
sudo sysctl -w "kernel.kptr_restrict=$ORIGINAL_KPTR"

# A persistent exception belongs in a separately reviewed local drop-in;
# do not edit the image-owned 99-hardening.conf.
sudoedit /etc/sysctl.d/zzzz-local-security-exception.conf
sudo sysctl -p /etc/sysctl.d/zzzz-local-security-exception.conf
```

Remove the local drop-in and reapply the original key immediately when the
exception is no longer needed. Routine package updates do not rerun kickstart
`%post`, but an image reinstall or recompose can replace image-owned files.
Record every deliberate hardening exception so it can be reviewed and restored.

## References

- Module 02 source: `kickstart/snippets/02-sysctl.ks` in the project repo — see `/etc/sysctl.d/` on the running system
- [CIS Benchmark RHEL 9](https://www.cisecurity.org/benchmark/red_hat_linux)
- [SELinux user docs — RHEL 9](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/)
- [Linux kernel lockdown parameter](https://docs.kernel.org/admin-guide/kernel-parameters.html)
- [Linux kernel module-signing facility](https://docs.kernel.org/admin-guide/module-signing.html)

SYSCTL_EOF
publish_doc "$SYSCTL_DOC"
log "  [OK] 02-system-security.md written"

# ------------------------------------------------------------------------------
# Phase 3 — 03-firewall-zones.md
# ------------------------------------------------------------------------------
PHASE="P3-firewall"
log "Writing 03-firewall-zones.md"

FW_DOC="$DOC_DIR/03-firewall-zones.md"
DOC_TMP=$(mktemp "$DOC_DIR/.03-firewall-zones.md.XXXXXXXX")
cat > "$DOC_TMP" <<'FW_EOF'
# Firewall Zones — How the firewalld Policy is Laid Out

This image runs firewalld with a default-DROP posture. Physical interfaces and
recognized VPN interfaces reject unsolicited inbound traffic; libvirt keeps
its separately scoped vendor zone when virtualization is installed. Outbound
traffic to the local LAN is blocked (the gateway included).

## Active zones

```bash
sudo firewall-cmd --get-active-zones
```

Typical layout after install:

- `drop` — default zone (unmatched unsolicited inbound packets are silently
  dropped; replies related to host-initiated connections still pass)
- `noid-vpn` — genuine VPN interfaces land here automatically (via Module 06
  dispatcher). Target DROP blocks unsolicited tunnel-side inbound traffic.
- `libvirt` — virtual machines (if @virtualization is installed)

Your physical interface (`enp*`, `wlp*`) lives in `drop` by default.
This means:

- Nothing on the LAN can initiate a connection to you (no SSH probe,
  no SMB scan, no mDNS reply, no Windows device discovery).
- Outbound internet connections work direct-to-WAN or through a configured
  VPN. `noid-vpn` is not by itself a route/DNS killswitch.
- Outbound connections to the LAN are **blocked** by the separate
  `block-lan-out` policy (see next section).

## Block-lan-out policy

A firewalld **policy** (not zone) named `block-lan-out` drops the selected
LAN/discovery services and explicit IPv4/IPv6 local, special-purpose and
multicast destinations. The independent topology boundary also covers every
currently connected physical prefix, including access to the default gateway
address; there is no blanket gateway exception. DHCP still works because
NetworkManager's lease exchange is admitted through the separately correlated
link-layer bootstrap contract rather than an application-level LAN exception.

This exists because on a hostile Wi-Fi (airport, hotel, coffee shop),
a malicious LAN peer could attack services on your machine (e.g. send
crafted mDNS / SSDP / NetBIOS packets). Even if firewalld drops inbound,
your **outbound** DNS / NTP / NetBIOS queries reveal your presence.
Blocking LAN application egress plus inbound DROP prevents ordinary LAN peers
from initiating useful host traffic. Minimal DHCP/ARP control traffic needed
for the WAN gateway remains visible on the physical segment.

Consequence: you can't reach other devices on your LAN (NAS, printer,
local test server) by default. That's intentional.

## How to allow a specific LAN device

Use the NoID Privacy Network app, or its `noid-lan-allow` backend. It updates
both the firewalld policy and the topology-aware nftables allow set atomically;
a hand-written firewalld exception alone is intentionally insufficient.

```bash
# Permanent host-initiated access to one peer
sudo noid-lan-allow --add 192.168.1.50 --direction outbound

# The same exception, automatically revoked after 30 minutes
sudo noid-lan-allow --add 192.168.1.50 --direction outbound --temp 30

# Temporary peer-initiated TCP access to one local port
sudo noid-lan-allow --add 192.168.1.50 --direction inbound \
  --protocol tcp --ports 8080 --temp 30

# Revoke and verify
sudo noid-lan-allow --revert 192.168.1.50
sudo noid-lan-allow --list
```

Temporary grants store a root-owned absolute deadline plus a same-boot
monotonic deadline. An installed reconciler runs before NetworkManager and
then every few seconds, so reboot or a lost PID 1 transient unit cannot turn a
temporary grant into a permanent one. Missing, invalid, expired or
clock-rollback-inconsistent metadata is revoked fail-closed.

Only one validated, directly attached IPv4 address is accepted. IPv6 per-IP
exceptions are deliberately rejected because the mandatory XDP boundary has no
IPv6/NDP peer-identity and return-flow admission contract; offering an IP-only
rule would be both nonfunctional and spoofable. Subnet-wide exceptions are not
part of the supported app workflow.

The bounded raw ARP observation must agree with exactly one device-scoped
kernel-neighbour identity, and the installed pin must then pass one exact
`PERMANENT` postcheck. This is trust on first use (TOFU), not cryptographic
Ethernet authentication.

## Allowing an inbound service (e.g. temporary HTTP server)

The Network app supports `Inbound only` and `Both directions`; the CLI
equivalent must name TCP or UDP and one port or range:

```bash
sudo noid-lan-allow --add 192.168.1.50 --direction inbound \
  --protocol tcp --ports 8080 --temp 30
```

This grants only the exact, directly attached IPv4/ARP/interface identity and
source/protocol/port tuple through every managed layer. `--direction both`
additionally permits host-initiated traffic to the peer. Do not add a
standalone firewalld exception: it cannot establish the required XDP/TC and
peer-identity state.

## Verifying the current ruleset

```bash
# Full dump
sudo firewall-cmd --list-all-zones
sudo firewall-cmd --list-all-policies

# Confirm the intentional no-packet-log posture and inspect controller events
sudo firewall-cmd --get-log-denied
sudo journalctl -b -t noid-lan-topology --no-pager -n 50
```

The expected `--get-log-denied` result is `off`: NoID Privacy does not create a
background log of every denied packet because that would add noise and retain
destination metadata. The `noid-lan-topology` entries report policy refresh
health, not per-packet events. Use an explicitly time-bounded packet capture
only when a concrete troubleshooting case requires that extra evidence.

## Recovering from a configuration mistake

Do **not** use `firewall-cmd --reset-to-defaults`: it removes the permanent
NoID Privacy policies as well as local changes. First validate and compare
runtime with permanent state. A reload safely drops runtime-only additions:

```bash
# See runtime and permanent state
sudo firewall-cmd --list-all
sudo firewall-cmd --permanent --list-all
sudo firewall-cmd --check-config

# Revert runtime-only additions to the reviewed permanent state
sudo firewall-cmd --reload

# Remove one exact permanent rule that you added (example)
sudo firewall-cmd --permanent --zone=drop --remove-port=8080/tcp
sudo firewall-cmd --reload
```

If permanent NoID Privacy policy is damaged, restore the exact reviewed files
through a checked Snapper rollback, image repair/reinstall, or a reviewed
deployment from the matching repository revision. Do not reconstruct a
security boundary from guessed commands. The principal policy files are:

- `/etc/firewalld/policies/block-lan-out.xml`
- `/etc/firewalld/policies/block-lan-out-vms.xml` (derived VM-forwarding peer)
- `/etc/firewalld/policies/allow-host-ipv6.xml`
- Direct rules: `sudo firewall-cmd --direct --get-all-rules`

## References

- [firewalld(1)](https://firewalld.org/documentation/man-pages/firewalld.html)
- Module 03 source: `kickstart/snippets/03-firewalld.ks` in the project repo — see the file's header for design rationale

FW_EOF
publish_doc "$FW_DOC"
log "  [OK] 03-firewall-zones.md written"

# ------------------------------------------------------------------------------
# Phase 4 — 05-lan-isolation.md
# ------------------------------------------------------------------------------
PHASE="P4-lan"
log "Writing 05-lan-isolation.md"

LAN_DOC="$DOC_DIR/05-lan-isolation.md"
DOC_TMP=$(mktemp "$DOC_DIR/.05-lan-isolation.md.XXXXXXXX")
cat > "$DOC_TMP" <<'LAN_EOF'
# LAN Isolation — What's Blocked + How to Allow a Device

Complementary to [03-firewall-zones.md](03-firewall-zones.md). This
doc focuses on application/discovery isolation: mDNS, SMB, NetBIOS, WSD,
CUPS-browse and SSDP, plus link-layer LLDP. All are off by default.

## What's blocked

### Application, discovery and link-layer protocols

The following discovery / chatter protocols are disabled in the image:

| Protocol | Used for | Package/service state |
|---|---|---|
| **mDNS / Avahi** | Printer discovery, Bonjour, `.local` resolution | `avahi-daemon` masked; PipeWire RAOP config excluded |
| **SMB / CIFS** | Windows file sharing | `samba`, `cifs-utils` excluded |
| **WSD** (Web Services Discovery) | Windows network printer / scanner discovery | `wsdd` masked (false-positive reported as listener) |
| **NetBIOS** | Legacy Windows name resolution | No daemon installed |
| **CUPS-browsed** | Network printer auto-discovery | `cups-browsed` masked if CUPS installed |
| **SSDP / UPnP** | IGD, DLNA, Sonos | No daemon installed |
| **LLDP** | Link-Layer Discovery Protocol (enterprise switches) | `lldp=0` per-connection (Module 23) |
| **WSDD** | Windows network discovery | `wsdd2` blocked at service + firewalld level |

### Layer 3-4 (firewalld block-lan-out policy — see 03-firewall-zones.md)

Outbound host traffic to static private/link-local/reserved ranges is dropped.
The topology-aware nftables layer additionally drops every directly connected
physical prefix, even when it uses unusual/public address space. Only minimal
DHCP/ARP link control and explicit per-IP Network-app exceptions remain.

### Layer 2 (ARP hardening — Module 04)

- First-boot/pre-up learning pins the exact IPv4 gateway as a permanent kernel
  neighbour; explicit IPv4 LAN exceptions receive the same permanent IP/MAC
  pin only after the bounded raw ARP result agrees with exactly one
  device-scoped kernel-neighbour identity and an exact `PERMANENT` postcheck.
- Standard ARP remains enabled. This preserves NetworkManager's native IPv4
  Address Conflict Detection (RFC 5227), announcements, address defence and
  ordinary replies; NoID Privacy does not claim Ethernet frames are authenticated.
- The XDP parser admits structurally valid standard ARP before AF_PACKET while
  continuing to default-drop unrelated unsolicited EtherTypes/IP traffic.

## Why this matters

On a public Wi-Fi, these protocols leak information:
- mDNS broadcasts your hostname + services
- SMB reveals your OS (Windows / Samba / macOS)
- WSD is the modern replacement that leaks similar info
- LLDP can reveal switch topology if you're on an enterprise LAN

Together with physical-interface DROP, `block-lan-out`, and the topology
guard, this prevents ordinary LAN clients from exchanging useful application
traffic with the host. Link-layer DHCP/ARP control remains observable.

## Consequences you might notice

Things that won't work by default:

- **Discovering devices by name**: `ping myprinter.local` fails
  (no mDNS resolver)
- **Browsing network shares**: GNOME Files → "Other Locations" is empty
- **Casting to Chromecast / AirPlay**: no SSDP / Bonjour
- **Windows "Network" browsing**: the neighbors list is empty
- **Enterprise print servers auto-appearing**: won't

Things that still work by default:

- Internet destinations outside the blocked LAN/topology ranges, subject to
  the active firewall and optional VPN configuration
- DHCP and ARP needed to establish the local link

Direct private-IP connections do **not** bypass the policy. First add an exact
device exception, then connect:

```bash
sudo noid-lan-allow --add 192.168.1.50 --direction outbound
ssh 192.168.1.50
# or: smb://192.168.1.50/share
```

## How to allow a specific device

See [03-firewall-zones.md](03-firewall-zones.md) "How to allow a
specific LAN device". The supported escape hatch updates the complete
firewalld, nftables, XDP/TC and peer-identity boundary; a protocol daemon or
firewalld rule alone is insufficient.

If you also need mDNS (e.g. you want to ping your printer by name):

Prefer the device's exact IPv4 address plus a `noid-lan-allow --add` exception.
NoID Privacy deliberately does not advertise a partial “enable Avahi” recipe:
working multicast discovery would require a separately reviewed opt-out across
the physical-interface inbound filter, topology/XDP/TC boundary, firewalld,
NetworkManager mDNS setting, systemd-resolved and the masked Avahi units.
Enabling only one or two layers is nonfunctional and creates a misleading
security state. Avahi also advertises host identity and services to the LAN.

For PipeWire AirPlay/RAOP output discovery, the separate Fedora config package
is additionally required, but installing it does not cross those network
boundaries:

```bash
sudo dnf install pipewire-config-raop
systemctl --user restart pipewire.service pipewire-pulse.service wireplumber.service
```

Installing it makes PipeWire request Avahi whenever the audio service starts.
Undo this package-side opt-in with:

```bash
sudo dnf remove pipewire-config-raop
systemctl --user restart pipewire.service pipewire-pulse.service wireplumber.service
```

## Re-enabling Samba

If you need to access a Windows / NAS SMB share:

```bash
sudo dnf install samba-client cifs-utils

# Add the exact NAS as an outbound peer first
sudo noid-lan-allow --add 192.168.1.50 --direction outbound

# Refuse to erase an existing credential file, then edit outside shell history
if sudo test -e /root/.nas-creds || sudo test -L /root/.nas-creds; then
    echo "Refusing to overwrite existing /root/.nas-creds" >&2
else
    sudo install -m 0600 -o root -g root /dev/null /root/.nas-creds
    sudoedit /root/.nas-creds
    sudo chmod 0600 /root/.nas-creds
    sudo chown root:root /root/.nas-creds
    sudo restorecon -F /root/.nas-creds
fi
# File contents:
# username=alice
# password=replace-with-the-real-password

# Require SMB 3.1.1 plus transport encryption. Relax only for a reviewed
# legacy NAS compatibility requirement.
sudo mkdir -p /mnt/nas
sudo mount -t cifs //192.168.1.50/share /mnt/nas \
    -o credentials=/root/.nas-creds,iocharset=utf8,vers=3.1.1,seal,nosuid,nodev,noexec

# Persistent fstab entry:
# //192.168.1.50/share /mnt/nas cifs credentials=/root/.nas-creds,iocharset=utf8,vers=3.1.1,seal,nosuid,nodev,noexec,_netdev,x-systemd.automount 0 0
```

Only install `samba-client` — the `samba` (server) package is a much
larger attack surface and normally is not needed for client mounts. Keep the
credentials file root-only. Keep SMB 3.1.1, encryption and `noexec` unless an
exact server or workload requirement has been reviewed and documented.

## TunnelVision (CVE-2024-3661) mitigation reminder

Module 23's NetworkManager dispatcher removes non-default DHCP Option 121
classless static routes after activation/renewal, preventing a malicious LAN
DHCP server from injecting routes that bypass your VPN. See
[06-vpn-setup.md](06-vpn-setup.md) safety-net section for the
trade-off analysis (vs policy-routing alternative).

## Verifying LAN isolation

```bash
# Which chatter daemons are running?
sudo systemctl list-units --type=service --state=running | \
    grep -iE 'avahi|cups|wsdd|samba|nmbd|upnp|sonos'
# Expected: no output

# Inspect TCP and UDP listeners and classify every non-loopback bind
sudo ss -H -lntup

# mDNS probe (should time out)
timeout 3 avahi-browse -a 2>/dev/null || echo "avahi not installed or not running — good"
```

Do not assume a universal empty listener list: local platform services and
deliberately installed applications can listen. Investigate the exact
address, protocol, process and active firewall zone.

## References

- Module 05 source: `kickstart/snippets/05-lan-isolation.ks` in the project repo — see the file's header for design rationale
- [TunnelVision CVE-2024-3661](https://www.leviathansecurity.com/blog/tunnelvision)

LAN_EOF
publish_doc "$LAN_DOC"
log "  [OK] 05-lan-isolation.md written"

# ------------------------------------------------------------------------------
# Phase 5 — 08-masked-services.md
# ------------------------------------------------------------------------------
PHASE="P5-services"
log "Writing 08-masked-services.md"

SVC_DOC="$DOC_DIR/08-masked-services.md"
DOC_TMP=$(mktemp "$DOC_DIR/.08-masked-services.md.XXXXXXXX")
cat > "$DOC_TMP" <<'SVC_EOF'
# Masked Services + Excluded Packages — Authoritative List + How to Undo

The image uses TWO different mechanisms to remove unwanted software:

1. **Package exclusion** (M05, M26) — the package is never installed.
   The service unit doesn't exist on disk, so there's nothing to
   "mask". To use the service you must first `dnf install` the
   package. Touches disk space + RPM DB.
2. **Service masking** (M05, M08, M18, M21, M24) — the unit is symlinked
   to `/dev/null`. Some owning packages remain installed; other masks persist
   as defense in depth after their package was excluded. Stronger than
   "disabled": a masked unit cannot be started manually or through socket,
   D-Bus or dependency activation. Before an opt-in, verify whether the owning
   package exists; install it if absent, then unmask only the required units.

This doc lists **exactly** what's masked / excluded, by which
Module, and how to undo either.

> Source of truth: `kickstart/snippets/08-service-minimization.ks`
> Phase 2 (main mask list), `05-lan-isolation.ks` Step "Service
> masking" (network-discovery services), `24-firmware-fwupd.ks`
> Step "fwupd-refresh.timer mask", and `%packages -…` exclusions
> across several Modules.

## A. Masked by Module 08 (service-minimization)

**82 units total** (the source test pins this reviewed count; run the
live-verify command below to include any additional Fedora preset masks).

Source-deployed unique mask total across all NoID Privacy Modules = **96**:
- M08: 82 (this section — see M08 source `kickstart/snippets/08-
  service-minimization.ks` MASK_LIST_EOF heredoc for authoritative
  current list)
- M05 LAN-isolation: 8 (avahi/wsdd/cups family — see B section)
- M11 dns-ntp: 1 (systemd-timesyncd.service — defense-in-depth so
  chrony-NTS stays sole NTP authority; see M11 source `kickstart/
  snippets/11-dns-ntp.ks` Phase Step 2)
- M24 firmware-fwupd: 3 direct masks; passim.service overlaps M08, so only
  fwupd-refresh.timer + .service add two unique entries to the total
- M18 Flatpak: 1 (`flatpak-add-fedora-repos.service`)
- M21 kernel policy: 2 (`proc-sys-fs-binfmt_misc.automount` and
  `systemd-binfmt.service`)

Run for the current live count. It can exceed that source-deployed total
because Fedora may ship additional preset masks; their number varies by release:
```bash
sudo find /etc/systemd/system -maxdepth 1 -lname /dev/null | wc -l
```

Grouped by category:

### A1 — Crash reporting + dumps (image ships without)
```
abrtd.service               abrt-journal-core.service
abrt-oops.service           abrt-vmcore.service
abrt-xorg.service           systemd-coredump.socket
```

### A2 — Package telemetry + periodic metadata fetches
```
packagekit.service          (D-Bus-activatable package-manager layer)
passim.service              (fwupd peer-to-peer metadata sync — also masked by M24)
plocate-updatedb.service    (file-name index, runs nightly)
plocate-updatedb.timer
dnf-makecache.service       (metadata refresh — noid-update-all handles)
dnf-makecache.timer
dnf5-makecache.service      (dnf5 variant)
dnf5-makecache.timer
```

### A3 — Unused hardware daemons (not present on a generic workstation)
```
fprintd.service             (fingerprint scanners)
pcscd.service               (smart-card readers)
pcscd.socket
ModemManager.service        (cellular modems)
systemd-homed.service       (alternate user-home daemon)
systemd-oomd.service        (cgroup-level OOM policy; M27 uses earlyoom)
systemd-oomd.socket
```

Fedora's `thermald.service` is intentionally not masked: its maintained
hardware probe decides applicability, and unsupported platforms exit through
the vendor-accepted hardware-N/A path. `intel_lpmd.service` IS masked
(single-EPP-writer policy): `tuned`/`tuned-ppd` is the one selected
power/EPP backend providing GNOME's user-selected power-profile API, and on
hybrid Intel platforms lpmd's Low Power Mode would additionally confine
light workloads to the slow SoC-die LP E-cores. The `intel-lpmd` package
itself stays installed; only the unit is masked.

Local safety/recovery monitors are also deliberately not masked.
`mcelog.service` is gated by the applicable kernel device/EDAC state;
`smartd.service` is disabled in virtual machines and Fedora's default
`-n standby,10,q` policy avoids waking sleeping ATA disks; `mdmonitor.service`
is gated by `/etc/mdadm.conf`. The mdadm oneshot worker and
`mdadm-grow-continue@.service` template remain available for degraded-array
notification and reshape continuation. Review the installed unit and its
active configuration before making a broader traffic claim about a locally
customized monitor.

> **Bluetooth and location are NOT in this `/dev/null` mask list.**
> Bluetooth ships OFF via rfkill soft-block + a flag-file + a udev
> enforcer — re-enable with `noid-toggle-bluetooth on`, not
> `systemctl unmask`. Location/geoclue is left at the Fedora default
> (static) but disabled via gsettings — toggle with `noid-toggle-location`.

### A4 — Enterprise / legacy storage daemons
```
gssproxy.service            (Kerberos)
iscsi.service               (iSCSI core daemon)
iscsid.service              (iSCSI persistent daemon)
iscsiuio.service            (iSCSI hardware offload)
iscsi-onboot.service        (iSCSI boot support)
iscsi-starter.service       (iSCSI userspace)
iscsid.socket               (iSCSI D-Bus)
iscsiuio.socket             (iSCSI hardware offload helper)
rpc-statd-notify.service    (NFS file-lock recovery)
sssd.service                (System Security Services Daemon)
sssd-kcm.service            (Kerberos credential manager)
sssd-kcm.socket
```

### A5 — VM-guest tools (image assumed to run on bare-metal or as host, not guest)
```
vboxservice.service         (VirtualBox guest tools)
vmtoolsd.service            (VMware guest tools)
vgauthd.service             (VMware guest authentication)
```

### A6 — Libvirt daemon split

The core modular VM-hosting set (`virtqemud`, `virtnetworkd`, `virtstoraged`,
`virtlogd` and `virtnodedevd`) stays socket-activated. The following legacy
monolithic compatibility units are masked so one deployment does not mix the
two libvirt architectures:

```
libvirtd.service            libvirtd.socket               libvirtd-ro.socket
libvirtd-admin.socket       libvirtd-tcp.socket           libvirtd-tls.socket
```

Four optional modular families are also masked, including every activation
socket, because the default local single-user VM-host workflow does not use
remote libvirt proxying, host-interface management, nwfilter rules or libvirt
secret storage:

```
virtproxyd.service          virtproxyd.socket          virtproxyd-admin.socket
virtproxyd-ro.socket        virtproxyd-tcp.socket
virtinterfaced.service      virtinterfaced.socket      virtinterfaced-admin.socket
virtinterfaced-ro.socket
virtnwfilterd.service       virtnwfilterd.socket       virtnwfilterd-admin.socket
virtnwfilterd-ro.socket
virtsecretd.service         virtsecretd.socket         virtsecretd-admin.socket
virtsecretd-ro.socket
```

If a reviewed workflow needs one family, unmask its service and required
sockets explicitly before enabling it; for example:

```bash
sudo systemctl unmask virtsecretd.service virtsecretd.socket \
    virtsecretd-admin.socket virtsecretd-ro.socket
sudo systemctl enable --now virtsecretd.socket
```

Undo that opt-in with `disable --now` for the socket, then mask the same four
units again. Do not unmask all optional families merely to enable one feature.

### A7 — Cockpit web-management
```
cockpit.service             cockpit.socket
cockpit-session.service     cockpit-session.socket
```
Cockpit packages can remain as compose dependencies. Masking the complete
socket/service set prevents its web-management activation. NoID Privacy uses
GNOME Settings plus the documented NoID Privacy tools instead of enabling a
background web-administration surface.

### A8 — Compatibility-name masks
```
apparmor.service            iptables.service
ip6tables.service           ebtables.service
ipset.service               ntpd.service
ntpdate.service             sntp.service
syslog.service              syslog.target
ssh-keygen.target           boot.automount
sysroot.mount               mkinitcpio-generate-shutdown-ramfs.service
systemd-quotacheck.service
```
These legacy or foreign-distro names are deliberately resolved to
`/dev/null`, so an accidental dependency or future package cannot activate an
unreviewed replacement. Fedora's selected implementations remain SELinux,
nftables/firewalld, chrony and journald. Do not infer system health merely from
whether a nonexistent compatibility name is masked.

### A9 — Other
```
atd.service                 (one-shot scheduled commands, use cron/systemd timers instead)
sshd-unix-local.socket      (SSH over unix socket — we don't run SSH server)
malcontent-timerd.service   (unused parental-control screen-time daemon)
```

## B. Masked by Module 05 (LAN-isolation)

Network-discovery services that would broadcast your presence on LAN:

```
avahi-daemon.service     (mDNS / zeroconf / Bonjour)
avahi-daemon.socket
wsdd.service             (Web Services Discovery — Windows interop)
wsdd2.service            (WSDD successor)
cups.service             (local printing)
cups.path                (autoload on print job)
cups.socket              (D-Bus activation)
cups-browsed.service     (network-printer auto-browse)
```

## C. Masked by Module 24 (firmware-fwupd)

```
fwupd-refresh.timer       (hourly schedule with up to one hour randomized
                           delay and Persistent=true in Fedora's vendor unit)
fwupd-refresh.service     (belt+suspenders: M24 also masks the service
                           directly so manual unmask of timer alone
                           wouldn't enable refresh — both must unmask)
```

Plus M24 belt+suspenders also masks `passim.service` (M08 already masks it
via A2 above; M24 ensures defense-in-depth in case M08 mask is somehow
reverted). The `fwupd.service` itself stays available for on-demand
`fwupdmgr` invocations; only the refresh paths are masked.

## D. Masked by Module 18 (Flatpak remote policy)

```
flatpak-add-fedora-repos.service
```

The automatic Fedora OCI remote registration path stays masked. The supported
manual opt-in is `sudo noid-toggle-fedora-flatpaks on`; it verifies and manages
the remote without enabling the background auto-registration unit.

## E. Masked by Module 21 (binfmt_misc activation)

```
proc-sys-fs-binfmt_misc.automount
systemd-binfmt.service
```

These masks disable automatic Wine/foreign-binary dispatch and cross-
architecture container handlers. The exact opt-in and undo commands are in
`21-kernel-module-blacklist.md` under **Enabling binfmt_misc (Opt-In)**.

## F. Packages excluded at compose time (M08 and M26)

These packages are not installed in the image. The associated
services / binaries don't exist on disk; `systemctl status X` would
return "Unit X not found".

### F1 — Printing, SMB, and mDNS packages

Install these on demand as described in `26-optional-packages.md`:
```
-bluez-cups          -cifs-utils          -cups-browsed
-cups-pdf            -gutenprint-cups     -gvfs-smb
-hplip               -nss-mdns            -samba
-samba-client
```

`samba-common` (config skeleton, no daemon) stays installed as the packaging
companion of retained `libsmbclient` (M26); M05 deletes its
`/etc/samba/smb.conf`.

### F2 — Evolution / PIM
```
-evolution-ews-core
```

### F3 — GNOME default apps that leak / phone-home
```
-gnome-calendar           -gnome-clocks
-gnome-contacts           -gnome-maps
-gnome-tour               -gnome-weather
```

### F4 — Avahi family (daemon masked; sub-packages excluded)

The base `avahi` package ships (its libs are pulled in as dependencies)
but `avahi-daemon.service` is **masked** (Module 05). Only these
sub-packages are excluded:
```
-avahi-autoipd            -avahi-tools
-avahi-ui                 -avahi-ui-tools
-nss-mdns
```

Install any of these on demand — see `26-optional-packages.md` for
commands + what else gets pulled as deps.

### F5 — PipeWire AirPlay discovery

```
-pipewire-config-raop
```

This Fedora configuration sub-package loads PipeWire's RAOP discovery module,
which requests Avahi Zeroconf on every PipeWire start. It is excluded from the
Silent-Machine baseline; ordinary local audio does not require it. The
package-side opt-in and undo are in `26-optional-packages.md`. Installing it
does not override NoID Privacy's XDP/TC, topology or firewalld LAN boundary.

### F6 — M08 exclusions with persistent defense-in-depth masks

Several A1–A4 rows deliberately retain `/dev/null` links even though M08 also
excludes their owning packages. Reinstalling one of these packages therefore
does not silently reactivate its service:

```
-plocate                    -PackageKit
-PackageKit-command-not-found
-passim

-abrt                       -abrt-addon-ccpp
-abrt-addon-kerneloops      -abrt-addon-pstoreoops
-abrt-addon-vmcore          -abrt-addon-xorg
-abrt-cli                   -abrt-console-notification
-abrt-dbus                  -abrt-desktop
-abrt-gui                   -abrt-gui-libs
-abrt-libs                  -abrt-tui

-gssproxy                   -sssd
-sssd-common                -sssd-client
-sssd-kcm                   -nfs-utils
-fprintd                    -fprintd-pam
```

This is why `systemctl unmask` alone is not a complete opt-in for those rows.
Review the package transaction first, install only the required package, then
unmask the exact service/socket set and document the resulting background or
network behavior.

## Checking what's masked / excluded on the running system

### Masked units

```bash
# All masked (incl. Fedora defaults + our additions)
sudo systemctl list-unit-files --state=masked

# Just the ones NoID Privacy masked (symlinks to /dev/null)
sudo find /etc/systemd/system -maxdepth 1 -lname /dev/null -printf '%f\n' | sort
```

### Excluded packages

```bash
# Is package X installed?
rpm -q samba-client        # "package samba-client is not installed"

# What WAS excluded (compare against a default Workstation)
# (no canonical diff — read 26-optional-packages.md for the list)
```

## How to restore a masked service

First confirm whether the owning package is installed. If it was excluded,
install it deliberately; then unmask, enable and start only the required units.

### Example 1 — Bluetooth

Bluetooth is **not** masked — it ships OFF via rfkill soft-block + a
flag-file + a udev enforcer (the `bluez` package IS installed). Use the
toggle rather than `systemctl unmask`:

```bash
# Clears the rfkill block + flag and starts the service
sudo noid-toggle-bluetooth on

# Optional only for Bluetooth file transfer:
sudo dnf install bluez-obexd

# Verify
systemctl status bluetooth
rfkill list bluetooth
```

GNOME's Bluetooth panel appears in Settings for pairing after the helper has
enabled the complete NoID Privacy state. The panel's raw radio switch does not update
the root-owned NoID Privacy flag or WirePlumber policy; use the helper (or Welcome
SwitchRow) for complete enable/disable transitions.

### Example 2 — CUPS for printing

CUPS is both masked (by M05) AND its helper packages excluded (by M26).
Install + unmask:

```bash
sudo dnf install cups cups-pdf hplip gutenprint-cups bluez-cups

# Unmask the three core units required for direct printer setup.
# cups-browsed.service is M05's fourth CUPS-family mask; keep it masked unless
# you deliberately install cups-browsed and accept network-printer discovery.
sudo systemctl unmask cups.service cups.socket cups.path
sudo systemctl enable --now cups.service

# Add a local printer via GNOME Settings → Printers.
# For a network printer, first create the exact peer exception documented in
# 05-lan-isolation.md and add it by IP. cups-browsed alone cannot cross the
# multicast and physical-interface boundaries.
```

### Example 3 — fwupd-refresh.timer

```bash
sudo systemctl unmask fwupd-refresh.timer fwupd-refresh.service
sudo systemctl enable --now fwupd-refresh.timer
```

Tradeoff: Fedora's vendor timer attempts LVFS refreshes every hour with a
randomized delay of up to one hour and `Persistent=true`. That creates
background HTTPS traffic on whatever route is active, including direct WAN
when no VPN is active. Manual alternative:

```bash
# Bring up your chosen VPN through its supported client or exact NM profile,
# verify the route, THEN fetch metadata
nmcli connection show --active
sudo fwupdmgr refresh && sudo fwupdmgr get-updates
```

### Example 4 — existing mdraid data array

The stock installer layout is single-device LUKS2+Btrfs, but the image keeps
Fedora's conditional mdadm safety units unmasked. If you deliberately add an
mdraid **data** array, install/configure `mdadm` and review `/etc/mdadm.conf`
for that exact array before starting the monitor:

```bash
sudo dnf install mdadm
sudo systemctl enable --now mdmonitor.service mdmonitor-oneshot.timer \
  raid-check.timer

# Verify the configured arrays and monitoring state
sudo mdadm --detail --scan
systemctl --no-pager --full status mdmonitor.service mdmonitor-oneshot.timer
systemctl is-enabled raid-check.timer
```

No unmask step is required. `mdadm-grow-continue@.service` is a template
invoked for a specific reshape; do not enable the template globally.
`raid-check.timer` remains enabled in the stock image and becomes useful once
an active array exists.

Root-on-mdraid is **not** enabled by those commands. It changes the storage and
boot topology and requires a planned install/migration plus Generic-recovery,
initramfs and real reboot validation. M21 has no global mdraid Dracut omission;
it derives the installed image from the detected root topology. Do not copy a
single-device partition recipe and assume that unmasking services converts it.

## How to INSTALL an excluded package

```bash
# Printing
sudo dnf install cups cups-pdf hplip gutenprint-cups
# Then unmask as above

# NetBIOS / Samba client (if you need SMB shares):
sudo dnf install samba-client cifs-utils
# Note: samba-common stays installed as the packaging companion of retained libsmbclient

# Avahi (local mDNS):
sudo dnf install avahi nss-mdns
# Do not start Avahi until you have deliberately reviewed and changed every
# LAN/multicast boundary listed in 05-lan-isolation.md.

# Optional PipeWire AirPlay discovery client (LAN boundary remains enforced):
sudo dnf install pipewire-config-raop
systemctl --user restart pipewire.service pipewire-pulse.service wireplumber.service
```

## If you unmask — survival across updates

`noid-update-all.sh` only runs `dnf upgrade`, `flatpak update`, etc.
It does NOT re-run the kickstart %post, so your unmask persists.
`dnf` won't re-mask what you unmasked.

Image re-installs (new ISO) would re-apply defaults — document your
customisations so you can re-apply.

## Re-mask something

```bash
UNIT=example.service
sudo systemctl disable --now "$UNIT"
sudo systemctl mask "$UNIT"
```

## References

- Module 08 source: `kickstart/snippets/08-service-minimization.ks`
  (Phase 2 contains the authoritative MASK_LIST)
- Module 05 source: `kickstart/snippets/05-lan-isolation.ks`
  (network-discovery masking)
- Module 24 source: `kickstart/snippets/24-firmware-fwupd.ks`
  (fwupd-refresh.timer mask)
- Module 26 source: `kickstart/snippets/26-package-set.ks`
  (default package exclusions)
- [systemctl(1)](https://www.freedesktop.org/software/systemd/man/systemctl.html)

SVC_EOF
publish_doc "$SVC_DOC"
log "  [OK] 08-masked-services.md written"

# ------------------------------------------------------------------------------
# Phase 6 — 11-dns-custom.md
# ------------------------------------------------------------------------------
PHASE="P6-dns"
log "Writing 11-dns-custom.md"

DNS_DOC="$DOC_DIR/11-dns-custom.md"
DOC_TMP=$(mktemp "$DOC_DIR/.11-dns-custom.md.XXXXXXXX")
cat > "$DOC_TMP" <<'DNS_EOF'
# DNS + NTP — Custom Providers + Troubleshooting

This image ships with:
- **DNS**: systemd-resolved using **Quad9 as the PRIMARY** global resolver
  (`9.9.9.9`, `149.112.112.112`, `2620:fe::fe`, `2620:fe::9`). The
  `#dns.quad9.net` suffix supplies the intended TLS server name and SNI.
  `DNSOverTLS=yes` is the strict authenticated global and physical image
  default: DNS fails closed instead of falling back to port 53 when TLS cannot
  be negotiated. Setup and Network expose a separate, explicit opportunistic
  pre-VPN/captive-portal compatibility choice for that physical bootstrap path;
  it tries DoT first but is downgrade-capable and permits DNS/53.
  `DNSSEC=allow-downgrade` still attempts validation,
  but an active attacker can force validation off. NetworkManager
  `ignore-auto-dns=true` blocks ISP DNS from DHCP. An explicit per-link VPN or
  private `~.` DNS scope takes precedence. When that profile leaves
  `connection.dns-over-tls` unset, the image's generic NetworkManager default
  selects opportunistic DoT: it tries TLS first but can fall back to DNS/53,
  cannot authenticate the resolver in this mode, and is not MITM-resistant.
  An explicit profile value wins. Quad9 remains the global path whenever no
  such link scope is active.
  (Source of truth: `kickstart/snippets/05-lan-isolation.ks` resolved
  drop-in, NOT `11-dns-ntp.ks` — the latter only covers NTP.)
  Firefox and Thunderbird use this system/VPN resolver path by default.
  Browser Secure DNS remains a user-controlled opt-in; enabling it creates
  a separate application DNS path that can bypass VPN/private link DNS.
- **NTP**: chrony with NTS (Network Time Security) — 6 operator-supported
  public/production EU servers,
  `minsources 3` minimum-selectable-source threshold, certificate-validated
  and IPv4-only. Sources start declaratively `offline` and are switched online
  only after the gateway/XDP readiness boundary.
  This threshold is not an operator quorum. Fedora's
  `chronyd-restricted.service` runs it as the `chrony` user with only
  `CAP_SYS_TIME`, the package-owned systemd/SELinux sandbox and maintained
  `-F 2` fork/exec filter. No custom library-syscall allowlist is layered on it.

## Checking current DNS resolvers

```bash
resolvectl status
```

Look for your physical interface (`enp*`, `wlp*`): DNS servers are
Quad9 by default. Look for your VPN interface (`proton0`, `wg0`,
`mullvad-*`): DNS servers are the VPN's internal resolvers.

```bash
# Test a lookup + see which resolver responded
resolvectl query example.com

# Flush the cache (if you just changed providers)
sudo resolvectl flush-caches
```

## Changing the upstream DNS provider

If you want to use a different provider than Quad9:

### Option A: NetworkManager profile (per-connection)

```bash
# List profiles, then select one exact existing profile
nmcli -f NAME,UUID,TYPE,DEVICE connection show
read -r -p 'Exact NetworkManager profile name: ' DNS_PROFILE
[ -n "$DNS_PROFILE" ] || { echo 'A profile name is required.' >&2; exit 1; }
nmcli --get-values GENERAL.NAME --escape no \
    connection show "$DNS_PROFILE" >/dev/null || {
    echo 'That exact NetworkManager profile does not exist.' >&2
    exit 1
}

# Set DNS for a specific connection (survives reboot)
sudo nmcli connection modify "$DNS_PROFILE" \
    ipv4.dns "1.1.1.1#one.one.one.one 1.0.0.1#one.one.one.one" \
    connection.dns-over-tls yes \
    ipv4.ignore-auto-dns yes
sudo nmcli --wait 30 connection up "$DNS_PROFILE"
```

Reactivation can briefly interrupt the selected connection. Verify its active
DNS and transport with `resolvectl status`; NetworkManager keeps the change
scoped to this profile.

### Option B: Global primary via resolved (override the image default)

The image's resolved drop-in is at
`/etc/systemd/resolved.conf.d/99-privacy.conf` (written by Module 05).
To keep the NoID Privacy hardening posture but use a different upstream DNS,
create a drop-in whose filename sorts lexically after `99-privacy.conf`.
The `zzz-` prefix below provides that ordering. First refuse to overwrite any
existing local policy and open a new root-owned file through `sudoedit`:

```bash
DNS_OVERRIDE=/etc/systemd/resolved.conf.d/zzz-local-dns-provider.conf
if sudo test -e "$DNS_OVERRIDE" || sudo test -L "$DNS_OVERRIDE"; then
    echo "Refusing to overwrite existing policy: $DNS_OVERRIDE" >&2
    exit 1
fi
sudoedit "$DNS_OVERRIDE"
```

Place exactly this content in the editor:

```ini
[Resolve]
# Override: Cloudflare with the names used for certificate validation + SNI
DNS=
DNS=1.1.1.1#one.one.one.one 1.0.0.1#one.one.one.one 2606:4700:4700::1111#one.one.one.one 2606:4700:4700::1001#one.one.one.one
FallbackDNS=
FallbackDNS=1.1.1.1#one.one.one.one 1.0.0.1#one.one.one.one
# Keep M05 hardening defaults (copied here for explicit reference):
DNSSEC=allow-downgrade
DNSOverTLS=yes
Cache=yes
```

Then normalize metadata, inspect the merged configuration, reload and verify:

```bash
sudo chmod 0644 "$DNS_OVERRIDE"
sudo chown root:root "$DNS_OVERRIDE"
sudo restorecon -F "$DNS_OVERRIDE"
sudo systemd-analyze cat-config systemd/resolved.conf
sudo systemctl reload systemd-resolved
resolvectl status
```

`DNS=` and `FallbackDNS=` are list-valued settings. Their empty assignments
reset the earlier M05 lists before the replacement values are added; filename
ordering alone does not replace an accumulated list. The fallback remains with
the same selected provider, preserving M05's no-unannounced-third-party
fallback policy.

This keeps the shipped strict global DoT posture. `DNSSEC=allow-downgrade`
remains a separate compatibility boundary. If a required resolver does not
support DoT, prefer a VPN/private per-link DNS scope where its DNS/53 traffic
stays inside that tunnel, or deliberately select the opportunistic
compatibility mode; do not silently weaken every DNS scope.

Do NOT edit `/etc/systemd/resolved.conf.d/99-privacy.conf` directly —
that's the drop-in shipped by NoID Privacy and gets overwritten on image re-install.
Use a lexically later drop-in as shown. Revert this example with:

```bash
sudo unlink /etc/systemd/resolved.conf.d/zzz-local-dns-provider.conf
sudo systemctl reload systemd-resolved
resolvectl status
```

### Option C: Global DoT mode (native NoID Privacy selector)

Use NoID Privacy Network → **DNS Privacy**, or the same narrow CLI:

```bash
noid-dns-mode status
sudo noid-dns-mode strict          # DNSOverTLS=yes: authenticated, fail closed
sudo noid-dns-mode opportunistic   # VPN compatibility; DNS/53 fallback possible
sudo noid-dns-mode off             # explicit plaintext recovery mode
sudo noid-dns-mode reset           # remove only the selector-owned override
```

`strict` requires reachable TCP port 853 and valid certificates for the
certificate-named global/physical resolver. If a captive portal or network
blocks 853, DNS fails instead of downgrading to DNS/53. The helper writes one
root-owned systemd-resolved drop-in atomically, updates managed physical
NetworkManager profiles, verifies merged/profile/runtime convergence, and
restores the complete previous state if that transaction fails. It does not
generate a test DNS query.

This selector changes the global resolver and managed physical Ethernet/Wi-Fi
profiles together; it never rewrites tunnel, bridge or provider profiles. If
such a NetworkManager profile leaves `connection.dns-over-tls` at its `-1`
default, NetworkManager consults
`/etc/NetworkManager/conf.d/02-noid-connection-defaults.conf`: `type:ethernet`
and `type:wifi` match strict DoT (`2`), while the `[connection]` catch-all
gives other managed types, including WireGuard and OpenVPN tunnels,
opportunistic DoT (`1`). An explicit profile value wins over that default. An
active VPN/private `~.` DNS scope with the unset property therefore tries DoT
but can fall back to DNS/53 and takes routing precedence over the global path.
That fallback can remain selected after a failed TLS capability probe; a
successful lookup or an `opportunistic` policy label alone does not prove that
the individual exchange used TLS. Inspect the raw profile, merged connection
default, resolver journal and a controlled transport probe separately.

Strict DNSSEC is a separate policy and remains a manual compatibility opt-in:

```bash
DNSSEC_OVERRIDE=/etc/systemd/resolved.conf.d/zzz-strict-dnssec.conf
if sudo test -e "$DNSSEC_OVERRIDE" || sudo test -L "$DNSSEC_OVERRIDE"; then
    echo "Refusing to overwrite existing policy: $DNSSEC_OVERRIDE" >&2
    exit 1
fi
sudoedit "$DNSSEC_OVERRIDE"
```

Place exactly:

```ini
[Resolve]
DNSSEC=yes
```

Then verify and activate it:

```bash
sudo chmod 0644 "$DNSSEC_OVERRIDE"
sudo chown root:root "$DNSSEC_OVERRIDE"
sudo restorecon -F "$DNSSEC_OVERRIDE"
sudo systemd-analyze cat-config systemd/resolved.conf
sudo systemctl reload systemd-resolved
resolvectl status
```

`DNSSEC=yes` requires a correctly supporting resolver. It still accepts a
domain with an authenticated proof of insecure delegation, so strict DNSSEC
does not require every domain to be signed. Test required private zones before
keeping the override. Revert with:

```bash
sudo unlink /etc/systemd/resolved.conf.d/zzz-strict-dnssec.conf
sudo systemctl reload systemd-resolved
```

## Firefox Secure DNS and VPN/private DNS

Firefox ships with `network.trr.mode=5`: its own DoH client is off by the
user-overridable image default, so `systemd-resolved` can select the active
VPN/private `~.` DNS scope. Without such a scope, the global Quad9 path above
is used. The default is an AutoConfig `defaultPref`, not a profile `user.js`
or `lockPref`, so a user choice survives Firefox restarts and Update All.
Firefox's separate country lookup stays disabled; the narrow
`doh-rollout.home-region=global` default only loads the built-in global
provider catalogue. It neither enables DoH nor chooses or contacts a provider.

To deliberately enable browser-level DoH:

- Settings → Privacy & Security → DNS over HTTPS
- Select a protection level and provider

That provider then receives Firefox DNS independently of the system resolver
and any active VPN/private link DNS selection or filtering. Keep it off when
the system/VPN resolver is the intended privacy boundary. If you deliberately
choose browser DoH, verify its endpoint, privacy policy, failover behavior and
tunnel-down routing rather than assuming the application path inherits the
system resolver's guarantees. The global catalogue deliberately gives up
region-specific and automatically detected local-provider choices in exchange
for avoiding Firefox's country lookup; a custom endpoint remains available.

## NTP: inspecting + changing servers

```bash
# Current chrony status
sudo chronyc tracking      # current sync state (offset, stratum)
sudo chronyc sources       # list of configured NTP sources
sudo chronyc sourcestats   # quality metrics per source
```

The image uses NTS (not legacy NTP). Configured in
`/etc/chrony.conf` — 6 NTS servers across 3 EU institutional operators
(PTB 2, Netnod 2, SIDN/TimeNL 2):

```
# Germany - PTB national metrology (ptbtime4 = separate location)
server ptbtime1.ptb.de iburst nts ipv4 maxpoll 11 offline
server ptbtime4.ptb.de iburst nts ipv4 maxpoll 11 offline

# Sweden - Netnod national IX (Lulea/Malmoe sites)
server lul1.nts.netnod.se iburst nts ipv4 maxpoll 11 offline
server mmo1.nts.netnod.se iburst nts ipv4 maxpoll 11 offline

# Netherlands - SIDN/TimeNL production endpoints
server ntppool1.time.nl iburst nts ipv4 maxpoll 11 offline
server ntppool2.time.nl iburst nts ipv4 maxpoll 11 offline

minsources 3
```

(Source of truth: `kickstart/snippets/11-dns-ntp.ks`. The image disables IPv6
on WAN and therefore configures these sources explicitly as IPv4. M04 releases
all six with `chronyc online` only after its exact gateway/XDP postcondition.)

The operator-status review is recorded in
`/usr/share/doc/noid-privacy/11-nts-sources.tsv`. SIDN currently labels
`ntppool3.time.nl` and `ntppool4.time.nl` **pre-production**, so they are not
base-image dependencies even though they provide GNSS-free UTC(VSL) time and
may be reachable. Public DNS, certificates, backend routing and operator
status can change; the release gate rechecks the configured names rather than
calling this list permanently reliable.

To add a custom NTS server:

```bash
read -r -p 'Exact reviewed NTS hostname: ' NTS_HOST
NTS_HOST_RE='^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$'
if [ "${#NTS_HOST}" -gt 253 ] || ! [[ "$NTS_HOST" =~ $NTS_HOST_RE ]]; then
    echo 'Use the operator-published fully qualified DNS hostname.' >&2
    exit 1
fi
printf 'Add this exact line in the editor:\nserver %s iburst nts ipv4 maxpoll 11 offline\n' \
    "$NTS_HOST"
sudo noid-snap-pre "before adding custom NTS source $NTS_HOST"
sudoedit /etc/chrony.conf
sudo chronyd -p -f /etc/chrony.conf
sudo systemctl restart chronyd-restricted.service
sudo chronyc sources -v
```

The shipped source set contains no legacy unauthenticated NTP fallback.
Chrony would accept a manually added plain `server` line, so do not add one;
validate every intentional edit with `sudo chronyd -p -f /etc/chrony.conf`
before restarting the service.

## Troubleshooting

### DNS resolves but Firefox says "Secure connection failed"

Clock-skew issue. NTS-NTP requires a working system clock to
validate TLS. Check:
```bash
sudo chronyc tracking
# Confirm a synchronized reference and "Leap status: Normal"; interpret
# offsets against chrony's source/selection state rather than a universal cutoff.
```

If a dead RTC put the clock outside the NTS certificate-validity window,
`chronyc makestep` cannot help because no authenticated measurement exists.
Obtain exact current UTC from an independently verified clock, switch to a
physical text console with `Ctrl+Alt+F3`, and enter that value:

```bash
read -r -p 'Verified current UTC (YYYY-MM-DDTHH:MM:SSZ): ' RECOVERY_UTC
sudo noid-time-recovery set "$RECOVERY_UTC"
```

The timestamp-bound confirmation, image-time floor and local-VT requirement
prevent remote or accidental use. The workflow never enables plaintext NTP or
disables certificate-time validation. Full guide:
`/usr/share/doc/noid-privacy/11-time-recovery.md`.

### DNF cannot resolve mirrors

Identify the actual active DNS scope before changing policy:
```bash
noid-dns-diagnose
resolvectl status
nmcli connection show --active
resolvectl query mirrors.fedoraproject.org
```

If a VPN/private `~.` scope is selected but its tunnel is down or unhealthy,
repair or disconnect that exact profile using its supported client. Quad9
remains the global fallback when no per-link catch-all scope is active. Do not
enable DHCP/ISP DNS merely to hide a routing or VPN failure.

### DNS lookups succeed but are slow

Inspect the resolver state and one domain you actually need; do not generate
unrelated “cache warming” traffic:
```bash
resolvectl statistics
resolvectl query example.com
journalctl -u systemd-resolved -b --no-pager
```

### Quad9 seems down / slow

Confirm whether the problem is transport, routing, the chosen name server or a
single domain with `noid-dns-diagnose` and `resolvectl`. If changing provider,
use its current official documentation to verify resolver addresses, the
certificate-validation hostname, DoT support, logging/privacy policy and
filtering behavior. Then use Option A or B above; do not copy an undated
third-party address list.

## Why NTS and not NTP?

Legacy NTP is unauthenticated — a man-in-the-middle on the LAN can feed
you a bogus time, which breaks TLS (every cert has `notBefore` /
`notAfter`). NTS authenticates NTP exchanges with per-session keys
negotiated via TLS.

`minsources 3` requires at least three selectable sources before an update;
chrony's separate source-selection algorithm determines agreement and
falsetickers. It is not a simplistic three-of-ten vote.

## References

- [systemd-resolved(8)](https://www.freedesktop.org/software/systemd/man/systemd-resolved.service.html)
- [NetworkManager connection.dns-over-tls](https://networkmanager.dev/docs/api/latest/settings-connection.html)
- [chrony 4.8 chronyd(8)](https://chrony-project.org/doc/4.8/chronyd.html)
- [Quad9](https://www.quad9.net/)
- [Cloudflare public DNS resolver privacy](https://developers.cloudflare.com/1.1.1.1/privacy/public-dns-resolver/)
- [Mullvad DNS](https://mullvad.net/en/help/dns-over-https-and-dns-over-tls)

DNS_EOF
publish_doc "$DNS_DOC"
log "  [OK] 11-dns-custom.md written"

# ------------------------------------------------------------------------------
# Phase 7 — 00-cheatsheet.md (quick reference)
# ------------------------------------------------------------------------------
PHASE="P7-cheatsheet"
log "Writing 00-cheatsheet.md"

CHEAT_DOC="$DOC_DIR/00-cheatsheet.md"
DOC_TMP=$(mktemp "$DOC_DIR/.00-cheatsheet.md.XXXXXXXX")
cat > "$DOC_TMP" <<'CHEAT_EOF'
# NoID Privacy — Cheat Sheet

Quick reference for the most common NoID Privacy CLI commands and the
diagnostic commands you'll use most. Paired with `noid-help` for interactive
doc navigation.

For the live inventory of installed user-facing `noid`/`noid-*` commands in
`/usr/local/bin` (including its `/usr/local/sbin` alias and later additions
there), run either. Internal `/usr/libexec` and `/usr/local/libexec` helpers are
deliberately excluded; their owning workflow documents an exact path when a
user must invoke one:

```bash
noid --help
noid-help commands
```

The table below is intentionally only the common interactive subset.

## Common NoID Privacy CLI commands

| Command | What it does |
|---------|--------------|
| `noid-status` | Selected one-screen posture overview, including persistent DNS policy and active DNS path |
| `noid-status --brief` | Single-line summary (for status bar / scripts), including `dns:strict`, `dns:opportunistic`, `dns:off` or `dns:check` |
| `noid-status --json` | Machine-readable RFC 8259 JSON object |
| `noid-help` | Open / list / search user-doc topics (this dir) |
| `noid-help list` | List all available topics |
| `noid-help commands` | List installed user-facing `noid`/`noid-*` commands in `/usr/local/bin` without running them |
| `noid-help <topic>` | Open a doc in `$PAGER` |
| `noid-help search <keyword>` | Grep all docs for a keyword |
| `noid-welcome.sh --again` | Re-run the first-boot welcome dialog |
| `sudo noid-snap-pre DESCRIPTION` | Manual snapshot before a risky change |
| `noid-update-all.sh` | Guided update: snapshot + dnf + flatpak + firmware; after a successful DNF transaction it runs the read-only AIDE drift check only when an active reviewed baseline exists (run as user — it calls sudo itself) |
| `sudo noid-toggle-aide-popup on\|off\|status` | Manage AIDE desktop notifications without changing the scan schedule |
| `sudo noid-usbguard-devices` | Show runtime versus durable USB policy, allow blocked devices, or revoke an exact persistent rule |
| `noid-firefox-relax-fpp` | Relax Firefox fingerprint protection in all registered profiles; `--restore` to revert |
| `noid-mei-restore-submodules` | Intel only: unblacklist MEI submodules (fwupd BootGuard detection) |
| `noid-mei-lockdown` | Intel only: re-apply MEI submodule lockdown (reverse of above) |

## Diagnostic commands (stock Linux, frequently useful)

### System health
```bash
noid-status                                # selected posture overview
systemctl --failed                         # failed system units
systemctl --user --failed                  # failed units in your user manager
journalctl -b -p warning                   # warnings/errors since last boot
```

### Firewall
```bash
sudo firewall-cmd --get-active-zones       # which zones are active
sudo firewall-cmd --list-all-policies      # custom policies (block-lan-out)
sudo firewall-cmd --get-log-denied         # expected default: off (no packet-log noise)
sudo journalctl -b -t noid-lan-topology --no-pager  # boundary-controller events
```

### Network
```bash
nmcli connection show                      # all profiles
nmcli connection show --active             # what's currently up
resolvectl status                          # DNS per interface
ip route show default                      # default gateway / VPN route
curl --fail --silent --show-error https://am.i.mullvad.net/json | jq
# Explicit external check: sends your source IP to Mullvad.
```

### SELinux + Audit
```bash
sestatus                                   # enforcing? policy loaded?
sudo ausearch -m avc -ts today             # today's denials
sudo aureport --summary -ts today          # event summary
```

### AIDE file-integrity
```bash
systemctl status aide-check.timer          # timer state
sudo journalctl -u aide-check.service -n 40  # latest check result
sudo noid-aide-check.sh                    # supported check-only workflow
```

### Secure Boot + firmware (HSI)
```bash
mokutil --sb-state                         # Secure Boot enabled?
fwupdmgr security                          # supported platform security attributes
sudo fwupdmgr get-devices                  # all fwupd-visible firmware
```

HSI coverage is hardware- and architecture-dependent. Read the individual
supported/unsupported attributes and recommendations; do not infer that every
machine exposes Intel ME, TPM or BootGuard checks.

### Disk encryption + snapshots
```bash
lsblk -f                                   # identify the actual crypto_LUKS device
read -r -p 'Exact LUKS device path: ' LUKS_DEV
sudo cryptsetup luksDump "$LUKS_DEV"        # verify LUKS version and keyslot KDF
sudo snapper -c root list                  # Snapper snapshots
sudo btrfs filesystem usage /              # btrfs space
```

`lsblk` identifies topology and filesystem type; only `cryptsetup luksDump`
establishes LUKS2 and the active keyslot's KDF.

### Packages + updates
```bash
rpm -qa | wc -l                            # how many packages installed
sudo dnf check-update                      # explicit repository metadata traffic
flatpak remote-ls --updates --system       # pending system-scope Flatpaks
flatpak remote-ls --updates --user         # pending user-scope Flatpaks
```

### Kernel + lockdown
```bash
cat /sys/kernel/security/lockdown          # [integrity] or [confidentiality]?
grep '^CONFIG_SECURITY_LOCKDOWN' "/boot/config-$(uname -r)"  # built-in?
uname -r                                   # running kernel
```

## Common first-aid

### GRUB appeared once after a very quick first-login reboot

Fedora's user-level `grub-boot-success.timer` deliberately waits two minutes
of a normal logged-in session (`OnActiveSec=2min`) before running
`grub2-set-bootflag boot_success`. If you manually reboot sooner, GRUB can show
the kernel-selection menu on the following start because the previous boot was
not yet marked healthy. Select the normal default entry. After a later healthy
session crosses that two-minute boundary, Fedora hides the menu again.

This one-time menu is recovery behavior, not by itself evidence of a crash.
If it repeats after sessions longer than two minutes, inspect the real state:

```bash
systemctl --failed
coredumpctl list --since today
journalctl -b -1 -p warning
```

### Something broke after an update — roll back

```bash
# 1. From working or rescue userspace, inspect the checked boot model:
sudo /usr/libexec/noid-snapper-status
# 2. Find the reviewed pre-update snapshot:
sudo snapper -c root list
# 3. Publish the verified read-write rollback root, then reboot:
read -r -p 'Exact reviewed snapshot number: ' NOID_SNAPSHOT_ID
case "$NOID_SNAPSHOT_ID" in
    ''|*[!0-9]*) echo 'Snapshot number must contain digits only.' >&2; exit 1 ;;
esac
sudo noid-snap-rollback "$NOID_SNAPSHOT_ID"
sudo reboot
```

GRUB does not list snapshots. See `20-rollback-recovery.md` for the exact
working-, rescue- and live-media boundaries.

### USB device blocked

```bash
# Plug device, then:
sudo noid-usbguard-devices allow
# Or click "Allow this device" in the GNOME notification for this device
# instance only; that notification action is temporary.
```

The helper creates a persistent device-specific rule and pre-change snapshot
evidence. See `14-usbguard.md`.

### AIDE reports changes I didn't make

```bash
# Check what changed
sudo journalctl -u aide-check.service | tail -40

# Coverage differs by path; check the exact AIDE rule before classifying:
# - /boot/efi: NOT excluded; content-tracked by the VFAT-safe ESP rule
# - /etc/pam.d: directory entry excluded; child files remain covered
# - /var/log/journal: active journal contents excluded
# - /var/log/boot.log: truncate/rewrite path excluded
sudo grep -nE '^ESP =|^/boot/efi ESP|^!/boot/efi' /etc/aide.conf
```

If unfamiliar, investigate. A familiar-looking path is not enough to classify
an event as benign. For source auditors, the reviewed coverage boundaries are
in `docs/fp-database.md` in the project repository; that auditor reference is
not installed in the image.
If you deliberately change `/etc/aide.conf`, preserve the
old report and prepare a separate candidate for explicit review:
```bash
sudo noid-aide-baseline-review prepare
# Review the candidate report and metadata yourself, then use the tool's
# exact SHA-256 commit flow. Never move aide.db.new.gz into place directly.
```

### Captive portal on public Wi-Fi

Captive portals can require local gateway, resolver or login peers that the LAN
boundary blocks. Prefer a time-bounded exception for each exact peer supplied
by or identified on that network:

```bash
# Inspect local route/link state, then enter one exact IPv4 peer
ip -4 route
read -r -p 'Exact portal/gateway IPv4 peer: ' PORTAL_PEER
sudo noid-lan-allow --add "$PORTAL_PEER" --direction outbound --temp 15
sudo noid-lan-allow --list
```

If the portal uses unknown or changing local peers, the complete broad fallback
is interactive and intentionally has no automatic timeout:

```bash
sudo noid-lan-allow on
# Complete only the captive-portal login.
sudo noid-lan-allow off
noid-lan-allow status
```

`on` synchronizes every managed outbound LAN layer; a raw
`firewall-cmd --delete-policy` does not. It leaves physical inbound DROP and
disabled discovery services intact, but exposes outbound access to every local
destination. If the workflow is interrupted, the broad allow remains active:
run `sudo noid-lan-allow off` immediately and verify `BLOCKED`. If the portal
also requires its own LAN DNS, use the exact interface/address supplied by the
network with `resolvectl`, add that resolver as another temporary exact peer,
then `resolvectl revert` that interface after login.

### VPN won't come up

```bash
# Check NM dispatcher logs
sudo journalctl -t noid-vpn-zone -n 20

# NetworkManager-managed VPN: select the exact profile, then inspect/activate it
nmcli connection show
read -r -p 'Exact VPN profile name: ' VPN_PROFILE
sudo nmcli connection show "$VPN_PROFILE"
sudo nmcli --wait 30 connection up "$VPN_PROFILE"
```

For a provider client rather than a NetworkManager profile, use that client's
maintained status/log/activation interface. See `06-vpn-setup.md`.

## Environment variables that affect NoID Privacy behavior

- `$EDITOR` / `$VISUAL` — honoured by `sudoedit` in the workflows above
  (`$SUDO_EDITOR` takes precedence)
- `$PAGER` — used by `noid-help` (default `less`)
- `$XDG_STATE_HOME` — where `noid-welcome` state is tracked (default `~/.local/state`)

## Where everything lives

| Path | What |
|------|------|
| `/usr/share/doc/noid-privacy/` | All installed user guides plus companion reference files |
| `/usr/local/bin/noid`, `/usr/local/bin/noid-*` | Installed NoID Privacy executables, including internal hooks placed in the public executable directories; on this Fedora image `/usr/local/sbin` resolves to the same directory |
| `/etc/firewalld/policies/` | Custom firewalld policies |
| `/etc/sysctl.d/99-*.conf` | Hardening sysctl drop-ins |
| `/etc/modprobe.d/noid-*.conf` | Module blacklists |
| `/etc/systemd/system/` | Custom services + masked units |
| `/var/lib/noid-privacy/` | Persistent system state and build-health evidence |
| `/var/log/aide/` | AIDE scan logs |
| `/var/log/audit/` | Kernel audit log |

## Where to dig deeper

- `noid-help list` — every topic in this dir
- `noid --help` or `noid-help commands` — installed user-facing NoID Privacy commands in `/usr/local/bin`
- `/usr/share/doc/noid-privacy/00-README.md` — master index
- `/usr/share/doc/noid-privacy/01-getting-started.md` — first-day checklist
- `kickstart/snippets/NN-name.ks` — authoritative source per Module

### Power-user: fzf integration

`noid-help` is line-based by design. If you have `fzf` installed
(`sudo dnf install fzf`), you can layer interactive fuzzy-find +
preview on top of it for faster doc browsing:

```bash
# Fuzzy-pick a topic + preview the doc + open in $PAGER on Enter
noid-help list | awk '
  /^Available topics:$/ { in_topics=1; next }
  in_topics && /^$/ { if (seen) exit; next }
  in_topics { print $1; seen=1 }
' \
  | fzf --preview 'PAGER=cat noid-help {} | head -200' \
        --bind 'enter:execute(noid-help {})'

# Fuzzy-search across all docs (live grep as you type)
fzf --disabled --ansi \
    --bind "change:reload(grep -rniF --color=always -- {q} /usr/share/doc/noid-privacy/ || true)" \
    --preview 'echo {}' \
    --query "${1:-}"
```

This is an optional interactive layer; `noid-help` itself has no `fzf`
dependency. Reference: [junegunn/fzf](https://github.com/junegunn/fzf).

CHEAT_EOF
publish_doc "$CHEAT_DOC"
log "  [OK] 00-cheatsheet.md written"

# ------------------------------------------------------------------------------
# Phase 8 — Install noid-help navigator/inventory + noid entry point
# ------------------------------------------------------------------------------
PHASE="P8-help-cli"
log "Writing /usr/local/bin/noid-help"

BIN_TMP=$(mktemp "$BIN_DIR/.noid-help.XXXXXXXX")
cat > "$BIN_TMP" <<'HELP_EOF'
#!/bin/bash
# noid-help — NoID Privacy user-doc navigator
#
# Usage:
#   noid-help                  list all topics
#   noid-help list             (same)
#   noid-help <topic>          open the matching doc in $PAGER
#   noid-help search <keyword> grep all docs for keyword
#   noid-help commands         list installed noid/noid-* executables
#   noid-help --help           this help

set -u

# shellcheck source=/dev/null
[ ! -r /usr/local/lib/noid-privacy/agent-install-format.sh ] || \
    NOID_FMT_AUTO_TITLE="NoID Privacy — Help" \
    NOID_FMT_AUTO_SUBTITLE="Documentation and command index" \
    . /usr/local/lib/noid-privacy/agent-install-format.sh

DOC_DIR="/usr/share/doc/noid-privacy"
COMMAND_DIRS=(/usr/local/bin /usr/local/sbin)
read -r -a PAGER_ARGV <<< "${PAGER:-less -R}"
if [ "${#PAGER_ARGV[@]}" -eq 0 ]; then
    PAGER_ARGV=(less -R)
fi

_usage() {
    cat <<'USAGE_EOF'
Usage:
  noid-help                  list documentation topics
  noid-help list             list documentation topics
  noid-help <topic>          open a matching topic in $PAGER
  noid-help search <keyword> search all documentation topics
  noid-help commands         list installed noid/noid-* executables
  noid-help --help           show this help
USAGE_EOF
}

_require_docs() {
    if [ ! -d "$DOC_DIR" ] || [ -L "$DOC_DIR" ] || \
       [ "$(stat -c '%u:%g:%a' -- "$DOC_DIR" 2>/dev/null)" != "0:0:755" ]; then
        echo "noid-help: documentation directory is missing or untrusted: $DOC_DIR" >&2
        echo "  (it must be a real root:root 0755 image directory;" >&2
        echo "   roll back to a reviewed known-good root snapshot if available," >&2
        echo "   or reinstall the image)" >&2
        return 2
    fi
}

_trusted_doc() {
    local path=$1
    [ -f "$path" ] && [ ! -L "$path" ] &&
        [ "$(stat -c '%u:%g:%a:%h' -- "$path" 2>/dev/null)" = "0:0:644:1" ]
}

_list_topics() {
    local f name desc
    _require_docs || return
    printf 'Available topics:\n\n'
    for f in "$DOC_DIR"/*.md; do
        _trusted_doc "$f" || continue
        name=$(basename "$f" .md)
        # First heading from the file, bounded without byte-splitting UTF-8.
        desc=$(awk '/^# / {sub(/^# +/,""); print substr($0,1,70); exit}' \
            "$f" 2>/dev/null)
        printf '  %-32s %s\n' "$name" "$desc"
    done
    printf '\n'
    printf 'Usage:\n'
    printf '  noid-help <topic>          open the doc in %s\n' \
        "${PAGER_ARGV[0]##*/}"
    printf '  noid-help search <keyword> grep all docs\n'
}

_list_commands() {
    local dir dir_key path name found=0
    declare -A seen_dirs=()
    printf 'Installed NoID Privacy executables:\n\n'
    printf '  %-40s %s\n' 'COMMAND' 'INSTALLED PATH'
    for dir in "${COMMAND_DIRS[@]}"; do
        [ -d "$dir" ] || continue
        dir_key=$(readlink -f -- "$dir" 2>/dev/null) || continue
        [ -n "$dir_key" ] || continue
        [ -z "${seen_dirs[$dir_key]+x}" ] || continue
        seen_dirs["$dir_key"]=1
        # Literal, fixed directories only. Merely inspect regular executable
        # entries; never invoke a discovered command to obtain its metadata.
        # Canonical directory keys prevent Fedora's /usr/local/sbin -> bin
        # compatibility link from doubling every row and the final count.
        for path in "$dir_key"/noid "$dir_key"/noid-*; do
            [ -f "$path" ] && [ ! -L "$path" ] && [ -x "$path" ] || continue
            name=${path##*/}
            printf '  %-40s %s\n' "$name" "$path"
            found=$((found + 1))
        done
    done
    printf '\n%d executable(s). This inventory is generated from the live image.\n' "$found"
    printf 'Directory aliases are canonicalized; this includes internal hooks in these public executable directories.\n'
    [ "$found" -gt 0 ] || return 1
}

_open_topic() {
    local query="$1"
    local f
    local target=""
    local -a matches=()
    _require_docs || return
    case "$query" in
        ""|.*|*/*|*..*|*[!A-Za-z0-9._-]*)
            echo "noid-help: invalid topic selector: '$query'" >&2
            echo "  Use one literal topic name from: noid-help list" >&2
            return 2
            ;;
    esac

    # Exact match first
    if _trusted_doc "$DOC_DIR/$query.md"; then
        matches=("$DOC_DIR/$query.md")
    else
        # Prefix match
        for f in "$DOC_DIR/$query"*.md; do
            _trusted_doc "$f" && matches+=("$f")
        done
    fi
    if [ "${#matches[@]}" -eq 0 ]; then
        # Substring match, anywhere
        for f in "$DOC_DIR"/*"$query"*.md; do
            _trusted_doc "$f" && matches+=("$f")
        done
    fi

    if [ "${#matches[@]}" -eq 0 ]; then
        echo "noid-help: no topic matching '$query'" >&2
        echo "  Try: noid-help list" >&2
        return 1
    fi
    if [ "${#matches[@]}" -gt 1 ]; then
        echo "noid-help: ambiguous topic selector '$query':" >&2
        for f in "${matches[@]}"; do
            printf '  %s\n' "$(basename "$f" .md)" >&2
        done
        echo "  Use one exact topic name from: noid-help list" >&2
        return 2
    fi
    target=${matches[0]}

    if ! command -v -- "${PAGER_ARGV[0]}" >/dev/null 2>&1; then
        echo "noid-help: pager not found: ${PAGER_ARGV[0]}" >&2
        return 2
    fi
    "${PAGER_ARGV[@]}" -- "$target"
}

_search() {
    local kw="$1"
    local f
    _require_docs || return
    if [ -z "$kw" ]; then
        echo "noid-help: search needs a keyword" >&2
        echo "  Usage: noid-help search <keyword>" >&2
        return 2
    fi
    local found=0
    for f in "$DOC_DIR"/*.md; do
        _trusted_doc "$f" || continue
        if grep -Fqi -- "$kw" "$f"; then
            found=$((found + 1))
            printf '\n=== %s ===\n' "$(basename "$f")"
            # Show up to 5 matches with context
            grep -Fni -m 5 --color=auto -- "$kw" "$f"
        fi
    done
    if [ "$found" -eq 0 ]; then
        echo "noid-help: no matches for '$kw'"
        return 1
    fi
}

case "${1:-list}" in
    list)
        [ "$#" -le 1 ] || { _usage >&2; exit 2; }
        _list_topics
        ;;
    --help|-h)
        [ "$#" -eq 1 ] || { _usage >&2; exit 2; }
        _usage
        ;;
    commands|command|tools)
        [ "$#" -eq 1 ] || { _usage >&2; exit 2; }
        _list_commands
        ;;
    search)
        [ "$#" -eq 2 ] || { _usage >&2; exit 2; }
        _search "${2:-}"
        ;;
    *)
        [ "$#" -eq 1 ] || { _usage >&2; exit 2; }
        _open_topic "$1"
        ;;
esac
HELP_EOF
publish_bin "$BIN_DIR/noid-help"
log "  [OK] /usr/local/bin/noid-help installed (755)"

log "Writing /usr/local/bin/noid"
BIN_TMP=$(mktemp "$BIN_DIR/.noid.XXXXXXXX")
cat > "$BIN_TMP" <<'NOID_EOF'
#!/bin/bash
# Stable discovery entry point. This is deliberately not a generic dispatcher:
# an arbitrary suffix must never select and execute a privileged helper.
set -eu

HELP_BIN=/usr/local/bin/noid-help
[ -f "$HELP_BIN" ] && [ ! -L "$HELP_BIN" ] && [ -x "$HELP_BIN" ] &&
[ "$(stat -c '%u:%g:%a:%h' -- "$HELP_BIN" 2>/dev/null)" = "0:0:755:1" ] || {
    echo "noid: required helper is missing or untrusted: $HELP_BIN" >&2
    exit 2
}

case "${1:---help}" in
    --help|-h|help|commands|list)
        [ "$#" -le 1 ] || {
            echo "usage: noid [--help|commands|docs [topic]]" >&2
            exit 2
        }
        exec "$HELP_BIN" commands
        ;;
    docs)
        shift
        if [ "$#" -eq 0 ]; then
            exec "$HELP_BIN" list
        fi
        exec "$HELP_BIN" "$@"
        ;;
    *)
        echo "noid: unknown argument: $1" >&2
        echo "usage: noid [--help|commands|docs [topic]]" >&2
        exit 2
        ;;
esac
NOID_EOF
publish_bin "$BIN_DIR/noid"
log "  [OK] /usr/local/bin/noid installed (755)"

# ------------------------------------------------------------------------------
# Phase 9 — SELinux context restore
# ------------------------------------------------------------------------------
PHASE="P9-selinux"
log "  [OK] every published file was labeled fail-closed"

# ------------------------------------------------------------------------------
# Phase 10 — Verification
# ------------------------------------------------------------------------------
PHASE="P10-verify"
log "Running verification"

checks=0
fails=0

check() {
    local desc=$1
    shift
    checks=$((checks + 1))
    if "$@" >/dev/null 2>&1; then
        log "  [OK] $desc"
    else
        fails=$((fails + 1))
        log "  [FAIL] $desc"
    fi
}

verify_owned_regular() {
    local path="$1" expected_mode="$2"
    [ -f "$path" ] &&
        [ ! -L "$path" ] &&
        [ "$(stat -Lc '%u:%g:%a:%h' -- "$path" 2>/dev/null)" = \
            "0:0:${expected_mode}:1" ] &&
        matchpathcon -V "$path" >/dev/null
}

# Tier-B docs exist + min size
for pair in \
    "02-system-security.md:3072" \
    "03-firewall-zones.md:3072" \
    "05-lan-isolation.md:3072" \
    "08-masked-services.md:3072" \
    "11-dns-custom.md:3072" \
    "00-cheatsheet.md:4096"; do
    f="${pair%:*}"
    min="${pair#*:}"
    path="/usr/share/doc/noid-privacy/$f"
    check "$f exists" test -f "$path"
    sz=$(stat -c %s "$path" 2>/dev/null || echo 0)
    sz=${sz:-0}
    check "$f >= ${min} bytes (actual: $sz)" test "$sz" -ge "$min"
    check "$f regular root:root 0644 link-count=1" \
        verify_owned_regular "$path" 644
done

# noid-help CLI
check "noid-help regular root:root 0755 link-count=1" \
    verify_owned_regular /usr/local/bin/noid-help 755
check "noid entry point regular root:root 0755 link-count=1" \
    verify_owned_regular /usr/local/bin/noid 755

# noid-help must have the three subcommands + bash syntax
if bash -n /usr/local/bin/noid-help 2>/dev/null; then
    checks=$((checks + 1))
    log "  [OK] noid-help bash syntax valid"
else
    checks=$((checks + 1))
    fails=$((fails + 1))
    log "  [FAIL] noid-help bash syntax ERROR"
fi

# Case-insensitive grep pins required implementation tokens.
for kw in "_list_topics" "_open_topic" "_search" "_list_commands" \
          "DOC_DIR=" "PAGER_ARGV=" "COMMAND_DIRS="; do
    check "noid-help has: $kw" grep -Fqi -- "$kw" /usr/local/bin/noid-help
done
check "noid entry point bash syntax valid" bash -n /usr/local/bin/noid
# shellcheck disable=SC2016  # Match the deployed literal, not this shell's value.
check "noid --help delegates only to the read-only command inventory" \
    grep -qF 'exec "$HELP_BIN" commands' /usr/local/bin/noid

# Each Tier-B doc should cross-reference at least one other doc + have
# a top-level title
for f in 02-system-security.md 03-firewall-zones.md 05-lan-isolation.md \
         08-masked-services.md 11-dns-custom.md 00-cheatsheet.md; do
    path="/usr/share/doc/noid-privacy/$f"
    first_line=$(head -n 1 "$path" 2>/dev/null || true)
    check "$f has top-level heading" grep -q '^# ' <<< "$first_line"
done

log "Verification: $((checks - fails))/$checks passed"
if [ "$fails" -gt 0 ]; then
    die "$fails verification check(s) FAILED"
fi

# ------------------------------------------------------------------------------
# Phase 11 — Health stamp
# ------------------------------------------------------------------------------
PHASE="P11-stamp"
# M30_HEALTH_PUBLICATION_BEGIN
if [ ! -d "$STAMP_DIR" ] || [ -L "$STAMP_DIR" ] \
   || [ "$(stat -Lc '%u:%g:%a' -- "$STAMP_DIR" 2>/dev/null || true)" != \
        0:0:755 ] \
   || ! matchpathcon -V "$STAMP_DIR" >/dev/null; then
    die "shared health-stamp directory drifted before Module 30 publication"
fi

verify_m30_health_stamp() {
    local path="$1"
    [ -f "$path" ] \
        && [ ! -L "$path" ] \
        && [ "$(stat -Lc '%u:%g:%a:%h' -- "$path" 2>/dev/null || true)" = \
            0:0:644:1 ] \
        && [ "$(wc -l < "$path")" -eq 8 ] \
        && [ "$(grep -c '^module=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^name=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^version=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^status=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^timestamp=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^checks_passed=' "$path" || true)" -eq 1 ] \
        && [ "$(grep -c '^checks_total=' "$path" || true)" -eq 1 ] \
        && grep -qFx '# NoID Privacy — Module 30 Health Stamp' "$path" \
        && grep -qFx 'module=30' "$path" \
        && grep -qFx 'name=user-docs-tier-b' "$path" \
        && grep -qFx 'version=1' "$path" \
        && grep -qFx 'status=ok' "$path" \
        && grep -Eq \
            '^timestamp=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' \
            "$path" \
        && grep -qFx "checks_passed=$((checks - fails))" "$path" \
        && grep -qFx "checks_total=$checks" "$path"
}

STAMP_TMP=$(mktemp "$STAMP_DIR/.stamp-30-user-docs-tier-b.ok.XXXXXXXX")
cat > "$STAMP_TMP" <<STAMP_EOF
# NoID Privacy — Module 30 Health Stamp
module=30
name=user-docs-tier-b
version=1
status=ok
timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
checks_passed=$((checks - fails))
checks_total=$checks
STAMP_EOF

chmod 0644 "$STAMP_TMP"
chown root:root "$STAMP_TMP"
restorecon -F -- "$STAMP_TMP" \
    || die "cannot label Module 30 health-stamp candidate"
matchpathcon -V "$STAMP_TMP" >/dev/null \
    || die "Module 30 health-stamp candidate label differs"
verify_m30_health_stamp "$STAMP_TMP" \
    || die "staged Module 30 health-stamp contract is invalid"
sync -- "$STAMP_TMP" \
    || die "cannot sync Module 30 health-stamp candidate"
if ! mv -fT -- "$STAMP_TMP" "$STAMP"; then
    rm -f -- "$STAMP" || true
    die "cannot publish Module 30 health stamp"
fi
STAMP_TMP=""
STAMP_PUBLICATION_ACTIVE=1
restorecon -F -- "$STAMP" \
    || die "cannot label published Module 30 health stamp"
matchpathcon -V "$STAMP" >/dev/null \
    || die "published Module 30 health-stamp label differs"
sync -- "$STAMP" \
    || die "cannot sync published Module 30 health stamp"
sync -- "$STAMP_DIR" \
    || die "cannot sync Module 30 health-stamp directory"
verify_m30_health_stamp "$STAMP" \
    || die "published Module 30 health-stamp contract is invalid"
STAMP_PUBLICATION_ACTIVE=0
log "  [OK] exact Module 30 health stamp published atomically"
# M30_HEALTH_PUBLICATION_END

trap - EXIT INT TERM
log "=== Module 30 User Documentation Tier B complete ==="
%end

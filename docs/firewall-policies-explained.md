# NoID Privacy Firewall Architecture — Policies + Zones Explained

NoID Privacy Workstation uses **firewalld with custom policies** (not just
zones) to implement layered network filtering: WAN-only egress, LAN
isolation, topology-aware directly-connected-prefix blocking, and a VPN zone
that permits outbound/established traffic without accepting new inbound flows.
This document explains the project-owned firewalld policies and zones, plus
the Fedora/libvirt policy objects that may also be present. `--get-policies`
shows installed objects, while `--get-active-zones` is runtime state and
changes with the available interfaces.

## Live Architecture (post-deploy)

```bash
firewall-cmd --get-default-zone        # → drop
firewall-cmd --get-active-zones        # runtime interface-to-zone assignments
firewall-cmd --get-policies            # installed project + package policies
firewall-cmd --info-zone=drop          # → empty services + ports
sudo nft list table inet noid_lan_topology
sudo /usr/local/sbin/noid-lan-xdp status
```

## Zone Layout

| Zone | Target | Interfaces | Purpose |
|---|---|---|---|
| `drop` (default) | DROP | physical Ethernet/Wi-Fi + killswitch dummy | Untrusted physical links: no new inbound host traffic |
| `noid-vpn` | DROP | active VPN tunnel | Tunnel egress and established replies; no new inbound host traffic |

`libvirt-routed-in`, `libvirt-routed-out` and `libvirt-to-host` are policies,
not zones. A libvirt installation may additionally provide its own `libvirt`
zone for `virbr*`; inspect the live assignment rather than treating a policy
name as an interface zone.

The drop default denies new inbound traffic on any interface that is not
explicitly assigned elsewhere. M23 also forces every physical profile back to
`drop` at pre-up and up time, closing imported/saved `home` or `public` zone
overrides.

Outbound LAN isolation has two layers: the `block-lan-out` policy covers known
private/reserved ranges and discovery ports, while `inet noid_lan_topology`
atomically tracks the actual directly connected Ethernet/Wi-Fi prefixes. The
latter also blocks a LAN that uses unusual or public address space. Explicit
per-IP exceptions from the Network app are mirrored into both layers.

DHCPv4 client egress is the deliberately narrow control-plane exception to
both layers. The earlier M03 output hook first admits a root-owned socket on a
physical interface using IPv4 UDP source 68 and destination 67. Exact
administrator-approved peer traffic and correlated replies are evaluated
next; they retain the complete access the Network app explicitly granted.
While the default boundary is `BLOCKED`, a dedicated interface set then drops
every remaining physical IPv4 UDP source-68 packet. A host-only
negative-priority firewalld rule can consequently continue source port 68
ahead of the static private/broadcast destination drops without creating an
application-data escape to an unapproved destination. firewalld rich language
accepts only one port element per rule, so neither rule is sufficient by
itself: their ordered intersection is the contract. Global LAN allow
atomically empties the dedicated guard set while detaching the host policy.
The derived libvirt policy removes the continuation entirely; forwarded VM
traffic receives no DHCP exception. A statically configured IPv4 link emits
no DHCP request, but its live address and directly connected prefix enter the
same topology boundary independently of their configuration source.

A third table, `netdev noid_l2_guard`, attaches ingress and egress hooks to
every kernel-backed physical NIC. It admits only IPv4, IPv6, ARP, and EAPOL;
all other EtherTypes are dropped. Ahead of that table, the project-owned XDP
program defaults to `XDP_DROP`. Native-driver XDP runs before `skb` allocation;
the generic fallback uses an `skb` but still runs before the kernel's ordinary
AF_PACKET packet taps. Its TC egress companion records bounded IPv4 reverse
tuples after nftables output filtering; gateway IPv4 reaches the host only as a
matching reply. Gateway/local MACs, reply flows and administrator-approved
peer IP/MAC bindings are keyed by the exact physical interface, so
authorization on one NIC is not reusable on another. The explicit global IP
opt-in is synchronized from the same topology transaction. Peer edits,
revocations and later re-activation publish a fresh reply-flow map with the
replacement policy; the old TC program therefore cannot race a stale tuple
back into the new generation. This fail-closed transition can require an
existing unrelated flow to retransmit once. Structurally valid
standard ARP requests/replies—including RFC 5227 Probes and Announcements—are
admitted to native kernel handling; exact permanent neighbours resist ordinary
gateway/approved-peer cache replacement. DHCPv4 replies are separately checked
against the receiving interface's local MAC and an egress-observed transaction.
TC can observe that request only after the exact host output selector above and
both nftables/firewalld layers have passed it.
When DHCP has not exported `IP4_GATEWAY` at the awaited `pre-up` event, M04
retries gateway learning at `up`/`dhcp4-change` from the exact-interface route.
Failure after activation disconnects only that unpinned interface. The brief
first-link interval before the post-DHCP observation remains an explicit
trust-on-first-use boundary; permanent neighbour pinning is not Ethernet
authentication.
The pre-up topology and pin-restore gates remain awaited. Their complete
post-activation XDP/nft and gateway revalidation transactions run through
NetworkManager's maintained `no-wait.d` placement, so several seconds of WLAN
lease/reapply work cannot sit in the serial dispatcher queue ahead of an
unrelated VPN tunnel's required pre-up zone assignment.
Every IPv4 fragment is rejected rather than admitted from cached first-fragment
state. The controller's root-private versioned state confines generations to
the BPF root, atomically reserves every fresh generation, validates exact
reusable-map layouts, and correlates structured live XDP/TC IDs and tags with
the pinned programs before reporting `ACTIVE`. Root-private locks under
`/run/noid-privacy` serialize refreshes without letting an unprivileged process
hold the network transaction lock.
EAPOL remains a documented authentication exception. Physical IPv6 is disabled
by Modules 02/07. Radio management frames below the host Ethernet/IP stack and
firmware OOB remain outside this host filter. VLAN/PPPoE and other non-default
WAN encapsulations require an explicit policy extension before use. The exact
hardware/update support boundary is documented in
[`hardware-network-compatibility.md`](hardware-network-compatibility.md).

## Policy Layout

### Active policies (used by NoID Privacy's networking design)

**`block-lan-out`** — primary LAN-isolation policy

- 38 rich-rules: 37 LAN drops plus one host-only DHCPv4 source-port
  continuation whose exact root-owned UDP 68-to-67 selector is enforced by
  M03 before firewalld
- Blocks SMB/NetBIOS (137-139, 445), SSDP/UPnP (1900, 3702, 5357),
  mDNS/LLMNR (5353, 5355) on **both IPv4 and IPv6**
- Blocks all IPv4 LAN destinations (10/8, 172.16/12, 192.168/16, 100.64/10
  CGN, 169.254/16 link-local, 127/8 loopback, 0/8 this-network, TEST-NET-1/2/3,
  RFC2544 benchmark, multicast, broadcast)
- Blocks all IPv6 ULA + link-local (fc00::/7, fe80::/10, multicast ff00::/8,
  doc 2001:db8::/32, loopback ::1/128, unspecified ::/128)
- Active ingress: `HOST` (= host's own outbound traffic)
- Active egress: `drop` (= the dropped interfaces, i.e. WiFi)
- Effect: even if a process tries to talk to the local network, it gets
  blocked before reaching the firewall's drop-zone

**`block-lan-out-vms`** — same drop rules, applied to libvirt-zone forwarding

- Inherits the 37 drop rules via `cp + sed` substitution from
  `block-lan-out`; the host DHCP-client continuation is deleted before
  publication
- Created when the libvirt zone is installed; it only sees matching forwarded
  traffic when that zone is actually used

**`allow-host-ipv6`** — narrowed stock IPv6 control policy

- Allows the six MLD/NDP ICMPv6 types retained by Module 03 from `ANY` to
  `HOST`; it is not tied to a provider-specific interface and does not label VPN IPv6
  “privacy-clean”.
- Router Advertisement and Redirect are removed; physical-WAN IPv6 has
  additional Module 02/07 controls.

**`libvirt-to-host`** — REJECT-target with limited service-allow

- Services allowed: `dhcp`, `dhcpv6`, `dns`, `tftp` (for VM PXE-boot if used)
- **`ssh` REMOVED at deploy time** (fix: pykickstart's
  `firewall --enabled` adds ssh by default to the allow-list, but NoID Privacy has
  no sshd installed — ssh-allowance is an inert attack-surface marker that
  was stripped at deploy time)

### Policies that exist but ARE EFFECTIVELY DISABLED

Current Fedora/firewalld packages can supply the following five `gateway-*`
policy files with Fedora's own `<disable />` marker. NoID Privacy neither
enables nor deletes them; verify the installed vendor policy state rather than
treating it as a project-owned disable transaction:

| Policy | Purpose (when enabled) | Shipped state |
|---|---|---|
| `gateway-dmz-to-HOST` | DMZ-zone → host filtering | Fedora vendor file contains `<disable />` |
| `gateway-lan-to-HOST` | LAN-zone → host filtering | Fedora vendor file contains `<disable />` |
| `gateway-lan-to-work` | LAN-zone → work-zone forwarding | Fedora vendor file contains `<disable />` |
| `gateway-lan-to-world` | LAN-zone → external forwarding | Fedora vendor file contains `<disable />` |
| `gateway-world-to-HOST` | External → host filtering | Fedora vendor file contains `<disable />` |

They remain package-owned instead of being deleted. Enabling gateway behavior
is outside this workstation threat model and requires a complete forwarding,
NAT, zone and service review; do not enable these stubs as a one-command recipe.

If you see `gateway-*` in `firewall-cmd --get-policies` and wonder if they
process traffic, the answer is **no** — verify with:

```bash
firewall-cmd --info-policy=gateway-lan-to-HOST | grep "disable:"
# Expected: disable: yes
```

### Permissive policies (libvirt-routed traffic forwarding)

**`libvirt-routed-in`** + **`libvirt-routed-out`** — VM traffic forwarding

- These are **permissive** (target ACCEPT, no rich-rules) by design
- They only become active when libvirt is running VMs on a virbr*
  interface
- On a workstation with no VMs: they exist but never see traffic
- The derived `block-lan-out-vms` policy applies the destination/on-link LAN
  restriction to libvirt egress when the libvirt zone is present. VM-to-host,
  hypervisor and guest policy still require separate review.

## Common questions

### "Why does `firewall-cmd --info-zone=drop` show empty services + ports?"

Because the drop-zone target is `DROP` — there are no services or ports to
list because nothing gets through. The drop-zone only exists to assign
interfaces to a deny-by-default policy. The actual filtering happens in
the policies (block-lan-out, etc.).

### "Why does a VPN use the custom `noid-vpn` zone?"

The tunnel must be outside the physical `drop` egress-zone so provider-internal
DNS/private tunnel addresses are not mistaken for the local physical LAN.
Using firewalld's stock `trusted` zone would be too permissive: it has target
ACCEPT and can expose a listening host service to traffic routed through the
VPN. `noid-vpn` has target DROP, so outbound connections and their established
replies work while unsolicited inbound tunnel traffic does not.

### "Why can a container-published port still require firewalld approval?"

`StrictForwardPorts=yes` prevents Docker, Podman or another external DNAT
manager from making forwarded traffic implicitly acceptable merely by creating
its own NAT rule. Publishing a container or VM port therefore also requires an
explicit firewalld allowance. This keeps the externally reachable surface in
one auditable policy plane.

### "Why does the host rule count look high (38)?"

Because every rich-rule generates a corresponding nftables entry, and IPv4
and IPv6 each get their own. The common drop body has 37 rules: 9 IPv4
service, 13 IPv4 destination, 9 IPv6 service and 6 IPv6 destination rules.
The host policy has one additional DHCPv4 continuation, for 38 total; the VM
policy retains only the 37 drops. The dynamic topology table adds a small
set-based guard rather than one rule per subnet.

### "How do I allow a specific LAN destination (e.g. printer, NAS)?"

`noid-lan-allow` supports exact per-peer exceptions with an explicit direction
and durable optional expiry:

```bash
# Permanent host-initiated access to one peer
sudo /usr/local/bin/noid-lan-allow --add <IP> --direction outbound

# The same exception with bounded auto-revert (range 1..1440 minutes)
sudo /usr/local/bin/noid-lan-allow --add <IP> --direction outbound --temp <MINUTES>

# Peer-initiated TCP access to one local port (use PORT or START-END)
sudo /usr/local/bin/noid-lan-allow --add <IP> --direction inbound \
  --protocol tcp --ports <PORT> [--temp <MINUTES>]

# Permit both host- and peer-initiated UDP traffic for one port range
sudo /usr/local/bin/noid-lan-allow --add <IP> --direction both \
  --protocol udp --ports <START-END> [--temp <MINUTES>]

# Revert a per-IP exception + remove its durable expiry state
sudo /usr/local/bin/noid-lan-allow --revert <IP>

# List all currently-active per-IP exceptions (no root required). Exception
# records are world-readable by design; peer MAC/interface bindings are
# root-private.
noid-lan-allow --list
```

Outbound permission is inserted as a `priority="-100"` destination accept in
`block-lan-out`; inbound permission is an exact source/protocol/port accept in
the physical `drop` zone. Every grant is also bound to the validated,
directly-attached IPv4 peer's interface and ARP identity across the XDP/TC,
nftables and WAN-strict mirrors. The bounded raw `arping` observation must
agree with exactly one device-scoped kernel-neighbour identity, and the final
pin is accepted only after one exact `PERMANENT` postcheck. This is TOFU, not
cryptographic Ethernet authentication. Outbound-only therefore permits
correlated replies but no new peer-initiated connection. IPv6 is rejected
until the mandatory XDP boundary has an IPv6/NDP peer-identity and return-flow
contract. Legacy IPv6 rules can still be revoked and are removed by
fail-closed reconciliation when their metadata is absent or invalid.

Temporary exceptions persist a closed root-owned record containing their
absolute deadline and a same-boot monotonic deadline. An installed boot service
reconciles that state before NetworkManager. While a temporary exception
exists, a systemd generator converts a closed root-owned runtime schedule into
both an absolute realtime trigger and a monotonic trigger for the earliest
deadline. This avoids continuous polling while retaining clock-jump coverage.
The installed five-second timer expression is a fail-closed fallback only; the
generated deadline resets it during normal operation. Reboot before expiry
preserves the remaining wall-clock bound; reboot at/after expiry, clock
rollback, missing or invalid state, and failed revocation all fail closed
instead of silently turning the rule into a permanent exception.

### "What about a GUI?"

NoID Privacy Network app (Module 36) provides the LAN Exceptions tab
with EntryRow + Duration ComboRow + Add button + active-exception list
with per-row revert button. Launches via the App Grid ("NoID Privacy
Network") or the Welcome dialog **Companion Apps** group.

### "How do I disable the whole policy (legacy global allow)?"

```bash
sudo /usr/local/bin/noid-lan-allow on    # disable the global local/on-link destination block
sudo /usr/local/bin/noid-lan-allow off   # restore hardened default (re-attach zones)
```

`on` is a verified cross-layer transaction: it records one empty, root-owned,
root-private and single-linked durable opt-in marker, detaches the firewalld
destination policy, empties the topology drop
sets, switches the XDP global-policy map on every qualified Ethernet link and
admits only currently connected prefixes through WAN-strict. The command does
not report success if that Ethernet XDP switch or its attachment postcheck
fails; the runtime state becomes `INCONSISTENT` and the later nft widening is
not applied. Standard ARP and existing permanent neighbour pins are unchanged.
It does **not** open unsolicited inbound IP services; physical interfaces
remain in the target-DROP zone. `off` restores all layers. A partial/manual
state is reported as `INCONSISTENT`, never as an optimistic allow or block:

```bash
noid-lan-allow status
noid-lan-allow --global-state
```

Per-IP exceptions are usually preferred because the global toggle deliberately
makes every peer on each connected local prefix reachable from the host.

## Cross-references

- [Module 03: firewalld](../kickstart/snippets/03-firewalld.ks) — design,
  rationale and current status
- [Module 05: LAN isolation](../kickstart/snippets/05-lan-isolation.ks) — destination
  block list rationale
- [Module 06: VPN killswitch](../kickstart/snippets/06-vpn-killswitch.ks) — kill-switch
  architecture
- [WAN egress strict](wan-egress-strict.md) — pinned-endpoint nft-table
- [Threat model](threat-model.md) — what NoID Privacy firewalls against

# NoID Privacy physical-link XDP boundary

This directory contains the source and pinned runtime payload for the earliest
host-controlled LAN ingress layer. In native-driver mode, XDP runs before Linux
allocates an `skb`. When a driver lacks native XDP, the controller uses generic
XDP: that mode works on an `skb`, but the kernel executes it before `ptype_all`
packet taps, including ordinary AF_PACKET capture. Frames dropped in either
mode therefore do not reach ordinary packet sockets. A TC egress program
records bounded IPv4 reverse tuples after the nftables output path; XDP admits
a gateway frame only when it matches one of those observed flows.

## Default behavior

- Drop all physical-link ingress unless a rule below admits it.
- Admit EAPOL for wired/WPA-Enterprise authentication.
- Admit a structurally valid DHCPv4 server reply only when its interface,
  transaction ID and BOOTP client hardware address match a request observed at
  TC egress during the previous 90 seconds. The same trusted egress hook
  registers the locally emitted unicast Ethernet source before address
  acquisition, so the ingress map follows NetworkManager stable-MAC rotation
  without opening source-unrestricted DHCP.
- Admit structurally valid ARP requests addressed to broadcast/local Ethernet
  and replies correlated to a local target MAC. This is intentionally broader
  than the IP-flow branches: RFC 5227 requires Probes, Announcements, conflict
  Requests/Replies and ordinary host replies to reach native IPv4 ACD. Exact
  permanent gateway/peer neighbour entries prevent ordinary cache replacement.
- Admit checksum-valid, unfragmented TCP or UDP matching the inbound protocol
  and port selector of an exact interface/IP/MAC peer binding created by the
  explicit NoID Privacy Network per-peer opt-in and addressed to that
  interface's local Ethernet MAC. A peer cannot initiate an ICMP echo request;
  correlated ICMP replies and errors require that peer's outbound bit.
- Admit checksum-valid, unfragmented TCP, UDP, ICMP echo replies and related
  ICMP errors only for a recently observed egress flow, the exact local
  Ethernet destination, and either a pinned gateway MAC or the exact
  outbound-approved LAN peer binding.
- Admit all ingress only while the explicit global LAN opt-in transaction is
  active. On a qualified Ethernet path, a failed XDP switch/postcheck aborts
  the widening before later nft layers and publishes `INCONSISTENT`.

Physical-interface IPv6 is disabled elsewhere in the image. VPN-internal IPv6
does not traverse these physical XDP links.

IPv4 total length is bounded to the release-qualified 1500-byte physical-link
contract. Every admitted IPv4 header must have a valid header checksum; TCP
and ICMP checksums are mandatory, and NoID Privacy deliberately requires a
nonzero, valid UDP checksum. IPv4 UDP historically permits an omitted checksum,
but the current UDP usage BCP recommends checksums and permits receivers to
discard zero-checksum datagrams
([RFC 8085 §3.4](https://www.rfc-editor.org/rfc/rfc8085.html#section-3.4)).
All IPv4 fragments are dropped because XDP cannot validate a transport
checksum until reassembly. Flow lifetimes are intentionally bounded in source:
TCP two hours, UDP five minutes, ICMP one minute and DHCP transactions 90
seconds. Ingress never refreshes them. An ordinary policy refresh reuses the
flow, DHCP and counter maps so it does not break an activation already in
progress or established WAN sessions; configuration maps and program links are
replaced from a fully populated fresh generation. The flow map is a
65,536-entry LRU map: sustained connection churn evicts the oldest reverse
tuples and therefore fails closed until a later egress packet recreates one. A
peer edit, revoke or new activation instead uses a fresh flow map before
publishing the replacement peer policy. The still-attached old TC program
cannot repopulate that new generation. This prevents an old peer session from
becoming valid again; an unrelated established flow may need one fail-closed
retransmission after the explicit policy transition.

The controller state is a root-owned mode-`0600` file with a closed, versioned
grammar: one state schema, one map schema, the selected object SHA-256, one
canonical generation directly below the non-symlink BPF root, and at least one
unique interface/mode row. Unknown, duplicate, partial, empty, cross-root and
symlinked states fail closed. A legacy `GEN`/`IFACE` state from the immediately
preceding controller is accepted only for one validated detach/rollback during
migration; its maps are never reused and it cannot report `ACTIVE`. Current
flow, DHCP and counter maps are reused only when their JSON-reported type,
flags, key/value sizes and capacity all match the declared schema.
Fresh generation names are reserved atomically with `mktemp` before cleanup can
own them. Controller invocations serialize on a mode-`0600`, root-owned lock
under `/run/noid-privacy`, so an unprivileged process cannot hold the refresh
boundary.

Before a refresh can modify a link, both programs in the old generation must
have the exact expected BPF type and name. A multi-interface failure restores
each already-modified interface from that validated generation in its recorded
old XDP mode. This includes an interface where the new XDP overwrite succeeded
but its paired TC attach failed; the fail-closed new XDP remains attached until
rollback replaces it, so that failure does not create an unprotected detach
window. The transaction leaves the authoritative state bytes unchanged and
removes the pending generation. `status` then binds each pinned program's
type, name and ID to the exact interface, XDP mode and clsact egress hook
reported by device-scoped BPF JSON; a name-only textual match is insufficient.
The attach transaction itself owns the fixed TC preference, handle and
direct-action arguments, which that status interface does not re-report.

## Security boundary and unavoidable exceptions

This closes the raw-socket observation gap left by nftables ingress hooks for
non-ARP unsolicited LAN frames. Standard ARP is deliberately visible to the
kernel and ordinary packet sockets because suppressing it would also suppress
native IPv4 conflict detection and address defence. It does not turn
an unauthenticated Ethernet or Wi-Fi link into a cryptographically authenticated
transport. DHCP, EAPOL and standard ARP remain necessary link traffic. A local
attacker on the WAN interface able to
spoof its pinned gateway MAC and correctly guess an active interface-bound
reverse tuple can still construct a frame
that reaches later firewall/conntrack layers. Use authenticated Wi-Fi/802.1X or
a separately controlled network adapter when the link itself is hostile.
Locally emitted source-MAC observations may leave the immediately preceding
MAC in the bounded map until the next topology refresh; stale unicast
destinations are filtered by the NIC, and DHCP still requires the exact live
transaction tuple.

## Hardware and update compatibility

The controller first requests native-driver XDP and then the kernel's generic
XDP fallback. It also requires a `clsact` TC egress hook. If either XDP mode or
the TC hook cannot be attached to a detected hardware-backed interface, the
independent firewalld/nft/netdev baseline remains active and WAN repair access
is retained. `/run/noid-privacy/lan-xdp-health`, `noid-status`, the journal and
a graphical-login warning then identify the incomplete raw-packet boundary as
`DEGRADED`. The warning points to the previous Fedora kernel in GRUB as the
full-protection rollback. The active mode is shown by `sudo noid-lan-xdp status`.

Conventional Ethernet and Wi-Fi netdevs are the intended physical data paths.
USB Ethernet is covered when it presents the same Ethernet netdev contract.
Raw-IP WWAN, bonding/team/bridge masters, VLAN, PPP/PPPoE and other stacked or
non-Ethernet paths are not release-qualified: they must not be represented as
supported until their complete topology and reply-flow behavior has a runtime
test. The controller rejects a non-Ethernet ARPHRD type before it can report
`ACTIVE`; the packet gate proves that PPPoE discovery/session EtherTypes take
the default-drop path. Unsupported paths fail closed rather than receiving a
weaker policy.

The object uses stable BPF instructions, map types, program types and helpers;
it does not call unstable BPF kfuncs or depend on kernel-internal structure
layouts. Every boot nevertheless submits the object to the running kernel
verifier, attaches both programs and verifies the live attachment. The guided
DNF workflow repeats the refresh and verification after package updates. A new
kernel can only be verified after reboot; if that verifier or a changed driver
rejects only XDP/TC, the explicitly degraded WAN-recovery state applies. A
failure of the independent firewall/topology baseline still blocks activation.
No arbitrary future kernel regression can honestly be guaranteed harmless.

## Reproducible build

The committed object was produced on updated Fedora 44 with:

```text
source_dir=<repo>/overrides/noid-lan-xdp
clang -target bpf -O2 -g -Wall -Wextra -Werror \
  -fdebug-prefix-map="$source_dir=/usr/src/noid-privacy-fedora" \
  -c "$source_dir/noid-lan-xdp.bpf.c" -o noid-lan-xdp.bpf.o
strip --strip-debug noid-lan-xdp.bpf.o
```

The prefix map removes the build-host path. Stripping removes DWARF while
retaining BTF/BTF.ext. The current object was independently reproduced with
this measured Fedora 44 toolchain:

```text
clang-0:22.1.8-4.fc44.x86_64
binutils-0:2.46.1-1.fc44.x86_64
libbpf-devel-2:1.6.3-2.fc44.x86_64
kernel-headers-0:7.1.3-200.fc44.x86_64
```

This is provenance, not a floating-package bypass: CI installs Fedora 44's
maintained toolchain and requires a byte-identical rebuild. A compiler update
that changes the object therefore fails the gate and requires a reviewed
object/toolchain refresh. Run the same checks locally with:

```bash
sudo scripts/build-lan-xdp-object.sh --check
scripts/regen-lan-xdp-embed.sh --check
```

The build helper rebuilds through the declared command, optionally submits
both programs to the running Fedora kernel verifier, and checks the decoded
object hash. The regeneration helper keeps the controller,
base64 object, hash assertion, and Module 03 heredocs byte-identical.

# Physical-network hardware and update compatibility

NoID Privacy Workstation 44 is an x86_64 Fedora image. Its physical-network
security boundary is capability-tested at runtime; it is not a chipset-name
allow-list and it is not a claim that every network topology ever exposed by a
Linux driver has identical semantics.

## Required runtime contract

For every detected hardware-backed Ethernet-framed network interface, the
topology transaction must complete all of these operations:

1. Load the exact SHA-256-pinned BPF object through the running kernel verifier.
2. Attach the ingress program in native-driver XDP mode, or use generic XDP if
   the driver has no native implementation.
3. Attach the egress flow observer at `clsact/egress` with the expected program.
4. Populate local-MAC, gateway-MAC, peer and global-policy maps from the same
   validated topology state. Every non-global identity/flow key includes the
   physical interface index; authorization on one NIC cannot satisfy another.
5. Require the Ethernet ARPHRD contract (`/sys/class/net/<iface>/type = 1`)
   and verify that the pinned XDP program ID and TC filter are live on each
   qualified link.

The explicit global LAN opt-in is also all-or-nothing on qualified Ethernet
links: if the XDP global-policy map cannot be switched and postchecked, the
transaction publishes `INCONSISTENT` and does not apply the later nft widening.
On a Raw-IP-only host there is no compatible XDP attachment to switch, so the
documented L3/firewalld/WAN-strict fallback remains the applicable boundary.

Hardware-backed non-Ethernet links remain in the port-independent L3 topology,
firewalld and WAN-strict interface sets, but are excluded from Ethernet
XDP/TC and `ether type` netdev hooks. Their presence publishes
`STATE=DEGRADED` with an explicit journal reason while already-qualified
Ethernet/Wi-Fi links retain their verified attachments. A durable LAN-peer
exception is rejected unless its exact interface satisfies the Ethernet XDP
contract; an unsupported link therefore cannot acquire a partially enforced
exception.

The initial service runs before NetworkManager and is a hard NetworkManager
dependency for the firewalld, topology and netdev-L2 layers. Failure in those
baseline layers prevents activation. A transient XDP/TC sync or postcheck
degradation repeats the complete topology transaction within the boot
wrapper's bounded retry budget; it does not silently consume only one attempt.
If all attempts retain that XDP-only degradation, the owner is not stranded
without WAN repair access: the committed baseline layers remain active,
`/run/noid-privacy/lan-xdp-health` stays `STATE=DEGRADED`, and the journal,
`noid-status` and graphical login notifier all expose that the raw-packet
boundary is incomplete. A hotplug service and NetworkManager dispatchers
repeat the transaction for later devices and connection changes. The
security-critical physical `pre-up` copies are awaited; ordinary `up`, lease
and reapply copies use the maintained `no-wait.d` phase so a long topology/ARP
refresh cannot delay a different profile's awaited activation gate. If DHCP
has not exported a gateway at
`pre-up`, the active-link event retries from that exact interface's route and
disconnects the interface when trust establishment fails. Gateway discovery
remains an exact-interface/exact-IP, bounded, ambiguity-rejecting standard-ARP
observation. The interval before that post-DHCP observation is a small
first-link trust-on-first-use boundary, not cryptographic link authentication.
It does not claim XDP is active; native IPv4 ACD and ordinary ARP remain
available in both ACTIVE and DEGRADED states.

WireGuard has a separate outer-link compatibility check. Before a
NetworkManager WireGuard activation completes, and again after physical-route
changes, M06 computes the fragmentation-free live ceiling from every resolved
peer's actual outer route. It only lowers an oversized kernel-link MTU and
never edits or saves a provider/user profile. An unresolved peer or an unsafe
sub-1280 result for a tunnel carrying IPv6 leaves the link unchanged and is
reported; `noid-network-audit mtu` independently exposes the postcondition.
OpenVPN owns a different encapsulation/MTU lifecycle and is not modified by
this WireGuard-specific helper. Detecting a standard tunnel transport does not
qualify a provider application's own privileged daemon, DNS, routing or
kill-switch firewall; those remain release-specific runtime boundaries.

Both the initial and hotplug services explicitly require and follow
`systemd-tmpfiles-setup.service`, which owns their shared root-only runtime
directory and locks. This makes ownership and failure propagation visible; it
is not a coldplug-race fix, because ordinary services already follow
`sysinit.target` and Fedora orders tmpfiles setup before that target. Preserve
an actual `226/NAMESPACE` journal as evidence and diagnose the exact namespace
path instead of inferring a timing cause.

`sudo /usr/local/sbin/noid-lan-xdp status` reports the actual per-interface mode
as `xdpdrv` or `xdpgeneric`; it does not infer support from a model database.
Each controller refresh uses an atomically reserved generation below the
root-private BPF directory and a root-private lock under `/run/noid-privacy`;
a colliding name or an unprivileged lock holder cannot replace or stall the
active transaction.

## Device and topology matrix

| Path | v1.7 boundary | Reason |
|---|---|---|
| Conventional PCIe/on-board Ethernet netdev | Supported when the boot transaction passes | Native XDP is preferred; generic XDP is the driver-independent fallback |
| Conventional PCIe/on-board Wi-Fi netdev | Supported when the boot transaction passes | Generic XDP covers drivers without native XDP; radio management/firmware traffic below the data netdev remains outside host filtering |
| USB Ethernet adapter exposing a normal Ethernet netdev | Conditional on the same live transaction | The bus/vendor is irrelevant to the BPF parser, but the particular driver still has to accept generic XDP and `clsact` |
| VM virtio/e1000-style guest NIC | Test target, not a physical-host guarantee | The guest sees a hardware-backed virtual PCI device; the host/hypervisor remains a separate trust boundary |
| Bond/team/bridge master or slave topology | Not release-qualified | Route/gateway ownership and lower-device attach order need a dedicated end-to-end policy test for every supported mode |
| VLAN or stacked macvlan/ipvlan | Not release-qualified | Encapsulation and parent/child hook placement require an explicit topology design and tests |
| PPP/PPPoE | Not supported by the current Ethernet-frame parser | Both PPPoE EtherTypes are default-drop packet fixtures; a separate parser and reply-flow model are required |
| WWAN/Raw-IP modem data path | L3/WAN-strict fallback only; visibly degraded | A non-Ethernet ARPHRD type is excluded from Ethernet XDP/L2 hooks without disabling qualified Ethernet links; Raw-IP devices do not satisfy the Ethernet-header contract and cannot receive LAN-peer exceptions |
| Thunderbolt/PCIe NIC | Same conditional network contract after deliberate PCIe authorization | Strict IOMMU/early-DMA protection is image-owned; the firmware/kernel domain level must be verified as `user` or `secure` on the actual device because the image cannot force it. boltd is not installed because its IOMMU policy can auto-enroll unknown devices |
| Intel AMT or other firmware out-of-band NIC path | Outside host control | Traffic can bypass the OS, XDP, TC and nftables; firmware provisioning and network hardware must disable/isolate it |

“Supported when the transaction passes” is deliberate: it permits deployment
across different vendors without silently labelling an incompatible driver as
fully protected. When only XDP/TC cannot be proven, WAN recovery remains
possible behind the still-active baseline filters, but the system is explicitly
degraded until repaired or rolled back.

## Native and generic XDP timing

Native-driver XDP executes before the kernel allocates an `skb`. Generic XDP
is the fallback that works with an `skb`; in the receive core it executes
before the `ptype_all` packet-tap lists used by ordinary AF_PACKET capture.
Both modes therefore enforce the project's raw-packet boundary, while only
native mode may be described as pre-`skb`.

The fallback itself is broadly available, but that does not automatically
qualify stacked routes or non-Ethernet frame formats. The full five-part
contract above—not merely a successful XDP attach—is the acceptance gate.

## Fedora 44 kernel and package updates

The BPF object uses UAPI program/map types, stable BPF helpers and packet bytes;
it does not use unstable kfuncs or dereference kernel-internal structures. This
minimizes kernel-version coupling, but no project can truthfully guarantee that
an arbitrary future kernel or driver regression will preserve connectivity.

The guided update workflow reloads and verifies the boundary after the DNF
transaction against the currently running kernel. A newly installed kernel is
not running yet, so its verifier cannot be tested before reboot. On the next
boot the mandatory topology service performs the real load/attach/postcondition
check before NetworkManager. An XDP/TC-only failure enters the visible degraded
recovery state described above. For immediate full protection, reboot and pick
the previous Fedora kernel under GRUB's advanced options, then confirm the
boundary with `noid-status`. Failures in the independent topology/firewall
transaction remain activation-blocking because no safe WAN/LAN baseline was
established.

For a release, source tests are not enough. The candidate matrix must include:

- native XDP on at least one driver;
- explicitly forced generic XDP with unsolicited AF_PACKET observation checked;
- Ethernet and Wi-Fi hardware-backed interfaces when representative hardware is
  available;
- an update to the newest Fedora 44 kernel/packages, reboot, and repeat of the
  installed-system LAN/WAN checks;
- negative attach/verifier tests proving that baseline filters and WAN repair
  remain active while every health/reporting surface says `DEGRADED`;
- negative topology/firewall tests proving that a missing baseline still blocks
  NetworkManager activation.

Hardware not exercised by that matrix remains protected by the same fail-closed
runtime gate, but must not be advertised as individually validated.

## Operator checks

```bash
sudo systemctl status noid-lan-topology-guard.service
sudo journalctl -b -t noid-lan-topology --no-pager
sudo /usr/local/sbin/noid-lan-xdp status
sudo bpftool net list
sudo tc filter show dev <interface> egress pref 10
firewall-cmd --get-active-zones
sudo nft list table inet noid_lan_topology
```

Do not work around a failed topology service by removing NetworkManager's
dependency. If only XDP/TC is degraded, use the retained WAN path to diagnose
or roll back; the previous kernel in GRUB is the preferred full-protection
recovery path. Do not treat degraded recovery as satisfying the complete LAN
raw-packet claim.

## Upstream references

- [Linux BPF Design Q&A](https://www.kernel.org/doc/html/next/bpf/bpf_design_QA.html)
  documents the stable BPF instruction/helper/program ABI and distinguishes it
  from unstable direct kernel-function interfaces.
- [Linux AF_XDP documentation](https://docs.kernel.org/networking/af_xdp.html)
  documents driver mode and the generic `XDP_SKB` fallback available to network
  devices without native XDP support.
- [Linux receive-core source](https://github.com/torvalds/linux/blob/v7.1/net/core/dev.c)
  places `do_xdp_generic()` before the `ptype_all` packet-tap traversal.
- [Linux bonding documentation](https://docs.kernel.org/networking/bonding.html)
  illustrates why successful XDP attachment alone does not qualify every
  stacked topology and bonding mode.

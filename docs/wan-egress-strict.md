# WAN-Egress-Strict — physical-interface egress boundary

NoID Privacy enables an nftables policy that blocks public-IP egress on hardware-backed
interfaces unless a packet matches a narrowly defined exception. This closes a
class of default-route bypasses such as `SO_BINDTODEVICE` or
`curl --interface <physical-iface>`. It is an independent backstop, not proof
that a VPN client, DNS resolver, LAN, firmware or application is leak-free.

Local-address traffic continues to Module 03, which owns the separate LAN
destination boundary. A never-armed installation starts in the disclosed
IPv4 bootstrap-grace mode so a user can obtain and configure a VPN. This is an
onboarding state, not active strict enforcement. Once strict mode has been
armed, an empty endpoint set stays fail-closed across reboot and every tunnel
disconnect, including a deliberate user disconnect. Direct-WAN grace then
requires a separate explicit pause, reset or feature-disable operation.

## Onboarding and no-VPN decision

`GRACE_BOOTSTRAP` deliberately has no automatic wall-clock expiry. An expiry
could strand a new installation before the user has network access to obtain a
profile, and NoID Privacy explicitly supports operation without a VPN. The trade-off is
conspicuous direct IPv4 WAN until the user makes one of these choices:

- configure a supported literal/runtime-confirmed endpoint and verify
  `STRICT`;
- choose an armed fail-closed posture with
  `sudo noid-wan-strict arm-empty` (`STRICT_EMPTY`) while no endpoint is
  available; or
- explicitly choose no VPN with `sudo noid-toggle-wan-strict off`, which
  publishes `DISABLED` instead of pretending grace is strict protection.

`GRACE_BOOTSTRAP` therefore means “decision pending”, regardless of service
enablement or flag absence. The Network app, both CLIs and the runtime status
file display this mode directly. No component may relabel it as merely
“enabled” or infer protection from file existence.

## What the policy permits

The `inet noid_wan_strict` output and forward chains run before firewalld. They
apply only when the egress interface belongs to the boot-populated
`physical_ifaces` set.

In strict mode, physical egress is limited to:

- link/bootstrap traffic and local-address ranges that must reach later policy;
- explicit LAN exceptions synchronized by Modules 03 and 05;
- durable exact VPN `address . TCP/UDP . destination-port` tuples;
- 120-second exact hostname handshake candidates;
- 60-second local-output-only `address . TCP/UDP` bootstrap routes derived
  from a VPN client's current applied physical host routes under the documented
  software-default, gateway and profile-ownership gates; and
- DNS on TCP/UDP 53 or TCP 853 only from the `systemd-resolve` service UID.

Everything else to public IPv4/IPv6 destinations through a physical interface
is dropped and counted without destination logging. Forwarded VM/container
traffic has the same hardware-interface boundary.

The process-scoped resolver exception is necessary because pre-tunnel hostname
resolution otherwise deadlocks behind strict mode. It is not a general direct
DNS exception for applications. A process with root-equivalent control can
still bypass host policy and is outside this layer's protection claim.

## Exact threat boundary

The `inet` output hook sees IPv4/IPv6 packets sent by local processes through
the initial host network stack; the forward hook sees packets routed through
that stack. M06 filters those packets when their selected egress device is in
its boot-discovered physical-interface set. This includes ordinary
unprivileged TCP/UDP applications using route selection, socket binding or
`SO_BINDTODEVICE`.

M06 is not described as malware-proof. In particular, it does not claim to
control:

- Ethernet frames injected through an `AF_PACKET` socket by a process with
  `CAP_NET_RAW`; those operate at the device/link layer rather than proving
  traversal of the nft `inet` output hook;
- a process with `CAP_NET_ADMIN` that can change firewall, routes, interfaces
  or other network controls;
- `CAP_SYS_ADMIN`/root-equivalent control able to create or join a separately
  controlled network namespace or rearrange its devices/control plane;
- non-IP link protocols, radio/driver behavior below the host IP stack, or
  firmware out-of-band networking such as Intel AMT; or
- compromise of the kernel, nftables authority or boot trust chain.

Network namespaces have their own network devices, IP stacks, routes and
firewall rules. Traffic that is ultimately forwarded through a physical
interface still meets the host forward boundary when that path traverses this
namespace, but M06 does not promise coverage after privileged control has
moved or replaced that path. Module 03's netdev/XDP receive controls are a
separate ingress boundary and do not turn M06 into an egress link-layer filter.

## Endpoint trust states

M06 deliberately separates six different facts.

### 1. Literal profile endpoint

An endpoint already expressed as a canonical numeric IP in a NetworkManager
profile can enter durable desired state. It is bound to:

- the NetworkManager profile UUID;
- a SHA-256 fingerprint of the relevant profile endpoint/identity fields;
- transport, canonical address and destination port; and
- provenance `literal` with expiry `0`.

The profile is read from NetworkManager's loaded libnm model. M06 does not scan
keyfiles with section-blind regular expressions. NetworkManager therefore owns
keyfile parsing, accepted sections and its root-ownership/non-writable checks.

### 2. Hostname handshake candidate

For a hostname, current resolver answers enter only
`vpn_candidates_v4`/`vpn_candidates_v6`. Each exact tuple has a kernel-enforced
120-second timeout and is never written to restart state. A DNS-change event or
profile reconciliation flushes the candidate sets and replaces them with the
current desired answers.

This is intentionally labeled unauthenticated. Opportunistic DNS can be
downgraded or forged. During the short candidate window, another local process
could address the same IP, transport and port; nftables cannot prove which
application originated a WireGuard packet. The bounded window enables the
cryptographic tunnel handshake but is not equivalent to trusting the VPN
provider or server.

Users who cannot accept that residual window must use a reviewed literal-IP
profile or keep WAN-strict fail-closed and perform no hostname candidate scan.

### 3. Runtime-confirmed hostname endpoint

A hostname answer becomes durable only when the active-tunnel dispatcher can
bind the actually observed address to stronger runtime evidence:

- **WireGuard:** the peer public key is the one in the loaded profile, the
  kernel reports the same runtime address/port, and its latest authenticated
  handshake is no more than 180 seconds old.
- **OpenVPN:** NetworkManager has emitted `vpn-up`, the observed external
  gateway matches a current endpoint answer, and the loaded OpenVPN profile
  contains a CA plus `remote-cert-tls=server`, `verify-x509-name`, or
  `tls-remote` identity policy.

Other VPN plugins and hidden proprietary endpoint schemas are not guessed.
They may require a literal endpoint, a deliberate bounded pause, or disabling
this optional layer. Universal provider compatibility is not claimed.

Runtime-confirmed records use provenance `authenticated` and expire after 24
hours. nftables applies the remaining lifetime to the element itself; a
five-minute timer also prunes expired file records without refreshing DNS
candidates. A long-running hostname-based tunnel may therefore need to
reconnect before the lease expires. This availability trade-off bounds stale
direct-WAN permission.

### 4. Volatile-profile retention lease

NetworkManager keeps a profile either saved under
`/etc/NetworkManager/system-connections` or, for a profile a client added without
asking for it to be saved, only in volatile `/run` state. Both are ordinary
loaded profiles while they exist. The difference appears on disconnect: a saved
profile stays and is re-read on the next reconciliation, while a volatile one is
taken away together with the tunnel.

Re-deriving desired state from loaded profiles alone therefore unpins exactly the
address such a client is about to dial for its next attempt, and its first
packets are dropped by the layer that exists to let them through. The attempt
still succeeds on a retry, so the cost is silent latency rather than a visible
error — and it recurs at every boot and every reconnect. ProtonVPN's Linux app is
the documented case: its WireGuard profile is created under `/run` on connect and
never reaches `/etc`, while its own kill-switch dummy profile is saved normally.

When the active-tunnel dispatcher confirms an activation for a profile that is
not saved on disk, its observed tuples therefore also receive provenance
`retained`, with the same 24-hour lifetime as an authenticated lease. A
`retained` record survives the absence of its profile; no other provenance does.

The trade-off is stated plainly: for up to 24 hours after the last confirmed
activation, one exact address/transport/port tuple per observed endpoint stays
permitted on physical interfaces although no loaded profile currently names it.
That is the same permission a saved profile grants continuously, so this makes
the boundary provider-independent rather than wider. It is bounded three ways:
the lease expires on its own, the five-minute expiry timer prunes it, and
`sudo noid-wan-strict reset` revokes every record at once.

A saved profile deliberately receives no lease. Deleting one still revokes its
pin in the same reconciliation.

Such clients create a **new** profile with a **new** UUID for every server, so
without a bound a week of server hopping would leave one open tuple per server
visited. At most eight leases are live at once; when more exist the oldest
activations are pruned and the pruning is reported. A user who always reconnects
to the same server therefore holds exactly one lease, refreshed on every connect.

### 5. Unmanaged kernel tunnel

`wg-quick`, Mullvad's own daemon and `systemd-networkd` configure kernel
WireGuard directly. NetworkManager does notice the device: it assumes it behind
a profile it invents and emits `up`/`down` with `CONNECTION_EXTERNAL=1`. That
reflection is not ownership, and it is not durable — NetworkManager releases
such a device again as soon as anything writes to that invented profile, taking
the address its real creator installed with it. So nothing may write there, and
the profile-driven path cannot be relied on to learn of the tunnel; with strict
mode armed it could not complete a handshake at all.

The endpoint is in the kernel as soon as the interface is configured, before any
handshake: `wg show all endpoints` answers while `latest-handshakes` is still
`0`. Pinning it in time is therefore a discovery problem, not a chicken-and-egg
one. The trigger is a udev rule on `SUBSYSTEM=="net", ACTION=="add",
ENV{DEVTYPE}=="wireguard"`, which the kernel emits with the device already
tagged for systemd — no polling and no background daemon.

Creating or configuring a WireGuard interface requires `CAP_NET_ADMIN`, so this
source is exactly as trustworthy as a root-owned NetworkManager profile. The
identity is the peer's public key, not the interface name: `wg-quick` takes the
name from a file name and other clients rename their interface between versions,
while the peer key is the server's cryptographic identity and is what the kernel
enforces. A peer that a loaded profile already describes keeps that profile's
identity, so one tunnel never produces two competing records.

A completed handshake — the kernel's own proof that the peer answered, the same
evidence the profile-backed WireGuard path already accepts — earns the same
bounded `retained` lease, because an unmanaged tunnel leaves the kernel entirely
when it is taken down.

That proof arrives *after* the event that discovered the tunnel: udev fires when
the interface appears, seconds before the first handshake completes. Measured in
a VM against a real `wg-quick` tunnel, the reconciliation triggered by that event
therefore always saw `latest-handshakes` at `0`, and on a host whose only tunnel
is unmanaged nothing else reconciles afterwards — so the lease was never issued
and the next connect paid the full handshake retry again. The five-minute expiry
pass is the second entry point and closes that window. A lease is only issued
while none exists with more than half its lifetime left, so a periodic pass
cannot turn into a periodic write loop.

At most eight interfaces and eight peers per interface are enumerated; anything
beyond that, and any line that does not match the measured three-field output
shape, is reported rather than silently dropped.

### 6. Dynamic-client bootstrap host route

Some clients install their own software default-route killswitch, then use
NetworkManager `Reapply` to add a temporary public `/32` or `/128` route through
the physical gateway before they create the tunnel profile. Waiting for a
profile-directory event is too late for that first probe.

The physical `reapply` dispatcher therefore reads NetworkManager's current
applied connection. A route is admitted only when all of these conditions hold:

- it is an exact host route (`/32` or `/128`) in the applied connection;
- its next hop is the physical connection's current gateway;
- a non-hardware NetworkManager `dummy` connection currently owns the default
  route for the same address family;
- no more than eight destination addresses are present; and
- the exception is limited to local TCP/UDP output and expires in 60 seconds.

Whether the client also saved that route to its keyfile is deliberately not a
criterion. NetworkManager offers `Update()`/`Update2(to-disk)` next to
`Reapply`, and a client that calls both makes the applied and persistent views
identical; Proton VPN GTK 4.16.5 does exactly that. Treating that difference as
"newly added" measured only whether the keyfile flush had won the race against
the dispatcher read, so the first connection succeeded and every later one
failed permanently. It also never distinguished a client probe route from a
saved user route -- only `Update`+`Reapply` clients from `Reapply`-only ones.
The bound that carries the policy is the event plus the conditions above: the
window is re-derived from scratch on each physical `reapply`, never persisted,
and always expires. A saved user host route toward the current physical gateway
therefore does obtain the same bounded window while a software kill switch owns
the default route; only root can write such a route, and root can already pause
or disable this layer outright. The persistent profile is still read, but only
as an ownership gate: an absent profile, or one that is not root-owned with
tight modes, yields no bootstrap window at all.

Prefixes broader than one host, non-global destinations, routes
through another gateway and forwarded traffic are never admitted. The route is
not authentication evidence, is not persisted and does not arm strict mode.
Like hostname candidates, another local process could use the same short-lived
destination/transport allowance. This bounded compatibility path is narrower
than reopening bootstrap grace, but it is still an explicit residual window.

## Exact reconciliation

`/usr/local/libexec/noid-wan-strict-endpoints` is the single state authority.
All bootstrap, profile, DNS, tunnel-up/down, expiry, reset and manual
transitions use one lock. The controller computes the complete desired set,
sends one nft batch, and atomically publishes the v2 state file. If nft
publication fails, the old state bytes remain. If the later file replacement
fails, the old nft set is restored.

Bootstrap/restart does not delete the live table and load a replacement in two
steps. One nft transaction contains idempotent `destroy table`, the complete
replacement policy, physical-interface membership, endpoint/candidate sets and
grace state. The old table therefore remains active until the kernel accepts the
entire replacement. Pause, resume, reset, feature-enable and feature-disable use
the same controller lock; the disabled marker is fsynced and versioned rather
than touched outside the transaction. Runtime status is derived from exact
marker contents and nftables' machine-readable JSON state, not from
human-formatted substring matches. A missing or unreadable set, malformed JSON
or mixed flag/table/armed state publishes `ERROR` instead of an optimistic
mode. The status file is published atomically under the same lock. If status
publication after a pause fails, grace is rolled back to strict; stale status
is removed on any publication failure rather than being presented as current
evidence.

An explicit bounded pause is also part of that locked reconciliation contract.
Profile changes, DNS changes, endpoint expiry and a service bootstrap preserve
`GRACE_PAUSED` only while both the current nft grace set and its transient
auto-resume timer agree. A stale timer cannot reopen a manually resumed strict
state, and an unbounded/stale grace set cannot survive the next reconciliation.
A supported tunnel activation likewise honors the still-active user-requested
pause; the timer or an explicit `resume` closes it.

The state header and record shape are closed:

```text
NOID-WAN-ENDPOINTS-V2
PROFILE_UUID FINGERPRINT literal|authenticated|retained tcp|udp IP PORT EXPIRY_EPOCH
```

Unknown versions, extra/missing fields, non-canonical UUID/IP values, invalid
ports, duplicate records, wrong provenance/expiry combinations, symlinks,
multiple hard links, wrong owner or a mode other than `0644` fail closed.
The armed and disabled markers likewise have exact versioned one-line contents,
root:root ownership, one link and mode `0644`; the transaction lock and active
tunnel evidence are pre-created root-private through tmpfiles.

Every profile create/change/delete and DNS-change rebuilds the desired set:

- deleted profiles revoke their records;
- a changed endpoint/peer/identity fingerprint invalidates old records;
- DNS rotation replaces candidates rather than accumulating answers;
- authenticated and retained records disappear at expiry;
- literal records remain only while the matching loaded profile exists; and
- retained records are the sole exception and outlive their profile's absence,
  because for a volatile profile that absence is the client's normal
  disconnected state rather than a deletion.

Only a `literal` record may carry expiry `0`; every other provenance is bounded
evidence and must carry a deadline. Several records can describe one tuple at
once — a loaded profile and the bounded proof that the same tunnel was observed
active. They are collapsed into a single nftables element per tuple, where a
record without a deadline outranks every timed one and the longest remaining
lifetime wins among timed ones. Neither direction can add a tuple.

Physical `reapply` events independently replace both transient bootstrap-route
sets from the current applied host routes that satisfy the software-default,
current-gateway and root-owned-profile gates. The dispatcher uses
NetworkManager's `no-wait.d` mechanism for the pre-profile race, while the
controller re-reads current state under the shared lock; a queued stale event
therefore cannot replay an address that is no longer applied.

`/var/lib/noid-privacy/wan-strict-armed.flag` records either that a supported
tunnel-up runtime path committed strict mode or that the user explicitly chose
`arm-empty`. Merely saving or scanning a profile never arms the boundary.
Profile deletion, expiry, crash, carrier loss and a supported down event can
therefore produce `STRICT_EMPTY`, but cannot silently reopen `0.0.0.0/0`
grace. The marker is removed only by an explicit `noid-wan-strict reset`.

## Tunnel disconnect remains fail-closed

On supported tunnel activation, the authenticated endpoint dispatcher commits
strict state and writes a root-private active marker under
`/run/noid-privacy/wan-strict-active/`. NetworkManager's later `down` or
`vpn-down` event removes only that volatile proof. The dispatcher first
requires the matching NetworkManager tunnel event; the controller then
requires either an existing authenticated active marker or a currently
supported profile schema. Unrelated virtual-interface events are ignored. A
qualifying event does not clear the armed marker, endpoint state or nft policy.

Clean user disconnect, client quit, crash, carrier loss, suspend/shutdown and a
queued stale down event therefore all retain `STRICT` or `STRICT_EMPTY`.
NetworkManager documents that dispatcher events are queued and can run after a
newer state transition, so a teardown event is not an authorization token for a
policy downgrade.

This behavior matches the persistent or “lockdown” kill-switch model: after
arming, connecting without a VPN requires a separately visible user action.
Use a bounded `pause` for captive-portal or compatibility work, `reset` to
return to onboarding grace, or turn the optional feature off. No VPN provider is
assumed, and provider-owned kill-switch behavior remains an independent layer.

## Runtime modes

| Mode | Meaning |
|---|---|
| `GRACE_BOOTSTRAP` | Unarmed after initial setup or explicit reset; direct IPv4 WAN deliberately available |
| `GRACE_PAUSED` | User requested a bounded direct-WAN pause |
| `STRICT` | At least one durable exact endpoint record is active |
| `STRICT_EMPTY` | Armed and fail-closed, but no durable endpoint remains |
| `DISABLED` | User explicitly disabled the layer |
| `ERROR` | Bootstrap/postcondition failed; do not infer protection |

### Endpoint-discovery coverage, stated plainly

Durable endpoint pinning has two sources: NetworkManager profiles through libnm,
and the kernel's own WireGuard state for tunnels no profile describes. The honest
summary is below. This table describes endpoint extraction only; it is not a
release qualification of a provider's routes, DNS, privileged daemon or separate
kill-switch firewall.

| Tunnel as configured | Pinned durably | Consequence when it is not |
|---|---|---|
| NetworkManager WireGuard profile | yes | — |
| NetworkManager OpenVPN profile | yes | — |
| Provider client that creates its profile on connect (Proton VPN) | yes, plus a bounded lease across disconnect | — |
| `wg-quick` / `systemd-networkd` WireGuard | yes, from the kernel | does not arm the boundary by itself |
| Mullvad native WireGuard over its standard kernel/UAPI path | yes, from the kernel | as above; obfuscated/private transports are separate rows below |
| IVPN desktop client | conditional on the exposed standard WireGuard UAPI or a recognized NetworkManager OpenVPN profile | no dedicated NoID Privacy client qualification; provider firewall/daemon remain separate |
| Userspace WireGuard exposing the standard UAPI (`wireguard-go`, `boringtun`) | yes, same path as the kernel | — |
| WireGuard-derived clients with a private control channel | no | not reachable through `wg`; the bounded bootstrap route is the only path out |
| OpenVPN outside NetworkManager | no | as above |
| WireGuard over TCP, obfuscation or "stealth" transports | no | the UDP-only pin does not describe the real tuple |

The current Mullvad source documents an independently managed Linux nftables
firewall, applied atomically by its privileged daemon, and lists several
WireGuard obfuscation transports. The current IVPN desktop source documents a
privileged daemon, its own kill switch, and WireGuard/OpenVPN as the advertised
protocols. NoID Privacy neither rewrites nor treats either provider firewall as proof of
M06 compatibility. A release-specific runtime test must still verify first-hop
reachability, tunnel-down behavior, DNS and the combined nftables ruleset.
IPsec/IKEv2 is not a recognized M06 profile path and is not implied by the name
"IVPN".

Discovery is a read of `wg show all endpoints`, so it needs `wireguard-tools`
present. Module 26 ships that package, so a stock image can enumerate. A host
that lacks it — an image predating that include, or an administrator who
removed it — simply has no WireGuard tooling to enumerate, and the
reconciliation continues on its profile source alone rather than failing.

"Does not arm the boundary by itself" is measured, not assumed: on an
unarmed host a `wg-quick` tunnel produced its kernel-derived identity and a
bounded handshake lease while the mode stayed `GRACE_BOOTSTRAP`, and the same
detector recorded `STRICT` when a NetworkManager WireGuard profile came up
instead. NetworkManager does assume such a device behind a profile it invents
and does emit dispatcher events for it, but that profile names the peer's
public key with no endpoint, so the endpoint dispatcher finds no endpoint
contract to commit and the arming path is never reached.

That single read covers more than the kernel: `wg` enumerates userspace
implementations through their `/run/wireguard/<interface>.sock` UAPI before it
falls back to netlink, so `wireguard-go` and `boringtun` — the implementations
`wg-quick` itself uses via `WG_QUICK_USERSPACE_IMPLEMENTATION` — appear in the
same listing with the same fields. Verified against a UAPI stub speaking the
documented protocol: the interface is discovered, receives its own peer-key
identity and its endpoint is committed to the boundary exactly like a kernel
tunnel. A client that keeps a private control channel instead of that socket is
not reachable this way and stays outside the coverage.

**Discovery pins, it does not arm.** A tunnel found in the kernel makes its
endpoint reachable inside an already-armed boundary; it never creates the armed
marker. Arming narrows connectivity, and an unrelated kernel WireGuard interface
— a container mesh, a test tunnel — must not be able to cut a machine off its
network. Users whose only tunnel is unmanaged therefore still arm deliberately:
bring the tunnel up, then `sudo noid-wan-strict arm-empty`. The next
reconciliation re-derives the tunnel's endpoint, so the result is `STRICT` with
that tuple pinned, not `STRICT_EMPTY`.

`STRICT_EMPTY` is a correct, fail-closed state, not a fault: the layer stays
armed and never reopens `0.0.0.0/0` merely because it lost sight of an endpoint.
For the rows that remain unpinned, a first connect depends on the bounded
bootstrap host route, so plan for that rather than being surprised by it.

Separately, none of this governs *when* a client starts. An application
launched from XDG autostart can probe its server before any physical link
exists, which fails with the boundary completely uninvolved and
`wan_blocked_v4` at zero. The App Autostart switch in `noid-welcome`
(`/usr/local/bin/noid-autostart-netwait`) addresses that case and is
provider-neutral; see the Proton VPN guide's Step 3 for the reasoning.

`DISABLED` also stops and disables the profile watcher and five-minute endpoint
expiry timer, drains already-triggered scan/expiry jobs, and stops both halves
of a transient auto-resume job. Policy removal aborts while enforcement is
still present if that background work cannot be quiesced. Re-enabling the
feature restores both persistent activators before reporting an exact
active-policy postcondition. Every queued controller action also rechecks the
exact disabled marker after acquiring the shared lock, so a dispatcher event
that began before opt-out cannot recreate the table afterward. Opt-out
therefore does not leave periodic or profile-change M06 work running in the
background.

Use the root-published runtime status, not file existence alone:

```bash
sudo noid-wan-strict status
noid-toggle-wan-strict status
sudo nft list table inet noid_wan_strict
```

## Normal and edge-case behavior

| Scenario | Behavior |
|---|---|
| Normal traffic routed over an arbitrary tunnel interface | Does not match the physical-interface set |
| Public destination via `curl --interface <physical-iface>` | Dropped unless it exactly matches an endpoint/candidate tuple |
| Same endpoint IP on another port/protocol | Dropped |
| Literal saved endpoint | Reconciled durably from libnm |
| New hostname endpoint | Bounded candidate, then runtime-confirmed promotion where supported |
| Dynamic client probes before creating its profile | Current exact applied-only host route receives a 60-second local TCP/UDP window when a software dummy default route is active |
| Forged/rotated DNS answer | Candidate only; cannot directly become durable state |
| Profile changed or deleted | Old fingerprint/UUID records revoked on reconciliation |
| Clean user/client disconnect after confirmed activation | Armed strict/strict-empty remains; unrestricted WAN is not restored |
| Crash, forced loss, reboot or profile disappearance | Armed strict/strict-empty remains; unrestricted WAN is not restored |
| Captive portal | Requires a deliberate bounded pause |
| Unsupported provider schema | Fails closed or requires an explicit user-chosen compatibility path |

### Captive portal

```bash
sudo noid-wan-strict pause 10
# complete portal authentication
sudo noid-wan-strict resume
```

The pause permits direct IPv4 WAN for the requested interval, not just portal
traffic. Auto-resume is armed before grace is added. Routine profile, DNS,
expiry and service reconciliation preserves the bounded pause; it cannot be
ended silently by a normal NetworkManager event. Reboot restores persisted
strict/strict-empty state when the armed marker exists.

### New or changed VPN profile

NetworkManager normally triggers the path/DNS reconciliation automatically.
The legacy-compatible command name performs the same exact replacement:

```bash
sudo noid-wan-strict scan-profiles
```

It does not certify or permanently trust DNS answers. If a client hides its
endpoint or uses an unsupported plugin schema, use a reviewed literal endpoint
or deliberately choose a pause/disable trade-off.

### Reset

```bash
sudo noid-wan-strict reset
```

Reset clears durable/candidate sets, removes the armed marker and deliberately
returns to full IPv4 bootstrap grace. It is not routine garbage collection;
normal reconciliation already removes stale profile state.

### No-VPN fail-closed

```bash
sudo noid-wan-strict arm-empty
```

This confirmed transition clears all endpoint records, writes the durable armed
marker, removes grace and verifies `STRICT_EMPTY`. Ordinary application and
forwarded physical WAN remain blocked until a supported VPN endpoint is
committed or the user explicitly chooses a reset, pause or feature disable.
The service-UID-scoped resolver bootstrap exception described above remains.

## Components

| Component | Path | Role |
|---|---|---|
| nft policy | `/etc/nftables.d/noid-wan-strict.nft` | Durable/candidate sets, resolver exception and physical drops |
| boot loader | `/usr/local/sbin/noid-wan-strict-bootstrap.sh` | Loads table/interface set and validated unexpired v2 state |
| boot status publisher | `noid-wan-strict-status-publish.service` | Republishes the closed runtime contract before login even when explicit opt-out keeps the policy service disabled |
| controller | `/usr/local/libexec/noid-wan-strict-endpoints` | libnm parsing, resolution, authentication, expiry and atomic reconciliation |
| profile wrapper | `/usr/local/sbin/noid-wan-strict-scan-profiles.sh` | Compatibility/manual reconcile entry point |
| boot guard | `/etc/NetworkManager/dispatcher.d/pre-up.d/20-noid-wan-strict-boot-guard` | Fails boot networking closed (downs the physical link) when armed strict state is missing or invalid |
| WireGuard MTU reconciler | `/usr/local/sbin/noid-wireguard-mtu-reconcile` + `pre-up.d/no-wait.d/45-noid-wireguard-mtu` | Lower-only live-interface correction from every resolved peer's real outer route; never edits or reconnects an owning profile |
| physical/DNS/reapply dispatcher | `/etc/NetworkManager/dispatcher.d/55-wan-strict-scan-on-network-up` → `no-wait.d/…` | Refreshes profile/candidate state and current transient bootstrap routes |
| tunnel-down dispatcher | `/etc/NetworkManager/dispatcher.d/58-wan-strict-tunnel-down` | Removes volatile active proof while preserving durable strict state |
| tunnel dispatcher | `/etc/NetworkManager/dispatcher.d/60-vpn-endpoint-pin` | Requests runtime-confirmed promotion and publishes active proof |
| profile path/service | `noid-wan-strict-scan-profiles.path/.service` | Reconciles create/change/delete events |
| expiry timer/service | `noid-wan-strict-endpoint-expiry.timer/.service` | Prunes bounded authenticated leases |
| tunnel hotplug | `/etc/udev/rules.d/71-noid-wan-strict-tunnel-hotplug.rules` + `noid-wan-strict-tunnel-scan.service` | Reconciles when a kernel WireGuard device appears that NetworkManager does not manage |
| state | `/var/lib/noid-privacy/wan-strict-endpoints.txt` | Closed v2 durable records |
| armed marker | `/var/lib/noid-privacy/wan-strict-armed.flag` | Prevents silent grace reopening |
| active runtime markers | `/run/noid-privacy/wan-strict-active/` | Root-private, reboot-volatile evidence of authenticated tunnel activation |
| CLI | `/usr/local/sbin/noid-wan-strict` | Status, pause, resume, arm-empty, reset, reconcile |
| feature toggle | `/usr/local/sbin/noid-toggle-wan-strict` | Explicit system-level on/off choice |

## Diagnostics without destination logging

```bash
sudo nft list counters table inet noid_wan_strict
sudo journalctl -b \
  -u noid-wan-strict.service \
  -u noid-wan-strict-scan-profiles.service \
  -u noid-wan-strict-endpoint-expiry.service \
  -t noid-vpn-endpoint-pin \
  -t noid-wan-strict-down
sudo noid-wan-strict status
```

Counters are aggregate. Endpoint state necessarily contains exact destination
addresses and profile UUIDs locally, so treat the state/status output as
network metadata when sharing diagnostics.

## References

- [NetworkManager dispatcher contract](https://networkmanager.dev/docs/api/latest/NetworkManager-dispatcher.html)
- [NetworkManager keyfile format and safety checks](https://networkmanager.dev/docs/api/latest/nm-settings-keyfile.html)
- [NetworkManager VPN settings](https://networkmanager.dev/docs/api/latest/settings-vpn.html)
- [NetworkManager active-connection state and reason](https://networkmanager.dev/docs/libnm/latest/NMActiveConnection.html)
- [Mullvad Lockdown mode](https://mullvad.net/en/help/using-mullvad-vpn-app#lockdown-mode)
- [Mullvad app security model](https://github.com/mullvad/mullvadvpn-app/blob/main/docs/security.md)
- [Mullvad current transport matrix](https://github.com/mullvad/mullvadvpn-app/blob/main/README.md)
- [IVPN desktop app source and protocol statement](https://github.com/ivpn/desktop-app/blob/development/readme.md)
- [Proton VPN Advanced kill switch](https://protonvpn.com/support/advanced-kill-switch)
- [WireGuard protocol and runtime model](https://www.wireguard.com/protocol/)
- [ProtonVPN issue #130 — interface-bind bypass report](https://github.com/ProtonVPN/proton-vpn-gtk-app/issues/130)
- [nftables hook semantics](https://netfilter.org/projects/nftables/manpage.html)
- [Linux `packet(7)` / `AF_PACKET`](https://man7.org/linux/man-pages/man7/packet.7.html)
- [Linux capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [Linux network namespaces](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)

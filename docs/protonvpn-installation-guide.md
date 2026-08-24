# ProtonVPN Installation Guide

ProtonVPN is **not pre-installed** on NoID Privacy Workstation 44 — the
default image ships provider-neutral inbound/LAN controls and optional
WAN-strict physical-egress enforcement (Module 06), but no provider route/DNS
kill switch or specific VPN client. This guide walks through the explicit-opt-in
installation of ProtonVPN's official client through NoID Privacy's
fingerprint-pinned helper.

The image-level threat model is provider-neutral: WAN-strict persists literal
endpoints or runtime-confirmed hostname endpoints, while raw DNS answers remain
short-lived handshake candidates. After strict has been armed, physical egress
is limited to exact durable/candidate tuples if the tunnel drops; empty state
stays fail-closed. Before first arming, bootstrap grace or an explicit pause
permits direct WAN. Provider routes, DNS behavior, application traffic, and
firmware OOB paths remain separate verification boundaries.

## Why ProtonVPN is not in the default image

- **User choice**: VPN selection is a personal-trust decision. NoID Privacy does
  not pre-pick a vendor.
- **Repo signature trust chain**: adding `repo.protonvpn.com` is an explicit
  opt-in. The shipped helper accepts its key only when the complete primary
  fingerprint matches the reviewed NoID Privacy pin.
- **Account requirement**: the official client requires a Proton account.
  Account creation and login are explicit provider interactions that the base
  image must not perform on the user's behalf.

## Prerequisites

- Active Proton account
- NoID Privacy's provider-neutral M06 VPN/WAN-strict infrastructure is
  installed; the provider client's own routing/DNS state remains separate
- If you choose WireGuard, verify that Fedora's kernel module is available:
  ```bash
  modinfo wireguard >/dev/null && echo "OK" || echo "MISSING"
  ```
  `modinfo` proves module availability, not that it is currently loaded;
  `lsmod | grep '^wireguard '` checks the latter after a WireGuard profile is
  active.

## Step 1: Install through the shipped NoID Privacy helper

Preferred GUI paths:

- **NoID Privacy Setup** → **VPN — Install Before Updates & Apps** →
  **Install Proton VPN**
- **NoID Privacy Tools** → **Opt-in Installers** → **Proton VPN** →
  **Install**

The equivalent terminal command runs as the normal user:

```bash
noid-protonvpn-install
```

The helper refuses a root invocation and elevates only the required
key/repository/package steps. Before it trusts anything, it downloads Proton's
Fedora key and requires the exact pinned primary fingerprint. It then writes
the canonical repository definition, installs
`proton-vpn-gnome-desktop` through DNF and verifies the core package and daemon
state. Review its prompt and DNF transaction before confirming.

The helper intentionally does not install a downloaded release RPM or pipe a
remote installer into a shell. If Proton changes its key or repository
contract, it fails closed until NoID Privacy reviews and updates the pin. The
current vendor instructions remain the manual comparison source:
<https://protonvpn.com/support/official-linux-vpn-fedora/>.

To remove the packages and NoID Privacy-managed repository file later:

```bash
noid-protonvpn-install --uninstall
```

The uninstall path deliberately leaves the already imported key in the RPM
trust store; it reports that boundary instead of silently removing a shared
trust anchor.

Dependency names remain vendor-controlled. Retain the installed inventory
instead of relying on a hard-coded list:

```bash
rpm -qa --qf '%{NAME}-%{EVR}.%{ARCH}\n' | grep -i 'proton'
```

## Step 2: First-time login + VPN config

1. Launch ProtonVPN from the GNOME applications menu (or `protonvpn-app`)
2. Log in with your Proton credentials
3. Pick a server (e.g. CH for Swiss egress)
4. Connect

Do not infer the effective transport, kill-switch or DNS state from a GUI
"Connected" label or from historical profile names. With the tunnel connected
and disconnected, record and compare the actual state:

```bash
nmcli -f NAME,TYPE,DEVICE connection show --active
ip -brief link
ip route show table all
resolvectl status
```

Then exercise the M06 WAN threat-boundary/runtime checks. The provider client
may add NetworkManager profiles, interfaces, routes and DNS configuration, but
their current names and behavior are not an image-level NoID Privacy contract.

## Step 3: Auto-start configuration (optional)

This launches the GUI after graphical login and lets Proton apply its
configured connect-at-app-start behavior. It is not a boot-level or
locked-session availability guarantee.

**On NoID Privacy Workstation 44 — preferred path**: use the
**built-in App Autostart picker** in `noid-welcome` (M13, GTK4 +
libadwaita Adw.Dialog with XDG filter + search):

1. Open **NoID Privacy Setup** (App Grid → "NoID Privacy Setup" or
   `noid-welcome.sh --again`).
2. Scroll to the **"App Autostart"** group (between **"Gaming Mode (Steam /
   Proton)"** and **"Security Notifications"**).
3. Click **"+ Add app to autostart"**.
4. Type "Proton" in the search field, select **Proton VPN**, click Add.
5. The picker writes `~/.config/autostart/proton.vpn.app.gtk.desktop`
   (user-level XDG, no `sudo` needed) and recognizes it as a VPN client.

6. Confirm that **Wait for network before starting** is on for the Proton VPN
   row. Setup selects it initially for semantically recognizable VPN,
   WireGuard and OpenVPN clients; the switch remains user-controlled and can
   be turned off again.

XDG autostart has no ordering contract with NetworkManager. gnome-session
launches every entry as soon as the session is ready, which on a fast machine is
seconds before association completes, and Proton's startup probe has a hardcoded
5-second budget. The switch runs the entry through
`/usr/local/bin/noid-autostart-netwait`, which waits for a NetworkManager device
that is both activated and backed by real hardware in the kernel. A kill-switch
placeholder, a WireGuard or tun interface and the loopback are all rejected, so
the gate cannot be satisfied by the very device that causes the problem — which
is also why `nm-online` is unusable here: it waits for "a connection", and the
placeholder is one.

The wrapper fails open. If no link appears within 30 seconds, if NetworkManager
is unreachable, or if anything else goes wrong, it starts the application
anyway. It can delay an app; it cannot stop one. Check it directly with:

```bash
noid-autostart-netwait --check      # names the device that opens the gate
```

The switch rewrites only the `Exec=` line of your own copy under
`~/.config/autostart`; the packaged launcher is never touched. Turning it off
restores the file byte-for-byte. Unrelated apps remain ungated by default. The
semantic VPN initial value is provider-neutral — Proton, Mullvad and entries
that explicitly identify as VPN, WireGuard or OpenVPN take the same path — but
it is not a claim that every named provider has a dedicated NoID Privacy integration.
Any other app that probes the network once at startup can use the switch
manually.

The same picker also lets you remove auto-start entries (per-row 🗑
button). It is included in NoID Privacy and needs no additional package. GNOME Help
also documents the optional `gnome-tweaks` Startup Applications panel; Tweaks
is omitted from the base image as redundant UI/package surface, not because it
can bypass system dconf locks.

**Manual CLI alternative** (only if `noid-welcome` is unavailable —
e.g. inside a TTY session before first graphical login):

```bash
mkdir -p ~/.config/autostart
cp /usr/share/applications/proton.vpn.app.gtk.desktop ~/.config/autostart/
```

The plain CLI copy does not apply Setup's VPN-client initial value. Either open
Setup afterward and enable the row switch, or edit only its primary
`[Desktop Entry]` line to the exact equivalent:

```ini
Exec=/usr/local/bin/noid-autostart-netwait -- protonvpn-app
```

Use `~/.config/autostart/` here because starting Proton VPN is this user's
explicit choice. `/etc/xdg/autostart/` is also a supported GNOME/XDG
mechanism, but it is administrator-managed policy for every user; it does not
inherently hide GTK windows. Use the same desktop-file basename as the packaged
launcher so XDG precedence remains predictable.

### Locked-session reconnect boundary

Tested with Proton VPN GTK 4.16.5: if its local-agent channel drops while
logind reports the GNOME session as locked, the app keeps scheduling retries
but defers the actual VPN reconnect until the session unlocks. The unlock
signal then schedules a new attempt. This is explicit provider behavior in the
tagged 4.16.5
[reconnector](https://github.com/ProtonVPN/proton-vpn-gtk-app/blob/v4.16.5/proton/vpn/app/gtk/services/reconnector/reconnector.py)
and
[logind session service](https://github.com/ProtonVPN/proton-vpn-gtk-app/blob/v4.16.5/proton/vpn/app/gtk/services/reconnector/login_session_service.py),
not a NoID Privacy firewall or sleep-policy decision.

Autostart, connect-at-app-start and Advanced kill switch therefore do not by
themselves promise unattended availability while the desktop remains locked.
When Proton's kill switch or NoID Privacy WAN-strict is enforcing, the safe
expected failure mode is blocked traffic until Proton reconnects. NoID Privacy
does not patch vendor Python, spoof logind's lock state, or mutate Proton-owned
NetworkManager profiles to bypass this boundary. Re-check the current
[Proton Linux release notes](https://protonvpn.com/support/release-notes-linux)
when upgrading because provider behavior can change.

## Step 4: Provider-owned kill-switch state — do not mutate

Proton owns the `pvpn-killswitch*` NetworkManager profiles and their complete
add/remove lifecycle. Its current backend deliberately creates dummy
connections that swallow traffic and assigns the sink DNS values `0.0.0.0`
and `::1` at a priority above the physical connection but below the VPN.
Those values are provider implementation state, not damaged user DNS
configuration.

Do not clear those DNS values, force the profiles down/up, change their
autoconnect priority, or automate such changes from a NetworkManager
dispatcher. Proton may delete and recreate the profiles during one state
transition. NetworkManager also serializes ordinary dispatcher scripts and
may execute a queued event after the device state has already changed, so a
profile mutation from its own `up` event can race the provider, stall unrelated
network events, and leave duplicate profiles.

NoID Privacy's WAN-strict policy is a separate, provider-neutral physical-egress
boundary; it neither depends on nor rewrites Proton's internal profiles. Enable
the desired standard or advanced kill-switch mode in Proton itself, then verify
the final tunnel, DNS, routing, firewall-zone and WAN-strict state using the
commands in Steps 2 and 5. A transient `SetLinkDNS` warning about a sentinel
address is not by itself evidence of a DNS leak. Persistent activation failure
or stale profiles should be diagnosed against the installed Proton version and
reported upstream rather than hidden by a local profile mutator.

### If Proton reports "VPN server NOT reachable" after a reboot

Three different faults produce that one message, and only one of them is a
dropped packet. Pausing WAN-strict "fixes" all three by accident, which is why
it used to be recommended here and why the actual cause stayed hidden. Identify
the mode first — the distinguishing signal is cheap to read.

Proton's reachability check is a plain TCP connect to the server IP on its
OpenVPN TCP ports, sent before the WireGuard tunnel exists, with a hardcoded
5-second timeout. All three modes make that probe fail; they differ in why.

```bash
# 1 — did WAN-strict drop anything at all in this boot?
sudo nft list table inet noid_wan_strict | grep -A2 wan_blocked_v4

# 2 — what does the boundary think it is enforcing?
sudo noid-wan-strict status

# 3 — did the app probe before or after the link came up? (times are UTC in
#     the app log and local in the journal; compare deliberately)
grep -aE 'CONNECT:START|REACHABLE|NOT reachable' \
    ~/.cache/Proton/VPN/logs/vpn-app.log | tail -5
journalctl -b -o short-precise --grep 'Activation: successful'
```

**Mode A — the app raced the network.** `wan_blocked_v4` is 0, and the app's
`NOT reachable` line precedes NetworkManager's `Activation: successful` for the
physical device. Nothing was blocked; the probe simply had nothing to send over.
This is a provider-side gap: Proton's own connectivity gate is `ip route get
192.0.2.1`, which its kill-switch placeholder device satisfies while no packet
can leave. Remedy: verify the **App Autostart** network gate from Step 3; old
or manually copied entries can still be ungated.
Pausing WAN-strict here changes nothing about the cause.

**Mode B — the kill-switch profile activation timed out.** `wan_blocked_v4` is
0, the app log shows exactly one `Reconnection attempt #0` and never a `#1`, and
the journal shows the `pvpnksintrf*` device spending seconds in one activation
step. Proton gives its own `add_connection_async` ten seconds; past that,
`kill_switch.enable()` raises and no further attempt is ever scheduled, so the
app stalls until it is restarted by hand. The image-side cause was a
NetworkManager dispatcher chain that rebuilt identical LAN-XDP state once per
queued event; that is fixed, and a recurrence is a bug worth reporting with the
`journalctl -b -u NetworkManager-dispatcher` excerpt.

**Mode C — WAN-strict really did drop the probe.** Only here is a pause the
right instrument. `wan_blocked_v4` rises while the app probes, `noid-wan-strict
status` reports `STRICT_EMPTY`, and the journal says `reconciled 0 transient
bootstrap route tuple(s)`.

`STRICT_EMPTY` means armed with no durable endpoint. It is the expected state
after a reboot for any provider that creates its VPN profile on connect and
deletes it on disconnect — Proton does exactly that with `ProtonVPN <server>` —
because a profile scan finds nothing to pin. In that state the only path outward
is the bounded bootstrap host route of Step 4 above. To connect once without
weakening the layer:

```bash
sudo noid-wan-strict pause 3
```

Then connect in the app. WAN-strict re-arms itself when the pause expires.

A failed probe has follow-on effects that look unrelated in all three modes:
chrony cannot complete its NTS handshakes, so
`noid-chrony-network-online.service` fails and the clock stays unsynchronised.
Fix the connection, not the clock.

Relevant maintained interfaces:

- [Proton VPN Core API source](https://github.com/ProtonVPN/python-proton-vpn-api-core)
- [NetworkManager dispatcher reference](https://networkmanager.dev/docs/api/latest/NetworkManager-dispatcher.html)
- [NetworkManager Settings.Connection API — Update / UpdateUnsaved / Update2 flags](https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.Settings.Connection.html)

## Step 5: Verify the tunnel is up + leak-tested

```bash
# Public IP (should be Proton's egress, NOT your ISP)
curl --fail --silent --show-error https://api.ipify.org

# Identify the actual active provider profile/device; names and transport are
# provider-controlled and may change.
nmcli -f NAME,TYPE,DEVICE connection show --active
VPN_PROFILE="replace with the active Proton profile name"
VPN_IF=$(nmcli -g GENERAL.DEVICES connection show "$VPN_PROFILE" | head -n1)
test -n "$VPN_IF" && test "$VPN_IF" != "--"

# Inspect the effective route and link-scoped resolver state.
ip route get 1.1.1.1
resolvectl status "$VPN_IF"

# Test IPv6 only if the selected profile advertises it.
curl --fail --silent --show-error -6 https://ifconfig.co/json

# WireGuard exposes a handshake only when the effective transport/interface
# is WireGuard. Do not apply this check to an OpenVPN connection.
if sudo wg show interfaces | tr ' ' '\n' | grep -qxF "$VPN_IF"; then
    sudo wg show "$VPN_IF"
fi
```

The public address should match the provider-selected egress; the default
route and DNS scope should use the active tunnel. A failed IPv6 request may
simply mean that the selected profile has no IPv6 path, and a non-WireGuard
transport has no `wg` handshake. Treat unexpected direct-WAN routing or
physical-link DNS as a suspected leak, then perform the full route/DNS,
browser and tunnel-down matrix in `06-vpn-setup.md`. Public-IP and DNS websites
alone do not prove kill-switch behavior.

## Cross-references

- [Module 06: VPN killswitch](../kickstart/snippets/06-vpn-killswitch.ks) —
  provider-neutral inbound/LAN controls and optional WAN-strict enforcement;
  recognized NetworkManager profile schemas still require verification
- [Module 07: IPv6 privacy](../kickstart/snippets/07-ipv6-privacy.ks) —
  physical-WAN IPv6 design + WAN-IPv6-disable rationale
- [Firewall policies explained](firewall-policies-explained.md) —
  inbound-DROP `noid-vpn` zone handling for recognized tunnel interfaces
- [WAN egress strict architecture](wan-egress-strict.md) — pinned-endpoint
  nft-table that closes the SO_BINDTODEVICE bypass
- ProtonVPN official Fedora docs:
  <https://protonvpn.com/support/official-linux-vpn-fedora/>

## Alternatives

If ProtonVPN does not fit your trust model, NoID Privacy remains
provider-neutral, but every alternative needs its own route/DNS and
tunnel-down verification:

- **Mullvad**: numbered account without an email address
- **IVPN**: no dedicated NoID Privacy installer or release-qualified client
  integration. IVPN's current official desktop source names OpenVPN and
  WireGuard as its two protocols; those transport classes can use NoID Privacy's
  provider-neutral controls, but that is not an IVPN-specific verification.
- **Self-hosted WireGuard**: full control, requires server infrastructure

IPsec/IKEv2 is not one of M06's recognized provider-neutral profile paths and
is not supported by this guide. Do not infer IPsec support from the letters in
the provider name “IVPN”. See IVPN's current
[official desktop-app source](https://github.com/ivpn/desktop-app/blob/development/readme.md)
for its own protocol statement.

For all of these, the same M06 VPN/WAN-strict layer plus the firewall
drop-default and DNS layers (M05 strict-default global/physical Quad9 DoT plus
provider-neutral per-link scopes; M16 system/VPN DNS as Firefox's
user-overridable default) provide the documented boundaries. They do not make
an unverified provider route/DNS killswitch leak-proof. Replace
"protonvpn-app" steps with the equivalent vendor tooling.

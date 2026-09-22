# Thunderbird Calendar Timezone

NoID Privacy defaults `calendar.timezone.useSystemTimezone = true`. Calendar
display follows the system timezone; individual event and CalDAV serialization
also depend on the event/provider data, so this is not a universal wire-format
claim.

## Why System-Locale Flow-Through?

The forced-UTC approach was reverted because it created persistent UX friction
for non-UTC users. Timezone data can reveal location or routine information to
the calendar provider and to invite recipients; TLS protects it in transit but
does not hide it from those endpoints. No single display preference removes
that metadata from existing events or provider-side copies. Users who prefer a
UTC display default can opt in as described below.

## Choose the Display Timezone

Open **Settings → Calendar → General**. Keep **Use system timezone**, or
choose **Set timezone manually** and select the desired timezone. This setting
applies to Thunderbird's calendar display; each event can retain its own
timezone. Calendar Properties has no separate display-timezone selector.

For a persistent UTC default while using NoID Privacy's profile `user.js`,
append these overrides after the NoID Privacy values while Thunderbird is closed:

```javascript
user_pref("calendar.timezone.useSystemTimezone", false);
user_pref("calendar.timezone.local", "Etc/UTC");
```

See [Override Any Default](35-thunderbird-mail-setup.md#override-any-default)
for preference precedence and what reapplying the profile hardening replaces.
This changes the local/default timezone selection; it does not rewrite existing
events or remove timezone data already shared with a provider or attendee.

## Calendar Privacy Defaults

| Pref | NoID Privacy Value | Reason |
|------|-----------|--------|
| `calendar.timezone.useSystemTimezone` | `true` | System-locale flow-through (reverted from forced-UTC) |
| `calendar.alarms.playsound` | `false` | No audible alarms (privacy: speaker leak) |
| `calendar.alarms.show` | `true` | Visual alarms allowed |

The retired `calendar.network.timeout` and `calendar.useragent.extra` names are
deliberately not configured: the shipped Thunderbird 152 engine does not read
them. Setting either name would create cosmetic hardening without changing
CalDAV behavior.

## CalDAV Setup

Most CalDAV providers (mailbox.org, Posteo, Fastmail, self-hosted Radicale) work natively. Setup:

1. Open **File → New → Calendar** and choose **On the Network**.
2. Enter the provider's username and CalDAV address, then continue discovery.
3. Authenticate when prompted and select the calendars to subscribe to.

Thunderbird follows the operating-system resolver by default. An active
VPN/private `~.` DNS scope takes precedence; direct WAN uses NoID Privacy's
strict global Quad9 resolver; explicit compatibility mode permits DNS/53
fallback. Destination IP, traffic timing and—unless ECH is successfully
negotiated—TLS metadata can still reveal or narrow the service.

## Tor / VPN Considerations

Module 06 places genuine VPN interfaces in the inbound-DROP `noid-vpn` zone
and can enforce WAN-strict after endpoint pinning. Routing all traffic through
the tunnel and DNS leak prevention remain VPN-profile/provider settings that
must be tested. CalDAV over a correctly configured tunnel is supported. The
image does not ship a general system Tor SOCKS listener. Only if you have
separately installed and verified one on `127.0.0.1:9050`, the corresponding
Thunderbird settings are:

```
network.proxy.type = 1
network.proxy.socks_remote_dns = true   (NoID Privacy default)
network.proxy.socks = 127.0.0.1
network.proxy.socks_port = 9050
```

## Local Calendar (Offline)

If you don't want any network sync:

1. Open **File → New → Calendar** and choose **On My Computer**.
2. Choose a name, color and reminder setting, then create the calendar.

Thunderbird stores this calendar in the profile. The creation dialog does not
ask you to select an ICS file, database format or filesystem location.

This creates no CalDAV sync for that calendar. Thunderbird and installed
extensions can still make unrelated network requests, so it is not a claim
that the whole application is offline.

## See Also

- `docs/35-thunderbird-mail-setup.md` — General setup
- `thunderbird/noid-thunderbird-hardening.js` (Calendar Privacy section) — canonical rationale

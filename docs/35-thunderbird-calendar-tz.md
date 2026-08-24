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

## Override to Forced UTC (privacy-paranoid mode)

```
about:config → calendar.timezone.useSystemTimezone = false
about:config → calendar.timezone.local = "Etc/UTC"
```

This changes Thunderbird's local/default timezone selection. It does not
rewrite existing events, guarantee a UTC-only CalDAV representation, or remove
timezone data already shared with a provider or attendee.

## Configure Display TZ Per-Calendar

In Thunderbird Calendar:

1. Click on the Calendar tab (or Tools → Calendar Layout → Calendar)
2. Right-click on any of your calendars → **Properties**
3. Find "Time Zone" section
4. Select your local TZ (e.g., `Europe/Berlin`, `America/New_York`, `Asia/Tokyo`)

This changes the calendar display choice. Existing event TZID/UTC data and the
provider's CalDAV representation are separate and should be inspected for the
calendar in question.

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

1. Calendar → File → New Calendar → On the Network
2. Format: CalDAV
3. Location: provider's CalDAV URL (e.g., `https://dav.mailbox.org/caldav/`)
4. Username + Password

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

1. Calendar → File → New Calendar → On My Computer
2. Format: ICS or storage.sqlite
3. Choose location

This creates no CalDAV sync for that calendar. Thunderbird and installed
extensions can still make unrelated network requests, so it is not a claim
that the whole application is offline.

## See Also

- `docs/35-thunderbird-mail-setup.md` — General setup
- `thunderbird/noid-thunderbird-hardening.js` (Calendar Privacy section) — canonical rationale

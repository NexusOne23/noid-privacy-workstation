# Thunderbird Mail Setup — NoID Privacy Workstation

NoID Privacy ships Thunderbird with privacy-first defaults pre-applied (Module
35). AutoConfig uses `defaultPref`, not `lockPref`, so the policy is not a
managed lock. The profile `user.js` is re-read at startup, however, and can
reset prefs that it lists; see the override section below.

## First Launch

When you launch Thunderbird for the first time, the account-setup wizard can
use five discovery channels:

1. **Own-domain lookup** (`fetchFromISP`) — TLS-only requests to
   `autoconfig.<domain>` and `<domain>/.well-known`. The full email address is
   not sent (`fetchFromISP.sendEmailAddress=false`), but the domain leaves the
   machine.
2. **Thunderbird ISPDB** (`mailnews.auto_config_url`) — asks Thunderbird's
   configuration service for the mail domain.
3. **MX lookup** — a DNS MX query for the domain, followed by the first two
   lookups for the mail provider's domain.
4. **Microsoft Exchange AutoDiscover** (`fetchFromExchange`) — **off by
   default.** When enabled it POSTs the full email address to
   `autodiscover.<domain>` and `<domain>` (one probe over plain HTTP) and sends
   the password entered in the wizard to the HTTPS endpoints.
5. **Hostname guessing** (`guess`) — **on.** TLS-only connection attempts to
   `imap.`, `pop3.`, `pop.`, `mail.` and `smtp.<domain>` and to `<domain>`
   itself on the standard mail ports, with strict certificate checks
   (`guess.sslOnly`, `guess.requireGoodCert`). These probes leave the machine
   like the other channels.

Enter settings manually if you do not want any discovery traffic.

For a no-discovery setup, append these after the NoID Privacy values in the
profile `user.js` before running the wizard (the MX DNS query still runs):

```
user_pref("mailnews.auto_config.guess.enabled", false);
user_pref("mailnews.auto_config.fetchFromISP.enabled", false);
user_pref("mailnews.auto_config.fetchFromExchange.enabled", false);
user_pref("mailnews.auto_config_url", "");
```

Exchange or Microsoft 365 accounts that rely on AutoDiscover can append
`user_pref("mailnews.auto_config.fetchFromExchange.enabled", true);` for the
account setup, accepting the disclosure above, and remove it afterwards.

Use the provider's current documentation for hostnames, ports and authentication.

## Manual Setup — Sample Settings

| Provider | IMAP | SMTP | Authentication |
|----------|------|------|----------------|
| **Proton Mail Bridge** | host/port/mode shown by Bridge | host/port/mode shown by Bridge | Bridge-generated credentials |
| **Self-Hosted (Dovecot+Postfix)** | `mail.example.com:993` SSL/TLS | `mail.example.com:587` STARTTLS | Normal Password |
| **Hosted provider** | provider's current IMAP value | provider's current SMTP value | provider-specific; OAuth2 where required |

## Privacy-First Defaults (NoID Privacy Highlights)

The most relevant NoID Privacy defaults for first-time users are:

- **Remote images blocked** — sender can't track when you open mail. A
  deliberate sender/site allow from the message banner persists across
  restarts and remains removable under Remote Content Exceptions.
- **HTML display/compose retained, remote content blocked** — HTML compatibility
  remains enabled; remote fetches are the separate tracking boundary.
- **JavaScript disabled in mail body** — no JS execution (security-critical, NoID Privacy keeps off).
- **Return receipts never sent automatically** — `mail.mdn.report.not_in_to_cc`,
  `.outside_domain` and `.other` default to 0 (never send). Requesting receipts
  stays at Thunderbird's own default (off); per-account Return Receipts settings
  can override both.
- **System/VPN DNS by default** — Thunderbird follows the active
  `systemd-resolved` scope, so VPN/private DNS takes precedence and direct WAN
  uses NoID Privacy's global Quad9 path. Secure DNS remains user-configurable
  under Settings → Privacy & Security → DNS over HTTPS. Thunderbird
  keeps dual-stack resolution enabled; the OS separately blocks unqualified
  physical-WAN IPv6 while allowing a VPN's internal IPv6 path.
- **DKIM TXT lookups follow the active resolver by default** — the bundled
  DKIM Verifier extension's provider-neutral JSDNS mode reads the OS resolver
  configuration, so VPN/private-link DNS remains in scope. A user can select a
  different resolver explicitly in the extension's settings.
- **Mozilla telemetry preferences disabled** — telemetry upload endpoints and
  automatic crash submission are disabled in the shipped preference layers.
  This is not a claim that ordinary account/provider traffic is absent.

## Updates

Thunderbird's own application and executable add-on background updaters are
disabled. A user-started NoID Privacy Update All run updates the Thunderbird RPM,
re-asserts the system hardening files, and advances DKIM Verifier (fixed GUID
`dkim_verifier@pl`) and every other profile-owned ATN extension in every
registered profile through ATN's compatibility-filtered official API.
Artifacts are size/SHA-256 and structure/identity checked, installed only while
Thunderbird is closed, published atomically, and recorded in the local extension
evidence ledger. DKIM Verifier's XPI does not claim a Mozilla signature; its
trust boundary is the fixed GUID plus the ATN API's declared file size/SHA-256
and those validation and publication gates. If Thunderbird is open or a
candidate cannot be authenticated, Update All reports an error instead of
claiming a complete run.

## Override Any Default

Every NoID Privacy preference remains user-overridable, but precedence matters:

1. **Per-profile `user-overrides.js`** — put the desired `user_pref` lines in
   `user-overrides.js` inside the profile directory (a regular file you own,
   at most 64 KiB). `noid-thunderbird-harden-profile`, and therefore every
   Update All run, appends it after the NoID Privacy values in `user.js`, so
   your values win at every launch. Run
   `noid-thunderbird-harden-profile <registered-profile-name>` once while
   Thunderbird is closed to apply a new or changed file immediately.
2. **Remove the NoID Privacy profile `user.js`** —
   `noid-thunderbird-harden-profile --remove <registered-profile-name>` stops
   re-applying the NoID Privacy values at startup. Values it already applied
   remain in `prefs.js` as user values; reset them in `about:config` to fall
   back to the system `defaultPref` layer. An `about:config` change then
   persists normally.
3. **System-wide** — edit `/usr/lib64/thunderbird/mozilla.cfg` as root only if
   you accept that a Thunderbird RPM update can overwrite it and Update All
   intentionally re-deploys the repository copy.

## Protect Stored Credentials

NoID Privacy does not disable Thunderbird's built-in credential store
(`signon.rememberSignons`). Review Thunderbird's stored-logins behavior for
each account. If you use its credential store, set a Primary Password under
≡ → Settings → Privacy & Security (menu bar: Edit → Settings) and understand
that this protects locally stored secrets at rest, not an already-unlocked
Thunderbird session. KeePassXC is also shipped as a separate password manager.

## See Also

- `docs/35-thunderbird-oauth2-providers.md` — Gmail / Office365 / Microsoft Entra
- `docs/35-thunderbird-proton-bridge.md` — Proton Mail Bridge setup
- `docs/35-thunderbird-smartcard.md` — Yubikey / OpenPGP-Smartcards
- `docs/35-thunderbird-calendar-tz.md` — Calendar timezone (follows the OS timezone; UTC opt-in)
- `docs/35-thunderbird-self-hosted-mail.md` — Self-hosted IMAP/SMTP
- `kickstart/snippets/35-thunderbird.ks` (header) — hardening design rationale and preference layers

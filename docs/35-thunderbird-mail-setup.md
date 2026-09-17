# Thunderbird Mail Setup — NoID Privacy Workstation

NoID Privacy ships Thunderbird with privacy-first defaults pre-applied (Module
35). AutoConfig uses `defaultPref`, not `lockPref`, so the policy is not a
managed lock. The profile `user.js` is re-read at startup, however, and can
reset prefs that it lists; see the override section below.

## First Launch

When you launch Thunderbird for the first time, the account-setup wizard may
use domain-based ISP/autoconfiguration lookup and TLS-only local guessing. The
full email address is not sent by the configured ISP lookup
(`fetchFromISP.sendEmailAddress=false`), but the domain/query still leaves the
machine. Enter settings manually if you do not want that discovery traffic.

For a no-discovery setup, set these to `false` in the profile `user.js` before
running the wizard:

```
user_pref("mailnews.auto_config.guess.enabled", false);
user_pref("mailnews.auto_config.fetchFromISP.enabled", false);
```

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
- **Return-receipt requesting defaults off** — review the per-account incoming
  receipt policy in Thunderbird's UI; do not infer it from remote-content settings.
- **System/VPN DNS by default** — Thunderbird follows the active
  `systemd-resolved` scope, so VPN/private DNS takes precedence and direct WAN
  uses NoID Privacy's global Quad9 path. Secure DNS remains user-configurable
  under Settings → General → Network & Disk → Connection Settings. Thunderbird
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
re-asserts the system hardening files, advances DKIM Verifier from its fixed
official repository, and advances every other profile-owned ATN extension in
every registered profile through ATN's compatibility-filtered official API.
Artifacts are size/SHA-256 and structure/identity checked, installed only while
Thunderbird is closed, published atomically, and recorded in the local extension
evidence ledger. DKIM Verifier's upstream XPI does not claim a Mozilla signature;
its trust boundary is the fixed repository/API digest plus those validation and
publication gates. If Thunderbird is open or a candidate cannot be authenticated,
Update All reports an error instead of claiming a complete run.

## Override Any Default

Every NoID Privacy preference remains user-overridable, but precedence matters:

1. **Per-profile `user.js`** — append the desired `user_pref` after the
   repository value. It is re-applied every launch. Re-running
   `noid-thunderbird-harden-profile` replaces this file after backing it up.
2. **Remove the NoID Privacy profile `user.js`** —
   `noid-thunderbird-harden-profile --remove <registered-profile-name>` leaves the
   system `defaultPref` layer, after which an `about:config` user value in
   `prefs.js` wins normally.
3. **System-wide** — edit `/usr/lib64/thunderbird/mozilla.cfg` as root only if
   you accept that a Thunderbird RPM update can overwrite it and Update All
   intentionally re-deploys the repository copy.

## Protect Stored Credentials

NoID Privacy does not set `signon.rememberSignons=false`; the previous claim that the
built-in credential store was disabled was incorrect. Review Thunderbird's
stored-logins behavior for each account. If you use its credential store, set a
Primary Password under Tools → Settings → Privacy & Security and understand
that this protects locally stored secrets at rest, not an already-unlocked
Thunderbird session. KeePassXC is also shipped as a separate password manager.

## See Also

- `docs/35-thunderbird-oauth2-providers.md` — Gmail / Office365 / Microsoft Entra
- `docs/35-thunderbird-proton-bridge.md` — Proton Mail Bridge setup
- `docs/35-thunderbird-smartcard.md` — Yubikey / OpenPGP-Smartcards
- `docs/35-thunderbird-calendar-tz.md` — Calendar timezone (system-locale flow-through; forced-UTC opt-in)
- `docs/35-thunderbird-self-hosted-mail.md` — Self-hosted IMAP/SMTP
- `kickstart/snippets/35-thunderbird.ks` (header) — hardening design rationale and preference layers

# Thunderbird + Self-Hosted Mail

Standards-compliant IMAP/SMTP servers can work, but compatibility depends on
TLS, authentication, DNS and the NoID Privacy LAN boundary. This document does not
promise every Dovecot/Postfix/Mailcow/Mailu/Stalwart configuration works.

## Internal LAN Mailserver

If your mailserver is on the local network (for example,
`mail.homelab.lan`), allowing its IP through the LAN boundary does not by
itself make a private name resolvable. NoID Privacy ignores physical-link DNS
learned from DHCP by default. Thunderbird now follows the system resolver, so
an explicitly configured private `~.` DNS scope can work without a separate
browser-level bypass.

First allow the exact server IP in NoID Privacy Network. Then choose one of these name
resolution paths:

### Option A: use the IP literal or a reviewed `/etc/hosts` entry

An IP literal requires no DNS. For a stable internal name, add a deliberate
`/etc/hosts` mapping after verifying the server address. Certificate hostname
validation still requires a certificate matching the name you configure.

### Option B: deliberately configure an internal resolver

NoID Privacy ignores physical-link DHCP DNS and uses global Quad9 when no
more-specific scope exists. Configure the intended private resolver and routing
domain explicitly; changing Thunderbird Secure DNS alone does **not** make a
router's private DNS authoritative. This is a system-level privacy exception
that must be paired with the exact LAN peer allow and tested for leakage. This
guide intentionally does not supply a universal resolver override.

## Server Setup Examples

### Dovecot+Postfix

| Setting | IMAP | SMTP-Submission |
|---------|------|-----------------|
| **Server** | `mail.example.com` | `mail.example.com` |
| **Port** | `993` | `587` |
| **Security** | SSL/TLS | STARTTLS |
| **Authentication** | Normal Password (PLAIN) | Normal Password (PLAIN) |

### Mailcow / Mailu / Stalwart

These commonly offer the same standards, but actual ports, TLS and
authentication are administrator-configurable. Use the server's own values.

## TLS Cert-Trust for Self-Signed

If your mailserver uses a self-signed certificate, Thunderbird may offer a
per-server exception. Confirm only after independently checking the certificate
and expected hostname; prefer a properly managed internal/public CA.

NoID Privacy's `security.cert_pinning.enforcement_level=2` does not authenticate a
self-signed server or private CA. The reviewed exception or imported CA remains
the relevant trust decision.

Prefer a certificate issued for the configured hostname. If an internal CA is
required, import and verify it through Thunderbird's certificate manager:

```
Tools → Settings → Privacy & Security → Certificates → Manage Certificates → Authorities → Import
```

System/NSS trust integration is distribution- and profile-dependent; verify the
effective issuer in Thunderbird instead of assuming a copied system anchor was
loaded.

## TLS-Only Configuration

Force TLS 1.2+ regardless of the server's offered ciphers (the managed
Thunderbird baseline):

```
security.tls.version.min = 3
security.tls.version.max = 4
security.tls.version.enable-deprecated = false
```

Servers without TLS 1.2 support are outside the hardened baseline. Upgrade or
isolate the server instead of enabling deprecated TLS globally in the mail
profile.

## STARTTLS strict mode

Select **STARTTLS** (or direct **SSL/TLS**) explicitly in each account's server
settings and verify that the resulting connection is encrypted. Do not rely on
an undocumented global preference or permit plaintext fallback.

## CalDAV/CardDAV on Self-Hosted

Most self-hosted setups bundle a CalDAV/CardDAV server (Radicale, Baikal, Sabre/dav). See `docs/35-thunderbird-calendar-tz.md` for setup.

## See Also

- `docs/35-thunderbird-mail-setup.md` — General setup
- `docs/35-thunderbird-calendar-tz.md` — Calendar/CalDAV
- `kickstart/snippets/35-thunderbird.ks` — Canonical DNS, TLS and
  user-overridable preference implementation

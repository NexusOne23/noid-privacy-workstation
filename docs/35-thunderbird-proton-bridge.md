# Thunderbird + Proton Mail Bridge

Proton Mail Bridge is a local IMAP/SMTP proxy that decrypts your Proton Mail messages on-the-fly. It runs as a desktop application alongside Thunderbird.

## Install Bridge

NoID Privacy does **not** ship Proton Mail Bridge by default. Obtain the
currently supported Linux package for an eligible plan from <https://proton.me/mail/bridge>
(follow Proton's current Linux RPM verification instructions), then:

```bash
sudo dnf install ./protonmail-bridge-<exact-verified-version>.rpm
```

Then launch it from GNOME Activities and use its current setup UI.

## Bridge Setup

1. Sign in through Bridge itself, not Thunderbird.
2. Bridge generates a **per-account password** for Thunderbird (different from your Proton password).
3. Copy the IMAP/SMTP host, ports, username and generated password shown by
   Bridge. Ports are configurable and must not be assumed from this document.

## Add Account in Thunderbird

| Field | Value |
|-------|-------|
| **Your Name** | (display name) |
| **Email Address** | `you@proton.me` (or your custom domain) |
| **Password** | Bridge-generated password (NOT your Proton password) |

Then "Configure manually":

| Setting | IMAP | SMTP |
|---------|------|------|
| **Server** | `127.0.0.1` | `127.0.0.1` |
| **Port** | value shown by Bridge | value shown by Bridge |
| **Connection Security** | mode shown by Bridge | mode shown by Bridge |
| **Authentication** | Normal Password | Normal Password |
| **Username** | `you@proton.me` | `you@proton.me` |

## Cert-Trust on First Connection

Proton Bridge uses a **self-signed certificate**. On first connection Thunderbird will prompt:

```
Security Exception
This site has provided a certificate that does not match...
```

Confirm the exception only while the expected Bridge instance is running and
the host/ports match Bridge's setup screen. The connection is loopback-only,
but a self-signed certificate is still a trust decision; “local” does not make
arbitrary certificate material harmless. Resetting Bridge can generate a new
certificate and require removal of the old exception.

NoID Privacy's `security.cert_pinning.enforcement_level=2` does not authenticate a
self-signed Bridge certificate for you. The explicitly reviewed certificate
exception remains the relevant trust decision.

## No DNS exception is required for the IP literal

`127.0.0.1` is already an IP address and does not require DNS resolution.
Do not change the system/VPN resolver or add a fake browser Secure-DNS
exception for this loopback connection. Use the exact host value Bridge
displays.

## Verify Connection

After setup, receive and send a test message and inspect Bridge/Thunderbird for
errors. That validates the exercised path, not every folder, import or recovery
operation.

## Bridge startup and diagnostics

Bridge needs to be running for Thunderbird to send/receive. Use Bridge's own
current **Open on startup** setting if you accept that background process; the
image does not enable it. Proton also documents a **Collect usage diagnostics**
setting—turn it off if you do not want those vendor diagnostics. Bridge still
needs network access to Proton when actively synchronizing.

## Troubleshooting

- **"Authentication failed"**: Wrong password — use **Bridge-generated** password, not Proton account password.
- **"Cannot connect to server"**: Bridge not running. Check `pgrep protonmail-bridge`.
- **"Certificate untrusted"**: First-launch exception expired. Re-add via Edit → Account Settings → Server Settings → "Edit certificate exceptions...".

## See Also

- `docs/35-thunderbird-mail-setup.md` — General setup
- Proton's official Bridge docs: <https://proton.me/support/protonmail-bridge-clients-windows-thunderbird>

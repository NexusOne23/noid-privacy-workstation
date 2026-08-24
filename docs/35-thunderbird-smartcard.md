# Thunderbird + YubiKey / OpenPGP Smartcard

NoID Privacy ships Thunderbird with `mail.openpgp.allow_external_gnupg=true`.
This enables Thunderbird's **experimental** external-GnuPG path for secret-key
operations: GnuPG can sign and decrypt with a secret key on a hardware token
(YubiKey 5, OpenPGP smartcard, Nitrokey). Thunderbird still uses its internal
RNP implementation for public-key encryption, signature verification,
public-key storage and trust decisions.

This preference only exposes the integration. It does not prove that a given
Thunderbird, GPGME, token and reader combination works. Verify signing and
decryption after installation and after major Thunderbird/GnuPG updates.

## Install Smartcard Stack

NoID Privacy ships GnuPG for repository verification, but the complete smartcard stack
is not a guaranteed image component and PC/SC is masked by default. Install the
packages, then explicitly unmask the socket-activated service:

```bash
sudo dnf install gnupg2 pcsc-lite pcsc-lite-ccid opensc
sudo systemctl unmask pcscd.socket pcscd.service
sudo systemctl enable --now pcscd.socket
systemctl is-active pcscd.socket
```

`pcscd` is the PC/SC daemon that talks to USB smartcards.
Enabling it adds a local PC/SC socket plus the daemon/reader/parser surface.
Fedora governs access through polkit, and this is not a network listener, but it
is still an intentional local attack-surface and privacy trade-off that should
remain enabled only while smartcard access is wanted.

To return to the NoID Privacy default:

```bash
sudo systemctl disable --now pcscd.socket
sudo systemctl stop pcscd.service
sudo systemctl mask pcscd.socket pcscd.service
systemctl is-enabled pcscd.socket pcscd.service
```

Both units should report `masked`; smartcard access through PC/SC then stops.

## Verify Smartcard Detection

Insert your YubiKey/smartcard, then:

```bash
gpg --card-status
```

You should see:

```
Reader ...........: <your reviewed reader>
Application ID ...: <redacted>
Version ..........: <device value>
Manufacturer .....: <device value>
Serial number ....: <redacted>
Name of cardholder: <redacted>
...
Signature key ....: ABCD 1234 ...
Encryption key ...: EF01 5678 ...
Authentication key: 9876 ABCD ...
```

If no output: check `journalctl -u pcscd` for permissions or detection errors.

## Configure Thunderbird

In Thunderbird:

1. Tools → OpenPGP Key Manager
2. File → Import Public Keys from File (or Server Key Search)
3. Import your **public key** (signing + encryption pubkey from your card)

For sending:

4. Tools → Account Settings → End-to-End Encryption
5. Select "Use external key configured in GnuPG" (NoID Privacy default `mail.openpgp.allow_external_gnupg=true` enables this option)
6. Enter the exact **16-character primary key ID** (the last 16 characters of
   the primary-key fingerprint), as required by Thunderbird. The field is not
   a full-fingerprint verifier, so compare the value carefully.

## Send Encrypted/Signed Mail

When composing:

- **Encrypt** = Thunderbird's internal RNP implementation encrypts with the
  recipients' imported public keys and also encrypts a copy to your configured
  public key; this is not a secret-key operation on the card.
- **Sign** = GnuPG can ask the card to perform the signing operation. The
  signing secret stays on the token when that is where GnuPG stores it.
- **Decrypt** = GnuPG can ask the card to decrypt messages addressed to its
  secret key.
- A PIN prompt depends on the token, reader, pinentry and agent-cache policy;
  it is not guaranteed for every operation.

## OpenPGP Pref Reference

| Pref | NoID Privacy Value | Reason |
|------|-----------|--------|
| `mail.openpgp.allow_external_gnupg` | `true` | Hardware-token secret-key operations through GnuPG/GPGME |
| `mail.openpgp.separate_mime_layers` | `true` | RFC 3156 PGP/MIME interoperability |

NoID Privacy leaves `mail.openpgp.load_untested_gpgme_version` unset. It is an escape
hatch for trying an additional GPGME shared-library filename suffix, not a
general compatibility or security switch. Current Thunderbird already probes
the common `.45`, `.11` and unsuffixed library names.

## GnuPG Smartcard-Only Setup

GnuPG 2 uses `gpg-agent` automatically; a `use-agent` line and custom cipher
preferences are not required for Thunderbird smartcard support. If you
deliberately want bounded agent caching, review and set values appropriate for
your token and threat model, for example:

```bash
install -d -m 0700 "$HOME/.gnupg"
${EDITOR:-vi} "$HOME/.gnupg/gpg-agent.conf"
```

Add or replace these keys once in the file:

```text
default-cache-ttl 600
max-cache-ttl 7200
```

Then reload the agent:

```bash
gpg-connect-agent reloadagent /bye
```

These are example GnuPG agent cache limits, but token/reader policy determines
whether a smartcard PIN is actually cached. NoID Privacy does not enforce them.

## Troubleshooting

- **"PIN required"**: use the device's documented user PIN and change any
  factory credential during provisioning; this guide does not publish or
  assume a universal default.
- **"Card not found"**: `pcscd` not running, or `dnf install pcsc-lite-ccid` missing.
- **"Permission denied" on card access**: on Fedora, pcscd access is
  governed by polkit (not a `plugdev` group — that is a Debian-ism).
  Check `journalctl -u polkit -u pcscd` for the denial; an active local
  session is normally sufficient (`org.debian.pcsc-lite.access_pcsc`).
- **"GPGME isn't working"**: confirm that the installed Thunderbird can load
  Fedora's GPGME shared library, then inspect Thunderbird's Error Console.
  Do not guess a `mail.openpgp.load_untested_gpgme_version` suffix: compare the
  installed library filenames with the current Thunderbird loader source and
  test the complete sign/decrypt path.

## See Also

- `docs/35-thunderbird-mail-setup.md` (source tree) — General setup
- Mozilla Smartcards Guide: <https://wiki.mozilla.org/Thunderbird:OpenPGP:Smartcards>
- Thunderbird GPGME loader source: <https://searchfox.org/comm-central/source/mail/extensions/openpgp/content/modules/GPGMELib.sys.mjs>

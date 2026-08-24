# Post-Quantum Cryptography (PQC) Readiness — NoID Privacy Workstation

**Package and standards evidence last verified**: 2026-08-02. The observed
Fedora 44 environment used OpenSSH 10.2p1, OpenSSL 3.5.7, OpenVPN 2.7.5,
Firefox 153, Thunderbird 152, NSS 3.125, and GnuPG 2.4.9. This dated snapshot
supports the assessment below but is not an exact v1.7 ISO package manifest;
Fedora packages remain updateable.

**Endpoint probe observations last rerun**: 2026-08-02. They are deliberately
dated separately because remote endpoint support can change without a local
package or source change.

**Purpose**: document which NoID Privacy transports can negotiate a
post-quantum hybrid, which ones remain classical, and how to verify the result
instead of inferring it from a client setting.

## Threat model

A sufficiently capable cryptographically relevant quantum computer (CRQC)
would break the integer-factorisation and discrete-log assumptions behind RSA,
finite-field DH, and ECC (including X25519 and Ed25519). NIST says that nobody
knows when such a machine will exist; estimates range from a few years to a few
decades. There is no “2030–2040 NIST consensus.”

The present concern is *harvest now, decrypt later* (HNDL): an adversary can
record classically protected traffic now and attack its public-key exchange
later. Rotating an ephemeral X25519 key quickly provides forward secrecy
against later theft of a long-term key, but it does **not** make a recorded
X25519 exchange resistant to a future CRQC. Confidentiality lifetime and the
actually negotiated key exchange matter.

Symmetric cryptography is affected differently. Generic quantum key search is
commonly modelled as reducing an ideal 256-bit key to roughly 128-bit work. It
does not give the exponential break that Shor's algorithm gives RSA and ECC.

## Current coverage

### SSH transport — hybrid preferred, classical fallback retained

Module 09 configures both the SSH client and the opt-in SSH server template:

```text
KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256@libssh.org,curve25519-sha256
```

- `mlkem768x25519-sha256` combines FIPS 203 ML-KEM-768 with X25519 and
  became OpenSSH's default in 10.0.
- `sntrup761x25519-sha512@openssh.com` is the older hybrid fallback available
  in OpenSSH 9.x.
- the two Curve25519 entries are compatibility fallbacks and are
  classical-only.

An SSH session is hybrid-protected only when the negotiated algorithm is one
of the first two entries. The image does not claim that every peer supports
them. The `openssh-server` package is excluded from the image and
`sshd-unix-local.socket` is additionally masked. If the user installs the
server package, Fedora's preset can enable `sshd.service`; follow the installed
`ssh-server-opt-in.md` procedure immediately to keep every listener closed
until the hardened configuration and first public key are ready.

### LUKS2 disk encryption — symmetric boundary

When encryption is selected, the current release expects LUKS2 with
`aes-xts-plain64`, a 512-bit combined XTS key (two AES-256 keys), and an
Argon2id passphrase keyslot. Those are installed-state claims: identify the
root mapping and verify the active keyslot with `cryptsetup luksDump` rather
than inferring the KDF from `lsblk` or the image defaults.

- AES-256 is not vulnerable to Shor's public-key break; the conservative
  generic quantum-search estimate is roughly 128-bit work.
- Argon2id raises the cost of passphrase guessing, but the passphrase's entropy
  and the actual LUKS parameters remain essential. “Memory-hard” is not a
  promise that quantum computation can provide no advantage.
- LUKS is an at-rest symmetric-encryption boundary, not a PQ public-key
  transport. A copied disk image can still be attacked offline.

Accordingly, the configuration has a strong symmetric post-quantum margin,
but the project does not label disk compromise “zero risk” or “fully quantum
safe.”

### Firefox and Thunderbird TLS — hybrid-capable, peer-dependent

NSS 3.105 added `mlkem768x25519` support; NSS 3.118 made it the default group.
NoID Privacy also sets `security.tls.enable_kyber=true` explicitly in the
Firefox and Thunderbird profiles so the intended client capability does not
depend only on an upstream default. The historical preference name still says
“kyber”; current NSS negotiates `X25519MLKEM768`, which combines the
FIPS 203-standardized ML-KEM with X25519. RFC 9954 defines the generic TLS 1.3
hybrid-key-exchange encoding, while the concrete `X25519MLKEM768` group
specification remains an IETF Internet-Draft as of the verification date.

This establishes **client capability**, not endpoint coverage. A connection is
hybrid-protected only if the peer supports the group and the TLS handshake
actually selects it. Otherwise TLS can fall back to classical X25519 or another
classical group.

On 2026-08-02, a direct OpenSSL 3.5 probe restricted to
`X25519MLKEM768` succeeded against the Cloudflare PQ test endpoint. Quad9's
two documented IPv4 DoT addresses showed session-dependent behavior: the
primary address completed `X25519MLKEM768` in two of six hybrid-only sessions
and rejected the other four handshakes. The secondary address rejected all six
hybrid-only sessions. A separate unrestricted session to the secondary address
nevertheless negotiated `X25519MLKEM768`. This establishes that some observed
Quad9 sessions can negotiate the hybrid group. It does not establish consistent
endpoint-wide support. These are dated endpoint observations, not a claim about
all Cloudflare or Quad9 sessions; the verification commands below are the source
of truth for a later release.

ECH is a separate property. Enabling ECH in Firefox hides the inner ClientHello
and SNI only where Firefox obtains a valid ECH configuration and the connection
successfully negotiates ECH. A preference alone does not hide every SNI.

## Upstream- and peer-dependent gaps

### WireGuard and provider VPNs

WireGuard's handshake remains based on Curve25519. NoID Privacy has not found a
standardised, interoperable WireGuard PQ mode in the upstream protocol as of
the verification date. Frequent WireGuard handshakes do not remove HNDL risk
for recorded classical exchanges. WireGuard's optional preshared key can add a
strong symmetric layer only when it is independently generated, exchanged and
protected correctly; it is not a standardised PQ public-key handshake or a
reason to advertise every provider tunnel as PQ-protected.

OpenVPN 2.7 with OpenSSL 3.5 can restrict the TLS control-channel group to
`X25519MLKEM768`, but **both peers must support it**. Installing those versions
or selecting “OpenVPN” in a provider GUI does not prove that a provider endpoint
negotiated the group. NoID Privacy therefore does not present any provider's
OpenVPN mode as a verified PQ alternative; inspect the exact OpenVPN connection
log for the negotiated key agreement.

The data channel uses symmetric encryption, but its traffic keys are delivered
through the control channel. A classical control-channel exchange remains
relevant to HNDL.

### Tor

Tor's short-lived classical circuit keys are not a PQ substitute: a future CRQC
could attack the public values in a recorded circuit handshake. Tor may still
be useful for routing anonymity, but layering Tor over WireGuard does not make
either classical key exchange post-quantum secure. End-to-end hybrid TLS can
independently protect application payloads where the destination supports it.

### OpenPGP email

RFC 9980, published as an IETF Proposed Standard in June 2026, defines
PQ/traditional composite algorithms for OpenPGP. Standardisation is not an
implementation guarantee: the installed Fedora 44 GnuPG 2.4.9 reports no
Kyber/PQ public-key algorithm, while upstream GnuPG 2.5 does. The system
Thunderbird/GnuPG workflow must not be assumed to interoperate with RFC 9980
keys until its installed versions document and demonstrate support.

Upstream declared GnuPG 2.4 end-of-life on 2026-06-30. Fedora 44 still
delivered 2.4.9 on the verification date, so keep the Fedora package fully
updated and track the distribution's migration rather than silently replacing
it with an unreviewed third-party build. Upstream 2.5 capability alone still
does not prove Thunderbird interoperability with RFC 9980 keys.

Proton Mail began a gradual, provider-specific PQ OpenPGP rollout in May 2026.
That is a useful option for eligible Proton Mail accounts, but it does not make
the generic Thunderbird/GnuPG path PQ-capable and does not by itself establish
interoperability with arbitrary OpenPGP correspondents.

Long-lived, public-key-encrypted mail remains a high-priority HNDL concern. Do
not promise that old archives can simply be made safe later: an adversary may
already possess the original ciphertext.

### Secure Boot, MOK, and RPM signatures

The platform Secure Boot chain, Fedora shim/kernel signatures, the optional
NVIDIA MOK workflow, and Fedora RPM signatures use classical public-key
signatures. Their exact algorithms and key sizes are properties of the
platform and current upstream packages, not a universal constant the image can
replace.

TLS transport, AIDE, Secure Boot lockdown, and signed repositories are useful
defence-in-depth today, but they do not convert a classical signature into a PQ
signature. DNF mirror selection is fallback, not independent cross-validation,
and a repository HTTPS connection is hybrid only when its own TLS stack and
selected mirror negotiate a hybrid group.

## Verification

### SSH

After connecting:

```bash
read -r -p 'Exact SSH destination (for example user@host): ' SSH_DEST
if [[ -n "$SSH_DEST" && "$SSH_DEST" != -* && "$SSH_DEST" != *[[:space:]]* ]]; then
    ssh -vv "$SSH_DEST" 2>&1 | grep -F 'kex: algorithm:'
else
    printf 'Invalid SSH destination\n' >&2
fi
```

Expected hybrid result:

```text
debug1: kex: algorithm: mlkem768x25519-sha256
```

`sntrup761x25519-sha512@openssh.com` is also hybrid. A Curve25519-only result
means the session used the documented classical fallback; it does not prove a
particular peer version.

### TLS endpoint probe

With Fedora 44's OpenSSL 3.5:

```bash
read -r -p 'Exact TLS DNS name (without scheme or port): ' TLS_HOST
if [[ "$TLS_HOST" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$ ]] &&
   [[ "$TLS_HOST" =~ [A-Za-z0-9]$ ]] && [[ "$TLS_HOST" == *.* ]] &&
   [[ "$TLS_HOST" != *..* ]]; then
    openssl s_client \
      -connect "${TLS_HOST}:443" \
      -servername "$TLS_HOST" \
      -groups X25519MLKEM768 \
      -brief </dev/null
else
    printf 'Invalid DNS name\n' >&2
fi
```

A successful handshake restricted to that group demonstrates endpoint support
at test time. A failure can also reflect a middlebox or endpoint-specific
configuration. Firefox's own connection can be checked at
<https://pq.cloudflareresearch.com/>; this tests that endpoint and session, not
the whole web.

### OpenVPN

OpenVPN 2.7 reports the selected group in its connection log. Look for a line
containing:

```text
key agreement: X25519MLKEM768
```

For a self-managed deployment, `tls-groups X25519MLKEM768` can make absence of
hybrid support fail closed. Do not inject that option into a provider profile
unless the provider documents support; it can make the connection unusable.

## Maintenance posture

- Re-run the endpoint probes for each release; do not preserve a server-support
  observation as a timeless product claim.
- Track RFC 9980 implementation and interoperability in GnuPG/Thunderbird,
  WireGuard protocol work, and platform/distribution signature migrations.
- Treat package updates as capability changes that require re-verification.
- Preserve classical fallbacks only where interoperability is an explicit
  product requirement, and report when one was negotiated.

## Primary references

- NIST PQC overview and CRQC timing uncertainty:
  <https://www.nist.gov/cybersecurity-and-privacy/what-post-quantum-cryptography>
- NIST FIPS 203 (ML-KEM): <https://csrc.nist.gov/pubs/fips/203/final>
- OpenSSH PQ status (`mlkem768x25519-sha256` default in 10.0):
  <https://www.openssh.org/pq.html>
- NSS 3.105 release notes (ML-KEM support):
  <https://firefox-source-docs.mozilla.org/security/nss/releases/nss_3_105.html>
- NSS 3.118 release notes (ML-KEM hybrid default):
  <https://firefox-source-docs.mozilla.org/security/nss/releases/nss_3_118.html>
- IETF RFC 9954 (Hybrid Key Exchange in TLS 1.3):
  <https://www.rfc-editor.org/rfc/rfc9954.html>
- IETF TLS ECDHE-MLKEM group draft:
  <https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/>
- IETF RFC 9980 (Post-Quantum Cryptography in OpenPGP):
  <https://datatracker.ietf.org/doc/rfc9980/>
- GnuPG upstream 2.5 Kyber capability example:
  <https://lists.gnupg.org/pipermail/gnupg-users/2026-April/068248.html>
- GnuPG upstream branch/EOL status:
  <https://gnupg.org/blog/20250827-new-repository.html>
- OpenVPN PQ test guidance:
  <https://community.openvpn.net/PQCryptoOpenVPN/>
- WireGuard protocol: <https://www.wireguard.com/protocol/>
- Proton Mail's provider-specific gradual PQ rollout:
  <https://proton.me/blog/introducing-post-quantum-encryption>

## See also

- [`docs/threat-model.md`](threat-model.md)
- [`docs/scope.md`](scope.md)
- [`docs/35-thunderbird-smartcard.md`](35-thunderbird-smartcard.md)

# ============================================================================
# Module 09 — SSH Hardening (client-only image)
# Status: LOCKED 2026-08-01 (v33) — keep root-private LAN grants behind the privileged reader and validate sshd after host-key generation.
#
# Covers:
#   - %packages: -openssh-server (no SSH server in the image; openssh +
#     openssh-clients STAY for outgoing ssh/scp/sftp)
#   - Step 1:  client drop-in /etc/ssh/ssh_config.d/99-noid-hardening.conf
#     (PQ-hybrid KEX ML-KEM-768, AEAD-only ciphers, HashKnownHosts,
#     VerifyHostKeyDNS=no, GSSAPI off, RequiredRSASize 3072)
#   - Step 1b: server drop-in /etc/ssh/sshd_config.d/01-noid-hardening.conf
#     deployed UNCONDITIONALLY at build time (secure-by-default for a later
#     user-initiated openssh-server install; harmless while sshd is absent)
#   - Step 2:  opt-in template + ssh-server-opt-in.md walkthrough
#   - Step 2b: ssh-client-hardening.md (HashKnownHosts migration guide)
#   - Step 3:  verification
#
# Design constraints (incident-verified; keep when editing):
#   - sshd drop-in processing is FIRST-OCCURRENCE-WINS. The 01- prefix loads
#     BEFORE Fedora's 50-redhat.conf — that ordering IS the hardening
#     mechanism. Directives present in BOTH 01- and the opt-in template MUST
#     carry the SAME values (dead-letter class: an opt-in value differing
#     from 01- silently never applies). Every directive in the 01- file is
#     intentionally repeated with the same value in the opt-in template;
#     edit and test both files together.
#   - Without the always-deploy 01- drop-in, a user-initiated sshd install
#     starts with stock defaults (root login via key allowed, password auth
#     on, X11 forwarding on) — that is the gap Step 1b closes. Do not fold
#     it into the opt-in template.
#   - 01- has NO AllowUsers (any local user with a valid pubkey may log in;
#     pubkey-only + no-root is the secure default). The opt-in template
#     carries the CHANGEME_USERNAME AllowUsers whitelist for stricter
#     setups.
#   - HostKey selection is deliberately narrow: Ed25519 primary plus RSA-SHA2
#     compatibility. This is an interoperability/surface policy, not a claim
#     that ECDSA/P-256 is compromised. Fedora's native keygen target may still
#     create an unused ECDSA key; sshd does not load it under these HostKey
#     directives. There is no separate keygen-unit patch without a security
#     requirement for non-generation.
#   - DEFAULT exposure: the `drop` firewalld zone keeps an opted-in sshd
#     local-only. WAN-egress-strict is the `noid_wan_strict` nftables
#     table, NOT a firewalld zone — keep the docs phrased that way.
#   - A dev-only fix-phase (temporarily re-enable sshd for VM forensics)
#     exists as a pattern; the ship-gate test
#     tests/pre-ship/09-ssh-fix-phase-disabled.sh guards against shipping
#     it enabled.
#
# Cross-reference:
#   - Module 08 masks sshd-unix-local.socket (systemd-ssh-generator) — with
#     openssh-server absent the mask is defense-in-depth; the opt-in guide
#     documents the unmask step.
#   - Module 26 MUST_ABSENT list carries openssh-server.
# ============================================================================

%packages --exclude-weakdeps
# --- Module 09 package removals ---

# Q1: openssh-server removed — no SSH server in default image
# (openssh package = ssh-keygen/ssh-add/ssh-agent + man, openssh-clients =
#  ssh/scp/sftp/ssh-copy-id — both STAY for outgoing SSH; only -server out)
#
# Users who want sshd opt-in via `dnf install openssh-server` and follow
# /usr/share/doc/noid-privacy/ssh-server-opt-in.md (template + walkthrough
# deployed in Step 2 below).
-openssh-server

%end

# ============================================================================
# %post — SSH client hardening drop-in
# ============================================================================

%post --erroronfail --log=/var/log/ks-09-ssh.log

set -euo pipefail
umask 077
echo "=============================================================="
echo "[Module 09] SSH Hardening — client-only mode"
echo "=============================================================="

# ----------------------------------------------------------------------------
# Step 1: SSH client hardening drop-in
# ----------------------------------------------------------------------------
#
# /etc/ssh/ssh_config.d/ is part of openssh (not openssh-server), so it exists
# even after -openssh-server removal.
#
# Drop-in applies to ALL outgoing SSH connections (ssh, scp, sftp).
# Overrides Fedora DEFAULT crypto-policy where stricter.

echo ""
echo "[Step 1] SSH client hardening drop-in"

install -d -m 0755 -o root -g root /etc/ssh/ssh_config.d
cat > /etc/ssh/ssh_config.d/99-noid-hardening.conf <<'SSH_EOF'
# ============================================================================
# NoID Privacy — SSH client hardening
#
# Overrides Fedora DEFAULT crypto-policy which includes legacy hmac-sha1 for
# backward compat. This drop-in explicitly whitelists strong modern crypto only.
#
# Applied to all outgoing SSH connections (ssh, scp, sftp).
# Per-host overrides: add Host blocks BEFORE this file (lower prefix number)
# or in ~/.ssh/config for user-level per-host overrides.
# ============================================================================

Host *
    # ----- Privacy -----
    HashKnownHosts yes
    VisualHostKey yes

    # ----- Anti-MITM / host verification -----
    StrictHostKeyChecking ask
    CheckHostIP yes
    # VerifyHostKeyDNS no (explicit): prevents the additional SSHFP lookup.
    # Ordinary A/AAAA resolution for a hostname still occurs; this directive
    # controls only DNS-based host-key verification and its extra query. The
    # trade-off is that a DNSSEC-authenticated SSHFP signal is not used; a
    # reviewed per-host `VerifyHostKeyDNS ask` override can opt back in.
    VerifyHostKeyDNS no

    # UpdateHostKeys ask: defensive vs silent host-key
    # rotation. Modern OpenSSH default with VerifyHostKeyDNS=no is `yes`
    # (silent rotation). Setting `ask` prompts admin on rotation — defense-
    # in-depth against unauthorized rotation by a compromised server.
    UpdateHostKeys ask

    # ----- Anti-forwarding attacks -----
    ForwardAgent no
    ForwardX11 no
    ForwardX11Trusted no
    PermitLocalCommand no

    # ----- Connection hygiene (encrypted keepalives only) -----
    ServerAliveInterval 60
    ServerAliveCountMax 3
    TCPKeepAlive no

    # ----- Crypto whitelist (strict) -----
    # Overrides /etc/crypto-policies/back-ends/openssh.config
    # Accepts only modern, strong, well-audited algorithms.

    # Symmetric: ChaCha20-Poly1305 (AEAD) + AES-256-GCM (AEAD) only
    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com

    # MAC: SHA2-512/256 encrypt-then-MAC only
    # (AEAD ciphers above make these effectively unused, but set for safety)
    MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

    # KEX: post-quantum hybrid (ML-KEM-768 + sntrup761) + modern X25519 only
    # mlkem768x25519-sha256 = OpenSSH 10.0+ default (NIST FIPS 203 ML-KEM-768 + X25519)
    # sntrup761x25519-sha512@openssh.com = OpenSSH 9.0+ default (pre-ML-KEM fallback)
    # curve25519-sha256 = classical fallback for legacy servers; unlike the
    # first two entries, it does not protect recorded sessions against a CRQC.
    KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256@libssh.org,curve25519-sha256

    # WarnWeakCrypto yes (OpenSSH 10.1+ option):
    # Warn when negotiating non-post-quantum KEX (harvest-now-decrypt-later
    # awareness). Default `yes` since OpenSSH 10.1; set explicitly so the
    # effective policy is inspectable. Fires only on legacy-server-fallback
    # since the configured KEX list is PQ-first.
    WarnWeakCrypto yes

    # Host keys: certificate forms first so a reviewed host CA is not bypassed
    # when the peer also offers a raw key. Within each trust form Ed25519
    # precedes RSA; RSA uses SHA2-512 only (no SHA1 ssh-rsa).
    HostKeyAlgorithms ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,ssh-ed25519,rsa-sha2-512

    # Authentication signatures: Ed25519 software/FIDO2 (plain + certificate)
    # and RSA-SHA2 fallback. The FIDO entries match the key type recommended in
    # the opt-in guide instead of silently excluding it.
    PubkeyAcceptedAlgorithms ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,ssh-ed25519,sk-ssh-ed25519@openssh.com,rsa-sha2-512
    # ----- RSA key size enforcement (closed policy) -----
    # Reject RSA user + host keys smaller than 3072 bits. Ed25519 is preferred
    # (256-bit = ~128-bit security, equivalent to RSA-3072 but faster).
    RequiredRSASize 3072

    # ----- Disable Kerberos/GSSAPI authentication -----
    # Fedora default is YES — explicit NO is critical to prevent accidental
    # Kerberos credential fetching. Not needed on a personal workstation.
    GSSAPIAuthentication no

    # ----- Session behavior -----
    # Fail fast instead of hanging forever
    ConnectTimeout 15

    # ----- Logging -----
    LogLevel INFO
SSH_EOF

chmod 644 /etc/ssh/ssh_config.d/99-noid-hardening.conf
chown root:root /etc/ssh/ssh_config.d/99-noid-hardening.conf
echo "  [OK] /etc/ssh/ssh_config.d/99-noid-hardening.conf"

# ----------------------------------------------------------------------------
# Step 1b: SSH server hardening drop-in (always-deploy, secure-by-default)
# ----------------------------------------------------------------------------
# Deployed unconditionally at build time so a later user-initiated
# openssh-server install is hardened automatically (no manual template
# copy). Harmless while sshd is absent. The 01- prefix loads before
# Fedora's 50-redhat.conf — FIRST-OCCURRENCE-WINS (verified on a VM:
# 50-redhat.conf X11Forwarding=yes won until the 01- prefix was
# established). No AllowUsers here by design — see header.

echo ""
echo "[Step 1b] SSH server hardening drop-in (always-deploy, secure-by-default)"

install -d -m 0700 -o root -g root /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/01-noid-hardening.conf <<'SSHD_HARDEN_DEFAULT_EOF'
# NoID Privacy — SSH server hardening (always deployed)
# Source-of-truth: /usr/share/doc/noid-privacy/ssh-server-opt-in/99-noid-sshd-
# hardening.conf (with AllowUsers placeholder removed for secure-default).
#
# 01- prefix: loads BEFORE Fedora's 50-redhat.conf — first-occurrence-wins
# for conflicting directives. Harmless when sshd is masked.

# Authentication
PasswordAuthentication no
PermitRootLogin no
PermitEmptyPasswords no
PubkeyAuthentication yes
KbdInteractiveAuthentication no
AuthenticationMethods publickey
StrictModes yes
HostbasedAuthentication no
IgnoreRhosts yes
PermitUserEnvironment no

# Forwarding (locked down)
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
AllowStreamLocalForwarding no
GatewayPorts no
PermitTunnel no
DisableForwarding yes
PermitUserRC no
# OpenSSH compression starts only after successful authentication. Keep it
# disabled so allowed sessions do not share a compression context across
# trusted and attacker-influenced content; no obsolete pre-auth claim applies.
Compression no

# Crypto policy must live in this 01- file. Fedora's 40-redhat-crypto-
# policies.conf includes its backend before later drop-ins, and sshd keeps the
# first global value. A 99- opt-in file therefore cannot tighten these values.
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
RequiredRSASize 3072
GSSAPIAuthentication no
KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256@libssh.org,curve25519-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
HostKeyAlgorithms ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,ssh-ed25519,rsa-sha2-512
PubkeyAcceptedAlgorithms ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,ssh-ed25519,sk-ssh-ed25519@openssh.com,rsa-sha2-512
PubkeyAuthOptions touch-required

# Connection limits (anti-bruteforce)
# LoginGraceTime tightened 30→20 to match opt-in template.
# Pubkey-only auth completes sub-second on local LAN; 20s is ample headroom.
MaxAuthTries 3
MaxSessions 2
LoginGraceTime 20
MaxStartups 10:30:60
PerSourceMaxStartups 10
# Group IPv4 scanners by /24 and IPv6 source rotation within one subscriber
# LAN by /64. /32 would merge unrelated customers across an ISP allocation.
PerSourceNetBlockSize 24:64
UseDNS no

# Logging
LogLevel VERBOSE
SSHD_HARDEN_DEFAULT_EOF

chmod 600 /etc/ssh/sshd_config.d/01-noid-hardening.conf
chown root:root /etc/ssh/sshd_config.d/01-noid-hardening.conf
echo "  [OK] /etc/ssh/sshd_config.d/01-noid-hardening.conf"

# ----------------------------------------------------------------------------
# Step 2: SSH server opt-in template
# ----------------------------------------------------------------------------
# Ships the ready-to-deploy sshd hardening template + walkthrough doc for
# users who explicitly opt in to an SSH server. Activates NOTHING —
# openssh-server stays removed, sshd-unix-local.socket stays masked (M08).
# The full user-flow lives in the deployed ssh-server-opt-in.md below;
# per-directive rationale is inline in the template heredoc.

echo ""
echo "[Step 2] SSH server opt-in template (for user-initiated sshd setup)"

install -d -m 0755 -o root -g root \
    /usr/share/doc/noid-privacy \
    /usr/share/doc/noid-privacy/ssh-server-opt-in

cat > /usr/share/doc/noid-privacy/ssh-server-opt-in/99-noid-sshd-hardening.conf <<'SSHD_TEMPLATE_EOF'
# ============================================================================
# NoID Privacy — sshd hardening (opt-in template)
# ============================================================================
# COPY to /etc/ssh/sshd_config.d/ AFTER installing openssh-server.
# CUSTOMIZE the AllowUsers line with YOUR username.
#
# Primary mechanism references used for this policy:
#   - OpenSSH sshd_config(5), ssh_config(5) and 10.x release notes
#   - Fedora 44 openssh-server package configuration and SELinux policy
#   - NIST FIPS 203 for ML-KEM
#
# References:
#   https://man.openbsd.org/sshd_config
#   https://man.openbsd.org/ssh_config
#   https://www.openssh.com/releasenotes.html
#   https://csrc.nist.gov/pubs/fips/203/final
# ============================================================================

# ----- Authentication -----
# PermitRootLogin no: even with pub key, root login is forbidden. Audit trail
# requires a real named user, then sudo.
PermitRootLogin no

# PasswordAuthentication no: disables password brute-force against sshd;
# private-key theft and vulnerabilities in other accepted components remain.
PasswordAuthentication no

# KbdInteractiveAuthentication no: OpenSSH 9.x+ new name, replaces deprecated
# ChallengeResponseAuthentication. Disables PAM password prompts too.
KbdInteractiveAuthentication no

# PubkeyAuthentication + AuthenticationMethods publickey: only pubkey, no fallback.
PubkeyAuthentication yes
AuthenticationMethods publickey

# PermitEmptyPasswords no: defense-in-depth.
PermitEmptyPasswords no
# StrictModes yes: reject unsafe ownership or modes on the user's key files.
StrictModes yes

# MaxAuthTries 3: max 3 auth attempts per connection (reduces log noise).
MaxAuthTries 3

# LoginGraceTime 20: 20 seconds to complete auth, then disconnect.
LoginGraceTime 20

# ----- User restrictions (MUST CUSTOMIZE) -----
# Replace CHANGEME_USERNAME with your actual login username.
# Multiple users: 'AllowUsers user1 user2'
AllowUsers CHANGEME_USERNAME

# ----- Session limits -----
# ClientAliveInterval 300 + CountMax 2: dead connections closed after ~10min idle.
ClientAliveInterval 300
ClientAliveCountMax 2

# MaxSessions 2: max 2 concurrent sessions from one authenticated connection.
# tightened 5→2 to match always-deploy 01-noid-hardening.conf
# (which loads first → wins regardless). 2 is ample for personal workstation
# (1 command + 1 tmux/screen typical).
MaxSessions 2

# MaxStartups 10:30:60: start dropping connections at 10 unauth, 30% chance,
# full drop at 60. Prevents pre-auth DoS.
MaxStartups 10:30:60

# ----- Forwarding (all off, defense in depth) -----
# X11Forwarding no: no X11 (Wayland default anyway).
X11Forwarding no
# AllowTcpForwarding no: no SSH-as-SOCKS tunnel.
AllowTcpForwarding no
# AllowStreamLocalForwarding no: no Unix-domain-socket forwarding.
AllowStreamLocalForwarding no
# AllowAgentForwarding no: no ssh-agent forwarding (prevents agent hijacking).
AllowAgentForwarding no
# PermitTunnel no: no TUN/TAP device forwarding.
PermitTunnel no
# GatewayPorts no: forwarded ports never bind external interfaces.
GatewayPorts no

# ----- Misc hardening -----
HostbasedAuthentication no
IgnoreRhosts yes
# UseDNS no: no reverse DNS lookups (performance + no DNS leak of client IPs).
UseDNS no
# GSSAPIAuthentication no: no Kerberos.
GSSAPIAuthentication no
# PermitUserEnvironment no: ~/.ssh/environment can't override $PATH etc.
PermitUserEnvironment no
# PermitUserRC no: prevent ~/.ssh/rc auto-execution on login.
# Without this, a compromised user account can persist via backdoored rc file.
PermitUserRC no
# DisableForwarding yes: OpenSSH's aggregate switch for the no-forwarding
# invariant. The individual directives remain explicit so `sshd -T` and an
# administrator can identify each denied forwarding surface.
DisableForwarding yes
# Compression is enabled only after successful authentication in current
# OpenSSH. Compression across trusted and attacker-influenced content can leak
# session information; disabling it keeps one closed policy for shell and
# subsystem traffic even though this template also denies forwarding.
Compression no

# ----- Per-source rate limiting (anti-scan/botnet) -----
# PerSourceMaxStartups 10: max 10 concurrent pre-auth connections from one IP.
# PerSourceNetBlockSize 24:64: rate-limit per /24 IPv4 and /64 IPv6. The /64
# groups address rotation within one ordinary IPv6 LAN without penalizing an
# ISP-scale /32 population.
PerSourceMaxStartups 10
PerSourceNetBlockSize 24:64

# ----- Deliberately narrow host-key selection -----
# Ed25519 is primary; RSA-SHA2 remains the compatibility fallback and is
# constrained to RSA-3072+ below. NoID Privacy does not claim ECDSA/P-256 is
# compromised. Fedora 44's native sshd-keygen.target still creates RSA, ECDSA
# and Ed25519 host-key files when sshd starts. These HostKey directives govern
# what sshd loads and offers, so the generated ECDSA file may exist unused.
# NoID Privacy does not mask a native keygen unit because non-generation is not a
# security requirement of this narrower negotiation policy.
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

# ----- Logging -----
# VERBOSE: logs user's key fingerprint on login — audit trail of which key.
LogLevel VERBOSE
# AUTHPRIV matches Fedora's 50-redhat.conf, which loads before this 99- file
# and wins under first-occurrence — a differing value here would be inert.
SyslogFacility AUTHPRIV

# ----- RSA key size enforcement (closed policy) -----
# Minimum 3072-bit for user and host RSA authentication keys.
# Ed25519 is preferred (256-bit, equivalent to RSA-3072 strength).
RequiredRSASize 3072

# ----- Crypto strict (post-quantum hybrid) -----
# Matches client drop-in (/etc/ssh/ssh_config.d/99-noid-hardening.conf).
#
# KexAlgorithms: post-quantum hybrid KEX for harvest-now-decrypt-later protection.
#   mlkem768x25519-sha256        = ML-KEM-768 (NIST FIPS 203) + X25519, OpenSSH 10.0+ default
#   sntrup761x25519-sha512       = Streamlined NTRU Prime + X25519, OpenSSH 9.0+ default
#   curve25519-sha256@libssh.org = classical fallback for older clients
KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256@libssh.org,curve25519-sha256

# Ciphers: AEAD (Authenticated Encryption with Associated Data) only.
#   chacha20-poly1305 = software-friendly where accelerated AES is unavailable
#   aes256-gcm        = commonly hardware-accelerated on supported x86 systems
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com

# MACs: encrypt-then-MAC (etm) only. AEAD ciphers make these mostly unused,
# but set explicitly for non-AEAD compatibility.
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

# HostKeyAlgorithms: certificate forms precede raw keys. Within each trust form
# Ed25519 precedes RSA, and RSA uses SHA2-512 only (no SHA1 ssh-rsa).
HostKeyAlgorithms ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,ssh-ed25519,rsa-sha2-512

# PubkeyAcceptedAlgorithms: software/FIDO2 Ed25519 plus RSA-SHA2 fallback.
PubkeyAcceptedAlgorithms ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,ssh-ed25519,sk-ssh-ed25519@openssh.com,rsa-sha2-512
# Require physical user presence for every FIDO signature, even if an
# authorized_keys entry attempts the no-touch-required relaxation.
PubkeyAuthOptions touch-required

# ----- Optional: custom port (uncomment + customize) -----
# Changing the port is security-through-obscurity — only marginal benefit
# against automated botnets. Firewalld/nftables filtering is the real defense.
# If you DO change the port, update firewall-cmd accordingly.
# Port 22

# ----- Optional: banner (uncomment + create /etc/issue.net) -----
# Legal banner shown BEFORE authentication. Useful for legal warnings in
# jurisdictions that require explicit unauthorized-access notice.
# Banner /etc/issue.net
SSHD_TEMPLATE_EOF

chmod 644 /usr/share/doc/noid-privacy/ssh-server-opt-in/99-noid-sshd-hardening.conf
chown root:root /usr/share/doc/noid-privacy/ssh-server-opt-in/99-noid-sshd-hardening.conf
echo "  [OK] sshd hardening template installed"

cat > /usr/share/doc/noid-privacy/ssh-server-opt-in.md <<'SSH_DOC_EOF'
# NoID Privacy — SSH Server Opt-In Guide

The NoID Privacy image ships **without an SSH server** by design
(Silent-Machine target). Only the hardened client is present.

Removing the firewalld `ssh` service closes **incoming** connections to this
workstation; it does not block destination TCP/22 for `ssh`, `scp`, `sftp` or
Git-over-SSH clients. A public server remains reachable through the active WAN
route. Once WAN-strict has entered strict VPN mode, that ordinary client
connection must traverse the VPN tunnel; a direct physical-WAN bypass is
blocked for every protocol, not only SSH.

The setup is deliberately two-phase: prepare and test a temporary exposure,
then commit it. Keep an authenticated local console open throughout. Do not
enable password authentication as a bootstrap path. The first public key must
exist before `sshd` starts.

This release qualifies physical-LAN SSH over IPv4 only. Replace every example
placeholder (`YOURNAME`, addresses, interface and zone) with the actual value;
do not paste the examples unchanged.

## 1. Prepare and authenticate the first key on the client

Generate a software Ed25519 key or a FIDO key on the **client**, before the
server package is installed or started:

```bash
# Choose exactly one enrollment command.
ssh-keygen -t ed25519 -C "user@client-host"
# Or use a non-resident FIDO handle (the handle file remains required):
ssh-keygen -t ed25519-sk -C "user@client-host"
# Optional resident FIDO handle with per-signature verification, when supported:
ssh-keygen -t ed25519-sk -O resident -O verify-required -C "user@client-host"
ssh-keygen -l -f ~/.ssh/id_ed25519.pub
# For either FIDO command, inspect its own handle:
ssh-keygen -l -f ~/.ssh/id_ed25519_sk.pub
```

Transfer the single `.pub` file to the server through physical media or a
separately authenticated channel and install it as
`/root/noid-ssh-client.pub`. Compare its `ssh-keygen -l -f` fingerprint with
the value observed on the client. `ssh-copy-id` cannot bootstrap this flow:
it requires an authentication path that does not exist yet.

## 2. Validate the user and key locally

Run these checks on the server's local console. A wrong user, missing file,
symlink, multiple keys or a key type outside this policy is fatal.
Start one dedicated nested Bash and execute the remaining server-side blocks
in that same shell. Its fail-fast options stop the transaction without closing
the parent console shell:

```bash
bash
set -euo pipefail
SSH_USER=YOURNAME
KEY_FILE=/root/noid-ssh-client.pub
case "$SSH_USER" in
  ''|[.-]*|*[!A-Za-z0-9_.-]*) echo 'unsafe SSH username'; false ;;
esac
PASSWD_RECORD=$(getent passwd "$SSH_USER")
test "$(printf '%s\n' "$PASSWD_RECORD" | awk -F: -v u="$SSH_USER" '$1 == u {n++} END {print n+0}')" -eq 1
SSH_HOME=$(printf '%s\n' "$PASSWD_RECORD" | awk -F: -v u="$SSH_USER" '$1 == u {print $6}')
SSH_UID=$(id -u "$SSH_USER")
SSH_GID=$(id -g "$SSH_USER")
test "$SSH_UID" -ne 0
case "$SSH_HOME" in /*) ;; *) echo 'home is not absolute'; false ;; esac
test "$SSH_HOME" != / && sudo test -d "$SSH_HOME" && sudo test ! -L "$SSH_HOME"
test "$(sudo stat -Lc '%u' -- "$SSH_HOME")" -eq "$SSH_UID"
SSH_HOME_PARENT=$(dirname -- "$SSH_HOME")
sudo test -d "$SSH_HOME_PARENT" && sudo test ! -L "$SSH_HOME_PARENT"
test "$(sudo stat -Lc '%u' -- "$SSH_HOME_PARENT")" -eq 0
SSH_HOME_PARENT_MODE=$(sudo stat -Lc '%a' -- "$SSH_HOME_PARENT")
test "$((8#$SSH_HOME_PARENT_MODE & 0022))" -eq 0
sudo test -f "$KEY_FILE" && sudo test ! -L "$KEY_FILE" && sudo test -s "$KEY_FILE"
sudo awk 'NF && $1 !~ /^#/ {n++; t=$1} END {exit !(n == 1 && (t == "ssh-ed25519" || t == "sk-ssh-ed25519@openssh.com"))}' "$KEY_FILE"
sudo ssh-keygen -l -f "$KEY_FILE"
```

## 3. Install the Fedora server package but keep every listener closed

```bash
sudo dnf install openssh-server
sudo systemctl disable --now sshd.service sshd.socket
sudo systemctl mask sshd.socket sshd-unix-local.socket
for SSH_LISTENER in sshd.service sshd.socket sshd-unix-local.socket; do
  if sudo systemctl is-active --quiet "$SSH_LISTENER"; then
    echo "SSH listener unexpectedly active: $SSH_LISTENER"
    false
  fi
done
```

`sshd.service` requires neither socket unit. Keep both activation sockets
masked unless you separately choose and review socket activation.

## 4. Stage `authorized_keys` and the drop-in atomically

Create a protected transaction directory and keep the printed path for the
rollback section. The following commands preserve an existing
`authorized_keys`, reject symlinks and append the reviewed key only once.

```bash
set -o pipefail
sudo test -d /var/lib/noid-privacy && sudo test ! -L /var/lib/noid-privacy
test "$(sudo stat -Lc '%u:%g:%a' -- /var/lib/noid-privacy)" = 0:0:755
TXN=$(sudo mktemp -d /var/lib/noid-privacy/ssh-opt-in.XXXXXX)
sudo chmod 0700 "$TXN"
printf 'Rollback directory: %s\n' "$TXN"
AUTH_DIR="$SSH_HOME/.ssh"
AUTH_KEYS="$AUTH_DIR/authorized_keys"
CONFIG=/etc/ssh/sshd_config.d/99-noid-sshd-hardening.conf

if sudo test -e "$AUTH_DIR" || sudo test -L "$AUTH_DIR"; then
  sudo test -d "$AUTH_DIR" && sudo test ! -L "$AUTH_DIR"
fi
if sudo test -e "$AUTH_KEYS" || sudo test -L "$AUTH_KEYS"; then
  sudo test -f "$AUTH_KEYS" && sudo test ! -L "$AUTH_KEYS"
  sudo -u "$SSH_USER" cat -- "$AUTH_KEYS" \
    | sudo tee "$TXN/authorized_keys.before" >/dev/null
  sudo chmod 0600 "$TXN/authorized_keys.before"
else
  sudo touch "$TXN/authorized_keys.was-absent"
fi
if sudo test -e "$CONFIG" || sudo test -L "$CONFIG"; then
  sudo test -f "$CONFIG" && sudo test ! -L "$CONFIG"
  sudo cp -a -- "$CONFIG" "$TXN/sshd-dropin.before"
else
  sudo touch "$TXN/sshd-dropin.was-absent"
fi

sudo install -d -m 0700 -o "$SSH_UID" -g "$SSH_GID" "$AUTH_DIR"
test "$(sudo stat -Lc '%u:%g:%a' -- "$AUTH_DIR")" = "$SSH_UID:$SSH_GID:700"
AUTH_STAGE_DIR=$(sudo mktemp -d "$SSH_HOME_PARENT/.noid-ssh-opt-in.XXXXXX")
sudo chmod 0700 "$AUTH_STAGE_DIR"
AUTH_TMP="$AUTH_STAGE_DIR/authorized_keys"
sudo install -m 0600 -o root -g root /dev/null "$AUTH_TMP"
if sudo test -f "$TXN/authorized_keys.before"; then
  sudo cp -- "$TXN/authorized_keys.before" "$AUTH_TMP"
fi
KEY_LINE=$(sudo awk 'NF && $1 !~ /^#/ {print; exit}' "$KEY_FILE")
if ! sudo grep -qxF -- "$KEY_LINE" "$AUTH_TMP"; then
  if sudo test -s "$AUTH_TMP" \
     && test "$(sudo tail -c 1 "$AUTH_TMP" | od -An -t x1 | tr -d '[:space:]')" != 0a; then
    printf '\n' | sudo tee -a "$AUTH_TMP" >/dev/null
  fi
  printf '%s\n' "$KEY_LINE" | sudo tee -a "$AUTH_TMP" >/dev/null
fi
sudo chown "$SSH_UID:$SSH_GID" "$AUTH_TMP"
sudo chmod 0600 "$AUTH_TMP"
sudo mv -fT -- "$AUTH_TMP" "$AUTH_KEYS"
sudo rmdir -- "$AUTH_STAGE_DIR"
sudo restorecon -F "$AUTH_DIR" "$AUTH_KEYS"
test "$(sudo stat -Lc '%u:%g:%a' -- "$AUTH_KEYS")" = "$SSH_UID:$SSH_GID:600"

SSH_PORT=22
case "$SSH_PORT" in ''|*[!0-9]*) echo 'invalid port'; exit 1;; esac
test "$SSH_PORT" -ge 1 && test "$SSH_PORT" -le 65535
test "$(sudo stat -Lc '%u:%g:%a' -- /etc/ssh/sshd_config.d)" = 0:0:700
CONFIG_TMP=$(sudo mktemp /etc/ssh/sshd_config.d/.99-noid.XXXXXX)
sudo sed -e "s/CHANGEME_USERNAME/$SSH_USER/" \
         -e "s/^# Port 22$/Port $SSH_PORT/" \
         /usr/share/doc/noid-privacy/ssh-server-opt-in/99-noid-sshd-hardening.conf \
  | sudo tee "$CONFIG_TMP" >/dev/null
sudo chown root:root "$CONFIG_TMP"
sudo chmod 0600 "$CONFIG_TMP"
sudo grep -qxF "AllowUsers $SSH_USER" "$CONFIG_TMP"
sudo grep -qxF "Port $SSH_PORT" "$CONFIG_TMP"
sudo mv -fT -- "$CONFIG_TMP" "$CONFIG"
sudo restorecon -F "$CONFIG"
test "$(sudo stat -Lc '%u:%g:%a' -- "$CONFIG")" = 0:0:600
```

Do not remove `$TXN` until the external login and recovery path have both been
tested.

## 5. Optional custom port: establish the SELinux label before start

Port changes do not provide meaningful authentication security. If you still
choose a port other than 22, install the Fedora policy tool and add a native
SELinux port mapping before starting sshd:

```bash
if [ "$SSH_PORT" -ne 22 ]; then
  sudo dnf install policycoreutils-python-utils
  if ! sudo semanage port -a -t ssh_port_t -p tcp "$SSH_PORT"; then
    echo 'SELinux port mapping was not added; stop and review the port'
    false
  fi
  if ! sudo touch "$TXN/selinux-port-added"; then
    sudo semanage port -d -p tcp "$SSH_PORT" || \
      echo 'CRITICAL: remove the newly added SSH SELinux port mapping manually'
    false
  fi
fi
```

If `semanage -a` says the port already has another type, stop and choose a
different port; do not use `-m` to steal an unrelated service's label. The
rollback may delete this mapping only when the transaction marker proves this
setup added it.

## 6. Validate the complete effective server policy

```bash
CLIENT_IP=192.168.1.50
sudo sshd -T -C "user=$SSH_USER,host=localhost,addr=$CLIENT_IP" \
  | grep -E '^(port|permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|authenticationmethods|allowusers|kexalgorithms|ciphers|compression) '
```

Confirm the exact user, port, `passwordauthentication no`,
`kbdinteractiveauthentication no`, `pubkeyauthentication yes` and
`authenticationmethods publickey` before continuing.

## 7. Open one bounded IPv4 test path

`noid-lan-allow` is the single writer for this LAN exposure. It binds the
client's exact IPv4/ARP/interface identity across the XDP/TC, nftables and
firewalld layers, then opens only inbound TCP to the selected SSH port.
Correlated replies remain possible without granting unrelated host-initiated
traffic to the client. This inbound service is the
explicit privacy trade-off for remote administration. Do not use the global
`on` switch or add a separate firewalld rule.

Choose the actual physical interface and exact client IPv4 address. Inspect
`sudo noid-lan-allow --list` first. If any exception for this address already
exists, stop and review it instead of replacing state that this transaction
does not own. Otherwise:

```bash
SERVER_IF=enp1s0
sudo firewall-cmd --get-active-zones
test "$(sudo firewall-cmd --get-zone-of-interface="$SERVER_IF")" = drop
sudo noid-lan-allow --list
sudo touch "$TXN/noid-lan-grant-added"
sudo noid-lan-allow --add "$CLIENT_IP" --direction inbound \
  --protocol tcp --ports "$SSH_PORT" --temp 30
```

The source-, protocol- and port-specific grant expires automatically. It is not
yet permanent. The transaction marker is deliberately written first, so a
partial or failed policy publication is still reconciled by the rollback.

## 8. Start without enabling, then test from a second client session

```bash
sudo systemctl start sshd.service
sudo systemctl is-active --quiet sshd.service
sudo sshd -t
sudo ssh-keygen -l -f /etc/ssh/ssh_host_ed25519_key.pub
```

From a second client terminal, verify the displayed server fingerprint through
the local console or another authenticated channel, then test the exact key:

```bash
SSH_USER=YOURNAME
SSH_PORT=22
ssh -o IdentitiesOnly=yes -i ~/.ssh/id_ed25519 \
  -p "$SSH_PORT" "${SSH_USER}@192.168.1.10"
```

The assignments make the second client terminal's independent variables
explicit. Use the FIDO private-key handle when applicable. Keep the
local console and the first successful SSH session open while testing a second
login and `sudo`. A displayed but unauthenticated fingerprint is not proof.

## 9. Commit only after the external test succeeds

```bash
if sudo test -e "$TXN/noid-lan-grant-added"; then
  sudo noid-lan-allow --add "$CLIENT_IP" --direction inbound \
    --protocol tcp --ports "$SSH_PORT"
fi
sudo systemctl enable sshd.service
sudo systemctl is-enabled --quiet sshd.service
```

Retain the protected transaction backup until a reboot and recovery test have
succeeded. Enabling the service is an explicit availability/privacy choice;
omit it if SSH should exist only for the current boot.

## Roll back or recover from a failed test

Use the still-open local console. This path never turns passwords on. The
block assumes the dedicated nested shell and its variables are still present.
If that shell exited on a failed precondition, start a new nested Bash, rerun
the validation block from step 2, then set `SSH_PORT`, `CLIENT_IP` and `TXN`
to the exact values used above and recreate `AUTH_DIR`, `AUTH_KEYS` and
`CONFIG` from step 4 before continuing:

```bash
sudo systemctl disable --now sshd.service sshd.socket
if sudo test -e "$TXN/noid-lan-grant-added"; then
  sudo noid-lan-allow --revert "$CLIENT_IP"
fi
if sudo test -e "$TXN/authorized_keys.was-absent"; then
  sudo rm -f -- "$AUTH_KEYS"
else
  AUTH_RESTORE_DIR=$(sudo mktemp -d "$SSH_HOME_PARENT/.noid-ssh-restore.XXXXXX")
  sudo chmod 0700 "$AUTH_RESTORE_DIR"
  AUTH_RESTORE="$AUTH_RESTORE_DIR/authorized_keys"
  sudo install -m 0600 -o root -g root \
    "$TXN/authorized_keys.before" "$AUTH_RESTORE"
  sudo chown "$SSH_UID:$SSH_GID" "$AUTH_RESTORE"
  sudo mv -fT -- "$AUTH_RESTORE" "$AUTH_KEYS"
  sudo rmdir -- "$AUTH_RESTORE_DIR"
  sudo restorecon -F "$AUTH_KEYS"
fi
if sudo test -e "$TXN/sshd-dropin.was-absent"; then
  sudo rm -f -- "$CONFIG"
else
  CONFIG_RESTORE=$(sudo mktemp /etc/ssh/sshd_config.d/.99-noid-restore.XXXXXX)
  sudo cp -- "$TXN/sshd-dropin.before" "$CONFIG_RESTORE"
  sudo chown root:root "$CONFIG_RESTORE"
  sudo chmod 0600 "$CONFIG_RESTORE"
  sudo mv -fT -- "$CONFIG_RESTORE" "$CONFIG"
  sudo restorecon -F "$CONFIG"
fi
if sudo test -e "$TXN/selinux-port-added"; then
  sudo semanage port -d -p tcp "$SSH_PORT"
fi
sudo systemctl mask sshd.socket sshd-unix-local.socket
```

If an authenticator or key is lost later, use local console recovery to install
a separately protected recovery key or the second enrolled authenticator,
remove/revoke the lost key, run `sshd -t`, and test again. Do not temporarily
enable password or keyboard-interactive authentication.

## Security notes

- **WAN exposure is outside this workflow**: this guide creates only one exact
  physical-LAN IPv4 grant. Fail2Ban is neither firewall authorization nor a
  substitute for that source/port boundary; review any Internet exposure as a
  separate change and disclose its traffic and attack-surface cost.
- **Key lifecycle**: revoke or replace a key on suspected disclosure, loss,
  authorization change or algorithm/policy deprecation. Calendar-only rotation
  of an otherwise protected Ed25519 key is not claimed as a security control.
  Test the recovery key or second authenticator before retiring the old one.
- **Consider FIDO2 keys** (YubiKey, SoloKey): `ssh-keygen -t ed25519-sk`
  generates a non-resident key handle backed by the authenticator. Both the
  client and opt-in server whitelist the plain and certificate Ed25519-SK
  signature forms. The server sets `PubkeyAuthOptions touch-required`, so an
  `authorized_keys` no-touch relaxation cannot bypass physical presence.
  `ssh-keygen -t ed25519-sk -O resident` stores the handle on the authenticator
  and typically requires a configured PIN at enrollment. Because a resident
  handle increases stolen-token usability, add `-O verify-required` when the
  token supports per-signature user verification.
  Enroll two authenticators or retain a separately protected recovery Ed25519
  key before relying on FIDO; remove the lost key from `authorized_keys` (or
  revoke its certificate/KRL entry) immediately. `ssh-add` may load either
  handle, but agent forwarding remains disabled by this template.
- **Package lifecycle**: rollback closes every listener but deliberately does
  not remove the Fedora package. Remove it later only if that is your explicit
  choice and after reviewing package-manager consequences.

---

**Primary sources for hardening choices** (see inline comments in the template):
- OpenSSH `sshd_config(5)`: <https://man.openbsd.org/sshd_config>
- OpenSSH `ssh_config(5)`: <https://man.openbsd.org/ssh_config>
- OpenSSH release notes: <https://www.openssh.com/releasenotes.html>
- NIST FIPS 203 (ML-KEM): <https://csrc.nist.gov/pubs/fips/203/final>
SSH_DOC_EOF

chmod 644 /usr/share/doc/noid-privacy/ssh-server-opt-in.md
chown root:root /usr/share/doc/noid-privacy/ssh-server-opt-in.md
echo "  [OK] sshd opt-in user guide installed"

# ----------------------------------------------------------------------------
# Step 2b: SSH client hardening user documentation
# ----------------------------------------------------------------------------
# HashKnownHosts is enabled in /etc/ssh/ssh_config.d/99-noid-hardening.conf
# (Step 1, line `HashKnownHosts yes`). New SSH connections HASH the
# server-fingerprint before storing in ~/.ssh/known_hosts → if known_hosts
# leaks, attacker cannot enumerate which servers the user has visited.
#
# BUT existing ~/.ssh/known_hosts entries (pre-NoID Privacy) are stored in plain
# `hostname,IP key` format. They remain plaintext until migrated.
# This doc explains the one-liner + caveats.

cat > /usr/share/doc/noid-privacy/ssh-client-hardening.md <<'SSH_CLIENT_DOC_EOF'
# NoID Privacy — SSH Client Hardening Guide

The NoID Privacy image ships an SSH client hardening drop-in at
`/etc/ssh/ssh_config.d/99-noid-hardening.conf` that applies to every
outgoing SSH connection (`ssh`, `scp`, `sftp`).

The default inbound firewall closure is independent of client egress: removing
the firewalld `ssh` service does not ban outbound destination TCP/22. Public
SSH servers remain reachable through the active WAN/VPN route. LAN targets
remain covered by the default LAN isolation unless their exact IP is enabled
through NoID Privacy Network.

Key client-side hardenings:
- **PQ-hybrid KEX**: ML-KEM-768 + X25519 (post-quantum harvest-now-decrypt-later
  protection)
- **AEAD only**: chacha20-poly1305 + aes256-gcm
- **Closed signature policy**: Ed25519 plus RSA-SHA2 fallback; ECDSA is not
  enabled by this deliberately narrow policy, but NoID Privacy does not claim it is
  compromised
- **HashKnownHosts yes**: ~/.ssh/known_hosts entries hashed (privacy)
- **VisualHostKey yes**: displays fingerprint RandomArt for comparison; it is
  not authentication by itself
- **CheckHostIP yes**: reports a host-key/IP association change for review; a
  mismatch can be legitimate rotation or an attack
- **VerifyHostKeyDNS no**: skips the additional SSHFP lookup and DNS-based
  host-key verification; ordinary hostname A/AAAA resolution still occurs

`VerifyHostKeyDNS no` also gives up a possible DNSSEC-authenticated SSHFP
signal. If a server publishes reviewed SSHFP records in a validated DNSSEC
path, opt in for that host with `VerifyHostKeyDNS ask`; OpenSSH will display
the match while `StrictHostKeyChecking` still governs acceptance.

---

## Migrating existing `~/.ssh/known_hosts` to hashed format

If you came from a previous Linux install and copied your
`~/.ssh/known_hosts` over, your existing entries are still in plaintext
`hostname,IP key` format. Hash them in-place:

```bash
ssh-keygen -H -f ~/.ssh/known_hosts
```

This rewrites `known_hosts` so all entries are HMAC-SHA1-hashed. The
original is backed up to `~/.ssh/known_hosts.old` automatically.

After comparing the rewritten file and confirming the backup is no longer
needed, unlink the backup:

```bash
rm -f -- ~/.ssh/known_hosts.old
```

This removes the directory entry; it is **not** a secure-erasure claim. NoID Privacy's
expected `/home` is Btrfs, and copy-on-write allocation, snapshots, SSD wear
levelling plus local/remote backups can retain older blocks or copies that a
regular-file overwrite cannot reach. Full-disk encryption protects discarded
blocks while the encrypted medium remains locked, but snapshot/backup
retention and eventual device disposal are separate trust decisions. Review
and expire those copies through their own supported workflows.

---

## Why HashKnownHosts matters

Without hashing:
```
github.com,140.82.114.3 ssh-ed25519 AAAA...
gitlab.com,172.65.251.78 ssh-ed25519 AAAA...
my-private-server.example.com,1.2.3.4 ssh-ed25519 AAAA...
```

If an attacker exfiltrates a plaintext `~/.ssh/known_hosts`, it can reveal SSH
destinations and aid subsequent targeting. Private-key compromise remains a
separate and more serious boundary.

With `HashKnownHosts yes`:
```
|1|abc...XYZ=|def...ABC= ssh-ed25519 AAAA...
|1|...|... ssh-ed25519 AAAA...
|1|...|... ssh-ed25519 AAAA...
```

The attacker can only verify a hostname they ALREADY know (offline brute-force),
not enumerate the list. Defense-in-depth alongside SSH key-encryption.

---

## Adding new servers (post-migration)

Just connect normally:

```bash
ssh user@new-server.example.com
```

The first-connect prompt shows the server's fingerprint. Compare it with an
authenticated out-of-band value before typing `yes`; merely displaying a
fingerprint does not authenticate it. NoID Privacy stores an accepted entry
hashed automatically.

The `VisualHostKey yes` setting also displays the ASCII-art fingerprint
representation. It can make a changed pattern more noticeable after a user has
learned or authenticated the expected pattern, but similar-looking RandomArt
is not unambiguous proof and a changed key may also be a legitimate rotation.

---

## Per-host overrides

If you need different settings for a specific host (e.g. legacy server
that doesn't support PQ-hybrid KEX), add a `Host` block in your
`~/.ssh/config` BEFORE NoID Privacy's drop-in:

```
Host legacy-server.example.com
    KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256@libssh.org,curve25519-sha256,diffie-hellman-group14-sha256

Host sshfp-reviewed.example.com
    VerifyHostKeyDNS ask

Host *
    # NoID Privacy drop-in still applies to other hosts
```

---

**Sources**: see inline comments in `/etc/ssh/ssh_config.d/99-noid-hardening.conf`.
SSH_CLIENT_DOC_EOF

chmod 644 /usr/share/doc/noid-privacy/ssh-client-hardening.md
chown root:root /usr/share/doc/noid-privacy/ssh-client-hardening.md
echo "  [OK] ssh-client-hardening.md user guide installed"

# Apply and verify the installed Fedora SELinux file-context contract. These
# files are security policy, so a missing label tool or a mislabeled output is
# fatal instead of being hidden behind a best-effort `|| true`.
for ssh_path in \
    /etc/ssh/ssh_config.d \
    /etc/ssh/ssh_config.d/99-noid-hardening.conf \
    /etc/ssh/sshd_config.d \
    /etc/ssh/sshd_config.d/01-noid-hardening.conf \
    /usr/share/doc/noid-privacy/ssh-server-opt-in \
    /usr/share/doc/noid-privacy/ssh-server-opt-in/99-noid-sshd-hardening.conf \
    /usr/share/doc/noid-privacy/ssh-server-opt-in.md \
    /usr/share/doc/noid-privacy/ssh-client-hardening.md; do
    restorecon -F "$ssh_path"
    matchpathcon -V "$ssh_path"
done

# ----------------------------------------------------------------------------
# Step 3: Verification
# ----------------------------------------------------------------------------

echo ""
echo "[Step 3] Verification"

# 3.1 — openssh-server NOT installed (server-removed mode is default for v1.0+)
if rpm -q openssh-server >/dev/null 2>&1; then
    echo "  [FAIL] openssh-server present — should be excluded via %packages"
    exit 1
else
    echo "  [OK] openssh-server not installed"
fi

# 3.2 — openssh-clients still present
if rpm -q openssh-clients >/dev/null 2>&1; then
    echo "  [OK] openssh-clients present"
else
    echo "  [FAIL] openssh-clients missing (unexpected)"
    exit 1
fi

# 3.3 — ssh client binary works
if command -v ssh >/dev/null 2>&1; then
    ssh_version=$(ssh -V 2>&1)
    echo "  [OK] ssh client: $ssh_version"
else
    echo "  [FAIL] ssh binary not found"
    exit 1
fi

# 3.4 — client drop-in file exists with the RPM-compatible public-client mode
if [ -f /etc/ssh/ssh_config.d/99-noid-hardening.conf ] \
   && [ ! -L /etc/ssh/ssh_config.d/99-noid-hardening.conf ] \
   && [ "$(stat -Lc '%u:%g:%a' /etc/ssh/ssh_config.d)" = 0:0:755 ] \
   && [ "$(stat -Lc '%u:%g:%a' /etc/ssh/ssh_config.d/99-noid-hardening.conf)" = 0:0:644 ]; then
    echo "  [OK] client hardening drop-in present"
else
    echo "  [FAIL] client hardening drop-in missing, symlinked or wrong metadata"
    exit 1
fi

# 3.4b — always-deploy server hardening drop-in exists (Step 1b — the
# security-load-bearing server config that hardens any later sshd opt-in)
if [ -f /etc/ssh/sshd_config.d/01-noid-hardening.conf ] \
   && [ ! -L /etc/ssh/sshd_config.d/01-noid-hardening.conf ] \
   && [ "$(stat -Lc '%u:%g:%a' /etc/ssh/sshd_config.d)" = 0:0:700 ] \
   && [ "$(stat -Lc '%u:%g:%a' /etc/ssh/sshd_config.d/01-noid-hardening.conf)" = 0:0:600 ]; then
    if grep -q '^PasswordAuthentication no' /etc/ssh/sshd_config.d/01-noid-hardening.conf \
       && grep -q '^PermitRootLogin no' /etc/ssh/sshd_config.d/01-noid-hardening.conf \
       && grep -q '^AuthenticationMethods publickey' /etc/ssh/sshd_config.d/01-noid-hardening.conf; then
        echo "  [OK] server hardening drop-in present + core directives set"
    else
        echo "  [FAIL] server hardening drop-in present but missing core directives"
        exit 1
    fi
else
    echo "  [FAIL] server hardening drop-in missing, symlinked or wrong metadata"
    exit 1
fi

# 3.5 — sshd binary absent (no SSH server in default v1.0+ image)
if command -v sshd >/dev/null 2>&1; then
    echo "  [FAIL] sshd binary present in the client-only image"
    exit 1
else
    echo "  [OK] sshd binary absent"
fi

# 3.6 — No sshd host keys (pre-flight, keys are generated on sshd start if installed)
# rc.5: use `find` instead of `ls glob` — `ls` with no-match glob
# returns 2, which combined with `set -euo pipefail` aborts the script silently
# at this assignment (no FAIL echo, just exit 2). `find` returns 0 even with
# no matches and just outputs empty. Robust glob counter pattern.
host_keys=$(find /etc/ssh -maxdepth 1 -name 'ssh_host_*_key' 2>/dev/null | wc -l)
if [ "$host_keys" = "0" ]; then
    echo "  [OK] no SSH host keys (no server to use them)"
else
    echo "  [FAIL] $host_keys private SSH host-key paths present in a client-only image"
    exit 1
fi

# 3.7 — sshd server opt-in template present (Step 2)
TEMPLATE=/usr/share/doc/noid-privacy/ssh-server-opt-in/99-noid-sshd-hardening.conf
if [ -f "$TEMPLATE" ]; then
    # Required content sanity check: load-bearing policy directives
    if grep -q '^KbdInteractiveAuthentication no' "$TEMPLATE" && \
       grep -q '^AuthenticationMethods publickey' "$TEMPLATE" && \
       grep -q 'mlkem768x25519-sha256' "$TEMPLATE" && \
       grep -q '^RequiredRSASize 3072' "$TEMPLATE"; then
        echo "  [OK] sshd opt-in template: KbdInt/AuthMethods/MLKEM/RSA3072"
    else
        echo "  [FAIL] sshd opt-in template missing load-bearing directives"
        exit 1
    fi
    # Aggregate forwarding, rate-limit and host-key policy.
    if grep -q '^PermitUserRC no' "$TEMPLATE" && \
       grep -q '^DisableForwarding yes' "$TEMPLATE" && \
       grep -q '^PerSourceMaxStartups 10' "$TEMPLATE" && \
       grep -q '^PerSourceNetBlockSize 24:64' "$TEMPLATE" && \
       grep -q '^HostKey /etc/ssh/ssh_host_ed25519_key' "$TEMPLATE" && \
       grep -q '^HostKey /etc/ssh/ssh_host_rsa_key' "$TEMPLATE" && \
       ! grep -q '^HostKey /etc/ssh/ssh_host_ecdsa_key' "$TEMPLATE"; then
        echo "  [OK] sshd opt-in template: PermitUserRC/DisableForwarding/PerSource/HostKey-policy"
    else
        echo "  [FAIL] sshd opt-in template missing aggregate policy"
        exit 1
    fi
else
    echo "  [FAIL] sshd opt-in template missing"
    exit 1
fi

# 3.7a — complete early-policy/template parity. OpenSSH uses the first global
# value it reads, so a differing later template line is dead configuration.
# Normalize only insignificant whitespace; duplicate directives such as the
# two HostKey lines remain independently load-bearing.
normalize_sshd_policy() {
    awk '
        /^[[:space:]]*($|#)/ { next }
        { $1=$1; print }
    ' "$1"
}
sshd_policy_drift=$(
    comm -23 \
        <(normalize_sshd_policy /etc/ssh/sshd_config.d/01-noid-hardening.conf | sort) \
        <(normalize_sshd_policy "$TEMPLATE" | sort)
)
if [ -z "$sshd_policy_drift" ]; then
    echo "  [OK] every early server directive is value-identical in the opt-in template"
else
    echo "  [FAIL] opt-in template differs from the first-occurrence server policy:"
    printf '    %s\n' "$sshd_policy_drift"
    exit 1
fi

# 3.7b — client drop-in has VerifyHostKeyDNS no (explicit). Anchored to
# line start: the literal also appears in an explanatory comment in the
# same deployed file, which would mask a deleted directive.
if grep -qE '^[[:space:]]*VerifyHostKeyDNS no' /etc/ssh/ssh_config.d/99-noid-hardening.conf; then
    echo "  [OK] client drop-in: VerifyHostKeyDNS no (explicit, no SSHFP leak)"
else
    echo "  [FAIL] client drop-in missing VerifyHostKeyDNS no"
    exit 1
fi

# 3.7b-sym — client/server crypto symmetry (all 3 v4 gaps fixed)
CLIENT=/etc/ssh/ssh_config.d/99-noid-hardening.conf
if grep -qE '^[[:space:]]*KexAlgorithms .*mlkem768x25519-sha256' "$CLIENT" && \
   grep -q 'RequiredRSASize 3072' "$CLIENT" && \
   grep -q 'GSSAPIAuthentication no' "$CLIENT"; then
    echo "  [OK] client drop-in symmetric to server (MLKEM768/RSA3072/GSSAPI-off)"
else
    echo "  [FAIL] client/server crypto asymmetry — 3 v4 gaps not closed"
    exit 1
fi

# 3.7c — user guide has SELinux port-label + authorized_keys instructions
GUIDE=/usr/share/doc/noid-privacy/ssh-server-opt-in.md
if grep -q 'semanage port' "$GUIDE" && grep -q 'authorized_keys' "$GUIDE"; then
    echo "  [OK] user guide: SELinux port-label + authorized_keys setup documented"
else
    echo "  [FAIL] user guide missing SELinux port-label or authorized_keys instructions"
    exit 1
fi

# 3.8 — sshd opt-in user guide present
if [ -f /usr/share/doc/noid-privacy/ssh-server-opt-in.md ]; then
    echo "  [OK] sshd opt-in user guide present"
else
    echo "  [FAIL] sshd opt-in user guide missing"
    exit 1
fi

echo ""
echo "=============================================================="
echo "[Module 09] Done — SSH client hardened, server removed"
echo "=============================================================="

%end

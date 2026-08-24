#!/bin/bash
# 09-ssh-structural — verify Module 09 SSH client hardening + server opt-in template
#
# Checks:
#   - Client drop-in: PQ hybrid KexAlgorithms (mlkem768x25519-sha256, sntrup761)
#   - Client drop-in: AEAD Ciphers only, Ed25519 preferred
#   - Client drop-in: VerifyHostKeyDNS no, GSSAPIAuthentication no, RequiredRSASize 3072
#   - Server opt-in template: PermitRootLogin no, PasswordAuth no, AuthMethods publickey
#   - Server template: DisableForwarding yes, PermitUserRC no, PerSourceMaxStartups
#   - Server template: narrow Ed25519 + RSA host-key policy without hype
#   - No dead mutation of package-owned moduli; current compression semantics

set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/09-ssh.ks"
PQC_DOC="$PROJECT_ROOT/docs/post-quantum-readiness.md"
THREAT_DOC="$PROJECT_ROOT/docs/threat-model.md"

test_start "09-ssh-structural"

assert_file_exists "$KS_FILE"
assert_file_exists "$PQC_DOC"
assert_file_exists "$THREAT_DOC"
assert_grep_fixed 'keep root-private LAN grants behind the privileged reader' "$KS_FILE" \
    "module status names the verified sshd policy surface"
assert_not_grep 'early sysctl template parity' "$KS_FILE" \
    "SSH module metadata does not mislabel its policy as sysctl"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

extract_heredoc "$KS_FILE" "SSH_EOF"          "$TMPDIR/ssh-client.conf" || _fail "client extraction"
extract_heredoc "$KS_FILE" "SSHD_HARDEN_DEFAULT_EOF" "$TMPDIR/sshd-default.conf" || _fail "sshd default extraction"
extract_heredoc "$KS_FILE" "SSHD_TEMPLATE_EOF" "$TMPDIR/sshd-template.conf" || _fail "sshd template"
extract_heredoc "$KS_FILE" "SSH_DOC_EOF"      "$TMPDIR/ssh-opt-in.md" || _fail "user guide"
extract_heredoc "$KS_FILE" "SSH_CLIENT_DOC_EOF" "$TMPDIR/ssh-client.md" || _fail "client guide"
assert_grep_fixed 'sudo noid-lan-allow --list' "$TMPDIR/ssh-opt-in.md" \
    "SSH opt-in reads root-private LAN exception state through sudo"
assert_not_grep_extended '^[[:space:]]*noid-lan-allow --list$' \
    "$TMPDIR/ssh-opt-in.md" \
    "SSH opt-in never presents the privileged LAN-state read as unprivileged"

# --- Client: PQ hybrid KEX + AEAD + strong RSA + privacy --------------------
assert_grep_fixed 'mlkem768x25519-sha256'       "$TMPDIR/ssh-client.conf"
assert_grep_fixed 'sntrup761x25519-sha512'      "$TMPDIR/ssh-client.conf"
assert_grep_fixed 'chacha20-poly1305@openssh.com' "$TMPDIR/ssh-client.conf"
assert_grep_fixed 'aes256-gcm@openssh.com'      "$TMPDIR/ssh-client.conf"
assert_grep_extended '^    RequiredRSASize 3072$'    "$TMPDIR/ssh-client.conf"
assert_grep_extended '^    VerifyHostKeyDNS no$'     "$TMPDIR/ssh-client.conf"
assert_grep_extended '^    GSSAPIAuthentication no$' "$TMPDIR/ssh-client.conf"
assert_grep_extended '^    HashKnownHosts yes$'      "$TMPDIR/ssh-client.conf"
assert_grep_fixed 'sk-ssh-ed25519@openssh.com'        "$TMPDIR/ssh-client.conf" \
    "client accepts the recommended Ed25519 FIDO signature"
assert_grep_fixed 'sk-ssh-ed25519-cert-v01@openssh.com' "$TMPDIR/ssh-client.conf" \
    "client accepts the Ed25519 FIDO certificate signature"
assert_grep_extended '^    HostKeyAlgorithms ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,ssh-ed25519,rsa-sha2-512$' \
    "$TMPDIR/ssh-client.conf" \
    "reviewed host certificates precede the corresponding raw host keys"

# --- Server template: strong auth policy ------------------------------------
assert_grep_extended '^PermitRootLogin no$'          "$TMPDIR/sshd-template.conf"
assert_grep_extended '^PasswordAuthentication no$'   "$TMPDIR/sshd-template.conf"
assert_grep_extended '^KbdInteractiveAuthentication no$' "$TMPDIR/sshd-template.conf"
assert_grep_extended '^AuthenticationMethods publickey$' "$TMPDIR/sshd-template.conf"
assert_grep_extended '^PermitEmptyPasswords no$'     "$TMPDIR/sshd-template.conf"
assert_grep_extended '^DisableForwarding yes$'       "$TMPDIR/sshd-template.conf"
assert_grep_extended '^PermitUserRC no$'             "$TMPDIR/sshd-template.conf"
assert_grep_extended '^PerSourceMaxStartups 10$'     "$TMPDIR/sshd-template.conf"
assert_grep_extended '^PerSourceNetBlockSize 24:64$' "$TMPDIR/sshd-template.conf"
assert_grep_extended '^RequiredRSASize 3072$'        "$TMPDIR/sshd-template.conf"
assert_grep_extended '^Compression no$'              "$TMPDIR/sshd-template.conf"
assert_grep_extended '^StrictModes yes$'              "$TMPDIR/sshd-template.conf"
assert_grep_extended '^HostbasedAuthentication no$'   "$TMPDIR/sshd-template.conf"
assert_grep_extended '^AllowStreamLocalForwarding no$' "$TMPDIR/sshd-template.conf"
assert_not_grep 'brute-force impossible'             "$TMPDIR/sshd-template.conf" \
    "SSH rationale does not overclaim private-key/auth-stack security"
assert_grep_fixed 'sk-ssh-ed25519@openssh.com' "$TMPDIR/sshd-template.conf" \
    "opt-in server accepts the recommended Ed25519 FIDO signature"
assert_grep_fixed 'sk-ssh-ed25519-cert-v01@openssh.com' "$TMPDIR/sshd-template.conf" \
    "opt-in server accepts the Ed25519 FIDO certificate signature"
assert_grep_extended '^PubkeyAuthOptions touch-required$' \
    "$TMPDIR/sshd-template.conf" \
    "opt-in server cannot accept an authorized_keys no-touch relaxation"
for config in "$TMPDIR/sshd-default.conf" "$TMPDIR/sshd-template.conf"; do
    assert_not_grep_extended '^ChallengeResponseAuthentication([[:space:]]|$)' \
        "$config" \
        "server policy uses KbdInteractiveAuthentication instead of its deprecated alias"
done

# --- Server template: narrow host-key policy, honest Fedora lifecycle -------
assert_grep_fixed 'HostKey /etc/ssh/ssh_host_ed25519_key' "$TMPDIR/sshd-template.conf"
assert_grep_fixed 'HostKey /etc/ssh/ssh_host_rsa_key'     "$TMPDIR/sshd-template.conf"
assert_not_grep 'HostKey /etc/ssh/ssh_host_ecdsa_key'     "$TMPDIR/sshd-template.conf"
assert_grep_fixed 'NoID Privacy does not claim ECDSA/P-256 is' "$TMPDIR/sshd-template.conf" \
    "template does not infer an ECDSA backdoor from unrelated history"
assert_grep_fixed 'sshd-keygen.target still creates RSA, ECDSA' \
    "$TMPDIR/sshd-template.conf" \
    "template states Fedora's actual host-key generation lifecycle"
assert_not_grep_extended 'Dual_EC_DRBG|NIST-curve trust|no NIST P-256|ECDSA.*backdoor' \
    "$KS_FILE" "M09 contains no unsupported ECDSA/backdoor rationale"

# The closed KEX policy cannot negotiate finite-field DH group exchange, so
# editing the RPM-owned parameter file would be dead package drift.
assert_not_grep_extended '/etc/ssh/moduli|MODULI_BEFORE|MODULI_AFTER' "$KS_FILE" \
    "M09 leaves the RPM-owned moduli file byte-identical"
for config in "$TMPDIR/ssh-client.conf" "$TMPDIR/sshd-default.conf" \
              "$TMPDIR/sshd-template.conf"; do
    assert_not_grep 'diffie-hellman-group-exchange' "$config" \
        "closed KEX policy does not negotiate DH group exchange"
done
assert_grep_fixed 'enabled only after successful authentication' \
    "$TMPDIR/sshd-template.conf" \
    "compression rationale matches current OpenSSH semantics"
assert_not_grep_extended 'CVE-2008-5161|enabled pre-auth' "$KS_FILE" \
    "compression rationale does not reuse an obsolete pre-auth claim"

# Fedora sshd uses first-occurrence-wins. Every value that must beat its
# 40-redhat crypto include or 50-redhat GSSAPI default belongs in 01-, not only
# in the later opt-in template.
for directive in AuthenticationMethods StrictModes HostbasedAuthentication \
                 IgnoreRhosts PermitUserEnvironment AllowStreamLocalForwarding \
                 GatewayPorts MaxStartups UseDNS \
                 GSSAPIAuthentication KexAlgorithms Ciphers MACs \
                 HostKeyAlgorithms PubkeyAcceptedAlgorithms PubkeyAuthOptions \
                 RequiredRSASize Compression; do
    assert_grep_extended "^${directive} " "$TMPDIR/sshd-default.conf" \
        "early server policy owns ${directive}"
done
assert_grep_extended '^GSSAPIAuthentication no$' "$TMPDIR/sshd-default.conf"
assert_grep_extended '^PerSourceNetBlockSize 24:64$' "$TMPDIR/sshd-default.conf"

# Every non-comment directive line in the early 01- policy must be present
# value-identically in the later opt-in template. Preserve duplicate
# directives (the two HostKey lines) as separate policy entries.
normalize_sshd_policy() {
    awk '
        /^[[:space:]]*($|#)/ { next }
        { $1=$1; print }
    ' "$1"
}
mapfile -t early_directives < <(
    normalize_sshd_policy "$TMPDIR/sshd-default.conf" | sort
)
mapfile -t template_directives < <(
    normalize_sshd_policy "$TMPDIR/sshd-template.conf" | sort
)
if comm -23 \
        <(printf '%s\n' "${early_directives[@]}") \
        <(printf '%s\n' "${template_directives[@]}") \
        > "$TMPDIR/sshd-policy-drift" \
        && [ ! -s "$TMPDIR/sshd-policy-drift" ]; then
    _pass "all early sshd policy lines are value-identical in the opt-in template"
else
    _fail "all early sshd policy lines are value-identical in the opt-in template"
fi
assert_eq 36 \
    "$(normalize_sshd_policy "$TMPDIR/sshd-default.conf" | awk '{print $1}' | sort -u | wc -l)" \
    "the complete 36-directive first-occurrence policy is parity-checked"
assert_grep_fixed 'Every directive in the 01- file is' "$KS_FILE" \
    "header describes the complete parity contract"

# Optional exact-package effective-config run. The product deliberately omits
# openssh-server, so ordinary source-only CI has no sshd binary. Release audit
# supplies an extracted Fedora RPM root through NOID_OPENSSH_SERVER_ROOT and
# exercises OpenSSH's real first-occurrence parser against Fedora's real 40-/
# 50- drop-ins plus the NoID Privacy 01- file.
if [ -n "${NOID_OPENSSH_SERVER_ROOT:-}" ]; then
    FEDORA_SSHD="$NOID_OPENSSH_SERVER_ROOT/usr/bin/sshd"
    FEDORA_ETC="$NOID_OPENSSH_SERVER_ROOT/etc/ssh"
    [ -x "$FEDORA_SSHD" ] || _fail "Fedora sshd binary missing in supplied RPM root"
    [ -f "$FEDORA_ETC/sshd_config" ] || _fail "Fedora sshd_config missing in supplied RPM root"
    FEDORA_KEYGEN_TARGET="$NOID_OPENSSH_SERVER_ROOT/usr/lib/systemd/system/sshd-keygen.target"
    [ -f "$FEDORA_KEYGEN_TARGET" ] || _fail "Fedora sshd-keygen.target missing in supplied RPM root"
    for key_type in rsa ecdsa ed25519; do
        assert_grep_extended "^Wants=sshd-keygen@${key_type}[.]service$" \
            "$FEDORA_KEYGEN_TARGET" \
            "signed Fedora RPM generates the documented ${key_type} host key"
    done
    mkdir -p "$TMPDIR/effective.d"
    cp "$FEDORA_ETC/sshd_config" "$TMPDIR/sshd_config"
    cp "$FEDORA_ETC/sshd_config.d/40-redhat-crypto-policies.conf" "$TMPDIR/effective.d/"
    cp "$FEDORA_ETC/sshd_config.d/50-redhat.conf" "$TMPDIR/effective.d/"
    cp "$TMPDIR/sshd-default.conf" "$TMPDIR/effective.d/01-noid-hardening.conf"
    ssh-keygen -q -t ed25519 -N '' -f "$TMPDIR/ssh_host_ed25519_key"
    ssh-keygen -q -t rsa -b 3072 -N '' -f "$TMPDIR/ssh_host_rsa_key"
    sed -i \
        -e "s|/etc/ssh/ssh_host_ed25519_key|$TMPDIR/ssh_host_ed25519_key|" \
        -e "s|/etc/ssh/ssh_host_rsa_key|$TMPDIR/ssh_host_rsa_key|" \
        "$TMPDIR/effective.d/01-noid-hardening.conf"
    sed -i "s|^Include /etc/ssh/sshd_config.d/\*.conf$|Include $TMPDIR/effective.d/*.conf|" \
        "$TMPDIR/sshd_config"
    if ! "$FEDORA_SSHD" -T -f "$TMPDIR/sshd_config" \
            -C user=nobody,host=localhost,addr=192.0.2.10 \
            > "$TMPDIR/sshd-effective.txt"; then
        _fail "Fedora sshd -T effective-config evaluation"
    fi
    assert_grep_extended '^gssapiauthentication no$' "$TMPDIR/sshd-effective.txt"
    assert_grep_extended '^requiredrsasize 3072$' "$TMPDIR/sshd-effective.txt"
    assert_grep_extended '^persourcenetblocksize 24:64$' "$TMPDIR/sshd-effective.txt"
    assert_grep_extended '^ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com$' "$TMPDIR/sshd-effective.txt"
    assert_grep_extended '^macs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com$' "$TMPDIR/sshd-effective.txt"
    assert_grep_extended '^authenticationmethods publickey$' "$TMPDIR/sshd-effective.txt"
    assert_grep_extended '^strictmodes yes$' "$TMPDIR/sshd-effective.txt"
    assert_grep_extended '^hostbasedauthentication no$' "$TMPDIR/sshd-effective.txt"
    assert_grep_extended '^allowstreamlocalforwarding no$' "$TMPDIR/sshd-effective.txt"
    assert_grep_extended '^hostkeyalgorithms ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,ssh-ed25519,rsa-sha2-512$' "$TMPDIR/sshd-effective.txt"
    assert_grep_extended '^pubkeyacceptedalgorithms ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,ssh-ed25519,sk-ssh-ed25519@openssh.com,rsa-sha2-512$' "$TMPDIR/sshd-effective.txt"
    assert_grep_extended '^pubkeyauthoptions touch-required$' "$TMPDIR/sshd-effective.txt"
    assert_grep_extended '^compression no$' "$TMPDIR/sshd-effective.txt" \
        "real Fedora sshd parser retains the compression policy"
fi

if command -v ssh >/dev/null 2>&1; then
    assert_grep_fixed 'sk-ssh-ed25519@openssh.com' \
        <(ssh -Q PubkeyAcceptedAlgorithms) \
        "installed Fedora client binary supports Ed25519 FIDO signatures"
    ssh -G -F "$TMPDIR/ssh-client.conf" example.invalid \
        > "$TMPDIR/ssh-effective.txt" 2>/dev/null
    assert_grep_fixed 'sk-ssh-ed25519@openssh.com' "$TMPDIR/ssh-effective.txt" \
        "real client parser retains Ed25519 FIDO in effective configuration"
    assert_grep_fixed 'sk-ssh-ed25519-cert-v01@openssh.com' \
        "$TMPDIR/ssh-effective.txt" \
        "real client parser retains Ed25519 FIDO certificates"
    assert_grep_extended '^kexalgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256@libssh.org,curve25519-sha256$' \
        "$TMPDIR/ssh-effective.txt" "real client parser retains exact KEX policy"
    assert_grep_extended '^ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com$' \
        "$TMPDIR/ssh-effective.txt" "real client parser retains exact cipher policy"
    assert_grep_extended '^hostkeyalgorithms ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,ssh-ed25519,rsa-sha2-512$' \
        "$TMPDIR/ssh-effective.txt" "real client parser retains exact host-key policy"
fi

# --- Package exclusion: openssh-server removed ------------------------------
assert_grep_extended '^-openssh-server$' "$KS_FILE"
assert_grep_extended '^[[:space:]]+openssh-clients$' \
    "$PROJECT_ROOT/kickstart/snippets/26-package-set.ks" \
    "outbound ssh/scp/sftp client remains in the image"

# The firewalld `ssh` service and master.ks --remove-service setting govern
# new inbound connections to a local sshd; they must never be confused with
# an egress TCP/22 ban. Public-WAN SSH remains ordinary client traffic (or
# traverses the VPN tunnel once WAN-strict has entered strict mode).
assert_not_grep_extended '(<port port="22" protocol="tcp"/>|th dport 22|tcp dport 22).*(<drop/>|[[:space:]]drop([[:space:]]|$))' \
    "$PROJECT_ROOT/kickstart/snippets/03-firewalld.ks" \
    "LAN firewall does not block outbound SSH by destination port"
assert_not_grep_extended '(th dport 22|tcp dport 22).*[[:space:]]drop([[:space:]]|$)' \
    "$PROJECT_ROOT/kickstart/snippets/06-vpn-killswitch.ks" \
    "WAN-strict stays protocol-neutral and has no SSH-specific egress ban"

# --- User guide has critical setup instructions ----------------------------
assert_grep_fixed 'semanage port'        "$TMPDIR/ssh-opt-in.md" "SELinux port-label instruction"
assert_grep_fixed 'authorized_keys'      "$TMPDIR/ssh-opt-in.md" "authorized_keys setup"
assert_not_grep 'systemctl unmask sshd-unix-local.socket' "$TMPDIR/ssh-opt-in.md" \
    "ordinary sshd service setup keeps the extra Unix socket masked"
assert_grep_fixed 'sudo systemctl mask sshd.socket sshd-unix-local.socket' \
    "$TMPDIR/ssh-opt-in.md" \
    "service opt-in keeps both alternative socket-activation paths masked"
assert_not_grep_extended 'ssh-copy-id YOURNAME|PasswordAuthentication yes|KbdInteractiveAuthentication yes' \
    "$TMPDIR/ssh-opt-in.md" \
    "first-key bootstrap never assumes an existing login or enables passwords"
assert_grep_fixed 'does not block destination TCP/22' "$TMPDIR/ssh-opt-in.md" \
    "server guide distinguishes inbound exposure from outbound SSH"
assert_grep_fixed 'ssh-keygen -t ed25519-sk -O resident -O verify-required' \
    "$TMPDIR/ssh-opt-in.md" \
    "resident FIDO enrollment requests per-signature verification when supported"
assert_grep_fixed 'PubkeyAuthOptions touch-required' "$TMPDIR/ssh-opt-in.md" \
    "server guide explains enforced physical presence"
assert_grep_fixed 'Enroll two authenticators' "$TMPDIR/ssh-opt-in.md" \
    "server guide includes lost-authenticator recovery"

# The numbered flow must establish and validate the first key, exact user,
# native network policy and temporary exposure before starting sshd. Enabling
# at boot is the post-login commit, never the bootstrap action.
first_guide_line() {
    grep -nF -- "$1" "$TMPDIR/ssh-opt-in.md" | head -n1 | cut -d: -f1 || true
}
line_key=$(first_guide_line 'sudo mv -fT -- "$AUTH_TMP" "$AUTH_KEYS"')
line_effective=$(first_guide_line 'sudo sshd -T -C')
line_lan_marker=$(first_guide_line 'sudo touch "$TXN/noid-lan-grant-added"')
line_lan=$(first_guide_line '--protocol tcp --ports "$SSH_PORT" --temp 30')
line_start=$(first_guide_line 'sudo systemctl start sshd.service')
line_sanity=$(first_guide_line 'sudo sshd -t')
line_enable=$(first_guide_line 'sudo systemctl enable sshd.service')
for line in line_key line_effective line_lan_marker line_lan line_start line_sanity line_enable; do
    [ -n "${!line}" ] || _fail "SSH opt-in guide missing ordered step: $line"
done
assert_cmd_success "first key/effective policy/managed LAN grant precede start; enable follows test" \
    test "$line_key" -lt "$line_effective" \
         -a "$line_effective" -lt "$line_lan_marker" \
         -a "$line_lan_marker" -lt "$line_lan" \
         -a "$line_lan" -lt "$line_start" \
         -a "$line_start" -lt "$line_sanity" \
         -a "$line_sanity" -lt "$line_enable"
assert_grep_fixed 'getent passwd "$SSH_USER"' "$TMPDIR/ssh-opt-in.md" \
    "guide validates the exact NSS user before mutation"
assert_grep_fixed 'set -euo pipefail' "$TMPDIR/ssh-opt-in.md" \
    "dedicated opt-in shell fails closed on a rejected precondition"
assert_grep_fixed '*[!A-Za-z0-9_.-]*' "$TMPDIR/ssh-opt-in.md" \
    "AllowUsers and sed input reject pattern and replacement metacharacters"
assert_grep_fixed 'SSH_HOME_PARENT_MODE & 0022' "$TMPDIR/ssh-opt-in.md" \
    "atomic sibling staging requires a non-writable root-owned home parent"
assert_grep_fixed 'sudo test -f "$KEY_FILE" && sudo test ! -L "$KEY_FILE"' \
    "$TMPDIR/ssh-opt-in.md" "guide rejects missing/non-regular/symlinked key input"
assert_grep_fixed 'sudo semanage port -a -t ssh_port_t -p tcp "$SSH_PORT"' \
    "$TMPDIR/ssh-opt-in.md" "custom port uses native SELinux labeling"
assert_grep_fixed 'if [ "$SSH_PORT" -ne 22 ]; then' "$TMPDIR/ssh-opt-in.md" \
    "default port 22 does not attempt to duplicate Fedora's SELinux mapping"
assert_grep_fixed 'sudo semanage port -d -p tcp "$SSH_PORT"' \
    "$TMPDIR/ssh-opt-in.md" \
    "failed custom-port marker publication compensates the new SELinux mapping"
assert_grep_fixed 'do not use `-m` to steal an unrelated service' \
    "$TMPDIR/ssh-opt-in.md" "custom-port flow preserves existing SELinux ownership"
assert_grep_fixed '--protocol tcp --ports "$SSH_PORT" --temp 30' \
    "$TMPDIR/ssh-opt-in.md" \
    "temporary SSH access uses the exact managed inbound selector"
assert_grep_fixed '--protocol tcp --ports "$SSH_PORT"' \
    "$TMPDIR/ssh-opt-in.md" \
    "permanent SSH access keeps the exact managed inbound selector"
assert_not_grep '--add-rich-rule=' "$TMPDIR/ssh-opt-in.md" \
    "SSH guide has one LAN policy writer instead of a parallel firewalld rule"
assert_grep_fixed 'explicit privacy trade-off for remote administration' \
    "$TMPDIR/ssh-opt-in.md" "guide discloses the NoID Privacy LAN grant trade-off"
assert_grep_fixed 'ssh-keygen -l -f ~/.ssh/id_ed25519_sk.pub' \
    "$TMPDIR/ssh-opt-in.md" "FIDO fingerprint command uses the FIDO handle"
assert_grep_fixed 'firewall-cmd --get-zone-of-interface="$SERVER_IF"' \
    "$TMPDIR/ssh-opt-in.md" "source rule is bound to the inspected active zone"
assert_grep_fixed 'sudo systemctl disable --now sshd.service' \
    "$TMPDIR/ssh-opt-in.md" "rollback closes the listener first"
assert_grep_fixed 'sudo noid-lan-allow --revert "$CLIENT_IP"' \
    "$TMPDIR/ssh-opt-in.md" "rollback revokes transaction-owned LAN trust"
assert_grep_fixed 'sudo mv -fT -- "$AUTH_RESTORE" "$AUTH_KEYS"' \
    "$TMPDIR/ssh-opt-in.md" \
    "rollback atomically restores authorized_keys without following the target"
assert_grep_fixed 'sudo mv -fT -- "$CONFIG_RESTORE" "$CONFIG"' \
    "$TMPDIR/ssh-opt-in.md" \
    "rollback atomically restores the prior root-owned server drop-in"
assert_grep_fixed '-p "$SSH_PORT" "${SSH_USER}@192.168.1.10"' \
    "$TMPDIR/ssh-opt-in.md" "external test uses the selected port and user"
assert_grep_fixed 'Do not temporarily' "$TMPDIR/ssh-opt-in.md" \
    "recovery does not weaken authentication"
assert_grep_fixed 'WAN exposure is outside this workflow' "$TMPDIR/ssh-opt-in.md" \
    "LAN-only authorization is not conflated with Internet exposure"
assert_grep_fixed 'Calendar-only rotation' "$TMPDIR/ssh-opt-in.md" \
    "key lifecycle guidance has no arbitrary calendar rotation"
assert_not_grep 'Fail2Ban optional' "$TMPDIR/ssh-opt-in.md" \
    "LAN-only flow does not advertise a package as a WAN security substitute"

# Client privacy guidance must distinguish SSHFP from ordinary name
# resolution, presentation from authentication and unlink from secure erase.
assert_grep_fixed 'ordinary hostname A/AAAA resolution still occurs' \
    "$TMPDIR/ssh-client.md" "VerifyHostKeyDNS claim is scoped to SSHFP"
assert_grep_fixed 'gives up a possible DNSSEC-authenticated SSHFP' \
    "$TMPDIR/ssh-client.md" "SSHFP authentication trade-off is explicit"
assert_grep_fixed 'VerifyHostKeyDNS ask' "$TMPDIR/ssh-client.md" \
    "reviewed per-host SSHFP opt-in is documented"
assert_grep_fixed 'authenticated out-of-band value before typing `yes`' \
    "$TMPDIR/ssh-client.md" "first-use fingerprint needs authenticated comparison"
assert_grep_fixed 'but similar-looking RandomArt' "$TMPDIR/ssh-client.md" \
    "VisualHostKey comparison limitation is explicit"
assert_grep_fixed 'is not unambiguous proof' "$TMPDIR/ssh-client.md" \
    "VisualHostKey is not presented as proof"
assert_grep_fixed 'rm -f -- ~/.ssh/known_hosts.old' "$TMPDIR/ssh-client.md" \
    "plaintext backup is unlinked after review"
assert_grep_fixed 'it is **not** a secure-erasure claim' "$TMPDIR/ssh-client.md" \
    "unlink semantics are explicit"
assert_grep_fixed 'expected `/home` is Btrfs' "$TMPDIR/ssh-client.md" \
    "guide names the expected copy-on-write boundary"
assert_grep_fixed 'retention and eventual device disposal are separate trust decisions' \
    "$TMPDIR/ssh-client.md" "guide names independent retention boundaries"
assert_not_grep 'KexAlgorithms +diffie-hellman-group14-sha256' \
    "$TMPDIR/ssh-client.md" \
    "one legacy exception cannot silently reopen the compiled default KEX set"
assert_not_grep_extended 'shred[[:space:]]+-u|prevents passive DNS-leak|VisualHostKey yes.*anti-MITM|would indicate MITM' \
    "$TMPDIR/ssh-client.md" "client guide has no secure-delete or display-as-proof claim"

# Build publication is explicit and RPM-compatible: client config stays
# world-readable, server configuration matches Fedora's root-private 0700/0600
# package layout, and all outputs are relabeled without a swallowed failure.
assert_grep_fixed 'install -d -m 0755 -o root -g root /etc/ssh/ssh_config.d' \
    "$KS_FILE" "client drop-in directory mode is explicit"
assert_grep_fixed 'install -d -m 0700 -o root -g root /etc/ssh/sshd_config.d' \
    "$KS_FILE" "server drop-in directory matches Fedora RPM metadata"
assert_grep_fixed 'chmod 600 /etc/ssh/sshd_config.d/01-noid-hardening.conf' \
    "$KS_FILE" "dormant server policy matches Fedora root-private config mode"
assert_grep_fixed 'matchpathcon -V "$ssh_path"' "$KS_FILE" \
    "every M09 output verifies its SELinux context"
assert_not_grep 'restorecon -F /etc/ssh/sshd_config.d/01-noid-hardening.conf 2>/dev/null || true' \
    "$KS_FILE" "server-policy relabel failures are never swallowed"
assert_grep_fixed '/etc/ssh/sshd_config.d|f|/etc/ssh/sshd_config.d/.noid-aide-coverage-probe' \
    "$PROJECT_ROOT/manifests/aide-secure-paths.tsv" \
    "dormant server policy is part of the canonical AIDE boundary"

# RFC publication and installed implementation support are separate claims.
# Do not let the release-facing PQ documents regress to the superseded draft
# status after draft-ietf-openpgp-pqc became RFC 9980 in June 2026.
for doc in "$PQC_DOC" "$THREAT_DOC"; do
    assert_grep_fixed 'RFC 9980' "$doc" \
        "OpenPGP PQ status names the published IETF standard"
    assert_not_grep_extended 'OpenPGP-PQC Internet-Draft|draft-ietf-openpgp-pqc' \
        "$doc" "OpenPGP PQ status does not call RFC 9980 a draft"
done
assert_grep_fixed 'installed Fedora 44 GnuPG 2.4.9 reports no' "$PQC_DOC" \
    "PQ guide separates standardisation from installed implementation support"
assert_grep_fixed 'installed GnuPG 2.4.9 has no PQ public-key algorithm' \
    "$THREAT_DOC" \
    "threat model does not infer installed OpenPGP PQ capability from RFC status"

test_finish

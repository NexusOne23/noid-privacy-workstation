#!/bin/bash
# 31-user-docs-tier-c — verify M31 Tier-C doc invariants
# Ships: three operational docs plus five canonical product-boundary docs.
# (yelp intentionally skipped per docs/decision-yelp-mallard-skip.md).

set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/31-user-docs-tier-c.ks"
M27_FILE="$PROJECT_ROOT/kickstart/snippets/27-hardware-tuning.ks"
M05_FILE="$PROJECT_ROOT/kickstart/snippets/05-lan-isolation.ks"
M08_FILE="$PROJECT_ROOT/kickstart/snippets/08-service-minimization.ks"
M09_FILE="$PROJECT_ROOT/kickstart/snippets/09-ssh.ks"
M11_FILE="$PROJECT_ROOT/kickstart/snippets/11-dns-ntp.ks"
M18_FILE="$PROJECT_ROOT/kickstart/snippets/18-flatpak-sandboxing.ks"
M20_FILE="$PROJECT_ROOT/kickstart/snippets/20-snapper.ks"
M21_FILE="$PROJECT_ROOT/kickstart/snippets/21-kernel-module-blacklist.ks"
M24_FILE="$PROJECT_ROOT/kickstart/snippets/24-firmware-fwupd.ks"
M26_FILE="$PROJECT_ROOT/kickstart/snippets/26-package-set.ks"
M28_FILE="$PROJECT_ROOT/kickstart/snippets/28-local-ai-docs.ks"
M29_FILE="$PROJECT_ROOT/kickstart/snippets/29-user-docs.ks"
M42_FILE="$PROJECT_ROOT/kickstart/snippets/42-forensic-retention.ks"
M99_FILE="$PROJECT_ROOT/kickstart/snippets/99-finalize.ks"
MASTER_FILE="$PROJECT_ROOT/kickstart/master.ks"
snippet_count=$(find "$PROJECT_ROOT/kickstart/snippets" -maxdepth 1 -type f \
    -name '*.ks' -print | wc -l)
functional_module_count=$((snippet_count - 1))

test_start "31-user-docs-tier-c"

if [ ! -f "$KS_FILE" ]; then
    _fail "M31 snippet missing: $KS_FILE"
    test_finish
    exit 1
fi

TMPDIR="$(mktemp -d "${TMPDIR:-/var/tmp}/noid-tier-c.XXXXXX")"
trap 'rm -rf "$TMPDIR"' EXIT

# --- Extract every installed doc --------------------------------------------

extract_heredoc "$KS_FILE" "TRB_EOF"   "$TMPDIR/99-troubleshooting.md"  || true
extract_heredoc "$KS_FILE" "ARCH_EOF"  "$TMPDIR/00-architecture.md"     || true
extract_heredoc "$KS_FILE" "PERFORMANCE_EOF" "$TMPDIR/27-performance.md" || true
extract_heredoc "$KS_FILE" "NOID_THREAT_MODEL_DOC_EOF" \
    "$TMPDIR/threat-model.md" || true
extract_heredoc "$KS_FILE" "NOID_SCOPE_DOC_EOF" "$TMPDIR/scope.md" || true
extract_heredoc "$KS_FILE" "NOID_PQ_DOC_EOF" \
    "$TMPDIR/post-quantum-readiness.md" || true
extract_heredoc "$KS_FILE" "NOID_PERFORMANCE_PROFILE_DOC_EOF" \
    "$TMPDIR/performance-profile.md" || true
extract_heredoc "$KS_FILE" "NOID_LICENSING_DOC_EOF" \
    "$TMPDIR/licensing.md" || true

assert_cmd_success "M31 kickstart shell syntax is valid" bash -n "$KS_FILE"
assert_file_executable "$PROJECT_ROOT/scripts/regen-product-boundary-docs.sh" \
    "product-boundary source generator is executable"
assert_cmd_success "product-boundary source generator reports no drift" \
    "$PROJECT_ROOT/scripts/regen-product-boundary-docs.sh" --check
assert_grep_fixed 'set -euo pipefail' "$KS_FILE" \
    "M31 enables strict unset-variable handling"
assert_grep_fixed \
    "sudo grep -cE '^-?[a-z]+\\.' /etc/sysctl.d/99-hardening.conf" \
    "$TMPDIR/00-architecture.md" \
    "shipped architecture M02 check counts the ignore-on-error directive"
if grep -qF -- "sudo grep -c '^[a-z].*=' /etc/sysctl.d/99-hardening.conf" \
        "$TMPDIR/00-architecture.md"; then
    _fail "shipped architecture M02 check cannot regress to a 100-line count"
else
    _pass "shipped architecture M02 check cannot regress to a 100-line count"
fi
assert_grep_fixed 'command -v restorecon' "$KS_FILE" \
    "M31 requires SELinux labeling before publishing payloads"
assert_grep_fixed 'mv -fT -- "$DOC_TMP" "$target"' "$KS_FILE" \
    "M31 publishes documents atomically without following destination links"
assert_grep_fixed 'chown root:root -- "$DOC_TMP"' "$KS_FILE" \
    "document temporaries converge to root ownership before publication"
assert_grep_fixed 'restorecon -F -- "$target"' "$KS_FILE" \
    "each document receives its policy-owned SELinux context"
assert_grep_fixed 'matchpathcon -V "$target"' "$KS_FILE" \
    "each published document receives a verified SELinux context"
assert_grep_fixed 'matchpathcon -V "$path"' "$KS_FILE" \
    "final document verification rechecks the active SELinux policy"
assert_not_grep 'Phase 5 — SELinux restore' "$KS_FILE" \
    "M31 has no empty SELinux-restore phase"
assert_not_grep 'PHASE="P5-selinux"' "$KS_FILE" \
    "M31 has no dead SELinux phase state"
assert_grep_fixed \
    'canonical product-boundary documentation written and labeled fail-closed' \
    "$KS_FILE" "M31 records labeling in the publishing phase"
assert_grep_fixed 'install -d -m 0755 -o root -g root -- "$DOC_DIR"' "$KS_FILE" \
    "M31 creates the trusted document directory with exact metadata"
assert_grep_fixed 'DOC_DIR exists but is not a real directory' "$KS_FILE" \
    "M31 rejects a symlinked or non-directory document root"
assert_grep_fixed 'DOC_DIR existing metadata differs from root:root 0755' \
    "$KS_FILE" "M31 rejects existing document-directory metadata drift"
assert_grep_fixed 'sync -- "$DOC_TMP"' "$KS_FILE" \
    "M31 syncs each staged document before its atomic rename"
assert_grep_fixed 'sync -- "$target" "$DOC_DIR"' "$KS_FILE" \
    "M31 syncs each canonical document and its parent directory"
assert_grep_fixed 'DOC_PUBLICATION_ACTIVE=1' "$KS_FILE" \
    "M31 tracks the exact unverified published document"
assert_grep_fixed "DOC_PUBLISHED_ID=\$(stat -Lc '%d:%i' -- \"\$DOC_TMP\")" \
    "$KS_FILE" "M31 binds publication cleanup to the staged inode"
assert_grep_fixed 'if [ "$current_id" = "$DOC_PUBLISHED_ID" ]; then' \
    "$KS_FILE" "M31 cleanup removes only the exact just-published inode"
assert_grep_fixed "trap 'exit 130' INT" "$KS_FILE" \
    "M31 INT handling reaches the shared cleanup boundary"
assert_grep_fixed "trap 'exit 143' TERM" "$KS_FILE" \
    "M31 TERM handling reaches the shared cleanup boundary"
assert_grep_fixed 'trap - EXIT INT TERM' "$KS_FILE" \
    "M31 clears every publication trap only after success"
assert_not_grep_extended \
    'cat > /usr/share/doc/noid-privacy/|chown root:root /usr/share/doc/noid-privacy/|chmod 0?644 /usr/share/doc/noid-privacy/' \
    "$KS_FILE" "M31 has no direct trust-boundary document writers"
assert_not_grep_extended '(^|[;&|[:space:]])eval([;&|[:space:]]|$)' "$KS_FILE" \
    "M31 verification does not evaluate command strings"
assert_grep_fixed 'restorecon -F -- "$STAMP"' "$KS_FILE" \
    "M31 health-stamp relabel is forced and fail-visible"
assert_grep_fixed "stat -Lc '%u:%g:%a:%h'" "$KS_FILE" \
    "M31 verifies ownership, exact mode and hardlink count"
assert_grep_fixed 'mv -fT -- "$STAMP_TMP" "$STAMP"' "$KS_FILE" \
    "M31 publishes the health stamp atomically"
assert_grep_fixed 'verify_m31_health_stamp()' "$KS_FILE" \
    "M31 binds staged and final health evidence to one exact validator"
assert_grep_fixed 'prior Module 31 health stamp is absent' "$KS_FILE" \
    "old M31 success evidence is retired before document publication"
assert_grep_fixed 'STAMP_PUBLICATION_ACTIVE=1' "$KS_FILE" \
    "published M31 evidence remains removable through every final gate"
assert_grep_fixed 'matchpathcon -V "$STAMP_TMP"' "$KS_FILE" \
    "M31 validates the staged stamp SELinux context"
assert_grep_fixed 'matchpathcon -V "$STAMP"' "$KS_FILE" \
    "M31 validates the final stamp SELinux context"

assert_file_min_size "$TMPDIR/99-troubleshooting.md" 5120 "99-troubleshooting >=5KB"
assert_file_min_size "$TMPDIR/00-architecture.md"    5120 "00-architecture >=5KB"
assert_file_min_size "$TMPDIR/27-performance.md"     3072 "27-performance >=3KB"
assert_file_min_size "$TMPDIR/threat-model.md" 20000 "threat-model >=20KB"
assert_file_min_size "$TMPDIR/scope.md" 14000 "scope >=14KB"
assert_file_min_size "$TMPDIR/post-quantum-readiness.md" 9000 \
    "post-quantum-readiness >=9KB"
assert_file_min_size "$TMPDIR/performance-profile.md" 5000 \
    "performance-profile >=5KB"
assert_file_min_size "$TMPDIR/licensing.md" 12000 "licensing >=12KB"

for doc in 99-troubleshooting.md 00-architecture.md 27-performance.md \
           threat-model.md scope.md post-quantum-readiness.md \
           performance-profile.md licensing.md; do
    case "$(head -n 1 "$TMPDIR/$doc")" in
        '# '*) _pass "$doc begins with an ATX H1" ;;
        *) _fail "$doc begins with an ATX H1" ;;
    esac
done

for mapping in \
    "threat-model.md|docs/threat-model.md" \
    "scope.md|docs/scope.md" \
    "post-quantum-readiness.md|docs/post-quantum-readiness.md" \
    "performance-profile.md|docs/performance-profile.md" \
    "licensing.md|LICENSING.md"; do
    installed=${mapping%%|*}
    source=${mapping#*|}
    if cmp -s "$TMPDIR/$installed" "$PROJECT_ROOT/$source"; then
        _pass "$installed is byte-identical to $source"
    else
        _fail "$installed drifted from $source"
    fi
done

# Every shell procedure shown to users must remain syntactically executable.
# Accept both top-level and list-indented Markdown fences, de-indent their
# contents exactly as Markdown does, and reject active angle-bracket tokens
# that would otherwise be interpreted by Bash as redirection.
if python3 - "$TMPDIR" 30 <<'M31_BASH_FENCE_EOF'
import pathlib
import re
import subprocess
import sys
import textwrap

root = pathlib.Path(sys.argv[1])
expected = int(sys.argv[2])
documents = (
    "99-troubleshooting.md",
    "00-architecture.md",
    "27-performance.md",
    "threat-model.md",
    "scope.md",
    "post-quantum-readiness.md",
    "performance-profile.md",
    "licensing.md",
)
fence_re = re.compile(
    r"^[ \t]*```bash[ \t]*\n(.*?)^[ \t]*```[ \t]*$",
    re.MULTILINE | re.DOTALL,
)
placeholder_re = re.compile(r"<[A-Za-z][A-Za-z0-9_.:@/-]*>")
count = 0

for name in documents:
    text = (root / name).read_text(encoding="utf-8")
    for index, body in enumerate(fence_re.findall(text), start=1):
        count += 1
        script = textwrap.dedent(body)
        for line_no, line in enumerate(script.splitlines(), start=1):
            if not line.lstrip().startswith("#") and placeholder_re.search(line):
                print(
                    f"{name}: bash fence {index}, line {line_no}: "
                    "active angle-bracket placeholder",
                    file=sys.stderr,
                )
                raise SystemExit(1)
        result = subprocess.run(
            ("bash", "-n"),
            input=script,
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode:
            print(
                f"{name}: bash fence {index} fails bash -n:\n"
                f"{result.stderr.rstrip()}",
                file=sys.stderr,
            )
            raise SystemExit(1)

if count != expected:
    print(
        f"expected {expected} bash fences across Tier-C docs, found {count}",
        file=sys.stderr,
    )
    raise SystemExit(1)
M31_BASH_FENCE_EOF
then
    _pass "all 30 Tier-C bash fences parse and contain no active placeholders"
else
    _fail "Tier-C bash-fence executable contract"
fi

assert_grep_fixed '**Package and standards evidence last verified**: 2026-08-02.' \
    "$TMPDIR/post-quantum-readiness.md" \
    "PQ package evidence carries its exact historical audit date"
assert_grep_fixed 'OpenSSH 10.2p1, OpenSSL 3.5.7,' \
    "$TMPDIR/post-quantum-readiness.md" \
    "PQ package inventory matches the Fedora 44 audit host"
assert_grep_fixed 'OpenVPN 2.7.5,' \
    "$TMPDIR/post-quantum-readiness.md" \
    "PQ package inventory retains the observed OpenVPN version"
assert_grep_fixed 'Firefox 153, Thunderbird 152, NSS 3.125, and GnuPG 2.4.9.' \
    "$TMPDIR/post-quantum-readiness.md" \
    "PQ package inventory covers the remaining load-bearing local transport versions"
assert_grep_fixed 'is not an exact v1.7 ISO package manifest;' \
    "$TMPDIR/post-quantum-readiness.md" \
    "PQ evidence does not overclaim the release package closure"
assert_grep_fixed 'an RFC 9700/provider account-access checklist' \
    "$TMPDIR/00-architecture.md" \
    "M33 architecture summary names the standards-backed account review"
assert_grep_fixed 'creates a persistent dedicated profile' \
    "$TMPDIR/00-architecture.md" \
    "M33 architecture summary does not call its profile helper amnesic"
assert_grep_fixed 'not an OS/filesystem sandbox' \
    "$TMPDIR/00-architecture.md" \
    "M34 architecture summary states the actual same-user boundary"
assert_not_grep_extended 'SentinelOne 2025|Katz Stealer|manual AIDE status \+ Snapper diff|file-system-level profile isolation' \
    "$TMPDIR/00-architecture.md" \
    "M33/M34 architecture summary contains no stale threat or isolation claims"
assert_grep_fixed '**Endpoint probe observations last rerun**: 2026-08-02' \
    "$TMPDIR/post-quantum-readiness.md" \
    "PQ endpoint evidence is explicitly dated"
assert_grep_fixed 'succeeded against the Cloudflare PQ test endpoint.' \
    "$TMPDIR/post-quantum-readiness.md" \
    "PQ endpoint observation retains the verified Cloudflare hybrid result"
assert_grep_fixed 'primary address completed `X25519MLKEM768` in two of six hybrid-only sessions' \
    "$TMPDIR/post-quantum-readiness.md" \
    "PQ endpoint observation records intermittent primary-address hybrid support"
assert_grep_fixed 'The secondary address rejected all six' \
    "$TMPDIR/post-quantum-readiness.md" \
    "PQ endpoint observation records the negative secondary-address series"
assert_grep_fixed 'separate unrestricted session to the secondary' \
    "$TMPDIR/post-quantum-readiness.md" \
    "PQ endpoint observation records the conflicting unrestricted session"
assert_grep_fixed 'It does not establish consistent' \
    "$TMPDIR/post-quantum-readiness.md" \
    "PQ endpoint observation does not generalize session-level support"
assert_not_grep "Quad9's two documented IPv4 DoT addresses did not establish hybrid" \
    "$TMPDIR/post-quantum-readiness.md" \
    "stale universal Quad9 negative observation cannot return"
assert_not_grep 'succeeded against both the Cloudflare PQ test endpoint and' \
    "$TMPDIR/post-quantum-readiness.md" \
    "stale universal Cloudflare/Quad9 hybrid claim cannot return"
assert_grep_fixed 'Upstream declared GnuPG 2.4 end-of-life on 2026-06-30.' \
    "$TMPDIR/post-quantum-readiness.md" \
    "PQ guidance records the installed GnuPG branch lifecycle boundary"
assert_grep_fixed "WireGuard's optional preshared key can add a" \
    "$TMPDIR/post-quantum-readiness.md" \
    "PQ guidance records WireGuard's optional symmetric layer"
assert_grep_fixed 'it is not a standardised PQ public-key handshake' \
    "$TMPDIR/post-quantum-readiness.md" \
    "WireGuard PSK guidance does not overclaim a standard PQ handshake"
assert_grep_fixed 'minimum firmware differ by processor family' \
    "$TMPDIR/threat-model.md" \
    "AMD TPM remediation follows the product-specific vendor table"
assert_not_grep 'patched via AMD AGESA 1.2.0.3e' \
    "$TMPDIR/threat-model.md" \
    "AMD TPM remediation is not misrepresented as one universal AGESA"
assert_grep_fixed '### Repository metadata and package-signature boundary' \
    "$TMPDIR/threat-model.md" \
    "threat model names the package-versus-metadata signature boundary"
assert_grep_fixed 'The Fedora 44 Cisco OpenH264 endpoint configured by Module 08 does not publish' \
    "$TMPDIR/threat-model.md" \
    "OpenH264 metadata-signature exception is documented at its canonical source"
assert_grep_fixed 'it does not OpenPGP-authenticate repository metadata or its' \
    "$TMPDIR/threat-model.md" \
    "OpenH264 exception states the residual metadata and freshness risk"
assert_not_grep '5+ min' "$TMPDIR/threat-model.md" \
    "USB residual risk has no invented universal attack duration"
assert_grep_fixed 'VPN endpoint IP and' "$TMPDIR/threat-model.md" \
    "VPN observer boundary names the invariant endpoint metadata"
assert_not_grep 'VPN endpoint visible in SNI/timing' "$TMPDIR/threat-model.md" \
    "VPN residual risk does not assume one transport's SNI behavior"
assert_grep_fixed 'wifi.cloned-mac-address=stable-ssid' \
    "$TMPDIR/threat-model.md" \
    "threat model names Fedora's actual per-SSID MAC mode"
assert_not_grep 'wifi\.cloned-mac-address=stable`' \
    "$TMPDIR/threat-model.md" \
    "stale generic WiFi stable-MAC mode cannot return"
assert_grep_fixed 'operators sharing an identical SSID can compare the same pseudonym' \
    "$TMPDIR/threat-model.md" \
    "threat model states the same-SSID correlation boundary"
assert_grep_fixed 'reused Ethernet profile remains linkable across wired LANs' \
    "$TMPDIR/threat-model.md" \
    "threat model states the wired-profile correlation boundary"
assert_grep_fixed 'global Quad9 uses strict authenticated' \
    "$TMPDIR/threat-model.md" \
    "threat model records the authenticated fail-closed DNS default"
assert_grep_fixed "\`connection.dns-over-tls\` inherits the image's generic \`opportunistic\`" \
    "$TMPDIR/threat-model.md" \
    "threat model attributes an unset tunnel transport to the image default"
assert_grep_fixed 'cannot authenticate the resolver' \
    "$TMPDIR/threat-model.md" \
    "threat model names the opportunistic per-link authentication boundary"
assert_not_grep 'provider-selected per-link transport' \
    "$TMPDIR/threat-model.md" \
    "threat model does not misattribute inherited tunnel transport"
assert_grep_fixed 'A self-encrypting drive is not a substitute' \
    "$TMPDIR/scope.md" \
    "cold-boot guidance does not conflate SSD locking with RAM erasure"
assert_not_grep 'instant crypto-erase on power-off' "$TMPDIR/scope.md" \
    "scope contains no unsupported Opal instant-erasure claim"
assert_grep_fixed 'PCR policy, recovery-key handling,' "$TMPDIR/scope.md" \
    "TPM-bound unlock trade-off is platform- and recovery-specific"
assert_not_grep 'because it breaks disk restoration after firmware updates' \
    "$TMPDIR/scope.md" \
    "TPM-bound unlock is not rejected by an absolute restoration claim"
assert_grep_fixed 'authenticates downloaded bytes only' "$TMPDIR/scope.md" \
    "firmware checksum guidance keeps the running-state trust boundary"
assert_grep_fixed 'resolver uses strict authenticated global' "$TMPDIR/scope.md" \
    "scope records the fail-closed global DNS default"
assert_grep_fixed 'while an explicit profile value wins' "$TMPDIR/scope.md" \
    "scope preserves provider overrides over the image tunnel default"
assert_not_grep 'keeps its own per-link transport' "$TMPDIR/scope.md" \
    "scope does not misattribute inherited tunnel transport"
assert_grep_fixed 'noid-mei-restore-submodules --block hdcp|pxp|wdt' \
    "$TMPDIR/threat-model.md" \
    "MEI opt-in example uses the helper's accepted short tokens"
assert_not_grep 'noid-mei-restore-submodules --block <name>' \
    "$TMPDIR/threat-model.md" \
    "MEI guide does not imply rejected mei-prefixed arguments"
assert_grep_fixed '](15-intel-me-hardware-layer.md)' "$TMPDIR/scope.md" \
    "scope links to an installed hardware-layer guide"
assert_not_grep '](../kickstart/snippets/15-intel-me-mitigation.ks)' \
    "$TMPDIR/scope.md" \
    "installed scope document has no repository-only relative link"
assert_not_grep 'and install Steam on' "$TMPDIR/scope.md" \
    "scope contains no duplicated Gaming Mode install claim"
assert_grep_fixed '`xdg-open` → `papers`' "$TMPDIR/scope.md" \
    "scope names the shipped native document viewer"
assert_not_grep '`xdg-open` → `evince`' "$TMPDIR/scope.md" \
    "scope contains no retired Evince example"
assert_grep_fixed 'papers showtime decibels snapshot loupe' "$M26_FILE" \
    "scope viewer example is anchored to M26's package truth gate"
assert_grep_fixed 'The `openssh-server` package is excluded from the image' \
    "$TMPDIR/post-quantum-readiness.md" \
    "PQ guide states the actual absent SSH-server package boundary"
assert_grep_fixed 'preset can enable `sshd.service`' \
    "$TMPDIR/post-quantum-readiness.md" \
    "PQ guide warns that package installation can activate Fedora's preset"
assert_grep_fixed '`ssh-server-opt-in.md` procedure immediately' \
    "$TMPDIR/post-quantum-readiness.md" \
    "PQ guide directs server installs through the listener-closed workflow"
assert_grep_fixed '-openssh-server' "$M09_FILE" \
    "PQ and architecture SSH posture is anchored to M09's package exclusion"
for mapping in \
    "99-troubleshooting.md|TRB_EOF" \
    "00-architecture.md|ARCH_EOF" \
    "27-performance.md|PERFORMANCE_EOF" \
    "threat-model.md|NOID_THREAT_MODEL_DOC_EOF" \
    "scope.md|NOID_SCOPE_DOC_EOF" \
    "post-quantum-readiness.md|NOID_PQ_DOC_EOF" \
    "performance-profile.md|NOID_PERFORMANCE_PROFILE_DOC_EOF" \
    "licensing.md|NOID_LICENSING_DOC_EOF"; do
    installed=${mapping%%|*}
    marker=${mapping#*|}
    assert_grep_fixed \
        "# Shipped Markdown target: /usr/share/doc/noid-privacy/$installed" \
        "$KS_FILE" "$installed declares its shipped target"
    assert_grep_fixed "# Shipped Markdown heredoc: $marker" \
        "$KS_FILE" "$installed declares its atomic heredoc"
done
for mapping in \
    "scope.md|threat-model.md" \
    "post-quantum-readiness.md|threat-model.md" \
    "performance-profile.md|scope.md" \
    "35-thunderbird-smartcard.md|post-quantum-readiness.md"; do
    required_link=${mapping%%|*}
    source_doc=${mapping#*|}
    assert_grep_fixed "]($required_link)" "$TMPDIR/$source_doc" \
        "$source_doc retains link to $required_link"
done
rollback_refs=$(grep -cF -- 'Rollback from a working boot' \
    "$TMPDIR/99-troubleshooting.md" || true)
assert_eq 2 "$rollback_refs" \
    "troubleshooting points both rollback references at the real section"
assert_not_grep 'Rollback (CLI)' "$TMPDIR/99-troubleshooting.md" \
    "troubleshooting contains no retired rollback section name"
assert_grep_fixed '## Rollback from a working boot' "$M20_FILE" \
    "troubleshooting rollback target is anchored to M20"
assert_grep_fixed '[28-local-ai.md](28-local-ai.md) → GPU boundary' \
    "$TMPDIR/99-troubleshooting.md" \
    "local-AI troubleshooting points at an existing GPU section"
assert_grep_fixed '### GPU boundary' "$M28_FILE" \
    "local-AI troubleshooting target is anchored to M28"
assert_not_grep_fixed '[28-local-ai.md](28-local-ai.md) → Troubleshooting' \
    "$TMPDIR/99-troubleshooting.md" \
    "local-AI index contains no nonexistent Troubleshooting target"
assert_grep_fixed 'journalctl -b -p notice --no-pager' \
    "$TMPDIR/99-troubleshooting.md" \
    "recent-log overview includes notice-priority dispatcher output"
assert_not_grep 'journalctl -b -p warning --no-pager' \
    "$TMPDIR/99-troubleshooting.md" \
    "recent-log overview cannot hide notice-priority dispatcher output"
assert_grep_fixed 'plain `logger` output used by the topology and VPN-zone dispatchers' \
    "$TMPDIR/99-troubleshooting.md" \
    "recent-log overview explains its notice-priority boundary"
assert_grep_fixed 'retained on the installed system for 30 days by' \
    "$TMPDIR/99-troubleshooting.md" \
    "troubleshooting states the install-log retention window"
assert_grep_fixed '`noid-install-logs-prune.timer`' \
    "$TMPDIR/99-troubleshooting.md" \
    "troubleshooting names the install-log retention owner"
assert_grep_fixed 'noid-install-logs-prune.timer' "$M42_FILE" \
    "install-log retention claim is anchored to M42"
assert_grep_fixed 'sudo journalctl -t noid-audit-notify' \
    "$TMPDIR/99-troubleshooting.md" \
    "troubleshooting uses the notifier's actual journal identifier"
assert_not_grep 'journalctl -t audit-notify' \
    "$TMPDIR/99-troubleshooting.md" \
    "troubleshooting contains no nonexistent audit journal identifier"
assert_not_grep 'will replace with custom RPMs via COPR' \
    "$TMPDIR/00-architecture.md" \
    "architecture does not promise an unplanned COPR migration"
assert_grep_fixed 'Flatseal is documented as an optional user install' \
    "$TMPDIR/00-architecture.md" \
    "architecture matches M18's documentation-only Flatseal boundary"
assert_not_grep 'Flatseal install (Silent-Machine Position B)' \
    "$TMPDIR/00-architecture.md" \
    "architecture does not claim an absent Flatseal installer"
assert_grep_fixed 'M13 Python GTK4/libadwaita' "$TMPDIR/00-architecture.md" \
    "architecture identifies the actual Welcome implementation"
assert_not_grep 'noid-welcome.sh (zenity dialog' "$TMPDIR/00-architecture.md" \
    "architecture has no removed Zenity Welcome description"
assert_grep_fixed 'No `/etc/issue.d` trademark artifact is' \
    "$TMPDIR/00-architecture.md" \
    "architecture follows the current branding artifact set"
assert_grep_fixed 'is mandatory and locally hardened, but no mail account is configured' \
    "$TMPDIR/00-architecture.md" \
    "neutral-image wording acknowledges the mandatory mail client"
assert_not_grep 'Ships no VPN provider, no mail client' \
    "$TMPDIR/00-architecture.md" \
    "neutral-image wording does not contradict M35"
assert_grep_fixed 'provider-compatible system/VPN DNS by default' \
    "$TMPDIR/00-architecture.md" \
    "architecture follows the current Firefox resolver contract"
assert_not_grep 'DoH Quad9 Mode 3' "$TMPDIR/00-architecture.md" \
    "architecture does not resurrect forced Firefox DoH"
assert_grep_fixed '### Mitigated or made more observable' \
    "$TMPDIR/00-architecture.md" \
    "threat model uses evidence-calibrated control wording"
assert_not_grep '^### Protected against$' "$TMPDIR/00-architecture.md" \
    "threat model does not turn mitigations into categorical protection"
assert_not_grep 'all channels closed' "$TMPDIR/00-architecture.md" \
    "architecture does not claim universal vendor-telemetry closure"
assert_grep_fixed 'historical dracut failure RHBZ#2274246 was fixed in dracut 102' \
    "$TMPDIR/00-architecture.md" \
    "architecture does not use a fixed dracut bug as a current justification"
assert_not_grep 'dnf breaks, confirmed by RHBZ#2274246' \
    "$TMPDIR/00-architecture.md" \
    "fixed dracut bug cannot return as a current DNF compatibility claim"
assert_grep_fixed 'require executable shared-memory mappings' \
    "$TMPDIR/00-architecture.md" \
    "shared-memory noexec trade-off is workload-scoped"
assert_not_grep 'V8 JIT compatibility empirically verified' \
    "$TMPDIR/00-architecture.md" \
    "architecture has no unretained universal V8 compatibility claim"
assert_grep_fixed 'cannot detect malicious artifacts authorized by that chain' \
    "$TMPDIR/00-architecture.md" \
    "supply-chain trust is not overstated as signature-based detection"
assert_not_grep 'requires physical access for hours' \
    "$TMPDIR/00-architecture.md" \
    "physical fault-injection feasibility has no invented duration"
assert_not_grep 'hard-locked' "$TMPDIR/00-architecture.md" \
    "architecture does not claim a universal AMD PSP lock state"
assert_not_grep 'PSP hardware-locked' "$TMPDIR/threat-model.md" \
    "canonical threat model does not claim a universal AMD PSP lock state"
assert_grep_fixed 'PSP is below the host-OS boundary and is not host-disableable' \
    "$TMPDIR/threat-model.md" \
    "AMD PSP claim matches the actual host-control boundary"
assert_grep_fixed 'exactly 1 durable assignment' \
    "$TMPDIR/00-architecture.md" \
    "architecture records the single selected-interface M07 durable state"
assert_grep_fixed 'live disable on every physical `pre-up`' \
    "$TMPDIR/00-architecture.md" \
    "architecture records M07 event-time enforcement on every physical link"
assert_grep_fixed 'event-time enforcement on every physical pre-up' \
    "$TMPDIR/threat-model.md" \
    "threat model records M07 event-time enforcement"
assert_grep_fixed 'provider client or import a generic NetworkManager' \
    "$TMPDIR/threat-model.md" \
    "threat model keeps provider clients inside the VPN-neutral boundary"
assert_grep_fixed 'WireGuard/OpenVPN profile' \
    "$TMPDIR/threat-model.md" \
    "threat model keeps generic WireGuard/OpenVPN profiles supported"
assert_grep_fixed 'generic NetworkManager WireGuard/OpenVPN' \
    "$TMPDIR/scope.md" \
    "scope keeps the VPN support boundary provider-neutral"
assert_not_grep 'ProtonVPN WireGuard' "$TMPDIR/threat-model.md" \
    "threat model does not turn one provider mode into the product boundary"
assert_not_grep "ProtonVPN's" "$TMPDIR/post-quantum-readiness.md" \
    "PQ guidance does not turn one provider mode into a verified alternative"
assert_not_grep 'third-party RPMs carry no AppStream catalog' "$KS_FILE" \
    "M31 maintainer contract matches the AppStream metadata boundary"
assert_not_grep 'uname -a' "$TMPDIR/27-performance.md" \
    "performance capture does not record the host name"
assert_not_grep 'uname -a' "$TMPDIR/performance-profile.md" \
    "canonical performance capture does not record the host name"
assert_grep_fixed 'After the user reviews and activates a baseline' \
    "$TMPDIR/00-architecture.md" \
    "AIDE claim respects the user-owned baseline boundary"
assert_grep_fixed 'check-only AIDE drift evidence after successful DNF when an' \
    "$TMPDIR/00-architecture.md" \
    "M25 architecture summary conditions updater AIDE evidence on DNF success"
assert_grep_fixed 'active baseline exists and the user has not skipped it' \
    "$TMPDIR/00-architecture.md" \
    "M25 architecture summary preserves baseline ownership and explicit skip"
assert_grep_fixed 'reviewed llama-vscode path, with Cline documented as a separately trusted' \
    "$TMPDIR/00-architecture.md" \
    "M28 architecture summary matches the reviewed editor integrations"
assert_not_grep 'Continue/llama-vscode' "$TMPDIR/00-architecture.md" \
    "retired Continue integration claim cannot return"
assert_grep_fixed 'performance/VM/network tuning remains Fedora/kernel vendor policy' \
    "$TMPDIR/00-architecture.md" \
    "architecture keeps unbenchmarked performance knobs out of M02"
assert_not_grep 'vm\.page-cluster=0 zram-readahead override' \
    "$TMPDIR/00-architecture.md" \
    "architecture has no retired global swap-readahead tuning claim"
assert_grep_fixed 'It ships no NoID Privacy-specific scheduler, HWP boost, zram compression/priority,' \
    "$TMPDIR/00-architecture.md" \
    "architecture records the cleaned M27 performance boundary"
assert_grep_fixed 'Fedora/kernel-owned I/O scheduler and zram' \
    "$TMPDIR/00-architecture.md" \
    "architecture assigns M27 performance policy to maintained owners"
assert_grep_fixed "M21's shared lock" "$TMPDIR/00-architecture.md" \
    "architecture names the central boot-mutation contract"
assert_not_grep_extended '^[[:space:]]*-[[:space:]]+Kernel cmdline.*`grubby --update-kernel=ALL' \
    "$TMPDIR/00-architecture.md" \
    "architecture does not advertise an uncoordinated BLS mutation recipe"
assert_grep_fixed '**Two authoritative ways to enable**' \
    "$TMPDIR/99-troubleshooting.md" \
    "Bluetooth documentation names only wired authoritative transitions"
assert_grep_fixed 'Its radio switch is not equivalent to the NoID Privacy helper' \
    "$TMPDIR/99-troubleshooting.md" \
    "GNOME rfkill UI is not conflated with the NoID Privacy state machine"
assert_not_grep 'Three equivalent ways to enable' \
    "$TMPDIR/99-troubleshooting.md" \
    "stale three-way Bluetooth equivalence cannot return"
assert_not_grep 'To re-disable.*GNOME Settings' \
    "$TMPDIR/99-troubleshooting.md" \
    "GNOME radio-off is not presented as a full policy transition"
assert_grep_fixed 'allow/block/reject target' \
    "$TMPDIR/99-troubleshooting.md" \
    "USBGuard troubleshooting follows the actual list-devices vocabulary"
assert_not_grep 'b = blocked, a = allowed' \
    "$TMPDIR/99-troubleshooting.md" \
    "USBGuard output is not misrepresented as one-letter states"
assert_grep_fixed '/var/cache/libdnf5 /var/cache/dnf5daemon-server' \
    "$TMPDIR/99-troubleshooting.md" \
    "disk diagnosis uses Fedora 44 DNF5 cache paths"
assert_not_grep '/var/cache/dnf$' "$TMPDIR/99-troubleshooting.md" \
    "retired DNF4 cache path is absent"
assert_grep_fixed 'do not import every file matching a' \
    "$TMPDIR/99-troubleshooting.md" \
    "signature recovery does not trust a wildcard key import"
assert_not_grep 'rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-\*-primary' \
    "$TMPDIR/99-troubleshooting.md" \
    "signature recovery has no unverified bulk key import"
assert_grep_fixed 'sudo dnf upgrade --refresh --best --assumeno' \
    "$TMPDIR/99-troubleshooting.md" \
    "package-conflict diagnosis is a non-mutating transaction preview"
assert_not_grep_extended 'sudo dnf upgrade --(refresh|best|allowerasing)$' \
    "$TMPDIR/99-troubleshooting.md" \
    "troubleshooting does not launch a bare full-system update"
assert_grep_fixed 'sudo noid-aide-check.sh' "$TMPDIR/99-troubleshooting.md" \
    "AIDE manual check uses the supported check-only wrapper"
assert_grep_fixed 'After a successful DNF step, update-all runs a check only when an' \
    "$TMPDIR/99-troubleshooting.md" \
    "updater troubleshooting conditions AIDE on successful DNF"
assert_grep_fixed 'active baseline exists and the user did not explicitly skip it.' \
    "$TMPDIR/99-troubleshooting.md" \
    "updater troubleshooting preserves the AIDE baseline/skip boundary"
assert_not_grep 'Do NOT run any more commands' \
    "$TMPDIR/99-troubleshooting.md" \
    "incident guidance does not impose an impossible absolute command ban"
assert_grep_fixed 'Minimize further' "$TMPDIR/99-troubleshooting.md" \
    "incident guidance minimizes activity while preserving evidence"
assert_grep_fixed 'remains disabled until you have reviewed and' \
    "$TMPDIR/99-troubleshooting.md" \
    "AIDE notification troubleshooting respects baseline activation"
assert_not_grep 'systemctl start aide-check.service' \
    "$TMPDIR/99-troubleshooting.md" \
    "AIDE troubleshooting does not bypass the supported wrapper"
assert_grep_fixed 'caps the system journal at 30 days/500 MiB' \
    "$TMPDIR/99-troubleshooting.md" \
    "disk recovery preserves the shipped forensic-retention boundary"
assert_not_grep 'journalctl --vacuum-time=7d' \
    "$TMPDIR/99-troubleshooting.md" \
    "troubleshooting does not discard the 30-day forensic window"
assert_grep_fixed "read -r -p 'Exact crypto_LUKS device path: ' LUKS_DEV" \
    "$TMPDIR/99-troubleshooting.md" \
    "LUKS passphrase recovery discovers the installed device"
assert_not_grep '/dev/nvme0n1p3' "$TMPDIR/99-troubleshooting.md" \
    "LUKS passphrase recovery is not tied to one machine topology"
assert_grep_fixed 'without assuming a provider or name' \
    "$TMPDIR/99-troubleshooting.md" \
    "VPN troubleshooting is provider-neutral"
assert_grep_fixed 'sudo noid-wan-strict pause 5' \
    "$TMPDIR/99-troubleshooting.md" \
    "WAN-strict troubleshooting uses the actual bounded-pause helper"
assert_grep_fixed 'owns only `on|off|status`; it has no pause action' \
    "$TMPDIR/99-troubleshooting.md" \
    "WAN-strict troubleshooting documents the toggle helper's exact verbs"
assert_not_grep 'noid-toggle-wan-strict pause' \
    "$TMPDIR/99-troubleshooting.md" \
    "unsupported WAN-strict pause command cannot return"
assert_not_grep_extended 'proton0|am\.i\.mullvad\.net|DNS servers should be VPN-internal' \
    "$TMPDIR/99-troubleshooting.md" \
    "VPN troubleshooting has no provider- or address-shape assumption"
assert_grep_fixed 'review/redact it before uploading' \
    "$TMPDIR/99-troubleshooting.md" \
    "support evidence is locally reviewed and redacted"
assert_not_grep 'uname -a' "$TMPDIR/99-troubleshooting.md" \
    "support guidance does not expose the host name through uname -a"
assert_grep_fixed 'sudo chronyc tracking' "$TMPDIR/00-architecture.md" \
    "architecture diagnostics account for the restricted command socket"
assert_not_grep '^[[:space:]]*chronyc tracking$' "$TMPDIR/00-architecture.md" \
    "architecture has no unprivileged chronyc diagnostic"
assert_grep_fixed 'chrony with 6 operator-supported public/production EU NTS' \
    "$TMPDIR/00-architecture.md" \
    "architecture records the production-status-gated NTS set"
assert_grep_fixed 'declaratively offline until gateway/XDP readiness' \
    "$TMPDIR/00-architecture.md" \
    "architecture records the NTS startup traffic boundary"
assert_grep_fixed 'A dated' "$TMPDIR/00-architecture.md" \
    "architecture records dated external-dependency evidence"
assert_grep_fixed 'permanent reliability claim' "$TMPDIR/00-architecture.md" \
    "architecture does not freeze mutable NTS reliability"
assert_not_grep 'chrony with 12 EU NTS servers' "$TMPDIR/00-architecture.md" \
    "architecture has no stale 12-source claim"
assert_grep_fixed '132 ABI-complete auditd rules' \
    "$TMPDIR/00-architecture.md" \
    "architecture: audit rule count and ABI-complete contract match M12"
assert_grep_fixed 'auditd/auparse complete-event desktop notifications' \
    "$TMPDIR/00-architecture.md" \
    "architecture: notification transport matches M12"
assert_grep_fixed 'for 16 keyed integrity categories' \
    "$TMPDIR/00-architecture.md" \
    "architecture: popup-key count matches the expanded M12 critical set"
assert_grep_fixed 'handles 16 reviewed keyed' \
    "$TMPDIR/99-troubleshooting.md" \
    "troubleshooting popup-key count matches M12"
assert_not_grep 'handles 15 reviewed keyed' \
    "$TMPDIR/99-troubleshooting.md" \
    "stale audit popup-key count cannot return"
assert_grep_fixed 'noid-toggle-audit-notify status' \
    "$TMPDIR/99-troubleshooting.md" \
    "troubleshooting exposes plugin delivery health"
assert_grep_fixed 'sudo auditctl --signal state' \
    "$TMPDIR/99-troubleshooting.md" \
    "troubleshooting refreshes auditd's detailed plugin-state file"
assert_grep_fixed '/run/audit/auditd.state' \
    "$TMPDIR/99-troubleshooting.md" \
    "auditd state signal remains paired with its generated state file"
assert_grep_fixed '`auditctl -s` reports the shorter kernel audit status' \
    "$TMPDIR/99-troubleshooting.md" \
    "troubleshooting distinguishes kernel status from auditd plugin metrics"
assert_not_grep_extended 'watches `/var/log/audit/audit.log` via `tail -F`|firing on AVCs' \
    "$TMPDIR/99-troubleshooting.md" \
    "troubleshooting has no retired tail/AVC popup claim"
assert_grep_fixed '### GNOME Software shows only Flatpaks; how do I browse Fedora RPMs?' \
    "$TMPDIR/99-troubleshooting.md" \
    "troubleshooting exposes the intentional Fedora-RPM one-shot"
assert_grep_fixed '/usr/local/bin/noid-gnome-software-rpm' \
    "$TMPDIR/99-troubleshooting.md" \
    "troubleshooting names the exact Fedora-RPM helper"
assert_grep_fixed 'all enabled DNF' "$TMPDIR/99-troubleshooting.md" \
    "troubleshooting does not imply an official-Fedora-only repository filter"
assert_grep_fixed 'checks every 250 ms for at most 90 seconds' \
    "$TMPDIR/99-troubleshooting.md" \
    "troubleshooting explains the bounded RPM complete-quit spinner"
assert_grep_fixed 'The monitor calls `g_application_hold()`' \
    "$TMPDIR/99-troubleshooting.md" \
    "troubleshooting records GNOME Software's upstream lifetime hold"
assert_grep_fixed '**Quit completely** (German: **Vollständig beenden**)' \
    "$TMPDIR/99-troubleshooting.md" \
    "troubleshooting exposes the native desktop complete-quit action"
assert_grep_fixed 'gnome-software --quit' "$TMPDIR/99-troubleshooting.md" \
    "troubleshooting uses GNOME Software's supported graceful quit path"
assert_grep_fixed '/usr/local/bin/noid-gnome-software-quit' \
    "$TMPDIR/99-troubleshooting.md" \
    "troubleshooting names the complete graceful idle-release helper"
assert_grep_fixed 'has no inactivity timeout' "$TMPDIR/99-troubleshooting.md" \
    "troubleshooting records the Fedora DNF daemon lifetime root cause"
assert_grep_fixed 'no dynamic package-manager Session.' \
    "$TMPDIR/99-troubleshooting.md" \
    "troubleshooting explains the backend stop's fail-closed boundary"
assert_grep_fixed '`sudo -n` rule' "$TMPDIR/99-troubleshooting.md" \
    "troubleshooting guarantees the desktop action is noninteractive"
assert_not_grep 'pkill -u.*gnome-software' "$TMPDIR/99-troubleshooting.md" \
    "troubleshooting does not recommend force-killing GNOME Software jobs"
assert_grep_fixed 'alone does not decide this: Fedora and third-party repositories can provide' \
    "$TMPDIR/99-troubleshooting.md" \
    "GNOME Software removal is tied to AppStream metadata, not repo origin"
assert_not_grep 'third-party repo.*have no catalog' \
    "$TMPDIR/99-troubleshooting.md" \
    "third-party RPMs are not categorically denied AppStream metadata"
assert_grep_fixed 'sudo dnf remove --assumeno "$PACKAGE"' \
    "$TMPDIR/99-troubleshooting.md" \
    "package removal is previewed before mutation"
assert_grep_fixed 'sudoedit /etc/default/earlyoom' \
    "$TMPDIR/99-troubleshooting.md" \
    "troubleshooting points at the shipped earlyoom EnvironmentFile"
assert_grep_fixed '`EARLYOOM_ARGS`' "$TMPDIR/99-troubleshooting.md" \
    "troubleshooting names the effective earlyoom argument variable"
assert_grep_fixed 'sudo systemctl restart earlyoom' \
    "$TMPDIR/99-troubleshooting.md" \
    "troubleshooting applies threshold changes through the maintained unit"
assert_grep_fixed 'Higher percentages kill earlier;' \
    "$TMPDIR/99-troubleshooting.md" \
    "earlyoom guidance explains the threshold trade-off"
assert_grep_fixed 'cat -- "/proc/$EARLYOOM_PID/cmdline"' \
    "$TMPDIR/99-troubleshooting.md" \
    "earlyoom guidance verifies the effective running command line"
assert_not_grep '/etc/systemd/system/earlyoom\.service\.d/' \
    "$TMPDIR/99-troubleshooting.md" \
    "invented earlyoom drop-in tuning path cannot return"
assert_grep_fixed 'cat > /etc/default/earlyoom' "$M27_FILE" \
    "troubleshooting path is anchored to M27's shipped configuration"
assert_grep_fixed 'EARLYOOM_ARGS="-m 5 -s 5' "$M27_FILE" \
    "troubleshooting variable is anchored to M27's effective arguments"

# --- 27-performance ownership and no-hype boundary -------------------------

for marker in "zram-generator-defaults" "tuned-ppd" \
              "NoID Privacy does not ship BBR/fq" \
              "Measure instead of guessing" \
              "SELinux, audit, IOMMU, CPU mitigations"; do
    assert_grep_fixed "$marker" "$TMPDIR/27-performance.md" \
        "27-performance: '$marker' present"
done
assert_grep_fixed 'No `/etc/udev/rules.d/60-noid-iosched.rules` override is installed' \
    "$TMPDIR/27-performance.md" \
    "27-performance documents vendor scheduler ownership"
assert_grep_fixed 'No NoID Privacy zram override is installed' \
    "$TMPDIR/27-performance.md" \
    "27-performance documents vendor zram ownership"
assert_grep_fixed 'No unconditional Intel HWP dynamic-boost write is made' \
    "$TMPDIR/27-performance.md" \
    "27-performance documents kernel/tuned CPU ownership"
assert_grep_fixed 'internal `noid-balanced` child profiles retain Fedora' \
    "$TMPDIR/27-performance.md" \
    "27-performance documents the built-in-governor error boundary"
assert_grep_fixed 'net.hadess.PowerProfiles ActiveProfile' \
    "$TMPDIR/27-performance.md" \
    "27-performance uses the actually shipped D-Bus verification surface"
assert_not_grep 'powerprofilesctl get' "$TMPDIR/27-performance.md" \
    "27-performance does not instruct use of an unshipped conflicting CLI"
assert_not_grep_extended 'up to [0-9]+%|battery impact <|sweet spot of|scheduler = pure overhead' \
    "$TMPDIR/27-performance.md" \
    "27-performance contains no unretained performance claims"
assert_grep_fixed 'M17 defaults GNOME idle auto-suspend to off on AC and battery without' \
    "$TMPDIR/27-performance.md" \
    "27-performance records the agent-workflow suspend default"
assert_grep_fixed 'users can re-enable it in GNOME Settings' \
    "$TMPDIR/27-performance.md" \
    "27-performance keeps the suspend default user-adjustable"

# --- 99-troubleshooting structural markers -------------------------------

for kw in "Decision tree" "noid-status" "systemctl --failed" \
          "audit2allow" "audit2why" "AIDE" "Forgot LUKS" \
          "emergency.target" "snapshot rollback" "block-lan-out" \
          "Reporting a real bug"; do
    assert_grep_fixed "$kw" "$TMPDIR/99-troubleshooting.md" \
        "99-troubleshoot: '$kw' present"
done
assert_grep_fixed 'systemctl --user --failed' \
    "$TMPDIR/99-troubleshooting.md" \
    "failure triage covers the user service manager"
assert_grep_fixed 'sudo firewall-cmd --get-log-denied' \
    "$TMPDIR/99-troubleshooting.md" \
    "firewall triage checks the actual LogDenied policy"
assert_grep_fixed 'firewalld `LogDenied=off`' \
    "$TMPDIR/99-troubleshooting.md" \
    "firewall triage explains why per-packet drop tags are absent"
assert_grep_fixed 'sudo journalctl -b -t noid-lan-topology --no-pager' \
    "$TMPDIR/99-troubleshooting.md" \
    "firewall triage uses the real topology-controller evidence"
assert_grep_fixed 'instead of expecting a `block-lan-out_DROP`' \
    "$TMPDIR/99-troubleshooting.md" \
    "stale firewall tag is named only as an expectation to avoid"
assert_not_grep '| `block-lan-out_DROP` |' \
    "$TMPDIR/99-troubleshooting.md" \
    "stale firewall packet-tag table row cannot return"

# Cross-references to actual shipped docs — NOT dead links
for link in "01-getting-started.md" "06-vpn-setup.md" "11-dns-custom.md" \
            "11-time-recovery.md" \
            "14-usbguard.md" "16-firefox-hardening.md" \
            "19-nvidia-drivers.md" "20-rollback-recovery.md" \
            "24-firmware-updates.md" "28-local-ai.md" "00-cheatsheet.md" \
            "02-system-security.md" "03-firewall-zones.md"; do
    assert_grep_fixed "$link" "$TMPDIR/99-troubleshooting.md" \
        "99-troubleshoot: cross-ref to $link"
done

# Boot recovery advice MUST warn that rescue.target/emergency.target
# provide no maintenance shell on this image (root account locked,
# SULOGIN_FORCE unset) and MUST document the multi-user.target text-login
# ladder as the supported path. init=/bin/bash appears only as the
# documented last resort together with the autorelabel caveat.
if grep -qF 'DO NOT use' "$TMPDIR/99-troubleshooting.md" && \
   grep -qF 'no maintenance shell' "$TMPDIR/99-troubleshooting.md" && \
   grep -qF 'systemd.unit=multi-user.target' "$TMPDIR/99-troubleshooting.md" && \
   grep -qE 'init=/bin/bash|rd\.emergency=shell|rd\.shell' "$TMPDIR/99-troubleshooting.md"; then
    _pass "99-troubleshoot: locked-root no-shell warning + text-login ladder present"
else
    _fail "99-troubleshoot: missing locked-root recovery-ladder contract"
fi
assert_grep_fixed '/.autorelabel' "$TMPDIR/99-troubleshooting.md" \
    "99-troubleshoot: init=/bin/bash last resort carries the autorelabel caveat"
assert_grep_fixed '`sync` and `/sbin/reboot -f`' \
    "$TMPDIR/99-troubleshooting.md" \
    "99-troubleshoot: forced last-resort reboot flushes writes first"
assert_grep_fixed 'systemd.mask=' "$TMPDIR/99-troubleshooting.md" \
    "99-troubleshoot: one-boot unit-mask recovery step documented"
assert_not_grep 'log in as root' "$TMPDIR/99-troubleshooting.md" \
    "99-troubleshoot: no root-login recovery instruction (root is locked)"
assert_grep_fixed "read -r -p 'Exact root snapshot ID to roll back to: ' SNAPSHOT_ID" \
    "$TMPDIR/99-troubleshooting.md" \
    "snapshot rollback discovers an exact user-selected ID"
assert_grep_fixed '[[ "$SNAPSHOT_ID" =~ ^[1-9][0-9]*$ ]]' \
    "$TMPDIR/99-troubleshooting.md" \
    "snapshot rollback validates the selected ID before privilege"
assert_not_grep 'noid-snap-rollback <N>' \
    "$TMPDIR/99-troubleshooting.md" \
    "snapshot rollback contains no active angle-bracket placeholder"

# SELinux troubleshooting must be root-cause first. audit2allow remains named
# only as a proposal boundary, not an automatic module generator.
assert_grep_fixed 'Wrong labels, unsupported paths, application configuration' \
    "$TMPDIR/99-troubleshooting.md" \
    "99-troubleshoot: SELinux root causes precede policy generation"
assert_grep_fixed 'sudo restorecon -n -v -- "$AFFECTED_PATH"' \
    "$TMPDIR/99-troubleshooting.md" \
    "99-troubleshoot: SELinux label repair is previewed before mutation"
assert_grep_fixed '`audit2allow` output is a proposal' \
    "$TMPDIR/99-troubleshooting.md" \
    "99-troubleshoot: generated policy is not treated as a security decision"
assert_not_grep 'audit2allow -M' "$TMPDIR/99-troubleshooting.md" \
    "99-troubleshoot: broad automatic audit2allow recipe is absent"
assert_grep_fixed "setenforce 0" "$TMPDIR/99-troubleshooting.md" \
    "99-troubleshoot: mentions setenforce 0 (to warn against it)"

# --- 00-architecture structural markers ----------------------------------

for kw in "Module structure (${functional_module_count} functional modules" "Silent-Machine" "Defense in depth" \
          "Neutral image" "Reversibility" "Source-of-truth" \
          "Threat model" "Dependency ordering" \
          "kickstart/snippets/" "noid-status" \
          "M40 audit-bundle" "M41 anaconda-"; do
    assert_grep_fixed "$kw" "$TMPDIR/00-architecture.md" \
        "architecture: '$kw' present"
done

# Architecture must document every sequential Module, not merely mention its
# number in the dependency-order code block.
for n in 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20 \
         21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37; do
    # Accept either "## XX" or "**XX " or "- **XX " pattern
    if grep -qE "(\*\*$n\s|^##+\s*$n\s|\*\*$n |\bModule $n\b)" \
            "$TMPDIR/00-architecture.md"; then
        _pass "architecture: Module $n referenced"
    else
        _fail "architecture: Module $n missing"
    fi
done
assert_grep_fixed "**37 sequentially-numbered Modules (M01-M37)**" \
    "$TMPDIR/00-architecture.md" \
    "architecture sequential inventory includes Module 37"
assert_grep_fixed \
    "${functional_module_count} functional modules + 99-finalize = ${snippet_count} kickstart snippets." \
    "$TMPDIR/00-architecture.md" \
    "architecture aggregate count matches snippet discovery"

# Cross-module ownership and package-policy pivots are load-bearing doc
# contracts. These assertions prevent the architecture aggregator from
# silently drifting back to pre-pivot ownership/counts.
assert_grep_fixed "22 LUKS + partitioning + mount-hardening" \
    "$TMPDIR/00-architecture.md" \
    "architecture: M22 includes LUKS and partitioning ownership"
assert_grep_fixed "23 networkmanager" "$TMPDIR/00-architecture.md" \
    "architecture: M23 section exists"
assert_grep_fixed "TunnelVision" "$TMPDIR/00-architecture.md" \
    "architecture: TunnelVision mitigation documented"
assert_grep_fixed '**05 lan-isolation**' "$TMPDIR/00-architecture.md" \
    "architecture M05 range start anchor exists"
assert_grep_fixed '**06 VPN zone safety layer**' "$TMPDIR/00-architecture.md" \
    "architecture M05 range end anchor exists"
if sed -n '/\*\*05 lan-isolation\*\*/,/\*\*06 VPN/p' \
        "$TMPDIR/00-architecture.md" | grep -qF 'TunnelVision'; then
    _fail "architecture: M05 must not claim M23 TunnelVision ownership"
else
    _pass "architecture: M05 does not claim M23 TunnelVision ownership"
fi
assert_grep_fixed "36 noid-network" "$TMPDIR/00-architecture.md" \
    "architecture: M36 application is categorized"
assert_grep_fixed 'noid-dns-mode` provides the atomic strict/opportunistic/off/reset selector' \
    "$TMPDIR/00-architecture.md" \
    "architecture assigns the DNS mutation boundary to M05"
assert_grep_fixed 'state-truthful global/physical DNS page' \
    "$TMPDIR/00-architecture.md" \
    "architecture assigns the DNS presentation boundary to M36"
assert_grep_fixed "formatted read-only WAN-strict, firewalld" \
    "$TMPDIR/00-architecture.md" \
    "architecture: M36 owns the formatted read-only policy-audit surfaces"
assert_grep_fixed "37 noid-tools" "$TMPDIR/00-architecture.md" \
    "architecture: M37 application is categorized"
assert_grep_fixed 'inventory, including the managed DNS transport selector' \
    "$TMPDIR/00-architecture.md" \
    "architecture keeps the Tools DNS row on the shared backend"
m08_mask_count=$(
    sed -n "/<<'MASK_LIST_EOF'$/,/^MASK_LIST_EOF$/p" "$M08_FILE" |
        sed '1d;$d' |
        grep -cE '^[a-zA-Z][a-zA-Z0-9_-]*(@)?\.(service|socket|timer|target|automount|mount)$' \
        || true
)
source_mask_count=$(
    {
        sed -n "/<<'MASK_LIST_EOF'$/,/^MASK_LIST_EOF$/p" "$M08_FILE" |
            sed '1d;$d' |
            sed '/^[[:space:]]*#/d;/^[[:space:]]*$/d' |
            sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
        sed -n \
            's/^[[:space:]]*systemctl mask[[:space:]][[:space:]]*//p' \
            "$M05_FILE" "$M11_FILE" "$M18_FILE" "$M24_FILE" |
            sed 's/[[:space:]]*#.*$//' |
            tr '[:space:]' '\n' |
            sed -n -E \
                '/^[A-Za-z0-9_.@-]+\.(service|socket|timer|target|automount|mount|path)$/p'
        sed -n '/STEP 2c: Disable automatic binfmt_misc/,/^[[:space:]]*done$/p' \
            "$M21_FILE" |
            sed -n 's/^[[:space:]]*for unit in \(.*\); do$/\1/p' |
            tr '[:space:]' '\n' |
            sed -n -E \
                '/^[A-Za-z0-9_.@-]+\.(service|socket|timer|target|automount|mount|path)$/p'
    } | sort -u | wc -l
)
assert_eq 82 "$m08_mask_count" \
    "architecture owner M08 retains the reviewed 82-mask set"
assert_eq 96 "$source_mask_count" \
    "architecture cross-module unique mask union remains 96"
assert_grep_fixed 'unique total is 96' "$KS_FILE" \
    "M31 maintainer header records the reviewed mask union"
assert_not_grep 'unique total is 93' "$KS_FILE" \
    "M31 maintainer header cannot retain the stale mask union"
assert_grep_fixed "**08 service-minimization** — ${m08_mask_count} systemd units" \
    "$TMPDIR/00-architecture.md" \
    "architecture M08 count is derived from the current owner"
assert_grep_fixed "→ **${source_mask_count} source-" \
    "$TMPDIR/00-architecture.md" \
    "architecture unique mask total is derived from all current owners"
assert_not_grep_extended '87 systemd units masked in M08|→ \*\*98 source-' \
    "$TMPDIR/00-architecture.md" \
    "stale mask inventory cannot return"
assert_grep_fixed "reviewed optional/default-package exclusions" \
    "$TMPDIR/00-architecture.md" \
    "architecture delegates M26 package counts to the owning module"
assert_not_grep_extended '[0-9]+ Tier-1 additions|[0-9]+ documented optional/default-package exclusions' \
    "$TMPDIR/00-architecture.md" \
    "architecture does not duplicate mutable M26 package counts"
assert_grep_fixed '**31 user-docs-tier-c** (this Module) — 99-troubleshooting +' \
    "$TMPDIR/00-architecture.md" \
    "architecture has the M31 documentation inventory"
for inventory_doc in 00-architecture 27-performance threat-model scope \
                     post-quantum-readiness performance-profile licensing; do
    assert_grep_fixed "$inventory_doc" "$TMPDIR/00-architecture.md" \
        "M31 architecture inventory includes $inventory_doc"
done
assert_grep_fixed 'gnome-extensions-autostart' \
    "$TMPDIR/00-architecture.md" \
    "architecture inventories M29's fourth Tier-A document"
assert_grep_fixed \
    '# Shipped Markdown target: /usr/share/doc/noid-privacy/gnome-extensions-autostart.md' \
    "$M29_FILE" "M29 document inventory is anchored to its source owner"
assert_grep_fixed 'adopter Modules enumerated by `99-finalize`' \
    "$TMPDIR/00-architecture.md" \
    "architecture describes health stamps by the maintained adopter set"
assert_grep_fixed '`EXPECTED_STAMPS`' "$TMPDIR/00-architecture.md" \
    "architecture points health-stamp discovery at M99's canonical list"
assert_not_grep 'Modules from 29+' "$TMPDIR/00-architecture.md" \
    "architecture has no false Module-29 health-stamp floor"
assert_not_grep 'Modules ≥29' "$TMPDIR/00-architecture.md" \
    "architecture has no stale numeric health-stamp floor"
assert_grep_fixed '"16:firefox"' "$M99_FILE" \
    "health-stamp documentation is anchored below Module 29"
assert_grep_fixed '"28:local-ai-docs"' "$M99_FILE" \
    "health-stamp documentation includes the second pre-M29 adopter"
assert_grep_fixed '`openssh-server` is excluded, so no inbound SSH server ships' \
    "$TMPDIR/00-architecture.md" \
    "architecture states the actual absent SSH-server boundary"
assert_not_grep 'SSH daemon disabled + masked' \
    "$TMPDIR/00-architecture.md" \
    "architecture does not misstate absent sshd as masked"
assert_grep_fixed '`openssh-server` is absent; mDNS/wsdd/Samba are not exposed' \
    "$TMPDIR/threat-model.md" \
    "threat model states the actual absent SSH-server boundary"
assert_not_grep 'SSH is masked by default' "$TMPDIR/threat-model.md" \
    "threat model does not misstate absent sshd as masked"
assert_not_grep 'reverted the modular-libvirt masks' \
    "$TMPDIR/00-architecture.md" \
    "architecture does not contradict M08's retained modular-libvirt masks"
help_topic_loop=$(
    sed -n '/^for topic in threat-model scope post-quantum-readiness \\/,/^done$/p' \
        "$KS_FILE"
)
for topic in threat-model scope post-quantum-readiness \
             performance-profile licensing; do
    if grep -qw -- "$topic" <<< "$help_topic_loop"; then
        _pass "M31 noid-help verification loop includes $topic"
    else
        _fail "M31 noid-help verification loop omits $topic"
    fi
done
assert_grep_fixed \
    'env PAGER=true /usr/local/bin/noid-help "$topic"' \
    "$KS_FILE" "M31 opens every canonical topic through noid-help"
assert_not_grep 'Every hardening setting can be toggled off' \
    "$TMPDIR/00-architecture.md" \
    "architecture does not claim universal one-click reversibility"
assert_grep_fixed 'This is not universal or necessarily one-click' \
    "$TMPDIR/00-architecture.md" \
    "architecture scopes reversibility to controls with documented opt-outs"
assert_grep_fixed "42 before 99" "$TMPDIR/00-architecture.md" \
    "architecture: M42 retention ordering constraint documented"
assert_grep_fixed 'loadable modules receive dual modprobe enforcement, while 8 built-ins' \
    "$TMPDIR/00-architecture.md" \
    "architecture: loadable and built-in module classes stay distinct"
assert_grep_fixed 'recorded without being miscounted as effective blocks' \
    "$TMPDIR/00-architecture.md" \
    "architecture: built-in/absent identities are not advertised as blocks"
assert_grep_fixed 'exact permanent kernel neighbour pin for the' \
    "$TMPDIR/00-architecture.md" \
    "architecture names M04's actual gateway enforcement"
assert_grep_fixed 'M04 owns no nftables ARP mirror' \
    "$TMPDIR/00-architecture.md" \
    "architecture does not resurrect the retired hookless M04 table"
assert_not_grep 'nftables IP-MAC binding' "$TMPDIR/00-architecture.md" \
    "retired M04 IP-MAC binding claim stays absent"
assert_grep_fixed 'sysctl default-off + per-physical pre-up/live enforcement with' \
    "$TMPDIR/00-architecture.md" \
    "architecture states the real IPv6 default-off layers"
assert_not_grep 'IPv6 disable: kernel cmdline' "$TMPDIR/00-architecture.md" \
    "architecture invents no IPv6 kernel-command-line layer"
assert_grep_fixed 'Just Perfection GNOME Shell extension v36 — GPL-3.0-only' \
    "$TMPDIR/licensing.md" \
    "licensing inventory includes the pinned build-time extension"
assert_grep_fixed 'VSCodium (`codium` RPM) — MIT, with bundled third-party notices' \
    "$TMPDIR/licensing.md" \
    "licensing inventory classifies the non-Fedora vendor RPM"
assert_grep_fixed 'https://kspp.github.io/' "$TMPDIR/licensing.md" \
    "licensing acknowledgments use the current KSPP project page"
assert_not_grep 'https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project' \
    "$TMPDIR/licensing.md" \
    "retired KSPP wiki redirect cannot return"

master_order=$(
    sed -n 's|^%include snippets/\([0-9][0-9]*[[:alpha:]]*\)-.*|\1|p' \
        "$MASTER_FILE" | paste -sd' ' -
)
documented_order=$(
    awk '
        /^## Dependency ordering$/ { section = 1; next }
        section && /^```$/ {
            if (code) {
                exit
            }
            code = 1
            next
        }
        section && code { printf "%s ", $0 }
    ' "$TMPDIR/00-architecture.md" |
        sed 's/[[:space:]]*→[[:space:]]*/ /g; s/[[:space:]][[:space:]]*/ /g; s/^ //; s/ $//'
)
assert_eq "$master_order" "$documented_order" \
    "architecture dependency order is derived from current master.ks"

# Must mention AMD PSP companion doc (not only Intel)
assert_grep_fixed "15-amd-psp-hardware-layer.md" \
    "$TMPDIR/00-architecture.md" \
    "architecture: AMD PSP companion doc referenced"

# Trade-off transparency section must list the 4 documented trade-offs
for tradeoff in "/home" "/dev/shm" "/var/tmp" "mei+mei_me"; do
    assert_grep_fixed "$tradeoff" "$TMPDIR/00-architecture.md" \
        "architecture: trade-off '$tradeoff' documented"
done

# --- Stamp pattern -----------------------------------------------------------

assert_grep_fixed "stamp-31-user-docs-tier-c.ok" "$KS_FILE" \
    "M31 stamp path"
assert_grep_fixed "module=31" "$KS_FILE" "M31 stamp declares module=31"

guard_line=$(grep -n 'fails.*-gt 0' "$KS_FILE" | head -1 | cut -d: -f1 || true)
invalidate_line=$(grep -nF \
    '# M31_HEALTH_INVALIDATION_BEGIN' "$KS_FILE" | cut -d: -f1 || true)
first_payload_line=$(grep -nF \
    'install -d -m 0755 -o root -g root -- "$DOC_DIR"' \
    "$KS_FILE" | cut -d: -f1 || true)
publish_line=$(grep -nF \
    '# M31_HEALTH_PUBLICATION_BEGIN' "$KS_FILE" | cut -d: -f1 || true)
complete_line=$(grep -nF \
    'log "=== Module 31 User Documentation Tier C complete ==="' \
    "$KS_FILE" | cut -d: -f1 || true)
if [ -n "$guard_line" ] && [ -n "$invalidate_line" ] \
   && [ -n "$first_payload_line" ] && [ -n "$publish_line" ] \
   && [ -n "$complete_line" ] \
   && [ "$invalidate_line" -lt "$first_payload_line" ] \
   && [ "$guard_line" -lt "$publish_line" ] \
   && [ "$publish_line" -lt "$complete_line" ]; then
    _pass "M31 retires old health before mutation and publishes only after verification"
else
    _fail "M31 health-stamp ordering is not failure-atomic"
fi

# Execute the exact production document-publication function through its
# success path, each final gate, both sides of a failing rename, and the
# signal window immediately after the canonical inode appears.
m31_doc_root="$TMPDIR/doc-publication"
m31_doc_state="$m31_doc_root/state"
m31_doc_bin="$m31_doc_root/bin"
m31_doc_harness="$m31_doc_root/publish.sh"
m31_doc_uid=$(id -u)
m31_doc_gid=$(id -g)
mkdir -p "$m31_doc_state" "$m31_doc_bin"

cat > "$m31_doc_bin/restorecon" <<'M31_DOC_RESTORECON_EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "${FAKE_RESTORECON_TERM:-0}" -eq 1 ]; then
    kill -TERM "$PPID"
    exit 0
fi
[ "${FAKE_RESTORECON_FAIL:-0}" -ne 1 ]
M31_DOC_RESTORECON_EOF
cat > "$m31_doc_bin/matchpathcon" <<'M31_DOC_MATCHPATHCON_EOF'
#!/usr/bin/env bash
[ "${FAKE_MATCHPATHCON_FAIL:-0}" -ne 1 ]
M31_DOC_MATCHPATHCON_EOF
cat > "$m31_doc_bin/mv" <<'M31_DOC_MV_EOF'
#!/usr/bin/env bash
set -euo pipefail
case "${FAKE_MV_MODE:-ok}" in
    before) exit 1 ;;
    after)
        /usr/bin/mv "$@"
        exit 1
        ;;
    ok) exec /usr/bin/mv "$@" ;;
    *) exit 2 ;;
esac
M31_DOC_MV_EOF
cat > "$m31_doc_bin/sync" <<'M31_DOC_SYNC_EOF'
#!/usr/bin/env bash
set -euo pipefail
case "${FAKE_SYNC_FAIL:-}" in
    staged)
        case "$*" in
            *'/.published.md.'*) exit 1 ;;
        esac
        ;;
    final)
        case "$*" in
            *'/published.md'*) exit 1 ;;
        esac
        ;;
esac
exit 0
M31_DOC_SYNC_EOF
chmod 0700 "$m31_doc_bin/restorecon" "$m31_doc_bin/matchpathcon" \
    "$m31_doc_bin/mv" "$m31_doc_bin/sync"

{
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
        'PHASE=test' 'log() { :; }' 'die() { exit 1; }' \
        "DOC_DIR=$m31_doc_state" \
        'DOC_TMP=' 'DOC_PUBLICATION_ACTIVE=0' \
        'DOC_PUBLISHED_TARGET=' 'DOC_PUBLISHED_ID=' \
        'STAMP_TMP=' 'STAMP_PUBLICATION_ACTIVE=0' \
        "STAMP_DIR=$m31_doc_state" \
        'STAMP="$STAMP_DIR/unused-stamp"'
    sed -n '/^cleanup() {$/,/^}$/p' "$KS_FILE"
    sed -n '/^publish_doc() {$/,/^}$/p' "$KS_FILE" |
        sed -e "s/chown root:root --/chown $m31_doc_uid:$m31_doc_gid --/" \
            -e "s/0:0:644:1/$m31_doc_uid:$m31_doc_gid:644:1/"
    printf '%s\n' \
        'trap cleanup EXIT' \
        "trap 'exit 130' INT" \
        "trap 'exit 143' TERM" \
        'DOC_TMP=$(mktemp "$DOC_DIR/.published.md.XXXXXXXX")' \
        'printf "%s\n" "${M31_DOC_CONTENT:-new}" > "$DOC_TMP"' \
        'publish_doc "$DOC_DIR/published.md"' \
        'trap - EXIT INT TERM'
} > "$m31_doc_harness"
chmod 0700 "$m31_doc_harness"

printf '%s\n' old > "$m31_doc_state/published.md"
assert_cmd_failure "M31 staged-sync failure preserves the prior document" \
    env PATH="$m31_doc_bin:$PATH" FAKE_SYNC_FAIL=staged \
        "$m31_doc_harness"
assert_grep_fixed old "$m31_doc_state/published.md" \
    "M31 staged-sync failure leaves the prior canonical inode untouched"

assert_cmd_failure "M31 pre-rename failure preserves the prior document" \
    env PATH="$m31_doc_bin:$PATH" FAKE_MV_MODE=before \
        "$m31_doc_harness"
assert_grep_fixed old "$m31_doc_state/published.md" \
    "M31 pre-rename failure cannot delete an unrelated prior target"

assert_cmd_failure "M31 post-rename failure retires the unverified inode" \
    env PATH="$m31_doc_bin:$PATH" FAKE_MV_MODE=after \
        "$m31_doc_harness"
if [ ! -e "$m31_doc_state/published.md" ]; then
    _pass "M31 post-rename failure leaves no unverified canonical document"
else
    _fail "M31 post-rename failure leaves no unverified canonical document"
fi

assert_cmd_failure "M31 final restorecon failure retires the published inode" \
    env PATH="$m31_doc_bin:$PATH" FAKE_RESTORECON_FAIL=1 \
        "$m31_doc_harness"
if [ ! -e "$m31_doc_state/published.md" ]; then
    _pass "M31 final restorecon failure leaves no unverified document"
else
    _fail "M31 final restorecon failure leaves no unverified document"
fi

assert_cmd_failure "M31 final label mismatch retires the published inode" \
    env PATH="$m31_doc_bin:$PATH" FAKE_MATCHPATHCON_FAIL=1 \
        "$m31_doc_harness"
if [ ! -e "$m31_doc_state/published.md" ]; then
    _pass "M31 final label mismatch leaves no unverified document"
else
    _fail "M31 final label mismatch leaves no unverified document"
fi

assert_cmd_failure "M31 final sync failure retires the published inode" \
    env PATH="$m31_doc_bin:$PATH" FAKE_SYNC_FAIL=final \
        "$m31_doc_harness"
if [ ! -e "$m31_doc_state/published.md" ]; then
    _pass "M31 final sync failure leaves no unverified document"
else
    _fail "M31 final sync failure leaves no unverified document"
fi

assert_cmd_failure "M31 TERM after rename retires the published inode" \
    env PATH="$m31_doc_bin:$PATH" FAKE_RESTORECON_TERM=1 \
        "$m31_doc_harness"
if [ ! -e "$m31_doc_state/published.md" ]; then
    _pass "M31 signal window leaves no unverified canonical document"
else
    _fail "M31 signal window leaves no unverified canonical document"
fi

assert_cmd_success "M31 publishes a document after every final gate" \
    env PATH="$m31_doc_bin:$PATH" M31_DOC_CONTENT=verified \
        "$m31_doc_harness"
assert_grep_fixed verified "$m31_doc_state/published.md" \
    "M31 successful publication retains the verified document"
assert_eq "$m31_doc_uid:$m31_doc_gid:644:1" \
    "$(stat -Lc '%u:%g:%a:%h' "$m31_doc_state/published.md")" \
    "M31 successful publication retains exact file metadata"
if [ -z "$(find "$m31_doc_state" -maxdepth 1 \
        -name '.published.md.*' -print -quit)" ]; then
    _pass "M31 publication paths leave no staged document behind"
else
    _fail "M31 publication paths leave no staged document behind"
fi

# Execute the exact production health-boundary blocks under every material
# publication failure.
m31_stamp_root="$TMPDIR/health-stamp"
m31_stamp_state="$m31_stamp_root/state"
m31_stamp_bin="$m31_stamp_root/bin"
m31_stamp_invalidate="$m31_stamp_root/invalidate.sh"
m31_stamp_publish="$m31_stamp_root/publish.sh"
m31_stamp_uid=$(id -u)
m31_stamp_gid=$(id -g)
mkdir -p "$m31_stamp_bin"

cat > "$m31_stamp_bin/restorecon" <<'M31_STAMP_RESTORECON_EOF'
#!/usr/bin/env bash
set -euo pipefail
target="${!#}"
case "${FAKE_RESTORECON_FAIL:-}" in
    all) exit 1 ;;
    final)
        case "$target" in
            */stamp-31-user-docs-tier-c.ok) exit 1 ;;
        esac
        ;;
esac
exit 0
M31_STAMP_RESTORECON_EOF
cat > "$m31_stamp_bin/matchpathcon" <<'M31_STAMP_MATCHPATHCON_EOF'
#!/usr/bin/env bash
exit 0
M31_STAMP_MATCHPATHCON_EOF
cat > "$m31_stamp_bin/mv" <<'M31_STAMP_MV_EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "${FAKE_MV_FAIL:-0}" -eq 1 ]; then
    exit 1
fi
exec /usr/bin/mv "$@"
M31_STAMP_MV_EOF
chmod 0700 "$m31_stamp_bin/restorecon" \
    "$m31_stamp_bin/matchpathcon" "$m31_stamp_bin/mv"

{
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
        'PHASE=test' 'log() { :; }' 'die() { exit 1; }' \
        "STAMP_DIR=$m31_stamp_state" \
        'STAMP="$STAMP_DIR/stamp-31-user-docs-tier-c.ok"'
    sed -n \
        '/^# M31_HEALTH_INVALIDATION_BEGIN$/,/^# M31_HEALTH_INVALIDATION_END$/p' \
        "$KS_FILE" |
        sed -e "s|/var/lib/noid-privacy|$m31_stamp_state|g" \
            -e "s/-o root -g root/-o $m31_stamp_uid -g $m31_stamp_gid/" \
            -e "s/0:0:755/$m31_stamp_uid:$m31_stamp_gid:755/"
} > "$m31_stamp_invalidate"
{
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
        'PHASE=test' 'log() { :; }' 'die() { exit 1; }' \
        "STAMP_DIR=$m31_stamp_state" \
        'STAMP="$STAMP_DIR/stamp-31-user-docs-tier-c.ok"' \
        'DOC_TMP=' 'STAMP_TMP=' 'STAMP_PUBLICATION_ACTIVE=0' \
        'checks=52' 'fails=0'
    sed -n '/^cleanup() {$/,/^}$/p' "$KS_FILE"
    printf '%s\n' 'trap cleanup EXIT'
    sed -n \
        '/^# M31_HEALTH_PUBLICATION_BEGIN$/,/^# M31_HEALTH_PUBLICATION_END$/p' \
        "$KS_FILE" |
        sed -e "s/chown root:root/chown $m31_stamp_uid:$m31_stamp_gid/" \
            -e "s/0:0:755/$m31_stamp_uid:$m31_stamp_gid:755/" \
            -e "s/0:0:644:1/$m31_stamp_uid:$m31_stamp_gid:644:1/"
} > "$m31_stamp_publish"
chmod 0700 "$m31_stamp_invalidate" "$m31_stamp_publish"

mkdir -m 0755 "$m31_stamp_state"
printf '%s\n' 'module=31' 'name=user-docs-tier-c' 'status=ok' \
    > "$m31_stamp_state/stamp-31-user-docs-tier-c.ok"
assert_cmd_success "M31 rerun invalidates its prior build-success stamp" \
    env PATH="$m31_stamp_bin:$PATH" "$m31_stamp_invalidate"
if [ ! -e "$m31_stamp_state/stamp-31-user-docs-tier-c.ok" ]; then
    _pass "M31 old success evidence is absent before document publication"
else
    _fail "M31 old success evidence is absent before document publication"
fi

chmod 0777 "$m31_stamp_state"
printf '%s\n' 'must-survive' \
    > "$m31_stamp_state/stamp-31-user-docs-tier-c.ok"
assert_cmd_failure "M31 rejects shared state-directory metadata drift" \
    env PATH="$m31_stamp_bin:$PATH" "$m31_stamp_invalidate"
assert_eq "$m31_stamp_uid:$m31_stamp_gid:777" \
    "$(stat -c '%u:%g:%a' "$m31_stamp_state")" \
    "M31 does not normalize drifted shared-directory metadata"
assert_grep_fixed 'must-survive' \
    "$m31_stamp_state/stamp-31-user-docs-tier-c.ok" \
    "M31 does not traverse a drifted shared state boundary"
rm "$m31_stamp_state/stamp-31-user-docs-tier-c.ok"
chmod 0755 "$m31_stamp_state"

assert_cmd_failure "M31 rejects a health-stamp candidate label failure" \
    env PATH="$m31_stamp_bin:$PATH" FAKE_RESTORECON_FAIL=all \
        "$m31_stamp_publish"
if [ ! -e "$m31_stamp_state/stamp-31-user-docs-tier-c.ok" ] \
   && [ -z "$(find "$m31_stamp_state" -maxdepth 1 \
        -name '.stamp-31-user-docs-tier-c.ok.*' -print -quit)" ]; then
    _pass "M31 candidate-label failure leaves no plausible health evidence"
else
    _fail "M31 candidate-label failure leaves no plausible health evidence"
fi

assert_cmd_failure "M31 retires a stamp after final-label failure" \
    env PATH="$m31_stamp_bin:$PATH" FAKE_RESTORECON_FAIL=final \
        "$m31_stamp_publish"
if [ ! -e "$m31_stamp_state/stamp-31-user-docs-tier-c.ok" ]; then
    _pass "M31 final-label failure removes the published success stamp"
else
    _fail "M31 final-label failure removes the published success stamp"
fi

assert_cmd_failure "M31 rejects an atomic health-stamp rename failure" \
    env PATH="$m31_stamp_bin:$PATH" FAKE_MV_FAIL=1 "$m31_stamp_publish"
if [ ! -e "$m31_stamp_state/stamp-31-user-docs-tier-c.ok" ] \
   && [ -z "$(find "$m31_stamp_state" -maxdepth 1 \
        -name '.stamp-31-user-docs-tier-c.ok.*' -print -quit)" ]; then
    _pass "M31 rename failure leaves no stamp or staged candidate"
else
    _fail "M31 rename failure leaves no stamp or staged candidate"
fi

assert_cmd_success "M31 publishes exact health evidence after all gates" \
    env PATH="$m31_stamp_bin:$PATH" "$m31_stamp_publish"
assert_grep_fixed 'module=31' \
    "$m31_stamp_state/stamp-31-user-docs-tier-c.ok"
assert_grep_fixed 'name=user-docs-tier-c' \
    "$m31_stamp_state/stamp-31-user-docs-tier-c.ok"
assert_grep_fixed 'checks_passed=52' \
    "$m31_stamp_state/stamp-31-user-docs-tier-c.ok"
assert_grep_fixed 'checks_total=52' \
    "$m31_stamp_state/stamp-31-user-docs-tier-c.ok"
assert_eq 8 \
    "$(wc -l < "$m31_stamp_state/stamp-31-user-docs-tier-c.ok")" \
    "M31 published health stamp has the exact eight-line schema"

# --- Yelp decision doc (should exist in project root docs/ dir) ---------

# The decision was documented in docs/decision-yelp-mallard-skip.md.
# This test checks that the decision doc exists — the M31 design says
# yelp is intentionally skipped.
DECISION_DOC="$PROJECT_ROOT/docs/decision-yelp-mallard-skip.md"
assert_file_exists "$DECISION_DOC" "yelp skip decision doc exists"
assert_grep_fixed "SKIP yelp/Mallard" "$DECISION_DOC" \
    "yelp decision doc says SKIP"
assert_not_grep_extended \
    'set up `mallard-cache.xml`|requires correct `mallard-cache.xml`' \
    "$DECISION_DOC" \
    "yelp decision does not invent a hand-maintained runtime cache contract"
assert_not_grep 'projectmallard.org' "$DECISION_DOC" \
    "yelp decision carries no dead Project Mallard site link"
assert_grep_fixed 'https://gitlab.gnome.org/GNOME/yelp-tools' "$DECISION_DOC" \
    "yelp decision points to the maintained GNOME tool source"

test_finish

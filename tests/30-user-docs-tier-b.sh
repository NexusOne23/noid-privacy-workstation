#!/bin/bash
# shellcheck disable=SC2016
# 30-user-docs-tier-b — verify M30 invariants + regression tests for the
# Tier-B source-of-truth audit findings.
#
# Background: several Tier-B doc claims (mask state, masked-service names,
# drop-in filenames, CLI syntax) had drifted from the kickstart source.
# This test locks the corrected claims to their source-of-truth.
#
# What this test catches:
#   - Regression to fabricated service names in 08-masked-services.md
#   - Drop-in filename drift in 11-dns-custom.md (must be 99-privacy.conf)
#   - Fabricated /etc/audit/audit-notify-suppress.conf path reappearing
#   - Destructive firewalld factory reset or incomplete captive-portal bypass
#   - Drift of chrony NTS server list vs M11 source
#   - noid-help/noid CLI regressing or omitting the user-facing live inventory
#   - Stamp pattern drift (write-before-fails-guard)

set -euo pipefail
# shellcheck source=tests/lib.sh
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/30-user-docs-tier-b.ks"
M26_FILE="$PROJECT_ROOT/kickstart/snippets/26-package-set.ks"
M05_FILE="$PROJECT_ROOT/kickstart/snippets/05-lan-isolation.ks"
M08_FILE="$PROJECT_ROOT/kickstart/snippets/08-service-minimization.ks"
M11_FILE="$PROJECT_ROOT/kickstart/snippets/11-dns-ntp.ks"
M18_FILE="$PROJECT_ROOT/kickstart/snippets/18-flatpak-sandboxing.ks"
M21_FILE="$PROJECT_ROOT/kickstart/snippets/21-kernel-module-blacklist.ks"
M24_FILE="$PROJECT_ROOT/kickstart/snippets/24-firmware-fwupd.ks"

test_start "30-user-docs-tier-b"

if [ ! -f "$KS_FILE" ]; then
    _fail "M30 snippet missing: $KS_FILE"
    test_finish
    exit 1
fi

assert_grep_fixed 'set -euo pipefail' "$KS_FILE" \
    "M30 post script fails on unset variables and pipeline errors"
assert_grep_fixed \
    "sudo grep -cE '^-?[a-z]+\\.' /etc/sysctl.d/99-hardening.conf" \
    "$KS_FILE" "shipped Tier-B M02 check counts the ignore-on-error directive"
if grep -qF -- "sudo grep -c '^[a-z].*=' /etc/sysctl.d/99-hardening.conf" \
        "$KS_FILE"; then
    _fail "shipped Tier-B M02 check cannot regress to a 100-line count"
else
    _pass "shipped Tier-B M02 check cannot regress to a 100-line count"
fi
assert_grep_fixed 'restorecon is required for fail-closed SELinux labeling' \
    "$KS_FILE" "M30 requires SELinux labeling before publishing payloads"
assert_grep_fixed 'restorecon -F -- "$target"' "$KS_FILE" \
    "each document/executable receives its policy-owned SELinux context"
assert_grep_fixed 'matchpathcon -V "$target"' "$KS_FILE" \
    "each published document/executable label is verified against policy"
assert_grep_fixed 'sync -- "$DOC_TMP"' "$KS_FILE" \
    "document bytes are synchronized before atomic publication"
assert_grep_fixed 'sync -- "$target" "$DOC_DIR"' "$KS_FILE" \
    "published document and parent entry are synchronized before success"
assert_grep_fixed 'sync -- "$BIN_TMP"' "$KS_FILE" \
    "executable bytes are synchronized before atomic publication"
assert_grep_fixed 'sync -- "$target" "$BIN_DIR"' "$KS_FILE" \
    "published executable and parent entry are synchronized before success"
assert_grep_fixed 'matchpathcon -V "$dir"' "$KS_FILE" \
    "shared payload directories retain their policy-owned labels"
assert_grep_fixed 'existing metadata differs from root:root 0755' "$KS_FILE" \
    "M30 rejects existing payload-directory metadata drift"
if python3 - "$KS_FILE" <<'M30_DIRECTORY_STRUCTURE_EOF'
from pathlib import Path
import sys

lines = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
try:
    start = lines.index('for dir in "$DOC_DIR" "$BIN_DIR"; do')
    end = lines.index("done", start + 1)
except ValueError:
    raise SystemExit(1)
block = lines[start:end + 1]
required = (
    '    if [ -e "$dir" ] || [ -L "$dir" ]; then',
    '            || die "$dir existing metadata differs from root:root 0755"',
    "    else",
    '        install -d -m 0755 -o root -g root -- "$dir"',
    "    fi",
)
try:
    positions = [block.index(line) for line in required]
except ValueError:
    raise SystemExit(1)
install_count = sum("install -d" in line for line in block)
raise SystemExit(0 if positions == sorted(positions) and install_count == 1 else 1)
M30_DIRECTORY_STRUCTURE_EOF
then
    _pass "M30 creates only absent payload directories and rejects existing drift"
else
    _fail "M30 creates only absent payload directories and rejects existing drift"
fi
assert_grep_fixed "trap 'exit 130' INT" "$KS_FILE" \
    "M30 converts interruption into the cleanup path"
assert_grep_fixed "trap 'exit 143' TERM" "$KS_FILE" \
    "M30 converts termination into the cleanup path"
assert_grep_fixed 'trap - EXIT INT TERM' "$KS_FILE" \
    "M30 clears every installed cleanup/signal trap after final success"
assert_grep_fixed 'restorecon -F -- "$STAMP"' "$KS_FILE" \
    "M30 health stamp receives its complete SELinux context"
if python3 - "$KS_FILE" <<'M30_RESTORECON_GUARD_EOF'
from pathlib import Path
import re
import sys

text = Path(sys.argv[1]).read_text(encoding="utf-8")
fail_open = re.search(
    r'(?m)^[ \t]*(?:if[ \t]+![ \t]+)?'
    r'(?:/usr/(?:s?bin)/)?restorecon\b[^\n]*'
    r'(?:\\\n[ \t]*)?\|\|[ \t]*true\b',
    text,
)
raise SystemExit(1 if fail_open else 0)
M30_RESTORECON_GUARD_EOF
then
    _pass "M30 cannot report success after SELinux labeling failed"
else
    _fail "M30 cannot report success after SELinux labeling failed"
fi
assert_grep_fixed "stat -Lc '%u:%g:%a:%h'" "$KS_FILE" \
    "M30 verifies ownership, exact mode and hardlink count"
assert_grep_fixed '[ ! -L "$path" ]' "$KS_FILE" \
    "M30 payload verification rejects symbolic links"
assert_grep_fixed 'mv -fT -- "$DOC_TMP" "$target"' "$KS_FILE" \
    "M30 publishes documents atomically without following destination links"
assert_grep_fixed 'mv -fT -- "$BIN_TMP" "$target"' "$KS_FILE" \
    "M30 publishes executables atomically without following destination links"
assert_grep_fixed 'bash -n "$BIN_TMP"' "$KS_FILE" \
    "M30 syntax-checks executables before publishing"
assert_not_grep_extended '(^|[;&|[:space:]])eval([;&|[:space:]]|$)' \
    "$KS_FILE" "M30 verification does not evaluate command strings"
assert_not_grep_extended '^cat > /usr/share/doc/noid-privacy/|^cat > /usr/local/bin/' \
    "$KS_FILE" "M30 has no direct trust-boundary target writers"
assert_grep_fixed 'prior Module 30 health stamp is absent' "$KS_FILE" \
    "old M30 success evidence is retired before payload publication"
assert_grep_fixed 'verify_m30_health_stamp()' "$KS_FILE" \
    "staged and final M30 evidence share one exact validator"
assert_grep_fixed 'STAMP_PUBLICATION_ACTIVE=1' "$KS_FILE" \
    "published M30 evidence remains removable through every final gate"
assert_grep_fixed 'matchpathcon -V "$STAMP_TMP"' "$KS_FILE" \
    "M30 validates the staged stamp SELinux context"
assert_grep_fixed 'matchpathcon -V "$STAMP"' "$KS_FILE" \
    "M30 validates the final stamp SELinux context"

TMPDIR="$(mktemp -d "${TMPDIR:-/var/tmp}/noid-tier-b.XXXXXX")"
trap 'rm -rf "$TMPDIR"' EXIT

# --- Extract all 6 Tier-B docs -----------------------------------------------

declare -A docs
docs[02-system-security.md]=SYSCTL_EOF
docs[03-firewall-zones.md]=FW_EOF
docs[05-lan-isolation.md]=LAN_EOF
docs[08-masked-services.md]=SVC_EOF
docs[11-dns-custom.md]=DNS_EOF
docs[00-cheatsheet.md]=CHEAT_EOF

for doc in "${!docs[@]}"; do
    marker="${docs[$doc]}"
    out="$TMPDIR/$doc"
    extract_heredoc "$KS_FILE" "$marker" "$out" || true

    # Every doc must be >3KB (our general min); cheatsheet >4KB
    if [ "$doc" = "00-cheatsheet.md" ]; then
        assert_file_min_size "$out" 4096 "$doc extracted >4KB"
    else
        assert_file_min_size "$out" 3072 "$doc extracted >3KB"
    fi
    assert_grep_fixed "# Shipped Markdown target: /usr/share/doc/noid-privacy/$doc" \
        "$KS_FILE" "$doc declares its shipped target"
    assert_grep_fixed "# Shipped Markdown heredoc: $marker" \
        "$KS_FILE" "$doc declares its atomic heredoc"
done
assert_grep_fixed 'chown root:root -- "$DOC_TMP"' "$KS_FILE" \
    "all document temporaries converge to root ownership before publication"
assert_grep_fixed 'matchpathcon -V "$path"' "$KS_FILE" \
    "final payload verification includes the active SELinux policy"

# Every runnable Bash fence must parse as copied and must not contain an active
# prose placeholder. Comments may describe placeholders because they are inert.
if python3 - "$TMPDIR" <<'PY'
from pathlib import Path
import re
import subprocess
import sys

doc_dir = Path(sys.argv[1])
failures = []
count = 0
for path in sorted(doc_dir.glob("*.md")):
    content = path.read_text()
    blocks = re.findall(
        r"^```bash\s*\n(.*?)^```\s*$",
        content,
        flags=re.MULTILINE | re.DOTALL,
    )
    for index, body in enumerate(blocks, 1):
        count += 1
        result = subprocess.run(
            ["bash", "-n", "-c", body],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode:
            failures.append(
                f"{path.name} Bash fence {index}: {result.stderr.strip()}"
            )
        for line_number, line in enumerate(body.splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            if re.search(r"<[A-Za-z][^>]*>", line):
                failures.append(
                    f"{path.name} Bash fence {index}, line {line_number}: "
                    f"active angle-bracket placeholder: {line}"
                )

if count != 63:
    failures.append(f"expected 63 Bash fences, found {count}")
if failures:
    print("\n".join(failures), file=sys.stderr)
    raise SystemExit(1)
PY
then
    _pass "all 63 Tier-B Bash fences parse and contain no active prose placeholders"
else
    _fail "Tier-B Bash fence is not directly executable as documented"
fi

# The documented cross-module mask total is the unique union of M08's
# authoritative heredoc, direct M05/M11/M18/M24 mask calls and M21's native
# binfmt activation loop. Keep the test
# derived from the owners so the aggregator cannot retain a stale duplicate.
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
assert_eq "96" "$source_mask_count" \
    "reviewed unique source mask union remains 96"
assert_grep_fixed \
    "Source-deployed unique mask total across all NoID Privacy Modules = **${source_mask_count}**" \
    "$TMPDIR/08-masked-services.md" \
    "08-masked derives its total from the current source owners"
assert_grep_fixed 'can exceed that source-deployed total' \
    "$TMPDIR/08-masked-services.md" \
    "08-masked does not duplicate the moving mask total"
assert_not_grep '93 NoID Privacy-source masks' \
    "$TMPDIR/08-masked-services.md" \
    "08-masked cannot restore the stale aggregate count"
assert_not_grep 'deploy 93 unique masks' "$KS_FILE" \
    "M30 source header cannot retain the stale aggregate count"
assert_grep_fixed 'deploy 96 unique masks' "$KS_FILE" \
    "M30 source header pins the reviewed aggregate count"
assert_not_grep 'the package IS installed' \
    "$TMPDIR/08-masked-services.md" \
    "08-masked does not claim every masked unit has an installed owner"
assert_grep_fixed 'M08 exclusions with persistent defense-in-depth masks' \
    "$TMPDIR/08-masked-services.md" \
    "08-masked explains masks whose owning packages were excluded"
for excluded_package in \
        -plocate -PackageKit -PackageKit-command-not-found -passim \
        -abrt -abrt-addon-ccpp -abrt-addon-kerneloops \
        -abrt-addon-pstoreoops -abrt-addon-vmcore -abrt-addon-xorg \
        -abrt-cli -abrt-console-notification -abrt-dbus -abrt-desktop \
        -abrt-gui -abrt-gui-libs -abrt-libs -abrt-tui \
        -gssproxy -sssd -sssd-common -sssd-client -sssd-kcm -nfs-utils \
        -fprintd -fprintd-pam; do
    assert_grep_extended \
        "(^|[[:space:]])${excluded_package}([[:space:]]|$)" \
        "$TMPDIR/08-masked-services.md" \
        "08-masked inventories excluded masked package: $excluded_package"
done

# --- Regression: 08-masked-services.md fabricated-service blacklist ---------

# These 9 service names must be ABSENT from the doc — they are not in
# M08's MASK_LIST, so listing any of them would be a doc-vs-source drift.
fabricated_in_08=(
    "nmb.service"
    "smb.service"
    "multipathd.service"
    "rpcbind.service"
    "nfs-client.target"
    "thermald.service"
    "dnf-automatic.timer"
    "flatpak-update-check.timer"
    "packagekit-offline-update.service"
)
for svc in "${fabricated_in_08[@]}"; do
    escaped_svc=${svc//./\\.}
    assert_not_grep_extended "^${escaped_svc}([[:space:]]|$)" \
        "$TMPDIR/08-masked-services.md" \
        "08-masked: '$svc' NOT present (regression guard)"
done

# --- Regression: 08-masked-services.md — real M08 units must be listed ------

# Every authoritative M08 unit must appear literally. This is intentionally
# complete rather than a spot-check because the document promises an exact
# inventory and missing optional libvirt families are operationally material.
while IFS= read -r svc; do
    assert_grep_fixed "$svc" "$TMPDIR/08-masked-services.md" \
        "08-masked: '$svc' present (matches M08 source)"
done < <(
    sed -n "/<<'MASK_LIST_EOF'$/,/^MASK_LIST_EOF$/p" "$M08_FILE" |
        sed '1d;$d' |
        sed '/^[[:space:]]*#/d;/^[[:space:]]*$/d' |
        sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
)

for svc in flatpak-add-fedora-repos.service \
        proc-sys-fs-binfmt_misc.automount systemd-binfmt.service; do
    assert_grep_fixed "$svc" "$TMPDIR/08-masked-services.md" \
        "cross-module mask is attributed in the complete inventory: $svc"
done

# --- Regression: 08-masked-services.md — correct Module attribution -------

# Services masked by M05 (not M08) must be in the M05 section
for svc in "avahi-daemon.service" "wsdd.service" "cups.service" "cups-browsed.service"; do
    assert_grep_fixed "$svc" "$TMPDIR/08-masked-services.md" \
        "08-masked: '$svc' documented (M05-masked)"
done
# fwupd-refresh.timer is masked by M24, must be attributed correctly
assert_grep_fixed "fwupd-refresh.timer" "$TMPDIR/08-masked-services.md" \
    "08-masked: fwupd-refresh.timer listed"
assert_grep_fixed "Module 24" "$TMPDIR/08-masked-services.md" \
    "08-masked: M24 attribution present"

# mdraid recovery must preserve Fedora's conditional monitor/template set
# without pretending that service activation converts the root topology.
for unit in mdmonitor.service mdmonitor-oneshot.service \
            mdadm-grow-continue@.service; do
    assert_not_grep "^${unit}[[:space:]]" "$TMPDIR/08-masked-services.md" \
        "08-masked: local mdraid safety unit is absent from the mask inventory: $unit"
done
assert_grep_fixed 'No unmask step is required.' "$TMPDIR/08-masked-services.md" \
    "08-masked: mdraid recovery retains Fedora conditional units"
assert_grep_fixed '`mdadm-grow-continue@.service` is a template' \
    "$TMPDIR/08-masked-services.md" \
    "08-masked: recovery documents the real reshape template"
assert_grep_fixed 'mdmonitor-oneshot.timer' "$TMPDIR/08-masked-services.md" \
    "08-masked: mdraid recovery enables the reminder timer"
assert_grep_fixed 'Root-on-mdraid is **not** enabled by those commands' \
    "$TMPDIR/08-masked-services.md" \
    "08-masked: service recovery is not conflated with root topology"
assert_grep_fixed 'M21 has no global mdraid Dracut omission' \
    "$TMPDIR/08-masked-services.md" \
    "08-masked: recovery doc matches current M21 topology policy"

# --- Regression: 11-dns-custom.md — resolved drop-in filename --------------

# The actual filename in M05 is 99-privacy.conf, not 00-noid.conf.
# If the doc reverts to 00-noid.conf that's a regression.
assert_grep_fixed "99-privacy.conf" "$TMPDIR/11-dns-custom.md" \
    "11-dns: drop-in filename is 99-privacy.conf (matches M05)"
assert_not_grep "00-noid.conf" "$TMPDIR/11-dns-custom.md" \
    "11-dns: fabricated 00-noid.conf NOT present (regression guard)"
assert_not_grep 'Wired connection 1' "$TMPDIR/11-dns-custom.md" \
    "11-dns: per-connection example never assumes a local profile name"
assert_grep_fixed "read -r -p 'Exact NetworkManager profile name: ' DNS_PROFILE" \
    "$TMPDIR/11-dns-custom.md" \
    "11-dns: per-connection example requires one exact selected profile"
assert_grep_fixed 'nmcli --get-values GENERAL.NAME --escape no' \
    "$TMPDIR/11-dns-custom.md" \
    "11-dns: selected profile existence is verified through NetworkManager"
assert_grep_fixed 'sudo nmcli --wait 30 connection up "$DNS_PROFILE"' \
    "$TMPDIR/11-dns-custom.md" \
    "11-dns: profile change uses bounded native reactivation"
assert_not_grep 'number >99' "$TMPDIR/11-dns-custom.md" \
    "11-dns: systemd drop-in order is not misdescribed as numeric"
assert_grep_fixed 'sorts lexically after `99-privacy.conf`' \
    "$TMPDIR/11-dns-custom.md" \
    "11-dns: systemd drop-in ordering follows lexical precedence"
assert_grep_extended '^DNS=$' "$TMPDIR/11-dns-custom.md" \
    "11-dns: global provider override resets the accumulated DNS list"
assert_grep_extended '^FallbackDNS=$' "$TMPDIR/11-dns-custom.md" \
    "11-dns: global provider override resets the accumulated fallback list"
assert_grep_fixed '2606:4700:4700::1001#one.one.one.one' \
    "$TMPDIR/11-dns-custom.md" \
    "11-dns: Cloudflare example includes its complete current IPv6 pair"
assert_grep_fixed 'FallbackDNS=1.1.1.1#one.one.one.one 1.0.0.1#one.one.one.one' \
    "$TMPDIR/11-dns-custom.md" \
    "11-dns: replacement fallback stays with the explicitly selected provider"
assert_grep_fixed "preserving M05's no-unannounced-third-party" \
    "$TMPDIR/11-dns-custom.md" \
    "11-dns: replacement fallback preserves the image privacy policy"
assert_grep_fixed 'Refusing to overwrite existing policy' \
    "$TMPDIR/11-dns-custom.md" \
    "11-dns: local resolved examples refuse to clobber existing policy"
assert_not_grep_extended 'tee .*resolved\.conf\.d' \
    "$TMPDIR/11-dns-custom.md" \
    "11-dns: resolved examples do not overwrite policy through tee"
assert_grep_fixed 'developers.cloudflare.com/1.1.1.1/privacy/public-dns-resolver/' \
    "$TMPDIR/11-dns-custom.md" \
    "11-dns: Cloudflare example links the resolver-specific privacy commitment"

# --- Regression: 11-dns-custom.md — correct chrony NTS servers -------------

# M11 uses IPv4-only + 6 EU institutional servers (2-2-2, all-unicast).
# Fabricated system76 servers must NOT reappear.
for srv in "ptbtime1.ptb.de" "ptbtime4.ptb.de" \
           "lul1.nts.netnod.se" "mmo1.nts.netnod.se" \
           "ntppool1.time.nl" "ntppool2.time.nl"; do
    assert_grep_fixed "$srv" "$TMPDIR/11-dns-custom.md" \
        "11-dns: NTS server $srv listed (matches M11)"
done
assert_not_grep_extended \
    'ptbtime(2|3)\.ptb\.de|^(server )?(sth1|gbg1)\.nts\.netnod\.se' \
    "$TMPDIR/11-dns-custom.md" \
    "11-dns: retired duplicate-operator slots stay absent"
assert_grep_fixed 'Sources start declaratively `offline`' \
    "$TMPDIR/11-dns-custom.md" \
    "11-dns: pre-readiness NTS silence is documented"
assert_grep_fixed 'gateway/XDP postcondition' \
    "$TMPDIR/11-dns-custom.md" \
    "11-dns: event-driven source release boundary is documented"
assert_grep_fixed 'iburst nts ipv4 maxpoll 11 offline' \
    "$TMPDIR/11-dns-custom.md" \
    "11-dns: custom source example preserves declarative offline startup"
assert_not_grep '^server ntppool[34]\.time\.nl ' "$TMPDIR/11-dns-custom.md" \
    "11-dns: SIDN pre-production endpoints are not configured"
assert_grep_fixed '/usr/share/doc/noid-privacy/11-nts-sources.tsv' \
    "$TMPDIR/11-dns-custom.md" \
    "11-dns: dated operator-status manifest is documented"
assert_grep_fixed '**pre-production**' "$TMPDIR/11-dns-custom.md" \
    "11-dns: SIDN 3/4 operator classification is explicit"
assert_grep_fixed 'status can change; the release gate rechecks' \
    "$TMPDIR/11-dns-custom.md" \
    "11-dns: mutable public dependencies are not promised permanently"
# regression guard: dead UNIZG-FER servers removed (lame-PTR stall root)
assert_not_grep "ntp.hr" "$TMPDIR/11-dns-custom.md" \
    "11-dns: dead ntp.hr servers NOT listed (regression guard)"
# regression guard: anycast entry replaced by unicast site servers
assert_not_grep "server nts.netnod.se iburst" "$TMPDIR/11-dns-custom.md" \
    "11-dns: anycast nts.netnod.se server line NOT present (regression guard)"
for srv in "virginia.time.system76.com" "ohio.time.system76.com" \
           "new-york-city.time.system76.com"; do
    assert_not_grep "$srv" "$TMPDIR/11-dns-custom.md" \
        "11-dns: fabricated '$srv' NOT present (regression guard)"
done

# DNSSEC mode = allow-downgrade, not just "yes"
assert_grep_fixed "allow-downgrade" "$TMPDIR/11-dns-custom.md" \
    "11-dns: DNSSEC=allow-downgrade documented (matches M05)"
assert_grep_fixed '`DNSOverTLS=yes` is the strict authenticated global and physical image' \
    "$TMPDIR/11-dns-custom.md" \
    "11-dns: strict authenticated global/physical DoT default is explicit"
assert_grep_fixed 'downgrade-capable and permits DNS/53' \
    "$TMPDIR/11-dns-custom.md" "11-dns: compatibility fallback behavior is documented"
assert_grep_fixed 'selects opportunistic DoT' \
    "$TMPDIR/11-dns-custom.md" "11-dns: unset VPN/private links use best-effort DoT"
assert_grep_fixed 'cannot authenticate the resolver in this mode' \
    "$TMPDIR/11-dns-custom.md" "11-dns: opportunistic transport does not overclaim authentication"
assert_grep_fixed 'policy label alone does not prove' \
    "$TMPDIR/11-dns-custom.md" "11-dns: policy and observed transport are distinguished"
assert_grep_fixed 'network.trr.mode=5' "$TMPDIR/11-dns-custom.md" \
    "11-dns: Firefox defaults to the provider-compatible system/VPN resolver"
assert_grep_fixed 'survives Firefox restarts and Update All' \
    "$TMPDIR/11-dns-custom.md" \
    "11-dns: user-selected Secure DNS persists across supported reconciliation"
assert_not_grep 'TRR Mode 3\|DoH-only' "$TMPDIR/11-dns-custom.md" \
    "11-dns: retired forced browser DoH is absent"
assert_grep_fixed 'force validation off' "$TMPDIR/11-dns-custom.md" \
    "11-dns: active DNSSEC downgrade is explicit"
assert_grep_fixed 'authenticated proof of insecure delegation' \
    "$TMPDIR/11-dns-custom.md" \
    "11-dns: strict DNSSEC is not confused with universal domain signing"
assert_grep_fixed 'sudo noid-dns-mode strict' "$TMPDIR/11-dns-custom.md" \
    "11-dns: authenticated fail-closed global DoT has the native selector"
assert_grep_fixed 'sudo noid-dns-mode opportunistic' "$TMPDIR/11-dns-custom.md" \
    "11-dns: compatibility mode has an explicit supported return path"
assert_grep_fixed 'sudo noid-dns-mode off' "$TMPDIR/11-dns-custom.md" \
    "11-dns: plaintext recovery is explicit rather than silently implied"
assert_grep_fixed 'sudo noid-dns-mode reset' "$TMPDIR/11-dns-custom.md" \
    "11-dns: selector override can return to the image policy"
assert_grep_fixed 'sudo systemctl reload systemd-resolved' \
    "$TMPDIR/11-dns-custom.md" \
    "11-dns: manual drop-ins use the native link-preserving reload path"
assert_not_grep 'systemctl restart systemd-resolved' \
    "$TMPDIR/11-dns-custom.md" \
    "11-dns: manual DNS changes never tear down resolve1 link objects"
assert_grep_fixed 'zzz-strict-dnssec.conf' "$TMPDIR/11-dns-custom.md" \
    "11-dns: separate strict DNSSEC opt-in has an explicit reversible file"
assert_grep_fixed 'it never rewrites tunnel, bridge or provider profiles' \
    "$TMPDIR/11-dns-custom.md" \
    "11-dns: global/physical selector does not claim provider-link ownership"
assert_grep_fixed '02-noid-connection-defaults.conf' \
    "$TMPDIR/11-dns-custom.md" \
    "11-dns: tunnel DoT is attributed to the NoID Privacy connection default"
assert_grep_fixed 'explicit profile value wins over that default' \
    "$TMPDIR/11-dns-custom.md" \
    "11-dns: an explicit provider transport overrides the image default"
assert_not_grep 'provider-selected transport\|profiles are never rewritten' \
    "$TMPDIR/11-dns-custom.md" \
    "11-dns: tunnel DoT is neither misattributed nor universally unset"
assert_grep_fixed 'stays inside that tunnel' \
    "$TMPDIR/11-dns-custom.md" \
    "11-dns: non-DoT resolver advice names the tunnel transport boundary"
assert_grep_fixed 'NetworkManager connection.dns-over-tls' \
    "$TMPDIR/11-dns-custom.md" "11-dns: per-link enum contract links to NetworkManager"
assert_grep_fixed 'updates managed physical' "$TMPDIR/11-dns-custom.md" \
    "11-dns: selector documents its NetworkManager physical-profile scope"
assert_not_grep 'zzz-strict-dns.conf' "$TMPDIR/11-dns-custom.md" \
    "11-dns: retired combined strict override is absent"
assert_not_grep 'hostname verification\|SNI verification\|~46%\|paranoia\|resolvectl dnsovertls yes' \
    "$TMPDIR/11-dns-custom.md" \
    "11-dns: hype, unsourced percentage and invalid linkless commands are absent"
assert_grep_fixed 'sudo noid-time-recovery set "$RECOVERY_UTC"' \
    "$TMPDIR/11-dns-custom.md" \
    "11-dns: dead-RTC recovery uses the local-VT helper with entered current UTC"
assert_not_grep '2026-07-13T18:42:00Z' "$TMPDIR/11-dns-custom.md" \
    "11-dns: recovery does not ship a stale timestamp"
assert_grep_fixed '/usr/share/doc/noid-privacy/11-time-recovery.md' \
    "$TMPDIR/11-dns-custom.md" \
    "11-dns: detailed authenticated recovery guide is linked"
assert_grep_fixed 'no authenticated measurement exists' \
    "$TMPDIR/11-dns-custom.md" \
    "11-dns: makestep dependency cycle is explained"
assert_grep_fixed 'It is not a simplistic three-of-ten vote' \
    "$TMPDIR/11-dns-custom.md" \
    "11-dns: minsources is not misdescribed as source agreement"
assert_grep_fixed 'This threshold is not an operator quorum' \
    "$TMPDIR/11-dns-custom.md" \
    "11-dns: minsources is not misdescribed as operator diversity"
assert_not_grep 'will be rejected by chrony\|NTS signs the NTP responses\|NTS over IPv6 is still flaky' \
    "$TMPDIR/11-dns-custom.md" \
    "11-dns: rejected-source, signature and unverified IPv6 claims are absent"
assert_grep_fixed '`chronyd-restricted.service` runs it as the `chrony` user' \
    "$TMPDIR/11-dns-custom.md" \
    "11-dns: Fedora restricted-client privilege boundary is documented"
assert_grep_fixed '`-F 2` fork/exec filter' \
    "$TMPDIR/11-dns-custom.md" \
    "11-dns: maintained seccomp level is documented without hype"
assert_not_grep 'sovereign-tier\|systemctl restart chronyd$\|^[[:space:]]*chronyc tracking' \
    "$TMPDIR/11-dns-custom.md" \
    "11-dns: hype, wrong service target and unprivileged socket examples are absent"
assert_grep_fixed 'sudo systemctl restart chronyd-restricted.service' \
    "$TMPDIR/11-dns-custom.md" \
    "11-dns: custom-source workflow restarts the enabled restricted unit"
assert_not_grep 'my-nts-server.example.com' "$TMPDIR/11-dns-custom.md" \
    "11-dns: custom-source workflow contains no active example hostname"
assert_grep_fixed "read -r -p 'Exact reviewed NTS hostname: ' NTS_HOST" \
    "$TMPDIR/11-dns-custom.md" \
    "11-dns: custom-source workflow requires an explicit reviewed hostname"
assert_grep_fixed 'NTS_HOST_RE=' "$TMPDIR/11-dns-custom.md" \
    "11-dns: custom-source workflow validates an FQDN without executing it"
assert_grep_fixed 'sudo noid-snap-pre "before adding custom NTS source $NTS_HOST"' \
    "$TMPDIR/11-dns-custom.md" \
    "11-dns: custom chrony edit has a pre-change rollback point"
assert_grep_fixed 'sudoedit /etc/chrony.conf' "$TMPDIR/11-dns-custom.md" \
    "11-dns: custom NTS source uses the reviewed editor boundary"
assert_grep_fixed 'noid-dns-diagnose' "$TMPDIR/11-dns-custom.md" \
    "11-dns: troubleshooting starts from the supported read-only diagnostic"
assert_not_grep 'ipv4.ignore-auto-dns no' "$TMPDIR/11-dns-custom.md" \
    "11-dns: troubleshooting does not silently re-enable DHCP/ISP DNS"
assert_not_grep 'for host in protonvpn.com' "$TMPDIR/11-dns-custom.md" \
    "11-dns: troubleshooting does not generate unrelated cache-warming traffic"

# --- Regression: 02-system-security.md — no fabricated suppress.conf ------

assert_not_grep "/etc/audit/audit-notify-suppress.conf" \
    "$TMPDIR/02-system-security.md" \
    "02-system: fabricated suppress.conf path NOT present (regression guard)"
assert_not_grep 'auditctl -a always,exclude' "$TMPDIR/02-system-security.md" \
    "02-system: immutable audit policy is not presented as runtime-mutable"
assert_grep_fixed 'runtime rule changes are rejected until reboot' \
    "$TMPDIR/02-system-security.md" \
    "02-system: auditd -e 2 limitation is stated correctly"
assert_grep_fixed 'records into the maintained auparse complete-event assembler' \
    "$TMPDIR/02-system-security.md" \
    "02-system: notification parser follows the maintained complete-event boundary"
assert_grep_fixed 'event AUID must match an unlocked active local graphical logind seat' \
    "$TMPDIR/02-system-security.md" \
    "02-system: notification paths cannot cross active-user/session boundaries"
assert_not_grep_extended 'Desktop notifications for AVC denials|tail -F' \
    "$TMPDIR/02-system-security.md" \
    "02-system: popup scope and transport are not overstated"
assert_grep_fixed 'Auditd (132 ABI-complete rules, immutable)' \
    "$TMPDIR/02-system-security.md" \
    "02-system: audit rule count and ABI-complete contract match M12"
assert_grep_fixed '16 reviewed keyed integrity-change' \
    "$TMPDIR/02-system-security.md" \
    "02-system: audit popup key count matches M12"
assert_grep_fixed '/boot/efi` is content-tracked' \
    "$TMPDIR/02-system-security.md" \
    "02-system: an ESP access denial is not dismissed as harmless"

# Value 1 is the kernel's irreversible-for-this-boot unprivileged-BPF state.
assert_grep_fixed "unprivileged_bpf_disabled=1" "$TMPDIR/02-system-security.md" \
    "02-system: irreversible bpf_disabled=1 matches M02"
assert_not_grep "unprivileged_bpf_disabled=2" "$TMPDIR/02-system-security.md" \
    "02-system: administrator-reversible value 2 is not documented as active"
assert_grep_fixed 'net.ipv4.tcp_timestamps=1' "$TMPDIR/02-system-security.md" \
    "02-system: maintained randomized TCP timestamp default is accurate"
assert_not_grep 'net.ipv4.tcp_timestamps=0' "$TMPDIR/02-system-security.md" \
    "02-system: retired timestamp-disable privacy patch is absent"
assert_grep_fixed 'retaining RFC 7323 RTT measurement and' \
    "$TMPDIR/02-system-security.md" \
    "02-system: timestamp reliability trade-off is not hidden"
assert_grep_fixed 'net.ipv4.ip_forward=0' "$TMPDIR/02-system-security.md" \
    "02-system: M07 forwarding parameter name is accurate"
assert_grep_fixed 'active libvirt routed/NAT' "$TMPDIR/02-system-security.md" \
    "02-system: runtime forwarding is correctly scoped to active virtualization"
assert_grep_fixed "grep -F 'net.ipv4.ip_forward = 0'" \
    "$TMPDIR/02-system-security.md" \
    "02-system: boot default is checked separately from runtime forwarding"
assert_grep_fixed 'sudo auditctl -l | wc -l' "$TMPDIR/02-system-security.md" \
    "02-system: loaded audit rule count comes from the rule-list interface"
assert_grep_fixed 'enabled=2 means immutable until reboot' \
    "$TMPDIR/02-system-security.md" \
    "02-system: audit status is not misrepresented as a rule counter"
assert_grep_fixed '/etc/sysctl.d/zzzz-local-security-exception.conf' \
    "$TMPDIR/02-system-security.md" \
    "02-system: persistent exception stays separate from image-owned policy"
assert_grep_fixed 'weakens KASLR' "$TMPDIR/02-system-security.md" \
    "02-system: debugger exception discloses the real security cost"
assert_not_grep 'default.accept_ra=0.*all.accept_ra=0' "$TMPDIR/02-system-security.md" \
    "02-system: privacy-network file is not confused with IPv6 RA policy"
assert_grep_fixed 'Generated rules can grant more access than intended.' \
    "$TMPDIR/02-system-security.md" \
    "02-system: audit2allow output is not presented as an automatic fix"
assert_grep_fixed 'fix a wrong label, packaging defect, configuration mismatch' \
    "$TMPDIR/02-system-security.md" \
    "02-system: SELinux troubleshooting is root-cause first"
assert_not_grep 'all pixbuf image rendering' "$TMPDIR/02-system-security.md" \
    "02-system: no unsupported universal Glycin rendering claim"

# --- Regression: 03-firewall-zones.md — topology and logging policy --------

assert_grep_fixed 'block-lan-out-vms.xml' "$TMPDIR/03-firewall-zones.md" \
    "03-firewall: derived VM-forwarding policy is documented"
assert_grep_fixed 'unmatched unsolicited inbound packets are silently' \
    "$TMPDIR/03-firewall-zones.md" \
    "03-firewall: DROP semantics preserve replies to host-initiated traffic"
assert_grep_fixed 'sudo noid-lan-allow --list' \
    "$TMPDIR/03-firewall-zones.md" \
    "03-firewall: LAN inventory uses its required privilege boundary"
assert_grep_fixed 'expected `--get-log-denied` result is `off`' \
    "$TMPDIR/03-firewall-zones.md" \
    "03-firewall: no-packet-log privacy posture is explicit"
assert_grep_fixed 'sudo journalctl -b -t noid-lan-topology' \
    "$TMPDIR/03-firewall-zones.md" \
    "03-firewall: diagnostics use the actual controller event source"
assert_not_grep 'block-lan-out_DROP' "$TMPDIR/03-firewall-zones.md" \
    "03-firewall: fabricated per-packet journal tag cannot return"

# --- Regression: 05-lan-isolation.md — ownership and escape hatches --------

assert_grep_fixed 'Module 23' "$TMPDIR/05-lan-isolation.md" \
    "05-lan: TunnelVision implementation is attributed to M23"
assert_not_grep 'This Module also configures NetworkManager' "$TMPDIR/05-lan-isolation.md" \
    "05-lan: M05 does not claim ownership of the M23 dispatcher"
assert_grep_fixed 'Direct private-IP connections do **not** bypass the policy' \
    "$TMPDIR/05-lan-isolation.md" \
    "05-lan: direct IP requires an explicit LAN exception"
assert_grep_fixed 'sudo noid-lan-allow --add 192.168.1.50 --direction outbound' \
    "$TMPDIR/05-lan-isolation.md" \
    "05-lan: exception is shown before the direct-IP example"
assert_grep_fixed '### Application, discovery and link-layer protocols' \
    "$TMPDIR/05-lan-isolation.md" \
    "05-lan: mixed protocol inventory is not mislabeled as Layer 7"
assert_grep_fixed 'sudo test -e /root/.nas-creds || sudo test -L /root/.nas-creds' \
    "$TMPDIR/05-lan-isolation.md" \
    "05-lan: credential creation refuses files and dangling symlinks"
awk '
    /^## Re-enabling Samba$/ { section=1; next }
    section && /^```bash$/ { capture=1; next }
    capture && /^```$/ { exit }
    capture { print }
' "$TMPDIR/05-lan-isolation.md" > "$TMPDIR/samba-fence.sh"
: > "$TMPDIR/samba-command.log"
assert_cmd_success "existing Samba credentials survive the pasted recipe" \
    env SAMBA_FENCE="$TMPDIR/samba-fence.sh" \
        SAMBA_LOG="$TMPDIR/samba-command.log" bash -c '
            sudo() {
                printf "sudo %s\\n" "$*" >> "$SAMBA_LOG"
                if [ "${1:-}" = test ]; then return 0; fi
                return 0
            }
            sudoedit() { printf "sudoedit %s\\n" "$*" >> "$SAMBA_LOG"; }
            source "$SAMBA_FENCE"
        '
assert_not_grep 'sudo install .* /root/.nas-creds' "$TMPDIR/samba-command.log" \
    "existing Samba credentials are never truncated"
assert_not_grep 'sudoedit /root/.nas-creds' "$TMPDIR/samba-command.log" \
    "existing Samba credentials are not replaced through the editor path"
assert_grep_fixed 'vers=3.1.1,seal' "$TMPDIR/05-lan-isolation.md" \
    "05-lan: SMB example requires current dialect plus transport encryption"
assert_not_grep 'vers=3.0' "$TMPDIR/05-lan-isolation.md" \
    "05-lan: SMB example does not cap negotiation at the older dialect"
assert_grep_fixed 'Things that still work by default:' \
    "$TMPDIR/05-lan-isolation.md" \
    "05-lan: default-working range start anchor exists"
assert_grep_fixed '## How to allow a specific device' \
    "$TMPDIR/05-lan-isolation.md" \
    "05-lan: default-working range end anchor exists"
if sed -n '/Things that still work by default:/,/## How to allow a specific device/p' \
        "$TMPDIR/05-lan-isolation.md" | \
        grep -qF -- '- Direct-IP connections'; then
    _fail "05-lan: direct private IP is not listed as default-working"
else
    _pass "05-lan: direct private IP is not listed as default-working"
fi

# --- Regression: 08-masked-services.md — exclusions and recovery -----------

assert_grep_fixed '-nss-mdns' "$TMPDIR/08-masked-services.md" \
    "08-masked: Avahi/mDNS exclusion list includes nss-mdns"
assert_grep_fixed '-pipewire-config-raop' "$TMPDIR/08-masked-services.md" \
    "08-masked: optional PipeWire AirPlay discovery is listed as excluded"
assert_grep_fixed '-pipewire-config-raop' "$M26_FILE" \
    "08-masked: PipeWire AirPlay exclusion is anchored to M26"
assert_grep_fixed 'sudo dnf install pipewire-config-raop' \
    "$TMPDIR/05-lan-isolation.md" \
    "05-lan: AirPlay discovery has a visible package opt-in"
assert_grep_fixed 'sudo dnf remove pipewire-config-raop' \
    "$TMPDIR/05-lan-isolation.md" \
    "05-lan: AirPlay discovery package opt-in has a visible undo"
assert_grep_fixed 'a protocol daemon or' \
    "$TMPDIR/05-lan-isolation.md" \
    "05-lan: userspace mDNS opt-in does not overclaim an XDP bypass"
assert_grep_fixed 'does not advertise a partial “enable Avahi” recipe' \
    "$TMPDIR/05-lan-isolation.md" \
    "05-lan: incomplete multicast enablement is rejected"
assert_not_grep '-gnome-bluetooth' "$TMPDIR/08-masked-services.md" \
    "08-masked: Bluetooth packages are not listed as excluded"
assert_not_grep 'dnf install -y gnome-bluetooth NetworkManager-bluetooth' \
    "$TMPDIR/08-masked-services.md" \
    "08-masked: Bluetooth opt-in does not reinstall present packages"
assert_grep_fixed 'three core units required for direct printer setup' \
    "$TMPDIR/08-masked-services.md" \
    "08-masked: printing recipe identifies the three direct-print units"
assert_grep_fixed "cups-browsed.service is M05's fourth CUPS-family mask" \
    "$TMPDIR/08-masked-services.md" \
    "08-masked: printing recipe accounts for M05's fourth CUPS mask"
assert_not_grep 'Unmask the THREE units M05 masked' \
    "$TMPDIR/08-masked-services.md" \
    "08-masked: printing recipe cannot misstate M05's mask count"
assert_grep_fixed '### F1 — Printing, SMB, and mDNS packages' \
    "$TMPDIR/08-masked-services.md" \
    "08-masked: mixed excluded-package group is labeled accurately"
assert_grep_fixed 'companion of retained `libsmbclient` (M26)' \
    "$TMPDIR/08-masked-services.md" \
    "08-masked: retained samba-common is not represented as excluded"
assert_not_grep '-samba-common' \
    "$TMPDIR/08-masked-services.md" \
    "08-masked: excluded-package block cannot absorb samba-common"
assert_grep_fixed 'samba-common stays installed as the packaging companion of retained libsmbclient' \
    "$TMPDIR/08-masked-services.md" \
    "08-masked: Samba install note names the retained package and owner"
assert_not_grep 'samba-common-libs stays installed\|pulled by gvfs' \
    "$TMPDIR/08-masked-services.md" \
    "08-masked: absent package and wrong dependency owner cannot return"
assert_not_grep 'eos-event-recorder-daemon' \
    "$TMPDIR/08-masked-services.md" \
    "08-masked: nonexistent EOS package is not represented as an M26 exclusion"
assert_grep_fixed '-evolution-ews-core' \
    "$TMPDIR/08-masked-services.md" \
    "08-masked: real optional EWS package remains in the exclusion inventory"
assert_grep_fixed 'samba-common' \
    <(sed -n '/^MUST_PRESENT=(/,/^)/p' "$M26_FILE") \
    "08-masked: retention claim is anchored to M26 MUST_PRESENT"
assert_grep_fixed "panel's raw radio switch does not update" \
    "$TMPDIR/08-masked-services.md" \
    "08-masked: GNOME radio UI is not presented as the root policy helper"
assert_not_grep_extended 'Audit 20[0-9]{2}|#[0-9]{2,}' \
    "$TMPDIR/08-masked-services.md" \
    "08-masked: numbered audit folklore is absent"
assert_not_grep 'systemctl is-system-running.*degraded' \
    "$TMPDIR/08-masked-services.md" \
    "08-masked: compatibility masks do not claim to cure degraded state"
assert_grep_fixed 'sudo systemctl unmask fwupd-refresh.timer fwupd-refresh.service' \
    "$TMPDIR/08-masked-services.md" \
    "08-masked: fwupd timer recovery unmasks both required units"
assert_grep_fixed 'every hour with a' "$TMPDIR/08-masked-services.md" \
    "08-masked: current Fedora fwupd refresh cadence is documented"
assert_not_grep 'weekly LVFS' "$TMPDIR/08-masked-services.md" \
    "08-masked: obsolete weekly fwupd cadence is absent"
assert_not_grep 'dnf install -y\|dnf remove -y' "$TMPDIR/05-lan-isolation.md" \
    "05-lan: package transactions remain reviewable"
assert_not_grep 'dnf install -y\|dnf remove -y' "$TMPDIR/08-masked-services.md" \
    "08-masked: package transactions remain reviewable"

# --- Regression: 02-system-security.md — pinned sysctl examples ------------

# Key sysctl values that must be in the doc
for kw in "kernel.kptr_restrict=2" "kernel.dmesg_restrict=1" "vm.mmap_rnd_bits=32" "user.max_user_namespaces=256"; do
    assert_grep_fixed "$kw" "$TMPDIR/02-system-security.md" \
        "02-system: $kw documented"
done

# --- Regression: 03-firewall-zones.md — preserve NoID Privacy policy --------

assert_grep_fixed 'Do **not** use `firewall-cmd --reset-to-defaults`' \
    "$TMPDIR/03-firewall-zones.md" \
    "03-firewall: warns that factory reset destroys NoID Privacy policy"
if grep -qE -- '^[[:space:]]*(sudo[[:space:]]+)?firewall-cmd[[:space:]]+--reset-to-defaults' \
        "$TMPDIR/03-firewall-zones.md"; then
    _fail "03-firewall: destructive factory-reset command is still runnable"
else
    _pass "03-firewall: no runnable factory-reset command"
fi

# --- Regression: 00-cheatsheet.md — captive portal fix -------------------

assert_grep_fixed 'sudo noid-lan-allow --add "$PORTAL_PEER" --direction outbound --temp 15' \
    "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet: captive portal prefers an exact temporary peer"
assert_grep_fixed 'sudo noid-lan-allow on' "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet: captive portal broad fallback uses the complete helper"
assert_grep_fixed 'sudo noid-lan-allow off' "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet: captive portal broad fallback has an immediate restore"
if grep -qE -- '^[[:space:]]*(sudo[[:space:]]+)?firewall-cmd[[:space:]]+--(delete-policy|remove-egress-zone)' \
        "$TMPDIR/00-cheatsheet.md"; then
    _fail "cheatsheet: runnable incomplete firewalld-only captive-portal bypass"
else
    _pass "cheatsheet: no runnable incomplete firewalld-only captive-portal bypass"
fi
assert_grep_fixed '/boot/efi: NOT excluded; content-tracked by the VFAT-safe ESP rule' \
    "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet: ESP coverage matches the active AIDE manifest"
assert_not_grep 'already excluded in image but may recur' \
    "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet: mixed AIDE coverage is not mislabeled as all excluded"
assert_grep_fixed 'Machine-readable RFC 8259 JSON object' \
    "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet: noid-status --json format is labeled correctly"
assert_grep_fixed 'including persistent DNS policy and active DNS path' \
    "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet: full noid-status exposes selected and effective DNS state"
assert_grep_fixed '`dns:strict`, `dns:opportunistic`, `dns:off` or `dns:check`' \
    "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet: brief noid-status documents the persistent DNS mode token"
assert_not_grep 'noid-status --json.*key=value' \
    "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet: JSON is not mislabeled as key=value"
assert_grep_fixed 'that auditor reference is' "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet: source-only false-positive database boundary is explicit"
assert_grep_fixed 'not installed in the image' "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet: project reference is not presented as a shipped user doc"
assert_grep_fixed 'noid --help' "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet exposes the installed user-facing CLI inventory"
assert_grep_fixed 'noid-help commands' "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet exposes noid-help command inventory mode"
assert_grep_fixed '`grub-boot-success.timer` deliberately waits two minutes' \
    "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet explains the one-time quick-reboot GRUB menu"
assert_grep_fixed '`OnActiveSec=2min`' "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet states Fedora's exact boot-success delay"
assert_grep_fixed '`grub2-set-bootflag boot_success`' \
    "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet attributes GRUB auto-hide to Fedora's native boot-success flag"
assert_grep_fixed "grep '^CONFIG_SECURITY_LOCKDOWN' \"/boot/config-\$(uname -r)\"" \
    "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet reads Fedora's package-owned running-kernel config"
assert_not_grep '/proc/config.gz' "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet does not assume Fedora enables IKCONFIG_PROC"
assert_grep_fixed 'sudo noid-aide-check.sh' "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet uses the supported AIDE check-only workflow"
assert_not_grep 'sudo aide --check' "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet does not bypass the supported AIDE wrapper"
assert_grep_fixed "sudo grep -nE '^ESP =|^/boot/efi ESP|^!/boot/efi' /etc/aide.conf" \
    "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet reads the root-only AIDE policy through its privilege boundary"
assert_grep_fixed 'systemctl --user --failed' "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet distinguishes system and user-manager failures"
assert_grep_fixed 'read -r -p '\''Exact LUKS device path: '\'' LUKS_DEV' \
    "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet discovers the actual LUKS target"
assert_not_grep '/dev/nvme0n1p3' "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet does not hard-code a storage device"
assert_grep_fixed 'HSI coverage is hardware- and architecture-dependent.' \
    "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet scopes fwupd HSI to supported platform attributes"
assert_not_grep 'sudo nmcli connection show "Proton US1"' \
    "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet VPN troubleshooting is provider-neutral"
assert_grep_fixed 'only when an active reviewed baseline exists' \
    "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet scopes update-time AIDE checks to an accepted baseline"
assert_grep_fixed '`sudo noid-snap-pre DESCRIPTION`' \
    "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet gives snapshot creation its required privilege boundary"
assert_not_grep '`noid-snap-pre <description>`' \
    "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet contains no unprivileged snapshot-creation example"
assert_grep_fixed 'sudo noid-toggle-aide-popup on\|off\|status' \
    "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet gives the AIDE popup helper its required privilege boundary"
assert_grep_fixed 'sudo noid-usbguard-devices' \
    "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet gives the unified USBGuard manager its required privilege boundary"
assert_grep_fixed 'all registered profiles' "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet states the actual Firefox FPP helper scope"
assert_not_grep 'journalctl -u firewalld | grep DROP' \
    "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet does not promise packet logs while LogDenied is off"
assert_grep_fixed 'sudo firewall-cmd --get-log-denied' \
    "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet exposes the actual packet-log posture"
assert_grep_fixed 'sudo journalctl -b -t noid-lan-topology --no-pager' \
    "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet uses the actual LAN controller event source"
assert_not_grep 'flatpak update --assumeno' "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet contains no nonexistent Flatpak dry-run option"
assert_grep_fixed 'flatpak remote-ls --updates --system' \
    "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet inventories pending system-scope Flatpaks without mutation"
assert_grep_fixed 'flatpak remote-ls --updates --user' \
    "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet inventories pending user-scope Flatpaks without mutation"
assert_not_grep '<snapshot-number>' "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet rollback has no active snapshot placeholder"
assert_grep_fixed "read -r -p 'Exact reviewed snapshot number: ' NOID_SNAPSHOT_ID" \
    "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet rollback requires one explicit snapshot selection"
assert_grep_fixed "''|*[!0-9]*)" "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet rollback rejects a nonnumeric snapshot selector"
assert_grep_fixed 'sudo noid-snap-rollback "$NOID_SNAPSHOT_ID"' \
    "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet rollback passes only the validated selection"
assert_grep_fixed 'notification action is temporary' \
    "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet distinguishes temporary notification authorization from persistence"
assert_grep_fixed 'All installed user guides plus companion reference files' \
    "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet accurately describes the complete documentation directory"
assert_grep_fixed 'Persistent system state and build-health evidence' \
    "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet does not misclassify /var/lib state as runtime-only"
assert_grep_fixed '/^Available topics:$/ { in_topics=1; next }' \
    "$TMPDIR/00-cheatsheet.md" \
    "fzf topic integration parses only the topic-table state"
assert_not_grep 'awk '\''{print $1}'\'' | tail -n +3' \
    "$TMPDIR/00-cheatsheet.md" \
    "fzf topic integration cannot ingest Usage rows as topics"
assert_grep_fixed 'grep -rniF --color=always -- {q}' \
    "$TMPDIR/00-cheatsheet.md" \
    "fzf document search treats the entered keyword literally"
assert_grep_fixed '`$EDITOR` / `$VISUAL` — honoured by `sudoedit`' \
    "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet attributes editor selection to sudoedit"
assert_grep_fixed '`$SUDO_EDITOR` takes precedence' \
    "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet records sudoedit's editor precedence"
assert_not_grep 'every installed NoID Privacy CLI/helper' \
    "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet does not overclaim a complete internal-helper inventory"
assert_grep_fixed 'installed user-facing NoID Privacy commands in `/usr/local/bin`' \
    "$TMPDIR/00-cheatsheet.md" \
    "cheatsheet scopes the live command inventory to its actual boundary"

# --- noid-help CLI -----------------------------------------------------------

NH_TMP="$TMPDIR/noid-help"
extract_heredoc "$KS_FILE" "HELP_EOF" "$NH_TMP" || true
assert_file_min_size "$NH_TMP" 1024 "noid-help extracted >1KB"

if bash -n "$NH_TMP" 2>/dev/null; then
    _pass "noid-help bash -n clean"
else
    _fail "noid-help bash syntax error"
fi
assert_grep_fixed 'reviewed known-good root snapshot if available' "$NH_TMP" \
    "noid-help missing-doc recovery is conditional and evidence-bound"
assert_not_grep 'noid-privacy-docs' "$NH_TMP" \
    "noid-help does not invent a repository package for image-owned docs"
assert_not_grep 'list|"")' "$NH_TMP" \
    "noid-help has no unreachable empty-argument case alternative"
assert_grep_fixed 'Installed NoID Privacy executables:' "$NH_TMP" \
    "noid-help labels the complete command inventory with its actual scope"
assert_grep_fixed 'this includes internal hooks in these public executable directories.' \
    "$NH_TMP" \
    "noid-help does not mislabel every installed executable as user-facing"

# CLI must support docs plus a side-effect-free user-facing runtime inventory.
for fn in "_list_topics" "_open_topic" "_search" "_list_commands"; do
    assert_grep_fixed "$fn" "$NH_TMP" "noid-help has $fn"
done
assert_not_grep '"\$path" --help' "$NH_TMP" \
    "command inventory never executes discovered tools"
assert_grep_fixed '"${PAGER_ARGV[@]}" -- "$target"' "$NH_TMP" \
    "noid-help invokes the pager as an argv array"
assert_not_grep 'PAGER_CMD' "$NH_TMP" \
    "noid-help has no string-expanded pager command"
assert_grep_fixed '*/*|*..*|*[!A-Za-z0-9._-]*' "$NH_TMP" \
    "noid-help rejects traversal and glob-like topic selectors"
assert_grep_fixed '[ ! -L "$path" ]' "$NH_TMP" \
    "noid-help command inventory rejects symlinks"
assert_grep_fixed 'grep -Fqi -- "$kw" "$f"' "$NH_TMP" \
    "noid-help keyword detection uses fixed-string matching"
assert_grep_fixed 'grep -Fni -m 5 --color=auto -- "$kw" "$f"' "$NH_TMP" \
    "noid-help keyword output uses fixed-string matching"
assert_grep_fixed 'check "noid-help has: $kw" grep -Fqi -- "$kw"' "$KS_FILE" \
    "M30 deployed-helper verification uses literal implementation tokens"
assert_not_grep 'grep -Fni.*| head -5' "$NH_TMP" \
    "noid-help bounds grep natively without a SIGPIPE-prone pipeline"
assert_grep_fixed 'print substr($0,1,70)' "$NH_TMP" \
    "noid-help bounds headings without splitting UTF-8 by bytes"
assert_grep_fixed 'ambiguous topic selector' "$NH_TMP" \
    "noid-help refuses to choose an arbitrary document from multiple matches"

# Functional smoke test: create a mock doc dir, run noid-help
chmod 0755 "$NH_TMP"
MOCK_DOC="$TMPDIR/mockdocs"
mkdir -p "$MOCK_DOC"
for f in 00-README.md 01-getting-started.md 06-vpn-setup.md; do
    printf "# Test title %s\n\nBody with VPN and firewall keywords plus [literal].\n" "$f" > "$MOCK_DOC/$f"
done
chmod 0755 "$MOCK_DOC"
chmod 0644 "$MOCK_DOC"/*.md
sed -i "s|^DOC_DIR=.*|DOC_DIR=\"$MOCK_DOC\"|" "$NH_TMP"
fixture_uid=$(id -u)
fixture_gid=$(id -g)
sed -i \
    "s/0:0:755/${fixture_uid}:${fixture_gid}:755/g; s/0:0:644:1/${fixture_uid}:${fixture_gid}:644:1/g" \
    "$NH_TMP"
ln -s /etc/passwd "$MOCK_DOC/99-untrusted.md"
MOCK_BIN="$TMPDIR/mock-bin"
MOCK_SBIN="$TMPDIR/mock-sbin"
MOCK_ALIAS="$TMPDIR/mock-sbin-alias"
mkdir -p "$MOCK_BIN" "$MOCK_SBIN"
ln -s "$MOCK_BIN" "$MOCK_ALIAS"
for path in "$MOCK_BIN/noid-alpha" "$MOCK_BIN/noid-help" \
            "$MOCK_SBIN/noid-root-helper"; do
    printf '#!/bin/sh\nexit 99\n' > "$path"
    chmod 0755 "$path"
done
printf '#!/bin/sh\nexit 99\n' > "$MOCK_BIN/noid-not-executable"
printf '#!/bin/sh\nexit 99\n' > "$MOCK_BIN/unrelated-tool"
chmod 0755 "$MOCK_BIN/unrelated-tool"
ln -s "$MOCK_BIN/noid-alpha" "$MOCK_BIN/noid-linked"
sed -i "s|^COMMAND_DIRS=.*|COMMAND_DIRS=($MOCK_BIN $MOCK_ALIAS $MOCK_SBIN)|" "$NH_TMP"

# Mode 1: list
list_out=$("$NH_TMP" list 2>&1 || true)
if echo "$list_out" | grep -q "06-vpn-setup" && \
   echo "$list_out" | grep -q "Available topics" && \
   ! echo "$list_out" | grep -q "99-untrusted"; then
    _pass "noid-help list mode works"
else
    _fail "noid-help list mode broken"
fi

# Mode 2: open topic (substring match)
open_out=$(env PAGER=cat "$NH_TMP" 06-vpn 2>&1 || true)
if echo "$open_out" | grep -q "Test title 06-vpn-setup"; then
    _pass "noid-help open mode (substring) works"
else
    _fail "noid-help open mode broken"
fi

printf '# Test title 06-vpn-extra.md\n\nSecond matching document.\n' \
    > "$MOCK_DOC/06-vpn-extra.md"
chmod 0644 "$MOCK_DOC/06-vpn-extra.md"
if ambiguous_out=$(env PAGER=cat "$NH_TMP" 06-vpn 2>&1); then
    _fail "noid-help silently selects one of multiple matching topics"
elif echo "$ambiguous_out" | grep -qF 'ambiguous topic selector'; then
    _pass "noid-help rejects ambiguous topic selectors"
else
    _fail "noid-help ambiguous-topic diagnostic is missing"
fi

pager_out=$(env PAGER='cat -n' "$NH_TMP" 06-vpn 2>&1 || true)
if echo "$pager_out" | grep -qF 'ambiguous topic selector'; then
    _pass "noid-help pager argv path remains ambiguity-safe"
else
    _fail "noid-help pager argv path bypasses ambiguity detection"
fi
pager_out=$(env PAGER='cat -n' "$NH_TMP" 06-vpn-setup 2>&1 || true)
if echo "$pager_out" | grep -q 'Test title 06-vpn-setup'; then
    _pass "noid-help pager argv preserves a reviewed option"
else
    _fail "noid-help pager argv handling is broken"
fi

if env PAGER=cat "$NH_TMP" ../../etc/passwd >/dev/null 2>&1; then
    _fail "noid-help accepts a traversal topic"
else
    _pass "noid-help rejects traversal topics"
fi
if env PAGER=cat "$NH_TMP" '06-*' >/dev/null 2>&1; then
    _fail "noid-help accepts a glob topic"
else
    _pass "noid-help rejects glob topics"
fi

# Mode 3: search
search_out=$("$NH_TMP" search VPN 2>&1 || true)
if echo "$search_out" | grep -q "06-vpn-setup" && \
   echo "$search_out" | grep -q "VPN and firewall"; then
    _pass "noid-help search mode works"
else
    _fail "noid-help search mode broken"
fi
literal_search_out=$("$NH_TMP" search '[literal]' 2>&1 || true)
if echo "$literal_search_out" | grep -qF '[literal]'; then
    _pass "noid-help search treats regular-expression metacharacters literally"
else
    _fail "noid-help fixed-string search is broken"
fi

# Mode 4: user-facing runtime inventory. Fixtures deliberately exit 99 if
# executed, proving that enumeration only inspects names/mode/path.
commands_out=$("$NH_TMP" commands 2>&1)
if echo "$commands_out" | grep -qF 'noid-alpha' && \
   echo "$commands_out" | grep -qF 'noid-help' && \
   echo "$commands_out" | grep -qF 'noid-root-helper' && \
   echo "$commands_out" | grep -qF '3 executable(s)' && \
   [ "$(grep -Ec '^[[:space:]]+noid-alpha[[:space:]]' <<<"$commands_out")" -eq 1 ] && \
   [ "$(grep -Ec '^[[:space:]]+noid-help[[:space:]]' <<<"$commands_out")" -eq 1 ] && \
   ! echo "$commands_out" | grep -qF 'noid-not-executable' && \
   ! echo "$commands_out" | grep -qF 'noid-linked' && \
   ! echo "$commands_out" | grep -qF 'unrelated-tool'; then
    _pass "noid-help commands lists each installed noid executable exactly once"
else
    _fail "noid-help commands inventory is incomplete, duplicated or overbroad"
fi

NOID_TMP="$TMPDIR/noid"
extract_heredoc "$KS_FILE" "NOID_EOF" "$NOID_TMP" || true
assert_file_min_size "$NOID_TMP" 512 "noid --help entry point extracted"
if bash -n "$NOID_TMP"; then
    _pass "noid --help entry point bash syntax clean"
else
    _fail "noid --help entry point bash syntax error"
fi
sed -i "s|^HELP_BIN=.*|HELP_BIN=\"$NH_TMP\"|" "$NOID_TMP"
sed -i "s/0:0:755:1/${fixture_uid}:${fixture_gid}:755:1/" "$NOID_TMP"
chmod 0755 "$NOID_TMP"
noid_out=$("$NOID_TMP" --help 2>&1)
if echo "$noid_out" | grep -qF 'noid-alpha' && \
   echo "$noid_out" | grep -qF 'noid-root-helper'; then
    _pass "noid --help exposes the exact noid-help command inventory"
else
    _fail "noid --help does not expose the installed command inventory"
fi
if "$NOID_TMP" noid-root-helper >/dev/null 2>&1; then
    _fail "noid entry point dispatches an arbitrary helper name"
else
    _pass "noid entry point refuses arbitrary helper dispatch"
fi
if "$NOID_TMP" --help unexpected >/dev/null 2>&1; then
    _fail "noid entry point silently ignores extra help arguments"
else
    _pass "noid entry point rejects extra help arguments"
fi

NOID_SYMLINK_TMP="$TMPDIR/noid-symlink-check"
cp "$NOID_TMP" "$NOID_SYMLINK_TMP"
HELP_LINK="$TMPDIR/noid-help-link"
ln -s "$NH_TMP" "$HELP_LINK"
sed -i "s|^HELP_BIN=.*|HELP_BIN=\"$HELP_LINK\"|" "$NOID_SYMLINK_TMP"
chmod 0755 "$NOID_SYMLINK_TMP"
if "$NOID_SYMLINK_TMP" --help >/dev/null 2>&1; then
    _fail "noid entry point trusts a symlinked help executable"
else
    _pass "noid entry point rejects a symlinked help executable"
fi

# --- Health-stamp failure boundary -----------------------------------------

# Stamp path
assert_grep_fixed "stamp-30-user-docs-tier-b.ok" "$KS_FILE" \
    "M30 health stamp path"
assert_grep_fixed "module=30" "$KS_FILE" \
    "M30 stamp declares module=30"

guard_line=$(grep -n 'fails.*-gt 0' "$KS_FILE" | head -1 | cut -d: -f1 || true)
invalidate_line=$(grep -nF \
    '# M30_HEALTH_INVALIDATION_BEGIN' "$KS_FILE" | cut -d: -f1 || true)
first_payload_line=$(grep -nF \
    'install -d -m 0755 -o root -g root -- "$dir"' \
    "$KS_FILE" | cut -d: -f1 || true)
publish_line=$(grep -nF \
    '# M30_HEALTH_PUBLICATION_BEGIN' "$KS_FILE" | cut -d: -f1 || true)
complete_line=$(grep -nF \
    'log "=== Module 30 User Documentation Tier B complete ==="' \
    "$KS_FILE" | cut -d: -f1 || true)
if [ -n "$guard_line" ] && [ -n "$invalidate_line" ] \
   && [ -n "$first_payload_line" ] && [ -n "$publish_line" ] \
   && [ -n "$complete_line" ] \
   && [ "$invalidate_line" -lt "$first_payload_line" ] \
   && [ "$guard_line" -lt "$publish_line" ] \
   && [ "$publish_line" -lt "$complete_line" ]; then
    _pass "M30 retires old health before mutation and publishes only after verification"
else
    _fail "M30 health-stamp ordering is not failure-atomic"
fi

# Execute the exact production invalidation and publication blocks.
m30_stamp_root="$TMPDIR/health-stamp"
m30_stamp_state="$m30_stamp_root/state"
m30_stamp_bin="$m30_stamp_root/bin"
m30_stamp_invalidate="$m30_stamp_root/invalidate.sh"
m30_stamp_publish="$m30_stamp_root/publish.sh"
m30_stamp_uid=$(id -u)
m30_stamp_gid=$(id -g)
mkdir -p "$m30_stamp_bin"

cat > "$m30_stamp_bin/restorecon" <<'M30_STAMP_RESTORECON_EOF'
#!/usr/bin/env bash
set -euo pipefail
target="${!#}"
case "${FAKE_RESTORECON_FAIL:-}" in
    all) exit 1 ;;
    final)
        case "$target" in
            */stamp-30-user-docs-tier-b.ok) exit 1 ;;
        esac
        ;;
esac
exit 0
M30_STAMP_RESTORECON_EOF
cat > "$m30_stamp_bin/matchpathcon" <<'M30_STAMP_MATCHPATHCON_EOF'
#!/usr/bin/env bash
exit 0
M30_STAMP_MATCHPATHCON_EOF
cat > "$m30_stamp_bin/mv" <<'M30_STAMP_MV_EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "${FAKE_MV_FAIL:-0}" -eq 1 ]; then
    exit 1
fi
exec /usr/bin/mv "$@"
M30_STAMP_MV_EOF
chmod 0700 "$m30_stamp_bin/restorecon" \
    "$m30_stamp_bin/matchpathcon" "$m30_stamp_bin/mv"

{
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
        'PHASE=test' 'log() { :; }' 'die() { exit 1; }' \
        "STAMP_DIR=$m30_stamp_state" \
        'STAMP="$STAMP_DIR/stamp-30-user-docs-tier-b.ok"'
    sed -n \
        '/^# M30_HEALTH_INVALIDATION_BEGIN$/,/^# M30_HEALTH_INVALIDATION_END$/p' \
        "$KS_FILE" |
        sed -e "s|/var/lib/noid-privacy|$m30_stamp_state|g" \
            -e "s/-o root -g root/-o $m30_stamp_uid -g $m30_stamp_gid/" \
            -e "s/0:0:755/$m30_stamp_uid:$m30_stamp_gid:755/"
} > "$m30_stamp_invalidate"
{
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
        'PHASE=test' 'log() { :; }' 'die() { exit 1; }' \
        "STAMP_DIR=$m30_stamp_state" \
        'STAMP="$STAMP_DIR/stamp-30-user-docs-tier-b.ok"' \
        'DOC_TMP=' 'BIN_TMP=' 'STAMP_TMP=' \
        'STAMP_PUBLICATION_ACTIVE=0' 'checks=35' 'fails=0'
    sed -n '/^cleanup() {$/,/^}$/p' "$KS_FILE"
    printf '%s\n' 'trap cleanup EXIT'
    sed -n \
        '/^# M30_HEALTH_PUBLICATION_BEGIN$/,/^# M30_HEALTH_PUBLICATION_END$/p' \
        "$KS_FILE" |
        sed -e "s/chown root:root/chown $m30_stamp_uid:$m30_stamp_gid/" \
            -e "s/0:0:755/$m30_stamp_uid:$m30_stamp_gid:755/" \
            -e "s/0:0:644:1/$m30_stamp_uid:$m30_stamp_gid:644:1/"
} > "$m30_stamp_publish"
chmod 0700 "$m30_stamp_invalidate" "$m30_stamp_publish"

mkdir -m 0755 "$m30_stamp_state"
printf '%s\n' 'module=30' 'name=user-docs-tier-b' 'status=ok' \
    > "$m30_stamp_state/stamp-30-user-docs-tier-b.ok"
assert_cmd_success "M30 rerun invalidates its prior build-success stamp" \
    env PATH="$m30_stamp_bin:$PATH" "$m30_stamp_invalidate"
if [ ! -e "$m30_stamp_state/stamp-30-user-docs-tier-b.ok" ]; then
    _pass "M30 old success evidence is absent before payload publication"
else
    _fail "M30 old success evidence is absent before payload publication"
fi

chmod 0777 "$m30_stamp_state"
printf '%s\n' 'must-survive' \
    > "$m30_stamp_state/stamp-30-user-docs-tier-b.ok"
assert_cmd_failure "M30 rejects shared state-directory metadata drift" \
    env PATH="$m30_stamp_bin:$PATH" "$m30_stamp_invalidate"
assert_eq "$m30_stamp_uid:$m30_stamp_gid:777" \
    "$(stat -c '%u:%g:%a' "$m30_stamp_state")" \
    "M30 does not normalize drifted shared-directory metadata"
assert_grep_fixed 'must-survive' \
    "$m30_stamp_state/stamp-30-user-docs-tier-b.ok" \
    "M30 does not traverse a drifted shared state boundary"
rm "$m30_stamp_state/stamp-30-user-docs-tier-b.ok"
chmod 0755 "$m30_stamp_state"

assert_cmd_failure "M30 rejects a health-stamp candidate label failure" \
    env PATH="$m30_stamp_bin:$PATH" FAKE_RESTORECON_FAIL=all \
        "$m30_stamp_publish"
if [ ! -e "$m30_stamp_state/stamp-30-user-docs-tier-b.ok" ] \
   && [ -z "$(find "$m30_stamp_state" -maxdepth 1 \
        -name '.stamp-30-user-docs-tier-b.ok.*' -print -quit)" ]; then
    _pass "M30 candidate-label failure leaves no plausible health evidence"
else
    _fail "M30 candidate-label failure leaves no plausible health evidence"
fi

assert_cmd_failure "M30 retires a stamp after final-label failure" \
    env PATH="$m30_stamp_bin:$PATH" FAKE_RESTORECON_FAIL=final \
        "$m30_stamp_publish"
if [ ! -e "$m30_stamp_state/stamp-30-user-docs-tier-b.ok" ]; then
    _pass "M30 final-label failure removes the published success stamp"
else
    _fail "M30 final-label failure removes the published success stamp"
fi

assert_cmd_failure "M30 rejects an atomic health-stamp rename failure" \
    env PATH="$m30_stamp_bin:$PATH" FAKE_MV_FAIL=1 "$m30_stamp_publish"
if [ ! -e "$m30_stamp_state/stamp-30-user-docs-tier-b.ok" ] \
   && [ -z "$(find "$m30_stamp_state" -maxdepth 1 \
        -name '.stamp-30-user-docs-tier-b.ok.*' -print -quit)" ]; then
    _pass "M30 rename failure leaves no stamp or staged candidate"
else
    _fail "M30 rename failure leaves no stamp or staged candidate"
fi

assert_cmd_success "M30 publishes exact health evidence after all gates" \
    env PATH="$m30_stamp_bin:$PATH" "$m30_stamp_publish"
assert_grep_fixed 'module=30' \
    "$m30_stamp_state/stamp-30-user-docs-tier-b.ok"
assert_grep_fixed 'name=user-docs-tier-b' \
    "$m30_stamp_state/stamp-30-user-docs-tier-b.ok"
assert_grep_fixed 'checks_passed=35' \
    "$m30_stamp_state/stamp-30-user-docs-tier-b.ok"
assert_grep_fixed 'checks_total=35' \
    "$m30_stamp_state/stamp-30-user-docs-tier-b.ok"
assert_eq 8 \
    "$(wc -l < "$m30_stamp_state/stamp-30-user-docs-tier-b.ok")" \
    "M30 published health stamp has the exact eight-line schema"

test_finish

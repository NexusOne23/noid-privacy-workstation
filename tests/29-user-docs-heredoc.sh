#!/bin/bash
# 29-user-docs-heredoc — verify all 4 Tier-A docs extract correctly from M29
#
# M29 ships four user-facing docs via heredocs inside its %post. This test
# extracts each heredoc and asserts:
#   - File is non-empty + above the 99-finalize size minimum
#   - Structural markers are present (so future edits can't accidentally
#     ship a truncated or mangled doc that silently passes bash -n)
#   - Every local Tier-A document reference resolves to a shipped payload

set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/29-user-docs.ks"
M08_FILE="$PROJECT_ROOT/kickstart/snippets/08-service-minimization.ks"
M13_FILE="$PROJECT_ROOT/kickstart/snippets/13-aide-welcome.ks"
M16_FILE="$PROJECT_ROOT/kickstart/snippets/16-firefox.ks"
M20_FILE="$PROJECT_ROOT/kickstart/snippets/20-snapper.ks"
M21_FILE="$PROJECT_ROOT/kickstart/snippets/21-kernel-module-blacklist.ks"
M25_FILE="$PROJECT_ROOT/kickstart/snippets/25-update-process.ks"
M26_FILE="$PROJECT_ROOT/kickstart/snippets/26-package-set.ks"
M03_FILE="$PROJECT_ROOT/kickstart/snippets/03-firewalld.ks"
M06_FILE="$PROJECT_ROOT/kickstart/snippets/06-vpn-killswitch.ks"
M13_FILE="$PROJECT_ROOT/kickstart/snippets/13-aide-welcome.ks"
M17_FILE="$PROJECT_ROOT/kickstart/snippets/17-gnome-hardening.ks"
VPN_FIXTURE="$PROJECT_ROOT/tests/29-vpn-tunnel-down-fixture.py"
PROTON_GUIDE="$PROJECT_ROOT/docs/protonvpn-installation-guide.md"
snippet_count=$(find "$PROJECT_ROOT/kickstart/snippets" -maxdepth 1 -type f \
    -name '*.ks' -print | wc -l)
functional_module_count=$((snippet_count - 1))

test_start "29-user-docs-heredoc"

assert_grep_fixed 'between **"Gaming Mode (Steam /' "$PROTON_GUIDE" \
    "Proton autostart guide names the current preceding Setup group"
assert_grep_fixed 'and **"Security Notifications"**' "$PROTON_GUIDE" \
    "Proton autostart guide names the current following group"
assert_not_grep 'Network Privacy Management' "$PROTON_GUIDE" \
    "Proton guide contains no retired Setup group title"
assert_grep_fixed "autostart_group.set_title('App Autostart')" "$M13_FILE" \
    "M13 owns the exact App Autostart group named by the guides"

if [ ! -f "$KS_FILE" ]; then
    _fail "M29 snippet missing: $KS_FILE"
    test_finish
    exit 1
fi

assert_not_grep_extended 'PROTONVPN_FPR_EXPECTED|PROTONVPN_KEY_URL|RPM-GPG-KEY-protonvpn|rpmkeys --import' \
    "$KS_FILE" "provider-neutral base image imports no Proton trust root"
assert_not_grep '6929133BDE1CE1CFA9EDB286D84176F6844830D4' "$KS_FILE" \
    "Fedora/provider-specific Proton fingerprint is not baked into M29"
assert_not_grep '^# Phase 4b — ProtonVPN GPG key pre-import' "$KS_FILE" \
    "removed provider-key phase cannot return"
assert_grep_fixed 'restorecon failed for user documentation' "$KS_FILE" \
    "documentation relabel failure remains release-visible"
assert_grep_fixed 'matchpathcon -V "$target"' "$KS_FILE" \
    "each published document label is verified against SELinux policy"
assert_grep_fixed 'sync -- "$DOC_TMP"' "$KS_FILE" \
    "document bytes are synchronized before atomic publication"
assert_grep_fixed 'sync -- "$target" "$DOC_DIR"' "$KS_FILE" \
    "published document and parent entry are synchronized before success"
assert_grep_fixed 'set -euo pipefail' "$KS_FILE" \
    "M29 post script fails on unset variables and pipeline errors"
assert_grep_fixed "trap 'exit 130' INT" "$KS_FILE" \
    "M29 converts interruption into the cleanup path"
assert_grep_fixed "trap 'exit 143' TERM" "$KS_FILE" \
    "M29 converts termination into the cleanup path"
assert_grep_fixed 'restorecon is required for fail-closed SELinux labeling' "$KS_FILE" \
    "missing SELinux labeling support is fatal"
assert_not_grep_extended '(^|[;&|[:space:]])eval([;&|[:space:]]|$)' "$KS_FILE" \
    "M29 verification executes argument vectors rather than shell-evaluated strings"
assert_grep_fixed 'mv -fT "$DOC_TMP" "$target"' "$KS_FILE" \
    "document publication atomically replaces the exact target"
assert_grep_fixed "doc_meta=\$(stat -c '%u:%g:%a:%h'" "$KS_FILE" \
    "deployed document ownership, mode and hard-link count are verified"
assert_grep_fixed 'restorecon -F -- "$STAMP"' "$KS_FILE" \
    "health-stamp ownership and SELinux type are reconciled"
assert_not_grep 'restorecon.*STAMP.*|| true' "$KS_FILE" \
    "M29 cannot report a healthy stamp after SELinux labeling failed"
assert_grep_fixed 'STAMP_TMP=$(mktemp "$STAMP_DIR/.stamp-29-user-docs.ok.XXXXXXXX")' \
    "$KS_FILE" "health-stamp publication starts from a private same-filesystem file"
assert_grep_fixed 'mv -fT -- "$STAMP_TMP" "$STAMP"' "$KS_FILE" \
    "health-stamp publication atomically replaces the exact target"
assert_grep_fixed "stat -Lc '%u:%g:%a:%h' -- \"\$path\"" "$KS_FILE" \
    "health-stamp ownership, mode and hard-link count are verified"
assert_grep_fixed 'prior Module 29 health stamp is absent' "$KS_FILE" \
    "old M29 success evidence is retired before document publication"
assert_grep_fixed 'verify_m29_health_stamp()' "$KS_FILE" \
    "staged and final M29 evidence share one exact validator"
assert_grep_fixed 'STAMP_PUBLICATION_ACTIVE=1' "$KS_FILE" \
    "published M29 evidence remains removable through every final gate"
assert_grep_fixed 'matchpathcon -V "$STAMP_TMP"' "$KS_FILE" \
    "M29 validates the staged stamp SELinux context"
assert_grep_fixed 'matchpathcon -V "$STAMP"' "$KS_FILE" \
    "M29 validates the final stamp SELinux context"

for shipped_spec in \
    '00-README.md:README_EOF' \
    '01-getting-started.md:GETSTART_EOF' \
    '06-vpn-setup.md:VPN_EOF' \
    'gnome-extensions-autostart.md:GNOME_EXT_EOF'; do
    shipped_doc=${shipped_spec%%:*}
    shipped_marker=${shipped_spec#*:}
    assert_grep_fixed \
        "# Shipped Markdown target: /usr/share/doc/noid-privacy/$shipped_doc" \
        "$KS_FILE" "$shipped_doc remains visible to document inventories"
    assert_grep_fixed "# Shipped Markdown heredoc: $shipped_marker" \
        "$KS_FILE" "$shipped_doc body remains visible to Markdown classifiers"
done

TMPDIR="$(mktemp -d)"
EXEC_TMPDIR="$(mktemp -d /var/tmp/noid-m29-test.XXXXXX)"
trap 'rm -rf "$TMPDIR" "$EXEC_TMPDIR"' EXIT

# --- extract docs -----------------------------------------------------------

extract_heredoc "$KS_FILE" "README_EOF"   "$TMPDIR/00-README.md"            || true
extract_heredoc "$KS_FILE" "GETSTART_EOF" "$TMPDIR/01-getting-started.md"   || true
extract_heredoc "$KS_FILE" "VPN_EOF"      "$TMPDIR/06-vpn-setup.md"         || true
extract_heredoc "$KS_FILE" "GNOME_EXT_EOF" "$TMPDIR/gnome-extensions-autostart.md" || true
extract_heredoc "$M03_FILE" "POLICY_EOF"  "$TMPDIR/block-lan-out.xml"       || true
extract_heredoc "$M06_FILE" "NFT_EOF"     "$TMPDIR/noid-wan-strict.nft"     || true
extract_heredoc "$M17_FILE" "DCONF_LOCKS_EOF" "$TMPDIR/noid-gnome-locks"    || true

assert_file_min_size "$TMPDIR/00-README.md"          4096 "00-README.md extracted >4KB"
assert_file_min_size "$TMPDIR/01-getting-started.md" 4096 "01-getting-started.md extracted >4KB"
assert_file_min_size "$TMPDIR/06-vpn-setup.md"       6144 "06-vpn-setup.md extracted >6KB"
assert_file_min_size "$TMPDIR/gnome-extensions-autostart.md" 4096 \
    "gnome-extensions-autostart.md extracted >4KB"

# Every fenced Bash example must parse exactly as shipped, and active command
# lines must not use angle-bracket prose placeholders. Bash accepts some such
# strings as input/output redirections, so `bash -n` alone cannot catch them.
if python3 - \
        "$TMPDIR/00-README.md" \
        "$TMPDIR/01-getting-started.md" \
        "$TMPDIR/06-vpn-setup.md" \
        "$TMPDIR/gnome-extensions-autostart.md" <<'PY'
import re
import subprocess
import sys
from pathlib import Path

fence_pattern = re.compile(
    r"^```bash[ \t]*\n(.*?)^```[ \t]*$",
    flags=re.MULTILINE | re.DOTALL,
)
placeholder_pattern = re.compile(r"<[A-Za-z][^<>]*>")
strict_markers = (
    "LUKS_BACKUP_DIR:?export",
    "NOID_SNAPSHOT_ID:?export",
    "vpn_profile=${VPN_PROFILE:?",
)
failures = []
count = 0

for name in sys.argv[1:]:
    path = Path(name)
    for index, match in enumerate(fence_pattern.finditer(path.read_text()), 1):
        count += 1
        body = match.group(1)
        result = subprocess.run(
            ["bash", "-n"],
            input=body,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode:
            failures.append(
                f"{path.name} Bash fence {index}: {result.stderr.strip()}"
            )
        lines = body.rstrip("\n").splitlines()
        if any(marker in body for marker in strict_markers):
            if (len(lines) < 3 or lines[0] != "("
                    or lines[1] != "set -euo pipefail" or lines[-1] != ")"):
                failures.append(
                    f"{path.name} Bash fence {index}: guarded operational "
                    "example is not a strict isolated unit"
                )
        if re.search(r"^VPN_PROFILE=", body, flags=re.MULTILINE):
            failures.append(
                f"{path.name} Bash fence {index}: active VPN profile is hard-coded"
            )
        for line_number, line in enumerate(body.splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            if placeholder_pattern.search(line):
                failures.append(
                    f"{path.name} Bash fence {index}, line {line_number}: "
                    "active angle-bracket placeholder"
                )

if count != 43:
    failures.append(f"expected 43 Bash fences, found {count}")
if failures:
    print("\n".join(failures), file=sys.stderr)
    raise SystemExit(1)
PY
then
    _pass "all 43 Tier-A Bash fences parse and contain no active prose placeholders"
else
    _fail "Tier-A Bash fence is not directly executable as documented"
fi

# Every local Markdown-document reference in the four Tier-A payloads must
# resolve to a declared Kickstart shipper. This closes the shared-assumption
# gap that allowed the unshipped 25-update-process.md target to remain green.
if python3 - "$PROJECT_ROOT/kickstart" \
        "$TMPDIR/00-README.md" \
        "$TMPDIR/01-getting-started.md" \
        "$TMPDIR/06-vpn-setup.md" \
        "$TMPDIR/gnome-extensions-autostart.md" <<'PY'
from pathlib import Path
import re
import sys

kickstart_root = Path(sys.argv[1])
documents = [Path(arg) for arg in sys.argv[2:]]
shipped = set()
for source in kickstart_root.rglob("*"):
    if source.is_file():
        content = source.read_text(errors="replace")
        shipped.update(re.findall(
            r"cat\s+>\s*/usr/share/doc/noid-privacy/([^\s<]+)",
            content,
        ))
        shipped.update(re.findall(
            r"^# Shipped Markdown target: "
            r"/usr/share/doc/noid-privacy/([^\s]+)$",
            content,
            flags=re.MULTILINE,
        ))

missing = []
for document in documents:
    content = document.read_text()
    markdown_targets = {
        target.split("#", 1)[0]
        for target in re.findall(
            r"\[[^\]]*\]\(([^)]+\.md(?:#[^)]*)?)\)", content
        )
    }
    plain_targets = set(re.findall(
        r"(?<![/\w.-])([0-9A-Za-z][0-9A-Za-z._-]*\.md)(?![/\w.-])",
        content,
    ))
    for target in sorted(markdown_targets | plain_targets):
        if target == document.name or re.match(
            r"^[A-Za-z][A-Za-z0-9+.-]*://", target
        ):
            continue
        if target not in shipped:
            missing.append(f"{document.name}: {target}")

if missing:
    print("unshipped Tier-A document references:", file=sys.stderr)
    print("\n".join(missing), file=sys.stderr)
    raise SystemExit(1)
PY
then
    _pass "every Tier-A local document reference has a Kickstart shipper"
else
    _fail "Tier-A local document reference lacks a Kickstart shipper"
fi

# --- 00-README.md structural markers ---------------------------------------

assert_grep_fixed "NoID Privacy Workstation"         "$TMPDIR/00-README.md"
assert_grep_fixed "with ${functional_module_count} functional sections" \
    "$TMPDIR/00-README.md" \
    "architecture summary count matches snippet discovery"
assert_grep_fixed 'Rerun support is' "$TMPDIR/00-README.md" \
    "architecture avoids a universal module-idempotency promise"
assert_not_grep 'each Module is self-contained and idempotent' \
    "$TMPDIR/00-README.md" \
    "stale universal module-independence claim cannot return"
assert_grep_fixed "01-getting-started.md"       "$TMPDIR/00-README.md" "references 01-getting-started"
assert_grep_fixed "06-vpn-setup.md"             "$TMPDIR/00-README.md" "references 06-vpn-setup"
assert_grep_fixed "22-disk-encryption.md"       "$TMPDIR/00-README.md" "references 22-disk-encryption"
assert_grep_fixed "11-time-recovery.md"         "$TMPDIR/00-README.md" \
    "references authenticated dead-RTC recovery"
assert_grep_fixed "ai-workspace.md"             "$TMPDIR/00-README.md" \
    "references installed cloud-agent trust-boundary documentation"
assert_grep_fixed "27-performance.md"           "$TMPDIR/00-README.md" \
    "references the installed M27 performance policy and measurement guide"
for product_doc in threat-model.md scope.md post-quantum-readiness.md \
                   performance-profile.md licensing.md \
                   35-thunderbird-smartcard.md; do
    assert_grep_fixed "$product_doc" "$TMPDIR/00-README.md" \
        "master index exposes installed product-boundary topic: $product_doc"
done
assert_grep_fixed "Task-based reference"        "$TMPDIR/00-README.md"
assert_grep_fixed "CLI tools"                   "$TMPDIR/00-README.md"
assert_grep_fixed "noid-status"                 "$TMPDIR/00-README.md"
assert_grep_fixed "noid-welcome.sh"             "$TMPDIR/00-README.md"
assert_grep_fixed 'noid-network-audit <wan\|firewall\|nft\|mtu>' \
    "$TMPDIR/00-README.md" \
    "master CLI inventory includes the formatted read-only Network audits"
assert_grep_fixed 'noid-dns-mode status\|opportunistic\|strict\|off\|reset' \
    "$TMPDIR/00-README.md" \
    "master CLI inventory exposes every supported managed DNS transport action"
assert_grep_fixed 'noid-help commands' "$TMPDIR/00-README.md" \
    "master CLI inventory points to the complete generated command inventory"
assert_grep_fixed '| Update my system safely | 01-getting-started.md | Prefer the guided update process |' \
    "$TMPDIR/00-README.md" "update task resolves to the shipped onboarding guide"
assert_not_grep '25-update-process\.md' "$TMPDIR/00-README.md" \
    "unshipped update-process document cannot return to the Tier-A index"
assert_grep_fixed 'noid-toggle-gsk-gl auto/on/off/status' "$TMPDIR/00-README.md" \
    "master CLI inventory includes the topology-gated GTK renderer policy"
assert_grep_fixed 'Diagnose a GTK4 hybrid-GPU launch stall' "$TMPDIR/00-README.md" \
    "task navigation reaches the M19 workaround documentation"
assert_not_grep 'works perfectly'                "$TMPDIR/00-README.md" \
    "master user guide avoids an absolute quality claim"
assert_not_grep '~60 masked services' "$TMPDIR/00-README.md" \
    "masked-service documentation avoids a stale hardcoded count"
assert_not_grep 'without a VPN provider, mail client' "$TMPDIR/00-README.md" \
    "master guide does not deny the mandatory Thunderbird package"
assert_grep_fixed 'Thunderbird is installed but has no account' "$TMPDIR/00-README.md" \
    "master guide distinguishes installed client from configured account"
assert_grep_extended '^[[:space:]]+thunderbird([[:space:]]|$)' "$M26_FILE" \
    "Thunderbird capability claim is anchored to M26 MUST_PRESENT"
assert_not_grep 'every hardening can be disabled' "$TMPDIR/00-README.md" \
    "master guide makes no universal reversibility promise"
assert_grep_fixed 'not universally one-click' "$TMPDIR/00-README.md" \
    "master guide states the scoped recovery boundary"
assert_not_grep 'Install H.265 codec, RAR, 7-Zip' "$TMPDIR/00-README.md" \
    "CLI table has no retired archive-install capability"
assert_grep_fixed '`unar`/`7zip` are already installed' "$TMPDIR/00-README.md" \
    "CLI table names the actual preinstalled archive tools"
assert_grep_fixed 'all 3 tasks OK' "$M08_FILE" \
    "codec helper capability is anchored to M08's exact task contract"
assert_not_grep 'Media codecs (~50 MB' "$TMPDIR/01-getting-started.md" \
    "onboarding does not freeze a moving codec transaction size"
assert_not_grep 'No telemetry is collected by this image' "$TMPDIR/00-README.md" \
    "master guide does not overclaim third-party or explicitly invoked traffic"
assert_grep_fixed "do not send project telemetry" "$TMPDIR/00-README.md" \
    "master guide preserves the scoped silent-machine claim"
assert_grep_fixed 'file-level and embedded-source exceptions' \
    "$TMPDIR/00-README.md" \
    "master guide points to the repository's exact multi-license boundary"
assert_not_grep 'GPL-2.0+' "$TMPDIR/00-README.md" \
    "deprecated ambiguous license shorthand is absent"

# --- 01-getting-started.md structural markers ------------------------------

assert_grep_fixed "Getting Started"             "$TMPDIR/01-getting-started.md"
# Three priority tiers — must all be present
assert_grep_fixed "CRITICAL"                    "$TMPDIR/01-getting-started.md"
assert_grep_fixed "IMPORTANT"                   "$TMPDIR/01-getting-started.md"
assert_grep_fixed "RECOMMENDED"                 "$TMPDIR/01-getting-started.md"
# LUKS backup
assert_grep_fixed "luksHeaderBackup"            "$TMPDIR/01-getting-started.md"
# Terminal-native documentation navigation. `noid-help` normally renders this
# guide through less, where relative Markdown links are text rather than
# clickable navigation.
assert_grep_fixed '/usr/share/doc/noid-privacy/' "$TMPDIR/01-getting-started.md" \
    "onboarding names the canonical installed documentation directory"
assert_grep_fixed 'noid-help list' "$TMPDIR/01-getting-started.md" \
    "onboarding exposes the complete installed topic inventory"
assert_grep_fixed 'noid-help search <keyword>' "$TMPDIR/01-getting-started.md" \
    "onboarding exposes the cross-document search workflow"
assert_grep_fixed 'noid-help 06-vpn-setup' "$TMPDIR/01-getting-started.md" \
    "VPN cross-reference is directly runnable in the terminal"
assert_grep_fixed 'noid-help 00-README' "$TMPDIR/01-getting-started.md" \
    "onboarding exposes the complete documentation index"
assert_not_grep_extended '[[:alnum:]_.-]+\.md' \
    "$TMPDIR/01-getting-started.md" \
    "terminal onboarding contains no inert local Markdown-document reference"
# CLI references
assert_grep_fixed "noid-status"                 "$TMPDIR/01-getting-started.md"
assert_grep_fixed "noid-update-all.sh"          "$TMPDIR/01-getting-started.md"
assert_grep_fixed "noid-welcome.sh"             "$TMPDIR/01-getting-started.md"
assert_grep_fixed 'sudo noid-usbguard-devices allow' \
    "$TMPDIR/01-getting-started.md" \
    "unified USBGuard manager reaches persistent admission through its required privilege boundary"
assert_not_grep_extended '^[[:space:]]*noid-usbguard-devices([[:space:]]|$)' \
    "$TMPDIR/01-getting-started.md" \
    "onboarding contains no unprivileged USBGuard invocation"
assert_grep_fixed 'https://docs.mesa3d.org/drivers/nvk.html' \
    "$TMPDIR/01-getting-started.md" \
    "NVIDIA default-driver guidance links the maintained NVK status"
assert_not_grep_extended 'Mesa [0-9]+|for the [0-9]+%|For [0-9]+%|Maxwell through Blackwell' \
    "$TMPDIR/01-getting-started.md" \
    "NVIDIA guidance has no moving version, generation or adoption claim"
assert_grep_fixed 'VSCodium and selected CLI tools are already installed.' \
    "$TMPDIR/01-getting-started.md" \
    "development guidance matches the installed RPM application"
assert_not_grep 'code-tools\|VSCodium via Flatpak' \
    "$TMPDIR/01-getting-started.md" \
    "onboarding cannot recommend a nonexistent package or duplicate editor"
assert_not_grep 'Each accepts `--dry-run`' "$TMPDIR/01-getting-started.md" \
    "onboarding does not invent a shared CLI option contract"
assert_not_grep 'dnf install gnome-bluetooth' "$TMPDIR/01-getting-started.md" \
    "Bluetooth docs follow the installed-but-off pivot"
assert_not_grep_extended 'next GRUB boot menu lets you pick|snapshot from (the )?GRUB|GRUB lists Snapper' \
    "$TMPDIR/01-getting-started.md" \
    "onboarding does not invent grub-btrfs snapshot selection"
assert_grep_fixed 'no grub-btrfs' \
    "$TMPDIR/01-getting-started.md" \
    "onboarding states the real rollback boot boundary"
assert_grep_fixed '-grub-btrfs' "$M20_FILE" \
    "rollback claim is anchored to M20's explicit exclusion"
assert_grep_fixed 'sudo noid-snap-rollback "$snapshot_id"' \
    "$TMPDIR/01-getting-started.md" \
    "onboarding provides the checked rollback command"
assert_not_grep_extended 'baseline taken at install time|automatic AIDE rebaseline' \
    "$TMPDIR/01-getting-started.md" \
    "onboarding does not invent or automatically replace AIDE trust"
assert_grep_fixed '`aide-check.timer` disabled' \
    "$TMPDIR/01-getting-started.md" \
    "onboarding states the initial AIDE timer state"
assert_grep_fixed 'noid-aide-baseline-review prepare' \
    "$TMPDIR/01-getting-started.md" \
    "onboarding requires explicit baseline preparation/review"
assert_grep_fixed 'systemctl disable aide-check.timer' "$M13_FILE" \
    "AIDE onboarding state is anchored to M13"
assert_grep_fixed 'updater does not absorb them automatically' \
    "$TMPDIR/01-getting-started.md" \
    "onboarding preserves update-time AIDE drift"
assert_not_grep 'state of every hardening component' \
    "$TMPDIR/01-getting-started.md" \
    "noid-status is not represented as exhaustive runtime proof"
# Runs-automatically table
assert_grep_fixed "Background services and schedules" "$TMPDIR/01-getting-started.md"
assert_grep_fixed 'disabled until reviewed baseline + explicit enable' \
    "$TMPDIR/01-getting-started.md" \
    "getting-started states the inactive AIDE schedule"
assert_not_grep 'AIDE check | daily 07-08' "$TMPDIR/01-getting-started.md" \
    "getting-started has no unconditional AIDE schedule"
assert_grep_fixed 'System/VPN DNS by default' "$TMPDIR/01-getting-started.md" \
    "getting-started documents the provider-compatible browser DNS default"
assert_not_grep 'TRR Mode 3\|DoH-only' "$TMPDIR/01-getting-started.md" \
    "getting-started does not resurrect the retired forced browser DoH path"
assert_not_grep 'only thing standing between' "$TMPDIR/01-getting-started.md" \
    "onboarding recognizes every active LUKS keyslot credential"
assert_grep_fixed 'Every active LUKS keyslot credential can unlock the volume' \
    "$TMPDIR/01-getting-started.md" \
    "LUKS recovery guidance matches the actual multi-keyslot model"
assert_not_grep 'ISP sees every domain' "$TMPDIR/01-getting-started.md" \
    "onboarding does not overclaim direct-WAN domain visibility"
assert_grep_fixed 'unset VPN/private profiles use best-effort' \
    "$TMPDIR/01-getting-started.md" \
    "onboarding attributes the independent tunnel transport default"
assert_grep_fixed 'both opportunistic paths permit DNS/53 fallback' \
    "$TMPDIR/01-getting-started.md" \
    "onboarding states both explicit and inherited fallback boundaries"
assert_not_grep 'Each site can be relaxed individually' \
    "$TMPDIR/01-getting-started.md" \
    "onboarding does not invent per-site scope for profile-level Firefox helpers"
assert_grep_fixed 'profile-scoped and affect every site' \
    "$TMPDIR/01-getting-started.md" \
    "Firefox compatibility guidance states the selected-profile blast radius"
assert_grep_fixed 'noid-firefox-relax-fpp' "$M16_FILE" \
    "profile-scoped Firefox compatibility claim is anchored to M16"
assert_not_grep_extended 'Continuum|Continue integration' \
    "$TMPDIR/01-getting-started.md" \
    "onboarding contains no removed Continue or Continuum integration"
assert_grep_fixed 'FAT32/exFAT desktop sticks are rejected' \
    "$TMPDIR/01-getting-started.md" \
    "onboarding states the LUKS helper filesystem-permission boundary"
assert_grep_fixed 'LUKS_DEVICE:?export LUKS_DEVICE' \
    "$TMPDIR/01-getting-started.md" \
    "manual LUKS example fails closed until the exact device is supplied"
assert_grep_fixed 'NOID_SNAPSHOT_ID:?export NOID_SNAPSHOT_ID' \
    "$TMPDIR/01-getting-started.md" \
    "rollback example requires the exact reviewed snapshot"
assert_grep_fixed 'Also available as "Install NVIDIA Driver"' \
    "$TMPDIR/01-getting-started.md" \
    "onboarding quotes the exact current NVIDIA Setup row"
assert_grep_fixed "'Install NVIDIA Driver'" "$M13_FILE" \
    "M13 owns the exact NVIDIA row quoted by onboarding"
awk '
    /^#### Manual walkthrough$/ { section=1; next }
    section && /^```bash$/ { capture=1; next }
    capture && /^```$/ { exit }
    capture { print }
' "$TMPDIR/01-getting-started.md" > "$EXEC_TMPDIR/luks-manual-fence.sh"
assert_cmd_success "manual LUKS backup fence parses" \
    bash -n "$EXEC_TMPDIR/luks-manual-fence.sh"
assert_grep_fixed '(' "$EXEC_TMPDIR/luks-manual-fence.sh" \
    "manual LUKS backup runs inside an isolated fail-fast shell"
assert_grep_fixed 'set -euo pipefail' "$EXEC_TMPDIR/luks-manual-fence.sh" \
    "manual LUKS backup makes every precondition load-bearing"
: > "$EXEC_TMPDIR/luks-sudo.log"
assert_cmd_failure "missing manual LUKS backup target stops the pasted fence" \
    env LUKS_DEVICE=/dev/noid-fixture-device \
        LUKS_FENCE="$EXEC_TMPDIR/luks-manual-fence.sh" \
        SUDO_LOG="$EXEC_TMPDIR/luks-sudo.log" bash -c '
            lsblk() { :; }
            sudo() { printf "%s\\n" "$*" >> "$SUDO_LOG"; }
            source "$LUKS_FENCE"
        '
assert_eq '' "$(<"$EXEC_TMPDIR/luks-sudo.log")" \
    "missing backup target cannot reach cryptsetup or any privileged command"
assert_grep_fixed 'even after that passphrase is removed from the live header' \
    "$TMPDIR/01-getting-started.md" \
    "onboarding states the cryptsetup header-backup credential-retention risk"

# --- 06-vpn-setup.md structural markers -------------------------------------

assert_grep_fixed "ProtonVPN"                   "$TMPDIR/06-vpn-setup.md"
assert_grep_fixed "Mullvad"                     "$TMPDIR/06-vpn-setup.md"
assert_grep_fixed "Generic WireGuard"           "$TMPDIR/06-vpn-setup.md"
assert_grep_fixed "OpenVPN"                     "$TMPDIR/06-vpn-setup.md"
assert_grep_fixed "nmcli connection import"     "$TMPDIR/06-vpn-setup.md"
assert_grep_fixed 'nmcli --get-values GENERAL.NAME --escape no connection show "$initial_profile"' \
    "$TMPDIR/06-vpn-setup.md" "import verification matches the created profile name"
assert_not_grep 'nmcli -g NAME connection show' \
    "$TMPDIR/06-vpn-setup.md" \
    "VPN examples do not request the invalid detailed NAME field"
assert_not_grep 'protonde' "$TMPDIR/06-vpn-setup.md" \
    "drifted Proton profile name cannot return"
assert_grep_fixed "killswitch"                  "$TMPDIR/06-vpn-setup.md"
assert_grep_fixed '**System/VPN DNS in Firefox**' "$TMPDIR/06-vpn-setup.md" \
    "VPN guide architecture list uses the current resolver contract"
assert_grep_fixed "TunnelVision"                "$TMPDIR/06-vpn-setup.md" "TunnelVision CVE referenced"
assert_grep_fixed 'Module 23' "$TMPDIR/06-vpn-setup.md" \
    "TunnelVision route enforcement is attributed to its actual owner"
assert_not_grep 'TunnelVision.*Module 05\|see Module 05 docs' "$TMPDIR/06-vpn-setup.md" \
    "TunnelVision docs contain no stale M05 ownership claim"
assert_grep_fixed "am.i.mullvad.net"            "$TMPDIR/06-vpn-setup.md" "IP-leak test procedure"
assert_grep_fixed "necessarily discloses the tested" \
    "$TMPDIR/06-vpn-setup.md" \
    "VPN guide states the external leak-test disclosure boundary"
assert_grep_fixed "Troubleshooting"             "$TMPDIR/06-vpn-setup.md"
assert_grep_fixed "connection.zone noid-vpn"    "$TMPDIR/06-vpn-setup.md" "NoID Privacy hardened VPN-zone behavior explained"
# Most providers embed the certificate and key in the .ovpn. NetworkManager
# extracts those under the importing user's home, and M08 raises ProtectHome to
# yes, so its OpenVPN child cannot open them: measured on the image, the same
# profile fails with errno=2 on the default path and connects with traffic when
# the extraction is redirected to /etc/openvpn. The documented command must
# carry that redirect, and the note must stay, because NetworkManager reports
# only "Unknown reason" to the user.
assert_grep_fixed 'sudo env XDG_DATA_HOME=/etc/openvpn/noid-imported' \
    "$TMPDIR/06-vpn-setup.md" \
    "the documented OpenVPN import keeps embedded certificates out of a home directory"
assert_grep_fixed 'sudo install -d -m 0700 /etc/openvpn/noid-imported' \
    "$TMPDIR/06-vpn-setup.md" \
    "the redirect target is created with a private mode before the import"
assert_grep_fixed 'ProtectHome=yes' "$TMPDIR/06-vpn-setup.md" \
    "the note names the sandbox setting that causes the failure"
assert_grep_fixed 'No such file or directory (errno=2)' \
    "$TMPDIR/06-vpn-setup.md" \
    "the note quotes the journal line, since the UI only says Unknown reason"
assert_grep_extended 'GNOME Settings import has no equivalent setting' \
    "$TMPDIR/06-vpn-setup.md" \
    "the unsupported graphical import path is named rather than left to fail silently"
assert_grep_fixed 'development release 1.51.6 and stable releases 1.50.2 / 1.48.16' \
    "$TMPDIR/06-vpn-setup.md" \
    "TunnelVision guidance distinguishes development and stable fixes"
assert_grep_fixed 'VPN_PROFILE:?export VPN_PROFILE with the exact VPN connection name' \
    "$TMPDIR/06-vpn-setup.md" \
    "policy-routing example requires an exact selected VPN profile"
assert_grep_fixed 'Table 75 is a table identifier; rule priority' \
    "$TMPDIR/06-vpn-setup.md" \
    "policy-routing explanation does not compare a table ID with rule priority"
assert_grep_fixed '32000 is evaluated before the main lookup rule at 32766.' \
    "$TMPDIR/06-vpn-setup.md" \
    "policy-routing precedence follows the kernel rule order"
assert_grep_fixed 'rpm -q unzip' \
    "$TMPDIR/06-vpn-setup.md" \
    "Mullvad NetworkManager prerequisites verify the image-owned unzip package"
assert_grep_fixed 'rpm -q wireguard-tools || sudo dnf install wireguard-tools' \
    "$TMPDIR/06-vpn-setup.md" \
    "the image-owned WireGuard tooling is confirmed, and recovered if removed"
# M26 ships wireguard-tools. The docs must never tell the reader otherwise;
# that claim was live in four places at once while every module's own tests
# stayed green, because each only checked itself.
assert_not_grep_extended 'not pre-installed|does not include[^[:cntrl:]]*wireguard-tools|NOT pre-installed' \
    "$TMPDIR/06-vpn-setup.md" \
    "the docs never claim the image ships without wireguard-tools"
assert_grep_fixed 'https://mullvad.net/en/help/wireguard-and-mullvad-vpn' \
    "$TMPDIR/06-vpn-setup.md" \
    "resolver-package ownership links Mullvad's separate wg-quick path"
assert_not_grep_extended 'dnf install[^[:cntrl:]]*openresolv|install both `wireguard-tools` and `openresolv`' \
    "$TMPDIR/06-vpn-setup.md" \
    "NetworkManager import guidance never installs the wg-quick resolver package"
assert_grep_fixed 'rpm -q NetworkManager-openvpn NetworkManager-openvpn-gnome' \
    "$TMPDIR/06-vpn-setup.md" \
    "OpenVPN path verifies its explicit native NetworkManager baseline"
assert_not_grep_extended 'dnf install[^[:cntrl:]]*NetworkManager-openvpn' \
    "$TMPDIR/06-vpn-setup.md" \
    "OpenVPN path does not perform a redundant package transaction"
for pkg in NetworkManager-openvpn NetworkManager-openvpn-gnome; do
    assert_grep_extended "^${pkg}$" "$M26_FILE" \
        "M26 explicitly owns M29's OpenVPN prerequisite: $pkg"
    if grep -Eq "(^|[[:space:]])${pkg}([[:space:]]|$)" \
            <<<"$(sed -n '/^MUST_PRESENT=(/,/^)/p' "$M26_FILE")"; then
        _pass "M26 runtime-gates M29's OpenVPN prerequisite: $pkg"
    else
        _fail "M26 does not runtime-gate M29's OpenVPN prerequisite: $pkg"
    fi
done
assert_not_grep 'OpenVPN** — legacy providers' \
    "$TMPDIR/01-getting-started.md" \
    "onboarding does not misclassify maintained OpenVPN as legacy-only"
assert_grep_fixed 'hardened inbound-DROP `noid-vpn`' \
    "$TMPDIR/06-vpn-setup.md" \
    "VPN dispatcher guidance names the actual target-DROP zone"
assert_grep_fixed "never promotes them to" "$TMPDIR/06-vpn-setup.md" \
    "VPN dispatcher guidance rejects target-ACCEPT trusted semantics"
assert_not_grep_extended 'auto-trust|always-VPN" 99%' "$TMPDIR/06-vpn-setup.md" \
    "VPN guidance has no trusted-zone or unmeasured adoption claim"
assert_grep_fixed 'sudo grep "zone=noid-vpn" /etc/NetworkManager/dispatcher.d/50-vpn-zone-enforce' \
    "$TMPDIR/06-vpn-setup.md" \
    "dispatcher diagnosis uses the privilege required by its root-private mode"
assert_grep_fixed 'protonvpn config set kill-switch standard' \
    "$TMPDIR/06-vpn-setup.md" "Proton CLI uses the current standard-mode command"
assert_grep_fixed 'protonvpn signin "$proton_account"' \
    "$TMPDIR/06-vpn-setup.md" \
    "Proton login example passes an explicitly supplied account value"
assert_grep_fixed 'PROTON_WG_CONFIG:?export PROTON_WG_CONFIG' \
    "$TMPDIR/06-vpn-setup.md" \
    "Proton import requires the exact downloaded configuration"
assert_grep_fixed 'PROTON_PROFILE:?export PROTON_PROFILE' \
    "$TMPDIR/06-vpn-setup.md" \
    "Proton preference steps require the exact imported profile"
assert_grep_fixed 'Remove the vendor repository package only after both clients are absent.' \
    "$TMPDIR/06-vpn-setup.md" \
    "Proton uninstall preserves repository ownership while another client remains"
assert_not_grep 'protonvpn config set kill-switch on' \
    "$TMPDIR/06-vpn-setup.md" "stale Proton kill-switch command is absent"
assert_grep_fixed 'CLI and GUI cannot run' "$TMPDIR/06-vpn-setup.md" \
    "Proton CLI/GUI concurrency limitation is explicit"
assert_not_grep_extended 'they can coexist|already prevents leaks|traffic simply stops|safety-net alone is sufficient' \
    "$TMPDIR/06-vpn-setup.md" "VPN guide has no merged-layer leak promise"
assert_grep_fixed 'NetworkManager native' "$TMPDIR/06-vpn-setup.md" \
    "Mullvad walkthrough distinguishes native NM from wg-quick"
assert_grep_fixed 'no corresponding hook setting' \
    "$TMPDIR/06-vpn-setup.md" \
    "Mullvad generated hooks are not misrepresented as imported kill-switch state"
assert_grep_fixed 'wg-quick `PostUp`/`PreDown` firewall commands' \
    "$TMPDIR/06-vpn-setup.md" \
    "Mullvad generator kill-switch ownership is explicit"
assert_grep_fixed 'MULLVAD_CONFIG_BASENAME:?export one exact .conf member basename' \
    "$TMPDIR/06-vpn-setup.md" \
    "Mullvad import extracts one explicitly selected archive member"
assert_grep_fixed 'MULLVAD_PROFILE:?export MULLVAD_PROFILE' \
    "$TMPDIR/06-vpn-setup.md" \
    "Mullvad preference steps require the exact imported profile"
assert_grep_fixed 'WIREGUARD_CONFIG:?export WIREGUARD_CONFIG' \
    "$TMPDIR/06-vpn-setup.md" \
    "generic WireGuard import requires the exact configuration"
assert_grep_fixed 'OPENVPN_CONFIG:?export OPENVPN_CONFIG' \
    "$TMPDIR/06-vpn-setup.md" \
    "OpenVPN import requires the exact configuration"
assert_not_grep_extended 'file ~/Downloads/myvpn\.(conf|ovpn)|modify myvpn|up myvpn' \
    "$TMPDIR/06-vpn-setup.md" \
    "generic VPN examples contain no assumed active filename or profile"
assert_not_grep_extended 'No dashes|chokes on dashes|remove dashes|more forgiving about dashes' \
    "$TMPDIR/06-vpn-setup.md" \
    "valid WireGuard dashes are never rejected by stale advice"
assert_grep_fixed 'Dashes are valid WireGuard' "$TMPDIR/06-vpn-setup.md" \
    "Proton walkthrough documents valid hyphenated names"
assert_grep_fixed 'under 15 characters' "$TMPDIR/06-vpn-setup.md" \
    "Proton walkthrough retains the current conservative length guidance"
assert_grep_fixed 'vpn_if=$(nmcli --get-values GENERAL.DEVICES --escape no' \
    "$TMPDIR/06-vpn-setup.md" \
    "verification resolves the effective tunnel device dynamically"
assert_not_grep '^VPN_PROFILE=' "$TMPDIR/06-vpn-setup.md" \
    "VPN verification contains no active assumed profile name"
assert_eq 4 \
    "$(grep -c '^vpn_profile=${VPN_PROFILE:?' "$TMPDIR/06-vpn-setup.md")" \
    "every operational VPN-profile fence requires an explicit selected profile"
assert_grep_fixed 'sudo sed -n '\''/^case "$IFACE" in/,/^esac/p'\''' \
    "$TMPDIR/06-vpn-setup.md" \
    "dispatcher diagnosis reads the complete active skip-list contract"
assert_grep_fixed 'case "$IFACE" in' "$M06_FILE" \
    "M06 owns the dispatcher case block read by the diagnosis"
assert_grep_fixed '### LAN isolation blocks local devices (block-lan-out)' \
    "$TMPDIR/06-vpn-setup.md" \
    "LAN-isolation troubleshooting is not mislabeled as a kill switch"
assert_not_grep '### Kill switch blocks local LAN' \
    "$TMPDIR/06-vpn-setup.md" \
    "retired LAN/killswitch conflation cannot return"
assert_not_grep 'via `Name = `' "$TMPDIR/06-vpn-setup.md" \
    "invalid WireGuard Name key cannot return"
assert_grep_fixed 'Only NoID Privacy inbound `drop` + block-lan-out' \
    "$TMPDIR/06-vpn-setup.md" "tunnel-down matrix states base direct-WAN fallback"
assert_grep_fixed 'NoID Privacy WAN-strict `STRICT`' "$TMPDIR/06-vpn-setup.md" \
    "tunnel-down matrix states strict physical-egress blocking"
assert_grep_fixed 'standard` blocks traffic after an accidental tunnel' \
    "$TMPDIR/06-vpn-setup.md" "Proton standard-mode accidental-loss scope is explicit"
assert_grep_fixed 'does **not** block when you deliberately disconnect' \
    "$TMPDIR/06-vpn-setup.md" "Proton standard-mode manual-disconnect boundary is explicit"
assert_grep_fixed 'defers the actual VPN reconnect until the session unlocks' \
    "$TMPDIR/06-vpn-setup.md" \
    "installed VPN guide documents Proton's locked-session reconnect boundary"
assert_grep_fixed 'proton-vpn-gtk-app/blob/v4.16.5/proton/vpn/app/gtk/services/reconnector/reconnector.py' \
    "$TMPDIR/06-vpn-setup.md" \
    "installed locked-session boundary links the tagged provider implementation"
assert_grep_fixed 'A failed ping alone is never sufficient proof' \
    "$TMPDIR/06-vpn-setup.md" "tunnel-down procedure rejects ping-only proof"
assert_grep_fixed 'curl --interface "$phys"' "$TMPDIR/06-vpn-setup.md" \
    "tunnel-down procedure binds a real connection to the physical interface"
assert_grep_fixed 'restore_vpn' "$TMPDIR/06-vpn-setup.md" \
    "tunnel-down procedure restores the selected VPN profile"
assert_not_grep 'PHYS=$(ip -4 route show default' \
    "$TMPDIR/06-vpn-setup.md" \
    "tunnel-down procedure does not guess a physical NIC from one default route"
assert_grep_fixed 'nft list counters table inet noid_wan_strict' \
    "$TMPDIR/06-vpn-setup.md" "strict-mode test retains counter evidence"
assert_grep_fixed 'sudo noid-lan-allow --list' \
    "$TMPDIR/06-vpn-setup.md" \
    "LAN-exception inventory uses the helper's privileged contract"
assert_not_grep 'modules are removed rather than left' \
    "$TMPDIR/06-vpn-setup.md" \
    "blacklisted IPsec/L2TP modules are not misrepresented as absent files"
assert_grep_fixed 'This is not a blanket claim that modern IKEv2/IPsec is insecure.' \
    "$TMPDIR/06-vpn-setup.md" \
    "unsupported IKEv2 is not misrepresented as cryptographically broken"
assert_grep_fixed 'RFC 9395' "$TMPDIR/06-vpn-setup.md" \
    "VPN guide distinguishes deprecated IKEv1 from modern IKEv2"
assert_grep_fixed 'Bare L2TP does not define' \
    "$TMPDIR/06-vpn-setup.md" \
    "VPN guide states the actual L2TP security boundary"
assert_grep_fixed 'Unknown WAN-strict schemas fail' \
    "$TMPDIR/06-vpn-setup.md" \
    "unsupported VPN schemas retain fail-closed WAN-strict semantics"
assert_grep_fixed 'provider, profile, account, server or credential is preconfigured.' \
    "$TMPDIR/06-vpn-setup.md" \
    "included OpenVPN integration is not misrepresented as a configured provider"
assert_grep_fixed $'esp4\tdeny-loadable\t-' "$M21_FILE" \
    "M21 owner denies the stock IPv4 ESP transform"
assert_grep_fixed $'esp6\tdeny-loadable\t-' "$M21_FILE" \
    "M21 owner denies the stock IPv6 ESP transform"
assert_grep_fixed $'l2tp_ppp\tdeny-loadable\t-' "$M21_FILE" \
    "M21 owner denies the stock L2TP PPP path"
assert_not_grep_extended \
    'NetworkManager-(strongswan|libreswan|l2tp)|(^|[[:space:]])(strongswan|libreswan|xl2tpd)([[:space:]]|$)' \
    "$M26_FILE" \
    "M26 base package set ships no IPsec/IKEv2/L2TP client stack"
assert_not_grep 'Most common cause:' "$TMPDIR/06-vpn-setup.md" \
    "troubleshooting avoids an unsupported cause-frequency claim"
assert_file_exists "$VPN_FIXTURE" "VPN tunnel-down source fixture exists"
assert_cmd_success "VPN tunnel-down fixture matches M03/M06 semantics" \
    python3 "$VPN_FIXTURE" "$TMPDIR/block-lan-out.xml" \
    "$TMPDIR/noid-wan-strict.nft" "$TMPDIR/06-vpn-setup.md"
assert_file_exists "$PROTON_GUIDE" "standalone Proton guide exists"
assert_grep_fixed 'Provider-owned kill-switch state' "$PROTON_GUIDE" \
    "Proton guide leaves provider profile lifecycle provider-owned"
assert_grep_fixed 'sink DNS values `0.0.0.0`' "$PROTON_GUIDE" \
    "Proton guide documents deliberate backend sentinel DNS"
assert_grep_fixed 'NoID Privacy' "$PROTON_GUIDE" \
    "Proton guide distinguishes the provider and NoID Privacy boundaries"
assert_grep_fixed 'defers the actual VPN reconnect until the session unlocks' \
    "$PROTON_GUIDE" \
    "standalone Proton guide documents locked-session reconnect behavior"
assert_grep_fixed 'proton-vpn-gtk-app/blob/v4.16.5/proton/vpn/app/gtk/services/reconnector/reconnector.py' \
    "$PROTON_GUIDE" \
    "standalone locked-session claim links the tested tagged source"
assert_not_grep 'immediate VPN reconnect on boot' "$PROTON_GUIDE" \
    "standalone guide makes no unsupported boot-level reconnect promise"
assert_not_grep_extended \
    'connection\.autoconnect-priority 999|re-apply 999|nmcli connection modify "pvpn-killswitch-perm"' \
    "$PROTON_GUIDE" \
    "Proton guide never recommends recurring mutation of an ephemeral provider profile"
assert_not_grep 'nmcli connection delete pvpn-' "$TMPDIR/06-vpn-setup.md" \
    "installed guide does not delete provider-owned profiles by guessed names"
assert_not_grep_extended \
    'protonvpn-stable-release-1\.0\.4|6929133BDE1CE1CFA9EDB286D84176F6844830D4' \
    "$PROTON_GUIDE" \
    "standalone guide does not freeze mutable Proton RPM or key values"
assert_grep_fixed \
    'cp /usr/share/applications/proton.vpn.app.gtk.desktop ~/.config/autostart/' \
    "$PROTON_GUIDE" \
    "manual Proton autostart preserves the packaged desktop-file basename"
assert_grep_fixed \
    'Exec=/usr/local/bin/noid-autostart-netwait -- protonvpn-app' \
    "$PROTON_GUIDE" \
    "manual Proton autostart documents the exact Setup gate equivalent"
assert_grep_fixed 'Unrelated apps remain ungated by default.' "$PROTON_GUIDE" \
    "VPN-aware initial gating does not silently delay every application"
assert_not_grep 'dedicated IVPN' "$PROTON_GUIDE" \
    "Proton guide does not grow an unreviewed IVPN support claim"
assert_grep_fixed 'IPsec/IKEv2 is not one of M06' "$PROTON_GUIDE" \
    "provider alternatives keep IPsec outside the supported M06 path"
assert_grep_fixed 'ivpn/desktop-app/blob/development/readme.md' \
    "$PROTON_GUIDE" \
    "IVPN protocol wording cites the provider's current official source"
assert_grep_fixed 'Public-IP and DNS websites' "$PROTON_GUIDE" \
    "standalone Proton guide does not flatten observations into kill-switch proof"

# --- gnome-extensions-autostart.md semantics -------------------------------

assert_grep_fixed 'GNOME 50 extensions and app autostart' \
    "$TMPDIR/gnome-extensions-autostart.md" "fourth M29 heredoc extracted"
assert_grep_fixed 'it **cannot bypass' \
    "$TMPDIR/gnome-extensions-autostart.md" \
    "Tweaks follows the real system-lock precedence model"
assert_grep_fixed 'a system lock takes precedence over the' \
    "$TMPDIR/gnome-extensions-autostart.md" \
    "dconf precedence is explicit"
assert_grep_fixed 'user-initiated M25 Update' \
    "$TMPDIR/gnome-extensions-autostart.md" \
    "Just-Perfection documentation states the explicit runtime EGO owner"
assert_not_grep 'performs no runtime EGO discovery' \
    "$TMPDIR/gnome-extensions-autostart.md" \
    "stale immutable-Just-Perfection update claim cannot return"
assert_grep_fixed 'explicit EGO update' "$M25_FILE" \
    "Just-Perfection runtime-update claim is anchored to M25"
assert_grep_fixed 'not an upstream signature or source review' \
    "$TMPDIR/gnome-extensions-autostart.md" \
    "EGO update evidence is not misrepresented as renewed code review"
assert_grep_fixed 'GPL-3.0-only' \
    "$TMPDIR/gnome-extensions-autostart.md" \
    "Just-Perfection license identifier matches its source headers"
assert_grep_fixed 'GPL-2.0-only' \
    "$TMPDIR/gnome-extensions-autostart.md" \
    "AppIndicator license identifier matches Fedora package metadata"

# Replay every production M29 keyword against each actual extracted deployed
# document. Bind the test to production's fixed-string search semantics as
# well: a regex grep interprets Markdown `**` and can fail despite identical
# bytes, which was exposed only by the seventh canonical compose.
replay_m29_verifier() {
    local start_marker="$1" end_marker="$2" doc="$3" expected_count="$4"
    local block="$TMPDIR/verifier-${doc}.block" verify_line kw count=0

    sed -n "/^# ---- ${start_marker} ----$/,/^# ---- ${end_marker} ----$/p" \
        "$KS_FILE" > "$block"
    assert_grep_fixed \
        "if grep -qiF -- \"\$kw\" /usr/share/doc/noid-privacy/${doc} 2>/dev/null; then" \
        "$block" "production M29 verifier uses literal search for ${doc}"
    verify_line=$(grep '^for kw in ' "$block")
    while IFS= read -r kw; do
        [ -n "$kw" ] || continue
        count=$((count + 1))
        if grep -qiF -- "$kw" "$TMPDIR/$doc"; then
            _pass "deployed M29 verifier keyword resolves in ${doc}: $kw"
        else
            _fail "deployed M29 verifier keyword is absent from ${doc}: $kw"
        fi
    done < <(printf '%s\n' "$verify_line" | grep -oE '"[^"]+"' | tr -d '"')
    assert_eq "$expected_count" "$count" \
        "deployed M29 verifier has the reviewed keyword count for ${doc}"
}

replay_m29_verifier '00-README.md' '01-getting-started.md' \
    '00-README.md' 7
replay_m29_verifier '01-getting-started.md' '06-vpn-setup.md' \
    '01-getting-started.md' 8
replay_m29_verifier '06-vpn-setup.md' 'gnome-extensions-autostart.md' \
    '06-vpn-setup.md' 10
replay_m29_verifier 'gnome-extensions-autostart.md' 'Permissions' \
    'gnome-extensions-autostart.md' 10
assert_not_grep '"cannot bypass a dconf lock"' "$KS_FILE" \
    "M29 verifier does not require a phrase spanning a Markdown line break"
assert_grep_fixed 'Tweaks → Startup Applications' \
    "$TMPDIR/gnome-extensions-autostart.md" \
    "GNOME-supported optional autostart GUI is documented"
assert_grep_fixed 'between **Gaming Mode (Steam /' \
    "$TMPDIR/gnome-extensions-autostart.md" \
    "installed autostart guide names the current preceding Setup group"
assert_grep_fixed 'and **Security Notifications**' \
    "$TMPDIR/gnome-extensions-autostart.md" \
    "installed autostart guide names the current following Setup group"
assert_grep_fixed 'https://help.gnome.org/gnome-help/shell-apps-auto-start.html' \
    "$TMPDIR/gnome-extensions-autostart.md" \
    "GNOME autostart guidance links its primary source"
assert_grep_fixed 'https://help.gnome.org/system-admin-guide/dconf-lockdown.html' \
    "$TMPDIR/gnome-extensions-autostart.md" \
    "dconf-lock statement links its primary source"
assert_grep_fixed 'system-wide entry does not inherently make GTK windows hidden' \
    "$TMPDIR/gnome-extensions-autostart.md" \
    "system-wide XDG behavior is not replaced by incident folklore"
assert_grep_fixed 'what an already launched application opens; it does not start that application' \
    "$TMPDIR/gnome-extensions-autostart.md" \
    "runtime-startup preferences are distinguished from login autostart"
assert_grep_fixed 'Do not assume byte or' \
    "$TMPDIR/gnome-extensions-autostart.md" \
    "application-owned controls make no invented implementation-equivalence claim"
assert_grep_fixed 'dnf --cacheonly search vitals' \
    "$TMPDIR/gnome-extensions-autostart.md" \
    "Vitals guidance checks cached repository availability without egress"
assert_not_grep 'gnome-shell-extension-vitals\|Vitals@CoreCoding.com' \
    "$TMPDIR/gnome-extensions-autostart.md" \
    "nonexistent Vitals RPM and assumed UUID recipe cannot return"
assert_not_grep_extended 'GNOME 49 dropped|was removed in GNOME 49|early-gnome-session|some of its toggles bypass|User clicks can undo' \
    "$TMPDIR/gnome-extensions-autostart.md" \
    "unsupported GNOME history, hidden-window and lock-bypass claims are absent"
assert_not_grep 'requires an administrator to deliberately remove' \
    "$TMPDIR/gnome-extensions-autostart.md" \
    "optional extension guidance does not recommend weakening the system lock"
assert_grep_fixed 'Keep the system extension-install lock in place.' \
    "$TMPDIR/gnome-extensions-autostart.md" \
    "optional extension guidance preserves the silent-machine policy"
assert_grep_fixed '/org/gnome/shell/allow-extension-installation' \
    "$TMPDIR/noid-gnome-locks" "M17 actually locks extension installation"
assert_not_grep '/org/gnome/shell/enabled-extensions' \
    "$TMPDIR/noid-gnome-locks" "M17 leaves installed-extension enablement user-controlled"
assert_grep_fixed 'shutil.copy2(source_desktop_path, target)' "$M13_FILE" \
    "M29 Welcome description is anchored to M13's actual copy operation"
assert_not_grep 'exactly the same as Method 3' \
    "$TMPDIR/gnome-extensions-autostart.md" \
    "Welcome and manual autostart paths are not misrepresented as metadata-identical"
assert_not_grep 'proton-vpn-app.desktop' \
    "$TMPDIR/gnome-extensions-autostart.md" \
    "autostart removal guidance contains no stale Proton desktop basename"
assert_grep_fixed "grep -qx 'Hidden=true'" \
    "$TMPDIR/gnome-extensions-autostart.md" \
    "reversible autostart disable verifies the resulting XDG key"
assert_not_grep 'ExecStart=/path/to/script' \
    "$TMPDIR/gnome-extensions-autostart.md" \
    "systemd user-service example contains no guaranteed-missing executable"
assert_grep_fixed 'systemd-analyze verify "$stage/myservice.service"' \
    "$TMPDIR/gnome-extensions-autostart.md" \
    "systemd user-service example validates its unit before publication"
assert_file_exists "$PROTON_GUIDE" "standalone Proton guide exists"
assert_not_grep_extended 'early-gnome-session-context|makes the GTK window stay' \
    "$PROTON_GUIDE" "standalone Proton guide shares the corrected XDG scope model"
assert_grep_fixed 'inherently hide GTK windows' "$PROTON_GUIDE" \
    "standalone Proton guide recognizes supported system-wide autostart"

# --- Module 29 must NOT install any packages ------------------------------
# (The %packages block should be empty except the `no packages` comment.)

if awk '/^%packages/,/^%end/' "$KS_FILE" | grep -vE '^(%|#|$|-)' | grep -qE '^[a-zA-Z]'; then
    _fail "M29 %packages contains non-comment package lines (should be doc-only)"
else
    _pass "M29 %packages is doc-only (no package installs)"
fi
assert_not_grep 'doc_rpms=' "$KS_FILE" \
    "M29 contains no permanently-green fictional package counter"
assert_grep_fixed 'rpm -qa >/dev/null 2>&1' "$KS_FILE" \
    "M29 requires a working RPM database before ownership checks"
assert_grep_fixed 'rpm -qf -- "$1"' "$KS_FILE" \
    "M29 verifies every published document has no RPM owner"

# --- Health stamp ----------------------------------------------------------
# Old success is retired before any owned document changes, and the exact
# replacement is published only after the verification guard.

assert_grep_fixed "stamp-29-user-docs.ok"    "$KS_FILE" "stamp file path present"
assert_grep_fixed "module=29"               "$KS_FILE" "stamp declares module=29"
assert_grep_fixed "status=ok"                "$KS_FILE" "stamp sets status=ok"
assert_grep_fixed "/var/lib/noid-privacy"    "$KS_FILE" "stamp lives under /var/lib/noid-privacy/"

guard_line=$(grep -n 'fails.*-gt 0' "$KS_FILE" | head -1 | cut -d: -f1)
invalidate_line=$(grep -nF \
    '# M29_HEALTH_INVALIDATION_BEGIN' "$KS_FILE" | cut -d: -f1)
first_payload_line=$(grep -nF \
    'install -d -m 0755 -o root -g root "$DOC_DIR"' \
    "$KS_FILE" | cut -d: -f1)
publish_line=$(grep -nF \
    '# M29_HEALTH_PUBLICATION_BEGIN' "$KS_FILE" | cut -d: -f1)
complete_line=$(grep -nF \
    'log "=== Module 29 User Documentation complete ==="' \
    "$KS_FILE" | cut -d: -f1)
if [ -n "$guard_line" ] && [ -n "$invalidate_line" ] \
   && [ -n "$first_payload_line" ] && [ -n "$publish_line" ] \
   && [ -n "$complete_line" ] \
   && [ "$invalidate_line" -lt "$first_payload_line" ] \
   && [ "$guard_line" -lt "$publish_line" ] \
   && [ "$publish_line" -lt "$complete_line" ]; then
    _pass "M29 retires old health before mutation and publishes only after verification"
else
    _fail "M29 health-stamp ordering is not failure-atomic"
fi

# Execute the exact production health-boundary blocks. Candidate/final label
# and rename failures must all remain stamp-less.
m29_stamp_root="$EXEC_TMPDIR/health-stamp"
m29_stamp_state="$m29_stamp_root/state"
m29_stamp_bin="$m29_stamp_root/bin"
m29_stamp_invalidate="$m29_stamp_root/invalidate.sh"
m29_stamp_publish="$m29_stamp_root/publish.sh"
m29_stamp_uid=$(id -u)
m29_stamp_gid=$(id -g)
mkdir -p "$m29_stamp_bin"

cat > "$m29_stamp_bin/restorecon" <<'M29_STAMP_RESTORECON_EOF'
#!/usr/bin/env bash
set -euo pipefail
target="${!#}"
case "${FAKE_RESTORECON_FAIL:-}" in
    all) exit 1 ;;
    final)
        case "$target" in
            */stamp-29-user-docs.ok) exit 1 ;;
        esac
        ;;
esac
exit 0
M29_STAMP_RESTORECON_EOF
cat > "$m29_stamp_bin/matchpathcon" <<'M29_STAMP_MATCHPATHCON_EOF'
#!/usr/bin/env bash
exit 0
M29_STAMP_MATCHPATHCON_EOF
cat > "$m29_stamp_bin/mv" <<'M29_STAMP_MV_EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "${FAKE_MV_FAIL:-0}" -eq 1 ]; then
    exit 1
fi
exec /usr/bin/mv "$@"
M29_STAMP_MV_EOF
chmod 0700 "$m29_stamp_bin/restorecon" \
    "$m29_stamp_bin/matchpathcon" "$m29_stamp_bin/mv"

{
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
        'PHASE=test' 'log() { :; }' 'die() { exit 1; }' \
        "STAMP_DIR=$m29_stamp_state" \
        'STAMP="$STAMP_DIR/stamp-29-user-docs.ok"'
    sed -n \
        '/^# M29_HEALTH_INVALIDATION_BEGIN$/,/^# M29_HEALTH_INVALIDATION_END$/p' \
        "$KS_FILE" |
        sed -e "s|/var/lib/noid-privacy|$m29_stamp_state|g" \
            -e "s/-o root -g root/-o $m29_stamp_uid -g $m29_stamp_gid/" \
            -e "s/0:0:755/$m29_stamp_uid:$m29_stamp_gid:755/"
} > "$m29_stamp_invalidate"
{
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' \
        'PHASE=test' 'log() { :; }' 'die() { exit 1; }' \
        "STAMP_DIR=$m29_stamp_state" \
        'STAMP="$STAMP_DIR/stamp-29-user-docs.ok"' \
        'DOC_TMP=' 'STAMP_TMP=' 'STAMP_PUBLICATION_ACTIVE=0' \
        'checks=41' 'fails=0'
    sed -n '/^cleanup() {$/,/^}$/p' "$KS_FILE"
    printf '%s\n' 'trap cleanup EXIT'
    sed -n \
        '/^# M29_HEALTH_PUBLICATION_BEGIN$/,/^# M29_HEALTH_PUBLICATION_END$/p' \
        "$KS_FILE" |
        sed -e "s/chown root:root/chown $m29_stamp_uid:$m29_stamp_gid/" \
            -e "s/0:0:755/$m29_stamp_uid:$m29_stamp_gid:755/" \
            -e "s/0:0:644:1/$m29_stamp_uid:$m29_stamp_gid:644:1/"
} > "$m29_stamp_publish"
chmod 0700 "$m29_stamp_invalidate" "$m29_stamp_publish"

mkdir -m 0755 "$m29_stamp_state"
printf '%s\n' 'module=29' 'name=user-docs' 'status=ok' \
    > "$m29_stamp_state/stamp-29-user-docs.ok"
assert_cmd_success "M29 rerun invalidates its prior build-success stamp" \
    env PATH="$m29_stamp_bin:$PATH" "$m29_stamp_invalidate"
if [ ! -e "$m29_stamp_state/stamp-29-user-docs.ok" ]; then
    _pass "M29 old success evidence is absent before document publication"
else
    _fail "M29 old success evidence is absent before document publication"
fi

chmod 0777 "$m29_stamp_state"
printf '%s\n' 'must-survive' \
    > "$m29_stamp_state/stamp-29-user-docs.ok"
assert_cmd_failure "M29 rejects shared state-directory metadata drift" \
    env PATH="$m29_stamp_bin:$PATH" "$m29_stamp_invalidate"
assert_eq "$m29_stamp_uid:$m29_stamp_gid:777" \
    "$(stat -c '%u:%g:%a' "$m29_stamp_state")" \
    "M29 does not normalize drifted shared-directory metadata"
assert_grep_fixed 'must-survive' \
    "$m29_stamp_state/stamp-29-user-docs.ok" \
    "M29 does not traverse a drifted shared state boundary"
rm "$m29_stamp_state/stamp-29-user-docs.ok"
chmod 0755 "$m29_stamp_state"

assert_cmd_failure "M29 rejects a health-stamp candidate label failure" \
    env PATH="$m29_stamp_bin:$PATH" FAKE_RESTORECON_FAIL=all \
        "$m29_stamp_publish"
if [ ! -e "$m29_stamp_state/stamp-29-user-docs.ok" ] \
   && [ -z "$(find "$m29_stamp_state" -maxdepth 1 \
        -name '.stamp-29-user-docs.ok.*' -print -quit)" ]; then
    _pass "M29 candidate-label failure leaves no plausible health evidence"
else
    _fail "M29 candidate-label failure leaves no plausible health evidence"
fi

assert_cmd_failure "M29 retires a stamp after final-label failure" \
    env PATH="$m29_stamp_bin:$PATH" FAKE_RESTORECON_FAIL=final \
        "$m29_stamp_publish"
if [ ! -e "$m29_stamp_state/stamp-29-user-docs.ok" ]; then
    _pass "M29 final-label failure removes the published success stamp"
else
    _fail "M29 final-label failure removes the published success stamp"
fi

assert_cmd_failure "M29 rejects an atomic health-stamp rename failure" \
    env PATH="$m29_stamp_bin:$PATH" FAKE_MV_FAIL=1 "$m29_stamp_publish"
if [ ! -e "$m29_stamp_state/stamp-29-user-docs.ok" ] \
   && [ -z "$(find "$m29_stamp_state" -maxdepth 1 \
        -name '.stamp-29-user-docs.ok.*' -print -quit)" ]; then
    _pass "M29 rename failure leaves no stamp or staged candidate"
else
    _fail "M29 rename failure leaves no stamp or staged candidate"
fi

assert_cmd_success "M29 publishes exact health evidence after all gates" \
    env PATH="$m29_stamp_bin:$PATH" "$m29_stamp_publish"
assert_grep_fixed 'module=29' \
    "$m29_stamp_state/stamp-29-user-docs.ok"
assert_grep_fixed 'name=user-docs' \
    "$m29_stamp_state/stamp-29-user-docs.ok"
assert_grep_fixed 'checks_passed=41' \
    "$m29_stamp_state/stamp-29-user-docs.ok"
assert_grep_fixed 'checks_total=41' \
    "$m29_stamp_state/stamp-29-user-docs.ok"
assert_eq 10 \
    "$(wc -l < "$m29_stamp_state/stamp-29-user-docs.ok")" \
    "M29 published health stamp has the exact ten-line schema"

test_finish

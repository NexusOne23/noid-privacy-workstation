#!/bin/bash
# 26-package-set-structural — M26 regression test
#
# Covers: explicit package inventory/runtime gates, optional-package and
# firstboot opt-in documentation, and the reviewed dormant/privileged package
# surfaces for BlueZ MPRIS, tmux and Btrfs Assistant.
# Would catch: package/verifier drift, missing or unsafe documentation, a
# default-enabled optional service, or a changed Btrfs privilege boundary.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/26-package-set.ks"

test_start "26-package-set-structural"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

assert_file_exists "$KS_FILE"
assert_cmd_success "bash -n $KS_FILE" bash -n "$KS_FILE"
assert_grep_fixed "M25's user-started GNOME-extension reconciliation" "$KS_FILE" \
    "jq package rationale names its functional runtime consumer"
assert_grep_fixed 'documented M29/M30 JSON inspection commands' "$KS_FILE" \
    "jq package rationale names its supported documentation consumers"
assert_not_grep 'M16 DoH-test\|M28, M29, M31' "$KS_FILE" \
    "retired jq consumer inventory cannot return"
assert_grep_fixed 'GNOME dconf locks still take precedence over' "$KS_FILE" "Tweaks omission is not represented as a dconf security boundary"
assert_not_grep_extended 'undoing hardening|bypass lockdowns|flip the dconf' "$KS_FILE" "package-set has no false Tweaks lock-bypass rationale"
assert_not_grep 'Phase 2.*COPR\|Phase-2.*COPR\|release RPM via COPR' "$KS_FILE" \
    "package-set does not promise an unplanned COPR release package"
assert_grep_fixed 'This is a documented deviation, not a claim of following the complete' \
    "$KS_FILE" "retained Fedora release runtime is disclosed as a Remix-recipe deviation"
assert_grep_fixed 'Fedora-provided replacement and the solver permits that swap' "$KS_FILE" \
    "generic-release is not misrepresented as unavailable to the solver"
assert_grep_fixed 'fedoraproject.org/wiki/Remix' "$KS_FILE" \
    "release-package deviation retains its primary Fedora recipe reference"
assert_grep_fixed 'generic-release-common-44-0.2' "$KS_FILE" \
    "release-package decision records the exact audited generic preset payload"
assert_not_grep_extended 'fedora-release CANNOT be swapped|packages hard-require (it|fedora-release)' \
    "$KS_FILE" "package-set has no disproven fedora-release dependency claim"
assert_not_grep_extended 'Official Fedora Remix path|follows the complete Fedora Remix recipe' \
    "$KS_FILE" "partial trademark asset replacement is not labeled the complete Remix recipe"
assert_not_grep_extended '^-fedora-release-notes$' "$KS_FILE" \
    "nonexistent Fedora 44 package is not a vacuous exclusion"
assert_grep_fixed 'generic-release-notes is added' "$KS_FILE" \
    "generic release notes are accurately described as additive"
assert_grep_fixed 'default-enabled background service/listener/autostart' \
    "$KS_FILE" "Tier-1 criterion is scoped to effective default execution"
assert_not_grep 'no package-owned background service/listener/autostart' \
    "$KS_FILE" "dormant packaged units are not falsely represented as absent"

# Optional-packages user doc shipped
assert_grep_fixed "/usr/share/doc/noid-privacy/26-optional-packages.md" "$KS_FILE"
assert_grep_fixed 'OPTDOC_EOF' "$KS_FILE"
OPTDOC_TMP="$TMPDIR/26-optional-packages.md"
extract_heredoc "$KS_FILE" "OPTDOC_EOF" "$OPTDOC_TMP" \
    || _fail "OPTDOC_EOF extraction"
if python3 - "$OPTDOC_TMP" <<'OPTIONAL_BASH_PY'
import pathlib
import subprocess
import sys

blocks = []
current = None
for line in pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    if line.strip() == "```bash":
        if current is not None:
            raise SystemExit("nested bash fence")
        current = []
    elif line.strip() == "```" and current is not None:
        blocks.append("\n".join(current) + "\n")
        current = None
    elif current is not None:
        current.append(line)
if current is not None or not blocks:
    raise SystemExit("missing or unterminated bash fence")
for index, block in enumerate(blocks, 1):
    result = subprocess.run(["bash", "-n"], input=block, text=True)
    if result.returncode:
        raise SystemExit(f"bash fence {index} does not parse")
OPTIONAL_BASH_PY
then
    _pass "every optional-package bash example is syntactically valid"
else
    _fail "an optional-package bash example is syntactically invalid"
fi
assert_grep_fixed '`samba-common` stays installed' "$OPTDOC_TMP" \
    "optional-package doc preserves the retained SMB packaging companion"
assert_grep_fixed 'Module 05 also excludes the' "$OPTDOC_TMP" \
    "optional-package doc attributes the server and CLI exclusions"
assert_not_grep '`samba`, `samba-client`, `samba-common`' "$OPTDOC_TMP" \
    "optional-package doc cannot list retained samba-common as excluded"
assert_grep_fixed 'sudo systemctl unmask cups.service cups.socket cups.path' \
    "$OPTDOC_TMP" "printing workflow reverses every deliberate CUPS mask"
assert_grep_fixed 'sudo systemctl enable --now cups.socket cups.path' \
    "$OPTDOC_TMP" "printing opt-in uses native socket/path activation"
assert_grep_fixed 'sudo systemctl disable --now cups.path cups.socket cups.service' \
    "$OPTDOC_TMP" "printing workflow documents a complete persistent disable"
assert_grep_fixed 'sudo systemctl mask cups.service cups.socket cups.path' \
    "$OPTDOC_TMP" "printing workflow restores every deliberate CUPS mask"
assert_grep_fixed 'may generate printer-discovery traffic' "$OPTDOC_TMP" \
    "printing opt-in names its privacy and network trade-off"
assert_grep_fixed "firewall and LAN" "$OPTDOC_TMP" \
    "printing opt-in does not imply weakening the LAN boundary"
assert_not_grep_extended '[(]~30-50 MB[)]|saves ~30-50 MB' "$KS_FILE" \
    "printing guidance has no stale package-size claim"
assert_grep_fixed '`showtime` (GNOME Video Player) is already installed.' \
    "$OPTDOC_TMP" "VLC guidance names the installed Fedora 44 video player"
assert_grep_fixed 'Papers, Showtime, Decibels, Snapshot, Loupe' \
    "$OPTDOC_TMP" "base application inventory matches the installed GNOME set"
assert_not_grep 'Evince, Totem, Rhythmbox, Cheese\|`totem`.*already installed' \
    "$OPTDOC_TMP" "retired Fedora Workstation app inventory cannot return"
assert_grep_fixed 'sudo dnf install pipewire-config-raop' "$OPTDOC_TMP" \
    "AirPlay discovery package is a visible explicit opt-in"
assert_grep_fixed 'sudo dnf remove pipewire-config-raop' "$OPTDOC_TMP" \
    "AirPlay discovery package has an explicit undo"
assert_grep_fixed 'does **not** by itself' "$OPTDOC_TMP" \
    "AirPlay package opt-in is not misrepresented as a LAN-boundary bypass"
assert_grep_fixed 'Fedora main/updates on Fedora 44' "$OPTDOC_TMP" \
    "VLC repository guidance matches the current Fedora package"
assert_not_grep 'VLC.*RPM Fusion FREE\|RPM Fusion FREE (codec-patent reasons)' \
    "$OPTDOC_TMP" "VLC is not falsely attributed to RPM Fusion"
assert_grep_fixed 'sudo dnf install audacity' "$OPTDOC_TMP" \
    "Audacity guidance uses the Fedora 44 package name"
assert_not_grep_extended 'sudo dnf install audacity-free|telemetry-free fork|### `audacity-free`' \
    "$KS_FILE" "nonexistent audacity-free install and fork claim cannot return"
assert_grep_fixed 'Fedora also offers the' "$KS_FILE" \
    "RAR guidance distinguishes Fedora unrar-free from RPM Fusion unrar"
assert_grep_fixed 'separately named `unrar-free`' "$KS_FILE" \
    "Fedora's actual free unrar package name is documented"
assert_grep_fixed 'Network/account-integrating GNOME apps' "$OPTDOC_TMP" \
    "GNOME exclusions are described by their optional integration surface"
assert_grep_fixed 'not because merely' "$OPTDOC_TMP" \
    "installing an excluded GNOME app is not equated with proven traffic"
assert_not_grep_extended 'GNOME "phoning" apps|contact external APIs by default' \
    "$KS_FILE" "broad phone-home-by-installation claim cannot return"
assert_not_grep 'privacy-clean' "$KS_FILE" \
    "unscoped privacy-clean package labels cannot return"
assert_not_grep_extended "yelp.*local-only|It's local-only|no network[)], small" \
    "$KS_FILE" "Yelp local-help rationale is not an absolute capability claim"

# Firstboot setup service + script + completion flag
assert_grep_fixed "/var/lib/noid-privacy/firstboot-setup-done.flag" "$KS_FILE"
assert_grep_extended '/usr/local/bin/noid-firstboot-setup\.sh|noid-firstboot-setup\.service' "$KS_FILE"
assert_grep_fixed 'Nothing is fetched at first' "$KS_FILE" \
    "optional-codec doc states the Silent-Machine opt-in boundary"
assert_grep_fixed 'noid-complete-setup.sh' "$KS_FILE" \
    "optional-codec doc names the explicit opt-in workflow"
assert_grep_fixed "streams only the current invocation's DNF/task output" "$KS_FILE" \
    "optional-codec doc describes the visible current-run progress boundary"
assert_grep_fixed '/var/log/noid-firstboot-setup.log' "$KS_FILE" \
    "optional-codec doc retains the complete troubleshooting log path"
assert_grep_fixed 'gstreamer1-plugins-bad-freeworld' "$KS_FILE" \
    "optional-codec contract includes GStreamer H.265 software fallback"
assert_grep_fixed 'sudo dnf install openh264 mozilla-openh264 gstreamer1-plugin-openh264' \
    "$OPTDOC_TMP" "manual OpenH264 fallback installs all three contracted packages"
assert_grep_fixed 'none of the three OpenH264 opt-in RPMs is' "$KS_FILE" \
    "pre-consent claim is scoped to the exact package family"
assert_not_grep_extended 'zero openh264-related code|ZERO impact' "$KS_FILE" \
    "package absence and successful cleanup are not overstated"
assert_grep_fixed 'adds no service, autostart or network' "$KS_FILE" \
    "GStreamer codec documentation states its Silent-Machine surface"
assert_not_grep 'retries automatically on every boot' "$KS_FILE" \
    "optional-codec doc has no false automatic retry promise"
assert_not_grep_extended 'retries? automatically (at|on) every boot|retries? at every boot|will retry at every boot' "$KS_FILE" \
    "all known automatic boot-retry phrasings are rejected"
assert_not_grep 'both tasks completed' "$KS_FILE" \
    "optional-codec doc has no stale task count"
assert_grep_fixed 'disabled service does not schedule itself for a later boot' "$KS_FILE" \
    "optional-codec doc states the manual retry boundary"
assert_not_grep 'Auto-installed at first boot' "$KS_FILE" \
    "disabled codec service is not documented as automatic"
assert_not_grep 'Netflix/YouTube 4K HDR' "$KS_FILE" \
    "codec opt-in does not promise unsupported DRM/4K outcomes"
assert_not_grep 'ZERO.*patent-encumbered' "$KS_FILE" \
    "codec doc avoids a jurisdiction-independent patent claim"
assert_grep_fixed 'They are not globally read-only' "$KS_FILE" \
    "hardware audit tools document their mutating command surface"
assert_not_grep 'All four are read-only audit tools' "$KS_FILE" \
    "hdparm/TPM tools are not misrepresented as capability-limited"
assert_grep_fixed 'SMART logs belong to smartctl' "$KS_FILE" \
    "hdparm is not misrepresented as a SMART-log reader"
assert_not_grep 'manual SMART read' "$KS_FILE" \
    "retired hdparm SMART claim cannot return"
assert_grep_fixed 'fwupd, not `tpm2-tools`, computes' "$OPTDOC_TMP" \
    "TPM tools and fwupd HSI responsibilities are separated"
assert_grep_fixed 'https://fwupd.github.io/libfwupdplugin/hsi.html' "$OPTDOC_TMP" \
    "HSI explanation links fwupd's primary documentation"
assert_not_grep_extended 'HSI-2[+] verification|Reads `/dev/tpm0`' "$KS_FILE" \
    "TPM access and HSI are not reduced to unsupported fixed-device claims"
assert_grep_fixed 'explicitly open them read-only' "$OPTDOC_TMP" \
    "sqlite mutability is stated"
assert_not_grep_extended 'AIDE-cache analysis|Standalone read-(only CLI)?$|^[[:space:]]*only CLI for' "$KS_FILE" \
    "sqlite has no invented AIDE role or global read-only claim"
assert_not_grep_extended 'exceeds CUSP|aligns with OSPP|hardening surface is comparable' "$KS_FILE" \
    "unmeasured comparative compliance claims are absent"
assert_grep_fixed 'No profile-specific OpenSCAP result is bundled' "$KS_FILE" \
    "compliance section starts from the actual evidence boundary"
assert_grep_fixed 'sudo rpm -q scap-security-guide openscap-scanner' "$KS_FILE" \
    "OpenSCAP evidence records exact package versions"
assert_grep_fixed 'sudo oscap --version' "$KS_FILE" \
    "OpenSCAP evidence records scanner version"
assert_grep_fixed 'sudo oscap info "$DATASTREAM"' "$KS_FILE" \
    "profile IDs are inventoried from the installed datastream"
assert_grep_fixed "PROFILE_ID='xccdf_org.ssgproject.content_profile_REPLACE_ME'" "$KS_FILE" \
    "operator must select an exact inventoried profile ID"
assert_grep_fixed '--results "$EVIDENCE_STAGE/results.xml"' "$KS_FILE" \
    "machine-readable profile results are retained"
assert_grep_fixed '--report "$EVIDENCE_STAGE/report.html"' "$KS_FILE" \
    "human-readable profile results are retained"
assert_grep_fixed 'EVIDENCE_STAGE="$(sudo mktemp -d /var/tmp/openscap-noid.XXXXXX)"' \
    "$KS_FILE" "privileged OpenSCAP output starts in a collision-safe root staging tree"
assert_grep_fixed 'EVIDENCE_DEST="$(mktemp -d "$HOME/openscap-noid-' \
    "$KS_FILE" "final OpenSCAP evidence directory is privately created by the user"
assert_grep_fixed 'sudo chmod 0700 "$EVIDENCE_STAGE"' "$KS_FILE" \
    "OpenSCAP root staging permissions are explicit"
assert_grep_fixed 'sudo chown -R -- "$(id -u):$(id -g)" "$EVIDENCE_STAGE"' \
    "$KS_FILE" "OpenSCAP evidence ownership returns to the exact invoking identity"
assert_grep_fixed 'find "$EVIDENCE_STAGE" -mindepth 1 -maxdepth 1' "$KS_FILE" \
    "OpenSCAP evidence is moved into the user-owned final directory"
assert_not_grep 'EVIDENCE="$HOME/' "$KS_FILE" \
    "privileged OpenSCAP tools never write directly into a predictable home path"
assert_grep_fixed 'it does not certify NoID Privacy, guarantee a security level' "$KS_FILE" \
    "profile result interpretation rejects certification hype"
assert_grep_fixed "M25's user-started Update workflow checks its fixed EGO identity" \
    "$KS_FILE" "Just-Perfection documentation matches M25's explicit EGO updater"
assert_grep_fixed 'atomically advance it to a newer compatible EGO stable release' \
    "$KS_FILE" "Just-Perfection mutable update boundary is visible"
assert_grep_fixed 'EGO does not' "$KS_FILE" \
    "Just-Perfection guidance names the missing artifact-signature boundary"
assert_not_grep 'not discover or install a mutable EGO release' "$KS_FILE" \
    "retired immutable Just-Perfection update claim cannot return"
assert_grep_fixed 'Fedora Workstation default groups,' "$KS_FILE" \
    "optional-package provenance covers groups, weak dependencies and integrations"
assert_not_grep 'The following 12 packages are installed by `@workstation-product-environment`' \
    "$KS_FILE" "optional-package doc makes no false single-group provenance claim"
assert_not_grep 'Each package is installed by @workstation-product-environment by default' \
    "$KS_FILE" "package exclusion comment makes no false single-group provenance claim"
assert_not_grep 'sudo dnf install gnome-bluetooth NetworkManager-bluetooth' "$KS_FILE" \
    "Bluetooth opt-in does not reinstall already-present control panels"
assert_grep_fixed \
    'MPRIS_PRESET=/etc/systemd/user-preset/40-noid-bluetooth-media.preset' \
    "$KS_FILE" "BlueZ media proxy has an administrator-priority preset owner"
assert_grep_fixed 'disable mpris-proxy.service' "$KS_FILE" \
    "BlueZ media proxy is default-disabled by preset"
MPRIS_PRESET_TMP="$TMPDIR/40-noid-bluetooth-media.preset"
extract_heredoc "$KS_FILE" MPRIS_PRESET_EOF "$MPRIS_PRESET_TMP" \
    || _fail "BlueZ media-proxy preset extraction"
assert_eq \
    aa2550c4376d482c1372bca0c3a3a4653d4b541e6e6cd25081875721fc09664c \
    "$(sha256sum "$MPRIS_PRESET_TMP" | awk '{ print $1 }')" \
    "BlueZ media-proxy preset has exact reviewed bytes"
assert_grep_fixed \
    aa2550c4376d482c1372bca0c3a3a4653d4b541e6e6cd25081875721fc09664c \
    "$KS_FILE" "compose verifies the exact BlueZ media-proxy preset"
assert_grep_fixed 'systemctl --global disable mpris-proxy.service' "$KS_FILE" \
    "compose removes any pre-existing global MPRIS enablement"
assert_grep_fixed 'systemctl --global is-enabled mpris-proxy.service' "$KS_FILE" \
    "compose verifies effective global MPRIS dormancy"
assert_not_grep 'mask mpris-proxy.service' "$KS_FILE" \
    "MPRIS default-off policy preserves explicit user opt-in"
assert_grep_fixed 'systemctl --user enable --now mpris-proxy.service' \
    "$OPTDOC_TMP" "Bluetooth media controls have a separate explicit opt-in"
assert_grep_fixed 'systemctl --user disable --now mpris-proxy.service' \
    "$OPTDOC_TMP" "Bluetooth media-control opt-in has an exact undo"
assert_grep_fixed 'sudo noid-toggle-bluetooth off' "$OPTDOC_TMP" \
    "Bluetooth media-control undo restores the complete platform default"
assert_grep_fixed 'tmux@.service' "$KS_FILE" \
    "Fedora tmux's dormant system-service template is disclosed"
assert_grep_fixed 'systemctl is-enabled tmux@.service' "$KS_FILE" \
    "compose verifies the tmux service template remains disabled"
assert_grep_fixed 'complete Qt interface as' "$OPTDOC_TMP" \
    "Btrfs Assistant documentation discloses its root GUI"
assert_grep_fixed 'PolicyKit after administrator authentication' \
    "$OPTDOC_TMP" "Btrfs Assistant documentation names its privilege boundary"
assert_grep_fixed 'do **not** use Btrfs Assistant' "$OPTDOC_TMP" \
    "Btrfs Assistant restore is not substituted for platform recovery"
assert_grep_fixed 'SNAPSHOT_NUMBER=REPLACE_WITH_REVIEWED_NUMBER' \
    "$OPTDOC_TMP" "Btrfs Assistant rollback example cannot run before review"
assert_grep_fixed 'sudo noid-snap-rollback "$SNAPSHOT_NUMBER"' \
    "$OPTDOC_TMP" "Btrfs Assistant guidance routes root rollback through M20"
assert_grep_fixed '/home` or `/var/lib/libvirt`' "$OPTDOC_TMP" \
    "Btrfs Assistant guidance preserves the snapshot coverage boundary"
assert_grep_fixed \
    'BTRFS_ASSISTANT_POLICY=/usr/share/polkit-1/actions/org.btrfs-assistant.pkexec.policy' \
    "$KS_FILE" "compose binds the Btrfs Assistant PolicyKit source"
assert_grep_fixed '/systemd/(system|user)/|/xdg/autostart/' "$KS_FILE" \
    "compose rejects a newly packaged Btrfs Assistant background surface"
assert_grep_fixed '^/etc/(anacrontab|cron)' "$KS_FILE" \
    "compose rejects a newly packaged Btrfs Assistant scheduled activation surface"
assert_grep_fixed '^/usr/share/polkit-1/(actions/.*\.policy|rules\.d/)' \
    "$KS_FILE" "compose inventories the complete packaged PolicyKit surface"
assert_grep_fixed "'[%{FILEMODES:perms} %{FILECAPS} %{FILENAMES}\\n]'" \
    "$KS_FILE" "compose audits packaged SUID, SGID and file-capability metadata"
assert_grep_fixed 'for path in "${BTRFS_ASSISTANT_OWNED_PATHS[@]}"; do' \
    "$KS_FILE" "every reviewed Btrfs Assistant boundary path is checked separately"
assert_grep_fixed 'rpm -V btrfs-assistant' "$KS_FILE" \
    "compose rejects a modified Btrfs Assistant RPM payload"
assert_grep_fixed 'org.freedesktop.policykit.exec.path' "$KS_FILE" \
    "compose parses the PolicyKit executable annotation"
assert_grep_fixed '"allow_active": "auth_admin"' "$KS_FILE" \
    "compose requires administrator authentication for the root GUI"
assert_grep_fixed 'org.freedesktop.policykit.exec.allow_gui' "$KS_FILE" \
    "compose makes the root GUI allowance explicit"
BTRFS_POLKIT_VALIDATOR="$TMPDIR/btrfs-polkit-validator.py"
extract_heredoc "$KS_FILE" BTRFS_POLKIT_EOF "$BTRFS_POLKIT_VALIDATOR" \
    || _fail "Btrfs Assistant PolicyKit validator extraction"
assert_cmd_success "Btrfs Assistant PolicyKit validator parses" \
    python3 -m py_compile "$BTRFS_POLKIT_VALIDATOR"
cat > "$TMPDIR/btrfs-good.policy" <<'BTRFS_GOOD_POLICY_EOF'
<policyconfig>
  <action id="org.example.btrfs">
    <defaults>
      <allow_any>no</allow_any>
      <allow_inactive>no</allow_inactive>
      <allow_active>auth_admin</allow_active>
    </defaults>
    <annotate key="org.freedesktop.policykit.exec.path">/usr/bin/btrfs-assistant</annotate>
    <annotate key="org.freedesktop.policykit.exec.allow_gui">true</annotate>
  </action>
</policyconfig>
BTRFS_GOOD_POLICY_EOF
assert_cmd_success "reviewed Btrfs Assistant root-UI policy is accepted" \
    python3 "$BTRFS_POLKIT_VALIDATOR" "$TMPDIR/btrfs-good.policy"
sed 's|<allow_active>auth_admin</allow_active>|<allow_active>yes</allow_active>|' \
    "$TMPDIR/btrfs-good.policy" > "$TMPDIR/btrfs-unsafe.policy"
assert_cmd_failure "authentication-free Btrfs Assistant policy is rejected" \
    python3 "$BTRFS_POLKIT_VALIDATOR" "$TMPDIR/btrfs-unsafe.policy"
assert_not_grep_extended 'eos-event-recorder-daemon|eos-metrics|eos-metrics-instrumentation' \
    "$KS_FILE" "nonexistent EOS package names cannot inflate verification evidence"
assert_grep_fixed 'nvidia-persistenced' "$KS_FILE" \
    "NVIDIA build-time absence check matches the installer rollback scope"
assert_not_grep 'python3-dnf-plugin-snapper absent (--exclude-weakdeps effective)' "$KS_FILE" \
    "explicit package exclusion is not used as a weak-dependency canary"
assert_grep_fixed "grep -qiE '^[[:space:]]*install_weak_deps" "$KS_FILE" \
    "runtime verifier accepts DNF boolean spelling case-insensitively"
dnf_fixture="$TMPDIR/dnf.conf"
printf '%s\n' '[main]' 'install_weak_deps=False' > "$dnf_fixture"
if grep -qiE '^[[:space:]]*install_weak_deps[[:space:]]*=[[:space:]]*(0|false)[[:space:]]*$' \
        "$dnf_fixture"; then
    _pass "runtime weak-dependency policy accepts M01's exact False spelling"
else
    _fail "runtime weak-dependency policy rejects M01's exact False spelling"
fi
must_present_block=$(sed -n '/^MUST_PRESENT=(/,/^)/p' "$KS_FILE")
for pkg in kernel-modules kernel-modules-core kernel-modules-extra dracut-live dracut-config-generic; do
    if grep -Eq "(^|[[:space:]])${pkg}([[:space:]]|$)" <<<"$must_present_block"; then
        _pass "M01 load-bearing package verified: $pkg"
    else
        _fail "M01 load-bearing package missing from MUST_PRESENT: $pkg"
    fi
done
for pkg in firewalld libnftnl nftables bpftool iproute iproute-tc util-linux-core; do
    if grep -Eq "(^|[[:space:]])${pkg}([[:space:]]|$)" <<<"$must_present_block"; then
        _pass "M03 load-bearing package verified: $pkg"
    else
        _fail "M03 load-bearing package missing from MUST_PRESENT: $pkg"
    fi
done
if grep -Eq '(^|[[:space:]])cryptsetup([[:space:]]|$)' <<<"$must_present_block"; then
    _pass "M22 LUKS recovery CLI participates in the runtime package gate"
else
    _fail "M22 LUKS recovery CLI missing from MUST_PRESENT"
fi
for pkg in papers showtime decibels snapshot loupe; do
    if grep -Eq "(^|[[:space:]])${pkg}([[:space:]]|$)" <<<"$must_present_block"; then
        _pass "documented GNOME application is compose-gated: $pkg"
    else
        _fail "documented GNOME application missing from MUST_PRESENT: $pkg"
    fi
done
assert_not_grep 'required by gnome-control-center,.*nautilus\|localsearch + nautilus' "$KS_FILE" \
    "retention comments contain no disproven desktop dependency chains"
assert_not_grep_extended 'are library-only|all retained below are LIBRARY-ONLY|retentions [(]library-only' \
    "$KS_FILE" "mixed GNOME compatibility retentions are not mislabeled library-only"
assert_grep_fixed 'avahi, mdadm and iscsi-initiator-utils also' "$KS_FILE" \
    "service-bearing retention packages are named explicitly"
assert_grep_fixed 'Fedora-conditioned local assembly/monitoring and' "$KS_FILE" \
    "mdadm's retained local safety units are documented"
assert_grep_fixed 'shadows the' "$KS_FILE" \
    "iSCSI NetworkManager activation surface is documented"
package_headers=$(grep -RHn '^%packages' "$PROJECT_ROOT/kickstart" 2>/dev/null || true)
if [ -z "$package_headers" ]; then
    _fail "no kickstart %packages headers found"
elif grep -v -- '--exclude-weakdeps' <<<"$package_headers" >/dev/null; then
    _fail "a kickstart %packages block omits --exclude-weakdeps"
else
    _pass "every kickstart %packages block disables weak dependencies at source"
fi

# Doc perms + ownership
assert_grep_fixed 'chmod 644 /usr/share/doc/noid-privacy/26-optional-packages.md' "$KS_FILE"
assert_grep_fixed 'chown root:root /usr/share/doc/noid-privacy/26-optional-packages.md' "$KS_FILE"

# Doc mentions optional-install workflow
assert_grep_fixed 'sudo dnf install' "$KS_FILE"

# Reference to update-reminder timer (correct Module attribution — M25 owns it, not M13)
assert_grep_fixed 'noid-update-reminder.timer' "$KS_FILE"

# Update all reference
assert_grep_fixed '/usr/local/bin/noid-update-all.sh' "$KS_FILE"

# glibc-utils exclusion (Immutable cross-audit implementation)
# Package block exclusion (line-leading -glibc-utils)
assert_grep_extended '^-glibc-utils$'  "$KS_FILE" "glibc-utils excluded in %packages"
# Rationale comment present
assert_grep_fixed 'libc_malloc_debug.so.0'  "$KS_FILE" "rationale references libc_malloc_debug.so.0"
assert_grep_fixed 'glibc 2.43 already disables MALLOC_CHECK_ for SUID/SGID programs' \
    "$KS_FILE" "glibc's native privileged-execution safety boundary is accurate"
assert_not_grep '/etc/suid-debug' "$KS_FILE" \
    "removed glibc administrator exception cannot return from older manuals"
assert_grep_fixed 'sourceware.org/glibc/manual/2.43/html_node/Heap-Consistency-Checking.html' \
    "$KS_FILE" "glibc-utils rationale links the primary glibc manual"
assert_grep_fixed 'not as the primary SUID safety boundary' "$KS_FILE" \
    "glibc-utils exclusion is scoped as defense in depth"
# MUST_ABSENT verification list includes glibc-utils
assert_grep_extended 'glibc-utils\)|^\s+glibc-utils\s*$'  "$KS_FILE" "glibc-utils in MUST_ABSENT runtime check"

# Complete explicit runtime for all three GTK4/libadwaita Python apps; Update
# additionally embeds Vte. Do not inherit these from a changing group.
for gui_pkg in python3-gobject gtk4 libadwaita vte291-gtk4; do
    assert_grep_extended "^${gui_pkg}$" "$KS_FILE" \
        "$gui_pkg is explicit for the three-app suite"
    if grep -Eq "(^|[[:space:]])${gui_pkg}([[:space:]]|$)" <<<"$must_present_block"; then
        _pass "$gui_pkg participates in the runtime package gate"
    else
        _fail "$gui_pkg missing from MUST_PRESENT"
    fi
done
assert_grep_extended '^python3-audit$' "$KS_FILE" \
    "python3-audit is an explicit M12 auparse dependency"
assert_grep_extended '^qt5-qtwayland$' "$KS_FILE" \
    "Qt5 Wayland plugin is explicit for the shipped KeePassXC runtime"
assert_grep_extended '^git$' "$KS_FILE" \
    "Fedora Git is an explicit VSCodium/agent/recovery dependency"
assert_not_grep_extended '^git-all$|^[[:space:]]+git-all([[:space:]]|$)' "$KS_FILE" \
    "unneeded Git foreign-SCM/web/daemon integrations stay outside the base image"
if grep -Eq '(^|[[:space:]])python3-audit([[:space:]]|$)' <<<"$must_present_block"; then
    _pass "python3-audit participates in the runtime package gate"
else
    _fail "python3-audit missing from MUST_PRESENT"
fi
if grep -Eq '(^|[[:space:]])qt5-qtwayland([[:space:]]|$)' <<<"$must_present_block"; then
    _pass "qt5-qtwayland participates in the runtime package gate"
else
    _fail "qt5-qtwayland missing from MUST_PRESENT"
fi
if grep -Eq '(^|[[:space:]])git([[:space:]]|$)' <<<"$must_present_block"; then
    _pass "git participates in the runtime package gate"
else
    _fail "git missing from MUST_PRESENT"
fi
for pkg in NetworkManager-openvpn NetworkManager-openvpn-gnome; do
    assert_grep_extended "^${pkg}$" "$KS_FILE" \
        "$pkg is explicit for M29's provider-neutral OpenVPN path"
    if grep -Eq "(^|[[:space:]])${pkg}([[:space:]]|$)" \
            <<<"$must_present_block"; then
        _pass "$pkg participates in the runtime package gate"
    else
        _fail "$pkg missing from MUST_PRESENT"
    fi
done
assert_grep_fixed 'openvpn_activation_paths=$(rpm -ql NetworkManager-openvpn' \
    "$KS_FILE" "OpenVPN baseline rejects future package-owned activation paths"
assert_grep_fixed 'openvpn_special_privileges=$(rpm -q --qf' \
    "$KS_FILE" "OpenVPN baseline rejects future special privileges"
assert_grep_fixed 'rpm -V NetworkManager-openvpn NetworkManager-openvpn-gnome' \
    "$KS_FILE" "OpenVPN baseline verifies the Fedora RPM payload"
# M06 discovers unmanaged kernel WireGuard tunnels through `wg show`. Shipping
# that discovery without its tool left a provider daemon's tunnel unpinnable and
# an armed boundary dropping every handshake, so the package is part of the
# contract and its two units must be asserted dormant rather than assumed so.
assert_grep_extended '^wireguard-tools$' "$KS_FILE" \
    "wireguard-tools is explicit so M06 can enumerate kernel tunnels"
if grep -Eq '(^|[[:space:]])wireguard-tools([[:space:]]|$)' \
        <<<"$must_present_block"; then
    _pass "wireguard-tools participates in the runtime package gate"
else
    _fail "wireguard-tools missing from MUST_PRESENT"
fi
assert_grep_fixed 'wireguard_activation_paths=$(rpm -ql wireguard-tools' \
    "$KS_FILE" "WireGuard baseline rejects future package-owned activation paths"
assert_grep_fixed "grep -vxE '/usr/lib/systemd/system/wg-quick(\\.target|@\\.service)'" \
    "$KS_FILE" "only the two reviewed wg-quick units are exempt from that check"
assert_grep_fixed '[ "$wg_target_state" = static ]' \
    "$KS_FILE" "wg-quick.target dormancy is asserted, not assumed"
assert_grep_fixed '[ "$wg_template_state" = disabled ]' \
    "$KS_FILE" "wg-quick@.service template dormancy is asserted, not assumed"
assert_grep_fixed 'rpm -V wireguard-tools' \
    "$KS_FILE" "WireGuard baseline verifies the Fedora RPM payload"
assert_grep_extended '^libva-utils$' "$KS_FILE" \
    "Fedora vainfo diagnostics are explicit for the mandatory codec runtime gate"
if grep -Eq '(^|[[:space:]])libva-utils([[:space:]]|$)' \
        <<<"$must_present_block"; then
    _pass "libva-utils participates in the runtime package gate"
else
    _fail "libva-utils missing from MUST_PRESENT"
fi
assert_grep_fixed "/usr/lib64/qt5/plugins/platforms/libqwayland-generic.so" \
    "$KS_FILE" "M26 binds the effective Qt5 Wayland plugin to its RPM owner"

# Canonical `.UTF-8` selections are an Anaconda backend concern; glibc's locale
# archive reports normalized `.utf8` names. Never reintroduce the old swallowed
# localedef loop that produced 0/13 aliases while claiming success.
assert_not_grep 'localedef -c -i' "$KS_FILE" \
    "no ineffective canonical-locale alias generation"
assert_not_grep '2>/dev/null.*localedef\|localedef.*2>/dev/null' "$KS_FILE" \
    "locale-generation diagnostics are not swallowed"
assert_grep_fixed 'no ineffective alias generation' "$KS_FILE" \
    "locale normalization decision is explicit"

# Package/document parity: jq is an explicit runtime dependency, not an
# optional install suggestion. `unrar` is deliberately replaced by `unar`;
# keep the actual package absent without counting nonexistent p7zip payloads.
assert_not_grep '### `ripgrep` (rg), `fd-find` (fd), `bat`, `eza`, `jq`, `tldr`' \
    "$KS_FILE" "installed jq is absent from the optional-package heading"
assert_not_grep 'sudo dnf install ripgrep fd-find bat eza jq tldr' "$KS_FILE" \
    "installed jq is absent from the optional-package command"
assert_grep_extended '^-unrar$' "$KS_FILE" \
    "every package named unrar is explicitly excluded in favor of unar"
if grep -Eq '(^|[[:space:]])unrar([[:space:]]|$)' <<<"$must_present_block"; then
    _fail "unrar incorrectly participates in MUST_PRESENT"
else
    _pass "unrar stays outside MUST_PRESENT"
fi
must_absent_block=$(sed -n '/^MUST_ABSENT=(/,/^)/p' "$KS_FILE")
must_absent_packages=$(awk '!/^[[:space:]]*#/' <<<"$must_absent_block")
if grep -Eq '(^|[[:space:]])(fedora-release-notes|grub-btrfs)([[:space:]]|$)' \
        <<<"$must_absent_packages"; then
    _fail "MUST_ABSENT contains an unavailable Fedora 44 package name"
else
    _pass "MUST_ABSENT does not count unavailable package names as green evidence"
fi
for pkg in oddjob oddjob-mkhomedir; do
    assert_grep_extended "^-${pkg}$" "$KS_FILE" \
        "unused M10 service-backed home helper is excluded: $pkg"
    if grep -Eq "(^|[[:space:]])${pkg}([[:space:]]|$)" \
            <<<"$must_present_block"; then
        _fail "$pkg incorrectly participates in MUST_PRESENT"
    else
        _pass "$pkg stays outside MUST_PRESENT"
    fi
    if grep -Eq "(^|[[:space:]])${pkg}([[:space:]]|$)" \
            <<<"$must_absent_block"; then
        _pass "$pkg participates in the runtime absence gate"
    else
        _fail "$pkg missing from MUST_ABSENT"
    fi
done
if grep -Eq '(^|[[:space:]])unrar([[:space:]]|$)' <<<"$must_absent_block"; then
    _pass "unrar participates in the runtime absence gate"
else
    _fail "unrar missing from MUST_ABSENT"
fi
assert_grep_extended '^-pipewire-config-raop$' "$KS_FILE" \
    "PipeWire RAOP discovery config is excluded from the Silent-Machine image"
if grep -Eq '(^|[[:space:]])pipewire-config-raop([[:space:]]|$)' \
        <<<"$must_absent_block"; then
    _pass "pipewire-config-raop participates in the runtime absence gate"
else
    _fail "pipewire-config-raop missing from MUST_ABSENT"
fi
assert_not_grep 'should be deferred to firstboot' "$KS_FILE" \
    "retired archive packages are not attributed to codec firstboot"
assert_not_grep 'for tpkg in unrar p7zip-plugins' "$KS_FILE" \
    "nonexistent p7zip-plugins cannot create an automatic green check"
assert_grep_fixed '# CHECK 3: Persistent weak-dependency policy (/etc/dnf/dnf.conf)' \
    "$KS_FILE" "CHECK 3 banner names the policy it actually verifies"
assert_not_grep 'CHECK 3: All %packages blocks used --exclude-weakdeps' \
    "$KS_FILE" "runtime CHECK 3 does not claim source-header coverage"
assert_grep_fixed 'for pkg in thunderbird keepassxc git btop 7zip unar nmap tmux btrfs-assistant; do' \
    "$KS_FILE" "CHECK 5 loop is exactly the documented nine Tier-1 products"
assert_not_grep 'missed this focused Tier-1 loop' "$KS_FILE" \
    "CHECK 5 contains no stale historical omission note"
assert_grep_fixed 'not as a tenth Tier-1 product' "$KS_FILE" \
    "Qt5 Wayland is classified as a KeePassXC runtime dependency"
assert_grep_fixed 'PackageKit daemon itself remains excluded by Module 08' \
    "$KS_FILE" "PackageKit exclusion ownership points to the actual module"
assert_grep_fixed 'H.264 (mozilla-openh264 + openh264) is OPT-IN only. Fedora builds and signs' \
    "$KS_FILE" "OpenH264 trust chain names Fedora as builder and signer"
assert_grep_fixed 'the RPMs; Cisco distributes them because' \
    "$KS_FILE" "OpenH264 trust chain names Cisco as distributor"
assert_grep_fixed 'Module 08 requests the plugin' "$KS_FILE" \
    "GStreamer OpenH264 is an explicit post-opt-in package"
assert_grep_fixed 'browser, CDM and streaming service' "$KS_FILE" \
    "protected-media results stay scoped to their actual policy boundary"
assert_not_grep 'DRM streams stay CPU-decoded' "$KS_FILE" \
    "package docs make no universal protected-media decode claim"
assert_not_grep 'Cisco-CDN' "$KS_FILE" \
    "OpenH264 documentation does not collapse the trust chain into a CDN label"
assert_grep_fixed '`--setopt=*.pkg_gpgcheck=True` guard' "$OPTDOC_TMP" \
    "optional-package update guidance includes M25's command-priority signature guard"
assert_grep_fixed 'The Module 25 user timer starts' "$OPTDOC_TMP" \
    "update reminder is described as a schedule start"
assert_not_grep_extended 'fires (exactly )?every Monday|fires at exactly' \
    "$OPTDOC_TMP" "update reminder does not promise an exact notification time"
assert_grep_fixed 'up to one hour of randomized delay' "$OPTDOC_TMP" \
    "update reminder matches the timer's randomized firing window"
assert_not_grep 'Security updates arrive via `fedora-updates`' "$KS_FILE" \
    "stale Fedora repository ID cannot return"
assert_grep_fixed 'Optional RPMs need no separate updater' "$OPTDOC_TMP" \
    "no-separate-updater claim is scoped to RPM components"

# Every explicit %packages directive must participate in the corresponding
# compose-time verification array. This prevents a future include/exclude edit
# from silently bypassing the runtime gate.
while IFS= read -r directive; do
    package=${directive#-}
    if [[ "$directive" == -* ]]; then
        verification_block=$must_absent_block
        verification_name=MUST_ABSENT
    else
        verification_block=$must_present_block
        verification_name=MUST_PRESENT
    fi
    if grep -Eq "(^|[[:space:]])${package}([[:space:]]|$)" \
            <<<"$verification_block"; then
        _pass "explicit package directive is gated by $verification_name: $directive"
    else
        _fail "explicit package directive missing from $verification_name: $directive"
    fi
done < <(
    awk '
        /^%packages([[:space:]]|$)/ { in_packages = 1; next }
        in_packages && /^%end$/ { exit }
        in_packages {
            sub(/[[:space:]]+#.*/, "", $0)
            sub(/^[[:space:]]+/, "", $0)
            sub(/[[:space:]]+$/, "", $0)
            if ($0 != "" && $0 !~ /^#/) {
                print $1
            }
        }
    ' "$KS_FILE"
)

test_finish

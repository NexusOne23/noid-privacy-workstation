#!/usr/bin/env bash
# Copy-isolated mutation-boundary tests for every repository source generator.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

ROOT=$(find_project_root)
TMPDIR=$(mktemp -d "${TMPDIR:-/var/tmp}/noid-generators.XXXXXX")
trap 'rm -rf -- "$TMPDIR"' EXIT HUP INT TERM
LIB="$ROOT/scripts/lib/source-generator.sh"
test_start "00-source-generators"

assert_file_exists "$LIB" "shared source-generator contract exists"
assert_cmd_success "shared source-generator library parses" bash -n "$LIB"
assert_grep_fixed \
    'for command in chmod cut diff grep mktemp mv od readlink sed stat tail tr "$@"; do' \
    "$LIB" "shared generator preflight owns every command used by the library"

exercise_heredoc_generator() {
    local name=$1 script=$2 source=$3 target=$4 source_var=$5 target_var=$6
    local closing=$7 fixture_comment=$8 dir before after expected_mode
    dir="$TMPDIR/$name"
    mkdir -p "$dir"
    cp "$source" "$dir/source"
    cp "$target" "$dir/target.ks"
    chmod 0751 "$dir/target.ks"
    expected_mode=$(stat -c %a "$dir/target.ks")
    local -a command=(env "$source_var=$dir/source" \
        "$target_var=$dir/target.ks" "$script")

    assert_cmd_success "$name fixture starts in sync" "${command[@]}" --check
    before=$(sha256sum "$dir/target.ks" | awk '{print $1}')
    assert_cmd_failure "$name rejects unknown CLI arguments" \
        "${command[@]}" --write-typo
    after=$(sha256sum "$dir/target.ks" | awk '{print $1}')
    assert_eq "$before" "$after" "$name unknown CLI preserves target bytes"

    printf '%s\n' "$closing" >> "$dir/target.ks"
    before=$(sha256sum "$dir/target.ks" | awk '{print $1}')
    assert_cmd_failure "$name rejects duplicate target delimiters" "${command[@]}"
    after=$(sha256sum "$dir/target.ks" | awk '{print $1}')
    assert_eq "$before" "$after" "$name ambiguous target remains unchanged"

    cp "$target" "$dir/target.ks"
    chmod "$expected_mode" "$dir/target.ks"
    cp "$source" "$dir/source"
    printf '%s\n' "$closing" >> "$dir/source"
    before=$(sha256sum "$dir/target.ks" | awk '{print $1}')
    assert_cmd_failure "$name rejects source delimiter injection" "${command[@]}"
    after=$(sha256sum "$dir/target.ks" | awk '{print $1}')
    assert_eq "$before" "$after" "$name delimiter injection preserves target bytes"

    cp "$source" "$dir/source"
    printf '\n%s\n' "$fixture_comment" >> "$dir/source"
    assert_cmd_success "$name repairs isolated drift" "${command[@]}"
    assert_eq "$expected_mode" "$(stat -c %a "$dir/target.ks")" \
        "$name preserves target mode"
    assert_cmd_success "$name publishes syntactically valid kickstart" \
        bash -n "$dir/target.ks"
    assert_cmd_success "$name regenerated fixture passes check mode" \
        "${command[@]}" --check
}

exercise_heredoc_generator ai-workspace \
    "$ROOT/scripts/regen-ai-workspace-doc.sh" \
    "$ROOT/docs/ai-workspace.md" \
    "$ROOT/kickstart/snippets/08-service-minimization.ks" \
    NOID_AI_WORKSPACE_SRC NOID_AI_WORKSPACE_M08 AI_WORKSPACE_DOC_EOF \
    '<!-- generator fixture -->'
exercise_heredoc_generator agent-policy \
    "$ROOT/scripts/regen-agent-policy-embed.sh" \
    "$ROOT/AGENTS.md" \
    "$ROOT/kickstart/snippets/08-service-minimization.ks" \
    NOID_AGENT_POLICY_SOURCE NOID_AGENT_POLICY_M08 CLAUDEMD_EOF \
    '<!-- generator fixture -->'
exercise_heredoc_generator codium-launch \
    "$ROOT/scripts/regen-codium-launcher-embed.sh" \
    "$ROOT/scripts/noid-codium-launch.sh" \
    "$ROOT/kickstart/snippets/08-service-minimization.ks" \
    NOID_CODIUM_LAUNCH_SOURCE NOID_CODIUM_LAUNCHER_M08 \
    NOID_CODIUM_LAUNCH_EOF '# generator fixture'
exercise_heredoc_generator codium-launcher-sync \
    "$ROOT/scripts/regen-codium-launcher-embed.sh" \
    "$ROOT/scripts/noid-codium-launcher-sync.sh" \
    "$ROOT/kickstart/snippets/08-service-minimization.ks" \
    NOID_CODIUM_SYNC_SOURCE NOID_CODIUM_LAUNCHER_M08 \
    NOID_CODIUM_SYNC_EOF '# generator fixture'
exercise_heredoc_generator threat-model \
    "$ROOT/scripts/regen-product-boundary-docs.sh" \
    "$ROOT/docs/threat-model.md" \
    "$ROOT/kickstart/snippets/31-user-docs-tier-c.ks" \
    NOID_THREAT_MODEL_SRC NOID_PRODUCT_BOUNDARY_M31 \
    NOID_THREAT_MODEL_DOC_EOF '<!-- generator fixture -->'
exercise_heredoc_generator scope \
    "$ROOT/scripts/regen-product-boundary-docs.sh" \
    "$ROOT/docs/scope.md" \
    "$ROOT/kickstart/snippets/31-user-docs-tier-c.ks" \
    NOID_SCOPE_SRC NOID_PRODUCT_BOUNDARY_M31 \
    NOID_SCOPE_DOC_EOF '<!-- generator fixture -->'
exercise_heredoc_generator post-quantum-readiness \
    "$ROOT/scripts/regen-product-boundary-docs.sh" \
    "$ROOT/docs/post-quantum-readiness.md" \
    "$ROOT/kickstart/snippets/31-user-docs-tier-c.ks" \
    NOID_PQ_SRC NOID_PRODUCT_BOUNDARY_M31 \
    NOID_PQ_DOC_EOF '<!-- generator fixture -->'
exercise_heredoc_generator performance-profile \
    "$ROOT/scripts/regen-product-boundary-docs.sh" \
    "$ROOT/docs/performance-profile.md" \
    "$ROOT/kickstart/snippets/31-user-docs-tier-c.ks" \
    NOID_PERFORMANCE_PROFILE_SRC NOID_PRODUCT_BOUNDARY_M31 \
    NOID_PERFORMANCE_PROFILE_DOC_EOF '<!-- generator fixture -->'
exercise_heredoc_generator licensing \
    "$ROOT/scripts/regen-product-boundary-docs.sh" \
    "$ROOT/LICENSING.md" \
    "$ROOT/kickstart/snippets/31-user-docs-tier-c.ks" \
    NOID_LICENSING_SRC NOID_PRODUCT_BOUNDARY_M31 \
    NOID_LICENSING_DOC_EOF '<!-- generator fixture -->'
exercise_heredoc_generator local-ai \
    "$ROOT/scripts/regen-local-ai-doc.sh" \
    "$ROOT/docs/28-local-ai.md" \
    "$ROOT/kickstart/snippets/28-local-ai-docs.ks" \
    NOID_LOCAL_AI_SRC NOID_LOCAL_AI_M28 AI_DOC_EOF \
    '<!-- generator fixture -->'
exercise_heredoc_generator wan-strict \
    "$ROOT/scripts/regen-wan-strict-doc.sh" \
    "$ROOT/docs/wan-egress-strict.md" \
    "$ROOT/kickstart/snippets/06-vpn-killswitch.ks" \
    NOID_WAN_STRICT_DOC_SRC NOID_WAN_STRICT_M06 DOC_EOF \
    '<!-- generator fixture -->'
exercise_heredoc_generator intel-me-doc \
    "$ROOT/scripts/regen-intel-me-doc.sh" \
    "$ROOT/docs/15-intel-me-hardware-layer.md" \
    "$ROOT/kickstart/snippets/15-intel-me-mitigation.ks" \
    NOID_INTEL_ME_DOC_SRC NOID_INTEL_ME_M15 DOC_EOF \
    '<!-- generator fixture -->'
exercise_heredoc_generator firefox-embed \
    "$ROOT/scripts/regen-firefox-embed.sh" \
    "$ROOT/firefox/noid-firefox-hardening.js" \
    "$ROOT/kickstart/snippets/16-firefox.ks" \
    NOID_FIREFOX_EMBED_SRC NOID_FIREFOX_EMBED_M16 HARDENING_GZ_B64_EOF \
    '// generator fixture'
exercise_heredoc_generator thunderbird-embed \
    "$ROOT/scripts/regen-thunderbird-embed.sh" \
    "$ROOT/thunderbird/noid-thunderbird-hardening.js" \
    "$ROOT/kickstart/snippets/35-thunderbird.ks" \
    NOID_THUNDERBIRD_EMBED_SRC NOID_THUNDERBIRD_EMBED_M35 \
    TB_HARDENING_GZ_B64_EOF '// generator fixture'
exercise_heredoc_generator thunderbird-cfg \
    "$ROOT/scripts/regen-thunderbird-mozilla-cfg.sh" \
    "$ROOT/thunderbird/mozilla.cfg" \
    "$ROOT/kickstart/snippets/35-thunderbird.ks" \
    NOID_THUNDERBIRD_CFG_SRC NOID_THUNDERBIRD_CFG_M35 MOZILLA_CFG_EOF \
    '// generator fixture'
exercise_heredoc_generator thunderbird-smartcard-doc \
    "$ROOT/scripts/regen-thunderbird-smartcard-doc.sh" \
    "$ROOT/docs/35-thunderbird-smartcard.md" \
    "$ROOT/kickstart/snippets/35-thunderbird.ks" \
    NOID_TB_SMARTCARD_SRC NOID_TB_SMARTCARD_M35 \
    NOID_TB_SMARTCARD_DOC_EOF '<!-- generator fixture -->'
exercise_heredoc_generator gnome-privacy-cleanup \
    "$ROOT/scripts/regen-gnome-privacy-cleanup-embed.sh" \
    "$ROOT/scripts/noid-gnome-privacy-cleanup.py" \
    "$ROOT/kickstart/snippets/17-gnome-hardening.ks" \
    NOID_GNOME_CLEANUP_SOURCE NOID_GNOME_CLEANUP_M17 \
    NOID_GNOME_CLEANUP_EOF '# generator fixture'
exercise_heredoc_generator liveinst-required-space \
    "$ROOT/scripts/regen-liveinst-required-space-embed.sh" \
    "$ROOT/overrides/anaconda/live-os-initialization.py" \
    "$ROOT/kickstart/snippets/17-gnome-hardening.ks" \
    NOID_LIVEINST_REQUIRED_SPACE_SOURCE NOID_LIVEINST_REQUIRED_SPACE_M17 \
    NOID_LIVEINST_REQUIRED_SPACE_EOF '# generator fixture'
exercise_heredoc_generator gnome-software-launcher \
    "$ROOT/scripts/regen-gnome-software-launcher-embed.sh" \
    "$ROOT/scripts/noid-gnome-software-launcher-sync.sh" \
    "$ROOT/kickstart/snippets/17-gnome-hardening.ks" \
    NOID_GS_LAUNCHER_SOURCE NOID_GS_LAUNCHER_M17 \
    NOID_GS_LAUNCHER_SYNC_EOF '# generator fixture'
exercise_heredoc_generator gnome-software-quit \
    "$ROOT/scripts/regen-gnome-software-quit-embed.sh" \
    "$ROOT/scripts/noid-gnome-software-quit.sh" \
    "$ROOT/kickstart/snippets/17-gnome-hardening.ks" \
    NOID_GS_QUIT_SOURCE NOID_GS_QUIT_M17 \
    NOID_GS_QUIT_EOF '# generator fixture'
exercise_heredoc_generator gnome-software-rpm \
    "$ROOT/scripts/regen-gnome-software-rpm-embed.sh" \
    "$ROOT/scripts/noid-gnome-software-rpm.sh" \
    "$ROOT/kickstart/snippets/17-gnome-hardening.ks" \
    NOID_GS_RPM_SOURCE NOID_GS_RPM_M17 \
    NOID_GS_RPM_EOF '# generator fixture'
exercise_heredoc_generator gnome-software-backend-stop \
    "$ROOT/scripts/regen-gnome-software-backend-stop-embed.sh" \
    "$ROOT/scripts/noid-gnome-software-backend-stop.sh" \
    "$ROOT/kickstart/snippets/17-gnome-hardening.ks" \
    NOID_GS_BACKEND_STOP_SOURCE NOID_GS_BACKEND_STOP_M17 \
    NOID_GS_BACKEND_STOP_EOF '# generator fixture'
exercise_heredoc_generator flatpak-remote-policy \
    "$ROOT/scripts/regen-flatpak-remote-policy-embed.sh" \
    "$ROOT/scripts/noid-flatpak-remote-policy.sh" \
    "$ROOT/kickstart/snippets/18-flatpak-sandboxing.ks" \
    NOID_FLATPAK_POLICY_SOURCE NOID_FLATPAK_POLICY_M18 \
    NOID_FLATPAK_POLICY_EOF '# generator fixture'
exercise_heredoc_generator wireguard-mtu-reconcile \
    "$ROOT/scripts/regen-wireguard-mtu-reconcile-embed.sh" \
    "$ROOT/scripts/noid-wireguard-mtu-reconcile.sh" \
    "$ROOT/kickstart/snippets/06-vpn-killswitch.ks" \
    NOID_WG_MTU_SOURCE NOID_WG_MTU_M06 \
    NOID_WG_MTU_EOF '# generator fixture'
exercise_heredoc_generator flathub-descriptor \
    "$ROOT/scripts/regen-flathub-descriptor-embed.sh" \
    "$ROOT/manifests/flathub.flatpakrepo" \
    "$ROOT/kickstart/snippets/18-flatpak-sandboxing.ks" \
    NOID_FLATHUB_DESCRIPTOR_SOURCE NOID_FLATHUB_DESCRIPTOR_M18 \
    NOID_FLATHUB_DESCRIPTOR_EOF '# generator fixture'

# Microphone policy owns three plain-text heredocs and publishes all three in
# one M17 replacement, so exercise its multi-source transaction separately.
mic_dir="$TMPDIR/microphone-policy"
mkdir -p "$mic_dir"
cp "$ROOT/kickstart/snippets/17-gnome-hardening.ks" "$mic_dir/module.ks"
cp "$ROOT/scripts/noid-microphone-privacy.conf" "$mic_dir/policy.conf"
cp "$ROOT/scripts/noid-microphone-privacy.lua" "$mic_dir/policy.lua"
cp "$ROOT/scripts/noid-toggle-microphone.sh" "$mic_dir/toggle.sh"
chmod 0751 "$mic_dir/module.ks"
mic_mode=$(stat -c %a "$mic_dir/module.ks")
MIC_COMMAND=(env NOID_MIC_POLICY_M17="$mic_dir/module.ks" \
    NOID_MIC_POLICY_CONF="$mic_dir/policy.conf" \
    NOID_MIC_POLICY_LUA="$mic_dir/policy.lua" \
    NOID_MIC_POLICY_TOGGLE="$mic_dir/toggle.sh" \
    "$ROOT/scripts/regen-microphone-policy-embed.sh")
assert_cmd_success "microphone-policy fixture starts in sync" \
    "${MIC_COMMAND[@]}" --check
before=$(sha256sum "$mic_dir/module.ks" | awk '{print $1}')
assert_cmd_failure "microphone-policy rejects unknown CLI arguments" \
    "${MIC_COMMAND[@]}" --write-typo
assert_eq "$before" "$(sha256sum "$mic_dir/module.ks" | awk '{print $1}')" \
    "microphone-policy unknown CLI preserves target bytes"
printf '%s\n' NOID_MIC_WP_LUA_EOF >> "$mic_dir/module.ks"
before=$(sha256sum "$mic_dir/module.ks" | awk '{print $1}')
assert_cmd_failure "microphone-policy rejects duplicate target delimiters" \
    "${MIC_COMMAND[@]}"
assert_eq "$before" "$(sha256sum "$mic_dir/module.ks" | awk '{print $1}')" \
    "microphone-policy ambiguous target remains unchanged"
cp "$ROOT/kickstart/snippets/17-gnome-hardening.ks" "$mic_dir/module.ks"
chmod "$mic_mode" "$mic_dir/module.ks"
printf '%s\n' NOID_MIC_TOGGLE_EOF >> "$mic_dir/toggle.sh"
before=$(sha256sum "$mic_dir/module.ks" | awk '{print $1}')
assert_cmd_failure "microphone-policy rejects source delimiter injection" \
    "${MIC_COMMAND[@]}"
assert_eq "$before" "$(sha256sum "$mic_dir/module.ks" | awk '{print $1}')" \
    "microphone-policy delimiter injection preserves target bytes"
cp "$ROOT/scripts/noid-toggle-microphone.sh" "$mic_dir/toggle.sh"
printf '%s\n' '# generator fixture' >> "$mic_dir/policy.lua"
assert_cmd_success "microphone-policy atomically repairs isolated drift" \
    "${MIC_COMMAND[@]}"
assert_eq "$mic_mode" "$(stat -c %a "$mic_dir/module.ks")" \
    "microphone-policy preserves target mode"
assert_cmd_success "microphone-policy candidate remains valid Bash" \
    bash -n "$mic_dir/module.ks"
assert_cmd_success "microphone-policy repaired fixture passes check mode" \
    "${MIC_COMMAND[@]}" --check

# LAN-XDP has two generated blocks plus one named digest field.
lan_dir="$TMPDIR/lan-xdp"
mkdir -p "$lan_dir"
cp "$ROOT/kickstart/snippets/03-firewalld.ks" "$lan_dir/module.ks"
cp "$ROOT/overrides/noid-lan-xdp/noid-lan-xdp.sh" "$lan_dir/controller.sh"
cp "$ROOT/overrides/noid-lan-xdp/noid-lan-xdp.bpf.o.b64" "$lan_dir/object.b64"
chmod 0751 "$lan_dir/module.ks"
lan_mode=$(stat -c %a "$lan_dir/module.ks")
LAN_COMMAND=(env NOID_LAN_XDP_M03="$lan_dir/module.ks" \
    NOID_LAN_XDP_CONTROLLER="$lan_dir/controller.sh" \
    NOID_LAN_XDP_OBJECT_B64="$lan_dir/object.b64" \
    "$ROOT/scripts/regen-lan-xdp-embed.sh")
assert_cmd_success "LAN-XDP fixture starts in sync" "${LAN_COMMAND[@]}" --check
before=$(sha256sum "$lan_dir/module.ks" | awk '{print $1}')
assert_cmd_failure "LAN-XDP rejects unknown CLI arguments" \
    "${LAN_COMMAND[@]}" --typo
assert_eq "$before" "$(sha256sum "$lan_dir/module.ks" | awk '{print $1}')" \
    "LAN-XDP unknown CLI preserves target bytes"
printf '%s\n' NOID_LAN_XDP_CONTROLLER_EOF >> "$lan_dir/module.ks"
before=$(sha256sum "$lan_dir/module.ks" | awk '{print $1}')
assert_cmd_failure "LAN-XDP rejects duplicate markers" "${LAN_COMMAND[@]}"
assert_eq "$before" "$(sha256sum "$lan_dir/module.ks" | awk '{print $1}')" \
    "LAN-XDP duplicate marker preserves target bytes"
cp "$ROOT/kickstart/snippets/03-firewalld.ks" "$lan_dir/module.ks"
chmod "$lan_mode" "$lan_dir/module.ks"
printf '%s\n' '# generator fixture' >> "$lan_dir/controller.sh"
assert_cmd_success "LAN-XDP atomically repairs controller drift" \
    "${LAN_COMMAND[@]}"
assert_eq "$lan_mode" "$(stat -c %a "$lan_dir/module.ks")" \
    "LAN-XDP preserves target mode"
assert_cmd_success "LAN-XDP candidate remains valid Bash" \
    bash -n "$lan_dir/module.ks"
assert_cmd_success "LAN-XDP repaired fixture passes check mode" \
    "${LAN_COMMAND[@]}" --check
assert_eq 1 "$(grep -c '^NOID_LAN_XDP_OBJECT_SHA256=[0-9a-f]\{64\}$' \
    "$lan_dir/module.ks")" "LAN-XDP digest update is confined to one named field"

# Branding uses a generated manifest rather than a heredoc.
branding_dir="$TMPDIR/branding"
cp -a "$ROOT/branding" "$branding_dir"
chmod 0640 "$branding_dir/SHA256SUMS"
branding_mode=$(stat -c %a "$branding_dir/SHA256SUMS")
BRANDING_COMMAND=(env NOID_BRANDING_DIR="$branding_dir" \
    NOID_BRANDING_MANIFEST="$branding_dir/SHA256SUMS" \
    "$ROOT/scripts/regen-branding-shasums.sh")
assert_cmd_success "branding fixture starts in sync" "${BRANDING_COMMAND[@]}" --check
before=$(sha256sum "$branding_dir/SHA256SUMS" | awk '{print $1}')
assert_cmd_failure "branding generator rejects unknown CLI arguments" \
    "${BRANDING_COMMAND[@]}" --typo
assert_eq "$before" "$(sha256sum "$branding_dir/SHA256SUMS" | awk '{print $1}')" \
    "branding unknown CLI preserves manifest bytes"
printf '%s\n' asset > "$branding_dir/generator-fixture.txt"
assert_cmd_success "branding manifest atomically incorporates drift" \
    "${BRANDING_COMMAND[@]}"
assert_eq "$branding_mode" "$(stat -c %a "$branding_dir/SHA256SUMS")" \
    "branding generator preserves manifest mode"
assert_cmd_success "branding repaired fixture passes check mode" \
    "${BRANDING_COMMAND[@]}" --check
ln -s wallpaper.png "$branding_dir/forbidden-link.png"
before=$(sha256sum "$branding_dir/SHA256SUMS" | awk '{print $1}')
assert_cmd_failure "branding generator rejects payload symlinks" \
    "${BRANDING_COMMAND[@]}"
assert_eq "$before" "$(sha256sum "$branding_dir/SHA256SUMS" | awk '{print $1}')" \
    "branding symlink rejection preserves manifest bytes"

for script in "$ROOT"/scripts/regen-*.sh; do
    assert_grep_fixed 'scripts/lib/source-generator.sh' "$script" \
        "$(basename "$script") uses the shared mutation contract"
    assert_cmd_success "$(basename "$script") canonical check passes" \
        "$script" --check
done

test_finish

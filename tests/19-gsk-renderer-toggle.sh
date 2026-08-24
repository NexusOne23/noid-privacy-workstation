#!/bin/bash
# 19-gsk-renderer-toggle — exact NVIDIA-offload GTK renderer policy tests
set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/19-nvidia-mok-docs.ks"
M99_FILE="$PROJECT_ROOT/kickstart/snippets/99-finalize.ks"
RUNTIME_GATE="$PROJECT_ROOT/tests/pre-ship/19-gsk-session-runtime.sh"
TMPDIR="$(mktemp -d "$PROJECT_ROOT/.test-19-gsk.XXXXXX")"
trap 'rm -rf "$TMPDIR"' EXIT

test_start "19-gsk-renderer-toggle"

MATCHER="$TMPDIR/noid-gsk-hybrid-match"
TOGGLE="$TMPDIR/noid-toggle-gsk-gl"
WRAPPER="$TMPDIR/gnome-control-center"
SOFTWARE_WRAPPER="$TMPDIR/gnome-software"
SESSION_HELPER="$TMPDIR/noid-gsk-session-environment"
SESSION_UNIT="$TMPDIR/noid-gsk-session-environment.service"
DESKTOP_SYNC="$TMPDIR/noid-gsk-settings-launcher-sync"
DESKTOP_ACTION="$TMPDIR/noid-gsk-settings-launcher.actions"
MUTTER_RULE="$TMPDIR/62-noid-mutter-headless-offload.rules"
assert_file_exists "$KS_FILE"
assert_file_exists "$M99_FILE"
assert_file_exists "$RUNTIME_GATE"
assert_cmd_success "M19 parses" bash -n "$KS_FILE"
assert_cmd_success "M19 session runtime gate parses" bash -n "$RUNTIME_GATE"
assert_grep_extended '^dbus-tools$' "$KS_FILE" \
    "M19 explicitly composes the GTK session helper's Fedora runtime"
extract_heredoc "$KS_FILE" GSK_MATCH_EOF "$MATCHER" \
    || _fail "GTK topology matcher extraction"
extract_heredoc "$KS_FILE" GSK_TOGGLE_EOF "$TOGGLE" \
    || _fail "GTK renderer toggle extraction"
extract_heredoc "$KS_FILE" GSK_SETTINGS_WRAPPER_EOF "$WRAPPER" \
    || _fail "GNOME Settings renderer wrapper extraction"
extract_heredoc "$KS_FILE" GSK_SOFTWARE_WRAPPER_EOF "$SOFTWARE_WRAPPER" \
    || _fail "GNOME Software renderer wrapper extraction"
extract_heredoc "$KS_FILE" GSK_SESSION_HELPER_EOF "$SESSION_HELPER" \
    || _fail "post-Shell GTK session helper extraction"
extract_heredoc "$KS_FILE" GSK_SESSION_UNIT_EOF "$SESSION_UNIT" \
    || _fail "post-Shell GTK user unit extraction"
extract_heredoc "$KS_FILE" GSK_DESKTOP_SYNC_EOF "$DESKTOP_SYNC" \
    || _fail "GNOME Settings launcher sync extraction"
extract_heredoc "$KS_FILE" GSK_DESKTOP_ACTION_EOF "$DESKTOP_ACTION" \
    || _fail "GNOME Settings dnf5 action extraction"
extract_heredoc "$KS_FILE" GSK_MUTTER_RULE_EOF "$MUTTER_RULE" \
    || _fail "connectorless offload GPU Mutter rule extraction"
chmod 0755 "$MATCHER" "$TOGGLE" "$WRAPPER" "$SOFTWARE_WRAPPER" \
    "$SESSION_HELPER" "$DESKTOP_SYNC"
for script in "$MATCHER" "$TOGGLE" "$WRAPPER" "$SOFTWARE_WRAPPER" \
        "$SESSION_HELPER" "$DESKTOP_SYNC"; do
    assert_cmd_success "$(basename "$script") parses" bash -n "$script"
    assert_cmd_success "$(basename "$script") passes ShellCheck" \
        shellcheck -S warning "$script"
done
sed "s#/usr/libexec/noid-gsk-session-environment#$SESSION_HELPER#g" \
    "$SESSION_UNIT" >"$TMPDIR/noid-gsk-session-environment-fixture.service"
USER_UNIT_COMPOSE_VERIFY="$TMPDIR/user-unit-compose-verify.sh"
user_unit_verify_extract_rc=0
awk '
        /# M19_USER_UNIT_COMPOSE_VERIFY_BEGIN/ {
            if (seen++) exit 2
            copy=1
            next
        }
        /# M19_USER_UNIT_COMPOSE_VERIFY_END/ {
            if (!copy || closed++) exit 3
            copy=0
            next
        }
        copy { print }
        END { if (seen != 1 || closed != 1 || copy) exit 4 }
    ' "$KS_FILE" > "$USER_UNIT_COMPOSE_VERIFY" \
    || user_unit_verify_extract_rc=$?
assert_eq 0 "$user_unit_verify_extract_rc" \
    "M19 user-unit compose verifier extracts from unique markers"
assert_cmd_success "post-Shell GTK user unit validates" \
    bash -c '. "$1"; verify_gsk_user_unit "$2" "$3"' \
    _ "$USER_UNIT_COMPOSE_VERIFY" \
    "$TMPDIR/noid-gsk-session-environment-fixture.service" "$TMPDIR"
assert_cmd_success "user-unit verification removes its private runtime" \
    bash -c '! compgen -G "$1/noid-m19-systemd-verify.*" >/dev/null' \
    _ "$TMPDIR"
assert_cmd_failure "user-unit verifier rejects a missing runtime parent" \
    bash -c '. "$1"; verify_gsk_user_unit "$2" "$3"' \
    _ "$USER_UNIT_COMPOSE_VERIFY" \
    "$TMPDIR/noid-gsk-session-environment-fixture.service" \
    "$TMPDIR/missing-runtime-parent"
for compose_gate in "$KS_FILE" "$M99_FILE"; do
    assert_grep_fixed 'noid-m19-systemd-verify.XXXXXX' "$compose_gate" \
        "compose creates a private offline user-manager runtime"
    assert_grep_fixed 'XDG_RUNTIME_DIR="$runtime_dir"' "$compose_gate" \
        "compose supplies the private runtime to the offline user manager"
    assert_grep_fixed \
        'find "$runtime_dir" -xdev -mindepth 1 -delete' \
        "$compose_gate" \
        "compose cleans only the private verifier runtime mount boundary"
    assert_not_grep 'XDG_RUNTIME_DIR="/run/user/' "$compose_gate" \
        "compose never assumes that root owns a logind login runtime"
done
assert_grep_fixed 'gsk_verify_output=$(verify_gsk_user_unit' "$KS_FILE" \
    "compose captures exact user-unit verifier output"
assert_grep_fixed 'log "  [DIAG] $line"' "$KS_FILE" \
    "failed user-unit diagnostics reach the retained compose log"

assert_grep_fixed 'case "$action" in auto|on|off|status)' "$TOGGLE" \
    "toggle exposes the closed auto/on/off/status policy"
assert_grep_fixed 'GSK_RENDERER=gl' "$TOGGLE" \
    "manual policy selects GTK's supported GL renderer"
assert_not_grep 'GSK_RENDERER=ngl' "$KS_FILE" \
    "deprecated renderer alias is absent"
assert_grep_fixed '0x8086|0x1002)' "$MATCHER" \
    "primary sink may be an Intel iGPU or AMD APU"
assert_grep_fixed '[ "$vendor" = 0x10de ]' "$MATCHER" \
    "only a non-primary NVIDIA GPU can trigger the automatic workaround"
assert_grep_fixed '[ "$gpu_count" -eq 2 ]' "$MATCHER" \
    "automatic renderer policy accepts exactly two display GPUs"
assert_grep_fixed '[ "$nvidia_offload_count" -eq 1 ]' "$MATCHER" \
    "automatic renderer policy accepts exactly one NVIDIA offload GPU"
assert_grep_fixed '8|9|10|11|14|30|31|32)' "$MATCHER" \
    "automatic policy is limited to portable chassis types"
assert_grep_fixed 'This renderer workaround deliberately requires a portable DMI identity' \
    "$MATCHER" "renderer retains its topology-specific portable gate"
assert_grep_fixed "lid policy," "$MATCHER"
assert_grep_fixed "kernel input subsystem's real SW_LID capability" "$MATCHER" \
    "renderer and physical-lid detection boundaries stay separate"
assert_grep_fixed '[[ "$card_name" =~ ^card[0-9]+$ ]]' "$MATCHER" \
    "DRM connector names cannot be miscounted as GPUs"
assert_grep_fixed '[ "$1" = --mutter-headless-card ]' "$MATCHER" \
    "matcher exposes only the closed Mutter card qualification mode"
assert_grep_fixed 'printf '\''%s\n'\'' mutter-device-ignore' "$MATCHER" \
    "successful card qualification returns the exact Mutter tag"
assert_grep_fixed 'TAG=="switcheroo-discrete-gpu"' "$MUTTER_RULE" \
    "Mutter rule starts from the maintained discrete-GPU classification"
assert_grep_fixed 'RESULT=="mutter-device-ignore", TAG+="mutter-device-ignore"' \
    "$MUTTER_RULE" "Mutter rule binds the exact helper result to the exact tag"
assert_not_grep 'renderD' "$MUTTER_RULE" \
    "Mutter rule cannot tag or hide a render node"
assert_cmd_success "connectorless offload GPU Mutter rule validates" \
    udevadm verify "$MUTTER_RULE"
assert_grep_fixed 'if [ "${GSK_RENDERER+x}" = x ]; then' "$WRAPPER" \
    "administrator environment configuration wins over app automation"
assert_grep_fixed 'exec env GSK_RENDERER=gl "$VENDOR" "$@"' "$WRAPPER" \
    "automatic GL selection is scoped to the wrapped application"
assert_not_grep 'LC_ALL=' "$WRAPPER" \
    "Settings wrapper never overrides the user's interface locale"
assert_grep_fixed 'MODE=/etc/xdg/noid-privacy/gsk-renderer.mode' "$WRAPPER" \
    "wrapper observes the explicit application policy"
assert_grep_fixed 'VENDOR=/usr/bin/gnome-software' "$SOFTWARE_WRAPPER" \
    "GNOME Software wrapper selects only the vendor executable"
assert_grep_fixed \
    'NOID_SOFTWARE_PLUGINS=flatpak,icons,hardcoded-blocklist,malcontent,modalias,os-release,provenance,provenance-license,generic-updates' \
    "$SOFTWARE_WRAPPER" \
    "GNOME Software wrapper pins the reviewed explicit Flatpak-store scope"
assert_grep_fixed \
    'export GNOME_SOFTWARE_PLUGINS_ALLOWLIST="$NOID_SOFTWARE_PLUGINS"' \
    "$SOFTWARE_WRAPPER" \
    "GNOME Software wrapper exports its Flatpak-store scope"
assert_grep_fixed '[ "${GNOME_SOFTWARE_PLUGINS_BLOCKLIST+x}" != x ]' \
    "$SOFTWARE_WRAPPER" \
    "administrator plugin blocklist ownership wins over app automation"
assert_not_grep 'systemctl' "$SOFTWARE_WRAPPER" \
    "GNOME Software wrapper cannot manage its background service"
assert_not_grep '--gapplication-service' "$SOFTWARE_WRAPPER" \
    "GNOME Software wrapper cannot request application-service mode"
assert_not_grep '--autostart' "$SOFTWARE_WRAPPER" \
    "GNOME Software wrapper cannot request autostart mode"
assert_grep_fixed \
    'The normal GNOME Software launcher stays on the explicit Flatpak-only plugin scope' \
    "$KS_FILE" "renderer documentation no longer claims the wrapper changes only rendering"
assert_grep_fixed 'Fedora-RPM one-shot is a separate named launch path' \
    "$KS_FILE" "renderer documentation distinguishes the opt-in package backend"
assert_grep_fixed 'After=org.gnome.Shell@user.service' "$SESSION_UNIT" \
    "automatic renderer propagation waits for GNOME Shell"
assert_grep_fixed 'Before=gnome-session.target' "$SESSION_UNIT" \
    "automatic renderer propagation completes inside session startup"
assert_grep_fixed 'RestrictAddressFamilies=AF_UNIX' "$SESSION_UNIT" \
    "post-Shell one-shot enforces an AF_UNIX-only socket allowlist"
assert_not_grep '^PrivateNetwork=' "$SESSION_UNIT" \
    "post-Shell one-shot makes no unenforceable network-namespace claim"
assert_not_grep '^IPAddressDeny=' "$SESSION_UNIT" \
    "post-Shell one-shot makes no unenforceable user-manager IP-firewall claim"
assert_grep_fixed 'CapabilityBoundingSet=' "$SESSION_UNIT" \
    "post-Shell one-shot has an empty capability bounding set"
assert_grep_fixed 'PrivateDevices=yes' "$SESSION_UNIT" \
    "post-Shell one-shot has no host-device namespace"
assert_grep_fixed 'RestrictNamespaces=yes' "$SESSION_UNIT" \
    "post-Shell helper cannot create child namespaces"
assert_grep_fixed 'SystemCallFilter=@system-service' "$SESSION_UNIT" \
    "post-Shell helper has the maintained system-service syscall baseline"
assert_grep_fixed 'ProtectHome=read-only' "$SESSION_UNIT" \
    "post-Shell one-shot cannot modify user data"
assert_grep_fixed 'RuntimeDirectory=noid-gsk-session-environment' "$SESSION_UNIT" \
    "post-Shell one-shot owns a private runtime marker directory"
assert_grep_fixed '/usr/bin/dbus-update-activation-environment --systemd GSK_RENDERER=gl' \
    "$SESSION_HELPER" "session helper updates only future activation environments"
assert_grep_fixed "rpm -qf --qf '%{NAME}' /usr/bin/dbus-update-activation-environment" \
    "$KS_FILE" "compose verifies the exact dbus-tools runtime owner"
assert_grep_fixed 'activation_updater=/usr/bin/dbus-update-activation-environment' \
    "$RUNTIME_GATE" "runtime gate binds the activation updater's exact path"
assert_grep_fixed 'required GTK session activation package dbus-tools is absent' \
    "$RUNTIME_GATE" "runtime gate rejects a missing dbus-tools package"
assert_grep_fixed 'systemctl --user show-environment | grep -qxF GSK_RENDERER=gl' \
    "$SESSION_HELPER" "session helper verifies the user-manager postcondition"
assert_grep_fixed 'systemctl --user show-environment' "$RUNTIME_GATE" \
    "runtime gate detects a lost user-manager renderer value"
assert_grep_fixed 'systemctl --user show org.gnome.Shell@user.service' \
    "$RUNTIME_GATE" "runtime gate identifies the real GNOME Shell through systemd"
assert_grep_fixed 'RestrictAddressFamilies=AF_UNIX' "$RUNTIME_GATE" \
    "runtime gate proves the retained socket boundary"
assert_grep_fixed 'PrivateNetwork=no' "$RUNTIME_GATE" \
    "runtime socket probe cannot rely on network namespaces"
assert_cmd_failure "runtime gate refuses an absent VM-pass identity" \
    bash "$RUNTIME_GATE"
assert_cmd_failure "runtime gate refuses an unknown VM-pass identity" \
    bash "$RUNTIME_GATE" source-host
assert_not_grep 'echo .*SKIP' "$RUNTIME_GATE" \
    "runtime gate contains no success-producing skip path"
assert_grep_fixed 'export PATH=/usr/local/bin:/usr/sbin:/usr/bin' \
    "$RUNTIME_GATE" "runtime gate closes executable resolution"
assert_grep_fixed 'unix:path=$SESSION_BUS' "$RUNTIME_GATE" \
    "runtime gate binds systemctl to the canonical user-bus socket"
assert_grep_fixed \
    'fail "cannot extract unique canonical renderer payloads"' \
    "$RUNTIME_GATE" "runtime gate requires unique canonical renderer payloads"
for runtime_payload in \
        FMT_EOF GSK_MATCH_EOF GSK_SESSION_HELPER_EOF GSK_SESSION_UNIT_EOF \
        GSK_TOGGLE_EOF; do
    assert_grep_fixed "$runtime_payload" "$RUNTIME_GATE" \
        "runtime gate extracts canonical payload: $runtime_payload"
done
assert_grep_fixed \
    '/usr/local/lib/noid-privacy/agent-install-format.sh' "$RUNTIME_GATE" \
    "runtime gate binds the library sourced by the renderer toggle"
assert_grep_fixed 'require_equal "$canonical" "$installed"' "$RUNTIME_GATE" \
    "runtime gate binds every executed renderer payload byte-for-byte"
assert_grep_fixed '"0:0:$mode:1"' "$RUNTIME_GATE" \
    "runtime gate authenticates root payload owner, mode and link count"
assert_grep_fixed 'matchpathcon -V "$path"' "$RUNTIME_GATE" \
    "runtime gate authenticates root payload SELinux labels"
assert_grep_fixed "'%{NAME}|%{FILEDIGESTALGO}" "$RUNTIME_GATE" \
    "runtime gate requires the Fedora drop-in's SHA-256 systemd ownership"
assert_grep_fixed 'sha256sum -- "$vendor_dropin"' "$RUNTIME_GATE" \
    "runtime gate authenticates only the permitted Fedora global user-unit drop-in"
for unit_contract in \
        'DropInPaths|$vendor_dropin' \
        'CapabilityBoundingSet|' \
        'ProtectHome|read-only' \
        'MemoryDenyWriteExecute|yes' \
        'SystemCallArchitectures|native'; do
    assert_grep_fixed "$unit_contract" "$RUNTIME_GATE" \
        "runtime gate binds effective user-unit state: $unit_contract"
done
assert_grep_fixed 'systemctl --user show "$probe_unit" -p LoadState --value' \
    "$RUNTIME_GATE" "runtime gate proves its transient AF probe is collected"
for gpu_selector in DRI_PRIME __NV_PRIME_RENDER_OFFLOAD \
        __GLX_VENDOR_LIBRARY_NAME __VK_LAYER_NV_optimus \
        VK_LOADER_DRIVERS_SELECT; do
    for renderer_surface in "$SESSION_HELPER" "$WRAPPER" "$SOFTWARE_WRAPPER"; do
        assert_not_grep "$gpu_selector" "$renderer_surface" \
            "$(basename "$renderer_surface") never overrides GPU selection: $gpu_selector"
    done
done
assert_grep_fixed 'gnome-session.target.wants/noid-gsk-session-environment.service' \
    "$KS_FILE" "distribution user unit is enabled only inside GNOME session startup"
assert_grep_fixed '[ -L /etc/systemd/user/gnome-software.service ]' "$KS_FILE" \
    "M19 verifies the silent-machine GNOME Software mask remains exact"
assert_grep_fixed 'Exec=/usr/local/bin/gnome-control-center' "$DESKTOP_SYNC" \
    "XDG admin launcher uses the application-scoped wrapper"
assert_grep_fixed 'DBusActivatable=false' "$DESKTOP_SYNC" \
    "XDG admin launcher selects its Exec path"
assert_grep_fixed 'post_transaction:gnome-control-center:in:enabled=host-only raise_error=1:' \
    "$DESKTOP_ACTION" "gnome-control-center updates regenerate the XDG launcher"
assert_grep_fixed 'rm -f -- /usr/local/share/dbus-1/services/org.gnome.Settings.service' \
    "$KS_FILE" "obsolete duplicate D-Bus service shadow is retired"
assert_grep_fixed 'LEGACY_MASK=/etc/systemd/user-environment-generators/55-noid-gsk-renderer' \
    "$TOGGLE" "toggle recognizes the retired generator mask for migration"
assert_grep_fixed 'refusing to overwrite an unsafe or independently modified' \
    "$TOGGLE" "manual on preserves independent environment ownership"
assert_grep_fixed 'refusing to replace an independently managed legacy generator override' \
    "$TOGGLE" "policy never overwrites an administrator legacy override"
assert_grep_fixed 'mv -fT -- "$temporary" "$TARGET"' "$TOGGLE" \
    "manual on publishes with same-directory atomic rename"
assert_grep_fixed 'restorecon -F "$temporary"' "$TOGGLE" \
    "SELinux context is final before policy publication"
assert_grep_fixed 'root:root:644' "$TOGGLE" \
    "managed renderer files have exact metadata"
assert_grep_fixed 'It does **not** match Intel-only, AMD-only, NVIDIA-only' "$KS_FILE" \
    "documentation states the automatic hardware exclusions"
assert_grep_fixed 'future systemd/D-Bus-activated GTK applications only' "$KS_FILE" \
    "documentation states the automatic application scope"
assert_grep_fixed 'This selects only GTK 4'\''s GSK renderer backend; it does not select a physical' \
    "$KS_FILE" "documentation separates renderer selection from GPU selection"
assert_grep_fixed 'used GTK 4.22.4 and three' "$KS_FILE" \
    "documentation records the current Fedora 44 renderer recheck"
assert_grep_fixed 'The native Vulkan path reached its first Wayland surface in 2.283–2.401 seconds' \
    "$KS_FILE" "documentation retains the reproduced Vulkan launch range"
assert_grep_fixed 'GTK'\''s supported GL renderer took 0.201–0.276 seconds' \
    "$KS_FILE" "documentation retains the reproduced GL launch range"
assert_grep_fixed 'Steam/Proton games, Godot'\''s Vulkan/OpenGL rendering drivers and' \
    "$KS_FILE" "documentation preserves non-GTK workload rendering"
assert_grep_fixed 'Android Emulator'\''s own `-gpu` mode are not redirected' \
    "$KS_FILE" "documentation preserves emulator GPU policy"
assert_grep_fixed 'Only the NVIDIA `cardN` KMS node receives the Mutter-specific tag.' \
    "$KS_FILE" "documentation limits Mutter filtering to the display node"
assert_grep_fixed 'The first focused cursor lazily creates Mutter'\''s native cursor' \
    "$KS_FILE" "documentation names the verified lazy Mutter object"
assert_grep_fixed 'both still admit every seat DRM primary node unless' \
    "$KS_FILE" "documentation records the current Mutter source result"
assert_grep_fixed 'Remove the rule only after the installed Mutter source' \
    "$KS_FILE" "documentation defines an evidence-based retirement gate"
assert_grep_fixed '`renderD*` node, device permissions, switcheroo-control tag and driver' \
    "$KS_FILE" "documentation preserves render-offload authority"
assert_grep_fixed 'flatpak override --user --env=GSK_RENDERER=gl APP_ID' "$KS_FILE" \
    "Flatpak workaround remains application-scoped and explicit"
assert_not_grep "cat > /usr/lib/systemd/user-environment-generators/55-noid-gsk-renderer" \
    "$KS_FILE" "retired global environment generator is not installed"

# Exercise the matcher against closed synthetic PCI/DRM topologies.
make_gpu() {
    local root=$1 card=$2 device=$3 vendor=$4 class=$5 boot_vga=$6 control=$7 runtime=$8
    mkdir -p "$root/class/drm" "$root/devices/$device/drm/$card" \
        "$root/devices/$device/power"
    ln -s "../../devices/$device/drm/$card" "$root/class/drm/$card"
    ln -s ../.. "$root/devices/$device/drm/$card/device"
    printf '%s\n' "$vendor" >"$root/devices/$device/vendor"
    printf '%s\n' "$class" >"$root/devices/$device/class"
    [ "$boot_vga" = missing ] || printf '%s\n' "$boot_vga" >"$root/devices/$device/boot_vga"
    printf '%s\n' "$control" >"$root/devices/$device/power/control"
    printf '%s\n' "$runtime" >"$root/devices/$device/power/runtime_status"
}
new_topology() {
    local chassis=$2 root="$TMPDIR/topology-$1"
    mkdir -p "$root/class/dmi/id"
    printf '%s\n' "$chassis" >"$root/class/dmi/id/chassis_type"
    printf '%s\n' "$root"
}
run_matcher() {
    local root=$1
    local fixture="$TMPDIR/matcher-run"
    sed -e "s#^SYS_ROOT=/sys\$#SYS_ROOT=$root#" \
        -e "s#^CHASSIS_TYPE_FILE=/sys/class/dmi/id/chassis_type\$#CHASSIS_TYPE_FILE=$root/class/dmi/id/chassis_type#" \
        "$MATCHER" >"$fixture"
    chmod 0755 "$fixture"
    "$fixture"
}
run_mutter_matcher() {
    local root=$1 card=$2
    local fixture="$TMPDIR/mutter-matcher-run"
    sed -e "s#^SYS_ROOT=/sys\$#SYS_ROOT=$root#" \
        -e "s#^CHASSIS_TYPE_FILE=/sys/class/dmi/id/chassis_type\$#CHASSIS_TYPE_FILE=$root/class/dmi/id/chassis_type#" \
        "$MATCHER" >"$fixture"
    chmod 0755 "$fixture"
    "$fixture" --mutter-headless-card "$root/class/drm/$card"
}
add_connector() {
    local root=$1 card=$2 connector=$3
    local real_card
    real_card=$(readlink -f "$root/class/drm/$card")
    mkdir -p "$real_card/$card-$connector"
    ln -s "../../${real_card#"$root/"}//$card-$connector" \
        "$root/class/drm/$card-$connector"
}
add_render_node() {
    local root=$1 card=$2 render=$3
    local real_card device
    real_card=$(readlink -f "$root/class/drm/$card")
    device=$(readlink -f "$real_card/device")
    mkdir -p "$device/drm/$render"
    ln -s ../.. "$device/drm/$render/device"
    ln -s "../../devices/${device#"$root/devices/"}/drm/$render" \
        "$root/class/drm/$render"
}

intel_nvidia=$(new_topology intel-nvidia 10)
make_gpu "$intel_nvidia" card0 intel 0x8086 0x030000 1 auto active
make_gpu "$intel_nvidia" card1 nvidia 0x10de 0x030200 missing auto suspended
add_connector "$intel_nvidia" card0 eDP-1
add_connector "$intel_nvidia" card1 DP-1
add_render_node "$intel_nvidia" card1 renderD129
assert_cmd_success "portable Intel-primary/NVIDIA-offload topology matches" \
    run_matcher "$intel_nvidia"
assert_cmd_failure "NVIDIA node with a wired connector stays visible to Mutter" \
    run_mutter_matcher "$intel_nvidia" card1

connectorless_nvidia=$(new_topology connectorless-nvidia 10)
make_gpu "$connectorless_nvidia" card0 intel 0x8086 0x030000 1 auto active
make_gpu "$connectorless_nvidia" card1 nvidia 0x10de 0x030200 0 auto suspended
add_connector "$connectorless_nvidia" card0 eDP-1
add_render_node "$connectorless_nvidia" card1 renderD129
assert_eq mutter-device-ignore \
    "$(run_mutter_matcher "$connectorless_nvidia" card1)" \
    "connectorless NVIDIA offload card receives the exact Mutter tag"

no_render_nvidia=$(new_topology no-render-nvidia 10)
make_gpu "$no_render_nvidia" card0 intel 0x8086 0x030000 1 auto active
make_gpu "$no_render_nvidia" card1 nvidia 0x10de 0x030200 0 auto suspended
add_connector "$no_render_nvidia" card0 eDP-1
assert_cmd_failure "card without an application render node stays visible to Mutter" \
    run_mutter_matcher "$no_render_nvidia" card1

no_panel_nvidia=$(new_topology no-panel-nvidia 10)
make_gpu "$no_panel_nvidia" card0 intel 0x8086 0x030000 1 auto active
make_gpu "$no_panel_nvidia" card1 nvidia 0x10de 0x030200 0 auto suspended
add_render_node "$no_panel_nvidia" card1 renderD129
assert_cmd_failure "topology without an internal primary panel stays visible to Mutter" \
    run_mutter_matcher "$no_panel_nvidia" card1

handheld_nvidia=$(new_topology handheld-nvidia 11)
make_gpu "$handheld_nvidia" card0 intel 0x8086 0x030000 1 auto active
make_gpu "$handheld_nvidia" card1 nvidia 0x10de 0x030200 0 auto suspended
assert_cmd_success "SMBIOS portable type 11 uses the aligned matcher contract" \
    run_matcher "$handheld_nvidia"

amd_nvidia=$(new_topology amd-nvidia 10)
make_gpu "$amd_nvidia" card0 amd-apu 0x1002 0x030000 1 auto active
make_gpu "$amd_nvidia" card1 nvidia 0x10de 0x030200 0 auto active
assert_cmd_success "portable AMD-primary/NVIDIA-offload topology matches" \
    run_matcher "$amd_nvidia"

intel_amd=$(new_topology intel-amd 10)
make_gpu "$intel_amd" card0 intel 0x8086 0x030000 1 auto active
make_gpu "$intel_amd" card1 amd-dgpu 0x1002 0x030200 0 auto suspended
assert_cmd_failure "AMD dGPU without NVIDIA does not match" run_matcher "$intel_amd"

nvidia_primary=$(new_topology nvidia-primary 10)
make_gpu "$nvidia_primary" card0 nvidia 0x10de 0x030000 1 auto active
make_gpu "$nvidia_primary" card1 intel 0x8086 0x030200 0 auto active
assert_cmd_failure "NVIDIA-primary/MUX topology does not match" \
    run_matcher "$nvidia_primary"

desktop_hybrid=$(new_topology desktop-hybrid 3)
make_gpu "$desktop_hybrid" card0 intel 0x8086 0x030000 1 auto active
make_gpu "$desktop_hybrid" card1 nvidia 0x10de 0x030200 0 auto suspended
assert_cmd_failure "desktop multi-GPU topology does not match" \
    run_matcher "$desktop_hybrid"

manual_power=$(new_topology manual-power 10)
make_gpu "$manual_power" card0 intel 0x8086 0x030000 1 auto active
make_gpu "$manual_power" card1 nvidia 0x10de 0x030200 0 on active
assert_cmd_failure "NVIDIA GPU outside runtime-PM policy does not match" \
    run_matcher "$manual_power"

triple_gpu=$(new_topology triple-gpu 10)
make_gpu "$triple_gpu" card0 intel 0x8086 0x030000 1 auto active
make_gpu "$triple_gpu" card1 nvidia-a 0x10de 0x030200 0 auto suspended
make_gpu "$triple_gpu" card2 amd-dgpu 0x1002 0x030200 0 auto suspended
assert_cmd_failure "unreviewed triple-GPU topology does not match" \
    run_matcher "$triple_gpu"

dual_nvidia_offload=$(new_topology dual-nvidia-offload 10)
make_gpu "$dual_nvidia_offload" card0 intel 0x8086 0x030000 1 auto active
make_gpu "$dual_nvidia_offload" card1 nvidia-a 0x10de 0x030200 0 auto suspended
make_gpu "$dual_nvidia_offload" card2 nvidia-b 0x10de 0x030200 0 auto active
assert_cmd_failure "multiple NVIDIA offload GPUs do not match" \
    run_matcher "$dual_nvidia_offload"

# Exercise wrapper scope and precedence with a controlled matcher and vendor
# executable. The real wrapper must never export GL to the parent session.
mkdir -p "$TMPDIR/wrapper-bin" "$TMPDIR/wrapper-policy"
cat >"$TMPDIR/wrapper-bin/matcher" <<'FAKE_MATCHER_EOF'
#!/bin/bash
[ "${MATCH_RESULT:-0}" = 1 ]
FAKE_MATCHER_EOF
cat >"$TMPDIR/wrapper-bin/vendor" <<'FAKE_VENDOR_EOF'
#!/bin/bash
printf 'renderer=%s\n' "${GSK_RENDERER-<unset>}"
[ "${PRINT_LOCALE:-0}" != 1 ] || printf 'lc_all=%s\n' "${LC_ALL-<unset>}"
[ "${PRINT_SOFTWARE_PLUGINS:-0}" != 1 ] || {
    printf 'allowlist=%s\n' "${GNOME_SOFTWARE_PLUGINS_ALLOWLIST-<unset>}"
    printf 'blocklist=%s\n' "${GNOME_SOFTWARE_PLUGINS_BLOCKLIST-<unset>}"
}
printf 'args=%s\n' "$*"
FAKE_VENDOR_EOF
chmod 0755 "$TMPDIR/wrapper-bin/"*
sed -e "s#^VENDOR=/usr/bin/gnome-control-center#VENDOR=$TMPDIR/wrapper-bin/vendor#" \
    -e "s#^MATCHER=/usr/libexec/noid-gsk-hybrid-match#MATCHER=$TMPDIR/wrapper-bin/matcher#" \
    -e "s#^MODE=/etc/xdg/noid-privacy/gsk-renderer.mode#MODE=$TMPDIR/wrapper-policy/gsk-renderer.mode#" \
    "$WRAPPER" >"$TMPDIR/wrapper-fixture"
chmod 0755 "$TMPDIR/wrapper-fixture"
assert_eq $'renderer=gl\nargs=display' \
    "$(env -u GSK_RENDERER MATCH_RESULT=1 "$TMPDIR/wrapper-fixture" display)" \
    "matched Settings launch receives app-scoped GL"
assert_eq $'renderer=vulkan\nargs=display' \
    "$(env GSK_RENDERER=vulkan MATCH_RESULT=1 "$TMPDIR/wrapper-fixture" display)" \
    "administrator renderer value is preserved exactly"
assert_eq $'renderer=<unset>\nargs=display' \
    "$(env -u GSK_RENDERER MATCH_RESULT=0 "$TMPDIR/wrapper-fixture" display)" \
    "unmatched topology retains the vendor renderer"
assert_eq $'renderer=gl\nlc_all=de_DE.UTF-8\nargs=display' \
    "$(env -u GSK_RENDERER LC_ALL=de_DE.UTF-8 PRINT_LOCALE=1 MATCH_RESULT=1 \
        "$TMPDIR/wrapper-fixture" display)" \
    "matched Settings launch preserves the user's interface locale"
printf '%s\n' off >"$TMPDIR/wrapper-policy/gsk-renderer.mode"
assert_eq $'renderer=<unset>\nargs=display' \
    "$(env -u GSK_RENDERER MATCH_RESULT=1 "$TMPDIR/wrapper-fixture" display)" \
    "off marker retains the vendor renderer on a matched topology"

rm -f "$TMPDIR/wrapper-policy/gsk-renderer.mode"
sed -e "s#^VENDOR=/usr/bin/gnome-software#VENDOR=$TMPDIR/wrapper-bin/vendor#" \
    -e "s#^MATCHER=/usr/libexec/noid-gsk-hybrid-match#MATCHER=$TMPDIR/wrapper-bin/matcher#" \
    -e "s#^MODE=/etc/xdg/noid-privacy/gsk-renderer.mode#MODE=$TMPDIR/wrapper-policy/gsk-renderer.mode#" \
    "$SOFTWARE_WRAPPER" >"$TMPDIR/software-wrapper-fixture"
chmod 0755 "$TMPDIR/software-wrapper-fixture"
software_plugins=flatpak,icons,hardcoded-blocklist,malcontent,modalias,os-release,provenance,provenance-license,generic-updates
assert_eq "renderer=gl
allowlist=$software_plugins
blocklist=<unset>
args=--mode=updates" \
    "$(env -u GSK_RENDERER -u GNOME_SOFTWARE_PLUGINS_ALLOWLIST \
        -u GNOME_SOFTWARE_PLUGINS_BLOCKLIST PRINT_SOFTWARE_PLUGINS=1 MATCH_RESULT=1 \
        "$TMPDIR/software-wrapper-fixture" --mode=updates)" \
    "explicit GNOME Software launch receives Flatpak scope, app GL and exact arguments"
assert_eq $'renderer=vulkan\nallowlist=admin\nblocklist=<unset>\nargs=--mode=updates' \
    "$(env -u GNOME_SOFTWARE_PLUGINS_BLOCKLIST GSK_RENDERER=vulkan \
        GNOME_SOFTWARE_PLUGINS_ALLOWLIST=admin PRINT_SOFTWARE_PLUGINS=1 \
        MATCH_RESULT=1 \
        "$TMPDIR/software-wrapper-fixture" --mode=updates)" \
    "GNOME Software wrapper preserves administrator renderer and allowlist"
assert_eq $'renderer=<unset>\nallowlist=<unset>\nblocklist=admin\nargs=details' \
    "$(env -u GSK_RENDERER -u GNOME_SOFTWARE_PLUGINS_ALLOWLIST \
        GNOME_SOFTWARE_PLUGINS_BLOCKLIST=admin PRINT_SOFTWARE_PLUGINS=1 \
        MATCH_RESULT=0 "$TMPDIR/software-wrapper-fixture" details)" \
    "GNOME Software wrapper preserves administrator blocklist ownership"
assert_eq $'renderer=<unset>\nallowlist=\nblocklist=<unset>\nargs=search' \
    "$(env -u GSK_RENDERER -u GNOME_SOFTWARE_PLUGINS_BLOCKLIST \
        GNOME_SOFTWARE_PLUGINS_ALLOWLIST= PRINT_SOFTWARE_PLUGINS=1 \
        MATCH_RESULT=0 "$TMPDIR/software-wrapper-fixture" search)" \
    "GNOME Software wrapper preserves an explicit empty administrator allowlist"

# Execute auto/on/off/status against private policy paths. Fake only root and
# SELinux observations; real atomic rename and unlink paths run.
mkdir -p "$TMPDIR/environment.d" "$TMPDIR/policy" \
    "$TMPDIR/legacy-generator" "$TMPDIR/fake-bin"
cp "$TMPDIR/wrapper-bin/matcher" "$TMPDIR/matcher-fixture"
sed -e "s#^ENV_DIR=/etc/environment.d#ENV_DIR=$TMPDIR/environment.d#" \
    -e "s#^POLICY_DIR=/etc/xdg/noid-privacy#POLICY_DIR=$TMPDIR/policy#" \
    -e "s#^MATCHER=/usr/libexec/noid-gsk-hybrid-match#MATCHER=$TMPDIR/matcher-fixture#" \
    -e "s#^LEGACY_MASK=/etc/systemd/user-environment-generators/55-noid-gsk-renderer#LEGACY_MASK=$TMPDIR/legacy-generator/55-noid-gsk-renderer#" \
    -e "s#^PATH=/usr/sbin:/usr/bin:/sbin:/bin#PATH=$TMPDIR/fake-bin:/usr/sbin:/usr/bin:/sbin:/bin#" \
    "$TOGGLE" >"$TMPDIR/toggle-fixture"
chmod 0755 "$TMPDIR/toggle-fixture"
cat >"$TMPDIR/fake-bin/id" <<'FAKE_ID_EOF'
#!/bin/bash
[ "${1:-}" = -u ] && { echo 0; exit 0; }
exec /usr/bin/id "$@"
FAKE_ID_EOF
cat >"$TMPDIR/fake-bin/chown" <<'FAKE_CHOWN_EOF'
#!/bin/bash
exit 0
FAKE_CHOWN_EOF
cat >"$TMPDIR/fake-bin/restorecon" <<'FAKE_RESTORECON_EOF'
#!/bin/bash
exit 0
FAKE_RESTORECON_EOF
cat >"$TMPDIR/fake-bin/stat" <<'FAKE_STAT_EOF'
#!/bin/bash
case "$*" in
    *'%U:%G:%a'*)
        target=${!#}
        mode=$(/usr/bin/stat -c %a -- "$target") || exit
        echo "root:root:$mode"
        ;;
    *'%C'*) echo system_u:object_r:etc_t:s0 ;;
    *) exec /usr/bin/stat "$@" ;;
esac
FAKE_STAT_EOF
chmod 0755 "$TMPDIR/fake-bin/"*
fixture_env=(PATH="$TMPDIR/fake-bin:/usr/sbin:/usr/bin:/sbin:/bin" MATCH_RESULT=1)

# Exercise the XDG launcher sync against a valid vendor fixture. It must retain
# every unrelated field and fail closed on anchor drift without replacing the
# last known-good destination.
mkdir -p "$TMPDIR/desktop-source" "$TMPDIR/desktop-dest"
cat >"$TMPDIR/desktop-source/org.gnome.Settings.desktop" <<'DESKTOP_FIXTURE_EOF'
[Desktop Entry]
Type=Application
Name=Settings
Name[de]=Einstellungen
Exec=gnome-control-center
DBusActivatable=true
Icon=org.gnome.Settings
OnlyShowIn=GNOME;
DESKTOP_FIXTURE_EOF
sed -e "s#^SOURCE=/usr/share/applications/org.gnome.Settings.desktop#SOURCE=$TMPDIR/desktop-source/org.gnome.Settings.desktop#" \
    -e "s#^DEST_DIR=/usr/local/share/applications#DEST_DIR=$TMPDIR/desktop-dest#" \
    -e "s#^PATH=/usr/sbin:/usr/bin:/sbin:/bin#PATH=$TMPDIR/fake-bin:/usr/sbin:/usr/bin:/sbin:/bin#" \
    "$DESKTOP_SYNC" >"$TMPDIR/desktop-sync-fixture"
chmod 0755 "$TMPDIR/desktop-sync-fixture"
assert_cmd_success "XDG launcher sync publishes a valid admin override" \
    env PATH="$TMPDIR/fake-bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    "$TMPDIR/desktop-sync-fixture"
assert_grep_fixed 'Name[de]=Einstellungen' \
    "$TMPDIR/desktop-dest/org.gnome.Settings.desktop" \
    "XDG launcher sync retains vendor translations"
assert_grep_fixed 'Exec=/usr/local/bin/gnome-control-center' \
    "$TMPDIR/desktop-dest/org.gnome.Settings.desktop" \
    "XDG launcher sync publishes the wrapped Exec"
assert_grep_fixed 'DBusActivatable=false' \
    "$TMPDIR/desktop-dest/org.gnome.Settings.desktop" \
    "XDG launcher sync disables desktop D-Bus activation"
assert_not_grep '^DBusActivatable=true$' \
    "$TMPDIR/desktop-dest/org.gnome.Settings.desktop" \
    "XDG launcher contains no active D-Bus activation"
desktop_before=$(sha256sum "$TMPDIR/desktop-dest/org.gnome.Settings.desktop")
sed -i '/^DBusActivatable=true$/d' \
    "$TMPDIR/desktop-source/org.gnome.Settings.desktop"
assert_cmd_failure "vendor launcher anchor drift fails closed" \
    env PATH="$TMPDIR/fake-bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    "$TMPDIR/desktop-sync-fixture"
assert_eq "$desktop_before" \
    "$(sha256sum "$TMPDIR/desktop-dest/org.gnome.Settings.desktop")" \
    "anchor drift preserves the last known-good XDG launcher"

assert_cmd_success "default status is post-Shell app GL on matched topology" \
    env "${fixture_env[@]}" bash -c \
    '"$1" status | grep -qxF system_override=absent && "$1" status | grep -qxF effective_future_apps=gl-session-apps-auto' _ \
    "$TMPDIR/toggle-fixture"
assert_cmd_success "manual on publishes managed bytes" \
    env "${fixture_env[@]}" "$TMPDIR/toggle-fixture" on
assert_eq $'# NoID Privacy explicit GTK4 GL renderer opt-in\nGSK_RENDERER=gl' \
    "$(cat "$TMPDIR/environment.d/90-noid-gsk-renderer.conf")" \
    "manual on writes exact managed renderer bytes"
assert_cmd_success "off removes manual bytes and publishes app policy" \
    env "${fixture_env[@]}" "$TMPDIR/toggle-fixture" off
assert_cmd_success "off leaves no static renderer target" test ! -e \
    "$TMPDIR/environment.d/90-noid-gsk-renderer.conf"
assert_eq off "$(cat "$TMPDIR/policy/gsk-renderer.mode")" \
    "off publishes the exact managed application marker"
chmod 0600 "$TMPDIR/policy/gsk-renderer.mode"
assert_cmd_success "off repairs exact managed bytes with unsafe metadata" \
    env "${fixture_env[@]}" "$TMPDIR/toggle-fixture" off
assert_eq 644 "$(stat -c %a "$TMPDIR/policy/gsk-renderer.mode")" \
    "off republishes the managed marker with exact metadata"
assert_cmd_success "auto removes the managed application marker" \
    env "${fixture_env[@]}" "$TMPDIR/toggle-fixture" auto
assert_cmd_success "auto leaves no static target or mode" bash -c \
    '[ ! -e "$1" ] && [ ! -L "$1" ] && [ ! -e "$2" ] && [ ! -L "$2" ]' _ \
    "$TMPDIR/environment.d/90-noid-gsk-renderer.conf" \
    "$TMPDIR/policy/gsk-renderer.mode"

ln -s /dev/null "$TMPDIR/legacy-generator/55-noid-gsk-renderer"
assert_cmd_success "auto removes the exact retired NoID Privacy generator mask" \
    env "${fixture_env[@]}" "$TMPDIR/toggle-fixture" auto
assert_cmd_success "retired generator mask is absent" test ! -L \
    "$TMPDIR/legacy-generator/55-noid-gsk-renderer"

printf '%s\n' 'GSK_RENDERER=vulkan' \
    >"$TMPDIR/environment.d/90-noid-gsk-renderer.conf"
assert_cmd_failure "manual on refuses an independently modified renderer file" \
    env "${fixture_env[@]}" "$TMPDIR/toggle-fixture" on
assert_eq 'GSK_RENDERER=vulkan' \
    "$(cat "$TMPDIR/environment.d/90-noid-gsk-renderer.conf")" \
    "refused policy change preserves independent bytes"

rm -f "$TMPDIR/environment.d/90-noid-gsk-renderer.conf"
printf '%s\n' custom >"$TMPDIR/policy/gsk-renderer.mode"
assert_cmd_failure "auto refuses an independently modified app policy" \
    env "${fixture_env[@]}" "$TMPDIR/toggle-fixture" auto
assert_eq custom "$(cat "$TMPDIR/policy/gsk-renderer.mode")" \
    "refused policy change preserves independent mode bytes"

test_finish

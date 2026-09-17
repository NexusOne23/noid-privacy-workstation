#!/bin/bash
# 19-nvidia-mok-docs-structural — M19 regression test
#
# Covers: hardware user-docs (NVIDIA, secure-boot, displaylink, docking),
# docs-only philosophy (no automatic driver install at build).
# Would catch: regression to auto-installing akmod-nvidia, missing doc.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/19-nvidia-mok-docs.ks"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

test_start "19-nvidia-mok-docs-structural"

assert_file_exists "$KS_FILE"
assert_cmd_success "bash -n $KS_FILE" bash -n "$KS_FILE"
extract_heredoc "$KS_FILE" "NVIDIA_DOC_EOF" "$TMPDIR/19-nvidia-drivers.md" \
    || _fail "NVIDIA driver guide extraction"
extract_heredoc "$KS_FILE" "MOK_DOC_EOF" "$TMPDIR/19-secure-boot-mok.md" \
    || _fail "NVIDIA MOK guide extraction"
extract_heredoc "$KS_FILE" "NVIDIA_INSTALL_EOF" "$TMPDIR/noid-nvidia-install.sh" \
    || _fail "NVIDIA installer extraction"
extract_heredoc "$KS_FILE" "REBIND_NV_EOF" "$TMPDIR/noid-nvidia-rebind-evidence" \
    || _fail "NVIDIA evidence bridge extraction"
extract_heredoc "$KS_FILE" "HELPER_NV_EOF" "$TMPDIR/noid-nvidia-initramfs-rebuild" \
    || _fail "NVIDIA initramfs worker extraction"
extract_heredoc "$KS_FILE" "POSTBOOT_NV_EOF" "$TMPDIR/noid-nvidia-postboot-verify" \
    || _fail "NVIDIA post-boot verifier extraction"
assert_cmd_success "deployed NVIDIA installer is valid bash" \
    bash -n "$TMPDIR/noid-nvidia-install.sh"
for nvidia_state_helper in \
        "$TMPDIR/noid-nvidia-rebind-evidence" \
        "$TMPDIR/noid-nvidia-initramfs-rebuild" \
        "$TMPDIR/noid-nvidia-postboot-verify"; do
    assert_cmd_success "deployed NVIDIA state helper is valid bash" \
        bash -n "$nvidia_state_helper"
done
if command -v shellcheck >/dev/null 2>&1; then
    assert_cmd_success "deployed NVIDIA installer passes ShellCheck warnings" \
        shellcheck -S warning "$TMPDIR/noid-nvidia-install.sh"
else
    _pass "shellcheck unavailable — deployed NVIDIA installer lint skipped"
fi

# Docs shipped under /usr/share/doc/noid-privacy/
assert_grep_fixed "/usr/share/doc/noid-privacy/19-nvidia-drivers.md" "$KS_FILE"
assert_grep_extended "/usr/share/doc/noid-privacy/19-(secure-boot|mok|displaylink|docking)" "$KS_FILE"

# Heredoc markers
assert_grep_fixed 'NVIDIA_DOC_EOF' "$KS_FILE"

# MANDATORY: NOT auto-installing akmod-nvidia in the live %post. Extract every
# executable %post line while excluding all heredoc payload bodies, including
# the large documentation and installer payloads.
POST_ACTIVE="$TMPDIR/post-active.sh"
if python3 - "$KS_FILE" "$POST_ACTIVE" <<'POST_ACTIVE_PY'
import pathlib
import re
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
output = []
in_post = False
terminator = None
for line in source:
    if terminator is not None:
        if line == terminator:
            terminator = None
        continue
    if line.startswith("%post"):
        in_post = True
        continue
    if in_post and line == "%end":
        in_post = False
        continue
    if not in_post:
        continue
    match = re.search(r"<<-?\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?", line)
    if match:
        terminator = match.group(1)
        continue
    output.append(line)
if terminator is not None or in_post:
    raise SystemExit("unterminated %post or heredoc while extracting active shell")
pathlib.Path(sys.argv[2]).write_text("\n".join(output) + "\n", encoding="utf-8")
POST_ACTIVE_PY
then
    _pass "complete active NVIDIA %post shell extracted"
else
    _fail "complete active NVIDIA %post shell extracted"
fi
if grep -qE '^[[:space:]]*dnf[[:space:]]+install.*akmod-nvidia' "$POST_ACTIVE"; then
    _fail "%post installs akmod-nvidia (must be docs-only)"
else
    _pass "%post does not install akmod-nvidia"
fi
if grep -qE '^[[:space:]]*dnf[[:space:]]+install.*xorg-x11-drv-nvidia' "$POST_ACTIVE"; then
    _fail "%post installs xorg-x11-drv-nvidia (must be docs-only)"
else
    _pass "%post does not install xorg-x11-drv-nvidia"
fi
assert_grep_fixed 'if ! nvidia_inventory=$(rpm -qa' "$POST_ACTIVE" \
    "compose-time NVIDIA inventory runs directly in the root %post"
assert_not_grep_extended '^[[:space:]]*sudo[[:space:]]+rpm[[:space:]]+-qa' \
    "$POST_ACTIVE" "compose-time RPM inventory has no needless sudo dependency"

# MANDATORY: NOT auto-writing blacklist-nouveau.conf in the live %post
# Docs explaining what akmod-nvidia RPM scriptlet creates
# are allowed.
if grep -qE '^[[:space:]]*cat[[:space:]]+>.*blacklist-nouveau\.conf' "$POST_ACTIVE"; then
    _fail "%post writes blacklist-nouveau.conf (must be docs-only)"
else
    _pass "%post does not write blacklist-nouveau.conf"
fi

# User docs reference the right post-install paths
assert_grep_fixed "/etc/modprobe.d/nvidia.conf" "$KS_FILE"
assert_grep_fixed "/etc/dracut.conf.d/nvidia.conf" "$KS_FILE"

# Driver installation may explain AIDE drift but cannot auto-accept it.
assert_grep_fixed 'noid-aide-baseline-review prepare' "$KS_FILE"
assert_grep_fixed 'never accepts the result or replaces the database' "$KS_FILE"
assert_not_grep '^[[:space:]]*sudo aide --update' "$KS_FILE"
assert_not_grep '^[[:space:]]*sudo cp /var/lib/aide/aide.db.new.gz' "$KS_FILE"
for expected_nvidia_drift in \
        /usr/libexec/noid-nvidia-initramfs-queue \
        /usr/libexec/noid-nvidia-reboot-guard \
        /usr/libexec/noid-nvidia-verify \
        /etc/systemd/system/noid-nvidia-reboot-guard.service \
        /etc/systemd/system/noid-nvidia-initramfs-resume.service \
        /var/lib/noid-nvidia-integrity/; do
    assert_grep_fixed "$expected_nvidia_drift" "$TMPDIR/19-nvidia-drivers.md" \
        "AIDE guidance names expected installer drift: $expected_nvidia_drift"
done

# User-facing names and recovery commands must match the shipped GNOME/systemd
# interfaces exactly; stale approximate labels make a working offload path look
# absent, while `unmask --now` leaves the service inactive.
assert_eq 3 "$(grep -cF 'Launch Using Discrete Graphics Card' \
    "$TMPDIR/19-nvidia-drivers.md" || true)" \
    "all three switcheroo references use GNOME's exact menu label"
assert_not_grep_extended 'Run with Discrete GPU|Launch with dedicated GPU' \
    "$TMPDIR/19-nvidia-drivers.md" \
    "NVIDIA guide contains no invented switcheroo menu label"
assert_grep_fixed 'sudo systemctl unmask switcheroo-control.service' \
    "$TMPDIR/19-nvidia-drivers.md" \
    "switcheroo recovery first removes the mask"
assert_grep_fixed 'sudo systemctl enable --now switcheroo-control.service' \
    "$TMPDIR/19-nvidia-drivers.md" \
    "switcheroo recovery then enables and starts the service"
assert_not_grep 'systemctl unmask --now' "$TMPDIR/19-nvidia-drivers.md" \
    "switcheroo recovery uses no unsupported unmask --now combination"

# MOK verification must match messages the kernel actually emits. A vacuous
# `loading unsigned` search misses `Loading of unsigned module is rejected`.
assert_grep_fixed \
    "sudo dmesg | grep -iE 'Loading of .* is rejected|module verification failed|unsigned module loading'" \
    "$TMPDIR/19-secure-boot-mok.md" \
    "MOK verification searches the real kernel failure messages"
assert_not_grep "grep -i 'loading unsigned'" "$TMPDIR/19-secure-boot-mok.md" \
    "MOK guide contains no impossible kernel-message search"
assert_grep_fixed '6-step MokManager walkthrough' "$KS_FILE" \
    "module contract matches the six shipped MokManager selections"
assert_not_grep '7-step' "$KS_FILE" \
    "NVIDIA module carries no stale seven-step walkthrough claim"

# MOK recovery must revoke only the pending import request; it must never reset
# the enrolled trust list. Verification is bound to the exact akmods cert, not
# a display-name grep across every enrolled key.
assert_not_grep 'mokutil --reset' "$KS_FILE"
assert_grep_fixed 'sudo mokutil --revoke-import' "$KS_FILE"
assert_grep_fixed 'sudo mokutil --test-key /etc/pki/akmods/certs/public_key.der' "$KS_FILE"
assert_not_grep "list-enrolled.*grep.*akmods" "$KS_FILE"

# Platform state and recovery truth: encryption and Secure Boot are measured,
# installer/firmware-selected state; snapshots are not GRUB entries without the
# deliberately absent grub-btrfs integration.
assert_grep_fixed 'Root encryption is selected in the installer' "$KS_FILE"
assert_grep_fixed 'cryptsetup luksDump <device>' "$KS_FILE"
assert_grep_fixed 'are not GRUB entries on this image' "$KS_FILE"
assert_not_grep_extended 'NoID Privacy (Privacy )?(ALWAYS )?encrypts root|encrypts root by default|LUKS-by-default' \
    "$KS_FILE"
assert_not_grep_extended 'boot a pre-update snapshot from GRUB|select a \*\*pre-update snapshot\*\* from the GRUB' \
    "$KS_FILE"
assert_not_grep_extended 'Wrong keypress = unbootable system|unsigned modules cannot load = GDM fails' \
    "$KS_FILE"

# NVIDIA helper owns only its lower lid-close compatibility default. M17 owns
# general idle defaults and the higher explicit choice on every graphics stack.
assert_not_grep '/etc/dconf/db/distro.d/20-noid-nvidia-suspend' "$KS_FILE" \
    "NVIDIA workflow no longer creates or deletes the base GNOME power policy"
assert_not_grep_extended '^[[:space:]]*sleep-inactive-(ac|battery)-type=' "$KS_FILE" \
    "NVIDIA workflow cannot overwrite a user's automatic-suspend choice"
# Lid-close = lock drop-in + real kernel SW_LID gate.
assert_grep_fixed '/etc/systemd/logind.conf.d/99-noid-nvidia-lid.conf' "$KS_FILE"
assert_grep_fixed 'HandleLidSwitch=lock' "$KS_FILE"
assert_grep_fixed 'HandleLidSwitchExternalPower=lock' "$KS_FILE"
assert_grep_fixed '/sys/class/input/event*/device/capabilities/sw' "$KS_FILE" \
    "NVIDIA lower default uses the real kernel lid capability"
assert_grep_fixed 'nv_sw_word=${nv_sw_bitmap##* }' "$KS_FILE" \
    "NVIDIA lower default handles multiword kernel switch bitmaps"
assert_not_grep_extended 'nv_chassis=|power_supply/BAT\*' "$KS_FILE" \
    "NVIDIA lid policy uses no DMI or battery heuristic"
# Rollback removes only the NVIDIA-owned mitigation.
assert_grep_fixed 'rm -f /etc/systemd/logind.conf.d/99-noid-nvidia-lid.conf' "$KS_FILE"
assert_not_grep_extended \
    'rm -f .*99-noid-user-lid-action\.conf|rm -rf .*99-noid-user-lid-action\.conf' \
    "$KS_FILE" "NVIDIA install and rollback cannot remove the explicit M17 choice"
assert_grep_fixed '99-noid-user-lid-action.conf sorts later' "$KS_FILE" \
    "installer documents deterministic explicit-choice precedence"
assert_grep_fixed 'NVIDIA helper neither writes nor removes' "$KS_FILE" \
    "installed guide preserves base/user power-policy ownership"
assert_grep_fixed 'not proof' "$KS_FILE" \
    "installed guide rejects a universal-failure claim"
assert_grep_fixed 'is no automatic lid-close sleep' "$KS_FILE" \
    "installed guide discloses the compatibility trade-off"
assert_not_grep_extended 'crashes in the s2idle suspend path on Ampere/Ada|Xid 154' \
    "$KS_FILE" "M19 contains no unsupported universal GPU/Xid claim"
assert_not_grep 'akmod-nvidia.*595\.xx current' "$KS_FILE" \
    "RPM Fusion package guidance carries no unrelated moving branch number"
assert_grep_fixed 'current RPM Fusion main branch, open kernel module' "$KS_FILE" \
    "modern-generation matrix names the package channel without a stale version pin"
assert_grep_fixed 'NVK supports Kepler+' "$KS_FILE" \
    "legacy refusal retains Mesa's documented Kepler-and-newer NVK boundary"
assert_grep_fixed '| **Kepler** (2012-2014) | GK* |' "$KS_FILE" \
    "generation matrix keeps Kepler explicit"
assert_grep_fixed '| **Nouveau + NVK** |' "$KS_FILE" \
    "Kepler recommendation uses the maintained in-tree/Mesa path"
assert_not_grep_extended 'Fermi.*NVK|Tesla.*NVK' "$KS_FILE" \
    "documentation does not extend NVK below Mesa's documented boundary"
assert_grep_fixed 'GeForce products have received critical' "$KS_FILE" \
    "R580 guidance identifies the GeForce security-only commitment"
assert_grep_fixed 'February 2026 Quadro plan describes one year of full R580 support' \
    "$KS_FILE" "R580 guidance preserves the distinct Quadro commitment"
assert_grep_fixed 'NVIDIA CUDA Architecture Support Guidance' "$KS_FILE" \
    "R580 lifecycle guidance cites NVIDIA's primary CUDA source"
assert_grep_fixed 'requires the `nvidia-kmod-common` capability provided by the' \
    "$KS_FILE" "MOK guide describes the RPM Fusion base-driver dependency"
assert_grep_fixed 'Do not add it as a redundant explicit request.' "$KS_FILE" \
    "Wayland guidance avoids both a false prohibition and a redundant request"
assert_grep_fixed 'An RPM package signature and a kernel-module signature are separate trust' \
    "$KS_FILE" "MOK guide separates package authentication from module trust"
assert_not_grep 'Any package from the Fedora main repos' "$KS_FILE" \
    "MOK guide contains no overbroad Fedora-repository exemption"
assert_grep_fixed 'They may be symlinks to a' "$KS_FILE" \
    "MOK guide describes the selected akmods key links"
assert_grep_fixed 'dereferenced key targets' "$KS_FILE" \
    "MOK guide binds permissions to the real key targets"
assert_not_grep "it's the X11-session driver" "$KS_FILE" \
    "base NVIDIA package is not falsely described as X11-session-only"
assert_not_grep 'Mesa 26.0' "$KS_FILE" \
    "default-stack guidance does not pin a stale Mesa minor release"
assert_grep_fixed 'R580 covers Maxwell/Pascal/Volta and' "$KS_FILE" \
    "mixed-generation guidance records R580's product-specific overlap"
assert_grep_fixed 'main branch excludes the legacy GPU' "$KS_FILE" \
    "mixed-generation guidance rejects a known-incompatible main branch"
assert_grep_fixed 'Blackwell is different: NVIDIA requires the open kernel' \
    "$KS_FILE" "mixed-generation guidance records Blackwell's open-only boundary"
assert_grep_fixed 'BLACKWELL + LEGACY MODULE-FLAVOR CONFLICT' "$KS_FILE" \
    "installer refuses the incompatible Blackwell-plus-legacy module plan"
assert_not_grep 'A single NVIDIA driver branch CANNOT support both generations' \
    "$KS_FILE" "documentation contains no false universal mixed-branch claim"
assert_grep_fixed 'One activation reboot' "$KS_FILE" \
    "documentation makes the already-enrolled reboot count conditional"
assert_not_grep 'proprietary branches EOL with' "$KS_FILE" \
    "module header remains grammatically complete"
assert_not_grep_extended '144\+ FPS|frees ~1MB RAM|value to about 1\.2' \
    "$KS_FILE" "documentation contains no hardware-dependent marketing numbers"
assert_not_grep 'kernel-debug*` packages conflict with the NVIDIA akmod' \
    "$KS_FILE" "documentation makes no unsupported universal debug-kernel conflict claim"
assert_grep_fixed 'helper supports only the kernel that is currently running' \
    "$KS_FILE" "debug-kernel guidance states the exact verified boundary"
assert_not_grep 'manual, unskippable, error-prone' "$KS_FILE" \
    "MOK guidance does not describe a skippable enrollment as unskippable"

# The pre-reboot state machine has one record per kernel. Prepared evidence is
# stronger than ready evidence because it retains the originating boot ID and
# requires live verification on a later boot. Every writer and transition must
# preserve that precedence, including recovery from old coexisting records.
assert_grep_fixed "%U:%G:%a' \"\$STATE_DIR\"" \
    "$TMPDIR/noid-nvidia-rebind-evidence" \
    "evidence bridge validates portable directory ownership and mode"
assert_not_grep "%U:%G:%a:%h' \"\$STATE_DIR\"" \
    "$TMPDIR/noid-nvidia-rebind-evidence" \
    "directory validation does not assume a Btrfs-specific link count"
assert_grep_fixed 'rebind_record "$prepared_record" prepared' \
    "$TMPDIR/noid-nvidia-rebind-evidence" \
    "evidence bridge validates prepared state before resolving coexistence"
assert_grep_fixed 'rm -f -- "$ready_record"' \
    "$TMPDIR/noid-nvidia-rebind-evidence" \
    "evidence bridge retires a superseded legacy ready record"
assert_not_grep 'multiple pre-reboot evidence records exist' \
    "$TMPDIR/noid-nvidia-rebind-evidence" \
    "legacy ready/prepared coexistence has a validated recovery transition"
assert_grep_fixed 'if [ -e "$prepared_record" ] || [ -L "$prepared_record" ]; then' \
    "$TMPDIR/noid-nvidia-initramfs-rebuild" \
    "background rebuild preserves stronger prepared evidence"
assert_grep_fixed 'post-reboot validation remains pending' \
    "$TMPDIR/noid-nvidia-initramfs-rebuild" \
    "background rebuild reports the retained prepared state accurately"
assert_grep_fixed 'rm -f -- "$prepared" "$STATE_DIR/${KVER}.ready" "$DEGRADED"' \
    "$TMPDIR/noid-nvidia-postboot-verify" \
    "successful live verification retires every pre-reboot record"
assert_not_grep '--require-enrolled' \
    "$TMPDIR/noid-nvidia-postboot-verify" \
    "post-boot sandbox does not re-read MokListRT without CAP_SYS_ADMIN"
assert_grep_fixed 'cmp -s -- "$live_build_id" "$disk_build_id"' \
    "$TMPDIR/noid-nvidia-postboot-verify" \
    "post-boot verification binds live modules to signed disk build identities"
assert_not_grep 'CapabilityBoundingSet=.*CAP_SYS_ADMIN' "$KS_FILE" \
    "NVIDIA services do not gain broad firmware-variable capabilities"
installer_ready_retire_line=$(grep -nF \
    'sudo rm -f -- "$NVIDIA_STATE_DIR/${kver}.ready"' \
    "$TMPDIR/noid-nvidia-install.sh" | head -n1 | cut -d: -f1 || true)
installer_prepared_publish_line=$(grep -nF \
    'sudo mv -fT -- "$prepared_tmp" "$NVIDIA_STATE_DIR/${kver}.prepared"' \
    "$TMPDIR/noid-nvidia-install.sh" | head -n1 | cut -d: -f1 || true)
if [ -n "$installer_ready_retire_line" ] \
        && [ -n "$installer_prepared_publish_line" ] \
        && [ "$installer_ready_retire_line" -lt "$installer_prepared_publish_line" ]; then
    _pass "installer retires ready evidence before publishing prepared state"
else
    _fail "installer retires ready evidence before publishing prepared state"
fi
assert_grep_fixed '/580.173.02/README/dynamicpowermanagement.html' "$KS_FILE" \
    "runtime-power guidance uses the reviewed current R580 primary source"
assert_not_grep '/580.76.05/README/dynamicpowermanagement.html' "$KS_FILE" \
    "runtime-power guidance contains no superseded R580 point-release link"

# RPM Fusion's akmod package starts the initial build asynchronously from
# %posttrans and /usr/sbin/akmods serializes every builder on this lock.
# Successful initial installation must consume that native result, not compile
# the same kmod again. One exact install-or-rebuild attempt remains the
# integrity-repair fallback.
assert_grep_fixed 'build_marker=$(sudo mktemp /run/noid-nvidia-build.XXXXXX)' \
    "$TMPDIR/noid-nvidia-install.sh" \
    "freshness evidence starts before the native post-transaction build"
assert_grep_fixed 'manifest_preinstalled=0' "$TMPDIR/noid-nvidia-install.sh" \
    "repeat verification distinguishes a coherent preinstalled manifest"
assert_grep_fixed 'run_system_root /usr/bin/flock -w 900' \
    "$TMPDIR/noid-nvidia-install.sh" \
    "initial verification waits on the native akmods transaction lock"
assert_grep_fixed '/run/akmods/akmods.lock /usr/bin/true' \
    "$TMPDIR/noid-nvidia-install.sh" \
    "installer uses the exact vendor akmods lock path"
assert_grep_fixed "run_system_root /usr/bin/akmods \\" \
    "$TMPDIR/noid-nvidia-install.sh" \
    "the normal path uses non-forced branch-scoped akmods"
assert_grep_fixed 'Native/current NVIDIA module verification failed; starting one serialized repair build.' \
    "$TMPDIR/noid-nvidia-install.sh" \
    "one serialized install-or-rebuild attempt is explicitly limited to integrity repair"
assert_grep_fixed "run_system_root /usr/bin/akmods --rebuild --force \\" \
    "$TMPDIR/noid-nvidia-install.sh" \
    "the repair path retains branch-scoped forced rebuild capability"
assert_grep_fixed 'if [ "$manifest_preinstalled" -eq 1 ]; then' \
    "$TMPDIR/noid-nvidia-install.sh" \
    "an existing exact module set is verified without fabricated freshness"

marker_line=$(grep -nF 'build_marker=$(sudo mktemp /run/noid-nvidia-build.XXXXXX)' \
    "$TMPDIR/noid-nvidia-install.sh" | head -1 | cut -d: -f1 || true)
driver_line=$(grep -nF 'install -y "$AKMOD_PKG" "$CUDA_PKG"' \
    "$TMPDIR/noid-nvidia-install.sh" | head -1 | cut -d: -f1 || true)
plain_line=$(grep -nF "run_system_root /usr/bin/akmods \\" \
    "$TMPDIR/noid-nvidia-install.sh" | head -1 | cut -d: -f1 || true)
repair_line=$(grep -nF "run_system_root /usr/bin/akmods --rebuild --force \\" \
    "$TMPDIR/noid-nvidia-install.sh" | head -1 | cut -d: -f1 || true)
if [ -n "$marker_line" ] && [ -n "$driver_line" ] \
        && [ -n "$plain_line" ] && [ -n "$repair_line" ] \
        && [ "$marker_line" -lt "$driver_line" ] \
        && [ "$driver_line" -lt "$plain_line" ] \
        && [ "$plain_line" -lt "$repair_line" ]; then
    _pass "native install evidence precedes one normal verification and its repair fallback"
else
    _fail "NVIDIA install/build ordering can reintroduce a duplicate successful build"
fi

test_finish

#!/bin/bash
# M27 hardware abstraction smoke test: vendor performance ownership + explicit
# WoL/earlyoom/UDisks-USB/thermald policy with vendor-owned EEE
set -euo pipefail
. "$(dirname "$0")/lib.sh"

smoke_start "M27-hardware-tuning"

PROJECT_ROOT="$(project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/27-hardware-tuning.ks"

TMP_POST=$(mktemp --tmpdir smoke-m27-post-XXXXXX.sh)
smoke_register_temp_file "$TMP_POST"

extract_post "$KS_FILE" "$TMP_POST"

# M27 verifies M08's earlier systemd-oomd and intel_lpmd masks: earlyoom
# replaces the former, while tuned remains the single EPP policy writer in
# place of the latter. Seed both ordered-kickstart prerequisites in this
# otherwise isolated smoke.
install -d -m 0755 "$SANDBOX_DIR/etc/systemd/system"
ln -s /dev/null "$SANDBOX_DIR/etc/systemd/system/systemd-oomd.service"
ln -s /dev/null "$SANDBOX_DIR/etc/systemd/system/intel_lpmd.service"

# Offline `systemctl enable` writes unit symlinks inside the disposable rootfs
# without requiring PID 1. Keep the real commands: broad sed stubs previously
# corrupted `elif ... | tee; then` syntax and bypassed the module's own checks.

# M27's native net_setup_link verification needs an actual read-only sysfs
# object. The shared harness keeps this opt-in so other module smoke tests do
# not accidentally inspect source-host hardware.
SMOKE_BIND_SYS=1
export SMOKE_BIND_SYS
if run_in_sandbox "$TMP_POST"; then
    _pass "M27 %post executed without error"
else
    _fail "M27 %post returned non-zero"
fi

assert_in_sandbox '[ ! -e /etc/udev/rules.d/60-noid-iosched.rules ]' \
    "retired scheduler override absent"
assert_in_sandbox '[ -f /usr/lib/udev/rules.d/60-block-scheduler.rules ]' \
    "Fedora scheduler policy present"
assert_in_sandbox '[ ! -e /etc/tmpfiles.d/noid-hwp-dynamic-boost.conf ]' \
    "retired HWP override absent"
assert_in_sandbox '[ -f /etc/systemd/network/10-noid-no-wol.link ]' \
    "native Wake-on-LAN policy present"
assert_in_sandbox '[ ! -e /etc/systemd/network/10-noid-no-eee.link ]' \
    "retired global EEE override absent"
assert_in_sandbox '! grep -q "^\\[EnergyEfficientEthernet\\]$" /etc/systemd/network/10-noid-no-wol.link' \
    "EEE remains Fedora/driver-owned"
assert_in_sandbox '[ -f /etc/udev/rules.d/99-noid-external-storage-mount.rules ]' \
    "99-noid-external-storage-mount.rules"
assert_in_sandbox '[ ! -e /etc/udev/rules.d/99-noid-usb-sync-mount.rules ]' \
    "retired blanket-sync USB rule absent"
assert_in_sandbox '[ ! -e /etc/udev/rules.d/99-noid-usb-write-through.rules ]' \
    "unsafe USB cache-view rule absent"
assert_in_sandbox '[ -f /etc/default/earlyoom ]' "/etc/default/earlyoom"
assert_in_sandbox '[ -f /etc/tuned/profiles/noid-balanced/tuned.conf ]' \
    "neutral Balanced TuneD child profile"
assert_in_sandbox '[ -f /etc/tuned/profiles/noid-balanced-battery/tuned.conf ]' \
    "neutral battery TuneD child profile"
assert_in_sandbox 'grep -Fqx "balanced=noid-balanced" /etc/tuned/ppd.conf' \
    "GNOME Balanced mapping"
assert_in_sandbox 'grep -Fqx "[noid-balanced]" /etc/tuned/recommend.conf' \
    "neutral TuneD recommendation"
assert_in_sandbox '[ ! -e /etc/systemd/zram-generator.conf ] && [ ! -e /etc/systemd/zram-generator.conf.d/99-noid-privacy.conf ]' \
    "retired zram overrides absent"
assert_in_sandbox '[ -f /usr/lib/systemd/zram-generator.conf ]' \
    "Fedora zram policy present"
assert_in_sandbox 'grep -Fqx "CONFIG_CPU_FREQ_GOV_CONSERVATIVE=y" /usr/lib/modules/*/config' \
    "kernel-core payload proves the inherited TuneD module is built in"

# Content invariants
assert_in_sandbox 'grep -Fq "EARLYOOM_ARGS=\"-m 5 -s 5 -r 3600" /etc/default/earlyoom' \
    "earlyoom has thresholds plus the hourly health-report interval"
assert_in_sandbox 'grep -Fq "Isolated Web Co|Privileged Cont" /etc/default/earlyoom' \
    "earlyoom matches Firefox content-process comm truncation"

smoke_finish

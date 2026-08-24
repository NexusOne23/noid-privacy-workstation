#!/bin/bash
# 27-hardware-tuning-structural — M27 regression test
#
# Covers: Fedora/kernel performance ownership, native .link/udev parsing, NIC
# WoL-disable scope plus vendor-owned EEE, earlyoom, vendor zram policy, native
# UDisks USB/SD noexec + external-NTFS policy and the three-pass runtime gate.
# Would catch: a returned unbenchmarked scheduler/HWP/zram/EEE override,
# missing vendor ownership, wrong udev path or a missing/mis-scoped WoL .link.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/27-hardware-tuning.ks"
PERFORMANCE_DOC="$PROJECT_ROOT/docs/performance-profile.md"
EXTERNAL_STORAGE_DOC="$PROJECT_ROOT/docs/external-storage-policy.md"

test_start "27-hardware-tuning-structural"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

assert_file_exists "$KS_FILE"
assert_cmd_success "bash -n $KS_FILE" bash -n "$KS_FILE"
assert_grep_fixed 'kernel/firmware owns platform suspend mode' "$KS_FILE" \
    "M27 declares vendor ownership of platform sleep selection"
assert_not_grep_extended 'CHASSIS_EXTRA=|grubby .*--args=.*mem_sleep_default' "$KS_FILE" \
    "M27 contains no active chassis-wide suspend workaround"

# Performance ownership: no NoID Privacy scheduler, HWP, zram, network or VM tuning.
assert_grep_fixed 'rm -f /etc/udev/rules.d/60-noid-iosched.rules' "$KS_FILE" \
    "M27 removes the retired scheduler override"
assert_grep_fixed '/usr/lib/udev/rules.d/60-block-scheduler.rules' "$KS_FILE" \
    "M27 verifies Fedora's maintained scheduler policy"
assert_grep_fixed 'rm -f /etc/tmpfiles.d/noid-hwp-dynamic-boost.conf' "$KS_FILE" \
    "M27 removes the retired Intel-only boost override"
assert_grep_fixed 'zram-generator-defaults' "$KS_FILE" \
    "M27 installs Fedora's maintained zram activation policy"
assert_grep_fixed 'rm -f /etc/systemd/zram-generator.conf.d/99-noid-privacy.conf' \
    "$KS_FILE" "M27 removes the retired zram drop-in"
assert_not_grep_extended 'ATTR\{queue/scheduler\}=|hwp_dynamic_boost - - - - 1|compression-algorithm =|swap-priority =' \
    "$KS_FILE" "M27 contains no active scheduler/HWP/zram performance bet"
assert_not_grep_extended 'net\.core\.|net\.ipv4\.tcp_congestion_control|default_qdisc|vm\.swappiness|page-cluster|read_ahead_kb' \
    "$KS_FILE" "M27 contains no network, VM or read-ahead tuning"
assert_grep_fixed '/etc/tuned/profiles/noid-balanced/tuned.conf' "$KS_FILE" \
    "M27 installs the neutral Fedora Balanced child profile"
assert_grep_fixed '/etc/tuned/profiles/noid-balanced-battery/tuned.conf' "$KS_FILE" \
    "M27 installs the neutral battery child profile"
TUNED_PPD="$TMPDIR/tuned-ppd.conf"
extract_heredoc "$KS_FILE" NOID_TUNED_PPD_EOF "$TUNED_PPD" \
    || _fail "M27 TuneD PPD mapping extraction"
assert_grep_extended '^balanced=noid-balanced$' "$TUNED_PPD" \
    "GNOME Balanced maps to the neutral child profile"
assert_grep_extended '^balanced=noid-balanced-battery$' "$TUNED_PPD" \
    "battery Balanced maps to the neutral battery child"
assert_grep_fixed '[noid-balanced]' "$KS_FILE" \
    "TuneD recommends the neutral child without an unknown-profile warning"
assert_grep_fixed 'TUNED_VENDOR_BALANCED=/usr/lib/tuned/profiles/balanced/tuned.conf' \
    "$KS_FILE" "compose identifies the exact inherited Fedora profile"
assert_grep_fixed 'TUNED_VENDOR_BATTERY=/usr/lib/tuned/profiles/balanced-battery/tuned.conf' \
    "$KS_FILE" "compose identifies the battery profile in the inheritance chain"
assert_grep_fixed 'TUNED_VENDOR_PPD=/etc/tuned/ppd.conf' "$KS_FILE" \
    "compose identifies tuned-ppd's package-owned full-file mapping"
assert_grep_fixed 'NOID_TUNED_VENDOR_PPD_CONTRACT_EOF' "$KS_FILE" \
    "compose records the complete Fedora tuned-ppd semantic baseline"
assert_grep_fixed 'TUNED_VENDOR_PPD_PAYLOAD=249:9c0ef6b27a67b5dd3b4d02f521730b8d2570c33d5df198a97d12c10b91e48111' \
    "$KS_FILE" "compose pins tuned-ppd's exact Fedora payload bytes"
assert_grep_fixed 'rpm -qf --qf '\''%{NAME}'\'' "$TUNED_VENDOR_PPD"' \
    "$KS_FILE" "compose requires the tuned-ppd RPM owner before replacement"
assert_grep_fixed '[ "$tuned_vendor_ppd_payload" != "$TUNED_VENDOR_PPD_PAYLOAD" ]' \
    "$KS_FILE" "compose rejects a changed tuned-ppd package payload"
assert_grep_fixed '[ "$vendor_ppd_contract" != "$expected_noid_ppd_contract" ]' \
    "$KS_FILE" "compose is idempotent only for the exact current NoID Privacy mapping"
assert_grep_fixed '[ "$vendor_modules" != '\''cpufreq_conservative=+r'\'' ]' \
    "$KS_FILE" "compose rejects a broadened Fedora modules plug-in contract"
assert_grep_fixed 'CONFIG_CPU_FREQ_GOV_CONSERVATIVE=y' "$KS_FILE" \
    "compose proves every installed kernel has the governor built in"
assert_grep_fixed 'for kernel_config in /usr/lib/modules/*/config /boot/config-*; do' \
    "$KS_FILE" "compose accepts kernel-core payload evidence without scriptlets"
assert_grep_fixed 'No global `slab_debug` option is enabled.' "$PERFORMANCE_DOC" \
    "performance documentation does not invent a global SLUB-debug cost"
assert_grep_fixed '`slab_nomerge` deliberately gives up some allocator cache merging' \
    "$PERFORMANCE_DOC" \
    "performance documentation names the actual reviewed allocator trade-off"
assert_grep_fixed 'tuned-adm verify --ignore-missing' "$PERFORMANCE_DOC" \
    "performance documentation uses TuneD's native hardware-conditional verifier"
assert_grep_fixed '`no_turbo=0` control' "$PERFORMANCE_DOC" \
    "performance documentation explains Intel boost read-back asymmetry"
assert_file_exists "$EXTERNAL_STORAGE_DOC"
for source_url in \
    'https://storaged.org/doc/udisks2-api/latest/mount_options.html' \
    'https://storaged.org/doc/udisks2-api/latest/gdbus-org.freedesktop.UDisks2.Drive.html' \
    'https://man7.org/linux/man-pages/man8/mount.8.html' \
    'https://docs.kernel.org/5.10/block/queue-sysfs.html' \
    'https://src.fedoraproject.org/rpms/udisks2/raw/f44/f/udisks2.spec' \
    'https://learn.microsoft.com/en-us/windows/client-management/client-tools/change-default-removal-policy-external-storage-media' \
    'https://support.apple.com/guide/mac-help/connect-storage-devices-mac-mchl027f1d66/mac'; do
    assert_grep_fixed "$source_url" "$EXTERNAL_STORAGE_DOC" \
        "external-storage decision links primary source: $source_url"
done
assert_grep_fixed '| VFAT | 136.035 s / 0.47 MiB/s | 2.434 s / 26.29 MiB/s |' \
    "$EXTERNAL_STORAGE_DOC" "physical sync/no-sync evidence is retained"
assert_grep_fixed 'No generic Linux option can guarantee safety' \
    "$EXTERNAL_STORAGE_DOC" "storage documentation avoids yank-safety overclaim"
assert_grep_fixed '99-noid-usb-sync-mount.rules' "$EXTERNAL_STORAGE_DOC" \
    "storage decision records the retired blanket-sync artifact"
assert_grep_fixed '99-noid-usb-write-through.rules' "$EXTERNAL_STORAGE_DOC" \
    "storage decision records the retired cache-view artifact"

# NIC WoL-disable .link (STEP 1c) — PCI/USB bus-backed Ethernet only; EEE vendor-owned
assert_grep_fixed "/etc/systemd/network/10-noid-no-wol.link" "$KS_FILE"
assert_grep_fixed 'WOL_LINK_EOF' "$KS_FILE"
assert_grep_fixed 'rm -f /etc/systemd/network/10-noid-no-eee.link' "$KS_FILE" \
    "M27 retires its legacy global EEE override"
assert_not_grep_extended '^Enable=no$' "$KS_FILE" \
    "M27 does not globally force Energy-Efficient Ethernet off"
assert_grep_fixed 'Path=pci-* usb-*' "$KS_FILE"
assert_grep_fixed 'NamePolicy=keep kernel database onboard slot path' "$KS_FILE" \
    "early WoL link preserves Fedora predictable-interface naming"
assert_grep_fixed 'AlternativeNamesPolicy=database onboard slot path mac' "$KS_FILE" \
    "early WoL link preserves Fedora alternative names"
assert_grep_fixed 'MACAddressPolicy=persistent' "$KS_FILE" \
    "early WoL link preserves Fedora persistent MAC policy"
assert_grep_fixed 'WakeOnLan=off' "$KS_FILE" \
    "selected Ethernet .link disables every Wake-on-LAN mode"
assert_grep_fixed 'link_section_value "$WOL_LINK" Match Type' "$KS_FILE" \
    "compose verifies the exact Type match in its section"
assert_grep_fixed 'link_section_value "$WOL_LINK" Match Path' "$KS_FILE" \
    "compose verifies the exact Path match in its section"
assert_grep_fixed 'link_section_value "$WOL_LINK" Link WakeOnLan' "$KS_FILE" \
    "compose verifies the effective .link Wake-on-LAN value"
assert_grep_fixed '! grep -q '\''^\[EnergyEfficientEthernet\]$'\'' "$WOL_LINK"' \
    "$KS_FILE" "compose rejects a returned global EEE section"
assert_grep_fixed 'stat -Lc '\''%u:%g:%a:%h'\'' "$WOL_LINK"' "$KS_FILE" \
    "compose requires regular root-owned non-hardlinked WoL policy metadata"
assert_grep_fixed 'link_section_value "$FEDORA_VENDOR_LINK" Link "$naming_key"' \
    "$KS_FILE" "compose compares copied naming policy with Fedora's vendor link"
assert_grep_fixed 'udevadm test-builtin' "$KS_FILE" \
    "compose uses systemd's native net_setup_link parser"

# earlyoom config
assert_grep_fixed "/etc/default/earlyoom" "$KS_FILE"
assert_grep_fixed 'EARLYOOM_EOF' "$KS_FILE"
assert_grep_fixed 'EARLYOOM_ARGS="-m 5 -s 5 -r 3600' "$KS_FILE" \
    "earlyoom retains upstream's hourly report interval"
assert_grep_fixed 'Isolated Web Co|Privileged Cont' "$KS_FILE" \
    "earlyoom recognizes current truncated Firefox Fission process names"
assert_grep_fixed 'soft selection biases, not ordering guarantees or immunity' \
    "$KS_FILE" "earlyoom preference semantics are documented accurately"
assert_grep_fixed 'sudo cat /proc/"$(systemctl show earlyoom -p MainPID --value)"/cmdline' \
    "$KS_FILE" "shipped earlyoom guidance reads the running process argv"
assert_not_grep 'show earlyoom --property=ExecStart` shows the regex passed' \
    "$KS_FILE" "shipped earlyoom guidance does not inspect the unexpanded unit declaration"
assert_grep_fixed 'systemctl --root=/ enable earlyoom.service' "$KS_FILE" \
    "earlyoom enablement targets the offline installed root"
assert_grep_fixed 'oomd_state=$(systemctl --root=/ is-enabled systemd-oomd.service' \
    "$KS_FILE" "M27 verifies the effective offline systemd-oomd mask"
assert_grep_fixed '[ "$oomd_state" = masked ]' "$KS_FILE" \
    "missing M08 oomd masking is a compose failure"
assert_grep_fixed 'REQUIRED_PACKAGES=(' "$KS_FILE" \
    "M27 closes its explicit package postcondition"
for package in earlyoom tuned tuned-ppd thermald intel-lpmd \
        zram-generator-defaults udisks2; do
    assert_grep_fixed "    $package" "$KS_FILE" \
        "M27 required-package contract includes $package"
done
package_directives=$(
    awk '
        /^%packages[[:space:]]/ { inside = 1; next }
        inside && /^%end$/ { exit }
        inside && $0 !~ /^[[:space:]]*(#|$)/ { print $1 }
    ' "$KS_FILE"
)
required_package_array=$(
    awk '
        /^REQUIRED_PACKAGES=\($/ { inside = 1; next }
        inside && /^\)$/ { exit }
        inside && $0 !~ /^[[:space:]]*(#|$)/ {
            value = $0
            sub(/^[[:space:]]+/, "", value)
            print value
        }
    ' "$KS_FILE"
)
assert_eq "$package_directives" "$required_package_array" \
    "every positive M27 package directive has one exact compose postcondition"

extract_heredoc "$KS_FILE" "WOL_LINK_EOF" "$TMPDIR/10-noid-no-wol.link" \
    || _fail "WoL link extraction"
extract_heredoc "$KS_FILE" "EXTERNAL_STORAGE_EOF" \
    "$TMPDIR/99-noid-external-storage-mount.rules" || \
    _fail "UDisks external-storage rules extraction"
extract_heredoc "$KS_FILE" "NOID_TUNED_BALANCED_EOF" \
    "$TMPDIR/noid-balanced.conf" || _fail "Balanced TuneD profile extraction"
extract_heredoc "$KS_FILE" "NOID_TUNED_BATTERY_EOF" \
    "$TMPDIR/noid-balanced-battery.conf" || \
    _fail "Balanced-battery TuneD profile extraction"
extract_heredoc "$KS_FILE" "NOID_TUNED_PPD_EOF" \
    "$TMPDIR/ppd.conf" || _fail "TuneD PPD mapping extraction"
extract_heredoc "$KS_FILE" "NOID_TUNED_RECOMMEND_EOF" \
    "$TMPDIR/recommend.conf" || _fail "TuneD recommendation extraction"
assert_grep_fixed 'include=balanced' "$TMPDIR/noid-balanced.conf" \
    "Balanced child inherits Fedora Balanced"
assert_grep_fixed 'include=balanced-battery' \
    "$TMPDIR/noid-balanced-battery.conf" \
    "battery child inherits Fedora Balanced Battery"
assert_grep_fixed 'enabled=0' "$TMPDIR/noid-balanced.conf" \
    "Balanced child disables only the inherited modules instance"
assert_grep_fixed 'enabled=0' "$TMPDIR/noid-balanced-battery.conf" \
    "battery child disables only the inherited modules instance"
assert_not_grep 'cpufreq_conservative=+r' "$TMPDIR/noid-balanced.conf" \
    "Balanced child does not reproduce the invalid built-in-governor reload"
assert_not_grep 'cpufreq_conservative=+r' "$TMPDIR/noid-balanced-battery.conf" \
    "battery child does not reproduce the invalid built-in-governor reload"
assert_grep_fixed 'default=balanced' "$TMPDIR/ppd.conf" \
    "PPD default remains the public Balanced label"
assert_grep_fixed 'power-saver=powersave' "$TMPDIR/ppd.conf" \
    "Power Saver keeps Fedora's maintained mapping"
assert_grep_fixed 'performance=throughput-performance' "$TMPDIR/ppd.conf" \
    "Performance keeps Fedora's maintained mapping"
assert_grep_fixed '[noid-balanced]' "$TMPDIR/recommend.conf" \
    "TuneD recommendation resolves directly to the child profile"
assert_grep_fixed \
    'ENV{ID_FS_USAGE}=="filesystem", SUBSYSTEMS=="usb", ENV{UDISKS_MOUNT_OPTIONS_DEFAULTS}="noexec"' \
    "$TMPDIR/99-noid-external-storage-mount.rules" \
    "all USB-backed filesystems receive noexec"
assert_grep_fixed \
    'ENV{ID_FS_USAGE}=="filesystem", ENV{ID_DRIVE_FLASH_SD}=="1", ENV{UDISKS_MOUNT_OPTIONS_DEFAULTS}="noexec"' \
    "$TMPDIR/99-noid-external-storage-mount.rules" \
    "recognized SD readers receive noexec"
assert_grep_fixed \
    'ENV{ID_FS_USAGE}=="filesystem", ENV{ID_DRIVE_MEDIA_FLASH_SD}=="1", ENV{UDISKS_MOUNT_OPTIONS_DEFAULTS}="noexec"' \
    "$TMPDIR/99-noid-external-storage-mount.rules" \
    "native SD/SD-combo media receive noexec"
for ntfs_scope in \
    'ENV{ID_FS_USAGE}=="filesystem", ENV{ID_FS_TYPE}=="ntfs", SUBSYSTEMS=="usb", ENV{UDISKS_MOUNT_OPTIONS_NTFS_DRIVERS}="ntfs3,ntfs"' \
    'ENV{ID_FS_USAGE}=="filesystem", ENV{ID_FS_TYPE}=="ntfs", ENV{ID_DRIVE_FLASH_SD}=="1", ENV{UDISKS_MOUNT_OPTIONS_NTFS_DRIVERS}="ntfs3,ntfs"' \
    'ENV{ID_FS_USAGE}=="filesystem", ENV{ID_FS_TYPE}=="ntfs", ENV{ID_DRIVE_MEDIA_FLASH_SD}=="1", ENV{UDISKS_MOUNT_OPTIONS_NTFS_DRIVERS}="ntfs3,ntfs"'; do
    assert_grep_fixed "$ntfs_scope" \
        "$TMPDIR/99-noid-external-storage-mount.rules" \
        "external NTFS receives ntfs3-first driver order"
done
assert_not_grep 'ID_DRIVE_FLASH_MMC' \
    "$TMPDIR/99-noid-external-storage-mount.rules" \
    "internal eMMC is not classified as removable SD media"
assert_not_grep_extended '^[^#].*UDISKS_MOUNT_OPTIONS_DEFAULTS.*sync' \
    "$TMPDIR/99-noid-external-storage-mount.rules" \
    "blanket sync is absent from the active removable-media policy"
assert_not_grep_extended '^[^#].*bdi/(max_bytes|min_bytes|strict_limit)' \
    "$TMPDIR/99-noid-external-storage-mount.rules" \
    "the rejected whole-disk BDI throttle is absent"

# Native udev rule parser: the sole M27 rule succeeds, while an invalid key is
# rejected. Scheduler policy is deliberately vendor-owned and has no M27 rule.
mkdir -p "$TMPDIR/root/etc/udev/rules.d"
cp "$TMPDIR/99-noid-external-storage-mount.rules" \
    "$TMPDIR/root/etc/udev/rules.d/99-noid-external-storage-mount.rules"
assert_cmd_success "native udev parser accepts UDisks external-storage rule" \
    udevadm verify --no-style --root="$TMPDIR/root" \
    /etc/udev/rules.d/99-noid-external-storage-mount.rules
printf '%s\n' 'ACTION=="add", BOGUS{queue/scheduler}="none"' \
    > "$TMPDIR/root/etc/udev/rules.d/60-invalid.rules"
assert_cmd_failure "native udev parser rejects an invalid rule key" \
    udevadm verify --no-style --root="$TMPDIR/root" \
    /etc/udev/rules.d/60-invalid.rules

# systemd has no standalone `.link verify` verb. Its documented native parser
# is the net_setup_link udev builtin. Run it against loopback in an isolated
# mount/PID namespace: the file is parsed, but its Type=ether/Path= match does
# not apply to or mutate the host interface.
mkdir -p "$TMPDIR/link-root/etc/systemd/network"
cp "$TMPDIR/10-noid-no-wol.link" \
    "$TMPDIR/link-root/etc/systemd/network/10-noid-no-wol.link"
link_parse_rc=0
link_parse=$(bwrap --unshare-all --share-net --die-with-parent \
    --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib \
    --symlink usr/lib64 /lib64 --symlink usr/sbin /sbin --ro-bind /sys /sys \
    --proc /proc --dir /run --ro-bind "$TMPDIR/link-root/etc" /etc \
    --setenv SYSTEMD_LOG_LEVEL debug /usr/bin/udevadm test-builtin \
    net_setup_link /sys/class/net/lo 2>&1) || link_parse_rc=$?
assert_eq "0" "$link_parse_rc" "native net_setup_link parser exits successfully"
if grep -Fq 'Parsed configuration file "/etc/systemd/network/10-noid-no-wol.link"' \
        <<<"$link_parse" && \
   ! grep -E '/etc/systemd/network/10-noid-no-wol\.link:.*(Failed|Invalid|Unknown|ignoring)' \
        <<<"$link_parse" >/dev/null; then
    _pass "native net_setup_link parser accepts canonical WoL policy"
else
    _fail "native net_setup_link parser did not accept canonical WoL policy"
fi

# Fedora/upstream runtime probing owns hardware applicability. The module must
# apply thermald's preset and leave intel_lpmd.service under the M08 mask
# (single-EPP-writer policy; the package itself ships).
assert_grep_fixed 'thermald' "$KS_FILE" "M27 explicitly installs thermald"
assert_grep_fixed 'intel-lpmd' "$KS_FILE" "M27 explicitly installs intel-lpmd"
assert_grep_fixed 'systemctl --root=/ unmask thermald.service' "$KS_FILE" \
    "M27 requires the Fedora service to remain unmasked in the offline target"
assert_grep_fixed 'systemctl --root=/ preset thermald.service' "$KS_FILE" \
    "M27 applies Fedora preset ownership through the offline target root"
assert_grep_fixed 'thermald_state=$(systemctl --root=/ is-enabled thermald.service' "$KS_FILE" \
    "M27 verifies hardware-service enablement without contacting PID 1"
assert_grep_fixed 'if [ "$thermald_state" != enabled ]; then' "$KS_FILE" \
    "M27 requires the effective Fedora thermald preset state"
assert_not_grep 'systemctl daemon-reload' "$KS_FILE" \
    "M27 does not contact a nonexistent build-chroot system manager"
assert_not_grep 'for unit in thermald.service; do' "$KS_FILE" \
    "M27 has no misleading one-element thermald loop"
assert_not_grep 'systemctl --root=/ unmask "intel_lpmd' "$KS_FILE" \
    "M27 never unmasks the M08-masked intel_lpmd unit"
assert_grep_fixed 'lpmd_state=$(systemctl --root=/ is-enabled intel_lpmd.service' "$KS_FILE" \
    "M27 cross-checks the M08 intel_lpmd mask"
assert_grep_fixed 'blocklist_paths' "$KS_FILE" \
    "M27 documents thermald's actual upstream DYTC mechanism"
assert_grep_fixed 'adaptive compatibility path exits successfully' "$KS_FILE" \
    "M27 documents the clean inactive hardware-N/A result"
assert_grep_fixed 'ConditionVirtualization=no' "$KS_FILE" \
    "M27 documents the vendor virtualization applicability condition"
# Native UDisks USB/SD noexec mounts; blanket sync and cache/BDI substitutes
# are retired, and NTFS driver selection stays external-media scoped.
assert_grep_fixed "/etc/udev/rules.d/99-noid-external-storage-mount.rules" "$KS_FILE"
assert_grep_fixed 'EXTERNAL_STORAGE_EOF' "$KS_FILE"
assert_grep_fixed 'UDISKS_MOUNT_OPTIONS_DEFAULTS}="noexec"' "$KS_FILE" \
    "USB/SD storage receives the supported UDisks noexec default"
assert_grep_fixed 'UDISKS_MOUNT_OPTIONS_NTFS_DRIVERS}="ntfs3,ntfs"' "$KS_FILE" \
    "external NTFS prefers ntfs3 with ntfs-3g fallback"
assert_grep_fixed 'rm -f /etc/udev/rules.d/99-noid-usb-sync-mount.rules' \
    "$KS_FILE" "M27 retires the blanket-sync rule"
assert_grep_fixed 'rm -f /etc/udev/rules.d/99-noid-usb-write-through.rules' \
    "$KS_FILE" "M27 retires the unsafe kernel cache-view rule"
assert_not_grep '/sys/block/%k/queue/write_cache' "$KS_FILE" \
    "M27 never writes the kernel device-cache sysfs path"
assert_not_grep_extended 'ATTR\{bdi/|ATTRS\{bdi/' "$KS_FILE" \
    "M27 never publishes the rejected whole-disk BDI workaround"
assert_grep_fixed 'udisks2' "$KS_FILE" \
    "M27 explicitly retains the maintained dynamic-mount backend"

# SELinux relabel
assert_grep_fixed 'restorecon' "$KS_FILE"
assert_grep_fixed '[FAIL] restorecon or matchpathcon is unavailable' "$KS_FILE" \
    "M27 fails closed when a SELinux publication tool is missing"
assert_not_grep_extended 'restorecon .*2>/dev/null.*\|\| true|restorecon .*\|\| true' \
    "$KS_FILE" "M27 does not report successful labeling after a restorecon failure"
m27_label_block=$(sed -n '/^M27_LABEL_PATHS=(/,/^)/p' "$KS_FILE")
for tuned_label_path in \
    /etc/tuned/profiles/noid-balanced \
    /etc/tuned/profiles/noid-balanced-battery; do
    assert_grep_fixed "$tuned_label_path" <(printf '%s\n' "$m27_label_block") \
        "M27 relabels its created TuneD directory: $tuned_label_path"
done
assert_not_grep 'thermald' \
    <(printf '%s\n' "$m27_label_block") \
    "M27 has no custom thermald artifact to relabel"
assert_grep_fixed 'for m27_label_path in "${M27_LABEL_PATHS[@]}"; do' \
    "$KS_FILE" "M27 applies one closed SELinux path inventory"
assert_grep_fixed 'restorecon -F "$m27_label_path"' "$KS_FILE" \
    "M27 force-restores every declared SELinux context"
assert_grep_fixed 'matchpathcon -V "$m27_label_path"' "$KS_FILE" \
    "M27 verifies every restored context against policy"

# Permissions set
assert_grep_fixed 'chmod 644 /etc/default/earlyoom' "$KS_FILE"
assert_grep_fixed 'for unit in tuned.service tuned-ppd.service; do' "$KS_FILE" \
    "compose verifies both power-profile service enablement postconditions"
assert_grep_fixed 'TuneD Balanced child profiles + GNOME PPD mappings exact' \
    "$KS_FILE" "compose verifies the full TuneD profile/mapping contract"

RUNTIME_GATE="$PROJECT_ROOT/tests/pre-ship/20-hardware-tuning-runtime.sh"
assert_file_executable "$RUNTIME_GATE" \
    "M27 three-pass behavior gate is executable"
assert_cmd_failure "M27 runtime gate refuses an absent pass identity" \
    bash "$RUNTIME_GATE"
assert_cmd_failure "M27 runtime gate refuses an unknown pass identity" \
    bash "$RUNTIME_GATE" source-host
assert_not_grep 'echo .*SKIP' "$RUNTIME_GATE" \
    "M27 runtime gate contains no success-producing skip path"
assert_grep_fixed 'live|fresh-install|reboot) ;;' "$RUNTIME_GATE" \
    "M27 runtime gate accepts the exact three lifecycle identities"
assert_grep_fixed 'ID_NET_LINK_FILE=/etc/systemd/network/10-noid-no-wol.link' \
    "$RUNTIME_GATE" "runtime gate proves the effective .link winner"
assert_grep_fixed 'wlan|wwan) continue' "$RUNTIME_GATE" \
    "runtime gate mirrors systemd.link Type=ether instead of treating WLAN as wired"
assert_grep_fixed 'link_section_value "$FEDORA_VENDOR_LINK" Link "$naming_key"' \
    "$RUNTIME_GATE" "runtime gate rejects WoL-link naming-policy drift"
assert_grep_fixed 'require_root_file()' "$RUNTIME_GATE" \
    "runtime gate has an exact owner/mode/hardlink verifier"
assert_grep_fixed 'require_equal "$canonical" "$installed"' "$RUNTIME_GATE" \
    "runtime gate binds every installed M27 policy to its canonical source"
for runtime_payload in \
        WOL_LINK_EOF EARLYOOM_EOF NOID_TUNED_BALANCED_EOF \
        NOID_TUNED_BATTERY_EOF NOID_TUNED_PPD_EOF \
        NOID_TUNED_RECOMMEND_EOF EXTERNAL_STORAGE_EOF; do
    assert_grep_fixed "$runtime_payload" "$RUNTIME_GATE" \
        "runtime gate extracts canonical M27 payload: $runtime_payload"
done
extract_heredoc "$RUNTIME_GATE" "EXTRACT_M27_PYEOF" \
    "$TMPDIR/m27-runtime-extract.py" || _fail "runtime M27 extractor extraction"
mkdir -p "$TMPDIR/m27-runtime-payloads"
assert_cmd_success "runtime gate extractor accepts the current M27 source" \
    python3 -I "$TMPDIR/m27-runtime-extract.py" "$KS_FILE" \
        "$TMPDIR/m27-runtime-payloads"
assert_grep_fixed 'THERMALD_VENDOR_UNIT=/usr/lib/systemd/system/thermald.service' \
    "$RUNTIME_GATE" "runtime gate authenticates Fedora's thermald unit"
assert_grep_fixed 'sha256sum -- "$path"' "$RUNTIME_GATE" \
    "runtime gate authenticates only the vendor RPM file it consumes"
assert_grep_fixed 'kvm|qemu)' "$RUNTIME_GATE" \
    "destructive fixture probes are confined to the disposable QEMU/KVM boundary"
assert_not_grep 'exec sudo' "$RUNTIME_GATE" \
    "runtime gate never re-executes a mutable relative script as root"
assert_grep_fixed 'FIXTURE_BYTES=134217728' "$RUNTIME_GATE" \
    "runtime gate requires the documented 128-MiB fixture size"
assert_grep_fixed 'USB_MATRIX_DISK_BYTES=805306368' "$RUNTIME_GATE" \
    "runtime gate requires the documented 768-MiB matrix disk"
assert_grep_fixed 'fixture label is not unique' "$RUNTIME_GATE" \
    "runtime gate rejects ambiguous destructive fixture labels"
assert_grep_fixed 'empty, malformed or reused filesystem UUID' "$RUNTIME_GATE" \
    "runtime gate requires distinct cross-filesystem fixture identities"
assert_grep_fixed 'must be unmounted before the release probe' "$RUNTIME_GATE" \
    "runtime gate cannot adopt an existing user mount"
assert_grep_fixed 'os.O_EXCL | os.O_NOFOLLOW' "$RUNTIME_GATE" \
    "runtime gate creates its probe without overwriting media content"
assert_grep_fixed 'cleanup_fixture_state' "$RUNTIME_GATE" \
    "runtime gate has signal-safe mount and probe cleanup"
assert_grep_fixed 'expected_target=/run/media/root/$label' "$RUNTIME_GATE" \
    "runtime gate confines writes to the exact UDisks root fixture mount"
assert_grep_fixed 'cmdline_key_count()' "$RUNTIME_GATE" \
    "runtime gate parses kernel arguments as exact keys"
assert_grep_fixed 'live pass requires exactly one rd.live.image parameter' \
    "$RUNTIME_GATE" "live identity cannot pass on a substring or duplicate key"
assert_not_grep "grep -q 'rd.live.image' /proc/cmdline" "$RUNTIME_GATE" \
    "runtime gate does not confuse a kernel-argument substring with the key"

RUNTIME_PROBE_CREATOR="$TMPDIR/runtime-probe-creator.py"
runtime_probe_extract_rc=0
awk '
    /<<'\''CREATE_PROBE_PYEOF'\''/ {
        if (seen++) exit 2
        capture=1
        next
    }
    capture && $0 == "CREATE_PROBE_PYEOF" {
        capture=0
        closed++
        next
    }
    capture { print }
    END {
        if (seen != 1 || closed != 1 || capture) exit 3
    }
' "$RUNTIME_GATE" >"$RUNTIME_PROBE_CREATOR" || runtime_probe_extract_rc=$?
assert_eq 0 "$runtime_probe_extract_rc" \
    "runtime gate exclusive probe creator extracts from unique markers"
RUNTIME_PROBE="$TMPDIR/noexec-probe"
assert_cmd_success "exclusive noexec probe creator publishes a new file" \
    python3 -I "$RUNTIME_PROBE_CREATOR" "$RUNTIME_PROBE"
assert_eq $'#!/bin/sh\nprintf noid-interpreter-ok' \
    "$(cat "$RUNTIME_PROBE")" \
    "exclusive noexec probe creator publishes exact bytes"
runtime_probe_before=$(sha256sum "$RUNTIME_PROBE")
assert_cmd_failure "exclusive noexec probe creator refuses an existing path" \
    python3 -I "$RUNTIME_PROBE_CREATOR" "$RUNTIME_PROBE"
assert_eq "$runtime_probe_before" "$(sha256sum "$RUNTIME_PROBE")" \
    "exclusive probe refusal preserves existing bytes"
assert_grep_fixed 'Wake-on:[[:space:]]+d' "$RUNTIME_GATE" \
    "runtime gate requires the driver-visible Wake-on-LAN disabled state"
assert_grep_fixed 'wol_state="unsupported (N/A)"' "$RUNTIME_GATE" \
    "runtime gate records absent driver WoL operations as hardware N/A"
assert_grep_fixed 'exposes Wake-on-LAN capability without a current state' \
    "$RUNTIME_GATE" "runtime gate rejects incomplete driver-visible WoL evidence"
assert_grep_fixed 'earlyoom_pid=$(systemctl show earlyoom.service --property=MainPID --value)' \
    "$RUNTIME_GATE" "runtime gate resolves the real earlyoom process"
assert_grep_fixed '"cmdline").read_bytes()' "$RUNTIME_GATE" \
    "runtime gate inspects the real earlyoom argv"
for matrix_fixture in NOID_VFAT:vfat NOID_EXFAT:exfat NOID_NTFS:ntfs \
        NOID_EXT4:ext4; do
    assert_grep_fixed "$matrix_fixture" "$RUNTIME_GATE" \
        "runtime gate covers USB filesystem matrix member $matrix_fixture"
done
assert_grep_fixed 'USB matrix disk does not expose removable=1' "$RUNTIME_GATE" \
    "runtime gate covers the USB-stick removable class"
assert_grep_fixed 'NOID_FIXED' "$RUNTIME_GATE" \
    "runtime gate covers USB SSDs that report removable=0"
assert_grep_fixed 'NOID_SD' "$RUNTIME_GATE" \
    "runtime gate covers media behind a native SD host"
assert_grep_fixed '*/mmc_host/*' "$RUNTIME_GATE" \
    "SD runtime fixture must traverse the native MMC/SD host path"
assert_grep_fixed 'ID_DRIVE_FLASH_MMC=1' "$RUNTIME_GATE" \
    "runtime gate rejects internal MMC/eMMC classification"
assert_grep_fixed 'UDISKS_MOUNT_OPTIONS_DEFAULTS=noexec' "$RUNTIME_GATE" \
    "runtime gate proves the effective UDisks mount override"
assert_grep_fixed 'UDISKS_MOUNT_OPTIONS_NTFS_DRIVERS=ntfs3,ntfs' \
    "$RUNTIME_GATE" "runtime gate proves external NTFS driver selection"
assert_grep_fixed 'mounted with retired blanket sync' "$RUNTIME_GATE" \
    "runtime gate rejects the retired sync default at the actual mount"
assert_grep_fixed "filesystem-specific vfat flush default" "$RUNTIME_GATE" \
    "runtime gate proves UDisks filesystem defaults still merge"
assert_grep_fixed 'direct execution unexpectedly succeeded' "$RUNTIME_GATE" \
    "runtime gate rejects executable removable-media mounts"
assert_grep_fixed '.noid-noexec-probe.com' "$RUNTIME_GATE" \
    "vfat noexec probe retains execute bits under the UDisks showexec default"
assert_grep_fixed 'interpreter read failed' "$RUNTIME_GATE" \
    "runtime gate documents and tests the noexec interpreter boundary"
assert_grep_fixed 'verify_explicit_exec_override "$label" "$dev"' \
    "$RUNTIME_GATE" "runtime gate proves the exec override on every USB filesystem"
assert_grep_fixed 'findmnt commonly omits it' "$RUNTIME_GATE" \
    "runtime gate does not require a non-canonical literal exec option"
assert_grep_fixed 'udisksctl power-off' "$RUNTIME_GATE" \
    "runtime gate completes the supported safe-removal path"
assert_grep_fixed 'SD clean-unmount complete' "$RUNTIME_GATE" \
    "runtime gate completes the supported SD removal boundary"
assert_grep_fixed 'current_cache_view()' "$RUNTIME_GATE" \
    "runtime gate reads the real whole-device kernel cache view"
assert_grep_fixed 'kernel cache view changed' "$RUNTIME_GATE" \
    "runtime gate rejects queue write-cache or FUA mutation"
assert_grep_fixed 'prior marker hash differs' "$RUNTIME_GATE" \
    "runtime gate carries cold data-integrity evidence across lifecycle passes"
assert_grep_fixed '/usr/lib/udev/rules.d/60-block-scheduler.rules' \
    "$RUNTIME_GATE" "runtime gate proves Fedora scheduler ownership"
assert_grep_fixed 'zram-generator-defaults' "$RUNTIME_GATE" \
    "runtime gate proves Fedora zram ownership"
assert_grep_fixed 'net.hadess.PowerProfiles ActiveProfile' "$RUNTIME_GATE" \
    "runtime gate reads GNOME's effective public Power Mode"
assert_grep_fixed 'noid-balanced-battery' "$RUNTIME_GATE" \
    "runtime gate accepts the battery-specific Balanced child"
assert_grep_fixed 'tuned-adm verify --ignore-missing' "$RUNTIME_GATE" \
    "runtime gate verifies exposed TuneD settings and skips only hardware-N/A nodes"
assert_grep_fixed 'TUNED_VENDOR_BALANCED=/usr/lib/tuned/profiles/balanced/tuned.conf' \
    "$RUNTIME_GATE" "runtime gate verifies the inherited vendor profile"
assert_grep_fixed 'TUNED_VENDOR_BATTERY=/usr/lib/tuned/profiles/balanced-battery/tuned.conf' \
    "$RUNTIME_GATE" "runtime gate verifies the battery inheritance layer"
assert_grep_fixed 'CONFIG_CPU_FREQ_GOV_CONSERVATIVE=y' "$RUNTIME_GATE" \
    "runtime gate proves the running kernel has the governor built in"
assert_not_grep_extended 'expected=mq-deadline|expected=bfq|expected=none|does not use zstd|expected 100' \
    "$RUNTIME_GATE" "runtime gate observes rather than dictates hardware tuning"
assert_grep_fixed 'Lenovo DYTC lap/desk sensor present' "$RUNTIME_GATE" \
    "runtime gate records DYTC as inventory only"
assert_grep_fixed '[ "$thermald_state" = enabled ]' "$RUNTIME_GATE" \
    "runtime gate requires Fedora-enabled thermald"
assert_grep_fixed 'thermald_result=$(systemctl show thermald.service --property=Result --value)' \
    "$RUNTIME_GATE" "runtime gate records thermald's effective systemd result"
assert_grep_fixed 'thermald_exec_status=$(systemctl show thermald.service --property=ExecMainStatus --value)' \
    "$RUNTIME_GATE" "runtime gate records thermald's effective exit status"
assert_grep_fixed '[ "$thermald_result" = success ]' "$RUNTIME_GATE" \
    "runtime gate accepts only Fedora/upstream's successful service result"
assert_grep_fixed '[ "$thermald_failed_state" != failed ]' "$RUNTIME_GATE" \
    "runtime gate rejects an abnormal thermald failure path"
assert_grep_fixed '(Fedora/upstream applicability)' "$RUNTIME_GATE" \
    "runtime evidence does not mislabel inactive thermald as active protection"
assert_grep_fixed '[ "$lpmd_state" = masked ]' "$RUNTIME_GATE" \
    "runtime gate requires the M08 intel_lpmd mask to hold"

test_finish

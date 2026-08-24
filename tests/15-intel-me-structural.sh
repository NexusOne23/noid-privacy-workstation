#!/bin/bash
# 15-intel-me-structural — verify Module 15 Intel ME / MEI mitigation
#
# Checks (full Kicksecure-consensus per security-misc #239):
#   - modprobe.d file has NO default MEI sub-module blacklist (regression
#     guard: mei_hdcp/mei_pxp/mei_wdt all LOAD by default, opt-in block only
#     via noid-mei-restore-submodules --block)
#   - mei + mei_me are NOT blacklisted (required for fwupd BootGuard)
#   - udev rule + helper block/unbind the exact KT/SOL PCI ID set
#   - Dracut conf ships modprobe.d plus KT/SOL enforcement into initramfs
#   - early boot service repeats and verifies enforcement after udev trigger
#   - complete vendor-specific mei-status.txt producer/consumer contract
#   - AMD PSP documentation present (hardware-layer)

set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/15-intel-me-mitigation.ks"
AIDE_SECURE_MANIFEST="$PROJECT_ROOT/manifests/aide-secure-paths.tsv"

test_start "15-intel-me-structural"

assert_file_exists "$KS_FILE"
assert_file_exists "$AIDE_SECURE_MANIFEST"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

# --- CPU vendor detection (Step 0) ------------------------------------------
# M15 detects Intel/AMD/unknown for status and verification. Mitigation files
# are deliberately always shipped so build-host vendor cannot weaken targets.
assert_grep_fixed 'CPU_VENDOR="unknown"' "$KS_FILE"
assert_grep_fixed 'GenuineIntel' "$KS_FILE"
assert_grep_extended 'AuthenticAMD\|HygonGenuine' "$KS_FILE"
assert_grep_fixed '/proc/cpuinfo' "$KS_FILE"
assert_grep_fixed '/var/lib/noid-privacy/cpu-vendor' "$KS_FILE"

# Intel-only runtime/status branches remain present.
assert_grep_extended 'if \[ "\$CPU_VENDOR" = "intel" \]; then' "$KS_FILE" \
    "Intel runtime/status branch present"

# AMD + unknown branch of Step 5 status file
assert_grep_fixed 'CPU_VENDOR=amd' "$KS_FILE"
assert_eq 3 "$(grep -c '^STATUS_LIFECYCLE=build-time-placeholder$' "$KS_FILE")" \
    "all three build-vendor records carry the explicit staged lifecycle"
assert_grep_fixed 'PSP_STATE=runtime-check-required' "$KS_FILE"
assert_grep_fixed 'CCP_POLICY=not-blacklisted' "$KS_FILE"
assert_grep_fixed 'PSP_FWUPD_VISIBILITY=runtime-check-required' "$KS_FILE"

# AMD verify branch — always-ship pattern (Intel mitigation files present
# but inert on AMD silicon). Refactored from old "skipped/absent"
# wording to "always-shipped, inert on $CPU_VENDOR" — semantic identical.
assert_grep_fixed 'always-shipped, inert on $CPU_VENDOR' "$KS_FILE"
assert_grep_fixed 'AMD PSP hardware-layer doc shipped' "$KS_FILE"

# ccp module NOT blacklisted on AMD
assert_grep_fixed 'ccp module NOT blacklisted' "$KS_FILE"
assert_grep_fixed 'does not stop ASP firmware' "$KS_FILE"
assert_grep_fixed 'firmware TPM is not universally controlled by `ccp`' "$KS_FILE"

extract_heredoc "$KS_FILE" "MODPROBE_EOF" "$TMPDIR/mei-submodules.conf" || _fail "modprobe.d extraction"
extract_heredoc "$KS_FILE" "KT_ENFORCE_EOF" "$TMPDIR/noid-mei-kt-enforce" || _fail "KT/SOL helper extraction"
extract_heredoc "$KS_FILE" "UDEV_EOF" "$TMPDIR/99-noid-mei-kt-block.rules" || _fail "KT/SOL udev extraction"
extract_heredoc "$KS_FILE" "KT_SERVICE_EOF" "$TMPDIR/noid-mei-kt-enforce.service" || _fail "KT/SOL service extraction"
extract_heredoc "$KS_FILE" "DRACUT_EOF" "$TMPDIR/noid-mei-blacklist.conf" || _fail "dracut extraction"
extract_heredoc "$KS_FILE" "DOC_EOF" "$TMPDIR/intel-me-hardware-layer.md" || _fail "Intel ME doc extraction"
extract_heredoc "$KS_FILE" "AMD_DOC_EOF" "$TMPDIR/amd-psp.md" || _fail "AMD doc extraction"
extract_heredoc "$KS_FILE" "MEI_RESTORE_EOF" "$TMPDIR/noid-mei-restore-submodules" || _fail "MEI toggle extraction"
extract_heredoc "$KS_FILE" "MEI_LOCKDOWN_EOF" "$TMPDIR/noid-mei-lockdown" || _fail "MEI lockdown extraction"
extract_heredoc "$KS_FILE" "CPU_DETECT_EOF" "$TMPDIR/noid-cpu-vendor-detect" || _fail "CPU detector extraction"
extract_heredoc "$KS_FILE" "POLICY_SHA_EOF" "$TMPDIR/noid-platform-policy-sha256" || _fail "policy hash helper extraction"
extract_heredoc "$KS_FILE" "CPU_DETECT_SVC_EOF" "$TMPDIR/noid-cpu-vendor-detect.service" || _fail "CPU detector service extraction"

# --- regression guard: NONE of mei_hdcp/mei_pxp/mei_wdt blacklisted ----
# Full Kicksecure-consensus per security-misc Issue #239:
# NO MEI sub-module is default-blacklisted. All three are opt-in only via
# `noid-mei-restore-submodules --block`. This regression guard catches
# accidental re-blacklist of any of them in the default heredoc.
for mod in mei_hdcp mei_pxp mei_wdt; do
    if grep -qE "^blacklist ${mod}$" "$TMPDIR/mei-submodules.conf"; then
        _fail "regression: ${mod} MUST NOT be in default blacklist (opt-in only via --block)"
    else
        _pass "${mod} not in default blacklist (Kicksecure-consensus)"
    fi
    if grep -qE "^install ${mod} /bin/false$" "$TMPDIR/mei-submodules.conf"; then
        _fail "regression: ${mod} install /bin/false MUST NOT be in default"
    else
        _pass "${mod} install /bin/false not in default (correct)"
    fi
done

# --- mei + mei_me NOT blacklisted (required for BootGuard) ------------------
# Must be explicitly checked: blacklist line MUST NOT exist for these
if grep -qE '^blacklist mei$' "$TMPDIR/mei-submodules.conf"; then
    _fail "mei module MUST NOT be blacklisted (preserves compatible fwupd inspection)"
else
    _pass "mei module not blacklisted (compatible hardware may bind)"
fi
if grep -qE '^blacklist mei_me$' "$TMPDIR/mei-submodules.conf"; then
    _fail "mei_me module MUST NOT be blacklisted (preserves compatible fwupd inspection)"
else
    _pass "mei_me module not blacklisted (compatible hardware may bind)"
fi

# --- KT/SOL udev rule: 6th-17th gen Intel PCI IDs (27 total) ---------------
# pci.ids-verified, 6th-11th gen (mainstream vPro, 2015-2022)
assert_grep_extended '0xa13d' "$KS_FILE" "6th gen Skylake-H/S (100/C230) KT PCI ID 0xa13d"
assert_grep_extended '0xa2bd' "$KS_FILE" "7th gen Kaby Lake (200 Series) KT PCI ID 0xa2bd"
assert_grep_extended '0x9de3' "$KS_FILE" "8th gen Whiskey/Amber (Cannon Point-LP) KT PCI ID 0x9de3"
assert_grep_extended '0xa363' "$KS_FILE" "8th/9th gen Coffee/Cannon Lake (300) SOL PCI ID 0xa363"
assert_grep_extended '0x06e3' "$KS_FILE" "10th gen Comet Lake-H (400) KT PCI ID 0x06e3"
assert_grep_extended '0x02e3' "$KS_FILE" "10th gen Comet Lake-LP SOL PCI ID 0x02e3"
assert_grep_extended '0xa0e3' "$KS_FILE" "11th gen Tiger Lake-LP (500) KT PCI ID 0xa0e3"
assert_grep_extended '0x43e3' "$KS_FILE" "11th gen Tiger Lake-H/Rocket Lake SOL PCI ID 0x43e3"
assert_grep_extended '0xa3bd' "$KS_FILE" "10th gen Comet Lake-V KT/SOL PCI ID 0xa3bd"

# kernel-registered tentative (low-volume / Atom-class / server)
assert_grep_extended '0x34e3' "$KS_FILE" "10th gen Ice Lake-LP KT/SOL PCI ID 0x34e3"
assert_grep_extended '0x38e3' "$KS_FILE" "10th gen Ice Lake-N KT/SOL PCI ID 0x38e3"
assert_grep_extended '0x4de3' "$KS_FILE" "10/11th gen Jasper Lake-N KT/SOL PCI ID 0x4de3"
assert_grep_extended '0x4b73' "$KS_FILE" "Elkhart Lake KT/SOL PCI ID 0x4b73"
assert_grep_extended '0x1be3' "$KS_FILE" "Sapphire Rapids W790 workstation KT/SOL PCI ID 0x1be3"

# 12th gen Alder Lake family (all 4 variants: S, LP, P, N)
assert_grep_extended '0x7aeb' "$KS_FILE" "12th gen Alder Lake-S KT PCI ID 0x7aeb"
assert_grep_extended '0x7a63' "$KS_FILE" "12th gen Alder Lake-LP KT/SOL PCI ID 0x7a63"
assert_grep_extended '0x51e3' "$KS_FILE" "12th gen Alder Lake-P SOL PCI ID 0x51e3"
assert_grep_extended '0x54e3' "$KS_FILE" "12th gen Alder Lake-N KT/SOL PCI ID 0x54e3"

# 13th/14th gen Raptor Lake + Meteor Lake
assert_grep_extended '0x7a6b' "$KS_FILE" "13/14th gen Raptor Lake-S KT PCI ID 0x7a6b"
assert_grep_extended '0x7e73' "$KS_FILE" "14th gen Meteor Lake Mobile (Core Ultra 100) KT PCI ID 0x7e73"

# 15th gen Arrow Lake + Lunar Lake (Core Ultra 200 series)
assert_grep_extended '0x7f6b' "$KS_FILE" "15th gen Arrow Lake-S KT/SOL PCI ID 0x7f6b"
assert_grep_extended '0x7773' "$KS_FILE" "15th gen Arrow Lake-H KT PCI ID 0x7773"
assert_grep_extended '0xa873' "$KS_FILE" "15th gen Lunar Lake-M KT PCI ID 0xa873"

# 16th-17th gen + future (Panther/Nova/Wildcat Lake)
assert_grep_extended '0xe373' "$KS_FILE" "16th gen Panther Lake-H KT/SOL PCI ID 0xe373"
assert_grep_extended '0xe473' "$KS_FILE" "16th gen Panther Lake-P KT/SOL PCI ID 0xe473"
assert_grep_extended '0x6e6b' "$KS_FILE" "17th gen Nova Lake-S KT/SOL PCI ID 0x6e6b"
assert_grep_extended '0x4d73' "$KS_FILE" "Future Wildcat Lake-P KT/SOL PCI ID 0x4d73"

# Exact-set regression: the helper, add rules, and add|bind fallback must use
# the same 27 target IDs. This catches a future partial update or typo.
EXPECTED_IDS='0x02e3 0x06e3 0x1be3 0x34e3 0x38e3 0x43e3 0x4b73 0x4d73 0x4de3 0x51e3 0x54e3 0x6e6b 0x7773 0x7a63 0x7a6b 0x7aeb 0x7e73 0x7f6b 0x9de3 0xa0e3 0xa13d 0xa2bd 0xa363 0xa3bd 0xa873 0xe373 0xe473'
expected_sorted=$(tr ' ' '\n' <<< "$EXPECTED_IDS" | sort | tr '\n' ' ' | sed 's/ $//')
helper_sorted=$(grep -Eo '0x[0-9a-f]{4}' "$TMPDIR/noid-mei-kt-enforce" | grep -Ev '^0x(0700|0780|8086)$' | sort -u | tr '\n' ' ' | sed 's/ $//')
add_sorted=$(grep 'ACTION=="add"' "$TMPDIR/99-noid-mei-kt-block.rules" | grep -Eo 'ATTR\{device\}=="0x[0-9a-f]{4}"' | grep -Eo '0x[0-9a-f]{4}' | sort -u | tr '\n' ' ' | sed 's/ $//')
fallback_sorted=$(grep 'ACTION=="add|bind"' "$TMPDIR/99-noid-mei-kt-block.rules" | grep -Eo '0x[0-9a-f]{4}' | grep -Ev '^0x(0700|0780|8086)$' | sort -u | tr '\n' ' ' | sed 's/ $//')
assert_eq "$expected_sorted" "$helper_sorted" "helper has exact 27-ID target set"
assert_eq "$expected_sorted" "$add_sorted" "udev add rules have exact 27-ID target set"
assert_eq "$expected_sorted" "$fallback_sorted" "udev add|bind fallback has exact 27-ID target set"
assert_eq 18 "$(grep -c 'pci.ids ✓' "$TMPDIR/99-noid-mei-kt-block.rules")" \
    "provenance table identifies all 18 directly named pci.ids devices"
assert_eq 9 "$(grep -c 'derived$' "$TMPDIR/99-noid-mei-kt-block.rules")" \
    "provenance table identifies exactly nine conservative derived candidates"

# Syntax and behavior of the enforcement helper.
assert_cmd_success "KT/SOL helper POSIX shell syntax" /bin/sh -n "$TMPDIR/noid-mei-kt-enforce"
assert_grep_fixed 'ATTR{driver_override}="none", RUN+="/usr/libexec/noid-mei-kt-enforce"' "$TMPDIR/99-noid-mei-kt-block.rules" "udev invokes active enforcement helper"
assert_eq 28 "$(grep -c 'KERNEL=="????:??:??.3".*ATTR{class}=="0x0700\*"' \
    "$TMPDIR/99-noid-mei-kt-block.rules")" \
    "every KT/SOL udev path requires PCI function 3 and serial-controller class"
# Regression guard: 0x078000 is the HECI/MEI class, not KT/SOL. Matching it
# selected the wrong PCI function and blocked nothing on real hardware, so no
# rule and no helper branch may reintroduce it.
assert_eq 0 "$(grep -c 'ATTR{class}=="0x078000"' \
    "$TMPDIR/99-noid-mei-kt-block.rules")" \
    "no udev rule matches the HECI/MEI class instead of KT/SOL"
assert_grep_fixed '0x0700??)' "$TMPDIR/noid-mei-kt-enforce" \
    "helper gates on the serial-controller subclass"
assert_eq 0 "$(grep -c '"\$class" = "0x078000"' \
    "$TMPDIR/noid-mei-kt-enforce")" \
    "helper does not compare the class against HECI/MEI"
if command -v udevadm >/dev/null 2>&1 && udevadm verify --help >/dev/null 2>&1; then
    assert_cmd_success "udev rule parses successfully" udevadm verify "$TMPDIR/99-noid-mei-kt-block.rules"
else
    _pass "udevadm unavailable — udev syntax gate skipped"
fi

mkdir -p \
    "$TMPDIR/pci/0000:00:16.3" \
    "$TMPDIR/pci/0000:01:16.3" \
    "$TMPDIR/pci/0000:02:16.3" \
    "$TMPDIR/pci/0000:03:16.3" \
    "$TMPDIR/pci/0000:04:16.2" \
    "$TMPDIR/pci/0000:05:16.3"
printf '%s\n' 0x8086 > "$TMPDIR/pci/0000:00:16.3/vendor"
printf '%s\n' 0x7aeb > "$TMPDIR/pci/0000:00:16.3/device"
printf '%s\n' 0x070002 > "$TMPDIR/pci/0000:00:16.3/class"
printf '%s\n' unset > "$TMPDIR/pci/0000:00:16.3/driver_override"
printf '%s\n' 0x1234 > "$TMPDIR/pci/0000:01:16.3/vendor"
printf '%s\n' 0x7aeb > "$TMPDIR/pci/0000:01:16.3/device"
printf '%s\n' 0x070002 > "$TMPDIR/pci/0000:01:16.3/class"
printf '%s\n' untouched > "$TMPDIR/pci/0000:01:16.3/driver_override"
printf '%s\n' 0x8086 > "$TMPDIR/pci/0000:02:16.3/vendor"
printf '%s\n' 0x1234 > "$TMPDIR/pci/0000:02:16.3/device"
printf '%s\n' 0x070002 > "$TMPDIR/pci/0000:02:16.3/class"
printf '%s\n' untouched > "$TMPDIR/pci/0000:02:16.3/driver_override"
printf '%s\n' 0x8086 > "$TMPDIR/pci/0000:03:16.3/vendor"
printf '%s\n' 0x7aeb > "$TMPDIR/pci/0000:03:16.3/device"
printf '%s\n' 0x030000 > "$TMPDIR/pci/0000:03:16.3/class"
printf '%s\n' untouched > "$TMPDIR/pci/0000:03:16.3/driver_override"
printf '%s\n' 0x8086 > "$TMPDIR/pci/0000:04:16.2/vendor"
printf '%s\n' 0x7aeb > "$TMPDIR/pci/0000:04:16.2/device"
printf '%s\n' 0x070002 > "$TMPDIR/pci/0000:04:16.2/class"
printf '%s\n' untouched > "$TMPDIR/pci/0000:04:16.2/driver_override"
# HECI/MEI sits at the neighbouring class 0x078000 and must keep its driver
# for fwupd visibility. A listed KT/SOL device ID carrying that class is the
# exact shape the old, non-matching predicate selected, so it stays a
# negative case here.
printf '%s\n' 0x8086 > "$TMPDIR/pci/0000:05:16.3/vendor"
printf '%s\n' 0x7aeb > "$TMPDIR/pci/0000:05:16.3/device"
printf '%s\n' 0x078000 > "$TMPDIR/pci/0000:05:16.3/class"
printf '%s\n' untouched > "$TMPDIR/pci/0000:05:16.3/driver_override"
if NOID_PCI_SYSFS_ROOT="$TMPDIR/pci" /bin/sh "$TMPDIR/noid-mei-kt-enforce" >/dev/null 2>&1; then
    _pass "KT/SOL helper succeeds on synthetic unbound target"
else
    _fail "KT/SOL helper succeeds on synthetic unbound target"
fi
assert_eq "none" "$(tr -d '\n' < "$TMPDIR/pci/0000:00:16.3/driver_override")" "matching Intel target receives driver_override=none"
assert_eq "untouched" "$(tr -d '\n' < "$TMPDIR/pci/0000:01:16.3/driver_override")" "same device ID from another vendor is untouched"
assert_eq "untouched" "$(tr -d '\n' < "$TMPDIR/pci/0000:02:16.3/driver_override")" "unlisted Intel device is untouched"
assert_eq "untouched" "$(tr -d '\n' < "$TMPDIR/pci/0000:03:16.3/driver_override")" "same ID from the wrong PCI class is untouched"
assert_eq "untouched" "$(tr -d '\n' < "$TMPDIR/pci/0000:04:16.2/driver_override")" "same ID outside PCI function 3 is untouched"
assert_eq "untouched" "$(tr -d '\n' < "$TMPDIR/pci/0000:05:16.3/driver_override")" "listed ID carrying the HECI/MEI class is untouched"
if NOID_MEI_KT_CHECK_ONLY=1 NOID_PCI_SYSFS_ROOT="$TMPDIR/pci" /bin/sh "$TMPDIR/noid-mei-kt-enforce" >/dev/null 2>&1; then
    _pass "KT/SOL helper check-only mode verifies enforced state"
else
    _fail "KT/SOL helper check-only mode verifies enforced state"
fi
assert_eq 'KT/SOL enforcement complete (matched=1, unbound=0)' \
    "$(NOID_MEI_KT_CHECK_ONLY=1 NOID_PCI_SYSFS_ROOT="$TMPDIR/pci" \
        /bin/sh "$TMPDIR/noid-mei-kt-enforce")" \
    "KT/SOL helper exposes the verified matched-device count"
mkdir -p "$TMPDIR/pci-empty"
assert_eq 'KT/SOL enforcement complete (matched=0, unbound=0)' \
    "$(NOID_MEI_KT_CHECK_ONLY=1 NOID_PCI_SYSFS_ROOT="$TMPDIR/pci-empty" \
        /bin/sh "$TMPDIR/noid-mei-kt-enforce")" \
    "KT/SOL helper distinguishes an empty hardware target set"

mkdir -p "$TMPDIR/pci-fail/0000:00:16.3"
printf '%s\n' 0x8086 > "$TMPDIR/pci-fail/0000:00:16.3/vendor"
printf '%s\n' 0x7aeb > "$TMPDIR/pci-fail/0000:00:16.3/device"
printf '%s\n' 0x070002 > "$TMPDIR/pci-fail/0000:00:16.3/class"
if NOID_PCI_SYSFS_ROOT="$TMPDIR/pci-fail" /bin/sh "$TMPDIR/noid-mei-kt-enforce" >/dev/null 2>&1; then
    _fail "KT/SOL helper fails closed when override cannot be written"
else
    _pass "KT/SOL helper fails closed when override cannot be written"
fi

# --- Dracut conf + initramfs enforcement -----------------------------------
assert_grep_fixed '/etc/dracut.conf.d/noid-mei-blacklist.conf' "$KS_FILE"
assert_grep_fixed '/etc/udev/rules.d/99-noid-mei-kt-block.rules' "$TMPDIR/noid-mei-blacklist.conf" "dracut ships KT/SOL udev rule"
assert_grep_fixed '/usr/libexec/noid-mei-kt-enforce' "$TMPDIR/noid-mei-blacklist.conf" "dracut ships KT/SOL helper"

# --- Early boot verification service ---------------------------------------
assert_grep_fixed 'After=systemd-udev-trigger.service' "$TMPDIR/noid-mei-kt-enforce.service"
assert_grep_fixed 'Before=sysinit.target' "$TMPDIR/noid-mei-kt-enforce.service"
assert_grep_fixed 'ExecStart=/usr/libexec/noid-mei-kt-enforce' "$TMPDIR/noid-mei-kt-enforce.service"
assert_grep_fixed 'systemctl enable noid-mei-kt-enforce.service' "$KS_FILE"
assert_grep_fixed 'ProtectSystem=strict' "$TMPDIR/noid-mei-kt-enforce.service"
assert_grep_fixed 'IPAddressDeny=any' "$TMPDIR/noid-mei-kt-enforce.service"
assert_grep_fixed 'PrivateDevices=yes' "$TMPDIR/noid-mei-kt-enforce.service"
assert_grep_fixed 'PrivateNetwork=yes' "$TMPDIR/noid-mei-kt-enforce.service"
if command -v systemd-analyze >/dev/null 2>&1; then
    assert_cmd_success "KT/SOL service unit verifies" \
        systemd-analyze verify "$TMPDIR/noid-mei-kt-enforce.service"
    assert_cmd_success "CPU detector service unit verifies" \
        systemd-analyze verify "$TMPDIR/noid-cpu-vendor-detect.service"
else
    _pass "systemd-analyze unavailable — unit syntax gates skipped"
fi

# --- CLI syntax, transactional rollback, and claim boundaries --------------
assert_cmd_success "MEI submodule CLI syntax" /bin/bash -n "$TMPDIR/noid-mei-restore-submodules"
assert_cmd_success "MEI lockdown CLI syntax" /bin/bash -n "$TMPDIR/noid-mei-lockdown"
assert_cmd_success "CPU detector syntax" /bin/bash -n "$TMPDIR/noid-cpu-vendor-detect"
assert_cmd_success "platform policy hash helper Bash syntax" /bin/bash -n "$TMPDIR/noid-platform-policy-sha256"

# These three helpers are private no-argument actions.  Replace their first
# post-validation operation with a marker so this test proves hostile argv is
# rejected before hardware, policy-input or platform-state access.  A valid
# zero-argument call must still cross the same boundary.
M15_ARGV_ROOT="$TMPDIR/m15-argv-fixtures"
M15_ARGV_MARKER="$M15_ARGV_ROOT/effect-reached"
mkdir -p "$M15_ARGV_ROOT"

make_noarg_boundary_fixture() {
    local source=$1 fixture=$2

    awk -v marker="$M15_ARGV_MARKER" '
        !done && /^umask 077$/ {
            print "/usr/bin/printf \047%s\\n\047 reached > \047" marker "\047"
            print "exit 97"
            done=1
            next
        }
        { print }
        END { if (!done) exit 1 }
    ' "$source" > "$fixture"
    chmod 0700 "$fixture"
}

assert_private_noarg_boundary() {
    local name=$1 shell=$2 fixture=$3 diagnostic=$4
    local vector rc stdout stderr
    local -a argv

    for vector in unknown empty surplus newline escape; do
        case "$vector" in
            unknown) argv=(--unknown) ;;
            empty) argv=('') ;;
            surplus) argv=(one two) ;;
            newline) argv=($'hostile\nargument') ;;
            escape) argv=($'hostile\033argument') ;;
        esac

        rm -f "$M15_ARGV_MARKER"
        set +e
        stdout=$(PATH="$M15_ARGV_ROOT/untrusted-path" "$shell" "$fixture" \
            "${argv[@]}" 2>"$M15_ARGV_ROOT/stderr")
        rc=$?
        set -e
        stderr=$(cat "$M15_ARGV_ROOT/stderr")

        assert_eq 2 "$rc" "$name rejects $vector argv before its first effect"
        assert_eq '' "$stdout" "$name keeps stdout empty for $vector argv"
        assert_eq "$diagnostic" "$stderr" "$name emits constant diagnostic for $vector argv"
        if [[ -e "$M15_ARGV_MARKER" ]]; then
            _fail "$name reached its first effect for $vector argv"
        else
            _pass "$name keeps its first effect unreachable for $vector argv"
        fi
    done

    rm -f "$M15_ARGV_MARKER"
    set +e
    PATH="$M15_ARGV_ROOT/untrusted-path" "$shell" "$fixture" \
        >"$M15_ARGV_ROOT/stdout" 2>"$M15_ARGV_ROOT/stderr"
    rc=$?
    set -e
    assert_eq 97 "$rc" "$name accepts its exact zero-argument contract"
    assert_file_exists "$M15_ARGV_MARKER" "$name reaches its first effect without argv"
}

make_noarg_boundary_fixture "$TMPDIR/noid-mei-kt-enforce" \
    "$M15_ARGV_ROOT/noid-mei-kt-enforce"
make_noarg_boundary_fixture "$TMPDIR/noid-platform-policy-sha256" \
    "$M15_ARGV_ROOT/noid-platform-policy-sha256"
make_noarg_boundary_fixture "$TMPDIR/noid-cpu-vendor-detect" \
    "$M15_ARGV_ROOT/noid-cpu-vendor-detect"
assert_cmd_success "KT/SOL argv fixture POSIX shell syntax" \
    /bin/sh -n "$M15_ARGV_ROOT/noid-mei-kt-enforce"
assert_cmd_success "policy hash argv fixture Bash syntax" \
    /bin/bash -n "$M15_ARGV_ROOT/noid-platform-policy-sha256"
assert_cmd_success "CPU detector argv fixture Bash syntax" \
    /bin/bash -n "$M15_ARGV_ROOT/noid-cpu-vendor-detect"
assert_private_noarg_boundary \
    "KT/SOL helper" /bin/sh "$M15_ARGV_ROOT/noid-mei-kt-enforce" \
    "ERROR: noid-mei-kt-enforce accepts no arguments"
assert_private_noarg_boundary \
    "platform policy hash helper" /bin/bash "$M15_ARGV_ROOT/noid-platform-policy-sha256" \
    "ERROR: noid-platform-policy-sha256 accepts no arguments"
assert_private_noarg_boundary \
    "CPU vendor detector" /bin/bash "$M15_ARGV_ROOT/noid-cpu-vendor-detect" \
    "ERROR: noid-cpu-vendor-detect accepts no arguments"

policy_hash=$(/bin/bash "$TMPDIR/noid-platform-policy-sha256" 2>/dev/null || true)
if [[ "$policy_hash" =~ ^[a-f0-9]{64}$ ]]; then
    _pass "platform policy helper emits one SHA-256"
else
    _fail "platform policy helper emits one SHA-256"
fi

writer_policy_validator="$TMPDIR/writer-policy-validator.sh"
awk '
    /^validate_managed_policy\(\) \{/ {copy=1}
    copy {print}
    copy && /^\}$/ {exit}
' "$TMPDIR/noid-mei-restore-submodules" > "$writer_policy_validator"
# shellcheck source=/dev/null
. "$writer_policy_validator"
# shellcheck disable=SC2317,SC2329 # called indirectly by validate_managed_policy
fail() { return 1; }
WRITER_POLICY_FIXTURE="$TMPDIR/writer-policy.conf"
printf '%s\n' \
    '# canonical managed policy' \
    'blacklist mei_hdcp' \
    'install mei_hdcp /bin/false' > "$WRITER_POLICY_FIXTURE"
assert_cmd_success "writer accepts one exact managed-policy pair" \
    validate_managed_policy "$WRITER_POLICY_FIXTURE"
printf '%s\n' \
    ' blacklist mei_hdcp' \
    'install mei_hdcp /bin/false' > "$WRITER_POLICY_FIXTURE"
assert_cmd_failure "writer rejects non-canonical managed-policy whitespace" \
    validate_managed_policy "$WRITER_POLICY_FIXTURE"
printf '%s\n' 'blacklist mei_hdcp' > "$WRITER_POLICY_FIXTURE"
assert_cmd_failure "writer rejects half-applied managed policy" \
    validate_managed_policy "$WRITER_POLICY_FIXTURE"
unset -f fail validate_managed_policy
assert_grep_fixed 'mktemp "$STATE_DIR/.cpu-vendor.tmp.XXXXXX"' \
    "$TMPDIR/noid-cpu-vendor-detect" "cpu-vendor uses a same-directory candidate"
assert_grep_fixed 'mktemp "$STATE_DIR/.mei-status.tmp.XXXXXX"' \
    "$TMPDIR/noid-cpu-vendor-detect" "mei-status uses a same-directory candidate"
assert_grep_fixed 'mv -fT -- "$candidate" "$destination"' \
    "$TMPDIR/noid-cpu-vendor-detect" "platform status publication is atomic"
assert_grep_fixed 'CHECKED_AT_KERNEL=$CHECKED_AT_KERNEL' \
    "$TMPDIR/noid-cpu-vendor-detect" "every runtime schema binds the checked kernel"
assert_grep_fixed 'CHECKED_POLICY_SHA256=$CHECKED_POLICY_SHA256' \
    "$TMPDIR/noid-cpu-vendor-detect" "every runtime schema binds relevant policy bytes"
assert_not_grep 'SENTINEL=' "$TMPDIR/noid-cpu-vendor-detect" \
    "detector is repeatable rather than permanently sentinel-suppressed"
assert_not_grep 'ConditionPathExists=.*cpu-vendor-detected' \
    "$TMPDIR/noid-cpu-vendor-detect.service" \
    "boot refresh is not suppressed by a first-run sentinel"
assert_eq 3 "$(grep -cF 'Written by noid-cpu-vendor-detect-firstboot.service at boot.' \
    "$TMPDIR/noid-cpu-vendor-detect")" \
    "all runtime platform schemas describe the repeatable boot refresh"
assert_not_grep 'at first boot\.' "$TMPDIR/noid-cpu-vendor-detect" \
    "runtime platform evidence is not mislabeled as first-boot-only"
assert_grep_fixed 'After=local-fs.target systemd-modules-load.service noid-mei-kt-enforce.service' \
    "$TMPDIR/noid-cpu-vendor-detect.service" \
    "boot refresh runs after module and KT/SOL enforcement state settles"
assert_not_grep '^ProtectKernelModules=yes$' \
    "$TMPDIR/noid-cpu-vendor-detect.service" \
    "CPU detector keeps the module tree visible for modprobe dry-run"
assert_not_grep_extended '^NoNewPrivileges=(yes|true)$' \
    "$TMPDIR/noid-cpu-vendor-detect.service" \
    "CPU detector permits Fedora's SELinux initrc_t-to-kmod_t transition"
assert_grep_fixed 'NNP blocks that LSM transition' \
    "$TMPDIR/noid-cpu-vendor-detect.service" \
    "NNP exception documents the observed SELinux mechanism"
assert_grep_fixed 'CapabilityBoundingSet=~CAP_SYS_MODULE' \
    "$TMPDIR/noid-cpu-vendor-detect.service" \
    "CPU detector cannot acquire module-load capability"
assert_grep_fixed 'SystemCallFilter=~@module' \
    "$TMPDIR/noid-cpu-vendor-detect.service" \
    "CPU detector blocks module syscalls"
assert_grep_fixed 'SystemCallErrorNumber=EPERM' \
    "$TMPDIR/noid-cpu-vendor-detect.service" \
    "blocked module syscalls fail deterministically"
assert_grep_fixed 'ProtectSystem=strict' "$TMPDIR/noid-cpu-vendor-detect.service" \
    "CPU detector has an immutable filesystem view by default"
assert_grep_fixed 'ReadWritePaths=/var/lib/noid-privacy' \
    "$TMPDIR/noid-cpu-vendor-detect.service" \
    "CPU detector can write only its reviewed state directory"
assert_grep_fixed 'RestrictAddressFamilies=AF_UNIX' \
    "$TMPDIR/noid-cpu-vendor-detect.service" \
    "CPU detector retains only local journal-socket addressing"

kt_classifier="$TMPDIR/classify-kt-sol-check.sh"
awk '
    /^classify_kt_sol_check\(\) \{/ {copy=1}
    copy {print}
    copy && /^\}$/ {exit}
' "$TMPDIR/noid-cpu-vendor-detect" > "$kt_classifier"
# shellcheck source=/dev/null
. "$kt_classifier"
assert_eq no-device-present \
    "$(classify_kt_sol_check 'KT/SOL enforcement complete (matched=0, unbound=0)')" \
    "zero matched KT/SOL functions are reported as absent hardware"
assert_eq enforced \
    "$(classify_kt_sol_check 'KT/SOL enforcement complete (matched=2, unbound=0)')" \
    "present verified KT/SOL functions are reported as enforced"
assert_cmd_failure "malformed KT/SOL output cannot become status evidence" \
    classify_kt_sol_check 'KT/SOL enforcement complete'
assert_cmd_failure "check-only output cannot claim an unbind operation" \
    classify_kt_sol_check 'KT/SOL enforcement complete (matched=2, unbound=1)'
assert_grep_fixed 'invalid KT/SOL check-only result; refusing status publication' \
    "$TMPDIR/noid-cpu-vendor-detect" \
    "detector preserves prior status rather than publishing malformed evidence"

mei_policy_helper="$TMPDIR/detect-mei-submodule-policy.sh"
awk '
    /^detect_mei_submodule_policy\(\) \{/ {copy=1}
    copy {print}
    copy && /^\}$/ {exit}
' "$TMPDIR/noid-cpu-vendor-detect" > "$mei_policy_helper"
# shellcheck source=/dev/null
. "$mei_policy_helper"
MEI_POLICY_FIXTURE="$TMPDIR/mei-submodule-policy.conf"
printf '%s\n' '# default: no blocks' > "$MEI_POLICY_FIXTURE"
assert_eq none "$(detect_mei_submodule_policy "$MEI_POLICY_FIXTURE")" \
    "empty canonical MEI policy reports none"
printf '%s\n' \
    'blacklist mei_wdt' \
    'install mei_wdt /bin/false' \
    'blacklist mei_hdcp' \
    'install mei_hdcp /bin/false' > "$MEI_POLICY_FIXTURE"
assert_eq hdcp,wdt "$(detect_mei_submodule_policy "$MEI_POLICY_FIXTURE")" \
    "MEI policy reports canonical order independent of file order"
printf '%s\n' \
    'blacklist mei' \
    'install mei /bin/false' \
    'blacklist mei_me' \
    'install mei_me /bin/false' > "$MEI_POLICY_FIXTURE"
assert_eq blacklisted \
    "$(detect_mei_submodule_policy "$MEI_POLICY_FIXTURE" core)" \
    "the shared policy parser recognizes the complete core lockdown"
printf '%s\n' '# no core block' > "$MEI_POLICY_FIXTURE"
assert_eq loadable \
    "$(detect_mei_submodule_policy "$MEI_POLICY_FIXTURE" core)" \
    "the shared policy parser distinguishes a loadable core"
printf '%s\n' \
    'blacklist mei' \
    'install mei /bin/false' > "$MEI_POLICY_FIXTURE"
assert_cmd_failure "a half-applied core lockdown is rejected" \
    detect_mei_submodule_policy "$MEI_POLICY_FIXTURE" core
printf '%s\n' 'blacklist mei_pxp' > "$MEI_POLICY_FIXTURE"
assert_cmd_failure "half-applied MEI policy is rejected" \
    detect_mei_submodule_policy "$MEI_POLICY_FIXTURE"
printf '%s\n' \
    'blacklist mei_hdcp' \
    'blacklist mei_hdcp' \
    'install mei_hdcp /bin/false' > "$MEI_POLICY_FIXTURE"
assert_cmd_failure "duplicate MEI policy is rejected" \
    detect_mei_submodule_policy "$MEI_POLICY_FIXTURE"

atomic_helper="$TMPDIR/atomic-platform-publish.sh"
awk '
    /^validate_publish_target\(\) \{/ {copy=1}
    copy {print}
    /^atomic_publish\(\) \{/ {atomic=1}
    copy && atomic && /^\}$/ {exit}
' "$TMPDIR/noid-cpu-vendor-detect" > "$atomic_helper"
# shellcheck source=/dev/null
. "$atomic_helper"
# shellcheck disable=SC2317,SC2329 # invoked indirectly by sourced atomic_publish
chown() { :; }
# shellcheck disable=SC2317,SC2329 # invoked indirectly by sourced atomic_publish
restorecon() { :; }
# shellcheck disable=SC2317,SC2329 # test disables the host SELinux branch
selinuxenabled() { return 1; }
NOID_PLATFORM_EXPECTED_META="$(id -u):$(id -g):644:1"
export NOID_PLATFORM_EXPECTED_META
printf '%s\n' old > "$TMPDIR/platform-status"
printf '%s\n' complete-new > "$TMPDIR/.platform-status.tmp"
chmod 0644 "$TMPDIR/platform-status" "$TMPDIR/.platform-status.tmp"
if atomic_publish "$TMPDIR/.platform-status.tmp" "$TMPDIR/platform-status"; then
    _pass "atomic publisher commits a complete regular candidate"
else
    _fail "atomic publisher commits a complete regular candidate"
fi
assert_grep_fixed 'complete-new' "$TMPDIR/platform-status" \
    "atomic publisher replaces the old record"
printf '%s\n' protected > "$TMPDIR/platform-status"
ln -s "$TMPDIR/platform-status" "$TMPDIR/.platform-status.symlink"
if atomic_publish "$TMPDIR/.platform-status.symlink" "$TMPDIR/platform-status"; then
    _fail "atomic publisher rejects a symlink candidate"
else
    _pass "atomic publisher rejects a symlink candidate"
fi
assert_grep_fixed 'protected' "$TMPDIR/platform-status" \
    "rejected candidate leaves the published record unchanged"
unset -f chown restorecon selinuxenabled
assert_grep_fixed 'validate_publish_target "$CPU_VENDOR_FILE"' \
    "$TMPDIR/noid-cpu-vendor-detect" \
    "both platform publication targets are prevalidated before the first rename"
assert_grep_fixed 'validate_publish_target "$MEI_STATUS_FILE"' \
    "$TMPDIR/noid-cpu-vendor-detect" \
    "consumed MEI status target is prevalidated before publication"
assert_grep_fixed 'rollback_on_exit()' "$TMPDIR/noid-mei-restore-submodules" "MEI submodule CLI has rollback transaction"
assert_grep_fixed 'rollback_lockdown()' "$TMPDIR/noid-mei-lockdown" "MEI lockdown CLI has rollback transaction"
for cli in "$TMPDIR/noid-mei-restore-submodules" "$TMPDIR/noid-mei-lockdown"; do
    assert_grep_fixed 'BOOT_MUTATION_LOCK=/run/lock/noid-boot-mutation.lock' "$cli" \
        "MEI writer uses the shared boot lock: ${cli##*/}"
    assert_grep_fixed '/usr/libexec/noid-boot-mutation-guard' "$cli" \
        "MEI writer requires a stable M21 basis: ${cli##*/}"
    assert_grep_fixed '/usr/libexec/noid-dracut-regenerate-all --lock-held=7' "$cli" \
        "MEI writer uses the inherited-lock atomic regenerator: ${cli##*/}"
    assert_grep_fixed 'exec 7<>"$BOOT_MUTATION_LOCK"' "$cli" \
        "MEI writer opens the reviewed lock without truncation: ${cli##*/}"
    assert_grep_fixed "stat -c '%u:%g:%a:%h'" "$cli" \
        "MEI writer validates numeric owner/mode/link metadata: ${cli##*/}"
    assert_grep_fixed 'mktemp /etc/modprobe.d/.noid-mei-' "$cli" \
        "MEI writer builds same-directory candidates: ${cli##*/}"
    assert_grep_fixed 'mv -fT -- "$candidate" "$destination"' "$cli" \
        "MEI writer publishes policy atomically: ${cli##*/}"
    assert_grep_fixed 'sync -- /etc/modprobe.d' "$cli" \
        "MEI writer durably synchronizes the policy directory: ${cli##*/}"
    assert_grep_fixed 'if cmp -s "$CONF" "$CANDIDATE"; then' "$cli" \
        "MEI writer detects no-op before snapshot/rebuild: ${cli##*/}"
    assert_not_grep 'sed -i .*"\$CONF"' "$cli" \
        "MEI writer never edits the published policy in place: ${cli##*/}"
    assert_not_grep '^[[:space:]]*dracut --force --regenerate-all' "$cli" \
        "MEI writer has no uncoordinated all-image rebuild: ${cli##*/}"
done
assert_cmd_success "submodule help is available without root" \
    /bin/bash "$TMPDIR/noid-mei-restore-submodules" --help
assert_cmd_success "submodule help can be captured as dedicated prose" \
    /bin/bash -c '/bin/bash "$1" --help > "$2"' _ \
        "$TMPDIR/noid-mei-restore-submodules" "$TMPDIR/mei-submodule-help"
assert_grep_fixed 'noid-mei-restore-submodules — MEI submodule blacklist toggle' \
    "$TMPDIR/mei-submodule-help" "submodule help carries its own stable heading"
assert_not_grep_fixed 'set -euo pipefail' "$TMPDIR/mei-submodule-help" \
    "submodule help never leaks executable shell source"
assert_cmd_success "lockdown help is available without root" \
    /bin/bash "$TMPDIR/noid-mei-lockdown" --help
assert_cmd_failure "submodule help rejects trailing arguments" \
    /bin/bash "$TMPDIR/noid-mei-restore-submodules" --help extra
assert_cmd_failure "lockdown status rejects trailing arguments" \
    /bin/bash "$TMPDIR/noid-mei-lockdown" --status extra
assert_grep_fixed "M21's shared" "$TMPDIR/intel-me-hardware-layer.md" \
    "installed MEI guide names the shared boot-mutation owner"
assert_not_grep 'dracut --force --regenerate-all' \
    "$TMPDIR/intel-me-hardware-layer.md" \
    "installed MEI guide cannot direct users around the atomic regenerator"
assert_not_grep 'noid-snap-pre .*|| true' "$TMPDIR/noid-mei-restore-submodules" "MEI submodule snapshot failures are not swallowed"
assert_not_grep 'noid-snap-pre .*|| true' "$TMPDIR/noid-mei-lockdown" "MEI lockdown snapshot failures are not swallowed"
for cli in "$TMPDIR/noid-mei-restore-submodules" "$TMPDIR/noid-mei-lockdown"; do
    assert_grep_fixed '[ -x /usr/local/bin/noid-snap-pre ]' "$cli" \
        "MEI mutation requires the installed snapshot boundary: ${cli##*/}"
    assert_grep_fixed '/usr/local/bin/noid-snap-pre ' "$cli" \
        "MEI mutation invokes the snapshot helper by absolute path: ${cli##*/}"
    assert_not_grep_fixed 'command -v noid-snap-pre' "$cli" \
        "MEI mutation has no unreachable PATH lookup: ${cli##*/}"
done
assert_not_grep '\[WARN\].*dracut failed' "$TMPDIR/noid-mei-lockdown" "MEI lockdown never recommends reboot after dracut failure"
assert_grep_fixed 'GSC-dependent Intel graphics/protected-media paths may fail' \
    "$TMPDIR/noid-mei-lockdown" \
    "experimental core block warns about the proven graphics dependency"
assert_not_grep 'Normal boot + runtime.*Works.*Works' \
    "$TMPDIR/intel-me-hardware-layer.md" \
    "installed guide makes no unconditional full-lockdown stability claim"
assert_grep_fixed 'INTEL-SA-01315' "$TMPDIR/intel-me-hardware-layer.md" \
    "installed guide carries the current Intel chipset-firmware advisory"
assert_grep_fixed '27 reviewed IDs across 6th–17th gen' \
    "$TMPDIR/intel-me-hardware-layer.md" \
    "installed guide states the exact KT/SOL generation boundary"
assert_grep_fixed 'pre-Skylake platforms are not covered' \
    "$TMPDIR/intel-me-hardware-layer.md" \
    "installed guide discloses the uncovered legacy-platform boundary"
assert_not_grep 'current and legacy Intel families' \
    "$TMPDIR/intel-me-hardware-layer.md" \
    "installed guide makes no vague legacy-platform coverage claim"
assert_grep_fixed 'A separate card alone is not a guarantee.' "$TMPDIR/amd-psp.md"
assert_grep_fixed 'There is no single' "$TMPDIR/amd-psp.md" "AMD bulletin guidance is product-specific"
assert_not_grep 'CCP_MODULE=loaded-for-ftpm-and-hsi' "$TMPDIR/amd-psp.md" "AMD doc does not claim universal fTPM dependency"

# --- Status file contract (mei-status.txt) ---------------------------------
assert_grep_fixed 'mei-status.txt' "$KS_FILE"
assert_grep_fixed 'MEI_STATE=' "$KS_FILE"
assert_grep_fixed 'MEI_CORE_POLICY=$MEI_CORE_POLICY' "$KS_FILE" \
    "runtime Intel status publishes the core-policy classification"
assert_grep_fixed 'MEI_STATE="blocked-by-policy"' "$KS_FILE" \
    "the core lockdown cannot appear as merely available-not-loaded"
assert_grep_fixed 'mei-status.txt carries the exact staged AMD lifecycle' \
    "$KS_FILE" "the reachable non-Intel branch validates the AMD schema"
assert_grep_fixed 'mei-status.txt carries the exact staged unknown-vendor lifecycle' \
    "$KS_FILE" "the reachable non-Intel branch validates the unknown schema"
assert_grep_fixed 'read_platform_status()' "$KS_FILE" \
    "M15 verifies a real noid-status consumer"
assert_not_grep 'MEI_STATUS_FILE.*noid-welcome' "$KS_FILE" \
    "M15 has no self-referential Welcome anchor"

# M15's local dependency gate must validate effective rule-tree coverage, not
# merely find a loose directory token. Exercise each required control against
# complete, missing, later-negative and later-weak rule fixtures.
aide_coverage_helper="$TMPDIR/aide-coverage-helper.sh"
awk '
    /^check_aide_coverage\(\) \{/ { copy=1 }
    copy { print }
    copy && /^\}$/ { exit }
' "$KS_FILE" > "$aide_coverage_helper"
# shellcheck source=/dev/null
. "$aide_coverage_helper"
mapfile -t m15_coverage_specs < <(sed -n \
    '/^M15_AIDE_COVERAGE=($/,/^)/p' "$KS_FILE" | \
    sed -n "s/^[[:space:]]*'\(.*\)'$/\1/p")
assert_eq 6 "${#m15_coverage_specs[@]}" \
    "M15 declares all six mandatory AIDE coverage contracts"
for spec in "${m15_coverage_specs[@]}"; do
    IFS='|' read -r rule_path _ _ <<< "$spec"
    if cut -d'|' -f1 "$AIDE_SECURE_MANIFEST" | grep -qxF "$rule_path"; then
        _pass "M15 AIDE selector is canonical: $rule_path"
    else
        _fail "M15 AIDE selector is canonical: $rule_path"
    fi
done
assert_not_grep '\[WARN\] Module 13 SECURE rule missing' "$KS_FILE" \
    "missing mandatory AIDE coverage is never warning-only"

write_m15_aide_fixture() {
    local omit="${1:-}" spec rule_path
    printf '%s\n' \
        'NORMAL = p+u+g+s+sha512' \
        'SECURE = p+u+g+s+sha256+sha512' \
        '/etc/modprobe.d NORMAL' \
        '/etc/dracut.conf.d NORMAL' > "$TMPDIR/aide-fixture.conf"
    for spec in "${m15_coverage_specs[@]}"; do
        IFS='|' read -r rule_path _ _ <<< "$spec"
        [ "$rule_path" = "$omit" ] || printf '%s SECURE\n' "$rule_path" \
            >> "$TMPDIR/aide-fixture.conf"
    done
}

for spec in "${m15_coverage_specs[@]}"; do
    IFS='|' read -r rule_path file_type probe_path <<< "$spec"
    write_m15_aide_fixture
    if check_aide_coverage "$TMPDIR/aide-fixture.conf" "$rule_path" \
            "$file_type" "$probe_path"; then
        _pass "effective SECURE fixture accepted: $probe_path"
    else
        _fail "effective SECURE fixture accepted: $probe_path"
    fi
    write_m15_aide_fixture "$rule_path"
    if check_aide_coverage "$TMPDIR/aide-fixture.conf" "$rule_path" \
            "$file_type" "$probe_path"; then
        _fail "missing exact SECURE rule rejected: $rule_path"
    else
        _pass "missing exact SECURE rule rejected: $rule_path"
    fi
    write_m15_aide_fixture
    printf '!%s$\n' "$probe_path" >> "$TMPDIR/aide-fixture.conf"
    if check_aide_coverage "$TMPDIR/aide-fixture.conf" "$rule_path" \
            "$file_type" "$probe_path"; then
        _fail "later negative rule rejected: $probe_path"
    else
        _pass "later negative rule rejected: $probe_path"
    fi
    # A child-specific positive rule can weaken an ordinary directory rule.
    # A trailing-slash rule already occupies the child node, however, and
    # AIDE's first-match rule makes a later weak rule in that same node inert.
    # The exact-file contracts are already the most-specific positive rules.
    if [ "$rule_path" != "$probe_path" ]; then
        write_m15_aide_fixture
        printf '%s\n%s WEAK\n' 'WEAK = p+u+g+s+sha256' "$probe_path" \
            >> "$TMPDIR/aide-fixture.conf"
        if [[ "$rule_path" == */ ]]; then
            if check_aide_coverage "$TMPDIR/aide-fixture.conf" "$rule_path" \
                    "$file_type" "$probe_path"; then
                _pass "later weak rule cannot shadow child-node SECURE: $probe_path"
            else
                _fail "later weak rule cannot shadow child-node SECURE: $probe_path"
            fi
        elif check_aide_coverage "$TMPDIR/aide-fixture.conf" "$rule_path" \
                "$file_type" "$probe_path"; then
            _fail "later weak rule rejected: $probe_path"
        else
            _pass "later weak rule rejected: $probe_path"
        fi
    fi
done

# --- AMD PSP docs ----------------------------------------------------------
assert_grep_fixed '15-amd-psp-hardware-layer.md' "$KS_FILE"

# --- Escape-hatch scripts ---------------------------------------------------
assert_grep_fixed '/usr/local/bin/noid-mei-restore-submodules' "$KS_FILE"
assert_grep_fixed '/usr/local/bin/noid-mei-lockdown' "$KS_FILE"

# The MEI status report embeds `fwupdmgr security` output. fwupd translates
# both its attribute names and its result words, so an unpinned call printed
# localized result strings inside an English report — and the `/^HSI/` arm of
# the filter is matched against that same translated text, surviving only
# because "BootGuard" is an untranslated product name. noid-status already
# pins the locale for this exact command; both callers must agree.
assert_grep_fixed 'LC_ALL=C fwupdmgr security' "$KS_FILE" \
    "the MEI HSI report pins its own locale for a single-language report"
assert_not_grep_extended '\$\(fwupdmgr security 2>/dev/null\)' "$KS_FILE" \
    "no unpinned fwupdmgr capture remains in the MEI helper"

test_finish

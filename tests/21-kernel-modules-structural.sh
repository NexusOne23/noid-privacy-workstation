#!/bin/bash
# Verify Module 21's normalized effective module policy and the split between
# a generic Live/installer initramfs and topology-derived installed images.

set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/21-kernel-module-blacklist.ks"
M17_KS_FILE="$PROJECT_ROOT/kickstart/snippets/17-gnome-hardening.ks"
M08_KS_FILE="$PROJECT_ROOT/kickstart/snippets/08-service-minimization.ks"
M31_KS_FILE="$PROJECT_ROOT/kickstart/snippets/31-user-docs-tier-c.ks"
RUNTIME_GATE="$PROJECT_ROOT/tests/pre-ship/21-dracut-hostonly-runtime.sh"
POWERLOSS_GATE="$PROJECT_ROOT/tests/pre-ship/21-dracut-powerloss-runtime.sh"
KARG_CONTRACT="$PROJECT_ROOT/tests/01-karg-contract.py"
HARDWARE_COMPAT="$PROJECT_ROOT/docs/hardware-network-compatibility.md"
THREAT_MODEL="$PROJECT_ROOT/docs/threat-model.md"
SCOPE_DOC="$PROJECT_ROOT/docs/scope.md"
COMPARISON_DOC="$PROJECT_ROOT/docs/comparison.md"
AI_WORKSPACE_DOC="$PROJECT_ROOT/docs/ai-workspace.md"

test_start "21-kernel-modules-structural"
assert_file_exists "$KS_FILE"
assert_file_exists "$M17_KS_FILE"
assert_file_exists "$M08_KS_FILE"
assert_file_exists "$M31_KS_FILE"
assert_file_exists "$RUNTIME_GATE"
assert_file_exists "$POWERLOSS_GATE"
assert_file_exists "$KARG_CONTRACT"
assert_file_exists "$HARDWARE_COMPAT"
assert_file_exists "$THREAT_MODEL"
assert_file_exists "$SCOPE_DOC"
assert_file_exists "$COMPARISON_DOC"
assert_file_exists "$AI_WORKSPACE_DOC"
assert_cmd_success "M21 runtime gate is executable" test -x "$RUNTIME_GATE"
assert_cmd_success "M21 power-loss gate is executable" test -x "$POWERLOSS_GATE"
assert_cmd_success "M21 runtime gate syntax" bash -n "$RUNTIME_GATE"
assert_cmd_success "M21 power-loss gate syntax" bash -n "$POWERLOSS_GATE"
assert_cmd_success "M21 runtime gates ShellCheck" \
    shellcheck -x "$RUNTIME_GATE" "$POWERLOSS_GATE"

TMPDIR="$(mktemp -d /var/tmp/noid-m21-structural.XXXXXX)"
trap 'rm -rf "$TMPDIR"' EXIT

extract_heredoc "$KS_FILE" KERNEL_MODULE_POLICY_EOF "$TMPDIR/policy.tsv" \
    || _fail "kernel policy manifest extraction"
extract_heredoc "$KS_FILE" DRACUT_OMIT_EOF "$TMPDIR/omit-firewire.conf" \
    || _fail "FireWire Dracut extraction"
extract_heredoc "$KS_FILE" INTEL_GSC_DRACUT_EOF "$TMPDIR/intel-gsc.conf" \
    || _fail "Intel GSC Dracut extraction"
extract_heredoc "$KS_FILE" BOOT_MUTATION_GUARD_EOF "$TMPDIR/boot-mutation-guard" \
    || _fail "boot-mutation guard extraction"
extract_heredoc "$KS_FILE" GUARDED_REGENERATE_EOF "$TMPDIR/dracut-regenerate-all" \
    || _fail "guarded Dracut regenerator extraction"
extract_heredoc "$KS_FILE" BOOT_MUTATION_SUDOERS_EOF "$TMPDIR/boot-mutation.sudoers" \
    || _fail "boot-mutation sudoers extraction"
extract_heredoc "$KS_FILE" HOSTONLY_SCRIPT_EOF "$TMPDIR/hostonly.sh" \
    || _fail "host-only convergence script extraction"
extract_heredoc "$KS_FILE" HOSTONLY_SERVICE_EOF "$TMPDIR/hostonly.service" \
    || _fail "host-only service extraction"
extract_heredoc "$KS_FILE" HOSTONLY_TIMER_EOF "$TMPDIR/hostonly.timer" \
    || _fail "host-only timer extraction"
extract_heredoc "$KS_FILE" HOSTONLY_BOOT_SUCCESS_EOF "$TMPDIR/hostonly-boot-success" \
    || _fail "host-only first-login boot-success helper extraction"
extract_heredoc "$KS_FILE" HOSTONLY_BOOT_SUCCESS_SERVICE_EOF \
    "$TMPDIR/hostonly-boot-success.service" \
    || _fail "host-only first-login boot-success service extraction"
extract_heredoc "$KS_FILE" HOSTONLY_BOOT_SUCCESS_PATH_EOF \
    "$TMPDIR/hostonly-boot-success.path" \
    || _fail "host-only first-login request path extraction"
extract_heredoc "$M17_KS_FILE" FIRSTRUN_SVC_EOF \
    "$TMPDIR/noid-user-firstrun.service" \
    || _fail "transactional first-login service extraction"
extract_heredoc "$KS_FILE" DOC_EOF "$TMPDIR/module-policy.md" \
    || _fail "Module 21 documentation extraction"

# Exact normalized policy shape. Counts are security evidence only when each
# state has a defined meaning and module identities are unique/canonical.
rows=$(awk -F '\t' '!/^#/ && NF { n++ } END { print n+0 }' "$TMPDIR/policy.tsv")
deny=$(awk -F '\t' '$2 == "deny-loadable" { n++ } END { print n+0 }' "$TMPDIR/policy.tsv")
builtin=$(awk -F '\t' '$2 == "unaffected-builtin" { n++ } END { print n+0 }' "$TMPDIR/policy.tsv")
absent=$(awk -F '\t' '$2 == "unaffected-absent" { n++ } END { print n+0 }' "$TMPDIR/policy.tsv")
aliases=$(awk -F '\t' '$2 == "alias-denied-via-target" { n++ } END { print n+0 }' "$TMPDIR/policy.tsv")
supported=$(awk -F '\t' '$2 == "supported" { n++ } END { print n+0 }' "$TMPDIR/policy.tsv")
assert_eq 134 "$rows" "134 unique policy identities"
assert_eq 53 "$deny" "53 canonical loadable denies"
assert_eq 8 "$builtin" "8 explicitly unaffected built-ins"
assert_eq 43 "$absent" "43 explicitly absent target-kernel identities"
assert_eq 2 "$aliases" "2 historical aliases mapped to deny targets"
assert_eq 28 "$supported" "28 deliberately supported modules"
for constant in \
    EXPECTED_POLICY_ROWS=134 \
    EXPECTED_DENY_COUNT=53 \
    EXPECTED_BUILTIN_COUNT=8 \
    EXPECTED_ABSENT_COUNT=43 \
    EXPECTED_ALIAS_COUNT=2 \
    EXPECTED_SUPPORTED_COUNT=28; do
    assert_grep_fixed "$constant" "$KS_FILE" "release gate: $constant"
done
for public_doc in "$THREAT_MODEL" "$SCOPE_DOC" "$COMPARISON_DOC"; do
    assert_grep_fixed "${rows}-state module" "$public_doc" \
        "public module-inventory claim follows the ${rows}-row manifest: ${public_doc#"$PROJECT_ROOT"/}"
done
for ai_doc in "$AI_WORKSPACE_DOC" "$M08_KS_FILE"; do
    assert_grep_fixed "${rows}-state module policy" "$ai_doc" \
        "AI-workspace module claim follows the ${rows}-row manifest: ${ai_doc#"$PROJECT_ROOT"/}"
done
assert_grep_fixed "${rows} normalized identities" "$M31_KS_FILE" \
    "architecture module claim follows the manifest row count"
assert_grep_fixed "while ${builtin} built-ins" "$M31_KS_FILE" \
    "architecture built-in claim follows the manifest state count"
assert_grep_fixed "contains ${rows} normalized module identities" \
    "$TMPDIR/module-policy.md" \
    "installed M21 guide follows the manifest row count"
assert_grep_fixed "- ${builtin} \`unaffected-builtin\`" \
    "$TMPDIR/module-policy.md" \
    "installed M21 guide follows the manifest built-in count"
assert_grep_fixed 'actual_bl=${actual_bl:-0}' "$KS_FILE" \
    "blacklist count has an explicit zero fallback"
assert_grep_fixed 'actual_inst=${actual_inst:-0}' "$KS_FILE" \
    "install-deny count has an explicit zero fallback"
assert_eq 2 "$(grep -cF 'btrfs_devices=${btrfs_devices:-0}' "$KS_FILE")" \
    "both root classifiers normalize an empty device count"
assert_eq 2 "$(grep -cF 'SHARED-LOGIC-MARKER: root-class detection' "$KS_FILE")" \
    "both standalone root classifiers carry the shared-logic marker"
assert_eq 2 "$(grep -cF 'SHARED-LOGIC-MARKER: integrated root-driver classification' "$KS_FILE")" \
    "both standalone integrated-driver classifiers carry the shared-logic marker"
assert_eq 2 "$(grep -cF 'SHARED-LOGIC-MARKER: root-path driver walk' "$KS_FILE")" \
    "both standalone root-path walks carry the shared-logic marker"
assert_not_grep 'restorecon.*2>/dev/null.*|| true' "$KS_FILE" \
    "module-policy SELinux reconciliation cannot hide a failure"
assert_grep_fixed 'final policy SELinux reconciliation failed' "$KS_FILE" \
    "final module-policy relabel is a hard installation postcondition"
assert_grep_fixed 'required kmod command missing: $command' "$KS_FILE" \
    "policy gate requires the kmod inspection and resolution tools"

if awk -F '\t' '
    BEGIN {
        state["deny-loadable"] = 1
        state["unaffected-builtin"] = 1
        state["unaffected-absent"] = 1
        state["alias-denied-via-target"] = 1
        state["supported"] = 1
    }
    /^#/ || NF == 0 { next }
    NF != 3 || $1 !~ /^[a-z0-9][a-z0-9_]*$/ || !($2 in state) { exit 1 }
    seen[$1]++ { exit 1 }
    $2 == "alias-denied-via-target" {
        if ($3 !~ /^[a-z0-9][a-z0-9_]*$/ || $3 == $1) exit 1
        alias[$1] = $3
        next
    }
    $3 != "-" { exit 1 }
    $2 == "deny-loadable" { denied[$1] = 1 }
    END {
        for (name in alias) if (!(alias[name] in denied)) exit 1
    }
' "$TMPDIR/policy.tsv"; then
    _pass "manifest schema, uniqueness and alias targets are valid"
else
    _fail "manifest schema, uniqueness or alias target failure"
fi

# Reproduce the generator and prove exact equivalence: only deny-loadable rows
# become modprobe directives. No built-in, absent, alias or supported row may
# be counted as effective enforcement.
awk -F '\t' '$2 == "deny-loadable" {
    printf "blacklist %s\ninstall %s /bin/false\n", $1, $1
}' "$TMPDIR/policy.tsv" > "$TMPDIR/generated.conf"
assert_eq 53 "$(grep -c '^blacklist ' "$TMPDIR/generated.conf")" \
    "generated blacklist cardinality"
assert_eq 53 "$(grep -c '^install .* /bin/false$' "$TMPDIR/generated.conf")" \
    "generated install cardinality"
while IFS=$'\t' read -r module state _target; do
    case "$module" in ''|'#'*) continue ;; esac
    if [ "$state" = deny-loadable ]; then
        assert_grep_extended "^blacklist ${module}$" "$TMPDIR/generated.conf" \
            "effective deny: $module"
        assert_grep_extended "^install ${module} /bin/false$" \
            "$TMPDIR/generated.conf" "effective install deny: $module"
    elif grep -qE "^(blacklist|install)[[:space:]]+${module}([[:space:]]|$)" \
            "$TMPDIR/generated.conf"; then
        _fail "$module ($state) leaked into effective enforcement"
    fi
done < "$TMPDIR/policy.tsv"

for row in \
    $'can\tunaffected-builtin\t-' \
    $'msr\tunaffected-builtin\t-' \
    $'vesafb\tunaffected-builtin\t-' \
    $'af_alg\tunaffected-builtin\t-' \
    $'algif_aead\tunaffected-builtin\t-' \
    $'algif_hash\tunaffected-builtin\t-' \
    $'algif_rng\tunaffected-builtin\t-' \
    $'algif_skcipher\tunaffected-builtin\t-' \
    $'ohci1394\talias-denied-via-target\tfirewire_ohci' \
    $'sbp2\talias-denied-via-target\tfirewire_sbp2' \
    $'squashfs\tsupported\t-' \
    $'nouveau\tsupported\t-' \
    $'usb_storage\tsupported\t-'; do
    assert_grep_fixed "$row" "$TMPDIR/policy.tsv" "policy row: $row"
done
assert_not_grep 'bolt service authenticates TB devices per-user-approval' \
    "$TMPDIR/module-policy.md" "module documentation cannot claim an absent prompt-only boltd policy"
assert_grep_fixed 'does not install `boltd`' "$TMPDIR/module-policy.md" \
    "module documentation states the deliberate Thunderbolt userspace boundary"
assert_grep_fixed 'image cannot force it' "$TMPDIR/module-policy.md" \
    "module documentation does not overclaim firmware authorization control"
assert_grep_fixed 'auto-enroll/authorize unknown devices' "$TMPDIR/module-policy.md" \
    "module documentation states the upstream IOMMU-policy trade-off"
assert_grep_fixed 'after deliberate PCIe authorization' "$HARDWARE_COMPAT" \
    "hardware matrix distinguishes netdev support from Thunderbolt authorization"
assert_grep_fixed 'boltd is not installed' "$HARDWARE_COMPAT" \
    "hardware matrix states the default Thunderbolt userspace posture"

# Early-boot FireWire removal contains only canonical loadable identities.
assert_grep_fixed \
    'omit_drivers+=" firewire_core firewire_net firewire_ohci firewire_sbp2 "' \
    "$TMPDIR/omit-firewire.conf" "canonical FireWire omit set"
assert_not_grep_extended '(^|[[:space:]"])(ohci1394|sbp2|dv1394|raw1394|video1394)([[:space:]"]|$)|firewire-[a-z]' \
    "$TMPDIR/omit-firewire.conf" "aliases/absent spellings are not counted twice"

# Intel i915 may request GSC before the real-root MEI module tree is visible.
# Include exact dependencies in every image without force-loading them on
# systems where the matching devices do not exist.
assert_eq 'add_drivers+=" mei_me mei_gsc_proxy "' \
    "$(tail -n 1 "$TMPDIR/intel-gsc.conf")" \
    "Intel GSC dependency closure uses Dracut add_drivers"
assert_not_grep 'force_drivers' "$TMPDIR/intel-gsc.conf" \
    "Intel GSC dependencies are never force-loaded"
assert_grep_fixed '/etc/dracut.conf.d/98-noid-intel-gsc.conf' "$KS_FILE" \
    "Intel GSC policy is included in final SELinux reconciliation"
assert_grep_fixed 'modprobe --set-version "$kernel" --dry-run' "$KS_FILE" \
    "each target-kernel deny is checked through effective kmod resolution"
assert_grep_fixed '$1 == "install" && $2 == "/bin/false" && NF == 2' \
    "$KS_FILE" "effective policy gate requires the exact deny command"
assert_grep_fixed '$1 == "insmod" && $2 == path' "$KS_FILE" \
    "effective policy gate rejects insertion of the target module"
assert_grep_fixed '`modprobe --dry-run --verbose` resolution' \
    "$TMPDIR/module-policy.md" \
    "documentation states the effective kmod release gate"
assert_not_grep_extended 'Tier 3k|5-module upstream|break lid-close sleep' \
    "$KS_FILE" "PMT compatibility rationale contains no stale or absolute claim"

# Compose boundary: Live/installer is explicitly generic. Installed boundary:
# stage and validate off-/boot, preserve a bootable Generic BLS entry, publish
# with durable ordering, and confirm only after a real reboot.
assert_cmd_success "host-only helper syntax" bash -n "$TMPDIR/hostonly.sh"
assert_cmd_success "host-only helper ShellCheck" \
    shellcheck -x "$TMPDIR/hostonly.sh"
chmod 0755 "$TMPDIR/hostonly.sh"
awk -v helper="$TMPDIR/hostonly.sh" '
    $0 == "ExecStart=/usr/libexec/noid-dracut-hostonly-configure" {
        print "ExecStart=" helper
        next
    }
    { print }
' "$TMPDIR/hostonly.service" > "$TMPDIR/noid-dracut-hostonly-firstboot.service"
cp -a -- "$TMPDIR/hostonly.timer" \
    "$TMPDIR/noid-dracut-hostonly-firstboot.timer"
assert_cmd_success "host-only system service/timer dependency graph" \
    env SYSTEMD_UNIT_PATH="$TMPDIR:/etc/systemd/system:/usr/lib/systemd/system" \
    systemd-analyze verify noid-dracut-hostonly-firstboot.service \
        noid-dracut-hostonly-firstboot.timer
assert_cmd_success "host-only first-login boot-success helper syntax" \
    bash -n "$TMPDIR/hostonly-boot-success"
chmod 0755 "$TMPDIR/hostonly-boot-success"
assert_cmd_success "host-only first-login boot-success helper ShellCheck" \
    shellcheck -x "$TMPDIR/hostonly-boot-success"
# systemd-analyze resolves ExecStart while verifying. Point only its disposable
# copy at the extracted helper; the source unit remains exact for assertions.
awk -v helper="$TMPDIR/hostonly-boot-success" '
    $0 == "ExecStart=/usr/libexec/noid-mark-hostonly-boot-success" {
        print "ExecStart=" helper
        next
    }
    { print }
' "$TMPDIR/hostonly-boot-success.service" \
    > "$TMPDIR/noid-hostonly-boot-success.service"
# systemd-analyze --user initializes the user-manager path table even for an
# offline verify.  CI/agent shells need not belong to a logind session, so give
# that disposable manager its own private runtime root instead of inheriting a
# missing or unrelated XDG_RUNTIME_DIR.
mkdir -m 0700 "$TMPDIR/user-runtime"
cp -a -- "$TMPDIR/hostonly-boot-success.path" \
    "$TMPDIR/noid-hostonly-boot-success.path"
assert_cmd_success "host-only boot-success user-unit dependency graph" \
    env XDG_RUNTIME_DIR="$TMPDIR/user-runtime" \
        SYSTEMD_UNIT_PATH="$TMPDIR:/usr/lib/systemd/user" \
    systemd-analyze --user verify noid-hostonly-boot-success.service \
        noid-hostonly-boot-success.path \
        noid-user-firstrun.service
assert_cmd_success "boot-mutation guard syntax" \
    bash -n "$TMPDIR/boot-mutation-guard"
assert_cmd_success "guarded regenerator syntax" \
    bash -n "$TMPDIR/dracut-regenerate-all"
assert_eq 1 "$(grep -cF 'trap cleanup EXIT' "$TMPDIR/dracut-regenerate-all")" \
    "guarded regenerator cleans temporary candidates on shell exit"
for signal_contract in \
    "trap 'exit 129' HUP" \
    "trap 'exit 130' INT" \
    "trap 'exit 143' TERM"; do
    assert_grep_fixed "$signal_contract" "$TMPDIR/dracut-regenerate-all" \
        "guarded regenerator preserves cancellation: $signal_contract"
done
assert_not_grep_extended '^trap cleanup (EXIT )?(INT|TERM|HUP)' \
    "$TMPDIR/dracut-regenerate-all" \
    "guarded regenerator never swallows a cancellation signal"
cleanup_start=$(grep -n '^cleanup() {$' "$TMPDIR/dracut-regenerate-all" \
    | cut -d: -f1 || true)
term_trap_line=$(grep -nF "trap 'exit 143' TERM" \
    "$TMPDIR/dracut-regenerate-all" | cut -d: -f1 || true)
if [ -n "$cleanup_start" ] && [ -n "$term_trap_line" ]; then
    _pass "guarded regenerator signal fixture extraction"
    sed -n "${cleanup_start},${term_trap_line}p" \
        "$TMPDIR/dracut-regenerate-all" \
        > "$TMPDIR/regenerator-signals.fragment"
else
    _fail "guarded regenerator signal fixture extraction"
    : > "$TMPDIR/regenerator-signals.fragment"
fi
for signal_case in HUP:129 INT:130 TERM:143; do
    signal=${signal_case%%:*}
    expected_status=${signal_case##*:}
    candidate="$TMPDIR/candidate-$signal"
    listing="$TMPDIR/listing-$signal"
    modules="$TMPDIR/modules-$signal"
    continued="$TMPDIR/continued-$signal"
    : > "$candidate"
    : > "$listing"
    : > "$modules"
    {
        printf '#!/bin/bash\nset -euo pipefail\n'
        printf 'candidate=%q\nlisting=%q\nmodules=%q\ncontinued=%q\n' \
            "$candidate" "$listing" "$modules" "$continued"
        cat "$TMPDIR/regenerator-signals.fragment"
        printf 'kill -%s "$$"\nprintf continued > "$continued"\n' "$signal"
    } > "$TMPDIR/regenerator-signal-$signal"
    set +e
    # run-all executes batches as background jobs, and POSIX shells inherit
    # SIGINT ignored in that context. Reset the tested signal before exec so
    # this fixture verifies the generated trap rather than its parent harness.
    python3 -I -c '
import os
import signal
import sys

signum = getattr(signal, "SIG" + sys.argv[1])
signal.signal(signum, signal.SIG_DFL)
os.execv("/bin/bash", ["bash", sys.argv[2]])
' "$signal" "$TMPDIR/regenerator-signal-$signal"
    signal_status=$?
    set -e
    assert_eq "$expected_status" "$signal_status" \
        "guarded regenerator exits with the conventional $signal status"
    if [ ! -e "$continued" ]; then
        _pass "guarded regenerator stops after $signal"
    else
        _fail "guarded regenerator continued after $signal"
    fi
    if [ ! -e "$candidate" ] && [ ! -e "$listing" ] \
            && [ ! -e "$modules" ]; then
        _pass "guarded regenerator cleans temporary files after $signal"
    else
        _fail "guarded regenerator left temporary files after $signal"
    fi
done
assert_grep_fixed 'LOCK=/run/lock/noid-boot-mutation.lock' \
    "$TMPDIR/dracut-regenerate-all" "later rebuilds use the shared boot lock"
assert_grep_fixed 'LOCK=/run/lock/noid-boot-mutation.lock' \
    "$TMPDIR/hostonly.sh" "firstboot convergence uses the shared boot lock"
assert_grep_fixed 'f /run/lock/noid-boot-mutation.lock 0660 root wheel -' "$KS_FILE" \
    "tmpfiles recreates the shared writer lock"
assert_eq 'Defaults!/usr/libexec/noid-dracut-regenerate-all closefrom_override' \
    "$(cat "$TMPDIR/boot-mutation.sudoers")" \
    "sudoers preserves descriptors only for the canonical regenerator"
assert_cmd_success "boot-mutation sudoers policy parses" \
    visudo -cf "$TMPDIR/boot-mutation.sudoers"
assert_grep_fixed 'chmod 0440 "$sudoers_candidate"' "$KS_FILE" \
    "sudoers candidate has mandatory restrictive mode before publication"
assert_grep_fixed 'mv -fT -- "$sudoers_candidate" /etc/sudoers.d/90-noid-boot-mutation-fd' \
    "$KS_FILE" "validated sudoers policy publishes atomically"
assert_grep_fixed 'complete) basis=hostonly' "$TMPDIR/boot-mutation-guard" \
    "confirmed host-only is an allowed terminal basis"
assert_grep_fixed 'recovered-generic) basis=generic' "$TMPDIR/boot-mutation-guard" \
    "fully restored Generic is an allowed terminal basis"
assert_grep_fixed 'M21 still requires recovery, an explicit retry or a real reboot' \
    "$TMPDIR/boot-mutation-guard" "pending and unknown M21 phases fail closed"
assert_grep_fixed 'M21 prepared boot ID is invalid' \
    "$TMPDIR/boot-mutation-guard" \
    "writer guard requires a canonical M21 boot ID"
assert_grep_fixed "'/boot/loader/entries/noid-generic-fallback-*.conf'" \
    "$TMPDIR/boot-mutation-guard" "active Generic recovery BLS blocks other writers"
assert_grep_fixed 'a GRUB one-shot boot entry is still armed' \
    "$TMPDIR/boot-mutation-guard" "armed next_entry blocks other writers"
assert_grep_fixed '1:--snapper-resume) allow_snapper_resume=1' \
    "$TMPDIR/boot-mutation-guard" "only the named Snapper recovery path can resume"
assert_grep_fixed 'validate_snapper_record "$SNAPPER_PENDING" pending' \
    "$TMPDIR/boot-mutation-guard" "pending rollback evidence is validated fail-closed"
assert_grep_fixed 'validate_snapper_record "$SNAPPER_READY" ready' \
    "$TMPDIR/boot-mutation-guard" "published rollback evidence is validated fail-closed"
assert_grep_fixed 'matchpathcon -V "$path"' \
    "$TMPDIR/boot-mutation-guard" \
    "boot guard authenticates each Snapper record SELinux label"
assert_grep_fixed 'Snapper stable state directory metadata or SELinux label differs' \
    "$TMPDIR/boot-mutation-guard" \
    "boot guard rejects an unlabeled persistent rollback boundary"
assert_grep_fixed 'a Snapper rollback root is selected; reboot before changing /boot' \
    "$TMPDIR/boot-mutation-guard" "selected next root blocks every ordinary boot writer"
assert_grep_fixed 'Snapper resume was requested without a pending transaction' \
    "$TMPDIR/boot-mutation-guard" "resume exception cannot open without pending evidence"
assert_grep_fixed 'basis_record=$(/usr/libexec/noid-boot-mutation-guard)' \
    "$TMPDIR/dracut-regenerate-all" "later rebuild binds validation to the guarded basis"
assert_grep_fixed 'dracut_basis_args=(--hostonly --hostonly-mode sloppy --no-hostonly-cmdline)' \
    "$TMPDIR/dracut-regenerate-all" "confirmed basis explicitly pins sloppy host-only rebuilds"
assert_grep_fixed 'dracut_basis_args=(--no-hostonly)' \
    "$TMPDIR/dracut-regenerate-all" "recovered basis explicitly pins Generic rebuilds"
assert_grep_fixed 'dracut --force "${dracut_basis_args[@]}" "$candidate" "$kernel"' \
    "$TMPDIR/dracut-regenerate-all" "every later candidate consumes the guarded basis arguments"
assert_grep_fixed 'candidate=$(mktemp "/boot/.initramfs-${kernel}.noid-candidate.XXXXXX")' \
    "$TMPDIR/dracut-regenerate-all" "later rebuild writes away from every BLS image path"
assert_grep_fixed 'mv -fT -- "$candidate" "$final"' \
    "$TMPDIR/dracut-regenerate-all" "later rebuild publication is same-filesystem atomic"
metadata_line=$(grep -nF 'restorecon -F "$candidate"' \
    "$TMPDIR/dracut-regenerate-all" | cut -d: -f1 || true)
publish_line=$(grep -nF 'mv -fT -- "$candidate" "$final"' \
    "$TMPDIR/dracut-regenerate-all" | cut -d: -f1 || true)
evidence_line=$(grep -nF '"$evidence_helper" "$kernel"' \
    "$TMPDIR/dracut-regenerate-all" | cut -d: -f1 || true)
if [ -n "$metadata_line" ] && [ -n "$publish_line" ] \
        && [ "$metadata_line" -lt "$publish_line" ]; then
    _pass "candidate metadata and SELinux context are final before publication"
else
    _fail "candidate can publish before metadata/context finalization"
fi
if [ -n "$publish_line" ] && [ -n "$evidence_line" ] \
        && [ "$publish_line" -lt "$evidence_line" ]; then
    _pass "M19 evidence is rebound only after the validated image publishes"
else
    _fail "M19 evidence can be rebound before its image publication"
fi
assert_grep_fixed 'Generic candidate for $kernel unexpectedly contains the M21 marker' \
    "$TMPDIR/dracut-regenerate-all" "recovered Generic cannot silently become host-only"
assert_grep_fixed 'host-only candidate for $kernel lacks the M21 marker' \
    "$TMPDIR/dracut-regenerate-all" "confirmed host-only retains its marker"
assert_grep_fixed 'nvidia_base=/usr/lib/modules/$kernel/extra/nvidia/nvidia.ko' \
    "$TMPDIR/dracut-regenerate-all" "NVIDIA validation follows M19's per-kernel presence rule"
assert_grep_fixed 'enrolled NVIDIA identity verification failed for $kernel' \
    "$TMPDIR/dracut-regenerate-all" "normal rebuilds require exact enrolled M19 identity"
assert_grep_fixed 'candidate_nvidia_verified=1' \
    "$TMPDIR/dracut-regenerate-all" \
    "evidence bridge is gated by exact candidate NVIDIA validation"
assert_grep_fixed " = '0:0:755:1' ]" \
    "$TMPDIR/dracut-regenerate-all" \
    "evidence bridge requires exact root-owned executable metadata"
assert_grep_fixed 'NVIDIA pre-reboot evidence reconciliation failed for $kernel' \
    "$TMPDIR/dracut-regenerate-all" \
    "evidence reconciliation failure makes the canonical writer fail closed"
assert_grep_fixed 'candidate for $kernel retained unmanaged proprietary NVIDIA objects' \
    "$TMPDIR/dracut-regenerate-all" "NVIDIA rollback cannot retain stale embedded objects"
assert_grep_fixed 'for required in kernel-modules rootfs-block plymouth; do' \
    "$TMPDIR/dracut-regenerate-all" "later images retain universal boot modules"
assert_grep_fixed 'for required in crypt dm systemd-cryptsetup; do' \
    "$TMPDIR/dracut-regenerate-all" "later images retain complete mapped-root modules"
assert_grep_fixed 'for required in dm_crypt drbg; do' \
    "$TMPDIR/dracut-regenerate-all" "later images retain loadable crypto objects"
assert_grep_fixed 'candidate for $kernel lacks root-path driver' \
    "$TMPDIR/dracut-regenerate-all" "later images retain every live root controller"
assert_grep_fixed 'root_driver_is_kernel_integrated "$controller_module"' \
    "$TMPDIR/dracut-regenerate-all" \
    "later rebuilds distinguish integrated root drivers from missing objects"
assert_grep_fixed 'candidate for $kernel retained an omitted FireWire object' \
    "$TMPDIR/dracut-regenerate-all" "later images preserve the FireWire omission"
assert_grep_fixed 'reserved stale candidate is not a regular file' \
    "$TMPDIR/dracut-regenerate-all" "power-loss candidates are safely type-checked before cleanup"
assert_not_grep_fixed '--lock-owner=' "$TMPDIR/dracut-regenerate-all" \
    "regenerator has no process-claim authority path"
assert_grep_fixed 'inherited descriptor does not name the boot-mutation lock' \
    "$TMPDIR/dracut-regenerate-all" "regenerator verifies the inherited lock identity"
assert_grep_fixed 'dracut --force --regenerate-all --no-hostonly' "$KS_FILE" \
    "Live/installer initramfs is explicitly generic"
assert_grep_fixed '! cmp -s "$BLACKLIST_CONFIG"' "$KS_FILE" \
    "compose verifies exact embedded blacklist bytes"
assert_grep_fixed 'exact blacklist policy bytes missing from $initramfs' "$KS_FILE" \
    "compose rejects a present-but-stale blacklist"
gsc_validator_count=$(grep -cF 'for required in mei_me mei_gsc_proxy; do' \
    "$KS_FILE" || true)
assert_eq 5 "$gsc_validator_count" \
    "guard, later rebuild, host-only, Generic and compose paths validate Intel GSC bytes"
assert_grep_fixed 'candidate for $kernel lacks exact Intel GSC dependency bytes: $required' \
    "$TMPDIR/dracut-regenerate-all" \
    "later atomic rebuild requires exact target-kernel GSC bytes"
assert_grep_fixed 'candidate $image lacks exact Intel GSC dependency bytes: $required' \
    "$TMPDIR/hostonly.sh" \
    "host-only candidate requires exact target-kernel GSC bytes"
assert_grep_fixed 'validate_generic_image "$STANDARD_IMAGE" "$kernel"' \
    "$TMPDIR/hostonly.sh" \
    "Generic recovery validation is bound to the target kernel"
assert_grep_fixed 'the running initramfs lacks exact Intel GSC dependency bytes: $required' \
    "$TMPDIR/boot-mutation-guard" \
    "writer guard verifies the running image's exact GSC bytes"
assert_not_grep_fixed 'case "$module_rel" in lib/modules/*)' "$KS_FILE" \
    "resolved module paths have no unreachable pre-usrmerge normalization"
assert_not_grep_fixed 'case "$module_rel" in lib/modules/*)' "$RUNTIME_GATE" \
    "runtime gate consumes the canonical path returned by readlink"
assert_grep_fixed 'exact Intel GSC dependency bytes missing from $initramfs: $required' \
    "$KS_FILE" "compose verifies every Generic image's exact GSC bytes"
publication_arm_line=$(grep -nF 'publication_active=1' "$TMPDIR/hostonly.sh" \
    | head -n 1 | cut -d: -f1 || true)
hostonly_publish_line=$(grep -nF 'publish_hostonly_inputs' "$TMPDIR/hostonly.sh" \
    | tail -n 1 | cut -d: -f1 || true)
dracut_stage_line=$(grep -nF 'if ! dracut --force --hostonly' "$TMPDIR/hostonly.sh" \
    | cut -d: -f1 || true)
if [ -n "$publication_arm_line" ] && [ -n "$hostonly_publish_line" ] \
   && [ -n "$dracut_stage_line" ] \
   && [ "$publication_arm_line" -lt "$hostonly_publish_line" ] \
   && [ "$hostonly_publish_line" -lt "$dracut_stage_line" ]; then
    _pass "rollback is armed before host-only inputs and staged dracut"
else
    _fail "host-only input publication can precede rollback arming"
fi
assert_grep_fixed 'dracut --force --hostonly --hostonly-mode sloppy --no-hostonly-cmdline' \
    "$TMPDIR/hostonly.sh" "staged candidate explicitly forces sloppy host-only"
assert_not_grep '^ProtectKernelModules=yes$' "$TMPDIR/hostonly.service" \
    "dracut service can see installed kernel modules"
assert_grep_fixed 'CapabilityBoundingSet=~CAP_SYS_MODULE' "$TMPDIR/hostonly.service" \
    "dracut service cannot load kernel modules"
assert_grep_fixed 'SystemCallFilter=~@module' "$TMPDIR/hostonly.service" \
    "dracut service denies module-loading syscall class"
assert_grep_fixed 'stage_dir=$(mktemp -d /var/tmp/noid-hostonly-stage.XXXXXX)' \
    "$TMPDIR/hostonly.sh" "candidate is built away from the standard /boot path"
assert_grep_fixed 'hostonly="yes"' "$TMPDIR/hostonly.sh"
assert_grep_fixed 'hostonly_mode="sloppy"' "$TMPDIR/hostonly.sh"
assert_grep_fixed 'etc/noid-privacy/initramfs-hostonly' "$TMPDIR/hostonly.sh" \
    "candidate must contain the host-only policy marker"
assert_grep_fixed 'simple-single-device-luks2-btrfs' "$TMPDIR/hostonly.sh" \
    "expected root topology receives the strict storage postcondition"
assert_grep_fixed "grep -Eq '^(mdraid|iscsi|fcoe|nbd)$'" "$TMPDIR/hostonly.sh" \
    "unused storage modules fail on the expected simple root"
assert_grep_fixed 'for required in kernel-modules rootfs-block; do' \
    "$TMPDIR/hostonly.sh" "universal root-critical Dracut modules are validated"
assert_grep_fixed 'if [ "${ROOT_FSTYPE-}" = btrfs ] && ! grep -qx btrfs' \
    "$TMPDIR/hostonly.sh" "Btrfs is required only for a Btrfs root"
assert_grep_fixed 'if grep -qw crypt <<<"${ROOT_TYPES-}"; then' \
    "$TMPDIR/hostonly.sh" "crypt/dm are required only for a mapped root"
assert_grep_fixed 'for required in crypt dm systemd-cryptsetup; do' \
    "$TMPDIR/hostonly.sh" "mapped root requires the complete Fedora unlock module set"
assert_grep_fixed 'usr/bin/systemd-cryptsetup' "$TMPDIR/hostonly.sh" \
    "mapped root requires the actual unlock executable"
assert_grep_fixed 'for required in dm_crypt drbg; do' "$TMPDIR/hostonly.sh" \
    "mapped root resolves named kernel unlock components"
assert_grep_fixed 'candidate lacks root-unlock kernel object' "$TMPDIR/hostonly.sh" \
    "loadable dm-crypt dependencies must exist in the candidate"
assert_grep_fixed \
    "grep -Eq '/firewire-(core|net|ohci|sbp2)\\.ko" \
    "$TMPDIR/hostonly.sh" "FireWire checks inspect kernel objects, not lsinitrd -m labels"
assert_grep_fixed 'while [[ "$device_path" == /sys/devices/* ]]; do' \
    "$TMPDIR/hostonly.sh" "root-disk driver ancestors are traversed"
assert_grep_fixed 'controller_path=$(modinfo -k "$kernel" -n "$controller_module"' \
    "$TMPDIR/hostonly.sh" "loadable root-path driver ownership is resolved"
assert_grep_fixed 'root_driver_is_kernel_integrated "$controller_module"' \
    "$TMPDIR/hostonly.sh" \
    "firstboot distinguishes integrated root drivers from missing objects"
assert_grep_fixed 'candidate lacks root-path driver object' "$TMPDIR/hostonly.sh" \
    "every loadable root-path driver object is required in the candidate"

awk '
    /^root_driver_is_kernel_integrated\(\)/ { copy=1 }
    copy { print }
    copy && /^}/ { exit }
' "$TMPDIR/hostonly.sh" > "$TMPDIR/root-driver-integrated.function"
fixture_sysfs="$TMPDIR/sys/module"
sed -i "s#module_root=/sys/module/\$module#module_root=$fixture_sysfs/\$module#" \
    "$TMPDIR/root-driver-integrated.function"
mkdir -p "$fixture_sysfs/pcieportdrv" "$fixture_sysfs/nvme"
: > "$fixture_sysfs/nvme/initstate"
assert_cmd_success "kernel-integrated root driver needs no initramfs object" \
    bash -c '. "$1"; root_driver_is_kernel_integrated pcieportdrv' _ \
    "$TMPDIR/root-driver-integrated.function"
assert_cmd_failure "dynamic root driver still requires its initramfs object" \
    bash -c '. "$1"; root_driver_is_kernel_integrated nvme' _ \
    "$TMPDIR/root-driver-integrated.function"
assert_cmd_failure "missing root-driver owner is not treated as integrated" \
    bash -c '. "$1"; root_driver_is_kernel_integrated vanished' _ \
    "$TMPDIR/root-driver-integrated.function"
assert_cmd_failure "malformed root-driver identity fails closed" \
    bash -c '. "$1"; root_driver_is_kernel_integrated "bad/name"' _ \
    "$TMPDIR/root-driver-integrated.function"
assert_not_grep 'omit_dracutmodules' "$TMPDIR/hostonly.sh" \
    "installed convergence never globally omits storage stacks"
assert_not_grep 'dracut --force --regenerate-all --hostonly' "$TMPDIR/hostonly.sh" \
    "firstboot never overwrites all standard images before validation"
assert_not_grep 'omit_dracutmodules+=' "$KS_FILE" \
    "source ships no static mdraid/iSCSI/FCoE/NBD omit"
assert_not_grep_extended 'compress="lz4"|99-noid-compress.conf <<' "$KS_FILE" \
    "unbenchmarked LZ4 override is not shipped"

# Generic recovery is a real BLS boot path and publication order is closed:
# Generic copy -> entry -> saved recovery default -> candidate rename ->
# durable pending state -> one-shot host-only boot -> boot-bound first-login
# request -> durable request -> committed transaction.
assert_grep_fixed 'FALLBACK_IMAGE=/boot/initramfs-$kernel.noid-generic-fallback.img' \
    "$TMPDIR/hostonly.sh"
assert_grep_fixed 'FALLBACK_BLS=/boot/loader/entries/noid-generic-fallback-$kernel.conf' \
    "$TMPDIR/hostonly.sh"
assert_grep_fixed 'noid.initramfs=generic-fallback' "$TMPDIR/hostonly.sh"
assert_grep_fixed 'Generic Initramfs Recovery' "$TMPDIR/hostonly.sh"
assert_grep_fixed 'candidate_bytes + generic_bytes + minimum_headroom' \
    "$TMPDIR/hostonly.sh" \
    "/boot preflight covers both new images plus explicit headroom"
generic_copy_line=$(grep -n 'mv -fT -- "$FALLBACK_TMP" "$FALLBACK_IMAGE"' \
    "$TMPDIR/hostonly.sh" | cut -d: -f1 || true)
bls_publish_line=$(grep -n 'mv -fT -- "$bls_publish_tmp" "$FALLBACK_BLS"' \
    "$TMPDIR/hostonly.sh" | cut -d: -f1 || true)
saved_fallback_line=$(grep -n 'set_saved_entry "$FALLBACK_BLS_ID"' \
    "$TMPDIR/hostonly.sh" | cut -d: -f1 || true)
candidate_publish_line=$(grep -n 'mv -fT -- "$PUBLISH_TMP" "$STANDARD_IMAGE"' \
    "$TMPDIR/hostonly.sh" | tail -n 1 | cut -d: -f1 || true)
pending_state_line=$(grep -n 'write_state pending-reboot' "$TMPDIR/hostonly.sh" \
    | cut -d: -f1 || true)
next_entry_line=$(grep -n 'set_next_entry "$SOURCE_BLS_ID"' \
    "$TMPDIR/hostonly.sh" | cut -d: -f1 || true)
boot_success_request_line=$(grep -n \
    'mv -fT -- "$boot_success_tmp" "$BOOT_SUCCESS_REQUEST"' \
    "$TMPDIR/hostonly.sh" | cut -d: -f1 || true)
boot_success_sync_line=$(grep -n 'sync -- "$BOOT_SUCCESS_REQUEST"' \
    "$TMPDIR/hostonly.sh" | cut -d: -f1 || true)
commit_line=$(grep -n '^committed=1$' "$TMPDIR/hostonly.sh" \
    | cut -d: -f1 || true)
if [ -n "$generic_copy_line" ] && [ -n "$bls_publish_line" ] && \
   [ -n "$saved_fallback_line" ] && [ -n "$candidate_publish_line" ] && \
   [ -n "$pending_state_line" ] && [ -n "$next_entry_line" ] && \
   [ -n "$boot_success_request_line" ] && [ -n "$boot_success_sync_line" ] && \
   [ -n "$commit_line" ] && \
   [ "$generic_copy_line" -lt "$bls_publish_line" ] && \
   [ "$bls_publish_line" -lt "$saved_fallback_line" ] && \
   [ "$saved_fallback_line" -lt "$candidate_publish_line" ] && \
   [ "$candidate_publish_line" -lt "$pending_state_line" ] && \
   [ "$pending_state_line" -lt "$next_entry_line" ] && \
   [ "$next_entry_line" -lt "$boot_success_request_line" ] && \
   [ "$boot_success_request_line" -lt "$boot_success_sync_line" ] && \
   [ "$boot_success_sync_line" -lt "$commit_line" ]; then
    _pass "Generic fallback, one-shot candidate and success request publish atomically"
else
    _fail "Generic fallback, candidate or success-request publication order is unsafe"
fi
assert_grep_fixed 'sync -- "$FALLBACK_BLS"' "$TMPDIR/hostonly.sh"
assert_grep_fixed 'sync -- "$FALLBACK_IMAGE"' "$TMPDIR/hostonly.sh"
assert_grep_fixed 'sync -- "$STANDARD_IMAGE"' "$TMPDIR/hostonly.sh"
assert_grep_fixed 'sync -- /boot' "$TMPDIR/hostonly.sh" \
    "publication fsyncs the boot-directory metadata boundary"
assert_grep_fixed 'set_saved_entry "$FALLBACK_BLS_ID"' "$TMPDIR/hostonly.sh" \
    "Generic recovery is the persistent default during the boot trial"
assert_grep_fixed 'set_next_entry "$SOURCE_BLS_ID"' "$TMPDIR/hostonly.sh" \
    "host-only candidate is selected for exactly one trial boot"
assert_grep_fixed 'set_saved_entry "$SOURCE_BLS_ID"' "$TMPDIR/hostonly.sh" \
    "normal entry is restored only on confirmation/recovery"
assert_not_grep_fixed 'rm -f -- "$STANDARD_IMAGE"' "$TMPDIR/hostonly.sh" \
    "Generic restore never creates a missing-standard-image window"

# Power interruption and post-boot phases are explicit. A fallback boot
# restores Generic; only a different boot-id on the target kernel can complete.
assert_grep_fixed 'interrupted publication detected; restoring generic image' \
    "$TMPDIR/hostonly.sh"
assert_grep_fixed 'restore_generic "$kernel"' "$TMPDIR/hostonly.sh"
assert_grep_fixed 'case "$phase" in' "$TMPDIR/hostonly.sh"
assert_grep_fixed 'pending-reboot)' "$TMPDIR/hostonly.sh"
assert_grep_fixed 'recovered-generic)' "$TMPDIR/hostonly.sh"
assert_grep_fixed 'complete)' "$TMPDIR/hostonly.sh"
assert_grep_fixed 'if [ "$current_boot_id" = "$prepared_boot_id" ]; then' \
    "$TMPDIR/hostonly.sh" "same-boot content validation is not a bootability claim"
assert_grep_fixed 'generic recovery boot detected; generic image restored as the default' \
    "$TMPDIR/hostonly.sh"
assert_grep_fixed 'marker-less pending image is not a valid Generic recovery' \
    "$TMPDIR/hostonly.sh" \
    "pending recovery rejects an arbitrary marker-less image"
assert_grep_fixed 'interrupted Generic restoration completed from the booted standard image' \
    "$TMPDIR/hostonly.sh" \
    "a hard cut after Generic publication self-heals on the next boot"
assert_grep_fixed 'host-only candidate boot confirmed; generic fallback retired' \
    "$TMPDIR/hostonly.sh"
assert_grep_fixed 'reconstructed confirmed host-only config, marker and state after root rollback' \
    "$TMPDIR/hostonly.sh" "root rollback repairs every rollback-local host-only input"
assert_grep_fixed 'sync -- "$STATE_DIR"' "$TMPDIR/hostonly.sh" \
    "M21 state renames synchronize parent-directory metadata"
assert_grep_fixed 'sync -- /etc/dracut.conf.d /etc/noid-privacy' \
    "$TMPDIR/hostonly.sh" \
    "host-only policy publication and retirement synchronize both directories"
assert_grep_fixed 'private NoID Privacy state directory is unsafe' \
    "$TMPDIR/hostonly.sh" \
    "M21 rejects a redirected private NoID Privacy state boundary"
assert_grep_fixed '0:0:755)' "$TMPDIR/hostonly.sh" \
    "M21 recognizes only the exact historical widened directory mode"
assert_grep_fixed 'chmod 0700 /etc/noid-privacy' "$TMPDIR/hostonly.sh" \
    "M21 tightens the historical directory mode before marker publication"
assert_grep_fixed 'private NoID Privacy state directory did not converge to 0700' \
    "$TMPDIR/hostonly.sh" \
    "M21 verifies the shared private-directory postcondition"
assert_not_grep_fixed \
    'install -d -m 0755 -o root -g root /etc/dracut.conf.d /etc/noid-privacy' \
    "$TMPDIR/hostonly.sh" \
    "M21 never widens private NoID Privacy state while preparing public Dracut state"
assert_grep_fixed 'validate_state_file' "$TMPDIR/hostonly.sh" \
    "firstboot validates the exact state schema before acting"
assert_grep_fixed 'state key is missing or duplicated' "$TMPDIR/hostonly.sh" \
    "firstboot rejects duplicate or missing state keys"
assert_grep_fixed 'invalid prepared boot ID in state' "$TMPDIR/hostonly.sh" \
    "firstboot binds state to a canonical boot ID"
assert_grep_fixed 'running-kernel BLS entry is missing or unsafe' \
    "$TMPDIR/hostonly.sh" "recovery rejects a symlinked or non-regular source BLS"
assert_grep_fixed 'root:root:600|root:root:644' "$TMPDIR/hostonly.sh" \
    "recovery accepts only root-owned Fedora BLS metadata"
reconstruction_line=$(grep -nF 'if image_has_hostonly_marker "$STANDARD_IMAGE"; then' \
    "$TMPDIR/hostonly.sh" | cut -d: -f1 || true)
reconstruction_publish_line=''
if [ -n "$reconstruction_line" ]; then
    reconstruction_publish_line=$(tail -n +"$reconstruction_line" \
        "$TMPDIR/hostonly.sh" | grep -nF 'publish_hostonly_inputs' \
        | head -n 1 | cut -d: -f1 || true)
fi
if [ -n "$reconstruction_publish_line" ]; then
    _pass "state reconstruction republishes rollback-local Dracut inputs"
else
    _fail "state reconstruction omits rollback-local Dracut inputs"
fi

# Generic restore must stay bootable at every durable boundary. Retire an
# armed one-shot while the saved fallback remains complete, publish a copied
# Generic standard image, switch the saved default, and only then remove the
# fallback entry and image. Moving the only fallback image away before the
# GRUB default changes recreates an unbootable power-loss window.
restore_start=$(grep -n '^restore_generic() {' "$TMPDIR/hostonly.sh" \
    | cut -d: -f1 || true)
restore_end=$(grep -n '^if \[ -e "\$STATE_FILE" \]; then' \
    "$TMPDIR/hostonly.sh" | cut -d: -f1 || true)
if [[ $restore_start =~ ^[1-9][0-9]*$ ]] && \
        [[ $restore_end =~ ^[1-9][0-9]*$ ]] && \
        [ "$restore_start" -lt "$restore_end" ]; then
    _pass "Generic restore fixture extraction"
    sed -n "${restore_start},$((restore_end - 1))p" "$TMPDIR/hostonly.sh" \
        > "$TMPDIR/restore-generic.function"
else
    _fail "Generic restore fixture extraction"
    : > "$TMPDIR/restore-generic.function"
fi
restore_clear_line=$(grep -nF 'clear_next_entry || return 1' \
    "$TMPDIR/restore-generic.function" | cut -d: -f1 || true)
restore_validate_line=$(grep -nF \
    'validate_generic_image "$FALLBACK_IMAGE" "$kernel" || return 1' \
    "$TMPDIR/restore-generic.function" | cut -d: -f1 || true)
restore_copy_line=$(grep -nF \
    'install -m 0600 -o root -g root "$FALLBACK_IMAGE" "$PUBLISH_TMP"' \
    "$TMPDIR/restore-generic.function" | cut -d: -f1 || true)
restore_publish_line=$(grep -nF 'mv -fT -- "$PUBLISH_TMP" "$STANDARD_IMAGE"' \
    "$TMPDIR/restore-generic.function" | cut -d: -f1 || true)
restore_default_line=$(grep -nF 'set_saved_entry "$SOURCE_BLS_ID"' \
    "$TMPDIR/restore-generic.function" | cut -d: -f1 || true)
restore_retire_line=$(grep -nF 'rm -f -- "$FALLBACK_BLS" "$FALLBACK_IMAGE"' \
    "$TMPDIR/restore-generic.function" | cut -d: -f1 || true)
if [ -n "$restore_validate_line" ] && [ -n "$restore_clear_line" ] \
   && [ -n "$restore_copy_line" ] \
   && [ -n "$restore_publish_line" ] && [ -n "$restore_default_line" ] \
   && [ -n "$restore_retire_line" ] \
   && [ "$restore_validate_line" -lt "$restore_clear_line" ] \
   && [ "$restore_clear_line" -lt "$restore_copy_line" ] \
   && [ "$restore_copy_line" -lt "$restore_publish_line" ] \
   && [ "$restore_publish_line" -lt "$restore_default_line" ] \
   && [ "$restore_default_line" -lt "$restore_retire_line" ]; then
    _pass "Generic restore has no missing saved-image power-loss window"
else
    _fail "Generic restore publication order can strand the saved GRUB entry"
fi
assert_not_grep_fixed 'mv -fT -- "$FALLBACK_IMAGE" "$STANDARD_IMAGE"' \
    "$TMPDIR/restore-generic.function" \
    "Generic restore never moves away the image named by the saved fallback"
assert_grep_fixed '= root:root:600' "$TMPDIR/restore-generic.function" \
    "Generic restore requires safe fallback ownership and mode"
assert_grep_fixed '[ -f "$image" ] && [ ! -L "$image" ] || return 1' \
    "$TMPDIR/hostonly.sh" "Generic validation rejects symlinked images"
assert_grep_fixed 'grub2-editenv - unset next_entry' "$TMPDIR/hostonly.sh" \
    "recovery durably retires an already-armed one-shot entry"
assert_eq 5 "$(grep -cF 'sync -- /boot || return 1' "$TMPDIR/hostonly.sh")" \
    "conditional GRUB/restore helpers propagate every boot-directory sync failure"
assert_eq 3 "$(grep -cF 'sync -- /boot/grub2/grubenv || return 1' \
    "$TMPDIR/hostonly.sh")" \
    "conditional GRUB helpers propagate every environment-block sync failure"
assert_eq 3 "$(grep -cF 'sync -- /boot/grub2 || return 1' \
    "$TMPDIR/hostonly.sh")" \
    "conditional GRUB helpers synchronize the direct grubenv parent"
assert_grep_fixed 'sync -- /boot/loader/entries || return 1' \
    "$TMPDIR/restore-generic.function" \
    "Generic restore synchronizes fallback-entry retirement"
assert_grep_fixed 'grub_env=$(grub2-editenv - list) || return 1' \
    "$TMPDIR/hostonly.sh" \
    "GRUB environment reads cannot collapse an I/O error into an empty value"
state_write_started_line=$(grep -n '^state_published=1$' "$TMPDIR/hostonly.sh" \
    | cut -d: -f1 || true)
pending_write_line=$(grep -nF \
    'write_state pending-reboot "$root_class" "$kernel" "$prepared_boot_id"' \
    "$TMPDIR/hostonly.sh" | cut -d: -f1 || true)
if [ -n "$state_write_started_line" ] && [ -n "$pending_write_line" ] \
   && [ "$state_write_started_line" -lt "$pending_write_line" ]; then
    _pass "cleanup can repair a partially published pending state"
else
    _fail "pending-state publication can fail before cleanup is armed"
fi
assert_not_grep_fixed 'grub2-set-bootflag menu_show_once' "$TMPDIR/hostonly.sh" \
    "planned host-only trial does not force a visible GRUB menu"
assert_grep_fixed \
    'BOOT_SUCCESS_REQUEST=/run/noid-privacy/hostonly-boot-success-needed' \
    "$TMPDIR/hostonly.sh" "publication owns the ephemeral first-login request"
assert_grep_fixed 'chmod 0444 "$boot_success_tmp"' "$TMPDIR/hostonly.sh" \
    "ephemeral first-login request is root-published read-only"
assert_grep_fixed 'prepared_boot_id=%s' "$TMPDIR/hostonly.sh" \
    "ephemeral request is bound to the publishing boot"
assert_grep_fixed 'rm -f -- "$BOOT_SUCCESS_REQUEST"' "$TMPDIR/hostonly.sh" \
    "failed publication removes the uncommitted success request"
assert_grep_fixed '"$BOOTFLAG" boot_success' "$TMPDIR/hostonly-boot-success" \
    "first-login bridge invokes only Fedora's boot_success operation"
assert_not_grep_fixed 'menu_show_once' "$TMPDIR/hostonly-boot-success" \
    "first-login bridge cannot request a visible boot menu"
assert_grep_fixed 'root:root:4755' "$TMPDIR/hostonly-boot-success" \
    "bridge verifies Fedora's narrowly scoped SUID helper metadata"
assert_grep_fixed 'Requires=noid-user-firstrun.service' \
    "$TMPDIR/hostonly-boot-success.service" \
    "boot success requires the transactional NoID Privacy first-login service"
assert_grep_fixed 'After=noid-user-firstrun.service' \
    "$TMPDIR/hostonly-boot-success.service" \
    "boot success waits for transactional first-login completion"
assert_grep_fixed 'ConditionKernelCommandLine=!rd.live.image' \
    "$TMPDIR/hostonly-boot-success.service" "Live mode cannot mark boot success"
assert_grep_fixed 'ConditionEnvironment=XDG_SESSION_CLASS=user' \
    "$TMPDIR/hostonly-boot-success.service" \
    "only a real graphical-user manager can mark boot success"
assert_grep_fixed \
    'ConditionPathExists=/run/noid-privacy/hostonly-boot-success-needed' \
    "$TMPDIR/hostonly-boot-success.service" \
    "only the active M21 publication can request first-login boot success"
assert_grep_fixed 'ExecStart=/usr/libexec/noid-mark-hostonly-boot-success' \
    "$TMPDIR/hostonly-boot-success.service" \
    "user unit has one fixed boot-success helper"
assert_grep_fixed 'RemainAfterExit=yes' "$TMPDIR/hostonly-boot-success.service" \
    "successful path activation remains active instead of retriggering"
assert_grep_fixed \
    'PathExists=/run/noid-privacy/hostonly-boot-success-needed' \
    "$TMPDIR/hostonly-boot-success.path" \
    "user path closes the request-after-login race"
assert_grep_fixed 'Unit=noid-hostonly-boot-success.service' \
    "$TMPDIR/hostonly-boot-success.path" \
    "request watcher activates only the reviewed bridge"
assert_grep_fixed 'ConditionEnvironment=XDG_SESSION_CLASS=user' \
    "$TMPDIR/hostonly-boot-success.path" \
    "greeter and pseudo-user managers cannot arm the watcher"
assert_grep_fixed 'NoNewPrivileges=no' "$TMPDIR/hostonly-boot-success.service" \
    "user unit explicitly permits only the reviewed SUID helper transition"
assert_grep_fixed 'PrivateUsers=no' "$TMPDIR/hostonly-boot-success.service" \
    "user unit keeps Fedora's SUID helper in the host user namespace"
assert_not_grep_extended '^(ProtectSystem|ProtectHome|PrivateTmp)=' \
    "$TMPDIR/hostonly-boot-success.service" \
    "user unit has no filesystem namespace that implicitly enables PrivateUsers"
assert_grep_fixed \
    'noid-user-firstrun.service.wants/noid-hostonly-boot-success.service' \
    "$KS_FILE" "first-login boot-success unit is statically enabled via firstrun"
assert_grep_fixed \
    'noid-user-firstrun.service.wants/noid-hostonly-boot-success.path' \
    "$KS_FILE" "first-login starts the race-free request watcher"
assert_grep_fixed 'phase=pending-reboot with durable Generic recovery' \
    "$RUNTIME_GATE" "fresh VM pass requires the staged recovery boundary"
assert_grep_fixed 'distinct reboot confirmed, fallback retired' \
    "$RUNTIME_GATE" "reboot VM pass is the actual bootability gate"
assert_eq 3 "$(grep -c -- '--grep=.*host-only\|--grep=.*installed boot successful' \
    "$RUNTIME_GATE")" \
    "runtime journal evidence uses journalctl filtering without SIGPIPE races"
assert_not_grep_extended \
    "grep -q .*(marked the current installed boot successful|host-only candidate boot confirmed)" \
    "$RUNTIME_GATE" \
    "runtime journal evidence has no pipefail-prone grep -q consumer"
assert_grep_fixed 'first installed shutdown entered the retired mdraid wait path' \
    "$RUNTIME_GATE" "reboot VM pass rejects mdraid shutdown-wait evidence"
assert_grep_fixed 'runtime timestamps do not prove M20 completed before M21 started' \
    "$RUNTIME_GATE" "fresh VM pass proves cross-service runtime ordering"
assert_grep_fixed 'boot-mutation guard allowed pending-reboot' \
    "$RUNTIME_GATE" "fresh VM pass proves other writers fail closed"
assert_grep_fixed 'refused writer changed M21 transaction bytes' \
    "$RUNTIME_GATE" "refused writer is non-mutating during the boot trial"
assert_grep_fixed 'shared guard does not recognize the confirmed host-only basis' \
    "$RUNTIME_GATE" "reboot VM pass opens the confirmed host-only terminal basis"
assert_grep_fixed 'runtime timestamps do not prove M01 completed before M20 started' \
    "$RUNTIME_GATE" "fresh VM pass proves the full M01 to M20 to M21 chain"
assert_not_grep_fixed 'entry.get("_CODE_FUNC")' "$RUNTIME_GATE" \
    "M01/M20 ordering does not require optional systemd source-location metadata"
assert_grep_fixed 'entry.get("_PID") == "1"' "$RUNTIME_GATE" \
    "M01/M20 ordering binds completion to journald-trusted PID 1 evidence"
assert_grep_fixed 'entry.get("_UID") == "0"' "$RUNTIME_GATE" \
    "M01/M20 ordering binds completion to journald-trusted root identity"
assert_grep_fixed 'entry.get("_EXE") == "/usr/lib/systemd/systemd"' \
    "$RUNTIME_GATE" "M01/M20 ordering binds completion to the systemd executable"
assert_grep_fixed 'entry.get("_SYSTEMD_UNIT") == "init.scope"' \
    "$RUNTIME_GATE" "M01/M20 ordering binds completion to PID 1's trusted unit"
assert_grep_fixed 'entry.get("TID") == "1"' "$RUNTIME_GATE" \
    "M01/M20 ordering binds completion to the system manager"
assert_grep_fixed 'entry.get("JOB_RESULT") == "done"' "$RUNTIME_GATE" \
    "M01/M20 ordering accepts only a successful completed start job"
assert_grep_fixed 'Generic BLS options are not exact normal options plus one recovery marker' \
    "$RUNTIME_GATE" "fresh VM pass proves the cross-module BLS byte contract"
assert_grep_fixed 'bls != kernel + [TUNED_BLS_ARG, FALLBACK_ARG]' \
    "$KARG_CONTRACT" \
    "M01 parity permits only Fedora's tuned macro then the M21 recovery marker"
assert_grep_fixed 'expected_recovery_entries = 1 if expected_phase == "pending-reboot" else 0' \
    "$KARG_CONTRACT" "M01/M21 lifecycle fixes recovery-entry cardinality"
assert_grep_fixed 'runtime image lacks exact Intel GSC dependency bytes: $required' \
    "$RUNTIME_GATE" "runtime gate proves exact GSC objects in the booted image"
assert_grep_fixed 'prepared_boot_id=$(cat /proc/sys/kernel/random/boot_id)' \
    "$POWERLOSS_GATE" "power-loss injection stops at the pre-state boundary"
assert_grep_fixed 'kill -STOP "$BASHPID"' "$POWERLOSS_GATE" \
    "power-loss injection holds the exact helper without changing its bytes"
assert_grep_fixed 'virsh destroy <disposable-domain>' "$POWERLOSS_GATE" \
    "power-loss gate requires a host-side hard cut"
assert_grep_fixed 'virtualization=$(systemd-detect-virt --vm 2>/dev/null || true)' \
    "$POWERLOSS_GATE" "destructive power-loss gate detects its VM boundary"
assert_grep_fixed 'kvm|qemu)' "$POWERLOSS_GATE" \
    "destructive power-loss gate accepts only QEMU/KVM guests"
assert_not_grep_fixed '--collect' "$POWERLOSS_GATE" \
    "failed transient injection units remain inspectable before cleanup"
assert_grep_fixed 'select-recovery|recover|arm|verify' "$POWERLOSS_GATE" \
    "power-loss gate exposes the explicit recovery observation action"
assert_grep_fixed 'recovery observation is only valid in the temporary Generic entry' \
    "$POWERLOSS_GATE" "recovery observation proves the Generic boot marker"
assert_grep_fixed 'temporary Generic recovery entry is not an allowed writer basis' \
    "$POWERLOSS_GATE" "temporary fallback cannot open the writer guard"
assert_grep_fixed 'phase=post-cut-recovery-observed' "$POWERLOSS_GATE" \
    "post-cut recovery publishes a durable observation checkpoint"
assert_grep_fixed 'power-loss arm checkpoint boot_id=$current_boot_id' \
    "$POWERLOSS_GATE" "arm publishes an exact injected-boot journal marker"
assert_grep_fixed 'journalctl --sync' "$POWERLOSS_GATE" \
    "arm fsynchronizes its abrupt-boot journal evidence before READY"
assert_grep_fixed 'sync -- /boot/grub2' "$POWERLOSS_GATE" \
    "recovery selection synchronizes the direct grubenv parent"
assert_eq 4 "$(grep -c -- '--grep=' "$POWERLOSS_GATE")" \
    "power-loss journal evidence uses journalctl filtering without SIGPIPE races"
assert_not_grep_extended 'journalctl .*\|[[:space:]]*grep -[EF]*q' \
    "$POWERLOSS_GATE" \
    "power-loss journal evidence has no pipefail-prone grep -q consumer"
assert_grep_fixed 'normalize_boot_id' "$POWERLOSS_GATE" \
    "proc and journal boot-ID encodings are compared canonically"
assert_grep_fixed 'final verification lacks three distinct lifecycle boots' \
    "$POWERLOSS_GATE" "final proof binds interrupted, recovery and stable boots"
assert_grep_fixed 'final restored Generic basis remains locked out' \
    "$POWERLOSS_GATE" "power-loss VM pass opens only fully restored Generic"
assert_grep_fixed 'hard power loss not proven' "$POWERLOSS_GATE" \
    "clean guest shutdown cannot masquerade as power loss"

assert_not_grep_extended '^Before=(multi-user|graphical)\.target' \
    "$TMPDIR/hostonly.service" \
    "long Dracut convergence is absent from the login critical path"
assert_grep_fixed 'Requires=noid-snapper-init.service' "$TMPDIR/hostonly.service" \
    "M21 does not publish if M20 root/BLS finalization fails"
assert_grep_fixed 'After=local-fs.target noid-snapper-init.service' \
    "$TMPDIR/hostonly.service" "M21 runs after M20 root/BLS finalization"
assert_grep_fixed 'Requires=noid-snapper-init.service systemd-tmpfiles-setup.service' \
    "$TMPDIR/hostonly.service" \
    "host-only convergence requires its shared runtime directory owner"
assert_grep_fixed 'After=local-fs.target noid-snapper-init.service systemd-tmpfiles-setup.service' \
    "$TMPDIR/hostonly.service" \
    "host-only convergence waits for shared runtime directory creation"
assert_not_grep '^RuntimeDirectory=noid-privacy$' "$TMPDIR/hostonly.service" \
    "stopping the boot oneshot cannot delete unrelated runtime state"
assert_grep_fixed 'RequiresMountsFor=/boot' "$TMPDIR/hostonly.service"
assert_grep_fixed 'ConditionKernelCommandLine=!rd.live.image' "$TMPDIR/hostonly.service"
assert_not_grep 'ConditionPathExists=!/var/lib/noid-privacy/dracut-hostonly.state' \
    "$TMPDIR/hostonly.service" "service remains available for next-boot confirmation"
assert_grep_fixed 'ExecStart=/usr/libexec/noid-dracut-hostonly-configure' \
    "$TMPDIR/hostonly.service"
assert_grep_fixed 'Nice=19' "$TMPDIR/hostonly.service" \
    "firstboot Dracut yields process scheduling priority"
assert_grep_fixed 'CPUWeight=10' "$TMPDIR/hostonly.service" \
    "firstboot Dracut yields CPU under contention"
assert_grep_fixed 'IOWeight=10' "$TMPDIR/hostonly.service" \
    "firstboot Dracut yields storage under contention"
assert_grep_fixed 'IOSchedulingClass=idle' "$TMPDIR/hostonly.service" \
    "firstboot Dracut uses idle I/O scheduling"
assert_grep_fixed 'OnActiveSec=1s' "$TMPDIR/hostonly.timer" \
    "native timer dispatches convergence outside target activation"
assert_grep_fixed 'AccuracySec=1s' "$TMPDIR/hostonly.timer" \
    "one-shot timer has deterministic release timing"
assert_grep_fixed 'Unit=noid-dracut-hostonly-firstboot.service' \
    "$TMPDIR/hostonly.timer" \
    "timer activates exactly the transactional convergence service"
assert_grep_fixed 'systemctl disable noid-dracut-hostonly-firstboot.service' \
    "$KS_FILE" "legacy critical-path service enablement is retired"
assert_grep_fixed 'systemctl enable noid-dracut-hostonly-firstboot.timer' \
    "$KS_FILE" "only the nonblocking native timer is enabled"

# Native binfmt activation is masked; the old udev RUN race is absent.
assert_grep_fixed \
    'for unit in proc-sys-fs-binfmt_misc.automount systemd-binfmt.service; do' \
    "$KS_FILE" "both Fedora binfmt activation units are covered"
assert_grep_fixed 'systemctl mask "$unit"' "$KS_FILE"
assert_not_grep_extended 'ACTION=="add".*binfmt_misc|binfmt_misc.status=0' "$KS_FILE" \
    "racy special-file udev write retired"

# Documentation and cross-module prerequisites must state real boundaries.
assert_grep_fixed 'They are not a security boundary against privileged root' \
    "$TMPDIR/module-policy.md"
assert_grep_fixed 'does **not** ship a global' "$TMPDIR/module-policy.md"
assert_grep_fixed 'waiting for mdraid devices to be clean' "$TMPDIR/module-policy.md"
assert_grep_fixed 'coordination contract for maintained NoID Privacy tooling' \
    "$TMPDIR/module-policy.md" "documentation states the unmanaged-root lock boundary"
assert_grep_fixed 'switches the saved default only after both paths are bootable' \
    "$TMPDIR/module-policy.md" \
    "documentation states the power-loss-safe Generic restore ordering"
assert_grep_fixed 'passes the complete Generic byte checks' \
    "$TMPDIR/module-policy.md" \
    "documentation states the interrupted-restore validation boundary"
assert_grep_fixed 'This proves the' "$TMPDIR/module-policy.md" \
    "documentation defines what the reboot gate actually proves"
assert_grep_fixed 'not the later graphical session' "$TMPDIR/module-policy.md" \
    "documentation does not overclaim full-session recovery"
assert_grep_fixed 'ordinary real-root/userspace recovery boundary' \
    "$TMPDIR/module-policy.md" \
    "documentation assigns post-M21 failures to their real recovery boundary"
assert_not_grep_fixed 'candidate cannot reach a successful user session' \
    "$KS_FILE" "M21 does not overclaim recovery through graphical login"
assert_grep_fixed 'sudo /usr/libexec/noid-dracut-regenerate-all' \
    "$TMPDIR/module-policy.md" "later policy edits use the real guarded rebuild path"
assert_not_grep_extended '^dracut[[:space:]]+--force' "$TMPDIR/module-policy.md" \
    "documentation does not expose a copy-pastable raw Dracut bypass"
assert_grep_fixed 'This describes the' "$TMPDIR/module-policy.md" \
    "internal candidate invocation is explicitly non-operator documentation"
assert_grep_fixed 'explicitly forces `--no-hostonly` for a recovered Generic' \
    "$TMPDIR/module-policy.md" "documentation binds later rebuilds to the terminal basis"
assert_not_grep 'sudo /usr/libexec/noid-dracut-hostonly-configure$' \
    "$TMPDIR/module-policy.md" "completed firstboot helper is not misdocumented as a later rebuild"
assert_not_grep_extended 'even by root|This image is not vulnerable|TRULY block AF_ALG' \
    "$TMPDIR/module-policy.md" "documentation avoids root/CVE overclaims"
assert_grep_fixed 'The UDF filesystem module is denied by default' \
    "$TMPDIR/module-policy.md" \
    "optical-media documentation discloses the UDF default deny"
assert_grep_fixed 'https://docs.kernel.org/admin-guide/thunderbolt.html' \
    "$TMPDIR/module-policy.md" "documentation cites the upstream Thunderbolt boundary"
assert_grep_fixed 'https://dracut-ng.github.io/dracut/man/dracut.conf.5.html' \
    "$TMPDIR/module-policy.md" "documentation cites current Dracut semantics"
assert_grep_fixed 'https://www.gnu.org/software/coreutils/manual/html_node/sync-invocation.html' \
    "$TMPDIR/module-policy.md" "documentation cites persistence semantics"
assert_grep_fixed 'https://messervices.cyber.gouv.fr/guides/' \
    "$TMPDIR/module-policy.md" "documentation cites the current ANSSI publication"
assert_grep_fixed 'sudo noid-toggle-bluetooth status        # expected: ENABLED' \
    "$TMPDIR/module-policy.md" "Bluetooth opt-in verifies the supported toggle contract"
assert_grep_fixed 'sudo noid-toggle-bluetooth off' \
    "$TMPDIR/module-policy.md" "Bluetooth opt-out returns through the supported toggle"
assert_grep_fixed '# expected: FULLY DISABLED' "$TMPDIR/module-policy.md" \
    "Bluetooth opt-out documents the complete privacy state"
assert_not_grep_extended 'Powered: yes|systemctl mask bluetooth\.service|To mask again' \
    "$TMPDIR/module-policy.md" \
    "Bluetooth documentation makes no unowned radio or service-mask promise"
assert_grep_fixed 'To re-enable the NFS and SMB/CIFS client modules:' \
    "$TMPDIR/module-policy.md" "network-filesystem example names its exact scope"
assert_grep_fixed 'for mod in cifs nfs nfsv3 nfsv4; do' \
    "$TMPDIR/module-policy.md" "network-filesystem example contains only that scope"
assert_not_grep_fixed 'for mod in cifs nfs nfsv3 nfsv4 gfs2 ksmbd; do' \
    "$TMPDIR/module-policy.md" "network-filesystem example has no false category claim"
assert_grep_fixed 'ANSSI R10 Opt-In' "$TMPDIR/module-policy.md" \
    "advanced module lock is attributed to the exact ANSSI recommendation"
assert_grep_fixed 'Hot-plugged hardware still works' "$TMPDIR/module-policy.md" \
    "ANSSI opt-in distinguishes already available drivers from new module loads"
assert_not_grep_fixed 'No USB devices, no new hardware after this!' \
    "$TMPDIR/module-policy.md" "ANSSI opt-in avoids an absolute hot-plug claim"
assert_eq 5 "$(grep -c '^# --- End optional:' "$TMPDIR/module-policy.md")" \
    "every manual opt-in block has an exact removal boundary"
assert_grep_fixed 'to remove the complete' "$TMPDIR/module-policy.md" \
    "optional module blocks document their supported undo path"
assert_not_grep_extended "Madaidan|Kicksecure|Thunderspy: all.*forever" \
    "$KS_FILE" "M21 avoids secondary or absolute source claims"
assert_grep_fixed '/usr/libexec/noid-verify-target-karg-payload >/dev/null' "$KS_FILE" \
    "compose gate executes M01's target-install karg payload verifier"
assert_grep_fixed "= root:root:755" "$KS_FILE" \
    "compose gate binds verifier ownership and executable mode"
assert_grep_fixed 'target-install module.sig_enforce=1 payload contract invalid' \
    "$KS_FILE" "invalid target-install signature enforcement remains fatal"
assert_not_grep_extended 'bls_missing_sig|no installed BLS entries were available' \
    "$KS_FILE" "compose gate does not misclassify build-topology BLS as the target"
assert_grep_fixed 'pre-ship runtime parser' "$KS_FILE" \
    "M21 names the effective installed BLS proof boundary"

test_finish

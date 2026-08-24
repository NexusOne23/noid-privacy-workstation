#!/bin/bash
# 10-pam-structural — verify Module 10 PAM + login + sudo + SUID + coredump
#
# Checks:
#   - faillock.conf: deny=10, unlock_time=900 (CIS L1), root_unlock_time=60 (STIG), even_deny_root
#   - pwquality.conf: minlen=15, no composition, blocklist/context checks,
#     enforce_for_root
#   - pwhistory.conf: explicit remember=10 + root enforcement
#   - logind drop-in: KillUserProcesses=yes, empty KillExcludeUsers + RemoveIPC
#   - exact local-account defaults + native yescrypt cost factor 8
#   - sudo-specific pam_systemd class=none without bypassing the PAM stack
#   - sudoers.d: timestamp_timeout=3 + exact DNF/DNF5 umask override
#   - Coredump Layer 5/6 plus native libvirt system-QEMU max_core ceiling
#   - native tmpfiles/dnf5 permission policy with five stripped and four
#     Fedora-native SUID paths
#   - maintained authselect local profile + five self-contained features

set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/10-pam-login.ks"
INHIBITOR_RUNTIME="$PROJECT_ROOT/tests/pre-ship/10-logind-inhibitors-runtime.sh"
LOGIN_RUNTIME="$PROJECT_ROOT/tests/pre-ship/10-login-privacy-runtime.sh"
HISTORY_RUNTIME="$PROJECT_ROOT/tests/pre-ship/10-bash-history-runtime.sh"
PERMISSION_RUNTIME="$PROJECT_ROOT/tests/pre-ship/10-permission-policy-runtime.sh"
LIBVIRT_RUNTIME="$PROJECT_ROOT/tests/pre-ship/10-libvirt-core-runtime.sh"

test_start "10-pam-structural"

assert_file_exists "$KS_FILE"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

extract_heredoc "$KS_FILE" "FAIL_EOF"     "$TMPDIR/faillock.conf" || _fail "faillock extraction"
extract_heredoc "$KS_FILE" "PWQ_EOF"      "$TMPDIR/pwquality.conf" || _fail "pwquality extraction"
extract_heredoc "$KS_FILE" "PWHIST_EOF"   "$TMPDIR/pwhistory.conf" || _fail "pwhistory extraction"
extract_heredoc "$KS_FILE" "LOGIND_EOF"   "$TMPDIR/logind.conf" || _fail "logind extraction"
extract_heredoc "$KS_FILE" "ACCESS_EOF"   "$TMPDIR/access.conf" || _fail "access.conf extraction"
extract_heredoc "$KS_FILE" "SUDO_PAM_ENV_EOF" "$TMPDIR/pam_env-sudo.conf" || _fail "sudo PAM environment extraction"
extract_heredoc "$KS_FILE" "SUDO_EOF"     "$TMPDIR/sudoers.conf" || _fail "sudoers extraction"
extract_heredoc "$KS_FILE" "NOFQDN_EOF"   "$TMPDIR/sudoers-nofqdn.conf" || _fail "!fqdn sudoers extraction"
extract_heredoc "$KS_FILE" "SYSTEMD_EOF"  "$TMPDIR/system-coredump.conf" || _fail "system.conf"
extract_heredoc "$KS_FILE" "LIBVIRT_CORE_DOC_EOF" "$TMPDIR/libvirt-core.md" || _fail "libvirt core documentation"
extract_heredoc "$KS_FILE" "PERMISSION_POLICY_EOF" "$TMPDIR/permission-policy.conf" || _fail "permission policy extraction"
extract_heredoc "$KS_FILE" "PERMISSION_ACTION_EOF" "$TMPDIR/permission-policy.actions" || _fail "permission action extraction"
extract_heredoc "$KS_FILE" "UMASK_EOF"    "$TMPDIR/umask.sh" || _fail "UMASK_EOF extraction"
extract_heredoc "$KS_FILE" "HIST_COMPACT_EOF" "$TMPDIR/history-compact" || _fail "history compactor extraction"
extract_heredoc "$KS_FILE" "HIST_EOF" "$TMPDIR/history-profile.sh" || _fail "history profile extraction"
extract_heredoc "$KS_FILE" "TOGGLE_HIST_EOF" "$TMPDIR/history-toggle" || _fail "history toggle extraction"
extract_heredoc "$KS_FILE" "BASH_DOC_EOF" "$TMPDIR/history-doc.md" || _fail "history documentation extraction"
extract_heredoc "$KS_FILE" "GPG_EOF" "$TMPDIR/gpg.conf" || _fail "GnuPG policy extraction"
chmod +x "$TMPDIR/history-compact" "$TMPDIR/history-toggle"

# --- faillock.conf (CIS L1 + STIG values) -------------
assert_grep_extended '^deny = 10$'               "$TMPDIR/faillock.conf"
assert_grep_extended '^unlock_time = 900$'       "$TMPDIR/faillock.conf"
assert_grep_extended '^fail_interval = 1800$'    "$TMPDIR/faillock.conf"
assert_grep_extended '^silent$'                  "$TMPDIR/faillock.conf"
assert_grep_extended '^audit$'                   "$TMPDIR/faillock.conf"
assert_grep_extended '^even_deny_root$'          "$TMPDIR/faillock.conf"
assert_grep_extended '^root_unlock_time = 60$'   "$TMPDIR/faillock.conf"
assert_grep_fixed "FAILLOCK_FCONTEXT='/var/lib/faillock(/.*)?'" "$KS_FILE" \
    "persistent faillock path has an explicit SELinux mapping"
assert_grep_fixed 'semanage fcontext -a -t faillog_t "$FAILLOCK_FCONTEXT"' \
    "$KS_FILE" "new faillock mapping uses Fedora's faillog_t"
assert_grep_fixed 'semanage fcontext -m -t faillog_t "$FAILLOCK_FCONTEXT"' \
    "$KS_FILE" "existing local faillock mapping is corrected idempotently"
assert_grep_fixed 'restorecon -RF "$FAILLOCK_PATH"' "$KS_FILE" \
    "persistent faillock state is recursively relabeled"
assert_grep_fixed 'matchpathcon -V "$FAILLOCK_PATH"' "$KS_FILE" \
    "faillock SELinux postcondition is verified"

# --- pwquality.conf (trailing inline comments OK, use word-boundary) --------
# Fifteen-character single-factor minimum; all composition controls disabled.
assert_grep_extended '^minlen = 15([[:space:]]|$)'    "$TMPDIR/pwquality.conf"
assert_grep_extended '^minclass = 0([[:space:]]|$)'   "$TMPDIR/pwquality.conf"
assert_grep_extended '^maxrepeat = 0([[:space:]]|$)'  "$TMPDIR/pwquality.conf"
assert_grep_extended '^maxclassrepeat = 0([[:space:]]|$)' "$TMPDIR/pwquality.conf"
assert_grep_extended '^maxsequence = 0([[:space:]]|$)' "$TMPDIR/pwquality.conf"
for credit in dcredit ucredit lcredit ocredit; do
    assert_grep_extended "^${credit} = 0([[:space:]]|$)" "$TMPDIR/pwquality.conf" \
        "no class length credit: $credit"
done
assert_grep_extended '^dictcheck = 1([[:space:]]|$)'  "$TMPDIR/pwquality.conf"
assert_grep_extended '^usercheck = 1([[:space:]]|$)'  "$TMPDIR/pwquality.conf"
assert_grep_extended '^gecoscheck = 1([[:space:]]|$)' "$TMPDIR/pwquality.conf"
assert_grep_extended '^enforcing = 1([[:space:]]|$)'  "$TMPDIR/pwquality.conf"
assert_grep_extended '^enforce_for_root$'              "$TMPDIR/pwquality.conf"
assert_not_grep_extended '95\^14|80 bits|2 ?s(ec(ond)?)?/hash|brute-force unrealistic' \
    "$KS_FILE" "M10 contains no human-entropy or universal hash-latency claim"

# --- pwhistory.conf ---------------------------------------------------------
assert_eq $'remember = 10\nenforce_for_root' \
    "$(awk '!/^[[:space:]]*($|#)/ {print}' "$TMPDIR/pwhistory.conf")" \
    "password history is explicit and covers root"
assert_grep_fixed 'chmod 0644 /etc/security/pwhistory.conf' "$KS_FILE"
assert_grep_fixed 'chmod 0600 /etc/security/opasswd' "$KS_FILE"
assert_grep_fixed 'pwhistory.conf exact policy + root-only history store' \
    "$KS_FILE" "compose verification covers policy and backing-store metadata"

# --- logind drop-in ---------------------------------------------------------
assert_grep_extended '^KillUserProcesses=yes$' "$TMPDIR/logind.conf"
assert_grep_extended '^KillExcludeUsers=$'      "$TMPDIR/logind.conf" \
    "logind lifecycle teardown deliberately includes root logins"
assert_grep_extended '^RemoveIPC=yes$'         "$TMPDIR/logind.conf"
assert_not_grep '^InhibitorsMax='              "$TMPDIR/logind.conf" \
    "M10 retains systemd's maintained inhibitor capacity"
assert_not_grep_extended '^IdleAction(Sec)?=|^Handle(Power|Suspend|Hibernate|Lid)' \
    "$TMPDIR/logind.conf" "M10 does not compete with GNOME/vendor power ownership"
assert_not_grep_extended 'default 8|no functional/security cost' "$KS_FILE" \
    "M10 contains no obsolete inhibitor default/cost claim"
assert_file_executable "$INHIBITOR_RUNTIME"
assert_cmd_success "inhibitor runtime gate parses" bash -n "$INHIBITOR_RUNTIME"
assert_grep_fixed 'for n in $(seq 1 20); do' "$INHIBITOR_RUNTIME" \
    "runtime gate exceeds the former 16-inhibitor cap"
assert_grep_fixed 'in_stanza && /Defaults to 8192 \(8K\)/ { expected_default=1 }' \
    "$INHIBITOR_RUNTIME" \
    "runtime gate verifies the installed systemd default"

# --- pam_access exact fail-closed policy -----------------------------------
assert_eq $'+:(wheel):ALL\n+:root:ALL\n-:ALL:ALL' \
    "$(awk '/^[[:space:]]*[+-]:/ {gsub(/[[:space:]]/, ""); print}' \
        "$TMPDIR/access.conf")" \
    "pam_access has the exact ordered allow-wheel/allow-root/deny-all policy"
assert_grep_fixed 'access.conf exact allow-wheel/allow-root/deny-all policy' \
    "$KS_FILE" "compose verification covers the fail-closed access policy"

# --- sudo PAM session class -------------------------------------------------
assert_eq 'XDG_SESSION_CLASS DEFAULT=none OVERRIDE=none' \
    "$(awk '!/^[[:space:]]*($|#)/ {print}' "$TMPDIR/pam_env-sudo.conf")" \
    "sudo PAM environment forces systemd's supported none session class"
assert_eq 1 \
    "$(grep -cF \
        'SUDO_PAM_ENV_LINE='\''session    optional     pam_env.so conffile=/etc/security/pam_env-sudo.conf readenv=0 user_readenv=0'\''' \
        "$KS_FILE")" \
    "sudo PAM prelude disables system and user environment sources"
assert_grep_fixed 'include_nr > env_nr' "$KS_FILE" \
    "compose verification requires the sudo environment before system-auth"
assert_grep_fixed "is not owned by Fedora's sudo package" "$KS_FILE" \
    "compose mutation is anchored to Fedora's packaged PAM service"
assert_grep_fixed 'falls back to Fedora'\''s normal sudo PAM session' "$KS_FILE" \
    "optional environment policy preserves sudo availability on local damage"
pam_bypass_re='pam_session[[:space:]]*=[[:space:]]*off|session[[:space:]]+.*pam_systemd\.so[[:space:]]+class=none'
assert_cmd_success "sudo PAM bypass guard matches its forbidden control" \
    grep -Eq "$pam_bypass_re" \
        <(printf '%s\n' 'session optional pam_systemd.so class=none')
assert_not_grep_extended "$pam_bypass_re" \
    "$KS_FILE" "sudo does not bypass PAM or copy authselect's pam_systemd owner"

# --- sudoers.d timestamp_timeout=3 (CIS 4.3.6) ------------------------------
assert_grep_extended '^Defaults timestamp_timeout=3$' "$TMPDIR/sudoers.conf"
assert_grep_extended '^Defaults env_reset$'           "$TMPDIR/sudoers.conf"
assert_cmd_success "sudoers drop-in passes the native parser" \
    visudo -cf "$TMPDIR/sudoers.conf"
assert_eq 2 \
    "$(grep -cE '^Defaults!/usr/bin/dnf5?[[:space:]]+umask=0022,[[:space:]]+umask_override$' \
        "$TMPDIR/sudoers.conf")" \
    "both supported DNF command names get the scoped system-state umask"
for dnf_command in /usr/bin/dnf /usr/bin/dnf5; do
    assert_grep_fixed \
        "Defaults!${dnf_command} umask=0022, umask_override" \
        "$TMPDIR/sudoers.conf" "command-scoped public system state: $dnf_command"
done
assert_not_grep_extended '^Defaults[[:space:]]+umask=0022|^Defaults[[:space:]]+umask_override' \
    "$TMPDIR/sudoers.conf" "DNF compatibility does not lower sudo's global umask"
assert_grep_extended '^Defaults !fqdn$' "$TMPDIR/sudoers-nofqdn.conf"
assert_cmd_success "!fqdn sudoers drop-in passes the native parser" \
    visudo -cf "$TMPDIR/sudoers-nofqdn.conf"
assert_grep_fixed '99-noid-no-fqdn missing, unsafe or invalid' "$KS_FILE" \
    "compose verification covers the defensive !fqdn artifact"

# --- Coredump Layer 6 -------------------------------------------------------
assert_grep_extended '^DefaultLimitCORE=0$' "$TMPDIR/system-coredump.conf"
assert_grep_fixed 'A unit-specific LimitCORE= overrides the manager default' \
    "$TMPDIR/system-coredump.conf" \
    "coredump policy does not overclaim that a manager default pins units"
assert_grep_fixed 'Layers 1-4 are the independent dump-production/storage boundary' \
    "$TMPDIR/system-coredump.conf" \
    "coredump comment identifies the independent enforcement layers"
assert_grep_fixed 'A privileged process' "$TMPDIR/system-coredump.conf" \
    "Layer 6 does not overclaim protection against CAP_SYS_RESOURCE"

# --- Native libvirt system-QEMU ceiling ------------------------------------
assert_grep_fixed 'QEMU_SYSTEM_CONF=/etc/libvirt/qemu.conf' "$KS_FILE" \
    "M10 edits libvirt's supported system-driver configuration path"
assert_grep_fixed "libvirt-daemon-driver-qemu" "$KS_FILE" \
    "system qemu.conf must remain owned by Fedora's driver package"
assert_grep_fixed 'qemu_max_active' "$KS_FILE" \
    "system qemu.conf transformer rejects ambiguous active settings"
assert_grep_fixed 'mv -fT -- "$QEMU_SYSTEM_TMP" "$QEMU_SYSTEM_CONF"' "$KS_FILE" \
    "system qemu.conf publishes through a same-directory atomic rename"
assert_grep_fixed 'sync -- /etc/libvirt' "$KS_FILE" \
    "system qemu.conf rename is made durable through its directory"
assert_grep_fixed 'max_core = 0' "$KS_FILE" \
    "system QEMU has an explicit zero core-file ceiling"
assert_grep_fixed 'dump_guest_core = 0' "$KS_FILE" \
    "system QEMU documents disabled guest-memory inclusion"
assert_grep_fixed 'max_core=0 above remains the file-size boundary' "$KS_FILE" \
    "dump_guest_core is not misrepresented as the load-bearing boundary"
assert_grep_fixed 'libvirt system-QEMU max_core boundary + documentation exact' \
    "$KS_FILE" "compose verification covers the native QEMU boundary"
assert_grep_fixed 'compatibility repair, not an additional security' \
    "$TMPDIR/libvirt-core.md" \
    "session qemu.conf is accurately described as functional compatibility"
assert_grep_fixed 'guest XML' "$TMPDIR/libvirt-core.md" \
    "documentation discloses the dump_guest_core XML override"
assert_grep_fixed 'qemu.conf.rpmnew' "$TMPDIR/libvirt-core.md" \
    "documentation covers Fedora config-noreplace drift"
assert_grep_fixed 'Such a core can contain' \
    "$TMPDIR/libvirt-core.md" \
    "diagnostic undo documents the core confidentiality cost"
assert_file_executable "$LIBVIRT_RUNTIME" \
    "system/session QEMU process-boundary gate is executable"
assert_cmd_success "libvirt core runtime gate parses" bash -n "$LIBVIRT_RUNTIME"
assert_cmd_success "libvirt core runtime gate passes ShellCheck" \
    shellcheck -S warning "$LIBVIRT_RUNTIME"
for pass_id in live fresh-install reboot; do
    assert_grep_fixed "$pass_id" "$LIBVIRT_RUNTIME" \
        "libvirt core gate recognizes $pass_id"
done
assert_grep_fixed "limits == '0 0'" "$LIBVIRT_RUNTIME" \
    "runtime gate proves QEMU's soft and hard core limits"
assert_grep_fixed 'dump-guest-core=off' "$LIBVIRT_RUNTIME" \
    "runtime gate proves the effective QEMU machine argument"
assert_grep_fixed '[[ -c /dev/kvm && -r /dev/kvm && -w /dev/kvm ]]' \
    "$LIBVIRT_RUNTIME" \
    "runtime gate requires its documented user-accessible KVM boundary"
assert_grep_fixed "<domain type='kvm'>" "$LIBVIRT_RUNTIME" \
    "runtime probes use transient KVM-accelerated QEMU domains"
assert_not_grep_fixed "<domain type='qemu'>" "$LIBVIRT_RUNTIME" \
    "runtime gate does not manufacture Fedora TCG SELinux noise"

# --- Native permission policy ------------------------------------------------
assert_eq 11 "$(grep -c '^z ' "$TMPDIR/permission-policy.conf")" \
    "tmpfiles policy has five binary and six directory entries"
for spec in \
    '/usr/bin/chfn                 0711' \
    '/usr/bin/chsh                 0711' \
    '/usr/bin/gpasswd              0755' \
    '/usr/bin/newgrp               0755' \
    '/usr/bin/fusermount-glusterfs 0755'; do
    assert_grep_fixed "z $spec root root - -" "$TMPDIR/permission-policy.conf" \
        "intentional admin-only permission: ${spec%% *}"
done
for native_path in /usr/bin/chage /usr/bin/pam_timestamp_check \
                   /usr/bin/userhelper /usr/libexec/libgtop_server2; do
    assert_not_grep "^z ${native_path}[[:space:]]" "$TMPDIR/permission-policy.conf" \
        "Fedora-native SUID retained: $native_path"
done
for dir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly \
           /etc/cron.monthly /etc/cron.d /etc/sudoers.d; do
    assert_grep_extended "^z ${dir}[[:space:]]+0700 root root - -$" \
        "$TMPDIR/permission-policy.conf" "root-only policy dir: $dir"
done
assert_eq 5 "$(grep -c '^post_transaction:' "$TMPDIR/permission-policy.actions")" \
    "dnf5 action has one trigger per owning package family"
for pkg in util-linux shadow-utils glusterfs-fuse cronie sudo; do
    assert_grep_fixed "post_transaction:${pkg}:in:enabled=host-only raise_error=1:" \
        "$TMPDIR/permission-policy.actions" "transaction-scoped trigger: $pkg"
done
assert_not_grep_extended 'cat > .*noid-suid-harden|OnUnitActiveSec=1w|SUID_REMOVE_LIST' \
    "$KS_FILE" "M10 contains no obsolete periodic chmod mutator"
assert_grep_fixed 'obsolete periodic permission mutator remains' "$KS_FILE" \
    "compose verification rejects surviving mutator artifacts"

# --- login.defs adds in KS source -------------------------------------------
assert_grep_fixed 'set_login_defs "LOG_OK_LOGINS"         "no"' "$KS_FILE" \
    "successful /bin/login metadata is not duplicated"
assert_grep_fixed 'set_login_defs "LOG_UNKFAIL_ENAB"      "no"' "$KS_FILE" \
    "password-like unknown usernames are not recorded"
assert_grep_fixed 'set_login_defs "FAIL_DELAY"            "4"' "$KS_FILE"
assert_grep_fixed 'set_login_defs "YESCRYPT_COST_FACTOR"  "8"' "$KS_FILE"
assert_grep_fixed 'set_login_defs "UMASK"                 "022"' "$KS_FILE"
assert_grep_fixed 'set_login_defs "HOME_MODE"             "0700"' "$KS_FILE"
assert_grep_fixed 'set_login_defs "CREATE_HOME"           "yes"' "$KS_FILE"
assert_grep_fixed 'set_login_defs "ENCRYPT_METHOD"        "YESCRYPT"' "$KS_FILE"
assert_grep_fixed 'set_login_defs "PASS_MAX_DAYS"         "99999"' "$KS_FILE"
assert_grep_fixed 'is not exact and unique' "$KS_FILE" \
    "compose verification rejects duplicate login.defs records"
assert_not_grep_extended 'set_login_defs "(LOG_OK_LOGINS|LOG_UNKFAIL_ENAB)"[[:space:]]+"yes"' \
    "$KS_FILE" "M10 does not enable privacy-inverting login logging"
assert_grep_fixed '`fqdn` is opt-in in maintained sudoers' "$KS_FILE" \
    "M10 accurately describes sudo's maintained default"
assert_not_grep_extended "sudo's default FQDN resolution does a DNS query per|lookup on every invocation" \
    "$KS_FILE" "M10 contains no universal sudo DNS-query claim"
assert_file_executable "$LOGIN_RUNTIME"
assert_cmd_success "login privacy runtime gate parses" bash -n "$LOGIN_RUNTIME"
assert_grep_fixed 'expect_one_login_def LOG_UNKFAIL_ENAB no' "$LOGIN_RUNTIME" \
    "runtime gate requires unknown-user logging off"
assert_grep_fixed 'sudo -n -U "$audit_user" -ll' "$LOGIN_RUNTIME" \
    "runtime gate resolves the effective sudo policy"
awk '
    /^effective_journal_value\(\) \{$/ { copy = 1 }
    copy { print }
    copy && /^}$/ { exit }
' "$LOGIN_RUNTIME" > "$TMPDIR/effective-journal-value.sh"
# shellcheck source=/dev/null
. "$TMPDIR/effective-journal-value.sh"
cat > "$TMPDIR/journald-effective.conf" <<'JOURNAL_FIXTURE_EOF'
# /usr/lib/systemd/journald.conf
[Journal]
Storage = persistent
SystemMaxUse = 500M
MaxRetentionSec = 30day
[Unrelated]
Storage = ignored
[Journal]
Storage = volatile
SystemMaxUse = 600M
# MaxRetentionSec = 90day
JOURNAL_FIXTURE_EOF
assert_eq volatile \
    "$(effective_journal_value Storage < "$TMPDIR/journald-effective.conf")" \
    "journal parser selects the last active value in the owning section"
assert_eq 600M \
    "$(effective_journal_value SystemMaxUse < "$TMPDIR/journald-effective.conf")" \
    "journal parser detects a later size override"
assert_eq 30day \
    "$(effective_journal_value MaxRetentionSec < "$TMPDIR/journald-effective.conf")" \
    "journal parser ignores commented overrides"
assert_cmd_failure "journal parser rejects a missing value" \
    effective_journal_value Compress < "$TMPDIR/journald-effective.conf"
assert_grep_fixed '[[ "$journal_retention" == 30day ]]' "$LOGIN_RUNTIME" \
    "runtime gate checks the effective bounded audit retention"
assert_grep_fixed 'set_login_defs "YESCRYPT_COST_FACTOR"  "8"' "$KS_FILE" \
    "M10 restores the measured yescrypt cost through login.defs"
assert_not_grep_extended 'mkdir -p /etc/authselect/custom|authselect select custom/|pam_unix\.so[^#]*rounds=8' \
    "$KS_FILE" "M10 does not fork authselect or duplicate the native cost"
assert_grep_fixed 'authselect select local' "$KS_FILE" \
    "M10 uses Fedora's maintained authselect profile"
assert_grep_fixed \
    "AUTHSELECT_EXPECTED='local with-silent-lastlog without-nullok with-faillock with-pwhistory with-pamaccess'" \
    "$KS_FILE" "M10 pins the exact five-feature local profile"
assert_grep_fixed 'authselect check 2>>"$AUTHSEL_LOG"' "$KS_FILE" \
    "M10 verifies authselect-owned checksums"
assert_not_grep 'authselect apply-changes' "$KS_FILE" \
    "M10 does not redundantly regenerate a profile after select"
assert_not_grep_extended '^[[:space:]]+with-mkhomedir[[:space:]]*\\$' "$KS_FILE" \
    "M10 does not select the oddjobd-backed feature"
assert_grep_fixed "! grep -qF 'pam_oddjob_mkhomedir.so'" "$KS_FILE" \
    "generated PAM verification rejects the disabled session helper"
assert_grep_fixed 'install -m 0600 -o root -g root /dev/null "$AUTHSEL_LOG"' \
    "$KS_FILE" "authselect install evidence starts root-only"
assert_not_grep_extended 'restorecon .*2>/dev/null \|\| true|restorecon.*&&' \
    "$KS_FILE" "M10 does not swallow output-label failures"
assert_grep_fixed 'for m10_label_path in "${M10_LABEL_PATHS[@]}"; do' \
    "$KS_FILE" "M10 verifies every declared output label"
assert_grep_fixed 'yescrypt, cost owned by login.defs' "$KS_FILE" \
    "generated PAM verification retains one native cost owner"
assert_grep_fixed 'expect_one_login_def YESCRYPT_COST_FACTOR 8' "$LOGIN_RUNTIME" \
    "runtime gate requires the yescrypt cost exactly once"
for login_contract in \
    'UMASK 022' \
    'HOME_MODE 0700' \
    'CREATE_HOME yes' \
    'ENCRYPT_METHOD YESCRYPT' \
    'PASS_MAX_DAYS 99999'; do
    assert_grep_fixed "expect_one_login_def $login_contract" "$LOGIN_RUNTIME" \
        "runtime gate requires local-account default: $login_contract"
done
assert_grep_fixed \
    "AUTHSELECT_EXPECTED='local with-silent-lastlog without-nullok with-faillock with-pwhistory with-pamaccess'" \
    "$LOGIN_RUNTIME" "runtime gate pins the exact authselect state"
assert_grep_fixed 'compose-only authselect evidence survived final image scrubbing' \
    "$LOGIN_RUNTIME" \
    "runtime gate requires private compose authselect evidence to be retired"
assert_grep_fixed 'pwhistory policy differs' "$LOGIN_RUNTIME" \
    "runtime gate verifies password-history policy"

# --- limits.conf Layer 5 content present in KS source -----------------------
assert_grep_fixed '*       hard    core    0' "$KS_FILE"

# Exercise the exact tmpfiles policy in an unprivileged synthetic root. Rewrite
# only the fixture owner/group because the real candidate policy is root-owned.
permission_root="$TMPDIR/permission-root"
mkdir -p "$permission_root/etc/tmpfiles.d" "$permission_root/usr/bin"
for path in chfn chsh gpasswd newgrp fusermount-glusterfs; do
    touch "$permission_root/usr/bin/$path"
    chmod 4755 "$permission_root/usr/bin/$path"
done
for dir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly \
           /etc/cron.monthly /etc/cron.d /etc/sudoers.d; do
    mkdir -p "$permission_root$dir"
    chmod 0755 "$permission_root$dir"
done
sed "s/root root/$(id -u) $(id -g)/" "$TMPDIR/permission-policy.conf" \
    > "$permission_root/etc/tmpfiles.d/90-noid-permission-policy.conf"
assert_cmd_success "native tmpfiles permission fixture applies" \
    systemd-tmpfiles --create --root="$permission_root" \
        90-noid-permission-policy.conf
for spec in chfn:711 chsh:711 gpasswd:755 newgrp:755 \
            fusermount-glusterfs:755; do
    assert_eq "${spec#*:}" \
        "$(stat -c %a "$permission_root/usr/bin/${spec%%:*}")" \
        "tmpfiles strips only the reviewed SUID path: ${spec%%:*}"
done
for dir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly \
           /etc/cron.monthly /etc/cron.d /etc/sudoers.d; do
    assert_eq 700 "$(stat -c %a "$permission_root$dir")" \
        "tmpfiles makes policy directory root-only: $dir"
done

# --- Step 9b profile.d/99-noid-security-umask.sh ------------
# Interactive-shell umask 027 (login.defs UMASK=022 stays for dnf5 compat).
assert_grep_fixed '/etc/profile.d/99-noid-security-umask.sh' "$KS_FILE" "profile.d drop-in path in KS source"
# Interactive-only guard: Fedora sources profile.d in noninteractive paths too.
assert_grep_fixed 'case $- in' "$TMPDIR/umask.sh" \
    "umask drop-in tests the shell's interactive flag"
assert_grep_fixed '*i*) umask 027 ;;' "$TMPDIR/umask.sh" \
    "umask 027 is scoped to interactive shells"
assert_not_grep '^umask 027$' "$TMPDIR/umask.sh" \
    "umask drop-in has no unconditional mutation"
assert_cmd_success "umask drop-in parses" bash -n "$TMPDIR/umask.sh"
noninteractive_umask="$(bash -c 'umask 022; . "$1"; umask' _ "$TMPDIR/umask.sh")"
assert_eq 0022 "$noninteractive_umask" \
    "noninteractive source preserves its inherited umask"
interactive_umask="$(bash --noprofile --norc -ic \
    'umask 022; . "$1"; umask' _ "$TMPDIR/umask.sh" 2>/dev/null)"
assert_eq 0027 "$interactive_umask" \
    "interactive source applies umask 027"

# --- Step 9b.2 prompt-compacted Bash history -------------------------------
assert_cmd_success "history compactor parses" bash -n "$TMPDIR/history-compact"
assert_cmd_success "history profile parses" bash -n "$TMPDIR/history-profile.sh"
assert_cmd_success "history toggle parses" bash -n "$TMPDIR/history-toggle"
assert_grep_fixed 'Bash history artifact missing, unsafe or invalid' "$KS_FILE" \
    "compose verification covers all three Bash-history artifacts"
assert_cmd_success "history compactor passes ShellCheck" \
    shellcheck -S warning "$TMPDIR/history-compact"
assert_cmd_success "history profile passes ShellCheck" \
    shellcheck -s bash -S warning "$TMPDIR/history-profile.sh"
assert_cmd_success "history toggle passes ShellCheck" \
    shellcheck -S warning "$TMPDIR/history-toggle"

assert_grep_fixed 'HISTFILESIZE=-1' "$TMPDIR/history-compact" \
    "compactor does not apply Bash's physical-line file limit"
assert_grep_fixed 'HISTSIZE=-1 HISTFILESIZE=-1' "$TMPDIR/history-compact" \
    "compactor reads the complete Bash event stream before trimming"
assert_grep_fixed 'unset HISTFILE HISTSIZE HISTFILESIZE HISTTIMEFORMAT' \
    "$TMPDIR/history-compact" \
    "outer helper cannot reapply the caller's physical-line cap at exit"
assert_grep_fixed '[[ "$history_line" =~ ^#[0-9]+$ ]]' \
    "$TMPDIR/history-compact" \
    "compactor detects actual numeric timestamp records before framing"
assert_grep_fixed 'if (( timestamp_framing == 1 )); then' \
    "$TMPDIR/history-compact" \
    "mixed Bash timestamp framing is conditional"
assert_grep_fixed "printf '#0\\n' > \"\$parse_tmp\"" \
    "$TMPDIR/history-compact" \
    "compactor canonicalizes detected mixed Bash timestamp framing"
assert_grep_fixed '"$history_dir/.${history_base}.noid-parse."*' \
    "$TMPDIR/history-compact" \
    "next sync finds exact SIGKILL parse leftovers"
assert_grep_fixed '[[ -f "$stale_tmp" && ! -L "$stale_tmp" && -O "$stale_tmp" ]]' \
    "$TMPDIR/history-compact" \
    "stale cleanup cannot follow or remove foreign non-regular paths"
assert_grep_fixed 'for ((history_offset=1;' "$TMPDIR/history-compact" \
    "compactor scans Bash events from newest to oldest"
assert_grep_fixed 'builtin fc -ln -- "-${history_offset}" "-${history_offset}"' \
    "$TMPDIR/history-compact" \
    "compactor retrieves relative events without reparsing their text as options"
assert_grep_fixed "[[ \"\${history_value:0:2}\" == \$'\\''\\t '\\'' ]] || exit 2" \
    "$TMPDIR/history-compact" \
    "compactor validates the fixed fc display prefix before removing it"
if grep -qF 'builtin history -p "!${history_index}"' "$TMPDIR/history-compact"; then
    _fail "compactor does not feed expanded event text back into history option parsing"
else
    _pass "compactor does not feed expanded event text back into history option parsing"
fi
assert_grep_fixed 'retained_reversed+=("$history_value")' \
    "$TMPDIR/history-compact" \
    "compactor retains only distinct exact Bash events before capping"
assert_grep_fixed 'builtin history -s -- "${retained_reversed[history_index]}"' \
    "$TMPDIR/history-compact" \
    "compactor rebuilds retained events option-safely in chronological order"
assert_grep_fixed 'mv -fT -- "$tmp" "$history_file"' "$TMPDIR/history-compact" \
    "compactor publishes with a same-directory atomic rename"
assert_grep_fixed 'rm -f -- "$parse_tmp"' "$TMPDIR/history-compact" \
    "successful compaction removes its full-history parse copy"
assert_grep_fixed 'flock -x "$lock_fd"' "$TMPDIR/history-profile.sh" \
    "profile serializes append and compaction across terminals"
assert_grep_fixed '[ -n "${BASH_VERSION-}" ] || return 0' \
    "$TMPDIR/history-profile.sh" \
    "Bash-only profile returns before mutating another interactive shell"
assert_grep_fixed 'builtin history -a' "$TMPDIR/history-profile.sh" \
    "profile appends current-shell entries under the lock"
assert_not_grep_extended 'unset PROMPT_COMMAND|PROMPT_COMMAND="history -a' \
    "$TMPDIR/history-profile.sh" \
    "history policy neither deletes nor overwrites existing prompt hooks"

printf '%s\n' alpha beta gamma delta epsilon > "$TMPDIR/history-fixture"
chmod 0644 "$TMPDIR/history-fixture"
assert_cmd_success "history compactor retains the newest three entries" \
    bash "$TMPDIR/history-compact" "$TMPDIR/history-fixture" 3
assert_eq $'gamma\ndelta\nepsilon' "$(cat "$TMPDIR/history-fixture")" \
    "history compactor uses Bash-parsed entry order"
assert_eq 600 "$(stat -c %a "$TMPDIR/history-fixture")" \
    "compacted history is mode 0600"

printf '%s\n' 'echo before' '#5 my note' 'echo after' \
    > "$TMPDIR/history-hash-digit-fixture"
assert_cmd_success "timestamp-free hash-digit command survives compaction" \
    bash "$TMPDIR/history-compact" "$TMPDIR/history-hash-digit-fixture" 10
assert_eq $'echo before\n#5 my note\necho after' \
    "$(cat "$TMPDIR/history-hash-digit-fixture")" \
    "conditional framing preserves hash-digit command text without timestamps"

printf '%s\n' 'echo before' '#1700000000' 'echo after' \
    > "$TMPDIR/history-timestamp-fixture"
assert_cmd_success "mixed timestamp history compacts with native framing" \
    bash "$TMPDIR/history-compact" "$TMPDIR/history-timestamp-fixture" 10
assert_eq $'echo before\necho after' \
    "$(cat "$TMPDIR/history-timestamp-fixture")" \
    "numeric Bash timestamp metadata is omitted from the published history"

: > "$TMPDIR/history-dedup-fixture"
for n in $(seq 1 80); do
    printf 'unique-%s\n' "$n" >> "$TMPDIR/history-dedup-fixture"
done
for _ in $(seq 1 20); do
    printf 'SAME\n' >> "$TMPDIR/history-dedup-fixture"
done
assert_cmd_success "history compactor deduplicates before applying its cap" \
    bash "$TMPDIR/history-compact" "$TMPDIR/history-dedup-fixture" 100
assert_eq 81 "$(wc -l < "$TMPDIR/history-dedup-fixture")" \
    "80 distinct commands plus 20 identical commands retain 81 entries"
assert_eq 1 "$(grep -c '^SAME$' "$TMPDIR/history-dedup-fixture")" \
    "persistent history keeps only the newest exact duplicate"
assert_eq SAME "$(tail -n 1 "$TMPDIR/history-dedup-fixture")" \
    "the newest duplicate retains its chronological position"

printf '%s\n' safe-first -pu-ok- -a -c '-d 1' -n -p -r -s -w -- -anrw \
    '  leading-spaces' -pu-ok- safe-last \
    > "$TMPDIR/history-option-fixture"
printf '%s\n' safe-first -a -c '-d 1' -n -p -r -s -w -- -anrw \
    '  leading-spaces' -pu-ok- safe-last \
    > "$TMPDIR/history-option-expected"
assert_cmd_success "history compactor accepts option-looking event text" \
    bash "$TMPDIR/history-compact" "$TMPDIR/history-option-fixture" 100
assert_cmd_success "option-looking entries remain exact data after deduplication" \
    cmp -s "$TMPDIR/history-option-expected" "$TMPDIR/history-option-fixture"

printf '%s\n' sentinel > "$TMPDIR/history-symlink-target"
ln -s "$TMPDIR/history-symlink-target" "$TMPDIR/history-symlink"
symlink_before=$(sha256sum "$TMPDIR/history-symlink-target" | awk '{print $1}')
assert_cmd_failure "history compactor rejects a symlink path" \
    bash "$TMPDIR/history-compact" "$TMPDIR/history-symlink" 3
symlink_after=$(sha256sum "$TMPDIR/history-symlink-target" | awk '{print $1}')
assert_eq "$symlink_before" "$symlink_after" \
    "rejected symlink compaction leaves the referent byte-identical"

array_state=$(PROFILE="$TMPDIR/history-profile.sh" \
    bash --noprofile --norc -ic \
    'PROMPT_COMMAND=(alpha beta); . "$PROFILE"; . "$PROFILE"; declare -p PROMPT_COMMAND; unset HISTFILE' \
    2>/dev/null)
assert_eq 'declare -a PROMPT_COMMAND=([0]="alpha" [1]="beta" [2]="_noid_history_sync")' \
    "$array_state" "array PROMPT_COMMAND is preserved and idempotent"
string_state=$(PROFILE="$TMPDIR/history-profile.sh" \
    bash --noprofile --norc -ic \
    'PROMPT_COMMAND="alpha; beta"; . "$PROFILE"; . "$PROFILE"; declare -p PROMPT_COMMAND; unset HISTFILE' \
    2>/dev/null)
assert_eq 'declare -- PROMPT_COMMAND="alpha; beta; _noid_history_sync"' \
    "$string_state" "string PROMPT_COMMAND is preserved and idempotent"

assert_grep_fixed 'no fixed byte cap and no “10 KiB at all times” promise' \
    "$TMPDIR/history-doc.md" "documentation rejects the fictitious byte cap"
assert_grep_fixed 'can leave an excess until the next' "$TMPDIR/history-doc.md" \
    "documentation states the abrupt-kill excess window"
assert_grep_fixed 'Under that framing Bash itself classifies every physical line beginning with' \
    "$TMPDIR/history-doc.md" \
    "documentation discloses Bash timestamp framing's hash-digit ambiguity"
assert_grep_fixed 'not a credential detector' "$TMPDIR/history-doc.md" \
    "HISTIGNORE is not presented as a credential detector"
assert_grep_fixed 'does **not** delete an' "$TMPDIR/history-doc.md" \
    "ephemeral mode does not overclaim deletion"
assert_not_grep 'unset PROMPT_COMMAND' "$TMPDIR/history-toggle" \
    "ephemeral toggle leaves the prompt synchronization function intact"
assert_grep_fixed 'Existing history files,' "$TMPDIR/history-toggle" \
    "ephemeral toggle discloses retained prior history"

# --- Step 9d GnuPG skel policy ---------------------------------------------
assert_eq 10 \
    "$(awk '!/^[[:space:]]*($|#)/ {count++} END {print count+0}' \
        "$TMPDIR/gpg.conf")" \
    "GnuPG skel carries the documented ten directives"
assert_grep_fixed 'GnuPG skel policy: 10 directives, root-only metadata' \
    "$KS_FILE" "compose verification covers GnuPG skel content and metadata"

assert_file_executable "$HISTORY_RUNTIME"
assert_cmd_success "Bash history runtime gate parses" bash -n "$HISTORY_RUNTIME"
assert_cmd_success "Bash history runtime gate passes ShellCheck" \
    shellcheck -S warning "$HISTORY_RUNTIME"
for pass_id in live fresh-install reboot; do
    assert_grep_fixed "$pass_id" "$HISTORY_RUNTIME" \
        "Bash history runtime gate accepts $pass_id"
done
assert_grep_fixed 'run_parallel_shell "$prefix" &' "$HISTORY_RUNTIME" \
    "runtime gate exercises simultaneous terminals"
assert_eq 2 "$(grep -c 'setsid bash --noprofile --norc -ic' "$HISTORY_RUNTIME")" \
    "runtime gate isolates both interrupted and parallel shell sessions"
assert_grep_fixed ''\'' _ "$prefix" </dev/null 2>"$tmp/parallel-$prefix.stderr"' \
    "$HISTORY_RUNTIME" \
    "parallel interactive fixtures cannot consume or control the gate terminal"
assert_grep_fixed "'PROMPT_COMMAND=(alpha beta);" "$HISTORY_RUNTIME" \
    "runtime gate behaviorally verifies prompt-array preservation"
assert_grep_fixed 'stat -c %s "$long_history"' "$HISTORY_RUNTIME" \
    "runtime gate proves long entries are not truncated to 10 KiB"
assert_grep_fixed 'multiline-first\nmultiline-second' \
    "$HISTORY_RUNTIME" "runtime gate exercises multiline serialization"
assert_grep_fixed '80 distinct plus 20 repeated commands did not retain 81' \
    "$HISTORY_RUNTIME" "runtime gate proves persistent deduplication before cap"
assert_grep_fixed 'timestamp-free hash-digit command was reclassified as metadata' \
    "$HISTORY_RUNTIME" \
    "runtime gate preserves hash-digit commands without timestamp framing"
assert_grep_fixed 'numeric Bash timestamp metadata survived compaction' \
    "$HISTORY_RUNTIME" \
    "runtime gate strips detected numeric timestamp metadata"
assert_grep_fixed 'history -s -- "-pu-ok-"' "$HISTORY_RUNTIME" \
    "runtime gate exercises a leading-dash entry through two prompt syncs"
assert_grep_fixed 'history -p "!!"' "$HISTORY_RUNTIME" \
    "runtime gate verifies retained history expansion"
assert_grep_fixed 'recovery-killed-newest' "$HISTORY_RUNTIME" \
    "runtime gate heals a literal SIGKILL interrupted-compaction excess"

# --- Candidate runtime permission/function boundary -------------------------
assert_file_executable "$PERMISSION_RUNTIME"
assert_cmd_success "permission-policy runtime gate parses" \
    bash -n "$PERMISSION_RUNTIME"
assert_cmd_success "permission-policy runtime gate passes ShellCheck" \
    shellcheck -S warning "$PERMISSION_RUNTIME"
for pass_id in live fresh-install reboot; do
    assert_grep_fixed "$pass_id" "$PERMISSION_RUNTIME" \
        "permission runtime gate accepts $pass_id"
done
assert_grep_fixed 'chage -l "$audit_user"' "$PERMISSION_RUNTIME" \
    "runtime gate proves the retained unprivileged expiry query"
assert_grep_fixed 'pam_timestamp_check' "$PERMISSION_RUNTIME" \
    "runtime gate distinguishes native PAM helper from no-SUID rc=2"
assert_grep_fixed 'noid-suid-harden' "$PERMISSION_RUNTIME" \
    "runtime gate rejects obsolete periodic mutator artifacts"

test_finish

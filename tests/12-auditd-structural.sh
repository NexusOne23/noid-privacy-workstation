#!/bin/bash
# 12-auditd-structural — verify Module 12 auditd rules + audit-notify
#
# Checks:
#   - 99-hardening.rules has exactly 132 rules with b64/b32 parity and no -w
#     and audits both AIDE configuration and trust-database changes
#   - -e 2 immutable is LAST rule
#   - no trusted-daemon suppression; all four clock syscalls are retained
#   - auditd.conf has a measured 640-MiB rolling bound + hard failure policy
#   - SELinux booleans set to off (selinuxuser_execstack, selinuxuser_execmod)
#   - audit-notify is a byte-exact auparse feed plugin with interlaced-event,
#     exact-AUID/local-seat and bounded-delivery behavior fixtures
#   - Fedora -a task,never gotcha fix (audit.rules is just -D)

set -euo pipefail
. "$(dirname "$0")/lib.sh"

PROJECT_ROOT="$(find_project_root)"
KS_FILE="$PROJECT_ROOT/kickstart/snippets/12-selinux-auditd.ks"
PLUGIN_SOURCE="$PROJECT_ROOT/scripts/noid-audit-notify-plugin.py"
PLUGIN_FIXTURE="$PROJECT_ROOT/tests/12-audit-notify-fixture.py"
NOTIFIER_SOURCE="$PROJECT_ROOT/scripts/noid-audit-event-notify.py"
NOTIFIER_FIXTURE="$PROJECT_ROOT/tests/12-audit-event-notify-fixture.py"
FINALIZE_KS="$PROJECT_ROOT/kickstart/snippets/99-finalize.ks"
WELCOME_KS="$PROJECT_ROOT/kickstart/snippets/13-aide-welcome.ks"
USER_DOCS_B_KS="$PROJECT_ROOT/kickstart/snippets/30-user-docs-tier-b.ks"
USER_DOCS_C_KS="$PROJECT_ROOT/kickstart/snippets/31-user-docs-tier-c.ks"

test_start "12-auditd-structural"

assert_file_exists "$KS_FILE"

assert_grep_fixed 'AUDIT_TARGET_DIRS=(' "$KS_FILE" \
    "optional audit directories have one canonical mode inventory"
for target_spec in \
    '/etc/chrony.d|755' \
    '/etc/cron.d|700' \
    '/etc/cron.daily|700' \
    '/etc/cron.hourly|700' \
    '/etc/cron.weekly|700' \
    '/etc/cron.monthly|700' \
    '/var/spool/cron|755' \
    '/var/lib/aide|700'; do
    assert_grep_fixed "'$target_spec'" "$KS_FILE" \
        "optional audit target carries its final mode: $target_spec"
done
assert_grep_fixed \
    'install -d -o root -g root -m "$audit_target_mode" "$audit_target_dir"' \
    "$KS_FILE" "optional directory targets use their canonical mode inventory"
assert_grep_fixed "stat -c '%U:%G:%a'" "$KS_FILE" \
    "build verification checks filesystem-neutral directory metadata"
assert_grep_fixed '[ -d "$audit_target_dir" ] && [ ! -L "$audit_target_dir" ]' \
    "$KS_FILE" "build verification retains exact directory and symlink checks"
assert_not_grep 'root:root:\${audit_target_mode}:1' "$KS_FILE" \
    "directory verification does not assume a Btrfs-specific link count"
assert_grep_fixed 'optional audit directory target invalid' "$KS_FILE" \
    "build verification rejects a missing, symlinked or misowned target"
assert_grep_fixed 'builtin-permissive type' "$KS_FILE" \
    "switcheroo transition states Fedora's actual enforcement boundary"
assert_not_grep 'proper confinement' "$KS_FILE" \
    "M12 does not overclaim enforcement in a builtin-permissive domain"
assert_grep_fixed 'privileged `setenforce 0` can still' "$KS_FILE" \
    "SELinux prose distinguishes enforcement state from removed hook teardown"
assert_grep_fixed '`selinux=0` is a boot-time choice' "$KS_FILE" \
    "SELinux prose identifies the remaining boot-disable boundary"
assert_not_grep 'relabel-on-reboot is the only remaining toggle path' "$KS_FILE" \
    "removed runtime-disable support is not conflated with permissive mode"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

# --- extract key heredocs ---------------------------------------------------
# M12 uses plain `EOF` markers for the three audit config files + named
# AUDIT_NOTIFY_SCRIPT_EOF / AUDIT_NOTIFY_UNIT_EOF for scripts/units. Since
# there are multiple `EOF` markers, use file-path-specific awk ranges and
# require the match ends at the FIRST `^EOF$` after the cat > line.
awk '/^cat > \/etc\/audit\/rules\.d\/audit\.rules /{f=1;next} f && /^EOF$/{exit} f' "$KS_FILE" > "$TMPDIR/audit.rules"
awk '/^cat > \/etc\/audit\/auditd\.conf /{f=1;next} f && /^EOF$/{exit} f' "$KS_FILE" > "$TMPDIR/auditd.conf"
awk '/^cat > \/etc\/audit\/rules\.d\/99-hardening\.rules /{f=1;next} f && /^EOF$/{exit} f' "$KS_FILE" > "$TMPDIR/99-hardening.rules"
extract_heredoc "$KS_FILE" "AUDIT_NOTIFY_SCRIPT_EOF" "$TMPDIR/audit-notify.sh" || _fail "audit-notify.sh extraction"
extract_heredoc "$KS_FILE" "AUDIT_NOTIFY_CONTROLLER_EOF" \
    "$TMPDIR/noid-audit-notify-controller" || _fail "audit-notify controller extraction"
extract_heredoc "$KS_FILE" "AUDIT_NOTIFY_UNIT_EOF" \
    "$TMPDIR/audit-notify.service" || _fail "audit-notify unit extraction"
extract_heredoc "$KS_FILE" "TOGGLE_AUDIT_NOTIFY_EOF" \
    "$TMPDIR/noid-toggle-audit-notify" || _fail "audit-notify toggle extraction"
extract_heredoc "$KS_FILE" "AUDIT_NOTIFY_PLUGIN_EOF" \
    "$TMPDIR/noid-notify.conf" || _fail "audit-notify plugin config extraction"
extract_heredoc "$KS_FILE" "AUDIT_EVENT_NOTIFY_EOF" \
    "$TMPDIR/noid-audit-event-notify" || _fail "audit event notifier extraction"
extract_heredoc "$KS_FILE" "AUDIT_EVENT_SERVICE_EOF" \
    "$TMPDIR/noid-audit-event-notify.service" || \
    _fail "audit event notifier unit extraction"
extract_heredoc "$KS_FILE" "AUDIT_EVENT_PATH_EOF" \
    "$TMPDIR/noid-audit-event-notify.path" || \
    _fail "audit event notifier path unit extraction"
extract_heredoc "$KS_FILE" "NOID_TE_EOF" "$TMPDIR/noid-selinux-fixes.te" || \
    _fail "SELinux module source extraction"
extract_heredoc "$KS_FILE" "NOID_SELINUX_RECONCILE_EOF" \
    "$TMPDIR/noid-selinux-policy-reconcile" || \
    _fail "SELinux policy reconcile helper extraction"
extract_heredoc "$KS_FILE" "NOID_SELINUX_ACTION_EOF" \
    "$TMPDIR/noid-selinux-policy.actions" || \
    _fail "SELinux policy action extraction"

assert_file_min_size "$TMPDIR/99-hardening.rules" 2048 "99-hardening.rules >2KB"
assert_file_min_size "$TMPDIR/auditd.conf"        512  "auditd.conf >512B"
assert_file_min_size "$TMPDIR/audit-notify.sh"    8192 "audit-notify.sh >8KB"

assert_grep_fixed 'boot-scoped low-space' "$KS_FILE" \
    "M12 header identifies low-space evidence as boot-scoped"
assert_not_grep_fixed 'persistent low-space' "$KS_FILE" \
    "M12 header does not claim runtime low-space evidence survives reboot"
assert_grep_fixed 'normally-domained event drain' "$KS_FILE" \
    "M12 header includes the audit-event notification drain"
assert_not_grep_extended '0 of 132 rules|ENTIRE ruleset load' "$KS_FILE" \
    "M12 does not misdescribe a failed audit rule as an empty ruleset"
assert_grep_fixed 'leaving a partial,' "$KS_FILE" \
    "M12 documents the partial non-immutable audit-rule failure mode"

# --- exact count + complete ABI parity --------------------------------------
syscall_count=$(grep -cE '^-a ' "$TMPDIR/99-hardening.rules" 2>/dev/null || true)
legacy_watch_count=$(grep -cE '^-w ' "$TMPDIR/99-hardening.rules" 2>/dev/null || true)
syscall_count=${syscall_count:-0}
legacy_watch_count=${legacy_watch_count:-0}
assert_eq "132" "$syscall_count" "99-hardening.rules has 132 ABI-qualified rules"
assert_eq "0" "$legacy_watch_count" "deprecated -w audit watches are absent"

# Every current-facing count must derive from the canonical payload above.
# Historical changelog/build-number occurrences are intentionally out of scope.
assert_grep_fixed "-ne ${syscall_count} ]" "$FINALIZE_KS" \
    "finalizer count matches the canonical audit payload"
assert_grep_fixed "auditd **immutable** (${syscall_count} b64/b32-complete rules" \
    "$PROJECT_ROOT/README.md" "README feature count matches the canonical payload"
assert_grep_fixed "auditd event monitoring** (${syscall_count} dual-ABI immutable rules)" \
    "$PROJECT_ROOT/README.md" "README scope count matches the canonical payload"
assert_grep_fixed "${syscall_count} b64/b32-complete audit rules" \
    "$PROJECT_ROOT/docs/comparison.md" \
    "comparison count matches the canonical audit payload"
assert_grep_fixed "override with ${syscall_count} hardened" \
    "$PROJECT_ROOT/docs/threat-model.md" \
    "threat-model count matches the canonical audit payload"
assert_grep_fixed "auditd log (${syscall_count} ABI-complete rules)" \
    "$WELCOME_KS" "Setup summary count matches the canonical audit payload"
assert_grep_fixed "Auditd (${syscall_count} ABI-complete rules, immutable)" \
    "$USER_DOCS_B_KS" "security guide count matches the canonical audit payload"
assert_grep_fixed "${syscall_count} ABI-complete auditd rules" \
    "$USER_DOCS_C_KS" "architecture guide count matches the canonical audit payload"
grep '^-a .*arch=b64' "$TMPDIR/99-hardening.rules" | \
    sed 's/arch=b64/arch=ABI/' | sort > "$TMPDIR/rules-b64.normalized"
grep '^-a .*arch=b32' "$TMPDIR/99-hardening.rules" | \
    sed 's/arch=b32/arch=ABI/' | sort > "$TMPDIR/rules-b32.normalized"
assert_cmd_success "every architecture-qualified rule has an exact ABI twin" \
    cmp -s "$TMPDIR/rules-b64.normalized" "$TMPDIR/rules-b32.normalized"
for rule in \
    '-a always,exit -F arch=b64 -F path=/etc/aide.conf -F perm=wa -F obj_type=etc_t -k aide_integrity' \
    '-a always,exit -F arch=b32 -F path=/etc/aide.conf -F perm=wa -F obj_type=etc_t -k aide_integrity' \
    '-a always,exit -F arch=b64 -F dir=/var/lib/aide -F perm=wa -k aide_integrity' \
    '-a always,exit -F arch=b32 -F dir=/var/lib/aide -F perm=wa -k aide_integrity'; do
    assert_grep_fixed "$rule" "$TMPDIR/99-hardening.rules" \
        "AIDE evidence rule is exact and ABI-complete"
done
assert_grep_fixed 'This never creates, updates or' "$TMPDIR/99-hardening.rules" \
    "AIDE audit coverage cannot be misread as baseline ownership"
assert_grep_fixed 'accepts an AIDE baseline.' "$TMPDIR/99-hardening.rules" \
    "AIDE baseline trust remains explicitly user-owned"

# --- -e 2 is LAST non-comment non-empty line --------------------------------
last_line=$(grep -vE '^$|^##|^#' "$TMPDIR/99-hardening.rules" | tail -1)
assert_eq "-e 2" "$last_line" "-e 2 is last rule (immutable mode)"

# --- daemon-inclusive time-change evidence ---------------------------------
assert_not_grep '^-a never,exit' "$TMPDIR/99-hardening.rules" \
    "no trusted process can erase its syscall evidence"
assert_eq 2 "$(grep -cE '^-a always,exit -F arch=b(32|64) -S adjtimex -S settimeofday -S clock_settime -S clock_adjtime -k time_change$' \
    "$TMPDIR/99-hardening.rules")" \
    "both ABIs retain every relevant time-adjustment syscall"

# Privilege evidence is attached to the set-ID transition itself. A rule that
# selects every euid=0 child under a user AUID floods normal sudo workflows
# while adding no new transition evidence.
assert_eq 2 "$(grep -cE '^-a always,exit -F arch=b(32|64) -S execve -C uid!=euid -F euid=0 -F auid>=1000 -F auid!=-1 -k priv_exec$' \
    "$TMPDIR/99-hardening.rules")" \
    "both ABIs record only unprivileged-to-root exec transitions"
assert_eq 0 "$(grep -cE '^-a always,exit -F arch=b(32|64) -S execve -F euid=0 .* -k priv_exec$' \
    "$TMPDIR/99-hardening.rules" 2>/dev/null || true)" \
    "broad root-child exec logging cannot return"

# --- login/session accounting gaps: exact dual-ABI targets ------------------
for rule_fragment in \
    '-F path=/run/utmp -F perm=wa -F obj_type=initrc_var_run_t -k session' \
    '-F path=/var/log/wtmp -F perm=wa -F obj_type=wtmp_t -k session' \
    '-F path=/var/log/btmp -F perm=wa -F obj_type=faillog_t -k logins' \
    '-F path=/var/log/lastlog -F perm=wa -F obj_type=lastlog_t -k logins' \
    '-F dir=/var/lib/faillock -F perm=wa -k logins' \
    '-F dir=/var/lib/lastlog -F perm=wa -k logins'; do
    assert_eq 2 "$(grep -cF -- "$rule_fragment" "$TMPDIR/99-hardening.rules")" \
        "dual-ABI audit target: $rule_fragment"
    assert_eq 1 "$(grep -cF -- "'$rule_fragment'" "$FINALIZE_KS")" \
        "finalizer mirrors the exact M12 audit target: $rule_fragment"
done
assert_eq 2 "$(grep -cF -- '-F dir=/etc/chrony.d -F perm=wa -k chrony_config' \
    "$TMPDIR/99-hardening.rules")" \
    "chrony drop-in directory has an exact dual-ABI audit pair"
assert_grep_fixed 'same-key pair only as a declarative reviewer marker' \
    "$TMPDIR/99-hardening.rules" \
    "redundant rules.d pair is not presented as additional coverage"
assert_grep_fixed 'means it adds no event or coverage beyond the parent pair' \
    "$TMPDIR/99-hardening.rules" \
    "audit parent/subtree first-match consequence is explicit"

# Btrfs subvolumes have independent inode namespaces, while Linux audit path
# matching uses only the filesystem device + inode. Every exact path watch
# must therefore conjunct the path's expected SELinux object type so a
# colliding inode on /home or a container subvolume cannot create false
# evidence. Keep this mapping explicit: policy-type drift must fail review.
declare -A expected_path_types=(
    [/etc/aide.conf]=etc_t
    [/etc/passwd]=passwd_file_t
    [/etc/shadow]=shadow_t
    [/etc/group]=passwd_file_t
    [/etc/gshadow]=shadow_t
    [/etc/sudoers]=etc_t
    [/etc/ssh/sshd_config]=etc_t
    [/etc/ssh/ssh_config]=etc_t
    [/etc/sysctl.conf]=system_conf_t
    [/etc/default/grub]=bootloader_etc_t
    [/usr/sbin/useradd]=useradd_exec_t
    [/usr/sbin/userdel]=useradd_exec_t
    [/usr/sbin/usermod]=useradd_exec_t
    [/usr/sbin/groupadd]=groupadd_exec_t
    [/usr/sbin/groupdel]=groupadd_exec_t
    [/usr/sbin/groupmod]=groupadd_exec_t
    [/usr/sbin/passwd]=passwd_exec_t
    [/usr/bin/sudo]=sudo_exec_t
    [/usr/bin/su]=su_exec_t
    [/usr/bin/bwrap]=bin_t
    [/etc/crypttab]=etc_t
    [/etc/login.defs]=etc_t
    [/run/utmp]=initrc_var_run_t
    [/var/log/wtmp]=wtmp_t
    [/var/log/btmp]=faillog_t
    [/var/log/lastlog]=lastlog_t
    [/etc/crontab]=system_cron_spool_t
    [/etc/chrony.conf]=etc_t
    [/etc/resolv.conf]=net_conf_t
    [/etc/nsswitch.conf]=etc_t
    [/etc/hosts]=net_conf_t
    [/etc/issue]=etc_t
    [/etc/issue.net]=etc_t
    [/etc/motd]=etc_t
    [/etc/localtime]=locale_t
)
distinct_path_count=$(grep -oE -- '-F path=[^ ]+' \
    "$TMPDIR/99-hardening.rules" | LC_ALL=C sort -u | wc -l || true)
assert_eq "$distinct_path_count" "${#expected_path_types[@]}" \
    "every exact audit path target has a reviewed SELinux type"
for watched_path in "${!expected_path_types[@]}"; do
    expected_type="${expected_path_types[$watched_path]}"
    assert_eq 2 "$(grep -cF -- \
        "-F path=$watched_path -F perm=" "$TMPDIR/99-hardening.rules")" \
        "exact path has a dual-ABI pair: $watched_path"
    assert_eq 2 "$(grep -E -c -- \
        "-F path=${watched_path//./\\.} -F perm=(wa|x) -F obj_type=${expected_type} -k " \
        "$TMPDIR/99-hardening.rules")" \
        "exact path uses expected object type: $watched_path"
done
assert_eq 70 "$(grep -cE '^-a .* -F path=' "$TMPDIR/99-hardening.rules")" \
    "there are exactly 35 dual-ABI exact path watches"
assert_eq 0 "$(grep -E '^-a .* -F path=' "$TMPDIR/99-hardening.rules" | \
    grep -vc -- '-F obj_type=' || true)" \
    "no exact path watch lacks Btrfs-safe object-type disambiguation"

assert_eq 2 "$(grep -cE '^-a always,exit -F arch=b(32|64) -S mount -S umount2 -F auid>=1000 -F auid!=-1 -F exe!=/usr/bin/bwrap -k mount_ops$' \
    "$TMPDIR/99-hardening.rules")" \
    "non-bwrap user-session mount syscalls retain exact dual-ABI coverage"
assert_eq 2 "$(grep -cE '^-a always,exit -F arch=b(32|64) -F path=/usr/bin/bwrap -F perm=x -F obj_type=bin_t -k mount_ops$' \
    "$TMPDIR/99-hardening.rules")" \
    "each Bubblewrap sandbox retains one typed execution record"
assert_eq 0 "$(grep -cE '^-a always,exit -F arch=b(32|64) -S mount -S umount2 -F auid>=1000 -F auid!=-1 -k mount_ops$' \
    "$TMPDIR/99-hardening.rules" 2>/dev/null || true)" \
    "unbounded Bubblewrap namespace mount logging cannot return"

# --- auditd.conf measured limits and failure behavior -----------------------
assert_grep_extended '^q_depth\s*=\s*2000$'     "$TMPDIR/auditd.conf" "vendor dispatcher q_depth=2000"
assert_grep_extended '^max_log_file\s*=\s*64$'  "$TMPDIR/auditd.conf" "max_log_file=64"
assert_grep_extended '^log_format\s*=\s*ENRICHED$' "$TMPDIR/auditd.conf" "log_format=ENRICHED"
assert_grep_fixed 'days is a maximum age, never a promise' \
    "$TMPDIR/auditd.conf" "retention claim is measured and bounded"
assert_grep_extended '^space_left\s*=\s*8192$' "$TMPDIR/auditd.conf"
assert_grep_fixed 'space_left_action = EXEC /usr/local/sbin/noid-audit-space-alert' \
    "$TMPDIR/auditd.conf"
assert_grep_extended '^admin_space_left\s*=\s*4096$' "$TMPDIR/auditd.conf"
assert_grep_fixed 'admin_space_left_action = EXEC /usr/local/sbin/noid-audit-space-critical' \
    "$TMPDIR/auditd.conf"
assert_grep_extended '^disk_full_action\s*=\s*ROTATE$' "$TMPDIR/auditd.conf"
assert_grep_fixed 'disk_error_action = EXEC /usr/local/sbin/noid-audit-space-critical' \
    "$TMPDIR/auditd.conf"
assert_not_grep_extended 'space_left_action\s*=\s*(SINGLE|HALT)|disk_(full|error)_action\s*=\s*(SINGLE|HALT)' \
    "$TMPDIR/auditd.conf" "no audit-storage action can take the desktop down"
extract_heredoc "$KS_FILE" "AUDIT_SPACE_ALERT_EOF" \
    "$TMPDIR/noid-audit-space-alert" || _fail "audit space alert extraction"
extract_heredoc "$KS_FILE" "AUDITD_LIVE_THRESHOLDS_EOF" \
    "$TMPDIR/noid-auditd-live-thresholds" || _fail "Live threshold helper extraction"
extract_heredoc "$KS_FILE" "AUDITD_LIVE_DROPIN_EOF" \
    "$TMPDIR/10-noid-live-thresholds.conf" || _fail "Live threshold drop-in extraction"
assert_cmd_success "audit storage alert parses" bash -n "$TMPDIR/noid-audit-space-alert"
assert_cmd_success "audit storage alert passes ShellCheck" \
    shellcheck -S warning "$TMPDIR/noid-audit-space-alert"
assert_grep_fixed '/run/noid-privacy/audit-storage-degraded' \
    "$TMPDIR/noid-audit-space-alert" \
    "low-space evidence is published where auditd_t may actually write"
# The helper runs in auditd_t without a domain transition, and the Fedora
# targeted policy grants that domain neither execute on auditctl_exec_t nor a
# transition to auditctl_t -- so calling auditctl here left auditd suspended
# for good. auditctl(8) documents resume as the friendly name for USR2 and
# auditd(8) documents SIGUSR2 as resume, so the signal is sent directly.
assert_grep_fixed 'kill -USR2 "$resume_target"' \
    "$TMPDIR/noid-audit-space-alert" \
    "auditd EXEC pause is resumed through an interface auditd_t already holds"
assert_grep_fixed '/proc/$resume_target/comm' \
    "$TMPDIR/noid-audit-space-alert" \
    "the resume signal is confirmed to target auditd itself"
assert_not_grep 'auditctl --signal resume' "$TMPDIR/noid-audit-space-alert" \
    "the alert helper no longer executes a binary auditd_t cannot reach"
# auditd_t may not create or relabel a directory, so the helper must consume
# the boot-created runtime path rather than installing it.
assert_not_grep_extended \
    '^[[:space:]]*install[[:space:]]+-d.*/var/lib/noid-privacy' \
    "$TMPDIR/noid-audit-space-alert" \
    "the helper does not attempt a directory operation auditd_t is denied"
extract_heredoc "$KS_FILE" "AUDIT_SPACE_CRITICAL_EOF" \
    "$TMPDIR/noid-audit-space-critical" || _fail "audit critical helper extraction"
assert_cmd_success "audit critical helper parses" \
    bash -n "$TMPDIR/noid-audit-space-critical"
assert_cmd_success "audit critical helper passes ShellCheck" \
    shellcheck -S warning "$TMPDIR/noid-audit-space-critical"
assert_grep_fixed 'status=critical' "$TMPDIR/noid-audit-space-critical" \
    "critical helper escalates the durable marker"
assert_grep_fixed 'audit_logging=suspended' "$TMPDIR/noid-audit-space-critical" \
    "critical marker states the suspended-capture consequence"
assert_not_grep_extended '^[[:space:]]*(if ! )?auditctl --signal resume' \
    "$TMPDIR/noid-audit-space-critical" \
    "critical helper never executes a resume: suspend is the deliberate end state (sudo-guidance text stays)"
extract_heredoc "$KS_FILE" "AUDIT_STORAGE_NOTIFY_EOF" \
    "$TMPDIR/noid-audit-storage-notify" || _fail "audit storage notifier extraction"
assert_cmd_success "audit storage notifier parses" \
    bash -n "$TMPDIR/noid-audit-storage-notify"
assert_cmd_success "audit storage notifier passes ShellCheck" \
    shellcheck -S warning "$TMPDIR/noid-audit-storage-notify"
assert_grep_fixed '--urgency=critical' "$TMPDIR/noid-audit-storage-notify" \
    "storage degradation reaches the session as a critical notification"
assert_grep_fixed "stat -c '%U:%G:%a:%h'" \
    "$TMPDIR/noid-audit-storage-notify" \
    "storage notifier rejects redirected, linked or misowned marker state"
assert_grep_fixed '[ ! -e "$MARKER" ] && [ ! -L "$MARKER" ]' \
    "$TMPDIR/noid-audit-storage-notify" \
    "a reviewed marker removal is a quiet successful no-op"
assert_grep_fixed '[[ "${marker_states[0]}" =~ ^(degraded|critical)$ ]]' \
    "$TMPDIR/noid-audit-storage-notify" \
    "storage marker state is unique and closed to the two supported values"
assert_grep_fixed 'loginctl list-sessions --json=short' \
    "$TMPDIR/noid-audit-storage-notify" \
    "storage notifier enumerates machine-readable logind sessions"
for session_property in User Seat Remote Class Type State Active LockedHint; do
    assert_grep_fixed "--property=$session_property" \
        "$TMPDIR/noid-audit-storage-notify" \
        "storage notifier validates logind property: $session_property"
done
assert_grep_fixed 'show-seat "$seat"' "$TMPDIR/noid-audit-storage-notify" \
    "logind seat authority must name the exact active session"
assert_grep_fixed '[ "$locked" = no ]' "$TMPDIR/noid-audit-storage-notify" \
    "locked sessions never receive audit-storage details"
assert_grep_fixed '/usr/bin/setpriv --reuid="$uid" --regid="$gid" --init-groups' \
    "$TMPDIR/noid-audit-storage-notify" \
    "notification delivery drops to the exact account without sudo policy"
assert_grep_fixed '--reset-env /usr/bin/timeout --signal=TERM --kill-after=1s 3s' \
    "$TMPDIR/noid-audit-storage-notify" \
    "target-UID socket checks have a hard timeout without CAP_KILL"
assert_grep_fixed '[ "$bus_status" = "socket:$uid" ]' \
    "$TMPDIR/noid-audit-storage-notify" \
    "redirected or foreign-owned session buses fail closed"
assert_not_grep_extended 'loginctl list-users|sudo -u|/run/user/\*' \
    "$TMPDIR/noid-audit-storage-notify" \
    "storage notification cannot target a generic logged-in or first user"
assert_eq 5 "$(grep -cF \
    '/usr/bin/timeout --signal=TERM --kill-after=1s 3s' \
    "$TMPDIR/noid-audit-storage-notify")" \
    "logind, NSS and socket lookups are individually bounded"
assert_grep_fixed \
    '--reset-env /usr/bin/timeout --signal=TERM --kill-after=1s 5s' \
    "$TMPDIR/noid-audit-storage-notify" \
    "notification timeout executes after the exact UID/GID drop"
extract_heredoc "$KS_FILE" "AUDIT_NOTIFY_SERVICE_EOF" \
    "$TMPDIR/noid-audit-storage-notify.service" || _fail "audit notify service extraction"
extract_heredoc "$KS_FILE" "AUDIT_NOTIFY_PATH_EOF" \
    "$TMPDIR/noid-audit-storage-notify.path" || _fail "audit notify path extraction"
assert_grep_fixed 'PathModified=/run/noid-privacy/audit-storage-degraded' \
    "$TMPDIR/noid-audit-storage-notify.path" \
    "marker replacement triggers the session notifier via inotify"
assert_not_grep 'PathExists=' "$TMPDIR/noid-audit-storage-notify.path" \
    "no steady-state PathExists retrigger loop"
for hardening_line in \
    'TimeoutStartSec=30s' \
    'UMask=0077' \
    'CapabilityBoundingSet=CAP_SETGID CAP_SETUID' \
    'NoNewPrivileges=true' \
    'PrivateDevices=true' \
    'PrivateTmp=true' \
    'InaccessiblePaths=/home /root' \
    'ProtectClock=true' \
    'ProtectControlGroups=true' \
    'ProtectHome=read-only' \
    'ProtectHostname=true' \
    'ProtectKernelLogs=true' \
    'ProtectKernelModules=true' \
    'ProtectKernelTunables=true' \
    'ProtectProc=invisible' \
    'ProtectSystem=strict' \
    'ProcSubset=pid' \
    'LockPersonality=true' \
    'MemoryDenyWriteExecute=true' \
    'RestrictAddressFamilies=AF_UNIX' \
    'RestrictNamespaces=true' \
    'RestrictRealtime=true' \
    'SystemCallArchitectures=native'; do
    assert_grep_fixed "$hardening_line" \
        "$TMPDIR/noid-audit-storage-notify.service" \
        "audit storage notifier hardening: $hardening_line"
done
assert_not_grep 'ProtectHome=true' \
    "$TMPDIR/noid-audit-storage-notify.service" \
    "storage notifier never hides its required /run/user D-Bus sockets"
mkdir -p "$TMPDIR/verify-notify"
sed 's#^ExecStart=.*#ExecStart=/bin/true#' \
    "$TMPDIR/noid-audit-storage-notify.service" \
    > "$TMPDIR/verify-notify/noid-audit-storage-notify.service"
cp "$TMPDIR/noid-audit-storage-notify.path" "$TMPDIR/verify-notify/"
assert_cmd_success "audit notify path/service unit pair verifies" \
    systemd-analyze verify "$TMPDIR/verify-notify/noid-audit-storage-notify.path"
assert_cmd_success "Live threshold helper parses" \
    bash -n "$TMPDIR/noid-auditd-live-thresholds"
assert_cmd_success "Live threshold helper passes ShellCheck" \
    shellcheck -S warning "$TMPDIR/noid-auditd-live-thresholds"
assert_grep_fixed 'rd.live.image|rd.live.image=*) live_image=1' \
    "$TMPDIR/noid-auditd-live-thresholds" \
    "only an explicit Live kernel token selects percentage thresholds"
assert_grep_fixed 'ExecStartPre=-/usr/local/libexec/noid-auditd-live-thresholds' \
    "$TMPDIR/10-noid-live-thresholds.conf" \
    "the selector executes before auditd reads its configuration (failure-tolerant)"
assert_grep_fixed "grep -qxF 'ExecStartPre=-/usr/local/libexec/noid-auditd-live-thresholds'" \
    "$KS_FILE" \
    "Step-10 verification pins the failure-tolerant ExecStartPre (writer/checker parity)"
assert_not_grep 'ExecStartPre=/usr/local/libexec/noid-auditd-live-thresholds' \
    "$KS_FILE" \
    "no stale dash-less ExecStartPre pin remains in Module 12"
{
    sed 's#ExecStartPre=.*#ExecStartPre=/bin/true#' \
        "$TMPDIR/10-noid-live-thresholds.conf"
    printf 'ExecStart=/bin/true\n'
} > "$TMPDIR/noid-auditd-live-thresholds.service"
assert_cmd_success "Live threshold drop-in verifies" \
    systemd-analyze verify "$TMPDIR/noid-auditd-live-thresholds.service"

make_threshold_fixture() {
    local name=$1 cmdline_value=$2 space=$3 admin=$4 root
    root="$TMPDIR/$name"
    mkdir -p "$root/etc/audit" "$root/proc"
    printf '%s\n' "$cmdline_value" > "$root/proc/cmdline"
    cat > "$root/etc/audit/auditd.conf" <<EOF
space_left = $space
space_left_action = EXEC /usr/local/sbin/noid-audit-space-alert
admin_space_left = $admin
admin_space_left_action = EXEC /usr/local/sbin/noid-audit-space-critical
disk_full_action = ROTATE
disk_error_action = EXEC /usr/local/sbin/noid-audit-space-critical
EOF
    chmod 0640 "$root/etc/audit/auditd.conf"
    printf '%s\n' "$root"
}

live_fixture=$(make_threshold_fixture live-thresholds \
    'root=live:CDLABEL=NOID rd.live.image quiet' 8192 4096)
assert_cmd_success "Live threshold fixture applies bounded percentages" \
    env NOID_AUDITD_THRESHOLD_TEST_MODE=1 \
        NOID_AUDITD_THRESHOLD_TEST_ROOT="$live_fixture" \
        bash "$TMPDIR/noid-auditd-live-thresholds"
assert_grep_fixed 'space_left = 15%' "$live_fixture/etc/audit/auditd.conf"
assert_grep_fixed 'admin_space_left = 10%' "$live_fixture/etc/audit/auditd.conf"
assert_eq "$(id -u):$(id -g):640" \
    "$(stat -c '%u:%g:%a' "$live_fixture/etc/audit/auditd.conf")" \
    "Live threshold replacement preserves exact fixture metadata"
assert_cmd_success "Live threshold fixture is idempotent" \
    env NOID_AUDITD_THRESHOLD_TEST_MODE=1 \
        NOID_AUDITD_THRESHOLD_TEST_ROOT="$live_fixture" \
        bash "$TMPDIR/noid-auditd-live-thresholds"

installed_fixture=$(make_threshold_fixture installed-thresholds \
    'root=UUID=test ro quiet' 8192 4096)
installed_before=$(sha256sum "$installed_fixture/etc/audit/auditd.conf")
assert_cmd_success "installed threshold fixture is a strict no-op" \
    env NOID_AUDITD_THRESHOLD_TEST_MODE=1 \
        NOID_AUDITD_THRESHOLD_TEST_ROOT="$installed_fixture" \
        bash "$TMPDIR/noid-auditd-live-thresholds"
assert_eq "$installed_before" \
    "$(sha256sum "$installed_fixture/etc/audit/auditd.conf")" \
    "installed absolute threshold bytes remain unchanged"

hostile_fixture=$(make_threshold_fixture hostile-thresholds \
    'root=live:CDLABEL=NOID rd.live.image=1 quiet' 7000 3500)
assert_cmd_failure "Live threshold helper rejects an unexpected embedded pair" \
    env NOID_AUDITD_THRESHOLD_TEST_MODE=1 \
        NOID_AUDITD_THRESHOLD_TEST_ROOT="$hostile_fixture" \
        bash "$TMPDIR/noid-auditd-live-thresholds"

# Every helper below has a closed invocation contract. auditd.conf's EXEC
# interface cannot pass arguments to the two storage-action scripts, both
# systemd units use argumentless ExecStart/ExecStartPre, and the plugin config
# has no args= field. The controller/toggle accept zero or one mode but never
# surplus argv. Derive safe fixtures that replace the first real dependency
# after the intended gate with an exit-97 marker. This proves the old path was
# reachable without touching audit state, runtime spools, sessions or units.
M12_ARGV_ROOT="$TMPDIR/m12-argv-fixtures"
mkdir -p "$M12_ARGV_ROOT"
M12_ARGV_MARKER="$M12_ARGV_ROOT/dependency.reached"
export M12_ARGV_MARKER

for helper in space-alert space-critical storage-notify; do
    source_path="$TMPDIR/noid-audit-${helper}"
    sed 's|^umask 077$|/usr/bin/printf "%s\\n" reached > "$M12_ARGV_MARKER"; exit 97|' \
        "$source_path" > "$M12_ARGV_ROOT/$helper"
done

awk '
    /^if \[ "\${NOID_AUDITD_THRESHOLD_TEST_MODE:-0}" = 1 \]; then$/ {
        print "/usr/bin/printf \"%s\\\\n\" reached > \"$M12_ARGV_MARKER\""
        print "exit 97"
    }
    { print }
' "$TMPDIR/noid-auditd-live-thresholds" > "$M12_ARGV_ROOT/live-thresholds"

sed 's|^CONF=.*|/usr/bin/printf "%s\\n" reached > "$M12_ARGV_MARKER"; exit 97|' \
    "$TMPDIR/noid-audit-notify-controller" > "$M12_ARGV_ROOT/controller"
sed \
    -e 's#/usr/local/lib/noid-privacy/agent-install-format.sh#/nonexistent/noid-format.sh#g' \
    -e 's|^UNIT=.*|/usr/bin/printf "%s\\n" reached > "$M12_ARGV_MARKER"; exit 97|' \
    "$TMPDIR/noid-toggle-audit-notify" > "$M12_ARGV_ROOT/toggle"

awk '
    /^    syslog[.]openlog\("noid-audit-event-notify"/ {
        print "    pathlib.Path(os.environ[\"M12_ARGV_MARKER\"]).write_text(\"reached\", encoding=\"utf-8\")"
        print "    return 97"
    }
    { print }
' "$TMPDIR/noid-audit-event-notify" > "$M12_ARGV_ROOT/event-notify"
sed \
    -e 's|^    return AuditNotificationPlugin().run()$|    pathlib.Path(os.environ["M12_ARGV_MARKER"]).write_text("reached", encoding="utf-8"); return 97|' \
    -e 's|^    raise SystemExit(AuditNotificationPlugin().run())$|    pathlib.Path(os.environ["M12_ARGV_MARKER"]).write_text("reached", encoding="utf-8"); raise SystemExit(97)|' \
    "$TMPDIR/audit-notify.sh" > "$M12_ARGV_ROOT/audit-plugin"

for helper in space-alert space-critical storage-notify live-thresholds \
              controller toggle; do
    assert_cmd_success "M12 argv fixture parses: $helper" \
        /usr/bin/bash -n "$M12_ARGV_ROOT/$helper"
done
for helper in event-notify audit-plugin; do
    assert_cmd_success "M12 argv fixture compiles: $helper" \
        /usr/bin/python3 -c \
        'import sys; p=sys.argv[1]; compile(open(p, encoding="utf-8").read(), p, "exec")' \
        "$M12_ARGV_ROOT/$helper"
done

run_m12_argv_rejection() {
    local runtime=$1 script=$2 diagnostic=$3 label=$4 rc
    shift 4
    rm -f -- "$M12_ARGV_MARKER"
    set +e
    PATH="$M12_ARGV_ROOT/untrusted-path" \
    M12_ARGV_MARKER="$M12_ARGV_MARKER" \
        "$runtime" "$script" "$@" \
        > "$M12_ARGV_ROOT/stdout" 2> "$M12_ARGV_ROOT/stderr"
    rc=$?
    set -e
    assert_eq 2 "$rc" "$label rejects hostile argv before its dependency"
    assert_eq '' "$(< "$M12_ARGV_ROOT/stdout")" \
        "$label hostile rejection keeps stdout empty"
    assert_eq "$diagnostic" "$(< "$M12_ARGV_ROOT/stderr")" \
        "$label hostile rejection is constant"
    if [[ -e $M12_ARGV_MARKER ]]; then
        _fail "$label hostile argv reached its dependency"
    else
        _pass "$label hostile argv cannot reach its dependency"
    fi
}

exercise_m12_noarg_matrix() {
    local runtime=$1 script=$2 diagnostic=$3 label=$4
    run_m12_argv_rejection "$runtime" "$script" "$diagnostic" "$label unknown" unknown
    run_m12_argv_rejection "$runtime" "$script" "$diagnostic" "$label empty" ''
    run_m12_argv_rejection "$runtime" "$script" "$diagnostic" "$label surplus" one two
    run_m12_argv_rejection "$runtime" "$script" "$diagnostic" "$label newline" $'line\nbreak'
    run_m12_argv_rejection "$runtime" "$script" "$diagnostic" "$label escape" $'\033[31m'
}

exercise_m12_surplus_matrix() {
    local script=$1 diagnostic=$2 label=$3
    run_m12_argv_rejection /usr/bin/bash "$script" "$diagnostic" "$label extra" on extra
    run_m12_argv_rejection /usr/bin/bash "$script" "$diagnostic" "$label empty-extra" on ''
    run_m12_argv_rejection /usr/bin/bash "$script" "$diagnostic" "$label multi-extra" on one two
    run_m12_argv_rejection /usr/bin/bash "$script" "$diagnostic" "$label newline-extra" on $'line\nbreak'
    run_m12_argv_rejection /usr/bin/bash "$script" "$diagnostic" "$label escape-extra" on $'\033[31m'
}

exercise_m12_noarg_matrix /usr/bin/bash "$M12_ARGV_ROOT/space-alert" \
    'ERROR: noid-audit-space-alert accepts no arguments' 'audit low-space EXEC helper'
exercise_m12_noarg_matrix /usr/bin/bash "$M12_ARGV_ROOT/space-critical" \
    'ERROR: noid-audit-space-critical accepts no arguments' 'audit critical-space EXEC helper'
exercise_m12_noarg_matrix /usr/bin/bash "$M12_ARGV_ROOT/live-thresholds" \
    'ERROR: noid-auditd-live-thresholds accepts no arguments' 'audit Live-threshold helper'
exercise_m12_noarg_matrix /usr/bin/bash "$M12_ARGV_ROOT/storage-notify" \
    'ERROR: noid-audit-storage-notify accepts no arguments' 'audit storage notifier'
exercise_m12_noarg_matrix /usr/bin/python3 "$M12_ARGV_ROOT/event-notify" \
    'ERROR: noid-audit-event-notify accepts no arguments' 'audit event drain'
exercise_m12_noarg_matrix /usr/bin/python3 "$M12_ARGV_ROOT/audit-plugin" \
    'ERROR: audit-notify.sh accepts no arguments' 'audit stdin plugin'
exercise_m12_surplus_matrix "$M12_ARGV_ROOT/controller" \
    'ERROR: noid-audit-notify-controller accepts at most one argument' \
    'audit plugin controller'
exercise_m12_surplus_matrix "$M12_ARGV_ROOT/toggle" \
    'ERROR: noid-toggle-audit-notify accepts at most one argument' \
    'audit notification toggle'

assert_m12_dependency_reachable() {
    local runtime=$1 script=$2 label=$3 rc
    shift 3
    rm -f -- "$M12_ARGV_MARKER"
    set +e
    M12_ARGV_MARKER="$M12_ARGV_MARKER" \
        "$runtime" "$script" "$@" \
        > "$M12_ARGV_ROOT/stdout" 2> "$M12_ARGV_ROOT/stderr"
    rc=$?
    set -e
    assert_eq 97 "$rc" "$label valid contract reaches its dependency fixture"
    if [[ -e $M12_ARGV_MARKER ]]; then
        _pass "$label dependency fixture is discriminating"
    else
        _fail "$label dependency fixture was not reached"
    fi
}

assert_m12_dependency_reachable /usr/bin/bash "$M12_ARGV_ROOT/space-alert" 'audit low-space EXEC helper'
assert_m12_dependency_reachable /usr/bin/bash "$M12_ARGV_ROOT/space-critical" 'audit critical-space EXEC helper'
assert_m12_dependency_reachable /usr/bin/bash "$M12_ARGV_ROOT/live-thresholds" 'audit Live-threshold helper'
assert_m12_dependency_reachable /usr/bin/bash "$M12_ARGV_ROOT/storage-notify" 'audit storage notifier'
assert_m12_dependency_reachable /usr/bin/python3 "$M12_ARGV_ROOT/event-notify" 'audit event drain'
assert_m12_dependency_reachable /usr/bin/python3 "$M12_ARGV_ROOT/audit-plugin" 'audit stdin plugin'
assert_m12_dependency_reachable /usr/bin/bash "$M12_ARGV_ROOT/controller" 'audit plugin controller' on
assert_m12_dependency_reachable /usr/bin/bash "$M12_ARGV_ROOT/toggle" 'audit notification toggle' on
unset M12_ARGV_MARKER

# --- audit.rules contains -D (Fedora gotcha fix) ----------------------------
assert_grep_extended '^-D$' "$TMPDIR/audit.rules" "audit.rules = -D only"
assert_not_grep '^-a task,never' "$TMPDIR/audit.rules"

# --- SELinux booleans set OFF in kickstart source ---------------------------
assert_grep_fixed 'boolean_set selinuxuser_execstack' "$KS_FILE"
assert_grep_fixed 'boolean_set selinuxuser_execmod'   "$KS_FILE"
assert_grep_fixed 'semanage boolean -E' "$KS_FILE" \
    "persistent boolean state is read from the native policy store"
assert_grep_fixed 'grep -xcF "boolean -m -0 $boolean_name"' "$KS_FILE" \
    "each persistent boolean override must be unique and exact"
assert_not_grep 'booleans.local' "$KS_FILE" \
    "M12 never writes SELinux policy-store internals directly"
assert_grep_fixed 'no maintained interface could persist $name=off' "$KS_FILE" \
    "boolean persistence fails closed when both native interfaces fail"
assert_grep_fixed "rpm -qf --qf '%{NAME}\\n' \"\$LIVEINST\"" "$KS_FILE" \
    "liveinst ownership comes from the signed RPM database"
assert_grep_fixed 'rpm_payload_file_pristine anaconda-live "$LIVEINST"' "$KS_FILE" \
    "liveinst bytes are bound to its exact signed RPM file record"
assert_grep_fixed "stat -c '%U:%G:%a' \"\$LIVEINST\"" "$KS_FILE" \
    "liveinst metadata is checked independently"
assert_not_grep 'rpm -Vf "$LIVEINST"' "$KS_FILE" \
    "liveinst verification never widens to intentionally branded package siblings"
assert_grep_fixed "[%{FILENAMES}\\t%{FILEDIGESTS}\\n]" "$KS_FILE" \
    "liveinst verifier selects one exact RPM filename/digest record"
assert_not_grep_extended 'LIVEINST_SOURCE_SHA256|LIVEINST_FINAL_SHA256' "$KS_FILE" \
    "M12 carries no private liveinst byte-patch contract"
assert_not_grep_extended 'sed -i.*setenforce|awk.*usr/bin/liveinst|LIVEINST_FINAL_SHA256' "$KS_FILE" \
    "M12 neither patches liveinst nor creates an integrity suppression"
assert_grep_fixed 'permissive installation environment' "$KS_FILE" \
    "vendor installer trade-off is explicit"
assert_grep_fixed 'M13 explicitly content-tracks /boot/efi with a VFAT-safe ESP rule' \
    "$KS_FILE" "SELinux rationale matches active ESP content coverage"
assert_not_grep 'M13 explicitly excludes /boot/efi' "$KS_FILE" \
    "stale ESP-exclusion rationale cannot return"
assert_not_grep 'preserving the M13 /boot/efi exclusion intent' "$KS_FILE" \
    "SELinux comment does not claim a nonexistent exclusion"
assert_grep_fixed 'key_fail=0' "$KS_FILE" \
    "audit-key aggregate verdict starts from a closed local counter"
assert_grep_fixed 'key_fail=$((key_fail + 1))' "$KS_FILE" \
    "every missing audit key invalidates the aggregate verdict"
assert_grep_fixed 'if [ "$key_fail" -eq 0 ]; then' "$KS_FILE" \
    "all-keys-present is emitted only after a clean aggregate result"
assert_grep_fixed 'grep -qE -- "(^|[[:space:]])-k[[:space:]]+${key}([[:space:]]|$)"' \
    "$KS_FILE" "audit-key lookup uses explicit token boundaries"

# The custom module is closed, warning-clean and contains only ten reviewed
# subject/target/class edges. The former MediaWriter rule was process-wide,
# not executable-specific, and must not return.
assert_cmd_success "SELinux module compiles with warnings fatal" \
    checkmodule -E -M -m -o "$TMPDIR/noid-selinux-fixes.mod" \
        "$TMPDIR/noid-selinux-fixes.te"
assert_cmd_success "SELinux module packages" \
    semodule_package -o "$TMPDIR/noid-selinux-fixes.pp" \
        -m "$TMPDIR/noid-selinux-fixes.mod"
assert_grep_fixed 'module noid-selinux-fixes 1.9;' \
    "$TMPDIR/noid-selinux-fixes.te" "SELinux module version is current"
assert_eq 10 "$(grep -c '^allow ' "$TMPDIR/noid-selinux-fixes.te")" \
    "custom module has exactly ten reviewed allow edges"
assert_grep_fixed 'allow init_t auditd_etc_t:dir mounton;' \
    "$TMPDIR/noid-selinux-fixes.te" \
    "audit controller sandbox has the exact mount-point permission it needs"
assert_grep_fixed 'It grants init_t no new' "$TMPDIR/noid-selinux-fixes.te" \
    "audit sandbox mounton rationale names the bounded permission surface"
assert_grep_fixed 'allow passwd_t hugetlbfs_t:file { read write map };' \
    "$TMPDIR/noid-selinux-fixes.te" \
    "password creation has the exact required Yescrypt HugeTLB edge"
assert_grep_fixed 'allow chkpwd_t hugetlbfs_t:file { read write map };' \
    "$TMPDIR/noid-selinux-fixes.te" \
    "password verification has the exact required Yescrypt HugeTLB edge"
assert_grep_fixed 'allow updpwd_t hugetlbfs_t:file { read write map };' \
    "$TMPDIR/noid-selinux-fixes.te" \
    "password history has the exact required Yescrypt HugeTLB edge"
assert_grep_fixed 'grants only the three access operations needed' \
    "$TMPDIR/noid-selinux-fixes.te" \
    "Yescrypt HugeTLB rationale names the bounded permission surface"
assert_not_grep_extended 'unconfined_t|user_tmp_t|execmod' "$TMPDIR/noid-selinux-fixes.te" \
    "custom module grants no broad user-domain executable modification"
assert_grep_fixed 'checkpolicy' "$KS_FILE" \
    "the checkmodule-owning package is fail-fast gated"
assert_grep_fixed 'checkmodule -E -M -m' "$KS_FILE" \
    "policy compiler warnings are fatal"
assert_grep_fixed 'MODULE_PRIORITY=400' "$TMPDIR/noid-selinux-policy-reconcile" \
    "module install uses one explicit local-policy priority"
assert_grep_fixed '/usr/libexec/selinux/hll/pp' "$KS_FILE" \
    "selected module checksum uses the vendor translator"
assert_grep_fixed 'module-store entry is missing or shadowed' \
    "$TMPDIR/noid-selinux-policy-reconcile" \
    "duplicate or higher-priority module state is fatal"
assert_grep_fixed 'module_checksum" = "$expected_checksum' \
    "$TMPDIR/noid-selinux-policy-reconcile" \
    "installed selected-module bytes are exact"
assert_cmd_success "SELinux policy reconcile helper parses" \
    bash -n "$TMPDIR/noid-selinux-policy-reconcile"
assert_grep_fixed '/usr/bin/semodule -X "$MODULE_PRIORITY" -i "$MODULE_PP"' \
    "$TMPDIR/noid-selinux-policy-reconcile" \
    "policy update recommits the retained module against the new base"
assert_grep_fixed '/usr/bin/semodule -X 400 -i "$NOID_SE_DIR/noid-selinux-fixes.pp"' \
    "$KS_FILE" \
    "initial compose installs the compiled policy directly from the kickstart runner"
assert_not_grep '^/usr/local/sbin/noid-selinux-policy-reconcile$' "$KS_FILE" \
    "Anaconda never executes the runtime bin_t reconciler from kernel_t"
assert_grep_fixed 'module_checksum" != "$expected_module_checksum"' "$KS_FILE" \
    "initial compose verifies the selected module checksum"
assert_grep_fixed '/usr/bin/semodule -lfull -m' \
    "$TMPDIR/noid-selinux-policy-reconcile" \
    "policy update inspects every local-module priority"
assert_grep_fixed '/usr/bin/checkmodule -E -M -m' \
    "$TMPDIR/noid-selinux-policy-reconcile" \
    "retained policy source is recompiled before installation"
assert_grep_fixed 'source_checksum" = "$expected_checksum' \
    "$TMPDIR/noid-selinux-policy-reconcile" \
    "retained source and package must translate to identical CIL"
for signal_contract in \
    "trap 'exit 129' HUP" \
    "trap 'exit 130' INT" \
    "trap 'exit 143' TERM"; do
    assert_grep_fixed "$signal_contract" "$TMPDIR/noid-selinux-policy-reconcile" \
        "policy reconciler preserves the signal-derived exit status"
    assert_grep_fixed "$signal_contract" "$TMPDIR/noid-auditd-live-thresholds" \
        "Live threshold helper preserves the signal-derived exit status"
done
assert_grep_fixed 'module_checksum" = "$expected_checksum' \
    "$TMPDIR/noid-selinux-policy-reconcile" \
    "policy update verifies the selected CIL checksum"
assert_eq 1 "$(grep -c '^post_transaction:' "$TMPDIR/noid-selinux-policy.actions")" \
    "SELinux policy action has one package trigger"
assert_grep_fixed \
    'post_transaction:selinux-policy-targeted:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/local/sbin/noid-selinux-policy-reconcile\ >/dev/null' \
    "$TMPDIR/noid-selinux-policy.actions" \
    "targeted-policy updates are host-only and fail-visible"

# --- audit-notify: maintained complete-event parser + exact session ---------
assert_file_exists "$PLUGIN_SOURCE" "canonical audit notification plugin exists"
assert_file_exists "$PLUGIN_FIXTURE" "audit notification behavior fixture exists"
assert_grep_fixed 'sys.dont_write_bytecode = True' "$PLUGIN_FIXTURE" \
    "audit notification fixture cannot leave source-tree bytecode"
assert_cmd_success "embedded plugin is byte-equal to canonical source" \
    cmp -s "$PLUGIN_SOURCE" "$TMPDIR/audit-notify.sh"
assert_cmd_success "canonical plugin parses without writing pyc" \
    python3 -c 'import sys; path=sys.argv[1]; compile(open(path, encoding="utf-8").read(), path, "exec")' \
        "$PLUGIN_SOURCE"
assert_cmd_success "embedded plugin parses without writing pyc" \
    python3 -c 'import sys; path=sys.argv[1]; compile(open(path, encoding="utf-8").read(), path, "exec")' \
        "$TMPDIR/audit-notify.sh"
assert_cmd_success "canonical plugin behavior fixtures pass" \
    python3 "$PLUGIN_FIXTURE" "$PLUGIN_SOURCE"
assert_cmd_success "embedded plugin behavior fixtures pass" \
    python3 "$PLUGIN_FIXTURE" "$TMPDIR/audit-notify.sh"
key_count=$(python3 -B - "$PLUGIN_SOURCE" <<'PY'
import importlib.util
import sys
spec = importlib.util.spec_from_file_location("noid_audit_notify", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
print(len(module.CRITICAL_KEYS))
PY
)
assert_eq "16" "$key_count" "CRITICAL_KEYS has exactly 16 keys"
assert_grep_fixed '"aide_integrity",' "$PLUGIN_SOURCE" \
    "AIDE evidence changes are eligible for opt-in critical notification"
assert_grep_fixed 'auparse.AuParser(auparse.AUSOURCE_FEED, None)' \
    "$TMPDIR/audit-notify.sh" "plugin uses the maintained auparse feed API"
assert_grep_fixed 'AUPARSE_CB_EVENT_READY' "$TMPDIR/audit-notify.sh" \
    "only complete events enter notification policy"
# The session gauntlet moved verbatim into the drain unit: auditd execve()s the
# plugin without a domain transition, so it runs in auditd_t, which holds no
# setuid/setgid capability and cannot reach a session_dbusd_tmp_t session bus.
# Assert the gauntlet at its new home AND assert it cannot come back.
assert_grep_fixed 'row.get("uid") != uid' "$TMPDIR/noid-audit-event-notify" \
    "desktop session must match the event AUID"
assert_grep_fixed 'LockedHint' "$TMPDIR/noid-audit-event-notify" \
    "locked graphical sessions do not receive sensitive paths"
assert_grep_fixed 'ActiveSession' "$TMPDIR/noid-audit-event-notify" \
    "logind seat authority selects the active session"
assert_grep_fixed '/usr/bin/setpriv' "$TMPDIR/noid-audit-event-notify" \
    "delivery drops privilege before touching a user session"
assert_grep_fixed '/usr/bin/notify-send' "$TMPDIR/noid-audit-event-notify" \
    "delivery uses the session notification service"
assert_not_grep '/usr/bin/setpriv' "$TMPDIR/audit-notify.sh" \
    "auditd-hosted plugin never attempts a privilege change it cannot make"
assert_not_grep '/usr/bin/notify-send' "$TMPDIR/audit-notify.sh" \
    "auditd-hosted plugin never attempts session-bus delivery"
assert_not_grep '/usr/bin/loginctl' "$TMPDIR/audit-notify.sh" \
    "auditd-hosted plugin does not enumerate desktop sessions"
assert_grep_fixed 'QUEUE_LIMIT = 512' "$TMPDIR/audit-notify.sh" \
    "plugin work queue is explicitly bounded"
assert_grep_fixed 'SPOOL_LIMIT = 64' "$TMPDIR/audit-notify.sh" \
    "handoff spool is explicitly bounded against an absent drain"
assert_grep_fixed 'self.mark_degraded("notification-spool-full")' \
    "$TMPDIR/audit-notify.sh" \
    "reaching the spool bound publishes durable degraded evidence"
assert_grep_fixed '(command, executable) in ROUTINE_PROCESSES' \
    "$TMPDIR/audit-notify.sh" \
    "routine suppression binds process-controlled comm to an absolute executable"
assert_grep_fixed 'temporary_parent=SPOOL_DIR.parent' \
    "$TMPDIR/audit-notify.sh" \
    "spool requests stage outside the level-triggered watched directory"
assert_grep_fixed 'prefix=f".{path.name}.", dir=temporary_parent' \
    "$TMPDIR/audit-notify.sh" \
    "atomic writer honors its reviewed sibling staging directory"
assert_not_grep 'path.parent.mkdir(parents=True, exist_ok=True)' \
    "$TMPDIR/audit-notify.sh" \
    "atomic writes never recreate a missing parent with ambient permissions"
assert_grep_fixed 'DEGRADED_MARKER = RUNTIME_DIR / "audit-notify-degraded"' \
    "$TMPDIR/audit-notify.sh" \
    "auditd_t publishes latched degradation inside its writable runtime type"
assert_not_grep_fixed '/var/lib/noid-privacy/audit-notify-degraded' \
    "$KS_FILE" "no automated health reader depends on an unwritable var_lib_t marker"
assert_grep_fixed '/run/noid-privacy/audit-notify-degraded' \
    "$FINALIZE_KS" "final verification consumes the writable runtime marker"
assert_grep_fixed 'os.O_RDONLY | os.O_DIRECTORY' \
    "$TMPDIR/audit-notify.sh" \
    "atomic plugin state fsyncs the parent directory after replacement"
assert_grep_fixed 'marker_persisted = False' "$TMPDIR/audit-notify.sh" \
    "persistent-marker failure degrades without terminating the worker"
assert_grep_fixed 'notification-worker-{type(error).__name__}' \
    "$TMPDIR/audit-notify.sh" \
    "unexpected delivery exceptions cannot silently kill the worker"
assert_grep_fixed 'initial-health-write-failed' "$TMPDIR/audit-notify.sh" \
    "initial health-state failure is persistently degraded and nonzero"
assert_grep_fixed 'final-health-write-failed' "$TMPDIR/audit-notify.sh" \
    "final health-write failure produces a nonzero degraded exit"
assert_grep_fixed 'including an unchanged active=yes reload' \
    "$TMPDIR/audit-notify.sh" \
    "plugin documents auditd-owned clean EOF reload lifecycle"
assert_not_grep 'auditd-plugin-input-closed' "$TMPDIR/audit-notify.sh" \
    "clean dispatcher EOF never creates false persistent degradation"
assert_grep_fixed '/usr/libexec/noid-update-window-active' \
    "$TMPDIR/audit-notify.sh" \
    "update suppression delegates to M25's process/lock validator"
assert_grep_fixed 'timeout=1' "$TMPDIR/audit-notify.sh" \
    "update-window validation cannot stall the audit notification worker"
assert_not_grep_extended 'UPDATE_MARKER|\.is_file\(\).*UPDATE_SUPPRESSED_KEYS' \
    "$TMPDIR/audit-notify.sh" \
    "mere marker existence cannot suppress critical audit notifications"
assert_not_grep_extended 'tail -n 0 -F|WATCHDOG_THRESHOLD|/run/user/\*' \
    "$TMPDIR/audit-notify.sh" \
    "raw tail parser and first-runtime-directory user selection are absent"

# --- audit event delivery: normally-domained drain unit ---------------------
assert_file_exists "$NOTIFIER_SOURCE" "canonical audit event notifier exists"
assert_file_exists "$NOTIFIER_FIXTURE" "audit event notifier fixture exists"
assert_grep_fixed 'sys.dont_write_bytecode = True' "$NOTIFIER_FIXTURE" \
    "event notifier fixture cannot leave source-tree bytecode"
assert_cmd_success "embedded event notifier is byte-equal to canonical source" \
    cmp -s "$NOTIFIER_SOURCE" "$TMPDIR/noid-audit-event-notify"
assert_cmd_success "canonical event notifier parses without writing pyc" \
    python3 -c 'import sys; path=sys.argv[1]; compile(open(path, encoding="utf-8").read(), path, "exec")' \
        "$NOTIFIER_SOURCE"
assert_cmd_success "canonical event notifier behavior fixtures pass" \
    python3 "$NOTIFIER_FIXTURE" "$NOTIFIER_SOURCE"
assert_cmd_success "embedded event notifier behavior fixtures pass" \
    python3 "$NOTIFIER_FIXTURE" "$TMPDIR/noid-audit-event-notify"
# DirectoryNotEmpty= is level-triggered: a request written while the drain is
# already running re-triggers the unit. An edge-triggered PathModified= on a
# single request file would silently drop that event instead.
assert_grep_fixed 'DirectoryNotEmpty=/run/noid-privacy/audit-notify.d' \
    "$TMPDIR/noid-audit-event-notify.path" \
    "spool watcher re-triggers while requests remain"
assert_not_grep '^PathModified=' "$TMPDIR/noid-audit-event-notify.path" \
    "spool watcher is not edge-triggered on a single request file"
assert_grep_fixed 'ExecStart=/usr/local/libexec/noid-audit-event-notify' \
    "$TMPDIR/noid-audit-event-notify.service" \
    "drain unit runs the reviewed notifier"
assert_grep_fixed 'CapabilityBoundingSet=CAP_SETGID CAP_SETUID' \
    "$TMPDIR/noid-audit-event-notify.service" \
    "drain unit keeps exactly the two capabilities setpriv needs"
assert_grep_fixed 'ProtectSystem=strict' \
    "$TMPDIR/noid-audit-event-notify.service" \
    "drain unit runs with a read-only system hierarchy"
assert_grep_fixed 'ReadWritePaths=/run/noid-privacy' \
    "$TMPDIR/noid-audit-event-notify.service" \
    "drain unit may retire the requests it handled"
assert_grep_fixed 'InaccessiblePaths=/home /root' \
    "$TMPDIR/noid-audit-event-notify.service" \
    "drain unit cannot read user or root home content"
assert_grep_fixed 'RestrictAddressFamilies=AF_UNIX' \
    "$TMPDIR/noid-audit-event-notify.service" \
    "drain unit reaches no network address family"
assert_grep_fixed 'NoNewPrivileges=true' \
    "$TMPDIR/noid-audit-event-notify.service" \
    "drain unit cannot regain privilege beyond its bounding set"
assert_grep_fixed 'retire_request(entry)' "$NOTIFIER_SOURCE" \
    "every handled request uses non-throwing retirement"
assert_grep_fixed 'audit notification request retirement failed' \
    "$NOTIFIER_SOURCE" \
    "an unremovable entry is logged without aborting the remaining drain"
# The watchdog has to sit INSIDE setpriv, exactly as the sibling shell notifier
# pins it at :354. This process is uid 0 with a bounding set of CAP_SETGID and
# CAP_SETUID only, so it has no CAP_KILL and cannot signal a child that already
# dropped to another uid: subprocess's own `timeout=` then raises
# PermissionError out of Popen.__exit__ and blocks in an unbounded wait().
# Verified live -- "SIGKILL -> Operation not permitted", child still running.
notifier_setpriv_calls=$(grep -c '"/usr/bin/setpriv",' "$NOTIFIER_SOURCE" || true)
notifier_inner_timeouts=$(grep -c '"/usr/bin/timeout",' "$NOTIFIER_SOURCE" || true)
assert_eq "$notifier_setpriv_calls" "$notifier_inner_timeouts" \
    "every setpriv'd child carries its own target-uid watchdog"
assert_grep_fixed '"--kill-after=1s",' "$NOTIFIER_SOURCE" \
    "the inner watchdog escalates to SIGKILL as the target uid"
# Each outer Python timeout must outlast its inner watchdog, otherwise it fires
# first and re-enters the unkillable-child path this construction avoids.
assert_grep_fixed 'timeout=10,' "$NOTIFIER_SOURCE" \
    "bus probe outer backstop outlasts its inner 3s+1s watchdog"
assert_grep_fixed 'timeout=12,' "$NOTIFIER_SOURCE" \
    "notify-send outer backstop outlasts its inner 5s+1s watchdog"
unset notifier_setpriv_calls notifier_inner_timeouts
assert_grep_fixed 'DRAIN_LIMIT = 64' "$NOTIFIER_SOURCE" \
    "one drain invocation is explicitly bounded"
# The fixture rebinds these two so an unprivileged run can exercise the
# metadata predicates. Pin the SHIPPED values here, or the seam could silently
# become a weaker check that no test would notice.
assert_grep_fixed 'TRUSTED_UID = 0' "$TMPDIR/noid-audit-event-notify" \
    "shipped drain trusts only a root-owned spool"
assert_grep_fixed 'TRUSTED_GID = 0' "$TMPDIR/noid-audit-event-notify" \
    "shipped drain trusts only a root-group spool"
assert_grep_fixed 'stat.S_IMODE(status.st_mode) == 0o700' "$NOTIFIER_SOURCE" \
    "drain refuses a spool directory any non-root identity could write"
assert_grep_fixed 'stat.S_IMODE(status.st_mode) != 0o600' "$NOTIFIER_SOURCE" \
    "drain refuses a request any non-root identity could rewrite"
# Reproduced live on this host: with CapabilityBoundingSet=CAP_SETGID CAP_SETUID
# the unit has no CAP_DAC_OVERRIDE, so a root-side lstat of the user's own 0700
# /run/user/<uid> fails EACCES on every real desktop. The bus must be inspected
# as the target user, exactly as the sibling storage notifier does.
assert_grep_fixed 'f"socket:{uid}"' "$NOTIFIER_SOURCE" \
    "session bus is proven a socket owned by the event AUID"
assert_not_grep 'bus.lstat()' "$NOTIFIER_SOURCE" \
    "session bus is never inspected with privileges the unit does not keep"
assert_grep_fixed 'LC_ALL=C.UTF-8' "$NOTIFIER_SOURCE" \
    "translated stat output can never reach the bus type comparison"
assert_not_grep 'CAP_DAC_OVERRIDE' "$TMPDIR/noid-audit-event-notify.service" \
    "drain does not regain filesystem override to reach a user runtime dir"

assert_grep_fixed 'M12_FILE_ARTIFACTS=(' "$KS_FILE" \
    "generated M12 files have one canonical metadata/label inventory"
assert_eq 22 "$(sed -n '/^M12_FILE_ARTIFACTS=(/,/^)/p' "$KS_FILE" | \
    grep -cE "^    '/")" \
    "all 22 generated Module-12 files are in the final inventory"
assert_grep_fixed "stat -c '%U:%G:%a:%h'" "$KS_FILE" \
    "generated files require exact owner, mode and single hardlink"
assert_grep_fixed '/usr/bin/matchpathcon -V "$m12_artifact"' "$KS_FILE" \
    "generated files must match the active SELinux file-context policy"
assert_not_grep_extended 'restorecon .*2>/dev/null|restorecon .*\|\| true' \
    "$KS_FILE" "SELinux label restoration is never best-effort"

assert_eq $'active = no\npath = /usr/local/bin/audit-notify.sh\ntype = always\nformat = string' \
    "$(cat "$TMPDIR/noid-notify.conf")" \
    "auditd plugin ships in an exact inactive string-feed state"
assert_cmd_success "audit notification controller parses" \
    bash -n "$TMPDIR/noid-audit-notify-controller"
assert_cmd_success "audit notification controller passes ShellCheck" \
    shellcheck -S warning "$TMPDIR/noid-audit-notify-controller"
assert_grep_fixed 'auditctl --signal reload' \
    "$TMPDIR/noid-audit-notify-controller" \
    "controller uses auditd's maintained reload interface"
assert_grep_fixed 'runtime_degraded=active-plugin-not-running' \
    "$TMPDIR/noid-audit-notify-controller" \
    "controller status rejects active=yes without the exact live plugin"
assert_grep_fixed 'existing audit notification degradation must be reviewed' \
    "$TMPDIR/noid-audit-notify-controller" \
    "controller never clears or ignores existing degradation evidence"
assert_grep_fixed 'stable_samples=$((stable_samples + 1))' \
    "$TMPDIR/noid-audit-notify-controller" \
    "activation requires consecutive healthy live-plugin samples"
assert_grep_fixed 'for _ in 1 2 3; do' \
    "$TMPDIR/noid-audit-notify-controller" \
    "status bounds retries across auditd dispatcher replacement"
assert_grep_fixed 'Type=oneshot' "$TMPDIR/audit-notify.service" \
    "systemd unit controls auditd rather than tailing logs"
assert_grep_fixed 'RemainAfterExit=yes' "$TMPDIR/audit-notify.service"
assert_grep_fixed 'NoNewPrivileges=true' "$TMPDIR/audit-notify.service"
assert_grep_fixed 'ProtectSystem=strict' "$TMPDIR/audit-notify.service" \
    "controller retains its read-only filesystem sandbox"
assert_grep_fixed 'ReadWritePaths=/etc/audit/plugins.d /run/noid-privacy' \
    "$TMPDIR/audit-notify.service" \
    "controller sandbox keeps only its two reviewed writable paths"
assert_grep_fixed 'Requires=auditd.service systemd-tmpfiles-setup.service' \
    "$TMPDIR/audit-notify.service" \
    "controller requires auditd and the shared runtime directory owner"
assert_grep_fixed 'After=auditd.service systemd-tmpfiles-setup.service' \
    "$TMPDIR/audit-notify.service" \
    "controller waits for shared runtime directory creation"
assert_not_grep '^RuntimeDirectory=noid-privacy$' "$TMPDIR/audit-notify.service" \
    "stopping the optional controller cannot delete unrelated runtime state"
sed -e 's#ExecStart=.*#ExecStart=/bin/true#' \
    -e 's#ExecStop=.*#ExecStop=/bin/true#' \
    "$TMPDIR/audit-notify.service" > "$TMPDIR/audit-notify-verify.service"
assert_cmd_success "audit notification controller unit validates" \
    systemd-analyze verify "$TMPDIR/audit-notify-verify.service"
assert_grep_fixed 'python3-audit' "$KS_FILE" \
    "M12 fails closed when the auparse package is absent"

# Installed state and build summary must agree: audit-notify is privacy-safe
# opt-in, not a boot-enabled service.
assert_grep_fixed 'plugin active=no' "$KS_FILE" \
    "build summary preserves the opt-in plugin boundary"
assert_not_grep 'audit-notify.service (v2) starts on boot' "$KS_FILE"
assert_grep_fixed 'noid-toggle-audit-notify on' "$KS_FILE"
assert_cmd_success "audit notification toggle parses" \
    bash -n "$TMPDIR/noid-toggle-audit-notify"
assert_cmd_success "audit notification toggle passes ShellCheck" \
    shellcheck -S warning "$TMPDIR/noid-toggle-audit-notify"
assert_grep_fixed 'disable_and_clear_unit()' "$TMPDIR/noid-toggle-audit-notify" \
    "toggle has one verified disable/failed-state recovery path"
assert_grep_fixed 'systemctl reset-failed "$UNIT"' \
    "$TMPDIR/noid-toggle-audit-notify" \
    "toggle clears a failed activation after disabling it"
assert_grep_fixed 'systemctl is-failed --quiet "$UNIT"' \
    "$TMPDIR/noid-toggle-audit-notify" \
    "toggle rejects a retained failed state"
assert_not_grep 'systemctl disable --now "$UNIT" 2>/dev/null || true' "$KS_FILE" \
    "audit-notify toggle does not hide disable failure"
assert_grep_fixed 'systemctl is-active --quiet "$UNIT"' "$KS_FILE" \
    "audit-notify toggle verifies that the unit stopped"

# A failed `systemctl enable --now` writes the wants symlink before reporting
# the service-start failure. The wrapper must transactionally disable, stop
# and reset that unit instead of leaving the GUI/status surface enabled/failed.
toggle_fixture="$TMPDIR/noid-toggle-audit-notify-fixture"
sed 's#/usr/local/lib/noid-privacy/agent-install-format.sh#/nonexistent/noid-format.sh#g' \
    "$TMPDIR/noid-toggle-audit-notify" > "$toggle_fixture"
chmod 0755 "$toggle_fixture"
# These command doubles are exported and invoked indirectly by the extracted
# toggle wrapper run in the subshell below.
# shellcheck disable=SC2317,SC2329
id() {
    [ "$#" -eq 1 ] && [ "$1" = -u ] || return 2
    printf '0\n'
}
# shellcheck disable=SC2317,SC2329
systemctl() {
    local log=${NOID_SYSTEMCTL_LOG:?}
    local state=${NOID_SYSTEMCTL_STATE:?}
    local enabled active failed
    printf '%s\n' "$*" >> "$log"
    read -r enabled active failed < "$state"
    case "$1" in
        enable)
            printf 'enabled failed failed\n' > "$state"
            return 1
            ;;
        disable)
            printf 'disabled inactive %s\n' "$failed" > "$state"
            ;;
        reset-failed)
            printf '%s %s inactive\n' "$enabled" "$active" > "$state"
            ;;
        is-enabled) [ "$enabled" = enabled ] ;;
        is-active) [ "$active" = active ] ;;
        is-failed) [ "$failed" = failed ] ;;
        *) return 2 ;;
    esac
}
export -f id systemctl
printf 'disabled inactive inactive\n' > "$TMPDIR/toggle-state"
: > "$TMPDIR/toggle-log"
toggle_rc=0
NOID_SYSTEMCTL_LOG="$TMPDIR/toggle-log" \
NOID_SYSTEMCTL_STATE="$TMPDIR/toggle-state" \
PATH="/usr/bin:/bin" \
    bash "$toggle_fixture" on > "$TMPDIR/toggle-out" 2> "$TMPDIR/toggle-err" \
    || toggle_rc=$?
assert_eq 1 "$toggle_rc" \
    "failed audit notification activation stays nonzero after rollback"
assert_eq 'disabled inactive inactive' "$(cat "$TMPDIR/toggle-state")" \
    "failed audit notification activation restores disabled/inactive state"
assert_eq $'enable --now audit-notify.service\ndisable --now audit-notify.service\nis-failed --quiet audit-notify.service\nreset-failed audit-notify.service\nis-enabled --quiet audit-notify.service\nis-active --quiet audit-notify.service\nis-failed --quiet audit-notify.service' \
    "$(cat "$TMPDIR/toggle-log")" \
    "failed activation executes the complete observable rollback sequence"

printf 'enabled active inactive\n' > "$TMPDIR/toggle-state"
: > "$TMPDIR/toggle-log"
toggle_rc=0
NOID_SYSTEMCTL_LOG="$TMPDIR/toggle-log" \
NOID_SYSTEMCTL_STATE="$TMPDIR/toggle-state" \
PATH="/usr/bin:/bin" \
    bash "$toggle_fixture" off > "$TMPDIR/toggle-out" 2> "$TMPDIR/toggle-err" \
    || toggle_rc=$?
assert_eq 0 "$toggle_rc" \
    "normal audit notification disable remains successful"
assert_eq 'disabled inactive inactive' "$(cat "$TMPDIR/toggle-state")" \
    "normal audit notification disable reaches the exact quiet state"
assert_eq $'disable --now audit-notify.service\nis-failed --quiet audit-notify.service\nis-enabled --quiet audit-notify.service\nis-active --quiet audit-notify.service\nis-failed --quiet audit-notify.service' \
    "$(cat "$TMPDIR/toggle-log")" \
    "normal disable does not reset a unit that is not failed"
unset -f id systemctl

# --- Key coverage spot-check: all 33 audit keys present in rules ------------
for key in identity sudoers sshd_config audit_config aide_integrity login_config security_config \
           pam_changes sysctl modprobe kernel_modules bootloader systemd firewall \
           usbguard_config network_config dns_config network_modifications \
           chrony_config system_locale time_change localtime \
           gnome_session_files user_mgmt sudo_usage su_usage priv_exec \
           luks mount_ops cron login_banners session logins; do
    assert_grep_extended "\-k ${key}([[:space:]]|\$)" "$TMPDIR/99-hardening.rules" "key: $key"
done

test_finish

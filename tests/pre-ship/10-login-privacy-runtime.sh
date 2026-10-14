#!/bin/bash
# Candidate-only M10 effective login/sudo privacy gate.
# Run as root in live, fresh-install and reboot passes.

set -euo pipefail

TEST_NAME=10-login-privacy-runtime
PASS_ID="${1:-}"
case "$PASS_ID" in
    live|fresh-install|reboot) ;;
    *)
        echo "Usage: sudo bash $0 {live|fresh-install|reboot}" >&2
        exit 2
        ;;
esac

fail() {
    echo "FAIL  $TEST_NAME [$PASS_ID]: $*" >&2
    exit 1
}

effective_journal_value() {
    local key=$1
    awk -v wanted="$key" '
        /^[[:space:]]*\[[^]]+\][[:space:]]*$/ {
            section = $0
            sub(/^[[:space:]]*\[/, "", section)
            sub(/\][[:space:]]*$/, "", section)
            in_journal = (section == "Journal")
            next
        }
        !in_journal || /^[[:space:]]*[#;]/ {
            next
        }
        {
            line = $0
            equals = index(line, "=")
            if (equals == 0) {
                next
            }
            name = substr(line, 1, equals - 1)
            value = substr(line, equals + 1)
            sub(/^[[:space:]]+/, "", name)
            sub(/[[:space:]]+$/, "", name)
            sub(/^[[:space:]]+/, "", value)
            sub(/[[:space:]]+$/, "", value)
            if (name == wanted) {
                result = value
                found = 1
            }
        }
        END {
            if (!found) {
                exit 1
            }
            print result
        }
    '
}

[[ $EUID -eq 0 ]] || fail "run as root"
grep -q '^ID=noid-privacy-workstation$' /etc/os-release 2>/dev/null || \
    fail "not running inside the NoID Privacy candidate"
for cmd in authselect awk grep runuser stat sudo systemd-analyze visudo; do
    command -v "$cmd" >/dev/null 2>&1 || fail "required command missing: $cmd"
done

expect_one_login_def() {
    local key=$1 value=$2 count
    count="$(grep -Ec "^${key}[[:space:]]+${value}$" /etc/login.defs || true)"
    [[ "$count" == 1 ]] || fail "$key=$value does not occur exactly once"
}

expect_one_login_def LOG_OK_LOGINS no
expect_one_login_def LOG_UNKFAIL_ENAB no
expect_one_login_def FAIL_DELAY 4
expect_one_login_def YESCRYPT_COST_FACTOR 8
expect_one_login_def UMASK 022
expect_one_login_def HOME_MODE 0700
expect_one_login_def CREATE_HOME yes
expect_one_login_def ENCRYPT_METHOD YESCRYPT
expect_one_login_def PASS_MAX_DAYS 99999
! grep -Eq '^(LOG_OK_LOGINS|LOG_UNKFAIL_ENAB)[[:space:]]+yes$' /etc/login.defs || \
    fail "privacy-inverting login logging remains active"

PWHISTORY=/etc/security/pwhistory.conf
OPASSWD=/etc/security/opasswd
[[ -f "$PWHISTORY" && ! -L "$PWHISTORY" ]] || \
    fail "pwhistory policy is missing or symlinked"
[[ "$(stat -c '%U:%G:%a:%h' "$PWHISTORY")" == root:root:644:1 ]] || \
    fail "pwhistory policy metadata differs"
pwhistory_rules="$(
    awk '!/^[[:space:]]*($|#)/ {gsub(/[[:space:]]/, ""); print}' "$PWHISTORY"
)"
[[ "$pwhistory_rules" == $'remember=10\nenforce_for_root' ]] || \
    fail "pwhistory policy differs"
[[ -f "$OPASSWD" && ! -L "$OPASSWD" ]] || \
    fail "password-history store is missing or symlinked"
[[ "$(stat -c '%U:%G:%a:%h' "$OPASSWD")" == root:root:600:1 ]] || \
    fail "password-history store metadata differs"

AUTHSELECT_EXPECTED='local with-silent-lastlog without-nullok with-faillock with-pwhistory with-pamaccess'
authselect check >/dev/null 2>&1 || fail "authselect-owned configuration is invalid"
[[ "$(authselect current -r 2>/dev/null)" == "$AUTHSELECT_EXPECTED" ]] || \
    fail "authselect profile/features differ"
AUTHSELECT_LOG=/var/log/ks-10-authselect.err
[[ ! -e "$AUTHSELECT_LOG" && ! -L "$AUTHSELECT_LOG" ]] || \
    fail "compose-only authselect evidence survived final image scrubbing"

for pam_file in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
    [[ -f "$pam_file" ]] || fail "generated PAM file missing: $pam_file"
    grep -Eq '^password[[:space:]]+.*pam_unix\.so[^#]*[[:space:]]yescrypt([[:space:]]|$)' \
        "$pam_file" || fail "pam_unix yescrypt missing: $pam_file"
    ! grep -Eq '^password[[:space:]]+.*pam_unix\.so[^#]*[[:space:]]rounds=' \
        "$pam_file" || fail "PAM template duplicates login.defs cost: $pam_file"
    ! grep -qF 'pam_oddjob_mkhomedir.so' "$pam_file" || \
        fail "disabled oddjobd-backed home helper remains: $pam_file"
done

SUDOERS=/etc/sudoers.d/99-noid-no-fqdn
SUDO_HARDENING=/etc/sudoers.d/99-noid-hardening
SUDO_PAM=/etc/pam.d/sudo
SUDO_PAM_ENV=/etc/security/pam_env-sudo.conf
SUDO_PAM_ENV_LINE='session    optional     pam_env.so conffile=/etc/security/pam_env-sudo.conf readenv=0 user_readenv=0'
[[ -f "$SUDO_PAM" && ! -L "$SUDO_PAM" ]] || \
    fail "sudo PAM service is missing or symlinked"
[[ "$(stat -c '%U:%G:%a:%h' "$SUDO_PAM")" == root:root:644:1 ]] || \
    fail "sudo PAM service metadata differs"
[[ "$(rpm -qf --qf '%{NAME}' "$SUDO_PAM" 2>/dev/null || true)" == sudo ]] || \
    fail "sudo PAM service is not owned by Fedora's sudo package"
[[ -f "$SUDO_PAM_ENV" && ! -L "$SUDO_PAM_ENV" ]] || \
    fail "sudo PAM environment is missing or symlinked"
[[ "$(stat -c '%U:%G:%a:%h' "$SUDO_PAM_ENV")" == root:root:644:1 ]] || \
    fail "sudo PAM environment metadata differs"
[[ "$(awk '!/^[[:space:]]*($|#)/ {print}' "$SUDO_PAM_ENV")" == \
   'XDG_SESSION_CLASS DEFAULT=none OVERRIDE=none' ]] || \
    fail "sudo PAM environment policy differs"
[[ "$(grep -cFx "$SUDO_PAM_ENV_LINE" "$SUDO_PAM")" == 1 ]] || \
    fail "sudo PAM environment prelude is not exact and unique"
[[ "$(grep -Ec \
    '^session[[:space:]]+include[[:space:]]+system-auth[[:space:]]*$' \
    "$SUDO_PAM")" == 1 ]] || fail "sudo PAM system-auth include is not unique"
awk -v env_line="$SUDO_PAM_ENV_LINE" '
    $0 == env_line { env_nr=NR }
    /^session[[:space:]]+include[[:space:]]+system-auth[[:space:]]*$/ {
        include_nr=NR
    }
    END { exit !(env_nr > 0 && include_nr > env_nr) }
' "$SUDO_PAM" || fail "sudo PAM environment does not precede system-auth"

[[ -f "$SUDOERS" && ! -L "$SUDOERS" ]] || fail "sudo !fqdn file missing or symlinked"
[[ "$(stat -c '%U:%G:%a' "$SUDOERS")" == root:root:440 ]] || \
    fail "sudo !fqdn file metadata differs"
[[ "$(grep -cFx 'Defaults !fqdn' "$SUDOERS")" == 1 ]] || \
    fail "sudo !fqdn directive is not exact and unique"
visudo -cf "$SUDOERS" >/dev/null || fail "sudo !fqdn file fails the native parser"
[[ -f "$SUDO_HARDENING" && ! -L "$SUDO_HARDENING" ]] || \
    fail "sudo hardening file missing or symlinked"
[[ "$(stat -c '%U:%G:%a' "$SUDO_HARDENING")" == root:root:440 ]] || \
    fail "sudo hardening file metadata differs"
visudo -cf "$SUDO_HARDENING" >/dev/null || \
    fail "sudo hardening file fails the native parser"
for dnf_command in /usr/bin/dnf /usr/bin/dnf5; do
    [[ "$(grep -cFx \
        "Defaults!${dnf_command} umask=0022, umask_override" \
        "$SUDO_HARDENING")" == 1 ]] || \
        fail "command-scoped DNF umask is not exact and unique: $dnf_command"
done

audit_user="$(awk -F: '$3 >= 1000 && $3 < 60000 && $7 !~ /(nologin|false)$/ { print $1; exit }' /etc/passwd)"
[[ -n "$audit_user" ]] || fail "no regular candidate user found"
effective_sudo="$(LC_ALL=C sudo -n -U "$audit_user" -ll 2>&1)" || \
    fail "cannot resolve effective sudo policy for $audit_user"
grep -Eq '(^|[,[:space:]])!fqdn([,[:space:]]|$)' <<<"$effective_sudo" || \
    fail "effective sudo policy does not contain !fqdn"

LIVE_SUDOERS=/etc/sudoers.d/liveuser-nopasswd
if [[ $PASS_ID == live ]]; then
    [[ -f $LIVE_SUDOERS && ! -L $LIVE_SUDOERS ]] || \
        fail "Live sudoers file is missing, non-regular or symlinked"
    [[ $(stat -c '%U:%G:%a:%h' "$LIVE_SUDOERS") == root:root:440:1 ]] || \
        fail "Live sudoers metadata differs"
    [[ $(grep -cEv '^[[:space:]]*(#|$)' "$LIVE_SUDOERS") == 2 ]] || \
        fail "Live sudoers active-record count differs"
    [[ $(grep -cFx 'Defaults:liveuser verifypw=any' "$LIVE_SUDOERS") == 1 ]] || \
        fail "Live sudo validation policy is not exact and unique"
    [[ $(grep -cFx 'liveuser ALL=(ALL) NOPASSWD: ALL' "$LIVE_SUDOERS") == 1 ]] || \
        fail "Live command NOPASSWD policy is not exact and unique"
    visudo -cf "$LIVE_SUDOERS" >/dev/null || \
        fail "Live sudoers file fails the native parser"
    runuser -u liveuser -- sudo -K
    runuser -u liveuser -- sudo -n -v </dev/null >/dev/null 2>&1 || \
        fail "uncached Live sudo validation still requires a password"
    [[ "$(runuser -u liveuser -- env XDG_SESSION_CLASS=user \
        sudo -n env 2>/dev/null | grep '^XDG_SESSION_CLASS=' || true)" == \
       XDG_SESSION_CLASS=none ]] || \
        fail "Live sudo did not enforce the non-login session class"
    runuser -u liveuser -- sudo -K
else
    [[ ! -e $LIVE_SUDOERS && ! -L $LIVE_SUDOERS ]] || \
        fail "installed system retained the Live sudoers file"
fi

journal_config="$(systemd-analyze cat-config systemd/journald.conf)" || \
    fail "cannot inspect effective journal retention"
journal_storage="$(effective_journal_value Storage <<<"$journal_config")" || \
    fail "cannot resolve effective journal storage"
journal_size="$(effective_journal_value SystemMaxUse <<<"$journal_config")" || \
    fail "cannot resolve effective journal size ceiling"
journal_retention="$(effective_journal_value MaxRetentionSec <<<"$journal_config")" || \
    fail "cannot resolve effective journal time ceiling"
[[ "$journal_storage" == persistent ]] || \
    fail "persistent audit journal is not configured"
[[ "$journal_size" == 500M ]] || \
    fail "journal size ceiling differs"
[[ "$journal_retention" == 30day ]] || \
    fail "journal time ceiling differs"

echo "PASS  $TEST_NAME [$PASS_ID]: login/privacy defaults, password history and five-feature authselect state are exact; yescrypt cost 8 has one native owner; sudo remains a complete PAM session without redundant logind registration; audit retention is bounded"

# ============================================================================
# Module 10 — PAM + Login Security
# Status: LOCKED 2026-08-11 (v43) — separate compose-only authselect evidence from runtime state.
#
# Covers (no %packages block):
#   1.  /etc/security/faillock.conf — deny=10, unlock 900s, silent +
#       persistent dir=/var/lib/faillock, even_deny_root, root_unlock 60s
#   2.  /etc/security/pwquality.conf — minlen=15, no composition rule,
#       dictionary/context checks and enforce_for_root
#   2b. /etc/security/pwhistory.conf — remember 10 + enforce_for_root
#   3.  /etc/systemd/logind.conf.d/99-noid-hardening.conf —
#       KillUserProcesses + an empty KillExcludeUsers (including root) +
#       RemoveIPC; GNOME owns graphical idle/power controls and systemd retains
#       vendor key/lid/inhibitor defaults
#   4.  /etc/login.defs — successful/unknown-user logging off, FAIL_DELAY=4,
#       native YESCRYPT_COST_FACTOR=8 and explicit local-account defaults
#   5.  /etc/pam.d/su — pam_wheel.so use_uid (wheel-only su)
#   6.  maintained authselect `local` profile + 5 self-contained features
#       (incl. with-pamaccess); PAM 1.7.2 reads the native login.defs cost
#   6a. /etc/security/access.conf — Console Lockdown (wheel + root
#       explicit-allow, deny-all)
#   6c. /etc/security/pam_env-sudo.conf + /etc/pam.d/sudo — supported
#       pam_systemd class=none for privilege delegation inside an existing login
#   7.  /etc/sudoers.d/99-noid-hardening — timestamp_timeout=3 (CIS 4.3.6)
#       + command-scoped DNF/DNF5 system-state umask 022
#   7b. /etc/sudoers.d/99-noid-no-fqdn — defensive Defaults !fqdn
#   8.  Coredump Layers 5+6 plus the libvirt system-QEMU max_core ceiling
#   9.  Native permission policy — tmpfiles + transaction-scoped dnf5 action
#   9b. /etc/profile.d/99-noid-security-umask.sh — umask 027 (interactive)
#   9b.2 locked/atomic deduplicating Bash history compaction + no-write toggle
#        + user-doc
#       Step 9 also sets /etc/cron.* + /etc/sudoers.d to 0700
#   9d. /etc/skel/.gnupg/gpg.conf — 10 hardening directives
#  10.  Verification
#
# Deliberate deviations (do NOT re-litigate):
#   - login.defs UMASK stays 022 — UMASK=027 breaks dnf5 on F41+
#     (rpm-software-management/dnf5#1908; Kicksecure security-misc#185
#     reverted it for the same reason). Interactive shells get umask 027
#     via profile.d instead (Step 9b). Because sudo normally unions its 022
#     default with the invoking user's 027, exact DNF/DNF5 commands receive a
#     command-scoped 022 override so their public system state remains readable.
#   - faillock deny=10, not 5 — repeated silent-lockout cascades on typo
#     clusters. Rate limiting, persistent counters and the 15-character
#     minimum work as layers; no universal hash latency is assumed. silent +
#     persistent stay (STIG anti-enumeration + anti-reboot-bypass V-258095).
#   - NO GDM login-banner — was added as a faillock warning, then REMOVED
#     on user feedback (UI quality). noid-status carries the Authentication
#     section instead. Do not re-propose the banner.
#   - /usr/src NOT in the dir-harden list — out-of-tree kernel-module
#     builds (akmods/DKMS) run as the unprivileged akmods user and must
#     traverse /usr/src to reach the kernel-devel build tree; 0700 silently
#     breaks every such build (akmods still exits 0, so an installer could
#     MOK-enroll + reboot with NO module present). Kernel headers are
#     public — 0700 added no confidentiality. /usr/lib/modules + /boot
#     skipped for the same traversal/regression reasons.
#   - The old copied `custom/noid-hardened` authselect profile stays removed.
#     Linux-PAM 1.7.2 natively reads YESCRYPT_COST_FACTOR from login.defs for
#     pam_unix yescrypt when no `rounds=` option is present. Cost 8 was measured
#     on the F44 reference host before restoration; it applies only when a
#     password hash is created or verified and does not affect application
#     starts. Existing hashes retain their encoded cost until a normal password
#     change. Future increases still require retained supported-hardware,
#     login, password-change and recovery latency measurements.
#   - `with-mkhomedir` stays disabled. Fedora's maintained local-profile
#     REQUIREMENTS says that feature needs oddjobd enabled and active; shipping
#     it with the Silent-Machine-disabled daemon made automatic home creation
#     nonfunctional while retaining a privileged D-Bus helper. This local-only
#     image instead pins login.defs CREATE_HOME=yes + HOME_MODE=0700, and its
#     supported AccountsService/useradd paths create homes natively. M26 keeps
#     oddjob + oddjob-mkhomedir absent. A later external-identity deployment
#     must review and enable its own home-provisioning mechanism explicitly.
#   - bash history = prompt-compacted rolling history, not full-ephemeral.
#     A locked atomic compactor retains at most the newest 100 distinct exact
#     Bash-parsed entries after each completed prompt sync, but there is no
#     byte-size or crash-instant guarantee. When a history file contains Bash
#     timestamp records, Bash treats every physical line beginning `#<digit>`
#     as timestamp metadata; that file-format ambiguity is documented on disk.
#     LUKS is the at-rest boundary; deletion/TRIM is not erasure.
#     Ephemeral mode stops future writes in new shells without pretending to
#     delete pre-existing history, snapshots or backups.
#   - Five privilege paths are intentionally admin-only: chfn, chsh, gpasswd,
#     newgrp and fusermount-glusterfs. The supported replacements are sudo for
#     account/group changes plus a new login, and libvirt/libgfapi rather than
#     an unprivileged Gluster FUSE mount. chage, pam_timestamp_check,
#     userhelper and libgtop_server2 retain Fedora-native SUID because removing
#     it breaks password-expiry queries, consolehelper and GNOME process views.
#   - chmod-0600 for crontab/sshd_config not applied: cronie and
#     openssh-server are not installed — package-purge is the stronger
#     defense. ld.so.preload-disable wrapper not applied: architecturally
#     void (ld.so processes /etc/ld.so.preload before any wrapper enters
#     its namespace).
#   - sudo remains a complete PAM session (keyring revocation, limits,
#     authselect-owned account/session modules and audit evidence all remain).
#     Its service-local, root-owned PAM environment selects systemd's supported
#     `class=none`, because privilege delegation inside an existing login is not
#     a second login. This avoids transient root session scopes/user managers
#     and their setuid real-UID `/run/user/0/bus` warning. Root commands remain
#     tied to the caller's login cgroup; use an explicit maintained systemd
#     workflow when an independently managed service/session is required.
#
# Constraint notes:
#   - The logind drop-in is verified working on F44 systemd 259.5; an early
#     build-chroot failure was transient — do not re-disable it.
#   - pam_access scope: fires for login / gdm-password / sudo / su (root
#     must stay explicit-allow — su target-user check) — NOT for systemd
#     services or gdm-launch-environment. Rollback path: authselect select
#     without with-pamaccess from a live wheel session.
#   - Permission idempotency uses maintained systemd-tmpfiles at compose/boot
#     and a fail-visible libdnf5 post-transaction action scoped to the five
#     owning packages. No periodic custom chmod mutator is shipped.
#   - InhibitorsMax is not overridden. systemd 259's maintained default is
#     8192; the former value 16 accidentally cut capacity by 512x despite no
#     demonstrated exhaustion threat or safe desktop failure mode.
#   - IdleAction and hardware-key/lid actions are not overridden. GNOME owns
#     the user-visible graphical idle, blank, lock and automatic-suspend state;
#     duplicate logind IdleAction=300 made a longer GNOME delay ineffective.
#     Current systemd key/lid values already are the desired vendor defaults.
#
# Cross-reference:
#   - Module 02: Coredump Layers 3+4 (core_pattern, suid_dumpable) — this
#     module adds Layers 5+6; Module 08 carries Layers 1+2.
#   - Module 17: qemu:///session gets the separate per-user compatibility
#     setting because it does not read /etc/libvirt/qemu.conf.
#   - Module 41: Section 7 re-install detection (sibling of the faillock
#     UX bundle).
#   - Module 13: noid-status Authentication section (post-lockout debug
#     path).
#   - Module 25: noid-update-all.sh verifies/reapplies the native tmpfiles
#     permission policy after dnf upgrades.
# ============================================================================

%post --erroronfail --log=/var/log/ks-10-pam-login.log

set -euo pipefail
echo "=============================================================="
echo "[Module 10] PAM + Login Security"
echo "=============================================================="

# ----------------------------------------------------------------------------
# Step 1: /etc/security/faillock.conf (Q1 — Option C)
# ----------------------------------------------------------------------------
#
# Lockout policy: 10 attempts → 15 min lockout, 30 min counter window.
# deny bumped 5→10: laptop-typo tolerance (repeated silent
# faillock-lockout-cascades convinced us 5 is too strict for desktop UX).

echo ""
echo "[Step 1] faillock.conf"

cat > /etc/security/faillock.conf <<'FAIL_EOF'
# NoID Privacy — faillock policy (Module 10)
# 10 attempts → 15 min lockout (CIS L1), 30 min counter window, root 60s STIG.

# Tally before lockout (bumped 5→10 for laptop-typo tolerance). The persistent
# counter and password policy are separate layers; no hash-time claim is used.
deny = 10

# Lockout duration in seconds (900 = 15 minutes, CIS Level 1)
# 300 → 900 — brute-force window 3x reduced. UX impact
# minimal on single-user privacy desktop (10× mistyped is very rare event).
unlock_time = 900

# Counter reset window in seconds (1800 = 30 minutes)
fail_interval = 1800

# Don't announce lockout to the user (minor privacy)
silent

# Log via audit subsystem for forensics (read via ausearch)
audit

# Apply to root too (Fedora default doesn't by default)
even_deny_root

# Root lockout duration (60 = 1 minute, STIG-conform)
# 300 → 60 — STIG-style. Single-user desktop has no legit
# reason for root-typo-flood. STIG-style 60 seconds retains a bounded local
# recovery path without inventing a hardware-independent hash cost.
root_unlock_time = 60

# Persisted faillock-state fix (validated in a VM against pam_faillock
# upstream + STIG/CIS RHEL-9 hardening guides): persist faillock state
# under /var/lib/faillock instead of default /var/run/faillock (tmpfs).
#
# THE actual threat closed: reboot-bypass.
# Default /var/run/faillock is tmpfs → cleared on every reboot → locked user
# just cycles power and is re-allowed unlimited password attempts. Persistent
# /var/lib/faillock survives reboots, so deny=10/unlock=900s applies across
# power cycles as intended. STIG-CIS aligned.
#
# Known scope limit (NOT closed by dir override): pam_faillock by upstream
# design creates per-user state files as mode 0660 owned by the user (so
# screensaver/GDM-PAM can update on lock-screen-failed-attempt). A user
# with active shell session CAN still `cat /dev/null > /var/lib/faillock/
# <self>` to clear their own lockout. This is inherent to pam_faillock's
# legacy IPC-via-file design. The directory is explicitly labeled `faillog_t`
# below, matching Fedora's `/run/faillock` policy so GDM and local console PAM
# domains can both update it; that correct service label intentionally does not
# redefine pam_faillock's user ownership semantics. Reboot-bypass is closed.
dir = /var/lib/faillock
FAIL_EOF

chmod 644 /etc/security/faillock.conf
chown root:root /etc/security/faillock.conf

# Pre-create the persistent tally path before GDM can create it under its own
# xdm_var_lib_t domain. Fedora labels /run/faillock as faillog_t; persist that
# same policy type for /var/lib/faillock and verify both expected and applied
# contexts. Without this, local_login_t cannot search/update GDM-created state.
FAILLOCK_PATH='/var/lib/faillock'
FAILLOCK_FCONTEXT='/var/lib/faillock(/.*)?'
install -d -m 0755 -o root -g root "$FAILLOCK_PATH"
if LC_ALL=C semanage fcontext -l -C | awk -v p="$FAILLOCK_FCONTEXT" \
        '$1 == p { found=1 } END { exit !found }'; then
    semanage fcontext -m -t faillog_t "$FAILLOCK_FCONTEXT"
else
    semanage fcontext -a -t faillog_t "$FAILLOCK_FCONTEXT"
fi
restorecon -RF "$FAILLOCK_PATH"
if ! matchpathcon -V "$FAILLOCK_PATH" >/dev/null 2>&1 \
   || ! stat -c '%C' "$FAILLOCK_PATH" | grep -q ':faillog_t:'; then
    echo "[Module 10] FAIL: persistent faillock path is not faillog_t" >&2
    exit 1
fi
echo "  [OK] /etc/security/faillock.conf"

# ----------------------------------------------------------------------------
# Step 2: /etc/security/pwquality.conf (length + blocklist/context policy)
# ----------------------------------------------------------------------------
#
# Password quality enforcement for local single-factor account passwords.
# This implements the NIST SP 800-63B-4 direction (15-character minimum, no
# composition rule and blocklist/context checks) without claiming complete
# NIST conformance or entropy for user-chosen passwords.

echo ""
echo "[Step 2] pwquality.conf"

cat > /etc/security/pwquality.conf <<'PWQ_EOF'
# NoID Privacy — password quality enforcement (Module 10)
# Local account passwords are a single authentication factor here.
minlen = 15

# No composition requirements. Zero explicitly disables class, repetition and
# sequence constraints and all length credits, so a 15+ character passphrase
# is not forced to add uppercase, digits or punctuation.
minclass = 0
maxrepeat = 0
maxclassrepeat = 0
maxsequence = 0
dcredit = 0
ucredit = 0
lcredit = 0
ocredit = 0

# Dictionary + context checks
dictcheck = 1                 # check against cracklib dictionary
usercheck = 1                 # password cannot contain username
gecoscheck = 1                # password cannot contain GECOS (full name, etc.)

# Enforcement. `enforcing` rejects weak passwords for ordinary users;
# `enforce_for_root` is the separate libpwquality switch required for root.
enforcing = 1
enforce_for_root
retry = 3                     # 3 retries per passwd invocation
difok = 5                     # at least 5 chars different from old password
PWQ_EOF

chmod 644 /etc/security/pwquality.conf
chown root:root /etc/security/pwquality.conf
echo "  [OK] /etc/security/pwquality.conf"

# ----------------------------------------------------------------------------
# Step 2b: /etc/security/pwhistory.conf
# ----------------------------------------------------------------------------
#
# The maintained authselect with-pwhistory feature loads pam_pwhistory with
# use_authtok. Pin its otherwise implicit default and cover root as well, so an
# explicitly changed compromised password cannot immediately be restored.

echo ""
echo "[Step 2b] pwhistory.conf"

cat > /etc/security/pwhistory.conf <<'PWHIST_EOF'
# NoID Privacy — local password reuse policy (Module 10)
remember = 10
enforce_for_root
PWHIST_EOF

chmod 0644 /etc/security/pwhistory.conf
chown root:root /etc/security/pwhistory.conf
if [ ! -f /etc/security/opasswd ] || [ -L /etc/security/opasswd ]; then
    echo "  [FAIL] PAM-owned /etc/security/opasswd is missing or unsafe"
    exit 1
fi
chmod 0600 /etc/security/opasswd
chown root:root /etc/security/opasswd
echo "  [OK] /etc/security/pwhistory.conf"

# ----------------------------------------------------------------------------
# Step 3: /etc/systemd/logind.conf.d/99-noid-hardening.conf (Q4)
# ----------------------------------------------------------------------------
#
# systemd-logind session hardening drop-in. Verified working on F44
# systemd 259.5 (an early build-chroot failure was transient — do not
# re-disable; see header Constraint notes).

echo ""
echo "[Step 3] logind hardening drop-in"

mkdir -p /etc/systemd/logind.conf.d
cat > /etc/systemd/logind.conf.d/99-noid-hardening.conf <<'LOGIND_EOF'
# NoID Privacy — systemd-logind session hardening
# Re-enabled after live-test confirmation

[Login]
# Kill all user processes on logout (anti-persistence; tmux/screen require
# `loginctl enable-linger` or `systemd-run --user --scope` to survive). Reset
# systemd's default root exclusion so the lifecycle policy covers root logins.
KillUserProcesses=yes
KillExcludeUsers=

# Cleanup POSIX/SysV IPC on logout (prevents inter-session leakage)
RemoveIPC=yes
LOGIND_EOF
chmod 644 /etc/systemd/logind.conf.d/99-noid-hardening.conf
chown root:root /etc/systemd/logind.conf.d/99-noid-hardening.conf
echo "  [OK] /etc/systemd/logind.conf.d/99-noid-hardening.conf written (3 directives)"

# ----------------------------------------------------------------------------
# Step 4: /etc/login.defs privacy policy + native yescrypt cost
# ----------------------------------------------------------------------------
#
# Fedora defaults explicitly retained: UMASK=022 (deliberate — see header
# deviations), HOME_MODE=0700, CREATE_HOME=yes, ENCRYPT_METHOD=YESCRYPT and
# PASS_MAX_DAYS=99999 (NIST 800-63B: no forced rotation).
#
# `/bin/login` successful-login logging is redundant with PAM/auditd/logind
# session evidence, so the additional metadata is disabled. Unknown-user
# logging is disabled because login.defs(5) warns that a password mistyped at
# the username prompt can otherwise be recorded as a username. FAIL_DELAY=4
# remains a console guessing throttle. Linux-PAM 1.7.2 reads
# YESCRYPT_COST_FACTOR for pam_unix yescrypt when the PAM template has no
# explicit `rounds=` option. Cost 8 restores the v1.3 work factor through the
# native system setting without copying Fedora's authselect templates.

echo ""
echo "[Step 4] login.defs privacy policy + native yescrypt cost 8"

# Helper: add-or-replace a login.defs directive
set_login_defs() {
    local key="$1"
    local value="$2"
    if grep -qE "^${key}[[:space:]]" /etc/login.defs; then
        sed -i "s|^${key}[[:space:]].*|${key}	${value}|" /etc/login.defs
        echo "  [OK] ${key} = ${value} (replaced)"
    else
        echo "${key}	${value}" >> /etc/login.defs
        echo "  [OK] ${key} = ${value} (appended)"
    fi
}

set_login_defs "LOG_OK_LOGINS"         "no"
set_login_defs "LOG_UNKFAIL_ENAB"      "no"
set_login_defs "FAIL_DELAY"            "4"
set_login_defs "YESCRYPT_COST_FACTOR"  "8"
set_login_defs "UMASK"                 "022"
set_login_defs "HOME_MODE"             "0700"
set_login_defs "CREATE_HOME"           "yes"
set_login_defs "ENCRYPT_METHOD"        "YESCRYPT"
set_login_defs "PASS_MAX_DAYS"         "99999"

# ----------------------------------------------------------------------------
# Step 5: /etc/pam.d/su — uncomment pam_wheel.so use_uid (Q6)
# ----------------------------------------------------------------------------
#
# Restrict su to wheel group members only. Defense-in-depth: even if root
# password is leaked, non-wheel users cannot su to root.
#
# Persistence: /etc/pam.d/su is %config(noreplace) in util-linux-core — rpm
# updates leave our modification intact (new version becomes .rpmnew).

echo ""
echo "[Step 5] /etc/pam.d/su — pam_wheel.so use_uid"

if grep -qE '^#auth[[:space:]]+required[[:space:]]+pam_wheel\.so use_uid' /etc/pam.d/su; then
    sed -i 's|^#auth[[:space:]]*required[[:space:]]*pam_wheel.so use_uid|auth		required	pam_wheel.so use_uid|' /etc/pam.d/su
    echo "  [OK] pam_wheel.so use_uid uncommented"
elif grep -qE '^auth[[:space:]]+required[[:space:]]+pam_wheel\.so use_uid' /etc/pam.d/su; then
    echo "  [INFO] pam_wheel.so use_uid already active (no change)"
else
    echo "  [WARN] expected line not found in /etc/pam.d/su — manual check needed"
fi

# Verify
if grep -qE '^auth[[:space:]]+required[[:space:]]+pam_wheel\.so use_uid' /etc/pam.d/su; then
    echo "  [verify] su now requires wheel group membership"
else
    echo "  [FAIL] pam_wheel.so use_uid not active after sed"
    exit 1
fi

# ----------------------------------------------------------------------------
# Step 6: authselect — maintained Fedora local profile
# ----------------------------------------------------------------------------
#
# Keep Fedora's vendor PAM templates. NoID Privacy enables only supported
# authselect features and does not copy/fork the profile. The yescrypt cost is
# supplied through login.defs, which the installed PAM 1.7.2 consumes natively.

echo ""
echo "[Step 6] authselect local profile + 5 self-contained features"

if [ ! -d /usr/share/authselect/default/local ]; then
    echo "  [FAIL] /usr/share/authselect/default/local missing (authselect-libs package broken?)"
    exit 1
fi

# Select Fedora's local profile with NoID Privacy's five self-contained
# features. with-mkhomedir is deliberately absent: authselect requires an
# enabled oddjobd for it, while local account creation already honors
# CREATE_HOME=yes without that privileged D-Bus service.
# Keep stderr root-only through M99's compose verification. The final mounted-
# root scrub removes this compose-only log before SquashFS publication; runtime
# gates authenticate authselect's generated state directly.
AUTHSEL_LOG="/var/log/ks-10-authselect.err"
install -m 0600 -o root -g root /dev/null "$AUTHSEL_LOG"
if ! authselect select local \
    with-silent-lastlog \
    without-nullok \
    with-faillock \
    with-pwhistory \
    with-pamaccess \
    --force 2>"$AUTHSEL_LOG"; then
    echo "  [FAIL] authselect select failed — see $AUTHSEL_LOG"
    cat "$AUTHSEL_LOG" || true
    exit 1
fi

echo "  [OK] authselect profile:"
authselect current | sed 's/^/    /'

# `select` already generates the PAM/NSS files. Validate its checksum-owned
# result and exact raw profile instead of running a redundant apply-changes and
# treating a failed regeneration as a warning.
AUTHSELECT_EXPECTED='local with-silent-lastlog without-nullok with-faillock with-pwhistory with-pamaccess'
if ! authselect check 2>>"$AUTHSEL_LOG"; then
    echo "  [FAIL] authselect generated configuration is invalid — see $AUTHSEL_LOG"
    cat "$AUTHSEL_LOG" || true
    exit 1
fi
if [ "$(authselect current -r 2>>"$AUTHSEL_LOG")" != "$AUTHSELECT_EXPECTED" ]; then
    echo "  [FAIL] authselect raw profile/features differ — see $AUTHSEL_LOG"
    cat "$AUTHSEL_LOG" || true
    exit 1
fi

# ----------------------------------------------------------------------------
# Step 6a: Deploy pam_access access.conf — Console Lockdown
# ----------------------------------------------------------------------------
# Kicksecure security-misc derivative (wheel-group instead of Debian
# sudo-group): wheel + root explicit-allow, deny-all. Blocks the
# RCE-useradd-login chain that nologin-shells alone don't.
#
# Scope (account-phase via system-auth/password-auth): fires for login,
# gdm-password, sudo (source-user), su (TARGET-user — root must stay
# explicit-allow), and a later-enabled sshd. NOT for systemd services,
# gdm-launch-environment, or cron (no /etc/pam.d/crond here).
# Activated by the `with-pamaccess` feature of the maintained local profile.
#
# Lockout-mitigation: rollback from a live wheel session via authselect
# select without with-pamaccess, or rescue-ISO + LUKS-mount + edit.
echo ""
echo "[Step 6a] Deploy /etc/security/access.conf — pam_access Console Lockdown"

cat > /etc/security/access.conf <<'ACCESS_EOF'
# NoID Privacy Workstation — pam_access Console Lockdown
# ============================================================================
# Activated via the `with-pamaccess` feature of Fedora's maintained
# `local` authselect profile (M10 — Step 6 + Step 6a). Replaces default Fedora
# /etc/security/access.conf (all-comments, no functional rules).
#
# Cross-audit reference: Kicksecure security-misc/etc/security/
# access-security-misc.conf adapted for Fedora wheel-group convention
# (Kicksecure uses sudo-group, Debian convention).
#
# Format: <permission>:<users/groups>:<origins>
#   + = allow
#   - = deny
#   ORIGINS: ALL = anywhere, LOCAL = console/tty only, host/network specs
#
# Order: first-match wins. Default fall-through if no rule matches = allow.
# Therefore -:ALL:ALL at end is REQUIRED to make the rule-set restrictive.
# ============================================================================

# Allow members of group `wheel` from any origin.
# Wheel-user covers all login/sudo/gdm/ssh by NoID Privacy baseline.
+:(wheel):ALL

# Allow root user from any origin (su target-user-check + future cron-as-root
# scenarios). NoID Privacy locks root account by default (passwd -l), so this is a
# safety-net for emergency-recovery + systemd-services-as-root that traverse
# PAM. Restrict to LOCAL later if remote-root never expected.
+:root:ALL

# Deny everyone else.
# Forces explicit wheel-add for any future regular user. Default service-
# users (apache, dbus, gdm, mail, etc.) typically don't go through PAM-
# account phase, so this rule mainly affects interactive login attempts.
-:ALL:ALL
ACCESS_EOF
chmod 0644 /etc/security/access.conf
chown root:root /etc/security/access.conf
restorecon -F /etc/security/access.conf
matchpathcon -V /etc/security/access.conf

echo "  [OK] /etc/security/access.conf deployed (wheel + root explicit-allow, deny-all default)"

# ----------------------------------------------------------------------------
# Step 6b: verify native yescrypt path and login.defs-owned cost
# ----------------------------------------------------------------------------
echo ""
echo "[Step 6b] verify pam_unix.so yescrypt + login.defs cost ownership"

for pam_file in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
    if [ ! -f "$pam_file" ]; then
        echo "  [FAIL] ${pam_file}: not generated by authselect select"
        exit 1
    fi
    if grep -qE '^password[[:space:]]+.*pam_unix\.so[^#]*[[:space:]]yescrypt([[:space:]]|$)' "$pam_file" \
       && ! grep -qE '^password[[:space:]]+.*pam_unix\.so[^#]*[[:space:]]rounds=' "$pam_file" \
       && ! grep -qF 'pam_oddjob_mkhomedir.so' "$pam_file"; then
        echo "  [OK] ${pam_file}: yescrypt and self-contained session policy"
    else
        echo "  [FAIL] ${pam_file}: vendor yescrypt owner or session policy invalid"
        exit 1
    fi
done

# ----------------------------------------------------------------------------
# Step 6c: keep sudo privilege delegation inside the caller's login session
# ----------------------------------------------------------------------------
#
# Fedora owns /etc/pam.d/sudo as %config(noreplace), and its session include
# deliberately retains pam_keyinit, pam_limits and the authselect-owned
# system-auth stack. systemd 258+ supports session class `none`: pam_systemd
# then skips logind registration, a session scope and a root user manager.
#
# The service-local pam_env prelude is required because pam_systemd lives in
# the shared authselect-generated system-auth file; copying that shared session
# stack here would drift on Fedora/authselect updates. Both environment sources
# are explicitly disabled and the root-owned override wins over a caller value.
# The module is optional for availability: a missing/invalid environment file
# falls back to Fedora's normal sudo PAM session rather than locking out sudo.

echo ""
echo "[Step 6c] sudo PAM — systemd class=none inside the caller login"

cat > /etc/security/pam_env-sudo.conf <<'SUDO_PAM_ENV_EOF'
# NoID Privacy — sudo stays inside the caller's existing login session.
XDG_SESSION_CLASS DEFAULT=none OVERRIDE=none
SUDO_PAM_ENV_EOF
chmod 0644 /etc/security/pam_env-sudo.conf
chown root:root /etc/security/pam_env-sudo.conf

SUDO_PAM=/etc/pam.d/sudo
SUDO_PAM_ENV_LINE='session    optional     pam_env.so conffile=/etc/security/pam_env-sudo.conf readenv=0 user_readenv=0'
if [ ! -f "$SUDO_PAM" ] || [ -L "$SUDO_PAM" ]; then
    echo "  [FAIL] $SUDO_PAM is missing, non-regular or symlinked"
    exit 1
fi
if [ "$(rpm -qf --qf '%{NAME}' "$SUDO_PAM" 2>/dev/null || true)" != sudo ]; then
    echo "  [FAIL] $SUDO_PAM is not owned by Fedora's sudo package"
    exit 1
fi

sudo_pam_env_refs=$(grep -cF 'pam_env-sudo.conf' "$SUDO_PAM" || true)
if [ "$sudo_pam_env_refs" -eq 0 ]; then
    sudo_system_auth_sessions=$(
        grep -Ec '^session[[:space:]]+include[[:space:]]+system-auth[[:space:]]*$' \
            "$SUDO_PAM" || true
    )
    if [ "$sudo_system_auth_sessions" -ne 1 ]; then
        echo "  [FAIL] $SUDO_PAM has no unique Fedora system-auth session include"
        exit 1
    fi

    SUDO_PAM_TMP=$(mktemp /var/tmp/noid-sudo-pam.XXXXXX)
    trap 'rm -f -- "$SUDO_PAM_TMP"' EXIT INT TERM
    awk -v env_line="$SUDO_PAM_ENV_LINE" '
        /^session[[:space:]]+include[[:space:]]+system-auth[[:space:]]*$/ {
            print "# sudo is privilege delegation inside an existing login, not a new login."
            print "# systemd 258+ class=none avoids a redundant logind/root-user-manager session."
            print env_line
        }
        { print }
    ' "$SUDO_PAM" > "$SUDO_PAM_TMP"
    install -m 0644 -o root -g root "$SUDO_PAM_TMP" "$SUDO_PAM"
    rm -f -- "$SUDO_PAM_TMP"
    trap - EXIT INT TERM
elif [ "$sudo_pam_env_refs" -ne 1 ] || \
     ! grep -qxF "$SUDO_PAM_ENV_LINE" "$SUDO_PAM"; then
    echo "  [FAIL] $SUDO_PAM contains a duplicate or non-canonical sudo PAM environment"
    exit 1
fi
unset sudo_pam_env_refs sudo_system_auth_sessions SUDO_PAM_TMP

if [ "$(stat -Lc '%U:%G:%a:%h' /etc/security/pam_env-sudo.conf)" != \
     root:root:644:1 ] || \
   [ "$(awk '!/^[[:space:]]*($|#)/ {print}' \
        /etc/security/pam_env-sudo.conf)" != \
     'XDG_SESSION_CLASS DEFAULT=none OVERRIDE=none' ] || \
   [ "$(grep -cFx "$SUDO_PAM_ENV_LINE" "$SUDO_PAM")" -ne 1 ] || \
   [ "$(grep -Ec \
        '^session[[:space:]]+include[[:space:]]+system-auth[[:space:]]*$' \
        "$SUDO_PAM")" -ne 1 ] || \
   ! awk -v env_line="$SUDO_PAM_ENV_LINE" '
        $0 == env_line { env_nr=NR }
        /^session[[:space:]]+include[[:space:]]+system-auth[[:space:]]*$/ {
            include_nr=NR
        }
        END { exit !(env_nr > 0 && include_nr > env_nr) }
     ' "$SUDO_PAM"; then
    echo "  [FAIL] sudo PAM class=none policy, metadata or ordering differs"
    exit 1
fi
echo "  [OK] sudo retains PAM controls without a redundant root logind session"

# ----------------------------------------------------------------------------
# Step 7: sudo hardening drop-in (CIS 4.3.6)
# ----------------------------------------------------------------------------
#
# CIS 4.3.6 sudo authentication timeout — L1 <=15 min, L2/STIG <=5 min;
# NoID Privacy choice: 3 min. Related controls 4.3.1-4.3.5 are satisfied by Fedora
# defaults (sudo installed, use_pty default since 1.9.8, no password-bypass
# directives, reauthentication not disabled).

echo ""
echo "[Step 7] sudo hardening drop-in (timestamp_timeout=3)"

cat > /etc/sudoers.d/99-noid-hardening <<'SUDO_EOF'
# NoID Privacy — sudo hardening (Module 10)
# Reference: CIS Linux Benchmark 4.3.6

# Authentication timeout: sudo-cached credentials expire after 3 minutes.
# Default is 5 min; NoID Privacy reduces to 3 for paranoid-security default.
Defaults timestamp_timeout=3

# Reset environment on sudo invocation (explicit, Fedora default).
Defaults env_reset

# DNF5 system state is package inventory, not secret state. Its RPM-owned TOML
# placeholders are 0644 and unprivileged queries must be able to read them.
# sudo otherwise preserves the restrictive bit from an interactive 0027 umask,
# reproducing upstream dnf5#1908 after any direct `sudo dnf` transaction. Scope
# the maintained 0022 creation contract to both the compatibility symlink and
# the real executable name; do not relax sudo or the interactive shell globally.
Defaults!/usr/bin/dnf umask=0022, umask_override
Defaults!/usr/bin/dnf5 umask=0022, umask_override

# env_keep minimal: only essentials (matches Fedora default, explicit).
Defaults env_keep += "COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS"
Defaults env_keep += "MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE"
Defaults env_keep += "LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES"
Defaults env_keep += "LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE"
Defaults env_keep += "LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY"
SUDO_EOF

chmod 440 /etc/sudoers.d/99-noid-hardening
chown root:root /etc/sudoers.d/99-noid-hardening

# Validate sudoers syntax (CRITICAL — broken sudoers locks out admin)
if ! visudo -cf /etc/sudoers.d/99-noid-hardening >/dev/null 2>&1; then
    echo "  [FAIL] /etc/sudoers.d/99-noid-hardening invalid syntax — removing"
    rm -f /etc/sudoers.d/99-noid-hardening
    exit 1
fi
echo "  [OK] /etc/sudoers.d/99-noid-hardening (440, validated via visudo -cf)"

# ----------------------------------------------------------------------------
# Step 7b: sudoers Defaults !fqdn
# ----------------------------------------------------------------------------
# sudoers' maintained `fqdn` flag is off by default; sudo does not inherently
# canonicalize the host through DNS on every invocation. Keep explicit `!fqdn`
# as defensive state so a future/global include cannot silently enable FQDN
# host matching and its resolver dependency. Separate file keeps attribution
# and rollback clear. Compatibility: FQDN-only Host_Alias entries would not
# match, and NoID Privacy ships none.

echo ""
echo "[Step 7b] sudoers Defaults !fqdn"

cat > /etc/sudoers.d/99-noid-no-fqdn <<'NOFQDN_EOF'
# NoID Privacy — keep sudo FQDN host canonicalization disabled (Module 10).
# `fqdn` is opt-in in maintained sudoers; this explicit negative prevents a
# later/global include from enabling resolver-dependent FQDN Host_Alias rules.
Defaults !fqdn
NOFQDN_EOF

chmod 440 /etc/sudoers.d/99-noid-no-fqdn
chown root:root /etc/sudoers.d/99-noid-no-fqdn

if ! visudo -cf /etc/sudoers.d/99-noid-no-fqdn >/dev/null 2>&1; then
    echo "  [FAIL] /etc/sudoers.d/99-noid-no-fqdn invalid syntax — removing"
    rm -f /etc/sudoers.d/99-noid-no-fqdn
    exit 1
fi
echo "  [OK] /etc/sudoers.d/99-noid-no-fqdn (440, validated via visudo -cf)"

# ----------------------------------------------------------------------------
# Step 8: Core dump defense-in-depth (Layers 5 + 6 + system QEMU ceiling)
# ----------------------------------------------------------------------------
# 6-Layer coredump block architecture:
#   Layer 1 systemd-coredump.socket masked            — M08
#   Layer 2 /etc/systemd/coredump.conf.d Storage=none — M08
#   Layer 3 kernel.core_pattern=|/bin/false           — M02 sysctl
#   Layer 4 fs.suid_dumpable=0                        — M02 sysctl
#   Layer 5 limits.conf * hard core 0                 — THIS STEP (user shells)
#   Layer 6 system.conf DefaultLimitCORE=0            — THIS STEP (services)
#   QEMU system driver /etc/libvirt/qemu.conf max_core=0 — THIS STEP
# limits.conf only covers user-shell processes; systemd services IGNORE it
# and use DefaultLimitCORE (https://systemd.io/COREDUMP/) — both needed.
# Layer 6 is an inherited default, not an absolute capability boundary: a
# privileged service with CAP_SYS_RESOURCE may raise its own hard limit.
# libvirt's system QEMU driver has that capability and otherwise defaults
# max_core to unlimited on Linux, so its native driver setting closes that
# specific bypass. qemu:///session reads a different XDG file; M17 supplies
# max_core=0 there only so an unprivileged driver does not attempt a forbidden
# raise and fail VM startup.

echo ""
echo "[Step 8] Core dump Layer 5 + 6 + libvirt system-QEMU ceiling"

# ----- Layer 5: limits.conf (user shell processes) -----
# Append to limits.conf if not already present (idempotent).
# Fedora default has commented-out examples at bottom; we append hardening block.
if ! grep -qE "^\*[[:space:]]+hard[[:space:]]+core[[:space:]]+0" /etc/security/limits.conf; then
    cat >> /etc/security/limits.conf <<'LIMITS_EOF'

# NoID Privacy — core dump disable (Module 10 Layer 5)
# Covers all user-shell-launched processes. Systemd services go via
# /etc/systemd/system.conf DefaultLimitCORE=0 (Layer 6).
*       soft    core    0
*       hard    core    0
LIMITS_EOF
    echo "  [OK] /etc/security/limits.conf: * hard core 0 appended"
else
    echo "  [OK] /etc/security/limits.conf: * hard core 0 already present"
fi

# ----- Layer 6: systemd system.conf drop-in (systemd-managed services) -----
mkdir -p /etc/systemd/system.conf.d
cat > /etc/systemd/system.conf.d/50-coredump.conf <<'SYSTEMD_EOF'
# NoID Privacy — disable core dumps for all systemd-managed services
# Module 10 Layer 6 — complements /etc/security/limits.conf Layer 5.
#
# limits.conf only affects user-shell-launched processes. systemd services
# IGNORE limits.conf and use this system.conf DefaultLimitCORE value instead.
# Reference: https://systemd.io/COREDUMP/
#
# DefaultLimitCORE=0 supplies a soft+hard limit of zero to units that do not
# declare LimitCORE=. A unit-specific LimitCORE= overrides the manager default
# either way; Layers 1-4 are the independent dump-production/storage boundary.
# Keeping the hard default at zero prevents ordinary service processes and
# user-manager units from raising the inherited limit. A privileged process
# with CAP_SYS_RESOURCE can exceed it; the libvirt system-QEMU ceiling below
# closes the confirmed QEMU case without weakening Layers 1-6.

[Manager]
DefaultLimitCORE=0
SYSTEMD_EOF

chmod 644 /etc/systemd/system.conf.d/50-coredump.conf
chown root:root /etc/systemd/system.conf.d/50-coredump.conf
echo "  [OK] /etc/systemd/system.conf.d/50-coredump.conf: DefaultLimitCORE=0"

# ----- Native libvirt system-QEMU ceiling -----
# libvirt has no qemu.conf.d interface. Its system driver reads exactly
# /etc/libvirt/qemu.conf, while qemu:///session reads the user's XDG path.
# Fedora marks this file %config(noreplace), so package updates retain the
# edited file and may publish qemu.conf.rpmnew for explicit review. The general
# Update workflow already reports every .rpmnew/.rpmsave/.rpmorig sibling.
QEMU_SYSTEM_CONF=/etc/libvirt/qemu.conf
if [ ! -f "$QEMU_SYSTEM_CONF" ] || [ -L "$QEMU_SYSTEM_CONF" ] \
   || [ "$(stat -Lc '%U:%G:%h' "$QEMU_SYSTEM_CONF" 2>/dev/null || true)" != \
        root:root:1 ] \
   || [ "$(rpm -qf --qf '%{NAME}' "$QEMU_SYSTEM_CONF" 2>/dev/null || true)" != \
        libvirt-daemon-driver-qemu ] \
   || [ "$(stat -Lc '%s' "$QEMU_SYSTEM_CONF" 2>/dev/null || echo 1048577)" -gt \
        1048576 ]; then
    echo "  [FAIL] libvirt system qemu.conf is absent, unsafe or not Fedora-owned"
    exit 1
fi

qemu_max_active=$(grep -Ec \
    '^[[:space:]]*max_core[[:space:]]*=' "$QEMU_SYSTEM_CONF" || true)
qemu_dump_active=$(grep -Ec \
    '^[[:space:]]*dump_guest_core[[:space:]]*=' "$QEMU_SYSTEM_CONF" || true)
qemu_max_anchor=$(grep -Ec \
    '^[[:space:]]*#[[:space:]]*max_core[[:space:]]*=' "$QEMU_SYSTEM_CONF" || true)
qemu_dump_anchor=$(grep -Ec \
    '^[[:space:]]*#[[:space:]]*dump_guest_core[[:space:]]*=' \
    "$QEMU_SYSTEM_CONF" || true)
if [ "$qemu_max_active" -gt 1 ] || [ "$qemu_dump_active" -gt 1 ] \
   || { [ "$qemu_max_active" -eq 0 ] && [ "$qemu_max_anchor" -ne 1 ]; } \
   || { [ "$qemu_dump_active" -eq 0 ] && [ "$qemu_dump_anchor" -ne 1 ]; }; then
    echo "  [FAIL] libvirt system qemu.conf core settings are ambiguous"
    exit 1
fi

if [ "$qemu_max_active" -ne 1 ] || [ "$qemu_dump_active" -ne 1 ] \
   || ! grep -Eq \
        '^[[:space:]]*max_core[[:space:]]*=[[:space:]]*0[[:space:]]*(#.*)?$' \
        "$QEMU_SYSTEM_CONF" \
   || ! grep -Eq \
        '^[[:space:]]*dump_guest_core[[:space:]]*=[[:space:]]*0[[:space:]]*(#.*)?$' \
        "$QEMU_SYSTEM_CONF"; then
    QEMU_SYSTEM_TMP=$(mktemp --tmpdir=/etc/libvirt .noid-qemu.conf.XXXXXX)
    trap 'rm -f -- "${QEMU_SYSTEM_TMP:-}"' EXIT INT TERM
    awk -v max_active="$qemu_max_active" -v dump_active="$qemu_dump_active" '
        /^[[:space:]]*max_core[[:space:]]*=/ {
            print "# NoID Privacy: the privileged system QEMU driver can otherwise"
            print "# raise Layer 6 through CAP_SYS_RESOURCE; this is its native ceiling."
            print "max_core = 0"
            next
        }
        max_active == 0 && /^[[:space:]]*#[[:space:]]*max_core[[:space:]]*=/ {
            print "# NoID Privacy: the privileged system QEMU driver can otherwise"
            print "# raise Layer 6 through CAP_SYS_RESOURCE; this is its native ceiling."
            print "max_core = 0"
            next
        }
        /^[[:space:]]*dump_guest_core[[:space:]]*=/ {
            print "# Documentation only: guest XML may override RAM inclusion;"
            print "# max_core=0 above remains the file-size boundary."
            print "dump_guest_core = 0"
            next
        }
        dump_active == 0 && /^[[:space:]]*#[[:space:]]*dump_guest_core[[:space:]]*=/ {
            print "# Documentation only: guest XML may override RAM inclusion;"
            print "# max_core=0 above remains the file-size boundary."
            print "dump_guest_core = 0"
            next
        }
        { print }
    ' "$QEMU_SYSTEM_CONF" > "$QEMU_SYSTEM_TMP"
    chmod 0644 "$QEMU_SYSTEM_TMP"
    chown root:root "$QEMU_SYSTEM_TMP"
    sync -- "$QEMU_SYSTEM_TMP"
    mv -fT -- "$QEMU_SYSTEM_TMP" "$QEMU_SYSTEM_CONF"
    QEMU_SYSTEM_TMP=
    sync -- /etc/libvirt
    trap - EXIT INT TERM
fi

if [ "$(stat -Lc '%U:%G:%a:%h' "$QEMU_SYSTEM_CONF")" != root:root:644:1 ] \
   || [ "$(grep -Ec '^[[:space:]]*max_core[[:space:]]*=' \
        "$QEMU_SYSTEM_CONF")" -ne 1 ] \
   || [ "$(grep -Ec '^[[:space:]]*dump_guest_core[[:space:]]*=' \
        "$QEMU_SYSTEM_CONF")" -ne 1 ] \
   || ! grep -Eq \
        '^[[:space:]]*max_core[[:space:]]*=[[:space:]]*0[[:space:]]*(#.*)?$' \
        "$QEMU_SYSTEM_CONF" \
   || ! grep -Eq \
        '^[[:space:]]*dump_guest_core[[:space:]]*=[[:space:]]*0[[:space:]]*(#.*)?$' \
        "$QEMU_SYSTEM_CONF"; then
    echo "  [FAIL] libvirt system qemu.conf postcondition differs"
    exit 1
fi
echo "  [OK] /etc/libvirt/qemu.conf: max_core=0 (system-QEMU boundary)"
echo "  [OK] /etc/libvirt/qemu.conf: dump_guest_core=0 (documented default)"
unset QEMU_SYSTEM_CONF QEMU_SYSTEM_TMP qemu_max_active qemu_dump_active \
    qemu_max_anchor qemu_dump_anchor

mkdir -p /usr/share/doc/noid-privacy
cat > /usr/share/doc/noid-privacy/10-libvirt-core-dumps.md <<'LIBVIRT_CORE_DOC_EOF'
# Libvirt/QEMU core-dump boundary

NoID Privacy keeps general core-dump Layers 1–6 disabled. For libvirt it also
sets two native driver values:

- `/etc/libvirt/qemu.conf` is read by `qemu:///system`. `max_core = 0` is the
  security boundary that prevents privileged `virtqemud` from raising the
  inherited hard limit through `CAP_SYS_RESOURCE`.
- `~/.config/libvirt/qemu.conf` is read by `qemu:///session`. The first-login
  transaction creates or safely completes this user-owned file so libvirt does
  not attempt a forbidden raise of the already-effective hard user limit and
  fail VM startup. This is a compatibility repair, not an additional security
  layer.
- `dump_guest_core = 0` documents the intended Linux default. A guest XML
  `dumpCore` attribute can override RAM inclusion, so this setting is not the
  boundary; `max_core = 0` is.

Neither driver mode falls back to the other configuration file. libvirt has no
supported `qemu.conf.d` interface, so the system file is an intentional edit of
Fedora's `%config(noreplace)` file. An RPM update preserves it and may create
`/etc/libvirt/qemu.conf.rpmnew`; `noid-update-all.sh` reports such configuration
siblings for review instead of merging them silently.

## Check

```bash
sudo grep -E '^[[:space:]]*(max_core|dump_guest_core)[[:space:]]*=' /etc/libvirt/qemu.conf
grep -E '^[[:space:]]*(max_core|dump_guest_core)[[:space:]]*=' "${XDG_CONFIG_HOME:-$HOME/.config}/libvirt/qemu.conf"
```

Each file must contain one active `max_core = 0` and one active
`dump_guest_core = 0` assignment.

## Diagnostic exception and undo

Removing or raising `max_core` weakens only the QEMU-specific boundary; the
general core handler, storage, kernel and inherited-limit layers still block a
usable dump. Conversely, raising the session value while the hard user limit
remains zero reproduces the VM-start failure this configuration fixes. A real
QEMU-core collection therefore requires a coordinated, temporary review of
all affected layers and of whether guest RAM is included. Such a core can contain
sensitive QEMU process and device state and, when RAM inclusion is enabled,
guest memory.

Before a diagnostic change, copy the affected file to root- or user-private
storage. Restore the saved file afterward and cold-start the corresponding
`virtqemud`; existing VMs keep the values loaded by their original daemon.
LIBVIRT_CORE_DOC_EOF
chmod 0644 /usr/share/doc/noid-privacy/10-libvirt-core-dumps.md
chown root:root /usr/share/doc/noid-privacy/10-libvirt-core-dumps.md

# ----------------------------------------------------------------------------
# Step 9: Native permission policy (systemd-tmpfiles + dnf5 actions)
# ----------------------------------------------------------------------------
# Five unnecessary privilege paths are intentionally admin-only on NoID Privacy:
# chfn/chsh account metadata and shell changes use sudo; group membership uses
# sudo usermod/gpasswd plus a new login instead of group passwords/newgrp; the
# image does not support unprivileged Gluster FUSE mounts. Fedora-native SUID is
# RETAINED for chage (self expiry query), pam_timestamp_check, userhelper
# (consolehelper VPNC/Mock paths) and libgtop_server2 (GNOME process view).
#
# systemd-tmpfiles is the maintained declarative owner. The normal boot
# tmpfiles pass applies it; the libdnf5 action closes the update window only
# when a package owning one of these paths is installed/upgraded. There is no
# periodic custom chmod service and no blind mutation of the four retained
# vendor privilege paths. The resulting five RPM mode differences are
# deliberate AIDE/RPM evidence and are never auto-baselined.

echo ""
echo "[Step 9] Native permission policy (tmpfiles + transaction-scoped reapply)"

mkdir -p /etc/tmpfiles.d /etc/dnf/libdnf5-plugins/actions.d
cat > /etc/tmpfiles.d/90-noid-permission-policy.conf <<'PERMISSION_POLICY_EOF'
# NoID Privacy — reviewed local permission policy (Module 10)
# type path mode user group age argument
# Intentionally remove SUID from five non-default workflows.
z /usr/bin/chfn                 0711 root root - -
z /usr/bin/chsh                 0711 root root - -
z /usr/bin/gpasswd              0755 root root - -
z /usr/bin/newgrp               0755 root root - -
z /usr/bin/fusermount-glusterfs 0755 root root - -
# Hide root-only scheduler/sudo policy metadata; do not create absent paths.
z /etc/cron.hourly              0700 root root - -
z /etc/cron.daily               0700 root root - -
z /etc/cron.weekly              0700 root root - -
z /etc/cron.monthly             0700 root root - -
z /etc/cron.d                   0700 root root - -
z /etc/sudoers.d                0700 root root - -
PERMISSION_POLICY_EOF
chmod 0644 /etc/tmpfiles.d/90-noid-permission-policy.conf
chown root:root /etc/tmpfiles.d/90-noid-permission-policy.conf

cat > /etc/dnf/libdnf5-plugins/actions.d/noid-permission-policy.actions <<'PERMISSION_ACTION_EOF'
# Reapply only after transactions that may restore an owned mode/directory.
post_transaction:util-linux:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/bin/systemd-tmpfiles\ --create\ /etc/tmpfiles.d/90-noid-permission-policy.conf\ >/dev/null
post_transaction:shadow-utils:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/bin/systemd-tmpfiles\ --create\ /etc/tmpfiles.d/90-noid-permission-policy.conf\ >/dev/null
post_transaction:glusterfs-fuse:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/bin/systemd-tmpfiles\ --create\ /etc/tmpfiles.d/90-noid-permission-policy.conf\ >/dev/null
post_transaction:cronie:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/bin/systemd-tmpfiles\ --create\ /etc/tmpfiles.d/90-noid-permission-policy.conf\ >/dev/null
post_transaction:sudo:in:enabled=host-only raise_error=1:/usr/bin/sh -c /usr/bin/systemd-tmpfiles\ --create\ /etc/tmpfiles.d/90-noid-permission-policy.conf\ >/dev/null
PERMISSION_ACTION_EOF
chmod 0644 /etc/dnf/libdnf5-plugins/actions.d/noid-permission-policy.actions
chown root:root /etc/dnf/libdnf5-plugins/actions.d/noid-permission-policy.actions
restorecon -F /etc/tmpfiles.d/90-noid-permission-policy.conf \
    /etc/dnf/libdnf5-plugins/actions.d/noid-permission-policy.actions
matchpathcon -V /etc/tmpfiles.d/90-noid-permission-policy.conf \
    /etc/dnf/libdnf5-plugins/actions.d/noid-permission-policy.actions

if ! systemd-tmpfiles --create /etc/tmpfiles.d/90-noid-permission-policy.conf; then
    echo "  [FAIL] native permission policy could not be applied"
    exit 1
fi
echo "  [OK] native permission policy applied; no periodic mutator installed"

# ----------------------------------------------------------------------------
# Step 9b: profile.d umask 027 — interactive-shell hardening
# ----------------------------------------------------------------------------
# Complements the KEPT login.defs UMASK=022 (header deviations: dnf5#1908).
# Fedora sources profile.d from interactive and noninteractive login shells and
# from /etc/bashrc. The deployed file therefore checks the shell's `i` option
# before changing umask. Result: interactive terminal files get 640/750 while
# `bash -lc`, remote commands, scripts and system jobs retain their caller/
# service umask. Services needing stricter modes must use native `UMask=`.

echo ""
echo "[Step 9b] profile.d umask 027 — interactive shell hardening"

cat > /etc/profile.d/99-noid-security-umask.sh <<'UMASK_EOF'
# NoID Privacy — stricter umask for interactive shells (Module 10 Step 9b)
#
# Fedora sources this file through /etc/profile and /etc/bashrc. Apply the
# policy only when the current shell is actually interactive (`i` in `$-`).
# Files created via `touch`, `cp`, `vim`, `echo > file`, redirects, etc.
# from the user's terminal will get mode 640 (dir 750) instead of 644/755.
#
# NOT applied to noninteractive login shells, remote commands or system
# processes (dnf, systemd, cron); their caller/service umask remains intact.
#
# To verify: open a terminal, run `umask` → should print 0027
case $- in
    *i*) umask 027 ;;
esac
UMASK_EOF
chmod 644 /etc/profile.d/99-noid-security-umask.sh
chown root:root /etc/profile.d/99-noid-security-umask.sh
echo "  [OK] /etc/profile.d/99-noid-security-umask.sh written (umask 027 interactive)"

# ----------------------------------------------------------------------------
# Step 9b.2: bash CLI history — prompt-compacted rolling default
# ----------------------------------------------------------------------------
# A per-user lock serializes append+atomic compaction across NoID Privacy shells. The
# completed prompt state contains at most the newest 100 distinct exact
# Bash-parsed history entries; an abrupt kill between append and compaction can
# temporarily exceed that until the next successful sync. There is deliberately
# no byte-size claim.
# Ephemeral mode remains available via the global root-owned toggle.
# Why /etc/profile.d (not /etc/skel/.bashrc): skel only reaches NEW users;
# profile.d applies to ALL existing + future users uniformly, and the
# toggle takes effect at the next shell session.

echo ""
echo "[Step 9b.2] bash history — locked prompt compaction (100 distinct Bash-parsed entries)"

mkdir -p /usr/local/libexec
cat > /usr/local/libexec/noid-bash-history-compact <<'HIST_COMPACT_EOF'
#!/bin/bash
# Rewrite one user-owned Bash history file atomically to the newest N distinct
# exact logical entries. The caller holds the per-user lock across `history -a`
# and this tool.
set -euo pipefail

[[ $# -eq 2 ]] || { echo "usage: $0 HISTORY_FILE LIMIT" >&2; exit 2; }
history_file=$1
limit=$2
[[ "$history_file" == /* && "$history_file" != *$'\n'* ]] || exit 2
[[ "$limit" =~ ^[1-9][0-9]*$ ]] || exit 2

# This helper is launched by an interactive shell that exports HISTFILE and
# its native physical-line limit. A noninteractive Bash script can apply that
# inherited limit again at exit even though this helper already published the
# Bash-event result. Clear the outer interpreter's history environment;
# the dedicated parser below receives only its explicit unlimited-read values.
unset HISTFILE HISTSIZE HISTFILESIZE HISTTIMEFORMAT

[[ -e "$history_file" ]] || exit 0
[[ -f "$history_file" && ! -L "$history_file" && -O "$history_file" ]] || exit 1
history_dir=${history_file%/*}
history_base=${history_file##*/}

# SIGKILL cannot run traps. The caller's per-user lock guarantees that exact
# same-history helpers do not overlap, so the next attempt can remove only
# regular, non-symlink, caller-owned leftovers from a killed prior attempt.
shopt -s nullglob
for stale_tmp in \
    "$history_dir/.${history_base}.noid-compact."* \
    "$history_dir/.${history_base}.noid-parse."*; do
    if [[ -f "$stale_tmp" && ! -L "$stale_tmp" && -O "$stale_tmp" ]]; then
        rm -f -- "$stale_tmp"
    fi
done
unset stale_tmp

tmp=$(mktemp --tmpdir="$history_dir" ".${history_base}.noid-compact.XXXXXX")
parse_tmp=$(mktemp --tmpdir="$history_dir" ".${history_base}.noid-parse.XXXXXX")
cleanup() { rm -f -- "$tmp" "$parse_tmp"; }
trap cleanup EXIT INT TERM
chmod 0600 "$tmp" "$parse_tmp"

# A Bash file may be mixed after a timestamp-free compaction followed by a
# user-enabled timestamp append. Bash recognizes later `#<epoch>` records as
# metadata only when timestamp framing starts at the first line. Add a
# synthetic non-published epoch marker only when an exact numeric timestamp
# record exists anywhere in the file. This preserves commands such as
# `#5 my note` in timestamp-free files. Once timestamp framing exists, Bash's
# format makes every physical line beginning `#<digit>` ambiguous and Bash
# consumes it as metadata; the shipped documentation discloses that boundary.
timestamp_framing=0
while IFS= read -r history_line || [[ -n "$history_line" ]]; do
    if [[ "$history_line" =~ ^#[0-9]+$ ]]; then
        timestamp_framing=1
        break
    fi
done < "$history_file"
if (( timestamp_framing == 1 )); then
    printf '#0\n' > "$parse_tmp"
fi
cat -- "$history_file" >> "$parse_tmp"
unset history_line timestamp_framing

# Read without Bash's physical-line cap and obtain Bash's own last event number.
# Walk backwards until the newest N distinct exact events are selected, then
# rebuild them in chronological order. Deduplication happens before the cap so
# prompt-time `history -a` cannot make repeated commands consume persistent
# slots. The scan stores at most N values and normally stops after N events.
# History recording stays disabled in the parser, so its own commands cannot
# consume retained user entries or appear in the published file.
HISTFILE="$parse_tmp" HISTSIZE=-1 HISTFILESIZE=-1 \
    /usr/bin/bash --noprofile --norc -c '
        set -euo pipefail
        builtin history -c
        builtin history -r "$HISTFILE"
        history_line=$(HISTTIMEFORMAT= builtin history 1)
        if [[ -n "$history_line" ]]; then
            read -r history_count _ <<< "$history_line"
            history_count=${history_count%\*}
            [[ "$history_count" =~ ^[0-9]+$ ]] || exit 2
        else
            history_count=0
        fi

        declare -a retained_reversed=()
        history_value=
        for ((history_offset=1;
              history_offset <= history_count && ${#retained_reversed[@]} < $2;
              history_offset++)); do
            history_value=$(
                builtin fc -ln -- "-${history_offset}" "-${history_offset}" || exit
                printf "\036"
            )
            [[ "$history_value" == *$'\''\036'\'' ]] || exit 2
            history_value=${history_value%$'\''\036'\''}
            # `fc -ln` emits one fixed tab+space display prefix and one final
            # newline. Validate/remove only that framing; the complete event,
            # including option-looking first bytes, remains opaque data.
            [[ "${history_value:0:2}" == $'\''\t '\'' ]] || exit 2
            history_value=${history_value:2}
            [[ "$history_value" == *$'\''\n'\'' ]] || exit 2
            history_value=${history_value%$'\''\n'\''}

            duplicate=0
            for retained_value in "${retained_reversed[@]}"; do
                if [[ "$history_value" == "$retained_value" ]]; then
                    duplicate=1
                    break
                fi
            done
            (( duplicate == 1 )) || retained_reversed+=("$history_value")
        done

        builtin history -c
        HISTCONTROL=
        HISTIGNORE=
        for ((history_index=${#retained_reversed[@]} - 1;
              history_index >= 0;
              history_index--)); do
            builtin history -s -- "${retained_reversed[history_index]}"
        done
        builtin history -w "$1"
    ' _ "$tmp" "$limit"

chmod 0600 "$tmp"
mv -fT -- "$tmp" "$history_file"
rm -f -- "$parse_tmp"
trap - EXIT INT TERM
HIST_COMPACT_EOF
chmod 0755 /usr/local/libexec/noid-bash-history-compact
chown root:root /usr/local/libexec/noid-bash-history-compact

cat > /etc/profile.d/98-noid-bash-history.sh <<'HIST_EOF'
# NoID Privacy — prompt-compacted Bash history (Module 10 Step 9b.2)
#
# After each successfully completed prompt hook, one per-user flock covers
# `history -a` plus an atomic rewrite to the newest 100 distinct exact
# Bash-parsed entries. Older exact duplicates are discarded before the cap.
# A SIGKILL/power loss between append and rewrite can leave a temporary excess
# until the next prompt. Long/multiline commands mean there is NO byte cap.
# LUKS is the at-rest boundary; unlink/TRIM is not secure erasure.
#
# `ignorespace`, HISTIGNORE and duplicate filtering are minimization/convenience
# controls, not secret-loss prevention: matching is user-dependent and
# applications may log independently. The file and lock are mode 0600.
#
# Override: file 99-noid-bash-history-ephemeral.sh (created by `sudo
# noid-toggle-bash-history ephemeral`) reverts to in-memory-only mode.
# That file is read AFTER this one (alphabetical) so it overrides.
#
# Manual single-session ephemeral: `unset HISTFILE; HISTSIZE=0`
# Manual single-session persistent: `HISTFILE=~/.bash_history; HISTSIZE=100`
[ -n "${BASH_VERSION-}" ] || return 0

case "$-" in
    *i*)
        # Interactive shell only
        export HISTFILE="${HISTFILE:-$HOME/.bash_history}"
        export HISTSIZE=100
        export HISTFILESIZE=100
        export HISTCONTROL=ignorespace:erasedups
        export HISTIGNORE='ls:cd:pwd:exit:clear:reset:history*'
        shopt -s histappend

        _noid_history_sync() {
            local history_file=${HISTFILE:-}
            local lock_file lock_fd
            [[ -n "$history_file" && "$history_file" == /* && ! -L "$history_file" ]] || return 0
            lock_file="${history_file}.noid.lock"
            (umask 077; : >> "$lock_file") || return 0
            chmod 0600 "$lock_file" 2>/dev/null || true
            exec {lock_fd}>>"$lock_file" || return 0
            if flock -x "$lock_fd"; then
                builtin history -a
                if ! /usr/local/libexec/noid-bash-history-compact "$history_file" 100; then
                    if [[ -z "${_NOID_HISTORY_WARNED:-}" ]]; then
                        printf '%s\n' 'NoID Privacy: bash history compaction failed; persistent history may exceed its prompt-time limit.' >&2
                        _NOID_HISTORY_WARNED=1
                    fi
                fi
                flock -u "$lock_fd" || true
            fi
            exec {lock_fd}>&-
            return 0
        }

        # Preserve Bash's array form and every existing hook. Re-sourcing this
        # file is idempotent. The string fallback appends without overwriting.
        _noid_history_hook_present=0
        if [[ "$(declare -p PROMPT_COMMAND 2>/dev/null)" == "declare -a"* ]]; then
            for _noid_history_hook in "${PROMPT_COMMAND[@]}"; do
                [[ "$_noid_history_hook" == _noid_history_sync ]] && \
                    _noid_history_hook_present=1
            done
            [[ $_noid_history_hook_present -eq 1 ]] || \
                PROMPT_COMMAND+=(_noid_history_sync)
        else
            _noid_history_prompt_string=${PROMPT_COMMAND[*]-}
            _noid_history_string_re=';[[:space:]]*_noid_history_sync[[:space:]]*;'
            if [[ ! ";${_noid_history_prompt_string};" =~ $_noid_history_string_re ]]; then
                printf -v PROMPT_COMMAND '%s' \
                    "${_noid_history_prompt_string:+${_noid_history_prompt_string}; }_noid_history_sync"
            fi
        fi
        unset _noid_history_hook _noid_history_hook_present \
            _noid_history_prompt_string _noid_history_string_re
        ;;
esac
HIST_EOF
chmod 644 /etc/profile.d/98-noid-bash-history.sh
chown root:root /etc/profile.d/98-noid-bash-history.sh
echo "  [OK] locked/atomic Bash history compactor + profile default written"

# Toggle script — power users can opt-in to full ephemeral mode
cat > /usr/local/bin/noid-toggle-bash-history <<'TOGGLE_HIST_EOF'
#!/bin/bash
# noid-toggle-bash-history — switch future Bash sessions between NoID Privacy's
# prompt-compacted persistent default and no-new-persistent-writes mode.
#
# Usage:
#   sudo noid-toggle-bash-history ephemeral  # stop future writes in new shells
#   sudo noid-toggle-bash-history default    # restore prompt-compacted default
#   noid-toggle-bash-history status          # show current state
#
# Mechanism: writes/removes /etc/profile.d/99-noid-bash-history-ephemeral.sh.
# Override file is loaded AFTER 98-noid-bash-history.sh (numeric sort) so
# it overrides the persistent default. Effect: next NEW shell session.

set -euo pipefail

# shellcheck source=/dev/null
[ ! -r /usr/local/lib/noid-privacy/agent-install-format.sh ] || \
    NOID_FMT_AUTO_TITLE="NoID Privacy — Bash History" \
    NOID_FMT_AUTO_SUBTITLE="Future shell history policy" \
    . /usr/local/lib/noid-privacy/agent-install-format.sh

OVERRIDE=/etc/profile.d/99-noid-bash-history-ephemeral.sh

case "${1:-}" in
    ephemeral)
        if [ "$EUID" -ne 0 ]; then
            echo "Error: must run as root (use sudo)." >&2
            exit 1
        fi
        cat > "$OVERRIDE" <<'OV_EOF'
# NoID Privacy — ephemeral bash history override (created by noid-toggle-bash-history)
# Stops future history-file writes in new shells. Existing history files,
# filesystem snapshots and backups are deliberately not deleted.
case "$-" in
    *i*)
        unset HISTFILE
        export HISTSIZE=1000
        export HISTFILESIZE=0
        export HISTCONTROL=ignorespace:erasedups
        ;;
esac
OV_EOF
        chmod 644 "$OVERRIDE"
        chown root:root "$OVERRIDE"
        echo "[OK] future Bash history writes DISABLED. Open a new terminal to apply."
        echo "[note] Existing ~/.bash_history files, snapshots and backups were NOT deleted."
        ;;
    default)
        if [ "$EUID" -ne 0 ]; then
            echo "Error: must run as root (use sudo)." >&2
            exit 1
        fi
        if [ -f "$OVERRIDE" ]; then
            rm -f "$OVERRIDE"
            echo "[OK] back to the prompt-compacted persistent default."
        else
            echo "[info] override not present — already in rolling-100 default mode."
        fi
        ;;
    status|"")
        if [ -f "$OVERRIDE" ]; then
            echo "bash history: NO FUTURE WRITES IN NEW SHELLS"
            echo "  Existing history files/snapshots/backups are retained."
            echo "  Override file: $OVERRIDE"
        else
            echo "bash history: PROMPT-COMPACTED PERSISTENT (newest 100 distinct exact Bash-parsed entries after successful sync)"
        fi
        ;;
    *)
        echo "Usage: $0 {ephemeral|default|status}" >&2
        exit 2
        ;;
esac
TOGGLE_HIST_EOF
chmod 755 /usr/local/bin/noid-toggle-bash-history
chown root:root /usr/local/bin/noid-toggle-bash-history
echo "  [OK] /usr/local/bin/noid-toggle-bash-history installed"

# Documentation
mkdir -p /usr/share/doc/noid-privacy
cat > /usr/share/doc/noid-privacy/10-bash-history.md <<'BASH_DOC_EOF'
# NoID Privacy — bash CLI history

## Default: prompt-compacted persistent history

NoID Privacy keeps cross-session Bash recall, but does not rely on Bash's native
`HISTFILESIZE` as a strict concurrent-command counter. After each successfully
completed prompt hook, a per-user `flock` serializes `history -a` and an atomic
rewrite to the newest 100 distinct exact history entries as parsed by Bash
itself. When an exact command recurs, only its newest occurrence is retained.

Timestamp-free files preserve command text beginning with `#<digit>`, such as
`#5 my note`. If a file contains an exact `#<digits>` timestamp record, the
compactor enables Bash's timestamp framing so mixed files are read correctly.
Under that framing Bash itself classifies every physical line beginning with
`#<digit>` as metadata, so such a command-like comment is not retained. An
exact numeric comment is indistinguishable from a timestamp record in Bash's
history-file format. Do not use persistent shell history as the only copy of
notes; use a normal mode-0600 file for content that must be retained exactly.

The boundary is exact only after a successful prompt sync. A process killed or
powered off between append and compaction can leave an excess until the next
successful sync. Long and multiline commands have variable size, so there is
no fixed byte cap and no “10 KiB at all times” promise. A successful compaction
does not retain Bash timestamp metadata. A user-enabled timestamp can exist in
the append-to-compaction failure window, but the next successful sync removes
it. Multiline serialization can occupy more than one Bash-parsed entry after a
later read. Bash's own exit-time physical-line limit can therefore retain fewer
than 100 parsed entries before the next prompt sync.

`SIGKILL` cannot run shell cleanup traps. If it lands during compaction, an
owner-only mode-0600 parse/output temporary file can remain beside the history
file. The next sync, while holding the same per-user lock, removes only exact
regular, non-symlink, user-owned leftovers before proceeding. A filesystem
snapshot or backup taken during that window is outside this cleanup boundary.

Existing `PROMPT_COMMAND` hooks are preserved whether Bash represents them as a
string or array, and repeated profile sourcing does not add another NoID Privacy hook.
The history file and its lock are mode 0600. An atomic same-directory rename
prevents a failed compaction from publishing a partial replacement.

## Why this design (vs full ephemeral)

Pre-rolling-100 the default was full-ephemeral (no `~/.bash_history`
file at all). That hardened against on-disk leaks at the cost of cross-
session recall (Arrow-up / `Ctrl+R` lost everything on logout).

For a single-user privacy workstation with LUKS encryption, bounded prompt-time
retention and mode 0600 are the accepted usability trade-off. The following are
convenience/minimization controls, not reliable secret-loss prevention:

1. `ignorespace` — prefix a sensitive command with a space → never enters
   history (e.g. `␣ curl -H "Authorization: Bearer ${TOKEN}" ...`)
2. `HISTIGNORE` skips a short list of routine navigation/history commands; its
   case-sensitive patterns are not a credential detector.
3. `erasedups` reduces duplicates in the running shell. Independently, the
   locked compactor retains only the newest occurrence of each exact persisted
   Bash-parsed entry; neither mechanism is a secrecy boundary.
4. The locked compactor retains the newest 100 distinct exact Bash-parsed
   entries after a successful prompt sync.
5. LUKS protects data at rest; deleted blocks may persist below the filesystem
   and are not described as scrubbed or securely erased
6. `~/.bash_history` mode 600 (owner-only, Fedora default)

## Override modes

### Stop future persistent writes in new shells

    sudo noid-toggle-bash-history ephemeral

Then open a new terminal. The new shell unsets `HISTFILE`, so it creates no new
persistent Bash history. The toggle intentionally does **not** delete an
existing `~/.bash_history`, filesystem snapshots or backups, and does not claim
secure erasure. Existing terminals keep their previous state until closed.

### Restore the prompt-compacted persistent default

    sudo noid-toggle-bash-history default

### Check current state

    noid-toggle-bash-history status

## Per-session manual overrides

Force ephemeral for one session (no persistent file written):

    unset HISTFILE; HISTSIZE=0

Force persistent history for one session even if the no-write override is active:

    HISTFILE=~/.bash_history; HISTSIZE=100; HISTFILESIZE=100

## Files involved

- `/etc/profile.d/98-noid-bash-history.sh` — NoID Privacy prompt-sync function/default.
- `/etc/profile.d/99-noid-bash-history-ephemeral.sh` — created by
  `noid-toggle-bash-history ephemeral` to override the default.
- `/usr/local/libexec/noid-bash-history-compact` — atomic Bash-entry
  compactor called while the per-user lock is held.
- `/usr/local/bin/noid-toggle-bash-history` — toggle CLI script.
- `~/.bash_history` — persistent history file (mode 600, owner-only).
- `~/.bash_history.noid.lock` — per-user serialization lock (mode 600).
BASH_DOC_EOF
chmod 644 /usr/share/doc/noid-privacy/10-bash-history.md
chown root:root /usr/share/doc/noid-privacy/10-bash-history.md
echo "  [OK] /usr/share/doc/noid-privacy/10-bash-history.md written"

# ----------------------------------------------------------------------------
# Step 9d: GPG /etc/skel hardening
# ----------------------------------------------------------------------------
# Hardened GnuPG defaults for NEWLY-created users (/etc/skel applies only
# at user-creation via useradd CREATE_HOME). 10 KS-consensus directives
# (inline in the heredoc) — `throw-keyids` deliberately omitted: it hides
# recipient key-IDs and breaks Thunderbird/multi-recipient workflows.
# Skel inheritance verified with a test user.

echo ""
echo "[Step 9d] GPG /etc/skel hardening"

mkdir -p /etc/skel/.gnupg
chmod 0700 /etc/skel/.gnupg
chown root:root /etc/skel/.gnupg

cat > /etc/skel/.gnupg/gpg.conf <<'GPG_EOF'
# NoID Privacy — GnuPG hardening defaults (KS-consensus, Module 10)
# throw-keyids OMITTED for workflow-compat (multi-recipient Thunderbird OK)

# Output hygiene
no-emit-version
no-comments

# Key-listing format (full 64-bit IDs, no ambiguous 32-bit)
keyid-format 0xlong
with-fingerprint
list-options show-uid-validity
verify-options show-uid-validity

# Cipher preferences (modern AES-only)
personal-cipher-preferences AES256 AES192 AES

# Digest preferences (modern SHA-2 only, NO SHA-1, NO MD5)
personal-digest-preferences SHA512 SHA384 SHA256

# Compression preferences
personal-compress-preferences ZLIB BZIP2 ZIP Uncompressed

# Default preference-list for new keys
default-preference-list SHA512 SHA384 SHA256 AES256 AES192 AES ZLIB BZIP2 ZIP Uncompressed
GPG_EOF

chmod 0600 /etc/skel/.gnupg/gpg.conf
chown root:root /etc/skel/.gnupg/gpg.conf
echo "  [OK] /etc/skel/.gnupg/gpg.conf (10 hardening directives, 0600 root:root)"

# Reassert and verify every Module 10 output label. Authentication, sudo,
# password history and executable profile hooks are security boundaries; a
# missing label tool or wrong context must abort the compose instead of being
# hidden behind a best-effort relabel.
M10_LABEL_PATHS=(
    /etc/security/faillock.conf
    /etc/security/pwquality.conf
    /etc/security/pwhistory.conf
    /etc/security/opasswd
    /etc/security/access.conf
    /etc/security/pam_env-sudo.conf
    /etc/security/limits.conf
    /etc/systemd/logind.conf.d
    /etc/systemd/logind.conf.d/99-noid-hardening.conf
    /etc/login.defs
    /etc/pam.d/su
    /etc/pam.d/sudo
    /etc/sudoers.d
    /etc/sudoers.d/99-noid-hardening
    /etc/sudoers.d/99-noid-no-fqdn
    /etc/systemd/system.conf.d/50-coredump.conf
    /etc/libvirt/qemu.conf
    /etc/tmpfiles.d/90-noid-permission-policy.conf
    /etc/dnf/libdnf5-plugins/actions.d/noid-permission-policy.actions
    /etc/profile.d/99-noid-security-umask.sh
    /etc/profile.d/98-noid-bash-history.sh
    /usr/local/libexec/noid-bash-history-compact
    /usr/local/bin/noid-toggle-bash-history
    /usr/share/doc/noid-privacy/10-bash-history.md
    /usr/share/doc/noid-privacy/10-libvirt-core-dumps.md
    /etc/skel/.gnupg
    /etc/skel/.gnupg/gpg.conf
    /var/log/ks-10-authselect.err
)
for m10_label_path in "${M10_LABEL_PATHS[@]}"; do
    restorecon -F "$m10_label_path"
    matchpathcon -V "$m10_label_path"
done
unset m10_label_path

# ----------------------------------------------------------------------------
# Step 10: Verification
# ----------------------------------------------------------------------------

echo ""
echo "[Step 10] Verification"

fail=0

# 10.1 — exact faillock.conf policy and metadata
if [ -f /etc/security/faillock.conf ] \
   && [ ! -L /etc/security/faillock.conf ] \
   && [ "$(stat -Lc '%U:%G:%a:%h' /etc/security/faillock.conf)" = root:root:644:1 ] \
   && grep -qxF 'deny = 10' /etc/security/faillock.conf \
   && grep -qxF 'unlock_time = 900' /etc/security/faillock.conf \
   && grep -qxF 'fail_interval = 1800' /etc/security/faillock.conf \
   && grep -qxF 'silent' /etc/security/faillock.conf \
   && grep -qxF 'audit' /etc/security/faillock.conf \
   && grep -qxF 'even_deny_root' /etc/security/faillock.conf \
   && grep -qxF 'root_unlock_time = 60' /etc/security/faillock.conf \
   && grep -qxF 'dir = /var/lib/faillock' /etc/security/faillock.conf; then
    echo "  [OK] faillock.conf exact policy + metadata"
else
    echo "  [FAIL] faillock.conf policy or metadata invalid"
    fail=$((fail + 1))
fi

# 10.2 — pwquality.conf (15 chars, no composition, root enforcement)
if [ -f /etc/security/pwquality.conf ] \
   && [ ! -L /etc/security/pwquality.conf ] \
   && [ "$(stat -Lc '%U:%G:%a:%h' /etc/security/pwquality.conf)" = root:root:644:1 ] \
   && grep -q "minlen = 15" /etc/security/pwquality.conf \
   && grep -q "minclass = 0" /etc/security/pwquality.conf \
   && grep -qx "enforce_for_root" /etc/security/pwquality.conf; then
    echo "  [OK] pwquality.conf (minlen=15, no class rule, root enforced)"
else
    echo "  [FAIL] pwquality.conf length/composition/root policy invalid"
    fail=$((fail + 1))
fi

# 10.2b — pwhistory is deterministic and also covers root.
pwhistory_rules=$(
    awk '!/^[[:space:]]*($|#)/ {gsub(/[[:space:]]/, ""); print}' \
        /etc/security/pwhistory.conf 2>/dev/null || true
)
if [ -f /etc/security/pwhistory.conf ] \
   && [ ! -L /etc/security/pwhistory.conf ] \
   && [ "$(stat -Lc '%U:%G:%a:%h' /etc/security/pwhistory.conf)" = root:root:644:1 ] \
   && [ "$pwhistory_rules" = $'remember=10\nenforce_for_root' ] \
   && [ -f /etc/security/opasswd ] \
   && [ ! -L /etc/security/opasswd ] \
   && [ "$(stat -Lc '%U:%G:%a:%h' /etc/security/opasswd)" = root:root:600:1 ]; then
    echo "  [OK] pwhistory.conf exact policy + root-only history store"
else
    echo "  [FAIL] pwhistory policy or history-store metadata invalid"
    fail=$((fail + 1))
fi

# 10.3 — logind drop-in
# Verify the lifecycle-only drop-in and single-owner desktop-power boundary.
if [ -f /etc/systemd/logind.conf.d/99-noid-hardening.conf ]; then
    if grep -q "^KillUserProcesses=yes" /etc/systemd/logind.conf.d/99-noid-hardening.conf \
       && grep -qxF "KillExcludeUsers=" /etc/systemd/logind.conf.d/99-noid-hardening.conf \
       && grep -q "^RemoveIPC=yes" /etc/systemd/logind.conf.d/99-noid-hardening.conf \
       && ! grep -qE "^(InhibitorsMax|IdleAction|IdleActionSec|Handle(Power|Suspend|Hibernate|Lid))=" \
            /etc/systemd/logind.conf.d/99-noid-hardening.conf; then
        echo "  [OK] logind lifecycle drop-in covers root; GNOME/vendor power ownership retained"
    else
        echo "  [FAIL] logind lifecycle directives missing or desktop power ownership overridden"
        fail=$((fail + 1))
    fi
else
    echo "  [FAIL] logind.conf.d drop-in absent"
    fail=$((fail + 1))
fi

# 10.4 — exact and unique login.defs policy
login_defs_ok=1
while read -r login_defs_key login_defs_value; do
    login_defs_count=$(
        grep -Ec "^${login_defs_key}[[:space:]]+${login_defs_value}$" \
            /etc/login.defs 2>/dev/null || true
    )
    if [ "$login_defs_count" -ne 1 ]; then
        echo "  [FAIL] login.defs: ${login_defs_key}=${login_defs_value} is not exact and unique"
        login_defs_ok=0
    fi
done <<'LOGIN_DEFS_VERIFY_EOF'
LOG_OK_LOGINS no
LOG_UNKFAIL_ENAB no
FAIL_DELAY 4
YESCRYPT_COST_FACTOR 8
UMASK 022
HOME_MODE 0700
CREATE_HOME yes
ENCRYPT_METHOD YESCRYPT
PASS_MAX_DAYS 99999
LOGIN_DEFS_VERIFY_EOF
if [ "$login_defs_ok" -eq 1 ]; then
    echo "  [OK] login.defs: privacy, hash and local-account defaults exact and unique"
else
    fail=$((fail + 1))
fi
unset login_defs_count login_defs_key login_defs_ok login_defs_value

# 10.4b — maintained yescrypt templates; native cost comes from login.defs
for pam_file in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
    if [ ! -f "$pam_file" ]; then
        echo "  [FAIL] ${pam_file}: not present"
        fail=$((fail + 1))
        continue
    fi
    if grep -qE '^password[[:space:]]+.*pam_unix\.so[^#]*[[:space:]]yescrypt([[:space:]]|$)' "$pam_file" \
       && ! grep -qE '^password[[:space:]]+.*pam_unix\.so[^#]*[[:space:]]rounds=' "$pam_file" \
       && ! grep -qF 'pam_oddjob_mkhomedir.so' "$pam_file"; then
        echo "  [OK] ${pam_file}: yescrypt, cost owned by login.defs"
    else
        echo "  [FAIL] ${pam_file}: yescrypt owner or self-contained session policy invalid"
        fail=$((fail + 1))
    fi
done

# 10.5 — pam_wheel active in su
if grep -qE '^auth[[:space:]]+required[[:space:]]+pam_wheel\.so use_uid' /etc/pam.d/su; then
    echo "  [OK] pam_wheel.so use_uid active in /etc/pam.d/su"
else
    echo "  [FAIL] pam_wheel not active in /etc/pam.d/su"
    fail=$((fail + 1))
fi

# 10.6/10.7 — exact, checksum-valid authselect state. A membership-only feature
# loop cannot reject stale, duplicate or newly added service-backed features.
authselect_raw=$(authselect current -r 2>>"$AUTHSEL_LOG") || authselect_raw=""
if authselect check 2>>"$AUTHSEL_LOG" \
   && [ "$authselect_raw" = "$AUTHSELECT_EXPECTED" ] \
   && [ -f "$AUTHSEL_LOG" ] \
   && [ ! -L "$AUTHSEL_LOG" ] \
   && [ "$(stat -Lc '%U:%G:%a:%h' "$AUTHSEL_LOG")" = root:root:600:1 ]; then
    echo "  [OK] authselect: exact five-feature local profile, valid checksums, private evidence"
else
    echo "  [FAIL] authselect state, generated checksums or evidence metadata invalid"
    fail=$((fail + 1))
fi
unset authselect_raw

# 10.7a — sudo is privilege delegation inside the existing login. Keep the
# complete Fedora PAM session stack, but select pam_systemd's supported
# class=none before the authselect-owned system-auth include.
SUDO_PAM=/etc/pam.d/sudo
SUDO_PAM_ENV=/etc/security/pam_env-sudo.conf
sudo_pam_env_rules=$(
    awk '!/^[[:space:]]*($|#)/ {print}' "$SUDO_PAM_ENV" 2>/dev/null || true
)
if [ -f "$SUDO_PAM" ] && [ ! -L "$SUDO_PAM" ] && \
   [ "$(stat -Lc '%U:%G:%a:%h' "$SUDO_PAM")" = root:root:644:1 ] && \
   [ -f "$SUDO_PAM_ENV" ] && [ ! -L "$SUDO_PAM_ENV" ] && \
   [ "$(stat -Lc '%U:%G:%a:%h' "$SUDO_PAM_ENV")" = root:root:644:1 ] && \
   [ "$sudo_pam_env_rules" = \
     'XDG_SESSION_CLASS DEFAULT=none OVERRIDE=none' ] && \
   [ "$(grep -cFx "$SUDO_PAM_ENV_LINE" "$SUDO_PAM")" -eq 1 ] && \
   [ "$(grep -Ec \
        '^session[[:space:]]+include[[:space:]]+system-auth[[:space:]]*$' \
        "$SUDO_PAM")" -eq 1 ] && \
   [ "$(rpm -qf --qf '%{NAME}' "$SUDO_PAM" 2>/dev/null || true)" = sudo ] && \
   awk -v env_line="$SUDO_PAM_ENV_LINE" '
        $0 == env_line { env_nr=NR }
        /^session[[:space:]]+include[[:space:]]+system-auth[[:space:]]*$/ {
            include_nr=NR
        }
        END { exit !(env_nr > 0 && include_nr > env_nr) }
   ' "$SUDO_PAM"; then
    echo "  [OK] sudo PAM keeps the complete stack without a root logind session"
else
    echo "  [FAIL] sudo PAM class=none policy, metadata or ordering invalid"
    fail=$((fail + 1))
fi
unset sudo_pam_env_rules

# 10.7b — pam_access is fail-open without a matching rule. Verify the exact
# ordered policy and metadata, not merely the authselect feature that loads it.
ACCESS_POLICY=/etc/security/access.conf
access_rules=$(
    awk '
        /^[[:space:]]*[+-]:/ {
            gsub(/[[:space:]]/, "")
            print
        }
    ' "$ACCESS_POLICY" 2>/dev/null || true
)
if [ -f "$ACCESS_POLICY" ] && [ ! -L "$ACCESS_POLICY" ] && \
   [ "$(stat -c '%U:%G:%a:%h' "$ACCESS_POLICY" 2>/dev/null || true)" = \
     "root:root:644:1" ] && \
   [ "$access_rules" = $'+:(wheel):ALL\n+:root:ALL\n-:ALL:ALL' ]; then
    echo "  [OK] access.conf exact allow-wheel/allow-root/deny-all policy"
else
    echo "  [FAIL] access.conf missing, unsafe or not the exact ordered policy"
    fail=$((fail + 1))
fi

# 10.9 — sudo hardening drop-in (Step 7)
if [ -f /etc/sudoers.d/99-noid-hardening ]; then
    if grep -qE '^Defaults[[:space:]]+timestamp_timeout=3' /etc/sudoers.d/99-noid-hardening; then
        echo "  [OK] sudo drop-in: timestamp_timeout=3 (CIS 4.3.6 hardened)"
    else
        echo "  [FAIL] sudo drop-in: timestamp_timeout=3 missing"
        fail=$((fail + 1))
    fi
    # Syntax validation post-install (belt-and-suspenders)
    if visudo -cf /etc/sudoers.d/99-noid-hardening >/dev/null 2>&1; then
        echo "  [OK] sudo drop-in: visudo syntax valid"
    else
        echo "  [FAIL] sudo drop-in: visudo syntax INVALID"
        fail=$((fail + 1))
    fi
    for dnf_command in /usr/bin/dnf /usr/bin/dnf5; do
        if grep -qxF "Defaults!${dnf_command} umask=0022, umask_override" \
                /etc/sudoers.d/99-noid-hardening; then
            echo "  [OK] sudo drop-in: ${dnf_command} uses command-scoped umask 0022"
        else
            echo "  [FAIL] sudo drop-in: ${dnf_command} umask contract missing"
            fail=$((fail + 1))
        fi
    done
    unset dnf_command
else
    echo "  [FAIL] /etc/sudoers.d/99-noid-hardening missing"
    fail=$((fail + 1))
fi

# 10.9b — defensive !fqdn drop-in (Step 7b)
if [ -f /etc/sudoers.d/99-noid-no-fqdn ] && \
   [ ! -L /etc/sudoers.d/99-noid-no-fqdn ] && \
   [ "$(stat -c '%U:%G:%a:%h' /etc/sudoers.d/99-noid-no-fqdn \
        2>/dev/null || true)" = "root:root:440:1" ] && \
   grep -qxF 'Defaults !fqdn' /etc/sudoers.d/99-noid-no-fqdn && \
   visudo -cf /etc/sudoers.d/99-noid-no-fqdn >/dev/null 2>&1; then
    echo "  [OK] sudo drop-in: explicit !fqdn policy valid"
else
    echo "  [FAIL] sudo drop-in: 99-noid-no-fqdn missing, unsafe or invalid"
    fail=$((fail + 1))
fi

# 10.10 — Core dump Layer 5 (limits.conf, Step 8)
if grep -qE "^\*[[:space:]]+hard[[:space:]]+core[[:space:]]+0" /etc/security/limits.conf; then
    echo "  [OK] limits.conf: * hard core 0 (Coredump Layer 5)"
else
    echo "  [FAIL] limits.conf: * hard core 0 missing (Layer 5)"
    fail=$((fail + 1))
fi

# 10.11 — Core dump Layer 6 (systemd.conf.d, Step 8)
if [ -f /etc/systemd/system.conf.d/50-coredump.conf ] && \
   grep -qE '^DefaultLimitCORE=0' /etc/systemd/system.conf.d/50-coredump.conf; then
    echo "  [OK] systemd.conf.d/50-coredump.conf: DefaultLimitCORE=0 (Layer 6)"
else
    echo "  [FAIL] systemd.conf.d/50-coredump.conf: DefaultLimitCORE=0 missing (Layer 6)"
    fail=$((fail + 1))
fi

# 10.11b — privileged system QEMU cannot raise Layer 6 (Step 8).
QEMU_SYSTEM_CONF=/etc/libvirt/qemu.conf
if [ -f "$QEMU_SYSTEM_CONF" ] && [ ! -L "$QEMU_SYSTEM_CONF" ] \
   && [ "$(stat -Lc '%U:%G:%a:%h' "$QEMU_SYSTEM_CONF" 2>/dev/null || true)" = \
        root:root:644:1 ] \
   && [ "$(rpm -qf --qf '%{NAME}' "$QEMU_SYSTEM_CONF" 2>/dev/null || true)" = \
        libvirt-daemon-driver-qemu ] \
   && [ "$(grep -Ec '^[[:space:]]*max_core[[:space:]]*=' \
        "$QEMU_SYSTEM_CONF")" -eq 1 ] \
   && [ "$(grep -Ec '^[[:space:]]*dump_guest_core[[:space:]]*=' \
        "$QEMU_SYSTEM_CONF")" -eq 1 ] \
   && grep -Eq \
        '^[[:space:]]*max_core[[:space:]]*=[[:space:]]*0[[:space:]]*(#.*)?$' \
        "$QEMU_SYSTEM_CONF" \
   && grep -Eq \
        '^[[:space:]]*dump_guest_core[[:space:]]*=[[:space:]]*0[[:space:]]*(#.*)?$' \
        "$QEMU_SYSTEM_CONF" \
   && [ -f /usr/share/doc/noid-privacy/10-libvirt-core-dumps.md ] \
   && [ ! -L /usr/share/doc/noid-privacy/10-libvirt-core-dumps.md ] \
   && [ "$(stat -Lc '%U:%G:%a:%h' \
        /usr/share/doc/noid-privacy/10-libvirt-core-dumps.md \
        2>/dev/null || true)" = root:root:644:1 ]; then
    echo "  [OK] libvirt system-QEMU max_core boundary + documentation exact"
else
    echo "  [FAIL] libvirt system-QEMU core boundary or documentation invalid"
    fail=$((fail + 1))
fi
unset QEMU_SYSTEM_CONF

# 10.12 — native permission policy (Step 9)
PERMISSION_POLICY=/etc/tmpfiles.d/90-noid-permission-policy.conf
PERMISSION_ACTION=/etc/dnf/libdnf5-plugins/actions.d/noid-permission-policy.actions
if [ -f "$PERMISSION_POLICY" ] && [ -f "$PERMISSION_ACTION" ] \
   && [ "$(stat -c '%U:%G:%a' "$PERMISSION_POLICY" 2>/dev/null)" = root:root:644 ] \
   && [ "$(stat -c '%U:%G:%a' "$PERMISSION_ACTION" 2>/dev/null)" = root:root:644 ]; then
    echo "  [OK] native permission policy + dnf5 action present"
else
    echo "  [FAIL] native permission policy/action missing or wrong metadata"
    fail=$((fail + 1))
fi
for obsolete in /usr/local/sbin/noid-suid-harden.sh \
                /etc/systemd/system/noid-suid-harden.service \
                /etc/systemd/system/noid-suid-harden.timer; do
    if [ -e "$obsolete" ] || [ -L "$obsolete" ]; then
        echo "  [FAIL] obsolete periodic permission mutator remains: $obsolete"
        fail=$((fail + 1))
    fi
done

# 10.13 — SUID/mode permission contract (Step 9)
# Five explicitly unsupported unprivileged workflows lose SUID. Four
# load-bearing Fedora paths retain their package-native SUID modes.
PERMISSION_STRIPPED=(
    '/usr/bin/chfn|711|util-linux'
    '/usr/bin/chsh|711|util-linux'
    '/usr/bin/gpasswd|755|shadow-utils'
    '/usr/bin/newgrp|755|shadow-utils'
    '/usr/bin/fusermount-glusterfs|755|glusterfs-fuse'
)
PERMISSION_NATIVE=(
    '/usr/bin/chage|4755|shadow-utils'
    '/usr/bin/pam_timestamp_check|4755|pam'
    '/usr/bin/userhelper|4711|usermode'
    '/usr/libexec/libgtop_server2|4755|libgtop2'
)
for permission_spec in "${PERMISSION_STRIPPED[@]}" "${PERMISSION_NATIVE[@]}"; do
    IFS='|' read -r permission_path permission_mode permission_pkg <<< "$permission_spec"
    permission_owner=$(rpm -qf --qf '%{NAME}' "$permission_path" 2>/dev/null || true)
    permission_actual=$(stat -c '%a' "$permission_path" 2>/dev/null || true)
    if [ ! -f "$permission_path" ] || [ -L "$permission_path" ] || \
       [ "$permission_owner" != "$permission_pkg" ] || \
       [ "$permission_actual" != "$permission_mode" ]; then
        echo "  [FAIL] permission contract: $permission_path owner=$permission_owner mode=$permission_actual"
        fail=$((fail + 1))
    fi
done
unset permission_spec permission_path permission_mode permission_pkg \
    permission_owner permission_actual

# 10.14 — profile.d umask 027 (Step 9b)
# Detects silent removal/overwrite via dnf-update of glibc/setup packages.
if [ -f /etc/profile.d/99-noid-security-umask.sh ]; then
    if grep -qF 'case $- in' /etc/profile.d/99-noid-security-umask.sh && \
       grep -qF '*i*) umask 027 ;;' /etc/profile.d/99-noid-security-umask.sh; then
        echo "  [OK] profile.d/99-noid-security-umask.sh: umask 027 (Step 9b)"
    else
        echo "  [FAIL] profile.d/99-noid-security-umask.sh present but umask 027 missing"
        fail=$((fail + 1))
    fi
else
    echo "  [FAIL] profile.d/99-noid-security-umask.sh missing (Step 9b)"
    fail=$((fail + 1))
fi

# 10.14b — complete Bash-history implementation (Step 9b.2)
for history_spec in \
    '/etc/profile.d/98-noid-bash-history.sh|644' \
    '/usr/local/libexec/noid-bash-history-compact|755' \
    '/usr/local/bin/noid-toggle-bash-history|755'; do
    IFS='|' read -r history_path history_mode <<< "$history_spec"
    if [ -f "$history_path" ] && [ ! -L "$history_path" ] && \
       [ "$(stat -c '%U:%G:%a:%h' "$history_path" 2>/dev/null || true)" = \
         "root:root:${history_mode}:1" ] && \
       bash -n "$history_path" 2>/dev/null; then
        echo "  [OK] Bash history artifact valid: $history_path"
    else
        echo "  [FAIL] Bash history artifact missing, unsafe or invalid: $history_path"
        fail=$((fail + 1))
    fi
done
unset history_spec history_path history_mode

# 10.15 — root-only policy-directory mode spot-check (Step 9)
# Detects silent permission-reset via rpm-update of cronie/sudo packages.
DIR_HARDEN_VERIFY_LIST=(
    /etc/cron.hourly
    /etc/cron.daily
    /etc/cron.weekly
    /etc/cron.monthly
    /etc/cron.d
    /etc/sudoers.d
)
dir_fail=0
for d in "${DIR_HARDEN_VERIFY_LIST[@]}"; do
    if [ -d "$d" ]; then
        cur_mode=$(stat -c '%a' "$d" 2>/dev/null || echo "")
        if [ "$cur_mode" != "700" ]; then
            echo "  [FAIL] $d mode=$cur_mode (expected native policy mode 700)"
            dir_fail=$((dir_fail + 1))
        fi
    fi
done
if [ $dir_fail -eq 0 ]; then
    echo "  [OK] root-only policy directories all mode 700 (Step 9)"
else
    fail=$((fail + dir_fail))
fi

# 10.16 — GnuPG defaults for newly created users (Step 9d)
GPG_SKEL=/etc/skel/.gnupg/gpg.conf
gpg_directives=$(
    awk '!/^[[:space:]]*($|#)/ {count++} END {print count+0}' \
        "$GPG_SKEL" 2>/dev/null || true
)
if [ -f "$GPG_SKEL" ] && [ ! -L "$GPG_SKEL" ] && \
   [ "$(stat -c '%U:%G:%a:%h' "$GPG_SKEL" 2>/dev/null || true)" = \
     "root:root:600:1" ] && \
   [ "$(stat -c '%U:%G:%a' /etc/skel/.gnupg 2>/dev/null || true)" = \
     "root:root:700" ] && \
   [ "$gpg_directives" = 10 ]; then
    echo "  [OK] GnuPG skel policy: 10 directives, root-only metadata"
else
    echo "  [FAIL] GnuPG skel policy missing, unsafe or incomplete"
    fail=$((fail + 1))
fi

if [ $fail -gt 0 ]; then
    echo ""
    echo "[Module 10] FAILED ($fail checks)"
    exit 1
fi

echo ""
echo "=============================================================="
echo "[Module 10] Done — all checks passed"
echo "=============================================================="

%end
